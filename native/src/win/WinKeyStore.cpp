// Windows key store: picks Hello, TPM or software per key (desktop-agent-plan.md §6).
//
//   identity key (requireUserPresence) → Windows Hello if set up
//                                      → TPM (PCP) with userPresence = false
//                                      → software (KSP)
//   session key                        → TPM (PCP) → software (KSP)
//   imported .p12 key                  → TPM (PCP) + Hello consent before each use
//                                      → software (KSP) with a Windows password on each use
//   (pkcs12-key-storage-plan.md §5.3)

#include <winrt/base.h>

#include <filesystem>
#include <fstream>

#include "WinStores.h"

namespace ks {
namespace win {

std::wstring widen(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring out(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n);
    return out;
}

std::string narrow(const std::wstring& s) {
    if (s.empty()) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0, nullptr, nullptr);
    std::string out(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n, nullptr, nullptr);
    return out;
}

}  // namespace win

namespace {

using win::CngKeyStore;
using win::HelloKeyStore;

// <keyDirectory()>/<keyId>.consent marks an imported TPM key that needs Hello
// consent before each use. Hello can't protect a key it didn't create, so the
// agent enforces it (and reports userPresence = false).
std::filesystem::path consentMarker(const std::string& keyId) {
    return std::filesystem::path(win::widen(keyDirectory())) / win::widen(keyId + ".consent");
}

bool needsConsent(const std::string& keyId) {
    std::error_code ec;
    return std::filesystem::exists(consentMarker(keyId), ec);
}

void writeConsentMarker(const std::string& keyId) {
    std::error_code ec;
    std::filesystem::create_directories(consentMarker(keyId).parent_path(), ec);
    std::ofstream out(consentMarker(keyId), std::ios::binary | std::ios::trunc);
    out << "consent";
    if (!out) throw Error(ErrorCode::Internal, "could not write the consent marker");
}

void removeConsentMarker(const std::string& keyId) {
    std::error_code ec;
    std::filesystem::remove(consentMarker(keyId), ec);
}

class WinKeyStore final : public KeyStore {
public:
    explicit WinKeyStore(Backend backend)
        : backend_(backend),
          pcp_(MS_PLATFORM_CRYPTO_PROVIDER, Protection::Tpm),
          ksp_(MS_KEY_STORAGE_PROVIDER, Protection::Software) {}

    Capabilities capabilities() override {
        Capabilities caps;
        caps.pkcs12 = true;
        if (backend_ == Backend::Software) return caps;
        caps.hardware = pcp_.available();
        caps.userPresence = hello_.supported();
        caps.attestation = caps.hardware && caps.userPresence;
        return caps;
    }

    KeyInfo create(const CreateOptions& opts) override {
        guard([&] {
            if (locate(opts.keyId) != Where::None) {
                throw Error(ErrorCode::Exists, "a key with this id already exists");
            }
        });
        return guard([&] {
            if (backend_ == Backend::Auto) {
                if (opts.requireUserPresence && hello_.supported()) {
                    return hello_.create(opts.keyId, helloProtection());
                }
                if (pcp_.available()) return pcp_.create(opts.keyId);
            }
            return ksp_.create(opts.keyId);
        });
    }

    std::optional<KeyInfo> find(const std::string& keyId) override {
        return guard([&]() -> std::optional<KeyInfo> {
            if (backend_ == Backend::Auto) {
                if (auto k = pcp_.find(keyId)) return k;
                if (auto k = hello_.find(keyId, helloProtection())) return k;
            }
            return ksp_.find(keyId);
        });
    }

    Bytes sign(const std::string& keyId, const Bytes& message, const std::string& reason,
               void* parentWindow) override {
        // Hello can't show custom text; the agent's confirm window shows the
        // document title before this call (§10.2).
        HWND parent = static_cast<HWND>(parentWindow);
        return guard([&] {
            switch (locate(keyId)) {
                case Where::Pcp:
                    if (needsConsent(keyId)) win::requireConsent(parent, reason);
                    return pcp_.sign(keyId, message, parent, reason);
                case Where::Hello: return hello_.sign(keyId, message, parent);
                case Where::Ksp: return ksp_.sign(keyId, message, parent, reason);
                case Where::None: break;
            }
            throw Error(ErrorCode::NotFound, "key not found");
        });
    }

    std::optional<Attestation> attest(const std::string& keyId) override {
        return guard([&]() -> std::optional<Attestation> {
            switch (locate(keyId)) {
                case Where::Hello: return hello_.attest(keyId);
                case Where::Pcp:
                case Where::Ksp: return std::nullopt;
                case Where::None: break;
            }
            throw Error(ErrorCode::NotFound, "key not found");
        });
    }

    void remove(const std::string& keyId) override {
        guard([&] {
            if (backend_ == Backend::Auto) {
                pcp_.remove(keyId);
                hello_.remove(keyId);
            }
            ksp_.remove(keyId);
            removeConsentMarker(keyId);
        });
    }

    Pkcs12Contents inspectPkcs12(const Bytes& data, const std::string& password) override {
        return win::parsePkcs12(data, password, /*withKey=*/false).contents;
    }

    ImportedCertificate importPkcs12(const ImportOptions& opts) override {
        return guard([&] {
            if (locate(opts.keyId) != Where::None) throw Error(ErrorCode::Exists, "a key with this id already exists");
            win::ParsedPkcs12 parsed = win::parsePkcs12(opts.data, opts.password, /*withKey=*/true);

            ImportedCertificate result;
            result.contents = parsed.contents;
            bool imported = false;
            const bool consent = opts.requireUserPresence && backend_ == Backend::Auto && win::consentAvailable();
            // The TPM when presence can still be asked for (Hello consent) or isn't wanted.
            if (backend_ == Backend::Auto && pcp_.available() && (consent || !opts.requireUserPresence)) {
                try {
                    result.key = pcp_.importKey(opts.keyId, parsed.blobType, parsed.privateBlob, false);
                    if (consent) writeConsentMarker(opts.keyId);
                    result.key.userPresence = false;  // agent-enforced, so not claimed (§13, D7)
                    imported = true;
                } catch (const Error&) {
                    // This TPM won't take the key (spike S2): fall back to the KSP.
                    pcp_.remove(opts.keyId);
                    removeConsentMarker(opts.keyId);
                }
            }
            if (!imported) {
                const bool strong = opts.requireUserPresence && backend_ == Backend::Auto;
                result.key = ksp_.importKey(opts.keyId, parsed.blobType, parsed.privateBlob, strong);
            }
            if (result.key.spki != parsed.spki) {
                remove(opts.keyId);
                throw Error(ErrorCode::KeyMismatch, "the private key doesn't match the certificate");
            }
            return result;
        });
    }

    bool privateKeyExportable(const std::string& keyId) override {
        return guard([&] {
            switch (locate(keyId)) {
                case Where::Pcp: return pcp_.exportable(keyId);
                case Where::Ksp: return ksp_.exportable(keyId);
                case Where::Hello: return false;  // Hello never exposes the private key
                case Where::None: break;
            }
            throw Error(ErrorCode::NotFound, "key not found");
        });
    }

private:
    enum class Where { None, Pcp, Hello, Ksp };

    Backend backend_;
    HelloKeyStore hello_;
    CngKeyStore pcp_;
    CngKeyStore ksp_;

    Protection helloProtection() { return pcp_.available() ? Protection::Tpm : Protection::Software; }

    Where locate(const std::string& keyId) {
        if (backend_ == Backend::Auto) {
            if (pcp_.find(keyId)) return Where::Pcp;
            if (hello_.find(keyId, helloProtection())) return Where::Hello;
        }
        if (ksp_.find(keyId)) return Where::Ksp;
        return Where::None;
    }

    // WinRT reports failures as hresult_error; surface them as ks::Error.
    template <typename F>
    auto guard(F&& f) -> decltype(f()) {
        try {
            return f();
        } catch (const winrt::hresult_error& e) {
            throw Error(ErrorCode::Internal, win::narrow(std::wstring(e.message())));
        }
    }
};

}  // namespace

std::unique_ptr<KeyStore> createPlatformKeyStore(Backend backend) {
    return std::make_unique<WinKeyStore>(backend);
}

// Windows keeps agent tokens in safeStorage (DPAPI), which isn't tied to the
// app's signature, so there's nothing to seal here.
bool sealingAvailable() {
    return false;
}

Bytes sealData(const Bytes&) {
    throw Error(ErrorCode::Unsupported, "sealing is not used on Windows");
}

Bytes openData(const Bytes&) {
    throw Error(ErrorCode::Unsupported, "sealing is not used on Windows");
}

}  // namespace ks
