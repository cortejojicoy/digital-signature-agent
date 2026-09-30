// Windows key store: picks Hello, TPM or software per key (desktop-agent-plan.md §6).
//
//   identity key (requireUserPresence) → Windows Hello if set up
//                                      → TPM (PCP) with userPresence = false
//                                      → software (KSP)
//   session key                        → TPM (PCP) → software (KSP)

#include <winrt/base.h>

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

class WinKeyStore final : public KeyStore {
public:
    explicit WinKeyStore(Backend backend)
        : backend_(backend),
          pcp_(MS_PLATFORM_CRYPTO_PROVIDER, Protection::Tpm),
          ksp_(MS_KEY_STORAGE_PROVIDER, Protection::Software) {}

    Capabilities capabilities() override {
        Capabilities caps;
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

    Bytes sign(const std::string& keyId, const Bytes& message, const std::string& /*reason*/,
               void* parentWindow) override {
        // Hello can't show custom text; the agent's confirm window shows the
        // document title before this call (§10.2).
        return guard([&] {
            switch (locate(keyId)) {
                case Where::Pcp: return pcp_.sign(keyId, message);
                case Where::Hello: return hello_.sign(keyId, message, static_cast<HWND>(parentWindow));
                case Where::Ksp: return ksp_.sign(keyId, message);
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
