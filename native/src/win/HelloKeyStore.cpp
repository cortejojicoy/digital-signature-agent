// Windows Hello keys via KeyCredentialManager (desktop-agent-plan.md §6.1).
//
// Calls run on libuv worker threads, which are fresh threads, so each joins
// the multi-threaded apartment and blocks on the async operations with .get().
//
// Prompt parenting (spike 0b): KeyCredentialManager has no window-handle
// overload, so from a Win32 / Electron app the Hello dialog can open behind
// the app window. PromptForegrounder gives the dialog foreground rights and
// brings it to the front once it appears. Verify this on real hardware.

#include "WinStores.h"

#include <atomic>
#include <chrono>
#include <thread>

#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Security.Credentials.h>
#include <winrt/Windows.Security.Cryptography.h>
#include <winrt/Windows.Security.Cryptography.Core.h>
#include <winrt/Windows.Storage.Streams.h>

namespace ks::win {
namespace {

using namespace winrt::Windows::Security::Credentials;
using winrt::Windows::Security::Cryptography::CryptographicBuffer;
using winrt::Windows::Security::Cryptography::Core::CryptographicPublicKeyBlobType;
using winrt::Windows::Storage::Streams::IBuffer;

void ensureApartment() {
    thread_local bool initialised = false;
    if (initialised) return;
    try {
        winrt::init_apartment(winrt::apartment_type::multi_threaded);
    } catch (const winrt::hresult_error&) {
        // Already initialised on this thread (RPC_E_CHANGED_MODE): usable as-is.
    }
    initialised = true;
}

Bytes toBytes(const IBuffer& buffer) {
    winrt::com_array<uint8_t> array;
    CryptographicBuffer::CopyToByteArray(buffer, array);
    return Bytes(array.begin(), array.end());
}

IBuffer toBuffer(const Bytes& bytes) {
    return CryptographicBuffer::CreateFromByteArray(winrt::array_view<const uint8_t>(bytes));
}

[[noreturn]] void failStatus(KeyCredentialStatus status) {
    switch (status) {
        case KeyCredentialStatus::NotFound:
            throw Error(ErrorCode::NotFound, "key not found");
        case KeyCredentialStatus::CredentialAlreadyExists:
            throw Error(ErrorCode::Exists, "a key with this id already exists");
        case KeyCredentialStatus::UserCanceled:
        case KeyCredentialStatus::UserPrefersPassword:
            throw Error(ErrorCode::Cancelled, "Windows Hello was cancelled");
        case KeyCredentialStatus::SecurityDeviceLocked:
            throw Error(ErrorCode::Internal, "the security device is locked");
        default:
            throw Error(ErrorCode::Internal, "Windows Hello failed");
    }
}

class PromptForegrounder {
public:
    explicit PromptForegrounder(HWND parent) {
        if (parent) {
            SetForegroundWindow(parent);
            AllowSetForegroundWindow(ASFW_ANY);
        }
        thread_ = std::thread([this] {
            using namespace std::chrono;
            const auto deadline = steady_clock::now() + seconds(5);
            while (!stop_ && steady_clock::now() < deadline) {
                if (HWND dialog = FindWindowW(L"Credential Dialog Xaml Host", nullptr)) {
                    SetForegroundWindow(dialog);
                    return;
                }
                std::this_thread::sleep_for(milliseconds(50));
            }
        });
    }
    ~PromptForegrounder() {
        stop_ = true;
        thread_.join();
    }

private:
    std::atomic<bool> stop_{false};
    std::thread thread_;
};

KeyInfo infoFor(const std::string& keyId, const KeyCredential& credential, Protection protection) {
    KeyInfo info;
    info.keyId = keyId;
    info.algorithm = Algorithm::RS256;  // Hello keys are RSA-2048
    info.spki = toBytes(credential.RetrievePublicKey(CryptographicPublicKeyBlobType::X509SubjectPublicKeyInfo));
    info.protection = protection;
    info.userPresence = true;
    return info;
}

}  // namespace

bool HelloKeyStore::supported() {
    if (!supported_) {
        ensureApartment();
        try {
            supported_ = KeyCredentialManager::IsSupportedAsync().get();
        } catch (const winrt::hresult_error&) {
            supported_ = false;
        }
    }
    return *supported_;
}

KeyInfo HelloKeyStore::create(const std::string& keyId, Protection protection) {
    ensureApartment();
    PromptForegrounder foreground(GetForegroundWindow());
    auto result = KeyCredentialManager::RequestCreateAsync(winrt::to_hstring(keyId),
                                                           KeyCredentialCreationOption::FailIfExists)
                      .get();
    if (result.Status() != KeyCredentialStatus::Success) failStatus(result.Status());
    return infoFor(keyId, result.Credential(), protection);
}

std::optional<KeyInfo> HelloKeyStore::find(const std::string& keyId, Protection protection) {
    ensureApartment();
    if (!supported()) return std::nullopt;
    auto result = KeyCredentialManager::OpenAsync(winrt::to_hstring(keyId)).get();
    if (result.Status() == KeyCredentialStatus::NotFound) return std::nullopt;
    if (result.Status() != KeyCredentialStatus::Success) failStatus(result.Status());
    return infoFor(keyId, result.Credential(), protection);
}

Bytes HelloKeyStore::sign(const std::string& keyId, const Bytes& message, HWND parent) {
    ensureApartment();
    auto opened = KeyCredentialManager::OpenAsync(winrt::to_hstring(keyId)).get();
    if (opened.Status() != KeyCredentialStatus::Success) failStatus(opened.Status());

    PromptForegrounder foreground(parent);
    // RSA PKCS#1 v1.5 over SHA-256 of the message; Hello hashes internally.
    auto signed_ = opened.Credential().RequestSignAsync(toBuffer(message)).get();
    if (signed_.Status() != KeyCredentialStatus::Success) failStatus(signed_.Status());
    return toBytes(signed_.Result());
}

std::optional<Attestation> HelloKeyStore::attest(const std::string& keyId) {
    ensureApartment();
    auto opened = KeyCredentialManager::OpenAsync(winrt::to_hstring(keyId)).get();
    if (opened.Status() != KeyCredentialStatus::Success) failStatus(opened.Status());

    auto result = opened.Credential().GetAttestationAsync().get();
    if (result.Status() != KeyCredentialAttestationStatus::Success) return std::nullopt;

    Attestation attestation;
    attestation.format = "windows-hello-tpm";
    attestation.statement = toBytes(result.AttestationBuffer());
    // The chain arrives as one buffer; the server splits and verifies it
    // against the bundled Microsoft TPM roots (§8.2).
    attestation.chain.push_back(toBytes(result.CertificateChainBuffer()));
    return attestation;
}

void HelloKeyStore::remove(const std::string& keyId) {
    ensureApartment();
    if (!supported()) return;
    try {
        KeyCredentialManager::DeleteAsync(winrt::to_hstring(keyId)).get();
    } catch (const winrt::hresult_error&) {
        // Not found: nothing to delete.
    }
}

}  // namespace ks::win
