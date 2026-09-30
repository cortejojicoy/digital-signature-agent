// Windows backends (desktop-agent-plan.md §6). WinKeyStore.cpp composes them.
#pragma once

#include <windows.h>
#include <ncrypt.h>

#include <optional>
#include <string>

#include "keystore.h"

namespace ks::win {

std::wstring widen(const std::string& s);
std::string narrow(const std::wstring& s);

// Windows Hello via KeyCredentialManager (C++/WinRT). RSA-2048, TPM-backed
// when a TPM exists, OS-enforced face / fingerprint / PIN on every use.
class HelloKeyStore {
public:
    bool supported();
    KeyInfo create(const std::string& keyId, Protection protection);
    std::optional<KeyInfo> find(const std::string& keyId, Protection protection);
    Bytes sign(const std::string& keyId, const Bytes& message, HWND parent);
    std::optional<Attestation> attest(const std::string& keyId);
    void remove(const std::string& keyId);

private:
    std::optional<bool> supported_;
};

// CNG persisted key. MS_PLATFORM_CRYPTO_PROVIDER puts it in the TPM;
// MS_KEY_STORAGE_PROVIDER is the software fallback. ECDSA P-256, never
// exportable, no user presence.
class CngKeyStore {
public:
    CngKeyStore(LPCWSTR provider, Protection protection);
    ~CngKeyStore();
    CngKeyStore(const CngKeyStore&) = delete;
    CngKeyStore& operator=(const CngKeyStore&) = delete;

    bool available();
    KeyInfo create(const std::string& keyId);
    std::optional<KeyInfo> find(const std::string& keyId);
    Bytes sign(const std::string& keyId, const Bytes& message);
    void remove(const std::string& keyId);
    bool exportable(const std::string& keyId);

private:
    LPCWSTR providerName_;
    Protection protection_;
    NCRYPT_PROV_HANDLE provider_ = 0;
    bool opened_ = false;
    bool available_ = false;

    KeyInfo infoFor(const std::string& keyId, NCRYPT_KEY_HANDLE key);
};

}  // namespace ks::win
