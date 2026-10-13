// TPM (Platform Crypto Provider) and software (Key Storage Provider) keys via
// CNG (desktop-agent-plan.md §6.2). Keys imported from a .p12 can be RSA
// (pkcs12-key-storage-plan.md §5.3).

#include "WinStores.h"

#include <cstdio>
#include <cwchar>

#include "../common/encoding.h"

namespace ks::win {
namespace {

struct KeyHandle {
    NCRYPT_KEY_HANDLE h = 0;
    ~KeyHandle() {
        if (h) NCryptFreeObject(h);
    }
    void release() { h = 0; }  // after NCryptDeleteKey, which frees the handle
};

std::string status(const char* what, SECURITY_STATUS s) {
    char buf[128];
    std::snprintf(buf, sizeof(buf), "%s failed (0x%08lx)", what, static_cast<unsigned long>(s));
    return buf;
}

[[noreturn]] void fail(const char* what, SECURITY_STATUS s) {
    throw Error(ErrorCode::Internal, status(what, s));
}

bool isMissing(SECURITY_STATUS s) {
    return s == NTE_BAD_KEYSET || s == NTE_NO_KEY || s == NTE_NOT_FOUND;
}

bool isCancelled(SECURITY_STATUS s) {
    return s == NTE_USER_CANCELLED || s == HRESULT_FROM_WIN32(ERROR_CANCELLED);
}

bool isRsa(NCRYPT_KEY_HANDLE key) {
    wchar_t group[32] = {0};
    DWORD size = 0;
    if (NCryptGetProperty(key, NCRYPT_ALGORITHM_GROUP_PROPERTY, reinterpret_cast<PBYTE>(group), sizeof(group) - sizeof(wchar_t),
                          &size, 0) != ERROR_SUCCESS) {
        return false;
    }
    return std::wcscmp(group, NCRYPT_RSA_ALGORITHM_GROUP) == 0;
}

// Whether Windows asks for the key's password on every use.
bool strongProtection(NCRYPT_KEY_HANDLE key) {
    DWORD size = 0;
    if (NCryptGetProperty(key, NCRYPT_UI_POLICY_PROPERTY, nullptr, 0, &size, 0) != ERROR_SUCCESS || size < sizeof(NCRYPT_UI_POLICY)) {
        return false;
    }
    Bytes buffer(size);
    if (NCryptGetProperty(key, NCRYPT_UI_POLICY_PROPERTY, buffer.data(), size, &size, 0) != ERROR_SUCCESS) return false;
    return (reinterpret_cast<const NCRYPT_UI_POLICY*>(buffer.data())->dwFlags & NCRYPT_UI_FORCE_HIGH_PROTECTION_FLAG) != 0;
}

}  // namespace

CngKeyStore::CngKeyStore(LPCWSTR provider, Protection protection)
    : providerName_(provider), protection_(protection) {}

CngKeyStore::~CngKeyStore() {
    if (provider_) NCryptFreeObject(provider_);
}

bool CngKeyStore::available() {
    if (!opened_) {
        opened_ = true;
        available_ = NCryptOpenStorageProvider(&provider_, providerName_, 0) == ERROR_SUCCESS;
    }
    return available_;
}

KeyInfo CngKeyStore::create(const std::string& keyId) {
    if (!available()) throw Error(ErrorCode::Unsupported, "key storage provider unavailable");
    KeyHandle key;
    std::wstring name = widen(keyId);
    SECURITY_STATUS s = NCryptCreatePersistedKey(provider_, &key.h, BCRYPT_ECDSA_P256_ALGORITHM,
                                                 name.c_str(), 0, 0);
    if (s == NTE_EXISTS) throw Error(ErrorCode::Exists, "a key with this id already exists");
    if (s != ERROR_SUCCESS) fail("NCryptCreatePersistedKey", s);

    // NCRYPT_ALLOW_EXPORT_FLAG is never set. The PCP rejects the property
    // (its keys are never exportable), so a failure here is fine.
    DWORD exportPolicy = 0;
    NCryptSetProperty(key.h, NCRYPT_EXPORT_POLICY_PROPERTY, reinterpret_cast<PBYTE>(&exportPolicy),
                      sizeof(exportPolicy), NCRYPT_PERSIST_FLAG);
    DWORD usage = NCRYPT_ALLOW_SIGNING_FLAG;
    NCryptSetProperty(key.h, NCRYPT_KEY_USAGE_PROPERTY, reinterpret_cast<PBYTE>(&usage), sizeof(usage),
                      NCRYPT_PERSIST_FLAG);

    s = NCryptFinalizeKey(key.h, 0);
    if (s != ERROR_SUCCESS) {
        NCryptDeleteKey(key.h, 0);
        key.release();
        fail("NCryptFinalizeKey", s);
    }
    return infoFor(keyId, key.h);
}

KeyInfo CngKeyStore::importKey(const std::string& keyId, LPCWSTR blobType, const Bytes& blob, bool strongProtection) {
    if (!available()) throw Error(ErrorCode::Unsupported, "key storage provider unavailable");
    std::wstring name = widen(keyId);
    NCryptBuffer nameParam{static_cast<ULONG>((name.size() + 1) * sizeof(wchar_t)), NCRYPTBUFFER_PKCS_KEY_NAME, name.data()};
    NCryptBufferDesc params{NCRYPTBUFFER_VERSION, 1, &nameParam};

    KeyHandle key;
    // Not finalised yet, so the export policy and UI policy can still be set.
    SECURITY_STATUS s = NCryptImportKey(provider_, 0, blobType, &params, &key.h, const_cast<PBYTE>(blob.data()),
                                        static_cast<DWORD>(blob.size()), NCRYPT_DO_NOT_FINALIZE_FLAG);
    bool finalised = false;
    if (s == NTE_BAD_FLAGS || s == NTE_NOT_SUPPORTED) {
        // Some providers (the PCP) only import finalised keys; theirs are never exportable anyway.
        s = NCryptImportKey(provider_, 0, blobType, &params, &key.h, const_cast<PBYTE>(blob.data()),
                            static_cast<DWORD>(blob.size()), 0);
        finalised = true;
    }
    if (s == NTE_EXISTS) throw Error(ErrorCode::Exists, "a key with this id already exists");
    if (s != ERROR_SUCCESS) fail("NCryptImportKey", s);

    if (!finalised) {
        DWORD exportPolicy = 0;
        NCryptSetProperty(key.h, NCRYPT_EXPORT_POLICY_PROPERTY, reinterpret_cast<PBYTE>(&exportPolicy),
                          sizeof(exportPolicy), NCRYPT_PERSIST_FLAG);
        DWORD usage = NCRYPT_ALLOW_SIGNING_FLAG;
        NCryptSetProperty(key.h, NCRYPT_KEY_USAGE_PROPERTY, reinterpret_cast<PBYTE>(&usage), sizeof(usage),
                          NCRYPT_PERSIST_FLAG);
        if (strongProtection) {
            NCRYPT_UI_POLICY policy{};
            policy.dwVersion = 1;
            policy.dwFlags = NCRYPT_UI_FORCE_HIGH_PROTECTION_FLAG;
            policy.pszFriendlyName = L"Kukux Sign Agent certificate";
            policy.pszDescription = L"Your signing certificate. Windows asks for this password every time you sign.";
            s = NCryptSetProperty(key.h, NCRYPT_UI_POLICY_PROPERTY, reinterpret_cast<PBYTE>(&policy), sizeof(policy),
                                  NCRYPT_PERSIST_FLAG);
            if (s != ERROR_SUCCESS) {
                NCryptDeleteKey(key.h, 0);
                key.release();
                fail("NCryptSetProperty (UI policy)", s);
            }
        }
        // With strong protection, Windows asks the user to set the key's password here.
        s = NCryptFinalizeKey(key.h, 0);
        if (s != ERROR_SUCCESS) {
            NCryptDeleteKey(key.h, 0);
            key.release();
            if (isCancelled(s)) throw Error(ErrorCode::Cancelled, "cancelled");
            fail("NCryptFinalizeKey", s);
        }
    }
    KeyInfo info = infoFor(keyId, key.h);
    // A provider that ignored the key name made an ephemeral key, which would
    // vanish with this handle: fail now rather than at the first signature.
    KeyHandle persisted;
    if (NCryptOpenKey(provider_, &persisted.h, name.c_str(), 0, 0) != ERROR_SUCCESS) {
        throw Error(ErrorCode::Internal, "the imported key was not persisted");
    }
    return info;
}

std::optional<KeyInfo> CngKeyStore::find(const std::string& keyId) {
    if (!available()) return std::nullopt;
    KeyHandle key;
    std::wstring name = widen(keyId);
    SECURITY_STATUS s = NCryptOpenKey(provider_, &key.h, name.c_str(), 0, 0);
    if (isMissing(s)) return std::nullopt;
    if (s != ERROR_SUCCESS) fail("NCryptOpenKey", s);
    return infoFor(keyId, key.h);
}

Bytes CngKeyStore::sign(const std::string& keyId, const Bytes& message, HWND parent, const std::string& reason) {
    if (!available()) throw Error(ErrorCode::NotFound, "key not found");
    KeyHandle key;
    std::wstring name = widen(keyId);
    SECURITY_STATUS s = NCryptOpenKey(provider_, &key.h, name.c_str(), 0, 0);
    if (isMissing(s)) throw Error(ErrorCode::NotFound, "key not found");
    if (s != ERROR_SUCCESS) fail("NCryptOpenKey", s);

    // A password-protected (imported) key prompts: parent it and say why.
    if (parent) {
        NCryptSetProperty(key.h, NCRYPT_WINDOW_HANDLE_PROPERTY, reinterpret_cast<PBYTE>(&parent), sizeof(parent), 0);
    }
    if (!reason.empty()) {
        std::wstring context = widen(reason);
        NCryptSetProperty(key.h, NCRYPT_USE_CONTEXT_PROPERTY, reinterpret_cast<PBYTE>(context.data()),
                          static_cast<DWORD>((context.size() + 1) * sizeof(wchar_t)), 0);
    }

    // The addon hashes; callers only ever pass the message.
    Bytes digest = sha256(message);
    const bool rsa = isRsa(key.h);
    // RSA (imported keys): PKCS#1 v1.5 over SHA-256, the same output as Hello keys.
    BCRYPT_PKCS1_PADDING_INFO pkcs1{BCRYPT_SHA256_ALGORITHM};
    void* padding = rsa ? &pkcs1 : nullptr;
    const DWORD flags = rsa ? BCRYPT_PAD_PKCS1 : 0;
    DWORD size = 0;
    s = NCryptSignHash(key.h, padding, digest.data(), static_cast<DWORD>(digest.size()), nullptr, 0, &size, flags);
    if (s != ERROR_SUCCESS) fail("NCryptSignHash (size)", s);
    Bytes raw(size);
    s = NCryptSignHash(key.h, padding, digest.data(), static_cast<DWORD>(digest.size()), raw.data(), size, &size,
                       flags);
    if (isCancelled(s)) throw Error(ErrorCode::Cancelled, "cancelled");
    if (s != ERROR_SUCCESS) fail("NCryptSignHash", s);
    raw.resize(size);
    if (rsa) return raw;
    // CNG returns raw r || s; every platform sends DER to the server.
    return ecdsaRawToDer(raw);
}

void CngKeyStore::remove(const std::string& keyId) {
    if (!available()) return;
    KeyHandle key;
    std::wstring name = widen(keyId);
    if (NCryptOpenKey(provider_, &key.h, name.c_str(), 0, 0) != ERROR_SUCCESS) return;
    if (NCryptDeleteKey(key.h, 0) == ERROR_SUCCESS) key.release();
}

bool CngKeyStore::exportable(const std::string& keyId) {
    KeyHandle key;
    std::wstring name = widen(keyId);
    if (!available() || NCryptOpenKey(provider_, &key.h, name.c_str(), 0, 0) != ERROR_SUCCESS) {
        throw Error(ErrorCode::NotFound, "key not found");
    }
    DWORD size = 0;
    LPCWSTR type = isRsa(key.h) ? BCRYPT_RSAPRIVATE_BLOB : BCRYPT_ECCPRIVATE_BLOB;
    return NCryptExportKey(key.h, 0, type, nullptr, nullptr, 0, &size, 0) == ERROR_SUCCESS;
}

KeyInfo CngKeyStore::infoFor(const std::string& keyId, NCRYPT_KEY_HANDLE key) {
    if (isRsa(key)) {
        DWORD size = 0;
        SECURITY_STATUS s = NCryptExportKey(key, 0, BCRYPT_RSAPUBLIC_BLOB, nullptr, nullptr, 0, &size, 0);
        if (s != ERROR_SUCCESS) fail("NCryptExportKey (size)", s);
        Bytes blob(size);
        s = NCryptExportKey(key, 0, BCRYPT_RSAPUBLIC_BLOB, nullptr, blob.data(), size, &size, 0);
        if (s != ERROR_SUCCESS) fail("NCryptExportKey", s);
        // BCRYPT_RSAKEY_BLOB header, then the public exponent and the modulus, big-endian.
        auto* header = reinterpret_cast<const BCRYPT_RSAKEY_BLOB*>(blob.data());
        if (size < sizeof(BCRYPT_RSAKEY_BLOB) || size < sizeof(BCRYPT_RSAKEY_BLOB) + header->cbPublicExp + header->cbModulus) {
            throw Error(ErrorCode::Internal, "unexpected RSA public key blob");
        }
        const uint8_t* exponent = blob.data() + sizeof(BCRYPT_RSAKEY_BLOB);
        const uint8_t* modulus = exponent + header->cbPublicExp;

        KeyInfo info;
        info.keyId = keyId;
        info.algorithm = Algorithm::RS256;
        info.spki = rsaSpkiFromPkcs1(rsaPkcs1FromModExp(modulus, header->cbModulus, exponent, header->cbPublicExp));
        info.protection = protection_;
        info.userPresence = strongProtection(key);
        return info;
    }

    DWORD size = 0;
    SECURITY_STATUS s = NCryptExportKey(key, 0, BCRYPT_ECCPUBLIC_BLOB, nullptr, nullptr, 0, &size, 0);
    if (s != ERROR_SUCCESS) fail("NCryptExportKey (size)", s);
    Bytes blob(size);
    s = NCryptExportKey(key, 0, BCRYPT_ECCPUBLIC_BLOB, nullptr, blob.data(), size, &size, 0);
    if (s != ERROR_SUCCESS) fail("NCryptExportKey", s);

    // BCRYPT_ECCKEY_BLOB header, then X and Y (cbKey bytes each).
    auto* header = reinterpret_cast<const BCRYPT_ECCKEY_BLOB*>(blob.data());
    if (size < sizeof(BCRYPT_ECCKEY_BLOB) || header->cbKey != 32 ||
        size < sizeof(BCRYPT_ECCKEY_BLOB) + 2 * header->cbKey) {
        throw Error(ErrorCode::Internal, "unexpected ECC public key blob");
    }
    const uint8_t* xy = blob.data() + sizeof(BCRYPT_ECCKEY_BLOB);
    Bytes point;
    point.push_back(0x04);
    point.insert(point.end(), xy, xy + 64);

    KeyInfo info;
    info.keyId = keyId;
    info.algorithm = Algorithm::ES256;
    info.spki = p256SpkiFromX963(point);
    info.protection = protection_;
    info.userPresence = strongProtection(key);
    return info;
}

}  // namespace ks::win
