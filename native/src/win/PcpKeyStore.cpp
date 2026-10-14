// TPM (Platform Crypto Provider) and software (Key Storage Provider) keys via
// CNG (desktop-agent-plan.md §6.2).

#include "WinStores.h"

#include <cstdio>

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

std::optional<KeyInfo> CngKeyStore::find(const std::string& keyId) {
    if (!available()) return std::nullopt;
    KeyHandle key;
    std::wstring name = widen(keyId);
    SECURITY_STATUS s = NCryptOpenKey(provider_, &key.h, name.c_str(), 0, 0);
    if (isMissing(s)) return std::nullopt;
    if (s != ERROR_SUCCESS) fail("NCryptOpenKey", s);
    return infoFor(keyId, key.h);
}

Bytes CngKeyStore::sign(const std::string& keyId, const Bytes& message) {
    if (!available()) throw Error(ErrorCode::NotFound, "key not found");
    KeyHandle key;
    std::wstring name = widen(keyId);
    SECURITY_STATUS s = NCryptOpenKey(provider_, &key.h, name.c_str(), 0, 0);
    if (isMissing(s)) throw Error(ErrorCode::NotFound, "key not found");
    if (s != ERROR_SUCCESS) fail("NCryptOpenKey", s);

    // The addon hashes; callers only ever pass the message.
    Bytes digest = sha256(message);
    DWORD size = 0;
    s = NCryptSignHash(key.h, nullptr, digest.data(), static_cast<DWORD>(digest.size()), nullptr, 0, &size, 0);
    if (s != ERROR_SUCCESS) fail("NCryptSignHash (size)", s);
    Bytes raw(size);
    s = NCryptSignHash(key.h, nullptr, digest.data(), static_cast<DWORD>(digest.size()), raw.data(), size,
                       &size, 0);
    if (s == NTE_USER_CANCELLED) throw Error(ErrorCode::Cancelled, "cancelled");
    if (s != ERROR_SUCCESS) fail("NCryptSignHash", s);
    raw.resize(size);
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
    return NCryptExportKey(key.h, 0, BCRYPT_ECCPRIVATE_BLOB, nullptr, nullptr, 0, &size, 0) == ERROR_SUCCESS;
}

KeyInfo CngKeyStore::infoFor(const std::string& keyId, NCRYPT_KEY_HANDLE key) {
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
    info.userPresence = false;
    return info;
}

}  // namespace ks::win
