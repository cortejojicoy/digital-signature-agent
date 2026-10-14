// Crypto for certificate key files on Windows (CertKeyFile.h;
// certificate-password-pairing-plan.md §6.2): BCrypt PBKDF2 and AES-GCM for
// the password layer, DPAPI for the outer layer, and signing with a private
// key blob held only in memory.

#include "WinStores.h"

#include <wincrypt.h>

#include <cstdio>

#include "../common/CertKeyFile.h"
#include "../common/encoding.h"

namespace ks {
namespace {

constexpr size_t kNonceLength = 12;
constexpr size_t kTagLength = 16;

[[noreturn]] void fail(const char* what, NTSTATUS status) {
    char buf[128];
    std::snprintf(buf, sizeof(buf), "%s failed (0x%08lx)", what, static_cast<unsigned long>(status));
    throw Error(ErrorCode::Internal, buf);
}

struct Algorithm_ {
    BCRYPT_ALG_HANDLE h = nullptr;
    Algorithm_(LPCWSTR name, ULONG flags = 0) {
        NTSTATUS s = BCryptOpenAlgorithmProvider(&h, name, nullptr, flags);
        if (s != 0) fail("BCryptOpenAlgorithmProvider", s);
    }
    ~Algorithm_() {
        if (h) BCryptCloseAlgorithmProvider(h, 0);
    }
};

struct KeyHandle {
    BCRYPT_KEY_HANDLE h = nullptr;
    ~KeyHandle() {
        if (h) BCryptDestroyKey(h);
    }
};

// AES-256-GCM with `key`; encrypts or decrypts `in` in place of `out`.
// Returns false when decryption's tag doesn't verify.
bool aesGcm(const Bytes& key, bool encrypt, const uint8_t* nonce, const uint8_t* in, size_t inLength, uint8_t* out,
            uint8_t* tag) {
    Algorithm_ aes(BCRYPT_AES_ALGORITHM);
    NTSTATUS s = BCryptSetProperty(aes.h, BCRYPT_CHAINING_MODE, reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
                                   sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (s != 0) fail("BCryptSetProperty (GCM)", s);
    KeyHandle handle;
    s = BCryptGenerateSymmetricKey(aes.h, &handle.h, nullptr, 0, const_cast<PUCHAR>(key.data()), static_cast<ULONG>(key.size()), 0);
    if (s != 0) fail("BCryptGenerateSymmetricKey", s);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = const_cast<PUCHAR>(nonce);
    info.cbNonce = static_cast<ULONG>(kNonceLength);
    info.pbTag = tag;
    info.cbTag = static_cast<ULONG>(kTagLength);
    ULONG written = 0;
    if (encrypt) {
        s = BCryptEncrypt(handle.h, const_cast<PUCHAR>(in), static_cast<ULONG>(inLength), &info, nullptr, 0, out,
                          static_cast<ULONG>(inLength), &written, 0);
        if (s != 0) fail("BCryptEncrypt", s);
        return true;
    }
    s = BCryptDecrypt(handle.h, const_cast<PUCHAR>(in), static_cast<ULONG>(inLength), &info, nullptr, 0, out,
                      static_cast<ULONG>(inLength), &written, 0);
    if (s == static_cast<NTSTATUS>(0xC000A002L) /* STATUS_AUTH_TAG_MISMATCH */) return false;
    if (s != 0) fail("BCryptDecrypt", s);
    return true;
}

}  // namespace

Bytes randomBytes(size_t length) {
    Bytes out(length);
    NTSTATUS s = BCryptGenRandom(nullptr, out.data(), static_cast<ULONG>(length), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (s != 0) fail("BCryptGenRandom", s);
    return out;
}

Bytes pbkdf2Sha256(const std::string& password, const Bytes& salt, uint32_t iterations, size_t length) {
    Algorithm_ hmac(BCRYPT_SHA256_ALGORITHM, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    Bytes out(length);
    // An empty password is a valid PKCS#12 password; BCrypt wants a non-null pointer.
    static UCHAR empty = 0;
    NTSTATUS s = BCryptDeriveKeyPBKDF2(
        hmac.h, password.empty() ? &empty : reinterpret_cast<PUCHAR>(const_cast<char*>(password.data())),
        static_cast<ULONG>(password.size()), const_cast<PUCHAR>(salt.data()), static_cast<ULONG>(salt.size()), iterations,
        out.data(), static_cast<ULONG>(out.size()), 0);
    if (s != 0) fail("BCryptDeriveKeyPBKDF2", s);
    return out;
}

Bytes aesGcmSeal(const Bytes& key, const Bytes& plain) {
    Bytes box = randomBytes(kNonceLength);
    box.resize(kNonceLength + plain.size() + kTagLength);
    aesGcm(key, true, box.data(), plain.data(), plain.size(), box.data() + kNonceLength,
           box.data() + kNonceLength + plain.size());
    return box;
}

std::optional<Bytes> aesGcmOpen(const Bytes& key, const Bytes& box) {
    if (box.size() < kNonceLength + kTagLength) return std::nullopt;
    const size_t length = box.size() - kNonceLength - kTagLength;
    Bytes plain(length);
    Bytes tag(box.end() - kTagLength, box.end());
    if (!aesGcm(key, false, box.data(), box.data() + kNonceLength, length, plain.data(), tag.data())) {
        secureZero(plain);
        return std::nullopt;
    }
    return plain;
}

namespace win {

Bytes dpapiProtect(const Bytes& plain) {
    DATA_BLOB in{static_cast<DWORD>(plain.size()), const_cast<BYTE*>(plain.data())};
    DATA_BLOB out{};
    if (!CryptProtectData(&in, L"Kukux Sign Agent certificate", nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out)) {
        fail("CryptProtectData", static_cast<NTSTATUS>(GetLastError()));
    }
    Bytes sealed(out.pbData, out.pbData + out.cbData);
    LocalFree(out.pbData);
    return sealed;
}

Bytes dpapiUnprotect(const Bytes& sealed) {
    DATA_BLOB in{static_cast<DWORD>(sealed.size()), const_cast<BYTE*>(sealed.data())};
    DATA_BLOB out{};
    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out)) {
        // Another user's or another computer's file, or a damaged one.
        fail("CryptUnprotectData", static_cast<NTSTATUS>(GetLastError()));
    }
    Bytes plain(out.pbData, out.pbData + out.cbData);
    SecureZeroMemory(out.pbData, out.cbData);
    LocalFree(out.pbData);
    return plain;
}

Bytes signWithBlob(LPCWSTR blobType, const Bytes& blob, Algorithm algorithm, const Bytes& message) {
    const bool rsa = algorithm == Algorithm::RS256;
    Algorithm_ alg(rsa ? BCRYPT_RSA_ALGORITHM : BCRYPT_ECDSA_P256_ALGORITHM);
    KeyHandle key;
    NTSTATUS s = BCryptImportKeyPair(alg.h, nullptr, blobType, &key.h, const_cast<PUCHAR>(blob.data()),
                                     static_cast<ULONG>(blob.size()), 0);
    if (s != 0) fail("BCryptImportKeyPair", s);

    Bytes digest = sha256(message);
    BCRYPT_PKCS1_PADDING_INFO pkcs1{BCRYPT_SHA256_ALGORITHM};
    void* padding = rsa ? &pkcs1 : nullptr;
    const ULONG flags = rsa ? BCRYPT_PAD_PKCS1 : 0;
    ULONG size = 0;
    s = BCryptSignHash(key.h, padding, digest.data(), static_cast<ULONG>(digest.size()), nullptr, 0, &size, flags);
    if (s != 0) fail("BCryptSignHash (size)", s);
    Bytes signature(size);
    s = BCryptSignHash(key.h, padding, digest.data(), static_cast<ULONG>(digest.size()), signature.data(), size, &size, flags);
    if (s != 0) fail("BCryptSignHash", s);
    signature.resize(size);
    // RSA: PKCS#1 v1.5 as Hello keys give. ECDSA: raw r || s → DER, as every platform sends.
    return rsa ? signature : ecdsaRawToDer(signature);
}

}  // namespace win
}  // namespace ks
