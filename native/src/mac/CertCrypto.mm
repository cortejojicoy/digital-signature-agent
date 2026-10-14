// Crypto primitives for the certificate password layer on macOS
// (CertKeyFile.h; certificate-password-pairing-plan.md §6.1).

#import <CommonCrypto/CommonCryptoError.h>
#import <CommonCrypto/CommonKeyDerivation.h>
#import <Security/Security.h>

#include "../common/CertKeyFile.h"
#include "../common/encoding.h"

extern "C" {
int32_t kse_gcm_seal(const uint8_t* key, const uint8_t* plain, long plainLen, uint8_t** out, long* outLen);
int32_t kse_gcm_open(const uint8_t* key, const uint8_t* box, long boxLen, uint8_t** out, long* outLen);
void kse_free(void* pointer);
}

namespace ks {

Bytes randomBytes(size_t length) {
    Bytes out(length);
    if (SecRandomCopyBytes(kSecRandomDefault, length, out.data()) != errSecSuccess) {
        throw Error(ErrorCode::Internal, "SecRandomCopyBytes failed");
    }
    return out;
}

Bytes pbkdf2Sha256(const std::string& password, const Bytes& salt, uint32_t iterations, size_t length) {
    Bytes out(length);
    if (CCKeyDerivationPBKDF(kCCPBKDF2, password.data(), password.size(), salt.data(), salt.size(), kCCPRFHmacAlgSHA256,
                             iterations, out.data(), out.size()) != kCCSuccess) {
        throw Error(ErrorCode::Internal, "PBKDF2 failed");
    }
    return out;
}

Bytes aesGcmSeal(const Bytes& key, const Bytes& plain) {
    if (key.size() != 32) throw Error(ErrorCode::Internal, "AES-256 needs a 32-byte key");
    uint8_t* out = nullptr;
    long outLen = 0;
    if (kse_gcm_seal(key.data(), plain.data(), static_cast<long>(plain.size()), &out, &outLen) != 0) {
        throw Error(ErrorCode::Internal, "AES-GCM seal failed");
    }
    Bytes box(out, out + outLen);
    kse_free(out);
    return box;
}

std::optional<Bytes> aesGcmOpen(const Bytes& key, const Bytes& box) {
    if (key.size() != 32) throw Error(ErrorCode::Internal, "AES-256 needs a 32-byte key");
    uint8_t* out = nullptr;
    long outLen = 0;
    if (kse_gcm_open(key.data(), box.data(), static_cast<long>(box.size()), &out, &outLen) != 0) return std::nullopt;
    Bytes plain(out, out + outLen);
    secureZero(out, static_cast<size_t>(outLen));
    kse_free(out);
    return plain;
}

}  // namespace ks
