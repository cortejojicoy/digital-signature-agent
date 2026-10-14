// Imported certificate keys, protected by the certificate's password
// (certificate-password-pairing-plan.md §6).
//
//   <keyDirectory()>/<keyId>.p12key =
//     "KP12" | version 2 | outer | algorithm
//     | u32 spki length | SPKI          (public, for find() without a password)
//     | u32 wrapping key length | wrapping key   (outer = SecureEnclave only)
//     | u32 iterations
//     | payload = outer( salt (16) | AES-256-GCM(PBKDF2-HMAC-SHA256(password, salt, iterations), private key) )
//
// The outer layer ties the file to this computer (Secure Enclave on macOS,
// DPAPI on Windows; none on the software backend). The inner layer needs the
// password: without it the key can't be decrypted, so a wrong password can't
// sign anything. Version 1 files (Touch ID-sealed, never released) are refused.
#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include "keystore.h"

namespace ks {

enum class CertOuter : uint8_t { None = 0, SecureEnclave = 1, Dpapi = 2 };

struct CertKeyFile {
    CertOuter outer = CertOuter::None;
    Algorithm algorithm = Algorithm::RS256;
    Bytes spki;
    Bytes wrappingKey;  // CertOuter::SecureEnclave: the SE key-agreement key blob
    uint32_t iterations = 0;
    Bytes payload;
};

std::string certKeyPath(const std::string& keyId);
// nullopt when there's no file. A version 1 file throws E_UNSUPPORTED.
std::optional<CertKeyFile> readCertKeyFile(const std::string& keyId);
void writeCertKeyFile(const std::string& keyId, const CertKeyFile& file);
void removeCertKeyFile(const std::string& keyId);

// The password layer, with the platform's crypto (CommonCrypto + CryptoKit on
// macOS, BCrypt on Windows). passwordOpen throws E_BAD_PASSWORD when the
// AES-GCM tag doesn't verify.
Bytes passwordSeal(const Bytes& plain, const std::string& password, uint32_t iterations);
Bytes passwordOpen(const Bytes& box, const std::string& password, uint32_t iterations);
// PBKDF2 rounds for about 250 ms here, at least 600,000.
uint32_t passwordIterations();

// Shared by the backends: the KeyInfo of an imported certificate key.
KeyInfo certKeyInfo(const std::string& keyId, const CertKeyFile& file);

// Platform primitives behind the password layer (Hash.cc / CertCrypto.cpp).
Bytes randomBytes(size_t length);
Bytes pbkdf2Sha256(const std::string& password, const Bytes& salt, uint32_t iterations, size_t length);
Bytes aesGcmSeal(const Bytes& key, const Bytes& plain);  // nonce (12) | ciphertext | tag (16)
// nullopt when the tag doesn't verify.
std::optional<Bytes> aesGcmOpen(const Bytes& key, const Bytes& box);

}  // namespace ks
