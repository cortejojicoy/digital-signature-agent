// Encoding helpers shared by every backend.
#pragma once

#include "keystore.h"

namespace ks {

// Wraps a raw uncompressed P-256 point (04 || X || Y, 65 bytes, as returned by
// SecKeyCopyExternalRepresentation / BCRYPT_ECCPUBLIC_BLOB) in the fixed
// SubjectPublicKeyInfo header (id-ecPublicKey + prime256v1).
Bytes p256SpkiFromX963(const Bytes& point);

// Converts a raw IEEE P1363 ECDSA signature (r || s, 64 bytes for P-256, as
// returned by NCryptSignHash) into ASN.1 DER, the format openssl_verify wants.
Bytes ecdsaRawToDer(const Bytes& rs);

std::string hexEncode(const Bytes& data);

// Platform-specific (CommonCrypto on macOS, BCrypt on Windows).
Bytes sha256(const Bytes& data);

// sha256_hex(salt_utf8 || uuid_utf8). The raw hardware UUID never leaves the
// addon (desktop-agent-plan.md §10.4). "" for no UUID or a firmware
// placeholder shared by many boards.
std::string saltedHardwareHash(const std::string& salt, const std::string& uuid);

}  // namespace ks
