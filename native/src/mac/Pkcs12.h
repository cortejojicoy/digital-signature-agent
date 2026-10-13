// PKCS#12 parsing on macOS (pkcs12-key-storage-plan.md §5.2).
#pragma once

#import <Security/Security.h>

#include "keystore.h"

namespace ks::mac {

// A parsed .p12: its certificates and the one private key, in memory only.
struct ParsedPkcs12 {
    Pkcs12Contents contents;
    Bytes spki;        // the first certificate's SubjectPublicKeyInfo
    Bytes privateKey;  // SecKeyCopyExternalRepresentation: PKCS#1 (RSA) or X9.63 (EC). Wipe with secureZero.

    ParsedPkcs12() = default;
    ParsedPkcs12(const ParsedPkcs12&) = delete;
    ParsedPkcs12& operator=(const ParsedPkcs12&) = delete;
    ParsedPkcs12(ParsedPkcs12&&) = default;
    ~ParsedPkcs12() { secureZeroKey(); }
    void secureZeroKey();
};

// Whether SecPKCS12Import can import to memory only (macOS 15+). Earlier
// versions only offer imports that write the key to a keychain.
bool pkcs12Supported();

// Parses `data` with `password`. Writes nothing to any keychain. Throws
// E_BAD_PASSWORD, E_BAD_FILE, E_KEY_MISMATCH or E_UNSUPPORTED.
// `withKey` false skips exporting the private key (inspect).
ParsedPkcs12 parsePkcs12(const Bytes& data, const std::string& password, bool withKey);

// SubjectPublicKeyInfo DER for an RSA or P-256 public key.
Bytes spkiForPublicKey(SecKeyRef publicKey);

// Algorithm of an RSA (≥ 2048) or P-256 key; E_UNSUPPORTED otherwise.
Algorithm algorithmForKey(SecKeyRef key, int* bits = nullptr);

}  // namespace ks::mac
