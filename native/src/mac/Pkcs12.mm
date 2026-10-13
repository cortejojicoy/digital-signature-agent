// PKCS#12 parsing on macOS (pkcs12-key-storage-plan.md §5.2).
//
// SecPKCS12Import with kSecImportToMemoryOnly (macOS 15+) reads both the
// legacy 3DES / SHA-1 files that PNPKI issues and modern AES / SHA-256 ones,
// and returns the identity without adding anything to the login keychain.
// SecItemImport with no keychain, the only alternative on macOS 12–14,
// returns the certificates but drops the private key (spike S1), so
// importing a certificate needs macOS 15.

#import <Foundation/Foundation.h>

#include "Pkcs12.h"

#include "../common/encoding.h"

namespace ks::mac {
namespace {

Bytes toBytes(CFDataRef data) {
    const uint8_t* p = CFDataGetBytePtr(data);
    return Bytes(p, p + CFDataGetLength(data));
}

Bytes certificateDer(SecCertificateRef cert) {
    CFDataRef der = SecCertificateCopyData(cert);
    Bytes out = toBytes(der);
    CFRelease(der);
    return out;
}

// errSecDecode etc. say "not a PKCS#12 file"; errSecAuthFailed / errSecPkcs12VerifyFailure say "wrong password".
[[noreturn]] void failImport(OSStatus status) {
    if (status == errSecAuthFailed || status == errSecPkcs12VerifyFailure || status == errSecPassphraseRequired) {
        throw Error(ErrorCode::BadPassword, "the password doesn't open this file");
    }
    if (status == errSecDecode || status == errSecUnknownFormat || status == errSecInvalidData) {
        throw Error(ErrorCode::BadFile, "this isn't a PKCS#12 file");
    }
    throw Error(ErrorCode::BadFile, "could not read the PKCS#12 file (OSStatus " + std::to_string(status) + ")");
}

}  // namespace

void ParsedPkcs12::secureZeroKey() {
    secureZero(privateKey);
}

bool pkcs12Supported() {
    if (@available(macOS 15.0, *)) return true;
    return false;
}

Algorithm algorithmForKey(SecKeyRef key, int* bits) {
    NSDictionary* attrs = (__bridge_transfer NSDictionary*)SecKeyCopyAttributes(key);
    const int size = [attrs[(id)kSecAttrKeySizeInBits] intValue];
    if (bits) *bits = size;
    id type = attrs[(id)kSecAttrKeyType];
    if ([type isEqual:(id)kSecAttrKeyTypeRSA]) {
        if (size < 2048) throw Error(ErrorCode::Unsupported, "RSA keys must be at least 2048 bits");
        return Algorithm::RS256;
    }
    if ([type isEqual:(id)kSecAttrKeyTypeECSECPrimeRandom] && size == 256) return Algorithm::ES256;
    throw Error(ErrorCode::Unsupported, "only RSA (2048 bits or more) and P-256 keys are supported");
}

Bytes spkiForPublicKey(SecKeyRef publicKey) {
    const Algorithm algorithm = algorithmForKey(publicKey);
    CFErrorRef error = nullptr;
    CFDataRef raw = SecKeyCopyExternalRepresentation(publicKey, &error);
    if (raw == nullptr) {
        if (error) CFRelease(error);
        throw Error(ErrorCode::Internal, "could not read the public key");
    }
    Bytes bytes = toBytes(raw);
    CFRelease(raw);
    // RSA: PKCS#1 RSAPublicKey. EC: X9.63 point (04 || X || Y).
    return algorithm == Algorithm::RS256 ? rsaSpkiFromPkcs1(bytes) : p256SpkiFromX963(bytes);
}

ParsedPkcs12 parsePkcs12(const Bytes& data, const std::string& password, bool withKey) {
    if (data.empty() || data.size() > kMaxPkcs12Size) throw Error(ErrorCode::BadFile, "the file is empty or too large");
    if (!pkcs12Supported()) {
        throw Error(ErrorCode::Unsupported, "importing a certificate needs macOS 15 or later");
    }

    ParsedPkcs12 parsed;
    @autoreleasepool {
        NSData* blob = [NSData dataWithBytes:data.data() length:data.size()];
        NSString* passphrase = [[NSString alloc] initWithBytes:password.data()
                                                        length:password.size()
                                                      encoding:NSUTF8StringEncoding];
        if (passphrase == nil) throw Error(ErrorCode::BadPassword, "the password isn't valid UTF-8");

        NSMutableDictionary* options = [@{(id)kSecImportExportPassphrase : passphrase} mutableCopy];
        if (@available(macOS 15.0, *)) options[(id)kSecImportToMemoryOnly] = @YES;

        CFArrayRef items = nullptr;
        OSStatus status = SecPKCS12Import((__bridge CFDataRef)blob, (__bridge CFDictionaryRef)options, &items);
        if (status != errSecSuccess) failImport(status);
        NSArray* results = (__bridge_transfer NSArray*)items;

        SecIdentityRef identity = nullptr;
        NSArray* chain = nil;
        for (NSDictionary* item in results) {
            id found = item[(id)kSecImportItemIdentity];
            if (found == nil) continue;
            if (identity != nullptr) throw Error(ErrorCode::BadFile, "the file holds more than one private key");
            identity = (__bridge SecIdentityRef)found;
            chain = item[(id)kSecImportItemCertChain];
        }
        if (identity == nullptr) throw Error(ErrorCode::BadFile, "the file has no private key");

        SecCertificateRef leaf = nullptr;
        if (SecIdentityCopyCertificate(identity, &leaf) != errSecSuccess || leaf == nullptr) {
            throw Error(ErrorCode::BadFile, "the private key has no certificate");
        }
        Bytes leafDer = certificateDer(leaf);
        SecKeyRef leafKey = SecCertificateCopyKey(leaf);
        CFRelease(leaf);
        if (leafKey == nullptr) throw Error(ErrorCode::Unsupported, "the certificate's key type isn't supported");

        SecKeyRef privateKey = nullptr;
        if (SecIdentityCopyPrivateKey(identity, &privateKey) != errSecSuccess || privateKey == nullptr) {
            CFRelease(leafKey);
            throw Error(ErrorCode::BadFile, "could not read the private key");
        }

        try {
            parsed.contents.algorithm = algorithmForKey(privateKey, &parsed.contents.keyBits);
            parsed.spki = spkiForPublicKey(leafKey);

            // The private key must belong to the certificate.
            SecKeyRef derived = SecKeyCopyPublicKey(privateKey);
            if (derived == nullptr) throw Error(ErrorCode::BadFile, "could not read the private key");
            Bytes derivedSpki;
            try {
                derivedSpki = spkiForPublicKey(derived);
            } catch (...) {
                CFRelease(derived);
                throw;
            }
            CFRelease(derived);
            if (derivedSpki != parsed.spki) {
                throw Error(ErrorCode::KeyMismatch, "the private key doesn't match the certificate");
            }

            if (withKey) {
                CFErrorRef error = nullptr;
                CFDataRef raw = SecKeyCopyExternalRepresentation(privateKey, &error);
                if (raw == nullptr) {
                    if (error) CFRelease(error);
                    throw Error(ErrorCode::Internal, "could not read the private key");
                }
                // Security.framework's own copy can't be wiped; ours is, by the destructor.
                parsed.privateKey = toBytes(raw);
                CFRelease(raw);
            }
        } catch (...) {
            CFRelease(privateKey);
            CFRelease(leafKey);
            throw;
        }
        CFRelease(privateKey);
        CFRelease(leafKey);

        parsed.contents.chain.push_back(leafDer);
        for (id cert in chain ?: @[]) {
            Bytes der = certificateDer((__bridge SecCertificateRef)cert);
            if (der != leafDer) parsed.contents.chain.push_back(std::move(der));
        }
    }
    return parsed;
}

}  // namespace ks::mac
