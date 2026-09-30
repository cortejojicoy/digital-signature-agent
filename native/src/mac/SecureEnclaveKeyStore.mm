// macOS key store (desktop-agent-plan.md §5).
//
// Order of preference when creating a key:
//   1. Secure Enclave key in the data-protection keychain, with an access
//      control that requires user presence for the identity key.
//   2. Software key in the data-protection keychain with the same access
//      control (Intel Macs without a T2 chip, VMs).
//   3. Non-extractable software key in the legacy file keychain. This is the
//      only option for an unsigned build (no keychain-access-groups
//      entitlement, errSecMissingEntitlement) and the one CI runs against.
//      It can't carry an access control, so userPresence = false.
//
// Whether a key requires presence can't be read back from its SecAccessControl,
// so it's recorded in the item's label ("kukuxsign|presence=1").

#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <Security/Security.h>

#include <cstdio>
#include <cstdlib>

#include "../common/encoding.h"
#include "keystore.h"

namespace ks {
namespace {

constexpr OSStatus kMissingEntitlement = -34018;  // errSecMissingEntitlement
NSString* const kLabelPresent = @"kukuxsign|presence=1";
NSString* const kLabelAbsent = @"kukuxsign|presence=0";

NSData* tagFor(const std::string& keyId) {
    return [NSData dataWithBytes:keyId.data() length:keyId.size()];
}

NSData* toNSData(const Bytes& bytes) {
    return [NSData dataWithBytes:bytes.data() length:bytes.size()];
}

Bytes toBytes(CFDataRef data) {
    const uint8_t* p = CFDataGetBytePtr(data);
    return Bytes(p, p + CFDataGetLength(data));
}

std::string describe(CFErrorRef error) {
    if (error == nullptr) return "unknown error";
    NSError* e = (__bridge NSError*)error;
    return std::string([[NSString stringWithFormat:@"%@ (%ld)", e.localizedDescription, (long)e.code]
                           UTF8String]);
}

bool isCancellation(CFErrorRef error) {
    NSError* e = (__bridge NSError*)error;
    if ([e.domain isEqualToString:LAErrorDomain]) {
        return e.code == LAErrorUserCancel || e.code == LAErrorSystemCancel ||
               e.code == LAErrorAppCancel || e.code == LAErrorAuthenticationFailed ||
               e.code == LAErrorUserFallback;
    }
    return e.code == errSecUserCanceled || e.code == errSecAuthFailed;
}

struct Found {
    SecKeyRef key = nullptr;  // +1, released by the owner
    bool secureEnclave = false;
    bool userPresence = false;

    Found() = default;
    Found(const Found&) = delete;
    Found& operator=(const Found&) = delete;
    Found(Found&& o) noexcept : key(o.key), secureEnclave(o.secureEnclave), userPresence(o.userPresence) {
        o.key = nullptr;
    }
    ~Found() {
        if (key) CFRelease(key);
    }
};

class SecureEnclaveKeyStore final : public KeyStore {
public:
    explicit SecureEnclaveKeyStore(Backend backend) : backend_(backend) {}

    Capabilities capabilities() override {
        @autoreleasepool {
            Capabilities caps;
            if (backend_ == Backend::Software) return caps;
            const bool dp = dataProtectionAvailable();
            caps.hardware = dp && secureEnclavePresent();
            LAContext* ctx = [LAContext new];
            caps.userPresence = dp && [ctx canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:nil];
            caps.attestation = false;  // no third-party SE attestation for macOS apps (§5.5)
            return caps;
        }
    }

    KeyInfo create(const CreateOptions& opts) override {
        @autoreleasepool {
            if (auto existing = lookup(opts.keyId, nil)) {
                throw Error(ErrorCode::Exists, "a key with this id already exists");
            }

            std::string lastError;
            if (backend_ == Backend::Auto) {
                if (auto info = createProtected(opts, /*secureEnclave=*/true, lastError)) return *info;
                if (auto info = createProtected(opts, /*secureEnclave=*/false, lastError)) return *info;
                if (std::getenv("KUKUX_KEYSTORE_DEBUG")) {
                    std::fprintf(stderr, "keystore: protected key creation failed, using legacy keychain: %s\n",
                                 lastError.c_str());
                }
            }
            return createLegacy(opts);
        }
    }

    std::optional<KeyInfo> find(const std::string& keyId) override {
        @autoreleasepool {
            auto found = lookup(keyId, nil);
            if (!found) return std::nullopt;
            return infoFor(keyId, *found);
        }
    }

    Bytes sign(const std::string& keyId, const Bytes& message, const std::string& reason,
               void* /*parentWindow*/) override {
        @autoreleasepool {
            LAContext* ctx = [LAContext new];
            ctx.localizedReason = [NSString stringWithUTF8String:reason.c_str()] ?: @"sign";
            auto found = lookup(keyId, ctx);
            if (!found) throw Error(ErrorCode::NotFound, "key not found");

            CFErrorRef error = nullptr;
            // Hashes with SHA-256 and returns an X9.62 DER signature, which
            // openssl_verify accepts as-is.
            CFDataRef sig = SecKeyCreateSignature(found->key,
                                                  kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
                                                  (__bridge CFDataRef)toNSData(message), &error);
            if (sig == nullptr) {
                const bool cancelled = isCancellation(error);
                std::string msg = describe(error);
                if (error) CFRelease(error);
                throw Error(cancelled ? ErrorCode::Cancelled : ErrorCode::Internal, msg);
            }
            Bytes out = toBytes(sig);
            CFRelease(sig);
            return out;
        }
    }

    std::optional<Attestation> attest(const std::string& keyId) override {
        if (!find(keyId)) throw Error(ErrorCode::NotFound, "key not found");
        return std::nullopt;  // hardware-protected, not attested (§5.5, §10.2)
    }

    void remove(const std::string& keyId) override {
        @autoreleasepool {
            for (bool dp : {true, false}) {
                NSDictionary* query = @{
                    (id)kSecClass : (id)kSecClassKey,
                    (id)kSecAttrApplicationTag : tagFor(keyId),
                    (id)kSecUseDataProtectionKeychain : @(dp),
                };
                // The legacy keychain deletes one match per call.
                for (int i = 0; i < 8; i++) {
                    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
                    if (status != errSecSuccess) break;
                }
            }
        }
    }

    bool privateKeyExportable(const std::string& keyId) override {
        @autoreleasepool {
            auto found = lookup(keyId, nil);
            if (!found) throw Error(ErrorCode::NotFound, "key not found");
            CFDataRef data = SecKeyCopyExternalRepresentation(found->key, nullptr);
            if (data == nullptr) return false;
            CFRelease(data);
            return true;
        }
    }

private:
    Backend backend_;

    std::optional<bool> dataProtection_;

    // The data-protection keychain needs the keychain-access-groups
    // entitlement plus an embedded provisioning profile (§5.5). Unsigned and
    // ad-hoc builds get errSecMissingEntitlement, but only on writes, so the
    // probe adds (and removes) a throwaway item. The result is cached.
    bool dataProtectionAvailable() {
        if (dataProtection_) return *dataProtection_;
        NSDictionary* item = @{
            (id)kSecClass : (id)kSecClassGenericPassword,
            (id)kSecAttrService : @"kukuxsign.probe",
            (id)kSecAttrAccount : @"probe",
            (id)kSecAttrAccessible : (id)kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            (id)kSecUseDataProtectionKeychain : @YES,
            (id)kSecValueData : [NSData data],
        };
        OSStatus status = SecItemAdd((__bridge CFDictionaryRef)item, nullptr);
        NSDictionary* query = @{
            (id)kSecClass : (id)kSecClassGenericPassword,
            (id)kSecAttrService : @"kukuxsign.probe",
            (id)kSecUseDataProtectionKeychain : @YES,
        };
        SecItemDelete((__bridge CFDictionaryRef)query);
        dataProtection_ = status == errSecSuccess || status == errSecDuplicateItem;
        return *dataProtection_;
    }

    // An ephemeral (non-permanent) Secure Enclave key needs no entitlement,
    // so it tells us whether the chip exists independently of signing.
    static bool secureEnclavePresent() {
        NSDictionary* attrs = @{
            (id)kSecAttrKeyType : (id)kSecAttrKeyTypeECSECPrimeRandom,
            (id)kSecAttrKeySizeInBits : @256,
            (id)kSecAttrTokenID : (id)kSecAttrTokenIDSecureEnclave,
            (id)kSecPrivateKeyAttrs : @{(id)kSecAttrIsPermanent : @NO},
        };
        CFErrorRef error = nullptr;
        SecKeyRef key = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attrs, &error);
        if (error) CFRelease(error);
        if (key == nullptr) return false;
        CFRelease(key);
        return true;
    }

    std::optional<Found> lookup(const std::string& keyId, LAContext* ctx) {
        for (bool dp : {true, false}) {
            if (dp && backend_ == Backend::Software) continue;
            NSMutableDictionary* query = [@{
                (id)kSecClass : (id)kSecClassKey,
                (id)kSecAttrKeyClass : (id)kSecAttrKeyClassPrivate,
                (id)kSecAttrApplicationTag : tagFor(keyId),
                (id)kSecUseDataProtectionKeychain : @(dp),
                (id)kSecReturnRef : @YES,
                (id)kSecReturnAttributes : @YES,
                (id)kSecMatchLimit : (id)kSecMatchLimitOne,
            } mutableCopy];
            if (ctx) query[(id)kSecUseAuthenticationContext] = ctx;

            CFTypeRef result = nullptr;
            OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
            if (status != errSecSuccess || result == nullptr) continue;

            NSDictionary* item = (__bridge_transfer NSDictionary*)result;
            id ref = item[(id)kSecValueRef];
            if (ref == nil) continue;

            Found found;
            found.key = (SecKeyRef)CFRetain((__bridge CFTypeRef)ref);
            found.secureEnclave = [item[(id)kSecAttrTokenID] isEqual:(id)kSecAttrTokenIDSecureEnclave];
            found.userPresence = [item[(id)kSecAttrLabel] isEqual:kLabelPresent];
            return found;
        }
        return std::nullopt;
    }

    KeyInfo infoFor(const std::string& keyId, const Found& found) {
        SecKeyRef pub = SecKeyCopyPublicKey(found.key);
        if (pub == nullptr) throw Error(ErrorCode::Internal, "could not derive the public key");
        CFErrorRef error = nullptr;
        // Raw X9.63 point (04 || X || Y), wrapped in SPKI below (§5.3).
        CFDataRef point = SecKeyCopyExternalRepresentation(pub, &error);
        CFRelease(pub);
        if (point == nullptr) {
            std::string msg = describe(error);
            if (error) CFRelease(error);
            throw Error(ErrorCode::Internal, msg);
        }
        KeyInfo info;
        info.keyId = keyId;
        info.algorithm = Algorithm::ES256;
        info.spki = p256SpkiFromX963(toBytes(point));
        CFRelease(point);
        info.protection = found.secureEnclave ? Protection::SecureEnclave : Protection::Software;
        info.userPresence = found.userPresence;
        return info;
    }

    std::optional<KeyInfo> createProtected(const CreateOptions& opts, bool secureEnclave,
                                           std::string& lastError) {
        SecAccessControlCreateFlags flags = 0;
        if (secureEnclave) flags |= kSecAccessControlPrivateKeyUsage;
        if (opts.requireUserPresence) {
            flags |= opts.biometryOnly ? kSecAccessControlBiometryCurrentSet
                                       : kSecAccessControlUserPresence;
        }

        CFErrorRef error = nullptr;
        SecAccessControlRef acl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,  // never syncs, never in backups
            flags, &error);
        if (acl == nullptr) {
            lastError = describe(error);
            if (error) CFRelease(error);
            return std::nullopt;
        }

        NSMutableDictionary* privateAttrs = [@{
            (id)kSecAttrIsPermanent : @YES,
            (id)kSecAttrApplicationTag : tagFor(opts.keyId),
            (id)kSecAttrLabel : opts.requireUserPresence ? kLabelPresent : kLabelAbsent,
            (id)kSecAttrAccessControl : (__bridge id)acl,
        } mutableCopy];
        if (!secureEnclave) privateAttrs[(id)kSecAttrIsExtractable] = @NO;

        NSMutableDictionary* attrs = [@{
            (id)kSecAttrKeyType : (id)kSecAttrKeyTypeECSECPrimeRandom,
            (id)kSecAttrKeySizeInBits : @256,
            (id)kSecUseDataProtectionKeychain : @YES,
            (id)kSecPrivateKeyAttrs : privateAttrs,
        } mutableCopy];
        if (secureEnclave) attrs[(id)kSecAttrTokenID] = (id)kSecAttrTokenIDSecureEnclave;

        SecKeyRef key = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attrs, &error);
        CFRelease(acl);
        if (key == nullptr) {
            lastError = describe(error);
            if (error) CFRelease(error);
            return std::nullopt;
        }
        CFRelease(key);

        auto found = lookup(opts.keyId, nil);
        if (!found) throw Error(ErrorCode::Internal, "key was created but can't be found");
        return infoFor(opts.keyId, *found);
    }

    KeyInfo createLegacy(const CreateOptions& opts) {
        NSDictionary* attrs = @{
            (id)kSecAttrKeyType : (id)kSecAttrKeyTypeECSECPrimeRandom,
            (id)kSecAttrKeySizeInBits : @256,
            (id)kSecUseDataProtectionKeychain : @NO,
            (id)kSecAttrIsExtractable : @NO,
            (id)kSecPrivateKeyAttrs : @{
                (id)kSecAttrIsPermanent : @YES,
                (id)kSecAttrIsExtractable : @NO,
                (id)kSecAttrApplicationTag : tagFor(opts.keyId),
                // No access control is possible here, so presence isn't enforced.
                (id)kSecAttrLabel : kLabelAbsent,
            },
            (id)kSecPublicKeyAttrs : @{(id)kSecAttrIsPermanent : @NO},
        };
        CFErrorRef error = nullptr;
        SecKeyRef key = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attrs, &error);
        if (key == nullptr) {
            std::string msg = describe(error);
            if (error) CFRelease(error);
            throw Error(ErrorCode::Internal, "could not create a keychain key: " + msg);
        }
        CFRelease(key);

        auto found = lookup(opts.keyId, nil);
        if (!found) throw Error(ErrorCode::Internal, "key was created but can't be found");
        return infoFor(opts.keyId, *found);
    }
};

}  // namespace

std::unique_ptr<KeyStore> createPlatformKeyStore(Backend backend) {
    return std::make_unique<SecureEnclaveKeyStore>(backend);
}

}  // namespace ks
