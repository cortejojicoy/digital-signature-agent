// macOS key store (desktop-agent-plan.md §5).
//
// Order of preference when creating a key:
//   1. Secure Enclave key in the data-protection keychain, with an access
//      control that requires user presence for the identity key. Needs the
//      keychain-access-groups entitlement (a paid Developer ID build).
//   2. Secure Enclave key outside the keychain (SecureEnclaveBlob.swift): the
//      same chip and the same access control, stored as an SE-wrapped blob in
//      keyDirectory(). Works in free, ad-hoc signed builds.
//   3. Software key in the data-protection keychain with the same access
//      control (Intel Macs without a T2 chip, VMs, in signed builds).
//   4. Non-extractable software key in the legacy file keychain: no Secure
//      Enclave and no entitlement. This is also what CI runs against. It
//      can't carry an access control, so userPresence = false.
//
// Whether a keychain key requires presence can't be read back from its
// SecAccessControl, so it's recorded in the item's label ("kukuxsign|presence=1").

#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <Security/Security.h>

#include <sys/stat.h>

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <mutex>

#include "../common/encoding.h"
#include "keystore.h"

// SecureEnclaveBlob.swift. Buffers returned through out-parameters are
// released with kse_free().
extern "C" {
bool kse_available(void);
int32_t kse_create(bool requirePresence, bool biometryOnly, uint8_t** blob, long* blobLen, uint8_t** spki,
                   long* spkiLen, char* err, long errSize);
int32_t kse_public_key(const uint8_t* blob, long blobLen, uint8_t** spki, long* spkiLen, char* err, long errSize);
int32_t kse_sign(const uint8_t* blob, long blobLen, const uint8_t* message, long messageLen, const char* reason,
                 uint8_t** sig, long* sigLen, char* err, long errSize);
int32_t kse_seal_key_create(uint8_t** blob, long* blobLen, char* err, long errSize);
int32_t kse_seal(const uint8_t* blob, long blobLen, const uint8_t* plain, long plainLen, uint8_t** out, long* outLen,
                 char* err, long errSize);
int32_t kse_open(const uint8_t* blob, long blobLen, const uint8_t* sealed, long sealedLen, uint8_t** out, long* outLen,
                 char* err, long errSize);
void kse_free(void* pointer);
}

namespace ks {
namespace {

constexpr int32_t kKseOk = 0;
constexpr int32_t kKseCancelled = 1;

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

// ── Secure Enclave blob files ──
//
// <keyDirectory()>/<keyId>.sekey = "KSE1" | presence (1 byte) | SE blob.
// The blob is only usable by this Mac's Secure Enclave; the files are 0600
// in a 0700 directory anyway.

struct BlobKey {
    Bytes blob;
    bool userPresence = false;
};

const char kBlobMagic[4] = {'K', 'S', 'E', '1'};

std::string blobPath(const std::string& keyId) {
    return keyDirectory() + "/" + keyId + ".sekey";
}

Bytes takeBuffer(uint8_t* data, long length) {
    Bytes out(data, data + length);
    kse_free(data);
    return out;
}

std::optional<BlobKey> readBlob(const std::string& keyId) {
    std::ifstream in(blobPath(keyId), std::ios::binary);
    if (!in) return std::nullopt;
    Bytes raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (raw.size() < 6 || !std::equal(kBlobMagic, kBlobMagic + 4, raw.begin())) {
        throw Error(ErrorCode::Internal, "corrupt key file: " + blobPath(keyId));
    }
    return BlobKey{Bytes(raw.begin() + 5, raw.end()), raw[4] == 1};
}

void writeBlob(const std::string& keyId, const BlobKey& key) {
    @autoreleasepool {
        NSString* dir = [NSString stringWithUTF8String:keyDirectory().c_str()];
        NSError* error = nil;
        if (![[NSFileManager defaultManager] createDirectoryAtPath:dir
                                       withIntermediateDirectories:YES
                                                        attributes:@{NSFilePosixPermissions : @0700}
                                                             error:&error]) {
            throw Error(ErrorCode::Internal, std::string("could not create the key directory: ") +
                                                 error.localizedDescription.UTF8String);
        }
    }
    const std::string path = blobPath(keyId);
    const std::string tmp = path + ".tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) throw Error(ErrorCode::Internal, "could not write " + tmp);
        chmod(tmp.c_str(), 0600);
        out.write(kBlobMagic, 4);
        out.put(key.userPresence ? 1 : 0);
        out.write(reinterpret_cast<const char*>(key.blob.data()), static_cast<std::streamsize>(key.blob.size()));
        if (!out) throw Error(ErrorCode::Internal, "could not write " + tmp);
    }
    if (std::rename(tmp.c_str(), path.c_str()) != 0) {
        std::remove(tmp.c_str());
        throw Error(ErrorCode::Internal, "could not write " + path);
    }
}

KeyInfo blobInfo(const std::string& keyId, const BlobKey& key) {
    uint8_t* spki = nullptr;
    long spkiLen = 0;
    char err[512] = {0};
    if (kse_public_key(key.blob.data(), static_cast<long>(key.blob.size()), &spki, &spkiLen, err, sizeof err) != kKseOk) {
        throw Error(ErrorCode::Internal, std::string("could not load the Secure Enclave key: ") + err);
    }
    KeyInfo info;
    info.keyId = keyId;
    info.algorithm = Algorithm::ES256;
    info.spki = takeBuffer(spki, spkiLen);
    info.protection = Protection::SecureEnclave;
    info.userPresence = key.userPresence;
    return info;
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
            // Either route to the Secure Enclave counts: the keychain (signed
            // builds) or SE blobs (any build).
            caps.hardware = kse_available() || (dataProtectionAvailable() && secureEnclavePresent());
            LAContext* ctx = [LAContext new];
            caps.userPresence = (caps.hardware || dataProtectionAvailable()) &&
                                [ctx canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:nil];
            caps.attestation = false;  // no third-party SE attestation for macOS apps (§5.5)
            return caps;
        }
    }

    KeyInfo create(const CreateOptions& opts) override {
        @autoreleasepool {
            if (lookup(opts.keyId, nil) || (backend_ == Backend::Auto && readBlob(opts.keyId))) {
                throw Error(ErrorCode::Exists, "a key with this id already exists");
            }

            std::string lastError;
            if (backend_ == Backend::Auto) {
                if (auto info = createProtected(opts, /*secureEnclave=*/true, lastError)) return *info;
                if (auto info = createBlob(opts, lastError)) return *info;
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
            if (auto found = lookup(keyId, nil)) return infoFor(keyId, *found);
            if (backend_ == Backend::Auto) {
                if (auto blob = readBlob(keyId)) return blobInfo(keyId, *blob);
            }
            return std::nullopt;
        }
    }

    Bytes sign(const std::string& keyId, const Bytes& message, const std::string& reason,
               void* /*parentWindow*/) override {
        @autoreleasepool {
            LAContext* ctx = [LAContext new];
            ctx.localizedReason = [NSString stringWithUTF8String:reason.c_str()] ?: @"sign";
            auto found = lookup(keyId, ctx);
            if (!found) {
                if (backend_ == Backend::Auto) {
                    if (auto blob = readBlob(keyId)) return signBlob(*blob, message, reason);
                }
                throw Error(ErrorCode::NotFound, "key not found");
            }

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
            std::remove(blobPath(keyId).c_str());
        }
    }

    bool privateKeyExportable(const std::string& keyId) override {
        @autoreleasepool {
            auto found = lookup(keyId, nil);
            if (!found) {
                // An SE blob is wrapped by the Secure Enclave; the private key
                // itself never exists outside the chip.
                if (backend_ == Backend::Auto && readBlob(keyId)) return false;
                throw Error(ErrorCode::NotFound, "key not found");
            }
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

    std::optional<KeyInfo> createBlob(const CreateOptions& opts, std::string& lastError) {
        if (!kse_available()) return std::nullopt;
        uint8_t *blob = nullptr, *spki = nullptr;
        long blobLen = 0, spkiLen = 0;
        char err[512] = {0};
        if (kse_create(opts.requireUserPresence, opts.biometryOnly, &blob, &blobLen, &spki, &spkiLen, err, sizeof err) !=
            kKseOk) {
            lastError = err;
            return std::nullopt;
        }
        BlobKey key{takeBuffer(blob, blobLen), opts.requireUserPresence};
        Bytes spkiBytes = takeBuffer(spki, spkiLen);
        writeBlob(opts.keyId, key);

        KeyInfo info;
        info.keyId = opts.keyId;
        info.algorithm = Algorithm::ES256;
        info.spki = std::move(spkiBytes);
        info.protection = Protection::SecureEnclave;
        info.userPresence = opts.requireUserPresence;
        return info;
    }

    static Bytes signBlob(const BlobKey& key, const Bytes& message, const std::string& reason) {
        uint8_t* sig = nullptr;
        long sigLen = 0;
        char err[512] = {0};
        const int32_t status = kse_sign(key.blob.data(), static_cast<long>(key.blob.size()), message.data(),
                                        static_cast<long>(message.size()), reason.c_str(), &sig, &sigLen, err, sizeof err);
        if (status == kKseCancelled) throw Error(ErrorCode::Cancelled, err);
        if (status != kKseOk) throw Error(ErrorCode::Internal, err);
        return takeBuffer(sig, sigLen);  // X9.62 DER, same as the keychain path
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

// ── Sealing (agent tokens) ──

namespace {
std::mutex g_sealMutex;  // not the addon mutex: that one is held during OS prompts
const char* const kSealKeyId = "_token-seal";

BlobKey sealKey() {
    if (auto key = readBlob(kSealKeyId)) return *key;
    uint8_t* blob = nullptr;
    long blobLen = 0;
    char err[512] = {0};
    if (kse_seal_key_create(&blob, &blobLen, err, sizeof err) != kKseOk) {
        throw Error(ErrorCode::Unsupported, std::string("could not create the sealing key: ") + err);
    }
    BlobKey key{takeBuffer(blob, blobLen), false};
    writeBlob(kSealKeyId, key);
    return key;
}
}  // namespace

bool sealingAvailable() {
    return kse_available();
}

Bytes sealData(const Bytes& plain) {
    std::lock_guard<std::mutex> lock(g_sealMutex);
    BlobKey key = sealKey();
    uint8_t* out = nullptr;
    long outLen = 0;
    char err[512] = {0};
    if (kse_seal(key.blob.data(), static_cast<long>(key.blob.size()), plain.data(), static_cast<long>(plain.size()), &out,
                 &outLen, err, sizeof err) != kKseOk) {
        throw Error(ErrorCode::Internal, std::string("seal failed: ") + err);
    }
    return takeBuffer(out, outLen);
}

Bytes openData(const Bytes& sealed) {
    std::lock_guard<std::mutex> lock(g_sealMutex);
    auto key = readBlob(kSealKeyId);
    if (!key) throw Error(ErrorCode::NotFound, "no sealing key on this machine");
    uint8_t* out = nullptr;
    long outLen = 0;
    char err[512] = {0};
    if (kse_open(key->blob.data(), static_cast<long>(key->blob.size()), sealed.data(), static_cast<long>(sealed.size()),
                 &out, &outLen, err, sizeof err) != kKseOk) {
        throw Error(ErrorCode::Internal, std::string("open failed: ") + err);
    }
    return takeBuffer(out, outLen);
}

std::unique_ptr<KeyStore> createPlatformKeyStore(Backend backend) {
    return std::make_unique<SecureEnclaveKeyStore>(backend);
}

}  // namespace ks
