// PKCS#12 parsing on Windows (pkcs12-key-storage-plan.md §5.3).
//
// PFXImportCertStore reads both the legacy 3DES / SHA-1 files PNPKI issues and
// AES ones. PKCS12_NO_PERSIST_KEY keeps the key in memory only, and nothing
// is added to the certificate store, so other apps never see the identity.
//
// Keys from PFXImportCertStore allow export but not plaintext export. To move
// one into the TPM or a named KSP key we need its plaintext blob, so it takes
// the same route .NET does: export an encrypted PKCS#8 under a random
// password, import that as an ephemeral KSP key that allows plaintext export,
// and export the blob from there. The blob only ever lives in this process.
//
// UNTESTED on real hardware at the time of writing (spike S2): verify with
// npm run test:native on Windows.

#include "WinStores.h"

#include <wincrypt.h>

#include <cstdio>
#include <cwchar>

#include "../common/encoding.h"

namespace ks::win {
namespace {

struct Store {
    HCERTSTORE h = nullptr;
    ~Store() {
        if (h) CertCloseStore(h, 0);
    }
};

struct Cert {
    PCCERT_CONTEXT c = nullptr;
    ~Cert() {
        if (c) CertFreeCertificateContext(c);
    }
};

struct Key {
    NCRYPT_KEY_HANDLE h = 0;
    bool owned = false;
    Key() = default;
    Key(const Key&) = delete;
    Key& operator=(const Key&) = delete;
    Key(Key&& o) noexcept : h(o.h), owned(o.owned) { o.h = 0; }
    ~Key() {
        if (h && owned) NCryptFreeObject(h);
    }
};

struct Provider {
    NCRYPT_PROV_HANDLE h = 0;
    ~Provider() {
        if (h) NCryptFreeObject(h);
    }
};

[[noreturn]] void fail(const char* what, SECURITY_STATUS s) {
    char buf[128];
    std::snprintf(buf, sizeof(buf), "%s failed (0x%08lx)", what, static_cast<unsigned long>(s));
    throw Error(ErrorCode::Internal, buf);
}

Bytes exportBlob(NCRYPT_KEY_HANDLE key, LPCWSTR type, NCryptBufferDesc* params, SECURITY_STATUS* status) {
    DWORD size = 0;
    *status = NCryptExportKey(key, 0, type, params, nullptr, 0, &size, 0);
    if (*status != ERROR_SUCCESS) return {};
    Bytes out(size);
    *status = NCryptExportKey(key, 0, type, params, out.data(), size, &size, 0);
    if (*status != ERROR_SUCCESS) {
        secureZero(out);
        return {};
    }
    out.resize(size);
    return out;
}

std::wstring keyProperty(NCRYPT_KEY_HANDLE key, LPCWSTR name) {
    DWORD size = 0;
    if (NCryptGetProperty(key, name, nullptr, 0, &size, 0) != ERROR_SUCCESS || size == 0) return L"";
    std::wstring value(size / sizeof(wchar_t), L'\0');
    if (NCryptGetProperty(key, name, reinterpret_cast<PBYTE>(value.data()), size, &size, 0) != ERROR_SUCCESS) return L"";
    while (!value.empty() && value.back() == L'\0') value.pop_back();
    return value;
}

DWORD keyLength(NCRYPT_KEY_HANDLE key) {
    DWORD bits = 0, size = 0;
    NCryptGetProperty(key, NCRYPT_LENGTH_PROPERTY, reinterpret_cast<PBYTE>(&bits), sizeof(bits), &size, 0);
    return bits;
}

// The plaintext private blob of a key that only allows encrypted export.
Bytes plaintextBlob(NCRYPT_KEY_HANDLE key, LPCWSTR type) {
    SECURITY_STATUS s = ERROR_SUCCESS;
    Bytes direct = exportBlob(key, type, nullptr, &s);
    if (s == ERROR_SUCCESS) return direct;

    // Random one-time password for the PKCS#8 round trip.
    uint8_t random[16];
    if (BCryptGenRandom(nullptr, random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        throw Error(ErrorCode::Internal, "BCryptGenRandom failed");
    }
    std::wstring secret;
    for (uint8_t b : random) {
        wchar_t hex[3];
        std::swprintf(hex, 3, L"%02x", b);
        secret += hex;
    }
    secureZero(random, sizeof(random));

    // PBEParameter ::= SEQUENCE { salt OCTET STRING (8), iterationCount INTEGER (2000) }
    uint8_t pbe[] = {0x30, 0x0e, 0x04, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x02, 0x07, 0xd0};
    if (BCryptGenRandom(nullptr, pbe + 4, 8, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        throw Error(ErrorCode::Internal, "BCryptGenRandom failed");
    }
    static char kOid[] = szOID_PKCS_12_pbeWithSHA1And3KeyTripleDES;
    const ULONG secretBytes = static_cast<ULONG>((secret.size() + 1) * sizeof(wchar_t));
    NCryptBuffer exportParams[] = {
        {secretBytes, NCRYPTBUFFER_PKCS_SECRET, secret.data()},
        {static_cast<ULONG>(sizeof(kOid)), NCRYPTBUFFER_PKCS_ALG_OID, kOid},
        {static_cast<ULONG>(sizeof(pbe)), NCRYPTBUFFER_PKCS_ALG_PARAM, pbe},
    };
    NCryptBufferDesc exportDesc{NCRYPTBUFFER_VERSION, 3, exportParams};
    Bytes pkcs8 = exportBlob(key, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, &exportDesc, &s);
    if (s != ERROR_SUCCESS) {
        secureZero(secret.data(), secret.size() * sizeof(wchar_t));
        fail("NCryptExportKey (PKCS#8)", s);
    }

    Provider ksp;
    s = NCryptOpenStorageProvider(&ksp.h, MS_KEY_STORAGE_PROVIDER, 0);
    if (s != ERROR_SUCCESS) fail("NCryptOpenStorageProvider", s);
    NCryptBuffer importParams[] = {{secretBytes, NCRYPTBUFFER_PKCS_SECRET, secret.data()}};
    NCryptBufferDesc importDesc{NCRYPTBUFFER_VERSION, 1, importParams};
    Key temp;
    temp.owned = true;
    // No key name: an ephemeral key that disappears with its handle.
    s = NCryptImportKey(ksp.h, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, &importDesc, &temp.h, pkcs8.data(),
                        static_cast<DWORD>(pkcs8.size()), NCRYPT_DO_NOT_FINALIZE_FLAG);
    secureZero(pkcs8);
    secureZero(secret.data(), secret.size() * sizeof(wchar_t));
    if (s != ERROR_SUCCESS) fail("NCryptImportKey (PKCS#8)", s);
    DWORD policy = NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
    s = NCryptSetProperty(temp.h, NCRYPT_EXPORT_POLICY_PROPERTY, reinterpret_cast<PBYTE>(&policy), sizeof(policy), 0);
    if (s != ERROR_SUCCESS) fail("NCryptSetProperty (export policy)", s);
    s = NCryptFinalizeKey(temp.h, 0);
    if (s != ERROR_SUCCESS) fail("NCryptFinalizeKey", s);

    Bytes blob = exportBlob(temp.h, type, nullptr, &s);
    if (s != ERROR_SUCCESS) fail("NCryptExportKey (plaintext)", s);
    return blob;
}

Bytes certSpki(PCCERT_CONTEXT cert) {
    BYTE* encoded = nullptr;
    DWORD size = 0;
    if (!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, &cert->pCertInfo->SubjectPublicKeyInfo,
                             CRYPT_ENCODE_ALLOC_FLAG, nullptr, &encoded, &size)) {
        throw Error(ErrorCode::Internal, "could not encode the certificate's public key");
    }
    Bytes out(encoded, encoded + size);
    LocalFree(encoded);
    return out;
}

bool hasProperty(PCCERT_CONTEXT cert, DWORD property) {
    DWORD size = 0;
    return CertGetCertificateContextProperty(cert, property, nullptr, &size) != FALSE;
}

bool hasKeyProperty(PCCERT_CONTEXT cert) {
    return hasProperty(cert, CERT_NCRYPT_KEY_HANDLE_PROP_ID) || hasProperty(cert, CERT_KEY_PROV_INFO_PROP_ID);
}

// With PKCS12_NO_PERSIST_KEY the key lives only in memory, attached to the
// certificate as CERT_NCRYPT_KEY_HANDLE_PROP_ID: read that first (the
// certificate context owns it). Otherwise ask CryptAcquireCertificatePrivateKey.
Key openKey(PCCERT_CONTEXT cert) {
    Key key;
    NCRYPT_KEY_HANDLE handle = 0;
    DWORD size = sizeof(handle);
    if (CertGetCertificateContextProperty(cert, CERT_NCRYPT_KEY_HANDLE_PROP_ID, &handle, &size) && handle) {
        key.h = handle;
        key.owned = false;
        return key;
    }
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE acquired = 0;
    DWORD spec = 0;
    BOOL mustFree = FALSE;
    if (!CryptAcquireCertificatePrivateKey(cert, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG, nullptr,
                                           &acquired, &spec, &mustFree)) {
        char buf[96];
        std::snprintf(buf, sizeof(buf), "could not open the file's private key (0x%08lx)",
                      static_cast<unsigned long>(GetLastError()));
        throw Error(ErrorCode::BadFile, buf);
    }
    key.h = acquired;
    key.owned = mustFree == TRUE;
    return key;
}

// SubjectPublicKeyInfo of a CNG key, in the same encoding as certSpki.
Bytes keySpki(NCRYPT_KEY_HANDLE key, Algorithm algorithm) {
    SECURITY_STATUS s = ERROR_SUCCESS;
    if (algorithm == Algorithm::RS256) {
        Bytes blob = exportBlob(key, BCRYPT_RSAPUBLIC_BLOB, nullptr, &s);
        if (s != ERROR_SUCCESS) fail("NCryptExportKey (RSA public)", s);
        auto* header = reinterpret_cast<const BCRYPT_RSAKEY_BLOB*>(blob.data());
        if (blob.size() < sizeof(BCRYPT_RSAKEY_BLOB) ||
            blob.size() < sizeof(BCRYPT_RSAKEY_BLOB) + header->cbPublicExp + header->cbModulus) {
            throw Error(ErrorCode::Internal, "unexpected RSA public key blob");
        }
        const uint8_t* exponent = blob.data() + sizeof(BCRYPT_RSAKEY_BLOB);
        return rsaSpkiFromPkcs1(rsaPkcs1FromModExp(exponent + header->cbPublicExp, header->cbModulus, exponent,
                                                   header->cbPublicExp));
    }
    Bytes blob = exportBlob(key, BCRYPT_ECCPUBLIC_BLOB, nullptr, &s);
    if (s != ERROR_SUCCESS) fail("NCryptExportKey (ECC public)", s);
    auto* header = reinterpret_cast<const BCRYPT_ECCKEY_BLOB*>(blob.data());
    if (blob.size() < sizeof(BCRYPT_ECCKEY_BLOB) || header->cbKey != 32 ||
        blob.size() < sizeof(BCRYPT_ECCKEY_BLOB) + 64) {
        throw Error(ErrorCode::Internal, "unexpected ECC public key blob");
    }
    Bytes point{0x04};
    point.insert(point.end(), blob.data() + sizeof(BCRYPT_ECCKEY_BLOB), blob.data() + sizeof(BCRYPT_ECCKEY_BLOB) + 64);
    return p256SpkiFromX963(point);
}

HCERTSTORE openPfx(const Bytes& data, const std::string& password) {
    CRYPT_DATA_BLOB pfx{static_cast<DWORD>(data.size()), const_cast<BYTE*>(data.data())};
    if (!PFXIsPFXBlob(&pfx)) throw Error(ErrorCode::BadFile, "this isn't a PKCS#12 file");

    const DWORD flags = PKCS12_NO_PERSIST_KEY | PKCS12_ALWAYS_CNG_KSP | CRYPT_EXPORTABLE;
    std::wstring wide = widen(password);
    HCERTSTORE store = PFXImportCertStore(&pfx, wide.c_str(), flags);
    DWORD error = store ? ERROR_SUCCESS : GetLastError();
    // An empty password can be encoded as "" or as no password at all.
    if (!store && password.empty()) {
        store = PFXImportCertStore(&pfx, nullptr, flags);
        if (!store) error = GetLastError();
    }
    if (!wide.empty()) secureZero(wide.data(), wide.size() * sizeof(wchar_t));
    if (store) return store;
    if (error == ERROR_INVALID_PASSWORD) {
        throw Error(ErrorCode::BadPassword, "the password doesn't open this file");
    }
    char buf[96];
    std::snprintf(buf, sizeof(buf), "could not read the PKCS#12 file (0x%08lx)", static_cast<unsigned long>(error));
    throw Error(ErrorCode::BadFile, buf);
}

}  // namespace

void ParsedPkcs12::secureZeroKey() {
    secureZero(privateBlob);
}

ParsedPkcs12 parsePkcs12(const Bytes& data, const std::string& password, bool withKey) {
    if (data.empty() || data.size() > kMaxPkcs12Size) throw Error(ErrorCode::BadFile, "the file is empty or too large");

    Store store;
    store.h = openPfx(data, password);

    // Only the certificate the file pairs with a key carries a key property;
    // the rest are its issuers.
    Cert leaf;
    std::vector<Bytes> others;
    for (PCCERT_CONTEXT cert = CertEnumCertificatesInStore(store.h, nullptr); cert != nullptr;
         cert = CertEnumCertificatesInStore(store.h, cert)) {
        if (hasKeyProperty(cert)) {
            if (leaf.c != nullptr) throw Error(ErrorCode::BadFile, "the file holds more than one private key");
            leaf.c = CertDuplicateCertificateContext(cert);
        } else {
            others.emplace_back(cert->pbCertEncoded, cert->pbCertEncoded + cert->cbCertEncoded);
        }
    }
    if (leaf.c == nullptr) throw Error(ErrorCode::BadFile, "the file has no private key");
    Key key = openKey(leaf.c);

    ParsedPkcs12 parsed;
    parsed.contents.chain.emplace_back(leaf.c->pbCertEncoded, leaf.c->pbCertEncoded + leaf.c->cbCertEncoded);
    for (auto& der : others) parsed.contents.chain.push_back(std::move(der));
    parsed.spki = certSpki(leaf.c);

    const std::wstring group = keyProperty(key.h, NCRYPT_ALGORITHM_GROUP_PROPERTY);
    const DWORD bits = keyLength(key.h);
    parsed.contents.keyBits = static_cast<int>(bits);
    if (group == NCRYPT_RSA_ALGORITHM_GROUP) {
        if (bits < 2048) throw Error(ErrorCode::Unsupported, "RSA keys must be at least 2048 bits");
        parsed.contents.algorithm = Algorithm::RS256;
        parsed.blobType = BCRYPT_RSAPRIVATE_BLOB;
    } else if ((group == NCRYPT_ECDSA_ALGORITHM_GROUP || group == NCRYPT_ECDH_ALGORITHM_GROUP) && bits == 256) {
        parsed.contents.algorithm = Algorithm::ES256;
        parsed.blobType = BCRYPT_ECCPRIVATE_BLOB;
    } else {
        throw Error(ErrorCode::Unsupported, "only RSA (2048 bits or more) and P-256 keys are supported");
    }

    // The OS pairs key and certificate by itself; check anyway, as on macOS.
    if (keySpki(key.h, parsed.contents.algorithm) != parsed.spki) {
        throw Error(ErrorCode::KeyMismatch, "the private key doesn't match the certificate");
    }

    if (withKey) {
        parsed.privateBlob = plaintextBlob(key.h, parsed.blobType);
        if (parsed.contents.algorithm == Algorithm::ES256) {
            // A P-256 key from a .p12 may come back as ECDH; sign with it as ECDSA.
            if (parsed.privateBlob.size() < sizeof(BCRYPT_ECCKEY_BLOB)) {
                throw Error(ErrorCode::Internal, "unexpected ECC private key blob");
            }
            reinterpret_cast<BCRYPT_ECCKEY_BLOB*>(parsed.privateBlob.data())->dwMagic = BCRYPT_ECDSA_PRIVATE_P256_MAGIC;
        }
    }
    return parsed;
}

}  // namespace ks::win
