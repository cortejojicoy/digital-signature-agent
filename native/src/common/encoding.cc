#include "encoding.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <mutex>

namespace ks {

namespace {

// SEQUENCE { SEQUENCE { OID id-ecPublicKey, OID prime256v1 }, BIT STRING (0 unused bits) ...
const uint8_t kP256SpkiPrefix[] = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
    0x42, 0x00,
};

// DER INTEGER body: strip leading zeros, then re-add one if the high bit is
// set so the value stays positive.
Bytes derInteger(const uint8_t* data, size_t len) {
    size_t start = 0;
    while (start < len - 1 && data[start] == 0x00) start++;
    Bytes out;
    if (data[start] & 0x80) out.push_back(0x00);
    out.insert(out.end(), data + start, data + len);
    return out;
}

void appendLength(Bytes& out, size_t len) {
    if (len < 0x80) {
        out.push_back(static_cast<uint8_t>(len));
        return;
    }
    Bytes digits;
    for (size_t n = len; n > 0; n >>= 8) digits.insert(digits.begin(), static_cast<uint8_t>(n & 0xff));
    out.push_back(static_cast<uint8_t>(0x80 | digits.size()));
    out.insert(out.end(), digits.begin(), digits.end());
}

Bytes tlv(uint8_t tag, const Bytes& body) {
    Bytes out{tag};
    appendLength(out, body.size());
    out.insert(out.end(), body.begin(), body.end());
    return out;
}

// SEQUENCE { OID rsaEncryption, NULL }
const uint8_t kRsaAlgorithmId[] = {
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
};

}  // namespace

const char* Error::codeName() const {
    switch (code_) {
        case ErrorCode::NotFound: return "E_NOT_FOUND";
        case ErrorCode::Exists: return "E_EXISTS";
        case ErrorCode::Cancelled: return "E_CANCELLED";
        case ErrorCode::Unsupported: return "E_UNSUPPORTED";
        case ErrorCode::Internal: return "E_INTERNAL";
        case ErrorCode::BadPassword: return "E_BAD_PASSWORD";
        case ErrorCode::BadFile: return "E_BAD_FILE";
        case ErrorCode::KeyMismatch: return "E_KEY_MISMATCH";
    }
    return "E_INTERNAL";
}

Bytes p256SpkiFromX963(const Bytes& point) {
    if (point.size() != 65 || point[0] != 0x04) {
        throw Error(ErrorCode::Internal, "expected an uncompressed 65-byte P-256 point");
    }
    Bytes spki(std::begin(kP256SpkiPrefix), std::end(kP256SpkiPrefix));
    spki.insert(spki.end(), point.begin(), point.end());
    return spki;
}

Bytes ecdsaRawToDer(const Bytes& rs) {
    if (rs.empty() || rs.size() % 2 != 0 || rs.size() > 132) {
        throw Error(ErrorCode::Internal, "invalid raw ECDSA signature length");
    }
    const size_t half = rs.size() / 2;
    Bytes r = derInteger(rs.data(), half);
    Bytes s = derInteger(rs.data() + half, half);

    Bytes body;
    body.push_back(0x02);
    body.push_back(static_cast<uint8_t>(r.size()));
    body.insert(body.end(), r.begin(), r.end());
    body.push_back(0x02);
    body.push_back(static_cast<uint8_t>(s.size()));
    body.insert(body.end(), s.begin(), s.end());

    Bytes der;
    der.push_back(0x30);
    if (body.size() >= 0x80) der.push_back(0x81);  // P-521 only; P-256 stays < 128
    der.push_back(static_cast<uint8_t>(body.size()));
    der.insert(der.end(), body.begin(), body.end());
    return der;
}

Bytes rsaSpkiFromPkcs1(const Bytes& rsaPublicKey) {
    if (rsaPublicKey.size() < 8 || rsaPublicKey[0] != 0x30) {
        throw Error(ErrorCode::Internal, "expected a DER RSAPublicKey");
    }
    Bytes bits{0x00};  // no unused bits
    bits.insert(bits.end(), rsaPublicKey.begin(), rsaPublicKey.end());
    Bytes body(std::begin(kRsaAlgorithmId), std::end(kRsaAlgorithmId));
    Bytes bitString = tlv(0x03, bits);
    body.insert(body.end(), bitString.begin(), bitString.end());
    return tlv(0x30, body);
}

Bytes rsaPkcs1FromModExp(const uint8_t* modulus, size_t modulusLen, const uint8_t* exponent, size_t exponentLen) {
    if (modulusLen == 0 || exponentLen == 0) throw Error(ErrorCode::Internal, "empty RSA modulus or exponent");
    Bytes body = tlv(0x02, derInteger(modulus, modulusLen));
    Bytes e = tlv(0x02, derInteger(exponent, exponentLen));
    body.insert(body.end(), e.begin(), e.end());
    return tlv(0x30, body);
}

void secureZero(void* data, size_t len) {
    volatile uint8_t* p = static_cast<volatile uint8_t*>(data);
    while (len--) *p++ = 0;
}

void secureZero(Bytes& data) {
    if (!data.empty()) secureZero(data.data(), data.size());
    data.clear();
}

void secureZero(std::string& data) {
    if (!data.empty()) secureZero(&data[0], data.size());
    data.clear();
}

std::string hexEncode(const Bytes& data) {
    static const char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2);
    for (uint8_t b : data) {
        out.push_back(kHex[b >> 4]);
        out.push_back(kHex[b & 0x0f]);
    }
    return out;
}

namespace {
// Firmware placeholder UUIDs that many boards ship with. Hashing one would
// make different computers look like the same one, so they count as no id
// (one-computer-per-account-plan.md §14). Keep in step with
// test/fixtures/placeholder-uuids.json, which the package checks too.
const char* const kPlaceholderUuids[] = {
    "03000200-0400-0500-0006-000700080009",
    "00020003-0004-0005-0006-000700080009",
    "12345678-1234-5678-90AB-CDDEEFAABBCC",
    "01234567-8910-1112-1314-151617181920",
    "11111111-2222-3333-4444-555555555555",
};

// `upper` is upper-case. Also catches any UUID of one repeated digit
// (all 0s, all Fs, …).
bool isPlaceholderUuid(const std::string& upper) {
    std::string digits;
    for (char c : upper) {
        if (c != '-') digits.push_back(c);
    }
    if (digits.empty() || digits.find_first_not_of(digits[0]) == std::string::npos) return true;
    for (const char* placeholder : kPlaceholderUuids) {
        if (upper == placeholder) return true;
    }
    return false;
}
}  // namespace

std::string saltedHardwareHash(const std::string& salt, const std::string& uuid) {
    if (uuid.empty()) return "";
    std::string upper = uuid;
    std::transform(upper.begin(), upper.end(), upper.begin(),
                   [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    if (isPlaceholderUuid(upper)) return "";
    Bytes input(salt.begin(), salt.end());
    input.insert(input.end(), upper.begin(), upper.end());
    return hexEncode(sha256(input));
}

namespace {
std::mutex g_keyDirMutex;
std::string g_keyDir;
}  // namespace

void setKeyDirectory(const std::string& path) {
    std::lock_guard<std::mutex> lock(g_keyDirMutex);
    g_keyDir = path;
}

std::string keyDirectory() {
    std::lock_guard<std::mutex> lock(g_keyDirMutex);
    if (!g_keyDir.empty()) return g_keyDir;
    const char* home = std::getenv("HOME");
    return std::string(home ? home : "") + "/Library/Application Support/Kukux Sign Agent/keys";
}

}  // namespace ks
