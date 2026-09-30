#include "encoding.h"

#include <algorithm>
#include <cctype>

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

}  // namespace

const char* Error::codeName() const {
    switch (code_) {
        case ErrorCode::NotFound: return "E_NOT_FOUND";
        case ErrorCode::Exists: return "E_EXISTS";
        case ErrorCode::Cancelled: return "E_CANCELLED";
        case ErrorCode::Unsupported: return "E_UNSUPPORTED";
        case ErrorCode::Internal: return "E_INTERNAL";
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

std::string saltedHardwareHash(const std::string& salt, const std::string& uuid) {
    if (uuid.empty()) return "";
    std::string upper = uuid;
    std::transform(upper.begin(), upper.end(), upper.begin(),
                   [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    Bytes input(salt.begin(), salt.end());
    input.insert(input.end(), upper.begin(), upper.end());
    return hexEncode(sha256(input));
}

}  // namespace ks
