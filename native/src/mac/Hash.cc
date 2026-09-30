#include <CommonCrypto/CommonDigest.h>

#include "../common/encoding.h"

namespace ks {

Bytes sha256(const Bytes& data) {
    Bytes out(CC_SHA256_DIGEST_LENGTH);
    CC_SHA256(data.data(), static_cast<CC_LONG>(data.size()), out.data());
    return out;
}

}  // namespace ks
