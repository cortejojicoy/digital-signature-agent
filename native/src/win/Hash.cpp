#include <windows.h>
#include <bcrypt.h>

#include "../common/encoding.h"

namespace ks {

Bytes sha256(const Bytes& data) {
    Bytes out(32);
    NTSTATUS status = BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0,
                                 const_cast<PUCHAR>(data.data()), static_cast<ULONG>(data.size()),
                                 out.data(), static_cast<ULONG>(out.size()));
    if (status < 0) throw Error(ErrorCode::Internal, "BCryptHash failed");
    return out;
}

}  // namespace ks
