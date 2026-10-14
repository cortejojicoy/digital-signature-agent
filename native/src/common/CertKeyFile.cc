#include "CertKeyFile.h"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iterator>

#include "encoding.h"

namespace ks {
namespace {

namespace fs = std::filesystem;

const char kMagic[4] = {'K', 'P', '1', '2'};
constexpr uint8_t kVersion = 2;
constexpr size_t kSaltLength = 16;
constexpr uint32_t kMinIterations = 600000;
constexpr uint32_t kMaxIterations = 5000000;

// keyDirectory() is UTF-8; Windows paths need it widened.
fs::path pathOf(const std::string& utf8) {
#ifdef _WIN32
    return fs::path(std::u8string(reinterpret_cast<const char8_t*>(utf8.data()), utf8.size()));
#else
    return fs::path(utf8);
#endif
}

void putU32(Bytes& out, size_t n) {
    for (int shift = 24; shift >= 0; shift -= 8) out.push_back(static_cast<uint8_t>((n >> shift) & 0xff));
}

}  // namespace

std::string certKeyPath(const std::string& keyId) {
    return keyDirectory() + "/" + keyId + ".p12key";
}

std::optional<CertKeyFile> readCertKeyFile(const std::string& keyId) {
    std::ifstream in(pathOf(certKeyPath(keyId)), std::ios::binary);
    if (!in) return std::nullopt;
    Bytes raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    auto corrupt = [&] { return Error(ErrorCode::Internal, "corrupt key file: " + certKeyPath(keyId)); };
    if (raw.size() < 7 || !std::equal(kMagic, kMagic + 4, raw.begin())) throw corrupt();
    if (raw[4] != kVersion) {
        throw Error(ErrorCode::Unsupported, "this certificate was imported by an older version; import it again");
    }
    size_t pos = 7;
    auto u32 = [&]() -> size_t {
        if (raw.size() < pos + 4) throw corrupt();
        size_t n = (size_t(raw[pos]) << 24) | (size_t(raw[pos + 1]) << 16) | (size_t(raw[pos + 2]) << 8) | raw[pos + 3];
        pos += 4;
        return n;
    };
    auto chunk = [&]() {
        size_t n = u32();
        if (raw.size() < pos + n) throw corrupt();
        Bytes out(raw.begin() + pos, raw.begin() + pos + n);
        pos += n;
        return out;
    };
    CertKeyFile file;
    if (raw[5] > static_cast<uint8_t>(CertOuter::Dpapi)) throw corrupt();
    file.outer = static_cast<CertOuter>(raw[5]);
    file.algorithm = raw[6] == 0 ? Algorithm::ES256 : Algorithm::RS256;
    file.spki = chunk();
    file.wrappingKey = chunk();
    file.iterations = static_cast<uint32_t>(u32());
    file.payload = Bytes(raw.begin() + pos, raw.end());
    if (file.payload.empty() || file.iterations == 0) throw corrupt();
    return file;
}

void writeCertKeyFile(const std::string& keyId, const CertKeyFile& file) {
    Bytes body(kMagic, kMagic + 4);
    body.push_back(kVersion);
    body.push_back(static_cast<uint8_t>(file.outer));
    body.push_back(file.algorithm == Algorithm::ES256 ? 0 : 1);
    putU32(body, file.spki.size());
    body.insert(body.end(), file.spki.begin(), file.spki.end());
    putU32(body, file.wrappingKey.size());
    body.insert(body.end(), file.wrappingKey.begin(), file.wrappingKey.end());
    putU32(body, file.iterations);
    body.insert(body.end(), file.payload.begin(), file.payload.end());

    const fs::path dir = pathOf(keyDirectory());
    std::error_code ec;
    fs::create_directories(dir, ec);
    fs::permissions(dir, fs::perms::owner_all, fs::perm_options::replace, ec);
    const fs::path target = pathOf(certKeyPath(keyId));
    fs::path tmp = target;
    tmp += ".tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) throw Error(ErrorCode::Internal, "could not write the certificate key file");
        fs::permissions(tmp, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace, ec);
        out.write(reinterpret_cast<const char*>(body.data()), static_cast<std::streamsize>(body.size()));
        if (!out) throw Error(ErrorCode::Internal, "could not write the certificate key file");
    }
    fs::rename(tmp, target, ec);
    if (ec) {
        fs::remove(tmp, ec);
        throw Error(ErrorCode::Internal, "could not write the certificate key file");
    }
}

void removeCertKeyFile(const std::string& keyId) {
    std::error_code ec;
    fs::remove(pathOf(certKeyPath(keyId)), ec);
}

Bytes passwordSeal(const Bytes& plain, const std::string& password, uint32_t iterations) {
    Bytes salt = randomBytes(kSaltLength);
    Bytes key = pbkdf2Sha256(password, salt, iterations, 32);
    Bytes box = aesGcmSeal(key, plain);
    secureZero(key);
    salt.insert(salt.end(), box.begin(), box.end());
    return salt;
}

Bytes passwordOpen(const Bytes& box, const std::string& password, uint32_t iterations) {
    if (box.size() <= kSaltLength) throw Error(ErrorCode::Internal, "corrupt certificate key");
    Bytes salt(box.begin(), box.begin() + kSaltLength);
    Bytes sealed(box.begin() + kSaltLength, box.end());
    Bytes key = pbkdf2Sha256(password, salt, iterations, 32);
    std::optional<Bytes> plain = aesGcmOpen(key, sealed);
    secureZero(key);
    if (!plain) throw Error(ErrorCode::BadPassword, "wrong certificate password");
    return std::move(*plain);
}

uint32_t passwordIterations() {
    using clock = std::chrono::steady_clock;
    const uint32_t probe = 100000;
    Bytes salt = randomBytes(kSaltLength);
    const auto start = clock::now();
    Bytes key = pbkdf2Sha256("calibrate", salt, probe, 32);
    const auto ms = std::chrono::duration_cast<std::chrono::microseconds>(clock::now() - start).count() / 1000.0;
    if (ms <= 0) return kMinIterations;
    const double target = probe * (250.0 / ms);
    if (target < kMinIterations) return kMinIterations;
    if (target > kMaxIterations) return kMaxIterations;
    return static_cast<uint32_t>(target);
}

KeyInfo certKeyInfo(const std::string& keyId, const CertKeyFile& file) {
    KeyInfo info;
    info.keyId = keyId;
    info.algorithm = file.algorithm;
    info.spki = file.spki;
    // A software key, kept bound to this computer; the password approves each use.
    info.protection = Protection::Software;
    info.userPresence = true;
    return info;
}

}  // namespace ks
