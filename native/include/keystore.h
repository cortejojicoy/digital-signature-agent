// Platform-neutral key store interface (desktop-agent-plan.md §4.1).
//
// Private key material never crosses this interface: callers hold key ids and
// receive public keys (SPKI DER) and signatures (DER for ES256, PKCS#1 v1.5
// for RS256). sign() takes the message, not a digest, and hashes it with
// SHA-256 internally, so JS can't ask a key to sign an arbitrary hash.
#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace ks {

using Bytes = std::vector<uint8_t>;

enum class Protection { SecureEnclave, Tpm, Software };
enum class Algorithm { ES256, RS256 };

// Which backends the factory may use. `Software` forces the software
// fallback on every platform (CI runners have no Secure Enclave / TPM / Hello).
enum class Backend { Auto, Software };

struct Capabilities {
    bool hardware = false;      // a hardware-backed store is usable
    bool userPresence = false;  // OS-enforced Touch ID / Hello / password on use
    bool attestation = false;   // keys can carry a third-party attestation
};

struct KeyInfo {
    std::string keyId;          // our label, e.g. "ds.<serverHash>.identity"
    Algorithm algorithm = Algorithm::ES256;
    Bytes spki;                 // SubjectPublicKeyInfo DER
    Protection protection = Protection::Software;
    bool userPresence = false;  // OS-enforced Touch ID / Hello on use
};

struct CreateOptions {
    std::string keyId;
    bool requireUserPresence = false;  // identity key: true; session key: false
    // macOS only: demand biometrics (and invalidate on enrolment change)
    // instead of "biometrics or login password".
    bool biometryOnly = false;
};

struct Attestation {
    std::string format;         // e.g. "windows-hello-tpm"
    Bytes statement;
    std::vector<Bytes> chain;
};

struct DeviceInfo {
    std::string platform;       // "macos" | "windows"
    std::string osVersion;
    std::string model;          // friendly name when known, e.g. "MacBook Pro"
    std::string modelIdentifier;// e.g. "Mac15,3" / "LENOVO 21CB"
    std::string formFactor;     // "laptop" | "desktop" | "unknown"
    std::string hostname;
    std::string hardwareIdHash; // sha256_hex(salt || hardware uuid), "" if unavailable
};

// Error codes surfaced to JS as `err.code`.
enum class ErrorCode {
    NotFound,       // E_NOT_FOUND
    Exists,         // E_EXISTS
    Cancelled,      // E_CANCELLED   user dismissed the OS prompt
    Unsupported,    // E_UNSUPPORTED
    Internal,       // E_INTERNAL
};

class Error : public std::runtime_error {
public:
    Error(ErrorCode code, const std::string& message)
        : std::runtime_error(message), code_(code) {}
    ErrorCode code() const { return code_; }
    const char* codeName() const;

private:
    ErrorCode code_;
};

class KeyStore {
public:
    virtual ~KeyStore() = default;
    virtual Capabilities capabilities() = 0;
    virtual KeyInfo create(const CreateOptions&) = 0;
    virtual std::optional<KeyInfo> find(const std::string& keyId) = 0;
    virtual Bytes sign(const std::string& keyId,
                       const Bytes& message,
                       const std::string& reason,  // shown in the OS prompt
                       void* parentWindow) = 0;    // HWND on Windows, unused on macOS
    virtual std::optional<Attestation> attest(const std::string& keyId) = 0;
    virtual void remove(const std::string& keyId) = 0;

    // Test hook: true if the private key can be exported. Must always be false.
    virtual bool privateKeyExportable(const std::string& keyId) = 0;
};

std::unique_ptr<KeyStore> createPlatformKeyStore(Backend backend);

// Where file-backed keys are kept (macOS: Secure Enclave blobs, see
// SecureEnclaveBlob.swift). The app sets it to <userData>/keys; when unset,
// ~/Library/Application Support/Kukux Sign Agent/keys is used.
void setKeyDirectory(const std::string& path);
std::string keyDirectory();

// Seals small secrets (agent tokens) to this machine's security chip, without
// the keychain. macOS: a Secure Enclave key-agreement key kept in
// keyDirectory(); no prompt. Windows: unsupported (safeStorage / DPAPI is used).
bool sealingAvailable();
Bytes sealData(const Bytes& plain);
Bytes openData(const Bytes& sealed);
DeviceInfo readDeviceInfo(const std::string& salt);

}  // namespace ks
