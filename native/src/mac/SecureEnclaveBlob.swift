// Secure Enclave keys that live outside the keychain (CryptoKit).
//
// The keychain route (SecureEnclaveKeyStore.mm) needs the keychain-access-groups
// entitlement, which needs a paid Apple Developer account and a provisioning
// profile. CryptoKit Secure Enclave keys need neither: the private key never
// leaves the Secure Enclave, and what we store is its dataRepresentation, a
// blob wrapped by this Mac's Secure Enclave that is useless on any other
// machine. The access control (user presence / biometry) is enforced by the
// Secure Enclave on every signature, exactly as for keychain keys.
//
// Exposed to C++ with @_cdecl. Buffers returned through out-parameters are
// malloc'd and must be released with kse_free().

import CryptoKit
import Foundation
import LocalAuthentication

private let kOK: Int32 = 0
private let kCancelled: Int32 = 1
private let kUnsupported: Int32 = 2
private let kFailed: Int32 = 3

private func copyOut(_ data: Data, _ out: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>, _ len: UnsafeMutablePointer<Int>) {
    let buffer = malloc(max(data.count, 1))!.assumingMemoryBound(to: UInt8.self)
    data.copyBytes(to: buffer, count: data.count)
    out.pointee = buffer
    len.pointee = data.count
}

private func writeError(_ message: String, _ buf: UnsafeMutablePointer<CChar>?, _ size: Int) {
    guard let buf = buf, size > 0 else { return }
    let bytes = Array(message.utf8.prefix(size - 1))
    for (i, b) in bytes.enumerated() { buf[i] = CChar(bitPattern: b) }
    buf[bytes.count] = 0
}

/// Maps a dismissed Touch ID / password prompt to kCancelled.
private func status(for error: Error) -> Int32 {
    let ns = error as NSError
    if ns.domain == LAErrorDomain {
        let cancelled: [Int] = [LAError.userCancel.rawValue, LAError.systemCancel.rawValue, LAError.appCancel.rawValue,
                                LAError.userFallback.rawValue, LAError.authenticationFailed.rawValue]
        if cancelled.contains(ns.code) { return kCancelled }
    }
    // CryptoTokenKit reports a cancelled Secure Enclave authentication as
    // TKErrorCodeCanceledByUser (-9), sometimes wrapped by CryptoKit.
    if ns.domain == "CryptoTokenKit" && ns.code == -9 { return kCancelled }
    let text = "\(error)".lowercased()
    if text.contains("cancel") { return kCancelled }
    return kFailed
}

@_cdecl("kse_free")
public func kse_free(_ pointer: UnsafeMutableRawPointer?) {
    free(pointer)
}

@_cdecl("kse_available")
public func kse_available() -> Bool {
    return SecureEnclave.isAvailable
}

/// Creates a key. Returns its Secure Enclave blob and SPKI DER public key.
@_cdecl("kse_create")
public func kse_create(
    _ requirePresence: Bool,
    _ biometryOnly: Bool,
    _ blobOut: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    _ blobLen: UnsafeMutablePointer<Int>,
    _ spkiOut: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    _ spkiLen: UnsafeMutablePointer<Int>,
    _ errBuf: UnsafeMutablePointer<CChar>?,
    _ errSize: Int
) -> Int32 {
    guard SecureEnclave.isAvailable else {
        writeError("this Mac has no Secure Enclave", errBuf, errSize)
        return kUnsupported
    }
    var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
    if requirePresence { flags.insert(biometryOnly ? .biometryCurrentSet : .userPresence) }
    var cfError: Unmanaged<CFError>?
    guard let acl = SecAccessControlCreateWithFlags(
        nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &cfError)
    else {
        writeError("SecAccessControlCreateWithFlags: \(String(describing: cfError?.takeRetainedValue()))", errBuf, errSize)
        return kFailed
    }
    do {
        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: acl)
        copyOut(key.dataRepresentation, blobOut, blobLen)
        copyOut(key.publicKey.derRepresentation, spkiOut, spkiLen)
        return kOK
    } catch {
        writeError("\(error)", errBuf, errSize)
        return status(for: error)
    }
}

/// Recovers the SPKI DER public key from a blob. Doesn't prompt.
@_cdecl("kse_public_key")
public func kse_public_key(
    _ blob: UnsafePointer<UInt8>,
    _ blobCount: Int,
    _ spkiOut: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    _ spkiLen: UnsafeMutablePointer<Int>,
    _ errBuf: UnsafeMutablePointer<CChar>?,
    _ errSize: Int
) -> Int32 {
    do {
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: Data(bytes: blob, count: blobCount))
        copyOut(key.publicKey.derRepresentation, spkiOut, spkiLen)
        return kOK
    } catch {
        writeError("\(error)", errBuf, errSize)
        return kFailed
    }
}

/// Signs SHA-256(message) and returns an X9.62 DER signature. Shows the
/// Touch ID / password prompt when the key requires presence.
@_cdecl("kse_sign")
public func kse_sign(
    _ blob: UnsafePointer<UInt8>,
    _ blobCount: Int,
    _ message: UnsafePointer<UInt8>,
    _ messageCount: Int,
    _ reason: UnsafePointer<CChar>,
    _ sigOut: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    _ sigLen: UnsafeMutablePointer<Int>,
    _ errBuf: UnsafeMutablePointer<CChar>?,
    _ errSize: Int
) -> Int32 {
    let context = LAContext()
    context.localizedReason = String(cString: reason)
    do {
        let key = try SecureEnclave.P256.Signing.PrivateKey(
            dataRepresentation: Data(bytes: blob, count: blobCount), authenticationContext: context)
        let signature = try key.signature(for: Data(bytes: message, count: messageCount))
        copyOut(signature.derRepresentation, sigOut, sigLen)
        return kOK
    } catch {
        writeError("\(error)", errBuf, errSize)
        return status(for: error)
    }
}

// ── Sealing small secrets (agent tokens) to the Secure Enclave ──
//
// Free builds can't use the keychain without prompts: its access rules are
// tied to the app's code signature, and an ad-hoc signature changes with every
// build. Instead, a Secure Enclave key-agreement key (no user presence) seals
// data with ECIES: ephemeral P-256 ECDH → HKDF-SHA256 → AES-256-GCM.
//   sealed = ephemeral public key (X9.63, 65 bytes) || AES-GCM combined box
// Only this Mac's Secure Enclave can open it.

private let sealInfo = Data("kukuxsign sealed secret v1".utf8)

private func sealingKey(_ shared: SharedSecret) -> SymmetricKey {
    return shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: Data(), sharedInfo: sealInfo, outputByteCount: 32)
}

@_cdecl("kse_seal_key_create")
public func kse_seal_key_create(
    _ blobOut: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    _ blobLen: UnsafeMutablePointer<Int>,
    _ errBuf: UnsafeMutablePointer<CChar>?,
    _ errSize: Int
) -> Int32 {
    guard SecureEnclave.isAvailable else {
        writeError("this Mac has no Secure Enclave", errBuf, errSize)
        return kUnsupported
    }
    var cfError: Unmanaged<CFError>?
    guard let acl = SecAccessControlCreateWithFlags(
        nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage], &cfError)
    else {
        writeError("SecAccessControlCreateWithFlags failed", errBuf, errSize)
        return kFailed
    }
    do {
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: acl)
        copyOut(key.dataRepresentation, blobOut, blobLen)
        return kOK
    } catch {
        writeError("\(error)", errBuf, errSize)
        return kFailed
    }
}

@_cdecl("kse_seal")
public func kse_seal(
    _ blob: UnsafePointer<UInt8>,
    _ blobCount: Int,
    _ plain: UnsafePointer<UInt8>,
    _ plainCount: Int,
    _ out: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    _ outLen: UnsafeMutablePointer<Int>,
    _ errBuf: UnsafeMutablePointer<CChar>?,
    _ errSize: Int
) -> Int32 {
    do {
        let recipient = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: Data(bytes: blob, count: blobCount)).publicKey
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let key = sealingKey(try ephemeral.sharedSecretFromKeyAgreement(with: recipient))
        let box = try AES.GCM.seal(Data(bytes: plain, count: plainCount), using: key)
        guard let combined = box.combined else { throw CryptoKitError.incorrectParameterSize }
        copyOut(ephemeral.publicKey.x963Representation + combined, out, outLen)
        return kOK
    } catch {
        writeError("\(error)", errBuf, errSize)
        return kFailed
    }
}

@_cdecl("kse_open")
public func kse_open(
    _ blob: UnsafePointer<UInt8>,
    _ blobCount: Int,
    _ sealed: UnsafePointer<UInt8>,
    _ sealedCount: Int,
    _ out: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    _ outLen: UnsafeMutablePointer<Int>,
    _ errBuf: UnsafeMutablePointer<CChar>?,
    _ errSize: Int
) -> Int32 {
    do {
        let data = Data(bytes: sealed, count: sealedCount)
        guard data.count > 65 else { throw CryptoKitError.incorrectParameterSize }
        let ephemeral = try P256.KeyAgreement.PublicKey(x963Representation: data.prefix(65))
        let own = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: Data(bytes: blob, count: blobCount))
        let key = sealingKey(try own.sharedSecretFromKeyAgreement(with: ephemeral))
        let plain = try AES.GCM.open(AES.GCM.SealedBox(combined: data.dropFirst(65)), using: key)
        copyOut(plain, out, outLen)
        return kOK
    } catch {
        writeError("\(error)", errBuf, errSize)
        return kFailed
    }
}
