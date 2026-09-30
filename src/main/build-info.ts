// Build flavour, baked in by scripts/build.mjs from the release workflow.
//
// Free builds (the default) have no paid code signing: ad-hoc signed on
// macOS, unsigned on Windows. Keys still live in the Secure Enclave / TPM.
export const SIGNED_BUILD = process.env.KUKUX_SIGNED_BUILD === 'true';

/**
 * macOS ties keychain access to the app's code signature, and an ad-hoc
 * signature changes with every build, so a free build would get a keychain
 * password prompt after each update. Free macOS builds therefore keep out of
 * the keychain entirely: Chromium gets a mock keychain, and agent tokens are
 * sealed to the Secure Enclave instead (see tokenCipher in index.ts).
 */
export const AVOID_KEYCHAIN = process.platform === 'darwin' && !SIGNED_BUILD;
