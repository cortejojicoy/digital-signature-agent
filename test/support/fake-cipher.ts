import type { TokenCipher } from '../../src/main/store';

// Stand-in for safeStorage: reversible, but never the plaintext.
export const fakeCipher: TokenCipher = {
  isAvailable: () => true,
  encrypt: (plain) => Buffer.from(`enc:${Buffer.from(plain).reverse().toString('hex')}`),
  decrypt: (cipher) => {
    const text = cipher.toString();
    if (!text.startsWith('enc:')) throw new Error('bad cipher');
    return Buffer.from(text.slice(4), 'hex').reverse().toString();
  },
};
