export {
  ensureSodium,
  generateIdentityKeyPair,
  generateEphemeralKeyPair,
  ed25519ToX25519Public,
  ed25519ToX25519Secret,
  generateOneTimeCode,
  sign,
  verify,
  type Ed25519KeyPair,
  type X25519KeyPair,
} from './keys.js';

export { computeSharedSecret, validateX25519PublicKey } from './ecdh.js';

export { deriveSessionKeys, deriveChainKey } from './hkdf.js';

export {
  encrypt,
  decrypt,
  NONCE_LENGTH,
  TAG_LENGTH,
  KEY_LENGTH,
} from './cipher.js';

export {
  initRatchet,
  ratchetEncrypt,
  ratchetDecrypt,
  needsKeyRotation,
  KEY_ROTATION_INTERVAL,
  type RatchetState,
} from './ratchet.js';

export {
  encodeQRPayload,
  decodeQRPayload,
  hashOneTimeCode,
  type QRPayload,
} from './qr-payload.js';

export {
  zeroize,
  computeFingerprint,
  toBase64Url,
  fromBase64Url,
} from './utils.js';
