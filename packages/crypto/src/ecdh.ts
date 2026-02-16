import { ensureSodium } from './keys.js';

/**
 * Compute X25519 ECDH shared secret from our secret key and their public key.
 * Returns 32-byte raw shared secret.
 */
export async function computeSharedSecret(
  ourSecretKey: Uint8Array,
  theirPublicKey: Uint8Array,
): Promise<Uint8Array> {
  if (ourSecretKey.length !== 32) {
    throw new Error(`Secret key must be 32 bytes, got ${ourSecretKey.length}`);
  }
  if (theirPublicKey.length !== 32) {
    throw new Error(`Public key must be 32 bytes, got ${theirPublicKey.length}`);
  }
  const s = await ensureSodium();
  return s.crypto_scalarmult(ourSecretKey, theirPublicKey);
}
