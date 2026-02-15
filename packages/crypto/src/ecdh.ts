import { ensureSodium } from './keys.js';

/**
 * Compute X25519 ECDH shared secret from our secret key and their public key.
 * Returns 32-byte raw shared secret.
 */
export async function computeSharedSecret(
  ourSecretKey: Uint8Array,
  theirPublicKey: Uint8Array,
): Promise<Uint8Array> {
  const s = await ensureSodium();
  return s.crypto_scalarmult(ourSecretKey, theirPublicKey);
}
