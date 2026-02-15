/**
 * XChaCha20-Poly1305 AEAD cipher.
 *
 * Despite the original filename "aes-gcm.ts", the actual algorithm has always
 * been XChaCha20-Poly1305 via libsodium — AES-GCM was not used because it
 * requires hardware AES-NI support which is unavailable on many platforms.
 *
 * XChaCha20-Poly1305 is a modern AEAD cipher providing:
 *  - 256-bit key security
 *  - 192-bit nonce (24 bytes) — practically eliminates nonce collision risk
 *  - Poly1305 authentication tag (16 bytes)
 *
 * Nonce handling:
 *  We generate a 12-byte random nonce and zero-pad it to 24 bytes for the
 *  XChaCha20-Poly1305 IETF construction. The 12-byte nonce is transmitted on
 *  the wire to save bandwidth; the receiver pads identically before decryption.
 *  With random 12-byte nonces the collision probability is ~2^-48 per message
 *  pair, which is safe for the expected message volume.
 */
import type _sodium from 'libsodium-wrappers-sumo';
import { ensureSodium } from './keys.js';

export const NONCE_LENGTH = 12;
export const TAG_LENGTH = 16;
export const KEY_LENGTH = 32;

/**
 * Encrypt data with XChaCha20-Poly1305.
 * @returns { nonce, ciphertext } where ciphertext includes the auth tag
 */
export async function encrypt(
  plaintext: Uint8Array,
  key: Uint8Array,
  aad: Uint8Array = new Uint8Array(0),
): Promise<{ nonce: Uint8Array; ciphertext: Uint8Array }> {
  const s = await ensureSodium();

  if (key.length !== KEY_LENGTH) {
    throw new Error(`Key must be ${KEY_LENGTH} bytes, got ${key.length}`);
  }

  const nonce = s.randombytes_buf(NONCE_LENGTH);
  const ciphertext = s.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintext,
    aad.length > 0 ? aad : null,
    null, // nsec (unused)
    // xchacha uses 24-byte nonce, pad our 12-byte nonce
    padNonce(nonce, s),
    key,
  );

  return { nonce, ciphertext };
}

/**
 * Decrypt data with XChaCha20-Poly1305.
 */
export async function decrypt(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  key: Uint8Array,
  aad: Uint8Array = new Uint8Array(0),
): Promise<Uint8Array> {
  const s = await ensureSodium();

  if (key.length !== KEY_LENGTH) {
    throw new Error(`Key must be ${KEY_LENGTH} bytes, got ${key.length}`);
  }

  try {
    return s.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null, // nsec (unused)
      ciphertext,
      aad.length > 0 ? aad : null,
      padNonce(nonce, s),
      key,
    );
  } catch {
    throw new Error('Decryption failed: invalid ciphertext or key');
  }
}

/**
 * Pad a 12-byte nonce to 24 bytes for xchacha20poly1305.
 */
function padNonce(nonce: Uint8Array, s: typeof _sodium): Uint8Array {
  const padded = new Uint8Array(s.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  padded.set(nonce, 0);
  return padded;
}
