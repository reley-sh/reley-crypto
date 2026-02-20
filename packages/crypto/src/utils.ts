import { ensureSodium } from './keys.js';

/**
 * Securely zeroize a key or sensitive buffer in memory.
 * Uses libsodium's memzero for guaranteed overwrite.
 */
export async function zeroize(...buffers: Uint8Array[]): Promise<void> {
  const s = await ensureSodium();
  for (const buf of buffers) {
    s.memzero(buf);
  }
}

/**
 * Compute a human-readable fingerprint from two public keys for MITM verification.
 * Keys are sorted lexicographically to ensure both parties produce the same fingerprint.
 * Uses Blake2b-256 (32 bytes) for strong collision resistance (birthday bound 2^128).
 * Formatted as uppercase hex groups: "XXXX-XXXX-..."
 */
export async function computeFingerprint(
  pk1: Uint8Array,
  pk2: Uint8Array,
): Promise<string> {
  const s = await ensureSodium();
  const sorted = [pk1, pk2].sort((a, b) => {
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) return a[i] - b[i];
    }
    return 0;
  });
  const combined = new Uint8Array(sorted[0].length + sorted[1].length);
  combined.set(sorted[0], 0);
  combined.set(sorted[1], sorted[0].length);
  // Security (L-2): Blake2b-256 instead of Blake2b-128
  const hash = s.crypto_generichash(32, combined, null);
  const hex = s.to_hex(hash).toUpperCase();
  return hex.match(/.{4}/g)!.join('-');
}

/**
 * Encode a Uint8Array to a base64url string (no padding).
 */
export async function toBase64Url(data: Uint8Array): Promise<string> {
  const s = await ensureSodium();
  return s.to_base64(data, s.base64_variants.URLSAFE_NO_PADDING);
}

/**
 * Decode a base64url string to a Uint8Array.
 */
export async function fromBase64Url(str: string): Promise<Uint8Array> {
  const s = await ensureSodium();
  return s.from_base64(str, s.base64_variants.URLSAFE_NO_PADDING);
}
