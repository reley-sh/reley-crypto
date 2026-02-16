import { ensureSodium } from './keys.js';
import { zeroize } from './utils.js';

const HKDF_HASH_LEN = 32; // SHA-256

/**
 * HKDF-Extract: PRK = HMAC-SHA256(salt, IKM)
 */
async function hkdfExtract(salt: Uint8Array, ikm: Uint8Array): Promise<Uint8Array> {
  const s = await ensureSodium();
  const key = salt.length > 0 ? salt : new Uint8Array(HKDF_HASH_LEN);
  return s.crypto_auth_hmacsha256(ikm, key);
}

/**
 * HKDF-Expand: OKM = T(1) || T(2) || ... truncated to length
 */
async function hkdfExpand(prk: Uint8Array, info: Uint8Array, length: number): Promise<Uint8Array> {
  const s = await ensureSodium();
  const n = Math.ceil(length / HKDF_HASH_LEN);
  const okm = new Uint8Array(n * HKDF_HASH_LEN);
  let prev = new Uint8Array(0);

  for (let i = 1; i <= n; i++) {
    const input = new Uint8Array(prev.length + info.length + 1);
    input.set(prev, 0);
    input.set(info, prev.length);
    input[prev.length + info.length] = i;
    prev = new Uint8Array(s.crypto_auth_hmacsha256(input, prk));
    okm.set(prev, (i - 1) * HKDF_HASH_LEN);
  }

  return okm.slice(0, length);
}

/**
 * Derive symmetric keys from ECDH shared secret.
 * Returns { sendKey, recvKey } each 32 bytes for AEAD cipher.
 */
export async function deriveSessionKeys(
  sharedSecret: Uint8Array,
  salt: Uint8Array = new Uint8Array(0),
  info: string = 'reley-v1',
): Promise<{ sendKey: Uint8Array; recvKey: Uint8Array }> {
  const infoBytes = new TextEncoder().encode(info);
  const prk = await hkdfExtract(salt, sharedSecret);
  // 64 bytes: first 32 = send key, next 32 = recv key
  const okm = await hkdfExpand(prk, infoBytes, 64);
  const sendKey = okm.slice(0, 32);
  const recvKey = okm.slice(32, 64);
  // Zeroize intermediate key material
  await zeroize(prk, okm);
  return { sendKey, recvKey };
}

/**
 * Derive a single chain key for ratchet progression.
 */
export async function deriveChainKey(
  chainKey: Uint8Array,
  info: string = 'reley-chain',
): Promise<{ messageKey: Uint8Array; nextChainKey: Uint8Array }> {
  const s = await ensureSodium();
  const msgKeyInput = new TextEncoder().encode(info + '-msg');
  const chainKeyInput = new TextEncoder().encode(info + '-chain');

  const messageKey = new Uint8Array(s.crypto_auth_hmacsha256(msgKeyInput, chainKey));
  const nextChainKey = new Uint8Array(s.crypto_auth_hmacsha256(chainKeyInput, chainKey));

  return { messageKey, nextChainKey };
}
