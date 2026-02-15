/**
 * Key generation, signing, and libsodium initialization.
 *
 * Uses a default import of libsodium-wrappers-sumo which works across
 * environments:
 *  - Node.js: vitest alias / bundler resolves to the CJS module
 *  - Browser: bundlers (webpack/vite) handle ESM resolution
 */

import _sodium from 'libsodium-wrappers-sumo';

let initialized = false;

/**
 * Ensure libsodium is loaded and ready.
 */
export async function ensureSodium(): Promise<typeof _sodium> {
  if (!initialized) {
    await _sodium.ready;
    initialized = true;
  }
  return _sodium;
}

export interface Ed25519KeyPair {
  publicKey: Uint8Array; // 32 bytes
  secretKey: Uint8Array; // 64 bytes
  keyType: 'ed25519';
}

export interface X25519KeyPair {
  publicKey: Uint8Array; // 32 bytes
  secretKey: Uint8Array; // 32 bytes
  keyType: 'x25519';
}

/**
 * Generate an Ed25519 identity key pair (long-term, per-device).
 */
export async function generateIdentityKeyPair(): Promise<Ed25519KeyPair> {
  const s = await ensureSodium();
  const kp = s.crypto_sign_keypair();
  return {
    publicKey: kp.publicKey,
    secretKey: kp.privateKey,
    keyType: 'ed25519',
  };
}

/**
 * Generate an X25519 ephemeral key pair (per-session).
 */
export async function generateEphemeralKeyPair(): Promise<X25519KeyPair> {
  const s = await ensureSodium();
  const kp = s.crypto_kx_keypair();
  return {
    publicKey: kp.publicKey,
    secretKey: kp.privateKey,
    keyType: 'x25519',
  };
}

/**
 * Convert an Ed25519 public key to X25519 for ECDH.
 */
export async function ed25519ToX25519Public(ed25519Pk: Uint8Array): Promise<Uint8Array> {
  const s = await ensureSodium();
  return s.crypto_sign_ed25519_pk_to_curve25519(ed25519Pk);
}

/**
 * Convert an Ed25519 secret key to X25519 for ECDH.
 */
export async function ed25519ToX25519Secret(ed25519Sk: Uint8Array): Promise<Uint8Array> {
  const s = await ensureSodium();
  return s.crypto_sign_ed25519_sk_to_curve25519(ed25519Sk);
}

/**
 * Generate a cryptographically secure random one-time code.
 */
export async function generateOneTimeCode(length: number = 32): Promise<Uint8Array> {
  const s = await ensureSodium();
  return s.randombytes_buf(length);
}

/**
 * Sign a message with an Ed25519 secret key.
 */
export async function sign(message: Uint8Array, secretKey: Uint8Array): Promise<Uint8Array> {
  const s = await ensureSodium();
  return s.crypto_sign_detached(message, secretKey);
}

/**
 * Verify an Ed25519 signature.
 */
export async function verify(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array,
): Promise<boolean> {
  const s = await ensureSodium();
  return s.crypto_sign_verify_detached(signature, message, publicKey);
}
