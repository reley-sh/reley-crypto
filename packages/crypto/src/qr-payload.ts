import { ensureSodium } from './keys.js';

export interface QRPayload {
  releyUrl: string;
  publicKey: Uint8Array; // 32 bytes - X25519 public key
  oneTimeCode: Uint8Array; // 32 bytes
  jwt: string;
}

const MAGIC = 'CB1'; // Reley v1

/**
 * Encode a QR payload to a base64url string.
 */
export async function encodeQRPayload(payload: QRPayload): Promise<string> {
  const s = await ensureSodium();

  const releyBytes = new TextEncoder().encode(payload.releyUrl);
  const jwtBytes = new TextEncoder().encode(payload.jwt);

  // Format: MAGIC(3) + releyLen(2 BE) + reley + pubKey(32) + otc(32) + jwtLen(2 BE) + jwt
  const totalLen =
    3 + 2 + releyBytes.length + 32 + 32 + 2 + jwtBytes.length;
  const buf = new Uint8Array(totalLen);
  let offset = 0;

  // Magic
  buf[offset++] = MAGIC.charCodeAt(0);
  buf[offset++] = MAGIC.charCodeAt(1);
  buf[offset++] = MAGIC.charCodeAt(2);

  // Reley URL length + data
  buf[offset++] = (releyBytes.length >>> 8) & 0xff;
  buf[offset++] = releyBytes.length & 0xff;
  buf.set(releyBytes, offset);
  offset += releyBytes.length;

  // Public key (32 bytes)
  buf.set(payload.publicKey, offset);
  offset += 32;

  // One-time code (32 bytes)
  buf.set(payload.oneTimeCode, offset);
  offset += 32;

  // JWT length + data
  buf[offset++] = (jwtBytes.length >>> 8) & 0xff;
  buf[offset++] = jwtBytes.length & 0xff;
  buf.set(jwtBytes, offset);

  return s.to_base64(buf, s.base64_variants.URLSAFE_NO_PADDING);
}

/**
 * Decode a QR payload from a base64url string.
 */
export async function decodeQRPayload(encoded: string): Promise<QRPayload> {
  const s = await ensureSodium();

  const buf = s.from_base64(encoded, s.base64_variants.URLSAFE_NO_PADDING);

  // Minimum: MAGIC(3) + releyLen(2) + pubKey(32) + otc(32) + jwtLen(2) = 71 bytes
  if (buf.length < 71) {
    throw new Error(`QR payload too short: ${buf.length} bytes (minimum 71)`);
  }

  let offset = 0;

  // Verify magic
  const magic = String.fromCharCode(buf[offset++], buf[offset++], buf[offset++]);
  if (magic !== MAGIC) {
    throw new Error(`Invalid QR payload magic: ${magic}`);
  }

  // Reley URL
  const releyLen = (buf[offset] << 8) | buf[offset + 1];
  offset += 2;
  if (offset + releyLen + 32 + 32 + 2 > buf.length) {
    throw new Error('QR payload truncated: reley URL overflows buffer');
  }
  const releyUrl = new TextDecoder().decode(buf.slice(offset, offset + releyLen));
  offset += releyLen;

  // Public key (32 bytes)
  const publicKey = buf.slice(offset, offset + 32);
  offset += 32;

  // One-time code (32 bytes)
  const oneTimeCode = buf.slice(offset, offset + 32);
  offset += 32;

  // JWT
  if (offset + 2 > buf.length) {
    throw new Error('QR payload truncated: missing JWT length');
  }
  const jwtLen = (buf[offset] << 8) | buf[offset + 1];
  offset += 2;
  if (offset + jwtLen > buf.length) {
    throw new Error('QR payload truncated: JWT overflows buffer');
  }
  const jwt = new TextDecoder().decode(buf.slice(offset, offset + jwtLen));

  return { releyUrl, publicKey, oneTimeCode, jwt };
}

/**
 * Hash a one-time code (for safe transmission to reley).
 */
export async function hashOneTimeCode(otc: Uint8Array): Promise<Uint8Array> {
  const s = await ensureSodium();
  return s.crypto_generichash(32, otc, null);
}
