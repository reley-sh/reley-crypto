import { describe, it, expect } from 'vitest';
import { encodeQRPayload, decodeQRPayload, hashOneTimeCode } from '../qr-payload.js';
import { ensureSodium } from '../keys.js';

describe('qr-payload', () => {
  it('should encode and decode QR payload round-trip', async () => {
    const s = await ensureSodium();
    const payload = {
      releyUrl: 'wss://reley.example.com',
      publicKey: s.randombytes_buf(32),
      oneTimeCode: s.randombytes_buf(32),
      jwt: 'eyJhbGciOiJIUzI1NiJ9.test.signature',
    };

    const encoded = await encodeQRPayload(payload);
    expect(typeof encoded).toBe('string');

    const decoded = await decodeQRPayload(encoded);
    expect(decoded.releyUrl).toBe(payload.releyUrl);
    expect(Buffer.from(decoded.publicKey)).toEqual(Buffer.from(payload.publicKey));
    expect(Buffer.from(decoded.oneTimeCode)).toEqual(Buffer.from(payload.oneTimeCode));
    expect(decoded.jwt).toBe(payload.jwt);
  });

  it('should reject too-short payload', async () => {
    const s = await ensureSodium();
    const badData = s.to_base64(
      new TextEncoder().encode('XX1bad'),
      s.base64_variants.URLSAFE_NO_PADDING,
    );
    await expect(decodeQRPayload(badData)).rejects.toThrow('QR payload too short');
  });

  it('should reject invalid magic', async () => {
    const s = await ensureSodium();
    // Build a buffer that passes the length check but has wrong magic
    const buf = new Uint8Array(71);
    buf[0] = 'X'.charCodeAt(0);
    buf[1] = 'X'.charCodeAt(0);
    buf[2] = '1'.charCodeAt(0);
    const badData = s.to_base64(buf, s.base64_variants.URLSAFE_NO_PADDING);
    await expect(decodeQRPayload(badData)).rejects.toThrow('Invalid QR payload magic');
  });

  it('should hash one-time codes consistently', async () => {
    const s = await ensureSodium();
    const otc = s.randombytes_buf(32);
    const hash1 = await hashOneTimeCode(otc);
    const hash2 = await hashOneTimeCode(otc);
    expect(Buffer.from(hash1)).toEqual(Buffer.from(hash2));
    expect(hash1).toHaveLength(32);
  });

  it('should produce different hashes for different OTCs', async () => {
    const s = await ensureSodium();
    const otc1 = s.randombytes_buf(32);
    const otc2 = s.randombytes_buf(32);
    const hash1 = await hashOneTimeCode(otc1);
    const hash2 = await hashOneTimeCode(otc2);
    expect(Buffer.from(hash1)).not.toEqual(Buffer.from(hash2));
  });
});
