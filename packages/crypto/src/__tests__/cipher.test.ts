import { describe, it, expect } from 'vitest';
import { encrypt, decrypt, KEY_LENGTH } from '../cipher.js';
import { ensureSodium } from '../keys.js';

describe('cipher (XChaCha20-Poly1305)', () => {
  it('should encrypt and decrypt round-trip', async () => {
    const s = await ensureSodium();
    const key = s.randombytes_buf(KEY_LENGTH);
    const plaintext = new TextEncoder().encode('Hello, Reley!');

    const { nonce, ciphertext } = await encrypt(plaintext, key);
    const decrypted = await decrypt(ciphertext, nonce, key);

    expect(new TextDecoder().decode(decrypted)).toBe('Hello, Reley!');
  });

  it('should fail with wrong key', async () => {
    const s = await ensureSodium();
    const key1 = s.randombytes_buf(KEY_LENGTH);
    const key2 = s.randombytes_buf(KEY_LENGTH);
    const plaintext = new TextEncoder().encode('secret');

    const { nonce, ciphertext } = await encrypt(plaintext, key1);
    await expect(decrypt(ciphertext, nonce, key2)).rejects.toThrow('Decryption failed');
  });

  it('should fail with tampered ciphertext', async () => {
    const s = await ensureSodium();
    const key = s.randombytes_buf(KEY_LENGTH);
    const plaintext = new TextEncoder().encode('secret');

    const { nonce, ciphertext } = await encrypt(plaintext, key);
    ciphertext[0] ^= 0xff; // tamper
    await expect(decrypt(ciphertext, nonce, key)).rejects.toThrow('Decryption failed');
  });

  it('should support AAD', async () => {
    const s = await ensureSodium();
    const key = s.randombytes_buf(KEY_LENGTH);
    const plaintext = new TextEncoder().encode('with aad');
    const aad = new TextEncoder().encode('additional data');

    const { nonce, ciphertext } = await encrypt(plaintext, key, aad);
    const decrypted = await decrypt(ciphertext, nonce, key, aad);
    expect(new TextDecoder().decode(decrypted)).toBe('with aad');

    // Wrong AAD should fail
    const wrongAad = new TextEncoder().encode('wrong');
    await expect(decrypt(ciphertext, nonce, key, wrongAad)).rejects.toThrow('Decryption failed');
  });

  it('should reject invalid key length', async () => {
    const plaintext = new TextEncoder().encode('test');
    const badKey = new Uint8Array(16);
    await expect(encrypt(plaintext, badKey)).rejects.toThrow('Key must be 32 bytes');
  });
});
