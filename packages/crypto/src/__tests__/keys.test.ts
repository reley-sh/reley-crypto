import { describe, it, expect } from 'vitest';
import {
  generateIdentityKeyPair,
  generateEphemeralKeyPair,
  ed25519ToX25519Public,
  ed25519ToX25519Secret,
  generateOneTimeCode,
  sign,
  verify,
} from '../keys.js';

describe('keys', () => {
  it('should generate Ed25519 identity key pair', async () => {
    const kp = await generateIdentityKeyPair();
    expect(kp.keyType).toBe('ed25519');
    expect(kp.publicKey).toHaveLength(32);
    expect(kp.secretKey).toHaveLength(64);
  });

  it('should generate unique key pairs', async () => {
    const kp1 = await generateIdentityKeyPair();
    const kp2 = await generateIdentityKeyPair();
    expect(kp1.publicKey).not.toEqual(kp2.publicKey);
  });

  it('should generate X25519 ephemeral key pair', async () => {
    const kp = await generateEphemeralKeyPair();
    expect(kp.keyType).toBe('x25519');
    expect(kp.publicKey).toHaveLength(32);
    expect(kp.secretKey).toHaveLength(32);
  });

  it('should convert Ed25519 to X25519 keys', async () => {
    const ed = await generateIdentityKeyPair();
    const x25519Pk = await ed25519ToX25519Public(ed.publicKey);
    const x25519Sk = await ed25519ToX25519Secret(ed.secretKey);
    expect(x25519Pk).toHaveLength(32);
    expect(x25519Sk).toHaveLength(32);
  });

  it('should generate one-time code', async () => {
    const otc = await generateOneTimeCode(32);
    expect(otc).toHaveLength(32);
    const otc2 = await generateOneTimeCode(32);
    expect(otc).not.toEqual(otc2);
  });

  it('should sign and verify messages', async () => {
    const kp = await generateIdentityKeyPair();
    const message = new TextEncoder().encode('hello world');
    const signature = await sign(message, kp.secretKey);
    expect(signature).toHaveLength(64);

    const valid = await verify(signature, message, kp.publicKey);
    expect(valid).toBe(true);

    // Tampered message should fail
    const tampered = new TextEncoder().encode('hello world!');
    const invalid = await verify(signature, tampered, kp.publicKey);
    expect(invalid).toBe(false);
  });
});
