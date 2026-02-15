import { describe, it, expect } from 'vitest';
import { generateEphemeralKeyPair } from '../keys.js';
import { computeSharedSecret } from '../ecdh.js';

describe('ecdh', () => {
  it('should compute matching shared secrets', async () => {
    const alice = await generateEphemeralKeyPair();
    const bob = await generateEphemeralKeyPair();

    const secretAlice = await computeSharedSecret(alice.secretKey, bob.publicKey);
    const secretBob = await computeSharedSecret(bob.secretKey, alice.publicKey);

    expect(secretAlice).toHaveLength(32);
    expect(Buffer.from(secretAlice)).toEqual(Buffer.from(secretBob));
  });

  it('should produce different secrets for different key pairs', async () => {
    const alice = await generateEphemeralKeyPair();
    const bob = await generateEphemeralKeyPair();
    const carol = await generateEphemeralKeyPair();

    const secretAB = await computeSharedSecret(alice.secretKey, bob.publicKey);
    const secretAC = await computeSharedSecret(alice.secretKey, carol.publicKey);

    expect(Buffer.from(secretAB)).not.toEqual(Buffer.from(secretAC));
  });
});
