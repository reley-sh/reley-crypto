import { describe, it, expect } from 'vitest';
import { generateEphemeralKeyPair } from '../keys.js';
import { computeSharedSecret } from '../ecdh.js';
import { deriveSessionKeys } from '../hkdf.js';
import {
  initRatchet,
  ratchetEncrypt,
  ratchetDecrypt,
  needsKeyRotation,
  KEY_ROTATION_INTERVAL,
} from '../ratchet.js';

describe('ratchet', () => {
  async function createPairedRatchets() {
    const alice = await generateEphemeralKeyPair();
    const bob = await generateEphemeralKeyPair();

    const sharedAlice = await computeSharedSecret(alice.secretKey, bob.publicKey);
    const sharedBob = await computeSharedSecret(bob.secretKey, alice.publicKey);

    const keysAlice = await deriveSessionKeys(sharedAlice);
    const keysBob = await deriveSessionKeys(sharedBob);

    // Alice's send = Bob's recv, Alice's recv = Bob's send
    const aliceState = initRatchet(keysAlice.sendKey, keysAlice.recvKey);
    const bobState = initRatchet(keysBob.recvKey, keysBob.sendKey);

    return { aliceState, bobState };
  }

  it('should encrypt and decrypt a message', async () => {
    let { aliceState, bobState } = await createPairedRatchets();

    const plaintext = new TextEncoder().encode('Hello Bob!');
    const encrypted = await ratchetEncrypt(aliceState, plaintext);
    aliceState = encrypted.state;

    const decrypted = await ratchetDecrypt(
      bobState,
      encrypted.ciphertext,
      encrypted.nonce,
      encrypted.counter,
    );
    bobState = decrypted.state;

    expect(new TextDecoder().decode(decrypted.plaintext)).toBe('Hello Bob!');
  });

  it('should handle multiple messages', async () => {
    let { aliceState, bobState } = await createPairedRatchets();

    for (let i = 0; i < 10; i++) {
      const msg = `Message ${i}`;
      const encrypted = await ratchetEncrypt(aliceState, new TextEncoder().encode(msg));
      aliceState = encrypted.state;

      const decrypted = await ratchetDecrypt(
        bobState,
        encrypted.ciphertext,
        encrypted.nonce,
        encrypted.counter,
      );
      bobState = decrypted.state;

      expect(new TextDecoder().decode(decrypted.plaintext)).toBe(msg);
    }

    expect(aliceState.sendCounter).toBe(10);
  });

  it('should detect replay attacks', async () => {
    let { aliceState, bobState } = await createPairedRatchets();

    const encrypted = await ratchetEncrypt(
      aliceState,
      new TextEncoder().encode('first'),
    );
    aliceState = encrypted.state;

    const decrypted = await ratchetDecrypt(
      bobState,
      encrypted.ciphertext,
      encrypted.nonce,
      encrypted.counter,
    );
    bobState = decrypted.state;

    // Replay the same message
    await expect(
      ratchetDecrypt(bobState, encrypted.ciphertext, encrypted.nonce, encrypted.counter),
    ).rejects.toThrow('Replay attack detected');
  });

  it('should signal key rotation need', () => {
    const state = initRatchet(new Uint8Array(32), new Uint8Array(32));
    expect(needsKeyRotation(state)).toBe(false);

    const rotationState = { ...state, sendCounter: KEY_ROTATION_INTERVAL };
    expect(needsKeyRotation(rotationState)).toBe(true);
  });

  it('should handle bidirectional communication', async () => {
    let { aliceState, bobState } = await createPairedRatchets();

    // Alice → Bob
    const enc1 = await ratchetEncrypt(aliceState, new TextEncoder().encode('A→B'));
    aliceState = enc1.state;
    const dec1 = await ratchetDecrypt(bobState, enc1.ciphertext, enc1.nonce, enc1.counter);
    bobState = dec1.state;
    expect(new TextDecoder().decode(dec1.plaintext)).toBe('A→B');

    // Bob → Alice
    const enc2 = await ratchetEncrypt(bobState, new TextEncoder().encode('B→A'));
    bobState = enc2.state;
    const dec2 = await ratchetDecrypt(aliceState, enc2.ciphertext, enc2.nonce, enc2.counter);
    aliceState = dec2.state;
    expect(new TextDecoder().decode(dec2.plaintext)).toBe('B→A');
  });
});
