import { describe, it, expect } from 'vitest';
import { deriveSessionKeys, deriveChainKey } from '../hkdf.js';
import { ensureSodium } from '../keys.js';

describe('hkdf', () => {
  it('should derive different send and recv keys', async () => {
    const s = await ensureSodium();
    const sharedSecret = s.randombytes_buf(32);

    const { sendKey, recvKey } = await deriveSessionKeys(sharedSecret);
    expect(sendKey).toHaveLength(32);
    expect(recvKey).toHaveLength(32);
    expect(Buffer.from(sendKey)).not.toEqual(Buffer.from(recvKey));
  });

  it('should produce deterministic keys for same input', async () => {
    const s = await ensureSodium();
    const sharedSecret = s.randombytes_buf(32);

    const keys1 = await deriveSessionKeys(sharedSecret);
    const keys2 = await deriveSessionKeys(sharedSecret);

    expect(Buffer.from(keys1.sendKey)).toEqual(Buffer.from(keys2.sendKey));
    expect(Buffer.from(keys1.recvKey)).toEqual(Buffer.from(keys2.recvKey));
  });

  it('should produce different keys for different secrets', async () => {
    const s = await ensureSodium();
    const secret1 = s.randombytes_buf(32);
    const secret2 = s.randombytes_buf(32);

    const keys1 = await deriveSessionKeys(secret1);
    const keys2 = await deriveSessionKeys(secret2);

    expect(Buffer.from(keys1.sendKey)).not.toEqual(Buffer.from(keys2.sendKey));
  });

  it('should derive chain keys progressively', async () => {
    const s = await ensureSodium();
    const chainKey = s.randombytes_buf(32);

    const { messageKey, nextChainKey } = await deriveChainKey(chainKey);
    expect(messageKey).toHaveLength(32);
    expect(nextChainKey).toHaveLength(32);

    // Chain key should change
    expect(Buffer.from(nextChainKey)).not.toEqual(Buffer.from(chainKey));
    // Message key should differ from chain key
    expect(Buffer.from(messageKey)).not.toEqual(Buffer.from(chainKey));
  });

  it('should produce deterministic chain progression', async () => {
    const s = await ensureSodium();
    const chainKey = s.randombytes_buf(32);

    const result1 = await deriveChainKey(chainKey);
    const result2 = await deriveChainKey(chainKey);

    expect(Buffer.from(result1.messageKey)).toEqual(Buffer.from(result2.messageKey));
    expect(Buffer.from(result1.nextChainKey)).toEqual(Buffer.from(result2.nextChainKey));
  });
});
