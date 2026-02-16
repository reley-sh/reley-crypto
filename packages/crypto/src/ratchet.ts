import { deriveChainKey } from './hkdf.js';
import { encrypt, decrypt } from './cipher.js';
import { zeroize } from './utils.js';

export const KEY_ROTATION_INTERVAL = 50;

export interface RatchetState {
  sendChainKey: Uint8Array;
  recvChainKey: Uint8Array;
  sendCounter: number;
  recvCounter: number;
  /** Highest received counter for replay protection */
  maxRecvCounter: number;
}

/**
 * Initialize a ratchet state from derived session keys.
 */
export function initRatchet(sendKey: Uint8Array, recvKey: Uint8Array): RatchetState {
  return {
    sendChainKey: sendKey,
    recvChainKey: recvKey,
    sendCounter: 0,
    recvCounter: 0,
    maxRecvCounter: -1,
  };
}

/**
 * Encrypt a message and advance the send ratchet.
 */
export async function ratchetEncrypt(
  state: RatchetState,
  plaintext: Uint8Array,
): Promise<{ ciphertext: Uint8Array; nonce: Uint8Array; counter: number; state: RatchetState }> {
  const { messageKey, nextChainKey } = await deriveChainKey(state.sendChainKey);
  const counter = state.sendCounter;

  // Build AAD: counter as 4-byte big-endian
  const aad = buildAAD(1, counter);

  const { nonce, ciphertext } = await encrypt(plaintext, messageKey, aad);

  // Zeroize message key after use
  await zeroize(messageKey);

  const newState: RatchetState = {
    ...state,
    sendChainKey: nextChainKey,
    sendCounter: counter + 1,
  };

  return { ciphertext, nonce, counter, state: newState };
}

/**
 * Decrypt a message and advance the receive ratchet.
 */
export async function ratchetDecrypt(
  state: RatchetState,
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  counter: number,
): Promise<{ plaintext: Uint8Array; state: RatchetState }> {
  // Replay protection: reject messages with counter <= maxRecvCounter
  if (counter <= state.maxRecvCounter) {
    throw new Error(`Replay attack detected: counter ${counter} <= ${state.maxRecvCounter}`);
  }

  // Prevent DoS via excessively large counter gaps.
  // Over a WebSocket (TCP-ordered), gaps should never exceed a few messages.
  const MAX_COUNTER_GAP = 1000;
  const gap = counter - state.recvCounter;
  if (gap > MAX_COUNTER_GAP) {
    throw new Error(`Counter gap too large: ${gap} (max ${MAX_COUNTER_GAP})`);
  }

  // Advance the recv chain to the correct counter
  let chainKey = state.recvChainKey;
  let currentCounter = state.recvCounter;
  let messageKey: Uint8Array | undefined;

  while (currentCounter <= counter) {
    const derived = await deriveChainKey(chainKey);
    if (currentCounter === counter) {
      messageKey = derived.messageKey;
    }
    chainKey = derived.nextChainKey;
    currentCounter++;
  }

  if (!messageKey) {
    throw new Error('Failed to derive message key');
  }

  const aad = buildAAD(1, counter);
  const plaintext = await decrypt(ciphertext, nonce, messageKey, aad);

  // Zeroize message key after use
  await zeroize(messageKey);

  const newState: RatchetState = {
    ...state,
    recvChainKey: chainKey,
    recvCounter: currentCounter,
    maxRecvCounter: counter,
  };

  return { plaintext, state: newState };
}

/**
 * Check if key rotation is needed.
 */
export function needsKeyRotation(state: RatchetState): boolean {
  return state.sendCounter > 0 && state.sendCounter % KEY_ROTATION_INTERVAL === 0;
}

/**
 * Build AAD bytes: version (1 byte) + type (1 byte) + counter (4 bytes BE)
 */
function buildAAD(version: number, counter: number): Uint8Array {
  const aad = new Uint8Array(6);
  aad[0] = version;
  aad[1] = 0x01; // message type
  aad[2] = (counter >>> 24) & 0xff;
  aad[3] = (counter >>> 16) & 0xff;
  aad[4] = (counter >>> 8) & 0xff;
  aad[5] = counter & 0xff;
  return aad;
}
