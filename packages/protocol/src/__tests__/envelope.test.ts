import { describe, it, expect } from 'vitest';
import {
  encodeEnvelope,
  decodeEnvelope,
  serializeMessage,
  deserializeMessage,
  getWireType,
  getMessageType,
  buildAAD,
  type Envelope,
} from '../envelope.js';
import { PROTOCOL_VERSION, MessageType } from '../constants.js';
import type { TerminalDataMessage, PingMessage } from '../messages.js';

describe('envelope', () => {
  it('should encode and decode envelope round-trip', () => {
    const envelope: Envelope = {
      version: PROTOCOL_VERSION,
      type: MessageType.TERMINAL_DATA,
      counter: 42,
      nonce: new Uint8Array(12).fill(0xab),
      ciphertext: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18]),
    };

    const encoded = encodeEnvelope(envelope);
    const decoded = decodeEnvelope(encoded);

    expect(decoded.version).toBe(PROTOCOL_VERSION);
    expect(decoded.type).toBe(MessageType.TERMINAL_DATA);
    expect(decoded.counter).toBe(42);
    expect(Buffer.from(decoded.nonce)).toEqual(Buffer.from(envelope.nonce));
    expect(Buffer.from(decoded.ciphertext)).toEqual(Buffer.from(envelope.ciphertext));
  });

  it('should reject invalid version', () => {
    const buf = new Uint8Array(36);
    buf[0] = 99; // invalid version
    expect(() => decodeEnvelope(buf)).toThrow('Unsupported protocol version');
  });

  it('should reject too-short data', () => {
    const buf = new Uint8Array(10);
    expect(() => decodeEnvelope(buf)).toThrow('Envelope too short');
  });

  it('should encode counter as big-endian', () => {
    const envelope: Envelope = {
      version: PROTOCOL_VERSION,
      type: MessageType.SESSION_PING,
      counter: 0x01020304,
      nonce: new Uint8Array(12),
      ciphertext: new Uint8Array(20),
    };

    const encoded = encodeEnvelope(envelope);
    // counter bytes at offset 2-5
    expect(encoded[2]).toBe(0x01);
    expect(encoded[3]).toBe(0x02);
    expect(encoded[4]).toBe(0x03);
    expect(encoded[5]).toBe(0x04);
  });
});

describe('message serialization', () => {
  it('should serialize and deserialize messages', () => {
    const msg: TerminalDataMessage = {
      type: 'terminal_data',
      data: btoa('hello'),
    };

    const bytes = serializeMessage(msg);
    const decoded = deserializeMessage(bytes) as TerminalDataMessage;

    expect(decoded.type).toBe('terminal_data');
    expect(decoded.data).toBe(msg.data);
  });

  it('should handle ping messages', () => {
    const msg: PingMessage = { type: 'ping', timestamp: Date.now() };
    const bytes = serializeMessage(msg);
    const decoded = deserializeMessage(bytes) as PingMessage;
    expect(decoded.type).toBe('ping');
    expect(decoded.timestamp).toBe(msg.timestamp);
  });
});

describe('wire type mapping', () => {
  it('should map message types correctly', () => {
    expect(getWireType('terminal_data')).toBe(MessageType.TERMINAL_DATA);
    expect(getWireType('hook_event')).toBe(MessageType.HOOK_EVENT);
    expect(getWireType('ping')).toBe(MessageType.SESSION_PING);
  });

  it('should reverse map wire types', () => {
    expect(getMessageType(MessageType.TERMINAL_DATA)).toBe('terminal_data');
    expect(getMessageType(MessageType.HOOK_EVENT)).toBe('hook_event');
  });

  it('should throw on unknown types', () => {
    expect(() => getWireType('unknown')).toThrow('Unknown message type');
    expect(() => getMessageType(0xff as any)).toThrow('Unknown wire type');
  });
});

describe('buildAAD', () => {
  it('should build correct AAD bytes', () => {
    const aad = buildAAD(1, MessageType.TERMINAL_DATA, 256);
    expect(aad).toHaveLength(6);
    expect(aad[0]).toBe(1); // version
    expect(aad[1]).toBe(MessageType.TERMINAL_DATA); // type
    expect(aad[2]).toBe(0); // counter high byte
    expect(aad[3]).toBe(0);
    expect(aad[4]).toBe(1);
    expect(aad[5]).toBe(0); // 256 = 0x0100
  });
});
