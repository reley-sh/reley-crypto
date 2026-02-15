import { PROTOCOL_VERSION, WIRE, MessageType, type MessageTypeValue } from './constants.js';
import type { ProtocolMessage } from './messages.js';

/**
 * Wire format:
 * [version:1B][type:1B][counter:4B BE][nonce:12B][ciphertext:var][tag:16B]
 *
 * AAD = version || type || counter
 */

export interface Envelope {
  version: number;
  type: MessageTypeValue;
  counter: number;
  nonce: Uint8Array;
  ciphertext: Uint8Array; // includes auth tag
}

const MESSAGE_TYPE_MAP: Record<string, MessageTypeValue> = {
  terminal_data: MessageType.TERMINAL_DATA,
  terminal_resize: MessageType.TERMINAL_RESIZE,
  terminal_input: MessageType.TERMINAL_INPUT,
  hook_event: MessageType.HOOK_EVENT,
  hook_response: MessageType.HOOK_RESPONSE,
  ping: MessageType.SESSION_PING,
  pong: MessageType.SESSION_PONG,
  session_close: MessageType.SESSION_CLOSE,
  key_rotation: MessageType.KEY_ROTATION,
  key_exchange: MessageType.KEY_EXCHANGE,
};

const REVERSE_TYPE_MAP = new Map<MessageTypeValue, string>();
for (const [k, v] of Object.entries(MESSAGE_TYPE_MAP)) {
  REVERSE_TYPE_MAP.set(v, k);
}

/**
 * Get the wire message type from a protocol message type string.
 */
export function getWireType(messageType: string): MessageTypeValue {
  const t = MESSAGE_TYPE_MAP[messageType];
  if (t === undefined) {
    throw new Error(`Unknown message type: ${messageType}`);
  }
  return t;
}

/**
 * Get the protocol message type string from a wire type.
 */
export function getMessageType(wireType: MessageTypeValue): string {
  const t = REVERSE_TYPE_MAP.get(wireType);
  if (!t) {
    throw new Error(`Unknown wire type: 0x${wireType.toString(16)}`);
  }
  return t;
}

/**
 * Build AAD bytes from envelope header fields.
 */
export function buildAAD(version: number, type: MessageTypeValue, counter: number): Uint8Array {
  const aad = new Uint8Array(6);
  aad[0] = version;
  aad[1] = type;
  aad[2] = (counter >>> 24) & 0xff;
  aad[3] = (counter >>> 16) & 0xff;
  aad[4] = (counter >>> 8) & 0xff;
  aad[5] = counter & 0xff;
  return aad;
}

/**
 * Encode an envelope to binary wire format.
 */
export function encodeEnvelope(envelope: Envelope): Uint8Array {
  const totalLen = WIRE.HEADER + envelope.ciphertext.length;
  const buf = new Uint8Array(totalLen);
  let offset = 0;

  buf[offset++] = envelope.version;
  buf[offset++] = envelope.type;

  // Counter as 4-byte big-endian
  buf[offset++] = (envelope.counter >>> 24) & 0xff;
  buf[offset++] = (envelope.counter >>> 16) & 0xff;
  buf[offset++] = (envelope.counter >>> 8) & 0xff;
  buf[offset++] = envelope.counter & 0xff;

  // Nonce (12 bytes)
  buf.set(envelope.nonce, offset);
  offset += WIRE.NONCE;

  // Ciphertext (variable length, includes tag)
  buf.set(envelope.ciphertext, offset);

  return buf;
}

/**
 * Decode binary wire format to an envelope.
 */
export function decodeEnvelope(data: Uint8Array): Envelope {
  if (data.length < WIRE.HEADER + WIRE.TAG) {
    throw new Error(`Envelope too short: ${data.length} bytes`);
  }

  let offset = 0;

  const version = data[offset++];
  if (version !== PROTOCOL_VERSION) {
    throw new Error(`Unsupported protocol version: ${version}`);
  }

  const type = data[offset++] as MessageTypeValue;

  const counter =
    (data[offset] << 24) |
    (data[offset + 1] << 16) |
    (data[offset + 2] << 8) |
    data[offset + 3];
  offset += 4;

  const nonce = data.slice(offset, offset + WIRE.NONCE);
  offset += WIRE.NONCE;

  const ciphertext = data.slice(offset);

  return { version, type, counter, nonce, ciphertext };
}

/**
 * Serialize a protocol message to JSON bytes for encryption.
 */
export function serializeMessage(message: ProtocolMessage): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(message));
}

/**
 * Deserialize JSON bytes to a protocol message.
 */
export function deserializeMessage(data: Uint8Array): ProtocolMessage {
  return JSON.parse(new TextDecoder().decode(data)) as ProtocolMessage;
}
