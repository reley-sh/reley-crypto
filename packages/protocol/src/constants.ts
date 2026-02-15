/** Protocol version */
export const PROTOCOL_VERSION = 1;

/** Wire format field sizes in bytes */
export const WIRE = {
  VERSION: 1,
  TYPE: 1,
  COUNTER: 4,
  NONCE: 12,
  TAG: 16,
  HEADER: 1 + 1 + 4 + 12, // 18 bytes total header before ciphertext
} as const;

/** Message types for the wire format */
export const MessageType = {
  TERMINAL_DATA: 0x01,
  TERMINAL_RESIZE: 0x02,
  TERMINAL_INPUT: 0x03,
  HOOK_EVENT: 0x10,
  HOOK_RESPONSE: 0x11,
  SESSION_PING: 0x20,
  SESSION_PONG: 0x21,
  SESSION_CLOSE: 0x22,
  KEY_ROTATION: 0x30,
  KEY_EXCHANGE: 0x31,
} as const;

export type MessageTypeValue = (typeof MessageType)[keyof typeof MessageType];

/** Timeouts in milliseconds */
export const TIMEOUTS = {
  PAIRING_EXPIRY: 5 * 60 * 1000, // 5 minutes
  JWT_EXPIRY: 24 * 60 * 60 * 1000, // 24 hours
  PING_INTERVAL: 30 * 1000, // 30 seconds
  PONG_TIMEOUT: 10 * 1000, // 10 seconds
  WS_RECONNECT_BASE: 1000, // 1 second base for exponential backoff
  WS_RECONNECT_MAX: 30 * 1000, // 30 seconds max
  HOOK_RESPONSE_TIMEOUT: 5 * 60 * 1000, // 5 minutes for user approval
} as const;

/** Rate limits */
export const RATE_LIMITS = {
  CONNECTIONS_PER_IP_PER_MINUTE: 100,
  MESSAGES_PER_DEVICE_PER_MINUTE: 5000,
  PAIRING_PER_HOUR: 10,
} as const;

/** WebSocket close codes */
export const WS_CLOSE = {
  SERVER_RESTART: 4006,
  SESSION_EXPIRED: 4007,
} as const;

/** Plan limits */
export const PLAN_LIMITS = {
  FREE_MAX_CONCURRENT_SESSIONS: 1,
  FREE_MAX_SESSION_DURATION_MS: 30 * 60 * 1000,
  FREE_WARNING_BEFORE_EXPIRY_MS: 5 * 60 * 1000,
} as const;

/** Push notification */
export const PUSH = {
  DEBOUNCE_MS: 2000,
  MAX_PAYLOAD_BYTES: 4096,
} as const;
