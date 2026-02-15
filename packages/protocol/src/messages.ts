/** Terminal output data from PTY to mobile */
export interface TerminalDataMessage {
  type: 'terminal_data';
  data: string; // base64 encoded terminal output
}

/** Terminal resize request from mobile */
export interface TerminalResizeMessage {
  type: 'terminal_resize';
  cols: number;
  rows: number;
}

/** Terminal input from mobile to PTY */
export interface TerminalInputMessage {
  type: 'terminal_input';
  data: string; // base64 encoded input
}

/** Claude Code hook events */
export interface HookEventMessage {
  type: 'hook_event';
  hookType: 'stop' | 'notification' | 'pre_tool_use' | 'subagent_stop';
  sessionId: string;
  payload: HookPayload;
}

export interface StopPayload {
  kind: 'stop';
  reason: string;
  transcript?: string;
}

export interface NotificationPayload {
  kind: 'notification';
  title: string;
  message: string;
  level: 'info' | 'warning' | 'error';
}

export interface PermissionPromptPayload {
  kind: 'permission_prompt';
  tool: string;
  command?: string;
  filePath?: string;
  description: string;
}

export interface PreToolUsePayload {
  kind: 'pre_tool_use';
  tool: string;
  input: Record<string, unknown>;
  requestId: string;
}

export interface SubagentStopPayload {
  kind: 'subagent_stop';
  agentId: string;
  status: string;
}

export type HookPayload =
  | StopPayload
  | NotificationPayload
  | PermissionPromptPayload
  | PreToolUsePayload
  | SubagentStopPayload;

/** Response to a hook event from mobile */
export interface HookResponseMessage {
  type: 'hook_response';
  requestId: string;
  action: 'approve' | 'deny' | 'input';
  value?: string; // for input responses
}

/** Ping/pong for connection keep-alive */
export interface PingMessage {
  type: 'ping';
  timestamp: number;
}

export interface PongMessage {
  type: 'pong';
  timestamp: number;
}

/** Session close */
export interface SessionCloseMessage {
  type: 'session_close';
  reason: string;
}

/** Key rotation notification */
export interface KeyRotationMessage {
  type: 'key_rotation';
  newPublicKey: string; // base64 encoded X25519 public key
}

/** Key exchange for E2E encryption setup */
export interface KeyExchangeMessage {
  type: 'key_exchange';
  publicKey: string; // base64url X25519 public key
  role: 'cli' | 'viewer';
}

export type ProtocolMessage =
  | TerminalDataMessage
  | TerminalResizeMessage
  | TerminalInputMessage
  | HookEventMessage
  | HookResponseMessage
  | PingMessage
  | PongMessage
  | SessionCloseMessage
  | KeyRotationMessage
  | KeyExchangeMessage;
