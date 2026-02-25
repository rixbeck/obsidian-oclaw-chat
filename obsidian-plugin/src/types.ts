/** Persisted plugin configuration */
export interface OpenClawSettings {
  /** WebSocket URL of the OpenClaw Gateway (e.g. ws://100.90.9.68:18789) */
  gatewayUrl: string;
  /** Auth token — must match the channel plugin's authToken */
  authToken: string;
  /** OpenClaw session key to subscribe to (e.g. "main") */
  sessionKey: string;
  /** (Deprecated) OpenClaw account ID (unused; chat.send uses sessionKey) */
  accountId: string;
  /** Whether to include the active note content with each message */
  includeActiveNote: boolean;
}

export const DEFAULT_SETTINGS: OpenClawSettings = {
  gatewayUrl: 'ws://localhost:18789',
  authToken: '',
  sessionKey: 'main',
  accountId: 'main',
  includeActiveNote: false,
};

/** A single chat message */
export interface ChatMessage {
  id: string;
  role: 'user' | 'assistant' | 'system';
  content: string;
  timestamp: number;
}

/** Payload for messages SENT to the server (outbound) */
export interface WSPayload {
  type: 'auth' | 'message' | 'ping' | 'pong' | 'error';
  payload?: Record<string, unknown>;
}

/** Messages RECEIVED from the server (inbound) — discriminated union */
export type InboundWSPayload =
  | { type: 'message'; payload: { content: string; role: string; timestamp: number } }
  | { type: 'error'; payload: { message: string } };

/** Available agents / models */
export interface AgentOption {
  id: string;
  label: string;
}
