/** Persisted plugin configuration */
export interface OpenClawSettings {
  /** WebSocket URL of the OpenClaw channel plugin (e.g. ws://localhost:8765) */
  gatewayUrl: string;
  /** Auth token — must match the channel plugin's authToken */
  authToken: string;
  /** Default agent to chat with */
  defaultAgent: string;
  /** Whether to include the active note content with each message */
  includeActiveNote: boolean;
}

export const DEFAULT_SETTINGS: OpenClawSettings = {
  gatewayUrl: 'ws://localhost:8765',
  authToken: '',
  defaultAgent: 'main',
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
  | { type: 'auth'; payload: { success: boolean; sessionId?: string } }
  | { type: 'message'; payload: { content: string; timestamp: number } }
  | { type: 'error'; payload: { message: string } }
  | { type: 'pong' };

/** Available agents / models */
export interface AgentOption {
  id: string;
  label: string;
}
