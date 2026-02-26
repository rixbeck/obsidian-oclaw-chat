/**
 * Type definitions for Obsidian Channel Plugin
 */

export interface ObsidianChannelConfig {
  enabled: boolean;
  wsPort: number;
  authToken: string;
  accounts: string[];
}

export interface PluginContext {
  log: Logger;
  config: ObsidianChannelConfig;
  runtime: any;
}

export interface Logger {
  info(message: string, meta?: any): void;
  warn(message: string, meta?: any): void;
  error(message: string, meta?: any): void;
  debug(message: string, meta?: any): void;
}

export interface WSMessage {
  type: 'auth' | 'message' | 'ping' | 'pong' | 'error';
  payload?: any;
  sessionId?: string;
  agentId?: string;
}

export interface InboundMessage {
  sessionId: string;
  agentId: string;
  message: string;
  context?: {
    activeNote?: string;
    noteContent?: string;
  };
}

export interface OutboundMessage {
  type: 'message' | 'error';
  payload: {
    content: string;
    timestamp: number;
  };
}

export interface SessionInfo {
  sessionId: string;
  agentId: string;
  wsClient: any; // WebSocket client
  authenticated: boolean;
}
