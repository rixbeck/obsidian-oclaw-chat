import type { ChatMessage } from './types';

/** Manages the in-memory list of chat messages and notifies UI on changes */
export class ChatManager {
  private messages: ChatMessage[] = [];

  /** Fired for a full re-render (clear/reload) */
  onUpdate: ((messages: readonly ChatMessage[]) => void) | null = null;
  /** Fired when a single message is appended — use for O(1) append-only UI */
  onMessageAdded: ((msg: ChatMessage) => void) | null = null;

  addMessage(msg: ChatMessage): void {
    this.messages.push(msg);
    this.onMessageAdded?.(msg);
  }

  getMessages(): readonly ChatMessage[] {
    return this.messages;
  }

  clear(): void {
    this.messages = [];
    this.onUpdate?.([]);
  }

  /** Create a user message object (without adding it) */
  static createUserMessage(content: string): ChatMessage {
    return {
      id: `msg-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      role: 'user',
      content,
      timestamp: Date.now(),
    };
  }

  /** Create an assistant message object (without adding it) */
  static createAssistantMessage(content: string): ChatMessage {
    return {
      id: `msg-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      role: 'assistant',
      content,
      timestamp: Date.now(),
    };
  }

  /** Create a system / status message (errors, reconnect notices, etc.) */
  static createSystemMessage(content: string, level: ChatMessage['level'] = 'info'): ChatMessage {
    return {
      id: `sys-${Date.now()}`,
      role: 'system',
      level,
      content,
      timestamp: Date.now(),
    };
  }
}
