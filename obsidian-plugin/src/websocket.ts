/**
 * WebSocket client for OpenClaw Gateway
 *
 * Pivot (2026-02-25): Do NOT use custom obsidian.* gateway methods.
 * Those require operator.admin scope which is not granted to external clients.
 *
 * Instead we use built-in gateway methods/events:
 * - Send: chat.send({ sessionKey, message, idempotencyKey, ... })
 * - Receive: event "chat" (filter by sessionKey)
 */

import type { InboundWSPayload } from './types';

/** Milliseconds before a reconnect attempt after an unexpected close */
const RECONNECT_DELAY_MS = 3_000;
/** Interval for sending heartbeat pings (check connection liveness) */
const HEARTBEAT_INTERVAL_MS = 30_000;

export type WSClientState = 'disconnected' | 'connecting' | 'handshaking' | 'connected';

interface PendingRequest {
  resolve: (payload: any) => void;
  reject: (error: any) => void;
}

function extractTextFromGatewayMessage(msg: any): string {
  if (!msg) return '';

  // Most common: { role, content } where content can be string or [{type:'text',text:'...'}]
  const content = msg.content ?? msg.message ?? msg;
  if (typeof content === 'string') return content;

  if (Array.isArray(content)) {
    const parts = content
      .filter((c) => c && typeof c === 'object' && c.type === 'text' && typeof c.text === 'string')
      .map((c) => c.text);
    return parts.join('\n');
  }

  // Fallback
  try {
    return JSON.stringify(content);
  } catch {
    return String(content);
  }
}

export class ObsidianWSClient {
  private ws: WebSocket | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  private intentionalClose = false;
  private sessionKey: string;
  private url = '';
  private token = '';
  private requestId = 0;
  private pendingRequests = new Map<string, PendingRequest>();

  state: WSClientState = 'disconnected';

  onMessage: ((msg: InboundWSPayload) => void) | null = null;
  onStateChange: ((state: WSClientState) => void) | null = null;

  constructor(sessionKey: string) {
    this.sessionKey = sessionKey;
  }

  connect(url: string, token: string): void {
    this.url = url;
    this.token = token;
    this.intentionalClose = false;
    this._connect();
  }

  disconnect(): void {
    this.intentionalClose = true;
    this._stopTimers();
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    this._setState('disconnected');
  }

  async sendMessage(message: string): Promise<void> {
    if (this.state !== 'connected') {
      throw new Error('Not connected — call connect() first');
    }

    const idempotencyKey = `obsidian-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;

    await this._sendRequest('chat.send', {
      sessionKey: this.sessionKey,
      message,
      idempotencyKey,
      // deliver defaults to true in gateway; keep default
    });
  }

  private _connect(): void {
    if (this.ws) {
      this.ws.onopen = null;
      this.ws.onclose = null;
      this.ws.onmessage = null;
      this.ws.onerror = null;
      this.ws.close();
      this.ws = null;
    }

    this._setState('connecting');

    const ws = new WebSocket(this.url);
    this.ws = ws;

    ws.onopen = async () => {
      this._setState('handshaking');
      try {
        await this._sendRequest('connect', {
          minProtocol: 3,
          maxProtocol: 3,
          client: {
            id: 'gateway-client',
            mode: 'backend',
            version: '0.1.8',
            platform: 'electron',
          },
          role: 'operator',
          scopes: ['operator.write'],
          auth: {
            token: this.token,
          },
        });

        this._setState('connected');
        this._startHeartbeat();
      } catch (err) {
        console.error('[oclaw-ws] Connect handshake failed', err);
        ws.close();
      }
    };

    ws.onmessage = (event: MessageEvent) => {
      let frame: any;
      try {
        frame = JSON.parse(event.data as string);
      } catch {
        console.error('[oclaw-ws] Failed to parse incoming message');
        return;
      }

      // Responses
      if (frame.type === 'res') {
        const pending = this.pendingRequests.get(frame.id);
        if (pending) {
          this.pendingRequests.delete(frame.id);
          if (frame.ok) pending.resolve(frame.payload);
          else pending.reject(new Error(frame.error?.message || 'Request failed'));
        }
        return;
      }

      // Events
      if (frame.type === 'event') {
        if (frame.event === 'chat') {
          const payload = frame.payload;
          if (payload?.sessionKey !== this.sessionKey) {
            return;
          }

          // We only append assistant output to UI.
          const msg = payload?.message;
          const role = msg?.role ?? 'assistant';
          if (role !== 'assistant') {
            return;
          }

          const text = extractTextFromGatewayMessage(msg);
          if (!text) return;

          this.onMessage?.({
            type: 'message',
            payload: {
              content: text,
              role: 'assistant',
              timestamp: Date.now(),
            },
          });
        }
        return;
      }

      console.debug('[oclaw-ws] Unhandled frame', frame);
    };

    ws.onclose = () => {
      this._stopTimers();
      this._setState('disconnected');

      for (const pending of this.pendingRequests.values()) {
        pending.reject(new Error('Connection closed'));
      }
      this.pendingRequests.clear();

      if (!this.intentionalClose) {
        this._scheduleReconnect();
      }
    };

    ws.onerror = (ev: Event) => {
      console.error('[oclaw-ws] WebSocket error', ev);
    };
  }

  private _sendRequest(method: string, params: any): Promise<any> {
    return new Promise((resolve, reject) => {
      if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
        reject(new Error('WebSocket not connected'));
        return;
      }

      const id = `req-${++this.requestId}`;
      this.pendingRequests.set(id, { resolve, reject });

      this.ws.send(
        JSON.stringify({
          type: 'req',
          method,
          id,
          params,
        })
      );

      setTimeout(() => {
        if (this.pendingRequests.has(id)) {
          this.pendingRequests.delete(id);
          reject(new Error(`Request timeout: ${method}`));
        }
      }, 30_000);
    });
  }

  private _scheduleReconnect(): void {
    if (this.reconnectTimer !== null) return;
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      if (!this.intentionalClose) {
        console.log(`[oclaw-ws] Reconnecting to ${this.url}…`);
        this._connect();
      }
    }, RECONNECT_DELAY_MS);
  }

  private _startHeartbeat(): void {
    this._stopHeartbeat();
    this.heartbeatTimer = setInterval(() => {
      if (this.ws?.readyState !== WebSocket.OPEN) return;
      if (this.ws.bufferedAmount > 0) {
        console.warn('[oclaw-ws] Send buffer not empty — connection may be stalled');
      }
    }, HEARTBEAT_INTERVAL_MS);
  }

  private _stopHeartbeat(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }

  private _stopTimers(): void {
    this._stopHeartbeat();
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
  }

  private _setState(state: WSClientState): void {
    if (this.state === state) return;
    this.state = state;
    this.onStateChange?.(state);
  }
}
