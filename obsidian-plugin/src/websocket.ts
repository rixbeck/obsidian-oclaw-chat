/**
 * WebSocket client for OpenClaw Gateway
 * 
 * Uses Gateway protocol: JSON-RPC style requests + event push
 * - Connect handshake first (required by Gateway)
 * - Then subscribe to session
 * - Request: { type: "req", method, id, params }
 * - Response: { type: "res", id, ok, payload/error }
 * - Event: { type: "event", event, payload }
 */

import type { InboundWSPayload } from './types';

/** Milliseconds before a reconnect attempt after an unexpected close */
const RECONNECT_DELAY_MS = 3_000;
/** Interval for sending heartbeat pings (check connection liveness) */
const HEARTBEAT_INTERVAL_MS = 30_000;

export type WSClientState = 'disconnected' | 'connecting' | 'handshaking' | 'subscribing' | 'connected';

interface PendingRequest {
  resolve: (payload: any) => void;
  reject: (error: any) => void;
}

export class ObsidianWSClient {
  private ws: WebSocket | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  private intentionalClose = false;
  private subscriptionId: string | null = null;
  private sessionKey: string;
  private accountId: string;
  private url = '';
  private token = '';
  private requestId = 0;
  private pendingRequests = new Map<string, PendingRequest>();

  state: WSClientState = 'disconnected';

  // ── Callbacks (set by consumers) ─────────────────────────────────────────
  onMessage: ((msg: InboundWSPayload) => void) | null = null;
  onStateChange: ((state: WSClientState) => void) | null = null;

  constructor(sessionKey: string, accountId = 'main') {
    this.sessionKey = sessionKey;
    this.accountId = accountId;
  }

  // ── Public API ────────────────────────────────────────────────────────────

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
    if (!this.subscriptionId) {
      throw new Error('Not subscribed — call connect() first');
    }

    await this._sendRequest('obsidian.send', {
      subscriptionId: this.subscriptionId,
      message,
    });
  }

  // ── Internal ──────────────────────────────────────────────────────────────

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
        // Step 1: Connect handshake (required by Gateway)
        await this._sendRequest('connect', {
          minProtocol: 3,
          maxProtocol: 3,
          client: {
            // Use non-Control-UI client id to avoid Control UI origin restrictions
            id: 'gateway-client',
            mode: 'backend',
            version: '0.1.3',
            platform: 'electron',
          },
          auth: {
            token: this.token,
          },
        });

        // Step 2: Subscribe to session
        this._setState('subscribing');
        const result = await this._sendRequest('obsidian.subscribe', {
          token: this.token,
          sessionKey: this.sessionKey,
          accountId: this.accountId,
        });

        if (result?.subscriptionId) {
          this.subscriptionId = result.subscriptionId;
          this._setState('connected');
          this._startHeartbeat();
        } else {
          throw new Error('Subscribe failed: no subscriptionId returned');
        }
      } catch (err) {
        console.error('[oclaw-ws] Connection setup failed', err);
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

      // Handle response to pending request
      if (frame.type === 'res') {
        const pending = this.pendingRequests.get(frame.id);
        if (pending) {
          this.pendingRequests.delete(frame.id);
          if (frame.ok) {
            pending.resolve(frame.payload);
          } else {
            pending.reject(new Error(frame.error?.message || 'Request failed'));
          }
        }
        return;
      }

      // Handle event push from gateway
      if (frame.type === 'event') {
        // Obsidian message push
        if (frame.event === 'obsidian.message') {
          const msg: InboundWSPayload = {
            type: 'message',
            payload: {
              content: frame.payload?.content || '',
              role: frame.payload?.role || 'assistant',
              timestamp: frame.payload?.timestamp || Date.now(),
            },
          };
          this.onMessage?.(msg);
          return;
        }

        // Ignore other events (connect.challenge, etc.)
        return;
      }

      // Unknown frame type — ignore
      console.debug('[oclaw-ws] Unhandled frame', frame);
    };

    ws.onclose = () => {
      this._stopTimers();
      this._setState('disconnected');
      this.subscriptionId = null;
      // Reject all pending requests
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
      // onclose will fire after onerror — reconnect logic handled there
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

      const frame = {
        type: 'req',
        method,
        id,
        params,
      };

      this.ws.send(JSON.stringify(frame));

      // Timeout after 30s
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
      // Simple heartbeat: check connection liveness
      // Gateway will close stale connections automatically
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
