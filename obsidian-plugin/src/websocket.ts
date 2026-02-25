import type { WSPayload, InboundWSPayload } from './types';

/** Milliseconds before a reconnect attempt after an unexpected close */
const RECONNECT_DELAY_MS = 3_000;
/** Interval for sending heartbeat pings to the server */
const HEARTBEAT_INTERVAL_MS = 30_000;
/** Maximum time to wait for a pong before considering the connection dead */
const PONG_TIMEOUT_MS = 10_000;

export type WSClientState = 'disconnected' | 'connecting' | 'authenticating' | 'connected';

export class ObsidianWSClient {
  private ws: WebSocket | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  private pongTimer: ReturnType<typeof setTimeout> | null = null;
  private intentionalClose = false;
  private sessionId: string;
  private agentId: string;
  private url = '';
  private token = '';

  state: WSClientState = 'disconnected';

  // ── Callbacks (set by consumers) ─────────────────────────────────────────
  onMessage: ((msg: InboundWSPayload) => void) | null = null;
  onStateChange: ((state: WSClientState) => void) | null = null;

  constructor() {
    // Use a stable, random session ID per plugin lifetime
    this.sessionId = `obs-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
    this.agentId = 'main';
  }

  // ── Public API ────────────────────────────────────────────────────────────

  connect(url: string, token: string, agentId = 'main'): void {
    this.url = url;
    this.token = token;
    this.agentId = agentId;
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

  send(payload: WSPayload): void {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      console.warn('[oclaw-ws] send() called while not connected — dropping message');
      return;
    }
    this.ws.send(JSON.stringify(payload));
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

    // Obsidian is Electron/browser — use window.WebSocket directly
    const ws = new WebSocket(this.url);
    this.ws = ws;

    ws.onopen = () => {
      this._setState('authenticating');
      // Send auth handshake immediately after connect
      ws.send(
        JSON.stringify({
          type: 'auth',
          payload: {
            // IMPORTANT: never log the token value
            token: this.token,
            sessionId: this.sessionId,
            agentId: this.agentId,
          },
        })
      );
    };

    ws.onmessage = (event: MessageEvent) => {
      let msg: InboundWSPayload;
      try {
        msg = JSON.parse(event.data as string) as InboundWSPayload;
      } catch {
        console.error('[oclaw-ws] Failed to parse incoming message');
        return;
      }

      // Handle pong for heartbeat
      if (msg.type === 'pong') {
        if (this.pongTimer) {
          clearTimeout(this.pongTimer);
          this.pongTimer = null;
        }
        return;
      }

      // Handle auth response
      if (msg.type === 'auth' && this.state === 'authenticating') {
        if (msg.payload.success) {
          // Adopt the server-assigned sessionId so RPC targeting works correctly
          if (msg.payload.sessionId) {
            this.sessionId = msg.payload.sessionId;
          }
          this._setState('connected');
          this._startHeartbeat();
        } else {
          console.error('[oclaw-ws] Authentication rejected by server');
          this._setState('disconnected');
          ws.close();
        }
        return;
      }

      this.onMessage?.(msg);
    };

    ws.onclose = () => {
      this._stopTimers();
      this._setState('disconnected');
      if (!this.intentionalClose) {
        this._scheduleReconnect();
      }
    };

    ws.onerror = (ev: Event) => {
      console.error('[oclaw-ws] WebSocket error', ev);
      // onclose will fire after onerror — reconnect logic handled there
    };
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
      this.ws.send(JSON.stringify({ type: 'ping' }));
      // Expect pong within PONG_TIMEOUT_MS, otherwise force reconnect
      this.pongTimer = setTimeout(() => {
        console.warn('[oclaw-ws] Pong timeout — reconnecting');
        this.ws?.close();
      }, PONG_TIMEOUT_MS);
    }, HEARTBEAT_INTERVAL_MS);
  }

  private _stopHeartbeat(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
    if (this.pongTimer) {
      clearTimeout(this.pongTimer);
      this.pongTimer = null;
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
