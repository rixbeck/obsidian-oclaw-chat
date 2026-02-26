/**
 * WebSocket client for OpenClaw Gateway
 *
 * Pivot (2026-02-25): Do NOT use custom obsidian.* gateway methods.
 * Those require operator.admin scope which is not granted to external clients.
 *
 * Auth note:
 * - chat.send requires operator.write
 * - external clients must present a paired device identity to receive write scopes
 *
 * We use built-in gateway methods/events:
 * - Send: chat.send({ sessionKey, message, idempotencyKey, ... })
 * - Receive: event "chat" (filter by sessionKey)
 */

import type { InboundWSPayload } from './types';

/** Milliseconds before a reconnect attempt after an unexpected close */
const RECONNECT_DELAY_MS = 3_000;
/** Interval for sending heartbeat pings (check connection liveness) */
const HEARTBEAT_INTERVAL_MS = 30_000;

/** Safety valve: hide working spinner if no assistant reply arrives in time */
const WORKING_MAX_MS = 120_000;

export type WSClientState = 'disconnected' | 'connecting' | 'handshaking' | 'connected';

export type WorkingStateListener = (working: boolean) => void;

interface PendingRequest {
  resolve: (payload: any) => void;
  reject: (error: any) => void;
}

type DeviceIdentity = {
  id: string;
  publicKey: string; // base64
  privateKeyJwk: JsonWebKey;
};

const DEVICE_STORAGE_KEY = 'openclawChat.deviceIdentity.v1';

function base64UrlEncode(bytes: ArrayBuffer): string {
  const u8 = new Uint8Array(bytes);
  let s = '';
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  const b64 = btoa(s);
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function hexEncode(bytes: ArrayBuffer): string {
  const u8 = new Uint8Array(bytes);
  return Array.from(u8)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function utf8Bytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

async function sha256Hex(bytes: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return hexEncode(digest);
}

async function loadOrCreateDeviceIdentity(): Promise<DeviceIdentity> {
  const existing = localStorage.getItem(DEVICE_STORAGE_KEY);
  if (existing) {
    const parsed = JSON.parse(existing) as DeviceIdentity;
    if (parsed?.id && parsed?.publicKey && parsed?.privateKeyJwk) return parsed;
  }

  const keyPair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const pubRaw = await crypto.subtle.exportKey('raw', keyPair.publicKey);
  const privJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);

  // IMPORTANT: device.id must be a stable fingerprint for the public key.
  // The gateway enforces deviceId ↔ publicKey binding; random ids can cause "device identity mismatch".
  const deviceId = await sha256Hex(pubRaw);
  const id = deviceId;

  const identity: DeviceIdentity = {
    id,
    publicKey: base64UrlEncode(pubRaw),
    privateKeyJwk: privJwk,
  };

  localStorage.setItem(DEVICE_STORAGE_KEY, JSON.stringify(identity));
  return identity;
}

function buildDeviceAuthPayload(params: {
  deviceId: string;
  clientId: string;
  clientMode: string;
  role: string;
  scopes: string[];
  signedAtMs: number;
  token: string;
  nonce?: string;
}): string {
  const version = params.nonce ? 'v2' : 'v1';
  const scopes = params.scopes.join(',');
  const base = [
    version,
    params.deviceId,
    params.clientId,
    params.clientMode,
    params.role,
    scopes,
    String(params.signedAtMs),
    params.token || '',
  ];
  if (version === 'v2') base.push(params.nonce || '');
  return base.join('|');
}

async function signDevicePayload(identity: DeviceIdentity, payload: string): Promise<{ signature: string; signedAt: number }> {
  const privateKey = await crypto.subtle.importKey(
    'jwk',
    identity.privateKeyJwk,
    { name: 'Ed25519' },
    false,
    ['sign'],
  );

  const signedAt = Date.now();
  const sig = await crypto.subtle.sign({ name: 'Ed25519' }, privateKey, utf8Bytes(payload) as unknown as BufferSource);
  return { signature: base64UrlEncode(sig), signedAt };
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

function sessionKeyMatches(configured: string, incoming: string): boolean {
  if (incoming === configured) return true;
  // OpenClaw resolves "main" to canonical session key like "agent:main:main".
  if (configured === 'main' && incoming === 'agent:main:main') return true;
  return false;
}

export class ObsidianWSClient {
  private ws: WebSocket | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  private workingTimer: ReturnType<typeof setTimeout> | null = null;
  private intentionalClose = false;
  private sessionKey: string;
  private url = '';
  private token = '';
  private requestId = 0;
  private pendingRequests = new Map<string, PendingRequest>();
  private working = false;

  /** The last in-flight chat run id. In OpenClaw WebChat this maps to chat.send idempotencyKey. */
  private activeRunId: string | null = null;

  state: WSClientState = 'disconnected';

  onMessage: ((msg: InboundWSPayload) => void) | null = null;
  onStateChange: ((state: WSClientState) => void) | null = null;
  onWorkingChange: WorkingStateListener | null = null;

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
    this.activeRunId = null;
    this._setWorking(false);
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

    const runId = `obsidian-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;

    // Show “working” ONLY after the gateway acknowledges the request.
    await this._sendRequest('chat.send', {
      sessionKey: this.sessionKey,
      message,
      idempotencyKey: runId,
      // deliver defaults to true in gateway; keep default
    });

    this.activeRunId = runId;
    this._setWorking(true);
    this._armWorkingSafetyTimeout();
  }

  /** Abort the active run for this session (and our last run id if present). */
  async abortActiveRun(): Promise<boolean> {
    if (this.state !== 'connected') {
      return false;
    }

    const runId = this.activeRunId;

    try {
      await this._sendRequest('chat.abort', runId ? { sessionKey: this.sessionKey, runId } : { sessionKey: this.sessionKey });
      return true;
    } catch (err) {
      console.error('[oclaw-ws] chat.abort failed', err);
      return false;
    } finally {
      // Always restore UI state immediately; the gateway may still emit an aborted event later.
      this.activeRunId = null;
      this._setWorking(false);
    }
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

    let connectNonce: string | null = null;
    let connectStarted = false;

    const tryConnect = async () => {
      if (connectStarted) return;
      if (!connectNonce) return;
      connectStarted = true;

      try {
        const identity = await loadOrCreateDeviceIdentity();
        const signedAtMs = Date.now();
        const payload = buildDeviceAuthPayload({
          deviceId: identity.id,
          clientId: 'gateway-client',
          clientMode: 'backend',
          role: 'operator',
          scopes: ['operator.read', 'operator.write'],
          signedAtMs,
          token: this.token,
          nonce: connectNonce,
        });
        const sig = await signDevicePayload(identity, payload);

        await this._sendRequest('connect', {
          minProtocol: 3,
          maxProtocol: 3,
          client: {
            id: 'gateway-client',
            mode: 'backend',
            version: '0.1.10',
            platform: 'electron',
          },
          role: 'operator',
          scopes: ['operator.read', 'operator.write'],
          device: {
            id: identity.id,
            publicKey: identity.publicKey,
            signature: sig.signature,
            signedAt: signedAtMs,
            nonce: connectNonce,
          },
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

    ws.onopen = () => {
      this._setState('handshaking');
      // The gateway will send connect.challenge; connect is sent once we have a nonce.
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
        if (frame.event === 'connect.challenge') {
          connectNonce = frame.payload?.nonce || null;
          // Attempt handshake once we have a nonce.
          void tryConnect();
          return;
        }

        if (frame.event === 'chat') {
          const payload = frame.payload;
          const incomingSessionKey = String(payload?.sessionKey || '');
          if (!incomingSessionKey || !sessionKeyMatches(this.sessionKey, incomingSessionKey)) {
            return;
          }

          // Avoid double-render: gateway emits delta + final + aborted. Render only final/aborted.
          if (payload?.state && payload.state !== 'final' && payload.state !== 'aborted') {
            return;
          }

          // We only append assistant output to UI.
          const msg = payload?.message;
          const role = msg?.role ?? 'assistant';

          // Both final and aborted resolve "working".
          this.activeRunId = null;
          this._setWorking(false);

          // Aborted may have no assistant message or may carry partial assistant content.
          if (payload?.state === 'aborted') {
            // If there's no usable assistant payload, just don't append anything.
            // (View layer may optionally add a system message on successful stop.)
            if (!msg) return;
          }

          if (role !== 'assistant') {
            return;
          }

          const text = extractTextFromGatewayMessage(msg);
          if (!text) return;

          // Optional: hide heartbeat acks (noise in UI)
          if (text.trim() === 'HEARTBEAT_OK') {
            return;
          }

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
      this._setWorking(false);
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
    this._disarmWorkingSafetyTimeout();
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

  private _setWorking(working: boolean): void {
    if (this.working === working) return;
    this.working = working;
    this.onWorkingChange?.(working);

    if (!working) {
      this._disarmWorkingSafetyTimeout();
    }
  }

  private _armWorkingSafetyTimeout(): void {
    this._disarmWorkingSafetyTimeout();
    this.workingTimer = setTimeout(() => {
      // If the gateway never emits an assistant final response, don’t leave UI stuck.
      this._setWorking(false);
    }, WORKING_MAX_MS);
  }

  private _disarmWorkingSafetyTimeout(): void {
    if (this.workingTimer) {
      clearTimeout(this.workingTimer);
      this.workingTimer = null;
    }
  }
}
