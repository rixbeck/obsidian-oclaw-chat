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

function isLocalHost(host: string): boolean {
  const h = host.toLowerCase();
  return h === 'localhost' || h === '127.0.0.1' || h === '::1';
}

function safeParseWsUrl(url: string):
  | { ok: true; scheme: 'ws' | 'wss'; host: string }
  | { ok: false; error: string } {
  try {
    const u = new URL(url);
    if (u.protocol !== 'ws:' && u.protocol !== 'wss:') {
      return { ok: false, error: `Gateway URL must be ws:// or wss:// (got ${u.protocol})` };
    }
    const scheme = u.protocol === 'ws:' ? 'ws' : 'wss';
    return { ok: true, scheme, host: u.hostname };
  } catch {
    return { ok: false, error: 'Invalid gateway URL' };
  }
}

/** Interval for sending heartbeat pings (check connection liveness) */
const HEARTBEAT_INTERVAL_MS = 30_000;

/** Safety valve: hide working spinner if no assistant reply arrives in time */
const WORKING_MAX_MS = 120_000;

/** Max inbound frame size to parse (DoS guard) */
const MAX_INBOUND_FRAME_BYTES = 512 * 1024;

/** Max in-flight requests before fast-failing (DoS/robustness guard) */
const MAX_PENDING_REQUESTS = 200;

/** Reconnect backoff */
const RECONNECT_BASE_MS = 3_000;
const RECONNECT_MAX_MS = 60_000;

/** Handshake deadline waiting for connect.challenge */
const HANDSHAKE_TIMEOUT_MS = 15_000;

export type WSClientState = 'disconnected' | 'connecting' | 'handshaking' | 'connected';

export type WorkingStateListener = (working: boolean) => void;

interface PendingRequest {
  resolve: (payload: any) => void;
  reject: (error: any) => void;
  timeout: ReturnType<typeof setTimeout> | null;
}

export type DeviceIdentity = {
  id: string;
  publicKey: string; // base64
  privateKeyJwk: JsonWebKey;
};

export interface DeviceIdentityStore {
  get(): Promise<DeviceIdentity | null>;
  set(identity: DeviceIdentity): Promise<void>;
  clear(): Promise<void>;
}

const DEVICE_STORAGE_KEY = 'openclawChat.deviceIdentity.v1'; // legacy localStorage key (migration only)

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

async function loadOrCreateDeviceIdentity(store?: DeviceIdentityStore): Promise<DeviceIdentity> {
  // 1) Prefer plugin-scoped storage (injected by main plugin).
  if (store) {
    try {
      const existing = await store.get();
      if (existing?.id && existing?.publicKey && existing?.privateKeyJwk) return existing;
    } catch {
      // ignore and continue (we can always re-generate)
    }
  }

  // 2) One-time migration: legacy localStorage identity.
  // NOTE: this remains a risk boundary; we only read+delete for migration.
  const legacy = localStorage.getItem(DEVICE_STORAGE_KEY);
  if (legacy) {
    try {
      const parsed = JSON.parse(legacy) as DeviceIdentity;
      if (parsed?.id && parsed?.publicKey && parsed?.privateKeyJwk) {
        if (store) {
          await store.set(parsed);
          localStorage.removeItem(DEVICE_STORAGE_KEY);
        }
        return parsed;
      }
    } catch {
      // Corrupt/partial data → delete and re-create.
      localStorage.removeItem(DEVICE_STORAGE_KEY);
    }
  }

  // 3) Create a new identity.
  const keyPair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const pubRaw = await crypto.subtle.exportKey('raw', keyPair.publicKey);
  const privJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);

  // IMPORTANT: device.id must be a stable fingerprint for the public key.
  // The gateway enforces deviceId ↔ publicKey binding; random ids can cause "device identity mismatch".
  const deviceId = await sha256Hex(pubRaw);

  const identity: DeviceIdentity = {
    id: deviceId,
    publicKey: base64UrlEncode(pubRaw),
    privateKeyJwk: privJwk,
  };

  if (store) {
    await store.set(identity);
  } else {
    // Fallback (should not happen in real plugin runtime) — keep legacy behavior.
    localStorage.setItem(DEVICE_STORAGE_KEY, JSON.stringify(identity));
  }

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

async function signDevicePayload(identity: DeviceIdentity, payload: string): Promise<{ signature: string }> {
  const privateKey = await crypto.subtle.importKey(
    'jwk',
    identity.privateKeyJwk,
    { name: 'Ed25519' },
    false,
    ['sign'],
  );

  const sig = await crypto.subtle.sign({ name: 'Ed25519' }, privateKey, utf8Bytes(payload) as unknown as BufferSource);
  return { signature: base64UrlEncode(sig) };
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

  /** Prevents abort spamming: while an abort request is in-flight, reuse the same promise. */
  private abortInFlight: Promise<boolean> | null = null;

  state: WSClientState = 'disconnected';

  onMessage: ((msg: InboundWSPayload) => void) | null = null;
  onStateChange: ((state: WSClientState) => void) | null = null;
  onWorkingChange: WorkingStateListener | null = null;

  private identityStore: DeviceIdentityStore | undefined;
  private allowInsecureWs = false;

  private reconnectAttempt = 0;

  constructor(sessionKey: string, opts?: { identityStore?: DeviceIdentityStore; allowInsecureWs?: boolean }) {
    this.sessionKey = sessionKey;
    this.identityStore = opts?.identityStore;
    this.allowInsecureWs = Boolean(opts?.allowInsecureWs);
  }

  connect(url: string, token: string, opts?: { allowInsecureWs?: boolean }): void {
    this.url = url;
    this.token = token;
    this.allowInsecureWs = Boolean(opts?.allowInsecureWs ?? this.allowInsecureWs);
    this.intentionalClose = false;

    // Security: block non-local ws:// unless explicitly allowed.
    const parsed = safeParseWsUrl(url);
    if (!parsed.ok) {
      this.onMessage?.({ type: 'error', payload: { message: parsed.error } });
      return;
    }
    if (parsed.scheme === 'ws' && !isLocalHost(parsed.host) && !this.allowInsecureWs) {
      this.onMessage?.({
        type: 'error',
        payload: { message: 'Refusing insecure ws:// to non-local gateway. Use wss:// or enable the unsafe override in settings.' },
      });
      return;
    }

    this._connect();
  }

  disconnect(): void {
    this.intentionalClose = true;
    this._stopTimers();
    this.activeRunId = null;
    this.abortInFlight = null;
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
    const ack = await this._sendRequest('chat.send', {
      sessionKey: this.sessionKey,
      message,
      idempotencyKey: runId,
      // deliver defaults to true in gateway; keep default
    });

    // If the gateway returns a canonical run identifier, prefer it.
    const canonicalRunId = String(ack?.runId || ack?.idempotencyKey || '');
    this.activeRunId = canonicalRunId || runId;
    this._setWorking(true);
    this._armWorkingSafetyTimeout();
  }

  /** Abort the active run for this session (and our last run id if present). */
  async abortActiveRun(): Promise<boolean> {
    if (this.state !== 'connected') {
      return false;
    }

    // Prevent request storms: while one abort is in flight, reuse it.
    if (this.abortInFlight) {
      return this.abortInFlight;
    }

    const runId = this.activeRunId;
    if (!runId) {
      return false;
    }

    this.abortInFlight = (async () => {
      try {
        await this._sendRequest('chat.abort', { sessionKey: this.sessionKey, runId });
        return true;
      } catch (err) {
        console.error('[oclaw-ws] chat.abort failed', err);
        return false;
      } finally {
        // Always restore UI state immediately; the gateway may still emit an aborted event later.
        this.activeRunId = null;
        this._setWorking(false);
        this.abortInFlight = null;
      }
    })();

    return this.abortInFlight;
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
        const identity = await loadOrCreateDeviceIdentity(this.identityStore);
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

        const ack = await this._sendRequest('connect', {
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
         this.reconnectAttempt = 0;
         if (handshakeTimer) {
           clearTimeout(handshakeTimer);
           handshakeTimer = null;
         }
         this._startHeartbeat();
      } catch (err) {
        console.error('[oclaw-ws] Connect handshake failed', err);
        ws.close();
      }
    };

    let handshakeTimer: ReturnType<typeof setTimeout> | null = null;

    ws.onopen = () => {
      this._setState('handshaking');
      // The gateway will send connect.challenge; connect is sent once we have a nonce.
      if (handshakeTimer) clearTimeout(handshakeTimer);
      handshakeTimer = setTimeout(() => {
        // If we never got the challenge nonce, force reconnect.
        if (this.state === 'handshaking' && !this.intentionalClose) {
          console.warn('[oclaw-ws] Handshake timed out waiting for connect.challenge');
          ws.close();
        }
      }, HANDSHAKE_TIMEOUT_MS);
    };

    ws.onmessage = (event: MessageEvent) => {
      // DoS guard: refuse huge frames.
      if (typeof event.data === 'string' && event.data.length > MAX_INBOUND_FRAME_BYTES) {
        console.error('[oclaw-ws] Inbound frame too large; closing connection');
        ws.close();
        return;
      }

      let frame: any;
      try {
        frame = JSON.parse(event.data as string);
      } catch {
        console.error('[oclaw-ws] Failed to parse incoming message');
        return;
      }

      // Responses
      if (frame.type === 'res') {
        this._handleResponseFrame(frame);
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
          this._handleChatEventFrame(frame);
        }
        return;
      }

      // Avoid logging full frames (may include message content or other sensitive payloads).
      console.debug('[oclaw-ws] Unhandled frame', { type: frame?.type, event: frame?.event, id: frame?.id });
    };

    ws.onclose = () => {
      this._stopTimers();
      this.activeRunId = null;
      this.abortInFlight = null;
      this._setWorking(false);
      this._setState('disconnected');

      for (const pending of this.pendingRequests.values()) {
        if (pending.timeout) clearTimeout(pending.timeout);
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

  private _handleResponseFrame(frame: any): void {
    const pending = this.pendingRequests.get(frame.id);
    if (!pending) return;

    this.pendingRequests.delete(frame.id);
    if (pending.timeout) clearTimeout(pending.timeout);

    if (frame.ok) pending.resolve(frame.payload);
    else pending.reject(new Error(frame.error?.message || 'Request failed'));
  }

  private _handleChatEventFrame(frame: any): void {
    const payload = frame.payload;
    const incomingSessionKey = String(payload?.sessionKey || '');
    if (!incomingSessionKey || !sessionKeyMatches(this.sessionKey, incomingSessionKey)) {
      return;
    }

    // Best-effort run correlation (if gateway includes a run id). This avoids clearing our UI
    // based on a different client's run in the same session.
    const incomingRunId = String(payload?.runId || payload?.idempotencyKey || payload?.meta?.runId || '');
    if (this.activeRunId && incomingRunId && incomingRunId !== this.activeRunId) {
      return;
    }

    // Avoid double-render: gateway emits delta + final + aborted. Render only explicit final/aborted.
    // If state is missing, treat as non-terminal (do not clear UI / do not render).
    if (!payload?.state) {
      return;
    }
    if (payload.state !== 'final' && payload.state !== 'aborted') {
      return;
    }

    // We only append assistant output to UI.
    const msg = payload?.message;
    const role = msg?.role ?? 'assistant';

    // Aborted ends the run regardless of role/message.
    if (payload.state === 'aborted') {
      this.activeRunId = null;
      this._setWorking(false);
      // Aborted may have no assistant message; if none, stop here.
      if (!msg) return;
      // If there is a message, only append assistant output.
      if (role !== 'assistant') return;
    }

    // Final should only complete the run when the assistant completes.
    if (payload.state === 'final') {
      if (role !== 'assistant') return;
      this.activeRunId = null;
      this._setWorking(false);
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

  private _sendRequest(method: string, params: any): Promise<any> {
    return new Promise((resolve, reject) => {
      if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
        reject(new Error('WebSocket not connected'));
        return;
      }

      if (this.pendingRequests.size >= MAX_PENDING_REQUESTS) {
        reject(new Error(`Too many in-flight requests (${this.pendingRequests.size})`));
        return;
      }

      const id = `req-${++this.requestId}`;

      const pending: PendingRequest = { resolve, reject, timeout: null };
      this.pendingRequests.set(id, pending);

      const payload = JSON.stringify({
        type: 'req',
        method,
        id,
        params,
      });

      try {
        this.ws.send(payload);
      } catch (err) {
        this.pendingRequests.delete(id);
        reject(err);
        return;
      }

      pending.timeout = setTimeout(() => {
        if (this.pendingRequests.has(id)) {
          this.pendingRequests.delete(id);
          reject(new Error(`Request timeout: ${method}`));
        }
      }, 30_000);
    });
  }

  private _scheduleReconnect(): void {
    if (this.reconnectTimer !== null) return;

    const attempt = ++this.reconnectAttempt;
    const exp = Math.min(RECONNECT_MAX_MS, RECONNECT_BASE_MS * Math.pow(2, attempt - 1));
    // Jitter: 0.5x..1.5x
    const jitter = 0.5 + Math.random();
    const delay = Math.floor(exp * jitter);

    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      if (!this.intentionalClose) {
        console.log(`[oclaw-ws] Reconnecting to ${this.url}… (attempt ${attempt}, ${delay}ms)`);
        this._connect();
      }
    }, delay);
  }

  private lastBufferedWarnAtMs = 0;

  private _startHeartbeat(): void {
    this._stopHeartbeat();
    this.heartbeatTimer = setInterval(() => {
      if (this.ws?.readyState !== WebSocket.OPEN) return;
      if (this.ws.bufferedAmount > 0) {
        const now = Date.now();
        // Throttle to avoid log spam in long-running sessions.
        if (now - this.lastBufferedWarnAtMs > 5 * 60_000) {
          this.lastBufferedWarnAtMs = now;
          console.warn('[oclaw-ws] Send buffer not empty — connection may be stalled');
        }
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
