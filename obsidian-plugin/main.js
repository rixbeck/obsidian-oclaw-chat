"use strict";
var __defProp = Object.defineProperty;
var __defProps = Object.defineProperties;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropDescs = Object.getOwnPropertyDescriptors;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getOwnPropSymbols = Object.getOwnPropertySymbols;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __propIsEnum = Object.prototype.propertyIsEnumerable;
var __defNormalProp = (obj, key, value) => key in obj ? __defProp(obj, key, { enumerable: true, configurable: true, writable: true, value }) : obj[key] = value;
var __spreadValues = (a, b) => {
  for (var prop in b || (b = {}))
    if (__hasOwnProp.call(b, prop))
      __defNormalProp(a, prop, b[prop]);
  if (__getOwnPropSymbols)
    for (var prop of __getOwnPropSymbols(b)) {
      if (__propIsEnum.call(b, prop))
        __defNormalProp(a, prop, b[prop]);
    }
  return a;
};
var __spreadProps = (a, b) => __defProps(a, __getOwnPropDescs(b));
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var __async = (__this, __arguments, generator) => {
  return new Promise((resolve, reject) => {
    var fulfilled = (value) => {
      try {
        step(generator.next(value));
      } catch (e) {
        reject(e);
      }
    };
    var rejected = (value) => {
      try {
        step(generator.throw(value));
      } catch (e) {
        reject(e);
      }
    };
    var step = (x) => x.done ? resolve(x.value) : Promise.resolve(x.value).then(fulfilled, rejected);
    step((generator = generator.apply(__this, __arguments)).next());
  });
};

// src/main.ts
var main_exports = {};
__export(main_exports, {
  default: () => OpenClawPlugin
});
module.exports = __toCommonJS(main_exports);
var import_obsidian3 = require("obsidian");

// src/settings.ts
var import_obsidian = require("obsidian");
var OpenClawSettingTab = class extends import_obsidian.PluginSettingTab {
  constructor(app, plugin) {
    super(app, plugin);
    this.plugin = plugin;
  }
  display() {
    const { containerEl } = this;
    containerEl.empty();
    containerEl.createEl("h2", { text: "OpenClaw Chat \u2013 Settings" });
    new import_obsidian.Setting(containerEl).setName("Gateway URL").setDesc("WebSocket URL of the OpenClaw Gateway (e.g. ws://hostname:18789).").addText(
      (text) => text.setPlaceholder("ws://localhost:18789").setValue(this.plugin.settings.gatewayUrl).onChange((value) => __async(this, null, function* () {
        this.plugin.settings.gatewayUrl = value.trim();
        yield this.plugin.saveSettings();
      }))
    );
    new import_obsidian.Setting(containerEl).setName("Auth token").setDesc("Must match the authToken in your openclaw.json channel config. Never shared.").addText((text) => {
      text.setPlaceholder("Enter token\u2026").setValue(this.plugin.settings.authToken).onChange((value) => __async(this, null, function* () {
        this.plugin.settings.authToken = value;
        yield this.plugin.saveSettings();
      }));
      text.inputEl.type = "password";
      text.inputEl.autocomplete = "off";
    });
    new import_obsidian.Setting(containerEl).setName("Session Key").setDesc('OpenClaw session to subscribe to (usually "main").').addText(
      (text) => text.setPlaceholder("main").setValue(this.plugin.settings.sessionKey).onChange((value) => __async(this, null, function* () {
        this.plugin.settings.sessionKey = value.trim() || "main";
        yield this.plugin.saveSettings();
      }))
    );
    new import_obsidian.Setting(containerEl).setName("Account ID").setDesc('OpenClaw account ID (usually "main").').addText(
      (text) => text.setPlaceholder("main").setValue(this.plugin.settings.accountId).onChange((value) => __async(this, null, function* () {
        this.plugin.settings.accountId = value.trim() || "main";
        yield this.plugin.saveSettings();
      }))
    );
    new import_obsidian.Setting(containerEl).setName("Include active note by default").setDesc('Pre-check "Include active note" in the chat panel when it opens.').addToggle(
      (toggle) => toggle.setValue(this.plugin.settings.includeActiveNote).onChange((value) => __async(this, null, function* () {
        this.plugin.settings.includeActiveNote = value;
        yield this.plugin.saveSettings();
      }))
    );
    new import_obsidian.Setting(containerEl).setName("Render assistant as Markdown (unsafe)").setDesc(
      "OFF recommended. If enabled, assistant output is rendered as Obsidian Markdown which may trigger embeds and other plugins' post-processors."
    ).addToggle(
      (toggle) => toggle.setValue(this.plugin.settings.renderAssistantMarkdown).onChange((value) => __async(this, null, function* () {
        this.plugin.settings.renderAssistantMarkdown = value;
        yield this.plugin.saveSettings();
      }))
    );
    new import_obsidian.Setting(containerEl).setName("Allow insecure ws:// for non-local gateways (unsafe)").setDesc(
      "OFF recommended. If enabled, you can connect to non-local gateways over ws://. This exposes your token and message content to network attackers; prefer wss://."
    ).addToggle(
      (toggle) => toggle.setValue(this.plugin.settings.allowInsecureWs).onChange((value) => __async(this, null, function* () {
        this.plugin.settings.allowInsecureWs = value;
        yield this.plugin.saveSettings();
      }))
    );
    new import_obsidian.Setting(containerEl).setName("Reset device identity (re-pair)").setDesc('Clears the stored device identity used for operator.write pairing. Use this if you suspect compromise or see "device identity mismatch".').addButton(
      (btn) => btn.setButtonText("Reset").setWarning().onClick(() => __async(this, null, function* () {
        yield this.plugin.resetDeviceIdentity();
      }))
    );
    containerEl.createEl("p", {
      text: "Reconnect: close and reopen the sidebar after changing the gateway URL or token.",
      cls: "setting-item-description"
    });
  }
};

// src/websocket.ts
function isLocalHost(host) {
  const h = host.toLowerCase();
  return h === "localhost" || h === "127.0.0.1" || h === "::1";
}
function safeParseWsUrl(url) {
  try {
    const u = new URL(url);
    if (u.protocol !== "ws:" && u.protocol !== "wss:") {
      return { ok: false, error: `Gateway URL must be ws:// or wss:// (got ${u.protocol})` };
    }
    const scheme = u.protocol === "ws:" ? "ws" : "wss";
    return { ok: true, scheme, host: u.hostname };
  } catch (e) {
    return { ok: false, error: "Invalid gateway URL" };
  }
}
var HEARTBEAT_INTERVAL_MS = 3e4;
var WORKING_MAX_MS = 12e4;
var MAX_INBOUND_FRAME_BYTES = 512 * 1024;
var MAX_PENDING_REQUESTS = 200;
var RECONNECT_BASE_MS = 3e3;
var RECONNECT_MAX_MS = 6e4;
var HANDSHAKE_TIMEOUT_MS = 15e3;
var DEVICE_STORAGE_KEY = "openclawChat.deviceIdentity.v1";
function base64UrlEncode(bytes) {
  const u8 = new Uint8Array(bytes);
  let s = "";
  for (let i = 0; i < u8.length; i++)
    s += String.fromCharCode(u8[i]);
  const b64 = btoa(s);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function hexEncode(bytes) {
  const u8 = new Uint8Array(bytes);
  return Array.from(u8).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function utf8Bytes(text) {
  return new TextEncoder().encode(text);
}
function sha256Hex(bytes) {
  return __async(this, null, function* () {
    const digest = yield crypto.subtle.digest("SHA-256", bytes);
    return hexEncode(digest);
  });
}
function loadOrCreateDeviceIdentity(store) {
  return __async(this, null, function* () {
    if (store) {
      try {
        const existing = yield store.get();
        if ((existing == null ? void 0 : existing.id) && (existing == null ? void 0 : existing.publicKey) && (existing == null ? void 0 : existing.privateKeyJwk))
          return existing;
      } catch (e) {
      }
    }
    const legacy = localStorage.getItem(DEVICE_STORAGE_KEY);
    if (legacy) {
      try {
        const parsed = JSON.parse(legacy);
        if ((parsed == null ? void 0 : parsed.id) && (parsed == null ? void 0 : parsed.publicKey) && (parsed == null ? void 0 : parsed.privateKeyJwk)) {
          if (store) {
            yield store.set(parsed);
            localStorage.removeItem(DEVICE_STORAGE_KEY);
          }
          return parsed;
        }
      } catch (e) {
        localStorage.removeItem(DEVICE_STORAGE_KEY);
      }
    }
    const keyPair = yield crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    const pubRaw = yield crypto.subtle.exportKey("raw", keyPair.publicKey);
    const privJwk = yield crypto.subtle.exportKey("jwk", keyPair.privateKey);
    const deviceId = yield sha256Hex(pubRaw);
    const identity = {
      id: deviceId,
      publicKey: base64UrlEncode(pubRaw),
      privateKeyJwk: privJwk
    };
    if (store) {
      yield store.set(identity);
    } else {
      localStorage.setItem(DEVICE_STORAGE_KEY, JSON.stringify(identity));
    }
    return identity;
  });
}
function buildDeviceAuthPayload(params) {
  const version = params.nonce ? "v2" : "v1";
  const scopes = params.scopes.join(",");
  const base = [
    version,
    params.deviceId,
    params.clientId,
    params.clientMode,
    params.role,
    scopes,
    String(params.signedAtMs),
    params.token || ""
  ];
  if (version === "v2")
    base.push(params.nonce || "");
  return base.join("|");
}
function signDevicePayload(identity, payload) {
  return __async(this, null, function* () {
    const privateKey = yield crypto.subtle.importKey(
      "jwk",
      identity.privateKeyJwk,
      { name: "Ed25519" },
      false,
      ["sign"]
    );
    const sig = yield crypto.subtle.sign({ name: "Ed25519" }, privateKey, utf8Bytes(payload));
    return { signature: base64UrlEncode(sig) };
  });
}
function extractTextFromGatewayMessage(msg) {
  var _a, _b;
  if (!msg)
    return "";
  const content = (_b = (_a = msg.content) != null ? _a : msg.message) != null ? _b : msg;
  if (typeof content === "string")
    return content;
  if (Array.isArray(content)) {
    const parts = content.filter((c) => c && typeof c === "object" && c.type === "text" && typeof c.text === "string").map((c) => c.text);
    return parts.join("\n");
  }
  try {
    return JSON.stringify(content);
  } catch (e) {
    return String(content);
  }
}
function sessionKeyMatches(configured, incoming) {
  if (incoming === configured)
    return true;
  if (configured === "main" && incoming === "agent:main:main")
    return true;
  return false;
}
var ObsidianWSClient = class {
  constructor(sessionKey, opts) {
    this.ws = null;
    this.reconnectTimer = null;
    this.heartbeatTimer = null;
    this.workingTimer = null;
    this.intentionalClose = false;
    this.url = "";
    this.token = "";
    this.requestId = 0;
    this.pendingRequests = /* @__PURE__ */ new Map();
    this.working = false;
    /** The last in-flight chat run id. In OpenClaw WebChat this maps to chat.send idempotencyKey. */
    this.activeRunId = null;
    /** Prevents abort spamming: while an abort request is in-flight, reuse the same promise. */
    this.abortInFlight = null;
    this.state = "disconnected";
    this.onMessage = null;
    this.onStateChange = null;
    this.onWorkingChange = null;
    this.allowInsecureWs = false;
    this.reconnectAttempt = 0;
    this.lastBufferedWarnAtMs = 0;
    this.sessionKey = sessionKey;
    this.identityStore = opts == null ? void 0 : opts.identityStore;
    this.allowInsecureWs = Boolean(opts == null ? void 0 : opts.allowInsecureWs);
  }
  connect(url, token, opts) {
    var _a, _b, _c;
    this.url = url;
    this.token = token;
    this.allowInsecureWs = Boolean((_a = opts == null ? void 0 : opts.allowInsecureWs) != null ? _a : this.allowInsecureWs);
    this.intentionalClose = false;
    const parsed = safeParseWsUrl(url);
    if (!parsed.ok) {
      (_b = this.onMessage) == null ? void 0 : _b.call(this, { type: "error", payload: { message: parsed.error } });
      return;
    }
    if (parsed.scheme === "ws" && !isLocalHost(parsed.host) && !this.allowInsecureWs) {
      (_c = this.onMessage) == null ? void 0 : _c.call(this, {
        type: "error",
        payload: { message: "Refusing insecure ws:// to non-local gateway. Use wss:// or enable the unsafe override in settings." }
      });
      return;
    }
    this._connect();
  }
  disconnect() {
    this.intentionalClose = true;
    this._stopTimers();
    this.activeRunId = null;
    this.abortInFlight = null;
    this._setWorking(false);
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    this._setState("disconnected");
  }
  sendMessage(message) {
    return __async(this, null, function* () {
      if (this.state !== "connected") {
        throw new Error("Not connected \u2014 call connect() first");
      }
      const runId = `obsidian-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
      const ack = yield this._sendRequest("chat.send", {
        sessionKey: this.sessionKey,
        message,
        idempotencyKey: runId
        // deliver defaults to true in gateway; keep default
      });
      const canonicalRunId = String((ack == null ? void 0 : ack.runId) || (ack == null ? void 0 : ack.idempotencyKey) || "");
      this.activeRunId = canonicalRunId || runId;
      this._setWorking(true);
      this._armWorkingSafetyTimeout();
    });
  }
  /** Abort the active run for this session (and our last run id if present). */
  abortActiveRun() {
    return __async(this, null, function* () {
      if (this.state !== "connected") {
        return false;
      }
      if (this.abortInFlight) {
        return this.abortInFlight;
      }
      const runId = this.activeRunId;
      if (!runId) {
        return false;
      }
      this.abortInFlight = (() => __async(this, null, function* () {
        try {
          yield this._sendRequest("chat.abort", { sessionKey: this.sessionKey, runId });
          return true;
        } catch (err) {
          console.error("[oclaw-ws] chat.abort failed", err);
          return false;
        } finally {
          this.activeRunId = null;
          this._setWorking(false);
          this.abortInFlight = null;
        }
      }))();
      return this.abortInFlight;
    });
  }
  _connect() {
    if (this.ws) {
      this.ws.onopen = null;
      this.ws.onclose = null;
      this.ws.onmessage = null;
      this.ws.onerror = null;
      this.ws.close();
      this.ws = null;
    }
    this._setState("connecting");
    const ws = new WebSocket(this.url);
    this.ws = ws;
    let connectNonce = null;
    let connectStarted = false;
    const tryConnect = () => __async(this, null, function* () {
      if (connectStarted)
        return;
      if (!connectNonce)
        return;
      connectStarted = true;
      try {
        const identity = yield loadOrCreateDeviceIdentity(this.identityStore);
        const signedAtMs = Date.now();
        const payload = buildDeviceAuthPayload({
          deviceId: identity.id,
          clientId: "gateway-client",
          clientMode: "backend",
          role: "operator",
          scopes: ["operator.read", "operator.write"],
          signedAtMs,
          token: this.token,
          nonce: connectNonce
        });
        const sig = yield signDevicePayload(identity, payload);
        const ack = yield this._sendRequest("connect", {
          minProtocol: 3,
          maxProtocol: 3,
          client: {
            id: "gateway-client",
            mode: "backend",
            version: "0.1.10",
            platform: "electron"
          },
          role: "operator",
          scopes: ["operator.read", "operator.write"],
          device: {
            id: identity.id,
            publicKey: identity.publicKey,
            signature: sig.signature,
            signedAt: signedAtMs,
            nonce: connectNonce
          },
          auth: {
            token: this.token
          }
        });
        this._setState("connected");
        this.reconnectAttempt = 0;
        if (handshakeTimer) {
          clearTimeout(handshakeTimer);
          handshakeTimer = null;
        }
        this._startHeartbeat();
      } catch (err) {
        console.error("[oclaw-ws] Connect handshake failed", err);
        ws.close();
      }
    });
    let handshakeTimer = null;
    ws.onopen = () => {
      this._setState("handshaking");
      if (handshakeTimer)
        clearTimeout(handshakeTimer);
      handshakeTimer = setTimeout(() => {
        if (this.state === "handshaking" && !this.intentionalClose) {
          console.warn("[oclaw-ws] Handshake timed out waiting for connect.challenge");
          ws.close();
        }
      }, HANDSHAKE_TIMEOUT_MS);
    };
    ws.onmessage = (event) => {
      var _a;
      if (typeof event.data === "string" && event.data.length > MAX_INBOUND_FRAME_BYTES) {
        console.error("[oclaw-ws] Inbound frame too large; closing connection");
        ws.close();
        return;
      }
      let frame;
      try {
        frame = JSON.parse(event.data);
      } catch (e) {
        console.error("[oclaw-ws] Failed to parse incoming message");
        return;
      }
      if (frame.type === "res") {
        this._handleResponseFrame(frame);
        return;
      }
      if (frame.type === "event") {
        if (frame.event === "connect.challenge") {
          connectNonce = ((_a = frame.payload) == null ? void 0 : _a.nonce) || null;
          void tryConnect();
          return;
        }
        if (frame.event === "chat") {
          this._handleChatEventFrame(frame);
        }
        return;
      }
      console.debug("[oclaw-ws] Unhandled frame", { type: frame == null ? void 0 : frame.type, event: frame == null ? void 0 : frame.event, id: frame == null ? void 0 : frame.id });
    };
    ws.onclose = () => {
      this._stopTimers();
      this.activeRunId = null;
      this.abortInFlight = null;
      this._setWorking(false);
      this._setState("disconnected");
      for (const pending of this.pendingRequests.values()) {
        if (pending.timeout)
          clearTimeout(pending.timeout);
        pending.reject(new Error("Connection closed"));
      }
      this.pendingRequests.clear();
      if (!this.intentionalClose) {
        this._scheduleReconnect();
      }
    };
    ws.onerror = (ev) => {
      console.error("[oclaw-ws] WebSocket error", ev);
    };
  }
  _handleResponseFrame(frame) {
    var _a;
    const pending = this.pendingRequests.get(frame.id);
    if (!pending)
      return;
    this.pendingRequests.delete(frame.id);
    if (pending.timeout)
      clearTimeout(pending.timeout);
    if (frame.ok)
      pending.resolve(frame.payload);
    else
      pending.reject(new Error(((_a = frame.error) == null ? void 0 : _a.message) || "Request failed"));
  }
  _handleChatEventFrame(frame) {
    var _a, _b, _c;
    const payload = frame.payload;
    const incomingSessionKey = String((payload == null ? void 0 : payload.sessionKey) || "");
    if (!incomingSessionKey || !sessionKeyMatches(this.sessionKey, incomingSessionKey)) {
      return;
    }
    const incomingRunId = String((payload == null ? void 0 : payload.runId) || (payload == null ? void 0 : payload.idempotencyKey) || ((_a = payload == null ? void 0 : payload.meta) == null ? void 0 : _a.runId) || "");
    if (this.activeRunId && incomingRunId && incomingRunId !== this.activeRunId) {
      return;
    }
    if (!(payload == null ? void 0 : payload.state)) {
      return;
    }
    if (payload.state !== "final" && payload.state !== "aborted") {
      return;
    }
    const msg = payload == null ? void 0 : payload.message;
    const role = (_b = msg == null ? void 0 : msg.role) != null ? _b : "assistant";
    if (payload.state === "aborted") {
      this.activeRunId = null;
      this._setWorking(false);
      if (!msg)
        return;
      if (role !== "assistant")
        return;
    }
    if (payload.state === "final") {
      if (role !== "assistant")
        return;
      this.activeRunId = null;
      this._setWorking(false);
    }
    const text = extractTextFromGatewayMessage(msg);
    if (!text)
      return;
    if (text.trim() === "HEARTBEAT_OK") {
      return;
    }
    (_c = this.onMessage) == null ? void 0 : _c.call(this, {
      type: "message",
      payload: {
        content: text,
        role: "assistant",
        timestamp: Date.now()
      }
    });
  }
  _sendRequest(method, params) {
    return new Promise((resolve, reject) => {
      if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
        reject(new Error("WebSocket not connected"));
        return;
      }
      if (this.pendingRequests.size >= MAX_PENDING_REQUESTS) {
        reject(new Error(`Too many in-flight requests (${this.pendingRequests.size})`));
        return;
      }
      const id = `req-${++this.requestId}`;
      const pending = { resolve, reject, timeout: null };
      this.pendingRequests.set(id, pending);
      const payload = JSON.stringify({
        type: "req",
        method,
        id,
        params
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
      }, 3e4);
    });
  }
  _scheduleReconnect() {
    if (this.reconnectTimer !== null)
      return;
    const attempt = ++this.reconnectAttempt;
    const exp = Math.min(RECONNECT_MAX_MS, RECONNECT_BASE_MS * Math.pow(2, attempt - 1));
    const jitter = 0.5 + Math.random();
    const delay = Math.floor(exp * jitter);
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      if (!this.intentionalClose) {
        console.log(`[oclaw-ws] Reconnecting to ${this.url}\u2026 (attempt ${attempt}, ${delay}ms)`);
        this._connect();
      }
    }, delay);
  }
  _startHeartbeat() {
    this._stopHeartbeat();
    this.heartbeatTimer = setInterval(() => {
      var _a;
      if (((_a = this.ws) == null ? void 0 : _a.readyState) !== WebSocket.OPEN)
        return;
      if (this.ws.bufferedAmount > 0) {
        const now = Date.now();
        if (now - this.lastBufferedWarnAtMs > 5 * 6e4) {
          this.lastBufferedWarnAtMs = now;
          console.warn("[oclaw-ws] Send buffer not empty \u2014 connection may be stalled");
        }
      }
    }, HEARTBEAT_INTERVAL_MS);
  }
  _stopHeartbeat() {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }
  _stopTimers() {
    this._stopHeartbeat();
    this._disarmWorkingSafetyTimeout();
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
  }
  _setState(state) {
    var _a;
    if (this.state === state)
      return;
    this.state = state;
    (_a = this.onStateChange) == null ? void 0 : _a.call(this, state);
  }
  _setWorking(working) {
    var _a;
    if (this.working === working)
      return;
    this.working = working;
    (_a = this.onWorkingChange) == null ? void 0 : _a.call(this, working);
    if (!working) {
      this._disarmWorkingSafetyTimeout();
    }
  }
  _armWorkingSafetyTimeout() {
    this._disarmWorkingSafetyTimeout();
    this.workingTimer = setTimeout(() => {
      this._setWorking(false);
    }, WORKING_MAX_MS);
  }
  _disarmWorkingSafetyTimeout() {
    if (this.workingTimer) {
      clearTimeout(this.workingTimer);
      this.workingTimer = null;
    }
  }
};

// src/chat.ts
var ChatManager = class {
  constructor() {
    this.messages = [];
    /** Fired for a full re-render (clear/reload) */
    this.onUpdate = null;
    /** Fired when a single message is appended — use for O(1) append-only UI */
    this.onMessageAdded = null;
  }
  addMessage(msg) {
    var _a;
    this.messages.push(msg);
    (_a = this.onMessageAdded) == null ? void 0 : _a.call(this, msg);
  }
  getMessages() {
    return this.messages;
  }
  clear() {
    var _a;
    this.messages = [];
    (_a = this.onUpdate) == null ? void 0 : _a.call(this, []);
  }
  /** Create a user message object (without adding it) */
  static createUserMessage(content) {
    return {
      id: `msg-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      role: "user",
      content,
      timestamp: Date.now()
    };
  }
  /** Create an assistant message object (without adding it) */
  static createAssistantMessage(content) {
    return {
      id: `msg-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      role: "assistant",
      content,
      timestamp: Date.now()
    };
  }
  /** Create a system / status message (errors, reconnect notices, etc.) */
  static createSystemMessage(content, level = "info") {
    return {
      id: `sys-${Date.now()}`,
      role: "system",
      level,
      content,
      timestamp: Date.now()
    };
  }
};

// src/view.ts
var import_obsidian2 = require("obsidian");

// src/context.ts
function getActiveNoteContext(app) {
  return __async(this, null, function* () {
    const file = app.workspace.getActiveFile();
    if (!file)
      return null;
    try {
      const content = yield app.vault.read(file);
      return {
        title: file.basename,
        path: file.path,
        content
      };
    } catch (err) {
      console.error("[oclaw-context] Failed to read active note", err);
      return null;
    }
  });
}

// src/view.ts
var VIEW_TYPE_OPENCLAW_CHAT = "openclaw-chat";
var OpenClawChatView = class extends import_obsidian2.ItemView {
  constructor(leaf, plugin) {
    super(leaf);
    // State
    this.isConnected = false;
    this.isWorking = false;
    this.plugin = plugin;
    this.chatManager = plugin.chatManager;
  }
  getViewType() {
    return VIEW_TYPE_OPENCLAW_CHAT;
  }
  getDisplayText() {
    return "OpenClaw Chat";
  }
  getIcon() {
    return "message-square";
  }
  onOpen() {
    return __async(this, null, function* () {
      this._buildUI();
      this.chatManager.onUpdate = (msgs) => this._renderMessages(msgs);
      this.chatManager.onMessageAdded = (msg) => this._appendMessage(msg);
      this.plugin.wsClient.onStateChange = (state) => {
        this.isConnected = state === "connected";
        this.statusDot.toggleClass("connected", this.isConnected);
        this.statusDot.title = `Gateway: ${state}`;
        this._updateSendButton();
      };
      this.plugin.wsClient.onWorkingChange = (working) => {
        this.isWorking = working;
        this._updateSendButton();
      };
      this.isConnected = this.plugin.wsClient.state === "connected";
      this.statusDot.toggleClass("connected", this.isConnected);
      this._updateSendButton();
      this._renderMessages(this.chatManager.getMessages());
    });
  }
  onClose() {
    return __async(this, null, function* () {
      this.chatManager.onUpdate = null;
      this.chatManager.onMessageAdded = null;
      this.plugin.wsClient.onStateChange = null;
      this.plugin.wsClient.onWorkingChange = null;
    });
  }
  // ── UI construction ───────────────────────────────────────────────────────
  _buildUI() {
    const root = this.contentEl;
    root.empty();
    root.addClass("oclaw-chat-view");
    const header = root.createDiv({ cls: "oclaw-header" });
    header.createSpan({ cls: "oclaw-header-title", text: "OpenClaw Chat" });
    this.statusDot = header.createDiv({ cls: "oclaw-status-dot" });
    this.statusDot.title = "Gateway: disconnected";
    this.messagesEl = root.createDiv({ cls: "oclaw-messages" });
    const ctxRow = root.createDiv({ cls: "oclaw-context-row" });
    this.includeNoteCheckbox = ctxRow.createEl("input", { type: "checkbox" });
    this.includeNoteCheckbox.id = "oclaw-include-note";
    this.includeNoteCheckbox.checked = this.plugin.settings.includeActiveNote;
    const ctxLabel = ctxRow.createEl("label", { text: "Include active note" });
    ctxLabel.htmlFor = "oclaw-include-note";
    const inputRow = root.createDiv({ cls: "oclaw-input-row" });
    this.inputEl = inputRow.createEl("textarea", {
      cls: "oclaw-input",
      placeholder: "Ask anything\u2026"
    });
    this.inputEl.rows = 1;
    this.sendBtn = inputRow.createEl("button", { cls: "oclaw-send-btn", text: "Send" });
    this.sendBtn.addEventListener("click", () => this._handleSend());
    this.inputEl.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        this._handleSend();
      }
    });
    this.inputEl.addEventListener("input", () => {
      this.inputEl.style.height = "auto";
      this.inputEl.style.height = `${this.inputEl.scrollHeight}px`;
    });
  }
  // ── Message rendering ─────────────────────────────────────────────────────
  _renderMessages(messages) {
    this.messagesEl.empty();
    if (messages.length === 0) {
      this.messagesEl.createEl("p", {
        text: "Send a message to start chatting.",
        cls: "oclaw-message system oclaw-placeholder"
      });
      return;
    }
    for (const msg of messages) {
      this._appendMessage(msg);
    }
    this.messagesEl.scrollTop = this.messagesEl.scrollHeight;
  }
  /** Appends a single message without rebuilding the DOM (O(1)) */
  _appendMessage(msg) {
    var _a, _b, _c;
    (_a = this.messagesEl.querySelector(".oclaw-placeholder")) == null ? void 0 : _a.remove();
    const levelClass = msg.level ? ` ${msg.level}` : "";
    const el = this.messagesEl.createDiv({ cls: `oclaw-message ${msg.role}${levelClass}` });
    const body = el.createDiv({ cls: "oclaw-message-body" });
    if (msg.role === "assistant" && this.plugin.settings.renderAssistantMarkdown) {
      const sourcePath = (_c = (_b = this.app.workspace.getActiveFile()) == null ? void 0 : _b.path) != null ? _c : "";
      void import_obsidian2.MarkdownRenderer.renderMarkdown(msg.content, body, sourcePath, this.plugin);
    } else {
      body.setText(msg.content);
    }
    this.messagesEl.scrollTop = this.messagesEl.scrollHeight;
  }
  _updateSendButton() {
    const disabled = !this.isConnected;
    this.sendBtn.disabled = disabled;
    this.sendBtn.toggleClass("is-working", this.isWorking);
    this.sendBtn.setAttr("aria-busy", this.isWorking ? "true" : "false");
    this.sendBtn.setAttr("aria-label", this.isWorking ? "Stop" : "Send");
    if (this.isWorking) {
      this.sendBtn.empty();
      const wrap = this.sendBtn.createDiv({ cls: "oclaw-stop-wrap" });
      wrap.createDiv({ cls: "oclaw-spinner-ring", attr: { "aria-hidden": "true" } });
      wrap.createDiv({ cls: "oclaw-stop-icon", attr: { "aria-hidden": "true" } });
    } else {
      this.sendBtn.setText("Send");
    }
  }
  // ── Send handler ──────────────────────────────────────────────────────────
  _handleSend() {
    return __async(this, null, function* () {
      if (this.isWorking) {
        const ok = yield this.plugin.wsClient.abortActiveRun();
        if (!ok) {
          new import_obsidian2.Notice("OpenClaw Chat: failed to stop");
          this.chatManager.addMessage(ChatManager.createSystemMessage("\u26A0 Stop failed", "error"));
        } else {
          this.chatManager.addMessage(ChatManager.createSystemMessage("\u26D4 Stopped", "info"));
        }
        return;
      }
      const text = this.inputEl.value.trim();
      if (!text)
        return;
      let message = text;
      if (this.includeNoteCheckbox.checked) {
        const note = yield getActiveNoteContext(this.app);
        if (note) {
          message = `Context: [[${note.title}]]

${text}`;
        }
      }
      const userMsg = ChatManager.createUserMessage(text);
      this.chatManager.addMessage(userMsg);
      this.inputEl.value = "";
      this.inputEl.style.height = "auto";
      try {
        yield this.plugin.wsClient.sendMessage(message);
      } catch (err) {
        console.error("[oclaw] Send failed", err);
        new import_obsidian2.Notice(`OpenClaw Chat: send failed (${String(err)})`);
        this.chatManager.addMessage(
          ChatManager.createSystemMessage(`\u26A0 Send failed: ${err}`, "error")
        );
      }
    });
  }
};

// src/types.ts
var DEFAULT_SETTINGS = {
  gatewayUrl: "ws://localhost:18789",
  authToken: "",
  sessionKey: "main",
  accountId: "main",
  includeActiveNote: false,
  renderAssistantMarkdown: false,
  allowInsecureWs: false
};

// src/main.ts
var OpenClawPlugin = class extends import_obsidian3.Plugin {
  constructor() {
    super(...arguments);
    this._deviceIdentityKey = "_openclawDeviceIdentityV1";
  }
  onload() {
    return __async(this, null, function* () {
      yield this.loadSettings();
      this.wsClient = new ObsidianWSClient(this.settings.sessionKey, {
        identityStore: {
          get: () => __async(this, null, function* () {
            return yield this._loadDeviceIdentity();
          }),
          set: (identity) => __async(this, null, function* () {
            return yield this._saveDeviceIdentity(identity);
          }),
          clear: () => __async(this, null, function* () {
            return yield this._clearDeviceIdentity();
          })
        }
      });
      this.chatManager = new ChatManager();
      this.wsClient.onMessage = (msg) => {
        var _a;
        if (msg.type === "message") {
          this.chatManager.addMessage(ChatManager.createAssistantMessage(msg.payload.content));
        } else if (msg.type === "error") {
          const errText = (_a = msg.payload.message) != null ? _a : "Unknown error from gateway";
          this.chatManager.addMessage(ChatManager.createSystemMessage(`\u26A0 ${errText}`, "error"));
        }
      };
      this.registerView(
        VIEW_TYPE_OPENCLAW_CHAT,
        (leaf) => new OpenClawChatView(leaf, this)
      );
      this.addRibbonIcon("message-square", "OpenClaw Chat", () => {
        this._activateChatView();
      });
      this.addSettingTab(new OpenClawSettingTab(this.app, this));
      this.addCommand({
        id: "open-openclaw-chat",
        name: "Open chat sidebar",
        callback: () => this._activateChatView()
      });
      if (this.settings.authToken) {
        this._connectWS();
      } else {
        new import_obsidian3.Notice("OpenClaw Chat: please configure your gateway token in Settings.");
      }
      console.log("[oclaw] Plugin loaded");
    });
  }
  onunload() {
    return __async(this, null, function* () {
      this.wsClient.disconnect();
      this.app.workspace.detachLeavesOfType(VIEW_TYPE_OPENCLAW_CHAT);
      console.log("[oclaw] Plugin unloaded");
    });
  }
  loadSettings() {
    return __async(this, null, function* () {
      var _a;
      const data = (_a = yield this.loadData()) != null ? _a : {};
      this.settings = Object.assign({}, DEFAULT_SETTINGS, data);
    });
  }
  saveSettings() {
    return __async(this, null, function* () {
      var _a;
      const data = (_a = yield this.loadData()) != null ? _a : {};
      yield this.saveData(__spreadValues(__spreadValues({}, data), this.settings));
    });
  }
  // ── Device identity persistence (plugin-scoped; NOT localStorage) ─────────
  resetDeviceIdentity() {
    return __async(this, null, function* () {
      yield this._clearDeviceIdentity();
      new import_obsidian3.Notice("OpenClaw Chat: device identity reset. Reconnect to pair again.");
    });
  }
  _loadDeviceIdentity() {
    return __async(this, null, function* () {
      var _a, _b;
      const data = (_a = yield this.loadData()) != null ? _a : {};
      return (_b = data == null ? void 0 : data[this._deviceIdentityKey]) != null ? _b : null;
    });
  }
  _saveDeviceIdentity(identity) {
    return __async(this, null, function* () {
      var _a;
      const data = (_a = yield this.loadData()) != null ? _a : {};
      yield this.saveData(__spreadProps(__spreadValues({}, data), { [this._deviceIdentityKey]: identity }));
    });
  }
  _clearDeviceIdentity() {
    return __async(this, null, function* () {
      var _a;
      const data = (_a = yield this.loadData()) != null ? _a : {};
      if ((data == null ? void 0 : data[this._deviceIdentityKey]) === void 0)
        return;
      const next = __spreadValues({}, data);
      delete next[this._deviceIdentityKey];
      yield this.saveData(next);
    });
  }
  // ── Helpers ───────────────────────────────────────────────────────────────
  _connectWS() {
    this.wsClient.connect(this.settings.gatewayUrl, this.settings.authToken, {
      allowInsecureWs: this.settings.allowInsecureWs
    });
  }
  _activateChatView() {
    return __async(this, null, function* () {
      const { workspace } = this.app;
      const existing = workspace.getLeavesOfType(VIEW_TYPE_OPENCLAW_CHAT);
      if (existing.length > 0) {
        workspace.revealLeaf(existing[0]);
        return;
      }
      const leaf = workspace.getRightLeaf(false);
      if (!leaf)
        return;
      yield leaf.setViewState({ type: VIEW_TYPE_OPENCLAW_CHAT, active: true });
      workspace.revealLeaf(leaf);
    });
  }
};
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsic3JjL21haW4udHMiLCAic3JjL3NldHRpbmdzLnRzIiwgInNyYy93ZWJzb2NrZXQudHMiLCAic3JjL2NoYXQudHMiLCAic3JjL3ZpZXcudHMiLCAic3JjL2NvbnRleHQudHMiLCAic3JjL3R5cGVzLnRzIl0sCiAgInNvdXJjZXNDb250ZW50IjogWyJpbXBvcnQgeyBOb3RpY2UsIFBsdWdpbiwgV29ya3NwYWNlTGVhZiB9IGZyb20gJ29ic2lkaWFuJztcbmltcG9ydCB7IE9wZW5DbGF3U2V0dGluZ1RhYiB9IGZyb20gJy4vc2V0dGluZ3MnO1xuaW1wb3J0IHsgT2JzaWRpYW5XU0NsaWVudCB9IGZyb20gJy4vd2Vic29ja2V0JztcbmltcG9ydCB7IENoYXRNYW5hZ2VyIH0gZnJvbSAnLi9jaGF0JztcbmltcG9ydCB7IFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFULCBPcGVuQ2xhd0NoYXRWaWV3IH0gZnJvbSAnLi92aWV3JztcbmltcG9ydCB7IERFRkFVTFRfU0VUVElOR1MsIHR5cGUgT3BlbkNsYXdTZXR0aW5ncyB9IGZyb20gJy4vdHlwZXMnO1xuXG5leHBvcnQgZGVmYXVsdCBjbGFzcyBPcGVuQ2xhd1BsdWdpbiBleHRlbmRzIFBsdWdpbiB7XG4gIHNldHRpbmdzITogT3BlbkNsYXdTZXR0aW5ncztcbiAgd3NDbGllbnQhOiBPYnNpZGlhbldTQ2xpZW50O1xuICBjaGF0TWFuYWdlciE6IENoYXRNYW5hZ2VyO1xuXG4gIGFzeW5jIG9ubG9hZCgpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBhd2FpdCB0aGlzLmxvYWRTZXR0aW5ncygpO1xuXG4gICAgdGhpcy53c0NsaWVudCA9IG5ldyBPYnNpZGlhbldTQ2xpZW50KHRoaXMuc2V0dGluZ3Muc2Vzc2lvbktleSwge1xuICAgICAgaWRlbnRpdHlTdG9yZToge1xuICAgICAgICBnZXQ6IGFzeW5jICgpID0+IChhd2FpdCB0aGlzLl9sb2FkRGV2aWNlSWRlbnRpdHkoKSksXG4gICAgICAgIHNldDogYXN5bmMgKGlkZW50aXR5KSA9PiBhd2FpdCB0aGlzLl9zYXZlRGV2aWNlSWRlbnRpdHkoaWRlbnRpdHkpLFxuICAgICAgICBjbGVhcjogYXN5bmMgKCkgPT4gYXdhaXQgdGhpcy5fY2xlYXJEZXZpY2VJZGVudGl0eSgpLFxuICAgICAgfSxcbiAgICB9KTtcbiAgICB0aGlzLmNoYXRNYW5hZ2VyID0gbmV3IENoYXRNYW5hZ2VyKCk7XG5cbiAgICAvLyBXaXJlIGluY29taW5nIFdTIG1lc3NhZ2VzIFx1MjE5MiBDaGF0TWFuYWdlclxuICAgIHRoaXMud3NDbGllbnQub25NZXNzYWdlID0gKG1zZykgPT4ge1xuICAgICAgaWYgKG1zZy50eXBlID09PSAnbWVzc2FnZScpIHtcbiAgICAgICAgdGhpcy5jaGF0TWFuYWdlci5hZGRNZXNzYWdlKENoYXRNYW5hZ2VyLmNyZWF0ZUFzc2lzdGFudE1lc3NhZ2UobXNnLnBheWxvYWQuY29udGVudCkpO1xuICAgICAgfSBlbHNlIGlmIChtc2cudHlwZSA9PT0gJ2Vycm9yJykge1xuICAgICAgICBjb25zdCBlcnJUZXh0ID0gbXNnLnBheWxvYWQubWVzc2FnZSA/PyAnVW5rbm93biBlcnJvciBmcm9tIGdhdGV3YXknO1xuICAgICAgICB0aGlzLmNoYXRNYW5hZ2VyLmFkZE1lc3NhZ2UoQ2hhdE1hbmFnZXIuY3JlYXRlU3lzdGVtTWVzc2FnZShgXHUyNkEwICR7ZXJyVGV4dH1gLCAnZXJyb3InKSk7XG4gICAgICB9XG4gICAgfTtcblxuICAgIC8vIFJlZ2lzdGVyIHRoZSBzaWRlYmFyIHZpZXdcbiAgICB0aGlzLnJlZ2lzdGVyVmlldyhcbiAgICAgIFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFULFxuICAgICAgKGxlYWY6IFdvcmtzcGFjZUxlYWYpID0+IG5ldyBPcGVuQ2xhd0NoYXRWaWV3KGxlYWYsIHRoaXMpXG4gICAgKTtcblxuICAgIC8vIFJpYmJvbiBpY29uIFx1MjAxNCBvcGVucyAvIHJldmVhbHMgdGhlIGNoYXQgc2lkZWJhclxuICAgIHRoaXMuYWRkUmliYm9uSWNvbignbWVzc2FnZS1zcXVhcmUnLCAnT3BlbkNsYXcgQ2hhdCcsICgpID0+IHtcbiAgICAgIHRoaXMuX2FjdGl2YXRlQ2hhdFZpZXcoKTtcbiAgICB9KTtcblxuICAgIC8vIFNldHRpbmdzIHRhYlxuICAgIHRoaXMuYWRkU2V0dGluZ1RhYihuZXcgT3BlbkNsYXdTZXR0aW5nVGFiKHRoaXMuYXBwLCB0aGlzKSk7XG5cbiAgICAvLyBDb21tYW5kIHBhbGV0dGUgZW50cnlcbiAgICB0aGlzLmFkZENvbW1hbmQoe1xuICAgICAgaWQ6ICdvcGVuLW9wZW5jbGF3LWNoYXQnLFxuICAgICAgbmFtZTogJ09wZW4gY2hhdCBzaWRlYmFyJyxcbiAgICAgIGNhbGxiYWNrOiAoKSA9PiB0aGlzLl9hY3RpdmF0ZUNoYXRWaWV3KCksXG4gICAgfSk7XG5cbiAgICAvLyBDb25uZWN0IHRvIGdhdGV3YXkgaWYgdG9rZW4gaXMgY29uZmlndXJlZFxuICAgIGlmICh0aGlzLnNldHRpbmdzLmF1dGhUb2tlbikge1xuICAgICAgdGhpcy5fY29ubmVjdFdTKCk7XG4gICAgfSBlbHNlIHtcbiAgICAgIG5ldyBOb3RpY2UoJ09wZW5DbGF3IENoYXQ6IHBsZWFzZSBjb25maWd1cmUgeW91ciBnYXRld2F5IHRva2VuIGluIFNldHRpbmdzLicpO1xuICAgIH1cblxuICAgIGNvbnNvbGUubG9nKCdbb2NsYXddIFBsdWdpbiBsb2FkZWQnKTtcbiAgfVxuXG4gIGFzeW5jIG9udW5sb2FkKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIHRoaXMud3NDbGllbnQuZGlzY29ubmVjdCgpO1xuICAgIHRoaXMuYXBwLndvcmtzcGFjZS5kZXRhY2hMZWF2ZXNPZlR5cGUoVklFV19UWVBFX09QRU5DTEFXX0NIQVQpO1xuICAgIGNvbnNvbGUubG9nKCdbb2NsYXddIFBsdWdpbiB1bmxvYWRlZCcpO1xuICB9XG5cbiAgYXN5bmMgbG9hZFNldHRpbmdzKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIGNvbnN0IGRhdGEgPSAoYXdhaXQgdGhpcy5sb2FkRGF0YSgpKSA/PyB7fTtcbiAgICAvLyBOT1RFOiBwbHVnaW4gZGF0YSBtYXkgY29udGFpbiBleHRyYSBwcml2YXRlIGZpZWxkcyAoZS5nLiBkZXZpY2UgaWRlbnRpdHkpLiBTZXR0aW5ncyBhcmUgdGhlIHB1YmxpYyBzdWJzZXQuXG4gICAgdGhpcy5zZXR0aW5ncyA9IE9iamVjdC5hc3NpZ24oe30sIERFRkFVTFRfU0VUVElOR1MsIGRhdGEpO1xuICB9XG5cbiAgYXN5bmMgc2F2ZVNldHRpbmdzKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIC8vIFByZXNlcnZlIGFueSBwcml2YXRlIGZpZWxkcyBzdG9yZWQgaW4gcGx1Z2luIGRhdGEuXG4gICAgY29uc3QgZGF0YSA9IChhd2FpdCB0aGlzLmxvYWREYXRhKCkpID8/IHt9O1xuICAgIGF3YWl0IHRoaXMuc2F2ZURhdGEoeyAuLi5kYXRhLCAuLi50aGlzLnNldHRpbmdzIH0pO1xuICB9XG5cbiAgLy8gXHUyNTAwXHUyNTAwIERldmljZSBpZGVudGl0eSBwZXJzaXN0ZW5jZSAocGx1Z2luLXNjb3BlZDsgTk9UIGxvY2FsU3RvcmFnZSkgXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG5cbiAgYXN5bmMgcmVzZXREZXZpY2VJZGVudGl0eSgpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBhd2FpdCB0aGlzLl9jbGVhckRldmljZUlkZW50aXR5KCk7XG4gICAgbmV3IE5vdGljZSgnT3BlbkNsYXcgQ2hhdDogZGV2aWNlIGlkZW50aXR5IHJlc2V0LiBSZWNvbm5lY3QgdG8gcGFpciBhZ2Fpbi4nKTtcbiAgfVxuXG4gIHByaXZhdGUgX2RldmljZUlkZW50aXR5S2V5ID0gJ19vcGVuY2xhd0RldmljZUlkZW50aXR5VjEnO1xuXG4gIHByaXZhdGUgYXN5bmMgX2xvYWREZXZpY2VJZGVudGl0eSgpOiBQcm9taXNlPGFueSB8IG51bGw+IHtcbiAgICBjb25zdCBkYXRhID0gKGF3YWl0IHRoaXMubG9hZERhdGEoKSkgPz8ge307XG4gICAgcmV0dXJuIChkYXRhIGFzIGFueSk/Llt0aGlzLl9kZXZpY2VJZGVudGl0eUtleV0gPz8gbnVsbDtcbiAgfVxuXG4gIHByaXZhdGUgYXN5bmMgX3NhdmVEZXZpY2VJZGVudGl0eShpZGVudGl0eTogYW55KTogUHJvbWlzZTx2b2lkPiB7XG4gICAgY29uc3QgZGF0YSA9IChhd2FpdCB0aGlzLmxvYWREYXRhKCkpID8/IHt9O1xuICAgIGF3YWl0IHRoaXMuc2F2ZURhdGEoeyAuLi5kYXRhLCBbdGhpcy5fZGV2aWNlSWRlbnRpdHlLZXldOiBpZGVudGl0eSB9KTtcbiAgfVxuXG4gIHByaXZhdGUgYXN5bmMgX2NsZWFyRGV2aWNlSWRlbnRpdHkoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgY29uc3QgZGF0YSA9IChhd2FpdCB0aGlzLmxvYWREYXRhKCkpID8/IHt9O1xuICAgIGlmICgoZGF0YSBhcyBhbnkpPy5bdGhpcy5fZGV2aWNlSWRlbnRpdHlLZXldID09PSB1bmRlZmluZWQpIHJldHVybjtcbiAgICBjb25zdCBuZXh0ID0geyAuLi4oZGF0YSBhcyBhbnkpIH07XG4gICAgZGVsZXRlIG5leHRbdGhpcy5fZGV2aWNlSWRlbnRpdHlLZXldO1xuICAgIGF3YWl0IHRoaXMuc2F2ZURhdGEobmV4dCk7XG4gIH1cblxuICAvLyBcdTI1MDBcdTI1MDAgSGVscGVycyBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcblxuICBwcml2YXRlIF9jb25uZWN0V1MoKTogdm9pZCB7XG4gICAgdGhpcy53c0NsaWVudC5jb25uZWN0KHRoaXMuc2V0dGluZ3MuZ2F0ZXdheVVybCwgdGhpcy5zZXR0aW5ncy5hdXRoVG9rZW4sIHtcbiAgICAgIGFsbG93SW5zZWN1cmVXczogdGhpcy5zZXR0aW5ncy5hbGxvd0luc2VjdXJlV3MsXG4gICAgfSk7XG4gIH1cblxuICBwcml2YXRlIGFzeW5jIF9hY3RpdmF0ZUNoYXRWaWV3KCk6IFByb21pc2U8dm9pZD4ge1xuICAgIGNvbnN0IHsgd29ya3NwYWNlIH0gPSB0aGlzLmFwcDtcblxuICAgIC8vIFJldXNlIGV4aXN0aW5nIGxlYWYgaWYgYWxyZWFkeSBvcGVuXG4gICAgY29uc3QgZXhpc3RpbmcgPSB3b3Jrc3BhY2UuZ2V0TGVhdmVzT2ZUeXBlKFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFUKTtcbiAgICBpZiAoZXhpc3RpbmcubGVuZ3RoID4gMCkge1xuICAgICAgd29ya3NwYWNlLnJldmVhbExlYWYoZXhpc3RpbmdbMF0pO1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIC8vIE9wZW4gaW4gcmlnaHQgc2lkZWJhclxuICAgIGNvbnN0IGxlYWYgPSB3b3Jrc3BhY2UuZ2V0UmlnaHRMZWFmKGZhbHNlKTtcbiAgICBpZiAoIWxlYWYpIHJldHVybjtcbiAgICBhd2FpdCBsZWFmLnNldFZpZXdTdGF0ZSh7IHR5cGU6IFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFULCBhY3RpdmU6IHRydWUgfSk7XG4gICAgd29ya3NwYWNlLnJldmVhbExlYWYobGVhZik7XG4gIH1cbn1cbiIsICJpbXBvcnQgeyBBcHAsIFBsdWdpblNldHRpbmdUYWIsIFNldHRpbmcgfSBmcm9tICdvYnNpZGlhbic7XG5pbXBvcnQgdHlwZSBPcGVuQ2xhd1BsdWdpbiBmcm9tICcuL21haW4nO1xuXG5leHBvcnQgY2xhc3MgT3BlbkNsYXdTZXR0aW5nVGFiIGV4dGVuZHMgUGx1Z2luU2V0dGluZ1RhYiB7XG4gIHBsdWdpbjogT3BlbkNsYXdQbHVnaW47XG5cbiAgY29uc3RydWN0b3IoYXBwOiBBcHAsIHBsdWdpbjogT3BlbkNsYXdQbHVnaW4pIHtcbiAgICBzdXBlcihhcHAsIHBsdWdpbik7XG4gICAgdGhpcy5wbHVnaW4gPSBwbHVnaW47XG4gIH1cblxuICBkaXNwbGF5KCk6IHZvaWQge1xuICAgIGNvbnN0IHsgY29udGFpbmVyRWwgfSA9IHRoaXM7XG4gICAgY29udGFpbmVyRWwuZW1wdHkoKTtcblxuICAgIGNvbnRhaW5lckVsLmNyZWF0ZUVsKCdoMicsIHsgdGV4dDogJ09wZW5DbGF3IENoYXQgXHUyMDEzIFNldHRpbmdzJyB9KTtcblxuICAgIG5ldyBTZXR0aW5nKGNvbnRhaW5lckVsKVxuICAgICAgLnNldE5hbWUoJ0dhdGV3YXkgVVJMJylcbiAgICAgIC5zZXREZXNjKCdXZWJTb2NrZXQgVVJMIG9mIHRoZSBPcGVuQ2xhdyBHYXRld2F5IChlLmcuIHdzOi8vaG9zdG5hbWU6MTg3ODkpLicpXG4gICAgICAuYWRkVGV4dCgodGV4dCkgPT5cbiAgICAgICAgdGV4dFxuICAgICAgICAgIC5zZXRQbGFjZWhvbGRlcignd3M6Ly9sb2NhbGhvc3Q6MTg3ODknKVxuICAgICAgICAgIC5zZXRWYWx1ZSh0aGlzLnBsdWdpbi5zZXR0aW5ncy5nYXRld2F5VXJsKVxuICAgICAgICAgIC5vbkNoYW5nZShhc3luYyAodmFsdWUpID0+IHtcbiAgICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLmdhdGV3YXlVcmwgPSB2YWx1ZS50cmltKCk7XG4gICAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgICB9KVxuICAgICAgKTtcblxuICAgIG5ldyBTZXR0aW5nKGNvbnRhaW5lckVsKVxuICAgICAgLnNldE5hbWUoJ0F1dGggdG9rZW4nKVxuICAgICAgLnNldERlc2MoJ011c3QgbWF0Y2ggdGhlIGF1dGhUb2tlbiBpbiB5b3VyIG9wZW5jbGF3Lmpzb24gY2hhbm5lbCBjb25maWcuIE5ldmVyIHNoYXJlZC4nKVxuICAgICAgLmFkZFRleHQoKHRleHQpID0+IHtcbiAgICAgICAgdGV4dFxuICAgICAgICAgIC5zZXRQbGFjZWhvbGRlcignRW50ZXIgdG9rZW5cdTIwMjYnKVxuICAgICAgICAgIC5zZXRWYWx1ZSh0aGlzLnBsdWdpbi5zZXR0aW5ncy5hdXRoVG9rZW4pXG4gICAgICAgICAgLm9uQ2hhbmdlKGFzeW5jICh2YWx1ZSkgPT4ge1xuICAgICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3MuYXV0aFRva2VuID0gdmFsdWU7XG4gICAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgICB9KTtcbiAgICAgICAgLy8gVHJlYXQgYXMgcGFzc3dvcmQgZmllbGQgXHUyMDEzIGRvIG5vdCByZXZlYWwgdG9rZW4gaW4gVUlcbiAgICAgICAgdGV4dC5pbnB1dEVsLnR5cGUgPSAncGFzc3dvcmQnO1xuICAgICAgICB0ZXh0LmlucHV0RWwuYXV0b2NvbXBsZXRlID0gJ29mZic7XG4gICAgICB9KTtcblxuICAgIG5ldyBTZXR0aW5nKGNvbnRhaW5lckVsKVxuICAgICAgLnNldE5hbWUoJ1Nlc3Npb24gS2V5JylcbiAgICAgIC5zZXREZXNjKCdPcGVuQ2xhdyBzZXNzaW9uIHRvIHN1YnNjcmliZSB0byAodXN1YWxseSBcIm1haW5cIikuJylcbiAgICAgIC5hZGRUZXh0KCh0ZXh0KSA9PlxuICAgICAgICB0ZXh0XG4gICAgICAgICAgLnNldFBsYWNlaG9sZGVyKCdtYWluJylcbiAgICAgICAgICAuc2V0VmFsdWUodGhpcy5wbHVnaW4uc2V0dGluZ3Muc2Vzc2lvbktleSlcbiAgICAgICAgICAub25DaGFuZ2UoYXN5bmMgKHZhbHVlKSA9PiB7XG4gICAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5zZXNzaW9uS2V5ID0gdmFsdWUudHJpbSgpIHx8ICdtYWluJztcbiAgICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICAgIH0pXG4gICAgICApO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZSgnQWNjb3VudCBJRCcpXG4gICAgICAuc2V0RGVzYygnT3BlbkNsYXcgYWNjb3VudCBJRCAodXN1YWxseSBcIm1haW5cIikuJylcbiAgICAgIC5hZGRUZXh0KCh0ZXh0KSA9PlxuICAgICAgICB0ZXh0XG4gICAgICAgICAgLnNldFBsYWNlaG9sZGVyKCdtYWluJylcbiAgICAgICAgICAuc2V0VmFsdWUodGhpcy5wbHVnaW4uc2V0dGluZ3MuYWNjb3VudElkKVxuICAgICAgICAgIC5vbkNoYW5nZShhc3luYyAodmFsdWUpID0+IHtcbiAgICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLmFjY291bnRJZCA9IHZhbHVlLnRyaW0oKSB8fCAnbWFpbic7XG4gICAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgICB9KVxuICAgICAgKTtcblxuICAgIG5ldyBTZXR0aW5nKGNvbnRhaW5lckVsKVxuICAgICAgLnNldE5hbWUoJ0luY2x1ZGUgYWN0aXZlIG5vdGUgYnkgZGVmYXVsdCcpXG4gICAgICAuc2V0RGVzYygnUHJlLWNoZWNrIFwiSW5jbHVkZSBhY3RpdmUgbm90ZVwiIGluIHRoZSBjaGF0IHBhbmVsIHdoZW4gaXQgb3BlbnMuJylcbiAgICAgIC5hZGRUb2dnbGUoKHRvZ2dsZSkgPT5cbiAgICAgICAgdG9nZ2xlLnNldFZhbHVlKHRoaXMucGx1Z2luLnNldHRpbmdzLmluY2x1ZGVBY3RpdmVOb3RlKS5vbkNoYW5nZShhc3luYyAodmFsdWUpID0+IHtcbiAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5pbmNsdWRlQWN0aXZlTm90ZSA9IHZhbHVlO1xuICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICB9KVxuICAgICAgKTtcblxuICAgIG5ldyBTZXR0aW5nKGNvbnRhaW5lckVsKVxuICAgICAgLnNldE5hbWUoJ1JlbmRlciBhc3Npc3RhbnQgYXMgTWFya2Rvd24gKHVuc2FmZSknKVxuICAgICAgLnNldERlc2MoXG4gICAgICAgICdPRkYgcmVjb21tZW5kZWQuIElmIGVuYWJsZWQsIGFzc2lzdGFudCBvdXRwdXQgaXMgcmVuZGVyZWQgYXMgT2JzaWRpYW4gTWFya2Rvd24gd2hpY2ggbWF5IHRyaWdnZXIgZW1iZWRzIGFuZCBvdGhlciBwbHVnaW5zXFwnIHBvc3QtcHJvY2Vzc29ycy4nXG4gICAgICApXG4gICAgICAuYWRkVG9nZ2xlKCh0b2dnbGUpID0+XG4gICAgICAgIHRvZ2dsZS5zZXRWYWx1ZSh0aGlzLnBsdWdpbi5zZXR0aW5ncy5yZW5kZXJBc3Npc3RhbnRNYXJrZG93bikub25DaGFuZ2UoYXN5bmMgKHZhbHVlKSA9PiB7XG4gICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3MucmVuZGVyQXNzaXN0YW50TWFya2Rvd24gPSB2YWx1ZTtcbiAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgfSlcbiAgICAgICk7XG5cbiAgICBuZXcgU2V0dGluZyhjb250YWluZXJFbClcbiAgICAgIC5zZXROYW1lKCdBbGxvdyBpbnNlY3VyZSB3czovLyBmb3Igbm9uLWxvY2FsIGdhdGV3YXlzICh1bnNhZmUpJylcbiAgICAgIC5zZXREZXNjKFxuICAgICAgICAnT0ZGIHJlY29tbWVuZGVkLiBJZiBlbmFibGVkLCB5b3UgY2FuIGNvbm5lY3QgdG8gbm9uLWxvY2FsIGdhdGV3YXlzIG92ZXIgd3M6Ly8uIFRoaXMgZXhwb3NlcyB5b3VyIHRva2VuIGFuZCBtZXNzYWdlIGNvbnRlbnQgdG8gbmV0d29yayBhdHRhY2tlcnM7IHByZWZlciB3c3M6Ly8uJ1xuICAgICAgKVxuICAgICAgLmFkZFRvZ2dsZSgodG9nZ2xlKSA9PlxuICAgICAgICB0b2dnbGUuc2V0VmFsdWUodGhpcy5wbHVnaW4uc2V0dGluZ3MuYWxsb3dJbnNlY3VyZVdzKS5vbkNoYW5nZShhc3luYyAodmFsdWUpID0+IHtcbiAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5hbGxvd0luc2VjdXJlV3MgPSB2YWx1ZTtcbiAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgfSlcbiAgICAgICk7XG5cbiAgICBuZXcgU2V0dGluZyhjb250YWluZXJFbClcbiAgICAgIC5zZXROYW1lKCdSZXNldCBkZXZpY2UgaWRlbnRpdHkgKHJlLXBhaXIpJylcbiAgICAgIC5zZXREZXNjKCdDbGVhcnMgdGhlIHN0b3JlZCBkZXZpY2UgaWRlbnRpdHkgdXNlZCBmb3Igb3BlcmF0b3Iud3JpdGUgcGFpcmluZy4gVXNlIHRoaXMgaWYgeW91IHN1c3BlY3QgY29tcHJvbWlzZSBvciBzZWUgXCJkZXZpY2UgaWRlbnRpdHkgbWlzbWF0Y2hcIi4nKVxuICAgICAgLmFkZEJ1dHRvbigoYnRuKSA9PlxuICAgICAgICBidG4uc2V0QnV0dG9uVGV4dCgnUmVzZXQnKS5zZXRXYXJuaW5nKCkub25DbGljayhhc3luYyAoKSA9PiB7XG4gICAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4ucmVzZXREZXZpY2VJZGVudGl0eSgpO1xuICAgICAgICB9KVxuICAgICAgKTtcblxuICAgIGNvbnRhaW5lckVsLmNyZWF0ZUVsKCdwJywge1xuICAgICAgdGV4dDogJ1JlY29ubmVjdDogY2xvc2UgYW5kIHJlb3BlbiB0aGUgc2lkZWJhciBhZnRlciBjaGFuZ2luZyB0aGUgZ2F0ZXdheSBVUkwgb3IgdG9rZW4uJyxcbiAgICAgIGNsczogJ3NldHRpbmctaXRlbS1kZXNjcmlwdGlvbicsXG4gICAgfSk7XG4gIH1cbn1cbiIsICIvKipcbiAqIFdlYlNvY2tldCBjbGllbnQgZm9yIE9wZW5DbGF3IEdhdGV3YXlcbiAqXG4gKiBQaXZvdCAoMjAyNi0wMi0yNSk6IERvIE5PVCB1c2UgY3VzdG9tIG9ic2lkaWFuLiogZ2F0ZXdheSBtZXRob2RzLlxuICogVGhvc2UgcmVxdWlyZSBvcGVyYXRvci5hZG1pbiBzY29wZSB3aGljaCBpcyBub3QgZ3JhbnRlZCB0byBleHRlcm5hbCBjbGllbnRzLlxuICpcbiAqIEF1dGggbm90ZTpcbiAqIC0gY2hhdC5zZW5kIHJlcXVpcmVzIG9wZXJhdG9yLndyaXRlXG4gKiAtIGV4dGVybmFsIGNsaWVudHMgbXVzdCBwcmVzZW50IGEgcGFpcmVkIGRldmljZSBpZGVudGl0eSB0byByZWNlaXZlIHdyaXRlIHNjb3Blc1xuICpcbiAqIFdlIHVzZSBidWlsdC1pbiBnYXRld2F5IG1ldGhvZHMvZXZlbnRzOlxuICogLSBTZW5kOiBjaGF0LnNlbmQoeyBzZXNzaW9uS2V5LCBtZXNzYWdlLCBpZGVtcG90ZW5jeUtleSwgLi4uIH0pXG4gKiAtIFJlY2VpdmU6IGV2ZW50IFwiY2hhdFwiIChmaWx0ZXIgYnkgc2Vzc2lvbktleSlcbiAqL1xuXG5pbXBvcnQgdHlwZSB7IEluYm91bmRXU1BheWxvYWQgfSBmcm9tICcuL3R5cGVzJztcblxuZnVuY3Rpb24gaXNMb2NhbEhvc3QoaG9zdDogc3RyaW5nKTogYm9vbGVhbiB7XG4gIGNvbnN0IGggPSBob3N0LnRvTG93ZXJDYXNlKCk7XG4gIHJldHVybiBoID09PSAnbG9jYWxob3N0JyB8fCBoID09PSAnMTI3LjAuMC4xJyB8fCBoID09PSAnOjoxJztcbn1cblxuZnVuY3Rpb24gc2FmZVBhcnNlV3NVcmwodXJsOiBzdHJpbmcpOlxuICB8IHsgb2s6IHRydWU7IHNjaGVtZTogJ3dzJyB8ICd3c3MnOyBob3N0OiBzdHJpbmcgfVxuICB8IHsgb2s6IGZhbHNlOyBlcnJvcjogc3RyaW5nIH0ge1xuICB0cnkge1xuICAgIGNvbnN0IHUgPSBuZXcgVVJMKHVybCk7XG4gICAgaWYgKHUucHJvdG9jb2wgIT09ICd3czonICYmIHUucHJvdG9jb2wgIT09ICd3c3M6Jykge1xuICAgICAgcmV0dXJuIHsgb2s6IGZhbHNlLCBlcnJvcjogYEdhdGV3YXkgVVJMIG11c3QgYmUgd3M6Ly8gb3Igd3NzOi8vIChnb3QgJHt1LnByb3RvY29sfSlgIH07XG4gICAgfVxuICAgIGNvbnN0IHNjaGVtZSA9IHUucHJvdG9jb2wgPT09ICd3czonID8gJ3dzJyA6ICd3c3MnO1xuICAgIHJldHVybiB7IG9rOiB0cnVlLCBzY2hlbWUsIGhvc3Q6IHUuaG9zdG5hbWUgfTtcbiAgfSBjYXRjaCB7XG4gICAgcmV0dXJuIHsgb2s6IGZhbHNlLCBlcnJvcjogJ0ludmFsaWQgZ2F0ZXdheSBVUkwnIH07XG4gIH1cbn1cblxuLyoqIEludGVydmFsIGZvciBzZW5kaW5nIGhlYXJ0YmVhdCBwaW5ncyAoY2hlY2sgY29ubmVjdGlvbiBsaXZlbmVzcykgKi9cbmNvbnN0IEhFQVJUQkVBVF9JTlRFUlZBTF9NUyA9IDMwXzAwMDtcblxuLyoqIFNhZmV0eSB2YWx2ZTogaGlkZSB3b3JraW5nIHNwaW5uZXIgaWYgbm8gYXNzaXN0YW50IHJlcGx5IGFycml2ZXMgaW4gdGltZSAqL1xuY29uc3QgV09SS0lOR19NQVhfTVMgPSAxMjBfMDAwO1xuXG4vKiogTWF4IGluYm91bmQgZnJhbWUgc2l6ZSB0byBwYXJzZSAoRG9TIGd1YXJkKSAqL1xuY29uc3QgTUFYX0lOQk9VTkRfRlJBTUVfQllURVMgPSA1MTIgKiAxMDI0O1xuXG4vKiogTWF4IGluLWZsaWdodCByZXF1ZXN0cyBiZWZvcmUgZmFzdC1mYWlsaW5nIChEb1Mvcm9idXN0bmVzcyBndWFyZCkgKi9cbmNvbnN0IE1BWF9QRU5ESU5HX1JFUVVFU1RTID0gMjAwO1xuXG4vKiogUmVjb25uZWN0IGJhY2tvZmYgKi9cbmNvbnN0IFJFQ09OTkVDVF9CQVNFX01TID0gM18wMDA7XG5jb25zdCBSRUNPTk5FQ1RfTUFYX01TID0gNjBfMDAwO1xuXG4vKiogSGFuZHNoYWtlIGRlYWRsaW5lIHdhaXRpbmcgZm9yIGNvbm5lY3QuY2hhbGxlbmdlICovXG5jb25zdCBIQU5EU0hBS0VfVElNRU9VVF9NUyA9IDE1XzAwMDtcblxuZXhwb3J0IHR5cGUgV1NDbGllbnRTdGF0ZSA9ICdkaXNjb25uZWN0ZWQnIHwgJ2Nvbm5lY3RpbmcnIHwgJ2hhbmRzaGFraW5nJyB8ICdjb25uZWN0ZWQnO1xuXG5leHBvcnQgdHlwZSBXb3JraW5nU3RhdGVMaXN0ZW5lciA9ICh3b3JraW5nOiBib29sZWFuKSA9PiB2b2lkO1xuXG5pbnRlcmZhY2UgUGVuZGluZ1JlcXVlc3Qge1xuICByZXNvbHZlOiAocGF5bG9hZDogYW55KSA9PiB2b2lkO1xuICByZWplY3Q6IChlcnJvcjogYW55KSA9PiB2b2lkO1xuICB0aW1lb3V0OiBSZXR1cm5UeXBlPHR5cGVvZiBzZXRUaW1lb3V0PiB8IG51bGw7XG59XG5cbmV4cG9ydCB0eXBlIERldmljZUlkZW50aXR5ID0ge1xuICBpZDogc3RyaW5nO1xuICBwdWJsaWNLZXk6IHN0cmluZzsgLy8gYmFzZTY0XG4gIHByaXZhdGVLZXlKd2s6IEpzb25XZWJLZXk7XG59O1xuXG5leHBvcnQgaW50ZXJmYWNlIERldmljZUlkZW50aXR5U3RvcmUge1xuICBnZXQoKTogUHJvbWlzZTxEZXZpY2VJZGVudGl0eSB8IG51bGw+O1xuICBzZXQoaWRlbnRpdHk6IERldmljZUlkZW50aXR5KTogUHJvbWlzZTx2b2lkPjtcbiAgY2xlYXIoKTogUHJvbWlzZTx2b2lkPjtcbn1cblxuY29uc3QgREVWSUNFX1NUT1JBR0VfS0VZID0gJ29wZW5jbGF3Q2hhdC5kZXZpY2VJZGVudGl0eS52MSc7IC8vIGxlZ2FjeSBsb2NhbFN0b3JhZ2Uga2V5IChtaWdyYXRpb24gb25seSlcblxuZnVuY3Rpb24gYmFzZTY0VXJsRW5jb2RlKGJ5dGVzOiBBcnJheUJ1ZmZlcik6IHN0cmluZyB7XG4gIGNvbnN0IHU4ID0gbmV3IFVpbnQ4QXJyYXkoYnl0ZXMpO1xuICBsZXQgcyA9ICcnO1xuICBmb3IgKGxldCBpID0gMDsgaSA8IHU4Lmxlbmd0aDsgaSsrKSBzICs9IFN0cmluZy5mcm9tQ2hhckNvZGUodThbaV0pO1xuICBjb25zdCBiNjQgPSBidG9hKHMpO1xuICByZXR1cm4gYjY0LnJlcGxhY2UoL1xcKy9nLCAnLScpLnJlcGxhY2UoL1xcLy9nLCAnXycpLnJlcGxhY2UoLz0rJC9nLCAnJyk7XG59XG5cbmZ1bmN0aW9uIGhleEVuY29kZShieXRlczogQXJyYXlCdWZmZXIpOiBzdHJpbmcge1xuICBjb25zdCB1OCA9IG5ldyBVaW50OEFycmF5KGJ5dGVzKTtcbiAgcmV0dXJuIEFycmF5LmZyb20odTgpXG4gICAgLm1hcCgoYikgPT4gYi50b1N0cmluZygxNikucGFkU3RhcnQoMiwgJzAnKSlcbiAgICAuam9pbignJyk7XG59XG5cbmZ1bmN0aW9uIHV0ZjhCeXRlcyh0ZXh0OiBzdHJpbmcpOiBVaW50OEFycmF5IHtcbiAgcmV0dXJuIG5ldyBUZXh0RW5jb2RlcigpLmVuY29kZSh0ZXh0KTtcbn1cblxuYXN5bmMgZnVuY3Rpb24gc2hhMjU2SGV4KGJ5dGVzOiBBcnJheUJ1ZmZlcik6IFByb21pc2U8c3RyaW5nPiB7XG4gIGNvbnN0IGRpZ2VzdCA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuZGlnZXN0KCdTSEEtMjU2JywgYnl0ZXMpO1xuICByZXR1cm4gaGV4RW5jb2RlKGRpZ2VzdCk7XG59XG5cbmFzeW5jIGZ1bmN0aW9uIGxvYWRPckNyZWF0ZURldmljZUlkZW50aXR5KHN0b3JlPzogRGV2aWNlSWRlbnRpdHlTdG9yZSk6IFByb21pc2U8RGV2aWNlSWRlbnRpdHk+IHtcbiAgLy8gMSkgUHJlZmVyIHBsdWdpbi1zY29wZWQgc3RvcmFnZSAoaW5qZWN0ZWQgYnkgbWFpbiBwbHVnaW4pLlxuICBpZiAoc3RvcmUpIHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgZXhpc3RpbmcgPSBhd2FpdCBzdG9yZS5nZXQoKTtcbiAgICAgIGlmIChleGlzdGluZz8uaWQgJiYgZXhpc3Rpbmc/LnB1YmxpY0tleSAmJiBleGlzdGluZz8ucHJpdmF0ZUtleUp3aykgcmV0dXJuIGV4aXN0aW5nO1xuICAgIH0gY2F0Y2gge1xuICAgICAgLy8gaWdub3JlIGFuZCBjb250aW51ZSAod2UgY2FuIGFsd2F5cyByZS1nZW5lcmF0ZSlcbiAgICB9XG4gIH1cblxuICAvLyAyKSBPbmUtdGltZSBtaWdyYXRpb246IGxlZ2FjeSBsb2NhbFN0b3JhZ2UgaWRlbnRpdHkuXG4gIC8vIE5PVEU6IHRoaXMgcmVtYWlucyBhIHJpc2sgYm91bmRhcnk7IHdlIG9ubHkgcmVhZCtkZWxldGUgZm9yIG1pZ3JhdGlvbi5cbiAgY29uc3QgbGVnYWN5ID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oREVWSUNFX1NUT1JBR0VfS0VZKTtcbiAgaWYgKGxlZ2FjeSkge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCBwYXJzZWQgPSBKU09OLnBhcnNlKGxlZ2FjeSkgYXMgRGV2aWNlSWRlbnRpdHk7XG4gICAgICBpZiAocGFyc2VkPy5pZCAmJiBwYXJzZWQ/LnB1YmxpY0tleSAmJiBwYXJzZWQ/LnByaXZhdGVLZXlKd2spIHtcbiAgICAgICAgaWYgKHN0b3JlKSB7XG4gICAgICAgICAgYXdhaXQgc3RvcmUuc2V0KHBhcnNlZCk7XG4gICAgICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oREVWSUNFX1NUT1JBR0VfS0VZKTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gcGFyc2VkO1xuICAgICAgfVxuICAgIH0gY2F0Y2gge1xuICAgICAgLy8gQ29ycnVwdC9wYXJ0aWFsIGRhdGEgXHUyMTkyIGRlbGV0ZSBhbmQgcmUtY3JlYXRlLlxuICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oREVWSUNFX1NUT1JBR0VfS0VZKTtcbiAgICB9XG4gIH1cblxuICAvLyAzKSBDcmVhdGUgYSBuZXcgaWRlbnRpdHkuXG4gIGNvbnN0IGtleVBhaXIgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmdlbmVyYXRlS2V5KHsgbmFtZTogJ0VkMjU1MTknIH0sIHRydWUsIFsnc2lnbicsICd2ZXJpZnknXSk7XG4gIGNvbnN0IHB1YlJhdyA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuZXhwb3J0S2V5KCdyYXcnLCBrZXlQYWlyLnB1YmxpY0tleSk7XG4gIGNvbnN0IHByaXZKd2sgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmV4cG9ydEtleSgnandrJywga2V5UGFpci5wcml2YXRlS2V5KTtcblxuICAvLyBJTVBPUlRBTlQ6IGRldmljZS5pZCBtdXN0IGJlIGEgc3RhYmxlIGZpbmdlcnByaW50IGZvciB0aGUgcHVibGljIGtleS5cbiAgLy8gVGhlIGdhdGV3YXkgZW5mb3JjZXMgZGV2aWNlSWQgXHUyMTk0IHB1YmxpY0tleSBiaW5kaW5nOyByYW5kb20gaWRzIGNhbiBjYXVzZSBcImRldmljZSBpZGVudGl0eSBtaXNtYXRjaFwiLlxuICBjb25zdCBkZXZpY2VJZCA9IGF3YWl0IHNoYTI1NkhleChwdWJSYXcpO1xuXG4gIGNvbnN0IGlkZW50aXR5OiBEZXZpY2VJZGVudGl0eSA9IHtcbiAgICBpZDogZGV2aWNlSWQsXG4gICAgcHVibGljS2V5OiBiYXNlNjRVcmxFbmNvZGUocHViUmF3KSxcbiAgICBwcml2YXRlS2V5SndrOiBwcml2SndrLFxuICB9O1xuXG4gIGlmIChzdG9yZSkge1xuICAgIGF3YWl0IHN0b3JlLnNldChpZGVudGl0eSk7XG4gIH0gZWxzZSB7XG4gICAgLy8gRmFsbGJhY2sgKHNob3VsZCBub3QgaGFwcGVuIGluIHJlYWwgcGx1Z2luIHJ1bnRpbWUpIFx1MjAxNCBrZWVwIGxlZ2FjeSBiZWhhdmlvci5cbiAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbShERVZJQ0VfU1RPUkFHRV9LRVksIEpTT04uc3RyaW5naWZ5KGlkZW50aXR5KSk7XG4gIH1cblxuICByZXR1cm4gaWRlbnRpdHk7XG59XG5cbmZ1bmN0aW9uIGJ1aWxkRGV2aWNlQXV0aFBheWxvYWQocGFyYW1zOiB7XG4gIGRldmljZUlkOiBzdHJpbmc7XG4gIGNsaWVudElkOiBzdHJpbmc7XG4gIGNsaWVudE1vZGU6IHN0cmluZztcbiAgcm9sZTogc3RyaW5nO1xuICBzY29wZXM6IHN0cmluZ1tdO1xuICBzaWduZWRBdE1zOiBudW1iZXI7XG4gIHRva2VuOiBzdHJpbmc7XG4gIG5vbmNlPzogc3RyaW5nO1xufSk6IHN0cmluZyB7XG4gIGNvbnN0IHZlcnNpb24gPSBwYXJhbXMubm9uY2UgPyAndjInIDogJ3YxJztcbiAgY29uc3Qgc2NvcGVzID0gcGFyYW1zLnNjb3Blcy5qb2luKCcsJyk7XG4gIGNvbnN0IGJhc2UgPSBbXG4gICAgdmVyc2lvbixcbiAgICBwYXJhbXMuZGV2aWNlSWQsXG4gICAgcGFyYW1zLmNsaWVudElkLFxuICAgIHBhcmFtcy5jbGllbnRNb2RlLFxuICAgIHBhcmFtcy5yb2xlLFxuICAgIHNjb3BlcyxcbiAgICBTdHJpbmcocGFyYW1zLnNpZ25lZEF0TXMpLFxuICAgIHBhcmFtcy50b2tlbiB8fCAnJyxcbiAgXTtcbiAgaWYgKHZlcnNpb24gPT09ICd2MicpIGJhc2UucHVzaChwYXJhbXMubm9uY2UgfHwgJycpO1xuICByZXR1cm4gYmFzZS5qb2luKCd8Jyk7XG59XG5cbmFzeW5jIGZ1bmN0aW9uIHNpZ25EZXZpY2VQYXlsb2FkKGlkZW50aXR5OiBEZXZpY2VJZGVudGl0eSwgcGF5bG9hZDogc3RyaW5nKTogUHJvbWlzZTx7IHNpZ25hdHVyZTogc3RyaW5nIH0+IHtcbiAgY29uc3QgcHJpdmF0ZUtleSA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KFxuICAgICdqd2snLFxuICAgIGlkZW50aXR5LnByaXZhdGVLZXlKd2ssXG4gICAgeyBuYW1lOiAnRWQyNTUxOScgfSxcbiAgICBmYWxzZSxcbiAgICBbJ3NpZ24nXSxcbiAgKTtcblxuICBjb25zdCBzaWcgPSBhd2FpdCBjcnlwdG8uc3VidGxlLnNpZ24oeyBuYW1lOiAnRWQyNTUxOScgfSwgcHJpdmF0ZUtleSwgdXRmOEJ5dGVzKHBheWxvYWQpIGFzIHVua25vd24gYXMgQnVmZmVyU291cmNlKTtcbiAgcmV0dXJuIHsgc2lnbmF0dXJlOiBiYXNlNjRVcmxFbmNvZGUoc2lnKSB9O1xufVxuXG5mdW5jdGlvbiBleHRyYWN0VGV4dEZyb21HYXRld2F5TWVzc2FnZShtc2c6IGFueSk6IHN0cmluZyB7XG4gIGlmICghbXNnKSByZXR1cm4gJyc7XG5cbiAgLy8gTW9zdCBjb21tb246IHsgcm9sZSwgY29udGVudCB9IHdoZXJlIGNvbnRlbnQgY2FuIGJlIHN0cmluZyBvciBbe3R5cGU6J3RleHQnLHRleHQ6Jy4uLid9XVxuICBjb25zdCBjb250ZW50ID0gbXNnLmNvbnRlbnQgPz8gbXNnLm1lc3NhZ2UgPz8gbXNnO1xuICBpZiAodHlwZW9mIGNvbnRlbnQgPT09ICdzdHJpbmcnKSByZXR1cm4gY29udGVudDtcblxuICBpZiAoQXJyYXkuaXNBcnJheShjb250ZW50KSkge1xuICAgIGNvbnN0IHBhcnRzID0gY29udGVudFxuICAgICAgLmZpbHRlcigoYykgPT4gYyAmJiB0eXBlb2YgYyA9PT0gJ29iamVjdCcgJiYgYy50eXBlID09PSAndGV4dCcgJiYgdHlwZW9mIGMudGV4dCA9PT0gJ3N0cmluZycpXG4gICAgICAubWFwKChjKSA9PiBjLnRleHQpO1xuICAgIHJldHVybiBwYXJ0cy5qb2luKCdcXG4nKTtcbiAgfVxuXG4gIC8vIEZhbGxiYWNrXG4gIHRyeSB7XG4gICAgcmV0dXJuIEpTT04uc3RyaW5naWZ5KGNvbnRlbnQpO1xuICB9IGNhdGNoIHtcbiAgICByZXR1cm4gU3RyaW5nKGNvbnRlbnQpO1xuICB9XG59XG5cbmZ1bmN0aW9uIHNlc3Npb25LZXlNYXRjaGVzKGNvbmZpZ3VyZWQ6IHN0cmluZywgaW5jb21pbmc6IHN0cmluZyk6IGJvb2xlYW4ge1xuICBpZiAoaW5jb21pbmcgPT09IGNvbmZpZ3VyZWQpIHJldHVybiB0cnVlO1xuICAvLyBPcGVuQ2xhdyByZXNvbHZlcyBcIm1haW5cIiB0byBjYW5vbmljYWwgc2Vzc2lvbiBrZXkgbGlrZSBcImFnZW50Om1haW46bWFpblwiLlxuICBpZiAoY29uZmlndXJlZCA9PT0gJ21haW4nICYmIGluY29taW5nID09PSAnYWdlbnQ6bWFpbjptYWluJykgcmV0dXJuIHRydWU7XG4gIHJldHVybiBmYWxzZTtcbn1cblxuZXhwb3J0IGNsYXNzIE9ic2lkaWFuV1NDbGllbnQge1xuICBwcml2YXRlIHdzOiBXZWJTb2NrZXQgfCBudWxsID0gbnVsbDtcbiAgcHJpdmF0ZSByZWNvbm5lY3RUaW1lcjogUmV0dXJuVHlwZTx0eXBlb2Ygc2V0VGltZW91dD4gfCBudWxsID0gbnVsbDtcbiAgcHJpdmF0ZSBoZWFydGJlYXRUaW1lcjogUmV0dXJuVHlwZTx0eXBlb2Ygc2V0SW50ZXJ2YWw+IHwgbnVsbCA9IG51bGw7XG4gIHByaXZhdGUgd29ya2luZ1RpbWVyOiBSZXR1cm5UeXBlPHR5cGVvZiBzZXRUaW1lb3V0PiB8IG51bGwgPSBudWxsO1xuICBwcml2YXRlIGludGVudGlvbmFsQ2xvc2UgPSBmYWxzZTtcbiAgcHJpdmF0ZSBzZXNzaW9uS2V5OiBzdHJpbmc7XG4gIHByaXZhdGUgdXJsID0gJyc7XG4gIHByaXZhdGUgdG9rZW4gPSAnJztcbiAgcHJpdmF0ZSByZXF1ZXN0SWQgPSAwO1xuICBwcml2YXRlIHBlbmRpbmdSZXF1ZXN0cyA9IG5ldyBNYXA8c3RyaW5nLCBQZW5kaW5nUmVxdWVzdD4oKTtcbiAgcHJpdmF0ZSB3b3JraW5nID0gZmFsc2U7XG5cbiAgLyoqIFRoZSBsYXN0IGluLWZsaWdodCBjaGF0IHJ1biBpZC4gSW4gT3BlbkNsYXcgV2ViQ2hhdCB0aGlzIG1hcHMgdG8gY2hhdC5zZW5kIGlkZW1wb3RlbmN5S2V5LiAqL1xuICBwcml2YXRlIGFjdGl2ZVJ1bklkOiBzdHJpbmcgfCBudWxsID0gbnVsbDtcblxuICAvKiogUHJldmVudHMgYWJvcnQgc3BhbW1pbmc6IHdoaWxlIGFuIGFib3J0IHJlcXVlc3QgaXMgaW4tZmxpZ2h0LCByZXVzZSB0aGUgc2FtZSBwcm9taXNlLiAqL1xuICBwcml2YXRlIGFib3J0SW5GbGlnaHQ6IFByb21pc2U8Ym9vbGVhbj4gfCBudWxsID0gbnVsbDtcblxuICBzdGF0ZTogV1NDbGllbnRTdGF0ZSA9ICdkaXNjb25uZWN0ZWQnO1xuXG4gIG9uTWVzc2FnZTogKChtc2c6IEluYm91bmRXU1BheWxvYWQpID0+IHZvaWQpIHwgbnVsbCA9IG51bGw7XG4gIG9uU3RhdGVDaGFuZ2U6ICgoc3RhdGU6IFdTQ2xpZW50U3RhdGUpID0+IHZvaWQpIHwgbnVsbCA9IG51bGw7XG4gIG9uV29ya2luZ0NoYW5nZTogV29ya2luZ1N0YXRlTGlzdGVuZXIgfCBudWxsID0gbnVsbDtcblxuICBwcml2YXRlIGlkZW50aXR5U3RvcmU6IERldmljZUlkZW50aXR5U3RvcmUgfCB1bmRlZmluZWQ7XG4gIHByaXZhdGUgYWxsb3dJbnNlY3VyZVdzID0gZmFsc2U7XG5cbiAgcHJpdmF0ZSByZWNvbm5lY3RBdHRlbXB0ID0gMDtcblxuICBjb25zdHJ1Y3RvcihzZXNzaW9uS2V5OiBzdHJpbmcsIG9wdHM/OiB7IGlkZW50aXR5U3RvcmU/OiBEZXZpY2VJZGVudGl0eVN0b3JlOyBhbGxvd0luc2VjdXJlV3M/OiBib29sZWFuIH0pIHtcbiAgICB0aGlzLnNlc3Npb25LZXkgPSBzZXNzaW9uS2V5O1xuICAgIHRoaXMuaWRlbnRpdHlTdG9yZSA9IG9wdHM/LmlkZW50aXR5U3RvcmU7XG4gICAgdGhpcy5hbGxvd0luc2VjdXJlV3MgPSBCb29sZWFuKG9wdHM/LmFsbG93SW5zZWN1cmVXcyk7XG4gIH1cblxuICBjb25uZWN0KHVybDogc3RyaW5nLCB0b2tlbjogc3RyaW5nLCBvcHRzPzogeyBhbGxvd0luc2VjdXJlV3M/OiBib29sZWFuIH0pOiB2b2lkIHtcbiAgICB0aGlzLnVybCA9IHVybDtcbiAgICB0aGlzLnRva2VuID0gdG9rZW47XG4gICAgdGhpcy5hbGxvd0luc2VjdXJlV3MgPSBCb29sZWFuKG9wdHM/LmFsbG93SW5zZWN1cmVXcyA/PyB0aGlzLmFsbG93SW5zZWN1cmVXcyk7XG4gICAgdGhpcy5pbnRlbnRpb25hbENsb3NlID0gZmFsc2U7XG5cbiAgICAvLyBTZWN1cml0eTogYmxvY2sgbm9uLWxvY2FsIHdzOi8vIHVubGVzcyBleHBsaWNpdGx5IGFsbG93ZWQuXG4gICAgY29uc3QgcGFyc2VkID0gc2FmZVBhcnNlV3NVcmwodXJsKTtcbiAgICBpZiAoIXBhcnNlZC5vaykge1xuICAgICAgdGhpcy5vbk1lc3NhZ2U/Lih7IHR5cGU6ICdlcnJvcicsIHBheWxvYWQ6IHsgbWVzc2FnZTogcGFyc2VkLmVycm9yIH0gfSk7XG4gICAgICByZXR1cm47XG4gICAgfVxuICAgIGlmIChwYXJzZWQuc2NoZW1lID09PSAnd3MnICYmICFpc0xvY2FsSG9zdChwYXJzZWQuaG9zdCkgJiYgIXRoaXMuYWxsb3dJbnNlY3VyZVdzKSB7XG4gICAgICB0aGlzLm9uTWVzc2FnZT8uKHtcbiAgICAgICAgdHlwZTogJ2Vycm9yJyxcbiAgICAgICAgcGF5bG9hZDogeyBtZXNzYWdlOiAnUmVmdXNpbmcgaW5zZWN1cmUgd3M6Ly8gdG8gbm9uLWxvY2FsIGdhdGV3YXkuIFVzZSB3c3M6Ly8gb3IgZW5hYmxlIHRoZSB1bnNhZmUgb3ZlcnJpZGUgaW4gc2V0dGluZ3MuJyB9LFxuICAgICAgfSk7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgdGhpcy5fY29ubmVjdCgpO1xuICB9XG5cbiAgZGlzY29ubmVjdCgpOiB2b2lkIHtcbiAgICB0aGlzLmludGVudGlvbmFsQ2xvc2UgPSB0cnVlO1xuICAgIHRoaXMuX3N0b3BUaW1lcnMoKTtcbiAgICB0aGlzLmFjdGl2ZVJ1bklkID0gbnVsbDtcbiAgICB0aGlzLmFib3J0SW5GbGlnaHQgPSBudWxsO1xuICAgIHRoaXMuX3NldFdvcmtpbmcoZmFsc2UpO1xuICAgIGlmICh0aGlzLndzKSB7XG4gICAgICB0aGlzLndzLmNsb3NlKCk7XG4gICAgICB0aGlzLndzID0gbnVsbDtcbiAgICB9XG4gICAgdGhpcy5fc2V0U3RhdGUoJ2Rpc2Nvbm5lY3RlZCcpO1xuICB9XG5cbiAgYXN5bmMgc2VuZE1lc3NhZ2UobWVzc2FnZTogc3RyaW5nKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgaWYgKHRoaXMuc3RhdGUgIT09ICdjb25uZWN0ZWQnKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ05vdCBjb25uZWN0ZWQgXHUyMDE0IGNhbGwgY29ubmVjdCgpIGZpcnN0Jyk7XG4gICAgfVxuXG4gICAgY29uc3QgcnVuSWQgPSBgb2JzaWRpYW4tJHtEYXRlLm5vdygpfS0ke01hdGgucmFuZG9tKCkudG9TdHJpbmcoMzYpLnNsaWNlKDIsIDkpfWA7XG5cbiAgICAvLyBTaG93IFx1MjAxQ3dvcmtpbmdcdTIwMUQgT05MWSBhZnRlciB0aGUgZ2F0ZXdheSBhY2tub3dsZWRnZXMgdGhlIHJlcXVlc3QuXG4gICAgY29uc3QgYWNrID0gYXdhaXQgdGhpcy5fc2VuZFJlcXVlc3QoJ2NoYXQuc2VuZCcsIHtcbiAgICAgIHNlc3Npb25LZXk6IHRoaXMuc2Vzc2lvbktleSxcbiAgICAgIG1lc3NhZ2UsXG4gICAgICBpZGVtcG90ZW5jeUtleTogcnVuSWQsXG4gICAgICAvLyBkZWxpdmVyIGRlZmF1bHRzIHRvIHRydWUgaW4gZ2F0ZXdheTsga2VlcCBkZWZhdWx0XG4gICAgfSk7XG5cbiAgICAvLyBJZiB0aGUgZ2F0ZXdheSByZXR1cm5zIGEgY2Fub25pY2FsIHJ1biBpZGVudGlmaWVyLCBwcmVmZXIgaXQuXG4gICAgY29uc3QgY2Fub25pY2FsUnVuSWQgPSBTdHJpbmcoYWNrPy5ydW5JZCB8fCBhY2s/LmlkZW1wb3RlbmN5S2V5IHx8ICcnKTtcbiAgICB0aGlzLmFjdGl2ZVJ1bklkID0gY2Fub25pY2FsUnVuSWQgfHwgcnVuSWQ7XG4gICAgdGhpcy5fc2V0V29ya2luZyh0cnVlKTtcbiAgICB0aGlzLl9hcm1Xb3JraW5nU2FmZXR5VGltZW91dCgpO1xuICB9XG5cbiAgLyoqIEFib3J0IHRoZSBhY3RpdmUgcnVuIGZvciB0aGlzIHNlc3Npb24gKGFuZCBvdXIgbGFzdCBydW4gaWQgaWYgcHJlc2VudCkuICovXG4gIGFzeW5jIGFib3J0QWN0aXZlUnVuKCk6IFByb21pc2U8Ym9vbGVhbj4ge1xuICAgIGlmICh0aGlzLnN0YXRlICE9PSAnY29ubmVjdGVkJykge1xuICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH1cblxuICAgIC8vIFByZXZlbnQgcmVxdWVzdCBzdG9ybXM6IHdoaWxlIG9uZSBhYm9ydCBpcyBpbiBmbGlnaHQsIHJldXNlIGl0LlxuICAgIGlmICh0aGlzLmFib3J0SW5GbGlnaHQpIHtcbiAgICAgIHJldHVybiB0aGlzLmFib3J0SW5GbGlnaHQ7XG4gICAgfVxuXG4gICAgY29uc3QgcnVuSWQgPSB0aGlzLmFjdGl2ZVJ1bklkO1xuICAgIGlmICghcnVuSWQpIHtcbiAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG5cbiAgICB0aGlzLmFib3J0SW5GbGlnaHQgPSAoYXN5bmMgKCkgPT4ge1xuICAgICAgdHJ5IHtcbiAgICAgICAgYXdhaXQgdGhpcy5fc2VuZFJlcXVlc3QoJ2NoYXQuYWJvcnQnLCB7IHNlc3Npb25LZXk6IHRoaXMuc2Vzc2lvbktleSwgcnVuSWQgfSk7XG4gICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgfSBjYXRjaCAoZXJyKSB7XG4gICAgICAgIGNvbnNvbGUuZXJyb3IoJ1tvY2xhdy13c10gY2hhdC5hYm9ydCBmYWlsZWQnLCBlcnIpO1xuICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICB9IGZpbmFsbHkge1xuICAgICAgICAvLyBBbHdheXMgcmVzdG9yZSBVSSBzdGF0ZSBpbW1lZGlhdGVseTsgdGhlIGdhdGV3YXkgbWF5IHN0aWxsIGVtaXQgYW4gYWJvcnRlZCBldmVudCBsYXRlci5cbiAgICAgICAgdGhpcy5hY3RpdmVSdW5JZCA9IG51bGw7XG4gICAgICAgIHRoaXMuX3NldFdvcmtpbmcoZmFsc2UpO1xuICAgICAgICB0aGlzLmFib3J0SW5GbGlnaHQgPSBudWxsO1xuICAgICAgfVxuICAgIH0pKCk7XG5cbiAgICByZXR1cm4gdGhpcy5hYm9ydEluRmxpZ2h0O1xuICB9XG5cbiAgcHJpdmF0ZSBfY29ubmVjdCgpOiB2b2lkIHtcbiAgICBpZiAodGhpcy53cykge1xuICAgICAgdGhpcy53cy5vbm9wZW4gPSBudWxsO1xuICAgICAgdGhpcy53cy5vbmNsb3NlID0gbnVsbDtcbiAgICAgIHRoaXMud3Mub25tZXNzYWdlID0gbnVsbDtcbiAgICAgIHRoaXMud3Mub25lcnJvciA9IG51bGw7XG4gICAgICB0aGlzLndzLmNsb3NlKCk7XG4gICAgICB0aGlzLndzID0gbnVsbDtcbiAgICB9XG5cbiAgICB0aGlzLl9zZXRTdGF0ZSgnY29ubmVjdGluZycpO1xuXG4gICAgY29uc3Qgd3MgPSBuZXcgV2ViU29ja2V0KHRoaXMudXJsKTtcbiAgICB0aGlzLndzID0gd3M7XG5cbiAgICBsZXQgY29ubmVjdE5vbmNlOiBzdHJpbmcgfCBudWxsID0gbnVsbDtcbiAgICBsZXQgY29ubmVjdFN0YXJ0ZWQgPSBmYWxzZTtcblxuICAgIGNvbnN0IHRyeUNvbm5lY3QgPSBhc3luYyAoKSA9PiB7XG4gICAgICBpZiAoY29ubmVjdFN0YXJ0ZWQpIHJldHVybjtcbiAgICAgIGlmICghY29ubmVjdE5vbmNlKSByZXR1cm47XG4gICAgICBjb25uZWN0U3RhcnRlZCA9IHRydWU7XG5cbiAgICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IGlkZW50aXR5ID0gYXdhaXQgbG9hZE9yQ3JlYXRlRGV2aWNlSWRlbnRpdHkodGhpcy5pZGVudGl0eVN0b3JlKTtcbiAgICAgICAgY29uc3Qgc2lnbmVkQXRNcyA9IERhdGUubm93KCk7XG4gICAgICAgIGNvbnN0IHBheWxvYWQgPSBidWlsZERldmljZUF1dGhQYXlsb2FkKHtcbiAgICAgICAgICBkZXZpY2VJZDogaWRlbnRpdHkuaWQsXG4gICAgICAgICAgY2xpZW50SWQ6ICdnYXRld2F5LWNsaWVudCcsXG4gICAgICAgICAgY2xpZW50TW9kZTogJ2JhY2tlbmQnLFxuICAgICAgICAgIHJvbGU6ICdvcGVyYXRvcicsXG4gICAgICAgICAgc2NvcGVzOiBbJ29wZXJhdG9yLnJlYWQnLCAnb3BlcmF0b3Iud3JpdGUnXSxcbiAgICAgICAgICBzaWduZWRBdE1zLFxuICAgICAgICAgIHRva2VuOiB0aGlzLnRva2VuLFxuICAgICAgICAgIG5vbmNlOiBjb25uZWN0Tm9uY2UsXG4gICAgICAgIH0pO1xuICAgICAgICBjb25zdCBzaWcgPSBhd2FpdCBzaWduRGV2aWNlUGF5bG9hZChpZGVudGl0eSwgcGF5bG9hZCk7XG5cbiAgICAgICAgY29uc3QgYWNrID0gYXdhaXQgdGhpcy5fc2VuZFJlcXVlc3QoJ2Nvbm5lY3QnLCB7XG4gICAgICAgICAgIG1pblByb3RvY29sOiAzLFxuICAgICAgICAgICBtYXhQcm90b2NvbDogMyxcbiAgICAgICAgICAgY2xpZW50OiB7XG4gICAgICAgICAgICAgaWQ6ICdnYXRld2F5LWNsaWVudCcsXG4gICAgICAgICAgICAgbW9kZTogJ2JhY2tlbmQnLFxuICAgICAgICAgICAgIHZlcnNpb246ICcwLjEuMTAnLFxuICAgICAgICAgICAgIHBsYXRmb3JtOiAnZWxlY3Ryb24nLFxuICAgICAgICAgICB9LFxuICAgICAgICAgICByb2xlOiAnb3BlcmF0b3InLFxuICAgICAgICAgICBzY29wZXM6IFsnb3BlcmF0b3IucmVhZCcsICdvcGVyYXRvci53cml0ZSddLFxuICAgICAgICAgICBkZXZpY2U6IHtcbiAgICAgICAgICAgICBpZDogaWRlbnRpdHkuaWQsXG4gICAgICAgICAgICAgcHVibGljS2V5OiBpZGVudGl0eS5wdWJsaWNLZXksXG4gICAgICAgICAgICAgc2lnbmF0dXJlOiBzaWcuc2lnbmF0dXJlLFxuICAgICAgICAgICAgIHNpZ25lZEF0OiBzaWduZWRBdE1zLFxuICAgICAgICAgICAgIG5vbmNlOiBjb25uZWN0Tm9uY2UsXG4gICAgICAgICAgIH0sXG4gICAgICAgICAgIGF1dGg6IHtcbiAgICAgICAgICAgICB0b2tlbjogdGhpcy50b2tlbixcbiAgICAgICAgICAgfSxcbiAgICAgICAgIH0pO1xuXG4gICAgICAgICB0aGlzLl9zZXRTdGF0ZSgnY29ubmVjdGVkJyk7XG4gICAgICAgICB0aGlzLnJlY29ubmVjdEF0dGVtcHQgPSAwO1xuICAgICAgICAgaWYgKGhhbmRzaGFrZVRpbWVyKSB7XG4gICAgICAgICAgIGNsZWFyVGltZW91dChoYW5kc2hha2VUaW1lcik7XG4gICAgICAgICAgIGhhbmRzaGFrZVRpbWVyID0gbnVsbDtcbiAgICAgICAgIH1cbiAgICAgICAgIHRoaXMuX3N0YXJ0SGVhcnRiZWF0KCk7XG4gICAgICB9IGNhdGNoIChlcnIpIHtcbiAgICAgICAgY29uc29sZS5lcnJvcignW29jbGF3LXdzXSBDb25uZWN0IGhhbmRzaGFrZSBmYWlsZWQnLCBlcnIpO1xuICAgICAgICB3cy5jbG9zZSgpO1xuICAgICAgfVxuICAgIH07XG5cbiAgICBsZXQgaGFuZHNoYWtlVGltZXI6IFJldHVyblR5cGU8dHlwZW9mIHNldFRpbWVvdXQ+IHwgbnVsbCA9IG51bGw7XG5cbiAgICB3cy5vbm9wZW4gPSAoKSA9PiB7XG4gICAgICB0aGlzLl9zZXRTdGF0ZSgnaGFuZHNoYWtpbmcnKTtcbiAgICAgIC8vIFRoZSBnYXRld2F5IHdpbGwgc2VuZCBjb25uZWN0LmNoYWxsZW5nZTsgY29ubmVjdCBpcyBzZW50IG9uY2Ugd2UgaGF2ZSBhIG5vbmNlLlxuICAgICAgaWYgKGhhbmRzaGFrZVRpbWVyKSBjbGVhclRpbWVvdXQoaGFuZHNoYWtlVGltZXIpO1xuICAgICAgaGFuZHNoYWtlVGltZXIgPSBzZXRUaW1lb3V0KCgpID0+IHtcbiAgICAgICAgLy8gSWYgd2UgbmV2ZXIgZ290IHRoZSBjaGFsbGVuZ2Ugbm9uY2UsIGZvcmNlIHJlY29ubmVjdC5cbiAgICAgICAgaWYgKHRoaXMuc3RhdGUgPT09ICdoYW5kc2hha2luZycgJiYgIXRoaXMuaW50ZW50aW9uYWxDbG9zZSkge1xuICAgICAgICAgIGNvbnNvbGUud2FybignW29jbGF3LXdzXSBIYW5kc2hha2UgdGltZWQgb3V0IHdhaXRpbmcgZm9yIGNvbm5lY3QuY2hhbGxlbmdlJyk7XG4gICAgICAgICAgd3MuY2xvc2UoKTtcbiAgICAgICAgfVxuICAgICAgfSwgSEFORFNIQUtFX1RJTUVPVVRfTVMpO1xuICAgIH07XG5cbiAgICB3cy5vbm1lc3NhZ2UgPSAoZXZlbnQ6IE1lc3NhZ2VFdmVudCkgPT4ge1xuICAgICAgLy8gRG9TIGd1YXJkOiByZWZ1c2UgaHVnZSBmcmFtZXMuXG4gICAgICBpZiAodHlwZW9mIGV2ZW50LmRhdGEgPT09ICdzdHJpbmcnICYmIGV2ZW50LmRhdGEubGVuZ3RoID4gTUFYX0lOQk9VTkRfRlJBTUVfQllURVMpIHtcbiAgICAgICAgY29uc29sZS5lcnJvcignW29jbGF3LXdzXSBJbmJvdW5kIGZyYW1lIHRvbyBsYXJnZTsgY2xvc2luZyBjb25uZWN0aW9uJyk7XG4gICAgICAgIHdzLmNsb3NlKCk7XG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cblxuICAgICAgbGV0IGZyYW1lOiBhbnk7XG4gICAgICB0cnkge1xuICAgICAgICBmcmFtZSA9IEpTT04ucGFyc2UoZXZlbnQuZGF0YSBhcyBzdHJpbmcpO1xuICAgICAgfSBjYXRjaCB7XG4gICAgICAgIGNvbnNvbGUuZXJyb3IoJ1tvY2xhdy13c10gRmFpbGVkIHRvIHBhcnNlIGluY29taW5nIG1lc3NhZ2UnKTtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuXG4gICAgICAvLyBSZXNwb25zZXNcbiAgICAgIGlmIChmcmFtZS50eXBlID09PSAncmVzJykge1xuICAgICAgICB0aGlzLl9oYW5kbGVSZXNwb25zZUZyYW1lKGZyYW1lKTtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuXG4gICAgICAvLyBFdmVudHNcbiAgICAgIGlmIChmcmFtZS50eXBlID09PSAnZXZlbnQnKSB7XG4gICAgICAgIGlmIChmcmFtZS5ldmVudCA9PT0gJ2Nvbm5lY3QuY2hhbGxlbmdlJykge1xuICAgICAgICAgIGNvbm5lY3ROb25jZSA9IGZyYW1lLnBheWxvYWQ/Lm5vbmNlIHx8IG51bGw7XG4gICAgICAgICAgLy8gQXR0ZW1wdCBoYW5kc2hha2Ugb25jZSB3ZSBoYXZlIGEgbm9uY2UuXG4gICAgICAgICAgdm9pZCB0cnlDb25uZWN0KCk7XG4gICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKGZyYW1lLmV2ZW50ID09PSAnY2hhdCcpIHtcbiAgICAgICAgICB0aGlzLl9oYW5kbGVDaGF0RXZlbnRGcmFtZShmcmFtZSk7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuXG4gICAgICAvLyBBdm9pZCBsb2dnaW5nIGZ1bGwgZnJhbWVzIChtYXkgaW5jbHVkZSBtZXNzYWdlIGNvbnRlbnQgb3Igb3RoZXIgc2Vuc2l0aXZlIHBheWxvYWRzKS5cbiAgICAgIGNvbnNvbGUuZGVidWcoJ1tvY2xhdy13c10gVW5oYW5kbGVkIGZyYW1lJywgeyB0eXBlOiBmcmFtZT8udHlwZSwgZXZlbnQ6IGZyYW1lPy5ldmVudCwgaWQ6IGZyYW1lPy5pZCB9KTtcbiAgICB9O1xuXG4gICAgd3Mub25jbG9zZSA9ICgpID0+IHtcbiAgICAgIHRoaXMuX3N0b3BUaW1lcnMoKTtcbiAgICAgIHRoaXMuYWN0aXZlUnVuSWQgPSBudWxsO1xuICAgICAgdGhpcy5hYm9ydEluRmxpZ2h0ID0gbnVsbDtcbiAgICAgIHRoaXMuX3NldFdvcmtpbmcoZmFsc2UpO1xuICAgICAgdGhpcy5fc2V0U3RhdGUoJ2Rpc2Nvbm5lY3RlZCcpO1xuXG4gICAgICBmb3IgKGNvbnN0IHBlbmRpbmcgb2YgdGhpcy5wZW5kaW5nUmVxdWVzdHMudmFsdWVzKCkpIHtcbiAgICAgICAgaWYgKHBlbmRpbmcudGltZW91dCkgY2xlYXJUaW1lb3V0KHBlbmRpbmcudGltZW91dCk7XG4gICAgICAgIHBlbmRpbmcucmVqZWN0KG5ldyBFcnJvcignQ29ubmVjdGlvbiBjbG9zZWQnKSk7XG4gICAgICB9XG4gICAgICB0aGlzLnBlbmRpbmdSZXF1ZXN0cy5jbGVhcigpO1xuXG4gICAgICBpZiAoIXRoaXMuaW50ZW50aW9uYWxDbG9zZSkge1xuICAgICAgICB0aGlzLl9zY2hlZHVsZVJlY29ubmVjdCgpO1xuICAgICAgfVxuICAgIH07XG5cbiAgICB3cy5vbmVycm9yID0gKGV2OiBFdmVudCkgPT4ge1xuICAgICAgY29uc29sZS5lcnJvcignW29jbGF3LXdzXSBXZWJTb2NrZXQgZXJyb3InLCBldik7XG4gICAgfTtcbiAgfVxuXG4gIHByaXZhdGUgX2hhbmRsZVJlc3BvbnNlRnJhbWUoZnJhbWU6IGFueSk6IHZvaWQge1xuICAgIGNvbnN0IHBlbmRpbmcgPSB0aGlzLnBlbmRpbmdSZXF1ZXN0cy5nZXQoZnJhbWUuaWQpO1xuICAgIGlmICghcGVuZGluZykgcmV0dXJuO1xuXG4gICAgdGhpcy5wZW5kaW5nUmVxdWVzdHMuZGVsZXRlKGZyYW1lLmlkKTtcbiAgICBpZiAocGVuZGluZy50aW1lb3V0KSBjbGVhclRpbWVvdXQocGVuZGluZy50aW1lb3V0KTtcblxuICAgIGlmIChmcmFtZS5vaykgcGVuZGluZy5yZXNvbHZlKGZyYW1lLnBheWxvYWQpO1xuICAgIGVsc2UgcGVuZGluZy5yZWplY3QobmV3IEVycm9yKGZyYW1lLmVycm9yPy5tZXNzYWdlIHx8ICdSZXF1ZXN0IGZhaWxlZCcpKTtcbiAgfVxuXG4gIHByaXZhdGUgX2hhbmRsZUNoYXRFdmVudEZyYW1lKGZyYW1lOiBhbnkpOiB2b2lkIHtcbiAgICBjb25zdCBwYXlsb2FkID0gZnJhbWUucGF5bG9hZDtcbiAgICBjb25zdCBpbmNvbWluZ1Nlc3Npb25LZXkgPSBTdHJpbmcocGF5bG9hZD8uc2Vzc2lvbktleSB8fCAnJyk7XG4gICAgaWYgKCFpbmNvbWluZ1Nlc3Npb25LZXkgfHwgIXNlc3Npb25LZXlNYXRjaGVzKHRoaXMuc2Vzc2lvbktleSwgaW5jb21pbmdTZXNzaW9uS2V5KSkge1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIC8vIEJlc3QtZWZmb3J0IHJ1biBjb3JyZWxhdGlvbiAoaWYgZ2F0ZXdheSBpbmNsdWRlcyBhIHJ1biBpZCkuIFRoaXMgYXZvaWRzIGNsZWFyaW5nIG91ciBVSVxuICAgIC8vIGJhc2VkIG9uIGEgZGlmZmVyZW50IGNsaWVudCdzIHJ1biBpbiB0aGUgc2FtZSBzZXNzaW9uLlxuICAgIGNvbnN0IGluY29taW5nUnVuSWQgPSBTdHJpbmcocGF5bG9hZD8ucnVuSWQgfHwgcGF5bG9hZD8uaWRlbXBvdGVuY3lLZXkgfHwgcGF5bG9hZD8ubWV0YT8ucnVuSWQgfHwgJycpO1xuICAgIGlmICh0aGlzLmFjdGl2ZVJ1bklkICYmIGluY29taW5nUnVuSWQgJiYgaW5jb21pbmdSdW5JZCAhPT0gdGhpcy5hY3RpdmVSdW5JZCkge1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIC8vIEF2b2lkIGRvdWJsZS1yZW5kZXI6IGdhdGV3YXkgZW1pdHMgZGVsdGEgKyBmaW5hbCArIGFib3J0ZWQuIFJlbmRlciBvbmx5IGV4cGxpY2l0IGZpbmFsL2Fib3J0ZWQuXG4gICAgLy8gSWYgc3RhdGUgaXMgbWlzc2luZywgdHJlYXQgYXMgbm9uLXRlcm1pbmFsIChkbyBub3QgY2xlYXIgVUkgLyBkbyBub3QgcmVuZGVyKS5cbiAgICBpZiAoIXBheWxvYWQ/LnN0YXRlKSB7XG4gICAgICByZXR1cm47XG4gICAgfVxuICAgIGlmIChwYXlsb2FkLnN0YXRlICE9PSAnZmluYWwnICYmIHBheWxvYWQuc3RhdGUgIT09ICdhYm9ydGVkJykge1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIC8vIFdlIG9ubHkgYXBwZW5kIGFzc2lzdGFudCBvdXRwdXQgdG8gVUkuXG4gICAgY29uc3QgbXNnID0gcGF5bG9hZD8ubWVzc2FnZTtcbiAgICBjb25zdCByb2xlID0gbXNnPy5yb2xlID8/ICdhc3Npc3RhbnQnO1xuXG4gICAgLy8gQWJvcnRlZCBlbmRzIHRoZSBydW4gcmVnYXJkbGVzcyBvZiByb2xlL21lc3NhZ2UuXG4gICAgaWYgKHBheWxvYWQuc3RhdGUgPT09ICdhYm9ydGVkJykge1xuICAgICAgdGhpcy5hY3RpdmVSdW5JZCA9IG51bGw7XG4gICAgICB0aGlzLl9zZXRXb3JraW5nKGZhbHNlKTtcbiAgICAgIC8vIEFib3J0ZWQgbWF5IGhhdmUgbm8gYXNzaXN0YW50IG1lc3NhZ2U7IGlmIG5vbmUsIHN0b3AgaGVyZS5cbiAgICAgIGlmICghbXNnKSByZXR1cm47XG4gICAgICAvLyBJZiB0aGVyZSBpcyBhIG1lc3NhZ2UsIG9ubHkgYXBwZW5kIGFzc2lzdGFudCBvdXRwdXQuXG4gICAgICBpZiAocm9sZSAhPT0gJ2Fzc2lzdGFudCcpIHJldHVybjtcbiAgICB9XG5cbiAgICAvLyBGaW5hbCBzaG91bGQgb25seSBjb21wbGV0ZSB0aGUgcnVuIHdoZW4gdGhlIGFzc2lzdGFudCBjb21wbGV0ZXMuXG4gICAgaWYgKHBheWxvYWQuc3RhdGUgPT09ICdmaW5hbCcpIHtcbiAgICAgIGlmIChyb2xlICE9PSAnYXNzaXN0YW50JykgcmV0dXJuO1xuICAgICAgdGhpcy5hY3RpdmVSdW5JZCA9IG51bGw7XG4gICAgICB0aGlzLl9zZXRXb3JraW5nKGZhbHNlKTtcbiAgICB9XG5cbiAgICBjb25zdCB0ZXh0ID0gZXh0cmFjdFRleHRGcm9tR2F0ZXdheU1lc3NhZ2UobXNnKTtcbiAgICBpZiAoIXRleHQpIHJldHVybjtcblxuICAgIC8vIE9wdGlvbmFsOiBoaWRlIGhlYXJ0YmVhdCBhY2tzIChub2lzZSBpbiBVSSlcbiAgICBpZiAodGV4dC50cmltKCkgPT09ICdIRUFSVEJFQVRfT0snKSB7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgdGhpcy5vbk1lc3NhZ2U/Lih7XG4gICAgICB0eXBlOiAnbWVzc2FnZScsXG4gICAgICBwYXlsb2FkOiB7XG4gICAgICAgIGNvbnRlbnQ6IHRleHQsXG4gICAgICAgIHJvbGU6ICdhc3Npc3RhbnQnLFxuICAgICAgICB0aW1lc3RhbXA6IERhdGUubm93KCksXG4gICAgICB9LFxuICAgIH0pO1xuICB9XG5cbiAgcHJpdmF0ZSBfc2VuZFJlcXVlc3QobWV0aG9kOiBzdHJpbmcsIHBhcmFtczogYW55KTogUHJvbWlzZTxhbnk+IHtcbiAgICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgaWYgKCF0aGlzLndzIHx8IHRoaXMud3MucmVhZHlTdGF0ZSAhPT0gV2ViU29ja2V0Lk9QRU4pIHtcbiAgICAgICAgcmVqZWN0KG5ldyBFcnJvcignV2ViU29ja2V0IG5vdCBjb25uZWN0ZWQnKSk7XG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cblxuICAgICAgaWYgKHRoaXMucGVuZGluZ1JlcXVlc3RzLnNpemUgPj0gTUFYX1BFTkRJTkdfUkVRVUVTVFMpIHtcbiAgICAgICAgcmVqZWN0KG5ldyBFcnJvcihgVG9vIG1hbnkgaW4tZmxpZ2h0IHJlcXVlc3RzICgke3RoaXMucGVuZGluZ1JlcXVlc3RzLnNpemV9KWApKTtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuXG4gICAgICBjb25zdCBpZCA9IGByZXEtJHsrK3RoaXMucmVxdWVzdElkfWA7XG5cbiAgICAgIGNvbnN0IHBlbmRpbmc6IFBlbmRpbmdSZXF1ZXN0ID0geyByZXNvbHZlLCByZWplY3QsIHRpbWVvdXQ6IG51bGwgfTtcbiAgICAgIHRoaXMucGVuZGluZ1JlcXVlc3RzLnNldChpZCwgcGVuZGluZyk7XG5cbiAgICAgIGNvbnN0IHBheWxvYWQgPSBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHR5cGU6ICdyZXEnLFxuICAgICAgICBtZXRob2QsXG4gICAgICAgIGlkLFxuICAgICAgICBwYXJhbXMsXG4gICAgICB9KTtcblxuICAgICAgdHJ5IHtcbiAgICAgICAgdGhpcy53cy5zZW5kKHBheWxvYWQpO1xuICAgICAgfSBjYXRjaCAoZXJyKSB7XG4gICAgICAgIHRoaXMucGVuZGluZ1JlcXVlc3RzLmRlbGV0ZShpZCk7XG4gICAgICAgIHJlamVjdChlcnIpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG5cbiAgICAgIHBlbmRpbmcudGltZW91dCA9IHNldFRpbWVvdXQoKCkgPT4ge1xuICAgICAgICBpZiAodGhpcy5wZW5kaW5nUmVxdWVzdHMuaGFzKGlkKSkge1xuICAgICAgICAgIHRoaXMucGVuZGluZ1JlcXVlc3RzLmRlbGV0ZShpZCk7XG4gICAgICAgICAgcmVqZWN0KG5ldyBFcnJvcihgUmVxdWVzdCB0aW1lb3V0OiAke21ldGhvZH1gKSk7XG4gICAgICAgIH1cbiAgICAgIH0sIDMwXzAwMCk7XG4gICAgfSk7XG4gIH1cblxuICBwcml2YXRlIF9zY2hlZHVsZVJlY29ubmVjdCgpOiB2b2lkIHtcbiAgICBpZiAodGhpcy5yZWNvbm5lY3RUaW1lciAhPT0gbnVsbCkgcmV0dXJuO1xuXG4gICAgY29uc3QgYXR0ZW1wdCA9ICsrdGhpcy5yZWNvbm5lY3RBdHRlbXB0O1xuICAgIGNvbnN0IGV4cCA9IE1hdGgubWluKFJFQ09OTkVDVF9NQVhfTVMsIFJFQ09OTkVDVF9CQVNFX01TICogTWF0aC5wb3coMiwgYXR0ZW1wdCAtIDEpKTtcbiAgICAvLyBKaXR0ZXI6IDAuNXguLjEuNXhcbiAgICBjb25zdCBqaXR0ZXIgPSAwLjUgKyBNYXRoLnJhbmRvbSgpO1xuICAgIGNvbnN0IGRlbGF5ID0gTWF0aC5mbG9vcihleHAgKiBqaXR0ZXIpO1xuXG4gICAgdGhpcy5yZWNvbm5lY3RUaW1lciA9IHNldFRpbWVvdXQoKCkgPT4ge1xuICAgICAgdGhpcy5yZWNvbm5lY3RUaW1lciA9IG51bGw7XG4gICAgICBpZiAoIXRoaXMuaW50ZW50aW9uYWxDbG9zZSkge1xuICAgICAgICBjb25zb2xlLmxvZyhgW29jbGF3LXdzXSBSZWNvbm5lY3RpbmcgdG8gJHt0aGlzLnVybH1cdTIwMjYgKGF0dGVtcHQgJHthdHRlbXB0fSwgJHtkZWxheX1tcylgKTtcbiAgICAgICAgdGhpcy5fY29ubmVjdCgpO1xuICAgICAgfVxuICAgIH0sIGRlbGF5KTtcbiAgfVxuXG4gIHByaXZhdGUgbGFzdEJ1ZmZlcmVkV2FybkF0TXMgPSAwO1xuXG4gIHByaXZhdGUgX3N0YXJ0SGVhcnRiZWF0KCk6IHZvaWQge1xuICAgIHRoaXMuX3N0b3BIZWFydGJlYXQoKTtcbiAgICB0aGlzLmhlYXJ0YmVhdFRpbWVyID0gc2V0SW50ZXJ2YWwoKCkgPT4ge1xuICAgICAgaWYgKHRoaXMud3M/LnJlYWR5U3RhdGUgIT09IFdlYlNvY2tldC5PUEVOKSByZXR1cm47XG4gICAgICBpZiAodGhpcy53cy5idWZmZXJlZEFtb3VudCA+IDApIHtcbiAgICAgICAgY29uc3Qgbm93ID0gRGF0ZS5ub3coKTtcbiAgICAgICAgLy8gVGhyb3R0bGUgdG8gYXZvaWQgbG9nIHNwYW0gaW4gbG9uZy1ydW5uaW5nIHNlc3Npb25zLlxuICAgICAgICBpZiAobm93IC0gdGhpcy5sYXN0QnVmZmVyZWRXYXJuQXRNcyA+IDUgKiA2MF8wMDApIHtcbiAgICAgICAgICB0aGlzLmxhc3RCdWZmZXJlZFdhcm5BdE1zID0gbm93O1xuICAgICAgICAgIGNvbnNvbGUud2FybignW29jbGF3LXdzXSBTZW5kIGJ1ZmZlciBub3QgZW1wdHkgXHUyMDE0IGNvbm5lY3Rpb24gbWF5IGJlIHN0YWxsZWQnKTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0sIEhFQVJUQkVBVF9JTlRFUlZBTF9NUyk7XG4gIH1cblxuICBwcml2YXRlIF9zdG9wSGVhcnRiZWF0KCk6IHZvaWQge1xuICAgIGlmICh0aGlzLmhlYXJ0YmVhdFRpbWVyKSB7XG4gICAgICBjbGVhckludGVydmFsKHRoaXMuaGVhcnRiZWF0VGltZXIpO1xuICAgICAgdGhpcy5oZWFydGJlYXRUaW1lciA9IG51bGw7XG4gICAgfVxuICB9XG5cbiAgcHJpdmF0ZSBfc3RvcFRpbWVycygpOiB2b2lkIHtcbiAgICB0aGlzLl9zdG9wSGVhcnRiZWF0KCk7XG4gICAgdGhpcy5fZGlzYXJtV29ya2luZ1NhZmV0eVRpbWVvdXQoKTtcbiAgICBpZiAodGhpcy5yZWNvbm5lY3RUaW1lcikge1xuICAgICAgY2xlYXJUaW1lb3V0KHRoaXMucmVjb25uZWN0VGltZXIpO1xuICAgICAgdGhpcy5yZWNvbm5lY3RUaW1lciA9IG51bGw7XG4gICAgfVxuICB9XG5cbiAgcHJpdmF0ZSBfc2V0U3RhdGUoc3RhdGU6IFdTQ2xpZW50U3RhdGUpOiB2b2lkIHtcbiAgICBpZiAodGhpcy5zdGF0ZSA9PT0gc3RhdGUpIHJldHVybjtcbiAgICB0aGlzLnN0YXRlID0gc3RhdGU7XG4gICAgdGhpcy5vblN0YXRlQ2hhbmdlPy4oc3RhdGUpO1xuICB9XG5cbiAgcHJpdmF0ZSBfc2V0V29ya2luZyh3b3JraW5nOiBib29sZWFuKTogdm9pZCB7XG4gICAgaWYgKHRoaXMud29ya2luZyA9PT0gd29ya2luZykgcmV0dXJuO1xuICAgIHRoaXMud29ya2luZyA9IHdvcmtpbmc7XG4gICAgdGhpcy5vbldvcmtpbmdDaGFuZ2U/Lih3b3JraW5nKTtcblxuICAgIGlmICghd29ya2luZykge1xuICAgICAgdGhpcy5fZGlzYXJtV29ya2luZ1NhZmV0eVRpbWVvdXQoKTtcbiAgICB9XG4gIH1cblxuICBwcml2YXRlIF9hcm1Xb3JraW5nU2FmZXR5VGltZW91dCgpOiB2b2lkIHtcbiAgICB0aGlzLl9kaXNhcm1Xb3JraW5nU2FmZXR5VGltZW91dCgpO1xuICAgIHRoaXMud29ya2luZ1RpbWVyID0gc2V0VGltZW91dCgoKSA9PiB7XG4gICAgICAvLyBJZiB0aGUgZ2F0ZXdheSBuZXZlciBlbWl0cyBhbiBhc3Npc3RhbnQgZmluYWwgcmVzcG9uc2UsIGRvblx1MjAxOXQgbGVhdmUgVUkgc3R1Y2suXG4gICAgICB0aGlzLl9zZXRXb3JraW5nKGZhbHNlKTtcbiAgICB9LCBXT1JLSU5HX01BWF9NUyk7XG4gIH1cblxuICBwcml2YXRlIF9kaXNhcm1Xb3JraW5nU2FmZXR5VGltZW91dCgpOiB2b2lkIHtcbiAgICBpZiAodGhpcy53b3JraW5nVGltZXIpIHtcbiAgICAgIGNsZWFyVGltZW91dCh0aGlzLndvcmtpbmdUaW1lcik7XG4gICAgICB0aGlzLndvcmtpbmdUaW1lciA9IG51bGw7XG4gICAgfVxuICB9XG59XG4iLCAiaW1wb3J0IHR5cGUgeyBDaGF0TWVzc2FnZSB9IGZyb20gJy4vdHlwZXMnO1xuXG4vKiogTWFuYWdlcyB0aGUgaW4tbWVtb3J5IGxpc3Qgb2YgY2hhdCBtZXNzYWdlcyBhbmQgbm90aWZpZXMgVUkgb24gY2hhbmdlcyAqL1xuZXhwb3J0IGNsYXNzIENoYXRNYW5hZ2VyIHtcbiAgcHJpdmF0ZSBtZXNzYWdlczogQ2hhdE1lc3NhZ2VbXSA9IFtdO1xuXG4gIC8qKiBGaXJlZCBmb3IgYSBmdWxsIHJlLXJlbmRlciAoY2xlYXIvcmVsb2FkKSAqL1xuICBvblVwZGF0ZTogKChtZXNzYWdlczogcmVhZG9ubHkgQ2hhdE1lc3NhZ2VbXSkgPT4gdm9pZCkgfCBudWxsID0gbnVsbDtcbiAgLyoqIEZpcmVkIHdoZW4gYSBzaW5nbGUgbWVzc2FnZSBpcyBhcHBlbmRlZCBcdTIwMTQgdXNlIGZvciBPKDEpIGFwcGVuZC1vbmx5IFVJICovXG4gIG9uTWVzc2FnZUFkZGVkOiAoKG1zZzogQ2hhdE1lc3NhZ2UpID0+IHZvaWQpIHwgbnVsbCA9IG51bGw7XG5cbiAgYWRkTWVzc2FnZShtc2c6IENoYXRNZXNzYWdlKTogdm9pZCB7XG4gICAgdGhpcy5tZXNzYWdlcy5wdXNoKG1zZyk7XG4gICAgdGhpcy5vbk1lc3NhZ2VBZGRlZD8uKG1zZyk7XG4gIH1cblxuICBnZXRNZXNzYWdlcygpOiByZWFkb25seSBDaGF0TWVzc2FnZVtdIHtcbiAgICByZXR1cm4gdGhpcy5tZXNzYWdlcztcbiAgfVxuXG4gIGNsZWFyKCk6IHZvaWQge1xuICAgIHRoaXMubWVzc2FnZXMgPSBbXTtcbiAgICB0aGlzLm9uVXBkYXRlPy4oW10pO1xuICB9XG5cbiAgLyoqIENyZWF0ZSBhIHVzZXIgbWVzc2FnZSBvYmplY3QgKHdpdGhvdXQgYWRkaW5nIGl0KSAqL1xuICBzdGF0aWMgY3JlYXRlVXNlck1lc3NhZ2UoY29udGVudDogc3RyaW5nKTogQ2hhdE1lc3NhZ2Uge1xuICAgIHJldHVybiB7XG4gICAgICBpZDogYG1zZy0ke0RhdGUubm93KCl9LSR7TWF0aC5yYW5kb20oKS50b1N0cmluZygzNikuc2xpY2UoMiwgNyl9YCxcbiAgICAgIHJvbGU6ICd1c2VyJyxcbiAgICAgIGNvbnRlbnQsXG4gICAgICB0aW1lc3RhbXA6IERhdGUubm93KCksXG4gICAgfTtcbiAgfVxuXG4gIC8qKiBDcmVhdGUgYW4gYXNzaXN0YW50IG1lc3NhZ2Ugb2JqZWN0ICh3aXRob3V0IGFkZGluZyBpdCkgKi9cbiAgc3RhdGljIGNyZWF0ZUFzc2lzdGFudE1lc3NhZ2UoY29udGVudDogc3RyaW5nKTogQ2hhdE1lc3NhZ2Uge1xuICAgIHJldHVybiB7XG4gICAgICBpZDogYG1zZy0ke0RhdGUubm93KCl9LSR7TWF0aC5yYW5kb20oKS50b1N0cmluZygzNikuc2xpY2UoMiwgNyl9YCxcbiAgICAgIHJvbGU6ICdhc3Npc3RhbnQnLFxuICAgICAgY29udGVudCxcbiAgICAgIHRpbWVzdGFtcDogRGF0ZS5ub3coKSxcbiAgICB9O1xuICB9XG5cbiAgLyoqIENyZWF0ZSBhIHN5c3RlbSAvIHN0YXR1cyBtZXNzYWdlIChlcnJvcnMsIHJlY29ubmVjdCBub3RpY2VzLCBldGMuKSAqL1xuICBzdGF0aWMgY3JlYXRlU3lzdGVtTWVzc2FnZShjb250ZW50OiBzdHJpbmcsIGxldmVsOiBDaGF0TWVzc2FnZVsnbGV2ZWwnXSA9ICdpbmZvJyk6IENoYXRNZXNzYWdlIHtcbiAgICByZXR1cm4ge1xuICAgICAgaWQ6IGBzeXMtJHtEYXRlLm5vdygpfWAsXG4gICAgICByb2xlOiAnc3lzdGVtJyxcbiAgICAgIGxldmVsLFxuICAgICAgY29udGVudCxcbiAgICAgIHRpbWVzdGFtcDogRGF0ZS5ub3coKSxcbiAgICB9O1xuICB9XG59XG4iLCAiaW1wb3J0IHsgSXRlbVZpZXcsIE1hcmtkb3duUmVuZGVyZXIsIE5vdGljZSwgV29ya3NwYWNlTGVhZiB9IGZyb20gJ29ic2lkaWFuJztcbmltcG9ydCB0eXBlIE9wZW5DbGF3UGx1Z2luIGZyb20gJy4vbWFpbic7XG5pbXBvcnQgeyBDaGF0TWFuYWdlciB9IGZyb20gJy4vY2hhdCc7XG5pbXBvcnQgdHlwZSB7IENoYXRNZXNzYWdlIH0gZnJvbSAnLi90eXBlcyc7XG5pbXBvcnQgeyBnZXRBY3RpdmVOb3RlQ29udGV4dCB9IGZyb20gJy4vY29udGV4dCc7XG5cbmV4cG9ydCBjb25zdCBWSUVXX1RZUEVfT1BFTkNMQVdfQ0hBVCA9ICdvcGVuY2xhdy1jaGF0JztcblxuZXhwb3J0IGNsYXNzIE9wZW5DbGF3Q2hhdFZpZXcgZXh0ZW5kcyBJdGVtVmlldyB7XG4gIHByaXZhdGUgcGx1Z2luOiBPcGVuQ2xhd1BsdWdpbjtcbiAgcHJpdmF0ZSBjaGF0TWFuYWdlcjogQ2hhdE1hbmFnZXI7XG5cbiAgLy8gU3RhdGVcbiAgcHJpdmF0ZSBpc0Nvbm5lY3RlZCA9IGZhbHNlO1xuICBwcml2YXRlIGlzV29ya2luZyA9IGZhbHNlO1xuXG4gIC8vIERPTSByZWZzXG4gIHByaXZhdGUgbWVzc2FnZXNFbCE6IEhUTUxFbGVtZW50O1xuICBwcml2YXRlIGlucHV0RWwhOiBIVE1MVGV4dEFyZWFFbGVtZW50O1xuICBwcml2YXRlIHNlbmRCdG4hOiBIVE1MQnV0dG9uRWxlbWVudDtcbiAgcHJpdmF0ZSBpbmNsdWRlTm90ZUNoZWNrYm94ITogSFRNTElucHV0RWxlbWVudDtcbiAgcHJpdmF0ZSBzdGF0dXNEb3QhOiBIVE1MRWxlbWVudDtcblxuICBjb25zdHJ1Y3RvcihsZWFmOiBXb3Jrc3BhY2VMZWFmLCBwbHVnaW46IE9wZW5DbGF3UGx1Z2luKSB7XG4gICAgc3VwZXIobGVhZik7XG4gICAgdGhpcy5wbHVnaW4gPSBwbHVnaW47XG4gICAgdGhpcy5jaGF0TWFuYWdlciA9IHBsdWdpbi5jaGF0TWFuYWdlcjtcbiAgfVxuXG4gIGdldFZpZXdUeXBlKCk6IHN0cmluZyB7XG4gICAgcmV0dXJuIFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFUO1xuICB9XG5cbiAgZ2V0RGlzcGxheVRleHQoKTogc3RyaW5nIHtcbiAgICByZXR1cm4gJ09wZW5DbGF3IENoYXQnO1xuICB9XG5cbiAgZ2V0SWNvbigpOiBzdHJpbmcge1xuICAgIHJldHVybiAnbWVzc2FnZS1zcXVhcmUnO1xuICB9XG5cbiAgYXN5bmMgb25PcGVuKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIHRoaXMuX2J1aWxkVUkoKTtcblxuICAgIC8vIEZ1bGwgcmUtcmVuZGVyIG9uIGNsZWFyIC8gcmVsb2FkXG4gICAgdGhpcy5jaGF0TWFuYWdlci5vblVwZGF0ZSA9IChtc2dzKSA9PiB0aGlzLl9yZW5kZXJNZXNzYWdlcyhtc2dzKTtcbiAgICAvLyBPKDEpIGFwcGVuZCBmb3IgbmV3IG1lc3NhZ2VzXG4gICAgdGhpcy5jaGF0TWFuYWdlci5vbk1lc3NhZ2VBZGRlZCA9IChtc2cpID0+IHRoaXMuX2FwcGVuZE1lc3NhZ2UobXNnKTtcblxuICAgIC8vIFN1YnNjcmliZSB0byBXUyBzdGF0ZSBjaGFuZ2VzXG4gICAgdGhpcy5wbHVnaW4ud3NDbGllbnQub25TdGF0ZUNoYW5nZSA9IChzdGF0ZSkgPT4ge1xuICAgICAgdGhpcy5pc0Nvbm5lY3RlZCA9IHN0YXRlID09PSAnY29ubmVjdGVkJztcbiAgICAgIHRoaXMuc3RhdHVzRG90LnRvZ2dsZUNsYXNzKCdjb25uZWN0ZWQnLCB0aGlzLmlzQ29ubmVjdGVkKTtcbiAgICAgIHRoaXMuc3RhdHVzRG90LnRpdGxlID0gYEdhdGV3YXk6ICR7c3RhdGV9YDtcbiAgICAgIHRoaXMuX3VwZGF0ZVNlbmRCdXR0b24oKTtcbiAgICB9O1xuXG4gICAgLy8gU3Vic2NyaWJlIHRvIFx1MjAxQ3dvcmtpbmdcdTIwMUQgKHJlcXVlc3QtaW4tZmxpZ2h0KSBzdGF0ZVxuICAgIHRoaXMucGx1Z2luLndzQ2xpZW50Lm9uV29ya2luZ0NoYW5nZSA9ICh3b3JraW5nKSA9PiB7XG4gICAgICB0aGlzLmlzV29ya2luZyA9IHdvcmtpbmc7XG4gICAgICB0aGlzLl91cGRhdGVTZW5kQnV0dG9uKCk7XG4gICAgfTtcblxuICAgIC8vIFJlZmxlY3QgY3VycmVudCBzdGF0ZVxuICAgIHRoaXMuaXNDb25uZWN0ZWQgPSB0aGlzLnBsdWdpbi53c0NsaWVudC5zdGF0ZSA9PT0gJ2Nvbm5lY3RlZCc7XG4gICAgdGhpcy5zdGF0dXNEb3QudG9nZ2xlQ2xhc3MoJ2Nvbm5lY3RlZCcsIHRoaXMuaXNDb25uZWN0ZWQpO1xuICAgIHRoaXMuX3VwZGF0ZVNlbmRCdXR0b24oKTtcblxuICAgIHRoaXMuX3JlbmRlck1lc3NhZ2VzKHRoaXMuY2hhdE1hbmFnZXIuZ2V0TWVzc2FnZXMoKSk7XG4gIH1cblxuICBhc3luYyBvbkNsb3NlKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIHRoaXMuY2hhdE1hbmFnZXIub25VcGRhdGUgPSBudWxsO1xuICAgIHRoaXMuY2hhdE1hbmFnZXIub25NZXNzYWdlQWRkZWQgPSBudWxsO1xuICAgIHRoaXMucGx1Z2luLndzQ2xpZW50Lm9uU3RhdGVDaGFuZ2UgPSBudWxsO1xuICAgIHRoaXMucGx1Z2luLndzQ2xpZW50Lm9uV29ya2luZ0NoYW5nZSA9IG51bGw7XG4gIH1cblxuICAvLyBcdTI1MDBcdTI1MDAgVUkgY29uc3RydWN0aW9uIFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFxuXG4gIHByaXZhdGUgX2J1aWxkVUkoKTogdm9pZCB7XG4gICAgY29uc3Qgcm9vdCA9IHRoaXMuY29udGVudEVsO1xuICAgIHJvb3QuZW1wdHkoKTtcbiAgICByb290LmFkZENsYXNzKCdvY2xhdy1jaGF0LXZpZXcnKTtcblxuICAgIC8vIFx1MjUwMFx1MjUwMCBIZWFkZXIgXHUyNTAwXHUyNTAwXG4gICAgY29uc3QgaGVhZGVyID0gcm9vdC5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1oZWFkZXInIH0pO1xuICAgIGhlYWRlci5jcmVhdGVTcGFuKHsgY2xzOiAnb2NsYXctaGVhZGVyLXRpdGxlJywgdGV4dDogJ09wZW5DbGF3IENoYXQnIH0pO1xuICAgIHRoaXMuc3RhdHVzRG90ID0gaGVhZGVyLmNyZWF0ZURpdih7IGNsczogJ29jbGF3LXN0YXR1cy1kb3QnIH0pO1xuICAgIHRoaXMuc3RhdHVzRG90LnRpdGxlID0gJ0dhdGV3YXk6IGRpc2Nvbm5lY3RlZCc7XG5cbiAgICAvLyBcdTI1MDBcdTI1MDAgTWVzc2FnZXMgYXJlYSBcdTI1MDBcdTI1MDBcbiAgICB0aGlzLm1lc3NhZ2VzRWwgPSByb290LmNyZWF0ZURpdih7IGNsczogJ29jbGF3LW1lc3NhZ2VzJyB9KTtcblxuICAgIC8vIFx1MjUwMFx1MjUwMCBDb250ZXh0IHJvdyBcdTI1MDBcdTI1MDBcbiAgICBjb25zdCBjdHhSb3cgPSByb290LmNyZWF0ZURpdih7IGNsczogJ29jbGF3LWNvbnRleHQtcm93JyB9KTtcbiAgICB0aGlzLmluY2x1ZGVOb3RlQ2hlY2tib3ggPSBjdHhSb3cuY3JlYXRlRWwoJ2lucHV0JywgeyB0eXBlOiAnY2hlY2tib3gnIH0pO1xuICAgIHRoaXMuaW5jbHVkZU5vdGVDaGVja2JveC5pZCA9ICdvY2xhdy1pbmNsdWRlLW5vdGUnO1xuICAgIHRoaXMuaW5jbHVkZU5vdGVDaGVja2JveC5jaGVja2VkID0gdGhpcy5wbHVnaW4uc2V0dGluZ3MuaW5jbHVkZUFjdGl2ZU5vdGU7XG4gICAgY29uc3QgY3R4TGFiZWwgPSBjdHhSb3cuY3JlYXRlRWwoJ2xhYmVsJywgeyB0ZXh0OiAnSW5jbHVkZSBhY3RpdmUgbm90ZScgfSk7XG4gICAgY3R4TGFiZWwuaHRtbEZvciA9ICdvY2xhdy1pbmNsdWRlLW5vdGUnO1xuXG4gICAgLy8gXHUyNTAwXHUyNTAwIElucHV0IHJvdyBcdTI1MDBcdTI1MDBcbiAgICBjb25zdCBpbnB1dFJvdyA9IHJvb3QuY3JlYXRlRGl2KHsgY2xzOiAnb2NsYXctaW5wdXQtcm93JyB9KTtcbiAgICB0aGlzLmlucHV0RWwgPSBpbnB1dFJvdy5jcmVhdGVFbCgndGV4dGFyZWEnLCB7XG4gICAgICBjbHM6ICdvY2xhdy1pbnB1dCcsXG4gICAgICBwbGFjZWhvbGRlcjogJ0FzayBhbnl0aGluZ1x1MjAyNicsXG4gICAgfSk7XG4gICAgdGhpcy5pbnB1dEVsLnJvd3MgPSAxO1xuXG4gICAgdGhpcy5zZW5kQnRuID0gaW5wdXRSb3cuY3JlYXRlRWwoJ2J1dHRvbicsIHsgY2xzOiAnb2NsYXctc2VuZC1idG4nLCB0ZXh0OiAnU2VuZCcgfSk7XG5cbiAgICAvLyBcdTI1MDBcdTI1MDAgRXZlbnQgbGlzdGVuZXJzIFx1MjUwMFx1MjUwMFxuICAgIHRoaXMuc2VuZEJ0bi5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpID0+IHRoaXMuX2hhbmRsZVNlbmQoKSk7XG4gICAgdGhpcy5pbnB1dEVsLmFkZEV2ZW50TGlzdGVuZXIoJ2tleWRvd24nLCAoZSkgPT4ge1xuICAgICAgaWYgKGUua2V5ID09PSAnRW50ZXInICYmICFlLnNoaWZ0S2V5KSB7XG4gICAgICAgIGUucHJldmVudERlZmF1bHQoKTtcbiAgICAgICAgdGhpcy5faGFuZGxlU2VuZCgpO1xuICAgICAgfVxuICAgIH0pO1xuICAgIC8vIEF1dG8tcmVzaXplIHRleHRhcmVhXG4gICAgdGhpcy5pbnB1dEVsLmFkZEV2ZW50TGlzdGVuZXIoJ2lucHV0JywgKCkgPT4ge1xuICAgICAgdGhpcy5pbnB1dEVsLnN0eWxlLmhlaWdodCA9ICdhdXRvJztcbiAgICAgIHRoaXMuaW5wdXRFbC5zdHlsZS5oZWlnaHQgPSBgJHt0aGlzLmlucHV0RWwuc2Nyb2xsSGVpZ2h0fXB4YDtcbiAgICB9KTtcbiAgfVxuXG4gIC8vIFx1MjUwMFx1MjUwMCBNZXNzYWdlIHJlbmRlcmluZyBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcblxuICBwcml2YXRlIF9yZW5kZXJNZXNzYWdlcyhtZXNzYWdlczogcmVhZG9ubHkgQ2hhdE1lc3NhZ2VbXSk6IHZvaWQge1xuICAgIHRoaXMubWVzc2FnZXNFbC5lbXB0eSgpO1xuXG4gICAgaWYgKG1lc3NhZ2VzLmxlbmd0aCA9PT0gMCkge1xuICAgICAgdGhpcy5tZXNzYWdlc0VsLmNyZWF0ZUVsKCdwJywge1xuICAgICAgICB0ZXh0OiAnU2VuZCBhIG1lc3NhZ2UgdG8gc3RhcnQgY2hhdHRpbmcuJyxcbiAgICAgICAgY2xzOiAnb2NsYXctbWVzc2FnZSBzeXN0ZW0gb2NsYXctcGxhY2Vob2xkZXInLFxuICAgICAgfSk7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgZm9yIChjb25zdCBtc2cgb2YgbWVzc2FnZXMpIHtcbiAgICAgIHRoaXMuX2FwcGVuZE1lc3NhZ2UobXNnKTtcbiAgICB9XG5cbiAgICAvLyBTY3JvbGwgdG8gYm90dG9tXG4gICAgdGhpcy5tZXNzYWdlc0VsLnNjcm9sbFRvcCA9IHRoaXMubWVzc2FnZXNFbC5zY3JvbGxIZWlnaHQ7XG4gIH1cblxuICAvKiogQXBwZW5kcyBhIHNpbmdsZSBtZXNzYWdlIHdpdGhvdXQgcmVidWlsZGluZyB0aGUgRE9NIChPKDEpKSAqL1xuICBwcml2YXRlIF9hcHBlbmRNZXNzYWdlKG1zZzogQ2hhdE1lc3NhZ2UpOiB2b2lkIHtcbiAgICAvLyBSZW1vdmUgZW1wdHktc3RhdGUgcGxhY2Vob2xkZXIgaWYgcHJlc2VudFxuICAgIHRoaXMubWVzc2FnZXNFbC5xdWVyeVNlbGVjdG9yKCcub2NsYXctcGxhY2Vob2xkZXInKT8ucmVtb3ZlKCk7XG5cbiAgICBjb25zdCBsZXZlbENsYXNzID0gbXNnLmxldmVsID8gYCAke21zZy5sZXZlbH1gIDogJyc7XG4gICAgY29uc3QgZWwgPSB0aGlzLm1lc3NhZ2VzRWwuY3JlYXRlRGl2KHsgY2xzOiBgb2NsYXctbWVzc2FnZSAke21zZy5yb2xlfSR7bGV2ZWxDbGFzc31gIH0pO1xuICAgIGNvbnN0IGJvZHkgPSBlbC5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1tZXNzYWdlLWJvZHknIH0pO1xuXG4gICAgLy8gVHJlYXQgYXNzaXN0YW50IG91dHB1dCBhcyBVTlRSVVNURUQgYnkgZGVmYXVsdC5cbiAgICAvLyBSZW5kZXJpbmcgYXMgT2JzaWRpYW4gTWFya2Rvd24gY2FuIHRyaWdnZXIgZW1iZWRzIGFuZCBvdGhlciBwbHVnaW5zJyBwb3N0LXByb2Nlc3NvcnMuXG4gICAgaWYgKG1zZy5yb2xlID09PSAnYXNzaXN0YW50JyAmJiB0aGlzLnBsdWdpbi5zZXR0aW5ncy5yZW5kZXJBc3Npc3RhbnRNYXJrZG93bikge1xuICAgICAgY29uc3Qgc291cmNlUGF0aCA9IHRoaXMuYXBwLndvcmtzcGFjZS5nZXRBY3RpdmVGaWxlKCk/LnBhdGggPz8gJyc7XG4gICAgICB2b2lkIE1hcmtkb3duUmVuZGVyZXIucmVuZGVyTWFya2Rvd24obXNnLmNvbnRlbnQsIGJvZHksIHNvdXJjZVBhdGgsIHRoaXMucGx1Z2luKTtcbiAgICB9IGVsc2Uge1xuICAgICAgYm9keS5zZXRUZXh0KG1zZy5jb250ZW50KTtcbiAgICB9XG5cbiAgICAvLyBTY3JvbGwgdG8gYm90dG9tXG4gICAgdGhpcy5tZXNzYWdlc0VsLnNjcm9sbFRvcCA9IHRoaXMubWVzc2FnZXNFbC5zY3JvbGxIZWlnaHQ7XG4gIH1cblxuICBwcml2YXRlIF91cGRhdGVTZW5kQnV0dG9uKCk6IHZvaWQge1xuICAgIC8vIERpc2Nvbm5lY3RlZDogZGlzYWJsZS5cbiAgICAvLyBXb3JraW5nOiBrZWVwIGVuYWJsZWQgc28gdXNlciBjYW4gc3RvcC9hYm9ydC5cbiAgICBjb25zdCBkaXNhYmxlZCA9ICF0aGlzLmlzQ29ubmVjdGVkO1xuICAgIHRoaXMuc2VuZEJ0bi5kaXNhYmxlZCA9IGRpc2FibGVkO1xuXG4gICAgdGhpcy5zZW5kQnRuLnRvZ2dsZUNsYXNzKCdpcy13b3JraW5nJywgdGhpcy5pc1dvcmtpbmcpO1xuICAgIHRoaXMuc2VuZEJ0bi5zZXRBdHRyKCdhcmlhLWJ1c3knLCB0aGlzLmlzV29ya2luZyA/ICd0cnVlJyA6ICdmYWxzZScpO1xuICAgIHRoaXMuc2VuZEJ0bi5zZXRBdHRyKCdhcmlhLWxhYmVsJywgdGhpcy5pc1dvcmtpbmcgPyAnU3RvcCcgOiAnU2VuZCcpO1xuXG4gICAgaWYgKHRoaXMuaXNXb3JraW5nKSB7XG4gICAgICAvLyBSZXBsYWNlIGJ1dHRvbiBjb250ZW50cyB3aXRoIFN0b3AgaWNvbiArIHNwaW5uZXIgcmluZy5cbiAgICAgIHRoaXMuc2VuZEJ0bi5lbXB0eSgpO1xuICAgICAgY29uc3Qgd3JhcCA9IHRoaXMuc2VuZEJ0bi5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1zdG9wLXdyYXAnIH0pO1xuICAgICAgd3JhcC5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1zcGlubmVyLXJpbmcnLCBhdHRyOiB7ICdhcmlhLWhpZGRlbic6ICd0cnVlJyB9IH0pO1xuICAgICAgd3JhcC5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1zdG9wLWljb24nLCBhdHRyOiB7ICdhcmlhLWhpZGRlbic6ICd0cnVlJyB9IH0pO1xuICAgIH0gZWxzZSB7XG4gICAgICAvLyBSZXN0b3JlIGxhYmVsXG4gICAgICB0aGlzLnNlbmRCdG4uc2V0VGV4dCgnU2VuZCcpO1xuICAgIH1cbiAgfVxuXG4gIC8vIFx1MjUwMFx1MjUwMCBTZW5kIGhhbmRsZXIgXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG5cbiAgcHJpdmF0ZSBhc3luYyBfaGFuZGxlU2VuZCgpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICAvLyBXaGlsZSB3b3JraW5nLCB0aGUgYnV0dG9uIGJlY29tZXMgU3RvcC5cbiAgICBpZiAodGhpcy5pc1dvcmtpbmcpIHtcbiAgICAgIGNvbnN0IG9rID0gYXdhaXQgdGhpcy5wbHVnaW4ud3NDbGllbnQuYWJvcnRBY3RpdmVSdW4oKTtcbiAgICAgIGlmICghb2spIHtcbiAgICAgICAgbmV3IE5vdGljZSgnT3BlbkNsYXcgQ2hhdDogZmFpbGVkIHRvIHN0b3AnKTtcbiAgICAgICAgdGhpcy5jaGF0TWFuYWdlci5hZGRNZXNzYWdlKENoYXRNYW5hZ2VyLmNyZWF0ZVN5c3RlbU1lc3NhZ2UoJ1x1MjZBMCBTdG9wIGZhaWxlZCcsICdlcnJvcicpKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHRoaXMuY2hhdE1hbmFnZXIuYWRkTWVzc2FnZShDaGF0TWFuYWdlci5jcmVhdGVTeXN0ZW1NZXNzYWdlKCdcdTI2RDQgU3RvcHBlZCcsICdpbmZvJykpO1xuICAgICAgfVxuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIGNvbnN0IHRleHQgPSB0aGlzLmlucHV0RWwudmFsdWUudHJpbSgpO1xuICAgIGlmICghdGV4dCkgcmV0dXJuO1xuXG4gICAgLy8gQnVpbGQgbWVzc2FnZSB3aXRoIGNvbnRleHQgaWYgZW5hYmxlZFxuICAgIGxldCBtZXNzYWdlID0gdGV4dDtcbiAgICBpZiAodGhpcy5pbmNsdWRlTm90ZUNoZWNrYm94LmNoZWNrZWQpIHtcbiAgICAgIGNvbnN0IG5vdGUgPSBhd2FpdCBnZXRBY3RpdmVOb3RlQ29udGV4dCh0aGlzLmFwcCk7XG4gICAgICBpZiAobm90ZSkge1xuICAgICAgICBtZXNzYWdlID0gYENvbnRleHQ6IFtbJHtub3RlLnRpdGxlfV1dXFxuXFxuJHt0ZXh0fWA7XG4gICAgICB9XG4gICAgfVxuXG4gICAgLy8gQWRkIHVzZXIgbWVzc2FnZSB0byBjaGF0IFVJXG4gICAgY29uc3QgdXNlck1zZyA9IENoYXRNYW5hZ2VyLmNyZWF0ZVVzZXJNZXNzYWdlKHRleHQpO1xuICAgIHRoaXMuY2hhdE1hbmFnZXIuYWRkTWVzc2FnZSh1c2VyTXNnKTtcblxuICAgIC8vIENsZWFyIGlucHV0XG4gICAgdGhpcy5pbnB1dEVsLnZhbHVlID0gJyc7XG4gICAgdGhpcy5pbnB1dEVsLnN0eWxlLmhlaWdodCA9ICdhdXRvJztcblxuICAgIC8vIFNlbmQgb3ZlciBXUyAoYXN5bmMpXG4gICAgdHJ5IHtcbiAgICAgIGF3YWl0IHRoaXMucGx1Z2luLndzQ2xpZW50LnNlbmRNZXNzYWdlKG1lc3NhZ2UpO1xuICAgIH0gY2F0Y2ggKGVycikge1xuICAgICAgY29uc29sZS5lcnJvcignW29jbGF3XSBTZW5kIGZhaWxlZCcsIGVycik7XG4gICAgICBuZXcgTm90aWNlKGBPcGVuQ2xhdyBDaGF0OiBzZW5kIGZhaWxlZCAoJHtTdHJpbmcoZXJyKX0pYCk7XG4gICAgICB0aGlzLmNoYXRNYW5hZ2VyLmFkZE1lc3NhZ2UoXG4gICAgICAgIENoYXRNYW5hZ2VyLmNyZWF0ZVN5c3RlbU1lc3NhZ2UoYFx1MjZBMCBTZW5kIGZhaWxlZDogJHtlcnJ9YCwgJ2Vycm9yJylcbiAgICAgICk7XG4gICAgfVxuICB9XG59XG4iLCAiaW1wb3J0IHR5cGUgeyBBcHAgfSBmcm9tICdvYnNpZGlhbic7XG5cbmV4cG9ydCBpbnRlcmZhY2UgTm90ZUNvbnRleHQge1xuICB0aXRsZTogc3RyaW5nO1xuICBwYXRoOiBzdHJpbmc7XG4gIGNvbnRlbnQ6IHN0cmluZztcbn1cblxuLyoqXG4gKiBSZXR1cm5zIHRoZSBhY3RpdmUgbm90ZSdzIHRpdGxlIGFuZCBjb250ZW50LCBvciBudWxsIGlmIG5vIG5vdGUgaXMgb3Blbi5cbiAqIEFzeW5jIGJlY2F1c2UgdmF1bHQucmVhZCgpIGlzIGFzeW5jLlxuICovXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZ2V0QWN0aXZlTm90ZUNvbnRleHQoYXBwOiBBcHApOiBQcm9taXNlPE5vdGVDb250ZXh0IHwgbnVsbD4ge1xuICBjb25zdCBmaWxlID0gYXBwLndvcmtzcGFjZS5nZXRBY3RpdmVGaWxlKCk7XG4gIGlmICghZmlsZSkgcmV0dXJuIG51bGw7XG5cbiAgdHJ5IHtcbiAgICBjb25zdCBjb250ZW50ID0gYXdhaXQgYXBwLnZhdWx0LnJlYWQoZmlsZSk7XG4gICAgcmV0dXJuIHtcbiAgICAgIHRpdGxlOiBmaWxlLmJhc2VuYW1lLFxuICAgICAgcGF0aDogZmlsZS5wYXRoLFxuICAgICAgY29udGVudCxcbiAgICB9O1xuICB9IGNhdGNoIChlcnIpIHtcbiAgICBjb25zb2xlLmVycm9yKCdbb2NsYXctY29udGV4dF0gRmFpbGVkIHRvIHJlYWQgYWN0aXZlIG5vdGUnLCBlcnIpO1xuICAgIHJldHVybiBudWxsO1xuICB9XG59XG4iLCAiLyoqIFBlcnNpc3RlZCBwbHVnaW4gY29uZmlndXJhdGlvbiAqL1xuZXhwb3J0IGludGVyZmFjZSBPcGVuQ2xhd1NldHRpbmdzIHtcbiAgLyoqIFdlYlNvY2tldCBVUkwgb2YgdGhlIE9wZW5DbGF3IEdhdGV3YXkgKGUuZy4gd3M6Ly8xMDAuOTAuOS42ODoxODc4OSkgKi9cbiAgZ2F0ZXdheVVybDogc3RyaW5nO1xuICAvKiogQXV0aCB0b2tlbiBcdTIwMTQgbXVzdCBtYXRjaCB0aGUgY2hhbm5lbCBwbHVnaW4ncyBhdXRoVG9rZW4gKi9cbiAgYXV0aFRva2VuOiBzdHJpbmc7XG4gIC8qKiBPcGVuQ2xhdyBzZXNzaW9uIGtleSB0byBzdWJzY3JpYmUgdG8gKGUuZy4gXCJtYWluXCIpICovXG4gIHNlc3Npb25LZXk6IHN0cmluZztcbiAgLyoqIChEZXByZWNhdGVkKSBPcGVuQ2xhdyBhY2NvdW50IElEICh1bnVzZWQ7IGNoYXQuc2VuZCB1c2VzIHNlc3Npb25LZXkpICovXG4gIGFjY291bnRJZDogc3RyaW5nO1xuICAvKiogV2hldGhlciB0byBpbmNsdWRlIHRoZSBhY3RpdmUgbm90ZSBjb250ZW50IHdpdGggZWFjaCBtZXNzYWdlICovXG4gIGluY2x1ZGVBY3RpdmVOb3RlOiBib29sZWFuO1xuICAvKiogUmVuZGVyIGFzc2lzdGFudCBvdXRwdXQgYXMgTWFya2Rvd24gKHVuc2FmZTogbWF5IHRyaWdnZXIgZW1iZWRzL3Bvc3QtcHJvY2Vzc29ycyk7IGRlZmF1bHQgT0ZGICovXG4gIHJlbmRlckFzc2lzdGFudE1hcmtkb3duOiBib29sZWFuO1xuICAvKiogQWxsb3cgdXNpbmcgaW5zZWN1cmUgd3M6Ly8gZm9yIG5vbi1sb2NhbCBnYXRld2F5IFVSTHMgKHVuc2FmZSk7IGRlZmF1bHQgT0ZGICovXG4gIGFsbG93SW5zZWN1cmVXczogYm9vbGVhbjtcbn1cblxuZXhwb3J0IGNvbnN0IERFRkFVTFRfU0VUVElOR1M6IE9wZW5DbGF3U2V0dGluZ3MgPSB7XG4gIGdhdGV3YXlVcmw6ICd3czovL2xvY2FsaG9zdDoxODc4OScsXG4gIGF1dGhUb2tlbjogJycsXG4gIHNlc3Npb25LZXk6ICdtYWluJyxcbiAgYWNjb3VudElkOiAnbWFpbicsXG4gIGluY2x1ZGVBY3RpdmVOb3RlOiBmYWxzZSxcbiAgcmVuZGVyQXNzaXN0YW50TWFya2Rvd246IGZhbHNlLFxuICBhbGxvd0luc2VjdXJlV3M6IGZhbHNlLFxufTtcblxuLyoqIEEgc2luZ2xlIGNoYXQgbWVzc2FnZSAqL1xuZXhwb3J0IGludGVyZmFjZSBDaGF0TWVzc2FnZSB7XG4gIGlkOiBzdHJpbmc7XG4gIHJvbGU6ICd1c2VyJyB8ICdhc3Npc3RhbnQnIHwgJ3N5c3RlbSc7XG4gIC8qKiBPcHRpb25hbCBzZXZlcml0eSBmb3Igc3lzdGVtL3N0YXR1cyBtZXNzYWdlcyAqL1xuICBsZXZlbD86ICdpbmZvJyB8ICdlcnJvcic7XG4gIGNvbnRlbnQ6IHN0cmluZztcbiAgdGltZXN0YW1wOiBudW1iZXI7XG59XG5cbi8qKiBQYXlsb2FkIGZvciBtZXNzYWdlcyBTRU5UIHRvIHRoZSBzZXJ2ZXIgKG91dGJvdW5kKSAqL1xuZXhwb3J0IGludGVyZmFjZSBXU1BheWxvYWQge1xuICB0eXBlOiAnYXV0aCcgfCAnbWVzc2FnZScgfCAncGluZycgfCAncG9uZycgfCAnZXJyb3InO1xuICBwYXlsb2FkPzogUmVjb3JkPHN0cmluZywgdW5rbm93bj47XG59XG5cbi8qKiBNZXNzYWdlcyBSRUNFSVZFRCBmcm9tIHRoZSBzZXJ2ZXIgKGluYm91bmQpIFx1MjAxNCBkaXNjcmltaW5hdGVkIHVuaW9uICovXG5leHBvcnQgdHlwZSBJbmJvdW5kV1NQYXlsb2FkID1cbiAgfCB7IHR5cGU6ICdtZXNzYWdlJzsgcGF5bG9hZDogeyBjb250ZW50OiBzdHJpbmc7IHJvbGU6IHN0cmluZzsgdGltZXN0YW1wOiBudW1iZXIgfSB9XG4gIHwgeyB0eXBlOiAnZXJyb3InOyBwYXlsb2FkOiB7IG1lc3NhZ2U6IHN0cmluZyB9IH07XG5cbi8qKiBBdmFpbGFibGUgYWdlbnRzIC8gbW9kZWxzICovXG5leHBvcnQgaW50ZXJmYWNlIEFnZW50T3B0aW9uIHtcbiAgaWQ6IHN0cmluZztcbiAgbGFiZWw6IHN0cmluZztcbn1cbiJdLAogICJtYXBwaW5ncyI6ICI7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQSxJQUFBQSxtQkFBOEM7OztBQ0E5QyxzQkFBK0M7QUFHeEMsSUFBTSxxQkFBTixjQUFpQyxpQ0FBaUI7QUFBQSxFQUd2RCxZQUFZLEtBQVUsUUFBd0I7QUFDNUMsVUFBTSxLQUFLLE1BQU07QUFDakIsU0FBSyxTQUFTO0FBQUEsRUFDaEI7QUFBQSxFQUVBLFVBQWdCO0FBQ2QsVUFBTSxFQUFFLFlBQVksSUFBSTtBQUN4QixnQkFBWSxNQUFNO0FBRWxCLGdCQUFZLFNBQVMsTUFBTSxFQUFFLE1BQU0sZ0NBQTJCLENBQUM7QUFFL0QsUUFBSSx3QkFBUSxXQUFXLEVBQ3BCLFFBQVEsYUFBYSxFQUNyQixR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
