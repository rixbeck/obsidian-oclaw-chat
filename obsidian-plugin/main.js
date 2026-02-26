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
    var _a;
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
    containerEl.createEl("h3", { text: "Path mappings (vault base \u2192 remote base)" });
    containerEl.createEl("p", {
      text: "Used to convert assistant file references (remote FS paths or exported URLs) into clickable Obsidian links. First match wins. Only creates a link if the mapped vault file exists.",
      cls: "setting-item-description"
    });
    const mappings = (_a = this.plugin.settings.pathMappings) != null ? _a : [];
    const rerender = () => __async(this, null, function* () {
      yield this.plugin.saveSettings();
      this.display();
    });
    mappings.forEach((row, idx) => {
      const s = new import_obsidian.Setting(containerEl).setName(`Mapping #${idx + 1}`).setDesc("vaultBase \u2192 remoteBase");
      s.addText(
        (t) => {
          var _a2;
          return t.setPlaceholder("vault base (e.g. docs/)").setValue((_a2 = row.vaultBase) != null ? _a2 : "").onChange((v) => __async(this, null, function* () {
            this.plugin.settings.pathMappings[idx].vaultBase = v;
            yield this.plugin.saveSettings();
          }));
        }
      );
      s.addText(
        (t) => {
          var _a2;
          return t.setPlaceholder("remote base (e.g. /home/.../docs/)").setValue((_a2 = row.remoteBase) != null ? _a2 : "").onChange((v) => __async(this, null, function* () {
            this.plugin.settings.pathMappings[idx].remoteBase = v;
            yield this.plugin.saveSettings();
          }));
        }
      );
      s.addExtraButton(
        (b) => b.setIcon("trash").setTooltip("Remove mapping").onClick(() => __async(this, null, function* () {
          this.plugin.settings.pathMappings.splice(idx, 1);
          yield rerender();
        }))
      );
    });
    new import_obsidian.Setting(containerEl).setName("Add mapping").setDesc("Add a new vaultBase \u2192 remoteBase mapping row.").addButton(
      (btn) => btn.setButtonText("Add").onClick(() => __async(this, null, function* () {
        this.plugin.settings.pathMappings.push({ vaultBase: "", remoteBase: "" });
        yield rerender();
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
function byteLengthUtf8(text) {
  return utf8Bytes(text).byteLength;
}
function normalizeWsDataToText(data) {
  return __async(this, null, function* () {
    if (typeof data === "string") {
      const bytes = byteLengthUtf8(data);
      return { ok: true, text: data, bytes };
    }
    if (typeof Blob !== "undefined" && data instanceof Blob) {
      const bytes = data.size;
      if (bytes > MAX_INBOUND_FRAME_BYTES)
        return { ok: false, reason: "too-large", bytes };
      const text = yield data.text();
      return { ok: true, text, bytes };
    }
    if (data instanceof ArrayBuffer) {
      const bytes = data.byteLength;
      if (bytes > MAX_INBOUND_FRAME_BYTES)
        return { ok: false, reason: "too-large", bytes };
      const text = new TextDecoder("utf-8", { fatal: false }).decode(new Uint8Array(data));
      return { ok: true, text, bytes };
    }
    if (data instanceof Uint8Array) {
      const bytes = data.byteLength;
      if (bytes > MAX_INBOUND_FRAME_BYTES)
        return { ok: false, reason: "too-large", bytes };
      const text = new TextDecoder("utf-8", { fatal: false }).decode(data);
      return { ok: true, text, bytes };
    }
    return { ok: false, reason: "unsupported-type" };
  });
}
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
      void (() => __async(this, null, function* () {
        var _a;
        const normalized = yield normalizeWsDataToText(event.data);
        if (!normalized.ok) {
          if (normalized.reason === "too-large") {
            console.error("[oclaw-ws] Inbound frame too large; closing connection");
            ws.close();
          } else {
            console.error("[oclaw-ws] Unsupported inbound frame type; ignoring");
          }
          return;
        }
        if (normalized.bytes > MAX_INBOUND_FRAME_BYTES) {
          console.error("[oclaw-ws] Inbound frame too large; closing connection");
          ws.close();
          return;
        }
        let frame;
        try {
          frame = JSON.parse(normalized.text);
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
      }))();
    };
    const clearHandshakeTimer = () => {
      if (handshakeTimer) {
        clearTimeout(handshakeTimer);
        handshakeTimer = null;
      }
    };
    ws.onclose = () => {
      clearHandshakeTimer();
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
      clearHandshakeTimer();
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

// src/linkify.ts
function normalizeBase(base) {
  const trimmed = String(base != null ? base : "").trim();
  if (!trimmed)
    return "";
  return trimmed.endsWith("/") ? trimmed : `${trimmed}/`;
}
function tryMapRemotePathToVaultPath(input, mappings) {
  const raw = String(input != null ? input : "");
  for (const row of mappings) {
    const remoteBase = normalizeBase(row.remoteBase);
    const vaultBase = normalizeBase(row.vaultBase);
    if (!remoteBase || !vaultBase)
      continue;
    if (raw.startsWith(remoteBase)) {
      const rest = raw.slice(remoteBase.length);
      return `${vaultBase}${rest}`.replace(/^\/+/, "");
    }
  }
  return null;
}
var URL_RE = /https?:\/\/[^\s<>()]+/g;
var PATH_RE = new RegExp("(?<![A-Za-z0-9._-])(?:\\/[A-Za-z0-9._~!$&'()*+,;=:@%\\-]+)+(?:\\.[A-Za-z0-9._-]+)?", "g");
var REL_PATH_RE = /\b(?![A-Za-z][A-Za-z0-9+.-]*:\/\/)[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)+(?:\.[A-Za-z0-9._-]+)?\b/g;
function extractCandidates(text) {
  const t = String(text != null ? text : "");
  const out = [];
  for (const m of t.matchAll(URL_RE)) {
    if (m.index === void 0)
      continue;
    out.push({ start: m.index, end: m.index + m[0].length, raw: m[0], kind: "url" });
  }
  for (const m of t.matchAll(PATH_RE)) {
    if (m.index === void 0)
      continue;
    const start = m.index;
    const end = start + m[0].length;
    const overlapsUrl = out.some((c) => c.kind === "url" && !(end <= c.start || start >= c.end));
    if (overlapsUrl)
      continue;
    out.push({ start, end, raw: m[0], kind: "path" });
  }
  for (const m of t.matchAll(REL_PATH_RE)) {
    if (m.index === void 0)
      continue;
    const start = m.index;
    const end = start + m[0].length;
    const overlapsExisting = out.some((c) => !(end <= c.start || start >= c.end));
    if (overlapsExisting)
      continue;
    out.push({ start, end, raw: m[0], kind: "path" });
  }
  out.sort((a, b) => a.start - b.start || (a.kind === "url" ? -1 : 1));
  const dedup = [];
  for (const c of out) {
    const last = dedup[dedup.length - 1];
    if (!last) {
      dedup.push(c);
      continue;
    }
    if (c.start < last.end)
      continue;
    dedup.push(c);
  }
  return dedup;
}

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
    // Connection notices (avoid spam)
    this.lastConnNoticeAtMs = 0;
    this.lastGatewayState = null;
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
        const prev = this.lastGatewayState;
        this.lastGatewayState = state;
        const now = Date.now();
        const NOTICE_THROTTLE_MS = 6e4;
        const shouldNotify = () => now - this.lastConnNoticeAtMs > NOTICE_THROTTLE_MS;
        const notify = (text) => {
          if (!shouldNotify())
            return;
          this.lastConnNoticeAtMs = now;
          new import_obsidian2.Notice(text);
        };
        if (prev === "connected" && state === "disconnected") {
          notify("OpenClaw Chat: connection lost \u2014 reconnecting\u2026");
          this.chatManager.addMessage(ChatManager.createSystemMessage("\u26A0 Connection lost \u2014 reconnecting\u2026", "error"));
        }
        if (prev && prev !== "connected" && state === "connected") {
          notify("OpenClaw Chat: reconnected");
          this.chatManager.addMessage(ChatManager.createSystemMessage("\u2705 Reconnected", "info"));
        }
        this.isConnected = state === "connected";
        this.statusDot.toggleClass("connected", this.isConnected);
        this.statusDot.title = `Gateway: ${state}`;
        this._updateSendButton();
      };
      this.plugin.wsClient.onWorkingChange = (working) => {
        this.isWorking = working;
        this._updateSendButton();
      };
      this.lastGatewayState = this.plugin.wsClient.state;
      this.isConnected = this.plugin.wsClient.state === "connected";
      this.statusDot.toggleClass("connected", this.isConnected);
      this.statusDot.title = `Gateway: ${this.plugin.wsClient.state}`;
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
    var _a, _b, _c, _d;
    (_a = this.messagesEl.querySelector(".oclaw-placeholder")) == null ? void 0 : _a.remove();
    const levelClass = msg.level ? ` ${msg.level}` : "";
    const el = this.messagesEl.createDiv({ cls: `oclaw-message ${msg.role}${levelClass}` });
    const body = el.createDiv({ cls: "oclaw-message-body" });
    if (msg.role === "assistant") {
      const mappings = (_b = this.plugin.settings.pathMappings) != null ? _b : [];
      const sourcePath = (_d = (_c = this.app.workspace.getActiveFile()) == null ? void 0 : _c.path) != null ? _d : "";
      if (this.plugin.settings.renderAssistantMarkdown) {
        const pre = this._preprocessAssistantMarkdown(msg.content, mappings);
        void import_obsidian2.MarkdownRenderer.renderMarkdown(pre, body, sourcePath, this.plugin);
      } else {
        this._renderAssistantPlainWithLinks(body, msg.content, mappings, sourcePath);
      }
    } else {
      body.setText(msg.content);
    }
    this.messagesEl.scrollTop = this.messagesEl.scrollHeight;
  }
  _tryReverseMapUrlToVaultPath(url, mappings) {
    var _a;
    let decoded = url;
    try {
      decoded = decodeURIComponent(url);
    } catch (e) {
    }
    for (const row of mappings) {
      const remoteBase = String((_a = row.remoteBase) != null ? _a : "");
      if (!remoteBase)
        continue;
      const idx = decoded.indexOf(remoteBase);
      if (idx < 0)
        continue;
      const tail = decoded.slice(idx);
      const token = tail.split(/[\s'"<>)]/)[0];
      const mapped = tryMapRemotePathToVaultPath(token, mappings);
      if (mapped && this.app.vault.getAbstractFileByPath(mapped))
        return mapped;
    }
    return null;
  }
  _preprocessAssistantMarkdown(text, mappings) {
    const candidates = extractCandidates(text);
    if (candidates.length === 0)
      return text;
    let out = "";
    let cursor = 0;
    for (const c of candidates) {
      out += text.slice(cursor, c.start);
      cursor = c.end;
      if (c.kind === "url") {
        const mapped2 = this._tryReverseMapUrlToVaultPath(c.raw, mappings);
        out += mapped2 ? `[[${mapped2}]]` : c.raw;
        continue;
      }
      const rawVaultPath = c.raw.replace(/^\/+/, "");
      if (this.app.vault.getAbstractFileByPath(rawVaultPath)) {
        out += `[[${rawVaultPath}]]`;
        continue;
      }
      const mapped = tryMapRemotePathToVaultPath(c.raw, mappings);
      if (!mapped) {
        out += c.raw;
        continue;
      }
      if (!this.app.vault.getAbstractFileByPath(mapped)) {
        out += c.raw;
        continue;
      }
      out += `[[${mapped}]]`;
    }
    out += text.slice(cursor);
    return out;
  }
  _renderAssistantPlainWithLinks(body, text, mappings, sourcePath) {
    const candidates = extractCandidates(text);
    if (candidates.length === 0) {
      body.setText(text);
      return;
    }
    let cursor = 0;
    const appendText = (s) => {
      if (!s)
        return;
      body.appendChild(document.createTextNode(s));
    };
    const appendObsidianLink = (vaultPath) => {
      const display = `[[${vaultPath}]]`;
      const a = body.createEl("a", { text: display, href: "#" });
      a.addEventListener("click", (ev) => {
        ev.preventDefault();
        ev.stopPropagation();
        void this.app.workspace.openLinkText(vaultPath, sourcePath, true);
      });
    };
    const appendExternalUrl = (url) => {
      body.createEl("a", { text: url, href: url });
    };
    const tryReverseMapUrlToVaultPath = (url) => this._tryReverseMapUrlToVaultPath(url, mappings);
    for (const c of candidates) {
      appendText(text.slice(cursor, c.start));
      cursor = c.end;
      if (c.kind === "url") {
        const mapped2 = tryReverseMapUrlToVaultPath(c.raw);
        if (mapped2) {
          appendObsidianLink(mapped2);
        } else {
          appendExternalUrl(c.raw);
        }
        continue;
      }
      const rawVaultPath = c.raw.replace(/^\/+/, "");
      if (this.app.vault.getAbstractFileByPath(rawVaultPath)) {
        appendObsidianLink(rawVaultPath);
        continue;
      }
      const mapped = tryMapRemotePathToVaultPath(c.raw, mappings);
      if (!mapped) {
        appendText(c.raw);
        continue;
      }
      if (!this.app.vault.getAbstractFileByPath(mapped)) {
        appendText(c.raw);
        continue;
      }
      appendObsidianLink(mapped);
    }
    appendText(text.slice(cursor));
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
  allowInsecureWs: false,
  pathMappings: []
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
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsic3JjL21haW4udHMiLCAic3JjL3NldHRpbmdzLnRzIiwgInNyYy93ZWJzb2NrZXQudHMiLCAic3JjL2NoYXQudHMiLCAic3JjL3ZpZXcudHMiLCAic3JjL2xpbmtpZnkudHMiLCAic3JjL2NvbnRleHQudHMiLCAic3JjL3R5cGVzLnRzIl0sCiAgInNvdXJjZXNDb250ZW50IjogWyJpbXBvcnQgeyBOb3RpY2UsIFBsdWdpbiwgV29ya3NwYWNlTGVhZiB9IGZyb20gJ29ic2lkaWFuJztcbmltcG9ydCB7IE9wZW5DbGF3U2V0dGluZ1RhYiB9IGZyb20gJy4vc2V0dGluZ3MnO1xuaW1wb3J0IHsgT2JzaWRpYW5XU0NsaWVudCB9IGZyb20gJy4vd2Vic29ja2V0JztcbmltcG9ydCB7IENoYXRNYW5hZ2VyIH0gZnJvbSAnLi9jaGF0JztcbmltcG9ydCB7IFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFULCBPcGVuQ2xhd0NoYXRWaWV3IH0gZnJvbSAnLi92aWV3JztcbmltcG9ydCB7IERFRkFVTFRfU0VUVElOR1MsIHR5cGUgT3BlbkNsYXdTZXR0aW5ncyB9IGZyb20gJy4vdHlwZXMnO1xuXG5leHBvcnQgZGVmYXVsdCBjbGFzcyBPcGVuQ2xhd1BsdWdpbiBleHRlbmRzIFBsdWdpbiB7XG4gIHNldHRpbmdzITogT3BlbkNsYXdTZXR0aW5ncztcbiAgd3NDbGllbnQhOiBPYnNpZGlhbldTQ2xpZW50O1xuICBjaGF0TWFuYWdlciE6IENoYXRNYW5hZ2VyO1xuXG4gIGFzeW5jIG9ubG9hZCgpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBhd2FpdCB0aGlzLmxvYWRTZXR0aW5ncygpO1xuXG4gICAgdGhpcy53c0NsaWVudCA9IG5ldyBPYnNpZGlhbldTQ2xpZW50KHRoaXMuc2V0dGluZ3Muc2Vzc2lvbktleSwge1xuICAgICAgaWRlbnRpdHlTdG9yZToge1xuICAgICAgICBnZXQ6IGFzeW5jICgpID0+IChhd2FpdCB0aGlzLl9sb2FkRGV2aWNlSWRlbnRpdHkoKSksXG4gICAgICAgIHNldDogYXN5bmMgKGlkZW50aXR5KSA9PiBhd2FpdCB0aGlzLl9zYXZlRGV2aWNlSWRlbnRpdHkoaWRlbnRpdHkpLFxuICAgICAgICBjbGVhcjogYXN5bmMgKCkgPT4gYXdhaXQgdGhpcy5fY2xlYXJEZXZpY2VJZGVudGl0eSgpLFxuICAgICAgfSxcbiAgICB9KTtcbiAgICB0aGlzLmNoYXRNYW5hZ2VyID0gbmV3IENoYXRNYW5hZ2VyKCk7XG5cbiAgICAvLyBXaXJlIGluY29taW5nIFdTIG1lc3NhZ2VzIFx1MjE5MiBDaGF0TWFuYWdlclxuICAgIHRoaXMud3NDbGllbnQub25NZXNzYWdlID0gKG1zZykgPT4ge1xuICAgICAgaWYgKG1zZy50eXBlID09PSAnbWVzc2FnZScpIHtcbiAgICAgICAgdGhpcy5jaGF0TWFuYWdlci5hZGRNZXNzYWdlKENoYXRNYW5hZ2VyLmNyZWF0ZUFzc2lzdGFudE1lc3NhZ2UobXNnLnBheWxvYWQuY29udGVudCkpO1xuICAgICAgfSBlbHNlIGlmIChtc2cudHlwZSA9PT0gJ2Vycm9yJykge1xuICAgICAgICBjb25zdCBlcnJUZXh0ID0gbXNnLnBheWxvYWQubWVzc2FnZSA/PyAnVW5rbm93biBlcnJvciBmcm9tIGdhdGV3YXknO1xuICAgICAgICB0aGlzLmNoYXRNYW5hZ2VyLmFkZE1lc3NhZ2UoQ2hhdE1hbmFnZXIuY3JlYXRlU3lzdGVtTWVzc2FnZShgXHUyNkEwICR7ZXJyVGV4dH1gLCAnZXJyb3InKSk7XG4gICAgICB9XG4gICAgfTtcblxuICAgIC8vIFJlZ2lzdGVyIHRoZSBzaWRlYmFyIHZpZXdcbiAgICB0aGlzLnJlZ2lzdGVyVmlldyhcbiAgICAgIFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFULFxuICAgICAgKGxlYWY6IFdvcmtzcGFjZUxlYWYpID0+IG5ldyBPcGVuQ2xhd0NoYXRWaWV3KGxlYWYsIHRoaXMpXG4gICAgKTtcblxuICAgIC8vIFJpYmJvbiBpY29uIFx1MjAxNCBvcGVucyAvIHJldmVhbHMgdGhlIGNoYXQgc2lkZWJhclxuICAgIHRoaXMuYWRkUmliYm9uSWNvbignbWVzc2FnZS1zcXVhcmUnLCAnT3BlbkNsYXcgQ2hhdCcsICgpID0+IHtcbiAgICAgIHRoaXMuX2FjdGl2YXRlQ2hhdFZpZXcoKTtcbiAgICB9KTtcblxuICAgIC8vIFNldHRpbmdzIHRhYlxuICAgIHRoaXMuYWRkU2V0dGluZ1RhYihuZXcgT3BlbkNsYXdTZXR0aW5nVGFiKHRoaXMuYXBwLCB0aGlzKSk7XG5cbiAgICAvLyBDb21tYW5kIHBhbGV0dGUgZW50cnlcbiAgICB0aGlzLmFkZENvbW1hbmQoe1xuICAgICAgaWQ6ICdvcGVuLW9wZW5jbGF3LWNoYXQnLFxuICAgICAgbmFtZTogJ09wZW4gY2hhdCBzaWRlYmFyJyxcbiAgICAgIGNhbGxiYWNrOiAoKSA9PiB0aGlzLl9hY3RpdmF0ZUNoYXRWaWV3KCksXG4gICAgfSk7XG5cbiAgICAvLyBDb25uZWN0IHRvIGdhdGV3YXkgaWYgdG9rZW4gaXMgY29uZmlndXJlZFxuICAgIGlmICh0aGlzLnNldHRpbmdzLmF1dGhUb2tlbikge1xuICAgICAgdGhpcy5fY29ubmVjdFdTKCk7XG4gICAgfSBlbHNlIHtcbiAgICAgIG5ldyBOb3RpY2UoJ09wZW5DbGF3IENoYXQ6IHBsZWFzZSBjb25maWd1cmUgeW91ciBnYXRld2F5IHRva2VuIGluIFNldHRpbmdzLicpO1xuICAgIH1cblxuICAgIGNvbnNvbGUubG9nKCdbb2NsYXddIFBsdWdpbiBsb2FkZWQnKTtcbiAgfVxuXG4gIGFzeW5jIG9udW5sb2FkKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIHRoaXMud3NDbGllbnQuZGlzY29ubmVjdCgpO1xuICAgIHRoaXMuYXBwLndvcmtzcGFjZS5kZXRhY2hMZWF2ZXNPZlR5cGUoVklFV19UWVBFX09QRU5DTEFXX0NIQVQpO1xuICAgIGNvbnNvbGUubG9nKCdbb2NsYXddIFBsdWdpbiB1bmxvYWRlZCcpO1xuICB9XG5cbiAgYXN5bmMgbG9hZFNldHRpbmdzKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIGNvbnN0IGRhdGEgPSAoYXdhaXQgdGhpcy5sb2FkRGF0YSgpKSA/PyB7fTtcbiAgICAvLyBOT1RFOiBwbHVnaW4gZGF0YSBtYXkgY29udGFpbiBleHRyYSBwcml2YXRlIGZpZWxkcyAoZS5nLiBkZXZpY2UgaWRlbnRpdHkpLiBTZXR0aW5ncyBhcmUgdGhlIHB1YmxpYyBzdWJzZXQuXG4gICAgdGhpcy5zZXR0aW5ncyA9IE9iamVjdC5hc3NpZ24oe30sIERFRkFVTFRfU0VUVElOR1MsIGRhdGEpO1xuICB9XG5cbiAgYXN5bmMgc2F2ZVNldHRpbmdzKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIC8vIFByZXNlcnZlIGFueSBwcml2YXRlIGZpZWxkcyBzdG9yZWQgaW4gcGx1Z2luIGRhdGEuXG4gICAgY29uc3QgZGF0YSA9IChhd2FpdCB0aGlzLmxvYWREYXRhKCkpID8/IHt9O1xuICAgIGF3YWl0IHRoaXMuc2F2ZURhdGEoeyAuLi5kYXRhLCAuLi50aGlzLnNldHRpbmdzIH0pO1xuICB9XG5cbiAgLy8gXHUyNTAwXHUyNTAwIERldmljZSBpZGVudGl0eSBwZXJzaXN0ZW5jZSAocGx1Z2luLXNjb3BlZDsgTk9UIGxvY2FsU3RvcmFnZSkgXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG5cbiAgYXN5bmMgcmVzZXREZXZpY2VJZGVudGl0eSgpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBhd2FpdCB0aGlzLl9jbGVhckRldmljZUlkZW50aXR5KCk7XG4gICAgbmV3IE5vdGljZSgnT3BlbkNsYXcgQ2hhdDogZGV2aWNlIGlkZW50aXR5IHJlc2V0LiBSZWNvbm5lY3QgdG8gcGFpciBhZ2Fpbi4nKTtcbiAgfVxuXG4gIHByaXZhdGUgX2RldmljZUlkZW50aXR5S2V5ID0gJ19vcGVuY2xhd0RldmljZUlkZW50aXR5VjEnO1xuXG4gIHByaXZhdGUgYXN5bmMgX2xvYWREZXZpY2VJZGVudGl0eSgpOiBQcm9taXNlPGFueSB8IG51bGw+IHtcbiAgICBjb25zdCBkYXRhID0gKGF3YWl0IHRoaXMubG9hZERhdGEoKSkgPz8ge307XG4gICAgcmV0dXJuIChkYXRhIGFzIGFueSk/Llt0aGlzLl9kZXZpY2VJZGVudGl0eUtleV0gPz8gbnVsbDtcbiAgfVxuXG4gIHByaXZhdGUgYXN5bmMgX3NhdmVEZXZpY2VJZGVudGl0eShpZGVudGl0eTogYW55KTogUHJvbWlzZTx2b2lkPiB7XG4gICAgY29uc3QgZGF0YSA9IChhd2FpdCB0aGlzLmxvYWREYXRhKCkpID8/IHt9O1xuICAgIGF3YWl0IHRoaXMuc2F2ZURhdGEoeyAuLi5kYXRhLCBbdGhpcy5fZGV2aWNlSWRlbnRpdHlLZXldOiBpZGVudGl0eSB9KTtcbiAgfVxuXG4gIHByaXZhdGUgYXN5bmMgX2NsZWFyRGV2aWNlSWRlbnRpdHkoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgY29uc3QgZGF0YSA9IChhd2FpdCB0aGlzLmxvYWREYXRhKCkpID8/IHt9O1xuICAgIGlmICgoZGF0YSBhcyBhbnkpPy5bdGhpcy5fZGV2aWNlSWRlbnRpdHlLZXldID09PSB1bmRlZmluZWQpIHJldHVybjtcbiAgICBjb25zdCBuZXh0ID0geyAuLi4oZGF0YSBhcyBhbnkpIH07XG4gICAgZGVsZXRlIG5leHRbdGhpcy5fZGV2aWNlSWRlbnRpdHlLZXldO1xuICAgIGF3YWl0IHRoaXMuc2F2ZURhdGEobmV4dCk7XG4gIH1cblxuICAvLyBcdTI1MDBcdTI1MDAgSGVscGVycyBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcblxuICBwcml2YXRlIF9jb25uZWN0V1MoKTogdm9pZCB7XG4gICAgdGhpcy53c0NsaWVudC5jb25uZWN0KHRoaXMuc2V0dGluZ3MuZ2F0ZXdheVVybCwgdGhpcy5zZXR0aW5ncy5hdXRoVG9rZW4sIHtcbiAgICAgIGFsbG93SW5zZWN1cmVXczogdGhpcy5zZXR0aW5ncy5hbGxvd0luc2VjdXJlV3MsXG4gICAgfSk7XG4gIH1cblxuICBwcml2YXRlIGFzeW5jIF9hY3RpdmF0ZUNoYXRWaWV3KCk6IFByb21pc2U8dm9pZD4ge1xuICAgIGNvbnN0IHsgd29ya3NwYWNlIH0gPSB0aGlzLmFwcDtcblxuICAgIC8vIFJldXNlIGV4aXN0aW5nIGxlYWYgaWYgYWxyZWFkeSBvcGVuXG4gICAgY29uc3QgZXhpc3RpbmcgPSB3b3Jrc3BhY2UuZ2V0TGVhdmVzT2ZUeXBlKFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFUKTtcbiAgICBpZiAoZXhpc3RpbmcubGVuZ3RoID4gMCkge1xuICAgICAgd29ya3NwYWNlLnJldmVhbExlYWYoZXhpc3RpbmdbMF0pO1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIC8vIE9wZW4gaW4gcmlnaHQgc2lkZWJhclxuICAgIGNvbnN0IGxlYWYgPSB3b3Jrc3BhY2UuZ2V0UmlnaHRMZWFmKGZhbHNlKTtcbiAgICBpZiAoIWxlYWYpIHJldHVybjtcbiAgICBhd2FpdCBsZWFmLnNldFZpZXdTdGF0ZSh7IHR5cGU6IFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFULCBhY3RpdmU6IHRydWUgfSk7XG4gICAgd29ya3NwYWNlLnJldmVhbExlYWYobGVhZik7XG4gIH1cbn1cbiIsICJpbXBvcnQgeyBBcHAsIFBsdWdpblNldHRpbmdUYWIsIFNldHRpbmcgfSBmcm9tICdvYnNpZGlhbic7XG5pbXBvcnQgdHlwZSBPcGVuQ2xhd1BsdWdpbiBmcm9tICcuL21haW4nO1xuXG5leHBvcnQgY2xhc3MgT3BlbkNsYXdTZXR0aW5nVGFiIGV4dGVuZHMgUGx1Z2luU2V0dGluZ1RhYiB7XG4gIHBsdWdpbjogT3BlbkNsYXdQbHVnaW47XG5cbiAgY29uc3RydWN0b3IoYXBwOiBBcHAsIHBsdWdpbjogT3BlbkNsYXdQbHVnaW4pIHtcbiAgICBzdXBlcihhcHAsIHBsdWdpbik7XG4gICAgdGhpcy5wbHVnaW4gPSBwbHVnaW47XG4gIH1cblxuICBkaXNwbGF5KCk6IHZvaWQge1xuICAgIGNvbnN0IHsgY29udGFpbmVyRWwgfSA9IHRoaXM7XG4gICAgY29udGFpbmVyRWwuZW1wdHkoKTtcblxuICAgIGNvbnRhaW5lckVsLmNyZWF0ZUVsKCdoMicsIHsgdGV4dDogJ09wZW5DbGF3IENoYXQgXHUyMDEzIFNldHRpbmdzJyB9KTtcblxuICAgIG5ldyBTZXR0aW5nKGNvbnRhaW5lckVsKVxuICAgICAgLnNldE5hbWUoJ0dhdGV3YXkgVVJMJylcbiAgICAgIC5zZXREZXNjKCdXZWJTb2NrZXQgVVJMIG9mIHRoZSBPcGVuQ2xhdyBHYXRld2F5IChlLmcuIHdzOi8vaG9zdG5hbWU6MTg3ODkpLicpXG4gICAgICAuYWRkVGV4dCgodGV4dCkgPT5cbiAgICAgICAgdGV4dFxuICAgICAgICAgIC5zZXRQbGFjZWhvbGRlcignd3M6Ly9sb2NhbGhvc3Q6MTg3ODknKVxuICAgICAgICAgIC5zZXRWYWx1ZSh0aGlzLnBsdWdpbi5zZXR0aW5ncy5nYXRld2F5VXJsKVxuICAgICAgICAgIC5vbkNoYW5nZShhc3luYyAodmFsdWUpID0+IHtcbiAgICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLmdhdGV3YXlVcmwgPSB2YWx1ZS50cmltKCk7XG4gICAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgICB9KVxuICAgICAgKTtcblxuICAgIG5ldyBTZXR0aW5nKGNvbnRhaW5lckVsKVxuICAgICAgLnNldE5hbWUoJ0F1dGggdG9rZW4nKVxuICAgICAgLnNldERlc2MoJ011c3QgbWF0Y2ggdGhlIGF1dGhUb2tlbiBpbiB5b3VyIG9wZW5jbGF3Lmpzb24gY2hhbm5lbCBjb25maWcuIE5ldmVyIHNoYXJlZC4nKVxuICAgICAgLmFkZFRleHQoKHRleHQpID0+IHtcbiAgICAgICAgdGV4dFxuICAgICAgICAgIC5zZXRQbGFjZWhvbGRlcignRW50ZXIgdG9rZW5cdTIwMjYnKVxuICAgICAgICAgIC5zZXRWYWx1ZSh0aGlzLnBsdWdpbi5zZXR0aW5ncy5hdXRoVG9rZW4pXG4gICAgICAgICAgLm9uQ2hhbmdlKGFzeW5jICh2YWx1ZSkgPT4ge1xuICAgICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3MuYXV0aFRva2VuID0gdmFsdWU7XG4gICAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgICB9KTtcbiAgICAgICAgLy8gVHJlYXQgYXMgcGFzc3dvcmQgZmllbGQgXHUyMDEzIGRvIG5vdCByZXZlYWwgdG9rZW4gaW4gVUlcbiAgICAgICAgdGV4dC5pbnB1dEVsLnR5cGUgPSAncGFzc3dvcmQnO1xuICAgICAgICB0ZXh0LmlucHV0RWwuYXV0b2NvbXBsZXRlID0gJ29mZic7XG4gICAgICB9KTtcblxuICAgIG5ldyBTZXR0aW5nKGNvbnRhaW5lckVsKVxuICAgICAgLnNldE5hbWUoJ1Nlc3Npb24gS2V5JylcbiAgICAgIC5zZXREZXNjKCdPcGVuQ2xhdyBzZXNzaW9uIHRvIHN1YnNjcmliZSB0byAodXN1YWxseSBcIm1haW5cIikuJylcbiAgICAgIC5hZGRUZXh0KCh0ZXh0KSA9PlxuICAgICAgICB0ZXh0XG4gICAgICAgICAgLnNldFBsYWNlaG9sZGVyKCdtYWluJylcbiAgICAgICAgICAuc2V0VmFsdWUodGhpcy5wbHVnaW4uc2V0dGluZ3Muc2Vzc2lvbktleSlcbiAgICAgICAgICAub25DaGFuZ2UoYXN5bmMgKHZhbHVlKSA9PiB7XG4gICAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5zZXNzaW9uS2V5ID0gdmFsdWUudHJpbSgpIHx8ICdtYWluJztcbiAgICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICAgIH0pXG4gICAgICApO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZSgnQWNjb3VudCBJRCcpXG4gICAgICAuc2V0RGVzYygnT3BlbkNsYXcgYWNjb3VudCBJRCAodXN1YWxseSBcIm1haW5cIikuJylcbiAgICAgIC5hZGRUZXh0KCh0ZXh0KSA9PlxuICAgICAgICB0ZXh0XG4gICAgICAgICAgLnNldFBsYWNlaG9sZGVyKCdtYWluJylcbiAgICAgICAgICAuc2V0VmFsdWUodGhpcy5wbHVnaW4uc2V0dGluZ3MuYWNjb3VudElkKVxuICAgICAgICAgIC5vbkNoYW5nZShhc3luYyAodmFsdWUpID0+IHtcbiAgICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLmFjY291bnRJZCA9IHZhbHVlLnRyaW0oKSB8fCAnbWFpbic7XG4gICAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgICB9KVxuICAgICAgKTtcblxuICAgIG5ldyBTZXR0aW5nKGNvbnRhaW5lckVsKVxuICAgICAgLnNldE5hbWUoJ0luY2x1ZGUgYWN0aXZlIG5vdGUgYnkgZGVmYXVsdCcpXG4gICAgICAuc2V0RGVzYygnUHJlLWNoZWNrIFwiSW5jbHVkZSBhY3RpdmUgbm90ZVwiIGluIHRoZSBjaGF0IHBhbmVsIHdoZW4gaXQgb3BlbnMuJylcbiAgICAgIC5hZGRUb2dnbGUoKHRvZ2dsZSkgPT5cbiAgICAgICAgdG9nZ2xlLnNldFZhbHVlKHRoaXMucGx1Z2luLnNldHRpbmdzLmluY2x1ZGVBY3RpdmVOb3RlKS5vbkNoYW5nZShhc3luYyAodmFsdWUpID0+IHtcbiAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5pbmNsdWRlQWN0aXZlTm90ZSA9IHZhbHVlO1xuICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICB9KVxuICAgICAgKTtcblxuICAgIG5ldyBTZXR0aW5nKGNvbnRhaW5lckVsKVxuICAgICAgLnNldE5hbWUoJ1JlbmRlciBhc3Npc3RhbnQgYXMgTWFya2Rvd24gKHVuc2FmZSknKVxuICAgICAgLnNldERlc2MoXG4gICAgICAgICdPRkYgcmVjb21tZW5kZWQuIElmIGVuYWJsZWQsIGFzc2lzdGFudCBvdXRwdXQgaXMgcmVuZGVyZWQgYXMgT2JzaWRpYW4gTWFya2Rvd24gd2hpY2ggbWF5IHRyaWdnZXIgZW1iZWRzIGFuZCBvdGhlciBwbHVnaW5zXFwnIHBvc3QtcHJvY2Vzc29ycy4nXG4gICAgICApXG4gICAgICAuYWRkVG9nZ2xlKCh0b2dnbGUpID0+XG4gICAgICAgIHRvZ2dsZS5zZXRWYWx1ZSh0aGlzLnBsdWdpbi5zZXR0aW5ncy5yZW5kZXJBc3Npc3RhbnRNYXJrZG93bikub25DaGFuZ2UoYXN5bmMgKHZhbHVlKSA9PiB7XG4gICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3MucmVuZGVyQXNzaXN0YW50TWFya2Rvd24gPSB2YWx1ZTtcbiAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgfSlcbiAgICAgICk7XG5cbiAgICBuZXcgU2V0dGluZyhjb250YWluZXJFbClcbiAgICAgIC5zZXROYW1lKCdBbGxvdyBpbnNlY3VyZSB3czovLyBmb3Igbm9uLWxvY2FsIGdhdGV3YXlzICh1bnNhZmUpJylcbiAgICAgIC5zZXREZXNjKFxuICAgICAgICAnT0ZGIHJlY29tbWVuZGVkLiBJZiBlbmFibGVkLCB5b3UgY2FuIGNvbm5lY3QgdG8gbm9uLWxvY2FsIGdhdGV3YXlzIG92ZXIgd3M6Ly8uIFRoaXMgZXhwb3NlcyB5b3VyIHRva2VuIGFuZCBtZXNzYWdlIGNvbnRlbnQgdG8gbmV0d29yayBhdHRhY2tlcnM7IHByZWZlciB3c3M6Ly8uJ1xuICAgICAgKVxuICAgICAgLmFkZFRvZ2dsZSgodG9nZ2xlKSA9PlxuICAgICAgICB0b2dnbGUuc2V0VmFsdWUodGhpcy5wbHVnaW4uc2V0dGluZ3MuYWxsb3dJbnNlY3VyZVdzKS5vbkNoYW5nZShhc3luYyAodmFsdWUpID0+IHtcbiAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5hbGxvd0luc2VjdXJlV3MgPSB2YWx1ZTtcbiAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgfSlcbiAgICAgICk7XG5cbiAgICBuZXcgU2V0dGluZyhjb250YWluZXJFbClcbiAgICAgIC5zZXROYW1lKCdSZXNldCBkZXZpY2UgaWRlbnRpdHkgKHJlLXBhaXIpJylcbiAgICAgIC5zZXREZXNjKCdDbGVhcnMgdGhlIHN0b3JlZCBkZXZpY2UgaWRlbnRpdHkgdXNlZCBmb3Igb3BlcmF0b3Iud3JpdGUgcGFpcmluZy4gVXNlIHRoaXMgaWYgeW91IHN1c3BlY3QgY29tcHJvbWlzZSBvciBzZWUgXCJkZXZpY2UgaWRlbnRpdHkgbWlzbWF0Y2hcIi4nKVxuICAgICAgLmFkZEJ1dHRvbigoYnRuKSA9PlxuICAgICAgICBidG4uc2V0QnV0dG9uVGV4dCgnUmVzZXQnKS5zZXRXYXJuaW5nKCkub25DbGljayhhc3luYyAoKSA9PiB7XG4gICAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4ucmVzZXREZXZpY2VJZGVudGl0eSgpO1xuICAgICAgICB9KVxuICAgICAgKTtcblxuICAgIC8vIFx1MjUwMFx1MjUwMCBQYXRoIG1hcHBpbmdzIFx1MjUwMFx1MjUwMFxuICAgIGNvbnRhaW5lckVsLmNyZWF0ZUVsKCdoMycsIHsgdGV4dDogJ1BhdGggbWFwcGluZ3MgKHZhdWx0IGJhc2UgXHUyMTkyIHJlbW90ZSBiYXNlKScgfSk7XG4gICAgY29udGFpbmVyRWwuY3JlYXRlRWwoJ3AnLCB7XG4gICAgICB0ZXh0OiAnVXNlZCB0byBjb252ZXJ0IGFzc2lzdGFudCBmaWxlIHJlZmVyZW5jZXMgKHJlbW90ZSBGUyBwYXRocyBvciBleHBvcnRlZCBVUkxzKSBpbnRvIGNsaWNrYWJsZSBPYnNpZGlhbiBsaW5rcy4gRmlyc3QgbWF0Y2ggd2lucy4gT25seSBjcmVhdGVzIGEgbGluayBpZiB0aGUgbWFwcGVkIHZhdWx0IGZpbGUgZXhpc3RzLicsXG4gICAgICBjbHM6ICdzZXR0aW5nLWl0ZW0tZGVzY3JpcHRpb24nLFxuICAgIH0pO1xuXG4gICAgY29uc3QgbWFwcGluZ3MgPSB0aGlzLnBsdWdpbi5zZXR0aW5ncy5wYXRoTWFwcGluZ3MgPz8gW107XG5cbiAgICBjb25zdCByZXJlbmRlciA9IGFzeW5jICgpID0+IHtcbiAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgdGhpcy5kaXNwbGF5KCk7XG4gICAgfTtcblxuICAgIG1hcHBpbmdzLmZvckVhY2goKHJvdywgaWR4KSA9PiB7XG4gICAgICBjb25zdCBzID0gbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAgIC5zZXROYW1lKGBNYXBwaW5nICMke2lkeCArIDF9YClcbiAgICAgICAgLnNldERlc2MoJ3ZhdWx0QmFzZSBcdTIxOTIgcmVtb3RlQmFzZScpO1xuXG4gICAgICBzLmFkZFRleHQoKHQpID0+XG4gICAgICAgIHRcbiAgICAgICAgICAuc2V0UGxhY2Vob2xkZXIoJ3ZhdWx0IGJhc2UgKGUuZy4gZG9jcy8pJylcbiAgICAgICAgICAuc2V0VmFsdWUocm93LnZhdWx0QmFzZSA/PyAnJylcbiAgICAgICAgICAub25DaGFuZ2UoYXN5bmMgKHYpID0+IHtcbiAgICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLnBhdGhNYXBwaW5nc1tpZHhdLnZhdWx0QmFzZSA9IHY7XG4gICAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgICB9KVxuICAgICAgKTtcblxuICAgICAgcy5hZGRUZXh0KCh0KSA9PlxuICAgICAgICB0XG4gICAgICAgICAgLnNldFBsYWNlaG9sZGVyKCdyZW1vdGUgYmFzZSAoZS5nLiAvaG9tZS8uLi4vZG9jcy8pJylcbiAgICAgICAgICAuc2V0VmFsdWUocm93LnJlbW90ZUJhc2UgPz8gJycpXG4gICAgICAgICAgLm9uQ2hhbmdlKGFzeW5jICh2KSA9PiB7XG4gICAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5wYXRoTWFwcGluZ3NbaWR4XS5yZW1vdGVCYXNlID0gdjtcbiAgICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICAgIH0pXG4gICAgICApO1xuXG4gICAgICBzLmFkZEV4dHJhQnV0dG9uKChiKSA9PlxuICAgICAgICBiXG4gICAgICAgICAgLnNldEljb24oJ3RyYXNoJylcbiAgICAgICAgICAuc2V0VG9vbHRpcCgnUmVtb3ZlIG1hcHBpbmcnKVxuICAgICAgICAgIC5vbkNsaWNrKGFzeW5jICgpID0+IHtcbiAgICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLnBhdGhNYXBwaW5ncy5zcGxpY2UoaWR4LCAxKTtcbiAgICAgICAgICAgIGF3YWl0IHJlcmVuZGVyKCk7XG4gICAgICAgICAgfSlcbiAgICAgICk7XG4gICAgfSk7XG5cbiAgICBuZXcgU2V0dGluZyhjb250YWluZXJFbClcbiAgICAgIC5zZXROYW1lKCdBZGQgbWFwcGluZycpXG4gICAgICAuc2V0RGVzYygnQWRkIGEgbmV3IHZhdWx0QmFzZSBcdTIxOTIgcmVtb3RlQmFzZSBtYXBwaW5nIHJvdy4nKVxuICAgICAgLmFkZEJ1dHRvbigoYnRuKSA9PlxuICAgICAgICBidG4uc2V0QnV0dG9uVGV4dCgnQWRkJykub25DbGljayhhc3luYyAoKSA9PiB7XG4gICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3MucGF0aE1hcHBpbmdzLnB1c2goeyB2YXVsdEJhc2U6ICcnLCByZW1vdGVCYXNlOiAnJyB9KTtcbiAgICAgICAgICBhd2FpdCByZXJlbmRlcigpO1xuICAgICAgICB9KVxuICAgICAgKTtcblxuICAgIGNvbnRhaW5lckVsLmNyZWF0ZUVsKCdwJywge1xuICAgICAgdGV4dDogJ1JlY29ubmVjdDogY2xvc2UgYW5kIHJlb3BlbiB0aGUgc2lkZWJhciBhZnRlciBjaGFuZ2luZyB0aGUgZ2F0ZXdheSBVUkwgb3IgdG9rZW4uJyxcbiAgICAgIGNsczogJ3NldHRpbmctaXRlbS1kZXNjcmlwdGlvbicsXG4gICAgfSk7XG4gIH1cbn1cbiIsICIvKipcbiAqIFdlYlNvY2tldCBjbGllbnQgZm9yIE9wZW5DbGF3IEdhdGV3YXlcbiAqXG4gKiBQaXZvdCAoMjAyNi0wMi0yNSk6IERvIE5PVCB1c2UgY3VzdG9tIG9ic2lkaWFuLiogZ2F0ZXdheSBtZXRob2RzLlxuICogVGhvc2UgcmVxdWlyZSBvcGVyYXRvci5hZG1pbiBzY29wZSB3aGljaCBpcyBub3QgZ3JhbnRlZCB0byBleHRlcm5hbCBjbGllbnRzLlxuICpcbiAqIEF1dGggbm90ZTpcbiAqIC0gY2hhdC5zZW5kIHJlcXVpcmVzIG9wZXJhdG9yLndyaXRlXG4gKiAtIGV4dGVybmFsIGNsaWVudHMgbXVzdCBwcmVzZW50IGEgcGFpcmVkIGRldmljZSBpZGVudGl0eSB0byByZWNlaXZlIHdyaXRlIHNjb3Blc1xuICpcbiAqIFdlIHVzZSBidWlsdC1pbiBnYXRld2F5IG1ldGhvZHMvZXZlbnRzOlxuICogLSBTZW5kOiBjaGF0LnNlbmQoeyBzZXNzaW9uS2V5LCBtZXNzYWdlLCBpZGVtcG90ZW5jeUtleSwgLi4uIH0pXG4gKiAtIFJlY2VpdmU6IGV2ZW50IFwiY2hhdFwiIChmaWx0ZXIgYnkgc2Vzc2lvbktleSlcbiAqL1xuXG5pbXBvcnQgdHlwZSB7IEluYm91bmRXU1BheWxvYWQgfSBmcm9tICcuL3R5cGVzJztcblxuZnVuY3Rpb24gaXNMb2NhbEhvc3QoaG9zdDogc3RyaW5nKTogYm9vbGVhbiB7XG4gIGNvbnN0IGggPSBob3N0LnRvTG93ZXJDYXNlKCk7XG4gIHJldHVybiBoID09PSAnbG9jYWxob3N0JyB8fCBoID09PSAnMTI3LjAuMC4xJyB8fCBoID09PSAnOjoxJztcbn1cblxuZnVuY3Rpb24gc2FmZVBhcnNlV3NVcmwodXJsOiBzdHJpbmcpOlxuICB8IHsgb2s6IHRydWU7IHNjaGVtZTogJ3dzJyB8ICd3c3MnOyBob3N0OiBzdHJpbmcgfVxuICB8IHsgb2s6IGZhbHNlOyBlcnJvcjogc3RyaW5nIH0ge1xuICB0cnkge1xuICAgIGNvbnN0IHUgPSBuZXcgVVJMKHVybCk7XG4gICAgaWYgKHUucHJvdG9jb2wgIT09ICd3czonICYmIHUucHJvdG9jb2wgIT09ICd3c3M6Jykge1xuICAgICAgcmV0dXJuIHsgb2s6IGZhbHNlLCBlcnJvcjogYEdhdGV3YXkgVVJMIG11c3QgYmUgd3M6Ly8gb3Igd3NzOi8vIChnb3QgJHt1LnByb3RvY29sfSlgIH07XG4gICAgfVxuICAgIGNvbnN0IHNjaGVtZSA9IHUucHJvdG9jb2wgPT09ICd3czonID8gJ3dzJyA6ICd3c3MnO1xuICAgIHJldHVybiB7IG9rOiB0cnVlLCBzY2hlbWUsIGhvc3Q6IHUuaG9zdG5hbWUgfTtcbiAgfSBjYXRjaCB7XG4gICAgcmV0dXJuIHsgb2s6IGZhbHNlLCBlcnJvcjogJ0ludmFsaWQgZ2F0ZXdheSBVUkwnIH07XG4gIH1cbn1cblxuLyoqIEludGVydmFsIGZvciBzZW5kaW5nIGhlYXJ0YmVhdCBwaW5ncyAoY2hlY2sgY29ubmVjdGlvbiBsaXZlbmVzcykgKi9cbmNvbnN0IEhFQVJUQkVBVF9JTlRFUlZBTF9NUyA9IDMwXzAwMDtcblxuLyoqIFNhZmV0eSB2YWx2ZTogaGlkZSB3b3JraW5nIHNwaW5uZXIgaWYgbm8gYXNzaXN0YW50IHJlcGx5IGFycml2ZXMgaW4gdGltZSAqL1xuY29uc3QgV09SS0lOR19NQVhfTVMgPSAxMjBfMDAwO1xuXG4vKiogTWF4IGluYm91bmQgZnJhbWUgc2l6ZSB0byBwYXJzZSAoRG9TIGd1YXJkKSAqL1xuY29uc3QgTUFYX0lOQk9VTkRfRlJBTUVfQllURVMgPSA1MTIgKiAxMDI0O1xuXG5mdW5jdGlvbiBieXRlTGVuZ3RoVXRmOCh0ZXh0OiBzdHJpbmcpOiBudW1iZXIge1xuICByZXR1cm4gdXRmOEJ5dGVzKHRleHQpLmJ5dGVMZW5ndGg7XG59XG5cbmFzeW5jIGZ1bmN0aW9uIG5vcm1hbGl6ZVdzRGF0YVRvVGV4dChkYXRhOiBhbnkpOiBQcm9taXNlPHsgb2s6IHRydWU7IHRleHQ6IHN0cmluZzsgYnl0ZXM6IG51bWJlciB9IHwgeyBvazogZmFsc2U7IHJlYXNvbjogc3RyaW5nOyBieXRlcz86IG51bWJlciB9PiB7XG4gIGlmICh0eXBlb2YgZGF0YSA9PT0gJ3N0cmluZycpIHtcbiAgICBjb25zdCBieXRlcyA9IGJ5dGVMZW5ndGhVdGY4KGRhdGEpO1xuICAgIHJldHVybiB7IG9rOiB0cnVlLCB0ZXh0OiBkYXRhLCBieXRlcyB9O1xuICB9XG5cbiAgLy8gQnJvd3NlciBXZWJTb2NrZXQgY2FuIGRlbGl2ZXIgQmxvYlxuICBpZiAodHlwZW9mIEJsb2IgIT09ICd1bmRlZmluZWQnICYmIGRhdGEgaW5zdGFuY2VvZiBCbG9iKSB7XG4gICAgY29uc3QgYnl0ZXMgPSBkYXRhLnNpemU7XG4gICAgaWYgKGJ5dGVzID4gTUFYX0lOQk9VTkRfRlJBTUVfQllURVMpIHJldHVybiB7IG9rOiBmYWxzZSwgcmVhc29uOiAndG9vLWxhcmdlJywgYnl0ZXMgfTtcbiAgICBjb25zdCB0ZXh0ID0gYXdhaXQgZGF0YS50ZXh0KCk7XG4gICAgLy8gQmxvYi5zaXplIGlzIGJ5dGVzIGFscmVhZHk7IG5vIG5lZWQgdG8gcmUtbWVhc3VyZS5cbiAgICByZXR1cm4geyBvazogdHJ1ZSwgdGV4dCwgYnl0ZXMgfTtcbiAgfVxuXG4gIGlmIChkYXRhIGluc3RhbmNlb2YgQXJyYXlCdWZmZXIpIHtcbiAgICBjb25zdCBieXRlcyA9IGRhdGEuYnl0ZUxlbmd0aDtcbiAgICBpZiAoYnl0ZXMgPiBNQVhfSU5CT1VORF9GUkFNRV9CWVRFUykgcmV0dXJuIHsgb2s6IGZhbHNlLCByZWFzb246ICd0b28tbGFyZ2UnLCBieXRlcyB9O1xuICAgIGNvbnN0IHRleHQgPSBuZXcgVGV4dERlY29kZXIoJ3V0Zi04JywgeyBmYXRhbDogZmFsc2UgfSkuZGVjb2RlKG5ldyBVaW50OEFycmF5KGRhdGEpKTtcbiAgICByZXR1cm4geyBvazogdHJ1ZSwgdGV4dCwgYnl0ZXMgfTtcbiAgfVxuXG4gIC8vIFNvbWUgcnVudGltZXMgY291bGQgcGFzcyBVaW50OEFycmF5IGRpcmVjdGx5XG4gIGlmIChkYXRhIGluc3RhbmNlb2YgVWludDhBcnJheSkge1xuICAgIGNvbnN0IGJ5dGVzID0gZGF0YS5ieXRlTGVuZ3RoO1xuICAgIGlmIChieXRlcyA+IE1BWF9JTkJPVU5EX0ZSQU1FX0JZVEVTKSByZXR1cm4geyBvazogZmFsc2UsIHJlYXNvbjogJ3Rvby1sYXJnZScsIGJ5dGVzIH07XG4gICAgY29uc3QgdGV4dCA9IG5ldyBUZXh0RGVjb2RlcigndXRmLTgnLCB7IGZhdGFsOiBmYWxzZSB9KS5kZWNvZGUoZGF0YSk7XG4gICAgcmV0dXJuIHsgb2s6IHRydWUsIHRleHQsIGJ5dGVzIH07XG4gIH1cblxuICByZXR1cm4geyBvazogZmFsc2UsIHJlYXNvbjogJ3Vuc3VwcG9ydGVkLXR5cGUnIH07XG59XG5cbi8qKiBNYXggaW4tZmxpZ2h0IHJlcXVlc3RzIGJlZm9yZSBmYXN0LWZhaWxpbmcgKERvUy9yb2J1c3RuZXNzIGd1YXJkKSAqL1xuY29uc3QgTUFYX1BFTkRJTkdfUkVRVUVTVFMgPSAyMDA7XG5cbi8qKiBSZWNvbm5lY3QgYmFja29mZiAqL1xuY29uc3QgUkVDT05ORUNUX0JBU0VfTVMgPSAzXzAwMDtcbmNvbnN0IFJFQ09OTkVDVF9NQVhfTVMgPSA2MF8wMDA7XG5cbi8qKiBIYW5kc2hha2UgZGVhZGxpbmUgd2FpdGluZyBmb3IgY29ubmVjdC5jaGFsbGVuZ2UgKi9cbmNvbnN0IEhBTkRTSEFLRV9USU1FT1VUX01TID0gMTVfMDAwO1xuXG5leHBvcnQgdHlwZSBXU0NsaWVudFN0YXRlID0gJ2Rpc2Nvbm5lY3RlZCcgfCAnY29ubmVjdGluZycgfCAnaGFuZHNoYWtpbmcnIHwgJ2Nvbm5lY3RlZCc7XG5cbmV4cG9ydCB0eXBlIFdvcmtpbmdTdGF0ZUxpc3RlbmVyID0gKHdvcmtpbmc6IGJvb2xlYW4pID0+IHZvaWQ7XG5cbmludGVyZmFjZSBQZW5kaW5nUmVxdWVzdCB7XG4gIHJlc29sdmU6IChwYXlsb2FkOiBhbnkpID0+IHZvaWQ7XG4gIHJlamVjdDogKGVycm9yOiBhbnkpID0+IHZvaWQ7XG4gIHRpbWVvdXQ6IFJldHVyblR5cGU8dHlwZW9mIHNldFRpbWVvdXQ+IHwgbnVsbDtcbn1cblxuZXhwb3J0IHR5cGUgRGV2aWNlSWRlbnRpdHkgPSB7XG4gIGlkOiBzdHJpbmc7XG4gIHB1YmxpY0tleTogc3RyaW5nOyAvLyBiYXNlNjRcbiAgcHJpdmF0ZUtleUp3azogSnNvbldlYktleTtcbn07XG5cbmV4cG9ydCBpbnRlcmZhY2UgRGV2aWNlSWRlbnRpdHlTdG9yZSB7XG4gIGdldCgpOiBQcm9taXNlPERldmljZUlkZW50aXR5IHwgbnVsbD47XG4gIHNldChpZGVudGl0eTogRGV2aWNlSWRlbnRpdHkpOiBQcm9taXNlPHZvaWQ+O1xuICBjbGVhcigpOiBQcm9taXNlPHZvaWQ+O1xufVxuXG5jb25zdCBERVZJQ0VfU1RPUkFHRV9LRVkgPSAnb3BlbmNsYXdDaGF0LmRldmljZUlkZW50aXR5LnYxJzsgLy8gbGVnYWN5IGxvY2FsU3RvcmFnZSBrZXkgKG1pZ3JhdGlvbiBvbmx5KVxuXG5mdW5jdGlvbiBiYXNlNjRVcmxFbmNvZGUoYnl0ZXM6IEFycmF5QnVmZmVyKTogc3RyaW5nIHtcbiAgY29uc3QgdTggPSBuZXcgVWludDhBcnJheShieXRlcyk7XG4gIGxldCBzID0gJyc7XG4gIGZvciAobGV0IGkgPSAwOyBpIDwgdTgubGVuZ3RoOyBpKyspIHMgKz0gU3RyaW5nLmZyb21DaGFyQ29kZSh1OFtpXSk7XG4gIGNvbnN0IGI2NCA9IGJ0b2Eocyk7XG4gIHJldHVybiBiNjQucmVwbGFjZSgvXFwrL2csICctJykucmVwbGFjZSgvXFwvL2csICdfJykucmVwbGFjZSgvPSskL2csICcnKTtcbn1cblxuZnVuY3Rpb24gaGV4RW5jb2RlKGJ5dGVzOiBBcnJheUJ1ZmZlcik6IHN0cmluZyB7XG4gIGNvbnN0IHU4ID0gbmV3IFVpbnQ4QXJyYXkoYnl0ZXMpO1xuICByZXR1cm4gQXJyYXkuZnJvbSh1OClcbiAgICAubWFwKChiKSA9PiBiLnRvU3RyaW5nKDE2KS5wYWRTdGFydCgyLCAnMCcpKVxuICAgIC5qb2luKCcnKTtcbn1cblxuZnVuY3Rpb24gdXRmOEJ5dGVzKHRleHQ6IHN0cmluZyk6IFVpbnQ4QXJyYXkge1xuICByZXR1cm4gbmV3IFRleHRFbmNvZGVyKCkuZW5jb2RlKHRleHQpO1xufVxuXG5hc3luYyBmdW5jdGlvbiBzaGEyNTZIZXgoYnl0ZXM6IEFycmF5QnVmZmVyKTogUHJvbWlzZTxzdHJpbmc+IHtcbiAgY29uc3QgZGlnZXN0ID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5kaWdlc3QoJ1NIQS0yNTYnLCBieXRlcyk7XG4gIHJldHVybiBoZXhFbmNvZGUoZGlnZXN0KTtcbn1cblxuYXN5bmMgZnVuY3Rpb24gbG9hZE9yQ3JlYXRlRGV2aWNlSWRlbnRpdHkoc3RvcmU/OiBEZXZpY2VJZGVudGl0eVN0b3JlKTogUHJvbWlzZTxEZXZpY2VJZGVudGl0eT4ge1xuICAvLyAxKSBQcmVmZXIgcGx1Z2luLXNjb3BlZCBzdG9yYWdlIChpbmplY3RlZCBieSBtYWluIHBsdWdpbikuXG4gIGlmIChzdG9yZSkge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCBleGlzdGluZyA9IGF3YWl0IHN0b3JlLmdldCgpO1xuICAgICAgaWYgKGV4aXN0aW5nPy5pZCAmJiBleGlzdGluZz8ucHVibGljS2V5ICYmIGV4aXN0aW5nPy5wcml2YXRlS2V5SndrKSByZXR1cm4gZXhpc3Rpbmc7XG4gICAgfSBjYXRjaCB7XG4gICAgICAvLyBpZ25vcmUgYW5kIGNvbnRpbnVlICh3ZSBjYW4gYWx3YXlzIHJlLWdlbmVyYXRlKVxuICAgIH1cbiAgfVxuXG4gIC8vIDIpIE9uZS10aW1lIG1pZ3JhdGlvbjogbGVnYWN5IGxvY2FsU3RvcmFnZSBpZGVudGl0eS5cbiAgLy8gTk9URTogdGhpcyByZW1haW5zIGEgcmlzayBib3VuZGFyeTsgd2Ugb25seSByZWFkK2RlbGV0ZSBmb3IgbWlncmF0aW9uLlxuICBjb25zdCBsZWdhY3kgPSBsb2NhbFN0b3JhZ2UuZ2V0SXRlbShERVZJQ0VfU1RPUkFHRV9LRVkpO1xuICBpZiAobGVnYWN5KSB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IHBhcnNlZCA9IEpTT04ucGFyc2UobGVnYWN5KSBhcyBEZXZpY2VJZGVudGl0eTtcbiAgICAgIGlmIChwYXJzZWQ/LmlkICYmIHBhcnNlZD8ucHVibGljS2V5ICYmIHBhcnNlZD8ucHJpdmF0ZUtleUp3aykge1xuICAgICAgICBpZiAoc3RvcmUpIHtcbiAgICAgICAgICBhd2FpdCBzdG9yZS5zZXQocGFyc2VkKTtcbiAgICAgICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbShERVZJQ0VfU1RPUkFHRV9LRVkpO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiBwYXJzZWQ7XG4gICAgICB9XG4gICAgfSBjYXRjaCB7XG4gICAgICAvLyBDb3JydXB0L3BhcnRpYWwgZGF0YSBcdTIxOTIgZGVsZXRlIGFuZCByZS1jcmVhdGUuXG4gICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbShERVZJQ0VfU1RPUkFHRV9LRVkpO1xuICAgIH1cbiAgfVxuXG4gIC8vIDMpIENyZWF0ZSBhIG5ldyBpZGVudGl0eS5cbiAgY29uc3Qga2V5UGFpciA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuZ2VuZXJhdGVLZXkoeyBuYW1lOiAnRWQyNTUxOScgfSwgdHJ1ZSwgWydzaWduJywgJ3ZlcmlmeSddKTtcbiAgY29uc3QgcHViUmF3ID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5leHBvcnRLZXkoJ3JhdycsIGtleVBhaXIucHVibGljS2V5KTtcbiAgY29uc3QgcHJpdkp3ayA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuZXhwb3J0S2V5KCdqd2snLCBrZXlQYWlyLnByaXZhdGVLZXkpO1xuXG4gIC8vIElNUE9SVEFOVDogZGV2aWNlLmlkIG11c3QgYmUgYSBzdGFibGUgZmluZ2VycHJpbnQgZm9yIHRoZSBwdWJsaWMga2V5LlxuICAvLyBUaGUgZ2F0ZXdheSBlbmZvcmNlcyBkZXZpY2VJZCBcdTIxOTQgcHVibGljS2V5IGJpbmRpbmc7IHJhbmRvbSBpZHMgY2FuIGNhdXNlIFwiZGV2aWNlIGlkZW50aXR5IG1pc21hdGNoXCIuXG4gIGNvbnN0IGRldmljZUlkID0gYXdhaXQgc2hhMjU2SGV4KHB1YlJhdyk7XG5cbiAgY29uc3QgaWRlbnRpdHk6IERldmljZUlkZW50aXR5ID0ge1xuICAgIGlkOiBkZXZpY2VJZCxcbiAgICBwdWJsaWNLZXk6IGJhc2U2NFVybEVuY29kZShwdWJSYXcpLFxuICAgIHByaXZhdGVLZXlKd2s6IHByaXZKd2ssXG4gIH07XG5cbiAgaWYgKHN0b3JlKSB7XG4gICAgYXdhaXQgc3RvcmUuc2V0KGlkZW50aXR5KTtcbiAgfSBlbHNlIHtcbiAgICAvLyBGYWxsYmFjayAoc2hvdWxkIG5vdCBoYXBwZW4gaW4gcmVhbCBwbHVnaW4gcnVudGltZSkgXHUyMDE0IGtlZXAgbGVnYWN5IGJlaGF2aW9yLlxuICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKERFVklDRV9TVE9SQUdFX0tFWSwgSlNPTi5zdHJpbmdpZnkoaWRlbnRpdHkpKTtcbiAgfVxuXG4gIHJldHVybiBpZGVudGl0eTtcbn1cblxuZnVuY3Rpb24gYnVpbGREZXZpY2VBdXRoUGF5bG9hZChwYXJhbXM6IHtcbiAgZGV2aWNlSWQ6IHN0cmluZztcbiAgY2xpZW50SWQ6IHN0cmluZztcbiAgY2xpZW50TW9kZTogc3RyaW5nO1xuICByb2xlOiBzdHJpbmc7XG4gIHNjb3Blczogc3RyaW5nW107XG4gIHNpZ25lZEF0TXM6IG51bWJlcjtcbiAgdG9rZW46IHN0cmluZztcbiAgbm9uY2U/OiBzdHJpbmc7XG59KTogc3RyaW5nIHtcbiAgY29uc3QgdmVyc2lvbiA9IHBhcmFtcy5ub25jZSA/ICd2MicgOiAndjEnO1xuICBjb25zdCBzY29wZXMgPSBwYXJhbXMuc2NvcGVzLmpvaW4oJywnKTtcbiAgY29uc3QgYmFzZSA9IFtcbiAgICB2ZXJzaW9uLFxuICAgIHBhcmFtcy5kZXZpY2VJZCxcbiAgICBwYXJhbXMuY2xpZW50SWQsXG4gICAgcGFyYW1zLmNsaWVudE1vZGUsXG4gICAgcGFyYW1zLnJvbGUsXG4gICAgc2NvcGVzLFxuICAgIFN0cmluZyhwYXJhbXMuc2lnbmVkQXRNcyksXG4gICAgcGFyYW1zLnRva2VuIHx8ICcnLFxuICBdO1xuICBpZiAodmVyc2lvbiA9PT0gJ3YyJykgYmFzZS5wdXNoKHBhcmFtcy5ub25jZSB8fCAnJyk7XG4gIHJldHVybiBiYXNlLmpvaW4oJ3wnKTtcbn1cblxuYXN5bmMgZnVuY3Rpb24gc2lnbkRldmljZVBheWxvYWQoaWRlbnRpdHk6IERldmljZUlkZW50aXR5LCBwYXlsb2FkOiBzdHJpbmcpOiBQcm9taXNlPHsgc2lnbmF0dXJlOiBzdHJpbmcgfT4ge1xuICBjb25zdCBwcml2YXRlS2V5ID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5pbXBvcnRLZXkoXG4gICAgJ2p3aycsXG4gICAgaWRlbnRpdHkucHJpdmF0ZUtleUp3ayxcbiAgICB7IG5hbWU6ICdFZDI1NTE5JyB9LFxuICAgIGZhbHNlLFxuICAgIFsnc2lnbiddLFxuICApO1xuXG4gIGNvbnN0IHNpZyA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuc2lnbih7IG5hbWU6ICdFZDI1NTE5JyB9LCBwcml2YXRlS2V5LCB1dGY4Qnl0ZXMocGF5bG9hZCkgYXMgdW5rbm93biBhcyBCdWZmZXJTb3VyY2UpO1xuICByZXR1cm4geyBzaWduYXR1cmU6IGJhc2U2NFVybEVuY29kZShzaWcpIH07XG59XG5cbmZ1bmN0aW9uIGV4dHJhY3RUZXh0RnJvbUdhdGV3YXlNZXNzYWdlKG1zZzogYW55KTogc3RyaW5nIHtcbiAgaWYgKCFtc2cpIHJldHVybiAnJztcblxuICAvLyBNb3N0IGNvbW1vbjogeyByb2xlLCBjb250ZW50IH0gd2hlcmUgY29udGVudCBjYW4gYmUgc3RyaW5nIG9yIFt7dHlwZTondGV4dCcsdGV4dDonLi4uJ31dXG4gIGNvbnN0IGNvbnRlbnQgPSBtc2cuY29udGVudCA/PyBtc2cubWVzc2FnZSA/PyBtc2c7XG4gIGlmICh0eXBlb2YgY29udGVudCA9PT0gJ3N0cmluZycpIHJldHVybiBjb250ZW50O1xuXG4gIGlmIChBcnJheS5pc0FycmF5KGNvbnRlbnQpKSB7XG4gICAgY29uc3QgcGFydHMgPSBjb250ZW50XG4gICAgICAuZmlsdGVyKChjKSA9PiBjICYmIHR5cGVvZiBjID09PSAnb2JqZWN0JyAmJiBjLnR5cGUgPT09ICd0ZXh0JyAmJiB0eXBlb2YgYy50ZXh0ID09PSAnc3RyaW5nJylcbiAgICAgIC5tYXAoKGMpID0+IGMudGV4dCk7XG4gICAgcmV0dXJuIHBhcnRzLmpvaW4oJ1xcbicpO1xuICB9XG5cbiAgLy8gRmFsbGJhY2tcbiAgdHJ5IHtcbiAgICByZXR1cm4gSlNPTi5zdHJpbmdpZnkoY29udGVudCk7XG4gIH0gY2F0Y2gge1xuICAgIHJldHVybiBTdHJpbmcoY29udGVudCk7XG4gIH1cbn1cblxuZnVuY3Rpb24gc2Vzc2lvbktleU1hdGNoZXMoY29uZmlndXJlZDogc3RyaW5nLCBpbmNvbWluZzogc3RyaW5nKTogYm9vbGVhbiB7XG4gIGlmIChpbmNvbWluZyA9PT0gY29uZmlndXJlZCkgcmV0dXJuIHRydWU7XG4gIC8vIE9wZW5DbGF3IHJlc29sdmVzIFwibWFpblwiIHRvIGNhbm9uaWNhbCBzZXNzaW9uIGtleSBsaWtlIFwiYWdlbnQ6bWFpbjptYWluXCIuXG4gIGlmIChjb25maWd1cmVkID09PSAnbWFpbicgJiYgaW5jb21pbmcgPT09ICdhZ2VudDptYWluOm1haW4nKSByZXR1cm4gdHJ1ZTtcbiAgcmV0dXJuIGZhbHNlO1xufVxuXG5leHBvcnQgY2xhc3MgT2JzaWRpYW5XU0NsaWVudCB7XG4gIHByaXZhdGUgd3M6IFdlYlNvY2tldCB8IG51bGwgPSBudWxsO1xuICBwcml2YXRlIHJlY29ubmVjdFRpbWVyOiBSZXR1cm5UeXBlPHR5cGVvZiBzZXRUaW1lb3V0PiB8IG51bGwgPSBudWxsO1xuICBwcml2YXRlIGhlYXJ0YmVhdFRpbWVyOiBSZXR1cm5UeXBlPHR5cGVvZiBzZXRJbnRlcnZhbD4gfCBudWxsID0gbnVsbDtcbiAgcHJpdmF0ZSB3b3JraW5nVGltZXI6IFJldHVyblR5cGU8dHlwZW9mIHNldFRpbWVvdXQ+IHwgbnVsbCA9IG51bGw7XG4gIHByaXZhdGUgaW50ZW50aW9uYWxDbG9zZSA9IGZhbHNlO1xuICBwcml2YXRlIHNlc3Npb25LZXk6IHN0cmluZztcbiAgcHJpdmF0ZSB1cmwgPSAnJztcbiAgcHJpdmF0ZSB0b2tlbiA9ICcnO1xuICBwcml2YXRlIHJlcXVlc3RJZCA9IDA7XG4gIHByaXZhdGUgcGVuZGluZ1JlcXVlc3RzID0gbmV3IE1hcDxzdHJpbmcsIFBlbmRpbmdSZXF1ZXN0PigpO1xuICBwcml2YXRlIHdvcmtpbmcgPSBmYWxzZTtcblxuICAvKiogVGhlIGxhc3QgaW4tZmxpZ2h0IGNoYXQgcnVuIGlkLiBJbiBPcGVuQ2xhdyBXZWJDaGF0IHRoaXMgbWFwcyB0byBjaGF0LnNlbmQgaWRlbXBvdGVuY3lLZXkuICovXG4gIHByaXZhdGUgYWN0aXZlUnVuSWQ6IHN0cmluZyB8IG51bGwgPSBudWxsO1xuXG4gIC8qKiBQcmV2ZW50cyBhYm9ydCBzcGFtbWluZzogd2hpbGUgYW4gYWJvcnQgcmVxdWVzdCBpcyBpbi1mbGlnaHQsIHJldXNlIHRoZSBzYW1lIHByb21pc2UuICovXG4gIHByaXZhdGUgYWJvcnRJbkZsaWdodDogUHJvbWlzZTxib29sZWFuPiB8IG51bGwgPSBudWxsO1xuXG4gIHN0YXRlOiBXU0NsaWVudFN0YXRlID0gJ2Rpc2Nvbm5lY3RlZCc7XG5cbiAgb25NZXNzYWdlOiAoKG1zZzogSW5ib3VuZFdTUGF5bG9hZCkgPT4gdm9pZCkgfCBudWxsID0gbnVsbDtcbiAgb25TdGF0ZUNoYW5nZTogKChzdGF0ZTogV1NDbGllbnRTdGF0ZSkgPT4gdm9pZCkgfCBudWxsID0gbnVsbDtcbiAgb25Xb3JraW5nQ2hhbmdlOiBXb3JraW5nU3RhdGVMaXN0ZW5lciB8IG51bGwgPSBudWxsO1xuXG4gIHByaXZhdGUgaWRlbnRpdHlTdG9yZTogRGV2aWNlSWRlbnRpdHlTdG9yZSB8IHVuZGVmaW5lZDtcbiAgcHJpdmF0ZSBhbGxvd0luc2VjdXJlV3MgPSBmYWxzZTtcblxuICBwcml2YXRlIHJlY29ubmVjdEF0dGVtcHQgPSAwO1xuXG4gIGNvbnN0cnVjdG9yKHNlc3Npb25LZXk6IHN0cmluZywgb3B0cz86IHsgaWRlbnRpdHlTdG9yZT86IERldmljZUlkZW50aXR5U3RvcmU7IGFsbG93SW5zZWN1cmVXcz86IGJvb2xlYW4gfSkge1xuICAgIHRoaXMuc2Vzc2lvbktleSA9IHNlc3Npb25LZXk7XG4gICAgdGhpcy5pZGVudGl0eVN0b3JlID0gb3B0cz8uaWRlbnRpdHlTdG9yZTtcbiAgICB0aGlzLmFsbG93SW5zZWN1cmVXcyA9IEJvb2xlYW4ob3B0cz8uYWxsb3dJbnNlY3VyZVdzKTtcbiAgfVxuXG4gIGNvbm5lY3QodXJsOiBzdHJpbmcsIHRva2VuOiBzdHJpbmcsIG9wdHM/OiB7IGFsbG93SW5zZWN1cmVXcz86IGJvb2xlYW4gfSk6IHZvaWQge1xuICAgIHRoaXMudXJsID0gdXJsO1xuICAgIHRoaXMudG9rZW4gPSB0b2tlbjtcbiAgICB0aGlzLmFsbG93SW5zZWN1cmVXcyA9IEJvb2xlYW4ob3B0cz8uYWxsb3dJbnNlY3VyZVdzID8/IHRoaXMuYWxsb3dJbnNlY3VyZVdzKTtcbiAgICB0aGlzLmludGVudGlvbmFsQ2xvc2UgPSBmYWxzZTtcblxuICAgIC8vIFNlY3VyaXR5OiBibG9jayBub24tbG9jYWwgd3M6Ly8gdW5sZXNzIGV4cGxpY2l0bHkgYWxsb3dlZC5cbiAgICBjb25zdCBwYXJzZWQgPSBzYWZlUGFyc2VXc1VybCh1cmwpO1xuICAgIGlmICghcGFyc2VkLm9rKSB7XG4gICAgICB0aGlzLm9uTWVzc2FnZT8uKHsgdHlwZTogJ2Vycm9yJywgcGF5bG9hZDogeyBtZXNzYWdlOiBwYXJzZWQuZXJyb3IgfSB9KTtcbiAgICAgIHJldHVybjtcbiAgICB9XG4gICAgaWYgKHBhcnNlZC5zY2hlbWUgPT09ICd3cycgJiYgIWlzTG9jYWxIb3N0KHBhcnNlZC5ob3N0KSAmJiAhdGhpcy5hbGxvd0luc2VjdXJlV3MpIHtcbiAgICAgIHRoaXMub25NZXNzYWdlPy4oe1xuICAgICAgICB0eXBlOiAnZXJyb3InLFxuICAgICAgICBwYXlsb2FkOiB7IG1lc3NhZ2U6ICdSZWZ1c2luZyBpbnNlY3VyZSB3czovLyB0byBub24tbG9jYWwgZ2F0ZXdheS4gVXNlIHdzczovLyBvciBlbmFibGUgdGhlIHVuc2FmZSBvdmVycmlkZSBpbiBzZXR0aW5ncy4nIH0sXG4gICAgICB9KTtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICB0aGlzLl9jb25uZWN0KCk7XG4gIH1cblxuICBkaXNjb25uZWN0KCk6IHZvaWQge1xuICAgIHRoaXMuaW50ZW50aW9uYWxDbG9zZSA9IHRydWU7XG4gICAgdGhpcy5fc3RvcFRpbWVycygpO1xuICAgIHRoaXMuYWN0aXZlUnVuSWQgPSBudWxsO1xuICAgIHRoaXMuYWJvcnRJbkZsaWdodCA9IG51bGw7XG4gICAgdGhpcy5fc2V0V29ya2luZyhmYWxzZSk7XG4gICAgaWYgKHRoaXMud3MpIHtcbiAgICAgIHRoaXMud3MuY2xvc2UoKTtcbiAgICAgIHRoaXMud3MgPSBudWxsO1xuICAgIH1cbiAgICB0aGlzLl9zZXRTdGF0ZSgnZGlzY29ubmVjdGVkJyk7XG4gIH1cblxuICBhc3luYyBzZW5kTWVzc2FnZShtZXNzYWdlOiBzdHJpbmcpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBpZiAodGhpcy5zdGF0ZSAhPT0gJ2Nvbm5lY3RlZCcpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcignTm90IGNvbm5lY3RlZCBcdTIwMTQgY2FsbCBjb25uZWN0KCkgZmlyc3QnKTtcbiAgICB9XG5cbiAgICBjb25zdCBydW5JZCA9IGBvYnNpZGlhbi0ke0RhdGUubm93KCl9LSR7TWF0aC5yYW5kb20oKS50b1N0cmluZygzNikuc2xpY2UoMiwgOSl9YDtcblxuICAgIC8vIFNob3cgXHUyMDFDd29ya2luZ1x1MjAxRCBPTkxZIGFmdGVyIHRoZSBnYXRld2F5IGFja25vd2xlZGdlcyB0aGUgcmVxdWVzdC5cbiAgICBjb25zdCBhY2sgPSBhd2FpdCB0aGlzLl9zZW5kUmVxdWVzdCgnY2hhdC5zZW5kJywge1xuICAgICAgc2Vzc2lvbktleTogdGhpcy5zZXNzaW9uS2V5LFxuICAgICAgbWVzc2FnZSxcbiAgICAgIGlkZW1wb3RlbmN5S2V5OiBydW5JZCxcbiAgICAgIC8vIGRlbGl2ZXIgZGVmYXVsdHMgdG8gdHJ1ZSBpbiBnYXRld2F5OyBrZWVwIGRlZmF1bHRcbiAgICB9KTtcblxuICAgIC8vIElmIHRoZSBnYXRld2F5IHJldHVybnMgYSBjYW5vbmljYWwgcnVuIGlkZW50aWZpZXIsIHByZWZlciBpdC5cbiAgICBjb25zdCBjYW5vbmljYWxSdW5JZCA9IFN0cmluZyhhY2s/LnJ1bklkIHx8IGFjaz8uaWRlbXBvdGVuY3lLZXkgfHwgJycpO1xuICAgIHRoaXMuYWN0aXZlUnVuSWQgPSBjYW5vbmljYWxSdW5JZCB8fCBydW5JZDtcbiAgICB0aGlzLl9zZXRXb3JraW5nKHRydWUpO1xuICAgIHRoaXMuX2FybVdvcmtpbmdTYWZldHlUaW1lb3V0KCk7XG4gIH1cblxuICAvKiogQWJvcnQgdGhlIGFjdGl2ZSBydW4gZm9yIHRoaXMgc2Vzc2lvbiAoYW5kIG91ciBsYXN0IHJ1biBpZCBpZiBwcmVzZW50KS4gKi9cbiAgYXN5bmMgYWJvcnRBY3RpdmVSdW4oKTogUHJvbWlzZTxib29sZWFuPiB7XG4gICAgaWYgKHRoaXMuc3RhdGUgIT09ICdjb25uZWN0ZWQnKSB7XG4gICAgICByZXR1cm4gZmFsc2U7XG4gICAgfVxuXG4gICAgLy8gUHJldmVudCByZXF1ZXN0IHN0b3Jtczogd2hpbGUgb25lIGFib3J0IGlzIGluIGZsaWdodCwgcmV1c2UgaXQuXG4gICAgaWYgKHRoaXMuYWJvcnRJbkZsaWdodCkge1xuICAgICAgcmV0dXJuIHRoaXMuYWJvcnRJbkZsaWdodDtcbiAgICB9XG5cbiAgICBjb25zdCBydW5JZCA9IHRoaXMuYWN0aXZlUnVuSWQ7XG4gICAgaWYgKCFydW5JZCkge1xuICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH1cblxuICAgIHRoaXMuYWJvcnRJbkZsaWdodCA9IChhc3luYyAoKSA9PiB7XG4gICAgICB0cnkge1xuICAgICAgICBhd2FpdCB0aGlzLl9zZW5kUmVxdWVzdCgnY2hhdC5hYm9ydCcsIHsgc2Vzc2lvbktleTogdGhpcy5zZXNzaW9uS2V5LCBydW5JZCB9KTtcbiAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICB9IGNhdGNoIChlcnIpIHtcbiAgICAgICAgY29uc29sZS5lcnJvcignW29jbGF3LXdzXSBjaGF0LmFib3J0IGZhaWxlZCcsIGVycik7XG4gICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgIH0gZmluYWxseSB7XG4gICAgICAgIC8vIEFsd2F5cyByZXN0b3JlIFVJIHN0YXRlIGltbWVkaWF0ZWx5OyB0aGUgZ2F0ZXdheSBtYXkgc3RpbGwgZW1pdCBhbiBhYm9ydGVkIGV2ZW50IGxhdGVyLlxuICAgICAgICB0aGlzLmFjdGl2ZVJ1bklkID0gbnVsbDtcbiAgICAgICAgdGhpcy5fc2V0V29ya2luZyhmYWxzZSk7XG4gICAgICAgIHRoaXMuYWJvcnRJbkZsaWdodCA9IG51bGw7XG4gICAgICB9XG4gICAgfSkoKTtcblxuICAgIHJldHVybiB0aGlzLmFib3J0SW5GbGlnaHQ7XG4gIH1cblxuICBwcml2YXRlIF9jb25uZWN0KCk6IHZvaWQge1xuICAgIGlmICh0aGlzLndzKSB7XG4gICAgICB0aGlzLndzLm9ub3BlbiA9IG51bGw7XG4gICAgICB0aGlzLndzLm9uY2xvc2UgPSBudWxsO1xuICAgICAgdGhpcy53cy5vbm1lc3NhZ2UgPSBudWxsO1xuICAgICAgdGhpcy53cy5vbmVycm9yID0gbnVsbDtcbiAgICAgIHRoaXMud3MuY2xvc2UoKTtcbiAgICAgIHRoaXMud3MgPSBudWxsO1xuICAgIH1cblxuICAgIHRoaXMuX3NldFN0YXRlKCdjb25uZWN0aW5nJyk7XG5cbiAgICBjb25zdCB3cyA9IG5ldyBXZWJTb2NrZXQodGhpcy51cmwpO1xuICAgIHRoaXMud3MgPSB3cztcblxuICAgIGxldCBjb25uZWN0Tm9uY2U6IHN0cmluZyB8IG51bGwgPSBudWxsO1xuICAgIGxldCBjb25uZWN0U3RhcnRlZCA9IGZhbHNlO1xuXG4gICAgY29uc3QgdHJ5Q29ubmVjdCA9IGFzeW5jICgpID0+IHtcbiAgICAgIGlmIChjb25uZWN0U3RhcnRlZCkgcmV0dXJuO1xuICAgICAgaWYgKCFjb25uZWN0Tm9uY2UpIHJldHVybjtcbiAgICAgIGNvbm5lY3RTdGFydGVkID0gdHJ1ZTtcblxuICAgICAgdHJ5IHtcbiAgICAgICAgY29uc3QgaWRlbnRpdHkgPSBhd2FpdCBsb2FkT3JDcmVhdGVEZXZpY2VJZGVudGl0eSh0aGlzLmlkZW50aXR5U3RvcmUpO1xuICAgICAgICBjb25zdCBzaWduZWRBdE1zID0gRGF0ZS5ub3coKTtcbiAgICAgICAgY29uc3QgcGF5bG9hZCA9IGJ1aWxkRGV2aWNlQXV0aFBheWxvYWQoe1xuICAgICAgICAgIGRldmljZUlkOiBpZGVudGl0eS5pZCxcbiAgICAgICAgICBjbGllbnRJZDogJ2dhdGV3YXktY2xpZW50JyxcbiAgICAgICAgICBjbGllbnRNb2RlOiAnYmFja2VuZCcsXG4gICAgICAgICAgcm9sZTogJ29wZXJhdG9yJyxcbiAgICAgICAgICBzY29wZXM6IFsnb3BlcmF0b3IucmVhZCcsICdvcGVyYXRvci53cml0ZSddLFxuICAgICAgICAgIHNpZ25lZEF0TXMsXG4gICAgICAgICAgdG9rZW46IHRoaXMudG9rZW4sXG4gICAgICAgICAgbm9uY2U6IGNvbm5lY3ROb25jZSxcbiAgICAgICAgfSk7XG4gICAgICAgIGNvbnN0IHNpZyA9IGF3YWl0IHNpZ25EZXZpY2VQYXlsb2FkKGlkZW50aXR5LCBwYXlsb2FkKTtcblxuICAgICAgICBjb25zdCBhY2sgPSBhd2FpdCB0aGlzLl9zZW5kUmVxdWVzdCgnY29ubmVjdCcsIHtcbiAgICAgICAgICAgbWluUHJvdG9jb2w6IDMsXG4gICAgICAgICAgIG1heFByb3RvY29sOiAzLFxuICAgICAgICAgICBjbGllbnQ6IHtcbiAgICAgICAgICAgICBpZDogJ2dhdGV3YXktY2xpZW50JyxcbiAgICAgICAgICAgICBtb2RlOiAnYmFja2VuZCcsXG4gICAgICAgICAgICAgdmVyc2lvbjogJzAuMS4xMCcsXG4gICAgICAgICAgICAgcGxhdGZvcm06ICdlbGVjdHJvbicsXG4gICAgICAgICAgIH0sXG4gICAgICAgICAgIHJvbGU6ICdvcGVyYXRvcicsXG4gICAgICAgICAgIHNjb3BlczogWydvcGVyYXRvci5yZWFkJywgJ29wZXJhdG9yLndyaXRlJ10sXG4gICAgICAgICAgIGRldmljZToge1xuICAgICAgICAgICAgIGlkOiBpZGVudGl0eS5pZCxcbiAgICAgICAgICAgICBwdWJsaWNLZXk6IGlkZW50aXR5LnB1YmxpY0tleSxcbiAgICAgICAgICAgICBzaWduYXR1cmU6IHNpZy5zaWduYXR1cmUsXG4gICAgICAgICAgICAgc2lnbmVkQXQ6IHNpZ25lZEF0TXMsXG4gICAgICAgICAgICAgbm9uY2U6IGNvbm5lY3ROb25jZSxcbiAgICAgICAgICAgfSxcbiAgICAgICAgICAgYXV0aDoge1xuICAgICAgICAgICAgIHRva2VuOiB0aGlzLnRva2VuLFxuICAgICAgICAgICB9LFxuICAgICAgICAgfSk7XG5cbiAgICAgICAgIHRoaXMuX3NldFN0YXRlKCdjb25uZWN0ZWQnKTtcbiAgICAgICAgIHRoaXMucmVjb25uZWN0QXR0ZW1wdCA9IDA7XG4gICAgICAgICBpZiAoaGFuZHNoYWtlVGltZXIpIHtcbiAgICAgICAgICAgY2xlYXJUaW1lb3V0KGhhbmRzaGFrZVRpbWVyKTtcbiAgICAgICAgICAgaGFuZHNoYWtlVGltZXIgPSBudWxsO1xuICAgICAgICAgfVxuICAgICAgICAgdGhpcy5fc3RhcnRIZWFydGJlYXQoKTtcbiAgICAgIH0gY2F0Y2ggKGVycikge1xuICAgICAgICBjb25zb2xlLmVycm9yKCdbb2NsYXctd3NdIENvbm5lY3QgaGFuZHNoYWtlIGZhaWxlZCcsIGVycik7XG4gICAgICAgIHdzLmNsb3NlKCk7XG4gICAgICB9XG4gICAgfTtcblxuICAgIGxldCBoYW5kc2hha2VUaW1lcjogUmV0dXJuVHlwZTx0eXBlb2Ygc2V0VGltZW91dD4gfCBudWxsID0gbnVsbDtcblxuICAgIHdzLm9ub3BlbiA9ICgpID0+IHtcbiAgICAgIHRoaXMuX3NldFN0YXRlKCdoYW5kc2hha2luZycpO1xuICAgICAgLy8gVGhlIGdhdGV3YXkgd2lsbCBzZW5kIGNvbm5lY3QuY2hhbGxlbmdlOyBjb25uZWN0IGlzIHNlbnQgb25jZSB3ZSBoYXZlIGEgbm9uY2UuXG4gICAgICBpZiAoaGFuZHNoYWtlVGltZXIpIGNsZWFyVGltZW91dChoYW5kc2hha2VUaW1lcik7XG4gICAgICBoYW5kc2hha2VUaW1lciA9IHNldFRpbWVvdXQoKCkgPT4ge1xuICAgICAgICAvLyBJZiB3ZSBuZXZlciBnb3QgdGhlIGNoYWxsZW5nZSBub25jZSwgZm9yY2UgcmVjb25uZWN0LlxuICAgICAgICBpZiAodGhpcy5zdGF0ZSA9PT0gJ2hhbmRzaGFraW5nJyAmJiAhdGhpcy5pbnRlbnRpb25hbENsb3NlKSB7XG4gICAgICAgICAgY29uc29sZS53YXJuKCdbb2NsYXctd3NdIEhhbmRzaGFrZSB0aW1lZCBvdXQgd2FpdGluZyBmb3IgY29ubmVjdC5jaGFsbGVuZ2UnKTtcbiAgICAgICAgICB3cy5jbG9zZSgpO1xuICAgICAgICB9XG4gICAgICB9LCBIQU5EU0hBS0VfVElNRU9VVF9NUyk7XG4gICAgfTtcblxuICAgIHdzLm9ubWVzc2FnZSA9IChldmVudDogTWVzc2FnZUV2ZW50KSA9PiB7XG4gICAgICAvLyBXZWJTb2NrZXQgb25tZXNzYWdlIGNhbm5vdCBiZSBhc3luYywgYnV0IHdlIGNhbiBydW4gYW4gYXN5bmMgdGFzayBpbnNpZGUuXG4gICAgICB2b2lkIChhc3luYyAoKSA9PiB7XG4gICAgICAgIGNvbnN0IG5vcm1hbGl6ZWQgPSBhd2FpdCBub3JtYWxpemVXc0RhdGFUb1RleHQoZXZlbnQuZGF0YSk7XG4gICAgICAgIGlmICghbm9ybWFsaXplZC5vaykge1xuICAgICAgICAgIGlmIChub3JtYWxpemVkLnJlYXNvbiA9PT0gJ3Rvby1sYXJnZScpIHtcbiAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IoJ1tvY2xhdy13c10gSW5ib3VuZCBmcmFtZSB0b28gbGFyZ2U7IGNsb3NpbmcgY29ubmVjdGlvbicpO1xuICAgICAgICAgICAgd3MuY2xvc2UoKTtcbiAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgY29uc29sZS5lcnJvcignW29jbGF3LXdzXSBVbnN1cHBvcnRlZCBpbmJvdW5kIGZyYW1lIHR5cGU7IGlnbm9yaW5nJyk7XG4gICAgICAgICAgfVxuICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmIChub3JtYWxpemVkLmJ5dGVzID4gTUFYX0lOQk9VTkRfRlJBTUVfQllURVMpIHtcbiAgICAgICAgICBjb25zb2xlLmVycm9yKCdbb2NsYXctd3NdIEluYm91bmQgZnJhbWUgdG9vIGxhcmdlOyBjbG9zaW5nIGNvbm5lY3Rpb24nKTtcbiAgICAgICAgICB3cy5jbG9zZSgpO1xuICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIGxldCBmcmFtZTogYW55O1xuICAgICAgICB0cnkge1xuICAgICAgICAgIGZyYW1lID0gSlNPTi5wYXJzZShub3JtYWxpemVkLnRleHQpO1xuICAgICAgICB9IGNhdGNoIHtcbiAgICAgICAgICBjb25zb2xlLmVycm9yKCdbb2NsYXctd3NdIEZhaWxlZCB0byBwYXJzZSBpbmNvbWluZyBtZXNzYWdlJyk7XG4gICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgLy8gUmVzcG9uc2VzXG4gICAgICAgIGlmIChmcmFtZS50eXBlID09PSAncmVzJykge1xuICAgICAgICAgIHRoaXMuX2hhbmRsZVJlc3BvbnNlRnJhbWUoZnJhbWUpO1xuICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIC8vIEV2ZW50c1xuICAgICAgICBpZiAoZnJhbWUudHlwZSA9PT0gJ2V2ZW50Jykge1xuICAgICAgICAgIGlmIChmcmFtZS5ldmVudCA9PT0gJ2Nvbm5lY3QuY2hhbGxlbmdlJykge1xuICAgICAgICAgICAgY29ubmVjdE5vbmNlID0gZnJhbWUucGF5bG9hZD8ubm9uY2UgfHwgbnVsbDtcbiAgICAgICAgICAgIC8vIEF0dGVtcHQgaGFuZHNoYWtlIG9uY2Ugd2UgaGF2ZSBhIG5vbmNlLlxuICAgICAgICAgICAgdm9pZCB0cnlDb25uZWN0KCk7XG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgaWYgKGZyYW1lLmV2ZW50ID09PSAnY2hhdCcpIHtcbiAgICAgICAgICAgIHRoaXMuX2hhbmRsZUNoYXRFdmVudEZyYW1lKGZyYW1lKTtcbiAgICAgICAgICB9XG4gICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgLy8gQXZvaWQgbG9nZ2luZyBmdWxsIGZyYW1lcyAobWF5IGluY2x1ZGUgbWVzc2FnZSBjb250ZW50IG9yIG90aGVyIHNlbnNpdGl2ZSBwYXlsb2FkcykuXG4gICAgICAgIGNvbnNvbGUuZGVidWcoJ1tvY2xhdy13c10gVW5oYW5kbGVkIGZyYW1lJywgeyB0eXBlOiBmcmFtZT8udHlwZSwgZXZlbnQ6IGZyYW1lPy5ldmVudCwgaWQ6IGZyYW1lPy5pZCB9KTtcbiAgICAgIH0pKCk7XG4gICAgfTtcblxuICAgIGNvbnN0IGNsZWFySGFuZHNoYWtlVGltZXIgPSAoKSA9PiB7XG4gICAgICBpZiAoaGFuZHNoYWtlVGltZXIpIHtcbiAgICAgICAgY2xlYXJUaW1lb3V0KGhhbmRzaGFrZVRpbWVyKTtcbiAgICAgICAgaGFuZHNoYWtlVGltZXIgPSBudWxsO1xuICAgICAgfVxuICAgIH07XG5cbiAgICB3cy5vbmNsb3NlID0gKCkgPT4ge1xuICAgICAgY2xlYXJIYW5kc2hha2VUaW1lcigpO1xuICAgICAgdGhpcy5fc3RvcFRpbWVycygpO1xuICAgICAgdGhpcy5hY3RpdmVSdW5JZCA9IG51bGw7XG4gICAgICB0aGlzLmFib3J0SW5GbGlnaHQgPSBudWxsO1xuICAgICAgdGhpcy5fc2V0V29ya2luZyhmYWxzZSk7XG4gICAgICB0aGlzLl9zZXRTdGF0ZSgnZGlzY29ubmVjdGVkJyk7XG5cbiAgICAgIGZvciAoY29uc3QgcGVuZGluZyBvZiB0aGlzLnBlbmRpbmdSZXF1ZXN0cy52YWx1ZXMoKSkge1xuICAgICAgICBpZiAocGVuZGluZy50aW1lb3V0KSBjbGVhclRpbWVvdXQocGVuZGluZy50aW1lb3V0KTtcbiAgICAgICAgcGVuZGluZy5yZWplY3QobmV3IEVycm9yKCdDb25uZWN0aW9uIGNsb3NlZCcpKTtcbiAgICAgIH1cbiAgICAgIHRoaXMucGVuZGluZ1JlcXVlc3RzLmNsZWFyKCk7XG5cbiAgICAgIGlmICghdGhpcy5pbnRlbnRpb25hbENsb3NlKSB7XG4gICAgICAgIHRoaXMuX3NjaGVkdWxlUmVjb25uZWN0KCk7XG4gICAgICB9XG4gICAgfTtcblxuICAgIHdzLm9uZXJyb3IgPSAoZXY6IEV2ZW50KSA9PiB7XG4gICAgICBjbGVhckhhbmRzaGFrZVRpbWVyKCk7XG4gICAgICBjb25zb2xlLmVycm9yKCdbb2NsYXctd3NdIFdlYlNvY2tldCBlcnJvcicsIGV2KTtcbiAgICB9O1xuICB9XG5cbiAgcHJpdmF0ZSBfaGFuZGxlUmVzcG9uc2VGcmFtZShmcmFtZTogYW55KTogdm9pZCB7XG4gICAgY29uc3QgcGVuZGluZyA9IHRoaXMucGVuZGluZ1JlcXVlc3RzLmdldChmcmFtZS5pZCk7XG4gICAgaWYgKCFwZW5kaW5nKSByZXR1cm47XG5cbiAgICB0aGlzLnBlbmRpbmdSZXF1ZXN0cy5kZWxldGUoZnJhbWUuaWQpO1xuICAgIGlmIChwZW5kaW5nLnRpbWVvdXQpIGNsZWFyVGltZW91dChwZW5kaW5nLnRpbWVvdXQpO1xuXG4gICAgaWYgKGZyYW1lLm9rKSBwZW5kaW5nLnJlc29sdmUoZnJhbWUucGF5bG9hZCk7XG4gICAgZWxzZSBwZW5kaW5nLnJlamVjdChuZXcgRXJyb3IoZnJhbWUuZXJyb3I/Lm1lc3NhZ2UgfHwgJ1JlcXVlc3QgZmFpbGVkJykpO1xuICB9XG5cbiAgcHJpdmF0ZSBfaGFuZGxlQ2hhdEV2ZW50RnJhbWUoZnJhbWU6IGFueSk6IHZvaWQge1xuICAgIGNvbnN0IHBheWxvYWQgPSBmcmFtZS5wYXlsb2FkO1xuICAgIGNvbnN0IGluY29taW5nU2Vzc2lvbktleSA9IFN0cmluZyhwYXlsb2FkPy5zZXNzaW9uS2V5IHx8ICcnKTtcbiAgICBpZiAoIWluY29taW5nU2Vzc2lvbktleSB8fCAhc2Vzc2lvbktleU1hdGNoZXModGhpcy5zZXNzaW9uS2V5LCBpbmNvbWluZ1Nlc3Npb25LZXkpKSB7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgLy8gQmVzdC1lZmZvcnQgcnVuIGNvcnJlbGF0aW9uIChpZiBnYXRld2F5IGluY2x1ZGVzIGEgcnVuIGlkKS4gVGhpcyBhdm9pZHMgY2xlYXJpbmcgb3VyIFVJXG4gICAgLy8gYmFzZWQgb24gYSBkaWZmZXJlbnQgY2xpZW50J3MgcnVuIGluIHRoZSBzYW1lIHNlc3Npb24uXG4gICAgY29uc3QgaW5jb21pbmdSdW5JZCA9IFN0cmluZyhwYXlsb2FkPy5ydW5JZCB8fCBwYXlsb2FkPy5pZGVtcG90ZW5jeUtleSB8fCBwYXlsb2FkPy5tZXRhPy5ydW5JZCB8fCAnJyk7XG4gICAgaWYgKHRoaXMuYWN0aXZlUnVuSWQgJiYgaW5jb21pbmdSdW5JZCAmJiBpbmNvbWluZ1J1bklkICE9PSB0aGlzLmFjdGl2ZVJ1bklkKSB7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgLy8gQXZvaWQgZG91YmxlLXJlbmRlcjogZ2F0ZXdheSBlbWl0cyBkZWx0YSArIGZpbmFsICsgYWJvcnRlZC4gUmVuZGVyIG9ubHkgZXhwbGljaXQgZmluYWwvYWJvcnRlZC5cbiAgICAvLyBJZiBzdGF0ZSBpcyBtaXNzaW5nLCB0cmVhdCBhcyBub24tdGVybWluYWwgKGRvIG5vdCBjbGVhciBVSSAvIGRvIG5vdCByZW5kZXIpLlxuICAgIGlmICghcGF5bG9hZD8uc3RhdGUpIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG4gICAgaWYgKHBheWxvYWQuc3RhdGUgIT09ICdmaW5hbCcgJiYgcGF5bG9hZC5zdGF0ZSAhPT0gJ2Fib3J0ZWQnKSB7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgLy8gV2Ugb25seSBhcHBlbmQgYXNzaXN0YW50IG91dHB1dCB0byBVSS5cbiAgICBjb25zdCBtc2cgPSBwYXlsb2FkPy5tZXNzYWdlO1xuICAgIGNvbnN0IHJvbGUgPSBtc2c/LnJvbGUgPz8gJ2Fzc2lzdGFudCc7XG5cbiAgICAvLyBBYm9ydGVkIGVuZHMgdGhlIHJ1biByZWdhcmRsZXNzIG9mIHJvbGUvbWVzc2FnZS5cbiAgICBpZiAocGF5bG9hZC5zdGF0ZSA9PT0gJ2Fib3J0ZWQnKSB7XG4gICAgICB0aGlzLmFjdGl2ZVJ1bklkID0gbnVsbDtcbiAgICAgIHRoaXMuX3NldFdvcmtpbmcoZmFsc2UpO1xuICAgICAgLy8gQWJvcnRlZCBtYXkgaGF2ZSBubyBhc3Npc3RhbnQgbWVzc2FnZTsgaWYgbm9uZSwgc3RvcCBoZXJlLlxuICAgICAgaWYgKCFtc2cpIHJldHVybjtcbiAgICAgIC8vIElmIHRoZXJlIGlzIGEgbWVzc2FnZSwgb25seSBhcHBlbmQgYXNzaXN0YW50IG91dHB1dC5cbiAgICAgIGlmIChyb2xlICE9PSAnYXNzaXN0YW50JykgcmV0dXJuO1xuICAgIH1cblxuICAgIC8vIEZpbmFsIHNob3VsZCBvbmx5IGNvbXBsZXRlIHRoZSBydW4gd2hlbiB0aGUgYXNzaXN0YW50IGNvbXBsZXRlcy5cbiAgICBpZiAocGF5bG9hZC5zdGF0ZSA9PT0gJ2ZpbmFsJykge1xuICAgICAgaWYgKHJvbGUgIT09ICdhc3Npc3RhbnQnKSByZXR1cm47XG4gICAgICB0aGlzLmFjdGl2ZVJ1bklkID0gbnVsbDtcbiAgICAgIHRoaXMuX3NldFdvcmtpbmcoZmFsc2UpO1xuICAgIH1cblxuICAgIGNvbnN0IHRleHQgPSBleHRyYWN0VGV4dEZyb21HYXRld2F5TWVzc2FnZShtc2cpO1xuICAgIGlmICghdGV4dCkgcmV0dXJuO1xuXG4gICAgLy8gT3B0aW9uYWw6IGhpZGUgaGVhcnRiZWF0IGFja3MgKG5vaXNlIGluIFVJKVxuICAgIGlmICh0ZXh0LnRyaW0oKSA9PT0gJ0hFQVJUQkVBVF9PSycpIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICB0aGlzLm9uTWVzc2FnZT8uKHtcbiAgICAgIHR5cGU6ICdtZXNzYWdlJyxcbiAgICAgIHBheWxvYWQ6IHtcbiAgICAgICAgY29udGVudDogdGV4dCxcbiAgICAgICAgcm9sZTogJ2Fzc2lzdGFudCcsXG4gICAgICAgIHRpbWVzdGFtcDogRGF0ZS5ub3coKSxcbiAgICAgIH0sXG4gICAgfSk7XG4gIH1cblxuICBwcml2YXRlIF9zZW5kUmVxdWVzdChtZXRob2Q6IHN0cmluZywgcGFyYW1zOiBhbnkpOiBQcm9taXNlPGFueT4ge1xuICAgIHJldHVybiBuZXcgUHJvbWlzZSgocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICBpZiAoIXRoaXMud3MgfHwgdGhpcy53cy5yZWFkeVN0YXRlICE9PSBXZWJTb2NrZXQuT1BFTikge1xuICAgICAgICByZWplY3QobmV3IEVycm9yKCdXZWJTb2NrZXQgbm90IGNvbm5lY3RlZCcpKTtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuXG4gICAgICBpZiAodGhpcy5wZW5kaW5nUmVxdWVzdHMuc2l6ZSA+PSBNQVhfUEVORElOR19SRVFVRVNUUykge1xuICAgICAgICByZWplY3QobmV3IEVycm9yKGBUb28gbWFueSBpbi1mbGlnaHQgcmVxdWVzdHMgKCR7dGhpcy5wZW5kaW5nUmVxdWVzdHMuc2l6ZX0pYCkpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG5cbiAgICAgIGNvbnN0IGlkID0gYHJlcS0keysrdGhpcy5yZXF1ZXN0SWR9YDtcblxuICAgICAgY29uc3QgcGVuZGluZzogUGVuZGluZ1JlcXVlc3QgPSB7IHJlc29sdmUsIHJlamVjdCwgdGltZW91dDogbnVsbCB9O1xuICAgICAgdGhpcy5wZW5kaW5nUmVxdWVzdHMuc2V0KGlkLCBwZW5kaW5nKTtcblxuICAgICAgY29uc3QgcGF5bG9hZCA9IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdHlwZTogJ3JlcScsXG4gICAgICAgIG1ldGhvZCxcbiAgICAgICAgaWQsXG4gICAgICAgIHBhcmFtcyxcbiAgICAgIH0pO1xuXG4gICAgICB0cnkge1xuICAgICAgICB0aGlzLndzLnNlbmQocGF5bG9hZCk7XG4gICAgICB9IGNhdGNoIChlcnIpIHtcbiAgICAgICAgdGhpcy5wZW5kaW5nUmVxdWVzdHMuZGVsZXRlKGlkKTtcbiAgICAgICAgcmVqZWN0KGVycik7XG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cblxuICAgICAgcGVuZGluZy50aW1lb3V0ID0gc2V0VGltZW91dCgoKSA9PiB7XG4gICAgICAgIGlmICh0aGlzLnBlbmRpbmdSZXF1ZXN0cy5oYXMoaWQpKSB7XG4gICAgICAgICAgdGhpcy5wZW5kaW5nUmVxdWVzdHMuZGVsZXRlKGlkKTtcbiAgICAgICAgICByZWplY3QobmV3IEVycm9yKGBSZXF1ZXN0IHRpbWVvdXQ6ICR7bWV0aG9kfWApKTtcbiAgICAgICAgfVxuICAgICAgfSwgMzBfMDAwKTtcbiAgICB9KTtcbiAgfVxuXG4gIHByaXZhdGUgX3NjaGVkdWxlUmVjb25uZWN0KCk6IHZvaWQge1xuICAgIGlmICh0aGlzLnJlY29ubmVjdFRpbWVyICE9PSBudWxsKSByZXR1cm47XG5cbiAgICBjb25zdCBhdHRlbXB0ID0gKyt0aGlzLnJlY29ubmVjdEF0dGVtcHQ7XG4gICAgY29uc3QgZXhwID0gTWF0aC5taW4oUkVDT05ORUNUX01BWF9NUywgUkVDT05ORUNUX0JBU0VfTVMgKiBNYXRoLnBvdygyLCBhdHRlbXB0IC0gMSkpO1xuICAgIC8vIEppdHRlcjogMC41eC4uMS41eFxuICAgIGNvbnN0IGppdHRlciA9IDAuNSArIE1hdGgucmFuZG9tKCk7XG4gICAgY29uc3QgZGVsYXkgPSBNYXRoLmZsb29yKGV4cCAqIGppdHRlcik7XG5cbiAgICB0aGlzLnJlY29ubmVjdFRpbWVyID0gc2V0VGltZW91dCgoKSA9PiB7XG4gICAgICB0aGlzLnJlY29ubmVjdFRpbWVyID0gbnVsbDtcbiAgICAgIGlmICghdGhpcy5pbnRlbnRpb25hbENsb3NlKSB7XG4gICAgICAgIGNvbnNvbGUubG9nKGBbb2NsYXctd3NdIFJlY29ubmVjdGluZyB0byAke3RoaXMudXJsfVx1MjAyNiAoYXR0ZW1wdCAke2F0dGVtcHR9LCAke2RlbGF5fW1zKWApO1xuICAgICAgICB0aGlzLl9jb25uZWN0KCk7XG4gICAgICB9XG4gICAgfSwgZGVsYXkpO1xuICB9XG5cbiAgcHJpdmF0ZSBsYXN0QnVmZmVyZWRXYXJuQXRNcyA9IDA7XG5cbiAgcHJpdmF0ZSBfc3RhcnRIZWFydGJlYXQoKTogdm9pZCB7XG4gICAgdGhpcy5fc3RvcEhlYXJ0YmVhdCgpO1xuICAgIHRoaXMuaGVhcnRiZWF0VGltZXIgPSBzZXRJbnRlcnZhbCgoKSA9PiB7XG4gICAgICBpZiAodGhpcy53cz8ucmVhZHlTdGF0ZSAhPT0gV2ViU29ja2V0Lk9QRU4pIHJldHVybjtcbiAgICAgIGlmICh0aGlzLndzLmJ1ZmZlcmVkQW1vdW50ID4gMCkge1xuICAgICAgICBjb25zdCBub3cgPSBEYXRlLm5vdygpO1xuICAgICAgICAvLyBUaHJvdHRsZSB0byBhdm9pZCBsb2cgc3BhbSBpbiBsb25nLXJ1bm5pbmcgc2Vzc2lvbnMuXG4gICAgICAgIGlmIChub3cgLSB0aGlzLmxhc3RCdWZmZXJlZFdhcm5BdE1zID4gNSAqIDYwXzAwMCkge1xuICAgICAgICAgIHRoaXMubGFzdEJ1ZmZlcmVkV2FybkF0TXMgPSBub3c7XG4gICAgICAgICAgY29uc29sZS53YXJuKCdbb2NsYXctd3NdIFNlbmQgYnVmZmVyIG5vdCBlbXB0eSBcdTIwMTQgY29ubmVjdGlvbiBtYXkgYmUgc3RhbGxlZCcpO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSwgSEVBUlRCRUFUX0lOVEVSVkFMX01TKTtcbiAgfVxuXG4gIHByaXZhdGUgX3N0b3BIZWFydGJlYXQoKTogdm9pZCB7XG4gICAgaWYgKHRoaXMuaGVhcnRiZWF0VGltZXIpIHtcbiAgICAgIGNsZWFySW50ZXJ2YWwodGhpcy5oZWFydGJlYXRUaW1lcik7XG4gICAgICB0aGlzLmhlYXJ0YmVhdFRpbWVyID0gbnVsbDtcbiAgICB9XG4gIH1cblxuICBwcml2YXRlIF9zdG9wVGltZXJzKCk6IHZvaWQge1xuICAgIHRoaXMuX3N0b3BIZWFydGJlYXQoKTtcbiAgICB0aGlzLl9kaXNhcm1Xb3JraW5nU2FmZXR5VGltZW91dCgpO1xuICAgIGlmICh0aGlzLnJlY29ubmVjdFRpbWVyKSB7XG4gICAgICBjbGVhclRpbWVvdXQodGhpcy5yZWNvbm5lY3RUaW1lcik7XG4gICAgICB0aGlzLnJlY29ubmVjdFRpbWVyID0gbnVsbDtcbiAgICB9XG4gIH1cblxuICBwcml2YXRlIF9zZXRTdGF0ZShzdGF0ZTogV1NDbGllbnRTdGF0ZSk6IHZvaWQge1xuICAgIGlmICh0aGlzLnN0YXRlID09PSBzdGF0ZSkgcmV0dXJuO1xuICAgIHRoaXMuc3RhdGUgPSBzdGF0ZTtcbiAgICB0aGlzLm9uU3RhdGVDaGFuZ2U/LihzdGF0ZSk7XG4gIH1cblxuICBwcml2YXRlIF9zZXRXb3JraW5nKHdvcmtpbmc6IGJvb2xlYW4pOiB2b2lkIHtcbiAgICBpZiAodGhpcy53b3JraW5nID09PSB3b3JraW5nKSByZXR1cm47XG4gICAgdGhpcy53b3JraW5nID0gd29ya2luZztcbiAgICB0aGlzLm9uV29ya2luZ0NoYW5nZT8uKHdvcmtpbmcpO1xuXG4gICAgaWYgKCF3b3JraW5nKSB7XG4gICAgICB0aGlzLl9kaXNhcm1Xb3JraW5nU2FmZXR5VGltZW91dCgpO1xuICAgIH1cbiAgfVxuXG4gIHByaXZhdGUgX2FybVdvcmtpbmdTYWZldHlUaW1lb3V0KCk6IHZvaWQge1xuICAgIHRoaXMuX2Rpc2FybVdvcmtpbmdTYWZldHlUaW1lb3V0KCk7XG4gICAgdGhpcy53b3JraW5nVGltZXIgPSBzZXRUaW1lb3V0KCgpID0+IHtcbiAgICAgIC8vIElmIHRoZSBnYXRld2F5IG5ldmVyIGVtaXRzIGFuIGFzc2lzdGFudCBmaW5hbCByZXNwb25zZSwgZG9uXHUyMDE5dCBsZWF2ZSBVSSBzdHVjay5cbiAgICAgIHRoaXMuX3NldFdvcmtpbmcoZmFsc2UpO1xuICAgIH0sIFdPUktJTkdfTUFYX01TKTtcbiAgfVxuXG4gIHByaXZhdGUgX2Rpc2FybVdvcmtpbmdTYWZldHlUaW1lb3V0KCk6IHZvaWQge1xuICAgIGlmICh0aGlzLndvcmtpbmdUaW1lcikge1xuICAgICAgY2xlYXJUaW1lb3V0KHRoaXMud29ya2luZ1RpbWVyKTtcbiAgICAgIHRoaXMud29ya2luZ1RpbWVyID0gbnVsbDtcbiAgICB9XG4gIH1cbn1cbiIsICJpbXBvcnQgdHlwZSB7IENoYXRNZXNzYWdlIH0gZnJvbSAnLi90eXBlcyc7XG5cbi8qKiBNYW5hZ2VzIHRoZSBpbi1tZW1vcnkgbGlzdCBvZiBjaGF0IG1lc3NhZ2VzIGFuZCBub3RpZmllcyBVSSBvbiBjaGFuZ2VzICovXG5leHBvcnQgY2xhc3MgQ2hhdE1hbmFnZXIge1xuICBwcml2YXRlIG1lc3NhZ2VzOiBDaGF0TWVzc2FnZVtdID0gW107XG5cbiAgLyoqIEZpcmVkIGZvciBhIGZ1bGwgcmUtcmVuZGVyIChjbGVhci9yZWxvYWQpICovXG4gIG9uVXBkYXRlOiAoKG1lc3NhZ2VzOiByZWFkb25seSBDaGF0TWVzc2FnZVtdKSA9PiB2b2lkKSB8IG51bGwgPSBudWxsO1xuICAvKiogRmlyZWQgd2hlbiBhIHNpbmdsZSBtZXNzYWdlIGlzIGFwcGVuZGVkIFx1MjAxNCB1c2UgZm9yIE8oMSkgYXBwZW5kLW9ubHkgVUkgKi9cbiAgb25NZXNzYWdlQWRkZWQ6ICgobXNnOiBDaGF0TWVzc2FnZSkgPT4gdm9pZCkgfCBudWxsID0gbnVsbDtcblxuICBhZGRNZXNzYWdlKG1zZzogQ2hhdE1lc3NhZ2UpOiB2b2lkIHtcbiAgICB0aGlzLm1lc3NhZ2VzLnB1c2gobXNnKTtcbiAgICB0aGlzLm9uTWVzc2FnZUFkZGVkPy4obXNnKTtcbiAgfVxuXG4gIGdldE1lc3NhZ2VzKCk6IHJlYWRvbmx5IENoYXRNZXNzYWdlW10ge1xuICAgIHJldHVybiB0aGlzLm1lc3NhZ2VzO1xuICB9XG5cbiAgY2xlYXIoKTogdm9pZCB7XG4gICAgdGhpcy5tZXNzYWdlcyA9IFtdO1xuICAgIHRoaXMub25VcGRhdGU/LihbXSk7XG4gIH1cblxuICAvKiogQ3JlYXRlIGEgdXNlciBtZXNzYWdlIG9iamVjdCAod2l0aG91dCBhZGRpbmcgaXQpICovXG4gIHN0YXRpYyBjcmVhdGVVc2VyTWVzc2FnZShjb250ZW50OiBzdHJpbmcpOiBDaGF0TWVzc2FnZSB7XG4gICAgcmV0dXJuIHtcbiAgICAgIGlkOiBgbXNnLSR7RGF0ZS5ub3coKX0tJHtNYXRoLnJhbmRvbSgpLnRvU3RyaW5nKDM2KS5zbGljZSgyLCA3KX1gLFxuICAgICAgcm9sZTogJ3VzZXInLFxuICAgICAgY29udGVudCxcbiAgICAgIHRpbWVzdGFtcDogRGF0ZS5ub3coKSxcbiAgICB9O1xuICB9XG5cbiAgLyoqIENyZWF0ZSBhbiBhc3Npc3RhbnQgbWVzc2FnZSBvYmplY3QgKHdpdGhvdXQgYWRkaW5nIGl0KSAqL1xuICBzdGF0aWMgY3JlYXRlQXNzaXN0YW50TWVzc2FnZShjb250ZW50OiBzdHJpbmcpOiBDaGF0TWVzc2FnZSB7XG4gICAgcmV0dXJuIHtcbiAgICAgIGlkOiBgbXNnLSR7RGF0ZS5ub3coKX0tJHtNYXRoLnJhbmRvbSgpLnRvU3RyaW5nKDM2KS5zbGljZSgyLCA3KX1gLFxuICAgICAgcm9sZTogJ2Fzc2lzdGFudCcsXG4gICAgICBjb250ZW50LFxuICAgICAgdGltZXN0YW1wOiBEYXRlLm5vdygpLFxuICAgIH07XG4gIH1cblxuICAvKiogQ3JlYXRlIGEgc3lzdGVtIC8gc3RhdHVzIG1lc3NhZ2UgKGVycm9ycywgcmVjb25uZWN0IG5vdGljZXMsIGV0Yy4pICovXG4gIHN0YXRpYyBjcmVhdGVTeXN0ZW1NZXNzYWdlKGNvbnRlbnQ6IHN0cmluZywgbGV2ZWw6IENoYXRNZXNzYWdlWydsZXZlbCddID0gJ2luZm8nKTogQ2hhdE1lc3NhZ2Uge1xuICAgIHJldHVybiB7XG4gICAgICBpZDogYHN5cy0ke0RhdGUubm93KCl9YCxcbiAgICAgIHJvbGU6ICdzeXN0ZW0nLFxuICAgICAgbGV2ZWwsXG4gICAgICBjb250ZW50LFxuICAgICAgdGltZXN0YW1wOiBEYXRlLm5vdygpLFxuICAgIH07XG4gIH1cbn1cbiIsICJpbXBvcnQgeyBJdGVtVmlldywgTWFya2Rvd25SZW5kZXJlciwgTm90aWNlLCBXb3Jrc3BhY2VMZWFmIH0gZnJvbSAnb2JzaWRpYW4nO1xuaW1wb3J0IHR5cGUgT3BlbkNsYXdQbHVnaW4gZnJvbSAnLi9tYWluJztcbmltcG9ydCB7IENoYXRNYW5hZ2VyIH0gZnJvbSAnLi9jaGF0JztcbmltcG9ydCB0eXBlIHsgQ2hhdE1lc3NhZ2UsIFBhdGhNYXBwaW5nIH0gZnJvbSAnLi90eXBlcyc7XG5pbXBvcnQgeyBleHRyYWN0Q2FuZGlkYXRlcywgdHJ5TWFwUmVtb3RlUGF0aFRvVmF1bHRQYXRoIH0gZnJvbSAnLi9saW5raWZ5JztcbmltcG9ydCB7IGdldEFjdGl2ZU5vdGVDb250ZXh0IH0gZnJvbSAnLi9jb250ZXh0JztcblxuZXhwb3J0IGNvbnN0IFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFUID0gJ29wZW5jbGF3LWNoYXQnO1xuXG5leHBvcnQgY2xhc3MgT3BlbkNsYXdDaGF0VmlldyBleHRlbmRzIEl0ZW1WaWV3IHtcbiAgcHJpdmF0ZSBwbHVnaW46IE9wZW5DbGF3UGx1Z2luO1xuICBwcml2YXRlIGNoYXRNYW5hZ2VyOiBDaGF0TWFuYWdlcjtcblxuICAvLyBTdGF0ZVxuICBwcml2YXRlIGlzQ29ubmVjdGVkID0gZmFsc2U7XG4gIHByaXZhdGUgaXNXb3JraW5nID0gZmFsc2U7XG5cbiAgLy8gQ29ubmVjdGlvbiBub3RpY2VzIChhdm9pZCBzcGFtKVxuICBwcml2YXRlIGxhc3RDb25uTm90aWNlQXRNcyA9IDA7XG4gIHByaXZhdGUgbGFzdEdhdGV3YXlTdGF0ZTogc3RyaW5nIHwgbnVsbCA9IG51bGw7XG5cbiAgLy8gRE9NIHJlZnNcbiAgcHJpdmF0ZSBtZXNzYWdlc0VsITogSFRNTEVsZW1lbnQ7XG4gIHByaXZhdGUgaW5wdXRFbCE6IEhUTUxUZXh0QXJlYUVsZW1lbnQ7XG4gIHByaXZhdGUgc2VuZEJ0biE6IEhUTUxCdXR0b25FbGVtZW50O1xuICBwcml2YXRlIGluY2x1ZGVOb3RlQ2hlY2tib3ghOiBIVE1MSW5wdXRFbGVtZW50O1xuICBwcml2YXRlIHN0YXR1c0RvdCE6IEhUTUxFbGVtZW50O1xuXG4gIGNvbnN0cnVjdG9yKGxlYWY6IFdvcmtzcGFjZUxlYWYsIHBsdWdpbjogT3BlbkNsYXdQbHVnaW4pIHtcbiAgICBzdXBlcihsZWFmKTtcbiAgICB0aGlzLnBsdWdpbiA9IHBsdWdpbjtcbiAgICB0aGlzLmNoYXRNYW5hZ2VyID0gcGx1Z2luLmNoYXRNYW5hZ2VyO1xuICB9XG5cbiAgZ2V0Vmlld1R5cGUoKTogc3RyaW5nIHtcbiAgICByZXR1cm4gVklFV19UWVBFX09QRU5DTEFXX0NIQVQ7XG4gIH1cblxuICBnZXREaXNwbGF5VGV4dCgpOiBzdHJpbmcge1xuICAgIHJldHVybiAnT3BlbkNsYXcgQ2hhdCc7XG4gIH1cblxuICBnZXRJY29uKCk6IHN0cmluZyB7XG4gICAgcmV0dXJuICdtZXNzYWdlLXNxdWFyZSc7XG4gIH1cblxuICBhc3luYyBvbk9wZW4oKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgdGhpcy5fYnVpbGRVSSgpO1xuXG4gICAgLy8gRnVsbCByZS1yZW5kZXIgb24gY2xlYXIgLyByZWxvYWRcbiAgICB0aGlzLmNoYXRNYW5hZ2VyLm9uVXBkYXRlID0gKG1zZ3MpID0+IHRoaXMuX3JlbmRlck1lc3NhZ2VzKG1zZ3MpO1xuICAgIC8vIE8oMSkgYXBwZW5kIGZvciBuZXcgbWVzc2FnZXNcbiAgICB0aGlzLmNoYXRNYW5hZ2VyLm9uTWVzc2FnZUFkZGVkID0gKG1zZykgPT4gdGhpcy5fYXBwZW5kTWVzc2FnZShtc2cpO1xuXG4gICAgLy8gU3Vic2NyaWJlIHRvIFdTIHN0YXRlIGNoYW5nZXNcbiAgICB0aGlzLnBsdWdpbi53c0NsaWVudC5vblN0YXRlQ2hhbmdlID0gKHN0YXRlKSA9PiB7XG4gICAgICAvLyBDb25uZWN0aW9uIGxvc3MgLyByZWNvbm5lY3Qgbm90aWNlcyAodGhyb3R0bGVkKVxuICAgICAgY29uc3QgcHJldiA9IHRoaXMubGFzdEdhdGV3YXlTdGF0ZTtcbiAgICAgIHRoaXMubGFzdEdhdGV3YXlTdGF0ZSA9IHN0YXRlO1xuXG4gICAgICBjb25zdCBub3cgPSBEYXRlLm5vdygpO1xuICAgICAgY29uc3QgTk9USUNFX1RIUk9UVExFX01TID0gNjBfMDAwO1xuXG4gICAgICBjb25zdCBzaG91bGROb3RpZnkgPSAoKSA9PiBub3cgLSB0aGlzLmxhc3RDb25uTm90aWNlQXRNcyA+IE5PVElDRV9USFJPVFRMRV9NUztcbiAgICAgIGNvbnN0IG5vdGlmeSA9ICh0ZXh0OiBzdHJpbmcpID0+IHtcbiAgICAgICAgaWYgKCFzaG91bGROb3RpZnkoKSkgcmV0dXJuO1xuICAgICAgICB0aGlzLmxhc3RDb25uTm90aWNlQXRNcyA9IG5vdztcbiAgICAgICAgbmV3IE5vdGljZSh0ZXh0KTtcbiAgICAgIH07XG5cbiAgICAgIC8vIE9ubHkgc2hvdyBcdTIwMUNsb3N0XHUyMDFEIGlmIHdlIHdlcmUgcHJldmlvdXNseSBjb25uZWN0ZWQuXG4gICAgICBpZiAocHJldiA9PT0gJ2Nvbm5lY3RlZCcgJiYgc3RhdGUgPT09ICdkaXNjb25uZWN0ZWQnKSB7XG4gICAgICAgIG5vdGlmeSgnT3BlbkNsYXcgQ2hhdDogY29ubmVjdGlvbiBsb3N0IFx1MjAxNCByZWNvbm5lY3RpbmdcdTIwMjYnKTtcbiAgICAgICAgLy8gQWxzbyBhcHBlbmQgYSBzeXN0ZW0gbWVzc2FnZSBzbyBpdFx1MjAxOXMgdmlzaWJsZSBpbiB0aGUgY2hhdCBoaXN0b3J5LlxuICAgICAgICB0aGlzLmNoYXRNYW5hZ2VyLmFkZE1lc3NhZ2UoQ2hhdE1hbmFnZXIuY3JlYXRlU3lzdGVtTWVzc2FnZSgnXHUyNkEwIENvbm5lY3Rpb24gbG9zdCBcdTIwMTQgcmVjb25uZWN0aW5nXHUyMDI2JywgJ2Vycm9yJykpO1xuICAgICAgfVxuXG4gICAgICAvLyBPcHRpb25hbCBcdTIwMUNyZWNvbm5lY3RlZFx1MjAxRCBub3RpY2VcbiAgICAgIGlmIChwcmV2ICYmIHByZXYgIT09ICdjb25uZWN0ZWQnICYmIHN0YXRlID09PSAnY29ubmVjdGVkJykge1xuICAgICAgICBub3RpZnkoJ09wZW5DbGF3IENoYXQ6IHJlY29ubmVjdGVkJyk7XG4gICAgICAgIHRoaXMuY2hhdE1hbmFnZXIuYWRkTWVzc2FnZShDaGF0TWFuYWdlci5jcmVhdGVTeXN0ZW1NZXNzYWdlKCdcdTI3MDUgUmVjb25uZWN0ZWQnLCAnaW5mbycpKTtcbiAgICAgIH1cblxuICAgICAgdGhpcy5pc0Nvbm5lY3RlZCA9IHN0YXRlID09PSAnY29ubmVjdGVkJztcbiAgICAgIHRoaXMuc3RhdHVzRG90LnRvZ2dsZUNsYXNzKCdjb25uZWN0ZWQnLCB0aGlzLmlzQ29ubmVjdGVkKTtcbiAgICAgIHRoaXMuc3RhdHVzRG90LnRpdGxlID0gYEdhdGV3YXk6ICR7c3RhdGV9YDtcbiAgICAgIHRoaXMuX3VwZGF0ZVNlbmRCdXR0b24oKTtcbiAgICB9O1xuXG4gICAgLy8gU3Vic2NyaWJlIHRvIFx1MjAxQ3dvcmtpbmdcdTIwMUQgKHJlcXVlc3QtaW4tZmxpZ2h0KSBzdGF0ZVxuICAgIHRoaXMucGx1Z2luLndzQ2xpZW50Lm9uV29ya2luZ0NoYW5nZSA9ICh3b3JraW5nKSA9PiB7XG4gICAgICB0aGlzLmlzV29ya2luZyA9IHdvcmtpbmc7XG4gICAgICB0aGlzLl91cGRhdGVTZW5kQnV0dG9uKCk7XG4gICAgfTtcblxuICAgIC8vIFJlZmxlY3QgY3VycmVudCBzdGF0ZVxuICAgIHRoaXMubGFzdEdhdGV3YXlTdGF0ZSA9IHRoaXMucGx1Z2luLndzQ2xpZW50LnN0YXRlO1xuICAgIHRoaXMuaXNDb25uZWN0ZWQgPSB0aGlzLnBsdWdpbi53c0NsaWVudC5zdGF0ZSA9PT0gJ2Nvbm5lY3RlZCc7XG4gICAgdGhpcy5zdGF0dXNEb3QudG9nZ2xlQ2xhc3MoJ2Nvbm5lY3RlZCcsIHRoaXMuaXNDb25uZWN0ZWQpO1xuICAgIHRoaXMuc3RhdHVzRG90LnRpdGxlID0gYEdhdGV3YXk6ICR7dGhpcy5wbHVnaW4ud3NDbGllbnQuc3RhdGV9YDtcbiAgICB0aGlzLl91cGRhdGVTZW5kQnV0dG9uKCk7XG5cbiAgICB0aGlzLl9yZW5kZXJNZXNzYWdlcyh0aGlzLmNoYXRNYW5hZ2VyLmdldE1lc3NhZ2VzKCkpO1xuICB9XG5cbiAgYXN5bmMgb25DbG9zZSgpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICB0aGlzLmNoYXRNYW5hZ2VyLm9uVXBkYXRlID0gbnVsbDtcbiAgICB0aGlzLmNoYXRNYW5hZ2VyLm9uTWVzc2FnZUFkZGVkID0gbnVsbDtcbiAgICB0aGlzLnBsdWdpbi53c0NsaWVudC5vblN0YXRlQ2hhbmdlID0gbnVsbDtcbiAgICB0aGlzLnBsdWdpbi53c0NsaWVudC5vbldvcmtpbmdDaGFuZ2UgPSBudWxsO1xuICB9XG5cbiAgLy8gXHUyNTAwXHUyNTAwIFVJIGNvbnN0cnVjdGlvbiBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcblxuICBwcml2YXRlIF9idWlsZFVJKCk6IHZvaWQge1xuICAgIGNvbnN0IHJvb3QgPSB0aGlzLmNvbnRlbnRFbDtcbiAgICByb290LmVtcHR5KCk7XG4gICAgcm9vdC5hZGRDbGFzcygnb2NsYXctY2hhdC12aWV3Jyk7XG5cbiAgICAvLyBcdTI1MDBcdTI1MDAgSGVhZGVyIFx1MjUwMFx1MjUwMFxuICAgIGNvbnN0IGhlYWRlciA9IHJvb3QuY3JlYXRlRGl2KHsgY2xzOiAnb2NsYXctaGVhZGVyJyB9KTtcbiAgICBoZWFkZXIuY3JlYXRlU3Bhbih7IGNsczogJ29jbGF3LWhlYWRlci10aXRsZScsIHRleHQ6ICdPcGVuQ2xhdyBDaGF0JyB9KTtcbiAgICB0aGlzLnN0YXR1c0RvdCA9IGhlYWRlci5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1zdGF0dXMtZG90JyB9KTtcbiAgICB0aGlzLnN0YXR1c0RvdC50aXRsZSA9ICdHYXRld2F5OiBkaXNjb25uZWN0ZWQnO1xuXG4gICAgLy8gXHUyNTAwXHUyNTAwIE1lc3NhZ2VzIGFyZWEgXHUyNTAwXHUyNTAwXG4gICAgdGhpcy5tZXNzYWdlc0VsID0gcm9vdC5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1tZXNzYWdlcycgfSk7XG5cbiAgICAvLyBcdTI1MDBcdTI1MDAgQ29udGV4dCByb3cgXHUyNTAwXHUyNTAwXG4gICAgY29uc3QgY3R4Um93ID0gcm9vdC5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1jb250ZXh0LXJvdycgfSk7XG4gICAgdGhpcy5pbmNsdWRlTm90ZUNoZWNrYm94ID0gY3R4Um93LmNyZWF0ZUVsKCdpbnB1dCcsIHsgdHlwZTogJ2NoZWNrYm94JyB9KTtcbiAgICB0aGlzLmluY2x1ZGVOb3RlQ2hlY2tib3guaWQgPSAnb2NsYXctaW5jbHVkZS1ub3RlJztcbiAgICB0aGlzLmluY2x1ZGVOb3RlQ2hlY2tib3guY2hlY2tlZCA9IHRoaXMucGx1Z2luLnNldHRpbmdzLmluY2x1ZGVBY3RpdmVOb3RlO1xuICAgIGNvbnN0IGN0eExhYmVsID0gY3R4Um93LmNyZWF0ZUVsKCdsYWJlbCcsIHsgdGV4dDogJ0luY2x1ZGUgYWN0aXZlIG5vdGUnIH0pO1xuICAgIGN0eExhYmVsLmh0bWxGb3IgPSAnb2NsYXctaW5jbHVkZS1ub3RlJztcblxuICAgIC8vIFx1MjUwMFx1MjUwMCBJbnB1dCByb3cgXHUyNTAwXHUyNTAwXG4gICAgY29uc3QgaW5wdXRSb3cgPSByb290LmNyZWF0ZURpdih7IGNsczogJ29jbGF3LWlucHV0LXJvdycgfSk7XG4gICAgdGhpcy5pbnB1dEVsID0gaW5wdXRSb3cuY3JlYXRlRWwoJ3RleHRhcmVhJywge1xuICAgICAgY2xzOiAnb2NsYXctaW5wdXQnLFxuICAgICAgcGxhY2Vob2xkZXI6ICdBc2sgYW55dGhpbmdcdTIwMjYnLFxuICAgIH0pO1xuICAgIHRoaXMuaW5wdXRFbC5yb3dzID0gMTtcblxuICAgIHRoaXMuc2VuZEJ0biA9IGlucHV0Um93LmNyZWF0ZUVsKCdidXR0b24nLCB7IGNsczogJ29jbGF3LXNlbmQtYnRuJywgdGV4dDogJ1NlbmQnIH0pO1xuXG4gICAgLy8gXHUyNTAwXHUyNTAwIEV2ZW50IGxpc3RlbmVycyBcdTI1MDBcdTI1MDBcbiAgICB0aGlzLnNlbmRCdG4uYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKSA9PiB0aGlzLl9oYW5kbGVTZW5kKCkpO1xuICAgIHRoaXMuaW5wdXRFbC5hZGRFdmVudExpc3RlbmVyKCdrZXlkb3duJywgKGUpID0+IHtcbiAgICAgIGlmIChlLmtleSA9PT0gJ0VudGVyJyAmJiAhZS5zaGlmdEtleSkge1xuICAgICAgICBlLnByZXZlbnREZWZhdWx0KCk7XG4gICAgICAgIHRoaXMuX2hhbmRsZVNlbmQoKTtcbiAgICAgIH1cbiAgICB9KTtcbiAgICAvLyBBdXRvLXJlc2l6ZSB0ZXh0YXJlYVxuICAgIHRoaXMuaW5wdXRFbC5hZGRFdmVudExpc3RlbmVyKCdpbnB1dCcsICgpID0+IHtcbiAgICAgIHRoaXMuaW5wdXRFbC5zdHlsZS5oZWlnaHQgPSAnYXV0byc7XG4gICAgICB0aGlzLmlucHV0RWwuc3R5bGUuaGVpZ2h0ID0gYCR7dGhpcy5pbnB1dEVsLnNjcm9sbEhlaWdodH1weGA7XG4gICAgfSk7XG4gIH1cblxuICAvLyBcdTI1MDBcdTI1MDAgTWVzc2FnZSByZW5kZXJpbmcgXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG5cbiAgcHJpdmF0ZSBfcmVuZGVyTWVzc2FnZXMobWVzc2FnZXM6IHJlYWRvbmx5IENoYXRNZXNzYWdlW10pOiB2b2lkIHtcbiAgICB0aGlzLm1lc3NhZ2VzRWwuZW1wdHkoKTtcblxuICAgIGlmIChtZXNzYWdlcy5sZW5ndGggPT09IDApIHtcbiAgICAgIHRoaXMubWVzc2FnZXNFbC5jcmVhdGVFbCgncCcsIHtcbiAgICAgICAgdGV4dDogJ1NlbmQgYSBtZXNzYWdlIHRvIHN0YXJ0IGNoYXR0aW5nLicsXG4gICAgICAgIGNsczogJ29jbGF3LW1lc3NhZ2Ugc3lzdGVtIG9jbGF3LXBsYWNlaG9sZGVyJyxcbiAgICAgIH0pO1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIGZvciAoY29uc3QgbXNnIG9mIG1lc3NhZ2VzKSB7XG4gICAgICB0aGlzLl9hcHBlbmRNZXNzYWdlKG1zZyk7XG4gICAgfVxuXG4gICAgLy8gU2Nyb2xsIHRvIGJvdHRvbVxuICAgIHRoaXMubWVzc2FnZXNFbC5zY3JvbGxUb3AgPSB0aGlzLm1lc3NhZ2VzRWwuc2Nyb2xsSGVpZ2h0O1xuICB9XG5cbiAgLyoqIEFwcGVuZHMgYSBzaW5nbGUgbWVzc2FnZSB3aXRob3V0IHJlYnVpbGRpbmcgdGhlIERPTSAoTygxKSkgKi9cbiAgcHJpdmF0ZSBfYXBwZW5kTWVzc2FnZShtc2c6IENoYXRNZXNzYWdlKTogdm9pZCB7XG4gICAgLy8gUmVtb3ZlIGVtcHR5LXN0YXRlIHBsYWNlaG9sZGVyIGlmIHByZXNlbnRcbiAgICB0aGlzLm1lc3NhZ2VzRWwucXVlcnlTZWxlY3RvcignLm9jbGF3LXBsYWNlaG9sZGVyJyk/LnJlbW92ZSgpO1xuXG4gICAgY29uc3QgbGV2ZWxDbGFzcyA9IG1zZy5sZXZlbCA/IGAgJHttc2cubGV2ZWx9YCA6ICcnO1xuICAgIGNvbnN0IGVsID0gdGhpcy5tZXNzYWdlc0VsLmNyZWF0ZURpdih7IGNsczogYG9jbGF3LW1lc3NhZ2UgJHttc2cucm9sZX0ke2xldmVsQ2xhc3N9YCB9KTtcbiAgICBjb25zdCBib2R5ID0gZWwuY3JlYXRlRGl2KHsgY2xzOiAnb2NsYXctbWVzc2FnZS1ib2R5JyB9KTtcblxuICAgIC8vIFRyZWF0IGFzc2lzdGFudCBvdXRwdXQgYXMgVU5UUlVTVEVEIGJ5IGRlZmF1bHQuXG4gICAgLy8gUmVuZGVyaW5nIGFzIE9ic2lkaWFuIE1hcmtkb3duIGNhbiB0cmlnZ2VyIGVtYmVkcyBhbmQgb3RoZXIgcGx1Z2lucycgcG9zdC1wcm9jZXNzb3JzLlxuICAgIGlmIChtc2cucm9sZSA9PT0gJ2Fzc2lzdGFudCcpIHtcbiAgICAgIGNvbnN0IG1hcHBpbmdzOiBQYXRoTWFwcGluZ1tdID0gdGhpcy5wbHVnaW4uc2V0dGluZ3MucGF0aE1hcHBpbmdzID8/IFtdO1xuICAgICAgY29uc3Qgc291cmNlUGF0aCA9IHRoaXMuYXBwLndvcmtzcGFjZS5nZXRBY3RpdmVGaWxlKCk/LnBhdGggPz8gJyc7XG5cbiAgICAgIGlmICh0aGlzLnBsdWdpbi5zZXR0aW5ncy5yZW5kZXJBc3Npc3RhbnRNYXJrZG93bikge1xuICAgICAgICAvLyBCZXN0LWVmZm9ydCBwcmUtcHJvY2Vzc2luZzogcmVwbGFjZSBrbm93biByZW1vdGUgcGF0aHMgd2l0aCB3aWtpbGlua3Mgd2hlbiB0aGUgdGFyZ2V0IGV4aXN0cy5cbiAgICAgICAgY29uc3QgcHJlID0gdGhpcy5fcHJlcHJvY2Vzc0Fzc2lzdGFudE1hcmtkb3duKG1zZy5jb250ZW50LCBtYXBwaW5ncyk7XG4gICAgICAgIHZvaWQgTWFya2Rvd25SZW5kZXJlci5yZW5kZXJNYXJrZG93bihwcmUsIGJvZHksIHNvdXJjZVBhdGgsIHRoaXMucGx1Z2luKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIC8vIFBsYWluIG1vZGU6IGJ1aWxkIHNhZmUsIGNsaWNrYWJsZSBsaW5rcyBpbiBET00gKG5vIE1hcmtkb3duIHJlbmRlcmluZykuXG4gICAgICAgIHRoaXMuX3JlbmRlckFzc2lzdGFudFBsYWluV2l0aExpbmtzKGJvZHksIG1zZy5jb250ZW50LCBtYXBwaW5ncywgc291cmNlUGF0aCk7XG4gICAgICB9XG4gICAgfSBlbHNlIHtcbiAgICAgIGJvZHkuc2V0VGV4dChtc2cuY29udGVudCk7XG4gICAgfVxuXG4gICAgLy8gU2Nyb2xsIHRvIGJvdHRvbVxuICAgIHRoaXMubWVzc2FnZXNFbC5zY3JvbGxUb3AgPSB0aGlzLm1lc3NhZ2VzRWwuc2Nyb2xsSGVpZ2h0O1xuICB9XG5cbiAgcHJpdmF0ZSBfdHJ5UmV2ZXJzZU1hcFVybFRvVmF1bHRQYXRoKHVybDogc3RyaW5nLCBtYXBwaW5nczogUGF0aE1hcHBpbmdbXSk6IHN0cmluZyB8IG51bGwge1xuICAgIC8vIEZTLWJhc2VkIG1hcHBpbmc7IGJlc3QtZWZmb3J0IG9ubHkuXG4gICAgbGV0IGRlY29kZWQgPSB1cmw7XG4gICAgdHJ5IHtcbiAgICAgIGRlY29kZWQgPSBkZWNvZGVVUklDb21wb25lbnQodXJsKTtcbiAgICB9IGNhdGNoIHtcbiAgICAgIC8vIGlnbm9yZVxuICAgIH1cblxuICAgIC8vIElmIHRoZSBkZWNvZGVkIFVSTCBjb250YWlucyBhIHJlbW90ZUJhc2Ugc3Vic3RyaW5nLCB0cnkgbWFwcGluZyBmcm9tIHRoYXQgcG9pbnQuXG4gICAgZm9yIChjb25zdCByb3cgb2YgbWFwcGluZ3MpIHtcbiAgICAgIGNvbnN0IHJlbW90ZUJhc2UgPSBTdHJpbmcocm93LnJlbW90ZUJhc2UgPz8gJycpO1xuICAgICAgaWYgKCFyZW1vdGVCYXNlKSBjb250aW51ZTtcbiAgICAgIGNvbnN0IGlkeCA9IGRlY29kZWQuaW5kZXhPZihyZW1vdGVCYXNlKTtcbiAgICAgIGlmIChpZHggPCAwKSBjb250aW51ZTtcblxuICAgICAgLy8gRXh0cmFjdCBmcm9tIHJlbW90ZUJhc2Ugb253YXJkIHVudGlsIGEgdGVybWluYXRvci5cbiAgICAgIGNvbnN0IHRhaWwgPSBkZWNvZGVkLnNsaWNlKGlkeCk7XG4gICAgICBjb25zdCB0b2tlbiA9IHRhaWwuc3BsaXQoL1tcXHMnXCI8PildLylbMF07XG4gICAgICBjb25zdCBtYXBwZWQgPSB0cnlNYXBSZW1vdGVQYXRoVG9WYXVsdFBhdGgodG9rZW4sIG1hcHBpbmdzKTtcbiAgICAgIGlmIChtYXBwZWQgJiYgdGhpcy5hcHAudmF1bHQuZ2V0QWJzdHJhY3RGaWxlQnlQYXRoKG1hcHBlZCkpIHJldHVybiBtYXBwZWQ7XG4gICAgfVxuXG4gICAgcmV0dXJuIG51bGw7XG4gIH1cblxuICBwcml2YXRlIF9wcmVwcm9jZXNzQXNzaXN0YW50TWFya2Rvd24odGV4dDogc3RyaW5nLCBtYXBwaW5nczogUGF0aE1hcHBpbmdbXSk6IHN0cmluZyB7XG4gICAgY29uc3QgY2FuZGlkYXRlcyA9IGV4dHJhY3RDYW5kaWRhdGVzKHRleHQpO1xuICAgIGlmIChjYW5kaWRhdGVzLmxlbmd0aCA9PT0gMCkgcmV0dXJuIHRleHQ7XG5cbiAgICBsZXQgb3V0ID0gJyc7XG4gICAgbGV0IGN1cnNvciA9IDA7XG5cbiAgICBmb3IgKGNvbnN0IGMgb2YgY2FuZGlkYXRlcykge1xuICAgICAgb3V0ICs9IHRleHQuc2xpY2UoY3Vyc29yLCBjLnN0YXJ0KTtcbiAgICAgIGN1cnNvciA9IGMuZW5kO1xuXG4gICAgICBpZiAoYy5raW5kID09PSAndXJsJykge1xuICAgICAgICAvLyBVUkxzIHJlbWFpbiBVUkxzIFVOTEVTUyB3ZSBjYW4gc2FmZWx5IG1hcCB0byBhbiBleGlzdGluZyB2YXVsdCBmaWxlLlxuICAgICAgICBjb25zdCBtYXBwZWQgPSB0aGlzLl90cnlSZXZlcnNlTWFwVXJsVG9WYXVsdFBhdGgoYy5yYXcsIG1hcHBpbmdzKTtcbiAgICAgICAgb3V0ICs9IG1hcHBlZCA/IGBbWyR7bWFwcGVkfV1dYCA6IGMucmF3O1xuICAgICAgICBjb250aW51ZTtcbiAgICAgIH1cblxuICAgICAgLy8gMSkgSWYgdGhlIHRva2VuIGlzIGFscmVhZHkgYSB2YXVsdC1yZWxhdGl2ZSBwYXRoIGFuZCBleGlzdHMsIGxpbmtpZnkgaXQgZGlyZWN0bHkuXG4gICAgICBjb25zdCByYXdWYXVsdFBhdGggPSBjLnJhdy5yZXBsYWNlKC9eXFwvKy8sICcnKTtcbiAgICAgIGlmICh0aGlzLmFwcC52YXVsdC5nZXRBYnN0cmFjdEZpbGVCeVBhdGgocmF3VmF1bHRQYXRoKSkge1xuICAgICAgICBvdXQgKz0gYFtbJHtyYXdWYXVsdFBhdGh9XV1gO1xuICAgICAgICBjb250aW51ZTtcbiAgICAgIH1cblxuICAgICAgLy8gMikgRWxzZTogdHJ5IHJlbW90ZVx1MjE5MnZhdWx0IG1hcHBpbmcuXG4gICAgICBjb25zdCBtYXBwZWQgPSB0cnlNYXBSZW1vdGVQYXRoVG9WYXVsdFBhdGgoYy5yYXcsIG1hcHBpbmdzKTtcbiAgICAgIGlmICghbWFwcGVkKSB7XG4gICAgICAgIG91dCArPSBjLnJhdztcbiAgICAgICAgY29udGludWU7XG4gICAgICB9XG5cbiAgICAgIGlmICghdGhpcy5hcHAudmF1bHQuZ2V0QWJzdHJhY3RGaWxlQnlQYXRoKG1hcHBlZCkpIHtcbiAgICAgICAgb3V0ICs9IGMucmF3O1xuICAgICAgICBjb250aW51ZTtcbiAgICAgIH1cblxuICAgICAgb3V0ICs9IGBbWyR7bWFwcGVkfV1dYDtcbiAgICB9XG5cbiAgICBvdXQgKz0gdGV4dC5zbGljZShjdXJzb3IpO1xuICAgIHJldHVybiBvdXQ7XG4gIH1cblxuICBwcml2YXRlIF9yZW5kZXJBc3Npc3RhbnRQbGFpbldpdGhMaW5rcyhcbiAgICBib2R5OiBIVE1MRWxlbWVudCxcbiAgICB0ZXh0OiBzdHJpbmcsXG4gICAgbWFwcGluZ3M6IFBhdGhNYXBwaW5nW10sXG4gICAgc291cmNlUGF0aDogc3RyaW5nLFxuICApOiB2b2lkIHtcbiAgICBjb25zdCBjYW5kaWRhdGVzID0gZXh0cmFjdENhbmRpZGF0ZXModGV4dCk7XG4gICAgaWYgKGNhbmRpZGF0ZXMubGVuZ3RoID09PSAwKSB7XG4gICAgICBib2R5LnNldFRleHQodGV4dCk7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgbGV0IGN1cnNvciA9IDA7XG5cbiAgICBjb25zdCBhcHBlbmRUZXh0ID0gKHM6IHN0cmluZykgPT4ge1xuICAgICAgaWYgKCFzKSByZXR1cm47XG4gICAgICBib2R5LmFwcGVuZENoaWxkKGRvY3VtZW50LmNyZWF0ZVRleHROb2RlKHMpKTtcbiAgICB9O1xuXG4gICAgY29uc3QgYXBwZW5kT2JzaWRpYW5MaW5rID0gKHZhdWx0UGF0aDogc3RyaW5nKSA9PiB7XG4gICAgICBjb25zdCBkaXNwbGF5ID0gYFtbJHt2YXVsdFBhdGh9XV1gO1xuICAgICAgY29uc3QgYSA9IGJvZHkuY3JlYXRlRWwoJ2EnLCB7IHRleHQ6IGRpc3BsYXksIGhyZWY6ICcjJyB9KTtcbiAgICAgIGEuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoZXYpID0+IHtcbiAgICAgICAgZXYucHJldmVudERlZmF1bHQoKTtcbiAgICAgICAgZXYuc3RvcFByb3BhZ2F0aW9uKCk7XG4gICAgICAgIHZvaWQgdGhpcy5hcHAud29ya3NwYWNlLm9wZW5MaW5rVGV4dCh2YXVsdFBhdGgsIHNvdXJjZVBhdGgsIHRydWUpO1xuICAgICAgfSk7XG4gICAgfTtcblxuICAgIGNvbnN0IGFwcGVuZEV4dGVybmFsVXJsID0gKHVybDogc3RyaW5nKSA9PiB7XG4gICAgICAvLyBMZXQgT2JzaWRpYW4vRWxlY3Ryb24gaGFuZGxlIGV4dGVybmFsIG9wZW4uXG4gICAgICBib2R5LmNyZWF0ZUVsKCdhJywgeyB0ZXh0OiB1cmwsIGhyZWY6IHVybCB9KTtcbiAgICB9O1xuXG4gICAgY29uc3QgdHJ5UmV2ZXJzZU1hcFVybFRvVmF1bHRQYXRoID0gKHVybDogc3RyaW5nKTogc3RyaW5nIHwgbnVsbCA9PiB0aGlzLl90cnlSZXZlcnNlTWFwVXJsVG9WYXVsdFBhdGgodXJsLCBtYXBwaW5ncyk7XG5cbiAgICBmb3IgKGNvbnN0IGMgb2YgY2FuZGlkYXRlcykge1xuICAgICAgYXBwZW5kVGV4dCh0ZXh0LnNsaWNlKGN1cnNvciwgYy5zdGFydCkpO1xuICAgICAgY3Vyc29yID0gYy5lbmQ7XG5cbiAgICAgIGlmIChjLmtpbmQgPT09ICd1cmwnKSB7XG4gICAgICAgIGNvbnN0IG1hcHBlZCA9IHRyeVJldmVyc2VNYXBVcmxUb1ZhdWx0UGF0aChjLnJhdyk7XG4gICAgICAgIGlmIChtYXBwZWQpIHtcbiAgICAgICAgICBhcHBlbmRPYnNpZGlhbkxpbmsobWFwcGVkKTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICBhcHBlbmRFeHRlcm5hbFVybChjLnJhdyk7XG4gICAgICAgIH1cbiAgICAgICAgY29udGludWU7XG4gICAgICB9XG5cbiAgICAgIC8vIDEpIElmIHRva2VuIGlzIGFscmVhZHkgYSB2YXVsdC1yZWxhdGl2ZSBwYXRoIGFuZCBleGlzdHMsIGxpbmtpZnkgZGlyZWN0bHkuXG4gICAgICBjb25zdCByYXdWYXVsdFBhdGggPSBjLnJhdy5yZXBsYWNlKC9eXFwvKy8sICcnKTtcbiAgICAgIGlmICh0aGlzLmFwcC52YXVsdC5nZXRBYnN0cmFjdEZpbGVCeVBhdGgocmF3VmF1bHRQYXRoKSkge1xuICAgICAgICBhcHBlbmRPYnNpZGlhbkxpbmsocmF3VmF1bHRQYXRoKTtcbiAgICAgICAgY29udGludWU7XG4gICAgICB9XG5cbiAgICAgIC8vIDIpIEVsc2U6IHRyeSByZW1vdGVcdTIxOTJ2YXVsdCBtYXBwaW5nLlxuICAgICAgY29uc3QgbWFwcGVkID0gdHJ5TWFwUmVtb3RlUGF0aFRvVmF1bHRQYXRoKGMucmF3LCBtYXBwaW5ncyk7XG4gICAgICBpZiAoIW1hcHBlZCkge1xuICAgICAgICBhcHBlbmRUZXh0KGMucmF3KTtcbiAgICAgICAgY29udGludWU7XG4gICAgICB9XG5cbiAgICAgIGlmICghdGhpcy5hcHAudmF1bHQuZ2V0QWJzdHJhY3RGaWxlQnlQYXRoKG1hcHBlZCkpIHtcbiAgICAgICAgYXBwZW5kVGV4dChjLnJhdyk7XG4gICAgICAgIGNvbnRpbnVlO1xuICAgICAgfVxuXG4gICAgICBhcHBlbmRPYnNpZGlhbkxpbmsobWFwcGVkKTtcbiAgICB9XG5cbiAgICBhcHBlbmRUZXh0KHRleHQuc2xpY2UoY3Vyc29yKSk7XG4gIH1cblxuICBwcml2YXRlIF91cGRhdGVTZW5kQnV0dG9uKCk6IHZvaWQge1xuICAgIC8vIERpc2Nvbm5lY3RlZDogZGlzYWJsZS5cbiAgICAvLyBXb3JraW5nOiBrZWVwIGVuYWJsZWQgc28gdXNlciBjYW4gc3RvcC9hYm9ydC5cbiAgICBjb25zdCBkaXNhYmxlZCA9ICF0aGlzLmlzQ29ubmVjdGVkO1xuICAgIHRoaXMuc2VuZEJ0bi5kaXNhYmxlZCA9IGRpc2FibGVkO1xuXG4gICAgdGhpcy5zZW5kQnRuLnRvZ2dsZUNsYXNzKCdpcy13b3JraW5nJywgdGhpcy5pc1dvcmtpbmcpO1xuICAgIHRoaXMuc2VuZEJ0bi5zZXRBdHRyKCdhcmlhLWJ1c3knLCB0aGlzLmlzV29ya2luZyA/ICd0cnVlJyA6ICdmYWxzZScpO1xuICAgIHRoaXMuc2VuZEJ0bi5zZXRBdHRyKCdhcmlhLWxhYmVsJywgdGhpcy5pc1dvcmtpbmcgPyAnU3RvcCcgOiAnU2VuZCcpO1xuXG4gICAgaWYgKHRoaXMuaXNXb3JraW5nKSB7XG4gICAgICAvLyBSZXBsYWNlIGJ1dHRvbiBjb250ZW50cyB3aXRoIFN0b3AgaWNvbiArIHNwaW5uZXIgcmluZy5cbiAgICAgIHRoaXMuc2VuZEJ0bi5lbXB0eSgpO1xuICAgICAgY29uc3Qgd3JhcCA9IHRoaXMuc2VuZEJ0bi5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1zdG9wLXdyYXAnIH0pO1xuICAgICAgd3JhcC5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1zcGlubmVyLXJpbmcnLCBhdHRyOiB7ICdhcmlhLWhpZGRlbic6ICd0cnVlJyB9IH0pO1xuICAgICAgd3JhcC5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1zdG9wLWljb24nLCBhdHRyOiB7ICdhcmlhLWhpZGRlbic6ICd0cnVlJyB9IH0pO1xuICAgIH0gZWxzZSB7XG4gICAgICAvLyBSZXN0b3JlIGxhYmVsXG4gICAgICB0aGlzLnNlbmRCdG4uc2V0VGV4dCgnU2VuZCcpO1xuICAgIH1cbiAgfVxuXG4gIC8vIFx1MjUwMFx1MjUwMCBTZW5kIGhhbmRsZXIgXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG5cbiAgcHJpdmF0ZSBhc3luYyBfaGFuZGxlU2VuZCgpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICAvLyBXaGlsZSB3b3JraW5nLCB0aGUgYnV0dG9uIGJlY29tZXMgU3RvcC5cbiAgICBpZiAodGhpcy5pc1dvcmtpbmcpIHtcbiAgICAgIGNvbnN0IG9rID0gYXdhaXQgdGhpcy5wbHVnaW4ud3NDbGllbnQuYWJvcnRBY3RpdmVSdW4oKTtcbiAgICAgIGlmICghb2spIHtcbiAgICAgICAgbmV3IE5vdGljZSgnT3BlbkNsYXcgQ2hhdDogZmFpbGVkIHRvIHN0b3AnKTtcbiAgICAgICAgdGhpcy5jaGF0TWFuYWdlci5hZGRNZXNzYWdlKENoYXRNYW5hZ2VyLmNyZWF0ZVN5c3RlbU1lc3NhZ2UoJ1x1MjZBMCBTdG9wIGZhaWxlZCcsICdlcnJvcicpKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHRoaXMuY2hhdE1hbmFnZXIuYWRkTWVzc2FnZShDaGF0TWFuYWdlci5jcmVhdGVTeXN0ZW1NZXNzYWdlKCdcdTI2RDQgU3RvcHBlZCcsICdpbmZvJykpO1xuICAgICAgfVxuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIGNvbnN0IHRleHQgPSB0aGlzLmlucHV0RWwudmFsdWUudHJpbSgpO1xuICAgIGlmICghdGV4dCkgcmV0dXJuO1xuXG4gICAgLy8gQnVpbGQgbWVzc2FnZSB3aXRoIGNvbnRleHQgaWYgZW5hYmxlZFxuICAgIGxldCBtZXNzYWdlID0gdGV4dDtcbiAgICBpZiAodGhpcy5pbmNsdWRlTm90ZUNoZWNrYm94LmNoZWNrZWQpIHtcbiAgICAgIGNvbnN0IG5vdGUgPSBhd2FpdCBnZXRBY3RpdmVOb3RlQ29udGV4dCh0aGlzLmFwcCk7XG4gICAgICBpZiAobm90ZSkge1xuICAgICAgICBtZXNzYWdlID0gYENvbnRleHQ6IFtbJHtub3RlLnRpdGxlfV1dXFxuXFxuJHt0ZXh0fWA7XG4gICAgICB9XG4gICAgfVxuXG4gICAgLy8gQWRkIHVzZXIgbWVzc2FnZSB0byBjaGF0IFVJXG4gICAgY29uc3QgdXNlck1zZyA9IENoYXRNYW5hZ2VyLmNyZWF0ZVVzZXJNZXNzYWdlKHRleHQpO1xuICAgIHRoaXMuY2hhdE1hbmFnZXIuYWRkTWVzc2FnZSh1c2VyTXNnKTtcblxuICAgIC8vIENsZWFyIGlucHV0XG4gICAgdGhpcy5pbnB1dEVsLnZhbHVlID0gJyc7XG4gICAgdGhpcy5pbnB1dEVsLnN0eWxlLmhlaWdodCA9ICdhdXRvJztcblxuICAgIC8vIFNlbmQgb3ZlciBXUyAoYXN5bmMpXG4gICAgdHJ5IHtcbiAgICAgIGF3YWl0IHRoaXMucGx1Z2luLndzQ2xpZW50LnNlbmRNZXNzYWdlKG1lc3NhZ2UpO1xuICAgIH0gY2F0Y2ggKGVycikge1xuICAgICAgY29uc29sZS5lcnJvcignW29jbGF3XSBTZW5kIGZhaWxlZCcsIGVycik7XG4gICAgICBuZXcgTm90aWNlKGBPcGVuQ2xhdyBDaGF0OiBzZW5kIGZhaWxlZCAoJHtTdHJpbmcoZXJyKX0pYCk7XG4gICAgICB0aGlzLmNoYXRNYW5hZ2VyLmFkZE1lc3NhZ2UoXG4gICAgICAgIENoYXRNYW5hZ2VyLmNyZWF0ZVN5c3RlbU1lc3NhZ2UoYFx1MjZBMCBTZW5kIGZhaWxlZDogJHtlcnJ9YCwgJ2Vycm9yJylcbiAgICAgICk7XG4gICAgfVxuICB9XG59XG4iLCAiaW1wb3J0IHR5cGUgeyBQYXRoTWFwcGluZyB9IGZyb20gJy4vdHlwZXMnO1xuXG5leHBvcnQgZnVuY3Rpb24gbm9ybWFsaXplQmFzZShiYXNlOiBzdHJpbmcpOiBzdHJpbmcge1xuICBjb25zdCB0cmltbWVkID0gU3RyaW5nKGJhc2UgPz8gJycpLnRyaW0oKTtcbiAgaWYgKCF0cmltbWVkKSByZXR1cm4gJyc7XG4gIHJldHVybiB0cmltbWVkLmVuZHNXaXRoKCcvJykgPyB0cmltbWVkIDogYCR7dHJpbW1lZH0vYDtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIHRyeU1hcFJlbW90ZVBhdGhUb1ZhdWx0UGF0aChpbnB1dDogc3RyaW5nLCBtYXBwaW5nczogcmVhZG9ubHkgUGF0aE1hcHBpbmdbXSk6IHN0cmluZyB8IG51bGwge1xuICBjb25zdCByYXcgPSBTdHJpbmcoaW5wdXQgPz8gJycpO1xuICBmb3IgKGNvbnN0IHJvdyBvZiBtYXBwaW5ncykge1xuICAgIGNvbnN0IHJlbW90ZUJhc2UgPSBub3JtYWxpemVCYXNlKHJvdy5yZW1vdGVCYXNlKTtcbiAgICBjb25zdCB2YXVsdEJhc2UgPSBub3JtYWxpemVCYXNlKHJvdy52YXVsdEJhc2UpO1xuICAgIGlmICghcmVtb3RlQmFzZSB8fCAhdmF1bHRCYXNlKSBjb250aW51ZTtcblxuICAgIGlmIChyYXcuc3RhcnRzV2l0aChyZW1vdGVCYXNlKSkge1xuICAgICAgY29uc3QgcmVzdCA9IHJhdy5zbGljZShyZW1vdGVCYXNlLmxlbmd0aCk7XG4gICAgICAvLyBPYnNpZGlhbiBwYXRocyBhcmUgdmF1bHQtcmVsYXRpdmUgYW5kIHNob3VsZCBub3Qgc3RhcnQgd2l0aCAnLydcbiAgICAgIHJldHVybiBgJHt2YXVsdEJhc2V9JHtyZXN0fWAucmVwbGFjZSgvXlxcLysvLCAnJyk7XG4gICAgfVxuICB9XG4gIHJldHVybiBudWxsO1xufVxuXG5leHBvcnQgdHlwZSBDYW5kaWRhdGUgPSB7IHN0YXJ0OiBudW1iZXI7IGVuZDogbnVtYmVyOyByYXc6IHN0cmluZzsga2luZDogJ3VybCcgfCAncGF0aCcgfTtcblxuLy8gQ29uc2VydmF0aXZlIGV4dHJhY3Rpb246IGFpbSB0byBhdm9pZCBmYWxzZSBwb3NpdGl2ZXMuXG5jb25zdCBVUkxfUkUgPSAvaHR0cHM/OlxcL1xcL1teXFxzPD4oKV0rL2c7XG4vLyBBYnNvbHV0ZSB1bml4LWlzaCBwYXRocy5cbi8vIChXZSBzdGlsbCBleGlzdGVuY2UtY2hlY2sgYmVmb3JlIHByb2R1Y2luZyBhIGxpbmsuKVxuY29uc3QgUEFUSF9SRSA9IC8oPzwhW0EtWmEtejAtOS5fLV0pKD86XFwvW0EtWmEtejAtOS5ffiEkJicoKSorLDs9OkAlXFwtXSspKyg/OlxcLltBLVphLXowLTkuXy1dKyk/L2c7XG5cbi8vIENvbnNlcnZhdGl2ZSByZWxhdGl2ZSBwYXRocyB3aXRoIGF0IGxlYXN0IG9uZSAnLycsIGUuZy4gY29tcGVuZy9wbGFucy94Lm1kXG4vLyBBdm9pZHMgbWF0Y2hpbmcgc2NoZW1lLWxpa2UgdG9rZW5zIHZpYSBuZWdhdGl2ZSBsb29rYWhlYWQgZm9yICc6Ly8nLlxuY29uc3QgUkVMX1BBVEhfUkUgPSAvXFxiKD8hW0EtWmEtel1bQS1aYS16MC05Ky4tXSo6XFwvXFwvKVtBLVphLXowLTkuXy1dKyg/OlxcL1tBLVphLXowLTkuXy1dKykrKD86XFwuW0EtWmEtejAtOS5fLV0rKT9cXGIvZztcblxuZXhwb3J0IGZ1bmN0aW9uIGV4dHJhY3RDYW5kaWRhdGVzKHRleHQ6IHN0cmluZyk6IENhbmRpZGF0ZVtdIHtcbiAgY29uc3QgdCA9IFN0cmluZyh0ZXh0ID8/ICcnKTtcbiAgY29uc3Qgb3V0OiBDYW5kaWRhdGVbXSA9IFtdO1xuXG4gIGZvciAoY29uc3QgbSBvZiB0Lm1hdGNoQWxsKFVSTF9SRSkpIHtcbiAgICBpZiAobS5pbmRleCA9PT0gdW5kZWZpbmVkKSBjb250aW51ZTtcbiAgICBvdXQucHVzaCh7IHN0YXJ0OiBtLmluZGV4LCBlbmQ6IG0uaW5kZXggKyBtWzBdLmxlbmd0aCwgcmF3OiBtWzBdLCBraW5kOiAndXJsJyB9KTtcbiAgfVxuXG4gIGZvciAoY29uc3QgbSBvZiB0Lm1hdGNoQWxsKFBBVEhfUkUpKSB7XG4gICAgaWYgKG0uaW5kZXggPT09IHVuZGVmaW5lZCkgY29udGludWU7XG5cbiAgICAvLyBTa2lwIGlmIHRoaXMgaXMgaW5zaWRlIGEgVVJMIHdlIGFscmVhZHkgY2FwdHVyZWQuXG4gICAgY29uc3Qgc3RhcnQgPSBtLmluZGV4O1xuICAgIGNvbnN0IGVuZCA9IHN0YXJ0ICsgbVswXS5sZW5ndGg7XG4gICAgY29uc3Qgb3ZlcmxhcHNVcmwgPSBvdXQuc29tZSgoYykgPT4gYy5raW5kID09PSAndXJsJyAmJiAhKGVuZCA8PSBjLnN0YXJ0IHx8IHN0YXJ0ID49IGMuZW5kKSk7XG4gICAgaWYgKG92ZXJsYXBzVXJsKSBjb250aW51ZTtcblxuICAgIG91dC5wdXNoKHsgc3RhcnQsIGVuZCwgcmF3OiBtWzBdLCBraW5kOiAncGF0aCcgfSk7XG4gIH1cblxuICBmb3IgKGNvbnN0IG0gb2YgdC5tYXRjaEFsbChSRUxfUEFUSF9SRSkpIHtcbiAgICBpZiAobS5pbmRleCA9PT0gdW5kZWZpbmVkKSBjb250aW51ZTtcblxuICAgIGNvbnN0IHN0YXJ0ID0gbS5pbmRleDtcbiAgICBjb25zdCBlbmQgPSBzdGFydCArIG1bMF0ubGVuZ3RoO1xuICAgIGNvbnN0IG92ZXJsYXBzRXhpc3RpbmcgPSBvdXQuc29tZSgoYykgPT4gIShlbmQgPD0gYy5zdGFydCB8fCBzdGFydCA+PSBjLmVuZCkpO1xuICAgIGlmIChvdmVybGFwc0V4aXN0aW5nKSBjb250aW51ZTtcblxuICAgIG91dC5wdXNoKHsgc3RhcnQsIGVuZCwgcmF3OiBtWzBdLCBraW5kOiAncGF0aCcgfSk7XG4gIH1cblxuICAvLyBTb3J0IGFuZCBkcm9wIG92ZXJsYXBzIChwcmVmZXIgVVJMcykuXG4gIG91dC5zb3J0KChhLCBiKSA9PiBhLnN0YXJ0IC0gYi5zdGFydCB8fCAoYS5raW5kID09PSAndXJsJyA/IC0xIDogMSkpO1xuICBjb25zdCBkZWR1cDogQ2FuZGlkYXRlW10gPSBbXTtcbiAgZm9yIChjb25zdCBjIG9mIG91dCkge1xuICAgIGNvbnN0IGxhc3QgPSBkZWR1cFtkZWR1cC5sZW5ndGggLSAxXTtcbiAgICBpZiAoIWxhc3QpIHtcbiAgICAgIGRlZHVwLnB1c2goYyk7XG4gICAgICBjb250aW51ZTtcbiAgICB9XG4gICAgaWYgKGMuc3RhcnQgPCBsYXN0LmVuZCkgY29udGludWU7XG4gICAgZGVkdXAucHVzaChjKTtcbiAgfVxuXG4gIHJldHVybiBkZWR1cDtcbn1cbiIsICJpbXBvcnQgdHlwZSB7IEFwcCB9IGZyb20gJ29ic2lkaWFuJztcblxuZXhwb3J0IGludGVyZmFjZSBOb3RlQ29udGV4dCB7XG4gIHRpdGxlOiBzdHJpbmc7XG4gIHBhdGg6IHN0cmluZztcbiAgY29udGVudDogc3RyaW5nO1xufVxuXG4vKipcbiAqIFJldHVybnMgdGhlIGFjdGl2ZSBub3RlJ3MgdGl0bGUgYW5kIGNvbnRlbnQsIG9yIG51bGwgaWYgbm8gbm90ZSBpcyBvcGVuLlxuICogQXN5bmMgYmVjYXVzZSB2YXVsdC5yZWFkKCkgaXMgYXN5bmMuXG4gKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBnZXRBY3RpdmVOb3RlQ29udGV4dChhcHA6IEFwcCk6IFByb21pc2U8Tm90ZUNvbnRleHQgfCBudWxsPiB7XG4gIGNvbnN0IGZpbGUgPSBhcHAud29ya3NwYWNlLmdldEFjdGl2ZUZpbGUoKTtcbiAgaWYgKCFmaWxlKSByZXR1cm4gbnVsbDtcblxuICB0cnkge1xuICAgIGNvbnN0IGNvbnRlbnQgPSBhd2FpdCBhcHAudmF1bHQucmVhZChmaWxlKTtcbiAgICByZXR1cm4ge1xuICAgICAgdGl0bGU6IGZpbGUuYmFzZW5hbWUsXG4gICAgICBwYXRoOiBmaWxlLnBhdGgsXG4gICAgICBjb250ZW50LFxuICAgIH07XG4gIH0gY2F0Y2ggKGVycikge1xuICAgIGNvbnNvbGUuZXJyb3IoJ1tvY2xhdy1jb250ZXh0XSBGYWlsZWQgdG8gcmVhZCBhY3RpdmUgbm90ZScsIGVycik7XG4gICAgcmV0dXJuIG51bGw7XG4gIH1cbn1cbiIsICIvKiogUGVyc2lzdGVkIHBsdWdpbiBjb25maWd1cmF0aW9uICovXG5leHBvcnQgaW50ZXJmYWNlIE9wZW5DbGF3U2V0dGluZ3Mge1xuICAvKiogV2ViU29ja2V0IFVSTCBvZiB0aGUgT3BlbkNsYXcgR2F0ZXdheSAoZS5nLiB3czovLzEwMC45MC45LjY4OjE4Nzg5KSAqL1xuICBnYXRld2F5VXJsOiBzdHJpbmc7XG4gIC8qKiBBdXRoIHRva2VuIFx1MjAxNCBtdXN0IG1hdGNoIHRoZSBjaGFubmVsIHBsdWdpbidzIGF1dGhUb2tlbiAqL1xuICBhdXRoVG9rZW46IHN0cmluZztcbiAgLyoqIE9wZW5DbGF3IHNlc3Npb24ga2V5IHRvIHN1YnNjcmliZSB0byAoZS5nLiBcIm1haW5cIikgKi9cbiAgc2Vzc2lvbktleTogc3RyaW5nO1xuICAvKiogKERlcHJlY2F0ZWQpIE9wZW5DbGF3IGFjY291bnQgSUQgKHVudXNlZDsgY2hhdC5zZW5kIHVzZXMgc2Vzc2lvbktleSkgKi9cbiAgYWNjb3VudElkOiBzdHJpbmc7XG4gIC8qKiBXaGV0aGVyIHRvIGluY2x1ZGUgdGhlIGFjdGl2ZSBub3RlIGNvbnRlbnQgd2l0aCBlYWNoIG1lc3NhZ2UgKi9cbiAgaW5jbHVkZUFjdGl2ZU5vdGU6IGJvb2xlYW47XG4gIC8qKiBSZW5kZXIgYXNzaXN0YW50IG91dHB1dCBhcyBNYXJrZG93biAodW5zYWZlOiBtYXkgdHJpZ2dlciBlbWJlZHMvcG9zdC1wcm9jZXNzb3JzKTsgZGVmYXVsdCBPRkYgKi9cbiAgcmVuZGVyQXNzaXN0YW50TWFya2Rvd246IGJvb2xlYW47XG4gIC8qKiBBbGxvdyB1c2luZyBpbnNlY3VyZSB3czovLyBmb3Igbm9uLWxvY2FsIGdhdGV3YXkgVVJMcyAodW5zYWZlKTsgZGVmYXVsdCBPRkYgKi9cbiAgYWxsb3dJbnNlY3VyZVdzOiBib29sZWFuO1xuXG4gIC8qKiBPcHRpb25hbDogbWFwIHJlbW90ZSBGUyBwYXRocyAvIGV4cG9ydGVkIHBhdGhzIGJhY2sgdG8gdmF1bHQtcmVsYXRpdmUgcGF0aHMgKi9cbiAgcGF0aE1hcHBpbmdzOiBQYXRoTWFwcGluZ1tdO1xufVxuXG5leHBvcnQgdHlwZSBQYXRoTWFwcGluZyA9IHtcbiAgLyoqIFZhdWx0LXJlbGF0aXZlIGJhc2UgcGF0aCAoZS5nLiBcImRvY3MvXCIgb3IgXCJjb21wZW5nL1wiKSAqL1xuICB2YXVsdEJhc2U6IHN0cmluZztcbiAgLyoqIFJlbW90ZSBGUyBiYXNlIHBhdGggKGUuZy4gXCIvaG9tZS93YWxsLWUvLm9wZW5jbGF3L3dvcmtzcGFjZS9kb2NzL1wiKSAqL1xuICByZW1vdGVCYXNlOiBzdHJpbmc7XG59O1xuXG5leHBvcnQgY29uc3QgREVGQVVMVF9TRVRUSU5HUzogT3BlbkNsYXdTZXR0aW5ncyA9IHtcbiAgZ2F0ZXdheVVybDogJ3dzOi8vbG9jYWxob3N0OjE4Nzg5JyxcbiAgYXV0aFRva2VuOiAnJyxcbiAgc2Vzc2lvbktleTogJ21haW4nLFxuICBhY2NvdW50SWQ6ICdtYWluJyxcbiAgaW5jbHVkZUFjdGl2ZU5vdGU6IGZhbHNlLFxuICByZW5kZXJBc3Npc3RhbnRNYXJrZG93bjogZmFsc2UsXG4gIGFsbG93SW5zZWN1cmVXczogZmFsc2UsXG4gIHBhdGhNYXBwaW5nczogW10sXG59O1xuXG4vKiogQSBzaW5nbGUgY2hhdCBtZXNzYWdlICovXG5leHBvcnQgaW50ZXJmYWNlIENoYXRNZXNzYWdlIHtcbiAgaWQ6IHN0cmluZztcbiAgcm9sZTogJ3VzZXInIHwgJ2Fzc2lzdGFudCcgfCAnc3lzdGVtJztcbiAgLyoqIE9wdGlvbmFsIHNldmVyaXR5IGZvciBzeXN0ZW0vc3RhdHVzIG1lc3NhZ2VzICovXG4gIGxldmVsPzogJ2luZm8nIHwgJ2Vycm9yJztcbiAgY29udGVudDogc3RyaW5nO1xuICB0aW1lc3RhbXA6IG51bWJlcjtcbn1cblxuLyoqIFBheWxvYWQgZm9yIG1lc3NhZ2VzIFNFTlQgdG8gdGhlIHNlcnZlciAob3V0Ym91bmQpICovXG5leHBvcnQgaW50ZXJmYWNlIFdTUGF5bG9hZCB7XG4gIHR5cGU6ICdhdXRoJyB8ICdtZXNzYWdlJyB8ICdwaW5nJyB8ICdwb25nJyB8ICdlcnJvcic7XG4gIHBheWxvYWQ/OiBSZWNvcmQ8c3RyaW5nLCB1bmtub3duPjtcbn1cblxuLyoqIE1lc3NhZ2VzIFJFQ0VJVkVEIGZyb20gdGhlIHNlcnZlciAoaW5ib3VuZCkgXHUyMDE0IGRpc2NyaW1pbmF0ZWQgdW5pb24gKi9cbmV4cG9ydCB0eXBlIEluYm91bmRXU1BheWxvYWQgPVxuICB8IHsgdHlwZTogJ21lc3NhZ2UnOyBwYXlsb2FkOiB7IGNvbnRlbnQ6IHN0cmluZzsgcm9sZTogc3RyaW5nOyB0aW1lc3RhbXA6IG51bWJlciB9IH1cbiAgfCB7IHR5cGU6ICdlcnJvcic7IHBheWxvYWQ6IHsgbWVzc2FnZTogc3RyaW5nIH0gfTtcblxuLyoqIEF2YWlsYWJsZSBhZ2VudHMgLyBtb2RlbHMgKi9cbmV4cG9ydCBpbnRlcmZhY2UgQWdlbnRPcHRpb24ge1xuICBpZDogc3RyaW5nO1xuICBsYWJlbDogc3RyaW5nO1xufVxuIl0sCiAgIm1hcHBpbmdzIjogIjs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7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Q0FBQyxHQUFHLGtCQUFrQixJQUFJO0FBQUEsSUFDMUQ7QUFBQTtBQUFBLEVBRU0sZUFBOEI7QUFBQTtBQTdFdEM7QUErRUksWUFBTSxRQUFRLFdBQU0sS0FBSyxTQUFTLE1BQXBCLFlBQTBCLENBQUM7QUFDekMsWUFBTSxLQUFLLFNBQVMsa0NBQUssT0FBUyxLQUFLLFNBQVU7QUFBQSxJQUNuRDtBQUFBO0FBQUE7QUFBQSxFQUlNLHNCQUFxQztBQUFBO0FBQ3pDLFlBQU0sS0FBSyxxQkFBcUI7QUFDaEMsVUFBSSx3QkFBTyxnRUFBZ0U7QUFBQSxJQUM3RTtBQUFBO0FBQUEsRUFJYyxzQkFBMkM7QUFBQTtBQTVGM0Q7QUE2RkksWUFBTSxRQUFRLFdBQU0sS0FBSyxTQUFTLE1BQXBCLFlBQTBCLENBQUM7QUFDekMsY0FBUSxrQ0FBZSxLQUFLLHdCQUFwQixZQUEyQztBQUFBLElBQ3JEO0FBQUE7QUFBQSxFQUVjLG9CQUFvQixVQUE4QjtBQUFBO0FBakdsRTtBQWtHSSxZQUFNLFFBQVEsV0FBTSxLQUFLLFNBQVMsTUFBcEIsWUFBMEIsQ0FBQztBQUN6QyxZQUFNLEtBQUssU0FBUyxpQ0FBSyxPQUFMLEVBQVcsQ0FBQyxLQUFLLGtCQUFrQixHQUFHLFNBQVMsRUFBQztBQUFBLElBQ3RFO0FBQUE7QUFBQSxFQUVjLHVCQUFzQztBQUFBO0FBdEd0RDtBQXVHSSxZQUFNLFFBQVEsV0FBTSxLQUFLLFNBQVMsTUFBcEIsWUFBMEIsQ0FBQztBQUN6QyxXQUFLLDZCQUFlLEtBQUsseUJBQXdCO0FBQVc7QUFDNUQsWUFBTSxPQUFPLG1CQUFNO0FBQ25CLGFBQU8sS0FBSyxLQUFLLGtCQUFrQjtBQUNuQyxZQUFNLEtBQUssU0FBUyxJQUFJO0FBQUEsSUFDMUI7QUFBQTtBQUFBO0FBQUEsRUFJUSxhQUFtQjtBQUN6QixTQUFLLFNBQVMsUUFBUSxLQUFLLFNBQVMsWUFBWSxLQUFLLFNBQVMsV0FBVztBQUFBLE1BQ3ZFLGlCQUFpQixLQUFLLFNBQVM7QUFBQSxJQUNqQyxDQUFDO0FBQUEsRUFDSDtBQUFBLEVBRWMsb0JBQW1DO0FBQUE7QUFDL0MsWUFBTSxFQUFFLFVBQVUsSUFBSSxLQUFLO0FBRzNCLFlBQU0sV0FBVyxVQUFVLGdCQUFnQix1QkFBdUI7QUFDbEUsVUFBSSxTQUFTLFNBQVMsR0FBRztBQUN2QixrQkFBVSxXQUFXLFNBQVMsQ0FBQyxDQUFDO0FBQ2hDO0FBQUEsTUFDRjtBQUdBLFlBQU0sT0FBTyxVQUFVLGFBQWEsS0FBSztBQUN6QyxVQUFJLENBQUM7QUFBTTtBQUNYLFlBQU0sS0FBSyxhQUFhLEVBQUUsTUFBTSx5QkFBeUIsUUFBUSxLQUFLLENBQUM7QUFDdkUsZ0JBQVUsV0FBVyxJQUFJO0FBQUEsSUFDM0I7QUFBQTtBQUNGOyIsCiAgIm5hbWVzIjogWyJpbXBvcnRfb2JzaWRpYW4iLCAiX2EiLCAiaW1wb3J0X29ic2lkaWFuIiwgIm1hcHBlZCJdCn0K
