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
  _tryMapVaultRelativeToken(token, mappings) {
    var _a;
    const t = token.replace(/^\/+/, "");
    if (this.app.vault.getAbstractFileByPath(t))
      return t;
    for (const row of mappings) {
      const vaultBaseRaw = String((_a = row.vaultBase) != null ? _a : "").trim();
      if (!vaultBaseRaw)
        continue;
      const vaultBase = vaultBaseRaw.endsWith("/") ? vaultBaseRaw : `${vaultBaseRaw}/`;
      const parts = vaultBase.replace(/\/+$/, "").split("/");
      const baseName = parts[parts.length - 1];
      if (!baseName)
        continue;
      const prefix = `${baseName}/`;
      if (!t.startsWith(prefix))
        continue;
      const candidate = `${vaultBase}${t.slice(prefix.length)}`;
      const normalized = candidate.replace(/^\/+/, "");
      if (this.app.vault.getAbstractFileByPath(normalized))
        return normalized;
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
      const direct = this._tryMapVaultRelativeToken(c.raw, mappings);
      if (direct) {
        out += `[[${direct}]]`;
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
        const f = this.app.vault.getAbstractFileByPath(vaultPath);
        if (f instanceof import_obsidian2.TFile) {
          void this.app.workspace.getLeaf(true).openFile(f);
          return;
        }
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
      const direct = this._tryMapVaultRelativeToken(c.raw, mappings);
      if (direct) {
        appendObsidianLink(direct);
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
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsic3JjL21haW4udHMiLCAic3JjL3NldHRpbmdzLnRzIiwgInNyYy93ZWJzb2NrZXQudHMiLCAic3JjL2NoYXQudHMiLCAic3JjL3ZpZXcudHMiLCAic3JjL2xpbmtpZnkudHMiLCAic3JjL2NvbnRleHQudHMiLCAic3JjL3R5cGVzLnRzIl0sCiAgInNvdXJjZXNDb250ZW50IjogWyJpbXBvcnQgeyBOb3RpY2UsIFBsdWdpbiwgV29ya3NwYWNlTGVhZiB9IGZyb20gJ29ic2lkaWFuJztcbmltcG9ydCB7IE9wZW5DbGF3U2V0dGluZ1RhYiB9IGZyb20gJy4vc2V0dGluZ3MnO1xuaW1wb3J0IHsgT2JzaWRpYW5XU0NsaWVudCB9IGZyb20gJy4vd2Vic29ja2V0JztcbmltcG9ydCB7IENoYXRNYW5hZ2VyIH0gZnJvbSAnLi9jaGF0JztcbmltcG9ydCB7IFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFULCBPcGVuQ2xhd0NoYXRWaWV3IH0gZnJvbSAnLi92aWV3JztcbmltcG9ydCB7IERFRkFVTFRfU0VUVElOR1MsIHR5cGUgT3BlbkNsYXdTZXR0aW5ncyB9IGZyb20gJy4vdHlwZXMnO1xuXG5leHBvcnQgZGVmYXVsdCBjbGFzcyBPcGVuQ2xhd1BsdWdpbiBleHRlbmRzIFBsdWdpbiB7XG4gIHNldHRpbmdzITogT3BlbkNsYXdTZXR0aW5ncztcbiAgd3NDbGllbnQhOiBPYnNpZGlhbldTQ2xpZW50O1xuICBjaGF0TWFuYWdlciE6IENoYXRNYW5hZ2VyO1xuXG4gIGFzeW5jIG9ubG9hZCgpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBhd2FpdCB0aGlzLmxvYWRTZXR0aW5ncygpO1xuXG4gICAgdGhpcy53c0NsaWVudCA9IG5ldyBPYnNpZGlhbldTQ2xpZW50KHRoaXMuc2V0dGluZ3Muc2Vzc2lvbktleSwge1xuICAgICAgaWRlbnRpdHlTdG9yZToge1xuICAgICAgICBnZXQ6IGFzeW5jICgpID0+IChhd2FpdCB0aGlzLl9sb2FkRGV2aWNlSWRlbnRpdHkoKSksXG4gICAgICAgIHNldDogYXN5bmMgKGlkZW50aXR5KSA9PiBhd2FpdCB0aGlzLl9zYXZlRGV2aWNlSWRlbnRpdHkoaWRlbnRpdHkpLFxuICAgICAgICBjbGVhcjogYXN5bmMgKCkgPT4gYXdhaXQgdGhpcy5fY2xlYXJEZXZpY2VJZGVudGl0eSgpLFxuICAgICAgfSxcbiAgICB9KTtcbiAgICB0aGlzLmNoYXRNYW5hZ2VyID0gbmV3IENoYXRNYW5hZ2VyKCk7XG5cbiAgICAvLyBXaXJlIGluY29taW5nIFdTIG1lc3NhZ2VzIFx1MjE5MiBDaGF0TWFuYWdlclxuICAgIHRoaXMud3NDbGllbnQub25NZXNzYWdlID0gKG1zZykgPT4ge1xuICAgICAgaWYgKG1zZy50eXBlID09PSAnbWVzc2FnZScpIHtcbiAgICAgICAgdGhpcy5jaGF0TWFuYWdlci5hZGRNZXNzYWdlKENoYXRNYW5hZ2VyLmNyZWF0ZUFzc2lzdGFudE1lc3NhZ2UobXNnLnBheWxvYWQuY29udGVudCkpO1xuICAgICAgfSBlbHNlIGlmIChtc2cudHlwZSA9PT0gJ2Vycm9yJykge1xuICAgICAgICBjb25zdCBlcnJUZXh0ID0gbXNnLnBheWxvYWQubWVzc2FnZSA/PyAnVW5rbm93biBlcnJvciBmcm9tIGdhdGV3YXknO1xuICAgICAgICB0aGlzLmNoYXRNYW5hZ2VyLmFkZE1lc3NhZ2UoQ2hhdE1hbmFnZXIuY3JlYXRlU3lzdGVtTWVzc2FnZShgXHUyNkEwICR7ZXJyVGV4dH1gLCAnZXJyb3InKSk7XG4gICAgICB9XG4gICAgfTtcblxuICAgIC8vIFJlZ2lzdGVyIHRoZSBzaWRlYmFyIHZpZXdcbiAgICB0aGlzLnJlZ2lzdGVyVmlldyhcbiAgICAgIFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFULFxuICAgICAgKGxlYWY6IFdvcmtzcGFjZUxlYWYpID0+IG5ldyBPcGVuQ2xhd0NoYXRWaWV3KGxlYWYsIHRoaXMpXG4gICAgKTtcblxuICAgIC8vIFJpYmJvbiBpY29uIFx1MjAxNCBvcGVucyAvIHJldmVhbHMgdGhlIGNoYXQgc2lkZWJhclxuICAgIHRoaXMuYWRkUmliYm9uSWNvbignbWVzc2FnZS1zcXVhcmUnLCAnT3BlbkNsYXcgQ2hhdCcsICgpID0+IHtcbiAgICAgIHRoaXMuX2FjdGl2YXRlQ2hhdFZpZXcoKTtcbiAgICB9KTtcblxuICAgIC8vIFNldHRpbmdzIHRhYlxuICAgIHRoaXMuYWRkU2V0dGluZ1RhYihuZXcgT3BlbkNsYXdTZXR0aW5nVGFiKHRoaXMuYXBwLCB0aGlzKSk7XG5cbiAgICAvLyBDb21tYW5kIHBhbGV0dGUgZW50cnlcbiAgICB0aGlzLmFkZENvbW1hbmQoe1xuICAgICAgaWQ6ICdvcGVuLW9wZW5jbGF3LWNoYXQnLFxuICAgICAgbmFtZTogJ09wZW4gY2hhdCBzaWRlYmFyJyxcbiAgICAgIGNhbGxiYWNrOiAoKSA9PiB0aGlzLl9hY3RpdmF0ZUNoYXRWaWV3KCksXG4gICAgfSk7XG5cbiAgICAvLyBDb25uZWN0IHRvIGdhdGV3YXkgaWYgdG9rZW4gaXMgY29uZmlndXJlZFxuICAgIGlmICh0aGlzLnNldHRpbmdzLmF1dGhUb2tlbikge1xuICAgICAgdGhpcy5fY29ubmVjdFdTKCk7XG4gICAgfSBlbHNlIHtcbiAgICAgIG5ldyBOb3RpY2UoJ09wZW5DbGF3IENoYXQ6IHBsZWFzZSBjb25maWd1cmUgeW91ciBnYXRld2F5IHRva2VuIGluIFNldHRpbmdzLicpO1xuICAgIH1cblxuICAgIGNvbnNvbGUubG9nKCdbb2NsYXddIFBsdWdpbiBsb2FkZWQnKTtcbiAgfVxuXG4gIGFzeW5jIG9udW5sb2FkKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIHRoaXMud3NDbGllbnQuZGlzY29ubmVjdCgpO1xuICAgIHRoaXMuYXBwLndvcmtzcGFjZS5kZXRhY2hMZWF2ZXNPZlR5cGUoVklFV19UWVBFX09QRU5DTEFXX0NIQVQpO1xuICAgIGNvbnNvbGUubG9nKCdbb2NsYXddIFBsdWdpbiB1bmxvYWRlZCcpO1xuICB9XG5cbiAgYXN5bmMgbG9hZFNldHRpbmdzKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIGNvbnN0IGRhdGEgPSAoYXdhaXQgdGhpcy5sb2FkRGF0YSgpKSA/PyB7fTtcbiAgICAvLyBOT1RFOiBwbHVnaW4gZGF0YSBtYXkgY29udGFpbiBleHRyYSBwcml2YXRlIGZpZWxkcyAoZS5nLiBkZXZpY2UgaWRlbnRpdHkpLiBTZXR0aW5ncyBhcmUgdGhlIHB1YmxpYyBzdWJzZXQuXG4gICAgdGhpcy5zZXR0aW5ncyA9IE9iamVjdC5hc3NpZ24oe30sIERFRkFVTFRfU0VUVElOR1MsIGRhdGEpO1xuICB9XG5cbiAgYXN5bmMgc2F2ZVNldHRpbmdzKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIC8vIFByZXNlcnZlIGFueSBwcml2YXRlIGZpZWxkcyBzdG9yZWQgaW4gcGx1Z2luIGRhdGEuXG4gICAgY29uc3QgZGF0YSA9IChhd2FpdCB0aGlzLmxvYWREYXRhKCkpID8/IHt9O1xuICAgIGF3YWl0IHRoaXMuc2F2ZURhdGEoeyAuLi5kYXRhLCAuLi50aGlzLnNldHRpbmdzIH0pO1xuICB9XG5cbiAgLy8gXHUyNTAwXHUyNTAwIERldmljZSBpZGVudGl0eSBwZXJzaXN0ZW5jZSAocGx1Z2luLXNjb3BlZDsgTk9UIGxvY2FsU3RvcmFnZSkgXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG5cbiAgYXN5bmMgcmVzZXREZXZpY2VJZGVudGl0eSgpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBhd2FpdCB0aGlzLl9jbGVhckRldmljZUlkZW50aXR5KCk7XG4gICAgbmV3IE5vdGljZSgnT3BlbkNsYXcgQ2hhdDogZGV2aWNlIGlkZW50aXR5IHJlc2V0LiBSZWNvbm5lY3QgdG8gcGFpciBhZ2Fpbi4nKTtcbiAgfVxuXG4gIHByaXZhdGUgX2RldmljZUlkZW50aXR5S2V5ID0gJ19vcGVuY2xhd0RldmljZUlkZW50aXR5VjEnO1xuXG4gIHByaXZhdGUgYXN5bmMgX2xvYWREZXZpY2VJZGVudGl0eSgpOiBQcm9taXNlPGFueSB8IG51bGw+IHtcbiAgICBjb25zdCBkYXRhID0gKGF3YWl0IHRoaXMubG9hZERhdGEoKSkgPz8ge307XG4gICAgcmV0dXJuIChkYXRhIGFzIGFueSk/Llt0aGlzLl9kZXZpY2VJZGVudGl0eUtleV0gPz8gbnVsbDtcbiAgfVxuXG4gIHByaXZhdGUgYXN5bmMgX3NhdmVEZXZpY2VJZGVudGl0eShpZGVudGl0eTogYW55KTogUHJvbWlzZTx2b2lkPiB7XG4gICAgY29uc3QgZGF0YSA9IChhd2FpdCB0aGlzLmxvYWREYXRhKCkpID8/IHt9O1xuICAgIGF3YWl0IHRoaXMuc2F2ZURhdGEoeyAuLi5kYXRhLCBbdGhpcy5fZGV2aWNlSWRlbnRpdHlLZXldOiBpZGVudGl0eSB9KTtcbiAgfVxuXG4gIHByaXZhdGUgYXN5bmMgX2NsZWFyRGV2aWNlSWRlbnRpdHkoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgY29uc3QgZGF0YSA9IChhd2FpdCB0aGlzLmxvYWREYXRhKCkpID8/IHt9O1xuICAgIGlmICgoZGF0YSBhcyBhbnkpPy5bdGhpcy5fZGV2aWNlSWRlbnRpdHlLZXldID09PSB1bmRlZmluZWQpIHJldHVybjtcbiAgICBjb25zdCBuZXh0ID0geyAuLi4oZGF0YSBhcyBhbnkpIH07XG4gICAgZGVsZXRlIG5leHRbdGhpcy5fZGV2aWNlSWRlbnRpdHlLZXldO1xuICAgIGF3YWl0IHRoaXMuc2F2ZURhdGEobmV4dCk7XG4gIH1cblxuICAvLyBcdTI1MDBcdTI1MDAgSGVscGVycyBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcblxuICBwcml2YXRlIF9jb25uZWN0V1MoKTogdm9pZCB7XG4gICAgdGhpcy53c0NsaWVudC5jb25uZWN0KHRoaXMuc2V0dGluZ3MuZ2F0ZXdheVVybCwgdGhpcy5zZXR0aW5ncy5hdXRoVG9rZW4sIHtcbiAgICAgIGFsbG93SW5zZWN1cmVXczogdGhpcy5zZXR0aW5ncy5hbGxvd0luc2VjdXJlV3MsXG4gICAgfSk7XG4gIH1cblxuICBwcml2YXRlIGFzeW5jIF9hY3RpdmF0ZUNoYXRWaWV3KCk6IFByb21pc2U8dm9pZD4ge1xuICAgIGNvbnN0IHsgd29ya3NwYWNlIH0gPSB0aGlzLmFwcDtcblxuICAgIC8vIFJldXNlIGV4aXN0aW5nIGxlYWYgaWYgYWxyZWFkeSBvcGVuXG4gICAgY29uc3QgZXhpc3RpbmcgPSB3b3Jrc3BhY2UuZ2V0TGVhdmVzT2ZUeXBlKFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFUKTtcbiAgICBpZiAoZXhpc3RpbmcubGVuZ3RoID4gMCkge1xuICAgICAgd29ya3NwYWNlLnJldmVhbExlYWYoZXhpc3RpbmdbMF0pO1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIC8vIE9wZW4gaW4gcmlnaHQgc2lkZWJhclxuICAgIGNvbnN0IGxlYWYgPSB3b3Jrc3BhY2UuZ2V0UmlnaHRMZWFmKGZhbHNlKTtcbiAgICBpZiAoIWxlYWYpIHJldHVybjtcbiAgICBhd2FpdCBsZWFmLnNldFZpZXdTdGF0ZSh7IHR5cGU6IFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFULCBhY3RpdmU6IHRydWUgfSk7XG4gICAgd29ya3NwYWNlLnJldmVhbExlYWYobGVhZik7XG4gIH1cbn1cbiIsICJpbXBvcnQgeyBBcHAsIFBsdWdpblNldHRpbmdUYWIsIFNldHRpbmcgfSBmcm9tICdvYnNpZGlhbic7XG5pbXBvcnQgdHlwZSBPcGVuQ2xhd1BsdWdpbiBmcm9tICcuL21haW4nO1xuXG5leHBvcnQgY2xhc3MgT3BlbkNsYXdTZXR0aW5nVGFiIGV4dGVuZHMgUGx1Z2luU2V0dGluZ1RhYiB7XG4gIHBsdWdpbjogT3BlbkNsYXdQbHVnaW47XG5cbiAgY29uc3RydWN0b3IoYXBwOiBBcHAsIHBsdWdpbjogT3BlbkNsYXdQbHVnaW4pIHtcbiAgICBzdXBlcihhcHAsIHBsdWdpbik7XG4gICAgdGhpcy5wbHVnaW4gPSBwbHVnaW47XG4gIH1cblxuICBkaXNwbGF5KCk6IHZvaWQge1xuICAgIGNvbnN0IHsgY29udGFpbmVyRWwgfSA9IHRoaXM7XG4gICAgY29udGFpbmVyRWwuZW1wdHkoKTtcblxuICAgIGNvbnRhaW5lckVsLmNyZWF0ZUVsKCdoMicsIHsgdGV4dDogJ09wZW5DbGF3IENoYXQgXHUyMDEzIFNldHRpbmdzJyB9KTtcblxuICAgIG5ldyBTZXR0aW5nKGNvbnRhaW5lckVsKVxuICAgICAgLnNldE5hbWUoJ0dhdGV3YXkgVVJMJylcbiAgICAgIC5zZXREZXNjKCdXZWJTb2NrZXQgVVJMIG9mIHRoZSBPcGVuQ2xhdyBHYXRld2F5IChlLmcuIHdzOi8vaG9zdG5hbWU6MTg3ODkpLicpXG4gICAgICAuYWRkVGV4dCgodGV4dCkgPT5cbiAgICAgICAgdGV4dFxuICAgICAgICAgIC5zZXRQbGFjZWhvbGRlcignd3M6Ly9sb2NhbGhvc3Q6MTg3ODknKVxuICAgICAgICAgIC5zZXRWYWx1ZSh0aGlzLnBsdWdpbi5zZXR0aW5ncy5nYXRld2F5VXJsKVxuICAgICAgICAgIC5vbkNoYW5nZShhc3luYyAodmFsdWUpID0+IHtcbiAgICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLmdhdGV3YXlVcmwgPSB2YWx1ZS50cmltKCk7XG4gICAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgICB9KVxuICAgICAgKTtcblxuICAgIG5ldyBTZXR0aW5nKGNvbnRhaW5lckVsKVxuICAgICAgLnNldE5hbWUoJ0F1dGggdG9rZW4nKVxuICAgICAgLnNldERlc2MoJ011c3QgbWF0Y2ggdGhlIGF1dGhUb2tlbiBpbiB5b3VyIG9wZW5jbGF3Lmpzb24gY2hhbm5lbCBjb25maWcuIE5ldmVyIHNoYXJlZC4nKVxuICAgICAgLmFkZFRleHQoKHRleHQpID0+IHtcbiAgICAgICAgdGV4dFxuICAgICAgICAgIC5zZXRQbGFjZWhvbGRlcignRW50ZXIgdG9rZW5cdTIwMjYnKVxuICAgICAgICAgIC5zZXRWYWx1ZSh0aGlzLnBsdWdpbi5zZXR0aW5ncy5hdXRoVG9rZW4pXG4gICAgICAgICAgLm9uQ2hhbmdlKGFzeW5jICh2YWx1ZSkgPT4ge1xuICAgICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3MuYXV0aFRva2VuID0gdmFsdWU7XG4gICAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgICB9KTtcbiAgICAgICAgLy8gVHJlYXQgYXMgcGFzc3dvcmQgZmllbGQgXHUyMDEzIGRvIG5vdCByZXZlYWwgdG9rZW4gaW4gVUlcbiAgICAgICAgdGV4dC5pbnB1dEVsLnR5cGUgPSAncGFzc3dvcmQnO1xuICAgICAgICB0ZXh0LmlucHV0RWwuYXV0b2NvbXBsZXRlID0gJ29mZic7XG4gICAgICB9KTtcblxuICAgIG5ldyBTZXR0aW5nKGNvbnRhaW5lckVsKVxuICAgICAgLnNldE5hbWUoJ1Nlc3Npb24gS2V5JylcbiAgICAgIC5zZXREZXNjKCdPcGVuQ2xhdyBzZXNzaW9uIHRvIHN1YnNjcmliZSB0byAodXN1YWxseSBcIm1haW5cIikuJylcbiAgICAgIC5hZGRUZXh0KCh0ZXh0KSA9PlxuICAgICAgICB0ZXh0XG4gICAgICAgICAgLnNldFBsYWNlaG9sZGVyKCdtYWluJylcbiAgICAgICAgICAuc2V0VmFsdWUodGhpcy5wbHVnaW4uc2V0dGluZ3Muc2Vzc2lvbktleSlcbiAgICAgICAgICAub25DaGFuZ2UoYXN5bmMgKHZhbHVlKSA9PiB7XG4gICAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5zZXNzaW9uS2V5ID0gdmFsdWUudHJpbSgpIHx8ICdtYWluJztcbiAgICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICAgIH0pXG4gICAgICApO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZSgnQWNjb3VudCBJRCcpXG4gICAgICAuc2V0RGVzYygnT3BlbkNsYXcgYWNjb3VudCBJRCAodXN1YWxseSBcIm1haW5cIikuJylcbiAgICAgIC5hZGRUZXh0KCh0ZXh0KSA9PlxuICAgICAgICB0ZXh0XG4gICAgICAgICAgLnNldFBsYWNlaG9sZGVyKCdtYWluJylcbiAgICAgICAgICAuc2V0VmFsdWUodGhpcy5wbHVnaW4uc2V0dGluZ3MuYWNjb3VudElkKVxuICAgICAgICAgIC5vbkNoYW5nZShhc3luYyAodmFsdWUpID0+IHtcbiAgICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLmFjY291bnRJZCA9IHZhbHVlLnRyaW0oKSB8fCAnbWFpbic7XG4gICAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgICB9KVxuICAgICAgKTtcblxuICAgIG5ldyBTZXR0aW5nKGNvbnRhaW5lckVsKVxuICAgICAgLnNldE5hbWUoJ0luY2x1ZGUgYWN0aXZlIG5vdGUgYnkgZGVmYXVsdCcpXG4gICAgICAuc2V0RGVzYygnUHJlLWNoZWNrIFwiSW5jbHVkZSBhY3RpdmUgbm90ZVwiIGluIHRoZSBjaGF0IHBhbmVsIHdoZW4gaXQgb3BlbnMuJylcbiAgICAgIC5hZGRUb2dnbGUoKHRvZ2dsZSkgPT5cbiAgICAgICAgdG9nZ2xlLnNldFZhbHVlKHRoaXMucGx1Z2luLnNldHRpbmdzLmluY2x1ZGVBY3RpdmVOb3RlKS5vbkNoYW5nZShhc3luYyAodmFsdWUpID0+IHtcbiAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5pbmNsdWRlQWN0aXZlTm90ZSA9IHZhbHVlO1xuICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICB9KVxuICAgICAgKTtcblxuICAgIG5ldyBTZXR0aW5nKGNvbnRhaW5lckVsKVxuICAgICAgLnNldE5hbWUoJ1JlbmRlciBhc3Npc3RhbnQgYXMgTWFya2Rvd24gKHVuc2FmZSknKVxuICAgICAgLnNldERlc2MoXG4gICAgICAgICdPRkYgcmVjb21tZW5kZWQuIElmIGVuYWJsZWQsIGFzc2lzdGFudCBvdXRwdXQgaXMgcmVuZGVyZWQgYXMgT2JzaWRpYW4gTWFya2Rvd24gd2hpY2ggbWF5IHRyaWdnZXIgZW1iZWRzIGFuZCBvdGhlciBwbHVnaW5zXFwnIHBvc3QtcHJvY2Vzc29ycy4nXG4gICAgICApXG4gICAgICAuYWRkVG9nZ2xlKCh0b2dnbGUpID0+XG4gICAgICAgIHRvZ2dsZS5zZXRWYWx1ZSh0aGlzLnBsdWdpbi5zZXR0aW5ncy5yZW5kZXJBc3Npc3RhbnRNYXJrZG93bikub25DaGFuZ2UoYXN5bmMgKHZhbHVlKSA9PiB7XG4gICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3MucmVuZGVyQXNzaXN0YW50TWFya2Rvd24gPSB2YWx1ZTtcbiAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgfSlcbiAgICAgICk7XG5cbiAgICBuZXcgU2V0dGluZyhjb250YWluZXJFbClcbiAgICAgIC5zZXROYW1lKCdBbGxvdyBpbnNlY3VyZSB3czovLyBmb3Igbm9uLWxvY2FsIGdhdGV3YXlzICh1bnNhZmUpJylcbiAgICAgIC5zZXREZXNjKFxuICAgICAgICAnT0ZGIHJlY29tbWVuZGVkLiBJZiBlbmFibGVkLCB5b3UgY2FuIGNvbm5lY3QgdG8gbm9uLWxvY2FsIGdhdGV3YXlzIG92ZXIgd3M6Ly8uIFRoaXMgZXhwb3NlcyB5b3VyIHRva2VuIGFuZCBtZXNzYWdlIGNvbnRlbnQgdG8gbmV0d29yayBhdHRhY2tlcnM7IHByZWZlciB3c3M6Ly8uJ1xuICAgICAgKVxuICAgICAgLmFkZFRvZ2dsZSgodG9nZ2xlKSA9PlxuICAgICAgICB0b2dnbGUuc2V0VmFsdWUodGhpcy5wbHVnaW4uc2V0dGluZ3MuYWxsb3dJbnNlY3VyZVdzKS5vbkNoYW5nZShhc3luYyAodmFsdWUpID0+IHtcbiAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5hbGxvd0luc2VjdXJlV3MgPSB2YWx1ZTtcbiAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgfSlcbiAgICAgICk7XG5cbiAgICBuZXcgU2V0dGluZyhjb250YWluZXJFbClcbiAgICAgIC5zZXROYW1lKCdSZXNldCBkZXZpY2UgaWRlbnRpdHkgKHJlLXBhaXIpJylcbiAgICAgIC5zZXREZXNjKCdDbGVhcnMgdGhlIHN0b3JlZCBkZXZpY2UgaWRlbnRpdHkgdXNlZCBmb3Igb3BlcmF0b3Iud3JpdGUgcGFpcmluZy4gVXNlIHRoaXMgaWYgeW91IHN1c3BlY3QgY29tcHJvbWlzZSBvciBzZWUgXCJkZXZpY2UgaWRlbnRpdHkgbWlzbWF0Y2hcIi4nKVxuICAgICAgLmFkZEJ1dHRvbigoYnRuKSA9PlxuICAgICAgICBidG4uc2V0QnV0dG9uVGV4dCgnUmVzZXQnKS5zZXRXYXJuaW5nKCkub25DbGljayhhc3luYyAoKSA9PiB7XG4gICAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4ucmVzZXREZXZpY2VJZGVudGl0eSgpO1xuICAgICAgICB9KVxuICAgICAgKTtcblxuICAgIC8vIFx1MjUwMFx1MjUwMCBQYXRoIG1hcHBpbmdzIFx1MjUwMFx1MjUwMFxuICAgIGNvbnRhaW5lckVsLmNyZWF0ZUVsKCdoMycsIHsgdGV4dDogJ1BhdGggbWFwcGluZ3MgKHZhdWx0IGJhc2UgXHUyMTkyIHJlbW90ZSBiYXNlKScgfSk7XG4gICAgY29udGFpbmVyRWwuY3JlYXRlRWwoJ3AnLCB7XG4gICAgICB0ZXh0OiAnVXNlZCB0byBjb252ZXJ0IGFzc2lzdGFudCBmaWxlIHJlZmVyZW5jZXMgKHJlbW90ZSBGUyBwYXRocyBvciBleHBvcnRlZCBVUkxzKSBpbnRvIGNsaWNrYWJsZSBPYnNpZGlhbiBsaW5rcy4gRmlyc3QgbWF0Y2ggd2lucy4gT25seSBjcmVhdGVzIGEgbGluayBpZiB0aGUgbWFwcGVkIHZhdWx0IGZpbGUgZXhpc3RzLicsXG4gICAgICBjbHM6ICdzZXR0aW5nLWl0ZW0tZGVzY3JpcHRpb24nLFxuICAgIH0pO1xuXG4gICAgY29uc3QgbWFwcGluZ3MgPSB0aGlzLnBsdWdpbi5zZXR0aW5ncy5wYXRoTWFwcGluZ3MgPz8gW107XG5cbiAgICBjb25zdCByZXJlbmRlciA9IGFzeW5jICgpID0+IHtcbiAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgdGhpcy5kaXNwbGF5KCk7XG4gICAgfTtcblxuICAgIG1hcHBpbmdzLmZvckVhY2goKHJvdywgaWR4KSA9PiB7XG4gICAgICBjb25zdCBzID0gbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAgIC5zZXROYW1lKGBNYXBwaW5nICMke2lkeCArIDF9YClcbiAgICAgICAgLnNldERlc2MoJ3ZhdWx0QmFzZSBcdTIxOTIgcmVtb3RlQmFzZScpO1xuXG4gICAgICBzLmFkZFRleHQoKHQpID0+XG4gICAgICAgIHRcbiAgICAgICAgICAuc2V0UGxhY2Vob2xkZXIoJ3ZhdWx0IGJhc2UgKGUuZy4gZG9jcy8pJylcbiAgICAgICAgICAuc2V0VmFsdWUocm93LnZhdWx0QmFzZSA/PyAnJylcbiAgICAgICAgICAub25DaGFuZ2UoYXN5bmMgKHYpID0+IHtcbiAgICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLnBhdGhNYXBwaW5nc1tpZHhdLnZhdWx0QmFzZSA9IHY7XG4gICAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgICB9KVxuICAgICAgKTtcblxuICAgICAgcy5hZGRUZXh0KCh0KSA9PlxuICAgICAgICB0XG4gICAgICAgICAgLnNldFBsYWNlaG9sZGVyKCdyZW1vdGUgYmFzZSAoZS5nLiAvaG9tZS8uLi4vZG9jcy8pJylcbiAgICAgICAgICAuc2V0VmFsdWUocm93LnJlbW90ZUJhc2UgPz8gJycpXG4gICAgICAgICAgLm9uQ2hhbmdlKGFzeW5jICh2KSA9PiB7XG4gICAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5wYXRoTWFwcGluZ3NbaWR4XS5yZW1vdGVCYXNlID0gdjtcbiAgICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICAgIH0pXG4gICAgICApO1xuXG4gICAgICBzLmFkZEV4dHJhQnV0dG9uKChiKSA9PlxuICAgICAgICBiXG4gICAgICAgICAgLnNldEljb24oJ3RyYXNoJylcbiAgICAgICAgICAuc2V0VG9vbHRpcCgnUmVtb3ZlIG1hcHBpbmcnKVxuICAgICAgICAgIC5vbkNsaWNrKGFzeW5jICgpID0+IHtcbiAgICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLnBhdGhNYXBwaW5ncy5zcGxpY2UoaWR4LCAxKTtcbiAgICAgICAgICAgIGF3YWl0IHJlcmVuZGVyKCk7XG4gICAgICAgICAgfSlcbiAgICAgICk7XG4gICAgfSk7XG5cbiAgICBuZXcgU2V0dGluZyhjb250YWluZXJFbClcbiAgICAgIC5zZXROYW1lKCdBZGQgbWFwcGluZycpXG4gICAgICAuc2V0RGVzYygnQWRkIGEgbmV3IHZhdWx0QmFzZSBcdTIxOTIgcmVtb3RlQmFzZSBtYXBwaW5nIHJvdy4nKVxuICAgICAgLmFkZEJ1dHRvbigoYnRuKSA9PlxuICAgICAgICBidG4uc2V0QnV0dG9uVGV4dCgnQWRkJykub25DbGljayhhc3luYyAoKSA9PiB7XG4gICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3MucGF0aE1hcHBpbmdzLnB1c2goeyB2YXVsdEJhc2U6ICcnLCByZW1vdGVCYXNlOiAnJyB9KTtcbiAgICAgICAgICBhd2FpdCByZXJlbmRlcigpO1xuICAgICAgICB9KVxuICAgICAgKTtcblxuICAgIGNvbnRhaW5lckVsLmNyZWF0ZUVsKCdwJywge1xuICAgICAgdGV4dDogJ1JlY29ubmVjdDogY2xvc2UgYW5kIHJlb3BlbiB0aGUgc2lkZWJhciBhZnRlciBjaGFuZ2luZyB0aGUgZ2F0ZXdheSBVUkwgb3IgdG9rZW4uJyxcbiAgICAgIGNsczogJ3NldHRpbmctaXRlbS1kZXNjcmlwdGlvbicsXG4gICAgfSk7XG4gIH1cbn1cbiIsICIvKipcbiAqIFdlYlNvY2tldCBjbGllbnQgZm9yIE9wZW5DbGF3IEdhdGV3YXlcbiAqXG4gKiBQaXZvdCAoMjAyNi0wMi0yNSk6IERvIE5PVCB1c2UgY3VzdG9tIG9ic2lkaWFuLiogZ2F0ZXdheSBtZXRob2RzLlxuICogVGhvc2UgcmVxdWlyZSBvcGVyYXRvci5hZG1pbiBzY29wZSB3aGljaCBpcyBub3QgZ3JhbnRlZCB0byBleHRlcm5hbCBjbGllbnRzLlxuICpcbiAqIEF1dGggbm90ZTpcbiAqIC0gY2hhdC5zZW5kIHJlcXVpcmVzIG9wZXJhdG9yLndyaXRlXG4gKiAtIGV4dGVybmFsIGNsaWVudHMgbXVzdCBwcmVzZW50IGEgcGFpcmVkIGRldmljZSBpZGVudGl0eSB0byByZWNlaXZlIHdyaXRlIHNjb3Blc1xuICpcbiAqIFdlIHVzZSBidWlsdC1pbiBnYXRld2F5IG1ldGhvZHMvZXZlbnRzOlxuICogLSBTZW5kOiBjaGF0LnNlbmQoeyBzZXNzaW9uS2V5LCBtZXNzYWdlLCBpZGVtcG90ZW5jeUtleSwgLi4uIH0pXG4gKiAtIFJlY2VpdmU6IGV2ZW50IFwiY2hhdFwiIChmaWx0ZXIgYnkgc2Vzc2lvbktleSlcbiAqL1xuXG5pbXBvcnQgdHlwZSB7IEluYm91bmRXU1BheWxvYWQgfSBmcm9tICcuL3R5cGVzJztcblxuZnVuY3Rpb24gaXNMb2NhbEhvc3QoaG9zdDogc3RyaW5nKTogYm9vbGVhbiB7XG4gIGNvbnN0IGggPSBob3N0LnRvTG93ZXJDYXNlKCk7XG4gIHJldHVybiBoID09PSAnbG9jYWxob3N0JyB8fCBoID09PSAnMTI3LjAuMC4xJyB8fCBoID09PSAnOjoxJztcbn1cblxuZnVuY3Rpb24gc2FmZVBhcnNlV3NVcmwodXJsOiBzdHJpbmcpOlxuICB8IHsgb2s6IHRydWU7IHNjaGVtZTogJ3dzJyB8ICd3c3MnOyBob3N0OiBzdHJpbmcgfVxuICB8IHsgb2s6IGZhbHNlOyBlcnJvcjogc3RyaW5nIH0ge1xuICB0cnkge1xuICAgIGNvbnN0IHUgPSBuZXcgVVJMKHVybCk7XG4gICAgaWYgKHUucHJvdG9jb2wgIT09ICd3czonICYmIHUucHJvdG9jb2wgIT09ICd3c3M6Jykge1xuICAgICAgcmV0dXJuIHsgb2s6IGZhbHNlLCBlcnJvcjogYEdhdGV3YXkgVVJMIG11c3QgYmUgd3M6Ly8gb3Igd3NzOi8vIChnb3QgJHt1LnByb3RvY29sfSlgIH07XG4gICAgfVxuICAgIGNvbnN0IHNjaGVtZSA9IHUucHJvdG9jb2wgPT09ICd3czonID8gJ3dzJyA6ICd3c3MnO1xuICAgIHJldHVybiB7IG9rOiB0cnVlLCBzY2hlbWUsIGhvc3Q6IHUuaG9zdG5hbWUgfTtcbiAgfSBjYXRjaCB7XG4gICAgcmV0dXJuIHsgb2s6IGZhbHNlLCBlcnJvcjogJ0ludmFsaWQgZ2F0ZXdheSBVUkwnIH07XG4gIH1cbn1cblxuLyoqIEludGVydmFsIGZvciBzZW5kaW5nIGhlYXJ0YmVhdCBwaW5ncyAoY2hlY2sgY29ubmVjdGlvbiBsaXZlbmVzcykgKi9cbmNvbnN0IEhFQVJUQkVBVF9JTlRFUlZBTF9NUyA9IDMwXzAwMDtcblxuLyoqIFNhZmV0eSB2YWx2ZTogaGlkZSB3b3JraW5nIHNwaW5uZXIgaWYgbm8gYXNzaXN0YW50IHJlcGx5IGFycml2ZXMgaW4gdGltZSAqL1xuY29uc3QgV09SS0lOR19NQVhfTVMgPSAxMjBfMDAwO1xuXG4vKiogTWF4IGluYm91bmQgZnJhbWUgc2l6ZSB0byBwYXJzZSAoRG9TIGd1YXJkKSAqL1xuY29uc3QgTUFYX0lOQk9VTkRfRlJBTUVfQllURVMgPSA1MTIgKiAxMDI0O1xuXG5mdW5jdGlvbiBieXRlTGVuZ3RoVXRmOCh0ZXh0OiBzdHJpbmcpOiBudW1iZXIge1xuICByZXR1cm4gdXRmOEJ5dGVzKHRleHQpLmJ5dGVMZW5ndGg7XG59XG5cbmFzeW5jIGZ1bmN0aW9uIG5vcm1hbGl6ZVdzRGF0YVRvVGV4dChkYXRhOiBhbnkpOiBQcm9taXNlPHsgb2s6IHRydWU7IHRleHQ6IHN0cmluZzsgYnl0ZXM6IG51bWJlciB9IHwgeyBvazogZmFsc2U7IHJlYXNvbjogc3RyaW5nOyBieXRlcz86IG51bWJlciB9PiB7XG4gIGlmICh0eXBlb2YgZGF0YSA9PT0gJ3N0cmluZycpIHtcbiAgICBjb25zdCBieXRlcyA9IGJ5dGVMZW5ndGhVdGY4KGRhdGEpO1xuICAgIHJldHVybiB7IG9rOiB0cnVlLCB0ZXh0OiBkYXRhLCBieXRlcyB9O1xuICB9XG5cbiAgLy8gQnJvd3NlciBXZWJTb2NrZXQgY2FuIGRlbGl2ZXIgQmxvYlxuICBpZiAodHlwZW9mIEJsb2IgIT09ICd1bmRlZmluZWQnICYmIGRhdGEgaW5zdGFuY2VvZiBCbG9iKSB7XG4gICAgY29uc3QgYnl0ZXMgPSBkYXRhLnNpemU7XG4gICAgaWYgKGJ5dGVzID4gTUFYX0lOQk9VTkRfRlJBTUVfQllURVMpIHJldHVybiB7IG9rOiBmYWxzZSwgcmVhc29uOiAndG9vLWxhcmdlJywgYnl0ZXMgfTtcbiAgICBjb25zdCB0ZXh0ID0gYXdhaXQgZGF0YS50ZXh0KCk7XG4gICAgLy8gQmxvYi5zaXplIGlzIGJ5dGVzIGFscmVhZHk7IG5vIG5lZWQgdG8gcmUtbWVhc3VyZS5cbiAgICByZXR1cm4geyBvazogdHJ1ZSwgdGV4dCwgYnl0ZXMgfTtcbiAgfVxuXG4gIGlmIChkYXRhIGluc3RhbmNlb2YgQXJyYXlCdWZmZXIpIHtcbiAgICBjb25zdCBieXRlcyA9IGRhdGEuYnl0ZUxlbmd0aDtcbiAgICBpZiAoYnl0ZXMgPiBNQVhfSU5CT1VORF9GUkFNRV9CWVRFUykgcmV0dXJuIHsgb2s6IGZhbHNlLCByZWFzb246ICd0b28tbGFyZ2UnLCBieXRlcyB9O1xuICAgIGNvbnN0IHRleHQgPSBuZXcgVGV4dERlY29kZXIoJ3V0Zi04JywgeyBmYXRhbDogZmFsc2UgfSkuZGVjb2RlKG5ldyBVaW50OEFycmF5KGRhdGEpKTtcbiAgICByZXR1cm4geyBvazogdHJ1ZSwgdGV4dCwgYnl0ZXMgfTtcbiAgfVxuXG4gIC8vIFNvbWUgcnVudGltZXMgY291bGQgcGFzcyBVaW50OEFycmF5IGRpcmVjdGx5XG4gIGlmIChkYXRhIGluc3RhbmNlb2YgVWludDhBcnJheSkge1xuICAgIGNvbnN0IGJ5dGVzID0gZGF0YS5ieXRlTGVuZ3RoO1xuICAgIGlmIChieXRlcyA+IE1BWF9JTkJPVU5EX0ZSQU1FX0JZVEVTKSByZXR1cm4geyBvazogZmFsc2UsIHJlYXNvbjogJ3Rvby1sYXJnZScsIGJ5dGVzIH07XG4gICAgY29uc3QgdGV4dCA9IG5ldyBUZXh0RGVjb2RlcigndXRmLTgnLCB7IGZhdGFsOiBmYWxzZSB9KS5kZWNvZGUoZGF0YSk7XG4gICAgcmV0dXJuIHsgb2s6IHRydWUsIHRleHQsIGJ5dGVzIH07XG4gIH1cblxuICByZXR1cm4geyBvazogZmFsc2UsIHJlYXNvbjogJ3Vuc3VwcG9ydGVkLXR5cGUnIH07XG59XG5cbi8qKiBNYXggaW4tZmxpZ2h0IHJlcXVlc3RzIGJlZm9yZSBmYXN0LWZhaWxpbmcgKERvUy9yb2J1c3RuZXNzIGd1YXJkKSAqL1xuY29uc3QgTUFYX1BFTkRJTkdfUkVRVUVTVFMgPSAyMDA7XG5cbi8qKiBSZWNvbm5lY3QgYmFja29mZiAqL1xuY29uc3QgUkVDT05ORUNUX0JBU0VfTVMgPSAzXzAwMDtcbmNvbnN0IFJFQ09OTkVDVF9NQVhfTVMgPSA2MF8wMDA7XG5cbi8qKiBIYW5kc2hha2UgZGVhZGxpbmUgd2FpdGluZyBmb3IgY29ubmVjdC5jaGFsbGVuZ2UgKi9cbmNvbnN0IEhBTkRTSEFLRV9USU1FT1VUX01TID0gMTVfMDAwO1xuXG5leHBvcnQgdHlwZSBXU0NsaWVudFN0YXRlID0gJ2Rpc2Nvbm5lY3RlZCcgfCAnY29ubmVjdGluZycgfCAnaGFuZHNoYWtpbmcnIHwgJ2Nvbm5lY3RlZCc7XG5cbmV4cG9ydCB0eXBlIFdvcmtpbmdTdGF0ZUxpc3RlbmVyID0gKHdvcmtpbmc6IGJvb2xlYW4pID0+IHZvaWQ7XG5cbmludGVyZmFjZSBQZW5kaW5nUmVxdWVzdCB7XG4gIHJlc29sdmU6IChwYXlsb2FkOiBhbnkpID0+IHZvaWQ7XG4gIHJlamVjdDogKGVycm9yOiBhbnkpID0+IHZvaWQ7XG4gIHRpbWVvdXQ6IFJldHVyblR5cGU8dHlwZW9mIHNldFRpbWVvdXQ+IHwgbnVsbDtcbn1cblxuZXhwb3J0IHR5cGUgRGV2aWNlSWRlbnRpdHkgPSB7XG4gIGlkOiBzdHJpbmc7XG4gIHB1YmxpY0tleTogc3RyaW5nOyAvLyBiYXNlNjRcbiAgcHJpdmF0ZUtleUp3azogSnNvbldlYktleTtcbn07XG5cbmV4cG9ydCBpbnRlcmZhY2UgRGV2aWNlSWRlbnRpdHlTdG9yZSB7XG4gIGdldCgpOiBQcm9taXNlPERldmljZUlkZW50aXR5IHwgbnVsbD47XG4gIHNldChpZGVudGl0eTogRGV2aWNlSWRlbnRpdHkpOiBQcm9taXNlPHZvaWQ+O1xuICBjbGVhcigpOiBQcm9taXNlPHZvaWQ+O1xufVxuXG5jb25zdCBERVZJQ0VfU1RPUkFHRV9LRVkgPSAnb3BlbmNsYXdDaGF0LmRldmljZUlkZW50aXR5LnYxJzsgLy8gbGVnYWN5IGxvY2FsU3RvcmFnZSBrZXkgKG1pZ3JhdGlvbiBvbmx5KVxuXG5mdW5jdGlvbiBiYXNlNjRVcmxFbmNvZGUoYnl0ZXM6IEFycmF5QnVmZmVyKTogc3RyaW5nIHtcbiAgY29uc3QgdTggPSBuZXcgVWludDhBcnJheShieXRlcyk7XG4gIGxldCBzID0gJyc7XG4gIGZvciAobGV0IGkgPSAwOyBpIDwgdTgubGVuZ3RoOyBpKyspIHMgKz0gU3RyaW5nLmZyb21DaGFyQ29kZSh1OFtpXSk7XG4gIGNvbnN0IGI2NCA9IGJ0b2Eocyk7XG4gIHJldHVybiBiNjQucmVwbGFjZSgvXFwrL2csICctJykucmVwbGFjZSgvXFwvL2csICdfJykucmVwbGFjZSgvPSskL2csICcnKTtcbn1cblxuZnVuY3Rpb24gaGV4RW5jb2RlKGJ5dGVzOiBBcnJheUJ1ZmZlcik6IHN0cmluZyB7XG4gIGNvbnN0IHU4ID0gbmV3IFVpbnQ4QXJyYXkoYnl0ZXMpO1xuICByZXR1cm4gQXJyYXkuZnJvbSh1OClcbiAgICAubWFwKChiKSA9PiBiLnRvU3RyaW5nKDE2KS5wYWRTdGFydCgyLCAnMCcpKVxuICAgIC5qb2luKCcnKTtcbn1cblxuZnVuY3Rpb24gdXRmOEJ5dGVzKHRleHQ6IHN0cmluZyk6IFVpbnQ4QXJyYXkge1xuICByZXR1cm4gbmV3IFRleHRFbmNvZGVyKCkuZW5jb2RlKHRleHQpO1xufVxuXG5hc3luYyBmdW5jdGlvbiBzaGEyNTZIZXgoYnl0ZXM6IEFycmF5QnVmZmVyKTogUHJvbWlzZTxzdHJpbmc+IHtcbiAgY29uc3QgZGlnZXN0ID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5kaWdlc3QoJ1NIQS0yNTYnLCBieXRlcyk7XG4gIHJldHVybiBoZXhFbmNvZGUoZGlnZXN0KTtcbn1cblxuYXN5bmMgZnVuY3Rpb24gbG9hZE9yQ3JlYXRlRGV2aWNlSWRlbnRpdHkoc3RvcmU/OiBEZXZpY2VJZGVudGl0eVN0b3JlKTogUHJvbWlzZTxEZXZpY2VJZGVudGl0eT4ge1xuICAvLyAxKSBQcmVmZXIgcGx1Z2luLXNjb3BlZCBzdG9yYWdlIChpbmplY3RlZCBieSBtYWluIHBsdWdpbikuXG4gIGlmIChzdG9yZSkge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCBleGlzdGluZyA9IGF3YWl0IHN0b3JlLmdldCgpO1xuICAgICAgaWYgKGV4aXN0aW5nPy5pZCAmJiBleGlzdGluZz8ucHVibGljS2V5ICYmIGV4aXN0aW5nPy5wcml2YXRlS2V5SndrKSByZXR1cm4gZXhpc3Rpbmc7XG4gICAgfSBjYXRjaCB7XG4gICAgICAvLyBpZ25vcmUgYW5kIGNvbnRpbnVlICh3ZSBjYW4gYWx3YXlzIHJlLWdlbmVyYXRlKVxuICAgIH1cbiAgfVxuXG4gIC8vIDIpIE9uZS10aW1lIG1pZ3JhdGlvbjogbGVnYWN5IGxvY2FsU3RvcmFnZSBpZGVudGl0eS5cbiAgLy8gTk9URTogdGhpcyByZW1haW5zIGEgcmlzayBib3VuZGFyeTsgd2Ugb25seSByZWFkK2RlbGV0ZSBmb3IgbWlncmF0aW9uLlxuICBjb25zdCBsZWdhY3kgPSBsb2NhbFN0b3JhZ2UuZ2V0SXRlbShERVZJQ0VfU1RPUkFHRV9LRVkpO1xuICBpZiAobGVnYWN5KSB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IHBhcnNlZCA9IEpTT04ucGFyc2UobGVnYWN5KSBhcyBEZXZpY2VJZGVudGl0eTtcbiAgICAgIGlmIChwYXJzZWQ/LmlkICYmIHBhcnNlZD8ucHVibGljS2V5ICYmIHBhcnNlZD8ucHJpdmF0ZUtleUp3aykge1xuICAgICAgICBpZiAoc3RvcmUpIHtcbiAgICAgICAgICBhd2FpdCBzdG9yZS5zZXQocGFyc2VkKTtcbiAgICAgICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbShERVZJQ0VfU1RPUkFHRV9LRVkpO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiBwYXJzZWQ7XG4gICAgICB9XG4gICAgfSBjYXRjaCB7XG4gICAgICAvLyBDb3JydXB0L3BhcnRpYWwgZGF0YSBcdTIxOTIgZGVsZXRlIGFuZCByZS1jcmVhdGUuXG4gICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbShERVZJQ0VfU1RPUkFHRV9LRVkpO1xuICAgIH1cbiAgfVxuXG4gIC8vIDMpIENyZWF0ZSBhIG5ldyBpZGVudGl0eS5cbiAgY29uc3Qga2V5UGFpciA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuZ2VuZXJhdGVLZXkoeyBuYW1lOiAnRWQyNTUxOScgfSwgdHJ1ZSwgWydzaWduJywgJ3ZlcmlmeSddKTtcbiAgY29uc3QgcHViUmF3ID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5leHBvcnRLZXkoJ3JhdycsIGtleVBhaXIucHVibGljS2V5KTtcbiAgY29uc3QgcHJpdkp3ayA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuZXhwb3J0S2V5KCdqd2snLCBrZXlQYWlyLnByaXZhdGVLZXkpO1xuXG4gIC8vIElNUE9SVEFOVDogZGV2aWNlLmlkIG11c3QgYmUgYSBzdGFibGUgZmluZ2VycHJpbnQgZm9yIHRoZSBwdWJsaWMga2V5LlxuICAvLyBUaGUgZ2F0ZXdheSBlbmZvcmNlcyBkZXZpY2VJZCBcdTIxOTQgcHVibGljS2V5IGJpbmRpbmc7IHJhbmRvbSBpZHMgY2FuIGNhdXNlIFwiZGV2aWNlIGlkZW50aXR5IG1pc21hdGNoXCIuXG4gIGNvbnN0IGRldmljZUlkID0gYXdhaXQgc2hhMjU2SGV4KHB1YlJhdyk7XG5cbiAgY29uc3QgaWRlbnRpdHk6IERldmljZUlkZW50aXR5ID0ge1xuICAgIGlkOiBkZXZpY2VJZCxcbiAgICBwdWJsaWNLZXk6IGJhc2U2NFVybEVuY29kZShwdWJSYXcpLFxuICAgIHByaXZhdGVLZXlKd2s6IHByaXZKd2ssXG4gIH07XG5cbiAgaWYgKHN0b3JlKSB7XG4gICAgYXdhaXQgc3RvcmUuc2V0KGlkZW50aXR5KTtcbiAgfSBlbHNlIHtcbiAgICAvLyBGYWxsYmFjayAoc2hvdWxkIG5vdCBoYXBwZW4gaW4gcmVhbCBwbHVnaW4gcnVudGltZSkgXHUyMDE0IGtlZXAgbGVnYWN5IGJlaGF2aW9yLlxuICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKERFVklDRV9TVE9SQUdFX0tFWSwgSlNPTi5zdHJpbmdpZnkoaWRlbnRpdHkpKTtcbiAgfVxuXG4gIHJldHVybiBpZGVudGl0eTtcbn1cblxuZnVuY3Rpb24gYnVpbGREZXZpY2VBdXRoUGF5bG9hZChwYXJhbXM6IHtcbiAgZGV2aWNlSWQ6IHN0cmluZztcbiAgY2xpZW50SWQ6IHN0cmluZztcbiAgY2xpZW50TW9kZTogc3RyaW5nO1xuICByb2xlOiBzdHJpbmc7XG4gIHNjb3Blczogc3RyaW5nW107XG4gIHNpZ25lZEF0TXM6IG51bWJlcjtcbiAgdG9rZW46IHN0cmluZztcbiAgbm9uY2U/OiBzdHJpbmc7XG59KTogc3RyaW5nIHtcbiAgY29uc3QgdmVyc2lvbiA9IHBhcmFtcy5ub25jZSA/ICd2MicgOiAndjEnO1xuICBjb25zdCBzY29wZXMgPSBwYXJhbXMuc2NvcGVzLmpvaW4oJywnKTtcbiAgY29uc3QgYmFzZSA9IFtcbiAgICB2ZXJzaW9uLFxuICAgIHBhcmFtcy5kZXZpY2VJZCxcbiAgICBwYXJhbXMuY2xpZW50SWQsXG4gICAgcGFyYW1zLmNsaWVudE1vZGUsXG4gICAgcGFyYW1zLnJvbGUsXG4gICAgc2NvcGVzLFxuICAgIFN0cmluZyhwYXJhbXMuc2lnbmVkQXRNcyksXG4gICAgcGFyYW1zLnRva2VuIHx8ICcnLFxuICBdO1xuICBpZiAodmVyc2lvbiA9PT0gJ3YyJykgYmFzZS5wdXNoKHBhcmFtcy5ub25jZSB8fCAnJyk7XG4gIHJldHVybiBiYXNlLmpvaW4oJ3wnKTtcbn1cblxuYXN5bmMgZnVuY3Rpb24gc2lnbkRldmljZVBheWxvYWQoaWRlbnRpdHk6IERldmljZUlkZW50aXR5LCBwYXlsb2FkOiBzdHJpbmcpOiBQcm9taXNlPHsgc2lnbmF0dXJlOiBzdHJpbmcgfT4ge1xuICBjb25zdCBwcml2YXRlS2V5ID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5pbXBvcnRLZXkoXG4gICAgJ2p3aycsXG4gICAgaWRlbnRpdHkucHJpdmF0ZUtleUp3ayxcbiAgICB7IG5hbWU6ICdFZDI1NTE5JyB9LFxuICAgIGZhbHNlLFxuICAgIFsnc2lnbiddLFxuICApO1xuXG4gIGNvbnN0IHNpZyA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuc2lnbih7IG5hbWU6ICdFZDI1NTE5JyB9LCBwcml2YXRlS2V5LCB1dGY4Qnl0ZXMocGF5bG9hZCkgYXMgdW5rbm93biBhcyBCdWZmZXJTb3VyY2UpO1xuICByZXR1cm4geyBzaWduYXR1cmU6IGJhc2U2NFVybEVuY29kZShzaWcpIH07XG59XG5cbmZ1bmN0aW9uIGV4dHJhY3RUZXh0RnJvbUdhdGV3YXlNZXNzYWdlKG1zZzogYW55KTogc3RyaW5nIHtcbiAgaWYgKCFtc2cpIHJldHVybiAnJztcblxuICAvLyBNb3N0IGNvbW1vbjogeyByb2xlLCBjb250ZW50IH0gd2hlcmUgY29udGVudCBjYW4gYmUgc3RyaW5nIG9yIFt7dHlwZTondGV4dCcsdGV4dDonLi4uJ31dXG4gIGNvbnN0IGNvbnRlbnQgPSBtc2cuY29udGVudCA/PyBtc2cubWVzc2FnZSA/PyBtc2c7XG4gIGlmICh0eXBlb2YgY29udGVudCA9PT0gJ3N0cmluZycpIHJldHVybiBjb250ZW50O1xuXG4gIGlmIChBcnJheS5pc0FycmF5KGNvbnRlbnQpKSB7XG4gICAgY29uc3QgcGFydHMgPSBjb250ZW50XG4gICAgICAuZmlsdGVyKChjKSA9PiBjICYmIHR5cGVvZiBjID09PSAnb2JqZWN0JyAmJiBjLnR5cGUgPT09ICd0ZXh0JyAmJiB0eXBlb2YgYy50ZXh0ID09PSAnc3RyaW5nJylcbiAgICAgIC5tYXAoKGMpID0+IGMudGV4dCk7XG4gICAgcmV0dXJuIHBhcnRzLmpvaW4oJ1xcbicpO1xuICB9XG5cbiAgLy8gRmFsbGJhY2tcbiAgdHJ5IHtcbiAgICByZXR1cm4gSlNPTi5zdHJpbmdpZnkoY29udGVudCk7XG4gIH0gY2F0Y2gge1xuICAgIHJldHVybiBTdHJpbmcoY29udGVudCk7XG4gIH1cbn1cblxuZnVuY3Rpb24gc2Vzc2lvbktleU1hdGNoZXMoY29uZmlndXJlZDogc3RyaW5nLCBpbmNvbWluZzogc3RyaW5nKTogYm9vbGVhbiB7XG4gIGlmIChpbmNvbWluZyA9PT0gY29uZmlndXJlZCkgcmV0dXJuIHRydWU7XG4gIC8vIE9wZW5DbGF3IHJlc29sdmVzIFwibWFpblwiIHRvIGNhbm9uaWNhbCBzZXNzaW9uIGtleSBsaWtlIFwiYWdlbnQ6bWFpbjptYWluXCIuXG4gIGlmIChjb25maWd1cmVkID09PSAnbWFpbicgJiYgaW5jb21pbmcgPT09ICdhZ2VudDptYWluOm1haW4nKSByZXR1cm4gdHJ1ZTtcbiAgcmV0dXJuIGZhbHNlO1xufVxuXG5leHBvcnQgY2xhc3MgT2JzaWRpYW5XU0NsaWVudCB7XG4gIHByaXZhdGUgd3M6IFdlYlNvY2tldCB8IG51bGwgPSBudWxsO1xuICBwcml2YXRlIHJlY29ubmVjdFRpbWVyOiBSZXR1cm5UeXBlPHR5cGVvZiBzZXRUaW1lb3V0PiB8IG51bGwgPSBudWxsO1xuICBwcml2YXRlIGhlYXJ0YmVhdFRpbWVyOiBSZXR1cm5UeXBlPHR5cGVvZiBzZXRJbnRlcnZhbD4gfCBudWxsID0gbnVsbDtcbiAgcHJpdmF0ZSB3b3JraW5nVGltZXI6IFJldHVyblR5cGU8dHlwZW9mIHNldFRpbWVvdXQ+IHwgbnVsbCA9IG51bGw7XG4gIHByaXZhdGUgaW50ZW50aW9uYWxDbG9zZSA9IGZhbHNlO1xuICBwcml2YXRlIHNlc3Npb25LZXk6IHN0cmluZztcbiAgcHJpdmF0ZSB1cmwgPSAnJztcbiAgcHJpdmF0ZSB0b2tlbiA9ICcnO1xuICBwcml2YXRlIHJlcXVlc3RJZCA9IDA7XG4gIHByaXZhdGUgcGVuZGluZ1JlcXVlc3RzID0gbmV3IE1hcDxzdHJpbmcsIFBlbmRpbmdSZXF1ZXN0PigpO1xuICBwcml2YXRlIHdvcmtpbmcgPSBmYWxzZTtcblxuICAvKiogVGhlIGxhc3QgaW4tZmxpZ2h0IGNoYXQgcnVuIGlkLiBJbiBPcGVuQ2xhdyBXZWJDaGF0IHRoaXMgbWFwcyB0byBjaGF0LnNlbmQgaWRlbXBvdGVuY3lLZXkuICovXG4gIHByaXZhdGUgYWN0aXZlUnVuSWQ6IHN0cmluZyB8IG51bGwgPSBudWxsO1xuXG4gIC8qKiBQcmV2ZW50cyBhYm9ydCBzcGFtbWluZzogd2hpbGUgYW4gYWJvcnQgcmVxdWVzdCBpcyBpbi1mbGlnaHQsIHJldXNlIHRoZSBzYW1lIHByb21pc2UuICovXG4gIHByaXZhdGUgYWJvcnRJbkZsaWdodDogUHJvbWlzZTxib29sZWFuPiB8IG51bGwgPSBudWxsO1xuXG4gIHN0YXRlOiBXU0NsaWVudFN0YXRlID0gJ2Rpc2Nvbm5lY3RlZCc7XG5cbiAgb25NZXNzYWdlOiAoKG1zZzogSW5ib3VuZFdTUGF5bG9hZCkgPT4gdm9pZCkgfCBudWxsID0gbnVsbDtcbiAgb25TdGF0ZUNoYW5nZTogKChzdGF0ZTogV1NDbGllbnRTdGF0ZSkgPT4gdm9pZCkgfCBudWxsID0gbnVsbDtcbiAgb25Xb3JraW5nQ2hhbmdlOiBXb3JraW5nU3RhdGVMaXN0ZW5lciB8IG51bGwgPSBudWxsO1xuXG4gIHByaXZhdGUgaWRlbnRpdHlTdG9yZTogRGV2aWNlSWRlbnRpdHlTdG9yZSB8IHVuZGVmaW5lZDtcbiAgcHJpdmF0ZSBhbGxvd0luc2VjdXJlV3MgPSBmYWxzZTtcblxuICBwcml2YXRlIHJlY29ubmVjdEF0dGVtcHQgPSAwO1xuXG4gIGNvbnN0cnVjdG9yKHNlc3Npb25LZXk6IHN0cmluZywgb3B0cz86IHsgaWRlbnRpdHlTdG9yZT86IERldmljZUlkZW50aXR5U3RvcmU7IGFsbG93SW5zZWN1cmVXcz86IGJvb2xlYW4gfSkge1xuICAgIHRoaXMuc2Vzc2lvbktleSA9IHNlc3Npb25LZXk7XG4gICAgdGhpcy5pZGVudGl0eVN0b3JlID0gb3B0cz8uaWRlbnRpdHlTdG9yZTtcbiAgICB0aGlzLmFsbG93SW5zZWN1cmVXcyA9IEJvb2xlYW4ob3B0cz8uYWxsb3dJbnNlY3VyZVdzKTtcbiAgfVxuXG4gIGNvbm5lY3QodXJsOiBzdHJpbmcsIHRva2VuOiBzdHJpbmcsIG9wdHM/OiB7IGFsbG93SW5zZWN1cmVXcz86IGJvb2xlYW4gfSk6IHZvaWQge1xuICAgIHRoaXMudXJsID0gdXJsO1xuICAgIHRoaXMudG9rZW4gPSB0b2tlbjtcbiAgICB0aGlzLmFsbG93SW5zZWN1cmVXcyA9IEJvb2xlYW4ob3B0cz8uYWxsb3dJbnNlY3VyZVdzID8/IHRoaXMuYWxsb3dJbnNlY3VyZVdzKTtcbiAgICB0aGlzLmludGVudGlvbmFsQ2xvc2UgPSBmYWxzZTtcblxuICAgIC8vIFNlY3VyaXR5OiBibG9jayBub24tbG9jYWwgd3M6Ly8gdW5sZXNzIGV4cGxpY2l0bHkgYWxsb3dlZC5cbiAgICBjb25zdCBwYXJzZWQgPSBzYWZlUGFyc2VXc1VybCh1cmwpO1xuICAgIGlmICghcGFyc2VkLm9rKSB7XG4gICAgICB0aGlzLm9uTWVzc2FnZT8uKHsgdHlwZTogJ2Vycm9yJywgcGF5bG9hZDogeyBtZXNzYWdlOiBwYXJzZWQuZXJyb3IgfSB9KTtcbiAgICAgIHJldHVybjtcbiAgICB9XG4gICAgaWYgKHBhcnNlZC5zY2hlbWUgPT09ICd3cycgJiYgIWlzTG9jYWxIb3N0KHBhcnNlZC5ob3N0KSAmJiAhdGhpcy5hbGxvd0luc2VjdXJlV3MpIHtcbiAgICAgIHRoaXMub25NZXNzYWdlPy4oe1xuICAgICAgICB0eXBlOiAnZXJyb3InLFxuICAgICAgICBwYXlsb2FkOiB7IG1lc3NhZ2U6ICdSZWZ1c2luZyBpbnNlY3VyZSB3czovLyB0byBub24tbG9jYWwgZ2F0ZXdheS4gVXNlIHdzczovLyBvciBlbmFibGUgdGhlIHVuc2FmZSBvdmVycmlkZSBpbiBzZXR0aW5ncy4nIH0sXG4gICAgICB9KTtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICB0aGlzLl9jb25uZWN0KCk7XG4gIH1cblxuICBkaXNjb25uZWN0KCk6IHZvaWQge1xuICAgIHRoaXMuaW50ZW50aW9uYWxDbG9zZSA9IHRydWU7XG4gICAgdGhpcy5fc3RvcFRpbWVycygpO1xuICAgIHRoaXMuYWN0aXZlUnVuSWQgPSBudWxsO1xuICAgIHRoaXMuYWJvcnRJbkZsaWdodCA9IG51bGw7XG4gICAgdGhpcy5fc2V0V29ya2luZyhmYWxzZSk7XG4gICAgaWYgKHRoaXMud3MpIHtcbiAgICAgIHRoaXMud3MuY2xvc2UoKTtcbiAgICAgIHRoaXMud3MgPSBudWxsO1xuICAgIH1cbiAgICB0aGlzLl9zZXRTdGF0ZSgnZGlzY29ubmVjdGVkJyk7XG4gIH1cblxuICBhc3luYyBzZW5kTWVzc2FnZShtZXNzYWdlOiBzdHJpbmcpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBpZiAodGhpcy5zdGF0ZSAhPT0gJ2Nvbm5lY3RlZCcpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcignTm90IGNvbm5lY3RlZCBcdTIwMTQgY2FsbCBjb25uZWN0KCkgZmlyc3QnKTtcbiAgICB9XG5cbiAgICBjb25zdCBydW5JZCA9IGBvYnNpZGlhbi0ke0RhdGUubm93KCl9LSR7TWF0aC5yYW5kb20oKS50b1N0cmluZygzNikuc2xpY2UoMiwgOSl9YDtcblxuICAgIC8vIFNob3cgXHUyMDFDd29ya2luZ1x1MjAxRCBPTkxZIGFmdGVyIHRoZSBnYXRld2F5IGFja25vd2xlZGdlcyB0aGUgcmVxdWVzdC5cbiAgICBjb25zdCBhY2sgPSBhd2FpdCB0aGlzLl9zZW5kUmVxdWVzdCgnY2hhdC5zZW5kJywge1xuICAgICAgc2Vzc2lvbktleTogdGhpcy5zZXNzaW9uS2V5LFxuICAgICAgbWVzc2FnZSxcbiAgICAgIGlkZW1wb3RlbmN5S2V5OiBydW5JZCxcbiAgICAgIC8vIGRlbGl2ZXIgZGVmYXVsdHMgdG8gdHJ1ZSBpbiBnYXRld2F5OyBrZWVwIGRlZmF1bHRcbiAgICB9KTtcblxuICAgIC8vIElmIHRoZSBnYXRld2F5IHJldHVybnMgYSBjYW5vbmljYWwgcnVuIGlkZW50aWZpZXIsIHByZWZlciBpdC5cbiAgICBjb25zdCBjYW5vbmljYWxSdW5JZCA9IFN0cmluZyhhY2s/LnJ1bklkIHx8IGFjaz8uaWRlbXBvdGVuY3lLZXkgfHwgJycpO1xuICAgIHRoaXMuYWN0aXZlUnVuSWQgPSBjYW5vbmljYWxSdW5JZCB8fCBydW5JZDtcbiAgICB0aGlzLl9zZXRXb3JraW5nKHRydWUpO1xuICAgIHRoaXMuX2FybVdvcmtpbmdTYWZldHlUaW1lb3V0KCk7XG4gIH1cblxuICAvKiogQWJvcnQgdGhlIGFjdGl2ZSBydW4gZm9yIHRoaXMgc2Vzc2lvbiAoYW5kIG91ciBsYXN0IHJ1biBpZCBpZiBwcmVzZW50KS4gKi9cbiAgYXN5bmMgYWJvcnRBY3RpdmVSdW4oKTogUHJvbWlzZTxib29sZWFuPiB7XG4gICAgaWYgKHRoaXMuc3RhdGUgIT09ICdjb25uZWN0ZWQnKSB7XG4gICAgICByZXR1cm4gZmFsc2U7XG4gICAgfVxuXG4gICAgLy8gUHJldmVudCByZXF1ZXN0IHN0b3Jtczogd2hpbGUgb25lIGFib3J0IGlzIGluIGZsaWdodCwgcmV1c2UgaXQuXG4gICAgaWYgKHRoaXMuYWJvcnRJbkZsaWdodCkge1xuICAgICAgcmV0dXJuIHRoaXMuYWJvcnRJbkZsaWdodDtcbiAgICB9XG5cbiAgICBjb25zdCBydW5JZCA9IHRoaXMuYWN0aXZlUnVuSWQ7XG4gICAgaWYgKCFydW5JZCkge1xuICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH1cblxuICAgIHRoaXMuYWJvcnRJbkZsaWdodCA9IChhc3luYyAoKSA9PiB7XG4gICAgICB0cnkge1xuICAgICAgICBhd2FpdCB0aGlzLl9zZW5kUmVxdWVzdCgnY2hhdC5hYm9ydCcsIHsgc2Vzc2lvbktleTogdGhpcy5zZXNzaW9uS2V5LCBydW5JZCB9KTtcbiAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICB9IGNhdGNoIChlcnIpIHtcbiAgICAgICAgY29uc29sZS5lcnJvcignW29jbGF3LXdzXSBjaGF0LmFib3J0IGZhaWxlZCcsIGVycik7XG4gICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgIH0gZmluYWxseSB7XG4gICAgICAgIC8vIEFsd2F5cyByZXN0b3JlIFVJIHN0YXRlIGltbWVkaWF0ZWx5OyB0aGUgZ2F0ZXdheSBtYXkgc3RpbGwgZW1pdCBhbiBhYm9ydGVkIGV2ZW50IGxhdGVyLlxuICAgICAgICB0aGlzLmFjdGl2ZVJ1bklkID0gbnVsbDtcbiAgICAgICAgdGhpcy5fc2V0V29ya2luZyhmYWxzZSk7XG4gICAgICAgIHRoaXMuYWJvcnRJbkZsaWdodCA9IG51bGw7XG4gICAgICB9XG4gICAgfSkoKTtcblxuICAgIHJldHVybiB0aGlzLmFib3J0SW5GbGlnaHQ7XG4gIH1cblxuICBwcml2YXRlIF9jb25uZWN0KCk6IHZvaWQge1xuICAgIGlmICh0aGlzLndzKSB7XG4gICAgICB0aGlzLndzLm9ub3BlbiA9IG51bGw7XG4gICAgICB0aGlzLndzLm9uY2xvc2UgPSBudWxsO1xuICAgICAgdGhpcy53cy5vbm1lc3NhZ2UgPSBudWxsO1xuICAgICAgdGhpcy53cy5vbmVycm9yID0gbnVsbDtcbiAgICAgIHRoaXMud3MuY2xvc2UoKTtcbiAgICAgIHRoaXMud3MgPSBudWxsO1xuICAgIH1cblxuICAgIHRoaXMuX3NldFN0YXRlKCdjb25uZWN0aW5nJyk7XG5cbiAgICBjb25zdCB3cyA9IG5ldyBXZWJTb2NrZXQodGhpcy51cmwpO1xuICAgIHRoaXMud3MgPSB3cztcblxuICAgIGxldCBjb25uZWN0Tm9uY2U6IHN0cmluZyB8IG51bGwgPSBudWxsO1xuICAgIGxldCBjb25uZWN0U3RhcnRlZCA9IGZhbHNlO1xuXG4gICAgY29uc3QgdHJ5Q29ubmVjdCA9IGFzeW5jICgpID0+IHtcbiAgICAgIGlmIChjb25uZWN0U3RhcnRlZCkgcmV0dXJuO1xuICAgICAgaWYgKCFjb25uZWN0Tm9uY2UpIHJldHVybjtcbiAgICAgIGNvbm5lY3RTdGFydGVkID0gdHJ1ZTtcblxuICAgICAgdHJ5IHtcbiAgICAgICAgY29uc3QgaWRlbnRpdHkgPSBhd2FpdCBsb2FkT3JDcmVhdGVEZXZpY2VJZGVudGl0eSh0aGlzLmlkZW50aXR5U3RvcmUpO1xuICAgICAgICBjb25zdCBzaWduZWRBdE1zID0gRGF0ZS5ub3coKTtcbiAgICAgICAgY29uc3QgcGF5bG9hZCA9IGJ1aWxkRGV2aWNlQXV0aFBheWxvYWQoe1xuICAgICAgICAgIGRldmljZUlkOiBpZGVudGl0eS5pZCxcbiAgICAgICAgICBjbGllbnRJZDogJ2dhdGV3YXktY2xpZW50JyxcbiAgICAgICAgICBjbGllbnRNb2RlOiAnYmFja2VuZCcsXG4gICAgICAgICAgcm9sZTogJ29wZXJhdG9yJyxcbiAgICAgICAgICBzY29wZXM6IFsnb3BlcmF0b3IucmVhZCcsICdvcGVyYXRvci53cml0ZSddLFxuICAgICAgICAgIHNpZ25lZEF0TXMsXG4gICAgICAgICAgdG9rZW46IHRoaXMudG9rZW4sXG4gICAgICAgICAgbm9uY2U6IGNvbm5lY3ROb25jZSxcbiAgICAgICAgfSk7XG4gICAgICAgIGNvbnN0IHNpZyA9IGF3YWl0IHNpZ25EZXZpY2VQYXlsb2FkKGlkZW50aXR5LCBwYXlsb2FkKTtcblxuICAgICAgICBjb25zdCBhY2sgPSBhd2FpdCB0aGlzLl9zZW5kUmVxdWVzdCgnY29ubmVjdCcsIHtcbiAgICAgICAgICAgbWluUHJvdG9jb2w6IDMsXG4gICAgICAgICAgIG1heFByb3RvY29sOiAzLFxuICAgICAgICAgICBjbGllbnQ6IHtcbiAgICAgICAgICAgICBpZDogJ2dhdGV3YXktY2xpZW50JyxcbiAgICAgICAgICAgICBtb2RlOiAnYmFja2VuZCcsXG4gICAgICAgICAgICAgdmVyc2lvbjogJzAuMS4xMCcsXG4gICAgICAgICAgICAgcGxhdGZvcm06ICdlbGVjdHJvbicsXG4gICAgICAgICAgIH0sXG4gICAgICAgICAgIHJvbGU6ICdvcGVyYXRvcicsXG4gICAgICAgICAgIHNjb3BlczogWydvcGVyYXRvci5yZWFkJywgJ29wZXJhdG9yLndyaXRlJ10sXG4gICAgICAgICAgIGRldmljZToge1xuICAgICAgICAgICAgIGlkOiBpZGVudGl0eS5pZCxcbiAgICAgICAgICAgICBwdWJsaWNLZXk6IGlkZW50aXR5LnB1YmxpY0tleSxcbiAgICAgICAgICAgICBzaWduYXR1cmU6IHNpZy5zaWduYXR1cmUsXG4gICAgICAgICAgICAgc2lnbmVkQXQ6IHNpZ25lZEF0TXMsXG4gICAgICAgICAgICAgbm9uY2U6IGNvbm5lY3ROb25jZSxcbiAgICAgICAgICAgfSxcbiAgICAgICAgICAgYXV0aDoge1xuICAgICAgICAgICAgIHRva2VuOiB0aGlzLnRva2VuLFxuICAgICAgICAgICB9LFxuICAgICAgICAgfSk7XG5cbiAgICAgICAgIHRoaXMuX3NldFN0YXRlKCdjb25uZWN0ZWQnKTtcbiAgICAgICAgIHRoaXMucmVjb25uZWN0QXR0ZW1wdCA9IDA7XG4gICAgICAgICBpZiAoaGFuZHNoYWtlVGltZXIpIHtcbiAgICAgICAgICAgY2xlYXJUaW1lb3V0KGhhbmRzaGFrZVRpbWVyKTtcbiAgICAgICAgICAgaGFuZHNoYWtlVGltZXIgPSBudWxsO1xuICAgICAgICAgfVxuICAgICAgICAgdGhpcy5fc3RhcnRIZWFydGJlYXQoKTtcbiAgICAgIH0gY2F0Y2ggKGVycikge1xuICAgICAgICBjb25zb2xlLmVycm9yKCdbb2NsYXctd3NdIENvbm5lY3QgaGFuZHNoYWtlIGZhaWxlZCcsIGVycik7XG4gICAgICAgIHdzLmNsb3NlKCk7XG4gICAgICB9XG4gICAgfTtcblxuICAgIGxldCBoYW5kc2hha2VUaW1lcjogUmV0dXJuVHlwZTx0eXBlb2Ygc2V0VGltZW91dD4gfCBudWxsID0gbnVsbDtcblxuICAgIHdzLm9ub3BlbiA9ICgpID0+IHtcbiAgICAgIHRoaXMuX3NldFN0YXRlKCdoYW5kc2hha2luZycpO1xuICAgICAgLy8gVGhlIGdhdGV3YXkgd2lsbCBzZW5kIGNvbm5lY3QuY2hhbGxlbmdlOyBjb25uZWN0IGlzIHNlbnQgb25jZSB3ZSBoYXZlIGEgbm9uY2UuXG4gICAgICBpZiAoaGFuZHNoYWtlVGltZXIpIGNsZWFyVGltZW91dChoYW5kc2hha2VUaW1lcik7XG4gICAgICBoYW5kc2hha2VUaW1lciA9IHNldFRpbWVvdXQoKCkgPT4ge1xuICAgICAgICAvLyBJZiB3ZSBuZXZlciBnb3QgdGhlIGNoYWxsZW5nZSBub25jZSwgZm9yY2UgcmVjb25uZWN0LlxuICAgICAgICBpZiAodGhpcy5zdGF0ZSA9PT0gJ2hhbmRzaGFraW5nJyAmJiAhdGhpcy5pbnRlbnRpb25hbENsb3NlKSB7XG4gICAgICAgICAgY29uc29sZS53YXJuKCdbb2NsYXctd3NdIEhhbmRzaGFrZSB0aW1lZCBvdXQgd2FpdGluZyBmb3IgY29ubmVjdC5jaGFsbGVuZ2UnKTtcbiAgICAgICAgICB3cy5jbG9zZSgpO1xuICAgICAgICB9XG4gICAgICB9LCBIQU5EU0hBS0VfVElNRU9VVF9NUyk7XG4gICAgfTtcblxuICAgIHdzLm9ubWVzc2FnZSA9IChldmVudDogTWVzc2FnZUV2ZW50KSA9PiB7XG4gICAgICAvLyBXZWJTb2NrZXQgb25tZXNzYWdlIGNhbm5vdCBiZSBhc3luYywgYnV0IHdlIGNhbiBydW4gYW4gYXN5bmMgdGFzayBpbnNpZGUuXG4gICAgICB2b2lkIChhc3luYyAoKSA9PiB7XG4gICAgICAgIGNvbnN0IG5vcm1hbGl6ZWQgPSBhd2FpdCBub3JtYWxpemVXc0RhdGFUb1RleHQoZXZlbnQuZGF0YSk7XG4gICAgICAgIGlmICghbm9ybWFsaXplZC5vaykge1xuICAgICAgICAgIGlmIChub3JtYWxpemVkLnJlYXNvbiA9PT0gJ3Rvby1sYXJnZScpIHtcbiAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IoJ1tvY2xhdy13c10gSW5ib3VuZCBmcmFtZSB0b28gbGFyZ2U7IGNsb3NpbmcgY29ubmVjdGlvbicpO1xuICAgICAgICAgICAgd3MuY2xvc2UoKTtcbiAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgY29uc29sZS5lcnJvcignW29jbGF3LXdzXSBVbnN1cHBvcnRlZCBpbmJvdW5kIGZyYW1lIHR5cGU7IGlnbm9yaW5nJyk7XG4gICAgICAgICAgfVxuICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmIChub3JtYWxpemVkLmJ5dGVzID4gTUFYX0lOQk9VTkRfRlJBTUVfQllURVMpIHtcbiAgICAgICAgICBjb25zb2xlLmVycm9yKCdbb2NsYXctd3NdIEluYm91bmQgZnJhbWUgdG9vIGxhcmdlOyBjbG9zaW5nIGNvbm5lY3Rpb24nKTtcbiAgICAgICAgICB3cy5jbG9zZSgpO1xuICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIGxldCBmcmFtZTogYW55O1xuICAgICAgICB0cnkge1xuICAgICAgICAgIGZyYW1lID0gSlNPTi5wYXJzZShub3JtYWxpemVkLnRleHQpO1xuICAgICAgICB9IGNhdGNoIHtcbiAgICAgICAgICBjb25zb2xlLmVycm9yKCdbb2NsYXctd3NdIEZhaWxlZCB0byBwYXJzZSBpbmNvbWluZyBtZXNzYWdlJyk7XG4gICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgLy8gUmVzcG9uc2VzXG4gICAgICAgIGlmIChmcmFtZS50eXBlID09PSAncmVzJykge1xuICAgICAgICAgIHRoaXMuX2hhbmRsZVJlc3BvbnNlRnJhbWUoZnJhbWUpO1xuICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIC8vIEV2ZW50c1xuICAgICAgICBpZiAoZnJhbWUudHlwZSA9PT0gJ2V2ZW50Jykge1xuICAgICAgICAgIGlmIChmcmFtZS5ldmVudCA9PT0gJ2Nvbm5lY3QuY2hhbGxlbmdlJykge1xuICAgICAgICAgICAgY29ubmVjdE5vbmNlID0gZnJhbWUucGF5bG9hZD8ubm9uY2UgfHwgbnVsbDtcbiAgICAgICAgICAgIC8vIEF0dGVtcHQgaGFuZHNoYWtlIG9uY2Ugd2UgaGF2ZSBhIG5vbmNlLlxuICAgICAgICAgICAgdm9pZCB0cnlDb25uZWN0KCk7XG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgaWYgKGZyYW1lLmV2ZW50ID09PSAnY2hhdCcpIHtcbiAgICAgICAgICAgIHRoaXMuX2hhbmRsZUNoYXRFdmVudEZyYW1lKGZyYW1lKTtcbiAgICAgICAgICB9XG4gICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgLy8gQXZvaWQgbG9nZ2luZyBmdWxsIGZyYW1lcyAobWF5IGluY2x1ZGUgbWVzc2FnZSBjb250ZW50IG9yIG90aGVyIHNlbnNpdGl2ZSBwYXlsb2FkcykuXG4gICAgICAgIGNvbnNvbGUuZGVidWcoJ1tvY2xhdy13c10gVW5oYW5kbGVkIGZyYW1lJywgeyB0eXBlOiBmcmFtZT8udHlwZSwgZXZlbnQ6IGZyYW1lPy5ldmVudCwgaWQ6IGZyYW1lPy5pZCB9KTtcbiAgICAgIH0pKCk7XG4gICAgfTtcblxuICAgIGNvbnN0IGNsZWFySGFuZHNoYWtlVGltZXIgPSAoKSA9PiB7XG4gICAgICBpZiAoaGFuZHNoYWtlVGltZXIpIHtcbiAgICAgICAgY2xlYXJUaW1lb3V0KGhhbmRzaGFrZVRpbWVyKTtcbiAgICAgICAgaGFuZHNoYWtlVGltZXIgPSBudWxsO1xuICAgICAgfVxuICAgIH07XG5cbiAgICB3cy5vbmNsb3NlID0gKCkgPT4ge1xuICAgICAgY2xlYXJIYW5kc2hha2VUaW1lcigpO1xuICAgICAgdGhpcy5fc3RvcFRpbWVycygpO1xuICAgICAgdGhpcy5hY3RpdmVSdW5JZCA9IG51bGw7XG4gICAgICB0aGlzLmFib3J0SW5GbGlnaHQgPSBudWxsO1xuICAgICAgdGhpcy5fc2V0V29ya2luZyhmYWxzZSk7XG4gICAgICB0aGlzLl9zZXRTdGF0ZSgnZGlzY29ubmVjdGVkJyk7XG5cbiAgICAgIGZvciAoY29uc3QgcGVuZGluZyBvZiB0aGlzLnBlbmRpbmdSZXF1ZXN0cy52YWx1ZXMoKSkge1xuICAgICAgICBpZiAocGVuZGluZy50aW1lb3V0KSBjbGVhclRpbWVvdXQocGVuZGluZy50aW1lb3V0KTtcbiAgICAgICAgcGVuZGluZy5yZWplY3QobmV3IEVycm9yKCdDb25uZWN0aW9uIGNsb3NlZCcpKTtcbiAgICAgIH1cbiAgICAgIHRoaXMucGVuZGluZ1JlcXVlc3RzLmNsZWFyKCk7XG5cbiAgICAgIGlmICghdGhpcy5pbnRlbnRpb25hbENsb3NlKSB7XG4gICAgICAgIHRoaXMuX3NjaGVkdWxlUmVjb25uZWN0KCk7XG4gICAgICB9XG4gICAgfTtcblxuICAgIHdzLm9uZXJyb3IgPSAoZXY6IEV2ZW50KSA9PiB7XG4gICAgICBjbGVhckhhbmRzaGFrZVRpbWVyKCk7XG4gICAgICBjb25zb2xlLmVycm9yKCdbb2NsYXctd3NdIFdlYlNvY2tldCBlcnJvcicsIGV2KTtcbiAgICB9O1xuICB9XG5cbiAgcHJpdmF0ZSBfaGFuZGxlUmVzcG9uc2VGcmFtZShmcmFtZTogYW55KTogdm9pZCB7XG4gICAgY29uc3QgcGVuZGluZyA9IHRoaXMucGVuZGluZ1JlcXVlc3RzLmdldChmcmFtZS5pZCk7XG4gICAgaWYgKCFwZW5kaW5nKSByZXR1cm47XG5cbiAgICB0aGlzLnBlbmRpbmdSZXF1ZXN0cy5kZWxldGUoZnJhbWUuaWQpO1xuICAgIGlmIChwZW5kaW5nLnRpbWVvdXQpIGNsZWFyVGltZW91dChwZW5kaW5nLnRpbWVvdXQpO1xuXG4gICAgaWYgKGZyYW1lLm9rKSBwZW5kaW5nLnJlc29sdmUoZnJhbWUucGF5bG9hZCk7XG4gICAgZWxzZSBwZW5kaW5nLnJlamVjdChuZXcgRXJyb3IoZnJhbWUuZXJyb3I/Lm1lc3NhZ2UgfHwgJ1JlcXVlc3QgZmFpbGVkJykpO1xuICB9XG5cbiAgcHJpdmF0ZSBfaGFuZGxlQ2hhdEV2ZW50RnJhbWUoZnJhbWU6IGFueSk6IHZvaWQge1xuICAgIGNvbnN0IHBheWxvYWQgPSBmcmFtZS5wYXlsb2FkO1xuICAgIGNvbnN0IGluY29taW5nU2Vzc2lvbktleSA9IFN0cmluZyhwYXlsb2FkPy5zZXNzaW9uS2V5IHx8ICcnKTtcbiAgICBpZiAoIWluY29taW5nU2Vzc2lvbktleSB8fCAhc2Vzc2lvbktleU1hdGNoZXModGhpcy5zZXNzaW9uS2V5LCBpbmNvbWluZ1Nlc3Npb25LZXkpKSB7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgLy8gQmVzdC1lZmZvcnQgcnVuIGNvcnJlbGF0aW9uIChpZiBnYXRld2F5IGluY2x1ZGVzIGEgcnVuIGlkKS4gVGhpcyBhdm9pZHMgY2xlYXJpbmcgb3VyIFVJXG4gICAgLy8gYmFzZWQgb24gYSBkaWZmZXJlbnQgY2xpZW50J3MgcnVuIGluIHRoZSBzYW1lIHNlc3Npb24uXG4gICAgY29uc3QgaW5jb21pbmdSdW5JZCA9IFN0cmluZyhwYXlsb2FkPy5ydW5JZCB8fCBwYXlsb2FkPy5pZGVtcG90ZW5jeUtleSB8fCBwYXlsb2FkPy5tZXRhPy5ydW5JZCB8fCAnJyk7XG4gICAgaWYgKHRoaXMuYWN0aXZlUnVuSWQgJiYgaW5jb21pbmdSdW5JZCAmJiBpbmNvbWluZ1J1bklkICE9PSB0aGlzLmFjdGl2ZVJ1bklkKSB7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgLy8gQXZvaWQgZG91YmxlLXJlbmRlcjogZ2F0ZXdheSBlbWl0cyBkZWx0YSArIGZpbmFsICsgYWJvcnRlZC4gUmVuZGVyIG9ubHkgZXhwbGljaXQgZmluYWwvYWJvcnRlZC5cbiAgICAvLyBJZiBzdGF0ZSBpcyBtaXNzaW5nLCB0cmVhdCBhcyBub24tdGVybWluYWwgKGRvIG5vdCBjbGVhciBVSSAvIGRvIG5vdCByZW5kZXIpLlxuICAgIGlmICghcGF5bG9hZD8uc3RhdGUpIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG4gICAgaWYgKHBheWxvYWQuc3RhdGUgIT09ICdmaW5hbCcgJiYgcGF5bG9hZC5zdGF0ZSAhPT0gJ2Fib3J0ZWQnKSB7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgLy8gV2Ugb25seSBhcHBlbmQgYXNzaXN0YW50IG91dHB1dCB0byBVSS5cbiAgICBjb25zdCBtc2cgPSBwYXlsb2FkPy5tZXNzYWdlO1xuICAgIGNvbnN0IHJvbGUgPSBtc2c/LnJvbGUgPz8gJ2Fzc2lzdGFudCc7XG5cbiAgICAvLyBBYm9ydGVkIGVuZHMgdGhlIHJ1biByZWdhcmRsZXNzIG9mIHJvbGUvbWVzc2FnZS5cbiAgICBpZiAocGF5bG9hZC5zdGF0ZSA9PT0gJ2Fib3J0ZWQnKSB7XG4gICAgICB0aGlzLmFjdGl2ZVJ1bklkID0gbnVsbDtcbiAgICAgIHRoaXMuX3NldFdvcmtpbmcoZmFsc2UpO1xuICAgICAgLy8gQWJvcnRlZCBtYXkgaGF2ZSBubyBhc3Npc3RhbnQgbWVzc2FnZTsgaWYgbm9uZSwgc3RvcCBoZXJlLlxuICAgICAgaWYgKCFtc2cpIHJldHVybjtcbiAgICAgIC8vIElmIHRoZXJlIGlzIGEgbWVzc2FnZSwgb25seSBhcHBlbmQgYXNzaXN0YW50IG91dHB1dC5cbiAgICAgIGlmIChyb2xlICE9PSAnYXNzaXN0YW50JykgcmV0dXJuO1xuICAgIH1cblxuICAgIC8vIEZpbmFsIHNob3VsZCBvbmx5IGNvbXBsZXRlIHRoZSBydW4gd2hlbiB0aGUgYXNzaXN0YW50IGNvbXBsZXRlcy5cbiAgICBpZiAocGF5bG9hZC5zdGF0ZSA9PT0gJ2ZpbmFsJykge1xuICAgICAgaWYgKHJvbGUgIT09ICdhc3Npc3RhbnQnKSByZXR1cm47XG4gICAgICB0aGlzLmFjdGl2ZVJ1bklkID0gbnVsbDtcbiAgICAgIHRoaXMuX3NldFdvcmtpbmcoZmFsc2UpO1xuICAgIH1cblxuICAgIGNvbnN0IHRleHQgPSBleHRyYWN0VGV4dEZyb21HYXRld2F5TWVzc2FnZShtc2cpO1xuICAgIGlmICghdGV4dCkgcmV0dXJuO1xuXG4gICAgLy8gT3B0aW9uYWw6IGhpZGUgaGVhcnRiZWF0IGFja3MgKG5vaXNlIGluIFVJKVxuICAgIGlmICh0ZXh0LnRyaW0oKSA9PT0gJ0hFQVJUQkVBVF9PSycpIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICB0aGlzLm9uTWVzc2FnZT8uKHtcbiAgICAgIHR5cGU6ICdtZXNzYWdlJyxcbiAgICAgIHBheWxvYWQ6IHtcbiAgICAgICAgY29udGVudDogdGV4dCxcbiAgICAgICAgcm9sZTogJ2Fzc2lzdGFudCcsXG4gICAgICAgIHRpbWVzdGFtcDogRGF0ZS5ub3coKSxcbiAgICAgIH0sXG4gICAgfSk7XG4gIH1cblxuICBwcml2YXRlIF9zZW5kUmVxdWVzdChtZXRob2Q6IHN0cmluZywgcGFyYW1zOiBhbnkpOiBQcm9taXNlPGFueT4ge1xuICAgIHJldHVybiBuZXcgUHJvbWlzZSgocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICBpZiAoIXRoaXMud3MgfHwgdGhpcy53cy5yZWFkeVN0YXRlICE9PSBXZWJTb2NrZXQuT1BFTikge1xuICAgICAgICByZWplY3QobmV3IEVycm9yKCdXZWJTb2NrZXQgbm90IGNvbm5lY3RlZCcpKTtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuXG4gICAgICBpZiAodGhpcy5wZW5kaW5nUmVxdWVzdHMuc2l6ZSA+PSBNQVhfUEVORElOR19SRVFVRVNUUykge1xuICAgICAgICByZWplY3QobmV3IEVycm9yKGBUb28gbWFueSBpbi1mbGlnaHQgcmVxdWVzdHMgKCR7dGhpcy5wZW5kaW5nUmVxdWVzdHMuc2l6ZX0pYCkpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG5cbiAgICAgIGNvbnN0IGlkID0gYHJlcS0keysrdGhpcy5yZXF1ZXN0SWR9YDtcblxuICAgICAgY29uc3QgcGVuZGluZzogUGVuZGluZ1JlcXVlc3QgPSB7IHJlc29sdmUsIHJlamVjdCwgdGltZW91dDogbnVsbCB9O1xuICAgICAgdGhpcy5wZW5kaW5nUmVxdWVzdHMuc2V0KGlkLCBwZW5kaW5nKTtcblxuICAgICAgY29uc3QgcGF5bG9hZCA9IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdHlwZTogJ3JlcScsXG4gICAgICAgIG1ldGhvZCxcbiAgICAgICAgaWQsXG4gICAgICAgIHBhcmFtcyxcbiAgICAgIH0pO1xuXG4gICAgICB0cnkge1xuICAgICAgICB0aGlzLndzLnNlbmQocGF5bG9hZCk7XG4gICAgICB9IGNhdGNoIChlcnIpIHtcbiAgICAgICAgdGhpcy5wZW5kaW5nUmVxdWVzdHMuZGVsZXRlKGlkKTtcbiAgICAgICAgcmVqZWN0KGVycik7XG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cblxuICAgICAgcGVuZGluZy50aW1lb3V0ID0gc2V0VGltZW91dCgoKSA9PiB7XG4gICAgICAgIGlmICh0aGlzLnBlbmRpbmdSZXF1ZXN0cy5oYXMoaWQpKSB7XG4gICAgICAgICAgdGhpcy5wZW5kaW5nUmVxdWVzdHMuZGVsZXRlKGlkKTtcbiAgICAgICAgICByZWplY3QobmV3IEVycm9yKGBSZXF1ZXN0IHRpbWVvdXQ6ICR7bWV0aG9kfWApKTtcbiAgICAgICAgfVxuICAgICAgfSwgMzBfMDAwKTtcbiAgICB9KTtcbiAgfVxuXG4gIHByaXZhdGUgX3NjaGVkdWxlUmVjb25uZWN0KCk6IHZvaWQge1xuICAgIGlmICh0aGlzLnJlY29ubmVjdFRpbWVyICE9PSBudWxsKSByZXR1cm47XG5cbiAgICBjb25zdCBhdHRlbXB0ID0gKyt0aGlzLnJlY29ubmVjdEF0dGVtcHQ7XG4gICAgY29uc3QgZXhwID0gTWF0aC5taW4oUkVDT05ORUNUX01BWF9NUywgUkVDT05ORUNUX0JBU0VfTVMgKiBNYXRoLnBvdygyLCBhdHRlbXB0IC0gMSkpO1xuICAgIC8vIEppdHRlcjogMC41eC4uMS41eFxuICAgIGNvbnN0IGppdHRlciA9IDAuNSArIE1hdGgucmFuZG9tKCk7XG4gICAgY29uc3QgZGVsYXkgPSBNYXRoLmZsb29yKGV4cCAqIGppdHRlcik7XG5cbiAgICB0aGlzLnJlY29ubmVjdFRpbWVyID0gc2V0VGltZW91dCgoKSA9PiB7XG4gICAgICB0aGlzLnJlY29ubmVjdFRpbWVyID0gbnVsbDtcbiAgICAgIGlmICghdGhpcy5pbnRlbnRpb25hbENsb3NlKSB7XG4gICAgICAgIGNvbnNvbGUubG9nKGBbb2NsYXctd3NdIFJlY29ubmVjdGluZyB0byAke3RoaXMudXJsfVx1MjAyNiAoYXR0ZW1wdCAke2F0dGVtcHR9LCAke2RlbGF5fW1zKWApO1xuICAgICAgICB0aGlzLl9jb25uZWN0KCk7XG4gICAgICB9XG4gICAgfSwgZGVsYXkpO1xuICB9XG5cbiAgcHJpdmF0ZSBsYXN0QnVmZmVyZWRXYXJuQXRNcyA9IDA7XG5cbiAgcHJpdmF0ZSBfc3RhcnRIZWFydGJlYXQoKTogdm9pZCB7XG4gICAgdGhpcy5fc3RvcEhlYXJ0YmVhdCgpO1xuICAgIHRoaXMuaGVhcnRiZWF0VGltZXIgPSBzZXRJbnRlcnZhbCgoKSA9PiB7XG4gICAgICBpZiAodGhpcy53cz8ucmVhZHlTdGF0ZSAhPT0gV2ViU29ja2V0Lk9QRU4pIHJldHVybjtcbiAgICAgIGlmICh0aGlzLndzLmJ1ZmZlcmVkQW1vdW50ID4gMCkge1xuICAgICAgICBjb25zdCBub3cgPSBEYXRlLm5vdygpO1xuICAgICAgICAvLyBUaHJvdHRsZSB0byBhdm9pZCBsb2cgc3BhbSBpbiBsb25nLXJ1bm5pbmcgc2Vzc2lvbnMuXG4gICAgICAgIGlmIChub3cgLSB0aGlzLmxhc3RCdWZmZXJlZFdhcm5BdE1zID4gNSAqIDYwXzAwMCkge1xuICAgICAgICAgIHRoaXMubGFzdEJ1ZmZlcmVkV2FybkF0TXMgPSBub3c7XG4gICAgICAgICAgY29uc29sZS53YXJuKCdbb2NsYXctd3NdIFNlbmQgYnVmZmVyIG5vdCBlbXB0eSBcdTIwMTQgY29ubmVjdGlvbiBtYXkgYmUgc3RhbGxlZCcpO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSwgSEVBUlRCRUFUX0lOVEVSVkFMX01TKTtcbiAgfVxuXG4gIHByaXZhdGUgX3N0b3BIZWFydGJlYXQoKTogdm9pZCB7XG4gICAgaWYgKHRoaXMuaGVhcnRiZWF0VGltZXIpIHtcbiAgICAgIGNsZWFySW50ZXJ2YWwodGhpcy5oZWFydGJlYXRUaW1lcik7XG4gICAgICB0aGlzLmhlYXJ0YmVhdFRpbWVyID0gbnVsbDtcbiAgICB9XG4gIH1cblxuICBwcml2YXRlIF9zdG9wVGltZXJzKCk6IHZvaWQge1xuICAgIHRoaXMuX3N0b3BIZWFydGJlYXQoKTtcbiAgICB0aGlzLl9kaXNhcm1Xb3JraW5nU2FmZXR5VGltZW91dCgpO1xuICAgIGlmICh0aGlzLnJlY29ubmVjdFRpbWVyKSB7XG4gICAgICBjbGVhclRpbWVvdXQodGhpcy5yZWNvbm5lY3RUaW1lcik7XG4gICAgICB0aGlzLnJlY29ubmVjdFRpbWVyID0gbnVsbDtcbiAgICB9XG4gIH1cblxuICBwcml2YXRlIF9zZXRTdGF0ZShzdGF0ZTogV1NDbGllbnRTdGF0ZSk6IHZvaWQge1xuICAgIGlmICh0aGlzLnN0YXRlID09PSBzdGF0ZSkgcmV0dXJuO1xuICAgIHRoaXMuc3RhdGUgPSBzdGF0ZTtcbiAgICB0aGlzLm9uU3RhdGVDaGFuZ2U/LihzdGF0ZSk7XG4gIH1cblxuICBwcml2YXRlIF9zZXRXb3JraW5nKHdvcmtpbmc6IGJvb2xlYW4pOiB2b2lkIHtcbiAgICBpZiAodGhpcy53b3JraW5nID09PSB3b3JraW5nKSByZXR1cm47XG4gICAgdGhpcy53b3JraW5nID0gd29ya2luZztcbiAgICB0aGlzLm9uV29ya2luZ0NoYW5nZT8uKHdvcmtpbmcpO1xuXG4gICAgaWYgKCF3b3JraW5nKSB7XG4gICAgICB0aGlzLl9kaXNhcm1Xb3JraW5nU2FmZXR5VGltZW91dCgpO1xuICAgIH1cbiAgfVxuXG4gIHByaXZhdGUgX2FybVdvcmtpbmdTYWZldHlUaW1lb3V0KCk6IHZvaWQge1xuICAgIHRoaXMuX2Rpc2FybVdvcmtpbmdTYWZldHlUaW1lb3V0KCk7XG4gICAgdGhpcy53b3JraW5nVGltZXIgPSBzZXRUaW1lb3V0KCgpID0+IHtcbiAgICAgIC8vIElmIHRoZSBnYXRld2F5IG5ldmVyIGVtaXRzIGFuIGFzc2lzdGFudCBmaW5hbCByZXNwb25zZSwgZG9uXHUyMDE5dCBsZWF2ZSBVSSBzdHVjay5cbiAgICAgIHRoaXMuX3NldFdvcmtpbmcoZmFsc2UpO1xuICAgIH0sIFdPUktJTkdfTUFYX01TKTtcbiAgfVxuXG4gIHByaXZhdGUgX2Rpc2FybVdvcmtpbmdTYWZldHlUaW1lb3V0KCk6IHZvaWQge1xuICAgIGlmICh0aGlzLndvcmtpbmdUaW1lcikge1xuICAgICAgY2xlYXJUaW1lb3V0KHRoaXMud29ya2luZ1RpbWVyKTtcbiAgICAgIHRoaXMud29ya2luZ1RpbWVyID0gbnVsbDtcbiAgICB9XG4gIH1cbn1cbiIsICJpbXBvcnQgdHlwZSB7IENoYXRNZXNzYWdlIH0gZnJvbSAnLi90eXBlcyc7XG5cbi8qKiBNYW5hZ2VzIHRoZSBpbi1tZW1vcnkgbGlzdCBvZiBjaGF0IG1lc3NhZ2VzIGFuZCBub3RpZmllcyBVSSBvbiBjaGFuZ2VzICovXG5leHBvcnQgY2xhc3MgQ2hhdE1hbmFnZXIge1xuICBwcml2YXRlIG1lc3NhZ2VzOiBDaGF0TWVzc2FnZVtdID0gW107XG5cbiAgLyoqIEZpcmVkIGZvciBhIGZ1bGwgcmUtcmVuZGVyIChjbGVhci9yZWxvYWQpICovXG4gIG9uVXBkYXRlOiAoKG1lc3NhZ2VzOiByZWFkb25seSBDaGF0TWVzc2FnZVtdKSA9PiB2b2lkKSB8IG51bGwgPSBudWxsO1xuICAvKiogRmlyZWQgd2hlbiBhIHNpbmdsZSBtZXNzYWdlIGlzIGFwcGVuZGVkIFx1MjAxNCB1c2UgZm9yIE8oMSkgYXBwZW5kLW9ubHkgVUkgKi9cbiAgb25NZXNzYWdlQWRkZWQ6ICgobXNnOiBDaGF0TWVzc2FnZSkgPT4gdm9pZCkgfCBudWxsID0gbnVsbDtcblxuICBhZGRNZXNzYWdlKG1zZzogQ2hhdE1lc3NhZ2UpOiB2b2lkIHtcbiAgICB0aGlzLm1lc3NhZ2VzLnB1c2gobXNnKTtcbiAgICB0aGlzLm9uTWVzc2FnZUFkZGVkPy4obXNnKTtcbiAgfVxuXG4gIGdldE1lc3NhZ2VzKCk6IHJlYWRvbmx5IENoYXRNZXNzYWdlW10ge1xuICAgIHJldHVybiB0aGlzLm1lc3NhZ2VzO1xuICB9XG5cbiAgY2xlYXIoKTogdm9pZCB7XG4gICAgdGhpcy5tZXNzYWdlcyA9IFtdO1xuICAgIHRoaXMub25VcGRhdGU/LihbXSk7XG4gIH1cblxuICAvKiogQ3JlYXRlIGEgdXNlciBtZXNzYWdlIG9iamVjdCAod2l0aG91dCBhZGRpbmcgaXQpICovXG4gIHN0YXRpYyBjcmVhdGVVc2VyTWVzc2FnZShjb250ZW50OiBzdHJpbmcpOiBDaGF0TWVzc2FnZSB7XG4gICAgcmV0dXJuIHtcbiAgICAgIGlkOiBgbXNnLSR7RGF0ZS5ub3coKX0tJHtNYXRoLnJhbmRvbSgpLnRvU3RyaW5nKDM2KS5zbGljZSgyLCA3KX1gLFxuICAgICAgcm9sZTogJ3VzZXInLFxuICAgICAgY29udGVudCxcbiAgICAgIHRpbWVzdGFtcDogRGF0ZS5ub3coKSxcbiAgICB9O1xuICB9XG5cbiAgLyoqIENyZWF0ZSBhbiBhc3Npc3RhbnQgbWVzc2FnZSBvYmplY3QgKHdpdGhvdXQgYWRkaW5nIGl0KSAqL1xuICBzdGF0aWMgY3JlYXRlQXNzaXN0YW50TWVzc2FnZShjb250ZW50OiBzdHJpbmcpOiBDaGF0TWVzc2FnZSB7XG4gICAgcmV0dXJuIHtcbiAgICAgIGlkOiBgbXNnLSR7RGF0ZS5ub3coKX0tJHtNYXRoLnJhbmRvbSgpLnRvU3RyaW5nKDM2KS5zbGljZSgyLCA3KX1gLFxuICAgICAgcm9sZTogJ2Fzc2lzdGFudCcsXG4gICAgICBjb250ZW50LFxuICAgICAgdGltZXN0YW1wOiBEYXRlLm5vdygpLFxuICAgIH07XG4gIH1cblxuICAvKiogQ3JlYXRlIGEgc3lzdGVtIC8gc3RhdHVzIG1lc3NhZ2UgKGVycm9ycywgcmVjb25uZWN0IG5vdGljZXMsIGV0Yy4pICovXG4gIHN0YXRpYyBjcmVhdGVTeXN0ZW1NZXNzYWdlKGNvbnRlbnQ6IHN0cmluZywgbGV2ZWw6IENoYXRNZXNzYWdlWydsZXZlbCddID0gJ2luZm8nKTogQ2hhdE1lc3NhZ2Uge1xuICAgIHJldHVybiB7XG4gICAgICBpZDogYHN5cy0ke0RhdGUubm93KCl9YCxcbiAgICAgIHJvbGU6ICdzeXN0ZW0nLFxuICAgICAgbGV2ZWwsXG4gICAgICBjb250ZW50LFxuICAgICAgdGltZXN0YW1wOiBEYXRlLm5vdygpLFxuICAgIH07XG4gIH1cbn1cbiIsICJpbXBvcnQgeyBJdGVtVmlldywgTWFya2Rvd25SZW5kZXJlciwgTm90aWNlLCBURmlsZSwgV29ya3NwYWNlTGVhZiB9IGZyb20gJ29ic2lkaWFuJztcbmltcG9ydCB0eXBlIE9wZW5DbGF3UGx1Z2luIGZyb20gJy4vbWFpbic7XG5pbXBvcnQgeyBDaGF0TWFuYWdlciB9IGZyb20gJy4vY2hhdCc7XG5pbXBvcnQgdHlwZSB7IENoYXRNZXNzYWdlLCBQYXRoTWFwcGluZyB9IGZyb20gJy4vdHlwZXMnO1xuaW1wb3J0IHsgZXh0cmFjdENhbmRpZGF0ZXMsIHRyeU1hcFJlbW90ZVBhdGhUb1ZhdWx0UGF0aCB9IGZyb20gJy4vbGlua2lmeSc7XG5pbXBvcnQgeyBnZXRBY3RpdmVOb3RlQ29udGV4dCB9IGZyb20gJy4vY29udGV4dCc7XG5cbmV4cG9ydCBjb25zdCBWSUVXX1RZUEVfT1BFTkNMQVdfQ0hBVCA9ICdvcGVuY2xhdy1jaGF0JztcblxuZXhwb3J0IGNsYXNzIE9wZW5DbGF3Q2hhdFZpZXcgZXh0ZW5kcyBJdGVtVmlldyB7XG4gIHByaXZhdGUgcGx1Z2luOiBPcGVuQ2xhd1BsdWdpbjtcbiAgcHJpdmF0ZSBjaGF0TWFuYWdlcjogQ2hhdE1hbmFnZXI7XG5cbiAgLy8gU3RhdGVcbiAgcHJpdmF0ZSBpc0Nvbm5lY3RlZCA9IGZhbHNlO1xuICBwcml2YXRlIGlzV29ya2luZyA9IGZhbHNlO1xuXG4gIC8vIENvbm5lY3Rpb24gbm90aWNlcyAoYXZvaWQgc3BhbSlcbiAgcHJpdmF0ZSBsYXN0Q29ubk5vdGljZUF0TXMgPSAwO1xuICBwcml2YXRlIGxhc3RHYXRld2F5U3RhdGU6IHN0cmluZyB8IG51bGwgPSBudWxsO1xuXG4gIC8vIERPTSByZWZzXG4gIHByaXZhdGUgbWVzc2FnZXNFbCE6IEhUTUxFbGVtZW50O1xuICBwcml2YXRlIGlucHV0RWwhOiBIVE1MVGV4dEFyZWFFbGVtZW50O1xuICBwcml2YXRlIHNlbmRCdG4hOiBIVE1MQnV0dG9uRWxlbWVudDtcbiAgcHJpdmF0ZSBpbmNsdWRlTm90ZUNoZWNrYm94ITogSFRNTElucHV0RWxlbWVudDtcbiAgcHJpdmF0ZSBzdGF0dXNEb3QhOiBIVE1MRWxlbWVudDtcblxuICBjb25zdHJ1Y3RvcihsZWFmOiBXb3Jrc3BhY2VMZWFmLCBwbHVnaW46IE9wZW5DbGF3UGx1Z2luKSB7XG4gICAgc3VwZXIobGVhZik7XG4gICAgdGhpcy5wbHVnaW4gPSBwbHVnaW47XG4gICAgdGhpcy5jaGF0TWFuYWdlciA9IHBsdWdpbi5jaGF0TWFuYWdlcjtcbiAgfVxuXG4gIGdldFZpZXdUeXBlKCk6IHN0cmluZyB7XG4gICAgcmV0dXJuIFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFUO1xuICB9XG5cbiAgZ2V0RGlzcGxheVRleHQoKTogc3RyaW5nIHtcbiAgICByZXR1cm4gJ09wZW5DbGF3IENoYXQnO1xuICB9XG5cbiAgZ2V0SWNvbigpOiBzdHJpbmcge1xuICAgIHJldHVybiAnbWVzc2FnZS1zcXVhcmUnO1xuICB9XG5cbiAgYXN5bmMgb25PcGVuKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIHRoaXMuX2J1aWxkVUkoKTtcblxuICAgIC8vIEZ1bGwgcmUtcmVuZGVyIG9uIGNsZWFyIC8gcmVsb2FkXG4gICAgdGhpcy5jaGF0TWFuYWdlci5vblVwZGF0ZSA9IChtc2dzKSA9PiB0aGlzLl9yZW5kZXJNZXNzYWdlcyhtc2dzKTtcbiAgICAvLyBPKDEpIGFwcGVuZCBmb3IgbmV3IG1lc3NhZ2VzXG4gICAgdGhpcy5jaGF0TWFuYWdlci5vbk1lc3NhZ2VBZGRlZCA9IChtc2cpID0+IHRoaXMuX2FwcGVuZE1lc3NhZ2UobXNnKTtcblxuICAgIC8vIFN1YnNjcmliZSB0byBXUyBzdGF0ZSBjaGFuZ2VzXG4gICAgdGhpcy5wbHVnaW4ud3NDbGllbnQub25TdGF0ZUNoYW5nZSA9IChzdGF0ZSkgPT4ge1xuICAgICAgLy8gQ29ubmVjdGlvbiBsb3NzIC8gcmVjb25uZWN0IG5vdGljZXMgKHRocm90dGxlZClcbiAgICAgIGNvbnN0IHByZXYgPSB0aGlzLmxhc3RHYXRld2F5U3RhdGU7XG4gICAgICB0aGlzLmxhc3RHYXRld2F5U3RhdGUgPSBzdGF0ZTtcblxuICAgICAgY29uc3Qgbm93ID0gRGF0ZS5ub3coKTtcbiAgICAgIGNvbnN0IE5PVElDRV9USFJPVFRMRV9NUyA9IDYwXzAwMDtcblxuICAgICAgY29uc3Qgc2hvdWxkTm90aWZ5ID0gKCkgPT4gbm93IC0gdGhpcy5sYXN0Q29ubk5vdGljZUF0TXMgPiBOT1RJQ0VfVEhST1RUTEVfTVM7XG4gICAgICBjb25zdCBub3RpZnkgPSAodGV4dDogc3RyaW5nKSA9PiB7XG4gICAgICAgIGlmICghc2hvdWxkTm90aWZ5KCkpIHJldHVybjtcbiAgICAgICAgdGhpcy5sYXN0Q29ubk5vdGljZUF0TXMgPSBub3c7XG4gICAgICAgIG5ldyBOb3RpY2UodGV4dCk7XG4gICAgICB9O1xuXG4gICAgICAvLyBPbmx5IHNob3cgXHUyMDFDbG9zdFx1MjAxRCBpZiB3ZSB3ZXJlIHByZXZpb3VzbHkgY29ubmVjdGVkLlxuICAgICAgaWYgKHByZXYgPT09ICdjb25uZWN0ZWQnICYmIHN0YXRlID09PSAnZGlzY29ubmVjdGVkJykge1xuICAgICAgICBub3RpZnkoJ09wZW5DbGF3IENoYXQ6IGNvbm5lY3Rpb24gbG9zdCBcdTIwMTQgcmVjb25uZWN0aW5nXHUyMDI2Jyk7XG4gICAgICAgIC8vIEFsc28gYXBwZW5kIGEgc3lzdGVtIG1lc3NhZ2Ugc28gaXRcdTIwMTlzIHZpc2libGUgaW4gdGhlIGNoYXQgaGlzdG9yeS5cbiAgICAgICAgdGhpcy5jaGF0TWFuYWdlci5hZGRNZXNzYWdlKENoYXRNYW5hZ2VyLmNyZWF0ZVN5c3RlbU1lc3NhZ2UoJ1x1MjZBMCBDb25uZWN0aW9uIGxvc3QgXHUyMDE0IHJlY29ubmVjdGluZ1x1MjAyNicsICdlcnJvcicpKTtcbiAgICAgIH1cblxuICAgICAgLy8gT3B0aW9uYWwgXHUyMDFDcmVjb25uZWN0ZWRcdTIwMUQgbm90aWNlXG4gICAgICBpZiAocHJldiAmJiBwcmV2ICE9PSAnY29ubmVjdGVkJyAmJiBzdGF0ZSA9PT0gJ2Nvbm5lY3RlZCcpIHtcbiAgICAgICAgbm90aWZ5KCdPcGVuQ2xhdyBDaGF0OiByZWNvbm5lY3RlZCcpO1xuICAgICAgICB0aGlzLmNoYXRNYW5hZ2VyLmFkZE1lc3NhZ2UoQ2hhdE1hbmFnZXIuY3JlYXRlU3lzdGVtTWVzc2FnZSgnXHUyNzA1IFJlY29ubmVjdGVkJywgJ2luZm8nKSk7XG4gICAgICB9XG5cbiAgICAgIHRoaXMuaXNDb25uZWN0ZWQgPSBzdGF0ZSA9PT0gJ2Nvbm5lY3RlZCc7XG4gICAgICB0aGlzLnN0YXR1c0RvdC50b2dnbGVDbGFzcygnY29ubmVjdGVkJywgdGhpcy5pc0Nvbm5lY3RlZCk7XG4gICAgICB0aGlzLnN0YXR1c0RvdC50aXRsZSA9IGBHYXRld2F5OiAke3N0YXRlfWA7XG4gICAgICB0aGlzLl91cGRhdGVTZW5kQnV0dG9uKCk7XG4gICAgfTtcblxuICAgIC8vIFN1YnNjcmliZSB0byBcdTIwMUN3b3JraW5nXHUyMDFEIChyZXF1ZXN0LWluLWZsaWdodCkgc3RhdGVcbiAgICB0aGlzLnBsdWdpbi53c0NsaWVudC5vbldvcmtpbmdDaGFuZ2UgPSAod29ya2luZykgPT4ge1xuICAgICAgdGhpcy5pc1dvcmtpbmcgPSB3b3JraW5nO1xuICAgICAgdGhpcy5fdXBkYXRlU2VuZEJ1dHRvbigpO1xuICAgIH07XG5cbiAgICAvLyBSZWZsZWN0IGN1cnJlbnQgc3RhdGVcbiAgICB0aGlzLmxhc3RHYXRld2F5U3RhdGUgPSB0aGlzLnBsdWdpbi53c0NsaWVudC5zdGF0ZTtcbiAgICB0aGlzLmlzQ29ubmVjdGVkID0gdGhpcy5wbHVnaW4ud3NDbGllbnQuc3RhdGUgPT09ICdjb25uZWN0ZWQnO1xuICAgIHRoaXMuc3RhdHVzRG90LnRvZ2dsZUNsYXNzKCdjb25uZWN0ZWQnLCB0aGlzLmlzQ29ubmVjdGVkKTtcbiAgICB0aGlzLnN0YXR1c0RvdC50aXRsZSA9IGBHYXRld2F5OiAke3RoaXMucGx1Z2luLndzQ2xpZW50LnN0YXRlfWA7XG4gICAgdGhpcy5fdXBkYXRlU2VuZEJ1dHRvbigpO1xuXG4gICAgdGhpcy5fcmVuZGVyTWVzc2FnZXModGhpcy5jaGF0TWFuYWdlci5nZXRNZXNzYWdlcygpKTtcbiAgfVxuXG4gIGFzeW5jIG9uQ2xvc2UoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgdGhpcy5jaGF0TWFuYWdlci5vblVwZGF0ZSA9IG51bGw7XG4gICAgdGhpcy5jaGF0TWFuYWdlci5vbk1lc3NhZ2VBZGRlZCA9IG51bGw7XG4gICAgdGhpcy5wbHVnaW4ud3NDbGllbnQub25TdGF0ZUNoYW5nZSA9IG51bGw7XG4gICAgdGhpcy5wbHVnaW4ud3NDbGllbnQub25Xb3JraW5nQ2hhbmdlID0gbnVsbDtcbiAgfVxuXG4gIC8vIFx1MjUwMFx1MjUwMCBVSSBjb25zdHJ1Y3Rpb24gXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG5cbiAgcHJpdmF0ZSBfYnVpbGRVSSgpOiB2b2lkIHtcbiAgICBjb25zdCByb290ID0gdGhpcy5jb250ZW50RWw7XG4gICAgcm9vdC5lbXB0eSgpO1xuICAgIHJvb3QuYWRkQ2xhc3MoJ29jbGF3LWNoYXQtdmlldycpO1xuXG4gICAgLy8gXHUyNTAwXHUyNTAwIEhlYWRlciBcdTI1MDBcdTI1MDBcbiAgICBjb25zdCBoZWFkZXIgPSByb290LmNyZWF0ZURpdih7IGNsczogJ29jbGF3LWhlYWRlcicgfSk7XG4gICAgaGVhZGVyLmNyZWF0ZVNwYW4oeyBjbHM6ICdvY2xhdy1oZWFkZXItdGl0bGUnLCB0ZXh0OiAnT3BlbkNsYXcgQ2hhdCcgfSk7XG4gICAgdGhpcy5zdGF0dXNEb3QgPSBoZWFkZXIuY3JlYXRlRGl2KHsgY2xzOiAnb2NsYXctc3RhdHVzLWRvdCcgfSk7XG4gICAgdGhpcy5zdGF0dXNEb3QudGl0bGUgPSAnR2F0ZXdheTogZGlzY29ubmVjdGVkJztcblxuICAgIC8vIFx1MjUwMFx1MjUwMCBNZXNzYWdlcyBhcmVhIFx1MjUwMFx1MjUwMFxuICAgIHRoaXMubWVzc2FnZXNFbCA9IHJvb3QuY3JlYXRlRGl2KHsgY2xzOiAnb2NsYXctbWVzc2FnZXMnIH0pO1xuXG4gICAgLy8gXHUyNTAwXHUyNTAwIENvbnRleHQgcm93IFx1MjUwMFx1MjUwMFxuICAgIGNvbnN0IGN0eFJvdyA9IHJvb3QuY3JlYXRlRGl2KHsgY2xzOiAnb2NsYXctY29udGV4dC1yb3cnIH0pO1xuICAgIHRoaXMuaW5jbHVkZU5vdGVDaGVja2JveCA9IGN0eFJvdy5jcmVhdGVFbCgnaW5wdXQnLCB7IHR5cGU6ICdjaGVja2JveCcgfSk7XG4gICAgdGhpcy5pbmNsdWRlTm90ZUNoZWNrYm94LmlkID0gJ29jbGF3LWluY2x1ZGUtbm90ZSc7XG4gICAgdGhpcy5pbmNsdWRlTm90ZUNoZWNrYm94LmNoZWNrZWQgPSB0aGlzLnBsdWdpbi5zZXR0aW5ncy5pbmNsdWRlQWN0aXZlTm90ZTtcbiAgICBjb25zdCBjdHhMYWJlbCA9IGN0eFJvdy5jcmVhdGVFbCgnbGFiZWwnLCB7IHRleHQ6ICdJbmNsdWRlIGFjdGl2ZSBub3RlJyB9KTtcbiAgICBjdHhMYWJlbC5odG1sRm9yID0gJ29jbGF3LWluY2x1ZGUtbm90ZSc7XG5cbiAgICAvLyBcdTI1MDBcdTI1MDAgSW5wdXQgcm93IFx1MjUwMFx1MjUwMFxuICAgIGNvbnN0IGlucHV0Um93ID0gcm9vdC5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1pbnB1dC1yb3cnIH0pO1xuICAgIHRoaXMuaW5wdXRFbCA9IGlucHV0Um93LmNyZWF0ZUVsKCd0ZXh0YXJlYScsIHtcbiAgICAgIGNsczogJ29jbGF3LWlucHV0JyxcbiAgICAgIHBsYWNlaG9sZGVyOiAnQXNrIGFueXRoaW5nXHUyMDI2JyxcbiAgICB9KTtcbiAgICB0aGlzLmlucHV0RWwucm93cyA9IDE7XG5cbiAgICB0aGlzLnNlbmRCdG4gPSBpbnB1dFJvdy5jcmVhdGVFbCgnYnV0dG9uJywgeyBjbHM6ICdvY2xhdy1zZW5kLWJ0bicsIHRleHQ6ICdTZW5kJyB9KTtcblxuICAgIC8vIFx1MjUwMFx1MjUwMCBFdmVudCBsaXN0ZW5lcnMgXHUyNTAwXHUyNTAwXG4gICAgdGhpcy5zZW5kQnRuLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gdGhpcy5faGFuZGxlU2VuZCgpKTtcbiAgICB0aGlzLmlucHV0RWwuYWRkRXZlbnRMaXN0ZW5lcigna2V5ZG93bicsIChlKSA9PiB7XG4gICAgICBpZiAoZS5rZXkgPT09ICdFbnRlcicgJiYgIWUuc2hpZnRLZXkpIHtcbiAgICAgICAgZS5wcmV2ZW50RGVmYXVsdCgpO1xuICAgICAgICB0aGlzLl9oYW5kbGVTZW5kKCk7XG4gICAgICB9XG4gICAgfSk7XG4gICAgLy8gQXV0by1yZXNpemUgdGV4dGFyZWFcbiAgICB0aGlzLmlucHV0RWwuYWRkRXZlbnRMaXN0ZW5lcignaW5wdXQnLCAoKSA9PiB7XG4gICAgICB0aGlzLmlucHV0RWwuc3R5bGUuaGVpZ2h0ID0gJ2F1dG8nO1xuICAgICAgdGhpcy5pbnB1dEVsLnN0eWxlLmhlaWdodCA9IGAke3RoaXMuaW5wdXRFbC5zY3JvbGxIZWlnaHR9cHhgO1xuICAgIH0pO1xuICB9XG5cbiAgLy8gXHUyNTAwXHUyNTAwIE1lc3NhZ2UgcmVuZGVyaW5nIFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFxuXG4gIHByaXZhdGUgX3JlbmRlck1lc3NhZ2VzKG1lc3NhZ2VzOiByZWFkb25seSBDaGF0TWVzc2FnZVtdKTogdm9pZCB7XG4gICAgdGhpcy5tZXNzYWdlc0VsLmVtcHR5KCk7XG5cbiAgICBpZiAobWVzc2FnZXMubGVuZ3RoID09PSAwKSB7XG4gICAgICB0aGlzLm1lc3NhZ2VzRWwuY3JlYXRlRWwoJ3AnLCB7XG4gICAgICAgIHRleHQ6ICdTZW5kIGEgbWVzc2FnZSB0byBzdGFydCBjaGF0dGluZy4nLFxuICAgICAgICBjbHM6ICdvY2xhdy1tZXNzYWdlIHN5c3RlbSBvY2xhdy1wbGFjZWhvbGRlcicsXG4gICAgICB9KTtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICBmb3IgKGNvbnN0IG1zZyBvZiBtZXNzYWdlcykge1xuICAgICAgdGhpcy5fYXBwZW5kTWVzc2FnZShtc2cpO1xuICAgIH1cblxuICAgIC8vIFNjcm9sbCB0byBib3R0b21cbiAgICB0aGlzLm1lc3NhZ2VzRWwuc2Nyb2xsVG9wID0gdGhpcy5tZXNzYWdlc0VsLnNjcm9sbEhlaWdodDtcbiAgfVxuXG4gIC8qKiBBcHBlbmRzIGEgc2luZ2xlIG1lc3NhZ2Ugd2l0aG91dCByZWJ1aWxkaW5nIHRoZSBET00gKE8oMSkpICovXG4gIHByaXZhdGUgX2FwcGVuZE1lc3NhZ2UobXNnOiBDaGF0TWVzc2FnZSk6IHZvaWQge1xuICAgIC8vIFJlbW92ZSBlbXB0eS1zdGF0ZSBwbGFjZWhvbGRlciBpZiBwcmVzZW50XG4gICAgdGhpcy5tZXNzYWdlc0VsLnF1ZXJ5U2VsZWN0b3IoJy5vY2xhdy1wbGFjZWhvbGRlcicpPy5yZW1vdmUoKTtcblxuICAgIGNvbnN0IGxldmVsQ2xhc3MgPSBtc2cubGV2ZWwgPyBgICR7bXNnLmxldmVsfWAgOiAnJztcbiAgICBjb25zdCBlbCA9IHRoaXMubWVzc2FnZXNFbC5jcmVhdGVEaXYoeyBjbHM6IGBvY2xhdy1tZXNzYWdlICR7bXNnLnJvbGV9JHtsZXZlbENsYXNzfWAgfSk7XG4gICAgY29uc3QgYm9keSA9IGVsLmNyZWF0ZURpdih7IGNsczogJ29jbGF3LW1lc3NhZ2UtYm9keScgfSk7XG5cbiAgICAvLyBUcmVhdCBhc3Npc3RhbnQgb3V0cHV0IGFzIFVOVFJVU1RFRCBieSBkZWZhdWx0LlxuICAgIC8vIFJlbmRlcmluZyBhcyBPYnNpZGlhbiBNYXJrZG93biBjYW4gdHJpZ2dlciBlbWJlZHMgYW5kIG90aGVyIHBsdWdpbnMnIHBvc3QtcHJvY2Vzc29ycy5cbiAgICBpZiAobXNnLnJvbGUgPT09ICdhc3Npc3RhbnQnKSB7XG4gICAgICBjb25zdCBtYXBwaW5nczogUGF0aE1hcHBpbmdbXSA9IHRoaXMucGx1Z2luLnNldHRpbmdzLnBhdGhNYXBwaW5ncyA/PyBbXTtcbiAgICAgIGNvbnN0IHNvdXJjZVBhdGggPSB0aGlzLmFwcC53b3Jrc3BhY2UuZ2V0QWN0aXZlRmlsZSgpPy5wYXRoID8/ICcnO1xuXG4gICAgICBpZiAodGhpcy5wbHVnaW4uc2V0dGluZ3MucmVuZGVyQXNzaXN0YW50TWFya2Rvd24pIHtcbiAgICAgICAgLy8gQmVzdC1lZmZvcnQgcHJlLXByb2Nlc3Npbmc6IHJlcGxhY2Uga25vd24gcmVtb3RlIHBhdGhzIHdpdGggd2lraWxpbmtzIHdoZW4gdGhlIHRhcmdldCBleGlzdHMuXG4gICAgICAgIGNvbnN0IHByZSA9IHRoaXMuX3ByZXByb2Nlc3NBc3Npc3RhbnRNYXJrZG93bihtc2cuY29udGVudCwgbWFwcGluZ3MpO1xuICAgICAgICB2b2lkIE1hcmtkb3duUmVuZGVyZXIucmVuZGVyTWFya2Rvd24ocHJlLCBib2R5LCBzb3VyY2VQYXRoLCB0aGlzLnBsdWdpbik7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICAvLyBQbGFpbiBtb2RlOiBidWlsZCBzYWZlLCBjbGlja2FibGUgbGlua3MgaW4gRE9NIChubyBNYXJrZG93biByZW5kZXJpbmcpLlxuICAgICAgICB0aGlzLl9yZW5kZXJBc3Npc3RhbnRQbGFpbldpdGhMaW5rcyhib2R5LCBtc2cuY29udGVudCwgbWFwcGluZ3MsIHNvdXJjZVBhdGgpO1xuICAgICAgfVxuICAgIH0gZWxzZSB7XG4gICAgICBib2R5LnNldFRleHQobXNnLmNvbnRlbnQpO1xuICAgIH1cblxuICAgIC8vIFNjcm9sbCB0byBib3R0b21cbiAgICB0aGlzLm1lc3NhZ2VzRWwuc2Nyb2xsVG9wID0gdGhpcy5tZXNzYWdlc0VsLnNjcm9sbEhlaWdodDtcbiAgfVxuXG4gIHByaXZhdGUgX3RyeVJldmVyc2VNYXBVcmxUb1ZhdWx0UGF0aCh1cmw6IHN0cmluZywgbWFwcGluZ3M6IFBhdGhNYXBwaW5nW10pOiBzdHJpbmcgfCBudWxsIHtcbiAgICAvLyBGUy1iYXNlZCBtYXBwaW5nOyBiZXN0LWVmZm9ydCBvbmx5LlxuICAgIGxldCBkZWNvZGVkID0gdXJsO1xuICAgIHRyeSB7XG4gICAgICBkZWNvZGVkID0gZGVjb2RlVVJJQ29tcG9uZW50KHVybCk7XG4gICAgfSBjYXRjaCB7XG4gICAgICAvLyBpZ25vcmVcbiAgICB9XG5cbiAgICAvLyBJZiB0aGUgZGVjb2RlZCBVUkwgY29udGFpbnMgYSByZW1vdGVCYXNlIHN1YnN0cmluZywgdHJ5IG1hcHBpbmcgZnJvbSB0aGF0IHBvaW50LlxuICAgIGZvciAoY29uc3Qgcm93IG9mIG1hcHBpbmdzKSB7XG4gICAgICBjb25zdCByZW1vdGVCYXNlID0gU3RyaW5nKHJvdy5yZW1vdGVCYXNlID8/ICcnKTtcbiAgICAgIGlmICghcmVtb3RlQmFzZSkgY29udGludWU7XG4gICAgICBjb25zdCBpZHggPSBkZWNvZGVkLmluZGV4T2YocmVtb3RlQmFzZSk7XG4gICAgICBpZiAoaWR4IDwgMCkgY29udGludWU7XG5cbiAgICAgIC8vIEV4dHJhY3QgZnJvbSByZW1vdGVCYXNlIG9ud2FyZCB1bnRpbCBhIHRlcm1pbmF0b3IuXG4gICAgICBjb25zdCB0YWlsID0gZGVjb2RlZC5zbGljZShpZHgpO1xuICAgICAgY29uc3QgdG9rZW4gPSB0YWlsLnNwbGl0KC9bXFxzJ1wiPD4pXS8pWzBdO1xuICAgICAgY29uc3QgbWFwcGVkID0gdHJ5TWFwUmVtb3RlUGF0aFRvVmF1bHRQYXRoKHRva2VuLCBtYXBwaW5ncyk7XG4gICAgICBpZiAobWFwcGVkICYmIHRoaXMuYXBwLnZhdWx0LmdldEFic3RyYWN0RmlsZUJ5UGF0aChtYXBwZWQpKSByZXR1cm4gbWFwcGVkO1xuICAgIH1cblxuICAgIHJldHVybiBudWxsO1xuICB9XG5cbiAgcHJpdmF0ZSBfdHJ5TWFwVmF1bHRSZWxhdGl2ZVRva2VuKHRva2VuOiBzdHJpbmcsIG1hcHBpbmdzOiBQYXRoTWFwcGluZ1tdKTogc3RyaW5nIHwgbnVsbCB7XG4gICAgY29uc3QgdCA9IHRva2VuLnJlcGxhY2UoL15cXC8rLywgJycpO1xuICAgIGlmICh0aGlzLmFwcC52YXVsdC5nZXRBYnN0cmFjdEZpbGVCeVBhdGgodCkpIHJldHVybiB0O1xuXG4gICAgLy8gSGV1cmlzdGljOiBpZiB2YXVsdEJhc2UgZW5kcyB3aXRoIGEgc2VnbWVudCAoZS5nLiB3b3Jrc3BhY2UvY29tcGVuZy8pIGFuZCB0b2tlbiBzdGFydHMgd2l0aCB0aGF0IHNlZ21lbnQgKGNvbXBlbmcvLi4uKSxcbiAgICAvLyBtYXAgdG9rZW4gdW5kZXIgdmF1bHRCYXNlLlxuICAgIGZvciAoY29uc3Qgcm93IG9mIG1hcHBpbmdzKSB7XG4gICAgICBjb25zdCB2YXVsdEJhc2VSYXcgPSBTdHJpbmcocm93LnZhdWx0QmFzZSA/PyAnJykudHJpbSgpO1xuICAgICAgaWYgKCF2YXVsdEJhc2VSYXcpIGNvbnRpbnVlO1xuICAgICAgY29uc3QgdmF1bHRCYXNlID0gdmF1bHRCYXNlUmF3LmVuZHNXaXRoKCcvJykgPyB2YXVsdEJhc2VSYXcgOiBgJHt2YXVsdEJhc2VSYXd9L2A7XG5cbiAgICAgIGNvbnN0IHBhcnRzID0gdmF1bHRCYXNlLnJlcGxhY2UoL1xcLyskLywgJycpLnNwbGl0KCcvJyk7XG4gICAgICBjb25zdCBiYXNlTmFtZSA9IHBhcnRzW3BhcnRzLmxlbmd0aCAtIDFdO1xuICAgICAgaWYgKCFiYXNlTmFtZSkgY29udGludWU7XG5cbiAgICAgIGNvbnN0IHByZWZpeCA9IGAke2Jhc2VOYW1lfS9gO1xuICAgICAgaWYgKCF0LnN0YXJ0c1dpdGgocHJlZml4KSkgY29udGludWU7XG5cbiAgICAgIGNvbnN0IGNhbmRpZGF0ZSA9IGAke3ZhdWx0QmFzZX0ke3Quc2xpY2UocHJlZml4Lmxlbmd0aCl9YDtcbiAgICAgIGNvbnN0IG5vcm1hbGl6ZWQgPSBjYW5kaWRhdGUucmVwbGFjZSgvXlxcLysvLCAnJyk7XG4gICAgICBpZiAodGhpcy5hcHAudmF1bHQuZ2V0QWJzdHJhY3RGaWxlQnlQYXRoKG5vcm1hbGl6ZWQpKSByZXR1cm4gbm9ybWFsaXplZDtcbiAgICB9XG5cbiAgICByZXR1cm4gbnVsbDtcbiAgfVxuXG4gIHByaXZhdGUgX3ByZXByb2Nlc3NBc3Npc3RhbnRNYXJrZG93bih0ZXh0OiBzdHJpbmcsIG1hcHBpbmdzOiBQYXRoTWFwcGluZ1tdKTogc3RyaW5nIHtcbiAgICBjb25zdCBjYW5kaWRhdGVzID0gZXh0cmFjdENhbmRpZGF0ZXModGV4dCk7XG4gICAgaWYgKGNhbmRpZGF0ZXMubGVuZ3RoID09PSAwKSByZXR1cm4gdGV4dDtcblxuICAgIGxldCBvdXQgPSAnJztcbiAgICBsZXQgY3Vyc29yID0gMDtcblxuICAgIGZvciAoY29uc3QgYyBvZiBjYW5kaWRhdGVzKSB7XG4gICAgICBvdXQgKz0gdGV4dC5zbGljZShjdXJzb3IsIGMuc3RhcnQpO1xuICAgICAgY3Vyc29yID0gYy5lbmQ7XG5cbiAgICAgIGlmIChjLmtpbmQgPT09ICd1cmwnKSB7XG4gICAgICAgIC8vIFVSTHMgcmVtYWluIFVSTHMgVU5MRVNTIHdlIGNhbiBzYWZlbHkgbWFwIHRvIGFuIGV4aXN0aW5nIHZhdWx0IGZpbGUuXG4gICAgICAgIGNvbnN0IG1hcHBlZCA9IHRoaXMuX3RyeVJldmVyc2VNYXBVcmxUb1ZhdWx0UGF0aChjLnJhdywgbWFwcGluZ3MpO1xuICAgICAgICBvdXQgKz0gbWFwcGVkID8gYFtbJHttYXBwZWR9XV1gIDogYy5yYXc7XG4gICAgICAgIGNvbnRpbnVlO1xuICAgICAgfVxuXG4gICAgICAvLyAxKSBJZiB0aGUgdG9rZW4gaXMgYWxyZWFkeSBhIHZhdWx0LXJlbGF0aXZlIHBhdGggKG9yIGNhbiBiZSByZXNvbHZlZCB2aWEgdmF1bHRCYXNlIGhldXJpc3RpYyksIGxpbmtpZnkgaXQgZGlyZWN0bHkuXG4gICAgICBjb25zdCBkaXJlY3QgPSB0aGlzLl90cnlNYXBWYXVsdFJlbGF0aXZlVG9rZW4oYy5yYXcsIG1hcHBpbmdzKTtcbiAgICAgIGlmIChkaXJlY3QpIHtcbiAgICAgICAgb3V0ICs9IGBbWyR7ZGlyZWN0fV1dYDtcbiAgICAgICAgY29udGludWU7XG4gICAgICB9XG5cbiAgICAgIC8vIDIpIEVsc2U6IHRyeSByZW1vdGVcdTIxOTJ2YXVsdCBtYXBwaW5nLlxuICAgICAgY29uc3QgbWFwcGVkID0gdHJ5TWFwUmVtb3RlUGF0aFRvVmF1bHRQYXRoKGMucmF3LCBtYXBwaW5ncyk7XG4gICAgICBpZiAoIW1hcHBlZCkge1xuICAgICAgICBvdXQgKz0gYy5yYXc7XG4gICAgICAgIGNvbnRpbnVlO1xuICAgICAgfVxuXG4gICAgICBpZiAoIXRoaXMuYXBwLnZhdWx0LmdldEFic3RyYWN0RmlsZUJ5UGF0aChtYXBwZWQpKSB7XG4gICAgICAgIG91dCArPSBjLnJhdztcbiAgICAgICAgY29udGludWU7XG4gICAgICB9XG5cbiAgICAgIG91dCArPSBgW1ske21hcHBlZH1dXWA7XG4gICAgfVxuXG4gICAgb3V0ICs9IHRleHQuc2xpY2UoY3Vyc29yKTtcbiAgICByZXR1cm4gb3V0O1xuICB9XG5cbiAgcHJpdmF0ZSBfcmVuZGVyQXNzaXN0YW50UGxhaW5XaXRoTGlua3MoXG4gICAgYm9keTogSFRNTEVsZW1lbnQsXG4gICAgdGV4dDogc3RyaW5nLFxuICAgIG1hcHBpbmdzOiBQYXRoTWFwcGluZ1tdLFxuICAgIHNvdXJjZVBhdGg6IHN0cmluZyxcbiAgKTogdm9pZCB7XG4gICAgY29uc3QgY2FuZGlkYXRlcyA9IGV4dHJhY3RDYW5kaWRhdGVzKHRleHQpO1xuICAgIGlmIChjYW5kaWRhdGVzLmxlbmd0aCA9PT0gMCkge1xuICAgICAgYm9keS5zZXRUZXh0KHRleHQpO1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIGxldCBjdXJzb3IgPSAwO1xuXG4gICAgY29uc3QgYXBwZW5kVGV4dCA9IChzOiBzdHJpbmcpID0+IHtcbiAgICAgIGlmICghcykgcmV0dXJuO1xuICAgICAgYm9keS5hcHBlbmRDaGlsZChkb2N1bWVudC5jcmVhdGVUZXh0Tm9kZShzKSk7XG4gICAgfTtcblxuICAgIGNvbnN0IGFwcGVuZE9ic2lkaWFuTGluayA9ICh2YXVsdFBhdGg6IHN0cmluZykgPT4ge1xuICAgICAgY29uc3QgZGlzcGxheSA9IGBbWyR7dmF1bHRQYXRofV1dYDtcbiAgICAgIGNvbnN0IGEgPSBib2R5LmNyZWF0ZUVsKCdhJywgeyB0ZXh0OiBkaXNwbGF5LCBocmVmOiAnIycgfSk7XG4gICAgICBhLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKGV2KSA9PiB7XG4gICAgICAgIGV2LnByZXZlbnREZWZhdWx0KCk7XG4gICAgICAgIGV2LnN0b3BQcm9wYWdhdGlvbigpO1xuXG4gICAgICAgIGNvbnN0IGYgPSB0aGlzLmFwcC52YXVsdC5nZXRBYnN0cmFjdEZpbGVCeVBhdGgodmF1bHRQYXRoKTtcbiAgICAgICAgaWYgKGYgaW5zdGFuY2VvZiBURmlsZSkge1xuICAgICAgICAgIHZvaWQgdGhpcy5hcHAud29ya3NwYWNlLmdldExlYWYodHJ1ZSkub3BlbkZpbGUoZik7XG4gICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgLy8gRmFsbGJhY2s6IGJlc3QtZWZmb3J0IGxpbmt0ZXh0IG9wZW4uXG4gICAgICAgIHZvaWQgdGhpcy5hcHAud29ya3NwYWNlLm9wZW5MaW5rVGV4dCh2YXVsdFBhdGgsIHNvdXJjZVBhdGgsIHRydWUpO1xuICAgICAgfSk7XG4gICAgfTtcblxuICAgIGNvbnN0IGFwcGVuZEV4dGVybmFsVXJsID0gKHVybDogc3RyaW5nKSA9PiB7XG4gICAgICAvLyBMZXQgT2JzaWRpYW4vRWxlY3Ryb24gaGFuZGxlIGV4dGVybmFsIG9wZW4uXG4gICAgICBib2R5LmNyZWF0ZUVsKCdhJywgeyB0ZXh0OiB1cmwsIGhyZWY6IHVybCB9KTtcbiAgICB9O1xuXG4gICAgY29uc3QgdHJ5UmV2ZXJzZU1hcFVybFRvVmF1bHRQYXRoID0gKHVybDogc3RyaW5nKTogc3RyaW5nIHwgbnVsbCA9PiB0aGlzLl90cnlSZXZlcnNlTWFwVXJsVG9WYXVsdFBhdGgodXJsLCBtYXBwaW5ncyk7XG5cbiAgICBmb3IgKGNvbnN0IGMgb2YgY2FuZGlkYXRlcykge1xuICAgICAgYXBwZW5kVGV4dCh0ZXh0LnNsaWNlKGN1cnNvciwgYy5zdGFydCkpO1xuICAgICAgY3Vyc29yID0gYy5lbmQ7XG5cbiAgICAgIGlmIChjLmtpbmQgPT09ICd1cmwnKSB7XG4gICAgICAgIGNvbnN0IG1hcHBlZCA9IHRyeVJldmVyc2VNYXBVcmxUb1ZhdWx0UGF0aChjLnJhdyk7XG4gICAgICAgIGlmIChtYXBwZWQpIHtcbiAgICAgICAgICBhcHBlbmRPYnNpZGlhbkxpbmsobWFwcGVkKTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICBhcHBlbmRFeHRlcm5hbFVybChjLnJhdyk7XG4gICAgICAgIH1cbiAgICAgICAgY29udGludWU7XG4gICAgICB9XG5cbiAgICAgIC8vIDEpIElmIHRva2VuIGlzIGFscmVhZHkgYSB2YXVsdC1yZWxhdGl2ZSBwYXRoIChvciBjYW4gYmUgcmVzb2x2ZWQgdmlhIHZhdWx0QmFzZSBoZXVyaXN0aWMpLCBsaW5raWZ5IGRpcmVjdGx5LlxuICAgICAgY29uc3QgZGlyZWN0ID0gdGhpcy5fdHJ5TWFwVmF1bHRSZWxhdGl2ZVRva2VuKGMucmF3LCBtYXBwaW5ncyk7XG4gICAgICBpZiAoZGlyZWN0KSB7XG4gICAgICAgIGFwcGVuZE9ic2lkaWFuTGluayhkaXJlY3QpO1xuICAgICAgICBjb250aW51ZTtcbiAgICAgIH1cblxuICAgICAgLy8gMikgRWxzZTogdHJ5IHJlbW90ZVx1MjE5MnZhdWx0IG1hcHBpbmcuXG4gICAgICBjb25zdCBtYXBwZWQgPSB0cnlNYXBSZW1vdGVQYXRoVG9WYXVsdFBhdGgoYy5yYXcsIG1hcHBpbmdzKTtcbiAgICAgIGlmICghbWFwcGVkKSB7XG4gICAgICAgIGFwcGVuZFRleHQoYy5yYXcpO1xuICAgICAgICBjb250aW51ZTtcbiAgICAgIH1cblxuICAgICAgaWYgKCF0aGlzLmFwcC52YXVsdC5nZXRBYnN0cmFjdEZpbGVCeVBhdGgobWFwcGVkKSkge1xuICAgICAgICBhcHBlbmRUZXh0KGMucmF3KTtcbiAgICAgICAgY29udGludWU7XG4gICAgICB9XG5cbiAgICAgIGFwcGVuZE9ic2lkaWFuTGluayhtYXBwZWQpO1xuICAgIH1cblxuICAgIGFwcGVuZFRleHQodGV4dC5zbGljZShjdXJzb3IpKTtcbiAgfVxuXG4gIHByaXZhdGUgX3VwZGF0ZVNlbmRCdXR0b24oKTogdm9pZCB7XG4gICAgLy8gRGlzY29ubmVjdGVkOiBkaXNhYmxlLlxuICAgIC8vIFdvcmtpbmc6IGtlZXAgZW5hYmxlZCBzbyB1c2VyIGNhbiBzdG9wL2Fib3J0LlxuICAgIGNvbnN0IGRpc2FibGVkID0gIXRoaXMuaXNDb25uZWN0ZWQ7XG4gICAgdGhpcy5zZW5kQnRuLmRpc2FibGVkID0gZGlzYWJsZWQ7XG5cbiAgICB0aGlzLnNlbmRCdG4udG9nZ2xlQ2xhc3MoJ2lzLXdvcmtpbmcnLCB0aGlzLmlzV29ya2luZyk7XG4gICAgdGhpcy5zZW5kQnRuLnNldEF0dHIoJ2FyaWEtYnVzeScsIHRoaXMuaXNXb3JraW5nID8gJ3RydWUnIDogJ2ZhbHNlJyk7XG4gICAgdGhpcy5zZW5kQnRuLnNldEF0dHIoJ2FyaWEtbGFiZWwnLCB0aGlzLmlzV29ya2luZyA/ICdTdG9wJyA6ICdTZW5kJyk7XG5cbiAgICBpZiAodGhpcy5pc1dvcmtpbmcpIHtcbiAgICAgIC8vIFJlcGxhY2UgYnV0dG9uIGNvbnRlbnRzIHdpdGggU3RvcCBpY29uICsgc3Bpbm5lciByaW5nLlxuICAgICAgdGhpcy5zZW5kQnRuLmVtcHR5KCk7XG4gICAgICBjb25zdCB3cmFwID0gdGhpcy5zZW5kQnRuLmNyZWF0ZURpdih7IGNsczogJ29jbGF3LXN0b3Atd3JhcCcgfSk7XG4gICAgICB3cmFwLmNyZWF0ZURpdih7IGNsczogJ29jbGF3LXNwaW5uZXItcmluZycsIGF0dHI6IHsgJ2FyaWEtaGlkZGVuJzogJ3RydWUnIH0gfSk7XG4gICAgICB3cmFwLmNyZWF0ZURpdih7IGNsczogJ29jbGF3LXN0b3AtaWNvbicsIGF0dHI6IHsgJ2FyaWEtaGlkZGVuJzogJ3RydWUnIH0gfSk7XG4gICAgfSBlbHNlIHtcbiAgICAgIC8vIFJlc3RvcmUgbGFiZWxcbiAgICAgIHRoaXMuc2VuZEJ0bi5zZXRUZXh0KCdTZW5kJyk7XG4gICAgfVxuICB9XG5cbiAgLy8gXHUyNTAwXHUyNTAwIFNlbmQgaGFuZGxlciBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcblxuICBwcml2YXRlIGFzeW5jIF9oYW5kbGVTZW5kKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIC8vIFdoaWxlIHdvcmtpbmcsIHRoZSBidXR0b24gYmVjb21lcyBTdG9wLlxuICAgIGlmICh0aGlzLmlzV29ya2luZykge1xuICAgICAgY29uc3Qgb2sgPSBhd2FpdCB0aGlzLnBsdWdpbi53c0NsaWVudC5hYm9ydEFjdGl2ZVJ1bigpO1xuICAgICAgaWYgKCFvaykge1xuICAgICAgICBuZXcgTm90aWNlKCdPcGVuQ2xhdyBDaGF0OiBmYWlsZWQgdG8gc3RvcCcpO1xuICAgICAgICB0aGlzLmNoYXRNYW5hZ2VyLmFkZE1lc3NhZ2UoQ2hhdE1hbmFnZXIuY3JlYXRlU3lzdGVtTWVzc2FnZSgnXHUyNkEwIFN0b3AgZmFpbGVkJywgJ2Vycm9yJykpO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgdGhpcy5jaGF0TWFuYWdlci5hZGRNZXNzYWdlKENoYXRNYW5hZ2VyLmNyZWF0ZVN5c3RlbU1lc3NhZ2UoJ1x1MjZENCBTdG9wcGVkJywgJ2luZm8nKSk7XG4gICAgICB9XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgY29uc3QgdGV4dCA9IHRoaXMuaW5wdXRFbC52YWx1ZS50cmltKCk7XG4gICAgaWYgKCF0ZXh0KSByZXR1cm47XG5cbiAgICAvLyBCdWlsZCBtZXNzYWdlIHdpdGggY29udGV4dCBpZiBlbmFibGVkXG4gICAgbGV0IG1lc3NhZ2UgPSB0ZXh0O1xuICAgIGlmICh0aGlzLmluY2x1ZGVOb3RlQ2hlY2tib3guY2hlY2tlZCkge1xuICAgICAgY29uc3Qgbm90ZSA9IGF3YWl0IGdldEFjdGl2ZU5vdGVDb250ZXh0KHRoaXMuYXBwKTtcbiAgICAgIGlmIChub3RlKSB7XG4gICAgICAgIG1lc3NhZ2UgPSBgQ29udGV4dDogW1ske25vdGUudGl0bGV9XV1cXG5cXG4ke3RleHR9YDtcbiAgICAgIH1cbiAgICB9XG5cbiAgICAvLyBBZGQgdXNlciBtZXNzYWdlIHRvIGNoYXQgVUlcbiAgICBjb25zdCB1c2VyTXNnID0gQ2hhdE1hbmFnZXIuY3JlYXRlVXNlck1lc3NhZ2UodGV4dCk7XG4gICAgdGhpcy5jaGF0TWFuYWdlci5hZGRNZXNzYWdlKHVzZXJNc2cpO1xuXG4gICAgLy8gQ2xlYXIgaW5wdXRcbiAgICB0aGlzLmlucHV0RWwudmFsdWUgPSAnJztcbiAgICB0aGlzLmlucHV0RWwuc3R5bGUuaGVpZ2h0ID0gJ2F1dG8nO1xuXG4gICAgLy8gU2VuZCBvdmVyIFdTIChhc3luYylcbiAgICB0cnkge1xuICAgICAgYXdhaXQgdGhpcy5wbHVnaW4ud3NDbGllbnQuc2VuZE1lc3NhZ2UobWVzc2FnZSk7XG4gICAgfSBjYXRjaCAoZXJyKSB7XG4gICAgICBjb25zb2xlLmVycm9yKCdbb2NsYXddIFNlbmQgZmFpbGVkJywgZXJyKTtcbiAgICAgIG5ldyBOb3RpY2UoYE9wZW5DbGF3IENoYXQ6IHNlbmQgZmFpbGVkICgke1N0cmluZyhlcnIpfSlgKTtcbiAgICAgIHRoaXMuY2hhdE1hbmFnZXIuYWRkTWVzc2FnZShcbiAgICAgICAgQ2hhdE1hbmFnZXIuY3JlYXRlU3lzdGVtTWVzc2FnZShgXHUyNkEwIFNlbmQgZmFpbGVkOiAke2Vycn1gLCAnZXJyb3InKVxuICAgICAgKTtcbiAgICB9XG4gIH1cbn1cbiIsICJpbXBvcnQgdHlwZSB7IFBhdGhNYXBwaW5nIH0gZnJvbSAnLi90eXBlcyc7XG5cbmV4cG9ydCBmdW5jdGlvbiBub3JtYWxpemVCYXNlKGJhc2U6IHN0cmluZyk6IHN0cmluZyB7XG4gIGNvbnN0IHRyaW1tZWQgPSBTdHJpbmcoYmFzZSA/PyAnJykudHJpbSgpO1xuICBpZiAoIXRyaW1tZWQpIHJldHVybiAnJztcbiAgcmV0dXJuIHRyaW1tZWQuZW5kc1dpdGgoJy8nKSA/IHRyaW1tZWQgOiBgJHt0cmltbWVkfS9gO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gdHJ5TWFwUmVtb3RlUGF0aFRvVmF1bHRQYXRoKGlucHV0OiBzdHJpbmcsIG1hcHBpbmdzOiByZWFkb25seSBQYXRoTWFwcGluZ1tdKTogc3RyaW5nIHwgbnVsbCB7XG4gIGNvbnN0IHJhdyA9IFN0cmluZyhpbnB1dCA/PyAnJyk7XG4gIGZvciAoY29uc3Qgcm93IG9mIG1hcHBpbmdzKSB7XG4gICAgY29uc3QgcmVtb3RlQmFzZSA9IG5vcm1hbGl6ZUJhc2Uocm93LnJlbW90ZUJhc2UpO1xuICAgIGNvbnN0IHZhdWx0QmFzZSA9IG5vcm1hbGl6ZUJhc2Uocm93LnZhdWx0QmFzZSk7XG4gICAgaWYgKCFyZW1vdGVCYXNlIHx8ICF2YXVsdEJhc2UpIGNvbnRpbnVlO1xuXG4gICAgaWYgKHJhdy5zdGFydHNXaXRoKHJlbW90ZUJhc2UpKSB7XG4gICAgICBjb25zdCByZXN0ID0gcmF3LnNsaWNlKHJlbW90ZUJhc2UubGVuZ3RoKTtcbiAgICAgIC8vIE9ic2lkaWFuIHBhdGhzIGFyZSB2YXVsdC1yZWxhdGl2ZSBhbmQgc2hvdWxkIG5vdCBzdGFydCB3aXRoICcvJ1xuICAgICAgcmV0dXJuIGAke3ZhdWx0QmFzZX0ke3Jlc3R9YC5yZXBsYWNlKC9eXFwvKy8sICcnKTtcbiAgICB9XG4gIH1cbiAgcmV0dXJuIG51bGw7XG59XG5cbmV4cG9ydCB0eXBlIENhbmRpZGF0ZSA9IHsgc3RhcnQ6IG51bWJlcjsgZW5kOiBudW1iZXI7IHJhdzogc3RyaW5nOyBraW5kOiAndXJsJyB8ICdwYXRoJyB9O1xuXG4vLyBDb25zZXJ2YXRpdmUgZXh0cmFjdGlvbjogYWltIHRvIGF2b2lkIGZhbHNlIHBvc2l0aXZlcy5cbmNvbnN0IFVSTF9SRSA9IC9odHRwcz86XFwvXFwvW15cXHM8PigpXSsvZztcbi8vIEFic29sdXRlIHVuaXgtaXNoIHBhdGhzLlxuLy8gKFdlIHN0aWxsIGV4aXN0ZW5jZS1jaGVjayBiZWZvcmUgcHJvZHVjaW5nIGEgbGluay4pXG5jb25zdCBQQVRIX1JFID0gLyg/PCFbQS1aYS16MC05Ll8tXSkoPzpcXC9bQS1aYS16MC05Ll9+ISQmJygpKissOz06QCVcXC1dKykrKD86XFwuW0EtWmEtejAtOS5fLV0rKT8vZztcblxuLy8gQ29uc2VydmF0aXZlIHJlbGF0aXZlIHBhdGhzIHdpdGggYXQgbGVhc3Qgb25lICcvJywgZS5nLiBjb21wZW5nL3BsYW5zL3gubWRcbi8vIEF2b2lkcyBtYXRjaGluZyBzY2hlbWUtbGlrZSB0b2tlbnMgdmlhIG5lZ2F0aXZlIGxvb2thaGVhZCBmb3IgJzovLycuXG5jb25zdCBSRUxfUEFUSF9SRSA9IC9cXGIoPyFbQS1aYS16XVtBLVphLXowLTkrLi1dKjpcXC9cXC8pW0EtWmEtejAtOS5fLV0rKD86XFwvW0EtWmEtejAtOS5fLV0rKSsoPzpcXC5bQS1aYS16MC05Ll8tXSspP1xcYi9nO1xuXG5leHBvcnQgZnVuY3Rpb24gZXh0cmFjdENhbmRpZGF0ZXModGV4dDogc3RyaW5nKTogQ2FuZGlkYXRlW10ge1xuICBjb25zdCB0ID0gU3RyaW5nKHRleHQgPz8gJycpO1xuICBjb25zdCBvdXQ6IENhbmRpZGF0ZVtdID0gW107XG5cbiAgZm9yIChjb25zdCBtIG9mIHQubWF0Y2hBbGwoVVJMX1JFKSkge1xuICAgIGlmIChtLmluZGV4ID09PSB1bmRlZmluZWQpIGNvbnRpbnVlO1xuICAgIG91dC5wdXNoKHsgc3RhcnQ6IG0uaW5kZXgsIGVuZDogbS5pbmRleCArIG1bMF0ubGVuZ3RoLCByYXc6IG1bMF0sIGtpbmQ6ICd1cmwnIH0pO1xuICB9XG5cbiAgZm9yIChjb25zdCBtIG9mIHQubWF0Y2hBbGwoUEFUSF9SRSkpIHtcbiAgICBpZiAobS5pbmRleCA9PT0gdW5kZWZpbmVkKSBjb250aW51ZTtcblxuICAgIC8vIFNraXAgaWYgdGhpcyBpcyBpbnNpZGUgYSBVUkwgd2UgYWxyZWFkeSBjYXB0dXJlZC5cbiAgICBjb25zdCBzdGFydCA9IG0uaW5kZXg7XG4gICAgY29uc3QgZW5kID0gc3RhcnQgKyBtWzBdLmxlbmd0aDtcbiAgICBjb25zdCBvdmVybGFwc1VybCA9IG91dC5zb21lKChjKSA9PiBjLmtpbmQgPT09ICd1cmwnICYmICEoZW5kIDw9IGMuc3RhcnQgfHwgc3RhcnQgPj0gYy5lbmQpKTtcbiAgICBpZiAob3ZlcmxhcHNVcmwpIGNvbnRpbnVlO1xuXG4gICAgb3V0LnB1c2goeyBzdGFydCwgZW5kLCByYXc6IG1bMF0sIGtpbmQ6ICdwYXRoJyB9KTtcbiAgfVxuXG4gIGZvciAoY29uc3QgbSBvZiB0Lm1hdGNoQWxsKFJFTF9QQVRIX1JFKSkge1xuICAgIGlmIChtLmluZGV4ID09PSB1bmRlZmluZWQpIGNvbnRpbnVlO1xuXG4gICAgY29uc3Qgc3RhcnQgPSBtLmluZGV4O1xuICAgIGNvbnN0IGVuZCA9IHN0YXJ0ICsgbVswXS5sZW5ndGg7XG4gICAgY29uc3Qgb3ZlcmxhcHNFeGlzdGluZyA9IG91dC5zb21lKChjKSA9PiAhKGVuZCA8PSBjLnN0YXJ0IHx8IHN0YXJ0ID49IGMuZW5kKSk7XG4gICAgaWYgKG92ZXJsYXBzRXhpc3RpbmcpIGNvbnRpbnVlO1xuXG4gICAgb3V0LnB1c2goeyBzdGFydCwgZW5kLCByYXc6IG1bMF0sIGtpbmQ6ICdwYXRoJyB9KTtcbiAgfVxuXG4gIC8vIFNvcnQgYW5kIGRyb3Agb3ZlcmxhcHMgKHByZWZlciBVUkxzKS5cbiAgb3V0LnNvcnQoKGEsIGIpID0+IGEuc3RhcnQgLSBiLnN0YXJ0IHx8IChhLmtpbmQgPT09ICd1cmwnID8gLTEgOiAxKSk7XG4gIGNvbnN0IGRlZHVwOiBDYW5kaWRhdGVbXSA9IFtdO1xuICBmb3IgKGNvbnN0IGMgb2Ygb3V0KSB7XG4gICAgY29uc3QgbGFzdCA9IGRlZHVwW2RlZHVwLmxlbmd0aCAtIDFdO1xuICAgIGlmICghbGFzdCkge1xuICAgICAgZGVkdXAucHVzaChjKTtcbiAgICAgIGNvbnRpbnVlO1xuICAgIH1cbiAgICBpZiAoYy5zdGFydCA8IGxhc3QuZW5kKSBjb250aW51ZTtcbiAgICBkZWR1cC5wdXNoKGMpO1xuICB9XG5cbiAgcmV0dXJuIGRlZHVwO1xufVxuIiwgImltcG9ydCB0eXBlIHsgQXBwIH0gZnJvbSAnb2JzaWRpYW4nO1xuXG5leHBvcnQgaW50ZXJmYWNlIE5vdGVDb250ZXh0IHtcbiAgdGl0bGU6IHN0cmluZztcbiAgcGF0aDogc3RyaW5nO1xuICBjb250ZW50OiBzdHJpbmc7XG59XG5cbi8qKlxuICogUmV0dXJucyB0aGUgYWN0aXZlIG5vdGUncyB0aXRsZSBhbmQgY29udGVudCwgb3IgbnVsbCBpZiBubyBub3RlIGlzIG9wZW4uXG4gKiBBc3luYyBiZWNhdXNlIHZhdWx0LnJlYWQoKSBpcyBhc3luYy5cbiAqL1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGdldEFjdGl2ZU5vdGVDb250ZXh0KGFwcDogQXBwKTogUHJvbWlzZTxOb3RlQ29udGV4dCB8IG51bGw+IHtcbiAgY29uc3QgZmlsZSA9IGFwcC53b3Jrc3BhY2UuZ2V0QWN0aXZlRmlsZSgpO1xuICBpZiAoIWZpbGUpIHJldHVybiBudWxsO1xuXG4gIHRyeSB7XG4gICAgY29uc3QgY29udGVudCA9IGF3YWl0IGFwcC52YXVsdC5yZWFkKGZpbGUpO1xuICAgIHJldHVybiB7XG4gICAgICB0aXRsZTogZmlsZS5iYXNlbmFtZSxcbiAgICAgIHBhdGg6IGZpbGUucGF0aCxcbiAgICAgIGNvbnRlbnQsXG4gICAgfTtcbiAgfSBjYXRjaCAoZXJyKSB7XG4gICAgY29uc29sZS5lcnJvcignW29jbGF3LWNvbnRleHRdIEZhaWxlZCB0byByZWFkIGFjdGl2ZSBub3RlJywgZXJyKTtcbiAgICByZXR1cm4gbnVsbDtcbiAgfVxufVxuIiwgIi8qKiBQZXJzaXN0ZWQgcGx1Z2luIGNvbmZpZ3VyYXRpb24gKi9cbmV4cG9ydCBpbnRlcmZhY2UgT3BlbkNsYXdTZXR0aW5ncyB7XG4gIC8qKiBXZWJTb2NrZXQgVVJMIG9mIHRoZSBPcGVuQ2xhdyBHYXRld2F5IChlLmcuIHdzOi8vMTAwLjkwLjkuNjg6MTg3ODkpICovXG4gIGdhdGV3YXlVcmw6IHN0cmluZztcbiAgLyoqIEF1dGggdG9rZW4gXHUyMDE0IG11c3QgbWF0Y2ggdGhlIGNoYW5uZWwgcGx1Z2luJ3MgYXV0aFRva2VuICovXG4gIGF1dGhUb2tlbjogc3RyaW5nO1xuICAvKiogT3BlbkNsYXcgc2Vzc2lvbiBrZXkgdG8gc3Vic2NyaWJlIHRvIChlLmcuIFwibWFpblwiKSAqL1xuICBzZXNzaW9uS2V5OiBzdHJpbmc7XG4gIC8qKiAoRGVwcmVjYXRlZCkgT3BlbkNsYXcgYWNjb3VudCBJRCAodW51c2VkOyBjaGF0LnNlbmQgdXNlcyBzZXNzaW9uS2V5KSAqL1xuICBhY2NvdW50SWQ6IHN0cmluZztcbiAgLyoqIFdoZXRoZXIgdG8gaW5jbHVkZSB0aGUgYWN0aXZlIG5vdGUgY29udGVudCB3aXRoIGVhY2ggbWVzc2FnZSAqL1xuICBpbmNsdWRlQWN0aXZlTm90ZTogYm9vbGVhbjtcbiAgLyoqIFJlbmRlciBhc3Npc3RhbnQgb3V0cHV0IGFzIE1hcmtkb3duICh1bnNhZmU6IG1heSB0cmlnZ2VyIGVtYmVkcy9wb3N0LXByb2Nlc3NvcnMpOyBkZWZhdWx0IE9GRiAqL1xuICByZW5kZXJBc3Npc3RhbnRNYXJrZG93bjogYm9vbGVhbjtcbiAgLyoqIEFsbG93IHVzaW5nIGluc2VjdXJlIHdzOi8vIGZvciBub24tbG9jYWwgZ2F0ZXdheSBVUkxzICh1bnNhZmUpOyBkZWZhdWx0IE9GRiAqL1xuICBhbGxvd0luc2VjdXJlV3M6IGJvb2xlYW47XG5cbiAgLyoqIE9wdGlvbmFsOiBtYXAgcmVtb3RlIEZTIHBhdGhzIC8gZXhwb3J0ZWQgcGF0aHMgYmFjayB0byB2YXVsdC1yZWxhdGl2ZSBwYXRocyAqL1xuICBwYXRoTWFwcGluZ3M6IFBhdGhNYXBwaW5nW107XG59XG5cbmV4cG9ydCB0eXBlIFBhdGhNYXBwaW5nID0ge1xuICAvKiogVmF1bHQtcmVsYXRpdmUgYmFzZSBwYXRoIChlLmcuIFwiZG9jcy9cIiBvciBcImNvbXBlbmcvXCIpICovXG4gIHZhdWx0QmFzZTogc3RyaW5nO1xuICAvKiogUmVtb3RlIEZTIGJhc2UgcGF0aCAoZS5nLiBcIi9ob21lL3dhbGwtZS8ub3BlbmNsYXcvd29ya3NwYWNlL2RvY3MvXCIpICovXG4gIHJlbW90ZUJhc2U6IHN0cmluZztcbn07XG5cbmV4cG9ydCBjb25zdCBERUZBVUxUX1NFVFRJTkdTOiBPcGVuQ2xhd1NldHRpbmdzID0ge1xuICBnYXRld2F5VXJsOiAnd3M6Ly9sb2NhbGhvc3Q6MTg3ODknLFxuICBhdXRoVG9rZW46ICcnLFxuICBzZXNzaW9uS2V5OiAnbWFpbicsXG4gIGFjY291bnRJZDogJ21haW4nLFxuICBpbmNsdWRlQWN0aXZlTm90ZTogZmFsc2UsXG4gIHJlbmRlckFzc2lzdGFudE1hcmtkb3duOiBmYWxzZSxcbiAgYWxsb3dJbnNlY3VyZVdzOiBmYWxzZSxcbiAgcGF0aE1hcHBpbmdzOiBbXSxcbn07XG5cbi8qKiBBIHNpbmdsZSBjaGF0IG1lc3NhZ2UgKi9cbmV4cG9ydCBpbnRlcmZhY2UgQ2hhdE1lc3NhZ2Uge1xuICBpZDogc3RyaW5nO1xuICByb2xlOiAndXNlcicgfCAnYXNzaXN0YW50JyB8ICdzeXN0ZW0nO1xuICAvKiogT3B0aW9uYWwgc2V2ZXJpdHkgZm9yIHN5c3RlbS9zdGF0dXMgbWVzc2FnZXMgKi9cbiAgbGV2ZWw/OiAnaW5mbycgfCAnZXJyb3InO1xuICBjb250ZW50OiBzdHJpbmc7XG4gIHRpbWVzdGFtcDogbnVtYmVyO1xufVxuXG4vKiogUGF5bG9hZCBmb3IgbWVzc2FnZXMgU0VOVCB0byB0aGUgc2VydmVyIChvdXRib3VuZCkgKi9cbmV4cG9ydCBpbnRlcmZhY2UgV1NQYXlsb2FkIHtcbiAgdHlwZTogJ2F1dGgnIHwgJ21lc3NhZ2UnIHwgJ3BpbmcnIHwgJ3BvbmcnIHwgJ2Vycm9yJztcbiAgcGF5bG9hZD86IFJlY29yZDxzdHJpbmcsIHVua25vd24+O1xufVxuXG4vKiogTWVzc2FnZXMgUkVDRUlWRUQgZnJvbSB0aGUgc2VydmVyIChpbmJvdW5kKSBcdTIwMTQgZGlzY3JpbWluYXRlZCB1bmlvbiAqL1xuZXhwb3J0IHR5cGUgSW5ib3VuZFdTUGF5bG9hZCA9XG4gIHwgeyB0eXBlOiAnbWVzc2FnZSc7IHBheWxvYWQ6IHsgY29udGVudDogc3RyaW5nOyByb2xlOiBzdHJpbmc7IHRpbWVzdGFtcDogbnVtYmVyIH0gfVxuICB8IHsgdHlwZTogJ2Vycm9yJzsgcGF5bG9hZDogeyBtZXNzYWdlOiBzdHJpbmcgfSB9O1xuXG4vKiogQXZhaWxhYmxlIGFnZW50cyAvIG1vZGVscyAqL1xuZXhwb3J0IGludGVyZmFjZSBBZ2VudE9wdGlvbiB7XG4gIGlkOiBzdHJpbmc7XG4gIGxhYmVsOiBzdHJpbmc7XG59XG4iXSwKICAibWFwcGluZ3MiOiAiOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUEsSUFBQUEsbUJBQThDOzs7QUNBOUMsc0JBQStDO0FBR3hDLElBQU0scUJBQU4sY0FBaUMsaUNBQWlCO0FBQUEsRUFHdkQsWUFBWSxLQUFVLFFBQXdCO0FBQzVDLFVBQU0sS0FBSyxNQUFNO0FBQ2pCLFNBQUssU0FBUztBQUFBLEVBQ2hCO0FBQUEsRUFFQSxVQUFnQjtBQVhsQjtBQVlJLFVBQU0sRUFBRSxZQUFZLElBQUk7QUFDeEIsZ0JBQVksTUFBTTtBQUVsQixnQkFBWSxTQUFTLE1BQU0sRUFBRSxNQUFNLGdDQUEyQixDQUFDO0FBRS9ELFFBQUksd0JBQVEsV0FBVyxFQUNwQixRQUFRLGFBQWEsRUFDckIsUUFBUSxtRUFBbUUsRUFDM0U7QUFBQSxNQUFRLENBQUMsU0FDUixLQUNHLGVBQWUsc0JBQXNCLEVBQ3JDLFNBQVMsS0FBSyxPQUFPLFNBQVMsVUFBVSxFQUN4QyxTQUFTLENBQU8sVUFBVTtBQUN6QixhQUFLLE9BQU8sU0FBUyxhQUFhLE1BQU0sS0FBSztBQUM3QyxjQUFNLEtBQUssT0FBTyxhQUFhO0FBQUEs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S0FBSyxrQkFBa0I7QUFDbkMsWUFBTSxLQUFLLFNBQVMsSUFBSTtBQUFBLElBQzFCO0FBQUE7QUFBQTtBQUFBLEVBSVEsYUFBbUI7QUFDekIsU0FBSyxTQUFTLFFBQVEsS0FBSyxTQUFTLFlBQVksS0FBSyxTQUFTLFdBQVc7QUFBQSxNQUN2RSxpQkFBaUIsS0FBSyxTQUFTO0FBQUEsSUFDakMsQ0FBQztBQUFBLEVBQ0g7QUFBQSxFQUVjLG9CQUFtQztBQUFBO0FBQy9DLFlBQU0sRUFBRSxVQUFVLElBQUksS0FBSztBQUczQixZQUFNLFdBQVcsVUFBVSxnQkFBZ0IsdUJBQXVCO0FBQ2xFLFVBQUksU0FBUyxTQUFTLEdBQUc7QUFDdkIsa0JBQVUsV0FBVyxTQUFTLENBQUMsQ0FBQztBQUNoQztBQUFBLE1BQ0Y7QUFHQSxZQUFNLE9BQU8sVUFBVSxhQUFhLEtBQUs7QUFDekMsVUFBSSxDQUFDO0FBQU07QUFDWCxZQUFNLEtBQUssYUFBYSxFQUFFLE1BQU0seUJBQXlCLFFBQVEsS0FBSyxDQUFDO0FBQ3ZFLGdCQUFVLFdBQVcsSUFBSTtBQUFBLElBQzNCO0FBQUE7QUFDRjsiLAogICJuYW1lcyI6IFsiaW1wb3J0X29ic2lkaWFuIiwgIl9hIiwgImltcG9ydF9vYnNpZGlhbiIsICJtYXBwZWQiXQp9Cg==
