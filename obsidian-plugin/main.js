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
  setSessionKey(sessionKey) {
    this.sessionKey = sessionKey.trim();
    this.activeRunId = null;
    this.abortInFlight = null;
    this._setWorking(false);
  }
  // NOTE: canonical Obsidian session keys do not require gateway sessions.list for core UX.
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
  static createSessionDivider(sessionKey) {
    const short = sessionKey.length > 28 ? `${sessionKey.slice(0, 12)}\u2026${sessionKey.slice(-12)}` : sessionKey;
    return {
      id: `div-${Date.now()}`,
      role: "system",
      level: "info",
      kind: "session-divider",
      title: sessionKey,
      content: `[Session: ${short}]`,
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
var NewSessionModal = class extends import_obsidian2.Modal {
  constructor(view, initialValue, onSubmit) {
    super(view.app);
    this.initialValue = initialValue;
    this.onSubmit = onSubmit;
  }
  onOpen() {
    const { contentEl } = this;
    contentEl.empty();
    contentEl.createEl("h3", { text: "New session key" });
    let value = this.initialValue;
    new import_obsidian2.Setting(contentEl).setName("Session key").setDesc("Tip: choose a short suffix; it will become agent:main:obsidian:direct:<vaultHash>-<suffix>.").addText((t) => {
      t.setValue(value);
      t.onChange((v) => {
        value = v;
      });
    });
    new import_obsidian2.Setting(contentEl).addButton((b) => {
      b.setButtonText("Cancel");
      b.onClick(() => this.close());
    }).addButton((b) => {
      b.setCta();
      b.setButtonText("Create");
      b.onClick(() => {
        const v = value.trim().toLowerCase();
        if (!v) {
          new import_obsidian2.Notice("Suffix cannot be empty");
          return;
        }
        if (!/^[a-z0-9][a-z0-9_-]{0,63}$/.test(v)) {
          new import_obsidian2.Notice("Use letters/numbers/_/- only (max 64 chars)");
          return;
        }
        this.onSubmit(v);
        this.close();
      });
    });
  }
};
var OpenClawChatView = class extends import_obsidian2.ItemView {
  constructor(leaf, plugin) {
    super(leaf);
    // State
    this.isConnected = false;
    this.isWorking = false;
    // Connection notices (avoid spam)
    this.lastConnNoticeAtMs = 0;
    this.lastGatewayState = null;
    this.suppressSessionSelectChange = false;
    this.onMessagesClick = null;
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
      this._loadKnownSessions();
    });
  }
  onClose() {
    return __async(this, null, function* () {
      var _a;
      this.chatManager.onUpdate = null;
      this.chatManager.onMessageAdded = null;
      this.plugin.wsClient.onStateChange = null;
      this.plugin.wsClient.onWorkingChange = null;
      if (this.onMessagesClick) {
        (_a = this.messagesEl) == null ? void 0 : _a.removeEventListener("click", this.onMessagesClick);
        this.onMessagesClick = null;
      }
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
    const sessRow = root.createDiv({ cls: "oclaw-session-row" });
    sessRow.createSpan({ cls: "oclaw-session-label", text: "Session" });
    this.sessionSelect = sessRow.createEl("select", { cls: "oclaw-session-select" });
    this.sessionRefreshBtn = sessRow.createEl("button", { cls: "oclaw-session-btn", text: "Reload" });
    this.sessionNewBtn = sessRow.createEl("button", { cls: "oclaw-session-btn", text: "New\u2026" });
    this.sessionMainBtn = sessRow.createEl("button", { cls: "oclaw-session-btn", text: "Main" });
    this.sessionRefreshBtn.addEventListener("click", () => this._loadKnownSessions());
    this.sessionNewBtn.addEventListener("click", () => void this._promptNewSession());
    this.sessionMainBtn.addEventListener("click", () => {
      void (() => __async(this, null, function* () {
        yield this.plugin.switchSession("main");
        this._loadKnownSessions();
        this.sessionSelect.value = "main";
        this.sessionSelect.title = "main";
      }))();
    });
    this.sessionSelect.addEventListener("change", () => {
      if (this.suppressSessionSelectChange)
        return;
      const next = this.sessionSelect.value;
      if (!next || next === this.plugin.settings.sessionKey)
        return;
      void (() => __async(this, null, function* () {
        yield this.plugin.switchSession(next);
        this._loadKnownSessions();
        this.sessionSelect.value = next;
        this.sessionSelect.title = next;
      }))();
    });
    this.messagesEl = root.createDiv({ cls: "oclaw-messages" });
    this._installInternalLinkDelegation();
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
  _setSessionSelectOptions(keys) {
    var _a;
    this.suppressSessionSelectChange = true;
    try {
      this.sessionSelect.empty();
      const current = ((_a = this.plugin.settings.sessionKey) != null ? _a : "main").toLowerCase();
      let unique = Array.from(new Set([current, ...keys].filter(Boolean)));
      unique = unique.filter((k) => k === "main" || String(k).startsWith("agent:main:obsidian:direct:"));
      if (unique.length === 0) {
        unique = ["main"];
      }
      for (const key of unique) {
        const opt = this.sessionSelect.createEl("option", { value: key, text: key });
        if (key === current)
          opt.selected = true;
      }
      if (unique.includes(current)) {
        this.sessionSelect.value = current;
      }
      this.sessionSelect.title = current;
    } finally {
      this.suppressSessionSelectChange = false;
    }
  }
  _loadKnownSessions() {
    var _a, _b;
    const vaultHash = ((_a = this.plugin.settings.vaultHash) != null ? _a : "").trim();
    const map = (_b = this.plugin.settings.knownSessionKeysByVault) != null ? _b : {};
    const keys = vaultHash && Array.isArray(map[vaultHash]) ? map[vaultHash] : [];
    this._setSessionSelectOptions(keys);
  }
  _promptNewSession() {
    return __async(this, null, function* () {
      const now = /* @__PURE__ */ new Date();
      const pad = (n) => String(n).padStart(2, "0");
      const suggested = `chat-${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}-${pad(now.getHours())}${pad(now.getMinutes())}`;
      const modal = new NewSessionModal(this, suggested, (suffix) => {
        var _a;
        const vaultHash = ((_a = this.plugin.settings.vaultHash) != null ? _a : "").trim();
        if (!vaultHash) {
          new import_obsidian2.Notice("OpenClaw Chat: cannot create session (missing vault identity).");
          return;
        }
        const key = `agent:main:obsidian:direct:${vaultHash}-${suffix}`;
        void (() => __async(this, null, function* () {
          yield this.plugin.switchSession(key);
          this._loadKnownSessions();
          this.sessionSelect.value = key;
          this.sessionSelect.title = key;
        }))();
      });
      modal.open();
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
    const kindClass = msg.kind ? ` oclaw-${msg.kind}` : "";
    const el = this.messagesEl.createDiv({ cls: `oclaw-message ${msg.role}${levelClass}${kindClass}` });
    const body = el.createDiv({ cls: "oclaw-message-body" });
    if (msg.title) {
      body.title = msg.title;
    }
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
  _installInternalLinkDelegation() {
    if (this.onMessagesClick)
      return;
    this.onMessagesClick = (ev) => {
      var _a;
      const target = ev.target;
      const a = (_a = target == null ? void 0 : target.closest) == null ? void 0 : _a.call(target, "a.internal-link");
      if (!a)
        return;
      const dataHref = a.getAttribute("data-href") || "";
      const hrefAttr = a.getAttribute("href") || "";
      const raw = (dataHref || hrefAttr).trim();
      if (!raw)
        return;
      if (/^https?:\/\//i.test(raw))
        return;
      const vaultPath = raw.replace(/^\/+/, "");
      const f = this.app.vault.getAbstractFileByPath(vaultPath);
      if (!(f instanceof import_obsidian2.TFile))
        return;
      ev.preventDefault();
      ev.stopPropagation();
      void this.app.workspace.getLeaf(true).openFile(f);
    };
    this.messagesEl.addEventListener("click", this.onMessagesClick);
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
  pathMappings: [],
  vaultHash: void 0,
  knownSessionKeysByVault: {},
  legacySessionKeys: []
};

// src/main.ts
var OpenClawPlugin = class extends import_obsidian3.Plugin {
  constructor() {
    super(...arguments);
    this._vaultHash = null;
    this._deviceIdentityKey = "_openclawDeviceIdentityV1";
  }
  _computeVaultHash() {
    try {
      const adapter = this.app.vault.adapter;
      if (adapter instanceof import_obsidian3.FileSystemAdapter) {
        const basePath = adapter.getBasePath();
        if (basePath) {
          const crypto2 = require("crypto");
          const hex = crypto2.createHash("sha256").update(basePath, "utf8").digest("hex");
          return hex.slice(0, 16);
        }
      }
    } catch (e) {
    }
    return null;
  }
  _canonicalVaultSessionKey(vaultHash) {
    return `agent:main:obsidian:direct:${vaultHash}`;
  }
  switchSession(sessionKey) {
    return __async(this, null, function* () {
      var _a;
      const next = sessionKey.trim().toLowerCase();
      if (!next) {
        new import_obsidian3.Notice("OpenClaw Chat: session key cannot be empty.");
        return;
      }
      if (!(next === "main" || next.startsWith("agent:main:obsidian:direct:"))) {
        new import_obsidian3.Notice("OpenClaw Chat: only main or agent:main:obsidian:direct:* sessions are allowed.");
        return;
      }
      try {
        yield this.wsClient.abortActiveRun();
      } catch (e) {
      }
      this.chatManager.addMessage(ChatManager.createSessionDivider(next));
      this.settings.sessionKey = next;
      if (this._vaultHash) {
        const map = (_a = this.settings.knownSessionKeysByVault) != null ? _a : {};
        const cur = Array.isArray(map[this._vaultHash]) ? map[this._vaultHash] : [];
        const nextList = [next, ...cur.filter((k) => k && k !== next)].slice(0, 20);
        map[this._vaultHash] = nextList;
        this.settings.knownSessionKeysByVault = map;
      }
      yield this.saveSettings();
      this.wsClient.disconnect();
      this.wsClient.setSessionKey(next);
      if (this.settings.authToken) {
        this.wsClient.connect(this.settings.gatewayUrl, this.settings.authToken, {
          allowInsecureWs: this.settings.allowInsecureWs
        });
      }
    });
  }
  onload() {
    return __async(this, null, function* () {
      var _a, _b, _c;
      yield this.loadSettings();
      this._vaultHash = this._computeVaultHash();
      if (this._vaultHash) {
        this.settings.vaultHash = this._vaultHash;
        const canonical = this._canonicalVaultSessionKey(this._vaultHash);
        const existing = ((_a = this.settings.sessionKey) != null ? _a : "").trim().toLowerCase();
        const isLegacy = existing.startsWith("obsidian-");
        const isEmptyOrMain = !existing || existing === "main" || existing === "agent:main:main";
        if (isLegacy) {
          const legacy = Array.isArray(this.settings.legacySessionKeys) ? this.settings.legacySessionKeys : [];
          this.settings.legacySessionKeys = [existing, ...legacy.filter((k) => k && k !== existing)].slice(0, 20);
        }
        if (isLegacy || isEmptyOrMain) {
          this.settings.sessionKey = canonical;
        }
        const map = (_b = this.settings.knownSessionKeysByVault) != null ? _b : {};
        const cur = Array.isArray(map[this._vaultHash]) ? map[this._vaultHash] : [];
        if (!cur.includes(canonical)) {
          map[this._vaultHash] = [canonical, ...cur].slice(0, 20);
          this.settings.knownSessionKeysByVault = map;
        }
        yield this.saveSettings();
      }
      this.wsClient = new ObsidianWSClient(((_c = this.settings.sessionKey) != null ? _c : "main").toLowerCase(), {
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
        var _a2;
        if (msg.type === "message") {
          this.chatManager.addMessage(ChatManager.createAssistantMessage(msg.payload.content));
        } else if (msg.type === "error") {
          const errText = (_a2 = msg.payload.message) != null ? _a2 : "Unknown error from gateway";
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
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsic3JjL21haW4udHMiLCAic3JjL3NldHRpbmdzLnRzIiwgInNyYy93ZWJzb2NrZXQudHMiLCAic3JjL2NoYXQudHMiLCAic3JjL3ZpZXcudHMiLCAic3JjL2xpbmtpZnkudHMiLCAic3JjL2NvbnRleHQudHMiLCAic3JjL3R5cGVzLnRzIl0sCiAgInNvdXJjZXNDb250ZW50IjogWyJpbXBvcnQgeyBGaWxlU3lzdGVtQWRhcHRlciwgTm90aWNlLCBQbHVnaW4sIFdvcmtzcGFjZUxlYWYgfSBmcm9tICdvYnNpZGlhbic7XG5pbXBvcnQgeyBPcGVuQ2xhd1NldHRpbmdUYWIgfSBmcm9tICcuL3NldHRpbmdzJztcbmltcG9ydCB7IE9ic2lkaWFuV1NDbGllbnQgfSBmcm9tICcuL3dlYnNvY2tldCc7XG5pbXBvcnQgeyBDaGF0TWFuYWdlciB9IGZyb20gJy4vY2hhdCc7XG5pbXBvcnQgeyBWSUVXX1RZUEVfT1BFTkNMQVdfQ0hBVCwgT3BlbkNsYXdDaGF0VmlldyB9IGZyb20gJy4vdmlldyc7XG5pbXBvcnQgeyBERUZBVUxUX1NFVFRJTkdTLCB0eXBlIE9wZW5DbGF3U2V0dGluZ3MgfSBmcm9tICcuL3R5cGVzJztcblxuZXhwb3J0IGRlZmF1bHQgY2xhc3MgT3BlbkNsYXdQbHVnaW4gZXh0ZW5kcyBQbHVnaW4ge1xuICBzZXR0aW5ncyE6IE9wZW5DbGF3U2V0dGluZ3M7XG4gIHdzQ2xpZW50ITogT2JzaWRpYW5XU0NsaWVudDtcbiAgY2hhdE1hbmFnZXIhOiBDaGF0TWFuYWdlcjtcblxuICBwcml2YXRlIF92YXVsdEhhc2g6IHN0cmluZyB8IG51bGwgPSBudWxsO1xuXG4gIHByaXZhdGUgX2NvbXB1dGVWYXVsdEhhc2goKTogc3RyaW5nIHwgbnVsbCB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IGFkYXB0ZXIgPSB0aGlzLmFwcC52YXVsdC5hZGFwdGVyO1xuICAgICAgLy8gRGVza3RvcCBvbmx5OiBGaWxlU3lzdGVtQWRhcHRlciBwcm92aWRlcyBhIHN0YWJsZSBiYXNlIHBhdGguXG4gICAgICBpZiAoYWRhcHRlciBpbnN0YW5jZW9mIEZpbGVTeXN0ZW1BZGFwdGVyKSB7XG4gICAgICAgIGNvbnN0IGJhc2VQYXRoID0gYWRhcHRlci5nZXRCYXNlUGF0aCgpO1xuICAgICAgICBpZiAoYmFzZVBhdGgpIHtcbiAgICAgICAgICAvLyBVc2UgTm9kZSBjcnlwdG8gKEVsZWN0cm9uIGVudmlyb25tZW50KS5cbiAgICAgICAgICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgQHR5cGVzY3JpcHQtZXNsaW50L25vLXZhci1yZXF1aXJlc1xuICAgICAgICAgIGNvbnN0IGNyeXB0byA9IHJlcXVpcmUoJ2NyeXB0bycpIGFzIHR5cGVvZiBpbXBvcnQoJ2NyeXB0bycpO1xuICAgICAgICAgIGNvbnN0IGhleCA9IGNyeXB0by5jcmVhdGVIYXNoKCdzaGEyNTYnKS51cGRhdGUoYmFzZVBhdGgsICd1dGY4JykuZGlnZXN0KCdoZXgnKTtcbiAgICAgICAgICByZXR1cm4gaGV4LnNsaWNlKDAsIDE2KTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0gY2F0Y2gge1xuICAgICAgLy8gaWdub3JlXG4gICAgfVxuICAgIHJldHVybiBudWxsO1xuICB9XG5cbiAgcHJpdmF0ZSBfY2Fub25pY2FsVmF1bHRTZXNzaW9uS2V5KHZhdWx0SGFzaDogc3RyaW5nKTogc3RyaW5nIHtcbiAgICByZXR1cm4gYGFnZW50Om1haW46b2JzaWRpYW46ZGlyZWN0OiR7dmF1bHRIYXNofWA7XG4gIH1cblxuICBhc3luYyBzd2l0Y2hTZXNzaW9uKHNlc3Npb25LZXk6IHN0cmluZyk6IFByb21pc2U8dm9pZD4ge1xuICAgIGNvbnN0IG5leHQgPSBzZXNzaW9uS2V5LnRyaW0oKS50b0xvd2VyQ2FzZSgpO1xuICAgIGlmICghbmV4dCkge1xuICAgICAgbmV3IE5vdGljZSgnT3BlbkNsYXcgQ2hhdDogc2Vzc2lvbiBrZXkgY2Fubm90IGJlIGVtcHR5LicpO1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIC8vIFNhZmV0eTogb25seSBhbGxvdyBtYWluIG9yIGNhbm9uaWNhbCBvYnNpZGlhbiBkaXJlY3Qgc2Vzc2lvbnMuXG4gICAgaWYgKCEobmV4dCA9PT0gJ21haW4nIHx8IG5leHQuc3RhcnRzV2l0aCgnYWdlbnQ6bWFpbjpvYnNpZGlhbjpkaXJlY3Q6JykpKSB7XG4gICAgICBuZXcgTm90aWNlKCdPcGVuQ2xhdyBDaGF0OiBvbmx5IG1haW4gb3IgYWdlbnQ6bWFpbjpvYnNpZGlhbjpkaXJlY3Q6KiBzZXNzaW9ucyBhcmUgYWxsb3dlZC4nKTtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICAvLyBBYm9ydCBhbnkgaW4tZmxpZ2h0IHJ1biBiZXN0LWVmZm9ydCAoYXZvaWQgbGVha2luZyBhIFwid29ya2luZ1wiIFVJIHN0YXRlKS5cbiAgICB0cnkge1xuICAgICAgYXdhaXQgdGhpcy53c0NsaWVudC5hYm9ydEFjdGl2ZVJ1bigpO1xuICAgIH0gY2F0Y2gge1xuICAgICAgLy8gaWdub3JlXG4gICAgfVxuXG4gICAgLy8gSW5zZXJ0IGRpdmlkZXIgYXQgdGhlIHN0YXJ0IG9mIHRoZSBuZXcgc2Vzc2lvbi5cbiAgICB0aGlzLmNoYXRNYW5hZ2VyLmFkZE1lc3NhZ2UoQ2hhdE1hbmFnZXIuY3JlYXRlU2Vzc2lvbkRpdmlkZXIobmV4dCkpO1xuXG4gICAgdGhpcy5zZXR0aW5ncy5zZXNzaW9uS2V5ID0gbmV4dDtcblxuICAgIC8vIFRyYWNrIGtub3duIHNlc3Npb25zIHBlciB2YXVsdCAodmF1bHQtc2NvcGVkKS5cbiAgICBpZiAodGhpcy5fdmF1bHRIYXNoKSB7XG4gICAgICBjb25zdCBtYXAgPSB0aGlzLnNldHRpbmdzLmtub3duU2Vzc2lvbktleXNCeVZhdWx0ID8/IHt9O1xuICAgICAgY29uc3QgY3VyID0gQXJyYXkuaXNBcnJheShtYXBbdGhpcy5fdmF1bHRIYXNoXSkgPyBtYXBbdGhpcy5fdmF1bHRIYXNoXSA6IFtdO1xuICAgICAgY29uc3QgbmV4dExpc3QgPSBbbmV4dCwgLi4uY3VyLmZpbHRlcigoaykgPT4gayAmJiBrICE9PSBuZXh0KV0uc2xpY2UoMCwgMjApO1xuICAgICAgbWFwW3RoaXMuX3ZhdWx0SGFzaF0gPSBuZXh0TGlzdDtcbiAgICAgIHRoaXMuc2V0dGluZ3Mua25vd25TZXNzaW9uS2V5c0J5VmF1bHQgPSBtYXA7XG4gICAgfVxuXG4gICAgYXdhaXQgdGhpcy5zYXZlU2V0dGluZ3MoKTtcblxuICAgIC8vIFJlY29ubmVjdCB3aXRoIHRoZSBuZXcgc2Vzc2lvbiBrZXkuXG4gICAgdGhpcy53c0NsaWVudC5kaXNjb25uZWN0KCk7XG4gICAgdGhpcy53c0NsaWVudC5zZXRTZXNzaW9uS2V5KG5leHQpO1xuXG4gICAgaWYgKHRoaXMuc2V0dGluZ3MuYXV0aFRva2VuKSB7XG4gICAgICB0aGlzLndzQ2xpZW50LmNvbm5lY3QodGhpcy5zZXR0aW5ncy5nYXRld2F5VXJsLCB0aGlzLnNldHRpbmdzLmF1dGhUb2tlbiwge1xuICAgICAgICBhbGxvd0luc2VjdXJlV3M6IHRoaXMuc2V0dGluZ3MuYWxsb3dJbnNlY3VyZVdzLFxuICAgICAgfSk7XG4gICAgfVxuICB9XG5cbiAgYXN5bmMgb25sb2FkKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIGF3YWl0IHRoaXMubG9hZFNldHRpbmdzKCk7XG5cbiAgICAvLyBDb21wdXRlIHZhdWx0IGhhc2ggKGRlc2t0b3ApIGFuZCBtaWdyYXRlIHRvIGNhbm9uaWNhbCBvYnNpZGlhbiBkaXJlY3Qgc2Vzc2lvbiBrZXkuXG4gICAgdGhpcy5fdmF1bHRIYXNoID0gdGhpcy5fY29tcHV0ZVZhdWx0SGFzaCgpO1xuICAgIGlmICh0aGlzLl92YXVsdEhhc2gpIHtcbiAgICAgIHRoaXMuc2V0dGluZ3MudmF1bHRIYXNoID0gdGhpcy5fdmF1bHRIYXNoO1xuXG4gICAgICBjb25zdCBjYW5vbmljYWwgPSB0aGlzLl9jYW5vbmljYWxWYXVsdFNlc3Npb25LZXkodGhpcy5fdmF1bHRIYXNoKTtcbiAgICAgIGNvbnN0IGV4aXN0aW5nID0gKHRoaXMuc2V0dGluZ3Muc2Vzc2lvbktleSA/PyAnJykudHJpbSgpLnRvTG93ZXJDYXNlKCk7XG4gICAgICBjb25zdCBpc0xlZ2FjeSA9IGV4aXN0aW5nLnN0YXJ0c1dpdGgoJ29ic2lkaWFuLScpO1xuICAgICAgY29uc3QgaXNFbXB0eU9yTWFpbiA9ICFleGlzdGluZyB8fCBleGlzdGluZyA9PT0gJ21haW4nIHx8IGV4aXN0aW5nID09PSAnYWdlbnQ6bWFpbjptYWluJztcblxuICAgICAgLy8gUmVtZW1iZXIgbGVnYWN5IGtleXMgZm9yIGRlYnVnZ2luZy9taWdyYXRpb24sIGJ1dCBkZWZhdWx0IHRvIGNhbm9uaWNhbC5cbiAgICAgIGlmIChpc0xlZ2FjeSkge1xuICAgICAgICBjb25zdCBsZWdhY3kgPSBBcnJheS5pc0FycmF5KHRoaXMuc2V0dGluZ3MubGVnYWN5U2Vzc2lvbktleXMpID8gdGhpcy5zZXR0aW5ncy5sZWdhY3lTZXNzaW9uS2V5cyA6IFtdO1xuICAgICAgICB0aGlzLnNldHRpbmdzLmxlZ2FjeVNlc3Npb25LZXlzID0gW2V4aXN0aW5nLCAuLi5sZWdhY3kuZmlsdGVyKChrKSA9PiBrICYmIGsgIT09IGV4aXN0aW5nKV0uc2xpY2UoMCwgMjApO1xuICAgICAgfVxuXG4gICAgICBpZiAoaXNMZWdhY3kgfHwgaXNFbXB0eU9yTWFpbikge1xuICAgICAgICB0aGlzLnNldHRpbmdzLnNlc3Npb25LZXkgPSBjYW5vbmljYWw7XG4gICAgICB9XG5cbiAgICAgIGNvbnN0IG1hcCA9IHRoaXMuc2V0dGluZ3Mua25vd25TZXNzaW9uS2V5c0J5VmF1bHQgPz8ge307XG4gICAgICBjb25zdCBjdXIgPSBBcnJheS5pc0FycmF5KG1hcFt0aGlzLl92YXVsdEhhc2hdKSA/IG1hcFt0aGlzLl92YXVsdEhhc2hdIDogW107XG4gICAgICBpZiAoIWN1ci5pbmNsdWRlcyhjYW5vbmljYWwpKSB7XG4gICAgICAgIG1hcFt0aGlzLl92YXVsdEhhc2hdID0gW2Nhbm9uaWNhbCwgLi4uY3VyXS5zbGljZSgwLCAyMCk7XG4gICAgICAgIHRoaXMuc2V0dGluZ3Mua25vd25TZXNzaW9uS2V5c0J5VmF1bHQgPSBtYXA7XG4gICAgICB9XG5cbiAgICAgIGF3YWl0IHRoaXMuc2F2ZVNldHRpbmdzKCk7XG4gICAgfVxuXG4gICAgdGhpcy53c0NsaWVudCA9IG5ldyBPYnNpZGlhbldTQ2xpZW50KCh0aGlzLnNldHRpbmdzLnNlc3Npb25LZXkgPz8gJ21haW4nKS50b0xvd2VyQ2FzZSgpLCB7XG4gICAgICBpZGVudGl0eVN0b3JlOiB7XG4gICAgICAgIGdldDogYXN5bmMgKCkgPT4gKGF3YWl0IHRoaXMuX2xvYWREZXZpY2VJZGVudGl0eSgpKSxcbiAgICAgICAgc2V0OiBhc3luYyAoaWRlbnRpdHkpID0+IGF3YWl0IHRoaXMuX3NhdmVEZXZpY2VJZGVudGl0eShpZGVudGl0eSksXG4gICAgICAgIGNsZWFyOiBhc3luYyAoKSA9PiBhd2FpdCB0aGlzLl9jbGVhckRldmljZUlkZW50aXR5KCksXG4gICAgICB9LFxuICAgIH0pO1xuICAgIHRoaXMuY2hhdE1hbmFnZXIgPSBuZXcgQ2hhdE1hbmFnZXIoKTtcblxuICAgIC8vIFdpcmUgaW5jb21pbmcgV1MgbWVzc2FnZXMgXHUyMTkyIENoYXRNYW5hZ2VyXG4gICAgdGhpcy53c0NsaWVudC5vbk1lc3NhZ2UgPSAobXNnKSA9PiB7XG4gICAgICBpZiAobXNnLnR5cGUgPT09ICdtZXNzYWdlJykge1xuICAgICAgICB0aGlzLmNoYXRNYW5hZ2VyLmFkZE1lc3NhZ2UoQ2hhdE1hbmFnZXIuY3JlYXRlQXNzaXN0YW50TWVzc2FnZShtc2cucGF5bG9hZC5jb250ZW50KSk7XG4gICAgICB9IGVsc2UgaWYgKG1zZy50eXBlID09PSAnZXJyb3InKSB7XG4gICAgICAgIGNvbnN0IGVyclRleHQgPSBtc2cucGF5bG9hZC5tZXNzYWdlID8/ICdVbmtub3duIGVycm9yIGZyb20gZ2F0ZXdheSc7XG4gICAgICAgIHRoaXMuY2hhdE1hbmFnZXIuYWRkTWVzc2FnZShDaGF0TWFuYWdlci5jcmVhdGVTeXN0ZW1NZXNzYWdlKGBcdTI2QTAgJHtlcnJUZXh0fWAsICdlcnJvcicpKTtcbiAgICAgIH1cbiAgICB9O1xuXG4gICAgLy8gUmVnaXN0ZXIgdGhlIHNpZGViYXIgdmlld1xuICAgIHRoaXMucmVnaXN0ZXJWaWV3KFxuICAgICAgVklFV19UWVBFX09QRU5DTEFXX0NIQVQsXG4gICAgICAobGVhZjogV29ya3NwYWNlTGVhZikgPT4gbmV3IE9wZW5DbGF3Q2hhdFZpZXcobGVhZiwgdGhpcylcbiAgICApO1xuXG4gICAgLy8gUmliYm9uIGljb24gXHUyMDE0IG9wZW5zIC8gcmV2ZWFscyB0aGUgY2hhdCBzaWRlYmFyXG4gICAgdGhpcy5hZGRSaWJib25JY29uKCdtZXNzYWdlLXNxdWFyZScsICdPcGVuQ2xhdyBDaGF0JywgKCkgPT4ge1xuICAgICAgdGhpcy5fYWN0aXZhdGVDaGF0VmlldygpO1xuICAgIH0pO1xuXG4gICAgLy8gU2V0dGluZ3MgdGFiXG4gICAgdGhpcy5hZGRTZXR0aW5nVGFiKG5ldyBPcGVuQ2xhd1NldHRpbmdUYWIodGhpcy5hcHAsIHRoaXMpKTtcblxuICAgIC8vIENvbW1hbmQgcGFsZXR0ZSBlbnRyeVxuICAgIHRoaXMuYWRkQ29tbWFuZCh7XG4gICAgICBpZDogJ29wZW4tb3BlbmNsYXctY2hhdCcsXG4gICAgICBuYW1lOiAnT3BlbiBjaGF0IHNpZGViYXInLFxuICAgICAgY2FsbGJhY2s6ICgpID0+IHRoaXMuX2FjdGl2YXRlQ2hhdFZpZXcoKSxcbiAgICB9KTtcblxuICAgIC8vIENvbm5lY3QgdG8gZ2F0ZXdheSBpZiB0b2tlbiBpcyBjb25maWd1cmVkXG4gICAgaWYgKHRoaXMuc2V0dGluZ3MuYXV0aFRva2VuKSB7XG4gICAgICB0aGlzLl9jb25uZWN0V1MoKTtcbiAgICB9IGVsc2Uge1xuICAgICAgbmV3IE5vdGljZSgnT3BlbkNsYXcgQ2hhdDogcGxlYXNlIGNvbmZpZ3VyZSB5b3VyIGdhdGV3YXkgdG9rZW4gaW4gU2V0dGluZ3MuJyk7XG4gICAgfVxuXG4gICAgY29uc29sZS5sb2coJ1tvY2xhd10gUGx1Z2luIGxvYWRlZCcpO1xuICB9XG5cbiAgYXN5bmMgb251bmxvYWQoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgdGhpcy53c0NsaWVudC5kaXNjb25uZWN0KCk7XG4gICAgdGhpcy5hcHAud29ya3NwYWNlLmRldGFjaExlYXZlc09mVHlwZShWSUVXX1RZUEVfT1BFTkNMQVdfQ0hBVCk7XG4gICAgY29uc29sZS5sb2coJ1tvY2xhd10gUGx1Z2luIHVubG9hZGVkJyk7XG4gIH1cblxuICBhc3luYyBsb2FkU2V0dGluZ3MoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgY29uc3QgZGF0YSA9IChhd2FpdCB0aGlzLmxvYWREYXRhKCkpID8/IHt9O1xuICAgIC8vIE5PVEU6IHBsdWdpbiBkYXRhIG1heSBjb250YWluIGV4dHJhIHByaXZhdGUgZmllbGRzIChlLmcuIGRldmljZSBpZGVudGl0eSkuIFNldHRpbmdzIGFyZSB0aGUgcHVibGljIHN1YnNldC5cbiAgICB0aGlzLnNldHRpbmdzID0gT2JqZWN0LmFzc2lnbih7fSwgREVGQVVMVF9TRVRUSU5HUywgZGF0YSk7XG4gIH1cblxuICBhc3luYyBzYXZlU2V0dGluZ3MoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgLy8gUHJlc2VydmUgYW55IHByaXZhdGUgZmllbGRzIHN0b3JlZCBpbiBwbHVnaW4gZGF0YS5cbiAgICBjb25zdCBkYXRhID0gKGF3YWl0IHRoaXMubG9hZERhdGEoKSkgPz8ge307XG4gICAgYXdhaXQgdGhpcy5zYXZlRGF0YSh7IC4uLmRhdGEsIC4uLnRoaXMuc2V0dGluZ3MgfSk7XG4gIH1cblxuICAvLyBcdTI1MDBcdTI1MDAgRGV2aWNlIGlkZW50aXR5IHBlcnNpc3RlbmNlIChwbHVnaW4tc2NvcGVkOyBOT1QgbG9jYWxTdG9yYWdlKSBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcblxuICBhc3luYyByZXNldERldmljZUlkZW50aXR5KCk6IFByb21pc2U8dm9pZD4ge1xuICAgIGF3YWl0IHRoaXMuX2NsZWFyRGV2aWNlSWRlbnRpdHkoKTtcbiAgICBuZXcgTm90aWNlKCdPcGVuQ2xhdyBDaGF0OiBkZXZpY2UgaWRlbnRpdHkgcmVzZXQuIFJlY29ubmVjdCB0byBwYWlyIGFnYWluLicpO1xuICB9XG5cbiAgcHJpdmF0ZSBfZGV2aWNlSWRlbnRpdHlLZXkgPSAnX29wZW5jbGF3RGV2aWNlSWRlbnRpdHlWMSc7XG5cbiAgcHJpdmF0ZSBhc3luYyBfbG9hZERldmljZUlkZW50aXR5KCk6IFByb21pc2U8YW55IHwgbnVsbD4ge1xuICAgIGNvbnN0IGRhdGEgPSAoYXdhaXQgdGhpcy5sb2FkRGF0YSgpKSA/PyB7fTtcbiAgICByZXR1cm4gKGRhdGEgYXMgYW55KT8uW3RoaXMuX2RldmljZUlkZW50aXR5S2V5XSA/PyBudWxsO1xuICB9XG5cbiAgcHJpdmF0ZSBhc3luYyBfc2F2ZURldmljZUlkZW50aXR5KGlkZW50aXR5OiBhbnkpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBjb25zdCBkYXRhID0gKGF3YWl0IHRoaXMubG9hZERhdGEoKSkgPz8ge307XG4gICAgYXdhaXQgdGhpcy5zYXZlRGF0YSh7IC4uLmRhdGEsIFt0aGlzLl9kZXZpY2VJZGVudGl0eUtleV06IGlkZW50aXR5IH0pO1xuICB9XG5cbiAgcHJpdmF0ZSBhc3luYyBfY2xlYXJEZXZpY2VJZGVudGl0eSgpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBjb25zdCBkYXRhID0gKGF3YWl0IHRoaXMubG9hZERhdGEoKSkgPz8ge307XG4gICAgaWYgKChkYXRhIGFzIGFueSk/Llt0aGlzLl9kZXZpY2VJZGVudGl0eUtleV0gPT09IHVuZGVmaW5lZCkgcmV0dXJuO1xuICAgIGNvbnN0IG5leHQgPSB7IC4uLihkYXRhIGFzIGFueSkgfTtcbiAgICBkZWxldGUgbmV4dFt0aGlzLl9kZXZpY2VJZGVudGl0eUtleV07XG4gICAgYXdhaXQgdGhpcy5zYXZlRGF0YShuZXh0KTtcbiAgfVxuXG4gIC8vIFx1MjUwMFx1MjUwMCBIZWxwZXJzIFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFxuXG4gIHByaXZhdGUgX2Nvbm5lY3RXUygpOiB2b2lkIHtcbiAgICB0aGlzLndzQ2xpZW50LmNvbm5lY3QodGhpcy5zZXR0aW5ncy5nYXRld2F5VXJsLCB0aGlzLnNldHRpbmdzLmF1dGhUb2tlbiwge1xuICAgICAgYWxsb3dJbnNlY3VyZVdzOiB0aGlzLnNldHRpbmdzLmFsbG93SW5zZWN1cmVXcyxcbiAgICB9KTtcbiAgfVxuXG4gIHByaXZhdGUgYXN5bmMgX2FjdGl2YXRlQ2hhdFZpZXcoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgY29uc3QgeyB3b3Jrc3BhY2UgfSA9IHRoaXMuYXBwO1xuXG4gICAgLy8gUmV1c2UgZXhpc3RpbmcgbGVhZiBpZiBhbHJlYWR5IG9wZW5cbiAgICBjb25zdCBleGlzdGluZyA9IHdvcmtzcGFjZS5nZXRMZWF2ZXNPZlR5cGUoVklFV19UWVBFX09QRU5DTEFXX0NIQVQpO1xuICAgIGlmIChleGlzdGluZy5sZW5ndGggPiAwKSB7XG4gICAgICB3b3Jrc3BhY2UucmV2ZWFsTGVhZihleGlzdGluZ1swXSk7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgLy8gT3BlbiBpbiByaWdodCBzaWRlYmFyXG4gICAgY29uc3QgbGVhZiA9IHdvcmtzcGFjZS5nZXRSaWdodExlYWYoZmFsc2UpO1xuICAgIGlmICghbGVhZikgcmV0dXJuO1xuICAgIGF3YWl0IGxlYWYuc2V0Vmlld1N0YXRlKHsgdHlwZTogVklFV19UWVBFX09QRU5DTEFXX0NIQVQsIGFjdGl2ZTogdHJ1ZSB9KTtcbiAgICB3b3Jrc3BhY2UucmV2ZWFsTGVhZihsZWFmKTtcbiAgfVxufVxuIiwgImltcG9ydCB7IEFwcCwgUGx1Z2luU2V0dGluZ1RhYiwgU2V0dGluZyB9IGZyb20gJ29ic2lkaWFuJztcbmltcG9ydCB0eXBlIE9wZW5DbGF3UGx1Z2luIGZyb20gJy4vbWFpbic7XG5cbmV4cG9ydCBjbGFzcyBPcGVuQ2xhd1NldHRpbmdUYWIgZXh0ZW5kcyBQbHVnaW5TZXR0aW5nVGFiIHtcbiAgcGx1Z2luOiBPcGVuQ2xhd1BsdWdpbjtcblxuICBjb25zdHJ1Y3RvcihhcHA6IEFwcCwgcGx1Z2luOiBPcGVuQ2xhd1BsdWdpbikge1xuICAgIHN1cGVyKGFwcCwgcGx1Z2luKTtcbiAgICB0aGlzLnBsdWdpbiA9IHBsdWdpbjtcbiAgfVxuXG4gIGRpc3BsYXkoKTogdm9pZCB7XG4gICAgY29uc3QgeyBjb250YWluZXJFbCB9ID0gdGhpcztcbiAgICBjb250YWluZXJFbC5lbXB0eSgpO1xuXG4gICAgY29udGFpbmVyRWwuY3JlYXRlRWwoJ2gyJywgeyB0ZXh0OiAnT3BlbkNsYXcgQ2hhdCBcdTIwMTMgU2V0dGluZ3MnIH0pO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZSgnR2F0ZXdheSBVUkwnKVxuICAgICAgLnNldERlc2MoJ1dlYlNvY2tldCBVUkwgb2YgdGhlIE9wZW5DbGF3IEdhdGV3YXkgKGUuZy4gd3M6Ly9ob3N0bmFtZToxODc4OSkuJylcbiAgICAgIC5hZGRUZXh0KCh0ZXh0KSA9PlxuICAgICAgICB0ZXh0XG4gICAgICAgICAgLnNldFBsYWNlaG9sZGVyKCd3czovL2xvY2FsaG9zdDoxODc4OScpXG4gICAgICAgICAgLnNldFZhbHVlKHRoaXMucGx1Z2luLnNldHRpbmdzLmdhdGV3YXlVcmwpXG4gICAgICAgICAgLm9uQ2hhbmdlKGFzeW5jICh2YWx1ZSkgPT4ge1xuICAgICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3MuZ2F0ZXdheVVybCA9IHZhbHVlLnRyaW0oKTtcbiAgICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICAgIH0pXG4gICAgICApO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZSgnQXV0aCB0b2tlbicpXG4gICAgICAuc2V0RGVzYygnTXVzdCBtYXRjaCB0aGUgYXV0aFRva2VuIGluIHlvdXIgb3BlbmNsYXcuanNvbiBjaGFubmVsIGNvbmZpZy4gTmV2ZXIgc2hhcmVkLicpXG4gICAgICAuYWRkVGV4dCgodGV4dCkgPT4ge1xuICAgICAgICB0ZXh0XG4gICAgICAgICAgLnNldFBsYWNlaG9sZGVyKCdFbnRlciB0b2tlblx1MjAyNicpXG4gICAgICAgICAgLnNldFZhbHVlKHRoaXMucGx1Z2luLnNldHRpbmdzLmF1dGhUb2tlbilcbiAgICAgICAgICAub25DaGFuZ2UoYXN5bmMgKHZhbHVlKSA9PiB7XG4gICAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5hdXRoVG9rZW4gPSB2YWx1ZTtcbiAgICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICAgIH0pO1xuICAgICAgICAvLyBUcmVhdCBhcyBwYXNzd29yZCBmaWVsZCBcdTIwMTMgZG8gbm90IHJldmVhbCB0b2tlbiBpbiBVSVxuICAgICAgICB0ZXh0LmlucHV0RWwudHlwZSA9ICdwYXNzd29yZCc7XG4gICAgICAgIHRleHQuaW5wdXRFbC5hdXRvY29tcGxldGUgPSAnb2ZmJztcbiAgICAgIH0pO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZSgnU2Vzc2lvbiBLZXknKVxuICAgICAgLnNldERlc2MoJ09wZW5DbGF3IHNlc3Npb24gdG8gc3Vic2NyaWJlIHRvICh1c3VhbGx5IFwibWFpblwiKS4nKVxuICAgICAgLmFkZFRleHQoKHRleHQpID0+XG4gICAgICAgIHRleHRcbiAgICAgICAgICAuc2V0UGxhY2Vob2xkZXIoJ21haW4nKVxuICAgICAgICAgIC5zZXRWYWx1ZSh0aGlzLnBsdWdpbi5zZXR0aW5ncy5zZXNzaW9uS2V5KVxuICAgICAgICAgIC5vbkNoYW5nZShhc3luYyAodmFsdWUpID0+IHtcbiAgICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLnNlc3Npb25LZXkgPSB2YWx1ZS50cmltKCkgfHwgJ21haW4nO1xuICAgICAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uc2F2ZVNldHRpbmdzKCk7XG4gICAgICAgICAgfSlcbiAgICAgICk7XG5cbiAgICBuZXcgU2V0dGluZyhjb250YWluZXJFbClcbiAgICAgIC5zZXROYW1lKCdBY2NvdW50IElEJylcbiAgICAgIC5zZXREZXNjKCdPcGVuQ2xhdyBhY2NvdW50IElEICh1c3VhbGx5IFwibWFpblwiKS4nKVxuICAgICAgLmFkZFRleHQoKHRleHQpID0+XG4gICAgICAgIHRleHRcbiAgICAgICAgICAuc2V0UGxhY2Vob2xkZXIoJ21haW4nKVxuICAgICAgICAgIC5zZXRWYWx1ZSh0aGlzLnBsdWdpbi5zZXR0aW5ncy5hY2NvdW50SWQpXG4gICAgICAgICAgLm9uQ2hhbmdlKGFzeW5jICh2YWx1ZSkgPT4ge1xuICAgICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3MuYWNjb3VudElkID0gdmFsdWUudHJpbSgpIHx8ICdtYWluJztcbiAgICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICAgIH0pXG4gICAgICApO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZSgnSW5jbHVkZSBhY3RpdmUgbm90ZSBieSBkZWZhdWx0JylcbiAgICAgIC5zZXREZXNjKCdQcmUtY2hlY2sgXCJJbmNsdWRlIGFjdGl2ZSBub3RlXCIgaW4gdGhlIGNoYXQgcGFuZWwgd2hlbiBpdCBvcGVucy4nKVxuICAgICAgLmFkZFRvZ2dsZSgodG9nZ2xlKSA9PlxuICAgICAgICB0b2dnbGUuc2V0VmFsdWUodGhpcy5wbHVnaW4uc2V0dGluZ3MuaW5jbHVkZUFjdGl2ZU5vdGUpLm9uQ2hhbmdlKGFzeW5jICh2YWx1ZSkgPT4ge1xuICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLmluY2x1ZGVBY3RpdmVOb3RlID0gdmFsdWU7XG4gICAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uc2F2ZVNldHRpbmdzKCk7XG4gICAgICAgIH0pXG4gICAgICApO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZSgnUmVuZGVyIGFzc2lzdGFudCBhcyBNYXJrZG93biAodW5zYWZlKScpXG4gICAgICAuc2V0RGVzYyhcbiAgICAgICAgJ09GRiByZWNvbW1lbmRlZC4gSWYgZW5hYmxlZCwgYXNzaXN0YW50IG91dHB1dCBpcyByZW5kZXJlZCBhcyBPYnNpZGlhbiBNYXJrZG93biB3aGljaCBtYXkgdHJpZ2dlciBlbWJlZHMgYW5kIG90aGVyIHBsdWdpbnNcXCcgcG9zdC1wcm9jZXNzb3JzLidcbiAgICAgIClcbiAgICAgIC5hZGRUb2dnbGUoKHRvZ2dsZSkgPT5cbiAgICAgICAgdG9nZ2xlLnNldFZhbHVlKHRoaXMucGx1Z2luLnNldHRpbmdzLnJlbmRlckFzc2lzdGFudE1hcmtkb3duKS5vbkNoYW5nZShhc3luYyAodmFsdWUpID0+IHtcbiAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5yZW5kZXJBc3Npc3RhbnRNYXJrZG93biA9IHZhbHVlO1xuICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICB9KVxuICAgICAgKTtcblxuICAgIG5ldyBTZXR0aW5nKGNvbnRhaW5lckVsKVxuICAgICAgLnNldE5hbWUoJ0FsbG93IGluc2VjdXJlIHdzOi8vIGZvciBub24tbG9jYWwgZ2F0ZXdheXMgKHVuc2FmZSknKVxuICAgICAgLnNldERlc2MoXG4gICAgICAgICdPRkYgcmVjb21tZW5kZWQuIElmIGVuYWJsZWQsIHlvdSBjYW4gY29ubmVjdCB0byBub24tbG9jYWwgZ2F0ZXdheXMgb3ZlciB3czovLy4gVGhpcyBleHBvc2VzIHlvdXIgdG9rZW4gYW5kIG1lc3NhZ2UgY29udGVudCB0byBuZXR3b3JrIGF0dGFja2VyczsgcHJlZmVyIHdzczovLy4nXG4gICAgICApXG4gICAgICAuYWRkVG9nZ2xlKCh0b2dnbGUpID0+XG4gICAgICAgIHRvZ2dsZS5zZXRWYWx1ZSh0aGlzLnBsdWdpbi5zZXR0aW5ncy5hbGxvd0luc2VjdXJlV3MpLm9uQ2hhbmdlKGFzeW5jICh2YWx1ZSkgPT4ge1xuICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLmFsbG93SW5zZWN1cmVXcyA9IHZhbHVlO1xuICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICB9KVxuICAgICAgKTtcblxuICAgIG5ldyBTZXR0aW5nKGNvbnRhaW5lckVsKVxuICAgICAgLnNldE5hbWUoJ1Jlc2V0IGRldmljZSBpZGVudGl0eSAocmUtcGFpciknKVxuICAgICAgLnNldERlc2MoJ0NsZWFycyB0aGUgc3RvcmVkIGRldmljZSBpZGVudGl0eSB1c2VkIGZvciBvcGVyYXRvci53cml0ZSBwYWlyaW5nLiBVc2UgdGhpcyBpZiB5b3Ugc3VzcGVjdCBjb21wcm9taXNlIG9yIHNlZSBcImRldmljZSBpZGVudGl0eSBtaXNtYXRjaFwiLicpXG4gICAgICAuYWRkQnV0dG9uKChidG4pID0+XG4gICAgICAgIGJ0bi5zZXRCdXR0b25UZXh0KCdSZXNldCcpLnNldFdhcm5pbmcoKS5vbkNsaWNrKGFzeW5jICgpID0+IHtcbiAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5yZXNldERldmljZUlkZW50aXR5KCk7XG4gICAgICAgIH0pXG4gICAgICApO1xuXG4gICAgLy8gXHUyNTAwXHUyNTAwIFBhdGggbWFwcGluZ3MgXHUyNTAwXHUyNTAwXG4gICAgY29udGFpbmVyRWwuY3JlYXRlRWwoJ2gzJywgeyB0ZXh0OiAnUGF0aCBtYXBwaW5ncyAodmF1bHQgYmFzZSBcdTIxOTIgcmVtb3RlIGJhc2UpJyB9KTtcbiAgICBjb250YWluZXJFbC5jcmVhdGVFbCgncCcsIHtcbiAgICAgIHRleHQ6ICdVc2VkIHRvIGNvbnZlcnQgYXNzaXN0YW50IGZpbGUgcmVmZXJlbmNlcyAocmVtb3RlIEZTIHBhdGhzIG9yIGV4cG9ydGVkIFVSTHMpIGludG8gY2xpY2thYmxlIE9ic2lkaWFuIGxpbmtzLiBGaXJzdCBtYXRjaCB3aW5zLiBPbmx5IGNyZWF0ZXMgYSBsaW5rIGlmIHRoZSBtYXBwZWQgdmF1bHQgZmlsZSBleGlzdHMuJyxcbiAgICAgIGNsczogJ3NldHRpbmctaXRlbS1kZXNjcmlwdGlvbicsXG4gICAgfSk7XG5cbiAgICBjb25zdCBtYXBwaW5ncyA9IHRoaXMucGx1Z2luLnNldHRpbmdzLnBhdGhNYXBwaW5ncyA/PyBbXTtcblxuICAgIGNvbnN0IHJlcmVuZGVyID0gYXN5bmMgKCkgPT4ge1xuICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uc2F2ZVNldHRpbmdzKCk7XG4gICAgICB0aGlzLmRpc3BsYXkoKTtcbiAgICB9O1xuXG4gICAgbWFwcGluZ3MuZm9yRWFjaCgocm93LCBpZHgpID0+IHtcbiAgICAgIGNvbnN0IHMgPSBuZXcgU2V0dGluZyhjb250YWluZXJFbClcbiAgICAgICAgLnNldE5hbWUoYE1hcHBpbmcgIyR7aWR4ICsgMX1gKVxuICAgICAgICAuc2V0RGVzYygndmF1bHRCYXNlIFx1MjE5MiByZW1vdGVCYXNlJyk7XG5cbiAgICAgIHMuYWRkVGV4dCgodCkgPT5cbiAgICAgICAgdFxuICAgICAgICAgIC5zZXRQbGFjZWhvbGRlcigndmF1bHQgYmFzZSAoZS5nLiBkb2NzLyknKVxuICAgICAgICAgIC5zZXRWYWx1ZShyb3cudmF1bHRCYXNlID8/ICcnKVxuICAgICAgICAgIC5vbkNoYW5nZShhc3luYyAodikgPT4ge1xuICAgICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3MucGF0aE1hcHBpbmdzW2lkeF0udmF1bHRCYXNlID0gdjtcbiAgICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICAgIH0pXG4gICAgICApO1xuXG4gICAgICBzLmFkZFRleHQoKHQpID0+XG4gICAgICAgIHRcbiAgICAgICAgICAuc2V0UGxhY2Vob2xkZXIoJ3JlbW90ZSBiYXNlIChlLmcuIC9ob21lLy4uLi9kb2NzLyknKVxuICAgICAgICAgIC5zZXRWYWx1ZShyb3cucmVtb3RlQmFzZSA/PyAnJylcbiAgICAgICAgICAub25DaGFuZ2UoYXN5bmMgKHYpID0+IHtcbiAgICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLnBhdGhNYXBwaW5nc1tpZHhdLnJlbW90ZUJhc2UgPSB2O1xuICAgICAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uc2F2ZVNldHRpbmdzKCk7XG4gICAgICAgICAgfSlcbiAgICAgICk7XG5cbiAgICAgIHMuYWRkRXh0cmFCdXR0b24oKGIpID0+XG4gICAgICAgIGJcbiAgICAgICAgICAuc2V0SWNvbigndHJhc2gnKVxuICAgICAgICAgIC5zZXRUb29sdGlwKCdSZW1vdmUgbWFwcGluZycpXG4gICAgICAgICAgLm9uQ2xpY2soYXN5bmMgKCkgPT4ge1xuICAgICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3MucGF0aE1hcHBpbmdzLnNwbGljZShpZHgsIDEpO1xuICAgICAgICAgICAgYXdhaXQgcmVyZW5kZXIoKTtcbiAgICAgICAgICB9KVxuICAgICAgKTtcbiAgICB9KTtcblxuICAgIG5ldyBTZXR0aW5nKGNvbnRhaW5lckVsKVxuICAgICAgLnNldE5hbWUoJ0FkZCBtYXBwaW5nJylcbiAgICAgIC5zZXREZXNjKCdBZGQgYSBuZXcgdmF1bHRCYXNlIFx1MjE5MiByZW1vdGVCYXNlIG1hcHBpbmcgcm93LicpXG4gICAgICAuYWRkQnV0dG9uKChidG4pID0+XG4gICAgICAgIGJ0bi5zZXRCdXR0b25UZXh0KCdBZGQnKS5vbkNsaWNrKGFzeW5jICgpID0+IHtcbiAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5wYXRoTWFwcGluZ3MucHVzaCh7IHZhdWx0QmFzZTogJycsIHJlbW90ZUJhc2U6ICcnIH0pO1xuICAgICAgICAgIGF3YWl0IHJlcmVuZGVyKCk7XG4gICAgICAgIH0pXG4gICAgICApO1xuXG4gICAgY29udGFpbmVyRWwuY3JlYXRlRWwoJ3AnLCB7XG4gICAgICB0ZXh0OiAnUmVjb25uZWN0OiBjbG9zZSBhbmQgcmVvcGVuIHRoZSBzaWRlYmFyIGFmdGVyIGNoYW5naW5nIHRoZSBnYXRld2F5IFVSTCBvciB0b2tlbi4nLFxuICAgICAgY2xzOiAnc2V0dGluZy1pdGVtLWRlc2NyaXB0aW9uJyxcbiAgICB9KTtcbiAgfVxufVxuIiwgIi8qKlxuICogV2ViU29ja2V0IGNsaWVudCBmb3IgT3BlbkNsYXcgR2F0ZXdheVxuICpcbiAqIFBpdm90ICgyMDI2LTAyLTI1KTogRG8gTk9UIHVzZSBjdXN0b20gb2JzaWRpYW4uKiBnYXRld2F5IG1ldGhvZHMuXG4gKiBUaG9zZSByZXF1aXJlIG9wZXJhdG9yLmFkbWluIHNjb3BlIHdoaWNoIGlzIG5vdCBncmFudGVkIHRvIGV4dGVybmFsIGNsaWVudHMuXG4gKlxuICogQXV0aCBub3RlOlxuICogLSBjaGF0LnNlbmQgcmVxdWlyZXMgb3BlcmF0b3Iud3JpdGVcbiAqIC0gZXh0ZXJuYWwgY2xpZW50cyBtdXN0IHByZXNlbnQgYSBwYWlyZWQgZGV2aWNlIGlkZW50aXR5IHRvIHJlY2VpdmUgd3JpdGUgc2NvcGVzXG4gKlxuICogV2UgdXNlIGJ1aWx0LWluIGdhdGV3YXkgbWV0aG9kcy9ldmVudHM6XG4gKiAtIFNlbmQ6IGNoYXQuc2VuZCh7IHNlc3Npb25LZXksIG1lc3NhZ2UsIGlkZW1wb3RlbmN5S2V5LCAuLi4gfSlcbiAqIC0gUmVjZWl2ZTogZXZlbnQgXCJjaGF0XCIgKGZpbHRlciBieSBzZXNzaW9uS2V5KVxuICovXG5cbmltcG9ydCB0eXBlIHsgSW5ib3VuZFdTUGF5bG9hZCB9IGZyb20gJy4vdHlwZXMnO1xuXG5mdW5jdGlvbiBpc0xvY2FsSG9zdChob3N0OiBzdHJpbmcpOiBib29sZWFuIHtcbiAgY29uc3QgaCA9IGhvc3QudG9Mb3dlckNhc2UoKTtcbiAgcmV0dXJuIGggPT09ICdsb2NhbGhvc3QnIHx8IGggPT09ICcxMjcuMC4wLjEnIHx8IGggPT09ICc6OjEnO1xufVxuXG5mdW5jdGlvbiBzYWZlUGFyc2VXc1VybCh1cmw6IHN0cmluZyk6XG4gIHwgeyBvazogdHJ1ZTsgc2NoZW1lOiAnd3MnIHwgJ3dzcyc7IGhvc3Q6IHN0cmluZyB9XG4gIHwgeyBvazogZmFsc2U7IGVycm9yOiBzdHJpbmcgfSB7XG4gIHRyeSB7XG4gICAgY29uc3QgdSA9IG5ldyBVUkwodXJsKTtcbiAgICBpZiAodS5wcm90b2NvbCAhPT0gJ3dzOicgJiYgdS5wcm90b2NvbCAhPT0gJ3dzczonKSB7XG4gICAgICByZXR1cm4geyBvazogZmFsc2UsIGVycm9yOiBgR2F0ZXdheSBVUkwgbXVzdCBiZSB3czovLyBvciB3c3M6Ly8gKGdvdCAke3UucHJvdG9jb2x9KWAgfTtcbiAgICB9XG4gICAgY29uc3Qgc2NoZW1lID0gdS5wcm90b2NvbCA9PT0gJ3dzOicgPyAnd3MnIDogJ3dzcyc7XG4gICAgcmV0dXJuIHsgb2s6IHRydWUsIHNjaGVtZSwgaG9zdDogdS5ob3N0bmFtZSB9O1xuICB9IGNhdGNoIHtcbiAgICByZXR1cm4geyBvazogZmFsc2UsIGVycm9yOiAnSW52YWxpZCBnYXRld2F5IFVSTCcgfTtcbiAgfVxufVxuXG4vKiogSW50ZXJ2YWwgZm9yIHNlbmRpbmcgaGVhcnRiZWF0IHBpbmdzIChjaGVjayBjb25uZWN0aW9uIGxpdmVuZXNzKSAqL1xuY29uc3QgSEVBUlRCRUFUX0lOVEVSVkFMX01TID0gMzBfMDAwO1xuXG4vKiogU2FmZXR5IHZhbHZlOiBoaWRlIHdvcmtpbmcgc3Bpbm5lciBpZiBubyBhc3Npc3RhbnQgcmVwbHkgYXJyaXZlcyBpbiB0aW1lICovXG5jb25zdCBXT1JLSU5HX01BWF9NUyA9IDEyMF8wMDA7XG5cbi8qKiBNYXggaW5ib3VuZCBmcmFtZSBzaXplIHRvIHBhcnNlIChEb1MgZ3VhcmQpICovXG5jb25zdCBNQVhfSU5CT1VORF9GUkFNRV9CWVRFUyA9IDUxMiAqIDEwMjQ7XG5cbmZ1bmN0aW9uIGJ5dGVMZW5ndGhVdGY4KHRleHQ6IHN0cmluZyk6IG51bWJlciB7XG4gIHJldHVybiB1dGY4Qnl0ZXModGV4dCkuYnl0ZUxlbmd0aDtcbn1cblxuYXN5bmMgZnVuY3Rpb24gbm9ybWFsaXplV3NEYXRhVG9UZXh0KGRhdGE6IGFueSk6IFByb21pc2U8eyBvazogdHJ1ZTsgdGV4dDogc3RyaW5nOyBieXRlczogbnVtYmVyIH0gfCB7IG9rOiBmYWxzZTsgcmVhc29uOiBzdHJpbmc7IGJ5dGVzPzogbnVtYmVyIH0+IHtcbiAgaWYgKHR5cGVvZiBkYXRhID09PSAnc3RyaW5nJykge1xuICAgIGNvbnN0IGJ5dGVzID0gYnl0ZUxlbmd0aFV0ZjgoZGF0YSk7XG4gICAgcmV0dXJuIHsgb2s6IHRydWUsIHRleHQ6IGRhdGEsIGJ5dGVzIH07XG4gIH1cblxuICAvLyBCcm93c2VyIFdlYlNvY2tldCBjYW4gZGVsaXZlciBCbG9iXG4gIGlmICh0eXBlb2YgQmxvYiAhPT0gJ3VuZGVmaW5lZCcgJiYgZGF0YSBpbnN0YW5jZW9mIEJsb2IpIHtcbiAgICBjb25zdCBieXRlcyA9IGRhdGEuc2l6ZTtcbiAgICBpZiAoYnl0ZXMgPiBNQVhfSU5CT1VORF9GUkFNRV9CWVRFUykgcmV0dXJuIHsgb2s6IGZhbHNlLCByZWFzb246ICd0b28tbGFyZ2UnLCBieXRlcyB9O1xuICAgIGNvbnN0IHRleHQgPSBhd2FpdCBkYXRhLnRleHQoKTtcbiAgICAvLyBCbG9iLnNpemUgaXMgYnl0ZXMgYWxyZWFkeTsgbm8gbmVlZCB0byByZS1tZWFzdXJlLlxuICAgIHJldHVybiB7IG9rOiB0cnVlLCB0ZXh0LCBieXRlcyB9O1xuICB9XG5cbiAgaWYgKGRhdGEgaW5zdGFuY2VvZiBBcnJheUJ1ZmZlcikge1xuICAgIGNvbnN0IGJ5dGVzID0gZGF0YS5ieXRlTGVuZ3RoO1xuICAgIGlmIChieXRlcyA+IE1BWF9JTkJPVU5EX0ZSQU1FX0JZVEVTKSByZXR1cm4geyBvazogZmFsc2UsIHJlYXNvbjogJ3Rvby1sYXJnZScsIGJ5dGVzIH07XG4gICAgY29uc3QgdGV4dCA9IG5ldyBUZXh0RGVjb2RlcigndXRmLTgnLCB7IGZhdGFsOiBmYWxzZSB9KS5kZWNvZGUobmV3IFVpbnQ4QXJyYXkoZGF0YSkpO1xuICAgIHJldHVybiB7IG9rOiB0cnVlLCB0ZXh0LCBieXRlcyB9O1xuICB9XG5cbiAgLy8gU29tZSBydW50aW1lcyBjb3VsZCBwYXNzIFVpbnQ4QXJyYXkgZGlyZWN0bHlcbiAgaWYgKGRhdGEgaW5zdGFuY2VvZiBVaW50OEFycmF5KSB7XG4gICAgY29uc3QgYnl0ZXMgPSBkYXRhLmJ5dGVMZW5ndGg7XG4gICAgaWYgKGJ5dGVzID4gTUFYX0lOQk9VTkRfRlJBTUVfQllURVMpIHJldHVybiB7IG9rOiBmYWxzZSwgcmVhc29uOiAndG9vLWxhcmdlJywgYnl0ZXMgfTtcbiAgICBjb25zdCB0ZXh0ID0gbmV3IFRleHREZWNvZGVyKCd1dGYtOCcsIHsgZmF0YWw6IGZhbHNlIH0pLmRlY29kZShkYXRhKTtcbiAgICByZXR1cm4geyBvazogdHJ1ZSwgdGV4dCwgYnl0ZXMgfTtcbiAgfVxuXG4gIHJldHVybiB7IG9rOiBmYWxzZSwgcmVhc29uOiAndW5zdXBwb3J0ZWQtdHlwZScgfTtcbn1cblxuLyoqIE1heCBpbi1mbGlnaHQgcmVxdWVzdHMgYmVmb3JlIGZhc3QtZmFpbGluZyAoRG9TL3JvYnVzdG5lc3MgZ3VhcmQpICovXG5jb25zdCBNQVhfUEVORElOR19SRVFVRVNUUyA9IDIwMDtcblxuLyoqIFJlY29ubmVjdCBiYWNrb2ZmICovXG5jb25zdCBSRUNPTk5FQ1RfQkFTRV9NUyA9IDNfMDAwO1xuY29uc3QgUkVDT05ORUNUX01BWF9NUyA9IDYwXzAwMDtcblxuLyoqIEhhbmRzaGFrZSBkZWFkbGluZSB3YWl0aW5nIGZvciBjb25uZWN0LmNoYWxsZW5nZSAqL1xuY29uc3QgSEFORFNIQUtFX1RJTUVPVVRfTVMgPSAxNV8wMDA7XG5cbmV4cG9ydCB0eXBlIFdTQ2xpZW50U3RhdGUgPSAnZGlzY29ubmVjdGVkJyB8ICdjb25uZWN0aW5nJyB8ICdoYW5kc2hha2luZycgfCAnY29ubmVjdGVkJztcblxuZXhwb3J0IHR5cGUgV29ya2luZ1N0YXRlTGlzdGVuZXIgPSAod29ya2luZzogYm9vbGVhbikgPT4gdm9pZDtcblxuaW50ZXJmYWNlIFBlbmRpbmdSZXF1ZXN0IHtcbiAgcmVzb2x2ZTogKHBheWxvYWQ6IGFueSkgPT4gdm9pZDtcbiAgcmVqZWN0OiAoZXJyb3I6IGFueSkgPT4gdm9pZDtcbiAgdGltZW91dDogUmV0dXJuVHlwZTx0eXBlb2Ygc2V0VGltZW91dD4gfCBudWxsO1xufVxuXG5leHBvcnQgdHlwZSBEZXZpY2VJZGVudGl0eSA9IHtcbiAgaWQ6IHN0cmluZztcbiAgcHVibGljS2V5OiBzdHJpbmc7IC8vIGJhc2U2NFxuICBwcml2YXRlS2V5SndrOiBKc29uV2ViS2V5O1xufTtcblxuZXhwb3J0IGludGVyZmFjZSBEZXZpY2VJZGVudGl0eVN0b3JlIHtcbiAgZ2V0KCk6IFByb21pc2U8RGV2aWNlSWRlbnRpdHkgfCBudWxsPjtcbiAgc2V0KGlkZW50aXR5OiBEZXZpY2VJZGVudGl0eSk6IFByb21pc2U8dm9pZD47XG4gIGNsZWFyKCk6IFByb21pc2U8dm9pZD47XG59XG5cbmNvbnN0IERFVklDRV9TVE9SQUdFX0tFWSA9ICdvcGVuY2xhd0NoYXQuZGV2aWNlSWRlbnRpdHkudjEnOyAvLyBsZWdhY3kgbG9jYWxTdG9yYWdlIGtleSAobWlncmF0aW9uIG9ubHkpXG5cbmZ1bmN0aW9uIGJhc2U2NFVybEVuY29kZShieXRlczogQXJyYXlCdWZmZXIpOiBzdHJpbmcge1xuICBjb25zdCB1OCA9IG5ldyBVaW50OEFycmF5KGJ5dGVzKTtcbiAgbGV0IHMgPSAnJztcbiAgZm9yIChsZXQgaSA9IDA7IGkgPCB1OC5sZW5ndGg7IGkrKykgcyArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKHU4W2ldKTtcbiAgY29uc3QgYjY0ID0gYnRvYShzKTtcbiAgcmV0dXJuIGI2NC5yZXBsYWNlKC9cXCsvZywgJy0nKS5yZXBsYWNlKC9cXC8vZywgJ18nKS5yZXBsYWNlKC89KyQvZywgJycpO1xufVxuXG5mdW5jdGlvbiBoZXhFbmNvZGUoYnl0ZXM6IEFycmF5QnVmZmVyKTogc3RyaW5nIHtcbiAgY29uc3QgdTggPSBuZXcgVWludDhBcnJheShieXRlcyk7XG4gIHJldHVybiBBcnJheS5mcm9tKHU4KVxuICAgIC5tYXAoKGIpID0+IGIudG9TdHJpbmcoMTYpLnBhZFN0YXJ0KDIsICcwJykpXG4gICAgLmpvaW4oJycpO1xufVxuXG5mdW5jdGlvbiB1dGY4Qnl0ZXModGV4dDogc3RyaW5nKTogVWludDhBcnJheSB7XG4gIHJldHVybiBuZXcgVGV4dEVuY29kZXIoKS5lbmNvZGUodGV4dCk7XG59XG5cbmFzeW5jIGZ1bmN0aW9uIHNoYTI1NkhleChieXRlczogQXJyYXlCdWZmZXIpOiBQcm9taXNlPHN0cmluZz4ge1xuICBjb25zdCBkaWdlc3QgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmRpZ2VzdCgnU0hBLTI1NicsIGJ5dGVzKTtcbiAgcmV0dXJuIGhleEVuY29kZShkaWdlc3QpO1xufVxuXG5hc3luYyBmdW5jdGlvbiBsb2FkT3JDcmVhdGVEZXZpY2VJZGVudGl0eShzdG9yZT86IERldmljZUlkZW50aXR5U3RvcmUpOiBQcm9taXNlPERldmljZUlkZW50aXR5PiB7XG4gIC8vIDEpIFByZWZlciBwbHVnaW4tc2NvcGVkIHN0b3JhZ2UgKGluamVjdGVkIGJ5IG1haW4gcGx1Z2luKS5cbiAgaWYgKHN0b3JlKSB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IGV4aXN0aW5nID0gYXdhaXQgc3RvcmUuZ2V0KCk7XG4gICAgICBpZiAoZXhpc3Rpbmc/LmlkICYmIGV4aXN0aW5nPy5wdWJsaWNLZXkgJiYgZXhpc3Rpbmc/LnByaXZhdGVLZXlKd2spIHJldHVybiBleGlzdGluZztcbiAgICB9IGNhdGNoIHtcbiAgICAgIC8vIGlnbm9yZSBhbmQgY29udGludWUgKHdlIGNhbiBhbHdheXMgcmUtZ2VuZXJhdGUpXG4gICAgfVxuICB9XG5cbiAgLy8gMikgT25lLXRpbWUgbWlncmF0aW9uOiBsZWdhY3kgbG9jYWxTdG9yYWdlIGlkZW50aXR5LlxuICAvLyBOT1RFOiB0aGlzIHJlbWFpbnMgYSByaXNrIGJvdW5kYXJ5OyB3ZSBvbmx5IHJlYWQrZGVsZXRlIGZvciBtaWdyYXRpb24uXG4gIGNvbnN0IGxlZ2FjeSA9IGxvY2FsU3RvcmFnZS5nZXRJdGVtKERFVklDRV9TVE9SQUdFX0tFWSk7XG4gIGlmIChsZWdhY3kpIHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgcGFyc2VkID0gSlNPTi5wYXJzZShsZWdhY3kpIGFzIERldmljZUlkZW50aXR5O1xuICAgICAgaWYgKHBhcnNlZD8uaWQgJiYgcGFyc2VkPy5wdWJsaWNLZXkgJiYgcGFyc2VkPy5wcml2YXRlS2V5SndrKSB7XG4gICAgICAgIGlmIChzdG9yZSkge1xuICAgICAgICAgIGF3YWl0IHN0b3JlLnNldChwYXJzZWQpO1xuICAgICAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKERFVklDRV9TVE9SQUdFX0tFWSk7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIHBhcnNlZDtcbiAgICAgIH1cbiAgICB9IGNhdGNoIHtcbiAgICAgIC8vIENvcnJ1cHQvcGFydGlhbCBkYXRhIFx1MjE5MiBkZWxldGUgYW5kIHJlLWNyZWF0ZS5cbiAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKERFVklDRV9TVE9SQUdFX0tFWSk7XG4gICAgfVxuICB9XG5cbiAgLy8gMykgQ3JlYXRlIGEgbmV3IGlkZW50aXR5LlxuICBjb25zdCBrZXlQYWlyID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5nZW5lcmF0ZUtleSh7IG5hbWU6ICdFZDI1NTE5JyB9LCB0cnVlLCBbJ3NpZ24nLCAndmVyaWZ5J10pO1xuICBjb25zdCBwdWJSYXcgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmV4cG9ydEtleSgncmF3Jywga2V5UGFpci5wdWJsaWNLZXkpO1xuICBjb25zdCBwcml2SndrID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5leHBvcnRLZXkoJ2p3aycsIGtleVBhaXIucHJpdmF0ZUtleSk7XG5cbiAgLy8gSU1QT1JUQU5UOiBkZXZpY2UuaWQgbXVzdCBiZSBhIHN0YWJsZSBmaW5nZXJwcmludCBmb3IgdGhlIHB1YmxpYyBrZXkuXG4gIC8vIFRoZSBnYXRld2F5IGVuZm9yY2VzIGRldmljZUlkIFx1MjE5NCBwdWJsaWNLZXkgYmluZGluZzsgcmFuZG9tIGlkcyBjYW4gY2F1c2UgXCJkZXZpY2UgaWRlbnRpdHkgbWlzbWF0Y2hcIi5cbiAgY29uc3QgZGV2aWNlSWQgPSBhd2FpdCBzaGEyNTZIZXgocHViUmF3KTtcblxuICBjb25zdCBpZGVudGl0eTogRGV2aWNlSWRlbnRpdHkgPSB7XG4gICAgaWQ6IGRldmljZUlkLFxuICAgIHB1YmxpY0tleTogYmFzZTY0VXJsRW5jb2RlKHB1YlJhdyksXG4gICAgcHJpdmF0ZUtleUp3azogcHJpdkp3ayxcbiAgfTtcblxuICBpZiAoc3RvcmUpIHtcbiAgICBhd2FpdCBzdG9yZS5zZXQoaWRlbnRpdHkpO1xuICB9IGVsc2Uge1xuICAgIC8vIEZhbGxiYWNrIChzaG91bGQgbm90IGhhcHBlbiBpbiByZWFsIHBsdWdpbiBydW50aW1lKSBcdTIwMTQga2VlcCBsZWdhY3kgYmVoYXZpb3IuXG4gICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oREVWSUNFX1NUT1JBR0VfS0VZLCBKU09OLnN0cmluZ2lmeShpZGVudGl0eSkpO1xuICB9XG5cbiAgcmV0dXJuIGlkZW50aXR5O1xufVxuXG5mdW5jdGlvbiBidWlsZERldmljZUF1dGhQYXlsb2FkKHBhcmFtczoge1xuICBkZXZpY2VJZDogc3RyaW5nO1xuICBjbGllbnRJZDogc3RyaW5nO1xuICBjbGllbnRNb2RlOiBzdHJpbmc7XG4gIHJvbGU6IHN0cmluZztcbiAgc2NvcGVzOiBzdHJpbmdbXTtcbiAgc2lnbmVkQXRNczogbnVtYmVyO1xuICB0b2tlbjogc3RyaW5nO1xuICBub25jZT86IHN0cmluZztcbn0pOiBzdHJpbmcge1xuICBjb25zdCB2ZXJzaW9uID0gcGFyYW1zLm5vbmNlID8gJ3YyJyA6ICd2MSc7XG4gIGNvbnN0IHNjb3BlcyA9IHBhcmFtcy5zY29wZXMuam9pbignLCcpO1xuICBjb25zdCBiYXNlID0gW1xuICAgIHZlcnNpb24sXG4gICAgcGFyYW1zLmRldmljZUlkLFxuICAgIHBhcmFtcy5jbGllbnRJZCxcbiAgICBwYXJhbXMuY2xpZW50TW9kZSxcbiAgICBwYXJhbXMucm9sZSxcbiAgICBzY29wZXMsXG4gICAgU3RyaW5nKHBhcmFtcy5zaWduZWRBdE1zKSxcbiAgICBwYXJhbXMudG9rZW4gfHwgJycsXG4gIF07XG4gIGlmICh2ZXJzaW9uID09PSAndjInKSBiYXNlLnB1c2gocGFyYW1zLm5vbmNlIHx8ICcnKTtcbiAgcmV0dXJuIGJhc2Uuam9pbignfCcpO1xufVxuXG5hc3luYyBmdW5jdGlvbiBzaWduRGV2aWNlUGF5bG9hZChpZGVudGl0eTogRGV2aWNlSWRlbnRpdHksIHBheWxvYWQ6IHN0cmluZyk6IFByb21pc2U8eyBzaWduYXR1cmU6IHN0cmluZyB9PiB7XG4gIGNvbnN0IHByaXZhdGVLZXkgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmltcG9ydEtleShcbiAgICAnandrJyxcbiAgICBpZGVudGl0eS5wcml2YXRlS2V5SndrLFxuICAgIHsgbmFtZTogJ0VkMjU1MTknIH0sXG4gICAgZmFsc2UsXG4gICAgWydzaWduJ10sXG4gICk7XG5cbiAgY29uc3Qgc2lnID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5zaWduKHsgbmFtZTogJ0VkMjU1MTknIH0sIHByaXZhdGVLZXksIHV0ZjhCeXRlcyhwYXlsb2FkKSBhcyB1bmtub3duIGFzIEJ1ZmZlclNvdXJjZSk7XG4gIHJldHVybiB7IHNpZ25hdHVyZTogYmFzZTY0VXJsRW5jb2RlKHNpZykgfTtcbn1cblxuZnVuY3Rpb24gZXh0cmFjdFRleHRGcm9tR2F0ZXdheU1lc3NhZ2UobXNnOiBhbnkpOiBzdHJpbmcge1xuICBpZiAoIW1zZykgcmV0dXJuICcnO1xuXG4gIC8vIE1vc3QgY29tbW9uOiB7IHJvbGUsIGNvbnRlbnQgfSB3aGVyZSBjb250ZW50IGNhbiBiZSBzdHJpbmcgb3IgW3t0eXBlOid0ZXh0Jyx0ZXh0OicuLi4nfV1cbiAgY29uc3QgY29udGVudCA9IG1zZy5jb250ZW50ID8/IG1zZy5tZXNzYWdlID8/IG1zZztcbiAgaWYgKHR5cGVvZiBjb250ZW50ID09PSAnc3RyaW5nJykgcmV0dXJuIGNvbnRlbnQ7XG5cbiAgaWYgKEFycmF5LmlzQXJyYXkoY29udGVudCkpIHtcbiAgICBjb25zdCBwYXJ0cyA9IGNvbnRlbnRcbiAgICAgIC5maWx0ZXIoKGMpID0+IGMgJiYgdHlwZW9mIGMgPT09ICdvYmplY3QnICYmIGMudHlwZSA9PT0gJ3RleHQnICYmIHR5cGVvZiBjLnRleHQgPT09ICdzdHJpbmcnKVxuICAgICAgLm1hcCgoYykgPT4gYy50ZXh0KTtcbiAgICByZXR1cm4gcGFydHMuam9pbignXFxuJyk7XG4gIH1cblxuICAvLyBGYWxsYmFja1xuICB0cnkge1xuICAgIHJldHVybiBKU09OLnN0cmluZ2lmeShjb250ZW50KTtcbiAgfSBjYXRjaCB7XG4gICAgcmV0dXJuIFN0cmluZyhjb250ZW50KTtcbiAgfVxufVxuXG5mdW5jdGlvbiBzZXNzaW9uS2V5TWF0Y2hlcyhjb25maWd1cmVkOiBzdHJpbmcsIGluY29taW5nOiBzdHJpbmcpOiBib29sZWFuIHtcbiAgaWYgKGluY29taW5nID09PSBjb25maWd1cmVkKSByZXR1cm4gdHJ1ZTtcbiAgLy8gT3BlbkNsYXcgcmVzb2x2ZXMgXCJtYWluXCIgdG8gY2Fub25pY2FsIHNlc3Npb24ga2V5IGxpa2UgXCJhZ2VudDptYWluOm1haW5cIi5cbiAgaWYgKGNvbmZpZ3VyZWQgPT09ICdtYWluJyAmJiBpbmNvbWluZyA9PT0gJ2FnZW50Om1haW46bWFpbicpIHJldHVybiB0cnVlO1xuICByZXR1cm4gZmFsc2U7XG59XG5cbmV4cG9ydCBjbGFzcyBPYnNpZGlhbldTQ2xpZW50IHtcbiAgcHJpdmF0ZSB3czogV2ViU29ja2V0IHwgbnVsbCA9IG51bGw7XG4gIHByaXZhdGUgcmVjb25uZWN0VGltZXI6IFJldHVyblR5cGU8dHlwZW9mIHNldFRpbWVvdXQ+IHwgbnVsbCA9IG51bGw7XG4gIHByaXZhdGUgaGVhcnRiZWF0VGltZXI6IFJldHVyblR5cGU8dHlwZW9mIHNldEludGVydmFsPiB8IG51bGwgPSBudWxsO1xuICBwcml2YXRlIHdvcmtpbmdUaW1lcjogUmV0dXJuVHlwZTx0eXBlb2Ygc2V0VGltZW91dD4gfCBudWxsID0gbnVsbDtcbiAgcHJpdmF0ZSBpbnRlbnRpb25hbENsb3NlID0gZmFsc2U7XG4gIHByaXZhdGUgc2Vzc2lvbktleTogc3RyaW5nO1xuICBwcml2YXRlIHVybCA9ICcnO1xuICBwcml2YXRlIHRva2VuID0gJyc7XG4gIHByaXZhdGUgcmVxdWVzdElkID0gMDtcbiAgcHJpdmF0ZSBwZW5kaW5nUmVxdWVzdHMgPSBuZXcgTWFwPHN0cmluZywgUGVuZGluZ1JlcXVlc3Q+KCk7XG4gIHByaXZhdGUgd29ya2luZyA9IGZhbHNlO1xuXG4gIC8qKiBUaGUgbGFzdCBpbi1mbGlnaHQgY2hhdCBydW4gaWQuIEluIE9wZW5DbGF3IFdlYkNoYXQgdGhpcyBtYXBzIHRvIGNoYXQuc2VuZCBpZGVtcG90ZW5jeUtleS4gKi9cbiAgcHJpdmF0ZSBhY3RpdmVSdW5JZDogc3RyaW5nIHwgbnVsbCA9IG51bGw7XG5cbiAgLyoqIFByZXZlbnRzIGFib3J0IHNwYW1taW5nOiB3aGlsZSBhbiBhYm9ydCByZXF1ZXN0IGlzIGluLWZsaWdodCwgcmV1c2UgdGhlIHNhbWUgcHJvbWlzZS4gKi9cbiAgcHJpdmF0ZSBhYm9ydEluRmxpZ2h0OiBQcm9taXNlPGJvb2xlYW4+IHwgbnVsbCA9IG51bGw7XG5cbiAgc3RhdGU6IFdTQ2xpZW50U3RhdGUgPSAnZGlzY29ubmVjdGVkJztcblxuICBvbk1lc3NhZ2U6ICgobXNnOiBJbmJvdW5kV1NQYXlsb2FkKSA9PiB2b2lkKSB8IG51bGwgPSBudWxsO1xuICBvblN0YXRlQ2hhbmdlOiAoKHN0YXRlOiBXU0NsaWVudFN0YXRlKSA9PiB2b2lkKSB8IG51bGwgPSBudWxsO1xuICBvbldvcmtpbmdDaGFuZ2U6IFdvcmtpbmdTdGF0ZUxpc3RlbmVyIHwgbnVsbCA9IG51bGw7XG5cbiAgcHJpdmF0ZSBpZGVudGl0eVN0b3JlOiBEZXZpY2VJZGVudGl0eVN0b3JlIHwgdW5kZWZpbmVkO1xuICBwcml2YXRlIGFsbG93SW5zZWN1cmVXcyA9IGZhbHNlO1xuXG4gIHByaXZhdGUgcmVjb25uZWN0QXR0ZW1wdCA9IDA7XG5cbiAgY29uc3RydWN0b3Ioc2Vzc2lvbktleTogc3RyaW5nLCBvcHRzPzogeyBpZGVudGl0eVN0b3JlPzogRGV2aWNlSWRlbnRpdHlTdG9yZTsgYWxsb3dJbnNlY3VyZVdzPzogYm9vbGVhbiB9KSB7XG4gICAgdGhpcy5zZXNzaW9uS2V5ID0gc2Vzc2lvbktleTtcbiAgICB0aGlzLmlkZW50aXR5U3RvcmUgPSBvcHRzPy5pZGVudGl0eVN0b3JlO1xuICAgIHRoaXMuYWxsb3dJbnNlY3VyZVdzID0gQm9vbGVhbihvcHRzPy5hbGxvd0luc2VjdXJlV3MpO1xuICB9XG5cbiAgY29ubmVjdCh1cmw6IHN0cmluZywgdG9rZW46IHN0cmluZywgb3B0cz86IHsgYWxsb3dJbnNlY3VyZVdzPzogYm9vbGVhbiB9KTogdm9pZCB7XG4gICAgdGhpcy51cmwgPSB1cmw7XG4gICAgdGhpcy50b2tlbiA9IHRva2VuO1xuICAgIHRoaXMuYWxsb3dJbnNlY3VyZVdzID0gQm9vbGVhbihvcHRzPy5hbGxvd0luc2VjdXJlV3MgPz8gdGhpcy5hbGxvd0luc2VjdXJlV3MpO1xuICAgIHRoaXMuaW50ZW50aW9uYWxDbG9zZSA9IGZhbHNlO1xuXG4gICAgLy8gU2VjdXJpdHk6IGJsb2NrIG5vbi1sb2NhbCB3czovLyB1bmxlc3MgZXhwbGljaXRseSBhbGxvd2VkLlxuICAgIGNvbnN0IHBhcnNlZCA9IHNhZmVQYXJzZVdzVXJsKHVybCk7XG4gICAgaWYgKCFwYXJzZWQub2spIHtcbiAgICAgIHRoaXMub25NZXNzYWdlPy4oeyB0eXBlOiAnZXJyb3InLCBwYXlsb2FkOiB7IG1lc3NhZ2U6IHBhcnNlZC5lcnJvciB9IH0pO1xuICAgICAgcmV0dXJuO1xuICAgIH1cbiAgICBpZiAocGFyc2VkLnNjaGVtZSA9PT0gJ3dzJyAmJiAhaXNMb2NhbEhvc3QocGFyc2VkLmhvc3QpICYmICF0aGlzLmFsbG93SW5zZWN1cmVXcykge1xuICAgICAgdGhpcy5vbk1lc3NhZ2U/Lih7XG4gICAgICAgIHR5cGU6ICdlcnJvcicsXG4gICAgICAgIHBheWxvYWQ6IHsgbWVzc2FnZTogJ1JlZnVzaW5nIGluc2VjdXJlIHdzOi8vIHRvIG5vbi1sb2NhbCBnYXRld2F5LiBVc2Ugd3NzOi8vIG9yIGVuYWJsZSB0aGUgdW5zYWZlIG92ZXJyaWRlIGluIHNldHRpbmdzLicgfSxcbiAgICAgIH0pO1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIHRoaXMuX2Nvbm5lY3QoKTtcbiAgfVxuXG4gIGRpc2Nvbm5lY3QoKTogdm9pZCB7XG4gICAgdGhpcy5pbnRlbnRpb25hbENsb3NlID0gdHJ1ZTtcbiAgICB0aGlzLl9zdG9wVGltZXJzKCk7XG4gICAgdGhpcy5hY3RpdmVSdW5JZCA9IG51bGw7XG4gICAgdGhpcy5hYm9ydEluRmxpZ2h0ID0gbnVsbDtcbiAgICB0aGlzLl9zZXRXb3JraW5nKGZhbHNlKTtcbiAgICBpZiAodGhpcy53cykge1xuICAgICAgdGhpcy53cy5jbG9zZSgpO1xuICAgICAgdGhpcy53cyA9IG51bGw7XG4gICAgfVxuICAgIHRoaXMuX3NldFN0YXRlKCdkaXNjb25uZWN0ZWQnKTtcbiAgfVxuXG4gIHNldFNlc3Npb25LZXkoc2Vzc2lvbktleTogc3RyaW5nKTogdm9pZCB7XG4gICAgdGhpcy5zZXNzaW9uS2V5ID0gc2Vzc2lvbktleS50cmltKCk7XG4gICAgLy8gUmVzZXQgcGVyLXNlc3Npb24gcnVuIHN0YXRlLlxuICAgIHRoaXMuYWN0aXZlUnVuSWQgPSBudWxsO1xuICAgIHRoaXMuYWJvcnRJbkZsaWdodCA9IG51bGw7XG4gICAgdGhpcy5fc2V0V29ya2luZyhmYWxzZSk7XG4gIH1cblxuICAvLyBOT1RFOiBjYW5vbmljYWwgT2JzaWRpYW4gc2Vzc2lvbiBrZXlzIGRvIG5vdCByZXF1aXJlIGdhdGV3YXkgc2Vzc2lvbnMubGlzdCBmb3IgY29yZSBVWC5cblxuICBhc3luYyBzZW5kTWVzc2FnZShtZXNzYWdlOiBzdHJpbmcpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBpZiAodGhpcy5zdGF0ZSAhPT0gJ2Nvbm5lY3RlZCcpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcignTm90IGNvbm5lY3RlZCBcdTIwMTQgY2FsbCBjb25uZWN0KCkgZmlyc3QnKTtcbiAgICB9XG5cbiAgICBjb25zdCBydW5JZCA9IGBvYnNpZGlhbi0ke0RhdGUubm93KCl9LSR7TWF0aC5yYW5kb20oKS50b1N0cmluZygzNikuc2xpY2UoMiwgOSl9YDtcblxuICAgIC8vIFNob3cgXHUyMDFDd29ya2luZ1x1MjAxRCBPTkxZIGFmdGVyIHRoZSBnYXRld2F5IGFja25vd2xlZGdlcyB0aGUgcmVxdWVzdC5cbiAgICBjb25zdCBhY2sgPSBhd2FpdCB0aGlzLl9zZW5kUmVxdWVzdCgnY2hhdC5zZW5kJywge1xuICAgICAgc2Vzc2lvbktleTogdGhpcy5zZXNzaW9uS2V5LFxuICAgICAgbWVzc2FnZSxcbiAgICAgIGlkZW1wb3RlbmN5S2V5OiBydW5JZCxcbiAgICAgIC8vIGRlbGl2ZXIgZGVmYXVsdHMgdG8gdHJ1ZSBpbiBnYXRld2F5OyBrZWVwIGRlZmF1bHRcbiAgICB9KTtcblxuICAgIC8vIElmIHRoZSBnYXRld2F5IHJldHVybnMgYSBjYW5vbmljYWwgcnVuIGlkZW50aWZpZXIsIHByZWZlciBpdC5cbiAgICBjb25zdCBjYW5vbmljYWxSdW5JZCA9IFN0cmluZyhhY2s/LnJ1bklkIHx8IGFjaz8uaWRlbXBvdGVuY3lLZXkgfHwgJycpO1xuICAgIHRoaXMuYWN0aXZlUnVuSWQgPSBjYW5vbmljYWxSdW5JZCB8fCBydW5JZDtcbiAgICB0aGlzLl9zZXRXb3JraW5nKHRydWUpO1xuICAgIHRoaXMuX2FybVdvcmtpbmdTYWZldHlUaW1lb3V0KCk7XG4gIH1cblxuICAvKiogQWJvcnQgdGhlIGFjdGl2ZSBydW4gZm9yIHRoaXMgc2Vzc2lvbiAoYW5kIG91ciBsYXN0IHJ1biBpZCBpZiBwcmVzZW50KS4gKi9cbiAgYXN5bmMgYWJvcnRBY3RpdmVSdW4oKTogUHJvbWlzZTxib29sZWFuPiB7XG4gICAgaWYgKHRoaXMuc3RhdGUgIT09ICdjb25uZWN0ZWQnKSB7XG4gICAgICByZXR1cm4gZmFsc2U7XG4gICAgfVxuXG4gICAgLy8gUHJldmVudCByZXF1ZXN0IHN0b3Jtczogd2hpbGUgb25lIGFib3J0IGlzIGluIGZsaWdodCwgcmV1c2UgaXQuXG4gICAgaWYgKHRoaXMuYWJvcnRJbkZsaWdodCkge1xuICAgICAgcmV0dXJuIHRoaXMuYWJvcnRJbkZsaWdodDtcbiAgICB9XG5cbiAgICBjb25zdCBydW5JZCA9IHRoaXMuYWN0aXZlUnVuSWQ7XG4gICAgaWYgKCFydW5JZCkge1xuICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH1cblxuICAgIHRoaXMuYWJvcnRJbkZsaWdodCA9IChhc3luYyAoKSA9PiB7XG4gICAgICB0cnkge1xuICAgICAgICBhd2FpdCB0aGlzLl9zZW5kUmVxdWVzdCgnY2hhdC5hYm9ydCcsIHsgc2Vzc2lvbktleTogdGhpcy5zZXNzaW9uS2V5LCBydW5JZCB9KTtcbiAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICB9IGNhdGNoIChlcnIpIHtcbiAgICAgICAgY29uc29sZS5lcnJvcignW29jbGF3LXdzXSBjaGF0LmFib3J0IGZhaWxlZCcsIGVycik7XG4gICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgIH0gZmluYWxseSB7XG4gICAgICAgIC8vIEFsd2F5cyByZXN0b3JlIFVJIHN0YXRlIGltbWVkaWF0ZWx5OyB0aGUgZ2F0ZXdheSBtYXkgc3RpbGwgZW1pdCBhbiBhYm9ydGVkIGV2ZW50IGxhdGVyLlxuICAgICAgICB0aGlzLmFjdGl2ZVJ1bklkID0gbnVsbDtcbiAgICAgICAgdGhpcy5fc2V0V29ya2luZyhmYWxzZSk7XG4gICAgICAgIHRoaXMuYWJvcnRJbkZsaWdodCA9IG51bGw7XG4gICAgICB9XG4gICAgfSkoKTtcblxuICAgIHJldHVybiB0aGlzLmFib3J0SW5GbGlnaHQ7XG4gIH1cblxuICBwcml2YXRlIF9jb25uZWN0KCk6IHZvaWQge1xuICAgIGlmICh0aGlzLndzKSB7XG4gICAgICB0aGlzLndzLm9ub3BlbiA9IG51bGw7XG4gICAgICB0aGlzLndzLm9uY2xvc2UgPSBudWxsO1xuICAgICAgdGhpcy53cy5vbm1lc3NhZ2UgPSBudWxsO1xuICAgICAgdGhpcy53cy5vbmVycm9yID0gbnVsbDtcbiAgICAgIHRoaXMud3MuY2xvc2UoKTtcbiAgICAgIHRoaXMud3MgPSBudWxsO1xuICAgIH1cblxuICAgIHRoaXMuX3NldFN0YXRlKCdjb25uZWN0aW5nJyk7XG5cbiAgICBjb25zdCB3cyA9IG5ldyBXZWJTb2NrZXQodGhpcy51cmwpO1xuICAgIHRoaXMud3MgPSB3cztcblxuICAgIGxldCBjb25uZWN0Tm9uY2U6IHN0cmluZyB8IG51bGwgPSBudWxsO1xuICAgIGxldCBjb25uZWN0U3RhcnRlZCA9IGZhbHNlO1xuXG4gICAgY29uc3QgdHJ5Q29ubmVjdCA9IGFzeW5jICgpID0+IHtcbiAgICAgIGlmIChjb25uZWN0U3RhcnRlZCkgcmV0dXJuO1xuICAgICAgaWYgKCFjb25uZWN0Tm9uY2UpIHJldHVybjtcbiAgICAgIGNvbm5lY3RTdGFydGVkID0gdHJ1ZTtcblxuICAgICAgdHJ5IHtcbiAgICAgICAgY29uc3QgaWRlbnRpdHkgPSBhd2FpdCBsb2FkT3JDcmVhdGVEZXZpY2VJZGVudGl0eSh0aGlzLmlkZW50aXR5U3RvcmUpO1xuICAgICAgICBjb25zdCBzaWduZWRBdE1zID0gRGF0ZS5ub3coKTtcbiAgICAgICAgY29uc3QgcGF5bG9hZCA9IGJ1aWxkRGV2aWNlQXV0aFBheWxvYWQoe1xuICAgICAgICAgIGRldmljZUlkOiBpZGVudGl0eS5pZCxcbiAgICAgICAgICBjbGllbnRJZDogJ2dhdGV3YXktY2xpZW50JyxcbiAgICAgICAgICBjbGllbnRNb2RlOiAnYmFja2VuZCcsXG4gICAgICAgICAgcm9sZTogJ29wZXJhdG9yJyxcbiAgICAgICAgICBzY29wZXM6IFsnb3BlcmF0b3IucmVhZCcsICdvcGVyYXRvci53cml0ZSddLFxuICAgICAgICAgIHNpZ25lZEF0TXMsXG4gICAgICAgICAgdG9rZW46IHRoaXMudG9rZW4sXG4gICAgICAgICAgbm9uY2U6IGNvbm5lY3ROb25jZSxcbiAgICAgICAgfSk7XG4gICAgICAgIGNvbnN0IHNpZyA9IGF3YWl0IHNpZ25EZXZpY2VQYXlsb2FkKGlkZW50aXR5LCBwYXlsb2FkKTtcblxuICAgICAgICBjb25zdCBhY2sgPSBhd2FpdCB0aGlzLl9zZW5kUmVxdWVzdCgnY29ubmVjdCcsIHtcbiAgICAgICAgICAgbWluUHJvdG9jb2w6IDMsXG4gICAgICAgICAgIG1heFByb3RvY29sOiAzLFxuICAgICAgICAgICBjbGllbnQ6IHtcbiAgICAgICAgICAgICBpZDogJ2dhdGV3YXktY2xpZW50JyxcbiAgICAgICAgICAgICBtb2RlOiAnYmFja2VuZCcsXG4gICAgICAgICAgICAgdmVyc2lvbjogJzAuMS4xMCcsXG4gICAgICAgICAgICAgcGxhdGZvcm06ICdlbGVjdHJvbicsXG4gICAgICAgICAgIH0sXG4gICAgICAgICAgIHJvbGU6ICdvcGVyYXRvcicsXG4gICAgICAgICAgIHNjb3BlczogWydvcGVyYXRvci5yZWFkJywgJ29wZXJhdG9yLndyaXRlJ10sXG4gICAgICAgICAgIGRldmljZToge1xuICAgICAgICAgICAgIGlkOiBpZGVudGl0eS5pZCxcbiAgICAgICAgICAgICBwdWJsaWNLZXk6IGlkZW50aXR5LnB1YmxpY0tleSxcbiAgICAgICAgICAgICBzaWduYXR1cmU6IHNpZy5zaWduYXR1cmUsXG4gICAgICAgICAgICAgc2lnbmVkQXQ6IHNpZ25lZEF0TXMsXG4gICAgICAgICAgICAgbm9uY2U6IGNvbm5lY3ROb25jZSxcbiAgICAgICAgICAgfSxcbiAgICAgICAgICAgYXV0aDoge1xuICAgICAgICAgICAgIHRva2VuOiB0aGlzLnRva2VuLFxuICAgICAgICAgICB9LFxuICAgICAgICAgfSk7XG5cbiAgICAgICAgIHRoaXMuX3NldFN0YXRlKCdjb25uZWN0ZWQnKTtcbiAgICAgICAgIHRoaXMucmVjb25uZWN0QXR0ZW1wdCA9IDA7XG4gICAgICAgICBpZiAoaGFuZHNoYWtlVGltZXIpIHtcbiAgICAgICAgICAgY2xlYXJUaW1lb3V0KGhhbmRzaGFrZVRpbWVyKTtcbiAgICAgICAgICAgaGFuZHNoYWtlVGltZXIgPSBudWxsO1xuICAgICAgICAgfVxuICAgICAgICAgdGhpcy5fc3RhcnRIZWFydGJlYXQoKTtcbiAgICAgIH0gY2F0Y2ggKGVycikge1xuICAgICAgICBjb25zb2xlLmVycm9yKCdbb2NsYXctd3NdIENvbm5lY3QgaGFuZHNoYWtlIGZhaWxlZCcsIGVycik7XG4gICAgICAgIHdzLmNsb3NlKCk7XG4gICAgICB9XG4gICAgfTtcblxuICAgIGxldCBoYW5kc2hha2VUaW1lcjogUmV0dXJuVHlwZTx0eXBlb2Ygc2V0VGltZW91dD4gfCBudWxsID0gbnVsbDtcblxuICAgIHdzLm9ub3BlbiA9ICgpID0+IHtcbiAgICAgIHRoaXMuX3NldFN0YXRlKCdoYW5kc2hha2luZycpO1xuICAgICAgLy8gVGhlIGdhdGV3YXkgd2lsbCBzZW5kIGNvbm5lY3QuY2hhbGxlbmdlOyBjb25uZWN0IGlzIHNlbnQgb25jZSB3ZSBoYXZlIGEgbm9uY2UuXG4gICAgICBpZiAoaGFuZHNoYWtlVGltZXIpIGNsZWFyVGltZW91dChoYW5kc2hha2VUaW1lcik7XG4gICAgICBoYW5kc2hha2VUaW1lciA9IHNldFRpbWVvdXQoKCkgPT4ge1xuICAgICAgICAvLyBJZiB3ZSBuZXZlciBnb3QgdGhlIGNoYWxsZW5nZSBub25jZSwgZm9yY2UgcmVjb25uZWN0LlxuICAgICAgICBpZiAodGhpcy5zdGF0ZSA9PT0gJ2hhbmRzaGFraW5nJyAmJiAhdGhpcy5pbnRlbnRpb25hbENsb3NlKSB7XG4gICAgICAgICAgY29uc29sZS53YXJuKCdbb2NsYXctd3NdIEhhbmRzaGFrZSB0aW1lZCBvdXQgd2FpdGluZyBmb3IgY29ubmVjdC5jaGFsbGVuZ2UnKTtcbiAgICAgICAgICB3cy5jbG9zZSgpO1xuICAgICAgICB9XG4gICAgICB9LCBIQU5EU0hBS0VfVElNRU9VVF9NUyk7XG4gICAgfTtcblxuICAgIHdzLm9ubWVzc2FnZSA9IChldmVudDogTWVzc2FnZUV2ZW50KSA9PiB7XG4gICAgICAvLyBXZWJTb2NrZXQgb25tZXNzYWdlIGNhbm5vdCBiZSBhc3luYywgYnV0IHdlIGNhbiBydW4gYW4gYXN5bmMgdGFzayBpbnNpZGUuXG4gICAgICB2b2lkIChhc3luYyAoKSA9PiB7XG4gICAgICAgIGNvbnN0IG5vcm1hbGl6ZWQgPSBhd2FpdCBub3JtYWxpemVXc0RhdGFUb1RleHQoZXZlbnQuZGF0YSk7XG4gICAgICAgIGlmICghbm9ybWFsaXplZC5vaykge1xuICAgICAgICAgIGlmIChub3JtYWxpemVkLnJlYXNvbiA9PT0gJ3Rvby1sYXJnZScpIHtcbiAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IoJ1tvY2xhdy13c10gSW5ib3VuZCBmcmFtZSB0b28gbGFyZ2U7IGNsb3NpbmcgY29ubmVjdGlvbicpO1xuICAgICAgICAgICAgd3MuY2xvc2UoKTtcbiAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgY29uc29sZS5lcnJvcignW29jbGF3LXdzXSBVbnN1cHBvcnRlZCBpbmJvdW5kIGZyYW1lIHR5cGU7IGlnbm9yaW5nJyk7XG4gICAgICAgICAgfVxuICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmIChub3JtYWxpemVkLmJ5dGVzID4gTUFYX0lOQk9VTkRfRlJBTUVfQllURVMpIHtcbiAgICAgICAgICBjb25zb2xlLmVycm9yKCdbb2NsYXctd3NdIEluYm91bmQgZnJhbWUgdG9vIGxhcmdlOyBjbG9zaW5nIGNvbm5lY3Rpb24nKTtcbiAgICAgICAgICB3cy5jbG9zZSgpO1xuICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIGxldCBmcmFtZTogYW55O1xuICAgICAgICB0cnkge1xuICAgICAgICAgIGZyYW1lID0gSlNPTi5wYXJzZShub3JtYWxpemVkLnRleHQpO1xuICAgICAgICB9IGNhdGNoIHtcbiAgICAgICAgICBjb25zb2xlLmVycm9yKCdbb2NsYXctd3NdIEZhaWxlZCB0byBwYXJzZSBpbmNvbWluZyBtZXNzYWdlJyk7XG4gICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgLy8gUmVzcG9uc2VzXG4gICAgICAgIGlmIChmcmFtZS50eXBlID09PSAncmVzJykge1xuICAgICAgICAgIHRoaXMuX2hhbmRsZVJlc3BvbnNlRnJhbWUoZnJhbWUpO1xuICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIC8vIEV2ZW50c1xuICAgICAgICBpZiAoZnJhbWUudHlwZSA9PT0gJ2V2ZW50Jykge1xuICAgICAgICAgIGlmIChmcmFtZS5ldmVudCA9PT0gJ2Nvbm5lY3QuY2hhbGxlbmdlJykge1xuICAgICAgICAgICAgY29ubmVjdE5vbmNlID0gZnJhbWUucGF5bG9hZD8ubm9uY2UgfHwgbnVsbDtcbiAgICAgICAgICAgIC8vIEF0dGVtcHQgaGFuZHNoYWtlIG9uY2Ugd2UgaGF2ZSBhIG5vbmNlLlxuICAgICAgICAgICAgdm9pZCB0cnlDb25uZWN0KCk7XG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgaWYgKGZyYW1lLmV2ZW50ID09PSAnY2hhdCcpIHtcbiAgICAgICAgICAgIHRoaXMuX2hhbmRsZUNoYXRFdmVudEZyYW1lKGZyYW1lKTtcbiAgICAgICAgICB9XG4gICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgLy8gQXZvaWQgbG9nZ2luZyBmdWxsIGZyYW1lcyAobWF5IGluY2x1ZGUgbWVzc2FnZSBjb250ZW50IG9yIG90aGVyIHNlbnNpdGl2ZSBwYXlsb2FkcykuXG4gICAgICAgIGNvbnNvbGUuZGVidWcoJ1tvY2xhdy13c10gVW5oYW5kbGVkIGZyYW1lJywgeyB0eXBlOiBmcmFtZT8udHlwZSwgZXZlbnQ6IGZyYW1lPy5ldmVudCwgaWQ6IGZyYW1lPy5pZCB9KTtcbiAgICAgIH0pKCk7XG4gICAgfTtcblxuICAgIGNvbnN0IGNsZWFySGFuZHNoYWtlVGltZXIgPSAoKSA9PiB7XG4gICAgICBpZiAoaGFuZHNoYWtlVGltZXIpIHtcbiAgICAgICAgY2xlYXJUaW1lb3V0KGhhbmRzaGFrZVRpbWVyKTtcbiAgICAgICAgaGFuZHNoYWtlVGltZXIgPSBudWxsO1xuICAgICAgfVxuICAgIH07XG5cbiAgICB3cy5vbmNsb3NlID0gKCkgPT4ge1xuICAgICAgY2xlYXJIYW5kc2hha2VUaW1lcigpO1xuICAgICAgdGhpcy5fc3RvcFRpbWVycygpO1xuICAgICAgdGhpcy5hY3RpdmVSdW5JZCA9IG51bGw7XG4gICAgICB0aGlzLmFib3J0SW5GbGlnaHQgPSBudWxsO1xuICAgICAgdGhpcy5fc2V0V29ya2luZyhmYWxzZSk7XG4gICAgICB0aGlzLl9zZXRTdGF0ZSgnZGlzY29ubmVjdGVkJyk7XG5cbiAgICAgIGZvciAoY29uc3QgcGVuZGluZyBvZiB0aGlzLnBlbmRpbmdSZXF1ZXN0cy52YWx1ZXMoKSkge1xuICAgICAgICBpZiAocGVuZGluZy50aW1lb3V0KSBjbGVhclRpbWVvdXQocGVuZGluZy50aW1lb3V0KTtcbiAgICAgICAgcGVuZGluZy5yZWplY3QobmV3IEVycm9yKCdDb25uZWN0aW9uIGNsb3NlZCcpKTtcbiAgICAgIH1cbiAgICAgIHRoaXMucGVuZGluZ1JlcXVlc3RzLmNsZWFyKCk7XG5cbiAgICAgIGlmICghdGhpcy5pbnRlbnRpb25hbENsb3NlKSB7XG4gICAgICAgIHRoaXMuX3NjaGVkdWxlUmVjb25uZWN0KCk7XG4gICAgICB9XG4gICAgfTtcblxuICAgIHdzLm9uZXJyb3IgPSAoZXY6IEV2ZW50KSA9PiB7XG4gICAgICBjbGVhckhhbmRzaGFrZVRpbWVyKCk7XG4gICAgICBjb25zb2xlLmVycm9yKCdbb2NsYXctd3NdIFdlYlNvY2tldCBlcnJvcicsIGV2KTtcbiAgICB9O1xuICB9XG5cbiAgcHJpdmF0ZSBfaGFuZGxlUmVzcG9uc2VGcmFtZShmcmFtZTogYW55KTogdm9pZCB7XG4gICAgY29uc3QgcGVuZGluZyA9IHRoaXMucGVuZGluZ1JlcXVlc3RzLmdldChmcmFtZS5pZCk7XG4gICAgaWYgKCFwZW5kaW5nKSByZXR1cm47XG5cbiAgICB0aGlzLnBlbmRpbmdSZXF1ZXN0cy5kZWxldGUoZnJhbWUuaWQpO1xuICAgIGlmIChwZW5kaW5nLnRpbWVvdXQpIGNsZWFyVGltZW91dChwZW5kaW5nLnRpbWVvdXQpO1xuXG4gICAgaWYgKGZyYW1lLm9rKSBwZW5kaW5nLnJlc29sdmUoZnJhbWUucGF5bG9hZCk7XG4gICAgZWxzZSBwZW5kaW5nLnJlamVjdChuZXcgRXJyb3IoZnJhbWUuZXJyb3I/Lm1lc3NhZ2UgfHwgJ1JlcXVlc3QgZmFpbGVkJykpO1xuICB9XG5cbiAgcHJpdmF0ZSBfaGFuZGxlQ2hhdEV2ZW50RnJhbWUoZnJhbWU6IGFueSk6IHZvaWQge1xuICAgIGNvbnN0IHBheWxvYWQgPSBmcmFtZS5wYXlsb2FkO1xuICAgIGNvbnN0IGluY29taW5nU2Vzc2lvbktleSA9IFN0cmluZyhwYXlsb2FkPy5zZXNzaW9uS2V5IHx8ICcnKTtcbiAgICBpZiAoIWluY29taW5nU2Vzc2lvbktleSB8fCAhc2Vzc2lvbktleU1hdGNoZXModGhpcy5zZXNzaW9uS2V5LCBpbmNvbWluZ1Nlc3Npb25LZXkpKSB7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgLy8gQmVzdC1lZmZvcnQgcnVuIGNvcnJlbGF0aW9uIChpZiBnYXRld2F5IGluY2x1ZGVzIGEgcnVuIGlkKS4gVGhpcyBhdm9pZHMgY2xlYXJpbmcgb3VyIFVJXG4gICAgLy8gYmFzZWQgb24gYSBkaWZmZXJlbnQgY2xpZW50J3MgcnVuIGluIHRoZSBzYW1lIHNlc3Npb24uXG4gICAgY29uc3QgaW5jb21pbmdSdW5JZCA9IFN0cmluZyhwYXlsb2FkPy5ydW5JZCB8fCBwYXlsb2FkPy5pZGVtcG90ZW5jeUtleSB8fCBwYXlsb2FkPy5tZXRhPy5ydW5JZCB8fCAnJyk7XG4gICAgaWYgKHRoaXMuYWN0aXZlUnVuSWQgJiYgaW5jb21pbmdSdW5JZCAmJiBpbmNvbWluZ1J1bklkICE9PSB0aGlzLmFjdGl2ZVJ1bklkKSB7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgLy8gQXZvaWQgZG91YmxlLXJlbmRlcjogZ2F0ZXdheSBlbWl0cyBkZWx0YSArIGZpbmFsICsgYWJvcnRlZC4gUmVuZGVyIG9ubHkgZXhwbGljaXQgZmluYWwvYWJvcnRlZC5cbiAgICAvLyBJZiBzdGF0ZSBpcyBtaXNzaW5nLCB0cmVhdCBhcyBub24tdGVybWluYWwgKGRvIG5vdCBjbGVhciBVSSAvIGRvIG5vdCByZW5kZXIpLlxuICAgIGlmICghcGF5bG9hZD8uc3RhdGUpIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG4gICAgaWYgKHBheWxvYWQuc3RhdGUgIT09ICdmaW5hbCcgJiYgcGF5bG9hZC5zdGF0ZSAhPT0gJ2Fib3J0ZWQnKSB7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgLy8gV2Ugb25seSBhcHBlbmQgYXNzaXN0YW50IG91dHB1dCB0byBVSS5cbiAgICBjb25zdCBtc2cgPSBwYXlsb2FkPy5tZXNzYWdlO1xuICAgIGNvbnN0IHJvbGUgPSBtc2c/LnJvbGUgPz8gJ2Fzc2lzdGFudCc7XG5cbiAgICAvLyBBYm9ydGVkIGVuZHMgdGhlIHJ1biByZWdhcmRsZXNzIG9mIHJvbGUvbWVzc2FnZS5cbiAgICBpZiAocGF5bG9hZC5zdGF0ZSA9PT0gJ2Fib3J0ZWQnKSB7XG4gICAgICB0aGlzLmFjdGl2ZVJ1bklkID0gbnVsbDtcbiAgICAgIHRoaXMuX3NldFdvcmtpbmcoZmFsc2UpO1xuICAgICAgLy8gQWJvcnRlZCBtYXkgaGF2ZSBubyBhc3Npc3RhbnQgbWVzc2FnZTsgaWYgbm9uZSwgc3RvcCBoZXJlLlxuICAgICAgaWYgKCFtc2cpIHJldHVybjtcbiAgICAgIC8vIElmIHRoZXJlIGlzIGEgbWVzc2FnZSwgb25seSBhcHBlbmQgYXNzaXN0YW50IG91dHB1dC5cbiAgICAgIGlmIChyb2xlICE9PSAnYXNzaXN0YW50JykgcmV0dXJuO1xuICAgIH1cblxuICAgIC8vIEZpbmFsIHNob3VsZCBvbmx5IGNvbXBsZXRlIHRoZSBydW4gd2hlbiB0aGUgYXNzaXN0YW50IGNvbXBsZXRlcy5cbiAgICBpZiAocGF5bG9hZC5zdGF0ZSA9PT0gJ2ZpbmFsJykge1xuICAgICAgaWYgKHJvbGUgIT09ICdhc3Npc3RhbnQnKSByZXR1cm47XG4gICAgICB0aGlzLmFjdGl2ZVJ1bklkID0gbnVsbDtcbiAgICAgIHRoaXMuX3NldFdvcmtpbmcoZmFsc2UpO1xuICAgIH1cblxuICAgIGNvbnN0IHRleHQgPSBleHRyYWN0VGV4dEZyb21HYXRld2F5TWVzc2FnZShtc2cpO1xuICAgIGlmICghdGV4dCkgcmV0dXJuO1xuXG4gICAgLy8gT3B0aW9uYWw6IGhpZGUgaGVhcnRiZWF0IGFja3MgKG5vaXNlIGluIFVJKVxuICAgIGlmICh0ZXh0LnRyaW0oKSA9PT0gJ0hFQVJUQkVBVF9PSycpIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICB0aGlzLm9uTWVzc2FnZT8uKHtcbiAgICAgIHR5cGU6ICdtZXNzYWdlJyxcbiAgICAgIHBheWxvYWQ6IHtcbiAgICAgICAgY29udGVudDogdGV4dCxcbiAgICAgICAgcm9sZTogJ2Fzc2lzdGFudCcsXG4gICAgICAgIHRpbWVzdGFtcDogRGF0ZS5ub3coKSxcbiAgICAgIH0sXG4gICAgfSk7XG4gIH1cblxuICBwcml2YXRlIF9zZW5kUmVxdWVzdChtZXRob2Q6IHN0cmluZywgcGFyYW1zOiBhbnkpOiBQcm9taXNlPGFueT4ge1xuICAgIHJldHVybiBuZXcgUHJvbWlzZSgocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICBpZiAoIXRoaXMud3MgfHwgdGhpcy53cy5yZWFkeVN0YXRlICE9PSBXZWJTb2NrZXQuT1BFTikge1xuICAgICAgICByZWplY3QobmV3IEVycm9yKCdXZWJTb2NrZXQgbm90IGNvbm5lY3RlZCcpKTtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuXG4gICAgICBpZiAodGhpcy5wZW5kaW5nUmVxdWVzdHMuc2l6ZSA+PSBNQVhfUEVORElOR19SRVFVRVNUUykge1xuICAgICAgICByZWplY3QobmV3IEVycm9yKGBUb28gbWFueSBpbi1mbGlnaHQgcmVxdWVzdHMgKCR7dGhpcy5wZW5kaW5nUmVxdWVzdHMuc2l6ZX0pYCkpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG5cbiAgICAgIGNvbnN0IGlkID0gYHJlcS0keysrdGhpcy5yZXF1ZXN0SWR9YDtcblxuICAgICAgY29uc3QgcGVuZGluZzogUGVuZGluZ1JlcXVlc3QgPSB7IHJlc29sdmUsIHJlamVjdCwgdGltZW91dDogbnVsbCB9O1xuICAgICAgdGhpcy5wZW5kaW5nUmVxdWVzdHMuc2V0KGlkLCBwZW5kaW5nKTtcblxuICAgICAgY29uc3QgcGF5bG9hZCA9IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdHlwZTogJ3JlcScsXG4gICAgICAgIG1ldGhvZCxcbiAgICAgICAgaWQsXG4gICAgICAgIHBhcmFtcyxcbiAgICAgIH0pO1xuXG4gICAgICB0cnkge1xuICAgICAgICB0aGlzLndzLnNlbmQocGF5bG9hZCk7XG4gICAgICB9IGNhdGNoIChlcnIpIHtcbiAgICAgICAgdGhpcy5wZW5kaW5nUmVxdWVzdHMuZGVsZXRlKGlkKTtcbiAgICAgICAgcmVqZWN0KGVycik7XG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cblxuICAgICAgcGVuZGluZy50aW1lb3V0ID0gc2V0VGltZW91dCgoKSA9PiB7XG4gICAgICAgIGlmICh0aGlzLnBlbmRpbmdSZXF1ZXN0cy5oYXMoaWQpKSB7XG4gICAgICAgICAgdGhpcy5wZW5kaW5nUmVxdWVzdHMuZGVsZXRlKGlkKTtcbiAgICAgICAgICByZWplY3QobmV3IEVycm9yKGBSZXF1ZXN0IHRpbWVvdXQ6ICR7bWV0aG9kfWApKTtcbiAgICAgICAgfVxuICAgICAgfSwgMzBfMDAwKTtcbiAgICB9KTtcbiAgfVxuXG4gIHByaXZhdGUgX3NjaGVkdWxlUmVjb25uZWN0KCk6IHZvaWQge1xuICAgIGlmICh0aGlzLnJlY29ubmVjdFRpbWVyICE9PSBudWxsKSByZXR1cm47XG5cbiAgICBjb25zdCBhdHRlbXB0ID0gKyt0aGlzLnJlY29ubmVjdEF0dGVtcHQ7XG4gICAgY29uc3QgZXhwID0gTWF0aC5taW4oUkVDT05ORUNUX01BWF9NUywgUkVDT05ORUNUX0JBU0VfTVMgKiBNYXRoLnBvdygyLCBhdHRlbXB0IC0gMSkpO1xuICAgIC8vIEppdHRlcjogMC41eC4uMS41eFxuICAgIGNvbnN0IGppdHRlciA9IDAuNSArIE1hdGgucmFuZG9tKCk7XG4gICAgY29uc3QgZGVsYXkgPSBNYXRoLmZsb29yKGV4cCAqIGppdHRlcik7XG5cbiAgICB0aGlzLnJlY29ubmVjdFRpbWVyID0gc2V0VGltZW91dCgoKSA9PiB7XG4gICAgICB0aGlzLnJlY29ubmVjdFRpbWVyID0gbnVsbDtcbiAgICAgIGlmICghdGhpcy5pbnRlbnRpb25hbENsb3NlKSB7XG4gICAgICAgIGNvbnNvbGUubG9nKGBbb2NsYXctd3NdIFJlY29ubmVjdGluZyB0byAke3RoaXMudXJsfVx1MjAyNiAoYXR0ZW1wdCAke2F0dGVtcHR9LCAke2RlbGF5fW1zKWApO1xuICAgICAgICB0aGlzLl9jb25uZWN0KCk7XG4gICAgICB9XG4gICAgfSwgZGVsYXkpO1xuICB9XG5cbiAgcHJpdmF0ZSBsYXN0QnVmZmVyZWRXYXJuQXRNcyA9IDA7XG5cbiAgcHJpdmF0ZSBfc3RhcnRIZWFydGJlYXQoKTogdm9pZCB7XG4gICAgdGhpcy5fc3RvcEhlYXJ0YmVhdCgpO1xuICAgIHRoaXMuaGVhcnRiZWF0VGltZXIgPSBzZXRJbnRlcnZhbCgoKSA9PiB7XG4gICAgICBpZiAodGhpcy53cz8ucmVhZHlTdGF0ZSAhPT0gV2ViU29ja2V0Lk9QRU4pIHJldHVybjtcbiAgICAgIGlmICh0aGlzLndzLmJ1ZmZlcmVkQW1vdW50ID4gMCkge1xuICAgICAgICBjb25zdCBub3cgPSBEYXRlLm5vdygpO1xuICAgICAgICAvLyBUaHJvdHRsZSB0byBhdm9pZCBsb2cgc3BhbSBpbiBsb25nLXJ1bm5pbmcgc2Vzc2lvbnMuXG4gICAgICAgIGlmIChub3cgLSB0aGlzLmxhc3RCdWZmZXJlZFdhcm5BdE1zID4gNSAqIDYwXzAwMCkge1xuICAgICAgICAgIHRoaXMubGFzdEJ1ZmZlcmVkV2FybkF0TXMgPSBub3c7XG4gICAgICAgICAgY29uc29sZS53YXJuKCdbb2NsYXctd3NdIFNlbmQgYnVmZmVyIG5vdCBlbXB0eSBcdTIwMTQgY29ubmVjdGlvbiBtYXkgYmUgc3RhbGxlZCcpO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSwgSEVBUlRCRUFUX0lOVEVSVkFMX01TKTtcbiAgfVxuXG4gIHByaXZhdGUgX3N0b3BIZWFydGJlYXQoKTogdm9pZCB7XG4gICAgaWYgKHRoaXMuaGVhcnRiZWF0VGltZXIpIHtcbiAgICAgIGNsZWFySW50ZXJ2YWwodGhpcy5oZWFydGJlYXRUaW1lcik7XG4gICAgICB0aGlzLmhlYXJ0YmVhdFRpbWVyID0gbnVsbDtcbiAgICB9XG4gIH1cblxuICBwcml2YXRlIF9zdG9wVGltZXJzKCk6IHZvaWQge1xuICAgIHRoaXMuX3N0b3BIZWFydGJlYXQoKTtcbiAgICB0aGlzLl9kaXNhcm1Xb3JraW5nU2FmZXR5VGltZW91dCgpO1xuICAgIGlmICh0aGlzLnJlY29ubmVjdFRpbWVyKSB7XG4gICAgICBjbGVhclRpbWVvdXQodGhpcy5yZWNvbm5lY3RUaW1lcik7XG4gICAgICB0aGlzLnJlY29ubmVjdFRpbWVyID0gbnVsbDtcbiAgICB9XG4gIH1cblxuICBwcml2YXRlIF9zZXRTdGF0ZShzdGF0ZTogV1NDbGllbnRTdGF0ZSk6IHZvaWQge1xuICAgIGlmICh0aGlzLnN0YXRlID09PSBzdGF0ZSkgcmV0dXJuO1xuICAgIHRoaXMuc3RhdGUgPSBzdGF0ZTtcbiAgICB0aGlzLm9uU3RhdGVDaGFuZ2U/LihzdGF0ZSk7XG4gIH1cblxuICBwcml2YXRlIF9zZXRXb3JraW5nKHdvcmtpbmc6IGJvb2xlYW4pOiB2b2lkIHtcbiAgICBpZiAodGhpcy53b3JraW5nID09PSB3b3JraW5nKSByZXR1cm47XG4gICAgdGhpcy53b3JraW5nID0gd29ya2luZztcbiAgICB0aGlzLm9uV29ya2luZ0NoYW5nZT8uKHdvcmtpbmcpO1xuXG4gICAgaWYgKCF3b3JraW5nKSB7XG4gICAgICB0aGlzLl9kaXNhcm1Xb3JraW5nU2FmZXR5VGltZW91dCgpO1xuICAgIH1cbiAgfVxuXG4gIHByaXZhdGUgX2FybVdvcmtpbmdTYWZldHlUaW1lb3V0KCk6IHZvaWQge1xuICAgIHRoaXMuX2Rpc2FybVdvcmtpbmdTYWZldHlUaW1lb3V0KCk7XG4gICAgdGhpcy53b3JraW5nVGltZXIgPSBzZXRUaW1lb3V0KCgpID0+IHtcbiAgICAgIC8vIElmIHRoZSBnYXRld2F5IG5ldmVyIGVtaXRzIGFuIGFzc2lzdGFudCBmaW5hbCByZXNwb25zZSwgZG9uXHUyMDE5dCBsZWF2ZSBVSSBzdHVjay5cbiAgICAgIHRoaXMuX3NldFdvcmtpbmcoZmFsc2UpO1xuICAgIH0sIFdPUktJTkdfTUFYX01TKTtcbiAgfVxuXG4gIHByaXZhdGUgX2Rpc2FybVdvcmtpbmdTYWZldHlUaW1lb3V0KCk6IHZvaWQge1xuICAgIGlmICh0aGlzLndvcmtpbmdUaW1lcikge1xuICAgICAgY2xlYXJUaW1lb3V0KHRoaXMud29ya2luZ1RpbWVyKTtcbiAgICAgIHRoaXMud29ya2luZ1RpbWVyID0gbnVsbDtcbiAgICB9XG4gIH1cbn1cbiIsICJpbXBvcnQgdHlwZSB7IENoYXRNZXNzYWdlIH0gZnJvbSAnLi90eXBlcyc7XG5cbi8qKiBNYW5hZ2VzIHRoZSBpbi1tZW1vcnkgbGlzdCBvZiBjaGF0IG1lc3NhZ2VzIGFuZCBub3RpZmllcyBVSSBvbiBjaGFuZ2VzICovXG5leHBvcnQgY2xhc3MgQ2hhdE1hbmFnZXIge1xuICBwcml2YXRlIG1lc3NhZ2VzOiBDaGF0TWVzc2FnZVtdID0gW107XG5cbiAgLyoqIEZpcmVkIGZvciBhIGZ1bGwgcmUtcmVuZGVyIChjbGVhci9yZWxvYWQpICovXG4gIG9uVXBkYXRlOiAoKG1lc3NhZ2VzOiByZWFkb25seSBDaGF0TWVzc2FnZVtdKSA9PiB2b2lkKSB8IG51bGwgPSBudWxsO1xuICAvKiogRmlyZWQgd2hlbiBhIHNpbmdsZSBtZXNzYWdlIGlzIGFwcGVuZGVkIFx1MjAxNCB1c2UgZm9yIE8oMSkgYXBwZW5kLW9ubHkgVUkgKi9cbiAgb25NZXNzYWdlQWRkZWQ6ICgobXNnOiBDaGF0TWVzc2FnZSkgPT4gdm9pZCkgfCBudWxsID0gbnVsbDtcblxuICBhZGRNZXNzYWdlKG1zZzogQ2hhdE1lc3NhZ2UpOiB2b2lkIHtcbiAgICB0aGlzLm1lc3NhZ2VzLnB1c2gobXNnKTtcbiAgICB0aGlzLm9uTWVzc2FnZUFkZGVkPy4obXNnKTtcbiAgfVxuXG4gIGdldE1lc3NhZ2VzKCk6IHJlYWRvbmx5IENoYXRNZXNzYWdlW10ge1xuICAgIHJldHVybiB0aGlzLm1lc3NhZ2VzO1xuICB9XG5cbiAgY2xlYXIoKTogdm9pZCB7XG4gICAgdGhpcy5tZXNzYWdlcyA9IFtdO1xuICAgIHRoaXMub25VcGRhdGU/LihbXSk7XG4gIH1cblxuICAvKiogQ3JlYXRlIGEgdXNlciBtZXNzYWdlIG9iamVjdCAod2l0aG91dCBhZGRpbmcgaXQpICovXG4gIHN0YXRpYyBjcmVhdGVVc2VyTWVzc2FnZShjb250ZW50OiBzdHJpbmcpOiBDaGF0TWVzc2FnZSB7XG4gICAgcmV0dXJuIHtcbiAgICAgIGlkOiBgbXNnLSR7RGF0ZS5ub3coKX0tJHtNYXRoLnJhbmRvbSgpLnRvU3RyaW5nKDM2KS5zbGljZSgyLCA3KX1gLFxuICAgICAgcm9sZTogJ3VzZXInLFxuICAgICAgY29udGVudCxcbiAgICAgIHRpbWVzdGFtcDogRGF0ZS5ub3coKSxcbiAgICB9O1xuICB9XG5cbiAgLyoqIENyZWF0ZSBhbiBhc3Npc3RhbnQgbWVzc2FnZSBvYmplY3QgKHdpdGhvdXQgYWRkaW5nIGl0KSAqL1xuICBzdGF0aWMgY3JlYXRlQXNzaXN0YW50TWVzc2FnZShjb250ZW50OiBzdHJpbmcpOiBDaGF0TWVzc2FnZSB7XG4gICAgcmV0dXJuIHtcbiAgICAgIGlkOiBgbXNnLSR7RGF0ZS5ub3coKX0tJHtNYXRoLnJhbmRvbSgpLnRvU3RyaW5nKDM2KS5zbGljZSgyLCA3KX1gLFxuICAgICAgcm9sZTogJ2Fzc2lzdGFudCcsXG4gICAgICBjb250ZW50LFxuICAgICAgdGltZXN0YW1wOiBEYXRlLm5vdygpLFxuICAgIH07XG4gIH1cblxuICAvKiogQ3JlYXRlIGEgc3lzdGVtIC8gc3RhdHVzIG1lc3NhZ2UgKGVycm9ycywgcmVjb25uZWN0IG5vdGljZXMsIGV0Yy4pICovXG4gIHN0YXRpYyBjcmVhdGVTeXN0ZW1NZXNzYWdlKGNvbnRlbnQ6IHN0cmluZywgbGV2ZWw6IENoYXRNZXNzYWdlWydsZXZlbCddID0gJ2luZm8nKTogQ2hhdE1lc3NhZ2Uge1xuICAgIHJldHVybiB7XG4gICAgICBpZDogYHN5cy0ke0RhdGUubm93KCl9YCxcbiAgICAgIHJvbGU6ICdzeXN0ZW0nLFxuICAgICAgbGV2ZWwsXG4gICAgICBjb250ZW50LFxuICAgICAgdGltZXN0YW1wOiBEYXRlLm5vdygpLFxuICAgIH07XG4gIH1cblxuICBzdGF0aWMgY3JlYXRlU2Vzc2lvbkRpdmlkZXIoc2Vzc2lvbktleTogc3RyaW5nKTogQ2hhdE1lc3NhZ2Uge1xuICAgIGNvbnN0IHNob3J0ID0gc2Vzc2lvbktleS5sZW5ndGggPiAyOCA/IGAke3Nlc3Npb25LZXkuc2xpY2UoMCwgMTIpfVx1MjAyNiR7c2Vzc2lvbktleS5zbGljZSgtMTIpfWAgOiBzZXNzaW9uS2V5O1xuICAgIHJldHVybiB7XG4gICAgICBpZDogYGRpdi0ke0RhdGUubm93KCl9YCxcbiAgICAgIHJvbGU6ICdzeXN0ZW0nLFxuICAgICAgbGV2ZWw6ICdpbmZvJyxcbiAgICAgIGtpbmQ6ICdzZXNzaW9uLWRpdmlkZXInLFxuICAgICAgdGl0bGU6IHNlc3Npb25LZXksXG4gICAgICBjb250ZW50OiBgW1Nlc3Npb246ICR7c2hvcnR9XWAsXG4gICAgICB0aW1lc3RhbXA6IERhdGUubm93KCksXG4gICAgfTtcbiAgfVxufVxuIiwgImltcG9ydCB7IEl0ZW1WaWV3LCBNYXJrZG93blJlbmRlcmVyLCBNb2RhbCwgTm90aWNlLCBTZXR0aW5nLCBURmlsZSwgV29ya3NwYWNlTGVhZiB9IGZyb20gJ29ic2lkaWFuJztcbmltcG9ydCB0eXBlIE9wZW5DbGF3UGx1Z2luIGZyb20gJy4vbWFpbic7XG5pbXBvcnQgeyBDaGF0TWFuYWdlciB9IGZyb20gJy4vY2hhdCc7XG5pbXBvcnQgdHlwZSB7IENoYXRNZXNzYWdlLCBQYXRoTWFwcGluZyB9IGZyb20gJy4vdHlwZXMnO1xuaW1wb3J0IHsgZXh0cmFjdENhbmRpZGF0ZXMsIHRyeU1hcFJlbW90ZVBhdGhUb1ZhdWx0UGF0aCB9IGZyb20gJy4vbGlua2lmeSc7XG5pbXBvcnQgeyBnZXRBY3RpdmVOb3RlQ29udGV4dCB9IGZyb20gJy4vY29udGV4dCc7XG5cbmV4cG9ydCBjb25zdCBWSUVXX1RZUEVfT1BFTkNMQVdfQ0hBVCA9ICdvcGVuY2xhdy1jaGF0JztcblxuY2xhc3MgTmV3U2Vzc2lvbk1vZGFsIGV4dGVuZHMgTW9kYWwge1xuICBwcml2YXRlIGluaXRpYWxWYWx1ZTogc3RyaW5nO1xuICBwcml2YXRlIG9uU3VibWl0OiAodmFsdWU6IHN0cmluZykgPT4gdm9pZDtcblxuICBjb25zdHJ1Y3Rvcih2aWV3OiBPcGVuQ2xhd0NoYXRWaWV3LCBpbml0aWFsVmFsdWU6IHN0cmluZywgb25TdWJtaXQ6ICh2YWx1ZTogc3RyaW5nKSA9PiB2b2lkKSB7XG4gICAgc3VwZXIodmlldy5hcHApO1xuICAgIHRoaXMuaW5pdGlhbFZhbHVlID0gaW5pdGlhbFZhbHVlO1xuICAgIHRoaXMub25TdWJtaXQgPSBvblN1Ym1pdDtcbiAgfVxuXG4gIG9uT3BlbigpOiB2b2lkIHtcbiAgICBjb25zdCB7IGNvbnRlbnRFbCB9ID0gdGhpcztcbiAgICBjb250ZW50RWwuZW1wdHkoKTtcblxuICAgIGNvbnRlbnRFbC5jcmVhdGVFbCgnaDMnLCB7IHRleHQ6ICdOZXcgc2Vzc2lvbiBrZXknIH0pO1xuXG4gICAgbGV0IHZhbHVlID0gdGhpcy5pbml0aWFsVmFsdWU7XG5cbiAgICBuZXcgU2V0dGluZyhjb250ZW50RWwpXG4gICAgICAuc2V0TmFtZSgnU2Vzc2lvbiBrZXknKVxuICAgICAgLnNldERlc2MoJ1RpcDogY2hvb3NlIGEgc2hvcnQgc3VmZml4OyBpdCB3aWxsIGJlY29tZSBhZ2VudDptYWluOm9ic2lkaWFuOmRpcmVjdDo8dmF1bHRIYXNoPi08c3VmZml4Pi4nKVxuICAgICAgLmFkZFRleHQoKHQpID0+IHtcbiAgICAgICAgdC5zZXRWYWx1ZSh2YWx1ZSk7XG4gICAgICAgIHQub25DaGFuZ2UoKHYpID0+IHtcbiAgICAgICAgICB2YWx1ZSA9IHY7XG4gICAgICAgIH0pO1xuICAgICAgfSk7XG5cbiAgICBuZXcgU2V0dGluZyhjb250ZW50RWwpXG4gICAgICAuYWRkQnV0dG9uKChiKSA9PiB7XG4gICAgICAgIGIuc2V0QnV0dG9uVGV4dCgnQ2FuY2VsJyk7XG4gICAgICAgIGIub25DbGljaygoKSA9PiB0aGlzLmNsb3NlKCkpO1xuICAgICAgfSlcbiAgICAgIC5hZGRCdXR0b24oKGIpID0+IHtcbiAgICAgICAgYi5zZXRDdGEoKTtcbiAgICAgICAgYi5zZXRCdXR0b25UZXh0KCdDcmVhdGUnKTtcbiAgICAgICAgYi5vbkNsaWNrKCgpID0+IHtcbiAgICAgICAgICBjb25zdCB2ID0gdmFsdWUudHJpbSgpLnRvTG93ZXJDYXNlKCk7XG4gICAgICAgICAgaWYgKCF2KSB7XG4gICAgICAgICAgICBuZXcgTm90aWNlKCdTdWZmaXggY2Fubm90IGJlIGVtcHR5Jyk7XG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgfVxuICAgICAgICAgIGlmICghL15bYS16MC05XVthLXowLTlfLV17MCw2M30kLy50ZXN0KHYpKSB7XG4gICAgICAgICAgICBuZXcgTm90aWNlKCdVc2UgbGV0dGVycy9udW1iZXJzL18vLSBvbmx5IChtYXggNjQgY2hhcnMpJyk7XG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgfVxuICAgICAgICAgIHRoaXMub25TdWJtaXQodik7XG4gICAgICAgICAgdGhpcy5jbG9zZSgpO1xuICAgICAgICB9KTtcbiAgICAgIH0pO1xuICB9XG59XG5cbmV4cG9ydCBjbGFzcyBPcGVuQ2xhd0NoYXRWaWV3IGV4dGVuZHMgSXRlbVZpZXcge1xuICBwcml2YXRlIHBsdWdpbjogT3BlbkNsYXdQbHVnaW47XG4gIHByaXZhdGUgY2hhdE1hbmFnZXI6IENoYXRNYW5hZ2VyO1xuXG4gIC8vIFN0YXRlXG4gIHByaXZhdGUgaXNDb25uZWN0ZWQgPSBmYWxzZTtcbiAgcHJpdmF0ZSBpc1dvcmtpbmcgPSBmYWxzZTtcblxuICAvLyBDb25uZWN0aW9uIG5vdGljZXMgKGF2b2lkIHNwYW0pXG4gIHByaXZhdGUgbGFzdENvbm5Ob3RpY2VBdE1zID0gMDtcbiAgcHJpdmF0ZSBsYXN0R2F0ZXdheVN0YXRlOiBzdHJpbmcgfCBudWxsID0gbnVsbDtcblxuICAvLyBET00gcmVmc1xuICBwcml2YXRlIG1lc3NhZ2VzRWwhOiBIVE1MRWxlbWVudDtcbiAgcHJpdmF0ZSBpbnB1dEVsITogSFRNTFRleHRBcmVhRWxlbWVudDtcbiAgcHJpdmF0ZSBzZW5kQnRuITogSFRNTEJ1dHRvbkVsZW1lbnQ7XG4gIHByaXZhdGUgaW5jbHVkZU5vdGVDaGVja2JveCE6IEhUTUxJbnB1dEVsZW1lbnQ7XG4gIHByaXZhdGUgc3RhdHVzRG90ITogSFRNTEVsZW1lbnQ7XG5cbiAgcHJpdmF0ZSBzZXNzaW9uU2VsZWN0ITogSFRNTFNlbGVjdEVsZW1lbnQ7XG4gIHByaXZhdGUgc2Vzc2lvblJlZnJlc2hCdG4hOiBIVE1MQnV0dG9uRWxlbWVudDtcbiAgcHJpdmF0ZSBzZXNzaW9uTmV3QnRuITogSFRNTEJ1dHRvbkVsZW1lbnQ7XG4gIHByaXZhdGUgc2Vzc2lvbk1haW5CdG4hOiBIVE1MQnV0dG9uRWxlbWVudDtcbiAgcHJpdmF0ZSBzdXBwcmVzc1Nlc3Npb25TZWxlY3RDaGFuZ2UgPSBmYWxzZTtcblxuICBwcml2YXRlIG9uTWVzc2FnZXNDbGljazogKChldjogTW91c2VFdmVudCkgPT4gdm9pZCkgfCBudWxsID0gbnVsbDtcblxuICBjb25zdHJ1Y3RvcihsZWFmOiBXb3Jrc3BhY2VMZWFmLCBwbHVnaW46IE9wZW5DbGF3UGx1Z2luKSB7XG4gICAgc3VwZXIobGVhZik7XG4gICAgdGhpcy5wbHVnaW4gPSBwbHVnaW47XG4gICAgdGhpcy5jaGF0TWFuYWdlciA9IHBsdWdpbi5jaGF0TWFuYWdlcjtcbiAgfVxuXG4gIGdldFZpZXdUeXBlKCk6IHN0cmluZyB7XG4gICAgcmV0dXJuIFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFUO1xuICB9XG5cbiAgZ2V0RGlzcGxheVRleHQoKTogc3RyaW5nIHtcbiAgICByZXR1cm4gJ09wZW5DbGF3IENoYXQnO1xuICB9XG5cbiAgZ2V0SWNvbigpOiBzdHJpbmcge1xuICAgIHJldHVybiAnbWVzc2FnZS1zcXVhcmUnO1xuICB9XG5cbiAgYXN5bmMgb25PcGVuKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIHRoaXMuX2J1aWxkVUkoKTtcblxuICAgIC8vIEZ1bGwgcmUtcmVuZGVyIG9uIGNsZWFyIC8gcmVsb2FkXG4gICAgdGhpcy5jaGF0TWFuYWdlci5vblVwZGF0ZSA9IChtc2dzKSA9PiB0aGlzLl9yZW5kZXJNZXNzYWdlcyhtc2dzKTtcbiAgICAvLyBPKDEpIGFwcGVuZCBmb3IgbmV3IG1lc3NhZ2VzXG4gICAgdGhpcy5jaGF0TWFuYWdlci5vbk1lc3NhZ2VBZGRlZCA9IChtc2cpID0+IHRoaXMuX2FwcGVuZE1lc3NhZ2UobXNnKTtcblxuICAgIC8vIFN1YnNjcmliZSB0byBXUyBzdGF0ZSBjaGFuZ2VzXG4gICAgdGhpcy5wbHVnaW4ud3NDbGllbnQub25TdGF0ZUNoYW5nZSA9IChzdGF0ZSkgPT4ge1xuICAgICAgLy8gQ29ubmVjdGlvbiBsb3NzIC8gcmVjb25uZWN0IG5vdGljZXMgKHRocm90dGxlZClcbiAgICAgIGNvbnN0IHByZXYgPSB0aGlzLmxhc3RHYXRld2F5U3RhdGU7XG4gICAgICB0aGlzLmxhc3RHYXRld2F5U3RhdGUgPSBzdGF0ZTtcblxuICAgICAgY29uc3Qgbm93ID0gRGF0ZS5ub3coKTtcbiAgICAgIGNvbnN0IE5PVElDRV9USFJPVFRMRV9NUyA9IDYwXzAwMDtcblxuICAgICAgY29uc3Qgc2hvdWxkTm90aWZ5ID0gKCkgPT4gbm93IC0gdGhpcy5sYXN0Q29ubk5vdGljZUF0TXMgPiBOT1RJQ0VfVEhST1RUTEVfTVM7XG4gICAgICBjb25zdCBub3RpZnkgPSAodGV4dDogc3RyaW5nKSA9PiB7XG4gICAgICAgIGlmICghc2hvdWxkTm90aWZ5KCkpIHJldHVybjtcbiAgICAgICAgdGhpcy5sYXN0Q29ubk5vdGljZUF0TXMgPSBub3c7XG4gICAgICAgIG5ldyBOb3RpY2UodGV4dCk7XG4gICAgICB9O1xuXG4gICAgICAvLyBPbmx5IHNob3cgXHUyMDFDbG9zdFx1MjAxRCBpZiB3ZSB3ZXJlIHByZXZpb3VzbHkgY29ubmVjdGVkLlxuICAgICAgaWYgKHByZXYgPT09ICdjb25uZWN0ZWQnICYmIHN0YXRlID09PSAnZGlzY29ubmVjdGVkJykge1xuICAgICAgICBub3RpZnkoJ09wZW5DbGF3IENoYXQ6IGNvbm5lY3Rpb24gbG9zdCBcdTIwMTQgcmVjb25uZWN0aW5nXHUyMDI2Jyk7XG4gICAgICAgIC8vIEFsc28gYXBwZW5kIGEgc3lzdGVtIG1lc3NhZ2Ugc28gaXRcdTIwMTlzIHZpc2libGUgaW4gdGhlIGNoYXQgaGlzdG9yeS5cbiAgICAgICAgdGhpcy5jaGF0TWFuYWdlci5hZGRNZXNzYWdlKENoYXRNYW5hZ2VyLmNyZWF0ZVN5c3RlbU1lc3NhZ2UoJ1x1MjZBMCBDb25uZWN0aW9uIGxvc3QgXHUyMDE0IHJlY29ubmVjdGluZ1x1MjAyNicsICdlcnJvcicpKTtcbiAgICAgIH1cblxuICAgICAgLy8gT3B0aW9uYWwgXHUyMDFDcmVjb25uZWN0ZWRcdTIwMUQgbm90aWNlXG4gICAgICBpZiAocHJldiAmJiBwcmV2ICE9PSAnY29ubmVjdGVkJyAmJiBzdGF0ZSA9PT0gJ2Nvbm5lY3RlZCcpIHtcbiAgICAgICAgbm90aWZ5KCdPcGVuQ2xhdyBDaGF0OiByZWNvbm5lY3RlZCcpO1xuICAgICAgICB0aGlzLmNoYXRNYW5hZ2VyLmFkZE1lc3NhZ2UoQ2hhdE1hbmFnZXIuY3JlYXRlU3lzdGVtTWVzc2FnZSgnXHUyNzA1IFJlY29ubmVjdGVkJywgJ2luZm8nKSk7XG4gICAgICB9XG5cbiAgICAgIHRoaXMuaXNDb25uZWN0ZWQgPSBzdGF0ZSA9PT0gJ2Nvbm5lY3RlZCc7XG4gICAgICB0aGlzLnN0YXR1c0RvdC50b2dnbGVDbGFzcygnY29ubmVjdGVkJywgdGhpcy5pc0Nvbm5lY3RlZCk7XG4gICAgICB0aGlzLnN0YXR1c0RvdC50aXRsZSA9IGBHYXRld2F5OiAke3N0YXRlfWA7XG4gICAgICB0aGlzLl91cGRhdGVTZW5kQnV0dG9uKCk7XG4gICAgfTtcblxuICAgIC8vIFN1YnNjcmliZSB0byBcdTIwMUN3b3JraW5nXHUyMDFEIChyZXF1ZXN0LWluLWZsaWdodCkgc3RhdGVcbiAgICB0aGlzLnBsdWdpbi53c0NsaWVudC5vbldvcmtpbmdDaGFuZ2UgPSAod29ya2luZykgPT4ge1xuICAgICAgdGhpcy5pc1dvcmtpbmcgPSB3b3JraW5nO1xuICAgICAgdGhpcy5fdXBkYXRlU2VuZEJ1dHRvbigpO1xuICAgIH07XG5cbiAgICAvLyBSZWZsZWN0IGN1cnJlbnQgc3RhdGVcbiAgICB0aGlzLmxhc3RHYXRld2F5U3RhdGUgPSB0aGlzLnBsdWdpbi53c0NsaWVudC5zdGF0ZTtcbiAgICB0aGlzLmlzQ29ubmVjdGVkID0gdGhpcy5wbHVnaW4ud3NDbGllbnQuc3RhdGUgPT09ICdjb25uZWN0ZWQnO1xuICAgIHRoaXMuc3RhdHVzRG90LnRvZ2dsZUNsYXNzKCdjb25uZWN0ZWQnLCB0aGlzLmlzQ29ubmVjdGVkKTtcbiAgICB0aGlzLnN0YXR1c0RvdC50aXRsZSA9IGBHYXRld2F5OiAke3RoaXMucGx1Z2luLndzQ2xpZW50LnN0YXRlfWA7XG4gICAgdGhpcy5fdXBkYXRlU2VuZEJ1dHRvbigpO1xuXG4gICAgdGhpcy5fcmVuZGVyTWVzc2FnZXModGhpcy5jaGF0TWFuYWdlci5nZXRNZXNzYWdlcygpKTtcblxuICAgIC8vIExvYWQgc2Vzc2lvbiBkcm9wZG93biBmcm9tIGxvY2FsIHZhdWx0LXNjb3BlZCBrbm93biBzZXNzaW9ucy5cbiAgICB0aGlzLl9sb2FkS25vd25TZXNzaW9ucygpO1xuICB9XG5cbiAgYXN5bmMgb25DbG9zZSgpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICB0aGlzLmNoYXRNYW5hZ2VyLm9uVXBkYXRlID0gbnVsbDtcbiAgICB0aGlzLmNoYXRNYW5hZ2VyLm9uTWVzc2FnZUFkZGVkID0gbnVsbDtcbiAgICB0aGlzLnBsdWdpbi53c0NsaWVudC5vblN0YXRlQ2hhbmdlID0gbnVsbDtcbiAgICB0aGlzLnBsdWdpbi53c0NsaWVudC5vbldvcmtpbmdDaGFuZ2UgPSBudWxsO1xuXG4gICAgaWYgKHRoaXMub25NZXNzYWdlc0NsaWNrKSB7XG4gICAgICB0aGlzLm1lc3NhZ2VzRWw/LnJlbW92ZUV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgdGhpcy5vbk1lc3NhZ2VzQ2xpY2spO1xuICAgICAgdGhpcy5vbk1lc3NhZ2VzQ2xpY2sgPSBudWxsO1xuICAgIH1cbiAgfVxuXG4gIC8vIFx1MjUwMFx1MjUwMCBVSSBjb25zdHJ1Y3Rpb24gXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG5cbiAgcHJpdmF0ZSBfYnVpbGRVSSgpOiB2b2lkIHtcbiAgICBjb25zdCByb290ID0gdGhpcy5jb250ZW50RWw7XG4gICAgcm9vdC5lbXB0eSgpO1xuICAgIHJvb3QuYWRkQ2xhc3MoJ29jbGF3LWNoYXQtdmlldycpO1xuXG4gICAgLy8gXHUyNTAwXHUyNTAwIEhlYWRlciBcdTI1MDBcdTI1MDBcbiAgICBjb25zdCBoZWFkZXIgPSByb290LmNyZWF0ZURpdih7IGNsczogJ29jbGF3LWhlYWRlcicgfSk7XG4gICAgaGVhZGVyLmNyZWF0ZVNwYW4oeyBjbHM6ICdvY2xhdy1oZWFkZXItdGl0bGUnLCB0ZXh0OiAnT3BlbkNsYXcgQ2hhdCcgfSk7XG4gICAgdGhpcy5zdGF0dXNEb3QgPSBoZWFkZXIuY3JlYXRlRGl2KHsgY2xzOiAnb2NsYXctc3RhdHVzLWRvdCcgfSk7XG4gICAgdGhpcy5zdGF0dXNEb3QudGl0bGUgPSAnR2F0ZXdheTogZGlzY29ubmVjdGVkJztcblxuICAgIC8vIFx1MjUwMFx1MjUwMCBTZXNzaW9uIHJvdyBcdTI1MDBcdTI1MDBcbiAgICBjb25zdCBzZXNzUm93ID0gcm9vdC5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1zZXNzaW9uLXJvdycgfSk7XG4gICAgc2Vzc1Jvdy5jcmVhdGVTcGFuKHsgY2xzOiAnb2NsYXctc2Vzc2lvbi1sYWJlbCcsIHRleHQ6ICdTZXNzaW9uJyB9KTtcblxuICAgIHRoaXMuc2Vzc2lvblNlbGVjdCA9IHNlc3NSb3cuY3JlYXRlRWwoJ3NlbGVjdCcsIHsgY2xzOiAnb2NsYXctc2Vzc2lvbi1zZWxlY3QnIH0pO1xuICAgIHRoaXMuc2Vzc2lvblJlZnJlc2hCdG4gPSBzZXNzUm93LmNyZWF0ZUVsKCdidXR0b24nLCB7IGNsczogJ29jbGF3LXNlc3Npb24tYnRuJywgdGV4dDogJ1JlbG9hZCcgfSk7XG4gICAgdGhpcy5zZXNzaW9uTmV3QnRuID0gc2Vzc1Jvdy5jcmVhdGVFbCgnYnV0dG9uJywgeyBjbHM6ICdvY2xhdy1zZXNzaW9uLWJ0bicsIHRleHQ6ICdOZXdcdTIwMjYnIH0pO1xuICAgIHRoaXMuc2Vzc2lvbk1haW5CdG4gPSBzZXNzUm93LmNyZWF0ZUVsKCdidXR0b24nLCB7IGNsczogJ29jbGF3LXNlc3Npb24tYnRuJywgdGV4dDogJ01haW4nIH0pO1xuXG4gICAgdGhpcy5zZXNzaW9uUmVmcmVzaEJ0bi5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpID0+IHRoaXMuX2xvYWRLbm93blNlc3Npb25zKCkpO1xuICAgIHRoaXMuc2Vzc2lvbk5ld0J0bi5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpID0+IHZvaWQgdGhpcy5fcHJvbXB0TmV3U2Vzc2lvbigpKTtcbiAgICB0aGlzLnNlc3Npb25NYWluQnRuLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4ge1xuICAgICAgdm9pZCAoYXN5bmMgKCkgPT4ge1xuICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zd2l0Y2hTZXNzaW9uKCdtYWluJyk7XG4gICAgICAgIHRoaXMuX2xvYWRLbm93blNlc3Npb25zKCk7XG4gICAgICAgIHRoaXMuc2Vzc2lvblNlbGVjdC52YWx1ZSA9ICdtYWluJztcbiAgICAgICAgdGhpcy5zZXNzaW9uU2VsZWN0LnRpdGxlID0gJ21haW4nO1xuICAgICAgfSkoKTtcbiAgICB9KTtcbiAgICB0aGlzLnNlc3Npb25TZWxlY3QuYWRkRXZlbnRMaXN0ZW5lcignY2hhbmdlJywgKCkgPT4ge1xuICAgICAgaWYgKHRoaXMuc3VwcHJlc3NTZXNzaW9uU2VsZWN0Q2hhbmdlKSByZXR1cm47XG4gICAgICBjb25zdCBuZXh0ID0gdGhpcy5zZXNzaW9uU2VsZWN0LnZhbHVlO1xuICAgICAgaWYgKCFuZXh0IHx8IG5leHQgPT09IHRoaXMucGx1Z2luLnNldHRpbmdzLnNlc3Npb25LZXkpIHJldHVybjtcbiAgICAgIHZvaWQgKGFzeW5jICgpID0+IHtcbiAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uc3dpdGNoU2Vzc2lvbihuZXh0KTtcbiAgICAgICAgdGhpcy5fbG9hZEtub3duU2Vzc2lvbnMoKTtcbiAgICAgICAgdGhpcy5zZXNzaW9uU2VsZWN0LnZhbHVlID0gbmV4dDtcbiAgICAgICAgdGhpcy5zZXNzaW9uU2VsZWN0LnRpdGxlID0gbmV4dDtcbiAgICAgIH0pKCk7XG4gICAgfSk7XG5cbiAgICAvLyBcdTI1MDBcdTI1MDAgTWVzc2FnZXMgYXJlYSBcdTI1MDBcdTI1MDBcbiAgICB0aGlzLm1lc3NhZ2VzRWwgPSByb290LmNyZWF0ZURpdih7IGNsczogJ29jbGF3LW1lc3NhZ2VzJyB9KTtcblxuICAgIC8vIERlbGVnYXRlIGludGVybmFsLWxpbmsgY2xpY2tzIChNYXJrZG93blJlbmRlcmVyIG91dHB1dCkgdG8gYSByZWxpYWJsZSBvcGVuRmlsZSBoYW5kbGVyLlxuICAgIHRoaXMuX2luc3RhbGxJbnRlcm5hbExpbmtEZWxlZ2F0aW9uKCk7XG5cbiAgICAvLyBcdTI1MDBcdTI1MDAgQ29udGV4dCByb3cgXHUyNTAwXHUyNTAwXG4gICAgY29uc3QgY3R4Um93ID0gcm9vdC5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1jb250ZXh0LXJvdycgfSk7XG4gICAgdGhpcy5pbmNsdWRlTm90ZUNoZWNrYm94ID0gY3R4Um93LmNyZWF0ZUVsKCdpbnB1dCcsIHsgdHlwZTogJ2NoZWNrYm94JyB9KTtcbiAgICB0aGlzLmluY2x1ZGVOb3RlQ2hlY2tib3guaWQgPSAnb2NsYXctaW5jbHVkZS1ub3RlJztcbiAgICB0aGlzLmluY2x1ZGVOb3RlQ2hlY2tib3guY2hlY2tlZCA9IHRoaXMucGx1Z2luLnNldHRpbmdzLmluY2x1ZGVBY3RpdmVOb3RlO1xuICAgIGNvbnN0IGN0eExhYmVsID0gY3R4Um93LmNyZWF0ZUVsKCdsYWJlbCcsIHsgdGV4dDogJ0luY2x1ZGUgYWN0aXZlIG5vdGUnIH0pO1xuICAgIGN0eExhYmVsLmh0bWxGb3IgPSAnb2NsYXctaW5jbHVkZS1ub3RlJztcblxuICAgIC8vIFx1MjUwMFx1MjUwMCBJbnB1dCByb3cgXHUyNTAwXHUyNTAwXG4gICAgY29uc3QgaW5wdXRSb3cgPSByb290LmNyZWF0ZURpdih7IGNsczogJ29jbGF3LWlucHV0LXJvdycgfSk7XG4gICAgdGhpcy5pbnB1dEVsID0gaW5wdXRSb3cuY3JlYXRlRWwoJ3RleHRhcmVhJywge1xuICAgICAgY2xzOiAnb2NsYXctaW5wdXQnLFxuICAgICAgcGxhY2Vob2xkZXI6ICdBc2sgYW55dGhpbmdcdTIwMjYnLFxuICAgIH0pO1xuICAgIHRoaXMuaW5wdXRFbC5yb3dzID0gMTtcblxuICAgIHRoaXMuc2VuZEJ0biA9IGlucHV0Um93LmNyZWF0ZUVsKCdidXR0b24nLCB7IGNsczogJ29jbGF3LXNlbmQtYnRuJywgdGV4dDogJ1NlbmQnIH0pO1xuXG4gICAgLy8gXHUyNTAwXHUyNTAwIEV2ZW50IGxpc3RlbmVycyBcdTI1MDBcdTI1MDBcbiAgICB0aGlzLnNlbmRCdG4uYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKSA9PiB0aGlzLl9oYW5kbGVTZW5kKCkpO1xuICAgIHRoaXMuaW5wdXRFbC5hZGRFdmVudExpc3RlbmVyKCdrZXlkb3duJywgKGUpID0+IHtcbiAgICAgIGlmIChlLmtleSA9PT0gJ0VudGVyJyAmJiAhZS5zaGlmdEtleSkge1xuICAgICAgICBlLnByZXZlbnREZWZhdWx0KCk7XG4gICAgICAgIHRoaXMuX2hhbmRsZVNlbmQoKTtcbiAgICAgIH1cbiAgICB9KTtcbiAgICAvLyBBdXRvLXJlc2l6ZSB0ZXh0YXJlYVxuICAgIHRoaXMuaW5wdXRFbC5hZGRFdmVudExpc3RlbmVyKCdpbnB1dCcsICgpID0+IHtcbiAgICAgIHRoaXMuaW5wdXRFbC5zdHlsZS5oZWlnaHQgPSAnYXV0byc7XG4gICAgICB0aGlzLmlucHV0RWwuc3R5bGUuaGVpZ2h0ID0gYCR7dGhpcy5pbnB1dEVsLnNjcm9sbEhlaWdodH1weGA7XG4gICAgfSk7XG4gIH1cblxuICBwcml2YXRlIF9zZXRTZXNzaW9uU2VsZWN0T3B0aW9ucyhrZXlzOiBzdHJpbmdbXSk6IHZvaWQge1xuICAgIHRoaXMuc3VwcHJlc3NTZXNzaW9uU2VsZWN0Q2hhbmdlID0gdHJ1ZTtcbiAgICB0cnkge1xuICAgICAgdGhpcy5zZXNzaW9uU2VsZWN0LmVtcHR5KCk7XG5cbiAgICAgIGNvbnN0IGN1cnJlbnQgPSAodGhpcy5wbHVnaW4uc2V0dGluZ3Muc2Vzc2lvbktleSA/PyAnbWFpbicpLnRvTG93ZXJDYXNlKCk7XG4gICAgICBsZXQgdW5pcXVlID0gQXJyYXkuZnJvbShuZXcgU2V0KFtjdXJyZW50LCAuLi5rZXlzXS5maWx0ZXIoQm9vbGVhbikpKTtcblxuICAgICAgLy8gQ2Fub25pY2FsLW9ubHk6IG1haW4gb3IgYWdlbnQ6bWFpbjpvYnNpZGlhbjpkaXJlY3Q6KlxuICAgICAgdW5pcXVlID0gdW5pcXVlLmZpbHRlcigoaykgPT4gayA9PT0gJ21haW4nIHx8IFN0cmluZyhrKS5zdGFydHNXaXRoKCdhZ2VudDptYWluOm9ic2lkaWFuOmRpcmVjdDonKSk7XG5cbiAgICAgIGlmICh1bmlxdWUubGVuZ3RoID09PSAwKSB7XG4gICAgICAgIHVuaXF1ZSA9IFsnbWFpbiddO1xuICAgICAgfVxuXG4gICAgICBmb3IgKGNvbnN0IGtleSBvZiB1bmlxdWUpIHtcbiAgICAgICAgY29uc3Qgb3B0ID0gdGhpcy5zZXNzaW9uU2VsZWN0LmNyZWF0ZUVsKCdvcHRpb24nLCB7IHZhbHVlOiBrZXksIHRleHQ6IGtleSB9KTtcbiAgICAgICAgaWYgKGtleSA9PT0gY3VycmVudCkgb3B0LnNlbGVjdGVkID0gdHJ1ZTtcbiAgICAgIH1cblxuICAgICAgaWYgKHVuaXF1ZS5pbmNsdWRlcyhjdXJyZW50KSkge1xuICAgICAgICB0aGlzLnNlc3Npb25TZWxlY3QudmFsdWUgPSBjdXJyZW50O1xuICAgICAgfVxuICAgICAgdGhpcy5zZXNzaW9uU2VsZWN0LnRpdGxlID0gY3VycmVudDtcbiAgICB9IGZpbmFsbHkge1xuICAgICAgdGhpcy5zdXBwcmVzc1Nlc3Npb25TZWxlY3RDaGFuZ2UgPSBmYWxzZTtcbiAgICB9XG4gIH1cblxuICBwcml2YXRlIF9sb2FkS25vd25TZXNzaW9ucygpOiB2b2lkIHtcbiAgICBjb25zdCB2YXVsdEhhc2ggPSAodGhpcy5wbHVnaW4uc2V0dGluZ3MudmF1bHRIYXNoID8/ICcnKS50cmltKCk7XG4gICAgY29uc3QgbWFwID0gdGhpcy5wbHVnaW4uc2V0dGluZ3Mua25vd25TZXNzaW9uS2V5c0J5VmF1bHQgPz8ge307XG4gICAgY29uc3Qga2V5cyA9IHZhdWx0SGFzaCAmJiBBcnJheS5pc0FycmF5KG1hcFt2YXVsdEhhc2hdKSA/IG1hcFt2YXVsdEhhc2hdIDogW107XG4gICAgdGhpcy5fc2V0U2Vzc2lvblNlbGVjdE9wdGlvbnMoa2V5cyk7XG4gIH1cblxuICBwcml2YXRlIGFzeW5jIF9wcm9tcHROZXdTZXNzaW9uKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIGNvbnN0IG5vdyA9IG5ldyBEYXRlKCk7XG4gICAgY29uc3QgcGFkID0gKG46IG51bWJlcikgPT4gU3RyaW5nKG4pLnBhZFN0YXJ0KDIsICcwJyk7XG4gICAgY29uc3Qgc3VnZ2VzdGVkID0gYGNoYXQtJHtub3cuZ2V0RnVsbFllYXIoKX0ke3BhZChub3cuZ2V0TW9udGgoKSArIDEpfSR7cGFkKG5vdy5nZXREYXRlKCkpfS0ke3BhZChub3cuZ2V0SG91cnMoKSl9JHtwYWQobm93LmdldE1pbnV0ZXMoKSl9YDtcblxuICAgIGNvbnN0IG1vZGFsID0gbmV3IE5ld1Nlc3Npb25Nb2RhbCh0aGlzLCBzdWdnZXN0ZWQsIChzdWZmaXgpID0+IHtcbiAgICAgIGNvbnN0IHZhdWx0SGFzaCA9ICh0aGlzLnBsdWdpbi5zZXR0aW5ncy52YXVsdEhhc2ggPz8gJycpLnRyaW0oKTtcbiAgICAgIGlmICghdmF1bHRIYXNoKSB7XG4gICAgICAgIG5ldyBOb3RpY2UoJ09wZW5DbGF3IENoYXQ6IGNhbm5vdCBjcmVhdGUgc2Vzc2lvbiAobWlzc2luZyB2YXVsdCBpZGVudGl0eSkuJyk7XG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cbiAgICAgIGNvbnN0IGtleSA9IGBhZ2VudDptYWluOm9ic2lkaWFuOmRpcmVjdDoke3ZhdWx0SGFzaH0tJHtzdWZmaXh9YDtcbiAgICAgIHZvaWQgKGFzeW5jICgpID0+IHtcbiAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uc3dpdGNoU2Vzc2lvbihrZXkpO1xuICAgICAgICB0aGlzLl9sb2FkS25vd25TZXNzaW9ucygpO1xuICAgICAgICB0aGlzLnNlc3Npb25TZWxlY3QudmFsdWUgPSBrZXk7XG4gICAgICAgIHRoaXMuc2Vzc2lvblNlbGVjdC50aXRsZSA9IGtleTtcbiAgICAgIH0pKCk7XG4gICAgfSk7XG4gICAgbW9kYWwub3BlbigpO1xuICB9XG5cbiAgLy8gXHUyNTAwXHUyNTAwIE1lc3NhZ2UgcmVuZGVyaW5nIFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFxuXG4gIHByaXZhdGUgX3JlbmRlck1lc3NhZ2VzKG1lc3NhZ2VzOiByZWFkb25seSBDaGF0TWVzc2FnZVtdKTogdm9pZCB7XG4gICAgdGhpcy5tZXNzYWdlc0VsLmVtcHR5KCk7XG5cbiAgICBpZiAobWVzc2FnZXMubGVuZ3RoID09PSAwKSB7XG4gICAgICB0aGlzLm1lc3NhZ2VzRWwuY3JlYXRlRWwoJ3AnLCB7XG4gICAgICAgIHRleHQ6ICdTZW5kIGEgbWVzc2FnZSB0byBzdGFydCBjaGF0dGluZy4nLFxuICAgICAgICBjbHM6ICdvY2xhdy1tZXNzYWdlIHN5c3RlbSBvY2xhdy1wbGFjZWhvbGRlcicsXG4gICAgICB9KTtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICBmb3IgKGNvbnN0IG1zZyBvZiBtZXNzYWdlcykge1xuICAgICAgdGhpcy5fYXBwZW5kTWVzc2FnZShtc2cpO1xuICAgIH1cblxuICAgIC8vIFNjcm9sbCB0byBib3R0b21cbiAgICB0aGlzLm1lc3NhZ2VzRWwuc2Nyb2xsVG9wID0gdGhpcy5tZXNzYWdlc0VsLnNjcm9sbEhlaWdodDtcbiAgfVxuXG4gIC8qKiBBcHBlbmRzIGEgc2luZ2xlIG1lc3NhZ2Ugd2l0aG91dCByZWJ1aWxkaW5nIHRoZSBET00gKE8oMSkpICovXG4gIHByaXZhdGUgX2FwcGVuZE1lc3NhZ2UobXNnOiBDaGF0TWVzc2FnZSk6IHZvaWQge1xuICAgIC8vIFJlbW92ZSBlbXB0eS1zdGF0ZSBwbGFjZWhvbGRlciBpZiBwcmVzZW50XG4gICAgdGhpcy5tZXNzYWdlc0VsLnF1ZXJ5U2VsZWN0b3IoJy5vY2xhdy1wbGFjZWhvbGRlcicpPy5yZW1vdmUoKTtcblxuICAgIGNvbnN0IGxldmVsQ2xhc3MgPSBtc2cubGV2ZWwgPyBgICR7bXNnLmxldmVsfWAgOiAnJztcbiAgICBjb25zdCBraW5kQ2xhc3MgPSBtc2cua2luZCA/IGAgb2NsYXctJHttc2cua2luZH1gIDogJyc7XG4gICAgY29uc3QgZWwgPSB0aGlzLm1lc3NhZ2VzRWwuY3JlYXRlRGl2KHsgY2xzOiBgb2NsYXctbWVzc2FnZSAke21zZy5yb2xlfSR7bGV2ZWxDbGFzc30ke2tpbmRDbGFzc31gIH0pO1xuICAgIGNvbnN0IGJvZHkgPSBlbC5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1tZXNzYWdlLWJvZHknIH0pO1xuICAgIGlmIChtc2cudGl0bGUpIHtcbiAgICAgIGJvZHkudGl0bGUgPSBtc2cudGl0bGU7XG4gICAgfVxuXG4gICAgLy8gVHJlYXQgYXNzaXN0YW50IG91dHB1dCBhcyBVTlRSVVNURUQgYnkgZGVmYXVsdC5cbiAgICAvLyBSZW5kZXJpbmcgYXMgT2JzaWRpYW4gTWFya2Rvd24gY2FuIHRyaWdnZXIgZW1iZWRzIGFuZCBvdGhlciBwbHVnaW5zJyBwb3N0LXByb2Nlc3NvcnMuXG4gICAgaWYgKG1zZy5yb2xlID09PSAnYXNzaXN0YW50Jykge1xuICAgICAgY29uc3QgbWFwcGluZ3M6IFBhdGhNYXBwaW5nW10gPSB0aGlzLnBsdWdpbi5zZXR0aW5ncy5wYXRoTWFwcGluZ3MgPz8gW107XG4gICAgICBjb25zdCBzb3VyY2VQYXRoID0gdGhpcy5hcHAud29ya3NwYWNlLmdldEFjdGl2ZUZpbGUoKT8ucGF0aCA/PyAnJztcblxuICAgICAgaWYgKHRoaXMucGx1Z2luLnNldHRpbmdzLnJlbmRlckFzc2lzdGFudE1hcmtkb3duKSB7XG4gICAgICAgIC8vIEJlc3QtZWZmb3J0IHByZS1wcm9jZXNzaW5nOiByZXBsYWNlIGtub3duIHJlbW90ZSBwYXRocyB3aXRoIHdpa2lsaW5rcyB3aGVuIHRoZSB0YXJnZXQgZXhpc3RzLlxuICAgICAgICBjb25zdCBwcmUgPSB0aGlzLl9wcmVwcm9jZXNzQXNzaXN0YW50TWFya2Rvd24obXNnLmNvbnRlbnQsIG1hcHBpbmdzKTtcbiAgICAgICAgdm9pZCBNYXJrZG93blJlbmRlcmVyLnJlbmRlck1hcmtkb3duKHByZSwgYm9keSwgc291cmNlUGF0aCwgdGhpcy5wbHVnaW4pO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgLy8gUGxhaW4gbW9kZTogYnVpbGQgc2FmZSwgY2xpY2thYmxlIGxpbmtzIGluIERPTSAobm8gTWFya2Rvd24gcmVuZGVyaW5nKS5cbiAgICAgICAgdGhpcy5fcmVuZGVyQXNzaXN0YW50UGxhaW5XaXRoTGlua3MoYm9keSwgbXNnLmNvbnRlbnQsIG1hcHBpbmdzLCBzb3VyY2VQYXRoKTtcbiAgICAgIH1cbiAgICB9IGVsc2Uge1xuICAgICAgYm9keS5zZXRUZXh0KG1zZy5jb250ZW50KTtcbiAgICB9XG5cbiAgICAvLyBTY3JvbGwgdG8gYm90dG9tXG4gICAgdGhpcy5tZXNzYWdlc0VsLnNjcm9sbFRvcCA9IHRoaXMubWVzc2FnZXNFbC5zY3JvbGxIZWlnaHQ7XG4gIH1cblxuICBwcml2YXRlIF90cnlSZXZlcnNlTWFwVXJsVG9WYXVsdFBhdGgodXJsOiBzdHJpbmcsIG1hcHBpbmdzOiBQYXRoTWFwcGluZ1tdKTogc3RyaW5nIHwgbnVsbCB7XG4gICAgLy8gRlMtYmFzZWQgbWFwcGluZzsgYmVzdC1lZmZvcnQgb25seS5cbiAgICBsZXQgZGVjb2RlZCA9IHVybDtcbiAgICB0cnkge1xuICAgICAgZGVjb2RlZCA9IGRlY29kZVVSSUNvbXBvbmVudCh1cmwpO1xuICAgIH0gY2F0Y2gge1xuICAgICAgLy8gaWdub3JlXG4gICAgfVxuXG4gICAgLy8gSWYgdGhlIGRlY29kZWQgVVJMIGNvbnRhaW5zIGEgcmVtb3RlQmFzZSBzdWJzdHJpbmcsIHRyeSBtYXBwaW5nIGZyb20gdGhhdCBwb2ludC5cbiAgICBmb3IgKGNvbnN0IHJvdyBvZiBtYXBwaW5ncykge1xuICAgICAgY29uc3QgcmVtb3RlQmFzZSA9IFN0cmluZyhyb3cucmVtb3RlQmFzZSA/PyAnJyk7XG4gICAgICBpZiAoIXJlbW90ZUJhc2UpIGNvbnRpbnVlO1xuICAgICAgY29uc3QgaWR4ID0gZGVjb2RlZC5pbmRleE9mKHJlbW90ZUJhc2UpO1xuICAgICAgaWYgKGlkeCA8IDApIGNvbnRpbnVlO1xuXG4gICAgICAvLyBFeHRyYWN0IGZyb20gcmVtb3RlQmFzZSBvbndhcmQgdW50aWwgYSB0ZXJtaW5hdG9yLlxuICAgICAgY29uc3QgdGFpbCA9IGRlY29kZWQuc2xpY2UoaWR4KTtcbiAgICAgIGNvbnN0IHRva2VuID0gdGFpbC5zcGxpdCgvW1xccydcIjw+KV0vKVswXTtcbiAgICAgIGNvbnN0IG1hcHBlZCA9IHRyeU1hcFJlbW90ZVBhdGhUb1ZhdWx0UGF0aCh0b2tlbiwgbWFwcGluZ3MpO1xuICAgICAgaWYgKG1hcHBlZCAmJiB0aGlzLmFwcC52YXVsdC5nZXRBYnN0cmFjdEZpbGVCeVBhdGgobWFwcGVkKSkgcmV0dXJuIG1hcHBlZDtcbiAgICB9XG5cbiAgICByZXR1cm4gbnVsbDtcbiAgfVxuXG4gIHByaXZhdGUgX2luc3RhbGxJbnRlcm5hbExpbmtEZWxlZ2F0aW9uKCk6IHZvaWQge1xuICAgIGlmICh0aGlzLm9uTWVzc2FnZXNDbGljaykgcmV0dXJuO1xuXG4gICAgdGhpcy5vbk1lc3NhZ2VzQ2xpY2sgPSAoZXY6IE1vdXNlRXZlbnQpID0+IHtcbiAgICAgIGNvbnN0IHRhcmdldCA9IGV2LnRhcmdldCBhcyBIVE1MRWxlbWVudCB8IG51bGw7XG4gICAgICBjb25zdCBhID0gdGFyZ2V0Py5jbG9zZXN0Py4oJ2EuaW50ZXJuYWwtbGluaycpIGFzIEhUTUxBbmNob3JFbGVtZW50IHwgbnVsbDtcbiAgICAgIGlmICghYSkgcmV0dXJuO1xuXG4gICAgICBjb25zdCBkYXRhSHJlZiA9IGEuZ2V0QXR0cmlidXRlKCdkYXRhLWhyZWYnKSB8fCAnJztcbiAgICAgIGNvbnN0IGhyZWZBdHRyID0gYS5nZXRBdHRyaWJ1dGUoJ2hyZWYnKSB8fCAnJztcblxuICAgICAgY29uc3QgcmF3ID0gKGRhdGFIcmVmIHx8IGhyZWZBdHRyKS50cmltKCk7XG4gICAgICBpZiAoIXJhdykgcmV0dXJuO1xuXG4gICAgICAvLyBJZiBpdCBpcyBhbiBhYnNvbHV0ZSBVUkwsIGxldCB0aGUgZGVmYXVsdCBiZWhhdmlvciBoYW5kbGUgaXQuXG4gICAgICBpZiAoL15odHRwcz86XFwvXFwvL2kudGVzdChyYXcpKSByZXR1cm47XG5cbiAgICAgIC8vIE9ic2lkaWFuIGludGVybmFsLWxpbmsgb2Z0ZW4gdXNlcyB2YXVsdC1yZWxhdGl2ZSBwYXRoLlxuICAgICAgY29uc3QgdmF1bHRQYXRoID0gcmF3LnJlcGxhY2UoL15cXC8rLywgJycpO1xuICAgICAgY29uc3QgZiA9IHRoaXMuYXBwLnZhdWx0LmdldEFic3RyYWN0RmlsZUJ5UGF0aCh2YXVsdFBhdGgpO1xuICAgICAgaWYgKCEoZiBpbnN0YW5jZW9mIFRGaWxlKSkgcmV0dXJuO1xuXG4gICAgICBldi5wcmV2ZW50RGVmYXVsdCgpO1xuICAgICAgZXYuc3RvcFByb3BhZ2F0aW9uKCk7XG4gICAgICB2b2lkIHRoaXMuYXBwLndvcmtzcGFjZS5nZXRMZWFmKHRydWUpLm9wZW5GaWxlKGYpO1xuICAgIH07XG5cbiAgICB0aGlzLm1lc3NhZ2VzRWwuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCB0aGlzLm9uTWVzc2FnZXNDbGljayk7XG4gIH1cblxuICBwcml2YXRlIF90cnlNYXBWYXVsdFJlbGF0aXZlVG9rZW4odG9rZW46IHN0cmluZywgbWFwcGluZ3M6IFBhdGhNYXBwaW5nW10pOiBzdHJpbmcgfCBudWxsIHtcbiAgICBjb25zdCB0ID0gdG9rZW4ucmVwbGFjZSgvXlxcLysvLCAnJyk7XG4gICAgaWYgKHRoaXMuYXBwLnZhdWx0LmdldEFic3RyYWN0RmlsZUJ5UGF0aCh0KSkgcmV0dXJuIHQ7XG5cbiAgICAvLyBIZXVyaXN0aWM6IGlmIHZhdWx0QmFzZSBlbmRzIHdpdGggYSBzZWdtZW50IChlLmcuIHdvcmtzcGFjZS9jb21wZW5nLykgYW5kIHRva2VuIHN0YXJ0cyB3aXRoIHRoYXQgc2VnbWVudCAoY29tcGVuZy8uLi4pLFxuICAgIC8vIG1hcCB0b2tlbiB1bmRlciB2YXVsdEJhc2UuXG4gICAgZm9yIChjb25zdCByb3cgb2YgbWFwcGluZ3MpIHtcbiAgICAgIGNvbnN0IHZhdWx0QmFzZVJhdyA9IFN0cmluZyhyb3cudmF1bHRCYXNlID8/ICcnKS50cmltKCk7XG4gICAgICBpZiAoIXZhdWx0QmFzZVJhdykgY29udGludWU7XG4gICAgICBjb25zdCB2YXVsdEJhc2UgPSB2YXVsdEJhc2VSYXcuZW5kc1dpdGgoJy8nKSA/IHZhdWx0QmFzZVJhdyA6IGAke3ZhdWx0QmFzZVJhd30vYDtcblxuICAgICAgY29uc3QgcGFydHMgPSB2YXVsdEJhc2UucmVwbGFjZSgvXFwvKyQvLCAnJykuc3BsaXQoJy8nKTtcbiAgICAgIGNvbnN0IGJhc2VOYW1lID0gcGFydHNbcGFydHMubGVuZ3RoIC0gMV07XG4gICAgICBpZiAoIWJhc2VOYW1lKSBjb250aW51ZTtcblxuICAgICAgY29uc3QgcHJlZml4ID0gYCR7YmFzZU5hbWV9L2A7XG4gICAgICBpZiAoIXQuc3RhcnRzV2l0aChwcmVmaXgpKSBjb250aW51ZTtcblxuICAgICAgY29uc3QgY2FuZGlkYXRlID0gYCR7dmF1bHRCYXNlfSR7dC5zbGljZShwcmVmaXgubGVuZ3RoKX1gO1xuICAgICAgY29uc3Qgbm9ybWFsaXplZCA9IGNhbmRpZGF0ZS5yZXBsYWNlKC9eXFwvKy8sICcnKTtcbiAgICAgIGlmICh0aGlzLmFwcC52YXVsdC5nZXRBYnN0cmFjdEZpbGVCeVBhdGgobm9ybWFsaXplZCkpIHJldHVybiBub3JtYWxpemVkO1xuICAgIH1cblxuICAgIHJldHVybiBudWxsO1xuICB9XG5cbiAgcHJpdmF0ZSBfcHJlcHJvY2Vzc0Fzc2lzdGFudE1hcmtkb3duKHRleHQ6IHN0cmluZywgbWFwcGluZ3M6IFBhdGhNYXBwaW5nW10pOiBzdHJpbmcge1xuICAgIGNvbnN0IGNhbmRpZGF0ZXMgPSBleHRyYWN0Q2FuZGlkYXRlcyh0ZXh0KTtcbiAgICBpZiAoY2FuZGlkYXRlcy5sZW5ndGggPT09IDApIHJldHVybiB0ZXh0O1xuXG4gICAgbGV0IG91dCA9ICcnO1xuICAgIGxldCBjdXJzb3IgPSAwO1xuXG4gICAgZm9yIChjb25zdCBjIG9mIGNhbmRpZGF0ZXMpIHtcbiAgICAgIG91dCArPSB0ZXh0LnNsaWNlKGN1cnNvciwgYy5zdGFydCk7XG4gICAgICBjdXJzb3IgPSBjLmVuZDtcblxuICAgICAgaWYgKGMua2luZCA9PT0gJ3VybCcpIHtcbiAgICAgICAgLy8gVVJMcyByZW1haW4gVVJMcyBVTkxFU1Mgd2UgY2FuIHNhZmVseSBtYXAgdG8gYW4gZXhpc3RpbmcgdmF1bHQgZmlsZS5cbiAgICAgICAgY29uc3QgbWFwcGVkID0gdGhpcy5fdHJ5UmV2ZXJzZU1hcFVybFRvVmF1bHRQYXRoKGMucmF3LCBtYXBwaW5ncyk7XG4gICAgICAgIG91dCArPSBtYXBwZWQgPyBgW1ske21hcHBlZH1dXWAgOiBjLnJhdztcbiAgICAgICAgY29udGludWU7XG4gICAgICB9XG5cbiAgICAgIC8vIDEpIElmIHRoZSB0b2tlbiBpcyBhbHJlYWR5IGEgdmF1bHQtcmVsYXRpdmUgcGF0aCAob3IgY2FuIGJlIHJlc29sdmVkIHZpYSB2YXVsdEJhc2UgaGV1cmlzdGljKSwgbGlua2lmeSBpdCBkaXJlY3RseS5cbiAgICAgIGNvbnN0IGRpcmVjdCA9IHRoaXMuX3RyeU1hcFZhdWx0UmVsYXRpdmVUb2tlbihjLnJhdywgbWFwcGluZ3MpO1xuICAgICAgaWYgKGRpcmVjdCkge1xuICAgICAgICBvdXQgKz0gYFtbJHtkaXJlY3R9XV1gO1xuICAgICAgICBjb250aW51ZTtcbiAgICAgIH1cblxuICAgICAgLy8gMikgRWxzZTogdHJ5IHJlbW90ZVx1MjE5MnZhdWx0IG1hcHBpbmcuXG4gICAgICBjb25zdCBtYXBwZWQgPSB0cnlNYXBSZW1vdGVQYXRoVG9WYXVsdFBhdGgoYy5yYXcsIG1hcHBpbmdzKTtcbiAgICAgIGlmICghbWFwcGVkKSB7XG4gICAgICAgIG91dCArPSBjLnJhdztcbiAgICAgICAgY29udGludWU7XG4gICAgICB9XG5cbiAgICAgIGlmICghdGhpcy5hcHAudmF1bHQuZ2V0QWJzdHJhY3RGaWxlQnlQYXRoKG1hcHBlZCkpIHtcbiAgICAgICAgb3V0ICs9IGMucmF3O1xuICAgICAgICBjb250aW51ZTtcbiAgICAgIH1cblxuICAgICAgb3V0ICs9IGBbWyR7bWFwcGVkfV1dYDtcbiAgICB9XG5cbiAgICBvdXQgKz0gdGV4dC5zbGljZShjdXJzb3IpO1xuICAgIHJldHVybiBvdXQ7XG4gIH1cblxuICBwcml2YXRlIF9yZW5kZXJBc3Npc3RhbnRQbGFpbldpdGhMaW5rcyhcbiAgICBib2R5OiBIVE1MRWxlbWVudCxcbiAgICB0ZXh0OiBzdHJpbmcsXG4gICAgbWFwcGluZ3M6IFBhdGhNYXBwaW5nW10sXG4gICAgc291cmNlUGF0aDogc3RyaW5nLFxuICApOiB2b2lkIHtcbiAgICBjb25zdCBjYW5kaWRhdGVzID0gZXh0cmFjdENhbmRpZGF0ZXModGV4dCk7XG4gICAgaWYgKGNhbmRpZGF0ZXMubGVuZ3RoID09PSAwKSB7XG4gICAgICBib2R5LnNldFRleHQodGV4dCk7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgbGV0IGN1cnNvciA9IDA7XG5cbiAgICBjb25zdCBhcHBlbmRUZXh0ID0gKHM6IHN0cmluZykgPT4ge1xuICAgICAgaWYgKCFzKSByZXR1cm47XG4gICAgICBib2R5LmFwcGVuZENoaWxkKGRvY3VtZW50LmNyZWF0ZVRleHROb2RlKHMpKTtcbiAgICB9O1xuXG4gICAgY29uc3QgYXBwZW5kT2JzaWRpYW5MaW5rID0gKHZhdWx0UGF0aDogc3RyaW5nKSA9PiB7XG4gICAgICBjb25zdCBkaXNwbGF5ID0gYFtbJHt2YXVsdFBhdGh9XV1gO1xuICAgICAgY29uc3QgYSA9IGJvZHkuY3JlYXRlRWwoJ2EnLCB7IHRleHQ6IGRpc3BsYXksIGhyZWY6ICcjJyB9KTtcbiAgICAgIGEuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoZXYpID0+IHtcbiAgICAgICAgZXYucHJldmVudERlZmF1bHQoKTtcbiAgICAgICAgZXYuc3RvcFByb3BhZ2F0aW9uKCk7XG5cbiAgICAgICAgY29uc3QgZiA9IHRoaXMuYXBwLnZhdWx0LmdldEFic3RyYWN0RmlsZUJ5UGF0aCh2YXVsdFBhdGgpO1xuICAgICAgICBpZiAoZiBpbnN0YW5jZW9mIFRGaWxlKSB7XG4gICAgICAgICAgdm9pZCB0aGlzLmFwcC53b3Jrc3BhY2UuZ2V0TGVhZih0cnVlKS5vcGVuRmlsZShmKTtcbiAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICAvLyBGYWxsYmFjazogYmVzdC1lZmZvcnQgbGlua3RleHQgb3Blbi5cbiAgICAgICAgdm9pZCB0aGlzLmFwcC53b3Jrc3BhY2Uub3BlbkxpbmtUZXh0KHZhdWx0UGF0aCwgc291cmNlUGF0aCwgdHJ1ZSk7XG4gICAgICB9KTtcbiAgICB9O1xuXG4gICAgY29uc3QgYXBwZW5kRXh0ZXJuYWxVcmwgPSAodXJsOiBzdHJpbmcpID0+IHtcbiAgICAgIC8vIExldCBPYnNpZGlhbi9FbGVjdHJvbiBoYW5kbGUgZXh0ZXJuYWwgb3Blbi5cbiAgICAgIGJvZHkuY3JlYXRlRWwoJ2EnLCB7IHRleHQ6IHVybCwgaHJlZjogdXJsIH0pO1xuICAgIH07XG5cbiAgICBjb25zdCB0cnlSZXZlcnNlTWFwVXJsVG9WYXVsdFBhdGggPSAodXJsOiBzdHJpbmcpOiBzdHJpbmcgfCBudWxsID0+IHRoaXMuX3RyeVJldmVyc2VNYXBVcmxUb1ZhdWx0UGF0aCh1cmwsIG1hcHBpbmdzKTtcblxuICAgIGZvciAoY29uc3QgYyBvZiBjYW5kaWRhdGVzKSB7XG4gICAgICBhcHBlbmRUZXh0KHRleHQuc2xpY2UoY3Vyc29yLCBjLnN0YXJ0KSk7XG4gICAgICBjdXJzb3IgPSBjLmVuZDtcblxuICAgICAgaWYgKGMua2luZCA9PT0gJ3VybCcpIHtcbiAgICAgICAgY29uc3QgbWFwcGVkID0gdHJ5UmV2ZXJzZU1hcFVybFRvVmF1bHRQYXRoKGMucmF3KTtcbiAgICAgICAgaWYgKG1hcHBlZCkge1xuICAgICAgICAgIGFwcGVuZE9ic2lkaWFuTGluayhtYXBwZWQpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIGFwcGVuZEV4dGVybmFsVXJsKGMucmF3KTtcbiAgICAgICAgfVxuICAgICAgICBjb250aW51ZTtcbiAgICAgIH1cblxuICAgICAgLy8gMSkgSWYgdG9rZW4gaXMgYWxyZWFkeSBhIHZhdWx0LXJlbGF0aXZlIHBhdGggKG9yIGNhbiBiZSByZXNvbHZlZCB2aWEgdmF1bHRCYXNlIGhldXJpc3RpYyksIGxpbmtpZnkgZGlyZWN0bHkuXG4gICAgICBjb25zdCBkaXJlY3QgPSB0aGlzLl90cnlNYXBWYXVsdFJlbGF0aXZlVG9rZW4oYy5yYXcsIG1hcHBpbmdzKTtcbiAgICAgIGlmIChkaXJlY3QpIHtcbiAgICAgICAgYXBwZW5kT2JzaWRpYW5MaW5rKGRpcmVjdCk7XG4gICAgICAgIGNvbnRpbnVlO1xuICAgICAgfVxuXG4gICAgICAvLyAyKSBFbHNlOiB0cnkgcmVtb3RlXHUyMTkydmF1bHQgbWFwcGluZy5cbiAgICAgIGNvbnN0IG1hcHBlZCA9IHRyeU1hcFJlbW90ZVBhdGhUb1ZhdWx0UGF0aChjLnJhdywgbWFwcGluZ3MpO1xuICAgICAgaWYgKCFtYXBwZWQpIHtcbiAgICAgICAgYXBwZW5kVGV4dChjLnJhdyk7XG4gICAgICAgIGNvbnRpbnVlO1xuICAgICAgfVxuXG4gICAgICBpZiAoIXRoaXMuYXBwLnZhdWx0LmdldEFic3RyYWN0RmlsZUJ5UGF0aChtYXBwZWQpKSB7XG4gICAgICAgIGFwcGVuZFRleHQoYy5yYXcpO1xuICAgICAgICBjb250aW51ZTtcbiAgICAgIH1cblxuICAgICAgYXBwZW5kT2JzaWRpYW5MaW5rKG1hcHBlZCk7XG4gICAgfVxuXG4gICAgYXBwZW5kVGV4dCh0ZXh0LnNsaWNlKGN1cnNvcikpO1xuICB9XG5cbiAgcHJpdmF0ZSBfdXBkYXRlU2VuZEJ1dHRvbigpOiB2b2lkIHtcbiAgICAvLyBEaXNjb25uZWN0ZWQ6IGRpc2FibGUuXG4gICAgLy8gV29ya2luZzoga2VlcCBlbmFibGVkIHNvIHVzZXIgY2FuIHN0b3AvYWJvcnQuXG4gICAgY29uc3QgZGlzYWJsZWQgPSAhdGhpcy5pc0Nvbm5lY3RlZDtcbiAgICB0aGlzLnNlbmRCdG4uZGlzYWJsZWQgPSBkaXNhYmxlZDtcblxuICAgIHRoaXMuc2VuZEJ0bi50b2dnbGVDbGFzcygnaXMtd29ya2luZycsIHRoaXMuaXNXb3JraW5nKTtcbiAgICB0aGlzLnNlbmRCdG4uc2V0QXR0cignYXJpYS1idXN5JywgdGhpcy5pc1dvcmtpbmcgPyAndHJ1ZScgOiAnZmFsc2UnKTtcbiAgICB0aGlzLnNlbmRCdG4uc2V0QXR0cignYXJpYS1sYWJlbCcsIHRoaXMuaXNXb3JraW5nID8gJ1N0b3AnIDogJ1NlbmQnKTtcblxuICAgIGlmICh0aGlzLmlzV29ya2luZykge1xuICAgICAgLy8gUmVwbGFjZSBidXR0b24gY29udGVudHMgd2l0aCBTdG9wIGljb24gKyBzcGlubmVyIHJpbmcuXG4gICAgICB0aGlzLnNlbmRCdG4uZW1wdHkoKTtcbiAgICAgIGNvbnN0IHdyYXAgPSB0aGlzLnNlbmRCdG4uY3JlYXRlRGl2KHsgY2xzOiAnb2NsYXctc3RvcC13cmFwJyB9KTtcbiAgICAgIHdyYXAuY3JlYXRlRGl2KHsgY2xzOiAnb2NsYXctc3Bpbm5lci1yaW5nJywgYXR0cjogeyAnYXJpYS1oaWRkZW4nOiAndHJ1ZScgfSB9KTtcbiAgICAgIHdyYXAuY3JlYXRlRGl2KHsgY2xzOiAnb2NsYXctc3RvcC1pY29uJywgYXR0cjogeyAnYXJpYS1oaWRkZW4nOiAndHJ1ZScgfSB9KTtcbiAgICB9IGVsc2Uge1xuICAgICAgLy8gUmVzdG9yZSBsYWJlbFxuICAgICAgdGhpcy5zZW5kQnRuLnNldFRleHQoJ1NlbmQnKTtcbiAgICB9XG4gIH1cblxuICAvLyBcdTI1MDBcdTI1MDAgU2VuZCBoYW5kbGVyIFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFxuXG4gIHByaXZhdGUgYXN5bmMgX2hhbmRsZVNlbmQoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgLy8gV2hpbGUgd29ya2luZywgdGhlIGJ1dHRvbiBiZWNvbWVzIFN0b3AuXG4gICAgaWYgKHRoaXMuaXNXb3JraW5nKSB7XG4gICAgICBjb25zdCBvayA9IGF3YWl0IHRoaXMucGx1Z2luLndzQ2xpZW50LmFib3J0QWN0aXZlUnVuKCk7XG4gICAgICBpZiAoIW9rKSB7XG4gICAgICAgIG5ldyBOb3RpY2UoJ09wZW5DbGF3IENoYXQ6IGZhaWxlZCB0byBzdG9wJyk7XG4gICAgICAgIHRoaXMuY2hhdE1hbmFnZXIuYWRkTWVzc2FnZShDaGF0TWFuYWdlci5jcmVhdGVTeXN0ZW1NZXNzYWdlKCdcdTI2QTAgU3RvcCBmYWlsZWQnLCAnZXJyb3InKSk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICB0aGlzLmNoYXRNYW5hZ2VyLmFkZE1lc3NhZ2UoQ2hhdE1hbmFnZXIuY3JlYXRlU3lzdGVtTWVzc2FnZSgnXHUyNkQ0IFN0b3BwZWQnLCAnaW5mbycpKTtcbiAgICAgIH1cbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICBjb25zdCB0ZXh0ID0gdGhpcy5pbnB1dEVsLnZhbHVlLnRyaW0oKTtcbiAgICBpZiAoIXRleHQpIHJldHVybjtcblxuICAgIC8vIEJ1aWxkIG1lc3NhZ2Ugd2l0aCBjb250ZXh0IGlmIGVuYWJsZWRcbiAgICBsZXQgbWVzc2FnZSA9IHRleHQ7XG4gICAgaWYgKHRoaXMuaW5jbHVkZU5vdGVDaGVja2JveC5jaGVja2VkKSB7XG4gICAgICBjb25zdCBub3RlID0gYXdhaXQgZ2V0QWN0aXZlTm90ZUNvbnRleHQodGhpcy5hcHApO1xuICAgICAgaWYgKG5vdGUpIHtcbiAgICAgICAgbWVzc2FnZSA9IGBDb250ZXh0OiBbWyR7bm90ZS50aXRsZX1dXVxcblxcbiR7dGV4dH1gO1xuICAgICAgfVxuICAgIH1cblxuICAgIC8vIEFkZCB1c2VyIG1lc3NhZ2UgdG8gY2hhdCBVSVxuICAgIGNvbnN0IHVzZXJNc2cgPSBDaGF0TWFuYWdlci5jcmVhdGVVc2VyTWVzc2FnZSh0ZXh0KTtcbiAgICB0aGlzLmNoYXRNYW5hZ2VyLmFkZE1lc3NhZ2UodXNlck1zZyk7XG5cbiAgICAvLyBDbGVhciBpbnB1dFxuICAgIHRoaXMuaW5wdXRFbC52YWx1ZSA9ICcnO1xuICAgIHRoaXMuaW5wdXRFbC5zdHlsZS5oZWlnaHQgPSAnYXV0byc7XG5cbiAgICAvLyBTZW5kIG92ZXIgV1MgKGFzeW5jKVxuICAgIHRyeSB7XG4gICAgICBhd2FpdCB0aGlzLnBsdWdpbi53c0NsaWVudC5zZW5kTWVzc2FnZShtZXNzYWdlKTtcbiAgICB9IGNhdGNoIChlcnIpIHtcbiAgICAgIGNvbnNvbGUuZXJyb3IoJ1tvY2xhd10gU2VuZCBmYWlsZWQnLCBlcnIpO1xuICAgICAgbmV3IE5vdGljZShgT3BlbkNsYXcgQ2hhdDogc2VuZCBmYWlsZWQgKCR7U3RyaW5nKGVycil9KWApO1xuICAgICAgdGhpcy5jaGF0TWFuYWdlci5hZGRNZXNzYWdlKFxuICAgICAgICBDaGF0TWFuYWdlci5jcmVhdGVTeXN0ZW1NZXNzYWdlKGBcdTI2QTAgU2VuZCBmYWlsZWQ6ICR7ZXJyfWAsICdlcnJvcicpXG4gICAgICApO1xuICAgIH1cbiAgfVxufVxuIiwgImltcG9ydCB0eXBlIHsgUGF0aE1hcHBpbmcgfSBmcm9tICcuL3R5cGVzJztcblxuZXhwb3J0IGZ1bmN0aW9uIG5vcm1hbGl6ZUJhc2UoYmFzZTogc3RyaW5nKTogc3RyaW5nIHtcbiAgY29uc3QgdHJpbW1lZCA9IFN0cmluZyhiYXNlID8/ICcnKS50cmltKCk7XG4gIGlmICghdHJpbW1lZCkgcmV0dXJuICcnO1xuICByZXR1cm4gdHJpbW1lZC5lbmRzV2l0aCgnLycpID8gdHJpbW1lZCA6IGAke3RyaW1tZWR9L2A7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiB0cnlNYXBSZW1vdGVQYXRoVG9WYXVsdFBhdGgoaW5wdXQ6IHN0cmluZywgbWFwcGluZ3M6IHJlYWRvbmx5IFBhdGhNYXBwaW5nW10pOiBzdHJpbmcgfCBudWxsIHtcbiAgY29uc3QgcmF3ID0gU3RyaW5nKGlucHV0ID8/ICcnKTtcbiAgZm9yIChjb25zdCByb3cgb2YgbWFwcGluZ3MpIHtcbiAgICBjb25zdCByZW1vdGVCYXNlID0gbm9ybWFsaXplQmFzZShyb3cucmVtb3RlQmFzZSk7XG4gICAgY29uc3QgdmF1bHRCYXNlID0gbm9ybWFsaXplQmFzZShyb3cudmF1bHRCYXNlKTtcbiAgICBpZiAoIXJlbW90ZUJhc2UgfHwgIXZhdWx0QmFzZSkgY29udGludWU7XG5cbiAgICBpZiAocmF3LnN0YXJ0c1dpdGgocmVtb3RlQmFzZSkpIHtcbiAgICAgIGNvbnN0IHJlc3QgPSByYXcuc2xpY2UocmVtb3RlQmFzZS5sZW5ndGgpO1xuICAgICAgLy8gT2JzaWRpYW4gcGF0aHMgYXJlIHZhdWx0LXJlbGF0aXZlIGFuZCBzaG91bGQgbm90IHN0YXJ0IHdpdGggJy8nXG4gICAgICByZXR1cm4gYCR7dmF1bHRCYXNlfSR7cmVzdH1gLnJlcGxhY2UoL15cXC8rLywgJycpO1xuICAgIH1cbiAgfVxuICByZXR1cm4gbnVsbDtcbn1cblxuZXhwb3J0IHR5cGUgQ2FuZGlkYXRlID0geyBzdGFydDogbnVtYmVyOyBlbmQ6IG51bWJlcjsgcmF3OiBzdHJpbmc7IGtpbmQ6ICd1cmwnIHwgJ3BhdGgnIH07XG5cbi8vIENvbnNlcnZhdGl2ZSBleHRyYWN0aW9uOiBhaW0gdG8gYXZvaWQgZmFsc2UgcG9zaXRpdmVzLlxuY29uc3QgVVJMX1JFID0gL2h0dHBzPzpcXC9cXC9bXlxcczw+KCldKy9nO1xuLy8gQWJzb2x1dGUgdW5peC1pc2ggcGF0aHMuXG4vLyAoV2Ugc3RpbGwgZXhpc3RlbmNlLWNoZWNrIGJlZm9yZSBwcm9kdWNpbmcgYSBsaW5rLilcbmNvbnN0IFBBVEhfUkUgPSAvKD88IVtBLVphLXowLTkuXy1dKSg/OlxcL1tBLVphLXowLTkuX34hJCYnKCkqKyw7PTpAJVxcLV0rKSsoPzpcXC5bQS1aYS16MC05Ll8tXSspPy9nO1xuXG4vLyBDb25zZXJ2YXRpdmUgcmVsYXRpdmUgcGF0aHMgd2l0aCBhdCBsZWFzdCBvbmUgJy8nLCBlLmcuIGNvbXBlbmcvcGxhbnMveC5tZFxuLy8gQXZvaWRzIG1hdGNoaW5nIHNjaGVtZS1saWtlIHRva2VucyB2aWEgbmVnYXRpdmUgbG9va2FoZWFkIGZvciAnOi8vJy5cbmNvbnN0IFJFTF9QQVRIX1JFID0gL1xcYig/IVtBLVphLXpdW0EtWmEtejAtOSsuLV0qOlxcL1xcLylbQS1aYS16MC05Ll8tXSsoPzpcXC9bQS1aYS16MC05Ll8tXSspKyg/OlxcLltBLVphLXowLTkuXy1dKyk/XFxiL2c7XG5cbmV4cG9ydCBmdW5jdGlvbiBleHRyYWN0Q2FuZGlkYXRlcyh0ZXh0OiBzdHJpbmcpOiBDYW5kaWRhdGVbXSB7XG4gIGNvbnN0IHQgPSBTdHJpbmcodGV4dCA/PyAnJyk7XG4gIGNvbnN0IG91dDogQ2FuZGlkYXRlW10gPSBbXTtcblxuICBmb3IgKGNvbnN0IG0gb2YgdC5tYXRjaEFsbChVUkxfUkUpKSB7XG4gICAgaWYgKG0uaW5kZXggPT09IHVuZGVmaW5lZCkgY29udGludWU7XG4gICAgb3V0LnB1c2goeyBzdGFydDogbS5pbmRleCwgZW5kOiBtLmluZGV4ICsgbVswXS5sZW5ndGgsIHJhdzogbVswXSwga2luZDogJ3VybCcgfSk7XG4gIH1cblxuICBmb3IgKGNvbnN0IG0gb2YgdC5tYXRjaEFsbChQQVRIX1JFKSkge1xuICAgIGlmIChtLmluZGV4ID09PSB1bmRlZmluZWQpIGNvbnRpbnVlO1xuXG4gICAgLy8gU2tpcCBpZiB0aGlzIGlzIGluc2lkZSBhIFVSTCB3ZSBhbHJlYWR5IGNhcHR1cmVkLlxuICAgIGNvbnN0IHN0YXJ0ID0gbS5pbmRleDtcbiAgICBjb25zdCBlbmQgPSBzdGFydCArIG1bMF0ubGVuZ3RoO1xuICAgIGNvbnN0IG92ZXJsYXBzVXJsID0gb3V0LnNvbWUoKGMpID0+IGMua2luZCA9PT0gJ3VybCcgJiYgIShlbmQgPD0gYy5zdGFydCB8fCBzdGFydCA+PSBjLmVuZCkpO1xuICAgIGlmIChvdmVybGFwc1VybCkgY29udGludWU7XG5cbiAgICBvdXQucHVzaCh7IHN0YXJ0LCBlbmQsIHJhdzogbVswXSwga2luZDogJ3BhdGgnIH0pO1xuICB9XG5cbiAgZm9yIChjb25zdCBtIG9mIHQubWF0Y2hBbGwoUkVMX1BBVEhfUkUpKSB7XG4gICAgaWYgKG0uaW5kZXggPT09IHVuZGVmaW5lZCkgY29udGludWU7XG5cbiAgICBjb25zdCBzdGFydCA9IG0uaW5kZXg7XG4gICAgY29uc3QgZW5kID0gc3RhcnQgKyBtWzBdLmxlbmd0aDtcbiAgICBjb25zdCBvdmVybGFwc0V4aXN0aW5nID0gb3V0LnNvbWUoKGMpID0+ICEoZW5kIDw9IGMuc3RhcnQgfHwgc3RhcnQgPj0gYy5lbmQpKTtcbiAgICBpZiAob3ZlcmxhcHNFeGlzdGluZykgY29udGludWU7XG5cbiAgICBvdXQucHVzaCh7IHN0YXJ0LCBlbmQsIHJhdzogbVswXSwga2luZDogJ3BhdGgnIH0pO1xuICB9XG5cbiAgLy8gU29ydCBhbmQgZHJvcCBvdmVybGFwcyAocHJlZmVyIFVSTHMpLlxuICBvdXQuc29ydCgoYSwgYikgPT4gYS5zdGFydCAtIGIuc3RhcnQgfHwgKGEua2luZCA9PT0gJ3VybCcgPyAtMSA6IDEpKTtcbiAgY29uc3QgZGVkdXA6IENhbmRpZGF0ZVtdID0gW107XG4gIGZvciAoY29uc3QgYyBvZiBvdXQpIHtcbiAgICBjb25zdCBsYXN0ID0gZGVkdXBbZGVkdXAubGVuZ3RoIC0gMV07XG4gICAgaWYgKCFsYXN0KSB7XG4gICAgICBkZWR1cC5wdXNoKGMpO1xuICAgICAgY29udGludWU7XG4gICAgfVxuICAgIGlmIChjLnN0YXJ0IDwgbGFzdC5lbmQpIGNvbnRpbnVlO1xuICAgIGRlZHVwLnB1c2goYyk7XG4gIH1cblxuICByZXR1cm4gZGVkdXA7XG59XG4iLCAiaW1wb3J0IHR5cGUgeyBBcHAgfSBmcm9tICdvYnNpZGlhbic7XG5cbmV4cG9ydCBpbnRlcmZhY2UgTm90ZUNvbnRleHQge1xuICB0aXRsZTogc3RyaW5nO1xuICBwYXRoOiBzdHJpbmc7XG4gIGNvbnRlbnQ6IHN0cmluZztcbn1cblxuLyoqXG4gKiBSZXR1cm5zIHRoZSBhY3RpdmUgbm90ZSdzIHRpdGxlIGFuZCBjb250ZW50LCBvciBudWxsIGlmIG5vIG5vdGUgaXMgb3Blbi5cbiAqIEFzeW5jIGJlY2F1c2UgdmF1bHQucmVhZCgpIGlzIGFzeW5jLlxuICovXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZ2V0QWN0aXZlTm90ZUNvbnRleHQoYXBwOiBBcHApOiBQcm9taXNlPE5vdGVDb250ZXh0IHwgbnVsbD4ge1xuICBjb25zdCBmaWxlID0gYXBwLndvcmtzcGFjZS5nZXRBY3RpdmVGaWxlKCk7XG4gIGlmICghZmlsZSkgcmV0dXJuIG51bGw7XG5cbiAgdHJ5IHtcbiAgICBjb25zdCBjb250ZW50ID0gYXdhaXQgYXBwLnZhdWx0LnJlYWQoZmlsZSk7XG4gICAgcmV0dXJuIHtcbiAgICAgIHRpdGxlOiBmaWxlLmJhc2VuYW1lLFxuICAgICAgcGF0aDogZmlsZS5wYXRoLFxuICAgICAgY29udGVudCxcbiAgICB9O1xuICB9IGNhdGNoIChlcnIpIHtcbiAgICBjb25zb2xlLmVycm9yKCdbb2NsYXctY29udGV4dF0gRmFpbGVkIHRvIHJlYWQgYWN0aXZlIG5vdGUnLCBlcnIpO1xuICAgIHJldHVybiBudWxsO1xuICB9XG59XG4iLCAiLyoqIFBlcnNpc3RlZCBwbHVnaW4gY29uZmlndXJhdGlvbiAqL1xuZXhwb3J0IGludGVyZmFjZSBPcGVuQ2xhd1NldHRpbmdzIHtcbiAgLyoqIFdlYlNvY2tldCBVUkwgb2YgdGhlIE9wZW5DbGF3IEdhdGV3YXkgKGUuZy4gd3M6Ly8xMDAuOTAuOS42ODoxODc4OSkgKi9cbiAgZ2F0ZXdheVVybDogc3RyaW5nO1xuICAvKiogQXV0aCB0b2tlbiBcdTIwMTQgbXVzdCBtYXRjaCB0aGUgY2hhbm5lbCBwbHVnaW4ncyBhdXRoVG9rZW4gKi9cbiAgYXV0aFRva2VuOiBzdHJpbmc7XG4gIC8qKiBPcGVuQ2xhdyBzZXNzaW9uIGtleSB0byBzdWJzY3JpYmUgdG8gKGUuZy4gXCJtYWluXCIpICovXG4gIHNlc3Npb25LZXk6IHN0cmluZztcbiAgLyoqIChEZXByZWNhdGVkKSBPcGVuQ2xhdyBhY2NvdW50IElEICh1bnVzZWQ7IGNoYXQuc2VuZCB1c2VzIHNlc3Npb25LZXkpICovXG4gIGFjY291bnRJZDogc3RyaW5nO1xuICAvKiogV2hldGhlciB0byBpbmNsdWRlIHRoZSBhY3RpdmUgbm90ZSBjb250ZW50IHdpdGggZWFjaCBtZXNzYWdlICovXG4gIGluY2x1ZGVBY3RpdmVOb3RlOiBib29sZWFuO1xuICAvKiogUmVuZGVyIGFzc2lzdGFudCBvdXRwdXQgYXMgTWFya2Rvd24gKHVuc2FmZTogbWF5IHRyaWdnZXIgZW1iZWRzL3Bvc3QtcHJvY2Vzc29ycyk7IGRlZmF1bHQgT0ZGICovXG4gIHJlbmRlckFzc2lzdGFudE1hcmtkb3duOiBib29sZWFuO1xuICAvKiogQWxsb3cgdXNpbmcgaW5zZWN1cmUgd3M6Ly8gZm9yIG5vbi1sb2NhbCBnYXRld2F5IFVSTHMgKHVuc2FmZSk7IGRlZmF1bHQgT0ZGICovXG4gIGFsbG93SW5zZWN1cmVXczogYm9vbGVhbjtcblxuICAvKiogT3B0aW9uYWw6IG1hcCByZW1vdGUgRlMgcGF0aHMgLyBleHBvcnRlZCBwYXRocyBiYWNrIHRvIHZhdWx0LXJlbGF0aXZlIHBhdGhzICovXG4gIHBhdGhNYXBwaW5nczogUGF0aE1hcHBpbmdbXTtcblxuICAvKiogVmF1bHQgaWRlbnRpdHkgKGhhc2gpIHVzZWQgZm9yIGNhbm9uaWNhbCBzZXNzaW9uIGtleXMuICovXG4gIHZhdWx0SGFzaD86IHN0cmluZztcblxuICAvKiogS25vd24gT2JzaWRpYW4gc2Vzc2lvbiBrZXlzIGZvciBlYWNoIHZhdWx0SGFzaCAodmF1bHQtc2NvcGVkIGNvbnRpbnVpdHkpLiAqL1xuICBrbm93blNlc3Npb25LZXlzQnlWYXVsdD86IFJlY29yZDxzdHJpbmcsIHN0cmluZ1tdPjtcblxuICAvKiogTGVnYWN5IGtleXMga2VwdCBmb3IgbWlncmF0aW9uL2RlYnVnIChvcHRpb25hbCkuICovXG4gIGxlZ2FjeVNlc3Npb25LZXlzPzogc3RyaW5nW107XG59XG5cbmV4cG9ydCB0eXBlIFBhdGhNYXBwaW5nID0ge1xuICAvKiogVmF1bHQtcmVsYXRpdmUgYmFzZSBwYXRoIChlLmcuIFwiZG9jcy9cIiBvciBcImNvbXBlbmcvXCIpICovXG4gIHZhdWx0QmFzZTogc3RyaW5nO1xuICAvKiogUmVtb3RlIEZTIGJhc2UgcGF0aCAoZS5nLiBcIi9ob21lL3dhbGwtZS8ub3BlbmNsYXcvd29ya3NwYWNlL2RvY3MvXCIpICovXG4gIHJlbW90ZUJhc2U6IHN0cmluZztcbn07XG5cbmV4cG9ydCBjb25zdCBERUZBVUxUX1NFVFRJTkdTOiBPcGVuQ2xhd1NldHRpbmdzID0ge1xuICBnYXRld2F5VXJsOiAnd3M6Ly9sb2NhbGhvc3Q6MTg3ODknLFxuICBhdXRoVG9rZW46ICcnLFxuICBzZXNzaW9uS2V5OiAnbWFpbicsXG4gIGFjY291bnRJZDogJ21haW4nLFxuICBpbmNsdWRlQWN0aXZlTm90ZTogZmFsc2UsXG4gIHJlbmRlckFzc2lzdGFudE1hcmtkb3duOiBmYWxzZSxcbiAgYWxsb3dJbnNlY3VyZVdzOiBmYWxzZSxcbiAgcGF0aE1hcHBpbmdzOiBbXSxcbiAgdmF1bHRIYXNoOiB1bmRlZmluZWQsXG4gIGtub3duU2Vzc2lvbktleXNCeVZhdWx0OiB7fSxcbiAgbGVnYWN5U2Vzc2lvbktleXM6IFtdLFxufTtcblxuLyoqIEEgc2luZ2xlIGNoYXQgbWVzc2FnZSAqL1xuZXhwb3J0IGludGVyZmFjZSBDaGF0TWVzc2FnZSB7XG4gIGlkOiBzdHJpbmc7XG4gIHJvbGU6ICd1c2VyJyB8ICdhc3Npc3RhbnQnIHwgJ3N5c3RlbSc7XG4gIC8qKiBPcHRpb25hbCBzZXZlcml0eSBmb3Igc3lzdGVtL3N0YXR1cyBtZXNzYWdlcyAqL1xuICBsZXZlbD86ICdpbmZvJyB8ICdlcnJvcic7XG4gIC8qKiBPcHRpb25hbCBzdWJ0eXBlIGZvciBzdHlsaW5nIHNwZWNpYWwgc3lzdGVtIG1lc3NhZ2VzIChlLmcuIHNlc3Npb24gZGl2aWRlcikuICovXG4gIGtpbmQ/OiAnc2Vzc2lvbi1kaXZpZGVyJztcbiAgLyoqIE9wdGlvbmFsIGhvdmVyIHRvb2x0aXAgZm9yIHRoZSBtZXNzYWdlIChlLmcuIGZ1bGwgc2Vzc2lvbiBrZXkpLiAqL1xuICB0aXRsZT86IHN0cmluZztcbiAgY29udGVudDogc3RyaW5nO1xuICB0aW1lc3RhbXA6IG51bWJlcjtcbn1cblxuLyoqIFBheWxvYWQgZm9yIG1lc3NhZ2VzIFNFTlQgdG8gdGhlIHNlcnZlciAob3V0Ym91bmQpICovXG5leHBvcnQgaW50ZXJmYWNlIFdTUGF5bG9hZCB7XG4gIHR5cGU6ICdhdXRoJyB8ICdtZXNzYWdlJyB8ICdwaW5nJyB8ICdwb25nJyB8ICdlcnJvcic7XG4gIHBheWxvYWQ/OiBSZWNvcmQ8c3RyaW5nLCB1bmtub3duPjtcbn1cblxuLyoqIE1lc3NhZ2VzIFJFQ0VJVkVEIGZyb20gdGhlIHNlcnZlciAoaW5ib3VuZCkgXHUyMDE0IGRpc2NyaW1pbmF0ZWQgdW5pb24gKi9cbmV4cG9ydCB0eXBlIEluYm91bmRXU1BheWxvYWQgPVxuICB8IHsgdHlwZTogJ21lc3NhZ2UnOyBwYXlsb2FkOiB7IGNvbnRlbnQ6IHN0cmluZzsgcm9sZTogc3RyaW5nOyB0aW1lc3RhbXA6IG51bWJlciB9IH1cbiAgfCB7IHR5cGU6ICdlcnJvcic7IHBheWxvYWQ6IHsgbWVzc2FnZTogc3RyaW5nIH0gfTtcblxuLyoqIEF2YWlsYWJsZSBhZ2VudHMgLyBtb2RlbHMgKi9cbmV4cG9ydCBpbnRlcmZhY2UgQWdlbnRPcHRpb24ge1xuICBpZDogc3RyaW5nO1xuICBsYWJlbDogc3RyaW5nO1xufVxuIl0sCiAgIm1hcHBpbmdzIjogIjs7Ozs7Ozs7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bUI7QUFDekIsU0FBSyxTQUFTLFFBQVEsS0FBSyxTQUFTLFlBQVksS0FBSyxTQUFTLFdBQVc7QUFBQSxNQUN2RSxpQkFBaUIsS0FBSyxTQUFTO0FBQUEsSUFDakMsQ0FBQztBQUFBLEVBQ0g7QUFBQSxFQUVjLG9CQUFtQztBQUFBO0FBQy9DLFlBQU0sRUFBRSxVQUFVLElBQUksS0FBSztBQUczQixZQUFNLFdBQVcsVUFBVSxnQkFBZ0IsdUJBQXVCO0FBQ2xFLFVBQUksU0FBUyxTQUFTLEdBQUc7QUFDdkIsa0JBQVUsV0FBVyxTQUFTLENBQUMsQ0FBQztBQUNoQztBQUFBLE1BQ0Y7QUFHQSxZQUFNLE9BQU8sVUFBVSxhQUFhLEtBQUs7QUFDekMsVUFBSSxDQUFDO0FBQU07QUFDWCxZQUFNLEtBQUssYUFBYSxFQUFFLE1BQU0seUJBQXlCLFFBQVEsS0FBSyxDQUFDO0FBQ3ZFLGdCQUFVLFdBQVcsSUFBSTtBQUFBLElBQzNCO0FBQUE7QUFDRjsiLAogICJuYW1lcyI6IFsiaW1wb3J0X29ic2lkaWFuIiwgIl9hIiwgImltcG9ydF9vYnNpZGlhbiIsICJtYXBwZWQiLCAiY3J5cHRvIiwgIl9hIl0KfQo=
