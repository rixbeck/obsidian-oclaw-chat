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

// src/view.ts
var import_obsidian2 = require("obsidian");

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
    this.chatManager = new ChatManager();
    this.wsClient = this.plugin.createWsClient(this.plugin.getDefaultSessionKey());
    this.wsClient.onMessage = (msg) => {
      var _a;
      if (msg.type === "message") {
        this.chatManager.addMessage(ChatManager.createAssistantMessage(msg.payload.content));
      } else if (msg.type === "error") {
        const errText = (_a = msg.payload.message) != null ? _a : "Unknown error from gateway";
        this.chatManager.addMessage(ChatManager.createSystemMessage(`\u26A0 ${errText}`, "error"));
      }
    };
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
      this.plugin.registerChatLeaf();
      this._buildUI();
      this.chatManager.onUpdate = (msgs) => this._renderMessages(msgs);
      this.chatManager.onMessageAdded = (msg) => this._appendMessage(msg);
      const gw = this.plugin.getGatewayConfig();
      if (gw.token) {
        this.wsClient.connect(gw.url, gw.token, { allowInsecureWs: gw.allowInsecureWs });
      } else {
        new import_obsidian2.Notice("OpenClaw Chat: please configure your gateway token in Settings.");
      }
      this.wsClient.onStateChange = (state) => {
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
      this.wsClient.onWorkingChange = (working) => {
        this.isWorking = working;
        this._updateSendButton();
      };
      this.lastGatewayState = this.wsClient.state;
      this.isConnected = this.wsClient.state === "connected";
      this.statusDot.toggleClass("connected", this.isConnected);
      this.statusDot.title = `Gateway: ${this.wsClient.state}`;
      this._updateSendButton();
      this._renderMessages(this.chatManager.getMessages());
      this._loadKnownSessions();
    });
  }
  onClose() {
    return __async(this, null, function* () {
      var _a;
      this.plugin.unregisterChatLeaf();
      this.chatManager.onUpdate = null;
      this.chatManager.onMessageAdded = null;
      this.wsClient.onStateChange = null;
      this.wsClient.onWorkingChange = null;
      this.wsClient.disconnect();
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
    this.sessionNewBtn.addEventListener("click", () => {
      if (!this.plugin.getVaultHash()) {
        new import_obsidian2.Notice("OpenClaw Chat: New session is unavailable (missing vault identity).");
        return;
      }
      void this._promptNewSession();
    });
    this.sessionMainBtn.addEventListener("click", () => {
      void (() => __async(this, null, function* () {
        yield this._switchSession("main");
        this._loadKnownSessions();
        this.sessionSelect.value = "main";
        this.sessionSelect.title = "main";
      }))();
    });
    this.sessionSelect.addEventListener("change", () => {
      if (this.suppressSessionSelectChange)
        return;
      const next = this.sessionSelect.value;
      if (!next)
        return;
      void (() => __async(this, null, function* () {
        yield this._switchSession(next);
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
    const prefix = vaultHash ? `agent:main:obsidian:direct:${vaultHash}` : "";
    const filtered = vaultHash ? keys.filter((k) => {
      const key = String(k || "").trim().toLowerCase();
      return key === prefix || key.startsWith(prefix + "-");
    }) : [];
    this._setSessionSelectOptions(filtered);
  }
  _switchSession(sessionKey) {
    return __async(this, null, function* () {
      const next = sessionKey.trim().toLowerCase();
      if (!next)
        return;
      const vaultHash = this.plugin.getVaultHash();
      if (vaultHash) {
        const prefix = `agent:main:obsidian:direct:${vaultHash}`;
        if (!(next === "main" || next === prefix || next.startsWith(prefix + "-"))) {
          new import_obsidian2.Notice("OpenClaw Chat: session key must match this vault.");
          return;
        }
      } else {
        if (next !== "main") {
          new import_obsidian2.Notice("OpenClaw Chat: cannot switch sessions (missing vault identity).");
          return;
        }
      }
      try {
        yield this.wsClient.abortActiveRun();
      } catch (e) {
      }
      this.chatManager.addMessage(ChatManager.createSessionDivider(next));
      yield this.plugin.rememberSessionKey(next);
      this.wsClient.disconnect();
      this.wsClient.setSessionKey(next);
      const gw = this.plugin.getGatewayConfig();
      if (gw.token) {
        this.wsClient.connect(gw.url, gw.token, { allowInsecureWs: gw.allowInsecureWs });
      } else {
        new import_obsidian2.Notice("OpenClaw Chat: please configure your gateway token in Settings.");
      }
    });
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
          yield this._switchSession(key);
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
        const ok = yield this.wsClient.abortActiveRun();
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
        yield this.wsClient.sendMessage(message);
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

// src/session.ts
function canonicalVaultSessionKey(vaultHash) {
  return `agent:main:obsidian:direct:${vaultHash}`;
}
function migrateSettingsForVault(settings, vaultHash) {
  var _a, _b;
  const canonicalKey = canonicalVaultSessionKey(vaultHash);
  const existing = ((_a = settings.sessionKey) != null ? _a : "").trim().toLowerCase();
  const isLegacy = existing.startsWith("obsidian-");
  const isEmptyOrMain = !existing || existing === "main" || existing === "agent:main:main";
  const next = __spreadValues({}, settings);
  next.vaultHash = vaultHash;
  if (isLegacy) {
    const legacy = Array.isArray(next.legacySessionKeys) ? next.legacySessionKeys : [];
    next.legacySessionKeys = [existing, ...legacy.filter((k) => k && k !== existing)].slice(0, 20);
  }
  if (isLegacy || isEmptyOrMain) {
    next.sessionKey = canonicalKey;
  }
  const map = (_b = next.knownSessionKeysByVault) != null ? _b : {};
  const cur = Array.isArray(map[vaultHash]) ? map[vaultHash] : [];
  if (!cur.includes(canonicalKey)) {
    map[vaultHash] = [canonicalKey, ...cur].slice(0, 20);
    next.knownSessionKeysByVault = map;
  }
  return { nextSettings: next, canonicalKey };
}

// src/main.ts
var _OpenClawPlugin = class _OpenClawPlugin extends import_obsidian3.Plugin {
  constructor() {
    super(...arguments);
    // NOTE: wsClient/chatManager are per-leaf (per view) to allow parallel sessions.
    this.openChatLeaves = 0;
    this.lastLeafWarnAtMs = 0;
    this._vaultHash = null;
    this._deviceIdentityKey = "_openclawDeviceIdentityV1";
  }
  registerChatLeaf() {
    this.openChatLeaves += 1;
    const now = Date.now();
    if (this.openChatLeaves > _OpenClawPlugin.MAX_CHAT_LEAVES && now - this.lastLeafWarnAtMs > 6e4) {
      this.lastLeafWarnAtMs = now;
      new import_obsidian3.Notice(
        `OpenClaw Chat: ${this.openChatLeaves} chat views are open. This may increase gateway load.`
      );
    }
  }
  unregisterChatLeaf() {
    this.openChatLeaves = Math.max(0, this.openChatLeaves - 1);
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
  // canonical session key helpers live in src/session.ts
  getVaultHash() {
    return this._vaultHash;
  }
  getDefaultSessionKey() {
    var _a;
    return ((_a = this.settings.sessionKey) != null ? _a : "main").trim().toLowerCase();
  }
  getGatewayConfig() {
    return {
      url: String(this.settings.gatewayUrl || ""),
      token: String(this.settings.authToken || ""),
      allowInsecureWs: Boolean(this.settings.allowInsecureWs)
    };
  }
  /** Persist + remember an Obsidian session key for the current vault. */
  rememberSessionKey(sessionKey) {
    return __async(this, null, function* () {
      var _a;
      const next = sessionKey.trim().toLowerCase();
      if (!next)
        return;
      const vaultHash = this._vaultHash;
      if (vaultHash) {
        const prefix = `agent:main:obsidian:direct:${vaultHash}`;
        if (!(next === "main" || next === prefix || next.startsWith(prefix + "-"))) {
          return;
        }
      } else {
        if (next !== "main")
          return;
      }
      this.settings.sessionKey = next;
      if (this._vaultHash) {
        const map = (_a = this.settings.knownSessionKeysByVault) != null ? _a : {};
        const cur = Array.isArray(map[this._vaultHash]) ? map[this._vaultHash] : [];
        const nextList = [next, ...cur.filter((k) => k && k !== next)].slice(0, 20);
        map[this._vaultHash] = nextList;
        this.settings.knownSessionKeysByVault = map;
      }
      yield this.saveSettings();
    });
  }
  createWsClient(sessionKey) {
    return new ObsidianWSClient(sessionKey.trim().toLowerCase(), {
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
  }
  onload() {
    return __async(this, null, function* () {
      yield this.loadSettings();
      this._vaultHash = this._computeVaultHash();
      if (this._vaultHash) {
        this.settings.vaultHash = this._vaultHash;
        const migrated = migrateSettingsForVault(this.settings, this._vaultHash);
        this.settings = migrated.nextSettings;
        yield this.saveSettings();
      } else {
        new import_obsidian3.Notice("OpenClaw Chat: could not determine vault identity (vaultHash).");
      }
      this.registerView(VIEW_TYPE_OPENCLAW_CHAT, (leaf) => new OpenClawChatView(leaf, this));
      this.addRibbonIcon("message-square", "OpenClaw Chat", () => {
        void this._activateChatView();
      });
      this.addSettingTab(new OpenClawSettingTab(this.app, this));
      this.addCommand({
        id: "open-openclaw-chat",
        name: "Open chat sidebar",
        callback: () => void this._activateChatView()
      });
      console.log("[oclaw] Plugin loaded");
    });
  }
  onunload() {
    return __async(this, null, function* () {
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
_OpenClawPlugin.MAX_CHAT_LEAVES = 3;
var OpenClawPlugin = _OpenClawPlugin;
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsic3JjL21haW4udHMiLCAic3JjL3NldHRpbmdzLnRzIiwgInNyYy93ZWJzb2NrZXQudHMiLCAic3JjL3ZpZXcudHMiLCAic3JjL2NoYXQudHMiLCAic3JjL2xpbmtpZnkudHMiLCAic3JjL2NvbnRleHQudHMiLCAic3JjL3R5cGVzLnRzIiwgInNyYy9zZXNzaW9uLnRzIl0sCiAgInNvdXJjZXNDb250ZW50IjogWyJpbXBvcnQgeyBGaWxlU3lzdGVtQWRhcHRlciwgTm90aWNlLCBQbHVnaW4sIFdvcmtzcGFjZUxlYWYgfSBmcm9tICdvYnNpZGlhbic7XG5pbXBvcnQgeyBPcGVuQ2xhd1NldHRpbmdUYWIgfSBmcm9tICcuL3NldHRpbmdzJztcbmltcG9ydCB7IE9ic2lkaWFuV1NDbGllbnQgfSBmcm9tICcuL3dlYnNvY2tldCc7XG5pbXBvcnQgeyBWSUVXX1RZUEVfT1BFTkNMQVdfQ0hBVCwgT3BlbkNsYXdDaGF0VmlldyB9IGZyb20gJy4vdmlldyc7XG5pbXBvcnQgeyBERUZBVUxUX1NFVFRJTkdTLCB0eXBlIE9wZW5DbGF3U2V0dGluZ3MgfSBmcm9tICcuL3R5cGVzJztcbmltcG9ydCB7IG1pZ3JhdGVTZXR0aW5nc0ZvclZhdWx0IH0gZnJvbSAnLi9zZXNzaW9uJztcblxuZXhwb3J0IGRlZmF1bHQgY2xhc3MgT3BlbkNsYXdQbHVnaW4gZXh0ZW5kcyBQbHVnaW4ge1xuICBzZXR0aW5ncyE6IE9wZW5DbGF3U2V0dGluZ3M7XG5cbiAgLy8gTk9URTogd3NDbGllbnQvY2hhdE1hbmFnZXIgYXJlIHBlci1sZWFmIChwZXIgdmlldykgdG8gYWxsb3cgcGFyYWxsZWwgc2Vzc2lvbnMuXG4gIHByaXZhdGUgb3BlbkNoYXRMZWF2ZXMgPSAwO1xuICBwcml2YXRlIGxhc3RMZWFmV2FybkF0TXMgPSAwO1xuICBwcml2YXRlIHN0YXRpYyBNQVhfQ0hBVF9MRUFWRVMgPSAzO1xuXG4gIHJlZ2lzdGVyQ2hhdExlYWYoKTogdm9pZCB7XG4gICAgdGhpcy5vcGVuQ2hhdExlYXZlcyArPSAxO1xuICAgIGNvbnN0IG5vdyA9IERhdGUubm93KCk7XG4gICAgaWYgKHRoaXMub3BlbkNoYXRMZWF2ZXMgPiBPcGVuQ2xhd1BsdWdpbi5NQVhfQ0hBVF9MRUFWRVMgJiYgbm93IC0gdGhpcy5sYXN0TGVhZldhcm5BdE1zID4gNjBfMDAwKSB7XG4gICAgICB0aGlzLmxhc3RMZWFmV2FybkF0TXMgPSBub3c7XG4gICAgICBuZXcgTm90aWNlKFxuICAgICAgICBgT3BlbkNsYXcgQ2hhdDogJHt0aGlzLm9wZW5DaGF0TGVhdmVzfSBjaGF0IHZpZXdzIGFyZSBvcGVuLiBUaGlzIG1heSBpbmNyZWFzZSBnYXRld2F5IGxvYWQuYFxuICAgICAgKTtcbiAgICB9XG4gIH1cblxuICB1bnJlZ2lzdGVyQ2hhdExlYWYoKTogdm9pZCB7XG4gICAgdGhpcy5vcGVuQ2hhdExlYXZlcyA9IE1hdGgubWF4KDAsIHRoaXMub3BlbkNoYXRMZWF2ZXMgLSAxKTtcbiAgfVxuXG4gIHByaXZhdGUgX3ZhdWx0SGFzaDogc3RyaW5nIHwgbnVsbCA9IG51bGw7XG5cbiAgcHJpdmF0ZSBfY29tcHV0ZVZhdWx0SGFzaCgpOiBzdHJpbmcgfCBudWxsIHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgYWRhcHRlciA9IHRoaXMuYXBwLnZhdWx0LmFkYXB0ZXI7XG4gICAgICAvLyBEZXNrdG9wIG9ubHk6IEZpbGVTeXN0ZW1BZGFwdGVyIHByb3ZpZGVzIGEgc3RhYmxlIGJhc2UgcGF0aC5cbiAgICAgIGlmIChhZGFwdGVyIGluc3RhbmNlb2YgRmlsZVN5c3RlbUFkYXB0ZXIpIHtcbiAgICAgICAgY29uc3QgYmFzZVBhdGggPSBhZGFwdGVyLmdldEJhc2VQYXRoKCk7XG4gICAgICAgIGlmIChiYXNlUGF0aCkge1xuICAgICAgICAgIC8vIFVzZSBOb2RlIGNyeXB0byAoRWxlY3Ryb24gZW52aXJvbm1lbnQpLlxuICAgICAgICAgIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBAdHlwZXNjcmlwdC1lc2xpbnQvbm8tdmFyLXJlcXVpcmVzXG4gICAgICAgICAgY29uc3QgY3J5cHRvID0gcmVxdWlyZSgnY3J5cHRvJykgYXMgdHlwZW9mIGltcG9ydCgnY3J5cHRvJyk7XG4gICAgICAgICAgY29uc3QgaGV4ID0gY3J5cHRvLmNyZWF0ZUhhc2goJ3NoYTI1NicpLnVwZGF0ZShiYXNlUGF0aCwgJ3V0ZjgnKS5kaWdlc3QoJ2hleCcpO1xuICAgICAgICAgIHJldHVybiBoZXguc2xpY2UoMCwgMTYpO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSBjYXRjaCB7XG4gICAgICAvLyBpZ25vcmVcbiAgICB9XG4gICAgcmV0dXJuIG51bGw7XG4gIH1cblxuICAvLyBjYW5vbmljYWwgc2Vzc2lvbiBrZXkgaGVscGVycyBsaXZlIGluIHNyYy9zZXNzaW9uLnRzXG5cbiAgZ2V0VmF1bHRIYXNoKCk6IHN0cmluZyB8IG51bGwge1xuICAgIHJldHVybiB0aGlzLl92YXVsdEhhc2g7XG4gIH1cblxuICBnZXREZWZhdWx0U2Vzc2lvbktleSgpOiBzdHJpbmcge1xuICAgIHJldHVybiAodGhpcy5zZXR0aW5ncy5zZXNzaW9uS2V5ID8/ICdtYWluJykudHJpbSgpLnRvTG93ZXJDYXNlKCk7XG4gIH1cblxuICBnZXRHYXRld2F5Q29uZmlnKCk6IHsgdXJsOiBzdHJpbmc7IHRva2VuOiBzdHJpbmc7IGFsbG93SW5zZWN1cmVXczogYm9vbGVhbiB9IHtcbiAgICByZXR1cm4ge1xuICAgICAgdXJsOiBTdHJpbmcodGhpcy5zZXR0aW5ncy5nYXRld2F5VXJsIHx8ICcnKSxcbiAgICAgIHRva2VuOiBTdHJpbmcodGhpcy5zZXR0aW5ncy5hdXRoVG9rZW4gfHwgJycpLFxuICAgICAgYWxsb3dJbnNlY3VyZVdzOiBCb29sZWFuKHRoaXMuc2V0dGluZ3MuYWxsb3dJbnNlY3VyZVdzKSxcbiAgICB9O1xuICB9XG5cbiAgLyoqIFBlcnNpc3QgKyByZW1lbWJlciBhbiBPYnNpZGlhbiBzZXNzaW9uIGtleSBmb3IgdGhlIGN1cnJlbnQgdmF1bHQuICovXG4gIGFzeW5jIHJlbWVtYmVyU2Vzc2lvbktleShzZXNzaW9uS2V5OiBzdHJpbmcpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBjb25zdCBuZXh0ID0gc2Vzc2lvbktleS50cmltKCkudG9Mb3dlckNhc2UoKTtcbiAgICBpZiAoIW5leHQpIHJldHVybjtcblxuICAgIC8vIFNFQzogYWxsb3cgb25seSB2YXVsdC1zY29wZWQga2V5cyAod2hlbiB2YXVsdEhhc2gga25vd24pIG9yIG1haW4uXG4gICAgY29uc3QgdmF1bHRIYXNoID0gdGhpcy5fdmF1bHRIYXNoO1xuICAgIGlmICh2YXVsdEhhc2gpIHtcbiAgICAgIGNvbnN0IHByZWZpeCA9IGBhZ2VudDptYWluOm9ic2lkaWFuOmRpcmVjdDoke3ZhdWx0SGFzaH1gO1xuICAgICAgaWYgKCEobmV4dCA9PT0gJ21haW4nIHx8IG5leHQgPT09IHByZWZpeCB8fCBuZXh0LnN0YXJ0c1dpdGgocHJlZml4ICsgJy0nKSkpIHtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuICAgIH0gZWxzZSB7XG4gICAgICAvLyBXaXRob3V0IGEgdmF1bHQgaWRlbnRpdHksIG9ubHkgYWxsb3cgbWFpbi5cbiAgICAgIGlmIChuZXh0ICE9PSAnbWFpbicpIHJldHVybjtcbiAgICB9XG5cbiAgICB0aGlzLnNldHRpbmdzLnNlc3Npb25LZXkgPSBuZXh0O1xuXG4gICAgaWYgKHRoaXMuX3ZhdWx0SGFzaCkge1xuICAgICAgY29uc3QgbWFwID0gdGhpcy5zZXR0aW5ncy5rbm93blNlc3Npb25LZXlzQnlWYXVsdCA/PyB7fTtcbiAgICAgIGNvbnN0IGN1ciA9IEFycmF5LmlzQXJyYXkobWFwW3RoaXMuX3ZhdWx0SGFzaF0pID8gbWFwW3RoaXMuX3ZhdWx0SGFzaF0gOiBbXTtcbiAgICAgIGNvbnN0IG5leHRMaXN0ID0gW25leHQsIC4uLmN1ci5maWx0ZXIoKGspID0+IGsgJiYgayAhPT0gbmV4dCldLnNsaWNlKDAsIDIwKTtcbiAgICAgIG1hcFt0aGlzLl92YXVsdEhhc2hdID0gbmV4dExpc3Q7XG4gICAgICB0aGlzLnNldHRpbmdzLmtub3duU2Vzc2lvbktleXNCeVZhdWx0ID0gbWFwO1xuICAgIH1cblxuICAgIGF3YWl0IHRoaXMuc2F2ZVNldHRpbmdzKCk7XG4gIH1cblxuICBjcmVhdGVXc0NsaWVudChzZXNzaW9uS2V5OiBzdHJpbmcpOiBPYnNpZGlhbldTQ2xpZW50IHtcbiAgICByZXR1cm4gbmV3IE9ic2lkaWFuV1NDbGllbnQoc2Vzc2lvbktleS50cmltKCkudG9Mb3dlckNhc2UoKSwge1xuICAgICAgaWRlbnRpdHlTdG9yZToge1xuICAgICAgICBnZXQ6IGFzeW5jICgpID0+IChhd2FpdCB0aGlzLl9sb2FkRGV2aWNlSWRlbnRpdHkoKSksXG4gICAgICAgIHNldDogYXN5bmMgKGlkZW50aXR5KSA9PiBhd2FpdCB0aGlzLl9zYXZlRGV2aWNlSWRlbnRpdHkoaWRlbnRpdHkpLFxuICAgICAgICBjbGVhcjogYXN5bmMgKCkgPT4gYXdhaXQgdGhpcy5fY2xlYXJEZXZpY2VJZGVudGl0eSgpLFxuICAgICAgfSxcbiAgICB9KTtcbiAgfVxuXG4gIGFzeW5jIG9ubG9hZCgpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBhd2FpdCB0aGlzLmxvYWRTZXR0aW5ncygpO1xuXG4gICAgLy8gQ29tcHV0ZSB2YXVsdCBoYXNoIChkZXNrdG9wKSBhbmQgbWlncmF0ZSB0byBjYW5vbmljYWwgb2JzaWRpYW4gZGlyZWN0IHNlc3Npb24ga2V5LlxuICAgIHRoaXMuX3ZhdWx0SGFzaCA9IHRoaXMuX2NvbXB1dGVWYXVsdEhhc2goKTtcbiAgICBpZiAodGhpcy5fdmF1bHRIYXNoKSB7XG4gICAgICB0aGlzLnNldHRpbmdzLnZhdWx0SGFzaCA9IHRoaXMuX3ZhdWx0SGFzaDtcblxuICAgICAgY29uc3QgbWlncmF0ZWQgPSBtaWdyYXRlU2V0dGluZ3NGb3JWYXVsdCh0aGlzLnNldHRpbmdzLCB0aGlzLl92YXVsdEhhc2gpO1xuICAgICAgdGhpcy5zZXR0aW5ncyA9IG1pZ3JhdGVkLm5leHRTZXR0aW5ncztcbiAgICAgIGF3YWl0IHRoaXMuc2F2ZVNldHRpbmdzKCk7XG4gICAgfSBlbHNlIHtcbiAgICAgIC8vIEtlZXAgd29ya2luZywgYnV0IE5ldy1zZXNzaW9uIGNyZWF0aW9uIG1heSBiZSB1bmF2YWlsYWJsZS5cbiAgICAgIG5ldyBOb3RpY2UoJ09wZW5DbGF3IENoYXQ6IGNvdWxkIG5vdCBkZXRlcm1pbmUgdmF1bHQgaWRlbnRpdHkgKHZhdWx0SGFzaCkuJyk7XG4gICAgfVxuXG4gICAgLy8gUmVnaXN0ZXIgdGhlIHNpZGViYXIgdmlld1xuICAgIHRoaXMucmVnaXN0ZXJWaWV3KFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFULCAobGVhZjogV29ya3NwYWNlTGVhZikgPT4gbmV3IE9wZW5DbGF3Q2hhdFZpZXcobGVhZiwgdGhpcykpO1xuXG4gICAgLy8gUmliYm9uIGljb24gXHUyMDE0IG9wZW5zIC8gcmV2ZWFscyB0aGUgY2hhdCBzaWRlYmFyXG4gICAgdGhpcy5hZGRSaWJib25JY29uKCdtZXNzYWdlLXNxdWFyZScsICdPcGVuQ2xhdyBDaGF0JywgKCkgPT4ge1xuICAgICAgdm9pZCB0aGlzLl9hY3RpdmF0ZUNoYXRWaWV3KCk7XG4gICAgfSk7XG5cbiAgICAvLyBTZXR0aW5ncyB0YWJcbiAgICB0aGlzLmFkZFNldHRpbmdUYWIobmV3IE9wZW5DbGF3U2V0dGluZ1RhYih0aGlzLmFwcCwgdGhpcykpO1xuXG4gICAgLy8gQ29tbWFuZCBwYWxldHRlIGVudHJ5XG4gICAgdGhpcy5hZGRDb21tYW5kKHtcbiAgICAgIGlkOiAnb3Blbi1vcGVuY2xhdy1jaGF0JyxcbiAgICAgIG5hbWU6ICdPcGVuIGNoYXQgc2lkZWJhcicsXG4gICAgICBjYWxsYmFjazogKCkgPT4gdm9pZCB0aGlzLl9hY3RpdmF0ZUNoYXRWaWV3KCksXG4gICAgfSk7XG5cbiAgICBjb25zb2xlLmxvZygnW29jbGF3XSBQbHVnaW4gbG9hZGVkJyk7XG4gIH1cblxuICBhc3luYyBvbnVubG9hZCgpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICB0aGlzLmFwcC53b3Jrc3BhY2UuZGV0YWNoTGVhdmVzT2ZUeXBlKFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFUKTtcbiAgICBjb25zb2xlLmxvZygnW29jbGF3XSBQbHVnaW4gdW5sb2FkZWQnKTtcbiAgfVxuXG4gIGFzeW5jIGxvYWRTZXR0aW5ncygpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBjb25zdCBkYXRhID0gKGF3YWl0IHRoaXMubG9hZERhdGEoKSkgPz8ge307XG4gICAgLy8gTk9URTogcGx1Z2luIGRhdGEgbWF5IGNvbnRhaW4gZXh0cmEgcHJpdmF0ZSBmaWVsZHMgKGUuZy4gZGV2aWNlIGlkZW50aXR5KS4gU2V0dGluZ3MgYXJlIHRoZSBwdWJsaWMgc3Vic2V0LlxuICAgIHRoaXMuc2V0dGluZ3MgPSBPYmplY3QuYXNzaWduKHt9LCBERUZBVUxUX1NFVFRJTkdTLCBkYXRhKTtcbiAgfVxuXG4gIGFzeW5jIHNhdmVTZXR0aW5ncygpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICAvLyBQcmVzZXJ2ZSBhbnkgcHJpdmF0ZSBmaWVsZHMgc3RvcmVkIGluIHBsdWdpbiBkYXRhLlxuICAgIGNvbnN0IGRhdGEgPSAoYXdhaXQgdGhpcy5sb2FkRGF0YSgpKSA/PyB7fTtcbiAgICBhd2FpdCB0aGlzLnNhdmVEYXRhKHsgLi4uZGF0YSwgLi4udGhpcy5zZXR0aW5ncyB9KTtcbiAgfVxuXG4gIC8vIFx1MjUwMFx1MjUwMCBEZXZpY2UgaWRlbnRpdHkgcGVyc2lzdGVuY2UgKHBsdWdpbi1zY29wZWQ7IE5PVCBsb2NhbFN0b3JhZ2UpIFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFxuXG4gIGFzeW5jIHJlc2V0RGV2aWNlSWRlbnRpdHkoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgYXdhaXQgdGhpcy5fY2xlYXJEZXZpY2VJZGVudGl0eSgpO1xuICAgIG5ldyBOb3RpY2UoJ09wZW5DbGF3IENoYXQ6IGRldmljZSBpZGVudGl0eSByZXNldC4gUmVjb25uZWN0IHRvIHBhaXIgYWdhaW4uJyk7XG4gIH1cblxuICBwcml2YXRlIF9kZXZpY2VJZGVudGl0eUtleSA9ICdfb3BlbmNsYXdEZXZpY2VJZGVudGl0eVYxJztcblxuICBwcml2YXRlIGFzeW5jIF9sb2FkRGV2aWNlSWRlbnRpdHkoKTogUHJvbWlzZTxhbnkgfCBudWxsPiB7XG4gICAgY29uc3QgZGF0YSA9IChhd2FpdCB0aGlzLmxvYWREYXRhKCkpID8/IHt9O1xuICAgIHJldHVybiAoZGF0YSBhcyBhbnkpPy5bdGhpcy5fZGV2aWNlSWRlbnRpdHlLZXldID8/IG51bGw7XG4gIH1cblxuICBwcml2YXRlIGFzeW5jIF9zYXZlRGV2aWNlSWRlbnRpdHkoaWRlbnRpdHk6IGFueSk6IFByb21pc2U8dm9pZD4ge1xuICAgIGNvbnN0IGRhdGEgPSAoYXdhaXQgdGhpcy5sb2FkRGF0YSgpKSA/PyB7fTtcbiAgICBhd2FpdCB0aGlzLnNhdmVEYXRhKHsgLi4uZGF0YSwgW3RoaXMuX2RldmljZUlkZW50aXR5S2V5XTogaWRlbnRpdHkgfSk7XG4gIH1cblxuICBwcml2YXRlIGFzeW5jIF9jbGVhckRldmljZUlkZW50aXR5KCk6IFByb21pc2U8dm9pZD4ge1xuICAgIGNvbnN0IGRhdGEgPSAoYXdhaXQgdGhpcy5sb2FkRGF0YSgpKSA/PyB7fTtcbiAgICBpZiAoKGRhdGEgYXMgYW55KT8uW3RoaXMuX2RldmljZUlkZW50aXR5S2V5XSA9PT0gdW5kZWZpbmVkKSByZXR1cm47XG4gICAgY29uc3QgbmV4dCA9IHsgLi4uKGRhdGEgYXMgYW55KSB9O1xuICAgIGRlbGV0ZSBuZXh0W3RoaXMuX2RldmljZUlkZW50aXR5S2V5XTtcbiAgICBhd2FpdCB0aGlzLnNhdmVEYXRhKG5leHQpO1xuICB9XG5cbiAgLy8gXHUyNTAwXHUyNTAwIEhlbHBlcnMgXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG5cbiAgcHJpdmF0ZSBhc3luYyBfYWN0aXZhdGVDaGF0VmlldygpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBjb25zdCB7IHdvcmtzcGFjZSB9ID0gdGhpcy5hcHA7XG5cbiAgICAvLyBSZXVzZSBleGlzdGluZyBsZWFmIGlmIGFscmVhZHkgb3BlblxuICAgIGNvbnN0IGV4aXN0aW5nID0gd29ya3NwYWNlLmdldExlYXZlc09mVHlwZShWSUVXX1RZUEVfT1BFTkNMQVdfQ0hBVCk7XG4gICAgaWYgKGV4aXN0aW5nLmxlbmd0aCA+IDApIHtcbiAgICAgIHdvcmtzcGFjZS5yZXZlYWxMZWFmKGV4aXN0aW5nWzBdKTtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICAvLyBPcGVuIGluIHJpZ2h0IHNpZGViYXJcbiAgICBjb25zdCBsZWFmID0gd29ya3NwYWNlLmdldFJpZ2h0TGVhZihmYWxzZSk7XG4gICAgaWYgKCFsZWFmKSByZXR1cm47XG4gICAgYXdhaXQgbGVhZi5zZXRWaWV3U3RhdGUoeyB0eXBlOiBWSUVXX1RZUEVfT1BFTkNMQVdfQ0hBVCwgYWN0aXZlOiB0cnVlIH0pO1xuICAgIHdvcmtzcGFjZS5yZXZlYWxMZWFmKGxlYWYpO1xuICB9XG59XG4iLCAiaW1wb3J0IHsgQXBwLCBQbHVnaW5TZXR0aW5nVGFiLCBTZXR0aW5nIH0gZnJvbSAnb2JzaWRpYW4nO1xuaW1wb3J0IHR5cGUgT3BlbkNsYXdQbHVnaW4gZnJvbSAnLi9tYWluJztcblxuZXhwb3J0IGNsYXNzIE9wZW5DbGF3U2V0dGluZ1RhYiBleHRlbmRzIFBsdWdpblNldHRpbmdUYWIge1xuICBwbHVnaW46IE9wZW5DbGF3UGx1Z2luO1xuXG4gIGNvbnN0cnVjdG9yKGFwcDogQXBwLCBwbHVnaW46IE9wZW5DbGF3UGx1Z2luKSB7XG4gICAgc3VwZXIoYXBwLCBwbHVnaW4pO1xuICAgIHRoaXMucGx1Z2luID0gcGx1Z2luO1xuICB9XG5cbiAgZGlzcGxheSgpOiB2b2lkIHtcbiAgICBjb25zdCB7IGNvbnRhaW5lckVsIH0gPSB0aGlzO1xuICAgIGNvbnRhaW5lckVsLmVtcHR5KCk7XG5cbiAgICBjb250YWluZXJFbC5jcmVhdGVFbCgnaDInLCB7IHRleHQ6ICdPcGVuQ2xhdyBDaGF0IFx1MjAxMyBTZXR0aW5ncycgfSk7XG5cbiAgICBuZXcgU2V0dGluZyhjb250YWluZXJFbClcbiAgICAgIC5zZXROYW1lKCdHYXRld2F5IFVSTCcpXG4gICAgICAuc2V0RGVzYygnV2ViU29ja2V0IFVSTCBvZiB0aGUgT3BlbkNsYXcgR2F0ZXdheSAoZS5nLiB3czovL2hvc3RuYW1lOjE4Nzg5KS4nKVxuICAgICAgLmFkZFRleHQoKHRleHQpID0+XG4gICAgICAgIHRleHRcbiAgICAgICAgICAuc2V0UGxhY2Vob2xkZXIoJ3dzOi8vbG9jYWxob3N0OjE4Nzg5JylcbiAgICAgICAgICAuc2V0VmFsdWUodGhpcy5wbHVnaW4uc2V0dGluZ3MuZ2F0ZXdheVVybClcbiAgICAgICAgICAub25DaGFuZ2UoYXN5bmMgKHZhbHVlKSA9PiB7XG4gICAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5nYXRld2F5VXJsID0gdmFsdWUudHJpbSgpO1xuICAgICAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uc2F2ZVNldHRpbmdzKCk7XG4gICAgICAgICAgfSlcbiAgICAgICk7XG5cbiAgICBuZXcgU2V0dGluZyhjb250YWluZXJFbClcbiAgICAgIC5zZXROYW1lKCdBdXRoIHRva2VuJylcbiAgICAgIC5zZXREZXNjKCdNdXN0IG1hdGNoIHRoZSBhdXRoVG9rZW4gaW4geW91ciBvcGVuY2xhdy5qc29uIGNoYW5uZWwgY29uZmlnLiBOZXZlciBzaGFyZWQuJylcbiAgICAgIC5hZGRUZXh0KCh0ZXh0KSA9PiB7XG4gICAgICAgIHRleHRcbiAgICAgICAgICAuc2V0UGxhY2Vob2xkZXIoJ0VudGVyIHRva2VuXHUyMDI2JylcbiAgICAgICAgICAuc2V0VmFsdWUodGhpcy5wbHVnaW4uc2V0dGluZ3MuYXV0aFRva2VuKVxuICAgICAgICAgIC5vbkNoYW5nZShhc3luYyAodmFsdWUpID0+IHtcbiAgICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLmF1dGhUb2tlbiA9IHZhbHVlO1xuICAgICAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uc2F2ZVNldHRpbmdzKCk7XG4gICAgICAgICAgfSk7XG4gICAgICAgIC8vIFRyZWF0IGFzIHBhc3N3b3JkIGZpZWxkIFx1MjAxMyBkbyBub3QgcmV2ZWFsIHRva2VuIGluIFVJXG4gICAgICAgIHRleHQuaW5wdXRFbC50eXBlID0gJ3Bhc3N3b3JkJztcbiAgICAgICAgdGV4dC5pbnB1dEVsLmF1dG9jb21wbGV0ZSA9ICdvZmYnO1xuICAgICAgfSk7XG5cbiAgICBuZXcgU2V0dGluZyhjb250YWluZXJFbClcbiAgICAgIC5zZXROYW1lKCdTZXNzaW9uIEtleScpXG4gICAgICAuc2V0RGVzYygnT3BlbkNsYXcgc2Vzc2lvbiB0byBzdWJzY3JpYmUgdG8gKHVzdWFsbHkgXCJtYWluXCIpLicpXG4gICAgICAuYWRkVGV4dCgodGV4dCkgPT5cbiAgICAgICAgdGV4dFxuICAgICAgICAgIC5zZXRQbGFjZWhvbGRlcignbWFpbicpXG4gICAgICAgICAgLnNldFZhbHVlKHRoaXMucGx1Z2luLnNldHRpbmdzLnNlc3Npb25LZXkpXG4gICAgICAgICAgLm9uQ2hhbmdlKGFzeW5jICh2YWx1ZSkgPT4ge1xuICAgICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3Muc2Vzc2lvbktleSA9IHZhbHVlLnRyaW0oKSB8fCAnbWFpbic7XG4gICAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgICB9KVxuICAgICAgKTtcblxuICAgIG5ldyBTZXR0aW5nKGNvbnRhaW5lckVsKVxuICAgICAgLnNldE5hbWUoJ0FjY291bnQgSUQnKVxuICAgICAgLnNldERlc2MoJ09wZW5DbGF3IGFjY291bnQgSUQgKHVzdWFsbHkgXCJtYWluXCIpLicpXG4gICAgICAuYWRkVGV4dCgodGV4dCkgPT5cbiAgICAgICAgdGV4dFxuICAgICAgICAgIC5zZXRQbGFjZWhvbGRlcignbWFpbicpXG4gICAgICAgICAgLnNldFZhbHVlKHRoaXMucGx1Z2luLnNldHRpbmdzLmFjY291bnRJZClcbiAgICAgICAgICAub25DaGFuZ2UoYXN5bmMgKHZhbHVlKSA9PiB7XG4gICAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5hY2NvdW50SWQgPSB2YWx1ZS50cmltKCkgfHwgJ21haW4nO1xuICAgICAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uc2F2ZVNldHRpbmdzKCk7XG4gICAgICAgICAgfSlcbiAgICAgICk7XG5cbiAgICBuZXcgU2V0dGluZyhjb250YWluZXJFbClcbiAgICAgIC5zZXROYW1lKCdJbmNsdWRlIGFjdGl2ZSBub3RlIGJ5IGRlZmF1bHQnKVxuICAgICAgLnNldERlc2MoJ1ByZS1jaGVjayBcIkluY2x1ZGUgYWN0aXZlIG5vdGVcIiBpbiB0aGUgY2hhdCBwYW5lbCB3aGVuIGl0IG9wZW5zLicpXG4gICAgICAuYWRkVG9nZ2xlKCh0b2dnbGUpID0+XG4gICAgICAgIHRvZ2dsZS5zZXRWYWx1ZSh0aGlzLnBsdWdpbi5zZXR0aW5ncy5pbmNsdWRlQWN0aXZlTm90ZSkub25DaGFuZ2UoYXN5bmMgKHZhbHVlKSA9PiB7XG4gICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3MuaW5jbHVkZUFjdGl2ZU5vdGUgPSB2YWx1ZTtcbiAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgfSlcbiAgICAgICk7XG5cbiAgICBuZXcgU2V0dGluZyhjb250YWluZXJFbClcbiAgICAgIC5zZXROYW1lKCdSZW5kZXIgYXNzaXN0YW50IGFzIE1hcmtkb3duICh1bnNhZmUpJylcbiAgICAgIC5zZXREZXNjKFxuICAgICAgICAnT0ZGIHJlY29tbWVuZGVkLiBJZiBlbmFibGVkLCBhc3Npc3RhbnQgb3V0cHV0IGlzIHJlbmRlcmVkIGFzIE9ic2lkaWFuIE1hcmtkb3duIHdoaWNoIG1heSB0cmlnZ2VyIGVtYmVkcyBhbmQgb3RoZXIgcGx1Z2luc1xcJyBwb3N0LXByb2Nlc3NvcnMuJ1xuICAgICAgKVxuICAgICAgLmFkZFRvZ2dsZSgodG9nZ2xlKSA9PlxuICAgICAgICB0b2dnbGUuc2V0VmFsdWUodGhpcy5wbHVnaW4uc2V0dGluZ3MucmVuZGVyQXNzaXN0YW50TWFya2Rvd24pLm9uQ2hhbmdlKGFzeW5jICh2YWx1ZSkgPT4ge1xuICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLnJlbmRlckFzc2lzdGFudE1hcmtkb3duID0gdmFsdWU7XG4gICAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uc2F2ZVNldHRpbmdzKCk7XG4gICAgICAgIH0pXG4gICAgICApO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZSgnQWxsb3cgaW5zZWN1cmUgd3M6Ly8gZm9yIG5vbi1sb2NhbCBnYXRld2F5cyAodW5zYWZlKScpXG4gICAgICAuc2V0RGVzYyhcbiAgICAgICAgJ09GRiByZWNvbW1lbmRlZC4gSWYgZW5hYmxlZCwgeW91IGNhbiBjb25uZWN0IHRvIG5vbi1sb2NhbCBnYXRld2F5cyBvdmVyIHdzOi8vLiBUaGlzIGV4cG9zZXMgeW91ciB0b2tlbiBhbmQgbWVzc2FnZSBjb250ZW50IHRvIG5ldHdvcmsgYXR0YWNrZXJzOyBwcmVmZXIgd3NzOi8vLidcbiAgICAgIClcbiAgICAgIC5hZGRUb2dnbGUoKHRvZ2dsZSkgPT5cbiAgICAgICAgdG9nZ2xlLnNldFZhbHVlKHRoaXMucGx1Z2luLnNldHRpbmdzLmFsbG93SW5zZWN1cmVXcykub25DaGFuZ2UoYXN5bmMgKHZhbHVlKSA9PiB7XG4gICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3MuYWxsb3dJbnNlY3VyZVdzID0gdmFsdWU7XG4gICAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uc2F2ZVNldHRpbmdzKCk7XG4gICAgICAgIH0pXG4gICAgICApO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZSgnUmVzZXQgZGV2aWNlIGlkZW50aXR5IChyZS1wYWlyKScpXG4gICAgICAuc2V0RGVzYygnQ2xlYXJzIHRoZSBzdG9yZWQgZGV2aWNlIGlkZW50aXR5IHVzZWQgZm9yIG9wZXJhdG9yLndyaXRlIHBhaXJpbmcuIFVzZSB0aGlzIGlmIHlvdSBzdXNwZWN0IGNvbXByb21pc2Ugb3Igc2VlIFwiZGV2aWNlIGlkZW50aXR5IG1pc21hdGNoXCIuJylcbiAgICAgIC5hZGRCdXR0b24oKGJ0bikgPT5cbiAgICAgICAgYnRuLnNldEJ1dHRvblRleHQoJ1Jlc2V0Jykuc2V0V2FybmluZygpLm9uQ2xpY2soYXN5bmMgKCkgPT4ge1xuICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnJlc2V0RGV2aWNlSWRlbnRpdHkoKTtcbiAgICAgICAgfSlcbiAgICAgICk7XG5cbiAgICAvLyBcdTI1MDBcdTI1MDAgUGF0aCBtYXBwaW5ncyBcdTI1MDBcdTI1MDBcbiAgICBjb250YWluZXJFbC5jcmVhdGVFbCgnaDMnLCB7IHRleHQ6ICdQYXRoIG1hcHBpbmdzICh2YXVsdCBiYXNlIFx1MjE5MiByZW1vdGUgYmFzZSknIH0pO1xuICAgIGNvbnRhaW5lckVsLmNyZWF0ZUVsKCdwJywge1xuICAgICAgdGV4dDogJ1VzZWQgdG8gY29udmVydCBhc3Npc3RhbnQgZmlsZSByZWZlcmVuY2VzIChyZW1vdGUgRlMgcGF0aHMgb3IgZXhwb3J0ZWQgVVJMcykgaW50byBjbGlja2FibGUgT2JzaWRpYW4gbGlua3MuIEZpcnN0IG1hdGNoIHdpbnMuIE9ubHkgY3JlYXRlcyBhIGxpbmsgaWYgdGhlIG1hcHBlZCB2YXVsdCBmaWxlIGV4aXN0cy4nLFxuICAgICAgY2xzOiAnc2V0dGluZy1pdGVtLWRlc2NyaXB0aW9uJyxcbiAgICB9KTtcblxuICAgIGNvbnN0IG1hcHBpbmdzID0gdGhpcy5wbHVnaW4uc2V0dGluZ3MucGF0aE1hcHBpbmdzID8/IFtdO1xuXG4gICAgY29uc3QgcmVyZW5kZXIgPSBhc3luYyAoKSA9PiB7XG4gICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgIHRoaXMuZGlzcGxheSgpO1xuICAgIH07XG5cbiAgICBtYXBwaW5ncy5mb3JFYWNoKChyb3csIGlkeCkgPT4ge1xuICAgICAgY29uc3QgcyA9IG5ldyBTZXR0aW5nKGNvbnRhaW5lckVsKVxuICAgICAgICAuc2V0TmFtZShgTWFwcGluZyAjJHtpZHggKyAxfWApXG4gICAgICAgIC5zZXREZXNjKCd2YXVsdEJhc2UgXHUyMTkyIHJlbW90ZUJhc2UnKTtcblxuICAgICAgcy5hZGRUZXh0KCh0KSA9PlxuICAgICAgICB0XG4gICAgICAgICAgLnNldFBsYWNlaG9sZGVyKCd2YXVsdCBiYXNlIChlLmcuIGRvY3MvKScpXG4gICAgICAgICAgLnNldFZhbHVlKHJvdy52YXVsdEJhc2UgPz8gJycpXG4gICAgICAgICAgLm9uQ2hhbmdlKGFzeW5jICh2KSA9PiB7XG4gICAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5wYXRoTWFwcGluZ3NbaWR4XS52YXVsdEJhc2UgPSB2O1xuICAgICAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uc2F2ZVNldHRpbmdzKCk7XG4gICAgICAgICAgfSlcbiAgICAgICk7XG5cbiAgICAgIHMuYWRkVGV4dCgodCkgPT5cbiAgICAgICAgdFxuICAgICAgICAgIC5zZXRQbGFjZWhvbGRlcigncmVtb3RlIGJhc2UgKGUuZy4gL2hvbWUvLi4uL2RvY3MvKScpXG4gICAgICAgICAgLnNldFZhbHVlKHJvdy5yZW1vdGVCYXNlID8/ICcnKVxuICAgICAgICAgIC5vbkNoYW5nZShhc3luYyAodikgPT4ge1xuICAgICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3MucGF0aE1hcHBpbmdzW2lkeF0ucmVtb3RlQmFzZSA9IHY7XG4gICAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgICB9KVxuICAgICAgKTtcblxuICAgICAgcy5hZGRFeHRyYUJ1dHRvbigoYikgPT5cbiAgICAgICAgYlxuICAgICAgICAgIC5zZXRJY29uKCd0cmFzaCcpXG4gICAgICAgICAgLnNldFRvb2x0aXAoJ1JlbW92ZSBtYXBwaW5nJylcbiAgICAgICAgICAub25DbGljayhhc3luYyAoKSA9PiB7XG4gICAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5wYXRoTWFwcGluZ3Muc3BsaWNlKGlkeCwgMSk7XG4gICAgICAgICAgICBhd2FpdCByZXJlbmRlcigpO1xuICAgICAgICAgIH0pXG4gICAgICApO1xuICAgIH0pO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZSgnQWRkIG1hcHBpbmcnKVxuICAgICAgLnNldERlc2MoJ0FkZCBhIG5ldyB2YXVsdEJhc2UgXHUyMTkyIHJlbW90ZUJhc2UgbWFwcGluZyByb3cuJylcbiAgICAgIC5hZGRCdXR0b24oKGJ0bikgPT5cbiAgICAgICAgYnRuLnNldEJ1dHRvblRleHQoJ0FkZCcpLm9uQ2xpY2soYXN5bmMgKCkgPT4ge1xuICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLnBhdGhNYXBwaW5ncy5wdXNoKHsgdmF1bHRCYXNlOiAnJywgcmVtb3RlQmFzZTogJycgfSk7XG4gICAgICAgICAgYXdhaXQgcmVyZW5kZXIoKTtcbiAgICAgICAgfSlcbiAgICAgICk7XG5cbiAgICBjb250YWluZXJFbC5jcmVhdGVFbCgncCcsIHtcbiAgICAgIHRleHQ6ICdSZWNvbm5lY3Q6IGNsb3NlIGFuZCByZW9wZW4gdGhlIHNpZGViYXIgYWZ0ZXIgY2hhbmdpbmcgdGhlIGdhdGV3YXkgVVJMIG9yIHRva2VuLicsXG4gICAgICBjbHM6ICdzZXR0aW5nLWl0ZW0tZGVzY3JpcHRpb24nLFxuICAgIH0pO1xuICB9XG59XG4iLCAiLyoqXG4gKiBXZWJTb2NrZXQgY2xpZW50IGZvciBPcGVuQ2xhdyBHYXRld2F5XG4gKlxuICogUGl2b3QgKDIwMjYtMDItMjUpOiBEbyBOT1QgdXNlIGN1c3RvbSBvYnNpZGlhbi4qIGdhdGV3YXkgbWV0aG9kcy5cbiAqIFRob3NlIHJlcXVpcmUgb3BlcmF0b3IuYWRtaW4gc2NvcGUgd2hpY2ggaXMgbm90IGdyYW50ZWQgdG8gZXh0ZXJuYWwgY2xpZW50cy5cbiAqXG4gKiBBdXRoIG5vdGU6XG4gKiAtIGNoYXQuc2VuZCByZXF1aXJlcyBvcGVyYXRvci53cml0ZVxuICogLSBleHRlcm5hbCBjbGllbnRzIG11c3QgcHJlc2VudCBhIHBhaXJlZCBkZXZpY2UgaWRlbnRpdHkgdG8gcmVjZWl2ZSB3cml0ZSBzY29wZXNcbiAqXG4gKiBXZSB1c2UgYnVpbHQtaW4gZ2F0ZXdheSBtZXRob2RzL2V2ZW50czpcbiAqIC0gU2VuZDogY2hhdC5zZW5kKHsgc2Vzc2lvbktleSwgbWVzc2FnZSwgaWRlbXBvdGVuY3lLZXksIC4uLiB9KVxuICogLSBSZWNlaXZlOiBldmVudCBcImNoYXRcIiAoZmlsdGVyIGJ5IHNlc3Npb25LZXkpXG4gKi9cblxuaW1wb3J0IHR5cGUgeyBJbmJvdW5kV1NQYXlsb2FkIH0gZnJvbSAnLi90eXBlcyc7XG5cbmZ1bmN0aW9uIGlzTG9jYWxIb3N0KGhvc3Q6IHN0cmluZyk6IGJvb2xlYW4ge1xuICBjb25zdCBoID0gaG9zdC50b0xvd2VyQ2FzZSgpO1xuICByZXR1cm4gaCA9PT0gJ2xvY2FsaG9zdCcgfHwgaCA9PT0gJzEyNy4wLjAuMScgfHwgaCA9PT0gJzo6MSc7XG59XG5cbmZ1bmN0aW9uIHNhZmVQYXJzZVdzVXJsKHVybDogc3RyaW5nKTpcbiAgfCB7IG9rOiB0cnVlOyBzY2hlbWU6ICd3cycgfCAnd3NzJzsgaG9zdDogc3RyaW5nIH1cbiAgfCB7IG9rOiBmYWxzZTsgZXJyb3I6IHN0cmluZyB9IHtcbiAgdHJ5IHtcbiAgICBjb25zdCB1ID0gbmV3IFVSTCh1cmwpO1xuICAgIGlmICh1LnByb3RvY29sICE9PSAnd3M6JyAmJiB1LnByb3RvY29sICE9PSAnd3NzOicpIHtcbiAgICAgIHJldHVybiB7IG9rOiBmYWxzZSwgZXJyb3I6IGBHYXRld2F5IFVSTCBtdXN0IGJlIHdzOi8vIG9yIHdzczovLyAoZ290ICR7dS5wcm90b2NvbH0pYCB9O1xuICAgIH1cbiAgICBjb25zdCBzY2hlbWUgPSB1LnByb3RvY29sID09PSAnd3M6JyA/ICd3cycgOiAnd3NzJztcbiAgICByZXR1cm4geyBvazogdHJ1ZSwgc2NoZW1lLCBob3N0OiB1Lmhvc3RuYW1lIH07XG4gIH0gY2F0Y2gge1xuICAgIHJldHVybiB7IG9rOiBmYWxzZSwgZXJyb3I6ICdJbnZhbGlkIGdhdGV3YXkgVVJMJyB9O1xuICB9XG59XG5cbi8qKiBJbnRlcnZhbCBmb3Igc2VuZGluZyBoZWFydGJlYXQgcGluZ3MgKGNoZWNrIGNvbm5lY3Rpb24gbGl2ZW5lc3MpICovXG5jb25zdCBIRUFSVEJFQVRfSU5URVJWQUxfTVMgPSAzMF8wMDA7XG5cbi8qKiBTYWZldHkgdmFsdmU6IGhpZGUgd29ya2luZyBzcGlubmVyIGlmIG5vIGFzc2lzdGFudCByZXBseSBhcnJpdmVzIGluIHRpbWUgKi9cbmNvbnN0IFdPUktJTkdfTUFYX01TID0gMTIwXzAwMDtcblxuLyoqIE1heCBpbmJvdW5kIGZyYW1lIHNpemUgdG8gcGFyc2UgKERvUyBndWFyZCkgKi9cbmNvbnN0IE1BWF9JTkJPVU5EX0ZSQU1FX0JZVEVTID0gNTEyICogMTAyNDtcblxuZnVuY3Rpb24gYnl0ZUxlbmd0aFV0ZjgodGV4dDogc3RyaW5nKTogbnVtYmVyIHtcbiAgcmV0dXJuIHV0ZjhCeXRlcyh0ZXh0KS5ieXRlTGVuZ3RoO1xufVxuXG5hc3luYyBmdW5jdGlvbiBub3JtYWxpemVXc0RhdGFUb1RleHQoZGF0YTogYW55KTogUHJvbWlzZTx7IG9rOiB0cnVlOyB0ZXh0OiBzdHJpbmc7IGJ5dGVzOiBudW1iZXIgfSB8IHsgb2s6IGZhbHNlOyByZWFzb246IHN0cmluZzsgYnl0ZXM/OiBudW1iZXIgfT4ge1xuICBpZiAodHlwZW9mIGRhdGEgPT09ICdzdHJpbmcnKSB7XG4gICAgY29uc3QgYnl0ZXMgPSBieXRlTGVuZ3RoVXRmOChkYXRhKTtcbiAgICByZXR1cm4geyBvazogdHJ1ZSwgdGV4dDogZGF0YSwgYnl0ZXMgfTtcbiAgfVxuXG4gIC8vIEJyb3dzZXIgV2ViU29ja2V0IGNhbiBkZWxpdmVyIEJsb2JcbiAgaWYgKHR5cGVvZiBCbG9iICE9PSAndW5kZWZpbmVkJyAmJiBkYXRhIGluc3RhbmNlb2YgQmxvYikge1xuICAgIGNvbnN0IGJ5dGVzID0gZGF0YS5zaXplO1xuICAgIGlmIChieXRlcyA+IE1BWF9JTkJPVU5EX0ZSQU1FX0JZVEVTKSByZXR1cm4geyBvazogZmFsc2UsIHJlYXNvbjogJ3Rvby1sYXJnZScsIGJ5dGVzIH07XG4gICAgY29uc3QgdGV4dCA9IGF3YWl0IGRhdGEudGV4dCgpO1xuICAgIC8vIEJsb2Iuc2l6ZSBpcyBieXRlcyBhbHJlYWR5OyBubyBuZWVkIHRvIHJlLW1lYXN1cmUuXG4gICAgcmV0dXJuIHsgb2s6IHRydWUsIHRleHQsIGJ5dGVzIH07XG4gIH1cblxuICBpZiAoZGF0YSBpbnN0YW5jZW9mIEFycmF5QnVmZmVyKSB7XG4gICAgY29uc3QgYnl0ZXMgPSBkYXRhLmJ5dGVMZW5ndGg7XG4gICAgaWYgKGJ5dGVzID4gTUFYX0lOQk9VTkRfRlJBTUVfQllURVMpIHJldHVybiB7IG9rOiBmYWxzZSwgcmVhc29uOiAndG9vLWxhcmdlJywgYnl0ZXMgfTtcbiAgICBjb25zdCB0ZXh0ID0gbmV3IFRleHREZWNvZGVyKCd1dGYtOCcsIHsgZmF0YWw6IGZhbHNlIH0pLmRlY29kZShuZXcgVWludDhBcnJheShkYXRhKSk7XG4gICAgcmV0dXJuIHsgb2s6IHRydWUsIHRleHQsIGJ5dGVzIH07XG4gIH1cblxuICAvLyBTb21lIHJ1bnRpbWVzIGNvdWxkIHBhc3MgVWludDhBcnJheSBkaXJlY3RseVxuICBpZiAoZGF0YSBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpIHtcbiAgICBjb25zdCBieXRlcyA9IGRhdGEuYnl0ZUxlbmd0aDtcbiAgICBpZiAoYnl0ZXMgPiBNQVhfSU5CT1VORF9GUkFNRV9CWVRFUykgcmV0dXJuIHsgb2s6IGZhbHNlLCByZWFzb246ICd0b28tbGFyZ2UnLCBieXRlcyB9O1xuICAgIGNvbnN0IHRleHQgPSBuZXcgVGV4dERlY29kZXIoJ3V0Zi04JywgeyBmYXRhbDogZmFsc2UgfSkuZGVjb2RlKGRhdGEpO1xuICAgIHJldHVybiB7IG9rOiB0cnVlLCB0ZXh0LCBieXRlcyB9O1xuICB9XG5cbiAgcmV0dXJuIHsgb2s6IGZhbHNlLCByZWFzb246ICd1bnN1cHBvcnRlZC10eXBlJyB9O1xufVxuXG4vKiogTWF4IGluLWZsaWdodCByZXF1ZXN0cyBiZWZvcmUgZmFzdC1mYWlsaW5nIChEb1Mvcm9idXN0bmVzcyBndWFyZCkgKi9cbmNvbnN0IE1BWF9QRU5ESU5HX1JFUVVFU1RTID0gMjAwO1xuXG4vKiogUmVjb25uZWN0IGJhY2tvZmYgKi9cbmNvbnN0IFJFQ09OTkVDVF9CQVNFX01TID0gM18wMDA7XG5jb25zdCBSRUNPTk5FQ1RfTUFYX01TID0gNjBfMDAwO1xuXG4vKiogSGFuZHNoYWtlIGRlYWRsaW5lIHdhaXRpbmcgZm9yIGNvbm5lY3QuY2hhbGxlbmdlICovXG5jb25zdCBIQU5EU0hBS0VfVElNRU9VVF9NUyA9IDE1XzAwMDtcblxuZXhwb3J0IHR5cGUgV1NDbGllbnRTdGF0ZSA9ICdkaXNjb25uZWN0ZWQnIHwgJ2Nvbm5lY3RpbmcnIHwgJ2hhbmRzaGFraW5nJyB8ICdjb25uZWN0ZWQnO1xuXG5leHBvcnQgdHlwZSBXb3JraW5nU3RhdGVMaXN0ZW5lciA9ICh3b3JraW5nOiBib29sZWFuKSA9PiB2b2lkO1xuXG5pbnRlcmZhY2UgUGVuZGluZ1JlcXVlc3Qge1xuICByZXNvbHZlOiAocGF5bG9hZDogYW55KSA9PiB2b2lkO1xuICByZWplY3Q6IChlcnJvcjogYW55KSA9PiB2b2lkO1xuICB0aW1lb3V0OiBSZXR1cm5UeXBlPHR5cGVvZiBzZXRUaW1lb3V0PiB8IG51bGw7XG59XG5cbmV4cG9ydCB0eXBlIERldmljZUlkZW50aXR5ID0ge1xuICBpZDogc3RyaW5nO1xuICBwdWJsaWNLZXk6IHN0cmluZzsgLy8gYmFzZTY0XG4gIHByaXZhdGVLZXlKd2s6IEpzb25XZWJLZXk7XG59O1xuXG5leHBvcnQgaW50ZXJmYWNlIERldmljZUlkZW50aXR5U3RvcmUge1xuICBnZXQoKTogUHJvbWlzZTxEZXZpY2VJZGVudGl0eSB8IG51bGw+O1xuICBzZXQoaWRlbnRpdHk6IERldmljZUlkZW50aXR5KTogUHJvbWlzZTx2b2lkPjtcbiAgY2xlYXIoKTogUHJvbWlzZTx2b2lkPjtcbn1cblxuY29uc3QgREVWSUNFX1NUT1JBR0VfS0VZID0gJ29wZW5jbGF3Q2hhdC5kZXZpY2VJZGVudGl0eS52MSc7IC8vIGxlZ2FjeSBsb2NhbFN0b3JhZ2Uga2V5IChtaWdyYXRpb24gb25seSlcblxuZnVuY3Rpb24gYmFzZTY0VXJsRW5jb2RlKGJ5dGVzOiBBcnJheUJ1ZmZlcik6IHN0cmluZyB7XG4gIGNvbnN0IHU4ID0gbmV3IFVpbnQ4QXJyYXkoYnl0ZXMpO1xuICBsZXQgcyA9ICcnO1xuICBmb3IgKGxldCBpID0gMDsgaSA8IHU4Lmxlbmd0aDsgaSsrKSBzICs9IFN0cmluZy5mcm9tQ2hhckNvZGUodThbaV0pO1xuICBjb25zdCBiNjQgPSBidG9hKHMpO1xuICByZXR1cm4gYjY0LnJlcGxhY2UoL1xcKy9nLCAnLScpLnJlcGxhY2UoL1xcLy9nLCAnXycpLnJlcGxhY2UoLz0rJC9nLCAnJyk7XG59XG5cbmZ1bmN0aW9uIGhleEVuY29kZShieXRlczogQXJyYXlCdWZmZXIpOiBzdHJpbmcge1xuICBjb25zdCB1OCA9IG5ldyBVaW50OEFycmF5KGJ5dGVzKTtcbiAgcmV0dXJuIEFycmF5LmZyb20odTgpXG4gICAgLm1hcCgoYikgPT4gYi50b1N0cmluZygxNikucGFkU3RhcnQoMiwgJzAnKSlcbiAgICAuam9pbignJyk7XG59XG5cbmZ1bmN0aW9uIHV0ZjhCeXRlcyh0ZXh0OiBzdHJpbmcpOiBVaW50OEFycmF5IHtcbiAgcmV0dXJuIG5ldyBUZXh0RW5jb2RlcigpLmVuY29kZSh0ZXh0KTtcbn1cblxuYXN5bmMgZnVuY3Rpb24gc2hhMjU2SGV4KGJ5dGVzOiBBcnJheUJ1ZmZlcik6IFByb21pc2U8c3RyaW5nPiB7XG4gIGNvbnN0IGRpZ2VzdCA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuZGlnZXN0KCdTSEEtMjU2JywgYnl0ZXMpO1xuICByZXR1cm4gaGV4RW5jb2RlKGRpZ2VzdCk7XG59XG5cbmFzeW5jIGZ1bmN0aW9uIGxvYWRPckNyZWF0ZURldmljZUlkZW50aXR5KHN0b3JlPzogRGV2aWNlSWRlbnRpdHlTdG9yZSk6IFByb21pc2U8RGV2aWNlSWRlbnRpdHk+IHtcbiAgLy8gMSkgUHJlZmVyIHBsdWdpbi1zY29wZWQgc3RvcmFnZSAoaW5qZWN0ZWQgYnkgbWFpbiBwbHVnaW4pLlxuICBpZiAoc3RvcmUpIHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgZXhpc3RpbmcgPSBhd2FpdCBzdG9yZS5nZXQoKTtcbiAgICAgIGlmIChleGlzdGluZz8uaWQgJiYgZXhpc3Rpbmc/LnB1YmxpY0tleSAmJiBleGlzdGluZz8ucHJpdmF0ZUtleUp3aykgcmV0dXJuIGV4aXN0aW5nO1xuICAgIH0gY2F0Y2gge1xuICAgICAgLy8gaWdub3JlIGFuZCBjb250aW51ZSAod2UgY2FuIGFsd2F5cyByZS1nZW5lcmF0ZSlcbiAgICB9XG4gIH1cblxuICAvLyAyKSBPbmUtdGltZSBtaWdyYXRpb246IGxlZ2FjeSBsb2NhbFN0b3JhZ2UgaWRlbnRpdHkuXG4gIC8vIE5PVEU6IHRoaXMgcmVtYWlucyBhIHJpc2sgYm91bmRhcnk7IHdlIG9ubHkgcmVhZCtkZWxldGUgZm9yIG1pZ3JhdGlvbi5cbiAgY29uc3QgbGVnYWN5ID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oREVWSUNFX1NUT1JBR0VfS0VZKTtcbiAgaWYgKGxlZ2FjeSkge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCBwYXJzZWQgPSBKU09OLnBhcnNlKGxlZ2FjeSkgYXMgRGV2aWNlSWRlbnRpdHk7XG4gICAgICBpZiAocGFyc2VkPy5pZCAmJiBwYXJzZWQ/LnB1YmxpY0tleSAmJiBwYXJzZWQ/LnByaXZhdGVLZXlKd2spIHtcbiAgICAgICAgaWYgKHN0b3JlKSB7XG4gICAgICAgICAgYXdhaXQgc3RvcmUuc2V0KHBhcnNlZCk7XG4gICAgICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oREVWSUNFX1NUT1JBR0VfS0VZKTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gcGFyc2VkO1xuICAgICAgfVxuICAgIH0gY2F0Y2gge1xuICAgICAgLy8gQ29ycnVwdC9wYXJ0aWFsIGRhdGEgXHUyMTkyIGRlbGV0ZSBhbmQgcmUtY3JlYXRlLlxuICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oREVWSUNFX1NUT1JBR0VfS0VZKTtcbiAgICB9XG4gIH1cblxuICAvLyAzKSBDcmVhdGUgYSBuZXcgaWRlbnRpdHkuXG4gIGNvbnN0IGtleVBhaXIgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmdlbmVyYXRlS2V5KHsgbmFtZTogJ0VkMjU1MTknIH0sIHRydWUsIFsnc2lnbicsICd2ZXJpZnknXSk7XG4gIGNvbnN0IHB1YlJhdyA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuZXhwb3J0S2V5KCdyYXcnLCBrZXlQYWlyLnB1YmxpY0tleSk7XG4gIGNvbnN0IHByaXZKd2sgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmV4cG9ydEtleSgnandrJywga2V5UGFpci5wcml2YXRlS2V5KTtcblxuICAvLyBJTVBPUlRBTlQ6IGRldmljZS5pZCBtdXN0IGJlIGEgc3RhYmxlIGZpbmdlcnByaW50IGZvciB0aGUgcHVibGljIGtleS5cbiAgLy8gVGhlIGdhdGV3YXkgZW5mb3JjZXMgZGV2aWNlSWQgXHUyMTk0IHB1YmxpY0tleSBiaW5kaW5nOyByYW5kb20gaWRzIGNhbiBjYXVzZSBcImRldmljZSBpZGVudGl0eSBtaXNtYXRjaFwiLlxuICBjb25zdCBkZXZpY2VJZCA9IGF3YWl0IHNoYTI1NkhleChwdWJSYXcpO1xuXG4gIGNvbnN0IGlkZW50aXR5OiBEZXZpY2VJZGVudGl0eSA9IHtcbiAgICBpZDogZGV2aWNlSWQsXG4gICAgcHVibGljS2V5OiBiYXNlNjRVcmxFbmNvZGUocHViUmF3KSxcbiAgICBwcml2YXRlS2V5SndrOiBwcml2SndrLFxuICB9O1xuXG4gIGlmIChzdG9yZSkge1xuICAgIGF3YWl0IHN0b3JlLnNldChpZGVudGl0eSk7XG4gIH0gZWxzZSB7XG4gICAgLy8gRmFsbGJhY2sgKHNob3VsZCBub3QgaGFwcGVuIGluIHJlYWwgcGx1Z2luIHJ1bnRpbWUpIFx1MjAxNCBrZWVwIGxlZ2FjeSBiZWhhdmlvci5cbiAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbShERVZJQ0VfU1RPUkFHRV9LRVksIEpTT04uc3RyaW5naWZ5KGlkZW50aXR5KSk7XG4gIH1cblxuICByZXR1cm4gaWRlbnRpdHk7XG59XG5cbmZ1bmN0aW9uIGJ1aWxkRGV2aWNlQXV0aFBheWxvYWQocGFyYW1zOiB7XG4gIGRldmljZUlkOiBzdHJpbmc7XG4gIGNsaWVudElkOiBzdHJpbmc7XG4gIGNsaWVudE1vZGU6IHN0cmluZztcbiAgcm9sZTogc3RyaW5nO1xuICBzY29wZXM6IHN0cmluZ1tdO1xuICBzaWduZWRBdE1zOiBudW1iZXI7XG4gIHRva2VuOiBzdHJpbmc7XG4gIG5vbmNlPzogc3RyaW5nO1xufSk6IHN0cmluZyB7XG4gIGNvbnN0IHZlcnNpb24gPSBwYXJhbXMubm9uY2UgPyAndjInIDogJ3YxJztcbiAgY29uc3Qgc2NvcGVzID0gcGFyYW1zLnNjb3Blcy5qb2luKCcsJyk7XG4gIGNvbnN0IGJhc2UgPSBbXG4gICAgdmVyc2lvbixcbiAgICBwYXJhbXMuZGV2aWNlSWQsXG4gICAgcGFyYW1zLmNsaWVudElkLFxuICAgIHBhcmFtcy5jbGllbnRNb2RlLFxuICAgIHBhcmFtcy5yb2xlLFxuICAgIHNjb3BlcyxcbiAgICBTdHJpbmcocGFyYW1zLnNpZ25lZEF0TXMpLFxuICAgIHBhcmFtcy50b2tlbiB8fCAnJyxcbiAgXTtcbiAgaWYgKHZlcnNpb24gPT09ICd2MicpIGJhc2UucHVzaChwYXJhbXMubm9uY2UgfHwgJycpO1xuICByZXR1cm4gYmFzZS5qb2luKCd8Jyk7XG59XG5cbmFzeW5jIGZ1bmN0aW9uIHNpZ25EZXZpY2VQYXlsb2FkKGlkZW50aXR5OiBEZXZpY2VJZGVudGl0eSwgcGF5bG9hZDogc3RyaW5nKTogUHJvbWlzZTx7IHNpZ25hdHVyZTogc3RyaW5nIH0+IHtcbiAgY29uc3QgcHJpdmF0ZUtleSA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KFxuICAgICdqd2snLFxuICAgIGlkZW50aXR5LnByaXZhdGVLZXlKd2ssXG4gICAgeyBuYW1lOiAnRWQyNTUxOScgfSxcbiAgICBmYWxzZSxcbiAgICBbJ3NpZ24nXSxcbiAgKTtcblxuICBjb25zdCBzaWcgPSBhd2FpdCBjcnlwdG8uc3VidGxlLnNpZ24oeyBuYW1lOiAnRWQyNTUxOScgfSwgcHJpdmF0ZUtleSwgdXRmOEJ5dGVzKHBheWxvYWQpIGFzIHVua25vd24gYXMgQnVmZmVyU291cmNlKTtcbiAgcmV0dXJuIHsgc2lnbmF0dXJlOiBiYXNlNjRVcmxFbmNvZGUoc2lnKSB9O1xufVxuXG5mdW5jdGlvbiBleHRyYWN0VGV4dEZyb21HYXRld2F5TWVzc2FnZShtc2c6IGFueSk6IHN0cmluZyB7XG4gIGlmICghbXNnKSByZXR1cm4gJyc7XG5cbiAgLy8gTW9zdCBjb21tb246IHsgcm9sZSwgY29udGVudCB9IHdoZXJlIGNvbnRlbnQgY2FuIGJlIHN0cmluZyBvciBbe3R5cGU6J3RleHQnLHRleHQ6Jy4uLid9XVxuICBjb25zdCBjb250ZW50ID0gbXNnLmNvbnRlbnQgPz8gbXNnLm1lc3NhZ2UgPz8gbXNnO1xuICBpZiAodHlwZW9mIGNvbnRlbnQgPT09ICdzdHJpbmcnKSByZXR1cm4gY29udGVudDtcblxuICBpZiAoQXJyYXkuaXNBcnJheShjb250ZW50KSkge1xuICAgIGNvbnN0IHBhcnRzID0gY29udGVudFxuICAgICAgLmZpbHRlcigoYykgPT4gYyAmJiB0eXBlb2YgYyA9PT0gJ29iamVjdCcgJiYgYy50eXBlID09PSAndGV4dCcgJiYgdHlwZW9mIGMudGV4dCA9PT0gJ3N0cmluZycpXG4gICAgICAubWFwKChjKSA9PiBjLnRleHQpO1xuICAgIHJldHVybiBwYXJ0cy5qb2luKCdcXG4nKTtcbiAgfVxuXG4gIC8vIEZhbGxiYWNrXG4gIHRyeSB7XG4gICAgcmV0dXJuIEpTT04uc3RyaW5naWZ5KGNvbnRlbnQpO1xuICB9IGNhdGNoIHtcbiAgICByZXR1cm4gU3RyaW5nKGNvbnRlbnQpO1xuICB9XG59XG5cbmZ1bmN0aW9uIHNlc3Npb25LZXlNYXRjaGVzKGNvbmZpZ3VyZWQ6IHN0cmluZywgaW5jb21pbmc6IHN0cmluZyk6IGJvb2xlYW4ge1xuICBpZiAoaW5jb21pbmcgPT09IGNvbmZpZ3VyZWQpIHJldHVybiB0cnVlO1xuICAvLyBPcGVuQ2xhdyByZXNvbHZlcyBcIm1haW5cIiB0byBjYW5vbmljYWwgc2Vzc2lvbiBrZXkgbGlrZSBcImFnZW50Om1haW46bWFpblwiLlxuICBpZiAoY29uZmlndXJlZCA9PT0gJ21haW4nICYmIGluY29taW5nID09PSAnYWdlbnQ6bWFpbjptYWluJykgcmV0dXJuIHRydWU7XG4gIHJldHVybiBmYWxzZTtcbn1cblxuZXhwb3J0IGNsYXNzIE9ic2lkaWFuV1NDbGllbnQge1xuICBwcml2YXRlIHdzOiBXZWJTb2NrZXQgfCBudWxsID0gbnVsbDtcbiAgcHJpdmF0ZSByZWNvbm5lY3RUaW1lcjogUmV0dXJuVHlwZTx0eXBlb2Ygc2V0VGltZW91dD4gfCBudWxsID0gbnVsbDtcbiAgcHJpdmF0ZSBoZWFydGJlYXRUaW1lcjogUmV0dXJuVHlwZTx0eXBlb2Ygc2V0SW50ZXJ2YWw+IHwgbnVsbCA9IG51bGw7XG4gIHByaXZhdGUgd29ya2luZ1RpbWVyOiBSZXR1cm5UeXBlPHR5cGVvZiBzZXRUaW1lb3V0PiB8IG51bGwgPSBudWxsO1xuICBwcml2YXRlIGludGVudGlvbmFsQ2xvc2UgPSBmYWxzZTtcbiAgcHJpdmF0ZSBzZXNzaW9uS2V5OiBzdHJpbmc7XG4gIHByaXZhdGUgdXJsID0gJyc7XG4gIHByaXZhdGUgdG9rZW4gPSAnJztcbiAgcHJpdmF0ZSByZXF1ZXN0SWQgPSAwO1xuICBwcml2YXRlIHBlbmRpbmdSZXF1ZXN0cyA9IG5ldyBNYXA8c3RyaW5nLCBQZW5kaW5nUmVxdWVzdD4oKTtcbiAgcHJpdmF0ZSB3b3JraW5nID0gZmFsc2U7XG5cbiAgLyoqIFRoZSBsYXN0IGluLWZsaWdodCBjaGF0IHJ1biBpZC4gSW4gT3BlbkNsYXcgV2ViQ2hhdCB0aGlzIG1hcHMgdG8gY2hhdC5zZW5kIGlkZW1wb3RlbmN5S2V5LiAqL1xuICBwcml2YXRlIGFjdGl2ZVJ1bklkOiBzdHJpbmcgfCBudWxsID0gbnVsbDtcblxuICAvKiogUHJldmVudHMgYWJvcnQgc3BhbW1pbmc6IHdoaWxlIGFuIGFib3J0IHJlcXVlc3QgaXMgaW4tZmxpZ2h0LCByZXVzZSB0aGUgc2FtZSBwcm9taXNlLiAqL1xuICBwcml2YXRlIGFib3J0SW5GbGlnaHQ6IFByb21pc2U8Ym9vbGVhbj4gfCBudWxsID0gbnVsbDtcblxuICBzdGF0ZTogV1NDbGllbnRTdGF0ZSA9ICdkaXNjb25uZWN0ZWQnO1xuXG4gIG9uTWVzc2FnZTogKChtc2c6IEluYm91bmRXU1BheWxvYWQpID0+IHZvaWQpIHwgbnVsbCA9IG51bGw7XG4gIG9uU3RhdGVDaGFuZ2U6ICgoc3RhdGU6IFdTQ2xpZW50U3RhdGUpID0+IHZvaWQpIHwgbnVsbCA9IG51bGw7XG4gIG9uV29ya2luZ0NoYW5nZTogV29ya2luZ1N0YXRlTGlzdGVuZXIgfCBudWxsID0gbnVsbDtcblxuICBwcml2YXRlIGlkZW50aXR5U3RvcmU6IERldmljZUlkZW50aXR5U3RvcmUgfCB1bmRlZmluZWQ7XG4gIHByaXZhdGUgYWxsb3dJbnNlY3VyZVdzID0gZmFsc2U7XG5cbiAgcHJpdmF0ZSByZWNvbm5lY3RBdHRlbXB0ID0gMDtcblxuICBjb25zdHJ1Y3RvcihzZXNzaW9uS2V5OiBzdHJpbmcsIG9wdHM/OiB7IGlkZW50aXR5U3RvcmU/OiBEZXZpY2VJZGVudGl0eVN0b3JlOyBhbGxvd0luc2VjdXJlV3M/OiBib29sZWFuIH0pIHtcbiAgICB0aGlzLnNlc3Npb25LZXkgPSBzZXNzaW9uS2V5O1xuICAgIHRoaXMuaWRlbnRpdHlTdG9yZSA9IG9wdHM/LmlkZW50aXR5U3RvcmU7XG4gICAgdGhpcy5hbGxvd0luc2VjdXJlV3MgPSBCb29sZWFuKG9wdHM/LmFsbG93SW5zZWN1cmVXcyk7XG4gIH1cblxuICBjb25uZWN0KHVybDogc3RyaW5nLCB0b2tlbjogc3RyaW5nLCBvcHRzPzogeyBhbGxvd0luc2VjdXJlV3M/OiBib29sZWFuIH0pOiB2b2lkIHtcbiAgICB0aGlzLnVybCA9IHVybDtcbiAgICB0aGlzLnRva2VuID0gdG9rZW47XG4gICAgdGhpcy5hbGxvd0luc2VjdXJlV3MgPSBCb29sZWFuKG9wdHM/LmFsbG93SW5zZWN1cmVXcyA/PyB0aGlzLmFsbG93SW5zZWN1cmVXcyk7XG4gICAgdGhpcy5pbnRlbnRpb25hbENsb3NlID0gZmFsc2U7XG5cbiAgICAvLyBTZWN1cml0eTogYmxvY2sgbm9uLWxvY2FsIHdzOi8vIHVubGVzcyBleHBsaWNpdGx5IGFsbG93ZWQuXG4gICAgY29uc3QgcGFyc2VkID0gc2FmZVBhcnNlV3NVcmwodXJsKTtcbiAgICBpZiAoIXBhcnNlZC5vaykge1xuICAgICAgdGhpcy5vbk1lc3NhZ2U/Lih7IHR5cGU6ICdlcnJvcicsIHBheWxvYWQ6IHsgbWVzc2FnZTogcGFyc2VkLmVycm9yIH0gfSk7XG4gICAgICByZXR1cm47XG4gICAgfVxuICAgIGlmIChwYXJzZWQuc2NoZW1lID09PSAnd3MnICYmICFpc0xvY2FsSG9zdChwYXJzZWQuaG9zdCkgJiYgIXRoaXMuYWxsb3dJbnNlY3VyZVdzKSB7XG4gICAgICB0aGlzLm9uTWVzc2FnZT8uKHtcbiAgICAgICAgdHlwZTogJ2Vycm9yJyxcbiAgICAgICAgcGF5bG9hZDogeyBtZXNzYWdlOiAnUmVmdXNpbmcgaW5zZWN1cmUgd3M6Ly8gdG8gbm9uLWxvY2FsIGdhdGV3YXkuIFVzZSB3c3M6Ly8gb3IgZW5hYmxlIHRoZSB1bnNhZmUgb3ZlcnJpZGUgaW4gc2V0dGluZ3MuJyB9LFxuICAgICAgfSk7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgdGhpcy5fY29ubmVjdCgpO1xuICB9XG5cbiAgZGlzY29ubmVjdCgpOiB2b2lkIHtcbiAgICB0aGlzLmludGVudGlvbmFsQ2xvc2UgPSB0cnVlO1xuICAgIHRoaXMuX3N0b3BUaW1lcnMoKTtcbiAgICB0aGlzLmFjdGl2ZVJ1bklkID0gbnVsbDtcbiAgICB0aGlzLmFib3J0SW5GbGlnaHQgPSBudWxsO1xuICAgIHRoaXMuX3NldFdvcmtpbmcoZmFsc2UpO1xuICAgIGlmICh0aGlzLndzKSB7XG4gICAgICB0aGlzLndzLmNsb3NlKCk7XG4gICAgICB0aGlzLndzID0gbnVsbDtcbiAgICB9XG4gICAgdGhpcy5fc2V0U3RhdGUoJ2Rpc2Nvbm5lY3RlZCcpO1xuICB9XG5cbiAgc2V0U2Vzc2lvbktleShzZXNzaW9uS2V5OiBzdHJpbmcpOiB2b2lkIHtcbiAgICB0aGlzLnNlc3Npb25LZXkgPSBzZXNzaW9uS2V5LnRyaW0oKTtcbiAgICAvLyBSZXNldCBwZXItc2Vzc2lvbiBydW4gc3RhdGUuXG4gICAgdGhpcy5hY3RpdmVSdW5JZCA9IG51bGw7XG4gICAgdGhpcy5hYm9ydEluRmxpZ2h0ID0gbnVsbDtcbiAgICB0aGlzLl9zZXRXb3JraW5nKGZhbHNlKTtcbiAgfVxuXG4gIC8vIE5PVEU6IGNhbm9uaWNhbCBPYnNpZGlhbiBzZXNzaW9uIGtleXMgZG8gbm90IHJlcXVpcmUgZ2F0ZXdheSBzZXNzaW9ucy5saXN0IGZvciBjb3JlIFVYLlxuXG4gIGFzeW5jIHNlbmRNZXNzYWdlKG1lc3NhZ2U6IHN0cmluZyk6IFByb21pc2U8dm9pZD4ge1xuICAgIGlmICh0aGlzLnN0YXRlICE9PSAnY29ubmVjdGVkJykge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKCdOb3QgY29ubmVjdGVkIFx1MjAxNCBjYWxsIGNvbm5lY3QoKSBmaXJzdCcpO1xuICAgIH1cblxuICAgIGNvbnN0IHJ1bklkID0gYG9ic2lkaWFuLSR7RGF0ZS5ub3coKX0tJHtNYXRoLnJhbmRvbSgpLnRvU3RyaW5nKDM2KS5zbGljZSgyLCA5KX1gO1xuXG4gICAgLy8gU2hvdyBcdTIwMUN3b3JraW5nXHUyMDFEIE9OTFkgYWZ0ZXIgdGhlIGdhdGV3YXkgYWNrbm93bGVkZ2VzIHRoZSByZXF1ZXN0LlxuICAgIGNvbnN0IGFjayA9IGF3YWl0IHRoaXMuX3NlbmRSZXF1ZXN0KCdjaGF0LnNlbmQnLCB7XG4gICAgICBzZXNzaW9uS2V5OiB0aGlzLnNlc3Npb25LZXksXG4gICAgICBtZXNzYWdlLFxuICAgICAgaWRlbXBvdGVuY3lLZXk6IHJ1bklkLFxuICAgICAgLy8gZGVsaXZlciBkZWZhdWx0cyB0byB0cnVlIGluIGdhdGV3YXk7IGtlZXAgZGVmYXVsdFxuICAgIH0pO1xuXG4gICAgLy8gSWYgdGhlIGdhdGV3YXkgcmV0dXJucyBhIGNhbm9uaWNhbCBydW4gaWRlbnRpZmllciwgcHJlZmVyIGl0LlxuICAgIGNvbnN0IGNhbm9uaWNhbFJ1bklkID0gU3RyaW5nKGFjaz8ucnVuSWQgfHwgYWNrPy5pZGVtcG90ZW5jeUtleSB8fCAnJyk7XG4gICAgdGhpcy5hY3RpdmVSdW5JZCA9IGNhbm9uaWNhbFJ1bklkIHx8IHJ1bklkO1xuICAgIHRoaXMuX3NldFdvcmtpbmcodHJ1ZSk7XG4gICAgdGhpcy5fYXJtV29ya2luZ1NhZmV0eVRpbWVvdXQoKTtcbiAgfVxuXG4gIC8qKiBBYm9ydCB0aGUgYWN0aXZlIHJ1biBmb3IgdGhpcyBzZXNzaW9uIChhbmQgb3VyIGxhc3QgcnVuIGlkIGlmIHByZXNlbnQpLiAqL1xuICBhc3luYyBhYm9ydEFjdGl2ZVJ1bigpOiBQcm9taXNlPGJvb2xlYW4+IHtcbiAgICBpZiAodGhpcy5zdGF0ZSAhPT0gJ2Nvbm5lY3RlZCcpIHtcbiAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG5cbiAgICAvLyBQcmV2ZW50IHJlcXVlc3Qgc3Rvcm1zOiB3aGlsZSBvbmUgYWJvcnQgaXMgaW4gZmxpZ2h0LCByZXVzZSBpdC5cbiAgICBpZiAodGhpcy5hYm9ydEluRmxpZ2h0KSB7XG4gICAgICByZXR1cm4gdGhpcy5hYm9ydEluRmxpZ2h0O1xuICAgIH1cblxuICAgIGNvbnN0IHJ1bklkID0gdGhpcy5hY3RpdmVSdW5JZDtcbiAgICBpZiAoIXJ1bklkKSB7XG4gICAgICByZXR1cm4gZmFsc2U7XG4gICAgfVxuXG4gICAgdGhpcy5hYm9ydEluRmxpZ2h0ID0gKGFzeW5jICgpID0+IHtcbiAgICAgIHRyeSB7XG4gICAgICAgIGF3YWl0IHRoaXMuX3NlbmRSZXF1ZXN0KCdjaGF0LmFib3J0JywgeyBzZXNzaW9uS2V5OiB0aGlzLnNlc3Npb25LZXksIHJ1bklkIH0pO1xuICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgIH0gY2F0Y2ggKGVycikge1xuICAgICAgICBjb25zb2xlLmVycm9yKCdbb2NsYXctd3NdIGNoYXQuYWJvcnQgZmFpbGVkJywgZXJyKTtcbiAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgfSBmaW5hbGx5IHtcbiAgICAgICAgLy8gQWx3YXlzIHJlc3RvcmUgVUkgc3RhdGUgaW1tZWRpYXRlbHk7IHRoZSBnYXRld2F5IG1heSBzdGlsbCBlbWl0IGFuIGFib3J0ZWQgZXZlbnQgbGF0ZXIuXG4gICAgICAgIHRoaXMuYWN0aXZlUnVuSWQgPSBudWxsO1xuICAgICAgICB0aGlzLl9zZXRXb3JraW5nKGZhbHNlKTtcbiAgICAgICAgdGhpcy5hYm9ydEluRmxpZ2h0ID0gbnVsbDtcbiAgICAgIH1cbiAgICB9KSgpO1xuXG4gICAgcmV0dXJuIHRoaXMuYWJvcnRJbkZsaWdodDtcbiAgfVxuXG4gIHByaXZhdGUgX2Nvbm5lY3QoKTogdm9pZCB7XG4gICAgaWYgKHRoaXMud3MpIHtcbiAgICAgIHRoaXMud3Mub25vcGVuID0gbnVsbDtcbiAgICAgIHRoaXMud3Mub25jbG9zZSA9IG51bGw7XG4gICAgICB0aGlzLndzLm9ubWVzc2FnZSA9IG51bGw7XG4gICAgICB0aGlzLndzLm9uZXJyb3IgPSBudWxsO1xuICAgICAgdGhpcy53cy5jbG9zZSgpO1xuICAgICAgdGhpcy53cyA9IG51bGw7XG4gICAgfVxuXG4gICAgdGhpcy5fc2V0U3RhdGUoJ2Nvbm5lY3RpbmcnKTtcblxuICAgIGNvbnN0IHdzID0gbmV3IFdlYlNvY2tldCh0aGlzLnVybCk7XG4gICAgdGhpcy53cyA9IHdzO1xuXG4gICAgbGV0IGNvbm5lY3ROb25jZTogc3RyaW5nIHwgbnVsbCA9IG51bGw7XG4gICAgbGV0IGNvbm5lY3RTdGFydGVkID0gZmFsc2U7XG5cbiAgICBjb25zdCB0cnlDb25uZWN0ID0gYXN5bmMgKCkgPT4ge1xuICAgICAgaWYgKGNvbm5lY3RTdGFydGVkKSByZXR1cm47XG4gICAgICBpZiAoIWNvbm5lY3ROb25jZSkgcmV0dXJuO1xuICAgICAgY29ubmVjdFN0YXJ0ZWQgPSB0cnVlO1xuXG4gICAgICB0cnkge1xuICAgICAgICBjb25zdCBpZGVudGl0eSA9IGF3YWl0IGxvYWRPckNyZWF0ZURldmljZUlkZW50aXR5KHRoaXMuaWRlbnRpdHlTdG9yZSk7XG4gICAgICAgIGNvbnN0IHNpZ25lZEF0TXMgPSBEYXRlLm5vdygpO1xuICAgICAgICBjb25zdCBwYXlsb2FkID0gYnVpbGREZXZpY2VBdXRoUGF5bG9hZCh7XG4gICAgICAgICAgZGV2aWNlSWQ6IGlkZW50aXR5LmlkLFxuICAgICAgICAgIGNsaWVudElkOiAnZ2F0ZXdheS1jbGllbnQnLFxuICAgICAgICAgIGNsaWVudE1vZGU6ICdiYWNrZW5kJyxcbiAgICAgICAgICByb2xlOiAnb3BlcmF0b3InLFxuICAgICAgICAgIHNjb3BlczogWydvcGVyYXRvci5yZWFkJywgJ29wZXJhdG9yLndyaXRlJ10sXG4gICAgICAgICAgc2lnbmVkQXRNcyxcbiAgICAgICAgICB0b2tlbjogdGhpcy50b2tlbixcbiAgICAgICAgICBub25jZTogY29ubmVjdE5vbmNlLFxuICAgICAgICB9KTtcbiAgICAgICAgY29uc3Qgc2lnID0gYXdhaXQgc2lnbkRldmljZVBheWxvYWQoaWRlbnRpdHksIHBheWxvYWQpO1xuXG4gICAgICAgIGNvbnN0IGFjayA9IGF3YWl0IHRoaXMuX3NlbmRSZXF1ZXN0KCdjb25uZWN0Jywge1xuICAgICAgICAgICBtaW5Qcm90b2NvbDogMyxcbiAgICAgICAgICAgbWF4UHJvdG9jb2w6IDMsXG4gICAgICAgICAgIGNsaWVudDoge1xuICAgICAgICAgICAgIGlkOiAnZ2F0ZXdheS1jbGllbnQnLFxuICAgICAgICAgICAgIG1vZGU6ICdiYWNrZW5kJyxcbiAgICAgICAgICAgICB2ZXJzaW9uOiAnMC4xLjEwJyxcbiAgICAgICAgICAgICBwbGF0Zm9ybTogJ2VsZWN0cm9uJyxcbiAgICAgICAgICAgfSxcbiAgICAgICAgICAgcm9sZTogJ29wZXJhdG9yJyxcbiAgICAgICAgICAgc2NvcGVzOiBbJ29wZXJhdG9yLnJlYWQnLCAnb3BlcmF0b3Iud3JpdGUnXSxcbiAgICAgICAgICAgZGV2aWNlOiB7XG4gICAgICAgICAgICAgaWQ6IGlkZW50aXR5LmlkLFxuICAgICAgICAgICAgIHB1YmxpY0tleTogaWRlbnRpdHkucHVibGljS2V5LFxuICAgICAgICAgICAgIHNpZ25hdHVyZTogc2lnLnNpZ25hdHVyZSxcbiAgICAgICAgICAgICBzaWduZWRBdDogc2lnbmVkQXRNcyxcbiAgICAgICAgICAgICBub25jZTogY29ubmVjdE5vbmNlLFxuICAgICAgICAgICB9LFxuICAgICAgICAgICBhdXRoOiB7XG4gICAgICAgICAgICAgdG9rZW46IHRoaXMudG9rZW4sXG4gICAgICAgICAgIH0sXG4gICAgICAgICB9KTtcblxuICAgICAgICAgdGhpcy5fc2V0U3RhdGUoJ2Nvbm5lY3RlZCcpO1xuICAgICAgICAgdGhpcy5yZWNvbm5lY3RBdHRlbXB0ID0gMDtcbiAgICAgICAgIGlmIChoYW5kc2hha2VUaW1lcikge1xuICAgICAgICAgICBjbGVhclRpbWVvdXQoaGFuZHNoYWtlVGltZXIpO1xuICAgICAgICAgICBoYW5kc2hha2VUaW1lciA9IG51bGw7XG4gICAgICAgICB9XG4gICAgICAgICB0aGlzLl9zdGFydEhlYXJ0YmVhdCgpO1xuICAgICAgfSBjYXRjaCAoZXJyKSB7XG4gICAgICAgIGNvbnNvbGUuZXJyb3IoJ1tvY2xhdy13c10gQ29ubmVjdCBoYW5kc2hha2UgZmFpbGVkJywgZXJyKTtcbiAgICAgICAgd3MuY2xvc2UoKTtcbiAgICAgIH1cbiAgICB9O1xuXG4gICAgbGV0IGhhbmRzaGFrZVRpbWVyOiBSZXR1cm5UeXBlPHR5cGVvZiBzZXRUaW1lb3V0PiB8IG51bGwgPSBudWxsO1xuXG4gICAgd3Mub25vcGVuID0gKCkgPT4ge1xuICAgICAgdGhpcy5fc2V0U3RhdGUoJ2hhbmRzaGFraW5nJyk7XG4gICAgICAvLyBUaGUgZ2F0ZXdheSB3aWxsIHNlbmQgY29ubmVjdC5jaGFsbGVuZ2U7IGNvbm5lY3QgaXMgc2VudCBvbmNlIHdlIGhhdmUgYSBub25jZS5cbiAgICAgIGlmIChoYW5kc2hha2VUaW1lcikgY2xlYXJUaW1lb3V0KGhhbmRzaGFrZVRpbWVyKTtcbiAgICAgIGhhbmRzaGFrZVRpbWVyID0gc2V0VGltZW91dCgoKSA9PiB7XG4gICAgICAgIC8vIElmIHdlIG5ldmVyIGdvdCB0aGUgY2hhbGxlbmdlIG5vbmNlLCBmb3JjZSByZWNvbm5lY3QuXG4gICAgICAgIGlmICh0aGlzLnN0YXRlID09PSAnaGFuZHNoYWtpbmcnICYmICF0aGlzLmludGVudGlvbmFsQ2xvc2UpIHtcbiAgICAgICAgICBjb25zb2xlLndhcm4oJ1tvY2xhdy13c10gSGFuZHNoYWtlIHRpbWVkIG91dCB3YWl0aW5nIGZvciBjb25uZWN0LmNoYWxsZW5nZScpO1xuICAgICAgICAgIHdzLmNsb3NlKCk7XG4gICAgICAgIH1cbiAgICAgIH0sIEhBTkRTSEFLRV9USU1FT1VUX01TKTtcbiAgICB9O1xuXG4gICAgd3Mub25tZXNzYWdlID0gKGV2ZW50OiBNZXNzYWdlRXZlbnQpID0+IHtcbiAgICAgIC8vIFdlYlNvY2tldCBvbm1lc3NhZ2UgY2Fubm90IGJlIGFzeW5jLCBidXQgd2UgY2FuIHJ1biBhbiBhc3luYyB0YXNrIGluc2lkZS5cbiAgICAgIHZvaWQgKGFzeW5jICgpID0+IHtcbiAgICAgICAgY29uc3Qgbm9ybWFsaXplZCA9IGF3YWl0IG5vcm1hbGl6ZVdzRGF0YVRvVGV4dChldmVudC5kYXRhKTtcbiAgICAgICAgaWYgKCFub3JtYWxpemVkLm9rKSB7XG4gICAgICAgICAgaWYgKG5vcm1hbGl6ZWQucmVhc29uID09PSAndG9vLWxhcmdlJykge1xuICAgICAgICAgICAgY29uc29sZS5lcnJvcignW29jbGF3LXdzXSBJbmJvdW5kIGZyYW1lIHRvbyBsYXJnZTsgY2xvc2luZyBjb25uZWN0aW9uJyk7XG4gICAgICAgICAgICB3cy5jbG9zZSgpO1xuICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBjb25zb2xlLmVycm9yKCdbb2NsYXctd3NdIFVuc3VwcG9ydGVkIGluYm91bmQgZnJhbWUgdHlwZTsgaWdub3JpbmcnKTtcbiAgICAgICAgICB9XG4gICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKG5vcm1hbGl6ZWQuYnl0ZXMgPiBNQVhfSU5CT1VORF9GUkFNRV9CWVRFUykge1xuICAgICAgICAgIGNvbnNvbGUuZXJyb3IoJ1tvY2xhdy13c10gSW5ib3VuZCBmcmFtZSB0b28gbGFyZ2U7IGNsb3NpbmcgY29ubmVjdGlvbicpO1xuICAgICAgICAgIHdzLmNsb3NlKCk7XG4gICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgbGV0IGZyYW1lOiBhbnk7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgZnJhbWUgPSBKU09OLnBhcnNlKG5vcm1hbGl6ZWQudGV4dCk7XG4gICAgICAgIH0gY2F0Y2gge1xuICAgICAgICAgIGNvbnNvbGUuZXJyb3IoJ1tvY2xhdy13c10gRmFpbGVkIHRvIHBhcnNlIGluY29taW5nIG1lc3NhZ2UnKTtcbiAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICAvLyBSZXNwb25zZXNcbiAgICAgICAgaWYgKGZyYW1lLnR5cGUgPT09ICdyZXMnKSB7XG4gICAgICAgICAgdGhpcy5faGFuZGxlUmVzcG9uc2VGcmFtZShmcmFtZSk7XG4gICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgLy8gRXZlbnRzXG4gICAgICAgIGlmIChmcmFtZS50eXBlID09PSAnZXZlbnQnKSB7XG4gICAgICAgICAgaWYgKGZyYW1lLmV2ZW50ID09PSAnY29ubmVjdC5jaGFsbGVuZ2UnKSB7XG4gICAgICAgICAgICBjb25uZWN0Tm9uY2UgPSBmcmFtZS5wYXlsb2FkPy5ub25jZSB8fCBudWxsO1xuICAgICAgICAgICAgLy8gQXR0ZW1wdCBoYW5kc2hha2Ugb25jZSB3ZSBoYXZlIGEgbm9uY2UuXG4gICAgICAgICAgICB2b2lkIHRyeUNvbm5lY3QoKTtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBpZiAoZnJhbWUuZXZlbnQgPT09ICdjaGF0Jykge1xuICAgICAgICAgICAgdGhpcy5faGFuZGxlQ2hhdEV2ZW50RnJhbWUoZnJhbWUpO1xuICAgICAgICAgIH1cbiAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICAvLyBBdm9pZCBsb2dnaW5nIGZ1bGwgZnJhbWVzIChtYXkgaW5jbHVkZSBtZXNzYWdlIGNvbnRlbnQgb3Igb3RoZXIgc2Vuc2l0aXZlIHBheWxvYWRzKS5cbiAgICAgICAgY29uc29sZS5kZWJ1ZygnW29jbGF3LXdzXSBVbmhhbmRsZWQgZnJhbWUnLCB7IHR5cGU6IGZyYW1lPy50eXBlLCBldmVudDogZnJhbWU/LmV2ZW50LCBpZDogZnJhbWU/LmlkIH0pO1xuICAgICAgfSkoKTtcbiAgICB9O1xuXG4gICAgY29uc3QgY2xlYXJIYW5kc2hha2VUaW1lciA9ICgpID0+IHtcbiAgICAgIGlmIChoYW5kc2hha2VUaW1lcikge1xuICAgICAgICBjbGVhclRpbWVvdXQoaGFuZHNoYWtlVGltZXIpO1xuICAgICAgICBoYW5kc2hha2VUaW1lciA9IG51bGw7XG4gICAgICB9XG4gICAgfTtcblxuICAgIHdzLm9uY2xvc2UgPSAoKSA9PiB7XG4gICAgICBjbGVhckhhbmRzaGFrZVRpbWVyKCk7XG4gICAgICB0aGlzLl9zdG9wVGltZXJzKCk7XG4gICAgICB0aGlzLmFjdGl2ZVJ1bklkID0gbnVsbDtcbiAgICAgIHRoaXMuYWJvcnRJbkZsaWdodCA9IG51bGw7XG4gICAgICB0aGlzLl9zZXRXb3JraW5nKGZhbHNlKTtcbiAgICAgIHRoaXMuX3NldFN0YXRlKCdkaXNjb25uZWN0ZWQnKTtcblxuICAgICAgZm9yIChjb25zdCBwZW5kaW5nIG9mIHRoaXMucGVuZGluZ1JlcXVlc3RzLnZhbHVlcygpKSB7XG4gICAgICAgIGlmIChwZW5kaW5nLnRpbWVvdXQpIGNsZWFyVGltZW91dChwZW5kaW5nLnRpbWVvdXQpO1xuICAgICAgICBwZW5kaW5nLnJlamVjdChuZXcgRXJyb3IoJ0Nvbm5lY3Rpb24gY2xvc2VkJykpO1xuICAgICAgfVxuICAgICAgdGhpcy5wZW5kaW5nUmVxdWVzdHMuY2xlYXIoKTtcblxuICAgICAgaWYgKCF0aGlzLmludGVudGlvbmFsQ2xvc2UpIHtcbiAgICAgICAgdGhpcy5fc2NoZWR1bGVSZWNvbm5lY3QoKTtcbiAgICAgIH1cbiAgICB9O1xuXG4gICAgd3Mub25lcnJvciA9IChldjogRXZlbnQpID0+IHtcbiAgICAgIGNsZWFySGFuZHNoYWtlVGltZXIoKTtcbiAgICAgIGNvbnNvbGUuZXJyb3IoJ1tvY2xhdy13c10gV2ViU29ja2V0IGVycm9yJywgZXYpO1xuICAgIH07XG4gIH1cblxuICBwcml2YXRlIF9oYW5kbGVSZXNwb25zZUZyYW1lKGZyYW1lOiBhbnkpOiB2b2lkIHtcbiAgICBjb25zdCBwZW5kaW5nID0gdGhpcy5wZW5kaW5nUmVxdWVzdHMuZ2V0KGZyYW1lLmlkKTtcbiAgICBpZiAoIXBlbmRpbmcpIHJldHVybjtcblxuICAgIHRoaXMucGVuZGluZ1JlcXVlc3RzLmRlbGV0ZShmcmFtZS5pZCk7XG4gICAgaWYgKHBlbmRpbmcudGltZW91dCkgY2xlYXJUaW1lb3V0KHBlbmRpbmcudGltZW91dCk7XG5cbiAgICBpZiAoZnJhbWUub2spIHBlbmRpbmcucmVzb2x2ZShmcmFtZS5wYXlsb2FkKTtcbiAgICBlbHNlIHBlbmRpbmcucmVqZWN0KG5ldyBFcnJvcihmcmFtZS5lcnJvcj8ubWVzc2FnZSB8fCAnUmVxdWVzdCBmYWlsZWQnKSk7XG4gIH1cblxuICBwcml2YXRlIF9oYW5kbGVDaGF0RXZlbnRGcmFtZShmcmFtZTogYW55KTogdm9pZCB7XG4gICAgY29uc3QgcGF5bG9hZCA9IGZyYW1lLnBheWxvYWQ7XG4gICAgY29uc3QgaW5jb21pbmdTZXNzaW9uS2V5ID0gU3RyaW5nKHBheWxvYWQ/LnNlc3Npb25LZXkgfHwgJycpO1xuICAgIGlmICghaW5jb21pbmdTZXNzaW9uS2V5IHx8ICFzZXNzaW9uS2V5TWF0Y2hlcyh0aGlzLnNlc3Npb25LZXksIGluY29taW5nU2Vzc2lvbktleSkpIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICAvLyBCZXN0LWVmZm9ydCBydW4gY29ycmVsYXRpb24gKGlmIGdhdGV3YXkgaW5jbHVkZXMgYSBydW4gaWQpLiBUaGlzIGF2b2lkcyBjbGVhcmluZyBvdXIgVUlcbiAgICAvLyBiYXNlZCBvbiBhIGRpZmZlcmVudCBjbGllbnQncyBydW4gaW4gdGhlIHNhbWUgc2Vzc2lvbi5cbiAgICBjb25zdCBpbmNvbWluZ1J1bklkID0gU3RyaW5nKHBheWxvYWQ/LnJ1bklkIHx8IHBheWxvYWQ/LmlkZW1wb3RlbmN5S2V5IHx8IHBheWxvYWQ/Lm1ldGE/LnJ1bklkIHx8ICcnKTtcbiAgICBpZiAodGhpcy5hY3RpdmVSdW5JZCAmJiBpbmNvbWluZ1J1bklkICYmIGluY29taW5nUnVuSWQgIT09IHRoaXMuYWN0aXZlUnVuSWQpIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICAvLyBBdm9pZCBkb3VibGUtcmVuZGVyOiBnYXRld2F5IGVtaXRzIGRlbHRhICsgZmluYWwgKyBhYm9ydGVkLiBSZW5kZXIgb25seSBleHBsaWNpdCBmaW5hbC9hYm9ydGVkLlxuICAgIC8vIElmIHN0YXRlIGlzIG1pc3NpbmcsIHRyZWF0IGFzIG5vbi10ZXJtaW5hbCAoZG8gbm90IGNsZWFyIFVJIC8gZG8gbm90IHJlbmRlcikuXG4gICAgaWYgKCFwYXlsb2FkPy5zdGF0ZSkge1xuICAgICAgcmV0dXJuO1xuICAgIH1cbiAgICBpZiAocGF5bG9hZC5zdGF0ZSAhPT0gJ2ZpbmFsJyAmJiBwYXlsb2FkLnN0YXRlICE9PSAnYWJvcnRlZCcpIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICAvLyBXZSBvbmx5IGFwcGVuZCBhc3Npc3RhbnQgb3V0cHV0IHRvIFVJLlxuICAgIGNvbnN0IG1zZyA9IHBheWxvYWQ/Lm1lc3NhZ2U7XG4gICAgY29uc3Qgcm9sZSA9IG1zZz8ucm9sZSA/PyAnYXNzaXN0YW50JztcblxuICAgIC8vIEFib3J0ZWQgZW5kcyB0aGUgcnVuIHJlZ2FyZGxlc3Mgb2Ygcm9sZS9tZXNzYWdlLlxuICAgIGlmIChwYXlsb2FkLnN0YXRlID09PSAnYWJvcnRlZCcpIHtcbiAgICAgIHRoaXMuYWN0aXZlUnVuSWQgPSBudWxsO1xuICAgICAgdGhpcy5fc2V0V29ya2luZyhmYWxzZSk7XG4gICAgICAvLyBBYm9ydGVkIG1heSBoYXZlIG5vIGFzc2lzdGFudCBtZXNzYWdlOyBpZiBub25lLCBzdG9wIGhlcmUuXG4gICAgICBpZiAoIW1zZykgcmV0dXJuO1xuICAgICAgLy8gSWYgdGhlcmUgaXMgYSBtZXNzYWdlLCBvbmx5IGFwcGVuZCBhc3Npc3RhbnQgb3V0cHV0LlxuICAgICAgaWYgKHJvbGUgIT09ICdhc3Npc3RhbnQnKSByZXR1cm47XG4gICAgfVxuXG4gICAgLy8gRmluYWwgc2hvdWxkIG9ubHkgY29tcGxldGUgdGhlIHJ1biB3aGVuIHRoZSBhc3Npc3RhbnQgY29tcGxldGVzLlxuICAgIGlmIChwYXlsb2FkLnN0YXRlID09PSAnZmluYWwnKSB7XG4gICAgICBpZiAocm9sZSAhPT0gJ2Fzc2lzdGFudCcpIHJldHVybjtcbiAgICAgIHRoaXMuYWN0aXZlUnVuSWQgPSBudWxsO1xuICAgICAgdGhpcy5fc2V0V29ya2luZyhmYWxzZSk7XG4gICAgfVxuXG4gICAgY29uc3QgdGV4dCA9IGV4dHJhY3RUZXh0RnJvbUdhdGV3YXlNZXNzYWdlKG1zZyk7XG4gICAgaWYgKCF0ZXh0KSByZXR1cm47XG5cbiAgICAvLyBPcHRpb25hbDogaGlkZSBoZWFydGJlYXQgYWNrcyAobm9pc2UgaW4gVUkpXG4gICAgaWYgKHRleHQudHJpbSgpID09PSAnSEVBUlRCRUFUX09LJykge1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIHRoaXMub25NZXNzYWdlPy4oe1xuICAgICAgdHlwZTogJ21lc3NhZ2UnLFxuICAgICAgcGF5bG9hZDoge1xuICAgICAgICBjb250ZW50OiB0ZXh0LFxuICAgICAgICByb2xlOiAnYXNzaXN0YW50JyxcbiAgICAgICAgdGltZXN0YW1wOiBEYXRlLm5vdygpLFxuICAgICAgfSxcbiAgICB9KTtcbiAgfVxuXG4gIHByaXZhdGUgX3NlbmRSZXF1ZXN0KG1ldGhvZDogc3RyaW5nLCBwYXJhbXM6IGFueSk6IFByb21pc2U8YW55PiB7XG4gICAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIGlmICghdGhpcy53cyB8fCB0aGlzLndzLnJlYWR5U3RhdGUgIT09IFdlYlNvY2tldC5PUEVOKSB7XG4gICAgICAgIHJlamVjdChuZXcgRXJyb3IoJ1dlYlNvY2tldCBub3QgY29ubmVjdGVkJykpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG5cbiAgICAgIGlmICh0aGlzLnBlbmRpbmdSZXF1ZXN0cy5zaXplID49IE1BWF9QRU5ESU5HX1JFUVVFU1RTKSB7XG4gICAgICAgIHJlamVjdChuZXcgRXJyb3IoYFRvbyBtYW55IGluLWZsaWdodCByZXF1ZXN0cyAoJHt0aGlzLnBlbmRpbmdSZXF1ZXN0cy5zaXplfSlgKSk7XG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cblxuICAgICAgY29uc3QgaWQgPSBgcmVxLSR7Kyt0aGlzLnJlcXVlc3RJZH1gO1xuXG4gICAgICBjb25zdCBwZW5kaW5nOiBQZW5kaW5nUmVxdWVzdCA9IHsgcmVzb2x2ZSwgcmVqZWN0LCB0aW1lb3V0OiBudWxsIH07XG4gICAgICB0aGlzLnBlbmRpbmdSZXF1ZXN0cy5zZXQoaWQsIHBlbmRpbmcpO1xuXG4gICAgICBjb25zdCBwYXlsb2FkID0gSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0eXBlOiAncmVxJyxcbiAgICAgICAgbWV0aG9kLFxuICAgICAgICBpZCxcbiAgICAgICAgcGFyYW1zLFxuICAgICAgfSk7XG5cbiAgICAgIHRyeSB7XG4gICAgICAgIHRoaXMud3Muc2VuZChwYXlsb2FkKTtcbiAgICAgIH0gY2F0Y2ggKGVycikge1xuICAgICAgICB0aGlzLnBlbmRpbmdSZXF1ZXN0cy5kZWxldGUoaWQpO1xuICAgICAgICByZWplY3QoZXJyKTtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuXG4gICAgICBwZW5kaW5nLnRpbWVvdXQgPSBzZXRUaW1lb3V0KCgpID0+IHtcbiAgICAgICAgaWYgKHRoaXMucGVuZGluZ1JlcXVlc3RzLmhhcyhpZCkpIHtcbiAgICAgICAgICB0aGlzLnBlbmRpbmdSZXF1ZXN0cy5kZWxldGUoaWQpO1xuICAgICAgICAgIHJlamVjdChuZXcgRXJyb3IoYFJlcXVlc3QgdGltZW91dDogJHttZXRob2R9YCkpO1xuICAgICAgICB9XG4gICAgICB9LCAzMF8wMDApO1xuICAgIH0pO1xuICB9XG5cbiAgcHJpdmF0ZSBfc2NoZWR1bGVSZWNvbm5lY3QoKTogdm9pZCB7XG4gICAgaWYgKHRoaXMucmVjb25uZWN0VGltZXIgIT09IG51bGwpIHJldHVybjtcblxuICAgIGNvbnN0IGF0dGVtcHQgPSArK3RoaXMucmVjb25uZWN0QXR0ZW1wdDtcbiAgICBjb25zdCBleHAgPSBNYXRoLm1pbihSRUNPTk5FQ1RfTUFYX01TLCBSRUNPTk5FQ1RfQkFTRV9NUyAqIE1hdGgucG93KDIsIGF0dGVtcHQgLSAxKSk7XG4gICAgLy8gSml0dGVyOiAwLjV4Li4xLjV4XG4gICAgY29uc3Qgaml0dGVyID0gMC41ICsgTWF0aC5yYW5kb20oKTtcbiAgICBjb25zdCBkZWxheSA9IE1hdGguZmxvb3IoZXhwICogaml0dGVyKTtcblxuICAgIHRoaXMucmVjb25uZWN0VGltZXIgPSBzZXRUaW1lb3V0KCgpID0+IHtcbiAgICAgIHRoaXMucmVjb25uZWN0VGltZXIgPSBudWxsO1xuICAgICAgaWYgKCF0aGlzLmludGVudGlvbmFsQ2xvc2UpIHtcbiAgICAgICAgY29uc29sZS5sb2coYFtvY2xhdy13c10gUmVjb25uZWN0aW5nIHRvICR7dGhpcy51cmx9XHUyMDI2IChhdHRlbXB0ICR7YXR0ZW1wdH0sICR7ZGVsYXl9bXMpYCk7XG4gICAgICAgIHRoaXMuX2Nvbm5lY3QoKTtcbiAgICAgIH1cbiAgICB9LCBkZWxheSk7XG4gIH1cblxuICBwcml2YXRlIGxhc3RCdWZmZXJlZFdhcm5BdE1zID0gMDtcblxuICBwcml2YXRlIF9zdGFydEhlYXJ0YmVhdCgpOiB2b2lkIHtcbiAgICB0aGlzLl9zdG9wSGVhcnRiZWF0KCk7XG4gICAgdGhpcy5oZWFydGJlYXRUaW1lciA9IHNldEludGVydmFsKCgpID0+IHtcbiAgICAgIGlmICh0aGlzLndzPy5yZWFkeVN0YXRlICE9PSBXZWJTb2NrZXQuT1BFTikgcmV0dXJuO1xuICAgICAgaWYgKHRoaXMud3MuYnVmZmVyZWRBbW91bnQgPiAwKSB7XG4gICAgICAgIGNvbnN0IG5vdyA9IERhdGUubm93KCk7XG4gICAgICAgIC8vIFRocm90dGxlIHRvIGF2b2lkIGxvZyBzcGFtIGluIGxvbmctcnVubmluZyBzZXNzaW9ucy5cbiAgICAgICAgaWYgKG5vdyAtIHRoaXMubGFzdEJ1ZmZlcmVkV2FybkF0TXMgPiA1ICogNjBfMDAwKSB7XG4gICAgICAgICAgdGhpcy5sYXN0QnVmZmVyZWRXYXJuQXRNcyA9IG5vdztcbiAgICAgICAgICBjb25zb2xlLndhcm4oJ1tvY2xhdy13c10gU2VuZCBidWZmZXIgbm90IGVtcHR5IFx1MjAxNCBjb25uZWN0aW9uIG1heSBiZSBzdGFsbGVkJyk7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9LCBIRUFSVEJFQVRfSU5URVJWQUxfTVMpO1xuICB9XG5cbiAgcHJpdmF0ZSBfc3RvcEhlYXJ0YmVhdCgpOiB2b2lkIHtcbiAgICBpZiAodGhpcy5oZWFydGJlYXRUaW1lcikge1xuICAgICAgY2xlYXJJbnRlcnZhbCh0aGlzLmhlYXJ0YmVhdFRpbWVyKTtcbiAgICAgIHRoaXMuaGVhcnRiZWF0VGltZXIgPSBudWxsO1xuICAgIH1cbiAgfVxuXG4gIHByaXZhdGUgX3N0b3BUaW1lcnMoKTogdm9pZCB7XG4gICAgdGhpcy5fc3RvcEhlYXJ0YmVhdCgpO1xuICAgIHRoaXMuX2Rpc2FybVdvcmtpbmdTYWZldHlUaW1lb3V0KCk7XG4gICAgaWYgKHRoaXMucmVjb25uZWN0VGltZXIpIHtcbiAgICAgIGNsZWFyVGltZW91dCh0aGlzLnJlY29ubmVjdFRpbWVyKTtcbiAgICAgIHRoaXMucmVjb25uZWN0VGltZXIgPSBudWxsO1xuICAgIH1cbiAgfVxuXG4gIHByaXZhdGUgX3NldFN0YXRlKHN0YXRlOiBXU0NsaWVudFN0YXRlKTogdm9pZCB7XG4gICAgaWYgKHRoaXMuc3RhdGUgPT09IHN0YXRlKSByZXR1cm47XG4gICAgdGhpcy5zdGF0ZSA9IHN0YXRlO1xuICAgIHRoaXMub25TdGF0ZUNoYW5nZT8uKHN0YXRlKTtcbiAgfVxuXG4gIHByaXZhdGUgX3NldFdvcmtpbmcod29ya2luZzogYm9vbGVhbik6IHZvaWQge1xuICAgIGlmICh0aGlzLndvcmtpbmcgPT09IHdvcmtpbmcpIHJldHVybjtcbiAgICB0aGlzLndvcmtpbmcgPSB3b3JraW5nO1xuICAgIHRoaXMub25Xb3JraW5nQ2hhbmdlPy4od29ya2luZyk7XG5cbiAgICBpZiAoIXdvcmtpbmcpIHtcbiAgICAgIHRoaXMuX2Rpc2FybVdvcmtpbmdTYWZldHlUaW1lb3V0KCk7XG4gICAgfVxuICB9XG5cbiAgcHJpdmF0ZSBfYXJtV29ya2luZ1NhZmV0eVRpbWVvdXQoKTogdm9pZCB7XG4gICAgdGhpcy5fZGlzYXJtV29ya2luZ1NhZmV0eVRpbWVvdXQoKTtcbiAgICB0aGlzLndvcmtpbmdUaW1lciA9IHNldFRpbWVvdXQoKCkgPT4ge1xuICAgICAgLy8gSWYgdGhlIGdhdGV3YXkgbmV2ZXIgZW1pdHMgYW4gYXNzaXN0YW50IGZpbmFsIHJlc3BvbnNlLCBkb25cdTIwMTl0IGxlYXZlIFVJIHN0dWNrLlxuICAgICAgdGhpcy5fc2V0V29ya2luZyhmYWxzZSk7XG4gICAgfSwgV09SS0lOR19NQVhfTVMpO1xuICB9XG5cbiAgcHJpdmF0ZSBfZGlzYXJtV29ya2luZ1NhZmV0eVRpbWVvdXQoKTogdm9pZCB7XG4gICAgaWYgKHRoaXMud29ya2luZ1RpbWVyKSB7XG4gICAgICBjbGVhclRpbWVvdXQodGhpcy53b3JraW5nVGltZXIpO1xuICAgICAgdGhpcy53b3JraW5nVGltZXIgPSBudWxsO1xuICAgIH1cbiAgfVxufVxuIiwgImltcG9ydCB7IEl0ZW1WaWV3LCBNYXJrZG93blJlbmRlcmVyLCBNb2RhbCwgTm90aWNlLCBTZXR0aW5nLCBURmlsZSwgV29ya3NwYWNlTGVhZiB9IGZyb20gJ29ic2lkaWFuJztcbmltcG9ydCB0eXBlIE9wZW5DbGF3UGx1Z2luIGZyb20gJy4vbWFpbic7XG5pbXBvcnQgeyBDaGF0TWFuYWdlciB9IGZyb20gJy4vY2hhdCc7XG5pbXBvcnQgdHlwZSB7IENoYXRNZXNzYWdlLCBQYXRoTWFwcGluZyB9IGZyb20gJy4vdHlwZXMnO1xuaW1wb3J0IHsgZXh0cmFjdENhbmRpZGF0ZXMsIHRyeU1hcFJlbW90ZVBhdGhUb1ZhdWx0UGF0aCB9IGZyb20gJy4vbGlua2lmeSc7XG5pbXBvcnQgeyBnZXRBY3RpdmVOb3RlQ29udGV4dCB9IGZyb20gJy4vY29udGV4dCc7XG5pbXBvcnQgeyBPYnNpZGlhbldTQ2xpZW50IH0gZnJvbSAnLi93ZWJzb2NrZXQnO1xuXG5leHBvcnQgY29uc3QgVklFV19UWVBFX09QRU5DTEFXX0NIQVQgPSAnb3BlbmNsYXctY2hhdCc7XG5cbmNsYXNzIE5ld1Nlc3Npb25Nb2RhbCBleHRlbmRzIE1vZGFsIHtcbiAgcHJpdmF0ZSBpbml0aWFsVmFsdWU6IHN0cmluZztcbiAgcHJpdmF0ZSBvblN1Ym1pdDogKHZhbHVlOiBzdHJpbmcpID0+IHZvaWQ7XG5cbiAgY29uc3RydWN0b3IodmlldzogT3BlbkNsYXdDaGF0VmlldywgaW5pdGlhbFZhbHVlOiBzdHJpbmcsIG9uU3VibWl0OiAodmFsdWU6IHN0cmluZykgPT4gdm9pZCkge1xuICAgIHN1cGVyKHZpZXcuYXBwKTtcbiAgICB0aGlzLmluaXRpYWxWYWx1ZSA9IGluaXRpYWxWYWx1ZTtcbiAgICB0aGlzLm9uU3VibWl0ID0gb25TdWJtaXQ7XG4gIH1cblxuICBvbk9wZW4oKTogdm9pZCB7XG4gICAgY29uc3QgeyBjb250ZW50RWwgfSA9IHRoaXM7XG4gICAgY29udGVudEVsLmVtcHR5KCk7XG5cbiAgICBjb250ZW50RWwuY3JlYXRlRWwoJ2gzJywgeyB0ZXh0OiAnTmV3IHNlc3Npb24ga2V5JyB9KTtcblxuICAgIGxldCB2YWx1ZSA9IHRoaXMuaW5pdGlhbFZhbHVlO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGVudEVsKVxuICAgICAgLnNldE5hbWUoJ1Nlc3Npb24ga2V5JylcbiAgICAgIC5zZXREZXNjKCdUaXA6IGNob29zZSBhIHNob3J0IHN1ZmZpeDsgaXQgd2lsbCBiZWNvbWUgYWdlbnQ6bWFpbjpvYnNpZGlhbjpkaXJlY3Q6PHZhdWx0SGFzaD4tPHN1ZmZpeD4uJylcbiAgICAgIC5hZGRUZXh0KCh0KSA9PiB7XG4gICAgICAgIHQuc2V0VmFsdWUodmFsdWUpO1xuICAgICAgICB0Lm9uQ2hhbmdlKCh2KSA9PiB7XG4gICAgICAgICAgdmFsdWUgPSB2O1xuICAgICAgICB9KTtcbiAgICAgIH0pO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGVudEVsKVxuICAgICAgLmFkZEJ1dHRvbigoYikgPT4ge1xuICAgICAgICBiLnNldEJ1dHRvblRleHQoJ0NhbmNlbCcpO1xuICAgICAgICBiLm9uQ2xpY2soKCkgPT4gdGhpcy5jbG9zZSgpKTtcbiAgICAgIH0pXG4gICAgICAuYWRkQnV0dG9uKChiKSA9PiB7XG4gICAgICAgIGIuc2V0Q3RhKCk7XG4gICAgICAgIGIuc2V0QnV0dG9uVGV4dCgnQ3JlYXRlJyk7XG4gICAgICAgIGIub25DbGljaygoKSA9PiB7XG4gICAgICAgICAgY29uc3QgdiA9IHZhbHVlLnRyaW0oKS50b0xvd2VyQ2FzZSgpO1xuICAgICAgICAgIGlmICghdikge1xuICAgICAgICAgICAgbmV3IE5vdGljZSgnU3VmZml4IGNhbm5vdCBiZSBlbXB0eScpO1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgIH1cbiAgICAgICAgICBpZiAoIS9eW2EtejAtOV1bYS16MC05Xy1dezAsNjN9JC8udGVzdCh2KSkge1xuICAgICAgICAgICAgbmV3IE5vdGljZSgnVXNlIGxldHRlcnMvbnVtYmVycy9fLy0gb25seSAobWF4IDY0IGNoYXJzKScpO1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgIH1cbiAgICAgICAgICB0aGlzLm9uU3VibWl0KHYpO1xuICAgICAgICAgIHRoaXMuY2xvc2UoKTtcbiAgICAgICAgfSk7XG4gICAgICB9KTtcbiAgfVxufVxuXG5leHBvcnQgY2xhc3MgT3BlbkNsYXdDaGF0VmlldyBleHRlbmRzIEl0ZW1WaWV3IHtcbiAgcHJpdmF0ZSBwbHVnaW46IE9wZW5DbGF3UGx1Z2luO1xuICBwcml2YXRlIGNoYXRNYW5hZ2VyOiBDaGF0TWFuYWdlcjtcbiAgcHJpdmF0ZSB3c0NsaWVudDogT2JzaWRpYW5XU0NsaWVudDtcblxuICAvLyBTdGF0ZVxuICBwcml2YXRlIGlzQ29ubmVjdGVkID0gZmFsc2U7XG4gIHByaXZhdGUgaXNXb3JraW5nID0gZmFsc2U7XG5cbiAgLy8gQ29ubmVjdGlvbiBub3RpY2VzIChhdm9pZCBzcGFtKVxuICBwcml2YXRlIGxhc3RDb25uTm90aWNlQXRNcyA9IDA7XG4gIHByaXZhdGUgbGFzdEdhdGV3YXlTdGF0ZTogc3RyaW5nIHwgbnVsbCA9IG51bGw7XG5cbiAgLy8gRE9NIHJlZnNcbiAgcHJpdmF0ZSBtZXNzYWdlc0VsITogSFRNTEVsZW1lbnQ7XG4gIHByaXZhdGUgaW5wdXRFbCE6IEhUTUxUZXh0QXJlYUVsZW1lbnQ7XG4gIHByaXZhdGUgc2VuZEJ0biE6IEhUTUxCdXR0b25FbGVtZW50O1xuICBwcml2YXRlIGluY2x1ZGVOb3RlQ2hlY2tib3ghOiBIVE1MSW5wdXRFbGVtZW50O1xuICBwcml2YXRlIHN0YXR1c0RvdCE6IEhUTUxFbGVtZW50O1xuXG4gIHByaXZhdGUgc2Vzc2lvblNlbGVjdCE6IEhUTUxTZWxlY3RFbGVtZW50O1xuICBwcml2YXRlIHNlc3Npb25SZWZyZXNoQnRuITogSFRNTEJ1dHRvbkVsZW1lbnQ7XG4gIHByaXZhdGUgc2Vzc2lvbk5ld0J0biE6IEhUTUxCdXR0b25FbGVtZW50O1xuICBwcml2YXRlIHNlc3Npb25NYWluQnRuITogSFRNTEJ1dHRvbkVsZW1lbnQ7XG4gIHByaXZhdGUgc3VwcHJlc3NTZXNzaW9uU2VsZWN0Q2hhbmdlID0gZmFsc2U7XG5cbiAgcHJpdmF0ZSBvbk1lc3NhZ2VzQ2xpY2s6ICgoZXY6IE1vdXNlRXZlbnQpID0+IHZvaWQpIHwgbnVsbCA9IG51bGw7XG5cbiAgY29uc3RydWN0b3IobGVhZjogV29ya3NwYWNlTGVhZiwgcGx1Z2luOiBPcGVuQ2xhd1BsdWdpbikge1xuICAgIHN1cGVyKGxlYWYpO1xuICAgIHRoaXMucGx1Z2luID0gcGx1Z2luO1xuICAgIHRoaXMuY2hhdE1hbmFnZXIgPSBuZXcgQ2hhdE1hbmFnZXIoKTtcbiAgICB0aGlzLndzQ2xpZW50ID0gdGhpcy5wbHVnaW4uY3JlYXRlV3NDbGllbnQodGhpcy5wbHVnaW4uZ2V0RGVmYXVsdFNlc3Npb25LZXkoKSk7XG5cbiAgICAvLyBXaXJlIGluY29taW5nIFdTIG1lc3NhZ2VzIFx1MjE5MiBDaGF0TWFuYWdlciAocGVyLWxlYWYpXG4gICAgdGhpcy53c0NsaWVudC5vbk1lc3NhZ2UgPSAobXNnKSA9PiB7XG4gICAgICBpZiAobXNnLnR5cGUgPT09ICdtZXNzYWdlJykge1xuICAgICAgICB0aGlzLmNoYXRNYW5hZ2VyLmFkZE1lc3NhZ2UoQ2hhdE1hbmFnZXIuY3JlYXRlQXNzaXN0YW50TWVzc2FnZShtc2cucGF5bG9hZC5jb250ZW50KSk7XG4gICAgICB9IGVsc2UgaWYgKG1zZy50eXBlID09PSAnZXJyb3InKSB7XG4gICAgICAgIGNvbnN0IGVyclRleHQgPSBtc2cucGF5bG9hZC5tZXNzYWdlID8/ICdVbmtub3duIGVycm9yIGZyb20gZ2F0ZXdheSc7XG4gICAgICAgIHRoaXMuY2hhdE1hbmFnZXIuYWRkTWVzc2FnZShDaGF0TWFuYWdlci5jcmVhdGVTeXN0ZW1NZXNzYWdlKGBcdTI2QTAgJHtlcnJUZXh0fWAsICdlcnJvcicpKTtcbiAgICAgIH1cbiAgICB9O1xuICB9XG5cbiAgZ2V0Vmlld1R5cGUoKTogc3RyaW5nIHtcbiAgICByZXR1cm4gVklFV19UWVBFX09QRU5DTEFXX0NIQVQ7XG4gIH1cblxuICBnZXREaXNwbGF5VGV4dCgpOiBzdHJpbmcge1xuICAgIHJldHVybiAnT3BlbkNsYXcgQ2hhdCc7XG4gIH1cblxuICBnZXRJY29uKCk6IHN0cmluZyB7XG4gICAgcmV0dXJuICdtZXNzYWdlLXNxdWFyZSc7XG4gIH1cblxuICBhc3luYyBvbk9wZW4oKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgdGhpcy5wbHVnaW4ucmVnaXN0ZXJDaGF0TGVhZigpO1xuICAgIHRoaXMuX2J1aWxkVUkoKTtcblxuICAgIC8vIEZ1bGwgcmUtcmVuZGVyIG9uIGNsZWFyIC8gcmVsb2FkXG4gICAgdGhpcy5jaGF0TWFuYWdlci5vblVwZGF0ZSA9IChtc2dzKSA9PiB0aGlzLl9yZW5kZXJNZXNzYWdlcyhtc2dzKTtcbiAgICAvLyBPKDEpIGFwcGVuZCBmb3IgbmV3IG1lc3NhZ2VzXG4gICAgdGhpcy5jaGF0TWFuYWdlci5vbk1lc3NhZ2VBZGRlZCA9IChtc2cpID0+IHRoaXMuX2FwcGVuZE1lc3NhZ2UobXNnKTtcblxuICAgIC8vIENvbm5lY3QgdGhpcyBsZWFmJ3MgV1MgY2xpZW50XG4gICAgY29uc3QgZ3cgPSB0aGlzLnBsdWdpbi5nZXRHYXRld2F5Q29uZmlnKCk7XG4gICAgaWYgKGd3LnRva2VuKSB7XG4gICAgICB0aGlzLndzQ2xpZW50LmNvbm5lY3QoZ3cudXJsLCBndy50b2tlbiwgeyBhbGxvd0luc2VjdXJlV3M6IGd3LmFsbG93SW5zZWN1cmVXcyB9KTtcbiAgICB9IGVsc2Uge1xuICAgICAgbmV3IE5vdGljZSgnT3BlbkNsYXcgQ2hhdDogcGxlYXNlIGNvbmZpZ3VyZSB5b3VyIGdhdGV3YXkgdG9rZW4gaW4gU2V0dGluZ3MuJyk7XG4gICAgfVxuXG4gICAgLy8gU3Vic2NyaWJlIHRvIFdTIHN0YXRlIGNoYW5nZXNcbiAgICB0aGlzLndzQ2xpZW50Lm9uU3RhdGVDaGFuZ2UgPSAoc3RhdGUpID0+IHsgXG4gICAgICAvLyBDb25uZWN0aW9uIGxvc3MgLyByZWNvbm5lY3Qgbm90aWNlcyAodGhyb3R0bGVkKVxuICAgICAgY29uc3QgcHJldiA9IHRoaXMubGFzdEdhdGV3YXlTdGF0ZTtcbiAgICAgIHRoaXMubGFzdEdhdGV3YXlTdGF0ZSA9IHN0YXRlO1xuXG4gICAgICBjb25zdCBub3cgPSBEYXRlLm5vdygpO1xuICAgICAgY29uc3QgTk9USUNFX1RIUk9UVExFX01TID0gNjBfMDAwO1xuXG4gICAgICBjb25zdCBzaG91bGROb3RpZnkgPSAoKSA9PiBub3cgLSB0aGlzLmxhc3RDb25uTm90aWNlQXRNcyA+IE5PVElDRV9USFJPVFRMRV9NUztcbiAgICAgIGNvbnN0IG5vdGlmeSA9ICh0ZXh0OiBzdHJpbmcpID0+IHtcbiAgICAgICAgaWYgKCFzaG91bGROb3RpZnkoKSkgcmV0dXJuO1xuICAgICAgICB0aGlzLmxhc3RDb25uTm90aWNlQXRNcyA9IG5vdztcbiAgICAgICAgbmV3IE5vdGljZSh0ZXh0KTtcbiAgICAgIH07XG5cbiAgICAgIC8vIE9ubHkgc2hvdyBcdTIwMUNsb3N0XHUyMDFEIGlmIHdlIHdlcmUgcHJldmlvdXNseSBjb25uZWN0ZWQuXG4gICAgICBpZiAocHJldiA9PT0gJ2Nvbm5lY3RlZCcgJiYgc3RhdGUgPT09ICdkaXNjb25uZWN0ZWQnKSB7XG4gICAgICAgIG5vdGlmeSgnT3BlbkNsYXcgQ2hhdDogY29ubmVjdGlvbiBsb3N0IFx1MjAxNCByZWNvbm5lY3RpbmdcdTIwMjYnKTtcbiAgICAgICAgLy8gQWxzbyBhcHBlbmQgYSBzeXN0ZW0gbWVzc2FnZSBzbyBpdFx1MjAxOXMgdmlzaWJsZSBpbiB0aGUgY2hhdCBoaXN0b3J5LlxuICAgICAgICB0aGlzLmNoYXRNYW5hZ2VyLmFkZE1lc3NhZ2UoQ2hhdE1hbmFnZXIuY3JlYXRlU3lzdGVtTWVzc2FnZSgnXHUyNkEwIENvbm5lY3Rpb24gbG9zdCBcdTIwMTQgcmVjb25uZWN0aW5nXHUyMDI2JywgJ2Vycm9yJykpO1xuICAgICAgfVxuXG4gICAgICAvLyBPcHRpb25hbCBcdTIwMUNyZWNvbm5lY3RlZFx1MjAxRCBub3RpY2VcbiAgICAgIGlmIChwcmV2ICYmIHByZXYgIT09ICdjb25uZWN0ZWQnICYmIHN0YXRlID09PSAnY29ubmVjdGVkJykge1xuICAgICAgICBub3RpZnkoJ09wZW5DbGF3IENoYXQ6IHJlY29ubmVjdGVkJyk7XG4gICAgICAgIHRoaXMuY2hhdE1hbmFnZXIuYWRkTWVzc2FnZShDaGF0TWFuYWdlci5jcmVhdGVTeXN0ZW1NZXNzYWdlKCdcdTI3MDUgUmVjb25uZWN0ZWQnLCAnaW5mbycpKTtcbiAgICAgIH1cblxuICAgICAgdGhpcy5pc0Nvbm5lY3RlZCA9IHN0YXRlID09PSAnY29ubmVjdGVkJztcbiAgICAgIHRoaXMuc3RhdHVzRG90LnRvZ2dsZUNsYXNzKCdjb25uZWN0ZWQnLCB0aGlzLmlzQ29ubmVjdGVkKTtcbiAgICAgIHRoaXMuc3RhdHVzRG90LnRpdGxlID0gYEdhdGV3YXk6ICR7c3RhdGV9YDtcbiAgICAgIHRoaXMuX3VwZGF0ZVNlbmRCdXR0b24oKTtcbiAgICB9O1xuXG4gICAgLy8gU3Vic2NyaWJlIHRvIFx1MjAxQ3dvcmtpbmdcdTIwMUQgKHJlcXVlc3QtaW4tZmxpZ2h0KSBzdGF0ZVxuICAgIHRoaXMud3NDbGllbnQub25Xb3JraW5nQ2hhbmdlID0gKHdvcmtpbmcpID0+IHtcbiAgICAgIHRoaXMuaXNXb3JraW5nID0gd29ya2luZztcbiAgICAgIHRoaXMuX3VwZGF0ZVNlbmRCdXR0b24oKTtcbiAgICB9O1xuXG4gICAgLy8gUmVmbGVjdCBjdXJyZW50IHN0YXRlXG4gICAgdGhpcy5sYXN0R2F0ZXdheVN0YXRlID0gdGhpcy53c0NsaWVudC5zdGF0ZTtcbiAgICB0aGlzLmlzQ29ubmVjdGVkID0gdGhpcy53c0NsaWVudC5zdGF0ZSA9PT0gJ2Nvbm5lY3RlZCc7XG4gICAgdGhpcy5zdGF0dXNEb3QudG9nZ2xlQ2xhc3MoJ2Nvbm5lY3RlZCcsIHRoaXMuaXNDb25uZWN0ZWQpO1xuICAgIHRoaXMuc3RhdHVzRG90LnRpdGxlID0gYEdhdGV3YXk6ICR7dGhpcy53c0NsaWVudC5zdGF0ZX1gO1xuICAgIHRoaXMuX3VwZGF0ZVNlbmRCdXR0b24oKTtcblxuICAgIHRoaXMuX3JlbmRlck1lc3NhZ2VzKHRoaXMuY2hhdE1hbmFnZXIuZ2V0TWVzc2FnZXMoKSk7XG5cbiAgICAvLyBMb2FkIHNlc3Npb24gZHJvcGRvd24gZnJvbSBsb2NhbCB2YXVsdC1zY29wZWQga25vd24gc2Vzc2lvbnMuXG4gICAgdGhpcy5fbG9hZEtub3duU2Vzc2lvbnMoKTtcbiAgfVxuXG4gIGFzeW5jIG9uQ2xvc2UoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgdGhpcy5wbHVnaW4udW5yZWdpc3RlckNoYXRMZWFmKCk7XG4gICAgdGhpcy5jaGF0TWFuYWdlci5vblVwZGF0ZSA9IG51bGw7XG4gICAgdGhpcy5jaGF0TWFuYWdlci5vbk1lc3NhZ2VBZGRlZCA9IG51bGw7XG4gICAgdGhpcy53c0NsaWVudC5vblN0YXRlQ2hhbmdlID0gbnVsbDtcbiAgICB0aGlzLndzQ2xpZW50Lm9uV29ya2luZ0NoYW5nZSA9IG51bGw7XG4gICAgdGhpcy53c0NsaWVudC5kaXNjb25uZWN0KCk7XG5cbiAgICBpZiAodGhpcy5vbk1lc3NhZ2VzQ2xpY2spIHtcbiAgICAgIHRoaXMubWVzc2FnZXNFbD8ucmVtb3ZlRXZlbnRMaXN0ZW5lcignY2xpY2snLCB0aGlzLm9uTWVzc2FnZXNDbGljayk7XG4gICAgICB0aGlzLm9uTWVzc2FnZXNDbGljayA9IG51bGw7XG4gICAgfVxuICB9XG5cbiAgLy8gXHUyNTAwXHUyNTAwIFVJIGNvbnN0cnVjdGlvbiBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcblxuICBwcml2YXRlIF9idWlsZFVJKCk6IHZvaWQge1xuICAgIGNvbnN0IHJvb3QgPSB0aGlzLmNvbnRlbnRFbDtcbiAgICByb290LmVtcHR5KCk7XG4gICAgcm9vdC5hZGRDbGFzcygnb2NsYXctY2hhdC12aWV3Jyk7XG5cbiAgICAvLyBcdTI1MDBcdTI1MDAgSGVhZGVyIFx1MjUwMFx1MjUwMFxuICAgIGNvbnN0IGhlYWRlciA9IHJvb3QuY3JlYXRlRGl2KHsgY2xzOiAnb2NsYXctaGVhZGVyJyB9KTtcbiAgICBoZWFkZXIuY3JlYXRlU3Bhbih7IGNsczogJ29jbGF3LWhlYWRlci10aXRsZScsIHRleHQ6ICdPcGVuQ2xhdyBDaGF0JyB9KTtcbiAgICB0aGlzLnN0YXR1c0RvdCA9IGhlYWRlci5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1zdGF0dXMtZG90JyB9KTtcbiAgICB0aGlzLnN0YXR1c0RvdC50aXRsZSA9ICdHYXRld2F5OiBkaXNjb25uZWN0ZWQnO1xuXG4gICAgLy8gXHUyNTAwXHUyNTAwIFNlc3Npb24gcm93IFx1MjUwMFx1MjUwMFxuICAgIGNvbnN0IHNlc3NSb3cgPSByb290LmNyZWF0ZURpdih7IGNsczogJ29jbGF3LXNlc3Npb24tcm93JyB9KTtcbiAgICBzZXNzUm93LmNyZWF0ZVNwYW4oeyBjbHM6ICdvY2xhdy1zZXNzaW9uLWxhYmVsJywgdGV4dDogJ1Nlc3Npb24nIH0pO1xuXG4gICAgdGhpcy5zZXNzaW9uU2VsZWN0ID0gc2Vzc1Jvdy5jcmVhdGVFbCgnc2VsZWN0JywgeyBjbHM6ICdvY2xhdy1zZXNzaW9uLXNlbGVjdCcgfSk7XG4gICAgdGhpcy5zZXNzaW9uUmVmcmVzaEJ0biA9IHNlc3NSb3cuY3JlYXRlRWwoJ2J1dHRvbicsIHsgY2xzOiAnb2NsYXctc2Vzc2lvbi1idG4nLCB0ZXh0OiAnUmVsb2FkJyB9KTtcbiAgICB0aGlzLnNlc3Npb25OZXdCdG4gPSBzZXNzUm93LmNyZWF0ZUVsKCdidXR0b24nLCB7IGNsczogJ29jbGF3LXNlc3Npb24tYnRuJywgdGV4dDogJ05ld1x1MjAyNicgfSk7XG4gICAgdGhpcy5zZXNzaW9uTWFpbkJ0biA9IHNlc3NSb3cuY3JlYXRlRWwoJ2J1dHRvbicsIHsgY2xzOiAnb2NsYXctc2Vzc2lvbi1idG4nLCB0ZXh0OiAnTWFpbicgfSk7XG5cbiAgICB0aGlzLnNlc3Npb25SZWZyZXNoQnRuLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gdGhpcy5fbG9hZEtub3duU2Vzc2lvbnMoKSk7XG4gICAgdGhpcy5zZXNzaW9uTmV3QnRuLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4ge1xuICAgICAgaWYgKCF0aGlzLnBsdWdpbi5nZXRWYXVsdEhhc2goKSkge1xuICAgICAgICBuZXcgTm90aWNlKCdPcGVuQ2xhdyBDaGF0OiBOZXcgc2Vzc2lvbiBpcyB1bmF2YWlsYWJsZSAobWlzc2luZyB2YXVsdCBpZGVudGl0eSkuJyk7XG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cbiAgICAgIHZvaWQgdGhpcy5fcHJvbXB0TmV3U2Vzc2lvbigpO1xuICAgIH0pO1xuICAgIHRoaXMuc2Vzc2lvbk1haW5CdG4uYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKSA9PiB7XG4gICAgICB2b2lkIChhc3luYyAoKSA9PiB7XG4gICAgICAgIGF3YWl0IHRoaXMuX3N3aXRjaFNlc3Npb24oJ21haW4nKTtcbiAgICAgICAgdGhpcy5fbG9hZEtub3duU2Vzc2lvbnMoKTtcbiAgICAgICAgdGhpcy5zZXNzaW9uU2VsZWN0LnZhbHVlID0gJ21haW4nO1xuICAgICAgICB0aGlzLnNlc3Npb25TZWxlY3QudGl0bGUgPSAnbWFpbic7XG4gICAgICB9KSgpO1xuICAgIH0pO1xuICAgIHRoaXMuc2Vzc2lvblNlbGVjdC5hZGRFdmVudExpc3RlbmVyKCdjaGFuZ2UnLCAoKSA9PiB7XG4gICAgICBpZiAodGhpcy5zdXBwcmVzc1Nlc3Npb25TZWxlY3RDaGFuZ2UpIHJldHVybjtcbiAgICAgIGNvbnN0IG5leHQgPSB0aGlzLnNlc3Npb25TZWxlY3QudmFsdWU7XG4gICAgICBpZiAoIW5leHQpIHJldHVybjtcbiAgICAgIHZvaWQgKGFzeW5jICgpID0+IHtcbiAgICAgICAgYXdhaXQgdGhpcy5fc3dpdGNoU2Vzc2lvbihuZXh0KTtcbiAgICAgICAgdGhpcy5fbG9hZEtub3duU2Vzc2lvbnMoKTtcbiAgICAgICAgdGhpcy5zZXNzaW9uU2VsZWN0LnZhbHVlID0gbmV4dDtcbiAgICAgICAgdGhpcy5zZXNzaW9uU2VsZWN0LnRpdGxlID0gbmV4dDtcbiAgICAgIH0pKCk7XG4gICAgfSk7XG5cbiAgICAvLyBcdTI1MDBcdTI1MDAgTWVzc2FnZXMgYXJlYSBcdTI1MDBcdTI1MDBcbiAgICB0aGlzLm1lc3NhZ2VzRWwgPSByb290LmNyZWF0ZURpdih7IGNsczogJ29jbGF3LW1lc3NhZ2VzJyB9KTtcblxuICAgIC8vIERlbGVnYXRlIGludGVybmFsLWxpbmsgY2xpY2tzIChNYXJrZG93blJlbmRlcmVyIG91dHB1dCkgdG8gYSByZWxpYWJsZSBvcGVuRmlsZSBoYW5kbGVyLlxuICAgIHRoaXMuX2luc3RhbGxJbnRlcm5hbExpbmtEZWxlZ2F0aW9uKCk7XG5cbiAgICAvLyBcdTI1MDBcdTI1MDAgQ29udGV4dCByb3cgXHUyNTAwXHUyNTAwXG4gICAgY29uc3QgY3R4Um93ID0gcm9vdC5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1jb250ZXh0LXJvdycgfSk7XG4gICAgdGhpcy5pbmNsdWRlTm90ZUNoZWNrYm94ID0gY3R4Um93LmNyZWF0ZUVsKCdpbnB1dCcsIHsgdHlwZTogJ2NoZWNrYm94JyB9KTtcbiAgICB0aGlzLmluY2x1ZGVOb3RlQ2hlY2tib3guaWQgPSAnb2NsYXctaW5jbHVkZS1ub3RlJztcbiAgICB0aGlzLmluY2x1ZGVOb3RlQ2hlY2tib3guY2hlY2tlZCA9IHRoaXMucGx1Z2luLnNldHRpbmdzLmluY2x1ZGVBY3RpdmVOb3RlO1xuICAgIGNvbnN0IGN0eExhYmVsID0gY3R4Um93LmNyZWF0ZUVsKCdsYWJlbCcsIHsgdGV4dDogJ0luY2x1ZGUgYWN0aXZlIG5vdGUnIH0pO1xuICAgIGN0eExhYmVsLmh0bWxGb3IgPSAnb2NsYXctaW5jbHVkZS1ub3RlJztcblxuICAgIC8vIFx1MjUwMFx1MjUwMCBJbnB1dCByb3cgXHUyNTAwXHUyNTAwXG4gICAgY29uc3QgaW5wdXRSb3cgPSByb290LmNyZWF0ZURpdih7IGNsczogJ29jbGF3LWlucHV0LXJvdycgfSk7XG4gICAgdGhpcy5pbnB1dEVsID0gaW5wdXRSb3cuY3JlYXRlRWwoJ3RleHRhcmVhJywge1xuICAgICAgY2xzOiAnb2NsYXctaW5wdXQnLFxuICAgICAgcGxhY2Vob2xkZXI6ICdBc2sgYW55dGhpbmdcdTIwMjYnLFxuICAgIH0pO1xuICAgIHRoaXMuaW5wdXRFbC5yb3dzID0gMTtcblxuICAgIHRoaXMuc2VuZEJ0biA9IGlucHV0Um93LmNyZWF0ZUVsKCdidXR0b24nLCB7IGNsczogJ29jbGF3LXNlbmQtYnRuJywgdGV4dDogJ1NlbmQnIH0pO1xuXG4gICAgLy8gXHUyNTAwXHUyNTAwIEV2ZW50IGxpc3RlbmVycyBcdTI1MDBcdTI1MDBcbiAgICB0aGlzLnNlbmRCdG4uYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKSA9PiB0aGlzLl9oYW5kbGVTZW5kKCkpO1xuICAgIHRoaXMuaW5wdXRFbC5hZGRFdmVudExpc3RlbmVyKCdrZXlkb3duJywgKGUpID0+IHtcbiAgICAgIGlmIChlLmtleSA9PT0gJ0VudGVyJyAmJiAhZS5zaGlmdEtleSkge1xuICAgICAgICBlLnByZXZlbnREZWZhdWx0KCk7XG4gICAgICAgIHRoaXMuX2hhbmRsZVNlbmQoKTtcbiAgICAgIH1cbiAgICB9KTtcbiAgICAvLyBBdXRvLXJlc2l6ZSB0ZXh0YXJlYVxuICAgIHRoaXMuaW5wdXRFbC5hZGRFdmVudExpc3RlbmVyKCdpbnB1dCcsICgpID0+IHtcbiAgICAgIHRoaXMuaW5wdXRFbC5zdHlsZS5oZWlnaHQgPSAnYXV0byc7XG4gICAgICB0aGlzLmlucHV0RWwuc3R5bGUuaGVpZ2h0ID0gYCR7dGhpcy5pbnB1dEVsLnNjcm9sbEhlaWdodH1weGA7XG4gICAgfSk7XG4gIH1cblxuICBwcml2YXRlIF9zZXRTZXNzaW9uU2VsZWN0T3B0aW9ucyhrZXlzOiBzdHJpbmdbXSk6IHZvaWQge1xuICAgIHRoaXMuc3VwcHJlc3NTZXNzaW9uU2VsZWN0Q2hhbmdlID0gdHJ1ZTtcbiAgICB0cnkge1xuICAgICAgdGhpcy5zZXNzaW9uU2VsZWN0LmVtcHR5KCk7XG5cbiAgICAgIGNvbnN0IGN1cnJlbnQgPSAodGhpcy5wbHVnaW4uc2V0dGluZ3Muc2Vzc2lvbktleSA/PyAnbWFpbicpLnRvTG93ZXJDYXNlKCk7XG4gICAgICBsZXQgdW5pcXVlID0gQXJyYXkuZnJvbShuZXcgU2V0KFtjdXJyZW50LCAuLi5rZXlzXS5maWx0ZXIoQm9vbGVhbikpKTtcblxuICAgICAgLy8gQ2Fub25pY2FsLW9ubHk6IG1haW4gb3IgYWdlbnQ6bWFpbjpvYnNpZGlhbjpkaXJlY3Q6KlxuICAgICAgdW5pcXVlID0gdW5pcXVlLmZpbHRlcigoaykgPT4gayA9PT0gJ21haW4nIHx8IFN0cmluZyhrKS5zdGFydHNXaXRoKCdhZ2VudDptYWluOm9ic2lkaWFuOmRpcmVjdDonKSk7XG5cbiAgICAgIGlmICh1bmlxdWUubGVuZ3RoID09PSAwKSB7XG4gICAgICAgIHVuaXF1ZSA9IFsnbWFpbiddO1xuICAgICAgfVxuXG4gICAgICBmb3IgKGNvbnN0IGtleSBvZiB1bmlxdWUpIHtcbiAgICAgICAgY29uc3Qgb3B0ID0gdGhpcy5zZXNzaW9uU2VsZWN0LmNyZWF0ZUVsKCdvcHRpb24nLCB7IHZhbHVlOiBrZXksIHRleHQ6IGtleSB9KTtcbiAgICAgICAgaWYgKGtleSA9PT0gY3VycmVudCkgb3B0LnNlbGVjdGVkID0gdHJ1ZTtcbiAgICAgIH1cblxuICAgICAgaWYgKHVuaXF1ZS5pbmNsdWRlcyhjdXJyZW50KSkge1xuICAgICAgICB0aGlzLnNlc3Npb25TZWxlY3QudmFsdWUgPSBjdXJyZW50O1xuICAgICAgfVxuICAgICAgdGhpcy5zZXNzaW9uU2VsZWN0LnRpdGxlID0gY3VycmVudDtcbiAgICB9IGZpbmFsbHkge1xuICAgICAgdGhpcy5zdXBwcmVzc1Nlc3Npb25TZWxlY3RDaGFuZ2UgPSBmYWxzZTtcbiAgICB9XG4gIH1cblxuICBwcml2YXRlIF9sb2FkS25vd25TZXNzaW9ucygpOiB2b2lkIHtcbiAgICBjb25zdCB2YXVsdEhhc2ggPSAodGhpcy5wbHVnaW4uc2V0dGluZ3MudmF1bHRIYXNoID8/ICcnKS50cmltKCk7XG4gICAgY29uc3QgbWFwID0gdGhpcy5wbHVnaW4uc2V0dGluZ3Mua25vd25TZXNzaW9uS2V5c0J5VmF1bHQgPz8ge307XG4gICAgY29uc3Qga2V5cyA9IHZhdWx0SGFzaCAmJiBBcnJheS5pc0FycmF5KG1hcFt2YXVsdEhhc2hdKSA/IG1hcFt2YXVsdEhhc2hdIDogW107XG5cbiAgICBjb25zdCBwcmVmaXggPSB2YXVsdEhhc2ggPyBgYWdlbnQ6bWFpbjpvYnNpZGlhbjpkaXJlY3Q6JHt2YXVsdEhhc2h9YCA6ICcnO1xuICAgIGNvbnN0IGZpbHRlcmVkID0gdmF1bHRIYXNoXG4gICAgICA/IGtleXMuZmlsdGVyKChrKSA9PiB7XG4gICAgICAgICAgY29uc3Qga2V5ID0gU3RyaW5nKGsgfHwgJycpLnRyaW0oKS50b0xvd2VyQ2FzZSgpO1xuICAgICAgICAgIHJldHVybiBrZXkgPT09IHByZWZpeCB8fCBrZXkuc3RhcnRzV2l0aChwcmVmaXggKyAnLScpO1xuICAgICAgICB9KVxuICAgICAgOiBbXTtcblxuICAgIHRoaXMuX3NldFNlc3Npb25TZWxlY3RPcHRpb25zKGZpbHRlcmVkKTtcbiAgfVxuXG4gIHByaXZhdGUgYXN5bmMgX3N3aXRjaFNlc3Npb24oc2Vzc2lvbktleTogc3RyaW5nKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgY29uc3QgbmV4dCA9IHNlc3Npb25LZXkudHJpbSgpLnRvTG93ZXJDYXNlKCk7XG4gICAgaWYgKCFuZXh0KSByZXR1cm47XG5cbiAgICBjb25zdCB2YXVsdEhhc2ggPSB0aGlzLnBsdWdpbi5nZXRWYXVsdEhhc2goKTtcbiAgICBpZiAodmF1bHRIYXNoKSB7XG4gICAgICBjb25zdCBwcmVmaXggPSBgYWdlbnQ6bWFpbjpvYnNpZGlhbjpkaXJlY3Q6JHt2YXVsdEhhc2h9YDtcbiAgICAgIGlmICghKG5leHQgPT09ICdtYWluJyB8fCBuZXh0ID09PSBwcmVmaXggfHwgbmV4dC5zdGFydHNXaXRoKHByZWZpeCArICctJykpKSB7XG4gICAgICAgIG5ldyBOb3RpY2UoJ09wZW5DbGF3IENoYXQ6IHNlc3Npb24ga2V5IG11c3QgbWF0Y2ggdGhpcyB2YXVsdC4nKTtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuICAgIH0gZWxzZSB7XG4gICAgICBpZiAobmV4dCAhPT0gJ21haW4nKSB7XG4gICAgICAgIG5ldyBOb3RpY2UoJ09wZW5DbGF3IENoYXQ6IGNhbm5vdCBzd2l0Y2ggc2Vzc2lvbnMgKG1pc3NpbmcgdmF1bHQgaWRlbnRpdHkpLicpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG4gICAgfVxuXG4gICAgLy8gQWJvcnQgYW55IGluLWZsaWdodCBydW4gYmVzdC1lZmZvcnQuXG4gICAgdHJ5IHtcbiAgICAgIGF3YWl0IHRoaXMud3NDbGllbnQuYWJvcnRBY3RpdmVSdW4oKTtcbiAgICB9IGNhdGNoIHtcbiAgICAgIC8vIGlnbm9yZVxuICAgIH1cblxuICAgIC8vIERpdmlkZXIgaW4gdGhpcyBsZWFmIG9ubHkuXG4gICAgdGhpcy5jaGF0TWFuYWdlci5hZGRNZXNzYWdlKENoYXRNYW5hZ2VyLmNyZWF0ZVNlc3Npb25EaXZpZGVyKG5leHQpKTtcblxuICAgIC8vIFBlcnNpc3QgYXMgdGhlIGRlZmF1bHQgYW5kIHJlbWVtYmVyIGl0IGluIHRoZSB2YXVsdC1zY29wZWQgbGlzdC5cbiAgICBhd2FpdCB0aGlzLnBsdWdpbi5yZW1lbWJlclNlc3Npb25LZXkobmV4dCk7XG5cbiAgICAvLyBTd2l0Y2ggV1Mgcm91dGluZyBmb3IgdGhpcyBsZWFmLlxuICAgIHRoaXMud3NDbGllbnQuZGlzY29ubmVjdCgpO1xuICAgIHRoaXMud3NDbGllbnQuc2V0U2Vzc2lvbktleShuZXh0KTtcblxuICAgIGNvbnN0IGd3ID0gdGhpcy5wbHVnaW4uZ2V0R2F0ZXdheUNvbmZpZygpO1xuICAgIGlmIChndy50b2tlbikge1xuICAgICAgdGhpcy53c0NsaWVudC5jb25uZWN0KGd3LnVybCwgZ3cudG9rZW4sIHsgYWxsb3dJbnNlY3VyZVdzOiBndy5hbGxvd0luc2VjdXJlV3MgfSk7XG4gICAgfSBlbHNlIHtcbiAgICAgIG5ldyBOb3RpY2UoJ09wZW5DbGF3IENoYXQ6IHBsZWFzZSBjb25maWd1cmUgeW91ciBnYXRld2F5IHRva2VuIGluIFNldHRpbmdzLicpO1xuICAgIH1cbiAgfVxuXG4gIHByaXZhdGUgYXN5bmMgX3Byb21wdE5ld1Nlc3Npb24oKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgY29uc3Qgbm93ID0gbmV3IERhdGUoKTtcbiAgICBjb25zdCBwYWQgPSAobjogbnVtYmVyKSA9PiBTdHJpbmcobikucGFkU3RhcnQoMiwgJzAnKTtcbiAgICBjb25zdCBzdWdnZXN0ZWQgPSBgY2hhdC0ke25vdy5nZXRGdWxsWWVhcigpfSR7cGFkKG5vdy5nZXRNb250aCgpICsgMSl9JHtwYWQobm93LmdldERhdGUoKSl9LSR7cGFkKG5vdy5nZXRIb3VycygpKX0ke3BhZChub3cuZ2V0TWludXRlcygpKX1gO1xuXG4gICAgY29uc3QgbW9kYWwgPSBuZXcgTmV3U2Vzc2lvbk1vZGFsKHRoaXMsIHN1Z2dlc3RlZCwgKHN1ZmZpeCkgPT4ge1xuICAgICAgY29uc3QgdmF1bHRIYXNoID0gKHRoaXMucGx1Z2luLnNldHRpbmdzLnZhdWx0SGFzaCA/PyAnJykudHJpbSgpO1xuICAgICAgaWYgKCF2YXVsdEhhc2gpIHtcbiAgICAgICAgbmV3IE5vdGljZSgnT3BlbkNsYXcgQ2hhdDogY2Fubm90IGNyZWF0ZSBzZXNzaW9uIChtaXNzaW5nIHZhdWx0IGlkZW50aXR5KS4nKTtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuICAgICAgY29uc3Qga2V5ID0gYGFnZW50Om1haW46b2JzaWRpYW46ZGlyZWN0OiR7dmF1bHRIYXNofS0ke3N1ZmZpeH1gO1xuICAgICAgdm9pZCAoYXN5bmMgKCkgPT4ge1xuICAgICAgICBhd2FpdCB0aGlzLl9zd2l0Y2hTZXNzaW9uKGtleSk7XG4gICAgICAgIHRoaXMuX2xvYWRLbm93blNlc3Npb25zKCk7XG4gICAgICAgIHRoaXMuc2Vzc2lvblNlbGVjdC52YWx1ZSA9IGtleTtcbiAgICAgICAgdGhpcy5zZXNzaW9uU2VsZWN0LnRpdGxlID0ga2V5O1xuICAgICAgfSkoKTtcbiAgICB9KTtcbiAgICBtb2RhbC5vcGVuKCk7XG4gIH1cblxuICAvLyBcdTI1MDBcdTI1MDAgTWVzc2FnZSByZW5kZXJpbmcgXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG5cbiAgcHJpdmF0ZSBfcmVuZGVyTWVzc2FnZXMobWVzc2FnZXM6IHJlYWRvbmx5IENoYXRNZXNzYWdlW10pOiB2b2lkIHtcbiAgICB0aGlzLm1lc3NhZ2VzRWwuZW1wdHkoKTtcblxuICAgIGlmIChtZXNzYWdlcy5sZW5ndGggPT09IDApIHtcbiAgICAgIHRoaXMubWVzc2FnZXNFbC5jcmVhdGVFbCgncCcsIHtcbiAgICAgICAgdGV4dDogJ1NlbmQgYSBtZXNzYWdlIHRvIHN0YXJ0IGNoYXR0aW5nLicsXG4gICAgICAgIGNsczogJ29jbGF3LW1lc3NhZ2Ugc3lzdGVtIG9jbGF3LXBsYWNlaG9sZGVyJyxcbiAgICAgIH0pO1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIGZvciAoY29uc3QgbXNnIG9mIG1lc3NhZ2VzKSB7XG4gICAgICB0aGlzLl9hcHBlbmRNZXNzYWdlKG1zZyk7XG4gICAgfVxuXG4gICAgLy8gU2Nyb2xsIHRvIGJvdHRvbVxuICAgIHRoaXMubWVzc2FnZXNFbC5zY3JvbGxUb3AgPSB0aGlzLm1lc3NhZ2VzRWwuc2Nyb2xsSGVpZ2h0O1xuICB9XG5cbiAgLyoqIEFwcGVuZHMgYSBzaW5nbGUgbWVzc2FnZSB3aXRob3V0IHJlYnVpbGRpbmcgdGhlIERPTSAoTygxKSkgKi9cbiAgcHJpdmF0ZSBfYXBwZW5kTWVzc2FnZShtc2c6IENoYXRNZXNzYWdlKTogdm9pZCB7XG4gICAgLy8gUmVtb3ZlIGVtcHR5LXN0YXRlIHBsYWNlaG9sZGVyIGlmIHByZXNlbnRcbiAgICB0aGlzLm1lc3NhZ2VzRWwucXVlcnlTZWxlY3RvcignLm9jbGF3LXBsYWNlaG9sZGVyJyk/LnJlbW92ZSgpO1xuXG4gICAgY29uc3QgbGV2ZWxDbGFzcyA9IG1zZy5sZXZlbCA/IGAgJHttc2cubGV2ZWx9YCA6ICcnO1xuICAgIGNvbnN0IGtpbmRDbGFzcyA9IG1zZy5raW5kID8gYCBvY2xhdy0ke21zZy5raW5kfWAgOiAnJztcbiAgICBjb25zdCBlbCA9IHRoaXMubWVzc2FnZXNFbC5jcmVhdGVEaXYoeyBjbHM6IGBvY2xhdy1tZXNzYWdlICR7bXNnLnJvbGV9JHtsZXZlbENsYXNzfSR7a2luZENsYXNzfWAgfSk7XG4gICAgY29uc3QgYm9keSA9IGVsLmNyZWF0ZURpdih7IGNsczogJ29jbGF3LW1lc3NhZ2UtYm9keScgfSk7XG4gICAgaWYgKG1zZy50aXRsZSkge1xuICAgICAgYm9keS50aXRsZSA9IG1zZy50aXRsZTtcbiAgICB9XG5cbiAgICAvLyBUcmVhdCBhc3Npc3RhbnQgb3V0cHV0IGFzIFVOVFJVU1RFRCBieSBkZWZhdWx0LlxuICAgIC8vIFJlbmRlcmluZyBhcyBPYnNpZGlhbiBNYXJrZG93biBjYW4gdHJpZ2dlciBlbWJlZHMgYW5kIG90aGVyIHBsdWdpbnMnIHBvc3QtcHJvY2Vzc29ycy5cbiAgICBpZiAobXNnLnJvbGUgPT09ICdhc3Npc3RhbnQnKSB7XG4gICAgICBjb25zdCBtYXBwaW5nczogUGF0aE1hcHBpbmdbXSA9IHRoaXMucGx1Z2luLnNldHRpbmdzLnBhdGhNYXBwaW5ncyA/PyBbXTtcbiAgICAgIGNvbnN0IHNvdXJjZVBhdGggPSB0aGlzLmFwcC53b3Jrc3BhY2UuZ2V0QWN0aXZlRmlsZSgpPy5wYXRoID8/ICcnO1xuXG4gICAgICBpZiAodGhpcy5wbHVnaW4uc2V0dGluZ3MucmVuZGVyQXNzaXN0YW50TWFya2Rvd24pIHtcbiAgICAgICAgLy8gQmVzdC1lZmZvcnQgcHJlLXByb2Nlc3Npbmc6IHJlcGxhY2Uga25vd24gcmVtb3RlIHBhdGhzIHdpdGggd2lraWxpbmtzIHdoZW4gdGhlIHRhcmdldCBleGlzdHMuXG4gICAgICAgIGNvbnN0IHByZSA9IHRoaXMuX3ByZXByb2Nlc3NBc3Npc3RhbnRNYXJrZG93bihtc2cuY29udGVudCwgbWFwcGluZ3MpO1xuICAgICAgICB2b2lkIE1hcmtkb3duUmVuZGVyZXIucmVuZGVyTWFya2Rvd24ocHJlLCBib2R5LCBzb3VyY2VQYXRoLCB0aGlzLnBsdWdpbik7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICAvLyBQbGFpbiBtb2RlOiBidWlsZCBzYWZlLCBjbGlja2FibGUgbGlua3MgaW4gRE9NIChubyBNYXJrZG93biByZW5kZXJpbmcpLlxuICAgICAgICB0aGlzLl9yZW5kZXJBc3Npc3RhbnRQbGFpbldpdGhMaW5rcyhib2R5LCBtc2cuY29udGVudCwgbWFwcGluZ3MsIHNvdXJjZVBhdGgpO1xuICAgICAgfVxuICAgIH0gZWxzZSB7XG4gICAgICBib2R5LnNldFRleHQobXNnLmNvbnRlbnQpO1xuICAgIH1cblxuICAgIC8vIFNjcm9sbCB0byBib3R0b21cbiAgICB0aGlzLm1lc3NhZ2VzRWwuc2Nyb2xsVG9wID0gdGhpcy5tZXNzYWdlc0VsLnNjcm9sbEhlaWdodDtcbiAgfVxuXG4gIHByaXZhdGUgX3RyeVJldmVyc2VNYXBVcmxUb1ZhdWx0UGF0aCh1cmw6IHN0cmluZywgbWFwcGluZ3M6IFBhdGhNYXBwaW5nW10pOiBzdHJpbmcgfCBudWxsIHtcbiAgICAvLyBGUy1iYXNlZCBtYXBwaW5nOyBiZXN0LWVmZm9ydCBvbmx5LlxuICAgIGxldCBkZWNvZGVkID0gdXJsO1xuICAgIHRyeSB7XG4gICAgICBkZWNvZGVkID0gZGVjb2RlVVJJQ29tcG9uZW50KHVybCk7XG4gICAgfSBjYXRjaCB7XG4gICAgICAvLyBpZ25vcmVcbiAgICB9XG5cbiAgICAvLyBJZiB0aGUgZGVjb2RlZCBVUkwgY29udGFpbnMgYSByZW1vdGVCYXNlIHN1YnN0cmluZywgdHJ5IG1hcHBpbmcgZnJvbSB0aGF0IHBvaW50LlxuICAgIGZvciAoY29uc3Qgcm93IG9mIG1hcHBpbmdzKSB7XG4gICAgICBjb25zdCByZW1vdGVCYXNlID0gU3RyaW5nKHJvdy5yZW1vdGVCYXNlID8/ICcnKTtcbiAgICAgIGlmICghcmVtb3RlQmFzZSkgY29udGludWU7XG4gICAgICBjb25zdCBpZHggPSBkZWNvZGVkLmluZGV4T2YocmVtb3RlQmFzZSk7XG4gICAgICBpZiAoaWR4IDwgMCkgY29udGludWU7XG5cbiAgICAgIC8vIEV4dHJhY3QgZnJvbSByZW1vdGVCYXNlIG9ud2FyZCB1bnRpbCBhIHRlcm1pbmF0b3IuXG4gICAgICBjb25zdCB0YWlsID0gZGVjb2RlZC5zbGljZShpZHgpO1xuICAgICAgY29uc3QgdG9rZW4gPSB0YWlsLnNwbGl0KC9bXFxzJ1wiPD4pXS8pWzBdO1xuICAgICAgY29uc3QgbWFwcGVkID0gdHJ5TWFwUmVtb3RlUGF0aFRvVmF1bHRQYXRoKHRva2VuLCBtYXBwaW5ncyk7XG4gICAgICBpZiAobWFwcGVkICYmIHRoaXMuYXBwLnZhdWx0LmdldEFic3RyYWN0RmlsZUJ5UGF0aChtYXBwZWQpKSByZXR1cm4gbWFwcGVkO1xuICAgIH1cblxuICAgIHJldHVybiBudWxsO1xuICB9XG5cbiAgcHJpdmF0ZSBfaW5zdGFsbEludGVybmFsTGlua0RlbGVnYXRpb24oKTogdm9pZCB7XG4gICAgaWYgKHRoaXMub25NZXNzYWdlc0NsaWNrKSByZXR1cm47XG5cbiAgICB0aGlzLm9uTWVzc2FnZXNDbGljayA9IChldjogTW91c2VFdmVudCkgPT4ge1xuICAgICAgY29uc3QgdGFyZ2V0ID0gZXYudGFyZ2V0IGFzIEhUTUxFbGVtZW50IHwgbnVsbDtcbiAgICAgIGNvbnN0IGEgPSB0YXJnZXQ/LmNsb3Nlc3Q/LignYS5pbnRlcm5hbC1saW5rJykgYXMgSFRNTEFuY2hvckVsZW1lbnQgfCBudWxsO1xuICAgICAgaWYgKCFhKSByZXR1cm47XG5cbiAgICAgIGNvbnN0IGRhdGFIcmVmID0gYS5nZXRBdHRyaWJ1dGUoJ2RhdGEtaHJlZicpIHx8ICcnO1xuICAgICAgY29uc3QgaHJlZkF0dHIgPSBhLmdldEF0dHJpYnV0ZSgnaHJlZicpIHx8ICcnO1xuXG4gICAgICBjb25zdCByYXcgPSAoZGF0YUhyZWYgfHwgaHJlZkF0dHIpLnRyaW0oKTtcbiAgICAgIGlmICghcmF3KSByZXR1cm47XG5cbiAgICAgIC8vIElmIGl0IGlzIGFuIGFic29sdXRlIFVSTCwgbGV0IHRoZSBkZWZhdWx0IGJlaGF2aW9yIGhhbmRsZSBpdC5cbiAgICAgIGlmICgvXmh0dHBzPzpcXC9cXC8vaS50ZXN0KHJhdykpIHJldHVybjtcblxuICAgICAgLy8gT2JzaWRpYW4gaW50ZXJuYWwtbGluayBvZnRlbiB1c2VzIHZhdWx0LXJlbGF0aXZlIHBhdGguXG4gICAgICBjb25zdCB2YXVsdFBhdGggPSByYXcucmVwbGFjZSgvXlxcLysvLCAnJyk7XG4gICAgICBjb25zdCBmID0gdGhpcy5hcHAudmF1bHQuZ2V0QWJzdHJhY3RGaWxlQnlQYXRoKHZhdWx0UGF0aCk7XG4gICAgICBpZiAoIShmIGluc3RhbmNlb2YgVEZpbGUpKSByZXR1cm47XG5cbiAgICAgIGV2LnByZXZlbnREZWZhdWx0KCk7XG4gICAgICBldi5zdG9wUHJvcGFnYXRpb24oKTtcbiAgICAgIHZvaWQgdGhpcy5hcHAud29ya3NwYWNlLmdldExlYWYodHJ1ZSkub3BlbkZpbGUoZik7XG4gICAgfTtcblxuICAgIHRoaXMubWVzc2FnZXNFbC5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsIHRoaXMub25NZXNzYWdlc0NsaWNrKTtcbiAgfVxuXG4gIHByaXZhdGUgX3RyeU1hcFZhdWx0UmVsYXRpdmVUb2tlbih0b2tlbjogc3RyaW5nLCBtYXBwaW5nczogUGF0aE1hcHBpbmdbXSk6IHN0cmluZyB8IG51bGwge1xuICAgIGNvbnN0IHQgPSB0b2tlbi5yZXBsYWNlKC9eXFwvKy8sICcnKTtcbiAgICBpZiAodGhpcy5hcHAudmF1bHQuZ2V0QWJzdHJhY3RGaWxlQnlQYXRoKHQpKSByZXR1cm4gdDtcblxuICAgIC8vIEhldXJpc3RpYzogaWYgdmF1bHRCYXNlIGVuZHMgd2l0aCBhIHNlZ21lbnQgKGUuZy4gd29ya3NwYWNlL2NvbXBlbmcvKSBhbmQgdG9rZW4gc3RhcnRzIHdpdGggdGhhdCBzZWdtZW50IChjb21wZW5nLy4uLiksXG4gICAgLy8gbWFwIHRva2VuIHVuZGVyIHZhdWx0QmFzZS5cbiAgICBmb3IgKGNvbnN0IHJvdyBvZiBtYXBwaW5ncykge1xuICAgICAgY29uc3QgdmF1bHRCYXNlUmF3ID0gU3RyaW5nKHJvdy52YXVsdEJhc2UgPz8gJycpLnRyaW0oKTtcbiAgICAgIGlmICghdmF1bHRCYXNlUmF3KSBjb250aW51ZTtcbiAgICAgIGNvbnN0IHZhdWx0QmFzZSA9IHZhdWx0QmFzZVJhdy5lbmRzV2l0aCgnLycpID8gdmF1bHRCYXNlUmF3IDogYCR7dmF1bHRCYXNlUmF3fS9gO1xuXG4gICAgICBjb25zdCBwYXJ0cyA9IHZhdWx0QmFzZS5yZXBsYWNlKC9cXC8rJC8sICcnKS5zcGxpdCgnLycpO1xuICAgICAgY29uc3QgYmFzZU5hbWUgPSBwYXJ0c1twYXJ0cy5sZW5ndGggLSAxXTtcbiAgICAgIGlmICghYmFzZU5hbWUpIGNvbnRpbnVlO1xuXG4gICAgICBjb25zdCBwcmVmaXggPSBgJHtiYXNlTmFtZX0vYDtcbiAgICAgIGlmICghdC5zdGFydHNXaXRoKHByZWZpeCkpIGNvbnRpbnVlO1xuXG4gICAgICBjb25zdCBjYW5kaWRhdGUgPSBgJHt2YXVsdEJhc2V9JHt0LnNsaWNlKHByZWZpeC5sZW5ndGgpfWA7XG4gICAgICBjb25zdCBub3JtYWxpemVkID0gY2FuZGlkYXRlLnJlcGxhY2UoL15cXC8rLywgJycpO1xuICAgICAgaWYgKHRoaXMuYXBwLnZhdWx0LmdldEFic3RyYWN0RmlsZUJ5UGF0aChub3JtYWxpemVkKSkgcmV0dXJuIG5vcm1hbGl6ZWQ7XG4gICAgfVxuXG4gICAgcmV0dXJuIG51bGw7XG4gIH1cblxuICBwcml2YXRlIF9wcmVwcm9jZXNzQXNzaXN0YW50TWFya2Rvd24odGV4dDogc3RyaW5nLCBtYXBwaW5nczogUGF0aE1hcHBpbmdbXSk6IHN0cmluZyB7XG4gICAgY29uc3QgY2FuZGlkYXRlcyA9IGV4dHJhY3RDYW5kaWRhdGVzKHRleHQpO1xuICAgIGlmIChjYW5kaWRhdGVzLmxlbmd0aCA9PT0gMCkgcmV0dXJuIHRleHQ7XG5cbiAgICBsZXQgb3V0ID0gJyc7XG4gICAgbGV0IGN1cnNvciA9IDA7XG5cbiAgICBmb3IgKGNvbnN0IGMgb2YgY2FuZGlkYXRlcykge1xuICAgICAgb3V0ICs9IHRleHQuc2xpY2UoY3Vyc29yLCBjLnN0YXJ0KTtcbiAgICAgIGN1cnNvciA9IGMuZW5kO1xuXG4gICAgICBpZiAoYy5raW5kID09PSAndXJsJykge1xuICAgICAgICAvLyBVUkxzIHJlbWFpbiBVUkxzIFVOTEVTUyB3ZSBjYW4gc2FmZWx5IG1hcCB0byBhbiBleGlzdGluZyB2YXVsdCBmaWxlLlxuICAgICAgICBjb25zdCBtYXBwZWQgPSB0aGlzLl90cnlSZXZlcnNlTWFwVXJsVG9WYXVsdFBhdGgoYy5yYXcsIG1hcHBpbmdzKTtcbiAgICAgICAgb3V0ICs9IG1hcHBlZCA/IGBbWyR7bWFwcGVkfV1dYCA6IGMucmF3O1xuICAgICAgICBjb250aW51ZTtcbiAgICAgIH1cblxuICAgICAgLy8gMSkgSWYgdGhlIHRva2VuIGlzIGFscmVhZHkgYSB2YXVsdC1yZWxhdGl2ZSBwYXRoIChvciBjYW4gYmUgcmVzb2x2ZWQgdmlhIHZhdWx0QmFzZSBoZXVyaXN0aWMpLCBsaW5raWZ5IGl0IGRpcmVjdGx5LlxuICAgICAgY29uc3QgZGlyZWN0ID0gdGhpcy5fdHJ5TWFwVmF1bHRSZWxhdGl2ZVRva2VuKGMucmF3LCBtYXBwaW5ncyk7XG4gICAgICBpZiAoZGlyZWN0KSB7XG4gICAgICAgIG91dCArPSBgW1ske2RpcmVjdH1dXWA7XG4gICAgICAgIGNvbnRpbnVlO1xuICAgICAgfVxuXG4gICAgICAvLyAyKSBFbHNlOiB0cnkgcmVtb3RlXHUyMTkydmF1bHQgbWFwcGluZy5cbiAgICAgIGNvbnN0IG1hcHBlZCA9IHRyeU1hcFJlbW90ZVBhdGhUb1ZhdWx0UGF0aChjLnJhdywgbWFwcGluZ3MpO1xuICAgICAgaWYgKCFtYXBwZWQpIHtcbiAgICAgICAgb3V0ICs9IGMucmF3O1xuICAgICAgICBjb250aW51ZTtcbiAgICAgIH1cblxuICAgICAgaWYgKCF0aGlzLmFwcC52YXVsdC5nZXRBYnN0cmFjdEZpbGVCeVBhdGgobWFwcGVkKSkge1xuICAgICAgICBvdXQgKz0gYy5yYXc7XG4gICAgICAgIGNvbnRpbnVlO1xuICAgICAgfVxuXG4gICAgICBvdXQgKz0gYFtbJHttYXBwZWR9XV1gO1xuICAgIH1cblxuICAgIG91dCArPSB0ZXh0LnNsaWNlKGN1cnNvcik7XG4gICAgcmV0dXJuIG91dDtcbiAgfVxuXG4gIHByaXZhdGUgX3JlbmRlckFzc2lzdGFudFBsYWluV2l0aExpbmtzKFxuICAgIGJvZHk6IEhUTUxFbGVtZW50LFxuICAgIHRleHQ6IHN0cmluZyxcbiAgICBtYXBwaW5nczogUGF0aE1hcHBpbmdbXSxcbiAgICBzb3VyY2VQYXRoOiBzdHJpbmcsXG4gICk6IHZvaWQge1xuICAgIGNvbnN0IGNhbmRpZGF0ZXMgPSBleHRyYWN0Q2FuZGlkYXRlcyh0ZXh0KTtcbiAgICBpZiAoY2FuZGlkYXRlcy5sZW5ndGggPT09IDApIHtcbiAgICAgIGJvZHkuc2V0VGV4dCh0ZXh0KTtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICBsZXQgY3Vyc29yID0gMDtcblxuICAgIGNvbnN0IGFwcGVuZFRleHQgPSAoczogc3RyaW5nKSA9PiB7XG4gICAgICBpZiAoIXMpIHJldHVybjtcbiAgICAgIGJvZHkuYXBwZW5kQ2hpbGQoZG9jdW1lbnQuY3JlYXRlVGV4dE5vZGUocykpO1xuICAgIH07XG5cbiAgICBjb25zdCBhcHBlbmRPYnNpZGlhbkxpbmsgPSAodmF1bHRQYXRoOiBzdHJpbmcpID0+IHtcbiAgICAgIGNvbnN0IGRpc3BsYXkgPSBgW1ske3ZhdWx0UGF0aH1dXWA7XG4gICAgICBjb25zdCBhID0gYm9keS5jcmVhdGVFbCgnYScsIHsgdGV4dDogZGlzcGxheSwgaHJlZjogJyMnIH0pO1xuICAgICAgYS5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsIChldikgPT4ge1xuICAgICAgICBldi5wcmV2ZW50RGVmYXVsdCgpO1xuICAgICAgICBldi5zdG9wUHJvcGFnYXRpb24oKTtcblxuICAgICAgICBjb25zdCBmID0gdGhpcy5hcHAudmF1bHQuZ2V0QWJzdHJhY3RGaWxlQnlQYXRoKHZhdWx0UGF0aCk7XG4gICAgICAgIGlmIChmIGluc3RhbmNlb2YgVEZpbGUpIHtcbiAgICAgICAgICB2b2lkIHRoaXMuYXBwLndvcmtzcGFjZS5nZXRMZWFmKHRydWUpLm9wZW5GaWxlKGYpO1xuICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIC8vIEZhbGxiYWNrOiBiZXN0LWVmZm9ydCBsaW5rdGV4dCBvcGVuLlxuICAgICAgICB2b2lkIHRoaXMuYXBwLndvcmtzcGFjZS5vcGVuTGlua1RleHQodmF1bHRQYXRoLCBzb3VyY2VQYXRoLCB0cnVlKTtcbiAgICAgIH0pO1xuICAgIH07XG5cbiAgICBjb25zdCBhcHBlbmRFeHRlcm5hbFVybCA9ICh1cmw6IHN0cmluZykgPT4ge1xuICAgICAgLy8gTGV0IE9ic2lkaWFuL0VsZWN0cm9uIGhhbmRsZSBleHRlcm5hbCBvcGVuLlxuICAgICAgYm9keS5jcmVhdGVFbCgnYScsIHsgdGV4dDogdXJsLCBocmVmOiB1cmwgfSk7XG4gICAgfTtcblxuICAgIGNvbnN0IHRyeVJldmVyc2VNYXBVcmxUb1ZhdWx0UGF0aCA9ICh1cmw6IHN0cmluZyk6IHN0cmluZyB8IG51bGwgPT4gdGhpcy5fdHJ5UmV2ZXJzZU1hcFVybFRvVmF1bHRQYXRoKHVybCwgbWFwcGluZ3MpO1xuXG4gICAgZm9yIChjb25zdCBjIG9mIGNhbmRpZGF0ZXMpIHtcbiAgICAgIGFwcGVuZFRleHQodGV4dC5zbGljZShjdXJzb3IsIGMuc3RhcnQpKTtcbiAgICAgIGN1cnNvciA9IGMuZW5kO1xuXG4gICAgICBpZiAoYy5raW5kID09PSAndXJsJykge1xuICAgICAgICBjb25zdCBtYXBwZWQgPSB0cnlSZXZlcnNlTWFwVXJsVG9WYXVsdFBhdGgoYy5yYXcpO1xuICAgICAgICBpZiAobWFwcGVkKSB7XG4gICAgICAgICAgYXBwZW5kT2JzaWRpYW5MaW5rKG1hcHBlZCk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgYXBwZW5kRXh0ZXJuYWxVcmwoYy5yYXcpO1xuICAgICAgICB9XG4gICAgICAgIGNvbnRpbnVlO1xuICAgICAgfVxuXG4gICAgICAvLyAxKSBJZiB0b2tlbiBpcyBhbHJlYWR5IGEgdmF1bHQtcmVsYXRpdmUgcGF0aCAob3IgY2FuIGJlIHJlc29sdmVkIHZpYSB2YXVsdEJhc2UgaGV1cmlzdGljKSwgbGlua2lmeSBkaXJlY3RseS5cbiAgICAgIGNvbnN0IGRpcmVjdCA9IHRoaXMuX3RyeU1hcFZhdWx0UmVsYXRpdmVUb2tlbihjLnJhdywgbWFwcGluZ3MpO1xuICAgICAgaWYgKGRpcmVjdCkge1xuICAgICAgICBhcHBlbmRPYnNpZGlhbkxpbmsoZGlyZWN0KTtcbiAgICAgICAgY29udGludWU7XG4gICAgICB9XG5cbiAgICAgIC8vIDIpIEVsc2U6IHRyeSByZW1vdGVcdTIxOTJ2YXVsdCBtYXBwaW5nLlxuICAgICAgY29uc3QgbWFwcGVkID0gdHJ5TWFwUmVtb3RlUGF0aFRvVmF1bHRQYXRoKGMucmF3LCBtYXBwaW5ncyk7XG4gICAgICBpZiAoIW1hcHBlZCkge1xuICAgICAgICBhcHBlbmRUZXh0KGMucmF3KTtcbiAgICAgICAgY29udGludWU7XG4gICAgICB9XG5cbiAgICAgIGlmICghdGhpcy5hcHAudmF1bHQuZ2V0QWJzdHJhY3RGaWxlQnlQYXRoKG1hcHBlZCkpIHtcbiAgICAgICAgYXBwZW5kVGV4dChjLnJhdyk7XG4gICAgICAgIGNvbnRpbnVlO1xuICAgICAgfVxuXG4gICAgICBhcHBlbmRPYnNpZGlhbkxpbmsobWFwcGVkKTtcbiAgICB9XG5cbiAgICBhcHBlbmRUZXh0KHRleHQuc2xpY2UoY3Vyc29yKSk7XG4gIH1cblxuICBwcml2YXRlIF91cGRhdGVTZW5kQnV0dG9uKCk6IHZvaWQge1xuICAgIC8vIERpc2Nvbm5lY3RlZDogZGlzYWJsZS5cbiAgICAvLyBXb3JraW5nOiBrZWVwIGVuYWJsZWQgc28gdXNlciBjYW4gc3RvcC9hYm9ydC5cbiAgICBjb25zdCBkaXNhYmxlZCA9ICF0aGlzLmlzQ29ubmVjdGVkO1xuICAgIHRoaXMuc2VuZEJ0bi5kaXNhYmxlZCA9IGRpc2FibGVkO1xuXG4gICAgdGhpcy5zZW5kQnRuLnRvZ2dsZUNsYXNzKCdpcy13b3JraW5nJywgdGhpcy5pc1dvcmtpbmcpO1xuICAgIHRoaXMuc2VuZEJ0bi5zZXRBdHRyKCdhcmlhLWJ1c3knLCB0aGlzLmlzV29ya2luZyA/ICd0cnVlJyA6ICdmYWxzZScpO1xuICAgIHRoaXMuc2VuZEJ0bi5zZXRBdHRyKCdhcmlhLWxhYmVsJywgdGhpcy5pc1dvcmtpbmcgPyAnU3RvcCcgOiAnU2VuZCcpO1xuXG4gICAgaWYgKHRoaXMuaXNXb3JraW5nKSB7XG4gICAgICAvLyBSZXBsYWNlIGJ1dHRvbiBjb250ZW50cyB3aXRoIFN0b3AgaWNvbiArIHNwaW5uZXIgcmluZy5cbiAgICAgIHRoaXMuc2VuZEJ0bi5lbXB0eSgpO1xuICAgICAgY29uc3Qgd3JhcCA9IHRoaXMuc2VuZEJ0bi5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1zdG9wLXdyYXAnIH0pO1xuICAgICAgd3JhcC5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1zcGlubmVyLXJpbmcnLCBhdHRyOiB7ICdhcmlhLWhpZGRlbic6ICd0cnVlJyB9IH0pO1xuICAgICAgd3JhcC5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1zdG9wLWljb24nLCBhdHRyOiB7ICdhcmlhLWhpZGRlbic6ICd0cnVlJyB9IH0pO1xuICAgIH0gZWxzZSB7XG4gICAgICAvLyBSZXN0b3JlIGxhYmVsXG4gICAgICB0aGlzLnNlbmRCdG4uc2V0VGV4dCgnU2VuZCcpO1xuICAgIH1cbiAgfVxuXG4gIC8vIFx1MjUwMFx1MjUwMCBTZW5kIGhhbmRsZXIgXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG5cbiAgcHJpdmF0ZSBhc3luYyBfaGFuZGxlU2VuZCgpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICAvLyBXaGlsZSB3b3JraW5nLCB0aGUgYnV0dG9uIGJlY29tZXMgU3RvcC5cbiAgICBpZiAodGhpcy5pc1dvcmtpbmcpIHtcbiAgICAgIGNvbnN0IG9rID0gYXdhaXQgdGhpcy53c0NsaWVudC5hYm9ydEFjdGl2ZVJ1bigpO1xuICAgICAgaWYgKCFvaykge1xuICAgICAgICBuZXcgTm90aWNlKCdPcGVuQ2xhdyBDaGF0OiBmYWlsZWQgdG8gc3RvcCcpO1xuICAgICAgICB0aGlzLmNoYXRNYW5hZ2VyLmFkZE1lc3NhZ2UoQ2hhdE1hbmFnZXIuY3JlYXRlU3lzdGVtTWVzc2FnZSgnXHUyNkEwIFN0b3AgZmFpbGVkJywgJ2Vycm9yJykpO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgdGhpcy5jaGF0TWFuYWdlci5hZGRNZXNzYWdlKENoYXRNYW5hZ2VyLmNyZWF0ZVN5c3RlbU1lc3NhZ2UoJ1x1MjZENCBTdG9wcGVkJywgJ2luZm8nKSk7XG4gICAgICB9XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgY29uc3QgdGV4dCA9IHRoaXMuaW5wdXRFbC52YWx1ZS50cmltKCk7XG4gICAgaWYgKCF0ZXh0KSByZXR1cm47XG5cbiAgICAvLyBCdWlsZCBtZXNzYWdlIHdpdGggY29udGV4dCBpZiBlbmFibGVkXG4gICAgbGV0IG1lc3NhZ2UgPSB0ZXh0O1xuICAgIGlmICh0aGlzLmluY2x1ZGVOb3RlQ2hlY2tib3guY2hlY2tlZCkge1xuICAgICAgY29uc3Qgbm90ZSA9IGF3YWl0IGdldEFjdGl2ZU5vdGVDb250ZXh0KHRoaXMuYXBwKTtcbiAgICAgIGlmIChub3RlKSB7XG4gICAgICAgIG1lc3NhZ2UgPSBgQ29udGV4dDogW1ske25vdGUudGl0bGV9XV1cXG5cXG4ke3RleHR9YDtcbiAgICAgIH1cbiAgICB9XG5cbiAgICAvLyBBZGQgdXNlciBtZXNzYWdlIHRvIGNoYXQgVUlcbiAgICBjb25zdCB1c2VyTXNnID0gQ2hhdE1hbmFnZXIuY3JlYXRlVXNlck1lc3NhZ2UodGV4dCk7XG4gICAgdGhpcy5jaGF0TWFuYWdlci5hZGRNZXNzYWdlKHVzZXJNc2cpO1xuXG4gICAgLy8gQ2xlYXIgaW5wdXRcbiAgICB0aGlzLmlucHV0RWwudmFsdWUgPSAnJztcbiAgICB0aGlzLmlucHV0RWwuc3R5bGUuaGVpZ2h0ID0gJ2F1dG8nO1xuXG4gICAgLy8gU2VuZCBvdmVyIFdTIChhc3luYylcbiAgICB0cnkge1xuICAgICAgYXdhaXQgdGhpcy53c0NsaWVudC5zZW5kTWVzc2FnZShtZXNzYWdlKTtcbiAgICB9IGNhdGNoIChlcnIpIHtcbiAgICAgIGNvbnNvbGUuZXJyb3IoJ1tvY2xhd10gU2VuZCBmYWlsZWQnLCBlcnIpO1xuICAgICAgbmV3IE5vdGljZShgT3BlbkNsYXcgQ2hhdDogc2VuZCBmYWlsZWQgKCR7U3RyaW5nKGVycil9KWApO1xuICAgICAgdGhpcy5jaGF0TWFuYWdlci5hZGRNZXNzYWdlKFxuICAgICAgICBDaGF0TWFuYWdlci5jcmVhdGVTeXN0ZW1NZXNzYWdlKGBcdTI2QTAgU2VuZCBmYWlsZWQ6ICR7ZXJyfWAsICdlcnJvcicpXG4gICAgICApO1xuICAgIH1cbiAgfVxufVxuIiwgImltcG9ydCB0eXBlIHsgQ2hhdE1lc3NhZ2UgfSBmcm9tICcuL3R5cGVzJztcblxuLyoqIE1hbmFnZXMgdGhlIGluLW1lbW9yeSBsaXN0IG9mIGNoYXQgbWVzc2FnZXMgYW5kIG5vdGlmaWVzIFVJIG9uIGNoYW5nZXMgKi9cbmV4cG9ydCBjbGFzcyBDaGF0TWFuYWdlciB7XG4gIHByaXZhdGUgbWVzc2FnZXM6IENoYXRNZXNzYWdlW10gPSBbXTtcblxuICAvKiogRmlyZWQgZm9yIGEgZnVsbCByZS1yZW5kZXIgKGNsZWFyL3JlbG9hZCkgKi9cbiAgb25VcGRhdGU6ICgobWVzc2FnZXM6IHJlYWRvbmx5IENoYXRNZXNzYWdlW10pID0+IHZvaWQpIHwgbnVsbCA9IG51bGw7XG4gIC8qKiBGaXJlZCB3aGVuIGEgc2luZ2xlIG1lc3NhZ2UgaXMgYXBwZW5kZWQgXHUyMDE0IHVzZSBmb3IgTygxKSBhcHBlbmQtb25seSBVSSAqL1xuICBvbk1lc3NhZ2VBZGRlZDogKChtc2c6IENoYXRNZXNzYWdlKSA9PiB2b2lkKSB8IG51bGwgPSBudWxsO1xuXG4gIGFkZE1lc3NhZ2UobXNnOiBDaGF0TWVzc2FnZSk6IHZvaWQge1xuICAgIHRoaXMubWVzc2FnZXMucHVzaChtc2cpO1xuICAgIHRoaXMub25NZXNzYWdlQWRkZWQ/Lihtc2cpO1xuICB9XG5cbiAgZ2V0TWVzc2FnZXMoKTogcmVhZG9ubHkgQ2hhdE1lc3NhZ2VbXSB7XG4gICAgcmV0dXJuIHRoaXMubWVzc2FnZXM7XG4gIH1cblxuICBjbGVhcigpOiB2b2lkIHtcbiAgICB0aGlzLm1lc3NhZ2VzID0gW107XG4gICAgdGhpcy5vblVwZGF0ZT8uKFtdKTtcbiAgfVxuXG4gIC8qKiBDcmVhdGUgYSB1c2VyIG1lc3NhZ2Ugb2JqZWN0ICh3aXRob3V0IGFkZGluZyBpdCkgKi9cbiAgc3RhdGljIGNyZWF0ZVVzZXJNZXNzYWdlKGNvbnRlbnQ6IHN0cmluZyk6IENoYXRNZXNzYWdlIHtcbiAgICByZXR1cm4ge1xuICAgICAgaWQ6IGBtc2ctJHtEYXRlLm5vdygpfS0ke01hdGgucmFuZG9tKCkudG9TdHJpbmcoMzYpLnNsaWNlKDIsIDcpfWAsXG4gICAgICByb2xlOiAndXNlcicsXG4gICAgICBjb250ZW50LFxuICAgICAgdGltZXN0YW1wOiBEYXRlLm5vdygpLFxuICAgIH07XG4gIH1cblxuICAvKiogQ3JlYXRlIGFuIGFzc2lzdGFudCBtZXNzYWdlIG9iamVjdCAod2l0aG91dCBhZGRpbmcgaXQpICovXG4gIHN0YXRpYyBjcmVhdGVBc3Npc3RhbnRNZXNzYWdlKGNvbnRlbnQ6IHN0cmluZyk6IENoYXRNZXNzYWdlIHtcbiAgICByZXR1cm4ge1xuICAgICAgaWQ6IGBtc2ctJHtEYXRlLm5vdygpfS0ke01hdGgucmFuZG9tKCkudG9TdHJpbmcoMzYpLnNsaWNlKDIsIDcpfWAsXG4gICAgICByb2xlOiAnYXNzaXN0YW50JyxcbiAgICAgIGNvbnRlbnQsXG4gICAgICB0aW1lc3RhbXA6IERhdGUubm93KCksXG4gICAgfTtcbiAgfVxuXG4gIC8qKiBDcmVhdGUgYSBzeXN0ZW0gLyBzdGF0dXMgbWVzc2FnZSAoZXJyb3JzLCByZWNvbm5lY3Qgbm90aWNlcywgZXRjLikgKi9cbiAgc3RhdGljIGNyZWF0ZVN5c3RlbU1lc3NhZ2UoY29udGVudDogc3RyaW5nLCBsZXZlbDogQ2hhdE1lc3NhZ2VbJ2xldmVsJ10gPSAnaW5mbycpOiBDaGF0TWVzc2FnZSB7XG4gICAgcmV0dXJuIHtcbiAgICAgIGlkOiBgc3lzLSR7RGF0ZS5ub3coKX1gLFxuICAgICAgcm9sZTogJ3N5c3RlbScsXG4gICAgICBsZXZlbCxcbiAgICAgIGNvbnRlbnQsXG4gICAgICB0aW1lc3RhbXA6IERhdGUubm93KCksXG4gICAgfTtcbiAgfVxuXG4gIHN0YXRpYyBjcmVhdGVTZXNzaW9uRGl2aWRlcihzZXNzaW9uS2V5OiBzdHJpbmcpOiBDaGF0TWVzc2FnZSB7XG4gICAgY29uc3Qgc2hvcnQgPSBzZXNzaW9uS2V5Lmxlbmd0aCA+IDI4ID8gYCR7c2Vzc2lvbktleS5zbGljZSgwLCAxMil9XHUyMDI2JHtzZXNzaW9uS2V5LnNsaWNlKC0xMil9YCA6IHNlc3Npb25LZXk7XG4gICAgcmV0dXJuIHtcbiAgICAgIGlkOiBgZGl2LSR7RGF0ZS5ub3coKX1gLFxuICAgICAgcm9sZTogJ3N5c3RlbScsXG4gICAgICBsZXZlbDogJ2luZm8nLFxuICAgICAga2luZDogJ3Nlc3Npb24tZGl2aWRlcicsXG4gICAgICB0aXRsZTogc2Vzc2lvbktleSxcbiAgICAgIGNvbnRlbnQ6IGBbU2Vzc2lvbjogJHtzaG9ydH1dYCxcbiAgICAgIHRpbWVzdGFtcDogRGF0ZS5ub3coKSxcbiAgICB9O1xuICB9XG59XG4iLCAiaW1wb3J0IHR5cGUgeyBQYXRoTWFwcGluZyB9IGZyb20gJy4vdHlwZXMnO1xuXG5leHBvcnQgZnVuY3Rpb24gbm9ybWFsaXplQmFzZShiYXNlOiBzdHJpbmcpOiBzdHJpbmcge1xuICBjb25zdCB0cmltbWVkID0gU3RyaW5nKGJhc2UgPz8gJycpLnRyaW0oKTtcbiAgaWYgKCF0cmltbWVkKSByZXR1cm4gJyc7XG4gIHJldHVybiB0cmltbWVkLmVuZHNXaXRoKCcvJykgPyB0cmltbWVkIDogYCR7dHJpbW1lZH0vYDtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIHRyeU1hcFJlbW90ZVBhdGhUb1ZhdWx0UGF0aChpbnB1dDogc3RyaW5nLCBtYXBwaW5nczogcmVhZG9ubHkgUGF0aE1hcHBpbmdbXSk6IHN0cmluZyB8IG51bGwge1xuICBjb25zdCByYXcgPSBTdHJpbmcoaW5wdXQgPz8gJycpO1xuICBmb3IgKGNvbnN0IHJvdyBvZiBtYXBwaW5ncykge1xuICAgIGNvbnN0IHJlbW90ZUJhc2UgPSBub3JtYWxpemVCYXNlKHJvdy5yZW1vdGVCYXNlKTtcbiAgICBjb25zdCB2YXVsdEJhc2UgPSBub3JtYWxpemVCYXNlKHJvdy52YXVsdEJhc2UpO1xuICAgIGlmICghcmVtb3RlQmFzZSB8fCAhdmF1bHRCYXNlKSBjb250aW51ZTtcblxuICAgIGlmIChyYXcuc3RhcnRzV2l0aChyZW1vdGVCYXNlKSkge1xuICAgICAgY29uc3QgcmVzdCA9IHJhdy5zbGljZShyZW1vdGVCYXNlLmxlbmd0aCk7XG4gICAgICAvLyBPYnNpZGlhbiBwYXRocyBhcmUgdmF1bHQtcmVsYXRpdmUgYW5kIHNob3VsZCBub3Qgc3RhcnQgd2l0aCAnLydcbiAgICAgIHJldHVybiBgJHt2YXVsdEJhc2V9JHtyZXN0fWAucmVwbGFjZSgvXlxcLysvLCAnJyk7XG4gICAgfVxuICB9XG4gIHJldHVybiBudWxsO1xufVxuXG5leHBvcnQgdHlwZSBDYW5kaWRhdGUgPSB7IHN0YXJ0OiBudW1iZXI7IGVuZDogbnVtYmVyOyByYXc6IHN0cmluZzsga2luZDogJ3VybCcgfCAncGF0aCcgfTtcblxuLy8gQ29uc2VydmF0aXZlIGV4dHJhY3Rpb246IGFpbSB0byBhdm9pZCBmYWxzZSBwb3NpdGl2ZXMuXG5jb25zdCBVUkxfUkUgPSAvaHR0cHM/OlxcL1xcL1teXFxzPD4oKV0rL2c7XG4vLyBBYnNvbHV0ZSB1bml4LWlzaCBwYXRocy5cbi8vIChXZSBzdGlsbCBleGlzdGVuY2UtY2hlY2sgYmVmb3JlIHByb2R1Y2luZyBhIGxpbmsuKVxuY29uc3QgUEFUSF9SRSA9IC8oPzwhW0EtWmEtejAtOS5fLV0pKD86XFwvW0EtWmEtejAtOS5ffiEkJicoKSorLDs9OkAlXFwtXSspKyg/OlxcLltBLVphLXowLTkuXy1dKyk/L2c7XG5cbi8vIENvbnNlcnZhdGl2ZSByZWxhdGl2ZSBwYXRocyB3aXRoIGF0IGxlYXN0IG9uZSAnLycsIGUuZy4gY29tcGVuZy9wbGFucy94Lm1kXG4vLyBBdm9pZHMgbWF0Y2hpbmcgc2NoZW1lLWxpa2UgdG9rZW5zIHZpYSBuZWdhdGl2ZSBsb29rYWhlYWQgZm9yICc6Ly8nLlxuY29uc3QgUkVMX1BBVEhfUkUgPSAvXFxiKD8hW0EtWmEtel1bQS1aYS16MC05Ky4tXSo6XFwvXFwvKVtBLVphLXowLTkuXy1dKyg/OlxcL1tBLVphLXowLTkuXy1dKykrKD86XFwuW0EtWmEtejAtOS5fLV0rKT9cXGIvZztcblxuZXhwb3J0IGZ1bmN0aW9uIGV4dHJhY3RDYW5kaWRhdGVzKHRleHQ6IHN0cmluZyk6IENhbmRpZGF0ZVtdIHtcbiAgY29uc3QgdCA9IFN0cmluZyh0ZXh0ID8/ICcnKTtcbiAgY29uc3Qgb3V0OiBDYW5kaWRhdGVbXSA9IFtdO1xuXG4gIGZvciAoY29uc3QgbSBvZiB0Lm1hdGNoQWxsKFVSTF9SRSkpIHtcbiAgICBpZiAobS5pbmRleCA9PT0gdW5kZWZpbmVkKSBjb250aW51ZTtcbiAgICBvdXQucHVzaCh7IHN0YXJ0OiBtLmluZGV4LCBlbmQ6IG0uaW5kZXggKyBtWzBdLmxlbmd0aCwgcmF3OiBtWzBdLCBraW5kOiAndXJsJyB9KTtcbiAgfVxuXG4gIGZvciAoY29uc3QgbSBvZiB0Lm1hdGNoQWxsKFBBVEhfUkUpKSB7XG4gICAgaWYgKG0uaW5kZXggPT09IHVuZGVmaW5lZCkgY29udGludWU7XG5cbiAgICAvLyBTa2lwIGlmIHRoaXMgaXMgaW5zaWRlIGEgVVJMIHdlIGFscmVhZHkgY2FwdHVyZWQuXG4gICAgY29uc3Qgc3RhcnQgPSBtLmluZGV4O1xuICAgIGNvbnN0IGVuZCA9IHN0YXJ0ICsgbVswXS5sZW5ndGg7XG4gICAgY29uc3Qgb3ZlcmxhcHNVcmwgPSBvdXQuc29tZSgoYykgPT4gYy5raW5kID09PSAndXJsJyAmJiAhKGVuZCA8PSBjLnN0YXJ0IHx8IHN0YXJ0ID49IGMuZW5kKSk7XG4gICAgaWYgKG92ZXJsYXBzVXJsKSBjb250aW51ZTtcblxuICAgIG91dC5wdXNoKHsgc3RhcnQsIGVuZCwgcmF3OiBtWzBdLCBraW5kOiAncGF0aCcgfSk7XG4gIH1cblxuICBmb3IgKGNvbnN0IG0gb2YgdC5tYXRjaEFsbChSRUxfUEFUSF9SRSkpIHtcbiAgICBpZiAobS5pbmRleCA9PT0gdW5kZWZpbmVkKSBjb250aW51ZTtcblxuICAgIGNvbnN0IHN0YXJ0ID0gbS5pbmRleDtcbiAgICBjb25zdCBlbmQgPSBzdGFydCArIG1bMF0ubGVuZ3RoO1xuICAgIGNvbnN0IG92ZXJsYXBzRXhpc3RpbmcgPSBvdXQuc29tZSgoYykgPT4gIShlbmQgPD0gYy5zdGFydCB8fCBzdGFydCA+PSBjLmVuZCkpO1xuICAgIGlmIChvdmVybGFwc0V4aXN0aW5nKSBjb250aW51ZTtcblxuICAgIG91dC5wdXNoKHsgc3RhcnQsIGVuZCwgcmF3OiBtWzBdLCBraW5kOiAncGF0aCcgfSk7XG4gIH1cblxuICAvLyBTb3J0IGFuZCBkcm9wIG92ZXJsYXBzIChwcmVmZXIgVVJMcykuXG4gIG91dC5zb3J0KChhLCBiKSA9PiBhLnN0YXJ0IC0gYi5zdGFydCB8fCAoYS5raW5kID09PSAndXJsJyA/IC0xIDogMSkpO1xuICBjb25zdCBkZWR1cDogQ2FuZGlkYXRlW10gPSBbXTtcbiAgZm9yIChjb25zdCBjIG9mIG91dCkge1xuICAgIGNvbnN0IGxhc3QgPSBkZWR1cFtkZWR1cC5sZW5ndGggLSAxXTtcbiAgICBpZiAoIWxhc3QpIHtcbiAgICAgIGRlZHVwLnB1c2goYyk7XG4gICAgICBjb250aW51ZTtcbiAgICB9XG4gICAgaWYgKGMuc3RhcnQgPCBsYXN0LmVuZCkgY29udGludWU7XG4gICAgZGVkdXAucHVzaChjKTtcbiAgfVxuXG4gIHJldHVybiBkZWR1cDtcbn1cbiIsICJpbXBvcnQgdHlwZSB7IEFwcCB9IGZyb20gJ29ic2lkaWFuJztcblxuZXhwb3J0IGludGVyZmFjZSBOb3RlQ29udGV4dCB7XG4gIHRpdGxlOiBzdHJpbmc7XG4gIHBhdGg6IHN0cmluZztcbiAgY29udGVudDogc3RyaW5nO1xufVxuXG4vKipcbiAqIFJldHVybnMgdGhlIGFjdGl2ZSBub3RlJ3MgdGl0bGUgYW5kIGNvbnRlbnQsIG9yIG51bGwgaWYgbm8gbm90ZSBpcyBvcGVuLlxuICogQXN5bmMgYmVjYXVzZSB2YXVsdC5yZWFkKCkgaXMgYXN5bmMuXG4gKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBnZXRBY3RpdmVOb3RlQ29udGV4dChhcHA6IEFwcCk6IFByb21pc2U8Tm90ZUNvbnRleHQgfCBudWxsPiB7XG4gIGNvbnN0IGZpbGUgPSBhcHAud29ya3NwYWNlLmdldEFjdGl2ZUZpbGUoKTtcbiAgaWYgKCFmaWxlKSByZXR1cm4gbnVsbDtcblxuICB0cnkge1xuICAgIGNvbnN0IGNvbnRlbnQgPSBhd2FpdCBhcHAudmF1bHQucmVhZChmaWxlKTtcbiAgICByZXR1cm4ge1xuICAgICAgdGl0bGU6IGZpbGUuYmFzZW5hbWUsXG4gICAgICBwYXRoOiBmaWxlLnBhdGgsXG4gICAgICBjb250ZW50LFxuICAgIH07XG4gIH0gY2F0Y2ggKGVycikge1xuICAgIGNvbnNvbGUuZXJyb3IoJ1tvY2xhdy1jb250ZXh0XSBGYWlsZWQgdG8gcmVhZCBhY3RpdmUgbm90ZScsIGVycik7XG4gICAgcmV0dXJuIG51bGw7XG4gIH1cbn1cbiIsICIvKiogUGVyc2lzdGVkIHBsdWdpbiBjb25maWd1cmF0aW9uICovXG5leHBvcnQgaW50ZXJmYWNlIE9wZW5DbGF3U2V0dGluZ3Mge1xuICAvKiogV2ViU29ja2V0IFVSTCBvZiB0aGUgT3BlbkNsYXcgR2F0ZXdheSAoZS5nLiB3czovLzEwMC45MC45LjY4OjE4Nzg5KSAqL1xuICBnYXRld2F5VXJsOiBzdHJpbmc7XG4gIC8qKiBBdXRoIHRva2VuIFx1MjAxNCBtdXN0IG1hdGNoIHRoZSBjaGFubmVsIHBsdWdpbidzIGF1dGhUb2tlbiAqL1xuICBhdXRoVG9rZW46IHN0cmluZztcbiAgLyoqIE9wZW5DbGF3IHNlc3Npb24ga2V5IHRvIHN1YnNjcmliZSB0byAoZS5nLiBcIm1haW5cIikgKi9cbiAgc2Vzc2lvbktleTogc3RyaW5nO1xuICAvKiogKERlcHJlY2F0ZWQpIE9wZW5DbGF3IGFjY291bnQgSUQgKHVudXNlZDsgY2hhdC5zZW5kIHVzZXMgc2Vzc2lvbktleSkgKi9cbiAgYWNjb3VudElkOiBzdHJpbmc7XG4gIC8qKiBXaGV0aGVyIHRvIGluY2x1ZGUgdGhlIGFjdGl2ZSBub3RlIGNvbnRlbnQgd2l0aCBlYWNoIG1lc3NhZ2UgKi9cbiAgaW5jbHVkZUFjdGl2ZU5vdGU6IGJvb2xlYW47XG4gIC8qKiBSZW5kZXIgYXNzaXN0YW50IG91dHB1dCBhcyBNYXJrZG93biAodW5zYWZlOiBtYXkgdHJpZ2dlciBlbWJlZHMvcG9zdC1wcm9jZXNzb3JzKTsgZGVmYXVsdCBPRkYgKi9cbiAgcmVuZGVyQXNzaXN0YW50TWFya2Rvd246IGJvb2xlYW47XG4gIC8qKiBBbGxvdyB1c2luZyBpbnNlY3VyZSB3czovLyBmb3Igbm9uLWxvY2FsIGdhdGV3YXkgVVJMcyAodW5zYWZlKTsgZGVmYXVsdCBPRkYgKi9cbiAgYWxsb3dJbnNlY3VyZVdzOiBib29sZWFuO1xuXG4gIC8qKiBPcHRpb25hbDogbWFwIHJlbW90ZSBGUyBwYXRocyAvIGV4cG9ydGVkIHBhdGhzIGJhY2sgdG8gdmF1bHQtcmVsYXRpdmUgcGF0aHMgKi9cbiAgcGF0aE1hcHBpbmdzOiBQYXRoTWFwcGluZ1tdO1xuXG4gIC8qKiBWYXVsdCBpZGVudGl0eSAoaGFzaCkgdXNlZCBmb3IgY2Fub25pY2FsIHNlc3Npb24ga2V5cy4gKi9cbiAgdmF1bHRIYXNoPzogc3RyaW5nO1xuXG4gIC8qKiBLbm93biBPYnNpZGlhbiBzZXNzaW9uIGtleXMgZm9yIGVhY2ggdmF1bHRIYXNoICh2YXVsdC1zY29wZWQgY29udGludWl0eSkuICovXG4gIGtub3duU2Vzc2lvbktleXNCeVZhdWx0PzogUmVjb3JkPHN0cmluZywgc3RyaW5nW10+O1xuXG4gIC8qKiBMZWdhY3kga2V5cyBrZXB0IGZvciBtaWdyYXRpb24vZGVidWcgKG9wdGlvbmFsKS4gKi9cbiAgbGVnYWN5U2Vzc2lvbktleXM/OiBzdHJpbmdbXTtcbn1cblxuZXhwb3J0IHR5cGUgUGF0aE1hcHBpbmcgPSB7XG4gIC8qKiBWYXVsdC1yZWxhdGl2ZSBiYXNlIHBhdGggKGUuZy4gXCJkb2NzL1wiIG9yIFwiY29tcGVuZy9cIikgKi9cbiAgdmF1bHRCYXNlOiBzdHJpbmc7XG4gIC8qKiBSZW1vdGUgRlMgYmFzZSBwYXRoIChlLmcuIFwiL2hvbWUvd2FsbC1lLy5vcGVuY2xhdy93b3Jrc3BhY2UvZG9jcy9cIikgKi9cbiAgcmVtb3RlQmFzZTogc3RyaW5nO1xufTtcblxuZXhwb3J0IGNvbnN0IERFRkFVTFRfU0VUVElOR1M6IE9wZW5DbGF3U2V0dGluZ3MgPSB7XG4gIGdhdGV3YXlVcmw6ICd3czovL2xvY2FsaG9zdDoxODc4OScsXG4gIGF1dGhUb2tlbjogJycsXG4gIHNlc3Npb25LZXk6ICdtYWluJyxcbiAgYWNjb3VudElkOiAnbWFpbicsXG4gIGluY2x1ZGVBY3RpdmVOb3RlOiBmYWxzZSxcbiAgcmVuZGVyQXNzaXN0YW50TWFya2Rvd246IGZhbHNlLFxuICBhbGxvd0luc2VjdXJlV3M6IGZhbHNlLFxuICBwYXRoTWFwcGluZ3M6IFtdLFxuICB2YXVsdEhhc2g6IHVuZGVmaW5lZCxcbiAga25vd25TZXNzaW9uS2V5c0J5VmF1bHQ6IHt9LFxuICBsZWdhY3lTZXNzaW9uS2V5czogW10sXG59O1xuXG4vKiogQSBzaW5nbGUgY2hhdCBtZXNzYWdlICovXG5leHBvcnQgaW50ZXJmYWNlIENoYXRNZXNzYWdlIHtcbiAgaWQ6IHN0cmluZztcbiAgcm9sZTogJ3VzZXInIHwgJ2Fzc2lzdGFudCcgfCAnc3lzdGVtJztcbiAgLyoqIE9wdGlvbmFsIHNldmVyaXR5IGZvciBzeXN0ZW0vc3RhdHVzIG1lc3NhZ2VzICovXG4gIGxldmVsPzogJ2luZm8nIHwgJ2Vycm9yJztcbiAgLyoqIE9wdGlvbmFsIHN1YnR5cGUgZm9yIHN0eWxpbmcgc3BlY2lhbCBzeXN0ZW0gbWVzc2FnZXMgKGUuZy4gc2Vzc2lvbiBkaXZpZGVyKS4gKi9cbiAga2luZD86ICdzZXNzaW9uLWRpdmlkZXInO1xuICAvKiogT3B0aW9uYWwgaG92ZXIgdG9vbHRpcCBmb3IgdGhlIG1lc3NhZ2UgKGUuZy4gZnVsbCBzZXNzaW9uIGtleSkuICovXG4gIHRpdGxlPzogc3RyaW5nO1xuICBjb250ZW50OiBzdHJpbmc7XG4gIHRpbWVzdGFtcDogbnVtYmVyO1xufVxuXG4vKiogUGF5bG9hZCBmb3IgbWVzc2FnZXMgU0VOVCB0byB0aGUgc2VydmVyIChvdXRib3VuZCkgKi9cbmV4cG9ydCBpbnRlcmZhY2UgV1NQYXlsb2FkIHtcbiAgdHlwZTogJ2F1dGgnIHwgJ21lc3NhZ2UnIHwgJ3BpbmcnIHwgJ3BvbmcnIHwgJ2Vycm9yJztcbiAgcGF5bG9hZD86IFJlY29yZDxzdHJpbmcsIHVua25vd24+O1xufVxuXG4vKiogTWVzc2FnZXMgUkVDRUlWRUQgZnJvbSB0aGUgc2VydmVyIChpbmJvdW5kKSBcdTIwMTQgZGlzY3JpbWluYXRlZCB1bmlvbiAqL1xuZXhwb3J0IHR5cGUgSW5ib3VuZFdTUGF5bG9hZCA9XG4gIHwgeyB0eXBlOiAnbWVzc2FnZSc7IHBheWxvYWQ6IHsgY29udGVudDogc3RyaW5nOyByb2xlOiBzdHJpbmc7IHRpbWVzdGFtcDogbnVtYmVyIH0gfVxuICB8IHsgdHlwZTogJ2Vycm9yJzsgcGF5bG9hZDogeyBtZXNzYWdlOiBzdHJpbmcgfSB9O1xuXG4vKiogQXZhaWxhYmxlIGFnZW50cyAvIG1vZGVscyAqL1xuZXhwb3J0IGludGVyZmFjZSBBZ2VudE9wdGlvbiB7XG4gIGlkOiBzdHJpbmc7XG4gIGxhYmVsOiBzdHJpbmc7XG59XG4iLCAiaW1wb3J0IHR5cGUgeyBPcGVuQ2xhd1NldHRpbmdzIH0gZnJvbSAnLi90eXBlcyc7XG5cbmV4cG9ydCBmdW5jdGlvbiBjYW5vbmljYWxWYXVsdFNlc3Npb25LZXkodmF1bHRIYXNoOiBzdHJpbmcpOiBzdHJpbmcge1xuICByZXR1cm4gYGFnZW50Om1haW46b2JzaWRpYW46ZGlyZWN0OiR7dmF1bHRIYXNofWA7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBpc0FsbG93ZWRPYnNpZGlhblNlc3Npb25LZXkocGFyYW1zOiB7XG4gIGtleTogc3RyaW5nO1xuICB2YXVsdEhhc2g6IHN0cmluZyB8IG51bGw7XG59KTogYm9vbGVhbiB7XG4gIGNvbnN0IGtleSA9IChwYXJhbXMua2V5ID8/ICcnKS50cmltKCkudG9Mb3dlckNhc2UoKTtcbiAgaWYgKCFrZXkpIHJldHVybiBmYWxzZTtcbiAgaWYgKGtleSA9PT0gJ21haW4nKSByZXR1cm4gdHJ1ZTtcblxuICBjb25zdCB2YXVsdEhhc2ggPSAocGFyYW1zLnZhdWx0SGFzaCA/PyAnJykudHJpbSgpLnRvTG93ZXJDYXNlKCk7XG4gIGlmICghdmF1bHRIYXNoKSB7XG4gICAgLy8gV2l0aG91dCBhIHZhdWx0IGlkZW50aXR5LCB3ZSBvbmx5IGFsbG93IG1haW4uXG4gICAgcmV0dXJuIGZhbHNlO1xuICB9XG5cbiAgY29uc3QgcHJlZml4ID0gYGFnZW50Om1haW46b2JzaWRpYW46ZGlyZWN0OiR7dmF1bHRIYXNofWA7XG4gIGlmIChrZXkgPT09IHByZWZpeCkgcmV0dXJuIHRydWU7XG4gIGlmIChrZXkuc3RhcnRzV2l0aChwcmVmaXggKyAnLScpKSByZXR1cm4gdHJ1ZTtcbiAgcmV0dXJuIGZhbHNlO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gbWlncmF0ZVNldHRpbmdzRm9yVmF1bHQoc2V0dGluZ3M6IE9wZW5DbGF3U2V0dGluZ3MsIHZhdWx0SGFzaDogc3RyaW5nKToge1xuICBuZXh0U2V0dGluZ3M6IE9wZW5DbGF3U2V0dGluZ3M7XG4gIGNhbm9uaWNhbEtleTogc3RyaW5nO1xufSB7XG4gIGNvbnN0IGNhbm9uaWNhbEtleSA9IGNhbm9uaWNhbFZhdWx0U2Vzc2lvbktleSh2YXVsdEhhc2gpO1xuICBjb25zdCBleGlzdGluZyA9IChzZXR0aW5ncy5zZXNzaW9uS2V5ID8/ICcnKS50cmltKCkudG9Mb3dlckNhc2UoKTtcbiAgY29uc3QgaXNMZWdhY3kgPSBleGlzdGluZy5zdGFydHNXaXRoKCdvYnNpZGlhbi0nKTtcbiAgY29uc3QgaXNFbXB0eU9yTWFpbiA9ICFleGlzdGluZyB8fCBleGlzdGluZyA9PT0gJ21haW4nIHx8IGV4aXN0aW5nID09PSAnYWdlbnQ6bWFpbjptYWluJztcblxuICBjb25zdCBuZXh0OiBPcGVuQ2xhd1NldHRpbmdzID0geyAuLi5zZXR0aW5ncyB9O1xuICBuZXh0LnZhdWx0SGFzaCA9IHZhdWx0SGFzaDtcblxuICBpZiAoaXNMZWdhY3kpIHtcbiAgICBjb25zdCBsZWdhY3kgPSBBcnJheS5pc0FycmF5KG5leHQubGVnYWN5U2Vzc2lvbktleXMpID8gbmV4dC5sZWdhY3lTZXNzaW9uS2V5cyA6IFtdO1xuICAgIG5leHQubGVnYWN5U2Vzc2lvbktleXMgPSBbZXhpc3RpbmcsIC4uLmxlZ2FjeS5maWx0ZXIoKGspID0+IGsgJiYgayAhPT0gZXhpc3RpbmcpXS5zbGljZSgwLCAyMCk7XG4gIH1cblxuICBpZiAoaXNMZWdhY3kgfHwgaXNFbXB0eU9yTWFpbikge1xuICAgIG5leHQuc2Vzc2lvbktleSA9IGNhbm9uaWNhbEtleTtcbiAgfVxuXG4gIGNvbnN0IG1hcCA9IG5leHQua25vd25TZXNzaW9uS2V5c0J5VmF1bHQgPz8ge307XG4gIGNvbnN0IGN1ciA9IEFycmF5LmlzQXJyYXkobWFwW3ZhdWx0SGFzaF0pID8gbWFwW3ZhdWx0SGFzaF0gOiBbXTtcbiAgaWYgKCFjdXIuaW5jbHVkZXMoY2Fub25pY2FsS2V5KSkge1xuICAgIG1hcFt2YXVsdEhhc2hdID0gW2Nhbm9uaWNhbEtleSwgLi4uY3VyXS5zbGljZSgwLCAyMCk7XG4gICAgbmV4dC5rbm93blNlc3Npb25LZXlzQnlWYXVsdCA9IG1hcDtcbiAgfVxuXG4gIHJldHVybiB7IG5leHRTZXR0aW5nczogbmV4dCwgY2Fub25pY2FsS2V5IH07XG59XG4iXSwKICAibWFwcGluZ3MiOiAiOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUEsSUFBQUEsbUJBQWlFOzs7QUNBakUsc0JBQStDO0FBR3hDLElBQU0scUJBQU4sY0FBaUMsaUNBQWlCO0FBQUEsRUFHdkQsWUFBWSxLQUFVLFFBQXdCO0FBQzVDLFVBQU0sS0FBSyxNQUFNO0FBQ2pCLFNBQUssU0FBUztBQUFBLEVBQ2hCO0FBQUEsRUFFQSxVQUFnQjtBQVhsQjtBQVlJLFVBQU0sRUFBRSxZQUFZLElBQUk7QUFDeEIsZ0JBQVksTUFBTTtBQUVsQixnQkFBWSxTQUFTLE1BQU0sRUFBRSxNQUFNLGdDQUEyQixDQUFDO0FBRS9ELFFBQUksd0JBQVEsV0FBVyxFQUNwQixRQUFRLGFBQWEsRUFDckIsUUFBUSxtRUFBbUUsRUFDM0U7QUFBQSxNQUFRLENBQUMsU0FDUixLQUNHLGVBQWUsc0JBQXNCLEVBQ3JDLFNBQVMsS0FBSyxPQUFPLFNBQVMsVUFBVSxFQUN4QyxTQUFTLENBQU8sVUFBVTtBQUN6QixhQUFLLE9BQU8sU0FBUyxhQUFhLE1BQU0sS0FBSztBQUM3QyxjQUFNLEtBQUssT0FBTyxhQUFhO0FBQUEsTUFDakMsRUFBQztBQUFBLElBQ0w7QUFFRixRQUFJLHdCQUFRLFdBQVcsRUFDcEIsUUFBUSxZQUFZLEVBQ3BCLFFBQVEsOEVBQThFLEVBQ3RGLFFBQVEsQ0FBQyxTQUFTO0FBQ2pCLFdBQ0csZUFBZSxtQkFBYyxFQUM3QixTQUFTLEtBQUssT0FBTyxTQUFTLFNBQVMsRUFDdkMsU0FBUyxDQUFPLFVBQVU7QUFDekIsYUFBSyxPQUFPLFNBQVMsWUFBWTtBQUNqQyxjQUFNLEtBQUssT0FBTyxhQUFhO0FBQUEsTUFDakMsRUFBQztBQUVILFdBQUssUUFBUSxPQUFPO0FBQ3BCLFdBQUssUUFBUSxlQUFlO0FBQUEsSUFDOUIsQ0FBQztBQUVILFFBQUksd0JBQVEsV0FBVyxFQUNwQixRQUFRLGFBQWEsRUFDckIsUUFBUSxvREFBb0QsRUFDNUQ7QUFBQSxNQUFRLENBQUMsU0FDUixLQUNHLGVBQWUsTUFBTSxFQUNyQixTQUFTLEtBQUssT0FBTyxTQUFTLFVBQVUsRUFDeEMsU0FBUyxDQUFPLFVBQVU7QUFDekIsYUFBSyxPQUFPLFNBQVMsYUFBYSxNQUFNLEtBQUssS0FBSztBQUNsRCxjQUFNLEtBQUssT0FBTyxhQUFhO0FBQUEsTUFDakMsRUFBQztBQUFBLElBQ0w7QUFFRixRQUFJLHdCQUFRLFdBQVcsRUFDcEIsUUFBUSxZQUFZLEVBQ3BCLFFBQVEsdUNBQXVDLEVBQy9DO0FBQUEsTUFBUSxDQUFDLFNBQ1IsS0FDRyxlQUFlLE1BQU0sRUFDckIsU0FBUyxLQUFLLE9BQU8sU0FBUyxTQUFTLEVBQ3ZDLFNBQVMsQ0FBTyxVQUFVO0FBQ3pCLGFBQUssT0FBTyxTQUFTLFlBQVksTUFBTSxLQUFLLEtBQUs7QUFDakQsY0FBTSxLQUFLLE9BQU8sYUFBYTtBQUFBLE1BQ2pDLEVBQUM7QUFBQSxJQUNMO0FBRUYsUUFBSSx3QkFBUSxXQUFXLEVBQ3BCLFFBQVEsZ0NBQWdDLEVBQ3hDLFFBQVEsa0VBQWtFLEVBQzFFO0FBQUEsTUFBVSxDQUFDLFdBQ1YsT0FBTyxTQUFTLEtBQUssT0FBTyxTQUFTLGlCQUFpQixFQUFFLFNBQVMsQ0FBTyxVQUFVO0FBQ2hGLGFBQUssT0FBTyxTQUFTLG9CQUFvQjtBQUN6QyxjQUFNLEtBQUssT0FBTyxhQUFhO0FBQUEsTUFDakMsRUFBQztBQUFBLElBQ0g7QUFFRixRQUFJLHdCQUFRLFdBQVcsRUFDcEIsUUFBUSx1Q0FBdUMsRUFDL0M7QUFBQSxNQUNDO0FBQUEsSUFDRixFQUNDO0FBQUEsTUFBVSxDQUFDLFdBQ1YsT0FBTyxTQUFTLEtBQUssT0FBTyxTQUFTLHVCQUF1QixFQUFFLFNBQVMsQ0FBTyxVQUFVO0FBQ3RGLGFBQUssT0FBTyxTQUFTLDBCQUEwQjtBQUMvQyxjQUFNLEtBQUssT0FBTyxhQUFhO0FBQUEsTUFDakMsRUFBQztBQUFBLElBQ0g7QUFFRixRQUFJLHdCQUFRLFdBQVcsRUFDcEIsUUFBUSxzREFBc0QsRUFDOUQ7QUFBQSxNQUNDO0FBQUEsSUFDRixFQUNDO0FBQUEsTUFBVSxDQUFDLFdBQ1YsT0FBTyxTQUFTLEtBQUssT0FBTyxTQUFTLGVBQWUsRUFBRSxTQUFTLENBQU8sVUFBVTtBQUM5RSxhQUFLLE9BQU8sU0FBUyxrQkFBa0I7QUFDdkMsY0FBTSxLQUFLLE9BQU8sYUFBYTtBQUFBLE1BQ2pDLEVBQUM7QUFBQSxJQUNIO0FBRUYsUUFBSSx3QkFBUSxXQUFXLEVBQ3BCLFFBQVEsaUNBQWlDLEVBQ3pDLFFBQVEsMElBQTBJLEVBQ2xKO0FBQUEsTUFBVSxDQUFDLFFBQ1YsSUFBSSxjQUFjLE9BQU8sRUFBRSxXQUFXLEVBQUUsUUFBUSxNQUFZO0FBQzFELGNBQU0sS0FBSyxPQUFPLG9CQUFvQjtBQUFBLE1BQ3hDLEVBQUM7QUFBQSxJQUNIO0FBR0YsZ0JBQVksU0FBUyxNQUFNLEVBQUUsTUFBTSxnREFBMkMsQ0FBQztBQUMvRSxnQkFBWSxTQUFTLEtBQUs7QUFBQSxNQUN4QixNQUFNO0FBQUEsTUFDTixLQUFLO0FBQUEsSUFDUCxDQUFDO0FBRUQsVUFBTSxZQUFXLFVBQUssT0FBTyxTQUFTLGlCQUFyQixZQUFxQyxDQUFDO0FBRXZELFVBQU0sV0FBVyxNQUFZO0FBQzNCLFlBQU0sS0FBSyxPQUFPLGFBQWE7QUFDL0IsV0FBSyxRQUFRO0FBQUEsSUFDZjtBQUVBLGFBQVMsUUFBUSxDQUFDLEtBQUssUUFBUTtBQUM3QixZQUFNLElBQUksSUFBSSx3QkFBUSxXQUFXLEVBQzlCLFFBQVEsWUFBWSxNQUFNLENBQUMsRUFBRSxFQUM3QixRQUFRLDZCQUF3QjtBQUVuQyxRQUFFO0FBQUEsUUFBUSxDQUFDLE1BQUc7QUF0SXBCLGNBQUFDO0FBdUlRLG1CQUNHLGVBQWUseUJBQXlCLEVBQ3hDLFVBQVNBLE1BQUEsSUFBSSxjQUFKLE9BQUFBLE1BQWlCLEVBQUUsRUFDNUIsU0FBUyxDQUFPLE1BQU07QUFDckIsaUJBQUssT0FBTyxTQUFTLGFBQWEsR0FBRyxFQUFFLFlBQVk7QUFDbkQsa0JBQU0sS0FBSyxPQUFPLGFBQWE7QUFBQSxVQUNqQyxFQUFDO0FBQUE7QUFBQSxNQUNMO0FBRUEsUUFBRTtBQUFBLFFBQVEsQ0FBQyxNQUFHO0FBaEpwQixjQUFBQTtBQWlKUSxtQkFDRyxlQUFlLG9DQUFvQyxFQUNuRCxVQUFTQSxNQUFBLElBQUksZUFBSixPQUFBQSxNQUFrQixFQUFFLEVBQzdCLFNBQVMsQ0FBTyxNQUFNO0FBQ3JCLGlCQUFLLE9BQU8sU0FBUyxhQUFhLEdBQUcsRUFBRSxhQUFhO0FBQ3BELGtCQUFNLEtBQUssT0FBTyxhQUFhO0FBQUEsVUFDakMsRUFBQztBQUFBO0FBQUEsTUFDTDtBQUVBLFFBQUU7QUFBQSxRQUFlLENBQUMsTUFDaEIsRUFDRyxRQUFRLE9BQU8sRUFDZixXQUFXLGdCQUFnQixFQUMzQixRQUFRLE1BQVk7QUFDbkIsZUFBSyxPQUFPLFNBQVMsYUFBYSxPQUFPLEtBQUssQ0FBQztBQUMvQyxnQkFBTSxTQUFTO0FBQUEsUUFDakIsRUFBQztBQUFBLE1BQ0w7QUFBQSxJQUNGLENBQUM7QUFFRCxRQUFJLHdCQUFRLFdBQVcsRUFDcEIsUUFBUSxhQUFhLEVBQ3JCLFFBQVEsb0RBQStDLEVBQ3ZEO0FBQUEsTUFBVSxDQUFDLFFBQ1YsSUFBSSxjQUFjLEtBQUssRUFBRSxRQUFRLE1BQVk7QUFDM0MsYUFBSyxPQUFPLFNBQVMsYUFBYSxLQUFLLEVBQUUsV0FBVyxJQUFJLFlBQVksR0FBRyxDQUFDO0FBQ3hFLGNBQU0sU0FBUztBQUFBLE1BQ2pCLEVBQUM7QUFBQSxJQUNIO0FBRUYsZ0JBQVksU0FBUyxLQUFLO0FBQUEsTUFDeEIsTUFBTTtBQUFBLE1BQ04sS0FBSztBQUFBLElBQ1AsQ0FBQztBQUFBLEVBQ0g7QUFDRjs7O0FDbktBLFNBQVMsWUFBWSxNQUF1QjtBQUMxQyxRQUFNLElBQUksS0FBSyxZQUFZO0FBQzNCLFNBQU8sTUFBTSxlQUFlLE1BQU0sZUFBZSxNQUFNO0FBQ3pEO0FBRUEsU0FBUyxlQUFlLEtBRVM7QUFDL0IsTUFBSTtBQUNGLFVBQU0sSUFBSSxJQUFJLElBQUksR0FBRztBQUNyQixRQUFJLEVBQUUsYUFBYSxTQUFTLEVBQUUsYUFBYSxRQUFRO0FBQ2pELGFBQU8sRUFBRSxJQUFJLE9BQU8sT0FBTyw0Q0FBNEMsRUFBRSxRQUFRLElBQUk7QUFBQSxJQUN2RjtBQUNBLFVBQU0sU0FBUyxFQUFFLGFBQWEsUUFBUSxPQUFPO0FBQzdDLFdBQU8sRUFBRSxJQUFJLE1BQU0sUUFBUSxNQUFNLEVBQUUsU0FBUztBQUFBLEVBQzlDLFNBQVE7QUFDTixXQUFPLEVBQUUsSUFBSSxPQUFPLE9BQU8sc0JBQXNCO0FBQUEsRUFDbkQ7QUFDRjtBQUdBLElBQU0sd0JBQXdCO0FBRzlCLElBQU0saUJBQWlCO0FBR3ZCLElBQU0sMEJBQTBCLE1BQU07QUFFdEMsU0FBUyxlQUFlLE1BQXNCO0FBQzVDLFNBQU8sVUFBVSxJQUFJLEVBQUU7QUFDekI7QUFFQSxTQUFlLHNCQUFzQixNQUErRztBQUFBO0FBQ2xKLFFBQUksT0FBTyxTQUFTLFVBQVU7QUFDNUIsWUFBTSxRQUFRLGVBQWUsSUFBSTtBQUNqQyxhQUFPLEVBQUUsSUFBSSxNQUFNLE1BQU0sTUFBTSxNQUFNO0FBQUEsSUFDdkM7QUFHQSxRQUFJLE9BQU8sU0FBUyxlQUFlLGdCQUFnQixNQUFNO0FBQ3ZELFlBQU0sUUFBUSxLQUFLO0FBQ25CLFVBQUksUUFBUTtBQUF5QixlQUFPLEVBQUUsSUFBSSxPQUFPLFFBQVEsYUFBYSxNQUFNO0FBQ3BGLFlBQU0sT0FBTyxNQUFNLEtBQUssS0FBSztBQUU3QixhQUFPLEVBQUUsSUFBSSxNQUFNLE1BQU0sTUFBTTtBQUFBLElBQ2pDO0FBRUEsUUFBSSxnQkFBZ0IsYUFBYTtBQUMvQixZQUFNLFFBQVEsS0FBSztBQUNuQixVQUFJLFFBQVE7QUFBeUIsZUFBTyxFQUFFLElBQUksT0FBTyxRQUFRLGFBQWEsTUFBTTtBQUNwRixZQUFNLE9BQU8sSUFBSSxZQUFZLFNBQVMsRUFBRSxPQUFPLE1BQU0sQ0FBQyxFQUFFLE9BQU8sSUFBSSxXQUFXLElBQUksQ0FBQztBQUNuRixhQUFPLEVBQUUsSUFBSSxNQUFNLE1BQU0sTUFBTTtBQUFBLElBQ2pDO0FBR0EsUUFBSSxnQkFBZ0IsWUFBWTtBQUM5QixZQUFNLFFBQVEsS0FBSztBQUNuQixVQUFJLFFBQVE7QUFBeUIsZUFBTyxFQUFFLElBQUksT0FBTyxRQUFRLGFBQWEsTUFBTTtBQUNwRixZQUFNLE9BQU8sSUFBSSxZQUFZLFNBQVMsRUFBRSxPQUFPLE1BQU0sQ0FBQyxFQUFFLE9BQU8sSUFBSTtBQUNuRSxhQUFPLEVBQUUsSUFBSSxNQUFNLE1BQU0sTUFBTTtBQUFBLElBQ2pDO0FBRUEsV0FBTyxFQUFFLElBQUksT0FBTyxRQUFRLG1CQUFtQjtBQUFBLEVBQ2pEO0FBQUE7QUFHQSxJQUFNLHVCQUF1QjtBQUc3QixJQUFNLG9CQUFvQjtBQUMxQixJQUFNLG1CQUFtQjtBQUd6QixJQUFNLHVCQUF1QjtBQXdCN0IsSUFBTSxxQkFBcUI7QUFFM0IsU0FBUyxnQkFBZ0IsT0FBNEI7QUFDbkQsUUFBTSxLQUFLLElBQUksV0FBVyxLQUFLO0FBQy9CLE1BQUksSUFBSTtBQUNSLFdBQVMsSUFBSSxHQUFHLElBQUksR0FBRyxRQUFRO0FBQUssU0FBSyxPQUFPLGFBQWEsR0FBRyxDQUFDLENBQUM7QUFDbEUsUUFBTSxNQUFNLEtBQUssQ0FBQztBQUNsQixTQUFPLElBQUksUUFBUSxPQUFPLEdBQUcsRUFBRSxRQUFRLE9BQU8sR0FBRyxFQUFFLFFBQVEsUUFBUSxFQUFFO0FBQ3ZFO0FBRUEsU0FBUyxVQUFVLE9BQTRCO0FBQzdDLFFBQU0sS0FBSyxJQUFJLFdBQVcsS0FBSztBQUMvQixTQUFPLE1BQU0sS0FBSyxFQUFFLEVBQ2pCLElBQUksQ0FBQyxNQUFNLEVBQUUsU0FBUyxFQUFFLEVBQUUsU0FBUyxHQUFHLEdBQUcsQ0FBQyxFQUMxQyxLQUFLLEVBQUU7QUFDWjtBQUVBLFNBQVMsVUFBVSxNQUEwQjtBQUMzQyxTQUFPLElBQUksWUFBWSxFQUFFLE9BQU8sSUFBSTtBQUN0QztBQUVBLFNBQWUsVUFBVSxPQUFxQztBQUFBO0FBQzVELFVBQU0sU0FBUyxNQUFNLE9BQU8sT0FBTyxPQUFPLFdBQVcsS0FBSztBQUMxRCxXQUFPLFVBQVUsTUFBTTtBQUFBLEVBQ3pCO0FBQUE7QUFFQSxTQUFlLDJCQUEyQixPQUFzRDtBQUFBO0FBRTlGLFFBQUksT0FBTztBQUNULFVBQUk7QUFDRixjQUFNLFdBQVcsTUFBTSxNQUFNLElBQUk7QUFDakMsYUFBSSxxQ0FBVSxRQUFNLHFDQUFVLGVBQWEscUNBQVU7QUFBZSxpQkFBTztBQUFBLE1BQzdFLFNBQVE7QUFBQSxNQUVSO0FBQUEsSUFDRjtBQUlBLFVBQU0sU0FBUyxhQUFhLFFBQVEsa0JBQWtCO0FBQ3RELFFBQUksUUFBUTtBQUNWLFVBQUk7QUFDRixjQUFNLFNBQVMsS0FBSyxNQUFNLE1BQU07QUFDaEMsYUFBSSxpQ0FBUSxRQUFNLGlDQUFRLGVBQWEsaUNBQVEsZ0JBQWU7QUFDNUQsY0FBSSxPQUFPO0FBQ1Qsa0JBQU0sTUFBTSxJQUFJLE1BQU07QUFDdEIseUJBQWEsV0FBVyxrQkFBa0I7QUFBQSxVQUM1QztBQUNBLGlCQUFPO0FBQUEsUUFDVDtBQUFBLE1BQ0YsU0FBUTtBQUVOLHFCQUFhLFdBQVcsa0JBQWtCO0FBQUEsTUFDNUM7QUFBQSxJQUNGO0FBR0EsVUFBTSxVQUFVLE1BQU0sT0FBTyxPQUFPLFlBQVksRUFBRSxNQUFNLFVBQVUsR0FBRyxNQUFNLENBQUMsUUFBUSxRQUFRLENBQUM7QUFDN0YsVUFBTSxTQUFTLE1BQU0sT0FBTyxPQUFPLFVBQVUsT0FBTyxRQUFRLFNBQVM7QUFDckUsVUFBTSxVQUFVLE1BQU0sT0FBTyxPQUFPLFVBQVUsT0FBTyxRQUFRLFVBQVU7QUFJdkUsVUFBTSxXQUFXLE1BQU0sVUFBVSxNQUFNO0FBRXZDLFVBQU0sV0FBMkI7QUFBQSxNQUMvQixJQUFJO0FBQUEsTUFDSixXQUFXLGdCQUFnQixNQUFNO0FBQUEsTUFDakMsZUFBZTtBQUFBLElBQ2pCO0FBRUEsUUFBSSxPQUFPO0FBQ1QsWUFBTSxNQUFNLElBQUksUUFBUTtBQUFBLElBQzFCLE9BQU87QUFFTCxtQkFBYSxRQUFRLG9CQUFvQixLQUFLLFVBQVUsUUFBUSxDQUFDO0FBQUEsSUFDbkU7QUFFQSxXQUFPO0FBQUEsRUFDVDtBQUFBO0FBRUEsU0FBUyx1QkFBdUIsUUFTckI7QUFDVCxRQUFNLFVBQVUsT0FBTyxRQUFRLE9BQU87QUFDdEMsUUFBTSxTQUFTLE9BQU8sT0FBTyxLQUFLLEdBQUc7QUFDckMsUUFBTSxPQUFPO0FBQUEsSUFDWDtBQUFBLElBQ0EsT0FBTztBQUFBLElBQ1AsT0FBTztBQUFBLElBQ1AsT0FBTztBQUFBLElBQ1AsT0FBTztBQUFBLElBQ1A7QUFBQSxJQUNBLE9BQU8sT0FBTyxVQUFVO0FBQUEsSUFDeEIsT0FBTyxTQUFTO0FBQUEsRUFDbEI7QUFDQSxNQUFJLFlBQVk7QUFBTSxTQUFLLEtBQUssT0FBTyxTQUFTLEVBQUU7QUFDbEQsU0FBTyxLQUFLLEtBQUssR0FBRztBQUN0QjtBQUVBLFNBQWUsa0JBQWtCLFVBQTBCLFNBQWlEO0FBQUE7QUFDMUcsVUFBTSxhQUFhLE1BQU0sT0FBTyxPQUFPO0FBQUEsTUFDckM7QUFBQSxNQUNBLFNBQVM7QUFBQSxNQUNULEVBQUUsTUFBTSxVQUFVO0FBQUEsTUFDbEI7QUFBQSxNQUNBLENBQUMsTUFBTTtBQUFBLElBQ1Q7QUFFQSxVQUFNLE1BQU0sTUFBTSxPQUFPLE9BQU8sS0FBSyxFQUFFLE1BQU0sVUFBVSxHQUFHLFlBQVksVUFBVSxPQUFPLENBQTRCO0FBQ25ILFdBQU8sRUFBRSxXQUFXLGdCQUFnQixHQUFHLEVBQUU7QUFBQSxFQUMzQztBQUFBO0FBRUEsU0FBUyw4QkFBOEIsS0FBa0I7QUEzT3pEO0FBNE9FLE1BQUksQ0FBQztBQUFLLFdBQU87QUFHakIsUUFBTSxXQUFVLGVBQUksWUFBSixZQUFlLElBQUksWUFBbkIsWUFBOEI7QUFDOUMsTUFBSSxPQUFPLFlBQVk7QUFBVSxXQUFPO0FBRXhDLE1BQUksTUFBTSxRQUFRLE9BQU8sR0FBRztBQUMxQixVQUFNLFFBQVEsUUFDWCxPQUFPLENBQUMsTUFBTSxLQUFLLE9BQU8sTUFBTSxZQUFZLEVBQUUsU0FBUyxVQUFVLE9BQU8sRUFBRSxTQUFTLFFBQVEsRUFDM0YsSUFBSSxDQUFDLE1BQU0sRUFBRSxJQUFJO0FBQ3BCLFdBQU8sTUFBTSxLQUFLLElBQUk7QUFBQSxFQUN4QjtBQUdBLE1BQUk7QUFDRixXQUFPLEtBQUssVUFBVSxPQUFPO0FBQUEsRUFDL0IsU0FBUTtBQUNOLFdBQU8sT0FBTyxPQUFPO0FBQUEsRUFDdkI7QUFDRjtBQUVBLFNBQVMsa0JBQWtCLFlBQW9CLFVBQTJCO0FBQ3hFLE1BQUksYUFBYTtBQUFZLFdBQU87QUFFcEMsTUFBSSxlQUFlLFVBQVUsYUFBYTtBQUFtQixXQUFPO0FBQ3BFLFNBQU87QUFDVDtBQUVPLElBQU0sbUJBQU4sTUFBdUI7QUFBQSxFQThCNUIsWUFBWSxZQUFvQixNQUEyRTtBQTdCM0csU0FBUSxLQUF1QjtBQUMvQixTQUFRLGlCQUF1RDtBQUMvRCxTQUFRLGlCQUF3RDtBQUNoRSxTQUFRLGVBQXFEO0FBQzdELFNBQVEsbUJBQW1CO0FBRTNCLFNBQVEsTUFBTTtBQUNkLFNBQVEsUUFBUTtBQUNoQixTQUFRLFlBQVk7QUFDcEIsU0FBUSxrQkFBa0Isb0JBQUksSUFBNEI7QUFDMUQsU0FBUSxVQUFVO0FBR2xCO0FBQUEsU0FBUSxjQUE2QjtBQUdyQztBQUFBLFNBQVEsZ0JBQXlDO0FBRWpELGlCQUF1QjtBQUV2QixxQkFBc0Q7QUFDdEQseUJBQXlEO0FBQ3pELDJCQUErQztBQUcvQyxTQUFRLGtCQUFrQjtBQUUxQixTQUFRLG1CQUFtQjtBQWlhM0IsU0FBUSx1QkFBdUI7QUE5WjdCLFNBQUssYUFBYTtBQUNsQixTQUFLLGdCQUFnQiw2QkFBTTtBQUMzQixTQUFLLGtCQUFrQixRQUFRLDZCQUFNLGVBQWU7QUFBQSxFQUN0RDtBQUFBLEVBRUEsUUFBUSxLQUFhLE9BQWUsTUFBNEM7QUE1U2xGO0FBNlNJLFNBQUssTUFBTTtBQUNYLFNBQUssUUFBUTtBQUNiLFNBQUssa0JBQWtCLFNBQVEsa0NBQU0sb0JBQU4sWUFBeUIsS0FBSyxlQUFlO0FBQzVFLFNBQUssbUJBQW1CO0FBR3hCLFVBQU0sU0FBUyxlQUFlLEdBQUc7QUFDakMsUUFBSSxDQUFDLE9BQU8sSUFBSTtBQUNkLGlCQUFLLGNBQUwsOEJBQWlCLEVBQUUsTUFBTSxTQUFTLFNBQVMsRUFBRSxTQUFTLE9BQU8sTUFBTSxFQUFFO0FBQ3JFO0FBQUEsSUFDRjtBQUNBLFFBQUksT0FBTyxXQUFXLFFBQVEsQ0FBQyxZQUFZLE9BQU8sSUFBSSxLQUFLLENBQUMsS0FBSyxpQkFBaUI7QUFDaEYsaUJBQUssY0FBTCw4QkFBaUI7QUFBQSxRQUNmLE1BQU07QUFBQSxRQUNOLFNBQVMsRUFBRSxTQUFTLHNHQUFzRztBQUFBLE1BQzVIO0FBQ0E7QUFBQSxJQUNGO0FBRUEsU0FBSyxTQUFTO0FBQUEsRUFDaEI7QUFBQSxFQUVBLGFBQW1CO0FBQ2pCLFNBQUssbUJBQW1CO0FBQ3hCLFNBQUssWUFBWTtBQUNqQixTQUFLLGNBQWM7QUFDbkIsU0FBSyxnQkFBZ0I7QUFDckIsU0FBSyxZQUFZLEtBQUs7QUFDdEIsUUFBSSxLQUFLLElBQUk7QUFDWCxXQUFLLEdBQUcsTUFBTTtBQUNkLFdBQUssS0FBSztBQUFBLElBQ1o7QUFDQSxTQUFLLFVBQVUsY0FBYztBQUFBLEVBQy9CO0FBQUEsRUFFQSxjQUFjLFlBQTBCO0FBQ3RDLFNBQUssYUFBYSxXQUFXLEtBQUs7QUFFbEMsU0FBSyxjQUFjO0FBQ25CLFNBQUssZ0JBQWdCO0FBQ3JCLFNBQUssWUFBWSxLQUFLO0FBQUEsRUFDeEI7QUFBQTtBQUFBLEVBSU0sWUFBWSxTQUFnQztBQUFBO0FBQ2hELFVBQUksS0FBSyxVQUFVLGFBQWE7QUFDOUIsY0FBTSxJQUFJLE1BQU0sMkNBQXNDO0FBQUEsTUFDeEQ7QUFFQSxZQUFNLFFBQVEsWUFBWSxLQUFLLElBQUksQ0FBQyxJQUFJLEtBQUssT0FBTyxFQUFFLFNBQVMsRUFBRSxFQUFFLE1BQU0sR0FBRyxDQUFDLENBQUM7QUFHOUUsWUFBTSxNQUFNLE1BQU0sS0FBSyxhQUFhLGFBQWE7QUFBQSxRQUMvQyxZQUFZLEtBQUs7QUFBQSxRQUNqQjtBQUFBLFFBQ0EsZ0JBQWdCO0FBQUE7QUFBQSxNQUVsQixDQUFDO0FBR0QsWUFBTSxpQkFBaUIsUUFBTywyQkFBSyxXQUFTLDJCQUFLLG1CQUFrQixFQUFFO0FBQ3JFLFdBQUssY0FBYyxrQkFBa0I7QUFDckMsV0FBSyxZQUFZLElBQUk7QUFDckIsV0FBSyx5QkFBeUI7QUFBQSxJQUNoQztBQUFBO0FBQUE7QUFBQSxFQUdNLGlCQUFtQztBQUFBO0FBQ3ZDLFVBQUksS0FBSyxVQUFVLGFBQWE7QUFDOUIsZUFBTztBQUFBLE1BQ1Q7QUFHQSxVQUFJLEtBQUssZUFBZTtBQUN0QixlQUFPLEtBQUs7QUFBQSxNQUNkO0FBRUEsWUFBTSxRQUFRLEtBQUs7QUFDbkIsVUFBSSxDQUFDLE9BQU87QUFDVixlQUFPO0FBQUEsTUFDVDtBQUVBLFdBQUssaUJBQWlCLE1BQVk7QUFDaEMsWUFBSTtBQUNGLGdCQUFNLEtBQUssYUFBYSxjQUFjLEVBQUUsWUFBWSxLQUFLLFlBQVksTUFBTSxDQUFDO0FBQzVFLGlCQUFPO0FBQUEsUUFDVCxTQUFTLEtBQUs7QUFDWixrQkFBUSxNQUFNLGdDQUFnQyxHQUFHO0FBQ2pELGlCQUFPO0FBQUEsUUFDVCxVQUFFO0FBRUEsZUFBSyxjQUFjO0FBQ25CLGVBQUssWUFBWSxLQUFLO0FBQ3RCLGVBQUssZ0JBQWdCO0FBQUEsUUFDdkI7QUFBQSxNQUNGLElBQUc7QUFFSCxhQUFPLEtBQUs7QUFBQSxJQUNkO0FBQUE7QUFBQSxFQUVRLFdBQWlCO0FBQ3ZCLFFBQUksS0FBSyxJQUFJO0FBQ1gsV0FBSyxHQUFHLFNBQVM7QUFDakIsV0FBSyxHQUFHLFVBQVU7QUFDbEIsV0FBSyxHQUFHLFlBQVk7QUFDcEIsV0FBSyxHQUFHLFVBQVU7QUFDbEIsV0FBSyxHQUFHLE1BQU07QUFDZCxXQUFLLEtBQUs7QUFBQSxJQUNaO0FBRUEsU0FBSyxVQUFVLFlBQVk7QUFFM0IsVUFBTSxLQUFLLElBQUksVUFBVSxLQUFLLEdBQUc7QUFDakMsU0FBSyxLQUFLO0FBRVYsUUFBSSxlQUE4QjtBQUNsQyxRQUFJLGlCQUFpQjtBQUVyQixVQUFNLGFBQWEsTUFBWTtBQUM3QixVQUFJO0FBQWdCO0FBQ3BCLFVBQUksQ0FBQztBQUFjO0FBQ25CLHVCQUFpQjtBQUVqQixVQUFJO0FBQ0YsY0FBTSxXQUFXLE1BQU0sMkJBQTJCLEtBQUssYUFBYTtBQUNwRSxjQUFNLGFBQWEsS0FBSyxJQUFJO0FBQzVCLGNBQU0sVUFBVSx1QkFBdUI7QUFBQSxVQUNyQyxVQUFVLFNBQVM7QUFBQSxVQUNuQixVQUFVO0FBQUEsVUFDVixZQUFZO0FBQUEsVUFDWixNQUFNO0FBQUEsVUFDTixRQUFRLENBQUMsaUJBQWlCLGdCQUFnQjtBQUFBLFVBQzFDO0FBQUEsVUFDQSxPQUFPLEtBQUs7QUFBQSxVQUNaLE9BQU87QUFBQSxRQUNULENBQUM7QUFDRCxjQUFNLE1BQU0sTUFBTSxrQkFBa0IsVUFBVSxPQUFPO0FBRXJELGNBQU0sTUFBTSxNQUFNLEtBQUssYUFBYSxXQUFXO0FBQUEsVUFDNUMsYUFBYTtBQUFBLFVBQ2IsYUFBYTtBQUFBLFVBQ2IsUUFBUTtBQUFBLFlBQ04sSUFBSTtBQUFBLFlBQ0osTUFBTTtBQUFBLFlBQ04sU0FBUztBQUFBLFlBQ1QsVUFBVTtBQUFBLFVBQ1o7QUFBQSxVQUNBLE1BQU07QUFBQSxVQUNOLFFBQVEsQ0FBQyxpQkFBaUIsZ0JBQWdCO0FBQUEsVUFDMUMsUUFBUTtBQUFBLFlBQ04sSUFBSSxTQUFTO0FBQUEsWUFDYixXQUFXLFNBQVM7QUFBQSxZQUNwQixXQUFXLElBQUk7QUFBQSxZQUNmLFVBQVU7QUFBQSxZQUNWLE9BQU87QUFBQSxVQUNUO0FBQUEsVUFDQSxNQUFNO0FBQUEsWUFDSixPQUFPLEtBQUs7QUFBQSxVQUNkO0FBQUEsUUFDRixDQUFDO0FBRUQsYUFBSyxVQUFVLFdBQVc7QUFDMUIsYUFBSyxtQkFBbUI7QUFDeEIsWUFBSSxnQkFBZ0I7QUFDbEIsdUJBQWEsY0FBYztBQUMzQiwyQkFBaUI7QUFBQSxRQUNuQjtBQUNBLGFBQUssZ0JBQWdCO0FBQUEsTUFDeEIsU0FBUyxLQUFLO0FBQ1osZ0JBQVEsTUFBTSx1Q0FBdUMsR0FBRztBQUN4RCxXQUFHLE1BQU07QUFBQSxNQUNYO0FBQUEsSUFDRjtBQUVBLFFBQUksaUJBQXVEO0FBRTNELE9BQUcsU0FBUyxNQUFNO0FBQ2hCLFdBQUssVUFBVSxhQUFhO0FBRTVCLFVBQUk7QUFBZ0IscUJBQWEsY0FBYztBQUMvQyx1QkFBaUIsV0FBVyxNQUFNO0FBRWhDLFlBQUksS0FBSyxVQUFVLGlCQUFpQixDQUFDLEtBQUssa0JBQWtCO0FBQzFELGtCQUFRLEtBQUssOERBQThEO0FBQzNFLGFBQUcsTUFBTTtBQUFBLFFBQ1g7QUFBQSxNQUNGLEdBQUcsb0JBQW9CO0FBQUEsSUFDekI7QUFFQSxPQUFHLFlBQVksQ0FBQyxVQUF3QjtBQUV0QyxZQUFNLE1BQVk7QUE3ZXhCO0FBOGVRLGNBQU0sYUFBYSxNQUFNLHNCQUFzQixNQUFNLElBQUk7QUFDekQsWUFBSSxDQUFDLFdBQVcsSUFBSTtBQUNsQixjQUFJLFdBQVcsV0FBVyxhQUFhO0FBQ3JDLG9CQUFRLE1BQU0sd0RBQXdEO0FBQ3RFLGVBQUcsTUFBTTtBQUFBLFVBQ1gsT0FBTztBQUNMLG9CQUFRLE1BQU0scURBQXFEO0FBQUEsVUFDckU7QUFDQTtBQUFBLFFBQ0Y7QUFFQSxZQUFJLFdBQVcsUUFBUSx5QkFBeUI7QUFDOUMsa0JBQVEsTUFBTSx3REFBd0Q7QUFDdEUsYUFBRyxNQUFNO0FBQ1Q7QUFBQSxRQUNGO0FBRUEsWUFBSTtBQUNKLFlBQUk7QUFDRixrQkFBUSxLQUFLLE1BQU0sV0FBVyxJQUFJO0FBQUEsUUFDcEMsU0FBUTtBQUNOLGtCQUFRLE1BQU0sNkNBQTZDO0FBQzNEO0FBQUEsUUFDRjtBQUdBLFlBQUksTUFBTSxTQUFTLE9BQU87QUFDeEIsZUFBSyxxQkFBcUIsS0FBSztBQUMvQjtBQUFBLFFBQ0Y7QUFHQSxZQUFJLE1BQU0sU0FBUyxTQUFTO0FBQzFCLGNBQUksTUFBTSxVQUFVLHFCQUFxQjtBQUN2Qyw2QkFBZSxXQUFNLFlBQU4sbUJBQWUsVUFBUztBQUV2QyxpQkFBSyxXQUFXO0FBQ2hCO0FBQUEsVUFDRjtBQUVBLGNBQUksTUFBTSxVQUFVLFFBQVE7QUFDMUIsaUJBQUssc0JBQXNCLEtBQUs7QUFBQSxVQUNsQztBQUNBO0FBQUEsUUFDRjtBQUdBLGdCQUFRLE1BQU0sOEJBQThCLEVBQUUsTUFBTSwrQkFBTyxNQUFNLE9BQU8sK0JBQU8sT0FBTyxJQUFJLCtCQUFPLEdBQUcsQ0FBQztBQUFBLE1BQ3ZHLElBQUc7QUFBQSxJQUNMO0FBRUEsVUFBTSxzQkFBc0IsTUFBTTtBQUNoQyxVQUFJLGdCQUFnQjtBQUNsQixxQkFBYSxjQUFjO0FBQzNCLHlCQUFpQjtBQUFBLE1BQ25CO0FBQUEsSUFDRjtBQUVBLE9BQUcsVUFBVSxNQUFNO0FBQ2pCLDBCQUFvQjtBQUNwQixXQUFLLFlBQVk7QUFDakIsV0FBSyxjQUFjO0FBQ25CLFdBQUssZ0JBQWdCO0FBQ3JCLFdBQUssWUFBWSxLQUFLO0FBQ3RCLFdBQUssVUFBVSxjQUFjO0FBRTdCLGlCQUFXLFdBQVcsS0FBSyxnQkFBZ0IsT0FBTyxHQUFHO0FBQ25ELFlBQUksUUFBUTtBQUFTLHVCQUFhLFFBQVEsT0FBTztBQUNqRCxnQkFBUSxPQUFPLElBQUksTUFBTSxtQkFBbUIsQ0FBQztBQUFBLE1BQy9DO0FBQ0EsV0FBSyxnQkFBZ0IsTUFBTTtBQUUzQixVQUFJLENBQUMsS0FBSyxrQkFBa0I7QUFDMUIsYUFBSyxtQkFBbUI7QUFBQSxNQUMxQjtBQUFBLElBQ0Y7QUFFQSxPQUFHLFVBQVUsQ0FBQyxPQUFjO0FBQzFCLDBCQUFvQjtBQUNwQixjQUFRLE1BQU0sOEJBQThCLEVBQUU7QUFBQSxJQUNoRDtBQUFBLEVBQ0Y7QUFBQSxFQUVRLHFCQUFxQixPQUFrQjtBQWprQmpEO0FBa2tCSSxVQUFNLFVBQVUsS0FBSyxnQkFBZ0IsSUFBSSxNQUFNLEVBQUU7QUFDakQsUUFBSSxDQUFDO0FBQVM7QUFFZCxTQUFLLGdCQUFnQixPQUFPLE1BQU0sRUFBRTtBQUNwQyxRQUFJLFFBQVE7QUFBUyxtQkFBYSxRQUFRLE9BQU87QUFFakQsUUFBSSxNQUFNO0FBQUksY0FBUSxRQUFRLE1BQU0sT0FBTztBQUFBO0FBQ3RDLGNBQVEsT0FBTyxJQUFJLFFBQU0sV0FBTSxVQUFOLG1CQUFhLFlBQVcsZ0JBQWdCLENBQUM7QUFBQSxFQUN6RTtBQUFBLEVBRVEsc0JBQXNCLE9BQWtCO0FBNWtCbEQ7QUE2a0JJLFVBQU0sVUFBVSxNQUFNO0FBQ3RCLFVBQU0scUJBQXFCLFFBQU8sbUNBQVMsZUFBYyxFQUFFO0FBQzNELFFBQUksQ0FBQyxzQkFBc0IsQ0FBQyxrQkFBa0IsS0FBSyxZQUFZLGtCQUFrQixHQUFHO0FBQ2xGO0FBQUEsSUFDRjtBQUlBLFVBQU0sZ0JBQWdCLFFBQU8sbUNBQVMsV0FBUyxtQ0FBUyxxQkFBa0Isd0NBQVMsU0FBVCxtQkFBZSxVQUFTLEVBQUU7QUFDcEcsUUFBSSxLQUFLLGVBQWUsaUJBQWlCLGtCQUFrQixLQUFLLGFBQWE7QUFDM0U7QUFBQSxJQUNGO0FBSUEsUUFBSSxFQUFDLG1DQUFTLFFBQU87QUFDbkI7QUFBQSxJQUNGO0FBQ0EsUUFBSSxRQUFRLFVBQVUsV0FBVyxRQUFRLFVBQVUsV0FBVztBQUM1RDtBQUFBLElBQ0Y7QUFHQSxVQUFNLE1BQU0sbUNBQVM7QUFDckIsVUFBTSxRQUFPLGdDQUFLLFNBQUwsWUFBYTtBQUcxQixRQUFJLFFBQVEsVUFBVSxXQUFXO0FBQy9CLFdBQUssY0FBYztBQUNuQixXQUFLLFlBQVksS0FBSztBQUV0QixVQUFJLENBQUM7QUFBSztBQUVWLFVBQUksU0FBUztBQUFhO0FBQUEsSUFDNUI7QUFHQSxRQUFJLFFBQVEsVUFBVSxTQUFTO0FBQzdCLFVBQUksU0FBUztBQUFhO0FBQzFCLFdBQUssY0FBYztBQUNuQixXQUFLLFlBQVksS0FBSztBQUFBLElBQ3hCO0FBRUEsVUFBTSxPQUFPLDhCQUE4QixHQUFHO0FBQzlDLFFBQUksQ0FBQztBQUFNO0FBR1gsUUFBSSxLQUFLLEtBQUssTUFBTSxnQkFBZ0I7QUFDbEM7QUFBQSxJQUNGO0FBRUEsZUFBSyxjQUFMLDhCQUFpQjtBQUFBLE1BQ2YsTUFBTTtBQUFBLE1BQ04sU0FBUztBQUFBLFFBQ1AsU0FBUztBQUFBLFFBQ1QsTUFBTTtBQUFBLFFBQ04sV0FBVyxLQUFLLElBQUk7QUFBQSxNQUN0QjtBQUFBLElBQ0Y7QUFBQSxFQUNGO0FBQUEsRUFFUSxhQUFhLFFBQWdCLFFBQTJCO0FBQzlELFdBQU8sSUFBSSxRQUFRLENBQUMsU0FBUyxXQUFXO0FBQ3RDLFVBQUksQ0FBQyxLQUFLLE1BQU0sS0FBSyxHQUFHLGVBQWUsVUFBVSxNQUFNO0FBQ3JELGVBQU8sSUFBSSxNQUFNLHlCQUF5QixDQUFDO0FBQzNDO0FBQUEsTUFDRjtBQUVBLFVBQUksS0FBSyxnQkFBZ0IsUUFBUSxzQkFBc0I7QUFDckQsZUFBTyxJQUFJLE1BQU0sZ0NBQWdDLEtBQUssZ0JBQWdCLElBQUksR0FBRyxDQUFDO0FBQzlFO0FBQUEsTUFDRjtBQUVBLFlBQU0sS0FBSyxPQUFPLEVBQUUsS0FBSyxTQUFTO0FBRWxDLFlBQU0sVUFBMEIsRUFBRSxTQUFTLFFBQVEsU0FBUyxLQUFLO0FBQ2pFLFdBQUssZ0JBQWdCLElBQUksSUFBSSxPQUFPO0FBRXBDLFlBQU0sVUFBVSxLQUFLLFVBQVU7QUFBQSxRQUM3QixNQUFNO0FBQUEsUUFDTjtBQUFBLFFBQ0E7QUFBQSxRQUNBO0FBQUEsTUFDRixDQUFDO0FBRUQsVUFBSTtBQUNGLGFBQUssR0FBRyxLQUFLLE9BQU87QUFBQSxNQUN0QixTQUFTLEtBQUs7QUFDWixhQUFLLGdCQUFnQixPQUFPLEVBQUU7QUFDOUIsZUFBTyxHQUFHO0FBQ1Y7QUFBQSxNQUNGO0FBRUEsY0FBUSxVQUFVLFdBQVcsTUFBTTtBQUNqQyxZQUFJLEtBQUssZ0JBQWdCLElBQUksRUFBRSxHQUFHO0FBQ2hDLGVBQUssZ0JBQWdCLE9BQU8sRUFBRTtBQUM5QixpQkFBTyxJQUFJLE1BQU0sb0JBQW9CLE1BQU0sRUFBRSxDQUFDO0FBQUEsUUFDaEQ7QUFBQSxNQUNGLEdBQUcsR0FBTTtBQUFBLElBQ1gsQ0FBQztBQUFBLEVBQ0g7QUFBQSxFQUVRLHFCQUEyQjtBQUNqQyxRQUFJLEtBQUssbUJBQW1CO0FBQU07QUFFbEMsVUFBTSxVQUFVLEVBQUUsS0FBSztBQUN2QixVQUFNLE1BQU0sS0FBSyxJQUFJLGtCQUFrQixvQkFBb0IsS0FBSyxJQUFJLEdBQUcsVUFBVSxDQUFDLENBQUM7QUFFbkYsVUFBTSxTQUFTLE1BQU0sS0FBSyxPQUFPO0FBQ2pDLFVBQU0sUUFBUSxLQUFLLE1BQU0sTUFBTSxNQUFNO0FBRXJDLFNBQUssaUJBQWlCLFdBQVcsTUFBTTtBQUNyQyxXQUFLLGlCQUFpQjtBQUN0QixVQUFJLENBQUMsS0FBSyxrQkFBa0I7QUFDMUIsZ0JBQVEsSUFBSSw4QkFBOEIsS0FBSyxHQUFHLG1CQUFjLE9BQU8sS0FBSyxLQUFLLEtBQUs7QUFDdEYsYUFBSyxTQUFTO0FBQUEsTUFDaEI7QUFBQSxJQUNGLEdBQUcsS0FBSztBQUFBLEVBQ1Y7QUFBQSxFQUlRLGtCQUF3QjtBQUM5QixTQUFLLGVBQWU7QUFDcEIsU0FBSyxpQkFBaUIsWUFBWSxNQUFNO0FBenNCNUM7QUEwc0JNLFlBQUksVUFBSyxPQUFMLG1CQUFTLGdCQUFlLFVBQVU7QUFBTTtBQUM1QyxVQUFJLEtBQUssR0FBRyxpQkFBaUIsR0FBRztBQUM5QixjQUFNLE1BQU0sS0FBSyxJQUFJO0FBRXJCLFlBQUksTUFBTSxLQUFLLHVCQUF1QixJQUFJLEtBQVE7QUFDaEQsZUFBSyx1QkFBdUI7QUFDNUIsa0JBQVEsS0FBSyxtRUFBOEQ7QUFBQSxRQUM3RTtBQUFBLE1BQ0Y7QUFBQSxJQUNGLEdBQUcscUJBQXFCO0FBQUEsRUFDMUI7QUFBQSxFQUVRLGlCQUF1QjtBQUM3QixRQUFJLEtBQUssZ0JBQWdCO0FBQ3ZCLG9CQUFjLEtBQUssY0FBYztBQUNqQyxXQUFLLGlCQUFpQjtBQUFBLElBQ3hCO0FBQUEsRUFDRjtBQUFBLEVBRVEsY0FBb0I7QUFDMUIsU0FBSyxlQUFlO0FBQ3BCLFNBQUssNEJBQTRCO0FBQ2pDLFFBQUksS0FBSyxnQkFBZ0I7QUFDdkIsbUJBQWEsS0FBSyxjQUFjO0FBQ2hDLFdBQUssaUJBQWlCO0FBQUEsSUFDeEI7QUFBQSxFQUNGO0FBQUEsRUFFUSxVQUFVLE9BQTRCO0FBdHVCaEQ7QUF1dUJJLFFBQUksS0FBSyxVQUFVO0FBQU87QUFDMUIsU0FBSyxRQUFRO0FBQ2IsZUFBSyxrQkFBTCw4QkFBcUI7QUFBQSxFQUN2QjtBQUFBLEVBRVEsWUFBWSxTQUF3QjtBQTV1QjlDO0FBNnVCSSxRQUFJLEtBQUssWUFBWTtBQUFTO0FBQzlCLFNBQUssVUFBVTtBQUNmLGVBQUssb0JBQUwsOEJBQXVCO0FBRXZCLFFBQUksQ0FBQyxTQUFTO0FBQ1osV0FBSyw0QkFBNEI7QUFBQSxJQUNuQztBQUFBLEVBQ0Y7QUFBQSxFQUVRLDJCQUFpQztBQUN2QyxTQUFLLDRCQUE0QjtBQUNqQyxTQUFLLGVBQWUsV0FBVyxNQUFNO0FBRW5DLFdBQUssWUFBWSxLQUFLO0FBQUEsSUFDeEIsR0FBRyxjQUFjO0FBQUEsRUFDbkI7QUFBQSxFQUVRLDhCQUFvQztBQUMxQyxRQUFJLEtBQUssY0FBYztBQUNyQixtQkFBYSxLQUFLLFlBQVk7QUFDOUIsV0FBSyxlQUFlO0FBQUEsSUFDdEI7QUFBQSxFQUNGO0FBQ0Y7OztBQ3B3QkEsSUFBQUMsbUJBQXlGOzs7QUNHbEYsSUFBTSxjQUFOLE1BQWtCO0FBQUEsRUFBbEI7QUFDTCxTQUFRLFdBQTBCLENBQUM7QUFHbkM7QUFBQSxvQkFBZ0U7QUFFaEU7QUFBQSwwQkFBc0Q7QUFBQTtBQUFBLEVBRXRELFdBQVcsS0FBd0I7QUFYckM7QUFZSSxTQUFLLFNBQVMsS0FBSyxHQUFHO0FBQ3RCLGVBQUssbUJBQUwsOEJBQXNCO0FBQUEsRUFDeEI7QUFBQSxFQUVBLGNBQXNDO0FBQ3BDLFdBQU8sS0FBSztBQUFBLEVBQ2Q7QUFBQSxFQUVBLFFBQWM7QUFwQmhCO0FBcUJJLFNBQUssV0FBVyxDQUFDO0FBQ2pCLGVBQUssYUFBTCw4QkFBZ0IsQ0FBQztBQUFBLEVBQ25CO0FBQUE7QUFBQSxFQUdBLE9BQU8sa0JBQWtCLFNBQThCO0FBQ3JELFdBQU87QUFBQSxNQUNMLElBQUksT0FBTyxLQUFLLElBQUksQ0FBQyxJQUFJLEtBQUssT0FBTyxFQUFFLFNBQVMsRUFBRSxFQUFFLE1BQU0sR0FBRyxDQUFDLENBQUM7QUFBQSxNQUMvRCxNQUFNO0FBQUEsTUFDTjtBQUFBLE1BQ0EsV0FBVyxLQUFLLElBQUk7QUFBQSxJQUN0QjtBQUFBLEVBQ0Y7QUFBQTtBQUFBLEVBR0EsT0FBTyx1QkFBdUIsU0FBOEI7QUFDMUQsV0FBTztBQUFBLE1BQ0wsSUFBSSxPQUFPLEtBQUssSUFBSSxDQUFDLElBQUksS0FBSyxPQUFPLEVBQUUsU0FBUyxFQUFFLEVBQUUsTUFBTSxHQUFHLENBQUMsQ0FBQztBQUFBLE1BQy9ELE1BQU07QUFBQSxNQUNOO0FBQUEsTUFDQSxXQUFXLEtBQUssSUFBSTtBQUFBLElBQ3RCO0FBQUEsRUFDRjtBQUFBO0FBQUEsRUFHQSxPQUFPLG9CQUFvQixTQUFpQixRQUE4QixRQUFxQjtBQUM3RixXQUFPO0FBQUEsTUFDTCxJQUFJLE9BQU8sS0FBSyxJQUFJLENBQUM7QUFBQSxNQUNyQixNQUFNO0FBQUEsTUFDTjtBQUFBLE1BQ0E7QUFBQSxNQUNBLFdBQVcsS0FBSyxJQUFJO0FBQUEsSUFDdEI7QUFBQSxFQUNGO0FBQUEsRUFFQSxPQUFPLHFCQUFxQixZQUFpQztBQUMzRCxVQUFNLFFBQVEsV0FBVyxTQUFTLEtBQUssR0FBRyxXQUFXLE1BQU0sR0FBRyxFQUFFLENBQUMsU0FBSSxXQUFXLE1BQU0sR0FBRyxDQUFDLEtBQUs7QUFDL0YsV0FBTztBQUFBLE1BQ0wsSUFBSSxPQUFPLEtBQUssSUFBSSxDQUFDO0FBQUEsTUFDckIsTUFBTTtBQUFBLE1BQ04sT0FBTztBQUFBLE1BQ1AsTUFBTTtBQUFBLE1BQ04sT0FBTztBQUFBLE1BQ1AsU0FBUyxhQUFhLEtBQUs7QUFBQSxNQUMzQixXQUFXLEtBQUssSUFBSTtBQUFBLElBQ3RCO0FBQUEsRUFDRjtBQUNGOzs7QUNsRU8sU0FBUyxjQUFjLE1BQXNCO0FBQ2xELFFBQU0sVUFBVSxPQUFPLHNCQUFRLEVBQUUsRUFBRSxLQUFLO0FBQ3hDLE1BQUksQ0FBQztBQUFTLFdBQU87QUFDckIsU0FBTyxRQUFRLFNBQVMsR0FBRyxJQUFJLFVBQVUsR0FBRyxPQUFPO0FBQ3JEO0FBRU8sU0FBUyw0QkFBNEIsT0FBZSxVQUFpRDtBQUMxRyxRQUFNLE1BQU0sT0FBTyx3QkFBUyxFQUFFO0FBQzlCLGFBQVcsT0FBTyxVQUFVO0FBQzFCLFVBQU0sYUFBYSxjQUFjLElBQUksVUFBVTtBQUMvQyxVQUFNLFlBQVksY0FBYyxJQUFJLFNBQVM7QUFDN0MsUUFBSSxDQUFDLGNBQWMsQ0FBQztBQUFXO0FBRS9CLFFBQUksSUFBSSxXQUFXLFVBQVUsR0FBRztBQUM5QixZQUFNLE9BQU8sSUFBSSxNQUFNLFdBQVcsTUFBTTtBQUV4QyxhQUFPLEdBQUcsU0FBUyxHQUFHLElBQUksR0FBRyxRQUFRLFFBQVEsRUFBRTtBQUFBLElBQ2pEO0FBQUEsRUFDRjtBQUNBLFNBQU87QUFDVDtBQUtBLElBQU0sU0FBUztBQUdmLElBQU0sVUFBVSxXQUFDLHNGQUFnRixHQUFDO0FBSWxHLElBQU0sY0FBYztBQUViLFNBQVMsa0JBQWtCLE1BQTJCO0FBQzNELFFBQU0sSUFBSSxPQUFPLHNCQUFRLEVBQUU7QUFDM0IsUUFBTSxNQUFtQixDQUFDO0FBRTFCLGFBQVcsS0FBSyxFQUFFLFNBQVMsTUFBTSxHQUFHO0FBQ2xDLFFBQUksRUFBRSxVQUFVO0FBQVc7QUFDM0IsUUFBSSxLQUFLLEVBQUUsT0FBTyxFQUFFLE9BQU8sS0FBSyxFQUFFLFFBQVEsRUFBRSxDQUFDLEVBQUUsUUFBUSxLQUFLLEVBQUUsQ0FBQyxHQUFHLE1BQU0sTUFBTSxDQUFDO0FBQUEsRUFDakY7QUFFQSxhQUFXLEtBQUssRUFBRSxTQUFTLE9BQU8sR0FBRztBQUNuQyxRQUFJLEVBQUUsVUFBVTtBQUFXO0FBRzNCLFVBQU0sUUFBUSxFQUFFO0FBQ2hCLFVBQU0sTUFBTSxRQUFRLEVBQUUsQ0FBQyxFQUFFO0FBQ3pCLFVBQU0sY0FBYyxJQUFJLEtBQUssQ0FBQyxNQUFNLEVBQUUsU0FBUyxTQUFTLEVBQUUsT0FBTyxFQUFFLFNBQVMsU0FBUyxFQUFFLElBQUk7QUFDM0YsUUFBSTtBQUFhO0FBRWpCLFFBQUksS0FBSyxFQUFFLE9BQU8sS0FBSyxLQUFLLEVBQUUsQ0FBQyxHQUFHLE1BQU0sT0FBTyxDQUFDO0FBQUEsRUFDbEQ7QUFFQSxhQUFXLEtBQUssRUFBRSxTQUFTLFdBQVcsR0FBRztBQUN2QyxRQUFJLEVBQUUsVUFBVTtBQUFXO0FBRTNCLFVBQU0sUUFBUSxFQUFFO0FBQ2hCLFVBQU0sTUFBTSxRQUFRLEVBQUUsQ0FBQyxFQUFFO0FBQ3pCLFVBQU0sbUJBQW1CLElBQUksS0FBSyxDQUFDLE1BQU0sRUFBRSxPQUFPLEVBQUUsU0FBUyxTQUFTLEVBQUUsSUFBSTtBQUM1RSxRQUFJO0FBQWtCO0FBRXRCLFFBQUksS0FBSyxFQUFFLE9BQU8sS0FBSyxLQUFLLEVBQUUsQ0FBQyxHQUFHLE1BQU0sT0FBTyxDQUFDO0FBQUEsRUFDbEQ7QUFHQSxNQUFJLEtBQUssQ0FBQyxHQUFHLE1BQU0sRUFBRSxRQUFRLEVBQUUsVUFBVSxFQUFFLFNBQVMsUUFBUSxLQUFLLEVBQUU7QUFDbkUsUUFBTSxRQUFxQixDQUFDO0FBQzVCLGFBQVcsS0FBSyxLQUFLO0FBQ25CLFVBQU0sT0FBTyxNQUFNLE1BQU0sU0FBUyxDQUFDO0FBQ25DLFFBQUksQ0FBQyxNQUFNO0FBQ1QsWUFBTSxLQUFLLENBQUM7QUFDWjtBQUFBLElBQ0Y7QUFDQSxRQUFJLEVBQUUsUUFBUSxLQUFLO0FBQUs7QUFDeEIsVUFBTSxLQUFLLENBQUM7QUFBQSxFQUNkO0FBRUEsU0FBTztBQUNUOzs7QUN0RUEsU0FBc0IscUJBQXFCLEtBQXVDO0FBQUE7QUFDaEYsVUFBTSxPQUFPLElBQUksVUFBVSxjQUFjO0FBQ3pDLFFBQUksQ0FBQztBQUFNLGFBQU87QUFFbEIsUUFBSTtBQUNGLFlBQU0sVUFBVSxNQUFNLElBQUksTUFBTSxLQUFLLElBQUk7QUFDekMsYUFBTztBQUFBLFFBQ0wsT0FBTyxLQUFLO0FBQUEsUUFDWixNQUFNLEtBQUs7QUFBQSxRQUNYO0FBQUEsTUFDRjtBQUFBLElBQ0YsU0FBUyxLQUFLO0FBQ1osY0FBUSxNQUFNLDhDQUE4QyxHQUFHO0FBQy9ELGFBQU87QUFBQSxJQUNUO0FBQUEsRUFDRjtBQUFBOzs7QUhuQk8sSUFBTSwwQkFBMEI7QUFFdkMsSUFBTSxrQkFBTixjQUE4Qix1QkFBTTtBQUFBLEVBSWxDLFlBQVksTUFBd0IsY0FBc0IsVUFBbUM7QUFDM0YsVUFBTSxLQUFLLEdBQUc7QUFDZCxTQUFLLGVBQWU7QUFDcEIsU0FBSyxXQUFXO0FBQUEsRUFDbEI7QUFBQSxFQUVBLFNBQWU7QUFDYixVQUFNLEVBQUUsVUFBVSxJQUFJO0FBQ3RCLGNBQVUsTUFBTTtBQUVoQixjQUFVLFNBQVMsTUFBTSxFQUFFLE1BQU0sa0JBQWtCLENBQUM7QUFFcEQsUUFBSSxRQUFRLEtBQUs7QUFFakIsUUFBSSx5QkFBUSxTQUFTLEVBQ2xCLFFBQVEsYUFBYSxFQUNyQixRQUFRLDZGQUE2RixFQUNyRyxRQUFRLENBQUMsTUFBTTtBQUNkLFFBQUUsU0FBUyxLQUFLO0FBQ2hCLFFBQUUsU0FBUyxDQUFDLE1BQU07QUFDaEIsZ0JBQVE7QUFBQSxNQUNWLENBQUM7QUFBQSxJQUNILENBQUM7QUFFSCxRQUFJLHlCQUFRLFNBQVMsRUFDbEIsVUFBVSxDQUFDLE1BQU07QUFDaEIsUUFBRSxjQUFjLFFBQVE7QUFDeEIsUUFBRSxRQUFRLE1BQU0sS0FBSyxNQUFNLENBQUM7QUFBQSxJQUM5QixDQUFDLEVBQ0EsVUFBVSxDQUFDLE1BQU07QUFDaEIsUUFBRSxPQUFPO0FBQ1QsUUFBRSxjQUFjLFFBQVE7QUFDeEIsUUFBRSxRQUFRLE1BQU07QUFDZCxjQUFNLElBQUksTUFBTSxLQUFLLEVBQUUsWUFBWTtBQUNuQyxZQUFJLENBQUMsR0FBRztBQUNOLGNBQUksd0JBQU8sd0JBQXdCO0FBQ25DO0FBQUEsUUFDRjtBQUNBLFlBQUksQ0FBQyw2QkFBNkIsS0FBSyxDQUFDLEdBQUc7QUFDekMsY0FBSSx3QkFBTyw2Q0FBNkM7QUFDeEQ7QUFBQSxRQUNGO0FBQ0EsYUFBSyxTQUFTLENBQUM7QUFDZixhQUFLLE1BQU07QUFBQSxNQUNiLENBQUM7QUFBQSxJQUNILENBQUM7QUFBQSxFQUNMO0FBQ0Y7QUFFTyxJQUFNLG1CQUFOLGNBQStCLDBCQUFTO0FBQUEsRUE0QjdDLFlBQVksTUFBcUIsUUFBd0I7QUFDdkQsVUFBTSxJQUFJO0FBdkJaO0FBQUEsU0FBUSxjQUFjO0FBQ3RCLFNBQVEsWUFBWTtBQUdwQjtBQUFBLFNBQVEscUJBQXFCO0FBQzdCLFNBQVEsbUJBQWtDO0FBYTFDLFNBQVEsOEJBQThCO0FBRXRDLFNBQVEsa0JBQXFEO0FBSTNELFNBQUssU0FBUztBQUNkLFNBQUssY0FBYyxJQUFJLFlBQVk7QUFDbkMsU0FBSyxXQUFXLEtBQUssT0FBTyxlQUFlLEtBQUssT0FBTyxxQkFBcUIsQ0FBQztBQUc3RSxTQUFLLFNBQVMsWUFBWSxDQUFDLFFBQVE7QUFsR3ZDO0FBbUdNLFVBQUksSUFBSSxTQUFTLFdBQVc7QUFDMUIsYUFBSyxZQUFZLFdBQVcsWUFBWSx1QkFBdUIsSUFBSSxRQUFRLE9BQU8sQ0FBQztBQUFBLE1BQ3JGLFdBQVcsSUFBSSxTQUFTLFNBQVM7QUFDL0IsY0FBTSxXQUFVLFNBQUksUUFBUSxZQUFaLFlBQXVCO0FBQ3ZDLGFBQUssWUFBWSxXQUFXLFlBQVksb0JBQW9CLFVBQUssT0FBTyxJQUFJLE9BQU8sQ0FBQztBQUFBLE1BQ3RGO0FBQUEsSUFDRjtBQUFBLEVBQ0Y7QUFBQSxFQUVBLGNBQXNCO0FBQ3BCLFdBQU87QUFBQSxFQUNUO0FBQUEsRUFFQSxpQkFBeUI7QUFDdkIsV0FBTztBQUFBLEVBQ1Q7QUFBQSxFQUVBLFVBQWtCO0FBQ2hCLFdBQU87QUFBQSxFQUNUO0FBQUEsRUFFTSxTQUF3QjtBQUFBO0FBQzVCLFdBQUssT0FBTyxpQkFBaUI7QUFDN0IsV0FBSyxTQUFTO0FBR2QsV0FBSyxZQUFZLFdBQVcsQ0FBQyxTQUFTLEtBQUssZ0JBQWdCLElBQUk7QUFFL0QsV0FBSyxZQUFZLGlCQUFpQixDQUFDLFFBQVEsS0FBSyxlQUFlLEdBQUc7QUFHbEUsWUFBTSxLQUFLLEtBQUssT0FBTyxpQkFBaUI7QUFDeEMsVUFBSSxHQUFHLE9BQU87QUFDWixhQUFLLFNBQVMsUUFBUSxHQUFHLEtBQUssR0FBRyxPQUFPLEVBQUUsaUJBQWlCLEdBQUcsZ0JBQWdCLENBQUM7QUFBQSxNQUNqRixPQUFPO0FBQ0wsWUFBSSx3QkFBTyxpRUFBaUU7QUFBQSxNQUM5RTtBQUdBLFdBQUssU0FBUyxnQkFBZ0IsQ0FBQyxVQUFVO0FBRXZDLGNBQU0sT0FBTyxLQUFLO0FBQ2xCLGFBQUssbUJBQW1CO0FBRXhCLGNBQU0sTUFBTSxLQUFLLElBQUk7QUFDckIsY0FBTSxxQkFBcUI7QUFFM0IsY0FBTSxlQUFlLE1BQU0sTUFBTSxLQUFLLHFCQUFxQjtBQUMzRCxjQUFNLFNBQVMsQ0FBQyxTQUFpQjtBQUMvQixjQUFJLENBQUMsYUFBYTtBQUFHO0FBQ3JCLGVBQUsscUJBQXFCO0FBQzFCLGNBQUksd0JBQU8sSUFBSTtBQUFBLFFBQ2pCO0FBR0EsWUFBSSxTQUFTLGVBQWUsVUFBVSxnQkFBZ0I7QUFDcEQsaUJBQU8sMERBQWdEO0FBRXZELGVBQUssWUFBWSxXQUFXLFlBQVksb0JBQW9CLG9EQUFxQyxPQUFPLENBQUM7QUFBQSxRQUMzRztBQUdBLFlBQUksUUFBUSxTQUFTLGVBQWUsVUFBVSxhQUFhO0FBQ3pELGlCQUFPLDRCQUE0QjtBQUNuQyxlQUFLLFlBQVksV0FBVyxZQUFZLG9CQUFvQixzQkFBaUIsTUFBTSxDQUFDO0FBQUEsUUFDdEY7QUFFQSxhQUFLLGNBQWMsVUFBVTtBQUM3QixhQUFLLFVBQVUsWUFBWSxhQUFhLEtBQUssV0FBVztBQUN4RCxhQUFLLFVBQVUsUUFBUSxZQUFZLEtBQUs7QUFDeEMsYUFBSyxrQkFBa0I7QUFBQSxNQUN6QjtBQUdBLFdBQUssU0FBUyxrQkFBa0IsQ0FBQyxZQUFZO0FBQzNDLGFBQUssWUFBWTtBQUNqQixhQUFLLGtCQUFrQjtBQUFBLE1BQ3pCO0FBR0EsV0FBSyxtQkFBbUIsS0FBSyxTQUFTO0FBQ3RDLFdBQUssY0FBYyxLQUFLLFNBQVMsVUFBVTtBQUMzQyxXQUFLLFVBQVUsWUFBWSxhQUFhLEtBQUssV0FBVztBQUN4RCxXQUFLLFVBQVUsUUFBUSxZQUFZLEtBQUssU0FBUyxLQUFLO0FBQ3RELFdBQUssa0JBQWtCO0FBRXZCLFdBQUssZ0JBQWdCLEtBQUssWUFBWSxZQUFZLENBQUM7QUFHbkQsV0FBSyxtQkFBbUI7QUFBQSxJQUMxQjtBQUFBO0FBQUEsRUFFTSxVQUF5QjtBQUFBO0FBL0xqQztBQWdNSSxXQUFLLE9BQU8sbUJBQW1CO0FBQy9CLFdBQUssWUFBWSxXQUFXO0FBQzVCLFdBQUssWUFBWSxpQkFBaUI7QUFDbEMsV0FBSyxTQUFTLGdCQUFnQjtBQUM5QixXQUFLLFNBQVMsa0JBQWtCO0FBQ2hDLFdBQUssU0FBUyxXQUFXO0FBRXpCLFVBQUksS0FBSyxpQkFBaUI7QUFDeEIsbUJBQUssZUFBTCxtQkFBaUIsb0JBQW9CLFNBQVMsS0FBSztBQUNuRCxhQUFLLGtCQUFrQjtBQUFBLE1BQ3pCO0FBQUEsSUFDRjtBQUFBO0FBQUE7QUFBQSxFQUlRLFdBQWlCO0FBQ3ZCLFVBQU0sT0FBTyxLQUFLO0FBQ2xCLFNBQUssTUFBTTtBQUNYLFNBQUssU0FBUyxpQkFBaUI7QUFHL0IsVUFBTSxTQUFTLEtBQUssVUFBVSxFQUFFLEtBQUssZUFBZSxDQUFDO0FBQ3JELFdBQU8sV0FBVyxFQUFFLEtBQUssc0JBQXNCLE1BQU0sZ0JBQWdCLENBQUM7QUFDdEUsU0FBSyxZQUFZLE9BQU8sVUFBVSxFQUFFLEtBQUssbUJBQW1CLENBQUM7QUFDN0QsU0FBSyxVQUFVLFFBQVE7QUFHdkIsVUFBTSxVQUFVLEtBQUssVUFBVSxFQUFFLEtBQUssb0JBQW9CLENBQUM7QUFDM0QsWUFBUSxXQUFXLEVBQUUsS0FBSyx1QkFBdUIsTUFBTSxVQUFVLENBQUM7QUFFbEUsU0FBSyxnQkFBZ0IsUUFBUSxTQUFTLFVBQVUsRUFBRSxLQUFLLHVCQUF1QixDQUFDO0FBQy9FLFNBQUssb0JBQW9CLFFBQVEsU0FBUyxVQUFVLEVBQUUsS0FBSyxxQkFBcUIsTUFBTSxTQUFTLENBQUM7QUFDaEcsU0FBSyxnQkFBZ0IsUUFBUSxTQUFTLFVBQVUsRUFBRSxLQUFLLHFCQUFxQixNQUFNLFlBQU8sQ0FBQztBQUMxRixTQUFLLGlCQUFpQixRQUFRLFNBQVMsVUFBVSxFQUFFLEtBQUsscUJBQXFCLE1BQU0sT0FBTyxDQUFDO0FBRTNGLFNBQUssa0JBQWtCLGlCQUFpQixTQUFTLE1BQU0sS0FBSyxtQkFBbUIsQ0FBQztBQUNoRixTQUFLLGNBQWMsaUJBQWlCLFNBQVMsTUFBTTtBQUNqRCxVQUFJLENBQUMsS0FBSyxPQUFPLGFBQWEsR0FBRztBQUMvQixZQUFJLHdCQUFPLHFFQUFxRTtBQUNoRjtBQUFBLE1BQ0Y7QUFDQSxXQUFLLEtBQUssa0JBQWtCO0FBQUEsSUFDOUIsQ0FBQztBQUNELFNBQUssZUFBZSxpQkFBaUIsU0FBUyxNQUFNO0FBQ2xELFlBQU0sTUFBWTtBQUNoQixjQUFNLEtBQUssZUFBZSxNQUFNO0FBQ2hDLGFBQUssbUJBQW1CO0FBQ3hCLGFBQUssY0FBYyxRQUFRO0FBQzNCLGFBQUssY0FBYyxRQUFRO0FBQUEsTUFDN0IsSUFBRztBQUFBLElBQ0wsQ0FBQztBQUNELFNBQUssY0FBYyxpQkFBaUIsVUFBVSxNQUFNO0FBQ2xELFVBQUksS0FBSztBQUE2QjtBQUN0QyxZQUFNLE9BQU8sS0FBSyxjQUFjO0FBQ2hDLFVBQUksQ0FBQztBQUFNO0FBQ1gsWUFBTSxNQUFZO0FBQ2hCLGNBQU0sS0FBSyxlQUFlLElBQUk7QUFDOUIsYUFBSyxtQkFBbUI7QUFDeEIsYUFBSyxjQUFjLFFBQVE7QUFDM0IsYUFBSyxjQUFjLFFBQVE7QUFBQSxNQUM3QixJQUFHO0FBQUEsSUFDTCxDQUFDO0FBR0QsU0FBSyxhQUFhLEtBQUssVUFBVSxFQUFFLEtBQUssaUJBQWlCLENBQUM7QUFHMUQsU0FBSywrQkFBK0I7QUFHcEMsVUFBTSxTQUFTLEtBQUssVUFBVSxFQUFFLEtBQUssb0JBQW9CLENBQUM7QUFDMUQsU0FBSyxzQkFBc0IsT0FBTyxTQUFTLFNBQVMsRUFBRSxNQUFNLFdBQVcsQ0FBQztBQUN4RSxTQUFLLG9CQUFvQixLQUFLO0FBQzlCLFNBQUssb0JBQW9CLFVBQVUsS0FBSyxPQUFPLFNBQVM7QUFDeEQsVUFBTSxXQUFXLE9BQU8sU0FBUyxTQUFTLEVBQUUsTUFBTSxzQkFBc0IsQ0FBQztBQUN6RSxhQUFTLFVBQVU7QUFHbkIsVUFBTSxXQUFXLEtBQUssVUFBVSxFQUFFLEtBQUssa0JBQWtCLENBQUM7QUFDMUQsU0FBSyxVQUFVLFNBQVMsU0FBUyxZQUFZO0FBQUEsTUFDM0MsS0FBSztBQUFBLE1BQ0wsYUFBYTtBQUFBLElBQ2YsQ0FBQztBQUNELFNBQUssUUFBUSxPQUFPO0FBRXBCLFNBQUssVUFBVSxTQUFTLFNBQVMsVUFBVSxFQUFFLEtBQUssa0JBQWtCLE1BQU0sT0FBTyxDQUFDO0FBR2xGLFNBQUssUUFBUSxpQkFBaUIsU0FBUyxNQUFNLEtBQUssWUFBWSxDQUFDO0FBQy9ELFNBQUssUUFBUSxpQkFBaUIsV0FBVyxDQUFDLE1BQU07QUFDOUMsVUFBSSxFQUFFLFFBQVEsV0FBVyxDQUFDLEVBQUUsVUFBVTtBQUNwQyxVQUFFLGVBQWU7QUFDakIsYUFBSyxZQUFZO0FBQUEsTUFDbkI7QUFBQSxJQUNGLENBQUM7QUFFRCxTQUFLLFFBQVEsaUJBQWlCLFNBQVMsTUFBTTtBQUMzQyxXQUFLLFFBQVEsTUFBTSxTQUFTO0FBQzVCLFdBQUssUUFBUSxNQUFNLFNBQVMsR0FBRyxLQUFLLFFBQVEsWUFBWTtBQUFBLElBQzFELENBQUM7QUFBQSxFQUNIO0FBQUEsRUFFUSx5QkFBeUIsTUFBc0I7QUF0U3pEO0FBdVNJLFNBQUssOEJBQThCO0FBQ25DLFFBQUk7QUFDRixXQUFLLGNBQWMsTUFBTTtBQUV6QixZQUFNLFlBQVcsVUFBSyxPQUFPLFNBQVMsZUFBckIsWUFBbUMsUUFBUSxZQUFZO0FBQ3hFLFVBQUksU0FBUyxNQUFNLEtBQUssSUFBSSxJQUFJLENBQUMsU0FBUyxHQUFHLElBQUksRUFBRSxPQUFPLE9BQU8sQ0FBQyxDQUFDO0FBR25FLGVBQVMsT0FBTyxPQUFPLENBQUMsTUFBTSxNQUFNLFVBQVUsT0FBTyxDQUFDLEVBQUUsV0FBVyw2QkFBNkIsQ0FBQztBQUVqRyxVQUFJLE9BQU8sV0FBVyxHQUFHO0FBQ3ZCLGlCQUFTLENBQUMsTUFBTTtBQUFBLE1BQ2xCO0FBRUEsaUJBQVcsT0FBTyxRQUFRO0FBQ3hCLGNBQU0sTUFBTSxLQUFLLGNBQWMsU0FBUyxVQUFVLEVBQUUsT0FBTyxLQUFLLE1BQU0sSUFBSSxDQUFDO0FBQzNFLFlBQUksUUFBUTtBQUFTLGNBQUksV0FBVztBQUFBLE1BQ3RDO0FBRUEsVUFBSSxPQUFPLFNBQVMsT0FBTyxHQUFHO0FBQzVCLGFBQUssY0FBYyxRQUFRO0FBQUEsTUFDN0I7QUFDQSxXQUFLLGNBQWMsUUFBUTtBQUFBLElBQzdCLFVBQUU7QUFDQSxXQUFLLDhCQUE4QjtBQUFBLElBQ3JDO0FBQUEsRUFDRjtBQUFBLEVBRVEscUJBQTJCO0FBblVyQztBQW9VSSxVQUFNLGNBQWEsVUFBSyxPQUFPLFNBQVMsY0FBckIsWUFBa0MsSUFBSSxLQUFLO0FBQzlELFVBQU0sT0FBTSxVQUFLLE9BQU8sU0FBUyw0QkFBckIsWUFBZ0QsQ0FBQztBQUM3RCxVQUFNLE9BQU8sYUFBYSxNQUFNLFFBQVEsSUFBSSxTQUFTLENBQUMsSUFBSSxJQUFJLFNBQVMsSUFBSSxDQUFDO0FBRTVFLFVBQU0sU0FBUyxZQUFZLDhCQUE4QixTQUFTLEtBQUs7QUFDdkUsVUFBTSxXQUFXLFlBQ2IsS0FBSyxPQUFPLENBQUMsTUFBTTtBQUNqQixZQUFNLE1BQU0sT0FBTyxLQUFLLEVBQUUsRUFBRSxLQUFLLEVBQUUsWUFBWTtBQUMvQyxhQUFPLFFBQVEsVUFBVSxJQUFJLFdBQVcsU0FBUyxHQUFHO0FBQUEsSUFDdEQsQ0FBQyxJQUNELENBQUM7QUFFTCxTQUFLLHlCQUF5QixRQUFRO0FBQUEsRUFDeEM7QUFBQSxFQUVjLGVBQWUsWUFBbUM7QUFBQTtBQUM5RCxZQUFNLE9BQU8sV0FBVyxLQUFLLEVBQUUsWUFBWTtBQUMzQyxVQUFJLENBQUM7QUFBTTtBQUVYLFlBQU0sWUFBWSxLQUFLLE9BQU8sYUFBYTtBQUMzQyxVQUFJLFdBQVc7QUFDYixjQUFNLFNBQVMsOEJBQThCLFNBQVM7QUFDdEQsWUFBSSxFQUFFLFNBQVMsVUFBVSxTQUFTLFVBQVUsS0FBSyxXQUFXLFNBQVMsR0FBRyxJQUFJO0FBQzFFLGNBQUksd0JBQU8sbURBQW1EO0FBQzlEO0FBQUEsUUFDRjtBQUFBLE1BQ0YsT0FBTztBQUNMLFlBQUksU0FBUyxRQUFRO0FBQ25CLGNBQUksd0JBQU8saUVBQWlFO0FBQzVFO0FBQUEsUUFDRjtBQUFBLE1BQ0Y7QUFHQSxVQUFJO0FBQ0YsY0FBTSxLQUFLLFNBQVMsZUFBZTtBQUFBLE1BQ3JDLFNBQVE7QUFBQSxNQUVSO0FBR0EsV0FBSyxZQUFZLFdBQVcsWUFBWSxxQkFBcUIsSUFBSSxDQUFDO0FBR2xFLFlBQU0sS0FBSyxPQUFPLG1CQUFtQixJQUFJO0FBR3pDLFdBQUssU0FBUyxXQUFXO0FBQ3pCLFdBQUssU0FBUyxjQUFjLElBQUk7QUFFaEMsWUFBTSxLQUFLLEtBQUssT0FBTyxpQkFBaUI7QUFDeEMsVUFBSSxHQUFHLE9BQU87QUFDWixhQUFLLFNBQVMsUUFBUSxHQUFHLEtBQUssR0FBRyxPQUFPLEVBQUUsaUJBQWlCLEdBQUcsZ0JBQWdCLENBQUM7QUFBQSxNQUNqRixPQUFPO0FBQ0wsWUFBSSx3QkFBTyxpRUFBaUU7QUFBQSxNQUM5RTtBQUFBLElBQ0Y7QUFBQTtBQUFBLEVBRWMsb0JBQW1DO0FBQUE7QUFDL0MsWUFBTSxNQUFNLG9CQUFJLEtBQUs7QUFDckIsWUFBTSxNQUFNLENBQUMsTUFBYyxPQUFPLENBQUMsRUFBRSxTQUFTLEdBQUcsR0FBRztBQUNwRCxZQUFNLFlBQVksUUFBUSxJQUFJLFlBQVksQ0FBQyxHQUFHLElBQUksSUFBSSxTQUFTLElBQUksQ0FBQyxDQUFDLEdBQUcsSUFBSSxJQUFJLFFBQVEsQ0FBQyxDQUFDLElBQUksSUFBSSxJQUFJLFNBQVMsQ0FBQyxDQUFDLEdBQUcsSUFBSSxJQUFJLFdBQVcsQ0FBQyxDQUFDO0FBRXpJLFlBQU0sUUFBUSxJQUFJLGdCQUFnQixNQUFNLFdBQVcsQ0FBQyxXQUFXO0FBblluRTtBQW9ZTSxjQUFNLGNBQWEsVUFBSyxPQUFPLFNBQVMsY0FBckIsWUFBa0MsSUFBSSxLQUFLO0FBQzlELFlBQUksQ0FBQyxXQUFXO0FBQ2QsY0FBSSx3QkFBTyxnRUFBZ0U7QUFDM0U7QUFBQSxRQUNGO0FBQ0EsY0FBTSxNQUFNLDhCQUE4QixTQUFTLElBQUksTUFBTTtBQUM3RCxjQUFNLE1BQVk7QUFDaEIsZ0JBQU0sS0FBSyxlQUFlLEdBQUc7QUFDN0IsZUFBSyxtQkFBbUI7QUFDeEIsZUFBSyxjQUFjLFFBQVE7QUFDM0IsZUFBSyxjQUFjLFFBQVE7QUFBQSxRQUM3QixJQUFHO0FBQUEsTUFDTCxDQUFDO0FBQ0QsWUFBTSxLQUFLO0FBQUEsSUFDYjtBQUFBO0FBQUE7QUFBQSxFQUlRLGdCQUFnQixVQUF3QztBQUM5RCxTQUFLLFdBQVcsTUFBTTtBQUV0QixRQUFJLFNBQVMsV0FBVyxHQUFHO0FBQ3pCLFdBQUssV0FBVyxTQUFTLEtBQUs7QUFBQSxRQUM1QixNQUFNO0FBQUEsUUFDTixLQUFLO0FBQUEsTUFDUCxDQUFDO0FBQ0Q7QUFBQSxJQUNGO0FBRUEsZUFBVyxPQUFPLFVBQVU7QUFDMUIsV0FBSyxlQUFlLEdBQUc7QUFBQSxJQUN6QjtBQUdBLFNBQUssV0FBVyxZQUFZLEtBQUssV0FBVztBQUFBLEVBQzlDO0FBQUE7QUFBQSxFQUdRLGVBQWUsS0FBd0I7QUExYWpEO0FBNGFJLGVBQUssV0FBVyxjQUFjLG9CQUFvQixNQUFsRCxtQkFBcUQ7QUFFckQsVUFBTSxhQUFhLElBQUksUUFBUSxJQUFJLElBQUksS0FBSyxLQUFLO0FBQ2pELFVBQU0sWUFBWSxJQUFJLE9BQU8sVUFBVSxJQUFJLElBQUksS0FBSztBQUNwRCxVQUFNLEtBQUssS0FBSyxXQUFXLFVBQVUsRUFBRSxLQUFLLGlCQUFpQixJQUFJLElBQUksR0FBRyxVQUFVLEdBQUcsU0FBUyxHQUFHLENBQUM7QUFDbEcsVUFBTSxPQUFPLEdBQUcsVUFBVSxFQUFFLEtBQUsscUJBQXFCLENBQUM7QUFDdkQsUUFBSSxJQUFJLE9BQU87QUFDYixXQUFLLFFBQVEsSUFBSTtBQUFBLElBQ25CO0FBSUEsUUFBSSxJQUFJLFNBQVMsYUFBYTtBQUM1QixZQUFNLFlBQTBCLFVBQUssT0FBTyxTQUFTLGlCQUFyQixZQUFxQyxDQUFDO0FBQ3RFLFlBQU0sY0FBYSxnQkFBSyxJQUFJLFVBQVUsY0FBYyxNQUFqQyxtQkFBb0MsU0FBcEMsWUFBNEM7QUFFL0QsVUFBSSxLQUFLLE9BQU8sU0FBUyx5QkFBeUI7QUFFaEQsY0FBTSxNQUFNLEtBQUssNkJBQTZCLElBQUksU0FBUyxRQUFRO0FBQ25FLGFBQUssa0NBQWlCLGVBQWUsS0FBSyxNQUFNLFlBQVksS0FBSyxNQUFNO0FBQUEsTUFDekUsT0FBTztBQUVMLGFBQUssK0JBQStCLE1BQU0sSUFBSSxTQUFTLFVBQVUsVUFBVTtBQUFBLE1BQzdFO0FBQUEsSUFDRixPQUFPO0FBQ0wsV0FBSyxRQUFRLElBQUksT0FBTztBQUFBLElBQzFCO0FBR0EsU0FBSyxXQUFXLFlBQVksS0FBSyxXQUFXO0FBQUEsRUFDOUM7QUFBQSxFQUVRLDZCQUE2QixLQUFhLFVBQXdDO0FBNWM1RjtBQThjSSxRQUFJLFVBQVU7QUFDZCxRQUFJO0FBQ0YsZ0JBQVUsbUJBQW1CLEdBQUc7QUFBQSxJQUNsQyxTQUFRO0FBQUEsSUFFUjtBQUdBLGVBQVcsT0FBTyxVQUFVO0FBQzFCLFlBQU0sYUFBYSxRQUFPLFNBQUksZUFBSixZQUFrQixFQUFFO0FBQzlDLFVBQUksQ0FBQztBQUFZO0FBQ2pCLFlBQU0sTUFBTSxRQUFRLFFBQVEsVUFBVTtBQUN0QyxVQUFJLE1BQU07QUFBRztBQUdiLFlBQU0sT0FBTyxRQUFRLE1BQU0sR0FBRztBQUM5QixZQUFNLFFBQVEsS0FBSyxNQUFNLFdBQVcsRUFBRSxDQUFDO0FBQ3ZDLFlBQU0sU0FBUyw0QkFBNEIsT0FBTyxRQUFRO0FBQzFELFVBQUksVUFBVSxLQUFLLElBQUksTUFBTSxzQkFBc0IsTUFBTTtBQUFHLGVBQU87QUFBQSxJQUNyRTtBQUVBLFdBQU87QUFBQSxFQUNUO0FBQUEsRUFFUSxpQ0FBdUM7QUFDN0MsUUFBSSxLQUFLO0FBQWlCO0FBRTFCLFNBQUssa0JBQWtCLENBQUMsT0FBbUI7QUF6ZS9DO0FBMGVNLFlBQU0sU0FBUyxHQUFHO0FBQ2xCLFlBQU0sS0FBSSxzQ0FBUSxZQUFSLGdDQUFrQjtBQUM1QixVQUFJLENBQUM7QUFBRztBQUVSLFlBQU0sV0FBVyxFQUFFLGFBQWEsV0FBVyxLQUFLO0FBQ2hELFlBQU0sV0FBVyxFQUFFLGFBQWEsTUFBTSxLQUFLO0FBRTNDLFlBQU0sT0FBTyxZQUFZLFVBQVUsS0FBSztBQUN4QyxVQUFJLENBQUM7QUFBSztBQUdWLFVBQUksZ0JBQWdCLEtBQUssR0FBRztBQUFHO0FBRy9CLFlBQU0sWUFBWSxJQUFJLFFBQVEsUUFBUSxFQUFFO0FBQ3hDLFlBQU0sSUFBSSxLQUFLLElBQUksTUFBTSxzQkFBc0IsU0FBUztBQUN4RCxVQUFJLEVBQUUsYUFBYTtBQUFRO0FBRTNCLFNBQUcsZUFBZTtBQUNsQixTQUFHLGdCQUFnQjtBQUNuQixXQUFLLEtBQUssSUFBSSxVQUFVLFFBQVEsSUFBSSxFQUFFLFNBQVMsQ0FBQztBQUFBLElBQ2xEO0FBRUEsU0FBSyxXQUFXLGlCQUFpQixTQUFTLEtBQUssZUFBZTtBQUFBLEVBQ2hFO0FBQUEsRUFFUSwwQkFBMEIsT0FBZSxVQUF3QztBQXBnQjNGO0FBcWdCSSxVQUFNLElBQUksTUFBTSxRQUFRLFFBQVEsRUFBRTtBQUNsQyxRQUFJLEtBQUssSUFBSSxNQUFNLHNCQUFzQixDQUFDO0FBQUcsYUFBTztBQUlwRCxlQUFXLE9BQU8sVUFBVTtBQUMxQixZQUFNLGVBQWUsUUFBTyxTQUFJLGNBQUosWUFBaUIsRUFBRSxFQUFFLEtBQUs7QUFDdEQsVUFBSSxDQUFDO0FBQWM7QUFDbkIsWUFBTSxZQUFZLGFBQWEsU0FBUyxHQUFHLElBQUksZUFBZSxHQUFHLFlBQVk7QUFFN0UsWUFBTSxRQUFRLFVBQVUsUUFBUSxRQUFRLEVBQUUsRUFBRSxNQUFNLEdBQUc7QUFDckQsWUFBTSxXQUFXLE1BQU0sTUFBTSxTQUFTLENBQUM7QUFDdkMsVUFBSSxDQUFDO0FBQVU7QUFFZixZQUFNLFNBQVMsR0FBRyxRQUFRO0FBQzFCLFVBQUksQ0FBQyxFQUFFLFdBQVcsTUFBTTtBQUFHO0FBRTNCLFlBQU0sWUFBWSxHQUFHLFNBQVMsR0FBRyxFQUFFLE1BQU0sT0FBTyxNQUFNLENBQUM7QUFDdkQsWUFBTSxhQUFhLFVBQVUsUUFBUSxRQUFRLEVBQUU7QUFDL0MsVUFBSSxLQUFLLElBQUksTUFBTSxzQkFBc0IsVUFBVTtBQUFHLGVBQU87QUFBQSxJQUMvRDtBQUVBLFdBQU87QUFBQSxFQUNUO0FBQUEsRUFFUSw2QkFBNkIsTUFBYyxVQUFpQztBQUNsRixVQUFNLGFBQWEsa0JBQWtCLElBQUk7QUFDekMsUUFBSSxXQUFXLFdBQVc7QUFBRyxhQUFPO0FBRXBDLFFBQUksTUFBTTtBQUNWLFFBQUksU0FBUztBQUViLGVBQVcsS0FBSyxZQUFZO0FBQzFCLGFBQU8sS0FBSyxNQUFNLFFBQVEsRUFBRSxLQUFLO0FBQ2pDLGVBQVMsRUFBRTtBQUVYLFVBQUksRUFBRSxTQUFTLE9BQU87QUFFcEIsY0FBTUMsVUFBUyxLQUFLLDZCQUE2QixFQUFFLEtBQUssUUFBUTtBQUNoRSxlQUFPQSxVQUFTLEtBQUtBLE9BQU0sT0FBTyxFQUFFO0FBQ3BDO0FBQUEsTUFDRjtBQUdBLFlBQU0sU0FBUyxLQUFLLDBCQUEwQixFQUFFLEtBQUssUUFBUTtBQUM3RCxVQUFJLFFBQVE7QUFDVixlQUFPLEtBQUssTUFBTTtBQUNsQjtBQUFBLE1BQ0Y7QUFHQSxZQUFNLFNBQVMsNEJBQTRCLEVBQUUsS0FBSyxRQUFRO0FBQzFELFVBQUksQ0FBQyxRQUFRO0FBQ1gsZUFBTyxFQUFFO0FBQ1Q7QUFBQSxNQUNGO0FBRUEsVUFBSSxDQUFDLEtBQUssSUFBSSxNQUFNLHNCQUFzQixNQUFNLEdBQUc7QUFDakQsZUFBTyxFQUFFO0FBQ1Q7QUFBQSxNQUNGO0FBRUEsYUFBTyxLQUFLLE1BQU07QUFBQSxJQUNwQjtBQUVBLFdBQU8sS0FBSyxNQUFNLE1BQU07QUFDeEIsV0FBTztBQUFBLEVBQ1Q7QUFBQSxFQUVRLCtCQUNOLE1BQ0EsTUFDQSxVQUNBLFlBQ007QUFDTixVQUFNLGFBQWEsa0JBQWtCLElBQUk7QUFDekMsUUFBSSxXQUFXLFdBQVcsR0FBRztBQUMzQixXQUFLLFFBQVEsSUFBSTtBQUNqQjtBQUFBLElBQ0Y7QUFFQSxRQUFJLFNBQVM7QUFFYixVQUFNLGFBQWEsQ0FBQyxNQUFjO0FBQ2hDLFVBQUksQ0FBQztBQUFHO0FBQ1IsV0FBSyxZQUFZLFNBQVMsZUFBZSxDQUFDLENBQUM7QUFBQSxJQUM3QztBQUVBLFVBQU0scUJBQXFCLENBQUMsY0FBc0I7QUFDaEQsWUFBTSxVQUFVLEtBQUssU0FBUztBQUM5QixZQUFNLElBQUksS0FBSyxTQUFTLEtBQUssRUFBRSxNQUFNLFNBQVMsTUFBTSxJQUFJLENBQUM7QUFDekQsUUFBRSxpQkFBaUIsU0FBUyxDQUFDLE9BQU87QUFDbEMsV0FBRyxlQUFlO0FBQ2xCLFdBQUcsZ0JBQWdCO0FBRW5CLGNBQU0sSUFBSSxLQUFLLElBQUksTUFBTSxzQkFBc0IsU0FBUztBQUN4RCxZQUFJLGFBQWEsd0JBQU87QUFDdEIsZUFBSyxLQUFLLElBQUksVUFBVSxRQUFRLElBQUksRUFBRSxTQUFTLENBQUM7QUFDaEQ7QUFBQSxRQUNGO0FBR0EsYUFBSyxLQUFLLElBQUksVUFBVSxhQUFhLFdBQVcsWUFBWSxJQUFJO0FBQUEsTUFDbEUsQ0FBQztBQUFBLElBQ0g7QUFFQSxVQUFNLG9CQUFvQixDQUFDLFFBQWdCO0FBRXpDLFdBQUssU0FBUyxLQUFLLEVBQUUsTUFBTSxLQUFLLE1BQU0sSUFBSSxDQUFDO0FBQUEsSUFDN0M7QUFFQSxVQUFNLDhCQUE4QixDQUFDLFFBQStCLEtBQUssNkJBQTZCLEtBQUssUUFBUTtBQUVuSCxlQUFXLEtBQUssWUFBWTtBQUMxQixpQkFBVyxLQUFLLE1BQU0sUUFBUSxFQUFFLEtBQUssQ0FBQztBQUN0QyxlQUFTLEVBQUU7QUFFWCxVQUFJLEVBQUUsU0FBUyxPQUFPO0FBQ3BCLGNBQU1BLFVBQVMsNEJBQTRCLEVBQUUsR0FBRztBQUNoRCxZQUFJQSxTQUFRO0FBQ1YsNkJBQW1CQSxPQUFNO0FBQUEsUUFDM0IsT0FBTztBQUNMLDRCQUFrQixFQUFFLEdBQUc7QUFBQSxRQUN6QjtBQUNBO0FBQUEsTUFDRjtBQUdBLFlBQU0sU0FBUyxLQUFLLDBCQUEwQixFQUFFLEtBQUssUUFBUTtBQUM3RCxVQUFJLFFBQVE7QUFDViwyQkFBbUIsTUFBTTtBQUN6QjtBQUFBLE1BQ0Y7QUFHQSxZQUFNLFNBQVMsNEJBQTRCLEVBQUUsS0FBSyxRQUFRO0FBQzFELFVBQUksQ0FBQyxRQUFRO0FBQ1gsbUJBQVcsRUFBRSxHQUFHO0FBQ2hCO0FBQUEsTUFDRjtBQUVBLFVBQUksQ0FBQyxLQUFLLElBQUksTUFBTSxzQkFBc0IsTUFBTSxHQUFHO0FBQ2pELG1CQUFXLEVBQUUsR0FBRztBQUNoQjtBQUFBLE1BQ0Y7QUFFQSx5QkFBbUIsTUFBTTtBQUFBLElBQzNCO0FBRUEsZUFBVyxLQUFLLE1BQU0sTUFBTSxDQUFDO0FBQUEsRUFDL0I7QUFBQSxFQUVRLG9CQUEwQjtBQUdoQyxVQUFNLFdBQVcsQ0FBQyxLQUFLO0FBQ3ZCLFNBQUssUUFBUSxXQUFXO0FBRXhCLFNBQUssUUFBUSxZQUFZLGNBQWMsS0FBSyxTQUFTO0FBQ3JELFNBQUssUUFBUSxRQUFRLGFBQWEsS0FBSyxZQUFZLFNBQVMsT0FBTztBQUNuRSxTQUFLLFFBQVEsUUFBUSxjQUFjLEtBQUssWUFBWSxTQUFTLE1BQU07QUFFbkUsUUFBSSxLQUFLLFdBQVc7QUFFbEIsV0FBSyxRQUFRLE1BQU07QUFDbkIsWUFBTSxPQUFPLEtBQUssUUFBUSxVQUFVLEVBQUUsS0FBSyxrQkFBa0IsQ0FBQztBQUM5RCxXQUFLLFVBQVUsRUFBRSxLQUFLLHNCQUFzQixNQUFNLEVBQUUsZUFBZSxPQUFPLEVBQUUsQ0FBQztBQUM3RSxXQUFLLFVBQVUsRUFBRSxLQUFLLG1CQUFtQixNQUFNLEVBQUUsZUFBZSxPQUFPLEVBQUUsQ0FBQztBQUFBLElBQzVFLE9BQU87QUFFTCxXQUFLLFFBQVEsUUFBUSxNQUFNO0FBQUEsSUFDN0I7QUFBQSxFQUNGO0FBQUE7QUFBQSxFQUljLGNBQTZCO0FBQUE7QUFFekMsVUFBSSxLQUFLLFdBQVc7QUFDbEIsY0FBTSxLQUFLLE1BQU0sS0FBSyxTQUFTLGVBQWU7QUFDOUMsWUFBSSxDQUFDLElBQUk7QUFDUCxjQUFJLHdCQUFPLCtCQUErQjtBQUMxQyxlQUFLLFlBQVksV0FBVyxZQUFZLG9CQUFvQixzQkFBaUIsT0FBTyxDQUFDO0FBQUEsUUFDdkYsT0FBTztBQUNMLGVBQUssWUFBWSxXQUFXLFlBQVksb0JBQW9CLGtCQUFhLE1BQU0sQ0FBQztBQUFBLFFBQ2xGO0FBQ0E7QUFBQSxNQUNGO0FBRUEsWUFBTSxPQUFPLEtBQUssUUFBUSxNQUFNLEtBQUs7QUFDckMsVUFBSSxDQUFDO0FBQU07QUFHWCxVQUFJLFVBQVU7QUFDZCxVQUFJLEtBQUssb0JBQW9CLFNBQVM7QUFDcEMsY0FBTSxPQUFPLE1BQU0scUJBQXFCLEtBQUssR0FBRztBQUNoRCxZQUFJLE1BQU07QUFDUixvQkFBVSxjQUFjLEtBQUssS0FBSztBQUFBO0FBQUEsRUFBUyxJQUFJO0FBQUEsUUFDakQ7QUFBQSxNQUNGO0FBR0EsWUFBTSxVQUFVLFlBQVksa0JBQWtCLElBQUk7QUFDbEQsV0FBSyxZQUFZLFdBQVcsT0FBTztBQUduQyxXQUFLLFFBQVEsUUFBUTtBQUNyQixXQUFLLFFBQVEsTUFBTSxTQUFTO0FBRzVCLFVBQUk7QUFDRixjQUFNLEtBQUssU0FBUyxZQUFZLE9BQU87QUFBQSxNQUN6QyxTQUFTLEtBQUs7QUFDWixnQkFBUSxNQUFNLHVCQUF1QixHQUFHO0FBQ3hDLFlBQUksd0JBQU8sK0JBQStCLE9BQU8sR0FBRyxDQUFDLEdBQUc7QUFDeEQsYUFBSyxZQUFZO0FBQUEsVUFDZixZQUFZLG9CQUFvQix1QkFBa0IsR0FBRyxJQUFJLE9BQU87QUFBQSxRQUNsRTtBQUFBLE1BQ0Y7QUFBQSxJQUNGO0FBQUE7QUFDRjs7O0FJNXJCTyxJQUFNLG1CQUFxQztBQUFBLEVBQ2hELFlBQVk7QUFBQSxFQUNaLFdBQVc7QUFBQSxFQUNYLFlBQVk7QUFBQSxFQUNaLFdBQVc7QUFBQSxFQUNYLG1CQUFtQjtBQUFBLEVBQ25CLHlCQUF5QjtBQUFBLEVBQ3pCLGlCQUFpQjtBQUFBLEVBQ2pCLGNBQWMsQ0FBQztBQUFBLEVBQ2YsV0FBVztBQUFBLEVBQ1gseUJBQXlCLENBQUM7QUFBQSxFQUMxQixtQkFBbUIsQ0FBQztBQUN0Qjs7O0FDL0NPLFNBQVMseUJBQXlCLFdBQTJCO0FBQ2xFLFNBQU8sOEJBQThCLFNBQVM7QUFDaEQ7QUFzQk8sU0FBUyx3QkFBd0IsVUFBNEIsV0FHbEU7QUE3QkY7QUE4QkUsUUFBTSxlQUFlLHlCQUF5QixTQUFTO0FBQ3ZELFFBQU0sYUFBWSxjQUFTLGVBQVQsWUFBdUIsSUFBSSxLQUFLLEVBQUUsWUFBWTtBQUNoRSxRQUFNLFdBQVcsU0FBUyxXQUFXLFdBQVc7QUFDaEQsUUFBTSxnQkFBZ0IsQ0FBQyxZQUFZLGFBQWEsVUFBVSxhQUFhO0FBRXZFLFFBQU0sT0FBeUIsbUJBQUs7QUFDcEMsT0FBSyxZQUFZO0FBRWpCLE1BQUksVUFBVTtBQUNaLFVBQU0sU0FBUyxNQUFNLFFBQVEsS0FBSyxpQkFBaUIsSUFBSSxLQUFLLG9CQUFvQixDQUFDO0FBQ2pGLFNBQUssb0JBQW9CLENBQUMsVUFBVSxHQUFHLE9BQU8sT0FBTyxDQUFDLE1BQU0sS0FBSyxNQUFNLFFBQVEsQ0FBQyxFQUFFLE1BQU0sR0FBRyxFQUFFO0FBQUEsRUFDL0Y7QUFFQSxNQUFJLFlBQVksZUFBZTtBQUM3QixTQUFLLGFBQWE7QUFBQSxFQUNwQjtBQUVBLFFBQU0sT0FBTSxVQUFLLDRCQUFMLFlBQWdDLENBQUM7QUFDN0MsUUFBTSxNQUFNLE1BQU0sUUFBUSxJQUFJLFNBQVMsQ0FBQyxJQUFJLElBQUksU0FBUyxJQUFJLENBQUM7QUFDOUQsTUFBSSxDQUFDLElBQUksU0FBUyxZQUFZLEdBQUc7QUFDL0IsUUFBSSxTQUFTLElBQUksQ0FBQyxjQUFjLEdBQUcsR0FBRyxFQUFFLE1BQU0sR0FBRyxFQUFFO0FBQ25ELFNBQUssMEJBQTBCO0FBQUEsRUFDakM7QUFFQSxTQUFPLEVBQUUsY0FBYyxNQUFNLGFBQWE7QUFDNUM7OztBUmhEQSxJQUFxQixrQkFBckIsTUFBcUIsd0JBQXVCLHdCQUFPO0FBQUEsRUFBbkQ7QUFBQTtBQUlFO0FBQUEsU0FBUSxpQkFBaUI7QUFDekIsU0FBUSxtQkFBbUI7QUFrQjNCLFNBQVEsYUFBNEI7QUE2SXBDLFNBQVEscUJBQXFCO0FBQUE7QUFBQSxFQTVKN0IsbUJBQXlCO0FBQ3ZCLFNBQUssa0JBQWtCO0FBQ3ZCLFVBQU0sTUFBTSxLQUFLLElBQUk7QUFDckIsUUFBSSxLQUFLLGlCQUFpQixnQkFBZSxtQkFBbUIsTUFBTSxLQUFLLG1CQUFtQixLQUFRO0FBQ2hHLFdBQUssbUJBQW1CO0FBQ3hCLFVBQUk7QUFBQSxRQUNGLGtCQUFrQixLQUFLLGNBQWM7QUFBQSxNQUN2QztBQUFBLElBQ0Y7QUFBQSxFQUNGO0FBQUEsRUFFQSxxQkFBMkI7QUFDekIsU0FBSyxpQkFBaUIsS0FBSyxJQUFJLEdBQUcsS0FBSyxpQkFBaUIsQ0FBQztBQUFBLEVBQzNEO0FBQUEsRUFJUSxvQkFBbUM7QUFDekMsUUFBSTtBQUNGLFlBQU0sVUFBVSxLQUFLLElBQUksTUFBTTtBQUUvQixVQUFJLG1CQUFtQixvQ0FBbUI7QUFDeEMsY0FBTSxXQUFXLFFBQVEsWUFBWTtBQUNyQyxZQUFJLFVBQVU7QUFHWixnQkFBTUMsVUFBUyxRQUFRLFFBQVE7QUFDL0IsZ0JBQU0sTUFBTUEsUUFBTyxXQUFXLFFBQVEsRUFBRSxPQUFPLFVBQVUsTUFBTSxFQUFFLE9BQU8sS0FBSztBQUM3RSxpQkFBTyxJQUFJLE1BQU0sR0FBRyxFQUFFO0FBQUEsUUFDeEI7QUFBQSxNQUNGO0FBQUEsSUFDRixTQUFRO0FBQUEsSUFFUjtBQUNBLFdBQU87QUFBQSxFQUNUO0FBQUE7QUFBQSxFQUlBLGVBQThCO0FBQzVCLFdBQU8sS0FBSztBQUFBLEVBQ2Q7QUFBQSxFQUVBLHVCQUErQjtBQTFEakM7QUEyREksYUFBUSxVQUFLLFNBQVMsZUFBZCxZQUE0QixRQUFRLEtBQUssRUFBRSxZQUFZO0FBQUEsRUFDakU7QUFBQSxFQUVBLG1CQUE2RTtBQUMzRSxXQUFPO0FBQUEsTUFDTCxLQUFLLE9BQU8sS0FBSyxTQUFTLGNBQWMsRUFBRTtBQUFBLE1BQzFDLE9BQU8sT0FBTyxLQUFLLFNBQVMsYUFBYSxFQUFFO0FBQUEsTUFDM0MsaUJBQWlCLFFBQVEsS0FBSyxTQUFTLGVBQWU7QUFBQSxJQUN4RDtBQUFBLEVBQ0Y7QUFBQTtBQUFBLEVBR00sbUJBQW1CLFlBQW1DO0FBQUE7QUF2RTlEO0FBd0VJLFlBQU0sT0FBTyxXQUFXLEtBQUssRUFBRSxZQUFZO0FBQzNDLFVBQUksQ0FBQztBQUFNO0FBR1gsWUFBTSxZQUFZLEtBQUs7QUFDdkIsVUFBSSxXQUFXO0FBQ2IsY0FBTSxTQUFTLDhCQUE4QixTQUFTO0FBQ3RELFlBQUksRUFBRSxTQUFTLFVBQVUsU0FBUyxVQUFVLEtBQUssV0FBVyxTQUFTLEdBQUcsSUFBSTtBQUMxRTtBQUFBLFFBQ0Y7QUFBQSxNQUNGLE9BQU87QUFFTCxZQUFJLFNBQVM7QUFBUTtBQUFBLE1BQ3ZCO0FBRUEsV0FBSyxTQUFTLGFBQWE7QUFFM0IsVUFBSSxLQUFLLFlBQVk7QUFDbkIsY0FBTSxPQUFNLFVBQUssU0FBUyw0QkFBZCxZQUF5QyxDQUFDO0FBQ3RELGNBQU0sTUFBTSxNQUFNLFFBQVEsSUFBSSxLQUFLLFVBQVUsQ0FBQyxJQUFJLElBQUksS0FBSyxVQUFVLElBQUksQ0FBQztBQUMxRSxjQUFNLFdBQVcsQ0FBQyxNQUFNLEdBQUcsSUFBSSxPQUFPLENBQUMsTUFBTSxLQUFLLE1BQU0sSUFBSSxDQUFDLEVBQUUsTUFBTSxHQUFHLEVBQUU7QUFDMUUsWUFBSSxLQUFLLFVBQVUsSUFBSTtBQUN2QixhQUFLLFNBQVMsMEJBQTBCO0FBQUEsTUFDMUM7QUFFQSxZQUFNLEtBQUssYUFBYTtBQUFBLElBQzFCO0FBQUE7QUFBQSxFQUVBLGVBQWUsWUFBc0M7QUFDbkQsV0FBTyxJQUFJLGlCQUFpQixXQUFXLEtBQUssRUFBRSxZQUFZLEdBQUc7QUFBQSxNQUMzRCxlQUFlO0FBQUEsUUFDYixLQUFLLE1BQVM7QUFBSSx1QkFBTSxLQUFLLG9CQUFvQjtBQUFBO0FBQUEsUUFDakQsS0FBSyxDQUFPLGFBQVU7QUFBRyx1QkFBTSxLQUFLLG9CQUFvQixRQUFRO0FBQUE7QUFBQSxRQUNoRSxPQUFPLE1BQVM7QUFBRyx1QkFBTSxLQUFLLHFCQUFxQjtBQUFBO0FBQUEsTUFDckQ7QUFBQSxJQUNGLENBQUM7QUFBQSxFQUNIO0FBQUEsRUFFTSxTQUF3QjtBQUFBO0FBQzVCLFlBQU0sS0FBSyxhQUFhO0FBR3hCLFdBQUssYUFBYSxLQUFLLGtCQUFrQjtBQUN6QyxVQUFJLEtBQUssWUFBWTtBQUNuQixhQUFLLFNBQVMsWUFBWSxLQUFLO0FBRS9CLGNBQU0sV0FBVyx3QkFBd0IsS0FBSyxVQUFVLEtBQUssVUFBVTtBQUN2RSxhQUFLLFdBQVcsU0FBUztBQUN6QixjQUFNLEtBQUssYUFBYTtBQUFBLE1BQzFCLE9BQU87QUFFTCxZQUFJLHdCQUFPLGdFQUFnRTtBQUFBLE1BQzdFO0FBR0EsV0FBSyxhQUFhLHlCQUF5QixDQUFDLFNBQXdCLElBQUksaUJBQWlCLE1BQU0sSUFBSSxDQUFDO0FBR3BHLFdBQUssY0FBYyxrQkFBa0IsaUJBQWlCLE1BQU07QUFDMUQsYUFBSyxLQUFLLGtCQUFrQjtBQUFBLE1BQzlCLENBQUM7QUFHRCxXQUFLLGNBQWMsSUFBSSxtQkFBbUIsS0FBSyxLQUFLLElBQUksQ0FBQztBQUd6RCxXQUFLLFdBQVc7QUFBQSxRQUNkLElBQUk7QUFBQSxRQUNKLE1BQU07QUFBQSxRQUNOLFVBQVUsTUFBTSxLQUFLLEtBQUssa0JBQWtCO0FBQUEsTUFDOUMsQ0FBQztBQUVELGNBQVEsSUFBSSx1QkFBdUI7QUFBQSxJQUNyQztBQUFBO0FBQUEsRUFFTSxXQUEwQjtBQUFBO0FBQzlCLFdBQUssSUFBSSxVQUFVLG1CQUFtQix1QkFBdUI7QUFDN0QsY0FBUSxJQUFJLHlCQUF5QjtBQUFBLElBQ3ZDO0FBQUE7QUFBQSxFQUVNLGVBQThCO0FBQUE7QUF4SnRDO0FBeUpJLFlBQU0sUUFBUSxXQUFNLEtBQUssU0FBUyxNQUFwQixZQUEwQixDQUFDO0FBRXpDLFdBQUssV0FBVyxPQUFPLE9BQU8sQ0FBQyxHQUFHLGtCQUFrQixJQUFJO0FBQUEsSUFDMUQ7QUFBQTtBQUFBLEVBRU0sZUFBOEI7QUFBQTtBQTlKdEM7QUFnS0ksWUFBTSxRQUFRLFdBQU0sS0FBSyxTQUFTLE1BQXBCLFlBQTBCLENBQUM7QUFDekMsWUFBTSxLQUFLLFNBQVMsa0NBQUssT0FBUyxLQUFLLFNBQVU7QUFBQSxJQUNuRDtBQUFBO0FBQUE7QUFBQSxFQUlNLHNCQUFxQztBQUFBO0FBQ3pDLFlBQU0sS0FBSyxxQkFBcUI7QUFDaEMsVUFBSSx3QkFBTyxnRUFBZ0U7QUFBQSxJQUM3RTtBQUFBO0FBQUEsRUFJYyxzQkFBMkM7QUFBQTtBQTdLM0Q7QUE4S0ksWUFBTSxRQUFRLFdBQU0sS0FBSyxTQUFTLE1BQXBCLFlBQTBCLENBQUM7QUFDekMsY0FBUSxrQ0FBZSxLQUFLLHdCQUFwQixZQUEyQztBQUFBLElBQ3JEO0FBQUE7QUFBQSxFQUVjLG9CQUFvQixVQUE4QjtBQUFBO0FBbExsRTtBQW1MSSxZQUFNLFFBQVEsV0FBTSxLQUFLLFNBQVMsTUFBcEIsWUFBMEIsQ0FBQztBQUN6QyxZQUFNLEtBQUssU0FBUyxpQ0FBSyxPQUFMLEVBQVcsQ0FBQyxLQUFLLGtCQUFrQixHQUFHLFNBQVMsRUFBQztBQUFBLElBQ3RFO0FBQUE7QUFBQSxFQUVjLHVCQUFzQztBQUFBO0FBdkx0RDtBQXdMSSxZQUFNLFFBQVEsV0FBTSxLQUFLLFNBQVMsTUFBcEIsWUFBMEIsQ0FBQztBQUN6QyxXQUFLLDZCQUFlLEtBQUsseUJBQXdCO0FBQVc7QUFDNUQsWUFBTSxPQUFPLG1CQUFNO0FBQ25CLGFBQU8sS0FBSyxLQUFLLGtCQUFrQjtBQUNuQyxZQUFNLEtBQUssU0FBUyxJQUFJO0FBQUEsSUFDMUI7QUFBQTtBQUFBO0FBQUEsRUFJYyxvQkFBbUM7QUFBQTtBQUMvQyxZQUFNLEVBQUUsVUFBVSxJQUFJLEtBQUs7QUFHM0IsWUFBTSxXQUFXLFVBQVUsZ0JBQWdCLHVCQUF1QjtBQUNsRSxVQUFJLFNBQVMsU0FBUyxHQUFHO0FBQ3ZCLGtCQUFVLFdBQVcsU0FBUyxDQUFDLENBQUM7QUFDaEM7QUFBQSxNQUNGO0FBR0EsWUFBTSxPQUFPLFVBQVUsYUFBYSxLQUFLO0FBQ3pDLFVBQUksQ0FBQztBQUFNO0FBQ1gsWUFBTSxLQUFLLGFBQWEsRUFBRSxNQUFNLHlCQUF5QixRQUFRLEtBQUssQ0FBQztBQUN2RSxnQkFBVSxXQUFXLElBQUk7QUFBQSxJQUMzQjtBQUFBO0FBQ0Y7QUExTXFCLGdCQU1KLGtCQUFrQjtBQU5uQyxJQUFxQixpQkFBckI7IiwKICAibmFtZXMiOiBbImltcG9ydF9vYnNpZGlhbiIsICJfYSIsICJpbXBvcnRfb2JzaWRpYW4iLCAibWFwcGVkIiwgImNyeXB0byJdCn0K
