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
    this.onDocClickCapture = null;
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
      var _a, _b;
      this.plugin.unregisterChatLeaf();
      this.chatManager.onUpdate = null;
      this.chatManager.onMessageAdded = null;
      this.wsClient.onStateChange = null;
      this.wsClient.onWorkingChange = null;
      this.wsClient.disconnect();
      if (this.onDocClickCapture) {
        (_b = (_a = this.contentEl) == null ? void 0 : _a.ownerDocument) == null ? void 0 : _b.removeEventListener("click", this.onDocClickCapture, true);
        this.onDocClickCapture = null;
      }
      this.onMessagesClick = null;
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
    if (this.onMessagesClick || this.onDocClickCapture)
      return;
    const handler = (ev) => {
      var _a, _b, _c, _d;
      const target = ev.target;
      if (!target)
        return;
      if (!((_a = this.messagesEl) == null ? void 0 : _a.contains(target)))
        return;
      const a = (_b = target.closest) == null ? void 0 : _b.call(target, "a.internal-link");
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
      ev.preventDefault();
      ev.stopPropagation();
      if (f instanceof import_obsidian2.TFile) {
        void this.app.workspace.getLeaf(true).openFile(f);
        return;
      }
      void this.app.workspace.openLinkText(vaultPath, (_d = (_c = this.app.workspace.getActiveFile()) == null ? void 0 : _c.path) != null ? _d : "", true);
    };
    this.onMessagesClick = handler;
    this.onDocClickCapture = handler;
    this.contentEl.ownerDocument.addEventListener("click", handler, true);
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
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsic3JjL21haW4udHMiLCAic3JjL3NldHRpbmdzLnRzIiwgInNyYy93ZWJzb2NrZXQudHMiLCAic3JjL3ZpZXcudHMiLCAic3JjL2NoYXQudHMiLCAic3JjL2xpbmtpZnkudHMiLCAic3JjL2NvbnRleHQudHMiLCAic3JjL3R5cGVzLnRzIiwgInNyYy9zZXNzaW9uLnRzIl0sCiAgInNvdXJjZXNDb250ZW50IjogWyJpbXBvcnQgeyBGaWxlU3lzdGVtQWRhcHRlciwgTm90aWNlLCBQbHVnaW4sIFdvcmtzcGFjZUxlYWYgfSBmcm9tICdvYnNpZGlhbic7XG5pbXBvcnQgeyBPcGVuQ2xhd1NldHRpbmdUYWIgfSBmcm9tICcuL3NldHRpbmdzJztcbmltcG9ydCB7IE9ic2lkaWFuV1NDbGllbnQgfSBmcm9tICcuL3dlYnNvY2tldCc7XG5pbXBvcnQgeyBWSUVXX1RZUEVfT1BFTkNMQVdfQ0hBVCwgT3BlbkNsYXdDaGF0VmlldyB9IGZyb20gJy4vdmlldyc7XG5pbXBvcnQgeyBERUZBVUxUX1NFVFRJTkdTLCB0eXBlIE9wZW5DbGF3U2V0dGluZ3MgfSBmcm9tICcuL3R5cGVzJztcbmltcG9ydCB7IG1pZ3JhdGVTZXR0aW5nc0ZvclZhdWx0IH0gZnJvbSAnLi9zZXNzaW9uJztcblxuZXhwb3J0IGRlZmF1bHQgY2xhc3MgT3BlbkNsYXdQbHVnaW4gZXh0ZW5kcyBQbHVnaW4ge1xuICBzZXR0aW5ncyE6IE9wZW5DbGF3U2V0dGluZ3M7XG5cbiAgLy8gTk9URTogd3NDbGllbnQvY2hhdE1hbmFnZXIgYXJlIHBlci1sZWFmIChwZXIgdmlldykgdG8gYWxsb3cgcGFyYWxsZWwgc2Vzc2lvbnMuXG4gIHByaXZhdGUgb3BlbkNoYXRMZWF2ZXMgPSAwO1xuICBwcml2YXRlIGxhc3RMZWFmV2FybkF0TXMgPSAwO1xuICBwcml2YXRlIHN0YXRpYyBNQVhfQ0hBVF9MRUFWRVMgPSAzO1xuXG4gIHJlZ2lzdGVyQ2hhdExlYWYoKTogdm9pZCB7XG4gICAgdGhpcy5vcGVuQ2hhdExlYXZlcyArPSAxO1xuICAgIGNvbnN0IG5vdyA9IERhdGUubm93KCk7XG4gICAgaWYgKHRoaXMub3BlbkNoYXRMZWF2ZXMgPiBPcGVuQ2xhd1BsdWdpbi5NQVhfQ0hBVF9MRUFWRVMgJiYgbm93IC0gdGhpcy5sYXN0TGVhZldhcm5BdE1zID4gNjBfMDAwKSB7XG4gICAgICB0aGlzLmxhc3RMZWFmV2FybkF0TXMgPSBub3c7XG4gICAgICBuZXcgTm90aWNlKFxuICAgICAgICBgT3BlbkNsYXcgQ2hhdDogJHt0aGlzLm9wZW5DaGF0TGVhdmVzfSBjaGF0IHZpZXdzIGFyZSBvcGVuLiBUaGlzIG1heSBpbmNyZWFzZSBnYXRld2F5IGxvYWQuYFxuICAgICAgKTtcbiAgICB9XG4gIH1cblxuICB1bnJlZ2lzdGVyQ2hhdExlYWYoKTogdm9pZCB7XG4gICAgdGhpcy5vcGVuQ2hhdExlYXZlcyA9IE1hdGgubWF4KDAsIHRoaXMub3BlbkNoYXRMZWF2ZXMgLSAxKTtcbiAgfVxuXG4gIHByaXZhdGUgX3ZhdWx0SGFzaDogc3RyaW5nIHwgbnVsbCA9IG51bGw7XG5cbiAgcHJpdmF0ZSBfY29tcHV0ZVZhdWx0SGFzaCgpOiBzdHJpbmcgfCBudWxsIHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgYWRhcHRlciA9IHRoaXMuYXBwLnZhdWx0LmFkYXB0ZXI7XG4gICAgICAvLyBEZXNrdG9wIG9ubHk6IEZpbGVTeXN0ZW1BZGFwdGVyIHByb3ZpZGVzIGEgc3RhYmxlIGJhc2UgcGF0aC5cbiAgICAgIGlmIChhZGFwdGVyIGluc3RhbmNlb2YgRmlsZVN5c3RlbUFkYXB0ZXIpIHtcbiAgICAgICAgY29uc3QgYmFzZVBhdGggPSBhZGFwdGVyLmdldEJhc2VQYXRoKCk7XG4gICAgICAgIGlmIChiYXNlUGF0aCkge1xuICAgICAgICAgIC8vIFVzZSBOb2RlIGNyeXB0byAoRWxlY3Ryb24gZW52aXJvbm1lbnQpLlxuICAgICAgICAgIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBAdHlwZXNjcmlwdC1lc2xpbnQvbm8tdmFyLXJlcXVpcmVzXG4gICAgICAgICAgY29uc3QgY3J5cHRvID0gcmVxdWlyZSgnY3J5cHRvJykgYXMgdHlwZW9mIGltcG9ydCgnY3J5cHRvJyk7XG4gICAgICAgICAgY29uc3QgaGV4ID0gY3J5cHRvLmNyZWF0ZUhhc2goJ3NoYTI1NicpLnVwZGF0ZShiYXNlUGF0aCwgJ3V0ZjgnKS5kaWdlc3QoJ2hleCcpO1xuICAgICAgICAgIHJldHVybiBoZXguc2xpY2UoMCwgMTYpO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSBjYXRjaCB7XG4gICAgICAvLyBpZ25vcmVcbiAgICB9XG4gICAgcmV0dXJuIG51bGw7XG4gIH1cblxuICAvLyBjYW5vbmljYWwgc2Vzc2lvbiBrZXkgaGVscGVycyBsaXZlIGluIHNyYy9zZXNzaW9uLnRzXG5cbiAgZ2V0VmF1bHRIYXNoKCk6IHN0cmluZyB8IG51bGwge1xuICAgIHJldHVybiB0aGlzLl92YXVsdEhhc2g7XG4gIH1cblxuICBnZXREZWZhdWx0U2Vzc2lvbktleSgpOiBzdHJpbmcge1xuICAgIHJldHVybiAodGhpcy5zZXR0aW5ncy5zZXNzaW9uS2V5ID8/ICdtYWluJykudHJpbSgpLnRvTG93ZXJDYXNlKCk7XG4gIH1cblxuICBnZXRHYXRld2F5Q29uZmlnKCk6IHsgdXJsOiBzdHJpbmc7IHRva2VuOiBzdHJpbmc7IGFsbG93SW5zZWN1cmVXczogYm9vbGVhbiB9IHtcbiAgICByZXR1cm4ge1xuICAgICAgdXJsOiBTdHJpbmcodGhpcy5zZXR0aW5ncy5nYXRld2F5VXJsIHx8ICcnKSxcbiAgICAgIHRva2VuOiBTdHJpbmcodGhpcy5zZXR0aW5ncy5hdXRoVG9rZW4gfHwgJycpLFxuICAgICAgYWxsb3dJbnNlY3VyZVdzOiBCb29sZWFuKHRoaXMuc2V0dGluZ3MuYWxsb3dJbnNlY3VyZVdzKSxcbiAgICB9O1xuICB9XG5cbiAgLyoqIFBlcnNpc3QgKyByZW1lbWJlciBhbiBPYnNpZGlhbiBzZXNzaW9uIGtleSBmb3IgdGhlIGN1cnJlbnQgdmF1bHQuICovXG4gIGFzeW5jIHJlbWVtYmVyU2Vzc2lvbktleShzZXNzaW9uS2V5OiBzdHJpbmcpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBjb25zdCBuZXh0ID0gc2Vzc2lvbktleS50cmltKCkudG9Mb3dlckNhc2UoKTtcbiAgICBpZiAoIW5leHQpIHJldHVybjtcblxuICAgIC8vIFNFQzogYWxsb3cgb25seSB2YXVsdC1zY29wZWQga2V5cyAod2hlbiB2YXVsdEhhc2gga25vd24pIG9yIG1haW4uXG4gICAgY29uc3QgdmF1bHRIYXNoID0gdGhpcy5fdmF1bHRIYXNoO1xuICAgIGlmICh2YXVsdEhhc2gpIHtcbiAgICAgIGNvbnN0IHByZWZpeCA9IGBhZ2VudDptYWluOm9ic2lkaWFuOmRpcmVjdDoke3ZhdWx0SGFzaH1gO1xuICAgICAgaWYgKCEobmV4dCA9PT0gJ21haW4nIHx8IG5leHQgPT09IHByZWZpeCB8fCBuZXh0LnN0YXJ0c1dpdGgocHJlZml4ICsgJy0nKSkpIHtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuICAgIH0gZWxzZSB7XG4gICAgICAvLyBXaXRob3V0IGEgdmF1bHQgaWRlbnRpdHksIG9ubHkgYWxsb3cgbWFpbi5cbiAgICAgIGlmIChuZXh0ICE9PSAnbWFpbicpIHJldHVybjtcbiAgICB9XG5cbiAgICB0aGlzLnNldHRpbmdzLnNlc3Npb25LZXkgPSBuZXh0O1xuXG4gICAgaWYgKHRoaXMuX3ZhdWx0SGFzaCkge1xuICAgICAgY29uc3QgbWFwID0gdGhpcy5zZXR0aW5ncy5rbm93blNlc3Npb25LZXlzQnlWYXVsdCA/PyB7fTtcbiAgICAgIGNvbnN0IGN1ciA9IEFycmF5LmlzQXJyYXkobWFwW3RoaXMuX3ZhdWx0SGFzaF0pID8gbWFwW3RoaXMuX3ZhdWx0SGFzaF0gOiBbXTtcbiAgICAgIGNvbnN0IG5leHRMaXN0ID0gW25leHQsIC4uLmN1ci5maWx0ZXIoKGspID0+IGsgJiYgayAhPT0gbmV4dCldLnNsaWNlKDAsIDIwKTtcbiAgICAgIG1hcFt0aGlzLl92YXVsdEhhc2hdID0gbmV4dExpc3Q7XG4gICAgICB0aGlzLnNldHRpbmdzLmtub3duU2Vzc2lvbktleXNCeVZhdWx0ID0gbWFwO1xuICAgIH1cblxuICAgIGF3YWl0IHRoaXMuc2F2ZVNldHRpbmdzKCk7XG4gIH1cblxuICBjcmVhdGVXc0NsaWVudChzZXNzaW9uS2V5OiBzdHJpbmcpOiBPYnNpZGlhbldTQ2xpZW50IHtcbiAgICByZXR1cm4gbmV3IE9ic2lkaWFuV1NDbGllbnQoc2Vzc2lvbktleS50cmltKCkudG9Mb3dlckNhc2UoKSwge1xuICAgICAgaWRlbnRpdHlTdG9yZToge1xuICAgICAgICBnZXQ6IGFzeW5jICgpID0+IChhd2FpdCB0aGlzLl9sb2FkRGV2aWNlSWRlbnRpdHkoKSksXG4gICAgICAgIHNldDogYXN5bmMgKGlkZW50aXR5KSA9PiBhd2FpdCB0aGlzLl9zYXZlRGV2aWNlSWRlbnRpdHkoaWRlbnRpdHkpLFxuICAgICAgICBjbGVhcjogYXN5bmMgKCkgPT4gYXdhaXQgdGhpcy5fY2xlYXJEZXZpY2VJZGVudGl0eSgpLFxuICAgICAgfSxcbiAgICB9KTtcbiAgfVxuXG4gIGFzeW5jIG9ubG9hZCgpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBhd2FpdCB0aGlzLmxvYWRTZXR0aW5ncygpO1xuXG4gICAgLy8gQ29tcHV0ZSB2YXVsdCBoYXNoIChkZXNrdG9wKSBhbmQgbWlncmF0ZSB0byBjYW5vbmljYWwgb2JzaWRpYW4gZGlyZWN0IHNlc3Npb24ga2V5LlxuICAgIHRoaXMuX3ZhdWx0SGFzaCA9IHRoaXMuX2NvbXB1dGVWYXVsdEhhc2goKTtcbiAgICBpZiAodGhpcy5fdmF1bHRIYXNoKSB7XG4gICAgICB0aGlzLnNldHRpbmdzLnZhdWx0SGFzaCA9IHRoaXMuX3ZhdWx0SGFzaDtcblxuICAgICAgY29uc3QgbWlncmF0ZWQgPSBtaWdyYXRlU2V0dGluZ3NGb3JWYXVsdCh0aGlzLnNldHRpbmdzLCB0aGlzLl92YXVsdEhhc2gpO1xuICAgICAgdGhpcy5zZXR0aW5ncyA9IG1pZ3JhdGVkLm5leHRTZXR0aW5ncztcbiAgICAgIGF3YWl0IHRoaXMuc2F2ZVNldHRpbmdzKCk7XG4gICAgfSBlbHNlIHtcbiAgICAgIC8vIEtlZXAgd29ya2luZywgYnV0IE5ldy1zZXNzaW9uIGNyZWF0aW9uIG1heSBiZSB1bmF2YWlsYWJsZS5cbiAgICAgIG5ldyBOb3RpY2UoJ09wZW5DbGF3IENoYXQ6IGNvdWxkIG5vdCBkZXRlcm1pbmUgdmF1bHQgaWRlbnRpdHkgKHZhdWx0SGFzaCkuJyk7XG4gICAgfVxuXG4gICAgLy8gUmVnaXN0ZXIgdGhlIHNpZGViYXIgdmlld1xuICAgIHRoaXMucmVnaXN0ZXJWaWV3KFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFULCAobGVhZjogV29ya3NwYWNlTGVhZikgPT4gbmV3IE9wZW5DbGF3Q2hhdFZpZXcobGVhZiwgdGhpcykpO1xuXG4gICAgLy8gUmliYm9uIGljb24gXHUyMDE0IG9wZW5zIC8gcmV2ZWFscyB0aGUgY2hhdCBzaWRlYmFyXG4gICAgdGhpcy5hZGRSaWJib25JY29uKCdtZXNzYWdlLXNxdWFyZScsICdPcGVuQ2xhdyBDaGF0JywgKCkgPT4ge1xuICAgICAgdm9pZCB0aGlzLl9hY3RpdmF0ZUNoYXRWaWV3KCk7XG4gICAgfSk7XG5cbiAgICAvLyBTZXR0aW5ncyB0YWJcbiAgICB0aGlzLmFkZFNldHRpbmdUYWIobmV3IE9wZW5DbGF3U2V0dGluZ1RhYih0aGlzLmFwcCwgdGhpcykpO1xuXG4gICAgLy8gQ29tbWFuZCBwYWxldHRlIGVudHJ5XG4gICAgdGhpcy5hZGRDb21tYW5kKHtcbiAgICAgIGlkOiAnb3Blbi1vcGVuY2xhdy1jaGF0JyxcbiAgICAgIG5hbWU6ICdPcGVuIGNoYXQgc2lkZWJhcicsXG4gICAgICBjYWxsYmFjazogKCkgPT4gdm9pZCB0aGlzLl9hY3RpdmF0ZUNoYXRWaWV3KCksXG4gICAgfSk7XG5cbiAgICBjb25zb2xlLmxvZygnW29jbGF3XSBQbHVnaW4gbG9hZGVkJyk7XG4gIH1cblxuICBhc3luYyBvbnVubG9hZCgpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICB0aGlzLmFwcC53b3Jrc3BhY2UuZGV0YWNoTGVhdmVzT2ZUeXBlKFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFUKTtcbiAgICBjb25zb2xlLmxvZygnW29jbGF3XSBQbHVnaW4gdW5sb2FkZWQnKTtcbiAgfVxuXG4gIGFzeW5jIGxvYWRTZXR0aW5ncygpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBjb25zdCBkYXRhID0gKGF3YWl0IHRoaXMubG9hZERhdGEoKSkgPz8ge307XG4gICAgLy8gTk9URTogcGx1Z2luIGRhdGEgbWF5IGNvbnRhaW4gZXh0cmEgcHJpdmF0ZSBmaWVsZHMgKGUuZy4gZGV2aWNlIGlkZW50aXR5KS4gU2V0dGluZ3MgYXJlIHRoZSBwdWJsaWMgc3Vic2V0LlxuICAgIHRoaXMuc2V0dGluZ3MgPSBPYmplY3QuYXNzaWduKHt9LCBERUZBVUxUX1NFVFRJTkdTLCBkYXRhKTtcbiAgfVxuXG4gIGFzeW5jIHNhdmVTZXR0aW5ncygpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICAvLyBQcmVzZXJ2ZSBhbnkgcHJpdmF0ZSBmaWVsZHMgc3RvcmVkIGluIHBsdWdpbiBkYXRhLlxuICAgIGNvbnN0IGRhdGEgPSAoYXdhaXQgdGhpcy5sb2FkRGF0YSgpKSA/PyB7fTtcbiAgICBhd2FpdCB0aGlzLnNhdmVEYXRhKHsgLi4uZGF0YSwgLi4udGhpcy5zZXR0aW5ncyB9KTtcbiAgfVxuXG4gIC8vIFx1MjUwMFx1MjUwMCBEZXZpY2UgaWRlbnRpdHkgcGVyc2lzdGVuY2UgKHBsdWdpbi1zY29wZWQ7IE5PVCBsb2NhbFN0b3JhZ2UpIFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFxuXG4gIGFzeW5jIHJlc2V0RGV2aWNlSWRlbnRpdHkoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgYXdhaXQgdGhpcy5fY2xlYXJEZXZpY2VJZGVudGl0eSgpO1xuICAgIG5ldyBOb3RpY2UoJ09wZW5DbGF3IENoYXQ6IGRldmljZSBpZGVudGl0eSByZXNldC4gUmVjb25uZWN0IHRvIHBhaXIgYWdhaW4uJyk7XG4gIH1cblxuICBwcml2YXRlIF9kZXZpY2VJZGVudGl0eUtleSA9ICdfb3BlbmNsYXdEZXZpY2VJZGVudGl0eVYxJztcblxuICBwcml2YXRlIGFzeW5jIF9sb2FkRGV2aWNlSWRlbnRpdHkoKTogUHJvbWlzZTxhbnkgfCBudWxsPiB7XG4gICAgY29uc3QgZGF0YSA9IChhd2FpdCB0aGlzLmxvYWREYXRhKCkpID8/IHt9O1xuICAgIHJldHVybiAoZGF0YSBhcyBhbnkpPy5bdGhpcy5fZGV2aWNlSWRlbnRpdHlLZXldID8/IG51bGw7XG4gIH1cblxuICBwcml2YXRlIGFzeW5jIF9zYXZlRGV2aWNlSWRlbnRpdHkoaWRlbnRpdHk6IGFueSk6IFByb21pc2U8dm9pZD4ge1xuICAgIGNvbnN0IGRhdGEgPSAoYXdhaXQgdGhpcy5sb2FkRGF0YSgpKSA/PyB7fTtcbiAgICBhd2FpdCB0aGlzLnNhdmVEYXRhKHsgLi4uZGF0YSwgW3RoaXMuX2RldmljZUlkZW50aXR5S2V5XTogaWRlbnRpdHkgfSk7XG4gIH1cblxuICBwcml2YXRlIGFzeW5jIF9jbGVhckRldmljZUlkZW50aXR5KCk6IFByb21pc2U8dm9pZD4ge1xuICAgIGNvbnN0IGRhdGEgPSAoYXdhaXQgdGhpcy5sb2FkRGF0YSgpKSA/PyB7fTtcbiAgICBpZiAoKGRhdGEgYXMgYW55KT8uW3RoaXMuX2RldmljZUlkZW50aXR5S2V5XSA9PT0gdW5kZWZpbmVkKSByZXR1cm47XG4gICAgY29uc3QgbmV4dCA9IHsgLi4uKGRhdGEgYXMgYW55KSB9O1xuICAgIGRlbGV0ZSBuZXh0W3RoaXMuX2RldmljZUlkZW50aXR5S2V5XTtcbiAgICBhd2FpdCB0aGlzLnNhdmVEYXRhKG5leHQpO1xuICB9XG5cbiAgLy8gXHUyNTAwXHUyNTAwIEhlbHBlcnMgXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG5cbiAgcHJpdmF0ZSBhc3luYyBfYWN0aXZhdGVDaGF0VmlldygpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBjb25zdCB7IHdvcmtzcGFjZSB9ID0gdGhpcy5hcHA7XG5cbiAgICAvLyBSZXVzZSBleGlzdGluZyBsZWFmIGlmIGFscmVhZHkgb3BlblxuICAgIGNvbnN0IGV4aXN0aW5nID0gd29ya3NwYWNlLmdldExlYXZlc09mVHlwZShWSUVXX1RZUEVfT1BFTkNMQVdfQ0hBVCk7XG4gICAgaWYgKGV4aXN0aW5nLmxlbmd0aCA+IDApIHtcbiAgICAgIHdvcmtzcGFjZS5yZXZlYWxMZWFmKGV4aXN0aW5nWzBdKTtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICAvLyBPcGVuIGluIHJpZ2h0IHNpZGViYXJcbiAgICBjb25zdCBsZWFmID0gd29ya3NwYWNlLmdldFJpZ2h0TGVhZihmYWxzZSk7XG4gICAgaWYgKCFsZWFmKSByZXR1cm47XG4gICAgYXdhaXQgbGVhZi5zZXRWaWV3U3RhdGUoeyB0eXBlOiBWSUVXX1RZUEVfT1BFTkNMQVdfQ0hBVCwgYWN0aXZlOiB0cnVlIH0pO1xuICAgIHdvcmtzcGFjZS5yZXZlYWxMZWFmKGxlYWYpO1xuICB9XG59XG4iLCAiaW1wb3J0IHsgQXBwLCBQbHVnaW5TZXR0aW5nVGFiLCBTZXR0aW5nIH0gZnJvbSAnb2JzaWRpYW4nO1xuaW1wb3J0IHR5cGUgT3BlbkNsYXdQbHVnaW4gZnJvbSAnLi9tYWluJztcblxuZXhwb3J0IGNsYXNzIE9wZW5DbGF3U2V0dGluZ1RhYiBleHRlbmRzIFBsdWdpblNldHRpbmdUYWIge1xuICBwbHVnaW46IE9wZW5DbGF3UGx1Z2luO1xuXG4gIGNvbnN0cnVjdG9yKGFwcDogQXBwLCBwbHVnaW46IE9wZW5DbGF3UGx1Z2luKSB7XG4gICAgc3VwZXIoYXBwLCBwbHVnaW4pO1xuICAgIHRoaXMucGx1Z2luID0gcGx1Z2luO1xuICB9XG5cbiAgZGlzcGxheSgpOiB2b2lkIHtcbiAgICBjb25zdCB7IGNvbnRhaW5lckVsIH0gPSB0aGlzO1xuICAgIGNvbnRhaW5lckVsLmVtcHR5KCk7XG5cbiAgICBjb250YWluZXJFbC5jcmVhdGVFbCgnaDInLCB7IHRleHQ6ICdPcGVuQ2xhdyBDaGF0IFx1MjAxMyBTZXR0aW5ncycgfSk7XG5cbiAgICBuZXcgU2V0dGluZyhjb250YWluZXJFbClcbiAgICAgIC5zZXROYW1lKCdHYXRld2F5IFVSTCcpXG4gICAgICAuc2V0RGVzYygnV2ViU29ja2V0IFVSTCBvZiB0aGUgT3BlbkNsYXcgR2F0ZXdheSAoZS5nLiB3czovL2hvc3RuYW1lOjE4Nzg5KS4nKVxuICAgICAgLmFkZFRleHQoKHRleHQpID0+XG4gICAgICAgIHRleHRcbiAgICAgICAgICAuc2V0UGxhY2Vob2xkZXIoJ3dzOi8vbG9jYWxob3N0OjE4Nzg5JylcbiAgICAgICAgICAuc2V0VmFsdWUodGhpcy5wbHVnaW4uc2V0dGluZ3MuZ2F0ZXdheVVybClcbiAgICAgICAgICAub25DaGFuZ2UoYXN5bmMgKHZhbHVlKSA9PiB7XG4gICAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5nYXRld2F5VXJsID0gdmFsdWUudHJpbSgpO1xuICAgICAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uc2F2ZVNldHRpbmdzKCk7XG4gICAgICAgICAgfSlcbiAgICAgICk7XG5cbiAgICBuZXcgU2V0dGluZyhjb250YWluZXJFbClcbiAgICAgIC5zZXROYW1lKCdBdXRoIHRva2VuJylcbiAgICAgIC5zZXREZXNjKCdNdXN0IG1hdGNoIHRoZSBhdXRoVG9rZW4gaW4geW91ciBvcGVuY2xhdy5qc29uIGNoYW5uZWwgY29uZmlnLiBOZXZlciBzaGFyZWQuJylcbiAgICAgIC5hZGRUZXh0KCh0ZXh0KSA9PiB7XG4gICAgICAgIHRleHRcbiAgICAgICAgICAuc2V0UGxhY2Vob2xkZXIoJ0VudGVyIHRva2VuXHUyMDI2JylcbiAgICAgICAgICAuc2V0VmFsdWUodGhpcy5wbHVnaW4uc2V0dGluZ3MuYXV0aFRva2VuKVxuICAgICAgICAgIC5vbkNoYW5nZShhc3luYyAodmFsdWUpID0+IHtcbiAgICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLmF1dGhUb2tlbiA9IHZhbHVlO1xuICAgICAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uc2F2ZVNldHRpbmdzKCk7XG4gICAgICAgICAgfSk7XG4gICAgICAgIC8vIFRyZWF0IGFzIHBhc3N3b3JkIGZpZWxkIFx1MjAxMyBkbyBub3QgcmV2ZWFsIHRva2VuIGluIFVJXG4gICAgICAgIHRleHQuaW5wdXRFbC50eXBlID0gJ3Bhc3N3b3JkJztcbiAgICAgICAgdGV4dC5pbnB1dEVsLmF1dG9jb21wbGV0ZSA9ICdvZmYnO1xuICAgICAgfSk7XG5cbiAgICBuZXcgU2V0dGluZyhjb250YWluZXJFbClcbiAgICAgIC5zZXROYW1lKCdTZXNzaW9uIEtleScpXG4gICAgICAuc2V0RGVzYygnT3BlbkNsYXcgc2Vzc2lvbiB0byBzdWJzY3JpYmUgdG8gKHVzdWFsbHkgXCJtYWluXCIpLicpXG4gICAgICAuYWRkVGV4dCgodGV4dCkgPT5cbiAgICAgICAgdGV4dFxuICAgICAgICAgIC5zZXRQbGFjZWhvbGRlcignbWFpbicpXG4gICAgICAgICAgLnNldFZhbHVlKHRoaXMucGx1Z2luLnNldHRpbmdzLnNlc3Npb25LZXkpXG4gICAgICAgICAgLm9uQ2hhbmdlKGFzeW5jICh2YWx1ZSkgPT4ge1xuICAgICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3Muc2Vzc2lvbktleSA9IHZhbHVlLnRyaW0oKSB8fCAnbWFpbic7XG4gICAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgICB9KVxuICAgICAgKTtcblxuICAgIG5ldyBTZXR0aW5nKGNvbnRhaW5lckVsKVxuICAgICAgLnNldE5hbWUoJ0FjY291bnQgSUQnKVxuICAgICAgLnNldERlc2MoJ09wZW5DbGF3IGFjY291bnQgSUQgKHVzdWFsbHkgXCJtYWluXCIpLicpXG4gICAgICAuYWRkVGV4dCgodGV4dCkgPT5cbiAgICAgICAgdGV4dFxuICAgICAgICAgIC5zZXRQbGFjZWhvbGRlcignbWFpbicpXG4gICAgICAgICAgLnNldFZhbHVlKHRoaXMucGx1Z2luLnNldHRpbmdzLmFjY291bnRJZClcbiAgICAgICAgICAub25DaGFuZ2UoYXN5bmMgKHZhbHVlKSA9PiB7XG4gICAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5hY2NvdW50SWQgPSB2YWx1ZS50cmltKCkgfHwgJ21haW4nO1xuICAgICAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uc2F2ZVNldHRpbmdzKCk7XG4gICAgICAgICAgfSlcbiAgICAgICk7XG5cbiAgICBuZXcgU2V0dGluZyhjb250YWluZXJFbClcbiAgICAgIC5zZXROYW1lKCdJbmNsdWRlIGFjdGl2ZSBub3RlIGJ5IGRlZmF1bHQnKVxuICAgICAgLnNldERlc2MoJ1ByZS1jaGVjayBcIkluY2x1ZGUgYWN0aXZlIG5vdGVcIiBpbiB0aGUgY2hhdCBwYW5lbCB3aGVuIGl0IG9wZW5zLicpXG4gICAgICAuYWRkVG9nZ2xlKCh0b2dnbGUpID0+XG4gICAgICAgIHRvZ2dsZS5zZXRWYWx1ZSh0aGlzLnBsdWdpbi5zZXR0aW5ncy5pbmNsdWRlQWN0aXZlTm90ZSkub25DaGFuZ2UoYXN5bmMgKHZhbHVlKSA9PiB7XG4gICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3MuaW5jbHVkZUFjdGl2ZU5vdGUgPSB2YWx1ZTtcbiAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgfSlcbiAgICAgICk7XG5cbiAgICBuZXcgU2V0dGluZyhjb250YWluZXJFbClcbiAgICAgIC5zZXROYW1lKCdSZW5kZXIgYXNzaXN0YW50IGFzIE1hcmtkb3duICh1bnNhZmUpJylcbiAgICAgIC5zZXREZXNjKFxuICAgICAgICAnT0ZGIHJlY29tbWVuZGVkLiBJZiBlbmFibGVkLCBhc3Npc3RhbnQgb3V0cHV0IGlzIHJlbmRlcmVkIGFzIE9ic2lkaWFuIE1hcmtkb3duIHdoaWNoIG1heSB0cmlnZ2VyIGVtYmVkcyBhbmQgb3RoZXIgcGx1Z2luc1xcJyBwb3N0LXByb2Nlc3NvcnMuJ1xuICAgICAgKVxuICAgICAgLmFkZFRvZ2dsZSgodG9nZ2xlKSA9PlxuICAgICAgICB0b2dnbGUuc2V0VmFsdWUodGhpcy5wbHVnaW4uc2V0dGluZ3MucmVuZGVyQXNzaXN0YW50TWFya2Rvd24pLm9uQ2hhbmdlKGFzeW5jICh2YWx1ZSkgPT4ge1xuICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLnJlbmRlckFzc2lzdGFudE1hcmtkb3duID0gdmFsdWU7XG4gICAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uc2F2ZVNldHRpbmdzKCk7XG4gICAgICAgIH0pXG4gICAgICApO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZSgnQWxsb3cgaW5zZWN1cmUgd3M6Ly8gZm9yIG5vbi1sb2NhbCBnYXRld2F5cyAodW5zYWZlKScpXG4gICAgICAuc2V0RGVzYyhcbiAgICAgICAgJ09GRiByZWNvbW1lbmRlZC4gSWYgZW5hYmxlZCwgeW91IGNhbiBjb25uZWN0IHRvIG5vbi1sb2NhbCBnYXRld2F5cyBvdmVyIHdzOi8vLiBUaGlzIGV4cG9zZXMgeW91ciB0b2tlbiBhbmQgbWVzc2FnZSBjb250ZW50IHRvIG5ldHdvcmsgYXR0YWNrZXJzOyBwcmVmZXIgd3NzOi8vLidcbiAgICAgIClcbiAgICAgIC5hZGRUb2dnbGUoKHRvZ2dsZSkgPT5cbiAgICAgICAgdG9nZ2xlLnNldFZhbHVlKHRoaXMucGx1Z2luLnNldHRpbmdzLmFsbG93SW5zZWN1cmVXcykub25DaGFuZ2UoYXN5bmMgKHZhbHVlKSA9PiB7XG4gICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3MuYWxsb3dJbnNlY3VyZVdzID0gdmFsdWU7XG4gICAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uc2F2ZVNldHRpbmdzKCk7XG4gICAgICAgIH0pXG4gICAgICApO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZSgnUmVzZXQgZGV2aWNlIGlkZW50aXR5IChyZS1wYWlyKScpXG4gICAgICAuc2V0RGVzYygnQ2xlYXJzIHRoZSBzdG9yZWQgZGV2aWNlIGlkZW50aXR5IHVzZWQgZm9yIG9wZXJhdG9yLndyaXRlIHBhaXJpbmcuIFVzZSB0aGlzIGlmIHlvdSBzdXNwZWN0IGNvbXByb21pc2Ugb3Igc2VlIFwiZGV2aWNlIGlkZW50aXR5IG1pc21hdGNoXCIuJylcbiAgICAgIC5hZGRCdXR0b24oKGJ0bikgPT5cbiAgICAgICAgYnRuLnNldEJ1dHRvblRleHQoJ1Jlc2V0Jykuc2V0V2FybmluZygpLm9uQ2xpY2soYXN5bmMgKCkgPT4ge1xuICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnJlc2V0RGV2aWNlSWRlbnRpdHkoKTtcbiAgICAgICAgfSlcbiAgICAgICk7XG5cbiAgICAvLyBcdTI1MDBcdTI1MDAgUGF0aCBtYXBwaW5ncyBcdTI1MDBcdTI1MDBcbiAgICBjb250YWluZXJFbC5jcmVhdGVFbCgnaDMnLCB7IHRleHQ6ICdQYXRoIG1hcHBpbmdzICh2YXVsdCBiYXNlIFx1MjE5MiByZW1vdGUgYmFzZSknIH0pO1xuICAgIGNvbnRhaW5lckVsLmNyZWF0ZUVsKCdwJywge1xuICAgICAgdGV4dDogJ1VzZWQgdG8gY29udmVydCBhc3Npc3RhbnQgZmlsZSByZWZlcmVuY2VzIChyZW1vdGUgRlMgcGF0aHMgb3IgZXhwb3J0ZWQgVVJMcykgaW50byBjbGlja2FibGUgT2JzaWRpYW4gbGlua3MuIEZpcnN0IG1hdGNoIHdpbnMuIE9ubHkgY3JlYXRlcyBhIGxpbmsgaWYgdGhlIG1hcHBlZCB2YXVsdCBmaWxlIGV4aXN0cy4nLFxuICAgICAgY2xzOiAnc2V0dGluZy1pdGVtLWRlc2NyaXB0aW9uJyxcbiAgICB9KTtcblxuICAgIGNvbnN0IG1hcHBpbmdzID0gdGhpcy5wbHVnaW4uc2V0dGluZ3MucGF0aE1hcHBpbmdzID8/IFtdO1xuXG4gICAgY29uc3QgcmVyZW5kZXIgPSBhc3luYyAoKSA9PiB7XG4gICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgIHRoaXMuZGlzcGxheSgpO1xuICAgIH07XG5cbiAgICBtYXBwaW5ncy5mb3JFYWNoKChyb3csIGlkeCkgPT4ge1xuICAgICAgY29uc3QgcyA9IG5ldyBTZXR0aW5nKGNvbnRhaW5lckVsKVxuICAgICAgICAuc2V0TmFtZShgTWFwcGluZyAjJHtpZHggKyAxfWApXG4gICAgICAgIC5zZXREZXNjKCd2YXVsdEJhc2UgXHUyMTkyIHJlbW90ZUJhc2UnKTtcblxuICAgICAgcy5hZGRUZXh0KCh0KSA9PlxuICAgICAgICB0XG4gICAgICAgICAgLnNldFBsYWNlaG9sZGVyKCd2YXVsdCBiYXNlIChlLmcuIGRvY3MvKScpXG4gICAgICAgICAgLnNldFZhbHVlKHJvdy52YXVsdEJhc2UgPz8gJycpXG4gICAgICAgICAgLm9uQ2hhbmdlKGFzeW5jICh2KSA9PiB7XG4gICAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5wYXRoTWFwcGluZ3NbaWR4XS52YXVsdEJhc2UgPSB2O1xuICAgICAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uc2F2ZVNldHRpbmdzKCk7XG4gICAgICAgICAgfSlcbiAgICAgICk7XG5cbiAgICAgIHMuYWRkVGV4dCgodCkgPT5cbiAgICAgICAgdFxuICAgICAgICAgIC5zZXRQbGFjZWhvbGRlcigncmVtb3RlIGJhc2UgKGUuZy4gL2hvbWUvLi4uL2RvY3MvKScpXG4gICAgICAgICAgLnNldFZhbHVlKHJvdy5yZW1vdGVCYXNlID8/ICcnKVxuICAgICAgICAgIC5vbkNoYW5nZShhc3luYyAodikgPT4ge1xuICAgICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3MucGF0aE1hcHBpbmdzW2lkeF0ucmVtb3RlQmFzZSA9IHY7XG4gICAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgICB9KVxuICAgICAgKTtcblxuICAgICAgcy5hZGRFeHRyYUJ1dHRvbigoYikgPT5cbiAgICAgICAgYlxuICAgICAgICAgIC5zZXRJY29uKCd0cmFzaCcpXG4gICAgICAgICAgLnNldFRvb2x0aXAoJ1JlbW92ZSBtYXBwaW5nJylcbiAgICAgICAgICAub25DbGljayhhc3luYyAoKSA9PiB7XG4gICAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5wYXRoTWFwcGluZ3Muc3BsaWNlKGlkeCwgMSk7XG4gICAgICAgICAgICBhd2FpdCByZXJlbmRlcigpO1xuICAgICAgICAgIH0pXG4gICAgICApO1xuICAgIH0pO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZSgnQWRkIG1hcHBpbmcnKVxuICAgICAgLnNldERlc2MoJ0FkZCBhIG5ldyB2YXVsdEJhc2UgXHUyMTkyIHJlbW90ZUJhc2UgbWFwcGluZyByb3cuJylcbiAgICAgIC5hZGRCdXR0b24oKGJ0bikgPT5cbiAgICAgICAgYnRuLnNldEJ1dHRvblRleHQoJ0FkZCcpLm9uQ2xpY2soYXN5bmMgKCkgPT4ge1xuICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLnBhdGhNYXBwaW5ncy5wdXNoKHsgdmF1bHRCYXNlOiAnJywgcmVtb3RlQmFzZTogJycgfSk7XG4gICAgICAgICAgYXdhaXQgcmVyZW5kZXIoKTtcbiAgICAgICAgfSlcbiAgICAgICk7XG5cbiAgICBjb250YWluZXJFbC5jcmVhdGVFbCgncCcsIHtcbiAgICAgIHRleHQ6ICdSZWNvbm5lY3Q6IGNsb3NlIGFuZCByZW9wZW4gdGhlIHNpZGViYXIgYWZ0ZXIgY2hhbmdpbmcgdGhlIGdhdGV3YXkgVVJMIG9yIHRva2VuLicsXG4gICAgICBjbHM6ICdzZXR0aW5nLWl0ZW0tZGVzY3JpcHRpb24nLFxuICAgIH0pO1xuICB9XG59XG4iLCAiLyoqXG4gKiBXZWJTb2NrZXQgY2xpZW50IGZvciBPcGVuQ2xhdyBHYXRld2F5XG4gKlxuICogUGl2b3QgKDIwMjYtMDItMjUpOiBEbyBOT1QgdXNlIGN1c3RvbSBvYnNpZGlhbi4qIGdhdGV3YXkgbWV0aG9kcy5cbiAqIFRob3NlIHJlcXVpcmUgb3BlcmF0b3IuYWRtaW4gc2NvcGUgd2hpY2ggaXMgbm90IGdyYW50ZWQgdG8gZXh0ZXJuYWwgY2xpZW50cy5cbiAqXG4gKiBBdXRoIG5vdGU6XG4gKiAtIGNoYXQuc2VuZCByZXF1aXJlcyBvcGVyYXRvci53cml0ZVxuICogLSBleHRlcm5hbCBjbGllbnRzIG11c3QgcHJlc2VudCBhIHBhaXJlZCBkZXZpY2UgaWRlbnRpdHkgdG8gcmVjZWl2ZSB3cml0ZSBzY29wZXNcbiAqXG4gKiBXZSB1c2UgYnVpbHQtaW4gZ2F0ZXdheSBtZXRob2RzL2V2ZW50czpcbiAqIC0gU2VuZDogY2hhdC5zZW5kKHsgc2Vzc2lvbktleSwgbWVzc2FnZSwgaWRlbXBvdGVuY3lLZXksIC4uLiB9KVxuICogLSBSZWNlaXZlOiBldmVudCBcImNoYXRcIiAoZmlsdGVyIGJ5IHNlc3Npb25LZXkpXG4gKi9cblxuaW1wb3J0IHR5cGUgeyBJbmJvdW5kV1NQYXlsb2FkIH0gZnJvbSAnLi90eXBlcyc7XG5cbmZ1bmN0aW9uIGlzTG9jYWxIb3N0KGhvc3Q6IHN0cmluZyk6IGJvb2xlYW4ge1xuICBjb25zdCBoID0gaG9zdC50b0xvd2VyQ2FzZSgpO1xuICByZXR1cm4gaCA9PT0gJ2xvY2FsaG9zdCcgfHwgaCA9PT0gJzEyNy4wLjAuMScgfHwgaCA9PT0gJzo6MSc7XG59XG5cbmZ1bmN0aW9uIHNhZmVQYXJzZVdzVXJsKHVybDogc3RyaW5nKTpcbiAgfCB7IG9rOiB0cnVlOyBzY2hlbWU6ICd3cycgfCAnd3NzJzsgaG9zdDogc3RyaW5nIH1cbiAgfCB7IG9rOiBmYWxzZTsgZXJyb3I6IHN0cmluZyB9IHtcbiAgdHJ5IHtcbiAgICBjb25zdCB1ID0gbmV3IFVSTCh1cmwpO1xuICAgIGlmICh1LnByb3RvY29sICE9PSAnd3M6JyAmJiB1LnByb3RvY29sICE9PSAnd3NzOicpIHtcbiAgICAgIHJldHVybiB7IG9rOiBmYWxzZSwgZXJyb3I6IGBHYXRld2F5IFVSTCBtdXN0IGJlIHdzOi8vIG9yIHdzczovLyAoZ290ICR7dS5wcm90b2NvbH0pYCB9O1xuICAgIH1cbiAgICBjb25zdCBzY2hlbWUgPSB1LnByb3RvY29sID09PSAnd3M6JyA/ICd3cycgOiAnd3NzJztcbiAgICByZXR1cm4geyBvazogdHJ1ZSwgc2NoZW1lLCBob3N0OiB1Lmhvc3RuYW1lIH07XG4gIH0gY2F0Y2gge1xuICAgIHJldHVybiB7IG9rOiBmYWxzZSwgZXJyb3I6ICdJbnZhbGlkIGdhdGV3YXkgVVJMJyB9O1xuICB9XG59XG5cbi8qKiBJbnRlcnZhbCBmb3Igc2VuZGluZyBoZWFydGJlYXQgcGluZ3MgKGNoZWNrIGNvbm5lY3Rpb24gbGl2ZW5lc3MpICovXG5jb25zdCBIRUFSVEJFQVRfSU5URVJWQUxfTVMgPSAzMF8wMDA7XG5cbi8qKiBTYWZldHkgdmFsdmU6IGhpZGUgd29ya2luZyBzcGlubmVyIGlmIG5vIGFzc2lzdGFudCByZXBseSBhcnJpdmVzIGluIHRpbWUgKi9cbmNvbnN0IFdPUktJTkdfTUFYX01TID0gMTIwXzAwMDtcblxuLyoqIE1heCBpbmJvdW5kIGZyYW1lIHNpemUgdG8gcGFyc2UgKERvUyBndWFyZCkgKi9cbmNvbnN0IE1BWF9JTkJPVU5EX0ZSQU1FX0JZVEVTID0gNTEyICogMTAyNDtcblxuZnVuY3Rpb24gYnl0ZUxlbmd0aFV0ZjgodGV4dDogc3RyaW5nKTogbnVtYmVyIHtcbiAgcmV0dXJuIHV0ZjhCeXRlcyh0ZXh0KS5ieXRlTGVuZ3RoO1xufVxuXG5hc3luYyBmdW5jdGlvbiBub3JtYWxpemVXc0RhdGFUb1RleHQoZGF0YTogYW55KTogUHJvbWlzZTx7IG9rOiB0cnVlOyB0ZXh0OiBzdHJpbmc7IGJ5dGVzOiBudW1iZXIgfSB8IHsgb2s6IGZhbHNlOyByZWFzb246IHN0cmluZzsgYnl0ZXM/OiBudW1iZXIgfT4ge1xuICBpZiAodHlwZW9mIGRhdGEgPT09ICdzdHJpbmcnKSB7XG4gICAgY29uc3QgYnl0ZXMgPSBieXRlTGVuZ3RoVXRmOChkYXRhKTtcbiAgICByZXR1cm4geyBvazogdHJ1ZSwgdGV4dDogZGF0YSwgYnl0ZXMgfTtcbiAgfVxuXG4gIC8vIEJyb3dzZXIgV2ViU29ja2V0IGNhbiBkZWxpdmVyIEJsb2JcbiAgaWYgKHR5cGVvZiBCbG9iICE9PSAndW5kZWZpbmVkJyAmJiBkYXRhIGluc3RhbmNlb2YgQmxvYikge1xuICAgIGNvbnN0IGJ5dGVzID0gZGF0YS5zaXplO1xuICAgIGlmIChieXRlcyA+IE1BWF9JTkJPVU5EX0ZSQU1FX0JZVEVTKSByZXR1cm4geyBvazogZmFsc2UsIHJlYXNvbjogJ3Rvby1sYXJnZScsIGJ5dGVzIH07XG4gICAgY29uc3QgdGV4dCA9IGF3YWl0IGRhdGEudGV4dCgpO1xuICAgIC8vIEJsb2Iuc2l6ZSBpcyBieXRlcyBhbHJlYWR5OyBubyBuZWVkIHRvIHJlLW1lYXN1cmUuXG4gICAgcmV0dXJuIHsgb2s6IHRydWUsIHRleHQsIGJ5dGVzIH07XG4gIH1cblxuICBpZiAoZGF0YSBpbnN0YW5jZW9mIEFycmF5QnVmZmVyKSB7XG4gICAgY29uc3QgYnl0ZXMgPSBkYXRhLmJ5dGVMZW5ndGg7XG4gICAgaWYgKGJ5dGVzID4gTUFYX0lOQk9VTkRfRlJBTUVfQllURVMpIHJldHVybiB7IG9rOiBmYWxzZSwgcmVhc29uOiAndG9vLWxhcmdlJywgYnl0ZXMgfTtcbiAgICBjb25zdCB0ZXh0ID0gbmV3IFRleHREZWNvZGVyKCd1dGYtOCcsIHsgZmF0YWw6IGZhbHNlIH0pLmRlY29kZShuZXcgVWludDhBcnJheShkYXRhKSk7XG4gICAgcmV0dXJuIHsgb2s6IHRydWUsIHRleHQsIGJ5dGVzIH07XG4gIH1cblxuICAvLyBTb21lIHJ1bnRpbWVzIGNvdWxkIHBhc3MgVWludDhBcnJheSBkaXJlY3RseVxuICBpZiAoZGF0YSBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpIHtcbiAgICBjb25zdCBieXRlcyA9IGRhdGEuYnl0ZUxlbmd0aDtcbiAgICBpZiAoYnl0ZXMgPiBNQVhfSU5CT1VORF9GUkFNRV9CWVRFUykgcmV0dXJuIHsgb2s6IGZhbHNlLCByZWFzb246ICd0b28tbGFyZ2UnLCBieXRlcyB9O1xuICAgIGNvbnN0IHRleHQgPSBuZXcgVGV4dERlY29kZXIoJ3V0Zi04JywgeyBmYXRhbDogZmFsc2UgfSkuZGVjb2RlKGRhdGEpO1xuICAgIHJldHVybiB7IG9rOiB0cnVlLCB0ZXh0LCBieXRlcyB9O1xuICB9XG5cbiAgcmV0dXJuIHsgb2s6IGZhbHNlLCByZWFzb246ICd1bnN1cHBvcnRlZC10eXBlJyB9O1xufVxuXG4vKiogTWF4IGluLWZsaWdodCByZXF1ZXN0cyBiZWZvcmUgZmFzdC1mYWlsaW5nIChEb1Mvcm9idXN0bmVzcyBndWFyZCkgKi9cbmNvbnN0IE1BWF9QRU5ESU5HX1JFUVVFU1RTID0gMjAwO1xuXG4vKiogUmVjb25uZWN0IGJhY2tvZmYgKi9cbmNvbnN0IFJFQ09OTkVDVF9CQVNFX01TID0gM18wMDA7XG5jb25zdCBSRUNPTk5FQ1RfTUFYX01TID0gNjBfMDAwO1xuXG4vKiogSGFuZHNoYWtlIGRlYWRsaW5lIHdhaXRpbmcgZm9yIGNvbm5lY3QuY2hhbGxlbmdlICovXG5jb25zdCBIQU5EU0hBS0VfVElNRU9VVF9NUyA9IDE1XzAwMDtcblxuZXhwb3J0IHR5cGUgV1NDbGllbnRTdGF0ZSA9ICdkaXNjb25uZWN0ZWQnIHwgJ2Nvbm5lY3RpbmcnIHwgJ2hhbmRzaGFraW5nJyB8ICdjb25uZWN0ZWQnO1xuXG5leHBvcnQgdHlwZSBXb3JraW5nU3RhdGVMaXN0ZW5lciA9ICh3b3JraW5nOiBib29sZWFuKSA9PiB2b2lkO1xuXG5pbnRlcmZhY2UgUGVuZGluZ1JlcXVlc3Qge1xuICByZXNvbHZlOiAocGF5bG9hZDogYW55KSA9PiB2b2lkO1xuICByZWplY3Q6IChlcnJvcjogYW55KSA9PiB2b2lkO1xuICB0aW1lb3V0OiBSZXR1cm5UeXBlPHR5cGVvZiBzZXRUaW1lb3V0PiB8IG51bGw7XG59XG5cbmV4cG9ydCB0eXBlIERldmljZUlkZW50aXR5ID0ge1xuICBpZDogc3RyaW5nO1xuICBwdWJsaWNLZXk6IHN0cmluZzsgLy8gYmFzZTY0XG4gIHByaXZhdGVLZXlKd2s6IEpzb25XZWJLZXk7XG59O1xuXG5leHBvcnQgaW50ZXJmYWNlIERldmljZUlkZW50aXR5U3RvcmUge1xuICBnZXQoKTogUHJvbWlzZTxEZXZpY2VJZGVudGl0eSB8IG51bGw+O1xuICBzZXQoaWRlbnRpdHk6IERldmljZUlkZW50aXR5KTogUHJvbWlzZTx2b2lkPjtcbiAgY2xlYXIoKTogUHJvbWlzZTx2b2lkPjtcbn1cblxuY29uc3QgREVWSUNFX1NUT1JBR0VfS0VZID0gJ29wZW5jbGF3Q2hhdC5kZXZpY2VJZGVudGl0eS52MSc7IC8vIGxlZ2FjeSBsb2NhbFN0b3JhZ2Uga2V5IChtaWdyYXRpb24gb25seSlcblxuZnVuY3Rpb24gYmFzZTY0VXJsRW5jb2RlKGJ5dGVzOiBBcnJheUJ1ZmZlcik6IHN0cmluZyB7XG4gIGNvbnN0IHU4ID0gbmV3IFVpbnQ4QXJyYXkoYnl0ZXMpO1xuICBsZXQgcyA9ICcnO1xuICBmb3IgKGxldCBpID0gMDsgaSA8IHU4Lmxlbmd0aDsgaSsrKSBzICs9IFN0cmluZy5mcm9tQ2hhckNvZGUodThbaV0pO1xuICBjb25zdCBiNjQgPSBidG9hKHMpO1xuICByZXR1cm4gYjY0LnJlcGxhY2UoL1xcKy9nLCAnLScpLnJlcGxhY2UoL1xcLy9nLCAnXycpLnJlcGxhY2UoLz0rJC9nLCAnJyk7XG59XG5cbmZ1bmN0aW9uIGhleEVuY29kZShieXRlczogQXJyYXlCdWZmZXIpOiBzdHJpbmcge1xuICBjb25zdCB1OCA9IG5ldyBVaW50OEFycmF5KGJ5dGVzKTtcbiAgcmV0dXJuIEFycmF5LmZyb20odTgpXG4gICAgLm1hcCgoYikgPT4gYi50b1N0cmluZygxNikucGFkU3RhcnQoMiwgJzAnKSlcbiAgICAuam9pbignJyk7XG59XG5cbmZ1bmN0aW9uIHV0ZjhCeXRlcyh0ZXh0OiBzdHJpbmcpOiBVaW50OEFycmF5IHtcbiAgcmV0dXJuIG5ldyBUZXh0RW5jb2RlcigpLmVuY29kZSh0ZXh0KTtcbn1cblxuYXN5bmMgZnVuY3Rpb24gc2hhMjU2SGV4KGJ5dGVzOiBBcnJheUJ1ZmZlcik6IFByb21pc2U8c3RyaW5nPiB7XG4gIGNvbnN0IGRpZ2VzdCA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuZGlnZXN0KCdTSEEtMjU2JywgYnl0ZXMpO1xuICByZXR1cm4gaGV4RW5jb2RlKGRpZ2VzdCk7XG59XG5cbmFzeW5jIGZ1bmN0aW9uIGxvYWRPckNyZWF0ZURldmljZUlkZW50aXR5KHN0b3JlPzogRGV2aWNlSWRlbnRpdHlTdG9yZSk6IFByb21pc2U8RGV2aWNlSWRlbnRpdHk+IHtcbiAgLy8gMSkgUHJlZmVyIHBsdWdpbi1zY29wZWQgc3RvcmFnZSAoaW5qZWN0ZWQgYnkgbWFpbiBwbHVnaW4pLlxuICBpZiAoc3RvcmUpIHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgZXhpc3RpbmcgPSBhd2FpdCBzdG9yZS5nZXQoKTtcbiAgICAgIGlmIChleGlzdGluZz8uaWQgJiYgZXhpc3Rpbmc/LnB1YmxpY0tleSAmJiBleGlzdGluZz8ucHJpdmF0ZUtleUp3aykgcmV0dXJuIGV4aXN0aW5nO1xuICAgIH0gY2F0Y2gge1xuICAgICAgLy8gaWdub3JlIGFuZCBjb250aW51ZSAod2UgY2FuIGFsd2F5cyByZS1nZW5lcmF0ZSlcbiAgICB9XG4gIH1cblxuICAvLyAyKSBPbmUtdGltZSBtaWdyYXRpb246IGxlZ2FjeSBsb2NhbFN0b3JhZ2UgaWRlbnRpdHkuXG4gIC8vIE5PVEU6IHRoaXMgcmVtYWlucyBhIHJpc2sgYm91bmRhcnk7IHdlIG9ubHkgcmVhZCtkZWxldGUgZm9yIG1pZ3JhdGlvbi5cbiAgY29uc3QgbGVnYWN5ID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oREVWSUNFX1NUT1JBR0VfS0VZKTtcbiAgaWYgKGxlZ2FjeSkge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCBwYXJzZWQgPSBKU09OLnBhcnNlKGxlZ2FjeSkgYXMgRGV2aWNlSWRlbnRpdHk7XG4gICAgICBpZiAocGFyc2VkPy5pZCAmJiBwYXJzZWQ/LnB1YmxpY0tleSAmJiBwYXJzZWQ/LnByaXZhdGVLZXlKd2spIHtcbiAgICAgICAgaWYgKHN0b3JlKSB7XG4gICAgICAgICAgYXdhaXQgc3RvcmUuc2V0KHBhcnNlZCk7XG4gICAgICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oREVWSUNFX1NUT1JBR0VfS0VZKTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gcGFyc2VkO1xuICAgICAgfVxuICAgIH0gY2F0Y2gge1xuICAgICAgLy8gQ29ycnVwdC9wYXJ0aWFsIGRhdGEgXHUyMTkyIGRlbGV0ZSBhbmQgcmUtY3JlYXRlLlxuICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oREVWSUNFX1NUT1JBR0VfS0VZKTtcbiAgICB9XG4gIH1cblxuICAvLyAzKSBDcmVhdGUgYSBuZXcgaWRlbnRpdHkuXG4gIGNvbnN0IGtleVBhaXIgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmdlbmVyYXRlS2V5KHsgbmFtZTogJ0VkMjU1MTknIH0sIHRydWUsIFsnc2lnbicsICd2ZXJpZnknXSk7XG4gIGNvbnN0IHB1YlJhdyA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuZXhwb3J0S2V5KCdyYXcnLCBrZXlQYWlyLnB1YmxpY0tleSk7XG4gIGNvbnN0IHByaXZKd2sgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmV4cG9ydEtleSgnandrJywga2V5UGFpci5wcml2YXRlS2V5KTtcblxuICAvLyBJTVBPUlRBTlQ6IGRldmljZS5pZCBtdXN0IGJlIGEgc3RhYmxlIGZpbmdlcnByaW50IGZvciB0aGUgcHVibGljIGtleS5cbiAgLy8gVGhlIGdhdGV3YXkgZW5mb3JjZXMgZGV2aWNlSWQgXHUyMTk0IHB1YmxpY0tleSBiaW5kaW5nOyByYW5kb20gaWRzIGNhbiBjYXVzZSBcImRldmljZSBpZGVudGl0eSBtaXNtYXRjaFwiLlxuICBjb25zdCBkZXZpY2VJZCA9IGF3YWl0IHNoYTI1NkhleChwdWJSYXcpO1xuXG4gIGNvbnN0IGlkZW50aXR5OiBEZXZpY2VJZGVudGl0eSA9IHtcbiAgICBpZDogZGV2aWNlSWQsXG4gICAgcHVibGljS2V5OiBiYXNlNjRVcmxFbmNvZGUocHViUmF3KSxcbiAgICBwcml2YXRlS2V5SndrOiBwcml2SndrLFxuICB9O1xuXG4gIGlmIChzdG9yZSkge1xuICAgIGF3YWl0IHN0b3JlLnNldChpZGVudGl0eSk7XG4gIH0gZWxzZSB7XG4gICAgLy8gRmFsbGJhY2sgKHNob3VsZCBub3QgaGFwcGVuIGluIHJlYWwgcGx1Z2luIHJ1bnRpbWUpIFx1MjAxNCBrZWVwIGxlZ2FjeSBiZWhhdmlvci5cbiAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbShERVZJQ0VfU1RPUkFHRV9LRVksIEpTT04uc3RyaW5naWZ5KGlkZW50aXR5KSk7XG4gIH1cblxuICByZXR1cm4gaWRlbnRpdHk7XG59XG5cbmZ1bmN0aW9uIGJ1aWxkRGV2aWNlQXV0aFBheWxvYWQocGFyYW1zOiB7XG4gIGRldmljZUlkOiBzdHJpbmc7XG4gIGNsaWVudElkOiBzdHJpbmc7XG4gIGNsaWVudE1vZGU6IHN0cmluZztcbiAgcm9sZTogc3RyaW5nO1xuICBzY29wZXM6IHN0cmluZ1tdO1xuICBzaWduZWRBdE1zOiBudW1iZXI7XG4gIHRva2VuOiBzdHJpbmc7XG4gIG5vbmNlPzogc3RyaW5nO1xufSk6IHN0cmluZyB7XG4gIGNvbnN0IHZlcnNpb24gPSBwYXJhbXMubm9uY2UgPyAndjInIDogJ3YxJztcbiAgY29uc3Qgc2NvcGVzID0gcGFyYW1zLnNjb3Blcy5qb2luKCcsJyk7XG4gIGNvbnN0IGJhc2UgPSBbXG4gICAgdmVyc2lvbixcbiAgICBwYXJhbXMuZGV2aWNlSWQsXG4gICAgcGFyYW1zLmNsaWVudElkLFxuICAgIHBhcmFtcy5jbGllbnRNb2RlLFxuICAgIHBhcmFtcy5yb2xlLFxuICAgIHNjb3BlcyxcbiAgICBTdHJpbmcocGFyYW1zLnNpZ25lZEF0TXMpLFxuICAgIHBhcmFtcy50b2tlbiB8fCAnJyxcbiAgXTtcbiAgaWYgKHZlcnNpb24gPT09ICd2MicpIGJhc2UucHVzaChwYXJhbXMubm9uY2UgfHwgJycpO1xuICByZXR1cm4gYmFzZS5qb2luKCd8Jyk7XG59XG5cbmFzeW5jIGZ1bmN0aW9uIHNpZ25EZXZpY2VQYXlsb2FkKGlkZW50aXR5OiBEZXZpY2VJZGVudGl0eSwgcGF5bG9hZDogc3RyaW5nKTogUHJvbWlzZTx7IHNpZ25hdHVyZTogc3RyaW5nIH0+IHtcbiAgY29uc3QgcHJpdmF0ZUtleSA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KFxuICAgICdqd2snLFxuICAgIGlkZW50aXR5LnByaXZhdGVLZXlKd2ssXG4gICAgeyBuYW1lOiAnRWQyNTUxOScgfSxcbiAgICBmYWxzZSxcbiAgICBbJ3NpZ24nXSxcbiAgKTtcblxuICBjb25zdCBzaWcgPSBhd2FpdCBjcnlwdG8uc3VidGxlLnNpZ24oeyBuYW1lOiAnRWQyNTUxOScgfSwgcHJpdmF0ZUtleSwgdXRmOEJ5dGVzKHBheWxvYWQpIGFzIHVua25vd24gYXMgQnVmZmVyU291cmNlKTtcbiAgcmV0dXJuIHsgc2lnbmF0dXJlOiBiYXNlNjRVcmxFbmNvZGUoc2lnKSB9O1xufVxuXG5mdW5jdGlvbiBleHRyYWN0VGV4dEZyb21HYXRld2F5TWVzc2FnZShtc2c6IGFueSk6IHN0cmluZyB7XG4gIGlmICghbXNnKSByZXR1cm4gJyc7XG5cbiAgLy8gTW9zdCBjb21tb246IHsgcm9sZSwgY29udGVudCB9IHdoZXJlIGNvbnRlbnQgY2FuIGJlIHN0cmluZyBvciBbe3R5cGU6J3RleHQnLHRleHQ6Jy4uLid9XVxuICBjb25zdCBjb250ZW50ID0gbXNnLmNvbnRlbnQgPz8gbXNnLm1lc3NhZ2UgPz8gbXNnO1xuICBpZiAodHlwZW9mIGNvbnRlbnQgPT09ICdzdHJpbmcnKSByZXR1cm4gY29udGVudDtcblxuICBpZiAoQXJyYXkuaXNBcnJheShjb250ZW50KSkge1xuICAgIGNvbnN0IHBhcnRzID0gY29udGVudFxuICAgICAgLmZpbHRlcigoYykgPT4gYyAmJiB0eXBlb2YgYyA9PT0gJ29iamVjdCcgJiYgYy50eXBlID09PSAndGV4dCcgJiYgdHlwZW9mIGMudGV4dCA9PT0gJ3N0cmluZycpXG4gICAgICAubWFwKChjKSA9PiBjLnRleHQpO1xuICAgIHJldHVybiBwYXJ0cy5qb2luKCdcXG4nKTtcbiAgfVxuXG4gIC8vIEZhbGxiYWNrXG4gIHRyeSB7XG4gICAgcmV0dXJuIEpTT04uc3RyaW5naWZ5KGNvbnRlbnQpO1xuICB9IGNhdGNoIHtcbiAgICByZXR1cm4gU3RyaW5nKGNvbnRlbnQpO1xuICB9XG59XG5cbmZ1bmN0aW9uIHNlc3Npb25LZXlNYXRjaGVzKGNvbmZpZ3VyZWQ6IHN0cmluZywgaW5jb21pbmc6IHN0cmluZyk6IGJvb2xlYW4ge1xuICBpZiAoaW5jb21pbmcgPT09IGNvbmZpZ3VyZWQpIHJldHVybiB0cnVlO1xuICAvLyBPcGVuQ2xhdyByZXNvbHZlcyBcIm1haW5cIiB0byBjYW5vbmljYWwgc2Vzc2lvbiBrZXkgbGlrZSBcImFnZW50Om1haW46bWFpblwiLlxuICBpZiAoY29uZmlndXJlZCA9PT0gJ21haW4nICYmIGluY29taW5nID09PSAnYWdlbnQ6bWFpbjptYWluJykgcmV0dXJuIHRydWU7XG4gIHJldHVybiBmYWxzZTtcbn1cblxuZXhwb3J0IGNsYXNzIE9ic2lkaWFuV1NDbGllbnQge1xuICBwcml2YXRlIHdzOiBXZWJTb2NrZXQgfCBudWxsID0gbnVsbDtcbiAgcHJpdmF0ZSByZWNvbm5lY3RUaW1lcjogUmV0dXJuVHlwZTx0eXBlb2Ygc2V0VGltZW91dD4gfCBudWxsID0gbnVsbDtcbiAgcHJpdmF0ZSBoZWFydGJlYXRUaW1lcjogUmV0dXJuVHlwZTx0eXBlb2Ygc2V0SW50ZXJ2YWw+IHwgbnVsbCA9IG51bGw7XG4gIHByaXZhdGUgd29ya2luZ1RpbWVyOiBSZXR1cm5UeXBlPHR5cGVvZiBzZXRUaW1lb3V0PiB8IG51bGwgPSBudWxsO1xuICBwcml2YXRlIGludGVudGlvbmFsQ2xvc2UgPSBmYWxzZTtcbiAgcHJpdmF0ZSBzZXNzaW9uS2V5OiBzdHJpbmc7XG4gIHByaXZhdGUgdXJsID0gJyc7XG4gIHByaXZhdGUgdG9rZW4gPSAnJztcbiAgcHJpdmF0ZSByZXF1ZXN0SWQgPSAwO1xuICBwcml2YXRlIHBlbmRpbmdSZXF1ZXN0cyA9IG5ldyBNYXA8c3RyaW5nLCBQZW5kaW5nUmVxdWVzdD4oKTtcbiAgcHJpdmF0ZSB3b3JraW5nID0gZmFsc2U7XG5cbiAgLyoqIFRoZSBsYXN0IGluLWZsaWdodCBjaGF0IHJ1biBpZC4gSW4gT3BlbkNsYXcgV2ViQ2hhdCB0aGlzIG1hcHMgdG8gY2hhdC5zZW5kIGlkZW1wb3RlbmN5S2V5LiAqL1xuICBwcml2YXRlIGFjdGl2ZVJ1bklkOiBzdHJpbmcgfCBudWxsID0gbnVsbDtcblxuICAvKiogUHJldmVudHMgYWJvcnQgc3BhbW1pbmc6IHdoaWxlIGFuIGFib3J0IHJlcXVlc3QgaXMgaW4tZmxpZ2h0LCByZXVzZSB0aGUgc2FtZSBwcm9taXNlLiAqL1xuICBwcml2YXRlIGFib3J0SW5GbGlnaHQ6IFByb21pc2U8Ym9vbGVhbj4gfCBudWxsID0gbnVsbDtcblxuICBzdGF0ZTogV1NDbGllbnRTdGF0ZSA9ICdkaXNjb25uZWN0ZWQnO1xuXG4gIG9uTWVzc2FnZTogKChtc2c6IEluYm91bmRXU1BheWxvYWQpID0+IHZvaWQpIHwgbnVsbCA9IG51bGw7XG4gIG9uU3RhdGVDaGFuZ2U6ICgoc3RhdGU6IFdTQ2xpZW50U3RhdGUpID0+IHZvaWQpIHwgbnVsbCA9IG51bGw7XG4gIG9uV29ya2luZ0NoYW5nZTogV29ya2luZ1N0YXRlTGlzdGVuZXIgfCBudWxsID0gbnVsbDtcblxuICBwcml2YXRlIGlkZW50aXR5U3RvcmU6IERldmljZUlkZW50aXR5U3RvcmUgfCB1bmRlZmluZWQ7XG4gIHByaXZhdGUgYWxsb3dJbnNlY3VyZVdzID0gZmFsc2U7XG5cbiAgcHJpdmF0ZSByZWNvbm5lY3RBdHRlbXB0ID0gMDtcblxuICBjb25zdHJ1Y3RvcihzZXNzaW9uS2V5OiBzdHJpbmcsIG9wdHM/OiB7IGlkZW50aXR5U3RvcmU/OiBEZXZpY2VJZGVudGl0eVN0b3JlOyBhbGxvd0luc2VjdXJlV3M/OiBib29sZWFuIH0pIHtcbiAgICB0aGlzLnNlc3Npb25LZXkgPSBzZXNzaW9uS2V5O1xuICAgIHRoaXMuaWRlbnRpdHlTdG9yZSA9IG9wdHM/LmlkZW50aXR5U3RvcmU7XG4gICAgdGhpcy5hbGxvd0luc2VjdXJlV3MgPSBCb29sZWFuKG9wdHM/LmFsbG93SW5zZWN1cmVXcyk7XG4gIH1cblxuICBjb25uZWN0KHVybDogc3RyaW5nLCB0b2tlbjogc3RyaW5nLCBvcHRzPzogeyBhbGxvd0luc2VjdXJlV3M/OiBib29sZWFuIH0pOiB2b2lkIHtcbiAgICB0aGlzLnVybCA9IHVybDtcbiAgICB0aGlzLnRva2VuID0gdG9rZW47XG4gICAgdGhpcy5hbGxvd0luc2VjdXJlV3MgPSBCb29sZWFuKG9wdHM/LmFsbG93SW5zZWN1cmVXcyA/PyB0aGlzLmFsbG93SW5zZWN1cmVXcyk7XG4gICAgdGhpcy5pbnRlbnRpb25hbENsb3NlID0gZmFsc2U7XG5cbiAgICAvLyBTZWN1cml0eTogYmxvY2sgbm9uLWxvY2FsIHdzOi8vIHVubGVzcyBleHBsaWNpdGx5IGFsbG93ZWQuXG4gICAgY29uc3QgcGFyc2VkID0gc2FmZVBhcnNlV3NVcmwodXJsKTtcbiAgICBpZiAoIXBhcnNlZC5vaykge1xuICAgICAgdGhpcy5vbk1lc3NhZ2U/Lih7IHR5cGU6ICdlcnJvcicsIHBheWxvYWQ6IHsgbWVzc2FnZTogcGFyc2VkLmVycm9yIH0gfSk7XG4gICAgICByZXR1cm47XG4gICAgfVxuICAgIGlmIChwYXJzZWQuc2NoZW1lID09PSAnd3MnICYmICFpc0xvY2FsSG9zdChwYXJzZWQuaG9zdCkgJiYgIXRoaXMuYWxsb3dJbnNlY3VyZVdzKSB7XG4gICAgICB0aGlzLm9uTWVzc2FnZT8uKHtcbiAgICAgICAgdHlwZTogJ2Vycm9yJyxcbiAgICAgICAgcGF5bG9hZDogeyBtZXNzYWdlOiAnUmVmdXNpbmcgaW5zZWN1cmUgd3M6Ly8gdG8gbm9uLWxvY2FsIGdhdGV3YXkuIFVzZSB3c3M6Ly8gb3IgZW5hYmxlIHRoZSB1bnNhZmUgb3ZlcnJpZGUgaW4gc2V0dGluZ3MuJyB9LFxuICAgICAgfSk7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgdGhpcy5fY29ubmVjdCgpO1xuICB9XG5cbiAgZGlzY29ubmVjdCgpOiB2b2lkIHtcbiAgICB0aGlzLmludGVudGlvbmFsQ2xvc2UgPSB0cnVlO1xuICAgIHRoaXMuX3N0b3BUaW1lcnMoKTtcbiAgICB0aGlzLmFjdGl2ZVJ1bklkID0gbnVsbDtcbiAgICB0aGlzLmFib3J0SW5GbGlnaHQgPSBudWxsO1xuICAgIHRoaXMuX3NldFdvcmtpbmcoZmFsc2UpO1xuICAgIGlmICh0aGlzLndzKSB7XG4gICAgICB0aGlzLndzLmNsb3NlKCk7XG4gICAgICB0aGlzLndzID0gbnVsbDtcbiAgICB9XG4gICAgdGhpcy5fc2V0U3RhdGUoJ2Rpc2Nvbm5lY3RlZCcpO1xuICB9XG5cbiAgc2V0U2Vzc2lvbktleShzZXNzaW9uS2V5OiBzdHJpbmcpOiB2b2lkIHtcbiAgICB0aGlzLnNlc3Npb25LZXkgPSBzZXNzaW9uS2V5LnRyaW0oKTtcbiAgICAvLyBSZXNldCBwZXItc2Vzc2lvbiBydW4gc3RhdGUuXG4gICAgdGhpcy5hY3RpdmVSdW5JZCA9IG51bGw7XG4gICAgdGhpcy5hYm9ydEluRmxpZ2h0ID0gbnVsbDtcbiAgICB0aGlzLl9zZXRXb3JraW5nKGZhbHNlKTtcbiAgfVxuXG4gIC8vIE5PVEU6IGNhbm9uaWNhbCBPYnNpZGlhbiBzZXNzaW9uIGtleXMgZG8gbm90IHJlcXVpcmUgZ2F0ZXdheSBzZXNzaW9ucy5saXN0IGZvciBjb3JlIFVYLlxuXG4gIGFzeW5jIHNlbmRNZXNzYWdlKG1lc3NhZ2U6IHN0cmluZyk6IFByb21pc2U8dm9pZD4ge1xuICAgIGlmICh0aGlzLnN0YXRlICE9PSAnY29ubmVjdGVkJykge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKCdOb3QgY29ubmVjdGVkIFx1MjAxNCBjYWxsIGNvbm5lY3QoKSBmaXJzdCcpO1xuICAgIH1cblxuICAgIGNvbnN0IHJ1bklkID0gYG9ic2lkaWFuLSR7RGF0ZS5ub3coKX0tJHtNYXRoLnJhbmRvbSgpLnRvU3RyaW5nKDM2KS5zbGljZSgyLCA5KX1gO1xuXG4gICAgLy8gU2hvdyBcdTIwMUN3b3JraW5nXHUyMDFEIE9OTFkgYWZ0ZXIgdGhlIGdhdGV3YXkgYWNrbm93bGVkZ2VzIHRoZSByZXF1ZXN0LlxuICAgIGNvbnN0IGFjayA9IGF3YWl0IHRoaXMuX3NlbmRSZXF1ZXN0KCdjaGF0LnNlbmQnLCB7XG4gICAgICBzZXNzaW9uS2V5OiB0aGlzLnNlc3Npb25LZXksXG4gICAgICBtZXNzYWdlLFxuICAgICAgaWRlbXBvdGVuY3lLZXk6IHJ1bklkLFxuICAgICAgLy8gZGVsaXZlciBkZWZhdWx0cyB0byB0cnVlIGluIGdhdGV3YXk7IGtlZXAgZGVmYXVsdFxuICAgIH0pO1xuXG4gICAgLy8gSWYgdGhlIGdhdGV3YXkgcmV0dXJucyBhIGNhbm9uaWNhbCBydW4gaWRlbnRpZmllciwgcHJlZmVyIGl0LlxuICAgIGNvbnN0IGNhbm9uaWNhbFJ1bklkID0gU3RyaW5nKGFjaz8ucnVuSWQgfHwgYWNrPy5pZGVtcG90ZW5jeUtleSB8fCAnJyk7XG4gICAgdGhpcy5hY3RpdmVSdW5JZCA9IGNhbm9uaWNhbFJ1bklkIHx8IHJ1bklkO1xuICAgIHRoaXMuX3NldFdvcmtpbmcodHJ1ZSk7XG4gICAgdGhpcy5fYXJtV29ya2luZ1NhZmV0eVRpbWVvdXQoKTtcbiAgfVxuXG4gIC8qKiBBYm9ydCB0aGUgYWN0aXZlIHJ1biBmb3IgdGhpcyBzZXNzaW9uIChhbmQgb3VyIGxhc3QgcnVuIGlkIGlmIHByZXNlbnQpLiAqL1xuICBhc3luYyBhYm9ydEFjdGl2ZVJ1bigpOiBQcm9taXNlPGJvb2xlYW4+IHtcbiAgICBpZiAodGhpcy5zdGF0ZSAhPT0gJ2Nvbm5lY3RlZCcpIHtcbiAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG5cbiAgICAvLyBQcmV2ZW50IHJlcXVlc3Qgc3Rvcm1zOiB3aGlsZSBvbmUgYWJvcnQgaXMgaW4gZmxpZ2h0LCByZXVzZSBpdC5cbiAgICBpZiAodGhpcy5hYm9ydEluRmxpZ2h0KSB7XG4gICAgICByZXR1cm4gdGhpcy5hYm9ydEluRmxpZ2h0O1xuICAgIH1cblxuICAgIGNvbnN0IHJ1bklkID0gdGhpcy5hY3RpdmVSdW5JZDtcbiAgICBpZiAoIXJ1bklkKSB7XG4gICAgICByZXR1cm4gZmFsc2U7XG4gICAgfVxuXG4gICAgdGhpcy5hYm9ydEluRmxpZ2h0ID0gKGFzeW5jICgpID0+IHtcbiAgICAgIHRyeSB7XG4gICAgICAgIGF3YWl0IHRoaXMuX3NlbmRSZXF1ZXN0KCdjaGF0LmFib3J0JywgeyBzZXNzaW9uS2V5OiB0aGlzLnNlc3Npb25LZXksIHJ1bklkIH0pO1xuICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgIH0gY2F0Y2ggKGVycikge1xuICAgICAgICBjb25zb2xlLmVycm9yKCdbb2NsYXctd3NdIGNoYXQuYWJvcnQgZmFpbGVkJywgZXJyKTtcbiAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgfSBmaW5hbGx5IHtcbiAgICAgICAgLy8gQWx3YXlzIHJlc3RvcmUgVUkgc3RhdGUgaW1tZWRpYXRlbHk7IHRoZSBnYXRld2F5IG1heSBzdGlsbCBlbWl0IGFuIGFib3J0ZWQgZXZlbnQgbGF0ZXIuXG4gICAgICAgIHRoaXMuYWN0aXZlUnVuSWQgPSBudWxsO1xuICAgICAgICB0aGlzLl9zZXRXb3JraW5nKGZhbHNlKTtcbiAgICAgICAgdGhpcy5hYm9ydEluRmxpZ2h0ID0gbnVsbDtcbiAgICAgIH1cbiAgICB9KSgpO1xuXG4gICAgcmV0dXJuIHRoaXMuYWJvcnRJbkZsaWdodDtcbiAgfVxuXG4gIHByaXZhdGUgX2Nvbm5lY3QoKTogdm9pZCB7XG4gICAgaWYgKHRoaXMud3MpIHtcbiAgICAgIHRoaXMud3Mub25vcGVuID0gbnVsbDtcbiAgICAgIHRoaXMud3Mub25jbG9zZSA9IG51bGw7XG4gICAgICB0aGlzLndzLm9ubWVzc2FnZSA9IG51bGw7XG4gICAgICB0aGlzLndzLm9uZXJyb3IgPSBudWxsO1xuICAgICAgdGhpcy53cy5jbG9zZSgpO1xuICAgICAgdGhpcy53cyA9IG51bGw7XG4gICAgfVxuXG4gICAgdGhpcy5fc2V0U3RhdGUoJ2Nvbm5lY3RpbmcnKTtcblxuICAgIGNvbnN0IHdzID0gbmV3IFdlYlNvY2tldCh0aGlzLnVybCk7XG4gICAgdGhpcy53cyA9IHdzO1xuXG4gICAgbGV0IGNvbm5lY3ROb25jZTogc3RyaW5nIHwgbnVsbCA9IG51bGw7XG4gICAgbGV0IGNvbm5lY3RTdGFydGVkID0gZmFsc2U7XG5cbiAgICBjb25zdCB0cnlDb25uZWN0ID0gYXN5bmMgKCkgPT4ge1xuICAgICAgaWYgKGNvbm5lY3RTdGFydGVkKSByZXR1cm47XG4gICAgICBpZiAoIWNvbm5lY3ROb25jZSkgcmV0dXJuO1xuICAgICAgY29ubmVjdFN0YXJ0ZWQgPSB0cnVlO1xuXG4gICAgICB0cnkge1xuICAgICAgICBjb25zdCBpZGVudGl0eSA9IGF3YWl0IGxvYWRPckNyZWF0ZURldmljZUlkZW50aXR5KHRoaXMuaWRlbnRpdHlTdG9yZSk7XG4gICAgICAgIGNvbnN0IHNpZ25lZEF0TXMgPSBEYXRlLm5vdygpO1xuICAgICAgICBjb25zdCBwYXlsb2FkID0gYnVpbGREZXZpY2VBdXRoUGF5bG9hZCh7XG4gICAgICAgICAgZGV2aWNlSWQ6IGlkZW50aXR5LmlkLFxuICAgICAgICAgIGNsaWVudElkOiAnZ2F0ZXdheS1jbGllbnQnLFxuICAgICAgICAgIGNsaWVudE1vZGU6ICdiYWNrZW5kJyxcbiAgICAgICAgICByb2xlOiAnb3BlcmF0b3InLFxuICAgICAgICAgIHNjb3BlczogWydvcGVyYXRvci5yZWFkJywgJ29wZXJhdG9yLndyaXRlJ10sXG4gICAgICAgICAgc2lnbmVkQXRNcyxcbiAgICAgICAgICB0b2tlbjogdGhpcy50b2tlbixcbiAgICAgICAgICBub25jZTogY29ubmVjdE5vbmNlLFxuICAgICAgICB9KTtcbiAgICAgICAgY29uc3Qgc2lnID0gYXdhaXQgc2lnbkRldmljZVBheWxvYWQoaWRlbnRpdHksIHBheWxvYWQpO1xuXG4gICAgICAgIGNvbnN0IGFjayA9IGF3YWl0IHRoaXMuX3NlbmRSZXF1ZXN0KCdjb25uZWN0Jywge1xuICAgICAgICAgICBtaW5Qcm90b2NvbDogMyxcbiAgICAgICAgICAgbWF4UHJvdG9jb2w6IDMsXG4gICAgICAgICAgIGNsaWVudDoge1xuICAgICAgICAgICAgIGlkOiAnZ2F0ZXdheS1jbGllbnQnLFxuICAgICAgICAgICAgIG1vZGU6ICdiYWNrZW5kJyxcbiAgICAgICAgICAgICB2ZXJzaW9uOiAnMC4xLjEwJyxcbiAgICAgICAgICAgICBwbGF0Zm9ybTogJ2VsZWN0cm9uJyxcbiAgICAgICAgICAgfSxcbiAgICAgICAgICAgcm9sZTogJ29wZXJhdG9yJyxcbiAgICAgICAgICAgc2NvcGVzOiBbJ29wZXJhdG9yLnJlYWQnLCAnb3BlcmF0b3Iud3JpdGUnXSxcbiAgICAgICAgICAgZGV2aWNlOiB7XG4gICAgICAgICAgICAgaWQ6IGlkZW50aXR5LmlkLFxuICAgICAgICAgICAgIHB1YmxpY0tleTogaWRlbnRpdHkucHVibGljS2V5LFxuICAgICAgICAgICAgIHNpZ25hdHVyZTogc2lnLnNpZ25hdHVyZSxcbiAgICAgICAgICAgICBzaWduZWRBdDogc2lnbmVkQXRNcyxcbiAgICAgICAgICAgICBub25jZTogY29ubmVjdE5vbmNlLFxuICAgICAgICAgICB9LFxuICAgICAgICAgICBhdXRoOiB7XG4gICAgICAgICAgICAgdG9rZW46IHRoaXMudG9rZW4sXG4gICAgICAgICAgIH0sXG4gICAgICAgICB9KTtcblxuICAgICAgICAgdGhpcy5fc2V0U3RhdGUoJ2Nvbm5lY3RlZCcpO1xuICAgICAgICAgdGhpcy5yZWNvbm5lY3RBdHRlbXB0ID0gMDtcbiAgICAgICAgIGlmIChoYW5kc2hha2VUaW1lcikge1xuICAgICAgICAgICBjbGVhclRpbWVvdXQoaGFuZHNoYWtlVGltZXIpO1xuICAgICAgICAgICBoYW5kc2hha2VUaW1lciA9IG51bGw7XG4gICAgICAgICB9XG4gICAgICAgICB0aGlzLl9zdGFydEhlYXJ0YmVhdCgpO1xuICAgICAgfSBjYXRjaCAoZXJyKSB7XG4gICAgICAgIGNvbnNvbGUuZXJyb3IoJ1tvY2xhdy13c10gQ29ubmVjdCBoYW5kc2hha2UgZmFpbGVkJywgZXJyKTtcbiAgICAgICAgd3MuY2xvc2UoKTtcbiAgICAgIH1cbiAgICB9O1xuXG4gICAgbGV0IGhhbmRzaGFrZVRpbWVyOiBSZXR1cm5UeXBlPHR5cGVvZiBzZXRUaW1lb3V0PiB8IG51bGwgPSBudWxsO1xuXG4gICAgd3Mub25vcGVuID0gKCkgPT4ge1xuICAgICAgdGhpcy5fc2V0U3RhdGUoJ2hhbmRzaGFraW5nJyk7XG4gICAgICAvLyBUaGUgZ2F0ZXdheSB3aWxsIHNlbmQgY29ubmVjdC5jaGFsbGVuZ2U7IGNvbm5lY3QgaXMgc2VudCBvbmNlIHdlIGhhdmUgYSBub25jZS5cbiAgICAgIGlmIChoYW5kc2hha2VUaW1lcikgY2xlYXJUaW1lb3V0KGhhbmRzaGFrZVRpbWVyKTtcbiAgICAgIGhhbmRzaGFrZVRpbWVyID0gc2V0VGltZW91dCgoKSA9PiB7XG4gICAgICAgIC8vIElmIHdlIG5ldmVyIGdvdCB0aGUgY2hhbGxlbmdlIG5vbmNlLCBmb3JjZSByZWNvbm5lY3QuXG4gICAgICAgIGlmICh0aGlzLnN0YXRlID09PSAnaGFuZHNoYWtpbmcnICYmICF0aGlzLmludGVudGlvbmFsQ2xvc2UpIHtcbiAgICAgICAgICBjb25zb2xlLndhcm4oJ1tvY2xhdy13c10gSGFuZHNoYWtlIHRpbWVkIG91dCB3YWl0aW5nIGZvciBjb25uZWN0LmNoYWxsZW5nZScpO1xuICAgICAgICAgIHdzLmNsb3NlKCk7XG4gICAgICAgIH1cbiAgICAgIH0sIEhBTkRTSEFLRV9USU1FT1VUX01TKTtcbiAgICB9O1xuXG4gICAgd3Mub25tZXNzYWdlID0gKGV2ZW50OiBNZXNzYWdlRXZlbnQpID0+IHtcbiAgICAgIC8vIFdlYlNvY2tldCBvbm1lc3NhZ2UgY2Fubm90IGJlIGFzeW5jLCBidXQgd2UgY2FuIHJ1biBhbiBhc3luYyB0YXNrIGluc2lkZS5cbiAgICAgIHZvaWQgKGFzeW5jICgpID0+IHtcbiAgICAgICAgY29uc3Qgbm9ybWFsaXplZCA9IGF3YWl0IG5vcm1hbGl6ZVdzRGF0YVRvVGV4dChldmVudC5kYXRhKTtcbiAgICAgICAgaWYgKCFub3JtYWxpemVkLm9rKSB7XG4gICAgICAgICAgaWYgKG5vcm1hbGl6ZWQucmVhc29uID09PSAndG9vLWxhcmdlJykge1xuICAgICAgICAgICAgY29uc29sZS5lcnJvcignW29jbGF3LXdzXSBJbmJvdW5kIGZyYW1lIHRvbyBsYXJnZTsgY2xvc2luZyBjb25uZWN0aW9uJyk7XG4gICAgICAgICAgICB3cy5jbG9zZSgpO1xuICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBjb25zb2xlLmVycm9yKCdbb2NsYXctd3NdIFVuc3VwcG9ydGVkIGluYm91bmQgZnJhbWUgdHlwZTsgaWdub3JpbmcnKTtcbiAgICAgICAgICB9XG4gICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKG5vcm1hbGl6ZWQuYnl0ZXMgPiBNQVhfSU5CT1VORF9GUkFNRV9CWVRFUykge1xuICAgICAgICAgIGNvbnNvbGUuZXJyb3IoJ1tvY2xhdy13c10gSW5ib3VuZCBmcmFtZSB0b28gbGFyZ2U7IGNsb3NpbmcgY29ubmVjdGlvbicpO1xuICAgICAgICAgIHdzLmNsb3NlKCk7XG4gICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgbGV0IGZyYW1lOiBhbnk7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgZnJhbWUgPSBKU09OLnBhcnNlKG5vcm1hbGl6ZWQudGV4dCk7XG4gICAgICAgIH0gY2F0Y2gge1xuICAgICAgICAgIGNvbnNvbGUuZXJyb3IoJ1tvY2xhdy13c10gRmFpbGVkIHRvIHBhcnNlIGluY29taW5nIG1lc3NhZ2UnKTtcbiAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICAvLyBSZXNwb25zZXNcbiAgICAgICAgaWYgKGZyYW1lLnR5cGUgPT09ICdyZXMnKSB7XG4gICAgICAgICAgdGhpcy5faGFuZGxlUmVzcG9uc2VGcmFtZShmcmFtZSk7XG4gICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgLy8gRXZlbnRzXG4gICAgICAgIGlmIChmcmFtZS50eXBlID09PSAnZXZlbnQnKSB7XG4gICAgICAgICAgaWYgKGZyYW1lLmV2ZW50ID09PSAnY29ubmVjdC5jaGFsbGVuZ2UnKSB7XG4gICAgICAgICAgICBjb25uZWN0Tm9uY2UgPSBmcmFtZS5wYXlsb2FkPy5ub25jZSB8fCBudWxsO1xuICAgICAgICAgICAgLy8gQXR0ZW1wdCBoYW5kc2hha2Ugb25jZSB3ZSBoYXZlIGEgbm9uY2UuXG4gICAgICAgICAgICB2b2lkIHRyeUNvbm5lY3QoKTtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBpZiAoZnJhbWUuZXZlbnQgPT09ICdjaGF0Jykge1xuICAgICAgICAgICAgdGhpcy5faGFuZGxlQ2hhdEV2ZW50RnJhbWUoZnJhbWUpO1xuICAgICAgICAgIH1cbiAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICAvLyBBdm9pZCBsb2dnaW5nIGZ1bGwgZnJhbWVzIChtYXkgaW5jbHVkZSBtZXNzYWdlIGNvbnRlbnQgb3Igb3RoZXIgc2Vuc2l0aXZlIHBheWxvYWRzKS5cbiAgICAgICAgY29uc29sZS5kZWJ1ZygnW29jbGF3LXdzXSBVbmhhbmRsZWQgZnJhbWUnLCB7IHR5cGU6IGZyYW1lPy50eXBlLCBldmVudDogZnJhbWU/LmV2ZW50LCBpZDogZnJhbWU/LmlkIH0pO1xuICAgICAgfSkoKTtcbiAgICB9O1xuXG4gICAgY29uc3QgY2xlYXJIYW5kc2hha2VUaW1lciA9ICgpID0+IHtcbiAgICAgIGlmIChoYW5kc2hha2VUaW1lcikge1xuICAgICAgICBjbGVhclRpbWVvdXQoaGFuZHNoYWtlVGltZXIpO1xuICAgICAgICBoYW5kc2hha2VUaW1lciA9IG51bGw7XG4gICAgICB9XG4gICAgfTtcblxuICAgIHdzLm9uY2xvc2UgPSAoKSA9PiB7XG4gICAgICBjbGVhckhhbmRzaGFrZVRpbWVyKCk7XG4gICAgICB0aGlzLl9zdG9wVGltZXJzKCk7XG4gICAgICB0aGlzLmFjdGl2ZVJ1bklkID0gbnVsbDtcbiAgICAgIHRoaXMuYWJvcnRJbkZsaWdodCA9IG51bGw7XG4gICAgICB0aGlzLl9zZXRXb3JraW5nKGZhbHNlKTtcbiAgICAgIHRoaXMuX3NldFN0YXRlKCdkaXNjb25uZWN0ZWQnKTtcblxuICAgICAgZm9yIChjb25zdCBwZW5kaW5nIG9mIHRoaXMucGVuZGluZ1JlcXVlc3RzLnZhbHVlcygpKSB7XG4gICAgICAgIGlmIChwZW5kaW5nLnRpbWVvdXQpIGNsZWFyVGltZW91dChwZW5kaW5nLnRpbWVvdXQpO1xuICAgICAgICBwZW5kaW5nLnJlamVjdChuZXcgRXJyb3IoJ0Nvbm5lY3Rpb24gY2xvc2VkJykpO1xuICAgICAgfVxuICAgICAgdGhpcy5wZW5kaW5nUmVxdWVzdHMuY2xlYXIoKTtcblxuICAgICAgaWYgKCF0aGlzLmludGVudGlvbmFsQ2xvc2UpIHtcbiAgICAgICAgdGhpcy5fc2NoZWR1bGVSZWNvbm5lY3QoKTtcbiAgICAgIH1cbiAgICB9O1xuXG4gICAgd3Mub25lcnJvciA9IChldjogRXZlbnQpID0+IHtcbiAgICAgIGNsZWFySGFuZHNoYWtlVGltZXIoKTtcbiAgICAgIGNvbnNvbGUuZXJyb3IoJ1tvY2xhdy13c10gV2ViU29ja2V0IGVycm9yJywgZXYpO1xuICAgIH07XG4gIH1cblxuICBwcml2YXRlIF9oYW5kbGVSZXNwb25zZUZyYW1lKGZyYW1lOiBhbnkpOiB2b2lkIHtcbiAgICBjb25zdCBwZW5kaW5nID0gdGhpcy5wZW5kaW5nUmVxdWVzdHMuZ2V0KGZyYW1lLmlkKTtcbiAgICBpZiAoIXBlbmRpbmcpIHJldHVybjtcblxuICAgIHRoaXMucGVuZGluZ1JlcXVlc3RzLmRlbGV0ZShmcmFtZS5pZCk7XG4gICAgaWYgKHBlbmRpbmcudGltZW91dCkgY2xlYXJUaW1lb3V0KHBlbmRpbmcudGltZW91dCk7XG5cbiAgICBpZiAoZnJhbWUub2spIHBlbmRpbmcucmVzb2x2ZShmcmFtZS5wYXlsb2FkKTtcbiAgICBlbHNlIHBlbmRpbmcucmVqZWN0KG5ldyBFcnJvcihmcmFtZS5lcnJvcj8ubWVzc2FnZSB8fCAnUmVxdWVzdCBmYWlsZWQnKSk7XG4gIH1cblxuICBwcml2YXRlIF9oYW5kbGVDaGF0RXZlbnRGcmFtZShmcmFtZTogYW55KTogdm9pZCB7XG4gICAgY29uc3QgcGF5bG9hZCA9IGZyYW1lLnBheWxvYWQ7XG4gICAgY29uc3QgaW5jb21pbmdTZXNzaW9uS2V5ID0gU3RyaW5nKHBheWxvYWQ/LnNlc3Npb25LZXkgfHwgJycpO1xuICAgIGlmICghaW5jb21pbmdTZXNzaW9uS2V5IHx8ICFzZXNzaW9uS2V5TWF0Y2hlcyh0aGlzLnNlc3Npb25LZXksIGluY29taW5nU2Vzc2lvbktleSkpIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICAvLyBCZXN0LWVmZm9ydCBydW4gY29ycmVsYXRpb24gKGlmIGdhdGV3YXkgaW5jbHVkZXMgYSBydW4gaWQpLiBUaGlzIGF2b2lkcyBjbGVhcmluZyBvdXIgVUlcbiAgICAvLyBiYXNlZCBvbiBhIGRpZmZlcmVudCBjbGllbnQncyBydW4gaW4gdGhlIHNhbWUgc2Vzc2lvbi5cbiAgICBjb25zdCBpbmNvbWluZ1J1bklkID0gU3RyaW5nKHBheWxvYWQ/LnJ1bklkIHx8IHBheWxvYWQ/LmlkZW1wb3RlbmN5S2V5IHx8IHBheWxvYWQ/Lm1ldGE/LnJ1bklkIHx8ICcnKTtcbiAgICBpZiAodGhpcy5hY3RpdmVSdW5JZCAmJiBpbmNvbWluZ1J1bklkICYmIGluY29taW5nUnVuSWQgIT09IHRoaXMuYWN0aXZlUnVuSWQpIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICAvLyBBdm9pZCBkb3VibGUtcmVuZGVyOiBnYXRld2F5IGVtaXRzIGRlbHRhICsgZmluYWwgKyBhYm9ydGVkLiBSZW5kZXIgb25seSBleHBsaWNpdCBmaW5hbC9hYm9ydGVkLlxuICAgIC8vIElmIHN0YXRlIGlzIG1pc3NpbmcsIHRyZWF0IGFzIG5vbi10ZXJtaW5hbCAoZG8gbm90IGNsZWFyIFVJIC8gZG8gbm90IHJlbmRlcikuXG4gICAgaWYgKCFwYXlsb2FkPy5zdGF0ZSkge1xuICAgICAgcmV0dXJuO1xuICAgIH1cbiAgICBpZiAocGF5bG9hZC5zdGF0ZSAhPT0gJ2ZpbmFsJyAmJiBwYXlsb2FkLnN0YXRlICE9PSAnYWJvcnRlZCcpIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICAvLyBXZSBvbmx5IGFwcGVuZCBhc3Npc3RhbnQgb3V0cHV0IHRvIFVJLlxuICAgIGNvbnN0IG1zZyA9IHBheWxvYWQ/Lm1lc3NhZ2U7XG4gICAgY29uc3Qgcm9sZSA9IG1zZz8ucm9sZSA/PyAnYXNzaXN0YW50JztcblxuICAgIC8vIEFib3J0ZWQgZW5kcyB0aGUgcnVuIHJlZ2FyZGxlc3Mgb2Ygcm9sZS9tZXNzYWdlLlxuICAgIGlmIChwYXlsb2FkLnN0YXRlID09PSAnYWJvcnRlZCcpIHtcbiAgICAgIHRoaXMuYWN0aXZlUnVuSWQgPSBudWxsO1xuICAgICAgdGhpcy5fc2V0V29ya2luZyhmYWxzZSk7XG4gICAgICAvLyBBYm9ydGVkIG1heSBoYXZlIG5vIGFzc2lzdGFudCBtZXNzYWdlOyBpZiBub25lLCBzdG9wIGhlcmUuXG4gICAgICBpZiAoIW1zZykgcmV0dXJuO1xuICAgICAgLy8gSWYgdGhlcmUgaXMgYSBtZXNzYWdlLCBvbmx5IGFwcGVuZCBhc3Npc3RhbnQgb3V0cHV0LlxuICAgICAgaWYgKHJvbGUgIT09ICdhc3Npc3RhbnQnKSByZXR1cm47XG4gICAgfVxuXG4gICAgLy8gRmluYWwgc2hvdWxkIG9ubHkgY29tcGxldGUgdGhlIHJ1biB3aGVuIHRoZSBhc3Npc3RhbnQgY29tcGxldGVzLlxuICAgIGlmIChwYXlsb2FkLnN0YXRlID09PSAnZmluYWwnKSB7XG4gICAgICBpZiAocm9sZSAhPT0gJ2Fzc2lzdGFudCcpIHJldHVybjtcbiAgICAgIHRoaXMuYWN0aXZlUnVuSWQgPSBudWxsO1xuICAgICAgdGhpcy5fc2V0V29ya2luZyhmYWxzZSk7XG4gICAgfVxuXG4gICAgY29uc3QgdGV4dCA9IGV4dHJhY3RUZXh0RnJvbUdhdGV3YXlNZXNzYWdlKG1zZyk7XG4gICAgaWYgKCF0ZXh0KSByZXR1cm47XG5cbiAgICAvLyBPcHRpb25hbDogaGlkZSBoZWFydGJlYXQgYWNrcyAobm9pc2UgaW4gVUkpXG4gICAgaWYgKHRleHQudHJpbSgpID09PSAnSEVBUlRCRUFUX09LJykge1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIHRoaXMub25NZXNzYWdlPy4oe1xuICAgICAgdHlwZTogJ21lc3NhZ2UnLFxuICAgICAgcGF5bG9hZDoge1xuICAgICAgICBjb250ZW50OiB0ZXh0LFxuICAgICAgICByb2xlOiAnYXNzaXN0YW50JyxcbiAgICAgICAgdGltZXN0YW1wOiBEYXRlLm5vdygpLFxuICAgICAgfSxcbiAgICB9KTtcbiAgfVxuXG4gIHByaXZhdGUgX3NlbmRSZXF1ZXN0KG1ldGhvZDogc3RyaW5nLCBwYXJhbXM6IGFueSk6IFByb21pc2U8YW55PiB7XG4gICAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIGlmICghdGhpcy53cyB8fCB0aGlzLndzLnJlYWR5U3RhdGUgIT09IFdlYlNvY2tldC5PUEVOKSB7XG4gICAgICAgIHJlamVjdChuZXcgRXJyb3IoJ1dlYlNvY2tldCBub3QgY29ubmVjdGVkJykpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG5cbiAgICAgIGlmICh0aGlzLnBlbmRpbmdSZXF1ZXN0cy5zaXplID49IE1BWF9QRU5ESU5HX1JFUVVFU1RTKSB7XG4gICAgICAgIHJlamVjdChuZXcgRXJyb3IoYFRvbyBtYW55IGluLWZsaWdodCByZXF1ZXN0cyAoJHt0aGlzLnBlbmRpbmdSZXF1ZXN0cy5zaXplfSlgKSk7XG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cblxuICAgICAgY29uc3QgaWQgPSBgcmVxLSR7Kyt0aGlzLnJlcXVlc3RJZH1gO1xuXG4gICAgICBjb25zdCBwZW5kaW5nOiBQZW5kaW5nUmVxdWVzdCA9IHsgcmVzb2x2ZSwgcmVqZWN0LCB0aW1lb3V0OiBudWxsIH07XG4gICAgICB0aGlzLnBlbmRpbmdSZXF1ZXN0cy5zZXQoaWQsIHBlbmRpbmcpO1xuXG4gICAgICBjb25zdCBwYXlsb2FkID0gSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0eXBlOiAncmVxJyxcbiAgICAgICAgbWV0aG9kLFxuICAgICAgICBpZCxcbiAgICAgICAgcGFyYW1zLFxuICAgICAgfSk7XG5cbiAgICAgIHRyeSB7XG4gICAgICAgIHRoaXMud3Muc2VuZChwYXlsb2FkKTtcbiAgICAgIH0gY2F0Y2ggKGVycikge1xuICAgICAgICB0aGlzLnBlbmRpbmdSZXF1ZXN0cy5kZWxldGUoaWQpO1xuICAgICAgICByZWplY3QoZXJyKTtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuXG4gICAgICBwZW5kaW5nLnRpbWVvdXQgPSBzZXRUaW1lb3V0KCgpID0+IHtcbiAgICAgICAgaWYgKHRoaXMucGVuZGluZ1JlcXVlc3RzLmhhcyhpZCkpIHtcbiAgICAgICAgICB0aGlzLnBlbmRpbmdSZXF1ZXN0cy5kZWxldGUoaWQpO1xuICAgICAgICAgIHJlamVjdChuZXcgRXJyb3IoYFJlcXVlc3QgdGltZW91dDogJHttZXRob2R9YCkpO1xuICAgICAgICB9XG4gICAgICB9LCAzMF8wMDApO1xuICAgIH0pO1xuICB9XG5cbiAgcHJpdmF0ZSBfc2NoZWR1bGVSZWNvbm5lY3QoKTogdm9pZCB7XG4gICAgaWYgKHRoaXMucmVjb25uZWN0VGltZXIgIT09IG51bGwpIHJldHVybjtcblxuICAgIGNvbnN0IGF0dGVtcHQgPSArK3RoaXMucmVjb25uZWN0QXR0ZW1wdDtcbiAgICBjb25zdCBleHAgPSBNYXRoLm1pbihSRUNPTk5FQ1RfTUFYX01TLCBSRUNPTk5FQ1RfQkFTRV9NUyAqIE1hdGgucG93KDIsIGF0dGVtcHQgLSAxKSk7XG4gICAgLy8gSml0dGVyOiAwLjV4Li4xLjV4XG4gICAgY29uc3Qgaml0dGVyID0gMC41ICsgTWF0aC5yYW5kb20oKTtcbiAgICBjb25zdCBkZWxheSA9IE1hdGguZmxvb3IoZXhwICogaml0dGVyKTtcblxuICAgIHRoaXMucmVjb25uZWN0VGltZXIgPSBzZXRUaW1lb3V0KCgpID0+IHtcbiAgICAgIHRoaXMucmVjb25uZWN0VGltZXIgPSBudWxsO1xuICAgICAgaWYgKCF0aGlzLmludGVudGlvbmFsQ2xvc2UpIHtcbiAgICAgICAgY29uc29sZS5sb2coYFtvY2xhdy13c10gUmVjb25uZWN0aW5nIHRvICR7dGhpcy51cmx9XHUyMDI2IChhdHRlbXB0ICR7YXR0ZW1wdH0sICR7ZGVsYXl9bXMpYCk7XG4gICAgICAgIHRoaXMuX2Nvbm5lY3QoKTtcbiAgICAgIH1cbiAgICB9LCBkZWxheSk7XG4gIH1cblxuICBwcml2YXRlIGxhc3RCdWZmZXJlZFdhcm5BdE1zID0gMDtcblxuICBwcml2YXRlIF9zdGFydEhlYXJ0YmVhdCgpOiB2b2lkIHtcbiAgICB0aGlzLl9zdG9wSGVhcnRiZWF0KCk7XG4gICAgdGhpcy5oZWFydGJlYXRUaW1lciA9IHNldEludGVydmFsKCgpID0+IHtcbiAgICAgIGlmICh0aGlzLndzPy5yZWFkeVN0YXRlICE9PSBXZWJTb2NrZXQuT1BFTikgcmV0dXJuO1xuICAgICAgaWYgKHRoaXMud3MuYnVmZmVyZWRBbW91bnQgPiAwKSB7XG4gICAgICAgIGNvbnN0IG5vdyA9IERhdGUubm93KCk7XG4gICAgICAgIC8vIFRocm90dGxlIHRvIGF2b2lkIGxvZyBzcGFtIGluIGxvbmctcnVubmluZyBzZXNzaW9ucy5cbiAgICAgICAgaWYgKG5vdyAtIHRoaXMubGFzdEJ1ZmZlcmVkV2FybkF0TXMgPiA1ICogNjBfMDAwKSB7XG4gICAgICAgICAgdGhpcy5sYXN0QnVmZmVyZWRXYXJuQXRNcyA9IG5vdztcbiAgICAgICAgICBjb25zb2xlLndhcm4oJ1tvY2xhdy13c10gU2VuZCBidWZmZXIgbm90IGVtcHR5IFx1MjAxNCBjb25uZWN0aW9uIG1heSBiZSBzdGFsbGVkJyk7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9LCBIRUFSVEJFQVRfSU5URVJWQUxfTVMpO1xuICB9XG5cbiAgcHJpdmF0ZSBfc3RvcEhlYXJ0YmVhdCgpOiB2b2lkIHtcbiAgICBpZiAodGhpcy5oZWFydGJlYXRUaW1lcikge1xuICAgICAgY2xlYXJJbnRlcnZhbCh0aGlzLmhlYXJ0YmVhdFRpbWVyKTtcbiAgICAgIHRoaXMuaGVhcnRiZWF0VGltZXIgPSBudWxsO1xuICAgIH1cbiAgfVxuXG4gIHByaXZhdGUgX3N0b3BUaW1lcnMoKTogdm9pZCB7XG4gICAgdGhpcy5fc3RvcEhlYXJ0YmVhdCgpO1xuICAgIHRoaXMuX2Rpc2FybVdvcmtpbmdTYWZldHlUaW1lb3V0KCk7XG4gICAgaWYgKHRoaXMucmVjb25uZWN0VGltZXIpIHtcbiAgICAgIGNsZWFyVGltZW91dCh0aGlzLnJlY29ubmVjdFRpbWVyKTtcbiAgICAgIHRoaXMucmVjb25uZWN0VGltZXIgPSBudWxsO1xuICAgIH1cbiAgfVxuXG4gIHByaXZhdGUgX3NldFN0YXRlKHN0YXRlOiBXU0NsaWVudFN0YXRlKTogdm9pZCB7XG4gICAgaWYgKHRoaXMuc3RhdGUgPT09IHN0YXRlKSByZXR1cm47XG4gICAgdGhpcy5zdGF0ZSA9IHN0YXRlO1xuICAgIHRoaXMub25TdGF0ZUNoYW5nZT8uKHN0YXRlKTtcbiAgfVxuXG4gIHByaXZhdGUgX3NldFdvcmtpbmcod29ya2luZzogYm9vbGVhbik6IHZvaWQge1xuICAgIGlmICh0aGlzLndvcmtpbmcgPT09IHdvcmtpbmcpIHJldHVybjtcbiAgICB0aGlzLndvcmtpbmcgPSB3b3JraW5nO1xuICAgIHRoaXMub25Xb3JraW5nQ2hhbmdlPy4od29ya2luZyk7XG5cbiAgICBpZiAoIXdvcmtpbmcpIHtcbiAgICAgIHRoaXMuX2Rpc2FybVdvcmtpbmdTYWZldHlUaW1lb3V0KCk7XG4gICAgfVxuICB9XG5cbiAgcHJpdmF0ZSBfYXJtV29ya2luZ1NhZmV0eVRpbWVvdXQoKTogdm9pZCB7XG4gICAgdGhpcy5fZGlzYXJtV29ya2luZ1NhZmV0eVRpbWVvdXQoKTtcbiAgICB0aGlzLndvcmtpbmdUaW1lciA9IHNldFRpbWVvdXQoKCkgPT4ge1xuICAgICAgLy8gSWYgdGhlIGdhdGV3YXkgbmV2ZXIgZW1pdHMgYW4gYXNzaXN0YW50IGZpbmFsIHJlc3BvbnNlLCBkb25cdTIwMTl0IGxlYXZlIFVJIHN0dWNrLlxuICAgICAgdGhpcy5fc2V0V29ya2luZyhmYWxzZSk7XG4gICAgfSwgV09SS0lOR19NQVhfTVMpO1xuICB9XG5cbiAgcHJpdmF0ZSBfZGlzYXJtV29ya2luZ1NhZmV0eVRpbWVvdXQoKTogdm9pZCB7XG4gICAgaWYgKHRoaXMud29ya2luZ1RpbWVyKSB7XG4gICAgICBjbGVhclRpbWVvdXQodGhpcy53b3JraW5nVGltZXIpO1xuICAgICAgdGhpcy53b3JraW5nVGltZXIgPSBudWxsO1xuICAgIH1cbiAgfVxufVxuIiwgImltcG9ydCB7IEl0ZW1WaWV3LCBNYXJrZG93blJlbmRlcmVyLCBNb2RhbCwgTm90aWNlLCBTZXR0aW5nLCBURmlsZSwgV29ya3NwYWNlTGVhZiB9IGZyb20gJ29ic2lkaWFuJztcbmltcG9ydCB0eXBlIE9wZW5DbGF3UGx1Z2luIGZyb20gJy4vbWFpbic7XG5pbXBvcnQgeyBDaGF0TWFuYWdlciB9IGZyb20gJy4vY2hhdCc7XG5pbXBvcnQgdHlwZSB7IENoYXRNZXNzYWdlLCBQYXRoTWFwcGluZyB9IGZyb20gJy4vdHlwZXMnO1xuaW1wb3J0IHsgZXh0cmFjdENhbmRpZGF0ZXMsIHRyeU1hcFJlbW90ZVBhdGhUb1ZhdWx0UGF0aCB9IGZyb20gJy4vbGlua2lmeSc7XG5pbXBvcnQgeyBnZXRBY3RpdmVOb3RlQ29udGV4dCB9IGZyb20gJy4vY29udGV4dCc7XG5pbXBvcnQgeyBPYnNpZGlhbldTQ2xpZW50IH0gZnJvbSAnLi93ZWJzb2NrZXQnO1xuXG5leHBvcnQgY29uc3QgVklFV19UWVBFX09QRU5DTEFXX0NIQVQgPSAnb3BlbmNsYXctY2hhdCc7XG5cbmNsYXNzIE5ld1Nlc3Npb25Nb2RhbCBleHRlbmRzIE1vZGFsIHtcbiAgcHJpdmF0ZSBpbml0aWFsVmFsdWU6IHN0cmluZztcbiAgcHJpdmF0ZSBvblN1Ym1pdDogKHZhbHVlOiBzdHJpbmcpID0+IHZvaWQ7XG5cbiAgY29uc3RydWN0b3IodmlldzogT3BlbkNsYXdDaGF0VmlldywgaW5pdGlhbFZhbHVlOiBzdHJpbmcsIG9uU3VibWl0OiAodmFsdWU6IHN0cmluZykgPT4gdm9pZCkge1xuICAgIHN1cGVyKHZpZXcuYXBwKTtcbiAgICB0aGlzLmluaXRpYWxWYWx1ZSA9IGluaXRpYWxWYWx1ZTtcbiAgICB0aGlzLm9uU3VibWl0ID0gb25TdWJtaXQ7XG4gIH1cblxuICBvbk9wZW4oKTogdm9pZCB7XG4gICAgY29uc3QgeyBjb250ZW50RWwgfSA9IHRoaXM7XG4gICAgY29udGVudEVsLmVtcHR5KCk7XG5cbiAgICBjb250ZW50RWwuY3JlYXRlRWwoJ2gzJywgeyB0ZXh0OiAnTmV3IHNlc3Npb24ga2V5JyB9KTtcblxuICAgIGxldCB2YWx1ZSA9IHRoaXMuaW5pdGlhbFZhbHVlO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGVudEVsKVxuICAgICAgLnNldE5hbWUoJ1Nlc3Npb24ga2V5JylcbiAgICAgIC5zZXREZXNjKCdUaXA6IGNob29zZSBhIHNob3J0IHN1ZmZpeDsgaXQgd2lsbCBiZWNvbWUgYWdlbnQ6bWFpbjpvYnNpZGlhbjpkaXJlY3Q6PHZhdWx0SGFzaD4tPHN1ZmZpeD4uJylcbiAgICAgIC5hZGRUZXh0KCh0KSA9PiB7XG4gICAgICAgIHQuc2V0VmFsdWUodmFsdWUpO1xuICAgICAgICB0Lm9uQ2hhbmdlKCh2KSA9PiB7XG4gICAgICAgICAgdmFsdWUgPSB2O1xuICAgICAgICB9KTtcbiAgICAgIH0pO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGVudEVsKVxuICAgICAgLmFkZEJ1dHRvbigoYikgPT4ge1xuICAgICAgICBiLnNldEJ1dHRvblRleHQoJ0NhbmNlbCcpO1xuICAgICAgICBiLm9uQ2xpY2soKCkgPT4gdGhpcy5jbG9zZSgpKTtcbiAgICAgIH0pXG4gICAgICAuYWRkQnV0dG9uKChiKSA9PiB7XG4gICAgICAgIGIuc2V0Q3RhKCk7XG4gICAgICAgIGIuc2V0QnV0dG9uVGV4dCgnQ3JlYXRlJyk7XG4gICAgICAgIGIub25DbGljaygoKSA9PiB7XG4gICAgICAgICAgY29uc3QgdiA9IHZhbHVlLnRyaW0oKS50b0xvd2VyQ2FzZSgpO1xuICAgICAgICAgIGlmICghdikge1xuICAgICAgICAgICAgbmV3IE5vdGljZSgnU3VmZml4IGNhbm5vdCBiZSBlbXB0eScpO1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgIH1cbiAgICAgICAgICBpZiAoIS9eW2EtejAtOV1bYS16MC05Xy1dezAsNjN9JC8udGVzdCh2KSkge1xuICAgICAgICAgICAgbmV3IE5vdGljZSgnVXNlIGxldHRlcnMvbnVtYmVycy9fLy0gb25seSAobWF4IDY0IGNoYXJzKScpO1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgIH1cbiAgICAgICAgICB0aGlzLm9uU3VibWl0KHYpO1xuICAgICAgICAgIHRoaXMuY2xvc2UoKTtcbiAgICAgICAgfSk7XG4gICAgICB9KTtcbiAgfVxufVxuXG5leHBvcnQgY2xhc3MgT3BlbkNsYXdDaGF0VmlldyBleHRlbmRzIEl0ZW1WaWV3IHtcbiAgcHJpdmF0ZSBwbHVnaW46IE9wZW5DbGF3UGx1Z2luO1xuICBwcml2YXRlIGNoYXRNYW5hZ2VyOiBDaGF0TWFuYWdlcjtcbiAgcHJpdmF0ZSB3c0NsaWVudDogT2JzaWRpYW5XU0NsaWVudDtcblxuICAvLyBTdGF0ZVxuICBwcml2YXRlIGlzQ29ubmVjdGVkID0gZmFsc2U7XG4gIHByaXZhdGUgaXNXb3JraW5nID0gZmFsc2U7XG5cbiAgLy8gQ29ubmVjdGlvbiBub3RpY2VzIChhdm9pZCBzcGFtKVxuICBwcml2YXRlIGxhc3RDb25uTm90aWNlQXRNcyA9IDA7XG4gIHByaXZhdGUgbGFzdEdhdGV3YXlTdGF0ZTogc3RyaW5nIHwgbnVsbCA9IG51bGw7XG5cbiAgLy8gRE9NIHJlZnNcbiAgcHJpdmF0ZSBtZXNzYWdlc0VsITogSFRNTEVsZW1lbnQ7XG4gIHByaXZhdGUgaW5wdXRFbCE6IEhUTUxUZXh0QXJlYUVsZW1lbnQ7XG4gIHByaXZhdGUgc2VuZEJ0biE6IEhUTUxCdXR0b25FbGVtZW50O1xuICBwcml2YXRlIGluY2x1ZGVOb3RlQ2hlY2tib3ghOiBIVE1MSW5wdXRFbGVtZW50O1xuICBwcml2YXRlIHN0YXR1c0RvdCE6IEhUTUxFbGVtZW50O1xuXG4gIHByaXZhdGUgc2Vzc2lvblNlbGVjdCE6IEhUTUxTZWxlY3RFbGVtZW50O1xuICBwcml2YXRlIHNlc3Npb25SZWZyZXNoQnRuITogSFRNTEJ1dHRvbkVsZW1lbnQ7XG4gIHByaXZhdGUgc2Vzc2lvbk5ld0J0biE6IEhUTUxCdXR0b25FbGVtZW50O1xuICBwcml2YXRlIHNlc3Npb25NYWluQnRuITogSFRNTEJ1dHRvbkVsZW1lbnQ7XG4gIHByaXZhdGUgc3VwcHJlc3NTZXNzaW9uU2VsZWN0Q2hhbmdlID0gZmFsc2U7XG5cbiAgcHJpdmF0ZSBvbk1lc3NhZ2VzQ2xpY2s6ICgoZXY6IE1vdXNlRXZlbnQpID0+IHZvaWQpIHwgbnVsbCA9IG51bGw7XG4gIHByaXZhdGUgb25Eb2NDbGlja0NhcHR1cmU6ICgoZXY6IE1vdXNlRXZlbnQpID0+IHZvaWQpIHwgbnVsbCA9IG51bGw7XG5cbiAgY29uc3RydWN0b3IobGVhZjogV29ya3NwYWNlTGVhZiwgcGx1Z2luOiBPcGVuQ2xhd1BsdWdpbikge1xuICAgIHN1cGVyKGxlYWYpO1xuICAgIHRoaXMucGx1Z2luID0gcGx1Z2luO1xuICAgIHRoaXMuY2hhdE1hbmFnZXIgPSBuZXcgQ2hhdE1hbmFnZXIoKTtcbiAgICB0aGlzLndzQ2xpZW50ID0gdGhpcy5wbHVnaW4uY3JlYXRlV3NDbGllbnQodGhpcy5wbHVnaW4uZ2V0RGVmYXVsdFNlc3Npb25LZXkoKSk7XG5cbiAgICAvLyBXaXJlIGluY29taW5nIFdTIG1lc3NhZ2VzIFx1MjE5MiBDaGF0TWFuYWdlciAocGVyLWxlYWYpXG4gICAgdGhpcy53c0NsaWVudC5vbk1lc3NhZ2UgPSAobXNnKSA9PiB7XG4gICAgICBpZiAobXNnLnR5cGUgPT09ICdtZXNzYWdlJykge1xuICAgICAgICB0aGlzLmNoYXRNYW5hZ2VyLmFkZE1lc3NhZ2UoQ2hhdE1hbmFnZXIuY3JlYXRlQXNzaXN0YW50TWVzc2FnZShtc2cucGF5bG9hZC5jb250ZW50KSk7XG4gICAgICB9IGVsc2UgaWYgKG1zZy50eXBlID09PSAnZXJyb3InKSB7XG4gICAgICAgIGNvbnN0IGVyclRleHQgPSBtc2cucGF5bG9hZC5tZXNzYWdlID8/ICdVbmtub3duIGVycm9yIGZyb20gZ2F0ZXdheSc7XG4gICAgICAgIHRoaXMuY2hhdE1hbmFnZXIuYWRkTWVzc2FnZShDaGF0TWFuYWdlci5jcmVhdGVTeXN0ZW1NZXNzYWdlKGBcdTI2QTAgJHtlcnJUZXh0fWAsICdlcnJvcicpKTtcbiAgICAgIH1cbiAgICB9O1xuICB9XG5cbiAgZ2V0Vmlld1R5cGUoKTogc3RyaW5nIHtcbiAgICByZXR1cm4gVklFV19UWVBFX09QRU5DTEFXX0NIQVQ7XG4gIH1cblxuICBnZXREaXNwbGF5VGV4dCgpOiBzdHJpbmcge1xuICAgIHJldHVybiAnT3BlbkNsYXcgQ2hhdCc7XG4gIH1cblxuICBnZXRJY29uKCk6IHN0cmluZyB7XG4gICAgcmV0dXJuICdtZXNzYWdlLXNxdWFyZSc7XG4gIH1cblxuICBhc3luYyBvbk9wZW4oKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgdGhpcy5wbHVnaW4ucmVnaXN0ZXJDaGF0TGVhZigpO1xuICAgIHRoaXMuX2J1aWxkVUkoKTtcblxuICAgIC8vIEZ1bGwgcmUtcmVuZGVyIG9uIGNsZWFyIC8gcmVsb2FkXG4gICAgdGhpcy5jaGF0TWFuYWdlci5vblVwZGF0ZSA9IChtc2dzKSA9PiB0aGlzLl9yZW5kZXJNZXNzYWdlcyhtc2dzKTtcbiAgICAvLyBPKDEpIGFwcGVuZCBmb3IgbmV3IG1lc3NhZ2VzXG4gICAgdGhpcy5jaGF0TWFuYWdlci5vbk1lc3NhZ2VBZGRlZCA9IChtc2cpID0+IHRoaXMuX2FwcGVuZE1lc3NhZ2UobXNnKTtcblxuICAgIC8vIENvbm5lY3QgdGhpcyBsZWFmJ3MgV1MgY2xpZW50XG4gICAgY29uc3QgZ3cgPSB0aGlzLnBsdWdpbi5nZXRHYXRld2F5Q29uZmlnKCk7XG4gICAgaWYgKGd3LnRva2VuKSB7XG4gICAgICB0aGlzLndzQ2xpZW50LmNvbm5lY3QoZ3cudXJsLCBndy50b2tlbiwgeyBhbGxvd0luc2VjdXJlV3M6IGd3LmFsbG93SW5zZWN1cmVXcyB9KTtcbiAgICB9IGVsc2Uge1xuICAgICAgbmV3IE5vdGljZSgnT3BlbkNsYXcgQ2hhdDogcGxlYXNlIGNvbmZpZ3VyZSB5b3VyIGdhdGV3YXkgdG9rZW4gaW4gU2V0dGluZ3MuJyk7XG4gICAgfVxuXG4gICAgLy8gU3Vic2NyaWJlIHRvIFdTIHN0YXRlIGNoYW5nZXNcbiAgICB0aGlzLndzQ2xpZW50Lm9uU3RhdGVDaGFuZ2UgPSAoc3RhdGUpID0+IHsgXG4gICAgICAvLyBDb25uZWN0aW9uIGxvc3MgLyByZWNvbm5lY3Qgbm90aWNlcyAodGhyb3R0bGVkKVxuICAgICAgY29uc3QgcHJldiA9IHRoaXMubGFzdEdhdGV3YXlTdGF0ZTtcbiAgICAgIHRoaXMubGFzdEdhdGV3YXlTdGF0ZSA9IHN0YXRlO1xuXG4gICAgICBjb25zdCBub3cgPSBEYXRlLm5vdygpO1xuICAgICAgY29uc3QgTk9USUNFX1RIUk9UVExFX01TID0gNjBfMDAwO1xuXG4gICAgICBjb25zdCBzaG91bGROb3RpZnkgPSAoKSA9PiBub3cgLSB0aGlzLmxhc3RDb25uTm90aWNlQXRNcyA+IE5PVElDRV9USFJPVFRMRV9NUztcbiAgICAgIGNvbnN0IG5vdGlmeSA9ICh0ZXh0OiBzdHJpbmcpID0+IHtcbiAgICAgICAgaWYgKCFzaG91bGROb3RpZnkoKSkgcmV0dXJuO1xuICAgICAgICB0aGlzLmxhc3RDb25uTm90aWNlQXRNcyA9IG5vdztcbiAgICAgICAgbmV3IE5vdGljZSh0ZXh0KTtcbiAgICAgIH07XG5cbiAgICAgIC8vIE9ubHkgc2hvdyBcdTIwMUNsb3N0XHUyMDFEIGlmIHdlIHdlcmUgcHJldmlvdXNseSBjb25uZWN0ZWQuXG4gICAgICBpZiAocHJldiA9PT0gJ2Nvbm5lY3RlZCcgJiYgc3RhdGUgPT09ICdkaXNjb25uZWN0ZWQnKSB7XG4gICAgICAgIG5vdGlmeSgnT3BlbkNsYXcgQ2hhdDogY29ubmVjdGlvbiBsb3N0IFx1MjAxNCByZWNvbm5lY3RpbmdcdTIwMjYnKTtcbiAgICAgICAgLy8gQWxzbyBhcHBlbmQgYSBzeXN0ZW0gbWVzc2FnZSBzbyBpdFx1MjAxOXMgdmlzaWJsZSBpbiB0aGUgY2hhdCBoaXN0b3J5LlxuICAgICAgICB0aGlzLmNoYXRNYW5hZ2VyLmFkZE1lc3NhZ2UoQ2hhdE1hbmFnZXIuY3JlYXRlU3lzdGVtTWVzc2FnZSgnXHUyNkEwIENvbm5lY3Rpb24gbG9zdCBcdTIwMTQgcmVjb25uZWN0aW5nXHUyMDI2JywgJ2Vycm9yJykpO1xuICAgICAgfVxuXG4gICAgICAvLyBPcHRpb25hbCBcdTIwMUNyZWNvbm5lY3RlZFx1MjAxRCBub3RpY2VcbiAgICAgIGlmIChwcmV2ICYmIHByZXYgIT09ICdjb25uZWN0ZWQnICYmIHN0YXRlID09PSAnY29ubmVjdGVkJykge1xuICAgICAgICBub3RpZnkoJ09wZW5DbGF3IENoYXQ6IHJlY29ubmVjdGVkJyk7XG4gICAgICAgIHRoaXMuY2hhdE1hbmFnZXIuYWRkTWVzc2FnZShDaGF0TWFuYWdlci5jcmVhdGVTeXN0ZW1NZXNzYWdlKCdcdTI3MDUgUmVjb25uZWN0ZWQnLCAnaW5mbycpKTtcbiAgICAgIH1cblxuICAgICAgdGhpcy5pc0Nvbm5lY3RlZCA9IHN0YXRlID09PSAnY29ubmVjdGVkJztcbiAgICAgIHRoaXMuc3RhdHVzRG90LnRvZ2dsZUNsYXNzKCdjb25uZWN0ZWQnLCB0aGlzLmlzQ29ubmVjdGVkKTtcbiAgICAgIHRoaXMuc3RhdHVzRG90LnRpdGxlID0gYEdhdGV3YXk6ICR7c3RhdGV9YDtcbiAgICAgIHRoaXMuX3VwZGF0ZVNlbmRCdXR0b24oKTtcbiAgICB9O1xuXG4gICAgLy8gU3Vic2NyaWJlIHRvIFx1MjAxQ3dvcmtpbmdcdTIwMUQgKHJlcXVlc3QtaW4tZmxpZ2h0KSBzdGF0ZVxuICAgIHRoaXMud3NDbGllbnQub25Xb3JraW5nQ2hhbmdlID0gKHdvcmtpbmcpID0+IHtcbiAgICAgIHRoaXMuaXNXb3JraW5nID0gd29ya2luZztcbiAgICAgIHRoaXMuX3VwZGF0ZVNlbmRCdXR0b24oKTtcbiAgICB9O1xuXG4gICAgLy8gUmVmbGVjdCBjdXJyZW50IHN0YXRlXG4gICAgdGhpcy5sYXN0R2F0ZXdheVN0YXRlID0gdGhpcy53c0NsaWVudC5zdGF0ZTtcbiAgICB0aGlzLmlzQ29ubmVjdGVkID0gdGhpcy53c0NsaWVudC5zdGF0ZSA9PT0gJ2Nvbm5lY3RlZCc7XG4gICAgdGhpcy5zdGF0dXNEb3QudG9nZ2xlQ2xhc3MoJ2Nvbm5lY3RlZCcsIHRoaXMuaXNDb25uZWN0ZWQpO1xuICAgIHRoaXMuc3RhdHVzRG90LnRpdGxlID0gYEdhdGV3YXk6ICR7dGhpcy53c0NsaWVudC5zdGF0ZX1gO1xuICAgIHRoaXMuX3VwZGF0ZVNlbmRCdXR0b24oKTtcblxuICAgIHRoaXMuX3JlbmRlck1lc3NhZ2VzKHRoaXMuY2hhdE1hbmFnZXIuZ2V0TWVzc2FnZXMoKSk7XG5cbiAgICAvLyBMb2FkIHNlc3Npb24gZHJvcGRvd24gZnJvbSBsb2NhbCB2YXVsdC1zY29wZWQga25vd24gc2Vzc2lvbnMuXG4gICAgdGhpcy5fbG9hZEtub3duU2Vzc2lvbnMoKTtcbiAgfVxuXG4gIGFzeW5jIG9uQ2xvc2UoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgdGhpcy5wbHVnaW4udW5yZWdpc3RlckNoYXRMZWFmKCk7XG4gICAgdGhpcy5jaGF0TWFuYWdlci5vblVwZGF0ZSA9IG51bGw7XG4gICAgdGhpcy5jaGF0TWFuYWdlci5vbk1lc3NhZ2VBZGRlZCA9IG51bGw7XG4gICAgdGhpcy53c0NsaWVudC5vblN0YXRlQ2hhbmdlID0gbnVsbDtcbiAgICB0aGlzLndzQ2xpZW50Lm9uV29ya2luZ0NoYW5nZSA9IG51bGw7XG4gICAgdGhpcy53c0NsaWVudC5kaXNjb25uZWN0KCk7XG5cbiAgICBpZiAodGhpcy5vbkRvY0NsaWNrQ2FwdHVyZSkge1xuICAgICAgdGhpcy5jb250ZW50RWw/Lm93bmVyRG9jdW1lbnQ/LnJlbW92ZUV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgdGhpcy5vbkRvY0NsaWNrQ2FwdHVyZSwgdHJ1ZSk7XG4gICAgICB0aGlzLm9uRG9jQ2xpY2tDYXB0dXJlID0gbnVsbDtcbiAgICB9XG4gICAgdGhpcy5vbk1lc3NhZ2VzQ2xpY2sgPSBudWxsO1xuICB9XG5cbiAgLy8gXHUyNTAwXHUyNTAwIFVJIGNvbnN0cnVjdGlvbiBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcblxuICBwcml2YXRlIF9idWlsZFVJKCk6IHZvaWQge1xuICAgIGNvbnN0IHJvb3QgPSB0aGlzLmNvbnRlbnRFbDtcbiAgICByb290LmVtcHR5KCk7XG4gICAgcm9vdC5hZGRDbGFzcygnb2NsYXctY2hhdC12aWV3Jyk7XG5cbiAgICAvLyBcdTI1MDBcdTI1MDAgSGVhZGVyIFx1MjUwMFx1MjUwMFxuICAgIGNvbnN0IGhlYWRlciA9IHJvb3QuY3JlYXRlRGl2KHsgY2xzOiAnb2NsYXctaGVhZGVyJyB9KTtcbiAgICBoZWFkZXIuY3JlYXRlU3Bhbih7IGNsczogJ29jbGF3LWhlYWRlci10aXRsZScsIHRleHQ6ICdPcGVuQ2xhdyBDaGF0JyB9KTtcbiAgICB0aGlzLnN0YXR1c0RvdCA9IGhlYWRlci5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1zdGF0dXMtZG90JyB9KTtcbiAgICB0aGlzLnN0YXR1c0RvdC50aXRsZSA9ICdHYXRld2F5OiBkaXNjb25uZWN0ZWQnO1xuXG4gICAgLy8gXHUyNTAwXHUyNTAwIFNlc3Npb24gcm93IFx1MjUwMFx1MjUwMFxuICAgIGNvbnN0IHNlc3NSb3cgPSByb290LmNyZWF0ZURpdih7IGNsczogJ29jbGF3LXNlc3Npb24tcm93JyB9KTtcbiAgICBzZXNzUm93LmNyZWF0ZVNwYW4oeyBjbHM6ICdvY2xhdy1zZXNzaW9uLWxhYmVsJywgdGV4dDogJ1Nlc3Npb24nIH0pO1xuXG4gICAgdGhpcy5zZXNzaW9uU2VsZWN0ID0gc2Vzc1Jvdy5jcmVhdGVFbCgnc2VsZWN0JywgeyBjbHM6ICdvY2xhdy1zZXNzaW9uLXNlbGVjdCcgfSk7XG4gICAgdGhpcy5zZXNzaW9uUmVmcmVzaEJ0biA9IHNlc3NSb3cuY3JlYXRlRWwoJ2J1dHRvbicsIHsgY2xzOiAnb2NsYXctc2Vzc2lvbi1idG4nLCB0ZXh0OiAnUmVsb2FkJyB9KTtcbiAgICB0aGlzLnNlc3Npb25OZXdCdG4gPSBzZXNzUm93LmNyZWF0ZUVsKCdidXR0b24nLCB7IGNsczogJ29jbGF3LXNlc3Npb24tYnRuJywgdGV4dDogJ05ld1x1MjAyNicgfSk7XG4gICAgdGhpcy5zZXNzaW9uTWFpbkJ0biA9IHNlc3NSb3cuY3JlYXRlRWwoJ2J1dHRvbicsIHsgY2xzOiAnb2NsYXctc2Vzc2lvbi1idG4nLCB0ZXh0OiAnTWFpbicgfSk7XG5cbiAgICB0aGlzLnNlc3Npb25SZWZyZXNoQnRuLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gdGhpcy5fbG9hZEtub3duU2Vzc2lvbnMoKSk7XG4gICAgdGhpcy5zZXNzaW9uTmV3QnRuLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4ge1xuICAgICAgaWYgKCF0aGlzLnBsdWdpbi5nZXRWYXVsdEhhc2goKSkge1xuICAgICAgICBuZXcgTm90aWNlKCdPcGVuQ2xhdyBDaGF0OiBOZXcgc2Vzc2lvbiBpcyB1bmF2YWlsYWJsZSAobWlzc2luZyB2YXVsdCBpZGVudGl0eSkuJyk7XG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cbiAgICAgIHZvaWQgdGhpcy5fcHJvbXB0TmV3U2Vzc2lvbigpO1xuICAgIH0pO1xuICAgIHRoaXMuc2Vzc2lvbk1haW5CdG4uYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKSA9PiB7XG4gICAgICB2b2lkIChhc3luYyAoKSA9PiB7XG4gICAgICAgIGF3YWl0IHRoaXMuX3N3aXRjaFNlc3Npb24oJ21haW4nKTtcbiAgICAgICAgdGhpcy5fbG9hZEtub3duU2Vzc2lvbnMoKTtcbiAgICAgICAgdGhpcy5zZXNzaW9uU2VsZWN0LnZhbHVlID0gJ21haW4nO1xuICAgICAgICB0aGlzLnNlc3Npb25TZWxlY3QudGl0bGUgPSAnbWFpbic7XG4gICAgICB9KSgpO1xuICAgIH0pO1xuICAgIHRoaXMuc2Vzc2lvblNlbGVjdC5hZGRFdmVudExpc3RlbmVyKCdjaGFuZ2UnLCAoKSA9PiB7XG4gICAgICBpZiAodGhpcy5zdXBwcmVzc1Nlc3Npb25TZWxlY3RDaGFuZ2UpIHJldHVybjtcbiAgICAgIGNvbnN0IG5leHQgPSB0aGlzLnNlc3Npb25TZWxlY3QudmFsdWU7XG4gICAgICBpZiAoIW5leHQpIHJldHVybjtcbiAgICAgIHZvaWQgKGFzeW5jICgpID0+IHtcbiAgICAgICAgYXdhaXQgdGhpcy5fc3dpdGNoU2Vzc2lvbihuZXh0KTtcbiAgICAgICAgdGhpcy5fbG9hZEtub3duU2Vzc2lvbnMoKTtcbiAgICAgICAgdGhpcy5zZXNzaW9uU2VsZWN0LnZhbHVlID0gbmV4dDtcbiAgICAgICAgdGhpcy5zZXNzaW9uU2VsZWN0LnRpdGxlID0gbmV4dDtcbiAgICAgIH0pKCk7XG4gICAgfSk7XG5cbiAgICAvLyBcdTI1MDBcdTI1MDAgTWVzc2FnZXMgYXJlYSBcdTI1MDBcdTI1MDBcbiAgICB0aGlzLm1lc3NhZ2VzRWwgPSByb290LmNyZWF0ZURpdih7IGNsczogJ29jbGF3LW1lc3NhZ2VzJyB9KTtcblxuICAgIC8vIERlbGVnYXRlIGludGVybmFsLWxpbmsgY2xpY2tzIChNYXJrZG93blJlbmRlcmVyIG91dHB1dCkgdG8gYSByZWxpYWJsZSBvcGVuRmlsZSBoYW5kbGVyLlxuICAgIHRoaXMuX2luc3RhbGxJbnRlcm5hbExpbmtEZWxlZ2F0aW9uKCk7XG5cbiAgICAvLyBcdTI1MDBcdTI1MDAgQ29udGV4dCByb3cgXHUyNTAwXHUyNTAwXG4gICAgY29uc3QgY3R4Um93ID0gcm9vdC5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1jb250ZXh0LXJvdycgfSk7XG4gICAgdGhpcy5pbmNsdWRlTm90ZUNoZWNrYm94ID0gY3R4Um93LmNyZWF0ZUVsKCdpbnB1dCcsIHsgdHlwZTogJ2NoZWNrYm94JyB9KTtcbiAgICB0aGlzLmluY2x1ZGVOb3RlQ2hlY2tib3guaWQgPSAnb2NsYXctaW5jbHVkZS1ub3RlJztcbiAgICB0aGlzLmluY2x1ZGVOb3RlQ2hlY2tib3guY2hlY2tlZCA9IHRoaXMucGx1Z2luLnNldHRpbmdzLmluY2x1ZGVBY3RpdmVOb3RlO1xuICAgIGNvbnN0IGN0eExhYmVsID0gY3R4Um93LmNyZWF0ZUVsKCdsYWJlbCcsIHsgdGV4dDogJ0luY2x1ZGUgYWN0aXZlIG5vdGUnIH0pO1xuICAgIGN0eExhYmVsLmh0bWxGb3IgPSAnb2NsYXctaW5jbHVkZS1ub3RlJztcblxuICAgIC8vIFx1MjUwMFx1MjUwMCBJbnB1dCByb3cgXHUyNTAwXHUyNTAwXG4gICAgY29uc3QgaW5wdXRSb3cgPSByb290LmNyZWF0ZURpdih7IGNsczogJ29jbGF3LWlucHV0LXJvdycgfSk7XG4gICAgdGhpcy5pbnB1dEVsID0gaW5wdXRSb3cuY3JlYXRlRWwoJ3RleHRhcmVhJywge1xuICAgICAgY2xzOiAnb2NsYXctaW5wdXQnLFxuICAgICAgcGxhY2Vob2xkZXI6ICdBc2sgYW55dGhpbmdcdTIwMjYnLFxuICAgIH0pO1xuICAgIHRoaXMuaW5wdXRFbC5yb3dzID0gMTtcblxuICAgIHRoaXMuc2VuZEJ0biA9IGlucHV0Um93LmNyZWF0ZUVsKCdidXR0b24nLCB7IGNsczogJ29jbGF3LXNlbmQtYnRuJywgdGV4dDogJ1NlbmQnIH0pO1xuXG4gICAgLy8gXHUyNTAwXHUyNTAwIEV2ZW50IGxpc3RlbmVycyBcdTI1MDBcdTI1MDBcbiAgICB0aGlzLnNlbmRCdG4uYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKSA9PiB0aGlzLl9oYW5kbGVTZW5kKCkpO1xuICAgIHRoaXMuaW5wdXRFbC5hZGRFdmVudExpc3RlbmVyKCdrZXlkb3duJywgKGUpID0+IHtcbiAgICAgIGlmIChlLmtleSA9PT0gJ0VudGVyJyAmJiAhZS5zaGlmdEtleSkge1xuICAgICAgICBlLnByZXZlbnREZWZhdWx0KCk7XG4gICAgICAgIHRoaXMuX2hhbmRsZVNlbmQoKTtcbiAgICAgIH1cbiAgICB9KTtcbiAgICAvLyBBdXRvLXJlc2l6ZSB0ZXh0YXJlYVxuICAgIHRoaXMuaW5wdXRFbC5hZGRFdmVudExpc3RlbmVyKCdpbnB1dCcsICgpID0+IHtcbiAgICAgIHRoaXMuaW5wdXRFbC5zdHlsZS5oZWlnaHQgPSAnYXV0byc7XG4gICAgICB0aGlzLmlucHV0RWwuc3R5bGUuaGVpZ2h0ID0gYCR7dGhpcy5pbnB1dEVsLnNjcm9sbEhlaWdodH1weGA7XG4gICAgfSk7XG4gIH1cblxuICBwcml2YXRlIF9zZXRTZXNzaW9uU2VsZWN0T3B0aW9ucyhrZXlzOiBzdHJpbmdbXSk6IHZvaWQge1xuICAgIHRoaXMuc3VwcHJlc3NTZXNzaW9uU2VsZWN0Q2hhbmdlID0gdHJ1ZTtcbiAgICB0cnkge1xuICAgICAgdGhpcy5zZXNzaW9uU2VsZWN0LmVtcHR5KCk7XG5cbiAgICAgIGNvbnN0IGN1cnJlbnQgPSAodGhpcy5wbHVnaW4uc2V0dGluZ3Muc2Vzc2lvbktleSA/PyAnbWFpbicpLnRvTG93ZXJDYXNlKCk7XG4gICAgICBsZXQgdW5pcXVlID0gQXJyYXkuZnJvbShuZXcgU2V0KFtjdXJyZW50LCAuLi5rZXlzXS5maWx0ZXIoQm9vbGVhbikpKTtcblxuICAgICAgLy8gQ2Fub25pY2FsLW9ubHk6IG1haW4gb3IgYWdlbnQ6bWFpbjpvYnNpZGlhbjpkaXJlY3Q6KlxuICAgICAgdW5pcXVlID0gdW5pcXVlLmZpbHRlcigoaykgPT4gayA9PT0gJ21haW4nIHx8IFN0cmluZyhrKS5zdGFydHNXaXRoKCdhZ2VudDptYWluOm9ic2lkaWFuOmRpcmVjdDonKSk7XG5cbiAgICAgIGlmICh1bmlxdWUubGVuZ3RoID09PSAwKSB7XG4gICAgICAgIHVuaXF1ZSA9IFsnbWFpbiddO1xuICAgICAgfVxuXG4gICAgICBmb3IgKGNvbnN0IGtleSBvZiB1bmlxdWUpIHtcbiAgICAgICAgY29uc3Qgb3B0ID0gdGhpcy5zZXNzaW9uU2VsZWN0LmNyZWF0ZUVsKCdvcHRpb24nLCB7IHZhbHVlOiBrZXksIHRleHQ6IGtleSB9KTtcbiAgICAgICAgaWYgKGtleSA9PT0gY3VycmVudCkgb3B0LnNlbGVjdGVkID0gdHJ1ZTtcbiAgICAgIH1cblxuICAgICAgaWYgKHVuaXF1ZS5pbmNsdWRlcyhjdXJyZW50KSkge1xuICAgICAgICB0aGlzLnNlc3Npb25TZWxlY3QudmFsdWUgPSBjdXJyZW50O1xuICAgICAgfVxuICAgICAgdGhpcy5zZXNzaW9uU2VsZWN0LnRpdGxlID0gY3VycmVudDtcbiAgICB9IGZpbmFsbHkge1xuICAgICAgdGhpcy5zdXBwcmVzc1Nlc3Npb25TZWxlY3RDaGFuZ2UgPSBmYWxzZTtcbiAgICB9XG4gIH1cblxuICBwcml2YXRlIF9sb2FkS25vd25TZXNzaW9ucygpOiB2b2lkIHtcbiAgICBjb25zdCB2YXVsdEhhc2ggPSAodGhpcy5wbHVnaW4uc2V0dGluZ3MudmF1bHRIYXNoID8/ICcnKS50cmltKCk7XG4gICAgY29uc3QgbWFwID0gdGhpcy5wbHVnaW4uc2V0dGluZ3Mua25vd25TZXNzaW9uS2V5c0J5VmF1bHQgPz8ge307XG4gICAgY29uc3Qga2V5cyA9IHZhdWx0SGFzaCAmJiBBcnJheS5pc0FycmF5KG1hcFt2YXVsdEhhc2hdKSA/IG1hcFt2YXVsdEhhc2hdIDogW107XG5cbiAgICBjb25zdCBwcmVmaXggPSB2YXVsdEhhc2ggPyBgYWdlbnQ6bWFpbjpvYnNpZGlhbjpkaXJlY3Q6JHt2YXVsdEhhc2h9YCA6ICcnO1xuICAgIGNvbnN0IGZpbHRlcmVkID0gdmF1bHRIYXNoXG4gICAgICA/IGtleXMuZmlsdGVyKChrKSA9PiB7XG4gICAgICAgICAgY29uc3Qga2V5ID0gU3RyaW5nKGsgfHwgJycpLnRyaW0oKS50b0xvd2VyQ2FzZSgpO1xuICAgICAgICAgIHJldHVybiBrZXkgPT09IHByZWZpeCB8fCBrZXkuc3RhcnRzV2l0aChwcmVmaXggKyAnLScpO1xuICAgICAgICB9KVxuICAgICAgOiBbXTtcblxuICAgIHRoaXMuX3NldFNlc3Npb25TZWxlY3RPcHRpb25zKGZpbHRlcmVkKTtcbiAgfVxuXG4gIHByaXZhdGUgYXN5bmMgX3N3aXRjaFNlc3Npb24oc2Vzc2lvbktleTogc3RyaW5nKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgY29uc3QgbmV4dCA9IHNlc3Npb25LZXkudHJpbSgpLnRvTG93ZXJDYXNlKCk7XG4gICAgaWYgKCFuZXh0KSByZXR1cm47XG5cbiAgICBjb25zdCB2YXVsdEhhc2ggPSB0aGlzLnBsdWdpbi5nZXRWYXVsdEhhc2goKTtcbiAgICBpZiAodmF1bHRIYXNoKSB7XG4gICAgICBjb25zdCBwcmVmaXggPSBgYWdlbnQ6bWFpbjpvYnNpZGlhbjpkaXJlY3Q6JHt2YXVsdEhhc2h9YDtcbiAgICAgIGlmICghKG5leHQgPT09ICdtYWluJyB8fCBuZXh0ID09PSBwcmVmaXggfHwgbmV4dC5zdGFydHNXaXRoKHByZWZpeCArICctJykpKSB7XG4gICAgICAgIG5ldyBOb3RpY2UoJ09wZW5DbGF3IENoYXQ6IHNlc3Npb24ga2V5IG11c3QgbWF0Y2ggdGhpcyB2YXVsdC4nKTtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuICAgIH0gZWxzZSB7XG4gICAgICBpZiAobmV4dCAhPT0gJ21haW4nKSB7XG4gICAgICAgIG5ldyBOb3RpY2UoJ09wZW5DbGF3IENoYXQ6IGNhbm5vdCBzd2l0Y2ggc2Vzc2lvbnMgKG1pc3NpbmcgdmF1bHQgaWRlbnRpdHkpLicpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG4gICAgfVxuXG4gICAgLy8gQWJvcnQgYW55IGluLWZsaWdodCBydW4gYmVzdC1lZmZvcnQuXG4gICAgdHJ5IHtcbiAgICAgIGF3YWl0IHRoaXMud3NDbGllbnQuYWJvcnRBY3RpdmVSdW4oKTtcbiAgICB9IGNhdGNoIHtcbiAgICAgIC8vIGlnbm9yZVxuICAgIH1cblxuICAgIC8vIERpdmlkZXIgaW4gdGhpcyBsZWFmIG9ubHkuXG4gICAgdGhpcy5jaGF0TWFuYWdlci5hZGRNZXNzYWdlKENoYXRNYW5hZ2VyLmNyZWF0ZVNlc3Npb25EaXZpZGVyKG5leHQpKTtcblxuICAgIC8vIFBlcnNpc3QgYXMgdGhlIGRlZmF1bHQgYW5kIHJlbWVtYmVyIGl0IGluIHRoZSB2YXVsdC1zY29wZWQgbGlzdC5cbiAgICBhd2FpdCB0aGlzLnBsdWdpbi5yZW1lbWJlclNlc3Npb25LZXkobmV4dCk7XG5cbiAgICAvLyBTd2l0Y2ggV1Mgcm91dGluZyBmb3IgdGhpcyBsZWFmLlxuICAgIHRoaXMud3NDbGllbnQuZGlzY29ubmVjdCgpO1xuICAgIHRoaXMud3NDbGllbnQuc2V0U2Vzc2lvbktleShuZXh0KTtcblxuICAgIGNvbnN0IGd3ID0gdGhpcy5wbHVnaW4uZ2V0R2F0ZXdheUNvbmZpZygpO1xuICAgIGlmIChndy50b2tlbikge1xuICAgICAgdGhpcy53c0NsaWVudC5jb25uZWN0KGd3LnVybCwgZ3cudG9rZW4sIHsgYWxsb3dJbnNlY3VyZVdzOiBndy5hbGxvd0luc2VjdXJlV3MgfSk7XG4gICAgfSBlbHNlIHtcbiAgICAgIG5ldyBOb3RpY2UoJ09wZW5DbGF3IENoYXQ6IHBsZWFzZSBjb25maWd1cmUgeW91ciBnYXRld2F5IHRva2VuIGluIFNldHRpbmdzLicpO1xuICAgIH1cbiAgfVxuXG4gIHByaXZhdGUgYXN5bmMgX3Byb21wdE5ld1Nlc3Npb24oKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgY29uc3Qgbm93ID0gbmV3IERhdGUoKTtcbiAgICBjb25zdCBwYWQgPSAobjogbnVtYmVyKSA9PiBTdHJpbmcobikucGFkU3RhcnQoMiwgJzAnKTtcbiAgICBjb25zdCBzdWdnZXN0ZWQgPSBgY2hhdC0ke25vdy5nZXRGdWxsWWVhcigpfSR7cGFkKG5vdy5nZXRNb250aCgpICsgMSl9JHtwYWQobm93LmdldERhdGUoKSl9LSR7cGFkKG5vdy5nZXRIb3VycygpKX0ke3BhZChub3cuZ2V0TWludXRlcygpKX1gO1xuXG4gICAgY29uc3QgbW9kYWwgPSBuZXcgTmV3U2Vzc2lvbk1vZGFsKHRoaXMsIHN1Z2dlc3RlZCwgKHN1ZmZpeCkgPT4ge1xuICAgICAgY29uc3QgdmF1bHRIYXNoID0gKHRoaXMucGx1Z2luLnNldHRpbmdzLnZhdWx0SGFzaCA/PyAnJykudHJpbSgpO1xuICAgICAgaWYgKCF2YXVsdEhhc2gpIHtcbiAgICAgICAgbmV3IE5vdGljZSgnT3BlbkNsYXcgQ2hhdDogY2Fubm90IGNyZWF0ZSBzZXNzaW9uIChtaXNzaW5nIHZhdWx0IGlkZW50aXR5KS4nKTtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuICAgICAgY29uc3Qga2V5ID0gYGFnZW50Om1haW46b2JzaWRpYW46ZGlyZWN0OiR7dmF1bHRIYXNofS0ke3N1ZmZpeH1gO1xuICAgICAgdm9pZCAoYXN5bmMgKCkgPT4ge1xuICAgICAgICBhd2FpdCB0aGlzLl9zd2l0Y2hTZXNzaW9uKGtleSk7XG4gICAgICAgIHRoaXMuX2xvYWRLbm93blNlc3Npb25zKCk7XG4gICAgICAgIHRoaXMuc2Vzc2lvblNlbGVjdC52YWx1ZSA9IGtleTtcbiAgICAgICAgdGhpcy5zZXNzaW9uU2VsZWN0LnRpdGxlID0ga2V5O1xuICAgICAgfSkoKTtcbiAgICB9KTtcbiAgICBtb2RhbC5vcGVuKCk7XG4gIH1cblxuICAvLyBcdTI1MDBcdTI1MDAgTWVzc2FnZSByZW5kZXJpbmcgXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG5cbiAgcHJpdmF0ZSBfcmVuZGVyTWVzc2FnZXMobWVzc2FnZXM6IHJlYWRvbmx5IENoYXRNZXNzYWdlW10pOiB2b2lkIHtcbiAgICB0aGlzLm1lc3NhZ2VzRWwuZW1wdHkoKTtcblxuICAgIGlmIChtZXNzYWdlcy5sZW5ndGggPT09IDApIHtcbiAgICAgIHRoaXMubWVzc2FnZXNFbC5jcmVhdGVFbCgncCcsIHtcbiAgICAgICAgdGV4dDogJ1NlbmQgYSBtZXNzYWdlIHRvIHN0YXJ0IGNoYXR0aW5nLicsXG4gICAgICAgIGNsczogJ29jbGF3LW1lc3NhZ2Ugc3lzdGVtIG9jbGF3LXBsYWNlaG9sZGVyJyxcbiAgICAgIH0pO1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIGZvciAoY29uc3QgbXNnIG9mIG1lc3NhZ2VzKSB7XG4gICAgICB0aGlzLl9hcHBlbmRNZXNzYWdlKG1zZyk7XG4gICAgfVxuXG4gICAgLy8gU2Nyb2xsIHRvIGJvdHRvbVxuICAgIHRoaXMubWVzc2FnZXNFbC5zY3JvbGxUb3AgPSB0aGlzLm1lc3NhZ2VzRWwuc2Nyb2xsSGVpZ2h0O1xuICB9XG5cbiAgLyoqIEFwcGVuZHMgYSBzaW5nbGUgbWVzc2FnZSB3aXRob3V0IHJlYnVpbGRpbmcgdGhlIERPTSAoTygxKSkgKi9cbiAgcHJpdmF0ZSBfYXBwZW5kTWVzc2FnZShtc2c6IENoYXRNZXNzYWdlKTogdm9pZCB7XG4gICAgLy8gUmVtb3ZlIGVtcHR5LXN0YXRlIHBsYWNlaG9sZGVyIGlmIHByZXNlbnRcbiAgICB0aGlzLm1lc3NhZ2VzRWwucXVlcnlTZWxlY3RvcignLm9jbGF3LXBsYWNlaG9sZGVyJyk/LnJlbW92ZSgpO1xuXG4gICAgY29uc3QgbGV2ZWxDbGFzcyA9IG1zZy5sZXZlbCA/IGAgJHttc2cubGV2ZWx9YCA6ICcnO1xuICAgIGNvbnN0IGtpbmRDbGFzcyA9IG1zZy5raW5kID8gYCBvY2xhdy0ke21zZy5raW5kfWAgOiAnJztcbiAgICBjb25zdCBlbCA9IHRoaXMubWVzc2FnZXNFbC5jcmVhdGVEaXYoeyBjbHM6IGBvY2xhdy1tZXNzYWdlICR7bXNnLnJvbGV9JHtsZXZlbENsYXNzfSR7a2luZENsYXNzfWAgfSk7XG4gICAgY29uc3QgYm9keSA9IGVsLmNyZWF0ZURpdih7IGNsczogJ29jbGF3LW1lc3NhZ2UtYm9keScgfSk7XG4gICAgaWYgKG1zZy50aXRsZSkge1xuICAgICAgYm9keS50aXRsZSA9IG1zZy50aXRsZTtcbiAgICB9XG5cbiAgICAvLyBUcmVhdCBhc3Npc3RhbnQgb3V0cHV0IGFzIFVOVFJVU1RFRCBieSBkZWZhdWx0LlxuICAgIC8vIFJlbmRlcmluZyBhcyBPYnNpZGlhbiBNYXJrZG93biBjYW4gdHJpZ2dlciBlbWJlZHMgYW5kIG90aGVyIHBsdWdpbnMnIHBvc3QtcHJvY2Vzc29ycy5cbiAgICBpZiAobXNnLnJvbGUgPT09ICdhc3Npc3RhbnQnKSB7XG4gICAgICBjb25zdCBtYXBwaW5nczogUGF0aE1hcHBpbmdbXSA9IHRoaXMucGx1Z2luLnNldHRpbmdzLnBhdGhNYXBwaW5ncyA/PyBbXTtcbiAgICAgIGNvbnN0IHNvdXJjZVBhdGggPSB0aGlzLmFwcC53b3Jrc3BhY2UuZ2V0QWN0aXZlRmlsZSgpPy5wYXRoID8/ICcnO1xuXG4gICAgICBpZiAodGhpcy5wbHVnaW4uc2V0dGluZ3MucmVuZGVyQXNzaXN0YW50TWFya2Rvd24pIHtcbiAgICAgICAgLy8gQmVzdC1lZmZvcnQgcHJlLXByb2Nlc3Npbmc6IHJlcGxhY2Uga25vd24gcmVtb3RlIHBhdGhzIHdpdGggd2lraWxpbmtzIHdoZW4gdGhlIHRhcmdldCBleGlzdHMuXG4gICAgICAgIGNvbnN0IHByZSA9IHRoaXMuX3ByZXByb2Nlc3NBc3Npc3RhbnRNYXJrZG93bihtc2cuY29udGVudCwgbWFwcGluZ3MpO1xuICAgICAgICB2b2lkIE1hcmtkb3duUmVuZGVyZXIucmVuZGVyTWFya2Rvd24ocHJlLCBib2R5LCBzb3VyY2VQYXRoLCB0aGlzLnBsdWdpbik7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICAvLyBQbGFpbiBtb2RlOiBidWlsZCBzYWZlLCBjbGlja2FibGUgbGlua3MgaW4gRE9NIChubyBNYXJrZG93biByZW5kZXJpbmcpLlxuICAgICAgICB0aGlzLl9yZW5kZXJBc3Npc3RhbnRQbGFpbldpdGhMaW5rcyhib2R5LCBtc2cuY29udGVudCwgbWFwcGluZ3MsIHNvdXJjZVBhdGgpO1xuICAgICAgfVxuICAgIH0gZWxzZSB7XG4gICAgICBib2R5LnNldFRleHQobXNnLmNvbnRlbnQpO1xuICAgIH1cblxuICAgIC8vIFNjcm9sbCB0byBib3R0b21cbiAgICB0aGlzLm1lc3NhZ2VzRWwuc2Nyb2xsVG9wID0gdGhpcy5tZXNzYWdlc0VsLnNjcm9sbEhlaWdodDtcbiAgfVxuXG4gIHByaXZhdGUgX3RyeVJldmVyc2VNYXBVcmxUb1ZhdWx0UGF0aCh1cmw6IHN0cmluZywgbWFwcGluZ3M6IFBhdGhNYXBwaW5nW10pOiBzdHJpbmcgfCBudWxsIHtcbiAgICAvLyBGUy1iYXNlZCBtYXBwaW5nOyBiZXN0LWVmZm9ydCBvbmx5LlxuICAgIGxldCBkZWNvZGVkID0gdXJsO1xuICAgIHRyeSB7XG4gICAgICBkZWNvZGVkID0gZGVjb2RlVVJJQ29tcG9uZW50KHVybCk7XG4gICAgfSBjYXRjaCB7XG4gICAgICAvLyBpZ25vcmVcbiAgICB9XG5cbiAgICAvLyBJZiB0aGUgZGVjb2RlZCBVUkwgY29udGFpbnMgYSByZW1vdGVCYXNlIHN1YnN0cmluZywgdHJ5IG1hcHBpbmcgZnJvbSB0aGF0IHBvaW50LlxuICAgIGZvciAoY29uc3Qgcm93IG9mIG1hcHBpbmdzKSB7XG4gICAgICBjb25zdCByZW1vdGVCYXNlID0gU3RyaW5nKHJvdy5yZW1vdGVCYXNlID8/ICcnKTtcbiAgICAgIGlmICghcmVtb3RlQmFzZSkgY29udGludWU7XG4gICAgICBjb25zdCBpZHggPSBkZWNvZGVkLmluZGV4T2YocmVtb3RlQmFzZSk7XG4gICAgICBpZiAoaWR4IDwgMCkgY29udGludWU7XG5cbiAgICAgIC8vIEV4dHJhY3QgZnJvbSByZW1vdGVCYXNlIG9ud2FyZCB1bnRpbCBhIHRlcm1pbmF0b3IuXG4gICAgICBjb25zdCB0YWlsID0gZGVjb2RlZC5zbGljZShpZHgpO1xuICAgICAgY29uc3QgdG9rZW4gPSB0YWlsLnNwbGl0KC9bXFxzJ1wiPD4pXS8pWzBdO1xuICAgICAgY29uc3QgbWFwcGVkID0gdHJ5TWFwUmVtb3RlUGF0aFRvVmF1bHRQYXRoKHRva2VuLCBtYXBwaW5ncyk7XG4gICAgICBpZiAobWFwcGVkICYmIHRoaXMuYXBwLnZhdWx0LmdldEFic3RyYWN0RmlsZUJ5UGF0aChtYXBwZWQpKSByZXR1cm4gbWFwcGVkO1xuICAgIH1cblxuICAgIHJldHVybiBudWxsO1xuICB9XG5cbiAgcHJpdmF0ZSBfaW5zdGFsbEludGVybmFsTGlua0RlbGVnYXRpb24oKTogdm9pZCB7XG4gICAgaWYgKHRoaXMub25NZXNzYWdlc0NsaWNrIHx8IHRoaXMub25Eb2NDbGlja0NhcHR1cmUpIHJldHVybjtcblxuICAgIGNvbnN0IGhhbmRsZXIgPSAoZXY6IE1vdXNlRXZlbnQpID0+IHtcbiAgICAgIGNvbnN0IHRhcmdldCA9IGV2LnRhcmdldCBhcyBIVE1MRWxlbWVudCB8IG51bGw7XG4gICAgICBpZiAoIXRhcmdldCkgcmV0dXJuO1xuXG4gICAgICAvLyBPbmx5IGhhbmRsZSBjbGlja3Mgb3JpZ2luYXRpbmcgZnJvbSB3aXRoaW4gb3VyIG1lc3NhZ2VzIGNvbnRhaW5lci5cbiAgICAgIGlmICghdGhpcy5tZXNzYWdlc0VsPy5jb250YWlucyh0YXJnZXQpKSByZXR1cm47XG5cbiAgICAgIGNvbnN0IGEgPSB0YXJnZXQuY2xvc2VzdD8uKCdhLmludGVybmFsLWxpbmsnKSBhcyBIVE1MQW5jaG9yRWxlbWVudCB8IG51bGw7XG4gICAgICBpZiAoIWEpIHJldHVybjtcblxuICAgICAgY29uc3QgZGF0YUhyZWYgPSBhLmdldEF0dHJpYnV0ZSgnZGF0YS1ocmVmJykgfHwgJyc7XG4gICAgICBjb25zdCBocmVmQXR0ciA9IGEuZ2V0QXR0cmlidXRlKCdocmVmJykgfHwgJyc7XG4gICAgICBjb25zdCByYXcgPSAoZGF0YUhyZWYgfHwgaHJlZkF0dHIpLnRyaW0oKTtcbiAgICAgIGlmICghcmF3KSByZXR1cm47XG5cbiAgICAgIC8vIElmIGl0IGlzIGFuIGFic29sdXRlIFVSTCwgbGV0IHRoZSBkZWZhdWx0IGJlaGF2aW9yIGhhbmRsZSBpdC5cbiAgICAgIGlmICgvXmh0dHBzPzpcXC9cXC8vaS50ZXN0KHJhdykpIHJldHVybjtcblxuICAgICAgY29uc3QgdmF1bHRQYXRoID0gcmF3LnJlcGxhY2UoL15cXC8rLywgJycpO1xuICAgICAgY29uc3QgZiA9IHRoaXMuYXBwLnZhdWx0LmdldEFic3RyYWN0RmlsZUJ5UGF0aCh2YXVsdFBhdGgpO1xuXG4gICAgICBldi5wcmV2ZW50RGVmYXVsdCgpO1xuICAgICAgZXYuc3RvcFByb3BhZ2F0aW9uKCk7XG5cbiAgICAgIGlmIChmIGluc3RhbmNlb2YgVEZpbGUpIHtcbiAgICAgICAgdm9pZCB0aGlzLmFwcC53b3Jrc3BhY2UuZ2V0TGVhZih0cnVlKS5vcGVuRmlsZShmKTtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuXG4gICAgICB2b2lkIHRoaXMuYXBwLndvcmtzcGFjZS5vcGVuTGlua1RleHQodmF1bHRQYXRoLCB0aGlzLmFwcC53b3Jrc3BhY2UuZ2V0QWN0aXZlRmlsZSgpPy5wYXRoID8/ICcnLCB0cnVlKTtcbiAgICB9O1xuXG4gICAgdGhpcy5vbk1lc3NhZ2VzQ2xpY2sgPSBoYW5kbGVyO1xuICAgIHRoaXMub25Eb2NDbGlja0NhcHR1cmUgPSBoYW5kbGVyO1xuXG4gICAgLy8gTWFjL09ic2lkaWFuIGNhbiBzd2FsbG93IGludGVybmFsLWxpbmsgZXZlbnRzOyBhdHRhY2ggYXQgZG9jdW1lbnQgY2FwdHVyZSBwaGFzZS5cbiAgICB0aGlzLmNvbnRlbnRFbC5vd25lckRvY3VtZW50LmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgaGFuZGxlciwgdHJ1ZSk7XG4gIH1cblxuICBwcml2YXRlIF90cnlNYXBWYXVsdFJlbGF0aXZlVG9rZW4odG9rZW46IHN0cmluZywgbWFwcGluZ3M6IFBhdGhNYXBwaW5nW10pOiBzdHJpbmcgfCBudWxsIHtcbiAgICBjb25zdCB0ID0gdG9rZW4ucmVwbGFjZSgvXlxcLysvLCAnJyk7XG4gICAgaWYgKHRoaXMuYXBwLnZhdWx0LmdldEFic3RyYWN0RmlsZUJ5UGF0aCh0KSkgcmV0dXJuIHQ7XG5cbiAgICAvLyBIZXVyaXN0aWM6IGlmIHZhdWx0QmFzZSBlbmRzIHdpdGggYSBzZWdtZW50IChlLmcuIHdvcmtzcGFjZS9jb21wZW5nLykgYW5kIHRva2VuIHN0YXJ0cyB3aXRoIHRoYXQgc2VnbWVudCAoY29tcGVuZy8uLi4pLFxuICAgIC8vIG1hcCB0b2tlbiB1bmRlciB2YXVsdEJhc2UuXG4gICAgZm9yIChjb25zdCByb3cgb2YgbWFwcGluZ3MpIHtcbiAgICAgIGNvbnN0IHZhdWx0QmFzZVJhdyA9IFN0cmluZyhyb3cudmF1bHRCYXNlID8/ICcnKS50cmltKCk7XG4gICAgICBpZiAoIXZhdWx0QmFzZVJhdykgY29udGludWU7XG4gICAgICBjb25zdCB2YXVsdEJhc2UgPSB2YXVsdEJhc2VSYXcuZW5kc1dpdGgoJy8nKSA/IHZhdWx0QmFzZVJhdyA6IGAke3ZhdWx0QmFzZVJhd30vYDtcblxuICAgICAgY29uc3QgcGFydHMgPSB2YXVsdEJhc2UucmVwbGFjZSgvXFwvKyQvLCAnJykuc3BsaXQoJy8nKTtcbiAgICAgIGNvbnN0IGJhc2VOYW1lID0gcGFydHNbcGFydHMubGVuZ3RoIC0gMV07XG4gICAgICBpZiAoIWJhc2VOYW1lKSBjb250aW51ZTtcblxuICAgICAgY29uc3QgcHJlZml4ID0gYCR7YmFzZU5hbWV9L2A7XG4gICAgICBpZiAoIXQuc3RhcnRzV2l0aChwcmVmaXgpKSBjb250aW51ZTtcblxuICAgICAgY29uc3QgY2FuZGlkYXRlID0gYCR7dmF1bHRCYXNlfSR7dC5zbGljZShwcmVmaXgubGVuZ3RoKX1gO1xuICAgICAgY29uc3Qgbm9ybWFsaXplZCA9IGNhbmRpZGF0ZS5yZXBsYWNlKC9eXFwvKy8sICcnKTtcbiAgICAgIGlmICh0aGlzLmFwcC52YXVsdC5nZXRBYnN0cmFjdEZpbGVCeVBhdGgobm9ybWFsaXplZCkpIHJldHVybiBub3JtYWxpemVkO1xuICAgIH1cblxuICAgIHJldHVybiBudWxsO1xuICB9XG5cbiAgcHJpdmF0ZSBfcHJlcHJvY2Vzc0Fzc2lzdGFudE1hcmtkb3duKHRleHQ6IHN0cmluZywgbWFwcGluZ3M6IFBhdGhNYXBwaW5nW10pOiBzdHJpbmcge1xuICAgIGNvbnN0IGNhbmRpZGF0ZXMgPSBleHRyYWN0Q2FuZGlkYXRlcyh0ZXh0KTtcbiAgICBpZiAoY2FuZGlkYXRlcy5sZW5ndGggPT09IDApIHJldHVybiB0ZXh0O1xuXG4gICAgbGV0IG91dCA9ICcnO1xuICAgIGxldCBjdXJzb3IgPSAwO1xuXG4gICAgZm9yIChjb25zdCBjIG9mIGNhbmRpZGF0ZXMpIHtcbiAgICAgIG91dCArPSB0ZXh0LnNsaWNlKGN1cnNvciwgYy5zdGFydCk7XG4gICAgICBjdXJzb3IgPSBjLmVuZDtcblxuICAgICAgaWYgKGMua2luZCA9PT0gJ3VybCcpIHtcbiAgICAgICAgLy8gVVJMcyByZW1haW4gVVJMcyBVTkxFU1Mgd2UgY2FuIHNhZmVseSBtYXAgdG8gYW4gZXhpc3RpbmcgdmF1bHQgZmlsZS5cbiAgICAgICAgY29uc3QgbWFwcGVkID0gdGhpcy5fdHJ5UmV2ZXJzZU1hcFVybFRvVmF1bHRQYXRoKGMucmF3LCBtYXBwaW5ncyk7XG4gICAgICAgIG91dCArPSBtYXBwZWQgPyBgW1ske21hcHBlZH1dXWAgOiBjLnJhdztcbiAgICAgICAgY29udGludWU7XG4gICAgICB9XG5cbiAgICAgIC8vIDEpIElmIHRoZSB0b2tlbiBpcyBhbHJlYWR5IGEgdmF1bHQtcmVsYXRpdmUgcGF0aCAob3IgY2FuIGJlIHJlc29sdmVkIHZpYSB2YXVsdEJhc2UgaGV1cmlzdGljKSwgbGlua2lmeSBpdCBkaXJlY3RseS5cbiAgICAgIGNvbnN0IGRpcmVjdCA9IHRoaXMuX3RyeU1hcFZhdWx0UmVsYXRpdmVUb2tlbihjLnJhdywgbWFwcGluZ3MpO1xuICAgICAgaWYgKGRpcmVjdCkge1xuICAgICAgICBvdXQgKz0gYFtbJHtkaXJlY3R9XV1gO1xuICAgICAgICBjb250aW51ZTtcbiAgICAgIH1cblxuICAgICAgLy8gMikgRWxzZTogdHJ5IHJlbW90ZVx1MjE5MnZhdWx0IG1hcHBpbmcuXG4gICAgICBjb25zdCBtYXBwZWQgPSB0cnlNYXBSZW1vdGVQYXRoVG9WYXVsdFBhdGgoYy5yYXcsIG1hcHBpbmdzKTtcbiAgICAgIGlmICghbWFwcGVkKSB7XG4gICAgICAgIG91dCArPSBjLnJhdztcbiAgICAgICAgY29udGludWU7XG4gICAgICB9XG5cbiAgICAgIGlmICghdGhpcy5hcHAudmF1bHQuZ2V0QWJzdHJhY3RGaWxlQnlQYXRoKG1hcHBlZCkpIHtcbiAgICAgICAgb3V0ICs9IGMucmF3O1xuICAgICAgICBjb250aW51ZTtcbiAgICAgIH1cblxuICAgICAgb3V0ICs9IGBbWyR7bWFwcGVkfV1dYDtcbiAgICB9XG5cbiAgICBvdXQgKz0gdGV4dC5zbGljZShjdXJzb3IpO1xuICAgIHJldHVybiBvdXQ7XG4gIH1cblxuICBwcml2YXRlIF9yZW5kZXJBc3Npc3RhbnRQbGFpbldpdGhMaW5rcyhcbiAgICBib2R5OiBIVE1MRWxlbWVudCxcbiAgICB0ZXh0OiBzdHJpbmcsXG4gICAgbWFwcGluZ3M6IFBhdGhNYXBwaW5nW10sXG4gICAgc291cmNlUGF0aDogc3RyaW5nLFxuICApOiB2b2lkIHtcbiAgICBjb25zdCBjYW5kaWRhdGVzID0gZXh0cmFjdENhbmRpZGF0ZXModGV4dCk7XG4gICAgaWYgKGNhbmRpZGF0ZXMubGVuZ3RoID09PSAwKSB7XG4gICAgICBib2R5LnNldFRleHQodGV4dCk7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgbGV0IGN1cnNvciA9IDA7XG5cbiAgICBjb25zdCBhcHBlbmRUZXh0ID0gKHM6IHN0cmluZykgPT4ge1xuICAgICAgaWYgKCFzKSByZXR1cm47XG4gICAgICBib2R5LmFwcGVuZENoaWxkKGRvY3VtZW50LmNyZWF0ZVRleHROb2RlKHMpKTtcbiAgICB9O1xuXG4gICAgY29uc3QgYXBwZW5kT2JzaWRpYW5MaW5rID0gKHZhdWx0UGF0aDogc3RyaW5nKSA9PiB7XG4gICAgICBjb25zdCBkaXNwbGF5ID0gYFtbJHt2YXVsdFBhdGh9XV1gO1xuICAgICAgY29uc3QgYSA9IGJvZHkuY3JlYXRlRWwoJ2EnLCB7IHRleHQ6IGRpc3BsYXksIGhyZWY6ICcjJyB9KTtcbiAgICAgIGEuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoZXYpID0+IHtcbiAgICAgICAgZXYucHJldmVudERlZmF1bHQoKTtcbiAgICAgICAgZXYuc3RvcFByb3BhZ2F0aW9uKCk7XG5cbiAgICAgICAgY29uc3QgZiA9IHRoaXMuYXBwLnZhdWx0LmdldEFic3RyYWN0RmlsZUJ5UGF0aCh2YXVsdFBhdGgpO1xuICAgICAgICBpZiAoZiBpbnN0YW5jZW9mIFRGaWxlKSB7XG4gICAgICAgICAgdm9pZCB0aGlzLmFwcC53b3Jrc3BhY2UuZ2V0TGVhZih0cnVlKS5vcGVuRmlsZShmKTtcbiAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICAvLyBGYWxsYmFjazogYmVzdC1lZmZvcnQgbGlua3RleHQgb3Blbi5cbiAgICAgICAgdm9pZCB0aGlzLmFwcC53b3Jrc3BhY2Uub3BlbkxpbmtUZXh0KHZhdWx0UGF0aCwgc291cmNlUGF0aCwgdHJ1ZSk7XG4gICAgICB9KTtcbiAgICB9O1xuXG4gICAgY29uc3QgYXBwZW5kRXh0ZXJuYWxVcmwgPSAodXJsOiBzdHJpbmcpID0+IHtcbiAgICAgIC8vIExldCBPYnNpZGlhbi9FbGVjdHJvbiBoYW5kbGUgZXh0ZXJuYWwgb3Blbi5cbiAgICAgIGJvZHkuY3JlYXRlRWwoJ2EnLCB7IHRleHQ6IHVybCwgaHJlZjogdXJsIH0pO1xuICAgIH07XG5cbiAgICBjb25zdCB0cnlSZXZlcnNlTWFwVXJsVG9WYXVsdFBhdGggPSAodXJsOiBzdHJpbmcpOiBzdHJpbmcgfCBudWxsID0+IHRoaXMuX3RyeVJldmVyc2VNYXBVcmxUb1ZhdWx0UGF0aCh1cmwsIG1hcHBpbmdzKTtcblxuICAgIGZvciAoY29uc3QgYyBvZiBjYW5kaWRhdGVzKSB7XG4gICAgICBhcHBlbmRUZXh0KHRleHQuc2xpY2UoY3Vyc29yLCBjLnN0YXJ0KSk7XG4gICAgICBjdXJzb3IgPSBjLmVuZDtcblxuICAgICAgaWYgKGMua2luZCA9PT0gJ3VybCcpIHtcbiAgICAgICAgY29uc3QgbWFwcGVkID0gdHJ5UmV2ZXJzZU1hcFVybFRvVmF1bHRQYXRoKGMucmF3KTtcbiAgICAgICAgaWYgKG1hcHBlZCkge1xuICAgICAgICAgIGFwcGVuZE9ic2lkaWFuTGluayhtYXBwZWQpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIGFwcGVuZEV4dGVybmFsVXJsKGMucmF3KTtcbiAgICAgICAgfVxuICAgICAgICBjb250aW51ZTtcbiAgICAgIH1cblxuICAgICAgLy8gMSkgSWYgdG9rZW4gaXMgYWxyZWFkeSBhIHZhdWx0LXJlbGF0aXZlIHBhdGggKG9yIGNhbiBiZSByZXNvbHZlZCB2aWEgdmF1bHRCYXNlIGhldXJpc3RpYyksIGxpbmtpZnkgZGlyZWN0bHkuXG4gICAgICBjb25zdCBkaXJlY3QgPSB0aGlzLl90cnlNYXBWYXVsdFJlbGF0aXZlVG9rZW4oYy5yYXcsIG1hcHBpbmdzKTtcbiAgICAgIGlmIChkaXJlY3QpIHtcbiAgICAgICAgYXBwZW5kT2JzaWRpYW5MaW5rKGRpcmVjdCk7XG4gICAgICAgIGNvbnRpbnVlO1xuICAgICAgfVxuXG4gICAgICAvLyAyKSBFbHNlOiB0cnkgcmVtb3RlXHUyMTkydmF1bHQgbWFwcGluZy5cbiAgICAgIGNvbnN0IG1hcHBlZCA9IHRyeU1hcFJlbW90ZVBhdGhUb1ZhdWx0UGF0aChjLnJhdywgbWFwcGluZ3MpO1xuICAgICAgaWYgKCFtYXBwZWQpIHtcbiAgICAgICAgYXBwZW5kVGV4dChjLnJhdyk7XG4gICAgICAgIGNvbnRpbnVlO1xuICAgICAgfVxuXG4gICAgICBpZiAoIXRoaXMuYXBwLnZhdWx0LmdldEFic3RyYWN0RmlsZUJ5UGF0aChtYXBwZWQpKSB7XG4gICAgICAgIGFwcGVuZFRleHQoYy5yYXcpO1xuICAgICAgICBjb250aW51ZTtcbiAgICAgIH1cblxuICAgICAgYXBwZW5kT2JzaWRpYW5MaW5rKG1hcHBlZCk7XG4gICAgfVxuXG4gICAgYXBwZW5kVGV4dCh0ZXh0LnNsaWNlKGN1cnNvcikpO1xuICB9XG5cbiAgcHJpdmF0ZSBfdXBkYXRlU2VuZEJ1dHRvbigpOiB2b2lkIHtcbiAgICAvLyBEaXNjb25uZWN0ZWQ6IGRpc2FibGUuXG4gICAgLy8gV29ya2luZzoga2VlcCBlbmFibGVkIHNvIHVzZXIgY2FuIHN0b3AvYWJvcnQuXG4gICAgY29uc3QgZGlzYWJsZWQgPSAhdGhpcy5pc0Nvbm5lY3RlZDtcbiAgICB0aGlzLnNlbmRCdG4uZGlzYWJsZWQgPSBkaXNhYmxlZDtcblxuICAgIHRoaXMuc2VuZEJ0bi50b2dnbGVDbGFzcygnaXMtd29ya2luZycsIHRoaXMuaXNXb3JraW5nKTtcbiAgICB0aGlzLnNlbmRCdG4uc2V0QXR0cignYXJpYS1idXN5JywgdGhpcy5pc1dvcmtpbmcgPyAndHJ1ZScgOiAnZmFsc2UnKTtcbiAgICB0aGlzLnNlbmRCdG4uc2V0QXR0cignYXJpYS1sYWJlbCcsIHRoaXMuaXNXb3JraW5nID8gJ1N0b3AnIDogJ1NlbmQnKTtcblxuICAgIGlmICh0aGlzLmlzV29ya2luZykge1xuICAgICAgLy8gUmVwbGFjZSBidXR0b24gY29udGVudHMgd2l0aCBTdG9wIGljb24gKyBzcGlubmVyIHJpbmcuXG4gICAgICB0aGlzLnNlbmRCdG4uZW1wdHkoKTtcbiAgICAgIGNvbnN0IHdyYXAgPSB0aGlzLnNlbmRCdG4uY3JlYXRlRGl2KHsgY2xzOiAnb2NsYXctc3RvcC13cmFwJyB9KTtcbiAgICAgIHdyYXAuY3JlYXRlRGl2KHsgY2xzOiAnb2NsYXctc3Bpbm5lci1yaW5nJywgYXR0cjogeyAnYXJpYS1oaWRkZW4nOiAndHJ1ZScgfSB9KTtcbiAgICAgIHdyYXAuY3JlYXRlRGl2KHsgY2xzOiAnb2NsYXctc3RvcC1pY29uJywgYXR0cjogeyAnYXJpYS1oaWRkZW4nOiAndHJ1ZScgfSB9KTtcbiAgICB9IGVsc2Uge1xuICAgICAgLy8gUmVzdG9yZSBsYWJlbFxuICAgICAgdGhpcy5zZW5kQnRuLnNldFRleHQoJ1NlbmQnKTtcbiAgICB9XG4gIH1cblxuICAvLyBcdTI1MDBcdTI1MDAgU2VuZCBoYW5kbGVyIFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFxuXG4gIHByaXZhdGUgYXN5bmMgX2hhbmRsZVNlbmQoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgLy8gV2hpbGUgd29ya2luZywgdGhlIGJ1dHRvbiBiZWNvbWVzIFN0b3AuXG4gICAgaWYgKHRoaXMuaXNXb3JraW5nKSB7XG4gICAgICBjb25zdCBvayA9IGF3YWl0IHRoaXMud3NDbGllbnQuYWJvcnRBY3RpdmVSdW4oKTtcbiAgICAgIGlmICghb2spIHtcbiAgICAgICAgbmV3IE5vdGljZSgnT3BlbkNsYXcgQ2hhdDogZmFpbGVkIHRvIHN0b3AnKTtcbiAgICAgICAgdGhpcy5jaGF0TWFuYWdlci5hZGRNZXNzYWdlKENoYXRNYW5hZ2VyLmNyZWF0ZVN5c3RlbU1lc3NhZ2UoJ1x1MjZBMCBTdG9wIGZhaWxlZCcsICdlcnJvcicpKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHRoaXMuY2hhdE1hbmFnZXIuYWRkTWVzc2FnZShDaGF0TWFuYWdlci5jcmVhdGVTeXN0ZW1NZXNzYWdlKCdcdTI2RDQgU3RvcHBlZCcsICdpbmZvJykpO1xuICAgICAgfVxuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIGNvbnN0IHRleHQgPSB0aGlzLmlucHV0RWwudmFsdWUudHJpbSgpO1xuICAgIGlmICghdGV4dCkgcmV0dXJuO1xuXG4gICAgLy8gQnVpbGQgbWVzc2FnZSB3aXRoIGNvbnRleHQgaWYgZW5hYmxlZFxuICAgIGxldCBtZXNzYWdlID0gdGV4dDtcbiAgICBpZiAodGhpcy5pbmNsdWRlTm90ZUNoZWNrYm94LmNoZWNrZWQpIHtcbiAgICAgIGNvbnN0IG5vdGUgPSBhd2FpdCBnZXRBY3RpdmVOb3RlQ29udGV4dCh0aGlzLmFwcCk7XG4gICAgICBpZiAobm90ZSkge1xuICAgICAgICBtZXNzYWdlID0gYENvbnRleHQ6IFtbJHtub3RlLnRpdGxlfV1dXFxuXFxuJHt0ZXh0fWA7XG4gICAgICB9XG4gICAgfVxuXG4gICAgLy8gQWRkIHVzZXIgbWVzc2FnZSB0byBjaGF0IFVJXG4gICAgY29uc3QgdXNlck1zZyA9IENoYXRNYW5hZ2VyLmNyZWF0ZVVzZXJNZXNzYWdlKHRleHQpO1xuICAgIHRoaXMuY2hhdE1hbmFnZXIuYWRkTWVzc2FnZSh1c2VyTXNnKTtcblxuICAgIC8vIENsZWFyIGlucHV0XG4gICAgdGhpcy5pbnB1dEVsLnZhbHVlID0gJyc7XG4gICAgdGhpcy5pbnB1dEVsLnN0eWxlLmhlaWdodCA9ICdhdXRvJztcblxuICAgIC8vIFNlbmQgb3ZlciBXUyAoYXN5bmMpXG4gICAgdHJ5IHtcbiAgICAgIGF3YWl0IHRoaXMud3NDbGllbnQuc2VuZE1lc3NhZ2UobWVzc2FnZSk7XG4gICAgfSBjYXRjaCAoZXJyKSB7XG4gICAgICBjb25zb2xlLmVycm9yKCdbb2NsYXddIFNlbmQgZmFpbGVkJywgZXJyKTtcbiAgICAgIG5ldyBOb3RpY2UoYE9wZW5DbGF3IENoYXQ6IHNlbmQgZmFpbGVkICgke1N0cmluZyhlcnIpfSlgKTtcbiAgICAgIHRoaXMuY2hhdE1hbmFnZXIuYWRkTWVzc2FnZShcbiAgICAgICAgQ2hhdE1hbmFnZXIuY3JlYXRlU3lzdGVtTWVzc2FnZShgXHUyNkEwIFNlbmQgZmFpbGVkOiAke2Vycn1gLCAnZXJyb3InKVxuICAgICAgKTtcbiAgICB9XG4gIH1cbn1cbiIsICJpbXBvcnQgdHlwZSB7IENoYXRNZXNzYWdlIH0gZnJvbSAnLi90eXBlcyc7XG5cbi8qKiBNYW5hZ2VzIHRoZSBpbi1tZW1vcnkgbGlzdCBvZiBjaGF0IG1lc3NhZ2VzIGFuZCBub3RpZmllcyBVSSBvbiBjaGFuZ2VzICovXG5leHBvcnQgY2xhc3MgQ2hhdE1hbmFnZXIge1xuICBwcml2YXRlIG1lc3NhZ2VzOiBDaGF0TWVzc2FnZVtdID0gW107XG5cbiAgLyoqIEZpcmVkIGZvciBhIGZ1bGwgcmUtcmVuZGVyIChjbGVhci9yZWxvYWQpICovXG4gIG9uVXBkYXRlOiAoKG1lc3NhZ2VzOiByZWFkb25seSBDaGF0TWVzc2FnZVtdKSA9PiB2b2lkKSB8IG51bGwgPSBudWxsO1xuICAvKiogRmlyZWQgd2hlbiBhIHNpbmdsZSBtZXNzYWdlIGlzIGFwcGVuZGVkIFx1MjAxNCB1c2UgZm9yIE8oMSkgYXBwZW5kLW9ubHkgVUkgKi9cbiAgb25NZXNzYWdlQWRkZWQ6ICgobXNnOiBDaGF0TWVzc2FnZSkgPT4gdm9pZCkgfCBudWxsID0gbnVsbDtcblxuICBhZGRNZXNzYWdlKG1zZzogQ2hhdE1lc3NhZ2UpOiB2b2lkIHtcbiAgICB0aGlzLm1lc3NhZ2VzLnB1c2gobXNnKTtcbiAgICB0aGlzLm9uTWVzc2FnZUFkZGVkPy4obXNnKTtcbiAgfVxuXG4gIGdldE1lc3NhZ2VzKCk6IHJlYWRvbmx5IENoYXRNZXNzYWdlW10ge1xuICAgIHJldHVybiB0aGlzLm1lc3NhZ2VzO1xuICB9XG5cbiAgY2xlYXIoKTogdm9pZCB7XG4gICAgdGhpcy5tZXNzYWdlcyA9IFtdO1xuICAgIHRoaXMub25VcGRhdGU/LihbXSk7XG4gIH1cblxuICAvKiogQ3JlYXRlIGEgdXNlciBtZXNzYWdlIG9iamVjdCAod2l0aG91dCBhZGRpbmcgaXQpICovXG4gIHN0YXRpYyBjcmVhdGVVc2VyTWVzc2FnZShjb250ZW50OiBzdHJpbmcpOiBDaGF0TWVzc2FnZSB7XG4gICAgcmV0dXJuIHtcbiAgICAgIGlkOiBgbXNnLSR7RGF0ZS5ub3coKX0tJHtNYXRoLnJhbmRvbSgpLnRvU3RyaW5nKDM2KS5zbGljZSgyLCA3KX1gLFxuICAgICAgcm9sZTogJ3VzZXInLFxuICAgICAgY29udGVudCxcbiAgICAgIHRpbWVzdGFtcDogRGF0ZS5ub3coKSxcbiAgICB9O1xuICB9XG5cbiAgLyoqIENyZWF0ZSBhbiBhc3Npc3RhbnQgbWVzc2FnZSBvYmplY3QgKHdpdGhvdXQgYWRkaW5nIGl0KSAqL1xuICBzdGF0aWMgY3JlYXRlQXNzaXN0YW50TWVzc2FnZShjb250ZW50OiBzdHJpbmcpOiBDaGF0TWVzc2FnZSB7XG4gICAgcmV0dXJuIHtcbiAgICAgIGlkOiBgbXNnLSR7RGF0ZS5ub3coKX0tJHtNYXRoLnJhbmRvbSgpLnRvU3RyaW5nKDM2KS5zbGljZSgyLCA3KX1gLFxuICAgICAgcm9sZTogJ2Fzc2lzdGFudCcsXG4gICAgICBjb250ZW50LFxuICAgICAgdGltZXN0YW1wOiBEYXRlLm5vdygpLFxuICAgIH07XG4gIH1cblxuICAvKiogQ3JlYXRlIGEgc3lzdGVtIC8gc3RhdHVzIG1lc3NhZ2UgKGVycm9ycywgcmVjb25uZWN0IG5vdGljZXMsIGV0Yy4pICovXG4gIHN0YXRpYyBjcmVhdGVTeXN0ZW1NZXNzYWdlKGNvbnRlbnQ6IHN0cmluZywgbGV2ZWw6IENoYXRNZXNzYWdlWydsZXZlbCddID0gJ2luZm8nKTogQ2hhdE1lc3NhZ2Uge1xuICAgIHJldHVybiB7XG4gICAgICBpZDogYHN5cy0ke0RhdGUubm93KCl9YCxcbiAgICAgIHJvbGU6ICdzeXN0ZW0nLFxuICAgICAgbGV2ZWwsXG4gICAgICBjb250ZW50LFxuICAgICAgdGltZXN0YW1wOiBEYXRlLm5vdygpLFxuICAgIH07XG4gIH1cblxuICBzdGF0aWMgY3JlYXRlU2Vzc2lvbkRpdmlkZXIoc2Vzc2lvbktleTogc3RyaW5nKTogQ2hhdE1lc3NhZ2Uge1xuICAgIGNvbnN0IHNob3J0ID0gc2Vzc2lvbktleS5sZW5ndGggPiAyOCA/IGAke3Nlc3Npb25LZXkuc2xpY2UoMCwgMTIpfVx1MjAyNiR7c2Vzc2lvbktleS5zbGljZSgtMTIpfWAgOiBzZXNzaW9uS2V5O1xuICAgIHJldHVybiB7XG4gICAgICBpZDogYGRpdi0ke0RhdGUubm93KCl9YCxcbiAgICAgIHJvbGU6ICdzeXN0ZW0nLFxuICAgICAgbGV2ZWw6ICdpbmZvJyxcbiAgICAgIGtpbmQ6ICdzZXNzaW9uLWRpdmlkZXInLFxuICAgICAgdGl0bGU6IHNlc3Npb25LZXksXG4gICAgICBjb250ZW50OiBgW1Nlc3Npb246ICR7c2hvcnR9XWAsXG4gICAgICB0aW1lc3RhbXA6IERhdGUubm93KCksXG4gICAgfTtcbiAgfVxufVxuIiwgImltcG9ydCB0eXBlIHsgUGF0aE1hcHBpbmcgfSBmcm9tICcuL3R5cGVzJztcblxuZXhwb3J0IGZ1bmN0aW9uIG5vcm1hbGl6ZUJhc2UoYmFzZTogc3RyaW5nKTogc3RyaW5nIHtcbiAgY29uc3QgdHJpbW1lZCA9IFN0cmluZyhiYXNlID8/ICcnKS50cmltKCk7XG4gIGlmICghdHJpbW1lZCkgcmV0dXJuICcnO1xuICByZXR1cm4gdHJpbW1lZC5lbmRzV2l0aCgnLycpID8gdHJpbW1lZCA6IGAke3RyaW1tZWR9L2A7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiB0cnlNYXBSZW1vdGVQYXRoVG9WYXVsdFBhdGgoaW5wdXQ6IHN0cmluZywgbWFwcGluZ3M6IHJlYWRvbmx5IFBhdGhNYXBwaW5nW10pOiBzdHJpbmcgfCBudWxsIHtcbiAgY29uc3QgcmF3ID0gU3RyaW5nKGlucHV0ID8/ICcnKTtcbiAgZm9yIChjb25zdCByb3cgb2YgbWFwcGluZ3MpIHtcbiAgICBjb25zdCByZW1vdGVCYXNlID0gbm9ybWFsaXplQmFzZShyb3cucmVtb3RlQmFzZSk7XG4gICAgY29uc3QgdmF1bHRCYXNlID0gbm9ybWFsaXplQmFzZShyb3cudmF1bHRCYXNlKTtcbiAgICBpZiAoIXJlbW90ZUJhc2UgfHwgIXZhdWx0QmFzZSkgY29udGludWU7XG5cbiAgICBpZiAocmF3LnN0YXJ0c1dpdGgocmVtb3RlQmFzZSkpIHtcbiAgICAgIGNvbnN0IHJlc3QgPSByYXcuc2xpY2UocmVtb3RlQmFzZS5sZW5ndGgpO1xuICAgICAgLy8gT2JzaWRpYW4gcGF0aHMgYXJlIHZhdWx0LXJlbGF0aXZlIGFuZCBzaG91bGQgbm90IHN0YXJ0IHdpdGggJy8nXG4gICAgICByZXR1cm4gYCR7dmF1bHRCYXNlfSR7cmVzdH1gLnJlcGxhY2UoL15cXC8rLywgJycpO1xuICAgIH1cbiAgfVxuICByZXR1cm4gbnVsbDtcbn1cblxuZXhwb3J0IHR5cGUgQ2FuZGlkYXRlID0geyBzdGFydDogbnVtYmVyOyBlbmQ6IG51bWJlcjsgcmF3OiBzdHJpbmc7IGtpbmQ6ICd1cmwnIHwgJ3BhdGgnIH07XG5cbi8vIENvbnNlcnZhdGl2ZSBleHRyYWN0aW9uOiBhaW0gdG8gYXZvaWQgZmFsc2UgcG9zaXRpdmVzLlxuY29uc3QgVVJMX1JFID0gL2h0dHBzPzpcXC9cXC9bXlxcczw+KCldKy9nO1xuLy8gQWJzb2x1dGUgdW5peC1pc2ggcGF0aHMuXG4vLyAoV2Ugc3RpbGwgZXhpc3RlbmNlLWNoZWNrIGJlZm9yZSBwcm9kdWNpbmcgYSBsaW5rLilcbmNvbnN0IFBBVEhfUkUgPSAvKD88IVtBLVphLXowLTkuXy1dKSg/OlxcL1tBLVphLXowLTkuX34hJCYnKCkqKyw7PTpAJVxcLV0rKSsoPzpcXC5bQS1aYS16MC05Ll8tXSspPy9nO1xuXG4vLyBDb25zZXJ2YXRpdmUgcmVsYXRpdmUgcGF0aHMgd2l0aCBhdCBsZWFzdCBvbmUgJy8nLCBlLmcuIGNvbXBlbmcvcGxhbnMveC5tZFxuLy8gQXZvaWRzIG1hdGNoaW5nIHNjaGVtZS1saWtlIHRva2VucyB2aWEgbmVnYXRpdmUgbG9va2FoZWFkIGZvciAnOi8vJy5cbmNvbnN0IFJFTF9QQVRIX1JFID0gL1xcYig/IVtBLVphLXpdW0EtWmEtejAtOSsuLV0qOlxcL1xcLylbQS1aYS16MC05Ll8tXSsoPzpcXC9bQS1aYS16MC05Ll8tXSspKyg/OlxcLltBLVphLXowLTkuXy1dKyk/XFxiL2c7XG5cbmV4cG9ydCBmdW5jdGlvbiBleHRyYWN0Q2FuZGlkYXRlcyh0ZXh0OiBzdHJpbmcpOiBDYW5kaWRhdGVbXSB7XG4gIGNvbnN0IHQgPSBTdHJpbmcodGV4dCA/PyAnJyk7XG4gIGNvbnN0IG91dDogQ2FuZGlkYXRlW10gPSBbXTtcblxuICBmb3IgKGNvbnN0IG0gb2YgdC5tYXRjaEFsbChVUkxfUkUpKSB7XG4gICAgaWYgKG0uaW5kZXggPT09IHVuZGVmaW5lZCkgY29udGludWU7XG4gICAgb3V0LnB1c2goeyBzdGFydDogbS5pbmRleCwgZW5kOiBtLmluZGV4ICsgbVswXS5sZW5ndGgsIHJhdzogbVswXSwga2luZDogJ3VybCcgfSk7XG4gIH1cblxuICBmb3IgKGNvbnN0IG0gb2YgdC5tYXRjaEFsbChQQVRIX1JFKSkge1xuICAgIGlmIChtLmluZGV4ID09PSB1bmRlZmluZWQpIGNvbnRpbnVlO1xuXG4gICAgLy8gU2tpcCBpZiB0aGlzIGlzIGluc2lkZSBhIFVSTCB3ZSBhbHJlYWR5IGNhcHR1cmVkLlxuICAgIGNvbnN0IHN0YXJ0ID0gbS5pbmRleDtcbiAgICBjb25zdCBlbmQgPSBzdGFydCArIG1bMF0ubGVuZ3RoO1xuICAgIGNvbnN0IG92ZXJsYXBzVXJsID0gb3V0LnNvbWUoKGMpID0+IGMua2luZCA9PT0gJ3VybCcgJiYgIShlbmQgPD0gYy5zdGFydCB8fCBzdGFydCA+PSBjLmVuZCkpO1xuICAgIGlmIChvdmVybGFwc1VybCkgY29udGludWU7XG5cbiAgICBvdXQucHVzaCh7IHN0YXJ0LCBlbmQsIHJhdzogbVswXSwga2luZDogJ3BhdGgnIH0pO1xuICB9XG5cbiAgZm9yIChjb25zdCBtIG9mIHQubWF0Y2hBbGwoUkVMX1BBVEhfUkUpKSB7XG4gICAgaWYgKG0uaW5kZXggPT09IHVuZGVmaW5lZCkgY29udGludWU7XG5cbiAgICBjb25zdCBzdGFydCA9IG0uaW5kZXg7XG4gICAgY29uc3QgZW5kID0gc3RhcnQgKyBtWzBdLmxlbmd0aDtcbiAgICBjb25zdCBvdmVybGFwc0V4aXN0aW5nID0gb3V0LnNvbWUoKGMpID0+ICEoZW5kIDw9IGMuc3RhcnQgfHwgc3RhcnQgPj0gYy5lbmQpKTtcbiAgICBpZiAob3ZlcmxhcHNFeGlzdGluZykgY29udGludWU7XG5cbiAgICBvdXQucHVzaCh7IHN0YXJ0LCBlbmQsIHJhdzogbVswXSwga2luZDogJ3BhdGgnIH0pO1xuICB9XG5cbiAgLy8gU29ydCBhbmQgZHJvcCBvdmVybGFwcyAocHJlZmVyIFVSTHMpLlxuICBvdXQuc29ydCgoYSwgYikgPT4gYS5zdGFydCAtIGIuc3RhcnQgfHwgKGEua2luZCA9PT0gJ3VybCcgPyAtMSA6IDEpKTtcbiAgY29uc3QgZGVkdXA6IENhbmRpZGF0ZVtdID0gW107XG4gIGZvciAoY29uc3QgYyBvZiBvdXQpIHtcbiAgICBjb25zdCBsYXN0ID0gZGVkdXBbZGVkdXAubGVuZ3RoIC0gMV07XG4gICAgaWYgKCFsYXN0KSB7XG4gICAgICBkZWR1cC5wdXNoKGMpO1xuICAgICAgY29udGludWU7XG4gICAgfVxuICAgIGlmIChjLnN0YXJ0IDwgbGFzdC5lbmQpIGNvbnRpbnVlO1xuICAgIGRlZHVwLnB1c2goYyk7XG4gIH1cblxuICByZXR1cm4gZGVkdXA7XG59XG4iLCAiaW1wb3J0IHR5cGUgeyBBcHAgfSBmcm9tICdvYnNpZGlhbic7XG5cbmV4cG9ydCBpbnRlcmZhY2UgTm90ZUNvbnRleHQge1xuICB0aXRsZTogc3RyaW5nO1xuICBwYXRoOiBzdHJpbmc7XG4gIGNvbnRlbnQ6IHN0cmluZztcbn1cblxuLyoqXG4gKiBSZXR1cm5zIHRoZSBhY3RpdmUgbm90ZSdzIHRpdGxlIGFuZCBjb250ZW50LCBvciBudWxsIGlmIG5vIG5vdGUgaXMgb3Blbi5cbiAqIEFzeW5jIGJlY2F1c2UgdmF1bHQucmVhZCgpIGlzIGFzeW5jLlxuICovXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZ2V0QWN0aXZlTm90ZUNvbnRleHQoYXBwOiBBcHApOiBQcm9taXNlPE5vdGVDb250ZXh0IHwgbnVsbD4ge1xuICBjb25zdCBmaWxlID0gYXBwLndvcmtzcGFjZS5nZXRBY3RpdmVGaWxlKCk7XG4gIGlmICghZmlsZSkgcmV0dXJuIG51bGw7XG5cbiAgdHJ5IHtcbiAgICBjb25zdCBjb250ZW50ID0gYXdhaXQgYXBwLnZhdWx0LnJlYWQoZmlsZSk7XG4gICAgcmV0dXJuIHtcbiAgICAgIHRpdGxlOiBmaWxlLmJhc2VuYW1lLFxuICAgICAgcGF0aDogZmlsZS5wYXRoLFxuICAgICAgY29udGVudCxcbiAgICB9O1xuICB9IGNhdGNoIChlcnIpIHtcbiAgICBjb25zb2xlLmVycm9yKCdbb2NsYXctY29udGV4dF0gRmFpbGVkIHRvIHJlYWQgYWN0aXZlIG5vdGUnLCBlcnIpO1xuICAgIHJldHVybiBudWxsO1xuICB9XG59XG4iLCAiLyoqIFBlcnNpc3RlZCBwbHVnaW4gY29uZmlndXJhdGlvbiAqL1xuZXhwb3J0IGludGVyZmFjZSBPcGVuQ2xhd1NldHRpbmdzIHtcbiAgLyoqIFdlYlNvY2tldCBVUkwgb2YgdGhlIE9wZW5DbGF3IEdhdGV3YXkgKGUuZy4gd3M6Ly8xMDAuOTAuOS42ODoxODc4OSkgKi9cbiAgZ2F0ZXdheVVybDogc3RyaW5nO1xuICAvKiogQXV0aCB0b2tlbiBcdTIwMTQgbXVzdCBtYXRjaCB0aGUgY2hhbm5lbCBwbHVnaW4ncyBhdXRoVG9rZW4gKi9cbiAgYXV0aFRva2VuOiBzdHJpbmc7XG4gIC8qKiBPcGVuQ2xhdyBzZXNzaW9uIGtleSB0byBzdWJzY3JpYmUgdG8gKGUuZy4gXCJtYWluXCIpICovXG4gIHNlc3Npb25LZXk6IHN0cmluZztcbiAgLyoqIChEZXByZWNhdGVkKSBPcGVuQ2xhdyBhY2NvdW50IElEICh1bnVzZWQ7IGNoYXQuc2VuZCB1c2VzIHNlc3Npb25LZXkpICovXG4gIGFjY291bnRJZDogc3RyaW5nO1xuICAvKiogV2hldGhlciB0byBpbmNsdWRlIHRoZSBhY3RpdmUgbm90ZSBjb250ZW50IHdpdGggZWFjaCBtZXNzYWdlICovXG4gIGluY2x1ZGVBY3RpdmVOb3RlOiBib29sZWFuO1xuICAvKiogUmVuZGVyIGFzc2lzdGFudCBvdXRwdXQgYXMgTWFya2Rvd24gKHVuc2FmZTogbWF5IHRyaWdnZXIgZW1iZWRzL3Bvc3QtcHJvY2Vzc29ycyk7IGRlZmF1bHQgT0ZGICovXG4gIHJlbmRlckFzc2lzdGFudE1hcmtkb3duOiBib29sZWFuO1xuICAvKiogQWxsb3cgdXNpbmcgaW5zZWN1cmUgd3M6Ly8gZm9yIG5vbi1sb2NhbCBnYXRld2F5IFVSTHMgKHVuc2FmZSk7IGRlZmF1bHQgT0ZGICovXG4gIGFsbG93SW5zZWN1cmVXczogYm9vbGVhbjtcblxuICAvKiogT3B0aW9uYWw6IG1hcCByZW1vdGUgRlMgcGF0aHMgLyBleHBvcnRlZCBwYXRocyBiYWNrIHRvIHZhdWx0LXJlbGF0aXZlIHBhdGhzICovXG4gIHBhdGhNYXBwaW5nczogUGF0aE1hcHBpbmdbXTtcblxuICAvKiogVmF1bHQgaWRlbnRpdHkgKGhhc2gpIHVzZWQgZm9yIGNhbm9uaWNhbCBzZXNzaW9uIGtleXMuICovXG4gIHZhdWx0SGFzaD86IHN0cmluZztcblxuICAvKiogS25vd24gT2JzaWRpYW4gc2Vzc2lvbiBrZXlzIGZvciBlYWNoIHZhdWx0SGFzaCAodmF1bHQtc2NvcGVkIGNvbnRpbnVpdHkpLiAqL1xuICBrbm93blNlc3Npb25LZXlzQnlWYXVsdD86IFJlY29yZDxzdHJpbmcsIHN0cmluZ1tdPjtcblxuICAvKiogTGVnYWN5IGtleXMga2VwdCBmb3IgbWlncmF0aW9uL2RlYnVnIChvcHRpb25hbCkuICovXG4gIGxlZ2FjeVNlc3Npb25LZXlzPzogc3RyaW5nW107XG59XG5cbmV4cG9ydCB0eXBlIFBhdGhNYXBwaW5nID0ge1xuICAvKiogVmF1bHQtcmVsYXRpdmUgYmFzZSBwYXRoIChlLmcuIFwiZG9jcy9cIiBvciBcImNvbXBlbmcvXCIpICovXG4gIHZhdWx0QmFzZTogc3RyaW5nO1xuICAvKiogUmVtb3RlIEZTIGJhc2UgcGF0aCAoZS5nLiBcIi9ob21lL3dhbGwtZS8ub3BlbmNsYXcvd29ya3NwYWNlL2RvY3MvXCIpICovXG4gIHJlbW90ZUJhc2U6IHN0cmluZztcbn07XG5cbmV4cG9ydCBjb25zdCBERUZBVUxUX1NFVFRJTkdTOiBPcGVuQ2xhd1NldHRpbmdzID0ge1xuICBnYXRld2F5VXJsOiAnd3M6Ly9sb2NhbGhvc3Q6MTg3ODknLFxuICBhdXRoVG9rZW46ICcnLFxuICBzZXNzaW9uS2V5OiAnbWFpbicsXG4gIGFjY291bnRJZDogJ21haW4nLFxuICBpbmNsdWRlQWN0aXZlTm90ZTogZmFsc2UsXG4gIHJlbmRlckFzc2lzdGFudE1hcmtkb3duOiBmYWxzZSxcbiAgYWxsb3dJbnNlY3VyZVdzOiBmYWxzZSxcbiAgcGF0aE1hcHBpbmdzOiBbXSxcbiAgdmF1bHRIYXNoOiB1bmRlZmluZWQsXG4gIGtub3duU2Vzc2lvbktleXNCeVZhdWx0OiB7fSxcbiAgbGVnYWN5U2Vzc2lvbktleXM6IFtdLFxufTtcblxuLyoqIEEgc2luZ2xlIGNoYXQgbWVzc2FnZSAqL1xuZXhwb3J0IGludGVyZmFjZSBDaGF0TWVzc2FnZSB7XG4gIGlkOiBzdHJpbmc7XG4gIHJvbGU6ICd1c2VyJyB8ICdhc3Npc3RhbnQnIHwgJ3N5c3RlbSc7XG4gIC8qKiBPcHRpb25hbCBzZXZlcml0eSBmb3Igc3lzdGVtL3N0YXR1cyBtZXNzYWdlcyAqL1xuICBsZXZlbD86ICdpbmZvJyB8ICdlcnJvcic7XG4gIC8qKiBPcHRpb25hbCBzdWJ0eXBlIGZvciBzdHlsaW5nIHNwZWNpYWwgc3lzdGVtIG1lc3NhZ2VzIChlLmcuIHNlc3Npb24gZGl2aWRlcikuICovXG4gIGtpbmQ/OiAnc2Vzc2lvbi1kaXZpZGVyJztcbiAgLyoqIE9wdGlvbmFsIGhvdmVyIHRvb2x0aXAgZm9yIHRoZSBtZXNzYWdlIChlLmcuIGZ1bGwgc2Vzc2lvbiBrZXkpLiAqL1xuICB0aXRsZT86IHN0cmluZztcbiAgY29udGVudDogc3RyaW5nO1xuICB0aW1lc3RhbXA6IG51bWJlcjtcbn1cblxuLyoqIFBheWxvYWQgZm9yIG1lc3NhZ2VzIFNFTlQgdG8gdGhlIHNlcnZlciAob3V0Ym91bmQpICovXG5leHBvcnQgaW50ZXJmYWNlIFdTUGF5bG9hZCB7XG4gIHR5cGU6ICdhdXRoJyB8ICdtZXNzYWdlJyB8ICdwaW5nJyB8ICdwb25nJyB8ICdlcnJvcic7XG4gIHBheWxvYWQ/OiBSZWNvcmQ8c3RyaW5nLCB1bmtub3duPjtcbn1cblxuLyoqIE1lc3NhZ2VzIFJFQ0VJVkVEIGZyb20gdGhlIHNlcnZlciAoaW5ib3VuZCkgXHUyMDE0IGRpc2NyaW1pbmF0ZWQgdW5pb24gKi9cbmV4cG9ydCB0eXBlIEluYm91bmRXU1BheWxvYWQgPVxuICB8IHsgdHlwZTogJ21lc3NhZ2UnOyBwYXlsb2FkOiB7IGNvbnRlbnQ6IHN0cmluZzsgcm9sZTogc3RyaW5nOyB0aW1lc3RhbXA6IG51bWJlciB9IH1cbiAgfCB7IHR5cGU6ICdlcnJvcic7IHBheWxvYWQ6IHsgbWVzc2FnZTogc3RyaW5nIH0gfTtcblxuLyoqIEF2YWlsYWJsZSBhZ2VudHMgLyBtb2RlbHMgKi9cbmV4cG9ydCBpbnRlcmZhY2UgQWdlbnRPcHRpb24ge1xuICBpZDogc3RyaW5nO1xuICBsYWJlbDogc3RyaW5nO1xufVxuIiwgImltcG9ydCB0eXBlIHsgT3BlbkNsYXdTZXR0aW5ncyB9IGZyb20gJy4vdHlwZXMnO1xuXG5leHBvcnQgZnVuY3Rpb24gY2Fub25pY2FsVmF1bHRTZXNzaW9uS2V5KHZhdWx0SGFzaDogc3RyaW5nKTogc3RyaW5nIHtcbiAgcmV0dXJuIGBhZ2VudDptYWluOm9ic2lkaWFuOmRpcmVjdDoke3ZhdWx0SGFzaH1gO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gaXNBbGxvd2VkT2JzaWRpYW5TZXNzaW9uS2V5KHBhcmFtczoge1xuICBrZXk6IHN0cmluZztcbiAgdmF1bHRIYXNoOiBzdHJpbmcgfCBudWxsO1xufSk6IGJvb2xlYW4ge1xuICBjb25zdCBrZXkgPSAocGFyYW1zLmtleSA/PyAnJykudHJpbSgpLnRvTG93ZXJDYXNlKCk7XG4gIGlmICgha2V5KSByZXR1cm4gZmFsc2U7XG4gIGlmIChrZXkgPT09ICdtYWluJykgcmV0dXJuIHRydWU7XG5cbiAgY29uc3QgdmF1bHRIYXNoID0gKHBhcmFtcy52YXVsdEhhc2ggPz8gJycpLnRyaW0oKS50b0xvd2VyQ2FzZSgpO1xuICBpZiAoIXZhdWx0SGFzaCkge1xuICAgIC8vIFdpdGhvdXQgYSB2YXVsdCBpZGVudGl0eSwgd2Ugb25seSBhbGxvdyBtYWluLlxuICAgIHJldHVybiBmYWxzZTtcbiAgfVxuXG4gIGNvbnN0IHByZWZpeCA9IGBhZ2VudDptYWluOm9ic2lkaWFuOmRpcmVjdDoke3ZhdWx0SGFzaH1gO1xuICBpZiAoa2V5ID09PSBwcmVmaXgpIHJldHVybiB0cnVlO1xuICBpZiAoa2V5LnN0YXJ0c1dpdGgocHJlZml4ICsgJy0nKSkgcmV0dXJuIHRydWU7XG4gIHJldHVybiBmYWxzZTtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIG1pZ3JhdGVTZXR0aW5nc0ZvclZhdWx0KHNldHRpbmdzOiBPcGVuQ2xhd1NldHRpbmdzLCB2YXVsdEhhc2g6IHN0cmluZyk6IHtcbiAgbmV4dFNldHRpbmdzOiBPcGVuQ2xhd1NldHRpbmdzO1xuICBjYW5vbmljYWxLZXk6IHN0cmluZztcbn0ge1xuICBjb25zdCBjYW5vbmljYWxLZXkgPSBjYW5vbmljYWxWYXVsdFNlc3Npb25LZXkodmF1bHRIYXNoKTtcbiAgY29uc3QgZXhpc3RpbmcgPSAoc2V0dGluZ3Muc2Vzc2lvbktleSA/PyAnJykudHJpbSgpLnRvTG93ZXJDYXNlKCk7XG4gIGNvbnN0IGlzTGVnYWN5ID0gZXhpc3Rpbmcuc3RhcnRzV2l0aCgnb2JzaWRpYW4tJyk7XG4gIGNvbnN0IGlzRW1wdHlPck1haW4gPSAhZXhpc3RpbmcgfHwgZXhpc3RpbmcgPT09ICdtYWluJyB8fCBleGlzdGluZyA9PT0gJ2FnZW50Om1haW46bWFpbic7XG5cbiAgY29uc3QgbmV4dDogT3BlbkNsYXdTZXR0aW5ncyA9IHsgLi4uc2V0dGluZ3MgfTtcbiAgbmV4dC52YXVsdEhhc2ggPSB2YXVsdEhhc2g7XG5cbiAgaWYgKGlzTGVnYWN5KSB7XG4gICAgY29uc3QgbGVnYWN5ID0gQXJyYXkuaXNBcnJheShuZXh0LmxlZ2FjeVNlc3Npb25LZXlzKSA/IG5leHQubGVnYWN5U2Vzc2lvbktleXMgOiBbXTtcbiAgICBuZXh0LmxlZ2FjeVNlc3Npb25LZXlzID0gW2V4aXN0aW5nLCAuLi5sZWdhY3kuZmlsdGVyKChrKSA9PiBrICYmIGsgIT09IGV4aXN0aW5nKV0uc2xpY2UoMCwgMjApO1xuICB9XG5cbiAgaWYgKGlzTGVnYWN5IHx8IGlzRW1wdHlPck1haW4pIHtcbiAgICBuZXh0LnNlc3Npb25LZXkgPSBjYW5vbmljYWxLZXk7XG4gIH1cblxuICBjb25zdCBtYXAgPSBuZXh0Lmtub3duU2Vzc2lvbktleXNCeVZhdWx0ID8/IHt9O1xuICBjb25zdCBjdXIgPSBBcnJheS5pc0FycmF5KG1hcFt2YXVsdEhhc2hdKSA/IG1hcFt2YXVsdEhhc2hdIDogW107XG4gIGlmICghY3VyLmluY2x1ZGVzKGNhbm9uaWNhbEtleSkpIHtcbiAgICBtYXBbdmF1bHRIYXNoXSA9IFtjYW5vbmljYWxLZXksIC4uLmN1cl0uc2xpY2UoMCwgMjApO1xuICAgIG5leHQua25vd25TZXNzaW9uS2V5c0J5VmF1bHQgPSBtYXA7XG4gIH1cblxuICByZXR1cm4geyBuZXh0U2V0dGluZ3M6IG5leHQsIGNhbm9uaWNhbEtleSB9O1xufVxuIl0sCiAgIm1hcHBpbmdzIjogIjs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBLElBQUFBLG1CQUFpRTs7O0FDQWpFLHNCQUErQztBQUd4QyxJQUFNLHFCQUFOLGNBQWlDLGlDQUFpQjtBQUFBLEVBR3ZELFlBQVksS0FBVSxRQUF3QjtBQUM1QyxVQUFNLEtBQUssTUFBTTtBQUNqQixTQUFLLFNBQVM7QUFBQSxFQUNoQjtBQUFBLEVBRUEsVUFBZ0I7QUFYbEI7QUFZSSxVQUFNLEVBQUUsWUFBWSxJQUFJO0FBQ3hCLGdCQUFZLE1BQU07QUFFbEIsZ0JBQVksU0FBUyxNQUFNLEVBQUUsTUFBTSxnQ0FBMkIsQ0FBQztBQUUvRCxRQUFJLHdCQUFRLFdBQVcsRUFDcEIsUUFBUSxhQUFhLEVBQ3JCLFFBQVEsbUVBQW1FLEVBQzNFO0FBQUEsTUFBUSxDQUFDLFNBQ1IsS0FDRyxlQUFlLHNCQUFzQixFQUNyQyxTQUFT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
