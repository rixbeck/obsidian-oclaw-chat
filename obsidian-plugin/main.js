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
        (_a = this.messagesEl) == null ? void 0 : _a.removeEventListener("click", this.onMessagesClick, true);
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
      var _a, _b, _c;
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
      ev.preventDefault();
      ev.stopPropagation();
      if (f instanceof import_obsidian2.TFile) {
        void this.app.workspace.getLeaf(true).openFile(f);
        return;
      }
      void this.app.workspace.openLinkText(vaultPath, (_c = (_b = this.app.workspace.getActiveFile()) == null ? void 0 : _b.path) != null ? _c : "", true);
    };
    this.messagesEl.addEventListener("click", this.onMessagesClick, true);
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
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsic3JjL21haW4udHMiLCAic3JjL3NldHRpbmdzLnRzIiwgInNyYy93ZWJzb2NrZXQudHMiLCAic3JjL3ZpZXcudHMiLCAic3JjL2NoYXQudHMiLCAic3JjL2xpbmtpZnkudHMiLCAic3JjL2NvbnRleHQudHMiLCAic3JjL3R5cGVzLnRzIiwgInNyYy9zZXNzaW9uLnRzIl0sCiAgInNvdXJjZXNDb250ZW50IjogWyJpbXBvcnQgeyBGaWxlU3lzdGVtQWRhcHRlciwgTm90aWNlLCBQbHVnaW4sIFdvcmtzcGFjZUxlYWYgfSBmcm9tICdvYnNpZGlhbic7XG5pbXBvcnQgeyBPcGVuQ2xhd1NldHRpbmdUYWIgfSBmcm9tICcuL3NldHRpbmdzJztcbmltcG9ydCB7IE9ic2lkaWFuV1NDbGllbnQgfSBmcm9tICcuL3dlYnNvY2tldCc7XG5pbXBvcnQgeyBWSUVXX1RZUEVfT1BFTkNMQVdfQ0hBVCwgT3BlbkNsYXdDaGF0VmlldyB9IGZyb20gJy4vdmlldyc7XG5pbXBvcnQgeyBERUZBVUxUX1NFVFRJTkdTLCB0eXBlIE9wZW5DbGF3U2V0dGluZ3MgfSBmcm9tICcuL3R5cGVzJztcbmltcG9ydCB7IG1pZ3JhdGVTZXR0aW5nc0ZvclZhdWx0IH0gZnJvbSAnLi9zZXNzaW9uJztcblxuZXhwb3J0IGRlZmF1bHQgY2xhc3MgT3BlbkNsYXdQbHVnaW4gZXh0ZW5kcyBQbHVnaW4ge1xuICBzZXR0aW5ncyE6IE9wZW5DbGF3U2V0dGluZ3M7XG5cbiAgLy8gTk9URTogd3NDbGllbnQvY2hhdE1hbmFnZXIgYXJlIHBlci1sZWFmIChwZXIgdmlldykgdG8gYWxsb3cgcGFyYWxsZWwgc2Vzc2lvbnMuXG4gIHByaXZhdGUgb3BlbkNoYXRMZWF2ZXMgPSAwO1xuICBwcml2YXRlIGxhc3RMZWFmV2FybkF0TXMgPSAwO1xuICBwcml2YXRlIHN0YXRpYyBNQVhfQ0hBVF9MRUFWRVMgPSAzO1xuXG4gIHJlZ2lzdGVyQ2hhdExlYWYoKTogdm9pZCB7XG4gICAgdGhpcy5vcGVuQ2hhdExlYXZlcyArPSAxO1xuICAgIGNvbnN0IG5vdyA9IERhdGUubm93KCk7XG4gICAgaWYgKHRoaXMub3BlbkNoYXRMZWF2ZXMgPiBPcGVuQ2xhd1BsdWdpbi5NQVhfQ0hBVF9MRUFWRVMgJiYgbm93IC0gdGhpcy5sYXN0TGVhZldhcm5BdE1zID4gNjBfMDAwKSB7XG4gICAgICB0aGlzLmxhc3RMZWFmV2FybkF0TXMgPSBub3c7XG4gICAgICBuZXcgTm90aWNlKFxuICAgICAgICBgT3BlbkNsYXcgQ2hhdDogJHt0aGlzLm9wZW5DaGF0TGVhdmVzfSBjaGF0IHZpZXdzIGFyZSBvcGVuLiBUaGlzIG1heSBpbmNyZWFzZSBnYXRld2F5IGxvYWQuYFxuICAgICAgKTtcbiAgICB9XG4gIH1cblxuICB1bnJlZ2lzdGVyQ2hhdExlYWYoKTogdm9pZCB7XG4gICAgdGhpcy5vcGVuQ2hhdExlYXZlcyA9IE1hdGgubWF4KDAsIHRoaXMub3BlbkNoYXRMZWF2ZXMgLSAxKTtcbiAgfVxuXG4gIHByaXZhdGUgX3ZhdWx0SGFzaDogc3RyaW5nIHwgbnVsbCA9IG51bGw7XG5cbiAgcHJpdmF0ZSBfY29tcHV0ZVZhdWx0SGFzaCgpOiBzdHJpbmcgfCBudWxsIHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgYWRhcHRlciA9IHRoaXMuYXBwLnZhdWx0LmFkYXB0ZXI7XG4gICAgICAvLyBEZXNrdG9wIG9ubHk6IEZpbGVTeXN0ZW1BZGFwdGVyIHByb3ZpZGVzIGEgc3RhYmxlIGJhc2UgcGF0aC5cbiAgICAgIGlmIChhZGFwdGVyIGluc3RhbmNlb2YgRmlsZVN5c3RlbUFkYXB0ZXIpIHtcbiAgICAgICAgY29uc3QgYmFzZVBhdGggPSBhZGFwdGVyLmdldEJhc2VQYXRoKCk7XG4gICAgICAgIGlmIChiYXNlUGF0aCkge1xuICAgICAgICAgIC8vIFVzZSBOb2RlIGNyeXB0byAoRWxlY3Ryb24gZW52aXJvbm1lbnQpLlxuICAgICAgICAgIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBAdHlwZXNjcmlwdC1lc2xpbnQvbm8tdmFyLXJlcXVpcmVzXG4gICAgICAgICAgY29uc3QgY3J5cHRvID0gcmVxdWlyZSgnY3J5cHRvJykgYXMgdHlwZW9mIGltcG9ydCgnY3J5cHRvJyk7XG4gICAgICAgICAgY29uc3QgaGV4ID0gY3J5cHRvLmNyZWF0ZUhhc2goJ3NoYTI1NicpLnVwZGF0ZShiYXNlUGF0aCwgJ3V0ZjgnKS5kaWdlc3QoJ2hleCcpO1xuICAgICAgICAgIHJldHVybiBoZXguc2xpY2UoMCwgMTYpO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSBjYXRjaCB7XG4gICAgICAvLyBpZ25vcmVcbiAgICB9XG4gICAgcmV0dXJuIG51bGw7XG4gIH1cblxuICAvLyBjYW5vbmljYWwgc2Vzc2lvbiBrZXkgaGVscGVycyBsaXZlIGluIHNyYy9zZXNzaW9uLnRzXG5cbiAgZ2V0VmF1bHRIYXNoKCk6IHN0cmluZyB8IG51bGwge1xuICAgIHJldHVybiB0aGlzLl92YXVsdEhhc2g7XG4gIH1cblxuICBnZXREZWZhdWx0U2Vzc2lvbktleSgpOiBzdHJpbmcge1xuICAgIHJldHVybiAodGhpcy5zZXR0aW5ncy5zZXNzaW9uS2V5ID8/ICdtYWluJykudHJpbSgpLnRvTG93ZXJDYXNlKCk7XG4gIH1cblxuICBnZXRHYXRld2F5Q29uZmlnKCk6IHsgdXJsOiBzdHJpbmc7IHRva2VuOiBzdHJpbmc7IGFsbG93SW5zZWN1cmVXczogYm9vbGVhbiB9IHtcbiAgICByZXR1cm4ge1xuICAgICAgdXJsOiBTdHJpbmcodGhpcy5zZXR0aW5ncy5nYXRld2F5VXJsIHx8ICcnKSxcbiAgICAgIHRva2VuOiBTdHJpbmcodGhpcy5zZXR0aW5ncy5hdXRoVG9rZW4gfHwgJycpLFxuICAgICAgYWxsb3dJbnNlY3VyZVdzOiBCb29sZWFuKHRoaXMuc2V0dGluZ3MuYWxsb3dJbnNlY3VyZVdzKSxcbiAgICB9O1xuICB9XG5cbiAgLyoqIFBlcnNpc3QgKyByZW1lbWJlciBhbiBPYnNpZGlhbiBzZXNzaW9uIGtleSBmb3IgdGhlIGN1cnJlbnQgdmF1bHQuICovXG4gIGFzeW5jIHJlbWVtYmVyU2Vzc2lvbktleShzZXNzaW9uS2V5OiBzdHJpbmcpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBjb25zdCBuZXh0ID0gc2Vzc2lvbktleS50cmltKCkudG9Mb3dlckNhc2UoKTtcbiAgICBpZiAoIW5leHQpIHJldHVybjtcblxuICAgIC8vIFNFQzogYWxsb3cgb25seSB2YXVsdC1zY29wZWQga2V5cyAod2hlbiB2YXVsdEhhc2gga25vd24pIG9yIG1haW4uXG4gICAgY29uc3QgdmF1bHRIYXNoID0gdGhpcy5fdmF1bHRIYXNoO1xuICAgIGlmICh2YXVsdEhhc2gpIHtcbiAgICAgIGNvbnN0IHByZWZpeCA9IGBhZ2VudDptYWluOm9ic2lkaWFuOmRpcmVjdDoke3ZhdWx0SGFzaH1gO1xuICAgICAgaWYgKCEobmV4dCA9PT0gJ21haW4nIHx8IG5leHQgPT09IHByZWZpeCB8fCBuZXh0LnN0YXJ0c1dpdGgocHJlZml4ICsgJy0nKSkpIHtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuICAgIH0gZWxzZSB7XG4gICAgICAvLyBXaXRob3V0IGEgdmF1bHQgaWRlbnRpdHksIG9ubHkgYWxsb3cgbWFpbi5cbiAgICAgIGlmIChuZXh0ICE9PSAnbWFpbicpIHJldHVybjtcbiAgICB9XG5cbiAgICB0aGlzLnNldHRpbmdzLnNlc3Npb25LZXkgPSBuZXh0O1xuXG4gICAgaWYgKHRoaXMuX3ZhdWx0SGFzaCkge1xuICAgICAgY29uc3QgbWFwID0gdGhpcy5zZXR0aW5ncy5rbm93blNlc3Npb25LZXlzQnlWYXVsdCA/PyB7fTtcbiAgICAgIGNvbnN0IGN1ciA9IEFycmF5LmlzQXJyYXkobWFwW3RoaXMuX3ZhdWx0SGFzaF0pID8gbWFwW3RoaXMuX3ZhdWx0SGFzaF0gOiBbXTtcbiAgICAgIGNvbnN0IG5leHRMaXN0ID0gW25leHQsIC4uLmN1ci5maWx0ZXIoKGspID0+IGsgJiYgayAhPT0gbmV4dCldLnNsaWNlKDAsIDIwKTtcbiAgICAgIG1hcFt0aGlzLl92YXVsdEhhc2hdID0gbmV4dExpc3Q7XG4gICAgICB0aGlzLnNldHRpbmdzLmtub3duU2Vzc2lvbktleXNCeVZhdWx0ID0gbWFwO1xuICAgIH1cblxuICAgIGF3YWl0IHRoaXMuc2F2ZVNldHRpbmdzKCk7XG4gIH1cblxuICBjcmVhdGVXc0NsaWVudChzZXNzaW9uS2V5OiBzdHJpbmcpOiBPYnNpZGlhbldTQ2xpZW50IHtcbiAgICByZXR1cm4gbmV3IE9ic2lkaWFuV1NDbGllbnQoc2Vzc2lvbktleS50cmltKCkudG9Mb3dlckNhc2UoKSwge1xuICAgICAgaWRlbnRpdHlTdG9yZToge1xuICAgICAgICBnZXQ6IGFzeW5jICgpID0+IChhd2FpdCB0aGlzLl9sb2FkRGV2aWNlSWRlbnRpdHkoKSksXG4gICAgICAgIHNldDogYXN5bmMgKGlkZW50aXR5KSA9PiBhd2FpdCB0aGlzLl9zYXZlRGV2aWNlSWRlbnRpdHkoaWRlbnRpdHkpLFxuICAgICAgICBjbGVhcjogYXN5bmMgKCkgPT4gYXdhaXQgdGhpcy5fY2xlYXJEZXZpY2VJZGVudGl0eSgpLFxuICAgICAgfSxcbiAgICB9KTtcbiAgfVxuXG4gIGFzeW5jIG9ubG9hZCgpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBhd2FpdCB0aGlzLmxvYWRTZXR0aW5ncygpO1xuXG4gICAgLy8gQ29tcHV0ZSB2YXVsdCBoYXNoIChkZXNrdG9wKSBhbmQgbWlncmF0ZSB0byBjYW5vbmljYWwgb2JzaWRpYW4gZGlyZWN0IHNlc3Npb24ga2V5LlxuICAgIHRoaXMuX3ZhdWx0SGFzaCA9IHRoaXMuX2NvbXB1dGVWYXVsdEhhc2goKTtcbiAgICBpZiAodGhpcy5fdmF1bHRIYXNoKSB7XG4gICAgICB0aGlzLnNldHRpbmdzLnZhdWx0SGFzaCA9IHRoaXMuX3ZhdWx0SGFzaDtcblxuICAgICAgY29uc3QgbWlncmF0ZWQgPSBtaWdyYXRlU2V0dGluZ3NGb3JWYXVsdCh0aGlzLnNldHRpbmdzLCB0aGlzLl92YXVsdEhhc2gpO1xuICAgICAgdGhpcy5zZXR0aW5ncyA9IG1pZ3JhdGVkLm5leHRTZXR0aW5ncztcbiAgICAgIGF3YWl0IHRoaXMuc2F2ZVNldHRpbmdzKCk7XG4gICAgfSBlbHNlIHtcbiAgICAgIC8vIEtlZXAgd29ya2luZywgYnV0IE5ldy1zZXNzaW9uIGNyZWF0aW9uIG1heSBiZSB1bmF2YWlsYWJsZS5cbiAgICAgIG5ldyBOb3RpY2UoJ09wZW5DbGF3IENoYXQ6IGNvdWxkIG5vdCBkZXRlcm1pbmUgdmF1bHQgaWRlbnRpdHkgKHZhdWx0SGFzaCkuJyk7XG4gICAgfVxuXG4gICAgLy8gUmVnaXN0ZXIgdGhlIHNpZGViYXIgdmlld1xuICAgIHRoaXMucmVnaXN0ZXJWaWV3KFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFULCAobGVhZjogV29ya3NwYWNlTGVhZikgPT4gbmV3IE9wZW5DbGF3Q2hhdFZpZXcobGVhZiwgdGhpcykpO1xuXG4gICAgLy8gUmliYm9uIGljb24gXHUyMDE0IG9wZW5zIC8gcmV2ZWFscyB0aGUgY2hhdCBzaWRlYmFyXG4gICAgdGhpcy5hZGRSaWJib25JY29uKCdtZXNzYWdlLXNxdWFyZScsICdPcGVuQ2xhdyBDaGF0JywgKCkgPT4ge1xuICAgICAgdm9pZCB0aGlzLl9hY3RpdmF0ZUNoYXRWaWV3KCk7XG4gICAgfSk7XG5cbiAgICAvLyBTZXR0aW5ncyB0YWJcbiAgICB0aGlzLmFkZFNldHRpbmdUYWIobmV3IE9wZW5DbGF3U2V0dGluZ1RhYih0aGlzLmFwcCwgdGhpcykpO1xuXG4gICAgLy8gQ29tbWFuZCBwYWxldHRlIGVudHJ5XG4gICAgdGhpcy5hZGRDb21tYW5kKHtcbiAgICAgIGlkOiAnb3Blbi1vcGVuY2xhdy1jaGF0JyxcbiAgICAgIG5hbWU6ICdPcGVuIGNoYXQgc2lkZWJhcicsXG4gICAgICBjYWxsYmFjazogKCkgPT4gdm9pZCB0aGlzLl9hY3RpdmF0ZUNoYXRWaWV3KCksXG4gICAgfSk7XG5cbiAgICBjb25zb2xlLmxvZygnW29jbGF3XSBQbHVnaW4gbG9hZGVkJyk7XG4gIH1cblxuICBhc3luYyBvbnVubG9hZCgpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICB0aGlzLmFwcC53b3Jrc3BhY2UuZGV0YWNoTGVhdmVzT2ZUeXBlKFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFUKTtcbiAgICBjb25zb2xlLmxvZygnW29jbGF3XSBQbHVnaW4gdW5sb2FkZWQnKTtcbiAgfVxuXG4gIGFzeW5jIGxvYWRTZXR0aW5ncygpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBjb25zdCBkYXRhID0gKGF3YWl0IHRoaXMubG9hZERhdGEoKSkgPz8ge307XG4gICAgLy8gTk9URTogcGx1Z2luIGRhdGEgbWF5IGNvbnRhaW4gZXh0cmEgcHJpdmF0ZSBmaWVsZHMgKGUuZy4gZGV2aWNlIGlkZW50aXR5KS4gU2V0dGluZ3MgYXJlIHRoZSBwdWJsaWMgc3Vic2V0LlxuICAgIHRoaXMuc2V0dGluZ3MgPSBPYmplY3QuYXNzaWduKHt9LCBERUZBVUxUX1NFVFRJTkdTLCBkYXRhKTtcbiAgfVxuXG4gIGFzeW5jIHNhdmVTZXR0aW5ncygpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICAvLyBQcmVzZXJ2ZSBhbnkgcHJpdmF0ZSBmaWVsZHMgc3RvcmVkIGluIHBsdWdpbiBkYXRhLlxuICAgIGNvbnN0IGRhdGEgPSAoYXdhaXQgdGhpcy5sb2FkRGF0YSgpKSA/PyB7fTtcbiAgICBhd2FpdCB0aGlzLnNhdmVEYXRhKHsgLi4uZGF0YSwgLi4udGhpcy5zZXR0aW5ncyB9KTtcbiAgfVxuXG4gIC8vIFx1MjUwMFx1MjUwMCBEZXZpY2UgaWRlbnRpdHkgcGVyc2lzdGVuY2UgKHBsdWdpbi1zY29wZWQ7IE5PVCBsb2NhbFN0b3JhZ2UpIFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFxuXG4gIGFzeW5jIHJlc2V0RGV2aWNlSWRlbnRpdHkoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgYXdhaXQgdGhpcy5fY2xlYXJEZXZpY2VJZGVudGl0eSgpO1xuICAgIG5ldyBOb3RpY2UoJ09wZW5DbGF3IENoYXQ6IGRldmljZSBpZGVudGl0eSByZXNldC4gUmVjb25uZWN0IHRvIHBhaXIgYWdhaW4uJyk7XG4gIH1cblxuICBwcml2YXRlIF9kZXZpY2VJZGVudGl0eUtleSA9ICdfb3BlbmNsYXdEZXZpY2VJZGVudGl0eVYxJztcblxuICBwcml2YXRlIGFzeW5jIF9sb2FkRGV2aWNlSWRlbnRpdHkoKTogUHJvbWlzZTxhbnkgfCBudWxsPiB7XG4gICAgY29uc3QgZGF0YSA9IChhd2FpdCB0aGlzLmxvYWREYXRhKCkpID8/IHt9O1xuICAgIHJldHVybiAoZGF0YSBhcyBhbnkpPy5bdGhpcy5fZGV2aWNlSWRlbnRpdHlLZXldID8/IG51bGw7XG4gIH1cblxuICBwcml2YXRlIGFzeW5jIF9zYXZlRGV2aWNlSWRlbnRpdHkoaWRlbnRpdHk6IGFueSk6IFByb21pc2U8dm9pZD4ge1xuICAgIGNvbnN0IGRhdGEgPSAoYXdhaXQgdGhpcy5sb2FkRGF0YSgpKSA/PyB7fTtcbiAgICBhd2FpdCB0aGlzLnNhdmVEYXRhKHsgLi4uZGF0YSwgW3RoaXMuX2RldmljZUlkZW50aXR5S2V5XTogaWRlbnRpdHkgfSk7XG4gIH1cblxuICBwcml2YXRlIGFzeW5jIF9jbGVhckRldmljZUlkZW50aXR5KCk6IFByb21pc2U8dm9pZD4ge1xuICAgIGNvbnN0IGRhdGEgPSAoYXdhaXQgdGhpcy5sb2FkRGF0YSgpKSA/PyB7fTtcbiAgICBpZiAoKGRhdGEgYXMgYW55KT8uW3RoaXMuX2RldmljZUlkZW50aXR5S2V5XSA9PT0gdW5kZWZpbmVkKSByZXR1cm47XG4gICAgY29uc3QgbmV4dCA9IHsgLi4uKGRhdGEgYXMgYW55KSB9O1xuICAgIGRlbGV0ZSBuZXh0W3RoaXMuX2RldmljZUlkZW50aXR5S2V5XTtcbiAgICBhd2FpdCB0aGlzLnNhdmVEYXRhKG5leHQpO1xuICB9XG5cbiAgLy8gXHUyNTAwXHUyNTAwIEhlbHBlcnMgXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG5cbiAgcHJpdmF0ZSBhc3luYyBfYWN0aXZhdGVDaGF0VmlldygpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBjb25zdCB7IHdvcmtzcGFjZSB9ID0gdGhpcy5hcHA7XG5cbiAgICAvLyBSZXVzZSBleGlzdGluZyBsZWFmIGlmIGFscmVhZHkgb3BlblxuICAgIGNvbnN0IGV4aXN0aW5nID0gd29ya3NwYWNlLmdldExlYXZlc09mVHlwZShWSUVXX1RZUEVfT1BFTkNMQVdfQ0hBVCk7XG4gICAgaWYgKGV4aXN0aW5nLmxlbmd0aCA+IDApIHtcbiAgICAgIHdvcmtzcGFjZS5yZXZlYWxMZWFmKGV4aXN0aW5nWzBdKTtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICAvLyBPcGVuIGluIHJpZ2h0IHNpZGViYXJcbiAgICBjb25zdCBsZWFmID0gd29ya3NwYWNlLmdldFJpZ2h0TGVhZihmYWxzZSk7XG4gICAgaWYgKCFsZWFmKSByZXR1cm47XG4gICAgYXdhaXQgbGVhZi5zZXRWaWV3U3RhdGUoeyB0eXBlOiBWSUVXX1RZUEVfT1BFTkNMQVdfQ0hBVCwgYWN0aXZlOiB0cnVlIH0pO1xuICAgIHdvcmtzcGFjZS5yZXZlYWxMZWFmKGxlYWYpO1xuICB9XG59XG4iLCAiaW1wb3J0IHsgQXBwLCBQbHVnaW5TZXR0aW5nVGFiLCBTZXR0aW5nIH0gZnJvbSAnb2JzaWRpYW4nO1xuaW1wb3J0IHR5cGUgT3BlbkNsYXdQbHVnaW4gZnJvbSAnLi9tYWluJztcblxuZXhwb3J0IGNsYXNzIE9wZW5DbGF3U2V0dGluZ1RhYiBleHRlbmRzIFBsdWdpblNldHRpbmdUYWIge1xuICBwbHVnaW46IE9wZW5DbGF3UGx1Z2luO1xuXG4gIGNvbnN0cnVjdG9yKGFwcDogQXBwLCBwbHVnaW46IE9wZW5DbGF3UGx1Z2luKSB7XG4gICAgc3VwZXIoYXBwLCBwbHVnaW4pO1xuICAgIHRoaXMucGx1Z2luID0gcGx1Z2luO1xuICB9XG5cbiAgZGlzcGxheSgpOiB2b2lkIHtcbiAgICBjb25zdCB7IGNvbnRhaW5lckVsIH0gPSB0aGlzO1xuICAgIGNvbnRhaW5lckVsLmVtcHR5KCk7XG5cbiAgICBjb250YWluZXJFbC5jcmVhdGVFbCgnaDInLCB7IHRleHQ6ICdPcGVuQ2xhdyBDaGF0IFx1MjAxMyBTZXR0aW5ncycgfSk7XG5cbiAgICBuZXcgU2V0dGluZyhjb250YWluZXJFbClcbiAgICAgIC5zZXROYW1lKCdHYXRld2F5IFVSTCcpXG4gICAgICAuc2V0RGVzYygnV2ViU29ja2V0IFVSTCBvZiB0aGUgT3BlbkNsYXcgR2F0ZXdheSAoZS5nLiB3czovL2hvc3RuYW1lOjE4Nzg5KS4nKVxuICAgICAgLmFkZFRleHQoKHRleHQpID0+XG4gICAgICAgIHRleHRcbiAgICAgICAgICAuc2V0UGxhY2Vob2xkZXIoJ3dzOi8vbG9jYWxob3N0OjE4Nzg5JylcbiAgICAgICAgICAuc2V0VmFsdWUodGhpcy5wbHVnaW4uc2V0dGluZ3MuZ2F0ZXdheVVybClcbiAgICAgICAgICAub25DaGFuZ2UoYXN5bmMgKHZhbHVlKSA9PiB7XG4gICAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5nYXRld2F5VXJsID0gdmFsdWUudHJpbSgpO1xuICAgICAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uc2F2ZVNldHRpbmdzKCk7XG4gICAgICAgICAgfSlcbiAgICAgICk7XG5cbiAgICBuZXcgU2V0dGluZyhjb250YWluZXJFbClcbiAgICAgIC5zZXROYW1lKCdBdXRoIHRva2VuJylcbiAgICAgIC5zZXREZXNjKCdNdXN0IG1hdGNoIHRoZSBhdXRoVG9rZW4gaW4geW91ciBvcGVuY2xhdy5qc29uIGNoYW5uZWwgY29uZmlnLiBOZXZlciBzaGFyZWQuJylcbiAgICAgIC5hZGRUZXh0KCh0ZXh0KSA9PiB7XG4gICAgICAgIHRleHRcbiAgICAgICAgICAuc2V0UGxhY2Vob2xkZXIoJ0VudGVyIHRva2VuXHUyMDI2JylcbiAgICAgICAgICAuc2V0VmFsdWUodGhpcy5wbHVnaW4uc2V0dGluZ3MuYXV0aFRva2VuKVxuICAgICAgICAgIC5vbkNoYW5nZShhc3luYyAodmFsdWUpID0+IHtcbiAgICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLmF1dGhUb2tlbiA9IHZhbHVlO1xuICAgICAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uc2F2ZVNldHRpbmdzKCk7XG4gICAgICAgICAgfSk7XG4gICAgICAgIC8vIFRyZWF0IGFzIHBhc3N3b3JkIGZpZWxkIFx1MjAxMyBkbyBub3QgcmV2ZWFsIHRva2VuIGluIFVJXG4gICAgICAgIHRleHQuaW5wdXRFbC50eXBlID0gJ3Bhc3N3b3JkJztcbiAgICAgICAgdGV4dC5pbnB1dEVsLmF1dG9jb21wbGV0ZSA9ICdvZmYnO1xuICAgICAgfSk7XG5cbiAgICBuZXcgU2V0dGluZyhjb250YWluZXJFbClcbiAgICAgIC5zZXROYW1lKCdTZXNzaW9uIEtleScpXG4gICAgICAuc2V0RGVzYygnT3BlbkNsYXcgc2Vzc2lvbiB0byBzdWJzY3JpYmUgdG8gKHVzdWFsbHkgXCJtYWluXCIpLicpXG4gICAgICAuYWRkVGV4dCgodGV4dCkgPT5cbiAgICAgICAgdGV4dFxuICAgICAgICAgIC5zZXRQbGFjZWhvbGRlcignbWFpbicpXG4gICAgICAgICAgLnNldFZhbHVlKHRoaXMucGx1Z2luLnNldHRpbmdzLnNlc3Npb25LZXkpXG4gICAgICAgICAgLm9uQ2hhbmdlKGFzeW5jICh2YWx1ZSkgPT4ge1xuICAgICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3Muc2Vzc2lvbktleSA9IHZhbHVlLnRyaW0oKSB8fCAnbWFpbic7XG4gICAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgICB9KVxuICAgICAgKTtcblxuICAgIG5ldyBTZXR0aW5nKGNvbnRhaW5lckVsKVxuICAgICAgLnNldE5hbWUoJ0FjY291bnQgSUQnKVxuICAgICAgLnNldERlc2MoJ09wZW5DbGF3IGFjY291bnQgSUQgKHVzdWFsbHkgXCJtYWluXCIpLicpXG4gICAgICAuYWRkVGV4dCgodGV4dCkgPT5cbiAgICAgICAgdGV4dFxuICAgICAgICAgIC5zZXRQbGFjZWhvbGRlcignbWFpbicpXG4gICAgICAgICAgLnNldFZhbHVlKHRoaXMucGx1Z2luLnNldHRpbmdzLmFjY291bnRJZClcbiAgICAgICAgICAub25DaGFuZ2UoYXN5bmMgKHZhbHVlKSA9PiB7XG4gICAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5hY2NvdW50SWQgPSB2YWx1ZS50cmltKCkgfHwgJ21haW4nO1xuICAgICAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uc2F2ZVNldHRpbmdzKCk7XG4gICAgICAgICAgfSlcbiAgICAgICk7XG5cbiAgICBuZXcgU2V0dGluZyhjb250YWluZXJFbClcbiAgICAgIC5zZXROYW1lKCdJbmNsdWRlIGFjdGl2ZSBub3RlIGJ5IGRlZmF1bHQnKVxuICAgICAgLnNldERlc2MoJ1ByZS1jaGVjayBcIkluY2x1ZGUgYWN0aXZlIG5vdGVcIiBpbiB0aGUgY2hhdCBwYW5lbCB3aGVuIGl0IG9wZW5zLicpXG4gICAgICAuYWRkVG9nZ2xlKCh0b2dnbGUpID0+XG4gICAgICAgIHRvZ2dsZS5zZXRWYWx1ZSh0aGlzLnBsdWdpbi5zZXR0aW5ncy5pbmNsdWRlQWN0aXZlTm90ZSkub25DaGFuZ2UoYXN5bmMgKHZhbHVlKSA9PiB7XG4gICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3MuaW5jbHVkZUFjdGl2ZU5vdGUgPSB2YWx1ZTtcbiAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgfSlcbiAgICAgICk7XG5cbiAgICBuZXcgU2V0dGluZyhjb250YWluZXJFbClcbiAgICAgIC5zZXROYW1lKCdSZW5kZXIgYXNzaXN0YW50IGFzIE1hcmtkb3duICh1bnNhZmUpJylcbiAgICAgIC5zZXREZXNjKFxuICAgICAgICAnT0ZGIHJlY29tbWVuZGVkLiBJZiBlbmFibGVkLCBhc3Npc3RhbnQgb3V0cHV0IGlzIHJlbmRlcmVkIGFzIE9ic2lkaWFuIE1hcmtkb3duIHdoaWNoIG1heSB0cmlnZ2VyIGVtYmVkcyBhbmQgb3RoZXIgcGx1Z2luc1xcJyBwb3N0LXByb2Nlc3NvcnMuJ1xuICAgICAgKVxuICAgICAgLmFkZFRvZ2dsZSgodG9nZ2xlKSA9PlxuICAgICAgICB0b2dnbGUuc2V0VmFsdWUodGhpcy5wbHVnaW4uc2V0dGluZ3MucmVuZGVyQXNzaXN0YW50TWFya2Rvd24pLm9uQ2hhbmdlKGFzeW5jICh2YWx1ZSkgPT4ge1xuICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLnJlbmRlckFzc2lzdGFudE1hcmtkb3duID0gdmFsdWU7XG4gICAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uc2F2ZVNldHRpbmdzKCk7XG4gICAgICAgIH0pXG4gICAgICApO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZSgnQWxsb3cgaW5zZWN1cmUgd3M6Ly8gZm9yIG5vbi1sb2NhbCBnYXRld2F5cyAodW5zYWZlKScpXG4gICAgICAuc2V0RGVzYyhcbiAgICAgICAgJ09GRiByZWNvbW1lbmRlZC4gSWYgZW5hYmxlZCwgeW91IGNhbiBjb25uZWN0IHRvIG5vbi1sb2NhbCBnYXRld2F5cyBvdmVyIHdzOi8vLiBUaGlzIGV4cG9zZXMgeW91ciB0b2tlbiBhbmQgbWVzc2FnZSBjb250ZW50IHRvIG5ldHdvcmsgYXR0YWNrZXJzOyBwcmVmZXIgd3NzOi8vLidcbiAgICAgIClcbiAgICAgIC5hZGRUb2dnbGUoKHRvZ2dsZSkgPT5cbiAgICAgICAgdG9nZ2xlLnNldFZhbHVlKHRoaXMucGx1Z2luLnNldHRpbmdzLmFsbG93SW5zZWN1cmVXcykub25DaGFuZ2UoYXN5bmMgKHZhbHVlKSA9PiB7XG4gICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3MuYWxsb3dJbnNlY3VyZVdzID0gdmFsdWU7XG4gICAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uc2F2ZVNldHRpbmdzKCk7XG4gICAgICAgIH0pXG4gICAgICApO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZSgnUmVzZXQgZGV2aWNlIGlkZW50aXR5IChyZS1wYWlyKScpXG4gICAgICAuc2V0RGVzYygnQ2xlYXJzIHRoZSBzdG9yZWQgZGV2aWNlIGlkZW50aXR5IHVzZWQgZm9yIG9wZXJhdG9yLndyaXRlIHBhaXJpbmcuIFVzZSB0aGlzIGlmIHlvdSBzdXNwZWN0IGNvbXByb21pc2Ugb3Igc2VlIFwiZGV2aWNlIGlkZW50aXR5IG1pc21hdGNoXCIuJylcbiAgICAgIC5hZGRCdXR0b24oKGJ0bikgPT5cbiAgICAgICAgYnRuLnNldEJ1dHRvblRleHQoJ1Jlc2V0Jykuc2V0V2FybmluZygpLm9uQ2xpY2soYXN5bmMgKCkgPT4ge1xuICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnJlc2V0RGV2aWNlSWRlbnRpdHkoKTtcbiAgICAgICAgfSlcbiAgICAgICk7XG5cbiAgICAvLyBcdTI1MDBcdTI1MDAgUGF0aCBtYXBwaW5ncyBcdTI1MDBcdTI1MDBcbiAgICBjb250YWluZXJFbC5jcmVhdGVFbCgnaDMnLCB7IHRleHQ6ICdQYXRoIG1hcHBpbmdzICh2YXVsdCBiYXNlIFx1MjE5MiByZW1vdGUgYmFzZSknIH0pO1xuICAgIGNvbnRhaW5lckVsLmNyZWF0ZUVsKCdwJywge1xuICAgICAgdGV4dDogJ1VzZWQgdG8gY29udmVydCBhc3Npc3RhbnQgZmlsZSByZWZlcmVuY2VzIChyZW1vdGUgRlMgcGF0aHMgb3IgZXhwb3J0ZWQgVVJMcykgaW50byBjbGlja2FibGUgT2JzaWRpYW4gbGlua3MuIEZpcnN0IG1hdGNoIHdpbnMuIE9ubHkgY3JlYXRlcyBhIGxpbmsgaWYgdGhlIG1hcHBlZCB2YXVsdCBmaWxlIGV4aXN0cy4nLFxuICAgICAgY2xzOiAnc2V0dGluZy1pdGVtLWRlc2NyaXB0aW9uJyxcbiAgICB9KTtcblxuICAgIGNvbnN0IG1hcHBpbmdzID0gdGhpcy5wbHVnaW4uc2V0dGluZ3MucGF0aE1hcHBpbmdzID8/IFtdO1xuXG4gICAgY29uc3QgcmVyZW5kZXIgPSBhc3luYyAoKSA9PiB7XG4gICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgIHRoaXMuZGlzcGxheSgpO1xuICAgIH07XG5cbiAgICBtYXBwaW5ncy5mb3JFYWNoKChyb3csIGlkeCkgPT4ge1xuICAgICAgY29uc3QgcyA9IG5ldyBTZXR0aW5nKGNvbnRhaW5lckVsKVxuICAgICAgICAuc2V0TmFtZShgTWFwcGluZyAjJHtpZHggKyAxfWApXG4gICAgICAgIC5zZXREZXNjKCd2YXVsdEJhc2UgXHUyMTkyIHJlbW90ZUJhc2UnKTtcblxuICAgICAgcy5hZGRUZXh0KCh0KSA9PlxuICAgICAgICB0XG4gICAgICAgICAgLnNldFBsYWNlaG9sZGVyKCd2YXVsdCBiYXNlIChlLmcuIGRvY3MvKScpXG4gICAgICAgICAgLnNldFZhbHVlKHJvdy52YXVsdEJhc2UgPz8gJycpXG4gICAgICAgICAgLm9uQ2hhbmdlKGFzeW5jICh2KSA9PiB7XG4gICAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5wYXRoTWFwcGluZ3NbaWR4XS52YXVsdEJhc2UgPSB2O1xuICAgICAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uc2F2ZVNldHRpbmdzKCk7XG4gICAgICAgICAgfSlcbiAgICAgICk7XG5cbiAgICAgIHMuYWRkVGV4dCgodCkgPT5cbiAgICAgICAgdFxuICAgICAgICAgIC5zZXRQbGFjZWhvbGRlcigncmVtb3RlIGJhc2UgKGUuZy4gL2hvbWUvLi4uL2RvY3MvKScpXG4gICAgICAgICAgLnNldFZhbHVlKHJvdy5yZW1vdGVCYXNlID8/ICcnKVxuICAgICAgICAgIC5vbkNoYW5nZShhc3luYyAodikgPT4ge1xuICAgICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3MucGF0aE1hcHBpbmdzW2lkeF0ucmVtb3RlQmFzZSA9IHY7XG4gICAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgICB9KVxuICAgICAgKTtcblxuICAgICAgcy5hZGRFeHRyYUJ1dHRvbigoYikgPT5cbiAgICAgICAgYlxuICAgICAgICAgIC5zZXRJY29uKCd0cmFzaCcpXG4gICAgICAgICAgLnNldFRvb2x0aXAoJ1JlbW92ZSBtYXBwaW5nJylcbiAgICAgICAgICAub25DbGljayhhc3luYyAoKSA9PiB7XG4gICAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5wYXRoTWFwcGluZ3Muc3BsaWNlKGlkeCwgMSk7XG4gICAgICAgICAgICBhd2FpdCByZXJlbmRlcigpO1xuICAgICAgICAgIH0pXG4gICAgICApO1xuICAgIH0pO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZSgnQWRkIG1hcHBpbmcnKVxuICAgICAgLnNldERlc2MoJ0FkZCBhIG5ldyB2YXVsdEJhc2UgXHUyMTkyIHJlbW90ZUJhc2UgbWFwcGluZyByb3cuJylcbiAgICAgIC5hZGRCdXR0b24oKGJ0bikgPT5cbiAgICAgICAgYnRuLnNldEJ1dHRvblRleHQoJ0FkZCcpLm9uQ2xpY2soYXN5bmMgKCkgPT4ge1xuICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLnBhdGhNYXBwaW5ncy5wdXNoKHsgdmF1bHRCYXNlOiAnJywgcmVtb3RlQmFzZTogJycgfSk7XG4gICAgICAgICAgYXdhaXQgcmVyZW5kZXIoKTtcbiAgICAgICAgfSlcbiAgICAgICk7XG5cbiAgICBjb250YWluZXJFbC5jcmVhdGVFbCgncCcsIHtcbiAgICAgIHRleHQ6ICdSZWNvbm5lY3Q6IGNsb3NlIGFuZCByZW9wZW4gdGhlIHNpZGViYXIgYWZ0ZXIgY2hhbmdpbmcgdGhlIGdhdGV3YXkgVVJMIG9yIHRva2VuLicsXG4gICAgICBjbHM6ICdzZXR0aW5nLWl0ZW0tZGVzY3JpcHRpb24nLFxuICAgIH0pO1xuICB9XG59XG4iLCAiLyoqXG4gKiBXZWJTb2NrZXQgY2xpZW50IGZvciBPcGVuQ2xhdyBHYXRld2F5XG4gKlxuICogUGl2b3QgKDIwMjYtMDItMjUpOiBEbyBOT1QgdXNlIGN1c3RvbSBvYnNpZGlhbi4qIGdhdGV3YXkgbWV0aG9kcy5cbiAqIFRob3NlIHJlcXVpcmUgb3BlcmF0b3IuYWRtaW4gc2NvcGUgd2hpY2ggaXMgbm90IGdyYW50ZWQgdG8gZXh0ZXJuYWwgY2xpZW50cy5cbiAqXG4gKiBBdXRoIG5vdGU6XG4gKiAtIGNoYXQuc2VuZCByZXF1aXJlcyBvcGVyYXRvci53cml0ZVxuICogLSBleHRlcm5hbCBjbGllbnRzIG11c3QgcHJlc2VudCBhIHBhaXJlZCBkZXZpY2UgaWRlbnRpdHkgdG8gcmVjZWl2ZSB3cml0ZSBzY29wZXNcbiAqXG4gKiBXZSB1c2UgYnVpbHQtaW4gZ2F0ZXdheSBtZXRob2RzL2V2ZW50czpcbiAqIC0gU2VuZDogY2hhdC5zZW5kKHsgc2Vzc2lvbktleSwgbWVzc2FnZSwgaWRlbXBvdGVuY3lLZXksIC4uLiB9KVxuICogLSBSZWNlaXZlOiBldmVudCBcImNoYXRcIiAoZmlsdGVyIGJ5IHNlc3Npb25LZXkpXG4gKi9cblxuaW1wb3J0IHR5cGUgeyBJbmJvdW5kV1NQYXlsb2FkIH0gZnJvbSAnLi90eXBlcyc7XG5cbmZ1bmN0aW9uIGlzTG9jYWxIb3N0KGhvc3Q6IHN0cmluZyk6IGJvb2xlYW4ge1xuICBjb25zdCBoID0gaG9zdC50b0xvd2VyQ2FzZSgpO1xuICByZXR1cm4gaCA9PT0gJ2xvY2FsaG9zdCcgfHwgaCA9PT0gJzEyNy4wLjAuMScgfHwgaCA9PT0gJzo6MSc7XG59XG5cbmZ1bmN0aW9uIHNhZmVQYXJzZVdzVXJsKHVybDogc3RyaW5nKTpcbiAgfCB7IG9rOiB0cnVlOyBzY2hlbWU6ICd3cycgfCAnd3NzJzsgaG9zdDogc3RyaW5nIH1cbiAgfCB7IG9rOiBmYWxzZTsgZXJyb3I6IHN0cmluZyB9IHtcbiAgdHJ5IHtcbiAgICBjb25zdCB1ID0gbmV3IFVSTCh1cmwpO1xuICAgIGlmICh1LnByb3RvY29sICE9PSAnd3M6JyAmJiB1LnByb3RvY29sICE9PSAnd3NzOicpIHtcbiAgICAgIHJldHVybiB7IG9rOiBmYWxzZSwgZXJyb3I6IGBHYXRld2F5IFVSTCBtdXN0IGJlIHdzOi8vIG9yIHdzczovLyAoZ290ICR7dS5wcm90b2NvbH0pYCB9O1xuICAgIH1cbiAgICBjb25zdCBzY2hlbWUgPSB1LnByb3RvY29sID09PSAnd3M6JyA/ICd3cycgOiAnd3NzJztcbiAgICByZXR1cm4geyBvazogdHJ1ZSwgc2NoZW1lLCBob3N0OiB1Lmhvc3RuYW1lIH07XG4gIH0gY2F0Y2gge1xuICAgIHJldHVybiB7IG9rOiBmYWxzZSwgZXJyb3I6ICdJbnZhbGlkIGdhdGV3YXkgVVJMJyB9O1xuICB9XG59XG5cbi8qKiBJbnRlcnZhbCBmb3Igc2VuZGluZyBoZWFydGJlYXQgcGluZ3MgKGNoZWNrIGNvbm5lY3Rpb24gbGl2ZW5lc3MpICovXG5jb25zdCBIRUFSVEJFQVRfSU5URVJWQUxfTVMgPSAzMF8wMDA7XG5cbi8qKiBTYWZldHkgdmFsdmU6IGhpZGUgd29ya2luZyBzcGlubmVyIGlmIG5vIGFzc2lzdGFudCByZXBseSBhcnJpdmVzIGluIHRpbWUgKi9cbmNvbnN0IFdPUktJTkdfTUFYX01TID0gMTIwXzAwMDtcblxuLyoqIE1heCBpbmJvdW5kIGZyYW1lIHNpemUgdG8gcGFyc2UgKERvUyBndWFyZCkgKi9cbmNvbnN0IE1BWF9JTkJPVU5EX0ZSQU1FX0JZVEVTID0gNTEyICogMTAyNDtcblxuZnVuY3Rpb24gYnl0ZUxlbmd0aFV0ZjgodGV4dDogc3RyaW5nKTogbnVtYmVyIHtcbiAgcmV0dXJuIHV0ZjhCeXRlcyh0ZXh0KS5ieXRlTGVuZ3RoO1xufVxuXG5hc3luYyBmdW5jdGlvbiBub3JtYWxpemVXc0RhdGFUb1RleHQoZGF0YTogYW55KTogUHJvbWlzZTx7IG9rOiB0cnVlOyB0ZXh0OiBzdHJpbmc7IGJ5dGVzOiBudW1iZXIgfSB8IHsgb2s6IGZhbHNlOyByZWFzb246IHN0cmluZzsgYnl0ZXM/OiBudW1iZXIgfT4ge1xuICBpZiAodHlwZW9mIGRhdGEgPT09ICdzdHJpbmcnKSB7XG4gICAgY29uc3QgYnl0ZXMgPSBieXRlTGVuZ3RoVXRmOChkYXRhKTtcbiAgICByZXR1cm4geyBvazogdHJ1ZSwgdGV4dDogZGF0YSwgYnl0ZXMgfTtcbiAgfVxuXG4gIC8vIEJyb3dzZXIgV2ViU29ja2V0IGNhbiBkZWxpdmVyIEJsb2JcbiAgaWYgKHR5cGVvZiBCbG9iICE9PSAndW5kZWZpbmVkJyAmJiBkYXRhIGluc3RhbmNlb2YgQmxvYikge1xuICAgIGNvbnN0IGJ5dGVzID0gZGF0YS5zaXplO1xuICAgIGlmIChieXRlcyA+IE1BWF9JTkJPVU5EX0ZSQU1FX0JZVEVTKSByZXR1cm4geyBvazogZmFsc2UsIHJlYXNvbjogJ3Rvby1sYXJnZScsIGJ5dGVzIH07XG4gICAgY29uc3QgdGV4dCA9IGF3YWl0IGRhdGEudGV4dCgpO1xuICAgIC8vIEJsb2Iuc2l6ZSBpcyBieXRlcyBhbHJlYWR5OyBubyBuZWVkIHRvIHJlLW1lYXN1cmUuXG4gICAgcmV0dXJuIHsgb2s6IHRydWUsIHRleHQsIGJ5dGVzIH07XG4gIH1cblxuICBpZiAoZGF0YSBpbnN0YW5jZW9mIEFycmF5QnVmZmVyKSB7XG4gICAgY29uc3QgYnl0ZXMgPSBkYXRhLmJ5dGVMZW5ndGg7XG4gICAgaWYgKGJ5dGVzID4gTUFYX0lOQk9VTkRfRlJBTUVfQllURVMpIHJldHVybiB7IG9rOiBmYWxzZSwgcmVhc29uOiAndG9vLWxhcmdlJywgYnl0ZXMgfTtcbiAgICBjb25zdCB0ZXh0ID0gbmV3IFRleHREZWNvZGVyKCd1dGYtOCcsIHsgZmF0YWw6IGZhbHNlIH0pLmRlY29kZShuZXcgVWludDhBcnJheShkYXRhKSk7XG4gICAgcmV0dXJuIHsgb2s6IHRydWUsIHRleHQsIGJ5dGVzIH07XG4gIH1cblxuICAvLyBTb21lIHJ1bnRpbWVzIGNvdWxkIHBhc3MgVWludDhBcnJheSBkaXJlY3RseVxuICBpZiAoZGF0YSBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpIHtcbiAgICBjb25zdCBieXRlcyA9IGRhdGEuYnl0ZUxlbmd0aDtcbiAgICBpZiAoYnl0ZXMgPiBNQVhfSU5CT1VORF9GUkFNRV9CWVRFUykgcmV0dXJuIHsgb2s6IGZhbHNlLCByZWFzb246ICd0b28tbGFyZ2UnLCBieXRlcyB9O1xuICAgIGNvbnN0IHRleHQgPSBuZXcgVGV4dERlY29kZXIoJ3V0Zi04JywgeyBmYXRhbDogZmFsc2UgfSkuZGVjb2RlKGRhdGEpO1xuICAgIHJldHVybiB7IG9rOiB0cnVlLCB0ZXh0LCBieXRlcyB9O1xuICB9XG5cbiAgcmV0dXJuIHsgb2s6IGZhbHNlLCByZWFzb246ICd1bnN1cHBvcnRlZC10eXBlJyB9O1xufVxuXG4vKiogTWF4IGluLWZsaWdodCByZXF1ZXN0cyBiZWZvcmUgZmFzdC1mYWlsaW5nIChEb1Mvcm9idXN0bmVzcyBndWFyZCkgKi9cbmNvbnN0IE1BWF9QRU5ESU5HX1JFUVVFU1RTID0gMjAwO1xuXG4vKiogUmVjb25uZWN0IGJhY2tvZmYgKi9cbmNvbnN0IFJFQ09OTkVDVF9CQVNFX01TID0gM18wMDA7XG5jb25zdCBSRUNPTk5FQ1RfTUFYX01TID0gNjBfMDAwO1xuXG4vKiogSGFuZHNoYWtlIGRlYWRsaW5lIHdhaXRpbmcgZm9yIGNvbm5lY3QuY2hhbGxlbmdlICovXG5jb25zdCBIQU5EU0hBS0VfVElNRU9VVF9NUyA9IDE1XzAwMDtcblxuZXhwb3J0IHR5cGUgV1NDbGllbnRTdGF0ZSA9ICdkaXNjb25uZWN0ZWQnIHwgJ2Nvbm5lY3RpbmcnIHwgJ2hhbmRzaGFraW5nJyB8ICdjb25uZWN0ZWQnO1xuXG5leHBvcnQgdHlwZSBXb3JraW5nU3RhdGVMaXN0ZW5lciA9ICh3b3JraW5nOiBib29sZWFuKSA9PiB2b2lkO1xuXG5pbnRlcmZhY2UgUGVuZGluZ1JlcXVlc3Qge1xuICByZXNvbHZlOiAocGF5bG9hZDogYW55KSA9PiB2b2lkO1xuICByZWplY3Q6IChlcnJvcjogYW55KSA9PiB2b2lkO1xuICB0aW1lb3V0OiBSZXR1cm5UeXBlPHR5cGVvZiBzZXRUaW1lb3V0PiB8IG51bGw7XG59XG5cbmV4cG9ydCB0eXBlIERldmljZUlkZW50aXR5ID0ge1xuICBpZDogc3RyaW5nO1xuICBwdWJsaWNLZXk6IHN0cmluZzsgLy8gYmFzZTY0XG4gIHByaXZhdGVLZXlKd2s6IEpzb25XZWJLZXk7XG59O1xuXG5leHBvcnQgaW50ZXJmYWNlIERldmljZUlkZW50aXR5U3RvcmUge1xuICBnZXQoKTogUHJvbWlzZTxEZXZpY2VJZGVudGl0eSB8IG51bGw+O1xuICBzZXQoaWRlbnRpdHk6IERldmljZUlkZW50aXR5KTogUHJvbWlzZTx2b2lkPjtcbiAgY2xlYXIoKTogUHJvbWlzZTx2b2lkPjtcbn1cblxuY29uc3QgREVWSUNFX1NUT1JBR0VfS0VZID0gJ29wZW5jbGF3Q2hhdC5kZXZpY2VJZGVudGl0eS52MSc7IC8vIGxlZ2FjeSBsb2NhbFN0b3JhZ2Uga2V5IChtaWdyYXRpb24gb25seSlcblxuZnVuY3Rpb24gYmFzZTY0VXJsRW5jb2RlKGJ5dGVzOiBBcnJheUJ1ZmZlcik6IHN0cmluZyB7XG4gIGNvbnN0IHU4ID0gbmV3IFVpbnQ4QXJyYXkoYnl0ZXMpO1xuICBsZXQgcyA9ICcnO1xuICBmb3IgKGxldCBpID0gMDsgaSA8IHU4Lmxlbmd0aDsgaSsrKSBzICs9IFN0cmluZy5mcm9tQ2hhckNvZGUodThbaV0pO1xuICBjb25zdCBiNjQgPSBidG9hKHMpO1xuICByZXR1cm4gYjY0LnJlcGxhY2UoL1xcKy9nLCAnLScpLnJlcGxhY2UoL1xcLy9nLCAnXycpLnJlcGxhY2UoLz0rJC9nLCAnJyk7XG59XG5cbmZ1bmN0aW9uIGhleEVuY29kZShieXRlczogQXJyYXlCdWZmZXIpOiBzdHJpbmcge1xuICBjb25zdCB1OCA9IG5ldyBVaW50OEFycmF5KGJ5dGVzKTtcbiAgcmV0dXJuIEFycmF5LmZyb20odTgpXG4gICAgLm1hcCgoYikgPT4gYi50b1N0cmluZygxNikucGFkU3RhcnQoMiwgJzAnKSlcbiAgICAuam9pbignJyk7XG59XG5cbmZ1bmN0aW9uIHV0ZjhCeXRlcyh0ZXh0OiBzdHJpbmcpOiBVaW50OEFycmF5IHtcbiAgcmV0dXJuIG5ldyBUZXh0RW5jb2RlcigpLmVuY29kZSh0ZXh0KTtcbn1cblxuYXN5bmMgZnVuY3Rpb24gc2hhMjU2SGV4KGJ5dGVzOiBBcnJheUJ1ZmZlcik6IFByb21pc2U8c3RyaW5nPiB7XG4gIGNvbnN0IGRpZ2VzdCA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuZGlnZXN0KCdTSEEtMjU2JywgYnl0ZXMpO1xuICByZXR1cm4gaGV4RW5jb2RlKGRpZ2VzdCk7XG59XG5cbmFzeW5jIGZ1bmN0aW9uIGxvYWRPckNyZWF0ZURldmljZUlkZW50aXR5KHN0b3JlPzogRGV2aWNlSWRlbnRpdHlTdG9yZSk6IFByb21pc2U8RGV2aWNlSWRlbnRpdHk+IHtcbiAgLy8gMSkgUHJlZmVyIHBsdWdpbi1zY29wZWQgc3RvcmFnZSAoaW5qZWN0ZWQgYnkgbWFpbiBwbHVnaW4pLlxuICBpZiAoc3RvcmUpIHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgZXhpc3RpbmcgPSBhd2FpdCBzdG9yZS5nZXQoKTtcbiAgICAgIGlmIChleGlzdGluZz8uaWQgJiYgZXhpc3Rpbmc/LnB1YmxpY0tleSAmJiBleGlzdGluZz8ucHJpdmF0ZUtleUp3aykgcmV0dXJuIGV4aXN0aW5nO1xuICAgIH0gY2F0Y2gge1xuICAgICAgLy8gaWdub3JlIGFuZCBjb250aW51ZSAod2UgY2FuIGFsd2F5cyByZS1nZW5lcmF0ZSlcbiAgICB9XG4gIH1cblxuICAvLyAyKSBPbmUtdGltZSBtaWdyYXRpb246IGxlZ2FjeSBsb2NhbFN0b3JhZ2UgaWRlbnRpdHkuXG4gIC8vIE5PVEU6IHRoaXMgcmVtYWlucyBhIHJpc2sgYm91bmRhcnk7IHdlIG9ubHkgcmVhZCtkZWxldGUgZm9yIG1pZ3JhdGlvbi5cbiAgY29uc3QgbGVnYWN5ID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oREVWSUNFX1NUT1JBR0VfS0VZKTtcbiAgaWYgKGxlZ2FjeSkge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCBwYXJzZWQgPSBKU09OLnBhcnNlKGxlZ2FjeSkgYXMgRGV2aWNlSWRlbnRpdHk7XG4gICAgICBpZiAocGFyc2VkPy5pZCAmJiBwYXJzZWQ/LnB1YmxpY0tleSAmJiBwYXJzZWQ/LnByaXZhdGVLZXlKd2spIHtcbiAgICAgICAgaWYgKHN0b3JlKSB7XG4gICAgICAgICAgYXdhaXQgc3RvcmUuc2V0KHBhcnNlZCk7XG4gICAgICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oREVWSUNFX1NUT1JBR0VfS0VZKTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gcGFyc2VkO1xuICAgICAgfVxuICAgIH0gY2F0Y2gge1xuICAgICAgLy8gQ29ycnVwdC9wYXJ0aWFsIGRhdGEgXHUyMTkyIGRlbGV0ZSBhbmQgcmUtY3JlYXRlLlxuICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oREVWSUNFX1NUT1JBR0VfS0VZKTtcbiAgICB9XG4gIH1cblxuICAvLyAzKSBDcmVhdGUgYSBuZXcgaWRlbnRpdHkuXG4gIGNvbnN0IGtleVBhaXIgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmdlbmVyYXRlS2V5KHsgbmFtZTogJ0VkMjU1MTknIH0sIHRydWUsIFsnc2lnbicsICd2ZXJpZnknXSk7XG4gIGNvbnN0IHB1YlJhdyA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuZXhwb3J0S2V5KCdyYXcnLCBrZXlQYWlyLnB1YmxpY0tleSk7XG4gIGNvbnN0IHByaXZKd2sgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmV4cG9ydEtleSgnandrJywga2V5UGFpci5wcml2YXRlS2V5KTtcblxuICAvLyBJTVBPUlRBTlQ6IGRldmljZS5pZCBtdXN0IGJlIGEgc3RhYmxlIGZpbmdlcnByaW50IGZvciB0aGUgcHVibGljIGtleS5cbiAgLy8gVGhlIGdhdGV3YXkgZW5mb3JjZXMgZGV2aWNlSWQgXHUyMTk0IHB1YmxpY0tleSBiaW5kaW5nOyByYW5kb20gaWRzIGNhbiBjYXVzZSBcImRldmljZSBpZGVudGl0eSBtaXNtYXRjaFwiLlxuICBjb25zdCBkZXZpY2VJZCA9IGF3YWl0IHNoYTI1NkhleChwdWJSYXcpO1xuXG4gIGNvbnN0IGlkZW50aXR5OiBEZXZpY2VJZGVudGl0eSA9IHtcbiAgICBpZDogZGV2aWNlSWQsXG4gICAgcHVibGljS2V5OiBiYXNlNjRVcmxFbmNvZGUocHViUmF3KSxcbiAgICBwcml2YXRlS2V5SndrOiBwcml2SndrLFxuICB9O1xuXG4gIGlmIChzdG9yZSkge1xuICAgIGF3YWl0IHN0b3JlLnNldChpZGVudGl0eSk7XG4gIH0gZWxzZSB7XG4gICAgLy8gRmFsbGJhY2sgKHNob3VsZCBub3QgaGFwcGVuIGluIHJlYWwgcGx1Z2luIHJ1bnRpbWUpIFx1MjAxNCBrZWVwIGxlZ2FjeSBiZWhhdmlvci5cbiAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbShERVZJQ0VfU1RPUkFHRV9LRVksIEpTT04uc3RyaW5naWZ5KGlkZW50aXR5KSk7XG4gIH1cblxuICByZXR1cm4gaWRlbnRpdHk7XG59XG5cbmZ1bmN0aW9uIGJ1aWxkRGV2aWNlQXV0aFBheWxvYWQocGFyYW1zOiB7XG4gIGRldmljZUlkOiBzdHJpbmc7XG4gIGNsaWVudElkOiBzdHJpbmc7XG4gIGNsaWVudE1vZGU6IHN0cmluZztcbiAgcm9sZTogc3RyaW5nO1xuICBzY29wZXM6IHN0cmluZ1tdO1xuICBzaWduZWRBdE1zOiBudW1iZXI7XG4gIHRva2VuOiBzdHJpbmc7XG4gIG5vbmNlPzogc3RyaW5nO1xufSk6IHN0cmluZyB7XG4gIGNvbnN0IHZlcnNpb24gPSBwYXJhbXMubm9uY2UgPyAndjInIDogJ3YxJztcbiAgY29uc3Qgc2NvcGVzID0gcGFyYW1zLnNjb3Blcy5qb2luKCcsJyk7XG4gIGNvbnN0IGJhc2UgPSBbXG4gICAgdmVyc2lvbixcbiAgICBwYXJhbXMuZGV2aWNlSWQsXG4gICAgcGFyYW1zLmNsaWVudElkLFxuICAgIHBhcmFtcy5jbGllbnRNb2RlLFxuICAgIHBhcmFtcy5yb2xlLFxuICAgIHNjb3BlcyxcbiAgICBTdHJpbmcocGFyYW1zLnNpZ25lZEF0TXMpLFxuICAgIHBhcmFtcy50b2tlbiB8fCAnJyxcbiAgXTtcbiAgaWYgKHZlcnNpb24gPT09ICd2MicpIGJhc2UucHVzaChwYXJhbXMubm9uY2UgfHwgJycpO1xuICByZXR1cm4gYmFzZS5qb2luKCd8Jyk7XG59XG5cbmFzeW5jIGZ1bmN0aW9uIHNpZ25EZXZpY2VQYXlsb2FkKGlkZW50aXR5OiBEZXZpY2VJZGVudGl0eSwgcGF5bG9hZDogc3RyaW5nKTogUHJvbWlzZTx7IHNpZ25hdHVyZTogc3RyaW5nIH0+IHtcbiAgY29uc3QgcHJpdmF0ZUtleSA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KFxuICAgICdqd2snLFxuICAgIGlkZW50aXR5LnByaXZhdGVLZXlKd2ssXG4gICAgeyBuYW1lOiAnRWQyNTUxOScgfSxcbiAgICBmYWxzZSxcbiAgICBbJ3NpZ24nXSxcbiAgKTtcblxuICBjb25zdCBzaWcgPSBhd2FpdCBjcnlwdG8uc3VidGxlLnNpZ24oeyBuYW1lOiAnRWQyNTUxOScgfSwgcHJpdmF0ZUtleSwgdXRmOEJ5dGVzKHBheWxvYWQpIGFzIHVua25vd24gYXMgQnVmZmVyU291cmNlKTtcbiAgcmV0dXJuIHsgc2lnbmF0dXJlOiBiYXNlNjRVcmxFbmNvZGUoc2lnKSB9O1xufVxuXG5mdW5jdGlvbiBleHRyYWN0VGV4dEZyb21HYXRld2F5TWVzc2FnZShtc2c6IGFueSk6IHN0cmluZyB7XG4gIGlmICghbXNnKSByZXR1cm4gJyc7XG5cbiAgLy8gTW9zdCBjb21tb246IHsgcm9sZSwgY29udGVudCB9IHdoZXJlIGNvbnRlbnQgY2FuIGJlIHN0cmluZyBvciBbe3R5cGU6J3RleHQnLHRleHQ6Jy4uLid9XVxuICBjb25zdCBjb250ZW50ID0gbXNnLmNvbnRlbnQgPz8gbXNnLm1lc3NhZ2UgPz8gbXNnO1xuICBpZiAodHlwZW9mIGNvbnRlbnQgPT09ICdzdHJpbmcnKSByZXR1cm4gY29udGVudDtcblxuICBpZiAoQXJyYXkuaXNBcnJheShjb250ZW50KSkge1xuICAgIGNvbnN0IHBhcnRzID0gY29udGVudFxuICAgICAgLmZpbHRlcigoYykgPT4gYyAmJiB0eXBlb2YgYyA9PT0gJ29iamVjdCcgJiYgYy50eXBlID09PSAndGV4dCcgJiYgdHlwZW9mIGMudGV4dCA9PT0gJ3N0cmluZycpXG4gICAgICAubWFwKChjKSA9PiBjLnRleHQpO1xuICAgIHJldHVybiBwYXJ0cy5qb2luKCdcXG4nKTtcbiAgfVxuXG4gIC8vIEZhbGxiYWNrXG4gIHRyeSB7XG4gICAgcmV0dXJuIEpTT04uc3RyaW5naWZ5KGNvbnRlbnQpO1xuICB9IGNhdGNoIHtcbiAgICByZXR1cm4gU3RyaW5nKGNvbnRlbnQpO1xuICB9XG59XG5cbmZ1bmN0aW9uIHNlc3Npb25LZXlNYXRjaGVzKGNvbmZpZ3VyZWQ6IHN0cmluZywgaW5jb21pbmc6IHN0cmluZyk6IGJvb2xlYW4ge1xuICBpZiAoaW5jb21pbmcgPT09IGNvbmZpZ3VyZWQpIHJldHVybiB0cnVlO1xuICAvLyBPcGVuQ2xhdyByZXNvbHZlcyBcIm1haW5cIiB0byBjYW5vbmljYWwgc2Vzc2lvbiBrZXkgbGlrZSBcImFnZW50Om1haW46bWFpblwiLlxuICBpZiAoY29uZmlndXJlZCA9PT0gJ21haW4nICYmIGluY29taW5nID09PSAnYWdlbnQ6bWFpbjptYWluJykgcmV0dXJuIHRydWU7XG4gIHJldHVybiBmYWxzZTtcbn1cblxuZXhwb3J0IGNsYXNzIE9ic2lkaWFuV1NDbGllbnQge1xuICBwcml2YXRlIHdzOiBXZWJTb2NrZXQgfCBudWxsID0gbnVsbDtcbiAgcHJpdmF0ZSByZWNvbm5lY3RUaW1lcjogUmV0dXJuVHlwZTx0eXBlb2Ygc2V0VGltZW91dD4gfCBudWxsID0gbnVsbDtcbiAgcHJpdmF0ZSBoZWFydGJlYXRUaW1lcjogUmV0dXJuVHlwZTx0eXBlb2Ygc2V0SW50ZXJ2YWw+IHwgbnVsbCA9IG51bGw7XG4gIHByaXZhdGUgd29ya2luZ1RpbWVyOiBSZXR1cm5UeXBlPHR5cGVvZiBzZXRUaW1lb3V0PiB8IG51bGwgPSBudWxsO1xuICBwcml2YXRlIGludGVudGlvbmFsQ2xvc2UgPSBmYWxzZTtcbiAgcHJpdmF0ZSBzZXNzaW9uS2V5OiBzdHJpbmc7XG4gIHByaXZhdGUgdXJsID0gJyc7XG4gIHByaXZhdGUgdG9rZW4gPSAnJztcbiAgcHJpdmF0ZSByZXF1ZXN0SWQgPSAwO1xuICBwcml2YXRlIHBlbmRpbmdSZXF1ZXN0cyA9IG5ldyBNYXA8c3RyaW5nLCBQZW5kaW5nUmVxdWVzdD4oKTtcbiAgcHJpdmF0ZSB3b3JraW5nID0gZmFsc2U7XG5cbiAgLyoqIFRoZSBsYXN0IGluLWZsaWdodCBjaGF0IHJ1biBpZC4gSW4gT3BlbkNsYXcgV2ViQ2hhdCB0aGlzIG1hcHMgdG8gY2hhdC5zZW5kIGlkZW1wb3RlbmN5S2V5LiAqL1xuICBwcml2YXRlIGFjdGl2ZVJ1bklkOiBzdHJpbmcgfCBudWxsID0gbnVsbDtcblxuICAvKiogUHJldmVudHMgYWJvcnQgc3BhbW1pbmc6IHdoaWxlIGFuIGFib3J0IHJlcXVlc3QgaXMgaW4tZmxpZ2h0LCByZXVzZSB0aGUgc2FtZSBwcm9taXNlLiAqL1xuICBwcml2YXRlIGFib3J0SW5GbGlnaHQ6IFByb21pc2U8Ym9vbGVhbj4gfCBudWxsID0gbnVsbDtcblxuICBzdGF0ZTogV1NDbGllbnRTdGF0ZSA9ICdkaXNjb25uZWN0ZWQnO1xuXG4gIG9uTWVzc2FnZTogKChtc2c6IEluYm91bmRXU1BheWxvYWQpID0+IHZvaWQpIHwgbnVsbCA9IG51bGw7XG4gIG9uU3RhdGVDaGFuZ2U6ICgoc3RhdGU6IFdTQ2xpZW50U3RhdGUpID0+IHZvaWQpIHwgbnVsbCA9IG51bGw7XG4gIG9uV29ya2luZ0NoYW5nZTogV29ya2luZ1N0YXRlTGlzdGVuZXIgfCBudWxsID0gbnVsbDtcblxuICBwcml2YXRlIGlkZW50aXR5U3RvcmU6IERldmljZUlkZW50aXR5U3RvcmUgfCB1bmRlZmluZWQ7XG4gIHByaXZhdGUgYWxsb3dJbnNlY3VyZVdzID0gZmFsc2U7XG5cbiAgcHJpdmF0ZSByZWNvbm5lY3RBdHRlbXB0ID0gMDtcblxuICBjb25zdHJ1Y3RvcihzZXNzaW9uS2V5OiBzdHJpbmcsIG9wdHM/OiB7IGlkZW50aXR5U3RvcmU/OiBEZXZpY2VJZGVudGl0eVN0b3JlOyBhbGxvd0luc2VjdXJlV3M/OiBib29sZWFuIH0pIHtcbiAgICB0aGlzLnNlc3Npb25LZXkgPSBzZXNzaW9uS2V5O1xuICAgIHRoaXMuaWRlbnRpdHlTdG9yZSA9IG9wdHM/LmlkZW50aXR5U3RvcmU7XG4gICAgdGhpcy5hbGxvd0luc2VjdXJlV3MgPSBCb29sZWFuKG9wdHM/LmFsbG93SW5zZWN1cmVXcyk7XG4gIH1cblxuICBjb25uZWN0KHVybDogc3RyaW5nLCB0b2tlbjogc3RyaW5nLCBvcHRzPzogeyBhbGxvd0luc2VjdXJlV3M/OiBib29sZWFuIH0pOiB2b2lkIHtcbiAgICB0aGlzLnVybCA9IHVybDtcbiAgICB0aGlzLnRva2VuID0gdG9rZW47XG4gICAgdGhpcy5hbGxvd0luc2VjdXJlV3MgPSBCb29sZWFuKG9wdHM/LmFsbG93SW5zZWN1cmVXcyA/PyB0aGlzLmFsbG93SW5zZWN1cmVXcyk7XG4gICAgdGhpcy5pbnRlbnRpb25hbENsb3NlID0gZmFsc2U7XG5cbiAgICAvLyBTZWN1cml0eTogYmxvY2sgbm9uLWxvY2FsIHdzOi8vIHVubGVzcyBleHBsaWNpdGx5IGFsbG93ZWQuXG4gICAgY29uc3QgcGFyc2VkID0gc2FmZVBhcnNlV3NVcmwodXJsKTtcbiAgICBpZiAoIXBhcnNlZC5vaykge1xuICAgICAgdGhpcy5vbk1lc3NhZ2U/Lih7IHR5cGU6ICdlcnJvcicsIHBheWxvYWQ6IHsgbWVzc2FnZTogcGFyc2VkLmVycm9yIH0gfSk7XG4gICAgICByZXR1cm47XG4gICAgfVxuICAgIGlmIChwYXJzZWQuc2NoZW1lID09PSAnd3MnICYmICFpc0xvY2FsSG9zdChwYXJzZWQuaG9zdCkgJiYgIXRoaXMuYWxsb3dJbnNlY3VyZVdzKSB7XG4gICAgICB0aGlzLm9uTWVzc2FnZT8uKHtcbiAgICAgICAgdHlwZTogJ2Vycm9yJyxcbiAgICAgICAgcGF5bG9hZDogeyBtZXNzYWdlOiAnUmVmdXNpbmcgaW5zZWN1cmUgd3M6Ly8gdG8gbm9uLWxvY2FsIGdhdGV3YXkuIFVzZSB3c3M6Ly8gb3IgZW5hYmxlIHRoZSB1bnNhZmUgb3ZlcnJpZGUgaW4gc2V0dGluZ3MuJyB9LFxuICAgICAgfSk7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgdGhpcy5fY29ubmVjdCgpO1xuICB9XG5cbiAgZGlzY29ubmVjdCgpOiB2b2lkIHtcbiAgICB0aGlzLmludGVudGlvbmFsQ2xvc2UgPSB0cnVlO1xuICAgIHRoaXMuX3N0b3BUaW1lcnMoKTtcbiAgICB0aGlzLmFjdGl2ZVJ1bklkID0gbnVsbDtcbiAgICB0aGlzLmFib3J0SW5GbGlnaHQgPSBudWxsO1xuICAgIHRoaXMuX3NldFdvcmtpbmcoZmFsc2UpO1xuICAgIGlmICh0aGlzLndzKSB7XG4gICAgICB0aGlzLndzLmNsb3NlKCk7XG4gICAgICB0aGlzLndzID0gbnVsbDtcbiAgICB9XG4gICAgdGhpcy5fc2V0U3RhdGUoJ2Rpc2Nvbm5lY3RlZCcpO1xuICB9XG5cbiAgc2V0U2Vzc2lvbktleShzZXNzaW9uS2V5OiBzdHJpbmcpOiB2b2lkIHtcbiAgICB0aGlzLnNlc3Npb25LZXkgPSBzZXNzaW9uS2V5LnRyaW0oKTtcbiAgICAvLyBSZXNldCBwZXItc2Vzc2lvbiBydW4gc3RhdGUuXG4gICAgdGhpcy5hY3RpdmVSdW5JZCA9IG51bGw7XG4gICAgdGhpcy5hYm9ydEluRmxpZ2h0ID0gbnVsbDtcbiAgICB0aGlzLl9zZXRXb3JraW5nKGZhbHNlKTtcbiAgfVxuXG4gIC8vIE5PVEU6IGNhbm9uaWNhbCBPYnNpZGlhbiBzZXNzaW9uIGtleXMgZG8gbm90IHJlcXVpcmUgZ2F0ZXdheSBzZXNzaW9ucy5saXN0IGZvciBjb3JlIFVYLlxuXG4gIGFzeW5jIHNlbmRNZXNzYWdlKG1lc3NhZ2U6IHN0cmluZyk6IFByb21pc2U8dm9pZD4ge1xuICAgIGlmICh0aGlzLnN0YXRlICE9PSAnY29ubmVjdGVkJykge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKCdOb3QgY29ubmVjdGVkIFx1MjAxNCBjYWxsIGNvbm5lY3QoKSBmaXJzdCcpO1xuICAgIH1cblxuICAgIGNvbnN0IHJ1bklkID0gYG9ic2lkaWFuLSR7RGF0ZS5ub3coKX0tJHtNYXRoLnJhbmRvbSgpLnRvU3RyaW5nKDM2KS5zbGljZSgyLCA5KX1gO1xuXG4gICAgLy8gU2hvdyBcdTIwMUN3b3JraW5nXHUyMDFEIE9OTFkgYWZ0ZXIgdGhlIGdhdGV3YXkgYWNrbm93bGVkZ2VzIHRoZSByZXF1ZXN0LlxuICAgIGNvbnN0IGFjayA9IGF3YWl0IHRoaXMuX3NlbmRSZXF1ZXN0KCdjaGF0LnNlbmQnLCB7XG4gICAgICBzZXNzaW9uS2V5OiB0aGlzLnNlc3Npb25LZXksXG4gICAgICBtZXNzYWdlLFxuICAgICAgaWRlbXBvdGVuY3lLZXk6IHJ1bklkLFxuICAgICAgLy8gZGVsaXZlciBkZWZhdWx0cyB0byB0cnVlIGluIGdhdGV3YXk7IGtlZXAgZGVmYXVsdFxuICAgIH0pO1xuXG4gICAgLy8gSWYgdGhlIGdhdGV3YXkgcmV0dXJucyBhIGNhbm9uaWNhbCBydW4gaWRlbnRpZmllciwgcHJlZmVyIGl0LlxuICAgIGNvbnN0IGNhbm9uaWNhbFJ1bklkID0gU3RyaW5nKGFjaz8ucnVuSWQgfHwgYWNrPy5pZGVtcG90ZW5jeUtleSB8fCAnJyk7XG4gICAgdGhpcy5hY3RpdmVSdW5JZCA9IGNhbm9uaWNhbFJ1bklkIHx8IHJ1bklkO1xuICAgIHRoaXMuX3NldFdvcmtpbmcodHJ1ZSk7XG4gICAgdGhpcy5fYXJtV29ya2luZ1NhZmV0eVRpbWVvdXQoKTtcbiAgfVxuXG4gIC8qKiBBYm9ydCB0aGUgYWN0aXZlIHJ1biBmb3IgdGhpcyBzZXNzaW9uIChhbmQgb3VyIGxhc3QgcnVuIGlkIGlmIHByZXNlbnQpLiAqL1xuICBhc3luYyBhYm9ydEFjdGl2ZVJ1bigpOiBQcm9taXNlPGJvb2xlYW4+IHtcbiAgICBpZiAodGhpcy5zdGF0ZSAhPT0gJ2Nvbm5lY3RlZCcpIHtcbiAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG5cbiAgICAvLyBQcmV2ZW50IHJlcXVlc3Qgc3Rvcm1zOiB3aGlsZSBvbmUgYWJvcnQgaXMgaW4gZmxpZ2h0LCByZXVzZSBpdC5cbiAgICBpZiAodGhpcy5hYm9ydEluRmxpZ2h0KSB7XG4gICAgICByZXR1cm4gdGhpcy5hYm9ydEluRmxpZ2h0O1xuICAgIH1cblxuICAgIGNvbnN0IHJ1bklkID0gdGhpcy5hY3RpdmVSdW5JZDtcbiAgICBpZiAoIXJ1bklkKSB7XG4gICAgICByZXR1cm4gZmFsc2U7XG4gICAgfVxuXG4gICAgdGhpcy5hYm9ydEluRmxpZ2h0ID0gKGFzeW5jICgpID0+IHtcbiAgICAgIHRyeSB7XG4gICAgICAgIGF3YWl0IHRoaXMuX3NlbmRSZXF1ZXN0KCdjaGF0LmFib3J0JywgeyBzZXNzaW9uS2V5OiB0aGlzLnNlc3Npb25LZXksIHJ1bklkIH0pO1xuICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgIH0gY2F0Y2ggKGVycikge1xuICAgICAgICBjb25zb2xlLmVycm9yKCdbb2NsYXctd3NdIGNoYXQuYWJvcnQgZmFpbGVkJywgZXJyKTtcbiAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgfSBmaW5hbGx5IHtcbiAgICAgICAgLy8gQWx3YXlzIHJlc3RvcmUgVUkgc3RhdGUgaW1tZWRpYXRlbHk7IHRoZSBnYXRld2F5IG1heSBzdGlsbCBlbWl0IGFuIGFib3J0ZWQgZXZlbnQgbGF0ZXIuXG4gICAgICAgIHRoaXMuYWN0aXZlUnVuSWQgPSBudWxsO1xuICAgICAgICB0aGlzLl9zZXRXb3JraW5nKGZhbHNlKTtcbiAgICAgICAgdGhpcy5hYm9ydEluRmxpZ2h0ID0gbnVsbDtcbiAgICAgIH1cbiAgICB9KSgpO1xuXG4gICAgcmV0dXJuIHRoaXMuYWJvcnRJbkZsaWdodDtcbiAgfVxuXG4gIHByaXZhdGUgX2Nvbm5lY3QoKTogdm9pZCB7XG4gICAgaWYgKHRoaXMud3MpIHtcbiAgICAgIHRoaXMud3Mub25vcGVuID0gbnVsbDtcbiAgICAgIHRoaXMud3Mub25jbG9zZSA9IG51bGw7XG4gICAgICB0aGlzLndzLm9ubWVzc2FnZSA9IG51bGw7XG4gICAgICB0aGlzLndzLm9uZXJyb3IgPSBudWxsO1xuICAgICAgdGhpcy53cy5jbG9zZSgpO1xuICAgICAgdGhpcy53cyA9IG51bGw7XG4gICAgfVxuXG4gICAgdGhpcy5fc2V0U3RhdGUoJ2Nvbm5lY3RpbmcnKTtcblxuICAgIGNvbnN0IHdzID0gbmV3IFdlYlNvY2tldCh0aGlzLnVybCk7XG4gICAgdGhpcy53cyA9IHdzO1xuXG4gICAgbGV0IGNvbm5lY3ROb25jZTogc3RyaW5nIHwgbnVsbCA9IG51bGw7XG4gICAgbGV0IGNvbm5lY3RTdGFydGVkID0gZmFsc2U7XG5cbiAgICBjb25zdCB0cnlDb25uZWN0ID0gYXN5bmMgKCkgPT4ge1xuICAgICAgaWYgKGNvbm5lY3RTdGFydGVkKSByZXR1cm47XG4gICAgICBpZiAoIWNvbm5lY3ROb25jZSkgcmV0dXJuO1xuICAgICAgY29ubmVjdFN0YXJ0ZWQgPSB0cnVlO1xuXG4gICAgICB0cnkge1xuICAgICAgICBjb25zdCBpZGVudGl0eSA9IGF3YWl0IGxvYWRPckNyZWF0ZURldmljZUlkZW50aXR5KHRoaXMuaWRlbnRpdHlTdG9yZSk7XG4gICAgICAgIGNvbnN0IHNpZ25lZEF0TXMgPSBEYXRlLm5vdygpO1xuICAgICAgICBjb25zdCBwYXlsb2FkID0gYnVpbGREZXZpY2VBdXRoUGF5bG9hZCh7XG4gICAgICAgICAgZGV2aWNlSWQ6IGlkZW50aXR5LmlkLFxuICAgICAgICAgIGNsaWVudElkOiAnZ2F0ZXdheS1jbGllbnQnLFxuICAgICAgICAgIGNsaWVudE1vZGU6ICdiYWNrZW5kJyxcbiAgICAgICAgICByb2xlOiAnb3BlcmF0b3InLFxuICAgICAgICAgIHNjb3BlczogWydvcGVyYXRvci5yZWFkJywgJ29wZXJhdG9yLndyaXRlJ10sXG4gICAgICAgICAgc2lnbmVkQXRNcyxcbiAgICAgICAgICB0b2tlbjogdGhpcy50b2tlbixcbiAgICAgICAgICBub25jZTogY29ubmVjdE5vbmNlLFxuICAgICAgICB9KTtcbiAgICAgICAgY29uc3Qgc2lnID0gYXdhaXQgc2lnbkRldmljZVBheWxvYWQoaWRlbnRpdHksIHBheWxvYWQpO1xuXG4gICAgICAgIGNvbnN0IGFjayA9IGF3YWl0IHRoaXMuX3NlbmRSZXF1ZXN0KCdjb25uZWN0Jywge1xuICAgICAgICAgICBtaW5Qcm90b2NvbDogMyxcbiAgICAgICAgICAgbWF4UHJvdG9jb2w6IDMsXG4gICAgICAgICAgIGNsaWVudDoge1xuICAgICAgICAgICAgIGlkOiAnZ2F0ZXdheS1jbGllbnQnLFxuICAgICAgICAgICAgIG1vZGU6ICdiYWNrZW5kJyxcbiAgICAgICAgICAgICB2ZXJzaW9uOiAnMC4xLjEwJyxcbiAgICAgICAgICAgICBwbGF0Zm9ybTogJ2VsZWN0cm9uJyxcbiAgICAgICAgICAgfSxcbiAgICAgICAgICAgcm9sZTogJ29wZXJhdG9yJyxcbiAgICAgICAgICAgc2NvcGVzOiBbJ29wZXJhdG9yLnJlYWQnLCAnb3BlcmF0b3Iud3JpdGUnXSxcbiAgICAgICAgICAgZGV2aWNlOiB7XG4gICAgICAgICAgICAgaWQ6IGlkZW50aXR5LmlkLFxuICAgICAgICAgICAgIHB1YmxpY0tleTogaWRlbnRpdHkucHVibGljS2V5LFxuICAgICAgICAgICAgIHNpZ25hdHVyZTogc2lnLnNpZ25hdHVyZSxcbiAgICAgICAgICAgICBzaWduZWRBdDogc2lnbmVkQXRNcyxcbiAgICAgICAgICAgICBub25jZTogY29ubmVjdE5vbmNlLFxuICAgICAgICAgICB9LFxuICAgICAgICAgICBhdXRoOiB7XG4gICAgICAgICAgICAgdG9rZW46IHRoaXMudG9rZW4sXG4gICAgICAgICAgIH0sXG4gICAgICAgICB9KTtcblxuICAgICAgICAgdGhpcy5fc2V0U3RhdGUoJ2Nvbm5lY3RlZCcpO1xuICAgICAgICAgdGhpcy5yZWNvbm5lY3RBdHRlbXB0ID0gMDtcbiAgICAgICAgIGlmIChoYW5kc2hha2VUaW1lcikge1xuICAgICAgICAgICBjbGVhclRpbWVvdXQoaGFuZHNoYWtlVGltZXIpO1xuICAgICAgICAgICBoYW5kc2hha2VUaW1lciA9IG51bGw7XG4gICAgICAgICB9XG4gICAgICAgICB0aGlzLl9zdGFydEhlYXJ0YmVhdCgpO1xuICAgICAgfSBjYXRjaCAoZXJyKSB7XG4gICAgICAgIGNvbnNvbGUuZXJyb3IoJ1tvY2xhdy13c10gQ29ubmVjdCBoYW5kc2hha2UgZmFpbGVkJywgZXJyKTtcbiAgICAgICAgd3MuY2xvc2UoKTtcbiAgICAgIH1cbiAgICB9O1xuXG4gICAgbGV0IGhhbmRzaGFrZVRpbWVyOiBSZXR1cm5UeXBlPHR5cGVvZiBzZXRUaW1lb3V0PiB8IG51bGwgPSBudWxsO1xuXG4gICAgd3Mub25vcGVuID0gKCkgPT4ge1xuICAgICAgdGhpcy5fc2V0U3RhdGUoJ2hhbmRzaGFraW5nJyk7XG4gICAgICAvLyBUaGUgZ2F0ZXdheSB3aWxsIHNlbmQgY29ubmVjdC5jaGFsbGVuZ2U7IGNvbm5lY3QgaXMgc2VudCBvbmNlIHdlIGhhdmUgYSBub25jZS5cbiAgICAgIGlmIChoYW5kc2hha2VUaW1lcikgY2xlYXJUaW1lb3V0KGhhbmRzaGFrZVRpbWVyKTtcbiAgICAgIGhhbmRzaGFrZVRpbWVyID0gc2V0VGltZW91dCgoKSA9PiB7XG4gICAgICAgIC8vIElmIHdlIG5ldmVyIGdvdCB0aGUgY2hhbGxlbmdlIG5vbmNlLCBmb3JjZSByZWNvbm5lY3QuXG4gICAgICAgIGlmICh0aGlzLnN0YXRlID09PSAnaGFuZHNoYWtpbmcnICYmICF0aGlzLmludGVudGlvbmFsQ2xvc2UpIHtcbiAgICAgICAgICBjb25zb2xlLndhcm4oJ1tvY2xhdy13c10gSGFuZHNoYWtlIHRpbWVkIG91dCB3YWl0aW5nIGZvciBjb25uZWN0LmNoYWxsZW5nZScpO1xuICAgICAgICAgIHdzLmNsb3NlKCk7XG4gICAgICAgIH1cbiAgICAgIH0sIEhBTkRTSEFLRV9USU1FT1VUX01TKTtcbiAgICB9O1xuXG4gICAgd3Mub25tZXNzYWdlID0gKGV2ZW50OiBNZXNzYWdlRXZlbnQpID0+IHtcbiAgICAgIC8vIFdlYlNvY2tldCBvbm1lc3NhZ2UgY2Fubm90IGJlIGFzeW5jLCBidXQgd2UgY2FuIHJ1biBhbiBhc3luYyB0YXNrIGluc2lkZS5cbiAgICAgIHZvaWQgKGFzeW5jICgpID0+IHtcbiAgICAgICAgY29uc3Qgbm9ybWFsaXplZCA9IGF3YWl0IG5vcm1hbGl6ZVdzRGF0YVRvVGV4dChldmVudC5kYXRhKTtcbiAgICAgICAgaWYgKCFub3JtYWxpemVkLm9rKSB7XG4gICAgICAgICAgaWYgKG5vcm1hbGl6ZWQucmVhc29uID09PSAndG9vLWxhcmdlJykge1xuICAgICAgICAgICAgY29uc29sZS5lcnJvcignW29jbGF3LXdzXSBJbmJvdW5kIGZyYW1lIHRvbyBsYXJnZTsgY2xvc2luZyBjb25uZWN0aW9uJyk7XG4gICAgICAgICAgICB3cy5jbG9zZSgpO1xuICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBjb25zb2xlLmVycm9yKCdbb2NsYXctd3NdIFVuc3VwcG9ydGVkIGluYm91bmQgZnJhbWUgdHlwZTsgaWdub3JpbmcnKTtcbiAgICAgICAgICB9XG4gICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKG5vcm1hbGl6ZWQuYnl0ZXMgPiBNQVhfSU5CT1VORF9GUkFNRV9CWVRFUykge1xuICAgICAgICAgIGNvbnNvbGUuZXJyb3IoJ1tvY2xhdy13c10gSW5ib3VuZCBmcmFtZSB0b28gbGFyZ2U7IGNsb3NpbmcgY29ubmVjdGlvbicpO1xuICAgICAgICAgIHdzLmNsb3NlKCk7XG4gICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgbGV0IGZyYW1lOiBhbnk7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgZnJhbWUgPSBKU09OLnBhcnNlKG5vcm1hbGl6ZWQudGV4dCk7XG4gICAgICAgIH0gY2F0Y2gge1xuICAgICAgICAgIGNvbnNvbGUuZXJyb3IoJ1tvY2xhdy13c10gRmFpbGVkIHRvIHBhcnNlIGluY29taW5nIG1lc3NhZ2UnKTtcbiAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICAvLyBSZXNwb25zZXNcbiAgICAgICAgaWYgKGZyYW1lLnR5cGUgPT09ICdyZXMnKSB7XG4gICAgICAgICAgdGhpcy5faGFuZGxlUmVzcG9uc2VGcmFtZShmcmFtZSk7XG4gICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgLy8gRXZlbnRzXG4gICAgICAgIGlmIChmcmFtZS50eXBlID09PSAnZXZlbnQnKSB7XG4gICAgICAgICAgaWYgKGZyYW1lLmV2ZW50ID09PSAnY29ubmVjdC5jaGFsbGVuZ2UnKSB7XG4gICAgICAgICAgICBjb25uZWN0Tm9uY2UgPSBmcmFtZS5wYXlsb2FkPy5ub25jZSB8fCBudWxsO1xuICAgICAgICAgICAgLy8gQXR0ZW1wdCBoYW5kc2hha2Ugb25jZSB3ZSBoYXZlIGEgbm9uY2UuXG4gICAgICAgICAgICB2b2lkIHRyeUNvbm5lY3QoKTtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBpZiAoZnJhbWUuZXZlbnQgPT09ICdjaGF0Jykge1xuICAgICAgICAgICAgdGhpcy5faGFuZGxlQ2hhdEV2ZW50RnJhbWUoZnJhbWUpO1xuICAgICAgICAgIH1cbiAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICAvLyBBdm9pZCBsb2dnaW5nIGZ1bGwgZnJhbWVzIChtYXkgaW5jbHVkZSBtZXNzYWdlIGNvbnRlbnQgb3Igb3RoZXIgc2Vuc2l0aXZlIHBheWxvYWRzKS5cbiAgICAgICAgY29uc29sZS5kZWJ1ZygnW29jbGF3LXdzXSBVbmhhbmRsZWQgZnJhbWUnLCB7IHR5cGU6IGZyYW1lPy50eXBlLCBldmVudDogZnJhbWU/LmV2ZW50LCBpZDogZnJhbWU/LmlkIH0pO1xuICAgICAgfSkoKTtcbiAgICB9O1xuXG4gICAgY29uc3QgY2xlYXJIYW5kc2hha2VUaW1lciA9ICgpID0+IHtcbiAgICAgIGlmIChoYW5kc2hha2VUaW1lcikge1xuICAgICAgICBjbGVhclRpbWVvdXQoaGFuZHNoYWtlVGltZXIpO1xuICAgICAgICBoYW5kc2hha2VUaW1lciA9IG51bGw7XG4gICAgICB9XG4gICAgfTtcblxuICAgIHdzLm9uY2xvc2UgPSAoKSA9PiB7XG4gICAgICBjbGVhckhhbmRzaGFrZVRpbWVyKCk7XG4gICAgICB0aGlzLl9zdG9wVGltZXJzKCk7XG4gICAgICB0aGlzLmFjdGl2ZVJ1bklkID0gbnVsbDtcbiAgICAgIHRoaXMuYWJvcnRJbkZsaWdodCA9IG51bGw7XG4gICAgICB0aGlzLl9zZXRXb3JraW5nKGZhbHNlKTtcbiAgICAgIHRoaXMuX3NldFN0YXRlKCdkaXNjb25uZWN0ZWQnKTtcblxuICAgICAgZm9yIChjb25zdCBwZW5kaW5nIG9mIHRoaXMucGVuZGluZ1JlcXVlc3RzLnZhbHVlcygpKSB7XG4gICAgICAgIGlmIChwZW5kaW5nLnRpbWVvdXQpIGNsZWFyVGltZW91dChwZW5kaW5nLnRpbWVvdXQpO1xuICAgICAgICBwZW5kaW5nLnJlamVjdChuZXcgRXJyb3IoJ0Nvbm5lY3Rpb24gY2xvc2VkJykpO1xuICAgICAgfVxuICAgICAgdGhpcy5wZW5kaW5nUmVxdWVzdHMuY2xlYXIoKTtcblxuICAgICAgaWYgKCF0aGlzLmludGVudGlvbmFsQ2xvc2UpIHtcbiAgICAgICAgdGhpcy5fc2NoZWR1bGVSZWNvbm5lY3QoKTtcbiAgICAgIH1cbiAgICB9O1xuXG4gICAgd3Mub25lcnJvciA9IChldjogRXZlbnQpID0+IHtcbiAgICAgIGNsZWFySGFuZHNoYWtlVGltZXIoKTtcbiAgICAgIGNvbnNvbGUuZXJyb3IoJ1tvY2xhdy13c10gV2ViU29ja2V0IGVycm9yJywgZXYpO1xuICAgIH07XG4gIH1cblxuICBwcml2YXRlIF9oYW5kbGVSZXNwb25zZUZyYW1lKGZyYW1lOiBhbnkpOiB2b2lkIHtcbiAgICBjb25zdCBwZW5kaW5nID0gdGhpcy5wZW5kaW5nUmVxdWVzdHMuZ2V0KGZyYW1lLmlkKTtcbiAgICBpZiAoIXBlbmRpbmcpIHJldHVybjtcblxuICAgIHRoaXMucGVuZGluZ1JlcXVlc3RzLmRlbGV0ZShmcmFtZS5pZCk7XG4gICAgaWYgKHBlbmRpbmcudGltZW91dCkgY2xlYXJUaW1lb3V0KHBlbmRpbmcudGltZW91dCk7XG5cbiAgICBpZiAoZnJhbWUub2spIHBlbmRpbmcucmVzb2x2ZShmcmFtZS5wYXlsb2FkKTtcbiAgICBlbHNlIHBlbmRpbmcucmVqZWN0KG5ldyBFcnJvcihmcmFtZS5lcnJvcj8ubWVzc2FnZSB8fCAnUmVxdWVzdCBmYWlsZWQnKSk7XG4gIH1cblxuICBwcml2YXRlIF9oYW5kbGVDaGF0RXZlbnRGcmFtZShmcmFtZTogYW55KTogdm9pZCB7XG4gICAgY29uc3QgcGF5bG9hZCA9IGZyYW1lLnBheWxvYWQ7XG4gICAgY29uc3QgaW5jb21pbmdTZXNzaW9uS2V5ID0gU3RyaW5nKHBheWxvYWQ/LnNlc3Npb25LZXkgfHwgJycpO1xuICAgIGlmICghaW5jb21pbmdTZXNzaW9uS2V5IHx8ICFzZXNzaW9uS2V5TWF0Y2hlcyh0aGlzLnNlc3Npb25LZXksIGluY29taW5nU2Vzc2lvbktleSkpIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICAvLyBCZXN0LWVmZm9ydCBydW4gY29ycmVsYXRpb24gKGlmIGdhdGV3YXkgaW5jbHVkZXMgYSBydW4gaWQpLiBUaGlzIGF2b2lkcyBjbGVhcmluZyBvdXIgVUlcbiAgICAvLyBiYXNlZCBvbiBhIGRpZmZlcmVudCBjbGllbnQncyBydW4gaW4gdGhlIHNhbWUgc2Vzc2lvbi5cbiAgICBjb25zdCBpbmNvbWluZ1J1bklkID0gU3RyaW5nKHBheWxvYWQ/LnJ1bklkIHx8IHBheWxvYWQ/LmlkZW1wb3RlbmN5S2V5IHx8IHBheWxvYWQ/Lm1ldGE/LnJ1bklkIHx8ICcnKTtcbiAgICBpZiAodGhpcy5hY3RpdmVSdW5JZCAmJiBpbmNvbWluZ1J1bklkICYmIGluY29taW5nUnVuSWQgIT09IHRoaXMuYWN0aXZlUnVuSWQpIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICAvLyBBdm9pZCBkb3VibGUtcmVuZGVyOiBnYXRld2F5IGVtaXRzIGRlbHRhICsgZmluYWwgKyBhYm9ydGVkLiBSZW5kZXIgb25seSBleHBsaWNpdCBmaW5hbC9hYm9ydGVkLlxuICAgIC8vIElmIHN0YXRlIGlzIG1pc3NpbmcsIHRyZWF0IGFzIG5vbi10ZXJtaW5hbCAoZG8gbm90IGNsZWFyIFVJIC8gZG8gbm90IHJlbmRlcikuXG4gICAgaWYgKCFwYXlsb2FkPy5zdGF0ZSkge1xuICAgICAgcmV0dXJuO1xuICAgIH1cbiAgICBpZiAocGF5bG9hZC5zdGF0ZSAhPT0gJ2ZpbmFsJyAmJiBwYXlsb2FkLnN0YXRlICE9PSAnYWJvcnRlZCcpIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICAvLyBXZSBvbmx5IGFwcGVuZCBhc3Npc3RhbnQgb3V0cHV0IHRvIFVJLlxuICAgIGNvbnN0IG1zZyA9IHBheWxvYWQ/Lm1lc3NhZ2U7XG4gICAgY29uc3Qgcm9sZSA9IG1zZz8ucm9sZSA/PyAnYXNzaXN0YW50JztcblxuICAgIC8vIEFib3J0ZWQgZW5kcyB0aGUgcnVuIHJlZ2FyZGxlc3Mgb2Ygcm9sZS9tZXNzYWdlLlxuICAgIGlmIChwYXlsb2FkLnN0YXRlID09PSAnYWJvcnRlZCcpIHtcbiAgICAgIHRoaXMuYWN0aXZlUnVuSWQgPSBudWxsO1xuICAgICAgdGhpcy5fc2V0V29ya2luZyhmYWxzZSk7XG4gICAgICAvLyBBYm9ydGVkIG1heSBoYXZlIG5vIGFzc2lzdGFudCBtZXNzYWdlOyBpZiBub25lLCBzdG9wIGhlcmUuXG4gICAgICBpZiAoIW1zZykgcmV0dXJuO1xuICAgICAgLy8gSWYgdGhlcmUgaXMgYSBtZXNzYWdlLCBvbmx5IGFwcGVuZCBhc3Npc3RhbnQgb3V0cHV0LlxuICAgICAgaWYgKHJvbGUgIT09ICdhc3Npc3RhbnQnKSByZXR1cm47XG4gICAgfVxuXG4gICAgLy8gRmluYWwgc2hvdWxkIG9ubHkgY29tcGxldGUgdGhlIHJ1biB3aGVuIHRoZSBhc3Npc3RhbnQgY29tcGxldGVzLlxuICAgIGlmIChwYXlsb2FkLnN0YXRlID09PSAnZmluYWwnKSB7XG4gICAgICBpZiAocm9sZSAhPT0gJ2Fzc2lzdGFudCcpIHJldHVybjtcbiAgICAgIHRoaXMuYWN0aXZlUnVuSWQgPSBudWxsO1xuICAgICAgdGhpcy5fc2V0V29ya2luZyhmYWxzZSk7XG4gICAgfVxuXG4gICAgY29uc3QgdGV4dCA9IGV4dHJhY3RUZXh0RnJvbUdhdGV3YXlNZXNzYWdlKG1zZyk7XG4gICAgaWYgKCF0ZXh0KSByZXR1cm47XG5cbiAgICAvLyBPcHRpb25hbDogaGlkZSBoZWFydGJlYXQgYWNrcyAobm9pc2UgaW4gVUkpXG4gICAgaWYgKHRleHQudHJpbSgpID09PSAnSEVBUlRCRUFUX09LJykge1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIHRoaXMub25NZXNzYWdlPy4oe1xuICAgICAgdHlwZTogJ21lc3NhZ2UnLFxuICAgICAgcGF5bG9hZDoge1xuICAgICAgICBjb250ZW50OiB0ZXh0LFxuICAgICAgICByb2xlOiAnYXNzaXN0YW50JyxcbiAgICAgICAgdGltZXN0YW1wOiBEYXRlLm5vdygpLFxuICAgICAgfSxcbiAgICB9KTtcbiAgfVxuXG4gIHByaXZhdGUgX3NlbmRSZXF1ZXN0KG1ldGhvZDogc3RyaW5nLCBwYXJhbXM6IGFueSk6IFByb21pc2U8YW55PiB7XG4gICAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIGlmICghdGhpcy53cyB8fCB0aGlzLndzLnJlYWR5U3RhdGUgIT09IFdlYlNvY2tldC5PUEVOKSB7XG4gICAgICAgIHJlamVjdChuZXcgRXJyb3IoJ1dlYlNvY2tldCBub3QgY29ubmVjdGVkJykpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG5cbiAgICAgIGlmICh0aGlzLnBlbmRpbmdSZXF1ZXN0cy5zaXplID49IE1BWF9QRU5ESU5HX1JFUVVFU1RTKSB7XG4gICAgICAgIHJlamVjdChuZXcgRXJyb3IoYFRvbyBtYW55IGluLWZsaWdodCByZXF1ZXN0cyAoJHt0aGlzLnBlbmRpbmdSZXF1ZXN0cy5zaXplfSlgKSk7XG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cblxuICAgICAgY29uc3QgaWQgPSBgcmVxLSR7Kyt0aGlzLnJlcXVlc3RJZH1gO1xuXG4gICAgICBjb25zdCBwZW5kaW5nOiBQZW5kaW5nUmVxdWVzdCA9IHsgcmVzb2x2ZSwgcmVqZWN0LCB0aW1lb3V0OiBudWxsIH07XG4gICAgICB0aGlzLnBlbmRpbmdSZXF1ZXN0cy5zZXQoaWQsIHBlbmRpbmcpO1xuXG4gICAgICBjb25zdCBwYXlsb2FkID0gSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0eXBlOiAncmVxJyxcbiAgICAgICAgbWV0aG9kLFxuICAgICAgICBpZCxcbiAgICAgICAgcGFyYW1zLFxuICAgICAgfSk7XG5cbiAgICAgIHRyeSB7XG4gICAgICAgIHRoaXMud3Muc2VuZChwYXlsb2FkKTtcbiAgICAgIH0gY2F0Y2ggKGVycikge1xuICAgICAgICB0aGlzLnBlbmRpbmdSZXF1ZXN0cy5kZWxldGUoaWQpO1xuICAgICAgICByZWplY3QoZXJyKTtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuXG4gICAgICBwZW5kaW5nLnRpbWVvdXQgPSBzZXRUaW1lb3V0KCgpID0+IHtcbiAgICAgICAgaWYgKHRoaXMucGVuZGluZ1JlcXVlc3RzLmhhcyhpZCkpIHtcbiAgICAgICAgICB0aGlzLnBlbmRpbmdSZXF1ZXN0cy5kZWxldGUoaWQpO1xuICAgICAgICAgIHJlamVjdChuZXcgRXJyb3IoYFJlcXVlc3QgdGltZW91dDogJHttZXRob2R9YCkpO1xuICAgICAgICB9XG4gICAgICB9LCAzMF8wMDApO1xuICAgIH0pO1xuICB9XG5cbiAgcHJpdmF0ZSBfc2NoZWR1bGVSZWNvbm5lY3QoKTogdm9pZCB7XG4gICAgaWYgKHRoaXMucmVjb25uZWN0VGltZXIgIT09IG51bGwpIHJldHVybjtcblxuICAgIGNvbnN0IGF0dGVtcHQgPSArK3RoaXMucmVjb25uZWN0QXR0ZW1wdDtcbiAgICBjb25zdCBleHAgPSBNYXRoLm1pbihSRUNPTk5FQ1RfTUFYX01TLCBSRUNPTk5FQ1RfQkFTRV9NUyAqIE1hdGgucG93KDIsIGF0dGVtcHQgLSAxKSk7XG4gICAgLy8gSml0dGVyOiAwLjV4Li4xLjV4XG4gICAgY29uc3Qgaml0dGVyID0gMC41ICsgTWF0aC5yYW5kb20oKTtcbiAgICBjb25zdCBkZWxheSA9IE1hdGguZmxvb3IoZXhwICogaml0dGVyKTtcblxuICAgIHRoaXMucmVjb25uZWN0VGltZXIgPSBzZXRUaW1lb3V0KCgpID0+IHtcbiAgICAgIHRoaXMucmVjb25uZWN0VGltZXIgPSBudWxsO1xuICAgICAgaWYgKCF0aGlzLmludGVudGlvbmFsQ2xvc2UpIHtcbiAgICAgICAgY29uc29sZS5sb2coYFtvY2xhdy13c10gUmVjb25uZWN0aW5nIHRvICR7dGhpcy51cmx9XHUyMDI2IChhdHRlbXB0ICR7YXR0ZW1wdH0sICR7ZGVsYXl9bXMpYCk7XG4gICAgICAgIHRoaXMuX2Nvbm5lY3QoKTtcbiAgICAgIH1cbiAgICB9LCBkZWxheSk7XG4gIH1cblxuICBwcml2YXRlIGxhc3RCdWZmZXJlZFdhcm5BdE1zID0gMDtcblxuICBwcml2YXRlIF9zdGFydEhlYXJ0YmVhdCgpOiB2b2lkIHtcbiAgICB0aGlzLl9zdG9wSGVhcnRiZWF0KCk7XG4gICAgdGhpcy5oZWFydGJlYXRUaW1lciA9IHNldEludGVydmFsKCgpID0+IHtcbiAgICAgIGlmICh0aGlzLndzPy5yZWFkeVN0YXRlICE9PSBXZWJTb2NrZXQuT1BFTikgcmV0dXJuO1xuICAgICAgaWYgKHRoaXMud3MuYnVmZmVyZWRBbW91bnQgPiAwKSB7XG4gICAgICAgIGNvbnN0IG5vdyA9IERhdGUubm93KCk7XG4gICAgICAgIC8vIFRocm90dGxlIHRvIGF2b2lkIGxvZyBzcGFtIGluIGxvbmctcnVubmluZyBzZXNzaW9ucy5cbiAgICAgICAgaWYgKG5vdyAtIHRoaXMubGFzdEJ1ZmZlcmVkV2FybkF0TXMgPiA1ICogNjBfMDAwKSB7XG4gICAgICAgICAgdGhpcy5sYXN0QnVmZmVyZWRXYXJuQXRNcyA9IG5vdztcbiAgICAgICAgICBjb25zb2xlLndhcm4oJ1tvY2xhdy13c10gU2VuZCBidWZmZXIgbm90IGVtcHR5IFx1MjAxNCBjb25uZWN0aW9uIG1heSBiZSBzdGFsbGVkJyk7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9LCBIRUFSVEJFQVRfSU5URVJWQUxfTVMpO1xuICB9XG5cbiAgcHJpdmF0ZSBfc3RvcEhlYXJ0YmVhdCgpOiB2b2lkIHtcbiAgICBpZiAodGhpcy5oZWFydGJlYXRUaW1lcikge1xuICAgICAgY2xlYXJJbnRlcnZhbCh0aGlzLmhlYXJ0YmVhdFRpbWVyKTtcbiAgICAgIHRoaXMuaGVhcnRiZWF0VGltZXIgPSBudWxsO1xuICAgIH1cbiAgfVxuXG4gIHByaXZhdGUgX3N0b3BUaW1lcnMoKTogdm9pZCB7XG4gICAgdGhpcy5fc3RvcEhlYXJ0YmVhdCgpO1xuICAgIHRoaXMuX2Rpc2FybVdvcmtpbmdTYWZldHlUaW1lb3V0KCk7XG4gICAgaWYgKHRoaXMucmVjb25uZWN0VGltZXIpIHtcbiAgICAgIGNsZWFyVGltZW91dCh0aGlzLnJlY29ubmVjdFRpbWVyKTtcbiAgICAgIHRoaXMucmVjb25uZWN0VGltZXIgPSBudWxsO1xuICAgIH1cbiAgfVxuXG4gIHByaXZhdGUgX3NldFN0YXRlKHN0YXRlOiBXU0NsaWVudFN0YXRlKTogdm9pZCB7XG4gICAgaWYgKHRoaXMuc3RhdGUgPT09IHN0YXRlKSByZXR1cm47XG4gICAgdGhpcy5zdGF0ZSA9IHN0YXRlO1xuICAgIHRoaXMub25TdGF0ZUNoYW5nZT8uKHN0YXRlKTtcbiAgfVxuXG4gIHByaXZhdGUgX3NldFdvcmtpbmcod29ya2luZzogYm9vbGVhbik6IHZvaWQge1xuICAgIGlmICh0aGlzLndvcmtpbmcgPT09IHdvcmtpbmcpIHJldHVybjtcbiAgICB0aGlzLndvcmtpbmcgPSB3b3JraW5nO1xuICAgIHRoaXMub25Xb3JraW5nQ2hhbmdlPy4od29ya2luZyk7XG5cbiAgICBpZiAoIXdvcmtpbmcpIHtcbiAgICAgIHRoaXMuX2Rpc2FybVdvcmtpbmdTYWZldHlUaW1lb3V0KCk7XG4gICAgfVxuICB9XG5cbiAgcHJpdmF0ZSBfYXJtV29ya2luZ1NhZmV0eVRpbWVvdXQoKTogdm9pZCB7XG4gICAgdGhpcy5fZGlzYXJtV29ya2luZ1NhZmV0eVRpbWVvdXQoKTtcbiAgICB0aGlzLndvcmtpbmdUaW1lciA9IHNldFRpbWVvdXQoKCkgPT4ge1xuICAgICAgLy8gSWYgdGhlIGdhdGV3YXkgbmV2ZXIgZW1pdHMgYW4gYXNzaXN0YW50IGZpbmFsIHJlc3BvbnNlLCBkb25cdTIwMTl0IGxlYXZlIFVJIHN0dWNrLlxuICAgICAgdGhpcy5fc2V0V29ya2luZyhmYWxzZSk7XG4gICAgfSwgV09SS0lOR19NQVhfTVMpO1xuICB9XG5cbiAgcHJpdmF0ZSBfZGlzYXJtV29ya2luZ1NhZmV0eVRpbWVvdXQoKTogdm9pZCB7XG4gICAgaWYgKHRoaXMud29ya2luZ1RpbWVyKSB7XG4gICAgICBjbGVhclRpbWVvdXQodGhpcy53b3JraW5nVGltZXIpO1xuICAgICAgdGhpcy53b3JraW5nVGltZXIgPSBudWxsO1xuICAgIH1cbiAgfVxufVxuIiwgImltcG9ydCB7IEl0ZW1WaWV3LCBNYXJrZG93blJlbmRlcmVyLCBNb2RhbCwgTm90aWNlLCBTZXR0aW5nLCBURmlsZSwgV29ya3NwYWNlTGVhZiB9IGZyb20gJ29ic2lkaWFuJztcbmltcG9ydCB0eXBlIE9wZW5DbGF3UGx1Z2luIGZyb20gJy4vbWFpbic7XG5pbXBvcnQgeyBDaGF0TWFuYWdlciB9IGZyb20gJy4vY2hhdCc7XG5pbXBvcnQgdHlwZSB7IENoYXRNZXNzYWdlLCBQYXRoTWFwcGluZyB9IGZyb20gJy4vdHlwZXMnO1xuaW1wb3J0IHsgZXh0cmFjdENhbmRpZGF0ZXMsIHRyeU1hcFJlbW90ZVBhdGhUb1ZhdWx0UGF0aCB9IGZyb20gJy4vbGlua2lmeSc7XG5pbXBvcnQgeyBnZXRBY3RpdmVOb3RlQ29udGV4dCB9IGZyb20gJy4vY29udGV4dCc7XG5pbXBvcnQgeyBPYnNpZGlhbldTQ2xpZW50IH0gZnJvbSAnLi93ZWJzb2NrZXQnO1xuXG5leHBvcnQgY29uc3QgVklFV19UWVBFX09QRU5DTEFXX0NIQVQgPSAnb3BlbmNsYXctY2hhdCc7XG5cbmNsYXNzIE5ld1Nlc3Npb25Nb2RhbCBleHRlbmRzIE1vZGFsIHtcbiAgcHJpdmF0ZSBpbml0aWFsVmFsdWU6IHN0cmluZztcbiAgcHJpdmF0ZSBvblN1Ym1pdDogKHZhbHVlOiBzdHJpbmcpID0+IHZvaWQ7XG5cbiAgY29uc3RydWN0b3IodmlldzogT3BlbkNsYXdDaGF0VmlldywgaW5pdGlhbFZhbHVlOiBzdHJpbmcsIG9uU3VibWl0OiAodmFsdWU6IHN0cmluZykgPT4gdm9pZCkge1xuICAgIHN1cGVyKHZpZXcuYXBwKTtcbiAgICB0aGlzLmluaXRpYWxWYWx1ZSA9IGluaXRpYWxWYWx1ZTtcbiAgICB0aGlzLm9uU3VibWl0ID0gb25TdWJtaXQ7XG4gIH1cblxuICBvbk9wZW4oKTogdm9pZCB7XG4gICAgY29uc3QgeyBjb250ZW50RWwgfSA9IHRoaXM7XG4gICAgY29udGVudEVsLmVtcHR5KCk7XG5cbiAgICBjb250ZW50RWwuY3JlYXRlRWwoJ2gzJywgeyB0ZXh0OiAnTmV3IHNlc3Npb24ga2V5JyB9KTtcblxuICAgIGxldCB2YWx1ZSA9IHRoaXMuaW5pdGlhbFZhbHVlO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGVudEVsKVxuICAgICAgLnNldE5hbWUoJ1Nlc3Npb24ga2V5JylcbiAgICAgIC5zZXREZXNjKCdUaXA6IGNob29zZSBhIHNob3J0IHN1ZmZpeDsgaXQgd2lsbCBiZWNvbWUgYWdlbnQ6bWFpbjpvYnNpZGlhbjpkaXJlY3Q6PHZhdWx0SGFzaD4tPHN1ZmZpeD4uJylcbiAgICAgIC5hZGRUZXh0KCh0KSA9PiB7XG4gICAgICAgIHQuc2V0VmFsdWUodmFsdWUpO1xuICAgICAgICB0Lm9uQ2hhbmdlKCh2KSA9PiB7XG4gICAgICAgICAgdmFsdWUgPSB2O1xuICAgICAgICB9KTtcbiAgICAgIH0pO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGVudEVsKVxuICAgICAgLmFkZEJ1dHRvbigoYikgPT4ge1xuICAgICAgICBiLnNldEJ1dHRvblRleHQoJ0NhbmNlbCcpO1xuICAgICAgICBiLm9uQ2xpY2soKCkgPT4gdGhpcy5jbG9zZSgpKTtcbiAgICAgIH0pXG4gICAgICAuYWRkQnV0dG9uKChiKSA9PiB7XG4gICAgICAgIGIuc2V0Q3RhKCk7XG4gICAgICAgIGIuc2V0QnV0dG9uVGV4dCgnQ3JlYXRlJyk7XG4gICAgICAgIGIub25DbGljaygoKSA9PiB7XG4gICAgICAgICAgY29uc3QgdiA9IHZhbHVlLnRyaW0oKS50b0xvd2VyQ2FzZSgpO1xuICAgICAgICAgIGlmICghdikge1xuICAgICAgICAgICAgbmV3IE5vdGljZSgnU3VmZml4IGNhbm5vdCBiZSBlbXB0eScpO1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgIH1cbiAgICAgICAgICBpZiAoIS9eW2EtejAtOV1bYS16MC05Xy1dezAsNjN9JC8udGVzdCh2KSkge1xuICAgICAgICAgICAgbmV3IE5vdGljZSgnVXNlIGxldHRlcnMvbnVtYmVycy9fLy0gb25seSAobWF4IDY0IGNoYXJzKScpO1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgIH1cbiAgICAgICAgICB0aGlzLm9uU3VibWl0KHYpO1xuICAgICAgICAgIHRoaXMuY2xvc2UoKTtcbiAgICAgICAgfSk7XG4gICAgICB9KTtcbiAgfVxufVxuXG5leHBvcnQgY2xhc3MgT3BlbkNsYXdDaGF0VmlldyBleHRlbmRzIEl0ZW1WaWV3IHtcbiAgcHJpdmF0ZSBwbHVnaW46IE9wZW5DbGF3UGx1Z2luO1xuICBwcml2YXRlIGNoYXRNYW5hZ2VyOiBDaGF0TWFuYWdlcjtcbiAgcHJpdmF0ZSB3c0NsaWVudDogT2JzaWRpYW5XU0NsaWVudDtcblxuICAvLyBTdGF0ZVxuICBwcml2YXRlIGlzQ29ubmVjdGVkID0gZmFsc2U7XG4gIHByaXZhdGUgaXNXb3JraW5nID0gZmFsc2U7XG5cbiAgLy8gQ29ubmVjdGlvbiBub3RpY2VzIChhdm9pZCBzcGFtKVxuICBwcml2YXRlIGxhc3RDb25uTm90aWNlQXRNcyA9IDA7XG4gIHByaXZhdGUgbGFzdEdhdGV3YXlTdGF0ZTogc3RyaW5nIHwgbnVsbCA9IG51bGw7XG5cbiAgLy8gRE9NIHJlZnNcbiAgcHJpdmF0ZSBtZXNzYWdlc0VsITogSFRNTEVsZW1lbnQ7XG4gIHByaXZhdGUgaW5wdXRFbCE6IEhUTUxUZXh0QXJlYUVsZW1lbnQ7XG4gIHByaXZhdGUgc2VuZEJ0biE6IEhUTUxCdXR0b25FbGVtZW50O1xuICBwcml2YXRlIGluY2x1ZGVOb3RlQ2hlY2tib3ghOiBIVE1MSW5wdXRFbGVtZW50O1xuICBwcml2YXRlIHN0YXR1c0RvdCE6IEhUTUxFbGVtZW50O1xuXG4gIHByaXZhdGUgc2Vzc2lvblNlbGVjdCE6IEhUTUxTZWxlY3RFbGVtZW50O1xuICBwcml2YXRlIHNlc3Npb25SZWZyZXNoQnRuITogSFRNTEJ1dHRvbkVsZW1lbnQ7XG4gIHByaXZhdGUgc2Vzc2lvbk5ld0J0biE6IEhUTUxCdXR0b25FbGVtZW50O1xuICBwcml2YXRlIHNlc3Npb25NYWluQnRuITogSFRNTEJ1dHRvbkVsZW1lbnQ7XG4gIHByaXZhdGUgc3VwcHJlc3NTZXNzaW9uU2VsZWN0Q2hhbmdlID0gZmFsc2U7XG5cbiAgcHJpdmF0ZSBvbk1lc3NhZ2VzQ2xpY2s6ICgoZXY6IE1vdXNlRXZlbnQpID0+IHZvaWQpIHwgbnVsbCA9IG51bGw7XG5cbiAgY29uc3RydWN0b3IobGVhZjogV29ya3NwYWNlTGVhZiwgcGx1Z2luOiBPcGVuQ2xhd1BsdWdpbikge1xuICAgIHN1cGVyKGxlYWYpO1xuICAgIHRoaXMucGx1Z2luID0gcGx1Z2luO1xuICAgIHRoaXMuY2hhdE1hbmFnZXIgPSBuZXcgQ2hhdE1hbmFnZXIoKTtcbiAgICB0aGlzLndzQ2xpZW50ID0gdGhpcy5wbHVnaW4uY3JlYXRlV3NDbGllbnQodGhpcy5wbHVnaW4uZ2V0RGVmYXVsdFNlc3Npb25LZXkoKSk7XG5cbiAgICAvLyBXaXJlIGluY29taW5nIFdTIG1lc3NhZ2VzIFx1MjE5MiBDaGF0TWFuYWdlciAocGVyLWxlYWYpXG4gICAgdGhpcy53c0NsaWVudC5vbk1lc3NhZ2UgPSAobXNnKSA9PiB7XG4gICAgICBpZiAobXNnLnR5cGUgPT09ICdtZXNzYWdlJykge1xuICAgICAgICB0aGlzLmNoYXRNYW5hZ2VyLmFkZE1lc3NhZ2UoQ2hhdE1hbmFnZXIuY3JlYXRlQXNzaXN0YW50TWVzc2FnZShtc2cucGF5bG9hZC5jb250ZW50KSk7XG4gICAgICB9IGVsc2UgaWYgKG1zZy50eXBlID09PSAnZXJyb3InKSB7XG4gICAgICAgIGNvbnN0IGVyclRleHQgPSBtc2cucGF5bG9hZC5tZXNzYWdlID8/ICdVbmtub3duIGVycm9yIGZyb20gZ2F0ZXdheSc7XG4gICAgICAgIHRoaXMuY2hhdE1hbmFnZXIuYWRkTWVzc2FnZShDaGF0TWFuYWdlci5jcmVhdGVTeXN0ZW1NZXNzYWdlKGBcdTI2QTAgJHtlcnJUZXh0fWAsICdlcnJvcicpKTtcbiAgICAgIH1cbiAgICB9O1xuICB9XG5cbiAgZ2V0Vmlld1R5cGUoKTogc3RyaW5nIHtcbiAgICByZXR1cm4gVklFV19UWVBFX09QRU5DTEFXX0NIQVQ7XG4gIH1cblxuICBnZXREaXNwbGF5VGV4dCgpOiBzdHJpbmcge1xuICAgIHJldHVybiAnT3BlbkNsYXcgQ2hhdCc7XG4gIH1cblxuICBnZXRJY29uKCk6IHN0cmluZyB7XG4gICAgcmV0dXJuICdtZXNzYWdlLXNxdWFyZSc7XG4gIH1cblxuICBhc3luYyBvbk9wZW4oKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgdGhpcy5wbHVnaW4ucmVnaXN0ZXJDaGF0TGVhZigpO1xuICAgIHRoaXMuX2J1aWxkVUkoKTtcblxuICAgIC8vIEZ1bGwgcmUtcmVuZGVyIG9uIGNsZWFyIC8gcmVsb2FkXG4gICAgdGhpcy5jaGF0TWFuYWdlci5vblVwZGF0ZSA9IChtc2dzKSA9PiB0aGlzLl9yZW5kZXJNZXNzYWdlcyhtc2dzKTtcbiAgICAvLyBPKDEpIGFwcGVuZCBmb3IgbmV3IG1lc3NhZ2VzXG4gICAgdGhpcy5jaGF0TWFuYWdlci5vbk1lc3NhZ2VBZGRlZCA9IChtc2cpID0+IHRoaXMuX2FwcGVuZE1lc3NhZ2UobXNnKTtcblxuICAgIC8vIENvbm5lY3QgdGhpcyBsZWFmJ3MgV1MgY2xpZW50XG4gICAgY29uc3QgZ3cgPSB0aGlzLnBsdWdpbi5nZXRHYXRld2F5Q29uZmlnKCk7XG4gICAgaWYgKGd3LnRva2VuKSB7XG4gICAgICB0aGlzLndzQ2xpZW50LmNvbm5lY3QoZ3cudXJsLCBndy50b2tlbiwgeyBhbGxvd0luc2VjdXJlV3M6IGd3LmFsbG93SW5zZWN1cmVXcyB9KTtcbiAgICB9IGVsc2Uge1xuICAgICAgbmV3IE5vdGljZSgnT3BlbkNsYXcgQ2hhdDogcGxlYXNlIGNvbmZpZ3VyZSB5b3VyIGdhdGV3YXkgdG9rZW4gaW4gU2V0dGluZ3MuJyk7XG4gICAgfVxuXG4gICAgLy8gU3Vic2NyaWJlIHRvIFdTIHN0YXRlIGNoYW5nZXNcbiAgICB0aGlzLndzQ2xpZW50Lm9uU3RhdGVDaGFuZ2UgPSAoc3RhdGUpID0+IHsgXG4gICAgICAvLyBDb25uZWN0aW9uIGxvc3MgLyByZWNvbm5lY3Qgbm90aWNlcyAodGhyb3R0bGVkKVxuICAgICAgY29uc3QgcHJldiA9IHRoaXMubGFzdEdhdGV3YXlTdGF0ZTtcbiAgICAgIHRoaXMubGFzdEdhdGV3YXlTdGF0ZSA9IHN0YXRlO1xuXG4gICAgICBjb25zdCBub3cgPSBEYXRlLm5vdygpO1xuICAgICAgY29uc3QgTk9USUNFX1RIUk9UVExFX01TID0gNjBfMDAwO1xuXG4gICAgICBjb25zdCBzaG91bGROb3RpZnkgPSAoKSA9PiBub3cgLSB0aGlzLmxhc3RDb25uTm90aWNlQXRNcyA+IE5PVElDRV9USFJPVFRMRV9NUztcbiAgICAgIGNvbnN0IG5vdGlmeSA9ICh0ZXh0OiBzdHJpbmcpID0+IHtcbiAgICAgICAgaWYgKCFzaG91bGROb3RpZnkoKSkgcmV0dXJuO1xuICAgICAgICB0aGlzLmxhc3RDb25uTm90aWNlQXRNcyA9IG5vdztcbiAgICAgICAgbmV3IE5vdGljZSh0ZXh0KTtcbiAgICAgIH07XG5cbiAgICAgIC8vIE9ubHkgc2hvdyBcdTIwMUNsb3N0XHUyMDFEIGlmIHdlIHdlcmUgcHJldmlvdXNseSBjb25uZWN0ZWQuXG4gICAgICBpZiAocHJldiA9PT0gJ2Nvbm5lY3RlZCcgJiYgc3RhdGUgPT09ICdkaXNjb25uZWN0ZWQnKSB7XG4gICAgICAgIG5vdGlmeSgnT3BlbkNsYXcgQ2hhdDogY29ubmVjdGlvbiBsb3N0IFx1MjAxNCByZWNvbm5lY3RpbmdcdTIwMjYnKTtcbiAgICAgICAgLy8gQWxzbyBhcHBlbmQgYSBzeXN0ZW0gbWVzc2FnZSBzbyBpdFx1MjAxOXMgdmlzaWJsZSBpbiB0aGUgY2hhdCBoaXN0b3J5LlxuICAgICAgICB0aGlzLmNoYXRNYW5hZ2VyLmFkZE1lc3NhZ2UoQ2hhdE1hbmFnZXIuY3JlYXRlU3lzdGVtTWVzc2FnZSgnXHUyNkEwIENvbm5lY3Rpb24gbG9zdCBcdTIwMTQgcmVjb25uZWN0aW5nXHUyMDI2JywgJ2Vycm9yJykpO1xuICAgICAgfVxuXG4gICAgICAvLyBPcHRpb25hbCBcdTIwMUNyZWNvbm5lY3RlZFx1MjAxRCBub3RpY2VcbiAgICAgIGlmIChwcmV2ICYmIHByZXYgIT09ICdjb25uZWN0ZWQnICYmIHN0YXRlID09PSAnY29ubmVjdGVkJykge1xuICAgICAgICBub3RpZnkoJ09wZW5DbGF3IENoYXQ6IHJlY29ubmVjdGVkJyk7XG4gICAgICAgIHRoaXMuY2hhdE1hbmFnZXIuYWRkTWVzc2FnZShDaGF0TWFuYWdlci5jcmVhdGVTeXN0ZW1NZXNzYWdlKCdcdTI3MDUgUmVjb25uZWN0ZWQnLCAnaW5mbycpKTtcbiAgICAgIH1cblxuICAgICAgdGhpcy5pc0Nvbm5lY3RlZCA9IHN0YXRlID09PSAnY29ubmVjdGVkJztcbiAgICAgIHRoaXMuc3RhdHVzRG90LnRvZ2dsZUNsYXNzKCdjb25uZWN0ZWQnLCB0aGlzLmlzQ29ubmVjdGVkKTtcbiAgICAgIHRoaXMuc3RhdHVzRG90LnRpdGxlID0gYEdhdGV3YXk6ICR7c3RhdGV9YDtcbiAgICAgIHRoaXMuX3VwZGF0ZVNlbmRCdXR0b24oKTtcbiAgICB9O1xuXG4gICAgLy8gU3Vic2NyaWJlIHRvIFx1MjAxQ3dvcmtpbmdcdTIwMUQgKHJlcXVlc3QtaW4tZmxpZ2h0KSBzdGF0ZVxuICAgIHRoaXMud3NDbGllbnQub25Xb3JraW5nQ2hhbmdlID0gKHdvcmtpbmcpID0+IHtcbiAgICAgIHRoaXMuaXNXb3JraW5nID0gd29ya2luZztcbiAgICAgIHRoaXMuX3VwZGF0ZVNlbmRCdXR0b24oKTtcbiAgICB9O1xuXG4gICAgLy8gUmVmbGVjdCBjdXJyZW50IHN0YXRlXG4gICAgdGhpcy5sYXN0R2F0ZXdheVN0YXRlID0gdGhpcy53c0NsaWVudC5zdGF0ZTtcbiAgICB0aGlzLmlzQ29ubmVjdGVkID0gdGhpcy53c0NsaWVudC5zdGF0ZSA9PT0gJ2Nvbm5lY3RlZCc7XG4gICAgdGhpcy5zdGF0dXNEb3QudG9nZ2xlQ2xhc3MoJ2Nvbm5lY3RlZCcsIHRoaXMuaXNDb25uZWN0ZWQpO1xuICAgIHRoaXMuc3RhdHVzRG90LnRpdGxlID0gYEdhdGV3YXk6ICR7dGhpcy53c0NsaWVudC5zdGF0ZX1gO1xuICAgIHRoaXMuX3VwZGF0ZVNlbmRCdXR0b24oKTtcblxuICAgIHRoaXMuX3JlbmRlck1lc3NhZ2VzKHRoaXMuY2hhdE1hbmFnZXIuZ2V0TWVzc2FnZXMoKSk7XG5cbiAgICAvLyBMb2FkIHNlc3Npb24gZHJvcGRvd24gZnJvbSBsb2NhbCB2YXVsdC1zY29wZWQga25vd24gc2Vzc2lvbnMuXG4gICAgdGhpcy5fbG9hZEtub3duU2Vzc2lvbnMoKTtcbiAgfVxuXG4gIGFzeW5jIG9uQ2xvc2UoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgdGhpcy5wbHVnaW4udW5yZWdpc3RlckNoYXRMZWFmKCk7XG4gICAgdGhpcy5jaGF0TWFuYWdlci5vblVwZGF0ZSA9IG51bGw7XG4gICAgdGhpcy5jaGF0TWFuYWdlci5vbk1lc3NhZ2VBZGRlZCA9IG51bGw7XG4gICAgdGhpcy53c0NsaWVudC5vblN0YXRlQ2hhbmdlID0gbnVsbDtcbiAgICB0aGlzLndzQ2xpZW50Lm9uV29ya2luZ0NoYW5nZSA9IG51bGw7XG4gICAgdGhpcy53c0NsaWVudC5kaXNjb25uZWN0KCk7XG5cbiAgICBpZiAodGhpcy5vbk1lc3NhZ2VzQ2xpY2spIHtcbiAgICAgIHRoaXMubWVzc2FnZXNFbD8ucmVtb3ZlRXZlbnRMaXN0ZW5lcignY2xpY2snLCB0aGlzLm9uTWVzc2FnZXNDbGljaywgdHJ1ZSk7XG4gICAgICB0aGlzLm9uTWVzc2FnZXNDbGljayA9IG51bGw7XG4gICAgfVxuICB9XG5cbiAgLy8gXHUyNTAwXHUyNTAwIFVJIGNvbnN0cnVjdGlvbiBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcblxuICBwcml2YXRlIF9idWlsZFVJKCk6IHZvaWQge1xuICAgIGNvbnN0IHJvb3QgPSB0aGlzLmNvbnRlbnRFbDtcbiAgICByb290LmVtcHR5KCk7XG4gICAgcm9vdC5hZGRDbGFzcygnb2NsYXctY2hhdC12aWV3Jyk7XG5cbiAgICAvLyBcdTI1MDBcdTI1MDAgSGVhZGVyIFx1MjUwMFx1MjUwMFxuICAgIGNvbnN0IGhlYWRlciA9IHJvb3QuY3JlYXRlRGl2KHsgY2xzOiAnb2NsYXctaGVhZGVyJyB9KTtcbiAgICBoZWFkZXIuY3JlYXRlU3Bhbih7IGNsczogJ29jbGF3LWhlYWRlci10aXRsZScsIHRleHQ6ICdPcGVuQ2xhdyBDaGF0JyB9KTtcbiAgICB0aGlzLnN0YXR1c0RvdCA9IGhlYWRlci5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1zdGF0dXMtZG90JyB9KTtcbiAgICB0aGlzLnN0YXR1c0RvdC50aXRsZSA9ICdHYXRld2F5OiBkaXNjb25uZWN0ZWQnO1xuXG4gICAgLy8gXHUyNTAwXHUyNTAwIFNlc3Npb24gcm93IFx1MjUwMFx1MjUwMFxuICAgIGNvbnN0IHNlc3NSb3cgPSByb290LmNyZWF0ZURpdih7IGNsczogJ29jbGF3LXNlc3Npb24tcm93JyB9KTtcbiAgICBzZXNzUm93LmNyZWF0ZVNwYW4oeyBjbHM6ICdvY2xhdy1zZXNzaW9uLWxhYmVsJywgdGV4dDogJ1Nlc3Npb24nIH0pO1xuXG4gICAgdGhpcy5zZXNzaW9uU2VsZWN0ID0gc2Vzc1Jvdy5jcmVhdGVFbCgnc2VsZWN0JywgeyBjbHM6ICdvY2xhdy1zZXNzaW9uLXNlbGVjdCcgfSk7XG4gICAgdGhpcy5zZXNzaW9uUmVmcmVzaEJ0biA9IHNlc3NSb3cuY3JlYXRlRWwoJ2J1dHRvbicsIHsgY2xzOiAnb2NsYXctc2Vzc2lvbi1idG4nLCB0ZXh0OiAnUmVsb2FkJyB9KTtcbiAgICB0aGlzLnNlc3Npb25OZXdCdG4gPSBzZXNzUm93LmNyZWF0ZUVsKCdidXR0b24nLCB7IGNsczogJ29jbGF3LXNlc3Npb24tYnRuJywgdGV4dDogJ05ld1x1MjAyNicgfSk7XG4gICAgdGhpcy5zZXNzaW9uTWFpbkJ0biA9IHNlc3NSb3cuY3JlYXRlRWwoJ2J1dHRvbicsIHsgY2xzOiAnb2NsYXctc2Vzc2lvbi1idG4nLCB0ZXh0OiAnTWFpbicgfSk7XG5cbiAgICB0aGlzLnNlc3Npb25SZWZyZXNoQnRuLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gdGhpcy5fbG9hZEtub3duU2Vzc2lvbnMoKSk7XG4gICAgdGhpcy5zZXNzaW9uTmV3QnRuLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4ge1xuICAgICAgaWYgKCF0aGlzLnBsdWdpbi5nZXRWYXVsdEhhc2goKSkge1xuICAgICAgICBuZXcgTm90aWNlKCdPcGVuQ2xhdyBDaGF0OiBOZXcgc2Vzc2lvbiBpcyB1bmF2YWlsYWJsZSAobWlzc2luZyB2YXVsdCBpZGVudGl0eSkuJyk7XG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cbiAgICAgIHZvaWQgdGhpcy5fcHJvbXB0TmV3U2Vzc2lvbigpO1xuICAgIH0pO1xuICAgIHRoaXMuc2Vzc2lvbk1haW5CdG4uYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKSA9PiB7XG4gICAgICB2b2lkIChhc3luYyAoKSA9PiB7XG4gICAgICAgIGF3YWl0IHRoaXMuX3N3aXRjaFNlc3Npb24oJ21haW4nKTtcbiAgICAgICAgdGhpcy5fbG9hZEtub3duU2Vzc2lvbnMoKTtcbiAgICAgICAgdGhpcy5zZXNzaW9uU2VsZWN0LnZhbHVlID0gJ21haW4nO1xuICAgICAgICB0aGlzLnNlc3Npb25TZWxlY3QudGl0bGUgPSAnbWFpbic7XG4gICAgICB9KSgpO1xuICAgIH0pO1xuICAgIHRoaXMuc2Vzc2lvblNlbGVjdC5hZGRFdmVudExpc3RlbmVyKCdjaGFuZ2UnLCAoKSA9PiB7XG4gICAgICBpZiAodGhpcy5zdXBwcmVzc1Nlc3Npb25TZWxlY3RDaGFuZ2UpIHJldHVybjtcbiAgICAgIGNvbnN0IG5leHQgPSB0aGlzLnNlc3Npb25TZWxlY3QudmFsdWU7XG4gICAgICBpZiAoIW5leHQpIHJldHVybjtcbiAgICAgIHZvaWQgKGFzeW5jICgpID0+IHtcbiAgICAgICAgYXdhaXQgdGhpcy5fc3dpdGNoU2Vzc2lvbihuZXh0KTtcbiAgICAgICAgdGhpcy5fbG9hZEtub3duU2Vzc2lvbnMoKTtcbiAgICAgICAgdGhpcy5zZXNzaW9uU2VsZWN0LnZhbHVlID0gbmV4dDtcbiAgICAgICAgdGhpcy5zZXNzaW9uU2VsZWN0LnRpdGxlID0gbmV4dDtcbiAgICAgIH0pKCk7XG4gICAgfSk7XG5cbiAgICAvLyBcdTI1MDBcdTI1MDAgTWVzc2FnZXMgYXJlYSBcdTI1MDBcdTI1MDBcbiAgICB0aGlzLm1lc3NhZ2VzRWwgPSByb290LmNyZWF0ZURpdih7IGNsczogJ29jbGF3LW1lc3NhZ2VzJyB9KTtcblxuICAgIC8vIERlbGVnYXRlIGludGVybmFsLWxpbmsgY2xpY2tzIChNYXJrZG93blJlbmRlcmVyIG91dHB1dCkgdG8gYSByZWxpYWJsZSBvcGVuRmlsZSBoYW5kbGVyLlxuICAgIHRoaXMuX2luc3RhbGxJbnRlcm5hbExpbmtEZWxlZ2F0aW9uKCk7XG5cbiAgICAvLyBcdTI1MDBcdTI1MDAgQ29udGV4dCByb3cgXHUyNTAwXHUyNTAwXG4gICAgY29uc3QgY3R4Um93ID0gcm9vdC5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1jb250ZXh0LXJvdycgfSk7XG4gICAgdGhpcy5pbmNsdWRlTm90ZUNoZWNrYm94ID0gY3R4Um93LmNyZWF0ZUVsKCdpbnB1dCcsIHsgdHlwZTogJ2NoZWNrYm94JyB9KTtcbiAgICB0aGlzLmluY2x1ZGVOb3RlQ2hlY2tib3guaWQgPSAnb2NsYXctaW5jbHVkZS1ub3RlJztcbiAgICB0aGlzLmluY2x1ZGVOb3RlQ2hlY2tib3guY2hlY2tlZCA9IHRoaXMucGx1Z2luLnNldHRpbmdzLmluY2x1ZGVBY3RpdmVOb3RlO1xuICAgIGNvbnN0IGN0eExhYmVsID0gY3R4Um93LmNyZWF0ZUVsKCdsYWJlbCcsIHsgdGV4dDogJ0luY2x1ZGUgYWN0aXZlIG5vdGUnIH0pO1xuICAgIGN0eExhYmVsLmh0bWxGb3IgPSAnb2NsYXctaW5jbHVkZS1ub3RlJztcblxuICAgIC8vIFx1MjUwMFx1MjUwMCBJbnB1dCByb3cgXHUyNTAwXHUyNTAwXG4gICAgY29uc3QgaW5wdXRSb3cgPSByb290LmNyZWF0ZURpdih7IGNsczogJ29jbGF3LWlucHV0LXJvdycgfSk7XG4gICAgdGhpcy5pbnB1dEVsID0gaW5wdXRSb3cuY3JlYXRlRWwoJ3RleHRhcmVhJywge1xuICAgICAgY2xzOiAnb2NsYXctaW5wdXQnLFxuICAgICAgcGxhY2Vob2xkZXI6ICdBc2sgYW55dGhpbmdcdTIwMjYnLFxuICAgIH0pO1xuICAgIHRoaXMuaW5wdXRFbC5yb3dzID0gMTtcblxuICAgIHRoaXMuc2VuZEJ0biA9IGlucHV0Um93LmNyZWF0ZUVsKCdidXR0b24nLCB7IGNsczogJ29jbGF3LXNlbmQtYnRuJywgdGV4dDogJ1NlbmQnIH0pO1xuXG4gICAgLy8gXHUyNTAwXHUyNTAwIEV2ZW50IGxpc3RlbmVycyBcdTI1MDBcdTI1MDBcbiAgICB0aGlzLnNlbmRCdG4uYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKSA9PiB0aGlzLl9oYW5kbGVTZW5kKCkpO1xuICAgIHRoaXMuaW5wdXRFbC5hZGRFdmVudExpc3RlbmVyKCdrZXlkb3duJywgKGUpID0+IHtcbiAgICAgIGlmIChlLmtleSA9PT0gJ0VudGVyJyAmJiAhZS5zaGlmdEtleSkge1xuICAgICAgICBlLnByZXZlbnREZWZhdWx0KCk7XG4gICAgICAgIHRoaXMuX2hhbmRsZVNlbmQoKTtcbiAgICAgIH1cbiAgICB9KTtcbiAgICAvLyBBdXRvLXJlc2l6ZSB0ZXh0YXJlYVxuICAgIHRoaXMuaW5wdXRFbC5hZGRFdmVudExpc3RlbmVyKCdpbnB1dCcsICgpID0+IHtcbiAgICAgIHRoaXMuaW5wdXRFbC5zdHlsZS5oZWlnaHQgPSAnYXV0byc7XG4gICAgICB0aGlzLmlucHV0RWwuc3R5bGUuaGVpZ2h0ID0gYCR7dGhpcy5pbnB1dEVsLnNjcm9sbEhlaWdodH1weGA7XG4gICAgfSk7XG4gIH1cblxuICBwcml2YXRlIF9zZXRTZXNzaW9uU2VsZWN0T3B0aW9ucyhrZXlzOiBzdHJpbmdbXSk6IHZvaWQge1xuICAgIHRoaXMuc3VwcHJlc3NTZXNzaW9uU2VsZWN0Q2hhbmdlID0gdHJ1ZTtcbiAgICB0cnkge1xuICAgICAgdGhpcy5zZXNzaW9uU2VsZWN0LmVtcHR5KCk7XG5cbiAgICAgIGNvbnN0IGN1cnJlbnQgPSAodGhpcy5wbHVnaW4uc2V0dGluZ3Muc2Vzc2lvbktleSA/PyAnbWFpbicpLnRvTG93ZXJDYXNlKCk7XG4gICAgICBsZXQgdW5pcXVlID0gQXJyYXkuZnJvbShuZXcgU2V0KFtjdXJyZW50LCAuLi5rZXlzXS5maWx0ZXIoQm9vbGVhbikpKTtcblxuICAgICAgLy8gQ2Fub25pY2FsLW9ubHk6IG1haW4gb3IgYWdlbnQ6bWFpbjpvYnNpZGlhbjpkaXJlY3Q6KlxuICAgICAgdW5pcXVlID0gdW5pcXVlLmZpbHRlcigoaykgPT4gayA9PT0gJ21haW4nIHx8IFN0cmluZyhrKS5zdGFydHNXaXRoKCdhZ2VudDptYWluOm9ic2lkaWFuOmRpcmVjdDonKSk7XG5cbiAgICAgIGlmICh1bmlxdWUubGVuZ3RoID09PSAwKSB7XG4gICAgICAgIHVuaXF1ZSA9IFsnbWFpbiddO1xuICAgICAgfVxuXG4gICAgICBmb3IgKGNvbnN0IGtleSBvZiB1bmlxdWUpIHtcbiAgICAgICAgY29uc3Qgb3B0ID0gdGhpcy5zZXNzaW9uU2VsZWN0LmNyZWF0ZUVsKCdvcHRpb24nLCB7IHZhbHVlOiBrZXksIHRleHQ6IGtleSB9KTtcbiAgICAgICAgaWYgKGtleSA9PT0gY3VycmVudCkgb3B0LnNlbGVjdGVkID0gdHJ1ZTtcbiAgICAgIH1cblxuICAgICAgaWYgKHVuaXF1ZS5pbmNsdWRlcyhjdXJyZW50KSkge1xuICAgICAgICB0aGlzLnNlc3Npb25TZWxlY3QudmFsdWUgPSBjdXJyZW50O1xuICAgICAgfVxuICAgICAgdGhpcy5zZXNzaW9uU2VsZWN0LnRpdGxlID0gY3VycmVudDtcbiAgICB9IGZpbmFsbHkge1xuICAgICAgdGhpcy5zdXBwcmVzc1Nlc3Npb25TZWxlY3RDaGFuZ2UgPSBmYWxzZTtcbiAgICB9XG4gIH1cblxuICBwcml2YXRlIF9sb2FkS25vd25TZXNzaW9ucygpOiB2b2lkIHtcbiAgICBjb25zdCB2YXVsdEhhc2ggPSAodGhpcy5wbHVnaW4uc2V0dGluZ3MudmF1bHRIYXNoID8/ICcnKS50cmltKCk7XG4gICAgY29uc3QgbWFwID0gdGhpcy5wbHVnaW4uc2V0dGluZ3Mua25vd25TZXNzaW9uS2V5c0J5VmF1bHQgPz8ge307XG4gICAgY29uc3Qga2V5cyA9IHZhdWx0SGFzaCAmJiBBcnJheS5pc0FycmF5KG1hcFt2YXVsdEhhc2hdKSA/IG1hcFt2YXVsdEhhc2hdIDogW107XG5cbiAgICBjb25zdCBwcmVmaXggPSB2YXVsdEhhc2ggPyBgYWdlbnQ6bWFpbjpvYnNpZGlhbjpkaXJlY3Q6JHt2YXVsdEhhc2h9YCA6ICcnO1xuICAgIGNvbnN0IGZpbHRlcmVkID0gdmF1bHRIYXNoXG4gICAgICA/IGtleXMuZmlsdGVyKChrKSA9PiB7XG4gICAgICAgICAgY29uc3Qga2V5ID0gU3RyaW5nKGsgfHwgJycpLnRyaW0oKS50b0xvd2VyQ2FzZSgpO1xuICAgICAgICAgIHJldHVybiBrZXkgPT09IHByZWZpeCB8fCBrZXkuc3RhcnRzV2l0aChwcmVmaXggKyAnLScpO1xuICAgICAgICB9KVxuICAgICAgOiBbXTtcblxuICAgIHRoaXMuX3NldFNlc3Npb25TZWxlY3RPcHRpb25zKGZpbHRlcmVkKTtcbiAgfVxuXG4gIHByaXZhdGUgYXN5bmMgX3N3aXRjaFNlc3Npb24oc2Vzc2lvbktleTogc3RyaW5nKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgY29uc3QgbmV4dCA9IHNlc3Npb25LZXkudHJpbSgpLnRvTG93ZXJDYXNlKCk7XG4gICAgaWYgKCFuZXh0KSByZXR1cm47XG5cbiAgICBjb25zdCB2YXVsdEhhc2ggPSB0aGlzLnBsdWdpbi5nZXRWYXVsdEhhc2goKTtcbiAgICBpZiAodmF1bHRIYXNoKSB7XG4gICAgICBjb25zdCBwcmVmaXggPSBgYWdlbnQ6bWFpbjpvYnNpZGlhbjpkaXJlY3Q6JHt2YXVsdEhhc2h9YDtcbiAgICAgIGlmICghKG5leHQgPT09ICdtYWluJyB8fCBuZXh0ID09PSBwcmVmaXggfHwgbmV4dC5zdGFydHNXaXRoKHByZWZpeCArICctJykpKSB7XG4gICAgICAgIG5ldyBOb3RpY2UoJ09wZW5DbGF3IENoYXQ6IHNlc3Npb24ga2V5IG11c3QgbWF0Y2ggdGhpcyB2YXVsdC4nKTtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuICAgIH0gZWxzZSB7XG4gICAgICBpZiAobmV4dCAhPT0gJ21haW4nKSB7XG4gICAgICAgIG5ldyBOb3RpY2UoJ09wZW5DbGF3IENoYXQ6IGNhbm5vdCBzd2l0Y2ggc2Vzc2lvbnMgKG1pc3NpbmcgdmF1bHQgaWRlbnRpdHkpLicpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG4gICAgfVxuXG4gICAgLy8gQWJvcnQgYW55IGluLWZsaWdodCBydW4gYmVzdC1lZmZvcnQuXG4gICAgdHJ5IHtcbiAgICAgIGF3YWl0IHRoaXMud3NDbGllbnQuYWJvcnRBY3RpdmVSdW4oKTtcbiAgICB9IGNhdGNoIHtcbiAgICAgIC8vIGlnbm9yZVxuICAgIH1cblxuICAgIC8vIERpdmlkZXIgaW4gdGhpcyBsZWFmIG9ubHkuXG4gICAgdGhpcy5jaGF0TWFuYWdlci5hZGRNZXNzYWdlKENoYXRNYW5hZ2VyLmNyZWF0ZVNlc3Npb25EaXZpZGVyKG5leHQpKTtcblxuICAgIC8vIFBlcnNpc3QgYXMgdGhlIGRlZmF1bHQgYW5kIHJlbWVtYmVyIGl0IGluIHRoZSB2YXVsdC1zY29wZWQgbGlzdC5cbiAgICBhd2FpdCB0aGlzLnBsdWdpbi5yZW1lbWJlclNlc3Npb25LZXkobmV4dCk7XG5cbiAgICAvLyBTd2l0Y2ggV1Mgcm91dGluZyBmb3IgdGhpcyBsZWFmLlxuICAgIHRoaXMud3NDbGllbnQuZGlzY29ubmVjdCgpO1xuICAgIHRoaXMud3NDbGllbnQuc2V0U2Vzc2lvbktleShuZXh0KTtcblxuICAgIGNvbnN0IGd3ID0gdGhpcy5wbHVnaW4uZ2V0R2F0ZXdheUNvbmZpZygpO1xuICAgIGlmIChndy50b2tlbikge1xuICAgICAgdGhpcy53c0NsaWVudC5jb25uZWN0KGd3LnVybCwgZ3cudG9rZW4sIHsgYWxsb3dJbnNlY3VyZVdzOiBndy5hbGxvd0luc2VjdXJlV3MgfSk7XG4gICAgfSBlbHNlIHtcbiAgICAgIG5ldyBOb3RpY2UoJ09wZW5DbGF3IENoYXQ6IHBsZWFzZSBjb25maWd1cmUgeW91ciBnYXRld2F5IHRva2VuIGluIFNldHRpbmdzLicpO1xuICAgIH1cbiAgfVxuXG4gIHByaXZhdGUgYXN5bmMgX3Byb21wdE5ld1Nlc3Npb24oKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgY29uc3Qgbm93ID0gbmV3IERhdGUoKTtcbiAgICBjb25zdCBwYWQgPSAobjogbnVtYmVyKSA9PiBTdHJpbmcobikucGFkU3RhcnQoMiwgJzAnKTtcbiAgICBjb25zdCBzdWdnZXN0ZWQgPSBgY2hhdC0ke25vdy5nZXRGdWxsWWVhcigpfSR7cGFkKG5vdy5nZXRNb250aCgpICsgMSl9JHtwYWQobm93LmdldERhdGUoKSl9LSR7cGFkKG5vdy5nZXRIb3VycygpKX0ke3BhZChub3cuZ2V0TWludXRlcygpKX1gO1xuXG4gICAgY29uc3QgbW9kYWwgPSBuZXcgTmV3U2Vzc2lvbk1vZGFsKHRoaXMsIHN1Z2dlc3RlZCwgKHN1ZmZpeCkgPT4ge1xuICAgICAgY29uc3QgdmF1bHRIYXNoID0gKHRoaXMucGx1Z2luLnNldHRpbmdzLnZhdWx0SGFzaCA/PyAnJykudHJpbSgpO1xuICAgICAgaWYgKCF2YXVsdEhhc2gpIHtcbiAgICAgICAgbmV3IE5vdGljZSgnT3BlbkNsYXcgQ2hhdDogY2Fubm90IGNyZWF0ZSBzZXNzaW9uIChtaXNzaW5nIHZhdWx0IGlkZW50aXR5KS4nKTtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuICAgICAgY29uc3Qga2V5ID0gYGFnZW50Om1haW46b2JzaWRpYW46ZGlyZWN0OiR7dmF1bHRIYXNofS0ke3N1ZmZpeH1gO1xuICAgICAgdm9pZCAoYXN5bmMgKCkgPT4ge1xuICAgICAgICBhd2FpdCB0aGlzLl9zd2l0Y2hTZXNzaW9uKGtleSk7XG4gICAgICAgIHRoaXMuX2xvYWRLbm93blNlc3Npb25zKCk7XG4gICAgICAgIHRoaXMuc2Vzc2lvblNlbGVjdC52YWx1ZSA9IGtleTtcbiAgICAgICAgdGhpcy5zZXNzaW9uU2VsZWN0LnRpdGxlID0ga2V5O1xuICAgICAgfSkoKTtcbiAgICB9KTtcbiAgICBtb2RhbC5vcGVuKCk7XG4gIH1cblxuICAvLyBcdTI1MDBcdTI1MDAgTWVzc2FnZSByZW5kZXJpbmcgXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG5cbiAgcHJpdmF0ZSBfcmVuZGVyTWVzc2FnZXMobWVzc2FnZXM6IHJlYWRvbmx5IENoYXRNZXNzYWdlW10pOiB2b2lkIHtcbiAgICB0aGlzLm1lc3NhZ2VzRWwuZW1wdHkoKTtcblxuICAgIGlmIChtZXNzYWdlcy5sZW5ndGggPT09IDApIHtcbiAgICAgIHRoaXMubWVzc2FnZXNFbC5jcmVhdGVFbCgncCcsIHtcbiAgICAgICAgdGV4dDogJ1NlbmQgYSBtZXNzYWdlIHRvIHN0YXJ0IGNoYXR0aW5nLicsXG4gICAgICAgIGNsczogJ29jbGF3LW1lc3NhZ2Ugc3lzdGVtIG9jbGF3LXBsYWNlaG9sZGVyJyxcbiAgICAgIH0pO1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIGZvciAoY29uc3QgbXNnIG9mIG1lc3NhZ2VzKSB7XG4gICAgICB0aGlzLl9hcHBlbmRNZXNzYWdlKG1zZyk7XG4gICAgfVxuXG4gICAgLy8gU2Nyb2xsIHRvIGJvdHRvbVxuICAgIHRoaXMubWVzc2FnZXNFbC5zY3JvbGxUb3AgPSB0aGlzLm1lc3NhZ2VzRWwuc2Nyb2xsSGVpZ2h0O1xuICB9XG5cbiAgLyoqIEFwcGVuZHMgYSBzaW5nbGUgbWVzc2FnZSB3aXRob3V0IHJlYnVpbGRpbmcgdGhlIERPTSAoTygxKSkgKi9cbiAgcHJpdmF0ZSBfYXBwZW5kTWVzc2FnZShtc2c6IENoYXRNZXNzYWdlKTogdm9pZCB7XG4gICAgLy8gUmVtb3ZlIGVtcHR5LXN0YXRlIHBsYWNlaG9sZGVyIGlmIHByZXNlbnRcbiAgICB0aGlzLm1lc3NhZ2VzRWwucXVlcnlTZWxlY3RvcignLm9jbGF3LXBsYWNlaG9sZGVyJyk/LnJlbW92ZSgpO1xuXG4gICAgY29uc3QgbGV2ZWxDbGFzcyA9IG1zZy5sZXZlbCA/IGAgJHttc2cubGV2ZWx9YCA6ICcnO1xuICAgIGNvbnN0IGtpbmRDbGFzcyA9IG1zZy5raW5kID8gYCBvY2xhdy0ke21zZy5raW5kfWAgOiAnJztcbiAgICBjb25zdCBlbCA9IHRoaXMubWVzc2FnZXNFbC5jcmVhdGVEaXYoeyBjbHM6IGBvY2xhdy1tZXNzYWdlICR7bXNnLnJvbGV9JHtsZXZlbENsYXNzfSR7a2luZENsYXNzfWAgfSk7XG4gICAgY29uc3QgYm9keSA9IGVsLmNyZWF0ZURpdih7IGNsczogJ29jbGF3LW1lc3NhZ2UtYm9keScgfSk7XG4gICAgaWYgKG1zZy50aXRsZSkge1xuICAgICAgYm9keS50aXRsZSA9IG1zZy50aXRsZTtcbiAgICB9XG5cbiAgICAvLyBUcmVhdCBhc3Npc3RhbnQgb3V0cHV0IGFzIFVOVFJVU1RFRCBieSBkZWZhdWx0LlxuICAgIC8vIFJlbmRlcmluZyBhcyBPYnNpZGlhbiBNYXJrZG93biBjYW4gdHJpZ2dlciBlbWJlZHMgYW5kIG90aGVyIHBsdWdpbnMnIHBvc3QtcHJvY2Vzc29ycy5cbiAgICBpZiAobXNnLnJvbGUgPT09ICdhc3Npc3RhbnQnKSB7XG4gICAgICBjb25zdCBtYXBwaW5nczogUGF0aE1hcHBpbmdbXSA9IHRoaXMucGx1Z2luLnNldHRpbmdzLnBhdGhNYXBwaW5ncyA/PyBbXTtcbiAgICAgIGNvbnN0IHNvdXJjZVBhdGggPSB0aGlzLmFwcC53b3Jrc3BhY2UuZ2V0QWN0aXZlRmlsZSgpPy5wYXRoID8/ICcnO1xuXG4gICAgICBpZiAodGhpcy5wbHVnaW4uc2V0dGluZ3MucmVuZGVyQXNzaXN0YW50TWFya2Rvd24pIHtcbiAgICAgICAgLy8gQmVzdC1lZmZvcnQgcHJlLXByb2Nlc3Npbmc6IHJlcGxhY2Uga25vd24gcmVtb3RlIHBhdGhzIHdpdGggd2lraWxpbmtzIHdoZW4gdGhlIHRhcmdldCBleGlzdHMuXG4gICAgICAgIGNvbnN0IHByZSA9IHRoaXMuX3ByZXByb2Nlc3NBc3Npc3RhbnRNYXJrZG93bihtc2cuY29udGVudCwgbWFwcGluZ3MpO1xuICAgICAgICB2b2lkIE1hcmtkb3duUmVuZGVyZXIucmVuZGVyTWFya2Rvd24ocHJlLCBib2R5LCBzb3VyY2VQYXRoLCB0aGlzLnBsdWdpbik7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICAvLyBQbGFpbiBtb2RlOiBidWlsZCBzYWZlLCBjbGlja2FibGUgbGlua3MgaW4gRE9NIChubyBNYXJrZG93biByZW5kZXJpbmcpLlxuICAgICAgICB0aGlzLl9yZW5kZXJBc3Npc3RhbnRQbGFpbldpdGhMaW5rcyhib2R5LCBtc2cuY29udGVudCwgbWFwcGluZ3MsIHNvdXJjZVBhdGgpO1xuICAgICAgfVxuICAgIH0gZWxzZSB7XG4gICAgICBib2R5LnNldFRleHQobXNnLmNvbnRlbnQpO1xuICAgIH1cblxuICAgIC8vIFNjcm9sbCB0byBib3R0b21cbiAgICB0aGlzLm1lc3NhZ2VzRWwuc2Nyb2xsVG9wID0gdGhpcy5tZXNzYWdlc0VsLnNjcm9sbEhlaWdodDtcbiAgfVxuXG4gIHByaXZhdGUgX3RyeVJldmVyc2VNYXBVcmxUb1ZhdWx0UGF0aCh1cmw6IHN0cmluZywgbWFwcGluZ3M6IFBhdGhNYXBwaW5nW10pOiBzdHJpbmcgfCBudWxsIHtcbiAgICAvLyBGUy1iYXNlZCBtYXBwaW5nOyBiZXN0LWVmZm9ydCBvbmx5LlxuICAgIGxldCBkZWNvZGVkID0gdXJsO1xuICAgIHRyeSB7XG4gICAgICBkZWNvZGVkID0gZGVjb2RlVVJJQ29tcG9uZW50KHVybCk7XG4gICAgfSBjYXRjaCB7XG4gICAgICAvLyBpZ25vcmVcbiAgICB9XG5cbiAgICAvLyBJZiB0aGUgZGVjb2RlZCBVUkwgY29udGFpbnMgYSByZW1vdGVCYXNlIHN1YnN0cmluZywgdHJ5IG1hcHBpbmcgZnJvbSB0aGF0IHBvaW50LlxuICAgIGZvciAoY29uc3Qgcm93IG9mIG1hcHBpbmdzKSB7XG4gICAgICBjb25zdCByZW1vdGVCYXNlID0gU3RyaW5nKHJvdy5yZW1vdGVCYXNlID8/ICcnKTtcbiAgICAgIGlmICghcmVtb3RlQmFzZSkgY29udGludWU7XG4gICAgICBjb25zdCBpZHggPSBkZWNvZGVkLmluZGV4T2YocmVtb3RlQmFzZSk7XG4gICAgICBpZiAoaWR4IDwgMCkgY29udGludWU7XG5cbiAgICAgIC8vIEV4dHJhY3QgZnJvbSByZW1vdGVCYXNlIG9ud2FyZCB1bnRpbCBhIHRlcm1pbmF0b3IuXG4gICAgICBjb25zdCB0YWlsID0gZGVjb2RlZC5zbGljZShpZHgpO1xuICAgICAgY29uc3QgdG9rZW4gPSB0YWlsLnNwbGl0KC9bXFxzJ1wiPD4pXS8pWzBdO1xuICAgICAgY29uc3QgbWFwcGVkID0gdHJ5TWFwUmVtb3RlUGF0aFRvVmF1bHRQYXRoKHRva2VuLCBtYXBwaW5ncyk7XG4gICAgICBpZiAobWFwcGVkICYmIHRoaXMuYXBwLnZhdWx0LmdldEFic3RyYWN0RmlsZUJ5UGF0aChtYXBwZWQpKSByZXR1cm4gbWFwcGVkO1xuICAgIH1cblxuICAgIHJldHVybiBudWxsO1xuICB9XG5cbiAgcHJpdmF0ZSBfaW5zdGFsbEludGVybmFsTGlua0RlbGVnYXRpb24oKTogdm9pZCB7XG4gICAgaWYgKHRoaXMub25NZXNzYWdlc0NsaWNrKSByZXR1cm47XG5cbiAgICB0aGlzLm9uTWVzc2FnZXNDbGljayA9IChldjogTW91c2VFdmVudCkgPT4ge1xuICAgICAgY29uc3QgdGFyZ2V0ID0gZXYudGFyZ2V0IGFzIEhUTUxFbGVtZW50IHwgbnVsbDtcbiAgICAgIGNvbnN0IGEgPSB0YXJnZXQ/LmNsb3Nlc3Q/LignYS5pbnRlcm5hbC1saW5rJykgYXMgSFRNTEFuY2hvckVsZW1lbnQgfCBudWxsO1xuICAgICAgaWYgKCFhKSByZXR1cm47XG5cbiAgICAgIGNvbnN0IGRhdGFIcmVmID0gYS5nZXRBdHRyaWJ1dGUoJ2RhdGEtaHJlZicpIHx8ICcnO1xuICAgICAgY29uc3QgaHJlZkF0dHIgPSBhLmdldEF0dHJpYnV0ZSgnaHJlZicpIHx8ICcnO1xuXG4gICAgICBjb25zdCByYXcgPSAoZGF0YUhyZWYgfHwgaHJlZkF0dHIpLnRyaW0oKTtcbiAgICAgIGlmICghcmF3KSByZXR1cm47XG5cbiAgICAgIC8vIElmIGl0IGlzIGFuIGFic29sdXRlIFVSTCwgbGV0IHRoZSBkZWZhdWx0IGJlaGF2aW9yIGhhbmRsZSBpdC5cbiAgICAgIGlmICgvXmh0dHBzPzpcXC9cXC8vaS50ZXN0KHJhdykpIHJldHVybjtcblxuICAgICAgLy8gT2JzaWRpYW4gaW50ZXJuYWwtbGluayBvZnRlbiB1c2VzIHZhdWx0LXJlbGF0aXZlIHBhdGguXG4gICAgICBjb25zdCB2YXVsdFBhdGggPSByYXcucmVwbGFjZSgvXlxcLysvLCAnJyk7XG4gICAgICBjb25zdCBmID0gdGhpcy5hcHAudmF1bHQuZ2V0QWJzdHJhY3RGaWxlQnlQYXRoKHZhdWx0UGF0aCk7XG5cbiAgICAgIGV2LnByZXZlbnREZWZhdWx0KCk7XG4gICAgICBldi5zdG9wUHJvcGFnYXRpb24oKTtcblxuICAgICAgaWYgKGYgaW5zdGFuY2VvZiBURmlsZSkge1xuICAgICAgICB2b2lkIHRoaXMuYXBwLndvcmtzcGFjZS5nZXRMZWFmKHRydWUpLm9wZW5GaWxlKGYpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG5cbiAgICAgIC8vIEZhbGxiYWNrOiBsZXQgT2JzaWRpYW4gcmVzb2x2ZSBsaW5rdGV4dCAoYmVzdC1lZmZvcnQpLlxuICAgICAgdm9pZCB0aGlzLmFwcC53b3Jrc3BhY2Uub3BlbkxpbmtUZXh0KHZhdWx0UGF0aCwgdGhpcy5hcHAud29ya3NwYWNlLmdldEFjdGl2ZUZpbGUoKT8ucGF0aCA/PyAnJywgdHJ1ZSk7XG4gICAgfTtcblxuICAgIC8vIFVzZSBjYXB0dXJlIHRvIGVuc3VyZSB3ZSBjYXRjaCBjbGlja3MgZXZlbiBpZiBPYnNpZGlhbi9kZWZhdWx0IGhhbmRsZXJzIHN0b3AgcHJvcGFnYXRpb24uXG4gICAgdGhpcy5tZXNzYWdlc0VsLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgdGhpcy5vbk1lc3NhZ2VzQ2xpY2ssIHRydWUpO1xuICB9XG5cbiAgcHJpdmF0ZSBfdHJ5TWFwVmF1bHRSZWxhdGl2ZVRva2VuKHRva2VuOiBzdHJpbmcsIG1hcHBpbmdzOiBQYXRoTWFwcGluZ1tdKTogc3RyaW5nIHwgbnVsbCB7XG4gICAgY29uc3QgdCA9IHRva2VuLnJlcGxhY2UoL15cXC8rLywgJycpO1xuICAgIGlmICh0aGlzLmFwcC52YXVsdC5nZXRBYnN0cmFjdEZpbGVCeVBhdGgodCkpIHJldHVybiB0O1xuXG4gICAgLy8gSGV1cmlzdGljOiBpZiB2YXVsdEJhc2UgZW5kcyB3aXRoIGEgc2VnbWVudCAoZS5nLiB3b3Jrc3BhY2UvY29tcGVuZy8pIGFuZCB0b2tlbiBzdGFydHMgd2l0aCB0aGF0IHNlZ21lbnQgKGNvbXBlbmcvLi4uKSxcbiAgICAvLyBtYXAgdG9rZW4gdW5kZXIgdmF1bHRCYXNlLlxuICAgIGZvciAoY29uc3Qgcm93IG9mIG1hcHBpbmdzKSB7XG4gICAgICBjb25zdCB2YXVsdEJhc2VSYXcgPSBTdHJpbmcocm93LnZhdWx0QmFzZSA/PyAnJykudHJpbSgpO1xuICAgICAgaWYgKCF2YXVsdEJhc2VSYXcpIGNvbnRpbnVlO1xuICAgICAgY29uc3QgdmF1bHRCYXNlID0gdmF1bHRCYXNlUmF3LmVuZHNXaXRoKCcvJykgPyB2YXVsdEJhc2VSYXcgOiBgJHt2YXVsdEJhc2VSYXd9L2A7XG5cbiAgICAgIGNvbnN0IHBhcnRzID0gdmF1bHRCYXNlLnJlcGxhY2UoL1xcLyskLywgJycpLnNwbGl0KCcvJyk7XG4gICAgICBjb25zdCBiYXNlTmFtZSA9IHBhcnRzW3BhcnRzLmxlbmd0aCAtIDFdO1xuICAgICAgaWYgKCFiYXNlTmFtZSkgY29udGludWU7XG5cbiAgICAgIGNvbnN0IHByZWZpeCA9IGAke2Jhc2VOYW1lfS9gO1xuICAgICAgaWYgKCF0LnN0YXJ0c1dpdGgocHJlZml4KSkgY29udGludWU7XG5cbiAgICAgIGNvbnN0IGNhbmRpZGF0ZSA9IGAke3ZhdWx0QmFzZX0ke3Quc2xpY2UocHJlZml4Lmxlbmd0aCl9YDtcbiAgICAgIGNvbnN0IG5vcm1hbGl6ZWQgPSBjYW5kaWRhdGUucmVwbGFjZSgvXlxcLysvLCAnJyk7XG4gICAgICBpZiAodGhpcy5hcHAudmF1bHQuZ2V0QWJzdHJhY3RGaWxlQnlQYXRoKG5vcm1hbGl6ZWQpKSByZXR1cm4gbm9ybWFsaXplZDtcbiAgICB9XG5cbiAgICByZXR1cm4gbnVsbDtcbiAgfVxuXG4gIHByaXZhdGUgX3ByZXByb2Nlc3NBc3Npc3RhbnRNYXJrZG93bih0ZXh0OiBzdHJpbmcsIG1hcHBpbmdzOiBQYXRoTWFwcGluZ1tdKTogc3RyaW5nIHtcbiAgICBjb25zdCBjYW5kaWRhdGVzID0gZXh0cmFjdENhbmRpZGF0ZXModGV4dCk7XG4gICAgaWYgKGNhbmRpZGF0ZXMubGVuZ3RoID09PSAwKSByZXR1cm4gdGV4dDtcblxuICAgIGxldCBvdXQgPSAnJztcbiAgICBsZXQgY3Vyc29yID0gMDtcblxuICAgIGZvciAoY29uc3QgYyBvZiBjYW5kaWRhdGVzKSB7XG4gICAgICBvdXQgKz0gdGV4dC5zbGljZShjdXJzb3IsIGMuc3RhcnQpO1xuICAgICAgY3Vyc29yID0gYy5lbmQ7XG5cbiAgICAgIGlmIChjLmtpbmQgPT09ICd1cmwnKSB7XG4gICAgICAgIC8vIFVSTHMgcmVtYWluIFVSTHMgVU5MRVNTIHdlIGNhbiBzYWZlbHkgbWFwIHRvIGFuIGV4aXN0aW5nIHZhdWx0IGZpbGUuXG4gICAgICAgIGNvbnN0IG1hcHBlZCA9IHRoaXMuX3RyeVJldmVyc2VNYXBVcmxUb1ZhdWx0UGF0aChjLnJhdywgbWFwcGluZ3MpO1xuICAgICAgICBvdXQgKz0gbWFwcGVkID8gYFtbJHttYXBwZWR9XV1gIDogYy5yYXc7XG4gICAgICAgIGNvbnRpbnVlO1xuICAgICAgfVxuXG4gICAgICAvLyAxKSBJZiB0aGUgdG9rZW4gaXMgYWxyZWFkeSBhIHZhdWx0LXJlbGF0aXZlIHBhdGggKG9yIGNhbiBiZSByZXNvbHZlZCB2aWEgdmF1bHRCYXNlIGhldXJpc3RpYyksIGxpbmtpZnkgaXQgZGlyZWN0bHkuXG4gICAgICBjb25zdCBkaXJlY3QgPSB0aGlzLl90cnlNYXBWYXVsdFJlbGF0aXZlVG9rZW4oYy5yYXcsIG1hcHBpbmdzKTtcbiAgICAgIGlmIChkaXJlY3QpIHtcbiAgICAgICAgb3V0ICs9IGBbWyR7ZGlyZWN0fV1dYDtcbiAgICAgICAgY29udGludWU7XG4gICAgICB9XG5cbiAgICAgIC8vIDIpIEVsc2U6IHRyeSByZW1vdGVcdTIxOTJ2YXVsdCBtYXBwaW5nLlxuICAgICAgY29uc3QgbWFwcGVkID0gdHJ5TWFwUmVtb3RlUGF0aFRvVmF1bHRQYXRoKGMucmF3LCBtYXBwaW5ncyk7XG4gICAgICBpZiAoIW1hcHBlZCkge1xuICAgICAgICBvdXQgKz0gYy5yYXc7XG4gICAgICAgIGNvbnRpbnVlO1xuICAgICAgfVxuXG4gICAgICBpZiAoIXRoaXMuYXBwLnZhdWx0LmdldEFic3RyYWN0RmlsZUJ5UGF0aChtYXBwZWQpKSB7XG4gICAgICAgIG91dCArPSBjLnJhdztcbiAgICAgICAgY29udGludWU7XG4gICAgICB9XG5cbiAgICAgIG91dCArPSBgW1ske21hcHBlZH1dXWA7XG4gICAgfVxuXG4gICAgb3V0ICs9IHRleHQuc2xpY2UoY3Vyc29yKTtcbiAgICByZXR1cm4gb3V0O1xuICB9XG5cbiAgcHJpdmF0ZSBfcmVuZGVyQXNzaXN0YW50UGxhaW5XaXRoTGlua3MoXG4gICAgYm9keTogSFRNTEVsZW1lbnQsXG4gICAgdGV4dDogc3RyaW5nLFxuICAgIG1hcHBpbmdzOiBQYXRoTWFwcGluZ1tdLFxuICAgIHNvdXJjZVBhdGg6IHN0cmluZyxcbiAgKTogdm9pZCB7XG4gICAgY29uc3QgY2FuZGlkYXRlcyA9IGV4dHJhY3RDYW5kaWRhdGVzKHRleHQpO1xuICAgIGlmIChjYW5kaWRhdGVzLmxlbmd0aCA9PT0gMCkge1xuICAgICAgYm9keS5zZXRUZXh0KHRleHQpO1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIGxldCBjdXJzb3IgPSAwO1xuXG4gICAgY29uc3QgYXBwZW5kVGV4dCA9IChzOiBzdHJpbmcpID0+IHtcbiAgICAgIGlmICghcykgcmV0dXJuO1xuICAgICAgYm9keS5hcHBlbmRDaGlsZChkb2N1bWVudC5jcmVhdGVUZXh0Tm9kZShzKSk7XG4gICAgfTtcblxuICAgIGNvbnN0IGFwcGVuZE9ic2lkaWFuTGluayA9ICh2YXVsdFBhdGg6IHN0cmluZykgPT4ge1xuICAgICAgY29uc3QgZGlzcGxheSA9IGBbWyR7dmF1bHRQYXRofV1dYDtcbiAgICAgIGNvbnN0IGEgPSBib2R5LmNyZWF0ZUVsKCdhJywgeyB0ZXh0OiBkaXNwbGF5LCBocmVmOiAnIycgfSk7XG4gICAgICBhLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKGV2KSA9PiB7XG4gICAgICAgIGV2LnByZXZlbnREZWZhdWx0KCk7XG4gICAgICAgIGV2LnN0b3BQcm9wYWdhdGlvbigpO1xuXG4gICAgICAgIGNvbnN0IGYgPSB0aGlzLmFwcC52YXVsdC5nZXRBYnN0cmFjdEZpbGVCeVBhdGgodmF1bHRQYXRoKTtcbiAgICAgICAgaWYgKGYgaW5zdGFuY2VvZiBURmlsZSkge1xuICAgICAgICAgIHZvaWQgdGhpcy5hcHAud29ya3NwYWNlLmdldExlYWYodHJ1ZSkub3BlbkZpbGUoZik7XG4gICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgLy8gRmFsbGJhY2s6IGJlc3QtZWZmb3J0IGxpbmt0ZXh0IG9wZW4uXG4gICAgICAgIHZvaWQgdGhpcy5hcHAud29ya3NwYWNlLm9wZW5MaW5rVGV4dCh2YXVsdFBhdGgsIHNvdXJjZVBhdGgsIHRydWUpO1xuICAgICAgfSk7XG4gICAgfTtcblxuICAgIGNvbnN0IGFwcGVuZEV4dGVybmFsVXJsID0gKHVybDogc3RyaW5nKSA9PiB7XG4gICAgICAvLyBMZXQgT2JzaWRpYW4vRWxlY3Ryb24gaGFuZGxlIGV4dGVybmFsIG9wZW4uXG4gICAgICBib2R5LmNyZWF0ZUVsKCdhJywgeyB0ZXh0OiB1cmwsIGhyZWY6IHVybCB9KTtcbiAgICB9O1xuXG4gICAgY29uc3QgdHJ5UmV2ZXJzZU1hcFVybFRvVmF1bHRQYXRoID0gKHVybDogc3RyaW5nKTogc3RyaW5nIHwgbnVsbCA9PiB0aGlzLl90cnlSZXZlcnNlTWFwVXJsVG9WYXVsdFBhdGgodXJsLCBtYXBwaW5ncyk7XG5cbiAgICBmb3IgKGNvbnN0IGMgb2YgY2FuZGlkYXRlcykge1xuICAgICAgYXBwZW5kVGV4dCh0ZXh0LnNsaWNlKGN1cnNvciwgYy5zdGFydCkpO1xuICAgICAgY3Vyc29yID0gYy5lbmQ7XG5cbiAgICAgIGlmIChjLmtpbmQgPT09ICd1cmwnKSB7XG4gICAgICAgIGNvbnN0IG1hcHBlZCA9IHRyeVJldmVyc2VNYXBVcmxUb1ZhdWx0UGF0aChjLnJhdyk7XG4gICAgICAgIGlmIChtYXBwZWQpIHtcbiAgICAgICAgICBhcHBlbmRPYnNpZGlhbkxpbmsobWFwcGVkKTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICBhcHBlbmRFeHRlcm5hbFVybChjLnJhdyk7XG4gICAgICAgIH1cbiAgICAgICAgY29udGludWU7XG4gICAgICB9XG5cbiAgICAgIC8vIDEpIElmIHRva2VuIGlzIGFscmVhZHkgYSB2YXVsdC1yZWxhdGl2ZSBwYXRoIChvciBjYW4gYmUgcmVzb2x2ZWQgdmlhIHZhdWx0QmFzZSBoZXVyaXN0aWMpLCBsaW5raWZ5IGRpcmVjdGx5LlxuICAgICAgY29uc3QgZGlyZWN0ID0gdGhpcy5fdHJ5TWFwVmF1bHRSZWxhdGl2ZVRva2VuKGMucmF3LCBtYXBwaW5ncyk7XG4gICAgICBpZiAoZGlyZWN0KSB7XG4gICAgICAgIGFwcGVuZE9ic2lkaWFuTGluayhkaXJlY3QpO1xuICAgICAgICBjb250aW51ZTtcbiAgICAgIH1cblxuICAgICAgLy8gMikgRWxzZTogdHJ5IHJlbW90ZVx1MjE5MnZhdWx0IG1hcHBpbmcuXG4gICAgICBjb25zdCBtYXBwZWQgPSB0cnlNYXBSZW1vdGVQYXRoVG9WYXVsdFBhdGgoYy5yYXcsIG1hcHBpbmdzKTtcbiAgICAgIGlmICghbWFwcGVkKSB7XG4gICAgICAgIGFwcGVuZFRleHQoYy5yYXcpO1xuICAgICAgICBjb250aW51ZTtcbiAgICAgIH1cblxuICAgICAgaWYgKCF0aGlzLmFwcC52YXVsdC5nZXRBYnN0cmFjdEZpbGVCeVBhdGgobWFwcGVkKSkge1xuICAgICAgICBhcHBlbmRUZXh0KGMucmF3KTtcbiAgICAgICAgY29udGludWU7XG4gICAgICB9XG5cbiAgICAgIGFwcGVuZE9ic2lkaWFuTGluayhtYXBwZWQpO1xuICAgIH1cblxuICAgIGFwcGVuZFRleHQodGV4dC5zbGljZShjdXJzb3IpKTtcbiAgfVxuXG4gIHByaXZhdGUgX3VwZGF0ZVNlbmRCdXR0b24oKTogdm9pZCB7XG4gICAgLy8gRGlzY29ubmVjdGVkOiBkaXNhYmxlLlxuICAgIC8vIFdvcmtpbmc6IGtlZXAgZW5hYmxlZCBzbyB1c2VyIGNhbiBzdG9wL2Fib3J0LlxuICAgIGNvbnN0IGRpc2FibGVkID0gIXRoaXMuaXNDb25uZWN0ZWQ7XG4gICAgdGhpcy5zZW5kQnRuLmRpc2FibGVkID0gZGlzYWJsZWQ7XG5cbiAgICB0aGlzLnNlbmRCdG4udG9nZ2xlQ2xhc3MoJ2lzLXdvcmtpbmcnLCB0aGlzLmlzV29ya2luZyk7XG4gICAgdGhpcy5zZW5kQnRuLnNldEF0dHIoJ2FyaWEtYnVzeScsIHRoaXMuaXNXb3JraW5nID8gJ3RydWUnIDogJ2ZhbHNlJyk7XG4gICAgdGhpcy5zZW5kQnRuLnNldEF0dHIoJ2FyaWEtbGFiZWwnLCB0aGlzLmlzV29ya2luZyA/ICdTdG9wJyA6ICdTZW5kJyk7XG5cbiAgICBpZiAodGhpcy5pc1dvcmtpbmcpIHtcbiAgICAgIC8vIFJlcGxhY2UgYnV0dG9uIGNvbnRlbnRzIHdpdGggU3RvcCBpY29uICsgc3Bpbm5lciByaW5nLlxuICAgICAgdGhpcy5zZW5kQnRuLmVtcHR5KCk7XG4gICAgICBjb25zdCB3cmFwID0gdGhpcy5zZW5kQnRuLmNyZWF0ZURpdih7IGNsczogJ29jbGF3LXN0b3Atd3JhcCcgfSk7XG4gICAgICB3cmFwLmNyZWF0ZURpdih7IGNsczogJ29jbGF3LXNwaW5uZXItcmluZycsIGF0dHI6IHsgJ2FyaWEtaGlkZGVuJzogJ3RydWUnIH0gfSk7XG4gICAgICB3cmFwLmNyZWF0ZURpdih7IGNsczogJ29jbGF3LXN0b3AtaWNvbicsIGF0dHI6IHsgJ2FyaWEtaGlkZGVuJzogJ3RydWUnIH0gfSk7XG4gICAgfSBlbHNlIHtcbiAgICAgIC8vIFJlc3RvcmUgbGFiZWxcbiAgICAgIHRoaXMuc2VuZEJ0bi5zZXRUZXh0KCdTZW5kJyk7XG4gICAgfVxuICB9XG5cbiAgLy8gXHUyNTAwXHUyNTAwIFNlbmQgaGFuZGxlciBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcblxuICBwcml2YXRlIGFzeW5jIF9oYW5kbGVTZW5kKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIC8vIFdoaWxlIHdvcmtpbmcsIHRoZSBidXR0b24gYmVjb21lcyBTdG9wLlxuICAgIGlmICh0aGlzLmlzV29ya2luZykge1xuICAgICAgY29uc3Qgb2sgPSBhd2FpdCB0aGlzLndzQ2xpZW50LmFib3J0QWN0aXZlUnVuKCk7XG4gICAgICBpZiAoIW9rKSB7XG4gICAgICAgIG5ldyBOb3RpY2UoJ09wZW5DbGF3IENoYXQ6IGZhaWxlZCB0byBzdG9wJyk7XG4gICAgICAgIHRoaXMuY2hhdE1hbmFnZXIuYWRkTWVzc2FnZShDaGF0TWFuYWdlci5jcmVhdGVTeXN0ZW1NZXNzYWdlKCdcdTI2QTAgU3RvcCBmYWlsZWQnLCAnZXJyb3InKSk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICB0aGlzLmNoYXRNYW5hZ2VyLmFkZE1lc3NhZ2UoQ2hhdE1hbmFnZXIuY3JlYXRlU3lzdGVtTWVzc2FnZSgnXHUyNkQ0IFN0b3BwZWQnLCAnaW5mbycpKTtcbiAgICAgIH1cbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICBjb25zdCB0ZXh0ID0gdGhpcy5pbnB1dEVsLnZhbHVlLnRyaW0oKTtcbiAgICBpZiAoIXRleHQpIHJldHVybjtcblxuICAgIC8vIEJ1aWxkIG1lc3NhZ2Ugd2l0aCBjb250ZXh0IGlmIGVuYWJsZWRcbiAgICBsZXQgbWVzc2FnZSA9IHRleHQ7XG4gICAgaWYgKHRoaXMuaW5jbHVkZU5vdGVDaGVja2JveC5jaGVja2VkKSB7XG4gICAgICBjb25zdCBub3RlID0gYXdhaXQgZ2V0QWN0aXZlTm90ZUNvbnRleHQodGhpcy5hcHApO1xuICAgICAgaWYgKG5vdGUpIHtcbiAgICAgICAgbWVzc2FnZSA9IGBDb250ZXh0OiBbWyR7bm90ZS50aXRsZX1dXVxcblxcbiR7dGV4dH1gO1xuICAgICAgfVxuICAgIH1cblxuICAgIC8vIEFkZCB1c2VyIG1lc3NhZ2UgdG8gY2hhdCBVSVxuICAgIGNvbnN0IHVzZXJNc2cgPSBDaGF0TWFuYWdlci5jcmVhdGVVc2VyTWVzc2FnZSh0ZXh0KTtcbiAgICB0aGlzLmNoYXRNYW5hZ2VyLmFkZE1lc3NhZ2UodXNlck1zZyk7XG5cbiAgICAvLyBDbGVhciBpbnB1dFxuICAgIHRoaXMuaW5wdXRFbC52YWx1ZSA9ICcnO1xuICAgIHRoaXMuaW5wdXRFbC5zdHlsZS5oZWlnaHQgPSAnYXV0byc7XG5cbiAgICAvLyBTZW5kIG92ZXIgV1MgKGFzeW5jKVxuICAgIHRyeSB7XG4gICAgICBhd2FpdCB0aGlzLndzQ2xpZW50LnNlbmRNZXNzYWdlKG1lc3NhZ2UpO1xuICAgIH0gY2F0Y2ggKGVycikge1xuICAgICAgY29uc29sZS5lcnJvcignW29jbGF3XSBTZW5kIGZhaWxlZCcsIGVycik7XG4gICAgICBuZXcgTm90aWNlKGBPcGVuQ2xhdyBDaGF0OiBzZW5kIGZhaWxlZCAoJHtTdHJpbmcoZXJyKX0pYCk7XG4gICAgICB0aGlzLmNoYXRNYW5hZ2VyLmFkZE1lc3NhZ2UoXG4gICAgICAgIENoYXRNYW5hZ2VyLmNyZWF0ZVN5c3RlbU1lc3NhZ2UoYFx1MjZBMCBTZW5kIGZhaWxlZDogJHtlcnJ9YCwgJ2Vycm9yJylcbiAgICAgICk7XG4gICAgfVxuICB9XG59XG4iLCAiaW1wb3J0IHR5cGUgeyBDaGF0TWVzc2FnZSB9IGZyb20gJy4vdHlwZXMnO1xuXG4vKiogTWFuYWdlcyB0aGUgaW4tbWVtb3J5IGxpc3Qgb2YgY2hhdCBtZXNzYWdlcyBhbmQgbm90aWZpZXMgVUkgb24gY2hhbmdlcyAqL1xuZXhwb3J0IGNsYXNzIENoYXRNYW5hZ2VyIHtcbiAgcHJpdmF0ZSBtZXNzYWdlczogQ2hhdE1lc3NhZ2VbXSA9IFtdO1xuXG4gIC8qKiBGaXJlZCBmb3IgYSBmdWxsIHJlLXJlbmRlciAoY2xlYXIvcmVsb2FkKSAqL1xuICBvblVwZGF0ZTogKChtZXNzYWdlczogcmVhZG9ubHkgQ2hhdE1lc3NhZ2VbXSkgPT4gdm9pZCkgfCBudWxsID0gbnVsbDtcbiAgLyoqIEZpcmVkIHdoZW4gYSBzaW5nbGUgbWVzc2FnZSBpcyBhcHBlbmRlZCBcdTIwMTQgdXNlIGZvciBPKDEpIGFwcGVuZC1vbmx5IFVJICovXG4gIG9uTWVzc2FnZUFkZGVkOiAoKG1zZzogQ2hhdE1lc3NhZ2UpID0+IHZvaWQpIHwgbnVsbCA9IG51bGw7XG5cbiAgYWRkTWVzc2FnZShtc2c6IENoYXRNZXNzYWdlKTogdm9pZCB7XG4gICAgdGhpcy5tZXNzYWdlcy5wdXNoKG1zZyk7XG4gICAgdGhpcy5vbk1lc3NhZ2VBZGRlZD8uKG1zZyk7XG4gIH1cblxuICBnZXRNZXNzYWdlcygpOiByZWFkb25seSBDaGF0TWVzc2FnZVtdIHtcbiAgICByZXR1cm4gdGhpcy5tZXNzYWdlcztcbiAgfVxuXG4gIGNsZWFyKCk6IHZvaWQge1xuICAgIHRoaXMubWVzc2FnZXMgPSBbXTtcbiAgICB0aGlzLm9uVXBkYXRlPy4oW10pO1xuICB9XG5cbiAgLyoqIENyZWF0ZSBhIHVzZXIgbWVzc2FnZSBvYmplY3QgKHdpdGhvdXQgYWRkaW5nIGl0KSAqL1xuICBzdGF0aWMgY3JlYXRlVXNlck1lc3NhZ2UoY29udGVudDogc3RyaW5nKTogQ2hhdE1lc3NhZ2Uge1xuICAgIHJldHVybiB7XG4gICAgICBpZDogYG1zZy0ke0RhdGUubm93KCl9LSR7TWF0aC5yYW5kb20oKS50b1N0cmluZygzNikuc2xpY2UoMiwgNyl9YCxcbiAgICAgIHJvbGU6ICd1c2VyJyxcbiAgICAgIGNvbnRlbnQsXG4gICAgICB0aW1lc3RhbXA6IERhdGUubm93KCksXG4gICAgfTtcbiAgfVxuXG4gIC8qKiBDcmVhdGUgYW4gYXNzaXN0YW50IG1lc3NhZ2Ugb2JqZWN0ICh3aXRob3V0IGFkZGluZyBpdCkgKi9cbiAgc3RhdGljIGNyZWF0ZUFzc2lzdGFudE1lc3NhZ2UoY29udGVudDogc3RyaW5nKTogQ2hhdE1lc3NhZ2Uge1xuICAgIHJldHVybiB7XG4gICAgICBpZDogYG1zZy0ke0RhdGUubm93KCl9LSR7TWF0aC5yYW5kb20oKS50b1N0cmluZygzNikuc2xpY2UoMiwgNyl9YCxcbiAgICAgIHJvbGU6ICdhc3Npc3RhbnQnLFxuICAgICAgY29udGVudCxcbiAgICAgIHRpbWVzdGFtcDogRGF0ZS5ub3coKSxcbiAgICB9O1xuICB9XG5cbiAgLyoqIENyZWF0ZSBhIHN5c3RlbSAvIHN0YXR1cyBtZXNzYWdlIChlcnJvcnMsIHJlY29ubmVjdCBub3RpY2VzLCBldGMuKSAqL1xuICBzdGF0aWMgY3JlYXRlU3lzdGVtTWVzc2FnZShjb250ZW50OiBzdHJpbmcsIGxldmVsOiBDaGF0TWVzc2FnZVsnbGV2ZWwnXSA9ICdpbmZvJyk6IENoYXRNZXNzYWdlIHtcbiAgICByZXR1cm4ge1xuICAgICAgaWQ6IGBzeXMtJHtEYXRlLm5vdygpfWAsXG4gICAgICByb2xlOiAnc3lzdGVtJyxcbiAgICAgIGxldmVsLFxuICAgICAgY29udGVudCxcbiAgICAgIHRpbWVzdGFtcDogRGF0ZS5ub3coKSxcbiAgICB9O1xuICB9XG5cbiAgc3RhdGljIGNyZWF0ZVNlc3Npb25EaXZpZGVyKHNlc3Npb25LZXk6IHN0cmluZyk6IENoYXRNZXNzYWdlIHtcbiAgICBjb25zdCBzaG9ydCA9IHNlc3Npb25LZXkubGVuZ3RoID4gMjggPyBgJHtzZXNzaW9uS2V5LnNsaWNlKDAsIDEyKX1cdTIwMjYke3Nlc3Npb25LZXkuc2xpY2UoLTEyKX1gIDogc2Vzc2lvbktleTtcbiAgICByZXR1cm4ge1xuICAgICAgaWQ6IGBkaXYtJHtEYXRlLm5vdygpfWAsXG4gICAgICByb2xlOiAnc3lzdGVtJyxcbiAgICAgIGxldmVsOiAnaW5mbycsXG4gICAgICBraW5kOiAnc2Vzc2lvbi1kaXZpZGVyJyxcbiAgICAgIHRpdGxlOiBzZXNzaW9uS2V5LFxuICAgICAgY29udGVudDogYFtTZXNzaW9uOiAke3Nob3J0fV1gLFxuICAgICAgdGltZXN0YW1wOiBEYXRlLm5vdygpLFxuICAgIH07XG4gIH1cbn1cbiIsICJpbXBvcnQgdHlwZSB7IFBhdGhNYXBwaW5nIH0gZnJvbSAnLi90eXBlcyc7XG5cbmV4cG9ydCBmdW5jdGlvbiBub3JtYWxpemVCYXNlKGJhc2U6IHN0cmluZyk6IHN0cmluZyB7XG4gIGNvbnN0IHRyaW1tZWQgPSBTdHJpbmcoYmFzZSA/PyAnJykudHJpbSgpO1xuICBpZiAoIXRyaW1tZWQpIHJldHVybiAnJztcbiAgcmV0dXJuIHRyaW1tZWQuZW5kc1dpdGgoJy8nKSA/IHRyaW1tZWQgOiBgJHt0cmltbWVkfS9gO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gdHJ5TWFwUmVtb3RlUGF0aFRvVmF1bHRQYXRoKGlucHV0OiBzdHJpbmcsIG1hcHBpbmdzOiByZWFkb25seSBQYXRoTWFwcGluZ1tdKTogc3RyaW5nIHwgbnVsbCB7XG4gIGNvbnN0IHJhdyA9IFN0cmluZyhpbnB1dCA/PyAnJyk7XG4gIGZvciAoY29uc3Qgcm93IG9mIG1hcHBpbmdzKSB7XG4gICAgY29uc3QgcmVtb3RlQmFzZSA9IG5vcm1hbGl6ZUJhc2Uocm93LnJlbW90ZUJhc2UpO1xuICAgIGNvbnN0IHZhdWx0QmFzZSA9IG5vcm1hbGl6ZUJhc2Uocm93LnZhdWx0QmFzZSk7XG4gICAgaWYgKCFyZW1vdGVCYXNlIHx8ICF2YXVsdEJhc2UpIGNvbnRpbnVlO1xuXG4gICAgaWYgKHJhdy5zdGFydHNXaXRoKHJlbW90ZUJhc2UpKSB7XG4gICAgICBjb25zdCByZXN0ID0gcmF3LnNsaWNlKHJlbW90ZUJhc2UubGVuZ3RoKTtcbiAgICAgIC8vIE9ic2lkaWFuIHBhdGhzIGFyZSB2YXVsdC1yZWxhdGl2ZSBhbmQgc2hvdWxkIG5vdCBzdGFydCB3aXRoICcvJ1xuICAgICAgcmV0dXJuIGAke3ZhdWx0QmFzZX0ke3Jlc3R9YC5yZXBsYWNlKC9eXFwvKy8sICcnKTtcbiAgICB9XG4gIH1cbiAgcmV0dXJuIG51bGw7XG59XG5cbmV4cG9ydCB0eXBlIENhbmRpZGF0ZSA9IHsgc3RhcnQ6IG51bWJlcjsgZW5kOiBudW1iZXI7IHJhdzogc3RyaW5nOyBraW5kOiAndXJsJyB8ICdwYXRoJyB9O1xuXG4vLyBDb25zZXJ2YXRpdmUgZXh0cmFjdGlvbjogYWltIHRvIGF2b2lkIGZhbHNlIHBvc2l0aXZlcy5cbmNvbnN0IFVSTF9SRSA9IC9odHRwcz86XFwvXFwvW15cXHM8PigpXSsvZztcbi8vIEFic29sdXRlIHVuaXgtaXNoIHBhdGhzLlxuLy8gKFdlIHN0aWxsIGV4aXN0ZW5jZS1jaGVjayBiZWZvcmUgcHJvZHVjaW5nIGEgbGluay4pXG5jb25zdCBQQVRIX1JFID0gLyg/PCFbQS1aYS16MC05Ll8tXSkoPzpcXC9bQS1aYS16MC05Ll9+ISQmJygpKissOz06QCVcXC1dKykrKD86XFwuW0EtWmEtejAtOS5fLV0rKT8vZztcblxuLy8gQ29uc2VydmF0aXZlIHJlbGF0aXZlIHBhdGhzIHdpdGggYXQgbGVhc3Qgb25lICcvJywgZS5nLiBjb21wZW5nL3BsYW5zL3gubWRcbi8vIEF2b2lkcyBtYXRjaGluZyBzY2hlbWUtbGlrZSB0b2tlbnMgdmlhIG5lZ2F0aXZlIGxvb2thaGVhZCBmb3IgJzovLycuXG5jb25zdCBSRUxfUEFUSF9SRSA9IC9cXGIoPyFbQS1aYS16XVtBLVphLXowLTkrLi1dKjpcXC9cXC8pW0EtWmEtejAtOS5fLV0rKD86XFwvW0EtWmEtejAtOS5fLV0rKSsoPzpcXC5bQS1aYS16MC05Ll8tXSspP1xcYi9nO1xuXG5leHBvcnQgZnVuY3Rpb24gZXh0cmFjdENhbmRpZGF0ZXModGV4dDogc3RyaW5nKTogQ2FuZGlkYXRlW10ge1xuICBjb25zdCB0ID0gU3RyaW5nKHRleHQgPz8gJycpO1xuICBjb25zdCBvdXQ6IENhbmRpZGF0ZVtdID0gW107XG5cbiAgZm9yIChjb25zdCBtIG9mIHQubWF0Y2hBbGwoVVJMX1JFKSkge1xuICAgIGlmIChtLmluZGV4ID09PSB1bmRlZmluZWQpIGNvbnRpbnVlO1xuICAgIG91dC5wdXNoKHsgc3RhcnQ6IG0uaW5kZXgsIGVuZDogbS5pbmRleCArIG1bMF0ubGVuZ3RoLCByYXc6IG1bMF0sIGtpbmQ6ICd1cmwnIH0pO1xuICB9XG5cbiAgZm9yIChjb25zdCBtIG9mIHQubWF0Y2hBbGwoUEFUSF9SRSkpIHtcbiAgICBpZiAobS5pbmRleCA9PT0gdW5kZWZpbmVkKSBjb250aW51ZTtcblxuICAgIC8vIFNraXAgaWYgdGhpcyBpcyBpbnNpZGUgYSBVUkwgd2UgYWxyZWFkeSBjYXB0dXJlZC5cbiAgICBjb25zdCBzdGFydCA9IG0uaW5kZXg7XG4gICAgY29uc3QgZW5kID0gc3RhcnQgKyBtWzBdLmxlbmd0aDtcbiAgICBjb25zdCBvdmVybGFwc1VybCA9IG91dC5zb21lKChjKSA9PiBjLmtpbmQgPT09ICd1cmwnICYmICEoZW5kIDw9IGMuc3RhcnQgfHwgc3RhcnQgPj0gYy5lbmQpKTtcbiAgICBpZiAob3ZlcmxhcHNVcmwpIGNvbnRpbnVlO1xuXG4gICAgb3V0LnB1c2goeyBzdGFydCwgZW5kLCByYXc6IG1bMF0sIGtpbmQ6ICdwYXRoJyB9KTtcbiAgfVxuXG4gIGZvciAoY29uc3QgbSBvZiB0Lm1hdGNoQWxsKFJFTF9QQVRIX1JFKSkge1xuICAgIGlmIChtLmluZGV4ID09PSB1bmRlZmluZWQpIGNvbnRpbnVlO1xuXG4gICAgY29uc3Qgc3RhcnQgPSBtLmluZGV4O1xuICAgIGNvbnN0IGVuZCA9IHN0YXJ0ICsgbVswXS5sZW5ndGg7XG4gICAgY29uc3Qgb3ZlcmxhcHNFeGlzdGluZyA9IG91dC5zb21lKChjKSA9PiAhKGVuZCA8PSBjLnN0YXJ0IHx8IHN0YXJ0ID49IGMuZW5kKSk7XG4gICAgaWYgKG92ZXJsYXBzRXhpc3RpbmcpIGNvbnRpbnVlO1xuXG4gICAgb3V0LnB1c2goeyBzdGFydCwgZW5kLCByYXc6IG1bMF0sIGtpbmQ6ICdwYXRoJyB9KTtcbiAgfVxuXG4gIC8vIFNvcnQgYW5kIGRyb3Agb3ZlcmxhcHMgKHByZWZlciBVUkxzKS5cbiAgb3V0LnNvcnQoKGEsIGIpID0+IGEuc3RhcnQgLSBiLnN0YXJ0IHx8IChhLmtpbmQgPT09ICd1cmwnID8gLTEgOiAxKSk7XG4gIGNvbnN0IGRlZHVwOiBDYW5kaWRhdGVbXSA9IFtdO1xuICBmb3IgKGNvbnN0IGMgb2Ygb3V0KSB7XG4gICAgY29uc3QgbGFzdCA9IGRlZHVwW2RlZHVwLmxlbmd0aCAtIDFdO1xuICAgIGlmICghbGFzdCkge1xuICAgICAgZGVkdXAucHVzaChjKTtcbiAgICAgIGNvbnRpbnVlO1xuICAgIH1cbiAgICBpZiAoYy5zdGFydCA8IGxhc3QuZW5kKSBjb250aW51ZTtcbiAgICBkZWR1cC5wdXNoKGMpO1xuICB9XG5cbiAgcmV0dXJuIGRlZHVwO1xufVxuIiwgImltcG9ydCB0eXBlIHsgQXBwIH0gZnJvbSAnb2JzaWRpYW4nO1xuXG5leHBvcnQgaW50ZXJmYWNlIE5vdGVDb250ZXh0IHtcbiAgdGl0bGU6IHN0cmluZztcbiAgcGF0aDogc3RyaW5nO1xuICBjb250ZW50OiBzdHJpbmc7XG59XG5cbi8qKlxuICogUmV0dXJucyB0aGUgYWN0aXZlIG5vdGUncyB0aXRsZSBhbmQgY29udGVudCwgb3IgbnVsbCBpZiBubyBub3RlIGlzIG9wZW4uXG4gKiBBc3luYyBiZWNhdXNlIHZhdWx0LnJlYWQoKSBpcyBhc3luYy5cbiAqL1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGdldEFjdGl2ZU5vdGVDb250ZXh0KGFwcDogQXBwKTogUHJvbWlzZTxOb3RlQ29udGV4dCB8IG51bGw+IHtcbiAgY29uc3QgZmlsZSA9IGFwcC53b3Jrc3BhY2UuZ2V0QWN0aXZlRmlsZSgpO1xuICBpZiAoIWZpbGUpIHJldHVybiBudWxsO1xuXG4gIHRyeSB7XG4gICAgY29uc3QgY29udGVudCA9IGF3YWl0IGFwcC52YXVsdC5yZWFkKGZpbGUpO1xuICAgIHJldHVybiB7XG4gICAgICB0aXRsZTogZmlsZS5iYXNlbmFtZSxcbiAgICAgIHBhdGg6IGZpbGUucGF0aCxcbiAgICAgIGNvbnRlbnQsXG4gICAgfTtcbiAgfSBjYXRjaCAoZXJyKSB7XG4gICAgY29uc29sZS5lcnJvcignW29jbGF3LWNvbnRleHRdIEZhaWxlZCB0byByZWFkIGFjdGl2ZSBub3RlJywgZXJyKTtcbiAgICByZXR1cm4gbnVsbDtcbiAgfVxufVxuIiwgIi8qKiBQZXJzaXN0ZWQgcGx1Z2luIGNvbmZpZ3VyYXRpb24gKi9cbmV4cG9ydCBpbnRlcmZhY2UgT3BlbkNsYXdTZXR0aW5ncyB7XG4gIC8qKiBXZWJTb2NrZXQgVVJMIG9mIHRoZSBPcGVuQ2xhdyBHYXRld2F5IChlLmcuIHdzOi8vMTAwLjkwLjkuNjg6MTg3ODkpICovXG4gIGdhdGV3YXlVcmw6IHN0cmluZztcbiAgLyoqIEF1dGggdG9rZW4gXHUyMDE0IG11c3QgbWF0Y2ggdGhlIGNoYW5uZWwgcGx1Z2luJ3MgYXV0aFRva2VuICovXG4gIGF1dGhUb2tlbjogc3RyaW5nO1xuICAvKiogT3BlbkNsYXcgc2Vzc2lvbiBrZXkgdG8gc3Vic2NyaWJlIHRvIChlLmcuIFwibWFpblwiKSAqL1xuICBzZXNzaW9uS2V5OiBzdHJpbmc7XG4gIC8qKiAoRGVwcmVjYXRlZCkgT3BlbkNsYXcgYWNjb3VudCBJRCAodW51c2VkOyBjaGF0LnNlbmQgdXNlcyBzZXNzaW9uS2V5KSAqL1xuICBhY2NvdW50SWQ6IHN0cmluZztcbiAgLyoqIFdoZXRoZXIgdG8gaW5jbHVkZSB0aGUgYWN0aXZlIG5vdGUgY29udGVudCB3aXRoIGVhY2ggbWVzc2FnZSAqL1xuICBpbmNsdWRlQWN0aXZlTm90ZTogYm9vbGVhbjtcbiAgLyoqIFJlbmRlciBhc3Npc3RhbnQgb3V0cHV0IGFzIE1hcmtkb3duICh1bnNhZmU6IG1heSB0cmlnZ2VyIGVtYmVkcy9wb3N0LXByb2Nlc3NvcnMpOyBkZWZhdWx0IE9GRiAqL1xuICByZW5kZXJBc3Npc3RhbnRNYXJrZG93bjogYm9vbGVhbjtcbiAgLyoqIEFsbG93IHVzaW5nIGluc2VjdXJlIHdzOi8vIGZvciBub24tbG9jYWwgZ2F0ZXdheSBVUkxzICh1bnNhZmUpOyBkZWZhdWx0IE9GRiAqL1xuICBhbGxvd0luc2VjdXJlV3M6IGJvb2xlYW47XG5cbiAgLyoqIE9wdGlvbmFsOiBtYXAgcmVtb3RlIEZTIHBhdGhzIC8gZXhwb3J0ZWQgcGF0aHMgYmFjayB0byB2YXVsdC1yZWxhdGl2ZSBwYXRocyAqL1xuICBwYXRoTWFwcGluZ3M6IFBhdGhNYXBwaW5nW107XG5cbiAgLyoqIFZhdWx0IGlkZW50aXR5IChoYXNoKSB1c2VkIGZvciBjYW5vbmljYWwgc2Vzc2lvbiBrZXlzLiAqL1xuICB2YXVsdEhhc2g/OiBzdHJpbmc7XG5cbiAgLyoqIEtub3duIE9ic2lkaWFuIHNlc3Npb24ga2V5cyBmb3IgZWFjaCB2YXVsdEhhc2ggKHZhdWx0LXNjb3BlZCBjb250aW51aXR5KS4gKi9cbiAga25vd25TZXNzaW9uS2V5c0J5VmF1bHQ/OiBSZWNvcmQ8c3RyaW5nLCBzdHJpbmdbXT47XG5cbiAgLyoqIExlZ2FjeSBrZXlzIGtlcHQgZm9yIG1pZ3JhdGlvbi9kZWJ1ZyAob3B0aW9uYWwpLiAqL1xuICBsZWdhY3lTZXNzaW9uS2V5cz86IHN0cmluZ1tdO1xufVxuXG5leHBvcnQgdHlwZSBQYXRoTWFwcGluZyA9IHtcbiAgLyoqIFZhdWx0LXJlbGF0aXZlIGJhc2UgcGF0aCAoZS5nLiBcImRvY3MvXCIgb3IgXCJjb21wZW5nL1wiKSAqL1xuICB2YXVsdEJhc2U6IHN0cmluZztcbiAgLyoqIFJlbW90ZSBGUyBiYXNlIHBhdGggKGUuZy4gXCIvaG9tZS93YWxsLWUvLm9wZW5jbGF3L3dvcmtzcGFjZS9kb2NzL1wiKSAqL1xuICByZW1vdGVCYXNlOiBzdHJpbmc7XG59O1xuXG5leHBvcnQgY29uc3QgREVGQVVMVF9TRVRUSU5HUzogT3BlbkNsYXdTZXR0aW5ncyA9IHtcbiAgZ2F0ZXdheVVybDogJ3dzOi8vbG9jYWxob3N0OjE4Nzg5JyxcbiAgYXV0aFRva2VuOiAnJyxcbiAgc2Vzc2lvbktleTogJ21haW4nLFxuICBhY2NvdW50SWQ6ICdtYWluJyxcbiAgaW5jbHVkZUFjdGl2ZU5vdGU6IGZhbHNlLFxuICByZW5kZXJBc3Npc3RhbnRNYXJrZG93bjogZmFsc2UsXG4gIGFsbG93SW5zZWN1cmVXczogZmFsc2UsXG4gIHBhdGhNYXBwaW5nczogW10sXG4gIHZhdWx0SGFzaDogdW5kZWZpbmVkLFxuICBrbm93blNlc3Npb25LZXlzQnlWYXVsdDoge30sXG4gIGxlZ2FjeVNlc3Npb25LZXlzOiBbXSxcbn07XG5cbi8qKiBBIHNpbmdsZSBjaGF0IG1lc3NhZ2UgKi9cbmV4cG9ydCBpbnRlcmZhY2UgQ2hhdE1lc3NhZ2Uge1xuICBpZDogc3RyaW5nO1xuICByb2xlOiAndXNlcicgfCAnYXNzaXN0YW50JyB8ICdzeXN0ZW0nO1xuICAvKiogT3B0aW9uYWwgc2V2ZXJpdHkgZm9yIHN5c3RlbS9zdGF0dXMgbWVzc2FnZXMgKi9cbiAgbGV2ZWw/OiAnaW5mbycgfCAnZXJyb3InO1xuICAvKiogT3B0aW9uYWwgc3VidHlwZSBmb3Igc3R5bGluZyBzcGVjaWFsIHN5c3RlbSBtZXNzYWdlcyAoZS5nLiBzZXNzaW9uIGRpdmlkZXIpLiAqL1xuICBraW5kPzogJ3Nlc3Npb24tZGl2aWRlcic7XG4gIC8qKiBPcHRpb25hbCBob3ZlciB0b29sdGlwIGZvciB0aGUgbWVzc2FnZSAoZS5nLiBmdWxsIHNlc3Npb24ga2V5KS4gKi9cbiAgdGl0bGU/OiBzdHJpbmc7XG4gIGNvbnRlbnQ6IHN0cmluZztcbiAgdGltZXN0YW1wOiBudW1iZXI7XG59XG5cbi8qKiBQYXlsb2FkIGZvciBtZXNzYWdlcyBTRU5UIHRvIHRoZSBzZXJ2ZXIgKG91dGJvdW5kKSAqL1xuZXhwb3J0IGludGVyZmFjZSBXU1BheWxvYWQge1xuICB0eXBlOiAnYXV0aCcgfCAnbWVzc2FnZScgfCAncGluZycgfCAncG9uZycgfCAnZXJyb3InO1xuICBwYXlsb2FkPzogUmVjb3JkPHN0cmluZywgdW5rbm93bj47XG59XG5cbi8qKiBNZXNzYWdlcyBSRUNFSVZFRCBmcm9tIHRoZSBzZXJ2ZXIgKGluYm91bmQpIFx1MjAxNCBkaXNjcmltaW5hdGVkIHVuaW9uICovXG5leHBvcnQgdHlwZSBJbmJvdW5kV1NQYXlsb2FkID1cbiAgfCB7IHR5cGU6ICdtZXNzYWdlJzsgcGF5bG9hZDogeyBjb250ZW50OiBzdHJpbmc7IHJvbGU6IHN0cmluZzsgdGltZXN0YW1wOiBudW1iZXIgfSB9XG4gIHwgeyB0eXBlOiAnZXJyb3InOyBwYXlsb2FkOiB7IG1lc3NhZ2U6IHN0cmluZyB9IH07XG5cbi8qKiBBdmFpbGFibGUgYWdlbnRzIC8gbW9kZWxzICovXG5leHBvcnQgaW50ZXJmYWNlIEFnZW50T3B0aW9uIHtcbiAgaWQ6IHN0cmluZztcbiAgbGFiZWw6IHN0cmluZztcbn1cbiIsICJpbXBvcnQgdHlwZSB7IE9wZW5DbGF3U2V0dGluZ3MgfSBmcm9tICcuL3R5cGVzJztcblxuZXhwb3J0IGZ1bmN0aW9uIGNhbm9uaWNhbFZhdWx0U2Vzc2lvbktleSh2YXVsdEhhc2g6IHN0cmluZyk6IHN0cmluZyB7XG4gIHJldHVybiBgYWdlbnQ6bWFpbjpvYnNpZGlhbjpkaXJlY3Q6JHt2YXVsdEhhc2h9YDtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIGlzQWxsb3dlZE9ic2lkaWFuU2Vzc2lvbktleShwYXJhbXM6IHtcbiAga2V5OiBzdHJpbmc7XG4gIHZhdWx0SGFzaDogc3RyaW5nIHwgbnVsbDtcbn0pOiBib29sZWFuIHtcbiAgY29uc3Qga2V5ID0gKHBhcmFtcy5rZXkgPz8gJycpLnRyaW0oKS50b0xvd2VyQ2FzZSgpO1xuICBpZiAoIWtleSkgcmV0dXJuIGZhbHNlO1xuICBpZiAoa2V5ID09PSAnbWFpbicpIHJldHVybiB0cnVlO1xuXG4gIGNvbnN0IHZhdWx0SGFzaCA9IChwYXJhbXMudmF1bHRIYXNoID8/ICcnKS50cmltKCkudG9Mb3dlckNhc2UoKTtcbiAgaWYgKCF2YXVsdEhhc2gpIHtcbiAgICAvLyBXaXRob3V0IGEgdmF1bHQgaWRlbnRpdHksIHdlIG9ubHkgYWxsb3cgbWFpbi5cbiAgICByZXR1cm4gZmFsc2U7XG4gIH1cblxuICBjb25zdCBwcmVmaXggPSBgYWdlbnQ6bWFpbjpvYnNpZGlhbjpkaXJlY3Q6JHt2YXVsdEhhc2h9YDtcbiAgaWYgKGtleSA9PT0gcHJlZml4KSByZXR1cm4gdHJ1ZTtcbiAgaWYgKGtleS5zdGFydHNXaXRoKHByZWZpeCArICctJykpIHJldHVybiB0cnVlO1xuICByZXR1cm4gZmFsc2U7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBtaWdyYXRlU2V0dGluZ3NGb3JWYXVsdChzZXR0aW5nczogT3BlbkNsYXdTZXR0aW5ncywgdmF1bHRIYXNoOiBzdHJpbmcpOiB7XG4gIG5leHRTZXR0aW5nczogT3BlbkNsYXdTZXR0aW5ncztcbiAgY2Fub25pY2FsS2V5OiBzdHJpbmc7XG59IHtcbiAgY29uc3QgY2Fub25pY2FsS2V5ID0gY2Fub25pY2FsVmF1bHRTZXNzaW9uS2V5KHZhdWx0SGFzaCk7XG4gIGNvbnN0IGV4aXN0aW5nID0gKHNldHRpbmdzLnNlc3Npb25LZXkgPz8gJycpLnRyaW0oKS50b0xvd2VyQ2FzZSgpO1xuICBjb25zdCBpc0xlZ2FjeSA9IGV4aXN0aW5nLnN0YXJ0c1dpdGgoJ29ic2lkaWFuLScpO1xuICBjb25zdCBpc0VtcHR5T3JNYWluID0gIWV4aXN0aW5nIHx8IGV4aXN0aW5nID09PSAnbWFpbicgfHwgZXhpc3RpbmcgPT09ICdhZ2VudDptYWluOm1haW4nO1xuXG4gIGNvbnN0IG5leHQ6IE9wZW5DbGF3U2V0dGluZ3MgPSB7IC4uLnNldHRpbmdzIH07XG4gIG5leHQudmF1bHRIYXNoID0gdmF1bHRIYXNoO1xuXG4gIGlmIChpc0xlZ2FjeSkge1xuICAgIGNvbnN0IGxlZ2FjeSA9IEFycmF5LmlzQXJyYXkobmV4dC5sZWdhY3lTZXNzaW9uS2V5cykgPyBuZXh0LmxlZ2FjeVNlc3Npb25LZXlzIDogW107XG4gICAgbmV4dC5sZWdhY3lTZXNzaW9uS2V5cyA9IFtleGlzdGluZywgLi4ubGVnYWN5LmZpbHRlcigoaykgPT4gayAmJiBrICE9PSBleGlzdGluZyldLnNsaWNlKDAsIDIwKTtcbiAgfVxuXG4gIGlmIChpc0xlZ2FjeSB8fCBpc0VtcHR5T3JNYWluKSB7XG4gICAgbmV4dC5zZXNzaW9uS2V5ID0gY2Fub25pY2FsS2V5O1xuICB9XG5cbiAgY29uc3QgbWFwID0gbmV4dC5rbm93blNlc3Npb25LZXlzQnlWYXVsdCA/PyB7fTtcbiAgY29uc3QgY3VyID0gQXJyYXkuaXNBcnJheShtYXBbdmF1bHRIYXNoXSkgPyBtYXBbdmF1bHRIYXNoXSA6IFtdO1xuICBpZiAoIWN1ci5pbmNsdWRlcyhjYW5vbmljYWxLZXkpKSB7XG4gICAgbWFwW3ZhdWx0SGFzaF0gPSBbY2Fub25pY2FsS2V5LCAuLi5jdXJdLnNsaWNlKDAsIDIwKTtcbiAgICBuZXh0Lmtub3duU2Vzc2lvbktleXNCeVZhdWx0ID0gbWFwO1xuICB9XG5cbiAgcmV0dXJuIHsgbmV4dFNldHRpbmdzOiBuZXh0LCBjYW5vbmljYWxLZXkgfTtcbn1cbiJdLAogICJtYXBwaW5ncyI6ICI7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQSxJQUFBQSxtQkFBaUU7OztBQ0FqRSxzQkFBK0M7QUFHeEMsSUFBTSxxQkFBTixjQUFpQyxpQ0FBaUI7QUFBQSxFQUd2RCxZQUFZLEtBQVUsUUFBd0I7QUFDNUMsVUFBTSxLQUFLLE1BQU07QUFDakIsU0FBSyxTQUFTO0FBQUEsRUFDaEI7QUFBQSxFQUVBLFVBQWdCO0FBWGxCO0FBWUksVUFBTSxFQUFFLFlBQVksSUFBSTtBQUN4QixnQkFBWSxNQUFNO0FBRWxCLGdCQUFZLFNBQVMsTUFBTSxFQUFFLE1BQU0sZ0NBQTJCLENBQUM7QUFFL0QsUUFBSSx3QkFBUSxXQUFXLEVBQ3BCLFFBQVEsYUFBYSxFQUNyQixRQUFRLG1FQUFtRSxFQUMzRTtBQUFBLE1BQVEsQ0FBQyxTQUNSLEtBQ0csZUFBZSxzQkFBc0IsRUFDckMsU0FBUyxLQUFLLE9BQU8sU0FBUyxVQUFVLEVBQ3hDLFNBQVMsQ0FBTyxVQUFVO0FBQ3pCLGFBQUssT0FBTyxTQUFTLGFBQWEsTUFBTSxLQUFLO0FBQzdDLGNBQU0sS0FBSyxPQUFPLGFBQWE7QUFBQSxNQUNqQyxFQUFDO0FBQUEsSUFDTDtBQUVGLFFBQUksd0JBQVEsV0FBVyxFQUNwQixRQUFRLFlBQVksRUFDcEIsUUFBUSw4RUFBOEUsRUFDdEYsUUFBUSxDQUFDLFNBQVM7QUFDakIsV0FDRyxlQUFlLG1CQUFjLEVBQzdCLFNBQVMsS0FBSyxP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USxXQUFNLEtBQUssU0FBUyxNQUFwQixZQUEwQixDQUFDO0FBQ3pDLFdBQUssNkJBQWUsS0FBSyx5QkFBd0I7QUFBVztBQUM1RCxZQUFNLE9BQU8sbUJBQU07QUFDbkIsYUFBTyxLQUFLLEtBQUssa0JBQWtCO0FBQ25DLFlBQU0sS0FBSyxTQUFTLElBQUk7QUFBQSxJQUMxQjtBQUFBO0FBQUE7QUFBQSxFQUljLG9CQUFtQztBQUFBO0FBQy9DLFlBQU0sRUFBRSxVQUFVLElBQUksS0FBSztBQUczQixZQUFNLFdBQVcsVUFBVSxnQkFBZ0IsdUJBQXVCO0FBQ2xFLFVBQUksU0FBUyxTQUFTLEdBQUc7QUFDdkIsa0JBQVUsV0FBVyxTQUFTLENBQUMsQ0FBQztBQUNoQztBQUFBLE1BQ0Y7QUFHQSxZQUFNLE9BQU8sVUFBVSxhQUFhLEtBQUs7QUFDekMsVUFBSSxDQUFDO0FBQU07QUFDWCxZQUFNLEtBQUssYUFBYSxFQUFFLE1BQU0seUJBQXlCLFFBQVEsS0FBSyxDQUFDO0FBQ3ZFLGdCQUFVLFdBQVcsSUFBSTtBQUFBLElBQzNCO0FBQUE7QUFDRjtBQTFNcUIsZ0JBTUosa0JBQWtCO0FBTm5DLElBQXFCLGlCQUFyQjsiLAogICJuYW1lcyI6IFsiaW1wb3J0X29ic2lkaWFuIiwgIl9hIiwgImltcG9ydF9vYnNpZGlhbiIsICJtYXBwZWQiLCAiY3J5cHRvIl0KfQo=
