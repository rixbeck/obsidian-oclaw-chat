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
  // (removed) internal-link delegation (handled by post-processing linkify)
  constructor(leaf, plugin) {
    super(leaf);
    // State
    this.isConnected = false;
    this.isWorking = false;
    // Connection notices (avoid spam)
    this.lastConnNoticeAtMs = 0;
    this.lastGatewayState = null;
    this.suppressSessionSelectChange = false;
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
      this.plugin.unregisterChatLeaf();
      this.chatManager.onUpdate = null;
      this.chatManager.onMessageAdded = null;
      this.wsClient.onStateChange = null;
      this.wsClient.onWorkingChange = null;
      this.wsClient.disconnect();
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
        void import_obsidian2.MarkdownRenderer.renderMarkdown(pre, body, sourcePath, this.plugin).then(() => {
          this._postprocessAssistantLinks(body, msg.content, mappings, sourcePath);
        });
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
  _preprocessAssistantMarkdown(text, _mappings) {
    return text;
  }
  _appendObsidianLink(container, vaultPath, sourcePath, displayText) {
    const display = displayText != null ? displayText : `[[${vaultPath}]]`;
    const a = container.createEl("a", { text: display, href: "#" });
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
  }
  _postprocessAssistantLinks(body, rawText, mappings, sourcePath) {
    var _a, _b;
    const candidatesByNode = /* @__PURE__ */ new Map();
    const walker = body.ownerDocument.createTreeWalker(body, NodeFilter.SHOW_TEXT);
    const textNodes = [];
    let n;
    while (n = walker.nextNode()) {
      const t = n;
      if (!t.nodeValue)
        continue;
      textNodes.push(t);
    }
    for (const t of textNodes) {
      const text = (_a = t.nodeValue) != null ? _a : "";
      const candidates = extractCandidates(text);
      if (candidates.length === 0)
        continue;
      candidatesByNode.set(t, candidates);
    }
    const tryReverseMapUrlToVaultPath = (url) => this._tryReverseMapUrlToVaultPath(url, mappings);
    for (const [t, candidates] of candidatesByNode.entries()) {
      const text = (_b = t.nodeValue) != null ? _b : "";
      const frag = body.ownerDocument.createDocumentFragment();
      let cursor = 0;
      const appendText = (s) => {
        if (!s)
          return;
        frag.appendChild(body.ownerDocument.createTextNode(s));
      };
      for (const c of candidates) {
        appendText(text.slice(cursor, c.start));
        cursor = c.end;
        if (c.kind === "url") {
          const mapped2 = tryReverseMapUrlToVaultPath(c.raw);
          if (mapped2) {
            this._appendObsidianLink(frag, mapped2, sourcePath, c.raw);
          } else {
            appendText(c.raw);
          }
          continue;
        }
        const direct = this._tryMapVaultRelativeToken(c.raw, mappings);
        if (direct) {
          this._appendObsidianLink(frag, direct, sourcePath, c.raw);
          continue;
        }
        const mapped = tryMapRemotePathToVaultPath(c.raw, mappings);
        if (mapped && this.app.vault.getAbstractFileByPath(mapped)) {
          this._appendObsidianLink(frag, mapped, sourcePath, c.raw);
          continue;
        }
        appendText(c.raw);
      }
      appendText(text.slice(cursor));
      const parent = t.parentNode;
      if (!parent)
        continue;
      parent.replaceChild(frag, t);
    }
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
          this._appendObsidianLink(body, mapped2, sourcePath);
        } else {
          appendExternalUrl(c.raw);
        }
        continue;
      }
      const direct = this._tryMapVaultRelativeToken(c.raw, mappings);
      if (direct) {
        this._appendObsidianLink(body, direct, sourcePath);
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
      this._appendObsidianLink(body, mapped, sourcePath);
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
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsic3JjL21haW4udHMiLCAic3JjL3NldHRpbmdzLnRzIiwgInNyYy93ZWJzb2NrZXQudHMiLCAic3JjL3ZpZXcudHMiLCAic3JjL2NoYXQudHMiLCAic3JjL2xpbmtpZnkudHMiLCAic3JjL2NvbnRleHQudHMiLCAic3JjL3R5cGVzLnRzIiwgInNyYy9zZXNzaW9uLnRzIl0sCiAgInNvdXJjZXNDb250ZW50IjogWyJpbXBvcnQgeyBGaWxlU3lzdGVtQWRhcHRlciwgTm90aWNlLCBQbHVnaW4sIFdvcmtzcGFjZUxlYWYgfSBmcm9tICdvYnNpZGlhbic7XG5pbXBvcnQgeyBPcGVuQ2xhd1NldHRpbmdUYWIgfSBmcm9tICcuL3NldHRpbmdzJztcbmltcG9ydCB7IE9ic2lkaWFuV1NDbGllbnQgfSBmcm9tICcuL3dlYnNvY2tldCc7XG5pbXBvcnQgeyBWSUVXX1RZUEVfT1BFTkNMQVdfQ0hBVCwgT3BlbkNsYXdDaGF0VmlldyB9IGZyb20gJy4vdmlldyc7XG5pbXBvcnQgeyBERUZBVUxUX1NFVFRJTkdTLCB0eXBlIE9wZW5DbGF3U2V0dGluZ3MgfSBmcm9tICcuL3R5cGVzJztcbmltcG9ydCB7IG1pZ3JhdGVTZXR0aW5nc0ZvclZhdWx0IH0gZnJvbSAnLi9zZXNzaW9uJztcblxuZXhwb3J0IGRlZmF1bHQgY2xhc3MgT3BlbkNsYXdQbHVnaW4gZXh0ZW5kcyBQbHVnaW4ge1xuICBzZXR0aW5ncyE6IE9wZW5DbGF3U2V0dGluZ3M7XG5cbiAgLy8gTk9URTogd3NDbGllbnQvY2hhdE1hbmFnZXIgYXJlIHBlci1sZWFmIChwZXIgdmlldykgdG8gYWxsb3cgcGFyYWxsZWwgc2Vzc2lvbnMuXG4gIHByaXZhdGUgb3BlbkNoYXRMZWF2ZXMgPSAwO1xuICBwcml2YXRlIGxhc3RMZWFmV2FybkF0TXMgPSAwO1xuICBwcml2YXRlIHN0YXRpYyBNQVhfQ0hBVF9MRUFWRVMgPSAzO1xuXG4gIHJlZ2lzdGVyQ2hhdExlYWYoKTogdm9pZCB7XG4gICAgdGhpcy5vcGVuQ2hhdExlYXZlcyArPSAxO1xuICAgIGNvbnN0IG5vdyA9IERhdGUubm93KCk7XG4gICAgaWYgKHRoaXMub3BlbkNoYXRMZWF2ZXMgPiBPcGVuQ2xhd1BsdWdpbi5NQVhfQ0hBVF9MRUFWRVMgJiYgbm93IC0gdGhpcy5sYXN0TGVhZldhcm5BdE1zID4gNjBfMDAwKSB7XG4gICAgICB0aGlzLmxhc3RMZWFmV2FybkF0TXMgPSBub3c7XG4gICAgICBuZXcgTm90aWNlKFxuICAgICAgICBgT3BlbkNsYXcgQ2hhdDogJHt0aGlzLm9wZW5DaGF0TGVhdmVzfSBjaGF0IHZpZXdzIGFyZSBvcGVuLiBUaGlzIG1heSBpbmNyZWFzZSBnYXRld2F5IGxvYWQuYFxuICAgICAgKTtcbiAgICB9XG4gIH1cblxuICB1bnJlZ2lzdGVyQ2hhdExlYWYoKTogdm9pZCB7XG4gICAgdGhpcy5vcGVuQ2hhdExlYXZlcyA9IE1hdGgubWF4KDAsIHRoaXMub3BlbkNoYXRMZWF2ZXMgLSAxKTtcbiAgfVxuXG4gIHByaXZhdGUgX3ZhdWx0SGFzaDogc3RyaW5nIHwgbnVsbCA9IG51bGw7XG5cbiAgcHJpdmF0ZSBfY29tcHV0ZVZhdWx0SGFzaCgpOiBzdHJpbmcgfCBudWxsIHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgYWRhcHRlciA9IHRoaXMuYXBwLnZhdWx0LmFkYXB0ZXI7XG4gICAgICAvLyBEZXNrdG9wIG9ubHk6IEZpbGVTeXN0ZW1BZGFwdGVyIHByb3ZpZGVzIGEgc3RhYmxlIGJhc2UgcGF0aC5cbiAgICAgIGlmIChhZGFwdGVyIGluc3RhbmNlb2YgRmlsZVN5c3RlbUFkYXB0ZXIpIHtcbiAgICAgICAgY29uc3QgYmFzZVBhdGggPSBhZGFwdGVyLmdldEJhc2VQYXRoKCk7XG4gICAgICAgIGlmIChiYXNlUGF0aCkge1xuICAgICAgICAgIC8vIFVzZSBOb2RlIGNyeXB0byAoRWxlY3Ryb24gZW52aXJvbm1lbnQpLlxuICAgICAgICAgIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBAdHlwZXNjcmlwdC1lc2xpbnQvbm8tdmFyLXJlcXVpcmVzXG4gICAgICAgICAgY29uc3QgY3J5cHRvID0gcmVxdWlyZSgnY3J5cHRvJykgYXMgdHlwZW9mIGltcG9ydCgnY3J5cHRvJyk7XG4gICAgICAgICAgY29uc3QgaGV4ID0gY3J5cHRvLmNyZWF0ZUhhc2goJ3NoYTI1NicpLnVwZGF0ZShiYXNlUGF0aCwgJ3V0ZjgnKS5kaWdlc3QoJ2hleCcpO1xuICAgICAgICAgIHJldHVybiBoZXguc2xpY2UoMCwgMTYpO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSBjYXRjaCB7XG4gICAgICAvLyBpZ25vcmVcbiAgICB9XG4gICAgcmV0dXJuIG51bGw7XG4gIH1cblxuICAvLyBjYW5vbmljYWwgc2Vzc2lvbiBrZXkgaGVscGVycyBsaXZlIGluIHNyYy9zZXNzaW9uLnRzXG5cbiAgZ2V0VmF1bHRIYXNoKCk6IHN0cmluZyB8IG51bGwge1xuICAgIHJldHVybiB0aGlzLl92YXVsdEhhc2g7XG4gIH1cblxuICBnZXREZWZhdWx0U2Vzc2lvbktleSgpOiBzdHJpbmcge1xuICAgIHJldHVybiAodGhpcy5zZXR0aW5ncy5zZXNzaW9uS2V5ID8/ICdtYWluJykudHJpbSgpLnRvTG93ZXJDYXNlKCk7XG4gIH1cblxuICBnZXRHYXRld2F5Q29uZmlnKCk6IHsgdXJsOiBzdHJpbmc7IHRva2VuOiBzdHJpbmc7IGFsbG93SW5zZWN1cmVXczogYm9vbGVhbiB9IHtcbiAgICByZXR1cm4ge1xuICAgICAgdXJsOiBTdHJpbmcodGhpcy5zZXR0aW5ncy5nYXRld2F5VXJsIHx8ICcnKSxcbiAgICAgIHRva2VuOiBTdHJpbmcodGhpcy5zZXR0aW5ncy5hdXRoVG9rZW4gfHwgJycpLFxuICAgICAgYWxsb3dJbnNlY3VyZVdzOiBCb29sZWFuKHRoaXMuc2V0dGluZ3MuYWxsb3dJbnNlY3VyZVdzKSxcbiAgICB9O1xuICB9XG5cbiAgLyoqIFBlcnNpc3QgKyByZW1lbWJlciBhbiBPYnNpZGlhbiBzZXNzaW9uIGtleSBmb3IgdGhlIGN1cnJlbnQgdmF1bHQuICovXG4gIGFzeW5jIHJlbWVtYmVyU2Vzc2lvbktleShzZXNzaW9uS2V5OiBzdHJpbmcpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBjb25zdCBuZXh0ID0gc2Vzc2lvbktleS50cmltKCkudG9Mb3dlckNhc2UoKTtcbiAgICBpZiAoIW5leHQpIHJldHVybjtcblxuICAgIC8vIFNFQzogYWxsb3cgb25seSB2YXVsdC1zY29wZWQga2V5cyAod2hlbiB2YXVsdEhhc2gga25vd24pIG9yIG1haW4uXG4gICAgY29uc3QgdmF1bHRIYXNoID0gdGhpcy5fdmF1bHRIYXNoO1xuICAgIGlmICh2YXVsdEhhc2gpIHtcbiAgICAgIGNvbnN0IHByZWZpeCA9IGBhZ2VudDptYWluOm9ic2lkaWFuOmRpcmVjdDoke3ZhdWx0SGFzaH1gO1xuICAgICAgaWYgKCEobmV4dCA9PT0gJ21haW4nIHx8IG5leHQgPT09IHByZWZpeCB8fCBuZXh0LnN0YXJ0c1dpdGgocHJlZml4ICsgJy0nKSkpIHtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuICAgIH0gZWxzZSB7XG4gICAgICAvLyBXaXRob3V0IGEgdmF1bHQgaWRlbnRpdHksIG9ubHkgYWxsb3cgbWFpbi5cbiAgICAgIGlmIChuZXh0ICE9PSAnbWFpbicpIHJldHVybjtcbiAgICB9XG5cbiAgICB0aGlzLnNldHRpbmdzLnNlc3Npb25LZXkgPSBuZXh0O1xuXG4gICAgaWYgKHRoaXMuX3ZhdWx0SGFzaCkge1xuICAgICAgY29uc3QgbWFwID0gdGhpcy5zZXR0aW5ncy5rbm93blNlc3Npb25LZXlzQnlWYXVsdCA/PyB7fTtcbiAgICAgIGNvbnN0IGN1ciA9IEFycmF5LmlzQXJyYXkobWFwW3RoaXMuX3ZhdWx0SGFzaF0pID8gbWFwW3RoaXMuX3ZhdWx0SGFzaF0gOiBbXTtcbiAgICAgIGNvbnN0IG5leHRMaXN0ID0gW25leHQsIC4uLmN1ci5maWx0ZXIoKGspID0+IGsgJiYgayAhPT0gbmV4dCldLnNsaWNlKDAsIDIwKTtcbiAgICAgIG1hcFt0aGlzLl92YXVsdEhhc2hdID0gbmV4dExpc3Q7XG4gICAgICB0aGlzLnNldHRpbmdzLmtub3duU2Vzc2lvbktleXNCeVZhdWx0ID0gbWFwO1xuICAgIH1cblxuICAgIGF3YWl0IHRoaXMuc2F2ZVNldHRpbmdzKCk7XG4gIH1cblxuICBjcmVhdGVXc0NsaWVudChzZXNzaW9uS2V5OiBzdHJpbmcpOiBPYnNpZGlhbldTQ2xpZW50IHtcbiAgICByZXR1cm4gbmV3IE9ic2lkaWFuV1NDbGllbnQoc2Vzc2lvbktleS50cmltKCkudG9Mb3dlckNhc2UoKSwge1xuICAgICAgaWRlbnRpdHlTdG9yZToge1xuICAgICAgICBnZXQ6IGFzeW5jICgpID0+IChhd2FpdCB0aGlzLl9sb2FkRGV2aWNlSWRlbnRpdHkoKSksXG4gICAgICAgIHNldDogYXN5bmMgKGlkZW50aXR5KSA9PiBhd2FpdCB0aGlzLl9zYXZlRGV2aWNlSWRlbnRpdHkoaWRlbnRpdHkpLFxuICAgICAgICBjbGVhcjogYXN5bmMgKCkgPT4gYXdhaXQgdGhpcy5fY2xlYXJEZXZpY2VJZGVudGl0eSgpLFxuICAgICAgfSxcbiAgICB9KTtcbiAgfVxuXG4gIGFzeW5jIG9ubG9hZCgpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBhd2FpdCB0aGlzLmxvYWRTZXR0aW5ncygpO1xuXG4gICAgLy8gQ29tcHV0ZSB2YXVsdCBoYXNoIChkZXNrdG9wKSBhbmQgbWlncmF0ZSB0byBjYW5vbmljYWwgb2JzaWRpYW4gZGlyZWN0IHNlc3Npb24ga2V5LlxuICAgIHRoaXMuX3ZhdWx0SGFzaCA9IHRoaXMuX2NvbXB1dGVWYXVsdEhhc2goKTtcbiAgICBpZiAodGhpcy5fdmF1bHRIYXNoKSB7XG4gICAgICB0aGlzLnNldHRpbmdzLnZhdWx0SGFzaCA9IHRoaXMuX3ZhdWx0SGFzaDtcblxuICAgICAgY29uc3QgbWlncmF0ZWQgPSBtaWdyYXRlU2V0dGluZ3NGb3JWYXVsdCh0aGlzLnNldHRpbmdzLCB0aGlzLl92YXVsdEhhc2gpO1xuICAgICAgdGhpcy5zZXR0aW5ncyA9IG1pZ3JhdGVkLm5leHRTZXR0aW5ncztcbiAgICAgIGF3YWl0IHRoaXMuc2F2ZVNldHRpbmdzKCk7XG4gICAgfSBlbHNlIHtcbiAgICAgIC8vIEtlZXAgd29ya2luZywgYnV0IE5ldy1zZXNzaW9uIGNyZWF0aW9uIG1heSBiZSB1bmF2YWlsYWJsZS5cbiAgICAgIG5ldyBOb3RpY2UoJ09wZW5DbGF3IENoYXQ6IGNvdWxkIG5vdCBkZXRlcm1pbmUgdmF1bHQgaWRlbnRpdHkgKHZhdWx0SGFzaCkuJyk7XG4gICAgfVxuXG4gICAgLy8gUmVnaXN0ZXIgdGhlIHNpZGViYXIgdmlld1xuICAgIHRoaXMucmVnaXN0ZXJWaWV3KFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFULCAobGVhZjogV29ya3NwYWNlTGVhZikgPT4gbmV3IE9wZW5DbGF3Q2hhdFZpZXcobGVhZiwgdGhpcykpO1xuXG4gICAgLy8gUmliYm9uIGljb24gXHUyMDE0IG9wZW5zIC8gcmV2ZWFscyB0aGUgY2hhdCBzaWRlYmFyXG4gICAgdGhpcy5hZGRSaWJib25JY29uKCdtZXNzYWdlLXNxdWFyZScsICdPcGVuQ2xhdyBDaGF0JywgKCkgPT4ge1xuICAgICAgdm9pZCB0aGlzLl9hY3RpdmF0ZUNoYXRWaWV3KCk7XG4gICAgfSk7XG5cbiAgICAvLyBTZXR0aW5ncyB0YWJcbiAgICB0aGlzLmFkZFNldHRpbmdUYWIobmV3IE9wZW5DbGF3U2V0dGluZ1RhYih0aGlzLmFwcCwgdGhpcykpO1xuXG4gICAgLy8gQ29tbWFuZCBwYWxldHRlIGVudHJ5XG4gICAgdGhpcy5hZGRDb21tYW5kKHtcbiAgICAgIGlkOiAnb3Blbi1vcGVuY2xhdy1jaGF0JyxcbiAgICAgIG5hbWU6ICdPcGVuIGNoYXQgc2lkZWJhcicsXG4gICAgICBjYWxsYmFjazogKCkgPT4gdm9pZCB0aGlzLl9hY3RpdmF0ZUNoYXRWaWV3KCksXG4gICAgfSk7XG5cbiAgICBjb25zb2xlLmxvZygnW29jbGF3XSBQbHVnaW4gbG9hZGVkJyk7XG4gIH1cblxuICBhc3luYyBvbnVubG9hZCgpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICB0aGlzLmFwcC53b3Jrc3BhY2UuZGV0YWNoTGVhdmVzT2ZUeXBlKFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFUKTtcbiAgICBjb25zb2xlLmxvZygnW29jbGF3XSBQbHVnaW4gdW5sb2FkZWQnKTtcbiAgfVxuXG4gIGFzeW5jIGxvYWRTZXR0aW5ncygpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBjb25zdCBkYXRhID0gKGF3YWl0IHRoaXMubG9hZERhdGEoKSkgPz8ge307XG4gICAgLy8gTk9URTogcGx1Z2luIGRhdGEgbWF5IGNvbnRhaW4gZXh0cmEgcHJpdmF0ZSBmaWVsZHMgKGUuZy4gZGV2aWNlIGlkZW50aXR5KS4gU2V0dGluZ3MgYXJlIHRoZSBwdWJsaWMgc3Vic2V0LlxuICAgIHRoaXMuc2V0dGluZ3MgPSBPYmplY3QuYXNzaWduKHt9LCBERUZBVUxUX1NFVFRJTkdTLCBkYXRhKTtcbiAgfVxuXG4gIGFzeW5jIHNhdmVTZXR0aW5ncygpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICAvLyBQcmVzZXJ2ZSBhbnkgcHJpdmF0ZSBmaWVsZHMgc3RvcmVkIGluIHBsdWdpbiBkYXRhLlxuICAgIGNvbnN0IGRhdGEgPSAoYXdhaXQgdGhpcy5sb2FkRGF0YSgpKSA/PyB7fTtcbiAgICBhd2FpdCB0aGlzLnNhdmVEYXRhKHsgLi4uZGF0YSwgLi4udGhpcy5zZXR0aW5ncyB9KTtcbiAgfVxuXG4gIC8vIFx1MjUwMFx1MjUwMCBEZXZpY2UgaWRlbnRpdHkgcGVyc2lzdGVuY2UgKHBsdWdpbi1zY29wZWQ7IE5PVCBsb2NhbFN0b3JhZ2UpIFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFxuXG4gIGFzeW5jIHJlc2V0RGV2aWNlSWRlbnRpdHkoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgYXdhaXQgdGhpcy5fY2xlYXJEZXZpY2VJZGVudGl0eSgpO1xuICAgIG5ldyBOb3RpY2UoJ09wZW5DbGF3IENoYXQ6IGRldmljZSBpZGVudGl0eSByZXNldC4gUmVjb25uZWN0IHRvIHBhaXIgYWdhaW4uJyk7XG4gIH1cblxuICBwcml2YXRlIF9kZXZpY2VJZGVudGl0eUtleSA9ICdfb3BlbmNsYXdEZXZpY2VJZGVudGl0eVYxJztcblxuICBwcml2YXRlIGFzeW5jIF9sb2FkRGV2aWNlSWRlbnRpdHkoKTogUHJvbWlzZTxhbnkgfCBudWxsPiB7XG4gICAgY29uc3QgZGF0YSA9IChhd2FpdCB0aGlzLmxvYWREYXRhKCkpID8/IHt9O1xuICAgIHJldHVybiAoZGF0YSBhcyBhbnkpPy5bdGhpcy5fZGV2aWNlSWRlbnRpdHlLZXldID8/IG51bGw7XG4gIH1cblxuICBwcml2YXRlIGFzeW5jIF9zYXZlRGV2aWNlSWRlbnRpdHkoaWRlbnRpdHk6IGFueSk6IFByb21pc2U8dm9pZD4ge1xuICAgIGNvbnN0IGRhdGEgPSAoYXdhaXQgdGhpcy5sb2FkRGF0YSgpKSA/PyB7fTtcbiAgICBhd2FpdCB0aGlzLnNhdmVEYXRhKHsgLi4uZGF0YSwgW3RoaXMuX2RldmljZUlkZW50aXR5S2V5XTogaWRlbnRpdHkgfSk7XG4gIH1cblxuICBwcml2YXRlIGFzeW5jIF9jbGVhckRldmljZUlkZW50aXR5KCk6IFByb21pc2U8dm9pZD4ge1xuICAgIGNvbnN0IGRhdGEgPSAoYXdhaXQgdGhpcy5sb2FkRGF0YSgpKSA/PyB7fTtcbiAgICBpZiAoKGRhdGEgYXMgYW55KT8uW3RoaXMuX2RldmljZUlkZW50aXR5S2V5XSA9PT0gdW5kZWZpbmVkKSByZXR1cm47XG4gICAgY29uc3QgbmV4dCA9IHsgLi4uKGRhdGEgYXMgYW55KSB9O1xuICAgIGRlbGV0ZSBuZXh0W3RoaXMuX2RldmljZUlkZW50aXR5S2V5XTtcbiAgICBhd2FpdCB0aGlzLnNhdmVEYXRhKG5leHQpO1xuICB9XG5cbiAgLy8gXHUyNTAwXHUyNTAwIEhlbHBlcnMgXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG5cbiAgcHJpdmF0ZSBhc3luYyBfYWN0aXZhdGVDaGF0VmlldygpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBjb25zdCB7IHdvcmtzcGFjZSB9ID0gdGhpcy5hcHA7XG5cbiAgICAvLyBSZXVzZSBleGlzdGluZyBsZWFmIGlmIGFscmVhZHkgb3BlblxuICAgIGNvbnN0IGV4aXN0aW5nID0gd29ya3NwYWNlLmdldExlYXZlc09mVHlwZShWSUVXX1RZUEVfT1BFTkNMQVdfQ0hBVCk7XG4gICAgaWYgKGV4aXN0aW5nLmxlbmd0aCA+IDApIHtcbiAgICAgIHdvcmtzcGFjZS5yZXZlYWxMZWFmKGV4aXN0aW5nWzBdKTtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICAvLyBPcGVuIGluIHJpZ2h0IHNpZGViYXJcbiAgICBjb25zdCBsZWFmID0gd29ya3NwYWNlLmdldFJpZ2h0TGVhZihmYWxzZSk7XG4gICAgaWYgKCFsZWFmKSByZXR1cm47XG4gICAgYXdhaXQgbGVhZi5zZXRWaWV3U3RhdGUoeyB0eXBlOiBWSUVXX1RZUEVfT1BFTkNMQVdfQ0hBVCwgYWN0aXZlOiB0cnVlIH0pO1xuICAgIHdvcmtzcGFjZS5yZXZlYWxMZWFmKGxlYWYpO1xuICB9XG59XG4iLCAiaW1wb3J0IHsgQXBwLCBQbHVnaW5TZXR0aW5nVGFiLCBTZXR0aW5nIH0gZnJvbSAnb2JzaWRpYW4nO1xuaW1wb3J0IHR5cGUgT3BlbkNsYXdQbHVnaW4gZnJvbSAnLi9tYWluJztcblxuZXhwb3J0IGNsYXNzIE9wZW5DbGF3U2V0dGluZ1RhYiBleHRlbmRzIFBsdWdpblNldHRpbmdUYWIge1xuICBwbHVnaW46IE9wZW5DbGF3UGx1Z2luO1xuXG4gIGNvbnN0cnVjdG9yKGFwcDogQXBwLCBwbHVnaW46IE9wZW5DbGF3UGx1Z2luKSB7XG4gICAgc3VwZXIoYXBwLCBwbHVnaW4pO1xuICAgIHRoaXMucGx1Z2luID0gcGx1Z2luO1xuICB9XG5cbiAgZGlzcGxheSgpOiB2b2lkIHtcbiAgICBjb25zdCB7IGNvbnRhaW5lckVsIH0gPSB0aGlzO1xuICAgIGNvbnRhaW5lckVsLmVtcHR5KCk7XG5cbiAgICBjb250YWluZXJFbC5jcmVhdGVFbCgnaDInLCB7IHRleHQ6ICdPcGVuQ2xhdyBDaGF0IFx1MjAxMyBTZXR0aW5ncycgfSk7XG5cbiAgICBuZXcgU2V0dGluZyhjb250YWluZXJFbClcbiAgICAgIC5zZXROYW1lKCdHYXRld2F5IFVSTCcpXG4gICAgICAuc2V0RGVzYygnV2ViU29ja2V0IFVSTCBvZiB0aGUgT3BlbkNsYXcgR2F0ZXdheSAoZS5nLiB3czovL2hvc3RuYW1lOjE4Nzg5KS4nKVxuICAgICAgLmFkZFRleHQoKHRleHQpID0+XG4gICAgICAgIHRleHRcbiAgICAgICAgICAuc2V0UGxhY2Vob2xkZXIoJ3dzOi8vbG9jYWxob3N0OjE4Nzg5JylcbiAgICAgICAgICAuc2V0VmFsdWUodGhpcy5wbHVnaW4uc2V0dGluZ3MuZ2F0ZXdheVVybClcbiAgICAgICAgICAub25DaGFuZ2UoYXN5bmMgKHZhbHVlKSA9PiB7XG4gICAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5nYXRld2F5VXJsID0gdmFsdWUudHJpbSgpO1xuICAgICAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uc2F2ZVNldHRpbmdzKCk7XG4gICAgICAgICAgfSlcbiAgICAgICk7XG5cbiAgICBuZXcgU2V0dGluZyhjb250YWluZXJFbClcbiAgICAgIC5zZXROYW1lKCdBdXRoIHRva2VuJylcbiAgICAgIC5zZXREZXNjKCdNdXN0IG1hdGNoIHRoZSBhdXRoVG9rZW4gaW4geW91ciBvcGVuY2xhdy5qc29uIGNoYW5uZWwgY29uZmlnLiBOZXZlciBzaGFyZWQuJylcbiAgICAgIC5hZGRUZXh0KCh0ZXh0KSA9PiB7XG4gICAgICAgIHRleHRcbiAgICAgICAgICAuc2V0UGxhY2Vob2xkZXIoJ0VudGVyIHRva2VuXHUyMDI2JylcbiAgICAgICAgICAuc2V0VmFsdWUodGhpcy5wbHVnaW4uc2V0dGluZ3MuYXV0aFRva2VuKVxuICAgICAgICAgIC5vbkNoYW5nZShhc3luYyAodmFsdWUpID0+IHtcbiAgICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLmF1dGhUb2tlbiA9IHZhbHVlO1xuICAgICAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uc2F2ZVNldHRpbmdzKCk7XG4gICAgICAgICAgfSk7XG4gICAgICAgIC8vIFRyZWF0IGFzIHBhc3N3b3JkIGZpZWxkIFx1MjAxMyBkbyBub3QgcmV2ZWFsIHRva2VuIGluIFVJXG4gICAgICAgIHRleHQuaW5wdXRFbC50eXBlID0gJ3Bhc3N3b3JkJztcbiAgICAgICAgdGV4dC5pbnB1dEVsLmF1dG9jb21wbGV0ZSA9ICdvZmYnO1xuICAgICAgfSk7XG5cbiAgICBuZXcgU2V0dGluZyhjb250YWluZXJFbClcbiAgICAgIC5zZXROYW1lKCdTZXNzaW9uIEtleScpXG4gICAgICAuc2V0RGVzYygnT3BlbkNsYXcgc2Vzc2lvbiB0byBzdWJzY3JpYmUgdG8gKHVzdWFsbHkgXCJtYWluXCIpLicpXG4gICAgICAuYWRkVGV4dCgodGV4dCkgPT5cbiAgICAgICAgdGV4dFxuICAgICAgICAgIC5zZXRQbGFjZWhvbGRlcignbWFpbicpXG4gICAgICAgICAgLnNldFZhbHVlKHRoaXMucGx1Z2luLnNldHRpbmdzLnNlc3Npb25LZXkpXG4gICAgICAgICAgLm9uQ2hhbmdlKGFzeW5jICh2YWx1ZSkgPT4ge1xuICAgICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3Muc2Vzc2lvbktleSA9IHZhbHVlLnRyaW0oKSB8fCAnbWFpbic7XG4gICAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgICB9KVxuICAgICAgKTtcblxuICAgIG5ldyBTZXR0aW5nKGNvbnRhaW5lckVsKVxuICAgICAgLnNldE5hbWUoJ0FjY291bnQgSUQnKVxuICAgICAgLnNldERlc2MoJ09wZW5DbGF3IGFjY291bnQgSUQgKHVzdWFsbHkgXCJtYWluXCIpLicpXG4gICAgICAuYWRkVGV4dCgodGV4dCkgPT5cbiAgICAgICAgdGV4dFxuICAgICAgICAgIC5zZXRQbGFjZWhvbGRlcignbWFpbicpXG4gICAgICAgICAgLnNldFZhbHVlKHRoaXMucGx1Z2luLnNldHRpbmdzLmFjY291bnRJZClcbiAgICAgICAgICAub25DaGFuZ2UoYXN5bmMgKHZhbHVlKSA9PiB7XG4gICAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5hY2NvdW50SWQgPSB2YWx1ZS50cmltKCkgfHwgJ21haW4nO1xuICAgICAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uc2F2ZVNldHRpbmdzKCk7XG4gICAgICAgICAgfSlcbiAgICAgICk7XG5cbiAgICBuZXcgU2V0dGluZyhjb250YWluZXJFbClcbiAgICAgIC5zZXROYW1lKCdJbmNsdWRlIGFjdGl2ZSBub3RlIGJ5IGRlZmF1bHQnKVxuICAgICAgLnNldERlc2MoJ1ByZS1jaGVjayBcIkluY2x1ZGUgYWN0aXZlIG5vdGVcIiBpbiB0aGUgY2hhdCBwYW5lbCB3aGVuIGl0IG9wZW5zLicpXG4gICAgICAuYWRkVG9nZ2xlKCh0b2dnbGUpID0+XG4gICAgICAgIHRvZ2dsZS5zZXRWYWx1ZSh0aGlzLnBsdWdpbi5zZXR0aW5ncy5pbmNsdWRlQWN0aXZlTm90ZSkub25DaGFuZ2UoYXN5bmMgKHZhbHVlKSA9PiB7XG4gICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3MuaW5jbHVkZUFjdGl2ZU5vdGUgPSB2YWx1ZTtcbiAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgfSlcbiAgICAgICk7XG5cbiAgICBuZXcgU2V0dGluZyhjb250YWluZXJFbClcbiAgICAgIC5zZXROYW1lKCdSZW5kZXIgYXNzaXN0YW50IGFzIE1hcmtkb3duICh1bnNhZmUpJylcbiAgICAgIC5zZXREZXNjKFxuICAgICAgICAnT0ZGIHJlY29tbWVuZGVkLiBJZiBlbmFibGVkLCBhc3Npc3RhbnQgb3V0cHV0IGlzIHJlbmRlcmVkIGFzIE9ic2lkaWFuIE1hcmtkb3duIHdoaWNoIG1heSB0cmlnZ2VyIGVtYmVkcyBhbmQgb3RoZXIgcGx1Z2luc1xcJyBwb3N0LXByb2Nlc3NvcnMuJ1xuICAgICAgKVxuICAgICAgLmFkZFRvZ2dsZSgodG9nZ2xlKSA9PlxuICAgICAgICB0b2dnbGUuc2V0VmFsdWUodGhpcy5wbHVnaW4uc2V0dGluZ3MucmVuZGVyQXNzaXN0YW50TWFya2Rvd24pLm9uQ2hhbmdlKGFzeW5jICh2YWx1ZSkgPT4ge1xuICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLnJlbmRlckFzc2lzdGFudE1hcmtkb3duID0gdmFsdWU7XG4gICAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uc2F2ZVNldHRpbmdzKCk7XG4gICAgICAgIH0pXG4gICAgICApO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZSgnQWxsb3cgaW5zZWN1cmUgd3M6Ly8gZm9yIG5vbi1sb2NhbCBnYXRld2F5cyAodW5zYWZlKScpXG4gICAgICAuc2V0RGVzYyhcbiAgICAgICAgJ09GRiByZWNvbW1lbmRlZC4gSWYgZW5hYmxlZCwgeW91IGNhbiBjb25uZWN0IHRvIG5vbi1sb2NhbCBnYXRld2F5cyBvdmVyIHdzOi8vLiBUaGlzIGV4cG9zZXMgeW91ciB0b2tlbiBhbmQgbWVzc2FnZSBjb250ZW50IHRvIG5ldHdvcmsgYXR0YWNrZXJzOyBwcmVmZXIgd3NzOi8vLidcbiAgICAgIClcbiAgICAgIC5hZGRUb2dnbGUoKHRvZ2dsZSkgPT5cbiAgICAgICAgdG9nZ2xlLnNldFZhbHVlKHRoaXMucGx1Z2luLnNldHRpbmdzLmFsbG93SW5zZWN1cmVXcykub25DaGFuZ2UoYXN5bmMgKHZhbHVlKSA9PiB7XG4gICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3MuYWxsb3dJbnNlY3VyZVdzID0gdmFsdWU7XG4gICAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uc2F2ZVNldHRpbmdzKCk7XG4gICAgICAgIH0pXG4gICAgICApO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZSgnUmVzZXQgZGV2aWNlIGlkZW50aXR5IChyZS1wYWlyKScpXG4gICAgICAuc2V0RGVzYygnQ2xlYXJzIHRoZSBzdG9yZWQgZGV2aWNlIGlkZW50aXR5IHVzZWQgZm9yIG9wZXJhdG9yLndyaXRlIHBhaXJpbmcuIFVzZSB0aGlzIGlmIHlvdSBzdXNwZWN0IGNvbXByb21pc2Ugb3Igc2VlIFwiZGV2aWNlIGlkZW50aXR5IG1pc21hdGNoXCIuJylcbiAgICAgIC5hZGRCdXR0b24oKGJ0bikgPT5cbiAgICAgICAgYnRuLnNldEJ1dHRvblRleHQoJ1Jlc2V0Jykuc2V0V2FybmluZygpLm9uQ2xpY2soYXN5bmMgKCkgPT4ge1xuICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnJlc2V0RGV2aWNlSWRlbnRpdHkoKTtcbiAgICAgICAgfSlcbiAgICAgICk7XG5cbiAgICAvLyBcdTI1MDBcdTI1MDAgUGF0aCBtYXBwaW5ncyBcdTI1MDBcdTI1MDBcbiAgICBjb250YWluZXJFbC5jcmVhdGVFbCgnaDMnLCB7IHRleHQ6ICdQYXRoIG1hcHBpbmdzICh2YXVsdCBiYXNlIFx1MjE5MiByZW1vdGUgYmFzZSknIH0pO1xuICAgIGNvbnRhaW5lckVsLmNyZWF0ZUVsKCdwJywge1xuICAgICAgdGV4dDogJ1VzZWQgdG8gY29udmVydCBhc3Npc3RhbnQgZmlsZSByZWZlcmVuY2VzIChyZW1vdGUgRlMgcGF0aHMgb3IgZXhwb3J0ZWQgVVJMcykgaW50byBjbGlja2FibGUgT2JzaWRpYW4gbGlua3MuIEZpcnN0IG1hdGNoIHdpbnMuIE9ubHkgY3JlYXRlcyBhIGxpbmsgaWYgdGhlIG1hcHBlZCB2YXVsdCBmaWxlIGV4aXN0cy4nLFxuICAgICAgY2xzOiAnc2V0dGluZy1pdGVtLWRlc2NyaXB0aW9uJyxcbiAgICB9KTtcblxuICAgIGNvbnN0IG1hcHBpbmdzID0gdGhpcy5wbHVnaW4uc2V0dGluZ3MucGF0aE1hcHBpbmdzID8/IFtdO1xuXG4gICAgY29uc3QgcmVyZW5kZXIgPSBhc3luYyAoKSA9PiB7XG4gICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgIHRoaXMuZGlzcGxheSgpO1xuICAgIH07XG5cbiAgICBtYXBwaW5ncy5mb3JFYWNoKChyb3csIGlkeCkgPT4ge1xuICAgICAgY29uc3QgcyA9IG5ldyBTZXR0aW5nKGNvbnRhaW5lckVsKVxuICAgICAgICAuc2V0TmFtZShgTWFwcGluZyAjJHtpZHggKyAxfWApXG4gICAgICAgIC5zZXREZXNjKCd2YXVsdEJhc2UgXHUyMTkyIHJlbW90ZUJhc2UnKTtcblxuICAgICAgcy5hZGRUZXh0KCh0KSA9PlxuICAgICAgICB0XG4gICAgICAgICAgLnNldFBsYWNlaG9sZGVyKCd2YXVsdCBiYXNlIChlLmcuIGRvY3MvKScpXG4gICAgICAgICAgLnNldFZhbHVlKHJvdy52YXVsdEJhc2UgPz8gJycpXG4gICAgICAgICAgLm9uQ2hhbmdlKGFzeW5jICh2KSA9PiB7XG4gICAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5wYXRoTWFwcGluZ3NbaWR4XS52YXVsdEJhc2UgPSB2O1xuICAgICAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uc2F2ZVNldHRpbmdzKCk7XG4gICAgICAgICAgfSlcbiAgICAgICk7XG5cbiAgICAgIHMuYWRkVGV4dCgodCkgPT5cbiAgICAgICAgdFxuICAgICAgICAgIC5zZXRQbGFjZWhvbGRlcigncmVtb3RlIGJhc2UgKGUuZy4gL2hvbWUvLi4uL2RvY3MvKScpXG4gICAgICAgICAgLnNldFZhbHVlKHJvdy5yZW1vdGVCYXNlID8/ICcnKVxuICAgICAgICAgIC5vbkNoYW5nZShhc3luYyAodikgPT4ge1xuICAgICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3MucGF0aE1hcHBpbmdzW2lkeF0ucmVtb3RlQmFzZSA9IHY7XG4gICAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgICB9KVxuICAgICAgKTtcblxuICAgICAgcy5hZGRFeHRyYUJ1dHRvbigoYikgPT5cbiAgICAgICAgYlxuICAgICAgICAgIC5zZXRJY29uKCd0cmFzaCcpXG4gICAgICAgICAgLnNldFRvb2x0aXAoJ1JlbW92ZSBtYXBwaW5nJylcbiAgICAgICAgICAub25DbGljayhhc3luYyAoKSA9PiB7XG4gICAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5wYXRoTWFwcGluZ3Muc3BsaWNlKGlkeCwgMSk7XG4gICAgICAgICAgICBhd2FpdCByZXJlbmRlcigpO1xuICAgICAgICAgIH0pXG4gICAgICApO1xuICAgIH0pO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZSgnQWRkIG1hcHBpbmcnKVxuICAgICAgLnNldERlc2MoJ0FkZCBhIG5ldyB2YXVsdEJhc2UgXHUyMTkyIHJlbW90ZUJhc2UgbWFwcGluZyByb3cuJylcbiAgICAgIC5hZGRCdXR0b24oKGJ0bikgPT5cbiAgICAgICAgYnRuLnNldEJ1dHRvblRleHQoJ0FkZCcpLm9uQ2xpY2soYXN5bmMgKCkgPT4ge1xuICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLnBhdGhNYXBwaW5ncy5wdXNoKHsgdmF1bHRCYXNlOiAnJywgcmVtb3RlQmFzZTogJycgfSk7XG4gICAgICAgICAgYXdhaXQgcmVyZW5kZXIoKTtcbiAgICAgICAgfSlcbiAgICAgICk7XG5cbiAgICBjb250YWluZXJFbC5jcmVhdGVFbCgncCcsIHtcbiAgICAgIHRleHQ6ICdSZWNvbm5lY3Q6IGNsb3NlIGFuZCByZW9wZW4gdGhlIHNpZGViYXIgYWZ0ZXIgY2hhbmdpbmcgdGhlIGdhdGV3YXkgVVJMIG9yIHRva2VuLicsXG4gICAgICBjbHM6ICdzZXR0aW5nLWl0ZW0tZGVzY3JpcHRpb24nLFxuICAgIH0pO1xuICB9XG59XG4iLCAiLyoqXG4gKiBXZWJTb2NrZXQgY2xpZW50IGZvciBPcGVuQ2xhdyBHYXRld2F5XG4gKlxuICogUGl2b3QgKDIwMjYtMDItMjUpOiBEbyBOT1QgdXNlIGN1c3RvbSBvYnNpZGlhbi4qIGdhdGV3YXkgbWV0aG9kcy5cbiAqIFRob3NlIHJlcXVpcmUgb3BlcmF0b3IuYWRtaW4gc2NvcGUgd2hpY2ggaXMgbm90IGdyYW50ZWQgdG8gZXh0ZXJuYWwgY2xpZW50cy5cbiAqXG4gKiBBdXRoIG5vdGU6XG4gKiAtIGNoYXQuc2VuZCByZXF1aXJlcyBvcGVyYXRvci53cml0ZVxuICogLSBleHRlcm5hbCBjbGllbnRzIG11c3QgcHJlc2VudCBhIHBhaXJlZCBkZXZpY2UgaWRlbnRpdHkgdG8gcmVjZWl2ZSB3cml0ZSBzY29wZXNcbiAqXG4gKiBXZSB1c2UgYnVpbHQtaW4gZ2F0ZXdheSBtZXRob2RzL2V2ZW50czpcbiAqIC0gU2VuZDogY2hhdC5zZW5kKHsgc2Vzc2lvbktleSwgbWVzc2FnZSwgaWRlbXBvdGVuY3lLZXksIC4uLiB9KVxuICogLSBSZWNlaXZlOiBldmVudCBcImNoYXRcIiAoZmlsdGVyIGJ5IHNlc3Npb25LZXkpXG4gKi9cblxuaW1wb3J0IHR5cGUgeyBJbmJvdW5kV1NQYXlsb2FkIH0gZnJvbSAnLi90eXBlcyc7XG5cbmZ1bmN0aW9uIGlzTG9jYWxIb3N0KGhvc3Q6IHN0cmluZyk6IGJvb2xlYW4ge1xuICBjb25zdCBoID0gaG9zdC50b0xvd2VyQ2FzZSgpO1xuICByZXR1cm4gaCA9PT0gJ2xvY2FsaG9zdCcgfHwgaCA9PT0gJzEyNy4wLjAuMScgfHwgaCA9PT0gJzo6MSc7XG59XG5cbmZ1bmN0aW9uIHNhZmVQYXJzZVdzVXJsKHVybDogc3RyaW5nKTpcbiAgfCB7IG9rOiB0cnVlOyBzY2hlbWU6ICd3cycgfCAnd3NzJzsgaG9zdDogc3RyaW5nIH1cbiAgfCB7IG9rOiBmYWxzZTsgZXJyb3I6IHN0cmluZyB9IHtcbiAgdHJ5IHtcbiAgICBjb25zdCB1ID0gbmV3IFVSTCh1cmwpO1xuICAgIGlmICh1LnByb3RvY29sICE9PSAnd3M6JyAmJiB1LnByb3RvY29sICE9PSAnd3NzOicpIHtcbiAgICAgIHJldHVybiB7IG9rOiBmYWxzZSwgZXJyb3I6IGBHYXRld2F5IFVSTCBtdXN0IGJlIHdzOi8vIG9yIHdzczovLyAoZ290ICR7dS5wcm90b2NvbH0pYCB9O1xuICAgIH1cbiAgICBjb25zdCBzY2hlbWUgPSB1LnByb3RvY29sID09PSAnd3M6JyA/ICd3cycgOiAnd3NzJztcbiAgICByZXR1cm4geyBvazogdHJ1ZSwgc2NoZW1lLCBob3N0OiB1Lmhvc3RuYW1lIH07XG4gIH0gY2F0Y2gge1xuICAgIHJldHVybiB7IG9rOiBmYWxzZSwgZXJyb3I6ICdJbnZhbGlkIGdhdGV3YXkgVVJMJyB9O1xuICB9XG59XG5cbi8qKiBJbnRlcnZhbCBmb3Igc2VuZGluZyBoZWFydGJlYXQgcGluZ3MgKGNoZWNrIGNvbm5lY3Rpb24gbGl2ZW5lc3MpICovXG5jb25zdCBIRUFSVEJFQVRfSU5URVJWQUxfTVMgPSAzMF8wMDA7XG5cbi8qKiBTYWZldHkgdmFsdmU6IGhpZGUgd29ya2luZyBzcGlubmVyIGlmIG5vIGFzc2lzdGFudCByZXBseSBhcnJpdmVzIGluIHRpbWUgKi9cbmNvbnN0IFdPUktJTkdfTUFYX01TID0gMTIwXzAwMDtcblxuLyoqIE1heCBpbmJvdW5kIGZyYW1lIHNpemUgdG8gcGFyc2UgKERvUyBndWFyZCkgKi9cbmNvbnN0IE1BWF9JTkJPVU5EX0ZSQU1FX0JZVEVTID0gNTEyICogMTAyNDtcblxuZnVuY3Rpb24gYnl0ZUxlbmd0aFV0ZjgodGV4dDogc3RyaW5nKTogbnVtYmVyIHtcbiAgcmV0dXJuIHV0ZjhCeXRlcyh0ZXh0KS5ieXRlTGVuZ3RoO1xufVxuXG5hc3luYyBmdW5jdGlvbiBub3JtYWxpemVXc0RhdGFUb1RleHQoZGF0YTogYW55KTogUHJvbWlzZTx7IG9rOiB0cnVlOyB0ZXh0OiBzdHJpbmc7IGJ5dGVzOiBudW1iZXIgfSB8IHsgb2s6IGZhbHNlOyByZWFzb246IHN0cmluZzsgYnl0ZXM/OiBudW1iZXIgfT4ge1xuICBpZiAodHlwZW9mIGRhdGEgPT09ICdzdHJpbmcnKSB7XG4gICAgY29uc3QgYnl0ZXMgPSBieXRlTGVuZ3RoVXRmOChkYXRhKTtcbiAgICByZXR1cm4geyBvazogdHJ1ZSwgdGV4dDogZGF0YSwgYnl0ZXMgfTtcbiAgfVxuXG4gIC8vIEJyb3dzZXIgV2ViU29ja2V0IGNhbiBkZWxpdmVyIEJsb2JcbiAgaWYgKHR5cGVvZiBCbG9iICE9PSAndW5kZWZpbmVkJyAmJiBkYXRhIGluc3RhbmNlb2YgQmxvYikge1xuICAgIGNvbnN0IGJ5dGVzID0gZGF0YS5zaXplO1xuICAgIGlmIChieXRlcyA+IE1BWF9JTkJPVU5EX0ZSQU1FX0JZVEVTKSByZXR1cm4geyBvazogZmFsc2UsIHJlYXNvbjogJ3Rvby1sYXJnZScsIGJ5dGVzIH07XG4gICAgY29uc3QgdGV4dCA9IGF3YWl0IGRhdGEudGV4dCgpO1xuICAgIC8vIEJsb2Iuc2l6ZSBpcyBieXRlcyBhbHJlYWR5OyBubyBuZWVkIHRvIHJlLW1lYXN1cmUuXG4gICAgcmV0dXJuIHsgb2s6IHRydWUsIHRleHQsIGJ5dGVzIH07XG4gIH1cblxuICBpZiAoZGF0YSBpbnN0YW5jZW9mIEFycmF5QnVmZmVyKSB7XG4gICAgY29uc3QgYnl0ZXMgPSBkYXRhLmJ5dGVMZW5ndGg7XG4gICAgaWYgKGJ5dGVzID4gTUFYX0lOQk9VTkRfRlJBTUVfQllURVMpIHJldHVybiB7IG9rOiBmYWxzZSwgcmVhc29uOiAndG9vLWxhcmdlJywgYnl0ZXMgfTtcbiAgICBjb25zdCB0ZXh0ID0gbmV3IFRleHREZWNvZGVyKCd1dGYtOCcsIHsgZmF0YWw6IGZhbHNlIH0pLmRlY29kZShuZXcgVWludDhBcnJheShkYXRhKSk7XG4gICAgcmV0dXJuIHsgb2s6IHRydWUsIHRleHQsIGJ5dGVzIH07XG4gIH1cblxuICAvLyBTb21lIHJ1bnRpbWVzIGNvdWxkIHBhc3MgVWludDhBcnJheSBkaXJlY3RseVxuICBpZiAoZGF0YSBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpIHtcbiAgICBjb25zdCBieXRlcyA9IGRhdGEuYnl0ZUxlbmd0aDtcbiAgICBpZiAoYnl0ZXMgPiBNQVhfSU5CT1VORF9GUkFNRV9CWVRFUykgcmV0dXJuIHsgb2s6IGZhbHNlLCByZWFzb246ICd0b28tbGFyZ2UnLCBieXRlcyB9O1xuICAgIGNvbnN0IHRleHQgPSBuZXcgVGV4dERlY29kZXIoJ3V0Zi04JywgeyBmYXRhbDogZmFsc2UgfSkuZGVjb2RlKGRhdGEpO1xuICAgIHJldHVybiB7IG9rOiB0cnVlLCB0ZXh0LCBieXRlcyB9O1xuICB9XG5cbiAgcmV0dXJuIHsgb2s6IGZhbHNlLCByZWFzb246ICd1bnN1cHBvcnRlZC10eXBlJyB9O1xufVxuXG4vKiogTWF4IGluLWZsaWdodCByZXF1ZXN0cyBiZWZvcmUgZmFzdC1mYWlsaW5nIChEb1Mvcm9idXN0bmVzcyBndWFyZCkgKi9cbmNvbnN0IE1BWF9QRU5ESU5HX1JFUVVFU1RTID0gMjAwO1xuXG4vKiogUmVjb25uZWN0IGJhY2tvZmYgKi9cbmNvbnN0IFJFQ09OTkVDVF9CQVNFX01TID0gM18wMDA7XG5jb25zdCBSRUNPTk5FQ1RfTUFYX01TID0gNjBfMDAwO1xuXG4vKiogSGFuZHNoYWtlIGRlYWRsaW5lIHdhaXRpbmcgZm9yIGNvbm5lY3QuY2hhbGxlbmdlICovXG5jb25zdCBIQU5EU0hBS0VfVElNRU9VVF9NUyA9IDE1XzAwMDtcblxuZXhwb3J0IHR5cGUgV1NDbGllbnRTdGF0ZSA9ICdkaXNjb25uZWN0ZWQnIHwgJ2Nvbm5lY3RpbmcnIHwgJ2hhbmRzaGFraW5nJyB8ICdjb25uZWN0ZWQnO1xuXG5leHBvcnQgdHlwZSBXb3JraW5nU3RhdGVMaXN0ZW5lciA9ICh3b3JraW5nOiBib29sZWFuKSA9PiB2b2lkO1xuXG5pbnRlcmZhY2UgUGVuZGluZ1JlcXVlc3Qge1xuICByZXNvbHZlOiAocGF5bG9hZDogYW55KSA9PiB2b2lkO1xuICByZWplY3Q6IChlcnJvcjogYW55KSA9PiB2b2lkO1xuICB0aW1lb3V0OiBSZXR1cm5UeXBlPHR5cGVvZiBzZXRUaW1lb3V0PiB8IG51bGw7XG59XG5cbmV4cG9ydCB0eXBlIERldmljZUlkZW50aXR5ID0ge1xuICBpZDogc3RyaW5nO1xuICBwdWJsaWNLZXk6IHN0cmluZzsgLy8gYmFzZTY0XG4gIHByaXZhdGVLZXlKd2s6IEpzb25XZWJLZXk7XG59O1xuXG5leHBvcnQgaW50ZXJmYWNlIERldmljZUlkZW50aXR5U3RvcmUge1xuICBnZXQoKTogUHJvbWlzZTxEZXZpY2VJZGVudGl0eSB8IG51bGw+O1xuICBzZXQoaWRlbnRpdHk6IERldmljZUlkZW50aXR5KTogUHJvbWlzZTx2b2lkPjtcbiAgY2xlYXIoKTogUHJvbWlzZTx2b2lkPjtcbn1cblxuY29uc3QgREVWSUNFX1NUT1JBR0VfS0VZID0gJ29wZW5jbGF3Q2hhdC5kZXZpY2VJZGVudGl0eS52MSc7IC8vIGxlZ2FjeSBsb2NhbFN0b3JhZ2Uga2V5IChtaWdyYXRpb24gb25seSlcblxuZnVuY3Rpb24gYmFzZTY0VXJsRW5jb2RlKGJ5dGVzOiBBcnJheUJ1ZmZlcik6IHN0cmluZyB7XG4gIGNvbnN0IHU4ID0gbmV3IFVpbnQ4QXJyYXkoYnl0ZXMpO1xuICBsZXQgcyA9ICcnO1xuICBmb3IgKGxldCBpID0gMDsgaSA8IHU4Lmxlbmd0aDsgaSsrKSBzICs9IFN0cmluZy5mcm9tQ2hhckNvZGUodThbaV0pO1xuICBjb25zdCBiNjQgPSBidG9hKHMpO1xuICByZXR1cm4gYjY0LnJlcGxhY2UoL1xcKy9nLCAnLScpLnJlcGxhY2UoL1xcLy9nLCAnXycpLnJlcGxhY2UoLz0rJC9nLCAnJyk7XG59XG5cbmZ1bmN0aW9uIGhleEVuY29kZShieXRlczogQXJyYXlCdWZmZXIpOiBzdHJpbmcge1xuICBjb25zdCB1OCA9IG5ldyBVaW50OEFycmF5KGJ5dGVzKTtcbiAgcmV0dXJuIEFycmF5LmZyb20odTgpXG4gICAgLm1hcCgoYikgPT4gYi50b1N0cmluZygxNikucGFkU3RhcnQoMiwgJzAnKSlcbiAgICAuam9pbignJyk7XG59XG5cbmZ1bmN0aW9uIHV0ZjhCeXRlcyh0ZXh0OiBzdHJpbmcpOiBVaW50OEFycmF5IHtcbiAgcmV0dXJuIG5ldyBUZXh0RW5jb2RlcigpLmVuY29kZSh0ZXh0KTtcbn1cblxuYXN5bmMgZnVuY3Rpb24gc2hhMjU2SGV4KGJ5dGVzOiBBcnJheUJ1ZmZlcik6IFByb21pc2U8c3RyaW5nPiB7XG4gIGNvbnN0IGRpZ2VzdCA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuZGlnZXN0KCdTSEEtMjU2JywgYnl0ZXMpO1xuICByZXR1cm4gaGV4RW5jb2RlKGRpZ2VzdCk7XG59XG5cbmFzeW5jIGZ1bmN0aW9uIGxvYWRPckNyZWF0ZURldmljZUlkZW50aXR5KHN0b3JlPzogRGV2aWNlSWRlbnRpdHlTdG9yZSk6IFByb21pc2U8RGV2aWNlSWRlbnRpdHk+IHtcbiAgLy8gMSkgUHJlZmVyIHBsdWdpbi1zY29wZWQgc3RvcmFnZSAoaW5qZWN0ZWQgYnkgbWFpbiBwbHVnaW4pLlxuICBpZiAoc3RvcmUpIHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgZXhpc3RpbmcgPSBhd2FpdCBzdG9yZS5nZXQoKTtcbiAgICAgIGlmIChleGlzdGluZz8uaWQgJiYgZXhpc3Rpbmc/LnB1YmxpY0tleSAmJiBleGlzdGluZz8ucHJpdmF0ZUtleUp3aykgcmV0dXJuIGV4aXN0aW5nO1xuICAgIH0gY2F0Y2gge1xuICAgICAgLy8gaWdub3JlIGFuZCBjb250aW51ZSAod2UgY2FuIGFsd2F5cyByZS1nZW5lcmF0ZSlcbiAgICB9XG4gIH1cblxuICAvLyAyKSBPbmUtdGltZSBtaWdyYXRpb246IGxlZ2FjeSBsb2NhbFN0b3JhZ2UgaWRlbnRpdHkuXG4gIC8vIE5PVEU6IHRoaXMgcmVtYWlucyBhIHJpc2sgYm91bmRhcnk7IHdlIG9ubHkgcmVhZCtkZWxldGUgZm9yIG1pZ3JhdGlvbi5cbiAgY29uc3QgbGVnYWN5ID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oREVWSUNFX1NUT1JBR0VfS0VZKTtcbiAgaWYgKGxlZ2FjeSkge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCBwYXJzZWQgPSBKU09OLnBhcnNlKGxlZ2FjeSkgYXMgRGV2aWNlSWRlbnRpdHk7XG4gICAgICBpZiAocGFyc2VkPy5pZCAmJiBwYXJzZWQ/LnB1YmxpY0tleSAmJiBwYXJzZWQ/LnByaXZhdGVLZXlKd2spIHtcbiAgICAgICAgaWYgKHN0b3JlKSB7XG4gICAgICAgICAgYXdhaXQgc3RvcmUuc2V0KHBhcnNlZCk7XG4gICAgICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oREVWSUNFX1NUT1JBR0VfS0VZKTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gcGFyc2VkO1xuICAgICAgfVxuICAgIH0gY2F0Y2gge1xuICAgICAgLy8gQ29ycnVwdC9wYXJ0aWFsIGRhdGEgXHUyMTkyIGRlbGV0ZSBhbmQgcmUtY3JlYXRlLlxuICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oREVWSUNFX1NUT1JBR0VfS0VZKTtcbiAgICB9XG4gIH1cblxuICAvLyAzKSBDcmVhdGUgYSBuZXcgaWRlbnRpdHkuXG4gIGNvbnN0IGtleVBhaXIgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmdlbmVyYXRlS2V5KHsgbmFtZTogJ0VkMjU1MTknIH0sIHRydWUsIFsnc2lnbicsICd2ZXJpZnknXSk7XG4gIGNvbnN0IHB1YlJhdyA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuZXhwb3J0S2V5KCdyYXcnLCBrZXlQYWlyLnB1YmxpY0tleSk7XG4gIGNvbnN0IHByaXZKd2sgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmV4cG9ydEtleSgnandrJywga2V5UGFpci5wcml2YXRlS2V5KTtcblxuICAvLyBJTVBPUlRBTlQ6IGRldmljZS5pZCBtdXN0IGJlIGEgc3RhYmxlIGZpbmdlcnByaW50IGZvciB0aGUgcHVibGljIGtleS5cbiAgLy8gVGhlIGdhdGV3YXkgZW5mb3JjZXMgZGV2aWNlSWQgXHUyMTk0IHB1YmxpY0tleSBiaW5kaW5nOyByYW5kb20gaWRzIGNhbiBjYXVzZSBcImRldmljZSBpZGVudGl0eSBtaXNtYXRjaFwiLlxuICBjb25zdCBkZXZpY2VJZCA9IGF3YWl0IHNoYTI1NkhleChwdWJSYXcpO1xuXG4gIGNvbnN0IGlkZW50aXR5OiBEZXZpY2VJZGVudGl0eSA9IHtcbiAgICBpZDogZGV2aWNlSWQsXG4gICAgcHVibGljS2V5OiBiYXNlNjRVcmxFbmNvZGUocHViUmF3KSxcbiAgICBwcml2YXRlS2V5SndrOiBwcml2SndrLFxuICB9O1xuXG4gIGlmIChzdG9yZSkge1xuICAgIGF3YWl0IHN0b3JlLnNldChpZGVudGl0eSk7XG4gIH0gZWxzZSB7XG4gICAgLy8gRmFsbGJhY2sgKHNob3VsZCBub3QgaGFwcGVuIGluIHJlYWwgcGx1Z2luIHJ1bnRpbWUpIFx1MjAxNCBrZWVwIGxlZ2FjeSBiZWhhdmlvci5cbiAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbShERVZJQ0VfU1RPUkFHRV9LRVksIEpTT04uc3RyaW5naWZ5KGlkZW50aXR5KSk7XG4gIH1cblxuICByZXR1cm4gaWRlbnRpdHk7XG59XG5cbmZ1bmN0aW9uIGJ1aWxkRGV2aWNlQXV0aFBheWxvYWQocGFyYW1zOiB7XG4gIGRldmljZUlkOiBzdHJpbmc7XG4gIGNsaWVudElkOiBzdHJpbmc7XG4gIGNsaWVudE1vZGU6IHN0cmluZztcbiAgcm9sZTogc3RyaW5nO1xuICBzY29wZXM6IHN0cmluZ1tdO1xuICBzaWduZWRBdE1zOiBudW1iZXI7XG4gIHRva2VuOiBzdHJpbmc7XG4gIG5vbmNlPzogc3RyaW5nO1xufSk6IHN0cmluZyB7XG4gIGNvbnN0IHZlcnNpb24gPSBwYXJhbXMubm9uY2UgPyAndjInIDogJ3YxJztcbiAgY29uc3Qgc2NvcGVzID0gcGFyYW1zLnNjb3Blcy5qb2luKCcsJyk7XG4gIGNvbnN0IGJhc2UgPSBbXG4gICAgdmVyc2lvbixcbiAgICBwYXJhbXMuZGV2aWNlSWQsXG4gICAgcGFyYW1zLmNsaWVudElkLFxuICAgIHBhcmFtcy5jbGllbnRNb2RlLFxuICAgIHBhcmFtcy5yb2xlLFxuICAgIHNjb3BlcyxcbiAgICBTdHJpbmcocGFyYW1zLnNpZ25lZEF0TXMpLFxuICAgIHBhcmFtcy50b2tlbiB8fCAnJyxcbiAgXTtcbiAgaWYgKHZlcnNpb24gPT09ICd2MicpIGJhc2UucHVzaChwYXJhbXMubm9uY2UgfHwgJycpO1xuICByZXR1cm4gYmFzZS5qb2luKCd8Jyk7XG59XG5cbmFzeW5jIGZ1bmN0aW9uIHNpZ25EZXZpY2VQYXlsb2FkKGlkZW50aXR5OiBEZXZpY2VJZGVudGl0eSwgcGF5bG9hZDogc3RyaW5nKTogUHJvbWlzZTx7IHNpZ25hdHVyZTogc3RyaW5nIH0+IHtcbiAgY29uc3QgcHJpdmF0ZUtleSA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KFxuICAgICdqd2snLFxuICAgIGlkZW50aXR5LnByaXZhdGVLZXlKd2ssXG4gICAgeyBuYW1lOiAnRWQyNTUxOScgfSxcbiAgICBmYWxzZSxcbiAgICBbJ3NpZ24nXSxcbiAgKTtcblxuICBjb25zdCBzaWcgPSBhd2FpdCBjcnlwdG8uc3VidGxlLnNpZ24oeyBuYW1lOiAnRWQyNTUxOScgfSwgcHJpdmF0ZUtleSwgdXRmOEJ5dGVzKHBheWxvYWQpIGFzIHVua25vd24gYXMgQnVmZmVyU291cmNlKTtcbiAgcmV0dXJuIHsgc2lnbmF0dXJlOiBiYXNlNjRVcmxFbmNvZGUoc2lnKSB9O1xufVxuXG5mdW5jdGlvbiBleHRyYWN0VGV4dEZyb21HYXRld2F5TWVzc2FnZShtc2c6IGFueSk6IHN0cmluZyB7XG4gIGlmICghbXNnKSByZXR1cm4gJyc7XG5cbiAgLy8gTW9zdCBjb21tb246IHsgcm9sZSwgY29udGVudCB9IHdoZXJlIGNvbnRlbnQgY2FuIGJlIHN0cmluZyBvciBbe3R5cGU6J3RleHQnLHRleHQ6Jy4uLid9XVxuICBjb25zdCBjb250ZW50ID0gbXNnLmNvbnRlbnQgPz8gbXNnLm1lc3NhZ2UgPz8gbXNnO1xuICBpZiAodHlwZW9mIGNvbnRlbnQgPT09ICdzdHJpbmcnKSByZXR1cm4gY29udGVudDtcblxuICBpZiAoQXJyYXkuaXNBcnJheShjb250ZW50KSkge1xuICAgIGNvbnN0IHBhcnRzID0gY29udGVudFxuICAgICAgLmZpbHRlcigoYykgPT4gYyAmJiB0eXBlb2YgYyA9PT0gJ29iamVjdCcgJiYgYy50eXBlID09PSAndGV4dCcgJiYgdHlwZW9mIGMudGV4dCA9PT0gJ3N0cmluZycpXG4gICAgICAubWFwKChjKSA9PiBjLnRleHQpO1xuICAgIHJldHVybiBwYXJ0cy5qb2luKCdcXG4nKTtcbiAgfVxuXG4gIC8vIEZhbGxiYWNrXG4gIHRyeSB7XG4gICAgcmV0dXJuIEpTT04uc3RyaW5naWZ5KGNvbnRlbnQpO1xuICB9IGNhdGNoIHtcbiAgICByZXR1cm4gU3RyaW5nKGNvbnRlbnQpO1xuICB9XG59XG5cbmZ1bmN0aW9uIHNlc3Npb25LZXlNYXRjaGVzKGNvbmZpZ3VyZWQ6IHN0cmluZywgaW5jb21pbmc6IHN0cmluZyk6IGJvb2xlYW4ge1xuICBpZiAoaW5jb21pbmcgPT09IGNvbmZpZ3VyZWQpIHJldHVybiB0cnVlO1xuICAvLyBPcGVuQ2xhdyByZXNvbHZlcyBcIm1haW5cIiB0byBjYW5vbmljYWwgc2Vzc2lvbiBrZXkgbGlrZSBcImFnZW50Om1haW46bWFpblwiLlxuICBpZiAoY29uZmlndXJlZCA9PT0gJ21haW4nICYmIGluY29taW5nID09PSAnYWdlbnQ6bWFpbjptYWluJykgcmV0dXJuIHRydWU7XG4gIHJldHVybiBmYWxzZTtcbn1cblxuZXhwb3J0IGNsYXNzIE9ic2lkaWFuV1NDbGllbnQge1xuICBwcml2YXRlIHdzOiBXZWJTb2NrZXQgfCBudWxsID0gbnVsbDtcbiAgcHJpdmF0ZSByZWNvbm5lY3RUaW1lcjogUmV0dXJuVHlwZTx0eXBlb2Ygc2V0VGltZW91dD4gfCBudWxsID0gbnVsbDtcbiAgcHJpdmF0ZSBoZWFydGJlYXRUaW1lcjogUmV0dXJuVHlwZTx0eXBlb2Ygc2V0SW50ZXJ2YWw+IHwgbnVsbCA9IG51bGw7XG4gIHByaXZhdGUgd29ya2luZ1RpbWVyOiBSZXR1cm5UeXBlPHR5cGVvZiBzZXRUaW1lb3V0PiB8IG51bGwgPSBudWxsO1xuICBwcml2YXRlIGludGVudGlvbmFsQ2xvc2UgPSBmYWxzZTtcbiAgcHJpdmF0ZSBzZXNzaW9uS2V5OiBzdHJpbmc7XG4gIHByaXZhdGUgdXJsID0gJyc7XG4gIHByaXZhdGUgdG9rZW4gPSAnJztcbiAgcHJpdmF0ZSByZXF1ZXN0SWQgPSAwO1xuICBwcml2YXRlIHBlbmRpbmdSZXF1ZXN0cyA9IG5ldyBNYXA8c3RyaW5nLCBQZW5kaW5nUmVxdWVzdD4oKTtcbiAgcHJpdmF0ZSB3b3JraW5nID0gZmFsc2U7XG5cbiAgLyoqIFRoZSBsYXN0IGluLWZsaWdodCBjaGF0IHJ1biBpZC4gSW4gT3BlbkNsYXcgV2ViQ2hhdCB0aGlzIG1hcHMgdG8gY2hhdC5zZW5kIGlkZW1wb3RlbmN5S2V5LiAqL1xuICBwcml2YXRlIGFjdGl2ZVJ1bklkOiBzdHJpbmcgfCBudWxsID0gbnVsbDtcblxuICAvKiogUHJldmVudHMgYWJvcnQgc3BhbW1pbmc6IHdoaWxlIGFuIGFib3J0IHJlcXVlc3QgaXMgaW4tZmxpZ2h0LCByZXVzZSB0aGUgc2FtZSBwcm9taXNlLiAqL1xuICBwcml2YXRlIGFib3J0SW5GbGlnaHQ6IFByb21pc2U8Ym9vbGVhbj4gfCBudWxsID0gbnVsbDtcblxuICBzdGF0ZTogV1NDbGllbnRTdGF0ZSA9ICdkaXNjb25uZWN0ZWQnO1xuXG4gIG9uTWVzc2FnZTogKChtc2c6IEluYm91bmRXU1BheWxvYWQpID0+IHZvaWQpIHwgbnVsbCA9IG51bGw7XG4gIG9uU3RhdGVDaGFuZ2U6ICgoc3RhdGU6IFdTQ2xpZW50U3RhdGUpID0+IHZvaWQpIHwgbnVsbCA9IG51bGw7XG4gIG9uV29ya2luZ0NoYW5nZTogV29ya2luZ1N0YXRlTGlzdGVuZXIgfCBudWxsID0gbnVsbDtcblxuICBwcml2YXRlIGlkZW50aXR5U3RvcmU6IERldmljZUlkZW50aXR5U3RvcmUgfCB1bmRlZmluZWQ7XG4gIHByaXZhdGUgYWxsb3dJbnNlY3VyZVdzID0gZmFsc2U7XG5cbiAgcHJpdmF0ZSByZWNvbm5lY3RBdHRlbXB0ID0gMDtcblxuICBjb25zdHJ1Y3RvcihzZXNzaW9uS2V5OiBzdHJpbmcsIG9wdHM/OiB7IGlkZW50aXR5U3RvcmU/OiBEZXZpY2VJZGVudGl0eVN0b3JlOyBhbGxvd0luc2VjdXJlV3M/OiBib29sZWFuIH0pIHtcbiAgICB0aGlzLnNlc3Npb25LZXkgPSBzZXNzaW9uS2V5O1xuICAgIHRoaXMuaWRlbnRpdHlTdG9yZSA9IG9wdHM/LmlkZW50aXR5U3RvcmU7XG4gICAgdGhpcy5hbGxvd0luc2VjdXJlV3MgPSBCb29sZWFuKG9wdHM/LmFsbG93SW5zZWN1cmVXcyk7XG4gIH1cblxuICBjb25uZWN0KHVybDogc3RyaW5nLCB0b2tlbjogc3RyaW5nLCBvcHRzPzogeyBhbGxvd0luc2VjdXJlV3M/OiBib29sZWFuIH0pOiB2b2lkIHtcbiAgICB0aGlzLnVybCA9IHVybDtcbiAgICB0aGlzLnRva2VuID0gdG9rZW47XG4gICAgdGhpcy5hbGxvd0luc2VjdXJlV3MgPSBCb29sZWFuKG9wdHM/LmFsbG93SW5zZWN1cmVXcyA/PyB0aGlzLmFsbG93SW5zZWN1cmVXcyk7XG4gICAgdGhpcy5pbnRlbnRpb25hbENsb3NlID0gZmFsc2U7XG5cbiAgICAvLyBTZWN1cml0eTogYmxvY2sgbm9uLWxvY2FsIHdzOi8vIHVubGVzcyBleHBsaWNpdGx5IGFsbG93ZWQuXG4gICAgY29uc3QgcGFyc2VkID0gc2FmZVBhcnNlV3NVcmwodXJsKTtcbiAgICBpZiAoIXBhcnNlZC5vaykge1xuICAgICAgdGhpcy5vbk1lc3NhZ2U/Lih7IHR5cGU6ICdlcnJvcicsIHBheWxvYWQ6IHsgbWVzc2FnZTogcGFyc2VkLmVycm9yIH0gfSk7XG4gICAgICByZXR1cm47XG4gICAgfVxuICAgIGlmIChwYXJzZWQuc2NoZW1lID09PSAnd3MnICYmICFpc0xvY2FsSG9zdChwYXJzZWQuaG9zdCkgJiYgIXRoaXMuYWxsb3dJbnNlY3VyZVdzKSB7XG4gICAgICB0aGlzLm9uTWVzc2FnZT8uKHtcbiAgICAgICAgdHlwZTogJ2Vycm9yJyxcbiAgICAgICAgcGF5bG9hZDogeyBtZXNzYWdlOiAnUmVmdXNpbmcgaW5zZWN1cmUgd3M6Ly8gdG8gbm9uLWxvY2FsIGdhdGV3YXkuIFVzZSB3c3M6Ly8gb3IgZW5hYmxlIHRoZSB1bnNhZmUgb3ZlcnJpZGUgaW4gc2V0dGluZ3MuJyB9LFxuICAgICAgfSk7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgdGhpcy5fY29ubmVjdCgpO1xuICB9XG5cbiAgZGlzY29ubmVjdCgpOiB2b2lkIHtcbiAgICB0aGlzLmludGVudGlvbmFsQ2xvc2UgPSB0cnVlO1xuICAgIHRoaXMuX3N0b3BUaW1lcnMoKTtcbiAgICB0aGlzLmFjdGl2ZVJ1bklkID0gbnVsbDtcbiAgICB0aGlzLmFib3J0SW5GbGlnaHQgPSBudWxsO1xuICAgIHRoaXMuX3NldFdvcmtpbmcoZmFsc2UpO1xuICAgIGlmICh0aGlzLndzKSB7XG4gICAgICB0aGlzLndzLmNsb3NlKCk7XG4gICAgICB0aGlzLndzID0gbnVsbDtcbiAgICB9XG4gICAgdGhpcy5fc2V0U3RhdGUoJ2Rpc2Nvbm5lY3RlZCcpO1xuICB9XG5cbiAgc2V0U2Vzc2lvbktleShzZXNzaW9uS2V5OiBzdHJpbmcpOiB2b2lkIHtcbiAgICB0aGlzLnNlc3Npb25LZXkgPSBzZXNzaW9uS2V5LnRyaW0oKTtcbiAgICAvLyBSZXNldCBwZXItc2Vzc2lvbiBydW4gc3RhdGUuXG4gICAgdGhpcy5hY3RpdmVSdW5JZCA9IG51bGw7XG4gICAgdGhpcy5hYm9ydEluRmxpZ2h0ID0gbnVsbDtcbiAgICB0aGlzLl9zZXRXb3JraW5nKGZhbHNlKTtcbiAgfVxuXG4gIC8vIE5PVEU6IGNhbm9uaWNhbCBPYnNpZGlhbiBzZXNzaW9uIGtleXMgZG8gbm90IHJlcXVpcmUgZ2F0ZXdheSBzZXNzaW9ucy5saXN0IGZvciBjb3JlIFVYLlxuXG4gIGFzeW5jIHNlbmRNZXNzYWdlKG1lc3NhZ2U6IHN0cmluZyk6IFByb21pc2U8dm9pZD4ge1xuICAgIGlmICh0aGlzLnN0YXRlICE9PSAnY29ubmVjdGVkJykge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKCdOb3QgY29ubmVjdGVkIFx1MjAxNCBjYWxsIGNvbm5lY3QoKSBmaXJzdCcpO1xuICAgIH1cblxuICAgIGNvbnN0IHJ1bklkID0gYG9ic2lkaWFuLSR7RGF0ZS5ub3coKX0tJHtNYXRoLnJhbmRvbSgpLnRvU3RyaW5nKDM2KS5zbGljZSgyLCA5KX1gO1xuXG4gICAgLy8gU2hvdyBcdTIwMUN3b3JraW5nXHUyMDFEIE9OTFkgYWZ0ZXIgdGhlIGdhdGV3YXkgYWNrbm93bGVkZ2VzIHRoZSByZXF1ZXN0LlxuICAgIGNvbnN0IGFjayA9IGF3YWl0IHRoaXMuX3NlbmRSZXF1ZXN0KCdjaGF0LnNlbmQnLCB7XG4gICAgICBzZXNzaW9uS2V5OiB0aGlzLnNlc3Npb25LZXksXG4gICAgICBtZXNzYWdlLFxuICAgICAgaWRlbXBvdGVuY3lLZXk6IHJ1bklkLFxuICAgICAgLy8gZGVsaXZlciBkZWZhdWx0cyB0byB0cnVlIGluIGdhdGV3YXk7IGtlZXAgZGVmYXVsdFxuICAgIH0pO1xuXG4gICAgLy8gSWYgdGhlIGdhdGV3YXkgcmV0dXJucyBhIGNhbm9uaWNhbCBydW4gaWRlbnRpZmllciwgcHJlZmVyIGl0LlxuICAgIGNvbnN0IGNhbm9uaWNhbFJ1bklkID0gU3RyaW5nKGFjaz8ucnVuSWQgfHwgYWNrPy5pZGVtcG90ZW5jeUtleSB8fCAnJyk7XG4gICAgdGhpcy5hY3RpdmVSdW5JZCA9IGNhbm9uaWNhbFJ1bklkIHx8IHJ1bklkO1xuICAgIHRoaXMuX3NldFdvcmtpbmcodHJ1ZSk7XG4gICAgdGhpcy5fYXJtV29ya2luZ1NhZmV0eVRpbWVvdXQoKTtcbiAgfVxuXG4gIC8qKiBBYm9ydCB0aGUgYWN0aXZlIHJ1biBmb3IgdGhpcyBzZXNzaW9uIChhbmQgb3VyIGxhc3QgcnVuIGlkIGlmIHByZXNlbnQpLiAqL1xuICBhc3luYyBhYm9ydEFjdGl2ZVJ1bigpOiBQcm9taXNlPGJvb2xlYW4+IHtcbiAgICBpZiAodGhpcy5zdGF0ZSAhPT0gJ2Nvbm5lY3RlZCcpIHtcbiAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG5cbiAgICAvLyBQcmV2ZW50IHJlcXVlc3Qgc3Rvcm1zOiB3aGlsZSBvbmUgYWJvcnQgaXMgaW4gZmxpZ2h0LCByZXVzZSBpdC5cbiAgICBpZiAodGhpcy5hYm9ydEluRmxpZ2h0KSB7XG4gICAgICByZXR1cm4gdGhpcy5hYm9ydEluRmxpZ2h0O1xuICAgIH1cblxuICAgIGNvbnN0IHJ1bklkID0gdGhpcy5hY3RpdmVSdW5JZDtcbiAgICBpZiAoIXJ1bklkKSB7XG4gICAgICByZXR1cm4gZmFsc2U7XG4gICAgfVxuXG4gICAgdGhpcy5hYm9ydEluRmxpZ2h0ID0gKGFzeW5jICgpID0+IHtcbiAgICAgIHRyeSB7XG4gICAgICAgIGF3YWl0IHRoaXMuX3NlbmRSZXF1ZXN0KCdjaGF0LmFib3J0JywgeyBzZXNzaW9uS2V5OiB0aGlzLnNlc3Npb25LZXksIHJ1bklkIH0pO1xuICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgIH0gY2F0Y2ggKGVycikge1xuICAgICAgICBjb25zb2xlLmVycm9yKCdbb2NsYXctd3NdIGNoYXQuYWJvcnQgZmFpbGVkJywgZXJyKTtcbiAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgfSBmaW5hbGx5IHtcbiAgICAgICAgLy8gQWx3YXlzIHJlc3RvcmUgVUkgc3RhdGUgaW1tZWRpYXRlbHk7IHRoZSBnYXRld2F5IG1heSBzdGlsbCBlbWl0IGFuIGFib3J0ZWQgZXZlbnQgbGF0ZXIuXG4gICAgICAgIHRoaXMuYWN0aXZlUnVuSWQgPSBudWxsO1xuICAgICAgICB0aGlzLl9zZXRXb3JraW5nKGZhbHNlKTtcbiAgICAgICAgdGhpcy5hYm9ydEluRmxpZ2h0ID0gbnVsbDtcbiAgICAgIH1cbiAgICB9KSgpO1xuXG4gICAgcmV0dXJuIHRoaXMuYWJvcnRJbkZsaWdodDtcbiAgfVxuXG4gIHByaXZhdGUgX2Nvbm5lY3QoKTogdm9pZCB7XG4gICAgaWYgKHRoaXMud3MpIHtcbiAgICAgIHRoaXMud3Mub25vcGVuID0gbnVsbDtcbiAgICAgIHRoaXMud3Mub25jbG9zZSA9IG51bGw7XG4gICAgICB0aGlzLndzLm9ubWVzc2FnZSA9IG51bGw7XG4gICAgICB0aGlzLndzLm9uZXJyb3IgPSBudWxsO1xuICAgICAgdGhpcy53cy5jbG9zZSgpO1xuICAgICAgdGhpcy53cyA9IG51bGw7XG4gICAgfVxuXG4gICAgdGhpcy5fc2V0U3RhdGUoJ2Nvbm5lY3RpbmcnKTtcblxuICAgIGNvbnN0IHdzID0gbmV3IFdlYlNvY2tldCh0aGlzLnVybCk7XG4gICAgdGhpcy53cyA9IHdzO1xuXG4gICAgbGV0IGNvbm5lY3ROb25jZTogc3RyaW5nIHwgbnVsbCA9IG51bGw7XG4gICAgbGV0IGNvbm5lY3RTdGFydGVkID0gZmFsc2U7XG5cbiAgICBjb25zdCB0cnlDb25uZWN0ID0gYXN5bmMgKCkgPT4ge1xuICAgICAgaWYgKGNvbm5lY3RTdGFydGVkKSByZXR1cm47XG4gICAgICBpZiAoIWNvbm5lY3ROb25jZSkgcmV0dXJuO1xuICAgICAgY29ubmVjdFN0YXJ0ZWQgPSB0cnVlO1xuXG4gICAgICB0cnkge1xuICAgICAgICBjb25zdCBpZGVudGl0eSA9IGF3YWl0IGxvYWRPckNyZWF0ZURldmljZUlkZW50aXR5KHRoaXMuaWRlbnRpdHlTdG9yZSk7XG4gICAgICAgIGNvbnN0IHNpZ25lZEF0TXMgPSBEYXRlLm5vdygpO1xuICAgICAgICBjb25zdCBwYXlsb2FkID0gYnVpbGREZXZpY2VBdXRoUGF5bG9hZCh7XG4gICAgICAgICAgZGV2aWNlSWQ6IGlkZW50aXR5LmlkLFxuICAgICAgICAgIGNsaWVudElkOiAnZ2F0ZXdheS1jbGllbnQnLFxuICAgICAgICAgIGNsaWVudE1vZGU6ICdiYWNrZW5kJyxcbiAgICAgICAgICByb2xlOiAnb3BlcmF0b3InLFxuICAgICAgICAgIHNjb3BlczogWydvcGVyYXRvci5yZWFkJywgJ29wZXJhdG9yLndyaXRlJ10sXG4gICAgICAgICAgc2lnbmVkQXRNcyxcbiAgICAgICAgICB0b2tlbjogdGhpcy50b2tlbixcbiAgICAgICAgICBub25jZTogY29ubmVjdE5vbmNlLFxuICAgICAgICB9KTtcbiAgICAgICAgY29uc3Qgc2lnID0gYXdhaXQgc2lnbkRldmljZVBheWxvYWQoaWRlbnRpdHksIHBheWxvYWQpO1xuXG4gICAgICAgIGNvbnN0IGFjayA9IGF3YWl0IHRoaXMuX3NlbmRSZXF1ZXN0KCdjb25uZWN0Jywge1xuICAgICAgICAgICBtaW5Qcm90b2NvbDogMyxcbiAgICAgICAgICAgbWF4UHJvdG9jb2w6IDMsXG4gICAgICAgICAgIGNsaWVudDoge1xuICAgICAgICAgICAgIGlkOiAnZ2F0ZXdheS1jbGllbnQnLFxuICAgICAgICAgICAgIG1vZGU6ICdiYWNrZW5kJyxcbiAgICAgICAgICAgICB2ZXJzaW9uOiAnMC4xLjEwJyxcbiAgICAgICAgICAgICBwbGF0Zm9ybTogJ2VsZWN0cm9uJyxcbiAgICAgICAgICAgfSxcbiAgICAgICAgICAgcm9sZTogJ29wZXJhdG9yJyxcbiAgICAgICAgICAgc2NvcGVzOiBbJ29wZXJhdG9yLnJlYWQnLCAnb3BlcmF0b3Iud3JpdGUnXSxcbiAgICAgICAgICAgZGV2aWNlOiB7XG4gICAgICAgICAgICAgaWQ6IGlkZW50aXR5LmlkLFxuICAgICAgICAgICAgIHB1YmxpY0tleTogaWRlbnRpdHkucHVibGljS2V5LFxuICAgICAgICAgICAgIHNpZ25hdHVyZTogc2lnLnNpZ25hdHVyZSxcbiAgICAgICAgICAgICBzaWduZWRBdDogc2lnbmVkQXRNcyxcbiAgICAgICAgICAgICBub25jZTogY29ubmVjdE5vbmNlLFxuICAgICAgICAgICB9LFxuICAgICAgICAgICBhdXRoOiB7XG4gICAgICAgICAgICAgdG9rZW46IHRoaXMudG9rZW4sXG4gICAgICAgICAgIH0sXG4gICAgICAgICB9KTtcblxuICAgICAgICAgdGhpcy5fc2V0U3RhdGUoJ2Nvbm5lY3RlZCcpO1xuICAgICAgICAgdGhpcy5yZWNvbm5lY3RBdHRlbXB0ID0gMDtcbiAgICAgICAgIGlmIChoYW5kc2hha2VUaW1lcikge1xuICAgICAgICAgICBjbGVhclRpbWVvdXQoaGFuZHNoYWtlVGltZXIpO1xuICAgICAgICAgICBoYW5kc2hha2VUaW1lciA9IG51bGw7XG4gICAgICAgICB9XG4gICAgICAgICB0aGlzLl9zdGFydEhlYXJ0YmVhdCgpO1xuICAgICAgfSBjYXRjaCAoZXJyKSB7XG4gICAgICAgIGNvbnNvbGUuZXJyb3IoJ1tvY2xhdy13c10gQ29ubmVjdCBoYW5kc2hha2UgZmFpbGVkJywgZXJyKTtcbiAgICAgICAgd3MuY2xvc2UoKTtcbiAgICAgIH1cbiAgICB9O1xuXG4gICAgbGV0IGhhbmRzaGFrZVRpbWVyOiBSZXR1cm5UeXBlPHR5cGVvZiBzZXRUaW1lb3V0PiB8IG51bGwgPSBudWxsO1xuXG4gICAgd3Mub25vcGVuID0gKCkgPT4ge1xuICAgICAgdGhpcy5fc2V0U3RhdGUoJ2hhbmRzaGFraW5nJyk7XG4gICAgICAvLyBUaGUgZ2F0ZXdheSB3aWxsIHNlbmQgY29ubmVjdC5jaGFsbGVuZ2U7IGNvbm5lY3QgaXMgc2VudCBvbmNlIHdlIGhhdmUgYSBub25jZS5cbiAgICAgIGlmIChoYW5kc2hha2VUaW1lcikgY2xlYXJUaW1lb3V0KGhhbmRzaGFrZVRpbWVyKTtcbiAgICAgIGhhbmRzaGFrZVRpbWVyID0gc2V0VGltZW91dCgoKSA9PiB7XG4gICAgICAgIC8vIElmIHdlIG5ldmVyIGdvdCB0aGUgY2hhbGxlbmdlIG5vbmNlLCBmb3JjZSByZWNvbm5lY3QuXG4gICAgICAgIGlmICh0aGlzLnN0YXRlID09PSAnaGFuZHNoYWtpbmcnICYmICF0aGlzLmludGVudGlvbmFsQ2xvc2UpIHtcbiAgICAgICAgICBjb25zb2xlLndhcm4oJ1tvY2xhdy13c10gSGFuZHNoYWtlIHRpbWVkIG91dCB3YWl0aW5nIGZvciBjb25uZWN0LmNoYWxsZW5nZScpO1xuICAgICAgICAgIHdzLmNsb3NlKCk7XG4gICAgICAgIH1cbiAgICAgIH0sIEhBTkRTSEFLRV9USU1FT1VUX01TKTtcbiAgICB9O1xuXG4gICAgd3Mub25tZXNzYWdlID0gKGV2ZW50OiBNZXNzYWdlRXZlbnQpID0+IHtcbiAgICAgIC8vIFdlYlNvY2tldCBvbm1lc3NhZ2UgY2Fubm90IGJlIGFzeW5jLCBidXQgd2UgY2FuIHJ1biBhbiBhc3luYyB0YXNrIGluc2lkZS5cbiAgICAgIHZvaWQgKGFzeW5jICgpID0+IHtcbiAgICAgICAgY29uc3Qgbm9ybWFsaXplZCA9IGF3YWl0IG5vcm1hbGl6ZVdzRGF0YVRvVGV4dChldmVudC5kYXRhKTtcbiAgICAgICAgaWYgKCFub3JtYWxpemVkLm9rKSB7XG4gICAgICAgICAgaWYgKG5vcm1hbGl6ZWQucmVhc29uID09PSAndG9vLWxhcmdlJykge1xuICAgICAgICAgICAgY29uc29sZS5lcnJvcignW29jbGF3LXdzXSBJbmJvdW5kIGZyYW1lIHRvbyBsYXJnZTsgY2xvc2luZyBjb25uZWN0aW9uJyk7XG4gICAgICAgICAgICB3cy5jbG9zZSgpO1xuICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBjb25zb2xlLmVycm9yKCdbb2NsYXctd3NdIFVuc3VwcG9ydGVkIGluYm91bmQgZnJhbWUgdHlwZTsgaWdub3JpbmcnKTtcbiAgICAgICAgICB9XG4gICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKG5vcm1hbGl6ZWQuYnl0ZXMgPiBNQVhfSU5CT1VORF9GUkFNRV9CWVRFUykge1xuICAgICAgICAgIGNvbnNvbGUuZXJyb3IoJ1tvY2xhdy13c10gSW5ib3VuZCBmcmFtZSB0b28gbGFyZ2U7IGNsb3NpbmcgY29ubmVjdGlvbicpO1xuICAgICAgICAgIHdzLmNsb3NlKCk7XG4gICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgbGV0IGZyYW1lOiBhbnk7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgZnJhbWUgPSBKU09OLnBhcnNlKG5vcm1hbGl6ZWQudGV4dCk7XG4gICAgICAgIH0gY2F0Y2gge1xuICAgICAgICAgIGNvbnNvbGUuZXJyb3IoJ1tvY2xhdy13c10gRmFpbGVkIHRvIHBhcnNlIGluY29taW5nIG1lc3NhZ2UnKTtcbiAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICAvLyBSZXNwb25zZXNcbiAgICAgICAgaWYgKGZyYW1lLnR5cGUgPT09ICdyZXMnKSB7XG4gICAgICAgICAgdGhpcy5faGFuZGxlUmVzcG9uc2VGcmFtZShmcmFtZSk7XG4gICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgLy8gRXZlbnRzXG4gICAgICAgIGlmIChmcmFtZS50eXBlID09PSAnZXZlbnQnKSB7XG4gICAgICAgICAgaWYgKGZyYW1lLmV2ZW50ID09PSAnY29ubmVjdC5jaGFsbGVuZ2UnKSB7XG4gICAgICAgICAgICBjb25uZWN0Tm9uY2UgPSBmcmFtZS5wYXlsb2FkPy5ub25jZSB8fCBudWxsO1xuICAgICAgICAgICAgLy8gQXR0ZW1wdCBoYW5kc2hha2Ugb25jZSB3ZSBoYXZlIGEgbm9uY2UuXG4gICAgICAgICAgICB2b2lkIHRyeUNvbm5lY3QoKTtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBpZiAoZnJhbWUuZXZlbnQgPT09ICdjaGF0Jykge1xuICAgICAgICAgICAgdGhpcy5faGFuZGxlQ2hhdEV2ZW50RnJhbWUoZnJhbWUpO1xuICAgICAgICAgIH1cbiAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICAvLyBBdm9pZCBsb2dnaW5nIGZ1bGwgZnJhbWVzIChtYXkgaW5jbHVkZSBtZXNzYWdlIGNvbnRlbnQgb3Igb3RoZXIgc2Vuc2l0aXZlIHBheWxvYWRzKS5cbiAgICAgICAgY29uc29sZS5kZWJ1ZygnW29jbGF3LXdzXSBVbmhhbmRsZWQgZnJhbWUnLCB7IHR5cGU6IGZyYW1lPy50eXBlLCBldmVudDogZnJhbWU/LmV2ZW50LCBpZDogZnJhbWU/LmlkIH0pO1xuICAgICAgfSkoKTtcbiAgICB9O1xuXG4gICAgY29uc3QgY2xlYXJIYW5kc2hha2VUaW1lciA9ICgpID0+IHtcbiAgICAgIGlmIChoYW5kc2hha2VUaW1lcikge1xuICAgICAgICBjbGVhclRpbWVvdXQoaGFuZHNoYWtlVGltZXIpO1xuICAgICAgICBoYW5kc2hha2VUaW1lciA9IG51bGw7XG4gICAgICB9XG4gICAgfTtcblxuICAgIHdzLm9uY2xvc2UgPSAoKSA9PiB7XG4gICAgICBjbGVhckhhbmRzaGFrZVRpbWVyKCk7XG4gICAgICB0aGlzLl9zdG9wVGltZXJzKCk7XG4gICAgICB0aGlzLmFjdGl2ZVJ1bklkID0gbnVsbDtcbiAgICAgIHRoaXMuYWJvcnRJbkZsaWdodCA9IG51bGw7XG4gICAgICB0aGlzLl9zZXRXb3JraW5nKGZhbHNlKTtcbiAgICAgIHRoaXMuX3NldFN0YXRlKCdkaXNjb25uZWN0ZWQnKTtcblxuICAgICAgZm9yIChjb25zdCBwZW5kaW5nIG9mIHRoaXMucGVuZGluZ1JlcXVlc3RzLnZhbHVlcygpKSB7XG4gICAgICAgIGlmIChwZW5kaW5nLnRpbWVvdXQpIGNsZWFyVGltZW91dChwZW5kaW5nLnRpbWVvdXQpO1xuICAgICAgICBwZW5kaW5nLnJlamVjdChuZXcgRXJyb3IoJ0Nvbm5lY3Rpb24gY2xvc2VkJykpO1xuICAgICAgfVxuICAgICAgdGhpcy5wZW5kaW5nUmVxdWVzdHMuY2xlYXIoKTtcblxuICAgICAgaWYgKCF0aGlzLmludGVudGlvbmFsQ2xvc2UpIHtcbiAgICAgICAgdGhpcy5fc2NoZWR1bGVSZWNvbm5lY3QoKTtcbiAgICAgIH1cbiAgICB9O1xuXG4gICAgd3Mub25lcnJvciA9IChldjogRXZlbnQpID0+IHtcbiAgICAgIGNsZWFySGFuZHNoYWtlVGltZXIoKTtcbiAgICAgIGNvbnNvbGUuZXJyb3IoJ1tvY2xhdy13c10gV2ViU29ja2V0IGVycm9yJywgZXYpO1xuICAgIH07XG4gIH1cblxuICBwcml2YXRlIF9oYW5kbGVSZXNwb25zZUZyYW1lKGZyYW1lOiBhbnkpOiB2b2lkIHtcbiAgICBjb25zdCBwZW5kaW5nID0gdGhpcy5wZW5kaW5nUmVxdWVzdHMuZ2V0KGZyYW1lLmlkKTtcbiAgICBpZiAoIXBlbmRpbmcpIHJldHVybjtcblxuICAgIHRoaXMucGVuZGluZ1JlcXVlc3RzLmRlbGV0ZShmcmFtZS5pZCk7XG4gICAgaWYgKHBlbmRpbmcudGltZW91dCkgY2xlYXJUaW1lb3V0KHBlbmRpbmcudGltZW91dCk7XG5cbiAgICBpZiAoZnJhbWUub2spIHBlbmRpbmcucmVzb2x2ZShmcmFtZS5wYXlsb2FkKTtcbiAgICBlbHNlIHBlbmRpbmcucmVqZWN0KG5ldyBFcnJvcihmcmFtZS5lcnJvcj8ubWVzc2FnZSB8fCAnUmVxdWVzdCBmYWlsZWQnKSk7XG4gIH1cblxuICBwcml2YXRlIF9oYW5kbGVDaGF0RXZlbnRGcmFtZShmcmFtZTogYW55KTogdm9pZCB7XG4gICAgY29uc3QgcGF5bG9hZCA9IGZyYW1lLnBheWxvYWQ7XG4gICAgY29uc3QgaW5jb21pbmdTZXNzaW9uS2V5ID0gU3RyaW5nKHBheWxvYWQ/LnNlc3Npb25LZXkgfHwgJycpO1xuICAgIGlmICghaW5jb21pbmdTZXNzaW9uS2V5IHx8ICFzZXNzaW9uS2V5TWF0Y2hlcyh0aGlzLnNlc3Npb25LZXksIGluY29taW5nU2Vzc2lvbktleSkpIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICAvLyBCZXN0LWVmZm9ydCBydW4gY29ycmVsYXRpb24gKGlmIGdhdGV3YXkgaW5jbHVkZXMgYSBydW4gaWQpLiBUaGlzIGF2b2lkcyBjbGVhcmluZyBvdXIgVUlcbiAgICAvLyBiYXNlZCBvbiBhIGRpZmZlcmVudCBjbGllbnQncyBydW4gaW4gdGhlIHNhbWUgc2Vzc2lvbi5cbiAgICBjb25zdCBpbmNvbWluZ1J1bklkID0gU3RyaW5nKHBheWxvYWQ/LnJ1bklkIHx8IHBheWxvYWQ/LmlkZW1wb3RlbmN5S2V5IHx8IHBheWxvYWQ/Lm1ldGE/LnJ1bklkIHx8ICcnKTtcbiAgICBpZiAodGhpcy5hY3RpdmVSdW5JZCAmJiBpbmNvbWluZ1J1bklkICYmIGluY29taW5nUnVuSWQgIT09IHRoaXMuYWN0aXZlUnVuSWQpIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICAvLyBBdm9pZCBkb3VibGUtcmVuZGVyOiBnYXRld2F5IGVtaXRzIGRlbHRhICsgZmluYWwgKyBhYm9ydGVkLiBSZW5kZXIgb25seSBleHBsaWNpdCBmaW5hbC9hYm9ydGVkLlxuICAgIC8vIElmIHN0YXRlIGlzIG1pc3NpbmcsIHRyZWF0IGFzIG5vbi10ZXJtaW5hbCAoZG8gbm90IGNsZWFyIFVJIC8gZG8gbm90IHJlbmRlcikuXG4gICAgaWYgKCFwYXlsb2FkPy5zdGF0ZSkge1xuICAgICAgcmV0dXJuO1xuICAgIH1cbiAgICBpZiAocGF5bG9hZC5zdGF0ZSAhPT0gJ2ZpbmFsJyAmJiBwYXlsb2FkLnN0YXRlICE9PSAnYWJvcnRlZCcpIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICAvLyBXZSBvbmx5IGFwcGVuZCBhc3Npc3RhbnQgb3V0cHV0IHRvIFVJLlxuICAgIGNvbnN0IG1zZyA9IHBheWxvYWQ/Lm1lc3NhZ2U7XG4gICAgY29uc3Qgcm9sZSA9IG1zZz8ucm9sZSA/PyAnYXNzaXN0YW50JztcblxuICAgIC8vIEFib3J0ZWQgZW5kcyB0aGUgcnVuIHJlZ2FyZGxlc3Mgb2Ygcm9sZS9tZXNzYWdlLlxuICAgIGlmIChwYXlsb2FkLnN0YXRlID09PSAnYWJvcnRlZCcpIHtcbiAgICAgIHRoaXMuYWN0aXZlUnVuSWQgPSBudWxsO1xuICAgICAgdGhpcy5fc2V0V29ya2luZyhmYWxzZSk7XG4gICAgICAvLyBBYm9ydGVkIG1heSBoYXZlIG5vIGFzc2lzdGFudCBtZXNzYWdlOyBpZiBub25lLCBzdG9wIGhlcmUuXG4gICAgICBpZiAoIW1zZykgcmV0dXJuO1xuICAgICAgLy8gSWYgdGhlcmUgaXMgYSBtZXNzYWdlLCBvbmx5IGFwcGVuZCBhc3Npc3RhbnQgb3V0cHV0LlxuICAgICAgaWYgKHJvbGUgIT09ICdhc3Npc3RhbnQnKSByZXR1cm47XG4gICAgfVxuXG4gICAgLy8gRmluYWwgc2hvdWxkIG9ubHkgY29tcGxldGUgdGhlIHJ1biB3aGVuIHRoZSBhc3Npc3RhbnQgY29tcGxldGVzLlxuICAgIGlmIChwYXlsb2FkLnN0YXRlID09PSAnZmluYWwnKSB7XG4gICAgICBpZiAocm9sZSAhPT0gJ2Fzc2lzdGFudCcpIHJldHVybjtcbiAgICAgIHRoaXMuYWN0aXZlUnVuSWQgPSBudWxsO1xuICAgICAgdGhpcy5fc2V0V29ya2luZyhmYWxzZSk7XG4gICAgfVxuXG4gICAgY29uc3QgdGV4dCA9IGV4dHJhY3RUZXh0RnJvbUdhdGV3YXlNZXNzYWdlKG1zZyk7XG4gICAgaWYgKCF0ZXh0KSByZXR1cm47XG5cbiAgICAvLyBPcHRpb25hbDogaGlkZSBoZWFydGJlYXQgYWNrcyAobm9pc2UgaW4gVUkpXG4gICAgaWYgKHRleHQudHJpbSgpID09PSAnSEVBUlRCRUFUX09LJykge1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIHRoaXMub25NZXNzYWdlPy4oe1xuICAgICAgdHlwZTogJ21lc3NhZ2UnLFxuICAgICAgcGF5bG9hZDoge1xuICAgICAgICBjb250ZW50OiB0ZXh0LFxuICAgICAgICByb2xlOiAnYXNzaXN0YW50JyxcbiAgICAgICAgdGltZXN0YW1wOiBEYXRlLm5vdygpLFxuICAgICAgfSxcbiAgICB9KTtcbiAgfVxuXG4gIHByaXZhdGUgX3NlbmRSZXF1ZXN0KG1ldGhvZDogc3RyaW5nLCBwYXJhbXM6IGFueSk6IFByb21pc2U8YW55PiB7XG4gICAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIGlmICghdGhpcy53cyB8fCB0aGlzLndzLnJlYWR5U3RhdGUgIT09IFdlYlNvY2tldC5PUEVOKSB7XG4gICAgICAgIHJlamVjdChuZXcgRXJyb3IoJ1dlYlNvY2tldCBub3QgY29ubmVjdGVkJykpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG5cbiAgICAgIGlmICh0aGlzLnBlbmRpbmdSZXF1ZXN0cy5zaXplID49IE1BWF9QRU5ESU5HX1JFUVVFU1RTKSB7XG4gICAgICAgIHJlamVjdChuZXcgRXJyb3IoYFRvbyBtYW55IGluLWZsaWdodCByZXF1ZXN0cyAoJHt0aGlzLnBlbmRpbmdSZXF1ZXN0cy5zaXplfSlgKSk7XG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cblxuICAgICAgY29uc3QgaWQgPSBgcmVxLSR7Kyt0aGlzLnJlcXVlc3RJZH1gO1xuXG4gICAgICBjb25zdCBwZW5kaW5nOiBQZW5kaW5nUmVxdWVzdCA9IHsgcmVzb2x2ZSwgcmVqZWN0LCB0aW1lb3V0OiBudWxsIH07XG4gICAgICB0aGlzLnBlbmRpbmdSZXF1ZXN0cy5zZXQoaWQsIHBlbmRpbmcpO1xuXG4gICAgICBjb25zdCBwYXlsb2FkID0gSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0eXBlOiAncmVxJyxcbiAgICAgICAgbWV0aG9kLFxuICAgICAgICBpZCxcbiAgICAgICAgcGFyYW1zLFxuICAgICAgfSk7XG5cbiAgICAgIHRyeSB7XG4gICAgICAgIHRoaXMud3Muc2VuZChwYXlsb2FkKTtcbiAgICAgIH0gY2F0Y2ggKGVycikge1xuICAgICAgICB0aGlzLnBlbmRpbmdSZXF1ZXN0cy5kZWxldGUoaWQpO1xuICAgICAgICByZWplY3QoZXJyKTtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuXG4gICAgICBwZW5kaW5nLnRpbWVvdXQgPSBzZXRUaW1lb3V0KCgpID0+IHtcbiAgICAgICAgaWYgKHRoaXMucGVuZGluZ1JlcXVlc3RzLmhhcyhpZCkpIHtcbiAgICAgICAgICB0aGlzLnBlbmRpbmdSZXF1ZXN0cy5kZWxldGUoaWQpO1xuICAgICAgICAgIHJlamVjdChuZXcgRXJyb3IoYFJlcXVlc3QgdGltZW91dDogJHttZXRob2R9YCkpO1xuICAgICAgICB9XG4gICAgICB9LCAzMF8wMDApO1xuICAgIH0pO1xuICB9XG5cbiAgcHJpdmF0ZSBfc2NoZWR1bGVSZWNvbm5lY3QoKTogdm9pZCB7XG4gICAgaWYgKHRoaXMucmVjb25uZWN0VGltZXIgIT09IG51bGwpIHJldHVybjtcblxuICAgIGNvbnN0IGF0dGVtcHQgPSArK3RoaXMucmVjb25uZWN0QXR0ZW1wdDtcbiAgICBjb25zdCBleHAgPSBNYXRoLm1pbihSRUNPTk5FQ1RfTUFYX01TLCBSRUNPTk5FQ1RfQkFTRV9NUyAqIE1hdGgucG93KDIsIGF0dGVtcHQgLSAxKSk7XG4gICAgLy8gSml0dGVyOiAwLjV4Li4xLjV4XG4gICAgY29uc3Qgaml0dGVyID0gMC41ICsgTWF0aC5yYW5kb20oKTtcbiAgICBjb25zdCBkZWxheSA9IE1hdGguZmxvb3IoZXhwICogaml0dGVyKTtcblxuICAgIHRoaXMucmVjb25uZWN0VGltZXIgPSBzZXRUaW1lb3V0KCgpID0+IHtcbiAgICAgIHRoaXMucmVjb25uZWN0VGltZXIgPSBudWxsO1xuICAgICAgaWYgKCF0aGlzLmludGVudGlvbmFsQ2xvc2UpIHtcbiAgICAgICAgY29uc29sZS5sb2coYFtvY2xhdy13c10gUmVjb25uZWN0aW5nIHRvICR7dGhpcy51cmx9XHUyMDI2IChhdHRlbXB0ICR7YXR0ZW1wdH0sICR7ZGVsYXl9bXMpYCk7XG4gICAgICAgIHRoaXMuX2Nvbm5lY3QoKTtcbiAgICAgIH1cbiAgICB9LCBkZWxheSk7XG4gIH1cblxuICBwcml2YXRlIGxhc3RCdWZmZXJlZFdhcm5BdE1zID0gMDtcblxuICBwcml2YXRlIF9zdGFydEhlYXJ0YmVhdCgpOiB2b2lkIHtcbiAgICB0aGlzLl9zdG9wSGVhcnRiZWF0KCk7XG4gICAgdGhpcy5oZWFydGJlYXRUaW1lciA9IHNldEludGVydmFsKCgpID0+IHtcbiAgICAgIGlmICh0aGlzLndzPy5yZWFkeVN0YXRlICE9PSBXZWJTb2NrZXQuT1BFTikgcmV0dXJuO1xuICAgICAgaWYgKHRoaXMud3MuYnVmZmVyZWRBbW91bnQgPiAwKSB7XG4gICAgICAgIGNvbnN0IG5vdyA9IERhdGUubm93KCk7XG4gICAgICAgIC8vIFRocm90dGxlIHRvIGF2b2lkIGxvZyBzcGFtIGluIGxvbmctcnVubmluZyBzZXNzaW9ucy5cbiAgICAgICAgaWYgKG5vdyAtIHRoaXMubGFzdEJ1ZmZlcmVkV2FybkF0TXMgPiA1ICogNjBfMDAwKSB7XG4gICAgICAgICAgdGhpcy5sYXN0QnVmZmVyZWRXYXJuQXRNcyA9IG5vdztcbiAgICAgICAgICBjb25zb2xlLndhcm4oJ1tvY2xhdy13c10gU2VuZCBidWZmZXIgbm90IGVtcHR5IFx1MjAxNCBjb25uZWN0aW9uIG1heSBiZSBzdGFsbGVkJyk7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9LCBIRUFSVEJFQVRfSU5URVJWQUxfTVMpO1xuICB9XG5cbiAgcHJpdmF0ZSBfc3RvcEhlYXJ0YmVhdCgpOiB2b2lkIHtcbiAgICBpZiAodGhpcy5oZWFydGJlYXRUaW1lcikge1xuICAgICAgY2xlYXJJbnRlcnZhbCh0aGlzLmhlYXJ0YmVhdFRpbWVyKTtcbiAgICAgIHRoaXMuaGVhcnRiZWF0VGltZXIgPSBudWxsO1xuICAgIH1cbiAgfVxuXG4gIHByaXZhdGUgX3N0b3BUaW1lcnMoKTogdm9pZCB7XG4gICAgdGhpcy5fc3RvcEhlYXJ0YmVhdCgpO1xuICAgIHRoaXMuX2Rpc2FybVdvcmtpbmdTYWZldHlUaW1lb3V0KCk7XG4gICAgaWYgKHRoaXMucmVjb25uZWN0VGltZXIpIHtcbiAgICAgIGNsZWFyVGltZW91dCh0aGlzLnJlY29ubmVjdFRpbWVyKTtcbiAgICAgIHRoaXMucmVjb25uZWN0VGltZXIgPSBudWxsO1xuICAgIH1cbiAgfVxuXG4gIHByaXZhdGUgX3NldFN0YXRlKHN0YXRlOiBXU0NsaWVudFN0YXRlKTogdm9pZCB7XG4gICAgaWYgKHRoaXMuc3RhdGUgPT09IHN0YXRlKSByZXR1cm47XG4gICAgdGhpcy5zdGF0ZSA9IHN0YXRlO1xuICAgIHRoaXMub25TdGF0ZUNoYW5nZT8uKHN0YXRlKTtcbiAgfVxuXG4gIHByaXZhdGUgX3NldFdvcmtpbmcod29ya2luZzogYm9vbGVhbik6IHZvaWQge1xuICAgIGlmICh0aGlzLndvcmtpbmcgPT09IHdvcmtpbmcpIHJldHVybjtcbiAgICB0aGlzLndvcmtpbmcgPSB3b3JraW5nO1xuICAgIHRoaXMub25Xb3JraW5nQ2hhbmdlPy4od29ya2luZyk7XG5cbiAgICBpZiAoIXdvcmtpbmcpIHtcbiAgICAgIHRoaXMuX2Rpc2FybVdvcmtpbmdTYWZldHlUaW1lb3V0KCk7XG4gICAgfVxuICB9XG5cbiAgcHJpdmF0ZSBfYXJtV29ya2luZ1NhZmV0eVRpbWVvdXQoKTogdm9pZCB7XG4gICAgdGhpcy5fZGlzYXJtV29ya2luZ1NhZmV0eVRpbWVvdXQoKTtcbiAgICB0aGlzLndvcmtpbmdUaW1lciA9IHNldFRpbWVvdXQoKCkgPT4ge1xuICAgICAgLy8gSWYgdGhlIGdhdGV3YXkgbmV2ZXIgZW1pdHMgYW4gYXNzaXN0YW50IGZpbmFsIHJlc3BvbnNlLCBkb25cdTIwMTl0IGxlYXZlIFVJIHN0dWNrLlxuICAgICAgdGhpcy5fc2V0V29ya2luZyhmYWxzZSk7XG4gICAgfSwgV09SS0lOR19NQVhfTVMpO1xuICB9XG5cbiAgcHJpdmF0ZSBfZGlzYXJtV29ya2luZ1NhZmV0eVRpbWVvdXQoKTogdm9pZCB7XG4gICAgaWYgKHRoaXMud29ya2luZ1RpbWVyKSB7XG4gICAgICBjbGVhclRpbWVvdXQodGhpcy53b3JraW5nVGltZXIpO1xuICAgICAgdGhpcy53b3JraW5nVGltZXIgPSBudWxsO1xuICAgIH1cbiAgfVxufVxuIiwgImltcG9ydCB7IEl0ZW1WaWV3LCBNYXJrZG93blJlbmRlcmVyLCBNb2RhbCwgTm90aWNlLCBTZXR0aW5nLCBURmlsZSwgV29ya3NwYWNlTGVhZiB9IGZyb20gJ29ic2lkaWFuJztcbmltcG9ydCB0eXBlIE9wZW5DbGF3UGx1Z2luIGZyb20gJy4vbWFpbic7XG5pbXBvcnQgeyBDaGF0TWFuYWdlciB9IGZyb20gJy4vY2hhdCc7XG5pbXBvcnQgdHlwZSB7IENoYXRNZXNzYWdlLCBQYXRoTWFwcGluZyB9IGZyb20gJy4vdHlwZXMnO1xuaW1wb3J0IHsgZXh0cmFjdENhbmRpZGF0ZXMsIHRyeU1hcFJlbW90ZVBhdGhUb1ZhdWx0UGF0aCB9IGZyb20gJy4vbGlua2lmeSc7XG5pbXBvcnQgeyBnZXRBY3RpdmVOb3RlQ29udGV4dCB9IGZyb20gJy4vY29udGV4dCc7XG5pbXBvcnQgeyBPYnNpZGlhbldTQ2xpZW50IH0gZnJvbSAnLi93ZWJzb2NrZXQnO1xuXG5leHBvcnQgY29uc3QgVklFV19UWVBFX09QRU5DTEFXX0NIQVQgPSAnb3BlbmNsYXctY2hhdCc7XG5cbmNsYXNzIE5ld1Nlc3Npb25Nb2RhbCBleHRlbmRzIE1vZGFsIHtcbiAgcHJpdmF0ZSBpbml0aWFsVmFsdWU6IHN0cmluZztcbiAgcHJpdmF0ZSBvblN1Ym1pdDogKHZhbHVlOiBzdHJpbmcpID0+IHZvaWQ7XG5cbiAgY29uc3RydWN0b3IodmlldzogT3BlbkNsYXdDaGF0VmlldywgaW5pdGlhbFZhbHVlOiBzdHJpbmcsIG9uU3VibWl0OiAodmFsdWU6IHN0cmluZykgPT4gdm9pZCkge1xuICAgIHN1cGVyKHZpZXcuYXBwKTtcbiAgICB0aGlzLmluaXRpYWxWYWx1ZSA9IGluaXRpYWxWYWx1ZTtcbiAgICB0aGlzLm9uU3VibWl0ID0gb25TdWJtaXQ7XG4gIH1cblxuICBvbk9wZW4oKTogdm9pZCB7XG4gICAgY29uc3QgeyBjb250ZW50RWwgfSA9IHRoaXM7XG4gICAgY29udGVudEVsLmVtcHR5KCk7XG5cbiAgICBjb250ZW50RWwuY3JlYXRlRWwoJ2gzJywgeyB0ZXh0OiAnTmV3IHNlc3Npb24ga2V5JyB9KTtcblxuICAgIGxldCB2YWx1ZSA9IHRoaXMuaW5pdGlhbFZhbHVlO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGVudEVsKVxuICAgICAgLnNldE5hbWUoJ1Nlc3Npb24ga2V5JylcbiAgICAgIC5zZXREZXNjKCdUaXA6IGNob29zZSBhIHNob3J0IHN1ZmZpeDsgaXQgd2lsbCBiZWNvbWUgYWdlbnQ6bWFpbjpvYnNpZGlhbjpkaXJlY3Q6PHZhdWx0SGFzaD4tPHN1ZmZpeD4uJylcbiAgICAgIC5hZGRUZXh0KCh0KSA9PiB7XG4gICAgICAgIHQuc2V0VmFsdWUodmFsdWUpO1xuICAgICAgICB0Lm9uQ2hhbmdlKCh2KSA9PiB7XG4gICAgICAgICAgdmFsdWUgPSB2O1xuICAgICAgICB9KTtcbiAgICAgIH0pO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGVudEVsKVxuICAgICAgLmFkZEJ1dHRvbigoYikgPT4ge1xuICAgICAgICBiLnNldEJ1dHRvblRleHQoJ0NhbmNlbCcpO1xuICAgICAgICBiLm9uQ2xpY2soKCkgPT4gdGhpcy5jbG9zZSgpKTtcbiAgICAgIH0pXG4gICAgICAuYWRkQnV0dG9uKChiKSA9PiB7XG4gICAgICAgIGIuc2V0Q3RhKCk7XG4gICAgICAgIGIuc2V0QnV0dG9uVGV4dCgnQ3JlYXRlJyk7XG4gICAgICAgIGIub25DbGljaygoKSA9PiB7XG4gICAgICAgICAgY29uc3QgdiA9IHZhbHVlLnRyaW0oKS50b0xvd2VyQ2FzZSgpO1xuICAgICAgICAgIGlmICghdikge1xuICAgICAgICAgICAgbmV3IE5vdGljZSgnU3VmZml4IGNhbm5vdCBiZSBlbXB0eScpO1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgIH1cbiAgICAgICAgICBpZiAoIS9eW2EtejAtOV1bYS16MC05Xy1dezAsNjN9JC8udGVzdCh2KSkge1xuICAgICAgICAgICAgbmV3IE5vdGljZSgnVXNlIGxldHRlcnMvbnVtYmVycy9fLy0gb25seSAobWF4IDY0IGNoYXJzKScpO1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgIH1cbiAgICAgICAgICB0aGlzLm9uU3VibWl0KHYpO1xuICAgICAgICAgIHRoaXMuY2xvc2UoKTtcbiAgICAgICAgfSk7XG4gICAgICB9KTtcbiAgfVxufVxuXG5leHBvcnQgY2xhc3MgT3BlbkNsYXdDaGF0VmlldyBleHRlbmRzIEl0ZW1WaWV3IHtcbiAgcHJpdmF0ZSBwbHVnaW46IE9wZW5DbGF3UGx1Z2luO1xuICBwcml2YXRlIGNoYXRNYW5hZ2VyOiBDaGF0TWFuYWdlcjtcbiAgcHJpdmF0ZSB3c0NsaWVudDogT2JzaWRpYW5XU0NsaWVudDtcblxuICAvLyBTdGF0ZVxuICBwcml2YXRlIGlzQ29ubmVjdGVkID0gZmFsc2U7XG4gIHByaXZhdGUgaXNXb3JraW5nID0gZmFsc2U7XG5cbiAgLy8gQ29ubmVjdGlvbiBub3RpY2VzIChhdm9pZCBzcGFtKVxuICBwcml2YXRlIGxhc3RDb25uTm90aWNlQXRNcyA9IDA7XG4gIHByaXZhdGUgbGFzdEdhdGV3YXlTdGF0ZTogc3RyaW5nIHwgbnVsbCA9IG51bGw7XG5cbiAgLy8gRE9NIHJlZnNcbiAgcHJpdmF0ZSBtZXNzYWdlc0VsITogSFRNTEVsZW1lbnQ7XG4gIHByaXZhdGUgaW5wdXRFbCE6IEhUTUxUZXh0QXJlYUVsZW1lbnQ7XG4gIHByaXZhdGUgc2VuZEJ0biE6IEhUTUxCdXR0b25FbGVtZW50O1xuICBwcml2YXRlIGluY2x1ZGVOb3RlQ2hlY2tib3ghOiBIVE1MSW5wdXRFbGVtZW50O1xuICBwcml2YXRlIHN0YXR1c0RvdCE6IEhUTUxFbGVtZW50O1xuXG4gIHByaXZhdGUgc2Vzc2lvblNlbGVjdCE6IEhUTUxTZWxlY3RFbGVtZW50O1xuICBwcml2YXRlIHNlc3Npb25SZWZyZXNoQnRuITogSFRNTEJ1dHRvbkVsZW1lbnQ7XG4gIHByaXZhdGUgc2Vzc2lvbk5ld0J0biE6IEhUTUxCdXR0b25FbGVtZW50O1xuICBwcml2YXRlIHNlc3Npb25NYWluQnRuITogSFRNTEJ1dHRvbkVsZW1lbnQ7XG4gIHByaXZhdGUgc3VwcHJlc3NTZXNzaW9uU2VsZWN0Q2hhbmdlID0gZmFsc2U7XG5cbiAgLy8gKHJlbW92ZWQpIGludGVybmFsLWxpbmsgZGVsZWdhdGlvbiAoaGFuZGxlZCBieSBwb3N0LXByb2Nlc3NpbmcgbGlua2lmeSlcblxuICBjb25zdHJ1Y3RvcihsZWFmOiBXb3Jrc3BhY2VMZWFmLCBwbHVnaW46IE9wZW5DbGF3UGx1Z2luKSB7XG4gICAgc3VwZXIobGVhZik7XG4gICAgdGhpcy5wbHVnaW4gPSBwbHVnaW47XG4gICAgdGhpcy5jaGF0TWFuYWdlciA9IG5ldyBDaGF0TWFuYWdlcigpO1xuICAgIHRoaXMud3NDbGllbnQgPSB0aGlzLnBsdWdpbi5jcmVhdGVXc0NsaWVudCh0aGlzLnBsdWdpbi5nZXREZWZhdWx0U2Vzc2lvbktleSgpKTtcblxuICAgIC8vIFdpcmUgaW5jb21pbmcgV1MgbWVzc2FnZXMgXHUyMTkyIENoYXRNYW5hZ2VyIChwZXItbGVhZilcbiAgICB0aGlzLndzQ2xpZW50Lm9uTWVzc2FnZSA9IChtc2cpID0+IHtcbiAgICAgIGlmIChtc2cudHlwZSA9PT0gJ21lc3NhZ2UnKSB7XG4gICAgICAgIHRoaXMuY2hhdE1hbmFnZXIuYWRkTWVzc2FnZShDaGF0TWFuYWdlci5jcmVhdGVBc3Npc3RhbnRNZXNzYWdlKG1zZy5wYXlsb2FkLmNvbnRlbnQpKTtcbiAgICAgIH0gZWxzZSBpZiAobXNnLnR5cGUgPT09ICdlcnJvcicpIHtcbiAgICAgICAgY29uc3QgZXJyVGV4dCA9IG1zZy5wYXlsb2FkLm1lc3NhZ2UgPz8gJ1Vua25vd24gZXJyb3IgZnJvbSBnYXRld2F5JztcbiAgICAgICAgdGhpcy5jaGF0TWFuYWdlci5hZGRNZXNzYWdlKENoYXRNYW5hZ2VyLmNyZWF0ZVN5c3RlbU1lc3NhZ2UoYFx1MjZBMCAke2VyclRleHR9YCwgJ2Vycm9yJykpO1xuICAgICAgfVxuICAgIH07XG4gIH1cblxuICBnZXRWaWV3VHlwZSgpOiBzdHJpbmcge1xuICAgIHJldHVybiBWSUVXX1RZUEVfT1BFTkNMQVdfQ0hBVDtcbiAgfVxuXG4gIGdldERpc3BsYXlUZXh0KCk6IHN0cmluZyB7XG4gICAgcmV0dXJuICdPcGVuQ2xhdyBDaGF0JztcbiAgfVxuXG4gIGdldEljb24oKTogc3RyaW5nIHtcbiAgICByZXR1cm4gJ21lc3NhZ2Utc3F1YXJlJztcbiAgfVxuXG4gIGFzeW5jIG9uT3BlbigpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICB0aGlzLnBsdWdpbi5yZWdpc3RlckNoYXRMZWFmKCk7XG4gICAgdGhpcy5fYnVpbGRVSSgpO1xuXG4gICAgLy8gRnVsbCByZS1yZW5kZXIgb24gY2xlYXIgLyByZWxvYWRcbiAgICB0aGlzLmNoYXRNYW5hZ2VyLm9uVXBkYXRlID0gKG1zZ3MpID0+IHRoaXMuX3JlbmRlck1lc3NhZ2VzKG1zZ3MpO1xuICAgIC8vIE8oMSkgYXBwZW5kIGZvciBuZXcgbWVzc2FnZXNcbiAgICB0aGlzLmNoYXRNYW5hZ2VyLm9uTWVzc2FnZUFkZGVkID0gKG1zZykgPT4gdGhpcy5fYXBwZW5kTWVzc2FnZShtc2cpO1xuXG4gICAgLy8gQ29ubmVjdCB0aGlzIGxlYWYncyBXUyBjbGllbnRcbiAgICBjb25zdCBndyA9IHRoaXMucGx1Z2luLmdldEdhdGV3YXlDb25maWcoKTtcbiAgICBpZiAoZ3cudG9rZW4pIHtcbiAgICAgIHRoaXMud3NDbGllbnQuY29ubmVjdChndy51cmwsIGd3LnRva2VuLCB7IGFsbG93SW5zZWN1cmVXczogZ3cuYWxsb3dJbnNlY3VyZVdzIH0pO1xuICAgIH0gZWxzZSB7XG4gICAgICBuZXcgTm90aWNlKCdPcGVuQ2xhdyBDaGF0OiBwbGVhc2UgY29uZmlndXJlIHlvdXIgZ2F0ZXdheSB0b2tlbiBpbiBTZXR0aW5ncy4nKTtcbiAgICB9XG5cbiAgICAvLyBTdWJzY3JpYmUgdG8gV1Mgc3RhdGUgY2hhbmdlc1xuICAgIHRoaXMud3NDbGllbnQub25TdGF0ZUNoYW5nZSA9IChzdGF0ZSkgPT4geyBcbiAgICAgIC8vIENvbm5lY3Rpb24gbG9zcyAvIHJlY29ubmVjdCBub3RpY2VzICh0aHJvdHRsZWQpXG4gICAgICBjb25zdCBwcmV2ID0gdGhpcy5sYXN0R2F0ZXdheVN0YXRlO1xuICAgICAgdGhpcy5sYXN0R2F0ZXdheVN0YXRlID0gc3RhdGU7XG5cbiAgICAgIGNvbnN0IG5vdyA9IERhdGUubm93KCk7XG4gICAgICBjb25zdCBOT1RJQ0VfVEhST1RUTEVfTVMgPSA2MF8wMDA7XG5cbiAgICAgIGNvbnN0IHNob3VsZE5vdGlmeSA9ICgpID0+IG5vdyAtIHRoaXMubGFzdENvbm5Ob3RpY2VBdE1zID4gTk9USUNFX1RIUk9UVExFX01TO1xuICAgICAgY29uc3Qgbm90aWZ5ID0gKHRleHQ6IHN0cmluZykgPT4ge1xuICAgICAgICBpZiAoIXNob3VsZE5vdGlmeSgpKSByZXR1cm47XG4gICAgICAgIHRoaXMubGFzdENvbm5Ob3RpY2VBdE1zID0gbm93O1xuICAgICAgICBuZXcgTm90aWNlKHRleHQpO1xuICAgICAgfTtcblxuICAgICAgLy8gT25seSBzaG93IFx1MjAxQ2xvc3RcdTIwMUQgaWYgd2Ugd2VyZSBwcmV2aW91c2x5IGNvbm5lY3RlZC5cbiAgICAgIGlmIChwcmV2ID09PSAnY29ubmVjdGVkJyAmJiBzdGF0ZSA9PT0gJ2Rpc2Nvbm5lY3RlZCcpIHtcbiAgICAgICAgbm90aWZ5KCdPcGVuQ2xhdyBDaGF0OiBjb25uZWN0aW9uIGxvc3QgXHUyMDE0IHJlY29ubmVjdGluZ1x1MjAyNicpO1xuICAgICAgICAvLyBBbHNvIGFwcGVuZCBhIHN5c3RlbSBtZXNzYWdlIHNvIGl0XHUyMDE5cyB2aXNpYmxlIGluIHRoZSBjaGF0IGhpc3RvcnkuXG4gICAgICAgIHRoaXMuY2hhdE1hbmFnZXIuYWRkTWVzc2FnZShDaGF0TWFuYWdlci5jcmVhdGVTeXN0ZW1NZXNzYWdlKCdcdTI2QTAgQ29ubmVjdGlvbiBsb3N0IFx1MjAxNCByZWNvbm5lY3RpbmdcdTIwMjYnLCAnZXJyb3InKSk7XG4gICAgICB9XG5cbiAgICAgIC8vIE9wdGlvbmFsIFx1MjAxQ3JlY29ubmVjdGVkXHUyMDFEIG5vdGljZVxuICAgICAgaWYgKHByZXYgJiYgcHJldiAhPT0gJ2Nvbm5lY3RlZCcgJiYgc3RhdGUgPT09ICdjb25uZWN0ZWQnKSB7XG4gICAgICAgIG5vdGlmeSgnT3BlbkNsYXcgQ2hhdDogcmVjb25uZWN0ZWQnKTtcbiAgICAgICAgdGhpcy5jaGF0TWFuYWdlci5hZGRNZXNzYWdlKENoYXRNYW5hZ2VyLmNyZWF0ZVN5c3RlbU1lc3NhZ2UoJ1x1MjcwNSBSZWNvbm5lY3RlZCcsICdpbmZvJykpO1xuICAgICAgfVxuXG4gICAgICB0aGlzLmlzQ29ubmVjdGVkID0gc3RhdGUgPT09ICdjb25uZWN0ZWQnO1xuICAgICAgdGhpcy5zdGF0dXNEb3QudG9nZ2xlQ2xhc3MoJ2Nvbm5lY3RlZCcsIHRoaXMuaXNDb25uZWN0ZWQpO1xuICAgICAgdGhpcy5zdGF0dXNEb3QudGl0bGUgPSBgR2F0ZXdheTogJHtzdGF0ZX1gO1xuICAgICAgdGhpcy5fdXBkYXRlU2VuZEJ1dHRvbigpO1xuICAgIH07XG5cbiAgICAvLyBTdWJzY3JpYmUgdG8gXHUyMDFDd29ya2luZ1x1MjAxRCAocmVxdWVzdC1pbi1mbGlnaHQpIHN0YXRlXG4gICAgdGhpcy53c0NsaWVudC5vbldvcmtpbmdDaGFuZ2UgPSAod29ya2luZykgPT4ge1xuICAgICAgdGhpcy5pc1dvcmtpbmcgPSB3b3JraW5nO1xuICAgICAgdGhpcy5fdXBkYXRlU2VuZEJ1dHRvbigpO1xuICAgIH07XG5cbiAgICAvLyBSZWZsZWN0IGN1cnJlbnQgc3RhdGVcbiAgICB0aGlzLmxhc3RHYXRld2F5U3RhdGUgPSB0aGlzLndzQ2xpZW50LnN0YXRlO1xuICAgIHRoaXMuaXNDb25uZWN0ZWQgPSB0aGlzLndzQ2xpZW50LnN0YXRlID09PSAnY29ubmVjdGVkJztcbiAgICB0aGlzLnN0YXR1c0RvdC50b2dnbGVDbGFzcygnY29ubmVjdGVkJywgdGhpcy5pc0Nvbm5lY3RlZCk7XG4gICAgdGhpcy5zdGF0dXNEb3QudGl0bGUgPSBgR2F0ZXdheTogJHt0aGlzLndzQ2xpZW50LnN0YXRlfWA7XG4gICAgdGhpcy5fdXBkYXRlU2VuZEJ1dHRvbigpO1xuXG4gICAgdGhpcy5fcmVuZGVyTWVzc2FnZXModGhpcy5jaGF0TWFuYWdlci5nZXRNZXNzYWdlcygpKTtcblxuICAgIC8vIExvYWQgc2Vzc2lvbiBkcm9wZG93biBmcm9tIGxvY2FsIHZhdWx0LXNjb3BlZCBrbm93biBzZXNzaW9ucy5cbiAgICB0aGlzLl9sb2FkS25vd25TZXNzaW9ucygpO1xuICB9XG5cbiAgYXN5bmMgb25DbG9zZSgpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICB0aGlzLnBsdWdpbi51bnJlZ2lzdGVyQ2hhdExlYWYoKTtcbiAgICB0aGlzLmNoYXRNYW5hZ2VyLm9uVXBkYXRlID0gbnVsbDtcbiAgICB0aGlzLmNoYXRNYW5hZ2VyLm9uTWVzc2FnZUFkZGVkID0gbnVsbDtcbiAgICB0aGlzLndzQ2xpZW50Lm9uU3RhdGVDaGFuZ2UgPSBudWxsO1xuICAgIHRoaXMud3NDbGllbnQub25Xb3JraW5nQ2hhbmdlID0gbnVsbDtcbiAgICB0aGlzLndzQ2xpZW50LmRpc2Nvbm5lY3QoKTtcblxuICAgIC8vIChyZW1vdmVkKSBpbnRlcm5hbC1saW5rIGRlbGVnYXRpb24gY2xlYW51cFxuICB9XG5cbiAgLy8gXHUyNTAwXHUyNTAwIFVJIGNvbnN0cnVjdGlvbiBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcblxuICBwcml2YXRlIF9idWlsZFVJKCk6IHZvaWQge1xuICAgIGNvbnN0IHJvb3QgPSB0aGlzLmNvbnRlbnRFbDtcbiAgICByb290LmVtcHR5KCk7XG4gICAgcm9vdC5hZGRDbGFzcygnb2NsYXctY2hhdC12aWV3Jyk7XG5cbiAgICAvLyBcdTI1MDBcdTI1MDAgSGVhZGVyIFx1MjUwMFx1MjUwMFxuICAgIGNvbnN0IGhlYWRlciA9IHJvb3QuY3JlYXRlRGl2KHsgY2xzOiAnb2NsYXctaGVhZGVyJyB9KTtcbiAgICBoZWFkZXIuY3JlYXRlU3Bhbih7IGNsczogJ29jbGF3LWhlYWRlci10aXRsZScsIHRleHQ6ICdPcGVuQ2xhdyBDaGF0JyB9KTtcbiAgICB0aGlzLnN0YXR1c0RvdCA9IGhlYWRlci5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1zdGF0dXMtZG90JyB9KTtcbiAgICB0aGlzLnN0YXR1c0RvdC50aXRsZSA9ICdHYXRld2F5OiBkaXNjb25uZWN0ZWQnO1xuXG4gICAgLy8gXHUyNTAwXHUyNTAwIFNlc3Npb24gcm93IFx1MjUwMFx1MjUwMFxuICAgIGNvbnN0IHNlc3NSb3cgPSByb290LmNyZWF0ZURpdih7IGNsczogJ29jbGF3LXNlc3Npb24tcm93JyB9KTtcbiAgICBzZXNzUm93LmNyZWF0ZVNwYW4oeyBjbHM6ICdvY2xhdy1zZXNzaW9uLWxhYmVsJywgdGV4dDogJ1Nlc3Npb24nIH0pO1xuXG4gICAgdGhpcy5zZXNzaW9uU2VsZWN0ID0gc2Vzc1Jvdy5jcmVhdGVFbCgnc2VsZWN0JywgeyBjbHM6ICdvY2xhdy1zZXNzaW9uLXNlbGVjdCcgfSk7XG4gICAgdGhpcy5zZXNzaW9uUmVmcmVzaEJ0biA9IHNlc3NSb3cuY3JlYXRlRWwoJ2J1dHRvbicsIHsgY2xzOiAnb2NsYXctc2Vzc2lvbi1idG4nLCB0ZXh0OiAnUmVsb2FkJyB9KTtcbiAgICB0aGlzLnNlc3Npb25OZXdCdG4gPSBzZXNzUm93LmNyZWF0ZUVsKCdidXR0b24nLCB7IGNsczogJ29jbGF3LXNlc3Npb24tYnRuJywgdGV4dDogJ05ld1x1MjAyNicgfSk7XG4gICAgdGhpcy5zZXNzaW9uTWFpbkJ0biA9IHNlc3NSb3cuY3JlYXRlRWwoJ2J1dHRvbicsIHsgY2xzOiAnb2NsYXctc2Vzc2lvbi1idG4nLCB0ZXh0OiAnTWFpbicgfSk7XG5cbiAgICB0aGlzLnNlc3Npb25SZWZyZXNoQnRuLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gdGhpcy5fbG9hZEtub3duU2Vzc2lvbnMoKSk7XG4gICAgdGhpcy5zZXNzaW9uTmV3QnRuLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4ge1xuICAgICAgaWYgKCF0aGlzLnBsdWdpbi5nZXRWYXVsdEhhc2goKSkge1xuICAgICAgICBuZXcgTm90aWNlKCdPcGVuQ2xhdyBDaGF0OiBOZXcgc2Vzc2lvbiBpcyB1bmF2YWlsYWJsZSAobWlzc2luZyB2YXVsdCBpZGVudGl0eSkuJyk7XG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cbiAgICAgIHZvaWQgdGhpcy5fcHJvbXB0TmV3U2Vzc2lvbigpO1xuICAgIH0pO1xuICAgIHRoaXMuc2Vzc2lvbk1haW5CdG4uYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKSA9PiB7XG4gICAgICB2b2lkIChhc3luYyAoKSA9PiB7XG4gICAgICAgIGF3YWl0IHRoaXMuX3N3aXRjaFNlc3Npb24oJ21haW4nKTtcbiAgICAgICAgdGhpcy5fbG9hZEtub3duU2Vzc2lvbnMoKTtcbiAgICAgICAgdGhpcy5zZXNzaW9uU2VsZWN0LnZhbHVlID0gJ21haW4nO1xuICAgICAgICB0aGlzLnNlc3Npb25TZWxlY3QudGl0bGUgPSAnbWFpbic7XG4gICAgICB9KSgpO1xuICAgIH0pO1xuICAgIHRoaXMuc2Vzc2lvblNlbGVjdC5hZGRFdmVudExpc3RlbmVyKCdjaGFuZ2UnLCAoKSA9PiB7XG4gICAgICBpZiAodGhpcy5zdXBwcmVzc1Nlc3Npb25TZWxlY3RDaGFuZ2UpIHJldHVybjtcbiAgICAgIGNvbnN0IG5leHQgPSB0aGlzLnNlc3Npb25TZWxlY3QudmFsdWU7XG4gICAgICBpZiAoIW5leHQpIHJldHVybjtcbiAgICAgIHZvaWQgKGFzeW5jICgpID0+IHtcbiAgICAgICAgYXdhaXQgdGhpcy5fc3dpdGNoU2Vzc2lvbihuZXh0KTtcbiAgICAgICAgdGhpcy5fbG9hZEtub3duU2Vzc2lvbnMoKTtcbiAgICAgICAgdGhpcy5zZXNzaW9uU2VsZWN0LnZhbHVlID0gbmV4dDtcbiAgICAgICAgdGhpcy5zZXNzaW9uU2VsZWN0LnRpdGxlID0gbmV4dDtcbiAgICAgIH0pKCk7XG4gICAgfSk7XG5cbiAgICAvLyBcdTI1MDBcdTI1MDAgTWVzc2FnZXMgYXJlYSBcdTI1MDBcdTI1MDBcbiAgICB0aGlzLm1lc3NhZ2VzRWwgPSByb290LmNyZWF0ZURpdih7IGNsczogJ29jbGF3LW1lc3NhZ2VzJyB9KTtcblxuICAgIC8vIE5vdGU6IG1hcmtkb3duLW1vZGUgbGlua2lmeSBpcyBoYW5kbGVkIHBvc3QtcmVuZGVyIHZpYSBfcG9zdHByb2Nlc3NBc3Npc3RhbnRMaW5rcy5cbiAgICAvLyBXZSBubyBsb25nZXIgcmVseSBvbiBpbnRlcm5hbC1saW5rIGNsaWNrIGRlbGVnYXRpb24uXG5cblxuICAgIC8vIFx1MjUwMFx1MjUwMCBDb250ZXh0IHJvdyBcdTI1MDBcdTI1MDBcbiAgICBjb25zdCBjdHhSb3cgPSByb290LmNyZWF0ZURpdih7IGNsczogJ29jbGF3LWNvbnRleHQtcm93JyB9KTtcbiAgICB0aGlzLmluY2x1ZGVOb3RlQ2hlY2tib3ggPSBjdHhSb3cuY3JlYXRlRWwoJ2lucHV0JywgeyB0eXBlOiAnY2hlY2tib3gnIH0pO1xuICAgIHRoaXMuaW5jbHVkZU5vdGVDaGVja2JveC5pZCA9ICdvY2xhdy1pbmNsdWRlLW5vdGUnO1xuICAgIHRoaXMuaW5jbHVkZU5vdGVDaGVja2JveC5jaGVja2VkID0gdGhpcy5wbHVnaW4uc2V0dGluZ3MuaW5jbHVkZUFjdGl2ZU5vdGU7XG4gICAgY29uc3QgY3R4TGFiZWwgPSBjdHhSb3cuY3JlYXRlRWwoJ2xhYmVsJywgeyB0ZXh0OiAnSW5jbHVkZSBhY3RpdmUgbm90ZScgfSk7XG4gICAgY3R4TGFiZWwuaHRtbEZvciA9ICdvY2xhdy1pbmNsdWRlLW5vdGUnO1xuXG4gICAgLy8gXHUyNTAwXHUyNTAwIElucHV0IHJvdyBcdTI1MDBcdTI1MDBcbiAgICBjb25zdCBpbnB1dFJvdyA9IHJvb3QuY3JlYXRlRGl2KHsgY2xzOiAnb2NsYXctaW5wdXQtcm93JyB9KTtcbiAgICB0aGlzLmlucHV0RWwgPSBpbnB1dFJvdy5jcmVhdGVFbCgndGV4dGFyZWEnLCB7XG4gICAgICBjbHM6ICdvY2xhdy1pbnB1dCcsXG4gICAgICBwbGFjZWhvbGRlcjogJ0FzayBhbnl0aGluZ1x1MjAyNicsXG4gICAgfSk7XG4gICAgdGhpcy5pbnB1dEVsLnJvd3MgPSAxO1xuXG4gICAgdGhpcy5zZW5kQnRuID0gaW5wdXRSb3cuY3JlYXRlRWwoJ2J1dHRvbicsIHsgY2xzOiAnb2NsYXctc2VuZC1idG4nLCB0ZXh0OiAnU2VuZCcgfSk7XG5cbiAgICAvLyBcdTI1MDBcdTI1MDAgRXZlbnQgbGlzdGVuZXJzIFx1MjUwMFx1MjUwMFxuICAgIHRoaXMuc2VuZEJ0bi5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpID0+IHRoaXMuX2hhbmRsZVNlbmQoKSk7XG4gICAgdGhpcy5pbnB1dEVsLmFkZEV2ZW50TGlzdGVuZXIoJ2tleWRvd24nLCAoZSkgPT4ge1xuICAgICAgaWYgKGUua2V5ID09PSAnRW50ZXInICYmICFlLnNoaWZ0S2V5KSB7XG4gICAgICAgIGUucHJldmVudERlZmF1bHQoKTtcbiAgICAgICAgdGhpcy5faGFuZGxlU2VuZCgpO1xuICAgICAgfVxuICAgIH0pO1xuICAgIC8vIEF1dG8tcmVzaXplIHRleHRhcmVhXG4gICAgdGhpcy5pbnB1dEVsLmFkZEV2ZW50TGlzdGVuZXIoJ2lucHV0JywgKCkgPT4ge1xuICAgICAgdGhpcy5pbnB1dEVsLnN0eWxlLmhlaWdodCA9ICdhdXRvJztcbiAgICAgIHRoaXMuaW5wdXRFbC5zdHlsZS5oZWlnaHQgPSBgJHt0aGlzLmlucHV0RWwuc2Nyb2xsSGVpZ2h0fXB4YDtcbiAgICB9KTtcbiAgfVxuXG4gIHByaXZhdGUgX3NldFNlc3Npb25TZWxlY3RPcHRpb25zKGtleXM6IHN0cmluZ1tdKTogdm9pZCB7XG4gICAgdGhpcy5zdXBwcmVzc1Nlc3Npb25TZWxlY3RDaGFuZ2UgPSB0cnVlO1xuICAgIHRyeSB7XG4gICAgICB0aGlzLnNlc3Npb25TZWxlY3QuZW1wdHkoKTtcblxuICAgICAgY29uc3QgY3VycmVudCA9ICh0aGlzLnBsdWdpbi5zZXR0aW5ncy5zZXNzaW9uS2V5ID8/ICdtYWluJykudG9Mb3dlckNhc2UoKTtcbiAgICAgIGxldCB1bmlxdWUgPSBBcnJheS5mcm9tKG5ldyBTZXQoW2N1cnJlbnQsIC4uLmtleXNdLmZpbHRlcihCb29sZWFuKSkpO1xuXG4gICAgICAvLyBDYW5vbmljYWwtb25seTogbWFpbiBvciBhZ2VudDptYWluOm9ic2lkaWFuOmRpcmVjdDoqXG4gICAgICB1bmlxdWUgPSB1bmlxdWUuZmlsdGVyKChrKSA9PiBrID09PSAnbWFpbicgfHwgU3RyaW5nKGspLnN0YXJ0c1dpdGgoJ2FnZW50Om1haW46b2JzaWRpYW46ZGlyZWN0OicpKTtcblxuICAgICAgaWYgKHVuaXF1ZS5sZW5ndGggPT09IDApIHtcbiAgICAgICAgdW5pcXVlID0gWydtYWluJ107XG4gICAgICB9XG5cbiAgICAgIGZvciAoY29uc3Qga2V5IG9mIHVuaXF1ZSkge1xuICAgICAgICBjb25zdCBvcHQgPSB0aGlzLnNlc3Npb25TZWxlY3QuY3JlYXRlRWwoJ29wdGlvbicsIHsgdmFsdWU6IGtleSwgdGV4dDoga2V5IH0pO1xuICAgICAgICBpZiAoa2V5ID09PSBjdXJyZW50KSBvcHQuc2VsZWN0ZWQgPSB0cnVlO1xuICAgICAgfVxuXG4gICAgICBpZiAodW5pcXVlLmluY2x1ZGVzKGN1cnJlbnQpKSB7XG4gICAgICAgIHRoaXMuc2Vzc2lvblNlbGVjdC52YWx1ZSA9IGN1cnJlbnQ7XG4gICAgICB9XG4gICAgICB0aGlzLnNlc3Npb25TZWxlY3QudGl0bGUgPSBjdXJyZW50O1xuICAgIH0gZmluYWxseSB7XG4gICAgICB0aGlzLnN1cHByZXNzU2Vzc2lvblNlbGVjdENoYW5nZSA9IGZhbHNlO1xuICAgIH1cbiAgfVxuXG4gIHByaXZhdGUgX2xvYWRLbm93blNlc3Npb25zKCk6IHZvaWQge1xuICAgIGNvbnN0IHZhdWx0SGFzaCA9ICh0aGlzLnBsdWdpbi5zZXR0aW5ncy52YXVsdEhhc2ggPz8gJycpLnRyaW0oKTtcbiAgICBjb25zdCBtYXAgPSB0aGlzLnBsdWdpbi5zZXR0aW5ncy5rbm93blNlc3Npb25LZXlzQnlWYXVsdCA/PyB7fTtcbiAgICBjb25zdCBrZXlzID0gdmF1bHRIYXNoICYmIEFycmF5LmlzQXJyYXkobWFwW3ZhdWx0SGFzaF0pID8gbWFwW3ZhdWx0SGFzaF0gOiBbXTtcblxuICAgIGNvbnN0IHByZWZpeCA9IHZhdWx0SGFzaCA/IGBhZ2VudDptYWluOm9ic2lkaWFuOmRpcmVjdDoke3ZhdWx0SGFzaH1gIDogJyc7XG4gICAgY29uc3QgZmlsdGVyZWQgPSB2YXVsdEhhc2hcbiAgICAgID8ga2V5cy5maWx0ZXIoKGspID0+IHtcbiAgICAgICAgICBjb25zdCBrZXkgPSBTdHJpbmcoayB8fCAnJykudHJpbSgpLnRvTG93ZXJDYXNlKCk7XG4gICAgICAgICAgcmV0dXJuIGtleSA9PT0gcHJlZml4IHx8IGtleS5zdGFydHNXaXRoKHByZWZpeCArICctJyk7XG4gICAgICAgIH0pXG4gICAgICA6IFtdO1xuXG4gICAgdGhpcy5fc2V0U2Vzc2lvblNlbGVjdE9wdGlvbnMoZmlsdGVyZWQpO1xuICB9XG5cbiAgcHJpdmF0ZSBhc3luYyBfc3dpdGNoU2Vzc2lvbihzZXNzaW9uS2V5OiBzdHJpbmcpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBjb25zdCBuZXh0ID0gc2Vzc2lvbktleS50cmltKCkudG9Mb3dlckNhc2UoKTtcbiAgICBpZiAoIW5leHQpIHJldHVybjtcblxuICAgIGNvbnN0IHZhdWx0SGFzaCA9IHRoaXMucGx1Z2luLmdldFZhdWx0SGFzaCgpO1xuICAgIGlmICh2YXVsdEhhc2gpIHtcbiAgICAgIGNvbnN0IHByZWZpeCA9IGBhZ2VudDptYWluOm9ic2lkaWFuOmRpcmVjdDoke3ZhdWx0SGFzaH1gO1xuICAgICAgaWYgKCEobmV4dCA9PT0gJ21haW4nIHx8IG5leHQgPT09IHByZWZpeCB8fCBuZXh0LnN0YXJ0c1dpdGgocHJlZml4ICsgJy0nKSkpIHtcbiAgICAgICAgbmV3IE5vdGljZSgnT3BlbkNsYXcgQ2hhdDogc2Vzc2lvbiBrZXkgbXVzdCBtYXRjaCB0aGlzIHZhdWx0LicpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG4gICAgfSBlbHNlIHtcbiAgICAgIGlmIChuZXh0ICE9PSAnbWFpbicpIHtcbiAgICAgICAgbmV3IE5vdGljZSgnT3BlbkNsYXcgQ2hhdDogY2Fubm90IHN3aXRjaCBzZXNzaW9ucyAobWlzc2luZyB2YXVsdCBpZGVudGl0eSkuJyk7XG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cbiAgICB9XG5cbiAgICAvLyBBYm9ydCBhbnkgaW4tZmxpZ2h0IHJ1biBiZXN0LWVmZm9ydC5cbiAgICB0cnkge1xuICAgICAgYXdhaXQgdGhpcy53c0NsaWVudC5hYm9ydEFjdGl2ZVJ1bigpO1xuICAgIH0gY2F0Y2gge1xuICAgICAgLy8gaWdub3JlXG4gICAgfVxuXG4gICAgLy8gRGl2aWRlciBpbiB0aGlzIGxlYWYgb25seS5cbiAgICB0aGlzLmNoYXRNYW5hZ2VyLmFkZE1lc3NhZ2UoQ2hhdE1hbmFnZXIuY3JlYXRlU2Vzc2lvbkRpdmlkZXIobmV4dCkpO1xuXG4gICAgLy8gUGVyc2lzdCBhcyB0aGUgZGVmYXVsdCBhbmQgcmVtZW1iZXIgaXQgaW4gdGhlIHZhdWx0LXNjb3BlZCBsaXN0LlxuICAgIGF3YWl0IHRoaXMucGx1Z2luLnJlbWVtYmVyU2Vzc2lvbktleShuZXh0KTtcblxuICAgIC8vIFN3aXRjaCBXUyByb3V0aW5nIGZvciB0aGlzIGxlYWYuXG4gICAgdGhpcy53c0NsaWVudC5kaXNjb25uZWN0KCk7XG4gICAgdGhpcy53c0NsaWVudC5zZXRTZXNzaW9uS2V5KG5leHQpO1xuXG4gICAgY29uc3QgZ3cgPSB0aGlzLnBsdWdpbi5nZXRHYXRld2F5Q29uZmlnKCk7XG4gICAgaWYgKGd3LnRva2VuKSB7XG4gICAgICB0aGlzLndzQ2xpZW50LmNvbm5lY3QoZ3cudXJsLCBndy50b2tlbiwgeyBhbGxvd0luc2VjdXJlV3M6IGd3LmFsbG93SW5zZWN1cmVXcyB9KTtcbiAgICB9IGVsc2Uge1xuICAgICAgbmV3IE5vdGljZSgnT3BlbkNsYXcgQ2hhdDogcGxlYXNlIGNvbmZpZ3VyZSB5b3VyIGdhdGV3YXkgdG9rZW4gaW4gU2V0dGluZ3MuJyk7XG4gICAgfVxuICB9XG5cbiAgcHJpdmF0ZSBhc3luYyBfcHJvbXB0TmV3U2Vzc2lvbigpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBjb25zdCBub3cgPSBuZXcgRGF0ZSgpO1xuICAgIGNvbnN0IHBhZCA9IChuOiBudW1iZXIpID0+IFN0cmluZyhuKS5wYWRTdGFydCgyLCAnMCcpO1xuICAgIGNvbnN0IHN1Z2dlc3RlZCA9IGBjaGF0LSR7bm93LmdldEZ1bGxZZWFyKCl9JHtwYWQobm93LmdldE1vbnRoKCkgKyAxKX0ke3BhZChub3cuZ2V0RGF0ZSgpKX0tJHtwYWQobm93LmdldEhvdXJzKCkpfSR7cGFkKG5vdy5nZXRNaW51dGVzKCkpfWA7XG5cbiAgICBjb25zdCBtb2RhbCA9IG5ldyBOZXdTZXNzaW9uTW9kYWwodGhpcywgc3VnZ2VzdGVkLCAoc3VmZml4KSA9PiB7XG4gICAgICBjb25zdCB2YXVsdEhhc2ggPSAodGhpcy5wbHVnaW4uc2V0dGluZ3MudmF1bHRIYXNoID8/ICcnKS50cmltKCk7XG4gICAgICBpZiAoIXZhdWx0SGFzaCkge1xuICAgICAgICBuZXcgTm90aWNlKCdPcGVuQ2xhdyBDaGF0OiBjYW5ub3QgY3JlYXRlIHNlc3Npb24gKG1pc3NpbmcgdmF1bHQgaWRlbnRpdHkpLicpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG4gICAgICBjb25zdCBrZXkgPSBgYWdlbnQ6bWFpbjpvYnNpZGlhbjpkaXJlY3Q6JHt2YXVsdEhhc2h9LSR7c3VmZml4fWA7XG4gICAgICB2b2lkIChhc3luYyAoKSA9PiB7XG4gICAgICAgIGF3YWl0IHRoaXMuX3N3aXRjaFNlc3Npb24oa2V5KTtcbiAgICAgICAgdGhpcy5fbG9hZEtub3duU2Vzc2lvbnMoKTtcbiAgICAgICAgdGhpcy5zZXNzaW9uU2VsZWN0LnZhbHVlID0ga2V5O1xuICAgICAgICB0aGlzLnNlc3Npb25TZWxlY3QudGl0bGUgPSBrZXk7XG4gICAgICB9KSgpO1xuICAgIH0pO1xuICAgIG1vZGFsLm9wZW4oKTtcbiAgfVxuXG4gIC8vIFx1MjUwMFx1MjUwMCBNZXNzYWdlIHJlbmRlcmluZyBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcblxuICBwcml2YXRlIF9yZW5kZXJNZXNzYWdlcyhtZXNzYWdlczogcmVhZG9ubHkgQ2hhdE1lc3NhZ2VbXSk6IHZvaWQge1xuICAgIHRoaXMubWVzc2FnZXNFbC5lbXB0eSgpO1xuXG4gICAgaWYgKG1lc3NhZ2VzLmxlbmd0aCA9PT0gMCkge1xuICAgICAgdGhpcy5tZXNzYWdlc0VsLmNyZWF0ZUVsKCdwJywge1xuICAgICAgICB0ZXh0OiAnU2VuZCBhIG1lc3NhZ2UgdG8gc3RhcnQgY2hhdHRpbmcuJyxcbiAgICAgICAgY2xzOiAnb2NsYXctbWVzc2FnZSBzeXN0ZW0gb2NsYXctcGxhY2Vob2xkZXInLFxuICAgICAgfSk7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgZm9yIChjb25zdCBtc2cgb2YgbWVzc2FnZXMpIHtcbiAgICAgIHRoaXMuX2FwcGVuZE1lc3NhZ2UobXNnKTtcbiAgICB9XG5cbiAgICAvLyBTY3JvbGwgdG8gYm90dG9tXG4gICAgdGhpcy5tZXNzYWdlc0VsLnNjcm9sbFRvcCA9IHRoaXMubWVzc2FnZXNFbC5zY3JvbGxIZWlnaHQ7XG4gIH1cblxuICAvKiogQXBwZW5kcyBhIHNpbmdsZSBtZXNzYWdlIHdpdGhvdXQgcmVidWlsZGluZyB0aGUgRE9NIChPKDEpKSAqL1xuICBwcml2YXRlIF9hcHBlbmRNZXNzYWdlKG1zZzogQ2hhdE1lc3NhZ2UpOiB2b2lkIHtcbiAgICAvLyBSZW1vdmUgZW1wdHktc3RhdGUgcGxhY2Vob2xkZXIgaWYgcHJlc2VudFxuICAgIHRoaXMubWVzc2FnZXNFbC5xdWVyeVNlbGVjdG9yKCcub2NsYXctcGxhY2Vob2xkZXInKT8ucmVtb3ZlKCk7XG5cbiAgICBjb25zdCBsZXZlbENsYXNzID0gbXNnLmxldmVsID8gYCAke21zZy5sZXZlbH1gIDogJyc7XG4gICAgY29uc3Qga2luZENsYXNzID0gbXNnLmtpbmQgPyBgIG9jbGF3LSR7bXNnLmtpbmR9YCA6ICcnO1xuICAgIGNvbnN0IGVsID0gdGhpcy5tZXNzYWdlc0VsLmNyZWF0ZURpdih7IGNsczogYG9jbGF3LW1lc3NhZ2UgJHttc2cucm9sZX0ke2xldmVsQ2xhc3N9JHtraW5kQ2xhc3N9YCB9KTtcbiAgICBjb25zdCBib2R5ID0gZWwuY3JlYXRlRGl2KHsgY2xzOiAnb2NsYXctbWVzc2FnZS1ib2R5JyB9KTtcbiAgICBpZiAobXNnLnRpdGxlKSB7XG4gICAgICBib2R5LnRpdGxlID0gbXNnLnRpdGxlO1xuICAgIH1cblxuICAgIC8vIFRyZWF0IGFzc2lzdGFudCBvdXRwdXQgYXMgVU5UUlVTVEVEIGJ5IGRlZmF1bHQuXG4gICAgLy8gUmVuZGVyaW5nIGFzIE9ic2lkaWFuIE1hcmtkb3duIGNhbiB0cmlnZ2VyIGVtYmVkcyBhbmQgb3RoZXIgcGx1Z2lucycgcG9zdC1wcm9jZXNzb3JzLlxuICAgIGlmIChtc2cucm9sZSA9PT0gJ2Fzc2lzdGFudCcpIHtcbiAgICAgIGNvbnN0IG1hcHBpbmdzOiBQYXRoTWFwcGluZ1tdID0gdGhpcy5wbHVnaW4uc2V0dGluZ3MucGF0aE1hcHBpbmdzID8/IFtdO1xuICAgICAgY29uc3Qgc291cmNlUGF0aCA9IHRoaXMuYXBwLndvcmtzcGFjZS5nZXRBY3RpdmVGaWxlKCk/LnBhdGggPz8gJyc7XG5cbiAgICAgIGlmICh0aGlzLnBsdWdpbi5zZXR0aW5ncy5yZW5kZXJBc3Npc3RhbnRNYXJrZG93bikge1xuICAgICAgICAvLyBCZXN0LWVmZm9ydCBwcmUtcHJvY2Vzc2luZzogcmVwbGFjZSBrbm93biByZW1vdGUgcGF0aHMgd2l0aCB3aWtpbGlua3Mgd2hlbiB0aGUgdGFyZ2V0IGV4aXN0cy5cbiAgICAgICAgY29uc3QgcHJlID0gdGhpcy5fcHJlcHJvY2Vzc0Fzc2lzdGFudE1hcmtkb3duKG1zZy5jb250ZW50LCBtYXBwaW5ncyk7XG4gICAgICAgIHZvaWQgTWFya2Rvd25SZW5kZXJlci5yZW5kZXJNYXJrZG93bihwcmUsIGJvZHksIHNvdXJjZVBhdGgsIHRoaXMucGx1Z2luKS50aGVuKCgpID0+IHtcbiAgICAgICAgICB0aGlzLl9wb3N0cHJvY2Vzc0Fzc2lzdGFudExpbmtzKGJvZHksIG1zZy5jb250ZW50LCBtYXBwaW5ncywgc291cmNlUGF0aCk7XG4gICAgICAgIH0pO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgLy8gUGxhaW4gbW9kZTogYnVpbGQgc2FmZSwgY2xpY2thYmxlIGxpbmtzIGluIERPTSAobm8gTWFya2Rvd24gcmVuZGVyaW5nKS5cbiAgICAgICAgdGhpcy5fcmVuZGVyQXNzaXN0YW50UGxhaW5XaXRoTGlua3MoYm9keSwgbXNnLmNvbnRlbnQsIG1hcHBpbmdzLCBzb3VyY2VQYXRoKTtcbiAgICAgIH1cbiAgICB9IGVsc2Uge1xuICAgICAgYm9keS5zZXRUZXh0KG1zZy5jb250ZW50KTtcbiAgICB9XG5cbiAgICAvLyBTY3JvbGwgdG8gYm90dG9tXG4gICAgdGhpcy5tZXNzYWdlc0VsLnNjcm9sbFRvcCA9IHRoaXMubWVzc2FnZXNFbC5zY3JvbGxIZWlnaHQ7XG4gIH1cblxuICBwcml2YXRlIF90cnlSZXZlcnNlTWFwVXJsVG9WYXVsdFBhdGgodXJsOiBzdHJpbmcsIG1hcHBpbmdzOiBQYXRoTWFwcGluZ1tdKTogc3RyaW5nIHwgbnVsbCB7XG4gICAgLy8gRlMtYmFzZWQgbWFwcGluZzsgYmVzdC1lZmZvcnQgb25seS5cbiAgICBsZXQgZGVjb2RlZCA9IHVybDtcbiAgICB0cnkge1xuICAgICAgZGVjb2RlZCA9IGRlY29kZVVSSUNvbXBvbmVudCh1cmwpO1xuICAgIH0gY2F0Y2gge1xuICAgICAgLy8gaWdub3JlXG4gICAgfVxuXG4gICAgLy8gSWYgdGhlIGRlY29kZWQgVVJMIGNvbnRhaW5zIGEgcmVtb3RlQmFzZSBzdWJzdHJpbmcsIHRyeSBtYXBwaW5nIGZyb20gdGhhdCBwb2ludC5cbiAgICBmb3IgKGNvbnN0IHJvdyBvZiBtYXBwaW5ncykge1xuICAgICAgY29uc3QgcmVtb3RlQmFzZSA9IFN0cmluZyhyb3cucmVtb3RlQmFzZSA/PyAnJyk7XG4gICAgICBpZiAoIXJlbW90ZUJhc2UpIGNvbnRpbnVlO1xuICAgICAgY29uc3QgaWR4ID0gZGVjb2RlZC5pbmRleE9mKHJlbW90ZUJhc2UpO1xuICAgICAgaWYgKGlkeCA8IDApIGNvbnRpbnVlO1xuXG4gICAgICAvLyBFeHRyYWN0IGZyb20gcmVtb3RlQmFzZSBvbndhcmQgdW50aWwgYSB0ZXJtaW5hdG9yLlxuICAgICAgY29uc3QgdGFpbCA9IGRlY29kZWQuc2xpY2UoaWR4KTtcbiAgICAgIGNvbnN0IHRva2VuID0gdGFpbC5zcGxpdCgvW1xccydcIjw+KV0vKVswXTtcbiAgICAgIGNvbnN0IG1hcHBlZCA9IHRyeU1hcFJlbW90ZVBhdGhUb1ZhdWx0UGF0aCh0b2tlbiwgbWFwcGluZ3MpO1xuICAgICAgaWYgKG1hcHBlZCAmJiB0aGlzLmFwcC52YXVsdC5nZXRBYnN0cmFjdEZpbGVCeVBhdGgobWFwcGVkKSkgcmV0dXJuIG1hcHBlZDtcbiAgICB9XG5cbiAgICByZXR1cm4gbnVsbDtcbiAgfVxuXG4gIHByaXZhdGUgX3RyeU1hcFZhdWx0UmVsYXRpdmVUb2tlbih0b2tlbjogc3RyaW5nLCBtYXBwaW5nczogUGF0aE1hcHBpbmdbXSk6IHN0cmluZyB8IG51bGwge1xuICAgIGNvbnN0IHQgPSB0b2tlbi5yZXBsYWNlKC9eXFwvKy8sICcnKTtcbiAgICBpZiAodGhpcy5hcHAudmF1bHQuZ2V0QWJzdHJhY3RGaWxlQnlQYXRoKHQpKSByZXR1cm4gdDtcblxuICAgIC8vIEhldXJpc3RpYzogaWYgdmF1bHRCYXNlIGVuZHMgd2l0aCBhIHNlZ21lbnQgKGUuZy4gd29ya3NwYWNlL2NvbXBlbmcvKSBhbmQgdG9rZW4gc3RhcnRzIHdpdGggdGhhdCBzZWdtZW50IChjb21wZW5nLy4uLiksXG4gICAgLy8gbWFwIHRva2VuIHVuZGVyIHZhdWx0QmFzZS5cbiAgICBmb3IgKGNvbnN0IHJvdyBvZiBtYXBwaW5ncykge1xuICAgICAgY29uc3QgdmF1bHRCYXNlUmF3ID0gU3RyaW5nKHJvdy52YXVsdEJhc2UgPz8gJycpLnRyaW0oKTtcbiAgICAgIGlmICghdmF1bHRCYXNlUmF3KSBjb250aW51ZTtcbiAgICAgIGNvbnN0IHZhdWx0QmFzZSA9IHZhdWx0QmFzZVJhdy5lbmRzV2l0aCgnLycpID8gdmF1bHRCYXNlUmF3IDogYCR7dmF1bHRCYXNlUmF3fS9gO1xuXG4gICAgICBjb25zdCBwYXJ0cyA9IHZhdWx0QmFzZS5yZXBsYWNlKC9cXC8rJC8sICcnKS5zcGxpdCgnLycpO1xuICAgICAgY29uc3QgYmFzZU5hbWUgPSBwYXJ0c1twYXJ0cy5sZW5ndGggLSAxXTtcbiAgICAgIGlmICghYmFzZU5hbWUpIGNvbnRpbnVlO1xuXG4gICAgICBjb25zdCBwcmVmaXggPSBgJHtiYXNlTmFtZX0vYDtcbiAgICAgIGlmICghdC5zdGFydHNXaXRoKHByZWZpeCkpIGNvbnRpbnVlO1xuXG4gICAgICBjb25zdCBjYW5kaWRhdGUgPSBgJHt2YXVsdEJhc2V9JHt0LnNsaWNlKHByZWZpeC5sZW5ndGgpfWA7XG4gICAgICBjb25zdCBub3JtYWxpemVkID0gY2FuZGlkYXRlLnJlcGxhY2UoL15cXC8rLywgJycpO1xuICAgICAgaWYgKHRoaXMuYXBwLnZhdWx0LmdldEFic3RyYWN0RmlsZUJ5UGF0aChub3JtYWxpemVkKSkgcmV0dXJuIG5vcm1hbGl6ZWQ7XG4gICAgfVxuXG4gICAgcmV0dXJuIG51bGw7XG4gIH1cblxuICBwcml2YXRlIF9wcmVwcm9jZXNzQXNzaXN0YW50TWFya2Rvd24odGV4dDogc3RyaW5nLCBfbWFwcGluZ3M6IFBhdGhNYXBwaW5nW10pOiBzdHJpbmcge1xuICAgIC8vIERvIG5vdCBpbmplY3Qgd2lraWxpbmtzIG9yIGN1c3RvbSBzY2hlbWVzIGludG8gTWFya2Rvd24uXG4gICAgLy8gV2UnbGwgcG9zdC1wcm9jZXNzIHJlbmRlcmVkIEhUTUwgd2l0aCB0aGUgc2FtZSBzYWZlIGxpbmtpZnkgbG9naWMgYXMgcGxhaW4gbW9kZS5cbiAgICByZXR1cm4gdGV4dDtcbiAgfVxuXG4gIHByaXZhdGUgX2FwcGVuZE9ic2lkaWFuTGluayhcbiAgICBjb250YWluZXI6IEhUTUxFbGVtZW50LFxuICAgIHZhdWx0UGF0aDogc3RyaW5nLFxuICAgIHNvdXJjZVBhdGg6IHN0cmluZyxcbiAgICBkaXNwbGF5VGV4dD86IHN0cmluZyxcbiAgKTogdm9pZCB7XG4gICAgY29uc3QgZGlzcGxheSA9IGRpc3BsYXlUZXh0ID8/IGBbWyR7dmF1bHRQYXRofV1dYDtcbiAgICBjb25zdCBhID0gY29udGFpbmVyLmNyZWF0ZUVsKCdhJywgeyB0ZXh0OiBkaXNwbGF5LCBocmVmOiAnIycgfSk7XG4gICAgYS5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsIChldikgPT4ge1xuICAgICAgZXYucHJldmVudERlZmF1bHQoKTtcbiAgICAgIGV2LnN0b3BQcm9wYWdhdGlvbigpO1xuXG4gICAgICBjb25zdCBmID0gdGhpcy5hcHAudmF1bHQuZ2V0QWJzdHJhY3RGaWxlQnlQYXRoKHZhdWx0UGF0aCk7XG4gICAgICBpZiAoZiBpbnN0YW5jZW9mIFRGaWxlKSB7XG4gICAgICAgIHZvaWQgdGhpcy5hcHAud29ya3NwYWNlLmdldExlYWYodHJ1ZSkub3BlbkZpbGUoZik7XG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cblxuICAgICAgdm9pZCB0aGlzLmFwcC53b3Jrc3BhY2Uub3BlbkxpbmtUZXh0KHZhdWx0UGF0aCwgc291cmNlUGF0aCwgdHJ1ZSk7XG4gICAgfSk7XG4gIH1cblxuICBwcml2YXRlIF9wb3N0cHJvY2Vzc0Fzc2lzdGFudExpbmtzKFxuICAgIGJvZHk6IEhUTUxFbGVtZW50LFxuICAgIHJhd1RleHQ6IHN0cmluZyxcbiAgICBtYXBwaW5nczogUGF0aE1hcHBpbmdbXSxcbiAgICBzb3VyY2VQYXRoOiBzdHJpbmcsXG4gICk6IHZvaWQge1xuICAgIC8vIExpbmtpZnkgYWZ0ZXIgTWFya2Rvd25SZW5kZXJlciBoYXMgcHJvZHVjZWQgSFRNTC5cbiAgICAvLyBXZSBvbmx5IHRyYW5zZm9ybSB0ZXh0IG5vZGVzLCBwcmVzZXJ2aW5nIGZvcm1hdHRpbmcuXG4gICAgY29uc3QgY2FuZGlkYXRlc0J5Tm9kZSA9IG5ldyBNYXA8VGV4dCwgUmV0dXJuVHlwZTx0eXBlb2YgZXh0cmFjdENhbmRpZGF0ZXM+PigpO1xuXG4gICAgY29uc3Qgd2Fsa2VyID0gYm9keS5vd25lckRvY3VtZW50LmNyZWF0ZVRyZWVXYWxrZXIoYm9keSwgTm9kZUZpbHRlci5TSE9XX1RFWFQpO1xuICAgIGNvbnN0IHRleHROb2RlczogVGV4dFtdID0gW107XG4gICAgbGV0IG46IE5vZGUgfCBudWxsO1xuICAgIHdoaWxlICgobiA9IHdhbGtlci5uZXh0Tm9kZSgpKSkge1xuICAgICAgY29uc3QgdCA9IG4gYXMgVGV4dDtcbiAgICAgIGlmICghdC5ub2RlVmFsdWUpIGNvbnRpbnVlO1xuICAgICAgdGV4dE5vZGVzLnB1c2godCk7XG4gICAgfVxuXG4gICAgZm9yIChjb25zdCB0IG9mIHRleHROb2Rlcykge1xuICAgICAgY29uc3QgdGV4dCA9IHQubm9kZVZhbHVlID8/ICcnO1xuICAgICAgY29uc3QgY2FuZGlkYXRlcyA9IGV4dHJhY3RDYW5kaWRhdGVzKHRleHQpO1xuICAgICAgaWYgKGNhbmRpZGF0ZXMubGVuZ3RoID09PSAwKSBjb250aW51ZTtcbiAgICAgIGNhbmRpZGF0ZXNCeU5vZGUuc2V0KHQsIGNhbmRpZGF0ZXMpO1xuICAgIH1cblxuICAgIGNvbnN0IHRyeVJldmVyc2VNYXBVcmxUb1ZhdWx0UGF0aCA9ICh1cmw6IHN0cmluZyk6IHN0cmluZyB8IG51bGwgPT4gdGhpcy5fdHJ5UmV2ZXJzZU1hcFVybFRvVmF1bHRQYXRoKHVybCwgbWFwcGluZ3MpO1xuXG4gICAgZm9yIChjb25zdCBbdCwgY2FuZGlkYXRlc10gb2YgY2FuZGlkYXRlc0J5Tm9kZS5lbnRyaWVzKCkpIHtcbiAgICAgIGNvbnN0IHRleHQgPSB0Lm5vZGVWYWx1ZSA/PyAnJztcbiAgICAgIGNvbnN0IGZyYWcgPSBib2R5Lm93bmVyRG9jdW1lbnQuY3JlYXRlRG9jdW1lbnRGcmFnbWVudCgpO1xuICAgICAgbGV0IGN1cnNvciA9IDA7XG5cbiAgICAgIGNvbnN0IGFwcGVuZFRleHQgPSAoczogc3RyaW5nKSA9PiB7XG4gICAgICAgIGlmICghcykgcmV0dXJuO1xuICAgICAgICBmcmFnLmFwcGVuZENoaWxkKGJvZHkub3duZXJEb2N1bWVudC5jcmVhdGVUZXh0Tm9kZShzKSk7XG4gICAgICB9O1xuXG4gICAgICBmb3IgKGNvbnN0IGMgb2YgY2FuZGlkYXRlcykge1xuICAgICAgICBhcHBlbmRUZXh0KHRleHQuc2xpY2UoY3Vyc29yLCBjLnN0YXJ0KSk7XG4gICAgICAgIGN1cnNvciA9IGMuZW5kO1xuXG4gICAgICAgIGlmIChjLmtpbmQgPT09ICd1cmwnKSB7XG4gICAgICAgICAgY29uc3QgbWFwcGVkID0gdHJ5UmV2ZXJzZU1hcFVybFRvVmF1bHRQYXRoKGMucmF3KTtcbiAgICAgICAgICBpZiAobWFwcGVkKSB7XG4gICAgICAgICAgICB0aGlzLl9hcHBlbmRPYnNpZGlhbkxpbmsoZnJhZyBhcyBhbnksIG1hcHBlZCwgc291cmNlUGF0aCwgYy5yYXcpO1xuICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAvLyBsZWF2ZSBVUkwgYXMgdGV4dDsgcmVuZGVyZXIgbGlrZWx5IGFscmVhZHkgY3JlYXRlZCBhbiA8YT4gZm9yIGl0XG4gICAgICAgICAgICBhcHBlbmRUZXh0KGMucmF3KTtcbiAgICAgICAgICB9XG4gICAgICAgICAgY29udGludWU7XG4gICAgICAgIH1cblxuICAgICAgICBjb25zdCBkaXJlY3QgPSB0aGlzLl90cnlNYXBWYXVsdFJlbGF0aXZlVG9rZW4oYy5yYXcsIG1hcHBpbmdzKTtcbiAgICAgICAgaWYgKGRpcmVjdCkge1xuICAgICAgICAgIHRoaXMuX2FwcGVuZE9ic2lkaWFuTGluayhmcmFnIGFzIGFueSwgZGlyZWN0LCBzb3VyY2VQYXRoLCBjLnJhdyk7XG4gICAgICAgICAgY29udGludWU7XG4gICAgICAgIH1cblxuICAgICAgICBjb25zdCBtYXBwZWQgPSB0cnlNYXBSZW1vdGVQYXRoVG9WYXVsdFBhdGgoYy5yYXcsIG1hcHBpbmdzKTtcbiAgICAgICAgaWYgKG1hcHBlZCAmJiB0aGlzLmFwcC52YXVsdC5nZXRBYnN0cmFjdEZpbGVCeVBhdGgobWFwcGVkKSkge1xuICAgICAgICAgIHRoaXMuX2FwcGVuZE9ic2lkaWFuTGluayhmcmFnIGFzIGFueSwgbWFwcGVkLCBzb3VyY2VQYXRoLCBjLnJhdyk7XG4gICAgICAgICAgY29udGludWU7XG4gICAgICAgIH1cblxuICAgICAgICBhcHBlbmRUZXh0KGMucmF3KTtcbiAgICAgIH1cblxuICAgICAgYXBwZW5kVGV4dCh0ZXh0LnNsaWNlKGN1cnNvcikpO1xuXG4gICAgICAvLyBSZXBsYWNlIHRoZSB0ZXh0IG5vZGUuXG4gICAgICBjb25zdCBwYXJlbnQgPSB0LnBhcmVudE5vZGU7XG4gICAgICBpZiAoIXBhcmVudCkgY29udGludWU7XG4gICAgICBwYXJlbnQucmVwbGFjZUNoaWxkKGZyYWcsIHQpO1xuICAgIH1cblxuICAgIHZvaWQgcmF3VGV4dDtcbiAgfVxuXG4gIHByaXZhdGUgX3JlbmRlckFzc2lzdGFudFBsYWluV2l0aExpbmtzKFxuICAgIGJvZHk6IEhUTUxFbGVtZW50LFxuICAgIHRleHQ6IHN0cmluZyxcbiAgICBtYXBwaW5nczogUGF0aE1hcHBpbmdbXSxcbiAgICBzb3VyY2VQYXRoOiBzdHJpbmcsXG4gICk6IHZvaWQge1xuICAgIGNvbnN0IGNhbmRpZGF0ZXMgPSBleHRyYWN0Q2FuZGlkYXRlcyh0ZXh0KTtcbiAgICBpZiAoY2FuZGlkYXRlcy5sZW5ndGggPT09IDApIHtcbiAgICAgIGJvZHkuc2V0VGV4dCh0ZXh0KTtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICBsZXQgY3Vyc29yID0gMDtcblxuICAgIGNvbnN0IGFwcGVuZFRleHQgPSAoczogc3RyaW5nKSA9PiB7XG4gICAgICBpZiAoIXMpIHJldHVybjtcbiAgICAgIGJvZHkuYXBwZW5kQ2hpbGQoZG9jdW1lbnQuY3JlYXRlVGV4dE5vZGUocykpO1xuICAgIH07XG5cbiAgICBjb25zdCBhcHBlbmRFeHRlcm5hbFVybCA9ICh1cmw6IHN0cmluZykgPT4ge1xuICAgICAgLy8gTGV0IE9ic2lkaWFuL0VsZWN0cm9uIGhhbmRsZSBleHRlcm5hbCBvcGVuLlxuICAgICAgYm9keS5jcmVhdGVFbCgnYScsIHsgdGV4dDogdXJsLCBocmVmOiB1cmwgfSk7XG4gICAgfTtcblxuICAgIGNvbnN0IHRyeVJldmVyc2VNYXBVcmxUb1ZhdWx0UGF0aCA9ICh1cmw6IHN0cmluZyk6IHN0cmluZyB8IG51bGwgPT4gdGhpcy5fdHJ5UmV2ZXJzZU1hcFVybFRvVmF1bHRQYXRoKHVybCwgbWFwcGluZ3MpO1xuXG4gICAgZm9yIChjb25zdCBjIG9mIGNhbmRpZGF0ZXMpIHtcbiAgICAgIGFwcGVuZFRleHQodGV4dC5zbGljZShjdXJzb3IsIGMuc3RhcnQpKTtcbiAgICAgIGN1cnNvciA9IGMuZW5kO1xuXG4gICAgICBpZiAoYy5raW5kID09PSAndXJsJykge1xuICAgICAgICBjb25zdCBtYXBwZWQgPSB0cnlSZXZlcnNlTWFwVXJsVG9WYXVsdFBhdGgoYy5yYXcpO1xuICAgICAgICBpZiAobWFwcGVkKSB7XG4gICAgICAgICAgdGhpcy5fYXBwZW5kT2JzaWRpYW5MaW5rKGJvZHksIG1hcHBlZCwgc291cmNlUGF0aCk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgYXBwZW5kRXh0ZXJuYWxVcmwoYy5yYXcpO1xuICAgICAgICB9XG4gICAgICAgIGNvbnRpbnVlO1xuICAgICAgfVxuXG4gICAgICBjb25zdCBkaXJlY3QgPSB0aGlzLl90cnlNYXBWYXVsdFJlbGF0aXZlVG9rZW4oYy5yYXcsIG1hcHBpbmdzKTtcbiAgICAgIGlmIChkaXJlY3QpIHtcbiAgICAgICAgdGhpcy5fYXBwZW5kT2JzaWRpYW5MaW5rKGJvZHksIGRpcmVjdCwgc291cmNlUGF0aCk7XG4gICAgICAgIGNvbnRpbnVlO1xuICAgICAgfVxuXG4gICAgICBjb25zdCBtYXBwZWQgPSB0cnlNYXBSZW1vdGVQYXRoVG9WYXVsdFBhdGgoYy5yYXcsIG1hcHBpbmdzKTtcbiAgICAgIGlmICghbWFwcGVkKSB7XG4gICAgICAgIGFwcGVuZFRleHQoYy5yYXcpO1xuICAgICAgICBjb250aW51ZTtcbiAgICAgIH1cblxuICAgICAgaWYgKCF0aGlzLmFwcC52YXVsdC5nZXRBYnN0cmFjdEZpbGVCeVBhdGgobWFwcGVkKSkge1xuICAgICAgICBhcHBlbmRUZXh0KGMucmF3KTtcbiAgICAgICAgY29udGludWU7XG4gICAgICB9XG5cbiAgICAgIHRoaXMuX2FwcGVuZE9ic2lkaWFuTGluayhib2R5LCBtYXBwZWQsIHNvdXJjZVBhdGgpO1xuICAgIH1cblxuICAgIGFwcGVuZFRleHQodGV4dC5zbGljZShjdXJzb3IpKTtcbiAgfVxuXG4gIHByaXZhdGUgX3VwZGF0ZVNlbmRCdXR0b24oKTogdm9pZCB7XG4gICAgLy8gRGlzY29ubmVjdGVkOiBkaXNhYmxlLlxuICAgIC8vIFdvcmtpbmc6IGtlZXAgZW5hYmxlZCBzbyB1c2VyIGNhbiBzdG9wL2Fib3J0LlxuICAgIGNvbnN0IGRpc2FibGVkID0gIXRoaXMuaXNDb25uZWN0ZWQ7XG4gICAgdGhpcy5zZW5kQnRuLmRpc2FibGVkID0gZGlzYWJsZWQ7XG5cbiAgICB0aGlzLnNlbmRCdG4udG9nZ2xlQ2xhc3MoJ2lzLXdvcmtpbmcnLCB0aGlzLmlzV29ya2luZyk7XG4gICAgdGhpcy5zZW5kQnRuLnNldEF0dHIoJ2FyaWEtYnVzeScsIHRoaXMuaXNXb3JraW5nID8gJ3RydWUnIDogJ2ZhbHNlJyk7XG4gICAgdGhpcy5zZW5kQnRuLnNldEF0dHIoJ2FyaWEtbGFiZWwnLCB0aGlzLmlzV29ya2luZyA/ICdTdG9wJyA6ICdTZW5kJyk7XG5cbiAgICBpZiAodGhpcy5pc1dvcmtpbmcpIHtcbiAgICAgIC8vIFJlcGxhY2UgYnV0dG9uIGNvbnRlbnRzIHdpdGggU3RvcCBpY29uICsgc3Bpbm5lciByaW5nLlxuICAgICAgdGhpcy5zZW5kQnRuLmVtcHR5KCk7XG4gICAgICBjb25zdCB3cmFwID0gdGhpcy5zZW5kQnRuLmNyZWF0ZURpdih7IGNsczogJ29jbGF3LXN0b3Atd3JhcCcgfSk7XG4gICAgICB3cmFwLmNyZWF0ZURpdih7IGNsczogJ29jbGF3LXNwaW5uZXItcmluZycsIGF0dHI6IHsgJ2FyaWEtaGlkZGVuJzogJ3RydWUnIH0gfSk7XG4gICAgICB3cmFwLmNyZWF0ZURpdih7IGNsczogJ29jbGF3LXN0b3AtaWNvbicsIGF0dHI6IHsgJ2FyaWEtaGlkZGVuJzogJ3RydWUnIH0gfSk7XG4gICAgfSBlbHNlIHtcbiAgICAgIC8vIFJlc3RvcmUgbGFiZWxcbiAgICAgIHRoaXMuc2VuZEJ0bi5zZXRUZXh0KCdTZW5kJyk7XG4gICAgfVxuICB9XG5cbiAgLy8gXHUyNTAwXHUyNTAwIFNlbmQgaGFuZGxlciBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcblxuICBwcml2YXRlIGFzeW5jIF9oYW5kbGVTZW5kKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIC8vIFdoaWxlIHdvcmtpbmcsIHRoZSBidXR0b24gYmVjb21lcyBTdG9wLlxuICAgIGlmICh0aGlzLmlzV29ya2luZykge1xuICAgICAgY29uc3Qgb2sgPSBhd2FpdCB0aGlzLndzQ2xpZW50LmFib3J0QWN0aXZlUnVuKCk7XG4gICAgICBpZiAoIW9rKSB7XG4gICAgICAgIG5ldyBOb3RpY2UoJ09wZW5DbGF3IENoYXQ6IGZhaWxlZCB0byBzdG9wJyk7XG4gICAgICAgIHRoaXMuY2hhdE1hbmFnZXIuYWRkTWVzc2FnZShDaGF0TWFuYWdlci5jcmVhdGVTeXN0ZW1NZXNzYWdlKCdcdTI2QTAgU3RvcCBmYWlsZWQnLCAnZXJyb3InKSk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICB0aGlzLmNoYXRNYW5hZ2VyLmFkZE1lc3NhZ2UoQ2hhdE1hbmFnZXIuY3JlYXRlU3lzdGVtTWVzc2FnZSgnXHUyNkQ0IFN0b3BwZWQnLCAnaW5mbycpKTtcbiAgICAgIH1cbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICBjb25zdCB0ZXh0ID0gdGhpcy5pbnB1dEVsLnZhbHVlLnRyaW0oKTtcbiAgICBpZiAoIXRleHQpIHJldHVybjtcblxuICAgIC8vIEJ1aWxkIG1lc3NhZ2Ugd2l0aCBjb250ZXh0IGlmIGVuYWJsZWRcbiAgICBsZXQgbWVzc2FnZSA9IHRleHQ7XG4gICAgaWYgKHRoaXMuaW5jbHVkZU5vdGVDaGVja2JveC5jaGVja2VkKSB7XG4gICAgICBjb25zdCBub3RlID0gYXdhaXQgZ2V0QWN0aXZlTm90ZUNvbnRleHQodGhpcy5hcHApO1xuICAgICAgaWYgKG5vdGUpIHtcbiAgICAgICAgbWVzc2FnZSA9IGBDb250ZXh0OiBbWyR7bm90ZS50aXRsZX1dXVxcblxcbiR7dGV4dH1gO1xuICAgICAgfVxuICAgIH1cblxuICAgIC8vIEFkZCB1c2VyIG1lc3NhZ2UgdG8gY2hhdCBVSVxuICAgIGNvbnN0IHVzZXJNc2cgPSBDaGF0TWFuYWdlci5jcmVhdGVVc2VyTWVzc2FnZSh0ZXh0KTtcbiAgICB0aGlzLmNoYXRNYW5hZ2VyLmFkZE1lc3NhZ2UodXNlck1zZyk7XG5cbiAgICAvLyBDbGVhciBpbnB1dFxuICAgIHRoaXMuaW5wdXRFbC52YWx1ZSA9ICcnO1xuICAgIHRoaXMuaW5wdXRFbC5zdHlsZS5oZWlnaHQgPSAnYXV0byc7XG5cbiAgICAvLyBTZW5kIG92ZXIgV1MgKGFzeW5jKVxuICAgIHRyeSB7XG4gICAgICBhd2FpdCB0aGlzLndzQ2xpZW50LnNlbmRNZXNzYWdlKG1lc3NhZ2UpO1xuICAgIH0gY2F0Y2ggKGVycikge1xuICAgICAgY29uc29sZS5lcnJvcignW29jbGF3XSBTZW5kIGZhaWxlZCcsIGVycik7XG4gICAgICBuZXcgTm90aWNlKGBPcGVuQ2xhdyBDaGF0OiBzZW5kIGZhaWxlZCAoJHtTdHJpbmcoZXJyKX0pYCk7XG4gICAgICB0aGlzLmNoYXRNYW5hZ2VyLmFkZE1lc3NhZ2UoXG4gICAgICAgIENoYXRNYW5hZ2VyLmNyZWF0ZVN5c3RlbU1lc3NhZ2UoYFx1MjZBMCBTZW5kIGZhaWxlZDogJHtlcnJ9YCwgJ2Vycm9yJylcbiAgICAgICk7XG4gICAgfVxuICB9XG59XG4iLCAiaW1wb3J0IHR5cGUgeyBDaGF0TWVzc2FnZSB9IGZyb20gJy4vdHlwZXMnO1xuXG4vKiogTWFuYWdlcyB0aGUgaW4tbWVtb3J5IGxpc3Qgb2YgY2hhdCBtZXNzYWdlcyBhbmQgbm90aWZpZXMgVUkgb24gY2hhbmdlcyAqL1xuZXhwb3J0IGNsYXNzIENoYXRNYW5hZ2VyIHtcbiAgcHJpdmF0ZSBtZXNzYWdlczogQ2hhdE1lc3NhZ2VbXSA9IFtdO1xuXG4gIC8qKiBGaXJlZCBmb3IgYSBmdWxsIHJlLXJlbmRlciAoY2xlYXIvcmVsb2FkKSAqL1xuICBvblVwZGF0ZTogKChtZXNzYWdlczogcmVhZG9ubHkgQ2hhdE1lc3NhZ2VbXSkgPT4gdm9pZCkgfCBudWxsID0gbnVsbDtcbiAgLyoqIEZpcmVkIHdoZW4gYSBzaW5nbGUgbWVzc2FnZSBpcyBhcHBlbmRlZCBcdTIwMTQgdXNlIGZvciBPKDEpIGFwcGVuZC1vbmx5IFVJICovXG4gIG9uTWVzc2FnZUFkZGVkOiAoKG1zZzogQ2hhdE1lc3NhZ2UpID0+IHZvaWQpIHwgbnVsbCA9IG51bGw7XG5cbiAgYWRkTWVzc2FnZShtc2c6IENoYXRNZXNzYWdlKTogdm9pZCB7XG4gICAgdGhpcy5tZXNzYWdlcy5wdXNoKG1zZyk7XG4gICAgdGhpcy5vbk1lc3NhZ2VBZGRlZD8uKG1zZyk7XG4gIH1cblxuICBnZXRNZXNzYWdlcygpOiByZWFkb25seSBDaGF0TWVzc2FnZVtdIHtcbiAgICByZXR1cm4gdGhpcy5tZXNzYWdlcztcbiAgfVxuXG4gIGNsZWFyKCk6IHZvaWQge1xuICAgIHRoaXMubWVzc2FnZXMgPSBbXTtcbiAgICB0aGlzLm9uVXBkYXRlPy4oW10pO1xuICB9XG5cbiAgLyoqIENyZWF0ZSBhIHVzZXIgbWVzc2FnZSBvYmplY3QgKHdpdGhvdXQgYWRkaW5nIGl0KSAqL1xuICBzdGF0aWMgY3JlYXRlVXNlck1lc3NhZ2UoY29udGVudDogc3RyaW5nKTogQ2hhdE1lc3NhZ2Uge1xuICAgIHJldHVybiB7XG4gICAgICBpZDogYG1zZy0ke0RhdGUubm93KCl9LSR7TWF0aC5yYW5kb20oKS50b1N0cmluZygzNikuc2xpY2UoMiwgNyl9YCxcbiAgICAgIHJvbGU6ICd1c2VyJyxcbiAgICAgIGNvbnRlbnQsXG4gICAgICB0aW1lc3RhbXA6IERhdGUubm93KCksXG4gICAgfTtcbiAgfVxuXG4gIC8qKiBDcmVhdGUgYW4gYXNzaXN0YW50IG1lc3NhZ2Ugb2JqZWN0ICh3aXRob3V0IGFkZGluZyBpdCkgKi9cbiAgc3RhdGljIGNyZWF0ZUFzc2lzdGFudE1lc3NhZ2UoY29udGVudDogc3RyaW5nKTogQ2hhdE1lc3NhZ2Uge1xuICAgIHJldHVybiB7XG4gICAgICBpZDogYG1zZy0ke0RhdGUubm93KCl9LSR7TWF0aC5yYW5kb20oKS50b1N0cmluZygzNikuc2xpY2UoMiwgNyl9YCxcbiAgICAgIHJvbGU6ICdhc3Npc3RhbnQnLFxuICAgICAgY29udGVudCxcbiAgICAgIHRpbWVzdGFtcDogRGF0ZS5ub3coKSxcbiAgICB9O1xuICB9XG5cbiAgLyoqIENyZWF0ZSBhIHN5c3RlbSAvIHN0YXR1cyBtZXNzYWdlIChlcnJvcnMsIHJlY29ubmVjdCBub3RpY2VzLCBldGMuKSAqL1xuICBzdGF0aWMgY3JlYXRlU3lzdGVtTWVzc2FnZShjb250ZW50OiBzdHJpbmcsIGxldmVsOiBDaGF0TWVzc2FnZVsnbGV2ZWwnXSA9ICdpbmZvJyk6IENoYXRNZXNzYWdlIHtcbiAgICByZXR1cm4ge1xuICAgICAgaWQ6IGBzeXMtJHtEYXRlLm5vdygpfWAsXG4gICAgICByb2xlOiAnc3lzdGVtJyxcbiAgICAgIGxldmVsLFxuICAgICAgY29udGVudCxcbiAgICAgIHRpbWVzdGFtcDogRGF0ZS5ub3coKSxcbiAgICB9O1xuICB9XG5cbiAgc3RhdGljIGNyZWF0ZVNlc3Npb25EaXZpZGVyKHNlc3Npb25LZXk6IHN0cmluZyk6IENoYXRNZXNzYWdlIHtcbiAgICBjb25zdCBzaG9ydCA9IHNlc3Npb25LZXkubGVuZ3RoID4gMjggPyBgJHtzZXNzaW9uS2V5LnNsaWNlKDAsIDEyKX1cdTIwMjYke3Nlc3Npb25LZXkuc2xpY2UoLTEyKX1gIDogc2Vzc2lvbktleTtcbiAgICByZXR1cm4ge1xuICAgICAgaWQ6IGBkaXYtJHtEYXRlLm5vdygpfWAsXG4gICAgICByb2xlOiAnc3lzdGVtJyxcbiAgICAgIGxldmVsOiAnaW5mbycsXG4gICAgICBraW5kOiAnc2Vzc2lvbi1kaXZpZGVyJyxcbiAgICAgIHRpdGxlOiBzZXNzaW9uS2V5LFxuICAgICAgY29udGVudDogYFtTZXNzaW9uOiAke3Nob3J0fV1gLFxuICAgICAgdGltZXN0YW1wOiBEYXRlLm5vdygpLFxuICAgIH07XG4gIH1cbn1cbiIsICJpbXBvcnQgdHlwZSB7IFBhdGhNYXBwaW5nIH0gZnJvbSAnLi90eXBlcyc7XG5cbmV4cG9ydCBmdW5jdGlvbiBub3JtYWxpemVCYXNlKGJhc2U6IHN0cmluZyk6IHN0cmluZyB7XG4gIGNvbnN0IHRyaW1tZWQgPSBTdHJpbmcoYmFzZSA/PyAnJykudHJpbSgpO1xuICBpZiAoIXRyaW1tZWQpIHJldHVybiAnJztcbiAgcmV0dXJuIHRyaW1tZWQuZW5kc1dpdGgoJy8nKSA/IHRyaW1tZWQgOiBgJHt0cmltbWVkfS9gO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gdHJ5TWFwUmVtb3RlUGF0aFRvVmF1bHRQYXRoKGlucHV0OiBzdHJpbmcsIG1hcHBpbmdzOiByZWFkb25seSBQYXRoTWFwcGluZ1tdKTogc3RyaW5nIHwgbnVsbCB7XG4gIGNvbnN0IHJhdyA9IFN0cmluZyhpbnB1dCA/PyAnJyk7XG4gIGZvciAoY29uc3Qgcm93IG9mIG1hcHBpbmdzKSB7XG4gICAgY29uc3QgcmVtb3RlQmFzZSA9IG5vcm1hbGl6ZUJhc2Uocm93LnJlbW90ZUJhc2UpO1xuICAgIGNvbnN0IHZhdWx0QmFzZSA9IG5vcm1hbGl6ZUJhc2Uocm93LnZhdWx0QmFzZSk7XG4gICAgaWYgKCFyZW1vdGVCYXNlIHx8ICF2YXVsdEJhc2UpIGNvbnRpbnVlO1xuXG4gICAgaWYgKHJhdy5zdGFydHNXaXRoKHJlbW90ZUJhc2UpKSB7XG4gICAgICBjb25zdCByZXN0ID0gcmF3LnNsaWNlKHJlbW90ZUJhc2UubGVuZ3RoKTtcbiAgICAgIC8vIE9ic2lkaWFuIHBhdGhzIGFyZSB2YXVsdC1yZWxhdGl2ZSBhbmQgc2hvdWxkIG5vdCBzdGFydCB3aXRoICcvJ1xuICAgICAgcmV0dXJuIGAke3ZhdWx0QmFzZX0ke3Jlc3R9YC5yZXBsYWNlKC9eXFwvKy8sICcnKTtcbiAgICB9XG4gIH1cbiAgcmV0dXJuIG51bGw7XG59XG5cbmV4cG9ydCB0eXBlIENhbmRpZGF0ZSA9IHsgc3RhcnQ6IG51bWJlcjsgZW5kOiBudW1iZXI7IHJhdzogc3RyaW5nOyBraW5kOiAndXJsJyB8ICdwYXRoJyB9O1xuXG4vLyBDb25zZXJ2YXRpdmUgZXh0cmFjdGlvbjogYWltIHRvIGF2b2lkIGZhbHNlIHBvc2l0aXZlcy5cbmNvbnN0IFVSTF9SRSA9IC9odHRwcz86XFwvXFwvW15cXHM8PigpXSsvZztcbi8vIEFic29sdXRlIHVuaXgtaXNoIHBhdGhzLlxuLy8gKFdlIHN0aWxsIGV4aXN0ZW5jZS1jaGVjayBiZWZvcmUgcHJvZHVjaW5nIGEgbGluay4pXG5jb25zdCBQQVRIX1JFID0gLyg/PCFbQS1aYS16MC05Ll8tXSkoPzpcXC9bQS1aYS16MC05Ll9+ISQmJygpKissOz06QCVcXC1dKykrKD86XFwuW0EtWmEtejAtOS5fLV0rKT8vZztcblxuLy8gQ29uc2VydmF0aXZlIHJlbGF0aXZlIHBhdGhzIHdpdGggYXQgbGVhc3Qgb25lICcvJywgZS5nLiBjb21wZW5nL3BsYW5zL3gubWRcbi8vIEF2b2lkcyBtYXRjaGluZyBzY2hlbWUtbGlrZSB0b2tlbnMgdmlhIG5lZ2F0aXZlIGxvb2thaGVhZCBmb3IgJzovLycuXG5jb25zdCBSRUxfUEFUSF9SRSA9IC9cXGIoPyFbQS1aYS16XVtBLVphLXowLTkrLi1dKjpcXC9cXC8pW0EtWmEtejAtOS5fLV0rKD86XFwvW0EtWmEtejAtOS5fLV0rKSsoPzpcXC5bQS1aYS16MC05Ll8tXSspP1xcYi9nO1xuXG5leHBvcnQgZnVuY3Rpb24gZXh0cmFjdENhbmRpZGF0ZXModGV4dDogc3RyaW5nKTogQ2FuZGlkYXRlW10ge1xuICBjb25zdCB0ID0gU3RyaW5nKHRleHQgPz8gJycpO1xuICBjb25zdCBvdXQ6IENhbmRpZGF0ZVtdID0gW107XG5cbiAgZm9yIChjb25zdCBtIG9mIHQubWF0Y2hBbGwoVVJMX1JFKSkge1xuICAgIGlmIChtLmluZGV4ID09PSB1bmRlZmluZWQpIGNvbnRpbnVlO1xuICAgIG91dC5wdXNoKHsgc3RhcnQ6IG0uaW5kZXgsIGVuZDogbS5pbmRleCArIG1bMF0ubGVuZ3RoLCByYXc6IG1bMF0sIGtpbmQ6ICd1cmwnIH0pO1xuICB9XG5cbiAgZm9yIChjb25zdCBtIG9mIHQubWF0Y2hBbGwoUEFUSF9SRSkpIHtcbiAgICBpZiAobS5pbmRleCA9PT0gdW5kZWZpbmVkKSBjb250aW51ZTtcblxuICAgIC8vIFNraXAgaWYgdGhpcyBpcyBpbnNpZGUgYSBVUkwgd2UgYWxyZWFkeSBjYXB0dXJlZC5cbiAgICBjb25zdCBzdGFydCA9IG0uaW5kZXg7XG4gICAgY29uc3QgZW5kID0gc3RhcnQgKyBtWzBdLmxlbmd0aDtcbiAgICBjb25zdCBvdmVybGFwc1VybCA9IG91dC5zb21lKChjKSA9PiBjLmtpbmQgPT09ICd1cmwnICYmICEoZW5kIDw9IGMuc3RhcnQgfHwgc3RhcnQgPj0gYy5lbmQpKTtcbiAgICBpZiAob3ZlcmxhcHNVcmwpIGNvbnRpbnVlO1xuXG4gICAgb3V0LnB1c2goeyBzdGFydCwgZW5kLCByYXc6IG1bMF0sIGtpbmQ6ICdwYXRoJyB9KTtcbiAgfVxuXG4gIGZvciAoY29uc3QgbSBvZiB0Lm1hdGNoQWxsKFJFTF9QQVRIX1JFKSkge1xuICAgIGlmIChtLmluZGV4ID09PSB1bmRlZmluZWQpIGNvbnRpbnVlO1xuXG4gICAgY29uc3Qgc3RhcnQgPSBtLmluZGV4O1xuICAgIGNvbnN0IGVuZCA9IHN0YXJ0ICsgbVswXS5sZW5ndGg7XG4gICAgY29uc3Qgb3ZlcmxhcHNFeGlzdGluZyA9IG91dC5zb21lKChjKSA9PiAhKGVuZCA8PSBjLnN0YXJ0IHx8IHN0YXJ0ID49IGMuZW5kKSk7XG4gICAgaWYgKG92ZXJsYXBzRXhpc3RpbmcpIGNvbnRpbnVlO1xuXG4gICAgb3V0LnB1c2goeyBzdGFydCwgZW5kLCByYXc6IG1bMF0sIGtpbmQ6ICdwYXRoJyB9KTtcbiAgfVxuXG4gIC8vIFNvcnQgYW5kIGRyb3Agb3ZlcmxhcHMgKHByZWZlciBVUkxzKS5cbiAgb3V0LnNvcnQoKGEsIGIpID0+IGEuc3RhcnQgLSBiLnN0YXJ0IHx8IChhLmtpbmQgPT09ICd1cmwnID8gLTEgOiAxKSk7XG4gIGNvbnN0IGRlZHVwOiBDYW5kaWRhdGVbXSA9IFtdO1xuICBmb3IgKGNvbnN0IGMgb2Ygb3V0KSB7XG4gICAgY29uc3QgbGFzdCA9IGRlZHVwW2RlZHVwLmxlbmd0aCAtIDFdO1xuICAgIGlmICghbGFzdCkge1xuICAgICAgZGVkdXAucHVzaChjKTtcbiAgICAgIGNvbnRpbnVlO1xuICAgIH1cbiAgICBpZiAoYy5zdGFydCA8IGxhc3QuZW5kKSBjb250aW51ZTtcbiAgICBkZWR1cC5wdXNoKGMpO1xuICB9XG5cbiAgcmV0dXJuIGRlZHVwO1xufVxuIiwgImltcG9ydCB0eXBlIHsgQXBwIH0gZnJvbSAnb2JzaWRpYW4nO1xuXG5leHBvcnQgaW50ZXJmYWNlIE5vdGVDb250ZXh0IHtcbiAgdGl0bGU6IHN0cmluZztcbiAgcGF0aDogc3RyaW5nO1xuICBjb250ZW50OiBzdHJpbmc7XG59XG5cbi8qKlxuICogUmV0dXJucyB0aGUgYWN0aXZlIG5vdGUncyB0aXRsZSBhbmQgY29udGVudCwgb3IgbnVsbCBpZiBubyBub3RlIGlzIG9wZW4uXG4gKiBBc3luYyBiZWNhdXNlIHZhdWx0LnJlYWQoKSBpcyBhc3luYy5cbiAqL1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGdldEFjdGl2ZU5vdGVDb250ZXh0KGFwcDogQXBwKTogUHJvbWlzZTxOb3RlQ29udGV4dCB8IG51bGw+IHtcbiAgY29uc3QgZmlsZSA9IGFwcC53b3Jrc3BhY2UuZ2V0QWN0aXZlRmlsZSgpO1xuICBpZiAoIWZpbGUpIHJldHVybiBudWxsO1xuXG4gIHRyeSB7XG4gICAgY29uc3QgY29udGVudCA9IGF3YWl0IGFwcC52YXVsdC5yZWFkKGZpbGUpO1xuICAgIHJldHVybiB7XG4gICAgICB0aXRsZTogZmlsZS5iYXNlbmFtZSxcbiAgICAgIHBhdGg6IGZpbGUucGF0aCxcbiAgICAgIGNvbnRlbnQsXG4gICAgfTtcbiAgfSBjYXRjaCAoZXJyKSB7XG4gICAgY29uc29sZS5lcnJvcignW29jbGF3LWNvbnRleHRdIEZhaWxlZCB0byByZWFkIGFjdGl2ZSBub3RlJywgZXJyKTtcbiAgICByZXR1cm4gbnVsbDtcbiAgfVxufVxuIiwgIi8qKiBQZXJzaXN0ZWQgcGx1Z2luIGNvbmZpZ3VyYXRpb24gKi9cbmV4cG9ydCBpbnRlcmZhY2UgT3BlbkNsYXdTZXR0aW5ncyB7XG4gIC8qKiBXZWJTb2NrZXQgVVJMIG9mIHRoZSBPcGVuQ2xhdyBHYXRld2F5IChlLmcuIHdzOi8vMTAwLjkwLjkuNjg6MTg3ODkpICovXG4gIGdhdGV3YXlVcmw6IHN0cmluZztcbiAgLyoqIEF1dGggdG9rZW4gXHUyMDE0IG11c3QgbWF0Y2ggdGhlIGNoYW5uZWwgcGx1Z2luJ3MgYXV0aFRva2VuICovXG4gIGF1dGhUb2tlbjogc3RyaW5nO1xuICAvKiogT3BlbkNsYXcgc2Vzc2lvbiBrZXkgdG8gc3Vic2NyaWJlIHRvIChlLmcuIFwibWFpblwiKSAqL1xuICBzZXNzaW9uS2V5OiBzdHJpbmc7XG4gIC8qKiAoRGVwcmVjYXRlZCkgT3BlbkNsYXcgYWNjb3VudCBJRCAodW51c2VkOyBjaGF0LnNlbmQgdXNlcyBzZXNzaW9uS2V5KSAqL1xuICBhY2NvdW50SWQ6IHN0cmluZztcbiAgLyoqIFdoZXRoZXIgdG8gaW5jbHVkZSB0aGUgYWN0aXZlIG5vdGUgY29udGVudCB3aXRoIGVhY2ggbWVzc2FnZSAqL1xuICBpbmNsdWRlQWN0aXZlTm90ZTogYm9vbGVhbjtcbiAgLyoqIFJlbmRlciBhc3Npc3RhbnQgb3V0cHV0IGFzIE1hcmtkb3duICh1bnNhZmU6IG1heSB0cmlnZ2VyIGVtYmVkcy9wb3N0LXByb2Nlc3NvcnMpOyBkZWZhdWx0IE9GRiAqL1xuICByZW5kZXJBc3Npc3RhbnRNYXJrZG93bjogYm9vbGVhbjtcbiAgLyoqIEFsbG93IHVzaW5nIGluc2VjdXJlIHdzOi8vIGZvciBub24tbG9jYWwgZ2F0ZXdheSBVUkxzICh1bnNhZmUpOyBkZWZhdWx0IE9GRiAqL1xuICBhbGxvd0luc2VjdXJlV3M6IGJvb2xlYW47XG5cbiAgLyoqIE9wdGlvbmFsOiBtYXAgcmVtb3RlIEZTIHBhdGhzIC8gZXhwb3J0ZWQgcGF0aHMgYmFjayB0byB2YXVsdC1yZWxhdGl2ZSBwYXRocyAqL1xuICBwYXRoTWFwcGluZ3M6IFBhdGhNYXBwaW5nW107XG5cbiAgLyoqIFZhdWx0IGlkZW50aXR5IChoYXNoKSB1c2VkIGZvciBjYW5vbmljYWwgc2Vzc2lvbiBrZXlzLiAqL1xuICB2YXVsdEhhc2g/OiBzdHJpbmc7XG5cbiAgLyoqIEtub3duIE9ic2lkaWFuIHNlc3Npb24ga2V5cyBmb3IgZWFjaCB2YXVsdEhhc2ggKHZhdWx0LXNjb3BlZCBjb250aW51aXR5KS4gKi9cbiAga25vd25TZXNzaW9uS2V5c0J5VmF1bHQ/OiBSZWNvcmQ8c3RyaW5nLCBzdHJpbmdbXT47XG5cbiAgLyoqIExlZ2FjeSBrZXlzIGtlcHQgZm9yIG1pZ3JhdGlvbi9kZWJ1ZyAob3B0aW9uYWwpLiAqL1xuICBsZWdhY3lTZXNzaW9uS2V5cz86IHN0cmluZ1tdO1xufVxuXG5leHBvcnQgdHlwZSBQYXRoTWFwcGluZyA9IHtcbiAgLyoqIFZhdWx0LXJlbGF0aXZlIGJhc2UgcGF0aCAoZS5nLiBcImRvY3MvXCIgb3IgXCJjb21wZW5nL1wiKSAqL1xuICB2YXVsdEJhc2U6IHN0cmluZztcbiAgLyoqIFJlbW90ZSBGUyBiYXNlIHBhdGggKGUuZy4gXCIvaG9tZS93YWxsLWUvLm9wZW5jbGF3L3dvcmtzcGFjZS9kb2NzL1wiKSAqL1xuICByZW1vdGVCYXNlOiBzdHJpbmc7XG59O1xuXG5leHBvcnQgY29uc3QgREVGQVVMVF9TRVRUSU5HUzogT3BlbkNsYXdTZXR0aW5ncyA9IHtcbiAgZ2F0ZXdheVVybDogJ3dzOi8vbG9jYWxob3N0OjE4Nzg5JyxcbiAgYXV0aFRva2VuOiAnJyxcbiAgc2Vzc2lvbktleTogJ21haW4nLFxuICBhY2NvdW50SWQ6ICdtYWluJyxcbiAgaW5jbHVkZUFjdGl2ZU5vdGU6IGZhbHNlLFxuICByZW5kZXJBc3Npc3RhbnRNYXJrZG93bjogZmFsc2UsXG4gIGFsbG93SW5zZWN1cmVXczogZmFsc2UsXG4gIHBhdGhNYXBwaW5nczogW10sXG4gIHZhdWx0SGFzaDogdW5kZWZpbmVkLFxuICBrbm93blNlc3Npb25LZXlzQnlWYXVsdDoge30sXG4gIGxlZ2FjeVNlc3Npb25LZXlzOiBbXSxcbn07XG5cbi8qKiBBIHNpbmdsZSBjaGF0IG1lc3NhZ2UgKi9cbmV4cG9ydCBpbnRlcmZhY2UgQ2hhdE1lc3NhZ2Uge1xuICBpZDogc3RyaW5nO1xuICByb2xlOiAndXNlcicgfCAnYXNzaXN0YW50JyB8ICdzeXN0ZW0nO1xuICAvKiogT3B0aW9uYWwgc2V2ZXJpdHkgZm9yIHN5c3RlbS9zdGF0dXMgbWVzc2FnZXMgKi9cbiAgbGV2ZWw/OiAnaW5mbycgfCAnZXJyb3InO1xuICAvKiogT3B0aW9uYWwgc3VidHlwZSBmb3Igc3R5bGluZyBzcGVjaWFsIHN5c3RlbSBtZXNzYWdlcyAoZS5nLiBzZXNzaW9uIGRpdmlkZXIpLiAqL1xuICBraW5kPzogJ3Nlc3Npb24tZGl2aWRlcic7XG4gIC8qKiBPcHRpb25hbCBob3ZlciB0b29sdGlwIGZvciB0aGUgbWVzc2FnZSAoZS5nLiBmdWxsIHNlc3Npb24ga2V5KS4gKi9cbiAgdGl0bGU/OiBzdHJpbmc7XG4gIGNvbnRlbnQ6IHN0cmluZztcbiAgdGltZXN0YW1wOiBudW1iZXI7XG59XG5cbi8qKiBQYXlsb2FkIGZvciBtZXNzYWdlcyBTRU5UIHRvIHRoZSBzZXJ2ZXIgKG91dGJvdW5kKSAqL1xuZXhwb3J0IGludGVyZmFjZSBXU1BheWxvYWQge1xuICB0eXBlOiAnYXV0aCcgfCAnbWVzc2FnZScgfCAncGluZycgfCAncG9uZycgfCAnZXJyb3InO1xuICBwYXlsb2FkPzogUmVjb3JkPHN0cmluZywgdW5rbm93bj47XG59XG5cbi8qKiBNZXNzYWdlcyBSRUNFSVZFRCBmcm9tIHRoZSBzZXJ2ZXIgKGluYm91bmQpIFx1MjAxNCBkaXNjcmltaW5hdGVkIHVuaW9uICovXG5leHBvcnQgdHlwZSBJbmJvdW5kV1NQYXlsb2FkID1cbiAgfCB7IHR5cGU6ICdtZXNzYWdlJzsgcGF5bG9hZDogeyBjb250ZW50OiBzdHJpbmc7IHJvbGU6IHN0cmluZzsgdGltZXN0YW1wOiBudW1iZXIgfSB9XG4gIHwgeyB0eXBlOiAnZXJyb3InOyBwYXlsb2FkOiB7IG1lc3NhZ2U6IHN0cmluZyB9IH07XG5cbi8qKiBBdmFpbGFibGUgYWdlbnRzIC8gbW9kZWxzICovXG5leHBvcnQgaW50ZXJmYWNlIEFnZW50T3B0aW9uIHtcbiAgaWQ6IHN0cmluZztcbiAgbGFiZWw6IHN0cmluZztcbn1cbiIsICJpbXBvcnQgdHlwZSB7IE9wZW5DbGF3U2V0dGluZ3MgfSBmcm9tICcuL3R5cGVzJztcblxuZXhwb3J0IGZ1bmN0aW9uIGNhbm9uaWNhbFZhdWx0U2Vzc2lvbktleSh2YXVsdEhhc2g6IHN0cmluZyk6IHN0cmluZyB7XG4gIHJldHVybiBgYWdlbnQ6bWFpbjpvYnNpZGlhbjpkaXJlY3Q6JHt2YXVsdEhhc2h9YDtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIGlzQWxsb3dlZE9ic2lkaWFuU2Vzc2lvbktleShwYXJhbXM6IHtcbiAga2V5OiBzdHJpbmc7XG4gIHZhdWx0SGFzaDogc3RyaW5nIHwgbnVsbDtcbn0pOiBib29sZWFuIHtcbiAgY29uc3Qga2V5ID0gKHBhcmFtcy5rZXkgPz8gJycpLnRyaW0oKS50b0xvd2VyQ2FzZSgpO1xuICBpZiAoIWtleSkgcmV0dXJuIGZhbHNlO1xuICBpZiAoa2V5ID09PSAnbWFpbicpIHJldHVybiB0cnVlO1xuXG4gIGNvbnN0IHZhdWx0SGFzaCA9IChwYXJhbXMudmF1bHRIYXNoID8/ICcnKS50cmltKCkudG9Mb3dlckNhc2UoKTtcbiAgaWYgKCF2YXVsdEhhc2gpIHtcbiAgICAvLyBXaXRob3V0IGEgdmF1bHQgaWRlbnRpdHksIHdlIG9ubHkgYWxsb3cgbWFpbi5cbiAgICByZXR1cm4gZmFsc2U7XG4gIH1cblxuICBjb25zdCBwcmVmaXggPSBgYWdlbnQ6bWFpbjpvYnNpZGlhbjpkaXJlY3Q6JHt2YXVsdEhhc2h9YDtcbiAgaWYgKGtleSA9PT0gcHJlZml4KSByZXR1cm4gdHJ1ZTtcbiAgaWYgKGtleS5zdGFydHNXaXRoKHByZWZpeCArICctJykpIHJldHVybiB0cnVlO1xuICByZXR1cm4gZmFsc2U7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBtaWdyYXRlU2V0dGluZ3NGb3JWYXVsdChzZXR0aW5nczogT3BlbkNsYXdTZXR0aW5ncywgdmF1bHRIYXNoOiBzdHJpbmcpOiB7XG4gIG5leHRTZXR0aW5nczogT3BlbkNsYXdTZXR0aW5ncztcbiAgY2Fub25pY2FsS2V5OiBzdHJpbmc7XG59IHtcbiAgY29uc3QgY2Fub25pY2FsS2V5ID0gY2Fub25pY2FsVmF1bHRTZXNzaW9uS2V5KHZhdWx0SGFzaCk7XG4gIGNvbnN0IGV4aXN0aW5nID0gKHNldHRpbmdzLnNlc3Npb25LZXkgPz8gJycpLnRyaW0oKS50b0xvd2VyQ2FzZSgpO1xuICBjb25zdCBpc0xlZ2FjeSA9IGV4aXN0aW5nLnN0YXJ0c1dpdGgoJ29ic2lkaWFuLScpO1xuICBjb25zdCBpc0VtcHR5T3JNYWluID0gIWV4aXN0aW5nIHx8IGV4aXN0aW5nID09PSAnbWFpbicgfHwgZXhpc3RpbmcgPT09ICdhZ2VudDptYWluOm1haW4nO1xuXG4gIGNvbnN0IG5leHQ6IE9wZW5DbGF3U2V0dGluZ3MgPSB7IC4uLnNldHRpbmdzIH07XG4gIG5leHQudmF1bHRIYXNoID0gdmF1bHRIYXNoO1xuXG4gIGlmIChpc0xlZ2FjeSkge1xuICAgIGNvbnN0IGxlZ2FjeSA9IEFycmF5LmlzQXJyYXkobmV4dC5sZWdhY3lTZXNzaW9uS2V5cykgPyBuZXh0LmxlZ2FjeVNlc3Npb25LZXlzIDogW107XG4gICAgbmV4dC5sZWdhY3lTZXNzaW9uS2V5cyA9IFtleGlzdGluZywgLi4ubGVnYWN5LmZpbHRlcigoaykgPT4gayAmJiBrICE9PSBleGlzdGluZyldLnNsaWNlKDAsIDIwKTtcbiAgfVxuXG4gIGlmIChpc0xlZ2FjeSB8fCBpc0VtcHR5T3JNYWluKSB7XG4gICAgbmV4dC5zZXNzaW9uS2V5ID0gY2Fub25pY2FsS2V5O1xuICB9XG5cbiAgY29uc3QgbWFwID0gbmV4dC5rbm93blNlc3Npb25LZXlzQnlWYXVsdCA/PyB7fTtcbiAgY29uc3QgY3VyID0gQXJyYXkuaXNBcnJheShtYXBbdmF1bHRIYXNoXSkgPyBtYXBbdmF1bHRIYXNoXSA6IFtdO1xuICBpZiAoIWN1ci5pbmNsdWRlcyhjYW5vbmljYWxLZXkpKSB7XG4gICAgbWFwW3ZhdWx0SGFzaF0gPSBbY2Fub25pY2FsS2V5LCAuLi5jdXJdLnNsaWNlKDAsIDIwKTtcbiAgICBuZXh0Lmtub3duU2Vzc2lvbktleXNCeVZhdWx0ID0gbWFwO1xuICB9XG5cbiAgcmV0dXJuIHsgbmV4dFNldHRpbmdzOiBuZXh0LCBjYW5vbmljYWxLZXkgfTtcbn1cbiJdLAogICJtYXBwaW5ncyI6ICI7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQSxJQUFBQSxtQkFBaUU7OztBQ0FqRSxzQkFBK0M7QUFHeEMsSUFBTSxxQkFBTixjQUFpQyxpQ0FBaUI7QUFBQSxFQUd2RCxZQUFZLEtBQVUsUUFBd0I7QUFDNUMsVUFBTSxLQUFLLE1BQU07QUFDakIsU0FBSyxTQUFTO0FBQUEsRUFDaEI7QUFBQSxFQUVBLFVBQWdCO0FBWGxCO0FBWUksVUFBTSxFQUFFLFlBQVksSUFBSTtBQUN4QixnQkFBWSxNQUFNO0FBRWxCLGdCQUFZLFNBQVMsTUFBTSxFQUFFLE1BQU0sZ0NBQTJCLENBQUM7QUFFL0QsUUFBSSx3QkFBUSxXQUFXLEVBQ3BCLFFBQVEsYUFBYSxFQUNyQixRQUFRLG1FQUFtRSxFQUMzRTtBQUFBLE1BQVEsQ0FBQyxTQUNSLEtBQ0csZUFBZSxzQkFBc0IsRUFDckMsU0FBUyxLQUFLLE9BQU8sU0FBUyxVQUFVLEVBQ3hDLFNBQVMsQ0FBTyxVQUFVO0FBQ3pCLGFBQUssT0FBTyxTQUFTLGFBQWEsTUFBTSxLQUFLO0FBQzdDLGNBQU0sS0FBSyxPQUFPLGFBQWE7QUFBQSxNQUNq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QUFBQSxFQUVjLG9CQUFvQixVQUE4QjtBQUFBO0FBbExsRTtBQW1MSSxZQUFNLFFBQVEsV0FBTSxLQUFLLFNBQVMsTUFBcEIsWUFBMEIsQ0FBQztBQUN6QyxZQUFNLEtBQUssU0FBUyxpQ0FBSyxPQUFMLEVBQVcsQ0FBQyxLQUFLLGtCQUFrQixHQUFHLFNBQVMsRUFBQztBQUFBLElBQ3RFO0FBQUE7QUFBQSxFQUVjLHVCQUFzQztBQUFBO0FBdkx0RDtBQXdMSSxZQUFNLFFBQVEsV0FBTSxLQUFLLFNBQVMsTUFBcEIsWUFBMEIsQ0FBQztBQUN6QyxXQUFLLDZCQUFlLEtBQUsseUJBQXdCO0FBQVc7QUFDNUQsWUFBTSxPQUFPLG1CQUFNO0FBQ25CLGFBQU8sS0FBSyxLQUFLLGtCQUFrQjtBQUNuQyxZQUFNLEtBQUssU0FBUyxJQUFJO0FBQUEsSUFDMUI7QUFBQTtBQUFBO0FBQUEsRUFJYyxvQkFBbUM7QUFBQTtBQUMvQyxZQUFNLEVBQUUsVUFBVSxJQUFJLEtBQUs7QUFHM0IsWUFBTSxXQUFXLFVBQVUsZ0JBQWdCLHVCQUF1QjtBQUNsRSxVQUFJLFNBQVMsU0FBUyxHQUFHO0FBQ3ZCLGtCQUFVLFdBQVcsU0FBUyxDQUFDLENBQUM7QUFDaEM7QUFBQSxNQUNGO0FBR0EsWUFBTSxPQUFPLFVBQVUsYUFBYSxLQUFLO0FBQ3pDLFVBQUksQ0FBQztBQUFNO0FBQ1gsWUFBTSxLQUFLLGFBQWEsRUFBRSxNQUFNLHlCQUF5QixRQUFRLEtBQUssQ0FBQztBQUN2RSxnQkFBVSxXQUFXLElBQUk7QUFBQSxJQUMzQjtBQUFBO0FBQ0Y7QUExTXFCLGdCQU1KLGtCQUFrQjtBQU5uQyxJQUFxQixpQkFBckI7IiwKICAibmFtZXMiOiBbImltcG9ydF9vYnNpZGlhbiIsICJfYSIsICJpbXBvcnRfb2JzaWRpYW4iLCAibWFwcGVkIiwgImNyeXB0byJdCn0K
