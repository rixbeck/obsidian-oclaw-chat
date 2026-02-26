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
  listSessions(opts) {
    return __async(this, null, function* () {
      var _a, _b;
      if (this.state !== "connected") {
        throw new Error("Not connected");
      }
      const params = {
        includeGlobal: Boolean((_a = opts == null ? void 0 : opts.includeGlobal) != null ? _a : false),
        includeUnknown: Boolean((_b = opts == null ? void 0 : opts.includeUnknown) != null ? _b : false)
      };
      if ((opts == null ? void 0 : opts.activeMinutes) && opts.activeMinutes > 0)
        params.activeMinutes = opts.activeMinutes;
      if ((opts == null ? void 0 : opts.limit) && opts.limit > 0)
        params.limit = opts.limit;
      const res = yield this._sendRequest("sessions.list", params);
      return res;
    });
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
    new import_obsidian2.Setting(contentEl).setName("Session key").setDesc("Tip: keep it Obsidian-specific (e.g. obsidian-YYYYMMDD-HHMM).").addText((t) => {
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
        this.onSubmit(value);
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
      void this._refreshSessions();
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
    this.sessionRefreshBtn = sessRow.createEl("button", { cls: "oclaw-session-btn", text: "Refresh" });
    this.sessionNewBtn = sessRow.createEl("button", { cls: "oclaw-session-btn", text: "New\u2026" });
    this.sessionMainBtn = sessRow.createEl("button", { cls: "oclaw-session-btn", text: "Main" });
    this.sessionRefreshBtn.addEventListener("click", () => void this._refreshSessions());
    this.sessionNewBtn.addEventListener("click", () => void this._promptNewSession());
    this.sessionMainBtn.addEventListener("click", () => void this.plugin.switchSession("main"));
    this.sessionSelect.addEventListener("change", () => {
      const next = this.sessionSelect.value;
      if (!next || next === this.plugin.settings.sessionKey)
        return;
      void this.plugin.switchSession(next);
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
    this.sessionSelect.empty();
    const current = this.plugin.settings.sessionKey;
    const recent = Array.isArray(this.plugin.settings.recentSessionKeys) ? this.plugin.settings.recentSessionKeys : [];
    const unique = Array.from(new Set([current, ...recent, ...keys].filter(Boolean)));
    for (const key of unique) {
      const opt = this.sessionSelect.createEl("option", { value: key, text: key });
      if (key === current)
        opt.selected = true;
    }
    this.sessionSelect.title = current;
  }
  _refreshSessions() {
    return __async(this, null, function* () {
      if (!this.sessionSelect)
        return;
      if (this.plugin.wsClient.state !== "connected") {
        this._setSessionSelectOptions([]);
        return;
      }
      try {
        const res = yield this.plugin.wsClient.listSessions({
          activeMinutes: 60 * 24,
          limit: 100,
          includeGlobal: false,
          includeUnknown: false
        });
        const rows = Array.isArray(res == null ? void 0 : res.sessions) ? res.sessions : [];
        const obsidianOnly = rows.filter((r) => {
          if (!r)
            return false;
          const key = String(r.key || "");
          if (key.startsWith("obsidian-"))
            return true;
          return r.channel === "obsidian" || key.includes(":obsidian:");
        });
        const keys = obsidianOnly.map((r) => r.key).filter(Boolean);
        this._setSessionSelectOptions(keys);
      } catch (err) {
        console.error("[oclaw] sessions.list failed", err);
        this._setSessionSelectOptions([]);
      }
    });
  }
  _promptNewSession() {
    return __async(this, null, function* () {
      const now = /* @__PURE__ */ new Date();
      const pad = (n) => String(n).padStart(2, "0");
      const suggested = `obsidian-${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}-${pad(now.getHours())}${pad(now.getMinutes())}`;
      const modal = new NewSessionModal(this, suggested, (value) => {
        const v = value.trim();
        if (!v)
          return;
        void (() => __async(this, null, function* () {
          yield this.plugin.switchSession(v);
          yield this._refreshSessions();
          this.sessionSelect.value = v;
          this.sessionSelect.title = v;
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
  recentSessionKeys: []
};

// src/main.ts
var OpenClawPlugin = class extends import_obsidian3.Plugin {
  constructor() {
    super(...arguments);
    this._deviceIdentityKey = "_openclawDeviceIdentityV1";
  }
  switchSession(sessionKey) {
    return __async(this, null, function* () {
      const next = sessionKey.trim();
      if (!next) {
        new import_obsidian3.Notice("OpenClaw Chat: session key cannot be empty.");
        return;
      }
      try {
        yield this.wsClient.abortActiveRun();
      } catch (e) {
      }
      this.chatManager.addMessage(ChatManager.createSessionDivider(next));
      this.settings.sessionKey = next;
      const recent = Array.isArray(this.settings.recentSessionKeys) ? this.settings.recentSessionKeys : [];
      const nextRecent = [next, ...recent.filter((k) => k && k !== next)].slice(0, 20);
      this.settings.recentSessionKeys = nextRecent;
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
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsic3JjL21haW4udHMiLCAic3JjL3NldHRpbmdzLnRzIiwgInNyYy93ZWJzb2NrZXQudHMiLCAic3JjL2NoYXQudHMiLCAic3JjL3ZpZXcudHMiLCAic3JjL2xpbmtpZnkudHMiLCAic3JjL2NvbnRleHQudHMiLCAic3JjL3R5cGVzLnRzIl0sCiAgInNvdXJjZXNDb250ZW50IjogWyJpbXBvcnQgeyBOb3RpY2UsIFBsdWdpbiwgV29ya3NwYWNlTGVhZiB9IGZyb20gJ29ic2lkaWFuJztcbmltcG9ydCB7IE9wZW5DbGF3U2V0dGluZ1RhYiB9IGZyb20gJy4vc2V0dGluZ3MnO1xuaW1wb3J0IHsgT2JzaWRpYW5XU0NsaWVudCB9IGZyb20gJy4vd2Vic29ja2V0JztcbmltcG9ydCB7IENoYXRNYW5hZ2VyIH0gZnJvbSAnLi9jaGF0JztcbmltcG9ydCB7IFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFULCBPcGVuQ2xhd0NoYXRWaWV3IH0gZnJvbSAnLi92aWV3JztcbmltcG9ydCB7IERFRkFVTFRfU0VUVElOR1MsIHR5cGUgT3BlbkNsYXdTZXR0aW5ncyB9IGZyb20gJy4vdHlwZXMnO1xuXG5leHBvcnQgZGVmYXVsdCBjbGFzcyBPcGVuQ2xhd1BsdWdpbiBleHRlbmRzIFBsdWdpbiB7XG4gIHNldHRpbmdzITogT3BlbkNsYXdTZXR0aW5ncztcbiAgd3NDbGllbnQhOiBPYnNpZGlhbldTQ2xpZW50O1xuICBjaGF0TWFuYWdlciE6IENoYXRNYW5hZ2VyO1xuXG4gIGFzeW5jIHN3aXRjaFNlc3Npb24oc2Vzc2lvbktleTogc3RyaW5nKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgY29uc3QgbmV4dCA9IHNlc3Npb25LZXkudHJpbSgpO1xuICAgIGlmICghbmV4dCkge1xuICAgICAgbmV3IE5vdGljZSgnT3BlbkNsYXcgQ2hhdDogc2Vzc2lvbiBrZXkgY2Fubm90IGJlIGVtcHR5LicpO1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIC8vIEFib3J0IGFueSBpbi1mbGlnaHQgcnVuIGJlc3QtZWZmb3J0IChhdm9pZCBsZWFraW5nIGEgXCJ3b3JraW5nXCIgVUkgc3RhdGUpLlxuICAgIHRyeSB7XG4gICAgICBhd2FpdCB0aGlzLndzQ2xpZW50LmFib3J0QWN0aXZlUnVuKCk7XG4gICAgfSBjYXRjaCB7XG4gICAgICAvLyBpZ25vcmVcbiAgICB9XG5cbiAgICAvLyBJbnNlcnQgZGl2aWRlciBhdCB0aGUgc3RhcnQgb2YgdGhlIG5ldyBzZXNzaW9uLlxuICAgIHRoaXMuY2hhdE1hbmFnZXIuYWRkTWVzc2FnZShDaGF0TWFuYWdlci5jcmVhdGVTZXNzaW9uRGl2aWRlcihuZXh0KSk7XG5cbiAgICAvLyBQZXJzaXN0ICsgcmVtZW1iZXIgYXMgYSByZWNlbnQgT2JzaWRpYW4gc2Vzc2lvbiBrZXkuXG4gICAgdGhpcy5zZXR0aW5ncy5zZXNzaW9uS2V5ID0gbmV4dDtcbiAgICBjb25zdCByZWNlbnQgPSBBcnJheS5pc0FycmF5KHRoaXMuc2V0dGluZ3MucmVjZW50U2Vzc2lvbktleXMpID8gdGhpcy5zZXR0aW5ncy5yZWNlbnRTZXNzaW9uS2V5cyA6IFtdO1xuICAgIGNvbnN0IG5leHRSZWNlbnQgPSBbbmV4dCwgLi4ucmVjZW50LmZpbHRlcigoaykgPT4gayAmJiBrICE9PSBuZXh0KV0uc2xpY2UoMCwgMjApO1xuICAgIHRoaXMuc2V0dGluZ3MucmVjZW50U2Vzc2lvbktleXMgPSBuZXh0UmVjZW50O1xuICAgIGF3YWl0IHRoaXMuc2F2ZVNldHRpbmdzKCk7XG5cbiAgICAvLyBSZWNvbm5lY3Qgd2l0aCB0aGUgbmV3IHNlc3Npb24ga2V5LlxuICAgIHRoaXMud3NDbGllbnQuZGlzY29ubmVjdCgpO1xuICAgIHRoaXMud3NDbGllbnQuc2V0U2Vzc2lvbktleShuZXh0KTtcblxuICAgIGlmICh0aGlzLnNldHRpbmdzLmF1dGhUb2tlbikge1xuICAgICAgdGhpcy53c0NsaWVudC5jb25uZWN0KHRoaXMuc2V0dGluZ3MuZ2F0ZXdheVVybCwgdGhpcy5zZXR0aW5ncy5hdXRoVG9rZW4sIHtcbiAgICAgICAgYWxsb3dJbnNlY3VyZVdzOiB0aGlzLnNldHRpbmdzLmFsbG93SW5zZWN1cmVXcyxcbiAgICAgIH0pO1xuICAgIH1cbiAgfVxuXG4gIGFzeW5jIG9ubG9hZCgpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBhd2FpdCB0aGlzLmxvYWRTZXR0aW5ncygpO1xuXG4gICAgdGhpcy53c0NsaWVudCA9IG5ldyBPYnNpZGlhbldTQ2xpZW50KHRoaXMuc2V0dGluZ3Muc2Vzc2lvbktleSwge1xuICAgICAgaWRlbnRpdHlTdG9yZToge1xuICAgICAgICBnZXQ6IGFzeW5jICgpID0+IChhd2FpdCB0aGlzLl9sb2FkRGV2aWNlSWRlbnRpdHkoKSksXG4gICAgICAgIHNldDogYXN5bmMgKGlkZW50aXR5KSA9PiBhd2FpdCB0aGlzLl9zYXZlRGV2aWNlSWRlbnRpdHkoaWRlbnRpdHkpLFxuICAgICAgICBjbGVhcjogYXN5bmMgKCkgPT4gYXdhaXQgdGhpcy5fY2xlYXJEZXZpY2VJZGVudGl0eSgpLFxuICAgICAgfSxcbiAgICB9KTtcbiAgICB0aGlzLmNoYXRNYW5hZ2VyID0gbmV3IENoYXRNYW5hZ2VyKCk7XG5cbiAgICAvLyBXaXJlIGluY29taW5nIFdTIG1lc3NhZ2VzIFx1MjE5MiBDaGF0TWFuYWdlclxuICAgIHRoaXMud3NDbGllbnQub25NZXNzYWdlID0gKG1zZykgPT4ge1xuICAgICAgaWYgKG1zZy50eXBlID09PSAnbWVzc2FnZScpIHtcbiAgICAgICAgdGhpcy5jaGF0TWFuYWdlci5hZGRNZXNzYWdlKENoYXRNYW5hZ2VyLmNyZWF0ZUFzc2lzdGFudE1lc3NhZ2UobXNnLnBheWxvYWQuY29udGVudCkpO1xuICAgICAgfSBlbHNlIGlmIChtc2cudHlwZSA9PT0gJ2Vycm9yJykge1xuICAgICAgICBjb25zdCBlcnJUZXh0ID0gbXNnLnBheWxvYWQubWVzc2FnZSA/PyAnVW5rbm93biBlcnJvciBmcm9tIGdhdGV3YXknO1xuICAgICAgICB0aGlzLmNoYXRNYW5hZ2VyLmFkZE1lc3NhZ2UoQ2hhdE1hbmFnZXIuY3JlYXRlU3lzdGVtTWVzc2FnZShgXHUyNkEwICR7ZXJyVGV4dH1gLCAnZXJyb3InKSk7XG4gICAgICB9XG4gICAgfTtcblxuICAgIC8vIFJlZ2lzdGVyIHRoZSBzaWRlYmFyIHZpZXdcbiAgICB0aGlzLnJlZ2lzdGVyVmlldyhcbiAgICAgIFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFULFxuICAgICAgKGxlYWY6IFdvcmtzcGFjZUxlYWYpID0+IG5ldyBPcGVuQ2xhd0NoYXRWaWV3KGxlYWYsIHRoaXMpXG4gICAgKTtcblxuICAgIC8vIFJpYmJvbiBpY29uIFx1MjAxNCBvcGVucyAvIHJldmVhbHMgdGhlIGNoYXQgc2lkZWJhclxuICAgIHRoaXMuYWRkUmliYm9uSWNvbignbWVzc2FnZS1zcXVhcmUnLCAnT3BlbkNsYXcgQ2hhdCcsICgpID0+IHtcbiAgICAgIHRoaXMuX2FjdGl2YXRlQ2hhdFZpZXcoKTtcbiAgICB9KTtcblxuICAgIC8vIFNldHRpbmdzIHRhYlxuICAgIHRoaXMuYWRkU2V0dGluZ1RhYihuZXcgT3BlbkNsYXdTZXR0aW5nVGFiKHRoaXMuYXBwLCB0aGlzKSk7XG5cbiAgICAvLyBDb21tYW5kIHBhbGV0dGUgZW50cnlcbiAgICB0aGlzLmFkZENvbW1hbmQoe1xuICAgICAgaWQ6ICdvcGVuLW9wZW5jbGF3LWNoYXQnLFxuICAgICAgbmFtZTogJ09wZW4gY2hhdCBzaWRlYmFyJyxcbiAgICAgIGNhbGxiYWNrOiAoKSA9PiB0aGlzLl9hY3RpdmF0ZUNoYXRWaWV3KCksXG4gICAgfSk7XG5cbiAgICAvLyBDb25uZWN0IHRvIGdhdGV3YXkgaWYgdG9rZW4gaXMgY29uZmlndXJlZFxuICAgIGlmICh0aGlzLnNldHRpbmdzLmF1dGhUb2tlbikge1xuICAgICAgdGhpcy5fY29ubmVjdFdTKCk7XG4gICAgfSBlbHNlIHtcbiAgICAgIG5ldyBOb3RpY2UoJ09wZW5DbGF3IENoYXQ6IHBsZWFzZSBjb25maWd1cmUgeW91ciBnYXRld2F5IHRva2VuIGluIFNldHRpbmdzLicpO1xuICAgIH1cblxuICAgIGNvbnNvbGUubG9nKCdbb2NsYXddIFBsdWdpbiBsb2FkZWQnKTtcbiAgfVxuXG4gIGFzeW5jIG9udW5sb2FkKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIHRoaXMud3NDbGllbnQuZGlzY29ubmVjdCgpO1xuICAgIHRoaXMuYXBwLndvcmtzcGFjZS5kZXRhY2hMZWF2ZXNPZlR5cGUoVklFV19UWVBFX09QRU5DTEFXX0NIQVQpO1xuICAgIGNvbnNvbGUubG9nKCdbb2NsYXddIFBsdWdpbiB1bmxvYWRlZCcpO1xuICB9XG5cbiAgYXN5bmMgbG9hZFNldHRpbmdzKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIGNvbnN0IGRhdGEgPSAoYXdhaXQgdGhpcy5sb2FkRGF0YSgpKSA/PyB7fTtcbiAgICAvLyBOT1RFOiBwbHVnaW4gZGF0YSBtYXkgY29udGFpbiBleHRyYSBwcml2YXRlIGZpZWxkcyAoZS5nLiBkZXZpY2UgaWRlbnRpdHkpLiBTZXR0aW5ncyBhcmUgdGhlIHB1YmxpYyBzdWJzZXQuXG4gICAgdGhpcy5zZXR0aW5ncyA9IE9iamVjdC5hc3NpZ24oe30sIERFRkFVTFRfU0VUVElOR1MsIGRhdGEpO1xuICB9XG5cbiAgYXN5bmMgc2F2ZVNldHRpbmdzKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIC8vIFByZXNlcnZlIGFueSBwcml2YXRlIGZpZWxkcyBzdG9yZWQgaW4gcGx1Z2luIGRhdGEuXG4gICAgY29uc3QgZGF0YSA9IChhd2FpdCB0aGlzLmxvYWREYXRhKCkpID8/IHt9O1xuICAgIGF3YWl0IHRoaXMuc2F2ZURhdGEoeyAuLi5kYXRhLCAuLi50aGlzLnNldHRpbmdzIH0pO1xuICB9XG5cbiAgLy8gXHUyNTAwXHUyNTAwIERldmljZSBpZGVudGl0eSBwZXJzaXN0ZW5jZSAocGx1Z2luLXNjb3BlZDsgTk9UIGxvY2FsU3RvcmFnZSkgXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG5cbiAgYXN5bmMgcmVzZXREZXZpY2VJZGVudGl0eSgpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBhd2FpdCB0aGlzLl9jbGVhckRldmljZUlkZW50aXR5KCk7XG4gICAgbmV3IE5vdGljZSgnT3BlbkNsYXcgQ2hhdDogZGV2aWNlIGlkZW50aXR5IHJlc2V0LiBSZWNvbm5lY3QgdG8gcGFpciBhZ2Fpbi4nKTtcbiAgfVxuXG4gIHByaXZhdGUgX2RldmljZUlkZW50aXR5S2V5ID0gJ19vcGVuY2xhd0RldmljZUlkZW50aXR5VjEnO1xuXG4gIHByaXZhdGUgYXN5bmMgX2xvYWREZXZpY2VJZGVudGl0eSgpOiBQcm9taXNlPGFueSB8IG51bGw+IHtcbiAgICBjb25zdCBkYXRhID0gKGF3YWl0IHRoaXMubG9hZERhdGEoKSkgPz8ge307XG4gICAgcmV0dXJuIChkYXRhIGFzIGFueSk/Llt0aGlzLl9kZXZpY2VJZGVudGl0eUtleV0gPz8gbnVsbDtcbiAgfVxuXG4gIHByaXZhdGUgYXN5bmMgX3NhdmVEZXZpY2VJZGVudGl0eShpZGVudGl0eTogYW55KTogUHJvbWlzZTx2b2lkPiB7XG4gICAgY29uc3QgZGF0YSA9IChhd2FpdCB0aGlzLmxvYWREYXRhKCkpID8/IHt9O1xuICAgIGF3YWl0IHRoaXMuc2F2ZURhdGEoeyAuLi5kYXRhLCBbdGhpcy5fZGV2aWNlSWRlbnRpdHlLZXldOiBpZGVudGl0eSB9KTtcbiAgfVxuXG4gIHByaXZhdGUgYXN5bmMgX2NsZWFyRGV2aWNlSWRlbnRpdHkoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgY29uc3QgZGF0YSA9IChhd2FpdCB0aGlzLmxvYWREYXRhKCkpID8/IHt9O1xuICAgIGlmICgoZGF0YSBhcyBhbnkpPy5bdGhpcy5fZGV2aWNlSWRlbnRpdHlLZXldID09PSB1bmRlZmluZWQpIHJldHVybjtcbiAgICBjb25zdCBuZXh0ID0geyAuLi4oZGF0YSBhcyBhbnkpIH07XG4gICAgZGVsZXRlIG5leHRbdGhpcy5fZGV2aWNlSWRlbnRpdHlLZXldO1xuICAgIGF3YWl0IHRoaXMuc2F2ZURhdGEobmV4dCk7XG4gIH1cblxuICAvLyBcdTI1MDBcdTI1MDAgSGVscGVycyBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcblxuICBwcml2YXRlIF9jb25uZWN0V1MoKTogdm9pZCB7XG4gICAgdGhpcy53c0NsaWVudC5jb25uZWN0KHRoaXMuc2V0dGluZ3MuZ2F0ZXdheVVybCwgdGhpcy5zZXR0aW5ncy5hdXRoVG9rZW4sIHtcbiAgICAgIGFsbG93SW5zZWN1cmVXczogdGhpcy5zZXR0aW5ncy5hbGxvd0luc2VjdXJlV3MsXG4gICAgfSk7XG4gIH1cblxuICBwcml2YXRlIGFzeW5jIF9hY3RpdmF0ZUNoYXRWaWV3KCk6IFByb21pc2U8dm9pZD4ge1xuICAgIGNvbnN0IHsgd29ya3NwYWNlIH0gPSB0aGlzLmFwcDtcblxuICAgIC8vIFJldXNlIGV4aXN0aW5nIGxlYWYgaWYgYWxyZWFkeSBvcGVuXG4gICAgY29uc3QgZXhpc3RpbmcgPSB3b3Jrc3BhY2UuZ2V0TGVhdmVzT2ZUeXBlKFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFUKTtcbiAgICBpZiAoZXhpc3RpbmcubGVuZ3RoID4gMCkge1xuICAgICAgd29ya3NwYWNlLnJldmVhbExlYWYoZXhpc3RpbmdbMF0pO1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIC8vIE9wZW4gaW4gcmlnaHQgc2lkZWJhclxuICAgIGNvbnN0IGxlYWYgPSB3b3Jrc3BhY2UuZ2V0UmlnaHRMZWFmKGZhbHNlKTtcbiAgICBpZiAoIWxlYWYpIHJldHVybjtcbiAgICBhd2FpdCBsZWFmLnNldFZpZXdTdGF0ZSh7IHR5cGU6IFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFULCBhY3RpdmU6IHRydWUgfSk7XG4gICAgd29ya3NwYWNlLnJldmVhbExlYWYobGVhZik7XG4gIH1cbn1cbiIsICJpbXBvcnQgeyBBcHAsIFBsdWdpblNldHRpbmdUYWIsIFNldHRpbmcgfSBmcm9tICdvYnNpZGlhbic7XG5pbXBvcnQgdHlwZSBPcGVuQ2xhd1BsdWdpbiBmcm9tICcuL21haW4nO1xuXG5leHBvcnQgY2xhc3MgT3BlbkNsYXdTZXR0aW5nVGFiIGV4dGVuZHMgUGx1Z2luU2V0dGluZ1RhYiB7XG4gIHBsdWdpbjogT3BlbkNsYXdQbHVnaW47XG5cbiAgY29uc3RydWN0b3IoYXBwOiBBcHAsIHBsdWdpbjogT3BlbkNsYXdQbHVnaW4pIHtcbiAgICBzdXBlcihhcHAsIHBsdWdpbik7XG4gICAgdGhpcy5wbHVnaW4gPSBwbHVnaW47XG4gIH1cblxuICBkaXNwbGF5KCk6IHZvaWQge1xuICAgIGNvbnN0IHsgY29udGFpbmVyRWwgfSA9IHRoaXM7XG4gICAgY29udGFpbmVyRWwuZW1wdHkoKTtcblxuICAgIGNvbnRhaW5lckVsLmNyZWF0ZUVsKCdoMicsIHsgdGV4dDogJ09wZW5DbGF3IENoYXQgXHUyMDEzIFNldHRpbmdzJyB9KTtcblxuICAgIG5ldyBTZXR0aW5nKGNvbnRhaW5lckVsKVxuICAgICAgLnNldE5hbWUoJ0dhdGV3YXkgVVJMJylcbiAgICAgIC5zZXREZXNjKCdXZWJTb2NrZXQgVVJMIG9mIHRoZSBPcGVuQ2xhdyBHYXRld2F5IChlLmcuIHdzOi8vaG9zdG5hbWU6MTg3ODkpLicpXG4gICAgICAuYWRkVGV4dCgodGV4dCkgPT5cbiAgICAgICAgdGV4dFxuICAgICAgICAgIC5zZXRQbGFjZWhvbGRlcignd3M6Ly9sb2NhbGhvc3Q6MTg3ODknKVxuICAgICAgICAgIC5zZXRWYWx1ZSh0aGlzLnBsdWdpbi5zZXR0aW5ncy5nYXRld2F5VXJsKVxuICAgICAgICAgIC5vbkNoYW5nZShhc3luYyAodmFsdWUpID0+IHtcbiAgICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLmdhdGV3YXlVcmwgPSB2YWx1ZS50cmltKCk7XG4gICAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgICB9KVxuICAgICAgKTtcblxuICAgIG5ldyBTZXR0aW5nKGNvbnRhaW5lckVsKVxuICAgICAgLnNldE5hbWUoJ0F1dGggdG9rZW4nKVxuICAgICAgLnNldERlc2MoJ011c3QgbWF0Y2ggdGhlIGF1dGhUb2tlbiBpbiB5b3VyIG9wZW5jbGF3Lmpzb24gY2hhbm5lbCBjb25maWcuIE5ldmVyIHNoYXJlZC4nKVxuICAgICAgLmFkZFRleHQoKHRleHQpID0+IHtcbiAgICAgICAgdGV4dFxuICAgICAgICAgIC5zZXRQbGFjZWhvbGRlcignRW50ZXIgdG9rZW5cdTIwMjYnKVxuICAgICAgICAgIC5zZXRWYWx1ZSh0aGlzLnBsdWdpbi5zZXR0aW5ncy5hdXRoVG9rZW4pXG4gICAgICAgICAgLm9uQ2hhbmdlKGFzeW5jICh2YWx1ZSkgPT4ge1xuICAgICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3MuYXV0aFRva2VuID0gdmFsdWU7XG4gICAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgICB9KTtcbiAgICAgICAgLy8gVHJlYXQgYXMgcGFzc3dvcmQgZmllbGQgXHUyMDEzIGRvIG5vdCByZXZlYWwgdG9rZW4gaW4gVUlcbiAgICAgICAgdGV4dC5pbnB1dEVsLnR5cGUgPSAncGFzc3dvcmQnO1xuICAgICAgICB0ZXh0LmlucHV0RWwuYXV0b2NvbXBsZXRlID0gJ29mZic7XG4gICAgICB9KTtcblxuICAgIG5ldyBTZXR0aW5nKGNvbnRhaW5lckVsKVxuICAgICAgLnNldE5hbWUoJ1Nlc3Npb24gS2V5JylcbiAgICAgIC5zZXREZXNjKCdPcGVuQ2xhdyBzZXNzaW9uIHRvIHN1YnNjcmliZSB0byAodXN1YWxseSBcIm1haW5cIikuJylcbiAgICAgIC5hZGRUZXh0KCh0ZXh0KSA9PlxuICAgICAgICB0ZXh0XG4gICAgICAgICAgLnNldFBsYWNlaG9sZGVyKCdtYWluJylcbiAgICAgICAgICAuc2V0VmFsdWUodGhpcy5wbHVnaW4uc2V0dGluZ3Muc2Vzc2lvbktleSlcbiAgICAgICAgICAub25DaGFuZ2UoYXN5bmMgKHZhbHVlKSA9PiB7XG4gICAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5zZXNzaW9uS2V5ID0gdmFsdWUudHJpbSgpIHx8ICdtYWluJztcbiAgICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICAgIH0pXG4gICAgICApO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZSgnQWNjb3VudCBJRCcpXG4gICAgICAuc2V0RGVzYygnT3BlbkNsYXcgYWNjb3VudCBJRCAodXN1YWxseSBcIm1haW5cIikuJylcbiAgICAgIC5hZGRUZXh0KCh0ZXh0KSA9PlxuICAgICAgICB0ZXh0XG4gICAgICAgICAgLnNldFBsYWNlaG9sZGVyKCdtYWluJylcbiAgICAgICAgICAuc2V0VmFsdWUodGhpcy5wbHVnaW4uc2V0dGluZ3MuYWNjb3VudElkKVxuICAgICAgICAgIC5vbkNoYW5nZShhc3luYyAodmFsdWUpID0+IHtcbiAgICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLmFjY291bnRJZCA9IHZhbHVlLnRyaW0oKSB8fCAnbWFpbic7XG4gICAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgICB9KVxuICAgICAgKTtcblxuICAgIG5ldyBTZXR0aW5nKGNvbnRhaW5lckVsKVxuICAgICAgLnNldE5hbWUoJ0luY2x1ZGUgYWN0aXZlIG5vdGUgYnkgZGVmYXVsdCcpXG4gICAgICAuc2V0RGVzYygnUHJlLWNoZWNrIFwiSW5jbHVkZSBhY3RpdmUgbm90ZVwiIGluIHRoZSBjaGF0IHBhbmVsIHdoZW4gaXQgb3BlbnMuJylcbiAgICAgIC5hZGRUb2dnbGUoKHRvZ2dsZSkgPT5cbiAgICAgICAgdG9nZ2xlLnNldFZhbHVlKHRoaXMucGx1Z2luLnNldHRpbmdzLmluY2x1ZGVBY3RpdmVOb3RlKS5vbkNoYW5nZShhc3luYyAodmFsdWUpID0+IHtcbiAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5pbmNsdWRlQWN0aXZlTm90ZSA9IHZhbHVlO1xuICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICB9KVxuICAgICAgKTtcblxuICAgIG5ldyBTZXR0aW5nKGNvbnRhaW5lckVsKVxuICAgICAgLnNldE5hbWUoJ1JlbmRlciBhc3Npc3RhbnQgYXMgTWFya2Rvd24gKHVuc2FmZSknKVxuICAgICAgLnNldERlc2MoXG4gICAgICAgICdPRkYgcmVjb21tZW5kZWQuIElmIGVuYWJsZWQsIGFzc2lzdGFudCBvdXRwdXQgaXMgcmVuZGVyZWQgYXMgT2JzaWRpYW4gTWFya2Rvd24gd2hpY2ggbWF5IHRyaWdnZXIgZW1iZWRzIGFuZCBvdGhlciBwbHVnaW5zXFwnIHBvc3QtcHJvY2Vzc29ycy4nXG4gICAgICApXG4gICAgICAuYWRkVG9nZ2xlKCh0b2dnbGUpID0+XG4gICAgICAgIHRvZ2dsZS5zZXRWYWx1ZSh0aGlzLnBsdWdpbi5zZXR0aW5ncy5yZW5kZXJBc3Npc3RhbnRNYXJrZG93bikub25DaGFuZ2UoYXN5bmMgKHZhbHVlKSA9PiB7XG4gICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3MucmVuZGVyQXNzaXN0YW50TWFya2Rvd24gPSB2YWx1ZTtcbiAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgfSlcbiAgICAgICk7XG5cbiAgICBuZXcgU2V0dGluZyhjb250YWluZXJFbClcbiAgICAgIC5zZXROYW1lKCdBbGxvdyBpbnNlY3VyZSB3czovLyBmb3Igbm9uLWxvY2FsIGdhdGV3YXlzICh1bnNhZmUpJylcbiAgICAgIC5zZXREZXNjKFxuICAgICAgICAnT0ZGIHJlY29tbWVuZGVkLiBJZiBlbmFibGVkLCB5b3UgY2FuIGNvbm5lY3QgdG8gbm9uLWxvY2FsIGdhdGV3YXlzIG92ZXIgd3M6Ly8uIFRoaXMgZXhwb3NlcyB5b3VyIHRva2VuIGFuZCBtZXNzYWdlIGNvbnRlbnQgdG8gbmV0d29yayBhdHRhY2tlcnM7IHByZWZlciB3c3M6Ly8uJ1xuICAgICAgKVxuICAgICAgLmFkZFRvZ2dsZSgodG9nZ2xlKSA9PlxuICAgICAgICB0b2dnbGUuc2V0VmFsdWUodGhpcy5wbHVnaW4uc2V0dGluZ3MuYWxsb3dJbnNlY3VyZVdzKS5vbkNoYW5nZShhc3luYyAodmFsdWUpID0+IHtcbiAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5hbGxvd0luc2VjdXJlV3MgPSB2YWx1ZTtcbiAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgfSlcbiAgICAgICk7XG5cbiAgICBuZXcgU2V0dGluZyhjb250YWluZXJFbClcbiAgICAgIC5zZXROYW1lKCdSZXNldCBkZXZpY2UgaWRlbnRpdHkgKHJlLXBhaXIpJylcbiAgICAgIC5zZXREZXNjKCdDbGVhcnMgdGhlIHN0b3JlZCBkZXZpY2UgaWRlbnRpdHkgdXNlZCBmb3Igb3BlcmF0b3Iud3JpdGUgcGFpcmluZy4gVXNlIHRoaXMgaWYgeW91IHN1c3BlY3QgY29tcHJvbWlzZSBvciBzZWUgXCJkZXZpY2UgaWRlbnRpdHkgbWlzbWF0Y2hcIi4nKVxuICAgICAgLmFkZEJ1dHRvbigoYnRuKSA9PlxuICAgICAgICBidG4uc2V0QnV0dG9uVGV4dCgnUmVzZXQnKS5zZXRXYXJuaW5nKCkub25DbGljayhhc3luYyAoKSA9PiB7XG4gICAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4ucmVzZXREZXZpY2VJZGVudGl0eSgpO1xuICAgICAgICB9KVxuICAgICAgKTtcblxuICAgIC8vIFx1MjUwMFx1MjUwMCBQYXRoIG1hcHBpbmdzIFx1MjUwMFx1MjUwMFxuICAgIGNvbnRhaW5lckVsLmNyZWF0ZUVsKCdoMycsIHsgdGV4dDogJ1BhdGggbWFwcGluZ3MgKHZhdWx0IGJhc2UgXHUyMTkyIHJlbW90ZSBiYXNlKScgfSk7XG4gICAgY29udGFpbmVyRWwuY3JlYXRlRWwoJ3AnLCB7XG4gICAgICB0ZXh0OiAnVXNlZCB0byBjb252ZXJ0IGFzc2lzdGFudCBmaWxlIHJlZmVyZW5jZXMgKHJlbW90ZSBGUyBwYXRocyBvciBleHBvcnRlZCBVUkxzKSBpbnRvIGNsaWNrYWJsZSBPYnNpZGlhbiBsaW5rcy4gRmlyc3QgbWF0Y2ggd2lucy4gT25seSBjcmVhdGVzIGEgbGluayBpZiB0aGUgbWFwcGVkIHZhdWx0IGZpbGUgZXhpc3RzLicsXG4gICAgICBjbHM6ICdzZXR0aW5nLWl0ZW0tZGVzY3JpcHRpb24nLFxuICAgIH0pO1xuXG4gICAgY29uc3QgbWFwcGluZ3MgPSB0aGlzLnBsdWdpbi5zZXR0aW5ncy5wYXRoTWFwcGluZ3MgPz8gW107XG5cbiAgICBjb25zdCByZXJlbmRlciA9IGFzeW5jICgpID0+IHtcbiAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgdGhpcy5kaXNwbGF5KCk7XG4gICAgfTtcblxuICAgIG1hcHBpbmdzLmZvckVhY2goKHJvdywgaWR4KSA9PiB7XG4gICAgICBjb25zdCBzID0gbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAgIC5zZXROYW1lKGBNYXBwaW5nICMke2lkeCArIDF9YClcbiAgICAgICAgLnNldERlc2MoJ3ZhdWx0QmFzZSBcdTIxOTIgcmVtb3RlQmFzZScpO1xuXG4gICAgICBzLmFkZFRleHQoKHQpID0+XG4gICAgICAgIHRcbiAgICAgICAgICAuc2V0UGxhY2Vob2xkZXIoJ3ZhdWx0IGJhc2UgKGUuZy4gZG9jcy8pJylcbiAgICAgICAgICAuc2V0VmFsdWUocm93LnZhdWx0QmFzZSA/PyAnJylcbiAgICAgICAgICAub25DaGFuZ2UoYXN5bmMgKHYpID0+IHtcbiAgICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLnBhdGhNYXBwaW5nc1tpZHhdLnZhdWx0QmFzZSA9IHY7XG4gICAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgICB9KVxuICAgICAgKTtcblxuICAgICAgcy5hZGRUZXh0KCh0KSA9PlxuICAgICAgICB0XG4gICAgICAgICAgLnNldFBsYWNlaG9sZGVyKCdyZW1vdGUgYmFzZSAoZS5nLiAvaG9tZS8uLi4vZG9jcy8pJylcbiAgICAgICAgICAuc2V0VmFsdWUocm93LnJlbW90ZUJhc2UgPz8gJycpXG4gICAgICAgICAgLm9uQ2hhbmdlKGFzeW5jICh2KSA9PiB7XG4gICAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5wYXRoTWFwcGluZ3NbaWR4XS5yZW1vdGVCYXNlID0gdjtcbiAgICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICAgIH0pXG4gICAgICApO1xuXG4gICAgICBzLmFkZEV4dHJhQnV0dG9uKChiKSA9PlxuICAgICAgICBiXG4gICAgICAgICAgLnNldEljb24oJ3RyYXNoJylcbiAgICAgICAgICAuc2V0VG9vbHRpcCgnUmVtb3ZlIG1hcHBpbmcnKVxuICAgICAgICAgIC5vbkNsaWNrKGFzeW5jICgpID0+IHtcbiAgICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLnBhdGhNYXBwaW5ncy5zcGxpY2UoaWR4LCAxKTtcbiAgICAgICAgICAgIGF3YWl0IHJlcmVuZGVyKCk7XG4gICAgICAgICAgfSlcbiAgICAgICk7XG4gICAgfSk7XG5cbiAgICBuZXcgU2V0dGluZyhjb250YWluZXJFbClcbiAgICAgIC5zZXROYW1lKCdBZGQgbWFwcGluZycpXG4gICAgICAuc2V0RGVzYygnQWRkIGEgbmV3IHZhdWx0QmFzZSBcdTIxOTIgcmVtb3RlQmFzZSBtYXBwaW5nIHJvdy4nKVxuICAgICAgLmFkZEJ1dHRvbigoYnRuKSA9PlxuICAgICAgICBidG4uc2V0QnV0dG9uVGV4dCgnQWRkJykub25DbGljayhhc3luYyAoKSA9PiB7XG4gICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3MucGF0aE1hcHBpbmdzLnB1c2goeyB2YXVsdEJhc2U6ICcnLCByZW1vdGVCYXNlOiAnJyB9KTtcbiAgICAgICAgICBhd2FpdCByZXJlbmRlcigpO1xuICAgICAgICB9KVxuICAgICAgKTtcblxuICAgIGNvbnRhaW5lckVsLmNyZWF0ZUVsKCdwJywge1xuICAgICAgdGV4dDogJ1JlY29ubmVjdDogY2xvc2UgYW5kIHJlb3BlbiB0aGUgc2lkZWJhciBhZnRlciBjaGFuZ2luZyB0aGUgZ2F0ZXdheSBVUkwgb3IgdG9rZW4uJyxcbiAgICAgIGNsczogJ3NldHRpbmctaXRlbS1kZXNjcmlwdGlvbicsXG4gICAgfSk7XG4gIH1cbn1cbiIsICIvKipcbiAqIFdlYlNvY2tldCBjbGllbnQgZm9yIE9wZW5DbGF3IEdhdGV3YXlcbiAqXG4gKiBQaXZvdCAoMjAyNi0wMi0yNSk6IERvIE5PVCB1c2UgY3VzdG9tIG9ic2lkaWFuLiogZ2F0ZXdheSBtZXRob2RzLlxuICogVGhvc2UgcmVxdWlyZSBvcGVyYXRvci5hZG1pbiBzY29wZSB3aGljaCBpcyBub3QgZ3JhbnRlZCB0byBleHRlcm5hbCBjbGllbnRzLlxuICpcbiAqIEF1dGggbm90ZTpcbiAqIC0gY2hhdC5zZW5kIHJlcXVpcmVzIG9wZXJhdG9yLndyaXRlXG4gKiAtIGV4dGVybmFsIGNsaWVudHMgbXVzdCBwcmVzZW50IGEgcGFpcmVkIGRldmljZSBpZGVudGl0eSB0byByZWNlaXZlIHdyaXRlIHNjb3Blc1xuICpcbiAqIFdlIHVzZSBidWlsdC1pbiBnYXRld2F5IG1ldGhvZHMvZXZlbnRzOlxuICogLSBTZW5kOiBjaGF0LnNlbmQoeyBzZXNzaW9uS2V5LCBtZXNzYWdlLCBpZGVtcG90ZW5jeUtleSwgLi4uIH0pXG4gKiAtIFJlY2VpdmU6IGV2ZW50IFwiY2hhdFwiIChmaWx0ZXIgYnkgc2Vzc2lvbktleSlcbiAqL1xuXG5pbXBvcnQgdHlwZSB7IEluYm91bmRXU1BheWxvYWQsIFNlc3Npb25zTGlzdFJlc3VsdCB9IGZyb20gJy4vdHlwZXMnO1xuXG5mdW5jdGlvbiBpc0xvY2FsSG9zdChob3N0OiBzdHJpbmcpOiBib29sZWFuIHtcbiAgY29uc3QgaCA9IGhvc3QudG9Mb3dlckNhc2UoKTtcbiAgcmV0dXJuIGggPT09ICdsb2NhbGhvc3QnIHx8IGggPT09ICcxMjcuMC4wLjEnIHx8IGggPT09ICc6OjEnO1xufVxuXG5mdW5jdGlvbiBzYWZlUGFyc2VXc1VybCh1cmw6IHN0cmluZyk6XG4gIHwgeyBvazogdHJ1ZTsgc2NoZW1lOiAnd3MnIHwgJ3dzcyc7IGhvc3Q6IHN0cmluZyB9XG4gIHwgeyBvazogZmFsc2U7IGVycm9yOiBzdHJpbmcgfSB7XG4gIHRyeSB7XG4gICAgY29uc3QgdSA9IG5ldyBVUkwodXJsKTtcbiAgICBpZiAodS5wcm90b2NvbCAhPT0gJ3dzOicgJiYgdS5wcm90b2NvbCAhPT0gJ3dzczonKSB7XG4gICAgICByZXR1cm4geyBvazogZmFsc2UsIGVycm9yOiBgR2F0ZXdheSBVUkwgbXVzdCBiZSB3czovLyBvciB3c3M6Ly8gKGdvdCAke3UucHJvdG9jb2x9KWAgfTtcbiAgICB9XG4gICAgY29uc3Qgc2NoZW1lID0gdS5wcm90b2NvbCA9PT0gJ3dzOicgPyAnd3MnIDogJ3dzcyc7XG4gICAgcmV0dXJuIHsgb2s6IHRydWUsIHNjaGVtZSwgaG9zdDogdS5ob3N0bmFtZSB9O1xuICB9IGNhdGNoIHtcbiAgICByZXR1cm4geyBvazogZmFsc2UsIGVycm9yOiAnSW52YWxpZCBnYXRld2F5IFVSTCcgfTtcbiAgfVxufVxuXG4vKiogSW50ZXJ2YWwgZm9yIHNlbmRpbmcgaGVhcnRiZWF0IHBpbmdzIChjaGVjayBjb25uZWN0aW9uIGxpdmVuZXNzKSAqL1xuY29uc3QgSEVBUlRCRUFUX0lOVEVSVkFMX01TID0gMzBfMDAwO1xuXG4vKiogU2FmZXR5IHZhbHZlOiBoaWRlIHdvcmtpbmcgc3Bpbm5lciBpZiBubyBhc3Npc3RhbnQgcmVwbHkgYXJyaXZlcyBpbiB0aW1lICovXG5jb25zdCBXT1JLSU5HX01BWF9NUyA9IDEyMF8wMDA7XG5cbi8qKiBNYXggaW5ib3VuZCBmcmFtZSBzaXplIHRvIHBhcnNlIChEb1MgZ3VhcmQpICovXG5jb25zdCBNQVhfSU5CT1VORF9GUkFNRV9CWVRFUyA9IDUxMiAqIDEwMjQ7XG5cbmZ1bmN0aW9uIGJ5dGVMZW5ndGhVdGY4KHRleHQ6IHN0cmluZyk6IG51bWJlciB7XG4gIHJldHVybiB1dGY4Qnl0ZXModGV4dCkuYnl0ZUxlbmd0aDtcbn1cblxuYXN5bmMgZnVuY3Rpb24gbm9ybWFsaXplV3NEYXRhVG9UZXh0KGRhdGE6IGFueSk6IFByb21pc2U8eyBvazogdHJ1ZTsgdGV4dDogc3RyaW5nOyBieXRlczogbnVtYmVyIH0gfCB7IG9rOiBmYWxzZTsgcmVhc29uOiBzdHJpbmc7IGJ5dGVzPzogbnVtYmVyIH0+IHtcbiAgaWYgKHR5cGVvZiBkYXRhID09PSAnc3RyaW5nJykge1xuICAgIGNvbnN0IGJ5dGVzID0gYnl0ZUxlbmd0aFV0ZjgoZGF0YSk7XG4gICAgcmV0dXJuIHsgb2s6IHRydWUsIHRleHQ6IGRhdGEsIGJ5dGVzIH07XG4gIH1cblxuICAvLyBCcm93c2VyIFdlYlNvY2tldCBjYW4gZGVsaXZlciBCbG9iXG4gIGlmICh0eXBlb2YgQmxvYiAhPT0gJ3VuZGVmaW5lZCcgJiYgZGF0YSBpbnN0YW5jZW9mIEJsb2IpIHtcbiAgICBjb25zdCBieXRlcyA9IGRhdGEuc2l6ZTtcbiAgICBpZiAoYnl0ZXMgPiBNQVhfSU5CT1VORF9GUkFNRV9CWVRFUykgcmV0dXJuIHsgb2s6IGZhbHNlLCByZWFzb246ICd0b28tbGFyZ2UnLCBieXRlcyB9O1xuICAgIGNvbnN0IHRleHQgPSBhd2FpdCBkYXRhLnRleHQoKTtcbiAgICAvLyBCbG9iLnNpemUgaXMgYnl0ZXMgYWxyZWFkeTsgbm8gbmVlZCB0byByZS1tZWFzdXJlLlxuICAgIHJldHVybiB7IG9rOiB0cnVlLCB0ZXh0LCBieXRlcyB9O1xuICB9XG5cbiAgaWYgKGRhdGEgaW5zdGFuY2VvZiBBcnJheUJ1ZmZlcikge1xuICAgIGNvbnN0IGJ5dGVzID0gZGF0YS5ieXRlTGVuZ3RoO1xuICAgIGlmIChieXRlcyA+IE1BWF9JTkJPVU5EX0ZSQU1FX0JZVEVTKSByZXR1cm4geyBvazogZmFsc2UsIHJlYXNvbjogJ3Rvby1sYXJnZScsIGJ5dGVzIH07XG4gICAgY29uc3QgdGV4dCA9IG5ldyBUZXh0RGVjb2RlcigndXRmLTgnLCB7IGZhdGFsOiBmYWxzZSB9KS5kZWNvZGUobmV3IFVpbnQ4QXJyYXkoZGF0YSkpO1xuICAgIHJldHVybiB7IG9rOiB0cnVlLCB0ZXh0LCBieXRlcyB9O1xuICB9XG5cbiAgLy8gU29tZSBydW50aW1lcyBjb3VsZCBwYXNzIFVpbnQ4QXJyYXkgZGlyZWN0bHlcbiAgaWYgKGRhdGEgaW5zdGFuY2VvZiBVaW50OEFycmF5KSB7XG4gICAgY29uc3QgYnl0ZXMgPSBkYXRhLmJ5dGVMZW5ndGg7XG4gICAgaWYgKGJ5dGVzID4gTUFYX0lOQk9VTkRfRlJBTUVfQllURVMpIHJldHVybiB7IG9rOiBmYWxzZSwgcmVhc29uOiAndG9vLWxhcmdlJywgYnl0ZXMgfTtcbiAgICBjb25zdCB0ZXh0ID0gbmV3IFRleHREZWNvZGVyKCd1dGYtOCcsIHsgZmF0YWw6IGZhbHNlIH0pLmRlY29kZShkYXRhKTtcbiAgICByZXR1cm4geyBvazogdHJ1ZSwgdGV4dCwgYnl0ZXMgfTtcbiAgfVxuXG4gIHJldHVybiB7IG9rOiBmYWxzZSwgcmVhc29uOiAndW5zdXBwb3J0ZWQtdHlwZScgfTtcbn1cblxuLyoqIE1heCBpbi1mbGlnaHQgcmVxdWVzdHMgYmVmb3JlIGZhc3QtZmFpbGluZyAoRG9TL3JvYnVzdG5lc3MgZ3VhcmQpICovXG5jb25zdCBNQVhfUEVORElOR19SRVFVRVNUUyA9IDIwMDtcblxuLyoqIFJlY29ubmVjdCBiYWNrb2ZmICovXG5jb25zdCBSRUNPTk5FQ1RfQkFTRV9NUyA9IDNfMDAwO1xuY29uc3QgUkVDT05ORUNUX01BWF9NUyA9IDYwXzAwMDtcblxuLyoqIEhhbmRzaGFrZSBkZWFkbGluZSB3YWl0aW5nIGZvciBjb25uZWN0LmNoYWxsZW5nZSAqL1xuY29uc3QgSEFORFNIQUtFX1RJTUVPVVRfTVMgPSAxNV8wMDA7XG5cbmV4cG9ydCB0eXBlIFdTQ2xpZW50U3RhdGUgPSAnZGlzY29ubmVjdGVkJyB8ICdjb25uZWN0aW5nJyB8ICdoYW5kc2hha2luZycgfCAnY29ubmVjdGVkJztcblxuZXhwb3J0IHR5cGUgV29ya2luZ1N0YXRlTGlzdGVuZXIgPSAod29ya2luZzogYm9vbGVhbikgPT4gdm9pZDtcblxuaW50ZXJmYWNlIFBlbmRpbmdSZXF1ZXN0IHtcbiAgcmVzb2x2ZTogKHBheWxvYWQ6IGFueSkgPT4gdm9pZDtcbiAgcmVqZWN0OiAoZXJyb3I6IGFueSkgPT4gdm9pZDtcbiAgdGltZW91dDogUmV0dXJuVHlwZTx0eXBlb2Ygc2V0VGltZW91dD4gfCBudWxsO1xufVxuXG5leHBvcnQgdHlwZSBEZXZpY2VJZGVudGl0eSA9IHtcbiAgaWQ6IHN0cmluZztcbiAgcHVibGljS2V5OiBzdHJpbmc7IC8vIGJhc2U2NFxuICBwcml2YXRlS2V5SndrOiBKc29uV2ViS2V5O1xufTtcblxuZXhwb3J0IGludGVyZmFjZSBEZXZpY2VJZGVudGl0eVN0b3JlIHtcbiAgZ2V0KCk6IFByb21pc2U8RGV2aWNlSWRlbnRpdHkgfCBudWxsPjtcbiAgc2V0KGlkZW50aXR5OiBEZXZpY2VJZGVudGl0eSk6IFByb21pc2U8dm9pZD47XG4gIGNsZWFyKCk6IFByb21pc2U8dm9pZD47XG59XG5cbmNvbnN0IERFVklDRV9TVE9SQUdFX0tFWSA9ICdvcGVuY2xhd0NoYXQuZGV2aWNlSWRlbnRpdHkudjEnOyAvLyBsZWdhY3kgbG9jYWxTdG9yYWdlIGtleSAobWlncmF0aW9uIG9ubHkpXG5cbmZ1bmN0aW9uIGJhc2U2NFVybEVuY29kZShieXRlczogQXJyYXlCdWZmZXIpOiBzdHJpbmcge1xuICBjb25zdCB1OCA9IG5ldyBVaW50OEFycmF5KGJ5dGVzKTtcbiAgbGV0IHMgPSAnJztcbiAgZm9yIChsZXQgaSA9IDA7IGkgPCB1OC5sZW5ndGg7IGkrKykgcyArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKHU4W2ldKTtcbiAgY29uc3QgYjY0ID0gYnRvYShzKTtcbiAgcmV0dXJuIGI2NC5yZXBsYWNlKC9cXCsvZywgJy0nKS5yZXBsYWNlKC9cXC8vZywgJ18nKS5yZXBsYWNlKC89KyQvZywgJycpO1xufVxuXG5mdW5jdGlvbiBoZXhFbmNvZGUoYnl0ZXM6IEFycmF5QnVmZmVyKTogc3RyaW5nIHtcbiAgY29uc3QgdTggPSBuZXcgVWludDhBcnJheShieXRlcyk7XG4gIHJldHVybiBBcnJheS5mcm9tKHU4KVxuICAgIC5tYXAoKGIpID0+IGIudG9TdHJpbmcoMTYpLnBhZFN0YXJ0KDIsICcwJykpXG4gICAgLmpvaW4oJycpO1xufVxuXG5mdW5jdGlvbiB1dGY4Qnl0ZXModGV4dDogc3RyaW5nKTogVWludDhBcnJheSB7XG4gIHJldHVybiBuZXcgVGV4dEVuY29kZXIoKS5lbmNvZGUodGV4dCk7XG59XG5cbmFzeW5jIGZ1bmN0aW9uIHNoYTI1NkhleChieXRlczogQXJyYXlCdWZmZXIpOiBQcm9taXNlPHN0cmluZz4ge1xuICBjb25zdCBkaWdlc3QgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmRpZ2VzdCgnU0hBLTI1NicsIGJ5dGVzKTtcbiAgcmV0dXJuIGhleEVuY29kZShkaWdlc3QpO1xufVxuXG5hc3luYyBmdW5jdGlvbiBsb2FkT3JDcmVhdGVEZXZpY2VJZGVudGl0eShzdG9yZT86IERldmljZUlkZW50aXR5U3RvcmUpOiBQcm9taXNlPERldmljZUlkZW50aXR5PiB7XG4gIC8vIDEpIFByZWZlciBwbHVnaW4tc2NvcGVkIHN0b3JhZ2UgKGluamVjdGVkIGJ5IG1haW4gcGx1Z2luKS5cbiAgaWYgKHN0b3JlKSB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IGV4aXN0aW5nID0gYXdhaXQgc3RvcmUuZ2V0KCk7XG4gICAgICBpZiAoZXhpc3Rpbmc/LmlkICYmIGV4aXN0aW5nPy5wdWJsaWNLZXkgJiYgZXhpc3Rpbmc/LnByaXZhdGVLZXlKd2spIHJldHVybiBleGlzdGluZztcbiAgICB9IGNhdGNoIHtcbiAgICAgIC8vIGlnbm9yZSBhbmQgY29udGludWUgKHdlIGNhbiBhbHdheXMgcmUtZ2VuZXJhdGUpXG4gICAgfVxuICB9XG5cbiAgLy8gMikgT25lLXRpbWUgbWlncmF0aW9uOiBsZWdhY3kgbG9jYWxTdG9yYWdlIGlkZW50aXR5LlxuICAvLyBOT1RFOiB0aGlzIHJlbWFpbnMgYSByaXNrIGJvdW5kYXJ5OyB3ZSBvbmx5IHJlYWQrZGVsZXRlIGZvciBtaWdyYXRpb24uXG4gIGNvbnN0IGxlZ2FjeSA9IGxvY2FsU3RvcmFnZS5nZXRJdGVtKERFVklDRV9TVE9SQUdFX0tFWSk7XG4gIGlmIChsZWdhY3kpIHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgcGFyc2VkID0gSlNPTi5wYXJzZShsZWdhY3kpIGFzIERldmljZUlkZW50aXR5O1xuICAgICAgaWYgKHBhcnNlZD8uaWQgJiYgcGFyc2VkPy5wdWJsaWNLZXkgJiYgcGFyc2VkPy5wcml2YXRlS2V5SndrKSB7XG4gICAgICAgIGlmIChzdG9yZSkge1xuICAgICAgICAgIGF3YWl0IHN0b3JlLnNldChwYXJzZWQpO1xuICAgICAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKERFVklDRV9TVE9SQUdFX0tFWSk7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIHBhcnNlZDtcbiAgICAgIH1cbiAgICB9IGNhdGNoIHtcbiAgICAgIC8vIENvcnJ1cHQvcGFydGlhbCBkYXRhIFx1MjE5MiBkZWxldGUgYW5kIHJlLWNyZWF0ZS5cbiAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKERFVklDRV9TVE9SQUdFX0tFWSk7XG4gICAgfVxuICB9XG5cbiAgLy8gMykgQ3JlYXRlIGEgbmV3IGlkZW50aXR5LlxuICBjb25zdCBrZXlQYWlyID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5nZW5lcmF0ZUtleSh7IG5hbWU6ICdFZDI1NTE5JyB9LCB0cnVlLCBbJ3NpZ24nLCAndmVyaWZ5J10pO1xuICBjb25zdCBwdWJSYXcgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmV4cG9ydEtleSgncmF3Jywga2V5UGFpci5wdWJsaWNLZXkpO1xuICBjb25zdCBwcml2SndrID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5leHBvcnRLZXkoJ2p3aycsIGtleVBhaXIucHJpdmF0ZUtleSk7XG5cbiAgLy8gSU1QT1JUQU5UOiBkZXZpY2UuaWQgbXVzdCBiZSBhIHN0YWJsZSBmaW5nZXJwcmludCBmb3IgdGhlIHB1YmxpYyBrZXkuXG4gIC8vIFRoZSBnYXRld2F5IGVuZm9yY2VzIGRldmljZUlkIFx1MjE5NCBwdWJsaWNLZXkgYmluZGluZzsgcmFuZG9tIGlkcyBjYW4gY2F1c2UgXCJkZXZpY2UgaWRlbnRpdHkgbWlzbWF0Y2hcIi5cbiAgY29uc3QgZGV2aWNlSWQgPSBhd2FpdCBzaGEyNTZIZXgocHViUmF3KTtcblxuICBjb25zdCBpZGVudGl0eTogRGV2aWNlSWRlbnRpdHkgPSB7XG4gICAgaWQ6IGRldmljZUlkLFxuICAgIHB1YmxpY0tleTogYmFzZTY0VXJsRW5jb2RlKHB1YlJhdyksXG4gICAgcHJpdmF0ZUtleUp3azogcHJpdkp3ayxcbiAgfTtcblxuICBpZiAoc3RvcmUpIHtcbiAgICBhd2FpdCBzdG9yZS5zZXQoaWRlbnRpdHkpO1xuICB9IGVsc2Uge1xuICAgIC8vIEZhbGxiYWNrIChzaG91bGQgbm90IGhhcHBlbiBpbiByZWFsIHBsdWdpbiBydW50aW1lKSBcdTIwMTQga2VlcCBsZWdhY3kgYmVoYXZpb3IuXG4gICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oREVWSUNFX1NUT1JBR0VfS0VZLCBKU09OLnN0cmluZ2lmeShpZGVudGl0eSkpO1xuICB9XG5cbiAgcmV0dXJuIGlkZW50aXR5O1xufVxuXG5mdW5jdGlvbiBidWlsZERldmljZUF1dGhQYXlsb2FkKHBhcmFtczoge1xuICBkZXZpY2VJZDogc3RyaW5nO1xuICBjbGllbnRJZDogc3RyaW5nO1xuICBjbGllbnRNb2RlOiBzdHJpbmc7XG4gIHJvbGU6IHN0cmluZztcbiAgc2NvcGVzOiBzdHJpbmdbXTtcbiAgc2lnbmVkQXRNczogbnVtYmVyO1xuICB0b2tlbjogc3RyaW5nO1xuICBub25jZT86IHN0cmluZztcbn0pOiBzdHJpbmcge1xuICBjb25zdCB2ZXJzaW9uID0gcGFyYW1zLm5vbmNlID8gJ3YyJyA6ICd2MSc7XG4gIGNvbnN0IHNjb3BlcyA9IHBhcmFtcy5zY29wZXMuam9pbignLCcpO1xuICBjb25zdCBiYXNlID0gW1xuICAgIHZlcnNpb24sXG4gICAgcGFyYW1zLmRldmljZUlkLFxuICAgIHBhcmFtcy5jbGllbnRJZCxcbiAgICBwYXJhbXMuY2xpZW50TW9kZSxcbiAgICBwYXJhbXMucm9sZSxcbiAgICBzY29wZXMsXG4gICAgU3RyaW5nKHBhcmFtcy5zaWduZWRBdE1zKSxcbiAgICBwYXJhbXMudG9rZW4gfHwgJycsXG4gIF07XG4gIGlmICh2ZXJzaW9uID09PSAndjInKSBiYXNlLnB1c2gocGFyYW1zLm5vbmNlIHx8ICcnKTtcbiAgcmV0dXJuIGJhc2Uuam9pbignfCcpO1xufVxuXG5hc3luYyBmdW5jdGlvbiBzaWduRGV2aWNlUGF5bG9hZChpZGVudGl0eTogRGV2aWNlSWRlbnRpdHksIHBheWxvYWQ6IHN0cmluZyk6IFByb21pc2U8eyBzaWduYXR1cmU6IHN0cmluZyB9PiB7XG4gIGNvbnN0IHByaXZhdGVLZXkgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmltcG9ydEtleShcbiAgICAnandrJyxcbiAgICBpZGVudGl0eS5wcml2YXRlS2V5SndrLFxuICAgIHsgbmFtZTogJ0VkMjU1MTknIH0sXG4gICAgZmFsc2UsXG4gICAgWydzaWduJ10sXG4gICk7XG5cbiAgY29uc3Qgc2lnID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5zaWduKHsgbmFtZTogJ0VkMjU1MTknIH0sIHByaXZhdGVLZXksIHV0ZjhCeXRlcyhwYXlsb2FkKSBhcyB1bmtub3duIGFzIEJ1ZmZlclNvdXJjZSk7XG4gIHJldHVybiB7IHNpZ25hdHVyZTogYmFzZTY0VXJsRW5jb2RlKHNpZykgfTtcbn1cblxuZnVuY3Rpb24gZXh0cmFjdFRleHRGcm9tR2F0ZXdheU1lc3NhZ2UobXNnOiBhbnkpOiBzdHJpbmcge1xuICBpZiAoIW1zZykgcmV0dXJuICcnO1xuXG4gIC8vIE1vc3QgY29tbW9uOiB7IHJvbGUsIGNvbnRlbnQgfSB3aGVyZSBjb250ZW50IGNhbiBiZSBzdHJpbmcgb3IgW3t0eXBlOid0ZXh0Jyx0ZXh0OicuLi4nfV1cbiAgY29uc3QgY29udGVudCA9IG1zZy5jb250ZW50ID8/IG1zZy5tZXNzYWdlID8/IG1zZztcbiAgaWYgKHR5cGVvZiBjb250ZW50ID09PSAnc3RyaW5nJykgcmV0dXJuIGNvbnRlbnQ7XG5cbiAgaWYgKEFycmF5LmlzQXJyYXkoY29udGVudCkpIHtcbiAgICBjb25zdCBwYXJ0cyA9IGNvbnRlbnRcbiAgICAgIC5maWx0ZXIoKGMpID0+IGMgJiYgdHlwZW9mIGMgPT09ICdvYmplY3QnICYmIGMudHlwZSA9PT0gJ3RleHQnICYmIHR5cGVvZiBjLnRleHQgPT09ICdzdHJpbmcnKVxuICAgICAgLm1hcCgoYykgPT4gYy50ZXh0KTtcbiAgICByZXR1cm4gcGFydHMuam9pbignXFxuJyk7XG4gIH1cblxuICAvLyBGYWxsYmFja1xuICB0cnkge1xuICAgIHJldHVybiBKU09OLnN0cmluZ2lmeShjb250ZW50KTtcbiAgfSBjYXRjaCB7XG4gICAgcmV0dXJuIFN0cmluZyhjb250ZW50KTtcbiAgfVxufVxuXG5mdW5jdGlvbiBzZXNzaW9uS2V5TWF0Y2hlcyhjb25maWd1cmVkOiBzdHJpbmcsIGluY29taW5nOiBzdHJpbmcpOiBib29sZWFuIHtcbiAgaWYgKGluY29taW5nID09PSBjb25maWd1cmVkKSByZXR1cm4gdHJ1ZTtcbiAgLy8gT3BlbkNsYXcgcmVzb2x2ZXMgXCJtYWluXCIgdG8gY2Fub25pY2FsIHNlc3Npb24ga2V5IGxpa2UgXCJhZ2VudDptYWluOm1haW5cIi5cbiAgaWYgKGNvbmZpZ3VyZWQgPT09ICdtYWluJyAmJiBpbmNvbWluZyA9PT0gJ2FnZW50Om1haW46bWFpbicpIHJldHVybiB0cnVlO1xuICByZXR1cm4gZmFsc2U7XG59XG5cbmV4cG9ydCBjbGFzcyBPYnNpZGlhbldTQ2xpZW50IHtcbiAgcHJpdmF0ZSB3czogV2ViU29ja2V0IHwgbnVsbCA9IG51bGw7XG4gIHByaXZhdGUgcmVjb25uZWN0VGltZXI6IFJldHVyblR5cGU8dHlwZW9mIHNldFRpbWVvdXQ+IHwgbnVsbCA9IG51bGw7XG4gIHByaXZhdGUgaGVhcnRiZWF0VGltZXI6IFJldHVyblR5cGU8dHlwZW9mIHNldEludGVydmFsPiB8IG51bGwgPSBudWxsO1xuICBwcml2YXRlIHdvcmtpbmdUaW1lcjogUmV0dXJuVHlwZTx0eXBlb2Ygc2V0VGltZW91dD4gfCBudWxsID0gbnVsbDtcbiAgcHJpdmF0ZSBpbnRlbnRpb25hbENsb3NlID0gZmFsc2U7XG4gIHByaXZhdGUgc2Vzc2lvbktleTogc3RyaW5nO1xuICBwcml2YXRlIHVybCA9ICcnO1xuICBwcml2YXRlIHRva2VuID0gJyc7XG4gIHByaXZhdGUgcmVxdWVzdElkID0gMDtcbiAgcHJpdmF0ZSBwZW5kaW5nUmVxdWVzdHMgPSBuZXcgTWFwPHN0cmluZywgUGVuZGluZ1JlcXVlc3Q+KCk7XG4gIHByaXZhdGUgd29ya2luZyA9IGZhbHNlO1xuXG4gIC8qKiBUaGUgbGFzdCBpbi1mbGlnaHQgY2hhdCBydW4gaWQuIEluIE9wZW5DbGF3IFdlYkNoYXQgdGhpcyBtYXBzIHRvIGNoYXQuc2VuZCBpZGVtcG90ZW5jeUtleS4gKi9cbiAgcHJpdmF0ZSBhY3RpdmVSdW5JZDogc3RyaW5nIHwgbnVsbCA9IG51bGw7XG5cbiAgLyoqIFByZXZlbnRzIGFib3J0IHNwYW1taW5nOiB3aGlsZSBhbiBhYm9ydCByZXF1ZXN0IGlzIGluLWZsaWdodCwgcmV1c2UgdGhlIHNhbWUgcHJvbWlzZS4gKi9cbiAgcHJpdmF0ZSBhYm9ydEluRmxpZ2h0OiBQcm9taXNlPGJvb2xlYW4+IHwgbnVsbCA9IG51bGw7XG5cbiAgc3RhdGU6IFdTQ2xpZW50U3RhdGUgPSAnZGlzY29ubmVjdGVkJztcblxuICBvbk1lc3NhZ2U6ICgobXNnOiBJbmJvdW5kV1NQYXlsb2FkKSA9PiB2b2lkKSB8IG51bGwgPSBudWxsO1xuICBvblN0YXRlQ2hhbmdlOiAoKHN0YXRlOiBXU0NsaWVudFN0YXRlKSA9PiB2b2lkKSB8IG51bGwgPSBudWxsO1xuICBvbldvcmtpbmdDaGFuZ2U6IFdvcmtpbmdTdGF0ZUxpc3RlbmVyIHwgbnVsbCA9IG51bGw7XG5cbiAgcHJpdmF0ZSBpZGVudGl0eVN0b3JlOiBEZXZpY2VJZGVudGl0eVN0b3JlIHwgdW5kZWZpbmVkO1xuICBwcml2YXRlIGFsbG93SW5zZWN1cmVXcyA9IGZhbHNlO1xuXG4gIHByaXZhdGUgcmVjb25uZWN0QXR0ZW1wdCA9IDA7XG5cbiAgY29uc3RydWN0b3Ioc2Vzc2lvbktleTogc3RyaW5nLCBvcHRzPzogeyBpZGVudGl0eVN0b3JlPzogRGV2aWNlSWRlbnRpdHlTdG9yZTsgYWxsb3dJbnNlY3VyZVdzPzogYm9vbGVhbiB9KSB7XG4gICAgdGhpcy5zZXNzaW9uS2V5ID0gc2Vzc2lvbktleTtcbiAgICB0aGlzLmlkZW50aXR5U3RvcmUgPSBvcHRzPy5pZGVudGl0eVN0b3JlO1xuICAgIHRoaXMuYWxsb3dJbnNlY3VyZVdzID0gQm9vbGVhbihvcHRzPy5hbGxvd0luc2VjdXJlV3MpO1xuICB9XG5cbiAgY29ubmVjdCh1cmw6IHN0cmluZywgdG9rZW46IHN0cmluZywgb3B0cz86IHsgYWxsb3dJbnNlY3VyZVdzPzogYm9vbGVhbiB9KTogdm9pZCB7XG4gICAgdGhpcy51cmwgPSB1cmw7XG4gICAgdGhpcy50b2tlbiA9IHRva2VuO1xuICAgIHRoaXMuYWxsb3dJbnNlY3VyZVdzID0gQm9vbGVhbihvcHRzPy5hbGxvd0luc2VjdXJlV3MgPz8gdGhpcy5hbGxvd0luc2VjdXJlV3MpO1xuICAgIHRoaXMuaW50ZW50aW9uYWxDbG9zZSA9IGZhbHNlO1xuXG4gICAgLy8gU2VjdXJpdHk6IGJsb2NrIG5vbi1sb2NhbCB3czovLyB1bmxlc3MgZXhwbGljaXRseSBhbGxvd2VkLlxuICAgIGNvbnN0IHBhcnNlZCA9IHNhZmVQYXJzZVdzVXJsKHVybCk7XG4gICAgaWYgKCFwYXJzZWQub2spIHtcbiAgICAgIHRoaXMub25NZXNzYWdlPy4oeyB0eXBlOiAnZXJyb3InLCBwYXlsb2FkOiB7IG1lc3NhZ2U6IHBhcnNlZC5lcnJvciB9IH0pO1xuICAgICAgcmV0dXJuO1xuICAgIH1cbiAgICBpZiAocGFyc2VkLnNjaGVtZSA9PT0gJ3dzJyAmJiAhaXNMb2NhbEhvc3QocGFyc2VkLmhvc3QpICYmICF0aGlzLmFsbG93SW5zZWN1cmVXcykge1xuICAgICAgdGhpcy5vbk1lc3NhZ2U/Lih7XG4gICAgICAgIHR5cGU6ICdlcnJvcicsXG4gICAgICAgIHBheWxvYWQ6IHsgbWVzc2FnZTogJ1JlZnVzaW5nIGluc2VjdXJlIHdzOi8vIHRvIG5vbi1sb2NhbCBnYXRld2F5LiBVc2Ugd3NzOi8vIG9yIGVuYWJsZSB0aGUgdW5zYWZlIG92ZXJyaWRlIGluIHNldHRpbmdzLicgfSxcbiAgICAgIH0pO1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIHRoaXMuX2Nvbm5lY3QoKTtcbiAgfVxuXG4gIGRpc2Nvbm5lY3QoKTogdm9pZCB7XG4gICAgdGhpcy5pbnRlbnRpb25hbENsb3NlID0gdHJ1ZTtcbiAgICB0aGlzLl9zdG9wVGltZXJzKCk7XG4gICAgdGhpcy5hY3RpdmVSdW5JZCA9IG51bGw7XG4gICAgdGhpcy5hYm9ydEluRmxpZ2h0ID0gbnVsbDtcbiAgICB0aGlzLl9zZXRXb3JraW5nKGZhbHNlKTtcbiAgICBpZiAodGhpcy53cykge1xuICAgICAgdGhpcy53cy5jbG9zZSgpO1xuICAgICAgdGhpcy53cyA9IG51bGw7XG4gICAgfVxuICAgIHRoaXMuX3NldFN0YXRlKCdkaXNjb25uZWN0ZWQnKTtcbiAgfVxuXG4gIHNldFNlc3Npb25LZXkoc2Vzc2lvbktleTogc3RyaW5nKTogdm9pZCB7XG4gICAgdGhpcy5zZXNzaW9uS2V5ID0gc2Vzc2lvbktleS50cmltKCk7XG4gICAgLy8gUmVzZXQgcGVyLXNlc3Npb24gcnVuIHN0YXRlLlxuICAgIHRoaXMuYWN0aXZlUnVuSWQgPSBudWxsO1xuICAgIHRoaXMuYWJvcnRJbkZsaWdodCA9IG51bGw7XG4gICAgdGhpcy5fc2V0V29ya2luZyhmYWxzZSk7XG4gIH1cblxuICBhc3luYyBsaXN0U2Vzc2lvbnMob3B0cz86IHtcbiAgICBhY3RpdmVNaW51dGVzPzogbnVtYmVyO1xuICAgIGxpbWl0PzogbnVtYmVyO1xuICAgIGluY2x1ZGVHbG9iYWw/OiBib29sZWFuO1xuICAgIGluY2x1ZGVVbmtub3duPzogYm9vbGVhbjtcbiAgfSk6IFByb21pc2U8U2Vzc2lvbnNMaXN0UmVzdWx0PiB7XG4gICAgaWYgKHRoaXMuc3RhdGUgIT09ICdjb25uZWN0ZWQnKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ05vdCBjb25uZWN0ZWQnKTtcbiAgICB9XG5cbiAgICBjb25zdCBwYXJhbXM6IFJlY29yZDxzdHJpbmcsIHVua25vd24+ID0ge1xuICAgICAgaW5jbHVkZUdsb2JhbDogQm9vbGVhbihvcHRzPy5pbmNsdWRlR2xvYmFsID8/IGZhbHNlKSxcbiAgICAgIGluY2x1ZGVVbmtub3duOiBCb29sZWFuKG9wdHM/LmluY2x1ZGVVbmtub3duID8/IGZhbHNlKSxcbiAgICB9O1xuICAgIGlmIChvcHRzPy5hY3RpdmVNaW51dGVzICYmIG9wdHMuYWN0aXZlTWludXRlcyA+IDApIHBhcmFtcy5hY3RpdmVNaW51dGVzID0gb3B0cy5hY3RpdmVNaW51dGVzO1xuICAgIGlmIChvcHRzPy5saW1pdCAmJiBvcHRzLmxpbWl0ID4gMCkgcGFyYW1zLmxpbWl0ID0gb3B0cy5saW1pdDtcblxuICAgIGNvbnN0IHJlcyA9IGF3YWl0IHRoaXMuX3NlbmRSZXF1ZXN0KCdzZXNzaW9ucy5saXN0JywgcGFyYW1zKTtcbiAgICByZXR1cm4gcmVzIGFzIFNlc3Npb25zTGlzdFJlc3VsdDtcbiAgfVxuXG4gIGFzeW5jIHNlbmRNZXNzYWdlKG1lc3NhZ2U6IHN0cmluZyk6IFByb21pc2U8dm9pZD4ge1xuICAgIGlmICh0aGlzLnN0YXRlICE9PSAnY29ubmVjdGVkJykge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKCdOb3QgY29ubmVjdGVkIFx1MjAxNCBjYWxsIGNvbm5lY3QoKSBmaXJzdCcpO1xuICAgIH1cblxuICAgIGNvbnN0IHJ1bklkID0gYG9ic2lkaWFuLSR7RGF0ZS5ub3coKX0tJHtNYXRoLnJhbmRvbSgpLnRvU3RyaW5nKDM2KS5zbGljZSgyLCA5KX1gO1xuXG4gICAgLy8gU2hvdyBcdTIwMUN3b3JraW5nXHUyMDFEIE9OTFkgYWZ0ZXIgdGhlIGdhdGV3YXkgYWNrbm93bGVkZ2VzIHRoZSByZXF1ZXN0LlxuICAgIGNvbnN0IGFjayA9IGF3YWl0IHRoaXMuX3NlbmRSZXF1ZXN0KCdjaGF0LnNlbmQnLCB7XG4gICAgICBzZXNzaW9uS2V5OiB0aGlzLnNlc3Npb25LZXksXG4gICAgICBtZXNzYWdlLFxuICAgICAgaWRlbXBvdGVuY3lLZXk6IHJ1bklkLFxuICAgICAgLy8gZGVsaXZlciBkZWZhdWx0cyB0byB0cnVlIGluIGdhdGV3YXk7IGtlZXAgZGVmYXVsdFxuICAgIH0pO1xuXG4gICAgLy8gSWYgdGhlIGdhdGV3YXkgcmV0dXJucyBhIGNhbm9uaWNhbCBydW4gaWRlbnRpZmllciwgcHJlZmVyIGl0LlxuICAgIGNvbnN0IGNhbm9uaWNhbFJ1bklkID0gU3RyaW5nKGFjaz8ucnVuSWQgfHwgYWNrPy5pZGVtcG90ZW5jeUtleSB8fCAnJyk7XG4gICAgdGhpcy5hY3RpdmVSdW5JZCA9IGNhbm9uaWNhbFJ1bklkIHx8IHJ1bklkO1xuICAgIHRoaXMuX3NldFdvcmtpbmcodHJ1ZSk7XG4gICAgdGhpcy5fYXJtV29ya2luZ1NhZmV0eVRpbWVvdXQoKTtcbiAgfVxuXG4gIC8qKiBBYm9ydCB0aGUgYWN0aXZlIHJ1biBmb3IgdGhpcyBzZXNzaW9uIChhbmQgb3VyIGxhc3QgcnVuIGlkIGlmIHByZXNlbnQpLiAqL1xuICBhc3luYyBhYm9ydEFjdGl2ZVJ1bigpOiBQcm9taXNlPGJvb2xlYW4+IHtcbiAgICBpZiAodGhpcy5zdGF0ZSAhPT0gJ2Nvbm5lY3RlZCcpIHtcbiAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG5cbiAgICAvLyBQcmV2ZW50IHJlcXVlc3Qgc3Rvcm1zOiB3aGlsZSBvbmUgYWJvcnQgaXMgaW4gZmxpZ2h0LCByZXVzZSBpdC5cbiAgICBpZiAodGhpcy5hYm9ydEluRmxpZ2h0KSB7XG4gICAgICByZXR1cm4gdGhpcy5hYm9ydEluRmxpZ2h0O1xuICAgIH1cblxuICAgIGNvbnN0IHJ1bklkID0gdGhpcy5hY3RpdmVSdW5JZDtcbiAgICBpZiAoIXJ1bklkKSB7XG4gICAgICByZXR1cm4gZmFsc2U7XG4gICAgfVxuXG4gICAgdGhpcy5hYm9ydEluRmxpZ2h0ID0gKGFzeW5jICgpID0+IHtcbiAgICAgIHRyeSB7XG4gICAgICAgIGF3YWl0IHRoaXMuX3NlbmRSZXF1ZXN0KCdjaGF0LmFib3J0JywgeyBzZXNzaW9uS2V5OiB0aGlzLnNlc3Npb25LZXksIHJ1bklkIH0pO1xuICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgIH0gY2F0Y2ggKGVycikge1xuICAgICAgICBjb25zb2xlLmVycm9yKCdbb2NsYXctd3NdIGNoYXQuYWJvcnQgZmFpbGVkJywgZXJyKTtcbiAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgfSBmaW5hbGx5IHtcbiAgICAgICAgLy8gQWx3YXlzIHJlc3RvcmUgVUkgc3RhdGUgaW1tZWRpYXRlbHk7IHRoZSBnYXRld2F5IG1heSBzdGlsbCBlbWl0IGFuIGFib3J0ZWQgZXZlbnQgbGF0ZXIuXG4gICAgICAgIHRoaXMuYWN0aXZlUnVuSWQgPSBudWxsO1xuICAgICAgICB0aGlzLl9zZXRXb3JraW5nKGZhbHNlKTtcbiAgICAgICAgdGhpcy5hYm9ydEluRmxpZ2h0ID0gbnVsbDtcbiAgICAgIH1cbiAgICB9KSgpO1xuXG4gICAgcmV0dXJuIHRoaXMuYWJvcnRJbkZsaWdodDtcbiAgfVxuXG4gIHByaXZhdGUgX2Nvbm5lY3QoKTogdm9pZCB7XG4gICAgaWYgKHRoaXMud3MpIHtcbiAgICAgIHRoaXMud3Mub25vcGVuID0gbnVsbDtcbiAgICAgIHRoaXMud3Mub25jbG9zZSA9IG51bGw7XG4gICAgICB0aGlzLndzLm9ubWVzc2FnZSA9IG51bGw7XG4gICAgICB0aGlzLndzLm9uZXJyb3IgPSBudWxsO1xuICAgICAgdGhpcy53cy5jbG9zZSgpO1xuICAgICAgdGhpcy53cyA9IG51bGw7XG4gICAgfVxuXG4gICAgdGhpcy5fc2V0U3RhdGUoJ2Nvbm5lY3RpbmcnKTtcblxuICAgIGNvbnN0IHdzID0gbmV3IFdlYlNvY2tldCh0aGlzLnVybCk7XG4gICAgdGhpcy53cyA9IHdzO1xuXG4gICAgbGV0IGNvbm5lY3ROb25jZTogc3RyaW5nIHwgbnVsbCA9IG51bGw7XG4gICAgbGV0IGNvbm5lY3RTdGFydGVkID0gZmFsc2U7XG5cbiAgICBjb25zdCB0cnlDb25uZWN0ID0gYXN5bmMgKCkgPT4ge1xuICAgICAgaWYgKGNvbm5lY3RTdGFydGVkKSByZXR1cm47XG4gICAgICBpZiAoIWNvbm5lY3ROb25jZSkgcmV0dXJuO1xuICAgICAgY29ubmVjdFN0YXJ0ZWQgPSB0cnVlO1xuXG4gICAgICB0cnkge1xuICAgICAgICBjb25zdCBpZGVudGl0eSA9IGF3YWl0IGxvYWRPckNyZWF0ZURldmljZUlkZW50aXR5KHRoaXMuaWRlbnRpdHlTdG9yZSk7XG4gICAgICAgIGNvbnN0IHNpZ25lZEF0TXMgPSBEYXRlLm5vdygpO1xuICAgICAgICBjb25zdCBwYXlsb2FkID0gYnVpbGREZXZpY2VBdXRoUGF5bG9hZCh7XG4gICAgICAgICAgZGV2aWNlSWQ6IGlkZW50aXR5LmlkLFxuICAgICAgICAgIGNsaWVudElkOiAnZ2F0ZXdheS1jbGllbnQnLFxuICAgICAgICAgIGNsaWVudE1vZGU6ICdiYWNrZW5kJyxcbiAgICAgICAgICByb2xlOiAnb3BlcmF0b3InLFxuICAgICAgICAgIHNjb3BlczogWydvcGVyYXRvci5yZWFkJywgJ29wZXJhdG9yLndyaXRlJ10sXG4gICAgICAgICAgc2lnbmVkQXRNcyxcbiAgICAgICAgICB0b2tlbjogdGhpcy50b2tlbixcbiAgICAgICAgICBub25jZTogY29ubmVjdE5vbmNlLFxuICAgICAgICB9KTtcbiAgICAgICAgY29uc3Qgc2lnID0gYXdhaXQgc2lnbkRldmljZVBheWxvYWQoaWRlbnRpdHksIHBheWxvYWQpO1xuXG4gICAgICAgIGNvbnN0IGFjayA9IGF3YWl0IHRoaXMuX3NlbmRSZXF1ZXN0KCdjb25uZWN0Jywge1xuICAgICAgICAgICBtaW5Qcm90b2NvbDogMyxcbiAgICAgICAgICAgbWF4UHJvdG9jb2w6IDMsXG4gICAgICAgICAgIGNsaWVudDoge1xuICAgICAgICAgICAgIGlkOiAnZ2F0ZXdheS1jbGllbnQnLFxuICAgICAgICAgICAgIG1vZGU6ICdiYWNrZW5kJyxcbiAgICAgICAgICAgICB2ZXJzaW9uOiAnMC4xLjEwJyxcbiAgICAgICAgICAgICBwbGF0Zm9ybTogJ2VsZWN0cm9uJyxcbiAgICAgICAgICAgfSxcbiAgICAgICAgICAgcm9sZTogJ29wZXJhdG9yJyxcbiAgICAgICAgICAgc2NvcGVzOiBbJ29wZXJhdG9yLnJlYWQnLCAnb3BlcmF0b3Iud3JpdGUnXSxcbiAgICAgICAgICAgZGV2aWNlOiB7XG4gICAgICAgICAgICAgaWQ6IGlkZW50aXR5LmlkLFxuICAgICAgICAgICAgIHB1YmxpY0tleTogaWRlbnRpdHkucHVibGljS2V5LFxuICAgICAgICAgICAgIHNpZ25hdHVyZTogc2lnLnNpZ25hdHVyZSxcbiAgICAgICAgICAgICBzaWduZWRBdDogc2lnbmVkQXRNcyxcbiAgICAgICAgICAgICBub25jZTogY29ubmVjdE5vbmNlLFxuICAgICAgICAgICB9LFxuICAgICAgICAgICBhdXRoOiB7XG4gICAgICAgICAgICAgdG9rZW46IHRoaXMudG9rZW4sXG4gICAgICAgICAgIH0sXG4gICAgICAgICB9KTtcblxuICAgICAgICAgdGhpcy5fc2V0U3RhdGUoJ2Nvbm5lY3RlZCcpO1xuICAgICAgICAgdGhpcy5yZWNvbm5lY3RBdHRlbXB0ID0gMDtcbiAgICAgICAgIGlmIChoYW5kc2hha2VUaW1lcikge1xuICAgICAgICAgICBjbGVhclRpbWVvdXQoaGFuZHNoYWtlVGltZXIpO1xuICAgICAgICAgICBoYW5kc2hha2VUaW1lciA9IG51bGw7XG4gICAgICAgICB9XG4gICAgICAgICB0aGlzLl9zdGFydEhlYXJ0YmVhdCgpO1xuICAgICAgfSBjYXRjaCAoZXJyKSB7XG4gICAgICAgIGNvbnNvbGUuZXJyb3IoJ1tvY2xhdy13c10gQ29ubmVjdCBoYW5kc2hha2UgZmFpbGVkJywgZXJyKTtcbiAgICAgICAgd3MuY2xvc2UoKTtcbiAgICAgIH1cbiAgICB9O1xuXG4gICAgbGV0IGhhbmRzaGFrZVRpbWVyOiBSZXR1cm5UeXBlPHR5cGVvZiBzZXRUaW1lb3V0PiB8IG51bGwgPSBudWxsO1xuXG4gICAgd3Mub25vcGVuID0gKCkgPT4ge1xuICAgICAgdGhpcy5fc2V0U3RhdGUoJ2hhbmRzaGFraW5nJyk7XG4gICAgICAvLyBUaGUgZ2F0ZXdheSB3aWxsIHNlbmQgY29ubmVjdC5jaGFsbGVuZ2U7IGNvbm5lY3QgaXMgc2VudCBvbmNlIHdlIGhhdmUgYSBub25jZS5cbiAgICAgIGlmIChoYW5kc2hha2VUaW1lcikgY2xlYXJUaW1lb3V0KGhhbmRzaGFrZVRpbWVyKTtcbiAgICAgIGhhbmRzaGFrZVRpbWVyID0gc2V0VGltZW91dCgoKSA9PiB7XG4gICAgICAgIC8vIElmIHdlIG5ldmVyIGdvdCB0aGUgY2hhbGxlbmdlIG5vbmNlLCBmb3JjZSByZWNvbm5lY3QuXG4gICAgICAgIGlmICh0aGlzLnN0YXRlID09PSAnaGFuZHNoYWtpbmcnICYmICF0aGlzLmludGVudGlvbmFsQ2xvc2UpIHtcbiAgICAgICAgICBjb25zb2xlLndhcm4oJ1tvY2xhdy13c10gSGFuZHNoYWtlIHRpbWVkIG91dCB3YWl0aW5nIGZvciBjb25uZWN0LmNoYWxsZW5nZScpO1xuICAgICAgICAgIHdzLmNsb3NlKCk7XG4gICAgICAgIH1cbiAgICAgIH0sIEhBTkRTSEFLRV9USU1FT1VUX01TKTtcbiAgICB9O1xuXG4gICAgd3Mub25tZXNzYWdlID0gKGV2ZW50OiBNZXNzYWdlRXZlbnQpID0+IHtcbiAgICAgIC8vIFdlYlNvY2tldCBvbm1lc3NhZ2UgY2Fubm90IGJlIGFzeW5jLCBidXQgd2UgY2FuIHJ1biBhbiBhc3luYyB0YXNrIGluc2lkZS5cbiAgICAgIHZvaWQgKGFzeW5jICgpID0+IHtcbiAgICAgICAgY29uc3Qgbm9ybWFsaXplZCA9IGF3YWl0IG5vcm1hbGl6ZVdzRGF0YVRvVGV4dChldmVudC5kYXRhKTtcbiAgICAgICAgaWYgKCFub3JtYWxpemVkLm9rKSB7XG4gICAgICAgICAgaWYgKG5vcm1hbGl6ZWQucmVhc29uID09PSAndG9vLWxhcmdlJykge1xuICAgICAgICAgICAgY29uc29sZS5lcnJvcignW29jbGF3LXdzXSBJbmJvdW5kIGZyYW1lIHRvbyBsYXJnZTsgY2xvc2luZyBjb25uZWN0aW9uJyk7XG4gICAgICAgICAgICB3cy5jbG9zZSgpO1xuICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBjb25zb2xlLmVycm9yKCdbb2NsYXctd3NdIFVuc3VwcG9ydGVkIGluYm91bmQgZnJhbWUgdHlwZTsgaWdub3JpbmcnKTtcbiAgICAgICAgICB9XG4gICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKG5vcm1hbGl6ZWQuYnl0ZXMgPiBNQVhfSU5CT1VORF9GUkFNRV9CWVRFUykge1xuICAgICAgICAgIGNvbnNvbGUuZXJyb3IoJ1tvY2xhdy13c10gSW5ib3VuZCBmcmFtZSB0b28gbGFyZ2U7IGNsb3NpbmcgY29ubmVjdGlvbicpO1xuICAgICAgICAgIHdzLmNsb3NlKCk7XG4gICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgbGV0IGZyYW1lOiBhbnk7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgZnJhbWUgPSBKU09OLnBhcnNlKG5vcm1hbGl6ZWQudGV4dCk7XG4gICAgICAgIH0gY2F0Y2gge1xuICAgICAgICAgIGNvbnNvbGUuZXJyb3IoJ1tvY2xhdy13c10gRmFpbGVkIHRvIHBhcnNlIGluY29taW5nIG1lc3NhZ2UnKTtcbiAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICAvLyBSZXNwb25zZXNcbiAgICAgICAgaWYgKGZyYW1lLnR5cGUgPT09ICdyZXMnKSB7XG4gICAgICAgICAgdGhpcy5faGFuZGxlUmVzcG9uc2VGcmFtZShmcmFtZSk7XG4gICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgLy8gRXZlbnRzXG4gICAgICAgIGlmIChmcmFtZS50eXBlID09PSAnZXZlbnQnKSB7XG4gICAgICAgICAgaWYgKGZyYW1lLmV2ZW50ID09PSAnY29ubmVjdC5jaGFsbGVuZ2UnKSB7XG4gICAgICAgICAgICBjb25uZWN0Tm9uY2UgPSBmcmFtZS5wYXlsb2FkPy5ub25jZSB8fCBudWxsO1xuICAgICAgICAgICAgLy8gQXR0ZW1wdCBoYW5kc2hha2Ugb25jZSB3ZSBoYXZlIGEgbm9uY2UuXG4gICAgICAgICAgICB2b2lkIHRyeUNvbm5lY3QoKTtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBpZiAoZnJhbWUuZXZlbnQgPT09ICdjaGF0Jykge1xuICAgICAgICAgICAgdGhpcy5faGFuZGxlQ2hhdEV2ZW50RnJhbWUoZnJhbWUpO1xuICAgICAgICAgIH1cbiAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICAvLyBBdm9pZCBsb2dnaW5nIGZ1bGwgZnJhbWVzIChtYXkgaW5jbHVkZSBtZXNzYWdlIGNvbnRlbnQgb3Igb3RoZXIgc2Vuc2l0aXZlIHBheWxvYWRzKS5cbiAgICAgICAgY29uc29sZS5kZWJ1ZygnW29jbGF3LXdzXSBVbmhhbmRsZWQgZnJhbWUnLCB7IHR5cGU6IGZyYW1lPy50eXBlLCBldmVudDogZnJhbWU/LmV2ZW50LCBpZDogZnJhbWU/LmlkIH0pO1xuICAgICAgfSkoKTtcbiAgICB9O1xuXG4gICAgY29uc3QgY2xlYXJIYW5kc2hha2VUaW1lciA9ICgpID0+IHtcbiAgICAgIGlmIChoYW5kc2hha2VUaW1lcikge1xuICAgICAgICBjbGVhclRpbWVvdXQoaGFuZHNoYWtlVGltZXIpO1xuICAgICAgICBoYW5kc2hha2VUaW1lciA9IG51bGw7XG4gICAgICB9XG4gICAgfTtcblxuICAgIHdzLm9uY2xvc2UgPSAoKSA9PiB7XG4gICAgICBjbGVhckhhbmRzaGFrZVRpbWVyKCk7XG4gICAgICB0aGlzLl9zdG9wVGltZXJzKCk7XG4gICAgICB0aGlzLmFjdGl2ZVJ1bklkID0gbnVsbDtcbiAgICAgIHRoaXMuYWJvcnRJbkZsaWdodCA9IG51bGw7XG4gICAgICB0aGlzLl9zZXRXb3JraW5nKGZhbHNlKTtcbiAgICAgIHRoaXMuX3NldFN0YXRlKCdkaXNjb25uZWN0ZWQnKTtcblxuICAgICAgZm9yIChjb25zdCBwZW5kaW5nIG9mIHRoaXMucGVuZGluZ1JlcXVlc3RzLnZhbHVlcygpKSB7XG4gICAgICAgIGlmIChwZW5kaW5nLnRpbWVvdXQpIGNsZWFyVGltZW91dChwZW5kaW5nLnRpbWVvdXQpO1xuICAgICAgICBwZW5kaW5nLnJlamVjdChuZXcgRXJyb3IoJ0Nvbm5lY3Rpb24gY2xvc2VkJykpO1xuICAgICAgfVxuICAgICAgdGhpcy5wZW5kaW5nUmVxdWVzdHMuY2xlYXIoKTtcblxuICAgICAgaWYgKCF0aGlzLmludGVudGlvbmFsQ2xvc2UpIHtcbiAgICAgICAgdGhpcy5fc2NoZWR1bGVSZWNvbm5lY3QoKTtcbiAgICAgIH1cbiAgICB9O1xuXG4gICAgd3Mub25lcnJvciA9IChldjogRXZlbnQpID0+IHtcbiAgICAgIGNsZWFySGFuZHNoYWtlVGltZXIoKTtcbiAgICAgIGNvbnNvbGUuZXJyb3IoJ1tvY2xhdy13c10gV2ViU29ja2V0IGVycm9yJywgZXYpO1xuICAgIH07XG4gIH1cblxuICBwcml2YXRlIF9oYW5kbGVSZXNwb25zZUZyYW1lKGZyYW1lOiBhbnkpOiB2b2lkIHtcbiAgICBjb25zdCBwZW5kaW5nID0gdGhpcy5wZW5kaW5nUmVxdWVzdHMuZ2V0KGZyYW1lLmlkKTtcbiAgICBpZiAoIXBlbmRpbmcpIHJldHVybjtcblxuICAgIHRoaXMucGVuZGluZ1JlcXVlc3RzLmRlbGV0ZShmcmFtZS5pZCk7XG4gICAgaWYgKHBlbmRpbmcudGltZW91dCkgY2xlYXJUaW1lb3V0KHBlbmRpbmcudGltZW91dCk7XG5cbiAgICBpZiAoZnJhbWUub2spIHBlbmRpbmcucmVzb2x2ZShmcmFtZS5wYXlsb2FkKTtcbiAgICBlbHNlIHBlbmRpbmcucmVqZWN0KG5ldyBFcnJvcihmcmFtZS5lcnJvcj8ubWVzc2FnZSB8fCAnUmVxdWVzdCBmYWlsZWQnKSk7XG4gIH1cblxuICBwcml2YXRlIF9oYW5kbGVDaGF0RXZlbnRGcmFtZShmcmFtZTogYW55KTogdm9pZCB7XG4gICAgY29uc3QgcGF5bG9hZCA9IGZyYW1lLnBheWxvYWQ7XG4gICAgY29uc3QgaW5jb21pbmdTZXNzaW9uS2V5ID0gU3RyaW5nKHBheWxvYWQ/LnNlc3Npb25LZXkgfHwgJycpO1xuICAgIGlmICghaW5jb21pbmdTZXNzaW9uS2V5IHx8ICFzZXNzaW9uS2V5TWF0Y2hlcyh0aGlzLnNlc3Npb25LZXksIGluY29taW5nU2Vzc2lvbktleSkpIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICAvLyBCZXN0LWVmZm9ydCBydW4gY29ycmVsYXRpb24gKGlmIGdhdGV3YXkgaW5jbHVkZXMgYSBydW4gaWQpLiBUaGlzIGF2b2lkcyBjbGVhcmluZyBvdXIgVUlcbiAgICAvLyBiYXNlZCBvbiBhIGRpZmZlcmVudCBjbGllbnQncyBydW4gaW4gdGhlIHNhbWUgc2Vzc2lvbi5cbiAgICBjb25zdCBpbmNvbWluZ1J1bklkID0gU3RyaW5nKHBheWxvYWQ/LnJ1bklkIHx8IHBheWxvYWQ/LmlkZW1wb3RlbmN5S2V5IHx8IHBheWxvYWQ/Lm1ldGE/LnJ1bklkIHx8ICcnKTtcbiAgICBpZiAodGhpcy5hY3RpdmVSdW5JZCAmJiBpbmNvbWluZ1J1bklkICYmIGluY29taW5nUnVuSWQgIT09IHRoaXMuYWN0aXZlUnVuSWQpIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICAvLyBBdm9pZCBkb3VibGUtcmVuZGVyOiBnYXRld2F5IGVtaXRzIGRlbHRhICsgZmluYWwgKyBhYm9ydGVkLiBSZW5kZXIgb25seSBleHBsaWNpdCBmaW5hbC9hYm9ydGVkLlxuICAgIC8vIElmIHN0YXRlIGlzIG1pc3NpbmcsIHRyZWF0IGFzIG5vbi10ZXJtaW5hbCAoZG8gbm90IGNsZWFyIFVJIC8gZG8gbm90IHJlbmRlcikuXG4gICAgaWYgKCFwYXlsb2FkPy5zdGF0ZSkge1xuICAgICAgcmV0dXJuO1xuICAgIH1cbiAgICBpZiAocGF5bG9hZC5zdGF0ZSAhPT0gJ2ZpbmFsJyAmJiBwYXlsb2FkLnN0YXRlICE9PSAnYWJvcnRlZCcpIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICAvLyBXZSBvbmx5IGFwcGVuZCBhc3Npc3RhbnQgb3V0cHV0IHRvIFVJLlxuICAgIGNvbnN0IG1zZyA9IHBheWxvYWQ/Lm1lc3NhZ2U7XG4gICAgY29uc3Qgcm9sZSA9IG1zZz8ucm9sZSA/PyAnYXNzaXN0YW50JztcblxuICAgIC8vIEFib3J0ZWQgZW5kcyB0aGUgcnVuIHJlZ2FyZGxlc3Mgb2Ygcm9sZS9tZXNzYWdlLlxuICAgIGlmIChwYXlsb2FkLnN0YXRlID09PSAnYWJvcnRlZCcpIHtcbiAgICAgIHRoaXMuYWN0aXZlUnVuSWQgPSBudWxsO1xuICAgICAgdGhpcy5fc2V0V29ya2luZyhmYWxzZSk7XG4gICAgICAvLyBBYm9ydGVkIG1heSBoYXZlIG5vIGFzc2lzdGFudCBtZXNzYWdlOyBpZiBub25lLCBzdG9wIGhlcmUuXG4gICAgICBpZiAoIW1zZykgcmV0dXJuO1xuICAgICAgLy8gSWYgdGhlcmUgaXMgYSBtZXNzYWdlLCBvbmx5IGFwcGVuZCBhc3Npc3RhbnQgb3V0cHV0LlxuICAgICAgaWYgKHJvbGUgIT09ICdhc3Npc3RhbnQnKSByZXR1cm47XG4gICAgfVxuXG4gICAgLy8gRmluYWwgc2hvdWxkIG9ubHkgY29tcGxldGUgdGhlIHJ1biB3aGVuIHRoZSBhc3Npc3RhbnQgY29tcGxldGVzLlxuICAgIGlmIChwYXlsb2FkLnN0YXRlID09PSAnZmluYWwnKSB7XG4gICAgICBpZiAocm9sZSAhPT0gJ2Fzc2lzdGFudCcpIHJldHVybjtcbiAgICAgIHRoaXMuYWN0aXZlUnVuSWQgPSBudWxsO1xuICAgICAgdGhpcy5fc2V0V29ya2luZyhmYWxzZSk7XG4gICAgfVxuXG4gICAgY29uc3QgdGV4dCA9IGV4dHJhY3RUZXh0RnJvbUdhdGV3YXlNZXNzYWdlKG1zZyk7XG4gICAgaWYgKCF0ZXh0KSByZXR1cm47XG5cbiAgICAvLyBPcHRpb25hbDogaGlkZSBoZWFydGJlYXQgYWNrcyAobm9pc2UgaW4gVUkpXG4gICAgaWYgKHRleHQudHJpbSgpID09PSAnSEVBUlRCRUFUX09LJykge1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIHRoaXMub25NZXNzYWdlPy4oe1xuICAgICAgdHlwZTogJ21lc3NhZ2UnLFxuICAgICAgcGF5bG9hZDoge1xuICAgICAgICBjb250ZW50OiB0ZXh0LFxuICAgICAgICByb2xlOiAnYXNzaXN0YW50JyxcbiAgICAgICAgdGltZXN0YW1wOiBEYXRlLm5vdygpLFxuICAgICAgfSxcbiAgICB9KTtcbiAgfVxuXG4gIHByaXZhdGUgX3NlbmRSZXF1ZXN0KG1ldGhvZDogc3RyaW5nLCBwYXJhbXM6IGFueSk6IFByb21pc2U8YW55PiB7XG4gICAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIGlmICghdGhpcy53cyB8fCB0aGlzLndzLnJlYWR5U3RhdGUgIT09IFdlYlNvY2tldC5PUEVOKSB7XG4gICAgICAgIHJlamVjdChuZXcgRXJyb3IoJ1dlYlNvY2tldCBub3QgY29ubmVjdGVkJykpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG5cbiAgICAgIGlmICh0aGlzLnBlbmRpbmdSZXF1ZXN0cy5zaXplID49IE1BWF9QRU5ESU5HX1JFUVVFU1RTKSB7XG4gICAgICAgIHJlamVjdChuZXcgRXJyb3IoYFRvbyBtYW55IGluLWZsaWdodCByZXF1ZXN0cyAoJHt0aGlzLnBlbmRpbmdSZXF1ZXN0cy5zaXplfSlgKSk7XG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cblxuICAgICAgY29uc3QgaWQgPSBgcmVxLSR7Kyt0aGlzLnJlcXVlc3RJZH1gO1xuXG4gICAgICBjb25zdCBwZW5kaW5nOiBQZW5kaW5nUmVxdWVzdCA9IHsgcmVzb2x2ZSwgcmVqZWN0LCB0aW1lb3V0OiBudWxsIH07XG4gICAgICB0aGlzLnBlbmRpbmdSZXF1ZXN0cy5zZXQoaWQsIHBlbmRpbmcpO1xuXG4gICAgICBjb25zdCBwYXlsb2FkID0gSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0eXBlOiAncmVxJyxcbiAgICAgICAgbWV0aG9kLFxuICAgICAgICBpZCxcbiAgICAgICAgcGFyYW1zLFxuICAgICAgfSk7XG5cbiAgICAgIHRyeSB7XG4gICAgICAgIHRoaXMud3Muc2VuZChwYXlsb2FkKTtcbiAgICAgIH0gY2F0Y2ggKGVycikge1xuICAgICAgICB0aGlzLnBlbmRpbmdSZXF1ZXN0cy5kZWxldGUoaWQpO1xuICAgICAgICByZWplY3QoZXJyKTtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuXG4gICAgICBwZW5kaW5nLnRpbWVvdXQgPSBzZXRUaW1lb3V0KCgpID0+IHtcbiAgICAgICAgaWYgKHRoaXMucGVuZGluZ1JlcXVlc3RzLmhhcyhpZCkpIHtcbiAgICAgICAgICB0aGlzLnBlbmRpbmdSZXF1ZXN0cy5kZWxldGUoaWQpO1xuICAgICAgICAgIHJlamVjdChuZXcgRXJyb3IoYFJlcXVlc3QgdGltZW91dDogJHttZXRob2R9YCkpO1xuICAgICAgICB9XG4gICAgICB9LCAzMF8wMDApO1xuICAgIH0pO1xuICB9XG5cbiAgcHJpdmF0ZSBfc2NoZWR1bGVSZWNvbm5lY3QoKTogdm9pZCB7XG4gICAgaWYgKHRoaXMucmVjb25uZWN0VGltZXIgIT09IG51bGwpIHJldHVybjtcblxuICAgIGNvbnN0IGF0dGVtcHQgPSArK3RoaXMucmVjb25uZWN0QXR0ZW1wdDtcbiAgICBjb25zdCBleHAgPSBNYXRoLm1pbihSRUNPTk5FQ1RfTUFYX01TLCBSRUNPTk5FQ1RfQkFTRV9NUyAqIE1hdGgucG93KDIsIGF0dGVtcHQgLSAxKSk7XG4gICAgLy8gSml0dGVyOiAwLjV4Li4xLjV4XG4gICAgY29uc3Qgaml0dGVyID0gMC41ICsgTWF0aC5yYW5kb20oKTtcbiAgICBjb25zdCBkZWxheSA9IE1hdGguZmxvb3IoZXhwICogaml0dGVyKTtcblxuICAgIHRoaXMucmVjb25uZWN0VGltZXIgPSBzZXRUaW1lb3V0KCgpID0+IHtcbiAgICAgIHRoaXMucmVjb25uZWN0VGltZXIgPSBudWxsO1xuICAgICAgaWYgKCF0aGlzLmludGVudGlvbmFsQ2xvc2UpIHtcbiAgICAgICAgY29uc29sZS5sb2coYFtvY2xhdy13c10gUmVjb25uZWN0aW5nIHRvICR7dGhpcy51cmx9XHUyMDI2IChhdHRlbXB0ICR7YXR0ZW1wdH0sICR7ZGVsYXl9bXMpYCk7XG4gICAgICAgIHRoaXMuX2Nvbm5lY3QoKTtcbiAgICAgIH1cbiAgICB9LCBkZWxheSk7XG4gIH1cblxuICBwcml2YXRlIGxhc3RCdWZmZXJlZFdhcm5BdE1zID0gMDtcblxuICBwcml2YXRlIF9zdGFydEhlYXJ0YmVhdCgpOiB2b2lkIHtcbiAgICB0aGlzLl9zdG9wSGVhcnRiZWF0KCk7XG4gICAgdGhpcy5oZWFydGJlYXRUaW1lciA9IHNldEludGVydmFsKCgpID0+IHtcbiAgICAgIGlmICh0aGlzLndzPy5yZWFkeVN0YXRlICE9PSBXZWJTb2NrZXQuT1BFTikgcmV0dXJuO1xuICAgICAgaWYgKHRoaXMud3MuYnVmZmVyZWRBbW91bnQgPiAwKSB7XG4gICAgICAgIGNvbnN0IG5vdyA9IERhdGUubm93KCk7XG4gICAgICAgIC8vIFRocm90dGxlIHRvIGF2b2lkIGxvZyBzcGFtIGluIGxvbmctcnVubmluZyBzZXNzaW9ucy5cbiAgICAgICAgaWYgKG5vdyAtIHRoaXMubGFzdEJ1ZmZlcmVkV2FybkF0TXMgPiA1ICogNjBfMDAwKSB7XG4gICAgICAgICAgdGhpcy5sYXN0QnVmZmVyZWRXYXJuQXRNcyA9IG5vdztcbiAgICAgICAgICBjb25zb2xlLndhcm4oJ1tvY2xhdy13c10gU2VuZCBidWZmZXIgbm90IGVtcHR5IFx1MjAxNCBjb25uZWN0aW9uIG1heSBiZSBzdGFsbGVkJyk7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9LCBIRUFSVEJFQVRfSU5URVJWQUxfTVMpO1xuICB9XG5cbiAgcHJpdmF0ZSBfc3RvcEhlYXJ0YmVhdCgpOiB2b2lkIHtcbiAgICBpZiAodGhpcy5oZWFydGJlYXRUaW1lcikge1xuICAgICAgY2xlYXJJbnRlcnZhbCh0aGlzLmhlYXJ0YmVhdFRpbWVyKTtcbiAgICAgIHRoaXMuaGVhcnRiZWF0VGltZXIgPSBudWxsO1xuICAgIH1cbiAgfVxuXG4gIHByaXZhdGUgX3N0b3BUaW1lcnMoKTogdm9pZCB7XG4gICAgdGhpcy5fc3RvcEhlYXJ0YmVhdCgpO1xuICAgIHRoaXMuX2Rpc2FybVdvcmtpbmdTYWZldHlUaW1lb3V0KCk7XG4gICAgaWYgKHRoaXMucmVjb25uZWN0VGltZXIpIHtcbiAgICAgIGNsZWFyVGltZW91dCh0aGlzLnJlY29ubmVjdFRpbWVyKTtcbiAgICAgIHRoaXMucmVjb25uZWN0VGltZXIgPSBudWxsO1xuICAgIH1cbiAgfVxuXG4gIHByaXZhdGUgX3NldFN0YXRlKHN0YXRlOiBXU0NsaWVudFN0YXRlKTogdm9pZCB7XG4gICAgaWYgKHRoaXMuc3RhdGUgPT09IHN0YXRlKSByZXR1cm47XG4gICAgdGhpcy5zdGF0ZSA9IHN0YXRlO1xuICAgIHRoaXMub25TdGF0ZUNoYW5nZT8uKHN0YXRlKTtcbiAgfVxuXG4gIHByaXZhdGUgX3NldFdvcmtpbmcod29ya2luZzogYm9vbGVhbik6IHZvaWQge1xuICAgIGlmICh0aGlzLndvcmtpbmcgPT09IHdvcmtpbmcpIHJldHVybjtcbiAgICB0aGlzLndvcmtpbmcgPSB3b3JraW5nO1xuICAgIHRoaXMub25Xb3JraW5nQ2hhbmdlPy4od29ya2luZyk7XG5cbiAgICBpZiAoIXdvcmtpbmcpIHtcbiAgICAgIHRoaXMuX2Rpc2FybVdvcmtpbmdTYWZldHlUaW1lb3V0KCk7XG4gICAgfVxuICB9XG5cbiAgcHJpdmF0ZSBfYXJtV29ya2luZ1NhZmV0eVRpbWVvdXQoKTogdm9pZCB7XG4gICAgdGhpcy5fZGlzYXJtV29ya2luZ1NhZmV0eVRpbWVvdXQoKTtcbiAgICB0aGlzLndvcmtpbmdUaW1lciA9IHNldFRpbWVvdXQoKCkgPT4ge1xuICAgICAgLy8gSWYgdGhlIGdhdGV3YXkgbmV2ZXIgZW1pdHMgYW4gYXNzaXN0YW50IGZpbmFsIHJlc3BvbnNlLCBkb25cdTIwMTl0IGxlYXZlIFVJIHN0dWNrLlxuICAgICAgdGhpcy5fc2V0V29ya2luZyhmYWxzZSk7XG4gICAgfSwgV09SS0lOR19NQVhfTVMpO1xuICB9XG5cbiAgcHJpdmF0ZSBfZGlzYXJtV29ya2luZ1NhZmV0eVRpbWVvdXQoKTogdm9pZCB7XG4gICAgaWYgKHRoaXMud29ya2luZ1RpbWVyKSB7XG4gICAgICBjbGVhclRpbWVvdXQodGhpcy53b3JraW5nVGltZXIpO1xuICAgICAgdGhpcy53b3JraW5nVGltZXIgPSBudWxsO1xuICAgIH1cbiAgfVxufVxuIiwgImltcG9ydCB0eXBlIHsgQ2hhdE1lc3NhZ2UgfSBmcm9tICcuL3R5cGVzJztcblxuLyoqIE1hbmFnZXMgdGhlIGluLW1lbW9yeSBsaXN0IG9mIGNoYXQgbWVzc2FnZXMgYW5kIG5vdGlmaWVzIFVJIG9uIGNoYW5nZXMgKi9cbmV4cG9ydCBjbGFzcyBDaGF0TWFuYWdlciB7XG4gIHByaXZhdGUgbWVzc2FnZXM6IENoYXRNZXNzYWdlW10gPSBbXTtcblxuICAvKiogRmlyZWQgZm9yIGEgZnVsbCByZS1yZW5kZXIgKGNsZWFyL3JlbG9hZCkgKi9cbiAgb25VcGRhdGU6ICgobWVzc2FnZXM6IHJlYWRvbmx5IENoYXRNZXNzYWdlW10pID0+IHZvaWQpIHwgbnVsbCA9IG51bGw7XG4gIC8qKiBGaXJlZCB3aGVuIGEgc2luZ2xlIG1lc3NhZ2UgaXMgYXBwZW5kZWQgXHUyMDE0IHVzZSBmb3IgTygxKSBhcHBlbmQtb25seSBVSSAqL1xuICBvbk1lc3NhZ2VBZGRlZDogKChtc2c6IENoYXRNZXNzYWdlKSA9PiB2b2lkKSB8IG51bGwgPSBudWxsO1xuXG4gIGFkZE1lc3NhZ2UobXNnOiBDaGF0TWVzc2FnZSk6IHZvaWQge1xuICAgIHRoaXMubWVzc2FnZXMucHVzaChtc2cpO1xuICAgIHRoaXMub25NZXNzYWdlQWRkZWQ/Lihtc2cpO1xuICB9XG5cbiAgZ2V0TWVzc2FnZXMoKTogcmVhZG9ubHkgQ2hhdE1lc3NhZ2VbXSB7XG4gICAgcmV0dXJuIHRoaXMubWVzc2FnZXM7XG4gIH1cblxuICBjbGVhcigpOiB2b2lkIHtcbiAgICB0aGlzLm1lc3NhZ2VzID0gW107XG4gICAgdGhpcy5vblVwZGF0ZT8uKFtdKTtcbiAgfVxuXG4gIC8qKiBDcmVhdGUgYSB1c2VyIG1lc3NhZ2Ugb2JqZWN0ICh3aXRob3V0IGFkZGluZyBpdCkgKi9cbiAgc3RhdGljIGNyZWF0ZVVzZXJNZXNzYWdlKGNvbnRlbnQ6IHN0cmluZyk6IENoYXRNZXNzYWdlIHtcbiAgICByZXR1cm4ge1xuICAgICAgaWQ6IGBtc2ctJHtEYXRlLm5vdygpfS0ke01hdGgucmFuZG9tKCkudG9TdHJpbmcoMzYpLnNsaWNlKDIsIDcpfWAsXG4gICAgICByb2xlOiAndXNlcicsXG4gICAgICBjb250ZW50LFxuICAgICAgdGltZXN0YW1wOiBEYXRlLm5vdygpLFxuICAgIH07XG4gIH1cblxuICAvKiogQ3JlYXRlIGFuIGFzc2lzdGFudCBtZXNzYWdlIG9iamVjdCAod2l0aG91dCBhZGRpbmcgaXQpICovXG4gIHN0YXRpYyBjcmVhdGVBc3Npc3RhbnRNZXNzYWdlKGNvbnRlbnQ6IHN0cmluZyk6IENoYXRNZXNzYWdlIHtcbiAgICByZXR1cm4ge1xuICAgICAgaWQ6IGBtc2ctJHtEYXRlLm5vdygpfS0ke01hdGgucmFuZG9tKCkudG9TdHJpbmcoMzYpLnNsaWNlKDIsIDcpfWAsXG4gICAgICByb2xlOiAnYXNzaXN0YW50JyxcbiAgICAgIGNvbnRlbnQsXG4gICAgICB0aW1lc3RhbXA6IERhdGUubm93KCksXG4gICAgfTtcbiAgfVxuXG4gIC8qKiBDcmVhdGUgYSBzeXN0ZW0gLyBzdGF0dXMgbWVzc2FnZSAoZXJyb3JzLCByZWNvbm5lY3Qgbm90aWNlcywgZXRjLikgKi9cbiAgc3RhdGljIGNyZWF0ZVN5c3RlbU1lc3NhZ2UoY29udGVudDogc3RyaW5nLCBsZXZlbDogQ2hhdE1lc3NhZ2VbJ2xldmVsJ10gPSAnaW5mbycpOiBDaGF0TWVzc2FnZSB7XG4gICAgcmV0dXJuIHtcbiAgICAgIGlkOiBgc3lzLSR7RGF0ZS5ub3coKX1gLFxuICAgICAgcm9sZTogJ3N5c3RlbScsXG4gICAgICBsZXZlbCxcbiAgICAgIGNvbnRlbnQsXG4gICAgICB0aW1lc3RhbXA6IERhdGUubm93KCksXG4gICAgfTtcbiAgfVxuXG4gIHN0YXRpYyBjcmVhdGVTZXNzaW9uRGl2aWRlcihzZXNzaW9uS2V5OiBzdHJpbmcpOiBDaGF0TWVzc2FnZSB7XG4gICAgY29uc3Qgc2hvcnQgPSBzZXNzaW9uS2V5Lmxlbmd0aCA+IDI4ID8gYCR7c2Vzc2lvbktleS5zbGljZSgwLCAxMil9XHUyMDI2JHtzZXNzaW9uS2V5LnNsaWNlKC0xMil9YCA6IHNlc3Npb25LZXk7XG4gICAgcmV0dXJuIHtcbiAgICAgIGlkOiBgZGl2LSR7RGF0ZS5ub3coKX1gLFxuICAgICAgcm9sZTogJ3N5c3RlbScsXG4gICAgICBsZXZlbDogJ2luZm8nLFxuICAgICAga2luZDogJ3Nlc3Npb24tZGl2aWRlcicsXG4gICAgICB0aXRsZTogc2Vzc2lvbktleSxcbiAgICAgIGNvbnRlbnQ6IGBbU2Vzc2lvbjogJHtzaG9ydH1dYCxcbiAgICAgIHRpbWVzdGFtcDogRGF0ZS5ub3coKSxcbiAgICB9O1xuICB9XG59XG4iLCAiaW1wb3J0IHsgSXRlbVZpZXcsIE1hcmtkb3duUmVuZGVyZXIsIE1vZGFsLCBOb3RpY2UsIFNldHRpbmcsIFRGaWxlLCBXb3Jrc3BhY2VMZWFmIH0gZnJvbSAnb2JzaWRpYW4nO1xuaW1wb3J0IHR5cGUgT3BlbkNsYXdQbHVnaW4gZnJvbSAnLi9tYWluJztcbmltcG9ydCB7IENoYXRNYW5hZ2VyIH0gZnJvbSAnLi9jaGF0JztcbmltcG9ydCB0eXBlIHsgQ2hhdE1lc3NhZ2UsIFBhdGhNYXBwaW5nIH0gZnJvbSAnLi90eXBlcyc7XG5pbXBvcnQgeyBleHRyYWN0Q2FuZGlkYXRlcywgdHJ5TWFwUmVtb3RlUGF0aFRvVmF1bHRQYXRoIH0gZnJvbSAnLi9saW5raWZ5JztcbmltcG9ydCB7IGdldEFjdGl2ZU5vdGVDb250ZXh0IH0gZnJvbSAnLi9jb250ZXh0JztcblxuZXhwb3J0IGNvbnN0IFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFUID0gJ29wZW5jbGF3LWNoYXQnO1xuXG5jbGFzcyBOZXdTZXNzaW9uTW9kYWwgZXh0ZW5kcyBNb2RhbCB7XG4gIHByaXZhdGUgaW5pdGlhbFZhbHVlOiBzdHJpbmc7XG4gIHByaXZhdGUgb25TdWJtaXQ6ICh2YWx1ZTogc3RyaW5nKSA9PiB2b2lkO1xuXG4gIGNvbnN0cnVjdG9yKHZpZXc6IE9wZW5DbGF3Q2hhdFZpZXcsIGluaXRpYWxWYWx1ZTogc3RyaW5nLCBvblN1Ym1pdDogKHZhbHVlOiBzdHJpbmcpID0+IHZvaWQpIHtcbiAgICBzdXBlcih2aWV3LmFwcCk7XG4gICAgdGhpcy5pbml0aWFsVmFsdWUgPSBpbml0aWFsVmFsdWU7XG4gICAgdGhpcy5vblN1Ym1pdCA9IG9uU3VibWl0O1xuICB9XG5cbiAgb25PcGVuKCk6IHZvaWQge1xuICAgIGNvbnN0IHsgY29udGVudEVsIH0gPSB0aGlzO1xuICAgIGNvbnRlbnRFbC5lbXB0eSgpO1xuXG4gICAgY29udGVudEVsLmNyZWF0ZUVsKCdoMycsIHsgdGV4dDogJ05ldyBzZXNzaW9uIGtleScgfSk7XG5cbiAgICBsZXQgdmFsdWUgPSB0aGlzLmluaXRpYWxWYWx1ZTtcblxuICAgIG5ldyBTZXR0aW5nKGNvbnRlbnRFbClcbiAgICAgIC5zZXROYW1lKCdTZXNzaW9uIGtleScpXG4gICAgICAuc2V0RGVzYygnVGlwOiBrZWVwIGl0IE9ic2lkaWFuLXNwZWNpZmljIChlLmcuIG9ic2lkaWFuLVlZWVlNTURELUhITU0pLicpXG4gICAgICAuYWRkVGV4dCgodCkgPT4ge1xuICAgICAgICB0LnNldFZhbHVlKHZhbHVlKTtcbiAgICAgICAgdC5vbkNoYW5nZSgodikgPT4ge1xuICAgICAgICAgIHZhbHVlID0gdjtcbiAgICAgICAgfSk7XG4gICAgICB9KTtcblxuICAgIG5ldyBTZXR0aW5nKGNvbnRlbnRFbClcbiAgICAgIC5hZGRCdXR0b24oKGIpID0+IHtcbiAgICAgICAgYi5zZXRCdXR0b25UZXh0KCdDYW5jZWwnKTtcbiAgICAgICAgYi5vbkNsaWNrKCgpID0+IHRoaXMuY2xvc2UoKSk7XG4gICAgICB9KVxuICAgICAgLmFkZEJ1dHRvbigoYikgPT4ge1xuICAgICAgICBiLnNldEN0YSgpO1xuICAgICAgICBiLnNldEJ1dHRvblRleHQoJ0NyZWF0ZScpO1xuICAgICAgICBiLm9uQ2xpY2soKCkgPT4ge1xuICAgICAgICAgIHRoaXMub25TdWJtaXQodmFsdWUpO1xuICAgICAgICAgIHRoaXMuY2xvc2UoKTtcbiAgICAgICAgfSk7XG4gICAgICB9KTtcbiAgfVxufVxuXG5leHBvcnQgY2xhc3MgT3BlbkNsYXdDaGF0VmlldyBleHRlbmRzIEl0ZW1WaWV3IHtcbiAgcHJpdmF0ZSBwbHVnaW46IE9wZW5DbGF3UGx1Z2luO1xuICBwcml2YXRlIGNoYXRNYW5hZ2VyOiBDaGF0TWFuYWdlcjtcblxuICAvLyBTdGF0ZVxuICBwcml2YXRlIGlzQ29ubmVjdGVkID0gZmFsc2U7XG4gIHByaXZhdGUgaXNXb3JraW5nID0gZmFsc2U7XG5cbiAgLy8gQ29ubmVjdGlvbiBub3RpY2VzIChhdm9pZCBzcGFtKVxuICBwcml2YXRlIGxhc3RDb25uTm90aWNlQXRNcyA9IDA7XG4gIHByaXZhdGUgbGFzdEdhdGV3YXlTdGF0ZTogc3RyaW5nIHwgbnVsbCA9IG51bGw7XG5cbiAgLy8gRE9NIHJlZnNcbiAgcHJpdmF0ZSBtZXNzYWdlc0VsITogSFRNTEVsZW1lbnQ7XG4gIHByaXZhdGUgaW5wdXRFbCE6IEhUTUxUZXh0QXJlYUVsZW1lbnQ7XG4gIHByaXZhdGUgc2VuZEJ0biE6IEhUTUxCdXR0b25FbGVtZW50O1xuICBwcml2YXRlIGluY2x1ZGVOb3RlQ2hlY2tib3ghOiBIVE1MSW5wdXRFbGVtZW50O1xuICBwcml2YXRlIHN0YXR1c0RvdCE6IEhUTUxFbGVtZW50O1xuXG4gIHByaXZhdGUgc2Vzc2lvblNlbGVjdCE6IEhUTUxTZWxlY3RFbGVtZW50O1xuICBwcml2YXRlIHNlc3Npb25SZWZyZXNoQnRuITogSFRNTEJ1dHRvbkVsZW1lbnQ7XG4gIHByaXZhdGUgc2Vzc2lvbk5ld0J0biE6IEhUTUxCdXR0b25FbGVtZW50O1xuICBwcml2YXRlIHNlc3Npb25NYWluQnRuITogSFRNTEJ1dHRvbkVsZW1lbnQ7XG5cbiAgcHJpdmF0ZSBvbk1lc3NhZ2VzQ2xpY2s6ICgoZXY6IE1vdXNlRXZlbnQpID0+IHZvaWQpIHwgbnVsbCA9IG51bGw7XG5cbiAgY29uc3RydWN0b3IobGVhZjogV29ya3NwYWNlTGVhZiwgcGx1Z2luOiBPcGVuQ2xhd1BsdWdpbikge1xuICAgIHN1cGVyKGxlYWYpO1xuICAgIHRoaXMucGx1Z2luID0gcGx1Z2luO1xuICAgIHRoaXMuY2hhdE1hbmFnZXIgPSBwbHVnaW4uY2hhdE1hbmFnZXI7XG4gIH1cblxuICBnZXRWaWV3VHlwZSgpOiBzdHJpbmcge1xuICAgIHJldHVybiBWSUVXX1RZUEVfT1BFTkNMQVdfQ0hBVDtcbiAgfVxuXG4gIGdldERpc3BsYXlUZXh0KCk6IHN0cmluZyB7XG4gICAgcmV0dXJuICdPcGVuQ2xhdyBDaGF0JztcbiAgfVxuXG4gIGdldEljb24oKTogc3RyaW5nIHtcbiAgICByZXR1cm4gJ21lc3NhZ2Utc3F1YXJlJztcbiAgfVxuXG4gIGFzeW5jIG9uT3BlbigpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICB0aGlzLl9idWlsZFVJKCk7XG5cbiAgICAvLyBGdWxsIHJlLXJlbmRlciBvbiBjbGVhciAvIHJlbG9hZFxuICAgIHRoaXMuY2hhdE1hbmFnZXIub25VcGRhdGUgPSAobXNncykgPT4gdGhpcy5fcmVuZGVyTWVzc2FnZXMobXNncyk7XG4gICAgLy8gTygxKSBhcHBlbmQgZm9yIG5ldyBtZXNzYWdlc1xuICAgIHRoaXMuY2hhdE1hbmFnZXIub25NZXNzYWdlQWRkZWQgPSAobXNnKSA9PiB0aGlzLl9hcHBlbmRNZXNzYWdlKG1zZyk7XG5cbiAgICAvLyBTdWJzY3JpYmUgdG8gV1Mgc3RhdGUgY2hhbmdlc1xuICAgIHRoaXMucGx1Z2luLndzQ2xpZW50Lm9uU3RhdGVDaGFuZ2UgPSAoc3RhdGUpID0+IHtcbiAgICAgIC8vIENvbm5lY3Rpb24gbG9zcyAvIHJlY29ubmVjdCBub3RpY2VzICh0aHJvdHRsZWQpXG4gICAgICBjb25zdCBwcmV2ID0gdGhpcy5sYXN0R2F0ZXdheVN0YXRlO1xuICAgICAgdGhpcy5sYXN0R2F0ZXdheVN0YXRlID0gc3RhdGU7XG5cbiAgICAgIGNvbnN0IG5vdyA9IERhdGUubm93KCk7XG4gICAgICBjb25zdCBOT1RJQ0VfVEhST1RUTEVfTVMgPSA2MF8wMDA7XG5cbiAgICAgIGNvbnN0IHNob3VsZE5vdGlmeSA9ICgpID0+IG5vdyAtIHRoaXMubGFzdENvbm5Ob3RpY2VBdE1zID4gTk9USUNFX1RIUk9UVExFX01TO1xuICAgICAgY29uc3Qgbm90aWZ5ID0gKHRleHQ6IHN0cmluZykgPT4ge1xuICAgICAgICBpZiAoIXNob3VsZE5vdGlmeSgpKSByZXR1cm47XG4gICAgICAgIHRoaXMubGFzdENvbm5Ob3RpY2VBdE1zID0gbm93O1xuICAgICAgICBuZXcgTm90aWNlKHRleHQpO1xuICAgICAgfTtcblxuICAgICAgLy8gT25seSBzaG93IFx1MjAxQ2xvc3RcdTIwMUQgaWYgd2Ugd2VyZSBwcmV2aW91c2x5IGNvbm5lY3RlZC5cbiAgICAgIGlmIChwcmV2ID09PSAnY29ubmVjdGVkJyAmJiBzdGF0ZSA9PT0gJ2Rpc2Nvbm5lY3RlZCcpIHtcbiAgICAgICAgbm90aWZ5KCdPcGVuQ2xhdyBDaGF0OiBjb25uZWN0aW9uIGxvc3QgXHUyMDE0IHJlY29ubmVjdGluZ1x1MjAyNicpO1xuICAgICAgICAvLyBBbHNvIGFwcGVuZCBhIHN5c3RlbSBtZXNzYWdlIHNvIGl0XHUyMDE5cyB2aXNpYmxlIGluIHRoZSBjaGF0IGhpc3RvcnkuXG4gICAgICAgIHRoaXMuY2hhdE1hbmFnZXIuYWRkTWVzc2FnZShDaGF0TWFuYWdlci5jcmVhdGVTeXN0ZW1NZXNzYWdlKCdcdTI2QTAgQ29ubmVjdGlvbiBsb3N0IFx1MjAxNCByZWNvbm5lY3RpbmdcdTIwMjYnLCAnZXJyb3InKSk7XG4gICAgICB9XG5cbiAgICAgIC8vIE9wdGlvbmFsIFx1MjAxQ3JlY29ubmVjdGVkXHUyMDFEIG5vdGljZVxuICAgICAgaWYgKHByZXYgJiYgcHJldiAhPT0gJ2Nvbm5lY3RlZCcgJiYgc3RhdGUgPT09ICdjb25uZWN0ZWQnKSB7XG4gICAgICAgIG5vdGlmeSgnT3BlbkNsYXcgQ2hhdDogcmVjb25uZWN0ZWQnKTtcbiAgICAgICAgdGhpcy5jaGF0TWFuYWdlci5hZGRNZXNzYWdlKENoYXRNYW5hZ2VyLmNyZWF0ZVN5c3RlbU1lc3NhZ2UoJ1x1MjcwNSBSZWNvbm5lY3RlZCcsICdpbmZvJykpO1xuICAgICAgfVxuXG4gICAgICB0aGlzLmlzQ29ubmVjdGVkID0gc3RhdGUgPT09ICdjb25uZWN0ZWQnO1xuICAgICAgdGhpcy5zdGF0dXNEb3QudG9nZ2xlQ2xhc3MoJ2Nvbm5lY3RlZCcsIHRoaXMuaXNDb25uZWN0ZWQpO1xuICAgICAgdGhpcy5zdGF0dXNEb3QudGl0bGUgPSBgR2F0ZXdheTogJHtzdGF0ZX1gO1xuICAgICAgdGhpcy5fdXBkYXRlU2VuZEJ1dHRvbigpO1xuICAgIH07XG5cbiAgICAvLyBTdWJzY3JpYmUgdG8gXHUyMDFDd29ya2luZ1x1MjAxRCAocmVxdWVzdC1pbi1mbGlnaHQpIHN0YXRlXG4gICAgdGhpcy5wbHVnaW4ud3NDbGllbnQub25Xb3JraW5nQ2hhbmdlID0gKHdvcmtpbmcpID0+IHtcbiAgICAgIHRoaXMuaXNXb3JraW5nID0gd29ya2luZztcbiAgICAgIHRoaXMuX3VwZGF0ZVNlbmRCdXR0b24oKTtcbiAgICB9O1xuXG4gICAgLy8gUmVmbGVjdCBjdXJyZW50IHN0YXRlXG4gICAgdGhpcy5sYXN0R2F0ZXdheVN0YXRlID0gdGhpcy5wbHVnaW4ud3NDbGllbnQuc3RhdGU7XG4gICAgdGhpcy5pc0Nvbm5lY3RlZCA9IHRoaXMucGx1Z2luLndzQ2xpZW50LnN0YXRlID09PSAnY29ubmVjdGVkJztcbiAgICB0aGlzLnN0YXR1c0RvdC50b2dnbGVDbGFzcygnY29ubmVjdGVkJywgdGhpcy5pc0Nvbm5lY3RlZCk7XG4gICAgdGhpcy5zdGF0dXNEb3QudGl0bGUgPSBgR2F0ZXdheTogJHt0aGlzLnBsdWdpbi53c0NsaWVudC5zdGF0ZX1gO1xuICAgIHRoaXMuX3VwZGF0ZVNlbmRCdXR0b24oKTtcblxuICAgIHRoaXMuX3JlbmRlck1lc3NhZ2VzKHRoaXMuY2hhdE1hbmFnZXIuZ2V0TWVzc2FnZXMoKSk7XG5cbiAgICAvLyBTZXNzaW9uIGRyb3Bkb3duIHBvcHVsYXRpb24gaXMgYmVzdC1lZmZvcnQuXG4gICAgdm9pZCB0aGlzLl9yZWZyZXNoU2Vzc2lvbnMoKTtcbiAgfVxuXG4gIGFzeW5jIG9uQ2xvc2UoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgdGhpcy5jaGF0TWFuYWdlci5vblVwZGF0ZSA9IG51bGw7XG4gICAgdGhpcy5jaGF0TWFuYWdlci5vbk1lc3NhZ2VBZGRlZCA9IG51bGw7XG4gICAgdGhpcy5wbHVnaW4ud3NDbGllbnQub25TdGF0ZUNoYW5nZSA9IG51bGw7XG4gICAgdGhpcy5wbHVnaW4ud3NDbGllbnQub25Xb3JraW5nQ2hhbmdlID0gbnVsbDtcblxuICAgIGlmICh0aGlzLm9uTWVzc2FnZXNDbGljaykge1xuICAgICAgdGhpcy5tZXNzYWdlc0VsPy5yZW1vdmVFdmVudExpc3RlbmVyKCdjbGljaycsIHRoaXMub25NZXNzYWdlc0NsaWNrKTtcbiAgICAgIHRoaXMub25NZXNzYWdlc0NsaWNrID0gbnVsbDtcbiAgICB9XG4gIH1cblxuICAvLyBcdTI1MDBcdTI1MDAgVUkgY29uc3RydWN0aW9uIFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFxuXG4gIHByaXZhdGUgX2J1aWxkVUkoKTogdm9pZCB7XG4gICAgY29uc3Qgcm9vdCA9IHRoaXMuY29udGVudEVsO1xuICAgIHJvb3QuZW1wdHkoKTtcbiAgICByb290LmFkZENsYXNzKCdvY2xhdy1jaGF0LXZpZXcnKTtcblxuICAgIC8vIFx1MjUwMFx1MjUwMCBIZWFkZXIgXHUyNTAwXHUyNTAwXG4gICAgY29uc3QgaGVhZGVyID0gcm9vdC5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1oZWFkZXInIH0pO1xuICAgIGhlYWRlci5jcmVhdGVTcGFuKHsgY2xzOiAnb2NsYXctaGVhZGVyLXRpdGxlJywgdGV4dDogJ09wZW5DbGF3IENoYXQnIH0pO1xuICAgIHRoaXMuc3RhdHVzRG90ID0gaGVhZGVyLmNyZWF0ZURpdih7IGNsczogJ29jbGF3LXN0YXR1cy1kb3QnIH0pO1xuICAgIHRoaXMuc3RhdHVzRG90LnRpdGxlID0gJ0dhdGV3YXk6IGRpc2Nvbm5lY3RlZCc7XG5cbiAgICAvLyBcdTI1MDBcdTI1MDAgU2Vzc2lvbiByb3cgXHUyNTAwXHUyNTAwXG4gICAgY29uc3Qgc2Vzc1JvdyA9IHJvb3QuY3JlYXRlRGl2KHsgY2xzOiAnb2NsYXctc2Vzc2lvbi1yb3cnIH0pO1xuICAgIHNlc3NSb3cuY3JlYXRlU3Bhbih7IGNsczogJ29jbGF3LXNlc3Npb24tbGFiZWwnLCB0ZXh0OiAnU2Vzc2lvbicgfSk7XG5cbiAgICB0aGlzLnNlc3Npb25TZWxlY3QgPSBzZXNzUm93LmNyZWF0ZUVsKCdzZWxlY3QnLCB7IGNsczogJ29jbGF3LXNlc3Npb24tc2VsZWN0JyB9KTtcbiAgICB0aGlzLnNlc3Npb25SZWZyZXNoQnRuID0gc2Vzc1Jvdy5jcmVhdGVFbCgnYnV0dG9uJywgeyBjbHM6ICdvY2xhdy1zZXNzaW9uLWJ0bicsIHRleHQ6ICdSZWZyZXNoJyB9KTtcbiAgICB0aGlzLnNlc3Npb25OZXdCdG4gPSBzZXNzUm93LmNyZWF0ZUVsKCdidXR0b24nLCB7IGNsczogJ29jbGF3LXNlc3Npb24tYnRuJywgdGV4dDogJ05ld1x1MjAyNicgfSk7XG4gICAgdGhpcy5zZXNzaW9uTWFpbkJ0biA9IHNlc3NSb3cuY3JlYXRlRWwoJ2J1dHRvbicsIHsgY2xzOiAnb2NsYXctc2Vzc2lvbi1idG4nLCB0ZXh0OiAnTWFpbicgfSk7XG5cbiAgICB0aGlzLnNlc3Npb25SZWZyZXNoQnRuLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gdm9pZCB0aGlzLl9yZWZyZXNoU2Vzc2lvbnMoKSk7XG4gICAgdGhpcy5zZXNzaW9uTmV3QnRuLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gdm9pZCB0aGlzLl9wcm9tcHROZXdTZXNzaW9uKCkpO1xuICAgIHRoaXMuc2Vzc2lvbk1haW5CdG4uYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKSA9PiB2b2lkIHRoaXMucGx1Z2luLnN3aXRjaFNlc3Npb24oJ21haW4nKSk7XG4gICAgdGhpcy5zZXNzaW9uU2VsZWN0LmFkZEV2ZW50TGlzdGVuZXIoJ2NoYW5nZScsICgpID0+IHtcbiAgICAgIGNvbnN0IG5leHQgPSB0aGlzLnNlc3Npb25TZWxlY3QudmFsdWU7XG4gICAgICBpZiAoIW5leHQgfHwgbmV4dCA9PT0gdGhpcy5wbHVnaW4uc2V0dGluZ3Muc2Vzc2lvbktleSkgcmV0dXJuO1xuICAgICAgdm9pZCB0aGlzLnBsdWdpbi5zd2l0Y2hTZXNzaW9uKG5leHQpO1xuICAgIH0pO1xuXG4gICAgLy8gXHUyNTAwXHUyNTAwIE1lc3NhZ2VzIGFyZWEgXHUyNTAwXHUyNTAwXG4gICAgdGhpcy5tZXNzYWdlc0VsID0gcm9vdC5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1tZXNzYWdlcycgfSk7XG5cbiAgICAvLyBEZWxlZ2F0ZSBpbnRlcm5hbC1saW5rIGNsaWNrcyAoTWFya2Rvd25SZW5kZXJlciBvdXRwdXQpIHRvIGEgcmVsaWFibGUgb3BlbkZpbGUgaGFuZGxlci5cbiAgICB0aGlzLl9pbnN0YWxsSW50ZXJuYWxMaW5rRGVsZWdhdGlvbigpO1xuXG4gICAgLy8gXHUyNTAwXHUyNTAwIENvbnRleHQgcm93IFx1MjUwMFx1MjUwMFxuICAgIGNvbnN0IGN0eFJvdyA9IHJvb3QuY3JlYXRlRGl2KHsgY2xzOiAnb2NsYXctY29udGV4dC1yb3cnIH0pO1xuICAgIHRoaXMuaW5jbHVkZU5vdGVDaGVja2JveCA9IGN0eFJvdy5jcmVhdGVFbCgnaW5wdXQnLCB7IHR5cGU6ICdjaGVja2JveCcgfSk7XG4gICAgdGhpcy5pbmNsdWRlTm90ZUNoZWNrYm94LmlkID0gJ29jbGF3LWluY2x1ZGUtbm90ZSc7XG4gICAgdGhpcy5pbmNsdWRlTm90ZUNoZWNrYm94LmNoZWNrZWQgPSB0aGlzLnBsdWdpbi5zZXR0aW5ncy5pbmNsdWRlQWN0aXZlTm90ZTtcbiAgICBjb25zdCBjdHhMYWJlbCA9IGN0eFJvdy5jcmVhdGVFbCgnbGFiZWwnLCB7IHRleHQ6ICdJbmNsdWRlIGFjdGl2ZSBub3RlJyB9KTtcbiAgICBjdHhMYWJlbC5odG1sRm9yID0gJ29jbGF3LWluY2x1ZGUtbm90ZSc7XG5cbiAgICAvLyBcdTI1MDBcdTI1MDAgSW5wdXQgcm93IFx1MjUwMFx1MjUwMFxuICAgIGNvbnN0IGlucHV0Um93ID0gcm9vdC5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1pbnB1dC1yb3cnIH0pO1xuICAgIHRoaXMuaW5wdXRFbCA9IGlucHV0Um93LmNyZWF0ZUVsKCd0ZXh0YXJlYScsIHtcbiAgICAgIGNsczogJ29jbGF3LWlucHV0JyxcbiAgICAgIHBsYWNlaG9sZGVyOiAnQXNrIGFueXRoaW5nXHUyMDI2JyxcbiAgICB9KTtcbiAgICB0aGlzLmlucHV0RWwucm93cyA9IDE7XG5cbiAgICB0aGlzLnNlbmRCdG4gPSBpbnB1dFJvdy5jcmVhdGVFbCgnYnV0dG9uJywgeyBjbHM6ICdvY2xhdy1zZW5kLWJ0bicsIHRleHQ6ICdTZW5kJyB9KTtcblxuICAgIC8vIFx1MjUwMFx1MjUwMCBFdmVudCBsaXN0ZW5lcnMgXHUyNTAwXHUyNTAwXG4gICAgdGhpcy5zZW5kQnRuLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gdGhpcy5faGFuZGxlU2VuZCgpKTtcbiAgICB0aGlzLmlucHV0RWwuYWRkRXZlbnRMaXN0ZW5lcigna2V5ZG93bicsIChlKSA9PiB7XG4gICAgICBpZiAoZS5rZXkgPT09ICdFbnRlcicgJiYgIWUuc2hpZnRLZXkpIHtcbiAgICAgICAgZS5wcmV2ZW50RGVmYXVsdCgpO1xuICAgICAgICB0aGlzLl9oYW5kbGVTZW5kKCk7XG4gICAgICB9XG4gICAgfSk7XG4gICAgLy8gQXV0by1yZXNpemUgdGV4dGFyZWFcbiAgICB0aGlzLmlucHV0RWwuYWRkRXZlbnRMaXN0ZW5lcignaW5wdXQnLCAoKSA9PiB7XG4gICAgICB0aGlzLmlucHV0RWwuc3R5bGUuaGVpZ2h0ID0gJ2F1dG8nO1xuICAgICAgdGhpcy5pbnB1dEVsLnN0eWxlLmhlaWdodCA9IGAke3RoaXMuaW5wdXRFbC5zY3JvbGxIZWlnaHR9cHhgO1xuICAgIH0pO1xuICB9XG5cbiAgcHJpdmF0ZSBfc2V0U2Vzc2lvblNlbGVjdE9wdGlvbnMoa2V5czogc3RyaW5nW10pOiB2b2lkIHtcbiAgICB0aGlzLnNlc3Npb25TZWxlY3QuZW1wdHkoKTtcblxuICAgIGNvbnN0IGN1cnJlbnQgPSB0aGlzLnBsdWdpbi5zZXR0aW5ncy5zZXNzaW9uS2V5O1xuICAgIGNvbnN0IHJlY2VudCA9IEFycmF5LmlzQXJyYXkodGhpcy5wbHVnaW4uc2V0dGluZ3MucmVjZW50U2Vzc2lvbktleXMpID8gdGhpcy5wbHVnaW4uc2V0dGluZ3MucmVjZW50U2Vzc2lvbktleXMgOiBbXTtcbiAgICBjb25zdCB1bmlxdWUgPSBBcnJheS5mcm9tKG5ldyBTZXQoW2N1cnJlbnQsIC4uLnJlY2VudCwgLi4ua2V5c10uZmlsdGVyKEJvb2xlYW4pKSk7XG5cbiAgICBmb3IgKGNvbnN0IGtleSBvZiB1bmlxdWUpIHtcbiAgICAgIGNvbnN0IG9wdCA9IHRoaXMuc2Vzc2lvblNlbGVjdC5jcmVhdGVFbCgnb3B0aW9uJywgeyB2YWx1ZToga2V5LCB0ZXh0OiBrZXkgfSk7XG4gICAgICBpZiAoa2V5ID09PSBjdXJyZW50KSBvcHQuc2VsZWN0ZWQgPSB0cnVlO1xuICAgIH1cblxuICAgIHRoaXMuc2Vzc2lvblNlbGVjdC50aXRsZSA9IGN1cnJlbnQ7XG4gIH1cblxuICBwcml2YXRlIGFzeW5jIF9yZWZyZXNoU2Vzc2lvbnMoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgLy8gQWx3YXlzIHNob3cgYXQgbGVhc3QgdGhlIGN1cnJlbnQgc2Vzc2lvbi5cbiAgICBpZiAoIXRoaXMuc2Vzc2lvblNlbGVjdCkgcmV0dXJuO1xuXG4gICAgaWYgKHRoaXMucGx1Z2luLndzQ2xpZW50LnN0YXRlICE9PSAnY29ubmVjdGVkJykge1xuICAgICAgdGhpcy5fc2V0U2Vzc2lvblNlbGVjdE9wdGlvbnMoW10pO1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIHRyeSB7XG4gICAgICBjb25zdCByZXMgPSBhd2FpdCB0aGlzLnBsdWdpbi53c0NsaWVudC5saXN0U2Vzc2lvbnMoe1xuICAgICAgICBhY3RpdmVNaW51dGVzOiA2MCAqIDI0LFxuICAgICAgICBsaW1pdDogMTAwLFxuICAgICAgICBpbmNsdWRlR2xvYmFsOiBmYWxzZSxcbiAgICAgICAgaW5jbHVkZVVua25vd246IGZhbHNlLFxuICAgICAgfSk7XG5cbiAgICAgIGNvbnN0IHJvd3MgPSBBcnJheS5pc0FycmF5KHJlcz8uc2Vzc2lvbnMpID8gcmVzLnNlc3Npb25zIDogW107XG4gICAgICBjb25zdCBvYnNpZGlhbk9ubHkgPSByb3dzLmZpbHRlcigocikgPT4ge1xuICAgICAgICBpZiAoIXIpIHJldHVybiBmYWxzZTtcbiAgICAgICAgY29uc3Qga2V5ID0gU3RyaW5nKHIua2V5IHx8ICcnKTtcbiAgICAgICAgLy8gT3VyIHBsdWdpbi1jcmVhdGVkIHNlc3Npb25zIGFyZSB0eXBpY2FsbHkgc2ltcGxlIGtleXMgbGlrZSBcIm9ic2lkaWFuLVlZWVlNTURELUhITU1cIi5cbiAgICAgICAgaWYgKGtleS5zdGFydHNXaXRoKCdvYnNpZGlhbi0nKSkgcmV0dXJuIHRydWU7XG4gICAgICAgIHJldHVybiByLmNoYW5uZWwgPT09ICdvYnNpZGlhbicgfHwga2V5LmluY2x1ZGVzKCc6b2JzaWRpYW46Jyk7XG4gICAgICB9KTtcbiAgICAgIGNvbnN0IGtleXMgPSBvYnNpZGlhbk9ubHkubWFwKChyKSA9PiByLmtleSkuZmlsdGVyKEJvb2xlYW4pO1xuICAgICAgdGhpcy5fc2V0U2Vzc2lvblNlbGVjdE9wdGlvbnMoa2V5cyk7XG4gICAgfSBjYXRjaCAoZXJyKSB7XG4gICAgICBjb25zb2xlLmVycm9yKCdbb2NsYXddIHNlc3Npb25zLmxpc3QgZmFpbGVkJywgZXJyKTtcbiAgICAgIC8vIEtlZXAgY3VycmVudCBvcHRpb24gb25seS5cbiAgICAgIHRoaXMuX3NldFNlc3Npb25TZWxlY3RPcHRpb25zKFtdKTtcbiAgICB9XG4gIH1cblxuICBwcml2YXRlIGFzeW5jIF9wcm9tcHROZXdTZXNzaW9uKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIGNvbnN0IG5vdyA9IG5ldyBEYXRlKCk7XG4gICAgY29uc3QgcGFkID0gKG46IG51bWJlcikgPT4gU3RyaW5nKG4pLnBhZFN0YXJ0KDIsICcwJyk7XG4gICAgY29uc3Qgc3VnZ2VzdGVkID0gYG9ic2lkaWFuLSR7bm93LmdldEZ1bGxZZWFyKCl9JHtwYWQobm93LmdldE1vbnRoKCkgKyAxKX0ke3BhZChub3cuZ2V0RGF0ZSgpKX0tJHtwYWQobm93LmdldEhvdXJzKCkpfSR7cGFkKG5vdy5nZXRNaW51dGVzKCkpfWA7XG5cbiAgICBjb25zdCBtb2RhbCA9IG5ldyBOZXdTZXNzaW9uTW9kYWwodGhpcywgc3VnZ2VzdGVkLCAodmFsdWUpID0+IHtcbiAgICAgIGNvbnN0IHYgPSB2YWx1ZS50cmltKCk7XG4gICAgICBpZiAoIXYpIHJldHVybjtcbiAgICAgIHZvaWQgKGFzeW5jICgpID0+IHtcbiAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uc3dpdGNoU2Vzc2lvbih2KTtcbiAgICAgICAgYXdhaXQgdGhpcy5fcmVmcmVzaFNlc3Npb25zKCk7XG4gICAgICAgIHRoaXMuc2Vzc2lvblNlbGVjdC52YWx1ZSA9IHY7XG4gICAgICAgIHRoaXMuc2Vzc2lvblNlbGVjdC50aXRsZSA9IHY7XG4gICAgICB9KSgpO1xuICAgIH0pO1xuICAgIG1vZGFsLm9wZW4oKTtcbiAgfVxuXG4gIC8vIFx1MjUwMFx1MjUwMCBNZXNzYWdlIHJlbmRlcmluZyBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcblxuICBwcml2YXRlIF9yZW5kZXJNZXNzYWdlcyhtZXNzYWdlczogcmVhZG9ubHkgQ2hhdE1lc3NhZ2VbXSk6IHZvaWQge1xuICAgIHRoaXMubWVzc2FnZXNFbC5lbXB0eSgpO1xuXG4gICAgaWYgKG1lc3NhZ2VzLmxlbmd0aCA9PT0gMCkge1xuICAgICAgdGhpcy5tZXNzYWdlc0VsLmNyZWF0ZUVsKCdwJywge1xuICAgICAgICB0ZXh0OiAnU2VuZCBhIG1lc3NhZ2UgdG8gc3RhcnQgY2hhdHRpbmcuJyxcbiAgICAgICAgY2xzOiAnb2NsYXctbWVzc2FnZSBzeXN0ZW0gb2NsYXctcGxhY2Vob2xkZXInLFxuICAgICAgfSk7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgZm9yIChjb25zdCBtc2cgb2YgbWVzc2FnZXMpIHtcbiAgICAgIHRoaXMuX2FwcGVuZE1lc3NhZ2UobXNnKTtcbiAgICB9XG5cbiAgICAvLyBTY3JvbGwgdG8gYm90dG9tXG4gICAgdGhpcy5tZXNzYWdlc0VsLnNjcm9sbFRvcCA9IHRoaXMubWVzc2FnZXNFbC5zY3JvbGxIZWlnaHQ7XG4gIH1cblxuICAvKiogQXBwZW5kcyBhIHNpbmdsZSBtZXNzYWdlIHdpdGhvdXQgcmVidWlsZGluZyB0aGUgRE9NIChPKDEpKSAqL1xuICBwcml2YXRlIF9hcHBlbmRNZXNzYWdlKG1zZzogQ2hhdE1lc3NhZ2UpOiB2b2lkIHtcbiAgICAvLyBSZW1vdmUgZW1wdHktc3RhdGUgcGxhY2Vob2xkZXIgaWYgcHJlc2VudFxuICAgIHRoaXMubWVzc2FnZXNFbC5xdWVyeVNlbGVjdG9yKCcub2NsYXctcGxhY2Vob2xkZXInKT8ucmVtb3ZlKCk7XG5cbiAgICBjb25zdCBsZXZlbENsYXNzID0gbXNnLmxldmVsID8gYCAke21zZy5sZXZlbH1gIDogJyc7XG4gICAgY29uc3Qga2luZENsYXNzID0gbXNnLmtpbmQgPyBgIG9jbGF3LSR7bXNnLmtpbmR9YCA6ICcnO1xuICAgIGNvbnN0IGVsID0gdGhpcy5tZXNzYWdlc0VsLmNyZWF0ZURpdih7IGNsczogYG9jbGF3LW1lc3NhZ2UgJHttc2cucm9sZX0ke2xldmVsQ2xhc3N9JHtraW5kQ2xhc3N9YCB9KTtcbiAgICBjb25zdCBib2R5ID0gZWwuY3JlYXRlRGl2KHsgY2xzOiAnb2NsYXctbWVzc2FnZS1ib2R5JyB9KTtcbiAgICBpZiAobXNnLnRpdGxlKSB7XG4gICAgICBib2R5LnRpdGxlID0gbXNnLnRpdGxlO1xuICAgIH1cblxuICAgIC8vIFRyZWF0IGFzc2lzdGFudCBvdXRwdXQgYXMgVU5UUlVTVEVEIGJ5IGRlZmF1bHQuXG4gICAgLy8gUmVuZGVyaW5nIGFzIE9ic2lkaWFuIE1hcmtkb3duIGNhbiB0cmlnZ2VyIGVtYmVkcyBhbmQgb3RoZXIgcGx1Z2lucycgcG9zdC1wcm9jZXNzb3JzLlxuICAgIGlmIChtc2cucm9sZSA9PT0gJ2Fzc2lzdGFudCcpIHtcbiAgICAgIGNvbnN0IG1hcHBpbmdzOiBQYXRoTWFwcGluZ1tdID0gdGhpcy5wbHVnaW4uc2V0dGluZ3MucGF0aE1hcHBpbmdzID8/IFtdO1xuICAgICAgY29uc3Qgc291cmNlUGF0aCA9IHRoaXMuYXBwLndvcmtzcGFjZS5nZXRBY3RpdmVGaWxlKCk/LnBhdGggPz8gJyc7XG5cbiAgICAgIGlmICh0aGlzLnBsdWdpbi5zZXR0aW5ncy5yZW5kZXJBc3Npc3RhbnRNYXJrZG93bikge1xuICAgICAgICAvLyBCZXN0LWVmZm9ydCBwcmUtcHJvY2Vzc2luZzogcmVwbGFjZSBrbm93biByZW1vdGUgcGF0aHMgd2l0aCB3aWtpbGlua3Mgd2hlbiB0aGUgdGFyZ2V0IGV4aXN0cy5cbiAgICAgICAgY29uc3QgcHJlID0gdGhpcy5fcHJlcHJvY2Vzc0Fzc2lzdGFudE1hcmtkb3duKG1zZy5jb250ZW50LCBtYXBwaW5ncyk7XG4gICAgICAgIHZvaWQgTWFya2Rvd25SZW5kZXJlci5yZW5kZXJNYXJrZG93bihwcmUsIGJvZHksIHNvdXJjZVBhdGgsIHRoaXMucGx1Z2luKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIC8vIFBsYWluIG1vZGU6IGJ1aWxkIHNhZmUsIGNsaWNrYWJsZSBsaW5rcyBpbiBET00gKG5vIE1hcmtkb3duIHJlbmRlcmluZykuXG4gICAgICAgIHRoaXMuX3JlbmRlckFzc2lzdGFudFBsYWluV2l0aExpbmtzKGJvZHksIG1zZy5jb250ZW50LCBtYXBwaW5ncywgc291cmNlUGF0aCk7XG4gICAgICB9XG4gICAgfSBlbHNlIHtcbiAgICAgIGJvZHkuc2V0VGV4dChtc2cuY29udGVudCk7XG4gICAgfVxuXG4gICAgLy8gU2Nyb2xsIHRvIGJvdHRvbVxuICAgIHRoaXMubWVzc2FnZXNFbC5zY3JvbGxUb3AgPSB0aGlzLm1lc3NhZ2VzRWwuc2Nyb2xsSGVpZ2h0O1xuICB9XG5cbiAgcHJpdmF0ZSBfdHJ5UmV2ZXJzZU1hcFVybFRvVmF1bHRQYXRoKHVybDogc3RyaW5nLCBtYXBwaW5nczogUGF0aE1hcHBpbmdbXSk6IHN0cmluZyB8IG51bGwge1xuICAgIC8vIEZTLWJhc2VkIG1hcHBpbmc7IGJlc3QtZWZmb3J0IG9ubHkuXG4gICAgbGV0IGRlY29kZWQgPSB1cmw7XG4gICAgdHJ5IHtcbiAgICAgIGRlY29kZWQgPSBkZWNvZGVVUklDb21wb25lbnQodXJsKTtcbiAgICB9IGNhdGNoIHtcbiAgICAgIC8vIGlnbm9yZVxuICAgIH1cblxuICAgIC8vIElmIHRoZSBkZWNvZGVkIFVSTCBjb250YWlucyBhIHJlbW90ZUJhc2Ugc3Vic3RyaW5nLCB0cnkgbWFwcGluZyBmcm9tIHRoYXQgcG9pbnQuXG4gICAgZm9yIChjb25zdCByb3cgb2YgbWFwcGluZ3MpIHtcbiAgICAgIGNvbnN0IHJlbW90ZUJhc2UgPSBTdHJpbmcocm93LnJlbW90ZUJhc2UgPz8gJycpO1xuICAgICAgaWYgKCFyZW1vdGVCYXNlKSBjb250aW51ZTtcbiAgICAgIGNvbnN0IGlkeCA9IGRlY29kZWQuaW5kZXhPZihyZW1vdGVCYXNlKTtcbiAgICAgIGlmIChpZHggPCAwKSBjb250aW51ZTtcblxuICAgICAgLy8gRXh0cmFjdCBmcm9tIHJlbW90ZUJhc2Ugb253YXJkIHVudGlsIGEgdGVybWluYXRvci5cbiAgICAgIGNvbnN0IHRhaWwgPSBkZWNvZGVkLnNsaWNlKGlkeCk7XG4gICAgICBjb25zdCB0b2tlbiA9IHRhaWwuc3BsaXQoL1tcXHMnXCI8PildLylbMF07XG4gICAgICBjb25zdCBtYXBwZWQgPSB0cnlNYXBSZW1vdGVQYXRoVG9WYXVsdFBhdGgodG9rZW4sIG1hcHBpbmdzKTtcbiAgICAgIGlmIChtYXBwZWQgJiYgdGhpcy5hcHAudmF1bHQuZ2V0QWJzdHJhY3RGaWxlQnlQYXRoKG1hcHBlZCkpIHJldHVybiBtYXBwZWQ7XG4gICAgfVxuXG4gICAgcmV0dXJuIG51bGw7XG4gIH1cblxuICBwcml2YXRlIF9pbnN0YWxsSW50ZXJuYWxMaW5rRGVsZWdhdGlvbigpOiB2b2lkIHtcbiAgICBpZiAodGhpcy5vbk1lc3NhZ2VzQ2xpY2spIHJldHVybjtcblxuICAgIHRoaXMub25NZXNzYWdlc0NsaWNrID0gKGV2OiBNb3VzZUV2ZW50KSA9PiB7XG4gICAgICBjb25zdCB0YXJnZXQgPSBldi50YXJnZXQgYXMgSFRNTEVsZW1lbnQgfCBudWxsO1xuICAgICAgY29uc3QgYSA9IHRhcmdldD8uY2xvc2VzdD8uKCdhLmludGVybmFsLWxpbmsnKSBhcyBIVE1MQW5jaG9yRWxlbWVudCB8IG51bGw7XG4gICAgICBpZiAoIWEpIHJldHVybjtcblxuICAgICAgY29uc3QgZGF0YUhyZWYgPSBhLmdldEF0dHJpYnV0ZSgnZGF0YS1ocmVmJykgfHwgJyc7XG4gICAgICBjb25zdCBocmVmQXR0ciA9IGEuZ2V0QXR0cmlidXRlKCdocmVmJykgfHwgJyc7XG5cbiAgICAgIGNvbnN0IHJhdyA9IChkYXRhSHJlZiB8fCBocmVmQXR0cikudHJpbSgpO1xuICAgICAgaWYgKCFyYXcpIHJldHVybjtcblxuICAgICAgLy8gSWYgaXQgaXMgYW4gYWJzb2x1dGUgVVJMLCBsZXQgdGhlIGRlZmF1bHQgYmVoYXZpb3IgaGFuZGxlIGl0LlxuICAgICAgaWYgKC9eaHR0cHM/OlxcL1xcLy9pLnRlc3QocmF3KSkgcmV0dXJuO1xuXG4gICAgICAvLyBPYnNpZGlhbiBpbnRlcm5hbC1saW5rIG9mdGVuIHVzZXMgdmF1bHQtcmVsYXRpdmUgcGF0aC5cbiAgICAgIGNvbnN0IHZhdWx0UGF0aCA9IHJhdy5yZXBsYWNlKC9eXFwvKy8sICcnKTtcbiAgICAgIGNvbnN0IGYgPSB0aGlzLmFwcC52YXVsdC5nZXRBYnN0cmFjdEZpbGVCeVBhdGgodmF1bHRQYXRoKTtcbiAgICAgIGlmICghKGYgaW5zdGFuY2VvZiBURmlsZSkpIHJldHVybjtcblxuICAgICAgZXYucHJldmVudERlZmF1bHQoKTtcbiAgICAgIGV2LnN0b3BQcm9wYWdhdGlvbigpO1xuICAgICAgdm9pZCB0aGlzLmFwcC53b3Jrc3BhY2UuZ2V0TGVhZih0cnVlKS5vcGVuRmlsZShmKTtcbiAgICB9O1xuXG4gICAgdGhpcy5tZXNzYWdlc0VsLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgdGhpcy5vbk1lc3NhZ2VzQ2xpY2spO1xuICB9XG5cbiAgcHJpdmF0ZSBfdHJ5TWFwVmF1bHRSZWxhdGl2ZVRva2VuKHRva2VuOiBzdHJpbmcsIG1hcHBpbmdzOiBQYXRoTWFwcGluZ1tdKTogc3RyaW5nIHwgbnVsbCB7XG4gICAgY29uc3QgdCA9IHRva2VuLnJlcGxhY2UoL15cXC8rLywgJycpO1xuICAgIGlmICh0aGlzLmFwcC52YXVsdC5nZXRBYnN0cmFjdEZpbGVCeVBhdGgodCkpIHJldHVybiB0O1xuXG4gICAgLy8gSGV1cmlzdGljOiBpZiB2YXVsdEJhc2UgZW5kcyB3aXRoIGEgc2VnbWVudCAoZS5nLiB3b3Jrc3BhY2UvY29tcGVuZy8pIGFuZCB0b2tlbiBzdGFydHMgd2l0aCB0aGF0IHNlZ21lbnQgKGNvbXBlbmcvLi4uKSxcbiAgICAvLyBtYXAgdG9rZW4gdW5kZXIgdmF1bHRCYXNlLlxuICAgIGZvciAoY29uc3Qgcm93IG9mIG1hcHBpbmdzKSB7XG4gICAgICBjb25zdCB2YXVsdEJhc2VSYXcgPSBTdHJpbmcocm93LnZhdWx0QmFzZSA/PyAnJykudHJpbSgpO1xuICAgICAgaWYgKCF2YXVsdEJhc2VSYXcpIGNvbnRpbnVlO1xuICAgICAgY29uc3QgdmF1bHRCYXNlID0gdmF1bHRCYXNlUmF3LmVuZHNXaXRoKCcvJykgPyB2YXVsdEJhc2VSYXcgOiBgJHt2YXVsdEJhc2VSYXd9L2A7XG5cbiAgICAgIGNvbnN0IHBhcnRzID0gdmF1bHRCYXNlLnJlcGxhY2UoL1xcLyskLywgJycpLnNwbGl0KCcvJyk7XG4gICAgICBjb25zdCBiYXNlTmFtZSA9IHBhcnRzW3BhcnRzLmxlbmd0aCAtIDFdO1xuICAgICAgaWYgKCFiYXNlTmFtZSkgY29udGludWU7XG5cbiAgICAgIGNvbnN0IHByZWZpeCA9IGAke2Jhc2VOYW1lfS9gO1xuICAgICAgaWYgKCF0LnN0YXJ0c1dpdGgocHJlZml4KSkgY29udGludWU7XG5cbiAgICAgIGNvbnN0IGNhbmRpZGF0ZSA9IGAke3ZhdWx0QmFzZX0ke3Quc2xpY2UocHJlZml4Lmxlbmd0aCl9YDtcbiAgICAgIGNvbnN0IG5vcm1hbGl6ZWQgPSBjYW5kaWRhdGUucmVwbGFjZSgvXlxcLysvLCAnJyk7XG4gICAgICBpZiAodGhpcy5hcHAudmF1bHQuZ2V0QWJzdHJhY3RGaWxlQnlQYXRoKG5vcm1hbGl6ZWQpKSByZXR1cm4gbm9ybWFsaXplZDtcbiAgICB9XG5cbiAgICByZXR1cm4gbnVsbDtcbiAgfVxuXG4gIHByaXZhdGUgX3ByZXByb2Nlc3NBc3Npc3RhbnRNYXJrZG93bih0ZXh0OiBzdHJpbmcsIG1hcHBpbmdzOiBQYXRoTWFwcGluZ1tdKTogc3RyaW5nIHtcbiAgICBjb25zdCBjYW5kaWRhdGVzID0gZXh0cmFjdENhbmRpZGF0ZXModGV4dCk7XG4gICAgaWYgKGNhbmRpZGF0ZXMubGVuZ3RoID09PSAwKSByZXR1cm4gdGV4dDtcblxuICAgIGxldCBvdXQgPSAnJztcbiAgICBsZXQgY3Vyc29yID0gMDtcblxuICAgIGZvciAoY29uc3QgYyBvZiBjYW5kaWRhdGVzKSB7XG4gICAgICBvdXQgKz0gdGV4dC5zbGljZShjdXJzb3IsIGMuc3RhcnQpO1xuICAgICAgY3Vyc29yID0gYy5lbmQ7XG5cbiAgICAgIGlmIChjLmtpbmQgPT09ICd1cmwnKSB7XG4gICAgICAgIC8vIFVSTHMgcmVtYWluIFVSTHMgVU5MRVNTIHdlIGNhbiBzYWZlbHkgbWFwIHRvIGFuIGV4aXN0aW5nIHZhdWx0IGZpbGUuXG4gICAgICAgIGNvbnN0IG1hcHBlZCA9IHRoaXMuX3RyeVJldmVyc2VNYXBVcmxUb1ZhdWx0UGF0aChjLnJhdywgbWFwcGluZ3MpO1xuICAgICAgICBvdXQgKz0gbWFwcGVkID8gYFtbJHttYXBwZWR9XV1gIDogYy5yYXc7XG4gICAgICAgIGNvbnRpbnVlO1xuICAgICAgfVxuXG4gICAgICAvLyAxKSBJZiB0aGUgdG9rZW4gaXMgYWxyZWFkeSBhIHZhdWx0LXJlbGF0aXZlIHBhdGggKG9yIGNhbiBiZSByZXNvbHZlZCB2aWEgdmF1bHRCYXNlIGhldXJpc3RpYyksIGxpbmtpZnkgaXQgZGlyZWN0bHkuXG4gICAgICBjb25zdCBkaXJlY3QgPSB0aGlzLl90cnlNYXBWYXVsdFJlbGF0aXZlVG9rZW4oYy5yYXcsIG1hcHBpbmdzKTtcbiAgICAgIGlmIChkaXJlY3QpIHtcbiAgICAgICAgb3V0ICs9IGBbWyR7ZGlyZWN0fV1dYDtcbiAgICAgICAgY29udGludWU7XG4gICAgICB9XG5cbiAgICAgIC8vIDIpIEVsc2U6IHRyeSByZW1vdGVcdTIxOTJ2YXVsdCBtYXBwaW5nLlxuICAgICAgY29uc3QgbWFwcGVkID0gdHJ5TWFwUmVtb3RlUGF0aFRvVmF1bHRQYXRoKGMucmF3LCBtYXBwaW5ncyk7XG4gICAgICBpZiAoIW1hcHBlZCkge1xuICAgICAgICBvdXQgKz0gYy5yYXc7XG4gICAgICAgIGNvbnRpbnVlO1xuICAgICAgfVxuXG4gICAgICBpZiAoIXRoaXMuYXBwLnZhdWx0LmdldEFic3RyYWN0RmlsZUJ5UGF0aChtYXBwZWQpKSB7XG4gICAgICAgIG91dCArPSBjLnJhdztcbiAgICAgICAgY29udGludWU7XG4gICAgICB9XG5cbiAgICAgIG91dCArPSBgW1ske21hcHBlZH1dXWA7XG4gICAgfVxuXG4gICAgb3V0ICs9IHRleHQuc2xpY2UoY3Vyc29yKTtcbiAgICByZXR1cm4gb3V0O1xuICB9XG5cbiAgcHJpdmF0ZSBfcmVuZGVyQXNzaXN0YW50UGxhaW5XaXRoTGlua3MoXG4gICAgYm9keTogSFRNTEVsZW1lbnQsXG4gICAgdGV4dDogc3RyaW5nLFxuICAgIG1hcHBpbmdzOiBQYXRoTWFwcGluZ1tdLFxuICAgIHNvdXJjZVBhdGg6IHN0cmluZyxcbiAgKTogdm9pZCB7XG4gICAgY29uc3QgY2FuZGlkYXRlcyA9IGV4dHJhY3RDYW5kaWRhdGVzKHRleHQpO1xuICAgIGlmIChjYW5kaWRhdGVzLmxlbmd0aCA9PT0gMCkge1xuICAgICAgYm9keS5zZXRUZXh0KHRleHQpO1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIGxldCBjdXJzb3IgPSAwO1xuXG4gICAgY29uc3QgYXBwZW5kVGV4dCA9IChzOiBzdHJpbmcpID0+IHtcbiAgICAgIGlmICghcykgcmV0dXJuO1xuICAgICAgYm9keS5hcHBlbmRDaGlsZChkb2N1bWVudC5jcmVhdGVUZXh0Tm9kZShzKSk7XG4gICAgfTtcblxuICAgIGNvbnN0IGFwcGVuZE9ic2lkaWFuTGluayA9ICh2YXVsdFBhdGg6IHN0cmluZykgPT4ge1xuICAgICAgY29uc3QgZGlzcGxheSA9IGBbWyR7dmF1bHRQYXRofV1dYDtcbiAgICAgIGNvbnN0IGEgPSBib2R5LmNyZWF0ZUVsKCdhJywgeyB0ZXh0OiBkaXNwbGF5LCBocmVmOiAnIycgfSk7XG4gICAgICBhLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKGV2KSA9PiB7XG4gICAgICAgIGV2LnByZXZlbnREZWZhdWx0KCk7XG4gICAgICAgIGV2LnN0b3BQcm9wYWdhdGlvbigpO1xuXG4gICAgICAgIGNvbnN0IGYgPSB0aGlzLmFwcC52YXVsdC5nZXRBYnN0cmFjdEZpbGVCeVBhdGgodmF1bHRQYXRoKTtcbiAgICAgICAgaWYgKGYgaW5zdGFuY2VvZiBURmlsZSkge1xuICAgICAgICAgIHZvaWQgdGhpcy5hcHAud29ya3NwYWNlLmdldExlYWYodHJ1ZSkub3BlbkZpbGUoZik7XG4gICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgLy8gRmFsbGJhY2s6IGJlc3QtZWZmb3J0IGxpbmt0ZXh0IG9wZW4uXG4gICAgICAgIHZvaWQgdGhpcy5hcHAud29ya3NwYWNlLm9wZW5MaW5rVGV4dCh2YXVsdFBhdGgsIHNvdXJjZVBhdGgsIHRydWUpO1xuICAgICAgfSk7XG4gICAgfTtcblxuICAgIGNvbnN0IGFwcGVuZEV4dGVybmFsVXJsID0gKHVybDogc3RyaW5nKSA9PiB7XG4gICAgICAvLyBMZXQgT2JzaWRpYW4vRWxlY3Ryb24gaGFuZGxlIGV4dGVybmFsIG9wZW4uXG4gICAgICBib2R5LmNyZWF0ZUVsKCdhJywgeyB0ZXh0OiB1cmwsIGhyZWY6IHVybCB9KTtcbiAgICB9O1xuXG4gICAgY29uc3QgdHJ5UmV2ZXJzZU1hcFVybFRvVmF1bHRQYXRoID0gKHVybDogc3RyaW5nKTogc3RyaW5nIHwgbnVsbCA9PiB0aGlzLl90cnlSZXZlcnNlTWFwVXJsVG9WYXVsdFBhdGgodXJsLCBtYXBwaW5ncyk7XG5cbiAgICBmb3IgKGNvbnN0IGMgb2YgY2FuZGlkYXRlcykge1xuICAgICAgYXBwZW5kVGV4dCh0ZXh0LnNsaWNlKGN1cnNvciwgYy5zdGFydCkpO1xuICAgICAgY3Vyc29yID0gYy5lbmQ7XG5cbiAgICAgIGlmIChjLmtpbmQgPT09ICd1cmwnKSB7XG4gICAgICAgIGNvbnN0IG1hcHBlZCA9IHRyeVJldmVyc2VNYXBVcmxUb1ZhdWx0UGF0aChjLnJhdyk7XG4gICAgICAgIGlmIChtYXBwZWQpIHtcbiAgICAgICAgICBhcHBlbmRPYnNpZGlhbkxpbmsobWFwcGVkKTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICBhcHBlbmRFeHRlcm5hbFVybChjLnJhdyk7XG4gICAgICAgIH1cbiAgICAgICAgY29udGludWU7XG4gICAgICB9XG5cbiAgICAgIC8vIDEpIElmIHRva2VuIGlzIGFscmVhZHkgYSB2YXVsdC1yZWxhdGl2ZSBwYXRoIChvciBjYW4gYmUgcmVzb2x2ZWQgdmlhIHZhdWx0QmFzZSBoZXVyaXN0aWMpLCBsaW5raWZ5IGRpcmVjdGx5LlxuICAgICAgY29uc3QgZGlyZWN0ID0gdGhpcy5fdHJ5TWFwVmF1bHRSZWxhdGl2ZVRva2VuKGMucmF3LCBtYXBwaW5ncyk7XG4gICAgICBpZiAoZGlyZWN0KSB7XG4gICAgICAgIGFwcGVuZE9ic2lkaWFuTGluayhkaXJlY3QpO1xuICAgICAgICBjb250aW51ZTtcbiAgICAgIH1cblxuICAgICAgLy8gMikgRWxzZTogdHJ5IHJlbW90ZVx1MjE5MnZhdWx0IG1hcHBpbmcuXG4gICAgICBjb25zdCBtYXBwZWQgPSB0cnlNYXBSZW1vdGVQYXRoVG9WYXVsdFBhdGgoYy5yYXcsIG1hcHBpbmdzKTtcbiAgICAgIGlmICghbWFwcGVkKSB7XG4gICAgICAgIGFwcGVuZFRleHQoYy5yYXcpO1xuICAgICAgICBjb250aW51ZTtcbiAgICAgIH1cblxuICAgICAgaWYgKCF0aGlzLmFwcC52YXVsdC5nZXRBYnN0cmFjdEZpbGVCeVBhdGgobWFwcGVkKSkge1xuICAgICAgICBhcHBlbmRUZXh0KGMucmF3KTtcbiAgICAgICAgY29udGludWU7XG4gICAgICB9XG5cbiAgICAgIGFwcGVuZE9ic2lkaWFuTGluayhtYXBwZWQpO1xuICAgIH1cblxuICAgIGFwcGVuZFRleHQodGV4dC5zbGljZShjdXJzb3IpKTtcbiAgfVxuXG4gIHByaXZhdGUgX3VwZGF0ZVNlbmRCdXR0b24oKTogdm9pZCB7XG4gICAgLy8gRGlzY29ubmVjdGVkOiBkaXNhYmxlLlxuICAgIC8vIFdvcmtpbmc6IGtlZXAgZW5hYmxlZCBzbyB1c2VyIGNhbiBzdG9wL2Fib3J0LlxuICAgIGNvbnN0IGRpc2FibGVkID0gIXRoaXMuaXNDb25uZWN0ZWQ7XG4gICAgdGhpcy5zZW5kQnRuLmRpc2FibGVkID0gZGlzYWJsZWQ7XG5cbiAgICB0aGlzLnNlbmRCdG4udG9nZ2xlQ2xhc3MoJ2lzLXdvcmtpbmcnLCB0aGlzLmlzV29ya2luZyk7XG4gICAgdGhpcy5zZW5kQnRuLnNldEF0dHIoJ2FyaWEtYnVzeScsIHRoaXMuaXNXb3JraW5nID8gJ3RydWUnIDogJ2ZhbHNlJyk7XG4gICAgdGhpcy5zZW5kQnRuLnNldEF0dHIoJ2FyaWEtbGFiZWwnLCB0aGlzLmlzV29ya2luZyA/ICdTdG9wJyA6ICdTZW5kJyk7XG5cbiAgICBpZiAodGhpcy5pc1dvcmtpbmcpIHtcbiAgICAgIC8vIFJlcGxhY2UgYnV0dG9uIGNvbnRlbnRzIHdpdGggU3RvcCBpY29uICsgc3Bpbm5lciByaW5nLlxuICAgICAgdGhpcy5zZW5kQnRuLmVtcHR5KCk7XG4gICAgICBjb25zdCB3cmFwID0gdGhpcy5zZW5kQnRuLmNyZWF0ZURpdih7IGNsczogJ29jbGF3LXN0b3Atd3JhcCcgfSk7XG4gICAgICB3cmFwLmNyZWF0ZURpdih7IGNsczogJ29jbGF3LXNwaW5uZXItcmluZycsIGF0dHI6IHsgJ2FyaWEtaGlkZGVuJzogJ3RydWUnIH0gfSk7XG4gICAgICB3cmFwLmNyZWF0ZURpdih7IGNsczogJ29jbGF3LXN0b3AtaWNvbicsIGF0dHI6IHsgJ2FyaWEtaGlkZGVuJzogJ3RydWUnIH0gfSk7XG4gICAgfSBlbHNlIHtcbiAgICAgIC8vIFJlc3RvcmUgbGFiZWxcbiAgICAgIHRoaXMuc2VuZEJ0bi5zZXRUZXh0KCdTZW5kJyk7XG4gICAgfVxuICB9XG5cbiAgLy8gXHUyNTAwXHUyNTAwIFNlbmQgaGFuZGxlciBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcblxuICBwcml2YXRlIGFzeW5jIF9oYW5kbGVTZW5kKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIC8vIFdoaWxlIHdvcmtpbmcsIHRoZSBidXR0b24gYmVjb21lcyBTdG9wLlxuICAgIGlmICh0aGlzLmlzV29ya2luZykge1xuICAgICAgY29uc3Qgb2sgPSBhd2FpdCB0aGlzLnBsdWdpbi53c0NsaWVudC5hYm9ydEFjdGl2ZVJ1bigpO1xuICAgICAgaWYgKCFvaykge1xuICAgICAgICBuZXcgTm90aWNlKCdPcGVuQ2xhdyBDaGF0OiBmYWlsZWQgdG8gc3RvcCcpO1xuICAgICAgICB0aGlzLmNoYXRNYW5hZ2VyLmFkZE1lc3NhZ2UoQ2hhdE1hbmFnZXIuY3JlYXRlU3lzdGVtTWVzc2FnZSgnXHUyNkEwIFN0b3AgZmFpbGVkJywgJ2Vycm9yJykpO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgdGhpcy5jaGF0TWFuYWdlci5hZGRNZXNzYWdlKENoYXRNYW5hZ2VyLmNyZWF0ZVN5c3RlbU1lc3NhZ2UoJ1x1MjZENCBTdG9wcGVkJywgJ2luZm8nKSk7XG4gICAgICB9XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgY29uc3QgdGV4dCA9IHRoaXMuaW5wdXRFbC52YWx1ZS50cmltKCk7XG4gICAgaWYgKCF0ZXh0KSByZXR1cm47XG5cbiAgICAvLyBCdWlsZCBtZXNzYWdlIHdpdGggY29udGV4dCBpZiBlbmFibGVkXG4gICAgbGV0IG1lc3NhZ2UgPSB0ZXh0O1xuICAgIGlmICh0aGlzLmluY2x1ZGVOb3RlQ2hlY2tib3guY2hlY2tlZCkge1xuICAgICAgY29uc3Qgbm90ZSA9IGF3YWl0IGdldEFjdGl2ZU5vdGVDb250ZXh0KHRoaXMuYXBwKTtcbiAgICAgIGlmIChub3RlKSB7XG4gICAgICAgIG1lc3NhZ2UgPSBgQ29udGV4dDogW1ske25vdGUudGl0bGV9XV1cXG5cXG4ke3RleHR9YDtcbiAgICAgIH1cbiAgICB9XG5cbiAgICAvLyBBZGQgdXNlciBtZXNzYWdlIHRvIGNoYXQgVUlcbiAgICBjb25zdCB1c2VyTXNnID0gQ2hhdE1hbmFnZXIuY3JlYXRlVXNlck1lc3NhZ2UodGV4dCk7XG4gICAgdGhpcy5jaGF0TWFuYWdlci5hZGRNZXNzYWdlKHVzZXJNc2cpO1xuXG4gICAgLy8gQ2xlYXIgaW5wdXRcbiAgICB0aGlzLmlucHV0RWwudmFsdWUgPSAnJztcbiAgICB0aGlzLmlucHV0RWwuc3R5bGUuaGVpZ2h0ID0gJ2F1dG8nO1xuXG4gICAgLy8gU2VuZCBvdmVyIFdTIChhc3luYylcbiAgICB0cnkge1xuICAgICAgYXdhaXQgdGhpcy5wbHVnaW4ud3NDbGllbnQuc2VuZE1lc3NhZ2UobWVzc2FnZSk7XG4gICAgfSBjYXRjaCAoZXJyKSB7XG4gICAgICBjb25zb2xlLmVycm9yKCdbb2NsYXddIFNlbmQgZmFpbGVkJywgZXJyKTtcbiAgICAgIG5ldyBOb3RpY2UoYE9wZW5DbGF3IENoYXQ6IHNlbmQgZmFpbGVkICgke1N0cmluZyhlcnIpfSlgKTtcbiAgICAgIHRoaXMuY2hhdE1hbmFnZXIuYWRkTWVzc2FnZShcbiAgICAgICAgQ2hhdE1hbmFnZXIuY3JlYXRlU3lzdGVtTWVzc2FnZShgXHUyNkEwIFNlbmQgZmFpbGVkOiAke2Vycn1gLCAnZXJyb3InKVxuICAgICAgKTtcbiAgICB9XG4gIH1cbn1cbiIsICJpbXBvcnQgdHlwZSB7IFBhdGhNYXBwaW5nIH0gZnJvbSAnLi90eXBlcyc7XG5cbmV4cG9ydCBmdW5jdGlvbiBub3JtYWxpemVCYXNlKGJhc2U6IHN0cmluZyk6IHN0cmluZyB7XG4gIGNvbnN0IHRyaW1tZWQgPSBTdHJpbmcoYmFzZSA/PyAnJykudHJpbSgpO1xuICBpZiAoIXRyaW1tZWQpIHJldHVybiAnJztcbiAgcmV0dXJuIHRyaW1tZWQuZW5kc1dpdGgoJy8nKSA/IHRyaW1tZWQgOiBgJHt0cmltbWVkfS9gO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gdHJ5TWFwUmVtb3RlUGF0aFRvVmF1bHRQYXRoKGlucHV0OiBzdHJpbmcsIG1hcHBpbmdzOiByZWFkb25seSBQYXRoTWFwcGluZ1tdKTogc3RyaW5nIHwgbnVsbCB7XG4gIGNvbnN0IHJhdyA9IFN0cmluZyhpbnB1dCA/PyAnJyk7XG4gIGZvciAoY29uc3Qgcm93IG9mIG1hcHBpbmdzKSB7XG4gICAgY29uc3QgcmVtb3RlQmFzZSA9IG5vcm1hbGl6ZUJhc2Uocm93LnJlbW90ZUJhc2UpO1xuICAgIGNvbnN0IHZhdWx0QmFzZSA9IG5vcm1hbGl6ZUJhc2Uocm93LnZhdWx0QmFzZSk7XG4gICAgaWYgKCFyZW1vdGVCYXNlIHx8ICF2YXVsdEJhc2UpIGNvbnRpbnVlO1xuXG4gICAgaWYgKHJhdy5zdGFydHNXaXRoKHJlbW90ZUJhc2UpKSB7XG4gICAgICBjb25zdCByZXN0ID0gcmF3LnNsaWNlKHJlbW90ZUJhc2UubGVuZ3RoKTtcbiAgICAgIC8vIE9ic2lkaWFuIHBhdGhzIGFyZSB2YXVsdC1yZWxhdGl2ZSBhbmQgc2hvdWxkIG5vdCBzdGFydCB3aXRoICcvJ1xuICAgICAgcmV0dXJuIGAke3ZhdWx0QmFzZX0ke3Jlc3R9YC5yZXBsYWNlKC9eXFwvKy8sICcnKTtcbiAgICB9XG4gIH1cbiAgcmV0dXJuIG51bGw7XG59XG5cbmV4cG9ydCB0eXBlIENhbmRpZGF0ZSA9IHsgc3RhcnQ6IG51bWJlcjsgZW5kOiBudW1iZXI7IHJhdzogc3RyaW5nOyBraW5kOiAndXJsJyB8ICdwYXRoJyB9O1xuXG4vLyBDb25zZXJ2YXRpdmUgZXh0cmFjdGlvbjogYWltIHRvIGF2b2lkIGZhbHNlIHBvc2l0aXZlcy5cbmNvbnN0IFVSTF9SRSA9IC9odHRwcz86XFwvXFwvW15cXHM8PigpXSsvZztcbi8vIEFic29sdXRlIHVuaXgtaXNoIHBhdGhzLlxuLy8gKFdlIHN0aWxsIGV4aXN0ZW5jZS1jaGVjayBiZWZvcmUgcHJvZHVjaW5nIGEgbGluay4pXG5jb25zdCBQQVRIX1JFID0gLyg/PCFbQS1aYS16MC05Ll8tXSkoPzpcXC9bQS1aYS16MC05Ll9+ISQmJygpKissOz06QCVcXC1dKykrKD86XFwuW0EtWmEtejAtOS5fLV0rKT8vZztcblxuLy8gQ29uc2VydmF0aXZlIHJlbGF0aXZlIHBhdGhzIHdpdGggYXQgbGVhc3Qgb25lICcvJywgZS5nLiBjb21wZW5nL3BsYW5zL3gubWRcbi8vIEF2b2lkcyBtYXRjaGluZyBzY2hlbWUtbGlrZSB0b2tlbnMgdmlhIG5lZ2F0aXZlIGxvb2thaGVhZCBmb3IgJzovLycuXG5jb25zdCBSRUxfUEFUSF9SRSA9IC9cXGIoPyFbQS1aYS16XVtBLVphLXowLTkrLi1dKjpcXC9cXC8pW0EtWmEtejAtOS5fLV0rKD86XFwvW0EtWmEtejAtOS5fLV0rKSsoPzpcXC5bQS1aYS16MC05Ll8tXSspP1xcYi9nO1xuXG5leHBvcnQgZnVuY3Rpb24gZXh0cmFjdENhbmRpZGF0ZXModGV4dDogc3RyaW5nKTogQ2FuZGlkYXRlW10ge1xuICBjb25zdCB0ID0gU3RyaW5nKHRleHQgPz8gJycpO1xuICBjb25zdCBvdXQ6IENhbmRpZGF0ZVtdID0gW107XG5cbiAgZm9yIChjb25zdCBtIG9mIHQubWF0Y2hBbGwoVVJMX1JFKSkge1xuICAgIGlmIChtLmluZGV4ID09PSB1bmRlZmluZWQpIGNvbnRpbnVlO1xuICAgIG91dC5wdXNoKHsgc3RhcnQ6IG0uaW5kZXgsIGVuZDogbS5pbmRleCArIG1bMF0ubGVuZ3RoLCByYXc6IG1bMF0sIGtpbmQ6ICd1cmwnIH0pO1xuICB9XG5cbiAgZm9yIChjb25zdCBtIG9mIHQubWF0Y2hBbGwoUEFUSF9SRSkpIHtcbiAgICBpZiAobS5pbmRleCA9PT0gdW5kZWZpbmVkKSBjb250aW51ZTtcblxuICAgIC8vIFNraXAgaWYgdGhpcyBpcyBpbnNpZGUgYSBVUkwgd2UgYWxyZWFkeSBjYXB0dXJlZC5cbiAgICBjb25zdCBzdGFydCA9IG0uaW5kZXg7XG4gICAgY29uc3QgZW5kID0gc3RhcnQgKyBtWzBdLmxlbmd0aDtcbiAgICBjb25zdCBvdmVybGFwc1VybCA9IG91dC5zb21lKChjKSA9PiBjLmtpbmQgPT09ICd1cmwnICYmICEoZW5kIDw9IGMuc3RhcnQgfHwgc3RhcnQgPj0gYy5lbmQpKTtcbiAgICBpZiAob3ZlcmxhcHNVcmwpIGNvbnRpbnVlO1xuXG4gICAgb3V0LnB1c2goeyBzdGFydCwgZW5kLCByYXc6IG1bMF0sIGtpbmQ6ICdwYXRoJyB9KTtcbiAgfVxuXG4gIGZvciAoY29uc3QgbSBvZiB0Lm1hdGNoQWxsKFJFTF9QQVRIX1JFKSkge1xuICAgIGlmIChtLmluZGV4ID09PSB1bmRlZmluZWQpIGNvbnRpbnVlO1xuXG4gICAgY29uc3Qgc3RhcnQgPSBtLmluZGV4O1xuICAgIGNvbnN0IGVuZCA9IHN0YXJ0ICsgbVswXS5sZW5ndGg7XG4gICAgY29uc3Qgb3ZlcmxhcHNFeGlzdGluZyA9IG91dC5zb21lKChjKSA9PiAhKGVuZCA8PSBjLnN0YXJ0IHx8IHN0YXJ0ID49IGMuZW5kKSk7XG4gICAgaWYgKG92ZXJsYXBzRXhpc3RpbmcpIGNvbnRpbnVlO1xuXG4gICAgb3V0LnB1c2goeyBzdGFydCwgZW5kLCByYXc6IG1bMF0sIGtpbmQ6ICdwYXRoJyB9KTtcbiAgfVxuXG4gIC8vIFNvcnQgYW5kIGRyb3Agb3ZlcmxhcHMgKHByZWZlciBVUkxzKS5cbiAgb3V0LnNvcnQoKGEsIGIpID0+IGEuc3RhcnQgLSBiLnN0YXJ0IHx8IChhLmtpbmQgPT09ICd1cmwnID8gLTEgOiAxKSk7XG4gIGNvbnN0IGRlZHVwOiBDYW5kaWRhdGVbXSA9IFtdO1xuICBmb3IgKGNvbnN0IGMgb2Ygb3V0KSB7XG4gICAgY29uc3QgbGFzdCA9IGRlZHVwW2RlZHVwLmxlbmd0aCAtIDFdO1xuICAgIGlmICghbGFzdCkge1xuICAgICAgZGVkdXAucHVzaChjKTtcbiAgICAgIGNvbnRpbnVlO1xuICAgIH1cbiAgICBpZiAoYy5zdGFydCA8IGxhc3QuZW5kKSBjb250aW51ZTtcbiAgICBkZWR1cC5wdXNoKGMpO1xuICB9XG5cbiAgcmV0dXJuIGRlZHVwO1xufVxuIiwgImltcG9ydCB0eXBlIHsgQXBwIH0gZnJvbSAnb2JzaWRpYW4nO1xuXG5leHBvcnQgaW50ZXJmYWNlIE5vdGVDb250ZXh0IHtcbiAgdGl0bGU6IHN0cmluZztcbiAgcGF0aDogc3RyaW5nO1xuICBjb250ZW50OiBzdHJpbmc7XG59XG5cbi8qKlxuICogUmV0dXJucyB0aGUgYWN0aXZlIG5vdGUncyB0aXRsZSBhbmQgY29udGVudCwgb3IgbnVsbCBpZiBubyBub3RlIGlzIG9wZW4uXG4gKiBBc3luYyBiZWNhdXNlIHZhdWx0LnJlYWQoKSBpcyBhc3luYy5cbiAqL1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGdldEFjdGl2ZU5vdGVDb250ZXh0KGFwcDogQXBwKTogUHJvbWlzZTxOb3RlQ29udGV4dCB8IG51bGw+IHtcbiAgY29uc3QgZmlsZSA9IGFwcC53b3Jrc3BhY2UuZ2V0QWN0aXZlRmlsZSgpO1xuICBpZiAoIWZpbGUpIHJldHVybiBudWxsO1xuXG4gIHRyeSB7XG4gICAgY29uc3QgY29udGVudCA9IGF3YWl0IGFwcC52YXVsdC5yZWFkKGZpbGUpO1xuICAgIHJldHVybiB7XG4gICAgICB0aXRsZTogZmlsZS5iYXNlbmFtZSxcbiAgICAgIHBhdGg6IGZpbGUucGF0aCxcbiAgICAgIGNvbnRlbnQsXG4gICAgfTtcbiAgfSBjYXRjaCAoZXJyKSB7XG4gICAgY29uc29sZS5lcnJvcignW29jbGF3LWNvbnRleHRdIEZhaWxlZCB0byByZWFkIGFjdGl2ZSBub3RlJywgZXJyKTtcbiAgICByZXR1cm4gbnVsbDtcbiAgfVxufVxuIiwgIi8qKiBQZXJzaXN0ZWQgcGx1Z2luIGNvbmZpZ3VyYXRpb24gKi9cbmV4cG9ydCBpbnRlcmZhY2UgT3BlbkNsYXdTZXR0aW5ncyB7XG4gIC8qKiBXZWJTb2NrZXQgVVJMIG9mIHRoZSBPcGVuQ2xhdyBHYXRld2F5IChlLmcuIHdzOi8vMTAwLjkwLjkuNjg6MTg3ODkpICovXG4gIGdhdGV3YXlVcmw6IHN0cmluZztcbiAgLyoqIEF1dGggdG9rZW4gXHUyMDE0IG11c3QgbWF0Y2ggdGhlIGNoYW5uZWwgcGx1Z2luJ3MgYXV0aFRva2VuICovXG4gIGF1dGhUb2tlbjogc3RyaW5nO1xuICAvKiogT3BlbkNsYXcgc2Vzc2lvbiBrZXkgdG8gc3Vic2NyaWJlIHRvIChlLmcuIFwibWFpblwiKSAqL1xuICBzZXNzaW9uS2V5OiBzdHJpbmc7XG4gIC8qKiAoRGVwcmVjYXRlZCkgT3BlbkNsYXcgYWNjb3VudCBJRCAodW51c2VkOyBjaGF0LnNlbmQgdXNlcyBzZXNzaW9uS2V5KSAqL1xuICBhY2NvdW50SWQ6IHN0cmluZztcbiAgLyoqIFdoZXRoZXIgdG8gaW5jbHVkZSB0aGUgYWN0aXZlIG5vdGUgY29udGVudCB3aXRoIGVhY2ggbWVzc2FnZSAqL1xuICBpbmNsdWRlQWN0aXZlTm90ZTogYm9vbGVhbjtcbiAgLyoqIFJlbmRlciBhc3Npc3RhbnQgb3V0cHV0IGFzIE1hcmtkb3duICh1bnNhZmU6IG1heSB0cmlnZ2VyIGVtYmVkcy9wb3N0LXByb2Nlc3NvcnMpOyBkZWZhdWx0IE9GRiAqL1xuICByZW5kZXJBc3Npc3RhbnRNYXJrZG93bjogYm9vbGVhbjtcbiAgLyoqIEFsbG93IHVzaW5nIGluc2VjdXJlIHdzOi8vIGZvciBub24tbG9jYWwgZ2F0ZXdheSBVUkxzICh1bnNhZmUpOyBkZWZhdWx0IE9GRiAqL1xuICBhbGxvd0luc2VjdXJlV3M6IGJvb2xlYW47XG5cbiAgLyoqIE9wdGlvbmFsOiBtYXAgcmVtb3RlIEZTIHBhdGhzIC8gZXhwb3J0ZWQgcGF0aHMgYmFjayB0byB2YXVsdC1yZWxhdGl2ZSBwYXRocyAqL1xuICBwYXRoTWFwcGluZ3M6IFBhdGhNYXBwaW5nW107XG5cbiAgLyoqIFJlY2VudCBzZXNzaW9uIGtleXMgKHVzZWQgdG8ga2VlcCBhIHN0YWJsZSBPYnNpZGlhbi1vbmx5IHNlc3Npb24gcGlja2VyKS4gKi9cbiAgcmVjZW50U2Vzc2lvbktleXM6IHN0cmluZ1tdO1xufVxuXG5leHBvcnQgdHlwZSBQYXRoTWFwcGluZyA9IHtcbiAgLyoqIFZhdWx0LXJlbGF0aXZlIGJhc2UgcGF0aCAoZS5nLiBcImRvY3MvXCIgb3IgXCJjb21wZW5nL1wiKSAqL1xuICB2YXVsdEJhc2U6IHN0cmluZztcbiAgLyoqIFJlbW90ZSBGUyBiYXNlIHBhdGggKGUuZy4gXCIvaG9tZS93YWxsLWUvLm9wZW5jbGF3L3dvcmtzcGFjZS9kb2NzL1wiKSAqL1xuICByZW1vdGVCYXNlOiBzdHJpbmc7XG59O1xuXG5leHBvcnQgY29uc3QgREVGQVVMVF9TRVRUSU5HUzogT3BlbkNsYXdTZXR0aW5ncyA9IHtcbiAgZ2F0ZXdheVVybDogJ3dzOi8vbG9jYWxob3N0OjE4Nzg5JyxcbiAgYXV0aFRva2VuOiAnJyxcbiAgc2Vzc2lvbktleTogJ21haW4nLFxuICBhY2NvdW50SWQ6ICdtYWluJyxcbiAgaW5jbHVkZUFjdGl2ZU5vdGU6IGZhbHNlLFxuICByZW5kZXJBc3Npc3RhbnRNYXJrZG93bjogZmFsc2UsXG4gIGFsbG93SW5zZWN1cmVXczogZmFsc2UsXG4gIHBhdGhNYXBwaW5nczogW10sXG4gIHJlY2VudFNlc3Npb25LZXlzOiBbXSxcbn07XG5cbi8qKiBBIHNpbmdsZSBjaGF0IG1lc3NhZ2UgKi9cbmV4cG9ydCBpbnRlcmZhY2UgQ2hhdE1lc3NhZ2Uge1xuICBpZDogc3RyaW5nO1xuICByb2xlOiAndXNlcicgfCAnYXNzaXN0YW50JyB8ICdzeXN0ZW0nO1xuICAvKiogT3B0aW9uYWwgc2V2ZXJpdHkgZm9yIHN5c3RlbS9zdGF0dXMgbWVzc2FnZXMgKi9cbiAgbGV2ZWw/OiAnaW5mbycgfCAnZXJyb3InO1xuICAvKiogT3B0aW9uYWwgc3VidHlwZSBmb3Igc3R5bGluZyBzcGVjaWFsIHN5c3RlbSBtZXNzYWdlcyAoZS5nLiBzZXNzaW9uIGRpdmlkZXIpLiAqL1xuICBraW5kPzogJ3Nlc3Npb24tZGl2aWRlcic7XG4gIC8qKiBPcHRpb25hbCBob3ZlciB0b29sdGlwIGZvciB0aGUgbWVzc2FnZSAoZS5nLiBmdWxsIHNlc3Npb24ga2V5KS4gKi9cbiAgdGl0bGU/OiBzdHJpbmc7XG4gIGNvbnRlbnQ6IHN0cmluZztcbiAgdGltZXN0YW1wOiBudW1iZXI7XG59XG5cbi8qKiBHYXRld2F5IHNlc3Npb25zLmxpc3QgdHlwZXMgKG1pbmltYWwgc3Vic2V0IHdlIHVzZSBpbiBVSSkuICovXG5leHBvcnQgdHlwZSBHYXRld2F5U2Vzc2lvblJvdyA9IHtcbiAga2V5OiBzdHJpbmc7XG4gIGtpbmQ/OiBzdHJpbmc7XG4gIGxhYmVsPzogc3RyaW5nO1xuICBkaXNwbGF5TmFtZT86IHN0cmluZztcbiAgZGVyaXZlZFRpdGxlPzogc3RyaW5nO1xuICBsYXN0TWVzc2FnZVByZXZpZXc/OiBzdHJpbmc7XG4gIGNoYW5uZWw/OiBzdHJpbmc7XG4gIHVwZGF0ZWRBdD86IG51bWJlciB8IG51bGw7XG4gIGxhc3RBY2NvdW50SWQ/OiBzdHJpbmc7XG59O1xuXG5leHBvcnQgdHlwZSBTZXNzaW9uc0xpc3RSZXN1bHQgPSB7XG4gIHRzOiBudW1iZXI7XG4gIHBhdGg6IHN0cmluZztcbiAgY291bnQ6IG51bWJlcjtcbiAgc2Vzc2lvbnM6IEdhdGV3YXlTZXNzaW9uUm93W107XG59O1xuXG4vKiogUGF5bG9hZCBmb3IgbWVzc2FnZXMgU0VOVCB0byB0aGUgc2VydmVyIChvdXRib3VuZCkgKi9cbmV4cG9ydCBpbnRlcmZhY2UgV1NQYXlsb2FkIHtcbiAgdHlwZTogJ2F1dGgnIHwgJ21lc3NhZ2UnIHwgJ3BpbmcnIHwgJ3BvbmcnIHwgJ2Vycm9yJztcbiAgcGF5bG9hZD86IFJlY29yZDxzdHJpbmcsIHVua25vd24+O1xufVxuXG4vKiogTWVzc2FnZXMgUkVDRUlWRUQgZnJvbSB0aGUgc2VydmVyIChpbmJvdW5kKSBcdTIwMTQgZGlzY3JpbWluYXRlZCB1bmlvbiAqL1xuZXhwb3J0IHR5cGUgSW5ib3VuZFdTUGF5bG9hZCA9XG4gIHwgeyB0eXBlOiAnbWVzc2FnZSc7IHBheWxvYWQ6IHsgY29udGVudDogc3RyaW5nOyByb2xlOiBzdHJpbmc7IHRpbWVzdGFtcDogbnVtYmVyIH0gfVxuICB8IHsgdHlwZTogJ2Vycm9yJzsgcGF5bG9hZDogeyBtZXNzYWdlOiBzdHJpbmcgfSB9O1xuXG4vKiogQXZhaWxhYmxlIGFnZW50cyAvIG1vZGVscyAqL1xuZXhwb3J0IGludGVyZmFjZSBBZ2VudE9wdGlvbiB7XG4gIGlkOiBzdHJpbmc7XG4gIGxhYmVsOiBzdHJpbmc7XG59XG4iXSwKICAibWFwcGluZ3MiOiAiOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUEsSUFBQUEsbUJBQThDOzs7QUNBOUMsc0JBQStDO0FBR3hDLElBQU0scUJBQU4sY0FBaUMsaUNBQWlCO0FBQUEsRUFHdkQsWUFBWSxLQUFVLFFBQXdCO0FBQzVDLFVBQU0sS0FBSyxNQUFNO0FBQ2pCLFNBQUssU0FBUztBQUFBLEVBQ2hCO0FBQUEsRUFFQSxVQUFnQjtBQVhsQjtBQVlJLFVBQU0sRUFBRSxZQUFZLElBQUk7QUFDeEIsZ0JBQVksTUFBTTtBQUVsQixnQkFBWSxTQUFTLE1BQU0sRUFBRSxNQUFNLGdDQUEyQixDQUFDO0FBRS9ELFFBQUksd0JBQVEsV0FBVyxFQUNwQixRQUFRLGFBQWEsRUFDckIsUUFBUSxtRUFBbUUsRUFDM0U7QUFBQSxNQUFRLENBQUMsU0FDUixLQUNHLGVBQWUsc0JBQXNCLEVBQ3JDLFNBQVMsS0FBSyxPQUFPLFNBQVMsVUFBVSxFQUN4QyxTQUFTLENBQU8sVUFBVTtBQUN6QixhQUFLLE9BQU8sU0FBUyxhQUFhLE1BQU0sS0FBSztBQUM3QyxjQUFNLEtBQUssT0FBTyxhQUFhO0FBQUEsTUFDakMsRUFBQztBQUFBLElBQ0w7QUFFRixRQUFJ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QixZQUEwQixDQUFDO0FBRXpDLFdBQUssV0FBVyxPQUFPLE9BQU8sQ0FBQyxHQUFHLGtCQUFrQixJQUFJO0FBQUEsSUFDMUQ7QUFBQTtBQUFBLEVBRU0sZUFBOEI7QUFBQTtBQWhIdEM7QUFrSEksWUFBTSxRQUFRLFdBQU0sS0FBSyxTQUFTLE1BQXBCLFlBQTBCLENBQUM7QUFDekMsWUFBTSxLQUFLLFNBQVMsa0NBQUssT0FBUyxLQUFLLFNBQVU7QUFBQSxJQUNuRDtBQUFBO0FBQUE7QUFBQSxFQUlNLHNCQUFxQztBQUFBO0FBQ3pDLFlBQU0sS0FBSyxxQkFBcUI7QUFDaEMsVUFBSSx3QkFBTyxnRUFBZ0U7QUFBQSxJQUM3RTtBQUFBO0FBQUEsRUFJYyxzQkFBMkM7QUFBQTtBQS9IM0Q7QUFnSUksWUFBTSxRQUFRLFdBQU0sS0FBSyxTQUFTLE1BQXBCLFlBQTBCLENBQUM7QUFDekMsY0FBUSxrQ0FBZSxLQUFLLHdCQUFwQixZQUEyQztBQUFBLElBQ3JEO0FBQUE7QUFBQSxFQUVjLG9CQUFvQixVQUE4QjtBQUFBO0FBcElsRTtBQXFJSSxZQUFNLFFBQVEsV0FBTSxLQUFLLFNBQVMsTUFBcEIsWUFBMEIsQ0FBQztBQUN6QyxZQUFNLEtBQUssU0FBUyxpQ0FBSyxPQUFMLEVBQVcsQ0FBQyxLQUFLLGtCQUFrQixHQUFHLFNBQVMsRUFBQztBQUFBLElBQ3RFO0FBQUE7QUFBQSxFQUVjLHVCQUFzQztBQUFBO0FBekl0RDtBQTBJSSxZQUFNLFFBQVEsV0FBTSxLQUFLLFNBQVMsTUFBcEIsWUFBMEIsQ0FBQztBQUN6QyxXQUFLLDZCQUFlLEtBQUsseUJBQXdCO0FBQVc7QUFDNUQsWUFBTSxPQUFPLG1CQUFNO0FBQ25CLGFBQU8sS0FBSyxLQUFLLGtCQUFrQjtBQUNuQyxZQUFNLEtBQUssU0FBUyxJQUFJO0FBQUEsSUFDMUI7QUFBQTtBQUFBO0FBQUEsRUFJUSxhQUFtQjtBQUN6QixTQUFLLFNBQVMsUUFBUSxLQUFLLFNBQVMsWUFBWSxLQUFLLFNBQVMsV0FBVztBQUFBLE1BQ3ZFLGlCQUFpQixLQUFLLFNBQVM7QUFBQSxJQUNqQyxDQUFDO0FBQUEsRUFDSDtBQUFBLEVBRWMsb0JBQW1DO0FBQUE7QUFDL0MsWUFBTSxFQUFFLFVBQVUsSUFBSSxLQUFLO0FBRzNCLFlBQU0sV0FBVyxVQUFVLGdCQUFnQix1QkFBdUI7QUFDbEUsVUFBSSxTQUFTLFNBQVMsR0FBRztBQUN2QixrQkFBVSxXQUFXLFNBQVMsQ0FBQyxDQUFDO0FBQ2hDO0FBQUEsTUFDRjtBQUdBLFlBQU0sT0FBTyxVQUFVLGFBQWEsS0FBSztBQUN6QyxVQUFJLENBQUM7QUFBTTtBQUNYLFlBQU0sS0FBSyxhQUFhLEVBQUUsTUFBTSx5QkFBeUIsUUFBUSxLQUFLLENBQUM7QUFDdkUsZ0JBQVUsV0FBVyxJQUFJO0FBQUEsSUFDM0I7QUFBQTtBQUNGOyIsCiAgIm5hbWVzIjogWyJpbXBvcnRfb2JzaWRpYW4iLCAiX2EiLCAiaW1wb3J0X29ic2lkaWFuIiwgIm1hcHBlZCJdCn0K
