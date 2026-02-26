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
    this.sessionRefreshBtn.addEventListener("click", () => void this._refreshSessions());
    this.sessionNewBtn.addEventListener("click", () => void this._promptNewSession());
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
    const unique = Array.from(new Set([current, ...keys].filter(Boolean)));
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
        const obsidianOnly = rows.filter((r) => r && (r.channel === "obsidian" || String(r.key).includes(":obsidian:")));
        const keys = (obsidianOnly.length ? obsidianOnly : rows).map((r) => r.key).filter(Boolean);
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
      const next = window.prompt("New session key", suggested);
      if (!next)
        return;
      yield this.plugin.switchSession(next);
      this._setSessionSelectOptions([]);
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
  pathMappings: []
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
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsic3JjL21haW4udHMiLCAic3JjL3NldHRpbmdzLnRzIiwgInNyYy93ZWJzb2NrZXQudHMiLCAic3JjL2NoYXQudHMiLCAic3JjL3ZpZXcudHMiLCAic3JjL2xpbmtpZnkudHMiLCAic3JjL2NvbnRleHQudHMiLCAic3JjL3R5cGVzLnRzIl0sCiAgInNvdXJjZXNDb250ZW50IjogWyJpbXBvcnQgeyBOb3RpY2UsIFBsdWdpbiwgV29ya3NwYWNlTGVhZiB9IGZyb20gJ29ic2lkaWFuJztcbmltcG9ydCB7IE9wZW5DbGF3U2V0dGluZ1RhYiB9IGZyb20gJy4vc2V0dGluZ3MnO1xuaW1wb3J0IHsgT2JzaWRpYW5XU0NsaWVudCB9IGZyb20gJy4vd2Vic29ja2V0JztcbmltcG9ydCB7IENoYXRNYW5hZ2VyIH0gZnJvbSAnLi9jaGF0JztcbmltcG9ydCB7IFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFULCBPcGVuQ2xhd0NoYXRWaWV3IH0gZnJvbSAnLi92aWV3JztcbmltcG9ydCB7IERFRkFVTFRfU0VUVElOR1MsIHR5cGUgT3BlbkNsYXdTZXR0aW5ncyB9IGZyb20gJy4vdHlwZXMnO1xuXG5leHBvcnQgZGVmYXVsdCBjbGFzcyBPcGVuQ2xhd1BsdWdpbiBleHRlbmRzIFBsdWdpbiB7XG4gIHNldHRpbmdzITogT3BlbkNsYXdTZXR0aW5ncztcbiAgd3NDbGllbnQhOiBPYnNpZGlhbldTQ2xpZW50O1xuICBjaGF0TWFuYWdlciE6IENoYXRNYW5hZ2VyO1xuXG4gIGFzeW5jIHN3aXRjaFNlc3Npb24oc2Vzc2lvbktleTogc3RyaW5nKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgY29uc3QgbmV4dCA9IHNlc3Npb25LZXkudHJpbSgpO1xuICAgIGlmICghbmV4dCkge1xuICAgICAgbmV3IE5vdGljZSgnT3BlbkNsYXcgQ2hhdDogc2Vzc2lvbiBrZXkgY2Fubm90IGJlIGVtcHR5LicpO1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIC8vIEFib3J0IGFueSBpbi1mbGlnaHQgcnVuIGJlc3QtZWZmb3J0IChhdm9pZCBsZWFraW5nIGEgXCJ3b3JraW5nXCIgVUkgc3RhdGUpLlxuICAgIHRyeSB7XG4gICAgICBhd2FpdCB0aGlzLndzQ2xpZW50LmFib3J0QWN0aXZlUnVuKCk7XG4gICAgfSBjYXRjaCB7XG4gICAgICAvLyBpZ25vcmVcbiAgICB9XG5cbiAgICAvLyBJbnNlcnQgZGl2aWRlciBhdCB0aGUgc3RhcnQgb2YgdGhlIG5ldyBzZXNzaW9uLlxuICAgIHRoaXMuY2hhdE1hbmFnZXIuYWRkTWVzc2FnZShDaGF0TWFuYWdlci5jcmVhdGVTZXNzaW9uRGl2aWRlcihuZXh0KSk7XG5cbiAgICB0aGlzLnNldHRpbmdzLnNlc3Npb25LZXkgPSBuZXh0O1xuICAgIGF3YWl0IHRoaXMuc2F2ZVNldHRpbmdzKCk7XG5cbiAgICAvLyBSZWNvbm5lY3Qgd2l0aCB0aGUgbmV3IHNlc3Npb24ga2V5LlxuICAgIHRoaXMud3NDbGllbnQuZGlzY29ubmVjdCgpO1xuICAgIHRoaXMud3NDbGllbnQuc2V0U2Vzc2lvbktleShuZXh0KTtcblxuICAgIGlmICh0aGlzLnNldHRpbmdzLmF1dGhUb2tlbikge1xuICAgICAgdGhpcy53c0NsaWVudC5jb25uZWN0KHRoaXMuc2V0dGluZ3MuZ2F0ZXdheVVybCwgdGhpcy5zZXR0aW5ncy5hdXRoVG9rZW4sIHtcbiAgICAgICAgYWxsb3dJbnNlY3VyZVdzOiB0aGlzLnNldHRpbmdzLmFsbG93SW5zZWN1cmVXcyxcbiAgICAgIH0pO1xuICAgIH1cbiAgfVxuXG4gIGFzeW5jIG9ubG9hZCgpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBhd2FpdCB0aGlzLmxvYWRTZXR0aW5ncygpO1xuXG4gICAgdGhpcy53c0NsaWVudCA9IG5ldyBPYnNpZGlhbldTQ2xpZW50KHRoaXMuc2V0dGluZ3Muc2Vzc2lvbktleSwge1xuICAgICAgaWRlbnRpdHlTdG9yZToge1xuICAgICAgICBnZXQ6IGFzeW5jICgpID0+IChhd2FpdCB0aGlzLl9sb2FkRGV2aWNlSWRlbnRpdHkoKSksXG4gICAgICAgIHNldDogYXN5bmMgKGlkZW50aXR5KSA9PiBhd2FpdCB0aGlzLl9zYXZlRGV2aWNlSWRlbnRpdHkoaWRlbnRpdHkpLFxuICAgICAgICBjbGVhcjogYXN5bmMgKCkgPT4gYXdhaXQgdGhpcy5fY2xlYXJEZXZpY2VJZGVudGl0eSgpLFxuICAgICAgfSxcbiAgICB9KTtcbiAgICB0aGlzLmNoYXRNYW5hZ2VyID0gbmV3IENoYXRNYW5hZ2VyKCk7XG5cbiAgICAvLyBXaXJlIGluY29taW5nIFdTIG1lc3NhZ2VzIFx1MjE5MiBDaGF0TWFuYWdlclxuICAgIHRoaXMud3NDbGllbnQub25NZXNzYWdlID0gKG1zZykgPT4ge1xuICAgICAgaWYgKG1zZy50eXBlID09PSAnbWVzc2FnZScpIHtcbiAgICAgICAgdGhpcy5jaGF0TWFuYWdlci5hZGRNZXNzYWdlKENoYXRNYW5hZ2VyLmNyZWF0ZUFzc2lzdGFudE1lc3NhZ2UobXNnLnBheWxvYWQuY29udGVudCkpO1xuICAgICAgfSBlbHNlIGlmIChtc2cudHlwZSA9PT0gJ2Vycm9yJykge1xuICAgICAgICBjb25zdCBlcnJUZXh0ID0gbXNnLnBheWxvYWQubWVzc2FnZSA/PyAnVW5rbm93biBlcnJvciBmcm9tIGdhdGV3YXknO1xuICAgICAgICB0aGlzLmNoYXRNYW5hZ2VyLmFkZE1lc3NhZ2UoQ2hhdE1hbmFnZXIuY3JlYXRlU3lzdGVtTWVzc2FnZShgXHUyNkEwICR7ZXJyVGV4dH1gLCAnZXJyb3InKSk7XG4gICAgICB9XG4gICAgfTtcblxuICAgIC8vIFJlZ2lzdGVyIHRoZSBzaWRlYmFyIHZpZXdcbiAgICB0aGlzLnJlZ2lzdGVyVmlldyhcbiAgICAgIFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFULFxuICAgICAgKGxlYWY6IFdvcmtzcGFjZUxlYWYpID0+IG5ldyBPcGVuQ2xhd0NoYXRWaWV3KGxlYWYsIHRoaXMpXG4gICAgKTtcblxuICAgIC8vIFJpYmJvbiBpY29uIFx1MjAxNCBvcGVucyAvIHJldmVhbHMgdGhlIGNoYXQgc2lkZWJhclxuICAgIHRoaXMuYWRkUmliYm9uSWNvbignbWVzc2FnZS1zcXVhcmUnLCAnT3BlbkNsYXcgQ2hhdCcsICgpID0+IHtcbiAgICAgIHRoaXMuX2FjdGl2YXRlQ2hhdFZpZXcoKTtcbiAgICB9KTtcblxuICAgIC8vIFNldHRpbmdzIHRhYlxuICAgIHRoaXMuYWRkU2V0dGluZ1RhYihuZXcgT3BlbkNsYXdTZXR0aW5nVGFiKHRoaXMuYXBwLCB0aGlzKSk7XG5cbiAgICAvLyBDb21tYW5kIHBhbGV0dGUgZW50cnlcbiAgICB0aGlzLmFkZENvbW1hbmQoe1xuICAgICAgaWQ6ICdvcGVuLW9wZW5jbGF3LWNoYXQnLFxuICAgICAgbmFtZTogJ09wZW4gY2hhdCBzaWRlYmFyJyxcbiAgICAgIGNhbGxiYWNrOiAoKSA9PiB0aGlzLl9hY3RpdmF0ZUNoYXRWaWV3KCksXG4gICAgfSk7XG5cbiAgICAvLyBDb25uZWN0IHRvIGdhdGV3YXkgaWYgdG9rZW4gaXMgY29uZmlndXJlZFxuICAgIGlmICh0aGlzLnNldHRpbmdzLmF1dGhUb2tlbikge1xuICAgICAgdGhpcy5fY29ubmVjdFdTKCk7XG4gICAgfSBlbHNlIHtcbiAgICAgIG5ldyBOb3RpY2UoJ09wZW5DbGF3IENoYXQ6IHBsZWFzZSBjb25maWd1cmUgeW91ciBnYXRld2F5IHRva2VuIGluIFNldHRpbmdzLicpO1xuICAgIH1cblxuICAgIGNvbnNvbGUubG9nKCdbb2NsYXddIFBsdWdpbiBsb2FkZWQnKTtcbiAgfVxuXG4gIGFzeW5jIG9udW5sb2FkKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIHRoaXMud3NDbGllbnQuZGlzY29ubmVjdCgpO1xuICAgIHRoaXMuYXBwLndvcmtzcGFjZS5kZXRhY2hMZWF2ZXNPZlR5cGUoVklFV19UWVBFX09QRU5DTEFXX0NIQVQpO1xuICAgIGNvbnNvbGUubG9nKCdbb2NsYXddIFBsdWdpbiB1bmxvYWRlZCcpO1xuICB9XG5cbiAgYXN5bmMgbG9hZFNldHRpbmdzKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIGNvbnN0IGRhdGEgPSAoYXdhaXQgdGhpcy5sb2FkRGF0YSgpKSA/PyB7fTtcbiAgICAvLyBOT1RFOiBwbHVnaW4gZGF0YSBtYXkgY29udGFpbiBleHRyYSBwcml2YXRlIGZpZWxkcyAoZS5nLiBkZXZpY2UgaWRlbnRpdHkpLiBTZXR0aW5ncyBhcmUgdGhlIHB1YmxpYyBzdWJzZXQuXG4gICAgdGhpcy5zZXR0aW5ncyA9IE9iamVjdC5hc3NpZ24oe30sIERFRkFVTFRfU0VUVElOR1MsIGRhdGEpO1xuICB9XG5cbiAgYXN5bmMgc2F2ZVNldHRpbmdzKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIC8vIFByZXNlcnZlIGFueSBwcml2YXRlIGZpZWxkcyBzdG9yZWQgaW4gcGx1Z2luIGRhdGEuXG4gICAgY29uc3QgZGF0YSA9IChhd2FpdCB0aGlzLmxvYWREYXRhKCkpID8/IHt9O1xuICAgIGF3YWl0IHRoaXMuc2F2ZURhdGEoeyAuLi5kYXRhLCAuLi50aGlzLnNldHRpbmdzIH0pO1xuICB9XG5cbiAgLy8gXHUyNTAwXHUyNTAwIERldmljZSBpZGVudGl0eSBwZXJzaXN0ZW5jZSAocGx1Z2luLXNjb3BlZDsgTk9UIGxvY2FsU3RvcmFnZSkgXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG5cbiAgYXN5bmMgcmVzZXREZXZpY2VJZGVudGl0eSgpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBhd2FpdCB0aGlzLl9jbGVhckRldmljZUlkZW50aXR5KCk7XG4gICAgbmV3IE5vdGljZSgnT3BlbkNsYXcgQ2hhdDogZGV2aWNlIGlkZW50aXR5IHJlc2V0LiBSZWNvbm5lY3QgdG8gcGFpciBhZ2Fpbi4nKTtcbiAgfVxuXG4gIHByaXZhdGUgX2RldmljZUlkZW50aXR5S2V5ID0gJ19vcGVuY2xhd0RldmljZUlkZW50aXR5VjEnO1xuXG4gIHByaXZhdGUgYXN5bmMgX2xvYWREZXZpY2VJZGVudGl0eSgpOiBQcm9taXNlPGFueSB8IG51bGw+IHtcbiAgICBjb25zdCBkYXRhID0gKGF3YWl0IHRoaXMubG9hZERhdGEoKSkgPz8ge307XG4gICAgcmV0dXJuIChkYXRhIGFzIGFueSk/Llt0aGlzLl9kZXZpY2VJZGVudGl0eUtleV0gPz8gbnVsbDtcbiAgfVxuXG4gIHByaXZhdGUgYXN5bmMgX3NhdmVEZXZpY2VJZGVudGl0eShpZGVudGl0eTogYW55KTogUHJvbWlzZTx2b2lkPiB7XG4gICAgY29uc3QgZGF0YSA9IChhd2FpdCB0aGlzLmxvYWREYXRhKCkpID8/IHt9O1xuICAgIGF3YWl0IHRoaXMuc2F2ZURhdGEoeyAuLi5kYXRhLCBbdGhpcy5fZGV2aWNlSWRlbnRpdHlLZXldOiBpZGVudGl0eSB9KTtcbiAgfVxuXG4gIHByaXZhdGUgYXN5bmMgX2NsZWFyRGV2aWNlSWRlbnRpdHkoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgY29uc3QgZGF0YSA9IChhd2FpdCB0aGlzLmxvYWREYXRhKCkpID8/IHt9O1xuICAgIGlmICgoZGF0YSBhcyBhbnkpPy5bdGhpcy5fZGV2aWNlSWRlbnRpdHlLZXldID09PSB1bmRlZmluZWQpIHJldHVybjtcbiAgICBjb25zdCBuZXh0ID0geyAuLi4oZGF0YSBhcyBhbnkpIH07XG4gICAgZGVsZXRlIG5leHRbdGhpcy5fZGV2aWNlSWRlbnRpdHlLZXldO1xuICAgIGF3YWl0IHRoaXMuc2F2ZURhdGEobmV4dCk7XG4gIH1cblxuICAvLyBcdTI1MDBcdTI1MDAgSGVscGVycyBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcblxuICBwcml2YXRlIF9jb25uZWN0V1MoKTogdm9pZCB7XG4gICAgdGhpcy53c0NsaWVudC5jb25uZWN0KHRoaXMuc2V0dGluZ3MuZ2F0ZXdheVVybCwgdGhpcy5zZXR0aW5ncy5hdXRoVG9rZW4sIHtcbiAgICAgIGFsbG93SW5zZWN1cmVXczogdGhpcy5zZXR0aW5ncy5hbGxvd0luc2VjdXJlV3MsXG4gICAgfSk7XG4gIH1cblxuICBwcml2YXRlIGFzeW5jIF9hY3RpdmF0ZUNoYXRWaWV3KCk6IFByb21pc2U8dm9pZD4ge1xuICAgIGNvbnN0IHsgd29ya3NwYWNlIH0gPSB0aGlzLmFwcDtcblxuICAgIC8vIFJldXNlIGV4aXN0aW5nIGxlYWYgaWYgYWxyZWFkeSBvcGVuXG4gICAgY29uc3QgZXhpc3RpbmcgPSB3b3Jrc3BhY2UuZ2V0TGVhdmVzT2ZUeXBlKFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFUKTtcbiAgICBpZiAoZXhpc3RpbmcubGVuZ3RoID4gMCkge1xuICAgICAgd29ya3NwYWNlLnJldmVhbExlYWYoZXhpc3RpbmdbMF0pO1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIC8vIE9wZW4gaW4gcmlnaHQgc2lkZWJhclxuICAgIGNvbnN0IGxlYWYgPSB3b3Jrc3BhY2UuZ2V0UmlnaHRMZWFmKGZhbHNlKTtcbiAgICBpZiAoIWxlYWYpIHJldHVybjtcbiAgICBhd2FpdCBsZWFmLnNldFZpZXdTdGF0ZSh7IHR5cGU6IFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFULCBhY3RpdmU6IHRydWUgfSk7XG4gICAgd29ya3NwYWNlLnJldmVhbExlYWYobGVhZik7XG4gIH1cbn1cbiIsICJpbXBvcnQgeyBBcHAsIFBsdWdpblNldHRpbmdUYWIsIFNldHRpbmcgfSBmcm9tICdvYnNpZGlhbic7XG5pbXBvcnQgdHlwZSBPcGVuQ2xhd1BsdWdpbiBmcm9tICcuL21haW4nO1xuXG5leHBvcnQgY2xhc3MgT3BlbkNsYXdTZXR0aW5nVGFiIGV4dGVuZHMgUGx1Z2luU2V0dGluZ1RhYiB7XG4gIHBsdWdpbjogT3BlbkNsYXdQbHVnaW47XG5cbiAgY29uc3RydWN0b3IoYXBwOiBBcHAsIHBsdWdpbjogT3BlbkNsYXdQbHVnaW4pIHtcbiAgICBzdXBlcihhcHAsIHBsdWdpbik7XG4gICAgdGhpcy5wbHVnaW4gPSBwbHVnaW47XG4gIH1cblxuICBkaXNwbGF5KCk6IHZvaWQge1xuICAgIGNvbnN0IHsgY29udGFpbmVyRWwgfSA9IHRoaXM7XG4gICAgY29udGFpbmVyRWwuZW1wdHkoKTtcblxuICAgIGNvbnRhaW5lckVsLmNyZWF0ZUVsKCdoMicsIHsgdGV4dDogJ09wZW5DbGF3IENoYXQgXHUyMDEzIFNldHRpbmdzJyB9KTtcblxuICAgIG5ldyBTZXR0aW5nKGNvbnRhaW5lckVsKVxuICAgICAgLnNldE5hbWUoJ0dhdGV3YXkgVVJMJylcbiAgICAgIC5zZXREZXNjKCdXZWJTb2NrZXQgVVJMIG9mIHRoZSBPcGVuQ2xhdyBHYXRld2F5IChlLmcuIHdzOi8vaG9zdG5hbWU6MTg3ODkpLicpXG4gICAgICAuYWRkVGV4dCgodGV4dCkgPT5cbiAgICAgICAgdGV4dFxuICAgICAgICAgIC5zZXRQbGFjZWhvbGRlcignd3M6Ly9sb2NhbGhvc3Q6MTg3ODknKVxuICAgICAgICAgIC5zZXRWYWx1ZSh0aGlzLnBsdWdpbi5zZXR0aW5ncy5nYXRld2F5VXJsKVxuICAgICAgICAgIC5vbkNoYW5nZShhc3luYyAodmFsdWUpID0+IHtcbiAgICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLmdhdGV3YXlVcmwgPSB2YWx1ZS50cmltKCk7XG4gICAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgICB9KVxuICAgICAgKTtcblxuICAgIG5ldyBTZXR0aW5nKGNvbnRhaW5lckVsKVxuICAgICAgLnNldE5hbWUoJ0F1dGggdG9rZW4nKVxuICAgICAgLnNldERlc2MoJ011c3QgbWF0Y2ggdGhlIGF1dGhUb2tlbiBpbiB5b3VyIG9wZW5jbGF3Lmpzb24gY2hhbm5lbCBjb25maWcuIE5ldmVyIHNoYXJlZC4nKVxuICAgICAgLmFkZFRleHQoKHRleHQpID0+IHtcbiAgICAgICAgdGV4dFxuICAgICAgICAgIC5zZXRQbGFjZWhvbGRlcignRW50ZXIgdG9rZW5cdTIwMjYnKVxuICAgICAgICAgIC5zZXRWYWx1ZSh0aGlzLnBsdWdpbi5zZXR0aW5ncy5hdXRoVG9rZW4pXG4gICAgICAgICAgLm9uQ2hhbmdlKGFzeW5jICh2YWx1ZSkgPT4ge1xuICAgICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3MuYXV0aFRva2VuID0gdmFsdWU7XG4gICAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgICB9KTtcbiAgICAgICAgLy8gVHJlYXQgYXMgcGFzc3dvcmQgZmllbGQgXHUyMDEzIGRvIG5vdCByZXZlYWwgdG9rZW4gaW4gVUlcbiAgICAgICAgdGV4dC5pbnB1dEVsLnR5cGUgPSAncGFzc3dvcmQnO1xuICAgICAgICB0ZXh0LmlucHV0RWwuYXV0b2NvbXBsZXRlID0gJ29mZic7XG4gICAgICB9KTtcblxuICAgIG5ldyBTZXR0aW5nKGNvbnRhaW5lckVsKVxuICAgICAgLnNldE5hbWUoJ1Nlc3Npb24gS2V5JylcbiAgICAgIC5zZXREZXNjKCdPcGVuQ2xhdyBzZXNzaW9uIHRvIHN1YnNjcmliZSB0byAodXN1YWxseSBcIm1haW5cIikuJylcbiAgICAgIC5hZGRUZXh0KCh0ZXh0KSA9PlxuICAgICAgICB0ZXh0XG4gICAgICAgICAgLnNldFBsYWNlaG9sZGVyKCdtYWluJylcbiAgICAgICAgICAuc2V0VmFsdWUodGhpcy5wbHVnaW4uc2V0dGluZ3Muc2Vzc2lvbktleSlcbiAgICAgICAgICAub25DaGFuZ2UoYXN5bmMgKHZhbHVlKSA9PiB7XG4gICAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5zZXNzaW9uS2V5ID0gdmFsdWUudHJpbSgpIHx8ICdtYWluJztcbiAgICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICAgIH0pXG4gICAgICApO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZSgnQWNjb3VudCBJRCcpXG4gICAgICAuc2V0RGVzYygnT3BlbkNsYXcgYWNjb3VudCBJRCAodXN1YWxseSBcIm1haW5cIikuJylcbiAgICAgIC5hZGRUZXh0KCh0ZXh0KSA9PlxuICAgICAgICB0ZXh0XG4gICAgICAgICAgLnNldFBsYWNlaG9sZGVyKCdtYWluJylcbiAgICAgICAgICAuc2V0VmFsdWUodGhpcy5wbHVnaW4uc2V0dGluZ3MuYWNjb3VudElkKVxuICAgICAgICAgIC5vbkNoYW5nZShhc3luYyAodmFsdWUpID0+IHtcbiAgICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLmFjY291bnRJZCA9IHZhbHVlLnRyaW0oKSB8fCAnbWFpbic7XG4gICAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgICB9KVxuICAgICAgKTtcblxuICAgIG5ldyBTZXR0aW5nKGNvbnRhaW5lckVsKVxuICAgICAgLnNldE5hbWUoJ0luY2x1ZGUgYWN0aXZlIG5vdGUgYnkgZGVmYXVsdCcpXG4gICAgICAuc2V0RGVzYygnUHJlLWNoZWNrIFwiSW5jbHVkZSBhY3RpdmUgbm90ZVwiIGluIHRoZSBjaGF0IHBhbmVsIHdoZW4gaXQgb3BlbnMuJylcbiAgICAgIC5hZGRUb2dnbGUoKHRvZ2dsZSkgPT5cbiAgICAgICAgdG9nZ2xlLnNldFZhbHVlKHRoaXMucGx1Z2luLnNldHRpbmdzLmluY2x1ZGVBY3RpdmVOb3RlKS5vbkNoYW5nZShhc3luYyAodmFsdWUpID0+IHtcbiAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5pbmNsdWRlQWN0aXZlTm90ZSA9IHZhbHVlO1xuICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICB9KVxuICAgICAgKTtcblxuICAgIG5ldyBTZXR0aW5nKGNvbnRhaW5lckVsKVxuICAgICAgLnNldE5hbWUoJ1JlbmRlciBhc3Npc3RhbnQgYXMgTWFya2Rvd24gKHVuc2FmZSknKVxuICAgICAgLnNldERlc2MoXG4gICAgICAgICdPRkYgcmVjb21tZW5kZWQuIElmIGVuYWJsZWQsIGFzc2lzdGFudCBvdXRwdXQgaXMgcmVuZGVyZWQgYXMgT2JzaWRpYW4gTWFya2Rvd24gd2hpY2ggbWF5IHRyaWdnZXIgZW1iZWRzIGFuZCBvdGhlciBwbHVnaW5zXFwnIHBvc3QtcHJvY2Vzc29ycy4nXG4gICAgICApXG4gICAgICAuYWRkVG9nZ2xlKCh0b2dnbGUpID0+XG4gICAgICAgIHRvZ2dsZS5zZXRWYWx1ZSh0aGlzLnBsdWdpbi5zZXR0aW5ncy5yZW5kZXJBc3Npc3RhbnRNYXJrZG93bikub25DaGFuZ2UoYXN5bmMgKHZhbHVlKSA9PiB7XG4gICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3MucmVuZGVyQXNzaXN0YW50TWFya2Rvd24gPSB2YWx1ZTtcbiAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgfSlcbiAgICAgICk7XG5cbiAgICBuZXcgU2V0dGluZyhjb250YWluZXJFbClcbiAgICAgIC5zZXROYW1lKCdBbGxvdyBpbnNlY3VyZSB3czovLyBmb3Igbm9uLWxvY2FsIGdhdGV3YXlzICh1bnNhZmUpJylcbiAgICAgIC5zZXREZXNjKFxuICAgICAgICAnT0ZGIHJlY29tbWVuZGVkLiBJZiBlbmFibGVkLCB5b3UgY2FuIGNvbm5lY3QgdG8gbm9uLWxvY2FsIGdhdGV3YXlzIG92ZXIgd3M6Ly8uIFRoaXMgZXhwb3NlcyB5b3VyIHRva2VuIGFuZCBtZXNzYWdlIGNvbnRlbnQgdG8gbmV0d29yayBhdHRhY2tlcnM7IHByZWZlciB3c3M6Ly8uJ1xuICAgICAgKVxuICAgICAgLmFkZFRvZ2dsZSgodG9nZ2xlKSA9PlxuICAgICAgICB0b2dnbGUuc2V0VmFsdWUodGhpcy5wbHVnaW4uc2V0dGluZ3MuYWxsb3dJbnNlY3VyZVdzKS5vbkNoYW5nZShhc3luYyAodmFsdWUpID0+IHtcbiAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5hbGxvd0luc2VjdXJlV3MgPSB2YWx1ZTtcbiAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgfSlcbiAgICAgICk7XG5cbiAgICBuZXcgU2V0dGluZyhjb250YWluZXJFbClcbiAgICAgIC5zZXROYW1lKCdSZXNldCBkZXZpY2UgaWRlbnRpdHkgKHJlLXBhaXIpJylcbiAgICAgIC5zZXREZXNjKCdDbGVhcnMgdGhlIHN0b3JlZCBkZXZpY2UgaWRlbnRpdHkgdXNlZCBmb3Igb3BlcmF0b3Iud3JpdGUgcGFpcmluZy4gVXNlIHRoaXMgaWYgeW91IHN1c3BlY3QgY29tcHJvbWlzZSBvciBzZWUgXCJkZXZpY2UgaWRlbnRpdHkgbWlzbWF0Y2hcIi4nKVxuICAgICAgLmFkZEJ1dHRvbigoYnRuKSA9PlxuICAgICAgICBidG4uc2V0QnV0dG9uVGV4dCgnUmVzZXQnKS5zZXRXYXJuaW5nKCkub25DbGljayhhc3luYyAoKSA9PiB7XG4gICAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4ucmVzZXREZXZpY2VJZGVudGl0eSgpO1xuICAgICAgICB9KVxuICAgICAgKTtcblxuICAgIC8vIFx1MjUwMFx1MjUwMCBQYXRoIG1hcHBpbmdzIFx1MjUwMFx1MjUwMFxuICAgIGNvbnRhaW5lckVsLmNyZWF0ZUVsKCdoMycsIHsgdGV4dDogJ1BhdGggbWFwcGluZ3MgKHZhdWx0IGJhc2UgXHUyMTkyIHJlbW90ZSBiYXNlKScgfSk7XG4gICAgY29udGFpbmVyRWwuY3JlYXRlRWwoJ3AnLCB7XG4gICAgICB0ZXh0OiAnVXNlZCB0byBjb252ZXJ0IGFzc2lzdGFudCBmaWxlIHJlZmVyZW5jZXMgKHJlbW90ZSBGUyBwYXRocyBvciBleHBvcnRlZCBVUkxzKSBpbnRvIGNsaWNrYWJsZSBPYnNpZGlhbiBsaW5rcy4gRmlyc3QgbWF0Y2ggd2lucy4gT25seSBjcmVhdGVzIGEgbGluayBpZiB0aGUgbWFwcGVkIHZhdWx0IGZpbGUgZXhpc3RzLicsXG4gICAgICBjbHM6ICdzZXR0aW5nLWl0ZW0tZGVzY3JpcHRpb24nLFxuICAgIH0pO1xuXG4gICAgY29uc3QgbWFwcGluZ3MgPSB0aGlzLnBsdWdpbi5zZXR0aW5ncy5wYXRoTWFwcGluZ3MgPz8gW107XG5cbiAgICBjb25zdCByZXJlbmRlciA9IGFzeW5jICgpID0+IHtcbiAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgdGhpcy5kaXNwbGF5KCk7XG4gICAgfTtcblxuICAgIG1hcHBpbmdzLmZvckVhY2goKHJvdywgaWR4KSA9PiB7XG4gICAgICBjb25zdCBzID0gbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAgIC5zZXROYW1lKGBNYXBwaW5nICMke2lkeCArIDF9YClcbiAgICAgICAgLnNldERlc2MoJ3ZhdWx0QmFzZSBcdTIxOTIgcmVtb3RlQmFzZScpO1xuXG4gICAgICBzLmFkZFRleHQoKHQpID0+XG4gICAgICAgIHRcbiAgICAgICAgICAuc2V0UGxhY2Vob2xkZXIoJ3ZhdWx0IGJhc2UgKGUuZy4gZG9jcy8pJylcbiAgICAgICAgICAuc2V0VmFsdWUocm93LnZhdWx0QmFzZSA/PyAnJylcbiAgICAgICAgICAub25DaGFuZ2UoYXN5bmMgKHYpID0+IHtcbiAgICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLnBhdGhNYXBwaW5nc1tpZHhdLnZhdWx0QmFzZSA9IHY7XG4gICAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgICB9KVxuICAgICAgKTtcblxuICAgICAgcy5hZGRUZXh0KCh0KSA9PlxuICAgICAgICB0XG4gICAgICAgICAgLnNldFBsYWNlaG9sZGVyKCdyZW1vdGUgYmFzZSAoZS5nLiAvaG9tZS8uLi4vZG9jcy8pJylcbiAgICAgICAgICAuc2V0VmFsdWUocm93LnJlbW90ZUJhc2UgPz8gJycpXG4gICAgICAgICAgLm9uQ2hhbmdlKGFzeW5jICh2KSA9PiB7XG4gICAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5wYXRoTWFwcGluZ3NbaWR4XS5yZW1vdGVCYXNlID0gdjtcbiAgICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICAgIH0pXG4gICAgICApO1xuXG4gICAgICBzLmFkZEV4dHJhQnV0dG9uKChiKSA9PlxuICAgICAgICBiXG4gICAgICAgICAgLnNldEljb24oJ3RyYXNoJylcbiAgICAgICAgICAuc2V0VG9vbHRpcCgnUmVtb3ZlIG1hcHBpbmcnKVxuICAgICAgICAgIC5vbkNsaWNrKGFzeW5jICgpID0+IHtcbiAgICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLnBhdGhNYXBwaW5ncy5zcGxpY2UoaWR4LCAxKTtcbiAgICAgICAgICAgIGF3YWl0IHJlcmVuZGVyKCk7XG4gICAgICAgICAgfSlcbiAgICAgICk7XG4gICAgfSk7XG5cbiAgICBuZXcgU2V0dGluZyhjb250YWluZXJFbClcbiAgICAgIC5zZXROYW1lKCdBZGQgbWFwcGluZycpXG4gICAgICAuc2V0RGVzYygnQWRkIGEgbmV3IHZhdWx0QmFzZSBcdTIxOTIgcmVtb3RlQmFzZSBtYXBwaW5nIHJvdy4nKVxuICAgICAgLmFkZEJ1dHRvbigoYnRuKSA9PlxuICAgICAgICBidG4uc2V0QnV0dG9uVGV4dCgnQWRkJykub25DbGljayhhc3luYyAoKSA9PiB7XG4gICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3MucGF0aE1hcHBpbmdzLnB1c2goeyB2YXVsdEJhc2U6ICcnLCByZW1vdGVCYXNlOiAnJyB9KTtcbiAgICAgICAgICBhd2FpdCByZXJlbmRlcigpO1xuICAgICAgICB9KVxuICAgICAgKTtcblxuICAgIGNvbnRhaW5lckVsLmNyZWF0ZUVsKCdwJywge1xuICAgICAgdGV4dDogJ1JlY29ubmVjdDogY2xvc2UgYW5kIHJlb3BlbiB0aGUgc2lkZWJhciBhZnRlciBjaGFuZ2luZyB0aGUgZ2F0ZXdheSBVUkwgb3IgdG9rZW4uJyxcbiAgICAgIGNsczogJ3NldHRpbmctaXRlbS1kZXNjcmlwdGlvbicsXG4gICAgfSk7XG4gIH1cbn1cbiIsICIvKipcbiAqIFdlYlNvY2tldCBjbGllbnQgZm9yIE9wZW5DbGF3IEdhdGV3YXlcbiAqXG4gKiBQaXZvdCAoMjAyNi0wMi0yNSk6IERvIE5PVCB1c2UgY3VzdG9tIG9ic2lkaWFuLiogZ2F0ZXdheSBtZXRob2RzLlxuICogVGhvc2UgcmVxdWlyZSBvcGVyYXRvci5hZG1pbiBzY29wZSB3aGljaCBpcyBub3QgZ3JhbnRlZCB0byBleHRlcm5hbCBjbGllbnRzLlxuICpcbiAqIEF1dGggbm90ZTpcbiAqIC0gY2hhdC5zZW5kIHJlcXVpcmVzIG9wZXJhdG9yLndyaXRlXG4gKiAtIGV4dGVybmFsIGNsaWVudHMgbXVzdCBwcmVzZW50IGEgcGFpcmVkIGRldmljZSBpZGVudGl0eSB0byByZWNlaXZlIHdyaXRlIHNjb3Blc1xuICpcbiAqIFdlIHVzZSBidWlsdC1pbiBnYXRld2F5IG1ldGhvZHMvZXZlbnRzOlxuICogLSBTZW5kOiBjaGF0LnNlbmQoeyBzZXNzaW9uS2V5LCBtZXNzYWdlLCBpZGVtcG90ZW5jeUtleSwgLi4uIH0pXG4gKiAtIFJlY2VpdmU6IGV2ZW50IFwiY2hhdFwiIChmaWx0ZXIgYnkgc2Vzc2lvbktleSlcbiAqL1xuXG5pbXBvcnQgdHlwZSB7IEluYm91bmRXU1BheWxvYWQsIFNlc3Npb25zTGlzdFJlc3VsdCB9IGZyb20gJy4vdHlwZXMnO1xuXG5mdW5jdGlvbiBpc0xvY2FsSG9zdChob3N0OiBzdHJpbmcpOiBib29sZWFuIHtcbiAgY29uc3QgaCA9IGhvc3QudG9Mb3dlckNhc2UoKTtcbiAgcmV0dXJuIGggPT09ICdsb2NhbGhvc3QnIHx8IGggPT09ICcxMjcuMC4wLjEnIHx8IGggPT09ICc6OjEnO1xufVxuXG5mdW5jdGlvbiBzYWZlUGFyc2VXc1VybCh1cmw6IHN0cmluZyk6XG4gIHwgeyBvazogdHJ1ZTsgc2NoZW1lOiAnd3MnIHwgJ3dzcyc7IGhvc3Q6IHN0cmluZyB9XG4gIHwgeyBvazogZmFsc2U7IGVycm9yOiBzdHJpbmcgfSB7XG4gIHRyeSB7XG4gICAgY29uc3QgdSA9IG5ldyBVUkwodXJsKTtcbiAgICBpZiAodS5wcm90b2NvbCAhPT0gJ3dzOicgJiYgdS5wcm90b2NvbCAhPT0gJ3dzczonKSB7XG4gICAgICByZXR1cm4geyBvazogZmFsc2UsIGVycm9yOiBgR2F0ZXdheSBVUkwgbXVzdCBiZSB3czovLyBvciB3c3M6Ly8gKGdvdCAke3UucHJvdG9jb2x9KWAgfTtcbiAgICB9XG4gICAgY29uc3Qgc2NoZW1lID0gdS5wcm90b2NvbCA9PT0gJ3dzOicgPyAnd3MnIDogJ3dzcyc7XG4gICAgcmV0dXJuIHsgb2s6IHRydWUsIHNjaGVtZSwgaG9zdDogdS5ob3N0bmFtZSB9O1xuICB9IGNhdGNoIHtcbiAgICByZXR1cm4geyBvazogZmFsc2UsIGVycm9yOiAnSW52YWxpZCBnYXRld2F5IFVSTCcgfTtcbiAgfVxufVxuXG4vKiogSW50ZXJ2YWwgZm9yIHNlbmRpbmcgaGVhcnRiZWF0IHBpbmdzIChjaGVjayBjb25uZWN0aW9uIGxpdmVuZXNzKSAqL1xuY29uc3QgSEVBUlRCRUFUX0lOVEVSVkFMX01TID0gMzBfMDAwO1xuXG4vKiogU2FmZXR5IHZhbHZlOiBoaWRlIHdvcmtpbmcgc3Bpbm5lciBpZiBubyBhc3Npc3RhbnQgcmVwbHkgYXJyaXZlcyBpbiB0aW1lICovXG5jb25zdCBXT1JLSU5HX01BWF9NUyA9IDEyMF8wMDA7XG5cbi8qKiBNYXggaW5ib3VuZCBmcmFtZSBzaXplIHRvIHBhcnNlIChEb1MgZ3VhcmQpICovXG5jb25zdCBNQVhfSU5CT1VORF9GUkFNRV9CWVRFUyA9IDUxMiAqIDEwMjQ7XG5cbmZ1bmN0aW9uIGJ5dGVMZW5ndGhVdGY4KHRleHQ6IHN0cmluZyk6IG51bWJlciB7XG4gIHJldHVybiB1dGY4Qnl0ZXModGV4dCkuYnl0ZUxlbmd0aDtcbn1cblxuYXN5bmMgZnVuY3Rpb24gbm9ybWFsaXplV3NEYXRhVG9UZXh0KGRhdGE6IGFueSk6IFByb21pc2U8eyBvazogdHJ1ZTsgdGV4dDogc3RyaW5nOyBieXRlczogbnVtYmVyIH0gfCB7IG9rOiBmYWxzZTsgcmVhc29uOiBzdHJpbmc7IGJ5dGVzPzogbnVtYmVyIH0+IHtcbiAgaWYgKHR5cGVvZiBkYXRhID09PSAnc3RyaW5nJykge1xuICAgIGNvbnN0IGJ5dGVzID0gYnl0ZUxlbmd0aFV0ZjgoZGF0YSk7XG4gICAgcmV0dXJuIHsgb2s6IHRydWUsIHRleHQ6IGRhdGEsIGJ5dGVzIH07XG4gIH1cblxuICAvLyBCcm93c2VyIFdlYlNvY2tldCBjYW4gZGVsaXZlciBCbG9iXG4gIGlmICh0eXBlb2YgQmxvYiAhPT0gJ3VuZGVmaW5lZCcgJiYgZGF0YSBpbnN0YW5jZW9mIEJsb2IpIHtcbiAgICBjb25zdCBieXRlcyA9IGRhdGEuc2l6ZTtcbiAgICBpZiAoYnl0ZXMgPiBNQVhfSU5CT1VORF9GUkFNRV9CWVRFUykgcmV0dXJuIHsgb2s6IGZhbHNlLCByZWFzb246ICd0b28tbGFyZ2UnLCBieXRlcyB9O1xuICAgIGNvbnN0IHRleHQgPSBhd2FpdCBkYXRhLnRleHQoKTtcbiAgICAvLyBCbG9iLnNpemUgaXMgYnl0ZXMgYWxyZWFkeTsgbm8gbmVlZCB0byByZS1tZWFzdXJlLlxuICAgIHJldHVybiB7IG9rOiB0cnVlLCB0ZXh0LCBieXRlcyB9O1xuICB9XG5cbiAgaWYgKGRhdGEgaW5zdGFuY2VvZiBBcnJheUJ1ZmZlcikge1xuICAgIGNvbnN0IGJ5dGVzID0gZGF0YS5ieXRlTGVuZ3RoO1xuICAgIGlmIChieXRlcyA+IE1BWF9JTkJPVU5EX0ZSQU1FX0JZVEVTKSByZXR1cm4geyBvazogZmFsc2UsIHJlYXNvbjogJ3Rvby1sYXJnZScsIGJ5dGVzIH07XG4gICAgY29uc3QgdGV4dCA9IG5ldyBUZXh0RGVjb2RlcigndXRmLTgnLCB7IGZhdGFsOiBmYWxzZSB9KS5kZWNvZGUobmV3IFVpbnQ4QXJyYXkoZGF0YSkpO1xuICAgIHJldHVybiB7IG9rOiB0cnVlLCB0ZXh0LCBieXRlcyB9O1xuICB9XG5cbiAgLy8gU29tZSBydW50aW1lcyBjb3VsZCBwYXNzIFVpbnQ4QXJyYXkgZGlyZWN0bHlcbiAgaWYgKGRhdGEgaW5zdGFuY2VvZiBVaW50OEFycmF5KSB7XG4gICAgY29uc3QgYnl0ZXMgPSBkYXRhLmJ5dGVMZW5ndGg7XG4gICAgaWYgKGJ5dGVzID4gTUFYX0lOQk9VTkRfRlJBTUVfQllURVMpIHJldHVybiB7IG9rOiBmYWxzZSwgcmVhc29uOiAndG9vLWxhcmdlJywgYnl0ZXMgfTtcbiAgICBjb25zdCB0ZXh0ID0gbmV3IFRleHREZWNvZGVyKCd1dGYtOCcsIHsgZmF0YWw6IGZhbHNlIH0pLmRlY29kZShkYXRhKTtcbiAgICByZXR1cm4geyBvazogdHJ1ZSwgdGV4dCwgYnl0ZXMgfTtcbiAgfVxuXG4gIHJldHVybiB7IG9rOiBmYWxzZSwgcmVhc29uOiAndW5zdXBwb3J0ZWQtdHlwZScgfTtcbn1cblxuLyoqIE1heCBpbi1mbGlnaHQgcmVxdWVzdHMgYmVmb3JlIGZhc3QtZmFpbGluZyAoRG9TL3JvYnVzdG5lc3MgZ3VhcmQpICovXG5jb25zdCBNQVhfUEVORElOR19SRVFVRVNUUyA9IDIwMDtcblxuLyoqIFJlY29ubmVjdCBiYWNrb2ZmICovXG5jb25zdCBSRUNPTk5FQ1RfQkFTRV9NUyA9IDNfMDAwO1xuY29uc3QgUkVDT05ORUNUX01BWF9NUyA9IDYwXzAwMDtcblxuLyoqIEhhbmRzaGFrZSBkZWFkbGluZSB3YWl0aW5nIGZvciBjb25uZWN0LmNoYWxsZW5nZSAqL1xuY29uc3QgSEFORFNIQUtFX1RJTUVPVVRfTVMgPSAxNV8wMDA7XG5cbmV4cG9ydCB0eXBlIFdTQ2xpZW50U3RhdGUgPSAnZGlzY29ubmVjdGVkJyB8ICdjb25uZWN0aW5nJyB8ICdoYW5kc2hha2luZycgfCAnY29ubmVjdGVkJztcblxuZXhwb3J0IHR5cGUgV29ya2luZ1N0YXRlTGlzdGVuZXIgPSAod29ya2luZzogYm9vbGVhbikgPT4gdm9pZDtcblxuaW50ZXJmYWNlIFBlbmRpbmdSZXF1ZXN0IHtcbiAgcmVzb2x2ZTogKHBheWxvYWQ6IGFueSkgPT4gdm9pZDtcbiAgcmVqZWN0OiAoZXJyb3I6IGFueSkgPT4gdm9pZDtcbiAgdGltZW91dDogUmV0dXJuVHlwZTx0eXBlb2Ygc2V0VGltZW91dD4gfCBudWxsO1xufVxuXG5leHBvcnQgdHlwZSBEZXZpY2VJZGVudGl0eSA9IHtcbiAgaWQ6IHN0cmluZztcbiAgcHVibGljS2V5OiBzdHJpbmc7IC8vIGJhc2U2NFxuICBwcml2YXRlS2V5SndrOiBKc29uV2ViS2V5O1xufTtcblxuZXhwb3J0IGludGVyZmFjZSBEZXZpY2VJZGVudGl0eVN0b3JlIHtcbiAgZ2V0KCk6IFByb21pc2U8RGV2aWNlSWRlbnRpdHkgfCBudWxsPjtcbiAgc2V0KGlkZW50aXR5OiBEZXZpY2VJZGVudGl0eSk6IFByb21pc2U8dm9pZD47XG4gIGNsZWFyKCk6IFByb21pc2U8dm9pZD47XG59XG5cbmNvbnN0IERFVklDRV9TVE9SQUdFX0tFWSA9ICdvcGVuY2xhd0NoYXQuZGV2aWNlSWRlbnRpdHkudjEnOyAvLyBsZWdhY3kgbG9jYWxTdG9yYWdlIGtleSAobWlncmF0aW9uIG9ubHkpXG5cbmZ1bmN0aW9uIGJhc2U2NFVybEVuY29kZShieXRlczogQXJyYXlCdWZmZXIpOiBzdHJpbmcge1xuICBjb25zdCB1OCA9IG5ldyBVaW50OEFycmF5KGJ5dGVzKTtcbiAgbGV0IHMgPSAnJztcbiAgZm9yIChsZXQgaSA9IDA7IGkgPCB1OC5sZW5ndGg7IGkrKykgcyArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKHU4W2ldKTtcbiAgY29uc3QgYjY0ID0gYnRvYShzKTtcbiAgcmV0dXJuIGI2NC5yZXBsYWNlKC9cXCsvZywgJy0nKS5yZXBsYWNlKC9cXC8vZywgJ18nKS5yZXBsYWNlKC89KyQvZywgJycpO1xufVxuXG5mdW5jdGlvbiBoZXhFbmNvZGUoYnl0ZXM6IEFycmF5QnVmZmVyKTogc3RyaW5nIHtcbiAgY29uc3QgdTggPSBuZXcgVWludDhBcnJheShieXRlcyk7XG4gIHJldHVybiBBcnJheS5mcm9tKHU4KVxuICAgIC5tYXAoKGIpID0+IGIudG9TdHJpbmcoMTYpLnBhZFN0YXJ0KDIsICcwJykpXG4gICAgLmpvaW4oJycpO1xufVxuXG5mdW5jdGlvbiB1dGY4Qnl0ZXModGV4dDogc3RyaW5nKTogVWludDhBcnJheSB7XG4gIHJldHVybiBuZXcgVGV4dEVuY29kZXIoKS5lbmNvZGUodGV4dCk7XG59XG5cbmFzeW5jIGZ1bmN0aW9uIHNoYTI1NkhleChieXRlczogQXJyYXlCdWZmZXIpOiBQcm9taXNlPHN0cmluZz4ge1xuICBjb25zdCBkaWdlc3QgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmRpZ2VzdCgnU0hBLTI1NicsIGJ5dGVzKTtcbiAgcmV0dXJuIGhleEVuY29kZShkaWdlc3QpO1xufVxuXG5hc3luYyBmdW5jdGlvbiBsb2FkT3JDcmVhdGVEZXZpY2VJZGVudGl0eShzdG9yZT86IERldmljZUlkZW50aXR5U3RvcmUpOiBQcm9taXNlPERldmljZUlkZW50aXR5PiB7XG4gIC8vIDEpIFByZWZlciBwbHVnaW4tc2NvcGVkIHN0b3JhZ2UgKGluamVjdGVkIGJ5IG1haW4gcGx1Z2luKS5cbiAgaWYgKHN0b3JlKSB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IGV4aXN0aW5nID0gYXdhaXQgc3RvcmUuZ2V0KCk7XG4gICAgICBpZiAoZXhpc3Rpbmc/LmlkICYmIGV4aXN0aW5nPy5wdWJsaWNLZXkgJiYgZXhpc3Rpbmc/LnByaXZhdGVLZXlKd2spIHJldHVybiBleGlzdGluZztcbiAgICB9IGNhdGNoIHtcbiAgICAgIC8vIGlnbm9yZSBhbmQgY29udGludWUgKHdlIGNhbiBhbHdheXMgcmUtZ2VuZXJhdGUpXG4gICAgfVxuICB9XG5cbiAgLy8gMikgT25lLXRpbWUgbWlncmF0aW9uOiBsZWdhY3kgbG9jYWxTdG9yYWdlIGlkZW50aXR5LlxuICAvLyBOT1RFOiB0aGlzIHJlbWFpbnMgYSByaXNrIGJvdW5kYXJ5OyB3ZSBvbmx5IHJlYWQrZGVsZXRlIGZvciBtaWdyYXRpb24uXG4gIGNvbnN0IGxlZ2FjeSA9IGxvY2FsU3RvcmFnZS5nZXRJdGVtKERFVklDRV9TVE9SQUdFX0tFWSk7XG4gIGlmIChsZWdhY3kpIHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgcGFyc2VkID0gSlNPTi5wYXJzZShsZWdhY3kpIGFzIERldmljZUlkZW50aXR5O1xuICAgICAgaWYgKHBhcnNlZD8uaWQgJiYgcGFyc2VkPy5wdWJsaWNLZXkgJiYgcGFyc2VkPy5wcml2YXRlS2V5SndrKSB7XG4gICAgICAgIGlmIChzdG9yZSkge1xuICAgICAgICAgIGF3YWl0IHN0b3JlLnNldChwYXJzZWQpO1xuICAgICAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKERFVklDRV9TVE9SQUdFX0tFWSk7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIHBhcnNlZDtcbiAgICAgIH1cbiAgICB9IGNhdGNoIHtcbiAgICAgIC8vIENvcnJ1cHQvcGFydGlhbCBkYXRhIFx1MjE5MiBkZWxldGUgYW5kIHJlLWNyZWF0ZS5cbiAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKERFVklDRV9TVE9SQUdFX0tFWSk7XG4gICAgfVxuICB9XG5cbiAgLy8gMykgQ3JlYXRlIGEgbmV3IGlkZW50aXR5LlxuICBjb25zdCBrZXlQYWlyID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5nZW5lcmF0ZUtleSh7IG5hbWU6ICdFZDI1NTE5JyB9LCB0cnVlLCBbJ3NpZ24nLCAndmVyaWZ5J10pO1xuICBjb25zdCBwdWJSYXcgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmV4cG9ydEtleSgncmF3Jywga2V5UGFpci5wdWJsaWNLZXkpO1xuICBjb25zdCBwcml2SndrID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5leHBvcnRLZXkoJ2p3aycsIGtleVBhaXIucHJpdmF0ZUtleSk7XG5cbiAgLy8gSU1QT1JUQU5UOiBkZXZpY2UuaWQgbXVzdCBiZSBhIHN0YWJsZSBmaW5nZXJwcmludCBmb3IgdGhlIHB1YmxpYyBrZXkuXG4gIC8vIFRoZSBnYXRld2F5IGVuZm9yY2VzIGRldmljZUlkIFx1MjE5NCBwdWJsaWNLZXkgYmluZGluZzsgcmFuZG9tIGlkcyBjYW4gY2F1c2UgXCJkZXZpY2UgaWRlbnRpdHkgbWlzbWF0Y2hcIi5cbiAgY29uc3QgZGV2aWNlSWQgPSBhd2FpdCBzaGEyNTZIZXgocHViUmF3KTtcblxuICBjb25zdCBpZGVudGl0eTogRGV2aWNlSWRlbnRpdHkgPSB7XG4gICAgaWQ6IGRldmljZUlkLFxuICAgIHB1YmxpY0tleTogYmFzZTY0VXJsRW5jb2RlKHB1YlJhdyksXG4gICAgcHJpdmF0ZUtleUp3azogcHJpdkp3ayxcbiAgfTtcblxuICBpZiAoc3RvcmUpIHtcbiAgICBhd2FpdCBzdG9yZS5zZXQoaWRlbnRpdHkpO1xuICB9IGVsc2Uge1xuICAgIC8vIEZhbGxiYWNrIChzaG91bGQgbm90IGhhcHBlbiBpbiByZWFsIHBsdWdpbiBydW50aW1lKSBcdTIwMTQga2VlcCBsZWdhY3kgYmVoYXZpb3IuXG4gICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oREVWSUNFX1NUT1JBR0VfS0VZLCBKU09OLnN0cmluZ2lmeShpZGVudGl0eSkpO1xuICB9XG5cbiAgcmV0dXJuIGlkZW50aXR5O1xufVxuXG5mdW5jdGlvbiBidWlsZERldmljZUF1dGhQYXlsb2FkKHBhcmFtczoge1xuICBkZXZpY2VJZDogc3RyaW5nO1xuICBjbGllbnRJZDogc3RyaW5nO1xuICBjbGllbnRNb2RlOiBzdHJpbmc7XG4gIHJvbGU6IHN0cmluZztcbiAgc2NvcGVzOiBzdHJpbmdbXTtcbiAgc2lnbmVkQXRNczogbnVtYmVyO1xuICB0b2tlbjogc3RyaW5nO1xuICBub25jZT86IHN0cmluZztcbn0pOiBzdHJpbmcge1xuICBjb25zdCB2ZXJzaW9uID0gcGFyYW1zLm5vbmNlID8gJ3YyJyA6ICd2MSc7XG4gIGNvbnN0IHNjb3BlcyA9IHBhcmFtcy5zY29wZXMuam9pbignLCcpO1xuICBjb25zdCBiYXNlID0gW1xuICAgIHZlcnNpb24sXG4gICAgcGFyYW1zLmRldmljZUlkLFxuICAgIHBhcmFtcy5jbGllbnRJZCxcbiAgICBwYXJhbXMuY2xpZW50TW9kZSxcbiAgICBwYXJhbXMucm9sZSxcbiAgICBzY29wZXMsXG4gICAgU3RyaW5nKHBhcmFtcy5zaWduZWRBdE1zKSxcbiAgICBwYXJhbXMudG9rZW4gfHwgJycsXG4gIF07XG4gIGlmICh2ZXJzaW9uID09PSAndjInKSBiYXNlLnB1c2gocGFyYW1zLm5vbmNlIHx8ICcnKTtcbiAgcmV0dXJuIGJhc2Uuam9pbignfCcpO1xufVxuXG5hc3luYyBmdW5jdGlvbiBzaWduRGV2aWNlUGF5bG9hZChpZGVudGl0eTogRGV2aWNlSWRlbnRpdHksIHBheWxvYWQ6IHN0cmluZyk6IFByb21pc2U8eyBzaWduYXR1cmU6IHN0cmluZyB9PiB7XG4gIGNvbnN0IHByaXZhdGVLZXkgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmltcG9ydEtleShcbiAgICAnandrJyxcbiAgICBpZGVudGl0eS5wcml2YXRlS2V5SndrLFxuICAgIHsgbmFtZTogJ0VkMjU1MTknIH0sXG4gICAgZmFsc2UsXG4gICAgWydzaWduJ10sXG4gICk7XG5cbiAgY29uc3Qgc2lnID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5zaWduKHsgbmFtZTogJ0VkMjU1MTknIH0sIHByaXZhdGVLZXksIHV0ZjhCeXRlcyhwYXlsb2FkKSBhcyB1bmtub3duIGFzIEJ1ZmZlclNvdXJjZSk7XG4gIHJldHVybiB7IHNpZ25hdHVyZTogYmFzZTY0VXJsRW5jb2RlKHNpZykgfTtcbn1cblxuZnVuY3Rpb24gZXh0cmFjdFRleHRGcm9tR2F0ZXdheU1lc3NhZ2UobXNnOiBhbnkpOiBzdHJpbmcge1xuICBpZiAoIW1zZykgcmV0dXJuICcnO1xuXG4gIC8vIE1vc3QgY29tbW9uOiB7IHJvbGUsIGNvbnRlbnQgfSB3aGVyZSBjb250ZW50IGNhbiBiZSBzdHJpbmcgb3IgW3t0eXBlOid0ZXh0Jyx0ZXh0OicuLi4nfV1cbiAgY29uc3QgY29udGVudCA9IG1zZy5jb250ZW50ID8/IG1zZy5tZXNzYWdlID8/IG1zZztcbiAgaWYgKHR5cGVvZiBjb250ZW50ID09PSAnc3RyaW5nJykgcmV0dXJuIGNvbnRlbnQ7XG5cbiAgaWYgKEFycmF5LmlzQXJyYXkoY29udGVudCkpIHtcbiAgICBjb25zdCBwYXJ0cyA9IGNvbnRlbnRcbiAgICAgIC5maWx0ZXIoKGMpID0+IGMgJiYgdHlwZW9mIGMgPT09ICdvYmplY3QnICYmIGMudHlwZSA9PT0gJ3RleHQnICYmIHR5cGVvZiBjLnRleHQgPT09ICdzdHJpbmcnKVxuICAgICAgLm1hcCgoYykgPT4gYy50ZXh0KTtcbiAgICByZXR1cm4gcGFydHMuam9pbignXFxuJyk7XG4gIH1cblxuICAvLyBGYWxsYmFja1xuICB0cnkge1xuICAgIHJldHVybiBKU09OLnN0cmluZ2lmeShjb250ZW50KTtcbiAgfSBjYXRjaCB7XG4gICAgcmV0dXJuIFN0cmluZyhjb250ZW50KTtcbiAgfVxufVxuXG5mdW5jdGlvbiBzZXNzaW9uS2V5TWF0Y2hlcyhjb25maWd1cmVkOiBzdHJpbmcsIGluY29taW5nOiBzdHJpbmcpOiBib29sZWFuIHtcbiAgaWYgKGluY29taW5nID09PSBjb25maWd1cmVkKSByZXR1cm4gdHJ1ZTtcbiAgLy8gT3BlbkNsYXcgcmVzb2x2ZXMgXCJtYWluXCIgdG8gY2Fub25pY2FsIHNlc3Npb24ga2V5IGxpa2UgXCJhZ2VudDptYWluOm1haW5cIi5cbiAgaWYgKGNvbmZpZ3VyZWQgPT09ICdtYWluJyAmJiBpbmNvbWluZyA9PT0gJ2FnZW50Om1haW46bWFpbicpIHJldHVybiB0cnVlO1xuICByZXR1cm4gZmFsc2U7XG59XG5cbmV4cG9ydCBjbGFzcyBPYnNpZGlhbldTQ2xpZW50IHtcbiAgcHJpdmF0ZSB3czogV2ViU29ja2V0IHwgbnVsbCA9IG51bGw7XG4gIHByaXZhdGUgcmVjb25uZWN0VGltZXI6IFJldHVyblR5cGU8dHlwZW9mIHNldFRpbWVvdXQ+IHwgbnVsbCA9IG51bGw7XG4gIHByaXZhdGUgaGVhcnRiZWF0VGltZXI6IFJldHVyblR5cGU8dHlwZW9mIHNldEludGVydmFsPiB8IG51bGwgPSBudWxsO1xuICBwcml2YXRlIHdvcmtpbmdUaW1lcjogUmV0dXJuVHlwZTx0eXBlb2Ygc2V0VGltZW91dD4gfCBudWxsID0gbnVsbDtcbiAgcHJpdmF0ZSBpbnRlbnRpb25hbENsb3NlID0gZmFsc2U7XG4gIHByaXZhdGUgc2Vzc2lvbktleTogc3RyaW5nO1xuICBwcml2YXRlIHVybCA9ICcnO1xuICBwcml2YXRlIHRva2VuID0gJyc7XG4gIHByaXZhdGUgcmVxdWVzdElkID0gMDtcbiAgcHJpdmF0ZSBwZW5kaW5nUmVxdWVzdHMgPSBuZXcgTWFwPHN0cmluZywgUGVuZGluZ1JlcXVlc3Q+KCk7XG4gIHByaXZhdGUgd29ya2luZyA9IGZhbHNlO1xuXG4gIC8qKiBUaGUgbGFzdCBpbi1mbGlnaHQgY2hhdCBydW4gaWQuIEluIE9wZW5DbGF3IFdlYkNoYXQgdGhpcyBtYXBzIHRvIGNoYXQuc2VuZCBpZGVtcG90ZW5jeUtleS4gKi9cbiAgcHJpdmF0ZSBhY3RpdmVSdW5JZDogc3RyaW5nIHwgbnVsbCA9IG51bGw7XG5cbiAgLyoqIFByZXZlbnRzIGFib3J0IHNwYW1taW5nOiB3aGlsZSBhbiBhYm9ydCByZXF1ZXN0IGlzIGluLWZsaWdodCwgcmV1c2UgdGhlIHNhbWUgcHJvbWlzZS4gKi9cbiAgcHJpdmF0ZSBhYm9ydEluRmxpZ2h0OiBQcm9taXNlPGJvb2xlYW4+IHwgbnVsbCA9IG51bGw7XG5cbiAgc3RhdGU6IFdTQ2xpZW50U3RhdGUgPSAnZGlzY29ubmVjdGVkJztcblxuICBvbk1lc3NhZ2U6ICgobXNnOiBJbmJvdW5kV1NQYXlsb2FkKSA9PiB2b2lkKSB8IG51bGwgPSBudWxsO1xuICBvblN0YXRlQ2hhbmdlOiAoKHN0YXRlOiBXU0NsaWVudFN0YXRlKSA9PiB2b2lkKSB8IG51bGwgPSBudWxsO1xuICBvbldvcmtpbmdDaGFuZ2U6IFdvcmtpbmdTdGF0ZUxpc3RlbmVyIHwgbnVsbCA9IG51bGw7XG5cbiAgcHJpdmF0ZSBpZGVudGl0eVN0b3JlOiBEZXZpY2VJZGVudGl0eVN0b3JlIHwgdW5kZWZpbmVkO1xuICBwcml2YXRlIGFsbG93SW5zZWN1cmVXcyA9IGZhbHNlO1xuXG4gIHByaXZhdGUgcmVjb25uZWN0QXR0ZW1wdCA9IDA7XG5cbiAgY29uc3RydWN0b3Ioc2Vzc2lvbktleTogc3RyaW5nLCBvcHRzPzogeyBpZGVudGl0eVN0b3JlPzogRGV2aWNlSWRlbnRpdHlTdG9yZTsgYWxsb3dJbnNlY3VyZVdzPzogYm9vbGVhbiB9KSB7XG4gICAgdGhpcy5zZXNzaW9uS2V5ID0gc2Vzc2lvbktleTtcbiAgICB0aGlzLmlkZW50aXR5U3RvcmUgPSBvcHRzPy5pZGVudGl0eVN0b3JlO1xuICAgIHRoaXMuYWxsb3dJbnNlY3VyZVdzID0gQm9vbGVhbihvcHRzPy5hbGxvd0luc2VjdXJlV3MpO1xuICB9XG5cbiAgY29ubmVjdCh1cmw6IHN0cmluZywgdG9rZW46IHN0cmluZywgb3B0cz86IHsgYWxsb3dJbnNlY3VyZVdzPzogYm9vbGVhbiB9KTogdm9pZCB7XG4gICAgdGhpcy51cmwgPSB1cmw7XG4gICAgdGhpcy50b2tlbiA9IHRva2VuO1xuICAgIHRoaXMuYWxsb3dJbnNlY3VyZVdzID0gQm9vbGVhbihvcHRzPy5hbGxvd0luc2VjdXJlV3MgPz8gdGhpcy5hbGxvd0luc2VjdXJlV3MpO1xuICAgIHRoaXMuaW50ZW50aW9uYWxDbG9zZSA9IGZhbHNlO1xuXG4gICAgLy8gU2VjdXJpdHk6IGJsb2NrIG5vbi1sb2NhbCB3czovLyB1bmxlc3MgZXhwbGljaXRseSBhbGxvd2VkLlxuICAgIGNvbnN0IHBhcnNlZCA9IHNhZmVQYXJzZVdzVXJsKHVybCk7XG4gICAgaWYgKCFwYXJzZWQub2spIHtcbiAgICAgIHRoaXMub25NZXNzYWdlPy4oeyB0eXBlOiAnZXJyb3InLCBwYXlsb2FkOiB7IG1lc3NhZ2U6IHBhcnNlZC5lcnJvciB9IH0pO1xuICAgICAgcmV0dXJuO1xuICAgIH1cbiAgICBpZiAocGFyc2VkLnNjaGVtZSA9PT0gJ3dzJyAmJiAhaXNMb2NhbEhvc3QocGFyc2VkLmhvc3QpICYmICF0aGlzLmFsbG93SW5zZWN1cmVXcykge1xuICAgICAgdGhpcy5vbk1lc3NhZ2U/Lih7XG4gICAgICAgIHR5cGU6ICdlcnJvcicsXG4gICAgICAgIHBheWxvYWQ6IHsgbWVzc2FnZTogJ1JlZnVzaW5nIGluc2VjdXJlIHdzOi8vIHRvIG5vbi1sb2NhbCBnYXRld2F5LiBVc2Ugd3NzOi8vIG9yIGVuYWJsZSB0aGUgdW5zYWZlIG92ZXJyaWRlIGluIHNldHRpbmdzLicgfSxcbiAgICAgIH0pO1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIHRoaXMuX2Nvbm5lY3QoKTtcbiAgfVxuXG4gIGRpc2Nvbm5lY3QoKTogdm9pZCB7XG4gICAgdGhpcy5pbnRlbnRpb25hbENsb3NlID0gdHJ1ZTtcbiAgICB0aGlzLl9zdG9wVGltZXJzKCk7XG4gICAgdGhpcy5hY3RpdmVSdW5JZCA9IG51bGw7XG4gICAgdGhpcy5hYm9ydEluRmxpZ2h0ID0gbnVsbDtcbiAgICB0aGlzLl9zZXRXb3JraW5nKGZhbHNlKTtcbiAgICBpZiAodGhpcy53cykge1xuICAgICAgdGhpcy53cy5jbG9zZSgpO1xuICAgICAgdGhpcy53cyA9IG51bGw7XG4gICAgfVxuICAgIHRoaXMuX3NldFN0YXRlKCdkaXNjb25uZWN0ZWQnKTtcbiAgfVxuXG4gIHNldFNlc3Npb25LZXkoc2Vzc2lvbktleTogc3RyaW5nKTogdm9pZCB7XG4gICAgdGhpcy5zZXNzaW9uS2V5ID0gc2Vzc2lvbktleS50cmltKCk7XG4gICAgLy8gUmVzZXQgcGVyLXNlc3Npb24gcnVuIHN0YXRlLlxuICAgIHRoaXMuYWN0aXZlUnVuSWQgPSBudWxsO1xuICAgIHRoaXMuYWJvcnRJbkZsaWdodCA9IG51bGw7XG4gICAgdGhpcy5fc2V0V29ya2luZyhmYWxzZSk7XG4gIH1cblxuICBhc3luYyBsaXN0U2Vzc2lvbnMob3B0cz86IHtcbiAgICBhY3RpdmVNaW51dGVzPzogbnVtYmVyO1xuICAgIGxpbWl0PzogbnVtYmVyO1xuICAgIGluY2x1ZGVHbG9iYWw/OiBib29sZWFuO1xuICAgIGluY2x1ZGVVbmtub3duPzogYm9vbGVhbjtcbiAgfSk6IFByb21pc2U8U2Vzc2lvbnNMaXN0UmVzdWx0PiB7XG4gICAgaWYgKHRoaXMuc3RhdGUgIT09ICdjb25uZWN0ZWQnKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ05vdCBjb25uZWN0ZWQnKTtcbiAgICB9XG5cbiAgICBjb25zdCBwYXJhbXM6IFJlY29yZDxzdHJpbmcsIHVua25vd24+ID0ge1xuICAgICAgaW5jbHVkZUdsb2JhbDogQm9vbGVhbihvcHRzPy5pbmNsdWRlR2xvYmFsID8/IGZhbHNlKSxcbiAgICAgIGluY2x1ZGVVbmtub3duOiBCb29sZWFuKG9wdHM/LmluY2x1ZGVVbmtub3duID8/IGZhbHNlKSxcbiAgICB9O1xuICAgIGlmIChvcHRzPy5hY3RpdmVNaW51dGVzICYmIG9wdHMuYWN0aXZlTWludXRlcyA+IDApIHBhcmFtcy5hY3RpdmVNaW51dGVzID0gb3B0cy5hY3RpdmVNaW51dGVzO1xuICAgIGlmIChvcHRzPy5saW1pdCAmJiBvcHRzLmxpbWl0ID4gMCkgcGFyYW1zLmxpbWl0ID0gb3B0cy5saW1pdDtcblxuICAgIGNvbnN0IHJlcyA9IGF3YWl0IHRoaXMuX3NlbmRSZXF1ZXN0KCdzZXNzaW9ucy5saXN0JywgcGFyYW1zKTtcbiAgICByZXR1cm4gcmVzIGFzIFNlc3Npb25zTGlzdFJlc3VsdDtcbiAgfVxuXG4gIGFzeW5jIHNlbmRNZXNzYWdlKG1lc3NhZ2U6IHN0cmluZyk6IFByb21pc2U8dm9pZD4ge1xuICAgIGlmICh0aGlzLnN0YXRlICE9PSAnY29ubmVjdGVkJykge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKCdOb3QgY29ubmVjdGVkIFx1MjAxNCBjYWxsIGNvbm5lY3QoKSBmaXJzdCcpO1xuICAgIH1cblxuICAgIGNvbnN0IHJ1bklkID0gYG9ic2lkaWFuLSR7RGF0ZS5ub3coKX0tJHtNYXRoLnJhbmRvbSgpLnRvU3RyaW5nKDM2KS5zbGljZSgyLCA5KX1gO1xuXG4gICAgLy8gU2hvdyBcdTIwMUN3b3JraW5nXHUyMDFEIE9OTFkgYWZ0ZXIgdGhlIGdhdGV3YXkgYWNrbm93bGVkZ2VzIHRoZSByZXF1ZXN0LlxuICAgIGNvbnN0IGFjayA9IGF3YWl0IHRoaXMuX3NlbmRSZXF1ZXN0KCdjaGF0LnNlbmQnLCB7XG4gICAgICBzZXNzaW9uS2V5OiB0aGlzLnNlc3Npb25LZXksXG4gICAgICBtZXNzYWdlLFxuICAgICAgaWRlbXBvdGVuY3lLZXk6IHJ1bklkLFxuICAgICAgLy8gZGVsaXZlciBkZWZhdWx0cyB0byB0cnVlIGluIGdhdGV3YXk7IGtlZXAgZGVmYXVsdFxuICAgIH0pO1xuXG4gICAgLy8gSWYgdGhlIGdhdGV3YXkgcmV0dXJucyBhIGNhbm9uaWNhbCBydW4gaWRlbnRpZmllciwgcHJlZmVyIGl0LlxuICAgIGNvbnN0IGNhbm9uaWNhbFJ1bklkID0gU3RyaW5nKGFjaz8ucnVuSWQgfHwgYWNrPy5pZGVtcG90ZW5jeUtleSB8fCAnJyk7XG4gICAgdGhpcy5hY3RpdmVSdW5JZCA9IGNhbm9uaWNhbFJ1bklkIHx8IHJ1bklkO1xuICAgIHRoaXMuX3NldFdvcmtpbmcodHJ1ZSk7XG4gICAgdGhpcy5fYXJtV29ya2luZ1NhZmV0eVRpbWVvdXQoKTtcbiAgfVxuXG4gIC8qKiBBYm9ydCB0aGUgYWN0aXZlIHJ1biBmb3IgdGhpcyBzZXNzaW9uIChhbmQgb3VyIGxhc3QgcnVuIGlkIGlmIHByZXNlbnQpLiAqL1xuICBhc3luYyBhYm9ydEFjdGl2ZVJ1bigpOiBQcm9taXNlPGJvb2xlYW4+IHtcbiAgICBpZiAodGhpcy5zdGF0ZSAhPT0gJ2Nvbm5lY3RlZCcpIHtcbiAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG5cbiAgICAvLyBQcmV2ZW50IHJlcXVlc3Qgc3Rvcm1zOiB3aGlsZSBvbmUgYWJvcnQgaXMgaW4gZmxpZ2h0LCByZXVzZSBpdC5cbiAgICBpZiAodGhpcy5hYm9ydEluRmxpZ2h0KSB7XG4gICAgICByZXR1cm4gdGhpcy5hYm9ydEluRmxpZ2h0O1xuICAgIH1cblxuICAgIGNvbnN0IHJ1bklkID0gdGhpcy5hY3RpdmVSdW5JZDtcbiAgICBpZiAoIXJ1bklkKSB7XG4gICAgICByZXR1cm4gZmFsc2U7XG4gICAgfVxuXG4gICAgdGhpcy5hYm9ydEluRmxpZ2h0ID0gKGFzeW5jICgpID0+IHtcbiAgICAgIHRyeSB7XG4gICAgICAgIGF3YWl0IHRoaXMuX3NlbmRSZXF1ZXN0KCdjaGF0LmFib3J0JywgeyBzZXNzaW9uS2V5OiB0aGlzLnNlc3Npb25LZXksIHJ1bklkIH0pO1xuICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgIH0gY2F0Y2ggKGVycikge1xuICAgICAgICBjb25zb2xlLmVycm9yKCdbb2NsYXctd3NdIGNoYXQuYWJvcnQgZmFpbGVkJywgZXJyKTtcbiAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgfSBmaW5hbGx5IHtcbiAgICAgICAgLy8gQWx3YXlzIHJlc3RvcmUgVUkgc3RhdGUgaW1tZWRpYXRlbHk7IHRoZSBnYXRld2F5IG1heSBzdGlsbCBlbWl0IGFuIGFib3J0ZWQgZXZlbnQgbGF0ZXIuXG4gICAgICAgIHRoaXMuYWN0aXZlUnVuSWQgPSBudWxsO1xuICAgICAgICB0aGlzLl9zZXRXb3JraW5nKGZhbHNlKTtcbiAgICAgICAgdGhpcy5hYm9ydEluRmxpZ2h0ID0gbnVsbDtcbiAgICAgIH1cbiAgICB9KSgpO1xuXG4gICAgcmV0dXJuIHRoaXMuYWJvcnRJbkZsaWdodDtcbiAgfVxuXG4gIHByaXZhdGUgX2Nvbm5lY3QoKTogdm9pZCB7XG4gICAgaWYgKHRoaXMud3MpIHtcbiAgICAgIHRoaXMud3Mub25vcGVuID0gbnVsbDtcbiAgICAgIHRoaXMud3Mub25jbG9zZSA9IG51bGw7XG4gICAgICB0aGlzLndzLm9ubWVzc2FnZSA9IG51bGw7XG4gICAgICB0aGlzLndzLm9uZXJyb3IgPSBudWxsO1xuICAgICAgdGhpcy53cy5jbG9zZSgpO1xuICAgICAgdGhpcy53cyA9IG51bGw7XG4gICAgfVxuXG4gICAgdGhpcy5fc2V0U3RhdGUoJ2Nvbm5lY3RpbmcnKTtcblxuICAgIGNvbnN0IHdzID0gbmV3IFdlYlNvY2tldCh0aGlzLnVybCk7XG4gICAgdGhpcy53cyA9IHdzO1xuXG4gICAgbGV0IGNvbm5lY3ROb25jZTogc3RyaW5nIHwgbnVsbCA9IG51bGw7XG4gICAgbGV0IGNvbm5lY3RTdGFydGVkID0gZmFsc2U7XG5cbiAgICBjb25zdCB0cnlDb25uZWN0ID0gYXN5bmMgKCkgPT4ge1xuICAgICAgaWYgKGNvbm5lY3RTdGFydGVkKSByZXR1cm47XG4gICAgICBpZiAoIWNvbm5lY3ROb25jZSkgcmV0dXJuO1xuICAgICAgY29ubmVjdFN0YXJ0ZWQgPSB0cnVlO1xuXG4gICAgICB0cnkge1xuICAgICAgICBjb25zdCBpZGVudGl0eSA9IGF3YWl0IGxvYWRPckNyZWF0ZURldmljZUlkZW50aXR5KHRoaXMuaWRlbnRpdHlTdG9yZSk7XG4gICAgICAgIGNvbnN0IHNpZ25lZEF0TXMgPSBEYXRlLm5vdygpO1xuICAgICAgICBjb25zdCBwYXlsb2FkID0gYnVpbGREZXZpY2VBdXRoUGF5bG9hZCh7XG4gICAgICAgICAgZGV2aWNlSWQ6IGlkZW50aXR5LmlkLFxuICAgICAgICAgIGNsaWVudElkOiAnZ2F0ZXdheS1jbGllbnQnLFxuICAgICAgICAgIGNsaWVudE1vZGU6ICdiYWNrZW5kJyxcbiAgICAgICAgICByb2xlOiAnb3BlcmF0b3InLFxuICAgICAgICAgIHNjb3BlczogWydvcGVyYXRvci5yZWFkJywgJ29wZXJhdG9yLndyaXRlJ10sXG4gICAgICAgICAgc2lnbmVkQXRNcyxcbiAgICAgICAgICB0b2tlbjogdGhpcy50b2tlbixcbiAgICAgICAgICBub25jZTogY29ubmVjdE5vbmNlLFxuICAgICAgICB9KTtcbiAgICAgICAgY29uc3Qgc2lnID0gYXdhaXQgc2lnbkRldmljZVBheWxvYWQoaWRlbnRpdHksIHBheWxvYWQpO1xuXG4gICAgICAgIGNvbnN0IGFjayA9IGF3YWl0IHRoaXMuX3NlbmRSZXF1ZXN0KCdjb25uZWN0Jywge1xuICAgICAgICAgICBtaW5Qcm90b2NvbDogMyxcbiAgICAgICAgICAgbWF4UHJvdG9jb2w6IDMsXG4gICAgICAgICAgIGNsaWVudDoge1xuICAgICAgICAgICAgIGlkOiAnZ2F0ZXdheS1jbGllbnQnLFxuICAgICAgICAgICAgIG1vZGU6ICdiYWNrZW5kJyxcbiAgICAgICAgICAgICB2ZXJzaW9uOiAnMC4xLjEwJyxcbiAgICAgICAgICAgICBwbGF0Zm9ybTogJ2VsZWN0cm9uJyxcbiAgICAgICAgICAgfSxcbiAgICAgICAgICAgcm9sZTogJ29wZXJhdG9yJyxcbiAgICAgICAgICAgc2NvcGVzOiBbJ29wZXJhdG9yLnJlYWQnLCAnb3BlcmF0b3Iud3JpdGUnXSxcbiAgICAgICAgICAgZGV2aWNlOiB7XG4gICAgICAgICAgICAgaWQ6IGlkZW50aXR5LmlkLFxuICAgICAgICAgICAgIHB1YmxpY0tleTogaWRlbnRpdHkucHVibGljS2V5LFxuICAgICAgICAgICAgIHNpZ25hdHVyZTogc2lnLnNpZ25hdHVyZSxcbiAgICAgICAgICAgICBzaWduZWRBdDogc2lnbmVkQXRNcyxcbiAgICAgICAgICAgICBub25jZTogY29ubmVjdE5vbmNlLFxuICAgICAgICAgICB9LFxuICAgICAgICAgICBhdXRoOiB7XG4gICAgICAgICAgICAgdG9rZW46IHRoaXMudG9rZW4sXG4gICAgICAgICAgIH0sXG4gICAgICAgICB9KTtcblxuICAgICAgICAgdGhpcy5fc2V0U3RhdGUoJ2Nvbm5lY3RlZCcpO1xuICAgICAgICAgdGhpcy5yZWNvbm5lY3RBdHRlbXB0ID0gMDtcbiAgICAgICAgIGlmIChoYW5kc2hha2VUaW1lcikge1xuICAgICAgICAgICBjbGVhclRpbWVvdXQoaGFuZHNoYWtlVGltZXIpO1xuICAgICAgICAgICBoYW5kc2hha2VUaW1lciA9IG51bGw7XG4gICAgICAgICB9XG4gICAgICAgICB0aGlzLl9zdGFydEhlYXJ0YmVhdCgpO1xuICAgICAgfSBjYXRjaCAoZXJyKSB7XG4gICAgICAgIGNvbnNvbGUuZXJyb3IoJ1tvY2xhdy13c10gQ29ubmVjdCBoYW5kc2hha2UgZmFpbGVkJywgZXJyKTtcbiAgICAgICAgd3MuY2xvc2UoKTtcbiAgICAgIH1cbiAgICB9O1xuXG4gICAgbGV0IGhhbmRzaGFrZVRpbWVyOiBSZXR1cm5UeXBlPHR5cGVvZiBzZXRUaW1lb3V0PiB8IG51bGwgPSBudWxsO1xuXG4gICAgd3Mub25vcGVuID0gKCkgPT4ge1xuICAgICAgdGhpcy5fc2V0U3RhdGUoJ2hhbmRzaGFraW5nJyk7XG4gICAgICAvLyBUaGUgZ2F0ZXdheSB3aWxsIHNlbmQgY29ubmVjdC5jaGFsbGVuZ2U7IGNvbm5lY3QgaXMgc2VudCBvbmNlIHdlIGhhdmUgYSBub25jZS5cbiAgICAgIGlmIChoYW5kc2hha2VUaW1lcikgY2xlYXJUaW1lb3V0KGhhbmRzaGFrZVRpbWVyKTtcbiAgICAgIGhhbmRzaGFrZVRpbWVyID0gc2V0VGltZW91dCgoKSA9PiB7XG4gICAgICAgIC8vIElmIHdlIG5ldmVyIGdvdCB0aGUgY2hhbGxlbmdlIG5vbmNlLCBmb3JjZSByZWNvbm5lY3QuXG4gICAgICAgIGlmICh0aGlzLnN0YXRlID09PSAnaGFuZHNoYWtpbmcnICYmICF0aGlzLmludGVudGlvbmFsQ2xvc2UpIHtcbiAgICAgICAgICBjb25zb2xlLndhcm4oJ1tvY2xhdy13c10gSGFuZHNoYWtlIHRpbWVkIG91dCB3YWl0aW5nIGZvciBjb25uZWN0LmNoYWxsZW5nZScpO1xuICAgICAgICAgIHdzLmNsb3NlKCk7XG4gICAgICAgIH1cbiAgICAgIH0sIEhBTkRTSEFLRV9USU1FT1VUX01TKTtcbiAgICB9O1xuXG4gICAgd3Mub25tZXNzYWdlID0gKGV2ZW50OiBNZXNzYWdlRXZlbnQpID0+IHtcbiAgICAgIC8vIFdlYlNvY2tldCBvbm1lc3NhZ2UgY2Fubm90IGJlIGFzeW5jLCBidXQgd2UgY2FuIHJ1biBhbiBhc3luYyB0YXNrIGluc2lkZS5cbiAgICAgIHZvaWQgKGFzeW5jICgpID0+IHtcbiAgICAgICAgY29uc3Qgbm9ybWFsaXplZCA9IGF3YWl0IG5vcm1hbGl6ZVdzRGF0YVRvVGV4dChldmVudC5kYXRhKTtcbiAgICAgICAgaWYgKCFub3JtYWxpemVkLm9rKSB7XG4gICAgICAgICAgaWYgKG5vcm1hbGl6ZWQucmVhc29uID09PSAndG9vLWxhcmdlJykge1xuICAgICAgICAgICAgY29uc29sZS5lcnJvcignW29jbGF3LXdzXSBJbmJvdW5kIGZyYW1lIHRvbyBsYXJnZTsgY2xvc2luZyBjb25uZWN0aW9uJyk7XG4gICAgICAgICAgICB3cy5jbG9zZSgpO1xuICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBjb25zb2xlLmVycm9yKCdbb2NsYXctd3NdIFVuc3VwcG9ydGVkIGluYm91bmQgZnJhbWUgdHlwZTsgaWdub3JpbmcnKTtcbiAgICAgICAgICB9XG4gICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKG5vcm1hbGl6ZWQuYnl0ZXMgPiBNQVhfSU5CT1VORF9GUkFNRV9CWVRFUykge1xuICAgICAgICAgIGNvbnNvbGUuZXJyb3IoJ1tvY2xhdy13c10gSW5ib3VuZCBmcmFtZSB0b28gbGFyZ2U7IGNsb3NpbmcgY29ubmVjdGlvbicpO1xuICAgICAgICAgIHdzLmNsb3NlKCk7XG4gICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgbGV0IGZyYW1lOiBhbnk7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgZnJhbWUgPSBKU09OLnBhcnNlKG5vcm1hbGl6ZWQudGV4dCk7XG4gICAgICAgIH0gY2F0Y2gge1xuICAgICAgICAgIGNvbnNvbGUuZXJyb3IoJ1tvY2xhdy13c10gRmFpbGVkIHRvIHBhcnNlIGluY29taW5nIG1lc3NhZ2UnKTtcbiAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICAvLyBSZXNwb25zZXNcbiAgICAgICAgaWYgKGZyYW1lLnR5cGUgPT09ICdyZXMnKSB7XG4gICAgICAgICAgdGhpcy5faGFuZGxlUmVzcG9uc2VGcmFtZShmcmFtZSk7XG4gICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgLy8gRXZlbnRzXG4gICAgICAgIGlmIChmcmFtZS50eXBlID09PSAnZXZlbnQnKSB7XG4gICAgICAgICAgaWYgKGZyYW1lLmV2ZW50ID09PSAnY29ubmVjdC5jaGFsbGVuZ2UnKSB7XG4gICAgICAgICAgICBjb25uZWN0Tm9uY2UgPSBmcmFtZS5wYXlsb2FkPy5ub25jZSB8fCBudWxsO1xuICAgICAgICAgICAgLy8gQXR0ZW1wdCBoYW5kc2hha2Ugb25jZSB3ZSBoYXZlIGEgbm9uY2UuXG4gICAgICAgICAgICB2b2lkIHRyeUNvbm5lY3QoKTtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBpZiAoZnJhbWUuZXZlbnQgPT09ICdjaGF0Jykge1xuICAgICAgICAgICAgdGhpcy5faGFuZGxlQ2hhdEV2ZW50RnJhbWUoZnJhbWUpO1xuICAgICAgICAgIH1cbiAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICAvLyBBdm9pZCBsb2dnaW5nIGZ1bGwgZnJhbWVzIChtYXkgaW5jbHVkZSBtZXNzYWdlIGNvbnRlbnQgb3Igb3RoZXIgc2Vuc2l0aXZlIHBheWxvYWRzKS5cbiAgICAgICAgY29uc29sZS5kZWJ1ZygnW29jbGF3LXdzXSBVbmhhbmRsZWQgZnJhbWUnLCB7IHR5cGU6IGZyYW1lPy50eXBlLCBldmVudDogZnJhbWU/LmV2ZW50LCBpZDogZnJhbWU/LmlkIH0pO1xuICAgICAgfSkoKTtcbiAgICB9O1xuXG4gICAgY29uc3QgY2xlYXJIYW5kc2hha2VUaW1lciA9ICgpID0+IHtcbiAgICAgIGlmIChoYW5kc2hha2VUaW1lcikge1xuICAgICAgICBjbGVhclRpbWVvdXQoaGFuZHNoYWtlVGltZXIpO1xuICAgICAgICBoYW5kc2hha2VUaW1lciA9IG51bGw7XG4gICAgICB9XG4gICAgfTtcblxuICAgIHdzLm9uY2xvc2UgPSAoKSA9PiB7XG4gICAgICBjbGVhckhhbmRzaGFrZVRpbWVyKCk7XG4gICAgICB0aGlzLl9zdG9wVGltZXJzKCk7XG4gICAgICB0aGlzLmFjdGl2ZVJ1bklkID0gbnVsbDtcbiAgICAgIHRoaXMuYWJvcnRJbkZsaWdodCA9IG51bGw7XG4gICAgICB0aGlzLl9zZXRXb3JraW5nKGZhbHNlKTtcbiAgICAgIHRoaXMuX3NldFN0YXRlKCdkaXNjb25uZWN0ZWQnKTtcblxuICAgICAgZm9yIChjb25zdCBwZW5kaW5nIG9mIHRoaXMucGVuZGluZ1JlcXVlc3RzLnZhbHVlcygpKSB7XG4gICAgICAgIGlmIChwZW5kaW5nLnRpbWVvdXQpIGNsZWFyVGltZW91dChwZW5kaW5nLnRpbWVvdXQpO1xuICAgICAgICBwZW5kaW5nLnJlamVjdChuZXcgRXJyb3IoJ0Nvbm5lY3Rpb24gY2xvc2VkJykpO1xuICAgICAgfVxuICAgICAgdGhpcy5wZW5kaW5nUmVxdWVzdHMuY2xlYXIoKTtcblxuICAgICAgaWYgKCF0aGlzLmludGVudGlvbmFsQ2xvc2UpIHtcbiAgICAgICAgdGhpcy5fc2NoZWR1bGVSZWNvbm5lY3QoKTtcbiAgICAgIH1cbiAgICB9O1xuXG4gICAgd3Mub25lcnJvciA9IChldjogRXZlbnQpID0+IHtcbiAgICAgIGNsZWFySGFuZHNoYWtlVGltZXIoKTtcbiAgICAgIGNvbnNvbGUuZXJyb3IoJ1tvY2xhdy13c10gV2ViU29ja2V0IGVycm9yJywgZXYpO1xuICAgIH07XG4gIH1cblxuICBwcml2YXRlIF9oYW5kbGVSZXNwb25zZUZyYW1lKGZyYW1lOiBhbnkpOiB2b2lkIHtcbiAgICBjb25zdCBwZW5kaW5nID0gdGhpcy5wZW5kaW5nUmVxdWVzdHMuZ2V0KGZyYW1lLmlkKTtcbiAgICBpZiAoIXBlbmRpbmcpIHJldHVybjtcblxuICAgIHRoaXMucGVuZGluZ1JlcXVlc3RzLmRlbGV0ZShmcmFtZS5pZCk7XG4gICAgaWYgKHBlbmRpbmcudGltZW91dCkgY2xlYXJUaW1lb3V0KHBlbmRpbmcudGltZW91dCk7XG5cbiAgICBpZiAoZnJhbWUub2spIHBlbmRpbmcucmVzb2x2ZShmcmFtZS5wYXlsb2FkKTtcbiAgICBlbHNlIHBlbmRpbmcucmVqZWN0KG5ldyBFcnJvcihmcmFtZS5lcnJvcj8ubWVzc2FnZSB8fCAnUmVxdWVzdCBmYWlsZWQnKSk7XG4gIH1cblxuICBwcml2YXRlIF9oYW5kbGVDaGF0RXZlbnRGcmFtZShmcmFtZTogYW55KTogdm9pZCB7XG4gICAgY29uc3QgcGF5bG9hZCA9IGZyYW1lLnBheWxvYWQ7XG4gICAgY29uc3QgaW5jb21pbmdTZXNzaW9uS2V5ID0gU3RyaW5nKHBheWxvYWQ/LnNlc3Npb25LZXkgfHwgJycpO1xuICAgIGlmICghaW5jb21pbmdTZXNzaW9uS2V5IHx8ICFzZXNzaW9uS2V5TWF0Y2hlcyh0aGlzLnNlc3Npb25LZXksIGluY29taW5nU2Vzc2lvbktleSkpIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICAvLyBCZXN0LWVmZm9ydCBydW4gY29ycmVsYXRpb24gKGlmIGdhdGV3YXkgaW5jbHVkZXMgYSBydW4gaWQpLiBUaGlzIGF2b2lkcyBjbGVhcmluZyBvdXIgVUlcbiAgICAvLyBiYXNlZCBvbiBhIGRpZmZlcmVudCBjbGllbnQncyBydW4gaW4gdGhlIHNhbWUgc2Vzc2lvbi5cbiAgICBjb25zdCBpbmNvbWluZ1J1bklkID0gU3RyaW5nKHBheWxvYWQ/LnJ1bklkIHx8IHBheWxvYWQ/LmlkZW1wb3RlbmN5S2V5IHx8IHBheWxvYWQ/Lm1ldGE/LnJ1bklkIHx8ICcnKTtcbiAgICBpZiAodGhpcy5hY3RpdmVSdW5JZCAmJiBpbmNvbWluZ1J1bklkICYmIGluY29taW5nUnVuSWQgIT09IHRoaXMuYWN0aXZlUnVuSWQpIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICAvLyBBdm9pZCBkb3VibGUtcmVuZGVyOiBnYXRld2F5IGVtaXRzIGRlbHRhICsgZmluYWwgKyBhYm9ydGVkLiBSZW5kZXIgb25seSBleHBsaWNpdCBmaW5hbC9hYm9ydGVkLlxuICAgIC8vIElmIHN0YXRlIGlzIG1pc3NpbmcsIHRyZWF0IGFzIG5vbi10ZXJtaW5hbCAoZG8gbm90IGNsZWFyIFVJIC8gZG8gbm90IHJlbmRlcikuXG4gICAgaWYgKCFwYXlsb2FkPy5zdGF0ZSkge1xuICAgICAgcmV0dXJuO1xuICAgIH1cbiAgICBpZiAocGF5bG9hZC5zdGF0ZSAhPT0gJ2ZpbmFsJyAmJiBwYXlsb2FkLnN0YXRlICE9PSAnYWJvcnRlZCcpIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICAvLyBXZSBvbmx5IGFwcGVuZCBhc3Npc3RhbnQgb3V0cHV0IHRvIFVJLlxuICAgIGNvbnN0IG1zZyA9IHBheWxvYWQ/Lm1lc3NhZ2U7XG4gICAgY29uc3Qgcm9sZSA9IG1zZz8ucm9sZSA/PyAnYXNzaXN0YW50JztcblxuICAgIC8vIEFib3J0ZWQgZW5kcyB0aGUgcnVuIHJlZ2FyZGxlc3Mgb2Ygcm9sZS9tZXNzYWdlLlxuICAgIGlmIChwYXlsb2FkLnN0YXRlID09PSAnYWJvcnRlZCcpIHtcbiAgICAgIHRoaXMuYWN0aXZlUnVuSWQgPSBudWxsO1xuICAgICAgdGhpcy5fc2V0V29ya2luZyhmYWxzZSk7XG4gICAgICAvLyBBYm9ydGVkIG1heSBoYXZlIG5vIGFzc2lzdGFudCBtZXNzYWdlOyBpZiBub25lLCBzdG9wIGhlcmUuXG4gICAgICBpZiAoIW1zZykgcmV0dXJuO1xuICAgICAgLy8gSWYgdGhlcmUgaXMgYSBtZXNzYWdlLCBvbmx5IGFwcGVuZCBhc3Npc3RhbnQgb3V0cHV0LlxuICAgICAgaWYgKHJvbGUgIT09ICdhc3Npc3RhbnQnKSByZXR1cm47XG4gICAgfVxuXG4gICAgLy8gRmluYWwgc2hvdWxkIG9ubHkgY29tcGxldGUgdGhlIHJ1biB3aGVuIHRoZSBhc3Npc3RhbnQgY29tcGxldGVzLlxuICAgIGlmIChwYXlsb2FkLnN0YXRlID09PSAnZmluYWwnKSB7XG4gICAgICBpZiAocm9sZSAhPT0gJ2Fzc2lzdGFudCcpIHJldHVybjtcbiAgICAgIHRoaXMuYWN0aXZlUnVuSWQgPSBudWxsO1xuICAgICAgdGhpcy5fc2V0V29ya2luZyhmYWxzZSk7XG4gICAgfVxuXG4gICAgY29uc3QgdGV4dCA9IGV4dHJhY3RUZXh0RnJvbUdhdGV3YXlNZXNzYWdlKG1zZyk7XG4gICAgaWYgKCF0ZXh0KSByZXR1cm47XG5cbiAgICAvLyBPcHRpb25hbDogaGlkZSBoZWFydGJlYXQgYWNrcyAobm9pc2UgaW4gVUkpXG4gICAgaWYgKHRleHQudHJpbSgpID09PSAnSEVBUlRCRUFUX09LJykge1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIHRoaXMub25NZXNzYWdlPy4oe1xuICAgICAgdHlwZTogJ21lc3NhZ2UnLFxuICAgICAgcGF5bG9hZDoge1xuICAgICAgICBjb250ZW50OiB0ZXh0LFxuICAgICAgICByb2xlOiAnYXNzaXN0YW50JyxcbiAgICAgICAgdGltZXN0YW1wOiBEYXRlLm5vdygpLFxuICAgICAgfSxcbiAgICB9KTtcbiAgfVxuXG4gIHByaXZhdGUgX3NlbmRSZXF1ZXN0KG1ldGhvZDogc3RyaW5nLCBwYXJhbXM6IGFueSk6IFByb21pc2U8YW55PiB7XG4gICAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIGlmICghdGhpcy53cyB8fCB0aGlzLndzLnJlYWR5U3RhdGUgIT09IFdlYlNvY2tldC5PUEVOKSB7XG4gICAgICAgIHJlamVjdChuZXcgRXJyb3IoJ1dlYlNvY2tldCBub3QgY29ubmVjdGVkJykpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG5cbiAgICAgIGlmICh0aGlzLnBlbmRpbmdSZXF1ZXN0cy5zaXplID49IE1BWF9QRU5ESU5HX1JFUVVFU1RTKSB7XG4gICAgICAgIHJlamVjdChuZXcgRXJyb3IoYFRvbyBtYW55IGluLWZsaWdodCByZXF1ZXN0cyAoJHt0aGlzLnBlbmRpbmdSZXF1ZXN0cy5zaXplfSlgKSk7XG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cblxuICAgICAgY29uc3QgaWQgPSBgcmVxLSR7Kyt0aGlzLnJlcXVlc3RJZH1gO1xuXG4gICAgICBjb25zdCBwZW5kaW5nOiBQZW5kaW5nUmVxdWVzdCA9IHsgcmVzb2x2ZSwgcmVqZWN0LCB0aW1lb3V0OiBudWxsIH07XG4gICAgICB0aGlzLnBlbmRpbmdSZXF1ZXN0cy5zZXQoaWQsIHBlbmRpbmcpO1xuXG4gICAgICBjb25zdCBwYXlsb2FkID0gSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0eXBlOiAncmVxJyxcbiAgICAgICAgbWV0aG9kLFxuICAgICAgICBpZCxcbiAgICAgICAgcGFyYW1zLFxuICAgICAgfSk7XG5cbiAgICAgIHRyeSB7XG4gICAgICAgIHRoaXMud3Muc2VuZChwYXlsb2FkKTtcbiAgICAgIH0gY2F0Y2ggKGVycikge1xuICAgICAgICB0aGlzLnBlbmRpbmdSZXF1ZXN0cy5kZWxldGUoaWQpO1xuICAgICAgICByZWplY3QoZXJyKTtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuXG4gICAgICBwZW5kaW5nLnRpbWVvdXQgPSBzZXRUaW1lb3V0KCgpID0+IHtcbiAgICAgICAgaWYgKHRoaXMucGVuZGluZ1JlcXVlc3RzLmhhcyhpZCkpIHtcbiAgICAgICAgICB0aGlzLnBlbmRpbmdSZXF1ZXN0cy5kZWxldGUoaWQpO1xuICAgICAgICAgIHJlamVjdChuZXcgRXJyb3IoYFJlcXVlc3QgdGltZW91dDogJHttZXRob2R9YCkpO1xuICAgICAgICB9XG4gICAgICB9LCAzMF8wMDApO1xuICAgIH0pO1xuICB9XG5cbiAgcHJpdmF0ZSBfc2NoZWR1bGVSZWNvbm5lY3QoKTogdm9pZCB7XG4gICAgaWYgKHRoaXMucmVjb25uZWN0VGltZXIgIT09IG51bGwpIHJldHVybjtcblxuICAgIGNvbnN0IGF0dGVtcHQgPSArK3RoaXMucmVjb25uZWN0QXR0ZW1wdDtcbiAgICBjb25zdCBleHAgPSBNYXRoLm1pbihSRUNPTk5FQ1RfTUFYX01TLCBSRUNPTk5FQ1RfQkFTRV9NUyAqIE1hdGgucG93KDIsIGF0dGVtcHQgLSAxKSk7XG4gICAgLy8gSml0dGVyOiAwLjV4Li4xLjV4XG4gICAgY29uc3Qgaml0dGVyID0gMC41ICsgTWF0aC5yYW5kb20oKTtcbiAgICBjb25zdCBkZWxheSA9IE1hdGguZmxvb3IoZXhwICogaml0dGVyKTtcblxuICAgIHRoaXMucmVjb25uZWN0VGltZXIgPSBzZXRUaW1lb3V0KCgpID0+IHtcbiAgICAgIHRoaXMucmVjb25uZWN0VGltZXIgPSBudWxsO1xuICAgICAgaWYgKCF0aGlzLmludGVudGlvbmFsQ2xvc2UpIHtcbiAgICAgICAgY29uc29sZS5sb2coYFtvY2xhdy13c10gUmVjb25uZWN0aW5nIHRvICR7dGhpcy51cmx9XHUyMDI2IChhdHRlbXB0ICR7YXR0ZW1wdH0sICR7ZGVsYXl9bXMpYCk7XG4gICAgICAgIHRoaXMuX2Nvbm5lY3QoKTtcbiAgICAgIH1cbiAgICB9LCBkZWxheSk7XG4gIH1cblxuICBwcml2YXRlIGxhc3RCdWZmZXJlZFdhcm5BdE1zID0gMDtcblxuICBwcml2YXRlIF9zdGFydEhlYXJ0YmVhdCgpOiB2b2lkIHtcbiAgICB0aGlzLl9zdG9wSGVhcnRiZWF0KCk7XG4gICAgdGhpcy5oZWFydGJlYXRUaW1lciA9IHNldEludGVydmFsKCgpID0+IHtcbiAgICAgIGlmICh0aGlzLndzPy5yZWFkeVN0YXRlICE9PSBXZWJTb2NrZXQuT1BFTikgcmV0dXJuO1xuICAgICAgaWYgKHRoaXMud3MuYnVmZmVyZWRBbW91bnQgPiAwKSB7XG4gICAgICAgIGNvbnN0IG5vdyA9IERhdGUubm93KCk7XG4gICAgICAgIC8vIFRocm90dGxlIHRvIGF2b2lkIGxvZyBzcGFtIGluIGxvbmctcnVubmluZyBzZXNzaW9ucy5cbiAgICAgICAgaWYgKG5vdyAtIHRoaXMubGFzdEJ1ZmZlcmVkV2FybkF0TXMgPiA1ICogNjBfMDAwKSB7XG4gICAgICAgICAgdGhpcy5sYXN0QnVmZmVyZWRXYXJuQXRNcyA9IG5vdztcbiAgICAgICAgICBjb25zb2xlLndhcm4oJ1tvY2xhdy13c10gU2VuZCBidWZmZXIgbm90IGVtcHR5IFx1MjAxNCBjb25uZWN0aW9uIG1heSBiZSBzdGFsbGVkJyk7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9LCBIRUFSVEJFQVRfSU5URVJWQUxfTVMpO1xuICB9XG5cbiAgcHJpdmF0ZSBfc3RvcEhlYXJ0YmVhdCgpOiB2b2lkIHtcbiAgICBpZiAodGhpcy5oZWFydGJlYXRUaW1lcikge1xuICAgICAgY2xlYXJJbnRlcnZhbCh0aGlzLmhlYXJ0YmVhdFRpbWVyKTtcbiAgICAgIHRoaXMuaGVhcnRiZWF0VGltZXIgPSBudWxsO1xuICAgIH1cbiAgfVxuXG4gIHByaXZhdGUgX3N0b3BUaW1lcnMoKTogdm9pZCB7XG4gICAgdGhpcy5fc3RvcEhlYXJ0YmVhdCgpO1xuICAgIHRoaXMuX2Rpc2FybVdvcmtpbmdTYWZldHlUaW1lb3V0KCk7XG4gICAgaWYgKHRoaXMucmVjb25uZWN0VGltZXIpIHtcbiAgICAgIGNsZWFyVGltZW91dCh0aGlzLnJlY29ubmVjdFRpbWVyKTtcbiAgICAgIHRoaXMucmVjb25uZWN0VGltZXIgPSBudWxsO1xuICAgIH1cbiAgfVxuXG4gIHByaXZhdGUgX3NldFN0YXRlKHN0YXRlOiBXU0NsaWVudFN0YXRlKTogdm9pZCB7XG4gICAgaWYgKHRoaXMuc3RhdGUgPT09IHN0YXRlKSByZXR1cm47XG4gICAgdGhpcy5zdGF0ZSA9IHN0YXRlO1xuICAgIHRoaXMub25TdGF0ZUNoYW5nZT8uKHN0YXRlKTtcbiAgfVxuXG4gIHByaXZhdGUgX3NldFdvcmtpbmcod29ya2luZzogYm9vbGVhbik6IHZvaWQge1xuICAgIGlmICh0aGlzLndvcmtpbmcgPT09IHdvcmtpbmcpIHJldHVybjtcbiAgICB0aGlzLndvcmtpbmcgPSB3b3JraW5nO1xuICAgIHRoaXMub25Xb3JraW5nQ2hhbmdlPy4od29ya2luZyk7XG5cbiAgICBpZiAoIXdvcmtpbmcpIHtcbiAgICAgIHRoaXMuX2Rpc2FybVdvcmtpbmdTYWZldHlUaW1lb3V0KCk7XG4gICAgfVxuICB9XG5cbiAgcHJpdmF0ZSBfYXJtV29ya2luZ1NhZmV0eVRpbWVvdXQoKTogdm9pZCB7XG4gICAgdGhpcy5fZGlzYXJtV29ya2luZ1NhZmV0eVRpbWVvdXQoKTtcbiAgICB0aGlzLndvcmtpbmdUaW1lciA9IHNldFRpbWVvdXQoKCkgPT4ge1xuICAgICAgLy8gSWYgdGhlIGdhdGV3YXkgbmV2ZXIgZW1pdHMgYW4gYXNzaXN0YW50IGZpbmFsIHJlc3BvbnNlLCBkb25cdTIwMTl0IGxlYXZlIFVJIHN0dWNrLlxuICAgICAgdGhpcy5fc2V0V29ya2luZyhmYWxzZSk7XG4gICAgfSwgV09SS0lOR19NQVhfTVMpO1xuICB9XG5cbiAgcHJpdmF0ZSBfZGlzYXJtV29ya2luZ1NhZmV0eVRpbWVvdXQoKTogdm9pZCB7XG4gICAgaWYgKHRoaXMud29ya2luZ1RpbWVyKSB7XG4gICAgICBjbGVhclRpbWVvdXQodGhpcy53b3JraW5nVGltZXIpO1xuICAgICAgdGhpcy53b3JraW5nVGltZXIgPSBudWxsO1xuICAgIH1cbiAgfVxufVxuIiwgImltcG9ydCB0eXBlIHsgQ2hhdE1lc3NhZ2UgfSBmcm9tICcuL3R5cGVzJztcblxuLyoqIE1hbmFnZXMgdGhlIGluLW1lbW9yeSBsaXN0IG9mIGNoYXQgbWVzc2FnZXMgYW5kIG5vdGlmaWVzIFVJIG9uIGNoYW5nZXMgKi9cbmV4cG9ydCBjbGFzcyBDaGF0TWFuYWdlciB7XG4gIHByaXZhdGUgbWVzc2FnZXM6IENoYXRNZXNzYWdlW10gPSBbXTtcblxuICAvKiogRmlyZWQgZm9yIGEgZnVsbCByZS1yZW5kZXIgKGNsZWFyL3JlbG9hZCkgKi9cbiAgb25VcGRhdGU6ICgobWVzc2FnZXM6IHJlYWRvbmx5IENoYXRNZXNzYWdlW10pID0+IHZvaWQpIHwgbnVsbCA9IG51bGw7XG4gIC8qKiBGaXJlZCB3aGVuIGEgc2luZ2xlIG1lc3NhZ2UgaXMgYXBwZW5kZWQgXHUyMDE0IHVzZSBmb3IgTygxKSBhcHBlbmQtb25seSBVSSAqL1xuICBvbk1lc3NhZ2VBZGRlZDogKChtc2c6IENoYXRNZXNzYWdlKSA9PiB2b2lkKSB8IG51bGwgPSBudWxsO1xuXG4gIGFkZE1lc3NhZ2UobXNnOiBDaGF0TWVzc2FnZSk6IHZvaWQge1xuICAgIHRoaXMubWVzc2FnZXMucHVzaChtc2cpO1xuICAgIHRoaXMub25NZXNzYWdlQWRkZWQ/Lihtc2cpO1xuICB9XG5cbiAgZ2V0TWVzc2FnZXMoKTogcmVhZG9ubHkgQ2hhdE1lc3NhZ2VbXSB7XG4gICAgcmV0dXJuIHRoaXMubWVzc2FnZXM7XG4gIH1cblxuICBjbGVhcigpOiB2b2lkIHtcbiAgICB0aGlzLm1lc3NhZ2VzID0gW107XG4gICAgdGhpcy5vblVwZGF0ZT8uKFtdKTtcbiAgfVxuXG4gIC8qKiBDcmVhdGUgYSB1c2VyIG1lc3NhZ2Ugb2JqZWN0ICh3aXRob3V0IGFkZGluZyBpdCkgKi9cbiAgc3RhdGljIGNyZWF0ZVVzZXJNZXNzYWdlKGNvbnRlbnQ6IHN0cmluZyk6IENoYXRNZXNzYWdlIHtcbiAgICByZXR1cm4ge1xuICAgICAgaWQ6IGBtc2ctJHtEYXRlLm5vdygpfS0ke01hdGgucmFuZG9tKCkudG9TdHJpbmcoMzYpLnNsaWNlKDIsIDcpfWAsXG4gICAgICByb2xlOiAndXNlcicsXG4gICAgICBjb250ZW50LFxuICAgICAgdGltZXN0YW1wOiBEYXRlLm5vdygpLFxuICAgIH07XG4gIH1cblxuICAvKiogQ3JlYXRlIGFuIGFzc2lzdGFudCBtZXNzYWdlIG9iamVjdCAod2l0aG91dCBhZGRpbmcgaXQpICovXG4gIHN0YXRpYyBjcmVhdGVBc3Npc3RhbnRNZXNzYWdlKGNvbnRlbnQ6IHN0cmluZyk6IENoYXRNZXNzYWdlIHtcbiAgICByZXR1cm4ge1xuICAgICAgaWQ6IGBtc2ctJHtEYXRlLm5vdygpfS0ke01hdGgucmFuZG9tKCkudG9TdHJpbmcoMzYpLnNsaWNlKDIsIDcpfWAsXG4gICAgICByb2xlOiAnYXNzaXN0YW50JyxcbiAgICAgIGNvbnRlbnQsXG4gICAgICB0aW1lc3RhbXA6IERhdGUubm93KCksXG4gICAgfTtcbiAgfVxuXG4gIC8qKiBDcmVhdGUgYSBzeXN0ZW0gLyBzdGF0dXMgbWVzc2FnZSAoZXJyb3JzLCByZWNvbm5lY3Qgbm90aWNlcywgZXRjLikgKi9cbiAgc3RhdGljIGNyZWF0ZVN5c3RlbU1lc3NhZ2UoY29udGVudDogc3RyaW5nLCBsZXZlbDogQ2hhdE1lc3NhZ2VbJ2xldmVsJ10gPSAnaW5mbycpOiBDaGF0TWVzc2FnZSB7XG4gICAgcmV0dXJuIHtcbiAgICAgIGlkOiBgc3lzLSR7RGF0ZS5ub3coKX1gLFxuICAgICAgcm9sZTogJ3N5c3RlbScsXG4gICAgICBsZXZlbCxcbiAgICAgIGNvbnRlbnQsXG4gICAgICB0aW1lc3RhbXA6IERhdGUubm93KCksXG4gICAgfTtcbiAgfVxuXG4gIHN0YXRpYyBjcmVhdGVTZXNzaW9uRGl2aWRlcihzZXNzaW9uS2V5OiBzdHJpbmcpOiBDaGF0TWVzc2FnZSB7XG4gICAgY29uc3Qgc2hvcnQgPSBzZXNzaW9uS2V5Lmxlbmd0aCA+IDI4ID8gYCR7c2Vzc2lvbktleS5zbGljZSgwLCAxMil9XHUyMDI2JHtzZXNzaW9uS2V5LnNsaWNlKC0xMil9YCA6IHNlc3Npb25LZXk7XG4gICAgcmV0dXJuIHtcbiAgICAgIGlkOiBgZGl2LSR7RGF0ZS5ub3coKX1gLFxuICAgICAgcm9sZTogJ3N5c3RlbScsXG4gICAgICBsZXZlbDogJ2luZm8nLFxuICAgICAga2luZDogJ3Nlc3Npb24tZGl2aWRlcicsXG4gICAgICB0aXRsZTogc2Vzc2lvbktleSxcbiAgICAgIGNvbnRlbnQ6IGBbU2Vzc2lvbjogJHtzaG9ydH1dYCxcbiAgICAgIHRpbWVzdGFtcDogRGF0ZS5ub3coKSxcbiAgICB9O1xuICB9XG59XG4iLCAiaW1wb3J0IHsgSXRlbVZpZXcsIE1hcmtkb3duUmVuZGVyZXIsIE5vdGljZSwgVEZpbGUsIFdvcmtzcGFjZUxlYWYgfSBmcm9tICdvYnNpZGlhbic7XG5pbXBvcnQgdHlwZSBPcGVuQ2xhd1BsdWdpbiBmcm9tICcuL21haW4nO1xuaW1wb3J0IHsgQ2hhdE1hbmFnZXIgfSBmcm9tICcuL2NoYXQnO1xuaW1wb3J0IHR5cGUgeyBDaGF0TWVzc2FnZSwgUGF0aE1hcHBpbmcgfSBmcm9tICcuL3R5cGVzJztcbmltcG9ydCB7IGV4dHJhY3RDYW5kaWRhdGVzLCB0cnlNYXBSZW1vdGVQYXRoVG9WYXVsdFBhdGggfSBmcm9tICcuL2xpbmtpZnknO1xuaW1wb3J0IHsgZ2V0QWN0aXZlTm90ZUNvbnRleHQgfSBmcm9tICcuL2NvbnRleHQnO1xuXG5leHBvcnQgY29uc3QgVklFV19UWVBFX09QRU5DTEFXX0NIQVQgPSAnb3BlbmNsYXctY2hhdCc7XG5cbmV4cG9ydCBjbGFzcyBPcGVuQ2xhd0NoYXRWaWV3IGV4dGVuZHMgSXRlbVZpZXcge1xuICBwcml2YXRlIHBsdWdpbjogT3BlbkNsYXdQbHVnaW47XG4gIHByaXZhdGUgY2hhdE1hbmFnZXI6IENoYXRNYW5hZ2VyO1xuXG4gIC8vIFN0YXRlXG4gIHByaXZhdGUgaXNDb25uZWN0ZWQgPSBmYWxzZTtcbiAgcHJpdmF0ZSBpc1dvcmtpbmcgPSBmYWxzZTtcblxuICAvLyBDb25uZWN0aW9uIG5vdGljZXMgKGF2b2lkIHNwYW0pXG4gIHByaXZhdGUgbGFzdENvbm5Ob3RpY2VBdE1zID0gMDtcbiAgcHJpdmF0ZSBsYXN0R2F0ZXdheVN0YXRlOiBzdHJpbmcgfCBudWxsID0gbnVsbDtcblxuICAvLyBET00gcmVmc1xuICBwcml2YXRlIG1lc3NhZ2VzRWwhOiBIVE1MRWxlbWVudDtcbiAgcHJpdmF0ZSBpbnB1dEVsITogSFRNTFRleHRBcmVhRWxlbWVudDtcbiAgcHJpdmF0ZSBzZW5kQnRuITogSFRNTEJ1dHRvbkVsZW1lbnQ7XG4gIHByaXZhdGUgaW5jbHVkZU5vdGVDaGVja2JveCE6IEhUTUxJbnB1dEVsZW1lbnQ7XG4gIHByaXZhdGUgc3RhdHVzRG90ITogSFRNTEVsZW1lbnQ7XG5cbiAgcHJpdmF0ZSBzZXNzaW9uU2VsZWN0ITogSFRNTFNlbGVjdEVsZW1lbnQ7XG4gIHByaXZhdGUgc2Vzc2lvblJlZnJlc2hCdG4hOiBIVE1MQnV0dG9uRWxlbWVudDtcbiAgcHJpdmF0ZSBzZXNzaW9uTmV3QnRuITogSFRNTEJ1dHRvbkVsZW1lbnQ7XG5cbiAgcHJpdmF0ZSBvbk1lc3NhZ2VzQ2xpY2s6ICgoZXY6IE1vdXNlRXZlbnQpID0+IHZvaWQpIHwgbnVsbCA9IG51bGw7XG5cbiAgY29uc3RydWN0b3IobGVhZjogV29ya3NwYWNlTGVhZiwgcGx1Z2luOiBPcGVuQ2xhd1BsdWdpbikge1xuICAgIHN1cGVyKGxlYWYpO1xuICAgIHRoaXMucGx1Z2luID0gcGx1Z2luO1xuICAgIHRoaXMuY2hhdE1hbmFnZXIgPSBwbHVnaW4uY2hhdE1hbmFnZXI7XG4gIH1cblxuICBnZXRWaWV3VHlwZSgpOiBzdHJpbmcge1xuICAgIHJldHVybiBWSUVXX1RZUEVfT1BFTkNMQVdfQ0hBVDtcbiAgfVxuXG4gIGdldERpc3BsYXlUZXh0KCk6IHN0cmluZyB7XG4gICAgcmV0dXJuICdPcGVuQ2xhdyBDaGF0JztcbiAgfVxuXG4gIGdldEljb24oKTogc3RyaW5nIHtcbiAgICByZXR1cm4gJ21lc3NhZ2Utc3F1YXJlJztcbiAgfVxuXG4gIGFzeW5jIG9uT3BlbigpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICB0aGlzLl9idWlsZFVJKCk7XG5cbiAgICAvLyBGdWxsIHJlLXJlbmRlciBvbiBjbGVhciAvIHJlbG9hZFxuICAgIHRoaXMuY2hhdE1hbmFnZXIub25VcGRhdGUgPSAobXNncykgPT4gdGhpcy5fcmVuZGVyTWVzc2FnZXMobXNncyk7XG4gICAgLy8gTygxKSBhcHBlbmQgZm9yIG5ldyBtZXNzYWdlc1xuICAgIHRoaXMuY2hhdE1hbmFnZXIub25NZXNzYWdlQWRkZWQgPSAobXNnKSA9PiB0aGlzLl9hcHBlbmRNZXNzYWdlKG1zZyk7XG5cbiAgICAvLyBTdWJzY3JpYmUgdG8gV1Mgc3RhdGUgY2hhbmdlc1xuICAgIHRoaXMucGx1Z2luLndzQ2xpZW50Lm9uU3RhdGVDaGFuZ2UgPSAoc3RhdGUpID0+IHtcbiAgICAgIC8vIENvbm5lY3Rpb24gbG9zcyAvIHJlY29ubmVjdCBub3RpY2VzICh0aHJvdHRsZWQpXG4gICAgICBjb25zdCBwcmV2ID0gdGhpcy5sYXN0R2F0ZXdheVN0YXRlO1xuICAgICAgdGhpcy5sYXN0R2F0ZXdheVN0YXRlID0gc3RhdGU7XG5cbiAgICAgIGNvbnN0IG5vdyA9IERhdGUubm93KCk7XG4gICAgICBjb25zdCBOT1RJQ0VfVEhST1RUTEVfTVMgPSA2MF8wMDA7XG5cbiAgICAgIGNvbnN0IHNob3VsZE5vdGlmeSA9ICgpID0+IG5vdyAtIHRoaXMubGFzdENvbm5Ob3RpY2VBdE1zID4gTk9USUNFX1RIUk9UVExFX01TO1xuICAgICAgY29uc3Qgbm90aWZ5ID0gKHRleHQ6IHN0cmluZykgPT4ge1xuICAgICAgICBpZiAoIXNob3VsZE5vdGlmeSgpKSByZXR1cm47XG4gICAgICAgIHRoaXMubGFzdENvbm5Ob3RpY2VBdE1zID0gbm93O1xuICAgICAgICBuZXcgTm90aWNlKHRleHQpO1xuICAgICAgfTtcblxuICAgICAgLy8gT25seSBzaG93IFx1MjAxQ2xvc3RcdTIwMUQgaWYgd2Ugd2VyZSBwcmV2aW91c2x5IGNvbm5lY3RlZC5cbiAgICAgIGlmIChwcmV2ID09PSAnY29ubmVjdGVkJyAmJiBzdGF0ZSA9PT0gJ2Rpc2Nvbm5lY3RlZCcpIHtcbiAgICAgICAgbm90aWZ5KCdPcGVuQ2xhdyBDaGF0OiBjb25uZWN0aW9uIGxvc3QgXHUyMDE0IHJlY29ubmVjdGluZ1x1MjAyNicpO1xuICAgICAgICAvLyBBbHNvIGFwcGVuZCBhIHN5c3RlbSBtZXNzYWdlIHNvIGl0XHUyMDE5cyB2aXNpYmxlIGluIHRoZSBjaGF0IGhpc3RvcnkuXG4gICAgICAgIHRoaXMuY2hhdE1hbmFnZXIuYWRkTWVzc2FnZShDaGF0TWFuYWdlci5jcmVhdGVTeXN0ZW1NZXNzYWdlKCdcdTI2QTAgQ29ubmVjdGlvbiBsb3N0IFx1MjAxNCByZWNvbm5lY3RpbmdcdTIwMjYnLCAnZXJyb3InKSk7XG4gICAgICB9XG5cbiAgICAgIC8vIE9wdGlvbmFsIFx1MjAxQ3JlY29ubmVjdGVkXHUyMDFEIG5vdGljZVxuICAgICAgaWYgKHByZXYgJiYgcHJldiAhPT0gJ2Nvbm5lY3RlZCcgJiYgc3RhdGUgPT09ICdjb25uZWN0ZWQnKSB7XG4gICAgICAgIG5vdGlmeSgnT3BlbkNsYXcgQ2hhdDogcmVjb25uZWN0ZWQnKTtcbiAgICAgICAgdGhpcy5jaGF0TWFuYWdlci5hZGRNZXNzYWdlKENoYXRNYW5hZ2VyLmNyZWF0ZVN5c3RlbU1lc3NhZ2UoJ1x1MjcwNSBSZWNvbm5lY3RlZCcsICdpbmZvJykpO1xuICAgICAgfVxuXG4gICAgICB0aGlzLmlzQ29ubmVjdGVkID0gc3RhdGUgPT09ICdjb25uZWN0ZWQnO1xuICAgICAgdGhpcy5zdGF0dXNEb3QudG9nZ2xlQ2xhc3MoJ2Nvbm5lY3RlZCcsIHRoaXMuaXNDb25uZWN0ZWQpO1xuICAgICAgdGhpcy5zdGF0dXNEb3QudGl0bGUgPSBgR2F0ZXdheTogJHtzdGF0ZX1gO1xuICAgICAgdGhpcy5fdXBkYXRlU2VuZEJ1dHRvbigpO1xuICAgIH07XG5cbiAgICAvLyBTdWJzY3JpYmUgdG8gXHUyMDFDd29ya2luZ1x1MjAxRCAocmVxdWVzdC1pbi1mbGlnaHQpIHN0YXRlXG4gICAgdGhpcy5wbHVnaW4ud3NDbGllbnQub25Xb3JraW5nQ2hhbmdlID0gKHdvcmtpbmcpID0+IHtcbiAgICAgIHRoaXMuaXNXb3JraW5nID0gd29ya2luZztcbiAgICAgIHRoaXMuX3VwZGF0ZVNlbmRCdXR0b24oKTtcbiAgICB9O1xuXG4gICAgLy8gUmVmbGVjdCBjdXJyZW50IHN0YXRlXG4gICAgdGhpcy5sYXN0R2F0ZXdheVN0YXRlID0gdGhpcy5wbHVnaW4ud3NDbGllbnQuc3RhdGU7XG4gICAgdGhpcy5pc0Nvbm5lY3RlZCA9IHRoaXMucGx1Z2luLndzQ2xpZW50LnN0YXRlID09PSAnY29ubmVjdGVkJztcbiAgICB0aGlzLnN0YXR1c0RvdC50b2dnbGVDbGFzcygnY29ubmVjdGVkJywgdGhpcy5pc0Nvbm5lY3RlZCk7XG4gICAgdGhpcy5zdGF0dXNEb3QudGl0bGUgPSBgR2F0ZXdheTogJHt0aGlzLnBsdWdpbi53c0NsaWVudC5zdGF0ZX1gO1xuICAgIHRoaXMuX3VwZGF0ZVNlbmRCdXR0b24oKTtcblxuICAgIHRoaXMuX3JlbmRlck1lc3NhZ2VzKHRoaXMuY2hhdE1hbmFnZXIuZ2V0TWVzc2FnZXMoKSk7XG5cbiAgICAvLyBTZXNzaW9uIGRyb3Bkb3duIHBvcHVsYXRpb24gaXMgYmVzdC1lZmZvcnQuXG4gICAgdm9pZCB0aGlzLl9yZWZyZXNoU2Vzc2lvbnMoKTtcbiAgfVxuXG4gIGFzeW5jIG9uQ2xvc2UoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgdGhpcy5jaGF0TWFuYWdlci5vblVwZGF0ZSA9IG51bGw7XG4gICAgdGhpcy5jaGF0TWFuYWdlci5vbk1lc3NhZ2VBZGRlZCA9IG51bGw7XG4gICAgdGhpcy5wbHVnaW4ud3NDbGllbnQub25TdGF0ZUNoYW5nZSA9IG51bGw7XG4gICAgdGhpcy5wbHVnaW4ud3NDbGllbnQub25Xb3JraW5nQ2hhbmdlID0gbnVsbDtcblxuICAgIGlmICh0aGlzLm9uTWVzc2FnZXNDbGljaykge1xuICAgICAgdGhpcy5tZXNzYWdlc0VsPy5yZW1vdmVFdmVudExpc3RlbmVyKCdjbGljaycsIHRoaXMub25NZXNzYWdlc0NsaWNrKTtcbiAgICAgIHRoaXMub25NZXNzYWdlc0NsaWNrID0gbnVsbDtcbiAgICB9XG4gIH1cblxuICAvLyBcdTI1MDBcdTI1MDAgVUkgY29uc3RydWN0aW9uIFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFxuXG4gIHByaXZhdGUgX2J1aWxkVUkoKTogdm9pZCB7XG4gICAgY29uc3Qgcm9vdCA9IHRoaXMuY29udGVudEVsO1xuICAgIHJvb3QuZW1wdHkoKTtcbiAgICByb290LmFkZENsYXNzKCdvY2xhdy1jaGF0LXZpZXcnKTtcblxuICAgIC8vIFx1MjUwMFx1MjUwMCBIZWFkZXIgXHUyNTAwXHUyNTAwXG4gICAgY29uc3QgaGVhZGVyID0gcm9vdC5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1oZWFkZXInIH0pO1xuICAgIGhlYWRlci5jcmVhdGVTcGFuKHsgY2xzOiAnb2NsYXctaGVhZGVyLXRpdGxlJywgdGV4dDogJ09wZW5DbGF3IENoYXQnIH0pO1xuICAgIHRoaXMuc3RhdHVzRG90ID0gaGVhZGVyLmNyZWF0ZURpdih7IGNsczogJ29jbGF3LXN0YXR1cy1kb3QnIH0pO1xuICAgIHRoaXMuc3RhdHVzRG90LnRpdGxlID0gJ0dhdGV3YXk6IGRpc2Nvbm5lY3RlZCc7XG5cbiAgICAvLyBcdTI1MDBcdTI1MDAgU2Vzc2lvbiByb3cgXHUyNTAwXHUyNTAwXG4gICAgY29uc3Qgc2Vzc1JvdyA9IHJvb3QuY3JlYXRlRGl2KHsgY2xzOiAnb2NsYXctc2Vzc2lvbi1yb3cnIH0pO1xuICAgIHNlc3NSb3cuY3JlYXRlU3Bhbih7IGNsczogJ29jbGF3LXNlc3Npb24tbGFiZWwnLCB0ZXh0OiAnU2Vzc2lvbicgfSk7XG5cbiAgICB0aGlzLnNlc3Npb25TZWxlY3QgPSBzZXNzUm93LmNyZWF0ZUVsKCdzZWxlY3QnLCB7IGNsczogJ29jbGF3LXNlc3Npb24tc2VsZWN0JyB9KTtcbiAgICB0aGlzLnNlc3Npb25SZWZyZXNoQnRuID0gc2Vzc1Jvdy5jcmVhdGVFbCgnYnV0dG9uJywgeyBjbHM6ICdvY2xhdy1zZXNzaW9uLWJ0bicsIHRleHQ6ICdSZWZyZXNoJyB9KTtcbiAgICB0aGlzLnNlc3Npb25OZXdCdG4gPSBzZXNzUm93LmNyZWF0ZUVsKCdidXR0b24nLCB7IGNsczogJ29jbGF3LXNlc3Npb24tYnRuJywgdGV4dDogJ05ld1x1MjAyNicgfSk7XG5cbiAgICB0aGlzLnNlc3Npb25SZWZyZXNoQnRuLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gdm9pZCB0aGlzLl9yZWZyZXNoU2Vzc2lvbnMoKSk7XG4gICAgdGhpcy5zZXNzaW9uTmV3QnRuLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gdm9pZCB0aGlzLl9wcm9tcHROZXdTZXNzaW9uKCkpO1xuICAgIHRoaXMuc2Vzc2lvblNlbGVjdC5hZGRFdmVudExpc3RlbmVyKCdjaGFuZ2UnLCAoKSA9PiB7XG4gICAgICBjb25zdCBuZXh0ID0gdGhpcy5zZXNzaW9uU2VsZWN0LnZhbHVlO1xuICAgICAgaWYgKCFuZXh0IHx8IG5leHQgPT09IHRoaXMucGx1Z2luLnNldHRpbmdzLnNlc3Npb25LZXkpIHJldHVybjtcbiAgICAgIHZvaWQgdGhpcy5wbHVnaW4uc3dpdGNoU2Vzc2lvbihuZXh0KTtcbiAgICB9KTtcblxuICAgIC8vIFx1MjUwMFx1MjUwMCBNZXNzYWdlcyBhcmVhIFx1MjUwMFx1MjUwMFxuICAgIHRoaXMubWVzc2FnZXNFbCA9IHJvb3QuY3JlYXRlRGl2KHsgY2xzOiAnb2NsYXctbWVzc2FnZXMnIH0pO1xuXG4gICAgLy8gRGVsZWdhdGUgaW50ZXJuYWwtbGluayBjbGlja3MgKE1hcmtkb3duUmVuZGVyZXIgb3V0cHV0KSB0byBhIHJlbGlhYmxlIG9wZW5GaWxlIGhhbmRsZXIuXG4gICAgdGhpcy5faW5zdGFsbEludGVybmFsTGlua0RlbGVnYXRpb24oKTtcblxuICAgIC8vIFx1MjUwMFx1MjUwMCBDb250ZXh0IHJvdyBcdTI1MDBcdTI1MDBcbiAgICBjb25zdCBjdHhSb3cgPSByb290LmNyZWF0ZURpdih7IGNsczogJ29jbGF3LWNvbnRleHQtcm93JyB9KTtcbiAgICB0aGlzLmluY2x1ZGVOb3RlQ2hlY2tib3ggPSBjdHhSb3cuY3JlYXRlRWwoJ2lucHV0JywgeyB0eXBlOiAnY2hlY2tib3gnIH0pO1xuICAgIHRoaXMuaW5jbHVkZU5vdGVDaGVja2JveC5pZCA9ICdvY2xhdy1pbmNsdWRlLW5vdGUnO1xuICAgIHRoaXMuaW5jbHVkZU5vdGVDaGVja2JveC5jaGVja2VkID0gdGhpcy5wbHVnaW4uc2V0dGluZ3MuaW5jbHVkZUFjdGl2ZU5vdGU7XG4gICAgY29uc3QgY3R4TGFiZWwgPSBjdHhSb3cuY3JlYXRlRWwoJ2xhYmVsJywgeyB0ZXh0OiAnSW5jbHVkZSBhY3RpdmUgbm90ZScgfSk7XG4gICAgY3R4TGFiZWwuaHRtbEZvciA9ICdvY2xhdy1pbmNsdWRlLW5vdGUnO1xuXG4gICAgLy8gXHUyNTAwXHUyNTAwIElucHV0IHJvdyBcdTI1MDBcdTI1MDBcbiAgICBjb25zdCBpbnB1dFJvdyA9IHJvb3QuY3JlYXRlRGl2KHsgY2xzOiAnb2NsYXctaW5wdXQtcm93JyB9KTtcbiAgICB0aGlzLmlucHV0RWwgPSBpbnB1dFJvdy5jcmVhdGVFbCgndGV4dGFyZWEnLCB7XG4gICAgICBjbHM6ICdvY2xhdy1pbnB1dCcsXG4gICAgICBwbGFjZWhvbGRlcjogJ0FzayBhbnl0aGluZ1x1MjAyNicsXG4gICAgfSk7XG4gICAgdGhpcy5pbnB1dEVsLnJvd3MgPSAxO1xuXG4gICAgdGhpcy5zZW5kQnRuID0gaW5wdXRSb3cuY3JlYXRlRWwoJ2J1dHRvbicsIHsgY2xzOiAnb2NsYXctc2VuZC1idG4nLCB0ZXh0OiAnU2VuZCcgfSk7XG5cbiAgICAvLyBcdTI1MDBcdTI1MDAgRXZlbnQgbGlzdGVuZXJzIFx1MjUwMFx1MjUwMFxuICAgIHRoaXMuc2VuZEJ0bi5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpID0+IHRoaXMuX2hhbmRsZVNlbmQoKSk7XG4gICAgdGhpcy5pbnB1dEVsLmFkZEV2ZW50TGlzdGVuZXIoJ2tleWRvd24nLCAoZSkgPT4ge1xuICAgICAgaWYgKGUua2V5ID09PSAnRW50ZXInICYmICFlLnNoaWZ0S2V5KSB7XG4gICAgICAgIGUucHJldmVudERlZmF1bHQoKTtcbiAgICAgICAgdGhpcy5faGFuZGxlU2VuZCgpO1xuICAgICAgfVxuICAgIH0pO1xuICAgIC8vIEF1dG8tcmVzaXplIHRleHRhcmVhXG4gICAgdGhpcy5pbnB1dEVsLmFkZEV2ZW50TGlzdGVuZXIoJ2lucHV0JywgKCkgPT4ge1xuICAgICAgdGhpcy5pbnB1dEVsLnN0eWxlLmhlaWdodCA9ICdhdXRvJztcbiAgICAgIHRoaXMuaW5wdXRFbC5zdHlsZS5oZWlnaHQgPSBgJHt0aGlzLmlucHV0RWwuc2Nyb2xsSGVpZ2h0fXB4YDtcbiAgICB9KTtcbiAgfVxuXG4gIHByaXZhdGUgX3NldFNlc3Npb25TZWxlY3RPcHRpb25zKGtleXM6IHN0cmluZ1tdKTogdm9pZCB7XG4gICAgdGhpcy5zZXNzaW9uU2VsZWN0LmVtcHR5KCk7XG5cbiAgICBjb25zdCBjdXJyZW50ID0gdGhpcy5wbHVnaW4uc2V0dGluZ3Muc2Vzc2lvbktleTtcbiAgICBjb25zdCB1bmlxdWUgPSBBcnJheS5mcm9tKG5ldyBTZXQoW2N1cnJlbnQsIC4uLmtleXNdLmZpbHRlcihCb29sZWFuKSkpO1xuXG4gICAgZm9yIChjb25zdCBrZXkgb2YgdW5pcXVlKSB7XG4gICAgICBjb25zdCBvcHQgPSB0aGlzLnNlc3Npb25TZWxlY3QuY3JlYXRlRWwoJ29wdGlvbicsIHsgdmFsdWU6IGtleSwgdGV4dDoga2V5IH0pO1xuICAgICAgaWYgKGtleSA9PT0gY3VycmVudCkgb3B0LnNlbGVjdGVkID0gdHJ1ZTtcbiAgICB9XG5cbiAgICB0aGlzLnNlc3Npb25TZWxlY3QudGl0bGUgPSBjdXJyZW50O1xuICB9XG5cbiAgcHJpdmF0ZSBhc3luYyBfcmVmcmVzaFNlc3Npb25zKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIC8vIEFsd2F5cyBzaG93IGF0IGxlYXN0IHRoZSBjdXJyZW50IHNlc3Npb24uXG4gICAgaWYgKCF0aGlzLnNlc3Npb25TZWxlY3QpIHJldHVybjtcblxuICAgIGlmICh0aGlzLnBsdWdpbi53c0NsaWVudC5zdGF0ZSAhPT0gJ2Nvbm5lY3RlZCcpIHtcbiAgICAgIHRoaXMuX3NldFNlc3Npb25TZWxlY3RPcHRpb25zKFtdKTtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICB0cnkge1xuICAgICAgY29uc3QgcmVzID0gYXdhaXQgdGhpcy5wbHVnaW4ud3NDbGllbnQubGlzdFNlc3Npb25zKHtcbiAgICAgICAgYWN0aXZlTWludXRlczogNjAgKiAyNCxcbiAgICAgICAgbGltaXQ6IDEwMCxcbiAgICAgICAgaW5jbHVkZUdsb2JhbDogZmFsc2UsXG4gICAgICAgIGluY2x1ZGVVbmtub3duOiBmYWxzZSxcbiAgICAgIH0pO1xuXG4gICAgICBjb25zdCByb3dzID0gQXJyYXkuaXNBcnJheShyZXM/LnNlc3Npb25zKSA/IHJlcy5zZXNzaW9ucyA6IFtdO1xuICAgICAgY29uc3Qgb2JzaWRpYW5Pbmx5ID0gcm93cy5maWx0ZXIoKHIpID0+IHIgJiYgKHIuY2hhbm5lbCA9PT0gJ29ic2lkaWFuJyB8fCBTdHJpbmcoci5rZXkpLmluY2x1ZGVzKCc6b2JzaWRpYW46JykpKTtcbiAgICAgIGNvbnN0IGtleXMgPSAob2JzaWRpYW5Pbmx5Lmxlbmd0aCA/IG9ic2lkaWFuT25seSA6IHJvd3MpLm1hcCgocikgPT4gci5rZXkpLmZpbHRlcihCb29sZWFuKTtcbiAgICAgIHRoaXMuX3NldFNlc3Npb25TZWxlY3RPcHRpb25zKGtleXMpO1xuICAgIH0gY2F0Y2ggKGVycikge1xuICAgICAgY29uc29sZS5lcnJvcignW29jbGF3XSBzZXNzaW9ucy5saXN0IGZhaWxlZCcsIGVycik7XG4gICAgICAvLyBLZWVwIGN1cnJlbnQgb3B0aW9uIG9ubHkuXG4gICAgICB0aGlzLl9zZXRTZXNzaW9uU2VsZWN0T3B0aW9ucyhbXSk7XG4gICAgfVxuICB9XG5cbiAgcHJpdmF0ZSBhc3luYyBfcHJvbXB0TmV3U2Vzc2lvbigpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBjb25zdCBub3cgPSBuZXcgRGF0ZSgpO1xuICAgIGNvbnN0IHBhZCA9IChuOiBudW1iZXIpID0+IFN0cmluZyhuKS5wYWRTdGFydCgyLCAnMCcpO1xuICAgIGNvbnN0IHN1Z2dlc3RlZCA9IGBvYnNpZGlhbi0ke25vdy5nZXRGdWxsWWVhcigpfSR7cGFkKG5vdy5nZXRNb250aCgpICsgMSl9JHtwYWQobm93LmdldERhdGUoKSl9LSR7cGFkKG5vdy5nZXRIb3VycygpKX0ke3BhZChub3cuZ2V0TWludXRlcygpKX1gO1xuICAgIGNvbnN0IG5leHQgPSB3aW5kb3cucHJvbXB0KCdOZXcgc2Vzc2lvbiBrZXknLCBzdWdnZXN0ZWQpO1xuICAgIGlmICghbmV4dCkgcmV0dXJuO1xuICAgIGF3YWl0IHRoaXMucGx1Z2luLnN3aXRjaFNlc3Npb24obmV4dCk7XG4gICAgLy8gVXBkYXRlIGRyb3Bkb3duIHNlbGVjdGlvbiBiZXN0LWVmZm9ydC5cbiAgICB0aGlzLl9zZXRTZXNzaW9uU2VsZWN0T3B0aW9ucyhbXSk7XG4gIH1cblxuICAvLyBcdTI1MDBcdTI1MDAgTWVzc2FnZSByZW5kZXJpbmcgXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG5cbiAgcHJpdmF0ZSBfcmVuZGVyTWVzc2FnZXMobWVzc2FnZXM6IHJlYWRvbmx5IENoYXRNZXNzYWdlW10pOiB2b2lkIHtcbiAgICB0aGlzLm1lc3NhZ2VzRWwuZW1wdHkoKTtcblxuICAgIGlmIChtZXNzYWdlcy5sZW5ndGggPT09IDApIHtcbiAgICAgIHRoaXMubWVzc2FnZXNFbC5jcmVhdGVFbCgncCcsIHtcbiAgICAgICAgdGV4dDogJ1NlbmQgYSBtZXNzYWdlIHRvIHN0YXJ0IGNoYXR0aW5nLicsXG4gICAgICAgIGNsczogJ29jbGF3LW1lc3NhZ2Ugc3lzdGVtIG9jbGF3LXBsYWNlaG9sZGVyJyxcbiAgICAgIH0pO1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIGZvciAoY29uc3QgbXNnIG9mIG1lc3NhZ2VzKSB7XG4gICAgICB0aGlzLl9hcHBlbmRNZXNzYWdlKG1zZyk7XG4gICAgfVxuXG4gICAgLy8gU2Nyb2xsIHRvIGJvdHRvbVxuICAgIHRoaXMubWVzc2FnZXNFbC5zY3JvbGxUb3AgPSB0aGlzLm1lc3NhZ2VzRWwuc2Nyb2xsSGVpZ2h0O1xuICB9XG5cbiAgLyoqIEFwcGVuZHMgYSBzaW5nbGUgbWVzc2FnZSB3aXRob3V0IHJlYnVpbGRpbmcgdGhlIERPTSAoTygxKSkgKi9cbiAgcHJpdmF0ZSBfYXBwZW5kTWVzc2FnZShtc2c6IENoYXRNZXNzYWdlKTogdm9pZCB7XG4gICAgLy8gUmVtb3ZlIGVtcHR5LXN0YXRlIHBsYWNlaG9sZGVyIGlmIHByZXNlbnRcbiAgICB0aGlzLm1lc3NhZ2VzRWwucXVlcnlTZWxlY3RvcignLm9jbGF3LXBsYWNlaG9sZGVyJyk/LnJlbW92ZSgpO1xuXG4gICAgY29uc3QgbGV2ZWxDbGFzcyA9IG1zZy5sZXZlbCA/IGAgJHttc2cubGV2ZWx9YCA6ICcnO1xuICAgIGNvbnN0IGtpbmRDbGFzcyA9IG1zZy5raW5kID8gYCBvY2xhdy0ke21zZy5raW5kfWAgOiAnJztcbiAgICBjb25zdCBlbCA9IHRoaXMubWVzc2FnZXNFbC5jcmVhdGVEaXYoeyBjbHM6IGBvY2xhdy1tZXNzYWdlICR7bXNnLnJvbGV9JHtsZXZlbENsYXNzfSR7a2luZENsYXNzfWAgfSk7XG4gICAgY29uc3QgYm9keSA9IGVsLmNyZWF0ZURpdih7IGNsczogJ29jbGF3LW1lc3NhZ2UtYm9keScgfSk7XG4gICAgaWYgKG1zZy50aXRsZSkge1xuICAgICAgYm9keS50aXRsZSA9IG1zZy50aXRsZTtcbiAgICB9XG5cbiAgICAvLyBUcmVhdCBhc3Npc3RhbnQgb3V0cHV0IGFzIFVOVFJVU1RFRCBieSBkZWZhdWx0LlxuICAgIC8vIFJlbmRlcmluZyBhcyBPYnNpZGlhbiBNYXJrZG93biBjYW4gdHJpZ2dlciBlbWJlZHMgYW5kIG90aGVyIHBsdWdpbnMnIHBvc3QtcHJvY2Vzc29ycy5cbiAgICBpZiAobXNnLnJvbGUgPT09ICdhc3Npc3RhbnQnKSB7XG4gICAgICBjb25zdCBtYXBwaW5nczogUGF0aE1hcHBpbmdbXSA9IHRoaXMucGx1Z2luLnNldHRpbmdzLnBhdGhNYXBwaW5ncyA/PyBbXTtcbiAgICAgIGNvbnN0IHNvdXJjZVBhdGggPSB0aGlzLmFwcC53b3Jrc3BhY2UuZ2V0QWN0aXZlRmlsZSgpPy5wYXRoID8/ICcnO1xuXG4gICAgICBpZiAodGhpcy5wbHVnaW4uc2V0dGluZ3MucmVuZGVyQXNzaXN0YW50TWFya2Rvd24pIHtcbiAgICAgICAgLy8gQmVzdC1lZmZvcnQgcHJlLXByb2Nlc3Npbmc6IHJlcGxhY2Uga25vd24gcmVtb3RlIHBhdGhzIHdpdGggd2lraWxpbmtzIHdoZW4gdGhlIHRhcmdldCBleGlzdHMuXG4gICAgICAgIGNvbnN0IHByZSA9IHRoaXMuX3ByZXByb2Nlc3NBc3Npc3RhbnRNYXJrZG93bihtc2cuY29udGVudCwgbWFwcGluZ3MpO1xuICAgICAgICB2b2lkIE1hcmtkb3duUmVuZGVyZXIucmVuZGVyTWFya2Rvd24ocHJlLCBib2R5LCBzb3VyY2VQYXRoLCB0aGlzLnBsdWdpbik7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICAvLyBQbGFpbiBtb2RlOiBidWlsZCBzYWZlLCBjbGlja2FibGUgbGlua3MgaW4gRE9NIChubyBNYXJrZG93biByZW5kZXJpbmcpLlxuICAgICAgICB0aGlzLl9yZW5kZXJBc3Npc3RhbnRQbGFpbldpdGhMaW5rcyhib2R5LCBtc2cuY29udGVudCwgbWFwcGluZ3MsIHNvdXJjZVBhdGgpO1xuICAgICAgfVxuICAgIH0gZWxzZSB7XG4gICAgICBib2R5LnNldFRleHQobXNnLmNvbnRlbnQpO1xuICAgIH1cblxuICAgIC8vIFNjcm9sbCB0byBib3R0b21cbiAgICB0aGlzLm1lc3NhZ2VzRWwuc2Nyb2xsVG9wID0gdGhpcy5tZXNzYWdlc0VsLnNjcm9sbEhlaWdodDtcbiAgfVxuXG4gIHByaXZhdGUgX3RyeVJldmVyc2VNYXBVcmxUb1ZhdWx0UGF0aCh1cmw6IHN0cmluZywgbWFwcGluZ3M6IFBhdGhNYXBwaW5nW10pOiBzdHJpbmcgfCBudWxsIHtcbiAgICAvLyBGUy1iYXNlZCBtYXBwaW5nOyBiZXN0LWVmZm9ydCBvbmx5LlxuICAgIGxldCBkZWNvZGVkID0gdXJsO1xuICAgIHRyeSB7XG4gICAgICBkZWNvZGVkID0gZGVjb2RlVVJJQ29tcG9uZW50KHVybCk7XG4gICAgfSBjYXRjaCB7XG4gICAgICAvLyBpZ25vcmVcbiAgICB9XG5cbiAgICAvLyBJZiB0aGUgZGVjb2RlZCBVUkwgY29udGFpbnMgYSByZW1vdGVCYXNlIHN1YnN0cmluZywgdHJ5IG1hcHBpbmcgZnJvbSB0aGF0IHBvaW50LlxuICAgIGZvciAoY29uc3Qgcm93IG9mIG1hcHBpbmdzKSB7XG4gICAgICBjb25zdCByZW1vdGVCYXNlID0gU3RyaW5nKHJvdy5yZW1vdGVCYXNlID8/ICcnKTtcbiAgICAgIGlmICghcmVtb3RlQmFzZSkgY29udGludWU7XG4gICAgICBjb25zdCBpZHggPSBkZWNvZGVkLmluZGV4T2YocmVtb3RlQmFzZSk7XG4gICAgICBpZiAoaWR4IDwgMCkgY29udGludWU7XG5cbiAgICAgIC8vIEV4dHJhY3QgZnJvbSByZW1vdGVCYXNlIG9ud2FyZCB1bnRpbCBhIHRlcm1pbmF0b3IuXG4gICAgICBjb25zdCB0YWlsID0gZGVjb2RlZC5zbGljZShpZHgpO1xuICAgICAgY29uc3QgdG9rZW4gPSB0YWlsLnNwbGl0KC9bXFxzJ1wiPD4pXS8pWzBdO1xuICAgICAgY29uc3QgbWFwcGVkID0gdHJ5TWFwUmVtb3RlUGF0aFRvVmF1bHRQYXRoKHRva2VuLCBtYXBwaW5ncyk7XG4gICAgICBpZiAobWFwcGVkICYmIHRoaXMuYXBwLnZhdWx0LmdldEFic3RyYWN0RmlsZUJ5UGF0aChtYXBwZWQpKSByZXR1cm4gbWFwcGVkO1xuICAgIH1cblxuICAgIHJldHVybiBudWxsO1xuICB9XG5cbiAgcHJpdmF0ZSBfaW5zdGFsbEludGVybmFsTGlua0RlbGVnYXRpb24oKTogdm9pZCB7XG4gICAgaWYgKHRoaXMub25NZXNzYWdlc0NsaWNrKSByZXR1cm47XG5cbiAgICB0aGlzLm9uTWVzc2FnZXNDbGljayA9IChldjogTW91c2VFdmVudCkgPT4ge1xuICAgICAgY29uc3QgdGFyZ2V0ID0gZXYudGFyZ2V0IGFzIEhUTUxFbGVtZW50IHwgbnVsbDtcbiAgICAgIGNvbnN0IGEgPSB0YXJnZXQ/LmNsb3Nlc3Q/LignYS5pbnRlcm5hbC1saW5rJykgYXMgSFRNTEFuY2hvckVsZW1lbnQgfCBudWxsO1xuICAgICAgaWYgKCFhKSByZXR1cm47XG5cbiAgICAgIGNvbnN0IGRhdGFIcmVmID0gYS5nZXRBdHRyaWJ1dGUoJ2RhdGEtaHJlZicpIHx8ICcnO1xuICAgICAgY29uc3QgaHJlZkF0dHIgPSBhLmdldEF0dHJpYnV0ZSgnaHJlZicpIHx8ICcnO1xuXG4gICAgICBjb25zdCByYXcgPSAoZGF0YUhyZWYgfHwgaHJlZkF0dHIpLnRyaW0oKTtcbiAgICAgIGlmICghcmF3KSByZXR1cm47XG5cbiAgICAgIC8vIElmIGl0IGlzIGFuIGFic29sdXRlIFVSTCwgbGV0IHRoZSBkZWZhdWx0IGJlaGF2aW9yIGhhbmRsZSBpdC5cbiAgICAgIGlmICgvXmh0dHBzPzpcXC9cXC8vaS50ZXN0KHJhdykpIHJldHVybjtcblxuICAgICAgLy8gT2JzaWRpYW4gaW50ZXJuYWwtbGluayBvZnRlbiB1c2VzIHZhdWx0LXJlbGF0aXZlIHBhdGguXG4gICAgICBjb25zdCB2YXVsdFBhdGggPSByYXcucmVwbGFjZSgvXlxcLysvLCAnJyk7XG4gICAgICBjb25zdCBmID0gdGhpcy5hcHAudmF1bHQuZ2V0QWJzdHJhY3RGaWxlQnlQYXRoKHZhdWx0UGF0aCk7XG4gICAgICBpZiAoIShmIGluc3RhbmNlb2YgVEZpbGUpKSByZXR1cm47XG5cbiAgICAgIGV2LnByZXZlbnREZWZhdWx0KCk7XG4gICAgICBldi5zdG9wUHJvcGFnYXRpb24oKTtcbiAgICAgIHZvaWQgdGhpcy5hcHAud29ya3NwYWNlLmdldExlYWYodHJ1ZSkub3BlbkZpbGUoZik7XG4gICAgfTtcblxuICAgIHRoaXMubWVzc2FnZXNFbC5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsIHRoaXMub25NZXNzYWdlc0NsaWNrKTtcbiAgfVxuXG4gIHByaXZhdGUgX3RyeU1hcFZhdWx0UmVsYXRpdmVUb2tlbih0b2tlbjogc3RyaW5nLCBtYXBwaW5nczogUGF0aE1hcHBpbmdbXSk6IHN0cmluZyB8IG51bGwge1xuICAgIGNvbnN0IHQgPSB0b2tlbi5yZXBsYWNlKC9eXFwvKy8sICcnKTtcbiAgICBpZiAodGhpcy5hcHAudmF1bHQuZ2V0QWJzdHJhY3RGaWxlQnlQYXRoKHQpKSByZXR1cm4gdDtcblxuICAgIC8vIEhldXJpc3RpYzogaWYgdmF1bHRCYXNlIGVuZHMgd2l0aCBhIHNlZ21lbnQgKGUuZy4gd29ya3NwYWNlL2NvbXBlbmcvKSBhbmQgdG9rZW4gc3RhcnRzIHdpdGggdGhhdCBzZWdtZW50IChjb21wZW5nLy4uLiksXG4gICAgLy8gbWFwIHRva2VuIHVuZGVyIHZhdWx0QmFzZS5cbiAgICBmb3IgKGNvbnN0IHJvdyBvZiBtYXBwaW5ncykge1xuICAgICAgY29uc3QgdmF1bHRCYXNlUmF3ID0gU3RyaW5nKHJvdy52YXVsdEJhc2UgPz8gJycpLnRyaW0oKTtcbiAgICAgIGlmICghdmF1bHRCYXNlUmF3KSBjb250aW51ZTtcbiAgICAgIGNvbnN0IHZhdWx0QmFzZSA9IHZhdWx0QmFzZVJhdy5lbmRzV2l0aCgnLycpID8gdmF1bHRCYXNlUmF3IDogYCR7dmF1bHRCYXNlUmF3fS9gO1xuXG4gICAgICBjb25zdCBwYXJ0cyA9IHZhdWx0QmFzZS5yZXBsYWNlKC9cXC8rJC8sICcnKS5zcGxpdCgnLycpO1xuICAgICAgY29uc3QgYmFzZU5hbWUgPSBwYXJ0c1twYXJ0cy5sZW5ndGggLSAxXTtcbiAgICAgIGlmICghYmFzZU5hbWUpIGNvbnRpbnVlO1xuXG4gICAgICBjb25zdCBwcmVmaXggPSBgJHtiYXNlTmFtZX0vYDtcbiAgICAgIGlmICghdC5zdGFydHNXaXRoKHByZWZpeCkpIGNvbnRpbnVlO1xuXG4gICAgICBjb25zdCBjYW5kaWRhdGUgPSBgJHt2YXVsdEJhc2V9JHt0LnNsaWNlKHByZWZpeC5sZW5ndGgpfWA7XG4gICAgICBjb25zdCBub3JtYWxpemVkID0gY2FuZGlkYXRlLnJlcGxhY2UoL15cXC8rLywgJycpO1xuICAgICAgaWYgKHRoaXMuYXBwLnZhdWx0LmdldEFic3RyYWN0RmlsZUJ5UGF0aChub3JtYWxpemVkKSkgcmV0dXJuIG5vcm1hbGl6ZWQ7XG4gICAgfVxuXG4gICAgcmV0dXJuIG51bGw7XG4gIH1cblxuICBwcml2YXRlIF9wcmVwcm9jZXNzQXNzaXN0YW50TWFya2Rvd24odGV4dDogc3RyaW5nLCBtYXBwaW5nczogUGF0aE1hcHBpbmdbXSk6IHN0cmluZyB7XG4gICAgY29uc3QgY2FuZGlkYXRlcyA9IGV4dHJhY3RDYW5kaWRhdGVzKHRleHQpO1xuICAgIGlmIChjYW5kaWRhdGVzLmxlbmd0aCA9PT0gMCkgcmV0dXJuIHRleHQ7XG5cbiAgICBsZXQgb3V0ID0gJyc7XG4gICAgbGV0IGN1cnNvciA9IDA7XG5cbiAgICBmb3IgKGNvbnN0IGMgb2YgY2FuZGlkYXRlcykge1xuICAgICAgb3V0ICs9IHRleHQuc2xpY2UoY3Vyc29yLCBjLnN0YXJ0KTtcbiAgICAgIGN1cnNvciA9IGMuZW5kO1xuXG4gICAgICBpZiAoYy5raW5kID09PSAndXJsJykge1xuICAgICAgICAvLyBVUkxzIHJlbWFpbiBVUkxzIFVOTEVTUyB3ZSBjYW4gc2FmZWx5IG1hcCB0byBhbiBleGlzdGluZyB2YXVsdCBmaWxlLlxuICAgICAgICBjb25zdCBtYXBwZWQgPSB0aGlzLl90cnlSZXZlcnNlTWFwVXJsVG9WYXVsdFBhdGgoYy5yYXcsIG1hcHBpbmdzKTtcbiAgICAgICAgb3V0ICs9IG1hcHBlZCA/IGBbWyR7bWFwcGVkfV1dYCA6IGMucmF3O1xuICAgICAgICBjb250aW51ZTtcbiAgICAgIH1cblxuICAgICAgLy8gMSkgSWYgdGhlIHRva2VuIGlzIGFscmVhZHkgYSB2YXVsdC1yZWxhdGl2ZSBwYXRoIChvciBjYW4gYmUgcmVzb2x2ZWQgdmlhIHZhdWx0QmFzZSBoZXVyaXN0aWMpLCBsaW5raWZ5IGl0IGRpcmVjdGx5LlxuICAgICAgY29uc3QgZGlyZWN0ID0gdGhpcy5fdHJ5TWFwVmF1bHRSZWxhdGl2ZVRva2VuKGMucmF3LCBtYXBwaW5ncyk7XG4gICAgICBpZiAoZGlyZWN0KSB7XG4gICAgICAgIG91dCArPSBgW1ske2RpcmVjdH1dXWA7XG4gICAgICAgIGNvbnRpbnVlO1xuICAgICAgfVxuXG4gICAgICAvLyAyKSBFbHNlOiB0cnkgcmVtb3RlXHUyMTkydmF1bHQgbWFwcGluZy5cbiAgICAgIGNvbnN0IG1hcHBlZCA9IHRyeU1hcFJlbW90ZVBhdGhUb1ZhdWx0UGF0aChjLnJhdywgbWFwcGluZ3MpO1xuICAgICAgaWYgKCFtYXBwZWQpIHtcbiAgICAgICAgb3V0ICs9IGMucmF3O1xuICAgICAgICBjb250aW51ZTtcbiAgICAgIH1cblxuICAgICAgaWYgKCF0aGlzLmFwcC52YXVsdC5nZXRBYnN0cmFjdEZpbGVCeVBhdGgobWFwcGVkKSkge1xuICAgICAgICBvdXQgKz0gYy5yYXc7XG4gICAgICAgIGNvbnRpbnVlO1xuICAgICAgfVxuXG4gICAgICBvdXQgKz0gYFtbJHttYXBwZWR9XV1gO1xuICAgIH1cblxuICAgIG91dCArPSB0ZXh0LnNsaWNlKGN1cnNvcik7XG4gICAgcmV0dXJuIG91dDtcbiAgfVxuXG4gIHByaXZhdGUgX3JlbmRlckFzc2lzdGFudFBsYWluV2l0aExpbmtzKFxuICAgIGJvZHk6IEhUTUxFbGVtZW50LFxuICAgIHRleHQ6IHN0cmluZyxcbiAgICBtYXBwaW5nczogUGF0aE1hcHBpbmdbXSxcbiAgICBzb3VyY2VQYXRoOiBzdHJpbmcsXG4gICk6IHZvaWQge1xuICAgIGNvbnN0IGNhbmRpZGF0ZXMgPSBleHRyYWN0Q2FuZGlkYXRlcyh0ZXh0KTtcbiAgICBpZiAoY2FuZGlkYXRlcy5sZW5ndGggPT09IDApIHtcbiAgICAgIGJvZHkuc2V0VGV4dCh0ZXh0KTtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICBsZXQgY3Vyc29yID0gMDtcblxuICAgIGNvbnN0IGFwcGVuZFRleHQgPSAoczogc3RyaW5nKSA9PiB7XG4gICAgICBpZiAoIXMpIHJldHVybjtcbiAgICAgIGJvZHkuYXBwZW5kQ2hpbGQoZG9jdW1lbnQuY3JlYXRlVGV4dE5vZGUocykpO1xuICAgIH07XG5cbiAgICBjb25zdCBhcHBlbmRPYnNpZGlhbkxpbmsgPSAodmF1bHRQYXRoOiBzdHJpbmcpID0+IHtcbiAgICAgIGNvbnN0IGRpc3BsYXkgPSBgW1ske3ZhdWx0UGF0aH1dXWA7XG4gICAgICBjb25zdCBhID0gYm9keS5jcmVhdGVFbCgnYScsIHsgdGV4dDogZGlzcGxheSwgaHJlZjogJyMnIH0pO1xuICAgICAgYS5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsIChldikgPT4ge1xuICAgICAgICBldi5wcmV2ZW50RGVmYXVsdCgpO1xuICAgICAgICBldi5zdG9wUHJvcGFnYXRpb24oKTtcblxuICAgICAgICBjb25zdCBmID0gdGhpcy5hcHAudmF1bHQuZ2V0QWJzdHJhY3RGaWxlQnlQYXRoKHZhdWx0UGF0aCk7XG4gICAgICAgIGlmIChmIGluc3RhbmNlb2YgVEZpbGUpIHtcbiAgICAgICAgICB2b2lkIHRoaXMuYXBwLndvcmtzcGFjZS5nZXRMZWFmKHRydWUpLm9wZW5GaWxlKGYpO1xuICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIC8vIEZhbGxiYWNrOiBiZXN0LWVmZm9ydCBsaW5rdGV4dCBvcGVuLlxuICAgICAgICB2b2lkIHRoaXMuYXBwLndvcmtzcGFjZS5vcGVuTGlua1RleHQodmF1bHRQYXRoLCBzb3VyY2VQYXRoLCB0cnVlKTtcbiAgICAgIH0pO1xuICAgIH07XG5cbiAgICBjb25zdCBhcHBlbmRFeHRlcm5hbFVybCA9ICh1cmw6IHN0cmluZykgPT4ge1xuICAgICAgLy8gTGV0IE9ic2lkaWFuL0VsZWN0cm9uIGhhbmRsZSBleHRlcm5hbCBvcGVuLlxuICAgICAgYm9keS5jcmVhdGVFbCgnYScsIHsgdGV4dDogdXJsLCBocmVmOiB1cmwgfSk7XG4gICAgfTtcblxuICAgIGNvbnN0IHRyeVJldmVyc2VNYXBVcmxUb1ZhdWx0UGF0aCA9ICh1cmw6IHN0cmluZyk6IHN0cmluZyB8IG51bGwgPT4gdGhpcy5fdHJ5UmV2ZXJzZU1hcFVybFRvVmF1bHRQYXRoKHVybCwgbWFwcGluZ3MpO1xuXG4gICAgZm9yIChjb25zdCBjIG9mIGNhbmRpZGF0ZXMpIHtcbiAgICAgIGFwcGVuZFRleHQodGV4dC5zbGljZShjdXJzb3IsIGMuc3RhcnQpKTtcbiAgICAgIGN1cnNvciA9IGMuZW5kO1xuXG4gICAgICBpZiAoYy5raW5kID09PSAndXJsJykge1xuICAgICAgICBjb25zdCBtYXBwZWQgPSB0cnlSZXZlcnNlTWFwVXJsVG9WYXVsdFBhdGgoYy5yYXcpO1xuICAgICAgICBpZiAobWFwcGVkKSB7XG4gICAgICAgICAgYXBwZW5kT2JzaWRpYW5MaW5rKG1hcHBlZCk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgYXBwZW5kRXh0ZXJuYWxVcmwoYy5yYXcpO1xuICAgICAgICB9XG4gICAgICAgIGNvbnRpbnVlO1xuICAgICAgfVxuXG4gICAgICAvLyAxKSBJZiB0b2tlbiBpcyBhbHJlYWR5IGEgdmF1bHQtcmVsYXRpdmUgcGF0aCAob3IgY2FuIGJlIHJlc29sdmVkIHZpYSB2YXVsdEJhc2UgaGV1cmlzdGljKSwgbGlua2lmeSBkaXJlY3RseS5cbiAgICAgIGNvbnN0IGRpcmVjdCA9IHRoaXMuX3RyeU1hcFZhdWx0UmVsYXRpdmVUb2tlbihjLnJhdywgbWFwcGluZ3MpO1xuICAgICAgaWYgKGRpcmVjdCkge1xuICAgICAgICBhcHBlbmRPYnNpZGlhbkxpbmsoZGlyZWN0KTtcbiAgICAgICAgY29udGludWU7XG4gICAgICB9XG5cbiAgICAgIC8vIDIpIEVsc2U6IHRyeSByZW1vdGVcdTIxOTJ2YXVsdCBtYXBwaW5nLlxuICAgICAgY29uc3QgbWFwcGVkID0gdHJ5TWFwUmVtb3RlUGF0aFRvVmF1bHRQYXRoKGMucmF3LCBtYXBwaW5ncyk7XG4gICAgICBpZiAoIW1hcHBlZCkge1xuICAgICAgICBhcHBlbmRUZXh0KGMucmF3KTtcbiAgICAgICAgY29udGludWU7XG4gICAgICB9XG5cbiAgICAgIGlmICghdGhpcy5hcHAudmF1bHQuZ2V0QWJzdHJhY3RGaWxlQnlQYXRoKG1hcHBlZCkpIHtcbiAgICAgICAgYXBwZW5kVGV4dChjLnJhdyk7XG4gICAgICAgIGNvbnRpbnVlO1xuICAgICAgfVxuXG4gICAgICBhcHBlbmRPYnNpZGlhbkxpbmsobWFwcGVkKTtcbiAgICB9XG5cbiAgICBhcHBlbmRUZXh0KHRleHQuc2xpY2UoY3Vyc29yKSk7XG4gIH1cblxuICBwcml2YXRlIF91cGRhdGVTZW5kQnV0dG9uKCk6IHZvaWQge1xuICAgIC8vIERpc2Nvbm5lY3RlZDogZGlzYWJsZS5cbiAgICAvLyBXb3JraW5nOiBrZWVwIGVuYWJsZWQgc28gdXNlciBjYW4gc3RvcC9hYm9ydC5cbiAgICBjb25zdCBkaXNhYmxlZCA9ICF0aGlzLmlzQ29ubmVjdGVkO1xuICAgIHRoaXMuc2VuZEJ0bi5kaXNhYmxlZCA9IGRpc2FibGVkO1xuXG4gICAgdGhpcy5zZW5kQnRuLnRvZ2dsZUNsYXNzKCdpcy13b3JraW5nJywgdGhpcy5pc1dvcmtpbmcpO1xuICAgIHRoaXMuc2VuZEJ0bi5zZXRBdHRyKCdhcmlhLWJ1c3knLCB0aGlzLmlzV29ya2luZyA/ICd0cnVlJyA6ICdmYWxzZScpO1xuICAgIHRoaXMuc2VuZEJ0bi5zZXRBdHRyKCdhcmlhLWxhYmVsJywgdGhpcy5pc1dvcmtpbmcgPyAnU3RvcCcgOiAnU2VuZCcpO1xuXG4gICAgaWYgKHRoaXMuaXNXb3JraW5nKSB7XG4gICAgICAvLyBSZXBsYWNlIGJ1dHRvbiBjb250ZW50cyB3aXRoIFN0b3AgaWNvbiArIHNwaW5uZXIgcmluZy5cbiAgICAgIHRoaXMuc2VuZEJ0bi5lbXB0eSgpO1xuICAgICAgY29uc3Qgd3JhcCA9IHRoaXMuc2VuZEJ0bi5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1zdG9wLXdyYXAnIH0pO1xuICAgICAgd3JhcC5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1zcGlubmVyLXJpbmcnLCBhdHRyOiB7ICdhcmlhLWhpZGRlbic6ICd0cnVlJyB9IH0pO1xuICAgICAgd3JhcC5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1zdG9wLWljb24nLCBhdHRyOiB7ICdhcmlhLWhpZGRlbic6ICd0cnVlJyB9IH0pO1xuICAgIH0gZWxzZSB7XG4gICAgICAvLyBSZXN0b3JlIGxhYmVsXG4gICAgICB0aGlzLnNlbmRCdG4uc2V0VGV4dCgnU2VuZCcpO1xuICAgIH1cbiAgfVxuXG4gIC8vIFx1MjUwMFx1MjUwMCBTZW5kIGhhbmRsZXIgXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG5cbiAgcHJpdmF0ZSBhc3luYyBfaGFuZGxlU2VuZCgpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICAvLyBXaGlsZSB3b3JraW5nLCB0aGUgYnV0dG9uIGJlY29tZXMgU3RvcC5cbiAgICBpZiAodGhpcy5pc1dvcmtpbmcpIHtcbiAgICAgIGNvbnN0IG9rID0gYXdhaXQgdGhpcy5wbHVnaW4ud3NDbGllbnQuYWJvcnRBY3RpdmVSdW4oKTtcbiAgICAgIGlmICghb2spIHtcbiAgICAgICAgbmV3IE5vdGljZSgnT3BlbkNsYXcgQ2hhdDogZmFpbGVkIHRvIHN0b3AnKTtcbiAgICAgICAgdGhpcy5jaGF0TWFuYWdlci5hZGRNZXNzYWdlKENoYXRNYW5hZ2VyLmNyZWF0ZVN5c3RlbU1lc3NhZ2UoJ1x1MjZBMCBTdG9wIGZhaWxlZCcsICdlcnJvcicpKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHRoaXMuY2hhdE1hbmFnZXIuYWRkTWVzc2FnZShDaGF0TWFuYWdlci5jcmVhdGVTeXN0ZW1NZXNzYWdlKCdcdTI2RDQgU3RvcHBlZCcsICdpbmZvJykpO1xuICAgICAgfVxuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIGNvbnN0IHRleHQgPSB0aGlzLmlucHV0RWwudmFsdWUudHJpbSgpO1xuICAgIGlmICghdGV4dCkgcmV0dXJuO1xuXG4gICAgLy8gQnVpbGQgbWVzc2FnZSB3aXRoIGNvbnRleHQgaWYgZW5hYmxlZFxuICAgIGxldCBtZXNzYWdlID0gdGV4dDtcbiAgICBpZiAodGhpcy5pbmNsdWRlTm90ZUNoZWNrYm94LmNoZWNrZWQpIHtcbiAgICAgIGNvbnN0IG5vdGUgPSBhd2FpdCBnZXRBY3RpdmVOb3RlQ29udGV4dCh0aGlzLmFwcCk7XG4gICAgICBpZiAobm90ZSkge1xuICAgICAgICBtZXNzYWdlID0gYENvbnRleHQ6IFtbJHtub3RlLnRpdGxlfV1dXFxuXFxuJHt0ZXh0fWA7XG4gICAgICB9XG4gICAgfVxuXG4gICAgLy8gQWRkIHVzZXIgbWVzc2FnZSB0byBjaGF0IFVJXG4gICAgY29uc3QgdXNlck1zZyA9IENoYXRNYW5hZ2VyLmNyZWF0ZVVzZXJNZXNzYWdlKHRleHQpO1xuICAgIHRoaXMuY2hhdE1hbmFnZXIuYWRkTWVzc2FnZSh1c2VyTXNnKTtcblxuICAgIC8vIENsZWFyIGlucHV0XG4gICAgdGhpcy5pbnB1dEVsLnZhbHVlID0gJyc7XG4gICAgdGhpcy5pbnB1dEVsLnN0eWxlLmhlaWdodCA9ICdhdXRvJztcblxuICAgIC8vIFNlbmQgb3ZlciBXUyAoYXN5bmMpXG4gICAgdHJ5IHtcbiAgICAgIGF3YWl0IHRoaXMucGx1Z2luLndzQ2xpZW50LnNlbmRNZXNzYWdlKG1lc3NhZ2UpO1xuICAgIH0gY2F0Y2ggKGVycikge1xuICAgICAgY29uc29sZS5lcnJvcignW29jbGF3XSBTZW5kIGZhaWxlZCcsIGVycik7XG4gICAgICBuZXcgTm90aWNlKGBPcGVuQ2xhdyBDaGF0OiBzZW5kIGZhaWxlZCAoJHtTdHJpbmcoZXJyKX0pYCk7XG4gICAgICB0aGlzLmNoYXRNYW5hZ2VyLmFkZE1lc3NhZ2UoXG4gICAgICAgIENoYXRNYW5hZ2VyLmNyZWF0ZVN5c3RlbU1lc3NhZ2UoYFx1MjZBMCBTZW5kIGZhaWxlZDogJHtlcnJ9YCwgJ2Vycm9yJylcbiAgICAgICk7XG4gICAgfVxuICB9XG59XG4iLCAiaW1wb3J0IHR5cGUgeyBQYXRoTWFwcGluZyB9IGZyb20gJy4vdHlwZXMnO1xuXG5leHBvcnQgZnVuY3Rpb24gbm9ybWFsaXplQmFzZShiYXNlOiBzdHJpbmcpOiBzdHJpbmcge1xuICBjb25zdCB0cmltbWVkID0gU3RyaW5nKGJhc2UgPz8gJycpLnRyaW0oKTtcbiAgaWYgKCF0cmltbWVkKSByZXR1cm4gJyc7XG4gIHJldHVybiB0cmltbWVkLmVuZHNXaXRoKCcvJykgPyB0cmltbWVkIDogYCR7dHJpbW1lZH0vYDtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIHRyeU1hcFJlbW90ZVBhdGhUb1ZhdWx0UGF0aChpbnB1dDogc3RyaW5nLCBtYXBwaW5nczogcmVhZG9ubHkgUGF0aE1hcHBpbmdbXSk6IHN0cmluZyB8IG51bGwge1xuICBjb25zdCByYXcgPSBTdHJpbmcoaW5wdXQgPz8gJycpO1xuICBmb3IgKGNvbnN0IHJvdyBvZiBtYXBwaW5ncykge1xuICAgIGNvbnN0IHJlbW90ZUJhc2UgPSBub3JtYWxpemVCYXNlKHJvdy5yZW1vdGVCYXNlKTtcbiAgICBjb25zdCB2YXVsdEJhc2UgPSBub3JtYWxpemVCYXNlKHJvdy52YXVsdEJhc2UpO1xuICAgIGlmICghcmVtb3RlQmFzZSB8fCAhdmF1bHRCYXNlKSBjb250aW51ZTtcblxuICAgIGlmIChyYXcuc3RhcnRzV2l0aChyZW1vdGVCYXNlKSkge1xuICAgICAgY29uc3QgcmVzdCA9IHJhdy5zbGljZShyZW1vdGVCYXNlLmxlbmd0aCk7XG4gICAgICAvLyBPYnNpZGlhbiBwYXRocyBhcmUgdmF1bHQtcmVsYXRpdmUgYW5kIHNob3VsZCBub3Qgc3RhcnQgd2l0aCAnLydcbiAgICAgIHJldHVybiBgJHt2YXVsdEJhc2V9JHtyZXN0fWAucmVwbGFjZSgvXlxcLysvLCAnJyk7XG4gICAgfVxuICB9XG4gIHJldHVybiBudWxsO1xufVxuXG5leHBvcnQgdHlwZSBDYW5kaWRhdGUgPSB7IHN0YXJ0OiBudW1iZXI7IGVuZDogbnVtYmVyOyByYXc6IHN0cmluZzsga2luZDogJ3VybCcgfCAncGF0aCcgfTtcblxuLy8gQ29uc2VydmF0aXZlIGV4dHJhY3Rpb246IGFpbSB0byBhdm9pZCBmYWxzZSBwb3NpdGl2ZXMuXG5jb25zdCBVUkxfUkUgPSAvaHR0cHM/OlxcL1xcL1teXFxzPD4oKV0rL2c7XG4vLyBBYnNvbHV0ZSB1bml4LWlzaCBwYXRocy5cbi8vIChXZSBzdGlsbCBleGlzdGVuY2UtY2hlY2sgYmVmb3JlIHByb2R1Y2luZyBhIGxpbmsuKVxuY29uc3QgUEFUSF9SRSA9IC8oPzwhW0EtWmEtejAtOS5fLV0pKD86XFwvW0EtWmEtejAtOS5ffiEkJicoKSorLDs9OkAlXFwtXSspKyg/OlxcLltBLVphLXowLTkuXy1dKyk/L2c7XG5cbi8vIENvbnNlcnZhdGl2ZSByZWxhdGl2ZSBwYXRocyB3aXRoIGF0IGxlYXN0IG9uZSAnLycsIGUuZy4gY29tcGVuZy9wbGFucy94Lm1kXG4vLyBBdm9pZHMgbWF0Y2hpbmcgc2NoZW1lLWxpa2UgdG9rZW5zIHZpYSBuZWdhdGl2ZSBsb29rYWhlYWQgZm9yICc6Ly8nLlxuY29uc3QgUkVMX1BBVEhfUkUgPSAvXFxiKD8hW0EtWmEtel1bQS1aYS16MC05Ky4tXSo6XFwvXFwvKVtBLVphLXowLTkuXy1dKyg/OlxcL1tBLVphLXowLTkuXy1dKykrKD86XFwuW0EtWmEtejAtOS5fLV0rKT9cXGIvZztcblxuZXhwb3J0IGZ1bmN0aW9uIGV4dHJhY3RDYW5kaWRhdGVzKHRleHQ6IHN0cmluZyk6IENhbmRpZGF0ZVtdIHtcbiAgY29uc3QgdCA9IFN0cmluZyh0ZXh0ID8/ICcnKTtcbiAgY29uc3Qgb3V0OiBDYW5kaWRhdGVbXSA9IFtdO1xuXG4gIGZvciAoY29uc3QgbSBvZiB0Lm1hdGNoQWxsKFVSTF9SRSkpIHtcbiAgICBpZiAobS5pbmRleCA9PT0gdW5kZWZpbmVkKSBjb250aW51ZTtcbiAgICBvdXQucHVzaCh7IHN0YXJ0OiBtLmluZGV4LCBlbmQ6IG0uaW5kZXggKyBtWzBdLmxlbmd0aCwgcmF3OiBtWzBdLCBraW5kOiAndXJsJyB9KTtcbiAgfVxuXG4gIGZvciAoY29uc3QgbSBvZiB0Lm1hdGNoQWxsKFBBVEhfUkUpKSB7XG4gICAgaWYgKG0uaW5kZXggPT09IHVuZGVmaW5lZCkgY29udGludWU7XG5cbiAgICAvLyBTa2lwIGlmIHRoaXMgaXMgaW5zaWRlIGEgVVJMIHdlIGFscmVhZHkgY2FwdHVyZWQuXG4gICAgY29uc3Qgc3RhcnQgPSBtLmluZGV4O1xuICAgIGNvbnN0IGVuZCA9IHN0YXJ0ICsgbVswXS5sZW5ndGg7XG4gICAgY29uc3Qgb3ZlcmxhcHNVcmwgPSBvdXQuc29tZSgoYykgPT4gYy5raW5kID09PSAndXJsJyAmJiAhKGVuZCA8PSBjLnN0YXJ0IHx8IHN0YXJ0ID49IGMuZW5kKSk7XG4gICAgaWYgKG92ZXJsYXBzVXJsKSBjb250aW51ZTtcblxuICAgIG91dC5wdXNoKHsgc3RhcnQsIGVuZCwgcmF3OiBtWzBdLCBraW5kOiAncGF0aCcgfSk7XG4gIH1cblxuICBmb3IgKGNvbnN0IG0gb2YgdC5tYXRjaEFsbChSRUxfUEFUSF9SRSkpIHtcbiAgICBpZiAobS5pbmRleCA9PT0gdW5kZWZpbmVkKSBjb250aW51ZTtcblxuICAgIGNvbnN0IHN0YXJ0ID0gbS5pbmRleDtcbiAgICBjb25zdCBlbmQgPSBzdGFydCArIG1bMF0ubGVuZ3RoO1xuICAgIGNvbnN0IG92ZXJsYXBzRXhpc3RpbmcgPSBvdXQuc29tZSgoYykgPT4gIShlbmQgPD0gYy5zdGFydCB8fCBzdGFydCA+PSBjLmVuZCkpO1xuICAgIGlmIChvdmVybGFwc0V4aXN0aW5nKSBjb250aW51ZTtcblxuICAgIG91dC5wdXNoKHsgc3RhcnQsIGVuZCwgcmF3OiBtWzBdLCBraW5kOiAncGF0aCcgfSk7XG4gIH1cblxuICAvLyBTb3J0IGFuZCBkcm9wIG92ZXJsYXBzIChwcmVmZXIgVVJMcykuXG4gIG91dC5zb3J0KChhLCBiKSA9PiBhLnN0YXJ0IC0gYi5zdGFydCB8fCAoYS5raW5kID09PSAndXJsJyA/IC0xIDogMSkpO1xuICBjb25zdCBkZWR1cDogQ2FuZGlkYXRlW10gPSBbXTtcbiAgZm9yIChjb25zdCBjIG9mIG91dCkge1xuICAgIGNvbnN0IGxhc3QgPSBkZWR1cFtkZWR1cC5sZW5ndGggLSAxXTtcbiAgICBpZiAoIWxhc3QpIHtcbiAgICAgIGRlZHVwLnB1c2goYyk7XG4gICAgICBjb250aW51ZTtcbiAgICB9XG4gICAgaWYgKGMuc3RhcnQgPCBsYXN0LmVuZCkgY29udGludWU7XG4gICAgZGVkdXAucHVzaChjKTtcbiAgfVxuXG4gIHJldHVybiBkZWR1cDtcbn1cbiIsICJpbXBvcnQgdHlwZSB7IEFwcCB9IGZyb20gJ29ic2lkaWFuJztcblxuZXhwb3J0IGludGVyZmFjZSBOb3RlQ29udGV4dCB7XG4gIHRpdGxlOiBzdHJpbmc7XG4gIHBhdGg6IHN0cmluZztcbiAgY29udGVudDogc3RyaW5nO1xufVxuXG4vKipcbiAqIFJldHVybnMgdGhlIGFjdGl2ZSBub3RlJ3MgdGl0bGUgYW5kIGNvbnRlbnQsIG9yIG51bGwgaWYgbm8gbm90ZSBpcyBvcGVuLlxuICogQXN5bmMgYmVjYXVzZSB2YXVsdC5yZWFkKCkgaXMgYXN5bmMuXG4gKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBnZXRBY3RpdmVOb3RlQ29udGV4dChhcHA6IEFwcCk6IFByb21pc2U8Tm90ZUNvbnRleHQgfCBudWxsPiB7XG4gIGNvbnN0IGZpbGUgPSBhcHAud29ya3NwYWNlLmdldEFjdGl2ZUZpbGUoKTtcbiAgaWYgKCFmaWxlKSByZXR1cm4gbnVsbDtcblxuICB0cnkge1xuICAgIGNvbnN0IGNvbnRlbnQgPSBhd2FpdCBhcHAudmF1bHQucmVhZChmaWxlKTtcbiAgICByZXR1cm4ge1xuICAgICAgdGl0bGU6IGZpbGUuYmFzZW5hbWUsXG4gICAgICBwYXRoOiBmaWxlLnBhdGgsXG4gICAgICBjb250ZW50LFxuICAgIH07XG4gIH0gY2F0Y2ggKGVycikge1xuICAgIGNvbnNvbGUuZXJyb3IoJ1tvY2xhdy1jb250ZXh0XSBGYWlsZWQgdG8gcmVhZCBhY3RpdmUgbm90ZScsIGVycik7XG4gICAgcmV0dXJuIG51bGw7XG4gIH1cbn1cbiIsICIvKiogUGVyc2lzdGVkIHBsdWdpbiBjb25maWd1cmF0aW9uICovXG5leHBvcnQgaW50ZXJmYWNlIE9wZW5DbGF3U2V0dGluZ3Mge1xuICAvKiogV2ViU29ja2V0IFVSTCBvZiB0aGUgT3BlbkNsYXcgR2F0ZXdheSAoZS5nLiB3czovLzEwMC45MC45LjY4OjE4Nzg5KSAqL1xuICBnYXRld2F5VXJsOiBzdHJpbmc7XG4gIC8qKiBBdXRoIHRva2VuIFx1MjAxNCBtdXN0IG1hdGNoIHRoZSBjaGFubmVsIHBsdWdpbidzIGF1dGhUb2tlbiAqL1xuICBhdXRoVG9rZW46IHN0cmluZztcbiAgLyoqIE9wZW5DbGF3IHNlc3Npb24ga2V5IHRvIHN1YnNjcmliZSB0byAoZS5nLiBcIm1haW5cIikgKi9cbiAgc2Vzc2lvbktleTogc3RyaW5nO1xuICAvKiogKERlcHJlY2F0ZWQpIE9wZW5DbGF3IGFjY291bnQgSUQgKHVudXNlZDsgY2hhdC5zZW5kIHVzZXMgc2Vzc2lvbktleSkgKi9cbiAgYWNjb3VudElkOiBzdHJpbmc7XG4gIC8qKiBXaGV0aGVyIHRvIGluY2x1ZGUgdGhlIGFjdGl2ZSBub3RlIGNvbnRlbnQgd2l0aCBlYWNoIG1lc3NhZ2UgKi9cbiAgaW5jbHVkZUFjdGl2ZU5vdGU6IGJvb2xlYW47XG4gIC8qKiBSZW5kZXIgYXNzaXN0YW50IG91dHB1dCBhcyBNYXJrZG93biAodW5zYWZlOiBtYXkgdHJpZ2dlciBlbWJlZHMvcG9zdC1wcm9jZXNzb3JzKTsgZGVmYXVsdCBPRkYgKi9cbiAgcmVuZGVyQXNzaXN0YW50TWFya2Rvd246IGJvb2xlYW47XG4gIC8qKiBBbGxvdyB1c2luZyBpbnNlY3VyZSB3czovLyBmb3Igbm9uLWxvY2FsIGdhdGV3YXkgVVJMcyAodW5zYWZlKTsgZGVmYXVsdCBPRkYgKi9cbiAgYWxsb3dJbnNlY3VyZVdzOiBib29sZWFuO1xuXG4gIC8qKiBPcHRpb25hbDogbWFwIHJlbW90ZSBGUyBwYXRocyAvIGV4cG9ydGVkIHBhdGhzIGJhY2sgdG8gdmF1bHQtcmVsYXRpdmUgcGF0aHMgKi9cbiAgcGF0aE1hcHBpbmdzOiBQYXRoTWFwcGluZ1tdO1xufVxuXG5leHBvcnQgdHlwZSBQYXRoTWFwcGluZyA9IHtcbiAgLyoqIFZhdWx0LXJlbGF0aXZlIGJhc2UgcGF0aCAoZS5nLiBcImRvY3MvXCIgb3IgXCJjb21wZW5nL1wiKSAqL1xuICB2YXVsdEJhc2U6IHN0cmluZztcbiAgLyoqIFJlbW90ZSBGUyBiYXNlIHBhdGggKGUuZy4gXCIvaG9tZS93YWxsLWUvLm9wZW5jbGF3L3dvcmtzcGFjZS9kb2NzL1wiKSAqL1xuICByZW1vdGVCYXNlOiBzdHJpbmc7XG59O1xuXG5leHBvcnQgY29uc3QgREVGQVVMVF9TRVRUSU5HUzogT3BlbkNsYXdTZXR0aW5ncyA9IHtcbiAgZ2F0ZXdheVVybDogJ3dzOi8vbG9jYWxob3N0OjE4Nzg5JyxcbiAgYXV0aFRva2VuOiAnJyxcbiAgc2Vzc2lvbktleTogJ21haW4nLFxuICBhY2NvdW50SWQ6ICdtYWluJyxcbiAgaW5jbHVkZUFjdGl2ZU5vdGU6IGZhbHNlLFxuICByZW5kZXJBc3Npc3RhbnRNYXJrZG93bjogZmFsc2UsXG4gIGFsbG93SW5zZWN1cmVXczogZmFsc2UsXG4gIHBhdGhNYXBwaW5nczogW10sXG59O1xuXG4vKiogQSBzaW5nbGUgY2hhdCBtZXNzYWdlICovXG5leHBvcnQgaW50ZXJmYWNlIENoYXRNZXNzYWdlIHtcbiAgaWQ6IHN0cmluZztcbiAgcm9sZTogJ3VzZXInIHwgJ2Fzc2lzdGFudCcgfCAnc3lzdGVtJztcbiAgLyoqIE9wdGlvbmFsIHNldmVyaXR5IGZvciBzeXN0ZW0vc3RhdHVzIG1lc3NhZ2VzICovXG4gIGxldmVsPzogJ2luZm8nIHwgJ2Vycm9yJztcbiAgLyoqIE9wdGlvbmFsIHN1YnR5cGUgZm9yIHN0eWxpbmcgc3BlY2lhbCBzeXN0ZW0gbWVzc2FnZXMgKGUuZy4gc2Vzc2lvbiBkaXZpZGVyKS4gKi9cbiAga2luZD86ICdzZXNzaW9uLWRpdmlkZXInO1xuICAvKiogT3B0aW9uYWwgaG92ZXIgdG9vbHRpcCBmb3IgdGhlIG1lc3NhZ2UgKGUuZy4gZnVsbCBzZXNzaW9uIGtleSkuICovXG4gIHRpdGxlPzogc3RyaW5nO1xuICBjb250ZW50OiBzdHJpbmc7XG4gIHRpbWVzdGFtcDogbnVtYmVyO1xufVxuXG4vKiogR2F0ZXdheSBzZXNzaW9ucy5saXN0IHR5cGVzIChtaW5pbWFsIHN1YnNldCB3ZSB1c2UgaW4gVUkpLiAqL1xuZXhwb3J0IHR5cGUgR2F0ZXdheVNlc3Npb25Sb3cgPSB7XG4gIGtleTogc3RyaW5nO1xuICBraW5kPzogc3RyaW5nO1xuICBsYWJlbD86IHN0cmluZztcbiAgZGlzcGxheU5hbWU/OiBzdHJpbmc7XG4gIGRlcml2ZWRUaXRsZT86IHN0cmluZztcbiAgbGFzdE1lc3NhZ2VQcmV2aWV3Pzogc3RyaW5nO1xuICBjaGFubmVsPzogc3RyaW5nO1xuICB1cGRhdGVkQXQ/OiBudW1iZXIgfCBudWxsO1xuICBsYXN0QWNjb3VudElkPzogc3RyaW5nO1xufTtcblxuZXhwb3J0IHR5cGUgU2Vzc2lvbnNMaXN0UmVzdWx0ID0ge1xuICB0czogbnVtYmVyO1xuICBwYXRoOiBzdHJpbmc7XG4gIGNvdW50OiBudW1iZXI7XG4gIHNlc3Npb25zOiBHYXRld2F5U2Vzc2lvblJvd1tdO1xufTtcblxuLyoqIFBheWxvYWQgZm9yIG1lc3NhZ2VzIFNFTlQgdG8gdGhlIHNlcnZlciAob3V0Ym91bmQpICovXG5leHBvcnQgaW50ZXJmYWNlIFdTUGF5bG9hZCB7XG4gIHR5cGU6ICdhdXRoJyB8ICdtZXNzYWdlJyB8ICdwaW5nJyB8ICdwb25nJyB8ICdlcnJvcic7XG4gIHBheWxvYWQ/OiBSZWNvcmQ8c3RyaW5nLCB1bmtub3duPjtcbn1cblxuLyoqIE1lc3NhZ2VzIFJFQ0VJVkVEIGZyb20gdGhlIHNlcnZlciAoaW5ib3VuZCkgXHUyMDE0IGRpc2NyaW1pbmF0ZWQgdW5pb24gKi9cbmV4cG9ydCB0eXBlIEluYm91bmRXU1BheWxvYWQgPVxuICB8IHsgdHlwZTogJ21lc3NhZ2UnOyBwYXlsb2FkOiB7IGNvbnRlbnQ6IHN0cmluZzsgcm9sZTogc3RyaW5nOyB0aW1lc3RhbXA6IG51bWJlciB9IH1cbiAgfCB7IHR5cGU6ICdlcnJvcic7IHBheWxvYWQ6IHsgbWVzc2FnZTogc3RyaW5nIH0gfTtcblxuLyoqIEF2YWlsYWJsZSBhZ2VudHMgLyBtb2RlbHMgKi9cbmV4cG9ydCBpbnRlcmZhY2UgQWdlbnRPcHRpb24ge1xuICBpZDogc3RyaW5nO1xuICBsYWJlbDogc3RyaW5nO1xufVxuIl0sCiAgIm1hcHBpbmdzIjogIjs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBLElBQUFBLG1CQUE4Qzs7O0FDQTlDLHNCQUErQztBQUd4QyxJQUFNLHFCQUFOLGNBQWlDLGlDQUFpQjtBQUFBLEVBR3ZELFlBQVksS0FBVSxRQUF3QjtB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VyxPQUFPLE9BQU8sQ0FBQyxHQUFHLGtCQUFrQixJQUFJO0FBQUEsSUFDMUQ7QUFBQTtBQUFBLEVBRU0sZUFBOEI7QUFBQTtBQTVHdEM7QUE4R0ksWUFBTSxRQUFRLFdBQU0sS0FBSyxTQUFTLE1BQXBCLFlBQTBCLENBQUM7QUFDekMsWUFBTSxLQUFLLFNBQVMsa0NBQUssT0FBUyxLQUFLLFNBQVU7QUFBQSxJQUNuRDtBQUFBO0FBQUE7QUFBQSxFQUlNLHNCQUFxQztBQUFBO0FBQ3pDLFlBQU0sS0FBSyxxQkFBcUI7QUFDaEMsVUFBSSx3QkFBTyxnRUFBZ0U7QUFBQSxJQUM3RTtBQUFBO0FBQUEsRUFJYyxzQkFBMkM7QUFBQTtBQTNIM0Q7QUE0SEksWUFBTSxRQUFRLFdBQU0sS0FBSyxTQUFTLE1BQXBCLFlBQTBCLENBQUM7QUFDekMsY0FBUSxrQ0FBZSxLQUFLLHdCQUFwQixZQUEyQztBQUFBLElBQ3JEO0FBQUE7QUFBQSxFQUVjLG9CQUFvQixVQUE4QjtBQUFBO0FBaElsRTtBQWlJSSxZQUFNLFFBQVEsV0FBTSxLQUFLLFNBQVMsTUFBcEIsWUFBMEIsQ0FBQztBQUN6QyxZQUFNLEtBQUssU0FBUyxpQ0FBSyxPQUFMLEVBQVcsQ0FBQyxLQUFLLGtCQUFrQixHQUFHLFNBQVMsRUFBQztBQUFBLElBQ3RFO0FBQUE7QUFBQSxFQUVjLHVCQUFzQztBQUFBO0FBckl0RDtBQXNJSSxZQUFNLFFBQVEsV0FBTSxLQUFLLFNBQVMsTUFBcEIsWUFBMEIsQ0FBQztBQUN6QyxXQUFLLDZCQUFlLEtBQUsseUJBQXdCO0FBQVc7QUFDNUQsWUFBTSxPQUFPLG1CQUFNO0FBQ25CLGFBQU8sS0FBSyxLQUFLLGtCQUFrQjtBQUNuQyxZQUFNLEtBQUssU0FBUyxJQUFJO0FBQUEsSUFDMUI7QUFBQTtBQUFBO0FBQUEsRUFJUSxhQUFtQjtBQUN6QixTQUFLLFNBQVMsUUFBUSxLQUFLLFNBQVMsWUFBWSxLQUFLLFNBQVMsV0FBVztBQUFBLE1BQ3ZFLGlCQUFpQixLQUFLLFNBQVM7QUFBQSxJQUNqQyxDQUFDO0FBQUEsRUFDSDtBQUFBLEVBRWMsb0JBQW1DO0FBQUE7QUFDL0MsWUFBTSxFQUFFLFVBQVUsSUFBSSxLQUFLO0FBRzNCLFlBQU0sV0FBVyxVQUFVLGdCQUFnQix1QkFBdUI7QUFDbEUsVUFBSSxTQUFTLFNBQVMsR0FBRztBQUN2QixrQkFBVSxXQUFXLFNBQVMsQ0FBQyxDQUFDO0FBQ2hDO0FBQUEsTUFDRjtBQUdBLFlBQU0sT0FBTyxVQUFVLGFBQWEsS0FBSztBQUN6QyxVQUFJLENBQUM7QUFBTTtBQUNYLFlBQU0sS0FBSyxhQUFhLEVBQUUsTUFBTSx5QkFBeUIsUUFBUSxLQUFLLENBQUM7QUFDdkUsZ0JBQVUsV0FBVyxJQUFJO0FBQUEsSUFDM0I7QUFBQTtBQUNGOyIsCiAgIm5hbWVzIjogWyJpbXBvcnRfb2JzaWRpYW4iLCAiX2EiLCAiaW1wb3J0X29ic2lkaWFuIiwgIm1hcHBlZCJdCn0K
