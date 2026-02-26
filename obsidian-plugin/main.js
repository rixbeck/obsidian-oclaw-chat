"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
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
    containerEl.createEl("p", {
      text: "Reconnect: close and reopen the sidebar after changing the gateway URL or token.",
      cls: "setting-item-description"
    });
  }
};

// src/websocket.ts
var RECONNECT_DELAY_MS = 3e3;
var HEARTBEAT_INTERVAL_MS = 3e4;
var WORKING_MAX_MS = 12e4;
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
function loadOrCreateDeviceIdentity() {
  return __async(this, null, function* () {
    const existing = localStorage.getItem(DEVICE_STORAGE_KEY);
    if (existing) {
      const parsed = JSON.parse(existing);
      if ((parsed == null ? void 0 : parsed.id) && (parsed == null ? void 0 : parsed.publicKey) && (parsed == null ? void 0 : parsed.privateKeyJwk))
        return parsed;
    }
    const keyPair = yield crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    const pubRaw = yield crypto.subtle.exportKey("raw", keyPair.publicKey);
    const privJwk = yield crypto.subtle.exportKey("jwk", keyPair.privateKey);
    const deviceId = yield sha256Hex(pubRaw);
    const id = deviceId;
    const identity = {
      id,
      publicKey: base64UrlEncode(pubRaw),
      privateKeyJwk: privJwk
    };
    localStorage.setItem(DEVICE_STORAGE_KEY, JSON.stringify(identity));
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
    const signedAt = Date.now();
    const sig = yield crypto.subtle.sign({ name: "Ed25519" }, privateKey, utf8Bytes(payload));
    return { signature: base64UrlEncode(sig), signedAt };
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
  constructor(sessionKey) {
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
    this.sessionKey = sessionKey;
  }
  connect(url, token) {
    this.url = url;
    this.token = token;
    this.intentionalClose = false;
    this._connect();
  }
  disconnect() {
    this.intentionalClose = true;
    this._stopTimers();
    this.activeRunId = null;
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
      yield this._sendRequest("chat.send", {
        sessionKey: this.sessionKey,
        message,
        idempotencyKey: runId
        // deliver defaults to true in gateway; keep default
      });
      this.activeRunId = runId;
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
      this.abortInFlight = (() => __async(this, null, function* () {
        try {
          yield this._sendRequest("chat.abort", runId ? { sessionKey: this.sessionKey, runId } : { sessionKey: this.sessionKey });
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
        const identity = yield loadOrCreateDeviceIdentity();
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
        yield this._sendRequest("connect", {
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
        this._startHeartbeat();
      } catch (err) {
        console.error("[oclaw-ws] Connect handshake failed", err);
        ws.close();
      }
    });
    ws.onopen = () => {
      this._setState("handshaking");
    };
    ws.onmessage = (event) => {
      var _a;
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
    if ((payload == null ? void 0 : payload.state) && payload.state !== "final" && payload.state !== "aborted") {
      return;
    }
    const msg = payload == null ? void 0 : payload.message;
    const role = (_b = msg == null ? void 0 : msg.role) != null ? _b : "assistant";
    this.activeRunId = null;
    this._setWorking(false);
    if ((payload == null ? void 0 : payload.state) === "aborted") {
      if (!msg)
        return;
    }
    if (role !== "assistant") {
      return;
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
      const id = `req-${++this.requestId}`;
      const pending = { resolve, reject, timeout: null };
      this.pendingRequests.set(id, pending);
      this.ws.send(
        JSON.stringify({
          type: "req",
          method,
          id,
          params
        })
      );
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
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      if (!this.intentionalClose) {
        console.log(`[oclaw-ws] Reconnecting to ${this.url}\u2026`);
        this._connect();
      }
    }, RECONNECT_DELAY_MS);
  }
  _startHeartbeat() {
    this._stopHeartbeat();
    this.heartbeatTimer = setInterval(() => {
      var _a;
      if (((_a = this.ws) == null ? void 0 : _a.readyState) !== WebSocket.OPEN)
        return;
      if (this.ws.bufferedAmount > 0) {
        console.warn("[oclaw-ws] Send buffer not empty \u2014 connection may be stalled");
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
    if (msg.role === "assistant") {
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
  includeActiveNote: false
};

// src/main.ts
var OpenClawPlugin = class extends import_obsidian3.Plugin {
  onload() {
    return __async(this, null, function* () {
      yield this.loadSettings();
      this.wsClient = new ObsidianWSClient(this.settings.sessionKey);
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
      this.settings = Object.assign({}, DEFAULT_SETTINGS, yield this.loadData());
    });
  }
  saveSettings() {
    return __async(this, null, function* () {
      yield this.saveData(this.settings);
    });
  }
  // ── Helpers ───────────────────────────────────────────────────────────────
  _connectWS() {
    this.wsClient.connect(
      this.settings.gatewayUrl,
      this.settings.authToken
    );
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
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsic3JjL21haW4udHMiLCAic3JjL3NldHRpbmdzLnRzIiwgInNyYy93ZWJzb2NrZXQudHMiLCAic3JjL2NoYXQudHMiLCAic3JjL3ZpZXcudHMiLCAic3JjL2NvbnRleHQudHMiLCAic3JjL3R5cGVzLnRzIl0sCiAgInNvdXJjZXNDb250ZW50IjogWyJpbXBvcnQgeyBOb3RpY2UsIFBsdWdpbiwgV29ya3NwYWNlTGVhZiB9IGZyb20gJ29ic2lkaWFuJztcbmltcG9ydCB7IE9wZW5DbGF3U2V0dGluZ1RhYiB9IGZyb20gJy4vc2V0dGluZ3MnO1xuaW1wb3J0IHsgT2JzaWRpYW5XU0NsaWVudCB9IGZyb20gJy4vd2Vic29ja2V0JztcbmltcG9ydCB7IENoYXRNYW5hZ2VyIH0gZnJvbSAnLi9jaGF0JztcbmltcG9ydCB7IFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFULCBPcGVuQ2xhd0NoYXRWaWV3IH0gZnJvbSAnLi92aWV3JztcbmltcG9ydCB7IERFRkFVTFRfU0VUVElOR1MsIHR5cGUgT3BlbkNsYXdTZXR0aW5ncyB9IGZyb20gJy4vdHlwZXMnO1xuXG5leHBvcnQgZGVmYXVsdCBjbGFzcyBPcGVuQ2xhd1BsdWdpbiBleHRlbmRzIFBsdWdpbiB7XG4gIHNldHRpbmdzITogT3BlbkNsYXdTZXR0aW5ncztcbiAgd3NDbGllbnQhOiBPYnNpZGlhbldTQ2xpZW50O1xuICBjaGF0TWFuYWdlciE6IENoYXRNYW5hZ2VyO1xuXG4gIGFzeW5jIG9ubG9hZCgpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBhd2FpdCB0aGlzLmxvYWRTZXR0aW5ncygpO1xuXG4gICAgdGhpcy53c0NsaWVudCA9IG5ldyBPYnNpZGlhbldTQ2xpZW50KHRoaXMuc2V0dGluZ3Muc2Vzc2lvbktleSk7XG4gICAgdGhpcy5jaGF0TWFuYWdlciA9IG5ldyBDaGF0TWFuYWdlcigpO1xuXG4gICAgLy8gV2lyZSBpbmNvbWluZyBXUyBtZXNzYWdlcyBcdTIxOTIgQ2hhdE1hbmFnZXJcbiAgICB0aGlzLndzQ2xpZW50Lm9uTWVzc2FnZSA9IChtc2cpID0+IHtcbiAgICAgIGlmIChtc2cudHlwZSA9PT0gJ21lc3NhZ2UnKSB7XG4gICAgICAgIHRoaXMuY2hhdE1hbmFnZXIuYWRkTWVzc2FnZShDaGF0TWFuYWdlci5jcmVhdGVBc3Npc3RhbnRNZXNzYWdlKG1zZy5wYXlsb2FkLmNvbnRlbnQpKTtcbiAgICAgIH0gZWxzZSBpZiAobXNnLnR5cGUgPT09ICdlcnJvcicpIHtcbiAgICAgICAgY29uc3QgZXJyVGV4dCA9IG1zZy5wYXlsb2FkLm1lc3NhZ2UgPz8gJ1Vua25vd24gZXJyb3IgZnJvbSBnYXRld2F5JztcbiAgICAgICAgdGhpcy5jaGF0TWFuYWdlci5hZGRNZXNzYWdlKENoYXRNYW5hZ2VyLmNyZWF0ZVN5c3RlbU1lc3NhZ2UoYFx1MjZBMCAke2VyclRleHR9YCwgJ2Vycm9yJykpO1xuICAgICAgfVxuICAgIH07XG5cbiAgICAvLyBSZWdpc3RlciB0aGUgc2lkZWJhciB2aWV3XG4gICAgdGhpcy5yZWdpc3RlclZpZXcoXG4gICAgICBWSUVXX1RZUEVfT1BFTkNMQVdfQ0hBVCxcbiAgICAgIChsZWFmOiBXb3Jrc3BhY2VMZWFmKSA9PiBuZXcgT3BlbkNsYXdDaGF0VmlldyhsZWFmLCB0aGlzKVxuICAgICk7XG5cbiAgICAvLyBSaWJib24gaWNvbiBcdTIwMTQgb3BlbnMgLyByZXZlYWxzIHRoZSBjaGF0IHNpZGViYXJcbiAgICB0aGlzLmFkZFJpYmJvbkljb24oJ21lc3NhZ2Utc3F1YXJlJywgJ09wZW5DbGF3IENoYXQnLCAoKSA9PiB7XG4gICAgICB0aGlzLl9hY3RpdmF0ZUNoYXRWaWV3KCk7XG4gICAgfSk7XG5cbiAgICAvLyBTZXR0aW5ncyB0YWJcbiAgICB0aGlzLmFkZFNldHRpbmdUYWIobmV3IE9wZW5DbGF3U2V0dGluZ1RhYih0aGlzLmFwcCwgdGhpcykpO1xuXG4gICAgLy8gQ29tbWFuZCBwYWxldHRlIGVudHJ5XG4gICAgdGhpcy5hZGRDb21tYW5kKHtcbiAgICAgIGlkOiAnb3Blbi1vcGVuY2xhdy1jaGF0JyxcbiAgICAgIG5hbWU6ICdPcGVuIGNoYXQgc2lkZWJhcicsXG4gICAgICBjYWxsYmFjazogKCkgPT4gdGhpcy5fYWN0aXZhdGVDaGF0VmlldygpLFxuICAgIH0pO1xuXG4gICAgLy8gQ29ubmVjdCB0byBnYXRld2F5IGlmIHRva2VuIGlzIGNvbmZpZ3VyZWRcbiAgICBpZiAodGhpcy5zZXR0aW5ncy5hdXRoVG9rZW4pIHtcbiAgICAgIHRoaXMuX2Nvbm5lY3RXUygpO1xuICAgIH0gZWxzZSB7XG4gICAgICBuZXcgTm90aWNlKCdPcGVuQ2xhdyBDaGF0OiBwbGVhc2UgY29uZmlndXJlIHlvdXIgZ2F0ZXdheSB0b2tlbiBpbiBTZXR0aW5ncy4nKTtcbiAgICB9XG5cbiAgICBjb25zb2xlLmxvZygnW29jbGF3XSBQbHVnaW4gbG9hZGVkJyk7XG4gIH1cblxuICBhc3luYyBvbnVubG9hZCgpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICB0aGlzLndzQ2xpZW50LmRpc2Nvbm5lY3QoKTtcbiAgICB0aGlzLmFwcC53b3Jrc3BhY2UuZGV0YWNoTGVhdmVzT2ZUeXBlKFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFUKTtcbiAgICBjb25zb2xlLmxvZygnW29jbGF3XSBQbHVnaW4gdW5sb2FkZWQnKTtcbiAgfVxuXG4gIGFzeW5jIGxvYWRTZXR0aW5ncygpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICB0aGlzLnNldHRpbmdzID0gT2JqZWN0LmFzc2lnbih7fSwgREVGQVVMVF9TRVRUSU5HUywgYXdhaXQgdGhpcy5sb2FkRGF0YSgpKTtcbiAgfVxuXG4gIGFzeW5jIHNhdmVTZXR0aW5ncygpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBhd2FpdCB0aGlzLnNhdmVEYXRhKHRoaXMuc2V0dGluZ3MpO1xuICB9XG5cbiAgLy8gXHUyNTAwXHUyNTAwIEhlbHBlcnMgXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG5cbiAgcHJpdmF0ZSBfY29ubmVjdFdTKCk6IHZvaWQge1xuICAgIHRoaXMud3NDbGllbnQuY29ubmVjdChcbiAgICAgIHRoaXMuc2V0dGluZ3MuZ2F0ZXdheVVybCxcbiAgICAgIHRoaXMuc2V0dGluZ3MuYXV0aFRva2VuXG4gICAgKTtcbiAgfVxuXG4gIHByaXZhdGUgYXN5bmMgX2FjdGl2YXRlQ2hhdFZpZXcoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgY29uc3QgeyB3b3Jrc3BhY2UgfSA9IHRoaXMuYXBwO1xuXG4gICAgLy8gUmV1c2UgZXhpc3RpbmcgbGVhZiBpZiBhbHJlYWR5IG9wZW5cbiAgICBjb25zdCBleGlzdGluZyA9IHdvcmtzcGFjZS5nZXRMZWF2ZXNPZlR5cGUoVklFV19UWVBFX09QRU5DTEFXX0NIQVQpO1xuICAgIGlmIChleGlzdGluZy5sZW5ndGggPiAwKSB7XG4gICAgICB3b3Jrc3BhY2UucmV2ZWFsTGVhZihleGlzdGluZ1swXSk7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgLy8gT3BlbiBpbiByaWdodCBzaWRlYmFyXG4gICAgY29uc3QgbGVhZiA9IHdvcmtzcGFjZS5nZXRSaWdodExlYWYoZmFsc2UpO1xuICAgIGlmICghbGVhZikgcmV0dXJuO1xuICAgIGF3YWl0IGxlYWYuc2V0Vmlld1N0YXRlKHsgdHlwZTogVklFV19UWVBFX09QRU5DTEFXX0NIQVQsIGFjdGl2ZTogdHJ1ZSB9KTtcbiAgICB3b3Jrc3BhY2UucmV2ZWFsTGVhZihsZWFmKTtcbiAgfVxufVxuIiwgImltcG9ydCB7IEFwcCwgUGx1Z2luU2V0dGluZ1RhYiwgU2V0dGluZyB9IGZyb20gJ29ic2lkaWFuJztcbmltcG9ydCB0eXBlIE9wZW5DbGF3UGx1Z2luIGZyb20gJy4vbWFpbic7XG5cbmV4cG9ydCBjbGFzcyBPcGVuQ2xhd1NldHRpbmdUYWIgZXh0ZW5kcyBQbHVnaW5TZXR0aW5nVGFiIHtcbiAgcGx1Z2luOiBPcGVuQ2xhd1BsdWdpbjtcblxuICBjb25zdHJ1Y3RvcihhcHA6IEFwcCwgcGx1Z2luOiBPcGVuQ2xhd1BsdWdpbikge1xuICAgIHN1cGVyKGFwcCwgcGx1Z2luKTtcbiAgICB0aGlzLnBsdWdpbiA9IHBsdWdpbjtcbiAgfVxuXG4gIGRpc3BsYXkoKTogdm9pZCB7XG4gICAgY29uc3QgeyBjb250YWluZXJFbCB9ID0gdGhpcztcbiAgICBjb250YWluZXJFbC5lbXB0eSgpO1xuXG4gICAgY29udGFpbmVyRWwuY3JlYXRlRWwoJ2gyJywgeyB0ZXh0OiAnT3BlbkNsYXcgQ2hhdCBcdTIwMTMgU2V0dGluZ3MnIH0pO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZSgnR2F0ZXdheSBVUkwnKVxuICAgICAgLnNldERlc2MoJ1dlYlNvY2tldCBVUkwgb2YgdGhlIE9wZW5DbGF3IEdhdGV3YXkgKGUuZy4gd3M6Ly9ob3N0bmFtZToxODc4OSkuJylcbiAgICAgIC5hZGRUZXh0KCh0ZXh0KSA9PlxuICAgICAgICB0ZXh0XG4gICAgICAgICAgLnNldFBsYWNlaG9sZGVyKCd3czovL2xvY2FsaG9zdDoxODc4OScpXG4gICAgICAgICAgLnNldFZhbHVlKHRoaXMucGx1Z2luLnNldHRpbmdzLmdhdGV3YXlVcmwpXG4gICAgICAgICAgLm9uQ2hhbmdlKGFzeW5jICh2YWx1ZSkgPT4ge1xuICAgICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3MuZ2F0ZXdheVVybCA9IHZhbHVlLnRyaW0oKTtcbiAgICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICAgIH0pXG4gICAgICApO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZSgnQXV0aCB0b2tlbicpXG4gICAgICAuc2V0RGVzYygnTXVzdCBtYXRjaCB0aGUgYXV0aFRva2VuIGluIHlvdXIgb3BlbmNsYXcuanNvbiBjaGFubmVsIGNvbmZpZy4gTmV2ZXIgc2hhcmVkLicpXG4gICAgICAuYWRkVGV4dCgodGV4dCkgPT4ge1xuICAgICAgICB0ZXh0XG4gICAgICAgICAgLnNldFBsYWNlaG9sZGVyKCdFbnRlciB0b2tlblx1MjAyNicpXG4gICAgICAgICAgLnNldFZhbHVlKHRoaXMucGx1Z2luLnNldHRpbmdzLmF1dGhUb2tlbilcbiAgICAgICAgICAub25DaGFuZ2UoYXN5bmMgKHZhbHVlKSA9PiB7XG4gICAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5hdXRoVG9rZW4gPSB2YWx1ZTtcbiAgICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICAgIH0pO1xuICAgICAgICAvLyBUcmVhdCBhcyBwYXNzd29yZCBmaWVsZCBcdTIwMTMgZG8gbm90IHJldmVhbCB0b2tlbiBpbiBVSVxuICAgICAgICB0ZXh0LmlucHV0RWwudHlwZSA9ICdwYXNzd29yZCc7XG4gICAgICAgIHRleHQuaW5wdXRFbC5hdXRvY29tcGxldGUgPSAnb2ZmJztcbiAgICAgIH0pO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZSgnU2Vzc2lvbiBLZXknKVxuICAgICAgLnNldERlc2MoJ09wZW5DbGF3IHNlc3Npb24gdG8gc3Vic2NyaWJlIHRvICh1c3VhbGx5IFwibWFpblwiKS4nKVxuICAgICAgLmFkZFRleHQoKHRleHQpID0+XG4gICAgICAgIHRleHRcbiAgICAgICAgICAuc2V0UGxhY2Vob2xkZXIoJ21haW4nKVxuICAgICAgICAgIC5zZXRWYWx1ZSh0aGlzLnBsdWdpbi5zZXR0aW5ncy5zZXNzaW9uS2V5KVxuICAgICAgICAgIC5vbkNoYW5nZShhc3luYyAodmFsdWUpID0+IHtcbiAgICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLnNlc3Npb25LZXkgPSB2YWx1ZS50cmltKCkgfHwgJ21haW4nO1xuICAgICAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uc2F2ZVNldHRpbmdzKCk7XG4gICAgICAgICAgfSlcbiAgICAgICk7XG5cbiAgICBuZXcgU2V0dGluZyhjb250YWluZXJFbClcbiAgICAgIC5zZXROYW1lKCdBY2NvdW50IElEJylcbiAgICAgIC5zZXREZXNjKCdPcGVuQ2xhdyBhY2NvdW50IElEICh1c3VhbGx5IFwibWFpblwiKS4nKVxuICAgICAgLmFkZFRleHQoKHRleHQpID0+XG4gICAgICAgIHRleHRcbiAgICAgICAgICAuc2V0UGxhY2Vob2xkZXIoJ21haW4nKVxuICAgICAgICAgIC5zZXRWYWx1ZSh0aGlzLnBsdWdpbi5zZXR0aW5ncy5hY2NvdW50SWQpXG4gICAgICAgICAgLm9uQ2hhbmdlKGFzeW5jICh2YWx1ZSkgPT4ge1xuICAgICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3MuYWNjb3VudElkID0gdmFsdWUudHJpbSgpIHx8ICdtYWluJztcbiAgICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICAgIH0pXG4gICAgICApO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZSgnSW5jbHVkZSBhY3RpdmUgbm90ZSBieSBkZWZhdWx0JylcbiAgICAgIC5zZXREZXNjKCdQcmUtY2hlY2sgXCJJbmNsdWRlIGFjdGl2ZSBub3RlXCIgaW4gdGhlIGNoYXQgcGFuZWwgd2hlbiBpdCBvcGVucy4nKVxuICAgICAgLmFkZFRvZ2dsZSgodG9nZ2xlKSA9PlxuICAgICAgICB0b2dnbGUuc2V0VmFsdWUodGhpcy5wbHVnaW4uc2V0dGluZ3MuaW5jbHVkZUFjdGl2ZU5vdGUpLm9uQ2hhbmdlKGFzeW5jICh2YWx1ZSkgPT4ge1xuICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLmluY2x1ZGVBY3RpdmVOb3RlID0gdmFsdWU7XG4gICAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uc2F2ZVNldHRpbmdzKCk7XG4gICAgICAgIH0pXG4gICAgICApO1xuXG4gICAgY29udGFpbmVyRWwuY3JlYXRlRWwoJ3AnLCB7XG4gICAgICB0ZXh0OiAnUmVjb25uZWN0OiBjbG9zZSBhbmQgcmVvcGVuIHRoZSBzaWRlYmFyIGFmdGVyIGNoYW5naW5nIHRoZSBnYXRld2F5IFVSTCBvciB0b2tlbi4nLFxuICAgICAgY2xzOiAnc2V0dGluZy1pdGVtLWRlc2NyaXB0aW9uJyxcbiAgICB9KTtcbiAgfVxufVxuIiwgIi8qKlxuICogV2ViU29ja2V0IGNsaWVudCBmb3IgT3BlbkNsYXcgR2F0ZXdheVxuICpcbiAqIFBpdm90ICgyMDI2LTAyLTI1KTogRG8gTk9UIHVzZSBjdXN0b20gb2JzaWRpYW4uKiBnYXRld2F5IG1ldGhvZHMuXG4gKiBUaG9zZSByZXF1aXJlIG9wZXJhdG9yLmFkbWluIHNjb3BlIHdoaWNoIGlzIG5vdCBncmFudGVkIHRvIGV4dGVybmFsIGNsaWVudHMuXG4gKlxuICogQXV0aCBub3RlOlxuICogLSBjaGF0LnNlbmQgcmVxdWlyZXMgb3BlcmF0b3Iud3JpdGVcbiAqIC0gZXh0ZXJuYWwgY2xpZW50cyBtdXN0IHByZXNlbnQgYSBwYWlyZWQgZGV2aWNlIGlkZW50aXR5IHRvIHJlY2VpdmUgd3JpdGUgc2NvcGVzXG4gKlxuICogV2UgdXNlIGJ1aWx0LWluIGdhdGV3YXkgbWV0aG9kcy9ldmVudHM6XG4gKiAtIFNlbmQ6IGNoYXQuc2VuZCh7IHNlc3Npb25LZXksIG1lc3NhZ2UsIGlkZW1wb3RlbmN5S2V5LCAuLi4gfSlcbiAqIC0gUmVjZWl2ZTogZXZlbnQgXCJjaGF0XCIgKGZpbHRlciBieSBzZXNzaW9uS2V5KVxuICovXG5cbmltcG9ydCB0eXBlIHsgSW5ib3VuZFdTUGF5bG9hZCB9IGZyb20gJy4vdHlwZXMnO1xuXG4vKiogTWlsbGlzZWNvbmRzIGJlZm9yZSBhIHJlY29ubmVjdCBhdHRlbXB0IGFmdGVyIGFuIHVuZXhwZWN0ZWQgY2xvc2UgKi9cbmNvbnN0IFJFQ09OTkVDVF9ERUxBWV9NUyA9IDNfMDAwO1xuLyoqIEludGVydmFsIGZvciBzZW5kaW5nIGhlYXJ0YmVhdCBwaW5ncyAoY2hlY2sgY29ubmVjdGlvbiBsaXZlbmVzcykgKi9cbmNvbnN0IEhFQVJUQkVBVF9JTlRFUlZBTF9NUyA9IDMwXzAwMDtcblxuLyoqIFNhZmV0eSB2YWx2ZTogaGlkZSB3b3JraW5nIHNwaW5uZXIgaWYgbm8gYXNzaXN0YW50IHJlcGx5IGFycml2ZXMgaW4gdGltZSAqL1xuY29uc3QgV09SS0lOR19NQVhfTVMgPSAxMjBfMDAwO1xuXG5leHBvcnQgdHlwZSBXU0NsaWVudFN0YXRlID0gJ2Rpc2Nvbm5lY3RlZCcgfCAnY29ubmVjdGluZycgfCAnaGFuZHNoYWtpbmcnIHwgJ2Nvbm5lY3RlZCc7XG5cbmV4cG9ydCB0eXBlIFdvcmtpbmdTdGF0ZUxpc3RlbmVyID0gKHdvcmtpbmc6IGJvb2xlYW4pID0+IHZvaWQ7XG5cbmludGVyZmFjZSBQZW5kaW5nUmVxdWVzdCB7XG4gIHJlc29sdmU6IChwYXlsb2FkOiBhbnkpID0+IHZvaWQ7XG4gIHJlamVjdDogKGVycm9yOiBhbnkpID0+IHZvaWQ7XG4gIHRpbWVvdXQ6IFJldHVyblR5cGU8dHlwZW9mIHNldFRpbWVvdXQ+IHwgbnVsbDtcbn1cblxudHlwZSBEZXZpY2VJZGVudGl0eSA9IHtcbiAgaWQ6IHN0cmluZztcbiAgcHVibGljS2V5OiBzdHJpbmc7IC8vIGJhc2U2NFxuICBwcml2YXRlS2V5SndrOiBKc29uV2ViS2V5O1xufTtcblxuY29uc3QgREVWSUNFX1NUT1JBR0VfS0VZID0gJ29wZW5jbGF3Q2hhdC5kZXZpY2VJZGVudGl0eS52MSc7XG5cbmZ1bmN0aW9uIGJhc2U2NFVybEVuY29kZShieXRlczogQXJyYXlCdWZmZXIpOiBzdHJpbmcge1xuICBjb25zdCB1OCA9IG5ldyBVaW50OEFycmF5KGJ5dGVzKTtcbiAgbGV0IHMgPSAnJztcbiAgZm9yIChsZXQgaSA9IDA7IGkgPCB1OC5sZW5ndGg7IGkrKykgcyArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKHU4W2ldKTtcbiAgY29uc3QgYjY0ID0gYnRvYShzKTtcbiAgcmV0dXJuIGI2NC5yZXBsYWNlKC9cXCsvZywgJy0nKS5yZXBsYWNlKC9cXC8vZywgJ18nKS5yZXBsYWNlKC89KyQvZywgJycpO1xufVxuXG5mdW5jdGlvbiBoZXhFbmNvZGUoYnl0ZXM6IEFycmF5QnVmZmVyKTogc3RyaW5nIHtcbiAgY29uc3QgdTggPSBuZXcgVWludDhBcnJheShieXRlcyk7XG4gIHJldHVybiBBcnJheS5mcm9tKHU4KVxuICAgIC5tYXAoKGIpID0+IGIudG9TdHJpbmcoMTYpLnBhZFN0YXJ0KDIsICcwJykpXG4gICAgLmpvaW4oJycpO1xufVxuXG5mdW5jdGlvbiB1dGY4Qnl0ZXModGV4dDogc3RyaW5nKTogVWludDhBcnJheSB7XG4gIHJldHVybiBuZXcgVGV4dEVuY29kZXIoKS5lbmNvZGUodGV4dCk7XG59XG5cbmFzeW5jIGZ1bmN0aW9uIHNoYTI1NkhleChieXRlczogQXJyYXlCdWZmZXIpOiBQcm9taXNlPHN0cmluZz4ge1xuICBjb25zdCBkaWdlc3QgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmRpZ2VzdCgnU0hBLTI1NicsIGJ5dGVzKTtcbiAgcmV0dXJuIGhleEVuY29kZShkaWdlc3QpO1xufVxuXG5hc3luYyBmdW5jdGlvbiBsb2FkT3JDcmVhdGVEZXZpY2VJZGVudGl0eSgpOiBQcm9taXNlPERldmljZUlkZW50aXR5PiB7XG4gIGNvbnN0IGV4aXN0aW5nID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oREVWSUNFX1NUT1JBR0VfS0VZKTtcbiAgaWYgKGV4aXN0aW5nKSB7XG4gICAgY29uc3QgcGFyc2VkID0gSlNPTi5wYXJzZShleGlzdGluZykgYXMgRGV2aWNlSWRlbnRpdHk7XG4gICAgaWYgKHBhcnNlZD8uaWQgJiYgcGFyc2VkPy5wdWJsaWNLZXkgJiYgcGFyc2VkPy5wcml2YXRlS2V5SndrKSByZXR1cm4gcGFyc2VkO1xuICB9XG5cbiAgY29uc3Qga2V5UGFpciA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuZ2VuZXJhdGVLZXkoeyBuYW1lOiAnRWQyNTUxOScgfSwgdHJ1ZSwgWydzaWduJywgJ3ZlcmlmeSddKTtcbiAgY29uc3QgcHViUmF3ID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5leHBvcnRLZXkoJ3JhdycsIGtleVBhaXIucHVibGljS2V5KTtcbiAgY29uc3QgcHJpdkp3ayA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuZXhwb3J0S2V5KCdqd2snLCBrZXlQYWlyLnByaXZhdGVLZXkpO1xuXG4gIC8vIElNUE9SVEFOVDogZGV2aWNlLmlkIG11c3QgYmUgYSBzdGFibGUgZmluZ2VycHJpbnQgZm9yIHRoZSBwdWJsaWMga2V5LlxuICAvLyBUaGUgZ2F0ZXdheSBlbmZvcmNlcyBkZXZpY2VJZCBcdTIxOTQgcHVibGljS2V5IGJpbmRpbmc7IHJhbmRvbSBpZHMgY2FuIGNhdXNlIFwiZGV2aWNlIGlkZW50aXR5IG1pc21hdGNoXCIuXG4gIGNvbnN0IGRldmljZUlkID0gYXdhaXQgc2hhMjU2SGV4KHB1YlJhdyk7XG4gIGNvbnN0IGlkID0gZGV2aWNlSWQ7XG5cbiAgY29uc3QgaWRlbnRpdHk6IERldmljZUlkZW50aXR5ID0ge1xuICAgIGlkLFxuICAgIHB1YmxpY0tleTogYmFzZTY0VXJsRW5jb2RlKHB1YlJhdyksXG4gICAgcHJpdmF0ZUtleUp3azogcHJpdkp3ayxcbiAgfTtcblxuICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbShERVZJQ0VfU1RPUkFHRV9LRVksIEpTT04uc3RyaW5naWZ5KGlkZW50aXR5KSk7XG4gIHJldHVybiBpZGVudGl0eTtcbn1cblxuZnVuY3Rpb24gYnVpbGREZXZpY2VBdXRoUGF5bG9hZChwYXJhbXM6IHtcbiAgZGV2aWNlSWQ6IHN0cmluZztcbiAgY2xpZW50SWQ6IHN0cmluZztcbiAgY2xpZW50TW9kZTogc3RyaW5nO1xuICByb2xlOiBzdHJpbmc7XG4gIHNjb3Blczogc3RyaW5nW107XG4gIHNpZ25lZEF0TXM6IG51bWJlcjtcbiAgdG9rZW46IHN0cmluZztcbiAgbm9uY2U/OiBzdHJpbmc7XG59KTogc3RyaW5nIHtcbiAgY29uc3QgdmVyc2lvbiA9IHBhcmFtcy5ub25jZSA/ICd2MicgOiAndjEnO1xuICBjb25zdCBzY29wZXMgPSBwYXJhbXMuc2NvcGVzLmpvaW4oJywnKTtcbiAgY29uc3QgYmFzZSA9IFtcbiAgICB2ZXJzaW9uLFxuICAgIHBhcmFtcy5kZXZpY2VJZCxcbiAgICBwYXJhbXMuY2xpZW50SWQsXG4gICAgcGFyYW1zLmNsaWVudE1vZGUsXG4gICAgcGFyYW1zLnJvbGUsXG4gICAgc2NvcGVzLFxuICAgIFN0cmluZyhwYXJhbXMuc2lnbmVkQXRNcyksXG4gICAgcGFyYW1zLnRva2VuIHx8ICcnLFxuICBdO1xuICBpZiAodmVyc2lvbiA9PT0gJ3YyJykgYmFzZS5wdXNoKHBhcmFtcy5ub25jZSB8fCAnJyk7XG4gIHJldHVybiBiYXNlLmpvaW4oJ3wnKTtcbn1cblxuYXN5bmMgZnVuY3Rpb24gc2lnbkRldmljZVBheWxvYWQoaWRlbnRpdHk6IERldmljZUlkZW50aXR5LCBwYXlsb2FkOiBzdHJpbmcpOiBQcm9taXNlPHsgc2lnbmF0dXJlOiBzdHJpbmc7IHNpZ25lZEF0OiBudW1iZXIgfT4ge1xuICBjb25zdCBwcml2YXRlS2V5ID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5pbXBvcnRLZXkoXG4gICAgJ2p3aycsXG4gICAgaWRlbnRpdHkucHJpdmF0ZUtleUp3ayxcbiAgICB7IG5hbWU6ICdFZDI1NTE5JyB9LFxuICAgIGZhbHNlLFxuICAgIFsnc2lnbiddLFxuICApO1xuXG4gIGNvbnN0IHNpZ25lZEF0ID0gRGF0ZS5ub3coKTtcbiAgY29uc3Qgc2lnID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5zaWduKHsgbmFtZTogJ0VkMjU1MTknIH0sIHByaXZhdGVLZXksIHV0ZjhCeXRlcyhwYXlsb2FkKSBhcyB1bmtub3duIGFzIEJ1ZmZlclNvdXJjZSk7XG4gIHJldHVybiB7IHNpZ25hdHVyZTogYmFzZTY0VXJsRW5jb2RlKHNpZyksIHNpZ25lZEF0IH07XG59XG5cbmZ1bmN0aW9uIGV4dHJhY3RUZXh0RnJvbUdhdGV3YXlNZXNzYWdlKG1zZzogYW55KTogc3RyaW5nIHtcbiAgaWYgKCFtc2cpIHJldHVybiAnJztcblxuICAvLyBNb3N0IGNvbW1vbjogeyByb2xlLCBjb250ZW50IH0gd2hlcmUgY29udGVudCBjYW4gYmUgc3RyaW5nIG9yIFt7dHlwZTondGV4dCcsdGV4dDonLi4uJ31dXG4gIGNvbnN0IGNvbnRlbnQgPSBtc2cuY29udGVudCA/PyBtc2cubWVzc2FnZSA/PyBtc2c7XG4gIGlmICh0eXBlb2YgY29udGVudCA9PT0gJ3N0cmluZycpIHJldHVybiBjb250ZW50O1xuXG4gIGlmIChBcnJheS5pc0FycmF5KGNvbnRlbnQpKSB7XG4gICAgY29uc3QgcGFydHMgPSBjb250ZW50XG4gICAgICAuZmlsdGVyKChjKSA9PiBjICYmIHR5cGVvZiBjID09PSAnb2JqZWN0JyAmJiBjLnR5cGUgPT09ICd0ZXh0JyAmJiB0eXBlb2YgYy50ZXh0ID09PSAnc3RyaW5nJylcbiAgICAgIC5tYXAoKGMpID0+IGMudGV4dCk7XG4gICAgcmV0dXJuIHBhcnRzLmpvaW4oJ1xcbicpO1xuICB9XG5cbiAgLy8gRmFsbGJhY2tcbiAgdHJ5IHtcbiAgICByZXR1cm4gSlNPTi5zdHJpbmdpZnkoY29udGVudCk7XG4gIH0gY2F0Y2gge1xuICAgIHJldHVybiBTdHJpbmcoY29udGVudCk7XG4gIH1cbn1cblxuZnVuY3Rpb24gc2Vzc2lvbktleU1hdGNoZXMoY29uZmlndXJlZDogc3RyaW5nLCBpbmNvbWluZzogc3RyaW5nKTogYm9vbGVhbiB7XG4gIGlmIChpbmNvbWluZyA9PT0gY29uZmlndXJlZCkgcmV0dXJuIHRydWU7XG4gIC8vIE9wZW5DbGF3IHJlc29sdmVzIFwibWFpblwiIHRvIGNhbm9uaWNhbCBzZXNzaW9uIGtleSBsaWtlIFwiYWdlbnQ6bWFpbjptYWluXCIuXG4gIGlmIChjb25maWd1cmVkID09PSAnbWFpbicgJiYgaW5jb21pbmcgPT09ICdhZ2VudDptYWluOm1haW4nKSByZXR1cm4gdHJ1ZTtcbiAgcmV0dXJuIGZhbHNlO1xufVxuXG5leHBvcnQgY2xhc3MgT2JzaWRpYW5XU0NsaWVudCB7XG4gIHByaXZhdGUgd3M6IFdlYlNvY2tldCB8IG51bGwgPSBudWxsO1xuICBwcml2YXRlIHJlY29ubmVjdFRpbWVyOiBSZXR1cm5UeXBlPHR5cGVvZiBzZXRUaW1lb3V0PiB8IG51bGwgPSBudWxsO1xuICBwcml2YXRlIGhlYXJ0YmVhdFRpbWVyOiBSZXR1cm5UeXBlPHR5cGVvZiBzZXRJbnRlcnZhbD4gfCBudWxsID0gbnVsbDtcbiAgcHJpdmF0ZSB3b3JraW5nVGltZXI6IFJldHVyblR5cGU8dHlwZW9mIHNldFRpbWVvdXQ+IHwgbnVsbCA9IG51bGw7XG4gIHByaXZhdGUgaW50ZW50aW9uYWxDbG9zZSA9IGZhbHNlO1xuICBwcml2YXRlIHNlc3Npb25LZXk6IHN0cmluZztcbiAgcHJpdmF0ZSB1cmwgPSAnJztcbiAgcHJpdmF0ZSB0b2tlbiA9ICcnO1xuICBwcml2YXRlIHJlcXVlc3RJZCA9IDA7XG4gIHByaXZhdGUgcGVuZGluZ1JlcXVlc3RzID0gbmV3IE1hcDxzdHJpbmcsIFBlbmRpbmdSZXF1ZXN0PigpO1xuICBwcml2YXRlIHdvcmtpbmcgPSBmYWxzZTtcblxuICAvKiogVGhlIGxhc3QgaW4tZmxpZ2h0IGNoYXQgcnVuIGlkLiBJbiBPcGVuQ2xhdyBXZWJDaGF0IHRoaXMgbWFwcyB0byBjaGF0LnNlbmQgaWRlbXBvdGVuY3lLZXkuICovXG4gIHByaXZhdGUgYWN0aXZlUnVuSWQ6IHN0cmluZyB8IG51bGwgPSBudWxsO1xuXG4gIC8qKiBQcmV2ZW50cyBhYm9ydCBzcGFtbWluZzogd2hpbGUgYW4gYWJvcnQgcmVxdWVzdCBpcyBpbi1mbGlnaHQsIHJldXNlIHRoZSBzYW1lIHByb21pc2UuICovXG4gIHByaXZhdGUgYWJvcnRJbkZsaWdodDogUHJvbWlzZTxib29sZWFuPiB8IG51bGwgPSBudWxsO1xuXG4gIHN0YXRlOiBXU0NsaWVudFN0YXRlID0gJ2Rpc2Nvbm5lY3RlZCc7XG5cbiAgb25NZXNzYWdlOiAoKG1zZzogSW5ib3VuZFdTUGF5bG9hZCkgPT4gdm9pZCkgfCBudWxsID0gbnVsbDtcbiAgb25TdGF0ZUNoYW5nZTogKChzdGF0ZTogV1NDbGllbnRTdGF0ZSkgPT4gdm9pZCkgfCBudWxsID0gbnVsbDtcbiAgb25Xb3JraW5nQ2hhbmdlOiBXb3JraW5nU3RhdGVMaXN0ZW5lciB8IG51bGwgPSBudWxsO1xuXG4gIGNvbnN0cnVjdG9yKHNlc3Npb25LZXk6IHN0cmluZykge1xuICAgIHRoaXMuc2Vzc2lvbktleSA9IHNlc3Npb25LZXk7XG4gIH1cblxuICBjb25uZWN0KHVybDogc3RyaW5nLCB0b2tlbjogc3RyaW5nKTogdm9pZCB7XG4gICAgdGhpcy51cmwgPSB1cmw7XG4gICAgdGhpcy50b2tlbiA9IHRva2VuO1xuICAgIHRoaXMuaW50ZW50aW9uYWxDbG9zZSA9IGZhbHNlO1xuICAgIHRoaXMuX2Nvbm5lY3QoKTtcbiAgfVxuXG4gIGRpc2Nvbm5lY3QoKTogdm9pZCB7XG4gICAgdGhpcy5pbnRlbnRpb25hbENsb3NlID0gdHJ1ZTtcbiAgICB0aGlzLl9zdG9wVGltZXJzKCk7XG4gICAgdGhpcy5hY3RpdmVSdW5JZCA9IG51bGw7XG4gICAgdGhpcy5fc2V0V29ya2luZyhmYWxzZSk7XG4gICAgaWYgKHRoaXMud3MpIHtcbiAgICAgIHRoaXMud3MuY2xvc2UoKTtcbiAgICAgIHRoaXMud3MgPSBudWxsO1xuICAgIH1cbiAgICB0aGlzLl9zZXRTdGF0ZSgnZGlzY29ubmVjdGVkJyk7XG4gIH1cblxuICBhc3luYyBzZW5kTWVzc2FnZShtZXNzYWdlOiBzdHJpbmcpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBpZiAodGhpcy5zdGF0ZSAhPT0gJ2Nvbm5lY3RlZCcpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcignTm90IGNvbm5lY3RlZCBcdTIwMTQgY2FsbCBjb25uZWN0KCkgZmlyc3QnKTtcbiAgICB9XG5cbiAgICBjb25zdCBydW5JZCA9IGBvYnNpZGlhbi0ke0RhdGUubm93KCl9LSR7TWF0aC5yYW5kb20oKS50b1N0cmluZygzNikuc2xpY2UoMiwgOSl9YDtcblxuICAgIC8vIFNob3cgXHUyMDFDd29ya2luZ1x1MjAxRCBPTkxZIGFmdGVyIHRoZSBnYXRld2F5IGFja25vd2xlZGdlcyB0aGUgcmVxdWVzdC5cbiAgICBhd2FpdCB0aGlzLl9zZW5kUmVxdWVzdCgnY2hhdC5zZW5kJywge1xuICAgICAgc2Vzc2lvbktleTogdGhpcy5zZXNzaW9uS2V5LFxuICAgICAgbWVzc2FnZSxcbiAgICAgIGlkZW1wb3RlbmN5S2V5OiBydW5JZCxcbiAgICAgIC8vIGRlbGl2ZXIgZGVmYXVsdHMgdG8gdHJ1ZSBpbiBnYXRld2F5OyBrZWVwIGRlZmF1bHRcbiAgICB9KTtcblxuICAgIHRoaXMuYWN0aXZlUnVuSWQgPSBydW5JZDtcbiAgICB0aGlzLl9zZXRXb3JraW5nKHRydWUpO1xuICAgIHRoaXMuX2FybVdvcmtpbmdTYWZldHlUaW1lb3V0KCk7XG4gIH1cblxuICAvKiogQWJvcnQgdGhlIGFjdGl2ZSBydW4gZm9yIHRoaXMgc2Vzc2lvbiAoYW5kIG91ciBsYXN0IHJ1biBpZCBpZiBwcmVzZW50KS4gKi9cbiAgYXN5bmMgYWJvcnRBY3RpdmVSdW4oKTogUHJvbWlzZTxib29sZWFuPiB7XG4gICAgaWYgKHRoaXMuc3RhdGUgIT09ICdjb25uZWN0ZWQnKSB7XG4gICAgICByZXR1cm4gZmFsc2U7XG4gICAgfVxuXG4gICAgLy8gUHJldmVudCByZXF1ZXN0IHN0b3Jtczogd2hpbGUgb25lIGFib3J0IGlzIGluIGZsaWdodCwgcmV1c2UgaXQuXG4gICAgaWYgKHRoaXMuYWJvcnRJbkZsaWdodCkge1xuICAgICAgcmV0dXJuIHRoaXMuYWJvcnRJbkZsaWdodDtcbiAgICB9XG5cbiAgICBjb25zdCBydW5JZCA9IHRoaXMuYWN0aXZlUnVuSWQ7XG5cbiAgICB0aGlzLmFib3J0SW5GbGlnaHQgPSAoYXN5bmMgKCkgPT4ge1xuICAgICAgdHJ5IHtcbiAgICAgICAgYXdhaXQgdGhpcy5fc2VuZFJlcXVlc3QoJ2NoYXQuYWJvcnQnLCBydW5JZCA/IHsgc2Vzc2lvbktleTogdGhpcy5zZXNzaW9uS2V5LCBydW5JZCB9IDogeyBzZXNzaW9uS2V5OiB0aGlzLnNlc3Npb25LZXkgfSk7XG4gICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgfSBjYXRjaCAoZXJyKSB7XG4gICAgICAgIGNvbnNvbGUuZXJyb3IoJ1tvY2xhdy13c10gY2hhdC5hYm9ydCBmYWlsZWQnLCBlcnIpO1xuICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICB9IGZpbmFsbHkge1xuICAgICAgICAvLyBBbHdheXMgcmVzdG9yZSBVSSBzdGF0ZSBpbW1lZGlhdGVseTsgdGhlIGdhdGV3YXkgbWF5IHN0aWxsIGVtaXQgYW4gYWJvcnRlZCBldmVudCBsYXRlci5cbiAgICAgICAgdGhpcy5hY3RpdmVSdW5JZCA9IG51bGw7XG4gICAgICAgIHRoaXMuX3NldFdvcmtpbmcoZmFsc2UpO1xuICAgICAgICB0aGlzLmFib3J0SW5GbGlnaHQgPSBudWxsO1xuICAgICAgfVxuICAgIH0pKCk7XG5cbiAgICByZXR1cm4gdGhpcy5hYm9ydEluRmxpZ2h0O1xuICB9XG5cbiAgcHJpdmF0ZSBfY29ubmVjdCgpOiB2b2lkIHtcbiAgICBpZiAodGhpcy53cykge1xuICAgICAgdGhpcy53cy5vbm9wZW4gPSBudWxsO1xuICAgICAgdGhpcy53cy5vbmNsb3NlID0gbnVsbDtcbiAgICAgIHRoaXMud3Mub25tZXNzYWdlID0gbnVsbDtcbiAgICAgIHRoaXMud3Mub25lcnJvciA9IG51bGw7XG4gICAgICB0aGlzLndzLmNsb3NlKCk7XG4gICAgICB0aGlzLndzID0gbnVsbDtcbiAgICB9XG5cbiAgICB0aGlzLl9zZXRTdGF0ZSgnY29ubmVjdGluZycpO1xuXG4gICAgY29uc3Qgd3MgPSBuZXcgV2ViU29ja2V0KHRoaXMudXJsKTtcbiAgICB0aGlzLndzID0gd3M7XG5cbiAgICBsZXQgY29ubmVjdE5vbmNlOiBzdHJpbmcgfCBudWxsID0gbnVsbDtcbiAgICBsZXQgY29ubmVjdFN0YXJ0ZWQgPSBmYWxzZTtcblxuICAgIGNvbnN0IHRyeUNvbm5lY3QgPSBhc3luYyAoKSA9PiB7XG4gICAgICBpZiAoY29ubmVjdFN0YXJ0ZWQpIHJldHVybjtcbiAgICAgIGlmICghY29ubmVjdE5vbmNlKSByZXR1cm47XG4gICAgICBjb25uZWN0U3RhcnRlZCA9IHRydWU7XG5cbiAgICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IGlkZW50aXR5ID0gYXdhaXQgbG9hZE9yQ3JlYXRlRGV2aWNlSWRlbnRpdHkoKTtcbiAgICAgICAgY29uc3Qgc2lnbmVkQXRNcyA9IERhdGUubm93KCk7XG4gICAgICAgIGNvbnN0IHBheWxvYWQgPSBidWlsZERldmljZUF1dGhQYXlsb2FkKHtcbiAgICAgICAgICBkZXZpY2VJZDogaWRlbnRpdHkuaWQsXG4gICAgICAgICAgY2xpZW50SWQ6ICdnYXRld2F5LWNsaWVudCcsXG4gICAgICAgICAgY2xpZW50TW9kZTogJ2JhY2tlbmQnLFxuICAgICAgICAgIHJvbGU6ICdvcGVyYXRvcicsXG4gICAgICAgICAgc2NvcGVzOiBbJ29wZXJhdG9yLnJlYWQnLCAnb3BlcmF0b3Iud3JpdGUnXSxcbiAgICAgICAgICBzaWduZWRBdE1zLFxuICAgICAgICAgIHRva2VuOiB0aGlzLnRva2VuLFxuICAgICAgICAgIG5vbmNlOiBjb25uZWN0Tm9uY2UsXG4gICAgICAgIH0pO1xuICAgICAgICBjb25zdCBzaWcgPSBhd2FpdCBzaWduRGV2aWNlUGF5bG9hZChpZGVudGl0eSwgcGF5bG9hZCk7XG5cbiAgICAgICAgYXdhaXQgdGhpcy5fc2VuZFJlcXVlc3QoJ2Nvbm5lY3QnLCB7XG4gICAgICAgICAgbWluUHJvdG9jb2w6IDMsXG4gICAgICAgICAgbWF4UHJvdG9jb2w6IDMsXG4gICAgICAgICAgY2xpZW50OiB7XG4gICAgICAgICAgICBpZDogJ2dhdGV3YXktY2xpZW50JyxcbiAgICAgICAgICAgIG1vZGU6ICdiYWNrZW5kJyxcbiAgICAgICAgICAgIHZlcnNpb246ICcwLjEuMTAnLFxuICAgICAgICAgICAgcGxhdGZvcm06ICdlbGVjdHJvbicsXG4gICAgICAgICAgfSxcbiAgICAgICAgICByb2xlOiAnb3BlcmF0b3InLFxuICAgICAgICAgIHNjb3BlczogWydvcGVyYXRvci5yZWFkJywgJ29wZXJhdG9yLndyaXRlJ10sXG4gICAgICAgICAgZGV2aWNlOiB7XG4gICAgICAgICAgICBpZDogaWRlbnRpdHkuaWQsXG4gICAgICAgICAgICBwdWJsaWNLZXk6IGlkZW50aXR5LnB1YmxpY0tleSxcbiAgICAgICAgICAgIHNpZ25hdHVyZTogc2lnLnNpZ25hdHVyZSxcbiAgICAgICAgICAgIHNpZ25lZEF0OiBzaWduZWRBdE1zLFxuICAgICAgICAgICAgbm9uY2U6IGNvbm5lY3ROb25jZSxcbiAgICAgICAgICB9LFxuICAgICAgICAgIGF1dGg6IHtcbiAgICAgICAgICAgIHRva2VuOiB0aGlzLnRva2VuLFxuICAgICAgICAgIH0sXG4gICAgICAgIH0pO1xuXG4gICAgICAgIHRoaXMuX3NldFN0YXRlKCdjb25uZWN0ZWQnKTtcbiAgICAgICAgdGhpcy5fc3RhcnRIZWFydGJlYXQoKTtcbiAgICAgIH0gY2F0Y2ggKGVycikge1xuICAgICAgICBjb25zb2xlLmVycm9yKCdbb2NsYXctd3NdIENvbm5lY3QgaGFuZHNoYWtlIGZhaWxlZCcsIGVycik7XG4gICAgICAgIHdzLmNsb3NlKCk7XG4gICAgICB9XG4gICAgfTtcblxuICAgIHdzLm9ub3BlbiA9ICgpID0+IHtcbiAgICAgIHRoaXMuX3NldFN0YXRlKCdoYW5kc2hha2luZycpO1xuICAgICAgLy8gVGhlIGdhdGV3YXkgd2lsbCBzZW5kIGNvbm5lY3QuY2hhbGxlbmdlOyBjb25uZWN0IGlzIHNlbnQgb25jZSB3ZSBoYXZlIGEgbm9uY2UuXG4gICAgfTtcblxuICAgIHdzLm9ubWVzc2FnZSA9IChldmVudDogTWVzc2FnZUV2ZW50KSA9PiB7XG4gICAgICBsZXQgZnJhbWU6IGFueTtcbiAgICAgIHRyeSB7XG4gICAgICAgIGZyYW1lID0gSlNPTi5wYXJzZShldmVudC5kYXRhIGFzIHN0cmluZyk7XG4gICAgICB9IGNhdGNoIHtcbiAgICAgICAgY29uc29sZS5lcnJvcignW29jbGF3LXdzXSBGYWlsZWQgdG8gcGFyc2UgaW5jb21pbmcgbWVzc2FnZScpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG5cbiAgICAgIC8vIFJlc3BvbnNlc1xuICAgICAgaWYgKGZyYW1lLnR5cGUgPT09ICdyZXMnKSB7XG4gICAgICAgIHRoaXMuX2hhbmRsZVJlc3BvbnNlRnJhbWUoZnJhbWUpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG5cbiAgICAgIC8vIEV2ZW50c1xuICAgICAgaWYgKGZyYW1lLnR5cGUgPT09ICdldmVudCcpIHtcbiAgICAgICAgaWYgKGZyYW1lLmV2ZW50ID09PSAnY29ubmVjdC5jaGFsbGVuZ2UnKSB7XG4gICAgICAgICAgY29ubmVjdE5vbmNlID0gZnJhbWUucGF5bG9hZD8ubm9uY2UgfHwgbnVsbDtcbiAgICAgICAgICAvLyBBdHRlbXB0IGhhbmRzaGFrZSBvbmNlIHdlIGhhdmUgYSBub25jZS5cbiAgICAgICAgICB2b2lkIHRyeUNvbm5lY3QoKTtcbiAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoZnJhbWUuZXZlbnQgPT09ICdjaGF0Jykge1xuICAgICAgICAgIHRoaXMuX2hhbmRsZUNoYXRFdmVudEZyYW1lKGZyYW1lKTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm47XG4gICAgICB9XG5cbiAgICAgIC8vIEF2b2lkIGxvZ2dpbmcgZnVsbCBmcmFtZXMgKG1heSBpbmNsdWRlIG1lc3NhZ2UgY29udGVudCBvciBvdGhlciBzZW5zaXRpdmUgcGF5bG9hZHMpLlxuICAgICAgY29uc29sZS5kZWJ1ZygnW29jbGF3LXdzXSBVbmhhbmRsZWQgZnJhbWUnLCB7IHR5cGU6IGZyYW1lPy50eXBlLCBldmVudDogZnJhbWU/LmV2ZW50LCBpZDogZnJhbWU/LmlkIH0pO1xuICAgIH07XG5cbiAgICB3cy5vbmNsb3NlID0gKCkgPT4ge1xuICAgICAgdGhpcy5fc3RvcFRpbWVycygpO1xuICAgICAgdGhpcy5fc2V0V29ya2luZyhmYWxzZSk7XG4gICAgICB0aGlzLl9zZXRTdGF0ZSgnZGlzY29ubmVjdGVkJyk7XG5cbiAgICAgIGZvciAoY29uc3QgcGVuZGluZyBvZiB0aGlzLnBlbmRpbmdSZXF1ZXN0cy52YWx1ZXMoKSkge1xuICAgICAgICBpZiAocGVuZGluZy50aW1lb3V0KSBjbGVhclRpbWVvdXQocGVuZGluZy50aW1lb3V0KTtcbiAgICAgICAgcGVuZGluZy5yZWplY3QobmV3IEVycm9yKCdDb25uZWN0aW9uIGNsb3NlZCcpKTtcbiAgICAgIH1cbiAgICAgIHRoaXMucGVuZGluZ1JlcXVlc3RzLmNsZWFyKCk7XG5cbiAgICAgIGlmICghdGhpcy5pbnRlbnRpb25hbENsb3NlKSB7XG4gICAgICAgIHRoaXMuX3NjaGVkdWxlUmVjb25uZWN0KCk7XG4gICAgICB9XG4gICAgfTtcblxuICAgIHdzLm9uZXJyb3IgPSAoZXY6IEV2ZW50KSA9PiB7XG4gICAgICBjb25zb2xlLmVycm9yKCdbb2NsYXctd3NdIFdlYlNvY2tldCBlcnJvcicsIGV2KTtcbiAgICB9O1xuICB9XG5cbiAgcHJpdmF0ZSBfaGFuZGxlUmVzcG9uc2VGcmFtZShmcmFtZTogYW55KTogdm9pZCB7XG4gICAgY29uc3QgcGVuZGluZyA9IHRoaXMucGVuZGluZ1JlcXVlc3RzLmdldChmcmFtZS5pZCk7XG4gICAgaWYgKCFwZW5kaW5nKSByZXR1cm47XG5cbiAgICB0aGlzLnBlbmRpbmdSZXF1ZXN0cy5kZWxldGUoZnJhbWUuaWQpO1xuICAgIGlmIChwZW5kaW5nLnRpbWVvdXQpIGNsZWFyVGltZW91dChwZW5kaW5nLnRpbWVvdXQpO1xuXG4gICAgaWYgKGZyYW1lLm9rKSBwZW5kaW5nLnJlc29sdmUoZnJhbWUucGF5bG9hZCk7XG4gICAgZWxzZSBwZW5kaW5nLnJlamVjdChuZXcgRXJyb3IoZnJhbWUuZXJyb3I/Lm1lc3NhZ2UgfHwgJ1JlcXVlc3QgZmFpbGVkJykpO1xuICB9XG5cbiAgcHJpdmF0ZSBfaGFuZGxlQ2hhdEV2ZW50RnJhbWUoZnJhbWU6IGFueSk6IHZvaWQge1xuICAgIGNvbnN0IHBheWxvYWQgPSBmcmFtZS5wYXlsb2FkO1xuICAgIGNvbnN0IGluY29taW5nU2Vzc2lvbktleSA9IFN0cmluZyhwYXlsb2FkPy5zZXNzaW9uS2V5IHx8ICcnKTtcbiAgICBpZiAoIWluY29taW5nU2Vzc2lvbktleSB8fCAhc2Vzc2lvbktleU1hdGNoZXModGhpcy5zZXNzaW9uS2V5LCBpbmNvbWluZ1Nlc3Npb25LZXkpKSB7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgLy8gQmVzdC1lZmZvcnQgcnVuIGNvcnJlbGF0aW9uIChpZiBnYXRld2F5IGluY2x1ZGVzIGEgcnVuIGlkKS4gVGhpcyBhdm9pZHMgY2xlYXJpbmcgb3VyIFVJXG4gICAgLy8gYmFzZWQgb24gYSBkaWZmZXJlbnQgY2xpZW50J3MgcnVuIGluIHRoZSBzYW1lIHNlc3Npb24uXG4gICAgY29uc3QgaW5jb21pbmdSdW5JZCA9IFN0cmluZyhwYXlsb2FkPy5ydW5JZCB8fCBwYXlsb2FkPy5pZGVtcG90ZW5jeUtleSB8fCBwYXlsb2FkPy5tZXRhPy5ydW5JZCB8fCAnJyk7XG4gICAgaWYgKHRoaXMuYWN0aXZlUnVuSWQgJiYgaW5jb21pbmdSdW5JZCAmJiBpbmNvbWluZ1J1bklkICE9PSB0aGlzLmFjdGl2ZVJ1bklkKSB7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgLy8gQXZvaWQgZG91YmxlLXJlbmRlcjogZ2F0ZXdheSBlbWl0cyBkZWx0YSArIGZpbmFsICsgYWJvcnRlZC4gUmVuZGVyIG9ubHkgZmluYWwvYWJvcnRlZC5cbiAgICBpZiAocGF5bG9hZD8uc3RhdGUgJiYgcGF5bG9hZC5zdGF0ZSAhPT0gJ2ZpbmFsJyAmJiBwYXlsb2FkLnN0YXRlICE9PSAnYWJvcnRlZCcpIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICAvLyBXZSBvbmx5IGFwcGVuZCBhc3Npc3RhbnQgb3V0cHV0IHRvIFVJLlxuICAgIGNvbnN0IG1zZyA9IHBheWxvYWQ/Lm1lc3NhZ2U7XG4gICAgY29uc3Qgcm9sZSA9IG1zZz8ucm9sZSA/PyAnYXNzaXN0YW50JztcblxuICAgIC8vIEJvdGggZmluYWwgYW5kIGFib3J0ZWQgcmVzb2x2ZSBcIndvcmtpbmdcIi5cbiAgICB0aGlzLmFjdGl2ZVJ1bklkID0gbnVsbDtcbiAgICB0aGlzLl9zZXRXb3JraW5nKGZhbHNlKTtcblxuICAgIC8vIEFib3J0ZWQgbWF5IGhhdmUgbm8gYXNzaXN0YW50IG1lc3NhZ2Ugb3IgbWF5IGNhcnJ5IHBhcnRpYWwgYXNzaXN0YW50IGNvbnRlbnQuXG4gICAgaWYgKHBheWxvYWQ/LnN0YXRlID09PSAnYWJvcnRlZCcpIHtcbiAgICAgIC8vIElmIHRoZXJlJ3Mgbm8gdXNhYmxlIGFzc2lzdGFudCBwYXlsb2FkLCBqdXN0IGRvbid0IGFwcGVuZCBhbnl0aGluZy5cbiAgICAgIC8vIChWaWV3IGxheWVyIG1heSBvcHRpb25hbGx5IGFkZCBhIHN5c3RlbSBtZXNzYWdlIG9uIHN1Y2Nlc3NmdWwgc3RvcC4pXG4gICAgICBpZiAoIW1zZykgcmV0dXJuO1xuICAgIH1cblxuICAgIGlmIChyb2xlICE9PSAnYXNzaXN0YW50Jykge1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIGNvbnN0IHRleHQgPSBleHRyYWN0VGV4dEZyb21HYXRld2F5TWVzc2FnZShtc2cpO1xuICAgIGlmICghdGV4dCkgcmV0dXJuO1xuXG4gICAgLy8gT3B0aW9uYWw6IGhpZGUgaGVhcnRiZWF0IGFja3MgKG5vaXNlIGluIFVJKVxuICAgIGlmICh0ZXh0LnRyaW0oKSA9PT0gJ0hFQVJUQkVBVF9PSycpIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICB0aGlzLm9uTWVzc2FnZT8uKHtcbiAgICAgIHR5cGU6ICdtZXNzYWdlJyxcbiAgICAgIHBheWxvYWQ6IHtcbiAgICAgICAgY29udGVudDogdGV4dCxcbiAgICAgICAgcm9sZTogJ2Fzc2lzdGFudCcsXG4gICAgICAgIHRpbWVzdGFtcDogRGF0ZS5ub3coKSxcbiAgICAgIH0sXG4gICAgfSk7XG4gIH1cblxuICBwcml2YXRlIF9zZW5kUmVxdWVzdChtZXRob2Q6IHN0cmluZywgcGFyYW1zOiBhbnkpOiBQcm9taXNlPGFueT4ge1xuICAgIHJldHVybiBuZXcgUHJvbWlzZSgocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICBpZiAoIXRoaXMud3MgfHwgdGhpcy53cy5yZWFkeVN0YXRlICE9PSBXZWJTb2NrZXQuT1BFTikge1xuICAgICAgICByZWplY3QobmV3IEVycm9yKCdXZWJTb2NrZXQgbm90IGNvbm5lY3RlZCcpKTtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuXG4gICAgICBjb25zdCBpZCA9IGByZXEtJHsrK3RoaXMucmVxdWVzdElkfWA7XG5cbiAgICAgIGNvbnN0IHBlbmRpbmc6IFBlbmRpbmdSZXF1ZXN0ID0geyByZXNvbHZlLCByZWplY3QsIHRpbWVvdXQ6IG51bGwgfTtcbiAgICAgIHRoaXMucGVuZGluZ1JlcXVlc3RzLnNldChpZCwgcGVuZGluZyk7XG5cbiAgICAgIHRoaXMud3Muc2VuZChcbiAgICAgICAgSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIHR5cGU6ICdyZXEnLFxuICAgICAgICAgIG1ldGhvZCxcbiAgICAgICAgICBpZCxcbiAgICAgICAgICBwYXJhbXMsXG4gICAgICAgIH0pXG4gICAgICApO1xuXG4gICAgICBwZW5kaW5nLnRpbWVvdXQgPSBzZXRUaW1lb3V0KCgpID0+IHtcbiAgICAgICAgaWYgKHRoaXMucGVuZGluZ1JlcXVlc3RzLmhhcyhpZCkpIHtcbiAgICAgICAgICB0aGlzLnBlbmRpbmdSZXF1ZXN0cy5kZWxldGUoaWQpO1xuICAgICAgICAgIHJlamVjdChuZXcgRXJyb3IoYFJlcXVlc3QgdGltZW91dDogJHttZXRob2R9YCkpO1xuICAgICAgICB9XG4gICAgICB9LCAzMF8wMDApO1xuICAgIH0pO1xuICB9XG5cbiAgcHJpdmF0ZSBfc2NoZWR1bGVSZWNvbm5lY3QoKTogdm9pZCB7XG4gICAgaWYgKHRoaXMucmVjb25uZWN0VGltZXIgIT09IG51bGwpIHJldHVybjtcbiAgICB0aGlzLnJlY29ubmVjdFRpbWVyID0gc2V0VGltZW91dCgoKSA9PiB7XG4gICAgICB0aGlzLnJlY29ubmVjdFRpbWVyID0gbnVsbDtcbiAgICAgIGlmICghdGhpcy5pbnRlbnRpb25hbENsb3NlKSB7XG4gICAgICAgIGNvbnNvbGUubG9nKGBbb2NsYXctd3NdIFJlY29ubmVjdGluZyB0byAke3RoaXMudXJsfVx1MjAyNmApO1xuICAgICAgICB0aGlzLl9jb25uZWN0KCk7XG4gICAgICB9XG4gICAgfSwgUkVDT05ORUNUX0RFTEFZX01TKTtcbiAgfVxuXG4gIHByaXZhdGUgX3N0YXJ0SGVhcnRiZWF0KCk6IHZvaWQge1xuICAgIHRoaXMuX3N0b3BIZWFydGJlYXQoKTtcbiAgICB0aGlzLmhlYXJ0YmVhdFRpbWVyID0gc2V0SW50ZXJ2YWwoKCkgPT4ge1xuICAgICAgaWYgKHRoaXMud3M/LnJlYWR5U3RhdGUgIT09IFdlYlNvY2tldC5PUEVOKSByZXR1cm47XG4gICAgICBpZiAodGhpcy53cy5idWZmZXJlZEFtb3VudCA+IDApIHtcbiAgICAgICAgY29uc29sZS53YXJuKCdbb2NsYXctd3NdIFNlbmQgYnVmZmVyIG5vdCBlbXB0eSBcdTIwMTQgY29ubmVjdGlvbiBtYXkgYmUgc3RhbGxlZCcpO1xuICAgICAgfVxuICAgIH0sIEhFQVJUQkVBVF9JTlRFUlZBTF9NUyk7XG4gIH1cblxuICBwcml2YXRlIF9zdG9wSGVhcnRiZWF0KCk6IHZvaWQge1xuICAgIGlmICh0aGlzLmhlYXJ0YmVhdFRpbWVyKSB7XG4gICAgICBjbGVhckludGVydmFsKHRoaXMuaGVhcnRiZWF0VGltZXIpO1xuICAgICAgdGhpcy5oZWFydGJlYXRUaW1lciA9IG51bGw7XG4gICAgfVxuICB9XG5cbiAgcHJpdmF0ZSBfc3RvcFRpbWVycygpOiB2b2lkIHtcbiAgICB0aGlzLl9zdG9wSGVhcnRiZWF0KCk7XG4gICAgdGhpcy5fZGlzYXJtV29ya2luZ1NhZmV0eVRpbWVvdXQoKTtcbiAgICBpZiAodGhpcy5yZWNvbm5lY3RUaW1lcikge1xuICAgICAgY2xlYXJUaW1lb3V0KHRoaXMucmVjb25uZWN0VGltZXIpO1xuICAgICAgdGhpcy5yZWNvbm5lY3RUaW1lciA9IG51bGw7XG4gICAgfVxuICB9XG5cbiAgcHJpdmF0ZSBfc2V0U3RhdGUoc3RhdGU6IFdTQ2xpZW50U3RhdGUpOiB2b2lkIHtcbiAgICBpZiAodGhpcy5zdGF0ZSA9PT0gc3RhdGUpIHJldHVybjtcbiAgICB0aGlzLnN0YXRlID0gc3RhdGU7XG4gICAgdGhpcy5vblN0YXRlQ2hhbmdlPy4oc3RhdGUpO1xuICB9XG5cbiAgcHJpdmF0ZSBfc2V0V29ya2luZyh3b3JraW5nOiBib29sZWFuKTogdm9pZCB7XG4gICAgaWYgKHRoaXMud29ya2luZyA9PT0gd29ya2luZykgcmV0dXJuO1xuICAgIHRoaXMud29ya2luZyA9IHdvcmtpbmc7XG4gICAgdGhpcy5vbldvcmtpbmdDaGFuZ2U/Lih3b3JraW5nKTtcblxuICAgIGlmICghd29ya2luZykge1xuICAgICAgdGhpcy5fZGlzYXJtV29ya2luZ1NhZmV0eVRpbWVvdXQoKTtcbiAgICB9XG4gIH1cblxuICBwcml2YXRlIF9hcm1Xb3JraW5nU2FmZXR5VGltZW91dCgpOiB2b2lkIHtcbiAgICB0aGlzLl9kaXNhcm1Xb3JraW5nU2FmZXR5VGltZW91dCgpO1xuICAgIHRoaXMud29ya2luZ1RpbWVyID0gc2V0VGltZW91dCgoKSA9PiB7XG4gICAgICAvLyBJZiB0aGUgZ2F0ZXdheSBuZXZlciBlbWl0cyBhbiBhc3Npc3RhbnQgZmluYWwgcmVzcG9uc2UsIGRvblx1MjAxOXQgbGVhdmUgVUkgc3R1Y2suXG4gICAgICB0aGlzLl9zZXRXb3JraW5nKGZhbHNlKTtcbiAgICB9LCBXT1JLSU5HX01BWF9NUyk7XG4gIH1cblxuICBwcml2YXRlIF9kaXNhcm1Xb3JraW5nU2FmZXR5VGltZW91dCgpOiB2b2lkIHtcbiAgICBpZiAodGhpcy53b3JraW5nVGltZXIpIHtcbiAgICAgIGNsZWFyVGltZW91dCh0aGlzLndvcmtpbmdUaW1lcik7XG4gICAgICB0aGlzLndvcmtpbmdUaW1lciA9IG51bGw7XG4gICAgfVxuICB9XG59XG4iLCAiaW1wb3J0IHR5cGUgeyBDaGF0TWVzc2FnZSB9IGZyb20gJy4vdHlwZXMnO1xuXG4vKiogTWFuYWdlcyB0aGUgaW4tbWVtb3J5IGxpc3Qgb2YgY2hhdCBtZXNzYWdlcyBhbmQgbm90aWZpZXMgVUkgb24gY2hhbmdlcyAqL1xuZXhwb3J0IGNsYXNzIENoYXRNYW5hZ2VyIHtcbiAgcHJpdmF0ZSBtZXNzYWdlczogQ2hhdE1lc3NhZ2VbXSA9IFtdO1xuXG4gIC8qKiBGaXJlZCBmb3IgYSBmdWxsIHJlLXJlbmRlciAoY2xlYXIvcmVsb2FkKSAqL1xuICBvblVwZGF0ZTogKChtZXNzYWdlczogcmVhZG9ubHkgQ2hhdE1lc3NhZ2VbXSkgPT4gdm9pZCkgfCBudWxsID0gbnVsbDtcbiAgLyoqIEZpcmVkIHdoZW4gYSBzaW5nbGUgbWVzc2FnZSBpcyBhcHBlbmRlZCBcdTIwMTQgdXNlIGZvciBPKDEpIGFwcGVuZC1vbmx5IFVJICovXG4gIG9uTWVzc2FnZUFkZGVkOiAoKG1zZzogQ2hhdE1lc3NhZ2UpID0+IHZvaWQpIHwgbnVsbCA9IG51bGw7XG5cbiAgYWRkTWVzc2FnZShtc2c6IENoYXRNZXNzYWdlKTogdm9pZCB7XG4gICAgdGhpcy5tZXNzYWdlcy5wdXNoKG1zZyk7XG4gICAgdGhpcy5vbk1lc3NhZ2VBZGRlZD8uKG1zZyk7XG4gIH1cblxuICBnZXRNZXNzYWdlcygpOiByZWFkb25seSBDaGF0TWVzc2FnZVtdIHtcbiAgICByZXR1cm4gdGhpcy5tZXNzYWdlcztcbiAgfVxuXG4gIGNsZWFyKCk6IHZvaWQge1xuICAgIHRoaXMubWVzc2FnZXMgPSBbXTtcbiAgICB0aGlzLm9uVXBkYXRlPy4oW10pO1xuICB9XG5cbiAgLyoqIENyZWF0ZSBhIHVzZXIgbWVzc2FnZSBvYmplY3QgKHdpdGhvdXQgYWRkaW5nIGl0KSAqL1xuICBzdGF0aWMgY3JlYXRlVXNlck1lc3NhZ2UoY29udGVudDogc3RyaW5nKTogQ2hhdE1lc3NhZ2Uge1xuICAgIHJldHVybiB7XG4gICAgICBpZDogYG1zZy0ke0RhdGUubm93KCl9LSR7TWF0aC5yYW5kb20oKS50b1N0cmluZygzNikuc2xpY2UoMiwgNyl9YCxcbiAgICAgIHJvbGU6ICd1c2VyJyxcbiAgICAgIGNvbnRlbnQsXG4gICAgICB0aW1lc3RhbXA6IERhdGUubm93KCksXG4gICAgfTtcbiAgfVxuXG4gIC8qKiBDcmVhdGUgYW4gYXNzaXN0YW50IG1lc3NhZ2Ugb2JqZWN0ICh3aXRob3V0IGFkZGluZyBpdCkgKi9cbiAgc3RhdGljIGNyZWF0ZUFzc2lzdGFudE1lc3NhZ2UoY29udGVudDogc3RyaW5nKTogQ2hhdE1lc3NhZ2Uge1xuICAgIHJldHVybiB7XG4gICAgICBpZDogYG1zZy0ke0RhdGUubm93KCl9LSR7TWF0aC5yYW5kb20oKS50b1N0cmluZygzNikuc2xpY2UoMiwgNyl9YCxcbiAgICAgIHJvbGU6ICdhc3Npc3RhbnQnLFxuICAgICAgY29udGVudCxcbiAgICAgIHRpbWVzdGFtcDogRGF0ZS5ub3coKSxcbiAgICB9O1xuICB9XG5cbiAgLyoqIENyZWF0ZSBhIHN5c3RlbSAvIHN0YXR1cyBtZXNzYWdlIChlcnJvcnMsIHJlY29ubmVjdCBub3RpY2VzLCBldGMuKSAqL1xuICBzdGF0aWMgY3JlYXRlU3lzdGVtTWVzc2FnZShjb250ZW50OiBzdHJpbmcsIGxldmVsOiBDaGF0TWVzc2FnZVsnbGV2ZWwnXSA9ICdpbmZvJyk6IENoYXRNZXNzYWdlIHtcbiAgICByZXR1cm4ge1xuICAgICAgaWQ6IGBzeXMtJHtEYXRlLm5vdygpfWAsXG4gICAgICByb2xlOiAnc3lzdGVtJyxcbiAgICAgIGxldmVsLFxuICAgICAgY29udGVudCxcbiAgICAgIHRpbWVzdGFtcDogRGF0ZS5ub3coKSxcbiAgICB9O1xuICB9XG59XG4iLCAiaW1wb3J0IHsgSXRlbVZpZXcsIE1hcmtkb3duUmVuZGVyZXIsIE5vdGljZSwgV29ya3NwYWNlTGVhZiB9IGZyb20gJ29ic2lkaWFuJztcbmltcG9ydCB0eXBlIE9wZW5DbGF3UGx1Z2luIGZyb20gJy4vbWFpbic7XG5pbXBvcnQgeyBDaGF0TWFuYWdlciB9IGZyb20gJy4vY2hhdCc7XG5pbXBvcnQgdHlwZSB7IENoYXRNZXNzYWdlIH0gZnJvbSAnLi90eXBlcyc7XG5pbXBvcnQgeyBnZXRBY3RpdmVOb3RlQ29udGV4dCB9IGZyb20gJy4vY29udGV4dCc7XG5cbmV4cG9ydCBjb25zdCBWSUVXX1RZUEVfT1BFTkNMQVdfQ0hBVCA9ICdvcGVuY2xhdy1jaGF0JztcblxuZXhwb3J0IGNsYXNzIE9wZW5DbGF3Q2hhdFZpZXcgZXh0ZW5kcyBJdGVtVmlldyB7XG4gIHByaXZhdGUgcGx1Z2luOiBPcGVuQ2xhd1BsdWdpbjtcbiAgcHJpdmF0ZSBjaGF0TWFuYWdlcjogQ2hhdE1hbmFnZXI7XG5cbiAgLy8gU3RhdGVcbiAgcHJpdmF0ZSBpc0Nvbm5lY3RlZCA9IGZhbHNlO1xuICBwcml2YXRlIGlzV29ya2luZyA9IGZhbHNlO1xuXG4gIC8vIERPTSByZWZzXG4gIHByaXZhdGUgbWVzc2FnZXNFbCE6IEhUTUxFbGVtZW50O1xuICBwcml2YXRlIGlucHV0RWwhOiBIVE1MVGV4dEFyZWFFbGVtZW50O1xuICBwcml2YXRlIHNlbmRCdG4hOiBIVE1MQnV0dG9uRWxlbWVudDtcbiAgcHJpdmF0ZSBpbmNsdWRlTm90ZUNoZWNrYm94ITogSFRNTElucHV0RWxlbWVudDtcbiAgcHJpdmF0ZSBzdGF0dXNEb3QhOiBIVE1MRWxlbWVudDtcblxuICBjb25zdHJ1Y3RvcihsZWFmOiBXb3Jrc3BhY2VMZWFmLCBwbHVnaW46IE9wZW5DbGF3UGx1Z2luKSB7XG4gICAgc3VwZXIobGVhZik7XG4gICAgdGhpcy5wbHVnaW4gPSBwbHVnaW47XG4gICAgdGhpcy5jaGF0TWFuYWdlciA9IHBsdWdpbi5jaGF0TWFuYWdlcjtcbiAgfVxuXG4gIGdldFZpZXdUeXBlKCk6IHN0cmluZyB7XG4gICAgcmV0dXJuIFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFUO1xuICB9XG5cbiAgZ2V0RGlzcGxheVRleHQoKTogc3RyaW5nIHtcbiAgICByZXR1cm4gJ09wZW5DbGF3IENoYXQnO1xuICB9XG5cbiAgZ2V0SWNvbigpOiBzdHJpbmcge1xuICAgIHJldHVybiAnbWVzc2FnZS1zcXVhcmUnO1xuICB9XG5cbiAgYXN5bmMgb25PcGVuKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIHRoaXMuX2J1aWxkVUkoKTtcblxuICAgIC8vIEZ1bGwgcmUtcmVuZGVyIG9uIGNsZWFyIC8gcmVsb2FkXG4gICAgdGhpcy5jaGF0TWFuYWdlci5vblVwZGF0ZSA9IChtc2dzKSA9PiB0aGlzLl9yZW5kZXJNZXNzYWdlcyhtc2dzKTtcbiAgICAvLyBPKDEpIGFwcGVuZCBmb3IgbmV3IG1lc3NhZ2VzXG4gICAgdGhpcy5jaGF0TWFuYWdlci5vbk1lc3NhZ2VBZGRlZCA9IChtc2cpID0+IHRoaXMuX2FwcGVuZE1lc3NhZ2UobXNnKTtcblxuICAgIC8vIFN1YnNjcmliZSB0byBXUyBzdGF0ZSBjaGFuZ2VzXG4gICAgdGhpcy5wbHVnaW4ud3NDbGllbnQub25TdGF0ZUNoYW5nZSA9IChzdGF0ZSkgPT4ge1xuICAgICAgdGhpcy5pc0Nvbm5lY3RlZCA9IHN0YXRlID09PSAnY29ubmVjdGVkJztcbiAgICAgIHRoaXMuc3RhdHVzRG90LnRvZ2dsZUNsYXNzKCdjb25uZWN0ZWQnLCB0aGlzLmlzQ29ubmVjdGVkKTtcbiAgICAgIHRoaXMuc3RhdHVzRG90LnRpdGxlID0gYEdhdGV3YXk6ICR7c3RhdGV9YDtcbiAgICAgIHRoaXMuX3VwZGF0ZVNlbmRCdXR0b24oKTtcbiAgICB9O1xuXG4gICAgLy8gU3Vic2NyaWJlIHRvIFx1MjAxQ3dvcmtpbmdcdTIwMUQgKHJlcXVlc3QtaW4tZmxpZ2h0KSBzdGF0ZVxuICAgIHRoaXMucGx1Z2luLndzQ2xpZW50Lm9uV29ya2luZ0NoYW5nZSA9ICh3b3JraW5nKSA9PiB7XG4gICAgICB0aGlzLmlzV29ya2luZyA9IHdvcmtpbmc7XG4gICAgICB0aGlzLl91cGRhdGVTZW5kQnV0dG9uKCk7XG4gICAgfTtcblxuICAgIC8vIFJlZmxlY3QgY3VycmVudCBzdGF0ZVxuICAgIHRoaXMuaXNDb25uZWN0ZWQgPSB0aGlzLnBsdWdpbi53c0NsaWVudC5zdGF0ZSA9PT0gJ2Nvbm5lY3RlZCc7XG4gICAgdGhpcy5zdGF0dXNEb3QudG9nZ2xlQ2xhc3MoJ2Nvbm5lY3RlZCcsIHRoaXMuaXNDb25uZWN0ZWQpO1xuICAgIHRoaXMuX3VwZGF0ZVNlbmRCdXR0b24oKTtcblxuICAgIHRoaXMuX3JlbmRlck1lc3NhZ2VzKHRoaXMuY2hhdE1hbmFnZXIuZ2V0TWVzc2FnZXMoKSk7XG4gIH1cblxuICBhc3luYyBvbkNsb3NlKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIHRoaXMuY2hhdE1hbmFnZXIub25VcGRhdGUgPSBudWxsO1xuICAgIHRoaXMuY2hhdE1hbmFnZXIub25NZXNzYWdlQWRkZWQgPSBudWxsO1xuICAgIHRoaXMucGx1Z2luLndzQ2xpZW50Lm9uU3RhdGVDaGFuZ2UgPSBudWxsO1xuICAgIHRoaXMucGx1Z2luLndzQ2xpZW50Lm9uV29ya2luZ0NoYW5nZSA9IG51bGw7XG4gIH1cblxuICAvLyBcdTI1MDBcdTI1MDAgVUkgY29uc3RydWN0aW9uIFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFxuXG4gIHByaXZhdGUgX2J1aWxkVUkoKTogdm9pZCB7XG4gICAgY29uc3Qgcm9vdCA9IHRoaXMuY29udGVudEVsO1xuICAgIHJvb3QuZW1wdHkoKTtcbiAgICByb290LmFkZENsYXNzKCdvY2xhdy1jaGF0LXZpZXcnKTtcblxuICAgIC8vIFx1MjUwMFx1MjUwMCBIZWFkZXIgXHUyNTAwXHUyNTAwXG4gICAgY29uc3QgaGVhZGVyID0gcm9vdC5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1oZWFkZXInIH0pO1xuICAgIGhlYWRlci5jcmVhdGVTcGFuKHsgY2xzOiAnb2NsYXctaGVhZGVyLXRpdGxlJywgdGV4dDogJ09wZW5DbGF3IENoYXQnIH0pO1xuICAgIHRoaXMuc3RhdHVzRG90ID0gaGVhZGVyLmNyZWF0ZURpdih7IGNsczogJ29jbGF3LXN0YXR1cy1kb3QnIH0pO1xuICAgIHRoaXMuc3RhdHVzRG90LnRpdGxlID0gJ0dhdGV3YXk6IGRpc2Nvbm5lY3RlZCc7XG5cbiAgICAvLyBcdTI1MDBcdTI1MDAgTWVzc2FnZXMgYXJlYSBcdTI1MDBcdTI1MDBcbiAgICB0aGlzLm1lc3NhZ2VzRWwgPSByb290LmNyZWF0ZURpdih7IGNsczogJ29jbGF3LW1lc3NhZ2VzJyB9KTtcblxuICAgIC8vIFx1MjUwMFx1MjUwMCBDb250ZXh0IHJvdyBcdTI1MDBcdTI1MDBcbiAgICBjb25zdCBjdHhSb3cgPSByb290LmNyZWF0ZURpdih7IGNsczogJ29jbGF3LWNvbnRleHQtcm93JyB9KTtcbiAgICB0aGlzLmluY2x1ZGVOb3RlQ2hlY2tib3ggPSBjdHhSb3cuY3JlYXRlRWwoJ2lucHV0JywgeyB0eXBlOiAnY2hlY2tib3gnIH0pO1xuICAgIHRoaXMuaW5jbHVkZU5vdGVDaGVja2JveC5pZCA9ICdvY2xhdy1pbmNsdWRlLW5vdGUnO1xuICAgIHRoaXMuaW5jbHVkZU5vdGVDaGVja2JveC5jaGVja2VkID0gdGhpcy5wbHVnaW4uc2V0dGluZ3MuaW5jbHVkZUFjdGl2ZU5vdGU7XG4gICAgY29uc3QgY3R4TGFiZWwgPSBjdHhSb3cuY3JlYXRlRWwoJ2xhYmVsJywgeyB0ZXh0OiAnSW5jbHVkZSBhY3RpdmUgbm90ZScgfSk7XG4gICAgY3R4TGFiZWwuaHRtbEZvciA9ICdvY2xhdy1pbmNsdWRlLW5vdGUnO1xuXG4gICAgLy8gXHUyNTAwXHUyNTAwIElucHV0IHJvdyBcdTI1MDBcdTI1MDBcbiAgICBjb25zdCBpbnB1dFJvdyA9IHJvb3QuY3JlYXRlRGl2KHsgY2xzOiAnb2NsYXctaW5wdXQtcm93JyB9KTtcbiAgICB0aGlzLmlucHV0RWwgPSBpbnB1dFJvdy5jcmVhdGVFbCgndGV4dGFyZWEnLCB7XG4gICAgICBjbHM6ICdvY2xhdy1pbnB1dCcsXG4gICAgICBwbGFjZWhvbGRlcjogJ0FzayBhbnl0aGluZ1x1MjAyNicsXG4gICAgfSk7XG4gICAgdGhpcy5pbnB1dEVsLnJvd3MgPSAxO1xuXG4gICAgdGhpcy5zZW5kQnRuID0gaW5wdXRSb3cuY3JlYXRlRWwoJ2J1dHRvbicsIHsgY2xzOiAnb2NsYXctc2VuZC1idG4nLCB0ZXh0OiAnU2VuZCcgfSk7XG5cbiAgICAvLyBcdTI1MDBcdTI1MDAgRXZlbnQgbGlzdGVuZXJzIFx1MjUwMFx1MjUwMFxuICAgIHRoaXMuc2VuZEJ0bi5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpID0+IHRoaXMuX2hhbmRsZVNlbmQoKSk7XG4gICAgdGhpcy5pbnB1dEVsLmFkZEV2ZW50TGlzdGVuZXIoJ2tleWRvd24nLCAoZSkgPT4ge1xuICAgICAgaWYgKGUua2V5ID09PSAnRW50ZXInICYmICFlLnNoaWZ0S2V5KSB7XG4gICAgICAgIGUucHJldmVudERlZmF1bHQoKTtcbiAgICAgICAgdGhpcy5faGFuZGxlU2VuZCgpO1xuICAgICAgfVxuICAgIH0pO1xuICAgIC8vIEF1dG8tcmVzaXplIHRleHRhcmVhXG4gICAgdGhpcy5pbnB1dEVsLmFkZEV2ZW50TGlzdGVuZXIoJ2lucHV0JywgKCkgPT4ge1xuICAgICAgdGhpcy5pbnB1dEVsLnN0eWxlLmhlaWdodCA9ICdhdXRvJztcbiAgICAgIHRoaXMuaW5wdXRFbC5zdHlsZS5oZWlnaHQgPSBgJHt0aGlzLmlucHV0RWwuc2Nyb2xsSGVpZ2h0fXB4YDtcbiAgICB9KTtcbiAgfVxuXG4gIC8vIFx1MjUwMFx1MjUwMCBNZXNzYWdlIHJlbmRlcmluZyBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcblxuICBwcml2YXRlIF9yZW5kZXJNZXNzYWdlcyhtZXNzYWdlczogcmVhZG9ubHkgQ2hhdE1lc3NhZ2VbXSk6IHZvaWQge1xuICAgIHRoaXMubWVzc2FnZXNFbC5lbXB0eSgpO1xuXG4gICAgaWYgKG1lc3NhZ2VzLmxlbmd0aCA9PT0gMCkge1xuICAgICAgdGhpcy5tZXNzYWdlc0VsLmNyZWF0ZUVsKCdwJywge1xuICAgICAgICB0ZXh0OiAnU2VuZCBhIG1lc3NhZ2UgdG8gc3RhcnQgY2hhdHRpbmcuJyxcbiAgICAgICAgY2xzOiAnb2NsYXctbWVzc2FnZSBzeXN0ZW0gb2NsYXctcGxhY2Vob2xkZXInLFxuICAgICAgfSk7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgZm9yIChjb25zdCBtc2cgb2YgbWVzc2FnZXMpIHtcbiAgICAgIHRoaXMuX2FwcGVuZE1lc3NhZ2UobXNnKTtcbiAgICB9XG5cbiAgICAvLyBTY3JvbGwgdG8gYm90dG9tXG4gICAgdGhpcy5tZXNzYWdlc0VsLnNjcm9sbFRvcCA9IHRoaXMubWVzc2FnZXNFbC5zY3JvbGxIZWlnaHQ7XG4gIH1cblxuICAvKiogQXBwZW5kcyBhIHNpbmdsZSBtZXNzYWdlIHdpdGhvdXQgcmVidWlsZGluZyB0aGUgRE9NIChPKDEpKSAqL1xuICBwcml2YXRlIF9hcHBlbmRNZXNzYWdlKG1zZzogQ2hhdE1lc3NhZ2UpOiB2b2lkIHtcbiAgICAvLyBSZW1vdmUgZW1wdHktc3RhdGUgcGxhY2Vob2xkZXIgaWYgcHJlc2VudFxuICAgIHRoaXMubWVzc2FnZXNFbC5xdWVyeVNlbGVjdG9yKCcub2NsYXctcGxhY2Vob2xkZXInKT8ucmVtb3ZlKCk7XG5cbiAgICBjb25zdCBsZXZlbENsYXNzID0gbXNnLmxldmVsID8gYCAke21zZy5sZXZlbH1gIDogJyc7XG4gICAgY29uc3QgZWwgPSB0aGlzLm1lc3NhZ2VzRWwuY3JlYXRlRGl2KHsgY2xzOiBgb2NsYXctbWVzc2FnZSAke21zZy5yb2xlfSR7bGV2ZWxDbGFzc31gIH0pO1xuICAgIGNvbnN0IGJvZHkgPSBlbC5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1tZXNzYWdlLWJvZHknIH0pO1xuXG4gICAgLy8gUmVuZGVyIGFzc2lzdGFudCBtZXNzYWdlcyBhcyBNYXJrZG93biAodW50cnVzdGVkIGNvbnRlbnQgXHUyMTkyIGtlZXAgdXNlci9zeXN0ZW0gcGxhaW4pXG4gICAgaWYgKG1zZy5yb2xlID09PSAnYXNzaXN0YW50Jykge1xuICAgICAgY29uc3Qgc291cmNlUGF0aCA9IHRoaXMuYXBwLndvcmtzcGFjZS5nZXRBY3RpdmVGaWxlKCk/LnBhdGggPz8gJyc7XG4gICAgICB2b2lkIE1hcmtkb3duUmVuZGVyZXIucmVuZGVyTWFya2Rvd24obXNnLmNvbnRlbnQsIGJvZHksIHNvdXJjZVBhdGgsIHRoaXMucGx1Z2luKTtcbiAgICB9IGVsc2Uge1xuICAgICAgYm9keS5zZXRUZXh0KG1zZy5jb250ZW50KTtcbiAgICB9XG5cbiAgICAvLyBTY3JvbGwgdG8gYm90dG9tXG4gICAgdGhpcy5tZXNzYWdlc0VsLnNjcm9sbFRvcCA9IHRoaXMubWVzc2FnZXNFbC5zY3JvbGxIZWlnaHQ7XG4gIH1cblxuICBwcml2YXRlIF91cGRhdGVTZW5kQnV0dG9uKCk6IHZvaWQge1xuICAgIC8vIERpc2Nvbm5lY3RlZDogZGlzYWJsZS5cbiAgICAvLyBXb3JraW5nOiBrZWVwIGVuYWJsZWQgc28gdXNlciBjYW4gc3RvcC9hYm9ydC5cbiAgICBjb25zdCBkaXNhYmxlZCA9ICF0aGlzLmlzQ29ubmVjdGVkO1xuICAgIHRoaXMuc2VuZEJ0bi5kaXNhYmxlZCA9IGRpc2FibGVkO1xuXG4gICAgdGhpcy5zZW5kQnRuLnRvZ2dsZUNsYXNzKCdpcy13b3JraW5nJywgdGhpcy5pc1dvcmtpbmcpO1xuICAgIHRoaXMuc2VuZEJ0bi5zZXRBdHRyKCdhcmlhLWJ1c3knLCB0aGlzLmlzV29ya2luZyA/ICd0cnVlJyA6ICdmYWxzZScpO1xuICAgIHRoaXMuc2VuZEJ0bi5zZXRBdHRyKCdhcmlhLWxhYmVsJywgdGhpcy5pc1dvcmtpbmcgPyAnU3RvcCcgOiAnU2VuZCcpO1xuXG4gICAgaWYgKHRoaXMuaXNXb3JraW5nKSB7XG4gICAgICAvLyBSZXBsYWNlIGJ1dHRvbiBjb250ZW50cyB3aXRoIFN0b3AgaWNvbiArIHNwaW5uZXIgcmluZy5cbiAgICAgIHRoaXMuc2VuZEJ0bi5lbXB0eSgpO1xuICAgICAgY29uc3Qgd3JhcCA9IHRoaXMuc2VuZEJ0bi5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1zdG9wLXdyYXAnIH0pO1xuICAgICAgd3JhcC5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1zcGlubmVyLXJpbmcnLCBhdHRyOiB7ICdhcmlhLWhpZGRlbic6ICd0cnVlJyB9IH0pO1xuICAgICAgd3JhcC5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1zdG9wLWljb24nLCBhdHRyOiB7ICdhcmlhLWhpZGRlbic6ICd0cnVlJyB9IH0pO1xuICAgIH0gZWxzZSB7XG4gICAgICAvLyBSZXN0b3JlIGxhYmVsXG4gICAgICB0aGlzLnNlbmRCdG4uc2V0VGV4dCgnU2VuZCcpO1xuICAgIH1cbiAgfVxuXG4gIC8vIFx1MjUwMFx1MjUwMCBTZW5kIGhhbmRsZXIgXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG5cbiAgcHJpdmF0ZSBhc3luYyBfaGFuZGxlU2VuZCgpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICAvLyBXaGlsZSB3b3JraW5nLCB0aGUgYnV0dG9uIGJlY29tZXMgU3RvcC5cbiAgICBpZiAodGhpcy5pc1dvcmtpbmcpIHtcbiAgICAgIGNvbnN0IG9rID0gYXdhaXQgdGhpcy5wbHVnaW4ud3NDbGllbnQuYWJvcnRBY3RpdmVSdW4oKTtcbiAgICAgIGlmICghb2spIHtcbiAgICAgICAgbmV3IE5vdGljZSgnT3BlbkNsYXcgQ2hhdDogZmFpbGVkIHRvIHN0b3AnKTtcbiAgICAgICAgdGhpcy5jaGF0TWFuYWdlci5hZGRNZXNzYWdlKENoYXRNYW5hZ2VyLmNyZWF0ZVN5c3RlbU1lc3NhZ2UoJ1x1MjZBMCBTdG9wIGZhaWxlZCcsICdlcnJvcicpKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHRoaXMuY2hhdE1hbmFnZXIuYWRkTWVzc2FnZShDaGF0TWFuYWdlci5jcmVhdGVTeXN0ZW1NZXNzYWdlKCdcdTI2RDQgU3RvcHBlZCcsICdpbmZvJykpO1xuICAgICAgfVxuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIGNvbnN0IHRleHQgPSB0aGlzLmlucHV0RWwudmFsdWUudHJpbSgpO1xuICAgIGlmICghdGV4dCkgcmV0dXJuO1xuXG4gICAgLy8gQnVpbGQgbWVzc2FnZSB3aXRoIGNvbnRleHQgaWYgZW5hYmxlZFxuICAgIGxldCBtZXNzYWdlID0gdGV4dDtcbiAgICBpZiAodGhpcy5pbmNsdWRlTm90ZUNoZWNrYm94LmNoZWNrZWQpIHtcbiAgICAgIGNvbnN0IG5vdGUgPSBhd2FpdCBnZXRBY3RpdmVOb3RlQ29udGV4dCh0aGlzLmFwcCk7XG4gICAgICBpZiAobm90ZSkge1xuICAgICAgICBtZXNzYWdlID0gYENvbnRleHQ6IFtbJHtub3RlLnRpdGxlfV1dXFxuXFxuJHt0ZXh0fWA7XG4gICAgICB9XG4gICAgfVxuXG4gICAgLy8gQWRkIHVzZXIgbWVzc2FnZSB0byBjaGF0IFVJXG4gICAgY29uc3QgdXNlck1zZyA9IENoYXRNYW5hZ2VyLmNyZWF0ZVVzZXJNZXNzYWdlKHRleHQpO1xuICAgIHRoaXMuY2hhdE1hbmFnZXIuYWRkTWVzc2FnZSh1c2VyTXNnKTtcblxuICAgIC8vIENsZWFyIGlucHV0XG4gICAgdGhpcy5pbnB1dEVsLnZhbHVlID0gJyc7XG4gICAgdGhpcy5pbnB1dEVsLnN0eWxlLmhlaWdodCA9ICdhdXRvJztcblxuICAgIC8vIFNlbmQgb3ZlciBXUyAoYXN5bmMpXG4gICAgdHJ5IHtcbiAgICAgIGF3YWl0IHRoaXMucGx1Z2luLndzQ2xpZW50LnNlbmRNZXNzYWdlKG1lc3NhZ2UpO1xuICAgIH0gY2F0Y2ggKGVycikge1xuICAgICAgY29uc29sZS5lcnJvcignW29jbGF3XSBTZW5kIGZhaWxlZCcsIGVycik7XG4gICAgICBuZXcgTm90aWNlKGBPcGVuQ2xhdyBDaGF0OiBzZW5kIGZhaWxlZCAoJHtTdHJpbmcoZXJyKX0pYCk7XG4gICAgICB0aGlzLmNoYXRNYW5hZ2VyLmFkZE1lc3NhZ2UoXG4gICAgICAgIENoYXRNYW5hZ2VyLmNyZWF0ZVN5c3RlbU1lc3NhZ2UoYFx1MjZBMCBTZW5kIGZhaWxlZDogJHtlcnJ9YCwgJ2Vycm9yJylcbiAgICAgICk7XG4gICAgfVxuICB9XG59XG4iLCAiaW1wb3J0IHR5cGUgeyBBcHAgfSBmcm9tICdvYnNpZGlhbic7XG5cbmV4cG9ydCBpbnRlcmZhY2UgTm90ZUNvbnRleHQge1xuICB0aXRsZTogc3RyaW5nO1xuICBwYXRoOiBzdHJpbmc7XG4gIGNvbnRlbnQ6IHN0cmluZztcbn1cblxuLyoqXG4gKiBSZXR1cm5zIHRoZSBhY3RpdmUgbm90ZSdzIHRpdGxlIGFuZCBjb250ZW50LCBvciBudWxsIGlmIG5vIG5vdGUgaXMgb3Blbi5cbiAqIEFzeW5jIGJlY2F1c2UgdmF1bHQucmVhZCgpIGlzIGFzeW5jLlxuICovXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZ2V0QWN0aXZlTm90ZUNvbnRleHQoYXBwOiBBcHApOiBQcm9taXNlPE5vdGVDb250ZXh0IHwgbnVsbD4ge1xuICBjb25zdCBmaWxlID0gYXBwLndvcmtzcGFjZS5nZXRBY3RpdmVGaWxlKCk7XG4gIGlmICghZmlsZSkgcmV0dXJuIG51bGw7XG5cbiAgdHJ5IHtcbiAgICBjb25zdCBjb250ZW50ID0gYXdhaXQgYXBwLnZhdWx0LnJlYWQoZmlsZSk7XG4gICAgcmV0dXJuIHtcbiAgICAgIHRpdGxlOiBmaWxlLmJhc2VuYW1lLFxuICAgICAgcGF0aDogZmlsZS5wYXRoLFxuICAgICAgY29udGVudCxcbiAgICB9O1xuICB9IGNhdGNoIChlcnIpIHtcbiAgICBjb25zb2xlLmVycm9yKCdbb2NsYXctY29udGV4dF0gRmFpbGVkIHRvIHJlYWQgYWN0aXZlIG5vdGUnLCBlcnIpO1xuICAgIHJldHVybiBudWxsO1xuICB9XG59XG4iLCAiLyoqIFBlcnNpc3RlZCBwbHVnaW4gY29uZmlndXJhdGlvbiAqL1xuZXhwb3J0IGludGVyZmFjZSBPcGVuQ2xhd1NldHRpbmdzIHtcbiAgLyoqIFdlYlNvY2tldCBVUkwgb2YgdGhlIE9wZW5DbGF3IEdhdGV3YXkgKGUuZy4gd3M6Ly8xMDAuOTAuOS42ODoxODc4OSkgKi9cbiAgZ2F0ZXdheVVybDogc3RyaW5nO1xuICAvKiogQXV0aCB0b2tlbiBcdTIwMTQgbXVzdCBtYXRjaCB0aGUgY2hhbm5lbCBwbHVnaW4ncyBhdXRoVG9rZW4gKi9cbiAgYXV0aFRva2VuOiBzdHJpbmc7XG4gIC8qKiBPcGVuQ2xhdyBzZXNzaW9uIGtleSB0byBzdWJzY3JpYmUgdG8gKGUuZy4gXCJtYWluXCIpICovXG4gIHNlc3Npb25LZXk6IHN0cmluZztcbiAgLyoqIChEZXByZWNhdGVkKSBPcGVuQ2xhdyBhY2NvdW50IElEICh1bnVzZWQ7IGNoYXQuc2VuZCB1c2VzIHNlc3Npb25LZXkpICovXG4gIGFjY291bnRJZDogc3RyaW5nO1xuICAvKiogV2hldGhlciB0byBpbmNsdWRlIHRoZSBhY3RpdmUgbm90ZSBjb250ZW50IHdpdGggZWFjaCBtZXNzYWdlICovXG4gIGluY2x1ZGVBY3RpdmVOb3RlOiBib29sZWFuO1xufVxuXG5leHBvcnQgY29uc3QgREVGQVVMVF9TRVRUSU5HUzogT3BlbkNsYXdTZXR0aW5ncyA9IHtcbiAgZ2F0ZXdheVVybDogJ3dzOi8vbG9jYWxob3N0OjE4Nzg5JyxcbiAgYXV0aFRva2VuOiAnJyxcbiAgc2Vzc2lvbktleTogJ21haW4nLFxuICBhY2NvdW50SWQ6ICdtYWluJyxcbiAgaW5jbHVkZUFjdGl2ZU5vdGU6IGZhbHNlLFxufTtcblxuLyoqIEEgc2luZ2xlIGNoYXQgbWVzc2FnZSAqL1xuZXhwb3J0IGludGVyZmFjZSBDaGF0TWVzc2FnZSB7XG4gIGlkOiBzdHJpbmc7XG4gIHJvbGU6ICd1c2VyJyB8ICdhc3Npc3RhbnQnIHwgJ3N5c3RlbSc7XG4gIC8qKiBPcHRpb25hbCBzZXZlcml0eSBmb3Igc3lzdGVtL3N0YXR1cyBtZXNzYWdlcyAqL1xuICBsZXZlbD86ICdpbmZvJyB8ICdlcnJvcic7XG4gIGNvbnRlbnQ6IHN0cmluZztcbiAgdGltZXN0YW1wOiBudW1iZXI7XG59XG5cbi8qKiBQYXlsb2FkIGZvciBtZXNzYWdlcyBTRU5UIHRvIHRoZSBzZXJ2ZXIgKG91dGJvdW5kKSAqL1xuZXhwb3J0IGludGVyZmFjZSBXU1BheWxvYWQge1xuICB0eXBlOiAnYXV0aCcgfCAnbWVzc2FnZScgfCAncGluZycgfCAncG9uZycgfCAnZXJyb3InO1xuICBwYXlsb2FkPzogUmVjb3JkPHN0cmluZywgdW5rbm93bj47XG59XG5cbi8qKiBNZXNzYWdlcyBSRUNFSVZFRCBmcm9tIHRoZSBzZXJ2ZXIgKGluYm91bmQpIFx1MjAxNCBkaXNjcmltaW5hdGVkIHVuaW9uICovXG5leHBvcnQgdHlwZSBJbmJvdW5kV1NQYXlsb2FkID1cbiAgfCB7IHR5cGU6ICdtZXNzYWdlJzsgcGF5bG9hZDogeyBjb250ZW50OiBzdHJpbmc7IHJvbGU6IHN0cmluZzsgdGltZXN0YW1wOiBudW1iZXIgfSB9XG4gIHwgeyB0eXBlOiAnZXJyb3InOyBwYXlsb2FkOiB7IG1lc3NhZ2U6IHN0cmluZyB9IH07XG5cbi8qKiBBdmFpbGFibGUgYWdlbnRzIC8gbW9kZWxzICovXG5leHBvcnQgaW50ZXJmYWNlIEFnZW50T3B0aW9uIHtcbiAgaWQ6IHN0cmluZztcbiAgbGFiZWw6IHN0cmluZztcbn1cbiJdLAogICJtYXBwaW5ncyI6ICI7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUEsSUFBQUEsbUJBQThDOzs7QUNBOUMsc0JBQStDO0FBR3hDLElBQU0scUJBQU4sY0FBaUMsaUNBQWlCO0FBQUEsRUFHdkQsWUFBWSxLQUFVLFFBQXdCO0FBQzVDLFVBQU0sS0FBSyxNQUFNO0FBQ2pCLFNBQUssU0FBUztBQUFBLEVBQ2hCO0FBQUEsRUFFQSxVQUFnQjtBQUNkLFVBQU0sRUFBRSxZQUFZLElBQUk7QUFDeEIsZ0JBQVksTUFBTTtBQUVsQixnQkFBWSxTQUFTLE1BQU0sRUFBRSxNQUFNLGdDQUEyQixDQUFDO0FBRS9ELFFBQUksd0JBQVEsV0FBVyxFQUNwQixRQUFRLGFBQWEsRUFDckIsUUFBUSxtRUFBbUUsRUFDM0U7QUFBQSxNQUFRLENBQUMsU0FDUixLQUNHLGVBQWUsc0JBQXNCLEVBQ3JDLFNBQVMsS0FBSyxPQUFPLFNBQVMsVUFBVSxFQUN4QyxTQUFTLENBQU8sVUFBVTtBQUN6QixhQUFLLE9BQU8sU0FBUyxhQUFhLE1BQU0sS0FBSztBQUM3QyxjQUFNLEtBQUssT0FBTyxhQUFhO0FBQUEsTUFDakMsRUFBQztBQUFBLElBQ0w7QUFFRixRQUFJLHdCQUFRLFdBQVcsRUFDcEIsUUFBUSxZQUFZLEVBQ3BCLFFBQVEsOEVBQThFLEVBQ3RGLFFBQVEsQ0FBQyxTQUFTO0FBQ2pCLFdBQ0csZUFBZSxtQkFBYyxFQUM3QixTQUFTLEtBQUssT0FBTyxTQUFTLFNBQVMsRUFDdkMsU0FBUyxDQUFPLFVBQVU7QUFDekIsYUFBSyxPQUFPLFNBQVMsWUFBWTtBQUNqQyxjQUFNLEtBQUssT0FBTyxhQUFhO0FBQUEsTUFDakMsRUFBQztBQUVILFdBQUssUUFBUSxPQUFPO0FBQ3BCLFdBQUssUUFBUSxlQUFlO0FBQUEsSUFDOUIsQ0FBQztBQUVILFFBQUksd0JBQVEsV0FBVyxFQUNwQixRQUFRLGFBQWEsRUFDckIsUUFBUSxvREFBb0QsRUFDNUQ7QUFBQSxNQUFRLENBQUMsU0FDUixLQUNHLGVBQWUsTUFBTSxFQUNyQixTQUFTLEtBQUssT0FBTyxTQUFTLFVBQVUsRUFDeEMsU0FBUyxDQUFPLFVBQVU7QUFDekIsYUFBSyxPQUFPLFNBQVMsYUFBYSxNQUFNLEtBQUssS0FBSztBQUNsRCxjQUFNLEtBQUssT0FBTyxhQUFhO0FBQUEsTUFDakMsRUFBQztBQUFBLElBQ0w7QUFFRixRQUFJLHdCQUFRLFdBQVcsRUFDcEIsUUFBUSxZQUFZLEVBQ3BCLFFBQVEsdUNBQXVDLEVBQy9DO0FBQUEsTUFBUSxDQUFDLFNBQ1IsS0FDRyxlQUFlLE1BQU0sRUFDckIsU0FBUyxLQUFLLE9BQU8sU0FBUyxTQUFTLEVBQ3ZDLFNBQVMsQ0FBTyxVQUFVO0FBQ3pCLGFBQUssT0FBTyxTQUFTLFlBQVksTUFBTSxLQUFLLEtBQUs7QUFDakQsY0FBTSxLQUFLLE9BQU8sYUFBYTtBQUFBLE1BQ2pDLEVBQUM7QUFBQSxJQUNMO0FBRUYsUUFBSSx3QkFBUSxXQUFXLEVBQ3BCLFFBQVEsZ0NBQWdDLEVBQ3hDLFFBQVEsa0VBQWtFLEVBQzFFO0FBQUEsTUFBVSxDQUFDLFdBQ1YsT0FBTyxTQUFTLEtBQUssT0FBTyxTQUFTLGlCQUFpQixFQUFFLFNBQVMsQ0FBTyxVQUFVO0FBQ2hGLGFBQUssT0FBTyxTQUFTLG9CQUFvQjtBQUN6QyxjQUFNLEtBQUssT0FBTyxhQUFhO0FBQUEsTUFDakMsRUFBQztBQUFBLElBQ0g7QUFFRixnQkFBWSxTQUFTLEtBQUs7QUFBQSxNQUN4QixNQUFNO0FBQUEsTUFDTixLQUFLO0FBQUEsSUFDUCxDQUFDO0FBQUEsRUFDSDtBQUNGOzs7QUNyRUEsSUFBTSxxQkFBcUI7QUFFM0IsSUFBTSx3QkFBd0I7QUFHOUIsSUFBTSxpQkFBaUI7QUFrQnZCLElBQU0scUJBQXFCO0FBRTNCLFNBQVMsZ0JBQWdCLE9BQTRCO0FBQ25ELFFBQU0sS0FBSyxJQUFJLFdBQVcsS0FBSztBQUMvQixNQUFJLElBQUk7QUFDUixXQUFTLElBQUksR0FBRyxJQUFJLEdBQUcsUUFBUTtBQUFLLFNBQUssT0FBTyxhQUFhLEdBQUcsQ0FBQyxDQUFDO0FBQ2xFLFFBQU0sTUFBTSxLQUFLLENBQUM7QUFDbEIsU0FBTyxJQUFJLFFBQVEsT0FBTyxHQUFHLEVBQUUsUUFBUSxPQUFPLEdBQUcsRUFBRSxRQUFRLFFBQVEsRUFBRTtBQUN2RTtBQUVBLFNBQVMsVUFBVSxPQUE0QjtBQUM3QyxRQUFNLEtBQUssSUFBSSxXQUFXLEtBQUs7QUFDL0IsU0FBTyxNQUFNLEtBQUssRUFBRSxFQUNqQixJQUFJLENBQUMsTUFBTSxFQUFFLFNBQVMsRUFBRSxFQUFFLFNBQVMsR0FBRyxHQUFHLENBQUMsRUFDMUMsS0FBSyxFQUFFO0FBQ1o7QUFFQSxTQUFTLFVBQVUsTUFBMEI7QUFDM0MsU0FBTyxJQUFJLFlBQVksRUFBRSxPQUFPLElBQUk7QUFDdEM7QUFFQSxTQUFlLFVBQVUsT0FBcUM7QUFBQTtBQUM1RCxVQUFNLFNBQVMsTUFBTSxPQUFPLE9BQU8sT0FBTyxXQUFXLEtBQUs7QUFDMUQsV0FBTyxVQUFVLE1BQU07QUFBQSxFQUN6QjtBQUFBO0FBRUEsU0FBZSw2QkFBc0Q7QUFBQTtBQUNuRSxVQUFNLFdBQVcsYUFBYSxRQUFRLGtCQUFrQjtBQUN4RCxRQUFJLFVBQVU7QUFDWixZQUFNLFNBQVMsS0FBSyxNQUFNLFFBQVE7QUFDbEMsV0FBSSxpQ0FBUSxRQUFNLGlDQUFRLGVBQWEsaUNBQVE7QUFBZSxlQUFPO0FBQUEsSUFDdkU7QUFFQSxVQUFNLFVBQVUsTUFBTSxPQUFPLE9BQU8sWUFBWSxFQUFFLE1BQU0sVUFBVSxHQUFHLE1BQU0sQ0FBQyxRQUFRLFFBQVEsQ0FBQztBQUM3RixVQUFNLFNBQVMsTUFBTSxPQUFPLE9BQU8sVUFBVSxPQUFPLFFBQVEsU0FBUztBQUNyRSxVQUFNLFVBQVUsTUFBTSxPQUFPLE9BQU8sVUFBVSxPQUFPLFFBQVEsVUFBVTtBQUl2RSxVQUFNLFdBQVcsTUFBTSxVQUFVLE1BQU07QUFDdkMsVUFBTSxLQUFLO0FBRVgsVUFBTSxXQUEyQjtBQUFBLE1BQy9CO0FBQUEsTUFDQSxXQUFXLGdCQUFnQixNQUFNO0FBQUEsTUFDakMsZUFBZTtBQUFBLElBQ2pCO0FBRUEsaUJBQWEsUUFBUSxvQkFBb0IsS0FBSyxVQUFVLFFBQVEsQ0FBQztBQUNqRSxXQUFPO0FBQUEsRUFDVDtBQUFBO0FBRUEsU0FBUyx1QkFBdUIsUUFTckI7QUFDVCxRQUFNLFVBQVUsT0FBTyxRQUFRLE9BQU87QUFDdEMsUUFBTSxTQUFTLE9BQU8sT0FBTyxLQUFLLEdBQUc7QUFDckMsUUFBTSxPQUFPO0FBQUEsSUFDWDtBQUFBLElBQ0EsT0FBTztBQUFBLElBQ1AsT0FBTztBQUFBLElBQ1AsT0FBTztBQUFBLElBQ1AsT0FBTztBQUFBLElBQ1A7QUFBQSxJQUNBLE9BQU8sT0FBTyxVQUFVO0FBQUEsSUFDeEIsT0FBTyxTQUFTO0FBQUEsRUFDbEI7QUFDQSxNQUFJLFlBQVk7QUFBTSxTQUFLLEtBQUssT0FBTyxTQUFTLEVBQUU7QUFDbEQsU0FBTyxLQUFLLEtBQUssR0FBRztBQUN0QjtBQUVBLFNBQWUsa0JBQWtCLFVBQTBCLFNBQW1FO0FBQUE7QUFDNUgsVUFBTSxhQUFhLE1BQU0sT0FBTyxPQUFPO0FBQUEsTUFDckM7QUFBQSxNQUNBLFNBQVM7QUFBQSxNQUNULEVBQUUsTUFBTSxVQUFVO0FBQUEsTUFDbEI7QUFBQSxNQUNBLENBQUMsTUFBTTtBQUFBLElBQ1Q7QUFFQSxVQUFNLFdBQVcsS0FBSyxJQUFJO0FBQzFCLFVBQU0sTUFBTSxNQUFNLE9BQU8sT0FBTyxLQUFLLEVBQUUsTUFBTSxVQUFVLEdBQUcsWUFBWSxVQUFVLE9BQU8sQ0FBNEI7QUFDbkgsV0FBTyxFQUFFLFdBQVcsZ0JBQWdCLEdBQUcsR0FBRyxTQUFTO0FBQUEsRUFDckQ7QUFBQTtBQUVBLFNBQVMsOEJBQThCLEtBQWtCO0FBckl6RDtBQXNJRSxNQUFJLENBQUM7QUFBSyxXQUFPO0FBR2pCLFFBQU0sV0FBVSxlQUFJLFlBQUosWUFBZSxJQUFJLFlBQW5CLFlBQThCO0FBQzlDLE1BQUksT0FBTyxZQUFZO0FBQVUsV0FBTztBQUV4QyxNQUFJLE1BQU0sUUFBUSxPQUFPLEdBQUc7QUFDMUIsVUFBTSxRQUFRLFFBQ1gsT0FBTyxDQUFDLE1BQU0sS0FBSyxPQUFPLE1BQU0sWUFBWSxFQUFFLFNBQVMsVUFBVSxPQUFPLEVBQUUsU0FBUyxRQUFRLEVBQzNGLElBQUksQ0FBQyxNQUFNLEVBQUUsSUFBSTtBQUNwQixXQUFPLE1BQU0sS0FBSyxJQUFJO0FBQUEsRUFDeEI7QUFHQSxNQUFJO0FBQ0YsV0FBTyxLQUFLLFVBQVUsT0FBTztBQUFBLEVBQy9CLFNBQVE7QUFDTixXQUFPLE9BQU8sT0FBTztBQUFBLEVBQ3ZCO0FBQ0Y7QUFFQSxTQUFTLGtCQUFrQixZQUFvQixVQUEyQjtBQUN4RSxNQUFJLGFBQWE7QUFBWSxXQUFPO0FBRXBDLE1BQUksZUFBZSxVQUFVLGFBQWE7QUFBbUIsV0FBTztBQUNwRSxTQUFPO0FBQ1Q7QUFFTyxJQUFNLG1CQUFOLE1BQXVCO0FBQUEsRUF5QjVCLFlBQVksWUFBb0I7QUF4QmhDLFNBQVEsS0FBdUI7QUFDL0IsU0FBUSxpQkFBdUQ7QUFDL0QsU0FBUSxpQkFBd0Q7QUFDaEUsU0FBUSxlQUFxRDtBQUM3RCxTQUFRLG1CQUFtQjtBQUUzQixTQUFRLE1BQU07QUFDZCxTQUFRLFFBQVE7QUFDaEIsU0FBUSxZQUFZO0FBQ3BCLFNBQVEsa0JBQWtCLG9CQUFJLElBQTRCO0FBQzFELFNBQVEsVUFBVTtBQUdsQjtBQUFBLFNBQVEsY0FBNkI7QUFHckM7QUFBQSxTQUFRLGdCQUF5QztBQUVqRCxpQkFBdUI7QUFFdkIscUJBQXNEO0FBQ3RELHlCQUF5RDtBQUN6RCwyQkFBK0M7QUFHN0MsU0FBSyxhQUFhO0FBQUEsRUFDcEI7QUFBQSxFQUVBLFFBQVEsS0FBYSxPQUFxQjtBQUN4QyxTQUFLLE1BQU07QUFDWCxTQUFLLFFBQVE7QUFDYixTQUFLLG1CQUFtQjtBQUN4QixTQUFLLFNBQVM7QUFBQSxFQUNoQjtBQUFBLEVBRUEsYUFBbUI7QUFDakIsU0FBSyxtQkFBbUI7QUFDeEIsU0FBSyxZQUFZO0FBQ2pCLFNBQUssY0FBYztBQUNuQixTQUFLLFlBQVksS0FBSztBQUN0QixRQUFJLEtBQUssSUFBSTtBQUNYLFdBQUssR0FBRyxNQUFNO0FBQ2QsV0FBSyxLQUFLO0FBQUEsSUFDWjtBQUNBLFNBQUssVUFBVSxjQUFjO0FBQUEsRUFDL0I7QUFBQSxFQUVNLFlBQVksU0FBZ0M7QUFBQTtBQUNoRCxVQUFJLEtBQUssVUFBVSxhQUFhO0FBQzlCLGNBQU0sSUFBSSxNQUFNLDJDQUFzQztBQUFBLE1BQ3hEO0FBRUEsWUFBTSxRQUFRLFlBQVksS0FBSyxJQUFJLENBQUMsSUFBSSxLQUFLLE9BQU8sRUFBRSxTQUFTLEVBQUUsRUFBRSxNQUFNLEdBQUcsQ0FBQyxDQUFDO0FBRzlFLFlBQU0sS0FBSyxhQUFhLGFBQWE7QUFBQSxRQUNuQyxZQUFZLEtBQUs7QUFBQSxRQUNqQjtBQUFBLFFBQ0EsZ0JBQWdCO0FBQUE7QUFBQSxNQUVsQixDQUFDO0FBRUQsV0FBSyxjQUFjO0FBQ25CLFdBQUssWUFBWSxJQUFJO0FBQ3JCLFdBQUsseUJBQXlCO0FBQUEsSUFDaEM7QUFBQTtBQUFBO0FBQUEsRUFHTSxpQkFBbUM7QUFBQTtBQUN2QyxVQUFJLEtBQUssVUFBVSxhQUFhO0FBQzlCLGVBQU87QUFBQSxNQUNUO0FBR0EsVUFBSSxLQUFLLGVBQWU7QUFDdEIsZUFBTyxLQUFLO0FBQUEsTUFDZDtBQUVBLFlBQU0sUUFBUSxLQUFLO0FBRW5CLFdBQUssaUJBQWlCLE1BQVk7QUFDaEMsWUFBSTtBQUNGLGdCQUFNLEtBQUssYUFBYSxjQUFjLFFBQVEsRUFBRSxZQUFZLEtBQUssWUFBWSxNQUFNLElBQUksRUFBRSxZQUFZLEtBQUssV0FBVyxDQUFDO0FBQ3RILGlCQUFPO0FBQUEsUUFDVCxTQUFTLEtBQUs7QUFDWixrQkFBUSxNQUFNLGdDQUFnQyxHQUFHO0FBQ2pELGlCQUFPO0FBQUEsUUFDVCxVQUFFO0FBRUEsZUFBSyxjQUFjO0FBQ25CLGVBQUssWUFBWSxLQUFLO0FBQ3RCLGVBQUssZ0JBQWdCO0FBQUEsUUFDdkI7QUFBQSxNQUNGLElBQUc7QUFFSCxhQUFPLEtBQUs7QUFBQSxJQUNkO0FBQUE7QUFBQSxFQUVRLFdBQWlCO0FBQ3ZCLFFBQUksS0FBSyxJQUFJO0FBQ1gsV0FBSyxHQUFHLFNBQVM7QUFDakIsV0FBSyxHQUFHLFVBQVU7QUFDbEIsV0FBSyxHQUFHLFlBQVk7QUFDcEIsV0FBSyxHQUFHLFVBQVU7QUFDbEIsV0FBSyxHQUFHLE1BQU07QUFDZCxXQUFLLEtBQUs7QUFBQSxJQUNaO0FBRUEsU0FBSyxVQUFVLFlBQVk7QUFFM0IsVUFBTSxLQUFLLElBQUksVUFBVSxLQUFLLEdBQUc7QUFDakMsU0FBSyxLQUFLO0FBRVYsUUFBSSxlQUE4QjtBQUNsQyxRQUFJLGlCQUFpQjtBQUVyQixVQUFNLGFBQWEsTUFBWTtBQUM3QixVQUFJO0FBQWdCO0FBQ3BCLFVBQUksQ0FBQztBQUFjO0FBQ25CLHVCQUFpQjtBQUVqQixVQUFJO0FBQ0YsY0FBTSxXQUFXLE1BQU0sMkJBQTJCO0FBQ2xELGNBQU0sYUFBYSxLQUFLLElBQUk7QUFDNUIsY0FBTSxVQUFVLHVCQUF1QjtBQUFBLFVBQ3JDLFVBQVUsU0FBUztBQUFBLFVBQ25CLFVBQVU7QUFBQSxVQUNWLFlBQVk7QUFBQSxVQUNaLE1BQU07QUFBQSxVQUNOLFFBQVEsQ0FBQyxpQkFBaUIsZ0JBQWdCO0FBQUEsVUFDMUM7QUFBQSxVQUNBLE9BQU8sS0FBSztBQUFBLFVBQ1osT0FBTztBQUFBLFFBQ1QsQ0FBQztBQUNELGNBQU0sTUFBTSxNQUFNLGtCQUFrQixVQUFVLE9BQU87QUFFckQsY0FBTSxLQUFLLGFBQWEsV0FBVztBQUFBLFVBQ2pDLGFBQWE7QUFBQSxVQUNiLGFBQWE7QUFBQSxVQUNiLFFBQVE7QUFBQSxZQUNOLElBQUk7QUFBQSxZQUNKLE1BQU07QUFBQSxZQUNOLFNBQVM7QUFBQSxZQUNULFVBQVU7QUFBQSxVQUNaO0FBQUEsVUFDQSxNQUFNO0FBQUEsVUFDTixRQUFRLENBQUMsaUJBQWlCLGdCQUFnQjtBQUFBLFVBQzFDLFFBQVE7QUFBQSxZQUNOLElBQUksU0FBUztBQUFBLFlBQ2IsV0FBVyxTQUFTO0FBQUEsWUFDcEIsV0FBVyxJQUFJO0FBQUEsWUFDZixVQUFVO0FBQUEsWUFDVixPQUFPO0FBQUEsVUFDVDtBQUFBLFVBQ0EsTUFBTTtBQUFBLFlBQ0osT0FBTyxLQUFLO0FBQUEsVUFDZDtBQUFBLFFBQ0YsQ0FBQztBQUVELGFBQUssVUFBVSxXQUFXO0FBQzFCLGFBQUssZ0JBQWdCO0FBQUEsTUFDdkIsU0FBUyxLQUFLO0FBQ1osZ0JBQVEsTUFBTSx1Q0FBdUMsR0FBRztBQUN4RCxXQUFHLE1BQU07QUFBQSxNQUNYO0FBQUEsSUFDRjtBQUVBLE9BQUcsU0FBUyxNQUFNO0FBQ2hCLFdBQUssVUFBVSxhQUFhO0FBQUEsSUFFOUI7QUFFQSxPQUFHLFlBQVksQ0FBQyxVQUF3QjtBQS9VNUM7QUFnVk0sVUFBSTtBQUNKLFVBQUk7QUFDRixnQkFBUSxLQUFLLE1BQU0sTUFBTSxJQUFjO0FBQUEsTUFDekMsU0FBUTtBQUNOLGdCQUFRLE1BQU0sNkNBQTZDO0FBQzNEO0FBQUEsTUFDRjtBQUdBLFVBQUksTUFBTSxTQUFTLE9BQU87QUFDeEIsYUFBSyxxQkFBcUIsS0FBSztBQUMvQjtBQUFBLE1BQ0Y7QUFHQSxVQUFJLE1BQU0sU0FBUyxTQUFTO0FBQzFCLFlBQUksTUFBTSxVQUFVLHFCQUFxQjtBQUN2QywyQkFBZSxXQUFNLFlBQU4sbUJBQWUsVUFBUztBQUV2QyxlQUFLLFdBQVc7QUFDaEI7QUFBQSxRQUNGO0FBRUEsWUFBSSxNQUFNLFVBQVUsUUFBUTtBQUMxQixlQUFLLHNCQUFzQixLQUFLO0FBQUEsUUFDbEM7QUFDQTtBQUFBLE1BQ0Y7QUFHQSxjQUFRLE1BQU0sOEJBQThCLEVBQUUsTUFBTSwrQkFBTyxNQUFNLE9BQU8sK0JBQU8sT0FBTyxJQUFJLCtCQUFPLEdBQUcsQ0FBQztBQUFBLElBQ3ZHO0FBRUEsT0FBRyxVQUFVLE1BQU07QUFDakIsV0FBSyxZQUFZO0FBQ2pCLFdBQUssWUFBWSxLQUFLO0FBQ3RCLFdBQUssVUFBVSxjQUFjO0FBRTdCLGlCQUFXLFdBQVcsS0FBSyxnQkFBZ0IsT0FBTyxHQUFHO0FBQ25ELFlBQUksUUFBUTtBQUFTLHVCQUFhLFFBQVEsT0FBTztBQUNqRCxnQkFBUSxPQUFPLElBQUksTUFBTSxtQkFBbUIsQ0FBQztBQUFBLE1BQy9DO0FBQ0EsV0FBSyxnQkFBZ0IsTUFBTTtBQUUzQixVQUFJLENBQUMsS0FBSyxrQkFBa0I7QUFDMUIsYUFBSyxtQkFBbUI7QUFBQSxNQUMxQjtBQUFBLElBQ0Y7QUFFQSxPQUFHLFVBQVUsQ0FBQyxPQUFjO0FBQzFCLGNBQVEsTUFBTSw4QkFBOEIsRUFBRTtBQUFBLElBQ2hEO0FBQUEsRUFDRjtBQUFBLEVBRVEscUJBQXFCLE9BQWtCO0FBdFlqRDtBQXVZSSxVQUFNLFVBQVUsS0FBSyxnQkFBZ0IsSUFBSSxNQUFNLEVBQUU7QUFDakQsUUFBSSxDQUFDO0FBQVM7QUFFZCxTQUFLLGdCQUFnQixPQUFPLE1BQU0sRUFBRTtBQUNwQyxRQUFJLFFBQVE7QUFBUyxtQkFBYSxRQUFRLE9BQU87QUFFakQsUUFBSSxNQUFNO0FBQUksY0FBUSxRQUFRLE1BQU0sT0FBTztBQUFBO0FBQ3RDLGNBQVEsT0FBTyxJQUFJLFFBQU0sV0FBTSxVQUFOLG1CQUFhLFlBQVcsZ0JBQWdCLENBQUM7QUFBQSxFQUN6RTtBQUFBLEVBRVEsc0JBQXNCLE9BQWtCO0FBalpsRDtBQWtaSSxVQUFNLFVBQVUsTUFBTTtBQUN0QixVQUFNLHFCQUFxQixRQUFPLG1DQUFTLGVBQWMsRUFBRTtBQUMzRCxRQUFJLENBQUMsc0JBQXNCLENBQUMsa0JBQWtCLEtBQUssWUFBWSxrQkFBa0IsR0FBRztBQUNsRjtBQUFBLElBQ0Y7QUFJQSxVQUFNLGdCQUFnQixRQUFPLG1DQUFTLFdBQVMsbUNBQVMscUJBQWtCLHdDQUFTLFNBQVQsbUJBQWUsVUFBUyxFQUFFO0FBQ3BHLFFBQUksS0FBSyxlQUFlLGlCQUFpQixrQkFBa0IsS0FBSyxhQUFhO0FBQzNFO0FBQUEsSUFDRjtBQUdBLFNBQUksbUNBQVMsVUFBUyxRQUFRLFVBQVUsV0FBVyxRQUFRLFVBQVUsV0FBVztBQUM5RTtBQUFBLElBQ0Y7QUFHQSxVQUFNLE1BQU0sbUNBQVM7QUFDckIsVUFBTSxRQUFPLGdDQUFLLFNBQUwsWUFBYTtBQUcxQixTQUFLLGNBQWM7QUFDbkIsU0FBSyxZQUFZLEtBQUs7QUFHdEIsU0FBSSxtQ0FBUyxXQUFVLFdBQVc7QUFHaEMsVUFBSSxDQUFDO0FBQUs7QUFBQSxJQUNaO0FBRUEsUUFBSSxTQUFTLGFBQWE7QUFDeEI7QUFBQSxJQUNGO0FBRUEsVUFBTSxPQUFPLDhCQUE4QixHQUFHO0FBQzlDLFFBQUksQ0FBQztBQUFNO0FBR1gsUUFBSSxLQUFLLEtBQUssTUFBTSxnQkFBZ0I7QUFDbEM7QUFBQSxJQUNGO0FBRUEsZUFBSyxjQUFMLDhCQUFpQjtBQUFBLE1BQ2YsTUFBTTtBQUFBLE1BQ04sU0FBUztBQUFBLFFBQ1AsU0FBUztBQUFBLFFBQ1QsTUFBTTtBQUFBLFFBQ04sV0FBVyxLQUFLLElBQUk7QUFBQSxNQUN0QjtBQUFBLElBQ0Y7QUFBQSxFQUNGO0FBQUEsRUFFUSxhQUFhLFFBQWdCLFFBQTJCO0FBQzlELFdBQU8sSUFBSSxRQUFRLENBQUMsU0FBUyxXQUFXO0FBQ3RDLFVBQUksQ0FBQyxLQUFLLE1BQU0sS0FBSyxHQUFHLGVBQWUsVUFBVSxNQUFNO0FBQ3JELGVBQU8sSUFBSSxNQUFNLHlCQUF5QixDQUFDO0FBQzNDO0FBQUEsTUFDRjtBQUVBLFlBQU0sS0FBSyxPQUFPLEVBQUUsS0FBSyxTQUFTO0FBRWxDLFlBQU0sVUFBMEIsRUFBRSxTQUFTLFFBQVEsU0FBUyxLQUFLO0FBQ2pFLFdBQUssZ0JBQWdCLElBQUksSUFBSSxPQUFPO0FBRXBDLFdBQUssR0FBRztBQUFBLFFBQ04sS0FBSyxVQUFVO0FBQUEsVUFDYixNQUFNO0FBQUEsVUFDTjtBQUFBLFVBQ0E7QUFBQSxVQUNBO0FBQUEsUUFDRixDQUFDO0FBQUEsTUFDSDtBQUVBLGNBQVEsVUFBVSxXQUFXLE1BQU07QUFDakMsWUFBSSxLQUFLLGdCQUFnQixJQUFJLEVBQUUsR0FBRztBQUNoQyxlQUFLLGdCQUFnQixPQUFPLEVBQUU7QUFDOUIsaUJBQU8sSUFBSSxNQUFNLG9CQUFvQixNQUFNLEVBQUUsQ0FBQztBQUFBLFFBQ2hEO0FBQUEsTUFDRixHQUFHLEdBQU07QUFBQSxJQUNYLENBQUM7QUFBQSxFQUNIO0FBQUEsRUFFUSxxQkFBMkI7QUFDakMsUUFBSSxLQUFLLG1CQUFtQjtBQUFNO0FBQ2xDLFNBQUssaUJBQWlCLFdBQVcsTUFBTTtBQUNyQyxXQUFLLGlCQUFpQjtBQUN0QixVQUFJLENBQUMsS0FBSyxrQkFBa0I7QUFDMUIsZ0JBQVEsSUFBSSw4QkFBOEIsS0FBSyxHQUFHLFFBQUc7QUFDckQsYUFBSyxTQUFTO0FBQUEsTUFDaEI7QUFBQSxJQUNGLEdBQUcsa0JBQWtCO0FBQUEsRUFDdkI7QUFBQSxFQUVRLGtCQUF3QjtBQUM5QixTQUFLLGVBQWU7QUFDcEIsU0FBSyxpQkFBaUIsWUFBWSxNQUFNO0FBcGY1QztBQXFmTSxZQUFJLFVBQUssT0FBTCxtQkFBUyxnQkFBZSxVQUFVO0FBQU07QUFDNUMsVUFBSSxLQUFLLEdBQUcsaUJBQWlCLEdBQUc7QUFDOUIsZ0JBQVEsS0FBSyxtRUFBOEQ7QUFBQSxNQUM3RTtBQUFBLElBQ0YsR0FBRyxxQkFBcUI7QUFBQSxFQUMxQjtBQUFBLEVBRVEsaUJBQXVCO0FBQzdCLFFBQUksS0FBSyxnQkFBZ0I7QUFDdkIsb0JBQWMsS0FBSyxjQUFjO0FBQ2pDLFdBQUssaUJBQWlCO0FBQUEsSUFDeEI7QUFBQSxFQUNGO0FBQUEsRUFFUSxjQUFvQjtBQUMxQixTQUFLLGVBQWU7QUFDcEIsU0FBSyw0QkFBNEI7QUFDakMsUUFBSSxLQUFLLGdCQUFnQjtBQUN2QixtQkFBYSxLQUFLLGNBQWM7QUFDaEMsV0FBSyxpQkFBaUI7QUFBQSxJQUN4QjtBQUFBLEVBQ0Y7QUFBQSxFQUVRLFVBQVUsT0FBNEI7QUE1Z0JoRDtBQTZnQkksUUFBSSxLQUFLLFVBQVU7QUFBTztBQUMxQixTQUFLLFFBQVE7QUFDYixlQUFLLGtCQUFMLDhCQUFxQjtBQUFBLEVBQ3ZCO0FBQUEsRUFFUSxZQUFZLFNBQXdCO0FBbGhCOUM7QUFtaEJJLFFBQUksS0FBSyxZQUFZO0FBQVM7QUFDOUIsU0FBSyxVQUFVO0FBQ2YsZUFBSyxvQkFBTCw4QkFBdUI7QUFFdkIsUUFBSSxDQUFDLFNBQVM7QUFDWixXQUFLLDRCQUE0QjtBQUFBLElBQ25DO0FBQUEsRUFDRjtBQUFBLEVBRVEsMkJBQWlDO0FBQ3ZDLFNBQUssNEJBQTRCO0FBQ2pDLFNBQUssZUFBZSxXQUFXLE1BQU07QUFFbkMsV0FBSyxZQUFZLEtBQUs7QUFBQSxJQUN4QixHQUFHLGNBQWM7QUFBQSxFQUNuQjtBQUFBLEVBRVEsOEJBQW9DO0FBQzFDLFFBQUksS0FBSyxjQUFjO0FBQ3JCLG1CQUFhLEtBQUssWUFBWTtBQUM5QixXQUFLLGVBQWU7QUFBQSxJQUN0QjtBQUFBLEVBQ0Y7QUFDRjs7O0FDdmlCTyxJQUFNLGNBQU4sTUFBa0I7QUFBQSxFQUFsQjtBQUNMLFNBQVEsV0FBMEIsQ0FBQztBQUduQztBQUFBLG9CQUFnRTtBQUVoRTtBQUFBLDBCQUFzRDtBQUFBO0FBQUEsRUFFdEQsV0FBVyxLQUF3QjtBQVhyQztBQVlJLFNBQUssU0FBUyxLQUFLLEdBQUc7QUFDdEIsZUFBSyxtQkFBTCw4QkFBc0I7QUFBQSxFQUN4QjtBQUFBLEVBRUEsY0FBc0M7QUFDcEMsV0FBTyxLQUFLO0FBQUEsRUFDZDtBQUFBLEVBRUEsUUFBYztBQXBCaEI7QUFxQkksU0FBSyxXQUFXLENBQUM7QUFDakIsZUFBSyxhQUFMLDhCQUFnQixDQUFDO0FBQUEsRUFDbkI7QUFBQTtBQUFBLEVBR0EsT0FBTyxrQkFBa0IsU0FBOEI7QUFDckQsV0FBTztBQUFBLE1BQ0wsSUFBSSxPQUFPLEtBQUssSUFBSSxDQUFDLElBQUksS0FBSyxPQUFPLEVBQUUsU0FBUyxFQUFFLEVBQUUsTUFBTSxHQUFHLENBQUMsQ0FBQztBQUFBLE1BQy9ELE1BQU07QUFBQSxNQUNOO0FBQUEsTUFDQSxXQUFXLEtBQUssSUFBSTtBQUFBLElBQ3RCO0FBQUEsRUFDRjtBQUFBO0FBQUEsRUFHQSxPQUFPLHVCQUF1QixTQUE4QjtBQUMxRCxXQUFPO0FBQUEsTUFDTCxJQUFJLE9BQU8sS0FBSyxJQUFJLENBQUMsSUFBSSxLQUFLLE9BQU8sRUFBRSxTQUFTLEVBQUUsRUFBRSxNQUFNLEdBQUcsQ0FBQyxDQUFDO0FBQUEsTUFDL0QsTUFBTTtBQUFBLE1BQ047QUFBQSxNQUNBLFdBQVcsS0FBSyxJQUFJO0FBQUEsSUFDdEI7QUFBQSxFQUNGO0FBQUE7QUFBQSxFQUdBLE9BQU8sb0JBQW9CLFNBQWlCLFFBQThCLFFBQXFCO0FBQzdGLFdBQU87QUFBQSxNQUNMLElBQUksT0FBTyxLQUFLLElBQUksQ0FBQztBQUFBLE1BQ3JCLE1BQU07QUFBQSxNQUNOO0FBQUEsTUFDQTtBQUFBLE1BQ0EsV0FBVyxLQUFLLElBQUk7QUFBQSxJQUN0QjtBQUFBLEVBQ0Y7QUFDRjs7O0FDdkRBLElBQUFDLG1CQUFrRTs7O0FDWWxFLFNBQXNCLHFCQUFxQixLQUF1QztBQUFBO0FBQ2hGLFVBQU0sT0FBTyxJQUFJLFVBQVUsY0FBYztBQUN6QyxRQUFJLENBQUM7QUFBTSxhQUFPO0FBRWxCLFFBQUk7QUFDRixZQUFNLFVBQVUsTUFBTSxJQUFJLE1BQU0sS0FBSyxJQUFJO0FBQ3pDLGFBQU87QUFBQSxRQUNMLE9BQU8sS0FBSztBQUFBLFFBQ1osTUFBTSxLQUFLO0FBQUEsUUFDWDtBQUFBLE1BQ0Y7QUFBQSxJQUNGLFNBQVMsS0FBSztBQUNaLGNBQVEsTUFBTSw4Q0FBOEMsR0FBRztBQUMvRCxhQUFPO0FBQUEsSUFDVDtBQUFBLEVBQ0Y7QUFBQTs7O0FEckJPLElBQU0sMEJBQTBCO0FBRWhDLElBQU0sbUJBQU4sY0FBK0IsMEJBQVM7QUFBQSxFQWU3QyxZQUFZLE1BQXFCLFFBQXdCO0FBQ3ZELFVBQU0sSUFBSTtBQVhaO0FBQUEsU0FBUSxjQUFjO0FBQ3RCLFNBQVEsWUFBWTtBQVdsQixTQUFLLFNBQVM7QUFDZCxTQUFLLGNBQWMsT0FBTztBQUFBLEVBQzVCO0FBQUEsRUFFQSxjQUFzQjtBQUNwQixXQUFPO0FBQUEsRUFDVDtBQUFBLEVBRUEsaUJBQXlCO0FBQ3ZCLFdBQU87QUFBQSxFQUNUO0FBQUEsRUFFQSxVQUFrQjtBQUNoQixXQUFPO0FBQUEsRUFDVDtBQUFBLEVBRU0sU0FBd0I7QUFBQTtBQUM1QixXQUFLLFNBQVM7QUFHZCxXQUFLLFlBQVksV0FBVyxDQUFDLFNBQVMsS0FBSyxnQkFBZ0IsSUFBSTtBQUUvRCxXQUFLLFlBQVksaUJBQWlCLENBQUMsUUFBUSxLQUFLLGVBQWUsR0FBRztBQUdsRSxXQUFLLE9BQU8sU0FBUyxnQkFBZ0IsQ0FBQyxVQUFVO0FBQzlDLGFBQUssY0FBYyxVQUFVO0FBQzdCLGFBQUssVUFBVSxZQUFZLGFBQWEsS0FBSyxXQUFXO0FBQ3hELGFBQUssVUFBVSxRQUFRLFlBQVksS0FBSztBQUN4QyxhQUFLLGtCQUFrQjtBQUFBLE1BQ3pCO0FBR0EsV0FBSyxPQUFPLFNBQVMsa0JBQWtCLENBQUMsWUFBWTtBQUNsRCxhQUFLLFlBQVk7QUFDakIsYUFBSyxrQkFBa0I7QUFBQSxNQUN6QjtBQUdBLFdBQUssY0FBYyxLQUFLLE9BQU8sU0FBUyxVQUFVO0FBQ2xELFdBQUssVUFBVSxZQUFZLGFBQWEsS0FBSyxXQUFXO0FBQ3hELFdBQUssa0JBQWtCO0FBRXZCLFdBQUssZ0JBQWdCLEtBQUssWUFBWSxZQUFZLENBQUM7QUFBQSxJQUNyRDtBQUFBO0FBQUEsRUFFTSxVQUF5QjtBQUFBO0FBQzdCLFdBQUssWUFBWSxXQUFXO0FBQzVCLFdBQUssWUFBWSxpQkFBaUI7QUFDbEMsV0FBSyxPQUFPLFNBQVMsZ0JBQWdCO0FBQ3JDLFdBQUssT0FBTyxTQUFTLGtCQUFrQjtBQUFBLElBQ3pDO0FBQUE7QUFBQTtBQUFBLEVBSVEsV0FBaUI7QUFDdkIsVUFBTSxPQUFPLEtBQUs7QUFDbEIsU0FBSyxNQUFNO0FBQ1gsU0FBSyxTQUFTLGlCQUFpQjtBQUcvQixVQUFNLFNBQVMsS0FBSyxVQUFVLEVBQUUsS0FBSyxlQUFlLENBQUM7QUFDckQsV0FBTyxXQUFXLEVBQUUsS0FBSyxzQkFBc0IsTUFBTSxnQkFBZ0IsQ0FBQztBQUN0RSxTQUFLLFlBQVksT0FBTyxVQUFVLEVBQUUsS0FBSyxtQkFBbUIsQ0FBQztBQUM3RCxTQUFLLFVBQVUsUUFBUTtBQUd2QixTQUFLLGFBQWEsS0FBSyxVQUFVLEVBQUUsS0FBSyxpQkFBaUIsQ0FBQztBQUcxRCxVQUFNLFNBQVMsS0FBSyxVQUFVLEVBQUUsS0FBSyxvQkFBb0IsQ0FBQztBQUMxRCxTQUFLLHNCQUFzQixPQUFPLFNBQVMsU0FBUyxFQUFFLE1BQU0sV0FBVyxDQUFDO0FBQ3hFLFNBQUssb0JBQW9CLEtBQUs7QUFDOUIsU0FBSyxvQkFBb0IsVUFBVSxLQUFLLE9BQU8sU0FBUztBQUN4RCxVQUFNLFdBQVcsT0FBTyxTQUFTLFNBQVMsRUFBRSxNQUFNLHNCQUFzQixDQUFDO0FBQ3pFLGFBQVMsVUFBVTtBQUduQixVQUFNLFdBQVcsS0FBSyxVQUFVLEVBQUUsS0FBSyxrQkFBa0IsQ0FBQztBQUMxRCxTQUFLLFVBQVUsU0FBUyxTQUFTLFlBQVk7QUFBQSxNQUMzQyxLQUFLO0FBQUEsTUFDTCxhQUFhO0FBQUEsSUFDZixDQUFDO0FBQ0QsU0FBSyxRQUFRLE9BQU87QUFFcEIsU0FBSyxVQUFVLFNBQVMsU0FBUyxVQUFVLEVBQUUsS0FBSyxrQkFBa0IsTUFBTSxPQUFPLENBQUM7QUFHbEYsU0FBSyxRQUFRLGlCQUFpQixTQUFTLE1BQU0sS0FBSyxZQUFZLENBQUM7QUFDL0QsU0FBSyxRQUFRLGlCQUFpQixXQUFXLENBQUMsTUFBTTtBQUM5QyxVQUFJLEVBQUUsUUFBUSxXQUFXLENBQUMsRUFBRSxVQUFVO0FBQ3BDLFVBQUUsZUFBZTtBQUNqQixhQUFLLFlBQVk7QUFBQSxNQUNuQjtBQUFBLElBQ0YsQ0FBQztBQUVELFNBQUssUUFBUSxpQkFBaUIsU0FBUyxNQUFNO0FBQzNDLFdBQUssUUFBUSxNQUFNLFNBQVM7QUFDNUIsV0FBSyxRQUFRLE1BQU0sU0FBUyxHQUFHLEtBQUssUUFBUSxZQUFZO0FBQUEsSUFDMUQsQ0FBQztBQUFBLEVBQ0g7QUFBQTtBQUFBLEVBSVEsZ0JBQWdCLFVBQXdDO0FBQzlELFNBQUssV0FBVyxNQUFNO0FBRXRCLFFBQUksU0FBUyxXQUFXLEdBQUc7QUFDekIsV0FBSyxXQUFXLFNBQVMsS0FBSztBQUFBLFFBQzVCLE1BQU07QUFBQSxRQUNOLEtBQUs7QUFBQSxNQUNQLENBQUM7QUFDRDtBQUFBLElBQ0Y7QUFFQSxlQUFXLE9BQU8sVUFBVTtBQUMxQixXQUFLLGVBQWUsR0FBRztBQUFBLElBQ3pCO0FBR0EsU0FBSyxXQUFXLFlBQVksS0FBSyxXQUFXO0FBQUEsRUFDOUM7QUFBQTtBQUFBLEVBR1EsZUFBZSxLQUF3QjtBQXJKakQ7QUF1SkksZUFBSyxXQUFXLGNBQWMsb0JBQW9CLE1BQWxELG1CQUFxRDtBQUVyRCxVQUFNLGFBQWEsSUFBSSxRQUFRLElBQUksSUFBSSxLQUFLLEtBQUs7QUFDakQsVUFBTSxLQUFLLEtBQUssV0FBVyxVQUFVLEVBQUUsS0FBSyxpQkFBaUIsSUFBSSxJQUFJLEdBQUcsVUFBVSxHQUFHLENBQUM7QUFDdEYsVUFBTSxPQUFPLEdBQUcsVUFBVSxFQUFFLEtBQUsscUJBQXFCLENBQUM7QUFHdkQsUUFBSSxJQUFJLFNBQVMsYUFBYTtBQUM1QixZQUFNLGNBQWEsZ0JBQUssSUFBSSxVQUFVLGNBQWMsTUFBakMsbUJBQW9DLFNBQXBDLFlBQTRDO0FBQy9ELFdBQUssa0NBQWlCLGVBQWUsSUFBSSxTQUFTLE1BQU0sWUFBWSxLQUFLLE1BQU07QUFBQSxJQUNqRixPQUFPO0FBQ0wsV0FBSyxRQUFRLElBQUksT0FBTztBQUFBLElBQzFCO0FBR0EsU0FBSyxXQUFXLFlBQVksS0FBSyxXQUFXO0FBQUEsRUFDOUM7QUFBQSxFQUVRLG9CQUEwQjtBQUdoQyxVQUFNLFdBQVcsQ0FBQyxLQUFLO0FBQ3ZCLFNBQUssUUFBUSxXQUFXO0FBRXhCLFNBQUssUUFBUSxZQUFZLGNBQWMsS0FBSyxTQUFTO0FBQ3JELFNBQUssUUFBUSxRQUFRLGFBQWEsS0FBSyxZQUFZLFNBQVMsT0FBTztBQUNuRSxTQUFLLFFBQVEsUUFBUSxjQUFjLEtBQUssWUFBWSxTQUFTLE1BQU07QUFFbkUsUUFBSSxLQUFLLFdBQVc7QUFFbEIsV0FBSyxRQUFRLE1BQU07QUFDbkIsWUFBTSxPQUFPLEtBQUssUUFBUSxVQUFVLEVBQUUsS0FBSyxrQkFBa0IsQ0FBQztBQUM5RCxXQUFLLFVBQVUsRUFBRSxLQUFLLHNCQUFzQixNQUFNLEVBQUUsZUFBZSxPQUFPLEVBQUUsQ0FBQztBQUM3RSxXQUFLLFVBQVUsRUFBRSxLQUFLLG1CQUFtQixNQUFNLEVBQUUsZUFBZSxPQUFPLEVBQUUsQ0FBQztBQUFBLElBQzVFLE9BQU87QUFFTCxXQUFLLFFBQVEsUUFBUSxNQUFNO0FBQUEsSUFDN0I7QUFBQSxFQUNGO0FBQUE7QUFBQSxFQUljLGNBQTZCO0FBQUE7QUFFekMsVUFBSSxLQUFLLFdBQVc7QUFDbEIsY0FBTSxLQUFLLE1BQU0sS0FBSyxPQUFPLFNBQVMsZUFBZTtBQUNyRCxZQUFJLENBQUMsSUFBSTtBQUNQLGNBQUksd0JBQU8sK0JBQStCO0FBQzFDLGVBQUssWUFBWSxXQUFXLFlBQVksb0JBQW9CLHNCQUFpQixPQUFPLENBQUM7QUFBQSxRQUN2RixPQUFPO0FBQ0wsZUFBSyxZQUFZLFdBQVcsWUFBWSxvQkFBb0Isa0JBQWEsTUFBTSxDQUFDO0FBQUEsUUFDbEY7QUFDQTtBQUFBLE1BQ0Y7QUFFQSxZQUFNLE9BQU8sS0FBSyxRQUFRLE1BQU0sS0FBSztBQUNyQyxVQUFJLENBQUM7QUFBTTtBQUdYLFVBQUksVUFBVTtBQUNkLFVBQUksS0FBSyxvQkFBb0IsU0FBUztBQUNwQyxjQUFNLE9BQU8sTUFBTSxxQkFBcUIsS0FBSyxHQUFHO0FBQ2hELFlBQUksTUFBTTtBQUNSLG9CQUFVLGNBQWMsS0FBSyxLQUFLO0FBQUE7QUFBQSxFQUFTLElBQUk7QUFBQSxRQUNqRDtBQUFBLE1BQ0Y7QUFHQSxZQUFNLFVBQVUsWUFBWSxrQkFBa0IsSUFBSTtBQUNsRCxXQUFLLFlBQVksV0FBVyxPQUFPO0FBR25DLFdBQUssUUFBUSxRQUFRO0FBQ3JCLFdBQUssUUFBUSxNQUFNLFNBQVM7QUFHNUIsVUFBSTtBQUNGLGNBQU0sS0FBSyxPQUFPLFNBQVMsWUFBWSxPQUFPO0FBQUEsTUFDaEQsU0FBUyxLQUFLO0FBQ1osZ0JBQVEsTUFBTSx1QkFBdUIsR0FBRztBQUN4QyxZQUFJLHdCQUFPLCtCQUErQixPQUFPLEdBQUcsQ0FBQyxHQUFHO0FBQ3hELGFBQUssWUFBWTtBQUFBLFVBQ2YsWUFBWSxvQkFBb0IsdUJBQWtCLEdBQUcsSUFBSSxPQUFPO0FBQUEsUUFDbEU7QUFBQSxNQUNGO0FBQUEsSUFDRjtBQUFBO0FBQ0Y7OztBRS9OTyxJQUFNLG1CQUFxQztBQUFBLEVBQ2hELFlBQVk7QUFBQSxFQUNaLFdBQVc7QUFBQSxFQUNYLFlBQVk7QUFBQSxFQUNaLFdBQVc7QUFBQSxFQUNYLG1CQUFtQjtBQUNyQjs7O0FOYkEsSUFBcUIsaUJBQXJCLGNBQTRDLHdCQUFPO0FBQUEsRUFLM0MsU0FBd0I7QUFBQTtBQUM1QixZQUFNLEtBQUssYUFBYTtBQUV4QixXQUFLLFdBQVcsSUFBSSxpQkFBaUIsS0FBSyxTQUFTLFVBQVU7QUFDN0QsV0FBSyxjQUFjLElBQUksWUFBWTtBQUduQyxXQUFLLFNBQVMsWUFBWSxDQUFDLFFBQVE7QUFuQnZDO0FBb0JNLFlBQUksSUFBSSxTQUFTLFdBQVc7QUFDMUIsZUFBSyxZQUFZLFdBQVcsWUFBWSx1QkFBdUIsSUFBSSxRQUFRLE9BQU8sQ0FBQztBQUFBLFFBQ3JGLFdBQVcsSUFBSSxTQUFTLFNBQVM7QUFDL0IsZ0JBQU0sV0FBVSxTQUFJLFFBQVEsWUFBWixZQUF1QjtBQUN2QyxlQUFLLFlBQVksV0FBVyxZQUFZLG9CQUFvQixVQUFLLE9BQU8sSUFBSSxPQUFPLENBQUM7QUFBQSxRQUN0RjtBQUFBLE1BQ0Y7QUFHQSxXQUFLO0FBQUEsUUFDSDtBQUFBLFFBQ0EsQ0FBQyxTQUF3QixJQUFJLGlCQUFpQixNQUFNLElBQUk7QUFBQSxNQUMxRDtBQUdBLFdBQUssY0FBYyxrQkFBa0IsaUJBQWlCLE1BQU07QUFDMUQsYUFBSyxrQkFBa0I7QUFBQSxNQUN6QixDQUFDO0FBR0QsV0FBSyxjQUFjLElBQUksbUJBQW1CLEtBQUssS0FBSyxJQUFJLENBQUM7QUFHekQsV0FBSyxXQUFXO0FBQUEsUUFDZCxJQUFJO0FBQUEsUUFDSixNQUFNO0FBQUEsUUFDTixVQUFVLE1BQU0sS0FBSyxrQkFBa0I7QUFBQSxNQUN6QyxDQUFDO0FBR0QsVUFBSSxLQUFLLFNBQVMsV0FBVztBQUMzQixhQUFLLFdBQVc7QUFBQSxNQUNsQixPQUFPO0FBQ0wsWUFBSSx3QkFBTyxpRUFBaUU7QUFBQSxNQUM5RTtBQUVBLGNBQVEsSUFBSSx1QkFBdUI7QUFBQSxJQUNyQztBQUFBO0FBQUEsRUFFTSxXQUEwQjtBQUFBO0FBQzlCLFdBQUssU0FBUyxXQUFXO0FBQ3pCLFdBQUssSUFBSSxVQUFVLG1CQUFtQix1QkFBdUI7QUFDN0QsY0FBUSxJQUFJLHlCQUF5QjtBQUFBLElBQ3ZDO0FBQUE7QUFBQSxFQUVNLGVBQThCO0FBQUE7QUFDbEMsV0FBSyxXQUFXLE9BQU8sT0FBTyxDQUFDLEdBQUcsa0JBQWtCLE1BQU0sS0FBSyxTQUFTLENBQUM7QUFBQSxJQUMzRTtBQUFBO0FBQUEsRUFFTSxlQUE4QjtBQUFBO0FBQ2xDLFlBQU0sS0FBSyxTQUFTLEtBQUssUUFBUTtBQUFBLElBQ25DO0FBQUE7QUFBQTtBQUFBLEVBSVEsYUFBbUI7QUFDekIsU0FBSyxTQUFTO0FBQUEsTUFDWixLQUFLLFNBQVM7QUFBQSxNQUNkLEtBQUssU0FBUztBQUFBLElBQ2hCO0FBQUEsRUFDRjtBQUFBLEVBRWMsb0JBQW1DO0FBQUE7QUFDL0MsWUFBTSxFQUFFLFVBQVUsSUFBSSxLQUFLO0FBRzNCLFlBQU0sV0FBVyxVQUFVLGdCQUFnQix1QkFBdUI7QUFDbEUsVUFBSSxTQUFTLFNBQVMsR0FBRztBQUN2QixrQkFBVSxXQUFXLFNBQVMsQ0FBQyxDQUFDO0FBQ2hDO0FBQUEsTUFDRjtBQUdBLFlBQU0sT0FBTyxVQUFVLGFBQWEsS0FBSztBQUN6QyxVQUFJLENBQUM7QUFBTTtBQUNYLFlBQU0sS0FBSyxhQUFhLEVBQUUsTUFBTSx5QkFBeUIsUUFBUSxLQUFLLENBQUM7QUFDdkUsZ0JBQVUsV0FBVyxJQUFJO0FBQUEsSUFDM0I7QUFBQTtBQUNGOyIsCiAgIm5hbWVzIjogWyJpbXBvcnRfb2JzaWRpYW4iLCAiaW1wb3J0X29ic2lkaWFuIl0KfQo=
