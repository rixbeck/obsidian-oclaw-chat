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
    new import_obsidian.Setting(containerEl).setName("Render assistant as Markdown (unsafe)").setDesc(
      "OFF recommended. If enabled, assistant output is rendered as Obsidian Markdown which may trigger embeds and other plugins' post-processors."
    ).addToggle(
      (toggle) => toggle.setValue(this.plugin.settings.renderAssistantMarkdown).onChange((value) => __async(this, null, function* () {
        this.plugin.settings.renderAssistantMarkdown = value;
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
    this.lastBufferedWarnAtMs = 0;
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
    if (msg.role === "assistant" && this.plugin.settings.renderAssistantMarkdown) {
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
  includeActiveNote: false,
  renderAssistantMarkdown: false
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
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsic3JjL21haW4udHMiLCAic3JjL3NldHRpbmdzLnRzIiwgInNyYy93ZWJzb2NrZXQudHMiLCAic3JjL2NoYXQudHMiLCAic3JjL3ZpZXcudHMiLCAic3JjL2NvbnRleHQudHMiLCAic3JjL3R5cGVzLnRzIl0sCiAgInNvdXJjZXNDb250ZW50IjogWyJpbXBvcnQgeyBOb3RpY2UsIFBsdWdpbiwgV29ya3NwYWNlTGVhZiB9IGZyb20gJ29ic2lkaWFuJztcbmltcG9ydCB7IE9wZW5DbGF3U2V0dGluZ1RhYiB9IGZyb20gJy4vc2V0dGluZ3MnO1xuaW1wb3J0IHsgT2JzaWRpYW5XU0NsaWVudCB9IGZyb20gJy4vd2Vic29ja2V0JztcbmltcG9ydCB7IENoYXRNYW5hZ2VyIH0gZnJvbSAnLi9jaGF0JztcbmltcG9ydCB7IFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFULCBPcGVuQ2xhd0NoYXRWaWV3IH0gZnJvbSAnLi92aWV3JztcbmltcG9ydCB7IERFRkFVTFRfU0VUVElOR1MsIHR5cGUgT3BlbkNsYXdTZXR0aW5ncyB9IGZyb20gJy4vdHlwZXMnO1xuXG5leHBvcnQgZGVmYXVsdCBjbGFzcyBPcGVuQ2xhd1BsdWdpbiBleHRlbmRzIFBsdWdpbiB7XG4gIHNldHRpbmdzITogT3BlbkNsYXdTZXR0aW5ncztcbiAgd3NDbGllbnQhOiBPYnNpZGlhbldTQ2xpZW50O1xuICBjaGF0TWFuYWdlciE6IENoYXRNYW5hZ2VyO1xuXG4gIGFzeW5jIG9ubG9hZCgpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBhd2FpdCB0aGlzLmxvYWRTZXR0aW5ncygpO1xuXG4gICAgdGhpcy53c0NsaWVudCA9IG5ldyBPYnNpZGlhbldTQ2xpZW50KHRoaXMuc2V0dGluZ3Muc2Vzc2lvbktleSk7XG4gICAgdGhpcy5jaGF0TWFuYWdlciA9IG5ldyBDaGF0TWFuYWdlcigpO1xuXG4gICAgLy8gV2lyZSBpbmNvbWluZyBXUyBtZXNzYWdlcyBcdTIxOTIgQ2hhdE1hbmFnZXJcbiAgICB0aGlzLndzQ2xpZW50Lm9uTWVzc2FnZSA9IChtc2cpID0+IHtcbiAgICAgIGlmIChtc2cudHlwZSA9PT0gJ21lc3NhZ2UnKSB7XG4gICAgICAgIHRoaXMuY2hhdE1hbmFnZXIuYWRkTWVzc2FnZShDaGF0TWFuYWdlci5jcmVhdGVBc3Npc3RhbnRNZXNzYWdlKG1zZy5wYXlsb2FkLmNvbnRlbnQpKTtcbiAgICAgIH0gZWxzZSBpZiAobXNnLnR5cGUgPT09ICdlcnJvcicpIHtcbiAgICAgICAgY29uc3QgZXJyVGV4dCA9IG1zZy5wYXlsb2FkLm1lc3NhZ2UgPz8gJ1Vua25vd24gZXJyb3IgZnJvbSBnYXRld2F5JztcbiAgICAgICAgdGhpcy5jaGF0TWFuYWdlci5hZGRNZXNzYWdlKENoYXRNYW5hZ2VyLmNyZWF0ZVN5c3RlbU1lc3NhZ2UoYFx1MjZBMCAke2VyclRleHR9YCwgJ2Vycm9yJykpO1xuICAgICAgfVxuICAgIH07XG5cbiAgICAvLyBSZWdpc3RlciB0aGUgc2lkZWJhciB2aWV3XG4gICAgdGhpcy5yZWdpc3RlclZpZXcoXG4gICAgICBWSUVXX1RZUEVfT1BFTkNMQVdfQ0hBVCxcbiAgICAgIChsZWFmOiBXb3Jrc3BhY2VMZWFmKSA9PiBuZXcgT3BlbkNsYXdDaGF0VmlldyhsZWFmLCB0aGlzKVxuICAgICk7XG5cbiAgICAvLyBSaWJib24gaWNvbiBcdTIwMTQgb3BlbnMgLyByZXZlYWxzIHRoZSBjaGF0IHNpZGViYXJcbiAgICB0aGlzLmFkZFJpYmJvbkljb24oJ21lc3NhZ2Utc3F1YXJlJywgJ09wZW5DbGF3IENoYXQnLCAoKSA9PiB7XG4gICAgICB0aGlzLl9hY3RpdmF0ZUNoYXRWaWV3KCk7XG4gICAgfSk7XG5cbiAgICAvLyBTZXR0aW5ncyB0YWJcbiAgICB0aGlzLmFkZFNldHRpbmdUYWIobmV3IE9wZW5DbGF3U2V0dGluZ1RhYih0aGlzLmFwcCwgdGhpcykpO1xuXG4gICAgLy8gQ29tbWFuZCBwYWxldHRlIGVudHJ5XG4gICAgdGhpcy5hZGRDb21tYW5kKHtcbiAgICAgIGlkOiAnb3Blbi1vcGVuY2xhdy1jaGF0JyxcbiAgICAgIG5hbWU6ICdPcGVuIGNoYXQgc2lkZWJhcicsXG4gICAgICBjYWxsYmFjazogKCkgPT4gdGhpcy5fYWN0aXZhdGVDaGF0VmlldygpLFxuICAgIH0pO1xuXG4gICAgLy8gQ29ubmVjdCB0byBnYXRld2F5IGlmIHRva2VuIGlzIGNvbmZpZ3VyZWRcbiAgICBpZiAodGhpcy5zZXR0aW5ncy5hdXRoVG9rZW4pIHtcbiAgICAgIHRoaXMuX2Nvbm5lY3RXUygpO1xuICAgIH0gZWxzZSB7XG4gICAgICBuZXcgTm90aWNlKCdPcGVuQ2xhdyBDaGF0OiBwbGVhc2UgY29uZmlndXJlIHlvdXIgZ2F0ZXdheSB0b2tlbiBpbiBTZXR0aW5ncy4nKTtcbiAgICB9XG5cbiAgICBjb25zb2xlLmxvZygnW29jbGF3XSBQbHVnaW4gbG9hZGVkJyk7XG4gIH1cblxuICBhc3luYyBvbnVubG9hZCgpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICB0aGlzLndzQ2xpZW50LmRpc2Nvbm5lY3QoKTtcbiAgICB0aGlzLmFwcC53b3Jrc3BhY2UuZGV0YWNoTGVhdmVzT2ZUeXBlKFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFUKTtcbiAgICBjb25zb2xlLmxvZygnW29jbGF3XSBQbHVnaW4gdW5sb2FkZWQnKTtcbiAgfVxuXG4gIGFzeW5jIGxvYWRTZXR0aW5ncygpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICB0aGlzLnNldHRpbmdzID0gT2JqZWN0LmFzc2lnbih7fSwgREVGQVVMVF9TRVRUSU5HUywgYXdhaXQgdGhpcy5sb2FkRGF0YSgpKTtcbiAgfVxuXG4gIGFzeW5jIHNhdmVTZXR0aW5ncygpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBhd2FpdCB0aGlzLnNhdmVEYXRhKHRoaXMuc2V0dGluZ3MpO1xuICB9XG5cbiAgLy8gXHUyNTAwXHUyNTAwIEhlbHBlcnMgXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG5cbiAgcHJpdmF0ZSBfY29ubmVjdFdTKCk6IHZvaWQge1xuICAgIHRoaXMud3NDbGllbnQuY29ubmVjdChcbiAgICAgIHRoaXMuc2V0dGluZ3MuZ2F0ZXdheVVybCxcbiAgICAgIHRoaXMuc2V0dGluZ3MuYXV0aFRva2VuXG4gICAgKTtcbiAgfVxuXG4gIHByaXZhdGUgYXN5bmMgX2FjdGl2YXRlQ2hhdFZpZXcoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgY29uc3QgeyB3b3Jrc3BhY2UgfSA9IHRoaXMuYXBwO1xuXG4gICAgLy8gUmV1c2UgZXhpc3RpbmcgbGVhZiBpZiBhbHJlYWR5IG9wZW5cbiAgICBjb25zdCBleGlzdGluZyA9IHdvcmtzcGFjZS5nZXRMZWF2ZXNPZlR5cGUoVklFV19UWVBFX09QRU5DTEFXX0NIQVQpO1xuICAgIGlmIChleGlzdGluZy5sZW5ndGggPiAwKSB7XG4gICAgICB3b3Jrc3BhY2UucmV2ZWFsTGVhZihleGlzdGluZ1swXSk7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgLy8gT3BlbiBpbiByaWdodCBzaWRlYmFyXG4gICAgY29uc3QgbGVhZiA9IHdvcmtzcGFjZS5nZXRSaWdodExlYWYoZmFsc2UpO1xuICAgIGlmICghbGVhZikgcmV0dXJuO1xuICAgIGF3YWl0IGxlYWYuc2V0Vmlld1N0YXRlKHsgdHlwZTogVklFV19UWVBFX09QRU5DTEFXX0NIQVQsIGFjdGl2ZTogdHJ1ZSB9KTtcbiAgICB3b3Jrc3BhY2UucmV2ZWFsTGVhZihsZWFmKTtcbiAgfVxufVxuIiwgImltcG9ydCB7IEFwcCwgUGx1Z2luU2V0dGluZ1RhYiwgU2V0dGluZyB9IGZyb20gJ29ic2lkaWFuJztcbmltcG9ydCB0eXBlIE9wZW5DbGF3UGx1Z2luIGZyb20gJy4vbWFpbic7XG5cbmV4cG9ydCBjbGFzcyBPcGVuQ2xhd1NldHRpbmdUYWIgZXh0ZW5kcyBQbHVnaW5TZXR0aW5nVGFiIHtcbiAgcGx1Z2luOiBPcGVuQ2xhd1BsdWdpbjtcblxuICBjb25zdHJ1Y3RvcihhcHA6IEFwcCwgcGx1Z2luOiBPcGVuQ2xhd1BsdWdpbikge1xuICAgIHN1cGVyKGFwcCwgcGx1Z2luKTtcbiAgICB0aGlzLnBsdWdpbiA9IHBsdWdpbjtcbiAgfVxuXG4gIGRpc3BsYXkoKTogdm9pZCB7XG4gICAgY29uc3QgeyBjb250YWluZXJFbCB9ID0gdGhpcztcbiAgICBjb250YWluZXJFbC5lbXB0eSgpO1xuXG4gICAgY29udGFpbmVyRWwuY3JlYXRlRWwoJ2gyJywgeyB0ZXh0OiAnT3BlbkNsYXcgQ2hhdCBcdTIwMTMgU2V0dGluZ3MnIH0pO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZSgnR2F0ZXdheSBVUkwnKVxuICAgICAgLnNldERlc2MoJ1dlYlNvY2tldCBVUkwgb2YgdGhlIE9wZW5DbGF3IEdhdGV3YXkgKGUuZy4gd3M6Ly9ob3N0bmFtZToxODc4OSkuJylcbiAgICAgIC5hZGRUZXh0KCh0ZXh0KSA9PlxuICAgICAgICB0ZXh0XG4gICAgICAgICAgLnNldFBsYWNlaG9sZGVyKCd3czovL2xvY2FsaG9zdDoxODc4OScpXG4gICAgICAgICAgLnNldFZhbHVlKHRoaXMucGx1Z2luLnNldHRpbmdzLmdhdGV3YXlVcmwpXG4gICAgICAgICAgLm9uQ2hhbmdlKGFzeW5jICh2YWx1ZSkgPT4ge1xuICAgICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3MuZ2F0ZXdheVVybCA9IHZhbHVlLnRyaW0oKTtcbiAgICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICAgIH0pXG4gICAgICApO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZSgnQXV0aCB0b2tlbicpXG4gICAgICAuc2V0RGVzYygnTXVzdCBtYXRjaCB0aGUgYXV0aFRva2VuIGluIHlvdXIgb3BlbmNsYXcuanNvbiBjaGFubmVsIGNvbmZpZy4gTmV2ZXIgc2hhcmVkLicpXG4gICAgICAuYWRkVGV4dCgodGV4dCkgPT4ge1xuICAgICAgICB0ZXh0XG4gICAgICAgICAgLnNldFBsYWNlaG9sZGVyKCdFbnRlciB0b2tlblx1MjAyNicpXG4gICAgICAgICAgLnNldFZhbHVlKHRoaXMucGx1Z2luLnNldHRpbmdzLmF1dGhUb2tlbilcbiAgICAgICAgICAub25DaGFuZ2UoYXN5bmMgKHZhbHVlKSA9PiB7XG4gICAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5hdXRoVG9rZW4gPSB2YWx1ZTtcbiAgICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICAgIH0pO1xuICAgICAgICAvLyBUcmVhdCBhcyBwYXNzd29yZCBmaWVsZCBcdTIwMTMgZG8gbm90IHJldmVhbCB0b2tlbiBpbiBVSVxuICAgICAgICB0ZXh0LmlucHV0RWwudHlwZSA9ICdwYXNzd29yZCc7XG4gICAgICAgIHRleHQuaW5wdXRFbC5hdXRvY29tcGxldGUgPSAnb2ZmJztcbiAgICAgIH0pO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZSgnU2Vzc2lvbiBLZXknKVxuICAgICAgLnNldERlc2MoJ09wZW5DbGF3IHNlc3Npb24gdG8gc3Vic2NyaWJlIHRvICh1c3VhbGx5IFwibWFpblwiKS4nKVxuICAgICAgLmFkZFRleHQoKHRleHQpID0+XG4gICAgICAgIHRleHRcbiAgICAgICAgICAuc2V0UGxhY2Vob2xkZXIoJ21haW4nKVxuICAgICAgICAgIC5zZXRWYWx1ZSh0aGlzLnBsdWdpbi5zZXR0aW5ncy5zZXNzaW9uS2V5KVxuICAgICAgICAgIC5vbkNoYW5nZShhc3luYyAodmFsdWUpID0+IHtcbiAgICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLnNlc3Npb25LZXkgPSB2YWx1ZS50cmltKCkgfHwgJ21haW4nO1xuICAgICAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uc2F2ZVNldHRpbmdzKCk7XG4gICAgICAgICAgfSlcbiAgICAgICk7XG5cbiAgICBuZXcgU2V0dGluZyhjb250YWluZXJFbClcbiAgICAgIC5zZXROYW1lKCdBY2NvdW50IElEJylcbiAgICAgIC5zZXREZXNjKCdPcGVuQ2xhdyBhY2NvdW50IElEICh1c3VhbGx5IFwibWFpblwiKS4nKVxuICAgICAgLmFkZFRleHQoKHRleHQpID0+XG4gICAgICAgIHRleHRcbiAgICAgICAgICAuc2V0UGxhY2Vob2xkZXIoJ21haW4nKVxuICAgICAgICAgIC5zZXRWYWx1ZSh0aGlzLnBsdWdpbi5zZXR0aW5ncy5hY2NvdW50SWQpXG4gICAgICAgICAgLm9uQ2hhbmdlKGFzeW5jICh2YWx1ZSkgPT4ge1xuICAgICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3MuYWNjb3VudElkID0gdmFsdWUudHJpbSgpIHx8ICdtYWluJztcbiAgICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICAgIH0pXG4gICAgICApO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZSgnSW5jbHVkZSBhY3RpdmUgbm90ZSBieSBkZWZhdWx0JylcbiAgICAgIC5zZXREZXNjKCdQcmUtY2hlY2sgXCJJbmNsdWRlIGFjdGl2ZSBub3RlXCIgaW4gdGhlIGNoYXQgcGFuZWwgd2hlbiBpdCBvcGVucy4nKVxuICAgICAgLmFkZFRvZ2dsZSgodG9nZ2xlKSA9PlxuICAgICAgICB0b2dnbGUuc2V0VmFsdWUodGhpcy5wbHVnaW4uc2V0dGluZ3MuaW5jbHVkZUFjdGl2ZU5vdGUpLm9uQ2hhbmdlKGFzeW5jICh2YWx1ZSkgPT4ge1xuICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLmluY2x1ZGVBY3RpdmVOb3RlID0gdmFsdWU7XG4gICAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uc2F2ZVNldHRpbmdzKCk7XG4gICAgICAgIH0pXG4gICAgICApO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZSgnUmVuZGVyIGFzc2lzdGFudCBhcyBNYXJrZG93biAodW5zYWZlKScpXG4gICAgICAuc2V0RGVzYyhcbiAgICAgICAgJ09GRiByZWNvbW1lbmRlZC4gSWYgZW5hYmxlZCwgYXNzaXN0YW50IG91dHB1dCBpcyByZW5kZXJlZCBhcyBPYnNpZGlhbiBNYXJrZG93biB3aGljaCBtYXkgdHJpZ2dlciBlbWJlZHMgYW5kIG90aGVyIHBsdWdpbnNcXCcgcG9zdC1wcm9jZXNzb3JzLidcbiAgICAgIClcbiAgICAgIC5hZGRUb2dnbGUoKHRvZ2dsZSkgPT5cbiAgICAgICAgdG9nZ2xlLnNldFZhbHVlKHRoaXMucGx1Z2luLnNldHRpbmdzLnJlbmRlckFzc2lzdGFudE1hcmtkb3duKS5vbkNoYW5nZShhc3luYyAodmFsdWUpID0+IHtcbiAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5yZW5kZXJBc3Npc3RhbnRNYXJrZG93biA9IHZhbHVlO1xuICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICB9KVxuICAgICAgKTtcblxuICAgIGNvbnRhaW5lckVsLmNyZWF0ZUVsKCdwJywge1xuICAgICAgdGV4dDogJ1JlY29ubmVjdDogY2xvc2UgYW5kIHJlb3BlbiB0aGUgc2lkZWJhciBhZnRlciBjaGFuZ2luZyB0aGUgZ2F0ZXdheSBVUkwgb3IgdG9rZW4uJyxcbiAgICAgIGNsczogJ3NldHRpbmctaXRlbS1kZXNjcmlwdGlvbicsXG4gICAgfSk7XG4gIH1cbn1cbiIsICIvKipcbiAqIFdlYlNvY2tldCBjbGllbnQgZm9yIE9wZW5DbGF3IEdhdGV3YXlcbiAqXG4gKiBQaXZvdCAoMjAyNi0wMi0yNSk6IERvIE5PVCB1c2UgY3VzdG9tIG9ic2lkaWFuLiogZ2F0ZXdheSBtZXRob2RzLlxuICogVGhvc2UgcmVxdWlyZSBvcGVyYXRvci5hZG1pbiBzY29wZSB3aGljaCBpcyBub3QgZ3JhbnRlZCB0byBleHRlcm5hbCBjbGllbnRzLlxuICpcbiAqIEF1dGggbm90ZTpcbiAqIC0gY2hhdC5zZW5kIHJlcXVpcmVzIG9wZXJhdG9yLndyaXRlXG4gKiAtIGV4dGVybmFsIGNsaWVudHMgbXVzdCBwcmVzZW50IGEgcGFpcmVkIGRldmljZSBpZGVudGl0eSB0byByZWNlaXZlIHdyaXRlIHNjb3Blc1xuICpcbiAqIFdlIHVzZSBidWlsdC1pbiBnYXRld2F5IG1ldGhvZHMvZXZlbnRzOlxuICogLSBTZW5kOiBjaGF0LnNlbmQoeyBzZXNzaW9uS2V5LCBtZXNzYWdlLCBpZGVtcG90ZW5jeUtleSwgLi4uIH0pXG4gKiAtIFJlY2VpdmU6IGV2ZW50IFwiY2hhdFwiIChmaWx0ZXIgYnkgc2Vzc2lvbktleSlcbiAqL1xuXG5pbXBvcnQgdHlwZSB7IEluYm91bmRXU1BheWxvYWQgfSBmcm9tICcuL3R5cGVzJztcblxuLyoqIE1pbGxpc2Vjb25kcyBiZWZvcmUgYSByZWNvbm5lY3QgYXR0ZW1wdCBhZnRlciBhbiB1bmV4cGVjdGVkIGNsb3NlICovXG5jb25zdCBSRUNPTk5FQ1RfREVMQVlfTVMgPSAzXzAwMDtcbi8qKiBJbnRlcnZhbCBmb3Igc2VuZGluZyBoZWFydGJlYXQgcGluZ3MgKGNoZWNrIGNvbm5lY3Rpb24gbGl2ZW5lc3MpICovXG5jb25zdCBIRUFSVEJFQVRfSU5URVJWQUxfTVMgPSAzMF8wMDA7XG5cbi8qKiBTYWZldHkgdmFsdmU6IGhpZGUgd29ya2luZyBzcGlubmVyIGlmIG5vIGFzc2lzdGFudCByZXBseSBhcnJpdmVzIGluIHRpbWUgKi9cbmNvbnN0IFdPUktJTkdfTUFYX01TID0gMTIwXzAwMDtcblxuZXhwb3J0IHR5cGUgV1NDbGllbnRTdGF0ZSA9ICdkaXNjb25uZWN0ZWQnIHwgJ2Nvbm5lY3RpbmcnIHwgJ2hhbmRzaGFraW5nJyB8ICdjb25uZWN0ZWQnO1xuXG5leHBvcnQgdHlwZSBXb3JraW5nU3RhdGVMaXN0ZW5lciA9ICh3b3JraW5nOiBib29sZWFuKSA9PiB2b2lkO1xuXG5pbnRlcmZhY2UgUGVuZGluZ1JlcXVlc3Qge1xuICByZXNvbHZlOiAocGF5bG9hZDogYW55KSA9PiB2b2lkO1xuICByZWplY3Q6IChlcnJvcjogYW55KSA9PiB2b2lkO1xuICB0aW1lb3V0OiBSZXR1cm5UeXBlPHR5cGVvZiBzZXRUaW1lb3V0PiB8IG51bGw7XG59XG5cbnR5cGUgRGV2aWNlSWRlbnRpdHkgPSB7XG4gIGlkOiBzdHJpbmc7XG4gIHB1YmxpY0tleTogc3RyaW5nOyAvLyBiYXNlNjRcbiAgcHJpdmF0ZUtleUp3azogSnNvbldlYktleTtcbn07XG5cbmNvbnN0IERFVklDRV9TVE9SQUdFX0tFWSA9ICdvcGVuY2xhd0NoYXQuZGV2aWNlSWRlbnRpdHkudjEnO1xuXG5mdW5jdGlvbiBiYXNlNjRVcmxFbmNvZGUoYnl0ZXM6IEFycmF5QnVmZmVyKTogc3RyaW5nIHtcbiAgY29uc3QgdTggPSBuZXcgVWludDhBcnJheShieXRlcyk7XG4gIGxldCBzID0gJyc7XG4gIGZvciAobGV0IGkgPSAwOyBpIDwgdTgubGVuZ3RoOyBpKyspIHMgKz0gU3RyaW5nLmZyb21DaGFyQ29kZSh1OFtpXSk7XG4gIGNvbnN0IGI2NCA9IGJ0b2Eocyk7XG4gIHJldHVybiBiNjQucmVwbGFjZSgvXFwrL2csICctJykucmVwbGFjZSgvXFwvL2csICdfJykucmVwbGFjZSgvPSskL2csICcnKTtcbn1cblxuZnVuY3Rpb24gaGV4RW5jb2RlKGJ5dGVzOiBBcnJheUJ1ZmZlcik6IHN0cmluZyB7XG4gIGNvbnN0IHU4ID0gbmV3IFVpbnQ4QXJyYXkoYnl0ZXMpO1xuICByZXR1cm4gQXJyYXkuZnJvbSh1OClcbiAgICAubWFwKChiKSA9PiBiLnRvU3RyaW5nKDE2KS5wYWRTdGFydCgyLCAnMCcpKVxuICAgIC5qb2luKCcnKTtcbn1cblxuZnVuY3Rpb24gdXRmOEJ5dGVzKHRleHQ6IHN0cmluZyk6IFVpbnQ4QXJyYXkge1xuICByZXR1cm4gbmV3IFRleHRFbmNvZGVyKCkuZW5jb2RlKHRleHQpO1xufVxuXG5hc3luYyBmdW5jdGlvbiBzaGEyNTZIZXgoYnl0ZXM6IEFycmF5QnVmZmVyKTogUHJvbWlzZTxzdHJpbmc+IHtcbiAgY29uc3QgZGlnZXN0ID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5kaWdlc3QoJ1NIQS0yNTYnLCBieXRlcyk7XG4gIHJldHVybiBoZXhFbmNvZGUoZGlnZXN0KTtcbn1cblxuYXN5bmMgZnVuY3Rpb24gbG9hZE9yQ3JlYXRlRGV2aWNlSWRlbnRpdHkoKTogUHJvbWlzZTxEZXZpY2VJZGVudGl0eT4ge1xuICBjb25zdCBleGlzdGluZyA9IGxvY2FsU3RvcmFnZS5nZXRJdGVtKERFVklDRV9TVE9SQUdFX0tFWSk7XG4gIGlmIChleGlzdGluZykge1xuICAgIGNvbnN0IHBhcnNlZCA9IEpTT04ucGFyc2UoZXhpc3RpbmcpIGFzIERldmljZUlkZW50aXR5O1xuICAgIGlmIChwYXJzZWQ/LmlkICYmIHBhcnNlZD8ucHVibGljS2V5ICYmIHBhcnNlZD8ucHJpdmF0ZUtleUp3aykgcmV0dXJuIHBhcnNlZDtcbiAgfVxuXG4gIGNvbnN0IGtleVBhaXIgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmdlbmVyYXRlS2V5KHsgbmFtZTogJ0VkMjU1MTknIH0sIHRydWUsIFsnc2lnbicsICd2ZXJpZnknXSk7XG4gIGNvbnN0IHB1YlJhdyA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuZXhwb3J0S2V5KCdyYXcnLCBrZXlQYWlyLnB1YmxpY0tleSk7XG4gIGNvbnN0IHByaXZKd2sgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmV4cG9ydEtleSgnandrJywga2V5UGFpci5wcml2YXRlS2V5KTtcblxuICAvLyBJTVBPUlRBTlQ6IGRldmljZS5pZCBtdXN0IGJlIGEgc3RhYmxlIGZpbmdlcnByaW50IGZvciB0aGUgcHVibGljIGtleS5cbiAgLy8gVGhlIGdhdGV3YXkgZW5mb3JjZXMgZGV2aWNlSWQgXHUyMTk0IHB1YmxpY0tleSBiaW5kaW5nOyByYW5kb20gaWRzIGNhbiBjYXVzZSBcImRldmljZSBpZGVudGl0eSBtaXNtYXRjaFwiLlxuICBjb25zdCBkZXZpY2VJZCA9IGF3YWl0IHNoYTI1NkhleChwdWJSYXcpO1xuICBjb25zdCBpZCA9IGRldmljZUlkO1xuXG4gIGNvbnN0IGlkZW50aXR5OiBEZXZpY2VJZGVudGl0eSA9IHtcbiAgICBpZCxcbiAgICBwdWJsaWNLZXk6IGJhc2U2NFVybEVuY29kZShwdWJSYXcpLFxuICAgIHByaXZhdGVLZXlKd2s6IHByaXZKd2ssXG4gIH07XG5cbiAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oREVWSUNFX1NUT1JBR0VfS0VZLCBKU09OLnN0cmluZ2lmeShpZGVudGl0eSkpO1xuICByZXR1cm4gaWRlbnRpdHk7XG59XG5cbmZ1bmN0aW9uIGJ1aWxkRGV2aWNlQXV0aFBheWxvYWQocGFyYW1zOiB7XG4gIGRldmljZUlkOiBzdHJpbmc7XG4gIGNsaWVudElkOiBzdHJpbmc7XG4gIGNsaWVudE1vZGU6IHN0cmluZztcbiAgcm9sZTogc3RyaW5nO1xuICBzY29wZXM6IHN0cmluZ1tdO1xuICBzaWduZWRBdE1zOiBudW1iZXI7XG4gIHRva2VuOiBzdHJpbmc7XG4gIG5vbmNlPzogc3RyaW5nO1xufSk6IHN0cmluZyB7XG4gIGNvbnN0IHZlcnNpb24gPSBwYXJhbXMubm9uY2UgPyAndjInIDogJ3YxJztcbiAgY29uc3Qgc2NvcGVzID0gcGFyYW1zLnNjb3Blcy5qb2luKCcsJyk7XG4gIGNvbnN0IGJhc2UgPSBbXG4gICAgdmVyc2lvbixcbiAgICBwYXJhbXMuZGV2aWNlSWQsXG4gICAgcGFyYW1zLmNsaWVudElkLFxuICAgIHBhcmFtcy5jbGllbnRNb2RlLFxuICAgIHBhcmFtcy5yb2xlLFxuICAgIHNjb3BlcyxcbiAgICBTdHJpbmcocGFyYW1zLnNpZ25lZEF0TXMpLFxuICAgIHBhcmFtcy50b2tlbiB8fCAnJyxcbiAgXTtcbiAgaWYgKHZlcnNpb24gPT09ICd2MicpIGJhc2UucHVzaChwYXJhbXMubm9uY2UgfHwgJycpO1xuICByZXR1cm4gYmFzZS5qb2luKCd8Jyk7XG59XG5cbmFzeW5jIGZ1bmN0aW9uIHNpZ25EZXZpY2VQYXlsb2FkKGlkZW50aXR5OiBEZXZpY2VJZGVudGl0eSwgcGF5bG9hZDogc3RyaW5nKTogUHJvbWlzZTx7IHNpZ25hdHVyZTogc3RyaW5nIH0+IHtcbiAgY29uc3QgcHJpdmF0ZUtleSA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KFxuICAgICdqd2snLFxuICAgIGlkZW50aXR5LnByaXZhdGVLZXlKd2ssXG4gICAgeyBuYW1lOiAnRWQyNTUxOScgfSxcbiAgICBmYWxzZSxcbiAgICBbJ3NpZ24nXSxcbiAgKTtcblxuICBjb25zdCBzaWcgPSBhd2FpdCBjcnlwdG8uc3VidGxlLnNpZ24oeyBuYW1lOiAnRWQyNTUxOScgfSwgcHJpdmF0ZUtleSwgdXRmOEJ5dGVzKHBheWxvYWQpIGFzIHVua25vd24gYXMgQnVmZmVyU291cmNlKTtcbiAgcmV0dXJuIHsgc2lnbmF0dXJlOiBiYXNlNjRVcmxFbmNvZGUoc2lnKSB9O1xufVxuXG5mdW5jdGlvbiBleHRyYWN0VGV4dEZyb21HYXRld2F5TWVzc2FnZShtc2c6IGFueSk6IHN0cmluZyB7XG4gIGlmICghbXNnKSByZXR1cm4gJyc7XG5cbiAgLy8gTW9zdCBjb21tb246IHsgcm9sZSwgY29udGVudCB9IHdoZXJlIGNvbnRlbnQgY2FuIGJlIHN0cmluZyBvciBbe3R5cGU6J3RleHQnLHRleHQ6Jy4uLid9XVxuICBjb25zdCBjb250ZW50ID0gbXNnLmNvbnRlbnQgPz8gbXNnLm1lc3NhZ2UgPz8gbXNnO1xuICBpZiAodHlwZW9mIGNvbnRlbnQgPT09ICdzdHJpbmcnKSByZXR1cm4gY29udGVudDtcblxuICBpZiAoQXJyYXkuaXNBcnJheShjb250ZW50KSkge1xuICAgIGNvbnN0IHBhcnRzID0gY29udGVudFxuICAgICAgLmZpbHRlcigoYykgPT4gYyAmJiB0eXBlb2YgYyA9PT0gJ29iamVjdCcgJiYgYy50eXBlID09PSAndGV4dCcgJiYgdHlwZW9mIGMudGV4dCA9PT0gJ3N0cmluZycpXG4gICAgICAubWFwKChjKSA9PiBjLnRleHQpO1xuICAgIHJldHVybiBwYXJ0cy5qb2luKCdcXG4nKTtcbiAgfVxuXG4gIC8vIEZhbGxiYWNrXG4gIHRyeSB7XG4gICAgcmV0dXJuIEpTT04uc3RyaW5naWZ5KGNvbnRlbnQpO1xuICB9IGNhdGNoIHtcbiAgICByZXR1cm4gU3RyaW5nKGNvbnRlbnQpO1xuICB9XG59XG5cbmZ1bmN0aW9uIHNlc3Npb25LZXlNYXRjaGVzKGNvbmZpZ3VyZWQ6IHN0cmluZywgaW5jb21pbmc6IHN0cmluZyk6IGJvb2xlYW4ge1xuICBpZiAoaW5jb21pbmcgPT09IGNvbmZpZ3VyZWQpIHJldHVybiB0cnVlO1xuICAvLyBPcGVuQ2xhdyByZXNvbHZlcyBcIm1haW5cIiB0byBjYW5vbmljYWwgc2Vzc2lvbiBrZXkgbGlrZSBcImFnZW50Om1haW46bWFpblwiLlxuICBpZiAoY29uZmlndXJlZCA9PT0gJ21haW4nICYmIGluY29taW5nID09PSAnYWdlbnQ6bWFpbjptYWluJykgcmV0dXJuIHRydWU7XG4gIHJldHVybiBmYWxzZTtcbn1cblxuZXhwb3J0IGNsYXNzIE9ic2lkaWFuV1NDbGllbnQge1xuICBwcml2YXRlIHdzOiBXZWJTb2NrZXQgfCBudWxsID0gbnVsbDtcbiAgcHJpdmF0ZSByZWNvbm5lY3RUaW1lcjogUmV0dXJuVHlwZTx0eXBlb2Ygc2V0VGltZW91dD4gfCBudWxsID0gbnVsbDtcbiAgcHJpdmF0ZSBoZWFydGJlYXRUaW1lcjogUmV0dXJuVHlwZTx0eXBlb2Ygc2V0SW50ZXJ2YWw+IHwgbnVsbCA9IG51bGw7XG4gIHByaXZhdGUgd29ya2luZ1RpbWVyOiBSZXR1cm5UeXBlPHR5cGVvZiBzZXRUaW1lb3V0PiB8IG51bGwgPSBudWxsO1xuICBwcml2YXRlIGludGVudGlvbmFsQ2xvc2UgPSBmYWxzZTtcbiAgcHJpdmF0ZSBzZXNzaW9uS2V5OiBzdHJpbmc7XG4gIHByaXZhdGUgdXJsID0gJyc7XG4gIHByaXZhdGUgdG9rZW4gPSAnJztcbiAgcHJpdmF0ZSByZXF1ZXN0SWQgPSAwO1xuICBwcml2YXRlIHBlbmRpbmdSZXF1ZXN0cyA9IG5ldyBNYXA8c3RyaW5nLCBQZW5kaW5nUmVxdWVzdD4oKTtcbiAgcHJpdmF0ZSB3b3JraW5nID0gZmFsc2U7XG5cbiAgLyoqIFRoZSBsYXN0IGluLWZsaWdodCBjaGF0IHJ1biBpZC4gSW4gT3BlbkNsYXcgV2ViQ2hhdCB0aGlzIG1hcHMgdG8gY2hhdC5zZW5kIGlkZW1wb3RlbmN5S2V5LiAqL1xuICBwcml2YXRlIGFjdGl2ZVJ1bklkOiBzdHJpbmcgfCBudWxsID0gbnVsbDtcblxuICAvKiogUHJldmVudHMgYWJvcnQgc3BhbW1pbmc6IHdoaWxlIGFuIGFib3J0IHJlcXVlc3QgaXMgaW4tZmxpZ2h0LCByZXVzZSB0aGUgc2FtZSBwcm9taXNlLiAqL1xuICBwcml2YXRlIGFib3J0SW5GbGlnaHQ6IFByb21pc2U8Ym9vbGVhbj4gfCBudWxsID0gbnVsbDtcblxuICBzdGF0ZTogV1NDbGllbnRTdGF0ZSA9ICdkaXNjb25uZWN0ZWQnO1xuXG4gIG9uTWVzc2FnZTogKChtc2c6IEluYm91bmRXU1BheWxvYWQpID0+IHZvaWQpIHwgbnVsbCA9IG51bGw7XG4gIG9uU3RhdGVDaGFuZ2U6ICgoc3RhdGU6IFdTQ2xpZW50U3RhdGUpID0+IHZvaWQpIHwgbnVsbCA9IG51bGw7XG4gIG9uV29ya2luZ0NoYW5nZTogV29ya2luZ1N0YXRlTGlzdGVuZXIgfCBudWxsID0gbnVsbDtcblxuICBjb25zdHJ1Y3RvcihzZXNzaW9uS2V5OiBzdHJpbmcpIHtcbiAgICB0aGlzLnNlc3Npb25LZXkgPSBzZXNzaW9uS2V5O1xuICB9XG5cbiAgY29ubmVjdCh1cmw6IHN0cmluZywgdG9rZW46IHN0cmluZyk6IHZvaWQge1xuICAgIHRoaXMudXJsID0gdXJsO1xuICAgIHRoaXMudG9rZW4gPSB0b2tlbjtcbiAgICB0aGlzLmludGVudGlvbmFsQ2xvc2UgPSBmYWxzZTtcbiAgICB0aGlzLl9jb25uZWN0KCk7XG4gIH1cblxuICBkaXNjb25uZWN0KCk6IHZvaWQge1xuICAgIHRoaXMuaW50ZW50aW9uYWxDbG9zZSA9IHRydWU7XG4gICAgdGhpcy5fc3RvcFRpbWVycygpO1xuICAgIHRoaXMuYWN0aXZlUnVuSWQgPSBudWxsO1xuICAgIHRoaXMuYWJvcnRJbkZsaWdodCA9IG51bGw7XG4gICAgdGhpcy5fc2V0V29ya2luZyhmYWxzZSk7XG4gICAgaWYgKHRoaXMud3MpIHtcbiAgICAgIHRoaXMud3MuY2xvc2UoKTtcbiAgICAgIHRoaXMud3MgPSBudWxsO1xuICAgIH1cbiAgICB0aGlzLl9zZXRTdGF0ZSgnZGlzY29ubmVjdGVkJyk7XG4gIH1cblxuICBhc3luYyBzZW5kTWVzc2FnZShtZXNzYWdlOiBzdHJpbmcpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBpZiAodGhpcy5zdGF0ZSAhPT0gJ2Nvbm5lY3RlZCcpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcignTm90IGNvbm5lY3RlZCBcdTIwMTQgY2FsbCBjb25uZWN0KCkgZmlyc3QnKTtcbiAgICB9XG5cbiAgICBjb25zdCBydW5JZCA9IGBvYnNpZGlhbi0ke0RhdGUubm93KCl9LSR7TWF0aC5yYW5kb20oKS50b1N0cmluZygzNikuc2xpY2UoMiwgOSl9YDtcblxuICAgIC8vIFNob3cgXHUyMDFDd29ya2luZ1x1MjAxRCBPTkxZIGFmdGVyIHRoZSBnYXRld2F5IGFja25vd2xlZGdlcyB0aGUgcmVxdWVzdC5cbiAgICBjb25zdCBhY2sgPSBhd2FpdCB0aGlzLl9zZW5kUmVxdWVzdCgnY2hhdC5zZW5kJywge1xuICAgICAgc2Vzc2lvbktleTogdGhpcy5zZXNzaW9uS2V5LFxuICAgICAgbWVzc2FnZSxcbiAgICAgIGlkZW1wb3RlbmN5S2V5OiBydW5JZCxcbiAgICAgIC8vIGRlbGl2ZXIgZGVmYXVsdHMgdG8gdHJ1ZSBpbiBnYXRld2F5OyBrZWVwIGRlZmF1bHRcbiAgICB9KTtcblxuICAgIC8vIElmIHRoZSBnYXRld2F5IHJldHVybnMgYSBjYW5vbmljYWwgcnVuIGlkZW50aWZpZXIsIHByZWZlciBpdC5cbiAgICBjb25zdCBjYW5vbmljYWxSdW5JZCA9IFN0cmluZyhhY2s/LnJ1bklkIHx8IGFjaz8uaWRlbXBvdGVuY3lLZXkgfHwgJycpO1xuICAgIHRoaXMuYWN0aXZlUnVuSWQgPSBjYW5vbmljYWxSdW5JZCB8fCBydW5JZDtcbiAgICB0aGlzLl9zZXRXb3JraW5nKHRydWUpO1xuICAgIHRoaXMuX2FybVdvcmtpbmdTYWZldHlUaW1lb3V0KCk7XG4gIH1cblxuICAvKiogQWJvcnQgdGhlIGFjdGl2ZSBydW4gZm9yIHRoaXMgc2Vzc2lvbiAoYW5kIG91ciBsYXN0IHJ1biBpZCBpZiBwcmVzZW50KS4gKi9cbiAgYXN5bmMgYWJvcnRBY3RpdmVSdW4oKTogUHJvbWlzZTxib29sZWFuPiB7XG4gICAgaWYgKHRoaXMuc3RhdGUgIT09ICdjb25uZWN0ZWQnKSB7XG4gICAgICByZXR1cm4gZmFsc2U7XG4gICAgfVxuXG4gICAgLy8gUHJldmVudCByZXF1ZXN0IHN0b3Jtczogd2hpbGUgb25lIGFib3J0IGlzIGluIGZsaWdodCwgcmV1c2UgaXQuXG4gICAgaWYgKHRoaXMuYWJvcnRJbkZsaWdodCkge1xuICAgICAgcmV0dXJuIHRoaXMuYWJvcnRJbkZsaWdodDtcbiAgICB9XG5cbiAgICBjb25zdCBydW5JZCA9IHRoaXMuYWN0aXZlUnVuSWQ7XG4gICAgaWYgKCFydW5JZCkge1xuICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH1cblxuICAgIHRoaXMuYWJvcnRJbkZsaWdodCA9IChhc3luYyAoKSA9PiB7XG4gICAgICB0cnkge1xuICAgICAgICBhd2FpdCB0aGlzLl9zZW5kUmVxdWVzdCgnY2hhdC5hYm9ydCcsIHsgc2Vzc2lvbktleTogdGhpcy5zZXNzaW9uS2V5LCBydW5JZCB9KTtcbiAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICB9IGNhdGNoIChlcnIpIHtcbiAgICAgICAgY29uc29sZS5lcnJvcignW29jbGF3LXdzXSBjaGF0LmFib3J0IGZhaWxlZCcsIGVycik7XG4gICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgIH0gZmluYWxseSB7XG4gICAgICAgIC8vIEFsd2F5cyByZXN0b3JlIFVJIHN0YXRlIGltbWVkaWF0ZWx5OyB0aGUgZ2F0ZXdheSBtYXkgc3RpbGwgZW1pdCBhbiBhYm9ydGVkIGV2ZW50IGxhdGVyLlxuICAgICAgICB0aGlzLmFjdGl2ZVJ1bklkID0gbnVsbDtcbiAgICAgICAgdGhpcy5fc2V0V29ya2luZyhmYWxzZSk7XG4gICAgICAgIHRoaXMuYWJvcnRJbkZsaWdodCA9IG51bGw7XG4gICAgICB9XG4gICAgfSkoKTtcblxuICAgIHJldHVybiB0aGlzLmFib3J0SW5GbGlnaHQ7XG4gIH1cblxuICBwcml2YXRlIF9jb25uZWN0KCk6IHZvaWQge1xuICAgIGlmICh0aGlzLndzKSB7XG4gICAgICB0aGlzLndzLm9ub3BlbiA9IG51bGw7XG4gICAgICB0aGlzLndzLm9uY2xvc2UgPSBudWxsO1xuICAgICAgdGhpcy53cy5vbm1lc3NhZ2UgPSBudWxsO1xuICAgICAgdGhpcy53cy5vbmVycm9yID0gbnVsbDtcbiAgICAgIHRoaXMud3MuY2xvc2UoKTtcbiAgICAgIHRoaXMud3MgPSBudWxsO1xuICAgIH1cblxuICAgIHRoaXMuX3NldFN0YXRlKCdjb25uZWN0aW5nJyk7XG5cbiAgICBjb25zdCB3cyA9IG5ldyBXZWJTb2NrZXQodGhpcy51cmwpO1xuICAgIHRoaXMud3MgPSB3cztcblxuICAgIGxldCBjb25uZWN0Tm9uY2U6IHN0cmluZyB8IG51bGwgPSBudWxsO1xuICAgIGxldCBjb25uZWN0U3RhcnRlZCA9IGZhbHNlO1xuXG4gICAgY29uc3QgdHJ5Q29ubmVjdCA9IGFzeW5jICgpID0+IHtcbiAgICAgIGlmIChjb25uZWN0U3RhcnRlZCkgcmV0dXJuO1xuICAgICAgaWYgKCFjb25uZWN0Tm9uY2UpIHJldHVybjtcbiAgICAgIGNvbm5lY3RTdGFydGVkID0gdHJ1ZTtcblxuICAgICAgdHJ5IHtcbiAgICAgICAgY29uc3QgaWRlbnRpdHkgPSBhd2FpdCBsb2FkT3JDcmVhdGVEZXZpY2VJZGVudGl0eSgpO1xuICAgICAgICBjb25zdCBzaWduZWRBdE1zID0gRGF0ZS5ub3coKTtcbiAgICAgICAgY29uc3QgcGF5bG9hZCA9IGJ1aWxkRGV2aWNlQXV0aFBheWxvYWQoe1xuICAgICAgICAgIGRldmljZUlkOiBpZGVudGl0eS5pZCxcbiAgICAgICAgICBjbGllbnRJZDogJ2dhdGV3YXktY2xpZW50JyxcbiAgICAgICAgICBjbGllbnRNb2RlOiAnYmFja2VuZCcsXG4gICAgICAgICAgcm9sZTogJ29wZXJhdG9yJyxcbiAgICAgICAgICBzY29wZXM6IFsnb3BlcmF0b3IucmVhZCcsICdvcGVyYXRvci53cml0ZSddLFxuICAgICAgICAgIHNpZ25lZEF0TXMsXG4gICAgICAgICAgdG9rZW46IHRoaXMudG9rZW4sXG4gICAgICAgICAgbm9uY2U6IGNvbm5lY3ROb25jZSxcbiAgICAgICAgfSk7XG4gICAgICAgIGNvbnN0IHNpZyA9IGF3YWl0IHNpZ25EZXZpY2VQYXlsb2FkKGlkZW50aXR5LCBwYXlsb2FkKTtcblxuICAgICAgICBhd2FpdCB0aGlzLl9zZW5kUmVxdWVzdCgnY29ubmVjdCcsIHtcbiAgICAgICAgICBtaW5Qcm90b2NvbDogMyxcbiAgICAgICAgICBtYXhQcm90b2NvbDogMyxcbiAgICAgICAgICBjbGllbnQ6IHtcbiAgICAgICAgICAgIGlkOiAnZ2F0ZXdheS1jbGllbnQnLFxuICAgICAgICAgICAgbW9kZTogJ2JhY2tlbmQnLFxuICAgICAgICAgICAgdmVyc2lvbjogJzAuMS4xMCcsXG4gICAgICAgICAgICBwbGF0Zm9ybTogJ2VsZWN0cm9uJyxcbiAgICAgICAgICB9LFxuICAgICAgICAgIHJvbGU6ICdvcGVyYXRvcicsXG4gICAgICAgICAgc2NvcGVzOiBbJ29wZXJhdG9yLnJlYWQnLCAnb3BlcmF0b3Iud3JpdGUnXSxcbiAgICAgICAgICBkZXZpY2U6IHtcbiAgICAgICAgICAgIGlkOiBpZGVudGl0eS5pZCxcbiAgICAgICAgICAgIHB1YmxpY0tleTogaWRlbnRpdHkucHVibGljS2V5LFxuICAgICAgICAgICAgc2lnbmF0dXJlOiBzaWcuc2lnbmF0dXJlLFxuICAgICAgICAgICAgc2lnbmVkQXQ6IHNpZ25lZEF0TXMsXG4gICAgICAgICAgICBub25jZTogY29ubmVjdE5vbmNlLFxuICAgICAgICAgIH0sXG4gICAgICAgICAgYXV0aDoge1xuICAgICAgICAgICAgdG9rZW46IHRoaXMudG9rZW4sXG4gICAgICAgICAgfSxcbiAgICAgICAgfSk7XG5cbiAgICAgICAgdGhpcy5fc2V0U3RhdGUoJ2Nvbm5lY3RlZCcpO1xuICAgICAgICB0aGlzLl9zdGFydEhlYXJ0YmVhdCgpO1xuICAgICAgfSBjYXRjaCAoZXJyKSB7XG4gICAgICAgIGNvbnNvbGUuZXJyb3IoJ1tvY2xhdy13c10gQ29ubmVjdCBoYW5kc2hha2UgZmFpbGVkJywgZXJyKTtcbiAgICAgICAgd3MuY2xvc2UoKTtcbiAgICAgIH1cbiAgICB9O1xuXG4gICAgd3Mub25vcGVuID0gKCkgPT4ge1xuICAgICAgdGhpcy5fc2V0U3RhdGUoJ2hhbmRzaGFraW5nJyk7XG4gICAgICAvLyBUaGUgZ2F0ZXdheSB3aWxsIHNlbmQgY29ubmVjdC5jaGFsbGVuZ2U7IGNvbm5lY3QgaXMgc2VudCBvbmNlIHdlIGhhdmUgYSBub25jZS5cbiAgICB9O1xuXG4gICAgd3Mub25tZXNzYWdlID0gKGV2ZW50OiBNZXNzYWdlRXZlbnQpID0+IHtcbiAgICAgIGxldCBmcmFtZTogYW55O1xuICAgICAgdHJ5IHtcbiAgICAgICAgZnJhbWUgPSBKU09OLnBhcnNlKGV2ZW50LmRhdGEgYXMgc3RyaW5nKTtcbiAgICAgIH0gY2F0Y2gge1xuICAgICAgICBjb25zb2xlLmVycm9yKCdbb2NsYXctd3NdIEZhaWxlZCB0byBwYXJzZSBpbmNvbWluZyBtZXNzYWdlJyk7XG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cblxuICAgICAgLy8gUmVzcG9uc2VzXG4gICAgICBpZiAoZnJhbWUudHlwZSA9PT0gJ3JlcycpIHtcbiAgICAgICAgdGhpcy5faGFuZGxlUmVzcG9uc2VGcmFtZShmcmFtZSk7XG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cblxuICAgICAgLy8gRXZlbnRzXG4gICAgICBpZiAoZnJhbWUudHlwZSA9PT0gJ2V2ZW50Jykge1xuICAgICAgICBpZiAoZnJhbWUuZXZlbnQgPT09ICdjb25uZWN0LmNoYWxsZW5nZScpIHtcbiAgICAgICAgICBjb25uZWN0Tm9uY2UgPSBmcmFtZS5wYXlsb2FkPy5ub25jZSB8fCBudWxsO1xuICAgICAgICAgIC8vIEF0dGVtcHQgaGFuZHNoYWtlIG9uY2Ugd2UgaGF2ZSBhIG5vbmNlLlxuICAgICAgICAgIHZvaWQgdHJ5Q29ubmVjdCgpO1xuICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmIChmcmFtZS5ldmVudCA9PT0gJ2NoYXQnKSB7XG4gICAgICAgICAgdGhpcy5faGFuZGxlQ2hhdEV2ZW50RnJhbWUoZnJhbWUpO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cblxuICAgICAgLy8gQXZvaWQgbG9nZ2luZyBmdWxsIGZyYW1lcyAobWF5IGluY2x1ZGUgbWVzc2FnZSBjb250ZW50IG9yIG90aGVyIHNlbnNpdGl2ZSBwYXlsb2FkcykuXG4gICAgICBjb25zb2xlLmRlYnVnKCdbb2NsYXctd3NdIFVuaGFuZGxlZCBmcmFtZScsIHsgdHlwZTogZnJhbWU/LnR5cGUsIGV2ZW50OiBmcmFtZT8uZXZlbnQsIGlkOiBmcmFtZT8uaWQgfSk7XG4gICAgfTtcblxuICAgIHdzLm9uY2xvc2UgPSAoKSA9PiB7XG4gICAgICB0aGlzLl9zdG9wVGltZXJzKCk7XG4gICAgICB0aGlzLmFjdGl2ZVJ1bklkID0gbnVsbDtcbiAgICAgIHRoaXMuYWJvcnRJbkZsaWdodCA9IG51bGw7XG4gICAgICB0aGlzLl9zZXRXb3JraW5nKGZhbHNlKTtcbiAgICAgIHRoaXMuX3NldFN0YXRlKCdkaXNjb25uZWN0ZWQnKTtcblxuICAgICAgZm9yIChjb25zdCBwZW5kaW5nIG9mIHRoaXMucGVuZGluZ1JlcXVlc3RzLnZhbHVlcygpKSB7XG4gICAgICAgIGlmIChwZW5kaW5nLnRpbWVvdXQpIGNsZWFyVGltZW91dChwZW5kaW5nLnRpbWVvdXQpO1xuICAgICAgICBwZW5kaW5nLnJlamVjdChuZXcgRXJyb3IoJ0Nvbm5lY3Rpb24gY2xvc2VkJykpO1xuICAgICAgfVxuICAgICAgdGhpcy5wZW5kaW5nUmVxdWVzdHMuY2xlYXIoKTtcblxuICAgICAgaWYgKCF0aGlzLmludGVudGlvbmFsQ2xvc2UpIHtcbiAgICAgICAgdGhpcy5fc2NoZWR1bGVSZWNvbm5lY3QoKTtcbiAgICAgIH1cbiAgICB9O1xuXG4gICAgd3Mub25lcnJvciA9IChldjogRXZlbnQpID0+IHtcbiAgICAgIGNvbnNvbGUuZXJyb3IoJ1tvY2xhdy13c10gV2ViU29ja2V0IGVycm9yJywgZXYpO1xuICAgIH07XG4gIH1cblxuICBwcml2YXRlIF9oYW5kbGVSZXNwb25zZUZyYW1lKGZyYW1lOiBhbnkpOiB2b2lkIHtcbiAgICBjb25zdCBwZW5kaW5nID0gdGhpcy5wZW5kaW5nUmVxdWVzdHMuZ2V0KGZyYW1lLmlkKTtcbiAgICBpZiAoIXBlbmRpbmcpIHJldHVybjtcblxuICAgIHRoaXMucGVuZGluZ1JlcXVlc3RzLmRlbGV0ZShmcmFtZS5pZCk7XG4gICAgaWYgKHBlbmRpbmcudGltZW91dCkgY2xlYXJUaW1lb3V0KHBlbmRpbmcudGltZW91dCk7XG5cbiAgICBpZiAoZnJhbWUub2spIHBlbmRpbmcucmVzb2x2ZShmcmFtZS5wYXlsb2FkKTtcbiAgICBlbHNlIHBlbmRpbmcucmVqZWN0KG5ldyBFcnJvcihmcmFtZS5lcnJvcj8ubWVzc2FnZSB8fCAnUmVxdWVzdCBmYWlsZWQnKSk7XG4gIH1cblxuICBwcml2YXRlIF9oYW5kbGVDaGF0RXZlbnRGcmFtZShmcmFtZTogYW55KTogdm9pZCB7XG4gICAgY29uc3QgcGF5bG9hZCA9IGZyYW1lLnBheWxvYWQ7XG4gICAgY29uc3QgaW5jb21pbmdTZXNzaW9uS2V5ID0gU3RyaW5nKHBheWxvYWQ/LnNlc3Npb25LZXkgfHwgJycpO1xuICAgIGlmICghaW5jb21pbmdTZXNzaW9uS2V5IHx8ICFzZXNzaW9uS2V5TWF0Y2hlcyh0aGlzLnNlc3Npb25LZXksIGluY29taW5nU2Vzc2lvbktleSkpIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICAvLyBCZXN0LWVmZm9ydCBydW4gY29ycmVsYXRpb24gKGlmIGdhdGV3YXkgaW5jbHVkZXMgYSBydW4gaWQpLiBUaGlzIGF2b2lkcyBjbGVhcmluZyBvdXIgVUlcbiAgICAvLyBiYXNlZCBvbiBhIGRpZmZlcmVudCBjbGllbnQncyBydW4gaW4gdGhlIHNhbWUgc2Vzc2lvbi5cbiAgICBjb25zdCBpbmNvbWluZ1J1bklkID0gU3RyaW5nKHBheWxvYWQ/LnJ1bklkIHx8IHBheWxvYWQ/LmlkZW1wb3RlbmN5S2V5IHx8IHBheWxvYWQ/Lm1ldGE/LnJ1bklkIHx8ICcnKTtcbiAgICBpZiAodGhpcy5hY3RpdmVSdW5JZCAmJiBpbmNvbWluZ1J1bklkICYmIGluY29taW5nUnVuSWQgIT09IHRoaXMuYWN0aXZlUnVuSWQpIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICAvLyBBdm9pZCBkb3VibGUtcmVuZGVyOiBnYXRld2F5IGVtaXRzIGRlbHRhICsgZmluYWwgKyBhYm9ydGVkLiBSZW5kZXIgb25seSBleHBsaWNpdCBmaW5hbC9hYm9ydGVkLlxuICAgIC8vIElmIHN0YXRlIGlzIG1pc3NpbmcsIHRyZWF0IGFzIG5vbi10ZXJtaW5hbCAoZG8gbm90IGNsZWFyIFVJIC8gZG8gbm90IHJlbmRlcikuXG4gICAgaWYgKCFwYXlsb2FkPy5zdGF0ZSkge1xuICAgICAgcmV0dXJuO1xuICAgIH1cbiAgICBpZiAocGF5bG9hZC5zdGF0ZSAhPT0gJ2ZpbmFsJyAmJiBwYXlsb2FkLnN0YXRlICE9PSAnYWJvcnRlZCcpIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICAvLyBXZSBvbmx5IGFwcGVuZCBhc3Npc3RhbnQgb3V0cHV0IHRvIFVJLlxuICAgIGNvbnN0IG1zZyA9IHBheWxvYWQ/Lm1lc3NhZ2U7XG4gICAgY29uc3Qgcm9sZSA9IG1zZz8ucm9sZSA/PyAnYXNzaXN0YW50JztcblxuICAgIC8vIEFib3J0ZWQgZW5kcyB0aGUgcnVuIHJlZ2FyZGxlc3Mgb2Ygcm9sZS9tZXNzYWdlLlxuICAgIGlmIChwYXlsb2FkLnN0YXRlID09PSAnYWJvcnRlZCcpIHtcbiAgICAgIHRoaXMuYWN0aXZlUnVuSWQgPSBudWxsO1xuICAgICAgdGhpcy5fc2V0V29ya2luZyhmYWxzZSk7XG4gICAgICAvLyBBYm9ydGVkIG1heSBoYXZlIG5vIGFzc2lzdGFudCBtZXNzYWdlOyBpZiBub25lLCBzdG9wIGhlcmUuXG4gICAgICBpZiAoIW1zZykgcmV0dXJuO1xuICAgICAgLy8gSWYgdGhlcmUgaXMgYSBtZXNzYWdlLCBvbmx5IGFwcGVuZCBhc3Npc3RhbnQgb3V0cHV0LlxuICAgICAgaWYgKHJvbGUgIT09ICdhc3Npc3RhbnQnKSByZXR1cm47XG4gICAgfVxuXG4gICAgLy8gRmluYWwgc2hvdWxkIG9ubHkgY29tcGxldGUgdGhlIHJ1biB3aGVuIHRoZSBhc3Npc3RhbnQgY29tcGxldGVzLlxuICAgIGlmIChwYXlsb2FkLnN0YXRlID09PSAnZmluYWwnKSB7XG4gICAgICBpZiAocm9sZSAhPT0gJ2Fzc2lzdGFudCcpIHJldHVybjtcbiAgICAgIHRoaXMuYWN0aXZlUnVuSWQgPSBudWxsO1xuICAgICAgdGhpcy5fc2V0V29ya2luZyhmYWxzZSk7XG4gICAgfVxuXG4gICAgY29uc3QgdGV4dCA9IGV4dHJhY3RUZXh0RnJvbUdhdGV3YXlNZXNzYWdlKG1zZyk7XG4gICAgaWYgKCF0ZXh0KSByZXR1cm47XG5cbiAgICAvLyBPcHRpb25hbDogaGlkZSBoZWFydGJlYXQgYWNrcyAobm9pc2UgaW4gVUkpXG4gICAgaWYgKHRleHQudHJpbSgpID09PSAnSEVBUlRCRUFUX09LJykge1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIHRoaXMub25NZXNzYWdlPy4oe1xuICAgICAgdHlwZTogJ21lc3NhZ2UnLFxuICAgICAgcGF5bG9hZDoge1xuICAgICAgICBjb250ZW50OiB0ZXh0LFxuICAgICAgICByb2xlOiAnYXNzaXN0YW50JyxcbiAgICAgICAgdGltZXN0YW1wOiBEYXRlLm5vdygpLFxuICAgICAgfSxcbiAgICB9KTtcbiAgfVxuXG4gIHByaXZhdGUgX3NlbmRSZXF1ZXN0KG1ldGhvZDogc3RyaW5nLCBwYXJhbXM6IGFueSk6IFByb21pc2U8YW55PiB7XG4gICAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIGlmICghdGhpcy53cyB8fCB0aGlzLndzLnJlYWR5U3RhdGUgIT09IFdlYlNvY2tldC5PUEVOKSB7XG4gICAgICAgIHJlamVjdChuZXcgRXJyb3IoJ1dlYlNvY2tldCBub3QgY29ubmVjdGVkJykpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG5cbiAgICAgIGNvbnN0IGlkID0gYHJlcS0keysrdGhpcy5yZXF1ZXN0SWR9YDtcblxuICAgICAgY29uc3QgcGVuZGluZzogUGVuZGluZ1JlcXVlc3QgPSB7IHJlc29sdmUsIHJlamVjdCwgdGltZW91dDogbnVsbCB9O1xuICAgICAgdGhpcy5wZW5kaW5nUmVxdWVzdHMuc2V0KGlkLCBwZW5kaW5nKTtcblxuICAgICAgdGhpcy53cy5zZW5kKFxuICAgICAgICBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgdHlwZTogJ3JlcScsXG4gICAgICAgICAgbWV0aG9kLFxuICAgICAgICAgIGlkLFxuICAgICAgICAgIHBhcmFtcyxcbiAgICAgICAgfSlcbiAgICAgICk7XG5cbiAgICAgIHBlbmRpbmcudGltZW91dCA9IHNldFRpbWVvdXQoKCkgPT4ge1xuICAgICAgICBpZiAodGhpcy5wZW5kaW5nUmVxdWVzdHMuaGFzKGlkKSkge1xuICAgICAgICAgIHRoaXMucGVuZGluZ1JlcXVlc3RzLmRlbGV0ZShpZCk7XG4gICAgICAgICAgcmVqZWN0KG5ldyBFcnJvcihgUmVxdWVzdCB0aW1lb3V0OiAke21ldGhvZH1gKSk7XG4gICAgICAgIH1cbiAgICAgIH0sIDMwXzAwMCk7XG4gICAgfSk7XG4gIH1cblxuICBwcml2YXRlIF9zY2hlZHVsZVJlY29ubmVjdCgpOiB2b2lkIHtcbiAgICBpZiAodGhpcy5yZWNvbm5lY3RUaW1lciAhPT0gbnVsbCkgcmV0dXJuO1xuICAgIHRoaXMucmVjb25uZWN0VGltZXIgPSBzZXRUaW1lb3V0KCgpID0+IHtcbiAgICAgIHRoaXMucmVjb25uZWN0VGltZXIgPSBudWxsO1xuICAgICAgaWYgKCF0aGlzLmludGVudGlvbmFsQ2xvc2UpIHtcbiAgICAgICAgY29uc29sZS5sb2coYFtvY2xhdy13c10gUmVjb25uZWN0aW5nIHRvICR7dGhpcy51cmx9XHUyMDI2YCk7XG4gICAgICAgIHRoaXMuX2Nvbm5lY3QoKTtcbiAgICAgIH1cbiAgICB9LCBSRUNPTk5FQ1RfREVMQVlfTVMpO1xuICB9XG5cbiAgcHJpdmF0ZSBsYXN0QnVmZmVyZWRXYXJuQXRNcyA9IDA7XG5cbiAgcHJpdmF0ZSBfc3RhcnRIZWFydGJlYXQoKTogdm9pZCB7XG4gICAgdGhpcy5fc3RvcEhlYXJ0YmVhdCgpO1xuICAgIHRoaXMuaGVhcnRiZWF0VGltZXIgPSBzZXRJbnRlcnZhbCgoKSA9PiB7XG4gICAgICBpZiAodGhpcy53cz8ucmVhZHlTdGF0ZSAhPT0gV2ViU29ja2V0Lk9QRU4pIHJldHVybjtcbiAgICAgIGlmICh0aGlzLndzLmJ1ZmZlcmVkQW1vdW50ID4gMCkge1xuICAgICAgICBjb25zdCBub3cgPSBEYXRlLm5vdygpO1xuICAgICAgICAvLyBUaHJvdHRsZSB0byBhdm9pZCBsb2cgc3BhbSBpbiBsb25nLXJ1bm5pbmcgc2Vzc2lvbnMuXG4gICAgICAgIGlmIChub3cgLSB0aGlzLmxhc3RCdWZmZXJlZFdhcm5BdE1zID4gNSAqIDYwXzAwMCkge1xuICAgICAgICAgIHRoaXMubGFzdEJ1ZmZlcmVkV2FybkF0TXMgPSBub3c7XG4gICAgICAgICAgY29uc29sZS53YXJuKCdbb2NsYXctd3NdIFNlbmQgYnVmZmVyIG5vdCBlbXB0eSBcdTIwMTQgY29ubmVjdGlvbiBtYXkgYmUgc3RhbGxlZCcpO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSwgSEVBUlRCRUFUX0lOVEVSVkFMX01TKTtcbiAgfVxuXG4gIHByaXZhdGUgX3N0b3BIZWFydGJlYXQoKTogdm9pZCB7XG4gICAgaWYgKHRoaXMuaGVhcnRiZWF0VGltZXIpIHtcbiAgICAgIGNsZWFySW50ZXJ2YWwodGhpcy5oZWFydGJlYXRUaW1lcik7XG4gICAgICB0aGlzLmhlYXJ0YmVhdFRpbWVyID0gbnVsbDtcbiAgICB9XG4gIH1cblxuICBwcml2YXRlIF9zdG9wVGltZXJzKCk6IHZvaWQge1xuICAgIHRoaXMuX3N0b3BIZWFydGJlYXQoKTtcbiAgICB0aGlzLl9kaXNhcm1Xb3JraW5nU2FmZXR5VGltZW91dCgpO1xuICAgIGlmICh0aGlzLnJlY29ubmVjdFRpbWVyKSB7XG4gICAgICBjbGVhclRpbWVvdXQodGhpcy5yZWNvbm5lY3RUaW1lcik7XG4gICAgICB0aGlzLnJlY29ubmVjdFRpbWVyID0gbnVsbDtcbiAgICB9XG4gIH1cblxuICBwcml2YXRlIF9zZXRTdGF0ZShzdGF0ZTogV1NDbGllbnRTdGF0ZSk6IHZvaWQge1xuICAgIGlmICh0aGlzLnN0YXRlID09PSBzdGF0ZSkgcmV0dXJuO1xuICAgIHRoaXMuc3RhdGUgPSBzdGF0ZTtcbiAgICB0aGlzLm9uU3RhdGVDaGFuZ2U/LihzdGF0ZSk7XG4gIH1cblxuICBwcml2YXRlIF9zZXRXb3JraW5nKHdvcmtpbmc6IGJvb2xlYW4pOiB2b2lkIHtcbiAgICBpZiAodGhpcy53b3JraW5nID09PSB3b3JraW5nKSByZXR1cm47XG4gICAgdGhpcy53b3JraW5nID0gd29ya2luZztcbiAgICB0aGlzLm9uV29ya2luZ0NoYW5nZT8uKHdvcmtpbmcpO1xuXG4gICAgaWYgKCF3b3JraW5nKSB7XG4gICAgICB0aGlzLl9kaXNhcm1Xb3JraW5nU2FmZXR5VGltZW91dCgpO1xuICAgIH1cbiAgfVxuXG4gIHByaXZhdGUgX2FybVdvcmtpbmdTYWZldHlUaW1lb3V0KCk6IHZvaWQge1xuICAgIHRoaXMuX2Rpc2FybVdvcmtpbmdTYWZldHlUaW1lb3V0KCk7XG4gICAgdGhpcy53b3JraW5nVGltZXIgPSBzZXRUaW1lb3V0KCgpID0+IHtcbiAgICAgIC8vIElmIHRoZSBnYXRld2F5IG5ldmVyIGVtaXRzIGFuIGFzc2lzdGFudCBmaW5hbCByZXNwb25zZSwgZG9uXHUyMDE5dCBsZWF2ZSBVSSBzdHVjay5cbiAgICAgIHRoaXMuX3NldFdvcmtpbmcoZmFsc2UpO1xuICAgIH0sIFdPUktJTkdfTUFYX01TKTtcbiAgfVxuXG4gIHByaXZhdGUgX2Rpc2FybVdvcmtpbmdTYWZldHlUaW1lb3V0KCk6IHZvaWQge1xuICAgIGlmICh0aGlzLndvcmtpbmdUaW1lcikge1xuICAgICAgY2xlYXJUaW1lb3V0KHRoaXMud29ya2luZ1RpbWVyKTtcbiAgICAgIHRoaXMud29ya2luZ1RpbWVyID0gbnVsbDtcbiAgICB9XG4gIH1cbn1cbiIsICJpbXBvcnQgdHlwZSB7IENoYXRNZXNzYWdlIH0gZnJvbSAnLi90eXBlcyc7XG5cbi8qKiBNYW5hZ2VzIHRoZSBpbi1tZW1vcnkgbGlzdCBvZiBjaGF0IG1lc3NhZ2VzIGFuZCBub3RpZmllcyBVSSBvbiBjaGFuZ2VzICovXG5leHBvcnQgY2xhc3MgQ2hhdE1hbmFnZXIge1xuICBwcml2YXRlIG1lc3NhZ2VzOiBDaGF0TWVzc2FnZVtdID0gW107XG5cbiAgLyoqIEZpcmVkIGZvciBhIGZ1bGwgcmUtcmVuZGVyIChjbGVhci9yZWxvYWQpICovXG4gIG9uVXBkYXRlOiAoKG1lc3NhZ2VzOiByZWFkb25seSBDaGF0TWVzc2FnZVtdKSA9PiB2b2lkKSB8IG51bGwgPSBudWxsO1xuICAvKiogRmlyZWQgd2hlbiBhIHNpbmdsZSBtZXNzYWdlIGlzIGFwcGVuZGVkIFx1MjAxNCB1c2UgZm9yIE8oMSkgYXBwZW5kLW9ubHkgVUkgKi9cbiAgb25NZXNzYWdlQWRkZWQ6ICgobXNnOiBDaGF0TWVzc2FnZSkgPT4gdm9pZCkgfCBudWxsID0gbnVsbDtcblxuICBhZGRNZXNzYWdlKG1zZzogQ2hhdE1lc3NhZ2UpOiB2b2lkIHtcbiAgICB0aGlzLm1lc3NhZ2VzLnB1c2gobXNnKTtcbiAgICB0aGlzLm9uTWVzc2FnZUFkZGVkPy4obXNnKTtcbiAgfVxuXG4gIGdldE1lc3NhZ2VzKCk6IHJlYWRvbmx5IENoYXRNZXNzYWdlW10ge1xuICAgIHJldHVybiB0aGlzLm1lc3NhZ2VzO1xuICB9XG5cbiAgY2xlYXIoKTogdm9pZCB7XG4gICAgdGhpcy5tZXNzYWdlcyA9IFtdO1xuICAgIHRoaXMub25VcGRhdGU/LihbXSk7XG4gIH1cblxuICAvKiogQ3JlYXRlIGEgdXNlciBtZXNzYWdlIG9iamVjdCAod2l0aG91dCBhZGRpbmcgaXQpICovXG4gIHN0YXRpYyBjcmVhdGVVc2VyTWVzc2FnZShjb250ZW50OiBzdHJpbmcpOiBDaGF0TWVzc2FnZSB7XG4gICAgcmV0dXJuIHtcbiAgICAgIGlkOiBgbXNnLSR7RGF0ZS5ub3coKX0tJHtNYXRoLnJhbmRvbSgpLnRvU3RyaW5nKDM2KS5zbGljZSgyLCA3KX1gLFxuICAgICAgcm9sZTogJ3VzZXInLFxuICAgICAgY29udGVudCxcbiAgICAgIHRpbWVzdGFtcDogRGF0ZS5ub3coKSxcbiAgICB9O1xuICB9XG5cbiAgLyoqIENyZWF0ZSBhbiBhc3Npc3RhbnQgbWVzc2FnZSBvYmplY3QgKHdpdGhvdXQgYWRkaW5nIGl0KSAqL1xuICBzdGF0aWMgY3JlYXRlQXNzaXN0YW50TWVzc2FnZShjb250ZW50OiBzdHJpbmcpOiBDaGF0TWVzc2FnZSB7XG4gICAgcmV0dXJuIHtcbiAgICAgIGlkOiBgbXNnLSR7RGF0ZS5ub3coKX0tJHtNYXRoLnJhbmRvbSgpLnRvU3RyaW5nKDM2KS5zbGljZSgyLCA3KX1gLFxuICAgICAgcm9sZTogJ2Fzc2lzdGFudCcsXG4gICAgICBjb250ZW50LFxuICAgICAgdGltZXN0YW1wOiBEYXRlLm5vdygpLFxuICAgIH07XG4gIH1cblxuICAvKiogQ3JlYXRlIGEgc3lzdGVtIC8gc3RhdHVzIG1lc3NhZ2UgKGVycm9ycywgcmVjb25uZWN0IG5vdGljZXMsIGV0Yy4pICovXG4gIHN0YXRpYyBjcmVhdGVTeXN0ZW1NZXNzYWdlKGNvbnRlbnQ6IHN0cmluZywgbGV2ZWw6IENoYXRNZXNzYWdlWydsZXZlbCddID0gJ2luZm8nKTogQ2hhdE1lc3NhZ2Uge1xuICAgIHJldHVybiB7XG4gICAgICBpZDogYHN5cy0ke0RhdGUubm93KCl9YCxcbiAgICAgIHJvbGU6ICdzeXN0ZW0nLFxuICAgICAgbGV2ZWwsXG4gICAgICBjb250ZW50LFxuICAgICAgdGltZXN0YW1wOiBEYXRlLm5vdygpLFxuICAgIH07XG4gIH1cbn1cbiIsICJpbXBvcnQgeyBJdGVtVmlldywgTWFya2Rvd25SZW5kZXJlciwgTm90aWNlLCBXb3Jrc3BhY2VMZWFmIH0gZnJvbSAnb2JzaWRpYW4nO1xuaW1wb3J0IHR5cGUgT3BlbkNsYXdQbHVnaW4gZnJvbSAnLi9tYWluJztcbmltcG9ydCB7IENoYXRNYW5hZ2VyIH0gZnJvbSAnLi9jaGF0JztcbmltcG9ydCB0eXBlIHsgQ2hhdE1lc3NhZ2UgfSBmcm9tICcuL3R5cGVzJztcbmltcG9ydCB7IGdldEFjdGl2ZU5vdGVDb250ZXh0IH0gZnJvbSAnLi9jb250ZXh0JztcblxuZXhwb3J0IGNvbnN0IFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFUID0gJ29wZW5jbGF3LWNoYXQnO1xuXG5leHBvcnQgY2xhc3MgT3BlbkNsYXdDaGF0VmlldyBleHRlbmRzIEl0ZW1WaWV3IHtcbiAgcHJpdmF0ZSBwbHVnaW46IE9wZW5DbGF3UGx1Z2luO1xuICBwcml2YXRlIGNoYXRNYW5hZ2VyOiBDaGF0TWFuYWdlcjtcblxuICAvLyBTdGF0ZVxuICBwcml2YXRlIGlzQ29ubmVjdGVkID0gZmFsc2U7XG4gIHByaXZhdGUgaXNXb3JraW5nID0gZmFsc2U7XG5cbiAgLy8gRE9NIHJlZnNcbiAgcHJpdmF0ZSBtZXNzYWdlc0VsITogSFRNTEVsZW1lbnQ7XG4gIHByaXZhdGUgaW5wdXRFbCE6IEhUTUxUZXh0QXJlYUVsZW1lbnQ7XG4gIHByaXZhdGUgc2VuZEJ0biE6IEhUTUxCdXR0b25FbGVtZW50O1xuICBwcml2YXRlIGluY2x1ZGVOb3RlQ2hlY2tib3ghOiBIVE1MSW5wdXRFbGVtZW50O1xuICBwcml2YXRlIHN0YXR1c0RvdCE6IEhUTUxFbGVtZW50O1xuXG4gIGNvbnN0cnVjdG9yKGxlYWY6IFdvcmtzcGFjZUxlYWYsIHBsdWdpbjogT3BlbkNsYXdQbHVnaW4pIHtcbiAgICBzdXBlcihsZWFmKTtcbiAgICB0aGlzLnBsdWdpbiA9IHBsdWdpbjtcbiAgICB0aGlzLmNoYXRNYW5hZ2VyID0gcGx1Z2luLmNoYXRNYW5hZ2VyO1xuICB9XG5cbiAgZ2V0Vmlld1R5cGUoKTogc3RyaW5nIHtcbiAgICByZXR1cm4gVklFV19UWVBFX09QRU5DTEFXX0NIQVQ7XG4gIH1cblxuICBnZXREaXNwbGF5VGV4dCgpOiBzdHJpbmcge1xuICAgIHJldHVybiAnT3BlbkNsYXcgQ2hhdCc7XG4gIH1cblxuICBnZXRJY29uKCk6IHN0cmluZyB7XG4gICAgcmV0dXJuICdtZXNzYWdlLXNxdWFyZSc7XG4gIH1cblxuICBhc3luYyBvbk9wZW4oKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgdGhpcy5fYnVpbGRVSSgpO1xuXG4gICAgLy8gRnVsbCByZS1yZW5kZXIgb24gY2xlYXIgLyByZWxvYWRcbiAgICB0aGlzLmNoYXRNYW5hZ2VyLm9uVXBkYXRlID0gKG1zZ3MpID0+IHRoaXMuX3JlbmRlck1lc3NhZ2VzKG1zZ3MpO1xuICAgIC8vIE8oMSkgYXBwZW5kIGZvciBuZXcgbWVzc2FnZXNcbiAgICB0aGlzLmNoYXRNYW5hZ2VyLm9uTWVzc2FnZUFkZGVkID0gKG1zZykgPT4gdGhpcy5fYXBwZW5kTWVzc2FnZShtc2cpO1xuXG4gICAgLy8gU3Vic2NyaWJlIHRvIFdTIHN0YXRlIGNoYW5nZXNcbiAgICB0aGlzLnBsdWdpbi53c0NsaWVudC5vblN0YXRlQ2hhbmdlID0gKHN0YXRlKSA9PiB7XG4gICAgICB0aGlzLmlzQ29ubmVjdGVkID0gc3RhdGUgPT09ICdjb25uZWN0ZWQnO1xuICAgICAgdGhpcy5zdGF0dXNEb3QudG9nZ2xlQ2xhc3MoJ2Nvbm5lY3RlZCcsIHRoaXMuaXNDb25uZWN0ZWQpO1xuICAgICAgdGhpcy5zdGF0dXNEb3QudGl0bGUgPSBgR2F0ZXdheTogJHtzdGF0ZX1gO1xuICAgICAgdGhpcy5fdXBkYXRlU2VuZEJ1dHRvbigpO1xuICAgIH07XG5cbiAgICAvLyBTdWJzY3JpYmUgdG8gXHUyMDFDd29ya2luZ1x1MjAxRCAocmVxdWVzdC1pbi1mbGlnaHQpIHN0YXRlXG4gICAgdGhpcy5wbHVnaW4ud3NDbGllbnQub25Xb3JraW5nQ2hhbmdlID0gKHdvcmtpbmcpID0+IHtcbiAgICAgIHRoaXMuaXNXb3JraW5nID0gd29ya2luZztcbiAgICAgIHRoaXMuX3VwZGF0ZVNlbmRCdXR0b24oKTtcbiAgICB9O1xuXG4gICAgLy8gUmVmbGVjdCBjdXJyZW50IHN0YXRlXG4gICAgdGhpcy5pc0Nvbm5lY3RlZCA9IHRoaXMucGx1Z2luLndzQ2xpZW50LnN0YXRlID09PSAnY29ubmVjdGVkJztcbiAgICB0aGlzLnN0YXR1c0RvdC50b2dnbGVDbGFzcygnY29ubmVjdGVkJywgdGhpcy5pc0Nvbm5lY3RlZCk7XG4gICAgdGhpcy5fdXBkYXRlU2VuZEJ1dHRvbigpO1xuXG4gICAgdGhpcy5fcmVuZGVyTWVzc2FnZXModGhpcy5jaGF0TWFuYWdlci5nZXRNZXNzYWdlcygpKTtcbiAgfVxuXG4gIGFzeW5jIG9uQ2xvc2UoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgdGhpcy5jaGF0TWFuYWdlci5vblVwZGF0ZSA9IG51bGw7XG4gICAgdGhpcy5jaGF0TWFuYWdlci5vbk1lc3NhZ2VBZGRlZCA9IG51bGw7XG4gICAgdGhpcy5wbHVnaW4ud3NDbGllbnQub25TdGF0ZUNoYW5nZSA9IG51bGw7XG4gICAgdGhpcy5wbHVnaW4ud3NDbGllbnQub25Xb3JraW5nQ2hhbmdlID0gbnVsbDtcbiAgfVxuXG4gIC8vIFx1MjUwMFx1MjUwMCBVSSBjb25zdHJ1Y3Rpb24gXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG5cbiAgcHJpdmF0ZSBfYnVpbGRVSSgpOiB2b2lkIHtcbiAgICBjb25zdCByb290ID0gdGhpcy5jb250ZW50RWw7XG4gICAgcm9vdC5lbXB0eSgpO1xuICAgIHJvb3QuYWRkQ2xhc3MoJ29jbGF3LWNoYXQtdmlldycpO1xuXG4gICAgLy8gXHUyNTAwXHUyNTAwIEhlYWRlciBcdTI1MDBcdTI1MDBcbiAgICBjb25zdCBoZWFkZXIgPSByb290LmNyZWF0ZURpdih7IGNsczogJ29jbGF3LWhlYWRlcicgfSk7XG4gICAgaGVhZGVyLmNyZWF0ZVNwYW4oeyBjbHM6ICdvY2xhdy1oZWFkZXItdGl0bGUnLCB0ZXh0OiAnT3BlbkNsYXcgQ2hhdCcgfSk7XG4gICAgdGhpcy5zdGF0dXNEb3QgPSBoZWFkZXIuY3JlYXRlRGl2KHsgY2xzOiAnb2NsYXctc3RhdHVzLWRvdCcgfSk7XG4gICAgdGhpcy5zdGF0dXNEb3QudGl0bGUgPSAnR2F0ZXdheTogZGlzY29ubmVjdGVkJztcblxuICAgIC8vIFx1MjUwMFx1MjUwMCBNZXNzYWdlcyBhcmVhIFx1MjUwMFx1MjUwMFxuICAgIHRoaXMubWVzc2FnZXNFbCA9IHJvb3QuY3JlYXRlRGl2KHsgY2xzOiAnb2NsYXctbWVzc2FnZXMnIH0pO1xuXG4gICAgLy8gXHUyNTAwXHUyNTAwIENvbnRleHQgcm93IFx1MjUwMFx1MjUwMFxuICAgIGNvbnN0IGN0eFJvdyA9IHJvb3QuY3JlYXRlRGl2KHsgY2xzOiAnb2NsYXctY29udGV4dC1yb3cnIH0pO1xuICAgIHRoaXMuaW5jbHVkZU5vdGVDaGVja2JveCA9IGN0eFJvdy5jcmVhdGVFbCgnaW5wdXQnLCB7IHR5cGU6ICdjaGVja2JveCcgfSk7XG4gICAgdGhpcy5pbmNsdWRlTm90ZUNoZWNrYm94LmlkID0gJ29jbGF3LWluY2x1ZGUtbm90ZSc7XG4gICAgdGhpcy5pbmNsdWRlTm90ZUNoZWNrYm94LmNoZWNrZWQgPSB0aGlzLnBsdWdpbi5zZXR0aW5ncy5pbmNsdWRlQWN0aXZlTm90ZTtcbiAgICBjb25zdCBjdHhMYWJlbCA9IGN0eFJvdy5jcmVhdGVFbCgnbGFiZWwnLCB7IHRleHQ6ICdJbmNsdWRlIGFjdGl2ZSBub3RlJyB9KTtcbiAgICBjdHhMYWJlbC5odG1sRm9yID0gJ29jbGF3LWluY2x1ZGUtbm90ZSc7XG5cbiAgICAvLyBcdTI1MDBcdTI1MDAgSW5wdXQgcm93IFx1MjUwMFx1MjUwMFxuICAgIGNvbnN0IGlucHV0Um93ID0gcm9vdC5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1pbnB1dC1yb3cnIH0pO1xuICAgIHRoaXMuaW5wdXRFbCA9IGlucHV0Um93LmNyZWF0ZUVsKCd0ZXh0YXJlYScsIHtcbiAgICAgIGNsczogJ29jbGF3LWlucHV0JyxcbiAgICAgIHBsYWNlaG9sZGVyOiAnQXNrIGFueXRoaW5nXHUyMDI2JyxcbiAgICB9KTtcbiAgICB0aGlzLmlucHV0RWwucm93cyA9IDE7XG5cbiAgICB0aGlzLnNlbmRCdG4gPSBpbnB1dFJvdy5jcmVhdGVFbCgnYnV0dG9uJywgeyBjbHM6ICdvY2xhdy1zZW5kLWJ0bicsIHRleHQ6ICdTZW5kJyB9KTtcblxuICAgIC8vIFx1MjUwMFx1MjUwMCBFdmVudCBsaXN0ZW5lcnMgXHUyNTAwXHUyNTAwXG4gICAgdGhpcy5zZW5kQnRuLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gdGhpcy5faGFuZGxlU2VuZCgpKTtcbiAgICB0aGlzLmlucHV0RWwuYWRkRXZlbnRMaXN0ZW5lcigna2V5ZG93bicsIChlKSA9PiB7XG4gICAgICBpZiAoZS5rZXkgPT09ICdFbnRlcicgJiYgIWUuc2hpZnRLZXkpIHtcbiAgICAgICAgZS5wcmV2ZW50RGVmYXVsdCgpO1xuICAgICAgICB0aGlzLl9oYW5kbGVTZW5kKCk7XG4gICAgICB9XG4gICAgfSk7XG4gICAgLy8gQXV0by1yZXNpemUgdGV4dGFyZWFcbiAgICB0aGlzLmlucHV0RWwuYWRkRXZlbnRMaXN0ZW5lcignaW5wdXQnLCAoKSA9PiB7XG4gICAgICB0aGlzLmlucHV0RWwuc3R5bGUuaGVpZ2h0ID0gJ2F1dG8nO1xuICAgICAgdGhpcy5pbnB1dEVsLnN0eWxlLmhlaWdodCA9IGAke3RoaXMuaW5wdXRFbC5zY3JvbGxIZWlnaHR9cHhgO1xuICAgIH0pO1xuICB9XG5cbiAgLy8gXHUyNTAwXHUyNTAwIE1lc3NhZ2UgcmVuZGVyaW5nIFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFxuXG4gIHByaXZhdGUgX3JlbmRlck1lc3NhZ2VzKG1lc3NhZ2VzOiByZWFkb25seSBDaGF0TWVzc2FnZVtdKTogdm9pZCB7XG4gICAgdGhpcy5tZXNzYWdlc0VsLmVtcHR5KCk7XG5cbiAgICBpZiAobWVzc2FnZXMubGVuZ3RoID09PSAwKSB7XG4gICAgICB0aGlzLm1lc3NhZ2VzRWwuY3JlYXRlRWwoJ3AnLCB7XG4gICAgICAgIHRleHQ6ICdTZW5kIGEgbWVzc2FnZSB0byBzdGFydCBjaGF0dGluZy4nLFxuICAgICAgICBjbHM6ICdvY2xhdy1tZXNzYWdlIHN5c3RlbSBvY2xhdy1wbGFjZWhvbGRlcicsXG4gICAgICB9KTtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICBmb3IgKGNvbnN0IG1zZyBvZiBtZXNzYWdlcykge1xuICAgICAgdGhpcy5fYXBwZW5kTWVzc2FnZShtc2cpO1xuICAgIH1cblxuICAgIC8vIFNjcm9sbCB0byBib3R0b21cbiAgICB0aGlzLm1lc3NhZ2VzRWwuc2Nyb2xsVG9wID0gdGhpcy5tZXNzYWdlc0VsLnNjcm9sbEhlaWdodDtcbiAgfVxuXG4gIC8qKiBBcHBlbmRzIGEgc2luZ2xlIG1lc3NhZ2Ugd2l0aG91dCByZWJ1aWxkaW5nIHRoZSBET00gKE8oMSkpICovXG4gIHByaXZhdGUgX2FwcGVuZE1lc3NhZ2UobXNnOiBDaGF0TWVzc2FnZSk6IHZvaWQge1xuICAgIC8vIFJlbW92ZSBlbXB0eS1zdGF0ZSBwbGFjZWhvbGRlciBpZiBwcmVzZW50XG4gICAgdGhpcy5tZXNzYWdlc0VsLnF1ZXJ5U2VsZWN0b3IoJy5vY2xhdy1wbGFjZWhvbGRlcicpPy5yZW1vdmUoKTtcblxuICAgIGNvbnN0IGxldmVsQ2xhc3MgPSBtc2cubGV2ZWwgPyBgICR7bXNnLmxldmVsfWAgOiAnJztcbiAgICBjb25zdCBlbCA9IHRoaXMubWVzc2FnZXNFbC5jcmVhdGVEaXYoeyBjbHM6IGBvY2xhdy1tZXNzYWdlICR7bXNnLnJvbGV9JHtsZXZlbENsYXNzfWAgfSk7XG4gICAgY29uc3QgYm9keSA9IGVsLmNyZWF0ZURpdih7IGNsczogJ29jbGF3LW1lc3NhZ2UtYm9keScgfSk7XG5cbiAgICAvLyBUcmVhdCBhc3Npc3RhbnQgb3V0cHV0IGFzIFVOVFJVU1RFRCBieSBkZWZhdWx0LlxuICAgIC8vIFJlbmRlcmluZyBhcyBPYnNpZGlhbiBNYXJrZG93biBjYW4gdHJpZ2dlciBlbWJlZHMgYW5kIG90aGVyIHBsdWdpbnMnIHBvc3QtcHJvY2Vzc29ycy5cbiAgICBpZiAobXNnLnJvbGUgPT09ICdhc3Npc3RhbnQnICYmIHRoaXMucGx1Z2luLnNldHRpbmdzLnJlbmRlckFzc2lzdGFudE1hcmtkb3duKSB7XG4gICAgICBjb25zdCBzb3VyY2VQYXRoID0gdGhpcy5hcHAud29ya3NwYWNlLmdldEFjdGl2ZUZpbGUoKT8ucGF0aCA/PyAnJztcbiAgICAgIHZvaWQgTWFya2Rvd25SZW5kZXJlci5yZW5kZXJNYXJrZG93bihtc2cuY29udGVudCwgYm9keSwgc291cmNlUGF0aCwgdGhpcy5wbHVnaW4pO1xuICAgIH0gZWxzZSB7XG4gICAgICBib2R5LnNldFRleHQobXNnLmNvbnRlbnQpO1xuICAgIH1cblxuICAgIC8vIFNjcm9sbCB0byBib3R0b21cbiAgICB0aGlzLm1lc3NhZ2VzRWwuc2Nyb2xsVG9wID0gdGhpcy5tZXNzYWdlc0VsLnNjcm9sbEhlaWdodDtcbiAgfVxuXG4gIHByaXZhdGUgX3VwZGF0ZVNlbmRCdXR0b24oKTogdm9pZCB7XG4gICAgLy8gRGlzY29ubmVjdGVkOiBkaXNhYmxlLlxuICAgIC8vIFdvcmtpbmc6IGtlZXAgZW5hYmxlZCBzbyB1c2VyIGNhbiBzdG9wL2Fib3J0LlxuICAgIGNvbnN0IGRpc2FibGVkID0gIXRoaXMuaXNDb25uZWN0ZWQ7XG4gICAgdGhpcy5zZW5kQnRuLmRpc2FibGVkID0gZGlzYWJsZWQ7XG5cbiAgICB0aGlzLnNlbmRCdG4udG9nZ2xlQ2xhc3MoJ2lzLXdvcmtpbmcnLCB0aGlzLmlzV29ya2luZyk7XG4gICAgdGhpcy5zZW5kQnRuLnNldEF0dHIoJ2FyaWEtYnVzeScsIHRoaXMuaXNXb3JraW5nID8gJ3RydWUnIDogJ2ZhbHNlJyk7XG4gICAgdGhpcy5zZW5kQnRuLnNldEF0dHIoJ2FyaWEtbGFiZWwnLCB0aGlzLmlzV29ya2luZyA/ICdTdG9wJyA6ICdTZW5kJyk7XG5cbiAgICBpZiAodGhpcy5pc1dvcmtpbmcpIHtcbiAgICAgIC8vIFJlcGxhY2UgYnV0dG9uIGNvbnRlbnRzIHdpdGggU3RvcCBpY29uICsgc3Bpbm5lciByaW5nLlxuICAgICAgdGhpcy5zZW5kQnRuLmVtcHR5KCk7XG4gICAgICBjb25zdCB3cmFwID0gdGhpcy5zZW5kQnRuLmNyZWF0ZURpdih7IGNsczogJ29jbGF3LXN0b3Atd3JhcCcgfSk7XG4gICAgICB3cmFwLmNyZWF0ZURpdih7IGNsczogJ29jbGF3LXNwaW5uZXItcmluZycsIGF0dHI6IHsgJ2FyaWEtaGlkZGVuJzogJ3RydWUnIH0gfSk7XG4gICAgICB3cmFwLmNyZWF0ZURpdih7IGNsczogJ29jbGF3LXN0b3AtaWNvbicsIGF0dHI6IHsgJ2FyaWEtaGlkZGVuJzogJ3RydWUnIH0gfSk7XG4gICAgfSBlbHNlIHtcbiAgICAgIC8vIFJlc3RvcmUgbGFiZWxcbiAgICAgIHRoaXMuc2VuZEJ0bi5zZXRUZXh0KCdTZW5kJyk7XG4gICAgfVxuICB9XG5cbiAgLy8gXHUyNTAwXHUyNTAwIFNlbmQgaGFuZGxlciBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcblxuICBwcml2YXRlIGFzeW5jIF9oYW5kbGVTZW5kKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIC8vIFdoaWxlIHdvcmtpbmcsIHRoZSBidXR0b24gYmVjb21lcyBTdG9wLlxuICAgIGlmICh0aGlzLmlzV29ya2luZykge1xuICAgICAgY29uc3Qgb2sgPSBhd2FpdCB0aGlzLnBsdWdpbi53c0NsaWVudC5hYm9ydEFjdGl2ZVJ1bigpO1xuICAgICAgaWYgKCFvaykge1xuICAgICAgICBuZXcgTm90aWNlKCdPcGVuQ2xhdyBDaGF0OiBmYWlsZWQgdG8gc3RvcCcpO1xuICAgICAgICB0aGlzLmNoYXRNYW5hZ2VyLmFkZE1lc3NhZ2UoQ2hhdE1hbmFnZXIuY3JlYXRlU3lzdGVtTWVzc2FnZSgnXHUyNkEwIFN0b3AgZmFpbGVkJywgJ2Vycm9yJykpO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgdGhpcy5jaGF0TWFuYWdlci5hZGRNZXNzYWdlKENoYXRNYW5hZ2VyLmNyZWF0ZVN5c3RlbU1lc3NhZ2UoJ1x1MjZENCBTdG9wcGVkJywgJ2luZm8nKSk7XG4gICAgICB9XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgY29uc3QgdGV4dCA9IHRoaXMuaW5wdXRFbC52YWx1ZS50cmltKCk7XG4gICAgaWYgKCF0ZXh0KSByZXR1cm47XG5cbiAgICAvLyBCdWlsZCBtZXNzYWdlIHdpdGggY29udGV4dCBpZiBlbmFibGVkXG4gICAgbGV0IG1lc3NhZ2UgPSB0ZXh0O1xuICAgIGlmICh0aGlzLmluY2x1ZGVOb3RlQ2hlY2tib3guY2hlY2tlZCkge1xuICAgICAgY29uc3Qgbm90ZSA9IGF3YWl0IGdldEFjdGl2ZU5vdGVDb250ZXh0KHRoaXMuYXBwKTtcbiAgICAgIGlmIChub3RlKSB7XG4gICAgICAgIG1lc3NhZ2UgPSBgQ29udGV4dDogW1ske25vdGUudGl0bGV9XV1cXG5cXG4ke3RleHR9YDtcbiAgICAgIH1cbiAgICB9XG5cbiAgICAvLyBBZGQgdXNlciBtZXNzYWdlIHRvIGNoYXQgVUlcbiAgICBjb25zdCB1c2VyTXNnID0gQ2hhdE1hbmFnZXIuY3JlYXRlVXNlck1lc3NhZ2UodGV4dCk7XG4gICAgdGhpcy5jaGF0TWFuYWdlci5hZGRNZXNzYWdlKHVzZXJNc2cpO1xuXG4gICAgLy8gQ2xlYXIgaW5wdXRcbiAgICB0aGlzLmlucHV0RWwudmFsdWUgPSAnJztcbiAgICB0aGlzLmlucHV0RWwuc3R5bGUuaGVpZ2h0ID0gJ2F1dG8nO1xuXG4gICAgLy8gU2VuZCBvdmVyIFdTIChhc3luYylcbiAgICB0cnkge1xuICAgICAgYXdhaXQgdGhpcy5wbHVnaW4ud3NDbGllbnQuc2VuZE1lc3NhZ2UobWVzc2FnZSk7XG4gICAgfSBjYXRjaCAoZXJyKSB7XG4gICAgICBjb25zb2xlLmVycm9yKCdbb2NsYXddIFNlbmQgZmFpbGVkJywgZXJyKTtcbiAgICAgIG5ldyBOb3RpY2UoYE9wZW5DbGF3IENoYXQ6IHNlbmQgZmFpbGVkICgke1N0cmluZyhlcnIpfSlgKTtcbiAgICAgIHRoaXMuY2hhdE1hbmFnZXIuYWRkTWVzc2FnZShcbiAgICAgICAgQ2hhdE1hbmFnZXIuY3JlYXRlU3lzdGVtTWVzc2FnZShgXHUyNkEwIFNlbmQgZmFpbGVkOiAke2Vycn1gLCAnZXJyb3InKVxuICAgICAgKTtcbiAgICB9XG4gIH1cbn1cbiIsICJpbXBvcnQgdHlwZSB7IEFwcCB9IGZyb20gJ29ic2lkaWFuJztcblxuZXhwb3J0IGludGVyZmFjZSBOb3RlQ29udGV4dCB7XG4gIHRpdGxlOiBzdHJpbmc7XG4gIHBhdGg6IHN0cmluZztcbiAgY29udGVudDogc3RyaW5nO1xufVxuXG4vKipcbiAqIFJldHVybnMgdGhlIGFjdGl2ZSBub3RlJ3MgdGl0bGUgYW5kIGNvbnRlbnQsIG9yIG51bGwgaWYgbm8gbm90ZSBpcyBvcGVuLlxuICogQXN5bmMgYmVjYXVzZSB2YXVsdC5yZWFkKCkgaXMgYXN5bmMuXG4gKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBnZXRBY3RpdmVOb3RlQ29udGV4dChhcHA6IEFwcCk6IFByb21pc2U8Tm90ZUNvbnRleHQgfCBudWxsPiB7XG4gIGNvbnN0IGZpbGUgPSBhcHAud29ya3NwYWNlLmdldEFjdGl2ZUZpbGUoKTtcbiAgaWYgKCFmaWxlKSByZXR1cm4gbnVsbDtcblxuICB0cnkge1xuICAgIGNvbnN0IGNvbnRlbnQgPSBhd2FpdCBhcHAudmF1bHQucmVhZChmaWxlKTtcbiAgICByZXR1cm4ge1xuICAgICAgdGl0bGU6IGZpbGUuYmFzZW5hbWUsXG4gICAgICBwYXRoOiBmaWxlLnBhdGgsXG4gICAgICBjb250ZW50LFxuICAgIH07XG4gIH0gY2F0Y2ggKGVycikge1xuICAgIGNvbnNvbGUuZXJyb3IoJ1tvY2xhdy1jb250ZXh0XSBGYWlsZWQgdG8gcmVhZCBhY3RpdmUgbm90ZScsIGVycik7XG4gICAgcmV0dXJuIG51bGw7XG4gIH1cbn1cbiIsICIvKiogUGVyc2lzdGVkIHBsdWdpbiBjb25maWd1cmF0aW9uICovXG5leHBvcnQgaW50ZXJmYWNlIE9wZW5DbGF3U2V0dGluZ3Mge1xuICAvKiogV2ViU29ja2V0IFVSTCBvZiB0aGUgT3BlbkNsYXcgR2F0ZXdheSAoZS5nLiB3czovLzEwMC45MC45LjY4OjE4Nzg5KSAqL1xuICBnYXRld2F5VXJsOiBzdHJpbmc7XG4gIC8qKiBBdXRoIHRva2VuIFx1MjAxNCBtdXN0IG1hdGNoIHRoZSBjaGFubmVsIHBsdWdpbidzIGF1dGhUb2tlbiAqL1xuICBhdXRoVG9rZW46IHN0cmluZztcbiAgLyoqIE9wZW5DbGF3IHNlc3Npb24ga2V5IHRvIHN1YnNjcmliZSB0byAoZS5nLiBcIm1haW5cIikgKi9cbiAgc2Vzc2lvbktleTogc3RyaW5nO1xuICAvKiogKERlcHJlY2F0ZWQpIE9wZW5DbGF3IGFjY291bnQgSUQgKHVudXNlZDsgY2hhdC5zZW5kIHVzZXMgc2Vzc2lvbktleSkgKi9cbiAgYWNjb3VudElkOiBzdHJpbmc7XG4gIC8qKiBXaGV0aGVyIHRvIGluY2x1ZGUgdGhlIGFjdGl2ZSBub3RlIGNvbnRlbnQgd2l0aCBlYWNoIG1lc3NhZ2UgKi9cbiAgaW5jbHVkZUFjdGl2ZU5vdGU6IGJvb2xlYW47XG4gIC8qKiBSZW5kZXIgYXNzaXN0YW50IG91dHB1dCBhcyBNYXJrZG93biAodW5zYWZlOiBtYXkgdHJpZ2dlciBlbWJlZHMvcG9zdC1wcm9jZXNzb3JzKTsgZGVmYXVsdCBPRkYgKi9cbiAgcmVuZGVyQXNzaXN0YW50TWFya2Rvd246IGJvb2xlYW47XG59XG5cbmV4cG9ydCBjb25zdCBERUZBVUxUX1NFVFRJTkdTOiBPcGVuQ2xhd1NldHRpbmdzID0ge1xuICBnYXRld2F5VXJsOiAnd3M6Ly9sb2NhbGhvc3Q6MTg3ODknLFxuICBhdXRoVG9rZW46ICcnLFxuICBzZXNzaW9uS2V5OiAnbWFpbicsXG4gIGFjY291bnRJZDogJ21haW4nLFxuICBpbmNsdWRlQWN0aXZlTm90ZTogZmFsc2UsXG4gIHJlbmRlckFzc2lzdGFudE1hcmtkb3duOiBmYWxzZSxcbn07XG5cbi8qKiBBIHNpbmdsZSBjaGF0IG1lc3NhZ2UgKi9cbmV4cG9ydCBpbnRlcmZhY2UgQ2hhdE1lc3NhZ2Uge1xuICBpZDogc3RyaW5nO1xuICByb2xlOiAndXNlcicgfCAnYXNzaXN0YW50JyB8ICdzeXN0ZW0nO1xuICAvKiogT3B0aW9uYWwgc2V2ZXJpdHkgZm9yIHN5c3RlbS9zdGF0dXMgbWVzc2FnZXMgKi9cbiAgbGV2ZWw/OiAnaW5mbycgfCAnZXJyb3InO1xuICBjb250ZW50OiBzdHJpbmc7XG4gIHRpbWVzdGFtcDogbnVtYmVyO1xufVxuXG4vKiogUGF5bG9hZCBmb3IgbWVzc2FnZXMgU0VOVCB0byB0aGUgc2VydmVyIChvdXRib3VuZCkgKi9cbmV4cG9ydCBpbnRlcmZhY2UgV1NQYXlsb2FkIHtcbiAgdHlwZTogJ2F1dGgnIHwgJ21lc3NhZ2UnIHwgJ3BpbmcnIHwgJ3BvbmcnIHwgJ2Vycm9yJztcbiAgcGF5bG9hZD86IFJlY29yZDxzdHJpbmcsIHVua25vd24+O1xufVxuXG4vKiogTWVzc2FnZXMgUkVDRUlWRUQgZnJvbSB0aGUgc2VydmVyIChpbmJvdW5kKSBcdTIwMTQgZGlzY3JpbWluYXRlZCB1bmlvbiAqL1xuZXhwb3J0IHR5cGUgSW5ib3VuZFdTUGF5bG9hZCA9XG4gIHwgeyB0eXBlOiAnbWVzc2FnZSc7IHBheWxvYWQ6IHsgY29udGVudDogc3RyaW5nOyByb2xlOiBzdHJpbmc7IHRpbWVzdGFtcDogbnVtYmVyIH0gfVxuICB8IHsgdHlwZTogJ2Vycm9yJzsgcGF5bG9hZDogeyBtZXNzYWdlOiBzdHJpbmcgfSB9O1xuXG4vKiogQXZhaWxhYmxlIGFnZW50cyAvIG1vZGVscyAqL1xuZXhwb3J0IGludGVyZmFjZSBBZ2VudE9wdGlvbiB7XG4gIGlkOiBzdHJpbmc7XG4gIGxhYmVsOiBzdHJpbmc7XG59XG4iXSwKICAibWFwcGluZ3MiOiAiOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBLElBQUFBLG1CQUE4Qzs7O0FDQTlDLHNCQUErQztBQUd4QyxJQUFNLHFCQUFOLGNBQWlDLGlDQUFpQjtBQUFBLEVBR3ZELFlBQVksS0FBVSxRQUF3QjtBQUM1QyxVQUFNLEtBQUssTUFBTTtBQUNqQixTQUFLLFNBQVM7QUFBQSxFQUNoQjtBQUFBLEVBRUEsVUFBZ0I7QUFDZCxVQUFNLEVBQUUsWUFBWSxJQUFJO0FBQ3hCLGdCQUFZLE1BQU07QUFFbEIsZ0JBQVksU0FBUyxNQUFNLEVBQUUsTUFBTSxnQ0FBMkIsQ0FBQztBQUUvRCxRQUFJLHdCQUFRLFdBQVcsRUFDcEIsUUFBUSxhQUFhLEVBQ3JCLFFBQVEsbUVBQW1FLEVBQzNFO0FBQUEsTUFBUSxDQUFDLFNBQ1IsS0FDRyxlQUFlLHNCQUFzQixFQUNyQyxTQUFTLEtBQUssT0FBTyxTQUFTLFVBQVUsRUFDeEMsU0FBUyxDQUFPLFVBQVU7QUFDekIsYUFBSyxPQUFPLFNBQVMsYUFBYSxNQUFNLEtBQUs7QUFDN0MsY0FBTSxLQUFLLE9BQU8s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
