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
      const runId = this.activeRunId;
      try {
        yield this._sendRequest("chat.abort", runId ? { sessionKey: this.sessionKey, runId } : { sessionKey: this.sessionKey });
        return true;
      } catch (err) {
        console.error("[oclaw-ws] chat.abort failed", err);
        return false;
      } finally {
        this.activeRunId = null;
        this._setWorking(false);
      }
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
      var _a, _b, _c, _d;
      let frame;
      try {
        frame = JSON.parse(event.data);
      } catch (e) {
        console.error("[oclaw-ws] Failed to parse incoming message");
        return;
      }
      if (frame.type === "res") {
        const pending = this.pendingRequests.get(frame.id);
        if (pending) {
          this.pendingRequests.delete(frame.id);
          if (frame.ok)
            pending.resolve(frame.payload);
          else
            pending.reject(new Error(((_a = frame.error) == null ? void 0 : _a.message) || "Request failed"));
        }
        return;
      }
      if (frame.type === "event") {
        if (frame.event === "connect.challenge") {
          connectNonce = ((_b = frame.payload) == null ? void 0 : _b.nonce) || null;
          void tryConnect();
          return;
        }
        if (frame.event === "chat") {
          const payload = frame.payload;
          const incomingSessionKey = String((payload == null ? void 0 : payload.sessionKey) || "");
          if (!incomingSessionKey || !sessionKeyMatches(this.sessionKey, incomingSessionKey)) {
            return;
          }
          if ((payload == null ? void 0 : payload.state) && payload.state !== "final" && payload.state !== "aborted") {
            return;
          }
          const msg = payload == null ? void 0 : payload.message;
          const role = (_c = msg == null ? void 0 : msg.role) != null ? _c : "assistant";
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
          (_d = this.onMessage) == null ? void 0 : _d.call(this, {
            type: "message",
            payload: {
              content: text,
              role: "assistant",
              timestamp: Date.now()
            }
          });
        }
        return;
      }
      console.debug("[oclaw-ws] Unhandled frame", frame);
    };
    ws.onclose = () => {
      this._stopTimers();
      this._setWorking(false);
      this._setState("disconnected");
      for (const pending of this.pendingRequests.values()) {
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
  _sendRequest(method, params) {
    return new Promise((resolve, reject) => {
      if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
        reject(new Error("WebSocket not connected"));
        return;
      }
      const id = `req-${++this.requestId}`;
      this.pendingRequests.set(id, { resolve, reject });
      this.ws.send(
        JSON.stringify({
          type: "req",
          method,
          id,
          params
        })
      );
      setTimeout(() => {
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
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsic3JjL21haW4udHMiLCAic3JjL3NldHRpbmdzLnRzIiwgInNyYy93ZWJzb2NrZXQudHMiLCAic3JjL2NoYXQudHMiLCAic3JjL3ZpZXcudHMiLCAic3JjL2NvbnRleHQudHMiLCAic3JjL3R5cGVzLnRzIl0sCiAgInNvdXJjZXNDb250ZW50IjogWyJpbXBvcnQgeyBOb3RpY2UsIFBsdWdpbiwgV29ya3NwYWNlTGVhZiB9IGZyb20gJ29ic2lkaWFuJztcbmltcG9ydCB7IE9wZW5DbGF3U2V0dGluZ1RhYiB9IGZyb20gJy4vc2V0dGluZ3MnO1xuaW1wb3J0IHsgT2JzaWRpYW5XU0NsaWVudCB9IGZyb20gJy4vd2Vic29ja2V0JztcbmltcG9ydCB7IENoYXRNYW5hZ2VyIH0gZnJvbSAnLi9jaGF0JztcbmltcG9ydCB7IFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFULCBPcGVuQ2xhd0NoYXRWaWV3IH0gZnJvbSAnLi92aWV3JztcbmltcG9ydCB7IERFRkFVTFRfU0VUVElOR1MsIHR5cGUgT3BlbkNsYXdTZXR0aW5ncyB9IGZyb20gJy4vdHlwZXMnO1xuXG5leHBvcnQgZGVmYXVsdCBjbGFzcyBPcGVuQ2xhd1BsdWdpbiBleHRlbmRzIFBsdWdpbiB7XG4gIHNldHRpbmdzITogT3BlbkNsYXdTZXR0aW5ncztcbiAgd3NDbGllbnQhOiBPYnNpZGlhbldTQ2xpZW50O1xuICBjaGF0TWFuYWdlciE6IENoYXRNYW5hZ2VyO1xuXG4gIGFzeW5jIG9ubG9hZCgpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBhd2FpdCB0aGlzLmxvYWRTZXR0aW5ncygpO1xuXG4gICAgdGhpcy53c0NsaWVudCA9IG5ldyBPYnNpZGlhbldTQ2xpZW50KHRoaXMuc2V0dGluZ3Muc2Vzc2lvbktleSk7XG4gICAgdGhpcy5jaGF0TWFuYWdlciA9IG5ldyBDaGF0TWFuYWdlcigpO1xuXG4gICAgLy8gV2lyZSBpbmNvbWluZyBXUyBtZXNzYWdlcyBcdTIxOTIgQ2hhdE1hbmFnZXJcbiAgICB0aGlzLndzQ2xpZW50Lm9uTWVzc2FnZSA9IChtc2cpID0+IHtcbiAgICAgIGlmIChtc2cudHlwZSA9PT0gJ21lc3NhZ2UnKSB7XG4gICAgICAgIHRoaXMuY2hhdE1hbmFnZXIuYWRkTWVzc2FnZShDaGF0TWFuYWdlci5jcmVhdGVBc3Npc3RhbnRNZXNzYWdlKG1zZy5wYXlsb2FkLmNvbnRlbnQpKTtcbiAgICAgIH0gZWxzZSBpZiAobXNnLnR5cGUgPT09ICdlcnJvcicpIHtcbiAgICAgICAgY29uc3QgZXJyVGV4dCA9IG1zZy5wYXlsb2FkLm1lc3NhZ2UgPz8gJ1Vua25vd24gZXJyb3IgZnJvbSBnYXRld2F5JztcbiAgICAgICAgdGhpcy5jaGF0TWFuYWdlci5hZGRNZXNzYWdlKENoYXRNYW5hZ2VyLmNyZWF0ZVN5c3RlbU1lc3NhZ2UoYFx1MjZBMCAke2VyclRleHR9YCwgJ2Vycm9yJykpO1xuICAgICAgfVxuICAgIH07XG5cbiAgICAvLyBSZWdpc3RlciB0aGUgc2lkZWJhciB2aWV3XG4gICAgdGhpcy5yZWdpc3RlclZpZXcoXG4gICAgICBWSUVXX1RZUEVfT1BFTkNMQVdfQ0hBVCxcbiAgICAgIChsZWFmOiBXb3Jrc3BhY2VMZWFmKSA9PiBuZXcgT3BlbkNsYXdDaGF0VmlldyhsZWFmLCB0aGlzKVxuICAgICk7XG5cbiAgICAvLyBSaWJib24gaWNvbiBcdTIwMTQgb3BlbnMgLyByZXZlYWxzIHRoZSBjaGF0IHNpZGViYXJcbiAgICB0aGlzLmFkZFJpYmJvbkljb24oJ21lc3NhZ2Utc3F1YXJlJywgJ09wZW5DbGF3IENoYXQnLCAoKSA9PiB7XG4gICAgICB0aGlzLl9hY3RpdmF0ZUNoYXRWaWV3KCk7XG4gICAgfSk7XG5cbiAgICAvLyBTZXR0aW5ncyB0YWJcbiAgICB0aGlzLmFkZFNldHRpbmdUYWIobmV3IE9wZW5DbGF3U2V0dGluZ1RhYih0aGlzLmFwcCwgdGhpcykpO1xuXG4gICAgLy8gQ29tbWFuZCBwYWxldHRlIGVudHJ5XG4gICAgdGhpcy5hZGRDb21tYW5kKHtcbiAgICAgIGlkOiAnb3Blbi1vcGVuY2xhdy1jaGF0JyxcbiAgICAgIG5hbWU6ICdPcGVuIGNoYXQgc2lkZWJhcicsXG4gICAgICBjYWxsYmFjazogKCkgPT4gdGhpcy5fYWN0aXZhdGVDaGF0VmlldygpLFxuICAgIH0pO1xuXG4gICAgLy8gQ29ubmVjdCB0byBnYXRld2F5IGlmIHRva2VuIGlzIGNvbmZpZ3VyZWRcbiAgICBpZiAodGhpcy5zZXR0aW5ncy5hdXRoVG9rZW4pIHtcbiAgICAgIHRoaXMuX2Nvbm5lY3RXUygpO1xuICAgIH0gZWxzZSB7XG4gICAgICBuZXcgTm90aWNlKCdPcGVuQ2xhdyBDaGF0OiBwbGVhc2UgY29uZmlndXJlIHlvdXIgZ2F0ZXdheSB0b2tlbiBpbiBTZXR0aW5ncy4nKTtcbiAgICB9XG5cbiAgICBjb25zb2xlLmxvZygnW29jbGF3XSBQbHVnaW4gbG9hZGVkJyk7XG4gIH1cblxuICBhc3luYyBvbnVubG9hZCgpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICB0aGlzLndzQ2xpZW50LmRpc2Nvbm5lY3QoKTtcbiAgICB0aGlzLmFwcC53b3Jrc3BhY2UuZGV0YWNoTGVhdmVzT2ZUeXBlKFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFUKTtcbiAgICBjb25zb2xlLmxvZygnW29jbGF3XSBQbHVnaW4gdW5sb2FkZWQnKTtcbiAgfVxuXG4gIGFzeW5jIGxvYWRTZXR0aW5ncygpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICB0aGlzLnNldHRpbmdzID0gT2JqZWN0LmFzc2lnbih7fSwgREVGQVVMVF9TRVRUSU5HUywgYXdhaXQgdGhpcy5sb2FkRGF0YSgpKTtcbiAgfVxuXG4gIGFzeW5jIHNhdmVTZXR0aW5ncygpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBhd2FpdCB0aGlzLnNhdmVEYXRhKHRoaXMuc2V0dGluZ3MpO1xuICB9XG5cbiAgLy8gXHUyNTAwXHUyNTAwIEhlbHBlcnMgXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG5cbiAgcHJpdmF0ZSBfY29ubmVjdFdTKCk6IHZvaWQge1xuICAgIHRoaXMud3NDbGllbnQuY29ubmVjdChcbiAgICAgIHRoaXMuc2V0dGluZ3MuZ2F0ZXdheVVybCxcbiAgICAgIHRoaXMuc2V0dGluZ3MuYXV0aFRva2VuXG4gICAgKTtcbiAgfVxuXG4gIHByaXZhdGUgYXN5bmMgX2FjdGl2YXRlQ2hhdFZpZXcoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgY29uc3QgeyB3b3Jrc3BhY2UgfSA9IHRoaXMuYXBwO1xuXG4gICAgLy8gUmV1c2UgZXhpc3RpbmcgbGVhZiBpZiBhbHJlYWR5IG9wZW5cbiAgICBjb25zdCBleGlzdGluZyA9IHdvcmtzcGFjZS5nZXRMZWF2ZXNPZlR5cGUoVklFV19UWVBFX09QRU5DTEFXX0NIQVQpO1xuICAgIGlmIChleGlzdGluZy5sZW5ndGggPiAwKSB7XG4gICAgICB3b3Jrc3BhY2UucmV2ZWFsTGVhZihleGlzdGluZ1swXSk7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgLy8gT3BlbiBpbiByaWdodCBzaWRlYmFyXG4gICAgY29uc3QgbGVhZiA9IHdvcmtzcGFjZS5nZXRSaWdodExlYWYoZmFsc2UpO1xuICAgIGlmICghbGVhZikgcmV0dXJuO1xuICAgIGF3YWl0IGxlYWYuc2V0Vmlld1N0YXRlKHsgdHlwZTogVklFV19UWVBFX09QRU5DTEFXX0NIQVQsIGFjdGl2ZTogdHJ1ZSB9KTtcbiAgICB3b3Jrc3BhY2UucmV2ZWFsTGVhZihsZWFmKTtcbiAgfVxufVxuIiwgImltcG9ydCB7IEFwcCwgUGx1Z2luU2V0dGluZ1RhYiwgU2V0dGluZyB9IGZyb20gJ29ic2lkaWFuJztcbmltcG9ydCB0eXBlIE9wZW5DbGF3UGx1Z2luIGZyb20gJy4vbWFpbic7XG5cbmV4cG9ydCBjbGFzcyBPcGVuQ2xhd1NldHRpbmdUYWIgZXh0ZW5kcyBQbHVnaW5TZXR0aW5nVGFiIHtcbiAgcGx1Z2luOiBPcGVuQ2xhd1BsdWdpbjtcblxuICBjb25zdHJ1Y3RvcihhcHA6IEFwcCwgcGx1Z2luOiBPcGVuQ2xhd1BsdWdpbikge1xuICAgIHN1cGVyKGFwcCwgcGx1Z2luKTtcbiAgICB0aGlzLnBsdWdpbiA9IHBsdWdpbjtcbiAgfVxuXG4gIGRpc3BsYXkoKTogdm9pZCB7XG4gICAgY29uc3QgeyBjb250YWluZXJFbCB9ID0gdGhpcztcbiAgICBjb250YWluZXJFbC5lbXB0eSgpO1xuXG4gICAgY29udGFpbmVyRWwuY3JlYXRlRWwoJ2gyJywgeyB0ZXh0OiAnT3BlbkNsYXcgQ2hhdCBcdTIwMTMgU2V0dGluZ3MnIH0pO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZSgnR2F0ZXdheSBVUkwnKVxuICAgICAgLnNldERlc2MoJ1dlYlNvY2tldCBVUkwgb2YgdGhlIE9wZW5DbGF3IEdhdGV3YXkgKGUuZy4gd3M6Ly9ob3N0bmFtZToxODc4OSkuJylcbiAgICAgIC5hZGRUZXh0KCh0ZXh0KSA9PlxuICAgICAgICB0ZXh0XG4gICAgICAgICAgLnNldFBsYWNlaG9sZGVyKCd3czovL2xvY2FsaG9zdDoxODc4OScpXG4gICAgICAgICAgLnNldFZhbHVlKHRoaXMucGx1Z2luLnNldHRpbmdzLmdhdGV3YXlVcmwpXG4gICAgICAgICAgLm9uQ2hhbmdlKGFzeW5jICh2YWx1ZSkgPT4ge1xuICAgICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3MuZ2F0ZXdheVVybCA9IHZhbHVlLnRyaW0oKTtcbiAgICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICAgIH0pXG4gICAgICApO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZSgnQXV0aCB0b2tlbicpXG4gICAgICAuc2V0RGVzYygnTXVzdCBtYXRjaCB0aGUgYXV0aFRva2VuIGluIHlvdXIgb3BlbmNsYXcuanNvbiBjaGFubmVsIGNvbmZpZy4gTmV2ZXIgc2hhcmVkLicpXG4gICAgICAuYWRkVGV4dCgodGV4dCkgPT4ge1xuICAgICAgICB0ZXh0XG4gICAgICAgICAgLnNldFBsYWNlaG9sZGVyKCdFbnRlciB0b2tlblx1MjAyNicpXG4gICAgICAgICAgLnNldFZhbHVlKHRoaXMucGx1Z2luLnNldHRpbmdzLmF1dGhUb2tlbilcbiAgICAgICAgICAub25DaGFuZ2UoYXN5bmMgKHZhbHVlKSA9PiB7XG4gICAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5hdXRoVG9rZW4gPSB2YWx1ZTtcbiAgICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICAgIH0pO1xuICAgICAgICAvLyBUcmVhdCBhcyBwYXNzd29yZCBmaWVsZCBcdTIwMTMgZG8gbm90IHJldmVhbCB0b2tlbiBpbiBVSVxuICAgICAgICB0ZXh0LmlucHV0RWwudHlwZSA9ICdwYXNzd29yZCc7XG4gICAgICAgIHRleHQuaW5wdXRFbC5hdXRvY29tcGxldGUgPSAnb2ZmJztcbiAgICAgIH0pO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZSgnU2Vzc2lvbiBLZXknKVxuICAgICAgLnNldERlc2MoJ09wZW5DbGF3IHNlc3Npb24gdG8gc3Vic2NyaWJlIHRvICh1c3VhbGx5IFwibWFpblwiKS4nKVxuICAgICAgLmFkZFRleHQoKHRleHQpID0+XG4gICAgICAgIHRleHRcbiAgICAgICAgICAuc2V0UGxhY2Vob2xkZXIoJ21haW4nKVxuICAgICAgICAgIC5zZXRWYWx1ZSh0aGlzLnBsdWdpbi5zZXR0aW5ncy5zZXNzaW9uS2V5KVxuICAgICAgICAgIC5vbkNoYW5nZShhc3luYyAodmFsdWUpID0+IHtcbiAgICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLnNlc3Npb25LZXkgPSB2YWx1ZS50cmltKCkgfHwgJ21haW4nO1xuICAgICAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uc2F2ZVNldHRpbmdzKCk7XG4gICAgICAgICAgfSlcbiAgICAgICk7XG5cbiAgICBuZXcgU2V0dGluZyhjb250YWluZXJFbClcbiAgICAgIC5zZXROYW1lKCdBY2NvdW50IElEJylcbiAgICAgIC5zZXREZXNjKCdPcGVuQ2xhdyBhY2NvdW50IElEICh1c3VhbGx5IFwibWFpblwiKS4nKVxuICAgICAgLmFkZFRleHQoKHRleHQpID0+XG4gICAgICAgIHRleHRcbiAgICAgICAgICAuc2V0UGxhY2Vob2xkZXIoJ21haW4nKVxuICAgICAgICAgIC5zZXRWYWx1ZSh0aGlzLnBsdWdpbi5zZXR0aW5ncy5hY2NvdW50SWQpXG4gICAgICAgICAgLm9uQ2hhbmdlKGFzeW5jICh2YWx1ZSkgPT4ge1xuICAgICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3MuYWNjb3VudElkID0gdmFsdWUudHJpbSgpIHx8ICdtYWluJztcbiAgICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICAgIH0pXG4gICAgICApO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZSgnSW5jbHVkZSBhY3RpdmUgbm90ZSBieSBkZWZhdWx0JylcbiAgICAgIC5zZXREZXNjKCdQcmUtY2hlY2sgXCJJbmNsdWRlIGFjdGl2ZSBub3RlXCIgaW4gdGhlIGNoYXQgcGFuZWwgd2hlbiBpdCBvcGVucy4nKVxuICAgICAgLmFkZFRvZ2dsZSgodG9nZ2xlKSA9PlxuICAgICAgICB0b2dnbGUuc2V0VmFsdWUodGhpcy5wbHVnaW4uc2V0dGluZ3MuaW5jbHVkZUFjdGl2ZU5vdGUpLm9uQ2hhbmdlKGFzeW5jICh2YWx1ZSkgPT4ge1xuICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLmluY2x1ZGVBY3RpdmVOb3RlID0gdmFsdWU7XG4gICAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uc2F2ZVNldHRpbmdzKCk7XG4gICAgICAgIH0pXG4gICAgICApO1xuXG4gICAgY29udGFpbmVyRWwuY3JlYXRlRWwoJ3AnLCB7XG4gICAgICB0ZXh0OiAnUmVjb25uZWN0OiBjbG9zZSBhbmQgcmVvcGVuIHRoZSBzaWRlYmFyIGFmdGVyIGNoYW5naW5nIHRoZSBnYXRld2F5IFVSTCBvciB0b2tlbi4nLFxuICAgICAgY2xzOiAnc2V0dGluZy1pdGVtLWRlc2NyaXB0aW9uJyxcbiAgICB9KTtcbiAgfVxufVxuIiwgIi8qKlxuICogV2ViU29ja2V0IGNsaWVudCBmb3IgT3BlbkNsYXcgR2F0ZXdheVxuICpcbiAqIFBpdm90ICgyMDI2LTAyLTI1KTogRG8gTk9UIHVzZSBjdXN0b20gb2JzaWRpYW4uKiBnYXRld2F5IG1ldGhvZHMuXG4gKiBUaG9zZSByZXF1aXJlIG9wZXJhdG9yLmFkbWluIHNjb3BlIHdoaWNoIGlzIG5vdCBncmFudGVkIHRvIGV4dGVybmFsIGNsaWVudHMuXG4gKlxuICogQXV0aCBub3RlOlxuICogLSBjaGF0LnNlbmQgcmVxdWlyZXMgb3BlcmF0b3Iud3JpdGVcbiAqIC0gZXh0ZXJuYWwgY2xpZW50cyBtdXN0IHByZXNlbnQgYSBwYWlyZWQgZGV2aWNlIGlkZW50aXR5IHRvIHJlY2VpdmUgd3JpdGUgc2NvcGVzXG4gKlxuICogV2UgdXNlIGJ1aWx0LWluIGdhdGV3YXkgbWV0aG9kcy9ldmVudHM6XG4gKiAtIFNlbmQ6IGNoYXQuc2VuZCh7IHNlc3Npb25LZXksIG1lc3NhZ2UsIGlkZW1wb3RlbmN5S2V5LCAuLi4gfSlcbiAqIC0gUmVjZWl2ZTogZXZlbnQgXCJjaGF0XCIgKGZpbHRlciBieSBzZXNzaW9uS2V5KVxuICovXG5cbmltcG9ydCB0eXBlIHsgSW5ib3VuZFdTUGF5bG9hZCB9IGZyb20gJy4vdHlwZXMnO1xuXG4vKiogTWlsbGlzZWNvbmRzIGJlZm9yZSBhIHJlY29ubmVjdCBhdHRlbXB0IGFmdGVyIGFuIHVuZXhwZWN0ZWQgY2xvc2UgKi9cbmNvbnN0IFJFQ09OTkVDVF9ERUxBWV9NUyA9IDNfMDAwO1xuLyoqIEludGVydmFsIGZvciBzZW5kaW5nIGhlYXJ0YmVhdCBwaW5ncyAoY2hlY2sgY29ubmVjdGlvbiBsaXZlbmVzcykgKi9cbmNvbnN0IEhFQVJUQkVBVF9JTlRFUlZBTF9NUyA9IDMwXzAwMDtcblxuLyoqIFNhZmV0eSB2YWx2ZTogaGlkZSB3b3JraW5nIHNwaW5uZXIgaWYgbm8gYXNzaXN0YW50IHJlcGx5IGFycml2ZXMgaW4gdGltZSAqL1xuY29uc3QgV09SS0lOR19NQVhfTVMgPSAxMjBfMDAwO1xuXG5leHBvcnQgdHlwZSBXU0NsaWVudFN0YXRlID0gJ2Rpc2Nvbm5lY3RlZCcgfCAnY29ubmVjdGluZycgfCAnaGFuZHNoYWtpbmcnIHwgJ2Nvbm5lY3RlZCc7XG5cbmV4cG9ydCB0eXBlIFdvcmtpbmdTdGF0ZUxpc3RlbmVyID0gKHdvcmtpbmc6IGJvb2xlYW4pID0+IHZvaWQ7XG5cbmludGVyZmFjZSBQZW5kaW5nUmVxdWVzdCB7XG4gIHJlc29sdmU6IChwYXlsb2FkOiBhbnkpID0+IHZvaWQ7XG4gIHJlamVjdDogKGVycm9yOiBhbnkpID0+IHZvaWQ7XG59XG5cbnR5cGUgRGV2aWNlSWRlbnRpdHkgPSB7XG4gIGlkOiBzdHJpbmc7XG4gIHB1YmxpY0tleTogc3RyaW5nOyAvLyBiYXNlNjRcbiAgcHJpdmF0ZUtleUp3azogSnNvbldlYktleTtcbn07XG5cbmNvbnN0IERFVklDRV9TVE9SQUdFX0tFWSA9ICdvcGVuY2xhd0NoYXQuZGV2aWNlSWRlbnRpdHkudjEnO1xuXG5mdW5jdGlvbiBiYXNlNjRVcmxFbmNvZGUoYnl0ZXM6IEFycmF5QnVmZmVyKTogc3RyaW5nIHtcbiAgY29uc3QgdTggPSBuZXcgVWludDhBcnJheShieXRlcyk7XG4gIGxldCBzID0gJyc7XG4gIGZvciAobGV0IGkgPSAwOyBpIDwgdTgubGVuZ3RoOyBpKyspIHMgKz0gU3RyaW5nLmZyb21DaGFyQ29kZSh1OFtpXSk7XG4gIGNvbnN0IGI2NCA9IGJ0b2Eocyk7XG4gIHJldHVybiBiNjQucmVwbGFjZSgvXFwrL2csICctJykucmVwbGFjZSgvXFwvL2csICdfJykucmVwbGFjZSgvPSskL2csICcnKTtcbn1cblxuZnVuY3Rpb24gaGV4RW5jb2RlKGJ5dGVzOiBBcnJheUJ1ZmZlcik6IHN0cmluZyB7XG4gIGNvbnN0IHU4ID0gbmV3IFVpbnQ4QXJyYXkoYnl0ZXMpO1xuICByZXR1cm4gQXJyYXkuZnJvbSh1OClcbiAgICAubWFwKChiKSA9PiBiLnRvU3RyaW5nKDE2KS5wYWRTdGFydCgyLCAnMCcpKVxuICAgIC5qb2luKCcnKTtcbn1cblxuZnVuY3Rpb24gdXRmOEJ5dGVzKHRleHQ6IHN0cmluZyk6IFVpbnQ4QXJyYXkge1xuICByZXR1cm4gbmV3IFRleHRFbmNvZGVyKCkuZW5jb2RlKHRleHQpO1xufVxuXG5hc3luYyBmdW5jdGlvbiBzaGEyNTZIZXgoYnl0ZXM6IEFycmF5QnVmZmVyKTogUHJvbWlzZTxzdHJpbmc+IHtcbiAgY29uc3QgZGlnZXN0ID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5kaWdlc3QoJ1NIQS0yNTYnLCBieXRlcyk7XG4gIHJldHVybiBoZXhFbmNvZGUoZGlnZXN0KTtcbn1cblxuYXN5bmMgZnVuY3Rpb24gbG9hZE9yQ3JlYXRlRGV2aWNlSWRlbnRpdHkoKTogUHJvbWlzZTxEZXZpY2VJZGVudGl0eT4ge1xuICBjb25zdCBleGlzdGluZyA9IGxvY2FsU3RvcmFnZS5nZXRJdGVtKERFVklDRV9TVE9SQUdFX0tFWSk7XG4gIGlmIChleGlzdGluZykge1xuICAgIGNvbnN0IHBhcnNlZCA9IEpTT04ucGFyc2UoZXhpc3RpbmcpIGFzIERldmljZUlkZW50aXR5O1xuICAgIGlmIChwYXJzZWQ/LmlkICYmIHBhcnNlZD8ucHVibGljS2V5ICYmIHBhcnNlZD8ucHJpdmF0ZUtleUp3aykgcmV0dXJuIHBhcnNlZDtcbiAgfVxuXG4gIGNvbnN0IGtleVBhaXIgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmdlbmVyYXRlS2V5KHsgbmFtZTogJ0VkMjU1MTknIH0sIHRydWUsIFsnc2lnbicsICd2ZXJpZnknXSk7XG4gIGNvbnN0IHB1YlJhdyA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuZXhwb3J0S2V5KCdyYXcnLCBrZXlQYWlyLnB1YmxpY0tleSk7XG4gIGNvbnN0IHByaXZKd2sgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmV4cG9ydEtleSgnandrJywga2V5UGFpci5wcml2YXRlS2V5KTtcblxuICAvLyBJTVBPUlRBTlQ6IGRldmljZS5pZCBtdXN0IGJlIGEgc3RhYmxlIGZpbmdlcnByaW50IGZvciB0aGUgcHVibGljIGtleS5cbiAgLy8gVGhlIGdhdGV3YXkgZW5mb3JjZXMgZGV2aWNlSWQgXHUyMTk0IHB1YmxpY0tleSBiaW5kaW5nOyByYW5kb20gaWRzIGNhbiBjYXVzZSBcImRldmljZSBpZGVudGl0eSBtaXNtYXRjaFwiLlxuICBjb25zdCBkZXZpY2VJZCA9IGF3YWl0IHNoYTI1NkhleChwdWJSYXcpO1xuICBjb25zdCBpZCA9IGRldmljZUlkO1xuXG4gIGNvbnN0IGlkZW50aXR5OiBEZXZpY2VJZGVudGl0eSA9IHtcbiAgICBpZCxcbiAgICBwdWJsaWNLZXk6IGJhc2U2NFVybEVuY29kZShwdWJSYXcpLFxuICAgIHByaXZhdGVLZXlKd2s6IHByaXZKd2ssXG4gIH07XG5cbiAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oREVWSUNFX1NUT1JBR0VfS0VZLCBKU09OLnN0cmluZ2lmeShpZGVudGl0eSkpO1xuICByZXR1cm4gaWRlbnRpdHk7XG59XG5cbmZ1bmN0aW9uIGJ1aWxkRGV2aWNlQXV0aFBheWxvYWQocGFyYW1zOiB7XG4gIGRldmljZUlkOiBzdHJpbmc7XG4gIGNsaWVudElkOiBzdHJpbmc7XG4gIGNsaWVudE1vZGU6IHN0cmluZztcbiAgcm9sZTogc3RyaW5nO1xuICBzY29wZXM6IHN0cmluZ1tdO1xuICBzaWduZWRBdE1zOiBudW1iZXI7XG4gIHRva2VuOiBzdHJpbmc7XG4gIG5vbmNlPzogc3RyaW5nO1xufSk6IHN0cmluZyB7XG4gIGNvbnN0IHZlcnNpb24gPSBwYXJhbXMubm9uY2UgPyAndjInIDogJ3YxJztcbiAgY29uc3Qgc2NvcGVzID0gcGFyYW1zLnNjb3Blcy5qb2luKCcsJyk7XG4gIGNvbnN0IGJhc2UgPSBbXG4gICAgdmVyc2lvbixcbiAgICBwYXJhbXMuZGV2aWNlSWQsXG4gICAgcGFyYW1zLmNsaWVudElkLFxuICAgIHBhcmFtcy5jbGllbnRNb2RlLFxuICAgIHBhcmFtcy5yb2xlLFxuICAgIHNjb3BlcyxcbiAgICBTdHJpbmcocGFyYW1zLnNpZ25lZEF0TXMpLFxuICAgIHBhcmFtcy50b2tlbiB8fCAnJyxcbiAgXTtcbiAgaWYgKHZlcnNpb24gPT09ICd2MicpIGJhc2UucHVzaChwYXJhbXMubm9uY2UgfHwgJycpO1xuICByZXR1cm4gYmFzZS5qb2luKCd8Jyk7XG59XG5cbmFzeW5jIGZ1bmN0aW9uIHNpZ25EZXZpY2VQYXlsb2FkKGlkZW50aXR5OiBEZXZpY2VJZGVudGl0eSwgcGF5bG9hZDogc3RyaW5nKTogUHJvbWlzZTx7IHNpZ25hdHVyZTogc3RyaW5nOyBzaWduZWRBdDogbnVtYmVyIH0+IHtcbiAgY29uc3QgcHJpdmF0ZUtleSA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KFxuICAgICdqd2snLFxuICAgIGlkZW50aXR5LnByaXZhdGVLZXlKd2ssXG4gICAgeyBuYW1lOiAnRWQyNTUxOScgfSxcbiAgICBmYWxzZSxcbiAgICBbJ3NpZ24nXSxcbiAgKTtcblxuICBjb25zdCBzaWduZWRBdCA9IERhdGUubm93KCk7XG4gIGNvbnN0IHNpZyA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuc2lnbih7IG5hbWU6ICdFZDI1NTE5JyB9LCBwcml2YXRlS2V5LCB1dGY4Qnl0ZXMocGF5bG9hZCkgYXMgdW5rbm93biBhcyBCdWZmZXJTb3VyY2UpO1xuICByZXR1cm4geyBzaWduYXR1cmU6IGJhc2U2NFVybEVuY29kZShzaWcpLCBzaWduZWRBdCB9O1xufVxuXG5mdW5jdGlvbiBleHRyYWN0VGV4dEZyb21HYXRld2F5TWVzc2FnZShtc2c6IGFueSk6IHN0cmluZyB7XG4gIGlmICghbXNnKSByZXR1cm4gJyc7XG5cbiAgLy8gTW9zdCBjb21tb246IHsgcm9sZSwgY29udGVudCB9IHdoZXJlIGNvbnRlbnQgY2FuIGJlIHN0cmluZyBvciBbe3R5cGU6J3RleHQnLHRleHQ6Jy4uLid9XVxuICBjb25zdCBjb250ZW50ID0gbXNnLmNvbnRlbnQgPz8gbXNnLm1lc3NhZ2UgPz8gbXNnO1xuICBpZiAodHlwZW9mIGNvbnRlbnQgPT09ICdzdHJpbmcnKSByZXR1cm4gY29udGVudDtcblxuICBpZiAoQXJyYXkuaXNBcnJheShjb250ZW50KSkge1xuICAgIGNvbnN0IHBhcnRzID0gY29udGVudFxuICAgICAgLmZpbHRlcigoYykgPT4gYyAmJiB0eXBlb2YgYyA9PT0gJ29iamVjdCcgJiYgYy50eXBlID09PSAndGV4dCcgJiYgdHlwZW9mIGMudGV4dCA9PT0gJ3N0cmluZycpXG4gICAgICAubWFwKChjKSA9PiBjLnRleHQpO1xuICAgIHJldHVybiBwYXJ0cy5qb2luKCdcXG4nKTtcbiAgfVxuXG4gIC8vIEZhbGxiYWNrXG4gIHRyeSB7XG4gICAgcmV0dXJuIEpTT04uc3RyaW5naWZ5KGNvbnRlbnQpO1xuICB9IGNhdGNoIHtcbiAgICByZXR1cm4gU3RyaW5nKGNvbnRlbnQpO1xuICB9XG59XG5cbmZ1bmN0aW9uIHNlc3Npb25LZXlNYXRjaGVzKGNvbmZpZ3VyZWQ6IHN0cmluZywgaW5jb21pbmc6IHN0cmluZyk6IGJvb2xlYW4ge1xuICBpZiAoaW5jb21pbmcgPT09IGNvbmZpZ3VyZWQpIHJldHVybiB0cnVlO1xuICAvLyBPcGVuQ2xhdyByZXNvbHZlcyBcIm1haW5cIiB0byBjYW5vbmljYWwgc2Vzc2lvbiBrZXkgbGlrZSBcImFnZW50Om1haW46bWFpblwiLlxuICBpZiAoY29uZmlndXJlZCA9PT0gJ21haW4nICYmIGluY29taW5nID09PSAnYWdlbnQ6bWFpbjptYWluJykgcmV0dXJuIHRydWU7XG4gIHJldHVybiBmYWxzZTtcbn1cblxuZXhwb3J0IGNsYXNzIE9ic2lkaWFuV1NDbGllbnQge1xuICBwcml2YXRlIHdzOiBXZWJTb2NrZXQgfCBudWxsID0gbnVsbDtcbiAgcHJpdmF0ZSByZWNvbm5lY3RUaW1lcjogUmV0dXJuVHlwZTx0eXBlb2Ygc2V0VGltZW91dD4gfCBudWxsID0gbnVsbDtcbiAgcHJpdmF0ZSBoZWFydGJlYXRUaW1lcjogUmV0dXJuVHlwZTx0eXBlb2Ygc2V0SW50ZXJ2YWw+IHwgbnVsbCA9IG51bGw7XG4gIHByaXZhdGUgd29ya2luZ1RpbWVyOiBSZXR1cm5UeXBlPHR5cGVvZiBzZXRUaW1lb3V0PiB8IG51bGwgPSBudWxsO1xuICBwcml2YXRlIGludGVudGlvbmFsQ2xvc2UgPSBmYWxzZTtcbiAgcHJpdmF0ZSBzZXNzaW9uS2V5OiBzdHJpbmc7XG4gIHByaXZhdGUgdXJsID0gJyc7XG4gIHByaXZhdGUgdG9rZW4gPSAnJztcbiAgcHJpdmF0ZSByZXF1ZXN0SWQgPSAwO1xuICBwcml2YXRlIHBlbmRpbmdSZXF1ZXN0cyA9IG5ldyBNYXA8c3RyaW5nLCBQZW5kaW5nUmVxdWVzdD4oKTtcbiAgcHJpdmF0ZSB3b3JraW5nID0gZmFsc2U7XG5cbiAgLyoqIFRoZSBsYXN0IGluLWZsaWdodCBjaGF0IHJ1biBpZC4gSW4gT3BlbkNsYXcgV2ViQ2hhdCB0aGlzIG1hcHMgdG8gY2hhdC5zZW5kIGlkZW1wb3RlbmN5S2V5LiAqL1xuICBwcml2YXRlIGFjdGl2ZVJ1bklkOiBzdHJpbmcgfCBudWxsID0gbnVsbDtcblxuICBzdGF0ZTogV1NDbGllbnRTdGF0ZSA9ICdkaXNjb25uZWN0ZWQnO1xuXG4gIG9uTWVzc2FnZTogKChtc2c6IEluYm91bmRXU1BheWxvYWQpID0+IHZvaWQpIHwgbnVsbCA9IG51bGw7XG4gIG9uU3RhdGVDaGFuZ2U6ICgoc3RhdGU6IFdTQ2xpZW50U3RhdGUpID0+IHZvaWQpIHwgbnVsbCA9IG51bGw7XG4gIG9uV29ya2luZ0NoYW5nZTogV29ya2luZ1N0YXRlTGlzdGVuZXIgfCBudWxsID0gbnVsbDtcblxuICBjb25zdHJ1Y3RvcihzZXNzaW9uS2V5OiBzdHJpbmcpIHtcbiAgICB0aGlzLnNlc3Npb25LZXkgPSBzZXNzaW9uS2V5O1xuICB9XG5cbiAgY29ubmVjdCh1cmw6IHN0cmluZywgdG9rZW46IHN0cmluZyk6IHZvaWQge1xuICAgIHRoaXMudXJsID0gdXJsO1xuICAgIHRoaXMudG9rZW4gPSB0b2tlbjtcbiAgICB0aGlzLmludGVudGlvbmFsQ2xvc2UgPSBmYWxzZTtcbiAgICB0aGlzLl9jb25uZWN0KCk7XG4gIH1cblxuICBkaXNjb25uZWN0KCk6IHZvaWQge1xuICAgIHRoaXMuaW50ZW50aW9uYWxDbG9zZSA9IHRydWU7XG4gICAgdGhpcy5fc3RvcFRpbWVycygpO1xuICAgIHRoaXMuYWN0aXZlUnVuSWQgPSBudWxsO1xuICAgIHRoaXMuX3NldFdvcmtpbmcoZmFsc2UpO1xuICAgIGlmICh0aGlzLndzKSB7XG4gICAgICB0aGlzLndzLmNsb3NlKCk7XG4gICAgICB0aGlzLndzID0gbnVsbDtcbiAgICB9XG4gICAgdGhpcy5fc2V0U3RhdGUoJ2Rpc2Nvbm5lY3RlZCcpO1xuICB9XG5cbiAgYXN5bmMgc2VuZE1lc3NhZ2UobWVzc2FnZTogc3RyaW5nKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgaWYgKHRoaXMuc3RhdGUgIT09ICdjb25uZWN0ZWQnKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ05vdCBjb25uZWN0ZWQgXHUyMDE0IGNhbGwgY29ubmVjdCgpIGZpcnN0Jyk7XG4gICAgfVxuXG4gICAgY29uc3QgcnVuSWQgPSBgb2JzaWRpYW4tJHtEYXRlLm5vdygpfS0ke01hdGgucmFuZG9tKCkudG9TdHJpbmcoMzYpLnNsaWNlKDIsIDkpfWA7XG5cbiAgICAvLyBTaG93IFx1MjAxQ3dvcmtpbmdcdTIwMUQgT05MWSBhZnRlciB0aGUgZ2F0ZXdheSBhY2tub3dsZWRnZXMgdGhlIHJlcXVlc3QuXG4gICAgYXdhaXQgdGhpcy5fc2VuZFJlcXVlc3QoJ2NoYXQuc2VuZCcsIHtcbiAgICAgIHNlc3Npb25LZXk6IHRoaXMuc2Vzc2lvbktleSxcbiAgICAgIG1lc3NhZ2UsXG4gICAgICBpZGVtcG90ZW5jeUtleTogcnVuSWQsXG4gICAgICAvLyBkZWxpdmVyIGRlZmF1bHRzIHRvIHRydWUgaW4gZ2F0ZXdheTsga2VlcCBkZWZhdWx0XG4gICAgfSk7XG5cbiAgICB0aGlzLmFjdGl2ZVJ1bklkID0gcnVuSWQ7XG4gICAgdGhpcy5fc2V0V29ya2luZyh0cnVlKTtcbiAgICB0aGlzLl9hcm1Xb3JraW5nU2FmZXR5VGltZW91dCgpO1xuICB9XG5cbiAgLyoqIEFib3J0IHRoZSBhY3RpdmUgcnVuIGZvciB0aGlzIHNlc3Npb24gKGFuZCBvdXIgbGFzdCBydW4gaWQgaWYgcHJlc2VudCkuICovXG4gIGFzeW5jIGFib3J0QWN0aXZlUnVuKCk6IFByb21pc2U8Ym9vbGVhbj4ge1xuICAgIGlmICh0aGlzLnN0YXRlICE9PSAnY29ubmVjdGVkJykge1xuICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH1cblxuICAgIGNvbnN0IHJ1bklkID0gdGhpcy5hY3RpdmVSdW5JZDtcblxuICAgIHRyeSB7XG4gICAgICBhd2FpdCB0aGlzLl9zZW5kUmVxdWVzdCgnY2hhdC5hYm9ydCcsIHJ1bklkID8geyBzZXNzaW9uS2V5OiB0aGlzLnNlc3Npb25LZXksIHJ1bklkIH0gOiB7IHNlc3Npb25LZXk6IHRoaXMuc2Vzc2lvbktleSB9KTtcbiAgICAgIHJldHVybiB0cnVlO1xuICAgIH0gY2F0Y2ggKGVycikge1xuICAgICAgY29uc29sZS5lcnJvcignW29jbGF3LXdzXSBjaGF0LmFib3J0IGZhaWxlZCcsIGVycik7XG4gICAgICByZXR1cm4gZmFsc2U7XG4gICAgfSBmaW5hbGx5IHtcbiAgICAgIC8vIEFsd2F5cyByZXN0b3JlIFVJIHN0YXRlIGltbWVkaWF0ZWx5OyB0aGUgZ2F0ZXdheSBtYXkgc3RpbGwgZW1pdCBhbiBhYm9ydGVkIGV2ZW50IGxhdGVyLlxuICAgICAgdGhpcy5hY3RpdmVSdW5JZCA9IG51bGw7XG4gICAgICB0aGlzLl9zZXRXb3JraW5nKGZhbHNlKTtcbiAgICB9XG4gIH1cblxuICBwcml2YXRlIF9jb25uZWN0KCk6IHZvaWQge1xuICAgIGlmICh0aGlzLndzKSB7XG4gICAgICB0aGlzLndzLm9ub3BlbiA9IG51bGw7XG4gICAgICB0aGlzLndzLm9uY2xvc2UgPSBudWxsO1xuICAgICAgdGhpcy53cy5vbm1lc3NhZ2UgPSBudWxsO1xuICAgICAgdGhpcy53cy5vbmVycm9yID0gbnVsbDtcbiAgICAgIHRoaXMud3MuY2xvc2UoKTtcbiAgICAgIHRoaXMud3MgPSBudWxsO1xuICAgIH1cblxuICAgIHRoaXMuX3NldFN0YXRlKCdjb25uZWN0aW5nJyk7XG5cbiAgICBjb25zdCB3cyA9IG5ldyBXZWJTb2NrZXQodGhpcy51cmwpO1xuICAgIHRoaXMud3MgPSB3cztcblxuICAgIGxldCBjb25uZWN0Tm9uY2U6IHN0cmluZyB8IG51bGwgPSBudWxsO1xuICAgIGxldCBjb25uZWN0U3RhcnRlZCA9IGZhbHNlO1xuXG4gICAgY29uc3QgdHJ5Q29ubmVjdCA9IGFzeW5jICgpID0+IHtcbiAgICAgIGlmIChjb25uZWN0U3RhcnRlZCkgcmV0dXJuO1xuICAgICAgaWYgKCFjb25uZWN0Tm9uY2UpIHJldHVybjtcbiAgICAgIGNvbm5lY3RTdGFydGVkID0gdHJ1ZTtcblxuICAgICAgdHJ5IHtcbiAgICAgICAgY29uc3QgaWRlbnRpdHkgPSBhd2FpdCBsb2FkT3JDcmVhdGVEZXZpY2VJZGVudGl0eSgpO1xuICAgICAgICBjb25zdCBzaWduZWRBdE1zID0gRGF0ZS5ub3coKTtcbiAgICAgICAgY29uc3QgcGF5bG9hZCA9IGJ1aWxkRGV2aWNlQXV0aFBheWxvYWQoe1xuICAgICAgICAgIGRldmljZUlkOiBpZGVudGl0eS5pZCxcbiAgICAgICAgICBjbGllbnRJZDogJ2dhdGV3YXktY2xpZW50JyxcbiAgICAgICAgICBjbGllbnRNb2RlOiAnYmFja2VuZCcsXG4gICAgICAgICAgcm9sZTogJ29wZXJhdG9yJyxcbiAgICAgICAgICBzY29wZXM6IFsnb3BlcmF0b3IucmVhZCcsICdvcGVyYXRvci53cml0ZSddLFxuICAgICAgICAgIHNpZ25lZEF0TXMsXG4gICAgICAgICAgdG9rZW46IHRoaXMudG9rZW4sXG4gICAgICAgICAgbm9uY2U6IGNvbm5lY3ROb25jZSxcbiAgICAgICAgfSk7XG4gICAgICAgIGNvbnN0IHNpZyA9IGF3YWl0IHNpZ25EZXZpY2VQYXlsb2FkKGlkZW50aXR5LCBwYXlsb2FkKTtcblxuICAgICAgICBhd2FpdCB0aGlzLl9zZW5kUmVxdWVzdCgnY29ubmVjdCcsIHtcbiAgICAgICAgICBtaW5Qcm90b2NvbDogMyxcbiAgICAgICAgICBtYXhQcm90b2NvbDogMyxcbiAgICAgICAgICBjbGllbnQ6IHtcbiAgICAgICAgICAgIGlkOiAnZ2F0ZXdheS1jbGllbnQnLFxuICAgICAgICAgICAgbW9kZTogJ2JhY2tlbmQnLFxuICAgICAgICAgICAgdmVyc2lvbjogJzAuMS4xMCcsXG4gICAgICAgICAgICBwbGF0Zm9ybTogJ2VsZWN0cm9uJyxcbiAgICAgICAgICB9LFxuICAgICAgICAgIHJvbGU6ICdvcGVyYXRvcicsXG4gICAgICAgICAgc2NvcGVzOiBbJ29wZXJhdG9yLnJlYWQnLCAnb3BlcmF0b3Iud3JpdGUnXSxcbiAgICAgICAgICBkZXZpY2U6IHtcbiAgICAgICAgICAgIGlkOiBpZGVudGl0eS5pZCxcbiAgICAgICAgICAgIHB1YmxpY0tleTogaWRlbnRpdHkucHVibGljS2V5LFxuICAgICAgICAgICAgc2lnbmF0dXJlOiBzaWcuc2lnbmF0dXJlLFxuICAgICAgICAgICAgc2lnbmVkQXQ6IHNpZ25lZEF0TXMsXG4gICAgICAgICAgICBub25jZTogY29ubmVjdE5vbmNlLFxuICAgICAgICAgIH0sXG4gICAgICAgICAgYXV0aDoge1xuICAgICAgICAgICAgdG9rZW46IHRoaXMudG9rZW4sXG4gICAgICAgICAgfSxcbiAgICAgICAgfSk7XG5cbiAgICAgICAgdGhpcy5fc2V0U3RhdGUoJ2Nvbm5lY3RlZCcpO1xuICAgICAgICB0aGlzLl9zdGFydEhlYXJ0YmVhdCgpO1xuICAgICAgfSBjYXRjaCAoZXJyKSB7XG4gICAgICAgIGNvbnNvbGUuZXJyb3IoJ1tvY2xhdy13c10gQ29ubmVjdCBoYW5kc2hha2UgZmFpbGVkJywgZXJyKTtcbiAgICAgICAgd3MuY2xvc2UoKTtcbiAgICAgIH1cbiAgICB9O1xuXG4gICAgd3Mub25vcGVuID0gKCkgPT4ge1xuICAgICAgdGhpcy5fc2V0U3RhdGUoJ2hhbmRzaGFraW5nJyk7XG4gICAgICAvLyBUaGUgZ2F0ZXdheSB3aWxsIHNlbmQgY29ubmVjdC5jaGFsbGVuZ2U7IGNvbm5lY3QgaXMgc2VudCBvbmNlIHdlIGhhdmUgYSBub25jZS5cbiAgICB9O1xuXG4gICAgd3Mub25tZXNzYWdlID0gKGV2ZW50OiBNZXNzYWdlRXZlbnQpID0+IHtcbiAgICAgIGxldCBmcmFtZTogYW55O1xuICAgICAgdHJ5IHtcbiAgICAgICAgZnJhbWUgPSBKU09OLnBhcnNlKGV2ZW50LmRhdGEgYXMgc3RyaW5nKTtcbiAgICAgIH0gY2F0Y2gge1xuICAgICAgICBjb25zb2xlLmVycm9yKCdbb2NsYXctd3NdIEZhaWxlZCB0byBwYXJzZSBpbmNvbWluZyBtZXNzYWdlJyk7XG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cblxuICAgICAgLy8gUmVzcG9uc2VzXG4gICAgICBpZiAoZnJhbWUudHlwZSA9PT0gJ3JlcycpIHtcbiAgICAgICAgY29uc3QgcGVuZGluZyA9IHRoaXMucGVuZGluZ1JlcXVlc3RzLmdldChmcmFtZS5pZCk7XG4gICAgICAgIGlmIChwZW5kaW5nKSB7XG4gICAgICAgICAgdGhpcy5wZW5kaW5nUmVxdWVzdHMuZGVsZXRlKGZyYW1lLmlkKTtcbiAgICAgICAgICBpZiAoZnJhbWUub2spIHBlbmRpbmcucmVzb2x2ZShmcmFtZS5wYXlsb2FkKTtcbiAgICAgICAgICBlbHNlIHBlbmRpbmcucmVqZWN0KG5ldyBFcnJvcihmcmFtZS5lcnJvcj8ubWVzc2FnZSB8fCAnUmVxdWVzdCBmYWlsZWQnKSk7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuXG4gICAgICAvLyBFdmVudHNcbiAgICAgIGlmIChmcmFtZS50eXBlID09PSAnZXZlbnQnKSB7XG4gICAgICAgIGlmIChmcmFtZS5ldmVudCA9PT0gJ2Nvbm5lY3QuY2hhbGxlbmdlJykge1xuICAgICAgICAgIGNvbm5lY3ROb25jZSA9IGZyYW1lLnBheWxvYWQ/Lm5vbmNlIHx8IG51bGw7XG4gICAgICAgICAgLy8gQXR0ZW1wdCBoYW5kc2hha2Ugb25jZSB3ZSBoYXZlIGEgbm9uY2UuXG4gICAgICAgICAgdm9pZCB0cnlDb25uZWN0KCk7XG4gICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKGZyYW1lLmV2ZW50ID09PSAnY2hhdCcpIHtcbiAgICAgICAgICBjb25zdCBwYXlsb2FkID0gZnJhbWUucGF5bG9hZDtcbiAgICAgICAgICBjb25zdCBpbmNvbWluZ1Nlc3Npb25LZXkgPSBTdHJpbmcocGF5bG9hZD8uc2Vzc2lvbktleSB8fCAnJyk7XG4gICAgICAgICAgaWYgKCFpbmNvbWluZ1Nlc3Npb25LZXkgfHwgIXNlc3Npb25LZXlNYXRjaGVzKHRoaXMuc2Vzc2lvbktleSwgaW5jb21pbmdTZXNzaW9uS2V5KSkge1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIC8vIEF2b2lkIGRvdWJsZS1yZW5kZXI6IGdhdGV3YXkgZW1pdHMgZGVsdGEgKyBmaW5hbCArIGFib3J0ZWQuIFJlbmRlciBvbmx5IGZpbmFsL2Fib3J0ZWQuXG4gICAgICAgICAgaWYgKHBheWxvYWQ/LnN0YXRlICYmIHBheWxvYWQuc3RhdGUgIT09ICdmaW5hbCcgJiYgcGF5bG9hZC5zdGF0ZSAhPT0gJ2Fib3J0ZWQnKSB7XG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgLy8gV2Ugb25seSBhcHBlbmQgYXNzaXN0YW50IG91dHB1dCB0byBVSS5cbiAgICAgICAgICBjb25zdCBtc2cgPSBwYXlsb2FkPy5tZXNzYWdlO1xuICAgICAgICAgIGNvbnN0IHJvbGUgPSBtc2c/LnJvbGUgPz8gJ2Fzc2lzdGFudCc7XG5cbiAgICAgICAgICAvLyBCb3RoIGZpbmFsIGFuZCBhYm9ydGVkIHJlc29sdmUgXCJ3b3JraW5nXCIuXG4gICAgICAgICAgdGhpcy5hY3RpdmVSdW5JZCA9IG51bGw7XG4gICAgICAgICAgdGhpcy5fc2V0V29ya2luZyhmYWxzZSk7XG5cbiAgICAgICAgICAvLyBBYm9ydGVkIG1heSBoYXZlIG5vIGFzc2lzdGFudCBtZXNzYWdlIG9yIG1heSBjYXJyeSBwYXJ0aWFsIGFzc2lzdGFudCBjb250ZW50LlxuICAgICAgICAgIGlmIChwYXlsb2FkPy5zdGF0ZSA9PT0gJ2Fib3J0ZWQnKSB7XG4gICAgICAgICAgICAvLyBJZiB0aGVyZSdzIG5vIHVzYWJsZSBhc3Npc3RhbnQgcGF5bG9hZCwganVzdCBkb24ndCBhcHBlbmQgYW55dGhpbmcuXG4gICAgICAgICAgICAvLyAoVmlldyBsYXllciBtYXkgb3B0aW9uYWxseSBhZGQgYSBzeXN0ZW0gbWVzc2FnZSBvbiBzdWNjZXNzZnVsIHN0b3AuKVxuICAgICAgICAgICAgaWYgKCFtc2cpIHJldHVybjtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBpZiAocm9sZSAhPT0gJ2Fzc2lzdGFudCcpIHtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBjb25zdCB0ZXh0ID0gZXh0cmFjdFRleHRGcm9tR2F0ZXdheU1lc3NhZ2UobXNnKTtcbiAgICAgICAgICBpZiAoIXRleHQpIHJldHVybjtcblxuICAgICAgICAgIC8vIE9wdGlvbmFsOiBoaWRlIGhlYXJ0YmVhdCBhY2tzIChub2lzZSBpbiBVSSlcbiAgICAgICAgICBpZiAodGV4dC50cmltKCkgPT09ICdIRUFSVEJFQVRfT0snKSB7XG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgdGhpcy5vbk1lc3NhZ2U/Lih7XG4gICAgICAgICAgICB0eXBlOiAnbWVzc2FnZScsXG4gICAgICAgICAgICBwYXlsb2FkOiB7XG4gICAgICAgICAgICAgIGNvbnRlbnQ6IHRleHQsXG4gICAgICAgICAgICAgIHJvbGU6ICdhc3Npc3RhbnQnLFxuICAgICAgICAgICAgICB0aW1lc3RhbXA6IERhdGUubm93KCksXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0pO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cblxuICAgICAgY29uc29sZS5kZWJ1ZygnW29jbGF3LXdzXSBVbmhhbmRsZWQgZnJhbWUnLCBmcmFtZSk7XG4gICAgfTtcblxuICAgIHdzLm9uY2xvc2UgPSAoKSA9PiB7XG4gICAgICB0aGlzLl9zdG9wVGltZXJzKCk7XG4gICAgICB0aGlzLl9zZXRXb3JraW5nKGZhbHNlKTtcbiAgICAgIHRoaXMuX3NldFN0YXRlKCdkaXNjb25uZWN0ZWQnKTtcblxuICAgICAgZm9yIChjb25zdCBwZW5kaW5nIG9mIHRoaXMucGVuZGluZ1JlcXVlc3RzLnZhbHVlcygpKSB7XG4gICAgICAgIHBlbmRpbmcucmVqZWN0KG5ldyBFcnJvcignQ29ubmVjdGlvbiBjbG9zZWQnKSk7XG4gICAgICB9XG4gICAgICB0aGlzLnBlbmRpbmdSZXF1ZXN0cy5jbGVhcigpO1xuXG4gICAgICBpZiAoIXRoaXMuaW50ZW50aW9uYWxDbG9zZSkge1xuICAgICAgICB0aGlzLl9zY2hlZHVsZVJlY29ubmVjdCgpO1xuICAgICAgfVxuICAgIH07XG5cbiAgICB3cy5vbmVycm9yID0gKGV2OiBFdmVudCkgPT4ge1xuICAgICAgY29uc29sZS5lcnJvcignW29jbGF3LXdzXSBXZWJTb2NrZXQgZXJyb3InLCBldik7XG4gICAgfTtcbiAgfVxuXG4gIHByaXZhdGUgX3NlbmRSZXF1ZXN0KG1ldGhvZDogc3RyaW5nLCBwYXJhbXM6IGFueSk6IFByb21pc2U8YW55PiB7XG4gICAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIGlmICghdGhpcy53cyB8fCB0aGlzLndzLnJlYWR5U3RhdGUgIT09IFdlYlNvY2tldC5PUEVOKSB7XG4gICAgICAgIHJlamVjdChuZXcgRXJyb3IoJ1dlYlNvY2tldCBub3QgY29ubmVjdGVkJykpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG5cbiAgICAgIGNvbnN0IGlkID0gYHJlcS0keysrdGhpcy5yZXF1ZXN0SWR9YDtcbiAgICAgIHRoaXMucGVuZGluZ1JlcXVlc3RzLnNldChpZCwgeyByZXNvbHZlLCByZWplY3QgfSk7XG5cbiAgICAgIHRoaXMud3Muc2VuZChcbiAgICAgICAgSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIHR5cGU6ICdyZXEnLFxuICAgICAgICAgIG1ldGhvZCxcbiAgICAgICAgICBpZCxcbiAgICAgICAgICBwYXJhbXMsXG4gICAgICAgIH0pXG4gICAgICApO1xuXG4gICAgICBzZXRUaW1lb3V0KCgpID0+IHtcbiAgICAgICAgaWYgKHRoaXMucGVuZGluZ1JlcXVlc3RzLmhhcyhpZCkpIHtcbiAgICAgICAgICB0aGlzLnBlbmRpbmdSZXF1ZXN0cy5kZWxldGUoaWQpO1xuICAgICAgICAgIHJlamVjdChuZXcgRXJyb3IoYFJlcXVlc3QgdGltZW91dDogJHttZXRob2R9YCkpO1xuICAgICAgICB9XG4gICAgICB9LCAzMF8wMDApO1xuICAgIH0pO1xuICB9XG5cbiAgcHJpdmF0ZSBfc2NoZWR1bGVSZWNvbm5lY3QoKTogdm9pZCB7XG4gICAgaWYgKHRoaXMucmVjb25uZWN0VGltZXIgIT09IG51bGwpIHJldHVybjtcbiAgICB0aGlzLnJlY29ubmVjdFRpbWVyID0gc2V0VGltZW91dCgoKSA9PiB7XG4gICAgICB0aGlzLnJlY29ubmVjdFRpbWVyID0gbnVsbDtcbiAgICAgIGlmICghdGhpcy5pbnRlbnRpb25hbENsb3NlKSB7XG4gICAgICAgIGNvbnNvbGUubG9nKGBbb2NsYXctd3NdIFJlY29ubmVjdGluZyB0byAke3RoaXMudXJsfVx1MjAyNmApO1xuICAgICAgICB0aGlzLl9jb25uZWN0KCk7XG4gICAgICB9XG4gICAgfSwgUkVDT05ORUNUX0RFTEFZX01TKTtcbiAgfVxuXG4gIHByaXZhdGUgX3N0YXJ0SGVhcnRiZWF0KCk6IHZvaWQge1xuICAgIHRoaXMuX3N0b3BIZWFydGJlYXQoKTtcbiAgICB0aGlzLmhlYXJ0YmVhdFRpbWVyID0gc2V0SW50ZXJ2YWwoKCkgPT4ge1xuICAgICAgaWYgKHRoaXMud3M/LnJlYWR5U3RhdGUgIT09IFdlYlNvY2tldC5PUEVOKSByZXR1cm47XG4gICAgICBpZiAodGhpcy53cy5idWZmZXJlZEFtb3VudCA+IDApIHtcbiAgICAgICAgY29uc29sZS53YXJuKCdbb2NsYXctd3NdIFNlbmQgYnVmZmVyIG5vdCBlbXB0eSBcdTIwMTQgY29ubmVjdGlvbiBtYXkgYmUgc3RhbGxlZCcpO1xuICAgICAgfVxuICAgIH0sIEhFQVJUQkVBVF9JTlRFUlZBTF9NUyk7XG4gIH1cblxuICBwcml2YXRlIF9zdG9wSGVhcnRiZWF0KCk6IHZvaWQge1xuICAgIGlmICh0aGlzLmhlYXJ0YmVhdFRpbWVyKSB7XG4gICAgICBjbGVhckludGVydmFsKHRoaXMuaGVhcnRiZWF0VGltZXIpO1xuICAgICAgdGhpcy5oZWFydGJlYXRUaW1lciA9IG51bGw7XG4gICAgfVxuICB9XG5cbiAgcHJpdmF0ZSBfc3RvcFRpbWVycygpOiB2b2lkIHtcbiAgICB0aGlzLl9zdG9wSGVhcnRiZWF0KCk7XG4gICAgdGhpcy5fZGlzYXJtV29ya2luZ1NhZmV0eVRpbWVvdXQoKTtcbiAgICBpZiAodGhpcy5yZWNvbm5lY3RUaW1lcikge1xuICAgICAgY2xlYXJUaW1lb3V0KHRoaXMucmVjb25uZWN0VGltZXIpO1xuICAgICAgdGhpcy5yZWNvbm5lY3RUaW1lciA9IG51bGw7XG4gICAgfVxuICB9XG5cbiAgcHJpdmF0ZSBfc2V0U3RhdGUoc3RhdGU6IFdTQ2xpZW50U3RhdGUpOiB2b2lkIHtcbiAgICBpZiAodGhpcy5zdGF0ZSA9PT0gc3RhdGUpIHJldHVybjtcbiAgICB0aGlzLnN0YXRlID0gc3RhdGU7XG4gICAgdGhpcy5vblN0YXRlQ2hhbmdlPy4oc3RhdGUpO1xuICB9XG5cbiAgcHJpdmF0ZSBfc2V0V29ya2luZyh3b3JraW5nOiBib29sZWFuKTogdm9pZCB7XG4gICAgaWYgKHRoaXMud29ya2luZyA9PT0gd29ya2luZykgcmV0dXJuO1xuICAgIHRoaXMud29ya2luZyA9IHdvcmtpbmc7XG4gICAgdGhpcy5vbldvcmtpbmdDaGFuZ2U/Lih3b3JraW5nKTtcblxuICAgIGlmICghd29ya2luZykge1xuICAgICAgdGhpcy5fZGlzYXJtV29ya2luZ1NhZmV0eVRpbWVvdXQoKTtcbiAgICB9XG4gIH1cblxuICBwcml2YXRlIF9hcm1Xb3JraW5nU2FmZXR5VGltZW91dCgpOiB2b2lkIHtcbiAgICB0aGlzLl9kaXNhcm1Xb3JraW5nU2FmZXR5VGltZW91dCgpO1xuICAgIHRoaXMud29ya2luZ1RpbWVyID0gc2V0VGltZW91dCgoKSA9PiB7XG4gICAgICAvLyBJZiB0aGUgZ2F0ZXdheSBuZXZlciBlbWl0cyBhbiBhc3Npc3RhbnQgZmluYWwgcmVzcG9uc2UsIGRvblx1MjAxOXQgbGVhdmUgVUkgc3R1Y2suXG4gICAgICB0aGlzLl9zZXRXb3JraW5nKGZhbHNlKTtcbiAgICB9LCBXT1JLSU5HX01BWF9NUyk7XG4gIH1cblxuICBwcml2YXRlIF9kaXNhcm1Xb3JraW5nU2FmZXR5VGltZW91dCgpOiB2b2lkIHtcbiAgICBpZiAodGhpcy53b3JraW5nVGltZXIpIHtcbiAgICAgIGNsZWFyVGltZW91dCh0aGlzLndvcmtpbmdUaW1lcik7XG4gICAgICB0aGlzLndvcmtpbmdUaW1lciA9IG51bGw7XG4gICAgfVxuICB9XG59XG4iLCAiaW1wb3J0IHR5cGUgeyBDaGF0TWVzc2FnZSB9IGZyb20gJy4vdHlwZXMnO1xuXG4vKiogTWFuYWdlcyB0aGUgaW4tbWVtb3J5IGxpc3Qgb2YgY2hhdCBtZXNzYWdlcyBhbmQgbm90aWZpZXMgVUkgb24gY2hhbmdlcyAqL1xuZXhwb3J0IGNsYXNzIENoYXRNYW5hZ2VyIHtcbiAgcHJpdmF0ZSBtZXNzYWdlczogQ2hhdE1lc3NhZ2VbXSA9IFtdO1xuXG4gIC8qKiBGaXJlZCBmb3IgYSBmdWxsIHJlLXJlbmRlciAoY2xlYXIvcmVsb2FkKSAqL1xuICBvblVwZGF0ZTogKChtZXNzYWdlczogcmVhZG9ubHkgQ2hhdE1lc3NhZ2VbXSkgPT4gdm9pZCkgfCBudWxsID0gbnVsbDtcbiAgLyoqIEZpcmVkIHdoZW4gYSBzaW5nbGUgbWVzc2FnZSBpcyBhcHBlbmRlZCBcdTIwMTQgdXNlIGZvciBPKDEpIGFwcGVuZC1vbmx5IFVJICovXG4gIG9uTWVzc2FnZUFkZGVkOiAoKG1zZzogQ2hhdE1lc3NhZ2UpID0+IHZvaWQpIHwgbnVsbCA9IG51bGw7XG5cbiAgYWRkTWVzc2FnZShtc2c6IENoYXRNZXNzYWdlKTogdm9pZCB7XG4gICAgdGhpcy5tZXNzYWdlcy5wdXNoKG1zZyk7XG4gICAgdGhpcy5vbk1lc3NhZ2VBZGRlZD8uKG1zZyk7XG4gIH1cblxuICBnZXRNZXNzYWdlcygpOiByZWFkb25seSBDaGF0TWVzc2FnZVtdIHtcbiAgICByZXR1cm4gdGhpcy5tZXNzYWdlcztcbiAgfVxuXG4gIGNsZWFyKCk6IHZvaWQge1xuICAgIHRoaXMubWVzc2FnZXMgPSBbXTtcbiAgICB0aGlzLm9uVXBkYXRlPy4oW10pO1xuICB9XG5cbiAgLyoqIENyZWF0ZSBhIHVzZXIgbWVzc2FnZSBvYmplY3QgKHdpdGhvdXQgYWRkaW5nIGl0KSAqL1xuICBzdGF0aWMgY3JlYXRlVXNlck1lc3NhZ2UoY29udGVudDogc3RyaW5nKTogQ2hhdE1lc3NhZ2Uge1xuICAgIHJldHVybiB7XG4gICAgICBpZDogYG1zZy0ke0RhdGUubm93KCl9LSR7TWF0aC5yYW5kb20oKS50b1N0cmluZygzNikuc2xpY2UoMiwgNyl9YCxcbiAgICAgIHJvbGU6ICd1c2VyJyxcbiAgICAgIGNvbnRlbnQsXG4gICAgICB0aW1lc3RhbXA6IERhdGUubm93KCksXG4gICAgfTtcbiAgfVxuXG4gIC8qKiBDcmVhdGUgYW4gYXNzaXN0YW50IG1lc3NhZ2Ugb2JqZWN0ICh3aXRob3V0IGFkZGluZyBpdCkgKi9cbiAgc3RhdGljIGNyZWF0ZUFzc2lzdGFudE1lc3NhZ2UoY29udGVudDogc3RyaW5nKTogQ2hhdE1lc3NhZ2Uge1xuICAgIHJldHVybiB7XG4gICAgICBpZDogYG1zZy0ke0RhdGUubm93KCl9LSR7TWF0aC5yYW5kb20oKS50b1N0cmluZygzNikuc2xpY2UoMiwgNyl9YCxcbiAgICAgIHJvbGU6ICdhc3Npc3RhbnQnLFxuICAgICAgY29udGVudCxcbiAgICAgIHRpbWVzdGFtcDogRGF0ZS5ub3coKSxcbiAgICB9O1xuICB9XG5cbiAgLyoqIENyZWF0ZSBhIHN5c3RlbSAvIHN0YXR1cyBtZXNzYWdlIChlcnJvcnMsIHJlY29ubmVjdCBub3RpY2VzLCBldGMuKSAqL1xuICBzdGF0aWMgY3JlYXRlU3lzdGVtTWVzc2FnZShjb250ZW50OiBzdHJpbmcsIGxldmVsOiBDaGF0TWVzc2FnZVsnbGV2ZWwnXSA9ICdpbmZvJyk6IENoYXRNZXNzYWdlIHtcbiAgICByZXR1cm4ge1xuICAgICAgaWQ6IGBzeXMtJHtEYXRlLm5vdygpfWAsXG4gICAgICByb2xlOiAnc3lzdGVtJyxcbiAgICAgIGxldmVsLFxuICAgICAgY29udGVudCxcbiAgICAgIHRpbWVzdGFtcDogRGF0ZS5ub3coKSxcbiAgICB9O1xuICB9XG59XG4iLCAiaW1wb3J0IHsgSXRlbVZpZXcsIE1hcmtkb3duUmVuZGVyZXIsIE5vdGljZSwgV29ya3NwYWNlTGVhZiB9IGZyb20gJ29ic2lkaWFuJztcbmltcG9ydCB0eXBlIE9wZW5DbGF3UGx1Z2luIGZyb20gJy4vbWFpbic7XG5pbXBvcnQgeyBDaGF0TWFuYWdlciB9IGZyb20gJy4vY2hhdCc7XG5pbXBvcnQgdHlwZSB7IENoYXRNZXNzYWdlIH0gZnJvbSAnLi90eXBlcyc7XG5pbXBvcnQgeyBnZXRBY3RpdmVOb3RlQ29udGV4dCB9IGZyb20gJy4vY29udGV4dCc7XG5cbmV4cG9ydCBjb25zdCBWSUVXX1RZUEVfT1BFTkNMQVdfQ0hBVCA9ICdvcGVuY2xhdy1jaGF0JztcblxuZXhwb3J0IGNsYXNzIE9wZW5DbGF3Q2hhdFZpZXcgZXh0ZW5kcyBJdGVtVmlldyB7XG4gIHByaXZhdGUgcGx1Z2luOiBPcGVuQ2xhd1BsdWdpbjtcbiAgcHJpdmF0ZSBjaGF0TWFuYWdlcjogQ2hhdE1hbmFnZXI7XG5cbiAgLy8gU3RhdGVcbiAgcHJpdmF0ZSBpc0Nvbm5lY3RlZCA9IGZhbHNlO1xuICBwcml2YXRlIGlzV29ya2luZyA9IGZhbHNlO1xuXG4gIC8vIERPTSByZWZzXG4gIHByaXZhdGUgbWVzc2FnZXNFbCE6IEhUTUxFbGVtZW50O1xuICBwcml2YXRlIGlucHV0RWwhOiBIVE1MVGV4dEFyZWFFbGVtZW50O1xuICBwcml2YXRlIHNlbmRCdG4hOiBIVE1MQnV0dG9uRWxlbWVudDtcbiAgcHJpdmF0ZSBpbmNsdWRlTm90ZUNoZWNrYm94ITogSFRNTElucHV0RWxlbWVudDtcbiAgcHJpdmF0ZSBzdGF0dXNEb3QhOiBIVE1MRWxlbWVudDtcblxuICBjb25zdHJ1Y3RvcihsZWFmOiBXb3Jrc3BhY2VMZWFmLCBwbHVnaW46IE9wZW5DbGF3UGx1Z2luKSB7XG4gICAgc3VwZXIobGVhZik7XG4gICAgdGhpcy5wbHVnaW4gPSBwbHVnaW47XG4gICAgdGhpcy5jaGF0TWFuYWdlciA9IHBsdWdpbi5jaGF0TWFuYWdlcjtcbiAgfVxuXG4gIGdldFZpZXdUeXBlKCk6IHN0cmluZyB7XG4gICAgcmV0dXJuIFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFUO1xuICB9XG5cbiAgZ2V0RGlzcGxheVRleHQoKTogc3RyaW5nIHtcbiAgICByZXR1cm4gJ09wZW5DbGF3IENoYXQnO1xuICB9XG5cbiAgZ2V0SWNvbigpOiBzdHJpbmcge1xuICAgIHJldHVybiAnbWVzc2FnZS1zcXVhcmUnO1xuICB9XG5cbiAgYXN5bmMgb25PcGVuKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIHRoaXMuX2J1aWxkVUkoKTtcblxuICAgIC8vIEZ1bGwgcmUtcmVuZGVyIG9uIGNsZWFyIC8gcmVsb2FkXG4gICAgdGhpcy5jaGF0TWFuYWdlci5vblVwZGF0ZSA9IChtc2dzKSA9PiB0aGlzLl9yZW5kZXJNZXNzYWdlcyhtc2dzKTtcbiAgICAvLyBPKDEpIGFwcGVuZCBmb3IgbmV3IG1lc3NhZ2VzXG4gICAgdGhpcy5jaGF0TWFuYWdlci5vbk1lc3NhZ2VBZGRlZCA9IChtc2cpID0+IHRoaXMuX2FwcGVuZE1lc3NhZ2UobXNnKTtcblxuICAgIC8vIFN1YnNjcmliZSB0byBXUyBzdGF0ZSBjaGFuZ2VzXG4gICAgdGhpcy5wbHVnaW4ud3NDbGllbnQub25TdGF0ZUNoYW5nZSA9IChzdGF0ZSkgPT4ge1xuICAgICAgdGhpcy5pc0Nvbm5lY3RlZCA9IHN0YXRlID09PSAnY29ubmVjdGVkJztcbiAgICAgIHRoaXMuc3RhdHVzRG90LnRvZ2dsZUNsYXNzKCdjb25uZWN0ZWQnLCB0aGlzLmlzQ29ubmVjdGVkKTtcbiAgICAgIHRoaXMuc3RhdHVzRG90LnRpdGxlID0gYEdhdGV3YXk6ICR7c3RhdGV9YDtcbiAgICAgIHRoaXMuX3VwZGF0ZVNlbmRCdXR0b24oKTtcbiAgICB9O1xuXG4gICAgLy8gU3Vic2NyaWJlIHRvIFx1MjAxQ3dvcmtpbmdcdTIwMUQgKHJlcXVlc3QtaW4tZmxpZ2h0KSBzdGF0ZVxuICAgIHRoaXMucGx1Z2luLndzQ2xpZW50Lm9uV29ya2luZ0NoYW5nZSA9ICh3b3JraW5nKSA9PiB7XG4gICAgICB0aGlzLmlzV29ya2luZyA9IHdvcmtpbmc7XG4gICAgICB0aGlzLl91cGRhdGVTZW5kQnV0dG9uKCk7XG4gICAgfTtcblxuICAgIC8vIFJlZmxlY3QgY3VycmVudCBzdGF0ZVxuICAgIHRoaXMuaXNDb25uZWN0ZWQgPSB0aGlzLnBsdWdpbi53c0NsaWVudC5zdGF0ZSA9PT0gJ2Nvbm5lY3RlZCc7XG4gICAgdGhpcy5zdGF0dXNEb3QudG9nZ2xlQ2xhc3MoJ2Nvbm5lY3RlZCcsIHRoaXMuaXNDb25uZWN0ZWQpO1xuICAgIHRoaXMuX3VwZGF0ZVNlbmRCdXR0b24oKTtcblxuICAgIHRoaXMuX3JlbmRlck1lc3NhZ2VzKHRoaXMuY2hhdE1hbmFnZXIuZ2V0TWVzc2FnZXMoKSk7XG4gIH1cblxuICBhc3luYyBvbkNsb3NlKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIHRoaXMuY2hhdE1hbmFnZXIub25VcGRhdGUgPSBudWxsO1xuICAgIHRoaXMuY2hhdE1hbmFnZXIub25NZXNzYWdlQWRkZWQgPSBudWxsO1xuICAgIHRoaXMucGx1Z2luLndzQ2xpZW50Lm9uU3RhdGVDaGFuZ2UgPSBudWxsO1xuICAgIHRoaXMucGx1Z2luLndzQ2xpZW50Lm9uV29ya2luZ0NoYW5nZSA9IG51bGw7XG4gIH1cblxuICAvLyBcdTI1MDBcdTI1MDAgVUkgY29uc3RydWN0aW9uIFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFxuXG4gIHByaXZhdGUgX2J1aWxkVUkoKTogdm9pZCB7XG4gICAgY29uc3Qgcm9vdCA9IHRoaXMuY29udGVudEVsO1xuICAgIHJvb3QuZW1wdHkoKTtcbiAgICByb290LmFkZENsYXNzKCdvY2xhdy1jaGF0LXZpZXcnKTtcblxuICAgIC8vIFx1MjUwMFx1MjUwMCBIZWFkZXIgXHUyNTAwXHUyNTAwXG4gICAgY29uc3QgaGVhZGVyID0gcm9vdC5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1oZWFkZXInIH0pO1xuICAgIGhlYWRlci5jcmVhdGVTcGFuKHsgY2xzOiAnb2NsYXctaGVhZGVyLXRpdGxlJywgdGV4dDogJ09wZW5DbGF3IENoYXQnIH0pO1xuICAgIHRoaXMuc3RhdHVzRG90ID0gaGVhZGVyLmNyZWF0ZURpdih7IGNsczogJ29jbGF3LXN0YXR1cy1kb3QnIH0pO1xuICAgIHRoaXMuc3RhdHVzRG90LnRpdGxlID0gJ0dhdGV3YXk6IGRpc2Nvbm5lY3RlZCc7XG5cbiAgICAvLyBcdTI1MDBcdTI1MDAgTWVzc2FnZXMgYXJlYSBcdTI1MDBcdTI1MDBcbiAgICB0aGlzLm1lc3NhZ2VzRWwgPSByb290LmNyZWF0ZURpdih7IGNsczogJ29jbGF3LW1lc3NhZ2VzJyB9KTtcblxuICAgIC8vIFx1MjUwMFx1MjUwMCBDb250ZXh0IHJvdyBcdTI1MDBcdTI1MDBcbiAgICBjb25zdCBjdHhSb3cgPSByb290LmNyZWF0ZURpdih7IGNsczogJ29jbGF3LWNvbnRleHQtcm93JyB9KTtcbiAgICB0aGlzLmluY2x1ZGVOb3RlQ2hlY2tib3ggPSBjdHhSb3cuY3JlYXRlRWwoJ2lucHV0JywgeyB0eXBlOiAnY2hlY2tib3gnIH0pO1xuICAgIHRoaXMuaW5jbHVkZU5vdGVDaGVja2JveC5pZCA9ICdvY2xhdy1pbmNsdWRlLW5vdGUnO1xuICAgIHRoaXMuaW5jbHVkZU5vdGVDaGVja2JveC5jaGVja2VkID0gdGhpcy5wbHVnaW4uc2V0dGluZ3MuaW5jbHVkZUFjdGl2ZU5vdGU7XG4gICAgY29uc3QgY3R4TGFiZWwgPSBjdHhSb3cuY3JlYXRlRWwoJ2xhYmVsJywgeyB0ZXh0OiAnSW5jbHVkZSBhY3RpdmUgbm90ZScgfSk7XG4gICAgY3R4TGFiZWwuaHRtbEZvciA9ICdvY2xhdy1pbmNsdWRlLW5vdGUnO1xuXG4gICAgLy8gXHUyNTAwXHUyNTAwIElucHV0IHJvdyBcdTI1MDBcdTI1MDBcbiAgICBjb25zdCBpbnB1dFJvdyA9IHJvb3QuY3JlYXRlRGl2KHsgY2xzOiAnb2NsYXctaW5wdXQtcm93JyB9KTtcbiAgICB0aGlzLmlucHV0RWwgPSBpbnB1dFJvdy5jcmVhdGVFbCgndGV4dGFyZWEnLCB7XG4gICAgICBjbHM6ICdvY2xhdy1pbnB1dCcsXG4gICAgICBwbGFjZWhvbGRlcjogJ0FzayBhbnl0aGluZ1x1MjAyNicsXG4gICAgfSk7XG4gICAgdGhpcy5pbnB1dEVsLnJvd3MgPSAxO1xuXG4gICAgdGhpcy5zZW5kQnRuID0gaW5wdXRSb3cuY3JlYXRlRWwoJ2J1dHRvbicsIHsgY2xzOiAnb2NsYXctc2VuZC1idG4nLCB0ZXh0OiAnU2VuZCcgfSk7XG5cbiAgICAvLyBcdTI1MDBcdTI1MDAgRXZlbnQgbGlzdGVuZXJzIFx1MjUwMFx1MjUwMFxuICAgIHRoaXMuc2VuZEJ0bi5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpID0+IHRoaXMuX2hhbmRsZVNlbmQoKSk7XG4gICAgdGhpcy5pbnB1dEVsLmFkZEV2ZW50TGlzdGVuZXIoJ2tleWRvd24nLCAoZSkgPT4ge1xuICAgICAgaWYgKGUua2V5ID09PSAnRW50ZXInICYmICFlLnNoaWZ0S2V5KSB7XG4gICAgICAgIGUucHJldmVudERlZmF1bHQoKTtcbiAgICAgICAgdGhpcy5faGFuZGxlU2VuZCgpO1xuICAgICAgfVxuICAgIH0pO1xuICAgIC8vIEF1dG8tcmVzaXplIHRleHRhcmVhXG4gICAgdGhpcy5pbnB1dEVsLmFkZEV2ZW50TGlzdGVuZXIoJ2lucHV0JywgKCkgPT4ge1xuICAgICAgdGhpcy5pbnB1dEVsLnN0eWxlLmhlaWdodCA9ICdhdXRvJztcbiAgICAgIHRoaXMuaW5wdXRFbC5zdHlsZS5oZWlnaHQgPSBgJHt0aGlzLmlucHV0RWwuc2Nyb2xsSGVpZ2h0fXB4YDtcbiAgICB9KTtcbiAgfVxuXG4gIC8vIFx1MjUwMFx1MjUwMCBNZXNzYWdlIHJlbmRlcmluZyBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcblxuICBwcml2YXRlIF9yZW5kZXJNZXNzYWdlcyhtZXNzYWdlczogcmVhZG9ubHkgQ2hhdE1lc3NhZ2VbXSk6IHZvaWQge1xuICAgIHRoaXMubWVzc2FnZXNFbC5lbXB0eSgpO1xuXG4gICAgaWYgKG1lc3NhZ2VzLmxlbmd0aCA9PT0gMCkge1xuICAgICAgdGhpcy5tZXNzYWdlc0VsLmNyZWF0ZUVsKCdwJywge1xuICAgICAgICB0ZXh0OiAnU2VuZCBhIG1lc3NhZ2UgdG8gc3RhcnQgY2hhdHRpbmcuJyxcbiAgICAgICAgY2xzOiAnb2NsYXctbWVzc2FnZSBzeXN0ZW0gb2NsYXctcGxhY2Vob2xkZXInLFxuICAgICAgfSk7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgZm9yIChjb25zdCBtc2cgb2YgbWVzc2FnZXMpIHtcbiAgICAgIHRoaXMuX2FwcGVuZE1lc3NhZ2UobXNnKTtcbiAgICB9XG5cbiAgICAvLyBTY3JvbGwgdG8gYm90dG9tXG4gICAgdGhpcy5tZXNzYWdlc0VsLnNjcm9sbFRvcCA9IHRoaXMubWVzc2FnZXNFbC5zY3JvbGxIZWlnaHQ7XG4gIH1cblxuICAvKiogQXBwZW5kcyBhIHNpbmdsZSBtZXNzYWdlIHdpdGhvdXQgcmVidWlsZGluZyB0aGUgRE9NIChPKDEpKSAqL1xuICBwcml2YXRlIF9hcHBlbmRNZXNzYWdlKG1zZzogQ2hhdE1lc3NhZ2UpOiB2b2lkIHtcbiAgICAvLyBSZW1vdmUgZW1wdHktc3RhdGUgcGxhY2Vob2xkZXIgaWYgcHJlc2VudFxuICAgIHRoaXMubWVzc2FnZXNFbC5xdWVyeVNlbGVjdG9yKCcub2NsYXctcGxhY2Vob2xkZXInKT8ucmVtb3ZlKCk7XG5cbiAgICBjb25zdCBsZXZlbENsYXNzID0gbXNnLmxldmVsID8gYCAke21zZy5sZXZlbH1gIDogJyc7XG4gICAgY29uc3QgZWwgPSB0aGlzLm1lc3NhZ2VzRWwuY3JlYXRlRGl2KHsgY2xzOiBgb2NsYXctbWVzc2FnZSAke21zZy5yb2xlfSR7bGV2ZWxDbGFzc31gIH0pO1xuICAgIGNvbnN0IGJvZHkgPSBlbC5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1tZXNzYWdlLWJvZHknIH0pO1xuXG4gICAgLy8gUmVuZGVyIGFzc2lzdGFudCBtZXNzYWdlcyBhcyBNYXJrZG93biAodW50cnVzdGVkIGNvbnRlbnQgXHUyMTkyIGtlZXAgdXNlci9zeXN0ZW0gcGxhaW4pXG4gICAgaWYgKG1zZy5yb2xlID09PSAnYXNzaXN0YW50Jykge1xuICAgICAgY29uc3Qgc291cmNlUGF0aCA9IHRoaXMuYXBwLndvcmtzcGFjZS5nZXRBY3RpdmVGaWxlKCk/LnBhdGggPz8gJyc7XG4gICAgICB2b2lkIE1hcmtkb3duUmVuZGVyZXIucmVuZGVyTWFya2Rvd24obXNnLmNvbnRlbnQsIGJvZHksIHNvdXJjZVBhdGgsIHRoaXMucGx1Z2luKTtcbiAgICB9IGVsc2Uge1xuICAgICAgYm9keS5zZXRUZXh0KG1zZy5jb250ZW50KTtcbiAgICB9XG5cbiAgICAvLyBTY3JvbGwgdG8gYm90dG9tXG4gICAgdGhpcy5tZXNzYWdlc0VsLnNjcm9sbFRvcCA9IHRoaXMubWVzc2FnZXNFbC5zY3JvbGxIZWlnaHQ7XG4gIH1cblxuICBwcml2YXRlIF91cGRhdGVTZW5kQnV0dG9uKCk6IHZvaWQge1xuICAgIC8vIERpc2Nvbm5lY3RlZDogZGlzYWJsZS5cbiAgICAvLyBXb3JraW5nOiBrZWVwIGVuYWJsZWQgc28gdXNlciBjYW4gc3RvcC9hYm9ydC5cbiAgICBjb25zdCBkaXNhYmxlZCA9ICF0aGlzLmlzQ29ubmVjdGVkO1xuICAgIHRoaXMuc2VuZEJ0bi5kaXNhYmxlZCA9IGRpc2FibGVkO1xuXG4gICAgdGhpcy5zZW5kQnRuLnRvZ2dsZUNsYXNzKCdpcy13b3JraW5nJywgdGhpcy5pc1dvcmtpbmcpO1xuICAgIHRoaXMuc2VuZEJ0bi5zZXRBdHRyKCdhcmlhLWJ1c3knLCB0aGlzLmlzV29ya2luZyA/ICd0cnVlJyA6ICdmYWxzZScpO1xuICAgIHRoaXMuc2VuZEJ0bi5zZXRBdHRyKCdhcmlhLWxhYmVsJywgdGhpcy5pc1dvcmtpbmcgPyAnU3RvcCcgOiAnU2VuZCcpO1xuXG4gICAgaWYgKHRoaXMuaXNXb3JraW5nKSB7XG4gICAgICAvLyBSZXBsYWNlIGJ1dHRvbiBjb250ZW50cyB3aXRoIFN0b3AgaWNvbiArIHNwaW5uZXIgcmluZy5cbiAgICAgIHRoaXMuc2VuZEJ0bi5lbXB0eSgpO1xuICAgICAgY29uc3Qgd3JhcCA9IHRoaXMuc2VuZEJ0bi5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1zdG9wLXdyYXAnIH0pO1xuICAgICAgd3JhcC5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1zcGlubmVyLXJpbmcnLCBhdHRyOiB7ICdhcmlhLWhpZGRlbic6ICd0cnVlJyB9IH0pO1xuICAgICAgd3JhcC5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1zdG9wLWljb24nLCBhdHRyOiB7ICdhcmlhLWhpZGRlbic6ICd0cnVlJyB9IH0pO1xuICAgIH0gZWxzZSB7XG4gICAgICAvLyBSZXN0b3JlIGxhYmVsXG4gICAgICB0aGlzLnNlbmRCdG4uc2V0VGV4dCgnU2VuZCcpO1xuICAgIH1cbiAgfVxuXG4gIC8vIFx1MjUwMFx1MjUwMCBTZW5kIGhhbmRsZXIgXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG5cbiAgcHJpdmF0ZSBhc3luYyBfaGFuZGxlU2VuZCgpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICAvLyBXaGlsZSB3b3JraW5nLCB0aGUgYnV0dG9uIGJlY29tZXMgU3RvcC5cbiAgICBpZiAodGhpcy5pc1dvcmtpbmcpIHtcbiAgICAgIGNvbnN0IG9rID0gYXdhaXQgdGhpcy5wbHVnaW4ud3NDbGllbnQuYWJvcnRBY3RpdmVSdW4oKTtcbiAgICAgIGlmICghb2spIHtcbiAgICAgICAgbmV3IE5vdGljZSgnT3BlbkNsYXcgQ2hhdDogZmFpbGVkIHRvIHN0b3AnKTtcbiAgICAgICAgdGhpcy5jaGF0TWFuYWdlci5hZGRNZXNzYWdlKENoYXRNYW5hZ2VyLmNyZWF0ZVN5c3RlbU1lc3NhZ2UoJ1x1MjZBMCBTdG9wIGZhaWxlZCcsICdlcnJvcicpKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHRoaXMuY2hhdE1hbmFnZXIuYWRkTWVzc2FnZShDaGF0TWFuYWdlci5jcmVhdGVTeXN0ZW1NZXNzYWdlKCdcdTI2RDQgU3RvcHBlZCcsICdpbmZvJykpO1xuICAgICAgfVxuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIGNvbnN0IHRleHQgPSB0aGlzLmlucHV0RWwudmFsdWUudHJpbSgpO1xuICAgIGlmICghdGV4dCkgcmV0dXJuO1xuXG4gICAgLy8gQnVpbGQgbWVzc2FnZSB3aXRoIGNvbnRleHQgaWYgZW5hYmxlZFxuICAgIGxldCBtZXNzYWdlID0gdGV4dDtcbiAgICBpZiAodGhpcy5pbmNsdWRlTm90ZUNoZWNrYm94LmNoZWNrZWQpIHtcbiAgICAgIGNvbnN0IG5vdGUgPSBhd2FpdCBnZXRBY3RpdmVOb3RlQ29udGV4dCh0aGlzLmFwcCk7XG4gICAgICBpZiAobm90ZSkge1xuICAgICAgICBtZXNzYWdlID0gYENvbnRleHQ6IFtbJHtub3RlLnRpdGxlfV1dXFxuXFxuJHt0ZXh0fWA7XG4gICAgICB9XG4gICAgfVxuXG4gICAgLy8gQWRkIHVzZXIgbWVzc2FnZSB0byBjaGF0IFVJXG4gICAgY29uc3QgdXNlck1zZyA9IENoYXRNYW5hZ2VyLmNyZWF0ZVVzZXJNZXNzYWdlKHRleHQpO1xuICAgIHRoaXMuY2hhdE1hbmFnZXIuYWRkTWVzc2FnZSh1c2VyTXNnKTtcblxuICAgIC8vIENsZWFyIGlucHV0XG4gICAgdGhpcy5pbnB1dEVsLnZhbHVlID0gJyc7XG4gICAgdGhpcy5pbnB1dEVsLnN0eWxlLmhlaWdodCA9ICdhdXRvJztcblxuICAgIC8vIFNlbmQgb3ZlciBXUyAoYXN5bmMpXG4gICAgdHJ5IHtcbiAgICAgIGF3YWl0IHRoaXMucGx1Z2luLndzQ2xpZW50LnNlbmRNZXNzYWdlKG1lc3NhZ2UpO1xuICAgIH0gY2F0Y2ggKGVycikge1xuICAgICAgY29uc29sZS5lcnJvcignW29jbGF3XSBTZW5kIGZhaWxlZCcsIGVycik7XG4gICAgICBuZXcgTm90aWNlKGBPcGVuQ2xhdyBDaGF0OiBzZW5kIGZhaWxlZCAoJHtTdHJpbmcoZXJyKX0pYCk7XG4gICAgICB0aGlzLmNoYXRNYW5hZ2VyLmFkZE1lc3NhZ2UoXG4gICAgICAgIENoYXRNYW5hZ2VyLmNyZWF0ZVN5c3RlbU1lc3NhZ2UoYFx1MjZBMCBTZW5kIGZhaWxlZDogJHtlcnJ9YCwgJ2Vycm9yJylcbiAgICAgICk7XG4gICAgfVxuICB9XG59XG4iLCAiaW1wb3J0IHR5cGUgeyBBcHAgfSBmcm9tICdvYnNpZGlhbic7XG5cbmV4cG9ydCBpbnRlcmZhY2UgTm90ZUNvbnRleHQge1xuICB0aXRsZTogc3RyaW5nO1xuICBwYXRoOiBzdHJpbmc7XG4gIGNvbnRlbnQ6IHN0cmluZztcbn1cblxuLyoqXG4gKiBSZXR1cm5zIHRoZSBhY3RpdmUgbm90ZSdzIHRpdGxlIGFuZCBjb250ZW50LCBvciBudWxsIGlmIG5vIG5vdGUgaXMgb3Blbi5cbiAqIEFzeW5jIGJlY2F1c2UgdmF1bHQucmVhZCgpIGlzIGFzeW5jLlxuICovXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZ2V0QWN0aXZlTm90ZUNvbnRleHQoYXBwOiBBcHApOiBQcm9taXNlPE5vdGVDb250ZXh0IHwgbnVsbD4ge1xuICBjb25zdCBmaWxlID0gYXBwLndvcmtzcGFjZS5nZXRBY3RpdmVGaWxlKCk7XG4gIGlmICghZmlsZSkgcmV0dXJuIG51bGw7XG5cbiAgdHJ5IHtcbiAgICBjb25zdCBjb250ZW50ID0gYXdhaXQgYXBwLnZhdWx0LnJlYWQoZmlsZSk7XG4gICAgcmV0dXJuIHtcbiAgICAgIHRpdGxlOiBmaWxlLmJhc2VuYW1lLFxuICAgICAgcGF0aDogZmlsZS5wYXRoLFxuICAgICAgY29udGVudCxcbiAgICB9O1xuICB9IGNhdGNoIChlcnIpIHtcbiAgICBjb25zb2xlLmVycm9yKCdbb2NsYXctY29udGV4dF0gRmFpbGVkIHRvIHJlYWQgYWN0aXZlIG5vdGUnLCBlcnIpO1xuICAgIHJldHVybiBudWxsO1xuICB9XG59XG4iLCAiLyoqIFBlcnNpc3RlZCBwbHVnaW4gY29uZmlndXJhdGlvbiAqL1xuZXhwb3J0IGludGVyZmFjZSBPcGVuQ2xhd1NldHRpbmdzIHtcbiAgLyoqIFdlYlNvY2tldCBVUkwgb2YgdGhlIE9wZW5DbGF3IEdhdGV3YXkgKGUuZy4gd3M6Ly8xMDAuOTAuOS42ODoxODc4OSkgKi9cbiAgZ2F0ZXdheVVybDogc3RyaW5nO1xuICAvKiogQXV0aCB0b2tlbiBcdTIwMTQgbXVzdCBtYXRjaCB0aGUgY2hhbm5lbCBwbHVnaW4ncyBhdXRoVG9rZW4gKi9cbiAgYXV0aFRva2VuOiBzdHJpbmc7XG4gIC8qKiBPcGVuQ2xhdyBzZXNzaW9uIGtleSB0byBzdWJzY3JpYmUgdG8gKGUuZy4gXCJtYWluXCIpICovXG4gIHNlc3Npb25LZXk6IHN0cmluZztcbiAgLyoqIChEZXByZWNhdGVkKSBPcGVuQ2xhdyBhY2NvdW50IElEICh1bnVzZWQ7IGNoYXQuc2VuZCB1c2VzIHNlc3Npb25LZXkpICovXG4gIGFjY291bnRJZDogc3RyaW5nO1xuICAvKiogV2hldGhlciB0byBpbmNsdWRlIHRoZSBhY3RpdmUgbm90ZSBjb250ZW50IHdpdGggZWFjaCBtZXNzYWdlICovXG4gIGluY2x1ZGVBY3RpdmVOb3RlOiBib29sZWFuO1xufVxuXG5leHBvcnQgY29uc3QgREVGQVVMVF9TRVRUSU5HUzogT3BlbkNsYXdTZXR0aW5ncyA9IHtcbiAgZ2F0ZXdheVVybDogJ3dzOi8vbG9jYWxob3N0OjE4Nzg5JyxcbiAgYXV0aFRva2VuOiAnJyxcbiAgc2Vzc2lvbktleTogJ21haW4nLFxuICBhY2NvdW50SWQ6ICdtYWluJyxcbiAgaW5jbHVkZUFjdGl2ZU5vdGU6IGZhbHNlLFxufTtcblxuLyoqIEEgc2luZ2xlIGNoYXQgbWVzc2FnZSAqL1xuZXhwb3J0IGludGVyZmFjZSBDaGF0TWVzc2FnZSB7XG4gIGlkOiBzdHJpbmc7XG4gIHJvbGU6ICd1c2VyJyB8ICdhc3Npc3RhbnQnIHwgJ3N5c3RlbSc7XG4gIC8qKiBPcHRpb25hbCBzZXZlcml0eSBmb3Igc3lzdGVtL3N0YXR1cyBtZXNzYWdlcyAqL1xuICBsZXZlbD86ICdpbmZvJyB8ICdlcnJvcic7XG4gIGNvbnRlbnQ6IHN0cmluZztcbiAgdGltZXN0YW1wOiBudW1iZXI7XG59XG5cbi8qKiBQYXlsb2FkIGZvciBtZXNzYWdlcyBTRU5UIHRvIHRoZSBzZXJ2ZXIgKG91dGJvdW5kKSAqL1xuZXhwb3J0IGludGVyZmFjZSBXU1BheWxvYWQge1xuICB0eXBlOiAnYXV0aCcgfCAnbWVzc2FnZScgfCAncGluZycgfCAncG9uZycgfCAnZXJyb3InO1xuICBwYXlsb2FkPzogUmVjb3JkPHN0cmluZywgdW5rbm93bj47XG59XG5cbi8qKiBNZXNzYWdlcyBSRUNFSVZFRCBmcm9tIHRoZSBzZXJ2ZXIgKGluYm91bmQpIFx1MjAxNCBkaXNjcmltaW5hdGVkIHVuaW9uICovXG5leHBvcnQgdHlwZSBJbmJvdW5kV1NQYXlsb2FkID1cbiAgfCB7IHR5cGU6ICdtZXNzYWdlJzsgcGF5bG9hZDogeyBjb250ZW50OiBzdHJpbmc7IHJvbGU6IHN0cmluZzsgdGltZXN0YW1wOiBudW1iZXIgfSB9XG4gIHwgeyB0eXBlOiAnZXJyb3InOyBwYXlsb2FkOiB7IG1lc3NhZ2U6IHN0cmluZyB9IH07XG5cbi8qKiBBdmFpbGFibGUgYWdlbnRzIC8gbW9kZWxzICovXG5leHBvcnQgaW50ZXJmYWNlIEFnZW50T3B0aW9uIHtcbiAgaWQ6IHN0cmluZztcbiAgbGFiZWw6IHN0cmluZztcbn1cbiJdLAogICJtYXBwaW5ncyI6ICI7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUEsSUFBQUEsbUJBQThDOzs7QUNBOUMsc0JBQStDO0FBR3hDLElBQU0scUJBQU4sY0FBaUMsaUNBQWlCO0FBQUEsRUFHdkQsWUFBWSxLQUFVLFFBQXdCO0FBQzVDLFVBQU0sS0FBSyxNQUFNO0FBQ2pCLFNBQUssU0FBUztBQUFBLEVBQ2hCO0FBQUEsRUFFQSxVQUFnQjtBQUNkLFVBQU0sRUFBRSxZQUFZLElBQUk7QUFDeEIsZ0JBQVksTUFBTTtBQUVsQixnQkFBWSxTQUFTLE1BQU0sRUFBRSxNQUFNLGdDQUEyQixDQUFDO0FBRS9ELFFBQUksd0JBQVEsV0FBVyxFQUNwQixRQUFRLGFBQWEsRUFDckIsUUFBUSxtRUFBbUUsRUFDM0U7QUFBQSxNQUFRLENBQUMsU0FDUixLQUNHLGVBQWUsc0JBQXNCLEVBQ3JDLFNBQVMsS0FBSyxPQUFPLFNBQVMsVUFBVSxFQUN4QyxTQUFTLENBQU8sVUFBVTtBQUN6QixhQUFLLE9BQU8sU0FBUyxhQUFhLE1BQU0sS0FBSztBQUM3Qyxj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
