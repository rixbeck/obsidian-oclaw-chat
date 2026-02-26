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
      var _a, _b, _c, _d, _e;
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
          if (pending.timeout)
            clearTimeout(pending.timeout);
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
          const incomingRunId = String((payload == null ? void 0 : payload.runId) || (payload == null ? void 0 : payload.idempotencyKey) || ((_c = payload == null ? void 0 : payload.meta) == null ? void 0 : _c.runId) || "");
          if (this.activeRunId && incomingRunId && incomingRunId !== this.activeRunId) {
            return;
          }
          if ((payload == null ? void 0 : payload.state) && payload.state !== "final" && payload.state !== "aborted") {
            return;
          }
          const msg = payload == null ? void 0 : payload.message;
          const role = (_d = msg == null ? void 0 : msg.role) != null ? _d : "assistant";
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
          (_e = this.onMessage) == null ? void 0 : _e.call(this, {
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
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsic3JjL21haW4udHMiLCAic3JjL3NldHRpbmdzLnRzIiwgInNyYy93ZWJzb2NrZXQudHMiLCAic3JjL2NoYXQudHMiLCAic3JjL3ZpZXcudHMiLCAic3JjL2NvbnRleHQudHMiLCAic3JjL3R5cGVzLnRzIl0sCiAgInNvdXJjZXNDb250ZW50IjogWyJpbXBvcnQgeyBOb3RpY2UsIFBsdWdpbiwgV29ya3NwYWNlTGVhZiB9IGZyb20gJ29ic2lkaWFuJztcbmltcG9ydCB7IE9wZW5DbGF3U2V0dGluZ1RhYiB9IGZyb20gJy4vc2V0dGluZ3MnO1xuaW1wb3J0IHsgT2JzaWRpYW5XU0NsaWVudCB9IGZyb20gJy4vd2Vic29ja2V0JztcbmltcG9ydCB7IENoYXRNYW5hZ2VyIH0gZnJvbSAnLi9jaGF0JztcbmltcG9ydCB7IFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFULCBPcGVuQ2xhd0NoYXRWaWV3IH0gZnJvbSAnLi92aWV3JztcbmltcG9ydCB7IERFRkFVTFRfU0VUVElOR1MsIHR5cGUgT3BlbkNsYXdTZXR0aW5ncyB9IGZyb20gJy4vdHlwZXMnO1xuXG5leHBvcnQgZGVmYXVsdCBjbGFzcyBPcGVuQ2xhd1BsdWdpbiBleHRlbmRzIFBsdWdpbiB7XG4gIHNldHRpbmdzITogT3BlbkNsYXdTZXR0aW5ncztcbiAgd3NDbGllbnQhOiBPYnNpZGlhbldTQ2xpZW50O1xuICBjaGF0TWFuYWdlciE6IENoYXRNYW5hZ2VyO1xuXG4gIGFzeW5jIG9ubG9hZCgpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBhd2FpdCB0aGlzLmxvYWRTZXR0aW5ncygpO1xuXG4gICAgdGhpcy53c0NsaWVudCA9IG5ldyBPYnNpZGlhbldTQ2xpZW50KHRoaXMuc2V0dGluZ3Muc2Vzc2lvbktleSk7XG4gICAgdGhpcy5jaGF0TWFuYWdlciA9IG5ldyBDaGF0TWFuYWdlcigpO1xuXG4gICAgLy8gV2lyZSBpbmNvbWluZyBXUyBtZXNzYWdlcyBcdTIxOTIgQ2hhdE1hbmFnZXJcbiAgICB0aGlzLndzQ2xpZW50Lm9uTWVzc2FnZSA9IChtc2cpID0+IHtcbiAgICAgIGlmIChtc2cudHlwZSA9PT0gJ21lc3NhZ2UnKSB7XG4gICAgICAgIHRoaXMuY2hhdE1hbmFnZXIuYWRkTWVzc2FnZShDaGF0TWFuYWdlci5jcmVhdGVBc3Npc3RhbnRNZXNzYWdlKG1zZy5wYXlsb2FkLmNvbnRlbnQpKTtcbiAgICAgIH0gZWxzZSBpZiAobXNnLnR5cGUgPT09ICdlcnJvcicpIHtcbiAgICAgICAgY29uc3QgZXJyVGV4dCA9IG1zZy5wYXlsb2FkLm1lc3NhZ2UgPz8gJ1Vua25vd24gZXJyb3IgZnJvbSBnYXRld2F5JztcbiAgICAgICAgdGhpcy5jaGF0TWFuYWdlci5hZGRNZXNzYWdlKENoYXRNYW5hZ2VyLmNyZWF0ZVN5c3RlbU1lc3NhZ2UoYFx1MjZBMCAke2VyclRleHR9YCwgJ2Vycm9yJykpO1xuICAgICAgfVxuICAgIH07XG5cbiAgICAvLyBSZWdpc3RlciB0aGUgc2lkZWJhciB2aWV3XG4gICAgdGhpcy5yZWdpc3RlclZpZXcoXG4gICAgICBWSUVXX1RZUEVfT1BFTkNMQVdfQ0hBVCxcbiAgICAgIChsZWFmOiBXb3Jrc3BhY2VMZWFmKSA9PiBuZXcgT3BlbkNsYXdDaGF0VmlldyhsZWFmLCB0aGlzKVxuICAgICk7XG5cbiAgICAvLyBSaWJib24gaWNvbiBcdTIwMTQgb3BlbnMgLyByZXZlYWxzIHRoZSBjaGF0IHNpZGViYXJcbiAgICB0aGlzLmFkZFJpYmJvbkljb24oJ21lc3NhZ2Utc3F1YXJlJywgJ09wZW5DbGF3IENoYXQnLCAoKSA9PiB7XG4gICAgICB0aGlzLl9hY3RpdmF0ZUNoYXRWaWV3KCk7XG4gICAgfSk7XG5cbiAgICAvLyBTZXR0aW5ncyB0YWJcbiAgICB0aGlzLmFkZFNldHRpbmdUYWIobmV3IE9wZW5DbGF3U2V0dGluZ1RhYih0aGlzLmFwcCwgdGhpcykpO1xuXG4gICAgLy8gQ29tbWFuZCBwYWxldHRlIGVudHJ5XG4gICAgdGhpcy5hZGRDb21tYW5kKHtcbiAgICAgIGlkOiAnb3Blbi1vcGVuY2xhdy1jaGF0JyxcbiAgICAgIG5hbWU6ICdPcGVuIGNoYXQgc2lkZWJhcicsXG4gICAgICBjYWxsYmFjazogKCkgPT4gdGhpcy5fYWN0aXZhdGVDaGF0VmlldygpLFxuICAgIH0pO1xuXG4gICAgLy8gQ29ubmVjdCB0byBnYXRld2F5IGlmIHRva2VuIGlzIGNvbmZpZ3VyZWRcbiAgICBpZiAodGhpcy5zZXR0aW5ncy5hdXRoVG9rZW4pIHtcbiAgICAgIHRoaXMuX2Nvbm5lY3RXUygpO1xuICAgIH0gZWxzZSB7XG4gICAgICBuZXcgTm90aWNlKCdPcGVuQ2xhdyBDaGF0OiBwbGVhc2UgY29uZmlndXJlIHlvdXIgZ2F0ZXdheSB0b2tlbiBpbiBTZXR0aW5ncy4nKTtcbiAgICB9XG5cbiAgICBjb25zb2xlLmxvZygnW29jbGF3XSBQbHVnaW4gbG9hZGVkJyk7XG4gIH1cblxuICBhc3luYyBvbnVubG9hZCgpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICB0aGlzLndzQ2xpZW50LmRpc2Nvbm5lY3QoKTtcbiAgICB0aGlzLmFwcC53b3Jrc3BhY2UuZGV0YWNoTGVhdmVzT2ZUeXBlKFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFUKTtcbiAgICBjb25zb2xlLmxvZygnW29jbGF3XSBQbHVnaW4gdW5sb2FkZWQnKTtcbiAgfVxuXG4gIGFzeW5jIGxvYWRTZXR0aW5ncygpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICB0aGlzLnNldHRpbmdzID0gT2JqZWN0LmFzc2lnbih7fSwgREVGQVVMVF9TRVRUSU5HUywgYXdhaXQgdGhpcy5sb2FkRGF0YSgpKTtcbiAgfVxuXG4gIGFzeW5jIHNhdmVTZXR0aW5ncygpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBhd2FpdCB0aGlzLnNhdmVEYXRhKHRoaXMuc2V0dGluZ3MpO1xuICB9XG5cbiAgLy8gXHUyNTAwXHUyNTAwIEhlbHBlcnMgXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG5cbiAgcHJpdmF0ZSBfY29ubmVjdFdTKCk6IHZvaWQge1xuICAgIHRoaXMud3NDbGllbnQuY29ubmVjdChcbiAgICAgIHRoaXMuc2V0dGluZ3MuZ2F0ZXdheVVybCxcbiAgICAgIHRoaXMuc2V0dGluZ3MuYXV0aFRva2VuXG4gICAgKTtcbiAgfVxuXG4gIHByaXZhdGUgYXN5bmMgX2FjdGl2YXRlQ2hhdFZpZXcoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgY29uc3QgeyB3b3Jrc3BhY2UgfSA9IHRoaXMuYXBwO1xuXG4gICAgLy8gUmV1c2UgZXhpc3RpbmcgbGVhZiBpZiBhbHJlYWR5IG9wZW5cbiAgICBjb25zdCBleGlzdGluZyA9IHdvcmtzcGFjZS5nZXRMZWF2ZXNPZlR5cGUoVklFV19UWVBFX09QRU5DTEFXX0NIQVQpO1xuICAgIGlmIChleGlzdGluZy5sZW5ndGggPiAwKSB7XG4gICAgICB3b3Jrc3BhY2UucmV2ZWFsTGVhZihleGlzdGluZ1swXSk7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgLy8gT3BlbiBpbiByaWdodCBzaWRlYmFyXG4gICAgY29uc3QgbGVhZiA9IHdvcmtzcGFjZS5nZXRSaWdodExlYWYoZmFsc2UpO1xuICAgIGlmICghbGVhZikgcmV0dXJuO1xuICAgIGF3YWl0IGxlYWYuc2V0Vmlld1N0YXRlKHsgdHlwZTogVklFV19UWVBFX09QRU5DTEFXX0NIQVQsIGFjdGl2ZTogdHJ1ZSB9KTtcbiAgICB3b3Jrc3BhY2UucmV2ZWFsTGVhZihsZWFmKTtcbiAgfVxufVxuIiwgImltcG9ydCB7IEFwcCwgUGx1Z2luU2V0dGluZ1RhYiwgU2V0dGluZyB9IGZyb20gJ29ic2lkaWFuJztcbmltcG9ydCB0eXBlIE9wZW5DbGF3UGx1Z2luIGZyb20gJy4vbWFpbic7XG5cbmV4cG9ydCBjbGFzcyBPcGVuQ2xhd1NldHRpbmdUYWIgZXh0ZW5kcyBQbHVnaW5TZXR0aW5nVGFiIHtcbiAgcGx1Z2luOiBPcGVuQ2xhd1BsdWdpbjtcblxuICBjb25zdHJ1Y3RvcihhcHA6IEFwcCwgcGx1Z2luOiBPcGVuQ2xhd1BsdWdpbikge1xuICAgIHN1cGVyKGFwcCwgcGx1Z2luKTtcbiAgICB0aGlzLnBsdWdpbiA9IHBsdWdpbjtcbiAgfVxuXG4gIGRpc3BsYXkoKTogdm9pZCB7XG4gICAgY29uc3QgeyBjb250YWluZXJFbCB9ID0gdGhpcztcbiAgICBjb250YWluZXJFbC5lbXB0eSgpO1xuXG4gICAgY29udGFpbmVyRWwuY3JlYXRlRWwoJ2gyJywgeyB0ZXh0OiAnT3BlbkNsYXcgQ2hhdCBcdTIwMTMgU2V0dGluZ3MnIH0pO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZSgnR2F0ZXdheSBVUkwnKVxuICAgICAgLnNldERlc2MoJ1dlYlNvY2tldCBVUkwgb2YgdGhlIE9wZW5DbGF3IEdhdGV3YXkgKGUuZy4gd3M6Ly9ob3N0bmFtZToxODc4OSkuJylcbiAgICAgIC5hZGRUZXh0KCh0ZXh0KSA9PlxuICAgICAgICB0ZXh0XG4gICAgICAgICAgLnNldFBsYWNlaG9sZGVyKCd3czovL2xvY2FsaG9zdDoxODc4OScpXG4gICAgICAgICAgLnNldFZhbHVlKHRoaXMucGx1Z2luLnNldHRpbmdzLmdhdGV3YXlVcmwpXG4gICAgICAgICAgLm9uQ2hhbmdlKGFzeW5jICh2YWx1ZSkgPT4ge1xuICAgICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3MuZ2F0ZXdheVVybCA9IHZhbHVlLnRyaW0oKTtcbiAgICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICAgIH0pXG4gICAgICApO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZSgnQXV0aCB0b2tlbicpXG4gICAgICAuc2V0RGVzYygnTXVzdCBtYXRjaCB0aGUgYXV0aFRva2VuIGluIHlvdXIgb3BlbmNsYXcuanNvbiBjaGFubmVsIGNvbmZpZy4gTmV2ZXIgc2hhcmVkLicpXG4gICAgICAuYWRkVGV4dCgodGV4dCkgPT4ge1xuICAgICAgICB0ZXh0XG4gICAgICAgICAgLnNldFBsYWNlaG9sZGVyKCdFbnRlciB0b2tlblx1MjAyNicpXG4gICAgICAgICAgLnNldFZhbHVlKHRoaXMucGx1Z2luLnNldHRpbmdzLmF1dGhUb2tlbilcbiAgICAgICAgICAub25DaGFuZ2UoYXN5bmMgKHZhbHVlKSA9PiB7XG4gICAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5hdXRoVG9rZW4gPSB2YWx1ZTtcbiAgICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICAgIH0pO1xuICAgICAgICAvLyBUcmVhdCBhcyBwYXNzd29yZCBmaWVsZCBcdTIwMTMgZG8gbm90IHJldmVhbCB0b2tlbiBpbiBVSVxuICAgICAgICB0ZXh0LmlucHV0RWwudHlwZSA9ICdwYXNzd29yZCc7XG4gICAgICAgIHRleHQuaW5wdXRFbC5hdXRvY29tcGxldGUgPSAnb2ZmJztcbiAgICAgIH0pO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZSgnU2Vzc2lvbiBLZXknKVxuICAgICAgLnNldERlc2MoJ09wZW5DbGF3IHNlc3Npb24gdG8gc3Vic2NyaWJlIHRvICh1c3VhbGx5IFwibWFpblwiKS4nKVxuICAgICAgLmFkZFRleHQoKHRleHQpID0+XG4gICAgICAgIHRleHRcbiAgICAgICAgICAuc2V0UGxhY2Vob2xkZXIoJ21haW4nKVxuICAgICAgICAgIC5zZXRWYWx1ZSh0aGlzLnBsdWdpbi5zZXR0aW5ncy5zZXNzaW9uS2V5KVxuICAgICAgICAgIC5vbkNoYW5nZShhc3luYyAodmFsdWUpID0+IHtcbiAgICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLnNlc3Npb25LZXkgPSB2YWx1ZS50cmltKCkgfHwgJ21haW4nO1xuICAgICAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uc2F2ZVNldHRpbmdzKCk7XG4gICAgICAgICAgfSlcbiAgICAgICk7XG5cbiAgICBuZXcgU2V0dGluZyhjb250YWluZXJFbClcbiAgICAgIC5zZXROYW1lKCdBY2NvdW50IElEJylcbiAgICAgIC5zZXREZXNjKCdPcGVuQ2xhdyBhY2NvdW50IElEICh1c3VhbGx5IFwibWFpblwiKS4nKVxuICAgICAgLmFkZFRleHQoKHRleHQpID0+XG4gICAgICAgIHRleHRcbiAgICAgICAgICAuc2V0UGxhY2Vob2xkZXIoJ21haW4nKVxuICAgICAgICAgIC5zZXRWYWx1ZSh0aGlzLnBsdWdpbi5zZXR0aW5ncy5hY2NvdW50SWQpXG4gICAgICAgICAgLm9uQ2hhbmdlKGFzeW5jICh2YWx1ZSkgPT4ge1xuICAgICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3MuYWNjb3VudElkID0gdmFsdWUudHJpbSgpIHx8ICdtYWluJztcbiAgICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICAgIH0pXG4gICAgICApO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZSgnSW5jbHVkZSBhY3RpdmUgbm90ZSBieSBkZWZhdWx0JylcbiAgICAgIC5zZXREZXNjKCdQcmUtY2hlY2sgXCJJbmNsdWRlIGFjdGl2ZSBub3RlXCIgaW4gdGhlIGNoYXQgcGFuZWwgd2hlbiBpdCBvcGVucy4nKVxuICAgICAgLmFkZFRvZ2dsZSgodG9nZ2xlKSA9PlxuICAgICAgICB0b2dnbGUuc2V0VmFsdWUodGhpcy5wbHVnaW4uc2V0dGluZ3MuaW5jbHVkZUFjdGl2ZU5vdGUpLm9uQ2hhbmdlKGFzeW5jICh2YWx1ZSkgPT4ge1xuICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLmluY2x1ZGVBY3RpdmVOb3RlID0gdmFsdWU7XG4gICAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uc2F2ZVNldHRpbmdzKCk7XG4gICAgICAgIH0pXG4gICAgICApO1xuXG4gICAgY29udGFpbmVyRWwuY3JlYXRlRWwoJ3AnLCB7XG4gICAgICB0ZXh0OiAnUmVjb25uZWN0OiBjbG9zZSBhbmQgcmVvcGVuIHRoZSBzaWRlYmFyIGFmdGVyIGNoYW5naW5nIHRoZSBnYXRld2F5IFVSTCBvciB0b2tlbi4nLFxuICAgICAgY2xzOiAnc2V0dGluZy1pdGVtLWRlc2NyaXB0aW9uJyxcbiAgICB9KTtcbiAgfVxufVxuIiwgIi8qKlxuICogV2ViU29ja2V0IGNsaWVudCBmb3IgT3BlbkNsYXcgR2F0ZXdheVxuICpcbiAqIFBpdm90ICgyMDI2LTAyLTI1KTogRG8gTk9UIHVzZSBjdXN0b20gb2JzaWRpYW4uKiBnYXRld2F5IG1ldGhvZHMuXG4gKiBUaG9zZSByZXF1aXJlIG9wZXJhdG9yLmFkbWluIHNjb3BlIHdoaWNoIGlzIG5vdCBncmFudGVkIHRvIGV4dGVybmFsIGNsaWVudHMuXG4gKlxuICogQXV0aCBub3RlOlxuICogLSBjaGF0LnNlbmQgcmVxdWlyZXMgb3BlcmF0b3Iud3JpdGVcbiAqIC0gZXh0ZXJuYWwgY2xpZW50cyBtdXN0IHByZXNlbnQgYSBwYWlyZWQgZGV2aWNlIGlkZW50aXR5IHRvIHJlY2VpdmUgd3JpdGUgc2NvcGVzXG4gKlxuICogV2UgdXNlIGJ1aWx0LWluIGdhdGV3YXkgbWV0aG9kcy9ldmVudHM6XG4gKiAtIFNlbmQ6IGNoYXQuc2VuZCh7IHNlc3Npb25LZXksIG1lc3NhZ2UsIGlkZW1wb3RlbmN5S2V5LCAuLi4gfSlcbiAqIC0gUmVjZWl2ZTogZXZlbnQgXCJjaGF0XCIgKGZpbHRlciBieSBzZXNzaW9uS2V5KVxuICovXG5cbmltcG9ydCB0eXBlIHsgSW5ib3VuZFdTUGF5bG9hZCB9IGZyb20gJy4vdHlwZXMnO1xuXG4vKiogTWlsbGlzZWNvbmRzIGJlZm9yZSBhIHJlY29ubmVjdCBhdHRlbXB0IGFmdGVyIGFuIHVuZXhwZWN0ZWQgY2xvc2UgKi9cbmNvbnN0IFJFQ09OTkVDVF9ERUxBWV9NUyA9IDNfMDAwO1xuLyoqIEludGVydmFsIGZvciBzZW5kaW5nIGhlYXJ0YmVhdCBwaW5ncyAoY2hlY2sgY29ubmVjdGlvbiBsaXZlbmVzcykgKi9cbmNvbnN0IEhFQVJUQkVBVF9JTlRFUlZBTF9NUyA9IDMwXzAwMDtcblxuLyoqIFNhZmV0eSB2YWx2ZTogaGlkZSB3b3JraW5nIHNwaW5uZXIgaWYgbm8gYXNzaXN0YW50IHJlcGx5IGFycml2ZXMgaW4gdGltZSAqL1xuY29uc3QgV09SS0lOR19NQVhfTVMgPSAxMjBfMDAwO1xuXG5leHBvcnQgdHlwZSBXU0NsaWVudFN0YXRlID0gJ2Rpc2Nvbm5lY3RlZCcgfCAnY29ubmVjdGluZycgfCAnaGFuZHNoYWtpbmcnIHwgJ2Nvbm5lY3RlZCc7XG5cbmV4cG9ydCB0eXBlIFdvcmtpbmdTdGF0ZUxpc3RlbmVyID0gKHdvcmtpbmc6IGJvb2xlYW4pID0+IHZvaWQ7XG5cbmludGVyZmFjZSBQZW5kaW5nUmVxdWVzdCB7XG4gIHJlc29sdmU6IChwYXlsb2FkOiBhbnkpID0+IHZvaWQ7XG4gIHJlamVjdDogKGVycm9yOiBhbnkpID0+IHZvaWQ7XG4gIHRpbWVvdXQ6IFJldHVyblR5cGU8dHlwZW9mIHNldFRpbWVvdXQ+IHwgbnVsbDtcbn1cblxudHlwZSBEZXZpY2VJZGVudGl0eSA9IHtcbiAgaWQ6IHN0cmluZztcbiAgcHVibGljS2V5OiBzdHJpbmc7IC8vIGJhc2U2NFxuICBwcml2YXRlS2V5SndrOiBKc29uV2ViS2V5O1xufTtcblxuY29uc3QgREVWSUNFX1NUT1JBR0VfS0VZID0gJ29wZW5jbGF3Q2hhdC5kZXZpY2VJZGVudGl0eS52MSc7XG5cbmZ1bmN0aW9uIGJhc2U2NFVybEVuY29kZShieXRlczogQXJyYXlCdWZmZXIpOiBzdHJpbmcge1xuICBjb25zdCB1OCA9IG5ldyBVaW50OEFycmF5KGJ5dGVzKTtcbiAgbGV0IHMgPSAnJztcbiAgZm9yIChsZXQgaSA9IDA7IGkgPCB1OC5sZW5ndGg7IGkrKykgcyArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKHU4W2ldKTtcbiAgY29uc3QgYjY0ID0gYnRvYShzKTtcbiAgcmV0dXJuIGI2NC5yZXBsYWNlKC9cXCsvZywgJy0nKS5yZXBsYWNlKC9cXC8vZywgJ18nKS5yZXBsYWNlKC89KyQvZywgJycpO1xufVxuXG5mdW5jdGlvbiBoZXhFbmNvZGUoYnl0ZXM6IEFycmF5QnVmZmVyKTogc3RyaW5nIHtcbiAgY29uc3QgdTggPSBuZXcgVWludDhBcnJheShieXRlcyk7XG4gIHJldHVybiBBcnJheS5mcm9tKHU4KVxuICAgIC5tYXAoKGIpID0+IGIudG9TdHJpbmcoMTYpLnBhZFN0YXJ0KDIsICcwJykpXG4gICAgLmpvaW4oJycpO1xufVxuXG5mdW5jdGlvbiB1dGY4Qnl0ZXModGV4dDogc3RyaW5nKTogVWludDhBcnJheSB7XG4gIHJldHVybiBuZXcgVGV4dEVuY29kZXIoKS5lbmNvZGUodGV4dCk7XG59XG5cbmFzeW5jIGZ1bmN0aW9uIHNoYTI1NkhleChieXRlczogQXJyYXlCdWZmZXIpOiBQcm9taXNlPHN0cmluZz4ge1xuICBjb25zdCBkaWdlc3QgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmRpZ2VzdCgnU0hBLTI1NicsIGJ5dGVzKTtcbiAgcmV0dXJuIGhleEVuY29kZShkaWdlc3QpO1xufVxuXG5hc3luYyBmdW5jdGlvbiBsb2FkT3JDcmVhdGVEZXZpY2VJZGVudGl0eSgpOiBQcm9taXNlPERldmljZUlkZW50aXR5PiB7XG4gIGNvbnN0IGV4aXN0aW5nID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oREVWSUNFX1NUT1JBR0VfS0VZKTtcbiAgaWYgKGV4aXN0aW5nKSB7XG4gICAgY29uc3QgcGFyc2VkID0gSlNPTi5wYXJzZShleGlzdGluZykgYXMgRGV2aWNlSWRlbnRpdHk7XG4gICAgaWYgKHBhcnNlZD8uaWQgJiYgcGFyc2VkPy5wdWJsaWNLZXkgJiYgcGFyc2VkPy5wcml2YXRlS2V5SndrKSByZXR1cm4gcGFyc2VkO1xuICB9XG5cbiAgY29uc3Qga2V5UGFpciA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuZ2VuZXJhdGVLZXkoeyBuYW1lOiAnRWQyNTUxOScgfSwgdHJ1ZSwgWydzaWduJywgJ3ZlcmlmeSddKTtcbiAgY29uc3QgcHViUmF3ID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5leHBvcnRLZXkoJ3JhdycsIGtleVBhaXIucHVibGljS2V5KTtcbiAgY29uc3QgcHJpdkp3ayA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuZXhwb3J0S2V5KCdqd2snLCBrZXlQYWlyLnByaXZhdGVLZXkpO1xuXG4gIC8vIElNUE9SVEFOVDogZGV2aWNlLmlkIG11c3QgYmUgYSBzdGFibGUgZmluZ2VycHJpbnQgZm9yIHRoZSBwdWJsaWMga2V5LlxuICAvLyBUaGUgZ2F0ZXdheSBlbmZvcmNlcyBkZXZpY2VJZCBcdTIxOTQgcHVibGljS2V5IGJpbmRpbmc7IHJhbmRvbSBpZHMgY2FuIGNhdXNlIFwiZGV2aWNlIGlkZW50aXR5IG1pc21hdGNoXCIuXG4gIGNvbnN0IGRldmljZUlkID0gYXdhaXQgc2hhMjU2SGV4KHB1YlJhdyk7XG4gIGNvbnN0IGlkID0gZGV2aWNlSWQ7XG5cbiAgY29uc3QgaWRlbnRpdHk6IERldmljZUlkZW50aXR5ID0ge1xuICAgIGlkLFxuICAgIHB1YmxpY0tleTogYmFzZTY0VXJsRW5jb2RlKHB1YlJhdyksXG4gICAgcHJpdmF0ZUtleUp3azogcHJpdkp3ayxcbiAgfTtcblxuICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbShERVZJQ0VfU1RPUkFHRV9LRVksIEpTT04uc3RyaW5naWZ5KGlkZW50aXR5KSk7XG4gIHJldHVybiBpZGVudGl0eTtcbn1cblxuZnVuY3Rpb24gYnVpbGREZXZpY2VBdXRoUGF5bG9hZChwYXJhbXM6IHtcbiAgZGV2aWNlSWQ6IHN0cmluZztcbiAgY2xpZW50SWQ6IHN0cmluZztcbiAgY2xpZW50TW9kZTogc3RyaW5nO1xuICByb2xlOiBzdHJpbmc7XG4gIHNjb3Blczogc3RyaW5nW107XG4gIHNpZ25lZEF0TXM6IG51bWJlcjtcbiAgdG9rZW46IHN0cmluZztcbiAgbm9uY2U/OiBzdHJpbmc7XG59KTogc3RyaW5nIHtcbiAgY29uc3QgdmVyc2lvbiA9IHBhcmFtcy5ub25jZSA/ICd2MicgOiAndjEnO1xuICBjb25zdCBzY29wZXMgPSBwYXJhbXMuc2NvcGVzLmpvaW4oJywnKTtcbiAgY29uc3QgYmFzZSA9IFtcbiAgICB2ZXJzaW9uLFxuICAgIHBhcmFtcy5kZXZpY2VJZCxcbiAgICBwYXJhbXMuY2xpZW50SWQsXG4gICAgcGFyYW1zLmNsaWVudE1vZGUsXG4gICAgcGFyYW1zLnJvbGUsXG4gICAgc2NvcGVzLFxuICAgIFN0cmluZyhwYXJhbXMuc2lnbmVkQXRNcyksXG4gICAgcGFyYW1zLnRva2VuIHx8ICcnLFxuICBdO1xuICBpZiAodmVyc2lvbiA9PT0gJ3YyJykgYmFzZS5wdXNoKHBhcmFtcy5ub25jZSB8fCAnJyk7XG4gIHJldHVybiBiYXNlLmpvaW4oJ3wnKTtcbn1cblxuYXN5bmMgZnVuY3Rpb24gc2lnbkRldmljZVBheWxvYWQoaWRlbnRpdHk6IERldmljZUlkZW50aXR5LCBwYXlsb2FkOiBzdHJpbmcpOiBQcm9taXNlPHsgc2lnbmF0dXJlOiBzdHJpbmc7IHNpZ25lZEF0OiBudW1iZXIgfT4ge1xuICBjb25zdCBwcml2YXRlS2V5ID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5pbXBvcnRLZXkoXG4gICAgJ2p3aycsXG4gICAgaWRlbnRpdHkucHJpdmF0ZUtleUp3ayxcbiAgICB7IG5hbWU6ICdFZDI1NTE5JyB9LFxuICAgIGZhbHNlLFxuICAgIFsnc2lnbiddLFxuICApO1xuXG4gIGNvbnN0IHNpZ25lZEF0ID0gRGF0ZS5ub3coKTtcbiAgY29uc3Qgc2lnID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5zaWduKHsgbmFtZTogJ0VkMjU1MTknIH0sIHByaXZhdGVLZXksIHV0ZjhCeXRlcyhwYXlsb2FkKSBhcyB1bmtub3duIGFzIEJ1ZmZlclNvdXJjZSk7XG4gIHJldHVybiB7IHNpZ25hdHVyZTogYmFzZTY0VXJsRW5jb2RlKHNpZyksIHNpZ25lZEF0IH07XG59XG5cbmZ1bmN0aW9uIGV4dHJhY3RUZXh0RnJvbUdhdGV3YXlNZXNzYWdlKG1zZzogYW55KTogc3RyaW5nIHtcbiAgaWYgKCFtc2cpIHJldHVybiAnJztcblxuICAvLyBNb3N0IGNvbW1vbjogeyByb2xlLCBjb250ZW50IH0gd2hlcmUgY29udGVudCBjYW4gYmUgc3RyaW5nIG9yIFt7dHlwZTondGV4dCcsdGV4dDonLi4uJ31dXG4gIGNvbnN0IGNvbnRlbnQgPSBtc2cuY29udGVudCA/PyBtc2cubWVzc2FnZSA/PyBtc2c7XG4gIGlmICh0eXBlb2YgY29udGVudCA9PT0gJ3N0cmluZycpIHJldHVybiBjb250ZW50O1xuXG4gIGlmIChBcnJheS5pc0FycmF5KGNvbnRlbnQpKSB7XG4gICAgY29uc3QgcGFydHMgPSBjb250ZW50XG4gICAgICAuZmlsdGVyKChjKSA9PiBjICYmIHR5cGVvZiBjID09PSAnb2JqZWN0JyAmJiBjLnR5cGUgPT09ICd0ZXh0JyAmJiB0eXBlb2YgYy50ZXh0ID09PSAnc3RyaW5nJylcbiAgICAgIC5tYXAoKGMpID0+IGMudGV4dCk7XG4gICAgcmV0dXJuIHBhcnRzLmpvaW4oJ1xcbicpO1xuICB9XG5cbiAgLy8gRmFsbGJhY2tcbiAgdHJ5IHtcbiAgICByZXR1cm4gSlNPTi5zdHJpbmdpZnkoY29udGVudCk7XG4gIH0gY2F0Y2gge1xuICAgIHJldHVybiBTdHJpbmcoY29udGVudCk7XG4gIH1cbn1cblxuZnVuY3Rpb24gc2Vzc2lvbktleU1hdGNoZXMoY29uZmlndXJlZDogc3RyaW5nLCBpbmNvbWluZzogc3RyaW5nKTogYm9vbGVhbiB7XG4gIGlmIChpbmNvbWluZyA9PT0gY29uZmlndXJlZCkgcmV0dXJuIHRydWU7XG4gIC8vIE9wZW5DbGF3IHJlc29sdmVzIFwibWFpblwiIHRvIGNhbm9uaWNhbCBzZXNzaW9uIGtleSBsaWtlIFwiYWdlbnQ6bWFpbjptYWluXCIuXG4gIGlmIChjb25maWd1cmVkID09PSAnbWFpbicgJiYgaW5jb21pbmcgPT09ICdhZ2VudDptYWluOm1haW4nKSByZXR1cm4gdHJ1ZTtcbiAgcmV0dXJuIGZhbHNlO1xufVxuXG5leHBvcnQgY2xhc3MgT2JzaWRpYW5XU0NsaWVudCB7XG4gIHByaXZhdGUgd3M6IFdlYlNvY2tldCB8IG51bGwgPSBudWxsO1xuICBwcml2YXRlIHJlY29ubmVjdFRpbWVyOiBSZXR1cm5UeXBlPHR5cGVvZiBzZXRUaW1lb3V0PiB8IG51bGwgPSBudWxsO1xuICBwcml2YXRlIGhlYXJ0YmVhdFRpbWVyOiBSZXR1cm5UeXBlPHR5cGVvZiBzZXRJbnRlcnZhbD4gfCBudWxsID0gbnVsbDtcbiAgcHJpdmF0ZSB3b3JraW5nVGltZXI6IFJldHVyblR5cGU8dHlwZW9mIHNldFRpbWVvdXQ+IHwgbnVsbCA9IG51bGw7XG4gIHByaXZhdGUgaW50ZW50aW9uYWxDbG9zZSA9IGZhbHNlO1xuICBwcml2YXRlIHNlc3Npb25LZXk6IHN0cmluZztcbiAgcHJpdmF0ZSB1cmwgPSAnJztcbiAgcHJpdmF0ZSB0b2tlbiA9ICcnO1xuICBwcml2YXRlIHJlcXVlc3RJZCA9IDA7XG4gIHByaXZhdGUgcGVuZGluZ1JlcXVlc3RzID0gbmV3IE1hcDxzdHJpbmcsIFBlbmRpbmdSZXF1ZXN0PigpO1xuICBwcml2YXRlIHdvcmtpbmcgPSBmYWxzZTtcblxuICAvKiogVGhlIGxhc3QgaW4tZmxpZ2h0IGNoYXQgcnVuIGlkLiBJbiBPcGVuQ2xhdyBXZWJDaGF0IHRoaXMgbWFwcyB0byBjaGF0LnNlbmQgaWRlbXBvdGVuY3lLZXkuICovXG4gIHByaXZhdGUgYWN0aXZlUnVuSWQ6IHN0cmluZyB8IG51bGwgPSBudWxsO1xuXG4gIC8qKiBQcmV2ZW50cyBhYm9ydCBzcGFtbWluZzogd2hpbGUgYW4gYWJvcnQgcmVxdWVzdCBpcyBpbi1mbGlnaHQsIHJldXNlIHRoZSBzYW1lIHByb21pc2UuICovXG4gIHByaXZhdGUgYWJvcnRJbkZsaWdodDogUHJvbWlzZTxib29sZWFuPiB8IG51bGwgPSBudWxsO1xuXG4gIHN0YXRlOiBXU0NsaWVudFN0YXRlID0gJ2Rpc2Nvbm5lY3RlZCc7XG5cbiAgb25NZXNzYWdlOiAoKG1zZzogSW5ib3VuZFdTUGF5bG9hZCkgPT4gdm9pZCkgfCBudWxsID0gbnVsbDtcbiAgb25TdGF0ZUNoYW5nZTogKChzdGF0ZTogV1NDbGllbnRTdGF0ZSkgPT4gdm9pZCkgfCBudWxsID0gbnVsbDtcbiAgb25Xb3JraW5nQ2hhbmdlOiBXb3JraW5nU3RhdGVMaXN0ZW5lciB8IG51bGwgPSBudWxsO1xuXG4gIGNvbnN0cnVjdG9yKHNlc3Npb25LZXk6IHN0cmluZykge1xuICAgIHRoaXMuc2Vzc2lvbktleSA9IHNlc3Npb25LZXk7XG4gIH1cblxuICBjb25uZWN0KHVybDogc3RyaW5nLCB0b2tlbjogc3RyaW5nKTogdm9pZCB7XG4gICAgdGhpcy51cmwgPSB1cmw7XG4gICAgdGhpcy50b2tlbiA9IHRva2VuO1xuICAgIHRoaXMuaW50ZW50aW9uYWxDbG9zZSA9IGZhbHNlO1xuICAgIHRoaXMuX2Nvbm5lY3QoKTtcbiAgfVxuXG4gIGRpc2Nvbm5lY3QoKTogdm9pZCB7XG4gICAgdGhpcy5pbnRlbnRpb25hbENsb3NlID0gdHJ1ZTtcbiAgICB0aGlzLl9zdG9wVGltZXJzKCk7XG4gICAgdGhpcy5hY3RpdmVSdW5JZCA9IG51bGw7XG4gICAgdGhpcy5fc2V0V29ya2luZyhmYWxzZSk7XG4gICAgaWYgKHRoaXMud3MpIHtcbiAgICAgIHRoaXMud3MuY2xvc2UoKTtcbiAgICAgIHRoaXMud3MgPSBudWxsO1xuICAgIH1cbiAgICB0aGlzLl9zZXRTdGF0ZSgnZGlzY29ubmVjdGVkJyk7XG4gIH1cblxuICBhc3luYyBzZW5kTWVzc2FnZShtZXNzYWdlOiBzdHJpbmcpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBpZiAodGhpcy5zdGF0ZSAhPT0gJ2Nvbm5lY3RlZCcpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcignTm90IGNvbm5lY3RlZCBcdTIwMTQgY2FsbCBjb25uZWN0KCkgZmlyc3QnKTtcbiAgICB9XG5cbiAgICBjb25zdCBydW5JZCA9IGBvYnNpZGlhbi0ke0RhdGUubm93KCl9LSR7TWF0aC5yYW5kb20oKS50b1N0cmluZygzNikuc2xpY2UoMiwgOSl9YDtcblxuICAgIC8vIFNob3cgXHUyMDFDd29ya2luZ1x1MjAxRCBPTkxZIGFmdGVyIHRoZSBnYXRld2F5IGFja25vd2xlZGdlcyB0aGUgcmVxdWVzdC5cbiAgICBhd2FpdCB0aGlzLl9zZW5kUmVxdWVzdCgnY2hhdC5zZW5kJywge1xuICAgICAgc2Vzc2lvbktleTogdGhpcy5zZXNzaW9uS2V5LFxuICAgICAgbWVzc2FnZSxcbiAgICAgIGlkZW1wb3RlbmN5S2V5OiBydW5JZCxcbiAgICAgIC8vIGRlbGl2ZXIgZGVmYXVsdHMgdG8gdHJ1ZSBpbiBnYXRld2F5OyBrZWVwIGRlZmF1bHRcbiAgICB9KTtcblxuICAgIHRoaXMuYWN0aXZlUnVuSWQgPSBydW5JZDtcbiAgICB0aGlzLl9zZXRXb3JraW5nKHRydWUpO1xuICAgIHRoaXMuX2FybVdvcmtpbmdTYWZldHlUaW1lb3V0KCk7XG4gIH1cblxuICAvKiogQWJvcnQgdGhlIGFjdGl2ZSBydW4gZm9yIHRoaXMgc2Vzc2lvbiAoYW5kIG91ciBsYXN0IHJ1biBpZCBpZiBwcmVzZW50KS4gKi9cbiAgYXN5bmMgYWJvcnRBY3RpdmVSdW4oKTogUHJvbWlzZTxib29sZWFuPiB7XG4gICAgaWYgKHRoaXMuc3RhdGUgIT09ICdjb25uZWN0ZWQnKSB7XG4gICAgICByZXR1cm4gZmFsc2U7XG4gICAgfVxuXG4gICAgLy8gUHJldmVudCByZXF1ZXN0IHN0b3Jtczogd2hpbGUgb25lIGFib3J0IGlzIGluIGZsaWdodCwgcmV1c2UgaXQuXG4gICAgaWYgKHRoaXMuYWJvcnRJbkZsaWdodCkge1xuICAgICAgcmV0dXJuIHRoaXMuYWJvcnRJbkZsaWdodDtcbiAgICB9XG5cbiAgICBjb25zdCBydW5JZCA9IHRoaXMuYWN0aXZlUnVuSWQ7XG5cbiAgICB0aGlzLmFib3J0SW5GbGlnaHQgPSAoYXN5bmMgKCkgPT4ge1xuICAgICAgdHJ5IHtcbiAgICAgICAgYXdhaXQgdGhpcy5fc2VuZFJlcXVlc3QoJ2NoYXQuYWJvcnQnLCBydW5JZCA/IHsgc2Vzc2lvbktleTogdGhpcy5zZXNzaW9uS2V5LCBydW5JZCB9IDogeyBzZXNzaW9uS2V5OiB0aGlzLnNlc3Npb25LZXkgfSk7XG4gICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgfSBjYXRjaCAoZXJyKSB7XG4gICAgICAgIGNvbnNvbGUuZXJyb3IoJ1tvY2xhdy13c10gY2hhdC5hYm9ydCBmYWlsZWQnLCBlcnIpO1xuICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICB9IGZpbmFsbHkge1xuICAgICAgICAvLyBBbHdheXMgcmVzdG9yZSBVSSBzdGF0ZSBpbW1lZGlhdGVseTsgdGhlIGdhdGV3YXkgbWF5IHN0aWxsIGVtaXQgYW4gYWJvcnRlZCBldmVudCBsYXRlci5cbiAgICAgICAgdGhpcy5hY3RpdmVSdW5JZCA9IG51bGw7XG4gICAgICAgIHRoaXMuX3NldFdvcmtpbmcoZmFsc2UpO1xuICAgICAgICB0aGlzLmFib3J0SW5GbGlnaHQgPSBudWxsO1xuICAgICAgfVxuICAgIH0pKCk7XG5cbiAgICByZXR1cm4gdGhpcy5hYm9ydEluRmxpZ2h0O1xuICB9XG5cbiAgcHJpdmF0ZSBfY29ubmVjdCgpOiB2b2lkIHtcbiAgICBpZiAodGhpcy53cykge1xuICAgICAgdGhpcy53cy5vbm9wZW4gPSBudWxsO1xuICAgICAgdGhpcy53cy5vbmNsb3NlID0gbnVsbDtcbiAgICAgIHRoaXMud3Mub25tZXNzYWdlID0gbnVsbDtcbiAgICAgIHRoaXMud3Mub25lcnJvciA9IG51bGw7XG4gICAgICB0aGlzLndzLmNsb3NlKCk7XG4gICAgICB0aGlzLndzID0gbnVsbDtcbiAgICB9XG5cbiAgICB0aGlzLl9zZXRTdGF0ZSgnY29ubmVjdGluZycpO1xuXG4gICAgY29uc3Qgd3MgPSBuZXcgV2ViU29ja2V0KHRoaXMudXJsKTtcbiAgICB0aGlzLndzID0gd3M7XG5cbiAgICBsZXQgY29ubmVjdE5vbmNlOiBzdHJpbmcgfCBudWxsID0gbnVsbDtcbiAgICBsZXQgY29ubmVjdFN0YXJ0ZWQgPSBmYWxzZTtcblxuICAgIGNvbnN0IHRyeUNvbm5lY3QgPSBhc3luYyAoKSA9PiB7XG4gICAgICBpZiAoY29ubmVjdFN0YXJ0ZWQpIHJldHVybjtcbiAgICAgIGlmICghY29ubmVjdE5vbmNlKSByZXR1cm47XG4gICAgICBjb25uZWN0U3RhcnRlZCA9IHRydWU7XG5cbiAgICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IGlkZW50aXR5ID0gYXdhaXQgbG9hZE9yQ3JlYXRlRGV2aWNlSWRlbnRpdHkoKTtcbiAgICAgICAgY29uc3Qgc2lnbmVkQXRNcyA9IERhdGUubm93KCk7XG4gICAgICAgIGNvbnN0IHBheWxvYWQgPSBidWlsZERldmljZUF1dGhQYXlsb2FkKHtcbiAgICAgICAgICBkZXZpY2VJZDogaWRlbnRpdHkuaWQsXG4gICAgICAgICAgY2xpZW50SWQ6ICdnYXRld2F5LWNsaWVudCcsXG4gICAgICAgICAgY2xpZW50TW9kZTogJ2JhY2tlbmQnLFxuICAgICAgICAgIHJvbGU6ICdvcGVyYXRvcicsXG4gICAgICAgICAgc2NvcGVzOiBbJ29wZXJhdG9yLnJlYWQnLCAnb3BlcmF0b3Iud3JpdGUnXSxcbiAgICAgICAgICBzaWduZWRBdE1zLFxuICAgICAgICAgIHRva2VuOiB0aGlzLnRva2VuLFxuICAgICAgICAgIG5vbmNlOiBjb25uZWN0Tm9uY2UsXG4gICAgICAgIH0pO1xuICAgICAgICBjb25zdCBzaWcgPSBhd2FpdCBzaWduRGV2aWNlUGF5bG9hZChpZGVudGl0eSwgcGF5bG9hZCk7XG5cbiAgICAgICAgYXdhaXQgdGhpcy5fc2VuZFJlcXVlc3QoJ2Nvbm5lY3QnLCB7XG4gICAgICAgICAgbWluUHJvdG9jb2w6IDMsXG4gICAgICAgICAgbWF4UHJvdG9jb2w6IDMsXG4gICAgICAgICAgY2xpZW50OiB7XG4gICAgICAgICAgICBpZDogJ2dhdGV3YXktY2xpZW50JyxcbiAgICAgICAgICAgIG1vZGU6ICdiYWNrZW5kJyxcbiAgICAgICAgICAgIHZlcnNpb246ICcwLjEuMTAnLFxuICAgICAgICAgICAgcGxhdGZvcm06ICdlbGVjdHJvbicsXG4gICAgICAgICAgfSxcbiAgICAgICAgICByb2xlOiAnb3BlcmF0b3InLFxuICAgICAgICAgIHNjb3BlczogWydvcGVyYXRvci5yZWFkJywgJ29wZXJhdG9yLndyaXRlJ10sXG4gICAgICAgICAgZGV2aWNlOiB7XG4gICAgICAgICAgICBpZDogaWRlbnRpdHkuaWQsXG4gICAgICAgICAgICBwdWJsaWNLZXk6IGlkZW50aXR5LnB1YmxpY0tleSxcbiAgICAgICAgICAgIHNpZ25hdHVyZTogc2lnLnNpZ25hdHVyZSxcbiAgICAgICAgICAgIHNpZ25lZEF0OiBzaWduZWRBdE1zLFxuICAgICAgICAgICAgbm9uY2U6IGNvbm5lY3ROb25jZSxcbiAgICAgICAgICB9LFxuICAgICAgICAgIGF1dGg6IHtcbiAgICAgICAgICAgIHRva2VuOiB0aGlzLnRva2VuLFxuICAgICAgICAgIH0sXG4gICAgICAgIH0pO1xuXG4gICAgICAgIHRoaXMuX3NldFN0YXRlKCdjb25uZWN0ZWQnKTtcbiAgICAgICAgdGhpcy5fc3RhcnRIZWFydGJlYXQoKTtcbiAgICAgIH0gY2F0Y2ggKGVycikge1xuICAgICAgICBjb25zb2xlLmVycm9yKCdbb2NsYXctd3NdIENvbm5lY3QgaGFuZHNoYWtlIGZhaWxlZCcsIGVycik7XG4gICAgICAgIHdzLmNsb3NlKCk7XG4gICAgICB9XG4gICAgfTtcblxuICAgIHdzLm9ub3BlbiA9ICgpID0+IHtcbiAgICAgIHRoaXMuX3NldFN0YXRlKCdoYW5kc2hha2luZycpO1xuICAgICAgLy8gVGhlIGdhdGV3YXkgd2lsbCBzZW5kIGNvbm5lY3QuY2hhbGxlbmdlOyBjb25uZWN0IGlzIHNlbnQgb25jZSB3ZSBoYXZlIGEgbm9uY2UuXG4gICAgfTtcblxuICAgIHdzLm9ubWVzc2FnZSA9IChldmVudDogTWVzc2FnZUV2ZW50KSA9PiB7XG4gICAgICBsZXQgZnJhbWU6IGFueTtcbiAgICAgIHRyeSB7XG4gICAgICAgIGZyYW1lID0gSlNPTi5wYXJzZShldmVudC5kYXRhIGFzIHN0cmluZyk7XG4gICAgICB9IGNhdGNoIHtcbiAgICAgICAgY29uc29sZS5lcnJvcignW29jbGF3LXdzXSBGYWlsZWQgdG8gcGFyc2UgaW5jb21pbmcgbWVzc2FnZScpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG5cbiAgICAgIC8vIFJlc3BvbnNlc1xuICAgICAgaWYgKGZyYW1lLnR5cGUgPT09ICdyZXMnKSB7XG4gICAgICAgIGNvbnN0IHBlbmRpbmcgPSB0aGlzLnBlbmRpbmdSZXF1ZXN0cy5nZXQoZnJhbWUuaWQpO1xuICAgICAgICBpZiAocGVuZGluZykge1xuICAgICAgICAgIHRoaXMucGVuZGluZ1JlcXVlc3RzLmRlbGV0ZShmcmFtZS5pZCk7XG4gICAgICAgICAgaWYgKHBlbmRpbmcudGltZW91dCkgY2xlYXJUaW1lb3V0KHBlbmRpbmcudGltZW91dCk7XG4gICAgICAgICAgaWYgKGZyYW1lLm9rKSBwZW5kaW5nLnJlc29sdmUoZnJhbWUucGF5bG9hZCk7XG4gICAgICAgICAgZWxzZSBwZW5kaW5nLnJlamVjdChuZXcgRXJyb3IoZnJhbWUuZXJyb3I/Lm1lc3NhZ2UgfHwgJ1JlcXVlc3QgZmFpbGVkJykpO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cblxuICAgICAgLy8gRXZlbnRzXG4gICAgICBpZiAoZnJhbWUudHlwZSA9PT0gJ2V2ZW50Jykge1xuICAgICAgICBpZiAoZnJhbWUuZXZlbnQgPT09ICdjb25uZWN0LmNoYWxsZW5nZScpIHtcbiAgICAgICAgICBjb25uZWN0Tm9uY2UgPSBmcmFtZS5wYXlsb2FkPy5ub25jZSB8fCBudWxsO1xuICAgICAgICAgIC8vIEF0dGVtcHQgaGFuZHNoYWtlIG9uY2Ugd2UgaGF2ZSBhIG5vbmNlLlxuICAgICAgICAgIHZvaWQgdHJ5Q29ubmVjdCgpO1xuICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmIChmcmFtZS5ldmVudCA9PT0gJ2NoYXQnKSB7XG4gICAgICAgICAgY29uc3QgcGF5bG9hZCA9IGZyYW1lLnBheWxvYWQ7XG4gICAgICAgICAgY29uc3QgaW5jb21pbmdTZXNzaW9uS2V5ID0gU3RyaW5nKHBheWxvYWQ/LnNlc3Npb25LZXkgfHwgJycpO1xuICAgICAgICAgIGlmICghaW5jb21pbmdTZXNzaW9uS2V5IHx8ICFzZXNzaW9uS2V5TWF0Y2hlcyh0aGlzLnNlc3Npb25LZXksIGluY29taW5nU2Vzc2lvbktleSkpIHtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICAvLyBCZXN0LWVmZm9ydCBydW4gY29ycmVsYXRpb24gKGlmIGdhdGV3YXkgaW5jbHVkZXMgYSBydW4gaWQpLiBUaGlzIGF2b2lkcyBjbGVhcmluZyBvdXIgVUlcbiAgICAgICAgICAvLyBiYXNlZCBvbiBhIGRpZmZlcmVudCBjbGllbnQncyBydW4gaW4gdGhlIHNhbWUgc2Vzc2lvbi5cbiAgICAgICAgICBjb25zdCBpbmNvbWluZ1J1bklkID0gU3RyaW5nKHBheWxvYWQ/LnJ1bklkIHx8IHBheWxvYWQ/LmlkZW1wb3RlbmN5S2V5IHx8IHBheWxvYWQ/Lm1ldGE/LnJ1bklkIHx8ICcnKTtcbiAgICAgICAgICBpZiAodGhpcy5hY3RpdmVSdW5JZCAmJiBpbmNvbWluZ1J1bklkICYmIGluY29taW5nUnVuSWQgIT09IHRoaXMuYWN0aXZlUnVuSWQpIHtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICAvLyBBdm9pZCBkb3VibGUtcmVuZGVyOiBnYXRld2F5IGVtaXRzIGRlbHRhICsgZmluYWwgKyBhYm9ydGVkLiBSZW5kZXIgb25seSBmaW5hbC9hYm9ydGVkLlxuICAgICAgICAgIGlmIChwYXlsb2FkPy5zdGF0ZSAmJiBwYXlsb2FkLnN0YXRlICE9PSAnZmluYWwnICYmIHBheWxvYWQuc3RhdGUgIT09ICdhYm9ydGVkJykge1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIC8vIFdlIG9ubHkgYXBwZW5kIGFzc2lzdGFudCBvdXRwdXQgdG8gVUkuXG4gICAgICAgICAgY29uc3QgbXNnID0gcGF5bG9hZD8ubWVzc2FnZTtcbiAgICAgICAgICBjb25zdCByb2xlID0gbXNnPy5yb2xlID8/ICdhc3Npc3RhbnQnO1xuXG4gICAgICAgICAgLy8gQm90aCBmaW5hbCBhbmQgYWJvcnRlZCByZXNvbHZlIFwid29ya2luZ1wiLlxuICAgICAgICAgIHRoaXMuYWN0aXZlUnVuSWQgPSBudWxsO1xuICAgICAgICAgIHRoaXMuX3NldFdvcmtpbmcoZmFsc2UpO1xuXG4gICAgICAgICAgLy8gQWJvcnRlZCBtYXkgaGF2ZSBubyBhc3Npc3RhbnQgbWVzc2FnZSBvciBtYXkgY2FycnkgcGFydGlhbCBhc3Npc3RhbnQgY29udGVudC5cbiAgICAgICAgICBpZiAocGF5bG9hZD8uc3RhdGUgPT09ICdhYm9ydGVkJykge1xuICAgICAgICAgICAgLy8gSWYgdGhlcmUncyBubyB1c2FibGUgYXNzaXN0YW50IHBheWxvYWQsIGp1c3QgZG9uJ3QgYXBwZW5kIGFueXRoaW5nLlxuICAgICAgICAgICAgLy8gKFZpZXcgbGF5ZXIgbWF5IG9wdGlvbmFsbHkgYWRkIGEgc3lzdGVtIG1lc3NhZ2Ugb24gc3VjY2Vzc2Z1bCBzdG9wLilcbiAgICAgICAgICAgIGlmICghbXNnKSByZXR1cm47XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgaWYgKHJvbGUgIT09ICdhc3Npc3RhbnQnKSB7XG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgY29uc3QgdGV4dCA9IGV4dHJhY3RUZXh0RnJvbUdhdGV3YXlNZXNzYWdlKG1zZyk7XG4gICAgICAgICAgaWYgKCF0ZXh0KSByZXR1cm47XG5cbiAgICAgICAgICAvLyBPcHRpb25hbDogaGlkZSBoZWFydGJlYXQgYWNrcyAobm9pc2UgaW4gVUkpXG4gICAgICAgICAgaWYgKHRleHQudHJpbSgpID09PSAnSEVBUlRCRUFUX09LJykge1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIHRoaXMub25NZXNzYWdlPy4oe1xuICAgICAgICAgICAgdHlwZTogJ21lc3NhZ2UnLFxuICAgICAgICAgICAgcGF5bG9hZDoge1xuICAgICAgICAgICAgICBjb250ZW50OiB0ZXh0LFxuICAgICAgICAgICAgICByb2xlOiAnYXNzaXN0YW50JyxcbiAgICAgICAgICAgICAgdGltZXN0YW1wOiBEYXRlLm5vdygpLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9KTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm47XG4gICAgICB9XG5cbiAgICAgIC8vIEF2b2lkIGxvZ2dpbmcgZnVsbCBmcmFtZXMgKG1heSBpbmNsdWRlIG1lc3NhZ2UgY29udGVudCBvciBvdGhlciBzZW5zaXRpdmUgcGF5bG9hZHMpLlxuICAgICAgY29uc29sZS5kZWJ1ZygnW29jbGF3LXdzXSBVbmhhbmRsZWQgZnJhbWUnLCB7IHR5cGU6IGZyYW1lPy50eXBlLCBldmVudDogZnJhbWU/LmV2ZW50LCBpZDogZnJhbWU/LmlkIH0pO1xuICAgIH07XG5cbiAgICB3cy5vbmNsb3NlID0gKCkgPT4ge1xuICAgICAgdGhpcy5fc3RvcFRpbWVycygpO1xuICAgICAgdGhpcy5fc2V0V29ya2luZyhmYWxzZSk7XG4gICAgICB0aGlzLl9zZXRTdGF0ZSgnZGlzY29ubmVjdGVkJyk7XG5cbiAgICAgIGZvciAoY29uc3QgcGVuZGluZyBvZiB0aGlzLnBlbmRpbmdSZXF1ZXN0cy52YWx1ZXMoKSkge1xuICAgICAgICBpZiAocGVuZGluZy50aW1lb3V0KSBjbGVhclRpbWVvdXQocGVuZGluZy50aW1lb3V0KTtcbiAgICAgICAgcGVuZGluZy5yZWplY3QobmV3IEVycm9yKCdDb25uZWN0aW9uIGNsb3NlZCcpKTtcbiAgICAgIH1cbiAgICAgIHRoaXMucGVuZGluZ1JlcXVlc3RzLmNsZWFyKCk7XG5cbiAgICAgIGlmICghdGhpcy5pbnRlbnRpb25hbENsb3NlKSB7XG4gICAgICAgIHRoaXMuX3NjaGVkdWxlUmVjb25uZWN0KCk7XG4gICAgICB9XG4gICAgfTtcblxuICAgIHdzLm9uZXJyb3IgPSAoZXY6IEV2ZW50KSA9PiB7XG4gICAgICBjb25zb2xlLmVycm9yKCdbb2NsYXctd3NdIFdlYlNvY2tldCBlcnJvcicsIGV2KTtcbiAgICB9O1xuICB9XG5cbiAgcHJpdmF0ZSBfc2VuZFJlcXVlc3QobWV0aG9kOiBzdHJpbmcsIHBhcmFtczogYW55KTogUHJvbWlzZTxhbnk+IHtcbiAgICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgaWYgKCF0aGlzLndzIHx8IHRoaXMud3MucmVhZHlTdGF0ZSAhPT0gV2ViU29ja2V0Lk9QRU4pIHtcbiAgICAgICAgcmVqZWN0KG5ldyBFcnJvcignV2ViU29ja2V0IG5vdCBjb25uZWN0ZWQnKSk7XG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cblxuICAgICAgY29uc3QgaWQgPSBgcmVxLSR7Kyt0aGlzLnJlcXVlc3RJZH1gO1xuXG4gICAgICBjb25zdCBwZW5kaW5nOiBQZW5kaW5nUmVxdWVzdCA9IHsgcmVzb2x2ZSwgcmVqZWN0LCB0aW1lb3V0OiBudWxsIH07XG4gICAgICB0aGlzLnBlbmRpbmdSZXF1ZXN0cy5zZXQoaWQsIHBlbmRpbmcpO1xuXG4gICAgICB0aGlzLndzLnNlbmQoXG4gICAgICAgIEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgICB0eXBlOiAncmVxJyxcbiAgICAgICAgICBtZXRob2QsXG4gICAgICAgICAgaWQsXG4gICAgICAgICAgcGFyYW1zLFxuICAgICAgICB9KVxuICAgICAgKTtcblxuICAgICAgcGVuZGluZy50aW1lb3V0ID0gc2V0VGltZW91dCgoKSA9PiB7XG4gICAgICAgIGlmICh0aGlzLnBlbmRpbmdSZXF1ZXN0cy5oYXMoaWQpKSB7XG4gICAgICAgICAgdGhpcy5wZW5kaW5nUmVxdWVzdHMuZGVsZXRlKGlkKTtcbiAgICAgICAgICByZWplY3QobmV3IEVycm9yKGBSZXF1ZXN0IHRpbWVvdXQ6ICR7bWV0aG9kfWApKTtcbiAgICAgICAgfVxuICAgICAgfSwgMzBfMDAwKTtcbiAgICB9KTtcbiAgfVxuXG4gIHByaXZhdGUgX3NjaGVkdWxlUmVjb25uZWN0KCk6IHZvaWQge1xuICAgIGlmICh0aGlzLnJlY29ubmVjdFRpbWVyICE9PSBudWxsKSByZXR1cm47XG4gICAgdGhpcy5yZWNvbm5lY3RUaW1lciA9IHNldFRpbWVvdXQoKCkgPT4ge1xuICAgICAgdGhpcy5yZWNvbm5lY3RUaW1lciA9IG51bGw7XG4gICAgICBpZiAoIXRoaXMuaW50ZW50aW9uYWxDbG9zZSkge1xuICAgICAgICBjb25zb2xlLmxvZyhgW29jbGF3LXdzXSBSZWNvbm5lY3RpbmcgdG8gJHt0aGlzLnVybH1cdTIwMjZgKTtcbiAgICAgICAgdGhpcy5fY29ubmVjdCgpO1xuICAgICAgfVxuICAgIH0sIFJFQ09OTkVDVF9ERUxBWV9NUyk7XG4gIH1cblxuICBwcml2YXRlIF9zdGFydEhlYXJ0YmVhdCgpOiB2b2lkIHtcbiAgICB0aGlzLl9zdG9wSGVhcnRiZWF0KCk7XG4gICAgdGhpcy5oZWFydGJlYXRUaW1lciA9IHNldEludGVydmFsKCgpID0+IHtcbiAgICAgIGlmICh0aGlzLndzPy5yZWFkeVN0YXRlICE9PSBXZWJTb2NrZXQuT1BFTikgcmV0dXJuO1xuICAgICAgaWYgKHRoaXMud3MuYnVmZmVyZWRBbW91bnQgPiAwKSB7XG4gICAgICAgIGNvbnNvbGUud2FybignW29jbGF3LXdzXSBTZW5kIGJ1ZmZlciBub3QgZW1wdHkgXHUyMDE0IGNvbm5lY3Rpb24gbWF5IGJlIHN0YWxsZWQnKTtcbiAgICAgIH1cbiAgICB9LCBIRUFSVEJFQVRfSU5URVJWQUxfTVMpO1xuICB9XG5cbiAgcHJpdmF0ZSBfc3RvcEhlYXJ0YmVhdCgpOiB2b2lkIHtcbiAgICBpZiAodGhpcy5oZWFydGJlYXRUaW1lcikge1xuICAgICAgY2xlYXJJbnRlcnZhbCh0aGlzLmhlYXJ0YmVhdFRpbWVyKTtcbiAgICAgIHRoaXMuaGVhcnRiZWF0VGltZXIgPSBudWxsO1xuICAgIH1cbiAgfVxuXG4gIHByaXZhdGUgX3N0b3BUaW1lcnMoKTogdm9pZCB7XG4gICAgdGhpcy5fc3RvcEhlYXJ0YmVhdCgpO1xuICAgIHRoaXMuX2Rpc2FybVdvcmtpbmdTYWZldHlUaW1lb3V0KCk7XG4gICAgaWYgKHRoaXMucmVjb25uZWN0VGltZXIpIHtcbiAgICAgIGNsZWFyVGltZW91dCh0aGlzLnJlY29ubmVjdFRpbWVyKTtcbiAgICAgIHRoaXMucmVjb25uZWN0VGltZXIgPSBudWxsO1xuICAgIH1cbiAgfVxuXG4gIHByaXZhdGUgX3NldFN0YXRlKHN0YXRlOiBXU0NsaWVudFN0YXRlKTogdm9pZCB7XG4gICAgaWYgKHRoaXMuc3RhdGUgPT09IHN0YXRlKSByZXR1cm47XG4gICAgdGhpcy5zdGF0ZSA9IHN0YXRlO1xuICAgIHRoaXMub25TdGF0ZUNoYW5nZT8uKHN0YXRlKTtcbiAgfVxuXG4gIHByaXZhdGUgX3NldFdvcmtpbmcod29ya2luZzogYm9vbGVhbik6IHZvaWQge1xuICAgIGlmICh0aGlzLndvcmtpbmcgPT09IHdvcmtpbmcpIHJldHVybjtcbiAgICB0aGlzLndvcmtpbmcgPSB3b3JraW5nO1xuICAgIHRoaXMub25Xb3JraW5nQ2hhbmdlPy4od29ya2luZyk7XG5cbiAgICBpZiAoIXdvcmtpbmcpIHtcbiAgICAgIHRoaXMuX2Rpc2FybVdvcmtpbmdTYWZldHlUaW1lb3V0KCk7XG4gICAgfVxuICB9XG5cbiAgcHJpdmF0ZSBfYXJtV29ya2luZ1NhZmV0eVRpbWVvdXQoKTogdm9pZCB7XG4gICAgdGhpcy5fZGlzYXJtV29ya2luZ1NhZmV0eVRpbWVvdXQoKTtcbiAgICB0aGlzLndvcmtpbmdUaW1lciA9IHNldFRpbWVvdXQoKCkgPT4ge1xuICAgICAgLy8gSWYgdGhlIGdhdGV3YXkgbmV2ZXIgZW1pdHMgYW4gYXNzaXN0YW50IGZpbmFsIHJlc3BvbnNlLCBkb25cdTIwMTl0IGxlYXZlIFVJIHN0dWNrLlxuICAgICAgdGhpcy5fc2V0V29ya2luZyhmYWxzZSk7XG4gICAgfSwgV09SS0lOR19NQVhfTVMpO1xuICB9XG5cbiAgcHJpdmF0ZSBfZGlzYXJtV29ya2luZ1NhZmV0eVRpbWVvdXQoKTogdm9pZCB7XG4gICAgaWYgKHRoaXMud29ya2luZ1RpbWVyKSB7XG4gICAgICBjbGVhclRpbWVvdXQodGhpcy53b3JraW5nVGltZXIpO1xuICAgICAgdGhpcy53b3JraW5nVGltZXIgPSBudWxsO1xuICAgIH1cbiAgfVxufVxuIiwgImltcG9ydCB0eXBlIHsgQ2hhdE1lc3NhZ2UgfSBmcm9tICcuL3R5cGVzJztcblxuLyoqIE1hbmFnZXMgdGhlIGluLW1lbW9yeSBsaXN0IG9mIGNoYXQgbWVzc2FnZXMgYW5kIG5vdGlmaWVzIFVJIG9uIGNoYW5nZXMgKi9cbmV4cG9ydCBjbGFzcyBDaGF0TWFuYWdlciB7XG4gIHByaXZhdGUgbWVzc2FnZXM6IENoYXRNZXNzYWdlW10gPSBbXTtcblxuICAvKiogRmlyZWQgZm9yIGEgZnVsbCByZS1yZW5kZXIgKGNsZWFyL3JlbG9hZCkgKi9cbiAgb25VcGRhdGU6ICgobWVzc2FnZXM6IHJlYWRvbmx5IENoYXRNZXNzYWdlW10pID0+IHZvaWQpIHwgbnVsbCA9IG51bGw7XG4gIC8qKiBGaXJlZCB3aGVuIGEgc2luZ2xlIG1lc3NhZ2UgaXMgYXBwZW5kZWQgXHUyMDE0IHVzZSBmb3IgTygxKSBhcHBlbmQtb25seSBVSSAqL1xuICBvbk1lc3NhZ2VBZGRlZDogKChtc2c6IENoYXRNZXNzYWdlKSA9PiB2b2lkKSB8IG51bGwgPSBudWxsO1xuXG4gIGFkZE1lc3NhZ2UobXNnOiBDaGF0TWVzc2FnZSk6IHZvaWQge1xuICAgIHRoaXMubWVzc2FnZXMucHVzaChtc2cpO1xuICAgIHRoaXMub25NZXNzYWdlQWRkZWQ/Lihtc2cpO1xuICB9XG5cbiAgZ2V0TWVzc2FnZXMoKTogcmVhZG9ubHkgQ2hhdE1lc3NhZ2VbXSB7XG4gICAgcmV0dXJuIHRoaXMubWVzc2FnZXM7XG4gIH1cblxuICBjbGVhcigpOiB2b2lkIHtcbiAgICB0aGlzLm1lc3NhZ2VzID0gW107XG4gICAgdGhpcy5vblVwZGF0ZT8uKFtdKTtcbiAgfVxuXG4gIC8qKiBDcmVhdGUgYSB1c2VyIG1lc3NhZ2Ugb2JqZWN0ICh3aXRob3V0IGFkZGluZyBpdCkgKi9cbiAgc3RhdGljIGNyZWF0ZVVzZXJNZXNzYWdlKGNvbnRlbnQ6IHN0cmluZyk6IENoYXRNZXNzYWdlIHtcbiAgICByZXR1cm4ge1xuICAgICAgaWQ6IGBtc2ctJHtEYXRlLm5vdygpfS0ke01hdGgucmFuZG9tKCkudG9TdHJpbmcoMzYpLnNsaWNlKDIsIDcpfWAsXG4gICAgICByb2xlOiAndXNlcicsXG4gICAgICBjb250ZW50LFxuICAgICAgdGltZXN0YW1wOiBEYXRlLm5vdygpLFxuICAgIH07XG4gIH1cblxuICAvKiogQ3JlYXRlIGFuIGFzc2lzdGFudCBtZXNzYWdlIG9iamVjdCAod2l0aG91dCBhZGRpbmcgaXQpICovXG4gIHN0YXRpYyBjcmVhdGVBc3Npc3RhbnRNZXNzYWdlKGNvbnRlbnQ6IHN0cmluZyk6IENoYXRNZXNzYWdlIHtcbiAgICByZXR1cm4ge1xuICAgICAgaWQ6IGBtc2ctJHtEYXRlLm5vdygpfS0ke01hdGgucmFuZG9tKCkudG9TdHJpbmcoMzYpLnNsaWNlKDIsIDcpfWAsXG4gICAgICByb2xlOiAnYXNzaXN0YW50JyxcbiAgICAgIGNvbnRlbnQsXG4gICAgICB0aW1lc3RhbXA6IERhdGUubm93KCksXG4gICAgfTtcbiAgfVxuXG4gIC8qKiBDcmVhdGUgYSBzeXN0ZW0gLyBzdGF0dXMgbWVzc2FnZSAoZXJyb3JzLCByZWNvbm5lY3Qgbm90aWNlcywgZXRjLikgKi9cbiAgc3RhdGljIGNyZWF0ZVN5c3RlbU1lc3NhZ2UoY29udGVudDogc3RyaW5nLCBsZXZlbDogQ2hhdE1lc3NhZ2VbJ2xldmVsJ10gPSAnaW5mbycpOiBDaGF0TWVzc2FnZSB7XG4gICAgcmV0dXJuIHtcbiAgICAgIGlkOiBgc3lzLSR7RGF0ZS5ub3coKX1gLFxuICAgICAgcm9sZTogJ3N5c3RlbScsXG4gICAgICBsZXZlbCxcbiAgICAgIGNvbnRlbnQsXG4gICAgICB0aW1lc3RhbXA6IERhdGUubm93KCksXG4gICAgfTtcbiAgfVxufVxuIiwgImltcG9ydCB7IEl0ZW1WaWV3LCBNYXJrZG93blJlbmRlcmVyLCBOb3RpY2UsIFdvcmtzcGFjZUxlYWYgfSBmcm9tICdvYnNpZGlhbic7XG5pbXBvcnQgdHlwZSBPcGVuQ2xhd1BsdWdpbiBmcm9tICcuL21haW4nO1xuaW1wb3J0IHsgQ2hhdE1hbmFnZXIgfSBmcm9tICcuL2NoYXQnO1xuaW1wb3J0IHR5cGUgeyBDaGF0TWVzc2FnZSB9IGZyb20gJy4vdHlwZXMnO1xuaW1wb3J0IHsgZ2V0QWN0aXZlTm90ZUNvbnRleHQgfSBmcm9tICcuL2NvbnRleHQnO1xuXG5leHBvcnQgY29uc3QgVklFV19UWVBFX09QRU5DTEFXX0NIQVQgPSAnb3BlbmNsYXctY2hhdCc7XG5cbmV4cG9ydCBjbGFzcyBPcGVuQ2xhd0NoYXRWaWV3IGV4dGVuZHMgSXRlbVZpZXcge1xuICBwcml2YXRlIHBsdWdpbjogT3BlbkNsYXdQbHVnaW47XG4gIHByaXZhdGUgY2hhdE1hbmFnZXI6IENoYXRNYW5hZ2VyO1xuXG4gIC8vIFN0YXRlXG4gIHByaXZhdGUgaXNDb25uZWN0ZWQgPSBmYWxzZTtcbiAgcHJpdmF0ZSBpc1dvcmtpbmcgPSBmYWxzZTtcblxuICAvLyBET00gcmVmc1xuICBwcml2YXRlIG1lc3NhZ2VzRWwhOiBIVE1MRWxlbWVudDtcbiAgcHJpdmF0ZSBpbnB1dEVsITogSFRNTFRleHRBcmVhRWxlbWVudDtcbiAgcHJpdmF0ZSBzZW5kQnRuITogSFRNTEJ1dHRvbkVsZW1lbnQ7XG4gIHByaXZhdGUgaW5jbHVkZU5vdGVDaGVja2JveCE6IEhUTUxJbnB1dEVsZW1lbnQ7XG4gIHByaXZhdGUgc3RhdHVzRG90ITogSFRNTEVsZW1lbnQ7XG5cbiAgY29uc3RydWN0b3IobGVhZjogV29ya3NwYWNlTGVhZiwgcGx1Z2luOiBPcGVuQ2xhd1BsdWdpbikge1xuICAgIHN1cGVyKGxlYWYpO1xuICAgIHRoaXMucGx1Z2luID0gcGx1Z2luO1xuICAgIHRoaXMuY2hhdE1hbmFnZXIgPSBwbHVnaW4uY2hhdE1hbmFnZXI7XG4gIH1cblxuICBnZXRWaWV3VHlwZSgpOiBzdHJpbmcge1xuICAgIHJldHVybiBWSUVXX1RZUEVfT1BFTkNMQVdfQ0hBVDtcbiAgfVxuXG4gIGdldERpc3BsYXlUZXh0KCk6IHN0cmluZyB7XG4gICAgcmV0dXJuICdPcGVuQ2xhdyBDaGF0JztcbiAgfVxuXG4gIGdldEljb24oKTogc3RyaW5nIHtcbiAgICByZXR1cm4gJ21lc3NhZ2Utc3F1YXJlJztcbiAgfVxuXG4gIGFzeW5jIG9uT3BlbigpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICB0aGlzLl9idWlsZFVJKCk7XG5cbiAgICAvLyBGdWxsIHJlLXJlbmRlciBvbiBjbGVhciAvIHJlbG9hZFxuICAgIHRoaXMuY2hhdE1hbmFnZXIub25VcGRhdGUgPSAobXNncykgPT4gdGhpcy5fcmVuZGVyTWVzc2FnZXMobXNncyk7XG4gICAgLy8gTygxKSBhcHBlbmQgZm9yIG5ldyBtZXNzYWdlc1xuICAgIHRoaXMuY2hhdE1hbmFnZXIub25NZXNzYWdlQWRkZWQgPSAobXNnKSA9PiB0aGlzLl9hcHBlbmRNZXNzYWdlKG1zZyk7XG5cbiAgICAvLyBTdWJzY3JpYmUgdG8gV1Mgc3RhdGUgY2hhbmdlc1xuICAgIHRoaXMucGx1Z2luLndzQ2xpZW50Lm9uU3RhdGVDaGFuZ2UgPSAoc3RhdGUpID0+IHtcbiAgICAgIHRoaXMuaXNDb25uZWN0ZWQgPSBzdGF0ZSA9PT0gJ2Nvbm5lY3RlZCc7XG4gICAgICB0aGlzLnN0YXR1c0RvdC50b2dnbGVDbGFzcygnY29ubmVjdGVkJywgdGhpcy5pc0Nvbm5lY3RlZCk7XG4gICAgICB0aGlzLnN0YXR1c0RvdC50aXRsZSA9IGBHYXRld2F5OiAke3N0YXRlfWA7XG4gICAgICB0aGlzLl91cGRhdGVTZW5kQnV0dG9uKCk7XG4gICAgfTtcblxuICAgIC8vIFN1YnNjcmliZSB0byBcdTIwMUN3b3JraW5nXHUyMDFEIChyZXF1ZXN0LWluLWZsaWdodCkgc3RhdGVcbiAgICB0aGlzLnBsdWdpbi53c0NsaWVudC5vbldvcmtpbmdDaGFuZ2UgPSAod29ya2luZykgPT4ge1xuICAgICAgdGhpcy5pc1dvcmtpbmcgPSB3b3JraW5nO1xuICAgICAgdGhpcy5fdXBkYXRlU2VuZEJ1dHRvbigpO1xuICAgIH07XG5cbiAgICAvLyBSZWZsZWN0IGN1cnJlbnQgc3RhdGVcbiAgICB0aGlzLmlzQ29ubmVjdGVkID0gdGhpcy5wbHVnaW4ud3NDbGllbnQuc3RhdGUgPT09ICdjb25uZWN0ZWQnO1xuICAgIHRoaXMuc3RhdHVzRG90LnRvZ2dsZUNsYXNzKCdjb25uZWN0ZWQnLCB0aGlzLmlzQ29ubmVjdGVkKTtcbiAgICB0aGlzLl91cGRhdGVTZW5kQnV0dG9uKCk7XG5cbiAgICB0aGlzLl9yZW5kZXJNZXNzYWdlcyh0aGlzLmNoYXRNYW5hZ2VyLmdldE1lc3NhZ2VzKCkpO1xuICB9XG5cbiAgYXN5bmMgb25DbG9zZSgpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICB0aGlzLmNoYXRNYW5hZ2VyLm9uVXBkYXRlID0gbnVsbDtcbiAgICB0aGlzLmNoYXRNYW5hZ2VyLm9uTWVzc2FnZUFkZGVkID0gbnVsbDtcbiAgICB0aGlzLnBsdWdpbi53c0NsaWVudC5vblN0YXRlQ2hhbmdlID0gbnVsbDtcbiAgICB0aGlzLnBsdWdpbi53c0NsaWVudC5vbldvcmtpbmdDaGFuZ2UgPSBudWxsO1xuICB9XG5cbiAgLy8gXHUyNTAwXHUyNTAwIFVJIGNvbnN0cnVjdGlvbiBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcblxuICBwcml2YXRlIF9idWlsZFVJKCk6IHZvaWQge1xuICAgIGNvbnN0IHJvb3QgPSB0aGlzLmNvbnRlbnRFbDtcbiAgICByb290LmVtcHR5KCk7XG4gICAgcm9vdC5hZGRDbGFzcygnb2NsYXctY2hhdC12aWV3Jyk7XG5cbiAgICAvLyBcdTI1MDBcdTI1MDAgSGVhZGVyIFx1MjUwMFx1MjUwMFxuICAgIGNvbnN0IGhlYWRlciA9IHJvb3QuY3JlYXRlRGl2KHsgY2xzOiAnb2NsYXctaGVhZGVyJyB9KTtcbiAgICBoZWFkZXIuY3JlYXRlU3Bhbih7IGNsczogJ29jbGF3LWhlYWRlci10aXRsZScsIHRleHQ6ICdPcGVuQ2xhdyBDaGF0JyB9KTtcbiAgICB0aGlzLnN0YXR1c0RvdCA9IGhlYWRlci5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1zdGF0dXMtZG90JyB9KTtcbiAgICB0aGlzLnN0YXR1c0RvdC50aXRsZSA9ICdHYXRld2F5OiBkaXNjb25uZWN0ZWQnO1xuXG4gICAgLy8gXHUyNTAwXHUyNTAwIE1lc3NhZ2VzIGFyZWEgXHUyNTAwXHUyNTAwXG4gICAgdGhpcy5tZXNzYWdlc0VsID0gcm9vdC5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1tZXNzYWdlcycgfSk7XG5cbiAgICAvLyBcdTI1MDBcdTI1MDAgQ29udGV4dCByb3cgXHUyNTAwXHUyNTAwXG4gICAgY29uc3QgY3R4Um93ID0gcm9vdC5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1jb250ZXh0LXJvdycgfSk7XG4gICAgdGhpcy5pbmNsdWRlTm90ZUNoZWNrYm94ID0gY3R4Um93LmNyZWF0ZUVsKCdpbnB1dCcsIHsgdHlwZTogJ2NoZWNrYm94JyB9KTtcbiAgICB0aGlzLmluY2x1ZGVOb3RlQ2hlY2tib3guaWQgPSAnb2NsYXctaW5jbHVkZS1ub3RlJztcbiAgICB0aGlzLmluY2x1ZGVOb3RlQ2hlY2tib3guY2hlY2tlZCA9IHRoaXMucGx1Z2luLnNldHRpbmdzLmluY2x1ZGVBY3RpdmVOb3RlO1xuICAgIGNvbnN0IGN0eExhYmVsID0gY3R4Um93LmNyZWF0ZUVsKCdsYWJlbCcsIHsgdGV4dDogJ0luY2x1ZGUgYWN0aXZlIG5vdGUnIH0pO1xuICAgIGN0eExhYmVsLmh0bWxGb3IgPSAnb2NsYXctaW5jbHVkZS1ub3RlJztcblxuICAgIC8vIFx1MjUwMFx1MjUwMCBJbnB1dCByb3cgXHUyNTAwXHUyNTAwXG4gICAgY29uc3QgaW5wdXRSb3cgPSByb290LmNyZWF0ZURpdih7IGNsczogJ29jbGF3LWlucHV0LXJvdycgfSk7XG4gICAgdGhpcy5pbnB1dEVsID0gaW5wdXRSb3cuY3JlYXRlRWwoJ3RleHRhcmVhJywge1xuICAgICAgY2xzOiAnb2NsYXctaW5wdXQnLFxuICAgICAgcGxhY2Vob2xkZXI6ICdBc2sgYW55dGhpbmdcdTIwMjYnLFxuICAgIH0pO1xuICAgIHRoaXMuaW5wdXRFbC5yb3dzID0gMTtcblxuICAgIHRoaXMuc2VuZEJ0biA9IGlucHV0Um93LmNyZWF0ZUVsKCdidXR0b24nLCB7IGNsczogJ29jbGF3LXNlbmQtYnRuJywgdGV4dDogJ1NlbmQnIH0pO1xuXG4gICAgLy8gXHUyNTAwXHUyNTAwIEV2ZW50IGxpc3RlbmVycyBcdTI1MDBcdTI1MDBcbiAgICB0aGlzLnNlbmRCdG4uYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKSA9PiB0aGlzLl9oYW5kbGVTZW5kKCkpO1xuICAgIHRoaXMuaW5wdXRFbC5hZGRFdmVudExpc3RlbmVyKCdrZXlkb3duJywgKGUpID0+IHtcbiAgICAgIGlmIChlLmtleSA9PT0gJ0VudGVyJyAmJiAhZS5zaGlmdEtleSkge1xuICAgICAgICBlLnByZXZlbnREZWZhdWx0KCk7XG4gICAgICAgIHRoaXMuX2hhbmRsZVNlbmQoKTtcbiAgICAgIH1cbiAgICB9KTtcbiAgICAvLyBBdXRvLXJlc2l6ZSB0ZXh0YXJlYVxuICAgIHRoaXMuaW5wdXRFbC5hZGRFdmVudExpc3RlbmVyKCdpbnB1dCcsICgpID0+IHtcbiAgICAgIHRoaXMuaW5wdXRFbC5zdHlsZS5oZWlnaHQgPSAnYXV0byc7XG4gICAgICB0aGlzLmlucHV0RWwuc3R5bGUuaGVpZ2h0ID0gYCR7dGhpcy5pbnB1dEVsLnNjcm9sbEhlaWdodH1weGA7XG4gICAgfSk7XG4gIH1cblxuICAvLyBcdTI1MDBcdTI1MDAgTWVzc2FnZSByZW5kZXJpbmcgXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG5cbiAgcHJpdmF0ZSBfcmVuZGVyTWVzc2FnZXMobWVzc2FnZXM6IHJlYWRvbmx5IENoYXRNZXNzYWdlW10pOiB2b2lkIHtcbiAgICB0aGlzLm1lc3NhZ2VzRWwuZW1wdHkoKTtcblxuICAgIGlmIChtZXNzYWdlcy5sZW5ndGggPT09IDApIHtcbiAgICAgIHRoaXMubWVzc2FnZXNFbC5jcmVhdGVFbCgncCcsIHtcbiAgICAgICAgdGV4dDogJ1NlbmQgYSBtZXNzYWdlIHRvIHN0YXJ0IGNoYXR0aW5nLicsXG4gICAgICAgIGNsczogJ29jbGF3LW1lc3NhZ2Ugc3lzdGVtIG9jbGF3LXBsYWNlaG9sZGVyJyxcbiAgICAgIH0pO1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIGZvciAoY29uc3QgbXNnIG9mIG1lc3NhZ2VzKSB7XG4gICAgICB0aGlzLl9hcHBlbmRNZXNzYWdlKG1zZyk7XG4gICAgfVxuXG4gICAgLy8gU2Nyb2xsIHRvIGJvdHRvbVxuICAgIHRoaXMubWVzc2FnZXNFbC5zY3JvbGxUb3AgPSB0aGlzLm1lc3NhZ2VzRWwuc2Nyb2xsSGVpZ2h0O1xuICB9XG5cbiAgLyoqIEFwcGVuZHMgYSBzaW5nbGUgbWVzc2FnZSB3aXRob3V0IHJlYnVpbGRpbmcgdGhlIERPTSAoTygxKSkgKi9cbiAgcHJpdmF0ZSBfYXBwZW5kTWVzc2FnZShtc2c6IENoYXRNZXNzYWdlKTogdm9pZCB7XG4gICAgLy8gUmVtb3ZlIGVtcHR5LXN0YXRlIHBsYWNlaG9sZGVyIGlmIHByZXNlbnRcbiAgICB0aGlzLm1lc3NhZ2VzRWwucXVlcnlTZWxlY3RvcignLm9jbGF3LXBsYWNlaG9sZGVyJyk/LnJlbW92ZSgpO1xuXG4gICAgY29uc3QgbGV2ZWxDbGFzcyA9IG1zZy5sZXZlbCA/IGAgJHttc2cubGV2ZWx9YCA6ICcnO1xuICAgIGNvbnN0IGVsID0gdGhpcy5tZXNzYWdlc0VsLmNyZWF0ZURpdih7IGNsczogYG9jbGF3LW1lc3NhZ2UgJHttc2cucm9sZX0ke2xldmVsQ2xhc3N9YCB9KTtcbiAgICBjb25zdCBib2R5ID0gZWwuY3JlYXRlRGl2KHsgY2xzOiAnb2NsYXctbWVzc2FnZS1ib2R5JyB9KTtcblxuICAgIC8vIFJlbmRlciBhc3Npc3RhbnQgbWVzc2FnZXMgYXMgTWFya2Rvd24gKHVudHJ1c3RlZCBjb250ZW50IFx1MjE5MiBrZWVwIHVzZXIvc3lzdGVtIHBsYWluKVxuICAgIGlmIChtc2cucm9sZSA9PT0gJ2Fzc2lzdGFudCcpIHtcbiAgICAgIGNvbnN0IHNvdXJjZVBhdGggPSB0aGlzLmFwcC53b3Jrc3BhY2UuZ2V0QWN0aXZlRmlsZSgpPy5wYXRoID8/ICcnO1xuICAgICAgdm9pZCBNYXJrZG93blJlbmRlcmVyLnJlbmRlck1hcmtkb3duKG1zZy5jb250ZW50LCBib2R5LCBzb3VyY2VQYXRoLCB0aGlzLnBsdWdpbik7XG4gICAgfSBlbHNlIHtcbiAgICAgIGJvZHkuc2V0VGV4dChtc2cuY29udGVudCk7XG4gICAgfVxuXG4gICAgLy8gU2Nyb2xsIHRvIGJvdHRvbVxuICAgIHRoaXMubWVzc2FnZXNFbC5zY3JvbGxUb3AgPSB0aGlzLm1lc3NhZ2VzRWwuc2Nyb2xsSGVpZ2h0O1xuICB9XG5cbiAgcHJpdmF0ZSBfdXBkYXRlU2VuZEJ1dHRvbigpOiB2b2lkIHtcbiAgICAvLyBEaXNjb25uZWN0ZWQ6IGRpc2FibGUuXG4gICAgLy8gV29ya2luZzoga2VlcCBlbmFibGVkIHNvIHVzZXIgY2FuIHN0b3AvYWJvcnQuXG4gICAgY29uc3QgZGlzYWJsZWQgPSAhdGhpcy5pc0Nvbm5lY3RlZDtcbiAgICB0aGlzLnNlbmRCdG4uZGlzYWJsZWQgPSBkaXNhYmxlZDtcblxuICAgIHRoaXMuc2VuZEJ0bi50b2dnbGVDbGFzcygnaXMtd29ya2luZycsIHRoaXMuaXNXb3JraW5nKTtcbiAgICB0aGlzLnNlbmRCdG4uc2V0QXR0cignYXJpYS1idXN5JywgdGhpcy5pc1dvcmtpbmcgPyAndHJ1ZScgOiAnZmFsc2UnKTtcbiAgICB0aGlzLnNlbmRCdG4uc2V0QXR0cignYXJpYS1sYWJlbCcsIHRoaXMuaXNXb3JraW5nID8gJ1N0b3AnIDogJ1NlbmQnKTtcblxuICAgIGlmICh0aGlzLmlzV29ya2luZykge1xuICAgICAgLy8gUmVwbGFjZSBidXR0b24gY29udGVudHMgd2l0aCBTdG9wIGljb24gKyBzcGlubmVyIHJpbmcuXG4gICAgICB0aGlzLnNlbmRCdG4uZW1wdHkoKTtcbiAgICAgIGNvbnN0IHdyYXAgPSB0aGlzLnNlbmRCdG4uY3JlYXRlRGl2KHsgY2xzOiAnb2NsYXctc3RvcC13cmFwJyB9KTtcbiAgICAgIHdyYXAuY3JlYXRlRGl2KHsgY2xzOiAnb2NsYXctc3Bpbm5lci1yaW5nJywgYXR0cjogeyAnYXJpYS1oaWRkZW4nOiAndHJ1ZScgfSB9KTtcbiAgICAgIHdyYXAuY3JlYXRlRGl2KHsgY2xzOiAnb2NsYXctc3RvcC1pY29uJywgYXR0cjogeyAnYXJpYS1oaWRkZW4nOiAndHJ1ZScgfSB9KTtcbiAgICB9IGVsc2Uge1xuICAgICAgLy8gUmVzdG9yZSBsYWJlbFxuICAgICAgdGhpcy5zZW5kQnRuLnNldFRleHQoJ1NlbmQnKTtcbiAgICB9XG4gIH1cblxuICAvLyBcdTI1MDBcdTI1MDAgU2VuZCBoYW5kbGVyIFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFxuXG4gIHByaXZhdGUgYXN5bmMgX2hhbmRsZVNlbmQoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgLy8gV2hpbGUgd29ya2luZywgdGhlIGJ1dHRvbiBiZWNvbWVzIFN0b3AuXG4gICAgaWYgKHRoaXMuaXNXb3JraW5nKSB7XG4gICAgICBjb25zdCBvayA9IGF3YWl0IHRoaXMucGx1Z2luLndzQ2xpZW50LmFib3J0QWN0aXZlUnVuKCk7XG4gICAgICBpZiAoIW9rKSB7XG4gICAgICAgIG5ldyBOb3RpY2UoJ09wZW5DbGF3IENoYXQ6IGZhaWxlZCB0byBzdG9wJyk7XG4gICAgICAgIHRoaXMuY2hhdE1hbmFnZXIuYWRkTWVzc2FnZShDaGF0TWFuYWdlci5jcmVhdGVTeXN0ZW1NZXNzYWdlKCdcdTI2QTAgU3RvcCBmYWlsZWQnLCAnZXJyb3InKSk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICB0aGlzLmNoYXRNYW5hZ2VyLmFkZE1lc3NhZ2UoQ2hhdE1hbmFnZXIuY3JlYXRlU3lzdGVtTWVzc2FnZSgnXHUyNkQ0IFN0b3BwZWQnLCAnaW5mbycpKTtcbiAgICAgIH1cbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICBjb25zdCB0ZXh0ID0gdGhpcy5pbnB1dEVsLnZhbHVlLnRyaW0oKTtcbiAgICBpZiAoIXRleHQpIHJldHVybjtcblxuICAgIC8vIEJ1aWxkIG1lc3NhZ2Ugd2l0aCBjb250ZXh0IGlmIGVuYWJsZWRcbiAgICBsZXQgbWVzc2FnZSA9IHRleHQ7XG4gICAgaWYgKHRoaXMuaW5jbHVkZU5vdGVDaGVja2JveC5jaGVja2VkKSB7XG4gICAgICBjb25zdCBub3RlID0gYXdhaXQgZ2V0QWN0aXZlTm90ZUNvbnRleHQodGhpcy5hcHApO1xuICAgICAgaWYgKG5vdGUpIHtcbiAgICAgICAgbWVzc2FnZSA9IGBDb250ZXh0OiBbWyR7bm90ZS50aXRsZX1dXVxcblxcbiR7dGV4dH1gO1xuICAgICAgfVxuICAgIH1cblxuICAgIC8vIEFkZCB1c2VyIG1lc3NhZ2UgdG8gY2hhdCBVSVxuICAgIGNvbnN0IHVzZXJNc2cgPSBDaGF0TWFuYWdlci5jcmVhdGVVc2VyTWVzc2FnZSh0ZXh0KTtcbiAgICB0aGlzLmNoYXRNYW5hZ2VyLmFkZE1lc3NhZ2UodXNlck1zZyk7XG5cbiAgICAvLyBDbGVhciBpbnB1dFxuICAgIHRoaXMuaW5wdXRFbC52YWx1ZSA9ICcnO1xuICAgIHRoaXMuaW5wdXRFbC5zdHlsZS5oZWlnaHQgPSAnYXV0byc7XG5cbiAgICAvLyBTZW5kIG92ZXIgV1MgKGFzeW5jKVxuICAgIHRyeSB7XG4gICAgICBhd2FpdCB0aGlzLnBsdWdpbi53c0NsaWVudC5zZW5kTWVzc2FnZShtZXNzYWdlKTtcbiAgICB9IGNhdGNoIChlcnIpIHtcbiAgICAgIGNvbnNvbGUuZXJyb3IoJ1tvY2xhd10gU2VuZCBmYWlsZWQnLCBlcnIpO1xuICAgICAgbmV3IE5vdGljZShgT3BlbkNsYXcgQ2hhdDogc2VuZCBmYWlsZWQgKCR7U3RyaW5nKGVycil9KWApO1xuICAgICAgdGhpcy5jaGF0TWFuYWdlci5hZGRNZXNzYWdlKFxuICAgICAgICBDaGF0TWFuYWdlci5jcmVhdGVTeXN0ZW1NZXNzYWdlKGBcdTI2QTAgU2VuZCBmYWlsZWQ6ICR7ZXJyfWAsICdlcnJvcicpXG4gICAgICApO1xuICAgIH1cbiAgfVxufVxuIiwgImltcG9ydCB0eXBlIHsgQXBwIH0gZnJvbSAnb2JzaWRpYW4nO1xuXG5leHBvcnQgaW50ZXJmYWNlIE5vdGVDb250ZXh0IHtcbiAgdGl0bGU6IHN0cmluZztcbiAgcGF0aDogc3RyaW5nO1xuICBjb250ZW50OiBzdHJpbmc7XG59XG5cbi8qKlxuICogUmV0dXJucyB0aGUgYWN0aXZlIG5vdGUncyB0aXRsZSBhbmQgY29udGVudCwgb3IgbnVsbCBpZiBubyBub3RlIGlzIG9wZW4uXG4gKiBBc3luYyBiZWNhdXNlIHZhdWx0LnJlYWQoKSBpcyBhc3luYy5cbiAqL1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGdldEFjdGl2ZU5vdGVDb250ZXh0KGFwcDogQXBwKTogUHJvbWlzZTxOb3RlQ29udGV4dCB8IG51bGw+IHtcbiAgY29uc3QgZmlsZSA9IGFwcC53b3Jrc3BhY2UuZ2V0QWN0aXZlRmlsZSgpO1xuICBpZiAoIWZpbGUpIHJldHVybiBudWxsO1xuXG4gIHRyeSB7XG4gICAgY29uc3QgY29udGVudCA9IGF3YWl0IGFwcC52YXVsdC5yZWFkKGZpbGUpO1xuICAgIHJldHVybiB7XG4gICAgICB0aXRsZTogZmlsZS5iYXNlbmFtZSxcbiAgICAgIHBhdGg6IGZpbGUucGF0aCxcbiAgICAgIGNvbnRlbnQsXG4gICAgfTtcbiAgfSBjYXRjaCAoZXJyKSB7XG4gICAgY29uc29sZS5lcnJvcignW29jbGF3LWNvbnRleHRdIEZhaWxlZCB0byByZWFkIGFjdGl2ZSBub3RlJywgZXJyKTtcbiAgICByZXR1cm4gbnVsbDtcbiAgfVxufVxuIiwgIi8qKiBQZXJzaXN0ZWQgcGx1Z2luIGNvbmZpZ3VyYXRpb24gKi9cbmV4cG9ydCBpbnRlcmZhY2UgT3BlbkNsYXdTZXR0aW5ncyB7XG4gIC8qKiBXZWJTb2NrZXQgVVJMIG9mIHRoZSBPcGVuQ2xhdyBHYXRld2F5IChlLmcuIHdzOi8vMTAwLjkwLjkuNjg6MTg3ODkpICovXG4gIGdhdGV3YXlVcmw6IHN0cmluZztcbiAgLyoqIEF1dGggdG9rZW4gXHUyMDE0IG11c3QgbWF0Y2ggdGhlIGNoYW5uZWwgcGx1Z2luJ3MgYXV0aFRva2VuICovXG4gIGF1dGhUb2tlbjogc3RyaW5nO1xuICAvKiogT3BlbkNsYXcgc2Vzc2lvbiBrZXkgdG8gc3Vic2NyaWJlIHRvIChlLmcuIFwibWFpblwiKSAqL1xuICBzZXNzaW9uS2V5OiBzdHJpbmc7XG4gIC8qKiAoRGVwcmVjYXRlZCkgT3BlbkNsYXcgYWNjb3VudCBJRCAodW51c2VkOyBjaGF0LnNlbmQgdXNlcyBzZXNzaW9uS2V5KSAqL1xuICBhY2NvdW50SWQ6IHN0cmluZztcbiAgLyoqIFdoZXRoZXIgdG8gaW5jbHVkZSB0aGUgYWN0aXZlIG5vdGUgY29udGVudCB3aXRoIGVhY2ggbWVzc2FnZSAqL1xuICBpbmNsdWRlQWN0aXZlTm90ZTogYm9vbGVhbjtcbn1cblxuZXhwb3J0IGNvbnN0IERFRkFVTFRfU0VUVElOR1M6IE9wZW5DbGF3U2V0dGluZ3MgPSB7XG4gIGdhdGV3YXlVcmw6ICd3czovL2xvY2FsaG9zdDoxODc4OScsXG4gIGF1dGhUb2tlbjogJycsXG4gIHNlc3Npb25LZXk6ICdtYWluJyxcbiAgYWNjb3VudElkOiAnbWFpbicsXG4gIGluY2x1ZGVBY3RpdmVOb3RlOiBmYWxzZSxcbn07XG5cbi8qKiBBIHNpbmdsZSBjaGF0IG1lc3NhZ2UgKi9cbmV4cG9ydCBpbnRlcmZhY2UgQ2hhdE1lc3NhZ2Uge1xuICBpZDogc3RyaW5nO1xuICByb2xlOiAndXNlcicgfCAnYXNzaXN0YW50JyB8ICdzeXN0ZW0nO1xuICAvKiogT3B0aW9uYWwgc2V2ZXJpdHkgZm9yIHN5c3RlbS9zdGF0dXMgbWVzc2FnZXMgKi9cbiAgbGV2ZWw/OiAnaW5mbycgfCAnZXJyb3InO1xuICBjb250ZW50OiBzdHJpbmc7XG4gIHRpbWVzdGFtcDogbnVtYmVyO1xufVxuXG4vKiogUGF5bG9hZCBmb3IgbWVzc2FnZXMgU0VOVCB0byB0aGUgc2VydmVyIChvdXRib3VuZCkgKi9cbmV4cG9ydCBpbnRlcmZhY2UgV1NQYXlsb2FkIHtcbiAgdHlwZTogJ2F1dGgnIHwgJ21lc3NhZ2UnIHwgJ3BpbmcnIHwgJ3BvbmcnIHwgJ2Vycm9yJztcbiAgcGF5bG9hZD86IFJlY29yZDxzdHJpbmcsIHVua25vd24+O1xufVxuXG4vKiogTWVzc2FnZXMgUkVDRUlWRUQgZnJvbSB0aGUgc2VydmVyIChpbmJvdW5kKSBcdTIwMTQgZGlzY3JpbWluYXRlZCB1bmlvbiAqL1xuZXhwb3J0IHR5cGUgSW5ib3VuZFdTUGF5bG9hZCA9XG4gIHwgeyB0eXBlOiAnbWVzc2FnZSc7IHBheWxvYWQ6IHsgY29udGVudDogc3RyaW5nOyByb2xlOiBzdHJpbmc7IHRpbWVzdGFtcDogbnVtYmVyIH0gfVxuICB8IHsgdHlwZTogJ2Vycm9yJzsgcGF5bG9hZDogeyBtZXNzYWdlOiBzdHJpbmcgfSB9O1xuXG4vKiogQXZhaWxhYmxlIGFnZW50cyAvIG1vZGVscyAqL1xuZXhwb3J0IGludGVyZmFjZSBBZ2VudE9wdGlvbiB7XG4gIGlkOiBzdHJpbmc7XG4gIGxhYmVsOiBzdHJpbmc7XG59XG4iXSwKICAibWFwcGluZ3MiOiAiOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBLElBQUFBLG1CQUE4Qzs7O0FDQTlDLHNCQUErQztBQUd4QyxJQUFNLHFCQUFOLGNBQWlDLGlDQUFpQjtBQUFBLEVBR3ZE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QXlCO0FBQUEsSUFDdkM7QUFBQTtBQUFBLEVBRU0sZUFBOEI7QUFBQTtBQUNsQyxXQUFLLFdBQVcsT0FBTyxPQUFPLENBQUMsR0FBRyxrQkFBa0IsTUFBTSxLQUFLLFNBQVMsQ0FBQztBQUFBLElBQzNFO0FBQUE7QUFBQSxFQUVNLGVBQThCO0FBQUE7QUFDbEMsWUFBTSxLQUFLLFNBQVMsS0FBSyxRQUFRO0FBQUEsSUFDbkM7QUFBQTtBQUFBO0FBQUEsRUFJUSxhQUFtQjtBQUN6QixTQUFLLFNBQVM7QUFBQSxNQUNaLEtBQUssU0FBUztBQUFBLE1BQ2QsS0FBSyxTQUFTO0FBQUEsSUFDaEI7QUFBQSxFQUNGO0FBQUEsRUFFYyxvQkFBbUM7QUFBQTtBQUMvQyxZQUFNLEVBQUUsVUFBVSxJQUFJLEtBQUs7QUFHM0IsWUFBTSxXQUFXLFVBQVUsZ0JBQWdCLHVCQUF1QjtBQUNsRSxVQUFJLFNBQVMsU0FBUyxHQUFHO0FBQ3ZCLGtCQUFVLFdBQVcsU0FBUyxDQUFDLENBQUM7QUFDaEM7QUFBQSxNQUNGO0FBR0EsWUFBTSxPQUFPLFVBQVUsYUFBYSxLQUFLO0FBQ3pDLFVBQUksQ0FBQztBQUFNO0FBQ1gsWUFBTSxLQUFLLGFBQWEsRUFBRSxNQUFNLHlCQUF5QixRQUFRLEtBQUssQ0FBQztBQUN2RSxnQkFBVSxXQUFXLElBQUk7QUFBQSxJQUMzQjtBQUFBO0FBQ0Y7IiwKICAibmFtZXMiOiBbImltcG9ydF9vYnNpZGlhbiIsICJpbXBvcnRfb2JzaWRpYW4iXQp9Cg==
