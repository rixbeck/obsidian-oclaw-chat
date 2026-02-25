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
    this.intentionalClose = false;
    this.url = "";
    this.token = "";
    this.requestId = 0;
    this.pendingRequests = /* @__PURE__ */ new Map();
    this.state = "disconnected";
    this.onMessage = null;
    this.onStateChange = null;
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
      const idempotencyKey = `obsidian-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
      yield this._sendRequest("chat.send", {
        sessionKey: this.sessionKey,
        message,
        idempotencyKey
        // deliver defaults to true in gateway; keep default
      });
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
          if ((payload == null ? void 0 : payload.state) && payload.state !== "final") {
            return;
          }
          const msg = payload == null ? void 0 : payload.message;
          const role = (_c = msg == null ? void 0 : msg.role) != null ? _c : "assistant";
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
  static createSystemMessage(content) {
    return {
      id: `sys-${Date.now()}`,
      role: "system",
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
        const connected2 = state === "connected";
        this.statusDot.toggleClass("connected", connected2);
        this.statusDot.title = `Gateway: ${state}`;
        this.sendBtn.disabled = !connected2;
      };
      const connected = this.plugin.wsClient.state === "connected";
      this.statusDot.toggleClass("connected", connected);
      this.sendBtn.disabled = !connected;
      this._renderMessages(this.chatManager.getMessages());
    });
  }
  onClose() {
    return __async(this, null, function* () {
      this.chatManager.onUpdate = null;
      this.chatManager.onMessageAdded = null;
      this.plugin.wsClient.onStateChange = null;
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
      const el = this.messagesEl.createDiv({ cls: `oclaw-message ${msg.role}` });
      el.createSpan({ text: msg.content });
    }
    this.messagesEl.scrollTop = this.messagesEl.scrollHeight;
  }
  /** Appends a single message without rebuilding the DOM (O(1)) */
  _appendMessage(msg) {
    var _a;
    (_a = this.messagesEl.querySelector(".oclaw-placeholder")) == null ? void 0 : _a.remove();
    const el = this.messagesEl.createDiv({ cls: `oclaw-message ${msg.role}` });
    el.createSpan({ text: msg.content });
    this.messagesEl.scrollTop = this.messagesEl.scrollHeight;
  }
  // ── Send handler ──────────────────────────────────────────────────────────
  _handleSend() {
    return __async(this, null, function* () {
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
        this.chatManager.addMessage(
          ChatManager.createSystemMessage(`\u26A0 Send failed: ${err}`)
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
          this.chatManager.addMessage(ChatManager.createSystemMessage(`\u26A0 ${errText}`));
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
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsic3JjL21haW4udHMiLCAic3JjL3NldHRpbmdzLnRzIiwgInNyYy93ZWJzb2NrZXQudHMiLCAic3JjL2NoYXQudHMiLCAic3JjL3ZpZXcudHMiLCAic3JjL2NvbnRleHQudHMiLCAic3JjL3R5cGVzLnRzIl0sCiAgInNvdXJjZXNDb250ZW50IjogWyJpbXBvcnQgeyBOb3RpY2UsIFBsdWdpbiwgV29ya3NwYWNlTGVhZiB9IGZyb20gJ29ic2lkaWFuJztcbmltcG9ydCB7IE9wZW5DbGF3U2V0dGluZ1RhYiB9IGZyb20gJy4vc2V0dGluZ3MnO1xuaW1wb3J0IHsgT2JzaWRpYW5XU0NsaWVudCB9IGZyb20gJy4vd2Vic29ja2V0JztcbmltcG9ydCB7IENoYXRNYW5hZ2VyIH0gZnJvbSAnLi9jaGF0JztcbmltcG9ydCB7IFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFULCBPcGVuQ2xhd0NoYXRWaWV3IH0gZnJvbSAnLi92aWV3JztcbmltcG9ydCB7IERFRkFVTFRfU0VUVElOR1MsIHR5cGUgT3BlbkNsYXdTZXR0aW5ncyB9IGZyb20gJy4vdHlwZXMnO1xuXG5leHBvcnQgZGVmYXVsdCBjbGFzcyBPcGVuQ2xhd1BsdWdpbiBleHRlbmRzIFBsdWdpbiB7XG4gIHNldHRpbmdzITogT3BlbkNsYXdTZXR0aW5ncztcbiAgd3NDbGllbnQhOiBPYnNpZGlhbldTQ2xpZW50O1xuICBjaGF0TWFuYWdlciE6IENoYXRNYW5hZ2VyO1xuXG4gIGFzeW5jIG9ubG9hZCgpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBhd2FpdCB0aGlzLmxvYWRTZXR0aW5ncygpO1xuXG4gICAgdGhpcy53c0NsaWVudCA9IG5ldyBPYnNpZGlhbldTQ2xpZW50KHRoaXMuc2V0dGluZ3Muc2Vzc2lvbktleSk7XG4gICAgdGhpcy5jaGF0TWFuYWdlciA9IG5ldyBDaGF0TWFuYWdlcigpO1xuXG4gICAgLy8gV2lyZSBpbmNvbWluZyBXUyBtZXNzYWdlcyBcdTIxOTIgQ2hhdE1hbmFnZXJcbiAgICB0aGlzLndzQ2xpZW50Lm9uTWVzc2FnZSA9IChtc2cpID0+IHtcbiAgICAgIGlmIChtc2cudHlwZSA9PT0gJ21lc3NhZ2UnKSB7XG4gICAgICAgIHRoaXMuY2hhdE1hbmFnZXIuYWRkTWVzc2FnZShDaGF0TWFuYWdlci5jcmVhdGVBc3Npc3RhbnRNZXNzYWdlKG1zZy5wYXlsb2FkLmNvbnRlbnQpKTtcbiAgICAgIH0gZWxzZSBpZiAobXNnLnR5cGUgPT09ICdlcnJvcicpIHtcbiAgICAgICAgY29uc3QgZXJyVGV4dCA9IG1zZy5wYXlsb2FkLm1lc3NhZ2UgPz8gJ1Vua25vd24gZXJyb3IgZnJvbSBnYXRld2F5JztcbiAgICAgICAgdGhpcy5jaGF0TWFuYWdlci5hZGRNZXNzYWdlKENoYXRNYW5hZ2VyLmNyZWF0ZVN5c3RlbU1lc3NhZ2UoYFx1MjZBMCAke2VyclRleHR9YCkpO1xuICAgICAgfVxuICAgIH07XG5cbiAgICAvLyBSZWdpc3RlciB0aGUgc2lkZWJhciB2aWV3XG4gICAgdGhpcy5yZWdpc3RlclZpZXcoXG4gICAgICBWSUVXX1RZUEVfT1BFTkNMQVdfQ0hBVCxcbiAgICAgIChsZWFmOiBXb3Jrc3BhY2VMZWFmKSA9PiBuZXcgT3BlbkNsYXdDaGF0VmlldyhsZWFmLCB0aGlzKVxuICAgICk7XG5cbiAgICAvLyBSaWJib24gaWNvbiBcdTIwMTQgb3BlbnMgLyByZXZlYWxzIHRoZSBjaGF0IHNpZGViYXJcbiAgICB0aGlzLmFkZFJpYmJvbkljb24oJ21lc3NhZ2Utc3F1YXJlJywgJ09wZW5DbGF3IENoYXQnLCAoKSA9PiB7XG4gICAgICB0aGlzLl9hY3RpdmF0ZUNoYXRWaWV3KCk7XG4gICAgfSk7XG5cbiAgICAvLyBTZXR0aW5ncyB0YWJcbiAgICB0aGlzLmFkZFNldHRpbmdUYWIobmV3IE9wZW5DbGF3U2V0dGluZ1RhYih0aGlzLmFwcCwgdGhpcykpO1xuXG4gICAgLy8gQ29tbWFuZCBwYWxldHRlIGVudHJ5XG4gICAgdGhpcy5hZGRDb21tYW5kKHtcbiAgICAgIGlkOiAnb3Blbi1vcGVuY2xhdy1jaGF0JyxcbiAgICAgIG5hbWU6ICdPcGVuIGNoYXQgc2lkZWJhcicsXG4gICAgICBjYWxsYmFjazogKCkgPT4gdGhpcy5fYWN0aXZhdGVDaGF0VmlldygpLFxuICAgIH0pO1xuXG4gICAgLy8gQ29ubmVjdCB0byBnYXRld2F5IGlmIHRva2VuIGlzIGNvbmZpZ3VyZWRcbiAgICBpZiAodGhpcy5zZXR0aW5ncy5hdXRoVG9rZW4pIHtcbiAgICAgIHRoaXMuX2Nvbm5lY3RXUygpO1xuICAgIH0gZWxzZSB7XG4gICAgICBuZXcgTm90aWNlKCdPcGVuQ2xhdyBDaGF0OiBwbGVhc2UgY29uZmlndXJlIHlvdXIgZ2F0ZXdheSB0b2tlbiBpbiBTZXR0aW5ncy4nKTtcbiAgICB9XG5cbiAgICBjb25zb2xlLmxvZygnW29jbGF3XSBQbHVnaW4gbG9hZGVkJyk7XG4gIH1cblxuICBhc3luYyBvbnVubG9hZCgpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICB0aGlzLndzQ2xpZW50LmRpc2Nvbm5lY3QoKTtcbiAgICB0aGlzLmFwcC53b3Jrc3BhY2UuZGV0YWNoTGVhdmVzT2ZUeXBlKFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFUKTtcbiAgICBjb25zb2xlLmxvZygnW29jbGF3XSBQbHVnaW4gdW5sb2FkZWQnKTtcbiAgfVxuXG4gIGFzeW5jIGxvYWRTZXR0aW5ncygpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICB0aGlzLnNldHRpbmdzID0gT2JqZWN0LmFzc2lnbih7fSwgREVGQVVMVF9TRVRUSU5HUywgYXdhaXQgdGhpcy5sb2FkRGF0YSgpKTtcbiAgfVxuXG4gIGFzeW5jIHNhdmVTZXR0aW5ncygpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBhd2FpdCB0aGlzLnNhdmVEYXRhKHRoaXMuc2V0dGluZ3MpO1xuICB9XG5cbiAgLy8gXHUyNTAwXHUyNTAwIEhlbHBlcnMgXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG5cbiAgcHJpdmF0ZSBfY29ubmVjdFdTKCk6IHZvaWQge1xuICAgIHRoaXMud3NDbGllbnQuY29ubmVjdChcbiAgICAgIHRoaXMuc2V0dGluZ3MuZ2F0ZXdheVVybCxcbiAgICAgIHRoaXMuc2V0dGluZ3MuYXV0aFRva2VuXG4gICAgKTtcbiAgfVxuXG4gIHByaXZhdGUgYXN5bmMgX2FjdGl2YXRlQ2hhdFZpZXcoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgY29uc3QgeyB3b3Jrc3BhY2UgfSA9IHRoaXMuYXBwO1xuXG4gICAgLy8gUmV1c2UgZXhpc3RpbmcgbGVhZiBpZiBhbHJlYWR5IG9wZW5cbiAgICBjb25zdCBleGlzdGluZyA9IHdvcmtzcGFjZS5nZXRMZWF2ZXNPZlR5cGUoVklFV19UWVBFX09QRU5DTEFXX0NIQVQpO1xuICAgIGlmIChleGlzdGluZy5sZW5ndGggPiAwKSB7XG4gICAgICB3b3Jrc3BhY2UucmV2ZWFsTGVhZihleGlzdGluZ1swXSk7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgLy8gT3BlbiBpbiByaWdodCBzaWRlYmFyXG4gICAgY29uc3QgbGVhZiA9IHdvcmtzcGFjZS5nZXRSaWdodExlYWYoZmFsc2UpO1xuICAgIGlmICghbGVhZikgcmV0dXJuO1xuICAgIGF3YWl0IGxlYWYuc2V0Vmlld1N0YXRlKHsgdHlwZTogVklFV19UWVBFX09QRU5DTEFXX0NIQVQsIGFjdGl2ZTogdHJ1ZSB9KTtcbiAgICB3b3Jrc3BhY2UucmV2ZWFsTGVhZihsZWFmKTtcbiAgfVxufVxuIiwgImltcG9ydCB7IEFwcCwgUGx1Z2luU2V0dGluZ1RhYiwgU2V0dGluZyB9IGZyb20gJ29ic2lkaWFuJztcbmltcG9ydCB0eXBlIE9wZW5DbGF3UGx1Z2luIGZyb20gJy4vbWFpbic7XG5cbmV4cG9ydCBjbGFzcyBPcGVuQ2xhd1NldHRpbmdUYWIgZXh0ZW5kcyBQbHVnaW5TZXR0aW5nVGFiIHtcbiAgcGx1Z2luOiBPcGVuQ2xhd1BsdWdpbjtcblxuICBjb25zdHJ1Y3RvcihhcHA6IEFwcCwgcGx1Z2luOiBPcGVuQ2xhd1BsdWdpbikge1xuICAgIHN1cGVyKGFwcCwgcGx1Z2luKTtcbiAgICB0aGlzLnBsdWdpbiA9IHBsdWdpbjtcbiAgfVxuXG4gIGRpc3BsYXkoKTogdm9pZCB7XG4gICAgY29uc3QgeyBjb250YWluZXJFbCB9ID0gdGhpcztcbiAgICBjb250YWluZXJFbC5lbXB0eSgpO1xuXG4gICAgY29udGFpbmVyRWwuY3JlYXRlRWwoJ2gyJywgeyB0ZXh0OiAnT3BlbkNsYXcgQ2hhdCBcdTIwMTMgU2V0dGluZ3MnIH0pO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZSgnR2F0ZXdheSBVUkwnKVxuICAgICAgLnNldERlc2MoJ1dlYlNvY2tldCBVUkwgb2YgdGhlIE9wZW5DbGF3IEdhdGV3YXkgKGUuZy4gd3M6Ly9ob3N0bmFtZToxODc4OSkuJylcbiAgICAgIC5hZGRUZXh0KCh0ZXh0KSA9PlxuICAgICAgICB0ZXh0XG4gICAgICAgICAgLnNldFBsYWNlaG9sZGVyKCd3czovL2xvY2FsaG9zdDoxODc4OScpXG4gICAgICAgICAgLnNldFZhbHVlKHRoaXMucGx1Z2luLnNldHRpbmdzLmdhdGV3YXlVcmwpXG4gICAgICAgICAgLm9uQ2hhbmdlKGFzeW5jICh2YWx1ZSkgPT4ge1xuICAgICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3MuZ2F0ZXdheVVybCA9IHZhbHVlLnRyaW0oKTtcbiAgICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICAgIH0pXG4gICAgICApO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZSgnQXV0aCB0b2tlbicpXG4gICAgICAuc2V0RGVzYygnTXVzdCBtYXRjaCB0aGUgYXV0aFRva2VuIGluIHlvdXIgb3BlbmNsYXcuanNvbiBjaGFubmVsIGNvbmZpZy4gTmV2ZXIgc2hhcmVkLicpXG4gICAgICAuYWRkVGV4dCgodGV4dCkgPT4ge1xuICAgICAgICB0ZXh0XG4gICAgICAgICAgLnNldFBsYWNlaG9sZGVyKCdFbnRlciB0b2tlblx1MjAyNicpXG4gICAgICAgICAgLnNldFZhbHVlKHRoaXMucGx1Z2luLnNldHRpbmdzLmF1dGhUb2tlbilcbiAgICAgICAgICAub25DaGFuZ2UoYXN5bmMgKHZhbHVlKSA9PiB7XG4gICAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5hdXRoVG9rZW4gPSB2YWx1ZTtcbiAgICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICAgIH0pO1xuICAgICAgICAvLyBUcmVhdCBhcyBwYXNzd29yZCBmaWVsZCBcdTIwMTMgZG8gbm90IHJldmVhbCB0b2tlbiBpbiBVSVxuICAgICAgICB0ZXh0LmlucHV0RWwudHlwZSA9ICdwYXNzd29yZCc7XG4gICAgICAgIHRleHQuaW5wdXRFbC5hdXRvY29tcGxldGUgPSAnb2ZmJztcbiAgICAgIH0pO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZSgnU2Vzc2lvbiBLZXknKVxuICAgICAgLnNldERlc2MoJ09wZW5DbGF3IHNlc3Npb24gdG8gc3Vic2NyaWJlIHRvICh1c3VhbGx5IFwibWFpblwiKS4nKVxuICAgICAgLmFkZFRleHQoKHRleHQpID0+XG4gICAgICAgIHRleHRcbiAgICAgICAgICAuc2V0UGxhY2Vob2xkZXIoJ21haW4nKVxuICAgICAgICAgIC5zZXRWYWx1ZSh0aGlzLnBsdWdpbi5zZXR0aW5ncy5zZXNzaW9uS2V5KVxuICAgICAgICAgIC5vbkNoYW5nZShhc3luYyAodmFsdWUpID0+IHtcbiAgICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLnNlc3Npb25LZXkgPSB2YWx1ZS50cmltKCkgfHwgJ21haW4nO1xuICAgICAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uc2F2ZVNldHRpbmdzKCk7XG4gICAgICAgICAgfSlcbiAgICAgICk7XG5cbiAgICBuZXcgU2V0dGluZyhjb250YWluZXJFbClcbiAgICAgIC5zZXROYW1lKCdBY2NvdW50IElEJylcbiAgICAgIC5zZXREZXNjKCdPcGVuQ2xhdyBhY2NvdW50IElEICh1c3VhbGx5IFwibWFpblwiKS4nKVxuICAgICAgLmFkZFRleHQoKHRleHQpID0+XG4gICAgICAgIHRleHRcbiAgICAgICAgICAuc2V0UGxhY2Vob2xkZXIoJ21haW4nKVxuICAgICAgICAgIC5zZXRWYWx1ZSh0aGlzLnBsdWdpbi5zZXR0aW5ncy5hY2NvdW50SWQpXG4gICAgICAgICAgLm9uQ2hhbmdlKGFzeW5jICh2YWx1ZSkgPT4ge1xuICAgICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3MuYWNjb3VudElkID0gdmFsdWUudHJpbSgpIHx8ICdtYWluJztcbiAgICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICAgIH0pXG4gICAgICApO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZSgnSW5jbHVkZSBhY3RpdmUgbm90ZSBieSBkZWZhdWx0JylcbiAgICAgIC5zZXREZXNjKCdQcmUtY2hlY2sgXCJJbmNsdWRlIGFjdGl2ZSBub3RlXCIgaW4gdGhlIGNoYXQgcGFuZWwgd2hlbiBpdCBvcGVucy4nKVxuICAgICAgLmFkZFRvZ2dsZSgodG9nZ2xlKSA9PlxuICAgICAgICB0b2dnbGUuc2V0VmFsdWUodGhpcy5wbHVnaW4uc2V0dGluZ3MuaW5jbHVkZUFjdGl2ZU5vdGUpLm9uQ2hhbmdlKGFzeW5jICh2YWx1ZSkgPT4ge1xuICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLmluY2x1ZGVBY3RpdmVOb3RlID0gdmFsdWU7XG4gICAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uc2F2ZVNldHRpbmdzKCk7XG4gICAgICAgIH0pXG4gICAgICApO1xuXG4gICAgY29udGFpbmVyRWwuY3JlYXRlRWwoJ3AnLCB7XG4gICAgICB0ZXh0OiAnUmVjb25uZWN0OiBjbG9zZSBhbmQgcmVvcGVuIHRoZSBzaWRlYmFyIGFmdGVyIGNoYW5naW5nIHRoZSBnYXRld2F5IFVSTCBvciB0b2tlbi4nLFxuICAgICAgY2xzOiAnc2V0dGluZy1pdGVtLWRlc2NyaXB0aW9uJyxcbiAgICB9KTtcbiAgfVxufVxuIiwgIi8qKlxuICogV2ViU29ja2V0IGNsaWVudCBmb3IgT3BlbkNsYXcgR2F0ZXdheVxuICpcbiAqIFBpdm90ICgyMDI2LTAyLTI1KTogRG8gTk9UIHVzZSBjdXN0b20gb2JzaWRpYW4uKiBnYXRld2F5IG1ldGhvZHMuXG4gKiBUaG9zZSByZXF1aXJlIG9wZXJhdG9yLmFkbWluIHNjb3BlIHdoaWNoIGlzIG5vdCBncmFudGVkIHRvIGV4dGVybmFsIGNsaWVudHMuXG4gKlxuICogQXV0aCBub3RlOlxuICogLSBjaGF0LnNlbmQgcmVxdWlyZXMgb3BlcmF0b3Iud3JpdGVcbiAqIC0gZXh0ZXJuYWwgY2xpZW50cyBtdXN0IHByZXNlbnQgYSBwYWlyZWQgZGV2aWNlIGlkZW50aXR5IHRvIHJlY2VpdmUgd3JpdGUgc2NvcGVzXG4gKlxuICogV2UgdXNlIGJ1aWx0LWluIGdhdGV3YXkgbWV0aG9kcy9ldmVudHM6XG4gKiAtIFNlbmQ6IGNoYXQuc2VuZCh7IHNlc3Npb25LZXksIG1lc3NhZ2UsIGlkZW1wb3RlbmN5S2V5LCAuLi4gfSlcbiAqIC0gUmVjZWl2ZTogZXZlbnQgXCJjaGF0XCIgKGZpbHRlciBieSBzZXNzaW9uS2V5KVxuICovXG5cbmltcG9ydCB0eXBlIHsgSW5ib3VuZFdTUGF5bG9hZCB9IGZyb20gJy4vdHlwZXMnO1xuXG4vKiogTWlsbGlzZWNvbmRzIGJlZm9yZSBhIHJlY29ubmVjdCBhdHRlbXB0IGFmdGVyIGFuIHVuZXhwZWN0ZWQgY2xvc2UgKi9cbmNvbnN0IFJFQ09OTkVDVF9ERUxBWV9NUyA9IDNfMDAwO1xuLyoqIEludGVydmFsIGZvciBzZW5kaW5nIGhlYXJ0YmVhdCBwaW5ncyAoY2hlY2sgY29ubmVjdGlvbiBsaXZlbmVzcykgKi9cbmNvbnN0IEhFQVJUQkVBVF9JTlRFUlZBTF9NUyA9IDMwXzAwMDtcblxuZXhwb3J0IHR5cGUgV1NDbGllbnRTdGF0ZSA9ICdkaXNjb25uZWN0ZWQnIHwgJ2Nvbm5lY3RpbmcnIHwgJ2hhbmRzaGFraW5nJyB8ICdjb25uZWN0ZWQnO1xuXG5pbnRlcmZhY2UgUGVuZGluZ1JlcXVlc3Qge1xuICByZXNvbHZlOiAocGF5bG9hZDogYW55KSA9PiB2b2lkO1xuICByZWplY3Q6IChlcnJvcjogYW55KSA9PiB2b2lkO1xufVxuXG50eXBlIERldmljZUlkZW50aXR5ID0ge1xuICBpZDogc3RyaW5nO1xuICBwdWJsaWNLZXk6IHN0cmluZzsgLy8gYmFzZTY0XG4gIHByaXZhdGVLZXlKd2s6IEpzb25XZWJLZXk7XG59O1xuXG5jb25zdCBERVZJQ0VfU1RPUkFHRV9LRVkgPSAnb3BlbmNsYXdDaGF0LmRldmljZUlkZW50aXR5LnYxJztcblxuZnVuY3Rpb24gYmFzZTY0VXJsRW5jb2RlKGJ5dGVzOiBBcnJheUJ1ZmZlcik6IHN0cmluZyB7XG4gIGNvbnN0IHU4ID0gbmV3IFVpbnQ4QXJyYXkoYnl0ZXMpO1xuICBsZXQgcyA9ICcnO1xuICBmb3IgKGxldCBpID0gMDsgaSA8IHU4Lmxlbmd0aDsgaSsrKSBzICs9IFN0cmluZy5mcm9tQ2hhckNvZGUodThbaV0pO1xuICBjb25zdCBiNjQgPSBidG9hKHMpO1xuICByZXR1cm4gYjY0LnJlcGxhY2UoL1xcKy9nLCAnLScpLnJlcGxhY2UoL1xcLy9nLCAnXycpLnJlcGxhY2UoLz0rJC9nLCAnJyk7XG59XG5cbmZ1bmN0aW9uIGhleEVuY29kZShieXRlczogQXJyYXlCdWZmZXIpOiBzdHJpbmcge1xuICBjb25zdCB1OCA9IG5ldyBVaW50OEFycmF5KGJ5dGVzKTtcbiAgcmV0dXJuIEFycmF5LmZyb20odTgpXG4gICAgLm1hcCgoYikgPT4gYi50b1N0cmluZygxNikucGFkU3RhcnQoMiwgJzAnKSlcbiAgICAuam9pbignJyk7XG59XG5cbmZ1bmN0aW9uIHV0ZjhCeXRlcyh0ZXh0OiBzdHJpbmcpOiBVaW50OEFycmF5IHtcbiAgcmV0dXJuIG5ldyBUZXh0RW5jb2RlcigpLmVuY29kZSh0ZXh0KTtcbn1cblxuYXN5bmMgZnVuY3Rpb24gc2hhMjU2SGV4KGJ5dGVzOiBBcnJheUJ1ZmZlcik6IFByb21pc2U8c3RyaW5nPiB7XG4gIGNvbnN0IGRpZ2VzdCA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuZGlnZXN0KCdTSEEtMjU2JywgYnl0ZXMpO1xuICByZXR1cm4gaGV4RW5jb2RlKGRpZ2VzdCk7XG59XG5cbmFzeW5jIGZ1bmN0aW9uIGxvYWRPckNyZWF0ZURldmljZUlkZW50aXR5KCk6IFByb21pc2U8RGV2aWNlSWRlbnRpdHk+IHtcbiAgY29uc3QgZXhpc3RpbmcgPSBsb2NhbFN0b3JhZ2UuZ2V0SXRlbShERVZJQ0VfU1RPUkFHRV9LRVkpO1xuICBpZiAoZXhpc3RpbmcpIHtcbiAgICBjb25zdCBwYXJzZWQgPSBKU09OLnBhcnNlKGV4aXN0aW5nKSBhcyBEZXZpY2VJZGVudGl0eTtcbiAgICBpZiAocGFyc2VkPy5pZCAmJiBwYXJzZWQ/LnB1YmxpY0tleSAmJiBwYXJzZWQ/LnByaXZhdGVLZXlKd2spIHJldHVybiBwYXJzZWQ7XG4gIH1cblxuICBjb25zdCBrZXlQYWlyID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5nZW5lcmF0ZUtleSh7IG5hbWU6ICdFZDI1NTE5JyB9LCB0cnVlLCBbJ3NpZ24nLCAndmVyaWZ5J10pO1xuICBjb25zdCBwdWJSYXcgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmV4cG9ydEtleSgncmF3Jywga2V5UGFpci5wdWJsaWNLZXkpO1xuICBjb25zdCBwcml2SndrID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5leHBvcnRLZXkoJ2p3aycsIGtleVBhaXIucHJpdmF0ZUtleSk7XG5cbiAgLy8gSU1QT1JUQU5UOiBkZXZpY2UuaWQgbXVzdCBiZSBhIHN0YWJsZSBmaW5nZXJwcmludCBmb3IgdGhlIHB1YmxpYyBrZXkuXG4gIC8vIFRoZSBnYXRld2F5IGVuZm9yY2VzIGRldmljZUlkIFx1MjE5NCBwdWJsaWNLZXkgYmluZGluZzsgcmFuZG9tIGlkcyBjYW4gY2F1c2UgXCJkZXZpY2UgaWRlbnRpdHkgbWlzbWF0Y2hcIi5cbiAgY29uc3QgZGV2aWNlSWQgPSBhd2FpdCBzaGEyNTZIZXgocHViUmF3KTtcbiAgY29uc3QgaWQgPSBkZXZpY2VJZDtcblxuICBjb25zdCBpZGVudGl0eTogRGV2aWNlSWRlbnRpdHkgPSB7XG4gICAgaWQsXG4gICAgcHVibGljS2V5OiBiYXNlNjRVcmxFbmNvZGUocHViUmF3KSxcbiAgICBwcml2YXRlS2V5SndrOiBwcml2SndrLFxuICB9O1xuXG4gIGxvY2FsU3RvcmFnZS5zZXRJdGVtKERFVklDRV9TVE9SQUdFX0tFWSwgSlNPTi5zdHJpbmdpZnkoaWRlbnRpdHkpKTtcbiAgcmV0dXJuIGlkZW50aXR5O1xufVxuXG5mdW5jdGlvbiBidWlsZERldmljZUF1dGhQYXlsb2FkKHBhcmFtczoge1xuICBkZXZpY2VJZDogc3RyaW5nO1xuICBjbGllbnRJZDogc3RyaW5nO1xuICBjbGllbnRNb2RlOiBzdHJpbmc7XG4gIHJvbGU6IHN0cmluZztcbiAgc2NvcGVzOiBzdHJpbmdbXTtcbiAgc2lnbmVkQXRNczogbnVtYmVyO1xuICB0b2tlbjogc3RyaW5nO1xuICBub25jZT86IHN0cmluZztcbn0pOiBzdHJpbmcge1xuICBjb25zdCB2ZXJzaW9uID0gcGFyYW1zLm5vbmNlID8gJ3YyJyA6ICd2MSc7XG4gIGNvbnN0IHNjb3BlcyA9IHBhcmFtcy5zY29wZXMuam9pbignLCcpO1xuICBjb25zdCBiYXNlID0gW1xuICAgIHZlcnNpb24sXG4gICAgcGFyYW1zLmRldmljZUlkLFxuICAgIHBhcmFtcy5jbGllbnRJZCxcbiAgICBwYXJhbXMuY2xpZW50TW9kZSxcbiAgICBwYXJhbXMucm9sZSxcbiAgICBzY29wZXMsXG4gICAgU3RyaW5nKHBhcmFtcy5zaWduZWRBdE1zKSxcbiAgICBwYXJhbXMudG9rZW4gfHwgJycsXG4gIF07XG4gIGlmICh2ZXJzaW9uID09PSAndjInKSBiYXNlLnB1c2gocGFyYW1zLm5vbmNlIHx8ICcnKTtcbiAgcmV0dXJuIGJhc2Uuam9pbignfCcpO1xufVxuXG5hc3luYyBmdW5jdGlvbiBzaWduRGV2aWNlUGF5bG9hZChpZGVudGl0eTogRGV2aWNlSWRlbnRpdHksIHBheWxvYWQ6IHN0cmluZyk6IFByb21pc2U8eyBzaWduYXR1cmU6IHN0cmluZzsgc2lnbmVkQXQ6IG51bWJlciB9PiB7XG4gIGNvbnN0IHByaXZhdGVLZXkgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmltcG9ydEtleShcbiAgICAnandrJyxcbiAgICBpZGVudGl0eS5wcml2YXRlS2V5SndrLFxuICAgIHsgbmFtZTogJ0VkMjU1MTknIH0sXG4gICAgZmFsc2UsXG4gICAgWydzaWduJ10sXG4gICk7XG5cbiAgY29uc3Qgc2lnbmVkQXQgPSBEYXRlLm5vdygpO1xuICBjb25zdCBzaWcgPSBhd2FpdCBjcnlwdG8uc3VidGxlLnNpZ24oeyBuYW1lOiAnRWQyNTUxOScgfSwgcHJpdmF0ZUtleSwgdXRmOEJ5dGVzKHBheWxvYWQpKTtcbiAgcmV0dXJuIHsgc2lnbmF0dXJlOiBiYXNlNjRVcmxFbmNvZGUoc2lnKSwgc2lnbmVkQXQgfTtcbn1cblxuZnVuY3Rpb24gZXh0cmFjdFRleHRGcm9tR2F0ZXdheU1lc3NhZ2UobXNnOiBhbnkpOiBzdHJpbmcge1xuICBpZiAoIW1zZykgcmV0dXJuICcnO1xuXG4gIC8vIE1vc3QgY29tbW9uOiB7IHJvbGUsIGNvbnRlbnQgfSB3aGVyZSBjb250ZW50IGNhbiBiZSBzdHJpbmcgb3IgW3t0eXBlOid0ZXh0Jyx0ZXh0OicuLi4nfV1cbiAgY29uc3QgY29udGVudCA9IG1zZy5jb250ZW50ID8/IG1zZy5tZXNzYWdlID8/IG1zZztcbiAgaWYgKHR5cGVvZiBjb250ZW50ID09PSAnc3RyaW5nJykgcmV0dXJuIGNvbnRlbnQ7XG5cbiAgaWYgKEFycmF5LmlzQXJyYXkoY29udGVudCkpIHtcbiAgICBjb25zdCBwYXJ0cyA9IGNvbnRlbnRcbiAgICAgIC5maWx0ZXIoKGMpID0+IGMgJiYgdHlwZW9mIGMgPT09ICdvYmplY3QnICYmIGMudHlwZSA9PT0gJ3RleHQnICYmIHR5cGVvZiBjLnRleHQgPT09ICdzdHJpbmcnKVxuICAgICAgLm1hcCgoYykgPT4gYy50ZXh0KTtcbiAgICByZXR1cm4gcGFydHMuam9pbignXFxuJyk7XG4gIH1cblxuICAvLyBGYWxsYmFja1xuICB0cnkge1xuICAgIHJldHVybiBKU09OLnN0cmluZ2lmeShjb250ZW50KTtcbiAgfSBjYXRjaCB7XG4gICAgcmV0dXJuIFN0cmluZyhjb250ZW50KTtcbiAgfVxufVxuXG5mdW5jdGlvbiBzZXNzaW9uS2V5TWF0Y2hlcyhjb25maWd1cmVkOiBzdHJpbmcsIGluY29taW5nOiBzdHJpbmcpOiBib29sZWFuIHtcbiAgaWYgKGluY29taW5nID09PSBjb25maWd1cmVkKSByZXR1cm4gdHJ1ZTtcbiAgLy8gT3BlbkNsYXcgcmVzb2x2ZXMgXCJtYWluXCIgdG8gY2Fub25pY2FsIHNlc3Npb24ga2V5IGxpa2UgXCJhZ2VudDptYWluOm1haW5cIi5cbiAgaWYgKGNvbmZpZ3VyZWQgPT09ICdtYWluJyAmJiBpbmNvbWluZyA9PT0gJ2FnZW50Om1haW46bWFpbicpIHJldHVybiB0cnVlO1xuICByZXR1cm4gZmFsc2U7XG59XG5cbmV4cG9ydCBjbGFzcyBPYnNpZGlhbldTQ2xpZW50IHtcbiAgcHJpdmF0ZSB3czogV2ViU29ja2V0IHwgbnVsbCA9IG51bGw7XG4gIHByaXZhdGUgcmVjb25uZWN0VGltZXI6IFJldHVyblR5cGU8dHlwZW9mIHNldFRpbWVvdXQ+IHwgbnVsbCA9IG51bGw7XG4gIHByaXZhdGUgaGVhcnRiZWF0VGltZXI6IFJldHVyblR5cGU8dHlwZW9mIHNldEludGVydmFsPiB8IG51bGwgPSBudWxsO1xuICBwcml2YXRlIGludGVudGlvbmFsQ2xvc2UgPSBmYWxzZTtcbiAgcHJpdmF0ZSBzZXNzaW9uS2V5OiBzdHJpbmc7XG4gIHByaXZhdGUgdXJsID0gJyc7XG4gIHByaXZhdGUgdG9rZW4gPSAnJztcbiAgcHJpdmF0ZSByZXF1ZXN0SWQgPSAwO1xuICBwcml2YXRlIHBlbmRpbmdSZXF1ZXN0cyA9IG5ldyBNYXA8c3RyaW5nLCBQZW5kaW5nUmVxdWVzdD4oKTtcblxuICBzdGF0ZTogV1NDbGllbnRTdGF0ZSA9ICdkaXNjb25uZWN0ZWQnO1xuXG4gIG9uTWVzc2FnZTogKChtc2c6IEluYm91bmRXU1BheWxvYWQpID0+IHZvaWQpIHwgbnVsbCA9IG51bGw7XG4gIG9uU3RhdGVDaGFuZ2U6ICgoc3RhdGU6IFdTQ2xpZW50U3RhdGUpID0+IHZvaWQpIHwgbnVsbCA9IG51bGw7XG5cbiAgY29uc3RydWN0b3Ioc2Vzc2lvbktleTogc3RyaW5nKSB7XG4gICAgdGhpcy5zZXNzaW9uS2V5ID0gc2Vzc2lvbktleTtcbiAgfVxuXG4gIGNvbm5lY3QodXJsOiBzdHJpbmcsIHRva2VuOiBzdHJpbmcpOiB2b2lkIHtcbiAgICB0aGlzLnVybCA9IHVybDtcbiAgICB0aGlzLnRva2VuID0gdG9rZW47XG4gICAgdGhpcy5pbnRlbnRpb25hbENsb3NlID0gZmFsc2U7XG4gICAgdGhpcy5fY29ubmVjdCgpO1xuICB9XG5cbiAgZGlzY29ubmVjdCgpOiB2b2lkIHtcbiAgICB0aGlzLmludGVudGlvbmFsQ2xvc2UgPSB0cnVlO1xuICAgIHRoaXMuX3N0b3BUaW1lcnMoKTtcbiAgICBpZiAodGhpcy53cykge1xuICAgICAgdGhpcy53cy5jbG9zZSgpO1xuICAgICAgdGhpcy53cyA9IG51bGw7XG4gICAgfVxuICAgIHRoaXMuX3NldFN0YXRlKCdkaXNjb25uZWN0ZWQnKTtcbiAgfVxuXG4gIGFzeW5jIHNlbmRNZXNzYWdlKG1lc3NhZ2U6IHN0cmluZyk6IFByb21pc2U8dm9pZD4ge1xuICAgIGlmICh0aGlzLnN0YXRlICE9PSAnY29ubmVjdGVkJykge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKCdOb3QgY29ubmVjdGVkIFx1MjAxNCBjYWxsIGNvbm5lY3QoKSBmaXJzdCcpO1xuICAgIH1cblxuICAgIGNvbnN0IGlkZW1wb3RlbmN5S2V5ID0gYG9ic2lkaWFuLSR7RGF0ZS5ub3coKX0tJHtNYXRoLnJhbmRvbSgpLnRvU3RyaW5nKDM2KS5zbGljZSgyLCA5KX1gO1xuXG4gICAgYXdhaXQgdGhpcy5fc2VuZFJlcXVlc3QoJ2NoYXQuc2VuZCcsIHtcbiAgICAgIHNlc3Npb25LZXk6IHRoaXMuc2Vzc2lvbktleSxcbiAgICAgIG1lc3NhZ2UsXG4gICAgICBpZGVtcG90ZW5jeUtleSxcbiAgICAgIC8vIGRlbGl2ZXIgZGVmYXVsdHMgdG8gdHJ1ZSBpbiBnYXRld2F5OyBrZWVwIGRlZmF1bHRcbiAgICB9KTtcbiAgfVxuXG4gIHByaXZhdGUgX2Nvbm5lY3QoKTogdm9pZCB7XG4gICAgaWYgKHRoaXMud3MpIHtcbiAgICAgIHRoaXMud3Mub25vcGVuID0gbnVsbDtcbiAgICAgIHRoaXMud3Mub25jbG9zZSA9IG51bGw7XG4gICAgICB0aGlzLndzLm9ubWVzc2FnZSA9IG51bGw7XG4gICAgICB0aGlzLndzLm9uZXJyb3IgPSBudWxsO1xuICAgICAgdGhpcy53cy5jbG9zZSgpO1xuICAgICAgdGhpcy53cyA9IG51bGw7XG4gICAgfVxuXG4gICAgdGhpcy5fc2V0U3RhdGUoJ2Nvbm5lY3RpbmcnKTtcblxuICAgIGNvbnN0IHdzID0gbmV3IFdlYlNvY2tldCh0aGlzLnVybCk7XG4gICAgdGhpcy53cyA9IHdzO1xuXG4gICAgbGV0IGNvbm5lY3ROb25jZTogc3RyaW5nIHwgbnVsbCA9IG51bGw7XG4gICAgbGV0IGNvbm5lY3RTdGFydGVkID0gZmFsc2U7XG5cbiAgICBjb25zdCB0cnlDb25uZWN0ID0gYXN5bmMgKCkgPT4ge1xuICAgICAgaWYgKGNvbm5lY3RTdGFydGVkKSByZXR1cm47XG4gICAgICBpZiAoIWNvbm5lY3ROb25jZSkgcmV0dXJuO1xuICAgICAgY29ubmVjdFN0YXJ0ZWQgPSB0cnVlO1xuXG4gICAgICB0cnkge1xuICAgICAgICBjb25zdCBpZGVudGl0eSA9IGF3YWl0IGxvYWRPckNyZWF0ZURldmljZUlkZW50aXR5KCk7XG4gICAgICAgIGNvbnN0IHNpZ25lZEF0TXMgPSBEYXRlLm5vdygpO1xuICAgICAgICBjb25zdCBwYXlsb2FkID0gYnVpbGREZXZpY2VBdXRoUGF5bG9hZCh7XG4gICAgICAgICAgZGV2aWNlSWQ6IGlkZW50aXR5LmlkLFxuICAgICAgICAgIGNsaWVudElkOiAnZ2F0ZXdheS1jbGllbnQnLFxuICAgICAgICAgIGNsaWVudE1vZGU6ICdiYWNrZW5kJyxcbiAgICAgICAgICByb2xlOiAnb3BlcmF0b3InLFxuICAgICAgICAgIHNjb3BlczogWydvcGVyYXRvci5yZWFkJywgJ29wZXJhdG9yLndyaXRlJ10sXG4gICAgICAgICAgc2lnbmVkQXRNcyxcbiAgICAgICAgICB0b2tlbjogdGhpcy50b2tlbixcbiAgICAgICAgICBub25jZTogY29ubmVjdE5vbmNlLFxuICAgICAgICB9KTtcbiAgICAgICAgY29uc3Qgc2lnID0gYXdhaXQgc2lnbkRldmljZVBheWxvYWQoaWRlbnRpdHksIHBheWxvYWQpO1xuXG4gICAgICAgIGF3YWl0IHRoaXMuX3NlbmRSZXF1ZXN0KCdjb25uZWN0Jywge1xuICAgICAgICAgIG1pblByb3RvY29sOiAzLFxuICAgICAgICAgIG1heFByb3RvY29sOiAzLFxuICAgICAgICAgIGNsaWVudDoge1xuICAgICAgICAgICAgaWQ6ICdnYXRld2F5LWNsaWVudCcsXG4gICAgICAgICAgICBtb2RlOiAnYmFja2VuZCcsXG4gICAgICAgICAgICB2ZXJzaW9uOiAnMC4xLjEwJyxcbiAgICAgICAgICAgIHBsYXRmb3JtOiAnZWxlY3Ryb24nLFxuICAgICAgICAgIH0sXG4gICAgICAgICAgcm9sZTogJ29wZXJhdG9yJyxcbiAgICAgICAgICBzY29wZXM6IFsnb3BlcmF0b3IucmVhZCcsICdvcGVyYXRvci53cml0ZSddLFxuICAgICAgICAgIGRldmljZToge1xuICAgICAgICAgICAgaWQ6IGlkZW50aXR5LmlkLFxuICAgICAgICAgICAgcHVibGljS2V5OiBpZGVudGl0eS5wdWJsaWNLZXksXG4gICAgICAgICAgICBzaWduYXR1cmU6IHNpZy5zaWduYXR1cmUsXG4gICAgICAgICAgICBzaWduZWRBdDogc2lnbmVkQXRNcyxcbiAgICAgICAgICAgIG5vbmNlOiBjb25uZWN0Tm9uY2UsXG4gICAgICAgICAgfSxcbiAgICAgICAgICBhdXRoOiB7XG4gICAgICAgICAgICB0b2tlbjogdGhpcy50b2tlbixcbiAgICAgICAgICB9LFxuICAgICAgICB9KTtcblxuICAgICAgICB0aGlzLl9zZXRTdGF0ZSgnY29ubmVjdGVkJyk7XG4gICAgICAgIHRoaXMuX3N0YXJ0SGVhcnRiZWF0KCk7XG4gICAgICB9IGNhdGNoIChlcnIpIHtcbiAgICAgICAgY29uc29sZS5lcnJvcignW29jbGF3LXdzXSBDb25uZWN0IGhhbmRzaGFrZSBmYWlsZWQnLCBlcnIpO1xuICAgICAgICB3cy5jbG9zZSgpO1xuICAgICAgfVxuICAgIH07XG5cbiAgICB3cy5vbm9wZW4gPSAoKSA9PiB7XG4gICAgICB0aGlzLl9zZXRTdGF0ZSgnaGFuZHNoYWtpbmcnKTtcbiAgICAgIC8vIFRoZSBnYXRld2F5IHdpbGwgc2VuZCBjb25uZWN0LmNoYWxsZW5nZTsgY29ubmVjdCBpcyBzZW50IG9uY2Ugd2UgaGF2ZSBhIG5vbmNlLlxuICAgIH07XG5cbiAgICB3cy5vbm1lc3NhZ2UgPSAoZXZlbnQ6IE1lc3NhZ2VFdmVudCkgPT4ge1xuICAgICAgbGV0IGZyYW1lOiBhbnk7XG4gICAgICB0cnkge1xuICAgICAgICBmcmFtZSA9IEpTT04ucGFyc2UoZXZlbnQuZGF0YSBhcyBzdHJpbmcpO1xuICAgICAgfSBjYXRjaCB7XG4gICAgICAgIGNvbnNvbGUuZXJyb3IoJ1tvY2xhdy13c10gRmFpbGVkIHRvIHBhcnNlIGluY29taW5nIG1lc3NhZ2UnKTtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuXG4gICAgICAvLyBSZXNwb25zZXNcbiAgICAgIGlmIChmcmFtZS50eXBlID09PSAncmVzJykge1xuICAgICAgICBjb25zdCBwZW5kaW5nID0gdGhpcy5wZW5kaW5nUmVxdWVzdHMuZ2V0KGZyYW1lLmlkKTtcbiAgICAgICAgaWYgKHBlbmRpbmcpIHtcbiAgICAgICAgICB0aGlzLnBlbmRpbmdSZXF1ZXN0cy5kZWxldGUoZnJhbWUuaWQpO1xuICAgICAgICAgIGlmIChmcmFtZS5vaykgcGVuZGluZy5yZXNvbHZlKGZyYW1lLnBheWxvYWQpO1xuICAgICAgICAgIGVsc2UgcGVuZGluZy5yZWplY3QobmV3IEVycm9yKGZyYW1lLmVycm9yPy5tZXNzYWdlIHx8ICdSZXF1ZXN0IGZhaWxlZCcpKTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm47XG4gICAgICB9XG5cbiAgICAgIC8vIEV2ZW50c1xuICAgICAgaWYgKGZyYW1lLnR5cGUgPT09ICdldmVudCcpIHtcbiAgICAgICAgaWYgKGZyYW1lLmV2ZW50ID09PSAnY29ubmVjdC5jaGFsbGVuZ2UnKSB7XG4gICAgICAgICAgY29ubmVjdE5vbmNlID0gZnJhbWUucGF5bG9hZD8ubm9uY2UgfHwgbnVsbDtcbiAgICAgICAgICAvLyBBdHRlbXB0IGhhbmRzaGFrZSBvbmNlIHdlIGhhdmUgYSBub25jZS5cbiAgICAgICAgICB2b2lkIHRyeUNvbm5lY3QoKTtcbiAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoZnJhbWUuZXZlbnQgPT09ICdjaGF0Jykge1xuICAgICAgICAgIGNvbnN0IHBheWxvYWQgPSBmcmFtZS5wYXlsb2FkO1xuICAgICAgICAgIGNvbnN0IGluY29taW5nU2Vzc2lvbktleSA9IFN0cmluZyhwYXlsb2FkPy5zZXNzaW9uS2V5IHx8ICcnKTtcbiAgICAgICAgICBpZiAoIWluY29taW5nU2Vzc2lvbktleSB8fCAhc2Vzc2lvbktleU1hdGNoZXModGhpcy5zZXNzaW9uS2V5LCBpbmNvbWluZ1Nlc3Npb25LZXkpKSB7XG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgLy8gQXZvaWQgZG91YmxlLXJlbmRlcjogZ2F0ZXdheSBlbWl0cyBkZWx0YSArIGZpbmFsLiBSZW5kZXIgb25seSBmaW5hbC5cbiAgICAgICAgICBpZiAocGF5bG9hZD8uc3RhdGUgJiYgcGF5bG9hZC5zdGF0ZSAhPT0gJ2ZpbmFsJykge1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIC8vIFdlIG9ubHkgYXBwZW5kIGFzc2lzdGFudCBvdXRwdXQgdG8gVUkuXG4gICAgICAgICAgY29uc3QgbXNnID0gcGF5bG9hZD8ubWVzc2FnZTtcbiAgICAgICAgICBjb25zdCByb2xlID0gbXNnPy5yb2xlID8/ICdhc3Npc3RhbnQnO1xuICAgICAgICAgIGlmIChyb2xlICE9PSAnYXNzaXN0YW50Jykge1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIGNvbnN0IHRleHQgPSBleHRyYWN0VGV4dEZyb21HYXRld2F5TWVzc2FnZShtc2cpO1xuICAgICAgICAgIGlmICghdGV4dCkgcmV0dXJuO1xuXG4gICAgICAgICAgLy8gT3B0aW9uYWw6IGhpZGUgaGVhcnRiZWF0IGFja3MgKG5vaXNlIGluIFVJKVxuICAgICAgICAgIGlmICh0ZXh0LnRyaW0oKSA9PT0gJ0hFQVJUQkVBVF9PSycpIHtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICB0aGlzLm9uTWVzc2FnZT8uKHtcbiAgICAgICAgICAgIHR5cGU6ICdtZXNzYWdlJyxcbiAgICAgICAgICAgIHBheWxvYWQ6IHtcbiAgICAgICAgICAgICAgY29udGVudDogdGV4dCxcbiAgICAgICAgICAgICAgcm9sZTogJ2Fzc2lzdGFudCcsXG4gICAgICAgICAgICAgIHRpbWVzdGFtcDogRGF0ZS5ub3coKSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSk7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuXG4gICAgICBjb25zb2xlLmRlYnVnKCdbb2NsYXctd3NdIFVuaGFuZGxlZCBmcmFtZScsIGZyYW1lKTtcbiAgICB9O1xuXG4gICAgd3Mub25jbG9zZSA9ICgpID0+IHtcbiAgICAgIHRoaXMuX3N0b3BUaW1lcnMoKTtcbiAgICAgIHRoaXMuX3NldFN0YXRlKCdkaXNjb25uZWN0ZWQnKTtcblxuICAgICAgZm9yIChjb25zdCBwZW5kaW5nIG9mIHRoaXMucGVuZGluZ1JlcXVlc3RzLnZhbHVlcygpKSB7XG4gICAgICAgIHBlbmRpbmcucmVqZWN0KG5ldyBFcnJvcignQ29ubmVjdGlvbiBjbG9zZWQnKSk7XG4gICAgICB9XG4gICAgICB0aGlzLnBlbmRpbmdSZXF1ZXN0cy5jbGVhcigpO1xuXG4gICAgICBpZiAoIXRoaXMuaW50ZW50aW9uYWxDbG9zZSkge1xuICAgICAgICB0aGlzLl9zY2hlZHVsZVJlY29ubmVjdCgpO1xuICAgICAgfVxuICAgIH07XG5cbiAgICB3cy5vbmVycm9yID0gKGV2OiBFdmVudCkgPT4ge1xuICAgICAgY29uc29sZS5lcnJvcignW29jbGF3LXdzXSBXZWJTb2NrZXQgZXJyb3InLCBldik7XG4gICAgfTtcbiAgfVxuXG4gIHByaXZhdGUgX3NlbmRSZXF1ZXN0KG1ldGhvZDogc3RyaW5nLCBwYXJhbXM6IGFueSk6IFByb21pc2U8YW55PiB7XG4gICAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIGlmICghdGhpcy53cyB8fCB0aGlzLndzLnJlYWR5U3RhdGUgIT09IFdlYlNvY2tldC5PUEVOKSB7XG4gICAgICAgIHJlamVjdChuZXcgRXJyb3IoJ1dlYlNvY2tldCBub3QgY29ubmVjdGVkJykpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG5cbiAgICAgIGNvbnN0IGlkID0gYHJlcS0keysrdGhpcy5yZXF1ZXN0SWR9YDtcbiAgICAgIHRoaXMucGVuZGluZ1JlcXVlc3RzLnNldChpZCwgeyByZXNvbHZlLCByZWplY3QgfSk7XG5cbiAgICAgIHRoaXMud3Muc2VuZChcbiAgICAgICAgSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIHR5cGU6ICdyZXEnLFxuICAgICAgICAgIG1ldGhvZCxcbiAgICAgICAgICBpZCxcbiAgICAgICAgICBwYXJhbXMsXG4gICAgICAgIH0pXG4gICAgICApO1xuXG4gICAgICBzZXRUaW1lb3V0KCgpID0+IHtcbiAgICAgICAgaWYgKHRoaXMucGVuZGluZ1JlcXVlc3RzLmhhcyhpZCkpIHtcbiAgICAgICAgICB0aGlzLnBlbmRpbmdSZXF1ZXN0cy5kZWxldGUoaWQpO1xuICAgICAgICAgIHJlamVjdChuZXcgRXJyb3IoYFJlcXVlc3QgdGltZW91dDogJHttZXRob2R9YCkpO1xuICAgICAgICB9XG4gICAgICB9LCAzMF8wMDApO1xuICAgIH0pO1xuICB9XG5cbiAgcHJpdmF0ZSBfc2NoZWR1bGVSZWNvbm5lY3QoKTogdm9pZCB7XG4gICAgaWYgKHRoaXMucmVjb25uZWN0VGltZXIgIT09IG51bGwpIHJldHVybjtcbiAgICB0aGlzLnJlY29ubmVjdFRpbWVyID0gc2V0VGltZW91dCgoKSA9PiB7XG4gICAgICB0aGlzLnJlY29ubmVjdFRpbWVyID0gbnVsbDtcbiAgICAgIGlmICghdGhpcy5pbnRlbnRpb25hbENsb3NlKSB7XG4gICAgICAgIGNvbnNvbGUubG9nKGBbb2NsYXctd3NdIFJlY29ubmVjdGluZyB0byAke3RoaXMudXJsfVx1MjAyNmApO1xuICAgICAgICB0aGlzLl9jb25uZWN0KCk7XG4gICAgICB9XG4gICAgfSwgUkVDT05ORUNUX0RFTEFZX01TKTtcbiAgfVxuXG4gIHByaXZhdGUgX3N0YXJ0SGVhcnRiZWF0KCk6IHZvaWQge1xuICAgIHRoaXMuX3N0b3BIZWFydGJlYXQoKTtcbiAgICB0aGlzLmhlYXJ0YmVhdFRpbWVyID0gc2V0SW50ZXJ2YWwoKCkgPT4ge1xuICAgICAgaWYgKHRoaXMud3M/LnJlYWR5U3RhdGUgIT09IFdlYlNvY2tldC5PUEVOKSByZXR1cm47XG4gICAgICBpZiAodGhpcy53cy5idWZmZXJlZEFtb3VudCA+IDApIHtcbiAgICAgICAgY29uc29sZS53YXJuKCdbb2NsYXctd3NdIFNlbmQgYnVmZmVyIG5vdCBlbXB0eSBcdTIwMTQgY29ubmVjdGlvbiBtYXkgYmUgc3RhbGxlZCcpO1xuICAgICAgfVxuICAgIH0sIEhFQVJUQkVBVF9JTlRFUlZBTF9NUyk7XG4gIH1cblxuICBwcml2YXRlIF9zdG9wSGVhcnRiZWF0KCk6IHZvaWQge1xuICAgIGlmICh0aGlzLmhlYXJ0YmVhdFRpbWVyKSB7XG4gICAgICBjbGVhckludGVydmFsKHRoaXMuaGVhcnRiZWF0VGltZXIpO1xuICAgICAgdGhpcy5oZWFydGJlYXRUaW1lciA9IG51bGw7XG4gICAgfVxuICB9XG5cbiAgcHJpdmF0ZSBfc3RvcFRpbWVycygpOiB2b2lkIHtcbiAgICB0aGlzLl9zdG9wSGVhcnRiZWF0KCk7XG4gICAgaWYgKHRoaXMucmVjb25uZWN0VGltZXIpIHtcbiAgICAgIGNsZWFyVGltZW91dCh0aGlzLnJlY29ubmVjdFRpbWVyKTtcbiAgICAgIHRoaXMucmVjb25uZWN0VGltZXIgPSBudWxsO1xuICAgIH1cbiAgfVxuXG4gIHByaXZhdGUgX3NldFN0YXRlKHN0YXRlOiBXU0NsaWVudFN0YXRlKTogdm9pZCB7XG4gICAgaWYgKHRoaXMuc3RhdGUgPT09IHN0YXRlKSByZXR1cm47XG4gICAgdGhpcy5zdGF0ZSA9IHN0YXRlO1xuICAgIHRoaXMub25TdGF0ZUNoYW5nZT8uKHN0YXRlKTtcbiAgfVxufVxuIiwgImltcG9ydCB0eXBlIHsgQ2hhdE1lc3NhZ2UgfSBmcm9tICcuL3R5cGVzJztcblxuLyoqIE1hbmFnZXMgdGhlIGluLW1lbW9yeSBsaXN0IG9mIGNoYXQgbWVzc2FnZXMgYW5kIG5vdGlmaWVzIFVJIG9uIGNoYW5nZXMgKi9cbmV4cG9ydCBjbGFzcyBDaGF0TWFuYWdlciB7XG4gIHByaXZhdGUgbWVzc2FnZXM6IENoYXRNZXNzYWdlW10gPSBbXTtcblxuICAvKiogRmlyZWQgZm9yIGEgZnVsbCByZS1yZW5kZXIgKGNsZWFyL3JlbG9hZCkgKi9cbiAgb25VcGRhdGU6ICgobWVzc2FnZXM6IHJlYWRvbmx5IENoYXRNZXNzYWdlW10pID0+IHZvaWQpIHwgbnVsbCA9IG51bGw7XG4gIC8qKiBGaXJlZCB3aGVuIGEgc2luZ2xlIG1lc3NhZ2UgaXMgYXBwZW5kZWQgXHUyMDE0IHVzZSBmb3IgTygxKSBhcHBlbmQtb25seSBVSSAqL1xuICBvbk1lc3NhZ2VBZGRlZDogKChtc2c6IENoYXRNZXNzYWdlKSA9PiB2b2lkKSB8IG51bGwgPSBudWxsO1xuXG4gIGFkZE1lc3NhZ2UobXNnOiBDaGF0TWVzc2FnZSk6IHZvaWQge1xuICAgIHRoaXMubWVzc2FnZXMucHVzaChtc2cpO1xuICAgIHRoaXMub25NZXNzYWdlQWRkZWQ/Lihtc2cpO1xuICB9XG5cbiAgZ2V0TWVzc2FnZXMoKTogcmVhZG9ubHkgQ2hhdE1lc3NhZ2VbXSB7XG4gICAgcmV0dXJuIHRoaXMubWVzc2FnZXM7XG4gIH1cblxuICBjbGVhcigpOiB2b2lkIHtcbiAgICB0aGlzLm1lc3NhZ2VzID0gW107XG4gICAgdGhpcy5vblVwZGF0ZT8uKFtdKTtcbiAgfVxuXG4gIC8qKiBDcmVhdGUgYSB1c2VyIG1lc3NhZ2Ugb2JqZWN0ICh3aXRob3V0IGFkZGluZyBpdCkgKi9cbiAgc3RhdGljIGNyZWF0ZVVzZXJNZXNzYWdlKGNvbnRlbnQ6IHN0cmluZyk6IENoYXRNZXNzYWdlIHtcbiAgICByZXR1cm4ge1xuICAgICAgaWQ6IGBtc2ctJHtEYXRlLm5vdygpfS0ke01hdGgucmFuZG9tKCkudG9TdHJpbmcoMzYpLnNsaWNlKDIsIDcpfWAsXG4gICAgICByb2xlOiAndXNlcicsXG4gICAgICBjb250ZW50LFxuICAgICAgdGltZXN0YW1wOiBEYXRlLm5vdygpLFxuICAgIH07XG4gIH1cblxuICAvKiogQ3JlYXRlIGFuIGFzc2lzdGFudCBtZXNzYWdlIG9iamVjdCAod2l0aG91dCBhZGRpbmcgaXQpICovXG4gIHN0YXRpYyBjcmVhdGVBc3Npc3RhbnRNZXNzYWdlKGNvbnRlbnQ6IHN0cmluZyk6IENoYXRNZXNzYWdlIHtcbiAgICByZXR1cm4ge1xuICAgICAgaWQ6IGBtc2ctJHtEYXRlLm5vdygpfS0ke01hdGgucmFuZG9tKCkudG9TdHJpbmcoMzYpLnNsaWNlKDIsIDcpfWAsXG4gICAgICByb2xlOiAnYXNzaXN0YW50JyxcbiAgICAgIGNvbnRlbnQsXG4gICAgICB0aW1lc3RhbXA6IERhdGUubm93KCksXG4gICAgfTtcbiAgfVxuXG4gIC8qKiBDcmVhdGUgYSBzeXN0ZW0gLyBzdGF0dXMgbWVzc2FnZSAoZXJyb3JzLCByZWNvbm5lY3Qgbm90aWNlcywgZXRjLikgKi9cbiAgc3RhdGljIGNyZWF0ZVN5c3RlbU1lc3NhZ2UoY29udGVudDogc3RyaW5nKTogQ2hhdE1lc3NhZ2Uge1xuICAgIHJldHVybiB7XG4gICAgICBpZDogYHN5cy0ke0RhdGUubm93KCl9YCxcbiAgICAgIHJvbGU6ICdzeXN0ZW0nLFxuICAgICAgY29udGVudCxcbiAgICAgIHRpbWVzdGFtcDogRGF0ZS5ub3coKSxcbiAgICB9O1xuICB9XG59XG4iLCAiaW1wb3J0IHsgSXRlbVZpZXcsIFdvcmtzcGFjZUxlYWYgfSBmcm9tICdvYnNpZGlhbic7XG5pbXBvcnQgdHlwZSBPcGVuQ2xhd1BsdWdpbiBmcm9tICcuL21haW4nO1xuaW1wb3J0IHsgQ2hhdE1hbmFnZXIgfSBmcm9tICcuL2NoYXQnO1xuaW1wb3J0IHR5cGUgeyBDaGF0TWVzc2FnZSB9IGZyb20gJy4vdHlwZXMnO1xuaW1wb3J0IHsgZ2V0QWN0aXZlTm90ZUNvbnRleHQgfSBmcm9tICcuL2NvbnRleHQnO1xuXG5leHBvcnQgY29uc3QgVklFV19UWVBFX09QRU5DTEFXX0NIQVQgPSAnb3BlbmNsYXctY2hhdCc7XG5cbmV4cG9ydCBjbGFzcyBPcGVuQ2xhd0NoYXRWaWV3IGV4dGVuZHMgSXRlbVZpZXcge1xuICBwcml2YXRlIHBsdWdpbjogT3BlbkNsYXdQbHVnaW47XG4gIHByaXZhdGUgY2hhdE1hbmFnZXI6IENoYXRNYW5hZ2VyO1xuXG4gIC8vIERPTSByZWZzXG4gIHByaXZhdGUgbWVzc2FnZXNFbCE6IEhUTUxFbGVtZW50O1xuICBwcml2YXRlIGlucHV0RWwhOiBIVE1MVGV4dEFyZWFFbGVtZW50O1xuICBwcml2YXRlIHNlbmRCdG4hOiBIVE1MQnV0dG9uRWxlbWVudDtcbiAgcHJpdmF0ZSBpbmNsdWRlTm90ZUNoZWNrYm94ITogSFRNTElucHV0RWxlbWVudDtcbiAgcHJpdmF0ZSBzdGF0dXNEb3QhOiBIVE1MRWxlbWVudDtcblxuICBjb25zdHJ1Y3RvcihsZWFmOiBXb3Jrc3BhY2VMZWFmLCBwbHVnaW46IE9wZW5DbGF3UGx1Z2luKSB7XG4gICAgc3VwZXIobGVhZik7XG4gICAgdGhpcy5wbHVnaW4gPSBwbHVnaW47XG4gICAgdGhpcy5jaGF0TWFuYWdlciA9IHBsdWdpbi5jaGF0TWFuYWdlcjtcbiAgfVxuXG4gIGdldFZpZXdUeXBlKCk6IHN0cmluZyB7XG4gICAgcmV0dXJuIFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFUO1xuICB9XG5cbiAgZ2V0RGlzcGxheVRleHQoKTogc3RyaW5nIHtcbiAgICByZXR1cm4gJ09wZW5DbGF3IENoYXQnO1xuICB9XG5cbiAgZ2V0SWNvbigpOiBzdHJpbmcge1xuICAgIHJldHVybiAnbWVzc2FnZS1zcXVhcmUnO1xuICB9XG5cbiAgYXN5bmMgb25PcGVuKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIHRoaXMuX2J1aWxkVUkoKTtcblxuICAgIC8vIEZ1bGwgcmUtcmVuZGVyIG9uIGNsZWFyIC8gcmVsb2FkXG4gICAgdGhpcy5jaGF0TWFuYWdlci5vblVwZGF0ZSA9IChtc2dzKSA9PiB0aGlzLl9yZW5kZXJNZXNzYWdlcyhtc2dzKTtcbiAgICAvLyBPKDEpIGFwcGVuZCBmb3IgbmV3IG1lc3NhZ2VzXG4gICAgdGhpcy5jaGF0TWFuYWdlci5vbk1lc3NhZ2VBZGRlZCA9IChtc2cpID0+IHRoaXMuX2FwcGVuZE1lc3NhZ2UobXNnKTtcblxuICAgIC8vIFN1YnNjcmliZSB0byBXUyBzdGF0ZSBjaGFuZ2VzXG4gICAgdGhpcy5wbHVnaW4ud3NDbGllbnQub25TdGF0ZUNoYW5nZSA9IChzdGF0ZSkgPT4ge1xuICAgICAgY29uc3QgY29ubmVjdGVkID0gc3RhdGUgPT09ICdjb25uZWN0ZWQnO1xuICAgICAgdGhpcy5zdGF0dXNEb3QudG9nZ2xlQ2xhc3MoJ2Nvbm5lY3RlZCcsIGNvbm5lY3RlZCk7XG4gICAgICB0aGlzLnN0YXR1c0RvdC50aXRsZSA9IGBHYXRld2F5OiAke3N0YXRlfWA7XG4gICAgICB0aGlzLnNlbmRCdG4uZGlzYWJsZWQgPSAhY29ubmVjdGVkO1xuICAgIH07XG5cbiAgICAvLyBSZWZsZWN0IGN1cnJlbnQgc3RhdGVcbiAgICBjb25zdCBjb25uZWN0ZWQgPSB0aGlzLnBsdWdpbi53c0NsaWVudC5zdGF0ZSA9PT0gJ2Nvbm5lY3RlZCc7XG4gICAgdGhpcy5zdGF0dXNEb3QudG9nZ2xlQ2xhc3MoJ2Nvbm5lY3RlZCcsIGNvbm5lY3RlZCk7XG4gICAgdGhpcy5zZW5kQnRuLmRpc2FibGVkID0gIWNvbm5lY3RlZDtcblxuICAgIHRoaXMuX3JlbmRlck1lc3NhZ2VzKHRoaXMuY2hhdE1hbmFnZXIuZ2V0TWVzc2FnZXMoKSk7XG4gIH1cblxuICBhc3luYyBvbkNsb3NlKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIHRoaXMuY2hhdE1hbmFnZXIub25VcGRhdGUgPSBudWxsO1xuICAgIHRoaXMuY2hhdE1hbmFnZXIub25NZXNzYWdlQWRkZWQgPSBudWxsO1xuICAgIHRoaXMucGx1Z2luLndzQ2xpZW50Lm9uU3RhdGVDaGFuZ2UgPSBudWxsO1xuICB9XG5cbiAgLy8gXHUyNTAwXHUyNTAwIFVJIGNvbnN0cnVjdGlvbiBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcblxuICBwcml2YXRlIF9idWlsZFVJKCk6IHZvaWQge1xuICAgIGNvbnN0IHJvb3QgPSB0aGlzLmNvbnRlbnRFbDtcbiAgICByb290LmVtcHR5KCk7XG4gICAgcm9vdC5hZGRDbGFzcygnb2NsYXctY2hhdC12aWV3Jyk7XG5cbiAgICAvLyBcdTI1MDBcdTI1MDAgSGVhZGVyIFx1MjUwMFx1MjUwMFxuICAgIGNvbnN0IGhlYWRlciA9IHJvb3QuY3JlYXRlRGl2KHsgY2xzOiAnb2NsYXctaGVhZGVyJyB9KTtcbiAgICBoZWFkZXIuY3JlYXRlU3Bhbih7IGNsczogJ29jbGF3LWhlYWRlci10aXRsZScsIHRleHQ6ICdPcGVuQ2xhdyBDaGF0JyB9KTtcbiAgICB0aGlzLnN0YXR1c0RvdCA9IGhlYWRlci5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1zdGF0dXMtZG90JyB9KTtcbiAgICB0aGlzLnN0YXR1c0RvdC50aXRsZSA9ICdHYXRld2F5OiBkaXNjb25uZWN0ZWQnO1xuXG4gICAgLy8gXHUyNTAwXHUyNTAwIE1lc3NhZ2VzIGFyZWEgXHUyNTAwXHUyNTAwXG4gICAgdGhpcy5tZXNzYWdlc0VsID0gcm9vdC5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1tZXNzYWdlcycgfSk7XG5cbiAgICAvLyBcdTI1MDBcdTI1MDAgQ29udGV4dCByb3cgXHUyNTAwXHUyNTAwXG4gICAgY29uc3QgY3R4Um93ID0gcm9vdC5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1jb250ZXh0LXJvdycgfSk7XG4gICAgdGhpcy5pbmNsdWRlTm90ZUNoZWNrYm94ID0gY3R4Um93LmNyZWF0ZUVsKCdpbnB1dCcsIHsgdHlwZTogJ2NoZWNrYm94JyB9KTtcbiAgICB0aGlzLmluY2x1ZGVOb3RlQ2hlY2tib3guaWQgPSAnb2NsYXctaW5jbHVkZS1ub3RlJztcbiAgICB0aGlzLmluY2x1ZGVOb3RlQ2hlY2tib3guY2hlY2tlZCA9IHRoaXMucGx1Z2luLnNldHRpbmdzLmluY2x1ZGVBY3RpdmVOb3RlO1xuICAgIGNvbnN0IGN0eExhYmVsID0gY3R4Um93LmNyZWF0ZUVsKCdsYWJlbCcsIHsgdGV4dDogJ0luY2x1ZGUgYWN0aXZlIG5vdGUnIH0pO1xuICAgIGN0eExhYmVsLmh0bWxGb3IgPSAnb2NsYXctaW5jbHVkZS1ub3RlJztcblxuICAgIC8vIFx1MjUwMFx1MjUwMCBJbnB1dCByb3cgXHUyNTAwXHUyNTAwXG4gICAgY29uc3QgaW5wdXRSb3cgPSByb290LmNyZWF0ZURpdih7IGNsczogJ29jbGF3LWlucHV0LXJvdycgfSk7XG4gICAgdGhpcy5pbnB1dEVsID0gaW5wdXRSb3cuY3JlYXRlRWwoJ3RleHRhcmVhJywge1xuICAgICAgY2xzOiAnb2NsYXctaW5wdXQnLFxuICAgICAgcGxhY2Vob2xkZXI6ICdBc2sgYW55dGhpbmdcdTIwMjYnLFxuICAgIH0pO1xuICAgIHRoaXMuaW5wdXRFbC5yb3dzID0gMTtcblxuICAgIHRoaXMuc2VuZEJ0biA9IGlucHV0Um93LmNyZWF0ZUVsKCdidXR0b24nLCB7IGNsczogJ29jbGF3LXNlbmQtYnRuJywgdGV4dDogJ1NlbmQnIH0pO1xuXG4gICAgLy8gXHUyNTAwXHUyNTAwIEV2ZW50IGxpc3RlbmVycyBcdTI1MDBcdTI1MDBcbiAgICB0aGlzLnNlbmRCdG4uYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKSA9PiB0aGlzLl9oYW5kbGVTZW5kKCkpO1xuICAgIHRoaXMuaW5wdXRFbC5hZGRFdmVudExpc3RlbmVyKCdrZXlkb3duJywgKGUpID0+IHtcbiAgICAgIGlmIChlLmtleSA9PT0gJ0VudGVyJyAmJiAhZS5zaGlmdEtleSkge1xuICAgICAgICBlLnByZXZlbnREZWZhdWx0KCk7XG4gICAgICAgIHRoaXMuX2hhbmRsZVNlbmQoKTtcbiAgICAgIH1cbiAgICB9KTtcbiAgICAvLyBBdXRvLXJlc2l6ZSB0ZXh0YXJlYVxuICAgIHRoaXMuaW5wdXRFbC5hZGRFdmVudExpc3RlbmVyKCdpbnB1dCcsICgpID0+IHtcbiAgICAgIHRoaXMuaW5wdXRFbC5zdHlsZS5oZWlnaHQgPSAnYXV0byc7XG4gICAgICB0aGlzLmlucHV0RWwuc3R5bGUuaGVpZ2h0ID0gYCR7dGhpcy5pbnB1dEVsLnNjcm9sbEhlaWdodH1weGA7XG4gICAgfSk7XG4gIH1cblxuICAvLyBcdTI1MDBcdTI1MDAgTWVzc2FnZSByZW5kZXJpbmcgXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG5cbiAgcHJpdmF0ZSBfcmVuZGVyTWVzc2FnZXMobWVzc2FnZXM6IHJlYWRvbmx5IENoYXRNZXNzYWdlW10pOiB2b2lkIHtcbiAgICB0aGlzLm1lc3NhZ2VzRWwuZW1wdHkoKTtcblxuICAgIGlmIChtZXNzYWdlcy5sZW5ndGggPT09IDApIHtcbiAgICAgIHRoaXMubWVzc2FnZXNFbC5jcmVhdGVFbCgncCcsIHtcbiAgICAgICAgdGV4dDogJ1NlbmQgYSBtZXNzYWdlIHRvIHN0YXJ0IGNoYXR0aW5nLicsXG4gICAgICAgIGNsczogJ29jbGF3LW1lc3NhZ2Ugc3lzdGVtIG9jbGF3LXBsYWNlaG9sZGVyJyxcbiAgICAgIH0pO1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIGZvciAoY29uc3QgbXNnIG9mIG1lc3NhZ2VzKSB7XG4gICAgICBjb25zdCBlbCA9IHRoaXMubWVzc2FnZXNFbC5jcmVhdGVEaXYoeyBjbHM6IGBvY2xhdy1tZXNzYWdlICR7bXNnLnJvbGV9YCB9KTtcbiAgICAgIGVsLmNyZWF0ZVNwYW4oeyB0ZXh0OiBtc2cuY29udGVudCB9KTtcbiAgICB9XG5cbiAgICAvLyBTY3JvbGwgdG8gYm90dG9tXG4gICAgdGhpcy5tZXNzYWdlc0VsLnNjcm9sbFRvcCA9IHRoaXMubWVzc2FnZXNFbC5zY3JvbGxIZWlnaHQ7XG4gIH1cblxuICAvKiogQXBwZW5kcyBhIHNpbmdsZSBtZXNzYWdlIHdpdGhvdXQgcmVidWlsZGluZyB0aGUgRE9NIChPKDEpKSAqL1xuICBwcml2YXRlIF9hcHBlbmRNZXNzYWdlKG1zZzogQ2hhdE1lc3NhZ2UpOiB2b2lkIHtcbiAgICAvLyBSZW1vdmUgZW1wdHktc3RhdGUgcGxhY2Vob2xkZXIgaWYgcHJlc2VudFxuICAgIHRoaXMubWVzc2FnZXNFbC5xdWVyeVNlbGVjdG9yKCcub2NsYXctcGxhY2Vob2xkZXInKT8ucmVtb3ZlKCk7XG5cbiAgICBjb25zdCBlbCA9IHRoaXMubWVzc2FnZXNFbC5jcmVhdGVEaXYoeyBjbHM6IGBvY2xhdy1tZXNzYWdlICR7bXNnLnJvbGV9YCB9KTtcbiAgICBlbC5jcmVhdGVTcGFuKHsgdGV4dDogbXNnLmNvbnRlbnQgfSk7XG5cbiAgICAvLyBTY3JvbGwgdG8gYm90dG9tXG4gICAgdGhpcy5tZXNzYWdlc0VsLnNjcm9sbFRvcCA9IHRoaXMubWVzc2FnZXNFbC5zY3JvbGxIZWlnaHQ7XG4gIH1cblxuICAvLyBcdTI1MDBcdTI1MDAgU2VuZCBoYW5kbGVyIFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFxuXG4gIHByaXZhdGUgYXN5bmMgX2hhbmRsZVNlbmQoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgY29uc3QgdGV4dCA9IHRoaXMuaW5wdXRFbC52YWx1ZS50cmltKCk7XG4gICAgaWYgKCF0ZXh0KSByZXR1cm47XG5cbiAgICAvLyBCdWlsZCBtZXNzYWdlIHdpdGggY29udGV4dCBpZiBlbmFibGVkXG4gICAgbGV0IG1lc3NhZ2UgPSB0ZXh0O1xuICAgIGlmICh0aGlzLmluY2x1ZGVOb3RlQ2hlY2tib3guY2hlY2tlZCkge1xuICAgICAgY29uc3Qgbm90ZSA9IGF3YWl0IGdldEFjdGl2ZU5vdGVDb250ZXh0KHRoaXMuYXBwKTtcbiAgICAgIGlmIChub3RlKSB7XG4gICAgICAgIG1lc3NhZ2UgPSBgQ29udGV4dDogW1ske25vdGUudGl0bGV9XV1cXG5cXG4ke3RleHR9YDtcbiAgICAgIH1cbiAgICB9XG5cbiAgICAvLyBBZGQgdXNlciBtZXNzYWdlIHRvIGNoYXQgVUlcbiAgICBjb25zdCB1c2VyTXNnID0gQ2hhdE1hbmFnZXIuY3JlYXRlVXNlck1lc3NhZ2UodGV4dCk7XG4gICAgdGhpcy5jaGF0TWFuYWdlci5hZGRNZXNzYWdlKHVzZXJNc2cpO1xuXG4gICAgLy8gQ2xlYXIgaW5wdXRcbiAgICB0aGlzLmlucHV0RWwudmFsdWUgPSAnJztcbiAgICB0aGlzLmlucHV0RWwuc3R5bGUuaGVpZ2h0ID0gJ2F1dG8nO1xuXG4gICAgLy8gU2VuZCBvdmVyIFdTIChhc3luYylcbiAgICB0cnkge1xuICAgICAgYXdhaXQgdGhpcy5wbHVnaW4ud3NDbGllbnQuc2VuZE1lc3NhZ2UobWVzc2FnZSk7XG4gICAgfSBjYXRjaCAoZXJyKSB7XG4gICAgICBjb25zb2xlLmVycm9yKCdbb2NsYXddIFNlbmQgZmFpbGVkJywgZXJyKTtcbiAgICAgIHRoaXMuY2hhdE1hbmFnZXIuYWRkTWVzc2FnZShcbiAgICAgICAgQ2hhdE1hbmFnZXIuY3JlYXRlU3lzdGVtTWVzc2FnZShgXHUyNkEwIFNlbmQgZmFpbGVkOiAke2Vycn1gKVxuICAgICAgKTtcbiAgICB9XG4gIH1cbn1cbiIsICJpbXBvcnQgdHlwZSB7IEFwcCB9IGZyb20gJ29ic2lkaWFuJztcblxuZXhwb3J0IGludGVyZmFjZSBOb3RlQ29udGV4dCB7XG4gIHRpdGxlOiBzdHJpbmc7XG4gIHBhdGg6IHN0cmluZztcbiAgY29udGVudDogc3RyaW5nO1xufVxuXG4vKipcbiAqIFJldHVybnMgdGhlIGFjdGl2ZSBub3RlJ3MgdGl0bGUgYW5kIGNvbnRlbnQsIG9yIG51bGwgaWYgbm8gbm90ZSBpcyBvcGVuLlxuICogQXN5bmMgYmVjYXVzZSB2YXVsdC5yZWFkKCkgaXMgYXN5bmMuXG4gKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBnZXRBY3RpdmVOb3RlQ29udGV4dChhcHA6IEFwcCk6IFByb21pc2U8Tm90ZUNvbnRleHQgfCBudWxsPiB7XG4gIGNvbnN0IGZpbGUgPSBhcHAud29ya3NwYWNlLmdldEFjdGl2ZUZpbGUoKTtcbiAgaWYgKCFmaWxlKSByZXR1cm4gbnVsbDtcblxuICB0cnkge1xuICAgIGNvbnN0IGNvbnRlbnQgPSBhd2FpdCBhcHAudmF1bHQucmVhZChmaWxlKTtcbiAgICByZXR1cm4ge1xuICAgICAgdGl0bGU6IGZpbGUuYmFzZW5hbWUsXG4gICAgICBwYXRoOiBmaWxlLnBhdGgsXG4gICAgICBjb250ZW50LFxuICAgIH07XG4gIH0gY2F0Y2ggKGVycikge1xuICAgIGNvbnNvbGUuZXJyb3IoJ1tvY2xhdy1jb250ZXh0XSBGYWlsZWQgdG8gcmVhZCBhY3RpdmUgbm90ZScsIGVycik7XG4gICAgcmV0dXJuIG51bGw7XG4gIH1cbn1cbiIsICIvKiogUGVyc2lzdGVkIHBsdWdpbiBjb25maWd1cmF0aW9uICovXG5leHBvcnQgaW50ZXJmYWNlIE9wZW5DbGF3U2V0dGluZ3Mge1xuICAvKiogV2ViU29ja2V0IFVSTCBvZiB0aGUgT3BlbkNsYXcgR2F0ZXdheSAoZS5nLiB3czovLzEwMC45MC45LjY4OjE4Nzg5KSAqL1xuICBnYXRld2F5VXJsOiBzdHJpbmc7XG4gIC8qKiBBdXRoIHRva2VuIFx1MjAxNCBtdXN0IG1hdGNoIHRoZSBjaGFubmVsIHBsdWdpbidzIGF1dGhUb2tlbiAqL1xuICBhdXRoVG9rZW46IHN0cmluZztcbiAgLyoqIE9wZW5DbGF3IHNlc3Npb24ga2V5IHRvIHN1YnNjcmliZSB0byAoZS5nLiBcIm1haW5cIikgKi9cbiAgc2Vzc2lvbktleTogc3RyaW5nO1xuICAvKiogKERlcHJlY2F0ZWQpIE9wZW5DbGF3IGFjY291bnQgSUQgKHVudXNlZDsgY2hhdC5zZW5kIHVzZXMgc2Vzc2lvbktleSkgKi9cbiAgYWNjb3VudElkOiBzdHJpbmc7XG4gIC8qKiBXaGV0aGVyIHRvIGluY2x1ZGUgdGhlIGFjdGl2ZSBub3RlIGNvbnRlbnQgd2l0aCBlYWNoIG1lc3NhZ2UgKi9cbiAgaW5jbHVkZUFjdGl2ZU5vdGU6IGJvb2xlYW47XG59XG5cbmV4cG9ydCBjb25zdCBERUZBVUxUX1NFVFRJTkdTOiBPcGVuQ2xhd1NldHRpbmdzID0ge1xuICBnYXRld2F5VXJsOiAnd3M6Ly9sb2NhbGhvc3Q6MTg3ODknLFxuICBhdXRoVG9rZW46ICcnLFxuICBzZXNzaW9uS2V5OiAnbWFpbicsXG4gIGFjY291bnRJZDogJ21haW4nLFxuICBpbmNsdWRlQWN0aXZlTm90ZTogZmFsc2UsXG59O1xuXG4vKiogQSBzaW5nbGUgY2hhdCBtZXNzYWdlICovXG5leHBvcnQgaW50ZXJmYWNlIENoYXRNZXNzYWdlIHtcbiAgaWQ6IHN0cmluZztcbiAgcm9sZTogJ3VzZXInIHwgJ2Fzc2lzdGFudCcgfCAnc3lzdGVtJztcbiAgY29udGVudDogc3RyaW5nO1xuICB0aW1lc3RhbXA6IG51bWJlcjtcbn1cblxuLyoqIFBheWxvYWQgZm9yIG1lc3NhZ2VzIFNFTlQgdG8gdGhlIHNlcnZlciAob3V0Ym91bmQpICovXG5leHBvcnQgaW50ZXJmYWNlIFdTUGF5bG9hZCB7XG4gIHR5cGU6ICdhdXRoJyB8ICdtZXNzYWdlJyB8ICdwaW5nJyB8ICdwb25nJyB8ICdlcnJvcic7XG4gIHBheWxvYWQ/OiBSZWNvcmQ8c3RyaW5nLCB1bmtub3duPjtcbn1cblxuLyoqIE1lc3NhZ2VzIFJFQ0VJVkVEIGZyb20gdGhlIHNlcnZlciAoaW5ib3VuZCkgXHUyMDE0IGRpc2NyaW1pbmF0ZWQgdW5pb24gKi9cbmV4cG9ydCB0eXBlIEluYm91bmRXU1BheWxvYWQgPVxuICB8IHsgdHlwZTogJ21lc3NhZ2UnOyBwYXlsb2FkOiB7IGNvbnRlbnQ6IHN0cmluZzsgcm9sZTogc3RyaW5nOyB0aW1lc3RhbXA6IG51bWJlciB9IH1cbiAgfCB7IHR5cGU6ICdlcnJvcic7IHBheWxvYWQ6IHsgbWVzc2FnZTogc3RyaW5nIH0gfTtcblxuLyoqIEF2YWlsYWJsZSBhZ2VudHMgLyBtb2RlbHMgKi9cbmV4cG9ydCBpbnRlcmZhY2UgQWdlbnRPcHRpb24ge1xuICBpZDogc3RyaW5nO1xuICBsYWJlbDogc3RyaW5nO1xufVxuIl0sCiAgIm1hcHBpbmdzIjogIjs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQSxJQUFBQSxtQkFBOEM7OztBQ0E5Qyxz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
