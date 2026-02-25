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
function base64Encode(bytes) {
  const u8 = new Uint8Array(bytes);
  let s = "";
  for (let i = 0; i < u8.length; i++)
    s += String.fromCharCode(u8[i]);
  return btoa(s);
}
function utf8Bytes(text) {
  return new TextEncoder().encode(text);
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
    const id = `obsidian-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
    const identity = {
      id,
      publicKey: base64Encode(pubRaw),
      privateKeyJwk: privJwk
    };
    localStorage.setItem(DEVICE_STORAGE_KEY, JSON.stringify(identity));
    return identity;
  });
}
function signNonce(identity, nonce) {
  return __async(this, null, function* () {
    const privateKey = yield crypto.subtle.importKey(
      "jwk",
      identity.privateKeyJwk,
      { name: "Ed25519" },
      false,
      ["sign"]
    );
    const signedAt = Date.now();
    const sig = yield crypto.subtle.sign({ name: "Ed25519" }, privateKey, utf8Bytes(nonce));
    return { signature: base64Encode(sig), signedAt };
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
        const sig = yield signNonce(identity, connectNonce);
        yield this._sendRequest("connect", {
          minProtocol: 3,
          maxProtocol: 3,
          client: {
            id: "gateway-client",
            mode: "backend",
            version: "0.1.9",
            platform: "electron"
          },
          role: "operator",
          scopes: ["operator.read", "operator.write"],
          device: {
            id: identity.id,
            publicKey: identity.publicKey,
            signature: sig.signature,
            signedAt: sig.signedAt,
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
          if ((payload == null ? void 0 : payload.sessionKey) !== this.sessionKey) {
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
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsic3JjL21haW4udHMiLCAic3JjL3NldHRpbmdzLnRzIiwgInNyYy93ZWJzb2NrZXQudHMiLCAic3JjL2NoYXQudHMiLCAic3JjL3ZpZXcudHMiLCAic3JjL2NvbnRleHQudHMiLCAic3JjL3R5cGVzLnRzIl0sCiAgInNvdXJjZXNDb250ZW50IjogWyJpbXBvcnQgeyBOb3RpY2UsIFBsdWdpbiwgV29ya3NwYWNlTGVhZiB9IGZyb20gJ29ic2lkaWFuJztcbmltcG9ydCB7IE9wZW5DbGF3U2V0dGluZ1RhYiB9IGZyb20gJy4vc2V0dGluZ3MnO1xuaW1wb3J0IHsgT2JzaWRpYW5XU0NsaWVudCB9IGZyb20gJy4vd2Vic29ja2V0JztcbmltcG9ydCB7IENoYXRNYW5hZ2VyIH0gZnJvbSAnLi9jaGF0JztcbmltcG9ydCB7IFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFULCBPcGVuQ2xhd0NoYXRWaWV3IH0gZnJvbSAnLi92aWV3JztcbmltcG9ydCB7IERFRkFVTFRfU0VUVElOR1MsIHR5cGUgT3BlbkNsYXdTZXR0aW5ncyB9IGZyb20gJy4vdHlwZXMnO1xuXG5leHBvcnQgZGVmYXVsdCBjbGFzcyBPcGVuQ2xhd1BsdWdpbiBleHRlbmRzIFBsdWdpbiB7XG4gIHNldHRpbmdzITogT3BlbkNsYXdTZXR0aW5ncztcbiAgd3NDbGllbnQhOiBPYnNpZGlhbldTQ2xpZW50O1xuICBjaGF0TWFuYWdlciE6IENoYXRNYW5hZ2VyO1xuXG4gIGFzeW5jIG9ubG9hZCgpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBhd2FpdCB0aGlzLmxvYWRTZXR0aW5ncygpO1xuXG4gICAgdGhpcy53c0NsaWVudCA9IG5ldyBPYnNpZGlhbldTQ2xpZW50KHRoaXMuc2V0dGluZ3Muc2Vzc2lvbktleSk7XG4gICAgdGhpcy5jaGF0TWFuYWdlciA9IG5ldyBDaGF0TWFuYWdlcigpO1xuXG4gICAgLy8gV2lyZSBpbmNvbWluZyBXUyBtZXNzYWdlcyBcdTIxOTIgQ2hhdE1hbmFnZXJcbiAgICB0aGlzLndzQ2xpZW50Lm9uTWVzc2FnZSA9IChtc2cpID0+IHtcbiAgICAgIGlmIChtc2cudHlwZSA9PT0gJ21lc3NhZ2UnKSB7XG4gICAgICAgIHRoaXMuY2hhdE1hbmFnZXIuYWRkTWVzc2FnZShDaGF0TWFuYWdlci5jcmVhdGVBc3Npc3RhbnRNZXNzYWdlKG1zZy5wYXlsb2FkLmNvbnRlbnQpKTtcbiAgICAgIH0gZWxzZSBpZiAobXNnLnR5cGUgPT09ICdlcnJvcicpIHtcbiAgICAgICAgY29uc3QgZXJyVGV4dCA9IG1zZy5wYXlsb2FkLm1lc3NhZ2UgPz8gJ1Vua25vd24gZXJyb3IgZnJvbSBnYXRld2F5JztcbiAgICAgICAgdGhpcy5jaGF0TWFuYWdlci5hZGRNZXNzYWdlKENoYXRNYW5hZ2VyLmNyZWF0ZVN5c3RlbU1lc3NhZ2UoYFx1MjZBMCAke2VyclRleHR9YCkpO1xuICAgICAgfVxuICAgIH07XG5cbiAgICAvLyBSZWdpc3RlciB0aGUgc2lkZWJhciB2aWV3XG4gICAgdGhpcy5yZWdpc3RlclZpZXcoXG4gICAgICBWSUVXX1RZUEVfT1BFTkNMQVdfQ0hBVCxcbiAgICAgIChsZWFmOiBXb3Jrc3BhY2VMZWFmKSA9PiBuZXcgT3BlbkNsYXdDaGF0VmlldyhsZWFmLCB0aGlzKVxuICAgICk7XG5cbiAgICAvLyBSaWJib24gaWNvbiBcdTIwMTQgb3BlbnMgLyByZXZlYWxzIHRoZSBjaGF0IHNpZGViYXJcbiAgICB0aGlzLmFkZFJpYmJvbkljb24oJ21lc3NhZ2Utc3F1YXJlJywgJ09wZW5DbGF3IENoYXQnLCAoKSA9PiB7XG4gICAgICB0aGlzLl9hY3RpdmF0ZUNoYXRWaWV3KCk7XG4gICAgfSk7XG5cbiAgICAvLyBTZXR0aW5ncyB0YWJcbiAgICB0aGlzLmFkZFNldHRpbmdUYWIobmV3IE9wZW5DbGF3U2V0dGluZ1RhYih0aGlzLmFwcCwgdGhpcykpO1xuXG4gICAgLy8gQ29tbWFuZCBwYWxldHRlIGVudHJ5XG4gICAgdGhpcy5hZGRDb21tYW5kKHtcbiAgICAgIGlkOiAnb3Blbi1vcGVuY2xhdy1jaGF0JyxcbiAgICAgIG5hbWU6ICdPcGVuIGNoYXQgc2lkZWJhcicsXG4gICAgICBjYWxsYmFjazogKCkgPT4gdGhpcy5fYWN0aXZhdGVDaGF0VmlldygpLFxuICAgIH0pO1xuXG4gICAgLy8gQ29ubmVjdCB0byBnYXRld2F5IGlmIHRva2VuIGlzIGNvbmZpZ3VyZWRcbiAgICBpZiAodGhpcy5zZXR0aW5ncy5hdXRoVG9rZW4pIHtcbiAgICAgIHRoaXMuX2Nvbm5lY3RXUygpO1xuICAgIH0gZWxzZSB7XG4gICAgICBuZXcgTm90aWNlKCdPcGVuQ2xhdyBDaGF0OiBwbGVhc2UgY29uZmlndXJlIHlvdXIgZ2F0ZXdheSB0b2tlbiBpbiBTZXR0aW5ncy4nKTtcbiAgICB9XG5cbiAgICBjb25zb2xlLmxvZygnW29jbGF3XSBQbHVnaW4gbG9hZGVkJyk7XG4gIH1cblxuICBhc3luYyBvbnVubG9hZCgpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICB0aGlzLndzQ2xpZW50LmRpc2Nvbm5lY3QoKTtcbiAgICB0aGlzLmFwcC53b3Jrc3BhY2UuZGV0YWNoTGVhdmVzT2ZUeXBlKFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFUKTtcbiAgICBjb25zb2xlLmxvZygnW29jbGF3XSBQbHVnaW4gdW5sb2FkZWQnKTtcbiAgfVxuXG4gIGFzeW5jIGxvYWRTZXR0aW5ncygpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICB0aGlzLnNldHRpbmdzID0gT2JqZWN0LmFzc2lnbih7fSwgREVGQVVMVF9TRVRUSU5HUywgYXdhaXQgdGhpcy5sb2FkRGF0YSgpKTtcbiAgfVxuXG4gIGFzeW5jIHNhdmVTZXR0aW5ncygpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBhd2FpdCB0aGlzLnNhdmVEYXRhKHRoaXMuc2V0dGluZ3MpO1xuICB9XG5cbiAgLy8gXHUyNTAwXHUyNTAwIEhlbHBlcnMgXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG5cbiAgcHJpdmF0ZSBfY29ubmVjdFdTKCk6IHZvaWQge1xuICAgIHRoaXMud3NDbGllbnQuY29ubmVjdChcbiAgICAgIHRoaXMuc2V0dGluZ3MuZ2F0ZXdheVVybCxcbiAgICAgIHRoaXMuc2V0dGluZ3MuYXV0aFRva2VuXG4gICAgKTtcbiAgfVxuXG4gIHByaXZhdGUgYXN5bmMgX2FjdGl2YXRlQ2hhdFZpZXcoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgY29uc3QgeyB3b3Jrc3BhY2UgfSA9IHRoaXMuYXBwO1xuXG4gICAgLy8gUmV1c2UgZXhpc3RpbmcgbGVhZiBpZiBhbHJlYWR5IG9wZW5cbiAgICBjb25zdCBleGlzdGluZyA9IHdvcmtzcGFjZS5nZXRMZWF2ZXNPZlR5cGUoVklFV19UWVBFX09QRU5DTEFXX0NIQVQpO1xuICAgIGlmIChleGlzdGluZy5sZW5ndGggPiAwKSB7XG4gICAgICB3b3Jrc3BhY2UucmV2ZWFsTGVhZihleGlzdGluZ1swXSk7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgLy8gT3BlbiBpbiByaWdodCBzaWRlYmFyXG4gICAgY29uc3QgbGVhZiA9IHdvcmtzcGFjZS5nZXRSaWdodExlYWYoZmFsc2UpO1xuICAgIGlmICghbGVhZikgcmV0dXJuO1xuICAgIGF3YWl0IGxlYWYuc2V0Vmlld1N0YXRlKHsgdHlwZTogVklFV19UWVBFX09QRU5DTEFXX0NIQVQsIGFjdGl2ZTogdHJ1ZSB9KTtcbiAgICB3b3Jrc3BhY2UucmV2ZWFsTGVhZihsZWFmKTtcbiAgfVxufVxuIiwgImltcG9ydCB7IEFwcCwgUGx1Z2luU2V0dGluZ1RhYiwgU2V0dGluZyB9IGZyb20gJ29ic2lkaWFuJztcbmltcG9ydCB0eXBlIE9wZW5DbGF3UGx1Z2luIGZyb20gJy4vbWFpbic7XG5cbmV4cG9ydCBjbGFzcyBPcGVuQ2xhd1NldHRpbmdUYWIgZXh0ZW5kcyBQbHVnaW5TZXR0aW5nVGFiIHtcbiAgcGx1Z2luOiBPcGVuQ2xhd1BsdWdpbjtcblxuICBjb25zdHJ1Y3RvcihhcHA6IEFwcCwgcGx1Z2luOiBPcGVuQ2xhd1BsdWdpbikge1xuICAgIHN1cGVyKGFwcCwgcGx1Z2luKTtcbiAgICB0aGlzLnBsdWdpbiA9IHBsdWdpbjtcbiAgfVxuXG4gIGRpc3BsYXkoKTogdm9pZCB7XG4gICAgY29uc3QgeyBjb250YWluZXJFbCB9ID0gdGhpcztcbiAgICBjb250YWluZXJFbC5lbXB0eSgpO1xuXG4gICAgY29udGFpbmVyRWwuY3JlYXRlRWwoJ2gyJywgeyB0ZXh0OiAnT3BlbkNsYXcgQ2hhdCBcdTIwMTMgU2V0dGluZ3MnIH0pO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZSgnR2F0ZXdheSBVUkwnKVxuICAgICAgLnNldERlc2MoJ1dlYlNvY2tldCBVUkwgb2YgdGhlIE9wZW5DbGF3IEdhdGV3YXkgKGUuZy4gd3M6Ly9ob3N0bmFtZToxODc4OSkuJylcbiAgICAgIC5hZGRUZXh0KCh0ZXh0KSA9PlxuICAgICAgICB0ZXh0XG4gICAgICAgICAgLnNldFBsYWNlaG9sZGVyKCd3czovL2xvY2FsaG9zdDoxODc4OScpXG4gICAgICAgICAgLnNldFZhbHVlKHRoaXMucGx1Z2luLnNldHRpbmdzLmdhdGV3YXlVcmwpXG4gICAgICAgICAgLm9uQ2hhbmdlKGFzeW5jICh2YWx1ZSkgPT4ge1xuICAgICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3MuZ2F0ZXdheVVybCA9IHZhbHVlLnRyaW0oKTtcbiAgICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICAgIH0pXG4gICAgICApO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZSgnQXV0aCB0b2tlbicpXG4gICAgICAuc2V0RGVzYygnTXVzdCBtYXRjaCB0aGUgYXV0aFRva2VuIGluIHlvdXIgb3BlbmNsYXcuanNvbiBjaGFubmVsIGNvbmZpZy4gTmV2ZXIgc2hhcmVkLicpXG4gICAgICAuYWRkVGV4dCgodGV4dCkgPT4ge1xuICAgICAgICB0ZXh0XG4gICAgICAgICAgLnNldFBsYWNlaG9sZGVyKCdFbnRlciB0b2tlblx1MjAyNicpXG4gICAgICAgICAgLnNldFZhbHVlKHRoaXMucGx1Z2luLnNldHRpbmdzLmF1dGhUb2tlbilcbiAgICAgICAgICAub25DaGFuZ2UoYXN5bmMgKHZhbHVlKSA9PiB7XG4gICAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5hdXRoVG9rZW4gPSB2YWx1ZTtcbiAgICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICAgIH0pO1xuICAgICAgICAvLyBUcmVhdCBhcyBwYXNzd29yZCBmaWVsZCBcdTIwMTMgZG8gbm90IHJldmVhbCB0b2tlbiBpbiBVSVxuICAgICAgICB0ZXh0LmlucHV0RWwudHlwZSA9ICdwYXNzd29yZCc7XG4gICAgICAgIHRleHQuaW5wdXRFbC5hdXRvY29tcGxldGUgPSAnb2ZmJztcbiAgICAgIH0pO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZSgnU2Vzc2lvbiBLZXknKVxuICAgICAgLnNldERlc2MoJ09wZW5DbGF3IHNlc3Npb24gdG8gc3Vic2NyaWJlIHRvICh1c3VhbGx5IFwibWFpblwiKS4nKVxuICAgICAgLmFkZFRleHQoKHRleHQpID0+XG4gICAgICAgIHRleHRcbiAgICAgICAgICAuc2V0UGxhY2Vob2xkZXIoJ21haW4nKVxuICAgICAgICAgIC5zZXRWYWx1ZSh0aGlzLnBsdWdpbi5zZXR0aW5ncy5zZXNzaW9uS2V5KVxuICAgICAgICAgIC5vbkNoYW5nZShhc3luYyAodmFsdWUpID0+IHtcbiAgICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLnNlc3Npb25LZXkgPSB2YWx1ZS50cmltKCkgfHwgJ21haW4nO1xuICAgICAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uc2F2ZVNldHRpbmdzKCk7XG4gICAgICAgICAgfSlcbiAgICAgICk7XG5cbiAgICBuZXcgU2V0dGluZyhjb250YWluZXJFbClcbiAgICAgIC5zZXROYW1lKCdBY2NvdW50IElEJylcbiAgICAgIC5zZXREZXNjKCdPcGVuQ2xhdyBhY2NvdW50IElEICh1c3VhbGx5IFwibWFpblwiKS4nKVxuICAgICAgLmFkZFRleHQoKHRleHQpID0+XG4gICAgICAgIHRleHRcbiAgICAgICAgICAuc2V0UGxhY2Vob2xkZXIoJ21haW4nKVxuICAgICAgICAgIC5zZXRWYWx1ZSh0aGlzLnBsdWdpbi5zZXR0aW5ncy5hY2NvdW50SWQpXG4gICAgICAgICAgLm9uQ2hhbmdlKGFzeW5jICh2YWx1ZSkgPT4ge1xuICAgICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3MuYWNjb3VudElkID0gdmFsdWUudHJpbSgpIHx8ICdtYWluJztcbiAgICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICAgIH0pXG4gICAgICApO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZSgnSW5jbHVkZSBhY3RpdmUgbm90ZSBieSBkZWZhdWx0JylcbiAgICAgIC5zZXREZXNjKCdQcmUtY2hlY2sgXCJJbmNsdWRlIGFjdGl2ZSBub3RlXCIgaW4gdGhlIGNoYXQgcGFuZWwgd2hlbiBpdCBvcGVucy4nKVxuICAgICAgLmFkZFRvZ2dsZSgodG9nZ2xlKSA9PlxuICAgICAgICB0b2dnbGUuc2V0VmFsdWUodGhpcy5wbHVnaW4uc2V0dGluZ3MuaW5jbHVkZUFjdGl2ZU5vdGUpLm9uQ2hhbmdlKGFzeW5jICh2YWx1ZSkgPT4ge1xuICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLmluY2x1ZGVBY3RpdmVOb3RlID0gdmFsdWU7XG4gICAgICAgICAgYXdhaXQgdGhpcy5wbHVnaW4uc2F2ZVNldHRpbmdzKCk7XG4gICAgICAgIH0pXG4gICAgICApO1xuXG4gICAgY29udGFpbmVyRWwuY3JlYXRlRWwoJ3AnLCB7XG4gICAgICB0ZXh0OiAnUmVjb25uZWN0OiBjbG9zZSBhbmQgcmVvcGVuIHRoZSBzaWRlYmFyIGFmdGVyIGNoYW5naW5nIHRoZSBnYXRld2F5IFVSTCBvciB0b2tlbi4nLFxuICAgICAgY2xzOiAnc2V0dGluZy1pdGVtLWRlc2NyaXB0aW9uJyxcbiAgICB9KTtcbiAgfVxufVxuIiwgIi8qKlxuICogV2ViU29ja2V0IGNsaWVudCBmb3IgT3BlbkNsYXcgR2F0ZXdheVxuICpcbiAqIFBpdm90ICgyMDI2LTAyLTI1KTogRG8gTk9UIHVzZSBjdXN0b20gb2JzaWRpYW4uKiBnYXRld2F5IG1ldGhvZHMuXG4gKiBUaG9zZSByZXF1aXJlIG9wZXJhdG9yLmFkbWluIHNjb3BlIHdoaWNoIGlzIG5vdCBncmFudGVkIHRvIGV4dGVybmFsIGNsaWVudHMuXG4gKlxuICogQXV0aCBub3RlOlxuICogLSBjaGF0LnNlbmQgcmVxdWlyZXMgb3BlcmF0b3Iud3JpdGVcbiAqIC0gZXh0ZXJuYWwgY2xpZW50cyBtdXN0IHByZXNlbnQgYSBwYWlyZWQgZGV2aWNlIGlkZW50aXR5IHRvIHJlY2VpdmUgd3JpdGUgc2NvcGVzXG4gKlxuICogV2UgdXNlIGJ1aWx0LWluIGdhdGV3YXkgbWV0aG9kcy9ldmVudHM6XG4gKiAtIFNlbmQ6IGNoYXQuc2VuZCh7IHNlc3Npb25LZXksIG1lc3NhZ2UsIGlkZW1wb3RlbmN5S2V5LCAuLi4gfSlcbiAqIC0gUmVjZWl2ZTogZXZlbnQgXCJjaGF0XCIgKGZpbHRlciBieSBzZXNzaW9uS2V5KVxuICovXG5cbmltcG9ydCB0eXBlIHsgSW5ib3VuZFdTUGF5bG9hZCB9IGZyb20gJy4vdHlwZXMnO1xuXG4vKiogTWlsbGlzZWNvbmRzIGJlZm9yZSBhIHJlY29ubmVjdCBhdHRlbXB0IGFmdGVyIGFuIHVuZXhwZWN0ZWQgY2xvc2UgKi9cbmNvbnN0IFJFQ09OTkVDVF9ERUxBWV9NUyA9IDNfMDAwO1xuLyoqIEludGVydmFsIGZvciBzZW5kaW5nIGhlYXJ0YmVhdCBwaW5ncyAoY2hlY2sgY29ubmVjdGlvbiBsaXZlbmVzcykgKi9cbmNvbnN0IEhFQVJUQkVBVF9JTlRFUlZBTF9NUyA9IDMwXzAwMDtcblxuZXhwb3J0IHR5cGUgV1NDbGllbnRTdGF0ZSA9ICdkaXNjb25uZWN0ZWQnIHwgJ2Nvbm5lY3RpbmcnIHwgJ2hhbmRzaGFraW5nJyB8ICdjb25uZWN0ZWQnO1xuXG5pbnRlcmZhY2UgUGVuZGluZ1JlcXVlc3Qge1xuICByZXNvbHZlOiAocGF5bG9hZDogYW55KSA9PiB2b2lkO1xuICByZWplY3Q6IChlcnJvcjogYW55KSA9PiB2b2lkO1xufVxuXG50eXBlIERldmljZUlkZW50aXR5ID0ge1xuICBpZDogc3RyaW5nO1xuICBwdWJsaWNLZXk6IHN0cmluZzsgLy8gYmFzZTY0XG4gIHByaXZhdGVLZXlKd2s6IEpzb25XZWJLZXk7XG59O1xuXG5jb25zdCBERVZJQ0VfU1RPUkFHRV9LRVkgPSAnb3BlbmNsYXdDaGF0LmRldmljZUlkZW50aXR5LnYxJztcblxuZnVuY3Rpb24gYmFzZTY0RW5jb2RlKGJ5dGVzOiBBcnJheUJ1ZmZlcik6IHN0cmluZyB7XG4gIGNvbnN0IHU4ID0gbmV3IFVpbnQ4QXJyYXkoYnl0ZXMpO1xuICBsZXQgcyA9ICcnO1xuICBmb3IgKGxldCBpID0gMDsgaSA8IHU4Lmxlbmd0aDsgaSsrKSBzICs9IFN0cmluZy5mcm9tQ2hhckNvZGUodThbaV0pO1xuICByZXR1cm4gYnRvYShzKTtcbn1cblxuZnVuY3Rpb24gdXRmOEJ5dGVzKHRleHQ6IHN0cmluZyk6IFVpbnQ4QXJyYXkge1xuICByZXR1cm4gbmV3IFRleHRFbmNvZGVyKCkuZW5jb2RlKHRleHQpO1xufVxuXG5hc3luYyBmdW5jdGlvbiBsb2FkT3JDcmVhdGVEZXZpY2VJZGVudGl0eSgpOiBQcm9taXNlPERldmljZUlkZW50aXR5PiB7XG4gIGNvbnN0IGV4aXN0aW5nID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oREVWSUNFX1NUT1JBR0VfS0VZKTtcbiAgaWYgKGV4aXN0aW5nKSB7XG4gICAgY29uc3QgcGFyc2VkID0gSlNPTi5wYXJzZShleGlzdGluZykgYXMgRGV2aWNlSWRlbnRpdHk7XG4gICAgaWYgKHBhcnNlZD8uaWQgJiYgcGFyc2VkPy5wdWJsaWNLZXkgJiYgcGFyc2VkPy5wcml2YXRlS2V5SndrKSByZXR1cm4gcGFyc2VkO1xuICB9XG5cbiAgY29uc3Qga2V5UGFpciA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuZ2VuZXJhdGVLZXkoeyBuYW1lOiAnRWQyNTUxOScgfSwgdHJ1ZSwgWydzaWduJywgJ3ZlcmlmeSddKTtcbiAgY29uc3QgcHViUmF3ID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5leHBvcnRLZXkoJ3JhdycsIGtleVBhaXIucHVibGljS2V5KTtcbiAgY29uc3QgcHJpdkp3ayA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuZXhwb3J0S2V5KCdqd2snLCBrZXlQYWlyLnByaXZhdGVLZXkpO1xuXG4gIGNvbnN0IGlkID0gYG9ic2lkaWFuLSR7RGF0ZS5ub3coKX0tJHtNYXRoLnJhbmRvbSgpLnRvU3RyaW5nKDM2KS5zbGljZSgyLCA5KX1gO1xuICBjb25zdCBpZGVudGl0eTogRGV2aWNlSWRlbnRpdHkgPSB7XG4gICAgaWQsXG4gICAgcHVibGljS2V5OiBiYXNlNjRFbmNvZGUocHViUmF3KSxcbiAgICBwcml2YXRlS2V5SndrOiBwcml2SndrLFxuICB9O1xuXG4gIGxvY2FsU3RvcmFnZS5zZXRJdGVtKERFVklDRV9TVE9SQUdFX0tFWSwgSlNPTi5zdHJpbmdpZnkoaWRlbnRpdHkpKTtcbiAgcmV0dXJuIGlkZW50aXR5O1xufVxuXG5hc3luYyBmdW5jdGlvbiBzaWduTm9uY2UoaWRlbnRpdHk6IERldmljZUlkZW50aXR5LCBub25jZTogc3RyaW5nKTogUHJvbWlzZTx7IHNpZ25hdHVyZTogc3RyaW5nOyBzaWduZWRBdDogbnVtYmVyIH0+IHtcbiAgY29uc3QgcHJpdmF0ZUtleSA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KFxuICAgICdqd2snLFxuICAgIGlkZW50aXR5LnByaXZhdGVLZXlKd2ssXG4gICAgeyBuYW1lOiAnRWQyNTUxOScgfSxcbiAgICBmYWxzZSxcbiAgICBbJ3NpZ24nXSxcbiAgKTtcblxuICBjb25zdCBzaWduZWRBdCA9IERhdGUubm93KCk7XG4gIC8vIFNpZ25hdHVyZSBpcyBvdmVyIHRoZSBub25jZSBieXRlcyAoc2VydmVyLXByb3ZpZGVkKVxuICBjb25zdCBzaWcgPSBhd2FpdCBjcnlwdG8uc3VidGxlLnNpZ24oeyBuYW1lOiAnRWQyNTUxOScgfSwgcHJpdmF0ZUtleSwgdXRmOEJ5dGVzKG5vbmNlKSk7XG4gIHJldHVybiB7IHNpZ25hdHVyZTogYmFzZTY0RW5jb2RlKHNpZyksIHNpZ25lZEF0IH07XG59XG5cbmZ1bmN0aW9uIGV4dHJhY3RUZXh0RnJvbUdhdGV3YXlNZXNzYWdlKG1zZzogYW55KTogc3RyaW5nIHtcbiAgaWYgKCFtc2cpIHJldHVybiAnJztcblxuICAvLyBNb3N0IGNvbW1vbjogeyByb2xlLCBjb250ZW50IH0gd2hlcmUgY29udGVudCBjYW4gYmUgc3RyaW5nIG9yIFt7dHlwZTondGV4dCcsdGV4dDonLi4uJ31dXG4gIGNvbnN0IGNvbnRlbnQgPSBtc2cuY29udGVudCA/PyBtc2cubWVzc2FnZSA/PyBtc2c7XG4gIGlmICh0eXBlb2YgY29udGVudCA9PT0gJ3N0cmluZycpIHJldHVybiBjb250ZW50O1xuXG4gIGlmIChBcnJheS5pc0FycmF5KGNvbnRlbnQpKSB7XG4gICAgY29uc3QgcGFydHMgPSBjb250ZW50XG4gICAgICAuZmlsdGVyKChjKSA9PiBjICYmIHR5cGVvZiBjID09PSAnb2JqZWN0JyAmJiBjLnR5cGUgPT09ICd0ZXh0JyAmJiB0eXBlb2YgYy50ZXh0ID09PSAnc3RyaW5nJylcbiAgICAgIC5tYXAoKGMpID0+IGMudGV4dCk7XG4gICAgcmV0dXJuIHBhcnRzLmpvaW4oJ1xcbicpO1xuICB9XG5cbiAgLy8gRmFsbGJhY2tcbiAgdHJ5IHtcbiAgICByZXR1cm4gSlNPTi5zdHJpbmdpZnkoY29udGVudCk7XG4gIH0gY2F0Y2gge1xuICAgIHJldHVybiBTdHJpbmcoY29udGVudCk7XG4gIH1cbn1cblxuZXhwb3J0IGNsYXNzIE9ic2lkaWFuV1NDbGllbnQge1xuICBwcml2YXRlIHdzOiBXZWJTb2NrZXQgfCBudWxsID0gbnVsbDtcbiAgcHJpdmF0ZSByZWNvbm5lY3RUaW1lcjogUmV0dXJuVHlwZTx0eXBlb2Ygc2V0VGltZW91dD4gfCBudWxsID0gbnVsbDtcbiAgcHJpdmF0ZSBoZWFydGJlYXRUaW1lcjogUmV0dXJuVHlwZTx0eXBlb2Ygc2V0SW50ZXJ2YWw+IHwgbnVsbCA9IG51bGw7XG4gIHByaXZhdGUgaW50ZW50aW9uYWxDbG9zZSA9IGZhbHNlO1xuICBwcml2YXRlIHNlc3Npb25LZXk6IHN0cmluZztcbiAgcHJpdmF0ZSB1cmwgPSAnJztcbiAgcHJpdmF0ZSB0b2tlbiA9ICcnO1xuICBwcml2YXRlIHJlcXVlc3RJZCA9IDA7XG4gIHByaXZhdGUgcGVuZGluZ1JlcXVlc3RzID0gbmV3IE1hcDxzdHJpbmcsIFBlbmRpbmdSZXF1ZXN0PigpO1xuXG4gIHN0YXRlOiBXU0NsaWVudFN0YXRlID0gJ2Rpc2Nvbm5lY3RlZCc7XG5cbiAgb25NZXNzYWdlOiAoKG1zZzogSW5ib3VuZFdTUGF5bG9hZCkgPT4gdm9pZCkgfCBudWxsID0gbnVsbDtcbiAgb25TdGF0ZUNoYW5nZTogKChzdGF0ZTogV1NDbGllbnRTdGF0ZSkgPT4gdm9pZCkgfCBudWxsID0gbnVsbDtcblxuICBjb25zdHJ1Y3RvcihzZXNzaW9uS2V5OiBzdHJpbmcpIHtcbiAgICB0aGlzLnNlc3Npb25LZXkgPSBzZXNzaW9uS2V5O1xuICB9XG5cbiAgY29ubmVjdCh1cmw6IHN0cmluZywgdG9rZW46IHN0cmluZyk6IHZvaWQge1xuICAgIHRoaXMudXJsID0gdXJsO1xuICAgIHRoaXMudG9rZW4gPSB0b2tlbjtcbiAgICB0aGlzLmludGVudGlvbmFsQ2xvc2UgPSBmYWxzZTtcbiAgICB0aGlzLl9jb25uZWN0KCk7XG4gIH1cblxuICBkaXNjb25uZWN0KCk6IHZvaWQge1xuICAgIHRoaXMuaW50ZW50aW9uYWxDbG9zZSA9IHRydWU7XG4gICAgdGhpcy5fc3RvcFRpbWVycygpO1xuICAgIGlmICh0aGlzLndzKSB7XG4gICAgICB0aGlzLndzLmNsb3NlKCk7XG4gICAgICB0aGlzLndzID0gbnVsbDtcbiAgICB9XG4gICAgdGhpcy5fc2V0U3RhdGUoJ2Rpc2Nvbm5lY3RlZCcpO1xuICB9XG5cbiAgYXN5bmMgc2VuZE1lc3NhZ2UobWVzc2FnZTogc3RyaW5nKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgaWYgKHRoaXMuc3RhdGUgIT09ICdjb25uZWN0ZWQnKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ05vdCBjb25uZWN0ZWQgXHUyMDE0IGNhbGwgY29ubmVjdCgpIGZpcnN0Jyk7XG4gICAgfVxuXG4gICAgY29uc3QgaWRlbXBvdGVuY3lLZXkgPSBgb2JzaWRpYW4tJHtEYXRlLm5vdygpfS0ke01hdGgucmFuZG9tKCkudG9TdHJpbmcoMzYpLnNsaWNlKDIsIDkpfWA7XG5cbiAgICBhd2FpdCB0aGlzLl9zZW5kUmVxdWVzdCgnY2hhdC5zZW5kJywge1xuICAgICAgc2Vzc2lvbktleTogdGhpcy5zZXNzaW9uS2V5LFxuICAgICAgbWVzc2FnZSxcbiAgICAgIGlkZW1wb3RlbmN5S2V5LFxuICAgICAgLy8gZGVsaXZlciBkZWZhdWx0cyB0byB0cnVlIGluIGdhdGV3YXk7IGtlZXAgZGVmYXVsdFxuICAgIH0pO1xuICB9XG5cbiAgcHJpdmF0ZSBfY29ubmVjdCgpOiB2b2lkIHtcbiAgICBpZiAodGhpcy53cykge1xuICAgICAgdGhpcy53cy5vbm9wZW4gPSBudWxsO1xuICAgICAgdGhpcy53cy5vbmNsb3NlID0gbnVsbDtcbiAgICAgIHRoaXMud3Mub25tZXNzYWdlID0gbnVsbDtcbiAgICAgIHRoaXMud3Mub25lcnJvciA9IG51bGw7XG4gICAgICB0aGlzLndzLmNsb3NlKCk7XG4gICAgICB0aGlzLndzID0gbnVsbDtcbiAgICB9XG5cbiAgICB0aGlzLl9zZXRTdGF0ZSgnY29ubmVjdGluZycpO1xuXG4gICAgY29uc3Qgd3MgPSBuZXcgV2ViU29ja2V0KHRoaXMudXJsKTtcbiAgICB0aGlzLndzID0gd3M7XG5cbiAgICBsZXQgY29ubmVjdE5vbmNlOiBzdHJpbmcgfCBudWxsID0gbnVsbDtcbiAgICBsZXQgY29ubmVjdFN0YXJ0ZWQgPSBmYWxzZTtcblxuICAgIGNvbnN0IHRyeUNvbm5lY3QgPSBhc3luYyAoKSA9PiB7XG4gICAgICBpZiAoY29ubmVjdFN0YXJ0ZWQpIHJldHVybjtcbiAgICAgIGlmICghY29ubmVjdE5vbmNlKSByZXR1cm47XG4gICAgICBjb25uZWN0U3RhcnRlZCA9IHRydWU7XG5cbiAgICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IGlkZW50aXR5ID0gYXdhaXQgbG9hZE9yQ3JlYXRlRGV2aWNlSWRlbnRpdHkoKTtcbiAgICAgICAgY29uc3Qgc2lnID0gYXdhaXQgc2lnbk5vbmNlKGlkZW50aXR5LCBjb25uZWN0Tm9uY2UpO1xuXG4gICAgICAgIGF3YWl0IHRoaXMuX3NlbmRSZXF1ZXN0KCdjb25uZWN0Jywge1xuICAgICAgICAgIG1pblByb3RvY29sOiAzLFxuICAgICAgICAgIG1heFByb3RvY29sOiAzLFxuICAgICAgICAgIGNsaWVudDoge1xuICAgICAgICAgICAgaWQ6ICdnYXRld2F5LWNsaWVudCcsXG4gICAgICAgICAgICBtb2RlOiAnYmFja2VuZCcsXG4gICAgICAgICAgICB2ZXJzaW9uOiAnMC4xLjknLFxuICAgICAgICAgICAgcGxhdGZvcm06ICdlbGVjdHJvbicsXG4gICAgICAgICAgfSxcbiAgICAgICAgICByb2xlOiAnb3BlcmF0b3InLFxuICAgICAgICAgIHNjb3BlczogWydvcGVyYXRvci5yZWFkJywgJ29wZXJhdG9yLndyaXRlJ10sXG4gICAgICAgICAgZGV2aWNlOiB7XG4gICAgICAgICAgICBpZDogaWRlbnRpdHkuaWQsXG4gICAgICAgICAgICBwdWJsaWNLZXk6IGlkZW50aXR5LnB1YmxpY0tleSxcbiAgICAgICAgICAgIHNpZ25hdHVyZTogc2lnLnNpZ25hdHVyZSxcbiAgICAgICAgICAgIHNpZ25lZEF0OiBzaWcuc2lnbmVkQXQsXG4gICAgICAgICAgICBub25jZTogY29ubmVjdE5vbmNlLFxuICAgICAgICAgIH0sXG4gICAgICAgICAgYXV0aDoge1xuICAgICAgICAgICAgdG9rZW46IHRoaXMudG9rZW4sXG4gICAgICAgICAgfSxcbiAgICAgICAgfSk7XG5cbiAgICAgICAgdGhpcy5fc2V0U3RhdGUoJ2Nvbm5lY3RlZCcpO1xuICAgICAgICB0aGlzLl9zdGFydEhlYXJ0YmVhdCgpO1xuICAgICAgfSBjYXRjaCAoZXJyKSB7XG4gICAgICAgIGNvbnNvbGUuZXJyb3IoJ1tvY2xhdy13c10gQ29ubmVjdCBoYW5kc2hha2UgZmFpbGVkJywgZXJyKTtcbiAgICAgICAgd3MuY2xvc2UoKTtcbiAgICAgIH1cbiAgICB9O1xuXG4gICAgd3Mub25vcGVuID0gKCkgPT4ge1xuICAgICAgdGhpcy5fc2V0U3RhdGUoJ2hhbmRzaGFraW5nJyk7XG4gICAgICAvLyBUaGUgZ2F0ZXdheSB3aWxsIHNlbmQgY29ubmVjdC5jaGFsbGVuZ2U7IGNvbm5lY3QgaXMgc2VudCBvbmNlIHdlIGhhdmUgYSBub25jZS5cbiAgICB9O1xuXG4gICAgd3Mub25tZXNzYWdlID0gKGV2ZW50OiBNZXNzYWdlRXZlbnQpID0+IHtcbiAgICAgIGxldCBmcmFtZTogYW55O1xuICAgICAgdHJ5IHtcbiAgICAgICAgZnJhbWUgPSBKU09OLnBhcnNlKGV2ZW50LmRhdGEgYXMgc3RyaW5nKTtcbiAgICAgIH0gY2F0Y2gge1xuICAgICAgICBjb25zb2xlLmVycm9yKCdbb2NsYXctd3NdIEZhaWxlZCB0byBwYXJzZSBpbmNvbWluZyBtZXNzYWdlJyk7XG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cblxuICAgICAgLy8gUmVzcG9uc2VzXG4gICAgICBpZiAoZnJhbWUudHlwZSA9PT0gJ3JlcycpIHtcbiAgICAgICAgY29uc3QgcGVuZGluZyA9IHRoaXMucGVuZGluZ1JlcXVlc3RzLmdldChmcmFtZS5pZCk7XG4gICAgICAgIGlmIChwZW5kaW5nKSB7XG4gICAgICAgICAgdGhpcy5wZW5kaW5nUmVxdWVzdHMuZGVsZXRlKGZyYW1lLmlkKTtcbiAgICAgICAgICBpZiAoZnJhbWUub2spIHBlbmRpbmcucmVzb2x2ZShmcmFtZS5wYXlsb2FkKTtcbiAgICAgICAgICBlbHNlIHBlbmRpbmcucmVqZWN0KG5ldyBFcnJvcihmcmFtZS5lcnJvcj8ubWVzc2FnZSB8fCAnUmVxdWVzdCBmYWlsZWQnKSk7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuXG4gICAgICAvLyBFdmVudHNcbiAgICAgIGlmIChmcmFtZS50eXBlID09PSAnZXZlbnQnKSB7XG4gICAgICAgIGlmIChmcmFtZS5ldmVudCA9PT0gJ2Nvbm5lY3QuY2hhbGxlbmdlJykge1xuICAgICAgICAgIGNvbm5lY3ROb25jZSA9IGZyYW1lLnBheWxvYWQ/Lm5vbmNlIHx8IG51bGw7XG4gICAgICAgICAgLy8gQXR0ZW1wdCBoYW5kc2hha2Ugb25jZSB3ZSBoYXZlIGEgbm9uY2UuXG4gICAgICAgICAgdm9pZCB0cnlDb25uZWN0KCk7XG4gICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKGZyYW1lLmV2ZW50ID09PSAnY2hhdCcpIHtcbiAgICAgICAgICBjb25zdCBwYXlsb2FkID0gZnJhbWUucGF5bG9hZDtcbiAgICAgICAgICBpZiAocGF5bG9hZD8uc2Vzc2lvbktleSAhPT0gdGhpcy5zZXNzaW9uS2V5KSB7XG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgLy8gV2Ugb25seSBhcHBlbmQgYXNzaXN0YW50IG91dHB1dCB0byBVSS5cbiAgICAgICAgICBjb25zdCBtc2cgPSBwYXlsb2FkPy5tZXNzYWdlO1xuICAgICAgICAgIGNvbnN0IHJvbGUgPSBtc2c/LnJvbGUgPz8gJ2Fzc2lzdGFudCc7XG4gICAgICAgICAgaWYgKHJvbGUgIT09ICdhc3Npc3RhbnQnKSB7XG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgY29uc3QgdGV4dCA9IGV4dHJhY3RUZXh0RnJvbUdhdGV3YXlNZXNzYWdlKG1zZyk7XG4gICAgICAgICAgaWYgKCF0ZXh0KSByZXR1cm47XG5cbiAgICAgICAgICB0aGlzLm9uTWVzc2FnZT8uKHtcbiAgICAgICAgICAgIHR5cGU6ICdtZXNzYWdlJyxcbiAgICAgICAgICAgIHBheWxvYWQ6IHtcbiAgICAgICAgICAgICAgY29udGVudDogdGV4dCxcbiAgICAgICAgICAgICAgcm9sZTogJ2Fzc2lzdGFudCcsXG4gICAgICAgICAgICAgIHRpbWVzdGFtcDogRGF0ZS5ub3coKSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSk7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuXG4gICAgICBjb25zb2xlLmRlYnVnKCdbb2NsYXctd3NdIFVuaGFuZGxlZCBmcmFtZScsIGZyYW1lKTtcbiAgICB9O1xuXG4gICAgd3Mub25jbG9zZSA9ICgpID0+IHtcbiAgICAgIHRoaXMuX3N0b3BUaW1lcnMoKTtcbiAgICAgIHRoaXMuX3NldFN0YXRlKCdkaXNjb25uZWN0ZWQnKTtcblxuICAgICAgZm9yIChjb25zdCBwZW5kaW5nIG9mIHRoaXMucGVuZGluZ1JlcXVlc3RzLnZhbHVlcygpKSB7XG4gICAgICAgIHBlbmRpbmcucmVqZWN0KG5ldyBFcnJvcignQ29ubmVjdGlvbiBjbG9zZWQnKSk7XG4gICAgICB9XG4gICAgICB0aGlzLnBlbmRpbmdSZXF1ZXN0cy5jbGVhcigpO1xuXG4gICAgICBpZiAoIXRoaXMuaW50ZW50aW9uYWxDbG9zZSkge1xuICAgICAgICB0aGlzLl9zY2hlZHVsZVJlY29ubmVjdCgpO1xuICAgICAgfVxuICAgIH07XG5cbiAgICB3cy5vbmVycm9yID0gKGV2OiBFdmVudCkgPT4ge1xuICAgICAgY29uc29sZS5lcnJvcignW29jbGF3LXdzXSBXZWJTb2NrZXQgZXJyb3InLCBldik7XG4gICAgfTtcbiAgfVxuXG4gIHByaXZhdGUgX3NlbmRSZXF1ZXN0KG1ldGhvZDogc3RyaW5nLCBwYXJhbXM6IGFueSk6IFByb21pc2U8YW55PiB7XG4gICAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIGlmICghdGhpcy53cyB8fCB0aGlzLndzLnJlYWR5U3RhdGUgIT09IFdlYlNvY2tldC5PUEVOKSB7XG4gICAgICAgIHJlamVjdChuZXcgRXJyb3IoJ1dlYlNvY2tldCBub3QgY29ubmVjdGVkJykpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG5cbiAgICAgIGNvbnN0IGlkID0gYHJlcS0keysrdGhpcy5yZXF1ZXN0SWR9YDtcbiAgICAgIHRoaXMucGVuZGluZ1JlcXVlc3RzLnNldChpZCwgeyByZXNvbHZlLCByZWplY3QgfSk7XG5cbiAgICAgIHRoaXMud3Muc2VuZChcbiAgICAgICAgSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIHR5cGU6ICdyZXEnLFxuICAgICAgICAgIG1ldGhvZCxcbiAgICAgICAgICBpZCxcbiAgICAgICAgICBwYXJhbXMsXG4gICAgICAgIH0pXG4gICAgICApO1xuXG4gICAgICBzZXRUaW1lb3V0KCgpID0+IHtcbiAgICAgICAgaWYgKHRoaXMucGVuZGluZ1JlcXVlc3RzLmhhcyhpZCkpIHtcbiAgICAgICAgICB0aGlzLnBlbmRpbmdSZXF1ZXN0cy5kZWxldGUoaWQpO1xuICAgICAgICAgIHJlamVjdChuZXcgRXJyb3IoYFJlcXVlc3QgdGltZW91dDogJHttZXRob2R9YCkpO1xuICAgICAgICB9XG4gICAgICB9LCAzMF8wMDApO1xuICAgIH0pO1xuICB9XG5cbiAgcHJpdmF0ZSBfc2NoZWR1bGVSZWNvbm5lY3QoKTogdm9pZCB7XG4gICAgaWYgKHRoaXMucmVjb25uZWN0VGltZXIgIT09IG51bGwpIHJldHVybjtcbiAgICB0aGlzLnJlY29ubmVjdFRpbWVyID0gc2V0VGltZW91dCgoKSA9PiB7XG4gICAgICB0aGlzLnJlY29ubmVjdFRpbWVyID0gbnVsbDtcbiAgICAgIGlmICghdGhpcy5pbnRlbnRpb25hbENsb3NlKSB7XG4gICAgICAgIGNvbnNvbGUubG9nKGBbb2NsYXctd3NdIFJlY29ubmVjdGluZyB0byAke3RoaXMudXJsfVx1MjAyNmApO1xuICAgICAgICB0aGlzLl9jb25uZWN0KCk7XG4gICAgICB9XG4gICAgfSwgUkVDT05ORUNUX0RFTEFZX01TKTtcbiAgfVxuXG4gIHByaXZhdGUgX3N0YXJ0SGVhcnRiZWF0KCk6IHZvaWQge1xuICAgIHRoaXMuX3N0b3BIZWFydGJlYXQoKTtcbiAgICB0aGlzLmhlYXJ0YmVhdFRpbWVyID0gc2V0SW50ZXJ2YWwoKCkgPT4ge1xuICAgICAgaWYgKHRoaXMud3M/LnJlYWR5U3RhdGUgIT09IFdlYlNvY2tldC5PUEVOKSByZXR1cm47XG4gICAgICBpZiAodGhpcy53cy5idWZmZXJlZEFtb3VudCA+IDApIHtcbiAgICAgICAgY29uc29sZS53YXJuKCdbb2NsYXctd3NdIFNlbmQgYnVmZmVyIG5vdCBlbXB0eSBcdTIwMTQgY29ubmVjdGlvbiBtYXkgYmUgc3RhbGxlZCcpO1xuICAgICAgfVxuICAgIH0sIEhFQVJUQkVBVF9JTlRFUlZBTF9NUyk7XG4gIH1cblxuICBwcml2YXRlIF9zdG9wSGVhcnRiZWF0KCk6IHZvaWQge1xuICAgIGlmICh0aGlzLmhlYXJ0YmVhdFRpbWVyKSB7XG4gICAgICBjbGVhckludGVydmFsKHRoaXMuaGVhcnRiZWF0VGltZXIpO1xuICAgICAgdGhpcy5oZWFydGJlYXRUaW1lciA9IG51bGw7XG4gICAgfVxuICB9XG5cbiAgcHJpdmF0ZSBfc3RvcFRpbWVycygpOiB2b2lkIHtcbiAgICB0aGlzLl9zdG9wSGVhcnRiZWF0KCk7XG4gICAgaWYgKHRoaXMucmVjb25uZWN0VGltZXIpIHtcbiAgICAgIGNsZWFyVGltZW91dCh0aGlzLnJlY29ubmVjdFRpbWVyKTtcbiAgICAgIHRoaXMucmVjb25uZWN0VGltZXIgPSBudWxsO1xuICAgIH1cbiAgfVxuXG4gIHByaXZhdGUgX3NldFN0YXRlKHN0YXRlOiBXU0NsaWVudFN0YXRlKTogdm9pZCB7XG4gICAgaWYgKHRoaXMuc3RhdGUgPT09IHN0YXRlKSByZXR1cm47XG4gICAgdGhpcy5zdGF0ZSA9IHN0YXRlO1xuICAgIHRoaXMub25TdGF0ZUNoYW5nZT8uKHN0YXRlKTtcbiAgfVxufVxuIiwgImltcG9ydCB0eXBlIHsgQ2hhdE1lc3NhZ2UgfSBmcm9tICcuL3R5cGVzJztcblxuLyoqIE1hbmFnZXMgdGhlIGluLW1lbW9yeSBsaXN0IG9mIGNoYXQgbWVzc2FnZXMgYW5kIG5vdGlmaWVzIFVJIG9uIGNoYW5nZXMgKi9cbmV4cG9ydCBjbGFzcyBDaGF0TWFuYWdlciB7XG4gIHByaXZhdGUgbWVzc2FnZXM6IENoYXRNZXNzYWdlW10gPSBbXTtcblxuICAvKiogRmlyZWQgZm9yIGEgZnVsbCByZS1yZW5kZXIgKGNsZWFyL3JlbG9hZCkgKi9cbiAgb25VcGRhdGU6ICgobWVzc2FnZXM6IHJlYWRvbmx5IENoYXRNZXNzYWdlW10pID0+IHZvaWQpIHwgbnVsbCA9IG51bGw7XG4gIC8qKiBGaXJlZCB3aGVuIGEgc2luZ2xlIG1lc3NhZ2UgaXMgYXBwZW5kZWQgXHUyMDE0IHVzZSBmb3IgTygxKSBhcHBlbmQtb25seSBVSSAqL1xuICBvbk1lc3NhZ2VBZGRlZDogKChtc2c6IENoYXRNZXNzYWdlKSA9PiB2b2lkKSB8IG51bGwgPSBudWxsO1xuXG4gIGFkZE1lc3NhZ2UobXNnOiBDaGF0TWVzc2FnZSk6IHZvaWQge1xuICAgIHRoaXMubWVzc2FnZXMucHVzaChtc2cpO1xuICAgIHRoaXMub25NZXNzYWdlQWRkZWQ/Lihtc2cpO1xuICB9XG5cbiAgZ2V0TWVzc2FnZXMoKTogcmVhZG9ubHkgQ2hhdE1lc3NhZ2VbXSB7XG4gICAgcmV0dXJuIHRoaXMubWVzc2FnZXM7XG4gIH1cblxuICBjbGVhcigpOiB2b2lkIHtcbiAgICB0aGlzLm1lc3NhZ2VzID0gW107XG4gICAgdGhpcy5vblVwZGF0ZT8uKFtdKTtcbiAgfVxuXG4gIC8qKiBDcmVhdGUgYSB1c2VyIG1lc3NhZ2Ugb2JqZWN0ICh3aXRob3V0IGFkZGluZyBpdCkgKi9cbiAgc3RhdGljIGNyZWF0ZVVzZXJNZXNzYWdlKGNvbnRlbnQ6IHN0cmluZyk6IENoYXRNZXNzYWdlIHtcbiAgICByZXR1cm4ge1xuICAgICAgaWQ6IGBtc2ctJHtEYXRlLm5vdygpfS0ke01hdGgucmFuZG9tKCkudG9TdHJpbmcoMzYpLnNsaWNlKDIsIDcpfWAsXG4gICAgICByb2xlOiAndXNlcicsXG4gICAgICBjb250ZW50LFxuICAgICAgdGltZXN0YW1wOiBEYXRlLm5vdygpLFxuICAgIH07XG4gIH1cblxuICAvKiogQ3JlYXRlIGFuIGFzc2lzdGFudCBtZXNzYWdlIG9iamVjdCAod2l0aG91dCBhZGRpbmcgaXQpICovXG4gIHN0YXRpYyBjcmVhdGVBc3Npc3RhbnRNZXNzYWdlKGNvbnRlbnQ6IHN0cmluZyk6IENoYXRNZXNzYWdlIHtcbiAgICByZXR1cm4ge1xuICAgICAgaWQ6IGBtc2ctJHtEYXRlLm5vdygpfS0ke01hdGgucmFuZG9tKCkudG9TdHJpbmcoMzYpLnNsaWNlKDIsIDcpfWAsXG4gICAgICByb2xlOiAnYXNzaXN0YW50JyxcbiAgICAgIGNvbnRlbnQsXG4gICAgICB0aW1lc3RhbXA6IERhdGUubm93KCksXG4gICAgfTtcbiAgfVxuXG4gIC8qKiBDcmVhdGUgYSBzeXN0ZW0gLyBzdGF0dXMgbWVzc2FnZSAoZXJyb3JzLCByZWNvbm5lY3Qgbm90aWNlcywgZXRjLikgKi9cbiAgc3RhdGljIGNyZWF0ZVN5c3RlbU1lc3NhZ2UoY29udGVudDogc3RyaW5nKTogQ2hhdE1lc3NhZ2Uge1xuICAgIHJldHVybiB7XG4gICAgICBpZDogYHN5cy0ke0RhdGUubm93KCl9YCxcbiAgICAgIHJvbGU6ICdzeXN0ZW0nLFxuICAgICAgY29udGVudCxcbiAgICAgIHRpbWVzdGFtcDogRGF0ZS5ub3coKSxcbiAgICB9O1xuICB9XG59XG4iLCAiaW1wb3J0IHsgSXRlbVZpZXcsIFdvcmtzcGFjZUxlYWYgfSBmcm9tICdvYnNpZGlhbic7XG5pbXBvcnQgdHlwZSBPcGVuQ2xhd1BsdWdpbiBmcm9tICcuL21haW4nO1xuaW1wb3J0IHsgQ2hhdE1hbmFnZXIgfSBmcm9tICcuL2NoYXQnO1xuaW1wb3J0IHR5cGUgeyBDaGF0TWVzc2FnZSB9IGZyb20gJy4vdHlwZXMnO1xuaW1wb3J0IHsgZ2V0QWN0aXZlTm90ZUNvbnRleHQgfSBmcm9tICcuL2NvbnRleHQnO1xuXG5leHBvcnQgY29uc3QgVklFV19UWVBFX09QRU5DTEFXX0NIQVQgPSAnb3BlbmNsYXctY2hhdCc7XG5cbmV4cG9ydCBjbGFzcyBPcGVuQ2xhd0NoYXRWaWV3IGV4dGVuZHMgSXRlbVZpZXcge1xuICBwcml2YXRlIHBsdWdpbjogT3BlbkNsYXdQbHVnaW47XG4gIHByaXZhdGUgY2hhdE1hbmFnZXI6IENoYXRNYW5hZ2VyO1xuXG4gIC8vIERPTSByZWZzXG4gIHByaXZhdGUgbWVzc2FnZXNFbCE6IEhUTUxFbGVtZW50O1xuICBwcml2YXRlIGlucHV0RWwhOiBIVE1MVGV4dEFyZWFFbGVtZW50O1xuICBwcml2YXRlIHNlbmRCdG4hOiBIVE1MQnV0dG9uRWxlbWVudDtcbiAgcHJpdmF0ZSBpbmNsdWRlTm90ZUNoZWNrYm94ITogSFRNTElucHV0RWxlbWVudDtcbiAgcHJpdmF0ZSBzdGF0dXNEb3QhOiBIVE1MRWxlbWVudDtcblxuICBjb25zdHJ1Y3RvcihsZWFmOiBXb3Jrc3BhY2VMZWFmLCBwbHVnaW46IE9wZW5DbGF3UGx1Z2luKSB7XG4gICAgc3VwZXIobGVhZik7XG4gICAgdGhpcy5wbHVnaW4gPSBwbHVnaW47XG4gICAgdGhpcy5jaGF0TWFuYWdlciA9IHBsdWdpbi5jaGF0TWFuYWdlcjtcbiAgfVxuXG4gIGdldFZpZXdUeXBlKCk6IHN0cmluZyB7XG4gICAgcmV0dXJuIFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFUO1xuICB9XG5cbiAgZ2V0RGlzcGxheVRleHQoKTogc3RyaW5nIHtcbiAgICByZXR1cm4gJ09wZW5DbGF3IENoYXQnO1xuICB9XG5cbiAgZ2V0SWNvbigpOiBzdHJpbmcge1xuICAgIHJldHVybiAnbWVzc2FnZS1zcXVhcmUnO1xuICB9XG5cbiAgYXN5bmMgb25PcGVuKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIHRoaXMuX2J1aWxkVUkoKTtcblxuICAgIC8vIEZ1bGwgcmUtcmVuZGVyIG9uIGNsZWFyIC8gcmVsb2FkXG4gICAgdGhpcy5jaGF0TWFuYWdlci5vblVwZGF0ZSA9IChtc2dzKSA9PiB0aGlzLl9yZW5kZXJNZXNzYWdlcyhtc2dzKTtcbiAgICAvLyBPKDEpIGFwcGVuZCBmb3IgbmV3IG1lc3NhZ2VzXG4gICAgdGhpcy5jaGF0TWFuYWdlci5vbk1lc3NhZ2VBZGRlZCA9IChtc2cpID0+IHRoaXMuX2FwcGVuZE1lc3NhZ2UobXNnKTtcblxuICAgIC8vIFN1YnNjcmliZSB0byBXUyBzdGF0ZSBjaGFuZ2VzXG4gICAgdGhpcy5wbHVnaW4ud3NDbGllbnQub25TdGF0ZUNoYW5nZSA9IChzdGF0ZSkgPT4ge1xuICAgICAgY29uc3QgY29ubmVjdGVkID0gc3RhdGUgPT09ICdjb25uZWN0ZWQnO1xuICAgICAgdGhpcy5zdGF0dXNEb3QudG9nZ2xlQ2xhc3MoJ2Nvbm5lY3RlZCcsIGNvbm5lY3RlZCk7XG4gICAgICB0aGlzLnN0YXR1c0RvdC50aXRsZSA9IGBHYXRld2F5OiAke3N0YXRlfWA7XG4gICAgICB0aGlzLnNlbmRCdG4uZGlzYWJsZWQgPSAhY29ubmVjdGVkO1xuICAgIH07XG5cbiAgICAvLyBSZWZsZWN0IGN1cnJlbnQgc3RhdGVcbiAgICBjb25zdCBjb25uZWN0ZWQgPSB0aGlzLnBsdWdpbi53c0NsaWVudC5zdGF0ZSA9PT0gJ2Nvbm5lY3RlZCc7XG4gICAgdGhpcy5zdGF0dXNEb3QudG9nZ2xlQ2xhc3MoJ2Nvbm5lY3RlZCcsIGNvbm5lY3RlZCk7XG4gICAgdGhpcy5zZW5kQnRuLmRpc2FibGVkID0gIWNvbm5lY3RlZDtcblxuICAgIHRoaXMuX3JlbmRlck1lc3NhZ2VzKHRoaXMuY2hhdE1hbmFnZXIuZ2V0TWVzc2FnZXMoKSk7XG4gIH1cblxuICBhc3luYyBvbkNsb3NlKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIHRoaXMuY2hhdE1hbmFnZXIub25VcGRhdGUgPSBudWxsO1xuICAgIHRoaXMuY2hhdE1hbmFnZXIub25NZXNzYWdlQWRkZWQgPSBudWxsO1xuICAgIHRoaXMucGx1Z2luLndzQ2xpZW50Lm9uU3RhdGVDaGFuZ2UgPSBudWxsO1xuICB9XG5cbiAgLy8gXHUyNTAwXHUyNTAwIFVJIGNvbnN0cnVjdGlvbiBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcblxuICBwcml2YXRlIF9idWlsZFVJKCk6IHZvaWQge1xuICAgIGNvbnN0IHJvb3QgPSB0aGlzLmNvbnRlbnRFbDtcbiAgICByb290LmVtcHR5KCk7XG4gICAgcm9vdC5hZGRDbGFzcygnb2NsYXctY2hhdC12aWV3Jyk7XG5cbiAgICAvLyBcdTI1MDBcdTI1MDAgSGVhZGVyIFx1MjUwMFx1MjUwMFxuICAgIGNvbnN0IGhlYWRlciA9IHJvb3QuY3JlYXRlRGl2KHsgY2xzOiAnb2NsYXctaGVhZGVyJyB9KTtcbiAgICBoZWFkZXIuY3JlYXRlU3Bhbih7IGNsczogJ29jbGF3LWhlYWRlci10aXRsZScsIHRleHQ6ICdPcGVuQ2xhdyBDaGF0JyB9KTtcbiAgICB0aGlzLnN0YXR1c0RvdCA9IGhlYWRlci5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1zdGF0dXMtZG90JyB9KTtcbiAgICB0aGlzLnN0YXR1c0RvdC50aXRsZSA9ICdHYXRld2F5OiBkaXNjb25uZWN0ZWQnO1xuXG4gICAgLy8gXHUyNTAwXHUyNTAwIE1lc3NhZ2VzIGFyZWEgXHUyNTAwXHUyNTAwXG4gICAgdGhpcy5tZXNzYWdlc0VsID0gcm9vdC5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1tZXNzYWdlcycgfSk7XG5cbiAgICAvLyBcdTI1MDBcdTI1MDAgQ29udGV4dCByb3cgXHUyNTAwXHUyNTAwXG4gICAgY29uc3QgY3R4Um93ID0gcm9vdC5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1jb250ZXh0LXJvdycgfSk7XG4gICAgdGhpcy5pbmNsdWRlTm90ZUNoZWNrYm94ID0gY3R4Um93LmNyZWF0ZUVsKCdpbnB1dCcsIHsgdHlwZTogJ2NoZWNrYm94JyB9KTtcbiAgICB0aGlzLmluY2x1ZGVOb3RlQ2hlY2tib3guaWQgPSAnb2NsYXctaW5jbHVkZS1ub3RlJztcbiAgICB0aGlzLmluY2x1ZGVOb3RlQ2hlY2tib3guY2hlY2tlZCA9IHRoaXMucGx1Z2luLnNldHRpbmdzLmluY2x1ZGVBY3RpdmVOb3RlO1xuICAgIGNvbnN0IGN0eExhYmVsID0gY3R4Um93LmNyZWF0ZUVsKCdsYWJlbCcsIHsgdGV4dDogJ0luY2x1ZGUgYWN0aXZlIG5vdGUnIH0pO1xuICAgIGN0eExhYmVsLmh0bWxGb3IgPSAnb2NsYXctaW5jbHVkZS1ub3RlJztcblxuICAgIC8vIFx1MjUwMFx1MjUwMCBJbnB1dCByb3cgXHUyNTAwXHUyNTAwXG4gICAgY29uc3QgaW5wdXRSb3cgPSByb290LmNyZWF0ZURpdih7IGNsczogJ29jbGF3LWlucHV0LXJvdycgfSk7XG4gICAgdGhpcy5pbnB1dEVsID0gaW5wdXRSb3cuY3JlYXRlRWwoJ3RleHRhcmVhJywge1xuICAgICAgY2xzOiAnb2NsYXctaW5wdXQnLFxuICAgICAgcGxhY2Vob2xkZXI6ICdBc2sgYW55dGhpbmdcdTIwMjYnLFxuICAgIH0pO1xuICAgIHRoaXMuaW5wdXRFbC5yb3dzID0gMTtcblxuICAgIHRoaXMuc2VuZEJ0biA9IGlucHV0Um93LmNyZWF0ZUVsKCdidXR0b24nLCB7IGNsczogJ29jbGF3LXNlbmQtYnRuJywgdGV4dDogJ1NlbmQnIH0pO1xuXG4gICAgLy8gXHUyNTAwXHUyNTAwIEV2ZW50IGxpc3RlbmVycyBcdTI1MDBcdTI1MDBcbiAgICB0aGlzLnNlbmRCdG4uYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKSA9PiB0aGlzLl9oYW5kbGVTZW5kKCkpO1xuICAgIHRoaXMuaW5wdXRFbC5hZGRFdmVudExpc3RlbmVyKCdrZXlkb3duJywgKGUpID0+IHtcbiAgICAgIGlmIChlLmtleSA9PT0gJ0VudGVyJyAmJiAhZS5zaGlmdEtleSkge1xuICAgICAgICBlLnByZXZlbnREZWZhdWx0KCk7XG4gICAgICAgIHRoaXMuX2hhbmRsZVNlbmQoKTtcbiAgICAgIH1cbiAgICB9KTtcbiAgICAvLyBBdXRvLXJlc2l6ZSB0ZXh0YXJlYVxuICAgIHRoaXMuaW5wdXRFbC5hZGRFdmVudExpc3RlbmVyKCdpbnB1dCcsICgpID0+IHtcbiAgICAgIHRoaXMuaW5wdXRFbC5zdHlsZS5oZWlnaHQgPSAnYXV0byc7XG4gICAgICB0aGlzLmlucHV0RWwuc3R5bGUuaGVpZ2h0ID0gYCR7dGhpcy5pbnB1dEVsLnNjcm9sbEhlaWdodH1weGA7XG4gICAgfSk7XG4gIH1cblxuICAvLyBcdTI1MDBcdTI1MDAgTWVzc2FnZSByZW5kZXJpbmcgXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG5cbiAgcHJpdmF0ZSBfcmVuZGVyTWVzc2FnZXMobWVzc2FnZXM6IHJlYWRvbmx5IENoYXRNZXNzYWdlW10pOiB2b2lkIHtcbiAgICB0aGlzLm1lc3NhZ2VzRWwuZW1wdHkoKTtcblxuICAgIGlmIChtZXNzYWdlcy5sZW5ndGggPT09IDApIHtcbiAgICAgIHRoaXMubWVzc2FnZXNFbC5jcmVhdGVFbCgncCcsIHtcbiAgICAgICAgdGV4dDogJ1NlbmQgYSBtZXNzYWdlIHRvIHN0YXJ0IGNoYXR0aW5nLicsXG4gICAgICAgIGNsczogJ29jbGF3LW1lc3NhZ2Ugc3lzdGVtIG9jbGF3LXBsYWNlaG9sZGVyJyxcbiAgICAgIH0pO1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIGZvciAoY29uc3QgbXNnIG9mIG1lc3NhZ2VzKSB7XG4gICAgICBjb25zdCBlbCA9IHRoaXMubWVzc2FnZXNFbC5jcmVhdGVEaXYoeyBjbHM6IGBvY2xhdy1tZXNzYWdlICR7bXNnLnJvbGV9YCB9KTtcbiAgICAgIGVsLmNyZWF0ZVNwYW4oeyB0ZXh0OiBtc2cuY29udGVudCB9KTtcbiAgICB9XG5cbiAgICAvLyBTY3JvbGwgdG8gYm90dG9tXG4gICAgdGhpcy5tZXNzYWdlc0VsLnNjcm9sbFRvcCA9IHRoaXMubWVzc2FnZXNFbC5zY3JvbGxIZWlnaHQ7XG4gIH1cblxuICAvKiogQXBwZW5kcyBhIHNpbmdsZSBtZXNzYWdlIHdpdGhvdXQgcmVidWlsZGluZyB0aGUgRE9NIChPKDEpKSAqL1xuICBwcml2YXRlIF9hcHBlbmRNZXNzYWdlKG1zZzogQ2hhdE1lc3NhZ2UpOiB2b2lkIHtcbiAgICAvLyBSZW1vdmUgZW1wdHktc3RhdGUgcGxhY2Vob2xkZXIgaWYgcHJlc2VudFxuICAgIHRoaXMubWVzc2FnZXNFbC5xdWVyeVNlbGVjdG9yKCcub2NsYXctcGxhY2Vob2xkZXInKT8ucmVtb3ZlKCk7XG5cbiAgICBjb25zdCBlbCA9IHRoaXMubWVzc2FnZXNFbC5jcmVhdGVEaXYoeyBjbHM6IGBvY2xhdy1tZXNzYWdlICR7bXNnLnJvbGV9YCB9KTtcbiAgICBlbC5jcmVhdGVTcGFuKHsgdGV4dDogbXNnLmNvbnRlbnQgfSk7XG5cbiAgICAvLyBTY3JvbGwgdG8gYm90dG9tXG4gICAgdGhpcy5tZXNzYWdlc0VsLnNjcm9sbFRvcCA9IHRoaXMubWVzc2FnZXNFbC5zY3JvbGxIZWlnaHQ7XG4gIH1cblxuICAvLyBcdTI1MDBcdTI1MDAgU2VuZCBoYW5kbGVyIFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFxuXG4gIHByaXZhdGUgYXN5bmMgX2hhbmRsZVNlbmQoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgY29uc3QgdGV4dCA9IHRoaXMuaW5wdXRFbC52YWx1ZS50cmltKCk7XG4gICAgaWYgKCF0ZXh0KSByZXR1cm47XG5cbiAgICAvLyBCdWlsZCBtZXNzYWdlIHdpdGggY29udGV4dCBpZiBlbmFibGVkXG4gICAgbGV0IG1lc3NhZ2UgPSB0ZXh0O1xuICAgIGlmICh0aGlzLmluY2x1ZGVOb3RlQ2hlY2tib3guY2hlY2tlZCkge1xuICAgICAgY29uc3Qgbm90ZSA9IGF3YWl0IGdldEFjdGl2ZU5vdGVDb250ZXh0KHRoaXMuYXBwKTtcbiAgICAgIGlmIChub3RlKSB7XG4gICAgICAgIG1lc3NhZ2UgPSBgQ29udGV4dDogW1ske25vdGUudGl0bGV9XV1cXG5cXG4ke3RleHR9YDtcbiAgICAgIH1cbiAgICB9XG5cbiAgICAvLyBBZGQgdXNlciBtZXNzYWdlIHRvIGNoYXQgVUlcbiAgICBjb25zdCB1c2VyTXNnID0gQ2hhdE1hbmFnZXIuY3JlYXRlVXNlck1lc3NhZ2UodGV4dCk7XG4gICAgdGhpcy5jaGF0TWFuYWdlci5hZGRNZXNzYWdlKHVzZXJNc2cpO1xuXG4gICAgLy8gQ2xlYXIgaW5wdXRcbiAgICB0aGlzLmlucHV0RWwudmFsdWUgPSAnJztcbiAgICB0aGlzLmlucHV0RWwuc3R5bGUuaGVpZ2h0ID0gJ2F1dG8nO1xuXG4gICAgLy8gU2VuZCBvdmVyIFdTIChhc3luYylcbiAgICB0cnkge1xuICAgICAgYXdhaXQgdGhpcy5wbHVnaW4ud3NDbGllbnQuc2VuZE1lc3NhZ2UobWVzc2FnZSk7XG4gICAgfSBjYXRjaCAoZXJyKSB7XG4gICAgICBjb25zb2xlLmVycm9yKCdbb2NsYXddIFNlbmQgZmFpbGVkJywgZXJyKTtcbiAgICAgIHRoaXMuY2hhdE1hbmFnZXIuYWRkTWVzc2FnZShcbiAgICAgICAgQ2hhdE1hbmFnZXIuY3JlYXRlU3lzdGVtTWVzc2FnZShgXHUyNkEwIFNlbmQgZmFpbGVkOiAke2Vycn1gKVxuICAgICAgKTtcbiAgICB9XG4gIH1cbn1cbiIsICJpbXBvcnQgdHlwZSB7IEFwcCB9IGZyb20gJ29ic2lkaWFuJztcblxuZXhwb3J0IGludGVyZmFjZSBOb3RlQ29udGV4dCB7XG4gIHRpdGxlOiBzdHJpbmc7XG4gIHBhdGg6IHN0cmluZztcbiAgY29udGVudDogc3RyaW5nO1xufVxuXG4vKipcbiAqIFJldHVybnMgdGhlIGFjdGl2ZSBub3RlJ3MgdGl0bGUgYW5kIGNvbnRlbnQsIG9yIG51bGwgaWYgbm8gbm90ZSBpcyBvcGVuLlxuICogQXN5bmMgYmVjYXVzZSB2YXVsdC5yZWFkKCkgaXMgYXN5bmMuXG4gKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBnZXRBY3RpdmVOb3RlQ29udGV4dChhcHA6IEFwcCk6IFByb21pc2U8Tm90ZUNvbnRleHQgfCBudWxsPiB7XG4gIGNvbnN0IGZpbGUgPSBhcHAud29ya3NwYWNlLmdldEFjdGl2ZUZpbGUoKTtcbiAgaWYgKCFmaWxlKSByZXR1cm4gbnVsbDtcblxuICB0cnkge1xuICAgIGNvbnN0IGNvbnRlbnQgPSBhd2FpdCBhcHAudmF1bHQucmVhZChmaWxlKTtcbiAgICByZXR1cm4ge1xuICAgICAgdGl0bGU6IGZpbGUuYmFzZW5hbWUsXG4gICAgICBwYXRoOiBmaWxlLnBhdGgsXG4gICAgICBjb250ZW50LFxuICAgIH07XG4gIH0gY2F0Y2ggKGVycikge1xuICAgIGNvbnNvbGUuZXJyb3IoJ1tvY2xhdy1jb250ZXh0XSBGYWlsZWQgdG8gcmVhZCBhY3RpdmUgbm90ZScsIGVycik7XG4gICAgcmV0dXJuIG51bGw7XG4gIH1cbn1cbiIsICIvKiogUGVyc2lzdGVkIHBsdWdpbiBjb25maWd1cmF0aW9uICovXG5leHBvcnQgaW50ZXJmYWNlIE9wZW5DbGF3U2V0dGluZ3Mge1xuICAvKiogV2ViU29ja2V0IFVSTCBvZiB0aGUgT3BlbkNsYXcgR2F0ZXdheSAoZS5nLiB3czovLzEwMC45MC45LjY4OjE4Nzg5KSAqL1xuICBnYXRld2F5VXJsOiBzdHJpbmc7XG4gIC8qKiBBdXRoIHRva2VuIFx1MjAxNCBtdXN0IG1hdGNoIHRoZSBjaGFubmVsIHBsdWdpbidzIGF1dGhUb2tlbiAqL1xuICBhdXRoVG9rZW46IHN0cmluZztcbiAgLyoqIE9wZW5DbGF3IHNlc3Npb24ga2V5IHRvIHN1YnNjcmliZSB0byAoZS5nLiBcIm1haW5cIikgKi9cbiAgc2Vzc2lvbktleTogc3RyaW5nO1xuICAvKiogKERlcHJlY2F0ZWQpIE9wZW5DbGF3IGFjY291bnQgSUQgKHVudXNlZDsgY2hhdC5zZW5kIHVzZXMgc2Vzc2lvbktleSkgKi9cbiAgYWNjb3VudElkOiBzdHJpbmc7XG4gIC8qKiBXaGV0aGVyIHRvIGluY2x1ZGUgdGhlIGFjdGl2ZSBub3RlIGNvbnRlbnQgd2l0aCBlYWNoIG1lc3NhZ2UgKi9cbiAgaW5jbHVkZUFjdGl2ZU5vdGU6IGJvb2xlYW47XG59XG5cbmV4cG9ydCBjb25zdCBERUZBVUxUX1NFVFRJTkdTOiBPcGVuQ2xhd1NldHRpbmdzID0ge1xuICBnYXRld2F5VXJsOiAnd3M6Ly9sb2NhbGhvc3Q6MTg3ODknLFxuICBhdXRoVG9rZW46ICcnLFxuICBzZXNzaW9uS2V5OiAnbWFpbicsXG4gIGFjY291bnRJZDogJ21haW4nLFxuICBpbmNsdWRlQWN0aXZlTm90ZTogZmFsc2UsXG59O1xuXG4vKiogQSBzaW5nbGUgY2hhdCBtZXNzYWdlICovXG5leHBvcnQgaW50ZXJmYWNlIENoYXRNZXNzYWdlIHtcbiAgaWQ6IHN0cmluZztcbiAgcm9sZTogJ3VzZXInIHwgJ2Fzc2lzdGFudCcgfCAnc3lzdGVtJztcbiAgY29udGVudDogc3RyaW5nO1xuICB0aW1lc3RhbXA6IG51bWJlcjtcbn1cblxuLyoqIFBheWxvYWQgZm9yIG1lc3NhZ2VzIFNFTlQgdG8gdGhlIHNlcnZlciAob3V0Ym91bmQpICovXG5leHBvcnQgaW50ZXJmYWNlIFdTUGF5bG9hZCB7XG4gIHR5cGU6ICdhdXRoJyB8ICdtZXNzYWdlJyB8ICdwaW5nJyB8ICdwb25nJyB8ICdlcnJvcic7XG4gIHBheWxvYWQ/OiBSZWNvcmQ8c3RyaW5nLCB1bmtub3duPjtcbn1cblxuLyoqIE1lc3NhZ2VzIFJFQ0VJVkVEIGZyb20gdGhlIHNlcnZlciAoaW5ib3VuZCkgXHUyMDE0IGRpc2NyaW1pbmF0ZWQgdW5pb24gKi9cbmV4cG9ydCB0eXBlIEluYm91bmRXU1BheWxvYWQgPVxuICB8IHsgdHlwZTogJ21lc3NhZ2UnOyBwYXlsb2FkOiB7IGNvbnRlbnQ6IHN0cmluZzsgcm9sZTogc3RyaW5nOyB0aW1lc3RhbXA6IG51bWJlciB9IH1cbiAgfCB7IHR5cGU6ICdlcnJvcic7IHBheWxvYWQ6IHsgbWVzc2FnZTogc3RyaW5nIH0gfTtcblxuLyoqIEF2YWlsYWJsZSBhZ2VudHMgLyBtb2RlbHMgKi9cbmV4cG9ydCBpbnRlcmZhY2UgQWdlbnRPcHRpb24ge1xuICBpZDogc3RyaW5nO1xuICBsYWJlbDogc3RyaW5nO1xufVxuIl0sCiAgIm1hcHBpbmdzIjogIjs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQSxJQUFBQSxtQkFBOEM7OztBQ0E5QyxzQkFBK0M7QUFHeEMsSUFBTSxxQkFBTixjQUFpQyxpQ0FBaUI7QUFBQSxFQUd2RCxZQUFZLEtBQVUsUUFBd0I7QUFDNUMsVUFBTSxLQUFLLE1BQU07QUFDakIsU0FBSyxTQUFTO0FBQUEsRUFDaEI7QUFBQSxFQUVBLFVBQWdCO0FBQ2QsVUFBTSxFQUFFLFlBQVksSUFBSTtBQUN4QixnQkFBWSxNQUFNO0FBRWxCLGdCQUFZLFNBQVMsTUFBTSxFQUFFLE1BQU0sZ0NBQTJCLENBQUM7QUFFL0QsUUFBSSx3QkFBUSxXQUFXLEVBQ3BCLFFBQVEsYUFBYSxFQUNyQixRQUFRLG1FQUFtRSxFQUMzRTtBQUFBLE1BQVEsQ0FBQyxTQUNSLEtBQ0csZUFBZSxzQkFBc0IsRUFDckMsU0FBUyxLQUFLLE9BQU8sU0FBUyxVQUFVLEVBQ3hDLFNBQVMsQ0FBTyxVQUFVO0FBQ3pCLGFBQUssT0FBTyxTQUFTLGFBQWEsTUFBTSxLQUFLO0FBQzdDLGNBQU0sS0FBSyxPQUFPLGFBQWE7QUFBQSxNQUNqQyxFQUFDO0FBQUEsSUFDTDtBQUVGLFFBQUksd0JBQVEsV0FBVyxFQUNwQixRQUFR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
