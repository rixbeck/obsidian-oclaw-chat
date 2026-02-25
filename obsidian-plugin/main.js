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
var ObsidianWSClient = class {
  constructor(sessionKey, accountId = "main") {
    this.ws = null;
    this.reconnectTimer = null;
    this.heartbeatTimer = null;
    this.intentionalClose = false;
    this.subscriptionId = null;
    this.url = "";
    this.token = "";
    this.requestId = 0;
    this.pendingRequests = /* @__PURE__ */ new Map();
    this.state = "disconnected";
    // ── Callbacks (set by consumers) ─────────────────────────────────────────
    this.onMessage = null;
    this.onStateChange = null;
    this.sessionKey = sessionKey;
    this.accountId = accountId;
  }
  // ── Public API ────────────────────────────────────────────────────────────
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
      if (!this.subscriptionId) {
        throw new Error("Not subscribed \u2014 call connect() first");
      }
      yield this._sendRequest("obsidian.send", {
        subscriptionId: this.subscriptionId,
        message
      });
    });
  }
  // ── Internal ──────────────────────────────────────────────────────────────
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
    ws.onopen = () => __async(this, null, function* () {
      this._setState("handshaking");
      try {
        yield this._sendRequest("connect", {
          minProtocol: 1,
          maxProtocol: 1,
          client: {
            id: "webchat-ui",
            mode: "ui",
            version: "0.1.0",
            platform: "electron"
          },
          auth: {
            token: this.token
          }
        });
        this._setState("subscribing");
        const result = yield this._sendRequest("obsidian.subscribe", {
          token: this.token,
          sessionKey: this.sessionKey,
          accountId: this.accountId
        });
        if (result == null ? void 0 : result.subscriptionId) {
          this.subscriptionId = result.subscriptionId;
          this._setState("connected");
          this._startHeartbeat();
        } else {
          throw new Error("Subscribe failed: no subscriptionId returned");
        }
      } catch (err) {
        console.error("[oclaw-ws] Connection setup failed", err);
        ws.close();
      }
    });
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
          if (frame.ok) {
            pending.resolve(frame.payload);
          } else {
            pending.reject(new Error(((_a = frame.error) == null ? void 0 : _a.message) || "Request failed"));
          }
        }
        return;
      }
      if (frame.type === "event") {
        if (frame.event === "obsidian.message") {
          const msg = {
            type: "message",
            payload: {
              content: ((_b = frame.payload) == null ? void 0 : _b.content) || "",
              role: ((_c = frame.payload) == null ? void 0 : _c.role) || "assistant",
              timestamp: ((_d = frame.payload) == null ? void 0 : _d.timestamp) || Date.now()
            }
          };
          (_e = this.onMessage) == null ? void 0 : _e.call(this, msg);
          return;
        }
        return;
      }
      console.debug("[oclaw-ws] Unhandled frame", frame);
    };
    ws.onclose = () => {
      this._stopTimers();
      this._setState("disconnected");
      this.subscriptionId = null;
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
      const frame = {
        type: "req",
        method,
        id,
        params
      };
      this.ws.send(JSON.stringify(frame));
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
      this.wsClient = new ObsidianWSClient(
        this.settings.sessionKey,
        this.settings.accountId
      );
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
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsic3JjL21haW4udHMiLCAic3JjL3NldHRpbmdzLnRzIiwgInNyYy93ZWJzb2NrZXQudHMiLCAic3JjL2NoYXQudHMiLCAic3JjL3ZpZXcudHMiLCAic3JjL2NvbnRleHQudHMiLCAic3JjL3R5cGVzLnRzIl0sCiAgInNvdXJjZXNDb250ZW50IjogWyJpbXBvcnQgeyBOb3RpY2UsIFBsdWdpbiwgV29ya3NwYWNlTGVhZiB9IGZyb20gJ29ic2lkaWFuJztcbmltcG9ydCB7IE9wZW5DbGF3U2V0dGluZ1RhYiB9IGZyb20gJy4vc2V0dGluZ3MnO1xuaW1wb3J0IHsgT2JzaWRpYW5XU0NsaWVudCB9IGZyb20gJy4vd2Vic29ja2V0JztcbmltcG9ydCB7IENoYXRNYW5hZ2VyIH0gZnJvbSAnLi9jaGF0JztcbmltcG9ydCB7IFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFULCBPcGVuQ2xhd0NoYXRWaWV3IH0gZnJvbSAnLi92aWV3JztcbmltcG9ydCB7IERFRkFVTFRfU0VUVElOR1MsIHR5cGUgT3BlbkNsYXdTZXR0aW5ncyB9IGZyb20gJy4vdHlwZXMnO1xuXG5leHBvcnQgZGVmYXVsdCBjbGFzcyBPcGVuQ2xhd1BsdWdpbiBleHRlbmRzIFBsdWdpbiB7XG4gIHNldHRpbmdzITogT3BlbkNsYXdTZXR0aW5ncztcbiAgd3NDbGllbnQhOiBPYnNpZGlhbldTQ2xpZW50O1xuICBjaGF0TWFuYWdlciE6IENoYXRNYW5hZ2VyO1xuXG4gIGFzeW5jIG9ubG9hZCgpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBhd2FpdCB0aGlzLmxvYWRTZXR0aW5ncygpO1xuXG4gICAgdGhpcy53c0NsaWVudCA9IG5ldyBPYnNpZGlhbldTQ2xpZW50KFxuICAgICAgdGhpcy5zZXR0aW5ncy5zZXNzaW9uS2V5LFxuICAgICAgdGhpcy5zZXR0aW5ncy5hY2NvdW50SWRcbiAgICApO1xuICAgIHRoaXMuY2hhdE1hbmFnZXIgPSBuZXcgQ2hhdE1hbmFnZXIoKTtcblxuICAgIC8vIFdpcmUgaW5jb21pbmcgV1MgbWVzc2FnZXMgXHUyMTkyIENoYXRNYW5hZ2VyXG4gICAgdGhpcy53c0NsaWVudC5vbk1lc3NhZ2UgPSAobXNnKSA9PiB7XG4gICAgICBpZiAobXNnLnR5cGUgPT09ICdtZXNzYWdlJykge1xuICAgICAgICB0aGlzLmNoYXRNYW5hZ2VyLmFkZE1lc3NhZ2UoQ2hhdE1hbmFnZXIuY3JlYXRlQXNzaXN0YW50TWVzc2FnZShtc2cucGF5bG9hZC5jb250ZW50KSk7XG4gICAgICB9IGVsc2UgaWYgKG1zZy50eXBlID09PSAnZXJyb3InKSB7XG4gICAgICAgIGNvbnN0IGVyclRleHQgPSBtc2cucGF5bG9hZC5tZXNzYWdlID8/ICdVbmtub3duIGVycm9yIGZyb20gZ2F0ZXdheSc7XG4gICAgICAgIHRoaXMuY2hhdE1hbmFnZXIuYWRkTWVzc2FnZShDaGF0TWFuYWdlci5jcmVhdGVTeXN0ZW1NZXNzYWdlKGBcdTI2QTAgJHtlcnJUZXh0fWApKTtcbiAgICAgIH1cbiAgICB9O1xuXG4gICAgLy8gUmVnaXN0ZXIgdGhlIHNpZGViYXIgdmlld1xuICAgIHRoaXMucmVnaXN0ZXJWaWV3KFxuICAgICAgVklFV19UWVBFX09QRU5DTEFXX0NIQVQsXG4gICAgICAobGVhZjogV29ya3NwYWNlTGVhZikgPT4gbmV3IE9wZW5DbGF3Q2hhdFZpZXcobGVhZiwgdGhpcylcbiAgICApO1xuXG4gICAgLy8gUmliYm9uIGljb24gXHUyMDE0IG9wZW5zIC8gcmV2ZWFscyB0aGUgY2hhdCBzaWRlYmFyXG4gICAgdGhpcy5hZGRSaWJib25JY29uKCdtZXNzYWdlLXNxdWFyZScsICdPcGVuQ2xhdyBDaGF0JywgKCkgPT4ge1xuICAgICAgdGhpcy5fYWN0aXZhdGVDaGF0VmlldygpO1xuICAgIH0pO1xuXG4gICAgLy8gU2V0dGluZ3MgdGFiXG4gICAgdGhpcy5hZGRTZXR0aW5nVGFiKG5ldyBPcGVuQ2xhd1NldHRpbmdUYWIodGhpcy5hcHAsIHRoaXMpKTtcblxuICAgIC8vIENvbW1hbmQgcGFsZXR0ZSBlbnRyeVxuICAgIHRoaXMuYWRkQ29tbWFuZCh7XG4gICAgICBpZDogJ29wZW4tb3BlbmNsYXctY2hhdCcsXG4gICAgICBuYW1lOiAnT3BlbiBjaGF0IHNpZGViYXInLFxuICAgICAgY2FsbGJhY2s6ICgpID0+IHRoaXMuX2FjdGl2YXRlQ2hhdFZpZXcoKSxcbiAgICB9KTtcblxuICAgIC8vIENvbm5lY3QgdG8gZ2F0ZXdheSBpZiB0b2tlbiBpcyBjb25maWd1cmVkXG4gICAgaWYgKHRoaXMuc2V0dGluZ3MuYXV0aFRva2VuKSB7XG4gICAgICB0aGlzLl9jb25uZWN0V1MoKTtcbiAgICB9IGVsc2Uge1xuICAgICAgbmV3IE5vdGljZSgnT3BlbkNsYXcgQ2hhdDogcGxlYXNlIGNvbmZpZ3VyZSB5b3VyIGdhdGV3YXkgdG9rZW4gaW4gU2V0dGluZ3MuJyk7XG4gICAgfVxuXG4gICAgY29uc29sZS5sb2coJ1tvY2xhd10gUGx1Z2luIGxvYWRlZCcpO1xuICB9XG5cbiAgYXN5bmMgb251bmxvYWQoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgdGhpcy53c0NsaWVudC5kaXNjb25uZWN0KCk7XG4gICAgdGhpcy5hcHAud29ya3NwYWNlLmRldGFjaExlYXZlc09mVHlwZShWSUVXX1RZUEVfT1BFTkNMQVdfQ0hBVCk7XG4gICAgY29uc29sZS5sb2coJ1tvY2xhd10gUGx1Z2luIHVubG9hZGVkJyk7XG4gIH1cblxuICBhc3luYyBsb2FkU2V0dGluZ3MoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgdGhpcy5zZXR0aW5ncyA9IE9iamVjdC5hc3NpZ24oe30sIERFRkFVTFRfU0VUVElOR1MsIGF3YWl0IHRoaXMubG9hZERhdGEoKSk7XG4gIH1cblxuICBhc3luYyBzYXZlU2V0dGluZ3MoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgYXdhaXQgdGhpcy5zYXZlRGF0YSh0aGlzLnNldHRpbmdzKTtcbiAgfVxuXG4gIC8vIFx1MjUwMFx1MjUwMCBIZWxwZXJzIFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFxuXG4gIHByaXZhdGUgX2Nvbm5lY3RXUygpOiB2b2lkIHtcbiAgICB0aGlzLndzQ2xpZW50LmNvbm5lY3QoXG4gICAgICB0aGlzLnNldHRpbmdzLmdhdGV3YXlVcmwsXG4gICAgICB0aGlzLnNldHRpbmdzLmF1dGhUb2tlblxuICAgICk7XG4gIH1cblxuICBwcml2YXRlIGFzeW5jIF9hY3RpdmF0ZUNoYXRWaWV3KCk6IFByb21pc2U8dm9pZD4ge1xuICAgIGNvbnN0IHsgd29ya3NwYWNlIH0gPSB0aGlzLmFwcDtcblxuICAgIC8vIFJldXNlIGV4aXN0aW5nIGxlYWYgaWYgYWxyZWFkeSBvcGVuXG4gICAgY29uc3QgZXhpc3RpbmcgPSB3b3Jrc3BhY2UuZ2V0TGVhdmVzT2ZUeXBlKFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFUKTtcbiAgICBpZiAoZXhpc3RpbmcubGVuZ3RoID4gMCkge1xuICAgICAgd29ya3NwYWNlLnJldmVhbExlYWYoZXhpc3RpbmdbMF0pO1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIC8vIE9wZW4gaW4gcmlnaHQgc2lkZWJhclxuICAgIGNvbnN0IGxlYWYgPSB3b3Jrc3BhY2UuZ2V0UmlnaHRMZWFmKGZhbHNlKTtcbiAgICBpZiAoIWxlYWYpIHJldHVybjtcbiAgICBhd2FpdCBsZWFmLnNldFZpZXdTdGF0ZSh7IHR5cGU6IFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFULCBhY3RpdmU6IHRydWUgfSk7XG4gICAgd29ya3NwYWNlLnJldmVhbExlYWYobGVhZik7XG4gIH1cbn1cbiIsICJpbXBvcnQgeyBBcHAsIFBsdWdpblNldHRpbmdUYWIsIFNldHRpbmcgfSBmcm9tICdvYnNpZGlhbic7XG5pbXBvcnQgdHlwZSBPcGVuQ2xhd1BsdWdpbiBmcm9tICcuL21haW4nO1xuXG5leHBvcnQgY2xhc3MgT3BlbkNsYXdTZXR0aW5nVGFiIGV4dGVuZHMgUGx1Z2luU2V0dGluZ1RhYiB7XG4gIHBsdWdpbjogT3BlbkNsYXdQbHVnaW47XG5cbiAgY29uc3RydWN0b3IoYXBwOiBBcHAsIHBsdWdpbjogT3BlbkNsYXdQbHVnaW4pIHtcbiAgICBzdXBlcihhcHAsIHBsdWdpbik7XG4gICAgdGhpcy5wbHVnaW4gPSBwbHVnaW47XG4gIH1cblxuICBkaXNwbGF5KCk6IHZvaWQge1xuICAgIGNvbnN0IHsgY29udGFpbmVyRWwgfSA9IHRoaXM7XG4gICAgY29udGFpbmVyRWwuZW1wdHkoKTtcblxuICAgIGNvbnRhaW5lckVsLmNyZWF0ZUVsKCdoMicsIHsgdGV4dDogJ09wZW5DbGF3IENoYXQgXHUyMDEzIFNldHRpbmdzJyB9KTtcblxuICAgIG5ldyBTZXR0aW5nKGNvbnRhaW5lckVsKVxuICAgICAgLnNldE5hbWUoJ0dhdGV3YXkgVVJMJylcbiAgICAgIC5zZXREZXNjKCdXZWJTb2NrZXQgVVJMIG9mIHRoZSBPcGVuQ2xhdyBHYXRld2F5IChlLmcuIHdzOi8vaG9zdG5hbWU6MTg3ODkpLicpXG4gICAgICAuYWRkVGV4dCgodGV4dCkgPT5cbiAgICAgICAgdGV4dFxuICAgICAgICAgIC5zZXRQbGFjZWhvbGRlcignd3M6Ly9sb2NhbGhvc3Q6MTg3ODknKVxuICAgICAgICAgIC5zZXRWYWx1ZSh0aGlzLnBsdWdpbi5zZXR0aW5ncy5nYXRld2F5VXJsKVxuICAgICAgICAgIC5vbkNoYW5nZShhc3luYyAodmFsdWUpID0+IHtcbiAgICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLmdhdGV3YXlVcmwgPSB2YWx1ZS50cmltKCk7XG4gICAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgICB9KVxuICAgICAgKTtcblxuICAgIG5ldyBTZXR0aW5nKGNvbnRhaW5lckVsKVxuICAgICAgLnNldE5hbWUoJ0F1dGggdG9rZW4nKVxuICAgICAgLnNldERlc2MoJ011c3QgbWF0Y2ggdGhlIGF1dGhUb2tlbiBpbiB5b3VyIG9wZW5jbGF3Lmpzb24gY2hhbm5lbCBjb25maWcuIE5ldmVyIHNoYXJlZC4nKVxuICAgICAgLmFkZFRleHQoKHRleHQpID0+IHtcbiAgICAgICAgdGV4dFxuICAgICAgICAgIC5zZXRQbGFjZWhvbGRlcignRW50ZXIgdG9rZW5cdTIwMjYnKVxuICAgICAgICAgIC5zZXRWYWx1ZSh0aGlzLnBsdWdpbi5zZXR0aW5ncy5hdXRoVG9rZW4pXG4gICAgICAgICAgLm9uQ2hhbmdlKGFzeW5jICh2YWx1ZSkgPT4ge1xuICAgICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3MuYXV0aFRva2VuID0gdmFsdWU7XG4gICAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgICB9KTtcbiAgICAgICAgLy8gVHJlYXQgYXMgcGFzc3dvcmQgZmllbGQgXHUyMDEzIGRvIG5vdCByZXZlYWwgdG9rZW4gaW4gVUlcbiAgICAgICAgdGV4dC5pbnB1dEVsLnR5cGUgPSAncGFzc3dvcmQnO1xuICAgICAgICB0ZXh0LmlucHV0RWwuYXV0b2NvbXBsZXRlID0gJ29mZic7XG4gICAgICB9KTtcblxuICAgIG5ldyBTZXR0aW5nKGNvbnRhaW5lckVsKVxuICAgICAgLnNldE5hbWUoJ1Nlc3Npb24gS2V5JylcbiAgICAgIC5zZXREZXNjKCdPcGVuQ2xhdyBzZXNzaW9uIHRvIHN1YnNjcmliZSB0byAodXN1YWxseSBcIm1haW5cIikuJylcbiAgICAgIC5hZGRUZXh0KCh0ZXh0KSA9PlxuICAgICAgICB0ZXh0XG4gICAgICAgICAgLnNldFBsYWNlaG9sZGVyKCdtYWluJylcbiAgICAgICAgICAuc2V0VmFsdWUodGhpcy5wbHVnaW4uc2V0dGluZ3Muc2Vzc2lvbktleSlcbiAgICAgICAgICAub25DaGFuZ2UoYXN5bmMgKHZhbHVlKSA9PiB7XG4gICAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5zZXNzaW9uS2V5ID0gdmFsdWUudHJpbSgpIHx8ICdtYWluJztcbiAgICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICAgIH0pXG4gICAgICApO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZSgnQWNjb3VudCBJRCcpXG4gICAgICAuc2V0RGVzYygnT3BlbkNsYXcgYWNjb3VudCBJRCAodXN1YWxseSBcIm1haW5cIikuJylcbiAgICAgIC5hZGRUZXh0KCh0ZXh0KSA9PlxuICAgICAgICB0ZXh0XG4gICAgICAgICAgLnNldFBsYWNlaG9sZGVyKCdtYWluJylcbiAgICAgICAgICAuc2V0VmFsdWUodGhpcy5wbHVnaW4uc2V0dGluZ3MuYWNjb3VudElkKVxuICAgICAgICAgIC5vbkNoYW5nZShhc3luYyAodmFsdWUpID0+IHtcbiAgICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLmFjY291bnRJZCA9IHZhbHVlLnRyaW0oKSB8fCAnbWFpbic7XG4gICAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgICB9KVxuICAgICAgKTtcblxuICAgIG5ldyBTZXR0aW5nKGNvbnRhaW5lckVsKVxuICAgICAgLnNldE5hbWUoJ0luY2x1ZGUgYWN0aXZlIG5vdGUgYnkgZGVmYXVsdCcpXG4gICAgICAuc2V0RGVzYygnUHJlLWNoZWNrIFwiSW5jbHVkZSBhY3RpdmUgbm90ZVwiIGluIHRoZSBjaGF0IHBhbmVsIHdoZW4gaXQgb3BlbnMuJylcbiAgICAgIC5hZGRUb2dnbGUoKHRvZ2dsZSkgPT5cbiAgICAgICAgdG9nZ2xlLnNldFZhbHVlKHRoaXMucGx1Z2luLnNldHRpbmdzLmluY2x1ZGVBY3RpdmVOb3RlKS5vbkNoYW5nZShhc3luYyAodmFsdWUpID0+IHtcbiAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5pbmNsdWRlQWN0aXZlTm90ZSA9IHZhbHVlO1xuICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICB9KVxuICAgICAgKTtcblxuICAgIGNvbnRhaW5lckVsLmNyZWF0ZUVsKCdwJywge1xuICAgICAgdGV4dDogJ1JlY29ubmVjdDogY2xvc2UgYW5kIHJlb3BlbiB0aGUgc2lkZWJhciBhZnRlciBjaGFuZ2luZyB0aGUgZ2F0ZXdheSBVUkwgb3IgdG9rZW4uJyxcbiAgICAgIGNsczogJ3NldHRpbmctaXRlbS1kZXNjcmlwdGlvbicsXG4gICAgfSk7XG4gIH1cbn1cbiIsICIvKipcbiAqIFdlYlNvY2tldCBjbGllbnQgZm9yIE9wZW5DbGF3IEdhdGV3YXlcbiAqIFxuICogVXNlcyBHYXRld2F5IHByb3RvY29sOiBKU09OLVJQQyBzdHlsZSByZXF1ZXN0cyArIGV2ZW50IHB1c2hcbiAqIC0gQ29ubmVjdCBoYW5kc2hha2UgZmlyc3QgKHJlcXVpcmVkIGJ5IEdhdGV3YXkpXG4gKiAtIFRoZW4gc3Vic2NyaWJlIHRvIHNlc3Npb25cbiAqIC0gUmVxdWVzdDogeyB0eXBlOiBcInJlcVwiLCBtZXRob2QsIGlkLCBwYXJhbXMgfVxuICogLSBSZXNwb25zZTogeyB0eXBlOiBcInJlc1wiLCBpZCwgb2ssIHBheWxvYWQvZXJyb3IgfVxuICogLSBFdmVudDogeyB0eXBlOiBcImV2ZW50XCIsIGV2ZW50LCBwYXlsb2FkIH1cbiAqL1xuXG5pbXBvcnQgdHlwZSB7IEluYm91bmRXU1BheWxvYWQgfSBmcm9tICcuL3R5cGVzJztcblxuLyoqIE1pbGxpc2Vjb25kcyBiZWZvcmUgYSByZWNvbm5lY3QgYXR0ZW1wdCBhZnRlciBhbiB1bmV4cGVjdGVkIGNsb3NlICovXG5jb25zdCBSRUNPTk5FQ1RfREVMQVlfTVMgPSAzXzAwMDtcbi8qKiBJbnRlcnZhbCBmb3Igc2VuZGluZyBoZWFydGJlYXQgcGluZ3MgKGNoZWNrIGNvbm5lY3Rpb24gbGl2ZW5lc3MpICovXG5jb25zdCBIRUFSVEJFQVRfSU5URVJWQUxfTVMgPSAzMF8wMDA7XG5cbmV4cG9ydCB0eXBlIFdTQ2xpZW50U3RhdGUgPSAnZGlzY29ubmVjdGVkJyB8ICdjb25uZWN0aW5nJyB8ICdoYW5kc2hha2luZycgfCAnc3Vic2NyaWJpbmcnIHwgJ2Nvbm5lY3RlZCc7XG5cbmludGVyZmFjZSBQZW5kaW5nUmVxdWVzdCB7XG4gIHJlc29sdmU6IChwYXlsb2FkOiBhbnkpID0+IHZvaWQ7XG4gIHJlamVjdDogKGVycm9yOiBhbnkpID0+IHZvaWQ7XG59XG5cbmV4cG9ydCBjbGFzcyBPYnNpZGlhbldTQ2xpZW50IHtcbiAgcHJpdmF0ZSB3czogV2ViU29ja2V0IHwgbnVsbCA9IG51bGw7XG4gIHByaXZhdGUgcmVjb25uZWN0VGltZXI6IFJldHVyblR5cGU8dHlwZW9mIHNldFRpbWVvdXQ+IHwgbnVsbCA9IG51bGw7XG4gIHByaXZhdGUgaGVhcnRiZWF0VGltZXI6IFJldHVyblR5cGU8dHlwZW9mIHNldEludGVydmFsPiB8IG51bGwgPSBudWxsO1xuICBwcml2YXRlIGludGVudGlvbmFsQ2xvc2UgPSBmYWxzZTtcbiAgcHJpdmF0ZSBzdWJzY3JpcHRpb25JZDogc3RyaW5nIHwgbnVsbCA9IG51bGw7XG4gIHByaXZhdGUgc2Vzc2lvbktleTogc3RyaW5nO1xuICBwcml2YXRlIGFjY291bnRJZDogc3RyaW5nO1xuICBwcml2YXRlIHVybCA9ICcnO1xuICBwcml2YXRlIHRva2VuID0gJyc7XG4gIHByaXZhdGUgcmVxdWVzdElkID0gMDtcbiAgcHJpdmF0ZSBwZW5kaW5nUmVxdWVzdHMgPSBuZXcgTWFwPHN0cmluZywgUGVuZGluZ1JlcXVlc3Q+KCk7XG5cbiAgc3RhdGU6IFdTQ2xpZW50U3RhdGUgPSAnZGlzY29ubmVjdGVkJztcblxuICAvLyBcdTI1MDBcdTI1MDAgQ2FsbGJhY2tzIChzZXQgYnkgY29uc3VtZXJzKSBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcbiAgb25NZXNzYWdlOiAoKG1zZzogSW5ib3VuZFdTUGF5bG9hZCkgPT4gdm9pZCkgfCBudWxsID0gbnVsbDtcbiAgb25TdGF0ZUNoYW5nZTogKChzdGF0ZTogV1NDbGllbnRTdGF0ZSkgPT4gdm9pZCkgfCBudWxsID0gbnVsbDtcblxuICBjb25zdHJ1Y3RvcihzZXNzaW9uS2V5OiBzdHJpbmcsIGFjY291bnRJZCA9ICdtYWluJykge1xuICAgIHRoaXMuc2Vzc2lvbktleSA9IHNlc3Npb25LZXk7XG4gICAgdGhpcy5hY2NvdW50SWQgPSBhY2NvdW50SWQ7XG4gIH1cblxuICAvLyBcdTI1MDBcdTI1MDAgUHVibGljIEFQSSBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcblxuICBjb25uZWN0KHVybDogc3RyaW5nLCB0b2tlbjogc3RyaW5nKTogdm9pZCB7XG4gICAgdGhpcy51cmwgPSB1cmw7XG4gICAgdGhpcy50b2tlbiA9IHRva2VuO1xuICAgIHRoaXMuaW50ZW50aW9uYWxDbG9zZSA9IGZhbHNlO1xuICAgIHRoaXMuX2Nvbm5lY3QoKTtcbiAgfVxuXG4gIGRpc2Nvbm5lY3QoKTogdm9pZCB7XG4gICAgdGhpcy5pbnRlbnRpb25hbENsb3NlID0gdHJ1ZTtcbiAgICB0aGlzLl9zdG9wVGltZXJzKCk7XG4gICAgaWYgKHRoaXMud3MpIHtcbiAgICAgIHRoaXMud3MuY2xvc2UoKTtcbiAgICAgIHRoaXMud3MgPSBudWxsO1xuICAgIH1cbiAgICB0aGlzLl9zZXRTdGF0ZSgnZGlzY29ubmVjdGVkJyk7XG4gIH1cblxuICBhc3luYyBzZW5kTWVzc2FnZShtZXNzYWdlOiBzdHJpbmcpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBpZiAoIXRoaXMuc3Vic2NyaXB0aW9uSWQpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcignTm90IHN1YnNjcmliZWQgXHUyMDE0IGNhbGwgY29ubmVjdCgpIGZpcnN0Jyk7XG4gICAgfVxuXG4gICAgYXdhaXQgdGhpcy5fc2VuZFJlcXVlc3QoJ29ic2lkaWFuLnNlbmQnLCB7XG4gICAgICBzdWJzY3JpcHRpb25JZDogdGhpcy5zdWJzY3JpcHRpb25JZCxcbiAgICAgIG1lc3NhZ2UsXG4gICAgfSk7XG4gIH1cblxuICAvLyBcdTI1MDBcdTI1MDAgSW50ZXJuYWwgXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG5cbiAgcHJpdmF0ZSBfY29ubmVjdCgpOiB2b2lkIHtcbiAgICBpZiAodGhpcy53cykge1xuICAgICAgdGhpcy53cy5vbm9wZW4gPSBudWxsO1xuICAgICAgdGhpcy53cy5vbmNsb3NlID0gbnVsbDtcbiAgICAgIHRoaXMud3Mub25tZXNzYWdlID0gbnVsbDtcbiAgICAgIHRoaXMud3Mub25lcnJvciA9IG51bGw7XG4gICAgICB0aGlzLndzLmNsb3NlKCk7XG4gICAgICB0aGlzLndzID0gbnVsbDtcbiAgICB9XG5cbiAgICB0aGlzLl9zZXRTdGF0ZSgnY29ubmVjdGluZycpO1xuXG4gICAgY29uc3Qgd3MgPSBuZXcgV2ViU29ja2V0KHRoaXMudXJsKTtcbiAgICB0aGlzLndzID0gd3M7XG5cbiAgICB3cy5vbm9wZW4gPSBhc3luYyAoKSA9PiB7XG4gICAgICB0aGlzLl9zZXRTdGF0ZSgnaGFuZHNoYWtpbmcnKTtcbiAgICAgIHRyeSB7XG4gICAgICAgIC8vIFN0ZXAgMTogQ29ubmVjdCBoYW5kc2hha2UgKHJlcXVpcmVkIGJ5IEdhdGV3YXkpXG4gICAgICAgIGF3YWl0IHRoaXMuX3NlbmRSZXF1ZXN0KCdjb25uZWN0Jywge1xuICAgICAgICAgIG1pblByb3RvY29sOiAxLFxuICAgICAgICAgIG1heFByb3RvY29sOiAxLFxuICAgICAgICAgIGNsaWVudDoge1xuICAgICAgICAgICAgaWQ6ICd3ZWJjaGF0LXVpJyxcbiAgICAgICAgICAgIG1vZGU6ICd1aScsXG4gICAgICAgICAgICB2ZXJzaW9uOiAnMC4xLjAnLFxuICAgICAgICAgICAgcGxhdGZvcm06ICdlbGVjdHJvbicsXG4gICAgICAgICAgfSxcbiAgICAgICAgICBhdXRoOiB7XG4gICAgICAgICAgICB0b2tlbjogdGhpcy50b2tlbixcbiAgICAgICAgICB9LFxuICAgICAgICB9KTtcblxuICAgICAgICAvLyBTdGVwIDI6IFN1YnNjcmliZSB0byBzZXNzaW9uXG4gICAgICAgIHRoaXMuX3NldFN0YXRlKCdzdWJzY3JpYmluZycpO1xuICAgICAgICBjb25zdCByZXN1bHQgPSBhd2FpdCB0aGlzLl9zZW5kUmVxdWVzdCgnb2JzaWRpYW4uc3Vic2NyaWJlJywge1xuICAgICAgICAgIHRva2VuOiB0aGlzLnRva2VuLFxuICAgICAgICAgIHNlc3Npb25LZXk6IHRoaXMuc2Vzc2lvbktleSxcbiAgICAgICAgICBhY2NvdW50SWQ6IHRoaXMuYWNjb3VudElkLFxuICAgICAgICB9KTtcblxuICAgICAgICBpZiAocmVzdWx0Py5zdWJzY3JpcHRpb25JZCkge1xuICAgICAgICAgIHRoaXMuc3Vic2NyaXB0aW9uSWQgPSByZXN1bHQuc3Vic2NyaXB0aW9uSWQ7XG4gICAgICAgICAgdGhpcy5fc2V0U3RhdGUoJ2Nvbm5lY3RlZCcpO1xuICAgICAgICAgIHRoaXMuX3N0YXJ0SGVhcnRiZWF0KCk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgdGhyb3cgbmV3IEVycm9yKCdTdWJzY3JpYmUgZmFpbGVkOiBubyBzdWJzY3JpcHRpb25JZCByZXR1cm5lZCcpO1xuICAgICAgICB9XG4gICAgICB9IGNhdGNoIChlcnIpIHtcbiAgICAgICAgY29uc29sZS5lcnJvcignW29jbGF3LXdzXSBDb25uZWN0aW9uIHNldHVwIGZhaWxlZCcsIGVycik7XG4gICAgICAgIHdzLmNsb3NlKCk7XG4gICAgICB9XG4gICAgfTtcblxuICAgIHdzLm9ubWVzc2FnZSA9IChldmVudDogTWVzc2FnZUV2ZW50KSA9PiB7XG4gICAgICBsZXQgZnJhbWU6IGFueTtcbiAgICAgIHRyeSB7XG4gICAgICAgIGZyYW1lID0gSlNPTi5wYXJzZShldmVudC5kYXRhIGFzIHN0cmluZyk7XG4gICAgICB9IGNhdGNoIHtcbiAgICAgICAgY29uc29sZS5lcnJvcignW29jbGF3LXdzXSBGYWlsZWQgdG8gcGFyc2UgaW5jb21pbmcgbWVzc2FnZScpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG5cbiAgICAgIC8vIEhhbmRsZSByZXNwb25zZSB0byBwZW5kaW5nIHJlcXVlc3RcbiAgICAgIGlmIChmcmFtZS50eXBlID09PSAncmVzJykge1xuICAgICAgICBjb25zdCBwZW5kaW5nID0gdGhpcy5wZW5kaW5nUmVxdWVzdHMuZ2V0KGZyYW1lLmlkKTtcbiAgICAgICAgaWYgKHBlbmRpbmcpIHtcbiAgICAgICAgICB0aGlzLnBlbmRpbmdSZXF1ZXN0cy5kZWxldGUoZnJhbWUuaWQpO1xuICAgICAgICAgIGlmIChmcmFtZS5vaykge1xuICAgICAgICAgICAgcGVuZGluZy5yZXNvbHZlKGZyYW1lLnBheWxvYWQpO1xuICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBwZW5kaW5nLnJlamVjdChuZXcgRXJyb3IoZnJhbWUuZXJyb3I/Lm1lc3NhZ2UgfHwgJ1JlcXVlc3QgZmFpbGVkJykpO1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgICByZXR1cm47XG4gICAgICB9XG5cbiAgICAgIC8vIEhhbmRsZSBldmVudCBwdXNoIGZyb20gZ2F0ZXdheVxuICAgICAgaWYgKGZyYW1lLnR5cGUgPT09ICdldmVudCcpIHtcbiAgICAgICAgLy8gT2JzaWRpYW4gbWVzc2FnZSBwdXNoXG4gICAgICAgIGlmIChmcmFtZS5ldmVudCA9PT0gJ29ic2lkaWFuLm1lc3NhZ2UnKSB7XG4gICAgICAgICAgY29uc3QgbXNnOiBJbmJvdW5kV1NQYXlsb2FkID0ge1xuICAgICAgICAgICAgdHlwZTogJ21lc3NhZ2UnLFxuICAgICAgICAgICAgcGF5bG9hZDoge1xuICAgICAgICAgICAgICBjb250ZW50OiBmcmFtZS5wYXlsb2FkPy5jb250ZW50IHx8ICcnLFxuICAgICAgICAgICAgICByb2xlOiBmcmFtZS5wYXlsb2FkPy5yb2xlIHx8ICdhc3Npc3RhbnQnLFxuICAgICAgICAgICAgICB0aW1lc3RhbXA6IGZyYW1lLnBheWxvYWQ/LnRpbWVzdGFtcCB8fCBEYXRlLm5vdygpLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9O1xuICAgICAgICAgIHRoaXMub25NZXNzYWdlPy4obXNnKTtcbiAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICAvLyBJZ25vcmUgb3RoZXIgZXZlbnRzIChjb25uZWN0LmNoYWxsZW5nZSwgZXRjLilcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuXG4gICAgICAvLyBVbmtub3duIGZyYW1lIHR5cGUgXHUyMDE0IGlnbm9yZVxuICAgICAgY29uc29sZS5kZWJ1ZygnW29jbGF3LXdzXSBVbmhhbmRsZWQgZnJhbWUnLCBmcmFtZSk7XG4gICAgfTtcblxuICAgIHdzLm9uY2xvc2UgPSAoKSA9PiB7XG4gICAgICB0aGlzLl9zdG9wVGltZXJzKCk7XG4gICAgICB0aGlzLl9zZXRTdGF0ZSgnZGlzY29ubmVjdGVkJyk7XG4gICAgICB0aGlzLnN1YnNjcmlwdGlvbklkID0gbnVsbDtcbiAgICAgIC8vIFJlamVjdCBhbGwgcGVuZGluZyByZXF1ZXN0c1xuICAgICAgZm9yIChjb25zdCBwZW5kaW5nIG9mIHRoaXMucGVuZGluZ1JlcXVlc3RzLnZhbHVlcygpKSB7XG4gICAgICAgIHBlbmRpbmcucmVqZWN0KG5ldyBFcnJvcignQ29ubmVjdGlvbiBjbG9zZWQnKSk7XG4gICAgICB9XG4gICAgICB0aGlzLnBlbmRpbmdSZXF1ZXN0cy5jbGVhcigpO1xuXG4gICAgICBpZiAoIXRoaXMuaW50ZW50aW9uYWxDbG9zZSkge1xuICAgICAgICB0aGlzLl9zY2hlZHVsZVJlY29ubmVjdCgpO1xuICAgICAgfVxuICAgIH07XG5cbiAgICB3cy5vbmVycm9yID0gKGV2OiBFdmVudCkgPT4ge1xuICAgICAgY29uc29sZS5lcnJvcignW29jbGF3LXdzXSBXZWJTb2NrZXQgZXJyb3InLCBldik7XG4gICAgICAvLyBvbmNsb3NlIHdpbGwgZmlyZSBhZnRlciBvbmVycm9yIFx1MjAxNCByZWNvbm5lY3QgbG9naWMgaGFuZGxlZCB0aGVyZVxuICAgIH07XG4gIH1cblxuICBwcml2YXRlIF9zZW5kUmVxdWVzdChtZXRob2Q6IHN0cmluZywgcGFyYW1zOiBhbnkpOiBQcm9taXNlPGFueT4ge1xuICAgIHJldHVybiBuZXcgUHJvbWlzZSgocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICBpZiAoIXRoaXMud3MgfHwgdGhpcy53cy5yZWFkeVN0YXRlICE9PSBXZWJTb2NrZXQuT1BFTikge1xuICAgICAgICByZWplY3QobmV3IEVycm9yKCdXZWJTb2NrZXQgbm90IGNvbm5lY3RlZCcpKTtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuXG4gICAgICBjb25zdCBpZCA9IGByZXEtJHsrK3RoaXMucmVxdWVzdElkfWA7XG4gICAgICB0aGlzLnBlbmRpbmdSZXF1ZXN0cy5zZXQoaWQsIHsgcmVzb2x2ZSwgcmVqZWN0IH0pO1xuXG4gICAgICBjb25zdCBmcmFtZSA9IHtcbiAgICAgICAgdHlwZTogJ3JlcScsXG4gICAgICAgIG1ldGhvZCxcbiAgICAgICAgaWQsXG4gICAgICAgIHBhcmFtcyxcbiAgICAgIH07XG5cbiAgICAgIHRoaXMud3Muc2VuZChKU09OLnN0cmluZ2lmeShmcmFtZSkpO1xuXG4gICAgICAvLyBUaW1lb3V0IGFmdGVyIDMwc1xuICAgICAgc2V0VGltZW91dCgoKSA9PiB7XG4gICAgICAgIGlmICh0aGlzLnBlbmRpbmdSZXF1ZXN0cy5oYXMoaWQpKSB7XG4gICAgICAgICAgdGhpcy5wZW5kaW5nUmVxdWVzdHMuZGVsZXRlKGlkKTtcbiAgICAgICAgICByZWplY3QobmV3IEVycm9yKGBSZXF1ZXN0IHRpbWVvdXQ6ICR7bWV0aG9kfWApKTtcbiAgICAgICAgfVxuICAgICAgfSwgMzBfMDAwKTtcbiAgICB9KTtcbiAgfVxuXG4gIHByaXZhdGUgX3NjaGVkdWxlUmVjb25uZWN0KCk6IHZvaWQge1xuICAgIGlmICh0aGlzLnJlY29ubmVjdFRpbWVyICE9PSBudWxsKSByZXR1cm47XG4gICAgdGhpcy5yZWNvbm5lY3RUaW1lciA9IHNldFRpbWVvdXQoKCkgPT4ge1xuICAgICAgdGhpcy5yZWNvbm5lY3RUaW1lciA9IG51bGw7XG4gICAgICBpZiAoIXRoaXMuaW50ZW50aW9uYWxDbG9zZSkge1xuICAgICAgICBjb25zb2xlLmxvZyhgW29jbGF3LXdzXSBSZWNvbm5lY3RpbmcgdG8gJHt0aGlzLnVybH1cdTIwMjZgKTtcbiAgICAgICAgdGhpcy5fY29ubmVjdCgpO1xuICAgICAgfVxuICAgIH0sIFJFQ09OTkVDVF9ERUxBWV9NUyk7XG4gIH1cblxuICBwcml2YXRlIF9zdGFydEhlYXJ0YmVhdCgpOiB2b2lkIHtcbiAgICB0aGlzLl9zdG9wSGVhcnRiZWF0KCk7XG4gICAgdGhpcy5oZWFydGJlYXRUaW1lciA9IHNldEludGVydmFsKCgpID0+IHtcbiAgICAgIGlmICh0aGlzLndzPy5yZWFkeVN0YXRlICE9PSBXZWJTb2NrZXQuT1BFTikgcmV0dXJuO1xuICAgICAgLy8gU2ltcGxlIGhlYXJ0YmVhdDogY2hlY2sgY29ubmVjdGlvbiBsaXZlbmVzc1xuICAgICAgLy8gR2F0ZXdheSB3aWxsIGNsb3NlIHN0YWxlIGNvbm5lY3Rpb25zIGF1dG9tYXRpY2FsbHlcbiAgICAgIGlmICh0aGlzLndzLmJ1ZmZlcmVkQW1vdW50ID4gMCkge1xuICAgICAgICBjb25zb2xlLndhcm4oJ1tvY2xhdy13c10gU2VuZCBidWZmZXIgbm90IGVtcHR5IFx1MjAxNCBjb25uZWN0aW9uIG1heSBiZSBzdGFsbGVkJyk7XG4gICAgICB9XG4gICAgfSwgSEVBUlRCRUFUX0lOVEVSVkFMX01TKTtcbiAgfVxuXG4gIHByaXZhdGUgX3N0b3BIZWFydGJlYXQoKTogdm9pZCB7XG4gICAgaWYgKHRoaXMuaGVhcnRiZWF0VGltZXIpIHtcbiAgICAgIGNsZWFySW50ZXJ2YWwodGhpcy5oZWFydGJlYXRUaW1lcik7XG4gICAgICB0aGlzLmhlYXJ0YmVhdFRpbWVyID0gbnVsbDtcbiAgICB9XG4gIH1cblxuICBwcml2YXRlIF9zdG9wVGltZXJzKCk6IHZvaWQge1xuICAgIHRoaXMuX3N0b3BIZWFydGJlYXQoKTtcbiAgICBpZiAodGhpcy5yZWNvbm5lY3RUaW1lcikge1xuICAgICAgY2xlYXJUaW1lb3V0KHRoaXMucmVjb25uZWN0VGltZXIpO1xuICAgICAgdGhpcy5yZWNvbm5lY3RUaW1lciA9IG51bGw7XG4gICAgfVxuICB9XG5cbiAgcHJpdmF0ZSBfc2V0U3RhdGUoc3RhdGU6IFdTQ2xpZW50U3RhdGUpOiB2b2lkIHtcbiAgICBpZiAodGhpcy5zdGF0ZSA9PT0gc3RhdGUpIHJldHVybjtcbiAgICB0aGlzLnN0YXRlID0gc3RhdGU7XG4gICAgdGhpcy5vblN0YXRlQ2hhbmdlPy4oc3RhdGUpO1xuICB9XG59XG4iLCAiaW1wb3J0IHR5cGUgeyBDaGF0TWVzc2FnZSB9IGZyb20gJy4vdHlwZXMnO1xuXG4vKiogTWFuYWdlcyB0aGUgaW4tbWVtb3J5IGxpc3Qgb2YgY2hhdCBtZXNzYWdlcyBhbmQgbm90aWZpZXMgVUkgb24gY2hhbmdlcyAqL1xuZXhwb3J0IGNsYXNzIENoYXRNYW5hZ2VyIHtcbiAgcHJpdmF0ZSBtZXNzYWdlczogQ2hhdE1lc3NhZ2VbXSA9IFtdO1xuXG4gIC8qKiBGaXJlZCBmb3IgYSBmdWxsIHJlLXJlbmRlciAoY2xlYXIvcmVsb2FkKSAqL1xuICBvblVwZGF0ZTogKChtZXNzYWdlczogcmVhZG9ubHkgQ2hhdE1lc3NhZ2VbXSkgPT4gdm9pZCkgfCBudWxsID0gbnVsbDtcbiAgLyoqIEZpcmVkIHdoZW4gYSBzaW5nbGUgbWVzc2FnZSBpcyBhcHBlbmRlZCBcdTIwMTQgdXNlIGZvciBPKDEpIGFwcGVuZC1vbmx5IFVJICovXG4gIG9uTWVzc2FnZUFkZGVkOiAoKG1zZzogQ2hhdE1lc3NhZ2UpID0+IHZvaWQpIHwgbnVsbCA9IG51bGw7XG5cbiAgYWRkTWVzc2FnZShtc2c6IENoYXRNZXNzYWdlKTogdm9pZCB7XG4gICAgdGhpcy5tZXNzYWdlcy5wdXNoKG1zZyk7XG4gICAgdGhpcy5vbk1lc3NhZ2VBZGRlZD8uKG1zZyk7XG4gIH1cblxuICBnZXRNZXNzYWdlcygpOiByZWFkb25seSBDaGF0TWVzc2FnZVtdIHtcbiAgICByZXR1cm4gdGhpcy5tZXNzYWdlcztcbiAgfVxuXG4gIGNsZWFyKCk6IHZvaWQge1xuICAgIHRoaXMubWVzc2FnZXMgPSBbXTtcbiAgICB0aGlzLm9uVXBkYXRlPy4oW10pO1xuICB9XG5cbiAgLyoqIENyZWF0ZSBhIHVzZXIgbWVzc2FnZSBvYmplY3QgKHdpdGhvdXQgYWRkaW5nIGl0KSAqL1xuICBzdGF0aWMgY3JlYXRlVXNlck1lc3NhZ2UoY29udGVudDogc3RyaW5nKTogQ2hhdE1lc3NhZ2Uge1xuICAgIHJldHVybiB7XG4gICAgICBpZDogYG1zZy0ke0RhdGUubm93KCl9LSR7TWF0aC5yYW5kb20oKS50b1N0cmluZygzNikuc2xpY2UoMiwgNyl9YCxcbiAgICAgIHJvbGU6ICd1c2VyJyxcbiAgICAgIGNvbnRlbnQsXG4gICAgICB0aW1lc3RhbXA6IERhdGUubm93KCksXG4gICAgfTtcbiAgfVxuXG4gIC8qKiBDcmVhdGUgYW4gYXNzaXN0YW50IG1lc3NhZ2Ugb2JqZWN0ICh3aXRob3V0IGFkZGluZyBpdCkgKi9cbiAgc3RhdGljIGNyZWF0ZUFzc2lzdGFudE1lc3NhZ2UoY29udGVudDogc3RyaW5nKTogQ2hhdE1lc3NhZ2Uge1xuICAgIHJldHVybiB7XG4gICAgICBpZDogYG1zZy0ke0RhdGUubm93KCl9LSR7TWF0aC5yYW5kb20oKS50b1N0cmluZygzNikuc2xpY2UoMiwgNyl9YCxcbiAgICAgIHJvbGU6ICdhc3Npc3RhbnQnLFxuICAgICAgY29udGVudCxcbiAgICAgIHRpbWVzdGFtcDogRGF0ZS5ub3coKSxcbiAgICB9O1xuICB9XG5cbiAgLyoqIENyZWF0ZSBhIHN5c3RlbSAvIHN0YXR1cyBtZXNzYWdlIChlcnJvcnMsIHJlY29ubmVjdCBub3RpY2VzLCBldGMuKSAqL1xuICBzdGF0aWMgY3JlYXRlU3lzdGVtTWVzc2FnZShjb250ZW50OiBzdHJpbmcpOiBDaGF0TWVzc2FnZSB7XG4gICAgcmV0dXJuIHtcbiAgICAgIGlkOiBgc3lzLSR7RGF0ZS5ub3coKX1gLFxuICAgICAgcm9sZTogJ3N5c3RlbScsXG4gICAgICBjb250ZW50LFxuICAgICAgdGltZXN0YW1wOiBEYXRlLm5vdygpLFxuICAgIH07XG4gIH1cbn1cbiIsICJpbXBvcnQgeyBJdGVtVmlldywgV29ya3NwYWNlTGVhZiB9IGZyb20gJ29ic2lkaWFuJztcbmltcG9ydCB0eXBlIE9wZW5DbGF3UGx1Z2luIGZyb20gJy4vbWFpbic7XG5pbXBvcnQgeyBDaGF0TWFuYWdlciB9IGZyb20gJy4vY2hhdCc7XG5pbXBvcnQgdHlwZSB7IENoYXRNZXNzYWdlIH0gZnJvbSAnLi90eXBlcyc7XG5pbXBvcnQgeyBnZXRBY3RpdmVOb3RlQ29udGV4dCB9IGZyb20gJy4vY29udGV4dCc7XG5cbmV4cG9ydCBjb25zdCBWSUVXX1RZUEVfT1BFTkNMQVdfQ0hBVCA9ICdvcGVuY2xhdy1jaGF0JztcblxuZXhwb3J0IGNsYXNzIE9wZW5DbGF3Q2hhdFZpZXcgZXh0ZW5kcyBJdGVtVmlldyB7XG4gIHByaXZhdGUgcGx1Z2luOiBPcGVuQ2xhd1BsdWdpbjtcbiAgcHJpdmF0ZSBjaGF0TWFuYWdlcjogQ2hhdE1hbmFnZXI7XG5cbiAgLy8gRE9NIHJlZnNcbiAgcHJpdmF0ZSBtZXNzYWdlc0VsITogSFRNTEVsZW1lbnQ7XG4gIHByaXZhdGUgaW5wdXRFbCE6IEhUTUxUZXh0QXJlYUVsZW1lbnQ7XG4gIHByaXZhdGUgc2VuZEJ0biE6IEhUTUxCdXR0b25FbGVtZW50O1xuICBwcml2YXRlIGluY2x1ZGVOb3RlQ2hlY2tib3ghOiBIVE1MSW5wdXRFbGVtZW50O1xuICBwcml2YXRlIHN0YXR1c0RvdCE6IEhUTUxFbGVtZW50O1xuXG4gIGNvbnN0cnVjdG9yKGxlYWY6IFdvcmtzcGFjZUxlYWYsIHBsdWdpbjogT3BlbkNsYXdQbHVnaW4pIHtcbiAgICBzdXBlcihsZWFmKTtcbiAgICB0aGlzLnBsdWdpbiA9IHBsdWdpbjtcbiAgICB0aGlzLmNoYXRNYW5hZ2VyID0gcGx1Z2luLmNoYXRNYW5hZ2VyO1xuICB9XG5cbiAgZ2V0Vmlld1R5cGUoKTogc3RyaW5nIHtcbiAgICByZXR1cm4gVklFV19UWVBFX09QRU5DTEFXX0NIQVQ7XG4gIH1cblxuICBnZXREaXNwbGF5VGV4dCgpOiBzdHJpbmcge1xuICAgIHJldHVybiAnT3BlbkNsYXcgQ2hhdCc7XG4gIH1cblxuICBnZXRJY29uKCk6IHN0cmluZyB7XG4gICAgcmV0dXJuICdtZXNzYWdlLXNxdWFyZSc7XG4gIH1cblxuICBhc3luYyBvbk9wZW4oKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgdGhpcy5fYnVpbGRVSSgpO1xuXG4gICAgLy8gRnVsbCByZS1yZW5kZXIgb24gY2xlYXIgLyByZWxvYWRcbiAgICB0aGlzLmNoYXRNYW5hZ2VyLm9uVXBkYXRlID0gKG1zZ3MpID0+IHRoaXMuX3JlbmRlck1lc3NhZ2VzKG1zZ3MpO1xuICAgIC8vIE8oMSkgYXBwZW5kIGZvciBuZXcgbWVzc2FnZXNcbiAgICB0aGlzLmNoYXRNYW5hZ2VyLm9uTWVzc2FnZUFkZGVkID0gKG1zZykgPT4gdGhpcy5fYXBwZW5kTWVzc2FnZShtc2cpO1xuXG4gICAgLy8gU3Vic2NyaWJlIHRvIFdTIHN0YXRlIGNoYW5nZXNcbiAgICB0aGlzLnBsdWdpbi53c0NsaWVudC5vblN0YXRlQ2hhbmdlID0gKHN0YXRlKSA9PiB7XG4gICAgICBjb25zdCBjb25uZWN0ZWQgPSBzdGF0ZSA9PT0gJ2Nvbm5lY3RlZCc7XG4gICAgICB0aGlzLnN0YXR1c0RvdC50b2dnbGVDbGFzcygnY29ubmVjdGVkJywgY29ubmVjdGVkKTtcbiAgICAgIHRoaXMuc3RhdHVzRG90LnRpdGxlID0gYEdhdGV3YXk6ICR7c3RhdGV9YDtcbiAgICAgIHRoaXMuc2VuZEJ0bi5kaXNhYmxlZCA9ICFjb25uZWN0ZWQ7XG4gICAgfTtcblxuICAgIC8vIFJlZmxlY3QgY3VycmVudCBzdGF0ZVxuICAgIGNvbnN0IGNvbm5lY3RlZCA9IHRoaXMucGx1Z2luLndzQ2xpZW50LnN0YXRlID09PSAnY29ubmVjdGVkJztcbiAgICB0aGlzLnN0YXR1c0RvdC50b2dnbGVDbGFzcygnY29ubmVjdGVkJywgY29ubmVjdGVkKTtcbiAgICB0aGlzLnNlbmRCdG4uZGlzYWJsZWQgPSAhY29ubmVjdGVkO1xuXG4gICAgdGhpcy5fcmVuZGVyTWVzc2FnZXModGhpcy5jaGF0TWFuYWdlci5nZXRNZXNzYWdlcygpKTtcbiAgfVxuXG4gIGFzeW5jIG9uQ2xvc2UoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgdGhpcy5jaGF0TWFuYWdlci5vblVwZGF0ZSA9IG51bGw7XG4gICAgdGhpcy5jaGF0TWFuYWdlci5vbk1lc3NhZ2VBZGRlZCA9IG51bGw7XG4gICAgdGhpcy5wbHVnaW4ud3NDbGllbnQub25TdGF0ZUNoYW5nZSA9IG51bGw7XG4gIH1cblxuICAvLyBcdTI1MDBcdTI1MDAgVUkgY29uc3RydWN0aW9uIFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFxuXG4gIHByaXZhdGUgX2J1aWxkVUkoKTogdm9pZCB7XG4gICAgY29uc3Qgcm9vdCA9IHRoaXMuY29udGVudEVsO1xuICAgIHJvb3QuZW1wdHkoKTtcbiAgICByb290LmFkZENsYXNzKCdvY2xhdy1jaGF0LXZpZXcnKTtcblxuICAgIC8vIFx1MjUwMFx1MjUwMCBIZWFkZXIgXHUyNTAwXHUyNTAwXG4gICAgY29uc3QgaGVhZGVyID0gcm9vdC5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1oZWFkZXInIH0pO1xuICAgIGhlYWRlci5jcmVhdGVTcGFuKHsgY2xzOiAnb2NsYXctaGVhZGVyLXRpdGxlJywgdGV4dDogJ09wZW5DbGF3IENoYXQnIH0pO1xuICAgIHRoaXMuc3RhdHVzRG90ID0gaGVhZGVyLmNyZWF0ZURpdih7IGNsczogJ29jbGF3LXN0YXR1cy1kb3QnIH0pO1xuICAgIHRoaXMuc3RhdHVzRG90LnRpdGxlID0gJ0dhdGV3YXk6IGRpc2Nvbm5lY3RlZCc7XG5cbiAgICAvLyBcdTI1MDBcdTI1MDAgTWVzc2FnZXMgYXJlYSBcdTI1MDBcdTI1MDBcbiAgICB0aGlzLm1lc3NhZ2VzRWwgPSByb290LmNyZWF0ZURpdih7IGNsczogJ29jbGF3LW1lc3NhZ2VzJyB9KTtcblxuICAgIC8vIFx1MjUwMFx1MjUwMCBDb250ZXh0IHJvdyBcdTI1MDBcdTI1MDBcbiAgICBjb25zdCBjdHhSb3cgPSByb290LmNyZWF0ZURpdih7IGNsczogJ29jbGF3LWNvbnRleHQtcm93JyB9KTtcbiAgICB0aGlzLmluY2x1ZGVOb3RlQ2hlY2tib3ggPSBjdHhSb3cuY3JlYXRlRWwoJ2lucHV0JywgeyB0eXBlOiAnY2hlY2tib3gnIH0pO1xuICAgIHRoaXMuaW5jbHVkZU5vdGVDaGVja2JveC5pZCA9ICdvY2xhdy1pbmNsdWRlLW5vdGUnO1xuICAgIHRoaXMuaW5jbHVkZU5vdGVDaGVja2JveC5jaGVja2VkID0gdGhpcy5wbHVnaW4uc2V0dGluZ3MuaW5jbHVkZUFjdGl2ZU5vdGU7XG4gICAgY29uc3QgY3R4TGFiZWwgPSBjdHhSb3cuY3JlYXRlRWwoJ2xhYmVsJywgeyB0ZXh0OiAnSW5jbHVkZSBhY3RpdmUgbm90ZScgfSk7XG4gICAgY3R4TGFiZWwuaHRtbEZvciA9ICdvY2xhdy1pbmNsdWRlLW5vdGUnO1xuXG4gICAgLy8gXHUyNTAwXHUyNTAwIElucHV0IHJvdyBcdTI1MDBcdTI1MDBcbiAgICBjb25zdCBpbnB1dFJvdyA9IHJvb3QuY3JlYXRlRGl2KHsgY2xzOiAnb2NsYXctaW5wdXQtcm93JyB9KTtcbiAgICB0aGlzLmlucHV0RWwgPSBpbnB1dFJvdy5jcmVhdGVFbCgndGV4dGFyZWEnLCB7XG4gICAgICBjbHM6ICdvY2xhdy1pbnB1dCcsXG4gICAgICBwbGFjZWhvbGRlcjogJ0FzayBhbnl0aGluZ1x1MjAyNicsXG4gICAgfSk7XG4gICAgdGhpcy5pbnB1dEVsLnJvd3MgPSAxO1xuXG4gICAgdGhpcy5zZW5kQnRuID0gaW5wdXRSb3cuY3JlYXRlRWwoJ2J1dHRvbicsIHsgY2xzOiAnb2NsYXctc2VuZC1idG4nLCB0ZXh0OiAnU2VuZCcgfSk7XG5cbiAgICAvLyBcdTI1MDBcdTI1MDAgRXZlbnQgbGlzdGVuZXJzIFx1MjUwMFx1MjUwMFxuICAgIHRoaXMuc2VuZEJ0bi5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpID0+IHRoaXMuX2hhbmRsZVNlbmQoKSk7XG4gICAgdGhpcy5pbnB1dEVsLmFkZEV2ZW50TGlzdGVuZXIoJ2tleWRvd24nLCAoZSkgPT4ge1xuICAgICAgaWYgKGUua2V5ID09PSAnRW50ZXInICYmICFlLnNoaWZ0S2V5KSB7XG4gICAgICAgIGUucHJldmVudERlZmF1bHQoKTtcbiAgICAgICAgdGhpcy5faGFuZGxlU2VuZCgpO1xuICAgICAgfVxuICAgIH0pO1xuICAgIC8vIEF1dG8tcmVzaXplIHRleHRhcmVhXG4gICAgdGhpcy5pbnB1dEVsLmFkZEV2ZW50TGlzdGVuZXIoJ2lucHV0JywgKCkgPT4ge1xuICAgICAgdGhpcy5pbnB1dEVsLnN0eWxlLmhlaWdodCA9ICdhdXRvJztcbiAgICAgIHRoaXMuaW5wdXRFbC5zdHlsZS5oZWlnaHQgPSBgJHt0aGlzLmlucHV0RWwuc2Nyb2xsSGVpZ2h0fXB4YDtcbiAgICB9KTtcbiAgfVxuXG4gIC8vIFx1MjUwMFx1MjUwMCBNZXNzYWdlIHJlbmRlcmluZyBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcblxuICBwcml2YXRlIF9yZW5kZXJNZXNzYWdlcyhtZXNzYWdlczogcmVhZG9ubHkgQ2hhdE1lc3NhZ2VbXSk6IHZvaWQge1xuICAgIHRoaXMubWVzc2FnZXNFbC5lbXB0eSgpO1xuXG4gICAgaWYgKG1lc3NhZ2VzLmxlbmd0aCA9PT0gMCkge1xuICAgICAgdGhpcy5tZXNzYWdlc0VsLmNyZWF0ZUVsKCdwJywge1xuICAgICAgICB0ZXh0OiAnU2VuZCBhIG1lc3NhZ2UgdG8gc3RhcnQgY2hhdHRpbmcuJyxcbiAgICAgICAgY2xzOiAnb2NsYXctbWVzc2FnZSBzeXN0ZW0gb2NsYXctcGxhY2Vob2xkZXInLFxuICAgICAgfSk7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgZm9yIChjb25zdCBtc2cgb2YgbWVzc2FnZXMpIHtcbiAgICAgIGNvbnN0IGVsID0gdGhpcy5tZXNzYWdlc0VsLmNyZWF0ZURpdih7IGNsczogYG9jbGF3LW1lc3NhZ2UgJHttc2cucm9sZX1gIH0pO1xuICAgICAgZWwuY3JlYXRlU3Bhbih7IHRleHQ6IG1zZy5jb250ZW50IH0pO1xuICAgIH1cblxuICAgIC8vIFNjcm9sbCB0byBib3R0b21cbiAgICB0aGlzLm1lc3NhZ2VzRWwuc2Nyb2xsVG9wID0gdGhpcy5tZXNzYWdlc0VsLnNjcm9sbEhlaWdodDtcbiAgfVxuXG4gIC8qKiBBcHBlbmRzIGEgc2luZ2xlIG1lc3NhZ2Ugd2l0aG91dCByZWJ1aWxkaW5nIHRoZSBET00gKE8oMSkpICovXG4gIHByaXZhdGUgX2FwcGVuZE1lc3NhZ2UobXNnOiBDaGF0TWVzc2FnZSk6IHZvaWQge1xuICAgIC8vIFJlbW92ZSBlbXB0eS1zdGF0ZSBwbGFjZWhvbGRlciBpZiBwcmVzZW50XG4gICAgdGhpcy5tZXNzYWdlc0VsLnF1ZXJ5U2VsZWN0b3IoJy5vY2xhdy1wbGFjZWhvbGRlcicpPy5yZW1vdmUoKTtcblxuICAgIGNvbnN0IGVsID0gdGhpcy5tZXNzYWdlc0VsLmNyZWF0ZURpdih7IGNsczogYG9jbGF3LW1lc3NhZ2UgJHttc2cucm9sZX1gIH0pO1xuICAgIGVsLmNyZWF0ZVNwYW4oeyB0ZXh0OiBtc2cuY29udGVudCB9KTtcblxuICAgIC8vIFNjcm9sbCB0byBib3R0b21cbiAgICB0aGlzLm1lc3NhZ2VzRWwuc2Nyb2xsVG9wID0gdGhpcy5tZXNzYWdlc0VsLnNjcm9sbEhlaWdodDtcbiAgfVxuXG4gIC8vIFx1MjUwMFx1MjUwMCBTZW5kIGhhbmRsZXIgXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG5cbiAgcHJpdmF0ZSBhc3luYyBfaGFuZGxlU2VuZCgpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBjb25zdCB0ZXh0ID0gdGhpcy5pbnB1dEVsLnZhbHVlLnRyaW0oKTtcbiAgICBpZiAoIXRleHQpIHJldHVybjtcblxuICAgIC8vIEJ1aWxkIG1lc3NhZ2Ugd2l0aCBjb250ZXh0IGlmIGVuYWJsZWRcbiAgICBsZXQgbWVzc2FnZSA9IHRleHQ7XG4gICAgaWYgKHRoaXMuaW5jbHVkZU5vdGVDaGVja2JveC5jaGVja2VkKSB7XG4gICAgICBjb25zdCBub3RlID0gYXdhaXQgZ2V0QWN0aXZlTm90ZUNvbnRleHQodGhpcy5hcHApO1xuICAgICAgaWYgKG5vdGUpIHtcbiAgICAgICAgbWVzc2FnZSA9IGBDb250ZXh0OiBbWyR7bm90ZS50aXRsZX1dXVxcblxcbiR7dGV4dH1gO1xuICAgICAgfVxuICAgIH1cblxuICAgIC8vIEFkZCB1c2VyIG1lc3NhZ2UgdG8gY2hhdCBVSVxuICAgIGNvbnN0IHVzZXJNc2cgPSBDaGF0TWFuYWdlci5jcmVhdGVVc2VyTWVzc2FnZSh0ZXh0KTtcbiAgICB0aGlzLmNoYXRNYW5hZ2VyLmFkZE1lc3NhZ2UodXNlck1zZyk7XG5cbiAgICAvLyBDbGVhciBpbnB1dFxuICAgIHRoaXMuaW5wdXRFbC52YWx1ZSA9ICcnO1xuICAgIHRoaXMuaW5wdXRFbC5zdHlsZS5oZWlnaHQgPSAnYXV0byc7XG5cbiAgICAvLyBTZW5kIG92ZXIgV1MgKGFzeW5jKVxuICAgIHRyeSB7XG4gICAgICBhd2FpdCB0aGlzLnBsdWdpbi53c0NsaWVudC5zZW5kTWVzc2FnZShtZXNzYWdlKTtcbiAgICB9IGNhdGNoIChlcnIpIHtcbiAgICAgIGNvbnNvbGUuZXJyb3IoJ1tvY2xhd10gU2VuZCBmYWlsZWQnLCBlcnIpO1xuICAgICAgdGhpcy5jaGF0TWFuYWdlci5hZGRNZXNzYWdlKFxuICAgICAgICBDaGF0TWFuYWdlci5jcmVhdGVTeXN0ZW1NZXNzYWdlKGBcdTI2QTAgU2VuZCBmYWlsZWQ6ICR7ZXJyfWApXG4gICAgICApO1xuICAgIH1cbiAgfVxufVxuIiwgImltcG9ydCB0eXBlIHsgQXBwIH0gZnJvbSAnb2JzaWRpYW4nO1xuXG5leHBvcnQgaW50ZXJmYWNlIE5vdGVDb250ZXh0IHtcbiAgdGl0bGU6IHN0cmluZztcbiAgcGF0aDogc3RyaW5nO1xuICBjb250ZW50OiBzdHJpbmc7XG59XG5cbi8qKlxuICogUmV0dXJucyB0aGUgYWN0aXZlIG5vdGUncyB0aXRsZSBhbmQgY29udGVudCwgb3IgbnVsbCBpZiBubyBub3RlIGlzIG9wZW4uXG4gKiBBc3luYyBiZWNhdXNlIHZhdWx0LnJlYWQoKSBpcyBhc3luYy5cbiAqL1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGdldEFjdGl2ZU5vdGVDb250ZXh0KGFwcDogQXBwKTogUHJvbWlzZTxOb3RlQ29udGV4dCB8IG51bGw+IHtcbiAgY29uc3QgZmlsZSA9IGFwcC53b3Jrc3BhY2UuZ2V0QWN0aXZlRmlsZSgpO1xuICBpZiAoIWZpbGUpIHJldHVybiBudWxsO1xuXG4gIHRyeSB7XG4gICAgY29uc3QgY29udGVudCA9IGF3YWl0IGFwcC52YXVsdC5yZWFkKGZpbGUpO1xuICAgIHJldHVybiB7XG4gICAgICB0aXRsZTogZmlsZS5iYXNlbmFtZSxcbiAgICAgIHBhdGg6IGZpbGUucGF0aCxcbiAgICAgIGNvbnRlbnQsXG4gICAgfTtcbiAgfSBjYXRjaCAoZXJyKSB7XG4gICAgY29uc29sZS5lcnJvcignW29jbGF3LWNvbnRleHRdIEZhaWxlZCB0byByZWFkIGFjdGl2ZSBub3RlJywgZXJyKTtcbiAgICByZXR1cm4gbnVsbDtcbiAgfVxufVxuIiwgIi8qKiBQZXJzaXN0ZWQgcGx1Z2luIGNvbmZpZ3VyYXRpb24gKi9cbmV4cG9ydCBpbnRlcmZhY2UgT3BlbkNsYXdTZXR0aW5ncyB7XG4gIC8qKiBXZWJTb2NrZXQgVVJMIG9mIHRoZSBPcGVuQ2xhdyBHYXRld2F5IChlLmcuIHdzOi8vMTAwLjkwLjkuNjg6MTg3ODkpICovXG4gIGdhdGV3YXlVcmw6IHN0cmluZztcbiAgLyoqIEF1dGggdG9rZW4gXHUyMDE0IG11c3QgbWF0Y2ggdGhlIGNoYW5uZWwgcGx1Z2luJ3MgYXV0aFRva2VuICovXG4gIGF1dGhUb2tlbjogc3RyaW5nO1xuICAvKiogT3BlbkNsYXcgc2Vzc2lvbiBrZXkgdG8gc3Vic2NyaWJlIHRvIChlLmcuIFwibWFpblwiKSAqL1xuICBzZXNzaW9uS2V5OiBzdHJpbmc7XG4gIC8qKiBPcGVuQ2xhdyBhY2NvdW50IElEICh1c3VhbGx5IFwibWFpblwiKSAqL1xuICBhY2NvdW50SWQ6IHN0cmluZztcbiAgLyoqIFdoZXRoZXIgdG8gaW5jbHVkZSB0aGUgYWN0aXZlIG5vdGUgY29udGVudCB3aXRoIGVhY2ggbWVzc2FnZSAqL1xuICBpbmNsdWRlQWN0aXZlTm90ZTogYm9vbGVhbjtcbn1cblxuZXhwb3J0IGNvbnN0IERFRkFVTFRfU0VUVElOR1M6IE9wZW5DbGF3U2V0dGluZ3MgPSB7XG4gIGdhdGV3YXlVcmw6ICd3czovL2xvY2FsaG9zdDoxODc4OScsXG4gIGF1dGhUb2tlbjogJycsXG4gIHNlc3Npb25LZXk6ICdtYWluJyxcbiAgYWNjb3VudElkOiAnbWFpbicsXG4gIGluY2x1ZGVBY3RpdmVOb3RlOiBmYWxzZSxcbn07XG5cbi8qKiBBIHNpbmdsZSBjaGF0IG1lc3NhZ2UgKi9cbmV4cG9ydCBpbnRlcmZhY2UgQ2hhdE1lc3NhZ2Uge1xuICBpZDogc3RyaW5nO1xuICByb2xlOiAndXNlcicgfCAnYXNzaXN0YW50JyB8ICdzeXN0ZW0nO1xuICBjb250ZW50OiBzdHJpbmc7XG4gIHRpbWVzdGFtcDogbnVtYmVyO1xufVxuXG4vKiogUGF5bG9hZCBmb3IgbWVzc2FnZXMgU0VOVCB0byB0aGUgc2VydmVyIChvdXRib3VuZCkgKi9cbmV4cG9ydCBpbnRlcmZhY2UgV1NQYXlsb2FkIHtcbiAgdHlwZTogJ2F1dGgnIHwgJ21lc3NhZ2UnIHwgJ3BpbmcnIHwgJ3BvbmcnIHwgJ2Vycm9yJztcbiAgcGF5bG9hZD86IFJlY29yZDxzdHJpbmcsIHVua25vd24+O1xufVxuXG4vKiogTWVzc2FnZXMgUkVDRUlWRUQgZnJvbSB0aGUgc2VydmVyIChpbmJvdW5kKSBcdTIwMTQgZGlzY3JpbWluYXRlZCB1bmlvbiAqL1xuZXhwb3J0IHR5cGUgSW5ib3VuZFdTUGF5bG9hZCA9XG4gIHwgeyB0eXBlOiAnbWVzc2FnZSc7IHBheWxvYWQ6IHsgY29udGVudDogc3RyaW5nOyByb2xlOiBzdHJpbmc7IHRpbWVzdGFtcDogbnVtYmVyIH0gfVxuICB8IHsgdHlwZTogJ2Vycm9yJzsgcGF5bG9hZDogeyBtZXNzYWdlOiBzdHJpbmcgfSB9O1xuXG4vKiogQXZhaWxhYmxlIGFnZW50cyAvIG1vZGVscyAqL1xuZXhwb3J0IGludGVyZmFjZSBBZ2VudE9wdGlvbiB7XG4gIGlkOiBzdHJpbmc7XG4gIGxhYmVsOiBzdHJpbmc7XG59XG4iXSwKICAibWFwcGluZ3MiOiAiOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBLElBQUFBLG1CQUE4Qzs7O0FDQTlDLHNCQUErQztBQUd4QyxJQUFNLHFCQUFOLGNBQWlDLGlDQUFpQjtBQUFBLEVBR3ZELFlBQVksS0FBVSxRQUF3QjtBQUM1QyxVQUFNLEtBQUssTUFBTTtBQUNqQixTQUFLLFNBQVM7QUFBQSxFQUNoQjtBQUFBLEVBRUEsVUFBZ0I7QUFDZCxVQUFNLEVBQUUsWUFBWSxJQUFJO0FBQ3hCLGdCQUFZLE1BQU07QUFFbEIsZ0JBQVksU0FBUyxNQUFNLEVBQUUsTUFBTSxnQ0FBMkIsQ0FBQztBQUUvRCxRQUFJLHdCQUFRLFdBQVcsRUFDcEIsUUFBUSxhQUFhLEVBQ3JCLFFBQVEsbUVBQW1FLEVBQzNFO0FBQUEsTUFBUSxDQUFDLFNBQ1IsS0FDRyxlQUFlLHNCQUFzQixFQUNyQyxTQUFTLEtBQUssT0FBTyxTQUFTLFVBQVUsRUFDeEMsU0FBUyxDQUFPLFVBQVU7QUFDekIsYUFBSyxPQUFPLFNBQVMsYUFBYSxNQUFNLEtBQUs7QUFDN0MsY0FBTSxLQUFLLE9BQU8sYUFBYTtBQUFB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
