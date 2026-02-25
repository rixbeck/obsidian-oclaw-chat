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
          minProtocol: 3,
          maxProtocol: 3,
          client: {
            // Use non-Control-UI client id to avoid Control UI origin restrictions
            id: "gateway-client",
            mode: "backend",
            version: "0.1.3",
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
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsic3JjL21haW4udHMiLCAic3JjL3NldHRpbmdzLnRzIiwgInNyYy93ZWJzb2NrZXQudHMiLCAic3JjL2NoYXQudHMiLCAic3JjL3ZpZXcudHMiLCAic3JjL2NvbnRleHQudHMiLCAic3JjL3R5cGVzLnRzIl0sCiAgInNvdXJjZXNDb250ZW50IjogWyJpbXBvcnQgeyBOb3RpY2UsIFBsdWdpbiwgV29ya3NwYWNlTGVhZiB9IGZyb20gJ29ic2lkaWFuJztcbmltcG9ydCB7IE9wZW5DbGF3U2V0dGluZ1RhYiB9IGZyb20gJy4vc2V0dGluZ3MnO1xuaW1wb3J0IHsgT2JzaWRpYW5XU0NsaWVudCB9IGZyb20gJy4vd2Vic29ja2V0JztcbmltcG9ydCB7IENoYXRNYW5hZ2VyIH0gZnJvbSAnLi9jaGF0JztcbmltcG9ydCB7IFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFULCBPcGVuQ2xhd0NoYXRWaWV3IH0gZnJvbSAnLi92aWV3JztcbmltcG9ydCB7IERFRkFVTFRfU0VUVElOR1MsIHR5cGUgT3BlbkNsYXdTZXR0aW5ncyB9IGZyb20gJy4vdHlwZXMnO1xuXG5leHBvcnQgZGVmYXVsdCBjbGFzcyBPcGVuQ2xhd1BsdWdpbiBleHRlbmRzIFBsdWdpbiB7XG4gIHNldHRpbmdzITogT3BlbkNsYXdTZXR0aW5ncztcbiAgd3NDbGllbnQhOiBPYnNpZGlhbldTQ2xpZW50O1xuICBjaGF0TWFuYWdlciE6IENoYXRNYW5hZ2VyO1xuXG4gIGFzeW5jIG9ubG9hZCgpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBhd2FpdCB0aGlzLmxvYWRTZXR0aW5ncygpO1xuXG4gICAgdGhpcy53c0NsaWVudCA9IG5ldyBPYnNpZGlhbldTQ2xpZW50KFxuICAgICAgdGhpcy5zZXR0aW5ncy5zZXNzaW9uS2V5LFxuICAgICAgdGhpcy5zZXR0aW5ncy5hY2NvdW50SWRcbiAgICApO1xuICAgIHRoaXMuY2hhdE1hbmFnZXIgPSBuZXcgQ2hhdE1hbmFnZXIoKTtcblxuICAgIC8vIFdpcmUgaW5jb21pbmcgV1MgbWVzc2FnZXMgXHUyMTkyIENoYXRNYW5hZ2VyXG4gICAgdGhpcy53c0NsaWVudC5vbk1lc3NhZ2UgPSAobXNnKSA9PiB7XG4gICAgICBpZiAobXNnLnR5cGUgPT09ICdtZXNzYWdlJykge1xuICAgICAgICB0aGlzLmNoYXRNYW5hZ2VyLmFkZE1lc3NhZ2UoQ2hhdE1hbmFnZXIuY3JlYXRlQXNzaXN0YW50TWVzc2FnZShtc2cucGF5bG9hZC5jb250ZW50KSk7XG4gICAgICB9IGVsc2UgaWYgKG1zZy50eXBlID09PSAnZXJyb3InKSB7XG4gICAgICAgIGNvbnN0IGVyclRleHQgPSBtc2cucGF5bG9hZC5tZXNzYWdlID8/ICdVbmtub3duIGVycm9yIGZyb20gZ2F0ZXdheSc7XG4gICAgICAgIHRoaXMuY2hhdE1hbmFnZXIuYWRkTWVzc2FnZShDaGF0TWFuYWdlci5jcmVhdGVTeXN0ZW1NZXNzYWdlKGBcdTI2QTAgJHtlcnJUZXh0fWApKTtcbiAgICAgIH1cbiAgICB9O1xuXG4gICAgLy8gUmVnaXN0ZXIgdGhlIHNpZGViYXIgdmlld1xuICAgIHRoaXMucmVnaXN0ZXJWaWV3KFxuICAgICAgVklFV19UWVBFX09QRU5DTEFXX0NIQVQsXG4gICAgICAobGVhZjogV29ya3NwYWNlTGVhZikgPT4gbmV3IE9wZW5DbGF3Q2hhdFZpZXcobGVhZiwgdGhpcylcbiAgICApO1xuXG4gICAgLy8gUmliYm9uIGljb24gXHUyMDE0IG9wZW5zIC8gcmV2ZWFscyB0aGUgY2hhdCBzaWRlYmFyXG4gICAgdGhpcy5hZGRSaWJib25JY29uKCdtZXNzYWdlLXNxdWFyZScsICdPcGVuQ2xhdyBDaGF0JywgKCkgPT4ge1xuICAgICAgdGhpcy5fYWN0aXZhdGVDaGF0VmlldygpO1xuICAgIH0pO1xuXG4gICAgLy8gU2V0dGluZ3MgdGFiXG4gICAgdGhpcy5hZGRTZXR0aW5nVGFiKG5ldyBPcGVuQ2xhd1NldHRpbmdUYWIodGhpcy5hcHAsIHRoaXMpKTtcblxuICAgIC8vIENvbW1hbmQgcGFsZXR0ZSBlbnRyeVxuICAgIHRoaXMuYWRkQ29tbWFuZCh7XG4gICAgICBpZDogJ29wZW4tb3BlbmNsYXctY2hhdCcsXG4gICAgICBuYW1lOiAnT3BlbiBjaGF0IHNpZGViYXInLFxuICAgICAgY2FsbGJhY2s6ICgpID0+IHRoaXMuX2FjdGl2YXRlQ2hhdFZpZXcoKSxcbiAgICB9KTtcblxuICAgIC8vIENvbm5lY3QgdG8gZ2F0ZXdheSBpZiB0b2tlbiBpcyBjb25maWd1cmVkXG4gICAgaWYgKHRoaXMuc2V0dGluZ3MuYXV0aFRva2VuKSB7XG4gICAgICB0aGlzLl9jb25uZWN0V1MoKTtcbiAgICB9IGVsc2Uge1xuICAgICAgbmV3IE5vdGljZSgnT3BlbkNsYXcgQ2hhdDogcGxlYXNlIGNvbmZpZ3VyZSB5b3VyIGdhdGV3YXkgdG9rZW4gaW4gU2V0dGluZ3MuJyk7XG4gICAgfVxuXG4gICAgY29uc29sZS5sb2coJ1tvY2xhd10gUGx1Z2luIGxvYWRlZCcpO1xuICB9XG5cbiAgYXN5bmMgb251bmxvYWQoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgdGhpcy53c0NsaWVudC5kaXNjb25uZWN0KCk7XG4gICAgdGhpcy5hcHAud29ya3NwYWNlLmRldGFjaExlYXZlc09mVHlwZShWSUVXX1RZUEVfT1BFTkNMQVdfQ0hBVCk7XG4gICAgY29uc29sZS5sb2coJ1tvY2xhd10gUGx1Z2luIHVubG9hZGVkJyk7XG4gIH1cblxuICBhc3luYyBsb2FkU2V0dGluZ3MoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgdGhpcy5zZXR0aW5ncyA9IE9iamVjdC5hc3NpZ24oe30sIERFRkFVTFRfU0VUVElOR1MsIGF3YWl0IHRoaXMubG9hZERhdGEoKSk7XG4gIH1cblxuICBhc3luYyBzYXZlU2V0dGluZ3MoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgYXdhaXQgdGhpcy5zYXZlRGF0YSh0aGlzLnNldHRpbmdzKTtcbiAgfVxuXG4gIC8vIFx1MjUwMFx1MjUwMCBIZWxwZXJzIFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFxuXG4gIHByaXZhdGUgX2Nvbm5lY3RXUygpOiB2b2lkIHtcbiAgICB0aGlzLndzQ2xpZW50LmNvbm5lY3QoXG4gICAgICB0aGlzLnNldHRpbmdzLmdhdGV3YXlVcmwsXG4gICAgICB0aGlzLnNldHRpbmdzLmF1dGhUb2tlblxuICAgICk7XG4gIH1cblxuICBwcml2YXRlIGFzeW5jIF9hY3RpdmF0ZUNoYXRWaWV3KCk6IFByb21pc2U8dm9pZD4ge1xuICAgIGNvbnN0IHsgd29ya3NwYWNlIH0gPSB0aGlzLmFwcDtcblxuICAgIC8vIFJldXNlIGV4aXN0aW5nIGxlYWYgaWYgYWxyZWFkeSBvcGVuXG4gICAgY29uc3QgZXhpc3RpbmcgPSB3b3Jrc3BhY2UuZ2V0TGVhdmVzT2ZUeXBlKFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFUKTtcbiAgICBpZiAoZXhpc3RpbmcubGVuZ3RoID4gMCkge1xuICAgICAgd29ya3NwYWNlLnJldmVhbExlYWYoZXhpc3RpbmdbMF0pO1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIC8vIE9wZW4gaW4gcmlnaHQgc2lkZWJhclxuICAgIGNvbnN0IGxlYWYgPSB3b3Jrc3BhY2UuZ2V0UmlnaHRMZWFmKGZhbHNlKTtcbiAgICBpZiAoIWxlYWYpIHJldHVybjtcbiAgICBhd2FpdCBsZWFmLnNldFZpZXdTdGF0ZSh7IHR5cGU6IFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFULCBhY3RpdmU6IHRydWUgfSk7XG4gICAgd29ya3NwYWNlLnJldmVhbExlYWYobGVhZik7XG4gIH1cbn1cbiIsICJpbXBvcnQgeyBBcHAsIFBsdWdpblNldHRpbmdUYWIsIFNldHRpbmcgfSBmcm9tICdvYnNpZGlhbic7XG5pbXBvcnQgdHlwZSBPcGVuQ2xhd1BsdWdpbiBmcm9tICcuL21haW4nO1xuXG5leHBvcnQgY2xhc3MgT3BlbkNsYXdTZXR0aW5nVGFiIGV4dGVuZHMgUGx1Z2luU2V0dGluZ1RhYiB7XG4gIHBsdWdpbjogT3BlbkNsYXdQbHVnaW47XG5cbiAgY29uc3RydWN0b3IoYXBwOiBBcHAsIHBsdWdpbjogT3BlbkNsYXdQbHVnaW4pIHtcbiAgICBzdXBlcihhcHAsIHBsdWdpbik7XG4gICAgdGhpcy5wbHVnaW4gPSBwbHVnaW47XG4gIH1cblxuICBkaXNwbGF5KCk6IHZvaWQge1xuICAgIGNvbnN0IHsgY29udGFpbmVyRWwgfSA9IHRoaXM7XG4gICAgY29udGFpbmVyRWwuZW1wdHkoKTtcblxuICAgIGNvbnRhaW5lckVsLmNyZWF0ZUVsKCdoMicsIHsgdGV4dDogJ09wZW5DbGF3IENoYXQgXHUyMDEzIFNldHRpbmdzJyB9KTtcblxuICAgIG5ldyBTZXR0aW5nKGNvbnRhaW5lckVsKVxuICAgICAgLnNldE5hbWUoJ0dhdGV3YXkgVVJMJylcbiAgICAgIC5zZXREZXNjKCdXZWJTb2NrZXQgVVJMIG9mIHRoZSBPcGVuQ2xhdyBHYXRld2F5IChlLmcuIHdzOi8vaG9zdG5hbWU6MTg3ODkpLicpXG4gICAgICAuYWRkVGV4dCgodGV4dCkgPT5cbiAgICAgICAgdGV4dFxuICAgICAgICAgIC5zZXRQbGFjZWhvbGRlcignd3M6Ly9sb2NhbGhvc3Q6MTg3ODknKVxuICAgICAgICAgIC5zZXRWYWx1ZSh0aGlzLnBsdWdpbi5zZXR0aW5ncy5nYXRld2F5VXJsKVxuICAgICAgICAgIC5vbkNoYW5nZShhc3luYyAodmFsdWUpID0+IHtcbiAgICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLmdhdGV3YXlVcmwgPSB2YWx1ZS50cmltKCk7XG4gICAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgICB9KVxuICAgICAgKTtcblxuICAgIG5ldyBTZXR0aW5nKGNvbnRhaW5lckVsKVxuICAgICAgLnNldE5hbWUoJ0F1dGggdG9rZW4nKVxuICAgICAgLnNldERlc2MoJ011c3QgbWF0Y2ggdGhlIGF1dGhUb2tlbiBpbiB5b3VyIG9wZW5jbGF3Lmpzb24gY2hhbm5lbCBjb25maWcuIE5ldmVyIHNoYXJlZC4nKVxuICAgICAgLmFkZFRleHQoKHRleHQpID0+IHtcbiAgICAgICAgdGV4dFxuICAgICAgICAgIC5zZXRQbGFjZWhvbGRlcignRW50ZXIgdG9rZW5cdTIwMjYnKVxuICAgICAgICAgIC5zZXRWYWx1ZSh0aGlzLnBsdWdpbi5zZXR0aW5ncy5hdXRoVG9rZW4pXG4gICAgICAgICAgLm9uQ2hhbmdlKGFzeW5jICh2YWx1ZSkgPT4ge1xuICAgICAgICAgICAgdGhpcy5wbHVnaW4uc2V0dGluZ3MuYXV0aFRva2VuID0gdmFsdWU7XG4gICAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgICB9KTtcbiAgICAgICAgLy8gVHJlYXQgYXMgcGFzc3dvcmQgZmllbGQgXHUyMDEzIGRvIG5vdCByZXZlYWwgdG9rZW4gaW4gVUlcbiAgICAgICAgdGV4dC5pbnB1dEVsLnR5cGUgPSAncGFzc3dvcmQnO1xuICAgICAgICB0ZXh0LmlucHV0RWwuYXV0b2NvbXBsZXRlID0gJ29mZic7XG4gICAgICB9KTtcblxuICAgIG5ldyBTZXR0aW5nKGNvbnRhaW5lckVsKVxuICAgICAgLnNldE5hbWUoJ1Nlc3Npb24gS2V5JylcbiAgICAgIC5zZXREZXNjKCdPcGVuQ2xhdyBzZXNzaW9uIHRvIHN1YnNjcmliZSB0byAodXN1YWxseSBcIm1haW5cIikuJylcbiAgICAgIC5hZGRUZXh0KCh0ZXh0KSA9PlxuICAgICAgICB0ZXh0XG4gICAgICAgICAgLnNldFBsYWNlaG9sZGVyKCdtYWluJylcbiAgICAgICAgICAuc2V0VmFsdWUodGhpcy5wbHVnaW4uc2V0dGluZ3Muc2Vzc2lvbktleSlcbiAgICAgICAgICAub25DaGFuZ2UoYXN5bmMgKHZhbHVlKSA9PiB7XG4gICAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5zZXNzaW9uS2V5ID0gdmFsdWUudHJpbSgpIHx8ICdtYWluJztcbiAgICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICAgIH0pXG4gICAgICApO1xuXG4gICAgbmV3IFNldHRpbmcoY29udGFpbmVyRWwpXG4gICAgICAuc2V0TmFtZSgnQWNjb3VudCBJRCcpXG4gICAgICAuc2V0RGVzYygnT3BlbkNsYXcgYWNjb3VudCBJRCAodXN1YWxseSBcIm1haW5cIikuJylcbiAgICAgIC5hZGRUZXh0KCh0ZXh0KSA9PlxuICAgICAgICB0ZXh0XG4gICAgICAgICAgLnNldFBsYWNlaG9sZGVyKCdtYWluJylcbiAgICAgICAgICAuc2V0VmFsdWUodGhpcy5wbHVnaW4uc2V0dGluZ3MuYWNjb3VudElkKVxuICAgICAgICAgIC5vbkNoYW5nZShhc3luYyAodmFsdWUpID0+IHtcbiAgICAgICAgICAgIHRoaXMucGx1Z2luLnNldHRpbmdzLmFjY291bnRJZCA9IHZhbHVlLnRyaW0oKSB8fCAnbWFpbic7XG4gICAgICAgICAgICBhd2FpdCB0aGlzLnBsdWdpbi5zYXZlU2V0dGluZ3MoKTtcbiAgICAgICAgICB9KVxuICAgICAgKTtcblxuICAgIG5ldyBTZXR0aW5nKGNvbnRhaW5lckVsKVxuICAgICAgLnNldE5hbWUoJ0luY2x1ZGUgYWN0aXZlIG5vdGUgYnkgZGVmYXVsdCcpXG4gICAgICAuc2V0RGVzYygnUHJlLWNoZWNrIFwiSW5jbHVkZSBhY3RpdmUgbm90ZVwiIGluIHRoZSBjaGF0IHBhbmVsIHdoZW4gaXQgb3BlbnMuJylcbiAgICAgIC5hZGRUb2dnbGUoKHRvZ2dsZSkgPT5cbiAgICAgICAgdG9nZ2xlLnNldFZhbHVlKHRoaXMucGx1Z2luLnNldHRpbmdzLmluY2x1ZGVBY3RpdmVOb3RlKS5vbkNoYW5nZShhc3luYyAodmFsdWUpID0+IHtcbiAgICAgICAgICB0aGlzLnBsdWdpbi5zZXR0aW5ncy5pbmNsdWRlQWN0aXZlTm90ZSA9IHZhbHVlO1xuICAgICAgICAgIGF3YWl0IHRoaXMucGx1Z2luLnNhdmVTZXR0aW5ncygpO1xuICAgICAgICB9KVxuICAgICAgKTtcblxuICAgIGNvbnRhaW5lckVsLmNyZWF0ZUVsKCdwJywge1xuICAgICAgdGV4dDogJ1JlY29ubmVjdDogY2xvc2UgYW5kIHJlb3BlbiB0aGUgc2lkZWJhciBhZnRlciBjaGFuZ2luZyB0aGUgZ2F0ZXdheSBVUkwgb3IgdG9rZW4uJyxcbiAgICAgIGNsczogJ3NldHRpbmctaXRlbS1kZXNjcmlwdGlvbicsXG4gICAgfSk7XG4gIH1cbn1cbiIsICIvKipcbiAqIFdlYlNvY2tldCBjbGllbnQgZm9yIE9wZW5DbGF3IEdhdGV3YXlcbiAqIFxuICogVXNlcyBHYXRld2F5IHByb3RvY29sOiBKU09OLVJQQyBzdHlsZSByZXF1ZXN0cyArIGV2ZW50IHB1c2hcbiAqIC0gQ29ubmVjdCBoYW5kc2hha2UgZmlyc3QgKHJlcXVpcmVkIGJ5IEdhdGV3YXkpXG4gKiAtIFRoZW4gc3Vic2NyaWJlIHRvIHNlc3Npb25cbiAqIC0gUmVxdWVzdDogeyB0eXBlOiBcInJlcVwiLCBtZXRob2QsIGlkLCBwYXJhbXMgfVxuICogLSBSZXNwb25zZTogeyB0eXBlOiBcInJlc1wiLCBpZCwgb2ssIHBheWxvYWQvZXJyb3IgfVxuICogLSBFdmVudDogeyB0eXBlOiBcImV2ZW50XCIsIGV2ZW50LCBwYXlsb2FkIH1cbiAqL1xuXG5pbXBvcnQgdHlwZSB7IEluYm91bmRXU1BheWxvYWQgfSBmcm9tICcuL3R5cGVzJztcblxuLyoqIE1pbGxpc2Vjb25kcyBiZWZvcmUgYSByZWNvbm5lY3QgYXR0ZW1wdCBhZnRlciBhbiB1bmV4cGVjdGVkIGNsb3NlICovXG5jb25zdCBSRUNPTk5FQ1RfREVMQVlfTVMgPSAzXzAwMDtcbi8qKiBJbnRlcnZhbCBmb3Igc2VuZGluZyBoZWFydGJlYXQgcGluZ3MgKGNoZWNrIGNvbm5lY3Rpb24gbGl2ZW5lc3MpICovXG5jb25zdCBIRUFSVEJFQVRfSU5URVJWQUxfTVMgPSAzMF8wMDA7XG5cbmV4cG9ydCB0eXBlIFdTQ2xpZW50U3RhdGUgPSAnZGlzY29ubmVjdGVkJyB8ICdjb25uZWN0aW5nJyB8ICdoYW5kc2hha2luZycgfCAnc3Vic2NyaWJpbmcnIHwgJ2Nvbm5lY3RlZCc7XG5cbmludGVyZmFjZSBQZW5kaW5nUmVxdWVzdCB7XG4gIHJlc29sdmU6IChwYXlsb2FkOiBhbnkpID0+IHZvaWQ7XG4gIHJlamVjdDogKGVycm9yOiBhbnkpID0+IHZvaWQ7XG59XG5cbmV4cG9ydCBjbGFzcyBPYnNpZGlhbldTQ2xpZW50IHtcbiAgcHJpdmF0ZSB3czogV2ViU29ja2V0IHwgbnVsbCA9IG51bGw7XG4gIHByaXZhdGUgcmVjb25uZWN0VGltZXI6IFJldHVyblR5cGU8dHlwZW9mIHNldFRpbWVvdXQ+IHwgbnVsbCA9IG51bGw7XG4gIHByaXZhdGUgaGVhcnRiZWF0VGltZXI6IFJldHVyblR5cGU8dHlwZW9mIHNldEludGVydmFsPiB8IG51bGwgPSBudWxsO1xuICBwcml2YXRlIGludGVudGlvbmFsQ2xvc2UgPSBmYWxzZTtcbiAgcHJpdmF0ZSBzdWJzY3JpcHRpb25JZDogc3RyaW5nIHwgbnVsbCA9IG51bGw7XG4gIHByaXZhdGUgc2Vzc2lvbktleTogc3RyaW5nO1xuICBwcml2YXRlIGFjY291bnRJZDogc3RyaW5nO1xuICBwcml2YXRlIHVybCA9ICcnO1xuICBwcml2YXRlIHRva2VuID0gJyc7XG4gIHByaXZhdGUgcmVxdWVzdElkID0gMDtcbiAgcHJpdmF0ZSBwZW5kaW5nUmVxdWVzdHMgPSBuZXcgTWFwPHN0cmluZywgUGVuZGluZ1JlcXVlc3Q+KCk7XG5cbiAgc3RhdGU6IFdTQ2xpZW50U3RhdGUgPSAnZGlzY29ubmVjdGVkJztcblxuICAvLyBcdTI1MDBcdTI1MDAgQ2FsbGJhY2tzIChzZXQgYnkgY29uc3VtZXJzKSBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcbiAgb25NZXNzYWdlOiAoKG1zZzogSW5ib3VuZFdTUGF5bG9hZCkgPT4gdm9pZCkgfCBudWxsID0gbnVsbDtcbiAgb25TdGF0ZUNoYW5nZTogKChzdGF0ZTogV1NDbGllbnRTdGF0ZSkgPT4gdm9pZCkgfCBudWxsID0gbnVsbDtcblxuICBjb25zdHJ1Y3RvcihzZXNzaW9uS2V5OiBzdHJpbmcsIGFjY291bnRJZCA9ICdtYWluJykge1xuICAgIHRoaXMuc2Vzc2lvbktleSA9IHNlc3Npb25LZXk7XG4gICAgdGhpcy5hY2NvdW50SWQgPSBhY2NvdW50SWQ7XG4gIH1cblxuICAvLyBcdTI1MDBcdTI1MDAgUHVibGljIEFQSSBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcblxuICBjb25uZWN0KHVybDogc3RyaW5nLCB0b2tlbjogc3RyaW5nKTogdm9pZCB7XG4gICAgdGhpcy51cmwgPSB1cmw7XG4gICAgdGhpcy50b2tlbiA9IHRva2VuO1xuICAgIHRoaXMuaW50ZW50aW9uYWxDbG9zZSA9IGZhbHNlO1xuICAgIHRoaXMuX2Nvbm5lY3QoKTtcbiAgfVxuXG4gIGRpc2Nvbm5lY3QoKTogdm9pZCB7XG4gICAgdGhpcy5pbnRlbnRpb25hbENsb3NlID0gdHJ1ZTtcbiAgICB0aGlzLl9zdG9wVGltZXJzKCk7XG4gICAgaWYgKHRoaXMud3MpIHtcbiAgICAgIHRoaXMud3MuY2xvc2UoKTtcbiAgICAgIHRoaXMud3MgPSBudWxsO1xuICAgIH1cbiAgICB0aGlzLl9zZXRTdGF0ZSgnZGlzY29ubmVjdGVkJyk7XG4gIH1cblxuICBhc3luYyBzZW5kTWVzc2FnZShtZXNzYWdlOiBzdHJpbmcpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBpZiAoIXRoaXMuc3Vic2NyaXB0aW9uSWQpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcignTm90IHN1YnNjcmliZWQgXHUyMDE0IGNhbGwgY29ubmVjdCgpIGZpcnN0Jyk7XG4gICAgfVxuXG4gICAgYXdhaXQgdGhpcy5fc2VuZFJlcXVlc3QoJ29ic2lkaWFuLnNlbmQnLCB7XG4gICAgICBzdWJzY3JpcHRpb25JZDogdGhpcy5zdWJzY3JpcHRpb25JZCxcbiAgICAgIG1lc3NhZ2UsXG4gICAgfSk7XG4gIH1cblxuICAvLyBcdTI1MDBcdTI1MDAgSW50ZXJuYWwgXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG5cbiAgcHJpdmF0ZSBfY29ubmVjdCgpOiB2b2lkIHtcbiAgICBpZiAodGhpcy53cykge1xuICAgICAgdGhpcy53cy5vbm9wZW4gPSBudWxsO1xuICAgICAgdGhpcy53cy5vbmNsb3NlID0gbnVsbDtcbiAgICAgIHRoaXMud3Mub25tZXNzYWdlID0gbnVsbDtcbiAgICAgIHRoaXMud3Mub25lcnJvciA9IG51bGw7XG4gICAgICB0aGlzLndzLmNsb3NlKCk7XG4gICAgICB0aGlzLndzID0gbnVsbDtcbiAgICB9XG5cbiAgICB0aGlzLl9zZXRTdGF0ZSgnY29ubmVjdGluZycpO1xuXG4gICAgY29uc3Qgd3MgPSBuZXcgV2ViU29ja2V0KHRoaXMudXJsKTtcbiAgICB0aGlzLndzID0gd3M7XG5cbiAgICB3cy5vbm9wZW4gPSBhc3luYyAoKSA9PiB7XG4gICAgICB0aGlzLl9zZXRTdGF0ZSgnaGFuZHNoYWtpbmcnKTtcbiAgICAgIHRyeSB7XG4gICAgICAgIC8vIFN0ZXAgMTogQ29ubmVjdCBoYW5kc2hha2UgKHJlcXVpcmVkIGJ5IEdhdGV3YXkpXG4gICAgICAgIGF3YWl0IHRoaXMuX3NlbmRSZXF1ZXN0KCdjb25uZWN0Jywge1xuICAgICAgICAgIG1pblByb3RvY29sOiAzLFxuICAgICAgICAgIG1heFByb3RvY29sOiAzLFxuICAgICAgICAgIGNsaWVudDoge1xuICAgICAgICAgICAgLy8gVXNlIG5vbi1Db250cm9sLVVJIGNsaWVudCBpZCB0byBhdm9pZCBDb250cm9sIFVJIG9yaWdpbiByZXN0cmljdGlvbnNcbiAgICAgICAgICAgIGlkOiAnZ2F0ZXdheS1jbGllbnQnLFxuICAgICAgICAgICAgbW9kZTogJ2JhY2tlbmQnLFxuICAgICAgICAgICAgdmVyc2lvbjogJzAuMS4zJyxcbiAgICAgICAgICAgIHBsYXRmb3JtOiAnZWxlY3Ryb24nLFxuICAgICAgICAgIH0sXG4gICAgICAgICAgYXV0aDoge1xuICAgICAgICAgICAgdG9rZW46IHRoaXMudG9rZW4sXG4gICAgICAgICAgfSxcbiAgICAgICAgfSk7XG5cbiAgICAgICAgLy8gU3RlcCAyOiBTdWJzY3JpYmUgdG8gc2Vzc2lvblxuICAgICAgICB0aGlzLl9zZXRTdGF0ZSgnc3Vic2NyaWJpbmcnKTtcbiAgICAgICAgY29uc3QgcmVzdWx0ID0gYXdhaXQgdGhpcy5fc2VuZFJlcXVlc3QoJ29ic2lkaWFuLnN1YnNjcmliZScsIHtcbiAgICAgICAgICB0b2tlbjogdGhpcy50b2tlbixcbiAgICAgICAgICBzZXNzaW9uS2V5OiB0aGlzLnNlc3Npb25LZXksXG4gICAgICAgICAgYWNjb3VudElkOiB0aGlzLmFjY291bnRJZCxcbiAgICAgICAgfSk7XG5cbiAgICAgICAgaWYgKHJlc3VsdD8uc3Vic2NyaXB0aW9uSWQpIHtcbiAgICAgICAgICB0aGlzLnN1YnNjcmlwdGlvbklkID0gcmVzdWx0LnN1YnNjcmlwdGlvbklkO1xuICAgICAgICAgIHRoaXMuX3NldFN0YXRlKCdjb25uZWN0ZWQnKTtcbiAgICAgICAgICB0aGlzLl9zdGFydEhlYXJ0YmVhdCgpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHRocm93IG5ldyBFcnJvcignU3Vic2NyaWJlIGZhaWxlZDogbm8gc3Vic2NyaXB0aW9uSWQgcmV0dXJuZWQnKTtcbiAgICAgICAgfVxuICAgICAgfSBjYXRjaCAoZXJyKSB7XG4gICAgICAgIGNvbnNvbGUuZXJyb3IoJ1tvY2xhdy13c10gQ29ubmVjdGlvbiBzZXR1cCBmYWlsZWQnLCBlcnIpO1xuICAgICAgICB3cy5jbG9zZSgpO1xuICAgICAgfVxuICAgIH07XG5cbiAgICB3cy5vbm1lc3NhZ2UgPSAoZXZlbnQ6IE1lc3NhZ2VFdmVudCkgPT4ge1xuICAgICAgbGV0IGZyYW1lOiBhbnk7XG4gICAgICB0cnkge1xuICAgICAgICBmcmFtZSA9IEpTT04ucGFyc2UoZXZlbnQuZGF0YSBhcyBzdHJpbmcpO1xuICAgICAgfSBjYXRjaCB7XG4gICAgICAgIGNvbnNvbGUuZXJyb3IoJ1tvY2xhdy13c10gRmFpbGVkIHRvIHBhcnNlIGluY29taW5nIG1lc3NhZ2UnKTtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuXG4gICAgICAvLyBIYW5kbGUgcmVzcG9uc2UgdG8gcGVuZGluZyByZXF1ZXN0XG4gICAgICBpZiAoZnJhbWUudHlwZSA9PT0gJ3JlcycpIHtcbiAgICAgICAgY29uc3QgcGVuZGluZyA9IHRoaXMucGVuZGluZ1JlcXVlc3RzLmdldChmcmFtZS5pZCk7XG4gICAgICAgIGlmIChwZW5kaW5nKSB7XG4gICAgICAgICAgdGhpcy5wZW5kaW5nUmVxdWVzdHMuZGVsZXRlKGZyYW1lLmlkKTtcbiAgICAgICAgICBpZiAoZnJhbWUub2spIHtcbiAgICAgICAgICAgIHBlbmRpbmcucmVzb2x2ZShmcmFtZS5wYXlsb2FkKTtcbiAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgcGVuZGluZy5yZWplY3QobmV3IEVycm9yKGZyYW1lLmVycm9yPy5tZXNzYWdlIHx8ICdSZXF1ZXN0IGZhaWxlZCcpKTtcbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuXG4gICAgICAvLyBIYW5kbGUgZXZlbnQgcHVzaCBmcm9tIGdhdGV3YXlcbiAgICAgIGlmIChmcmFtZS50eXBlID09PSAnZXZlbnQnKSB7XG4gICAgICAgIC8vIE9ic2lkaWFuIG1lc3NhZ2UgcHVzaFxuICAgICAgICBpZiAoZnJhbWUuZXZlbnQgPT09ICdvYnNpZGlhbi5tZXNzYWdlJykge1xuICAgICAgICAgIGNvbnN0IG1zZzogSW5ib3VuZFdTUGF5bG9hZCA9IHtcbiAgICAgICAgICAgIHR5cGU6ICdtZXNzYWdlJyxcbiAgICAgICAgICAgIHBheWxvYWQ6IHtcbiAgICAgICAgICAgICAgY29udGVudDogZnJhbWUucGF5bG9hZD8uY29udGVudCB8fCAnJyxcbiAgICAgICAgICAgICAgcm9sZTogZnJhbWUucGF5bG9hZD8ucm9sZSB8fCAnYXNzaXN0YW50JyxcbiAgICAgICAgICAgICAgdGltZXN0YW1wOiBmcmFtZS5wYXlsb2FkPy50aW1lc3RhbXAgfHwgRGF0ZS5ub3coKSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfTtcbiAgICAgICAgICB0aGlzLm9uTWVzc2FnZT8uKG1zZyk7XG4gICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgLy8gSWdub3JlIG90aGVyIGV2ZW50cyAoY29ubmVjdC5jaGFsbGVuZ2UsIGV0Yy4pXG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cblxuICAgICAgLy8gVW5rbm93biBmcmFtZSB0eXBlIFx1MjAxNCBpZ25vcmVcbiAgICAgIGNvbnNvbGUuZGVidWcoJ1tvY2xhdy13c10gVW5oYW5kbGVkIGZyYW1lJywgZnJhbWUpO1xuICAgIH07XG5cbiAgICB3cy5vbmNsb3NlID0gKCkgPT4ge1xuICAgICAgdGhpcy5fc3RvcFRpbWVycygpO1xuICAgICAgdGhpcy5fc2V0U3RhdGUoJ2Rpc2Nvbm5lY3RlZCcpO1xuICAgICAgdGhpcy5zdWJzY3JpcHRpb25JZCA9IG51bGw7XG4gICAgICAvLyBSZWplY3QgYWxsIHBlbmRpbmcgcmVxdWVzdHNcbiAgICAgIGZvciAoY29uc3QgcGVuZGluZyBvZiB0aGlzLnBlbmRpbmdSZXF1ZXN0cy52YWx1ZXMoKSkge1xuICAgICAgICBwZW5kaW5nLnJlamVjdChuZXcgRXJyb3IoJ0Nvbm5lY3Rpb24gY2xvc2VkJykpO1xuICAgICAgfVxuICAgICAgdGhpcy5wZW5kaW5nUmVxdWVzdHMuY2xlYXIoKTtcblxuICAgICAgaWYgKCF0aGlzLmludGVudGlvbmFsQ2xvc2UpIHtcbiAgICAgICAgdGhpcy5fc2NoZWR1bGVSZWNvbm5lY3QoKTtcbiAgICAgIH1cbiAgICB9O1xuXG4gICAgd3Mub25lcnJvciA9IChldjogRXZlbnQpID0+IHtcbiAgICAgIGNvbnNvbGUuZXJyb3IoJ1tvY2xhdy13c10gV2ViU29ja2V0IGVycm9yJywgZXYpO1xuICAgICAgLy8gb25jbG9zZSB3aWxsIGZpcmUgYWZ0ZXIgb25lcnJvciBcdTIwMTQgcmVjb25uZWN0IGxvZ2ljIGhhbmRsZWQgdGhlcmVcbiAgICB9O1xuICB9XG5cbiAgcHJpdmF0ZSBfc2VuZFJlcXVlc3QobWV0aG9kOiBzdHJpbmcsIHBhcmFtczogYW55KTogUHJvbWlzZTxhbnk+IHtcbiAgICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgaWYgKCF0aGlzLndzIHx8IHRoaXMud3MucmVhZHlTdGF0ZSAhPT0gV2ViU29ja2V0Lk9QRU4pIHtcbiAgICAgICAgcmVqZWN0KG5ldyBFcnJvcignV2ViU29ja2V0IG5vdCBjb25uZWN0ZWQnKSk7XG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cblxuICAgICAgY29uc3QgaWQgPSBgcmVxLSR7Kyt0aGlzLnJlcXVlc3RJZH1gO1xuICAgICAgdGhpcy5wZW5kaW5nUmVxdWVzdHMuc2V0KGlkLCB7IHJlc29sdmUsIHJlamVjdCB9KTtcblxuICAgICAgY29uc3QgZnJhbWUgPSB7XG4gICAgICAgIHR5cGU6ICdyZXEnLFxuICAgICAgICBtZXRob2QsXG4gICAgICAgIGlkLFxuICAgICAgICBwYXJhbXMsXG4gICAgICB9O1xuXG4gICAgICB0aGlzLndzLnNlbmQoSlNPTi5zdHJpbmdpZnkoZnJhbWUpKTtcblxuICAgICAgLy8gVGltZW91dCBhZnRlciAzMHNcbiAgICAgIHNldFRpbWVvdXQoKCkgPT4ge1xuICAgICAgICBpZiAodGhpcy5wZW5kaW5nUmVxdWVzdHMuaGFzKGlkKSkge1xuICAgICAgICAgIHRoaXMucGVuZGluZ1JlcXVlc3RzLmRlbGV0ZShpZCk7XG4gICAgICAgICAgcmVqZWN0KG5ldyBFcnJvcihgUmVxdWVzdCB0aW1lb3V0OiAke21ldGhvZH1gKSk7XG4gICAgICAgIH1cbiAgICAgIH0sIDMwXzAwMCk7XG4gICAgfSk7XG4gIH1cblxuICBwcml2YXRlIF9zY2hlZHVsZVJlY29ubmVjdCgpOiB2b2lkIHtcbiAgICBpZiAodGhpcy5yZWNvbm5lY3RUaW1lciAhPT0gbnVsbCkgcmV0dXJuO1xuICAgIHRoaXMucmVjb25uZWN0VGltZXIgPSBzZXRUaW1lb3V0KCgpID0+IHtcbiAgICAgIHRoaXMucmVjb25uZWN0VGltZXIgPSBudWxsO1xuICAgICAgaWYgKCF0aGlzLmludGVudGlvbmFsQ2xvc2UpIHtcbiAgICAgICAgY29uc29sZS5sb2coYFtvY2xhdy13c10gUmVjb25uZWN0aW5nIHRvICR7dGhpcy51cmx9XHUyMDI2YCk7XG4gICAgICAgIHRoaXMuX2Nvbm5lY3QoKTtcbiAgICAgIH1cbiAgICB9LCBSRUNPTk5FQ1RfREVMQVlfTVMpO1xuICB9XG5cbiAgcHJpdmF0ZSBfc3RhcnRIZWFydGJlYXQoKTogdm9pZCB7XG4gICAgdGhpcy5fc3RvcEhlYXJ0YmVhdCgpO1xuICAgIHRoaXMuaGVhcnRiZWF0VGltZXIgPSBzZXRJbnRlcnZhbCgoKSA9PiB7XG4gICAgICBpZiAodGhpcy53cz8ucmVhZHlTdGF0ZSAhPT0gV2ViU29ja2V0Lk9QRU4pIHJldHVybjtcbiAgICAgIC8vIFNpbXBsZSBoZWFydGJlYXQ6IGNoZWNrIGNvbm5lY3Rpb24gbGl2ZW5lc3NcbiAgICAgIC8vIEdhdGV3YXkgd2lsbCBjbG9zZSBzdGFsZSBjb25uZWN0aW9ucyBhdXRvbWF0aWNhbGx5XG4gICAgICBpZiAodGhpcy53cy5idWZmZXJlZEFtb3VudCA+IDApIHtcbiAgICAgICAgY29uc29sZS53YXJuKCdbb2NsYXctd3NdIFNlbmQgYnVmZmVyIG5vdCBlbXB0eSBcdTIwMTQgY29ubmVjdGlvbiBtYXkgYmUgc3RhbGxlZCcpO1xuICAgICAgfVxuICAgIH0sIEhFQVJUQkVBVF9JTlRFUlZBTF9NUyk7XG4gIH1cblxuICBwcml2YXRlIF9zdG9wSGVhcnRiZWF0KCk6IHZvaWQge1xuICAgIGlmICh0aGlzLmhlYXJ0YmVhdFRpbWVyKSB7XG4gICAgICBjbGVhckludGVydmFsKHRoaXMuaGVhcnRiZWF0VGltZXIpO1xuICAgICAgdGhpcy5oZWFydGJlYXRUaW1lciA9IG51bGw7XG4gICAgfVxuICB9XG5cbiAgcHJpdmF0ZSBfc3RvcFRpbWVycygpOiB2b2lkIHtcbiAgICB0aGlzLl9zdG9wSGVhcnRiZWF0KCk7XG4gICAgaWYgKHRoaXMucmVjb25uZWN0VGltZXIpIHtcbiAgICAgIGNsZWFyVGltZW91dCh0aGlzLnJlY29ubmVjdFRpbWVyKTtcbiAgICAgIHRoaXMucmVjb25uZWN0VGltZXIgPSBudWxsO1xuICAgIH1cbiAgfVxuXG4gIHByaXZhdGUgX3NldFN0YXRlKHN0YXRlOiBXU0NsaWVudFN0YXRlKTogdm9pZCB7XG4gICAgaWYgKHRoaXMuc3RhdGUgPT09IHN0YXRlKSByZXR1cm47XG4gICAgdGhpcy5zdGF0ZSA9IHN0YXRlO1xuICAgIHRoaXMub25TdGF0ZUNoYW5nZT8uKHN0YXRlKTtcbiAgfVxufVxuIiwgImltcG9ydCB0eXBlIHsgQ2hhdE1lc3NhZ2UgfSBmcm9tICcuL3R5cGVzJztcblxuLyoqIE1hbmFnZXMgdGhlIGluLW1lbW9yeSBsaXN0IG9mIGNoYXQgbWVzc2FnZXMgYW5kIG5vdGlmaWVzIFVJIG9uIGNoYW5nZXMgKi9cbmV4cG9ydCBjbGFzcyBDaGF0TWFuYWdlciB7XG4gIHByaXZhdGUgbWVzc2FnZXM6IENoYXRNZXNzYWdlW10gPSBbXTtcblxuICAvKiogRmlyZWQgZm9yIGEgZnVsbCByZS1yZW5kZXIgKGNsZWFyL3JlbG9hZCkgKi9cbiAgb25VcGRhdGU6ICgobWVzc2FnZXM6IHJlYWRvbmx5IENoYXRNZXNzYWdlW10pID0+IHZvaWQpIHwgbnVsbCA9IG51bGw7XG4gIC8qKiBGaXJlZCB3aGVuIGEgc2luZ2xlIG1lc3NhZ2UgaXMgYXBwZW5kZWQgXHUyMDE0IHVzZSBmb3IgTygxKSBhcHBlbmQtb25seSBVSSAqL1xuICBvbk1lc3NhZ2VBZGRlZDogKChtc2c6IENoYXRNZXNzYWdlKSA9PiB2b2lkKSB8IG51bGwgPSBudWxsO1xuXG4gIGFkZE1lc3NhZ2UobXNnOiBDaGF0TWVzc2FnZSk6IHZvaWQge1xuICAgIHRoaXMubWVzc2FnZXMucHVzaChtc2cpO1xuICAgIHRoaXMub25NZXNzYWdlQWRkZWQ/Lihtc2cpO1xuICB9XG5cbiAgZ2V0TWVzc2FnZXMoKTogcmVhZG9ubHkgQ2hhdE1lc3NhZ2VbXSB7XG4gICAgcmV0dXJuIHRoaXMubWVzc2FnZXM7XG4gIH1cblxuICBjbGVhcigpOiB2b2lkIHtcbiAgICB0aGlzLm1lc3NhZ2VzID0gW107XG4gICAgdGhpcy5vblVwZGF0ZT8uKFtdKTtcbiAgfVxuXG4gIC8qKiBDcmVhdGUgYSB1c2VyIG1lc3NhZ2Ugb2JqZWN0ICh3aXRob3V0IGFkZGluZyBpdCkgKi9cbiAgc3RhdGljIGNyZWF0ZVVzZXJNZXNzYWdlKGNvbnRlbnQ6IHN0cmluZyk6IENoYXRNZXNzYWdlIHtcbiAgICByZXR1cm4ge1xuICAgICAgaWQ6IGBtc2ctJHtEYXRlLm5vdygpfS0ke01hdGgucmFuZG9tKCkudG9TdHJpbmcoMzYpLnNsaWNlKDIsIDcpfWAsXG4gICAgICByb2xlOiAndXNlcicsXG4gICAgICBjb250ZW50LFxuICAgICAgdGltZXN0YW1wOiBEYXRlLm5vdygpLFxuICAgIH07XG4gIH1cblxuICAvKiogQ3JlYXRlIGFuIGFzc2lzdGFudCBtZXNzYWdlIG9iamVjdCAod2l0aG91dCBhZGRpbmcgaXQpICovXG4gIHN0YXRpYyBjcmVhdGVBc3Npc3RhbnRNZXNzYWdlKGNvbnRlbnQ6IHN0cmluZyk6IENoYXRNZXNzYWdlIHtcbiAgICByZXR1cm4ge1xuICAgICAgaWQ6IGBtc2ctJHtEYXRlLm5vdygpfS0ke01hdGgucmFuZG9tKCkudG9TdHJpbmcoMzYpLnNsaWNlKDIsIDcpfWAsXG4gICAgICByb2xlOiAnYXNzaXN0YW50JyxcbiAgICAgIGNvbnRlbnQsXG4gICAgICB0aW1lc3RhbXA6IERhdGUubm93KCksXG4gICAgfTtcbiAgfVxuXG4gIC8qKiBDcmVhdGUgYSBzeXN0ZW0gLyBzdGF0dXMgbWVzc2FnZSAoZXJyb3JzLCByZWNvbm5lY3Qgbm90aWNlcywgZXRjLikgKi9cbiAgc3RhdGljIGNyZWF0ZVN5c3RlbU1lc3NhZ2UoY29udGVudDogc3RyaW5nKTogQ2hhdE1lc3NhZ2Uge1xuICAgIHJldHVybiB7XG4gICAgICBpZDogYHN5cy0ke0RhdGUubm93KCl9YCxcbiAgICAgIHJvbGU6ICdzeXN0ZW0nLFxuICAgICAgY29udGVudCxcbiAgICAgIHRpbWVzdGFtcDogRGF0ZS5ub3coKSxcbiAgICB9O1xuICB9XG59XG4iLCAiaW1wb3J0IHsgSXRlbVZpZXcsIFdvcmtzcGFjZUxlYWYgfSBmcm9tICdvYnNpZGlhbic7XG5pbXBvcnQgdHlwZSBPcGVuQ2xhd1BsdWdpbiBmcm9tICcuL21haW4nO1xuaW1wb3J0IHsgQ2hhdE1hbmFnZXIgfSBmcm9tICcuL2NoYXQnO1xuaW1wb3J0IHR5cGUgeyBDaGF0TWVzc2FnZSB9IGZyb20gJy4vdHlwZXMnO1xuaW1wb3J0IHsgZ2V0QWN0aXZlTm90ZUNvbnRleHQgfSBmcm9tICcuL2NvbnRleHQnO1xuXG5leHBvcnQgY29uc3QgVklFV19UWVBFX09QRU5DTEFXX0NIQVQgPSAnb3BlbmNsYXctY2hhdCc7XG5cbmV4cG9ydCBjbGFzcyBPcGVuQ2xhd0NoYXRWaWV3IGV4dGVuZHMgSXRlbVZpZXcge1xuICBwcml2YXRlIHBsdWdpbjogT3BlbkNsYXdQbHVnaW47XG4gIHByaXZhdGUgY2hhdE1hbmFnZXI6IENoYXRNYW5hZ2VyO1xuXG4gIC8vIERPTSByZWZzXG4gIHByaXZhdGUgbWVzc2FnZXNFbCE6IEhUTUxFbGVtZW50O1xuICBwcml2YXRlIGlucHV0RWwhOiBIVE1MVGV4dEFyZWFFbGVtZW50O1xuICBwcml2YXRlIHNlbmRCdG4hOiBIVE1MQnV0dG9uRWxlbWVudDtcbiAgcHJpdmF0ZSBpbmNsdWRlTm90ZUNoZWNrYm94ITogSFRNTElucHV0RWxlbWVudDtcbiAgcHJpdmF0ZSBzdGF0dXNEb3QhOiBIVE1MRWxlbWVudDtcblxuICBjb25zdHJ1Y3RvcihsZWFmOiBXb3Jrc3BhY2VMZWFmLCBwbHVnaW46IE9wZW5DbGF3UGx1Z2luKSB7XG4gICAgc3VwZXIobGVhZik7XG4gICAgdGhpcy5wbHVnaW4gPSBwbHVnaW47XG4gICAgdGhpcy5jaGF0TWFuYWdlciA9IHBsdWdpbi5jaGF0TWFuYWdlcjtcbiAgfVxuXG4gIGdldFZpZXdUeXBlKCk6IHN0cmluZyB7XG4gICAgcmV0dXJuIFZJRVdfVFlQRV9PUEVOQ0xBV19DSEFUO1xuICB9XG5cbiAgZ2V0RGlzcGxheVRleHQoKTogc3RyaW5nIHtcbiAgICByZXR1cm4gJ09wZW5DbGF3IENoYXQnO1xuICB9XG5cbiAgZ2V0SWNvbigpOiBzdHJpbmcge1xuICAgIHJldHVybiAnbWVzc2FnZS1zcXVhcmUnO1xuICB9XG5cbiAgYXN5bmMgb25PcGVuKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIHRoaXMuX2J1aWxkVUkoKTtcblxuICAgIC8vIEZ1bGwgcmUtcmVuZGVyIG9uIGNsZWFyIC8gcmVsb2FkXG4gICAgdGhpcy5jaGF0TWFuYWdlci5vblVwZGF0ZSA9IChtc2dzKSA9PiB0aGlzLl9yZW5kZXJNZXNzYWdlcyhtc2dzKTtcbiAgICAvLyBPKDEpIGFwcGVuZCBmb3IgbmV3IG1lc3NhZ2VzXG4gICAgdGhpcy5jaGF0TWFuYWdlci5vbk1lc3NhZ2VBZGRlZCA9IChtc2cpID0+IHRoaXMuX2FwcGVuZE1lc3NhZ2UobXNnKTtcblxuICAgIC8vIFN1YnNjcmliZSB0byBXUyBzdGF0ZSBjaGFuZ2VzXG4gICAgdGhpcy5wbHVnaW4ud3NDbGllbnQub25TdGF0ZUNoYW5nZSA9IChzdGF0ZSkgPT4ge1xuICAgICAgY29uc3QgY29ubmVjdGVkID0gc3RhdGUgPT09ICdjb25uZWN0ZWQnO1xuICAgICAgdGhpcy5zdGF0dXNEb3QudG9nZ2xlQ2xhc3MoJ2Nvbm5lY3RlZCcsIGNvbm5lY3RlZCk7XG4gICAgICB0aGlzLnN0YXR1c0RvdC50aXRsZSA9IGBHYXRld2F5OiAke3N0YXRlfWA7XG4gICAgICB0aGlzLnNlbmRCdG4uZGlzYWJsZWQgPSAhY29ubmVjdGVkO1xuICAgIH07XG5cbiAgICAvLyBSZWZsZWN0IGN1cnJlbnQgc3RhdGVcbiAgICBjb25zdCBjb25uZWN0ZWQgPSB0aGlzLnBsdWdpbi53c0NsaWVudC5zdGF0ZSA9PT0gJ2Nvbm5lY3RlZCc7XG4gICAgdGhpcy5zdGF0dXNEb3QudG9nZ2xlQ2xhc3MoJ2Nvbm5lY3RlZCcsIGNvbm5lY3RlZCk7XG4gICAgdGhpcy5zZW5kQnRuLmRpc2FibGVkID0gIWNvbm5lY3RlZDtcblxuICAgIHRoaXMuX3JlbmRlck1lc3NhZ2VzKHRoaXMuY2hhdE1hbmFnZXIuZ2V0TWVzc2FnZXMoKSk7XG4gIH1cblxuICBhc3luYyBvbkNsb3NlKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIHRoaXMuY2hhdE1hbmFnZXIub25VcGRhdGUgPSBudWxsO1xuICAgIHRoaXMuY2hhdE1hbmFnZXIub25NZXNzYWdlQWRkZWQgPSBudWxsO1xuICAgIHRoaXMucGx1Z2luLndzQ2xpZW50Lm9uU3RhdGVDaGFuZ2UgPSBudWxsO1xuICB9XG5cbiAgLy8gXHUyNTAwXHUyNTAwIFVJIGNvbnN0cnVjdGlvbiBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcdTI1MDBcblxuICBwcml2YXRlIF9idWlsZFVJKCk6IHZvaWQge1xuICAgIGNvbnN0IHJvb3QgPSB0aGlzLmNvbnRlbnRFbDtcbiAgICByb290LmVtcHR5KCk7XG4gICAgcm9vdC5hZGRDbGFzcygnb2NsYXctY2hhdC12aWV3Jyk7XG5cbiAgICAvLyBcdTI1MDBcdTI1MDAgSGVhZGVyIFx1MjUwMFx1MjUwMFxuICAgIGNvbnN0IGhlYWRlciA9IHJvb3QuY3JlYXRlRGl2KHsgY2xzOiAnb2NsYXctaGVhZGVyJyB9KTtcbiAgICBoZWFkZXIuY3JlYXRlU3Bhbih7IGNsczogJ29jbGF3LWhlYWRlci10aXRsZScsIHRleHQ6ICdPcGVuQ2xhdyBDaGF0JyB9KTtcbiAgICB0aGlzLnN0YXR1c0RvdCA9IGhlYWRlci5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1zdGF0dXMtZG90JyB9KTtcbiAgICB0aGlzLnN0YXR1c0RvdC50aXRsZSA9ICdHYXRld2F5OiBkaXNjb25uZWN0ZWQnO1xuXG4gICAgLy8gXHUyNTAwXHUyNTAwIE1lc3NhZ2VzIGFyZWEgXHUyNTAwXHUyNTAwXG4gICAgdGhpcy5tZXNzYWdlc0VsID0gcm9vdC5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1tZXNzYWdlcycgfSk7XG5cbiAgICAvLyBcdTI1MDBcdTI1MDAgQ29udGV4dCByb3cgXHUyNTAwXHUyNTAwXG4gICAgY29uc3QgY3R4Um93ID0gcm9vdC5jcmVhdGVEaXYoeyBjbHM6ICdvY2xhdy1jb250ZXh0LXJvdycgfSk7XG4gICAgdGhpcy5pbmNsdWRlTm90ZUNoZWNrYm94ID0gY3R4Um93LmNyZWF0ZUVsKCdpbnB1dCcsIHsgdHlwZTogJ2NoZWNrYm94JyB9KTtcbiAgICB0aGlzLmluY2x1ZGVOb3RlQ2hlY2tib3guaWQgPSAnb2NsYXctaW5jbHVkZS1ub3RlJztcbiAgICB0aGlzLmluY2x1ZGVOb3RlQ2hlY2tib3guY2hlY2tlZCA9IHRoaXMucGx1Z2luLnNldHRpbmdzLmluY2x1ZGVBY3RpdmVOb3RlO1xuICAgIGNvbnN0IGN0eExhYmVsID0gY3R4Um93LmNyZWF0ZUVsKCdsYWJlbCcsIHsgdGV4dDogJ0luY2x1ZGUgYWN0aXZlIG5vdGUnIH0pO1xuICAgIGN0eExhYmVsLmh0bWxGb3IgPSAnb2NsYXctaW5jbHVkZS1ub3RlJztcblxuICAgIC8vIFx1MjUwMFx1MjUwMCBJbnB1dCByb3cgXHUyNTAwXHUyNTAwXG4gICAgY29uc3QgaW5wdXRSb3cgPSByb290LmNyZWF0ZURpdih7IGNsczogJ29jbGF3LWlucHV0LXJvdycgfSk7XG4gICAgdGhpcy5pbnB1dEVsID0gaW5wdXRSb3cuY3JlYXRlRWwoJ3RleHRhcmVhJywge1xuICAgICAgY2xzOiAnb2NsYXctaW5wdXQnLFxuICAgICAgcGxhY2Vob2xkZXI6ICdBc2sgYW55dGhpbmdcdTIwMjYnLFxuICAgIH0pO1xuICAgIHRoaXMuaW5wdXRFbC5yb3dzID0gMTtcblxuICAgIHRoaXMuc2VuZEJ0biA9IGlucHV0Um93LmNyZWF0ZUVsKCdidXR0b24nLCB7IGNsczogJ29jbGF3LXNlbmQtYnRuJywgdGV4dDogJ1NlbmQnIH0pO1xuXG4gICAgLy8gXHUyNTAwXHUyNTAwIEV2ZW50IGxpc3RlbmVycyBcdTI1MDBcdTI1MDBcbiAgICB0aGlzLnNlbmRCdG4uYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKSA9PiB0aGlzLl9oYW5kbGVTZW5kKCkpO1xuICAgIHRoaXMuaW5wdXRFbC5hZGRFdmVudExpc3RlbmVyKCdrZXlkb3duJywgKGUpID0+IHtcbiAgICAgIGlmIChlLmtleSA9PT0gJ0VudGVyJyAmJiAhZS5zaGlmdEtleSkge1xuICAgICAgICBlLnByZXZlbnREZWZhdWx0KCk7XG4gICAgICAgIHRoaXMuX2hhbmRsZVNlbmQoKTtcbiAgICAgIH1cbiAgICB9KTtcbiAgICAvLyBBdXRvLXJlc2l6ZSB0ZXh0YXJlYVxuICAgIHRoaXMuaW5wdXRFbC5hZGRFdmVudExpc3RlbmVyKCdpbnB1dCcsICgpID0+IHtcbiAgICAgIHRoaXMuaW5wdXRFbC5zdHlsZS5oZWlnaHQgPSAnYXV0byc7XG4gICAgICB0aGlzLmlucHV0RWwuc3R5bGUuaGVpZ2h0ID0gYCR7dGhpcy5pbnB1dEVsLnNjcm9sbEhlaWdodH1weGA7XG4gICAgfSk7XG4gIH1cblxuICAvLyBcdTI1MDBcdTI1MDAgTWVzc2FnZSByZW5kZXJpbmcgXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXHUyNTAwXG5cbiAgcHJpdmF0ZSBfcmVuZGVyTWVzc2FnZXMobWVzc2FnZXM6IHJlYWRvbmx5IENoYXRNZXNzYWdlW10pOiB2b2lkIHtcbiAgICB0aGlzLm1lc3NhZ2VzRWwuZW1wdHkoKTtcblxuICAgIGlmIChtZXNzYWdlcy5sZW5ndGggPT09IDApIHtcbiAgICAgIHRoaXMubWVzc2FnZXNFbC5jcmVhdGVFbCgncCcsIHtcbiAgICAgICAgdGV4dDogJ1NlbmQgYSBtZXNzYWdlIHRvIHN0YXJ0IGNoYXR0aW5nLicsXG4gICAgICAgIGNsczogJ29jbGF3LW1lc3NhZ2Ugc3lzdGVtIG9jbGF3LXBsYWNlaG9sZGVyJyxcbiAgICAgIH0pO1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIGZvciAoY29uc3QgbXNnIG9mIG1lc3NhZ2VzKSB7XG4gICAgICBjb25zdCBlbCA9IHRoaXMubWVzc2FnZXNFbC5jcmVhdGVEaXYoeyBjbHM6IGBvY2xhdy1tZXNzYWdlICR7bXNnLnJvbGV9YCB9KTtcbiAgICAgIGVsLmNyZWF0ZVNwYW4oeyB0ZXh0OiBtc2cuY29udGVudCB9KTtcbiAgICB9XG5cbiAgICAvLyBTY3JvbGwgdG8gYm90dG9tXG4gICAgdGhpcy5tZXNzYWdlc0VsLnNjcm9sbFRvcCA9IHRoaXMubWVzc2FnZXNFbC5zY3JvbGxIZWlnaHQ7XG4gIH1cblxuICAvKiogQXBwZW5kcyBhIHNpbmdsZSBtZXNzYWdlIHdpdGhvdXQgcmVidWlsZGluZyB0aGUgRE9NIChPKDEpKSAqL1xuICBwcml2YXRlIF9hcHBlbmRNZXNzYWdlKG1zZzogQ2hhdE1lc3NhZ2UpOiB2b2lkIHtcbiAgICAvLyBSZW1vdmUgZW1wdHktc3RhdGUgcGxhY2Vob2xkZXIgaWYgcHJlc2VudFxuICAgIHRoaXMubWVzc2FnZXNFbC5xdWVyeVNlbGVjdG9yKCcub2NsYXctcGxhY2Vob2xkZXInKT8ucmVtb3ZlKCk7XG5cbiAgICBjb25zdCBlbCA9IHRoaXMubWVzc2FnZXNFbC5jcmVhdGVEaXYoeyBjbHM6IGBvY2xhdy1tZXNzYWdlICR7bXNnLnJvbGV9YCB9KTtcbiAgICBlbC5jcmVhdGVTcGFuKHsgdGV4dDogbXNnLmNvbnRlbnQgfSk7XG5cbiAgICAvLyBTY3JvbGwgdG8gYm90dG9tXG4gICAgdGhpcy5tZXNzYWdlc0VsLnNjcm9sbFRvcCA9IHRoaXMubWVzc2FnZXNFbC5zY3JvbGxIZWlnaHQ7XG4gIH1cblxuICAvLyBcdTI1MDBcdTI1MDAgU2VuZCBoYW5kbGVyIFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFx1MjUwMFxuXG4gIHByaXZhdGUgYXN5bmMgX2hhbmRsZVNlbmQoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgY29uc3QgdGV4dCA9IHRoaXMuaW5wdXRFbC52YWx1ZS50cmltKCk7XG4gICAgaWYgKCF0ZXh0KSByZXR1cm47XG5cbiAgICAvLyBCdWlsZCBtZXNzYWdlIHdpdGggY29udGV4dCBpZiBlbmFibGVkXG4gICAgbGV0IG1lc3NhZ2UgPSB0ZXh0O1xuICAgIGlmICh0aGlzLmluY2x1ZGVOb3RlQ2hlY2tib3guY2hlY2tlZCkge1xuICAgICAgY29uc3Qgbm90ZSA9IGF3YWl0IGdldEFjdGl2ZU5vdGVDb250ZXh0KHRoaXMuYXBwKTtcbiAgICAgIGlmIChub3RlKSB7XG4gICAgICAgIG1lc3NhZ2UgPSBgQ29udGV4dDogW1ske25vdGUudGl0bGV9XV1cXG5cXG4ke3RleHR9YDtcbiAgICAgIH1cbiAgICB9XG5cbiAgICAvLyBBZGQgdXNlciBtZXNzYWdlIHRvIGNoYXQgVUlcbiAgICBjb25zdCB1c2VyTXNnID0gQ2hhdE1hbmFnZXIuY3JlYXRlVXNlck1lc3NhZ2UodGV4dCk7XG4gICAgdGhpcy5jaGF0TWFuYWdlci5hZGRNZXNzYWdlKHVzZXJNc2cpO1xuXG4gICAgLy8gQ2xlYXIgaW5wdXRcbiAgICB0aGlzLmlucHV0RWwudmFsdWUgPSAnJztcbiAgICB0aGlzLmlucHV0RWwuc3R5bGUuaGVpZ2h0ID0gJ2F1dG8nO1xuXG4gICAgLy8gU2VuZCBvdmVyIFdTIChhc3luYylcbiAgICB0cnkge1xuICAgICAgYXdhaXQgdGhpcy5wbHVnaW4ud3NDbGllbnQuc2VuZE1lc3NhZ2UobWVzc2FnZSk7XG4gICAgfSBjYXRjaCAoZXJyKSB7XG4gICAgICBjb25zb2xlLmVycm9yKCdbb2NsYXddIFNlbmQgZmFpbGVkJywgZXJyKTtcbiAgICAgIHRoaXMuY2hhdE1hbmFnZXIuYWRkTWVzc2FnZShcbiAgICAgICAgQ2hhdE1hbmFnZXIuY3JlYXRlU3lzdGVtTWVzc2FnZShgXHUyNkEwIFNlbmQgZmFpbGVkOiAke2Vycn1gKVxuICAgICAgKTtcbiAgICB9XG4gIH1cbn1cbiIsICJpbXBvcnQgdHlwZSB7IEFwcCB9IGZyb20gJ29ic2lkaWFuJztcblxuZXhwb3J0IGludGVyZmFjZSBOb3RlQ29udGV4dCB7XG4gIHRpdGxlOiBzdHJpbmc7XG4gIHBhdGg6IHN0cmluZztcbiAgY29udGVudDogc3RyaW5nO1xufVxuXG4vKipcbiAqIFJldHVybnMgdGhlIGFjdGl2ZSBub3RlJ3MgdGl0bGUgYW5kIGNvbnRlbnQsIG9yIG51bGwgaWYgbm8gbm90ZSBpcyBvcGVuLlxuICogQXN5bmMgYmVjYXVzZSB2YXVsdC5yZWFkKCkgaXMgYXN5bmMuXG4gKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBnZXRBY3RpdmVOb3RlQ29udGV4dChhcHA6IEFwcCk6IFByb21pc2U8Tm90ZUNvbnRleHQgfCBudWxsPiB7XG4gIGNvbnN0IGZpbGUgPSBhcHAud29ya3NwYWNlLmdldEFjdGl2ZUZpbGUoKTtcbiAgaWYgKCFmaWxlKSByZXR1cm4gbnVsbDtcblxuICB0cnkge1xuICAgIGNvbnN0IGNvbnRlbnQgPSBhd2FpdCBhcHAudmF1bHQucmVhZChmaWxlKTtcbiAgICByZXR1cm4ge1xuICAgICAgdGl0bGU6IGZpbGUuYmFzZW5hbWUsXG4gICAgICBwYXRoOiBmaWxlLnBhdGgsXG4gICAgICBjb250ZW50LFxuICAgIH07XG4gIH0gY2F0Y2ggKGVycikge1xuICAgIGNvbnNvbGUuZXJyb3IoJ1tvY2xhdy1jb250ZXh0XSBGYWlsZWQgdG8gcmVhZCBhY3RpdmUgbm90ZScsIGVycik7XG4gICAgcmV0dXJuIG51bGw7XG4gIH1cbn1cbiIsICIvKiogUGVyc2lzdGVkIHBsdWdpbiBjb25maWd1cmF0aW9uICovXG5leHBvcnQgaW50ZXJmYWNlIE9wZW5DbGF3U2V0dGluZ3Mge1xuICAvKiogV2ViU29ja2V0IFVSTCBvZiB0aGUgT3BlbkNsYXcgR2F0ZXdheSAoZS5nLiB3czovLzEwMC45MC45LjY4OjE4Nzg5KSAqL1xuICBnYXRld2F5VXJsOiBzdHJpbmc7XG4gIC8qKiBBdXRoIHRva2VuIFx1MjAxNCBtdXN0IG1hdGNoIHRoZSBjaGFubmVsIHBsdWdpbidzIGF1dGhUb2tlbiAqL1xuICBhdXRoVG9rZW46IHN0cmluZztcbiAgLyoqIE9wZW5DbGF3IHNlc3Npb24ga2V5IHRvIHN1YnNjcmliZSB0byAoZS5nLiBcIm1haW5cIikgKi9cbiAgc2Vzc2lvbktleTogc3RyaW5nO1xuICAvKiogT3BlbkNsYXcgYWNjb3VudCBJRCAodXN1YWxseSBcIm1haW5cIikgKi9cbiAgYWNjb3VudElkOiBzdHJpbmc7XG4gIC8qKiBXaGV0aGVyIHRvIGluY2x1ZGUgdGhlIGFjdGl2ZSBub3RlIGNvbnRlbnQgd2l0aCBlYWNoIG1lc3NhZ2UgKi9cbiAgaW5jbHVkZUFjdGl2ZU5vdGU6IGJvb2xlYW47XG59XG5cbmV4cG9ydCBjb25zdCBERUZBVUxUX1NFVFRJTkdTOiBPcGVuQ2xhd1NldHRpbmdzID0ge1xuICBnYXRld2F5VXJsOiAnd3M6Ly9sb2NhbGhvc3Q6MTg3ODknLFxuICBhdXRoVG9rZW46ICcnLFxuICBzZXNzaW9uS2V5OiAnbWFpbicsXG4gIGFjY291bnRJZDogJ21haW4nLFxuICBpbmNsdWRlQWN0aXZlTm90ZTogZmFsc2UsXG59O1xuXG4vKiogQSBzaW5nbGUgY2hhdCBtZXNzYWdlICovXG5leHBvcnQgaW50ZXJmYWNlIENoYXRNZXNzYWdlIHtcbiAgaWQ6IHN0cmluZztcbiAgcm9sZTogJ3VzZXInIHwgJ2Fzc2lzdGFudCcgfCAnc3lzdGVtJztcbiAgY29udGVudDogc3RyaW5nO1xuICB0aW1lc3RhbXA6IG51bWJlcjtcbn1cblxuLyoqIFBheWxvYWQgZm9yIG1lc3NhZ2VzIFNFTlQgdG8gdGhlIHNlcnZlciAob3V0Ym91bmQpICovXG5leHBvcnQgaW50ZXJmYWNlIFdTUGF5bG9hZCB7XG4gIHR5cGU6ICdhdXRoJyB8ICdtZXNzYWdlJyB8ICdwaW5nJyB8ICdwb25nJyB8ICdlcnJvcic7XG4gIHBheWxvYWQ/OiBSZWNvcmQ8c3RyaW5nLCB1bmtub3duPjtcbn1cblxuLyoqIE1lc3NhZ2VzIFJFQ0VJVkVEIGZyb20gdGhlIHNlcnZlciAoaW5ib3VuZCkgXHUyMDE0IGRpc2NyaW1pbmF0ZWQgdW5pb24gKi9cbmV4cG9ydCB0eXBlIEluYm91bmRXU1BheWxvYWQgPVxuICB8IHsgdHlwZTogJ21lc3NhZ2UnOyBwYXlsb2FkOiB7IGNvbnRlbnQ6IHN0cmluZzsgcm9sZTogc3RyaW5nOyB0aW1lc3RhbXA6IG51bWJlciB9IH1cbiAgfCB7IHR5cGU6ICdlcnJvcic7IHBheWxvYWQ6IHsgbWVzc2FnZTogc3RyaW5nIH0gfTtcblxuLyoqIEF2YWlsYWJsZSBhZ2VudHMgLyBtb2RlbHMgKi9cbmV4cG9ydCBpbnRlcmZhY2UgQWdlbnRPcHRpb24ge1xuICBpZDogc3RyaW5nO1xuICBsYWJlbDogc3RyaW5nO1xufVxuIl0sCiAgIm1hcHBpbmdzIjogIjs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQSxJQUFBQSxtQkFBOEM7OztBQ0E5QyxzQkFBK0M7QUFHeEMsSUFBTSxxQkFBTixjQUFpQyxpQ0FBaUI7QUFBQSxFQUd2RCxZQUFZLEtBQVUsUUFBd0I7QUFDNUMsVUFBTSxLQUFLLE1BQU07QUFDakIsU0FBSyxTQUFTO0FBQUEsRUFDaEI7QUFBQSxFQUVBLFVBQWdCO0FBQ2QsVUFBTSxFQUFFLFlBQVksSUFBSTtBQUN4QixnQkFBWSxNQUFNO0FBRWxCLGdCQUFZLFNBQVMsTUFBTSxFQUFFLE1BQU0sZ0NBQTJCLENBQUM7QUFFL0QsUUFBSSx3QkFBUSxXQUFXLEVBQ3BCLFFBQVEsYUFBYSxFQUNyQixRQUFRLG1FQUFtRSxFQUMzRTtBQUFBLE1BQVEsQ0FBQyxTQUNSLEtBQ0csZUFBZSxzQkFBc0IsRUFDckMsU0FBUyxLQUFLLE9BQU8sU0FB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QSxDQUFDLFNBQXdCLElBQUksaUJBQWlCLE1BQU0sSUFBSTtBQUFBLE1BQzFEO0FBR0EsV0FBSyxjQUFjLGtCQUFrQixpQkFBaUIsTUFBTTtBQUMxRCxhQUFLLGtCQUFrQjtBQUFBLE1BQ3pCLENBQUM7QUFHRCxXQUFLLGNBQWMsSUFBSSxtQkFBbUIsS0FBSyxLQUFLLElBQUksQ0FBQztBQUd6RCxXQUFLLFdBQVc7QUFBQSxRQUNkLElBQUk7QUFBQSxRQUNKLE1BQU07QUFBQSxRQUNOLFVBQVUsTUFBTSxLQUFLLGtCQUFrQjtBQUFBLE1BQ3pDLENBQUM7QUFHRCxVQUFJLEtBQUssU0FBUyxXQUFXO0FBQzNCLGFBQUssV0FBVztBQUFBLE1BQ2xCLE9BQU87QUFDTCxZQUFJLHdCQUFPLGlFQUFpRTtBQUFBLE1BQzlFO0FBRUEsY0FBUSxJQUFJLHVCQUF1QjtBQUFBLElBQ3JDO0FBQUE7QUFBQSxFQUVNLFdBQTBCO0FBQUE7QUFDOUIsV0FBSyxTQUFTLFdBQVc7QUFDekIsV0FBSyxJQUFJLFVBQVUsbUJBQW1CLHVCQUF1QjtBQUM3RCxjQUFRLElBQUkseUJBQXlCO0FBQUEsSUFDdkM7QUFBQTtBQUFBLEVBRU0sZUFBOEI7QUFBQTtBQUNsQyxXQUFLLFdBQVcsT0FBTyxPQUFPLENBQUMsR0FBRyxrQkFBa0IsTUFBTSxLQUFLLFNBQVMsQ0FBQztBQUFBLElBQzNFO0FBQUE7QUFBQSxFQUVNLGVBQThCO0FBQUE7QUFDbEMsWUFBTSxLQUFLLFNBQVMsS0FBSyxRQUFRO0FBQUEsSUFDbkM7QUFBQTtBQUFBO0FBQUEsRUFJUSxhQUFtQjtBQUN6QixTQUFLLFNBQVM7QUFBQSxNQUNaLEtBQUssU0FBUztBQUFBLE1BQ2QsS0FBSyxTQUFTO0FBQUEsSUFDaEI7QUFBQSxFQUNGO0FBQUEsRUFFYyxvQkFBbUM7QUFBQTtBQUMvQyxZQUFNLEVBQUUsVUFBVSxJQUFJLEtBQUs7QUFHM0IsWUFBTSxXQUFXLFVBQVUsZ0JBQWdCLHVCQUF1QjtBQUNsRSxVQUFJLFNBQVMsU0FBUyxHQUFHO0FBQ3ZCLGtCQUFVLFdBQVcsU0FBUyxDQUFDLENBQUM7QUFDaEM7QUFBQSxNQUNGO0FBR0EsWUFBTSxPQUFPLFVBQVUsYUFBYSxLQUFLO0FBQ3pDLFVBQUksQ0FBQztBQUFNO0FBQ1gsWUFBTSxLQUFLLGFBQWEsRUFBRSxNQUFNLHlCQUF5QixRQUFRLEtBQUssQ0FBQztBQUN2RSxnQkFBVSxXQUFXLElBQUk7QUFBQSxJQUMzQjtBQUFBO0FBQ0Y7IiwKICAibmFtZXMiOiBbImltcG9ydF9vYnNpZGlhbiIsICJpbXBvcnRfb2JzaWRpYW4iLCAiY29ubmVjdGVkIl0KfQo=
