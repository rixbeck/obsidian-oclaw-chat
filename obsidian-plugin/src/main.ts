import { Notice, Plugin, WorkspaceLeaf } from 'obsidian';
import { OpenClawSettingTab } from './settings';
import { ObsidianWSClient } from './websocket';
import { ChatManager } from './chat';
import { VIEW_TYPE_OPENCLAW_CHAT, OpenClawChatView } from './view';
import { DEFAULT_SETTINGS, type OpenClawSettings } from './types';

export default class OpenClawPlugin extends Plugin {
  settings!: OpenClawSettings;
  wsClient!: ObsidianWSClient;
  chatManager!: ChatManager;

  async onload(): Promise<void> {
    await this.loadSettings();

    this.wsClient = new ObsidianWSClient(this.settings.sessionKey);
    this.chatManager = new ChatManager();

    // Wire incoming WS messages → ChatManager
    this.wsClient.onMessage = (msg) => {
      if (msg.type === 'message') {
        this.chatManager.addMessage(ChatManager.createAssistantMessage(msg.payload.content));
      } else if (msg.type === 'error') {
        const errText = msg.payload.message ?? 'Unknown error from gateway';
        this.chatManager.addMessage(ChatManager.createSystemMessage(`⚠ ${errText}`));
      }
    };

    // Register the sidebar view
    this.registerView(
      VIEW_TYPE_OPENCLAW_CHAT,
      (leaf: WorkspaceLeaf) => new OpenClawChatView(leaf, this)
    );

    // Ribbon icon — opens / reveals the chat sidebar
    this.addRibbonIcon('message-square', 'OpenClaw Chat', () => {
      this._activateChatView();
    });

    // Settings tab
    this.addSettingTab(new OpenClawSettingTab(this.app, this));

    // Command palette entry
    this.addCommand({
      id: 'open-openclaw-chat',
      name: 'Open chat sidebar',
      callback: () => this._activateChatView(),
    });

    // Connect to gateway if token is configured
    if (this.settings.authToken) {
      this._connectWS();
    } else {
      new Notice('OpenClaw Chat: please configure your gateway token in Settings.');
    }

    console.log('[oclaw] Plugin loaded');
  }

  async onunload(): Promise<void> {
    this.wsClient.disconnect();
    this.app.workspace.detachLeavesOfType(VIEW_TYPE_OPENCLAW_CHAT);
    console.log('[oclaw] Plugin unloaded');
  }

  async loadSettings(): Promise<void> {
    this.settings = Object.assign({}, DEFAULT_SETTINGS, await this.loadData());
  }

  async saveSettings(): Promise<void> {
    await this.saveData(this.settings);
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  private _connectWS(): void {
    this.wsClient.connect(
      this.settings.gatewayUrl,
      this.settings.authToken
    );
  }

  private async _activateChatView(): Promise<void> {
    const { workspace } = this.app;

    // Reuse existing leaf if already open
    const existing = workspace.getLeavesOfType(VIEW_TYPE_OPENCLAW_CHAT);
    if (existing.length > 0) {
      workspace.revealLeaf(existing[0]);
      return;
    }

    // Open in right sidebar
    const leaf = workspace.getRightLeaf(false);
    if (!leaf) return;
    await leaf.setViewState({ type: VIEW_TYPE_OPENCLAW_CHAT, active: true });
    workspace.revealLeaf(leaf);
  }
}
