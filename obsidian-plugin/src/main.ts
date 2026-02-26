import { FileSystemAdapter, Notice, Plugin, WorkspaceLeaf } from 'obsidian';
import { OpenClawSettingTab } from './settings';
import { ObsidianWSClient } from './websocket';
import { ChatManager } from './chat';
import { VIEW_TYPE_OPENCLAW_CHAT, OpenClawChatView } from './view';
import { DEFAULT_SETTINGS, type OpenClawSettings } from './types';

export default class OpenClawPlugin extends Plugin {
  settings!: OpenClawSettings;
  wsClient!: ObsidianWSClient;
  chatManager!: ChatManager;

  private _vaultHash: string | null = null;

  private _computeVaultHash(): string | null {
    try {
      const adapter = this.app.vault.adapter;
      // Desktop only: FileSystemAdapter provides a stable base path.
      if (adapter instanceof FileSystemAdapter) {
        const basePath = adapter.getBasePath();
        if (basePath) {
          // Use Node crypto (Electron environment).
          // eslint-disable-next-line @typescript-eslint/no-var-requires
          const crypto = require('crypto') as typeof import('crypto');
          const hex = crypto.createHash('sha256').update(basePath, 'utf8').digest('hex');
          return hex.slice(0, 16);
        }
      }
    } catch {
      // ignore
    }
    return null;
  }

  private _canonicalVaultSessionKey(vaultHash: string): string {
    return `agent:main:obsidian:direct:${vaultHash}`;
  }

  async switchSession(sessionKey: string): Promise<void> {
    const next = sessionKey.trim().toLowerCase();
    if (!next) {
      new Notice('OpenClaw Chat: session key cannot be empty.');
      return;
    }

    // Safety: only allow main or canonical obsidian direct sessions.
    if (!(next === 'main' || next.startsWith('agent:main:obsidian:direct:'))) {
      new Notice('OpenClaw Chat: only main or agent:main:obsidian:direct:* sessions are allowed.');
      return;
    }

    // Abort any in-flight run best-effort (avoid leaking a "working" UI state).
    try {
      await this.wsClient.abortActiveRun();
    } catch {
      // ignore
    }

    // Insert divider at the start of the new session.
    this.chatManager.addMessage(ChatManager.createSessionDivider(next));

    this.settings.sessionKey = next;

    // Track known sessions per vault (vault-scoped).
    if (this._vaultHash) {
      const map = this.settings.knownSessionKeysByVault ?? {};
      const cur = Array.isArray(map[this._vaultHash]) ? map[this._vaultHash] : [];
      const nextList = [next, ...cur.filter((k) => k && k !== next)].slice(0, 20);
      map[this._vaultHash] = nextList;
      this.settings.knownSessionKeysByVault = map;
    }

    await this.saveSettings();

    // Reconnect with the new session key.
    this.wsClient.disconnect();
    this.wsClient.setSessionKey(next);

    if (this.settings.authToken) {
      this.wsClient.connect(this.settings.gatewayUrl, this.settings.authToken, {
        allowInsecureWs: this.settings.allowInsecureWs,
      });
    }
  }

  async onload(): Promise<void> {
    await this.loadSettings();

    // Compute vault hash (desktop) and migrate to canonical obsidian direct session key.
    this._vaultHash = this._computeVaultHash();
    if (this._vaultHash) {
      this.settings.vaultHash = this._vaultHash;

      const canonical = this._canonicalVaultSessionKey(this._vaultHash);
      const existing = (this.settings.sessionKey ?? '').trim().toLowerCase();
      const isLegacy = existing.startsWith('obsidian-');
      const isEmptyOrMain = !existing || existing === 'main' || existing === 'agent:main:main';

      // Remember legacy keys for debugging/migration, but default to canonical.
      if (isLegacy) {
        const legacy = Array.isArray(this.settings.legacySessionKeys) ? this.settings.legacySessionKeys : [];
        this.settings.legacySessionKeys = [existing, ...legacy.filter((k) => k && k !== existing)].slice(0, 20);
      }

      if (isLegacy || isEmptyOrMain) {
        this.settings.sessionKey = canonical;
      }

      const map = this.settings.knownSessionKeysByVault ?? {};
      const cur = Array.isArray(map[this._vaultHash]) ? map[this._vaultHash] : [];
      if (!cur.includes(canonical)) {
        map[this._vaultHash] = [canonical, ...cur].slice(0, 20);
        this.settings.knownSessionKeysByVault = map;
      }

      await this.saveSettings();
    }

    this.wsClient = new ObsidianWSClient((this.settings.sessionKey ?? 'main').toLowerCase(), {
      identityStore: {
        get: async () => (await this._loadDeviceIdentity()),
        set: async (identity) => await this._saveDeviceIdentity(identity),
        clear: async () => await this._clearDeviceIdentity(),
      },
    });
    this.chatManager = new ChatManager();

    // Wire incoming WS messages → ChatManager
    this.wsClient.onMessage = (msg) => {
      if (msg.type === 'message') {
        this.chatManager.addMessage(ChatManager.createAssistantMessage(msg.payload.content));
      } else if (msg.type === 'error') {
        const errText = msg.payload.message ?? 'Unknown error from gateway';
        this.chatManager.addMessage(ChatManager.createSystemMessage(`⚠ ${errText}`, 'error'));
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
    const data = (await this.loadData()) ?? {};
    // NOTE: plugin data may contain extra private fields (e.g. device identity). Settings are the public subset.
    this.settings = Object.assign({}, DEFAULT_SETTINGS, data);
  }

  async saveSettings(): Promise<void> {
    // Preserve any private fields stored in plugin data.
    const data = (await this.loadData()) ?? {};
    await this.saveData({ ...data, ...this.settings });
  }

  // ── Device identity persistence (plugin-scoped; NOT localStorage) ─────────

  async resetDeviceIdentity(): Promise<void> {
    await this._clearDeviceIdentity();
    new Notice('OpenClaw Chat: device identity reset. Reconnect to pair again.');
  }

  private _deviceIdentityKey = '_openclawDeviceIdentityV1';

  private async _loadDeviceIdentity(): Promise<any | null> {
    const data = (await this.loadData()) ?? {};
    return (data as any)?.[this._deviceIdentityKey] ?? null;
  }

  private async _saveDeviceIdentity(identity: any): Promise<void> {
    const data = (await this.loadData()) ?? {};
    await this.saveData({ ...data, [this._deviceIdentityKey]: identity });
  }

  private async _clearDeviceIdentity(): Promise<void> {
    const data = (await this.loadData()) ?? {};
    if ((data as any)?.[this._deviceIdentityKey] === undefined) return;
    const next = { ...(data as any) };
    delete next[this._deviceIdentityKey];
    await this.saveData(next);
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  private _connectWS(): void {
    this.wsClient.connect(this.settings.gatewayUrl, this.settings.authToken, {
      allowInsecureWs: this.settings.allowInsecureWs,
    });
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
