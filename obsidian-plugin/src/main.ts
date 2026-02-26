import { FileSystemAdapter, Notice, Plugin, WorkspaceLeaf } from 'obsidian';
import { OpenClawSettingTab } from './settings';
import { ObsidianWSClient } from './websocket';
import { VIEW_TYPE_OPENCLAW_CHAT, OpenClawChatView } from './view';
import { DEFAULT_SETTINGS, type OpenClawSettings } from './types';
import { migrateSettingsForVault } from './session';

export default class OpenClawPlugin extends Plugin {
  settings!: OpenClawSettings;

  // NOTE: wsClient/chatManager are per-leaf (per view) to allow parallel sessions.
  private openChatLeaves = 0;
  private lastLeafWarnAtMs = 0;
  private static MAX_CHAT_LEAVES = 3;

  registerChatLeaf(): void {
    this.openChatLeaves += 1;
    const now = Date.now();
    if (this.openChatLeaves > OpenClawPlugin.MAX_CHAT_LEAVES && now - this.lastLeafWarnAtMs > 60_000) {
      this.lastLeafWarnAtMs = now;
      new Notice(
        `OpenClaw Chat: ${this.openChatLeaves} chat views are open. This may increase gateway load.`
      );
    }
  }

  unregisterChatLeaf(): void {
    this.openChatLeaves = Math.max(0, this.openChatLeaves - 1);
  }

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

  // canonical session key helpers live in src/session.ts

  getVaultHash(): string | null {
    return this._vaultHash;
  }

  getDefaultSessionKey(): string {
    return (this.settings.sessionKey ?? 'main').trim().toLowerCase();
  }

  getGatewayConfig(): { url: string; token: string; allowInsecureWs: boolean } {
    return {
      url: String(this.settings.gatewayUrl || ''),
      token: String(this.settings.authToken || ''),
      allowInsecureWs: Boolean(this.settings.allowInsecureWs),
    };
  }

  /** Persist + remember an Obsidian session key for the current vault. */
  async rememberSessionKey(sessionKey: string): Promise<void> {
    const next = sessionKey.trim().toLowerCase();
    if (!next) return;

    // SEC: allow only vault-scoped keys (when vaultHash known) or main.
    const vaultHash = this._vaultHash;
    if (vaultHash) {
      const prefix = `agent:main:obsidian:direct:${vaultHash}`;
      if (!(next === 'main' || next === prefix || next.startsWith(prefix + '-'))) {
        return;
      }
    } else {
      // Without a vault identity, only allow main.
      if (next !== 'main') return;
    }

    this.settings.sessionKey = next;

    if (this._vaultHash) {
      const map = this.settings.knownSessionKeysByVault ?? {};
      const cur = Array.isArray(map[this._vaultHash]) ? map[this._vaultHash] : [];
      const nextList = [next, ...cur.filter((k) => k && k !== next)].slice(0, 20);
      map[this._vaultHash] = nextList;
      this.settings.knownSessionKeysByVault = map;
    }

    await this.saveSettings();
  }

  createWsClient(sessionKey: string): ObsidianWSClient {
    return new ObsidianWSClient(sessionKey.trim().toLowerCase(), {
      identityStore: {
        get: async () => (await this._loadDeviceIdentity()),
        set: async (identity) => await this._saveDeviceIdentity(identity),
        clear: async () => await this._clearDeviceIdentity(),
      },
    });
  }

  async onload(): Promise<void> {
    await this.loadSettings();

    // Compute vault hash (desktop) and migrate to canonical obsidian direct session key.
    this._vaultHash = this._computeVaultHash();
    if (this._vaultHash) {
      this.settings.vaultHash = this._vaultHash;

      const migrated = migrateSettingsForVault(this.settings, this._vaultHash);
      this.settings = migrated.nextSettings;
      await this.saveSettings();
    } else {
      // Keep working, but New-session creation may be unavailable.
      new Notice('OpenClaw Chat: could not determine vault identity (vaultHash).');
    }

    // Register the sidebar view
    this.registerView(VIEW_TYPE_OPENCLAW_CHAT, (leaf: WorkspaceLeaf) => new OpenClawChatView(leaf, this));

    // Ribbon icon — opens / reveals the chat sidebar
    this.addRibbonIcon('message-square', 'OpenClaw Chat', () => {
      void this._activateChatView();
    });

    // Settings tab
    this.addSettingTab(new OpenClawSettingTab(this.app, this));

    // Command palette entry
    this.addCommand({
      id: 'open-openclaw-chat',
      name: 'Open chat sidebar',
      callback: () => void this._activateChatView(),
    });

    console.log('[oclaw] Plugin loaded');
  }

  async onunload(): Promise<void> {
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
