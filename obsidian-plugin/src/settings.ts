import { App, PluginSettingTab, Setting } from 'obsidian';
import type OpenClawPlugin from './main';

export class OpenClawSettingTab extends PluginSettingTab {
  plugin: OpenClawPlugin;

  constructor(app: App, plugin: OpenClawPlugin) {
    super(app, plugin);
    this.plugin = plugin;
  }

  display(): void {
    const { containerEl } = this;
    containerEl.empty();

    containerEl.createEl('h2', { text: 'OpenClaw Chat – Settings' });

    new Setting(containerEl)
      .setName('Gateway URL')
      .setDesc('WebSocket URL of the OpenClaw Gateway (e.g. ws://hostname:18789).')
      .addText((text) =>
        text
          .setPlaceholder('ws://localhost:18789')
          .setValue(this.plugin.settings.gatewayUrl)
          .onChange(async (value) => {
            this.plugin.settings.gatewayUrl = value.trim();
            await this.plugin.saveSettings();
          })
      );

    new Setting(containerEl)
      .setName('Auth token')
      .setDesc('Must match the authToken in your openclaw.json channel config. Never shared.')
      .addText((text) => {
        text
          .setPlaceholder('Enter token…')
          .setValue(this.plugin.settings.authToken)
          .onChange(async (value) => {
            this.plugin.settings.authToken = value;
            await this.plugin.saveSettings();
          });
        // Treat as password field – do not reveal token in UI
        text.inputEl.type = 'password';
        text.inputEl.autocomplete = 'off';
      });

    new Setting(containerEl)
      .setName('Session Key')
      .setDesc('OpenClaw session to subscribe to (usually "main").')
      .addText((text) =>
        text
          .setPlaceholder('main')
          .setValue(this.plugin.settings.sessionKey)
          .onChange(async (value) => {
            this.plugin.settings.sessionKey = value.trim() || 'main';
            await this.plugin.saveSettings();
          })
      );

    new Setting(containerEl)
      .setName('Account ID')
      .setDesc('OpenClaw account ID (usually "main").')
      .addText((text) =>
        text
          .setPlaceholder('main')
          .setValue(this.plugin.settings.accountId)
          .onChange(async (value) => {
            this.plugin.settings.accountId = value.trim() || 'main';
            await this.plugin.saveSettings();
          })
      );

    new Setting(containerEl)
      .setName('Include active note by default')
      .setDesc('Pre-check "Include active note" in the chat panel when it opens.')
      .addToggle((toggle) =>
        toggle.setValue(this.plugin.settings.includeActiveNote).onChange(async (value) => {
          this.plugin.settings.includeActiveNote = value;
          await this.plugin.saveSettings();
        })
      );

    new Setting(containerEl)
      .setName('Render assistant as Markdown (unsafe)')
      .setDesc(
        'OFF recommended. If enabled, assistant output is rendered as Obsidian Markdown which may trigger embeds and other plugins\' post-processors.'
      )
      .addToggle((toggle) =>
        toggle.setValue(this.plugin.settings.renderAssistantMarkdown).onChange(async (value) => {
          this.plugin.settings.renderAssistantMarkdown = value;
          await this.plugin.saveSettings();
        })
      );

    new Setting(containerEl)
      .setName('Allow insecure ws:// for non-local gateways (unsafe)')
      .setDesc(
        'OFF recommended. If enabled, you can connect to non-local gateways over ws://. This exposes your token and message content to network attackers; prefer wss://.'
      )
      .addToggle((toggle) =>
        toggle.setValue(this.plugin.settings.allowInsecureWs).onChange(async (value) => {
          this.plugin.settings.allowInsecureWs = value;
          await this.plugin.saveSettings();
        })
      );

    new Setting(containerEl)
      .setName('Reset device identity (re-pair)')
      .setDesc('Clears the stored device identity used for operator.write pairing. Use this if you suspect compromise or see "device identity mismatch".')
      .addButton((btn) =>
        btn.setButtonText('Reset').setWarning().onClick(async () => {
          await this.plugin.resetDeviceIdentity();
        })
      );

    // ── Path mappings ──
    containerEl.createEl('h3', { text: 'Path mappings (vault base → remote base)' });
    containerEl.createEl('p', {
      text: 'Used to convert assistant file references (remote FS paths or exported URLs) into clickable Obsidian links. First match wins. Only creates a link if the mapped vault file exists.',
      cls: 'setting-item-description',
    });

    const mappings = this.plugin.settings.pathMappings ?? [];

    const rerender = async () => {
      await this.plugin.saveSettings();
      this.display();
    };

    mappings.forEach((row, idx) => {
      const s = new Setting(containerEl)
        .setName(`Mapping #${idx + 1}`)
        .setDesc('vaultBase → remoteBase');

      s.addText((t) =>
        t
          .setPlaceholder('vault base (e.g. docs/)')
          .setValue(row.vaultBase ?? '')
          .onChange(async (v) => {
            this.plugin.settings.pathMappings[idx].vaultBase = v;
            await this.plugin.saveSettings();
          })
      );

      s.addText((t) =>
        t
          .setPlaceholder('remote base (e.g. /home/.../docs/)')
          .setValue(row.remoteBase ?? '')
          .onChange(async (v) => {
            this.plugin.settings.pathMappings[idx].remoteBase = v;
            await this.plugin.saveSettings();
          })
      );

      s.addExtraButton((b) =>
        b
          .setIcon('trash')
          .setTooltip('Remove mapping')
          .onClick(async () => {
            this.plugin.settings.pathMappings.splice(idx, 1);
            await rerender();
          })
      );
    });

    new Setting(containerEl)
      .setName('Add mapping')
      .setDesc('Add a new vaultBase → remoteBase mapping row.')
      .addButton((btn) =>
        btn.setButtonText('Add').onClick(async () => {
          this.plugin.settings.pathMappings.push({ vaultBase: '', remoteBase: '' });
          await rerender();
        })
      );

    containerEl.createEl('p', {
      text: 'Reconnect: close and reopen the sidebar after changing the gateway URL or token.',
      cls: 'setting-item-description',
    });
  }
}
