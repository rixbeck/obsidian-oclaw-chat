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

    containerEl.createEl('p', {
      text: 'Reconnect: close and reopen the sidebar after changing the gateway URL or token.',
      cls: 'setting-item-description',
    });
  }
}
