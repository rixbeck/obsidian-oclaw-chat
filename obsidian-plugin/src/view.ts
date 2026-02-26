import { ItemView, MarkdownRenderer, Notice, WorkspaceLeaf } from 'obsidian';
import type OpenClawPlugin from './main';
import { ChatManager } from './chat';
import type { ChatMessage, PathMapping } from './types';
import { extractCandidates, tryMapRemotePathToVaultPath } from './linkify';
import { getActiveNoteContext } from './context';

export const VIEW_TYPE_OPENCLAW_CHAT = 'openclaw-chat';

export class OpenClawChatView extends ItemView {
  private plugin: OpenClawPlugin;
  private chatManager: ChatManager;

  // State
  private isConnected = false;
  private isWorking = false;

  // Connection notices (avoid spam)
  private lastConnNoticeAtMs = 0;
  private lastGatewayState: string | null = null;

  // DOM refs
  private messagesEl!: HTMLElement;
  private inputEl!: HTMLTextAreaElement;
  private sendBtn!: HTMLButtonElement;
  private includeNoteCheckbox!: HTMLInputElement;
  private statusDot!: HTMLElement;

  constructor(leaf: WorkspaceLeaf, plugin: OpenClawPlugin) {
    super(leaf);
    this.plugin = plugin;
    this.chatManager = plugin.chatManager;
  }

  getViewType(): string {
    return VIEW_TYPE_OPENCLAW_CHAT;
  }

  getDisplayText(): string {
    return 'OpenClaw Chat';
  }

  getIcon(): string {
    return 'message-square';
  }

  async onOpen(): Promise<void> {
    this._buildUI();

    // Full re-render on clear / reload
    this.chatManager.onUpdate = (msgs) => this._renderMessages(msgs);
    // O(1) append for new messages
    this.chatManager.onMessageAdded = (msg) => this._appendMessage(msg);

    // Subscribe to WS state changes
    this.plugin.wsClient.onStateChange = (state) => {
      // Connection loss / reconnect notices (throttled)
      const prev = this.lastGatewayState;
      this.lastGatewayState = state;

      const now = Date.now();
      const NOTICE_THROTTLE_MS = 60_000;

      const shouldNotify = () => now - this.lastConnNoticeAtMs > NOTICE_THROTTLE_MS;
      const notify = (text: string) => {
        if (!shouldNotify()) return;
        this.lastConnNoticeAtMs = now;
        new Notice(text);
      };

      // Only show “lost” if we were previously connected.
      if (prev === 'connected' && state === 'disconnected') {
        notify('OpenClaw Chat: connection lost — reconnecting…');
        // Also append a system message so it’s visible in the chat history.
        this.chatManager.addMessage(ChatManager.createSystemMessage('⚠ Connection lost — reconnecting…', 'error'));
      }

      // Optional “reconnected” notice
      if (prev && prev !== 'connected' && state === 'connected') {
        notify('OpenClaw Chat: reconnected');
        this.chatManager.addMessage(ChatManager.createSystemMessage('✅ Reconnected', 'info'));
      }

      this.isConnected = state === 'connected';
      this.statusDot.toggleClass('connected', this.isConnected);
      this.statusDot.title = `Gateway: ${state}`;
      this._updateSendButton();
    };

    // Subscribe to “working” (request-in-flight) state
    this.plugin.wsClient.onWorkingChange = (working) => {
      this.isWorking = working;
      this._updateSendButton();
    };

    // Reflect current state
    this.lastGatewayState = this.plugin.wsClient.state;
    this.isConnected = this.plugin.wsClient.state === 'connected';
    this.statusDot.toggleClass('connected', this.isConnected);
    this.statusDot.title = `Gateway: ${this.plugin.wsClient.state}`;
    this._updateSendButton();

    this._renderMessages(this.chatManager.getMessages());
  }

  async onClose(): Promise<void> {
    this.chatManager.onUpdate = null;
    this.chatManager.onMessageAdded = null;
    this.plugin.wsClient.onStateChange = null;
    this.plugin.wsClient.onWorkingChange = null;
  }

  // ── UI construction ───────────────────────────────────────────────────────

  private _buildUI(): void {
    const root = this.contentEl;
    root.empty();
    root.addClass('oclaw-chat-view');

    // ── Header ──
    const header = root.createDiv({ cls: 'oclaw-header' });
    header.createSpan({ cls: 'oclaw-header-title', text: 'OpenClaw Chat' });
    this.statusDot = header.createDiv({ cls: 'oclaw-status-dot' });
    this.statusDot.title = 'Gateway: disconnected';

    // ── Messages area ──
    this.messagesEl = root.createDiv({ cls: 'oclaw-messages' });

    // ── Context row ──
    const ctxRow = root.createDiv({ cls: 'oclaw-context-row' });
    this.includeNoteCheckbox = ctxRow.createEl('input', { type: 'checkbox' });
    this.includeNoteCheckbox.id = 'oclaw-include-note';
    this.includeNoteCheckbox.checked = this.plugin.settings.includeActiveNote;
    const ctxLabel = ctxRow.createEl('label', { text: 'Include active note' });
    ctxLabel.htmlFor = 'oclaw-include-note';

    // ── Input row ──
    const inputRow = root.createDiv({ cls: 'oclaw-input-row' });
    this.inputEl = inputRow.createEl('textarea', {
      cls: 'oclaw-input',
      placeholder: 'Ask anything…',
    });
    this.inputEl.rows = 1;

    this.sendBtn = inputRow.createEl('button', { cls: 'oclaw-send-btn', text: 'Send' });

    // ── Event listeners ──
    this.sendBtn.addEventListener('click', () => this._handleSend());
    this.inputEl.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        this._handleSend();
      }
    });
    // Auto-resize textarea
    this.inputEl.addEventListener('input', () => {
      this.inputEl.style.height = 'auto';
      this.inputEl.style.height = `${this.inputEl.scrollHeight}px`;
    });
  }

  // ── Message rendering ─────────────────────────────────────────────────────

  private _renderMessages(messages: readonly ChatMessage[]): void {
    this.messagesEl.empty();

    if (messages.length === 0) {
      this.messagesEl.createEl('p', {
        text: 'Send a message to start chatting.',
        cls: 'oclaw-message system oclaw-placeholder',
      });
      return;
    }

    for (const msg of messages) {
      this._appendMessage(msg);
    }

    // Scroll to bottom
    this.messagesEl.scrollTop = this.messagesEl.scrollHeight;
  }

  /** Appends a single message without rebuilding the DOM (O(1)) */
  private _appendMessage(msg: ChatMessage): void {
    // Remove empty-state placeholder if present
    this.messagesEl.querySelector('.oclaw-placeholder')?.remove();

    const levelClass = msg.level ? ` ${msg.level}` : '';
    const el = this.messagesEl.createDiv({ cls: `oclaw-message ${msg.role}${levelClass}` });
    const body = el.createDiv({ cls: 'oclaw-message-body' });

    // Treat assistant output as UNTRUSTED by default.
    // Rendering as Obsidian Markdown can trigger embeds and other plugins' post-processors.
    if (msg.role === 'assistant') {
      const mappings: PathMapping[] = this.plugin.settings.pathMappings ?? [];
      const sourcePath = this.app.workspace.getActiveFile()?.path ?? '';

      if (this.plugin.settings.renderAssistantMarkdown) {
        // Best-effort pre-processing: replace known remote paths with wikilinks when the target exists.
        const pre = this._preprocessAssistantMarkdown(msg.content, mappings);
        void MarkdownRenderer.renderMarkdown(pre, body, sourcePath, this.plugin);
      } else {
        // Plain mode: build safe, clickable links in DOM (no Markdown rendering).
        this._renderAssistantPlainWithLinks(body, msg.content, mappings, sourcePath);
      }
    } else {
      body.setText(msg.content);
    }

    // Scroll to bottom
    this.messagesEl.scrollTop = this.messagesEl.scrollHeight;
  }

  private _tryReverseMapUrlToVaultPath(url: string, mappings: PathMapping[]): string | null {
    // FS-based mapping; best-effort only.
    let decoded = url;
    try {
      decoded = decodeURIComponent(url);
    } catch {
      // ignore
    }

    // If the decoded URL contains a remoteBase substring, try mapping from that point.
    for (const row of mappings) {
      const remoteBase = String(row.remoteBase ?? '');
      if (!remoteBase) continue;
      const idx = decoded.indexOf(remoteBase);
      if (idx < 0) continue;

      // Extract from remoteBase onward until a terminator.
      const tail = decoded.slice(idx);
      const token = tail.split(/[\s'"<>)]/)[0];
      const mapped = tryMapRemotePathToVaultPath(token, mappings);
      if (mapped && this.app.vault.getAbstractFileByPath(mapped)) return mapped;
    }

    return null;
  }

  private _tryMapVaultRelativeToken(token: string, mappings: PathMapping[]): string | null {
    const t = token.replace(/^\/+/, '');
    if (this.app.vault.getAbstractFileByPath(t)) return t;

    // Heuristic: if vaultBase ends with a segment (e.g. workspace/compeng/) and token starts with that segment (compeng/...),
    // map token under vaultBase.
    for (const row of mappings) {
      const vaultBaseRaw = String(row.vaultBase ?? '').trim();
      if (!vaultBaseRaw) continue;
      const vaultBase = vaultBaseRaw.endsWith('/') ? vaultBaseRaw : `${vaultBaseRaw}/`;

      const parts = vaultBase.replace(/\/+$/, '').split('/');
      const baseName = parts[parts.length - 1];
      if (!baseName) continue;

      const prefix = `${baseName}/`;
      if (!t.startsWith(prefix)) continue;

      const candidate = `${vaultBase}${t.slice(prefix.length)}`;
      const normalized = candidate.replace(/^\/+/, '');
      if (this.app.vault.getAbstractFileByPath(normalized)) return normalized;
    }

    return null;
  }

  private _preprocessAssistantMarkdown(text: string, mappings: PathMapping[]): string {
    const candidates = extractCandidates(text);
    if (candidates.length === 0) return text;

    let out = '';
    let cursor = 0;

    for (const c of candidates) {
      out += text.slice(cursor, c.start);
      cursor = c.end;

      if (c.kind === 'url') {
        // URLs remain URLs UNLESS we can safely map to an existing vault file.
        const mapped = this._tryReverseMapUrlToVaultPath(c.raw, mappings);
        out += mapped ? `[[${mapped}]]` : c.raw;
        continue;
      }

      // 1) If the token is already a vault-relative path (or can be resolved via vaultBase heuristic), linkify it directly.
      const direct = this._tryMapVaultRelativeToken(c.raw, mappings);
      if (direct) {
        out += `[[${direct}]]`;
        continue;
      }

      // 2) Else: try remote→vault mapping.
      const mapped = tryMapRemotePathToVaultPath(c.raw, mappings);
      if (!mapped) {
        out += c.raw;
        continue;
      }

      if (!this.app.vault.getAbstractFileByPath(mapped)) {
        out += c.raw;
        continue;
      }

      out += `[[${mapped}]]`;
    }

    out += text.slice(cursor);
    return out;
  }

  private _renderAssistantPlainWithLinks(
    body: HTMLElement,
    text: string,
    mappings: PathMapping[],
    sourcePath: string,
  ): void {
    const candidates = extractCandidates(text);
    if (candidates.length === 0) {
      body.setText(text);
      return;
    }

    let cursor = 0;

    const appendText = (s: string) => {
      if (!s) return;
      body.appendChild(document.createTextNode(s));
    };

    const appendObsidianLink = (vaultPath: string) => {
      const display = `[[${vaultPath}]]`;
      const a = body.createEl('a', { text: display, href: '#' });
      a.addEventListener('click', (ev) => {
        ev.preventDefault();
        ev.stopPropagation();
        void this.app.workspace.openLinkText(vaultPath, sourcePath, true);
      });
    };

    const appendExternalUrl = (url: string) => {
      // Let Obsidian/Electron handle external open.
      body.createEl('a', { text: url, href: url });
    };

    const tryReverseMapUrlToVaultPath = (url: string): string | null => this._tryReverseMapUrlToVaultPath(url, mappings);

    for (const c of candidates) {
      appendText(text.slice(cursor, c.start));
      cursor = c.end;

      if (c.kind === 'url') {
        const mapped = tryReverseMapUrlToVaultPath(c.raw);
        if (mapped) {
          appendObsidianLink(mapped);
        } else {
          appendExternalUrl(c.raw);
        }
        continue;
      }

      // 1) If token is already a vault-relative path (or can be resolved via vaultBase heuristic), linkify directly.
      const direct = this._tryMapVaultRelativeToken(c.raw, mappings);
      if (direct) {
        appendObsidianLink(direct);
        continue;
      }

      // 2) Else: try remote→vault mapping.
      const mapped = tryMapRemotePathToVaultPath(c.raw, mappings);
      if (!mapped) {
        appendText(c.raw);
        continue;
      }

      if (!this.app.vault.getAbstractFileByPath(mapped)) {
        appendText(c.raw);
        continue;
      }

      appendObsidianLink(mapped);
    }

    appendText(text.slice(cursor));
  }

  private _updateSendButton(): void {
    // Disconnected: disable.
    // Working: keep enabled so user can stop/abort.
    const disabled = !this.isConnected;
    this.sendBtn.disabled = disabled;

    this.sendBtn.toggleClass('is-working', this.isWorking);
    this.sendBtn.setAttr('aria-busy', this.isWorking ? 'true' : 'false');
    this.sendBtn.setAttr('aria-label', this.isWorking ? 'Stop' : 'Send');

    if (this.isWorking) {
      // Replace button contents with Stop icon + spinner ring.
      this.sendBtn.empty();
      const wrap = this.sendBtn.createDiv({ cls: 'oclaw-stop-wrap' });
      wrap.createDiv({ cls: 'oclaw-spinner-ring', attr: { 'aria-hidden': 'true' } });
      wrap.createDiv({ cls: 'oclaw-stop-icon', attr: { 'aria-hidden': 'true' } });
    } else {
      // Restore label
      this.sendBtn.setText('Send');
    }
  }

  // ── Send handler ──────────────────────────────────────────────────────────

  private async _handleSend(): Promise<void> {
    // While working, the button becomes Stop.
    if (this.isWorking) {
      const ok = await this.plugin.wsClient.abortActiveRun();
      if (!ok) {
        new Notice('OpenClaw Chat: failed to stop');
        this.chatManager.addMessage(ChatManager.createSystemMessage('⚠ Stop failed', 'error'));
      } else {
        this.chatManager.addMessage(ChatManager.createSystemMessage('⛔ Stopped', 'info'));
      }
      return;
    }

    const text = this.inputEl.value.trim();
    if (!text) return;

    // Build message with context if enabled
    let message = text;
    if (this.includeNoteCheckbox.checked) {
      const note = await getActiveNoteContext(this.app);
      if (note) {
        message = `Context: [[${note.title}]]\n\n${text}`;
      }
    }

    // Add user message to chat UI
    const userMsg = ChatManager.createUserMessage(text);
    this.chatManager.addMessage(userMsg);

    // Clear input
    this.inputEl.value = '';
    this.inputEl.style.height = 'auto';

    // Send over WS (async)
    try {
      await this.plugin.wsClient.sendMessage(message);
    } catch (err) {
      console.error('[oclaw] Send failed', err);
      new Notice(`OpenClaw Chat: send failed (${String(err)})`);
      this.chatManager.addMessage(
        ChatManager.createSystemMessage(`⚠ Send failed: ${err}`, 'error')
      );
    }
  }
}
