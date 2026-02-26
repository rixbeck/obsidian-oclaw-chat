import { ItemView, MarkdownRenderer, Modal, Notice, Setting, TFile, WorkspaceLeaf } from 'obsidian';
import type OpenClawPlugin from './main';
import { ChatManager } from './chat';
import type { ChatMessage, PathMapping } from './types';
import { extractCandidates, tryMapRemotePathToVaultPath } from './linkify';
import { getActiveNoteContext } from './context';
import { ObsidianWSClient } from './websocket';

export const VIEW_TYPE_OPENCLAW_CHAT = 'openclaw-chat';

class NewSessionModal extends Modal {
  private initialValue: string;
  private onSubmit: (value: string) => void;

  constructor(view: OpenClawChatView, initialValue: string, onSubmit: (value: string) => void) {
    super(view.app);
    this.initialValue = initialValue;
    this.onSubmit = onSubmit;
  }

  onOpen(): void {
    const { contentEl } = this;
    contentEl.empty();

    contentEl.createEl('h3', { text: 'New session key' });

    let value = this.initialValue;

    new Setting(contentEl)
      .setName('Session key')
      .setDesc('Tip: choose a short suffix; it will become agent:main:obsidian:direct:<vaultHash>-<suffix>.')
      .addText((t) => {
        t.setValue(value);
        t.onChange((v) => {
          value = v;
        });
      });

    new Setting(contentEl)
      .addButton((b) => {
        b.setButtonText('Cancel');
        b.onClick(() => this.close());
      })
      .addButton((b) => {
        b.setCta();
        b.setButtonText('Create');
        b.onClick(() => {
          const v = value.trim().toLowerCase();
          if (!v) {
            new Notice('Suffix cannot be empty');
            return;
          }
          if (!/^[a-z0-9][a-z0-9_-]{0,63}$/.test(v)) {
            new Notice('Use letters/numbers/_/- only (max 64 chars)');
            return;
          }
          this.onSubmit(v);
          this.close();
        });
      });
  }
}

export class OpenClawChatView extends ItemView {
  private plugin: OpenClawPlugin;
  private chatManager: ChatManager;
  private wsClient: ObsidianWSClient;

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

  private sessionSelect!: HTMLSelectElement;
  private sessionRefreshBtn!: HTMLButtonElement;
  private sessionNewBtn!: HTMLButtonElement;
  private sessionMainBtn!: HTMLButtonElement;
  private suppressSessionSelectChange = false;

  // (removed) internal-link delegation (handled by post-processing linkify)

  constructor(leaf: WorkspaceLeaf, plugin: OpenClawPlugin) {
    super(leaf);
    this.plugin = plugin;
    this.chatManager = new ChatManager();
    this.wsClient = this.plugin.createWsClient(this.plugin.getDefaultSessionKey());

    // Wire incoming WS messages → ChatManager (per-leaf)
    this.wsClient.onMessage = (msg) => {
      if (msg.type === 'message') {
        this.chatManager.addMessage(ChatManager.createAssistantMessage(msg.payload.content));
      } else if (msg.type === 'error') {
        const errText = msg.payload.message ?? 'Unknown error from gateway';
        this.chatManager.addMessage(ChatManager.createSystemMessage(`⚠ ${errText}`, 'error'));
      }
    };
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
    this.plugin.registerChatLeaf();
    this._buildUI();

    // Full re-render on clear / reload
    this.chatManager.onUpdate = (msgs) => this._renderMessages(msgs);
    // O(1) append for new messages
    this.chatManager.onMessageAdded = (msg) => this._appendMessage(msg);

    // Connect this leaf's WS client
    const gw = this.plugin.getGatewayConfig();
    if (gw.token) {
      this.wsClient.connect(gw.url, gw.token, { allowInsecureWs: gw.allowInsecureWs });
    } else {
      new Notice('OpenClaw Chat: please configure your gateway token in Settings.');
    }

    // Subscribe to WS state changes
    this.wsClient.onStateChange = (state) => { 
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
    this.wsClient.onWorkingChange = (working) => {
      this.isWorking = working;
      this._updateSendButton();
    };

    // Reflect current state
    this.lastGatewayState = this.wsClient.state;
    this.isConnected = this.wsClient.state === 'connected';
    this.statusDot.toggleClass('connected', this.isConnected);
    this.statusDot.title = `Gateway: ${this.wsClient.state}`;
    this._updateSendButton();

    this._renderMessages(this.chatManager.getMessages());

    // Load session dropdown from local vault-scoped known sessions.
    this._loadKnownSessions();
  }

  async onClose(): Promise<void> {
    this.plugin.unregisterChatLeaf();
    this.chatManager.onUpdate = null;
    this.chatManager.onMessageAdded = null;
    this.wsClient.onStateChange = null;
    this.wsClient.onWorkingChange = null;
    this.wsClient.disconnect();

    // (removed) internal-link delegation cleanup
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

    // ── Session row ──
    const sessRow = root.createDiv({ cls: 'oclaw-session-row' });
    sessRow.createSpan({ cls: 'oclaw-session-label', text: 'Session' });

    this.sessionSelect = sessRow.createEl('select', { cls: 'oclaw-session-select' });
    this.sessionRefreshBtn = sessRow.createEl('button', { cls: 'oclaw-session-btn', text: 'Reload' });
    this.sessionNewBtn = sessRow.createEl('button', { cls: 'oclaw-session-btn', text: 'New…' });
    this.sessionMainBtn = sessRow.createEl('button', { cls: 'oclaw-session-btn', text: 'Main' });

    this.sessionRefreshBtn.addEventListener('click', () => this._loadKnownSessions());
    this.sessionNewBtn.addEventListener('click', () => {
      if (!this.plugin.getVaultHash()) {
        new Notice('OpenClaw Chat: New session is unavailable (missing vault identity).');
        return;
      }
      void this._promptNewSession();
    });
    this.sessionMainBtn.addEventListener('click', () => {
      void (async () => {
        await this._switchSession('main');
        this._loadKnownSessions();
        this.sessionSelect.value = 'main';
        this.sessionSelect.title = 'main';
      })();
    });
    this.sessionSelect.addEventListener('change', () => {
      if (this.suppressSessionSelectChange) return;
      const next = this.sessionSelect.value;
      if (!next) return;
      void (async () => {
        await this._switchSession(next);
        this._loadKnownSessions();
        this.sessionSelect.value = next;
        this.sessionSelect.title = next;
      })();
    });

    // ── Messages area ──
    this.messagesEl = root.createDiv({ cls: 'oclaw-messages' });

    // Note: markdown-mode linkify is handled post-render via _postprocessAssistantLinks.
    // We no longer rely on internal-link click delegation.


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

  private _setSessionSelectOptions(keys: string[]): void {
    this.suppressSessionSelectChange = true;
    try {
      this.sessionSelect.empty();

      const current = (this.plugin.settings.sessionKey ?? 'main').toLowerCase();
      let unique = Array.from(new Set([current, ...keys].filter(Boolean)));

      // Canonical-only: main or agent:main:obsidian:direct:*
      unique = unique.filter((k) => k === 'main' || String(k).startsWith('agent:main:obsidian:direct:'));

      if (unique.length === 0) {
        unique = ['main'];
      }

      for (const key of unique) {
        const opt = this.sessionSelect.createEl('option', { value: key, text: key });
        if (key === current) opt.selected = true;
      }

      if (unique.includes(current)) {
        this.sessionSelect.value = current;
      }
      this.sessionSelect.title = current;
    } finally {
      this.suppressSessionSelectChange = false;
    }
  }

  private _loadKnownSessions(): void {
    const vaultHash = (this.plugin.settings.vaultHash ?? '').trim();
    const map = this.plugin.settings.knownSessionKeysByVault ?? {};
    const keys = vaultHash && Array.isArray(map[vaultHash]) ? map[vaultHash] : [];

    const prefix = vaultHash ? `agent:main:obsidian:direct:${vaultHash}` : '';
    const filtered = vaultHash
      ? keys.filter((k) => {
          const key = String(k || '').trim().toLowerCase();
          return key === prefix || key.startsWith(prefix + '-');
        })
      : [];

    this._setSessionSelectOptions(filtered);
  }

  private async _switchSession(sessionKey: string): Promise<void> {
    const next = sessionKey.trim().toLowerCase();
    if (!next) return;

    const vaultHash = this.plugin.getVaultHash();
    if (vaultHash) {
      const prefix = `agent:main:obsidian:direct:${vaultHash}`;
      if (!(next === 'main' || next === prefix || next.startsWith(prefix + '-'))) {
        new Notice('OpenClaw Chat: session key must match this vault.');
        return;
      }
    } else {
      if (next !== 'main') {
        new Notice('OpenClaw Chat: cannot switch sessions (missing vault identity).');
        return;
      }
    }

    // Abort any in-flight run best-effort.
    try {
      await this.wsClient.abortActiveRun();
    } catch {
      // ignore
    }

    // Divider in this leaf only.
    this.chatManager.addMessage(ChatManager.createSessionDivider(next));

    // Persist as the default and remember it in the vault-scoped list.
    await this.plugin.rememberSessionKey(next);

    // Switch WS routing for this leaf.
    this.wsClient.disconnect();
    this.wsClient.setSessionKey(next);

    const gw = this.plugin.getGatewayConfig();
    if (gw.token) {
      this.wsClient.connect(gw.url, gw.token, { allowInsecureWs: gw.allowInsecureWs });
    } else {
      new Notice('OpenClaw Chat: please configure your gateway token in Settings.');
    }
  }

  private async _promptNewSession(): Promise<void> {
    const now = new Date();
    const pad = (n: number) => String(n).padStart(2, '0');
    const suggested = `chat-${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}-${pad(now.getHours())}${pad(now.getMinutes())}`;

    const modal = new NewSessionModal(this, suggested, (suffix) => {
      const vaultHash = (this.plugin.settings.vaultHash ?? '').trim();
      if (!vaultHash) {
        new Notice('OpenClaw Chat: cannot create session (missing vault identity).');
        return;
      }
      const key = `agent:main:obsidian:direct:${vaultHash}-${suffix}`;
      void (async () => {
        await this._switchSession(key);
        this._loadKnownSessions();
        this.sessionSelect.value = key;
        this.sessionSelect.title = key;
      })();
    });
    modal.open();
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
    const kindClass = msg.kind ? ` oclaw-${msg.kind}` : '';
    const el = this.messagesEl.createDiv({ cls: `oclaw-message ${msg.role}${levelClass}${kindClass}` });
    const body = el.createDiv({ cls: 'oclaw-message-body' });
    if (msg.title) {
      body.title = msg.title;
    }

    // Treat assistant output as UNTRUSTED by default.
    // Rendering as Obsidian Markdown can trigger embeds and other plugins' post-processors.
    if (msg.role === 'assistant') {
      const mappings: PathMapping[] = this.plugin.settings.pathMappings ?? [];
      const sourcePath = this.app.workspace.getActiveFile()?.path ?? '';

      if (this.plugin.settings.renderAssistantMarkdown) {
        // Best-effort pre-processing: replace known remote paths with wikilinks when the target exists.
        const pre = this._preprocessAssistantMarkdown(msg.content, mappings);
        void MarkdownRenderer.renderMarkdown(pre, body, sourcePath, this.plugin).then(() => {
          this._postprocessAssistantLinks(body, msg.content, mappings, sourcePath);
        });
      } else {
        // Plain mode: build safe, clickable links in DOM (no Markdown rendering).
        this._renderAssistantPlainWithLinks(body, msg.content, mappings, sourcePath);
      }
    } else {
      body.setText(msg.content);
    }

    // Auto-dismiss transient system messages (but keep session dividers).
    if (msg.role === 'system' && msg.kind !== 'session-divider') {
      const FADE_DELAY_MS = 5_000;
      const FADE_ANIM_MS = 450;

      window.setTimeout(() => {
        el.addClass('oclaw-fade-out');
        window.setTimeout(() => {
          this.chatManager.removeMessage(msg.id);
        }, FADE_ANIM_MS);
      }, FADE_DELAY_MS);
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

  private _preprocessAssistantMarkdown(text: string, _mappings: PathMapping[]): string {
    // Do not inject wikilinks or custom schemes into Markdown.
    // We'll post-process rendered HTML with the same safe linkify logic as plain mode.
    return text;
  }

  private _appendObsidianLink(
    container: HTMLElement,
    vaultPath: string,
    sourcePath: string,
    displayText?: string,
  ): void {
    const display = displayText ?? `[[${vaultPath}]]`;
    const a = container.createEl('a', { text: display, href: '#' });
    a.addEventListener('click', (ev) => {
      ev.preventDefault();
      ev.stopPropagation();

      const f = this.app.vault.getAbstractFileByPath(vaultPath);
      if (f instanceof TFile) {
        void this.app.workspace.getLeaf(true).openFile(f);
        return;
      }

      void this.app.workspace.openLinkText(vaultPath, sourcePath, true);
    });
  }

  private _postprocessAssistantLinks(
    body: HTMLElement,
    rawText: string,
    mappings: PathMapping[],
    sourcePath: string,
  ): void {
    // Linkify after MarkdownRenderer has produced HTML.
    // We only transform text nodes, preserving formatting.
    const candidatesByNode = new Map<Text, ReturnType<typeof extractCandidates>>();

    const walker = body.ownerDocument.createTreeWalker(body, NodeFilter.SHOW_TEXT);
    const textNodes: Text[] = [];
    let n: Node | null;
    while ((n = walker.nextNode())) {
      const t = n as Text;
      if (!t.nodeValue) continue;
      textNodes.push(t);
    }

    for (const t of textNodes) {
      const text = t.nodeValue ?? '';
      const candidates = extractCandidates(text);
      if (candidates.length === 0) continue;
      candidatesByNode.set(t, candidates);
    }

    const tryReverseMapUrlToVaultPath = (url: string): string | null => this._tryReverseMapUrlToVaultPath(url, mappings);

    for (const [t, candidates] of candidatesByNode.entries()) {
      const text = t.nodeValue ?? '';
      const frag = body.ownerDocument.createDocumentFragment();
      let cursor = 0;

      const appendText = (s: string) => {
        if (!s) return;
        frag.appendChild(body.ownerDocument.createTextNode(s));
      };

      for (const c of candidates) {
        appendText(text.slice(cursor, c.start));
        cursor = c.end;

        if (c.kind === 'url') {
          const mapped = tryReverseMapUrlToVaultPath(c.raw);
          if (mapped) {
            this._appendObsidianLink(frag as any, mapped, sourcePath, c.raw);
          } else {
            // leave URL as text; renderer likely already created an <a> for it
            appendText(c.raw);
          }
          continue;
        }

        const direct = this._tryMapVaultRelativeToken(c.raw, mappings);
        if (direct) {
          this._appendObsidianLink(frag as any, direct, sourcePath, c.raw);
          continue;
        }

        const mapped = tryMapRemotePathToVaultPath(c.raw, mappings);
        if (mapped && this.app.vault.getAbstractFileByPath(mapped)) {
          this._appendObsidianLink(frag as any, mapped, sourcePath, c.raw);
          continue;
        }

        appendText(c.raw);
      }

      appendText(text.slice(cursor));

      // Replace the text node.
      const parent = t.parentNode;
      if (!parent) continue;
      parent.replaceChild(frag, t);
    }

    void rawText;
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
          this._appendObsidianLink(body, mapped, sourcePath);
        } else {
          appendExternalUrl(c.raw);
        }
        continue;
      }

      const direct = this._tryMapVaultRelativeToken(c.raw, mappings);
      if (direct) {
        this._appendObsidianLink(body, direct, sourcePath);
        continue;
      }

      const mapped = tryMapRemotePathToVaultPath(c.raw, mappings);
      if (!mapped) {
        appendText(c.raw);
        continue;
      }

      if (!this.app.vault.getAbstractFileByPath(mapped)) {
        appendText(c.raw);
        continue;
      }

      this._appendObsidianLink(body, mapped, sourcePath);
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
      const ok = await this.wsClient.abortActiveRun();
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
      await this.wsClient.sendMessage(message);
    } catch (err) {
      console.error('[oclaw] Send failed', err);
      new Notice(`OpenClaw Chat: send failed (${String(err)})`);
      this.chatManager.addMessage(
        ChatManager.createSystemMessage(`⚠ Send failed: ${err}`, 'error')
      );
    }
  }
}
