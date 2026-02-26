import { ItemView, MarkdownRenderer, Notice, WorkspaceLeaf } from 'obsidian';
import type OpenClawPlugin from './main';
import { ChatManager } from './chat';
import type { ChatMessage } from './types';
import { getActiveNoteContext } from './context';

export const VIEW_TYPE_OPENCLAW_CHAT = 'openclaw-chat';

export class OpenClawChatView extends ItemView {
  private plugin: OpenClawPlugin;
  private chatManager: ChatManager;

  // State
  private isConnected = false;
  private isWorking = false;

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
    this.isConnected = this.plugin.wsClient.state === 'connected';
    this.statusDot.toggleClass('connected', this.isConnected);
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

    // Render assistant messages as Markdown (untrusted content → keep user/system plain)
    if (msg.role === 'assistant') {
      const sourcePath = this.app.workspace.getActiveFile()?.path ?? '';
      void MarkdownRenderer.renderMarkdown(msg.content, body, sourcePath, this.plugin);
    } else {
      body.setText(msg.content);
    }

    // Scroll to bottom
    this.messagesEl.scrollTop = this.messagesEl.scrollHeight;
  }

  private _updateSendButton(): void {
    const disabled = !this.isConnected || this.isWorking;
    this.sendBtn.disabled = disabled;

    this.sendBtn.toggleClass('is-working', this.isWorking);
    this.sendBtn.setAttr('aria-busy', this.isWorking ? 'true' : 'false');

    if (this.isWorking) {
      // Replace button contents with spinner
      this.sendBtn.empty();
      this.sendBtn.createDiv({ cls: 'oclaw-spinner', attr: { 'aria-hidden': 'true' } });
    } else {
      // Restore label
      this.sendBtn.setText('Send');
    }
  }

  // ── Send handler ──────────────────────────────────────────────────────────

  private async _handleSend(): Promise<void> {
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
