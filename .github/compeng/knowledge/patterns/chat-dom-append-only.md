# Pattern: Append-only DOM for Chat / Streaming List UIs

**Domain:** obsidian-plugin (UI)
**Created:** 2026-02-25

---

## When to Use

Any UI that displays a growing ordered list where:
- New items are only ever appended at the end (chat messages, log entries, search results stream)
- The full list is occasionally reset/cleared (conversation cleared, view reopened)
- Performance matters at N > 20 items

## The Anti-pattern: Full Re-render

```typescript
// ❌ O(N) — rebuilds all N nodes on every new message
chatManager.onUpdate = (msgs) => {
  this.messagesEl.empty();
  for (const msg of msgs) {
    renderMessage(this.messagesEl, msg);
  }
};
```

At 100 messages this runs 100 render operations per new message, causing visible UI freezes if render is expensive (e.g. MarkdownRenderer).

## The Pattern: Dual Callbacks

### ChatManager (model layer)

Add **two** callbacks:
- `onUpdate` — fires on full reset (`clear()`), with the full list
- `onMessageAdded` — fires on append, with just the single new message

```typescript
class ChatManager {
  onUpdate: ((msgs: readonly ChatMessage[]) => void) | null = null;
  onMessageAdded: ((msg: ChatMessage) => void) | null = null;

  addMessage(msg: ChatMessage): void {
    this.messages.push(msg);
    this.onMessageAdded?.(msg);          // O(1) path
  }

  clear(): void {
    this.messages = [];
    this.onUpdate?.([]);                 // full reset path
  }
}
```

### View layer

Subscribe to both, using each for its appropriate case:

```typescript
// Full reset (clear / panel reopen)
this.chatManager.onUpdate = (msgs) => this._renderMessages(msgs);
// Single append (new message) — O(1)
this.chatManager.onMessageAdded = (msg) => this._appendMessage(msg);

private _appendMessage(msg: ChatMessage): void {
  // Remove empty-state placeholder if present
  this.messagesEl.querySelector('.oclaw-placeholder')?.remove();

  const el = this.messagesEl.createDiv({ cls: `oclaw-message ${msg.role}` });
  el.createSpan({ text: msg.content });
  this.messagesEl.scrollTop = this.messagesEl.scrollHeight;
}
```

**Mark the empty-state element** with a dedicated class so it's removable on first message:

```typescript
private _renderMessages(messages: readonly ChatMessage[]): void {
  this.messagesEl.empty();
  if (messages.length === 0) {
    this.messagesEl.createEl('p', {
      text: 'Send a message to start chatting.',
      cls: 'oclaw-message system oclaw-placeholder',   // ← sentinel class
    });
    return;
  }
  for (const msg of messages) { /* ... */ }
}
```

### Cleanup in onClose

```typescript
async onClose(): Promise<void> {
  this.chatManager.onUpdate = null;
  this.chatManager.onMessageAdded = null;  // ← must null both
  this.plugin.wsClient.onStateChange = null;
}
```

## Best Practices

- ✅ DO: Use `onMessageAdded` for every new message in steady-state operation
- ✅ DO: Use `onUpdate` only for full resets (clear/reload)
- ✅ DO: Null both callbacks in `onClose` to prevent memory leaks after view unmount
- ✅ DO: Mark the empty-state placeholder with a sentinel class (`.oclaw-placeholder`) so `_appendMessage` can clean it up on first message
- ❌ DON'T: Call `messagesEl.empty()` in the append path — defeats the purpose
- ❌ DON'T: Share a single `onUpdate` callback for both appends and resets — callee can't distinguish and must re-render everything

## Performance Profile

| Scenario | Full Re-render | Append-only |
|----------|---------------|-------------|
| 1st message (N=0→1) | O(1) | O(1) |
| 50th message (N=49→50) | O(50) | O(1) |
| Clear + reload 50 msgs | — | O(50) one-time |

## Examples

- `obsidian-plugin/src/chat.ts` — `ChatManager` with dual callbacks
- `obsidian-plugin/src/view.ts` — `_appendMessage()` + `_renderMessages()`

## Related Patterns

- [ADR: WS inbound/outbound type split](../decisions/ADR-20260225-ws-inbound-outbound-type-split.md)

## References

- Review Issue 5 (Critical — O(N) full re-render): [Review](../../reviews/20260225-1430-channel-fix-and-obsidian-phase2.md#issue-5)
