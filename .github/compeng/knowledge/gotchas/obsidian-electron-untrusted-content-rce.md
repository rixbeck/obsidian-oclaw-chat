# Gotcha: MarkdownRenderer on Untrusted Content Enables RCE in Obsidian (Electron)

**Domain:** obsidian-plugin
**First observed:** 2026-02-25
**Severity:** Critical — arbitrary code execution

---

## What Happened

`MarkdownRenderer.render(this.app, msg.content, el, '', this)` was called for all assistant messages. When `msg.content` originates from a server (over WebSocket), the content is untrusted. Obsidian's markdown renderer supports raw HTML passthrough and script execution in the Electron renderer process.

## Root Cause

Electron renderer processes have access to Node.js APIs (`require`, `fs`, `child_process`, etc.) unless explicitly sandboxed. Obsidian does not fully sandbox plugins. A markdown string containing:

```html
<script>require('child_process').execSync('rm -rf ~')</script>
```

would execute with full user privileges if rendered via `MarkdownRenderer.render`.

The attack vector chain: **compromised server → injected payload → MarkdownRenderer → RCE on user's machine**.

## Prevention

**Default to plain text for any server-controlled content:**

```typescript
// ✅ Safe — HTML-escaped, no script execution
el.createSpan({ text: msg.content });

// ❌ Dangerous for untrusted content
MarkdownRenderer.render(this.app, msg.content, el, '', this);
```

If markdown rendering is genuinely needed in the future, it must be opt-in and the content must come from a trusted source (local, user-authored). Add an explicit flag to the message type:

```typescript
// Future: only render markdown for explicitly trusted messages
if (msg.trusted && msg.role === 'assistant') {
  MarkdownRenderer.render(this.app, msg.content, el, '', this);
} else {
  el.createSpan({ text: msg.content });
}
```

## The Broader Rule

In Obsidian plugins, treat all data from **any external source** (WebSocket, HTTP, localStorage, vault) as untrusted HTML unless you authored it yourself in the same process. Use `createEl`/`createSpan` with `text:` (not `innerHTML`) for any external content.

## Detection

Look for any occurrence of these patterns in `src/view.ts` or any render function:
- `MarkdownRenderer.render(` applied to `msg.content`, `response.content`, or any field read from outside the plugin
- `.innerHTML =` assignments on any external data

## References

- Review Issue 4 (Critical — XSS/RCE): [Review](../../reviews/20260225-1430-channel-fix-and-obsidian-phase2.md#issue-4)
- `obsidian-plugin/src/view.ts` — `_appendMessage()` uses safe `createSpan({ text })`
- Obsidian developer docs: https://docs.obsidian.md/Plugins/Releasing/Plugin+guidelines#Avoid+innerHTML%2C+outerHTML+and+insertAdjacentHTML
