# Checklist: Channel Plugin Security Review

**Updated:** 2026-02-25

All items below have corresponding Must-fix precedents from prior reviews. Check each before shipping.

---

## WebSocket Server Hardening

- [ ] **WS server binds to `127.0.0.1`, not `0.0.0.0`**
  - **Why:** Default `WebSocketServer({ port })` exposes the server on all interfaces including LAN/VPN.
  - **Fix:** `new WebSocketServer({ host: '127.0.0.1', port })`
  - **Precedent:** [Review 2026-02-25 Issue 2](../../reviews/20260225-1430-channel-fix-and-obsidian-phase2.md)

- [ ] **Session IDs are server-generated — client-supplied sessionId is ignored**
  - **Why:** Client-supplied sessionId allows session fixation / session hijacking.
  - **Fix:** Always use the server-generated `clientId`; return the assigned sessionId in the auth success response.
  - **Precedent:** [Review 2026-02-25 Issue 3](../../reviews/20260225-1430-channel-fix-and-obsidian-phase2.md)

- [ ] **Incoming message size is bounded (max 1 MB)**
  - **Why:** Unbounded frames allow heap exhaustion DoS.
  - **Fix:** `if (data.length > 1_048_576) { ws.close(1009, 'Message too large'); return; }`
  - **Precedent:** [Review 2026-02-25 Issue 15](../../reviews/20260225-1430-channel-fix-and-obsidian-phase2.md)

- [ ] **Auth token comparison is timing-safe**
  - **Why:** String equality short-circuits on first mismatch — leaks token length and char-by-char info.
  - **Fix:** XOR all bytes, accumulate into a single integer, compare to 0.
  - **Note:** Also ensure equal-length padding so length-oracle isn't available.

- [ ] **Session IDs use `crypto.randomUUID()`, not `Math.random()`**
  - **Why:** `Math.random()` is not a CSPRNG — output is deterministic.
  - **Fix:** `import { randomUUID } from 'node:crypto'`
  - **Precedent:** [Review 2026-02-25 Issue 14](../../reviews/20260225-1430-channel-fix-and-obsidian-phase2.md)

- [ ] **Auth token is never logged**
  - **Why:** Tokens in logs = credentials in log aggregation systems.
  - **Fix:** Log `{ sessionId }` only; never `{ token }`.

---

## Obsidian Plugin (Electron Renderer)

- [ ] **External content is never passed to `MarkdownRenderer.render()`**
  - **Why:** Markdown renderer allows raw HTML in Electron — XSS → RCE with full Node.js access.
  - **Fix:** `el.createSpan({ text: msg.content })` for all server-sourced content.
  - **Precedent:** [Review 2026-02-25 Issue 4](../../reviews/20260225-1430-channel-fix-and-obsidian-phase2.md)

- [ ] **No `.innerHTML = ` on external data**
  - **Why:** Same Electron RCE vector as MarkdownRenderer.
  - **Fix:** Use Obsidian's DOM builder APIs (`createEl`, `createDiv`, `createSpan` with `text:` key).

- [ ] **WebSocket gateway URL is validated before connect**
  - **Why:** A misconfigured URL could connect to a non-local endpoint, leaking tokens.
  - **Fix:** Enforce `ws://localhost:` or `ws://127.0.0.1:` prefix.

---

## Production Code Quality

- [ ] **No test/debug stubs in production routing paths**
  - **Why:** Echo stubs masquerade as real responses — users cannot distinguish real vs fake agent output.
  - **Fix:** Replace with a proper `{ type: 'error', payload: { message: '...' } }` response.
  - **Precedent:** [Review 2026-02-25 Issue 6](../../reviews/20260225-1430-channel-fix-and-obsidian-phase2.md)
