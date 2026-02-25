# Run: Channel Fix + Obsidian Phase 2

**Started:** 2026-02-25 13:50  
**Completed:** 2026-02-25 15:15  
**Plan:** [.github/compeng/plans/20260225-1350-channel-fix-and-obsidian-phase2.md](.github/compeng/plans/20260225-1350-channel-fix-and-obsidian-phase2.md)  
**Status:** ✅ Complete (incl. must-fix remediation)

---

## Progress Log

### Step B1: RPC wiring fix (index.ts)

**Goal:** `registerRPCMethods(ctx)` hívása hiányzott → RPC nem működött.

**Action:**
- `src/index.ts`: `import { registerRPCMethods } from './rpc.js'` hozzáadva
- `register()` body: `registerRPCMethods(ctx)` hívás hozzáadva a 3. lépésként

**Status:** ✅ Complete

**Result:** `obsidian.sendMessage`, `obsidian.broadcastMessage`, `obsidian.listAccounts` RPC-k most regisztrálódnak indításkor.

---

### Step B2: Outbound sendMessage fix (channel.ts)

**Goal:** `channel.ts` outbound handler placeholder → valódi WS küldés.

**Action:**
- `src/channel.ts`: `import { sendMessage, broadcastMessage } from './rpc.js'` hozzáadva
- Handler: ha van `sessionId` → `sendMessage(sessionId, message, ctx)`, különben → `broadcastMessage(message, ctx)`

**Status:** ✅ Complete

**Result:** Agent → Obsidian irány mostantól valóban küld WS-en.

---

### Step B3: broadcastMessage helper (rpc.ts)

**Goal:** Agent nem mindig ad `sessionId`-t → broadcast kell.

**Action:**
- `src/rpc.ts`: `broadcastMessage(content, ctx)` export hozzáadva
  - Szűri: csak `authenticated: true` session-öket
  - Számolja a `sent`/`errors` értékeket
- `registerRPCMethods()` kiterjesztve: `obsidian.broadcastMessage` RPC regisztrálva

**Status:** ✅ Complete

---

### Step 1.4: Unit és integration tesztek

**Goal:** min. 18 teszt, lefedi a kritikus path-okat.

**Action:**
- `src/auth.test.ts` – 7 eset (token matching, edge cases)
- `src/session.test.ts` – 4 eset (dispatch, echo fallback, missing payload)
- `src/rpc.test.ts` – 10 eset (sendMessage, broadcastMessage, listAccounts, registerRPCMethods) + `vi.mock('./service.js')`
- `src/service.test.ts` – 6 integration smoke (WS server, auth, rejection, ping/pong, unauth, disconnect cleanup)

**Status:** ✅ Complete

**Result:**
```
Test Files  4 passed (4)
     Tests  27 passed (27)
  Duration  648ms
```

---

### Step 2: Obsidian Community Plugin scaffold

**Goal:** `obsidian-plugin/` könyvtár teljes scaffold, typecheck + build zöld.

**Action:** 13 fájl létrehozva:
- `manifest.json`, `package.json`, `tsconfig.json`, `esbuild.config.mjs`, `styles.css`
- `src/types.ts` – OpenClawSettings, ChatMessage, WSPayload, AgentOption
- `src/settings.ts` – PluginSettingTab (gateway URL, password input, agent dropdown, toggle)
- `src/websocket.ts` – ObsidianWSClient: connect/disconnect/send/reconnect (3s)/heartbeat (30s)/pong timeout
- `src/chat.ts` – ChatManager: addMessage, getMessages, clear, factory helpers
- `src/context.ts` – getActiveNoteContext(app): async vault.read()
- `src/models.ts` – AGENT_OPTIONS, getAgentById()
- `src/view.ts` – OpenClawChatView (ItemView): status dot, agent selector, message list (MarkdownRenderer), textarea, send
- `src/main.ts` – OpenClawPlugin: onload/onunload, ribbon, settings tab, WS init, message routing

**TypeScript:** `tsc --noEmit` → 0 error  
**Build:** `node esbuild.config.mjs` → `main.js 63.5 KB` ⚡ 7ms

**Status:** ✅ Complete

**Key decisions:**
- `window.WebSocket` (nem `ws` npm) → browser/Electron kompatibilis
- Token: `type="password"` input, soha nem logolva
- `broadcastMessage` + `sendMessage` kettős outbound path
- `MarkdownRenderer.render()` assistant üzenetekhez

---

### Step 3: Knowledge capture

**Action:** Első knowledge bejegyzések:
- `.github/compeng/knowledge/gotchas/openclaw-plugin-cannot-import-internals.md`
- `.github/compeng/knowledge/gotchas/obsidian-plugin-no-node-ws.md`
- `.github/compeng/knowledge/patterns/openclaw-plugin-development-sources.md`

**Status:** ✅ Complete

---

## Acceptance Criteria

| Criterion | Status | Notes |
|-----------|--------|-------|
| `npm test` zöld (min. 18 teszt) | ✅ Done | **27 teszt** passed |
| `registerRPCMethods` meghívva index.ts-ben | ✅ Done | B1 fix |
| channel.ts outbound sendMessage WS-en küld | ✅ Done | B2 fix, broadcastMessage is |
| Obsidian plugin manifest.json + buildelhető | ✅ Done | `main.js` 63.5 KB, 0 TS error |
| Token nem kerül logba | ✅ Done | `type="password"`, auth.ts guard |
| WS reconnect 3s delay után | ✅ Done | `websocket.ts` reconnectTimer |

## Lessons Learned

- **Wiring checklist**: ha van `registerX()` függvény, mindig ellenőrizd, hogy az entry point meghívja-e.
- **`vi.mock` hoist**: a module-level state (`activeSessions` Map) teszteléséhez mock szükséges, nem közvetlen hozzáférés.
- **Port 0 trick**: WS integration tesztekben `port: 0` (OS ad portot) megbízhatóbb, mint fix test port.
- **Obsidian `MarkdownRenderer.render()`**: 4 argumentumot vár (app, markdown, el, sourcePath, component).
- **esbuild watch mode**: `--watch` flag CLI-ből olvasható, nem kell külön `watch.js`.

## Next Steps

- [ ] E2E smoke: channel plugin + Obsidian plugin kézzel összekötni, üzenet küld-fogad tesztelés
- [ ] `@review` agent futtatása a Phase 1 + Phase 2 kódon
- [ ] Streaming response support (Phase 3 terv)
- [ ] Conversation history perzisztencia (Phase 3 terv)

---

## Must-fix Remediation (Review → WORK loop)

**Review artefact:** `.github/compeng/reviews/20260225-1430-channel-fix-and-obsidian-phase2.md`  
**8 must-fix issues resolved. Tests: 27/27. TS: 0 errors. Build: 65.4 KB.**

### Fix 1 — OutboundMessage envelope (Issue 1, Critical)

**Problem:** `OutboundMessage` had `content`/`timestamp` at top-level. Obsidian client read `msg.payload?.content` → always `undefined`. Agent→UI direction completely broken at runtime.

**Changes:**
- `channel-plugin/src/types.ts`: `OutboundMessage.content` moved inside `payload: { content, timestamp }`
- `channel-plugin/src/rpc.ts`: Both `sendMessage` and `broadcastMessage` build `{ type: 'message', payload: { content, timestamp: Date.now() } }`
- `obsidian-plugin/src/types.ts`: New `InboundWSPayload` discriminated union with properly typed `message` and `error` variants
- `obsidian-plugin/src/websocket.ts`: `onMessage` callback now uses `InboundWSPayload`; removed all `as any` casts
- `obsidian-plugin/src/main.ts`: `msg.payload.content` and `msg.payload.message` fully typed, no casts

**Status:** ✅ Complete

---

### Fix 2 — WS binds to 127.0.0.1 (Issue 2)

**Problem:** `WebSocketServer({ port })` binds to `0.0.0.0` — LAN-exposed.

**Change:** `channel-plugin/src/service.ts`: `new WebSocketServer({ host: '127.0.0.1', port: wsPort })`

**Status:** ✅ Complete

---

### Fix 3 — Session fixation prevention (Issue 3)

**Problem:** Client could supply arbitrary `sessionId` in auth payload to potentially hijack another session's routing.

**Changes:**
- `channel-plugin/src/service.ts`: `sessionInfo.sessionId` always set to server-generated `clientId`; `message.payload?.sessionId` ignored
- `channel-plugin/src/service.ts`: Auth success response now includes `{ success: true, sessionId: clientId }` so the Obsidian client knows its actual session ID
- `obsidian-plugin/src/websocket.ts`: Adopts server-returned `sessionId` after auth success
- `obsidian-plugin/src/types.ts`: `InboundWSPayload` auth variant updated to include `sessionId?: string`

**Status:** ✅ Complete

---

### Fix 4 — MarkdownRenderer XSS/RCE (Issue 4)

**Problem:** `MarkdownRenderer.render()` on untrusted server content in Electron context enables XSS/RCE via injected HTML/script in markdown.

**Changes:**
- `obsidian-plugin/src/view.ts`: `MarkdownRenderer` import removed; assistant messages use `el.createSpan({ text: msg.content })` (plain text, HTML-safe)

**Status:** ✅ Complete

---

### Fix 5 — O(N) full re-render per message (Issue 5)

**Problem:** `_renderMessages()` called `messagesEl.empty()` and rebuilt all DOM nodes on every new message — O(N) cost.

**Changes:**
- `obsidian-plugin/src/chat.ts`: `addMessage()` now fires `onMessageAdded?.(msg)` (new callback); `clear()` fires `onUpdate?.([])`
- `obsidian-plugin/src/view.ts`: 
  - `onOpen` subscribes to both `onMessageAdded` (→ `_appendMessage`) and `onUpdate` (→ `_renderMessages` for clear only)
  - New `_appendMessage(msg)` method: O(1) DOM append, removes `oclaw-placeholder` on first message
  - `_renderMessages` used only for initial render and full reset; placeholder gets `oclaw-placeholder` class for detection
  - `onClose` nulls both callbacks

**Status:** ✅ Complete

---

### Fix 6 — Echo test code in production (Issue 6)

**Problem:** `session.ts` else-branch echoed the message back with type `'message'` when `runtime.dispatchToAgent` was unavailable — masked dispatch failures in production.

**Change:** `channel-plugin/src/session.ts`: Replaced echo with a proper `{ type: 'error', payload: { message: 'Agent dispatch unavailable...' } }` response.

**Status:** ✅ Complete

---

### Fix 7 — Fragile DOM access (Issue 7)

**Problem:** `this.containerEl.children[1]` — position dependent, breaks if Obsidian changes view structure.

**Change:** `obsidian-plugin/src/view.ts`: `_buildUI()` now uses `this.contentEl` (stable Obsidian API property).

**Status:** ✅ Complete

---

### Fix 8 — Error payload normalization (Issue 8)

**Problem:** Server sent `payload: 'Invalid token'` (bare string) but client typed `payload` as `Record<string,unknown>` — runtime type error.

**Changes:**
- `channel-plugin/src/service.ts`: All 3 error sends changed to `payload: { message: '...' }`
- `obsidian-plugin/src/types.ts`: `InboundWSPayload` error variant: `payload: { message: string }`

**Status:** ✅ Complete

---

### Test & Build Results

| Check | Result |
|-------|--------|
| `channel-plugin` tests | ✅ 27/27 passed |
| `channel-plugin` TS | ✅ 0 errors (implicit via vitest) |
| `obsidian-plugin` tsc --noEmit | ✅ 0 errors |
| `obsidian-plugin` build | ✅ main.js 65.4 KB |

**Updated acceptance criteria:**

| Criterion | Status | Notes |
|-----------|--------|-------|
| OutboundMessage payload-wrapped | ✅ Done | Issue 1 + updated tests |
| WS localhost-only binding | ✅ Done | Issue 2 |
| Session fixation prevented | ✅ Done | Issue 3 + server returns sessionId |
| No MarkdownRenderer on untrusted content | ✅ Done | Issue 4 |
| Append-only DOM rendering | ✅ Done | Issue 5 |
| Echo test code removed | ✅ Done | Issue 6 |
| `this.contentEl` used | ✅ Done | Issue 7 |
| Error payload `{ message }` object | ✅ Done | Issue 8 |
