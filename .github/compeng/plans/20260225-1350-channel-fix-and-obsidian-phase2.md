---
status: approved
priority: high
tags: [obsidian, channel-plugin, rpc-fix, phase2, obsidian-community-plugin]
owner: Rix
created: 2026-02-25
parent-plan: 20260225-0954-hybrid-obsidian-integration.md
estimated_hours: 16-20
---

# Plan: Channel fix + Obsidian Plugin Phase 2

**Created:** 2026-02-25 13:50  
**Status:** Draft  
**Parent plan:** [20260225-0954-hybrid-obsidian-integration](20260225-0954-hybrid-obsidian-integration.md)

---

## Helyzetértékelés (ahol tartunk)

A previous run (`20260225-1015`) létrehozta a channel plugin 7 TypeScript fájlját.
A run log tévesen "⏸️ Starting" állapotot mutat – valójában a skeleton kódok megvannak.

### Mi van meg (Phase 1 skeleton)
- `channel-plugin/src/` → 7 fájl: `index.ts`, `channel.ts`, `service.ts`, `auth.ts`, `session.ts`, `rpc.ts`, `types.ts`
- `package.json`, `openclaw.plugin.json`, `tsconfig.json` ✅

### Mi hiányzik / bugos

| # | Issue | Helye | Súlyosság |
|---|-------|-------|-----------|
| B1 | `registerRPCMethods()` nincs hívva | `index.ts` | **Critical** – RPC nem működik |
| B2 | `channel.ts` outbound `sendMessage` nem használja a WS-t | `channel.ts` | **High** – agent→Obsidian path törött |
| B3 | Nincs egyetlen test sem | `src/*.test.ts` | **High** – acceptance criteria nincs teljesítve |
| B4 | Knowledge base üres | `.github/compeng/knowledge/` | Medium – tanulás nem mentett |
| B5 | Phase 2 Obsidian plugin nem indult | `obsidian-plugin/` | **High** – fő UI hiányzik |

---

## Objective

1. **Javítani a Phase 1 bugokat** (B1–B3): minimum RPC wiring + outbound fix + alap tesztek.
2. **Phase 2: Obsidian Community Plugin scaffold** létrehozása.
3. **Knowledge capture** a gotchákból, amik eddig előjöttek.

## Non-goals

- OAuth/SSO (MVP scope-on kívül)
- Streaming tokenenkénti megjelenítés (Phase 3+)
- @mentions, insert-into-note (Phase 3+)
- Multimodal (Phase 3+)

## Constraints

- Obsidian plugin API: `obsidian` npm csomag, esbuild bundle
- Channel plugin: ESM, Node 20+, `ws` könyvtár
- Nem importálunk OpenClaw core belső modulokat (ERR_PACKAGE_PATH_NOT_EXPORTED)
- Obsidian plugin nem futhat Node.js natív modulokkal (browser-like env)

---

## Knowledge Applied

- Knowledge base jelenleg üres → ez az iteráció fogja feltölteni.
- Implicit gotcha (a kódból olvasható): runtime API-k (`registerChannel`, `dispatchToAgent`, `registerRPC`) nem garantáltan elérhetők → mindig `if (runtime.X)` guard.

---

## Phase 1 — Bugfixek és tesztek

### Step 1.1 — RPC wiring fix (`index.ts`) [Critical]

**Probléma:** `registerRPCMethods(ctx)` importálva van `rpc.ts`-ben, de `index.ts` nem hívja meg.

**Változtatás:**
```typescript
// index.ts – hozzáadni:
import { registerRPCMethods } from './rpc.js';

export function register(ctx: any) {
  // ...meglévő kód...
  registerObsidianChannel(ctx);
  startWebSocketService(ctx);
  registerRPCMethods(ctx);   // ← EZ HIÁNYZIK
  // ...
}
```

**Fájl:** `channel-plugin/src/index.ts`  
**Várható hatás:** `obsidian.sendMessage` és `obsidian.listAccounts` RPC-k elérhetővé válnak.

---

### Step 1.2 — Outbound sendMessage fix (`channel.ts`) [High]

**Probléma:** `registerObsidianChannel` → `sendMessage` handler placeholder, nem küldi el WS-en.

**Megoldás:** Importálni `sendMessage` from `./rpc.js` és meghívni, vagy átirányítani a WS-n.

```typescript
// channel.ts – módosítás
import { sendMessage } from './rpc.js';

// sendMessage handler-ben:
async sendMessage(message: string, options: any) {
  const sessionId = options?.sessionId;
  if (!sessionId) {
    log.warn('[obsidian-channel] sendMessage called without sessionId');
    return { success: false, error: 'sessionId required' };
  }
  return await sendMessage(sessionId, message, ctx);
}
```

**Fájl:** `channel-plugin/src/channel.ts`

---

### Step 1.3 — Broadcast helper (`service.ts` / `rpc.ts`) [Medium]

**Hiányzó use case:** Agent nem tudja mindig megadni a `sessionId`-t. Kell egy broadcast:
```typescript
// rpc.ts – új export:
export async function broadcastMessage(content: string, ctx: PluginContext): Promise<void>
```
Ez minden autentikált session-be küldi az üzenetet.

**Fájl:** `channel-plugin/src/rpc.ts` + type update `types.ts`

---

### Step 1.4 — Unit tesztek (vitest) [High]

Létrehozni: `channel-plugin/src/auth.test.ts`, `session.test.ts`, `rpc.test.ts`, `service.test.ts`

#### `auth.test.ts`
```
- validateToken('abc', 'abc') → true
- validateToken('abc', 'xyz') → false
- validateToken(undefined, 'tok') → false
- validateToken('abc', '') → false
- Długość mismatch → false (timing-safe)
```

#### `session.test.ts`
```
- routeToSession: runtime.dispatchToAgent hívva a helyes payload-dal
- routeToSession: fallback echo ha nincs dispatchToAgent
- Missing payload → warn, no throw
```

#### `rpc.test.ts`
```
- sendMessage: session nem létezik → { success: false }
- sendMessage: session létezik, ws.send hívva
- listAccounts: üres lista → []
- listAccounts: 2 session → 2 elem
- registerRPCMethods: runtime.registerRPC hívva 2x
```

#### `service.test.ts` (integration smoke)
```
- WS server elindul a megadott porton
- Auth üzenet helyes tokennel → auth success vissza
- Auth üzenet rossz tokennel → error + ws close
- Ping → pong
- Not authenticated message → error
```

**Megjegyzés:** WS tesztekhez mock `ws` vagy `vitest-websocket-mock`.

---

### Step 1.5 — `obsidian.json` config sample

Dokumentumban (README vagy `config-sample.json`):
```json
{
  "channels": {
    "obsidian": {
      "enabled": true,
      "wsPort": 8765,
      "authToken": "<CHANGE_ME>",
      "accounts": ["main", "senilla"]
    }
  }
}
```

---

## Phase 2 — Obsidian Community Plugin scaffold

**Helye:** `/home/rix/Documents/wall-e/openclaw/obsidian-oclaw-chat/obsidian-plugin/`

### Könyvtárstruktúra

```
obsidian-plugin/
  manifest.json          ← Obsidian plugin manifest (kötelező)
  package.json           ← build + dev dependencies
  tsconfig.json          ← ES6 target (Obsidian requirement)
  esbuild.config.mjs     ← bundle script (inline, nem external)
  styles.css             ← sidebar panel stílusok
  src/
    main.ts              ← Plugin entry: load/unload, ribbon, registerView
    view.ts              ← ItemView: chat sidebar panel (render, update)
    settings.ts          ← PluginSettingTab: gateway URL + token
    websocket.ts         ← WS client: connect, reconnect, heartbeat
    chat.ts              ← Chat state: messages[], send, receive
    context.ts           ← Active note helper: getActiveNoteContent()
    models.ts            ← Agent/model selector state és optionok
    types.ts             ← Shared interfaces (Message, Settings, etc.)
```

### Step 2.1 — manifest.json + package.json + tsconfig

**manifest.json kulcs mezők:**
```json
{
  "id": "obsidian-openclaw-chat",
  "name": "OpenClaw Chat",
  "version": "0.1.0",
  "minAppVersion": "1.0.0",
  "description": "Chat with OpenClaw AI agents directly from Obsidian",
  "author": "Rix Beck",
  "authorUrl": "https://openclaw.ai",
  "isDesktopOnly": false
}
```

**Kritikus:** `id` kisbetűs, kötőjeles. Obsidian a `manifest.json`-t keresi a plugin gyökerében.

**package.json devDependencies:**
```json
{
  "obsidian": "latest",
  "@types/node": "^20",
  "esbuild": "^0.20",
  "typescript": "^5"
}
```

**tsconfig:** `"target": "ES6"`, `"lib": ["ES6", "DOM"]`, `"moduleResolution": "bundler"`.

---

### Step 2.2 — types.ts

```typescript
export interface OpenClawSettings {
  gatewayUrl: string;    // ws://localhost:8765
  authToken: string;
  defaultAgent: string;  // 'main' | 'senilla'
  includeActiveNote: boolean;
}

export interface ChatMessage {
  id: string;
  role: 'user' | 'assistant' | 'system';
  content: string;
  timestamp: number;
}
```

---

### Step 2.3 — settings.ts

`PluginSettingTab` extend:
- Gateway URL input (default: `ws://localhost:8765`)
- Token input: **password type**, nem plain text
- Agent selector: dropdown (main / senilla)

**Gotcha:** Token redaction → `display: none` vagy password input. Soha ne logolj token értéket.

---

### Step 2.4 — websocket.ts

```typescript
class ObsidianWSClient {
  private ws: WebSocket | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private readonly RECONNECT_DELAY = 3000;
  private readonly HEARTBEAT_INTERVAL = 30000;

  connect(url: string, token: string): void
  disconnect(): void
  send(message: WSMessage): void
  private scheduleReconnect(): void
  private startHeartbeat(): void
  onMessage: (msg: WSMessage) => void
  onConnected: () => void
  onDisconnected: () => void
}
```

**Protokoll flow:**
1. `connect()` → new WebSocket
2. `onopen` → küld `{ type: 'auth', payload: { token, sessionId, agentId } }`
3. Auth success → `onConnected()`
4. `scheduleReconnect()` on close (nem intentional disconnect esetén)
5. Heartbeat: 30s-onként `{ type: 'ping' }`, vár `pong`-ot

**Kritikus Obsidian-specifikus korlát:**
- Obsidian pluginban `window.WebSocket` elérhető (nem Node.js `ws`!)
- Ne importáld a `ws` npm csomagot az Obsidian pluginba

---

### Step 2.5 — chat.ts

```typescript
class ChatManager {
  private messages: ChatMessage[] = [];
  
  addMessage(msg: ChatMessage): void
  getMessages(): readonly ChatMessage[]
  clear(): void
  onUpdate: (messages: ChatMessage[]) => void  // UI refresh callback
}
```

---

### Step 2.6 — context.ts

```typescript
export function getActiveNoteContext(app: App): { title: string; content: string } | null
```

- `app.workspace.getActiveFile()` → fájl elérési út + tartalom
- `app.vault.read(file)` → async content
- Ha nincs aktív note → `null`

---

### Step 2.7 — view.ts (ChatView)

`ItemView` extend (`VIEW_TYPE_OPENCLAW_CHAT = 'openclaw-chat'`):

```
[Fejléc: "OpenClaw Chat"]
[Agent dropdown: main / senilla       ▼]
┌─────────────────────────────────────┐
│ assistant: Szia! Miben segíthetek?  │
│                                     │
│ user: Mi a főváros?                 │
│ assistant: Budapest.                │
└─────────────────────────────────────┘
[☑ Include active note]
[________________________] [Küldés]
```

**Rendering:**
- Messages: `div.oclaw-messages` → scroll to bottom on new message
- Markdown rendering: `MarkdownRenderer.render()` (Obsidian API)

---

### Step 2.8 — main.ts

```typescript
export default class OpenClawPlugin extends Plugin {
  settings: OpenClawSettings;
  wsClient: ObsidianWSClient;
  chatManager: ChatManager;

  async onload(): Promise<void>    // ribbon + view register + WS init
  async onunload(): Promise<void>  // WS disconnect
  async loadSettings(): Promise<void>
  async saveSettings(): Promise<void>
}
```

**Ribbon:** `addRibbonIcon('message-square', 'OpenClaw Chat', ...)`

---

### Step 2.9 — esbuild.config.mjs

```javascript
import esbuild from 'esbuild';
await esbuild.build({
  entryPoints: ['src/main.ts'],
  bundle: true,
  external: ['obsidian', 'electron', '@codemirror/*', '@lezer/*'],
  format: 'cjs',
  outfile: 'main.js',
  platform: 'browser',
  sourcemap: 'inline',
  target: 'es6',
});
```

**Kritikus:** `external: ['obsidian']` – az Obsidian API-t nem bundleoljuk be.

---

### Step 2.10 — styles.css (alap)

```css
.oclaw-chat-view { display: flex; flex-direction: column; height: 100%; }
.oclaw-messages { flex: 1; overflow-y: auto; padding: 8px; }
.oclaw-message { margin-bottom: 8px; padding: 6px 10px; border-radius: 6px; }
.oclaw-message.user { background: var(--interactive-accent); color: var(--text-on-accent); }
.oclaw-message.assistant { background: var(--background-secondary); }
.oclaw-input-row { display: flex; gap: 8px; padding: 8px; }
.oclaw-input { flex: 1; }
```

---

## Files Touched

### Channel plugin (fixes)
| Fájl | Változás |
|------|---------|
| `channel-plugin/src/index.ts` | `registerRPCMethods(ctx)` import + hívás hozzáadva |
| `channel-plugin/src/channel.ts` | outbound sendMessage → rpc.sendMessage hívás |
| `channel-plugin/src/rpc.ts` | `broadcastMessage` export hozzáadva |
| `channel-plugin/src/types.ts` | esetleges típus bővítés |
| `channel-plugin/src/auth.test.ts` | **ÚJ** unit tesztek |
| `channel-plugin/src/session.test.ts` | **ÚJ** unit tesztek |
| `channel-plugin/src/rpc.test.ts` | **ÚJ** unit tesztek |
| `channel-plugin/src/service.test.ts` | **ÚJ** integration smoke |

### Obsidian plugin (új)
| Fájl | Változás |
|------|---------|
| `obsidian-plugin/manifest.json` | **ÚJ** |
| `obsidian-plugin/package.json` | **ÚJ** |
| `obsidian-plugin/tsconfig.json` | **ÚJ** |
| `obsidian-plugin/esbuild.config.mjs` | **ÚJ** |
| `obsidian-plugin/styles.css` | **ÚJ** |
| `obsidian-plugin/src/main.ts` | **ÚJ** |
| `obsidian-plugin/src/view.ts` | **ÚJ** |
| `obsidian-plugin/src/settings.ts` | **ÚJ** |
| `obsidian-plugin/src/websocket.ts` | **ÚJ** |
| `obsidian-plugin/src/chat.ts` | **ÚJ** |
| `obsidian-plugin/src/context.ts` | **ÚJ** |
| `obsidian-plugin/src/models.ts` | **ÚJ** |
| `obsidian-plugin/src/types.ts` | **ÚJ** |

### Knowledge (első bejegyzések)
| Fájl | Változás |
|------|---------|
| `.github/compeng/knowledge/gotchas/openclaw-plugin-cannot-import-internals.md` | **ÚJ** |
| `.github/compeng/knowledge/gotchas/obsidian-plugin-no-node-ws.md` | **ÚJ** |
| `.github/compeng/knowledge/patterns/openclaw-plugin-development-sources.md` | **ÚJ** |

---

## Test Plan

### Channel plugin tesztek (vitest)
```bash
cd channel-plugin && npm test
```
- auth.test.ts: 5 eset
- session.test.ts: 3 eset  
- rpc.test.ts: 5 eset
- service.test.ts: 5 integration smoke

### Obsidian plugin manuális smoke test
1. Build: `cd obsidian-plugin && npm run build`
2. Copy `main.js`, `manifest.json`, `styles.css` → `~/.obsidian/plugins/obsidian-openclaw-chat/`
3. Obsidian → Settings → Community Plugins → Enable "OpenClaw Chat"
4. Ribbon ikon megjelenik
5. Settings → Gateway URL: `ws://localhost:8765`, Token: `<test-token>`
6. Channel plugin gateway indítása
7. Sidebar megnyílik, WS csatlakozik, üzenet küldhető/fogadható

---

## Rollback Plan

- Channel plugin fix: `git revert` az érintett kommitokra
- Obsidian plugin: `rm -rf obsidian-plugin/` + Obsidian-ban disable

---

## Acceptance Criteria

- [ ] `npm test` a channel pluginban zöld (min. 18 teszt)
- [ ] `registerRPCMethods` meghívásra kerül (`index.ts`-ben)
- [ ] `channel.ts` outbound sendMessage WS-en valóban küld
- [ ] Obsidian pluginban `manifest.json` + `main.js` buildelhető
- [ ] Sidebar chat panel megnyílik Obsidian-ban
- [ ] WS auth flow működik (token ellenőrzés)
- [ ] Token nem kerül semmilyen logba
- [ ] WS reconnect 3s delay után automatikusan

---

## Risks and Open Questions

| Kockázat / Kérdés | Mitigation |
|---|---|
| `runtime.registerRPC` / `runtime.registerChannel` API formátuma nem ismert | Guard + log warn; echo fallback-kel tesztelhető |
| Obsidian reviewer: `isDesktopOnly` kérdéses | Egyelőre `false`; ha Node.js dep kerülne be, `true`-ra módosítandó |
| WS heartbeat timeout: ha a pong késik, reconnect trigger | Timeout értéket teszttel validálni (30s + 5s grace) |
| Channel plugin `activeSessions` in-memory → gateway restart esetén elvész | MVP-ben elfogadható; Phase 3: persistence |

---

## Sorrend (work agent számára)

**Prioritás:**
1. B1 fix (`index.ts` RPC wiring) – 5 perc
2. B2 fix (`channel.ts` outbound) – 10 perc
3. B3 `broadcastMessage` hozzáadása – 10 perc
4. Tesztek (auth, session, rpc, service) – 60-90 perc
5. Obsidian plugin scaffold – 2-3 óra
6. Knowledge capture – 20 perc
