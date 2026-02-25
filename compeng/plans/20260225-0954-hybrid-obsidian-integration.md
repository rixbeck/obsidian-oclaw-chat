---
status: draft
priority: high
tags: [obsidian, channel-plugin, community-plugin, hybrid-architecture, websocket, gateway-rpc]
owner: Rix
created: 2026-02-25
estimated_hours: 20-28
---

# Plan — Hybrid Obsidian integráció (OpenClaw Channel + Obsidian Community Plugin)

## 0) Issue (inline)

### Probléma / kontextus
- Jelenleg **nincs natív Obsidian felület** OpenClaw agentekhez.
- Nincs **bidirectional / push** csatorna: az agent nem tud proaktívan üzenni Obsidian-ba.
- A note/vault kontextus és a chat szét van esve (Telegram ↔ Obsidian).

### Javaslat (megoldás)
**Hybrid architektúra:**
1) **OpenClaw Channel plugin** (gateway extension) = üzenet-csatorna + session routing + RPC.
2) **Obsidian Community plugin** = rich UI + vault műveletek + kliens oldali WS.

### Előnyök
- Rich UI (sidebar chat panel, model/agent selector, később @mentions/quick commands).
- Bidirectional kommunikáció + proaktív push (Alfred OS workflow-k eredményei is küldhetők).
- Egységesebb session-logika (nem per-note fragmentáció).
- Vault műveletek (active note context, később insert/apply).

### Kockázatok
- Két komponens kompatibilitás/ verziózás.
- WebSocket connection management (reconnect, heartbeat).
- Obsidian community review / distribution kockázat.

---

## 1) Célok / kimenetek

### Must-have (MVP)
**Channel plugin (OpenClaw):**
- WS szerver, amihez az Obsidian plugin csatlakozik.
- Auth: gateway token (MVP).
- Inbound: Obsidian → agent (chat üzenet + opcionális context).
- Outbound: agent → Obsidian (push üzenet/stream).
- RPC: `obsidian.sendMessage`, `obsidian.listAccounts` (minimum).

**Obsidian plugin:**
- Sidebar chat UI (Copilot-szerű baseline).
- Settings: gateway URL + token.
- Chat send/receive (streaming megjelenítéssel, ha támogatott).
- "Include current note" checkbox: active note tartalom beküldése contextként.
- Agent/model selector (legalább: main/senilla).

### Nice-to-have (Phase 3+)
- @mentions (note/folder context hivatkozás, Copilot pattern).
- „Insert into note” + quick commands (apply changes).
- Conversation history perzisztencia (note-based vagy DB).
- Tool-calling jellegű vault search approval flow (ChatGPT MD mintára).

---

## 2) Non-goals
- Nem cél azonnal teljes Copilot feature-parity.
- Nem cél OAuth/SSO az MVP-ben.
- Nem cél multimodal (PDF/image/video) az MVP-ben.

---

## 3) UX (felhasználói élmény)

### MVP
- Ribbon icon → megnyitja a chat sidebar-t.
- Chat input + message list.
- Dropdown: agent (main/senilla).
- Checkbox: include active note.

### Proaktív üzenetek
- Agent/Temporal workflow eredmény → megjelenik a sidebar-ban (és opcionális Obsidian Notice).

---

## 4) Architektúra

### 4.1 Komponensek
- **obsidian-channel** (OpenClaw plugin): channel registration + WS service + RPC.
- **obsidian-openclaw** (Obsidian plugin): UI + WS client + vault access.

### 4.2 Üzenetfolyamok
**User → Agent:** Obsidian UI → WS → channel plugin → OpenClaw session → válasz → WS → UI.

**Agent → User:** agent → RPC `obsidian.sendMessage` → channel plugin → WS → UI.

### 4.3 Hard rule-ok (knowledge alkalmazása)
- **Nem importálunk OpenClaw core belső modulokat** (ERR_PACKAGE_PATH_NOT_EXPORTED).
  - Ref: `compeng/knowledge/gotchas/openclaw-plugin-cannot-import-internals.md`
- Preferált: publikus WS/RPC + saját vékony validáció.
  - Ref: `compeng/knowledge/patterns/openclaw-plugin-development-sources.md`

---

## 5) Implementáció (fájlok / érintett területek)

### OpenClaw channel plugin
- `openclaw.plugin.json`
- `package.json` (`openclaw.extensions` entry)
- `src/index.ts` (register)
- `src/channel.ts` (meta/capabilities/config/outbound)
- `src/service.ts` (WS server)
- `src/rpc.ts` (RPC methods)
- `src/auth.ts` (token validate)
- `src/session.ts` (routing)
- `src/*.test.ts` (vitest)

### Obsidian community plugin
- `manifest.json`
- `src/main.ts`, `src/view.ts`, `src/settings.ts`
- `src/websocket.ts`, `src/chat.ts`, `src/context.ts`, `src/models.ts`
- `styles.css`
- build: esbuild

### OpenClaw config
- `~/.openclaw/openclaw.json`: `channels.obsidian` blokk (enabled, wsPort, accounts)

---

## 6) Lépések (high-level)

### Phase 1 — Channel plugin (8–12h)
1. Skeleton + registerChannel
2. WS service (auth, connect/disconnect, message schema)
3. Inbound dispatch (Obsidian → session)
4. Outbound sendText (session → Obsidian)
5. RPC: sendMessage + listAccounts
6. Unit + integration smoke

### Phase 2 — Obsidian plugin (12–16h)
1. Skeleton (view + ribbon + settings)
2. WS client (reconnect + heartbeat)
3. Chat UI (render + markdown)
4. Include active note context
5. Agent selector
6. E2E smoke

---

## 7) Test plan
- Unit: WS auth, message parsing, reconnect logic.
- Integration: end-to-end chat flow + agent-initiated push.
- Security: token redaction, no secrets in logs.

Ref: `compeng/knowledge/checklists/tests.md`

---

## 8) Rollback
- OpenClaw: plugin uninstall + gateway restart.
- Obsidian: disable/remove plugin folder.

---

## 9) Acceptance criteria
- Obsidian sidebar-ból üzenet → agent válasz visszajön és látszik.
- Agent képes proaktívan üzenni (RPC `obsidian.sendMessage`).
- WS reconnect működik (gateway restart után automatikus reconnect).
- Token nem kerül logba.

---

## 10) Linkek / inspiráció
- Copilot for Obsidian: https://github.com/logancyang/obsidian-copilot
- Obsidian AI Reviewer: https://github.com/VozVule/av-obisidian-ai-plugin
- ChatGPT MD: https://github.com/bramses/chatgpt-md
- OpenClaw channel plugin guide: https://docs.openclaw.ai/cli/channels
