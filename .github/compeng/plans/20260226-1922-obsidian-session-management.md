---
type: plan
status: approved
created: 2026-02-26T19:22:00+01:00
repo: obsidian-oclaw-chat
branch: develop
owner: Rix
scope:
  - obsidian-plugin/src/websocket.ts
  - obsidian-plugin/src/main.ts
  - obsidian-plugin/src/view.ts
  - obsidian-plugin/src/types.ts
  - obsidian-plugin/src/settings.ts
  - obsidian-plugin/src/*.test.ts
---

# Plan — Session management (select existing sessions + start new session)

## Goal
In the Obsidian client we want:
1) **Select** from already-running OpenClaw sessions that belong to the Obsidian channel/client.
2) **Start a new session** (practically: choose a new sessionKey and begin using it).

## Assumptions (based on OpenClaw source-of-truth)
- Gateway WS/RPC supports `sessions.list` (used by OpenClaw Web UI): `client.request("sessions.list", { includeGlobal, includeUnknown, activeMinutes?, limit? })`.
- Chat send/receive already uses `sessionKey` as the routing key.
- A “new session” likely does not require explicit create; it can be created lazily when first used (via `chat.send` + later events), but we’ll confirm during implementation.

## UX
### A) Session picker (in chat view)
- Add a compact row above messages:
  - `Select` dropdown: shows sessions (label/displayName/key)
  - `Refresh` button: re-fetch sessions
  - `New…` button: prompts for a new sessionKey string

### B) Switching sessions
- When user selects a session:
  - persist `settings.sessionKey`
  - insert a **session divider** into the current chat log (no clearing), e.g. `[Session: <short>] —————` with hover = full key
  - reconnect WS client so:
    - outbound `chat.send` goes to the selected sessionKey
    - inbound `chat` events are filtered to the selected sessionKey

### C) Starting a new session
- Clicking `New…` prompts for sessionKey (default suggestion: `obsidian-YYYYMMDD-HHMM` or similar)
- On confirm:
  - switch to that sessionKey
  - (optional) send a first “system hello” or just wait for first user message

## Decisions (locked)
1) **Chat history model**
   - Do **not** clear messages on session switch.
   - Insert a styled **session divider** message at the start of the newly selected session.

2) **Filtering sessions “belonging to Obsidian”**
   - Filter rows where `row.channel === 'obsidian'` OR `row.key.includes(':obsidian:')`.
   - Provide an “Include non-obsidian” toggle only if needed.

## Implementation

### 1) WS client support (`obsidian-plugin/src/websocket.ts`)
Add public methods:
- `setSessionKey(sessionKey: string): void`
  - update internal `this.sessionKey`
  - clear `activeRunId/abortInFlight/working`

- `listSessions(opts?: { activeMinutes?: number; limit?: number; includeUnknown?: boolean; includeGlobal?: boolean }): Promise<SessionsListResult>`
  - call `_sendRequest('sessions.list', params)`
  - **types:** define minimal `SessionsListResult` + `GatewaySessionRow` in plugin `types.ts` (only needed fields)

### 2) Plugin orchestration (`obsidian-plugin/src/main.ts`)
Add helper:
- `async switchSession(sessionKey: string): Promise<void>`
  - validate non-empty
  - `this.settings.sessionKey = sessionKey; await saveSettings()`
  - `this.wsClient.disconnect()`
  - `this.wsClient.setSessionKey(sessionKey)`
  - `this._connectWS()`
  - `this.chatManager.addMessage(ChatManager.createSessionDivider(sessionKey))`

### 3) UI (`obsidian-plugin/src/view.ts`)
- Add UI elements:
  - dropdown + refresh + new buttons
- On open:
  - load sessions list and populate dropdown
  - set current selection based on `plugin.settings.sessionKey`
- On refresh:
  - call `wsClient.listSessions()`
  - filter + render
- On selection change:
  - call `plugin.switchSession(key)`

### 4) Settings (`obsidian-plugin/src/settings.ts`)
- Keep existing `Session Key` text field for manual edit.
- Add note: “Session picker exists in chat view; this field is the default.”

### 5) Tests
- Unit tests for `listSessions()` frame formatting (mock `_sendRequest` via seam or expose test helper)
- Unit tests for `setSessionKey()` effects:
  - clears working/run state

## Gates
- typecheck
- tests
- build

## Risks
- session list might include sensitive sessions; filter defaults to obsidian-only.
- switching sessions while a run is in-flight: ensure we abort UI state (and optionally call `chat.abort` first).
