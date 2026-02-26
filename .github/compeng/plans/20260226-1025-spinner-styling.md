---
title: "obsidian-oclaw-chat: spinner styling + Stop button while waiting"
date: 2026-02-26
author: Wall-e
status: draft
project: obsidian-oclaw-chat
---

## Issue
In light UI mode (white background) the current “working” spinner inside the Send button is not visible.

## Goals
1. **Clear visuals**: spinner clearly represents “agent is working” in both light and dark Obsidian themes.
2. **New action button state**: while waiting for the assistant response, the Send button transforms into a **Stop** button.
3. **Stop UX**:
   - Stop button shows a **red stop icon** (center) surrounded by a **spinning colored ring**.
   - Clicking Stop **breaks the in-flight chat request**, sends a **stop event** to the gateway, then restores the Send state.

## Non-goals / Out of scope
- Redesigning the full chat UI.
- Implementing multi-request concurrency (we keep current “single in-flight request” model).
- Changing gateway auth/pairing behavior.

## Context / Knowledge artifacts applied
- Device pairing is separate from auth token; UI must not assume stop works without paired write scopes.
  - Ref: `compeng/knowledge/gotchas/gateway-token-vs-device-pairing.md`
- Prefer public WS/RPC methods; avoid importing core internals.
  - Ref: `compeng/knowledge/patterns/openclaw-plugin-development-sources.md`
- Add tests where possible for plugin lifecycle & state handling.
  - Ref: `compeng/knowledge/checklists/tests.md`

## Current implementation (baseline)
- Obsidian view state tracks:
  - `isConnected` (WS state)
  - `isWorking` (set true after `chat.send` ack; set false on first final assistant message; safety timeout 120s)
- `src/view.ts::_updateSendButton()`:
  - disables button when `isWorking`
  - replaces innerHTML with `.oclaw-spinner`
- `styles.css` spinner uses **white** borders, poor contrast on light theme.

## Proposed UX + UI states
### Button states
1. **Disconnected**
   - Label: “Send”
   - Disabled: yes
2. **Ready (connected, not working)**
   - Label: “Send”
   - Disabled: no
3. **Working (connected, request in-flight)**
   - Label/icon: **Stop** (red stop icon)
   - Spinner: **ring around icon** (theme-safe colors)
   - Disabled: **no** (must be clickable)
   - `aria-busy=true`, plus `aria-label="Stop"`

### Visual spec (CSS)
- Ring color should be based on Obsidian variables:
  - `--interactive-accent` for the active arc
  - `--text-muted` or `--background-modifier-border` for the base ring
- Stop icon color: `--color-red` (fallback to a hardcoded red if var missing)
- Provide good contrast in both modes.

## Gateway stop semantics (contract)
We need a stable, supported way to cancel an in-flight assistant generation.

### Confirmed contract (from openclaw.src)
- **WS/RPC method:** `chat.abort`
- **Params:**
  - preferred: `{ sessionKey, runId }`
  - fallback: `{ sessionKey }` (abort active run for session)

Source of truth:
- `openclaw.src/ui/src/ui/controllers/chat.ts` → `abortChatRun()` calls:
  - `client.request("chat.abort", runId ? { sessionKey, runId } : { sessionKey })`

Implication for this plugin:
- We will treat our existing `idempotencyKey` (generated in `sendMessage`) as the **runId** for aborting.

### Implementation intent
- Track the last in-flight request identifiers:
  - `sessionKey` (already known)
  - `runId` (store the last `idempotencyKey` we used for `chat.send`)
- On Stop click:
  1) send `chat.abort({ sessionKey, runId })`
  2) transition UI to not-working state immediately (optimistic), with a system message only if gateway rejects
  3) restore Send button

## Technical plan

### Files likely to change
- `obsidian-oclaw-chat/obsidian-plugin/src/view.ts`
- `obsidian-oclaw-chat/obsidian-plugin/src/websocket.ts`
- `obsidian-oclaw-chat/obsidian-plugin/styles.css`
- (optional) `obsidian-oclaw-chat/obsidian-plugin/src/types.ts` (if we add typed stop payload)
- (optional) tests: create `obsidian-oclaw-chat/obsidian-plugin/src/__tests__/...` or minimal `node --test` harness depending on current setup

### Step-by-step
1) **Identify stop/cancel WS method**
   - Search OpenClaw docs / core for method name and expected params.
   - Decide what request identifier we need to store (idempotencyKey may not be sufficient).

2) **WebSocket client: add stop API** (`src/websocket.ts`)
   - Track an in-flight “request handle” when `sendMessage()` succeeds:
     - store `idempotencyKey` (already generated)
     - store any gateway-returned ids from `chat.send` response payload (if available)
   - Add `stop()` method:
     - If not working: no-op
     - Else: call `_sendRequest(<stopMethod>, <params>)`
     - Regardless of result, ensure we don’t leave UI stuck in working state:
       - set working false
       - disarm working timeout

3) **View layer: change button behavior** (`src/view.ts`)
   - When `isWorking`:
     - **do not disable** the button.
     - Change click handler to stop (or branch in handler):
       - if working → call `this.plugin.wsClient.stop()`
       - else → existing send flow
   - Update accessibility:
     - `aria-label` changes between Send/Stop
     - keep `aria-busy` as today

4) **CSS: theme-safe spinner + stop icon** (`styles.css`)
   - Replace `.oclaw-spinner` colors to use Obsidian vars (not hardcoded white).
   - Add new markup/CSS classes, e.g.:
     - `.oclaw-send-btn.is-working` contains:
       - `.oclaw-spinner-ring` (spinning ring)
       - `.oclaw-stop-icon` (static red square)
   - Ensure layout is stable (no button size jump between Send and Stop).

5) **Failure handling / edge cases**
   - If stop is clicked and WS is disconnected: show Notice/system message, restore Send.
   - If stop request fails (gateway rejects): show system message but still restore Send.
   - If assistant final arrives right as Stop is clicked: ensure state transitions are idempotent.

6) **Tests (minimum viable)**
   - Unit-ish tests for view state logic (if harness exists) OR simple tests for WS client state machine:
     - `sendMessage()` sets working true only after ack
     - receiving final assistant message sets working false
     - `stop()` sets working false and calls the configured method with expected params
   - Manual smoke test in Obsidian:
     - Light + dark themes: spinner ring visible
     - Stop button clickable while working
     - Stop cancels the generation (gateway stops streaming / returns final)

## Acceptance criteria
- In **light theme**, the working indicator is clearly visible on the button.
- While waiting for response, button is **Stop** with:
  - red stop icon
  - animated spinning ring
- Clicking Stop:
  - sends a stop/cancel request to gateway
  - stops the assistant response (no further deltas/finals after cancellation, or gateway emits a clear cancellation event)
  - restores Send button state
- No regressions:
  - Send still works
  - Disconnected state still disables Send

## Risks & mitigations
- **Unknown gateway stop API**: we must confirm method + identifiers; otherwise we can only “UI cancel” which would be misleading.
  - Mitigation: implement stop only after method confirmation; fallback to disabling further UI updates only if explicitly accepted.
- **Race conditions**: stop vs final arrival.
  - Mitigation: make state transitions idempotent; guard with `if (!working) return` checks.

## Rollback plan
- Keep changes localized to button rendering + WS stop method.
- If stop integration is unstable, revert to previous behavior:
  - spinner-only working state
  - button disabled while working

