---
status: draft
type: review
repo: obsidian-oclaw-chat
branch: develop
commit: 9286ac8
plan: compeng/plans/20260226-1025-spinner-styling.md
run: compeng/runs/20260226-1026-spinner-styling.md
date: 2026-02-26
---

# Review — Obsidian plugin: Send→Stop + theme-safe spinner ring + `chat.abort`

## Scope
Commit **9286ac8** (“obsidian-plugin: Stop button + theme-safe spinner ring; chat.abort”).

Files:
- `obsidian-plugin/src/view.ts`
- `obsidian-plugin/src/websocket.ts`
- `obsidian-plugin/styles.css`
- `obsidian-plugin/main.js` (built output)

Goal recap:
- Spinner must be clearly visible in light mode.
- While waiting: Send button becomes **Stop** with **red stop icon** + **spinning ring**.
- Clicking Stop must **abort the in-flight run** via gateway (WS/RPC) and restore Send state.
- Stop mechanism must follow **OpenClaw core contract** (source-of-truth: `openclaw.src/ui/.../chat.ts` → `chat.abort`).

## High-level assessment
This is a good, minimal change set:
- UI: clear, theme-safe spinner that should be visible in both light/dark.
- Contract: uses `chat.abort({sessionKey, runId})` with fallback `{sessionKey}`.
- Behavior: button stays enabled while “working”, so Stop is always available.

Main correctness risk is **runId mapping**: the plugin sets `activeRunId` to the local `runId` it generates and sends it as `idempotencyKey`. This matches the WebChat approach, but only if the gateway continues to accept `runId` as the idempotencyKey value for `chat.abort`.

## Findings

### MUST-FIX
None identified from the current diff.

### SHOULD-FIX
1) **Avoid false “Stopped” success if abort doesn’t actually cancel**
- Current: `abortActiveRun()` returns `true` if the RPC request succeeds (i.e., gateway accepted the request), and the view appends **“⛔ Stopped”**.
- But: success of the RPC call doesn’t guarantee the underlying model/run has actually stopped (race conditions; run already finished; gateway implementation differences).
- Suggestion:
  - Prefer messaging like **“Stop requested”** unless/until you observe a terminal `payload.state === 'aborted'`.
  - Or: append “⛔ Stopped” only when an `aborted` event is observed.

2) **Race / multi-run behavior: activeRunId is “last send”, not necessarily “current run”**
- If user sends multiple messages quickly (or retry logic exists elsewhere), `activeRunId` will be overwritten.
- Depending on gateway semantics, you might abort the wrong run.
- Suggestion: ensure “working” mode forbids initiating a second send while working (UI likely does already via `isWorking`, but now the button is enabled, so code relies on `_handleSend()` branching). Verify there is no other send trigger (e.g., Enter key handler) that still sends while working.

3) **Working state clearing: clear on abort request vs clear on terminal event**
- Current behavior clears UI immediately in `finally { this._setWorking(false) }`, which is good UX (button restores instantly).
- But it can create confusion if output continues streaming for a moment (gateway/model lag).
- Suggestion: consider a short “stopping…” intermediate state, or keep Stop visible until `aborted` (tradeoff UX vs accuracy).

4) **Event filtering might hide useful partial assistant output**
- You filter out any non-`final` and non-`aborted` states to avoid double-render.
- If “aborted” includes a partial assistant message, you allow it; if not, you render nothing.
- This is fine, but you should confirm gateway doesn’t send a distinct terminal state like `error`/`failed` that you now drop. If it does, you’ll get a stuck “working” unless some other path clears it.
  - In this diff, you clear working when you see `payload.state` of final/aborted; but if gateway ends with some other terminal, it will be filtered.
- Suggestion: treat other known terminal states as terminal too (if they exist), or clear working when you receive a `chat.event` with `state` in a terminal set `{final, aborted, error, failed}`.

### NICE-TO-HAVE
1) **A11y: keep a visible text label next to icon**
- Right now, during working you replace text with icon-only. You did add `aria-label` to the button — good.
- Consider keeping “Stop” text (or tooltip) visible for clarity.

2) **Unit tests for abort behavior (minimal harness)**
- There is no `npm test` script for the obsidian plugin.
- Add a minimal unit test setup (vitest) for `ObsidianWSClient.abortActiveRun()`:
  - abort sends `chat.abort` with `{sessionKey, runId}` when activeRunId exists
  - abort sends with `{sessionKey}` when runId absent
  - activeRunId cleared + working cleared on success and failure

3) **Docs / README note**
- Document the gateway dependency: Stop requires gateway support for `chat.abort` and using `idempotencyKey` as `runId`.

## Security notes
- No secrets introduced.
- `console.error('[oclaw-ws] chat.abort failed', err)` is acceptable; just ensure errors don’t accidentally include tokens (depends on underlying error objects).
- XSS: this change does not directly add new HTML rendering pathways; still worth ensuring `ChatManager` escapes/uses `setText`.

## Performance notes
- CSS spinner uses a simple transform animation; negligible.
- DOM updates: only when toggling working state.

## API/contract notes
- Contract aligns with OpenClaw WebChat controller (`chat.abort` with `{sessionKey, runId}`), and uses a sensible fallback.
- Risk: if gateway changes to a different canonical `runId` (server-generated), then aborting by idempotencyKey may stop working. If gateway emits/returns canonical runId in response, consider storing that instead.

## Smoke-test checklist (manual)
- Light theme: ring visible on white background.
- Dark theme: ring still visible.
- While streaming: button shows Stop and remains clickable.
- Stop: output stops (or soon stops), and UI returns to Send.
- Stop when not working: no-op.
- Stop when disconnected: no crash, shows error.

## Recommendation
✅ **Approve** with the “Should-fix” items tracked, especially the messaging semantics (“Stop requested” vs “Stopped”) and the terminal state filtering robustness.
