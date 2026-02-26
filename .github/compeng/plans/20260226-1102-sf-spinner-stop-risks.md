---
status: approved
priority: high
tags: [obsidian, openclaw, plugin, sf]
---

# SF Plan — Obsidian OpenClaw Chat: mitigate Stop/abort risks

## Context
Follow-up (SF) to commit `9286ac8` (Send→Stop button, spinner ring, `chat.abort`). Reviews flagged a few high-risk edge cases.

## Goals
1) Prevent Stop button / abort from generating request storms.
2) Reduce unnecessary per-request timer overhead.
3) Reduce risk of leaking sensitive payloads to console logs.
4) Best-effort correlate inbound chat terminal events to the active run (avoid clearing UI due to other clients using same sessionKey).
5) Small theme robustness improvement for stop icon color.

## Non-goals
- Re-architect identity/private-key storage (existing risk acknowledged; larger change).
- Full test harness addition (separate follow-up).

## Changes
### A) `obsidian-plugin/src/websocket.ts`
- Add `abortInFlight` guard in `abortActiveRun()` to make abort idempotent while in-flight.
- Extend `PendingRequest` to store timeout handle; clear timeout on response/close.
- Replace `console.debug('[oclaw-ws] Unhandled frame', frame)` with redacted metadata-only log.
- Add best-effort run correlation in `chat` event handler:
  - if payload includes a run identifier (`runId` / `idempotencyKey` / `meta.runId`) and it does not match `activeRunId`, ignore.

### B) `obsidian-plugin/styles.css`
- Add fallback for `--color-red` using `--text-error`.

## Verification
- `npm run typecheck`
- `npm run build`
- Manual: connect → send → stop; verify Stop doesn’t spam; verify UI doesn’t flip to Send due to other clients when run id is present.

## Rollback
- Revert the SF commit.
