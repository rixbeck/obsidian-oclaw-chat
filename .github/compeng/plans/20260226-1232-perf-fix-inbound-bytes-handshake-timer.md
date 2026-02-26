---
type: plan
status: approved
created: 2026-02-26T12:32:00+01:00
repo: obsidian-oclaw-chat
branch: develop
scope:
  - obsidian-plugin/src/websocket.ts
  - obsidian-plugin/src/websocket.test.ts
---

# Plan — Fix inbound frame size guard + handshake timer cleanup

## Goal
Address two MUST items from perf review:
1) Inbound frame “bytes” guard is not byte-accurate and skips non-string WS payloads.
2) Handshake timeout timer is not cleared on close/error → possible timer leak / stray closes.

## Non-goals
- Redesign reconnect/backoff strategy.
- Broad refactors of test architecture (separate follow-up).

## Changes
### A) Inbound frame size guard (byte-accurate, all payload types)
- Add a small helper in `src/websocket.ts` to normalize WS `event.data` into a string and compute size:
  - `string` → measure bytes via `TextEncoder().encode(str).byteLength` and parse.
  - `Blob` → check `blob.size` (bytes) before reading; then `await blob.text()`.
  - `ArrayBuffer` → use `byteLength` and decode via `TextDecoder`.
  - Unknown types → log + ignore (or close).
- Enforce `MAX_INBOUND_FRAME_BYTES` consistently across all cases.

### B) Handshake timer cleanup
- Ensure the handshake timer is cleared in:
  - `ws.onclose`
  - `ws.onerror` (or error path leading to reconnect)
  - and on successful connection (already does)

## Tests
Add/extend unit tests in `src/websocket.test.ts`:
- Oversize inbound frame closes connection:
  - string oversize
  - ArrayBuffer oversize (if test harness supports it)
- Handshake timer cleared on close before timeout fires (use fake timers).

## Gates
- `npm -C obsidian-plugin run typecheck`
- `npm -C obsidian-plugin run test:once`
- `npm -C obsidian-plugin run build`

## Risks / rollback
- Risk: async `onmessage` handler changes ordering. Keep it minimal and do not introduce awaits on normal string frames.
- Rollback: revert commit(s) affecting websocket handler + tests.
