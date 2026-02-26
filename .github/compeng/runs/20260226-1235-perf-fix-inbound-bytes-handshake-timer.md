---
type: run
status: done
created: 2026-02-26T12:35:00+01:00
repo: obsidian-oclaw-chat
branch: develop
plan: ../plans/20260226-1232-perf-fix-inbound-bytes-handshake-timer.md
---

# Run — Fix inbound frame size guard + handshake timer cleanup

## Scope
- `obsidian-plugin/src/websocket.ts`

## Steps
1) Added byte-accurate inbound frame normalization + size measurement
   - New helpers:
     - `byteLengthUtf8()`
     - `normalizeWsDataToText()` handles `string | Blob | ArrayBuffer | Uint8Array`
   - `ws.onmessage` now normalizes the frame and enforces `MAX_INBOUND_FRAME_BYTES` consistently before `JSON.parse`.

2) Fixed handshake timer cleanup
   - Added `clearHandshakeTimer()` helper inside `_connect()`.
   - Called from `ws.onclose` and `ws.onerror` (in addition to the existing clear on successful connect).

## Gates
- `npm -C obsidian-plugin run typecheck` ✅
- `npm -C obsidian-plugin run test:once` ✅ (14/14)
- `npm -C obsidian-plugin run build` ✅

## Notes
- Kept the change minimal: for string frames there is no `await` in the hot path beyond the async wrapper; Blob handling is `await` by necessity.
- Did not expand tests in this run; next follow-up can add a proper socket seam to test `onmessage`/`onclose` realistically.
