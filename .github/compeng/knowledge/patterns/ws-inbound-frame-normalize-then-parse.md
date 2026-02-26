---
type: pattern
created: 2026-02-26T12:33:00+01:00
tags: [websocket, robustness, dos-guard]
---

# Pattern — Normalize inbound WebSocket frames (type + size) before parsing

## Intent
Make inbound WebSocket handling robust and DoS-resistant by:
1) handling multiple payload types, and
2) enforcing size limits consistently,
3) only then parsing JSON.

## Sketch
- `normalizeWsDataToText(data)` → `{ text, bytes }` for `string|Blob|ArrayBuffer|Uint8Array`.
- `if (bytes > MAX_INBOUND_FRAME_BYTES) close()`.
- `JSON.parse(text)`.

## Notes
- Keep the hot path fast for `string` frames.
- Avoid logging full frames (may contain sensitive content).
- Pair this with a **handshake timer cleanup** pattern: any per-socket timers must be cleared on `onclose`/`onerror`.
