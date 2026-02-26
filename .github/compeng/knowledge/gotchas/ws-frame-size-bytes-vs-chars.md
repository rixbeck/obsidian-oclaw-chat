---
type: gotcha
created: 2026-02-26T12:33:00+01:00
tags: [websocket, dos-guard, obsidian-plugin]
---

# Gotcha — WebSocket frame size guard: chars ≠ bytes (and Blob/ArrayBuffer bypass)

## Problem
A DoS guard that compares `event.data.length` to a constant expressed in **bytes** is wrong:
- JS string `.length` counts **UTF-16 code units**, not UTF‑8 bytes.
- WebSocket `event.data` can be **`Blob`** or **`ArrayBuffer`** (browser/runtime dependent). In that case, a string-only guard can be **skipped entirely**.

## Why it matters
- You can under/over-count size and parse frames larger than intended.
- Attackers (or just weird gateways) can force large allocations / JSON parse cost.

## Safer pattern
Before `JSON.parse`, normalize `event.data` and measure a byte-accurate size:
- `string` → `new TextEncoder().encode(str).byteLength`
- `Blob` → `blob.size` (bytes) and only `await blob.text()` if below limit
- `ArrayBuffer`/`Uint8Array` → `.byteLength` then decode via `TextDecoder`

If size exceeds limit: close the socket (or drop frame) and log only metadata (no payload).

## Where we hit this
`obsidian-oclaw-chat/obsidian-plugin/src/websocket.ts` inbound frame guard originally used `.length` and only for `string`.
