---
type: run
status: done
created: 2026-02-26T12:04:00+01:00
plan:
  - http://asus-x555ld.tailf13b03.ts.net:8088/files/workspace/obsidian-oclaw-chat/.github/compeng/plans/20260226-1202-obsidian-plugin-security-robustness-hardening.md
repo: obsidian-oclaw-chat
branch: develop
---

# Run — Obsidian OpenClaw Chat: security + robustness hardening

## Goal
Execute the approved plan `.github/compeng/plans/20260226-1202-obsidian-plugin-security-robustness-hardening.md`.

## Steps / log

### 0) Baseline gates
- [x] `npm -C obsidian-plugin run typecheck` ✅
- [x] `npm -C obsidian-plugin run test:once` ✅ (8/8)
- [x] `npm -C obsidian-plugin run build` ✅

### 1) Device identity: migrate off localStorage + add reset UX
- Updated WS client to use an injected `DeviceIdentityStore` (plugin-scoped persistence) and only use `localStorage` for **one-time migration**.
- Added settings button: **Reset device identity (re-pair)**.

Files:
- `obsidian-plugin/src/websocket.ts`
- `obsidian-plugin/src/main.ts`
- `obsidian-plugin/src/settings.ts`

### 2) Gateway URL safety: block non-local ws:// unless explicit override
- Added `allowInsecureWs` setting (default false).
- WS client `connect()` now refuses `ws://` to non-local hosts unless override enabled.

Files:
- `obsidian-plugin/src/types.ts`
- `obsidian-plugin/src/settings.ts`
- `obsidian-plugin/src/main.ts`
- `obsidian-plugin/src/websocket.ts`

### 3) DoS/robustness: inbound frame cap, pendingRequests cap, ws.send throw cleanup
- Added `MAX_INBOUND_FRAME_BYTES` guard before `JSON.parse`.
- Added `MAX_PENDING_REQUESTS` guard.
- Wrapped `ws.send()` in try/catch and ensured `pendingRequests` cleanup on throw.

File:
- `obsidian-plugin/src/websocket.ts`

### 4) Connection resilience: handshake timeout + reconnect backoff/jitter
- Added `HANDSHAKE_TIMEOUT_MS` waiting for `connect.challenge`.
- Implemented exponential backoff + jitter reconnect (resets on successful connect).

File:
- `obsidian-plugin/src/websocket.ts`

### 5) Tests: add missing edge cases
- Expanded `websocket.test.ts` from 8 → 14 tests, including:
  - runId mismatch ignored
  - aborted edge cases
  - sessionKey mismatch ignored
  - HEARTBEAT_OK suppression
  - ws.send throw cleanup

File:
- `obsidian-plugin/src/websocket.test.ts`

### 6) Final gates + commit/push
- [x] `npm -C obsidian-plugin run typecheck` ✅
- [x] `npm -C obsidian-plugin run test:once` ✅ (14/14)
- [x] `npm -C obsidian-plugin run build` ✅
