---
status: approved
priority: high
tags: [obsidian, openclaw, plugin, security, robustness]
---

# Plan — Obsidian OpenClaw Chat: security + robustness hardening (follow-up)

## Issue (inline)
After the Stop/abort SF plan, remaining high-risk items are:
- DeviceIdentity private key JWK persisted in renderer `localStorage`.
- Gateway URL allows insecure `ws://` to non-local hosts while using bearer token.
- Robustness/DoS gaps: no inbound frame size cap, no pendingRequests cap, possible leak if `ws.send()` throws, handshake can stall without timeout.
- Connection resilience: observational heartbeat only, reconnect fixed delay (no backoff/jitter).
- Missing unit tests for correlation/sessionKey/aborted edge cases.

## Goals
1) Remove private key from `localStorage` and add “Reset device identity” UX + migration.
2) Enforce `wss://` for non-local gateways (or explicit unsafe override).
3) Add caps/timeouts to avoid renderer DoS and hanging states.
4) Improve reconnect behavior (backoff/jitter; optional ping if available).
5) Add unit tests for the critical edges.

## Changes (planned)
### A) `obsidian-plugin/src/websocket.ts`
- Introduce a device-identity persistence abstraction (plugin-scoped store), migrate from old localStorage key, then delete it.
- Add inbound frame size guard before JSON.parse.
- Add `MAX_PENDING_REQUESTS` cap.
- Wrap `ws.send()` in try/catch and cleanup pending entry on throw.
- Add handshake timeout for waiting `connect.challenge`.
- Add reconnect backoff + jitter.
- (Optional) liveness ping if gateway supports a safe method.

### B) Settings
- Add an explicit “Reset device identity” control.
- Add gateway URL safety validation; block non-local `ws://` unless explicitly overridden.

### C) Tests
Add/extend vitest tests for:
- runId mismatch ignored
- sessionKey mismatch ignored (+ main alias)
- aborted edge cases (no msg / non-assistant / assistant)
- HEARTBEAT_OK suppression
- pendingRequests reject+clear on close
- ws.send throw cleanup

## Verification
- `npm -C obsidian-plugin run typecheck`
- `npm -C obsidian-plugin run test:once`
- `npm -C obsidian-plugin run build`

## Rollback
- Revert the hardening commits.
- If migration breaks, keep compatibility path reading old localStorage for one version and provide manual reset.
