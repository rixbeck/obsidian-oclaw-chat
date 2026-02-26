---
type: plan
status: approved
created: 2026-02-26T21:42:00+01:00
repo: obsidian-oclaw-chat
branch: develop
owner: Rix
scope:
  - obsidian-plugin/src/main.ts
  - obsidian-plugin/src/view.ts
  - obsidian-plugin/src/websocket.ts
  - obsidian-plugin/src/chat.ts
  - obsidian-plugin/src/types.ts
  - obsidian-plugin/src/*.test.ts
---

# Plan — Multi-leaf independent sessions (per-view WSClient + ChatManager)

## Goal
Allow multiple OpenClaw Chat views (leaves) to run **in parallel** in Obsidian, each with its own:
- sessionKey
- WebSocket client connection/state (or at least independent send/abort/working state)
- chat history (messages)

So `Ctrl+Shift+T` → new chat view can select a different session and chat concurrently without affecting other leaves.

## Context / Why now
Current architecture is plugin-global:
- `plugin.wsClient` (single)
- `plugin.chatManager` (single)
- `plugin.settings.sessionKey` (single)

This makes multiple leaves fight over the same connection and session routing.

We also just introduced canonical, vault-scoped session keys:
- default: `agent:main:obsidian:direct:<vaultHash>`

Multi-leaf should build on this instead of reintroducing gateway-driven discovery.

## Design options
### Option A (recommended): Per-leaf objects
Each `OpenClawChatView` owns:
- `wsClient: ObsidianWSClient`
- `chatManager: ChatManager`
- `sessionKey: string`

The plugin becomes a factory + settings storage + shared helpers (device identity store, gateway settings).

**Pros:** simplest reasoning, true parallelism.
**Cons:** multiple WS connections (one per leaf).

### Option B: One WS connection + multiplexer (defer)
Harder: per-leaf working state, abort correlation, reconnect, filtering, etc.

## Decisions (proposed)
- Start with **Option A**.
- Keep session keys **canonical-only** (main + `agent:main:obsidian:direct:*`).
- Leaf default sessionKey:
  - use canonical vault default from settings unless user changes it in that leaf.

## UX
- Each leaf shows its own session dropdown and can switch without affecting other leaves.
- Add a subtle label in header: `Leaf session: <short>` (optional).

## Implementation steps

### 1) Refactor ownership
- Move `chatManager` off plugin-global.
  - `OpenClawChatView` constructs a new `ChatManager()`.
- Move `wsClient` off plugin-global.
  - `OpenClawChatView` constructs a new `ObsidianWSClient(sessionKey, { identityStore, allowInsecureWs })`.

### 2) Keep shared concerns in plugin
- Keep device identity store methods in plugin (`_loadDeviceIdentity/_saveDeviceIdentity/_clearDeviceIdentity`).
- Expose a small factory helper:
  - `plugin.createWsClient(sessionKey): ObsidianWSClient`
- Keep canonical vaultHash + known sessions map in plugin settings.

### 3) Per-leaf session switching
- Replace `plugin.switchSession(...)` usage inside view.
- Implement `view.switchSession(next)`:
  - best-effort abort on its own wsClient
  - insert divider into its own chatManager
  - update leaf-local `this.sessionKey`
  - call `wsClient.disconnect(); wsClient.setSessionKey(next); wsClient.connect(...)`
  - update UI dropdown

### 4) Persist per-leaf session selection (optional)
Two levels:
- minimal v1: do NOT persist per-leaf; each new leaf starts at canonical vault default.
- v2: store `leafState` in plugin data keyed by `leaf.id` (might be unstable); better: store nothing.

Recommend: **v1 (no persistence)**.

### 5) Tests
- Add unit tests for:
  - two view instances switching sessions do not affect each other (mock wsClient / dependency injection seam)
  - `ChatManager` separation (messages don’t leak between views)

### 6) Safety / resource guards
- Cap max WS connections (e.g. 3 leaves) or show Notice if too many.

## Gates
- typecheck
- tests
- build

## Rollback
- Revert to single plugin-global wsClient/chatManager.

## Risks
- Multiple WS connections increase gateway load.
- Must ensure listeners are detached on `onClose()` to avoid leaks.
