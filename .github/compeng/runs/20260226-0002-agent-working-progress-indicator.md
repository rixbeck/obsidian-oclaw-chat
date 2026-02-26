---
status: done
repo: rixbeck/obsidian-oclaw-chat
branch: develop
started: 2026-02-26 00:02 Europe/Budapest
plan: .github/compeng/plans/20260225-2353-agent-working-progress-indicator.md
---

# Run — Obsidian client progress indicator (“agent is working”)

## Goal
Add visual feedback while the agent is working:
- after the first gateway acknowledgement of `chat.send`, replace **Send** button with a CSS spinner
- hide spinner on assistant final response, error, disconnect/reconnect
- show errors as Notice + red system message block

## Changes implemented

### 1) Add system message severity (red error blocks)
- Updated `ChatMessage` with optional `level?: 'info' | 'error'`
- Updated `ChatManager.createSystemMessage(content, level)`
- Updated rendering to include `level` as CSS class

Files:
- `obsidian-plugin/src/types.ts`
- `obsidian-plugin/src/chat.ts`
- `obsidian-plugin/src/main.ts`
- `obsidian-plugin/src/view.ts`

### 2) Working/progress state plumbing (WebSocket client)
- Added `onWorkingChange` callback
- Set working=true **only after** successful `chat.send` response ("first event" definition)
- Set working=false on:
  - first assistant `chat` event with `state === 'final'`
  - ws close/disconnect
  - a safety timeout (WORKING_MAX_MS=120s) to avoid stuck UI

File:
- `obsidian-plugin/src/websocket.ts`

### 3) UI: Send button spinner
- View tracks `isConnected` + `isWorking`
- When working:
  - disable button
  - replace contents with `.oclaw-spinner`
  - set `aria-busy=true`
- On send error:
  - show `Notice(...)`
  - append red system message

File:
- `obsidian-plugin/src/view.ts`

### 4) CSS
- Added spinner animation + error styling

File:
- `obsidian-plugin/styles.css`

## Build / checks

- `cd obsidian-plugin && npm run build` ✅
  - `main.js` rebuilt successfully.

## Manual test checklist (to be done by Rix in Obsidian)
1) Open sidebar, connect to gateway.
2) Send a message:
   - expect: Send button becomes spinner after request acknowledged.
3) On first assistant final reply:
   - expect: spinner disappears, Send returns.
4) Trigger an error (e.g., wrong token):
   - expect: spinner not stuck; Notice + red system message.

## Notes
- No changes to gateway/network exposure; this is UI-only + client-side state management.
