---
type: gotcha
created: 2026-02-26T16:08:00+01:00
tags: [obsidian-plugin, ui, state-sync]
---

# Gotcha — Status indicator: visual state vs tooltip can drift on initial render

## Symptom
On plugin load the **status dot can appear green** (CSS class reflects `connected`), but mouse-over tooltip still shows **“disconnected”**.

## Root cause
The UI updated the dot class based on current state, but **did not update the tooltip/title** in the initial “reflect current state” render path.

## Fix pattern
Whenever you mirror connection state into the UI, update **all** coupled surfaces together:
- CSS classes (`.connected`)
- tooltip/title (`Gateway: <state>`)
- button enabled/label state

Prefer a single helper like `renderGatewayState(state)` to avoid partial updates.

## Where we hit this
`obsidian-oclaw-chat/obsidian-plugin/src/view.ts` in `onOpen()` initial state reflection.
