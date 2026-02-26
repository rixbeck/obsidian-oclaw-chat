---
type: plan
status: approved
created: 2026-02-26T20:21:00+01:00
repo: obsidian-oclaw-chat
branch: develop
owner: Rix
scope:
  - obsidian-plugin/src/view.ts
---

# Plan — Hotfix: await session change from dropdown and refresh afterwards

## Problem
After selecting a session from the dropdown, async switching/reconnect was not awaited. This can cause UI/session mismatch and stale selection.

## Change
- In sessionSelect change handler:
  - `await plugin.switchSession(next)`
  - `await _refreshSessions()`
  - force `sessionSelect.value/title = next`

## Gates
- typecheck
- tests
- build
