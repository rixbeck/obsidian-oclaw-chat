---
type: plan
status: approved
created: 2026-02-26T20:16:00+01:00
repo: obsidian-oclaw-chat
branch: develop
owner: Rix
scope:
  - obsidian-plugin/src/view.ts
---

# Plan — Hotfix: prevent session select drift / wrong active after switching to main

## Problem
After switching to `main`, UI may show `main` but actual active session remains the previous `obsidian-*` key.
Likely caused by:
- async session switching not awaited in Main button
- dropdown rebuild triggering change events / selecting a stale option

## Change
- Add `suppressSessionSelectChange` guard to ignore programmatic option rebuilds.
- In `_setSessionSelectOptions()`:
  - wrap option rebuild with suppression
  - force select value to `settings.sessionKey` after rebuild
- Make Main button async: `await switchSession('main')` then refresh + set select value.

## Gates
- typecheck
- tests
- build
