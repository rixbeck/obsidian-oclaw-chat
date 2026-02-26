---
type: plan
status: approved
created: 2026-02-26T20:11:00+01:00
repo: obsidian-oclaw-chat
branch: develop
owner: Rix
scope:
  - obsidian-plugin/src/view.ts
---

# Plan — Hotfix: show Main when no obsidian sessions; enforce `obsidian-` prefix for New

## Requirements
- If refresh yields no `obsidian-*` / `:obsidian:` sessions, the dropdown should still show **Main**.
- New session creation must only allow names starting with `obsidian-`.

## Changes
- `_setSessionSelectOptions()`:
  - filter options to `main | obsidian-* | *:obsidian:*`
  - if empty → set `['main']`
- `NewSessionModal`:
  - validate `value.startsWith('obsidian-')` before submit; otherwise show Notice and stay open.

## Gates
- typecheck
- tests
- build
