---
type: plan
status: approved
created: 2026-02-26T20:01:00+01:00
repo: obsidian-oclaw-chat
branch: develop
owner: Rix
scope:
  - obsidian-plugin/src/view.ts
---

# Plan — Hotfix: after New session, auto-refresh list and select the created key

## Problem
After creating a new session key via New modal, the session dropdown is not refreshed and does not reliably switch selection to the new key.

## Goal
After New/Create:
- switch session
- refresh sessions list
- set dropdown active value to the created session key

## Change
- In `_promptNewSession()` submit handler:
  - `await plugin.switchSession(v)`
  - `await _refreshSessions()`
  - set `sessionSelect.value = v` and `title = v`

## Gates
- typecheck
- tests
- build
