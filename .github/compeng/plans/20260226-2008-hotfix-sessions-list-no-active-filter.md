---
type: plan
status: approved
created: 2026-02-26T20:08:00+01:00
repo: obsidian-oclaw-chat
branch: develop
owner: Rix
scope:
  - obsidian-plugin/src/view.ts
---

# Plan — Hotfix: refresh should not filter sessions by activity

## Problem
Refresh only shows `main`. Gateway `sessions.list` can be filtered by `activeMinutes`; with a non-zero filter, older `obsidian-*` sessions may not be returned and thus cannot be selected.

## Goal
On Refresh, list all sessions (still filtered client-side to Obsidian-only) so older `obsidian-*` keys appear.

## Change
- In `_refreshSessions()` call `listSessions({ activeMinutes: 0, limit: 200, includeUnknown: true })`.

## Gates
- typecheck
- tests
- build
