---
type: plan
status: approved
created: 2026-02-26T19:45:00+01:00
repo: obsidian-oclaw-chat
branch: develop
owner: Rix
scope:
  - obsidian-plugin/src/view.ts
---

# Plan — Hotfix: session picker must list Obsidian sessions only (no fallback)

## Problem
`sessions.list` can include sessions from other channels (telegram/signal/etc.). The Obsidian client should not list or allow switching into those by default.

Current implementation filters obsidian sessions, but **falls back to showing all sessions** if none match.

## Goal
Make session picker **Obsidian-only**. If none are found, show only the current sessionKey and require `New…` for creating/starting an Obsidian session.

## Change
- In `OpenClawChatView._refreshSessions()`:
  - keep only rows where `row.channel === 'obsidian'` OR `row.key.includes(':obsidian:')`
  - remove fallback to `rows`
  - if result empty:
    - call `_setSessionSelectOptions([])` (which still includes current session)

## Gates
- typecheck
- tests
- build
