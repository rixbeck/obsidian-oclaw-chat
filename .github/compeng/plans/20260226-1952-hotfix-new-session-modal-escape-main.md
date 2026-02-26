---
type: plan
status: approved
created: 2026-02-26T19:52:00+01:00
repo: obsidian-oclaw-chat
branch: develop
owner: Rix
scope:
  - obsidian-plugin/src/view.ts
  - obsidian-plugin/main.js
---

# Plan — Hotfix: make New Session work (Obsidian Modal) + provide escape hatch to main

## Problem
- `window.prompt()` is unreliable in Obsidian/Electron for custom views → New session flow doesn’t work.
- User can get stuck on a non-Obsidian `sessionKey` (previously selected) while the picker now hides non-Obsidian sessions.

## Goal
- Make **New…** always work.
- Provide a safe recovery button to switch back to `main`.

## Change
- Replace `window.prompt()` with an Obsidian `Modal` + `Setting` text input.
- Add a `Main` button in the session row that switches to sessionKey `main`.

## Gates
- typecheck
- tests
- build
