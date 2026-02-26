---
type: plan
status: approved
created: 2026-02-26T20:05:00+01:00
repo: obsidian-oclaw-chat
branch: develop
owner: Rix
scope:
  - obsidian-plugin/src/types.ts
  - obsidian-plugin/src/main.ts
  - obsidian-plugin/src/view.ts
---

# Plan — Hotfix: keep Obsidian session picker stable via recent keys

## Problem
We restrict the picker to “Obsidian-only” sessions. But `sessions.list` may not return simple keys like `obsidian-YYYY...` reliably (channel field may be unset / key doesn’t contain `:obsidian:`), so previously used Obsidian sessions can disappear from the dropdown.

## Goal
- Keep an Obsidian-only picker, but never lose access to sessions we created/used in this client.

## Change
- Add `recentSessionKeys: string[]` to settings (persisted).
- On `switchSession()`:
  - push the new key into `recentSessionKeys` (dedup, cap 20)
- In `_setSessionSelectOptions()`:
  - merge `current + recent + fetchedKeys`.
- Loosen Obsidian filter to include keys starting with `obsidian-`.

## Gates
- typecheck
- tests
- build
