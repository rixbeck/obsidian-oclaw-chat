---
type: run
status: done
created: 2026-02-26T19:53:00+01:00
repo: obsidian-oclaw-chat
branch: develop
plan: ../plans/20260226-1952-hotfix-new-session-modal-escape-main.md
---

# Run — Hotfix: New Session modal + Main escape

## Change
- `obsidian-plugin/src/view.ts`
  - `New…` now opens `NewSessionModal` (Obsidian Modal) instead of `window.prompt()`.
  - Added `Main` button to switch sessionKey back to `main`.

## Gates
- typecheck ✅
- tests ✅ (20/20)
- build ✅
