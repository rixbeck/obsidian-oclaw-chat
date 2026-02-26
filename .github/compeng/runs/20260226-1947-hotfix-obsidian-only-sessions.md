---
type: run
status: done
created: 2026-02-26T19:47:00+01:00
repo: obsidian-oclaw-chat
branch: develop
plan: ../plans/20260226-1945-hotfix-obsidian-only-sessions.md
---

# Run — Hotfix: Obsidian-only session picker

## Change
- `obsidian-plugin/src/view.ts`
  - `_refreshSessions()` now lists **only** sessions where:
    - `row.channel === 'obsidian'` OR `row.key.includes(':obsidian:')`
  - Removed fallback that previously listed *all* sessions when no Obsidian sessions were found.

## Gates
- typecheck ✅
- tests ✅ (20/20)
- build ✅
