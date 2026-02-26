---
type: run
status: done
created: 2026-02-27T00:01:00+01:00
repo: obsidian-oclaw-chat
branch: develop
plan: ../plans/20260226-2359-autodismiss-system-notices.md
---

# Run — Auto-dismiss system notifications

## Implemented
- System messages (role=system) auto-dismiss after 5s with fade-out, excluding session dividers.
- Added `ChatManager.removeMessage(id)` and a small unit test.

## Gates
- typecheck ✅
- tests ✅ (26/26)
- build ✅
