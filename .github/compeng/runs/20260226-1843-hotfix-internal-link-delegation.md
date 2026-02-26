---
type: run
status: done
created: 2026-02-26T18:43:00+01:00
repo: obsidian-oclaw-chat
branch: develop
plan: ../plans/20260226-1841-hotfix-internal-link-delegation.md
---

# Run — Hotfix: internal-link click delegation

## Change
- `obsidian-plugin/src/view.ts`
  - Added delegated click handler on `this.messagesEl`.
  - When clicking `a.internal-link`, we read `data-href`/`href`, resolve to `TFile`, and open via `workspace.getLeaf(true).openFile(file)`.
  - External `http/https` links are left to default handling.
  - Cleanup on `onClose()` removes the listener.

## Gates
- typecheck ✅
- tests ✅ (20/20)
- build ✅
