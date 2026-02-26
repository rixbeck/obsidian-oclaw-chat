---
type: run
status: done
created: 2026-02-26T18:32:00+01:00
repo: obsidian-oclaw-chat
branch: develop
plan: ../plans/20260226-1831-hotfix-openfile-click.md
---

# Run — Hotfix: openFile on link click

## Change
- `obsidian-plugin/src/view.ts`
  - Obsidian-link click handler now resolves `vaultPath` to a `TFile` and opens it via `workspace.getLeaf(true).openFile(file)`.
  - Keeps `openLinkText(...)` as fallback.

## Gates
- typecheck ✅
- tests ✅ (20/20)
- build ✅
