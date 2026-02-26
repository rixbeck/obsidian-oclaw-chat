---
type: run
status: done
created: 2026-02-26T18:24:00+01:00
repo: obsidian-oclaw-chat
branch: develop
plan: ../plans/20260226-1823-hotfix-linkify-vaultbase-basename.md
---

# Run — Hotfix: vaultBase basename mapping for assistant paths

## Change
- `obsidian-plugin/src/view.ts`
  - Added `_tryMapVaultRelativeToken(token, mappings)` which:
    - accepts exact vault-relative tokens when they exist
    - also resolves `compeng/...` into `workspace/compeng/...` when there is a mapping row with `vaultBase=workspace/compeng/` (basename heuristic)
  - Used in both Markdown and plain render paths.

## Gates
- typecheck ✅
- tests ✅ (20/20)
- build ✅
