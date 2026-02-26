---
type: run
status: done
created: 2026-02-26T18:14:00+01:00
repo: obsidian-oclaw-chat
branch: develop
plan: ../plans/20260226-1812-hotfix-linkify-vault-relative.md
---

# Run — Hotfix: linkify vault-relative paths directly

## Change
- `obsidian-plugin/src/view.ts`
  - For `kind:'path'` candidates, we now first check whether the raw token itself refers to an existing vault file (after stripping leading `/`).
  - If it exists, we linkify it directly (no mapping required).
  - Mapping remains as fallback for remote FS paths.

## Gates
- typecheck ✅
- tests ✅ (20/20)
- build ✅
