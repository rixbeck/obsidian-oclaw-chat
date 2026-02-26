---
type: run
status: done
created: 2026-02-26T17:51:00+01:00
repo: obsidian-oclaw-chat
branch: develop
plan: ../plans/20260226-1716-obsidian-path-mapping-linkify.md
---

# Run — Linkify must-fix follow-up (URL reverse-map in markdown + relative paths)

## Changes
- `src/view.ts`
  - Implemented URL reverse-mapping in Markdown mode too (only when it maps to an existing vault file).
  - Deduplicated reverse-map logic into a shared helper `_tryReverseMapUrlToVaultPath()` used by both markdown and plain render paths.

- `src/linkify.ts`
  - Extended candidate extraction to include **relative paths** (`foo/bar.md`).
  - Tightened absolute-path regex so it does not “steal” `/bar/...` inside a relative token (`compeng/plans/...`).

- `src/linkify.test.ts`
  - Added test for relative path extraction.

## Gates
- `npm -C obsidian-plugin run typecheck` ✅
- `npm -C obsidian-plugin run test:once` ✅ (20 tests)
- `npm -C obsidian-plugin run build` ✅
