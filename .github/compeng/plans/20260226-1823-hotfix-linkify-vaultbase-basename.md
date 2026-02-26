---
type: plan
status: approved
created: 2026-02-26T18:23:00+01:00
repo: obsidian-oclaw-chat
branch: develop
owner: Rix
scope:
  - obsidian-plugin/src/view.ts
---

# Plan — Hotfix: resolve `compeng/...` into `workspace/compeng/...` via vaultBase basename

## Problem
Rix vault stores files under `workspace/compeng/...`, but assistant often references them as `compeng/...`.
Existing linkify only:
- links exact vault-relative tokens, or
- maps remote FS paths via `remoteBase`.

So `compeng/plans/...` doesn’t exist as-is in the vault, and doesn’t match `remoteBase` either.

## Goal
When a path token starts with the basename of a configured `vaultBase` (e.g. `compeng/` for `workspace/compeng/`), map it under that vaultBase and linkify if the target exists.

## Change
- Add helper `_tryMapVaultRelativeToken(token, mappings)` in `view.ts`:
  1) If `token` exists as vault path → use it.
  2) Else, for each mapping row:
     - `baseName = basename(vaultBase)`
     - if token starts with `${baseName}/` → candidate = `${vaultBase}/${token minus baseName/}`
     - if candidate exists → use it.
- Use this helper in both:
  - `_preprocessAssistantMarkdown()`
  - `_renderAssistantPlainWithLinks()`

## Gates
- typecheck
- tests
- build
