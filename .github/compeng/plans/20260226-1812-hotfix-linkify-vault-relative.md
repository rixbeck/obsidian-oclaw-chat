---
type: plan
status: approved
created: 2026-02-26T18:12:00+01:00
repo: obsidian-oclaw-chat
branch: develop
owner: Rix
scope:
  - obsidian-plugin/src/view.ts
---

# Plan — Hotfix: linkify vault-relative paths directly

## Problem
Assistant often outputs vault-relative paths (e.g. `compeng/plans/x.md`). Current linkify flow only links paths that map from a configured `remoteBase`, so vault-relative references do not become clickable.

## Goal
If a candidate path token already refers to an **existing vault file**, linkify it directly (no mapping required). Mapping remains as fallback.

## Changes
- In `OpenClawChatView`:
  - `_preprocessAssistantMarkdown()`
    - For `kind:'path'`: first check whether `c.raw` itself (normalized) exists in vault → then emit `[[raw]]`.
    - Else fall back to mapping.
  - `_renderAssistantPlainWithLinks()`
    - For `kind:'path'`: first check existence of `c.raw` itself → render clickable Obsidian link.
    - Else fall back to mapping.
- Normalization: remove leading `/` before `getAbstractFileByPath`.

## Gates
- `npm -C obsidian-plugin run typecheck`
- `npm -C obsidian-plugin run test:once`
- `npm -C obsidian-plugin run build`
