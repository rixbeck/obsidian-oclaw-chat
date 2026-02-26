---
type: plan
status: approved
created: 2026-02-26T18:41:00+01:00
repo: obsidian-oclaw-chat
branch: develop
owner: Rix
scope:
  - obsidian-plugin/src/view.ts
---

# Plan — Hotfix: handle internal-link clicks via event delegation

## Problem
In Markdown render mode, Obsidian generates `<a class="internal-link" data-href="...">` anchors, but in this chat view they are not opening reliably.

## Goal
Ensure clicking an internal-link inside the chat message body opens the corresponding vault file.

## Change
- Add a click event handler on the messages container (`this.messagesEl`) that:
  - detects clicks on `a.internal-link`
  - extracts `data-href` (preferred) or `href`
  - ignores `http/https` URLs
  - resolves via `vault.getAbstractFileByPath(path)`
  - if it’s a `TFile`, calls `workspace.getLeaf(true).openFile(file)`
  - `preventDefault()` / `stopPropagation()` when we handle it
- Ensure cleanup on `onClose()` (remove the delegated handler).

## Gates
- typecheck
- tests
- build
