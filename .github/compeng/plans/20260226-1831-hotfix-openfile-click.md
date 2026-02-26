---
type: plan
status: approved
created: 2026-02-26T18:31:00+01:00
repo: obsidian-oclaw-chat
branch: develop
owner: Rix
scope:
  - obsidian-plugin/src/view.ts
---

# Plan — Hotfix: open Obsidian files via `openFile` on link click

## Problem
Links are rendered, but clicking does not open the file reliably. Current handler uses `workspace.openLinkText(...)`, which can depend on `sourcePath` context and linktext parsing.

## Goal
When we have a vault-resolved path, open the actual `TFile` directly.

## Changes
- In `OpenClawChatView` link rendering (plain mode):
  - On click:
    - `const f = this.app.vault.getAbstractFileByPath(vaultPath)`
    - if `f` is a `TFile`, open via `this.app.workspace.getLeaf(true).openFile(f)`
    - else fallback to `openLinkText(vaultPath, sourcePath, true)`

## Gates
- typecheck
- tests
- build
