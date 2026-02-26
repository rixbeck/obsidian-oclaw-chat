---
type: pattern
created: 2026-02-26T18:47:00+01:00
tags: [obsidian, plugin, navigation]
---

# Pattern — Prefer `openFile(TFile)` over `openLinkText()` when you already have a vault path

## Intent
Make navigation deterministic from custom UIs.

## Why
`workspace.openLinkText(linkText, sourcePath, ...)` depends on:
- linktext parsing rules
- correct `sourcePath`
- view context

If you can resolve the target to a `TFile`, you can open it directly.

## Recipe
1) `const f = app.vault.getAbstractFileByPath(vaultPath)`
2) if `f instanceof TFile` → `app.workspace.getLeaf(true).openFile(f)`
3) fallback to `openLinkText` only if needed
