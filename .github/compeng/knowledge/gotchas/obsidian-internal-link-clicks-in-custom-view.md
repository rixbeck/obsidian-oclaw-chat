---
type: gotcha
created: 2026-02-26T18:47:00+01:00
tags: [obsidian, plugin, links]
---

# Gotcha — `a.internal-link` may not open in custom views without explicit click handling

## Symptom
In a custom `ItemView`, Markdown-rendered internal links appear correctly as:
```html
<a class="internal-link" data-href="path/to/file.md" ...>
```
…but clicking does nothing (or opens unreliably).

## Root cause
Obsidian’s default internal-link click handling is not guaranteed to fire in every custom DOM context / event propagation chain.

## Fix pattern
Use **event delegation** on the message/container element:
- on click, find `closest('a.internal-link')`
- read `data-href` (preferred) or `href`
- resolve to `TFile` via `vault.getAbstractFileByPath()`
- open via `workspace.getLeaf(true).openFile(file)`
- `preventDefault()` + `stopPropagation()` when handled

## Where we hit this
`obsidian-oclaw-chat/obsidian-plugin/src/view.ts` for assistant message rendering.
