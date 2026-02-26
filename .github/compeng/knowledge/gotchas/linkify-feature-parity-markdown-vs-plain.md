---
type: gotcha
created: 2026-02-26T17:53:00+01:00
tags: [obsidian-plugin, linkify, ux]
---

# Gotcha — Feature parity drift between Markdown and plain render paths

## Symptom
A feature implemented only in one render mode (e.g. URL reverse-mapping in plain mode only) creates inconsistent UX:
- same assistant output renders differently depending on `renderAssistantMarkdown`.

## Fix pattern
- Share core logic in a single helper (or pure module), and call it from both code paths.
- Add tests that lock the expected behavior at the logic layer.

## Where we hit this
`obsidian-plugin/src/view.ts` had URL reverse-mapping in plain mode, but not in Markdown mode initially.
