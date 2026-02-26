---
id: pattern.obsidian-chat-render-assistant-markdown
created: 2026-02-26
summary: Render assistant chat messages as Obsidian Markdown, keep user/system plain text for safety.
tags: [obsidian, ux, markdown, security]
---

# Pattern: Render assistant messages as Markdown (Obsidian Chat)

## Context
Chat agents typically answer in Markdown (lists, headings, code blocks). Rendering assistant output as plain text loses structure.

## Pattern
- Render **only** `role === 'assistant'` message bodies using Obsidian’s renderer:
  - `MarkdownRenderer.renderMarkdown(markdown, containerEl, sourcePath, component)`
- Keep `user` and `system` messages as **plain text** (`setText`) as a baseline guardrail.

## Why this is a good default
- UX: preserves formatting where it matters most (assistant responses).
- Safety: reduces the surface for “prompted” rich features on user/system messages.

## Implementation notes
- Wrap content in a dedicated container (e.g. `.oclaw-message-body`) so CSS can target markdown elements.
- Ensure code blocks (`pre`) are scrollable (`overflow-x: auto`) inside bubbles.

## Optional enhancements
- Add a settings toggle: `renderMarkdown: boolean` (default true) for quick rollback/debug.
- Add an additional guardrail to neutralize embeds/transclusions in assistant content (see related gotcha).

## Related
- Gotcha: `../gotchas/obsidian-markdown-render-embeds-and-race.md`
