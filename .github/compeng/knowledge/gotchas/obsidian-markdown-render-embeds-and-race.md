---
id: gotcha.obsidian-markdown-render-embeds-and-race
created: 2026-02-26
summary: Obsidian Markdown rendering of untrusted assistant output can trigger embeds/wikilinks; async rendering can race with view lifecycle.
tags: [obsidian, markdown, security, performance]
---

# Gotcha: Obsidian Markdown render of untrusted assistant output (embeds + async race)

## Problem
Rendering assistant output via Obsidian’s `MarkdownRenderer.renderMarkdown(...)` is powerful, but it comes with two sharp edges:

1) **Feature surface:** Obsidian Markdown supports wikilinks and embeds (e.g. `[[...]]`, `![[...]]`). In some environments this can pull content into the UI or create confusing link interactions.

2) **Async race:** `renderMarkdown` may be async. If the view is cleared/rebuilt quickly, a “fire-and-forget” render can finish after DOM teardown and render into stale elements.

## Symptoms
- Unexpected embedded content or link behavior originating from assistant text.
- Rare UI glitches where markdown appears in the wrong place after rapid re-render.

## Mitigations
- **Guardrail:** render Markdown only for assistant messages; keep user/system plain.
- **Embed neutralization (optional):** if needed, escape/disable `![[` patterns in assistant output (policy decision).
- **Lifecycle safety:** before rendering, ensure the target element is still connected:
  - e.g. `if (!body.isConnected) return;`
  - or keep a message-id attribute and validate the node is still present.
- Consider adding a settings toggle (`renderMarkdown`) for quick rollback.
