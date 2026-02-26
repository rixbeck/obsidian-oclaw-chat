---
type: pattern
created: 2026-02-26T23:44:00+01:00
tags: [obsidian, markdown, security, links]
---

# Pattern — Render Markdown, then safe-linkify as a DOM post-process

## Problem
Relying on Obsidian's internal-link click handling (or injecting wikilinks / custom schemes into Markdown) can be inconsistent across platforms (e.g. macOS) and can produce ugly raw markdown if escaping/post-processors interfere.

## Pattern
- Keep assistant Markdown rendering as an independent concern:
  - `MarkdownRenderer.renderMarkdown(rawText, container, sourcePath, plugin)`
- After render completes, scan the produced DOM for text nodes and apply **the same safe linkify** logic used in plain mode:
  - extract path candidates
  - map/reverse-map to vault paths
  - existence-check in vault
  - replace token substrings with `<a>` elements whose click handler opens the `TFile`

## Benefits
- Identical link behavior in safe/plain and unsafe/markdown modes.
- Avoids dependence on Obsidian internal-link navigation quirks.
- Does not require unwrapping or injecting wiki links into Markdown.
