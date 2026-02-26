---
type: gotcha
area: obsidian-plugin
risk: security
status: active
---

# Gotcha: Assistant Markdown is untrusted (Obsidian render pipeline can execute “stuff”)

## Problem
In an Obsidian plugin, rendering assistant output using `MarkdownRenderer.renderMarkdown(...)` is **not equivalent** to safe “string formatting”.

Obsidian’s Markdown pipeline can:
- trigger markdown **post-processors** (including those registered by *other plugins*),
- resolve **embeds/transclusions** (e.g. `![[...]]`), links, and other vault-references,
- potentially enable HTML-like behaviors depending on theme/plugins/settings.

So **remote assistant-controlled content** can cause unexpected code paths or vault data exposure (via embeds), even if your plugin never explicitly executes code.

## Impact
- Expands attack surface: assistant response becomes an input to other plugins’ processors.
- Potential data leakage: embeds/transclusions can pull in vault content.
- Increases severity of any renderer-context compromise (because secrets like device identity may be readable from storage).

## Recommended default
- Treat assistant output as **UNTRUSTED**.
- Default render mode: **plain text** (`setText`).

If Markdown rendering is desired:
- Put it behind an explicit setting like **“Render assistant as Markdown (unsafe)”**.
- Default it to **OFF**.
- Explain the risk clearly in settings/help.

## Related
- `obsidian-electron-untrusted-content-rce.md`
- `obsidian-markdown-render-embeds-and-race.md`
