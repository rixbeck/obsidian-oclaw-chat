---
type: plan
status: approved
created: 2026-02-26T17:16:00+01:00
repo: obsidian-oclaw-chat
branch: develop
owner: Rix
scope:
  - obsidian-plugin/src/types.ts
  - obsidian-plugin/src/settings.ts
  - obsidian-plugin/src/view.ts
  - obsidian-plugin/src/(new)linkify.ts
  - obsidian-plugin/src/(new)linkify.test.ts
---

# Plan — Client-side path mapping + Obsidian-openable links for agent file references

## Goal
When the assistant references a file path that corresponds to a vault path, the Obsidian client should render it as a **clickable Obsidian link**.

Constraints from Rix:
- Conversion happens **client-side**.
- Config provides an **editable table** of mappings: **vault base → remote base (FS-based)**.
- If a path can’t be matched and verified, **do not create a fake link**.
- **Absolute http/https URLs remain absolute** (no existence check), but we should **try to reverse-convert** to a vault link when possible.
- Even when `renderAssistantMarkdown=false` (default), we use approach **B**: create a clickable link in the DOM (not just `[[...]]` text).

## Non-goals
- Indexing the whole vault / fuzzy matching.
- Changing agent output format.
- Making Obsidian Markdown rendering “safe”.

## UX / Behavior
- For assistant messages:
  - Detect candidate paths/URLs in the message content.
  - For each candidate:
    - If it is `http://` or `https://`:
      - Keep it as an absolute clickable link.
      - Additionally, if we can reverse-map it to a vault path (heuristic), replace with an Obsidian link instead (optional; see below).
    - Else if it matches `remoteBase` in any mapping row:
      - Replace the `remoteBase` prefix with `vaultBase` prefix.
      - Normalize to a vault-relative path.
      - **Existence check** in the vault. If exists: render as clickable Obsidian link.
      - If missing: leave as plain text.

- Link format:
  - In UI we can display it as `[[path]]` (for “Obsidian feel”), but it must be truly clickable:
    - Click handler: `this.app.workspace.openLinkText(linkText, sourcePath, true)` (or equivalent).

## Data model / Settings
### 1) Add mapping config
In `obsidian-plugin/src/types.ts`:
- Add:
  ```ts
  export type PathMapping = {
    vaultBase: string;  // e.g. "docs/" or "compeng/"
    remoteBase: string; // e.g. "/home/wall-e/.openclaw/workspace/docs/"
  };

  pathMappings: PathMapping[];
  ```
- Default: `pathMappings: []`.

### 2) Settings UI (editable table)
In `obsidian-plugin/src/settings.ts`:
- Add a section: **“Path mappings (vault base → remote base)”**
- Implement as a simple repeating list with:
  - text inputs for `vaultBase` and `remoteBase`
  - add-row button
  - remove-row button
  - preserve order (first match wins)

## Implementation details

### A) Extract a small linkify module (testable)
Create `obsidian-plugin/src/linkify.ts` with pure helpers:
- `normalizeBase(base: string): string` (trim, ensure trailing `/` for prefix matching)
- `tryMapRemotePathToVaultPath(input: string, mappings: PathMapping[]): string | null`
  - for each mapping row:
    - if `input.startsWith(remoteBase)`: return `vaultBase + input.slice(remoteBase.length)`
- `extractCandidates(text: string): Array<{ start:number; end:number; raw:string; kind:'url'|'path' }>`
  - simple regex-based extraction (conservative; avoid false positives)

### B) Existence check
In `view.ts`, when rendering a candidate mapped vault path:
- `const normalized = vaultPath.replace(/^\/+/, '')` (Obsidian vault paths are relative)
- `const exists = Boolean(this.app.vault.getAbstractFileByPath(normalized))`
- Only linkify when `exists===true`.

### C) Rendering strategy (safe, works with renderAssistantMarkdown=false)
Modify `_appendMessage()` in `obsidian-plugin/src/view.ts`:
- If `msg.role !== 'assistant'`: keep current behavior.
- If `assistant` and `renderAssistantMarkdown===true`:
  - Preprocess `msg.content` by replacing known remote paths with `[[vault/path]]` (optional), then pass to `MarkdownRenderer`.
- If `assistant` and `renderAssistantMarkdown===false`:
  - Do NOT call `setText(msg.content)`.
  - Instead, build the message body by:
    - appending text nodes for normal text segments
    - appending `<a>` (or `<span class="oclaw-link">`) nodes for linkified segments
    - clicking the Obsidian link calls `openLinkText`.
  - For absolute URLs: render `<a href>` and let Obsidian/Electron open externally.

### D) URL reverse-conversion (best effort, no fake links)
Because mapping is FS-based, URL reverse conversion is heuristic-only. Implement only if safe:
- If URL contains an encoded or direct occurrence of any `remoteBase` substring, attempt to extract the path portion and run the same mapping.
- If the resulting vault path exists: render as Obsidian link.
- Else: keep URL as URL.

## Tests
Add `obsidian-plugin/src/linkify.test.ts` (Vitest) covering:
- mapping works with/without trailing slashes
- first match wins
- no match → null
- conservative extraction (doesn’t match random punctuation)

(We won’t unit-test Obsidian `vault.getAbstractFileByPath`; that stays in view logic.)

## Gates
- `npm -C obsidian-plugin run typecheck`
- `npm -C obsidian-plugin run test:once`
- `npm -C obsidian-plugin run build`

## Acceptance criteria
- Given a mapping row, when assistant outputs a remote FS path that maps to an existing vault file, the chat UI shows a clickable Obsidian link that opens the note.
- If the mapped target does not exist, the text remains plain (no fake link).
- http/https URLs remain clickable URLs; if reverse-mapped to an existing vault file, they become Obsidian links.
- Works when `renderAssistantMarkdown=false`.
