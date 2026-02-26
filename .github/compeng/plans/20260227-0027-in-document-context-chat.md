---
type: plan
status: draft
created: 2026-02-27T00:27:00+01:00
repo: obsidian-oclaw-chat
branch: develop
owner: Rix
tags: [obsidian, context-menu, references, diff, apply]
---

# Plan — In-document context chat (per-leaf references + diff editor + apply)

## Decisions (locked)
- **References are per leaf** (multi-leaf isolation).
- Edits flow: **generate diff → open in a diff editor tab → apply to original doc**.
- Reference IDs are **short** (`R1`, `R2`, …) for semantic citation in chat.

## Problem
We want to use cursor/selection from any Markdown document to:
- add it to OpenClaw chat as a *reference* (indexed)
- let the assistant cite and act on those references
- support safe, user-reviewed edits back into the document.

## Goals
1) Context menu commands in editor (cursor/selection based).
2) A per-leaf reference list the assistant can cite (`[R1]`).
3) A reviewable edit workflow with a diff editor and explicit Apply.

## Non-goals (v1)
- Background/automatic edits without confirmation.
- Cross-leaf shared reference pools.
- Multi-user/ACL.

---

## UX

### Editor context menu (any MD)
**OpenClaw Chat →**
- **Add selection to chat context** (creates `Rk`)
- **Add paragraph to chat context** (cursor paragraph)
- **Add section to chat context** (current heading block)

(Optional future)
- Remove last reference
- Clear references

### Chat view (per leaf)
- References panel/list:
  - `R1` / `R2` … with short preview
  - actions: Open, Remove
- When sending a chat message, plugin attaches the selected references (or all references; decision below).

### Edit workflow
- User asks: “Rewrite [R1] …”
- Assistant responds with a structured edit proposal (see “Edit contract”).
- Plugin opens a **Diff Editor tab** showing Original vs Proposed.
- Buttons: **Apply** (writes into the original doc), **Cancel**.

---

## Data model
### Reference (per leaf)
- `id`: `R1`, `R2`, …
- `notePath`: vault-relative path
- `kind`: `selection | paragraph | section`
- `selection`: `{ from: EditorPosition, to: EditorPosition }` (or offsets)
- `textSnapshot`: string (captured at add time)
- `createdAt`: epoch ms

**Snapshot is the source of truth** for what assistant saw.

### Reference store
- In-memory on `OpenClawChatView` (NOT in plugin global settings).

---

## Custody modes (locked)
We support two explicit modes, controlled by the **client UI** and surfaced to the assistant.

- **custody** (default): assistant proposes edits; user reviews in diff tab; apply is manual.
- **unattended**: assistant can request edits that the plugin auto-applies.

Controls:
- Chat commands: `/custody`, `/unattended`
- Each outbound message includes a header line: `EDIT_MODE: custody|unattended`

## Edit contract (assistant output)
We need a rigid machine-readable block so the plugin can reliably open diff views and/or apply edits.

### Proposed contract (v1): multi-op edit plan
```text
EDIT_PLAN
mode: custody|unattended
ops:
- op: replace
  ref: R1
  file: workspace/compeng/plans/x.md
  from: <<<
  <exact snapshot text>
  >>>
  to: <<<
  <replacement text>
  >>>
- op: create
  file: workspace/new-note.md
  content: <<<
  <full file content>
  >>>
- op: append
  file: workspace/notes.md
  afterHeading: "## Notes"
  content: <<<
  <text to append>
  >>>
END_EDIT_PLAN
```

Rules:
- `ref` must exist for `replace` ops (selection/paragraph/section reference).
- For `replace`:
  - plugin validates target range exists and `from` matches snapshot OR current text at range (best-effort); otherwise mark op as failed.
- For `create`:
  - if file exists, open in diff tab and require explicit user decision (overwrite policy TBD).
- For multi-file plans:
  - diff tab should allow navigating ops (list on the left).

### Execution
- In **custody** mode: open diff tab(s), apply is manual.
- In **unattended** mode: auto-apply ops sequentially, then post a system summary back to chat.

---

## Diff editor options (research + choose)
We need an embedded diff view inside Obsidian.

Candidates:
1) **CodeMirror 6 Merge / diff view** (preferred)
   - Pros: matches Obsidian editor stack, no heavy dependencies.
   - Cons: implementation complexity.

2) **Monaco diff editor**
   - Pros: excellent UX.
   - Cons: large bundle size, more complexity.

3) **Simple side-by-side HTML diff (diff2html)**
   - Pros: quick.
   - Cons: not a real editor; apply flow still needs careful mapping.

Decision gate: pick #1 if feasible in ~2-4h; else #3 as v1.

---

## Implementation steps

### 1) Command plumbing
Files:
- `obsidian-plugin/src/main.ts`
- `obsidian-plugin/src/view.ts`

Add editor commands (registerMarkdownPostProcessor not needed):
- `add-selection-to-context`
- `add-paragraph-to-context`
- `add-section-to-context`

Use Obsidian command API to access active editor selection.

### 2) Reference handling (per leaf)
- Add `references: Reference[]` to `OpenClawChatView`.
- Add helper: `addReferenceFromSelection(...)` → returns `Rk`.
- Display in view.

### 3) Attaching references to outbound messages
In `sendMessage`, augment user message with:
- `References:` header
- each reference:
  - `Rk path: <notePath>`
  - `Rk kind: selection/paragraph/section`
  - `Rk text:` snapshot

### 4) Detect edit proposals
- After assistant message arrives, parse for `EDIT_PROPOSAL` blocks.
- If valid, show a “Review diff” button.

### 5) Diff Editor tab
- Implement a new `ItemView` type: `openclaw-diff`.
- Render chosen diff editor inside.
- Buttons: Apply / Cancel.

### 6) Apply
- Apply modifies the original file/editor range.
- Must confirm `FROM` matches current selection text (or warn).

---

## Tests
- Pure unit tests:
  - reference id increment
  - edit proposal parser
  - apply guard: FROM mismatch → reject
- Minimal view wiring tests are optional (hard in unit), but parser/apply guards must be tested.

---

## Risks
- Editor API differences desktop vs mobile.
- Diff editor dependency/bundle size.
- Range drift if the doc changes between snapshot and apply → mitigate with FROM matching.

## Acceptance criteria
- From any MD doc selection: Add to context creates `R1` and appears in chat leaf.
- Chat send includes references block.
- Assistant can cite `[R1]`.
- A valid edit proposal opens diff view and Apply updates the doc selection only.
