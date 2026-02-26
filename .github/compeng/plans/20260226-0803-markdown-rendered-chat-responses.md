---
status: draft
priority: high
tags: [obsidian, ux, markdown, chat]
owner: Rix
created: 2026-02-26 08:03 Europe/Budapest
estimated_hours: 1-3
issue: inline
---

# Plan — Markdown-rendered chat responses in Obsidian client

## 0) Issue (inline)

### Problem
Az Obsidian oldali OpenClaw Chat panel jelenleg **plain text**-ként rendereli az agent válaszokat:

- `obsidian-plugin/src/view.ts` → `el.createSpan({ text: msg.content })`

Ez elveszíti a struktúrát (bullet list, bold, headers, code blockok), pedig a chat válaszok jellemzően Markdownban érkeznek.

### Goal
A chat üzenetek (minimum az **assistant** üzenetek) **Markdownként renderelődjenek** Obsidianban.

### Non-goals
- Teljes “Obsidian note” szintű funkciók (embeds, transclusion, file műveletek) automatizálása.
- Rich interactive widgetek.

### Constraints / risks
- Biztonság: az agent output **untrusted content**; Markdown render során kerülni kell az olyan feature-öket, amik RCE / link spoof / embed abuse irányba vihetnek.
- Teljesítmény: nagy üzeneteknél ne legyen O(n²) újrarender minden update-nél.

## 1) Approach (recommended)

### 1.1 Render only assistant messages as Markdown
- `role === 'assistant'` → Markdown render
- `role === 'user'` → maradhat plain text (opcionálisan később markdown)
- `role === 'system'` → maradhat plain text (vagy minimál markdown, de inkább plain)

### 1.2 Use Obsidian’s Markdown renderer
Obsidian API:
- `MarkdownRenderer.renderMarkdown(markdown, containerEl, sourcePath, component)`

Ezzel a plugin “natív” Obsidian markdownot kap (listák, code blockok, inline code, stb.).

## 2) Implementation steps

### Step A — UI rendering changes
**Files:**
- `obsidian-plugin/src/view.ts`

**Changes:**
1) A message DOM elembe ne `createSpan(text)` menjen, hanem legyen egy dedikált body container, pl.:
   - `const body = el.createDiv({ cls: 'oclaw-message-body' })`
2) Assistant üzenetnél:
   - `await MarkdownRenderer.renderMarkdown(msg.content, body, /*sourcePath*/ '', this.plugin)`
   - (vagy `this.app.workspace.getActiveFile()?.path ?? ''` sourcePath)
3) User/system üzenetnél:
   - `body.setText(msg.content)`

**Megjegyzés:**
- A `_appendMessage` jelenleg sync. Ha MarkdownRenderer async, akkor:
  - `_appendMessage` legyen `async` és a hívási lánc igazodjon, VAGY
  - renderelő helper függvény, ami “fire-and-forget” módon `void render()`

### Step B — Styling
**Files:**
- `obsidian-plugin/styles.css`

**Changes:**
- Adjunk CSS-t a `.oclaw-message-body` alá, hogy a markdown elemek (pl. `pre`, `code`, `p`, `ul`, `ol`, `blockquote`) jól nézzenek ki és ne essenek szét a bubble layoutban.
- `pre` overflow-x kezelése (code block scroll).

### Step C — Settings toggle (optional but recommended)
**Motivation:** gyors rollback / debug, ha a markdown render valamiért gond.

**Files:**
- `obsidian-plugin/src/types.ts` (settings)
- `obsidian-plugin/src/settings.ts` (UI)
- `obsidian-plugin/src/view.ts` (conditional render)

**Setting:**
- `renderMarkdown: boolean` (default: true)

### Step D — Safety guardrails
**Minimum:**
- By default only assistant messages render markdown.
- System error strings stay plain.

**Optional hardening (if needed):**
- Strip HTML tags from agent content before rendering (keep pure markdown). (This might be too aggressive; only do if we see problems.)
- Consider disabling embeds/transclusions by sanitizing `![[...]]` and `![](…)` in assistant output (or add an allowlist).

## 3) Test plan

### Manual
1) Küldj üzenetet, ami listát kér:
   - expected: bullet list rendesen jelenjen meg
2) Küldj üzenetet, ami code blockot kér (```ts ...```):
   - expected: monospaced, scrollable, nem töri szét a layoutot
3) Linkek:
   - expected: kattintható linkek, de ne legyen automatikus “execute” jelleg
4) Nagy válasz (több bekezdés):
   - expected: append-only működés, nem akad

### Regression
- Spinner / working state továbbra is működik.
- Error message red block továbbra is plain text és jól látható.

## 4) Acceptance criteria
- AC1: Assistant válaszok Markdownként renderelődnek (listák, kiemelés, code block)
- AC2: Nem duplikálódik az üzenet (append-only pipeline megmarad)
- AC3: Nem romlik érzékelhetően a UI performance tipikus használatnál
- AC4: Legalább alap guardrail: csak assistant markdown, system/user marad plain

## 5) Rollback
- Kapcsoló (`renderMarkdown=false`) vagy gyors revert commit a view render részben.
