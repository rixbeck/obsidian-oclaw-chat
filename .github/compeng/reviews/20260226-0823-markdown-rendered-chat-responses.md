---
status: draft
created: 2026-02-26 08:23 Europe/Budapest
repo: rixbeck/obsidian-oclaw-chat
branch: develop
plan: .github/compeng/plans/20260226-0803-markdown-rendered-chat-responses.md
run: .github/compeng/runs/20260226-0806-markdown-rendered-chat-responses.md
scope: "Render assistant chat responses as Markdown in Obsidian client"
---

# Review — Markdown-rendered chat responses (Obsidian client)

## Summary
A változtatás a megfelelő irány: az **assistant** üzenetek Markdownként renderelődnek `MarkdownRenderer.renderMarkdown(...)` segítségével, miközben a `user/system` üzenetek plain text-ek maradnak (jó alap guardrail).

A megoldás várhatóan javítja a UX-et (listák, code blockok, kiemelés), és nem bontja meg az append-only rendering pipeline-t.

## What changed (high level)
- `obsidian-plugin/src/view.ts`
  - `.oclaw-message-body` wrapper
  - assistant: MarkdownRenderer
  - user/system: `setText`
- `obsidian-plugin/styles.css`
  - minimál styling a markdown elemekhez

## Must-fix

- Nincs.

## Should-fix

1) **CompEng státuszok konzisztenciája (workflow hygiene)**
   - A Plan frontmatter még `status: draft`.
   - A Run frontmatter még `status: in-progress`.

   Javaslat:
   - Plan: `approved` (mert explicit jóváhagytad: “Approved: Work!”)
   - Run: `done` (ha a manuális teszt is megvolt), vagy minimum `in-review`

   Megjegyzés: ez **CompEng-related**, nem a feature működésének blokkere; akkor érdemes szigorítani, ha a csapat kifejezetten így akarja enforce-olni.

2) **Markdown render guardrail: wikilink/embe d kockázat**

1) **Markdown render guardrail: wikilink/embe d kockázat**
   - Obsidian Markdown támogat `![[embed]]`, wikilinkeket, és bizonyos plugin-ek mellett ezek erős képességek.
   - Mivel az assistant output untrusted, érdemes legalább megfontolni:
     - embed-ek és transclusion minták semlegesítése (`![[` → `\![[`), vagy
     - egy beállítás (`renderMarkdown`) + külön beállítás a "disable embeds" jelleghez.

2) **Deterministic render / race safety**
   - Most `void MarkdownRenderer.renderMarkdown(...)` “fire-and-forget”.
   - Ha a view gyorsan újrarenderel (clear/reload), a régi async render még beleírhat egy már törölt DOM-ba.

   Minimál javítás:
   - üzenet elemhez egy `data-msg-id`, és render előtt ellenőrizni, hogy az elem még a DOM-ban van.
   - vagy `await`-tel sorosítani (ha nem okoz UI lagot) — de ez átvezetés a callback láncon.

## Compound artifacts created
- Pattern: `.github/compeng/knowledge/patterns/obsidian-chat-render-assistant-markdown.md`
- Gotcha: `.github/compeng/knowledge/gotchas/obsidian-markdown-render-embeds-and-race.md`

## Nice-to-have

1) **Settings toggle**
   - A Plan is említi: `renderMarkdown: boolean` (default true).
   - Ez hasznos gyors rollback/debug esetén.

2) **CSS finomhangolás**
   - `blockquote`, `table`, `hr` stílus a bubble-ben
   - `pre code` színezés / theme kompatibilitás

## Acceptance criteria check
- AC1 (markdown render): ✅ implementálva (assistant)
- AC2 (no duplication): ✅ továbbra is append-only
- AC3 (performance): ⚠️ valószínű oké, de nagy üzeneteknél érdemes ránézni (async render)
- AC4 (guardrail): ✅ user/system plain text

## Recommendation
**Approve with changes**: funkcionálisan jó, de a státuszok rendbetétele (Plan/Run) és legalább egy minimál markdown-guardrail mérlegelése ajánlott.
