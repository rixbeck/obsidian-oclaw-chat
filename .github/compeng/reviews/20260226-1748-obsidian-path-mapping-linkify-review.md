---
type: review
status: changes-requested
created: 2026-02-26T17:48:00+01:00
repo: obsidian-oclaw-chat
branch: develop
commit_range: a581423..0cb1c75
scope:
  - obsidian-plugin/src/view.ts
  - obsidian-plugin/src/linkify.ts
  - obsidian-plugin/src/settings.ts
  - obsidian-plugin/src/types.ts
---

# Review — Path mapping + linkify (assistant file references)

## Summary
Strong direction: client-side mapping + existence check is exactly the right safety posture, and the "B" approach (clickable DOM links even when Markdown render is OFF) preserves the *untrusted-by-default* stance.

There are a couple of correctness / UX / maintainability issues worth fixing before shipping.

## Evidence / gates
- `npm -C obsidian-plugin run typecheck` ✅
- `npm -C obsidian-plugin run test:once` ✅ (19 tests)
- `npm -C obsidian-plugin run build` ✅

## Must-fix

### 1) Markdown preprocessor does not do URL reverse-conversion (spec mismatch)
- In Markdown mode, `_preprocessAssistantMarkdown()` currently leaves URLs as-is (comment says reverse-mapping handled in plain mode).
- The agreed behavior was: URLs remain absolute **unless** we can reverse-map safely to an existing vault file.

**Fix options:**
- Option A: implement the same best-effort URL reverse mapping in `_preprocessAssistantMarkdown()`.
- Option B: document/accept that reverse mapping only works in plain mode. (But then spec + user expectation differ.)

### 2) Candidate extraction misses common relative paths
- `PATH_RE` only matches absolute unix paths (`/a/b/...`).
- Assistant will often output repo-relative paths like `compeng/plans/x.md` or `obsidian-plugin/src/view.ts`.

If we keep it absolute-only, mapping won’t fire for the most common case.

**Fix:** extend extraction to include conservative relative path tokens containing at least one `/` (e.g. `foo/bar.md`) while avoiding false positives.

## Should-fix

### 1) Use `openLinkText` with a normalized link target
- Right now we pass `vaultPath` from mapping directly.
- Consider stripping `.md` for display but keep it for lookup; or use the exact vault path for open.

### 2) Settings UI: avoid full `display()` rerender on every delete/add
- The rerender approach is fine for a small list, but it resets scroll position and is a bit jarring.
- Not critical, but if this becomes used often, consider updating in-place.

### 3) Tests: add one case for URL reverse-mapping logic
- Current `linkify.test.ts` checks extraction and mapping, but not the URL reverse-map heuristic.
- A small unit test (pure helper if extracted) would lock the contract.

## Nice-to-have
- Add minimal styling for links in chat bubbles (e.g. underline / `var(--text-accent)`) so they look clickable.
- Consider supporting Windows-style paths if needed later (`C:\...`).

## Recommendation
**Changes requested** (two Must-fix items above). Once those are addressed, this is a solid feature to ship.
