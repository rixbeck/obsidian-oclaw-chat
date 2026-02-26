---
status: in-progress
repo: rixbeck/obsidian-oclaw-chat
branch: dev-terse
started: 2026-02-26 07:49 Europe/Budapest
plan: .github/compeng/plans/20260226-0748-unify-compeng-structure.md
scope: "Unify CompEng under .github/compeng; remove repo-root compeng"
---

# Run — Unify CompEng structure under `.github/compeng/`

## Goal
- Make `.github/compeng/` the only CompEng root in this repo
- Move/merge all `compeng/` artifacts under `.github/compeng/`
- Update references
- Delete repo-root `compeng/`

## Progress log

### 1) Discovery
- Enumerated artifacts in both trees: `compeng/` vs `.github/compeng/`
- Found one duplicate plan `20260225-0954-hybrid-obsidian-integration.md` in both places; hashes matched (identical).

### 2) Move / merge
- Moved unique artifacts from `compeng/` into `.github/compeng/`:
  - plan: `20260225-2353-agent-working-progress-indicator.md`
  - run: `20260226-0002-agent-working-progress-indicator.md`
  - reviews: `20260225-2146-obsidian-oclaw-chat.md`, `20260225-2336-obsidian-oclaw-chat-followup.md`
- Removed the duplicate `20260225-0954` copy from repo-root.
- Deleted the now-empty `compeng/` directory.

### 3) Reference updates
- Updated repo `README.md` review links to `.github/compeng/...`
- Updated internal frontmatter/path references that still pointed at `compeng/...`
- Adjusted the older status report tree snippet to show `.github/compeng/`.

### 4) Validation
- Verified `compeng/` directory no longer exists.
- Verified artifacts exist under `.github/compeng/{plans,runs,reviews,knowledge}`.
- `rg "\bcompeng/"` now only shows historical prose mentions, not active paths.

