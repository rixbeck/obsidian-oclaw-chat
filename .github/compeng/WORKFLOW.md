# CompEng workflow (repo-local)

This repo uses a lightweight IPWRC workflow under **`.github/compeng/`**.

## Canonical location (SSOT)

- ✅ **All** CompEng artifacts live under: `.github/compeng/`
- ❌ Do not create `repo-root/compeng/` (divergent state risk)

Structure:
- `.github/compeng/plans/`
- `.github/compeng/runs/`
- `.github/compeng/reviews/`
- `.github/compeng/knowledge/`

## Plan lifecycle

Plan statuses follow the standard CompEng flow:
- `draft` → `approved` → `work` → `review` → `compound` → `done`

(We still keep historical artifacts even after `done`.)

## Repo rule: Obsidian plugin manifest versioning (REQUIRED)

When you change Obsidian plugin code (anything that affects the shipped plugin), you must bump the plugin version **before committing**.

### What to bump
- `obsidian-plugin/manifest.json` → `version`

### Versioning scheme
- Use **Semantic Versioning**: `MAJOR.MINOR.PATCH`
  - **PATCH**: bugfix / internal changes, no new features
  - **MINOR**: new feature, backwards-compatible
  - **MAJOR**: breaking change

### When
- **Every code change** (incl. UI, WS protocol behavior, settings, styles) that results in a new plugin build.
- Do it **before** the commit that contains the change.

### Why
- Keeps Obsidian updates predictable.
- Avoids “changed code but same version” confusion during manual installs.
