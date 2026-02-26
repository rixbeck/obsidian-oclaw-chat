---
type: gotcha
created: 2026-02-26T17:53:00+01:00
tags: [obsidian-plugin, linkify, regex]
---

# Gotcha — Absolute-path regex can “steal” subpaths inside relative tokens

## Symptom
Given text like:
- `compeng/plans/2026...md`

An absolute-path regex like `/(?:\/...)+/g` may match the **inner** `/plans/...` substring, causing:
- incorrect tokenization,
- missed relative-path extraction,
- wrong mapping behavior.

## Fix pattern
- Add a boundary check so absolute paths only match when they start as a standalone token:
  - e.g. `(?<![A-Za-z0-9._-])/(?:...)+`
- Add a separate conservative relative-path matcher for `foo/bar.md`.
- Add a unit test covering the regression.

## Where we hit this
`obsidian-plugin/src/linkify.ts` absolute path regex and `extractCandidates()`.
