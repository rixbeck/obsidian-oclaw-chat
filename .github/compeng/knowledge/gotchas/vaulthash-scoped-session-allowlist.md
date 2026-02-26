---
type: gotcha
created: 2026-02-26T22:20:00+01:00
tags: [obsidian, sessions, security]
---

# Gotcha — Prefix-based session allowlists can break vault isolation

## Symptom
A client intends vault-scoped session isolation using keys like:
- `agent:main:obsidian:direct:<vaultHash>`

…but enforces only a broad prefix allowlist:
- allow any `agent:main:obsidian:direct:*`

This allows cross-vault routing if settings are modified or a wrong key is selected.

## Fix
When `vaultHash` is known, enforce:
- `main`, or
- `agent:main:obsidian:direct:<vaultHash>`
- `agent:main:obsidian:direct:<vaultHash>-<suffix>`

Reject other `agent:main:obsidian:direct:*` keys.
