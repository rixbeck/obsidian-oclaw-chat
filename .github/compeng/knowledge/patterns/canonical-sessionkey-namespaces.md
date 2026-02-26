---
type: pattern
created: 2026-02-26T21:38:00+01:00
tags: [openclaw, sessions, routing]
---

# Pattern — Use canonical session key namespaces for external clients

## Intent
Make sessions predictable, filterable, and compatible with OpenClaw routing + storage.

## Pattern
Use canonical store keys:
- `agent:<agentId>:<channel>:direct:<peerId>`
- `agent:<agentId>:<channel>:group:<peerId>` (defer if no ACL)

For Obsidian:
- choose vault-scoped peerId: `peerId = shortHash(absVaultPath)`
- session: `agent:main:obsidian:direct:<vaultHash>`

## Why
- aligns with `resolveAgentRoute()` + `buildAgentPeerSessionKey()` conventions
- avoids alias/freeform drift
- makes it safe to filter "obsidian sessions" by prefix
