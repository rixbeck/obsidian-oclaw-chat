---
type: review
status: approved
created: 2026-02-26T22:05:00+01:00
repo: obsidian-oclaw-chat
branch: develop
range: 7aae941..f3e960c
focus: [sessions, obsidian, multi-leaf, canonical-sessionkeys]
---

# Review — Multi-leaf independent sessions + canonical Obsidian session keys

## Scope
Key changes reviewed:
- Canonical vault-scoped session keys: `agent:main:obsidian:direct:<vaultHash>` (and optional `-<suffix>`)
- Session picker no longer depends on `sessions.list` gateway discovery; uses vault-scoped known list
- Multi-leaf refactor: per-view `ObsidianWSClient` + per-view `ChatManager`

Commits (high level):
- `b30b187` canonical obsidian direct session keys
- `f3e960c` multi-leaf: per-view wsClient/chatManager

## Summary
Direction is correct.

- Canonical keys align with OpenClaw routing/storage conventions and avoid the earlier `sessions.list`-driven UX brittleness.
- Per-leaf ownership is the simplest way to get true parallel chats (Ctrl+Shift+T) without state fighting.

Overall risk is **moderate** (behavioral refactor) but bounded to the Obsidian plugin.

## Must-fix (blocking)
None spotted that clearly block merge, given current constraints.

## Should-fix
1) **Resource guard for multi-leaf WS connections**
   - Each leaf opens its own WS connection and timers/heartbeats.
   - Add a soft cap (e.g. 3) or a Notice when opening many leaves.
   - Rationale: avoids accidental DoS on gateway / battery drain.

2) **Mobile / non-desktop vault identity fallback**
   - `vaultHash` depends on `FileSystemAdapter.getBasePath()` (desktop).
   - Current behavior: show Notice and keep running, but New-session creation becomes unavailable.
   - Add a deterministic fallback:
     - generate and persist a vault UUID the first time `vaultHash` can’t be computed.
   - Rationale: keeps canonical session keys usable on mobile.

3) **Settings migration clarity**
   - Settings schema shifted from earlier experimental fields to `vaultHash/knownSessionKeysByVault`.
   - Add a short note in Settings UI that session keys are now canonical and per-vault.

4) **Leaf isolation test seam**
   - Multi-leaf behavior has no automated coverage.
   - Add minimal seam for view testing (inject wsClient factory / connect function) so you can assert:
     - leaf A switching sessions doesn’t affect leaf B
     - leaf A disconnects onClose

## Nice-to-have
1) **Naming / UX polish**
   - Rename “Reload”/“New…” tooltips to clarify they are vault-scoped session keys.
   - Consider displaying a short session label in header.

2) **Model for known sessions**
   - `knownSessionKeysByVault[vaultHash]` is capped to 20 — good.
   - Consider adding a “forget session” action in future to keep list tidy.

## Risk & blast radius
- Biggest risk: more WS connections than expected → gateway load.
- Behavioral changes are local to Obsidian plugin; gateway API use remains the same (`chat.send`, `chat.abort`, `connect`).

## Security / supply-chain notes
- No new runtime dependencies added.
- `vaultHash` uses sha256 of local absolute path but only stores a 16-hex prefix → does not leak the path, but it’s still a stable identifier.
- Session switching is restricted to `main` or `agent:main:obsidian:direct:*` (good constraint).

## Verdict
**Approved** with Should-fix items tracked (resource guard + mobile fallback + minimal tests).