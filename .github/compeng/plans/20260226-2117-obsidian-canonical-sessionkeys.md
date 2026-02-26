---
type: plan
status: approved
created: 2026-02-26T21:17:00+01:00
repo: obsidian-oclaw-chat
branch: develop
owner: Rix
---

# Plan — Canonical Obsidian session keys (agent:main:obsidian:direct:<vaultHash>)

## Context / Why (lessons from the previous plan)
The previous “session picker based on `sessions.list`” approach proved unreliable and confusing because:

1) **Gateway `sessions.list` is not a registry of arbitrary user-chosen strings**
   - It’s primarily a view over *routing-derived* sessions (telegram/signal/web/etc.), not “any string you ever used”.
   - Therefore freeform keys like `obsidian-YYYY...` may **not** appear (or appear inconsistently).

2) **Alias/request keys vs canonical store keys**
   - The system supports *legacy/alias* keys (`telegram:@rixbeck`, `openclaw-tui`) and canonical agent store keys (`agent:<agentId>:<channel>:direct|group:<peerId>`).
   - Mixing these without an explicit convention made filtering and UX brittle.

3) **UI races + prompt reliability**
   - `window.prompt()` is unreliable in Obsidian/Electron.
   - Async session switching + rebuilding a `<select>` can cause drift unless the model is simpler.

## Goal
Adopt OpenClaw’s canonical routing convention for Obsidian sessions so that:
- session keys are predictable and filterable
- “Obsidian sessions” are unambiguous
- vault-scoped continuity works across devices (Decision B)

## Non-goals (for now)
- User-auth / ACL / multi-user sharing
- `:group` sessions (explicitly deferred)

## Key decision
- **Vault-scope (B):** same vault on multiple machines → same session.

## Canonical key shape
- Default sessionKey for a vault:
  - `agent:main:obsidian:direct:<vaultHash>`

Where:
- `vaultHash = shortHash(absoluteVaultPath)`
  - e.g. sha256 hex → first 12–16 chars
  - never store the raw path in sessionKey

## UX / Settings
### 1) Remove (or demote) gateway-driven session picker
- The session dropdown should list **only** the plugin-known Obsidian sessions for this vault.
- No `sessions.list` dependency for core UX.

### 2) New session semantics (optional)
If you still want multiple sessions per vault, define them as:
- `agent:main:obsidian:direct:<vaultHash>-<slug>`

and keep a **vault-local list** (persisted) of known sessions.

### 3) Migration
On startup:
- Compute `vaultHash`.
- If `settings.sessionKey` is:
  - `main` or empty → set to the canonical vault key.
  - legacy `obsidian-YYYY...` → keep in `legacySessionKeys` (selectable) but default to canonical.

Persist:
- `vaultId` / `vaultHash` (for UI display only)
- `knownSessionKeysByVault[vaultHash] = [...]`

## Implementation steps
1) **Vault identity**
   - Determine how to get the absolute vault path in Obsidian API (desktop).
   - Compute `vaultHash` via Node `crypto` (Electron) with safe fallback.

2) **Settings schema** (`types.ts`)
   - Add:
     - `vaultHash?: string`
     - `knownSessionKeysByVault?: Record<string, string[]>`
     - `legacySessionKeys?: string[]` (optional)

3) **Startup logic** (`main.ts`)
   - Compute vaultHash.
   - Ensure `settings.sessionKey` follows the canonical format.
   - Initialize `knownSessionKeysByVault[vaultHash]` with the canonical key.

4) **UI changes** (`view.ts`, `styles.css`)
   - Session dropdown sources from `knownSessionKeysByVault[vaultHash]`.
   - Provide:
     - `New…` (creates `agent:main:obsidian:direct:<vaultHash>-<slug>`) and adds to list.
     - `Main` button can remain as an explicit escape hatch (but may be “advanced”).

5) **WS client** (`websocket.ts`)
   - No change besides `setSessionKey()` usage.

6) **Tests**
   - Unit test for canonical key generation (given a vault path → stable hash).
   - Unit test for migration rules.

## Gates
- typecheck
- tests
- build

## Risks
- Obsidian API differences between Desktop/Mobile for vault path access.
  - If mobile can’t provide a stable absolute path, we may need a user-provided vault ID or a generated/stored UUID.
