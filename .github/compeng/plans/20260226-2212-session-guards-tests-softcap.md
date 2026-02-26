---
type: plan
status: approved
created: 2026-02-26T22:12:00+01:00
repo: obsidian-oclaw-chat
branch: develop
owner: Rix
scope:
  - obsidian-plugin/src/main.ts
  - obsidian-plugin/src/view.ts
  - obsidian-plugin/src/session.ts (new)
  - obsidian-plugin/src/*.test.ts
---

# Plan — Session guards + multi-leaf soft cap + tests (A)

## Goals
1) **VaultHash-scoped allowlist**: prevent cross-vault session routing.
2) **Multi-leaf soft cap / warning**: reduce WS storm risk.
3) **Tests** for canonical session migration + multi-leaf isolation.

## 1) VaultHash-scoped allowlist (SEC must-fix)
### Behavior
If `vaultHash` is known:
- Allow only:
  - `main`
  - `agent:main:obsidian:direct:<vaultHash>`
  - `agent:main:obsidian:direct:<vaultHash>-<suffix>`
- Reject everything else (Notice + no switch + do not persist).

If `vaultHash` is unknown:
- Disable New…
- Allow switching to `main` only.

### Changes
- Add helper `isAllowedObsidianSessionKey({ key, vaultHash })` in new module `src/session.ts`.
- Use it in:
  - view `_switchSession`
  - plugin `rememberSessionKey`
  - view dropdown population (filter keys)

## 2) Multi-leaf soft cap (PERF)
### Behavior
- Track number of open chat leaves.
- If count exceeds `MAX_CHAT_LEAVES` (default 3):
  - show Notice once per session (throttled)
  - still allow opening, but warn.

### Changes
- In plugin:
  - `registerChatLeaf()` / `unregisterChatLeaf()` counters.
- In view:
  - call register in `onOpen`, unregister in `onClose`.

## 3) Tests (TESTS must-fix)
### Migration pure function
- Extract migration logic from plugin `onload()` into pure function in `src/session.ts`:
  - `migrateSettingsForVault(settings, vaultHash) -> { nextSettings, canonicalKey }`
- Unit test cases:
  - empty/main/agent:main:main -> canonical
  - legacy `obsidian-*` stored into `legacySessionKeys` + canonical
  - idempotent (no duplicates in known list)

### Multi-leaf isolation (minimal)
- Add a test stub view class or factory injection:
  - ensure two `OpenClawChatView` instances have distinct `wsClient` + `chatManager`.

(We can do this by exporting small factories from `main.ts` or by injecting `createWsClient` already present.)

## Gates
- typecheck
- tests
- build
