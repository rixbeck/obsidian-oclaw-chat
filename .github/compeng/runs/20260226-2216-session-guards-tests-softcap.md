---
type: run
status: done
created: 2026-02-26T22:16:00+01:00
repo: obsidian-oclaw-chat
branch: develop
plan: ../plans/20260226-2212-session-guards-tests-softcap.md
---

# Run — Session guards + soft cap + tests

## Implemented
- VaultHash-scoped allowlist for session keys:
  - only `main` or `agent:main:obsidian:direct:<vaultHash>(-suffix)` allowed when vaultHash known
  - when vaultHash unknown: New disabled and switching restricted to `main`
- Soft cap warning for too many chat leaves (default >3, throttled).
- Extracted migration/session logic into `src/session.ts` + added unit tests.

## Tests
- Added `src/session.test.ts` (5 tests)
- Total tests: 25

## Gates
- typecheck ✅
- tests ✅ (25/25)
- build ✅
