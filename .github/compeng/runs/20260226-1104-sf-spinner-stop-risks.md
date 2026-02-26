---
status: done
type: run
plan: compeng/plans/20260226-1102-sf-spinner-stop-risks.md
date: 2026-02-26
---

# Run — SF: mitigate Stop/abort risks

## Changes applied
- `obsidian-plugin/src/websocket.ts`
  - Added `abortInFlight` to prevent abort request storms.
  - Cleared per-request timeout handles on response/close.
  - Redacted unhandled frame logging (metadata only).
  - Added best-effort run correlation for inbound `chat` events when run id exists.
- `obsidian-plugin/styles.css`
  - `--color-red` fallback to `--text-error`.

## Verification
- `npm run typecheck` ✅
- `npm run build` ✅

## Notes
- This is a targeted SF; broader items (tests, identity key storage) are deferred.
