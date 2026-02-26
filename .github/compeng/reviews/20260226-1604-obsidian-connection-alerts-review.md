---
type: review
status: approved
created: 2026-02-26T16:04:00+01:00
repo: obsidian-oclaw-chat
branch: develop
commit_range: adfe43d..a4dc49c
scope:
  - obsidian-plugin/src/view.ts
---

# Review — Obsidian connection lost/reconnect notices

## What changed
- `OpenClawChatView` now shows **throttled** Obsidian `Notice` popups and also appends a **system message** in-chat when:
  - `connected → disconnected`: “connection lost — reconnecting…”
  - `* → connected` (from a non-connected previous state): “reconnected”

## Gates / evidence
- Typecheck ✅
- Tests ✅ (14/14)
- Build ✅

## Must-fix
- None for this delta.

## Should-fix
1) **Multi-leaf duplicate notices**
   - If multiple chat views are open, each leaf will emit Notices + system messages.
   - Follow-up (if it bites): move throttling to plugin-level shared state (single source of truth), or guard by “active leaf only”.

2) **Throttle coupling**
   - One timestamp throttles both “lost” and “reconnected”. In fast reconnects, the reconnect Notice may be suppressed.
   - If you want both reliably: keep separate throttles (`lastLostNoticeAtMs`, `lastReconnectedNoticeAtMs`).

## Nice-to-have
- Consider Hungarian/localized text (or reuse Obsidian i18n patterns) if you want consistent UX language.

## Recommendation
✅ Approve / good to ship. The UX improvement is clear and the spam-risk is bounded by the 60s throttle.
