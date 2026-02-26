---
type: run
status: done
created: 2026-02-26T16:00:00+01:00
repo: obsidian-oclaw-chat
branch: develop
plan: ../plans/20260226-1536-obsidian-connection-alerts.md
---

# Run — Kommunikációs hiba / reconnect alert az Obsidian kliensben

## Changes
- Implementáltam egy throttled Notice + chat system message jelzést gateway kapcsolat megszakadás / visszacsatlakozás esetére.

### Fájlok
- `obsidian-plugin/src/view.ts`
  - új state: `lastConnNoticeAtMs`, `lastGatewayState`
  - `wsClient.onStateChange`-ben:
    - `connected → disconnected`: Notice + `⚠ Connection lost — reconnecting…` system message
    - `* → connected` (ahol előtte nem connected volt): Notice + `✅ Reconnected` system message
  - Throttle: 60s (hogy reconnect loop ne spammeljen)

## Gates
- `npm -C obsidian-plugin run typecheck` ✅
- `npm -C obsidian-plugin run test:once` ✅ (14/14)
- `npm -C obsidian-plugin run build` ✅

## Notes
- A Notice szándékosan throttled; több chat leaf esetén lehet duplikáció (későbbi follow-up: plugin-szintű throttle).
