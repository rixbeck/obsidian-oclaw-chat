---
type: pattern
created: 2026-02-26T19:38:00+01:00
tags: [obsidian, plugin, sessions, ux]
---

# Pattern — Session switch UX: insert a divider, don’t clear chat

## Intent
Let the user switch OpenClaw `sessionKey` from a UI without losing local context and without confusing continuity.

## Pattern
On session switch:
1) (best-effort) abort any in-flight run for the previous session
2) append a **system divider** message at the start of the new session
   - short label in content
   - full session key on hover (title)
3) persist `settings.sessionKey`
4) reconnect WS client / update routing

## Why
- clearing chat is disruptive
- mixing sessions without any marker is confusing
- divider gives a cheap, scannable boundary
