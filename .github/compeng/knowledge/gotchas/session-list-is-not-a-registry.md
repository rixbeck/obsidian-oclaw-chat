---
type: gotcha
created: 2026-02-26T21:38:00+01:00
tags: [openclaw, sessions, gateway, obsidian]
---

# Gotcha — `sessions.list` is not a registry of arbitrary session keys

## Symptom
A client uses freeform session keys (e.g. `obsidian-YYYYMMDD-HHMM`) and expects them to show up in `sessions.list` for selection.
In practice, they often disappear or never appear, causing confusing UX.

## Root cause
OpenClaw’s session model is primarily **routing-derived**:
- canonical store keys follow `agent:<agentId>:<channel>:(direct|group|channel):<peerId>` (or special kinds like `agent:...:cron:...`)
- UI/request keys may be aliases (`telegram:@user`, `openclaw-tui`) that are converted to store keys

`sessions.list` reflects this store/routing reality; it does not guarantee visibility of arbitrary user-chosen strings.

## Fix
For non-channel clients (e.g. Obsidian), adopt canonical keys under your own channel namespace:
- `agent:main:obsidian:direct:<vaultHash>`

If you need multiple sessions, keep a **client-local known list** (persisted) rather than relying on gateway discovery.
