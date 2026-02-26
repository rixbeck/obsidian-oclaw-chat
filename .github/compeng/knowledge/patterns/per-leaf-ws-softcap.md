---
type: pattern
created: 2026-02-26T22:20:00+01:00
tags: [obsidian, websocket, performance]
---

# Pattern — Multi-leaf WS clients: add a soft cap / warning

## Intent
When each UI leaf opens its own WebSocket connection, prevent accidental reconnect storms / duplicated inbound work.

## Pattern
- Track the number of open leaves.
- If above a small threshold (e.g. 3), show a throttled warning Notice.
- (Later) consider reuse/pooling if it becomes a real issue.
