# obsidian-oclaw-chat

**Bidirectional chat integration between Obsidian and OpenClaw.**

## Architecture

**Two-layer plugin system:**

1. **OpenClaw Channel Plugin** (`channel-plugin/`)
   - Runs inside OpenClaw Gateway
   - Provides gateway methods: `obsidian.subscribe`, `obsidian.send`, `obsidian.unsubscribe`
   - Session-scoped push via `before_message_write` hook
   - No custom WebSocket server (uses Gateway WS directly)

2. **Obsidian Community Plugin** (`obsidian-plugin/`)
   - Runs inside Obsidian
   - Connects to OpenClaw Gateway WebSocket (e.g. `ws://100.90.9.68:18789`)
   - Uses Gateway protocol: JSON-RPC style requests + event push
   - Sidebar chat panel with assistant message streaming

## Setup

### 1. OpenClaw Channel Plugin

**Install:**
```bash
# Copy to OpenClaw extensions directory
cp -r channel-plugin/dist ~/.openclaw/extensions/openclaw-channel-obsidian/
```

**Config** (`~/.openclaw/openclaw.json`):
```json
{
  "channels": {
    "obsidian": {
      "enabled": true,
      "authToken": "your-secret-token-here",
      "accounts": ["main"]
    }
  }
}
```

**Gateway must listen on tailnet or LAN** (not just loopback):
```json
{
  "gateway": {
    "bind": "tailnet"
  }
}
```

### 2. Obsidian Plugin

**Install:**
```bash
# Copy to Obsidian vault plugins directory
cp -r obsidian-plugin/* /path/to/vault/.obsidian/plugins/openclaw-chat/
```

**Enable in Obsidian:**
- Settings → Community plugins → Enable "OpenClaw Chat"

**Configure:**
- Gateway URL: `ws://your-gateway-host:18789` (e.g. `ws://100.90.9.68:18789`)
- Auth Token: (same as channel plugin config)
- Session Key: `main` (or your target OpenClaw session)
- Account ID: `main`

## Protocol

**Gateway methods (JSON-RPC style):**

**Subscribe:**
```json
{
  "type": "req",
  "method": "obsidian.subscribe",
  "id": "sub-1",
  "params": {
    "token": "your-token",
    "sessionKey": "main",
    "accountId": "main"
  }
}
```

**Response:**
```json
{
  "type": "res",
  "id": "sub-1",
  "ok": true,
  "payload": {
    "subscriptionId": "obsidian-123456-abc",
    "sessionKey": "main",
    "accountId": "main"
  }
}
```

**Send message:**
```json
{
  "type": "req",
  "method": "obsidian.send",
  "id": "msg-1",
  "params": {
    "subscriptionId": "obsidian-123456-abc",
    "message": "Hello from Obsidian!"
  }
}
```

**Push event (assistant message):**
```json
{
  "type": "event",
  "event": "obsidian.message",
  "payload": {
    "role": "assistant",
    "content": "Hello from OpenClaw!",
    "timestamp": 1708876543210
  }
}
```

## Development

**Build channel plugin:**
```bash
cd channel-plugin
npm install
npm run build
```

**Build Obsidian plugin:**
```bash
cd obsidian-plugin
npm install
npm run build
```

## Testing

**E2E deployment plan:** `.github/compeng/plans/20260225-1440-e2e-obsidian-channel-eve1-deployment.md`  
**Run log:** `.github/compeng/runs/20260225-1459-e2e-deployment-progress.md`

## License

MIT
