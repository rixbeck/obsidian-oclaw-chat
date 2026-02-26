# OpenClaw Channel Plugin — Obsidian (`openclaw-channel-obsidian`)

This is an **OpenClaw extension** (channel plugin) that runs **inside the OpenClaw Gateway**.

## What it does

- Registers the `obsidian` channel id (so `channels.obsidian` config can exist)
- (Currently) registers gateway methods:
  - `obsidian.subscribe`
  - `obsidian.send`
  - `obsidian.unsubscribe`
- Emits session-scoped push events via a `before_message_write` hook.

### Important note (current architecture)
The Obsidian client plugin has pivoted to the **built-in gateway API**:
- send: `chat.send`
- receive: `event: "chat"`

So, in practice, the Obsidian client does **not** need to call `obsidian.*` methods.

## Install

Build:
```bash
cd channel-plugin
npm ci
npm run build
```

Install into OpenClaw extensions directory:
```bash
mkdir -p ~/.openclaw/extensions/openclaw-channel-obsidian
rsync -av --delete dist/ ~/.openclaw/extensions/openclaw-channel-obsidian/dist/
cp openclaw.plugin.json package.json ~/.openclaw/extensions/openclaw-channel-obsidian/
```

## Enable (OpenClaw config)

Edit `~/.openclaw/openclaw.json`:

```jsonc
{
  "plugins": {
    "allow": [
      "telegram",
      "openclaw-channel-obsidian"
    ],
    "entries": {
      "openclaw-channel-obsidian": { "enabled": true }
    }
  },
  "channels": {
    "obsidian": {
      "enabled": true,
      "accounts": ["main"]
    }
  }
}
```

Restart gateway:
```bash
openclaw gateway restart
```

## Secure remote access recommendation

Do **not** expose the gateway as plaintext `ws://<tailnet-ip>:18789` unless you really know what you’re doing.

Recommended:
- `gateway.bind = loopback`
- `gateway.tailscale.mode = serve`

This yields a tailnet endpoint:
- Web UI: `https://<host>.tailnet.ts.net/`
- WebSocket: `wss://<host>.tailnet.ts.net/`

(Port is **implicit 443** when using Tailscale Serve.)
