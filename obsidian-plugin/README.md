# Obsidian Community Plugin — OpenClaw Chat (`obsidian-openclaw-chat`)

Chat with an OpenClaw agent **from inside Obsidian**.

## How it works (current)

The plugin connects directly to the **OpenClaw Gateway WebSocket** and uses built-in Gateway protocol:

- Handshake: `connect` (protocol v3) + device-auth (Ed25519)
- Send: `chat.send({ sessionKey, message, idempotencyKey })`
- Receive: `event: "chat"` (filtered to `state:"final"`)

## Install

1) Build the plugin:
```bash
cd obsidian-plugin
npm ci
npm run build
```

2) Copy to your vault:
```bash
VAULT=/path/to/your/vault
mkdir -p "$VAULT/.obsidian/plugins/obsidian-openclaw-chat"
cp main.js manifest.json styles.css "$VAULT/.obsidian/plugins/obsidian-openclaw-chat/"
```

3) Enable it:
- Obsidian → Settings → Community plugins → Installed plugins → **OpenClaw Chat** → ON

## Configuration

### Recommended gateway URL (tailnet, secure)
If the gateway is exposed via **Tailscale Serve**:
- **Gateway URL:** `wss://<host>.tailnet.ts.net`
  - Note: **no `:18789`** here (Serve terminates TLS on 443 and proxies to 127.0.0.1:18789).

### Token
- **Gateway token:** must match the OpenClaw Gateway token (`gateway.auth.token` / `OPENCLAW_GATEWAY_TOKEN`).

### Session Key
- Usually: `main`

### Progress indicator
- After the gateway acknowledges `chat.send` (first successful response), the **Send** button becomes a spinner.
- It disappears on the first assistant final response, or on error/disconnect.

## Pairing (required for sending)

To obtain `operator.write`, the plugin uses a device identity and requires pairing/approval.

If sending fails with `pairing required` / missing scope:
1) Open the Gateway Control UI
2) Approve the device pairing request
3) Retry sending

## Troubleshooting

- “No response / hangs”:
  - You likely used `ws://` instead of `wss://` against a Serve endpoint.

- “Origin not allowed”:
  - Ensure gateway `controlUi.allowedOrigins` includes:
    - `app://obsidian.md`
    - `https://<host>.tailnet.ts.net`

- Spinner stuck:
  - There is a 120s safety timeout; reconnecting should also reset it.
