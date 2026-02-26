# obsidian-oclaw-chat

Bidirectional chat integration between **Obsidian** and **OpenClaw Gateway**.

## Components

- **OpenClaw channel extension**: `channel-plugin/`
  - README: `channel-plugin/README.md`
- **Obsidian community plugin**: `obsidian-plugin/`
  - README: `obsidian-plugin/README.md`

## Current architecture (important)

The Obsidian client plugin uses the **built-in Gateway protocol**:
- handshake: `connect` (protocol v3) + device-auth
- send: `chat.send`
- receive: gateway `event: "chat"` (render final-only)

The `obsidian.*` gateway methods exist in the channel plugin, but the client does not rely on them.

## Recommended secure remote access (tailnet)

Use **Tailscale Serve** (TLS termination) instead of direct plaintext `ws://<tailnet-ip>:18789`:

- Gateway binds to loopback: `127.0.0.1:18789`
- Tailscale Serve exposes:
  - Web UI: `https://<host>.tailnet.ts.net/`
  - WebSocket: `wss://<host>.tailnet.ts.net/` (**no port**, implicit 443)

## Quick links (CompEng)

- E2E deployment plan: `.github/compeng/plans/20260225-1440-e2e-obsidian-channel-eve1-deployment.md`
- Run log: `.github/compeng/runs/20260225-1459-e2e-deployment-progress.md`
- Reviews:
  - `.github/compeng/reviews/20260225-2146-obsidian-oclaw-chat.md`
  - `.github/compeng/reviews/20260225-2336-obsidian-oclaw-chat-followup.md`

## License

MIT
