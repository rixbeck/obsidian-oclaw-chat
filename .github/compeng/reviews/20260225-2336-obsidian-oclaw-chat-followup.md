---
status: draft
repo: rixbeck/obsidian-oclaw-chat
branch: develop
reviewedAt: 2026-02-25 23:36 Europe/Budapest
plan:
  - .github/compeng/plans/20260225-1440-e2e-obsidian-channel-eve1-deployment.md
run:
  - .github/compeng/runs/20260225-1459-e2e-deployment-progress.md
context:
  - Follow-up review after successful tailnet/WSS connectivity on Asus gateway (Tailscale Serve) and enabling the channel plugin locally.
notes:
  - Attempted parallel sub-agent review; some runs hit provider 429 rate limits and one hit a gateway-token mismatch. This report is therefore single-agent + partial sub-agent signals.
---

# Follow-up Review — Obsidian ↔ OpenClaw chat integration (post-E2E + ops hardening)

## Scope / summary

This review follows the earlier report (`.github/compeng/reviews/20260225-2146-obsidian-oclaw-chat.md`) and incorporates the additional findings from the final “make it work securely on tailnet” steps:

- Gateway exposure mode matters: direct `ws://<tailnet-ip>:18789` vs **Tailscale Serve** exposing `wss://<host>.tailnet` (portless).
- Local gateway configuration ended up using **loopback + tailscale serve**, which is the correct trade-off for UI/TUI and Obsidian client.
- Channel plugin **loads** and registers gateway methods (confirmed by logs).

## Must-fix (blocking)

1) **Documentation + settings drift: “ws://…:18789” vs “wss://… (no port)”**
   - Real-world usage on Asus proved that clients can “hang” with *no response* if they accidentally use `ws://` against an HTTPS-served endpoint.
   - Action:
     - In `README.md`, make `wss://<host>.tailnet` the *primary* recipe.
     - Explicit callout: **no `:18789` when using Tailscale Serve**.
     - Keep `ws://127.0.0.1:18789` (SSH tunnel) as the “safe fallback”.

2) **Plugin config schema mismatch / stale requirements**
   - Earlier, `openclaw.plugin.json` required `authToken` which caused config validation failures.
   - We removed `authToken` requirement locally to unblock load; the repo should reflect this final architecture consistently.
   - Action:
     - Ensure `channel-plugin/openclaw.plugin.json` configSchema matches *actual runtime behavior* (Gateway handshake handles auth; plugin methods do not require a separate token).
     - Ensure README does not instruct to set `channels.obsidian.authToken` if it’s no longer used.

3) **Clarify and/or remove `obsidian.*` gateway methods**
   - Current Obsidian client path uses built-in `chat.send` + event stream.
   - Keeping `obsidian.subscribe/send/unsubscribe` invites confusion and may require scopes external clients can’t obtain.
   - Action (choose one):
     - **Remove** `obsidian.*` methods from `channel-plugin/src/gateway.ts` (prefer), OR
     - Mark explicitly internal/admin-only, and document scopes/limitations.

## Should-fix

1) **Connection lifecycle / memory safety in subscription map**
   - `gateway.ts` stores subscriptions keyed by `subscriptionId` and can broadcast by filtering all values.
   - Without a guaranteed “connection closed” hook, subscriptions can leak if a client disappears without calling `unsubscribe`.
   - Action:
     - If `obsidian.*` remains: add TTL-based sweep OR index subscriptions by `connId` to prune on any available lifecycle event.

2) **Remove or quarantine legacy code paths (potential overhang)**
   - There are legacy artifacts from the initial “custom WS server (8765)” design (`service.ts`, `rpc.ts` etc.).
   - Even if not used, they increase cognitive load and can mislead future changes.
   - Action:
     - Delete unused files or add big “DEPRECATED / NOT USED” header comments.

3) **Settings UX cleanup**
   - Ensure labels consistently say **Gateway URL** + **Gateway token**.
   - If `accountId` is no longer meaningful for the client path, hide it (or explain it).

4) **Gateway proxy trust / origin policy**
   - When using Tailscale Serve as a reverse proxy, the gateway may see proxy headers.
   - Action:
     - Document recommended `gateway.trustedProxies` and required `gateway.controlUi.allowedOrigins` entries for:
       - `app://obsidian.md`
       - `https://<host>.tailnet`

## Nice-to-have

- Add an E2E smoke test checklist for the Serve/WSS setup:
  - `wss://host.tailnet` connects
  - pairing flow if `operator.write`
  - `chat.send` roundtrip

## Risk & blast radius

- **High-risk:** exposing token auth over plaintext `ws://` to tailnet IPs.
- **Medium-risk:** lingering unused code and schema drift causing future breakage when someone follows the README.

## Security / supply-chain notes

- Ensure no tokens are committed (only runtime files).
- Prefer `wss://` (Serve) or SSH tunnel to avoid token leakage.

## Suggested next actions (sequenced)

1) Update `README.md` with the *canonical* “Tailscale Serve → wss://host.tailnet (no port)” recipe.
2) Align `channel-plugin/openclaw.plugin.json` schema with the post-pivot architecture (no `authToken` requirement).
3) Decide fate of `obsidian.*` gateway methods; remove if not needed.
4) Add minimal tests for connect/protocol version, and a lint/build CI check.
