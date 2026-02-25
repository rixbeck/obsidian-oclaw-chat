---
status: draft
repo: rixbeck/obsidian-oclaw-chat
branch: develop
reviewedAt: 2026-02-25 21:46 Europe/Budapest
plan:
  - .github/compeng/plans/20260225-1440-e2e-obsidian-channel-eve1-deployment.md
run:
  - .github/compeng/runs/20260225-1459-e2e-deployment-progress.md
---

# Review — Obsidian ↔ OpenClaw chat integration

## Scope / summary

Reviewed the current `develop` branch changes implementing the Obsidian client plugin + OpenClaw channel plugin and the later protocol pivot to use **built-in Gateway methods** (`connect`, `chat.send`, `event:chat`) plus device-auth.

**High-level state:** the E2E path is now close to correct: pairing via Web UI succeeds, `chat.send` starts runs, and chat events arrive (sessionKey canonicalization + delta/final behavior already handled).

> Note: I attempted to run the full multi-subagent `walle-review` workflow, but `sessions_spawn` is currently failing in this environment due to a Gateway token mismatch in the main OpenClaw runtime. This report is a single-agent review.

## Must-fix (blocking)

1) **Clarify/standardize “token” naming in the Obsidian settings UI + docs**
   - Current UX repeatedly caused confusion between:
     - **Gateway shared token** (`gateway.auth.token`) — required for `connect`.
     - Legacy per-channel `channels.obsidian.authToken` — no longer used after pivot.
   - Action:
     - Rename setting label to **“Gateway token”**.
     - Update description text accordingly.
     - Remove/mark deprecated any mention of per-channel token.

2) **Remove dead-end/unused Gateway methods (`obsidian.*`) or clearly mark deprecated**
   - The repo currently contains:
     - Channel plugin gateway methods: `obsidian.subscribe/send/unsubscribe` (channel-plugin/src/gateway.ts)
     - Obsidian client currently uses `chat.send` and `event:chat`.
   - Problem: `obsidian.*` methods require scopes that external clients typically cannot obtain (earlier blocker). Keeping them invites future confusion.
   - Action:
     - Either delete `obsidian.*` methods from the channel plugin,
     - or make them internal-only with clear docs (“requires operator.admin; not intended for Obsidian client”).

3) **Security posture: ws:// to tailnet is dangerous-by-default**
   - OpenClaw CLI already blocks `ws://` to non-loopback for good reason.
   - The Obsidian client currently uses `ws://...:18789` in docs/examples.
   - Action (choose one):
     - Provide a supported **wss://** path (Tailscale Serve / TLS reverse-proxy), or
     - Provide an SSH-tunnel + `ws://127.0.0.1:18789` workflow for clients,
     - and document it as the recommended default.

## Should-fix

1) **Device identity storage & rotation UX**
   - Private key is stored as JWK in `localStorage` (`openclawChat.deviceIdentity.v1`).
   - This is acceptable for a dev prototype, but needs:
     - explicit “Reset device identity” button in settings (clears localStorage key)
     - clear explanation that pairing is bound to this identity.

2) **Chat rendering semantics**
   - Current client filters `state !== 'final'` which avoids duplicates.
   - However, it also removes any partial streaming UX.
   - Action: either:
     - keep final-only (simpler) but document it, or
     - implement streaming accumulation keyed by `runId` (nice UX).

3) **Session key canonicalization**
   - You added `main -> agent:main:main` alias.
   - Consider generalizing:
     - optionally call `sessions.resolve` (if available) to discover canonical key,
     - or accept any `incomingSessionKey.endsWith(':main')` when configured is `main`.

4) **Channel-plugin: subscription cleanup**
   - `cleanupConnection()` exists but is not called (no hook exists).
   - If `obsidian.*` methods are kept, add a TTL sweep or integrate cleanup through a gateway lifecycle hook (if/when SDK adds one).

## Nice-to-have

- Add an “E2E smoke test script” (even manual steps codified) validating:
  - connect handshake
  - pairing required → approve
  - chat.send ok
  - chat event received
- Add CI checks:
  - lint/format
  - TypeScript build for both plugins
- Reduce repo noise:
  - consider whether shipping built artifacts (`obsidian-plugin/main.js`) in-repo is desired; if yes, document release flow; if no, ignore it in git.

## Risk & blast radius

- **High-risk area:** device-auth implementation (crypto + protocol exactness). Small changes can break pairing/handshake.
- **Operational risk:** leaving `allowedOrigins: ["*"]` and Control UI break-glass flags enabled on a tailnet-exposed gateway.

## Security / supply-chain notes

- New dependencies + lockfiles are committed (notably large `package-lock.json`). That’s fine, but:
  - ensure `npm audit`/pinning strategy is acceptable.
- Confirm no secrets committed:
  - token values should never appear in repo (only in runtime files on Eve-1).

## Suggested next actions (sequenced)

1) Update Obsidian settings UI: rename token field to “Gateway token” + update help text.
2) Decide fate of `obsidian.*` methods in channel plugin (delete or explicitly internal-only).
3) Document secure transport (wss/ssh tunnel) as default.
4) Add “Reset device identity” button.
5) Tighten Eve-1 gateway config back to safe defaults after debugging:
   - remove `dangerouslyDisableDeviceAuth`
   - restrict `allowedOrigins` to `app://obsidian.md`

---

## Appendix: key files reviewed

- `obsidian-plugin/src/websocket.ts`
- `obsidian-plugin/src/view.ts`
- `obsidian-plugin/src/settings.ts`
- `channel-plugin/src/gateway.ts`
- `channel-plugin/src/index.ts`
- `.github/compeng/runs/20260225-1459-e2e-deployment-progress.md`
