---
status: in-progress
repo: rixbeck/obsidian-oclaw-chat
branch: develop
started: 2026-02-25 14:59 Europe/Budapest
plan: .github/compeng/plans/20260225-1440-e2e-obsidian-channel-eve1-deployment.md
scope: "E2E deployment + testing: Obsidian channel on Eve-1"
---

# Run — E2E Deployment Progress (Eve-1)

## Goal

Deploy and test Obsidian channel plugin + Obsidian client plugin on Eve-1 gateway.

## Steps Completed

### 1. Environment Setup (14:59-15:15)

✅ **Obsidian installed Eve-1:**
- AppImage: `~/bin/obsidian`
- FUSE dependency installed
- `--no-sandbox` flag required (SUID sandbox issue)

✅ **OpenClaw version sync:**
- Local (Asus): 2026.2.15 → 2026.2.19-2
- Eve-1: 2026.2.19-2 ✅ Match

✅ **Obsidian GNOME integration (Eve-1):**
- Desktop entry: `~/.local/share/applications/obsidian.desktop`
- Wrapper script: `~/bin/obsidian-launcher` (DISPLAY fallback)
- Desktop database updated

✅ **Passwordless GNOME login (Eve-1):**
- wall-e: NP (No Password)
- rix: NP (No Password)
- PAM configured: `pam_unix.so nullok`
- GDM restarted (16:41:03 CET)

### 2. Plugin Build (Local) (15:00-15:15)

✅ **Channel plugin build:**
- `npm run build` → `dist/` output
- Location: `workspace/obsidian-oclaw-chat/channel-plugin/dist/`

✅ **Obsidian plugin build:**
- `npm run build` → `main.js`
- Location: `workspace/obsidian-oclaw-chat/obsidian-plugin/main.js`

✅ **Auth token generated:**
- Token: `a3a89c8eab8cd88062702b79858ac7ad`
- Saved: `/tmp/eve-obsidian-token.txt` (600 perms)

### 3. Plugin Deployment Attempts (15:02-15:17)

⚠️ **Initial deployment failed:**
- Plugin copied to `~/.openclaw/plugins/openclaw-channel-obsidian/`
- Config added: `channels.obsidian` block
- **Error:** "unknown channel id: obsidian"

✅ **Root cause identified (15:08-16:07):**
- Analyzed OpenClaw source code (`/usr/lib/node_modules/openclaw/extensions/`)
- Compared with bundled plugins (telegram/discord/slack)
- **Missing:** `channels: ["obsidian"]` in `openclaw.plugin.json`

✅ **Manifest fix applied:**
```json
{
  "id": "openclaw-channel-obsidian",
  "channels": ["obsidian"],  // ← Added
  "name": "OpenClaw Channel - Obsidian",
  // ...
}
```

✅ **Plugin moved to correct location:**
- From: `~/.openclaw/plugins/` (wrong)
- To: `~/.openclaw/extensions/openclaw-channel-obsidian/` (correct)

⚠️ **Runtime error encountered (15:17):**
```
TypeError: Cannot read properties of undefined (reading 'info')
```

### 4. Source Code Analysis & Refactoring (16:36-17:07)

✅ **Canonical plugin pattern identified:**

**Bundled plugins (telegram/discord/slack):**
```typescript
const plugin = {
  id: "plugin-id",
  name: "Plugin Name",
  description: "Description",
  configSchema: emptyPluginConfigSchema(),
  register(api: OpenClawPluginApi) {
    setRuntimeReference(api.runtime);
    api.registerChannel({ plugin: channelPluginObject });
  },
};

export default plugin;  // ← DEFAULT EXPORT
```

**Our plugin (original - broken):**
```typescript
export function register(ctx: any) {  // ← NAMED EXPORT, wrong signature
  const { log, config, runtime } = ctx;
  // ...
}
```

✅ **Refactored files:**
- `src/index.ts` — Default export plugin object ✅
- `src/runtime.ts` — Runtime reference storage ✅
- `src/channel.ts` — ChannelPlugin object (type errors remain)
- `src/service.ts` — Refactored to use runtime (type errors remain)

✅ **Dependencies installed:**
- `npm install --save-dev openclaw@2026.2.19-2`
- `tsconfig.json` updated: `moduleResolution: "bundler"`

⚠️ **TypeScript type errors (blocker):**
```
- ChannelMeta.name does not exist
- setup.gatewayStart does not exist
- OpenClawRuntime type not exported
- setAccountEnabled/deleteAccount return type mismatch
```

**Commit:** `2d68089` — WIP refactor to canonical pattern

---

## Current Status (17:07)

**Phase:** WORK (in progress)  
**Blocker:** TypeScript type errors in plugin code  
**Next:** Fix type errors by studying OpenClaw plugin-sdk type definitions

---

## Next Steps (Immediate)

1. **Fix TypeScript type errors:**
   - Study `/usr/lib/node_modules/openclaw/dist/plugin-sdk/*.d.ts`
   - Correct ChannelPlugin field names/signatures
   - Fix ChannelMeta structure

2. **Build + Deploy:**
   - `npm run build` → resolve all type errors
   - Deploy to Eve-1: `~/.openclaw/extensions/openclaw-channel-obsidian/`
   - Update config: `plugins.entries` + `channels.obsidian`

3. **Gateway Test:**
   - Start Eve-1 gateway
   - Check plugin load logs
   - Verify WebSocket server starts on port 8765

4. **Obsidian Client Test:**
   - Install plugin in local Obsidian vault
   - Configure gateway URL + token
   - Test connection + message flow

---

## Files Changed (This Run)

**Repo (obsidian-oclaw-chat):**
- `channel-plugin/openclaw.plugin.json` — Added `channels` array
- `channel-plugin/src/index.ts` — Refactored to default export pattern
- `channel-plugin/src/runtime.ts` — Created runtime storage
- `channel-plugin/src/channel.ts` — Refactored ChannelPlugin object (WIP)
- `channel-plugin/src/service.ts` — Refactored WebSocket service (WIP)
- `channel-plugin/tsconfig.json` — Updated moduleResolution
- `channel-plugin/package.json` — Added openclaw devDependency

**Eve-1 (remote):**
- `~/bin/obsidian` — Obsidian AppImage
- `~/bin/obsidian-launcher` — Wrapper script
- `~/.local/share/applications/obsidian.desktop` — Desktop entry
- `~/.openclaw/extensions/openclaw-channel-obsidian/` — Plugin deployment
- `~/.openclaw/openclaw.json` — Config: channels.obsidian + plugins.entries
- `/etc/pam.d/common-auth` — Added nullok for passwordless login
- `/etc/gdm3/custom.conf` — Disabled autologin

**Local (Asus):**
- `/tmp/eve-obsidian-token.txt` — Auth token (600)

---

## Lessons / Gotchas

1. **Plugin manifest `channels` array is required:**
   - Without it, OpenClaw validation rejects `channels.<id>` config blocks
   - Ref: `openclaw.plugin.json` must declare channel IDs

2. **Plugin export pattern:**
   - Must use `export default plugin` (NOT `export function register`)
   - Signature: `register(api: OpenClawPluginApi)` (NOT `ctx: any`)

3. **Plugin location:**
   - Local plugins: `~/.openclaw/extensions/<plugin-id>/`
   - NOT `~/.openclaw/plugins/` (that's for npm-installed plugins)

4. **Config structure:**
   - `plugins.entries.<plugin-id>.enabled: true`
   - `plugins.entries.<plugin-id>.config: { ... }` (plugin-specific config)
   - `channels.<channel-id>: { ... }` (channel-specific config)

5. **TypeScript module resolution:**
   - `openclaw/plugin-sdk` requires `moduleResolution: "bundler"` or `"node16"`
   - Default `"node"` does not resolve package.json exports map

---

## Time Log

| Phase | Duration | Notes |
|-------|----------|-------|
| Obsidian install | 16 min | AppImage + FUSE + GNOME integration |
| Channel plugin build | 15 min | Initial build + dependencies |
| Deployment troubleshooting | 1h 15min | Manifest fix, location fix, source analysis |
| Refactoring to canonical pattern | 31 min | index.ts, runtime.ts, channel.ts, service.ts |
| **Total elapsed** | **~2h 17min** | **Still in progress** |

---

## Estimated Remaining

- Fix type errors: 30-60 min
- Build + deploy: 15 min
- Gateway test: 15 min
- Obsidian client test: 30 min
- **Total:** ~1.5-2h

---

**Status:** In progress, type errors blocking build  
**Next checkpoint:** After successful plugin load in gateway

---

### 7. Architecture Refactor: Gateway Method-Based API (17:48-18:11)

**Rationale:** Remove custom WS server (port 8765), use Gateway WebSocket only (18789).

✅ **Gateway bind mode changed to tailnet:**
- Eve-1 config: `gateway.bind = "tailnet"` (was `loopback`)
- Gateway now listens on Tailscale IP: `ws://100.90.9.68:18789`
- Obsidian clients can connect from tailnet (not just localhost)

✅ **New gateway.ts implementation:**
- Gateway methods: `obsidian.subscribe`, `obsidian.send`, `obsidian.unsubscribe`
- Session-scoped subscriptions: `subscriptionId -> { sessionKey, connectionId }`
- Broadcast function captured from `context.broadcastToConnIds` (first subscribe call)
- Push hook: `api.on("before_message_write")` → filters assistant messages → broadcasts to subscribed clients

✅ **index.ts refactored:**
- Removed `registerService()` call (no custom WS server)
- Registered 3 gateway methods
- Registered `before_message_write` hook for push
- No `gateway_connection_closed` hook (doesn't exist in OpenClaw SDK)

✅ **TypeScript build fixed:**
- Corrected `GatewayBroadcastToConnIdsFn` signature: `(event: string, payload: unknown, connIds: ReadonlySet<string>, opts?)` 
- Used `client.connId` instead of `context.connectionId` (correct SDK type)
- Build passed: `npm run build` ✅

✅ **Deployed to Eve-1:**
- Synced `dist/` to `eve-1:.openclaw/extensions/openclaw-channel-obsidian/dist/`
- Gateway restarted with `--bind tailnet --port 18789`

✅ **Gateway logs confirm:**
```
2026-02-25T17:09:58.983Z [gateway] [obsidian] Gateway methods registered (subscribe, send, unsubscribe)
2026-02-25T17:09:59.257Z [gateway] listening on ws://100.90.9.68:18789
```

✅ **No more port 8765 WS server** (successfully removed)

---

## Updated Status

**Gateway running:** Eve-1, ws://100.90.9.68:18789, tailnet bind ✅  
**Plugin loaded:** openclaw-channel-obsidian, gateway methods registered ✅  
**Custom WS server:** Removed ✅ (only Gateway WS now)

**Next:** Update Obsidian client to use Gateway WS + new protocol (subscribe/send/unsubscribe methods).
