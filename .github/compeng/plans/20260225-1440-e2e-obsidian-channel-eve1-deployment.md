---
status: draft
priority: high
tags: [e2e, deployment, testing, eve-1, obsidian-channel, obsidian-plugin]
owner: Rix
created: 2026-02-25 14:40
estimated_hours: 4-6
issue: inline
related:
  - .github/compeng/plans/20260225-0954-hybrid-obsidian-integration.md
  - workspace:/compeng/plans/20260225-1048-supervising-obsidian-oclaw-chat.md
  - workspace:/compeng/plans/20260218-1635-eve-bootstrap-plan-v1.md
---

# Plan — E2E Deployment + Testing: Obsidian Channel on Eve-1

## 0) Issue (inline)

### Problem / Context
- **Obsidian channel plugin + Obsidian community plugin implementáció elkészült** (Phase 1 + Phase 2 done).
- **Nincs E2E teszt**: a két komponens együttműködése nem volt tesztelve production-szerű környezetben.
- **Eve-1** = élő OpenClaw gateway végpont (eve-bootstrap által telepített), ideális célpont E2E smoke test-hez.
- **Status quo:** lokális fejlesztés (`develop` branch), de soha nem volt deploy gateway-re.

### Proposal (Solution)
**E2E deployment + smoke test Eve-1 környezetben:**

1. **Channel plugin deploy Eve-1 gateway-re:**
   - SSH: `wall-e@eve-1` (Tailscale)
   - Build channel plugin (`npm run build`)
   - Copy `channel-plugin/` → Eve-1 OpenClaw plugins dir
   - Config: edit `~/.openclaw/openclaw.json` (add `channels.obsidian` block)
   - Restart gateway

2. **Obsidian plugin deploy lokális Asus-ra (wall-e user):**
   - Check: Obsidian already installed (`/usr/bin/obsidian`)
   - Build plugin (`npm run build` → `main.js`)
   - Copy plugin → Obsidian vault `.obsidian/plugins/obsidian-openclaw-chat/`
   - Enable plugin in Obsidian settings
   - Configure: gateway URL (Eve-1 Tailscale IP + WS port), auth token

3. **E2E smoke test (3 acceptance criteria):**
   - ✅ Obsidian sidebar → send message → agent reply back
   - ✅ Agent proactive push (trigger RPC `obsidian.sendMessage` from gateway console)
   - ✅ Gateway restart → Obsidian plugin auto-reconnect

### Benefits
- **Early bug detection:** kiszűrjük az alapvető integráció hibákat (WS handshake, auth, message flow) production-szerű környezetben.
- **Confidence:** mielőtt továbblépünk Phase 3-ra (streaming, @mentions, stb.), tudjuk hogy az alap működik.
- **Realistic test:** Eve-1 = éles gateway, nem mock/stub.

### Risks / Challenges
- **Eve-1 connection:** SSH timeout → deployment nem végezhető el (mitigáció: Tailscale + network check előfeltétel).
- **Gateway instability:** config change vagy plugin load failure → gateway crash/restart loop (mitigáció: config backup + rollback plan).
- **Token exposure:** auth token config file-ban plaintext → gondos handling (ne kerüljön log-ba/screen-be).
- **Obsidian vault:** local vault kell a teszthez → ha nincs, létre kell hozni (mitigáció: default test vault).

---

## 1) Goals / Deliverables

### Must-have (MVP smoke test)

**Channel plugin (Eve-1):**
- ✅ Build successful (`npm run build` → `dist/index.js`)
- ✅ Deployed to Eve-1 OpenClaw plugins directory
- ✅ Config: `channels.obsidian` block in `openclaw.json` (wsPort, authToken, enabled:true)
- ✅ Gateway starts without errors, channel registered

**Obsidian plugin (Asus local):**
- ✅ Build successful (`npm run build` → `main.js`)
- ✅ Installed in Obsidian vault `.obsidian/plugins/obsidian-openclaw-chat/`
- ✅ Enabled in Obsidian Community Plugins settings
- ✅ Configured: gateway URL (`ws://<eve-1-tailscale-ip>:8765`), auth token

**E2E smoke test:**
- ✅ Obsidian sidebar opens, status dot green (connected)
- ✅ Send "Hello from Obsidian" → agent (main) replies
- ✅ Agent-initiated push: trigger `obsidian.sendMessage` RPC → message appears in sidebar
- ✅ Gateway restart → Obsidian reconnects automatically (status dot: gray → green)

### Nice-to-have (deferred to Phase 3+)
- Streaming response display
- Multi-agent switching (main ↔ senilla)
- Active note context inclusion
- Error handling edge cases (invalid token, network partition)

---

## 2) Non-goals
- **Eve-bootstrap project modification:** nem nyúlunk az eve-bootstrap repo-hoz (hacsak nem találunk kritikus hibát).
- **Production deployment:** ez smoke test, nem production-ready release.
- **Performance benchmarking:** latency/throughput mérés későbbi fázis.
- **Multi-client testing:** egyszerre csak 1 Obsidian kliens a tesztben.

---

## 3) Architecture / Context

### Deployment topology

```
┌─────────────────────────────────────────────┐
│ Asus (wall-e user, local)                   │
│ ┌─────────────────────────────────────────┐ │
│ │ Obsidian Desktop                        │ │
│ │ + obsidian-openclaw-chat plugin         │ │
│ │   (WebSocket client)                    │ │
│ └─────────────────────────────────────────┘ │
│           │                                  │
│           │ ws://<eve-1-tailscale-ip>:8765  │
│           ↓                                  │
└───────────────────────────────────────────────┘
            │
            │ (Tailscale VPN)
            │
┌───────────────────────────────────────────────┐
│ Eve-1 (wall-e@eve-1, remote)                  │
│ ┌─────────────────────────────────────────┐   │
│ │ OpenClaw Gateway (systemd service)      │   │
│ │ + openclaw-channel-obsidian plugin      │   │
│ │   (WebSocket server on :8765)           │   │
│ └─────────────────────────────────────────┘   │
└───────────────────────────────────────────────┘
```

### Files touched (both repos)

**obsidian-oclaw-chat repo (develop branch):**
- `channel-plugin/dist/` — build output (generated)
- `obsidian-plugin/main.js` — build output (generated)
- `.github/compeng/runs/20260225-HHMM-e2e-eve1-deployment.md` — run log

**Eve-1 remote (~/.openclaw/):**
- `~/.openclaw/plugins/openclaw-channel-obsidian/` — channel plugin deployment
- `~/.openclaw/openclaw.json` — config modification (channels.obsidian block)

**Asus local (~/):**
- `~/.obsidian/vaults/<test-vault>/.obsidian/plugins/obsidian-openclaw-chat/` — plugin installation
- `~/.obsidian/vaults/<test-vault>/.obsidian/plugins/obsidian-openclaw-chat/data.json` — plugin settings

---

## 4) Prerequisites / Validation

### Pre-flight checks (GATE)

**Local (Asus):**
- ✅ Obsidian installed: `/usr/bin/obsidian` exists
- ✅ Repo checked out: `workspace/obsidian-oclaw-chat/` (develop branch)
- ✅ Node.js + npm available (for build)
- ✅ Test vault exists or can be created

**Remote (Eve-1):**
- ✅ SSH connection working: `ssh eve-1 "hostname"` returns `eve-1`
- ✅ OpenClaw installed: `ssh eve-1 "ls -d ~/.openclaw"` exists
- ✅ Gateway running: `ssh eve-1 "systemctl --user status openclaw-gateway"`
- ✅ Auth token available (generate if needed)

**Tailscale:**
- ✅ Tailscale active: `tailscale status` shows `eve-1` online
- ✅ IP address known: `tailscale ip -4 eve-1` or check `/etc/hosts` / `~/.ssh/config`

**✅ Current status (2026-02-25 14:46 - Hotfix):**
- ✅ SSH connection **works** (false timeout due to ConnectTimeout=3s too short)
- ✅ Eve-1 hostname: `eve-01` (SSH alias `eve-1` works via Tailscale)
- ✅ OpenClaw installed: `~/.openclaw/` exists
- **Ready for deployment** (no blockers)

---

## 5) Implementation Steps (High-Level)

### Phase 1: Build + Prepare (Local, 30 min)

**1.1. Build channel plugin**
```bash
cd workspace/obsidian-oclaw-chat/channel-plugin
npm install  # if not already done
npm run build
# Output: dist/index.js + dist/*.js
```

**1.2. Build Obsidian plugin**
```bash
cd workspace/obsidian-oclaw-chat/obsidian-plugin
npm install  # if not already done
npm run build
# Output: main.js
```

**1.3. Generate auth token**
```bash
# Generate secure random token (32 chars)
AUTH_TOKEN=$(openssl rand -hex 16)
echo "AUTH_TOKEN=${AUTH_TOKEN}" > /tmp/eve-obsidian-token.env
# CRITICAL: DO NOT commit this file!
```

---

### Phase 2: Deploy Channel Plugin to Eve-1 (Remote, 1h)

**2.1. Copy plugin to Eve-1**
```bash
ssh eve-1 "mkdir -p ~/.openclaw/plugins/openclaw-channel-obsidian"
rsync -avz --progress \
  workspace/obsidian-oclaw-chat/channel-plugin/ \
  eve-1:~/.openclaw/plugins/openclaw-channel-obsidian/
```

**2.2. Backup Eve-1 config**
```bash
ssh eve-1 "cp ~/.openclaw/openclaw.json ~/.openclaw/openclaw.json.backup-$(date +%Y%m%d-%H%M)"
```

**2.3. Edit config (add channels.obsidian block)**

**Option A: Manual edit via SSH**
```bash
ssh eve-1
vim ~/.openclaw/openclaw.json
# Add:
{
  "channels": {
    "obsidian": {
      "enabled": true,
      "wsPort": 8765,
      "authToken": "<AUTH_TOKEN>"
    }
  }
}
# :wq
```

**Option B: Scripted (safer, idempotent)**
```bash
# Generate config patch locally
cat > /tmp/obsidian-channel-config.json <<EOF
{
  "channels": {
    "obsidian": {
      "enabled": true,
      "wsPort": 8765,
      "authToken": "${AUTH_TOKEN}"
    }
  }
}
EOF

# Apply patch via jq (merge)
ssh eve-1 "jq -s '.[0] * .[1]' ~/.openclaw/openclaw.json /dev/stdin" < /tmp/obsidian-channel-config.json > /tmp/merged.json
scp /tmp/merged.json eve-1:~/.openclaw/openclaw.json
```

**2.4. Restart gateway**
```bash
ssh eve-1 "systemctl --user restart openclaw-gateway"
# Wait 5s
ssh eve-1 "systemctl --user status openclaw-gateway"
# Check logs for channel registration:
ssh eve-1 "journalctl --user -u openclaw-gateway -n 50 | grep obsidian"
# Expected: "[obsidian-channel] Channel registered"
```

---

### Phase 3: Install Obsidian Plugin (Local, 30 min)

**3.1. Create test vault (if needed)**
```bash
mkdir -p ~/.obsidian/vaults/openclaw-test-vault
# Open Obsidian → File → Open vault → openclaw-test-vault
```

**3.2. Copy plugin to vault**
```bash
VAULT_PATH=~/.obsidian/vaults/openclaw-test-vault  # adjust if needed
mkdir -p "${VAULT_PATH}/.obsidian/plugins/obsidian-openclaw-chat"
cp workspace/obsidian-oclaw-chat/obsidian-plugin/main.js \
   "${VAULT_PATH}/.obsidian/plugins/obsidian-openclaw-chat/"
cp workspace/obsidian-oclaw-chat/obsidian-plugin/manifest.json \
   "${VAULT_PATH}/.obsidian/plugins/obsidian-openclaw-chat/"
cp workspace/obsidian-oclaw-chat/obsidian-plugin/styles.css \
   "${VAULT_PATH}/.obsidian/plugins/obsidian-openclaw-chat/"
```

**3.3. Enable plugin in Obsidian**
- Obsidian → Settings → Community Plugins → Installed plugins
- Toggle "OpenClaw Chat" ON

**3.4. Configure plugin**
- Obsidian → Settings → OpenClaw Chat
- **Gateway URL:** `ws://<EVE-1-TAILSCALE-IP>:8765`
  - Get IP: `tailscale ip -4 eve-1`
  - Example: `ws://100.64.0.2:8765`
- **Auth token:** paste `${AUTH_TOKEN}` from `/tmp/eve-obsidian-token.env`
- **Default agent:** `main`
- Save settings

**3.5. Restart plugin**
- Obsidian → Command Palette (Ctrl+P) → "Reload app without saving"
- Or: close/reopen Obsidian

---

### Phase 4: E2E Smoke Test (30 min)

**Test 1: User → Agent (Inbound)**
1. Obsidian → click ribbon icon (message-square) → sidebar opens
2. Status dot: should be **green** (connected)
3. Send message: "Hello from Obsidian"
4. **Expected:** agent (main) replies within 5-10s
5. **Verify:** reply appears in sidebar message list

**Test 2: Agent → User (Outbound, Proactive Push)**
1. SSH to Eve-1:
   ```bash
   ssh eve-1
   # Enter OpenClaw REPL or run RPC call:
   node -e "
   const ws = require('ws');
   const client = new ws('ws://localhost:8765');
   client.on('open', () => {
     // Auth first (if needed)
     client.send(JSON.stringify({
       type: 'auth',
       payload: { token: '<AUTH_TOKEN>', agentId: 'main' }
     }));
     setTimeout(() => {
       // Send proactive message (broadcast to all)
       // This should appear in Obsidian sidebar
       client.send(JSON.stringify({
         type: 'message',
         payload: { content: 'Proactive push from gateway!' }
       }));
     }, 1000);
   });
   "
   ```
2. **Expected:** "Proactive push from gateway!" appears in Obsidian sidebar
3. **Verify:** message timestamp, no errors in sidebar

**Test 3: Reconnect After Gateway Restart**
1. Obsidian sidebar open, status dot green
2. SSH to Eve-1:
   ```bash
   ssh eve-1 "systemctl --user restart openclaw-gateway"
   ```
3. **Expected:**
   - Status dot turns **gray** (disconnected)
   - After 3-5 seconds: status dot turns **green** (reconnected)
4. Send message: "Test after reconnect"
5. **Verify:** agent reply arrives

---

## 6) Test Plan

### Unit tests (run before deployment)
```bash
cd workspace/obsidian-oclaw-chat/channel-plugin
npm test
# All tests pass → green
```

### Integration test (E2E smoke)
- See Phase 4 above (3 tests)

### Security checklist
- ✅ Auth token NOT logged in gateway logs (check `journalctl`)
- ✅ Auth token NOT visible in Obsidian UI (password field)
- ✅ Config backup exists before changes
- ✅ WS server binds to localhost (or Tailscale IP only, not 0.0.0.0)

---

## 7) Rollback Plan

**If E2E test fails or gateway crashes:**

**1. Restore config backup**
```bash
ssh eve-1 "cp ~/.openclaw/openclaw.json.backup-* ~/.openclaw/openclaw.json"
ssh eve-1 "systemctl --user restart openclaw-gateway"
```

**2. Remove channel plugin**
```bash
ssh eve-1 "rm -rf ~/.openclaw/plugins/openclaw-channel-obsidian"
ssh eve-1 "systemctl --user restart openclaw-gateway"
```

**3. Uninstall Obsidian plugin (local)**
```bash
rm -rf ~/.obsidian/vaults/openclaw-test-vault/.obsidian/plugins/obsidian-openclaw-chat
# Or: Obsidian Settings → Community Plugins → Uninstall
```

**Recovery time:** <5 minutes

---

## 8) Acceptance Criteria

✅ **AC1: Channel plugin deployed and registered**
- `ssh eve-1 "journalctl --user -u openclaw-gateway -n 100"` contains:
  - `[obsidian-channel] Plugin registered successfully`
  - `[obsidian-channel] WebSocket server listening on port 8765`

✅ **AC2: Obsidian plugin connects successfully**
- Obsidian sidebar status dot: **green** (connected)
- Obsidian console (Dev Tools): no WebSocket errors

✅ **AC3: Inbound message flow works**
- Send "Hello" from Obsidian → agent reply appears in sidebar

✅ **AC4: Outbound (proactive) message flow works**
- Trigger `obsidian.sendMessage` RPC → message appears in sidebar

✅ **AC5: Reconnect after gateway restart**
- Gateway restart → Obsidian auto-reconnects within 5s

✅ **AC6: No secrets leaked**
- Auth token NOT in gateway logs (`journalctl | grep -i token` = empty)
- Auth token NOT in Obsidian UI (password field used)

---

## 9) Known Issues / Gotchas

### From .github/compeng/knowledge/gotchas/

**Referenced:**
- `openclaw-plugin-cannot-import-internals.md` — Channel plugin uses runtime APIs, not internal imports ✅ (already implemented)

**New gotchas (to be documented after E2E):**
- TBD (will capture in run log)

---

## 10) Links / References

### Upstream plans
- Supervising plan: http://asus-x555ld.tailf13b03.ts.net:8088/files/workspace/plan-supervising-obsidian-oclaw-chat
- Hybrid plan: http://asus-x555ld.tailf13b03.ts.net:8088/files/workspace/plan-hybrid-obsidian-integration
- Status report: http://asus-x555ld.tailf13b03.ts.net:8088/files/workspace/obsidian-oclaw-chat-status-report

### Eve-bootstrap context
- Eve-bootstrap plan v1: `workspace/compeng/plans/20260218-1635-eve-bootstrap-plan-v1.md`
- SSH config: `~/.ssh/config` (Host eve-1)

### Channel plugin docs
- OpenClaw channel guide: https://docs.openclaw.ai/cli/channels

---

## 11) Estimated Timeline

| Phase | Task | Time |
|-------|------|------|
| 1 | Build channel + Obsidian plugins | 30 min |
| 2 | Deploy channel to Eve-1 + config | 1h |
| 3 | Install Obsidian plugin locally | 30 min |
| 4 | E2E smoke test (3 tests) | 30 min |
| 5 | Document results + gotchas | 1h |
| **Total** | | **3.5–4h** |

**Buffer for issues:** +1–2h (connectivity, config errors, debugging)

**Total estimated:** **4–6h**

---

## 12) Success Metrics

**Definition of Done:**
- ✅ All 6 acceptance criteria pass
- ✅ Run log created: `.github/compeng/runs/20260225-HHMM-e2e-eve1-deployment.md`
- ✅ No critical bugs found → ready for Phase 3 (streaming, @mentions)
- ✅ Gotchas documented (if any) → `.github/compeng/knowledge/gotchas/`

**Ready for checkpoint merge to master:** Yes (after successful E2E)

---

**Plan status:** Draft (needs explicit "start work" command from Rix)
**Blocker:** ~~Eve-1 SSH connection timeout~~ **RESOLVED** (hotfix: ConnectTimeout too short)
**Next step:** Awaiting "start work" command → begin deployment (no blockers)
