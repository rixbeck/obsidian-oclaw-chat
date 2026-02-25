# Gotcha: WebSocket Server Security Pitfalls

**Domain:** channel-plugin (WebSocket server)
**First observed:** 2026-02-25
**Severity:** Critical — exposed to LAN/session hijacking in production

---

## Issue 1: Default binding is 0.0.0.0 — server is LAN-exposed

### What Happened

`new WebSocketServer({ port: wsPort })` was the initial implementation. This binds to all interfaces including LAN, VPN, and hotspot. Any machine on the same network could reach the auth endpoint and brute-force the token.

### Root Cause

The `ws` library's `WebSocketServer` defaults to `0.0.0.0` when `host` is not specified — same as Node's `net.Server`.

### Prevention

**Always pass `host: '127.0.0.1'`:**

```typescript
// ✅ Correct — loopback only
const wss = new WebSocketServer({ host: '127.0.0.1', port: wsPort });

// ❌ Wrong — binds all interfaces
const wss = new WebSocketServer({ port: wsPort });
```

---

## Issue 2: Session fixation via client-supplied sessionId

### What Happened

The auth handler used `message.payload?.sessionId || clientId` as the session key. A malicious client could supply the sessionId of an existing authenticated session, overwriting it in `activeSessions` and hijacking that session's inbound/outbound routing.

### Root Cause

Trust boundary violation: the session identity must be assigned by the server, not negotiated with the client.

### Prevention

**Always use the server-generated connection ID — ignore any client-supplied sessionId:**

```typescript
// ✅ Correct — server owns identity assignment
sessionInfo = {
  sessionId: clientId,   // always server-generated
  agentId: message.payload?.agentId || 'main',  // agentId is OK to accept
  ...
};

// ✅ Return the assigned sessionId so the client can use it for RPC targeting
ws.send(JSON.stringify({ type: 'auth', payload: { success: true, sessionId: clientId } }));

// ❌ Wrong — client can choose any session ID
sessionId: message.payload?.sessionId || clientId
```

The client receiving the assigned `sessionId` in the auth response lets it correctly target itself via RPC (`obsidian.sendMessage(sessionId, ...)`).

---

## Issue 3: Missing message size limit — heap exhaustion DoS

### What Happened

No check on incoming message size. A client (or compromised upstream) could send a multi-GB WS frame, exhausting Node.js heap.

### Prevention

```typescript
ws.on('message', async (data: Buffer) => {
  if (data.length > 1_048_576) {          // 1 MB hard limit
    ws.close(1009, 'Message too large');
    return;
  }
  // ...
});
```

---

## Issue 4: Math.random() for session IDs — predictable

### What Happened

`const clientId = \`client-${Date.now()}-${Math.random().toString(36).substr(2, 9)}\`` was used. `Math.random()` is not a CSPRNG — output is deterministic given the engine state.

### Prevention

```typescript
import { randomUUID } from 'node:crypto';
const clientId = `client-${randomUUID()}`;
```

---

## Detection

- Symptom of 0.0.0.0 binding: `netstat -tlnp | grep <port>` shows `0.0.0.0:<port>` instead of `127.0.0.1:<port>`
- Symptom of session fixation: two clients can have the same session ID in activeSessions

---

## References

- Review Issues 2, 3, 14, 15: [Review](../../reviews/20260225-1430-channel-fix-and-obsidian-phase2.md)
- `channel-plugin/src/service.ts`
