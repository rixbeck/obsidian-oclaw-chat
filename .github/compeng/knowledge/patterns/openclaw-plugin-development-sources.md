# Pattern: OpenClaw Channel Plugin Development

**Domain:** openclaw-plugin  
**Created:** 2026-02-25

---

## When to Use

When building a new OpenClaw channel plugin that needs to:
- Register a named channel with the gateway
- Expose RPC methods callable by agents
- Communicate bidirectionally with external clients (WS, HTTP, etc.)

---

## Plugin Structure

```
my-channel-plugin/
  openclaw.plugin.json   ← plugin manifest (id, kind: "channel", configSchema)
  package.json           ← openclaw.extensions: ["./dist/index.js"]
  tsconfig.json          ← ESNext, ESM
  src/
    index.ts             ← export function register(ctx)  ← ENTRY POINT
    channel.ts           ← registerChannel meta + outbound handler
    service.ts           ← transport layer (WS server, etc.)
    rpc.ts               ← RPC method implementations + registerRPCMethods()
    auth.ts              ← token validation
    session.ts           ← inbound message routing
    types.ts             ← shared interfaces
```

---

## `register(ctx)` Contract

```typescript
export function register(ctx: any) {
  const { log, config, runtime } = ctx;

  // 1. Register channel metadata + outbound handler
  registerObsidianChannel(ctx);

  // 2. Start transport (WS server, etc.)
  startTransport(ctx);

  // 3. Register RPC methods with runtime
  registerRPCMethods(ctx);   // ← MUST be called or RPC won't work
}
```

**Critical:** All three registration calls must happen in `register()`. A common mistake is forgetting `registerRPCMethods()`, which silently means no agent can call the plugin's RPC methods.

---

## Runtime API Guard Pattern

```typescript
if (runtime.registerChannel) {
  runtime.registerChannel(meta, handlers);
} else {
  log.warn('[my-channel] registerChannel not available – graceful degradation');
}
```

Always guard. The runtime API surface changes across OpenClaw versions.

---

## Token Handling Rules

1. **Never log auth tokens** — use `log.debug(..., { sessionId })` not `{ token }`.
2. Use **timing-safe comparison** for token validation (prevent timing attacks):
   ```typescript
   function timingSafeEqual(a: string, b: string): boolean {
     if (a.length !== b.length) return false;
     let r = 0;
     for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
     return r === 0;
   }
   ```
3. Token goes in `~/.openclaw/openclaw.json` → `channels.<id>.authToken`, not in code.

---

## RPC Naming Convention

```
<channelId>.<methodName>

obsidian.sendMessage      ← send to specific session
obsidian.broadcastMessage ← send to all authenticated sessions
obsidian.listAccounts     ← list active sessions
```

---

## Broadcast vs. Targeted Send

If an agent knows the `sessionId`, use `sendMessage(sessionId, content)`.  
If there is no specific target (e.g. proactive agent push), use `broadcastMessage(content)`.

```typescript
// Outbound handler in channel.ts:
async sendMessage(message: string, options: any) {
  const sessionId = options?.sessionId;
  if (sessionId) {
    return await sendMessage(sessionId, message, ctx);
  }
  await broadcastMessage(message, ctx);
  return { success: true };
}
```

---

## References

- `channel-plugin/src/index.ts` — reference implementation
- `channel-plugin/src/rpc.ts` — RPC pattern
- Gotcha: `gotchas/openclaw-plugin-cannot-import-internals.md`
