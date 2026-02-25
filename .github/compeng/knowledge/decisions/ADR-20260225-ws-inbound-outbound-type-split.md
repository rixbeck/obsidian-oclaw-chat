# ADR: Split WebSocket message types into Inbound and Outbound discriminated unions

**Date:** 2026-02-25
**Status:** Accepted
**Context:** [Plan](../../plans/20260225-1350-channel-fix-and-obsidian-phase2.md) → [Run](../../runs/20260225-1350-channel-fix-and-obsidian-phase2.md) → [Review](../../reviews/20260225-1430-channel-fix-and-obsidian-phase2.md)

## Context

The initial implementation used a single shared `WSPayload` type for both messages sent *to* the server and messages received *from* the server. This caused two distinct problems:

1. **Wire format mismatch**: `OutboundMessage` had `content`/`timestamp` at top-level; `WSPayload` only had `payload?: Record<string,unknown>`. The agent→Obsidian direction was silently broken at runtime — no TypeScript error was raised because the loose `Record<string,unknown>` type accepted anything.
2. **Forced `as any` casts**: Because the single type couldn't express the exact shape for each variant, every consumer had to cast `(msg.payload as any)?.content`, masking errors.

## Decision

Use **two distinct types** for the two directions:

```typescript
// Outbound (Obsidian → server): permissive — client controls the shape
export interface WSPayload {
  type: 'auth' | 'message' | 'ping' | 'pong' | 'error';
  payload?: Record<string, unknown>;
}

// Inbound (server → Obsidian): tight discriminated union — matches server contract exactly
export type InboundWSPayload =
  | { type: 'auth';    payload: { success: boolean; sessionId?: string } }
  | { type: 'message'; payload: { content: string; timestamp: number } }
  | { type: 'error';   payload: { message: string } }
  | { type: 'pong' };
```

The `ObsidianWSClient.onMessage` callback is typed `(msg: InboundWSPayload) => void`.

## Consequences

### Positive
- Consumers access `msg.payload.content` without any casts — TS catches field typos at compile time
- Wire format bugs (like moving `content` inside `payload`) immediately surface as type errors
- Protocol evolution is explicit: adding a new server→client message type requires updating the union

### Negative
- Two types to maintain and keep in sync with the server-side types
- Outbound remains permissive (`Record<string,unknown>`) — outbound wire bugs still require e2e tests

### Neutral
- The split mirrors the asymmetric nature of the protocol: the client author controls what they *send*, but must precisely match what the server *sends*

## Alternatives Considered

### Alternative 1: Single bidirectional discriminated union
- Pros: One type, symmetric
- Cons: `auth` appears twice (client sends `{token,sessionId,agentId}`, server sends `{success,sessionId}`), forces an awkward overloaded union or two separate `auth` subtypes with identical `type` discriminant — unusable in a switch

### Alternative 2: Generated types from a shared schema (OpenAPI / JSON Schema)
- Pros: Single source of truth across server + client
- Cons: Significant tooling overhead for an MVP; premature
- Why rejected: YAGNI at this stage

## Follow-up Actions

- [ ] Add JSON Schema for the wire protocol to `openclaw.plugin.json` once the protocol stabilises
- [ ] When server gains new message types, update `InboundWSPayload` first (types as documentation)

## References

- Review Issue 1 (Critical — OutboundMessage envelope mismatch): [Review](../../reviews/20260225-1430-channel-fix-and-obsidian-phase2.md#issue-1)
- Review Issue 8 (Error payload type mismatch): [Review](../../reviews/20260225-1430-channel-fix-and-obsidian-phase2.md#issue-8)
- `obsidian-plugin/src/types.ts` — implementation
- `obsidian-plugin/src/websocket.ts` — consumer
