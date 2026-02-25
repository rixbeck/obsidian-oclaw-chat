# Checklist: WebSocket Wire Protocol Review

**Updated:** 2026-02-25

Covers the server↔client contract for the Obsidian channel plugin protocol. Run this before any release that changes `types.ts` on either side.

---

## Message Envelope Shape

- [ ] **All user-visible content is inside `payload`, not at the top-level envelope**
  - **Why:** The receiver types the frame as `{ type, payload? }`. Any field placed at the top level is invisible to typed consumers.
  - **Example of the bug:**
    ```typescript
    // ❌ Wrong — content invisible to consumer
    { type: 'message', content: 'Hello', timestamp: 123 }
    
    // ✅ Correct
    { type: 'message', payload: { content: 'Hello', timestamp: 123 } }
    ```
  - **Precedent:** [Review 2026-02-25 Issue 1 — CRITICAL — agent→user direction was completely broken](../../reviews/20260225-1430-channel-fix-and-obsidian-phase2.md)

- [ ] **Error payload is always `{ message: string }`, never a bare string**
  - **Why:** A typed consumer cannot do `msg.payload.message` on a bare string payload — silent undefined.
  - **Fix:** `{ type: 'error', payload: { message: 'Reason here' } }`
  - **Precedent:** [Review 2026-02-25 Issue 8](../../reviews/20260225-1430-channel-fix-and-obsidian-phase2.md)

- [ ] **Auth success response includes the server-assigned `sessionId`**
  - **Why:** The server ignores client-supplied sessionIds (session fixation prevention). The client needs to know its actual session ID for RPC targeting.
  - **Fix:** `{ type: 'auth', payload: { success: true, sessionId: serverClientId } }`

---

## Type Contract Alignment

- [ ] **`InboundWSPayload` discriminated union exactly matches every message the server can send**
  - Checklist: `auth` (success + sessionId), `message` (content + timestamp), `error` (message), `pong`
  - **Why:** Loose typing (`Record<string,unknown>`) forces `as any` casts that mask field-name bugs.
  - **See:** [ADR: WS inbound/outbound type split](../decisions/ADR-20260225-ws-inbound-outbound-type-split.md)

- [ ] **No top-level `sessionId?` / `agentId?` fields on `WSMessage` / `WSPayload`**
  - **Why:** Top-level fields that are never populated are misleading — future code silently reads `undefined`.
  - **Fix:** Keep these only inside `payload`.

- [ ] **No `as any` casts in WS message handlers**
  - **Why:** Each `as any` is a type-safety hole. If you need a cast, the type is wrong — fix the type.

---

## E2E Wire Format Testing

- [ ] **At least one integration test serialises a message to JSON and deserialises it on the other side**
  - **Why:** Unit tests mock `.send()` — they verify *that* send was called but not *what format* was sent. The Issue 1 bug (content at top level) slipped through 27/27 passing unit tests because no test parsed the JSON and navigated to `payload.content`.
  - **Fix pattern:**
    ```typescript
    const sent = JSON.parse(mockWs.send.mock.calls[0][0]);
    expect(sent.payload.content).toBe('expected message');   // navigate the actual JSON
    expect(sent.type).toBe('message');
    ```
  - **Precedent:** Issue 1 root cause — tests verified shape via TypeScript but not via runtime JSON navigation.

---

## Obsidian DOM Safety

- [ ] **`this.contentEl` is used instead of `this.containerEl.children[1]`**
  - **Why:** Positional DOM access breaks silently when Obsidian changes its internal view structure.
  - **Fix:** `const root = this.contentEl;` — this is the stable `ItemView` property.
  - **Precedent:** [Review 2026-02-25 Issue 7](../../reviews/20260225-1430-channel-fix-and-obsidian-phase2.md)
