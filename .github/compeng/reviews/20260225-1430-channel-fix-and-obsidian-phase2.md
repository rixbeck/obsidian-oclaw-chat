# Review: Channel Fix + Obsidian Phase 2

**Reviewed:** 2026-02-25 14:30  
**Run:** [.github/compeng/runs/20260225-1350-channel-fix-and-obsidian-phase2.md](.github/compeng/runs/20260225-1350-channel-fix-and-obsidian-phase2.md)  
**Plan:** [.github/compeng/plans/20260225-1350-channel-fix-and-obsidian-phase2.md](.github/compeng/plans/20260225-1350-channel-fix-and-obsidian-phase2.md)  
**Status:** ❌ Rejected — Must-fix issues present, return to work phase

---

## Summary

6 párhuzamos reviewer értékelte a channel plugin bugfixeit (B1–B3) és a teljes Obsidian plugin Phase 2 scaffoldot. Az implementáció struktúrálisan helyes és a tesztek zöldek (27/27), de **8 Must-fix issue** blokkol éles használatot. Legkritikusabb: az agent→Obsidian üzenetek egyáltalán nem jutnak el a klienshez (wire format mismatch), a szerver nyitott minden interfészen, és van egy session fixation támadási vektor.

---

## Must-fix Issues

### Issue 1: OutboundMessage envelope mismatch — agent→Obsidian üzenetek soha nem érnek célba

- **Reviewer:** API Contracts
- **Severity:** Critical
- **Description:** A szerver `OutboundMessage`-t küld `{ type: 'message', content: "…", timestamp: 1234 }` — a `content` és `timestamp` mezők a top-level objektumban vannak. Az Obsidian kliens `WSPayload`-ként deszializálja, aminek nincs `content` mezője — csak `{ type, payload?: Record<string,unknown> }`. Futás közben `msg.payload` undefined, a tartalom soha nem érhető el. Az agent → user irány **teljesen törött**.
- **Location:** [channel-plugin/src/rpc.ts](channel-plugin/src/rpc.ts#L35-L39) (OutboundMessage build), [channel-plugin/src/types.ts](channel-plugin/src/types.ts#L44-L48), [obsidian-plugin/src/types.ts](obsidian-plugin/src/types.ts#L25-L31)
- **Recommendation:** Csomagold a tartalmat `payload`-be:
  ```typescript
  session.wsClient.send(JSON.stringify({
    type: 'message',
    payload: { content, timestamp: Date.now() }
  }));
  ```
  Egységesítsd mindkét oldal `WSMessage`/`WSPayload` típusát egy diskriminált union-ra.

---

### Issue 2: WS szerver 0.0.0.0-ra bind — hálózaton elérhető

- **Reviewer:** Security
- **Severity:** Critical
- **Description:** `new WebSocketServer({ port: wsPort })` alapértelmezetten 0.0.0.0-n hallgat. Bárki azonos LAN-on, VPN-en vagy hotspoten brute-force-olhatja az auth tokent.
- **Location:** [channel-plugin/src/service.ts](channel-plugin/src/service.ts#L16)
- **Recommendation:**
  ```typescript
  const wss = new WebSocketServer({ host: '127.0.0.1', port: wsPort });
  ```

---

### Issue 3: Session fixation — kliens felülírhat létező sessiont

- **Reviewer:** Security
- **Severity:** Critical
- **Description:** Az auth payload-ban a kliens által megadott `sessionId` közvetlenül kerül az `activeSessions` Map-be, meglévő session felülírásával. Egy rosszindulatú kliens eltérítheti más session routing-ját.
- **Location:** [channel-plugin/src/service.ts](channel-plugin/src/service.ts#L44)
- **Recommendation:** Mindig a szerver által generált `clientId`-t használj:
  ```typescript
  sessionId: clientId,  // ignore message.payload?.sessionId
  ```

---

### Issue 4: MarkdownRenderer.render nem megbízható forráson — XSS / RCE Electron-ban

- **Reviewer:** Security
- **Severity:** Critical
- **Description:** `MarkdownRenderer.render(this.app, msg.content, el, '', this)` meghívódik minden agentüzenetre. Ha a backend kompromittált vagy egy csomag spoofol üzenetet, az Electron renderer JS-t futtat, ami Node.js API-khoz és a fájlrendszerhez hozzáfér.
- **Location:** [obsidian-plugin/src/view.ts](obsidian-plugin/src/view.ts#L127)
- **Recommendation:** Safe default: rendereld plain text-ként, és csak expliciteden jelölt tartalomnál hívd meg a markdown renderert:
  ```typescript
  el.createSpan({ text: msg.content });  // safe default
  ```

---

### Issue 5: O(N) teljes DOM re-render minden új üzenetnél

- **Reviewer:** Performance
- **Severity:** Critical
- **Description:** `_renderMessages()` minden egyes `chatManager.onUpdate` callbacknél (`containerEl.empty()` + teljes újraépítés) az összes üzenetre meghívja a `MarkdownRenderer.render()`-t. 50 üzenetnél az 51. üzenet 51 markdown parsolást triggerel — látható UI freeze.
- **Location:** [obsidian-plugin/src/view.ts](obsidian-plugin/src/view.ts#L116)
- **Recommendation:** Append-only pattern: csak az új üzenetet fűzd a DOM-hoz. Teljes újrarajzolás csak panel megnyitásnál szükséges. `ChatManager`-hez adj `onMessageAdded(msg)` callback-et.

---

### Issue 6: Test echo kód production routing path-ban

- **Reviewer:** Maintainability + Overengineering
- **Severity:** High
- **Description:** `session.ts` `else` ágában: ha `runtime.dispatchToAgent` nem elérhető, a kód csendesen echo-zza vissza a felhasználó üzenetét `// Temporary: echo back for testing` kommenttel. Productionban félrevezető phantom válaszokat küld ahelyett, hogy hibát jelezne.
- **Location:** [channel-plugin/src/session.ts](channel-plugin/src/session.ts#L39-L46)
- **Recommendation:**
  ```typescript
  } else {
    log.error('[obsidian-channel] runtime.dispatchToAgent not available');
    sessionInfo.wsClient.send(JSON.stringify({
      type: 'error',
      payload: { message: 'Agent dispatch unavailable — check gateway config' }
    }));
  }
  ```

---

### Issue 7: `this.containerEl.children[1]` törékeny DOM hozzáférés

- **Reviewer:** Maintainability
- **Severity:** High
- **Description:** `OpenClawChatView._buildUI()` `this.containerEl.children[1] as HTMLElement`-t használ. Obsidian belső view struktúra változás esetén csendesen rossz elemet ad vissza, néma UI-t eredményezve.
- **Location:** [obsidian-plugin/src/view.ts](obsidian-plugin/src/view.ts#L63)
- **Recommendation:**
  ```typescript
  const root = this.contentEl;  // Obsidian ItemView stable property
  ```

---

### Issue 8: Error payload típus mismatch — string vs Record

- **Reviewer:** API Contracts
- **Severity:** High
- **Description:** A szerver error frame-eket `{ type: 'error', payload: 'Invalid token' }` alakban küld (bare string payload). A kliens `payload?: Record<string,unknown>`-ként típusozza. `msg.payload.message` `undefined`-ot ad vissza, a hibakezelés csendesen elveszik.
- **Location:** [channel-plugin/src/service.ts](channel-plugin/src/service.ts#L40), [obsidian-plugin/src/types.ts](obsidian-plugin/src/types.ts#L29)
- **Recommendation:** Normalizálj: `{ type: 'error', payload: { message: string } }` — mindkét oldalon.

---

## Should-fix Issues

### Issue 9: `channel.ts` és `index.ts` zero test coverage

- **Reviewer:** Tests
- **Severity:** Medium
- **Description:** `registerObsidianChannel()` és a plugin entry point `register()` teljesen teszteletlen. A `sendMessage`/`broadcastMessage` routing (`channel.ts`), a `config.enabled=false` early-return, és a throw path sem tesztelve.
- **Recommendation:** `channel.test.ts` + `index.test.ts` hozzáadása. Mock ctx-szel tesztelni az összes elágazást.

---

### Issue 10: GlobalMutable `activeSessions` Map tesztek között nem resetelődik

- **Reviewer:** Tests + Maintainability
- **Severity:** Medium
- **Description:** `activeSessions` modul-szintű singleton. `afterEach`-ben a WebSocketServer bezárása nem garantálja, hogy a Map tiszta lesz a következő tesztnél — flaky tesztek lehetségesek.
- **Location:** [channel-plugin/src/service.ts](channel-plugin/src/service.ts#L9-L10)
- **Recommendation:** Exportálj `clearActiveSessions()` test-only reset függvényt, és hívd `afterEach`-ben. Hosszútávon encapsulate a `SessionStore` osztályba.

---

### Issue 11: `rpc.ts` sendMessage ws.send throw path teszteletlen

- **Reviewer:** Tests
- **Severity:** Medium
- **Description:** A `try/catch` blokk `{ success: false, error: 'Send failed' }` visszatérési értékét egyetlen teszt sem ellenőrzi.
- **Location:** [channel-plugin/src/rpc.ts](channel-plugin/src/rpc.ts#L40)
- **Recommendation:** Adj hozzá tesztesetet ahol `ws.send` dob, és ellenőrizd a visszatérési értéket.

---

### Issue 12: `getStatus()` hardcoded hazugság

- **Reviewer:** Maintainability + Overengineering
- **Severity:** Medium
- **Description:** `getStatus()` mindig `{ connected: true, clients: 0 }` értékkel tér vissza, kommentben "Will be dynamic". Bármely health-check consumer tévesen healthy-nek látja a channelt.
- **Location:** [channel-plugin/src/channel.ts](channel-plugin/src/channel.ts#L37-L41)
- **Recommendation:** Kösd a session store-hoz: `{ connected: getAllActiveSessions().length > 0, clients: getAllActiveSessions().length }` — vagy töröld amíg nem kész.

---

### Issue 13: Settings dropdown hardcoded agent lista vs models.ts AGENT_OPTIONS (DRY)

- **Reviewer:** Maintainability
- **Severity:** Medium
- **Description:** `settings.ts` kézzel adja hozzá a 'main'/'senilla' opciókat, holott `AGENT_OPTIONS` már létezik `models.ts`-ben. `view.ts` már azt használja.
- **Location:** [obsidian-plugin/src/settings.ts](obsidian-plugin/src/settings.ts#L52-L54)
- **Recommendation:**
  ```typescript
  import { AGENT_OPTIONS } from './models';
  for (const opt of AGENT_OPTIONS) drop.addOption(opt.id, opt.label);
  ```

---

### Issue 14: `Math.random()` session/message ID generálás — nem CSPRNG

- **Reviewer:** Security
- **Severity:** Medium
- **Description:** `Math.random()` kimenetele prediktábilis. Session ID-k belőle guessable.
- **Location:** [channel-plugin/src/service.ts](channel-plugin/src/service.ts#L24), [obsidian-plugin/src/websocket.ts](obsidian-plugin/src/websocket.ts#L33)
- **Recommendation:** `import { randomUUID } from 'crypto'` → `const clientId = \`client-${randomUUID()}\``

---

### Issue 15: Üzenet méret limit hiányzik — DoS vektor

- **Reviewer:** Security
- **Severity:** Medium
- **Description:** Nincs `data.length` ellenőrzés a WS message handler előtt. Egy kliens gigabyte-os üzenetet küldhet, heap exhaust-ot okozva.
- **Location:** [channel-plugin/src/service.ts](channel-plugin/src/service.ts#L29)
- **Recommendation:** `if (data.length > 1_048_576) { ws.close(1009, 'Message too large'); return; }`

---

### Issue 16: `send()` csendesen eldob üzeneteket reconnect alatt

- **Reviewer:** Performance
- **Severity:** Medium
- **Description:** Ha a WS éppen `connecting` vagy `authenticating` állapotban van, a felhasználó üzenete `console.warn` után elveszik. Flaky lokális hálóval a felhasználó észrevétlenül elveszítheti az üzeneteit.
- **Location:** [obsidian-plugin/src/websocket.ts](obsidian-plugin/src/websocket.ts#L55)
- **Recommendation:** Max 20 elemű outbound queue, ami automatikusan ürül ha `state === 'connected'` lesz.

---

### Issue 17: Dead mezők a `WSMessage` típuson

- **Reviewer:** API Contracts + Overengineering
- **Severity:** Medium
- **Description:** `WSMessage` top-level `sessionId?` és `agentId?` mezői sosem töltődnek — mindkettőt `message.payload?.X`-ből olvasnak. Félrevezető típus, jövőbeli kód csendesen `undefined`-ot kapna.
- **Location:** [channel-plugin/src/types.ts](channel-plugin/src/types.ts#L32-L33)
- **Recommendation:** Töröld a top-level mezőket, tartsd csak a payload-ban.

---

### Issue 18: `register(ctx: any)` — `PluginContext` típus nem alkalmazott

- **Reviewer:** Maintainability
- **Severity:** Medium
- **Description:** Az entry point `any`-t használ, elnyeli a downstream típushibákat.
- **Location:** [channel-plugin/src/index.ts](channel-plugin/src/index.ts#L12)
- **Recommendation:** `export function register(ctx: PluginContext)`

---

## Nice-to-have Suggestions

- **Exponential backoff** reconnect-nél (3s→6s→30s cap) — websocket.ts
- **`crypto.randomUUID()`** ID generáláshoz a `Date.now()+random` kombináció helyett — chat.ts, service.ts
- **URL validáció** a settings gateway URL-re (ws:// és localhost-ra korlátozva) — websocket.ts connect()
- **`broadcastMessage` RPC** eltávolítása amíg nincs multi-instance use case (YAGNI) — rpc.ts
- **`accounts` config field** eltávolítása amíg account-szintű szűrés nincs implementálva — types.ts
- **`models.ts` egyszerűsítése** — `AGENT_OPTIONS` plain string const vagy beolvasztás types.ts-be, `getAgentById` törlése
- **`createUserMessage` / `createAssistantMessage` / `createSystemMessage`** egységesítése egyetlen `createMessage(role, content)` factory-vá — chat.ts
- **Üzenet tartalom log-olás** (session.ts messagePreview) eltávolítása adatvédelmi szempontból
- **`RPC method contract`** hozzáadása `openclaw.plugin.json`-hoz — felfedezhetőség
- **`wsPort` JSON Schema** min/max validáció (1024–65535) — openclaw.plugin.json
- **Unbounded message array** limit (pl. 500 üzenet shift() a végéről) — chat.ts

---

## Reviewer Reports

### Security Review
- **Must-fix:** 0.0.0.0 binding (→127.0.0.1), session fixation, XSS/MarkdownRenderer, token length oracle
- **Should-fix:** No message size limit, Math.random for IDs, no URL validation, note content unencrypted, token plaintext in vault, unvalidated RPC input
- **Nice-to-have:** console.log státusz szivárog, messagePreview logban, no rate limiting

### Performance Review
- **Must-fix:** Full DOM + markdown re-render O(N) per message
- **Should-fix:** Unbounded message array, full note read per send, silent message drop during reconnect, unnecessary array alloc in broadcast
- **Nice-to-have:** No exponential backoff, weak ID generation, mutable array reference exposed

### API Contracts Review
- **Must-fix:** OutboundMessage envelope mismatch (content at top vs payload), error payload string vs Record, auth response `as any` cast
- **Should-fix:** Dead WSMessage top-level fields, InboundMessage shape mismatch, RPC methods absent from manifest, no protocol version, WSPayload too permissive
- **Nice-to-have:** wsPort schema missing range, WSMessage/WSPayload dual naming, authToken schema missing docs

### Maintainability Review
- **Must-fix:** `register(ctx: any)` type gap, module-level mutable session store, test echo in production path, `containerEl.children[1]` fragile DOM
- **Should-fix:** ChatManager duplicate factory methods, OutboundMessage build duplicated, settings agent list DRY, `_buildUI()` god method, `as any` payload cast, `getStatus()` hardcoded, deprecated `substr`
- **Nice-to-have:** Inconsistent log abstraction, non-unique DOM element ID, dual field names in payload

### Tests Review
- **Must-fix:** channel.ts zero coverage, index.ts zero coverage, activeSessions not cleared between tests, sendMessage throw path untested
- **Should-fix:** Unknown message type untested, malformed JSON untested, dispatchToAgent not asserted in service test, dispatch throw not tested, RPC handler lambdas not invoked
- **Nice-to-have:** Empty provided token, auth fallback for missing sessionId, empty message string, mixed send/error counters, obsidian-plugin no tests

### Overengineering Review
- **Must-fix:** timingSafeEqual premature+broken, echo test stub in production, dead WSMessage fields
- **Should-fix:** models.ts over-abstraction, 3 factory methods diff only by role, broadcastMessage RPC YAGNI, `push` capability advertised early, accounts config field unused, getStatus() hardcoded, WSPayload.payload too loose
- **Nice-to-have:** 4-state enum (authenticating YAGNI), listAccounts always return authenticated:true, over-engineered ID for in-memory use

---

## Decision

❌ **Rejected** — 8 Must-fix issue (köztük runtime-broken agent→user kommunikáció, security vulnerabilities és törékenyen tesztelt produkciós kód). Visszaadva `@work` agentnek.

### Must-fix prioritási sorrend a work agent számára

1. **Issue 1** — OutboundMessage envelope fix (agent üzenetek töröttek)
2. **Issue 8** — Error payload normalizálás
3. **Issue 7** — `contentEl` DOM fix (Obsidian)
4. **Issue 6** — Echo test kód eltávolítása production session routing-ból
5. **Issue 2** — WS 127.0.0.1 binding
6. **Issue 3** — Session fixation (clientId vs payload sessionId)
7. **Issue 4** — MarkdownRenderer plain-text default
8. **Issue 5** — Append-only DOM rendering (O(N) → O(1))
