---
status: approved
priority: medium
tags: [obsidian-plugin, ux, progress, gateway, websocket]
owner: Rix
created: 2026-02-25 23:53 Europe/Budapest
estimated_hours: 1-2
issue: inline
related:
  - .github/compeng/plans/20260225-1440-e2e-obsidian-channel-eve1-deployment.md
  - .github/compeng/reviews/20260225-2146-obsidian-oclaw-chat.md
  - .github/compeng/reviews/20260225-2336-obsidian-oclaw-chat-followup.md
---

# Plan — Obsidian OpenClaw Chat: “agent is working” progress visual feedback

## 0) Issue (inline)

### Problem / context
A jelenlegi Obsidian `obsidian-oclaw-chat` kliens pluginben, amikor a user elküld egy üzenetet és az agent válaszára vár, **nincs vizuális visszajelzés** arról, hogy a Gateway/agent dolgozik. Emiatt bizonytalan a UX ("lefagyott?" vs "dolgozik").

### Proposal / solution
Vezessünk be egy **progress/working indikátort** a UI-ban:
- amikor a kliens elküldi a kérést és a Gateway visszajelez ("első esemény" = a `chat.send` request sikeres `res` válasza), a **Send gomb helyén jelenjen meg spinner** (CSS).
- amikor válasz érkezik (assistant final), vagy hiba történik, az indikátor tűnjön el és a Send gomb álljon vissza.
- hiba esetén a hibát **user-visible** módon mutassuk meg: `Notice` (alert-szerű) + egy **piros** rendszerüzenet blokk a chatben.

### Benefits
- Egyértelművé teszi, hogy a rendszer dolgozik → kevesebb duplaküldés, jobb perceived performance.

### Risks
- Regresszió: ha a working-state nem kerül megfelelően resetelésre reconnect/timeout esetén, beragadhat a spinner.

## 1) Prior art / tanulságok (CompEng knowledge)

- **Unbounded / beragadó állapotok kerülése**: working-state legyen per-request, timeouttal és connection close reset-tel. (Ref: `.github/compeng/knowledge/gotchas/unbounded-message-capture-timeout-risk.md` — a lényeg: legyenek cap-ek és reset ágak.)
- **Secure gateway exposure**: a UX változtatás nem nyúljon a hálózati beállításhoz; marad a `wss://...` serve setup. (Ref: `.github/compeng/knowledge/patterns/secure-gateway-exposure-via-tailscale-serve.md`)

## 2) Scope

### In-scope
- Obsidian view: Send gomb spinner mód.
- Working state kezelése `chat.send` sikeres response-tól az első assistant `final` üzenetig.
- Error handling: Notice + piros blokk.

### Out-of-scope
- Streaming/delta megjelenítés (jelenleg final-only).
- Multi-run progress (token/step), explicit run status API.

## 3) Affected files

- `obsidian-plugin/src/view.ts`
- `obsidian-plugin/src/websocket.ts`
- `obsidian-plugin/src/chat.ts` (opcionális: error message helper)
- `obsidian-plugin/src/types.ts` (opcionális: üzenet severity)
- `obsidian-plugin/styles.css`
- `README.md` (opcionális: UX leírás)

## 4) Design details

### 4.1 Working-state definíció

**Trigger (show spinner):**
- a user klikkelett Send → `wsClient.sendMessage(...)` elindul
- **első esemény**: a `chat.send` request `res.ok=true` válasza → innentől `working=true`

**Stop (hide spinner):**
- első beérkező assistant üzenet, ami:
  - `frame.event === 'chat'`
  - `payload.state === 'final'`
  - `role === 'assistant'`
  - `sessionKeyMatches(...) === true`
- vagy bármelyik error ág:
  - `sendMessage` throw
  - request timeout
  - ws close/reconnect

### 4.2 UI viselkedés

- Send gombnak legyen 3 állapota:
  1) disconnected → disabled (most is)
  2) connected + not working → `Send`
  3) connected + working → disabled + spinner (a gombon belül)

- Input továbbra is szerkeszthető (opcionális), de Send tiltott, hogy ne legyen párhuzamos run.

### 4.3 Error megjelenítés

- `Notice('OpenClaw Chat: <error>')`
- Chat listába egy `system` üzenet, ami kap egy CSS osztályt (pl. `oclaw-error`) és piros blokk.

## 5) Implementation steps

1) **Websocket: working callbacks**
   - Adjunk az `ObsidianWSClient`-hez egyszerű hookokat:
     - `onWorkingChange?: (working: boolean) => void`
   - `sendMessage`:
     - `await _sendRequest('chat.send', ...)` siker után → `onWorkingChange(true)`
   - `onmessage` (chat final assistant) után → `onWorkingChange(false)`
   - `onclose` + timeout error ágak → `onWorkingChange(false)`

2) **View: spinner UI**
   - `OpenClawChatView` figyelje `wsClient.onWorkingChange`
   - Implementáljunk egy `setSendButtonWorking(isWorking)` helpert:
     - gomb text cseréje spinner markup-ra
     - disabled true
     - `aria-busy=true`

3) **CSS: spinner**
   - `styles.css`:
     - `.oclaw-send-btn.is-working { ... }`
     - `.oclaw-spinner { width/height/border-radius; animation: spin ... }`
     - `.oclaw-message.system.oclaw-error { background: #...; border-left ... }`

4) **Error path**
   - `view.ts` catch ágban:
     - `this.plugin.wsClient.onWorkingChange(false)` (vagy a hook mechanizmus automatikusan)
     - `new Notice(...)`
     - `chatManager.addMessage(createSystemMessage(...))` + jelölés/piros style

5) **Docs (optional)**
   - README: röviden “Send után spinner jelenik meg, eltűnik válasznál/hibánál”.

## 6) Test plan

### Manual (primary)
1) Nyisd meg az Obsidian sidebar view-t.
2) Küldj üzenetet.
   - Elvárt: a `chat.send` siker után a Send gomb spinnerre vált.
3) Amikor megjön az assistant final válasz:
   - Elvárt: spinner eltűnik, Send visszaáll.
4) Szimulált hiba:
   - rossz token / wss url → elvárt: spinner nem ragad be; Notice + piros system üzenet megjelenik.
5) Reconnect:
   - gateway restart közben → elvárt: working-state reset.

### Optional lightweight unit tests (ha gyors)
- `sessionKeyMatches` + “final-only” logika köré egyszerű tesztesetek.

## 7) Acceptance criteria

- AC1: Sikeres `chat.send` után a Send gomb **spinnerre vált** (progress feedback).
- AC2: Assistant final válasz érkezésekor a spinner **eltűnik**.
- AC3: Hiba esetén a spinner **eltűnik**, és a user kap:
  - Notice/alert jellegű üzenetet
  - piros hiba blokkot a chatben.
- AC4: Gateway disconnect/reconnect esetén **nem ragad be** working state.

## 8) Rollback

- `obsidian-plugin/styles.css` és `view.ts` working-state részek visszavonása.
- A `websocket.ts` working hookok eltávolítása: ha gond van, a jelenlegi final-only működés visszaáll.
