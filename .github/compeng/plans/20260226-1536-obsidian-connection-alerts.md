---
type: plan
status: approved
created: 2026-02-26T15:36:00+01:00
repo: obsidian-oclaw-chat
branch: develop
owner: Rix
scope:
  - obsidian-plugin/src/view.ts
  - (optional) obsidian-plugin/src/types.ts
  - (optional) obsidian-plugin/src/settings.ts
---

# Plan — Kommunikációs hiba / reconnect alert az Obsidian kliensben

## Cél
Legyen egy egyértelmű, user-facing visszajelzés, ha a gateway kapcsolat megszakad vagy épp reconnectel:
- **„Connection lost / reconnecting…”** jellegű Obsidian **Notice** (popup)
- Opcionálisan egy **system message** a chat ablakban (hogy később visszanézhető legyen)

## Kiinduló helyzet
- Jelenleg a státusz főleg a **status dot**-on látszik (`Gateway: disconnected|connecting|handshaking|connected`).
- Van Notice **küldési hibánál** (`Send failed`), illetve a `wsClient.onMessage(type:'error')` bekerül system message-ként.
- Nincs dedikált Notice a WS **onclose/reconnect** eseményekre.

## Scope / Nem célok
**Scope:** csak kliens UX jelzés a kapcsolat állapotáról.
**Nem cél:** reconnect algoritmus módosítása, gateway contract változtatás, deep telemetry.

## Tervezett változtatások

### 1) Connection-state figyelés + Notice (throttlinggal)
Implementáció a `OpenClawChatView`-ban (`obsidian-plugin/src/view.ts`):
- Tartsunk egy `lastConnectionNoticeAtMs` timestampet + `lastState`-et.
- `wsClient.onStateChange` handlerben:
  - Ha **connected → disconnected**: `new Notice('OpenClaw Chat: connection lost — reconnecting…')`
  - Ha **disconnected/connecting/handshaking → connected**: opcionális `new Notice('OpenClaw Chat: reconnected')`
- Throttle:
  - „lost/reconnecting” max **1x / 60s** (vagy 2–5 perc, ha túl zajos)
  - „reconnected” max **1x / 60s**

### 2) Chat ablakba system message (opcionális)
Ugyanitt (view), a Notice mellett:
- `this.chatManager.addMessage(ChatManager.createSystemMessage('⚠ Connection lost — reconnecting…', 'error'))`
- `...('✅ Reconnected', 'info')`

(Alternatíva: ezt a `main.ts`-ben csinálni, de akkor minden view nélküli futásnál is beíródik; a view-ben UX-centrikusabb.)

### 3) (Opcionális) Beállítás a popupokhoz
Ha azt szeretnéd, hogy kikapcsolható legyen:
- `types.ts`: `showConnectionNotices: boolean` (default: `true`)
- `settings.ts`: toggle „Show connection notices”

## Acceptance criteria
- Ha a kapcsolat megszakad (state `disconnected` lesz egy korábbi `connected` után), a user kap egy **egyszerű Notice**-t.
- Reconnect loop esetén **nem spammel** (throttling működik).
- Sikeres újracsatlakozáskor opcionálisan jelez (Notice és/vagy system message).
- Nincs regresszió: build + typecheck + tesztek zöldek.

## Tesztek / Gates
- `npm -C obsidian-plugin run typecheck`
- `npm -C obsidian-plugin run test:once`
- `npm -C obsidian-plugin run build`

## Kockázatok
- UX zajosság: ezért kell throttle.
- Több chat view leaf esetén duplikált Notice: ezért érdemes **globálisan** (plugin-szinten) throttlingot tárolni, ha ez valós probléma lesz.

## Rollback
- Egy commit revert a view-state notice logikára.
