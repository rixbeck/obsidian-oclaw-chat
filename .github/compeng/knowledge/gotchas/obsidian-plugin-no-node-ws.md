# Gotcha: Obsidian Plugin Must Not Import Node.js `ws` Package

**Domain:** obsidian-plugin  
**First observed:** 2026-02-25  
**Severity:** High — breaks plugin in Obsidian runtime

---

## What Happened

Obsidian plugins run in an **Electron renderer process** (browser-like environment). Importing the `ws` npm package in the Obsidian plugin will fail because `ws` uses Node.js built-ins (`net`, `http`, `tls`) that are not available in the renderer.

## Root Cause

The Obsidian plugin is bundled for `platform: 'browser'` with esbuild. Node.js native modules are not available.

## Prevention

**Use `window.WebSocket` (the browser API) in the Obsidian plugin:**

```typescript
// ✅ Correct — browser WebSocket available in Electron renderer
const ws = new WebSocket('ws://localhost:8765');

// ❌ Wrong — Node.js ws package, crashes in Obsidian
import { WebSocket } from 'ws';
```

The `ws` npm package is fine in the **channel plugin** (Node.js server), but must never be imported in the **Obsidian plugin** (browser/Electron renderer).

## esbuild config reminder

```javascript
// esbuild.config.mjs
await esbuild.build({
  platform: 'browser',   // ← this is why no Node builtins
  external: ['obsidian', 'electron', ...],
});
```

## References

- `obsidian-plugin/src/websocket.ts` — uses `new WebSocket(url)` directly
- Plan: `.github/compeng/plans/20260225-1350-channel-fix-and-obsidian-phase2.md` §Step 2.4
