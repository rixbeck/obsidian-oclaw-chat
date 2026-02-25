# Gotcha: OpenClaw Plugin Cannot Import Core Internals

**Domain:** openclaw-plugin  
**First observed:** 2026-02-25  
**Severity:** High — causes runtime crash

---

## What Happened

When a channel plugin tried to `import { something } from 'openclaw/internal/...'`, Node.js threw:

```
Error [ERR_PACKAGE_PATH_NOT_EXPORTED]:
  Package subpath './internal/...' is not defined by "exports" in
  node_modules/openclaw/package.json
```

## Root Cause

OpenClaw's `package.json` uses the `exports` field to restrict which subpaths are publicly importable. Internal modules are intentionally excluded.

## Prevention

**Never import OpenClaw internal modules.** Use only the `runtime` context object passed to `register(ctx)`:

```typescript
export function register(ctx: any) {
  const { log, config, runtime } = ctx;

  // ✅ OK — use runtime APIs
  if (runtime.registerChannel) { ... }
  if (runtime.registerRPC) { ... }
  if (runtime.dispatchToAgent) { ... }

  // ❌ NEVER — will throw ERR_PACKAGE_PATH_NOT_EXPORTED
  // import { Session } from 'openclaw/core/session';
}
```

Always guard runtime API calls with `if (runtime.X)` — the API surface may differ between OpenClaw versions.

## References

- Plan: `.github/compeng/plans/20260225-0954-hybrid-obsidian-integration.md` §4.3
