import type { PathMapping } from './types';

export function normalizeBase(base: string): string {
  const trimmed = String(base ?? '').trim();
  if (!trimmed) return '';
  return trimmed.endsWith('/') ? trimmed : `${trimmed}/`;
}

export function tryMapRemotePathToVaultPath(input: string, mappings: readonly PathMapping[]): string | null {
  const raw = String(input ?? '');
  for (const row of mappings) {
    const remoteBase = normalizeBase(row.remoteBase);
    const vaultBase = normalizeBase(row.vaultBase);
    if (!remoteBase || !vaultBase) continue;

    if (raw.startsWith(remoteBase)) {
      const rest = raw.slice(remoteBase.length);
      // Obsidian paths are vault-relative and should not start with '/'
      return `${vaultBase}${rest}`.replace(/^\/+/, '');
    }
  }
  return null;
}

export type Candidate = { start: number; end: number; raw: string; kind: 'url' | 'path' };

// Conservative extraction: aim to avoid false positives.
const URL_RE = /https?:\/\/[^\s<>()]+/g;
// Absolute unix-ish paths.
// (We still existence-check before producing a link.)
const PATH_RE = /(?<![A-Za-z0-9._-])(?:\/[A-Za-z0-9._~!$&'()*+,;=:@%\-]+)+(?:\.[A-Za-z0-9._-]+)?/g;

// Conservative relative paths with at least one '/', e.g. compeng/plans/x.md
// Avoids matching scheme-like tokens via negative lookahead for '://'.
const REL_PATH_RE = /\b(?![A-Za-z][A-Za-z0-9+.-]*:\/\/)[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)+(?:\.[A-Za-z0-9._-]+)?\b/g;

export function extractCandidates(text: string): Candidate[] {
  const t = String(text ?? '');
  const out: Candidate[] = [];

  for (const m of t.matchAll(URL_RE)) {
    if (m.index === undefined) continue;
    out.push({ start: m.index, end: m.index + m[0].length, raw: m[0], kind: 'url' });
  }

  for (const m of t.matchAll(PATH_RE)) {
    if (m.index === undefined) continue;

    // Skip if this is inside a URL we already captured.
    const start = m.index;
    const end = start + m[0].length;
    const overlapsUrl = out.some((c) => c.kind === 'url' && !(end <= c.start || start >= c.end));
    if (overlapsUrl) continue;

    out.push({ start, end, raw: m[0], kind: 'path' });
  }

  for (const m of t.matchAll(REL_PATH_RE)) {
    if (m.index === undefined) continue;

    const start = m.index;
    const end = start + m[0].length;
    const overlapsExisting = out.some((c) => !(end <= c.start || start >= c.end));
    if (overlapsExisting) continue;

    out.push({ start, end, raw: m[0], kind: 'path' });
  }

  // Sort and drop overlaps (prefer URLs).
  out.sort((a, b) => a.start - b.start || (a.kind === 'url' ? -1 : 1));
  const dedup: Candidate[] = [];
  for (const c of out) {
    const last = dedup[dedup.length - 1];
    if (!last) {
      dedup.push(c);
      continue;
    }
    if (c.start < last.end) continue;
    dedup.push(c);
  }

  return dedup;
}
