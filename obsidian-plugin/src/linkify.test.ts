import { describe, expect, it } from 'vitest';
import { extractCandidates, normalizeBase, tryMapRemotePathToVaultPath } from './linkify';

describe('linkify', () => {
  it('normalizeBase trims and enforces trailing slash', () => {
    expect(normalizeBase('')).toBe('');
    expect(normalizeBase(' docs ')).toBe('docs/');
    expect(normalizeBase('docs/')).toBe('docs/');
  });

  it('tryMapRemotePathToVaultPath maps prefixes and strips leading slash', () => {
    const mappings = [
      { vaultBase: 'vault/', remoteBase: '/remote/base/' },
    ];

    expect(tryMapRemotePathToVaultPath('/remote/base/foo/bar.md', mappings)).toBe('vault/foo/bar.md');
  });

  it('tryMapRemotePathToVaultPath uses first match', () => {
    const mappings = [
      { vaultBase: 'v1/', remoteBase: '/remote/' },
      { vaultBase: 'v2/', remoteBase: '/remote/base/' },
    ];

    expect(tryMapRemotePathToVaultPath('/remote/base/x.md', mappings)).toBe('v1/base/x.md');
  });

  it('tryMapRemotePathToVaultPath returns null when no match', () => {
    const mappings = [{ vaultBase: 'v/', remoteBase: '/other/' }];
    expect(tryMapRemotePathToVaultPath('/remote/base/x.md', mappings)).toBeNull();
  });

  it('extractCandidates finds urls and absolute paths (no url overlaps)', () => {
    const s = 'See https://example.com/a/b and /home/user/file.md';
    const c = extractCandidates(s);

    expect(c.some((x) => x.kind === 'url' && x.raw === 'https://example.com/a/b')).toBe(true);
    expect(c.some((x) => x.kind === 'path' && x.raw === '/home/user/file.md')).toBe(true);
  });

  it('extractCandidates finds relative paths', () => {
    const s = 'See compeng/plans/20260226-1716-obsidian-path-mapping-linkify.md for details.';
    const c = extractCandidates(s);
    expect(c.some((x) => x.kind === 'path' && x.raw === 'compeng/plans/20260226-1716-obsidian-path-mapping-linkify.md')).toBe(true);
  });
});
