import { describe, expect, it } from 'vitest';
import { DEFAULT_SETTINGS, type OpenClawSettings } from './types';
import { migrateSettingsForVault, canonicalVaultSessionKey, isAllowedObsidianSessionKey } from './session';

describe('session helpers', () => {
  it('canonicalVaultSessionKey builds expected key', () => {
    expect(canonicalVaultSessionKey('abcd')).toBe('agent:main:obsidian:direct:abcd');
  });

  it('migrates empty/main to canonical', () => {
    const vaultHash = 'deadbeefdeadbeef';
    const s: OpenClawSettings = { ...DEFAULT_SETTINGS, sessionKey: 'main' };
    const { nextSettings, canonicalKey } = migrateSettingsForVault(s, vaultHash);
    expect(canonicalKey).toBe(`agent:main:obsidian:direct:${vaultHash}`);
    expect(nextSettings.sessionKey).toBe(canonicalKey);
    expect(nextSettings.knownSessionKeysByVault?.[vaultHash]).toContain(canonicalKey);
  });

  it('records legacy obsidian-* and migrates to canonical', () => {
    const vaultHash = '1111222233334444';
    const s: OpenClawSettings = { ...DEFAULT_SETTINGS, sessionKey: 'obsidian-20260226-1955' };
    const { nextSettings, canonicalKey } = migrateSettingsForVault(s, vaultHash);
    expect(nextSettings.sessionKey).toBe(canonicalKey);
    expect(nextSettings.legacySessionKeys).toContain('obsidian-20260226-1955');
  });

  it('migration is idempotent (no duplicate canonical)', () => {
    const vaultHash = 'aaaaaaaaaaaaaaaa';
    const canonical = canonicalVaultSessionKey(vaultHash);
    const s: OpenClawSettings = {
      ...DEFAULT_SETTINGS,
      sessionKey: canonical,
      knownSessionKeysByVault: { [vaultHash]: [canonical] },
    };
    const { nextSettings } = migrateSettingsForVault(s, vaultHash);
    expect(nextSettings.knownSessionKeysByVault?.[vaultHash]).toEqual([canonical]);
  });

  it('isAllowedObsidianSessionKey enforces vaultHash', () => {
    const vaultHash = 'bbbbbbbbbbbbbbbb';
    const ok = `agent:main:obsidian:direct:${vaultHash}-x`;
    const bad = 'agent:main:obsidian:direct:cccccccccccccccc-x';
    expect(isAllowedObsidianSessionKey({ key: ok, vaultHash })).toBe(true);
    expect(isAllowedObsidianSessionKey({ key: bad, vaultHash })).toBe(false);
    expect(isAllowedObsidianSessionKey({ key: 'main', vaultHash })).toBe(true);
  });
});
