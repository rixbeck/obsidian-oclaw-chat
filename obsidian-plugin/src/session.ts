import type { OpenClawSettings } from './types';

export function canonicalVaultSessionKey(vaultHash: string): string {
  return `agent:main:obsidian:direct:${vaultHash}`;
}

export function isAllowedObsidianSessionKey(params: {
  key: string;
  vaultHash: string | null;
}): boolean {
  const key = (params.key ?? '').trim().toLowerCase();
  if (!key) return false;
  if (key === 'main') return true;

  const vaultHash = (params.vaultHash ?? '').trim().toLowerCase();
  if (!vaultHash) {
    // Without a vault identity, we only allow main.
    return false;
  }

  const prefix = `agent:main:obsidian:direct:${vaultHash}`;
  if (key === prefix) return true;
  if (key.startsWith(prefix + '-')) return true;
  return false;
}

export function migrateSettingsForVault(settings: OpenClawSettings, vaultHash: string): {
  nextSettings: OpenClawSettings;
  canonicalKey: string;
} {
  const canonicalKey = canonicalVaultSessionKey(vaultHash);
  const existing = (settings.sessionKey ?? '').trim().toLowerCase();
  const isLegacy = existing.startsWith('obsidian-');
  const isEmptyOrMain = !existing || existing === 'main' || existing === 'agent:main:main';

  const next: OpenClawSettings = { ...settings };
  next.vaultHash = vaultHash;

  if (isLegacy) {
    const legacy = Array.isArray(next.legacySessionKeys) ? next.legacySessionKeys : [];
    next.legacySessionKeys = [existing, ...legacy.filter((k) => k && k !== existing)].slice(0, 20);
  }

  if (isLegacy || isEmptyOrMain) {
    next.sessionKey = canonicalKey;
  }

  const map = next.knownSessionKeysByVault ?? {};
  const cur = Array.isArray(map[vaultHash]) ? map[vaultHash] : [];
  if (!cur.includes(canonicalKey)) {
    map[vaultHash] = [canonicalKey, ...cur].slice(0, 20);
    next.knownSessionKeysByVault = map;
  }

  return { nextSettings: next, canonicalKey };
}
