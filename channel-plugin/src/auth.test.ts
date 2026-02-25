import { describe, it, expect } from 'vitest';
import { validateToken } from './auth.js';

describe('validateToken', () => {
  it('returns true when tokens match', () => {
    expect(validateToken('my-secret-token', 'my-secret-token')).toBe(true);
  });

  it('returns false when tokens differ', () => {
    expect(validateToken('wrong-token', 'my-secret-token')).toBe(false);
  });

  it('returns false when provided token is undefined', () => {
    expect(validateToken(undefined, 'my-secret-token')).toBe(false);
  });

  it('returns false when expected token is empty string', () => {
    expect(validateToken('some-token', '')).toBe(false);
  });

  it('returns false when lengths differ (timing-safe path)', () => {
    expect(validateToken('short', 'much-longer-token')).toBe(false);
  });

  it('returns false when both are empty strings', () => {
    // Empty expected token is invalid config → false
    expect(validateToken('', '')).toBe(false);
  });

  it('is case-sensitive', () => {
    expect(validateToken('Token', 'token')).toBe(false);
    expect(validateToken('TOKEN', 'TOKEN')).toBe(true);
  });
});
