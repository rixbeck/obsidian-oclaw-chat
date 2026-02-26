import { beforeAll, vi } from 'vitest';

beforeAll(() => {
  // Quiet noisy logs during tests (can be overridden per-test).
  vi.spyOn(console, 'debug').mockImplementation(() => {});
  vi.spyOn(console, 'log').mockImplementation(() => {});
  vi.spyOn(console, 'warn').mockImplementation(() => {});
  vi.spyOn(console, 'error').mockImplementation(() => {});
});
