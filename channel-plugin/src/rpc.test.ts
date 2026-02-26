import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { PluginContext, SessionInfo } from './types.js';

// Mock service.ts so we control the session store
vi.mock('./service.js', () => ({
  getActiveSession: vi.fn(),
  getAllActiveSessions: vi.fn(),
}));

import { getActiveSession, getAllActiveSessions } from './service.js';
import { sendMessage, listAccounts, broadcastMessage, registerRPCMethods } from './rpc.js';

function makeCtx(): PluginContext {
  return {
    log: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
    config: { enabled: true, wsPort: 8765, authToken: 'test-token', accounts: ['main'] },
    runtime: { registerRPC: vi.fn() },
  };
}

function makeSession(overrides?: Partial<SessionInfo>): SessionInfo {
  return {
    sessionId: 'sess-1',
    agentId: 'main',
    wsClient: { send: vi.fn() },
    authenticated: true,
    ...overrides,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('sendMessage', () => {
  it('returns { success: false } when session is not found', async () => {
    vi.mocked(getActiveSession).mockReturnValue(undefined);
    const ctx = makeCtx();

    const result = await sendMessage('unknown-sess', 'hello', ctx);

    expect(result).toEqual({ success: false, error: 'Session not found' });
  });

  it('returns { success: false } when session is not authenticated', async () => {
    const session = makeSession({ authenticated: false });
    vi.mocked(getActiveSession).mockReturnValue(session);
    const ctx = makeCtx();

    const result = await sendMessage('sess-1', 'hello', ctx);

    expect(result).toEqual({ success: false, error: 'Session not authenticated' });
  });

  it('calls ws.send and returns { success: true } for authenticated session', async () => {
    const session = makeSession();
    vi.mocked(getActiveSession).mockReturnValue(session);
    const ctx = makeCtx();

    const result = await sendMessage('sess-1', 'Hello Obsidian!', ctx);

    expect(result).toEqual({ success: true });
    expect(session.wsClient.send).toHaveBeenCalledOnce();
    const sent = JSON.parse((session.wsClient.send as ReturnType<typeof vi.fn>).mock.calls[0][0]);
    expect(sent.type).toBe('message');
    expect(sent.payload.content).toBe('Hello Obsidian!');
    expect(typeof sent.payload.timestamp).toBe('number');
  });
});

describe('broadcastMessage', () => {
  it('returns { sent: 0, errors: 0 } when no sessions', async () => {
    vi.mocked(getAllActiveSessions).mockReturnValue([]);
    const ctx = makeCtx();

    const result = await broadcastMessage('hello everyone', ctx);
    expect(result).toEqual({ sent: 0, errors: 0 });
  });

  it('sends to all authenticated sessions, skips unauthenticated', async () => {
    const sess1 = makeSession({ sessionId: 'sess-1' });
    const sess2 = makeSession({ sessionId: 'sess-2' });
    const sessUnauth = makeSession({ sessionId: 'sess-3', authenticated: false });
    vi.mocked(getAllActiveSessions).mockReturnValue([sess1, sess2, sessUnauth]);
    const ctx = makeCtx();

    const result = await broadcastMessage('broadcast!', ctx);

    expect(result).toEqual({ sent: 2, errors: 0 });
    expect(sess1.wsClient.send).toHaveBeenCalledOnce();
    expect(sess2.wsClient.send).toHaveBeenCalledOnce();
    expect(sessUnauth.wsClient.send).not.toHaveBeenCalled();
  });

  it('counts errors when ws.send throws', async () => {
    const sess = makeSession();
    (sess.wsClient.send as ReturnType<typeof vi.fn>).mockImplementation(() => {
      throw new Error('WS closed');
    });
    vi.mocked(getAllActiveSessions).mockReturnValue([sess]);
    const ctx = makeCtx();

    const result = await broadcastMessage('oops', ctx);
    expect(result).toEqual({ sent: 0, errors: 1 });
  });
});

describe('listAccounts', () => {
  it('returns empty array when no sessions exist', async () => {
    vi.mocked(getAllActiveSessions).mockReturnValue([]);
    const ctx = makeCtx();

    const result = await listAccounts(ctx);
    expect(result).toEqual([]);
  });

  it('maps sessions to account info objects', async () => {
    const sess1 = makeSession({ sessionId: 'sess-a', agentId: 'main', authenticated: true });
    const sess2 = makeSession({ sessionId: 'sess-b', agentId: 'senilla', authenticated: true });
    vi.mocked(getAllActiveSessions).mockReturnValue([sess1, sess2]);
    const ctx = makeCtx();

    const result = await listAccounts(ctx);
    expect(result).toEqual([
      { agentId: 'main', sessionId: 'sess-a', authenticated: true },
      { agentId: 'senilla', sessionId: 'sess-b', authenticated: true },
    ]);
  });
});

describe('registerRPCMethods', () => {
  it('registers obsidian.sendMessage, obsidian.broadcastMessage, obsidian.listAccounts', () => {
    const ctx = makeCtx();
    registerRPCMethods(ctx);

    const registerRPC = ctx.runtime.registerRPC as ReturnType<typeof vi.fn>;
    expect(registerRPC).toHaveBeenCalledTimes(3);

    const registeredNames = registerRPC.mock.calls.map((call: any[]) => call[0]);
    expect(registeredNames).toContain('obsidian.sendMessage');
    expect(registeredNames).toContain('obsidian.broadcastMessage');
    expect(registeredNames).toContain('obsidian.listAccounts');
  });

  it('warns and does nothing when runtime.registerRPC is not available', () => {
    const ctx = makeCtx();
    ctx.runtime = {}; // no registerRPC

    expect(() => registerRPCMethods(ctx)).not.toThrow();
    expect((ctx.log.warn as ReturnType<typeof vi.fn>)).toHaveBeenCalled();
  });
});
