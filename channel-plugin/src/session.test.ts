import { describe, it, expect, vi } from 'vitest';
import { routeToSession } from './session.js';
import type { PluginContext, SessionInfo, WSMessage } from './types.js';

function makeCtx(dispatchToAgent?: (...args: any[]) => Promise<any>): PluginContext {
  return {
    log: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
    config: { enabled: true, wsPort: 8765, authToken: 'test-token', accounts: ['main'] },
    runtime: dispatchToAgent ? { dispatchToAgent } : {},
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

describe('routeToSession', () => {
  it('calls runtime.dispatchToAgent with the correct payload', async () => {
    const dispatch = vi.fn().mockResolvedValue(undefined);
    const ctx = makeCtx(dispatch);
    const session = makeSession();
    const msg: WSMessage = {
      type: 'message',
      payload: { message: 'Hello agent', context: { activeNote: 'note.md', noteContent: 'hello' } },
    };

    await routeToSession(msg, session, ctx);

    expect(dispatch).toHaveBeenCalledOnce();
    expect(dispatch).toHaveBeenCalledWith('main', {
      channel: 'obsidian',
      sessionId: 'sess-1',
      message: 'Hello agent',
      context: { activeNote: 'note.md', noteContent: 'hello' },
    });
  });

  it('accepts payload.text as message fallback', async () => {
    const dispatch = vi.fn().mockResolvedValue(undefined);
    const ctx = makeCtx(dispatch);
    const session = makeSession();
    const msg: WSMessage = {
      type: 'message',
      payload: { text: 'text fallback' },
    };

    await routeToSession(msg, session, ctx);

    expect(dispatch).toHaveBeenCalledWith('main', expect.objectContaining({ message: 'text fallback' }));
  });

  it('sends error response when runtime.dispatchToAgent is not available', async () => {
    const ctx = makeCtx(undefined); // no dispatchToAgent
    const session = makeSession();
    const msg: WSMessage = {
      type: 'message',
      payload: { message: 'echo me please' },
    };

    await routeToSession(msg, session, ctx);

    expect(session.wsClient.send).toHaveBeenCalledOnce();
    const sent = JSON.parse((session.wsClient.send as ReturnType<typeof vi.fn>).mock.calls[0][0]);
    expect(sent.type).toBe('error');
    expect(sent.payload.message).toMatch(/unavailable/i);
  });

  it('warns and returns early when payload is missing', async () => {
    const ctx = makeCtx();
    const session = makeSession();
    const msg: WSMessage = { type: 'message' }; // no payload

    await expect(routeToSession(msg, session, ctx)).resolves.toBeUndefined();
    expect((ctx.log.warn as ReturnType<typeof vi.fn>)).toHaveBeenCalled();
    expect(session.wsClient.send).not.toHaveBeenCalled();
  });
});
