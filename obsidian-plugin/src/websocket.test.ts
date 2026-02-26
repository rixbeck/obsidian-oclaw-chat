import { describe, expect, it, vi } from 'vitest';
import { ObsidianWSClient } from './websocket';

class MockWebSocket {
  readyState: number = WebSocket.OPEN;
  bufferedAmount = 0;
  sent: string[] = [];

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  constructor(_url: string) {}

  send(data: string) {
    this.sent.push(data);
  }

  close() {
    this.readyState = 3;
  }
}

function lastSentReq(ws: MockWebSocket) {
  expect(ws.sent.length).toBeGreaterThan(0);
  return JSON.parse(ws.sent[ws.sent.length - 1]);
}

describe('ObsidianWSClient (abort/working state)', () => {
  it('sendMessage sets working=true only after chat.send ack', async () => {
    const client = new ObsidianWSClient('main');
    const ws = new MockWebSocket('ws://test');
    (client as any).ws = ws;
    (client as any).state = 'connected';

    const workingCalls: boolean[] = [];
    client.onWorkingChange = (w) => workingCalls.push(w);

    const p = client.sendMessage('hi');

    // ensure request was sent
    expect(ws.sent.length).toBe(1);

    // still not working (no ack yet)
    expect(workingCalls).toEqual([]);

    const req = lastSentReq(ws);
    (client as any)._handleResponseFrame({ type: 'res', id: req.id, ok: true, payload: {} });

    await p;

    expect(workingCalls).toEqual([true]);
    expect((client as any).activeRunId).toMatch(/^obsidian-/);
  });

  it('final chat event clears working and activeRunId (runId match best-effort)', async () => {
    const client = new ObsidianWSClient('main');
    const ws = new MockWebSocket('ws://test');
    (client as any).ws = ws;
    (client as any).state = 'connected';

    const workingCalls: boolean[] = [];
    client.onWorkingChange = (w) => workingCalls.push(w);

    const p = client.sendMessage('hi');
    const req = lastSentReq(ws);
    (client as any)._handleResponseFrame({ type: 'res', id: req.id, ok: true, payload: {} });
    await p;

    const runId = (client as any).activeRunId as string;

    (client as any)._handleChatEventFrame({
      type: 'event',
      event: 'chat',
      payload: {
        sessionKey: 'agent:main:main',
        state: 'final',
        runId,
        message: { role: 'assistant', content: [{ type: 'text', text: 'hello' }] },
      },
    });

    expect((client as any).activeRunId).toBeNull();
    expect(workingCalls[workingCalls.length - 1]).toBe(false);
  });

  it('abortActiveRun is idempotent while in-flight (prevents abort spamming)', async () => {
    const client = new ObsidianWSClient('main');
    const ws = new MockWebSocket('ws://test');
    (client as any).ws = ws;
    (client as any).state = 'connected';

    (client as any).activeRunId = 'obsidian-test-run';
    (client as any)._setWorking(true);

    const p1 = client.abortActiveRun();
    const p2 = client.abortActiveRun();

    expect(ws.sent.length).toBe(1);

    const req = lastSentReq(ws);
    expect(req.method).toBe('chat.abort');
    expect(req.params).toMatchObject({ sessionKey: 'main', runId: 'obsidian-test-run' });

    (client as any)._handleResponseFrame({ type: 'res', id: req.id, ok: true, payload: {} });

    await expect(Promise.all([p1, p2])).resolves.toEqual([true, true]);
    expect((client as any).activeRunId).toBeNull();
  });

  it('working safety timeout clears working if no terminal event arrives', async () => {
    vi.useFakeTimers();

    const client = new ObsidianWSClient('main');
    const ws = new MockWebSocket('ws://test');
    (client as any).ws = ws;
    (client as any).state = 'connected';

    const workingCalls: boolean[] = [];
    client.onWorkingChange = (w) => workingCalls.push(w);

    const p = client.sendMessage('hi');
    const req = lastSentReq(ws);
    (client as any)._handleResponseFrame({ type: 'res', id: req.id, ok: true, payload: {} });
    await p;

    expect(workingCalls).toContain(true);

    vi.advanceTimersByTime(120_000);

    expect(workingCalls[workingCalls.length - 1]).toBe(false);

    vi.useRealTimers();
  });
});
