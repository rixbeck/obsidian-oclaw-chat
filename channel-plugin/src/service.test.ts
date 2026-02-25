import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { WebSocket } from 'ws';
import type { AddressInfo } from 'net';
import { startWebSocketService, getActiveSession, getAllActiveSessions } from './service.js';
import type { PluginContext } from './types.js';

const TEST_TOKEN = 'integration-test-token';

function makeCtx(overrides?: Partial<PluginContext['config']>): PluginContext {
  return {
    log: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
    config: {
      enabled: true,
      wsPort: 0, // 0 = OS assigns free port
      authToken: TEST_TOKEN,
      accounts: ['main'],
      ...overrides,
    },
    runtime: { dispatchToAgent: vi.fn().mockResolvedValue(undefined) },
  };
}

/** Wait for a single message from a WebSocket client */
function waitForMessage(ws: WebSocket): Promise<any> {
  return new Promise((resolve, reject) => {
    ws.once('message', (data) => {
      try {
        resolve(JSON.parse(data.toString()));
      } catch (e) {
        reject(e);
      }
    });
    ws.once('error', reject);
  });
}

/** Connect a client and wait for the connection to be open */
function connectClient(port: number): Promise<WebSocket> {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://localhost:${port}`);
    ws.once('open', () => resolve(ws));
    ws.once('error', reject);
  });
}

let wss: ReturnType<typeof startWebSocketService>;
let port: number;
let ctx: PluginContext;

beforeEach(async () => {
  ctx = makeCtx();
  wss = startWebSocketService(ctx);
  await new Promise<void>((resolve) => wss.once('listening', resolve));
  port = (wss.address() as AddressInfo).port;
});

afterEach(async () => {
  await new Promise<void>((resolve) => wss.close(() => resolve()));
});

describe('WebSocket server', () => {
  it('starts and listens on the assigned port', () => {
    expect(port).toBeGreaterThan(0);
  });

  it('accepts connection and authenticates with correct token', async () => {
    const client = await connectClient(port);
    const msgPromise = waitForMessage(client);

    client.send(JSON.stringify({
      type: 'auth',
      payload: { token: TEST_TOKEN, sessionId: 'test-session', agentId: 'main' },
    }));

    const response = await msgPromise;
    expect(response.type).toBe('auth');
    expect(response.payload.success).toBe(true);

    client.close();
  });

  it('rejects and closes connection on wrong token', async () => {
    const client = await connectClient(port);
    const closePromise = new Promise<void>((resolve) => client.once('close', () => resolve()));
    const msgPromise = waitForMessage(client);

    client.send(JSON.stringify({
      type: 'auth',
      payload: { token: 'wrong-token', sessionId: 'bad-sess', agentId: 'main' },
    }));

    const response = await msgPromise;
    expect(response.type).toBe('error');
    await closePromise; // server should close the connection
  });

  it('responds to ping with pong after authentication', async () => {
    const client = await connectClient(port);

    // Auth first
    const authPromise = waitForMessage(client);
    client.send(JSON.stringify({
      type: 'auth',
      payload: { token: TEST_TOKEN, sessionId: 'ping-sess', agentId: 'main' },
    }));
    await authPromise;

    // Send ping
    const pongPromise = waitForMessage(client);
    client.send(JSON.stringify({ type: 'ping' }));
    const pong = await pongPromise;

    expect(pong.type).toBe('pong');
    client.close();
  });

  it('rejects non-auth messages from unauthenticated clients', async () => {
    const client = await connectClient(port);
    const msgPromise = waitForMessage(client);

    client.send(JSON.stringify({
      type: 'message',
      payload: { message: 'sneaky message' },
    }));

    const response = await msgPromise;
    expect(response.type).toBe('error');
    expect(response.payload.message).toMatch(/not authenticated/i);
    client.close();
  });

  it('removes session from active sessions on disconnect', async () => {
    const client = await connectClient(port);

    const authPromise = waitForMessage(client);
    client.send(JSON.stringify({
      type: 'auth',
      payload: { token: TEST_TOKEN, agentId: 'main' },
    }));
    const authResponse = await authPromise;
    // Server assigns its own session ID — ignore any client-supplied value
    const serverSessionId: string = authResponse.payload.sessionId;
    expect(serverSessionId).toBeDefined();

    expect(getActiveSession(serverSessionId)).toBeDefined();

    const closePromise = new Promise<void>((resolve) => {
      // Small delay to allow server-side close handler to run
      client.once('close', () => setTimeout(resolve, 50));
    });
    client.close();
    await closePromise;

    expect(getActiveSession(serverSessionId)).toBeUndefined();
  });
});
