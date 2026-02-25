/**
 * RPC methods for agent -> Obsidian communication
 */

import type { PluginContext, OutboundMessage } from './types.js';
import { getActiveSession, getAllActiveSessions } from './service.js';

/**
 * Send a message from agent to Obsidian client
 * 
 * RPC method: obsidian.sendMessage
 */
export async function sendMessage(
  sessionId: string,
  content: string,
  ctx: PluginContext
): Promise<{ success: boolean; error?: string }> {
  const { log } = ctx;

  const session = getActiveSession(sessionId);
  
  if (!session) {
    log.warn('[obsidian-channel] Session not found for sendMessage', { sessionId });
    return { success: false, error: 'Session not found' };
  }

  if (!session.authenticated) {
    return { success: false, error: 'Session not authenticated' };
  }

  const outboundMessage: OutboundMessage = {
    type: 'message',
    payload: { content, timestamp: Date.now() },
  };

  try {
    session.wsClient.send(JSON.stringify(outboundMessage));
    log.debug('[obsidian-channel] Message sent to Obsidian client', { sessionId });
    return { success: true };
  } catch (error) {
    log.error('[obsidian-channel] Failed to send message', { sessionId, error });
    return { success: false, error: 'Send failed' };
  }
}

/**
 * List all active Obsidian accounts/sessions
 * 
 * RPC method: obsidian.listAccounts
 */
export async function listAccounts(
  ctx: PluginContext
): Promise<Array<{ agentId: string; sessionId: string; authenticated: boolean }>> {
  const { log } = ctx;

  const sessions = getAllActiveSessions();
  
  log.debug('[obsidian-channel] Listing active accounts', { count: sessions.length });

  return sessions.map(session => ({
    agentId: session.agentId,
    sessionId: session.sessionId,
    authenticated: session.authenticated,
  }));
}

/**
 * Broadcast a message from agent to ALL authenticated Obsidian clients
 *
 * Used when no specific sessionId is provided (e.g. proactive push).
 */
export async function broadcastMessage(
  content: string,
  ctx: PluginContext,
): Promise<{ sent: number; errors: number }> {
  const { log } = ctx;

  const sessions = getAllActiveSessions().filter(s => s.authenticated);
  let sent = 0;
  let errors = 0;

  const outboundMessage: OutboundMessage = {
    type: 'message',
    payload: { content, timestamp: Date.now() },
  };

  const payload = JSON.stringify(outboundMessage);

  for (const session of sessions) {
    try {
      session.wsClient.send(payload);
      sent++;
    } catch (error) {
      log.error('[obsidian-channel] broadcastMessage send failed', {
        sessionId: session.sessionId,
        error,
      });
      errors++;
    }
  }

  log.debug('[obsidian-channel] broadcastMessage complete', { sent, errors });
  return { sent, errors };
}

/**
 * Register RPC methods with OpenClaw runtime
 */
export function registerRPCMethods(ctx: PluginContext) {
  const { log, runtime } = ctx;

  if (!runtime.registerRPC) {
    log.warn('[obsidian-channel] runtime.registerRPC not available - RPC methods will not be registered');
    return;
  }

  runtime.registerRPC('obsidian.sendMessage', async (sessionId: string, content: string) => {
    return await sendMessage(sessionId, content, ctx);
  });

  runtime.registerRPC('obsidian.broadcastMessage', async (content: string) => {
    return await broadcastMessage(content, ctx);
  });

  runtime.registerRPC('obsidian.listAccounts', async () => {
    return await listAccounts(ctx);
  });

  log.info('[obsidian-channel] RPC methods registered', {
    methods: ['obsidian.sendMessage', 'obsidian.broadcastMessage', 'obsidian.listAccounts'],
  });
}
