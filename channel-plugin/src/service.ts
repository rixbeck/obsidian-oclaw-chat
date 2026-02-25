/**
 * WebSocket service for Obsidian communication
 */

import { WebSocketServer, WebSocket } from 'ws';
import type { PluginContext, SessionInfo, WSMessage } from './types.js';
import { validateToken } from './auth.js';
import { routeToSession } from './session.js';

const activeSessions = new Map<string, SessionInfo>();

export function startWebSocketService(ctx: PluginContext) {
  const { log, config } = ctx;
  const { wsPort } = config;

  const wss = new WebSocketServer({ host: '127.0.0.1', port: wsPort });

  wss.on('listening', () => {
    log.info(`[obsidian-channel] WebSocket server listening on port ${wsPort}`);
  });

  wss.on('connection', (ws: WebSocket, req) => {
    const clientId = `client-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    log.debug('[obsidian-channel] New connection', { clientId, url: req.url });

    let sessionInfo: SessionInfo | null = null;

    ws.on('message', async (data: Buffer) => {
      try {
        const message: WSMessage = JSON.parse(data.toString());
        
        // Handle authentication first
        if (message.type === 'auth') {
          const isValid = validateToken(message.payload?.token, config.authToken);
          
          if (!isValid) {
            ws.send(JSON.stringify({ type: 'error', payload: { message: 'Invalid token' } }));
            ws.close();
            return;
          }

          // Always use the server-generated clientId — never trust client-supplied sessionId
          sessionInfo = {
            sessionId: clientId,
            agentId: message.payload?.agentId || 'main',
            wsClient: ws,
            authenticated: true,
          };

          activeSessions.set(sessionInfo.sessionId, sessionInfo);
          
          ws.send(JSON.stringify({ type: 'auth', payload: { success: true, sessionId: sessionInfo.sessionId } }));
          log.info('[obsidian-channel] Client authenticated', { 
            sessionId: sessionInfo.sessionId,
            agentId: sessionInfo.agentId
          });
          return;
        }

        // Require authentication for other message types
        if (!sessionInfo?.authenticated) {
          ws.send(JSON.stringify({ type: 'error', payload: { message: 'Not authenticated' } }));
          return;
        }

        // Handle other message types
        await handleMessage(message, sessionInfo, ctx);

      } catch (error) {
        log.error('[obsidian-channel] Error processing message', { error });
        ws.send(JSON.stringify({ type: 'error', payload: { message: 'Message processing failed' } }));
      }
    });

    ws.on('close', () => {
      if (sessionInfo) {
        activeSessions.delete(sessionInfo.sessionId);
        log.info('[obsidian-channel] Client disconnected', { sessionId: sessionInfo.sessionId });
      }
    });

    ws.on('error', (error) => {
      log.error('[obsidian-channel] WebSocket error', { error, clientId });
    });
  });

  wss.on('error', (error) => {
    log.error('[obsidian-channel] WebSocket server error', { error });
  });

  return wss;
}

async function handleMessage(message: WSMessage, sessionInfo: SessionInfo, ctx: PluginContext) {
  const { log } = ctx;

  switch (message.type) {
    case 'message':
      // Route message to agent session
      await routeToSession(message, sessionInfo, ctx);
      break;

    case 'ping':
      sessionInfo.wsClient.send(JSON.stringify({ type: 'pong' }));
      break;

    default:
      log.warn('[obsidian-channel] Unknown message type', { type: message.type });
  }
}

export function getActiveSession(sessionId: string): SessionInfo | undefined {
  return activeSessions.get(sessionId);
}

export function getAllActiveSessions(): SessionInfo[] {
  return Array.from(activeSessions.values());
}
