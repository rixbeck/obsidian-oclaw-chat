/**
 * WebSocket service for Obsidian communication
 */

import { WebSocketServer, WebSocket } from 'ws';
import { getObsidianRuntime } from './runtime.js';
import { validateToken } from './auth.js';

interface ObsidianConfig {
  wsPort: number;
  authToken: string;
  accounts: string[];
}

interface SessionInfo {
  sessionId: string;
  agentId: string;
  wsClient: WebSocket;
  authenticated: boolean;
}

interface WSMessage {
  type: string;
  payload?: any;
}

const activeSessions = new Map<string, SessionInfo>();
let wsServer: WebSocketServer | null = null;

export function startWebSocketService(config: ObsidianConfig) {
  const runtime = getObsidianRuntime();
  const log = runtime.logging.getChildLogger({ plugin: "openclaw-channel-obsidian", component: "ws" });

  // Prevent double-start
  if (wsServer) {
    log.warn('[obsidian-channel] WebSocket server already running');
    return;
  }

  const wss = new WebSocketServer({ host: '127.0.0.1', port: config.wsPort });
  wsServer = wss;

  wss.on('listening', () => {
    log.info(`[obsidian-channel] WebSocket server listening on port ${config.wsPort}`);
  });

  wss.on('connection', (ws: WebSocket, req) => {
    const clientId = `client-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    log.debug?.('[obsidian-channel] New connection', { clientId, url: req.url });

    let sessionInfo: SessionInfo | null = null;

    ws.on('message', async (data: Buffer) => {
      try {
        const message: WSMessage = JSON.parse(data.toString());
        
        // Handle authentication
        if (message.type === 'auth') {
          const isValid = validateToken(message.payload?.token, config.authToken);
          
          if (!isValid) {
            ws.send(JSON.stringify({ type: 'error', payload: { message: 'Invalid token' } }));
            ws.close();
            return;
          }

          // Server-generated sessionId (never trust client)
          sessionInfo = {
            sessionId: clientId,
            agentId: message.payload?.agentId || 'main',
            wsClient: ws,
            authenticated: true,
          };

          activeSessions.set(sessionInfo.sessionId, sessionInfo);
          
          ws.send(JSON.stringify({ 
            type: 'auth', 
            payload: { success: true, sessionId: sessionInfo.sessionId } 
          }));
          
          log.info('[obsidian-channel] Client authenticated', { 
            sessionId: sessionInfo.sessionId,
            agentId: sessionInfo.agentId
          });
          return;
        }

        // Require authentication for other messages
        if (!sessionInfo?.authenticated) {
          ws.send(JSON.stringify({ type: 'error', payload: { message: 'Not authenticated' } }));
          return;
        }

        // Handle other message types
        await handleMessage(message, sessionInfo);

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
}

async function handleMessage(message: WSMessage, sessionInfo: SessionInfo) {
  const runtime = getObsidianRuntime();
  const log = runtime.logging.getChildLogger({ plugin: "openclaw-channel-obsidian", component: "ws" });

  switch (message.type) {
    case 'message':
      // Route message to agent session
      // TODO: implement routing to OpenClaw session
      log.debug?.('[obsidian-channel] Message from client', {
        sessionId: sessionInfo.sessionId,
        agentId: sessionInfo.agentId,
        messagePreview: message.payload?.message?.substring(0, 100),
      });
      
      // For now, echo back
      sessionInfo.wsClient.send(JSON.stringify({
        type: 'message',
        payload: {
          content: `Echo: ${message.payload?.message}`,
          timestamp: Date.now(),
        },
      }));
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

export function stopWebSocketService() {
  if (wsServer) {
    wsServer.close();
    wsServer = null;
    activeSessions.clear();
  }
}
