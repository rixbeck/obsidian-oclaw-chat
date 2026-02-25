/**
 * Session routing and message dispatch
 */

import type { PluginContext, SessionInfo, WSMessage, InboundMessage } from './types.js';

export async function routeToSession(
  message: WSMessage,
  sessionInfo: SessionInfo,
  ctx: PluginContext
) {
  const { log, runtime } = ctx;

  if (!message.payload) {
    log.warn('[obsidian-channel] Message missing payload');
    return;
  }

  const inboundMessage: InboundMessage = {
    sessionId: sessionInfo.sessionId,
    agentId: sessionInfo.agentId,
    message: message.payload.message || message.payload.text || '',
    context: message.payload.context,
  };

  log.debug('[obsidian-channel] Routing message to agent', {
    sessionId: inboundMessage.sessionId,
    agentId: inboundMessage.agentId,
    messagePreview: inboundMessage.message.substring(0, 100),
  });

  // Note: Following knowledge base pattern - we use runtime APIs, not internal imports
  // The exact API for dispatching to an agent session will depend on OpenClaw's runtime
  // For now, this is a placeholder that logs the intent
  
  if (runtime.dispatchToAgent) {
    await runtime.dispatchToAgent(inboundMessage.agentId, {
      channel: 'obsidian',
      sessionId: inboundMessage.sessionId,
      message: inboundMessage.message,
      context: inboundMessage.context,
    });
  } else {
    log.warn('[obsidian-channel] runtime.dispatchToAgent not available — message dropped', {
      sessionId: inboundMessage.sessionId,
    });
    sessionInfo.wsClient.send(JSON.stringify({
      type: 'error',
      payload: { message: 'Agent dispatch unavailable — please check channel plugin configuration' },
    }));
  }
}
