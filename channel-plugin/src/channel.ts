/**
 * Channel registration and metadata
 */

import type { PluginContext } from './types.js';
import { sendMessage, broadcastMessage } from './rpc.js';

export function registerObsidianChannel(ctx: PluginContext) {
  const { log, runtime } = ctx;

  // Note: Following the pattern from knowledge base - we DON'T import internal
  // core modules (ERR_PACKAGE_PATH_NOT_EXPORTED). Instead, we use runtime APIs.
  
  // Check if runtime has a channel registration API
  if (!runtime.registerChannel) {
    log.warn('[obsidian-channel] runtime.registerChannel not available - channel registration may need alternative approach');
    return;
  }

  const channelMeta = {
    id: 'obsidian',
    name: 'Obsidian',
    description: 'Bidirectional communication with Obsidian vault',
    capabilities: ['send', 'receive', 'push'],
    version: '0.1.0',
  };

  runtime.registerChannel(channelMeta, {
    // Outbound handler: agent wants to send message to Obsidian
    async sendMessage(message: string, options: any) {
      log.debug('[obsidian-channel] sendMessage called', { options });
      const sessionId: string | undefined = options?.sessionId;
      if (sessionId) {
        return await sendMessage(sessionId, message, ctx);
      }
      // No sessionId → broadcast to all authenticated sessions
      await broadcastMessage(message, ctx);
      return { success: true, channel: 'obsidian' };
    },

    // Get channel status
    async getStatus() {
      return {
        connected: true, // Will be dynamic once WS is implemented
        clients: 0,
      };
    },
  });

  log.info('[obsidian-channel] Channel registered', channelMeta);
}
