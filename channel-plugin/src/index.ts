/**
 * OpenClaw Channel Plugin: Obsidian
 * 
 * Provides bidirectional communication between OpenClaw agents and Obsidian
 * via WebSocket and RPC methods.
 */

import { registerObsidianChannel } from './channel.js';
import { startWebSocketService } from './service.js';
import { registerRPCMethods } from './rpc.js';

export function register(ctx: any) {
  const { log, config, runtime } = ctx;

  if (!config?.enabled) {
    log.info('[obsidian-channel] Plugin disabled via config');
    return;
  }

  try {
    // 1. Register the channel with OpenClaw
    registerObsidianChannel(ctx);

    // 2. Start WebSocket service
    startWebSocketService(ctx);

    // 3. Register RPC methods (obsidian.sendMessage, obsidian.listAccounts)
    registerRPCMethods(ctx);

    log.info('[obsidian-channel] Plugin registered successfully', {
      wsPort: config.wsPort,
      accounts: config.accounts,
    });
  } catch (error) {
    log.error('[obsidian-channel] Plugin registration failed', { error });
    throw error;
  }
}
