/**
 * Obsidian Channel Plugin
 */

import type { ChannelPlugin } from "openclaw/plugin-sdk";
import { getObsidianRuntime } from "./runtime.js";
import { startWebSocketService } from "./service.js";

export const obsidianChannelPlugin: ChannelPlugin = {
  id: "obsidian",
  
  meta: {
    id: "obsidian",
    name: "Obsidian",
    description: "Bidirectional communication with Obsidian vault via WebSocket",
  },
  
  capabilities: {
    chatTypes: ["direct"],
    reactions: false,
    threads: false,
    media: false,
    polls: false,
    nativeCommands: false,
    blockStreaming: false,
  },
  
  config: {
    // List account IDs (for us: just "default")
    listAccountIds: () => ["default"],
    
    // Resolve account config
    resolveAccount: (cfg, accountId) => {
      const obsidianCfg = cfg.channels?.obsidian;
      if (!obsidianCfg) {
        throw new Error("Obsidian channel not configured");
      }
      
      return {
        accountId: accountId ?? "default",
        enabled: obsidianCfg.enabled !== false,
        config: obsidianCfg,
      };
    },
    
    // Default account ID
    defaultAccountId: () => "default",
    
    // Set account enabled (no-op for single account)
    setAccountEnabled: () => {},
    
    // Delete account (no-op for single account)
    deleteAccount: () => {},
  },
  
  // Setup hook: start WebSocket server
  setup: {
    async gatewayStart(ctx) {
      const runtime = getObsidianRuntime();
      const cfg = ctx.config?.channels?.obsidian;
      
      if (!cfg?.enabled) {
        runtime.log.info("[obsidian-channel] Channel disabled, skipping setup");
        return;
      }
      
      if (!cfg.authToken) {
        runtime.log.error("[obsidian-channel] authToken required but not configured");
        throw new Error("Obsidian channel: authToken required");
      }
      
      runtime.log.info("[obsidian-channel] Starting WebSocket service", {
        wsPort: cfg.wsPort,
      });
      
      // Start WebSocket server
      startWebSocketService({
        wsPort: cfg.wsPort ?? 8765,
        authToken: cfg.authToken,
        accounts: cfg.accounts ?? ["main"],
      });
      
      runtime.log.info("[obsidian-channel] WebSocket service started successfully");
    },
    
    async gatewayStop(ctx) {
      const runtime = getObsidianRuntime();
      runtime.log.info("[obsidian-channel] Stopping WebSocket service");
      // TODO: implement graceful shutdown if needed
    },
  },
  
  // Reload config when channels.obsidian changes
  reload: {
    configPrefixes: ["channels.obsidian"],
  },
};
