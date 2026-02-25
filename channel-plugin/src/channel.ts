/**
 * Obsidian Channel Plugin
 */

import type { ChannelPlugin, OpenClawConfig } from "openclaw/plugin-sdk";

export const obsidianChannelPlugin: ChannelPlugin = {
  id: "obsidian",
  
  meta: {
    id: "obsidian",
    label: "Obsidian",
    selectionLabel: "Obsidian",
    docsPath: "/channels/obsidian",
    blurb: "Bidirectional communication with Obsidian vault via WebSocket",
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
    resolveAccount: (cfg: OpenClawConfig, accountId?: string | null) => {
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
    
    // Set account enabled
    setAccountEnabled: (params: { cfg: OpenClawConfig; accountId: string; enabled: boolean }) => {
      // No-op for single account channel
      return params.cfg;
    },
    
    // Delete account
    deleteAccount: (params: { cfg: OpenClawConfig; accountId: string }) => {
      // No-op for single account channel
      return params.cfg;
    },
  },
  
  // Reload config when channels.obsidian changes
  reload: {
    configPrefixes: ["channels.obsidian"],
  },
};
