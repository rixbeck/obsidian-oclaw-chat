/**
 * OpenClaw Channel Plugin: Obsidian
 * 
 * Provides bidirectional communication between OpenClaw agents and Obsidian
 * via WebSocket and RPC methods.
 */

import type { OpenClawPluginApi, OpenClawPluginService } from "openclaw/plugin-sdk";
import { emptyPluginConfigSchema } from "openclaw/plugin-sdk";
import { obsidianChannelPlugin } from "./channel.js";
import { setObsidianRuntime } from "./runtime.js";
import { startWebSocketService, stopWebSocketService } from "./service.js";

const plugin: any = {
  id: "openclaw-channel-obsidian",
  name: "Obsidian Channel",
  description: "Bidirectional communication channel for Obsidian (WebSocket + RPC)",
  configSchema: emptyPluginConfigSchema(),
  register(api: OpenClawPluginApi) {
    setObsidianRuntime(api.runtime);

    // Register channel
    api.registerChannel({ plugin: obsidianChannelPlugin });

    // Register a gateway service to start/stop the WebSocket server
    const svc: OpenClawPluginService = {
      id: "obsidian-ws",
      start: () => {
        const cfg: any = api.config?.channels?.obsidian;
        if (!cfg?.enabled) return;
        if (!cfg.authToken) {
          throw new Error("Obsidian channel: channels.obsidian.authToken is required");
        }
        startWebSocketService(
          {
            wsPort: cfg.wsPort ?? 8765,
            authToken: cfg.authToken,
            accounts: cfg.accounts ?? ["main"],
          },
          api.logger,
        );
      },
      stop: () => {
        stopWebSocketService();
      },
    };

    api.registerService(svc);
  },
};

export default plugin;
