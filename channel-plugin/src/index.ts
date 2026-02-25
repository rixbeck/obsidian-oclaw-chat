/**
 * OpenClaw Channel Plugin: Obsidian
 * 
 * Provides bidirectional communication between OpenClaw agents and Obsidian
 * via WebSocket and RPC methods.
 */

import type { OpenClawPluginApi } from "openclaw/plugin-sdk";
import { emptyPluginConfigSchema } from "openclaw/plugin-sdk";
import { obsidianChannelPlugin } from "./channel.js";
import { setObsidianRuntime } from "./runtime.js";

const plugin: any = {
  id: "openclaw-channel-obsidian",
  name: "Obsidian Channel",
  description: "Bidirectional communication channel for Obsidian (WebSocket + RPC)",
  configSchema: emptyPluginConfigSchema(),
  register(api: OpenClawPluginApi) {
    // Store runtime reference for later use
    setObsidianRuntime(api.runtime);
    
    // Register channel with OpenClaw
    api.registerChannel({ plugin: obsidianChannelPlugin });
  },
};

export default plugin;
