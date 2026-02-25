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

const plugin = {
  id: "openclaw-channel-obsidian",
  name: "Obsidian Channel",
  description: "Bidirectional communication channel for Obsidian (WebSocket + RPC)",
  configSchema: emptyPluginConfigSchema(),
  register(api: OpenClawPluginApi) {
    setObsidianRuntime(api.runtime);
    api.registerChannel({ plugin: obsidianChannelPlugin });
  },
};

export default plugin;
