/**
 * OpenClaw Channel Plugin: Obsidian
 * 
 * Provides bidirectional communication between OpenClaw agents and Obsidian
 * via Gateway WebSocket and RPC methods.
 */

import type { OpenClawPluginApi } from "openclaw/plugin-sdk";
import { emptyPluginConfigSchema } from "openclaw/plugin-sdk";
import { obsidianChannelPlugin } from "./channel.js";
import { setObsidianRuntime } from "./runtime.js";
import {
  setBroadcastFunction,
  createSubscribeHandler,
  createUnsubscribeHandler,
  createSendHandler,
  pushToSubscribedClients,
  cleanupConnection,
} from "./gateway.js";

const plugin: any = {
  id: "openclaw-channel-obsidian",
  name: "Obsidian Channel",
  description: "Bidirectional communication channel for Obsidian (Gateway WebSocket + RPC)",
  configSchema: emptyPluginConfigSchema(),
  register(api: OpenClawPluginApi) {
    setObsidianRuntime(api.runtime);

    // Register channel
    api.registerChannel({ plugin: obsidianChannelPlugin });

    // Get config
    const cfg: any = api.config?.channels?.obsidian;
    if (!cfg?.enabled) {
      api.logger.info?.("[obsidian] Channel disabled in config");
      return;
    }

    const gatewayConfig = {
      accounts: cfg.accounts ?? ["main"],
    };

    // Note: Broadcast function will be captured from context in subscribe handler

    // Register gateway methods
    api.registerGatewayMethod(
      "obsidian.subscribe",
      createSubscribeHandler(gatewayConfig, api.logger)
    );

    api.registerGatewayMethod(
      "obsidian.unsubscribe",
      createUnsubscribeHandler(api.logger)
    );

    api.registerGatewayMethod(
      "obsidian.send",
      createSendHandler(api.logger)
    );

    // Register hook: push assistant messages to subscribed clients
    api.on("before_message_write", (event, ctx) => {
      // Only push assistant messages
      if (event.message?.role !== "assistant") {
        return;
      }

      // Extract text content
      const content = Array.isArray(event.message.content)
        ? event.message.content
            .filter((c: any) => c.type === "text")
            .map((c: any) => c.text)
            .join("\n")
        : typeof event.message.content === "string"
          ? event.message.content
          : "";

      if (!content) {
        return;
      }

      // Push to subscribed clients for this sessionKey
      const sessionKey = ctx?.sessionKey || event.sessionKey;
      if (sessionKey) {
        pushToSubscribedClients(
          sessionKey,
          {
            role: "assistant",
            content,
          },
          api.logger
        );
      }
    });

    // Note: Connection cleanup will be handled via periodic TTL check or manual unsubscribe

    api.logger.info?.("[obsidian] Gateway methods registered (subscribe, send, unsubscribe)");
  },
};

export default plugin;
