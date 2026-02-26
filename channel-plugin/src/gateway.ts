/**
 * Gateway methods for Obsidian integration
 * 
 * Provides session-scoped subscription and messaging via OpenClaw Gateway WebSocket.
 */

import type { GatewayRequestHandlerOptions } from "openclaw/plugin-sdk";

interface SubscriptionInfo {
  subscriptionId: string;
  sessionKey: string;
  accountId: string;
  connectionId: string;
  createdAt: number;
}

interface ObsidianGatewayConfig {
  accounts: string[];
}

type Logger = {
  debug?: (message: string, meta?: any) => void;
  info?: (message: string, meta?: any) => void;
  warn?: (message: string, meta?: any) => void;
  error?: (message: string, meta?: any) => void;
};

// Store active subscriptions: subscriptionId -> SubscriptionInfo
const subscriptions = new Map<string, SubscriptionInfo>();

// Gateway broadcast function type (from OpenClaw SDK)
type GatewayBroadcastToConnIdsFn = (
  event: string,
  payload: unknown,
  connIds: ReadonlySet<string>,
  opts?: any
) => void;

// Store broadcast function (set by plugin registration)
let broadcastToConnIds: GatewayBroadcastToConnIdsFn | null = null;

export function setBroadcastFunction(fn: GatewayBroadcastToConnIdsFn) {
  broadcastToConnIds = fn;
}

export function createSubscribeHandler(config: ObsidianGatewayConfig, logger: Logger) {
  return async ({ params, client, context, respond }: GatewayRequestHandlerOptions) => {
    try {
      // Capture broadcast function on first call
      if (!broadcastToConnIds && context.broadcastToConnIds) {
        setBroadcastFunction(context.broadcastToConnIds);
      }
      // Auth is handled by Gateway connect handshake; no per-channel token needed.

      // Extract parameters
      const sessionKey = typeof params?.sessionKey === "string" ? params.sessionKey : "";
      const accountId = typeof params?.accountId === "string" ? params.accountId : "main";

      if (!sessionKey) {
        respond(false, { error: "sessionKey required" });
        return;
      }

      // Check account allowlist
      if (!config.accounts.includes(accountId)) {
        respond(false, { error: `Account ${accountId} not allowed` });
        return;
      }

      // Generate subscription ID
      const subscriptionId = `obsidian-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;

      // Store subscription with connection ID from client
      const connectionId = client?.connId || "";
      if (!connectionId) {
        respond(false, { error: "Connection ID not available" });
        return;
      }

      const subscription: SubscriptionInfo = {
        subscriptionId,
        sessionKey,
        accountId,
        connectionId,
        createdAt: Date.now(),
      };

      subscriptions.set(subscriptionId, subscription);

      logger.info?.("[obsidian-gateway] Client subscribed", {
        subscriptionId,
        sessionKey,
        accountId,
        connectionId,
      });

      respond(true, {
        subscriptionId,
        sessionKey,
        accountId,
      });
    } catch (err) {
      logger.error?.("[obsidian-gateway] Subscribe error", { error: err });
      respond(false, { error: err instanceof Error ? err.message : String(err) });
    }
  };
}

export function createUnsubscribeHandler(logger: Logger) {
  return async ({ params, respond }: GatewayRequestHandlerOptions) => {
    try {
      const subscriptionId = typeof params?.subscriptionId === "string" ? params.subscriptionId : "";

      if (!subscriptionId) {
        respond(false, { error: "subscriptionId required" });
        return;
      }

      const subscription = subscriptions.get(subscriptionId);
      if (!subscription) {
        respond(false, { error: "Subscription not found" });
        return;
      }

      subscriptions.delete(subscriptionId);

      logger.info?.("[obsidian-gateway] Client unsubscribed", { subscriptionId });

      respond(true, { success: true });
    } catch (err) {
      logger.error?.("[obsidian-gateway] Unsubscribe error", { error: err });
      respond(false, { error: err instanceof Error ? err.message : String(err) });
    }
  };
}

export function createSendHandler(logger: Logger) {
  return async ({ params, respond }: GatewayRequestHandlerOptions) => {
    try {
      const subscriptionId = typeof params?.subscriptionId === "string" ? params.subscriptionId : "";
      const message = typeof params?.message === "string" ? params.message : "";

      if (!subscriptionId || !message) {
        respond(false, { error: "subscriptionId and message required" });
        return;
      }

      const subscription = subscriptions.get(subscriptionId);
      if (!subscription) {
        respond(false, { error: "Subscription not found" });
        return;
      }

      logger.debug?.("[obsidian-gateway] Message from client", {
        subscriptionId,
        sessionKey: subscription.sessionKey,
        messagePreview: message.substring(0, 100),
      });

      // TODO: Route message to session (sessions_send or direct write)
      // For now, acknowledge receipt
      respond(true, {
        success: true,
        sessionKey: subscription.sessionKey,
        messageId: `${Date.now()}`,
      });
    } catch (err) {
      logger.error?.("[obsidian-gateway] Send error", { error: err });
      respond(false, { error: err instanceof Error ? err.message : String(err) });
    }
  };
}

/**
 * Push assistant message to subscribed Obsidian clients
 * Called from plugin hook (before_message_write)
 */
export function pushToSubscribedClients(
  sessionKey: string,
  message: { role: string; content: string },
  logger: Logger
) {
  if (!broadcastToConnIds) {
    logger.warn?.("[obsidian-gateway] Broadcast function not set, cannot push");
    return;
  }

  // Find all subscriptions for this sessionKey
  const targetSubscriptions = Array.from(subscriptions.values()).filter(
    (sub) => sub.sessionKey === sessionKey
  );

  if (targetSubscriptions.length === 0) {
    // No subscribers for this session, skip
    return;
  }

  // Extract connection IDs as Set
  const connectionIds = new Set(targetSubscriptions.map((sub) => sub.connectionId));

  // Prepare push payload
  const payload = {
    role: message.role,
    content: message.content,
    timestamp: Date.now(),
  };

  // Broadcast to all subscribed connections
  try {
    broadcastToConnIds("obsidian.message", payload, connectionIds);

    logger.debug?.("[obsidian-gateway] Pushed message to clients", {
      sessionKey,
      subscriptionCount: targetSubscriptions.length,
      connectionIds: Array.from(connectionIds),
    });
  } catch (err) {
    logger.error?.("[obsidian-gateway] Push error", { error: err });
  }
}

/**
 * Clean up subscriptions when connection closes
 */
export function cleanupConnection(connectionId: string, logger: Logger) {
  const removed: string[] = [];

  for (const [subId, sub] of subscriptions.entries()) {
    if (sub.connectionId === connectionId) {
      subscriptions.delete(subId);
      removed.push(subId);
    }
  }

  if (removed.length > 0) {
    logger.info?.("[obsidian-gateway] Cleaned up subscriptions for closed connection", {
      connectionId,
      subscriptionIds: removed,
    });
  }
}
