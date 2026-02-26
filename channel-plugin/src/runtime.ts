/**
 * Runtime reference storage for Obsidian channel plugin
 */

import type { PluginRuntime } from "openclaw/plugin-sdk";

let runtime: PluginRuntime | null = null;

export function setObsidianRuntime(rt: PluginRuntime): void {
  runtime = rt;
}

export function getObsidianRuntime(): PluginRuntime {
  if (!runtime) {
    throw new Error("Obsidian runtime not initialized");
  }
  return runtime;
}
