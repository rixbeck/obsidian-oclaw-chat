/**
 * Runtime reference storage for Obsidian channel plugin
 */

import type { OpenClawRuntime } from "openclaw/plugin-sdk";

let runtime: OpenClawRuntime | null = null;

export function setObsidianRuntime(rt: OpenClawRuntime): void {
  runtime = rt;
}

export function getObsidianRuntime(): OpenClawRuntime {
  if (!runtime) {
    throw new Error("Obsidian runtime not initialized");
  }
  return runtime;
}
