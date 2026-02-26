import type { AgentOption } from './types';

/** Canonical list of available OpenClaw agents */
export const AGENT_OPTIONS: AgentOption[] = [
  { id: 'main', label: 'main' },
  { id: 'senilla', label: 'senilla' },
];

/** Returns the agent option for a given id, or the first option as default */
export function getAgentById(id: string): AgentOption {
  return AGENT_OPTIONS.find((a) => a.id === id) ?? AGENT_OPTIONS[0];
}
