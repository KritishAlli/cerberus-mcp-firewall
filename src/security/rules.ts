import type { FirewallPolicy, PolicyDecision, ToolCallContext } from '../shared/contracts.js';
import { toCanonicalToolName } from '../shared/contracts.js';
import { destinationMatches, isPlainRecord, normalizeDestination, pathMatches } from './normalize.js';

const deny = (ruleId: PolicyDecision['ruleId'], reason: string): PolicyDecision => ({ decision: 'DENY', ruleId, reason });
const allow = (reason: string): PolicyDecision => ({ decision: 'ALLOW', ruleId: 'APPROVED_TOOL', reason });

export function matchDeniedTool(request: ToolCallContext, policy: FirewallPolicy): PolicyDecision | undefined {
  const canonical = toCanonicalToolName(request.serverId, request.toolName);
  return policy.deniedTools.includes(canonical) ? deny('DENIED_TOOL', 'Tool is explicitly denied by policy') : undefined;
}

function collectNamedValues(value: unknown, names: Set<string>, output: unknown[]): void {
  if (Array.isArray(value)) { for (const item of value) collectNamedValues(item, names, output); return; }
  if (!isPlainRecord(value)) return;
  for (const [key, item] of Object.entries(value)) {
    if (names.has(key)) output.push(item);
    if (Array.isArray(item) || isPlainRecord(item)) collectNamedValues(item, names, output);
  }
}

export function matchProtectedPath(request: ToolCallContext, policy: FirewallPolicy): PolicyDecision | undefined {
  const paths: unknown[] = [];
  collectNamedValues(request.arguments, new Set(policy.pathArgs), paths);
  for (const value of paths) {
    if (typeof value !== 'string') return deny('INVALID_ARGUMENTS', 'A configured path argument must be a string');
    if (policy.protectedPaths.some(pattern => pathMatches(value, pattern))) return deny('PROTECTED_PATH', 'Requested path is protected by policy');
  }
  return undefined;
}

export function matchDeniedDestination(request: ToolCallContext, policy: FirewallPolicy): PolicyDecision | undefined {
  const key = toCanonicalToolName(request.serverId, request.toolName);
  const names = policy.destinationArgs[key];
  if (!names) return undefined;
  const values: unknown[] = [];
  collectNamedValues(request.arguments, new Set(names), values);
  if (values.length === 0) return deny('INVALID_ARGUMENTS', 'A configured destination argument is missing');
  for (const value of values) {
    if (typeof value !== 'string') return deny('INVALID_ARGUMENTS', 'A configured destination argument must be a string');
    const normalized = normalizeDestination(value);
    if (normalized.malformed) return deny('INVALID_ARGUMENTS', 'Destination URL is malformed or uses an unsupported scheme');
    if (policy.deniedDestinations.some(pattern => destinationMatches(normalized, pattern))) {
      return deny('DENIED_DESTINATION', 'Destination is denied by policy');
    }
  }
  return undefined;
}

export function matchDestructiveAction(request: ToolCallContext, policy: FirewallPolicy): PolicyDecision | undefined {
  const key = toCanonicalToolName(request.serverId, request.toolName);
  return policy.destructiveTools.includes(key) ? deny('DESTRUCTIVE_ACTION', 'Destructive operation is disabled by policy') : undefined;
}

export function matchApprovedTool(request: ToolCallContext, policy: FirewallPolicy): PolicyDecision | undefined {
  const key = toCanonicalToolName(request.serverId, request.toolName);
  return policy.approvedTools.includes(key) ? allow('Tool is explicitly approved by policy') : undefined;
}
