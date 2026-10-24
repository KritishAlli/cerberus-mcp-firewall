import type { FirewallPolicy, PolicyDecision, ToolCallContext } from '../shared/contracts.js';
import { toCanonicalToolName } from '../shared/contracts.js';
import {
  destinationAllowed,
  destinationMatches,
  extractPathReferences,
  extractUrlReferences,
  isPlainRecord,
  normalizeDestination,
  pathMatches,
  pathWithinRoots,
} from './normalize.js';
import { containsSecretPattern } from './secrets.js';

const deny = (ruleId: PolicyDecision['ruleId'], reason: string): PolicyDecision => ({ decision: 'DENY', ruleId, reason });
const allow = (reason: string): PolicyDecision => ({ decision: 'ALLOW', ruleId: 'APPROVED_TOOL', reason });

interface ArgumentString {
  value: string;
  isPathArgument: boolean;
  isDestinationArgument: boolean;
}

function collectStrings(
  value: unknown,
  pathNames: Set<string>,
  destinationNames: Set<string>,
  output: ArgumentString[],
  inheritedPath = false,
  inheritedDestination = false,
): boolean {
  if (typeof value === 'string') {
    output.push({ value, isPathArgument: inheritedPath, isDestinationArgument: inheritedDestination });
    return true;
  }
  if (Array.isArray(value)) {
    return value.every((item) => collectStrings(item, pathNames, destinationNames, output, inheritedPath, inheritedDestination));
  }
  if (isPlainRecord(value)) {
    let valid = true;
    for (const [key, item] of Object.entries(value)) {
      const isPath = inheritedPath || pathNames.has(key);
      const isDestination = inheritedDestination || destinationNames.has(key);
      if (!collectStrings(item, pathNames, destinationNames, output, isPath, isDestination)) valid = false;
    }
    return valid;
  }
  return !inheritedPath && !inheritedDestination;
}

function argumentStrings(request: ToolCallContext, policy: FirewallPolicy): { values: ArgumentString[]; valid: boolean } {
  const canonical = toCanonicalToolName(request.serverId, request.toolName);
  const values: ArgumentString[] = [];
  const valid = collectStrings(
    request.arguments,
    new Set(policy.pathArgs),
    new Set(policy.destinationArgs[canonical] ?? []),
    values,
  );
  return { values, valid };
}

const sensitiveNameTokens = new Set([
  'read', 'write', 'edit', 'create', 'delete', 'remove', 'send', 'upload', 'post', 'fetch', 'download',
  'exec', 'execute', 'shell', 'command', 'move', 'copy', 'chmod', 'permission', 'credential', 'credentials',
  'secret', 'secrets', 'auth', 'token', 'database', 'sql',
]);
const writeNameTokens = new Set(['write', 'edit', 'create', 'delete', 'remove', 'move', 'copy', 'patch', 'mkdir', 'chmod', 'save', 'put', 'run', 'exec', 'execute', 'shell', 'command']);
const networkNameTokens = new Set(['send', 'upload', 'post', 'fetch', 'download', 'request', 'http', 'https', 'network', 'browse', 'run', 'exec', 'execute', 'shell', 'command']);

function nameTokens(toolName: string): Set<string> {
  return new Set(toolName.replace(/([a-z0-9])([A-Z])/g, '$1 $2').toLowerCase().split(/[^a-z0-9]+/).filter(Boolean));
}

function isWriteTool(request: ToolCallContext, policy: FirewallPolicy): boolean {
  const canonical = toCanonicalToolName(request.serverId, request.toolName);
  const tokens = nameTokens(request.toolName);
  return policy.writeTools.includes(canonical) || [...tokens].some((token) => writeNameTokens.has(token));
}

function isNetworkTool(request: ToolCallContext, policy: FirewallPolicy, values: ArgumentString[]): boolean {
  const canonical = toCanonicalToolName(request.serverId, request.toolName);
  const tokens = nameTokens(request.toolName);
  return Object.hasOwn(policy.destinationArgs, canonical)
    || [...tokens].some((token) => networkNameTokens.has(token))
    || values.some((item) => extractUrlReferences(item.value).length > 0);
}

export function isSensitiveToolName(toolName: string): boolean {
  return [...nameTokens(toolName)].some((token) => sensitiveNameTokens.has(token));
}

export function matchDeniedTool(request: ToolCallContext, policy: FirewallPolicy): PolicyDecision | undefined {
  const canonical = toCanonicalToolName(request.serverId, request.toolName);
  return policy.deniedTools.includes(canonical) ? deny('DENIED_TOOL', 'Tool is explicitly denied by policy') : undefined;
}

function pathCandidates(item: ArgumentString): string[] {
  const fileUrls = extractUrlReferences(item.value).filter((ref) => ref.value.toLowerCase().startsWith('file://'));
  if (fileUrls.length > 0) {
    return fileUrls.flatMap((ref) => {
      try { return [decodeURIComponent(new URL(ref.value).pathname)]; }
      catch { return []; }
    });
  }
  if (item.isPathArgument) return [item.value];
  return extractPathReferences(item.value);
}

export function matchProtectedPath(request: ToolCallContext, policy: FirewallPolicy): PolicyDecision | undefined {
  const { values, valid } = argumentStrings(request, policy);
  if (!valid) return deny('INVALID_ARGUMENTS', 'A configured path or destination argument must contain strings');
  for (const item of values) {
    for (const candidate of pathCandidates(item)) {
      if (policy.protectedPaths.some((pattern) => pathMatches(candidate, pattern))) {
        return deny('PROTECTED_PATH', 'Requested path is protected by policy');
      }
    }
  }
  return undefined;
}

export function matchAllowedRoot(request: ToolCallContext, policy: FirewallPolicy): PolicyDecision | undefined {
  const { values, valid } = argumentStrings(request, policy);
  if (!valid) return deny('INVALID_ARGUMENTS', 'A configured path or destination argument must contain strings');
  for (const item of values) {
    for (const ref of extractUrlReferences(item.value).filter((r) => r.value.toLowerCase().startsWith('file://'))) {
      try {
        const host = new URL(ref.value).hostname.toLowerCase();
        if (host !== '' && host !== 'localhost') {
          return deny('PATH_NOT_ALLOWED', 'Remote file URLs are outside the configured local roots');
        }
      } catch {
        return deny('INVALID_ARGUMENTS', 'File URL is malformed');
      }
    }
    for (const candidate of pathCandidates(item)) {
      if (!pathWithinRoots(candidate, policy.allowedRoots)) {
        return deny('PATH_NOT_ALLOWED', 'Path is outside the configured allowed roots');
      }
    }
    // file:// references are paths, not network destinations.
    for (const ref of extractUrlReferences(item.value).filter((r) => r.value.toLowerCase().startsWith('file://'))) {
      let pathname: string;
      try { pathname = decodeURIComponent(new URL(ref.value).pathname); }
      catch { return deny('INVALID_ARGUMENTS', 'File URL is malformed'); }
      if (policy.protectedPaths.some((pattern) => pathMatches(pathname, pattern))) {
        return deny('PROTECTED_PATH', 'Requested path is protected by policy');
      }
      if (!pathWithinRoots(pathname, policy.allowedRoots)) {
        return deny('PATH_NOT_ALLOWED', 'Path is outside the configured allowed roots');
      }
    }
  }
  return undefined;
}

export function matchDeniedDestination(request: ToolCallContext, policy: FirewallPolicy): PolicyDecision | undefined {
  const { values, valid } = argumentStrings(request, policy);
  if (!valid) return deny('INVALID_ARGUMENTS', 'A configured path or destination argument must contain strings');
  const canonical = toCanonicalToolName(request.serverId, request.toolName);
  const configuredDestinationTool = Object.hasOwn(policy.destinationArgs, canonical);
  const destinations: string[] = [];
  for (const item of values) {
    if (item.isDestinationArgument) {
      if (!item.value.trim()) return deny('INVALID_ARGUMENTS', 'A configured destination argument is empty');
      const refs = extractUrlReferences(item.value);
      if (refs.length > 0) destinations.push(...refs.map((r) => r.value));
      else destinations.push(item.value.trim());
    } else {
      destinations.push(...extractUrlReferences(item.value).map((r) => r.value));
    }
  }
  if (configuredDestinationTool && destinations.length === 0) {
    return deny('INVALID_ARGUMENTS', 'A configured destination argument is missing or malformed');
  }
  if (isNetworkTool(request, policy, values) && destinations.length === 0) {
    return deny('INVALID_ARGUMENTS', 'A network tool must provide a destination that can be checked');
  }
  for (const raw of destinations) {
    if (raw.toLowerCase().startsWith('file://')) continue;
    const destination = normalizeDestination(raw, true);
    if (destination.malformed) return deny('INVALID_ARGUMENTS', 'Destination URL is malformed or uses an unsupported scheme');
    if (policy.deniedDestinations.some((pattern) => destinationMatches(destination, pattern))) {
      return deny('DENIED_DESTINATION', 'Destination is denied by policy');
    }
    if (!destinationAllowed(destination, policy.allowedHosts)) {
      return deny('HOST_NOT_ALLOWED', 'Destination host is outside the configured allowed hosts');
    }
  }
  return undefined;
}

export function matchTaintedSession(request: ToolCallContext, policy: FirewallPolicy): PolicyDecision | undefined {
  if (!request.session.tainted) return undefined;
  const { values } = argumentStrings(request, policy);
  if (isWriteTool(request, policy) || isNetworkTool(request, policy, values)) {
    return deny('SESSION_TAINTED', 'Write and network tools are blocked for a tainted session');
  }
  return undefined;
}

export function matchArgumentSecrets(request: ToolCallContext, policy: FirewallPolicy): PolicyDecision | undefined {
  const { values, valid } = argumentStrings(request, policy);
  if (!valid) return deny('INVALID_ARGUMENTS', 'Tool arguments are invalid');
  if (!isWriteTool(request, policy) && !isNetworkTool(request, policy, values)) return undefined;
  return values.some((item) => containsSecretPattern(item.value))
    ? deny('SECRET_DETECTED', 'Sensitive credential material in write or network arguments is blocked')
    : undefined;
}

export function matchDestructiveAction(request: ToolCallContext, policy: FirewallPolicy): PolicyDecision | undefined {
  const key = toCanonicalToolName(request.serverId, request.toolName);
  return policy.destructiveTools.includes(key) ? deny('DESTRUCTIVE_ACTION', 'Destructive operation is disabled by policy') : undefined;
}

export function matchApprovedTool(request: ToolCallContext, policy: FirewallPolicy): PolicyDecision | undefined {
  const key = toCanonicalToolName(request.serverId, request.toolName);
  return policy.approvedTools.includes(key) ? allow('Tool is explicitly approved by policy') : undefined;
}
