/** Pure, synchronous policy evaluation. No I/O, logging, or MCP dependencies. */
import { FirewallPolicySchema, ToolCallContextSchema, type EvaluateToolCall, type PolicyDecision } from '../shared/contracts.js';
import { matchApprovedTool, matchDeniedDestination, matchDeniedTool, matchDestructiveAction, matchProtectedPath } from './rules.js';

const invalid: PolicyDecision = { decision: 'DENY', ruleId: 'INVALID_ARGUMENTS', reason: 'Request or policy has an invalid shape' };

/** Names that imply access, mutation, execution, or data transfer need explicit approval. */
const sensitiveOperationTokens = new Set([
  'read', 'write', 'delete', 'remove', 'send', 'upload', 'post', 'fetch', 'download',
  'exec', 'execute', 'shell', 'command', 'move', 'copy', 'chmod', 'permission',
  'credential', 'credentials', 'secret', 'secrets', 'auth', 'token', 'database', 'sql',
]);

function hasSensitiveOperationName(toolName: string): boolean {
  // Split camelCase and punctuation into whole tokens; avoid substring matches such as
  // `address` accidentally matching `read` or `remove_preview` matching `move`.
  const tokens = toolName.replace(/([a-z0-9])([A-Z])/g, '$1 $2').toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
  return tokens.some(token => sensitiveOperationTokens.has(token));
}

export const evaluateToolCall: EvaluateToolCall = (request, policy) => {
  const checkedRequest = ToolCallContextSchema.safeParse(request);
  const checkedPolicy = FirewallPolicySchema.safeParse(policy);
  if (!checkedRequest.success || !checkedPolicy.success) return invalid;
  const context = checkedRequest.data;
  const rules = [
    matchDeniedTool(context, checkedPolicy.data),
    matchProtectedPath(context, checkedPolicy.data),
    matchDeniedDestination(context, checkedPolicy.data),
    matchDestructiveAction(context, checkedPolicy.data),
    matchApprovedTool(context, checkedPolicy.data),
  ];
  for (const result of rules) if (result) return result;
  if (hasSensitiveOperationName(context.toolName)) {
    return { decision: 'DENY', ruleId: 'DEFAULT_DENY', reason: 'Sensitive tool requires explicit approval' };
  }
  if (checkedPolicy.data.defaultDecision === 'DENY') {
    return { decision: 'DENY', ruleId: 'DEFAULT_DENY', reason: 'No policy rule approved this tool call' };
  }
  return { decision: 'ALLOW', ruleId: 'APPROVED_TOOL', reason: 'Allowed by the configured default policy' };
};
