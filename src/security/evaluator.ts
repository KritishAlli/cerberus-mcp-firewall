/** Pure, synchronous policy evaluation. No I/O, logging, or MCP dependencies. */
import { FirewallPolicySchema, ToolCallContextSchema, type EvaluateToolCall, type PolicyDecision } from '../shared/contracts.js';
import {
  isSensitiveToolName,
  matchAllowedRoot,
  matchApprovedTool,
  matchArgumentSecrets,
  matchDeniedDestination,
  matchDeniedTool,
  matchDestructiveAction,
  matchProtectedPath,
  matchTaintedSession,
} from './rules.js';

const invalid: PolicyDecision = { decision: 'DENY', ruleId: 'INVALID_ARGUMENTS', reason: 'Request or policy has an invalid shape' };

export const evaluateToolCall: EvaluateToolCall = (request, policy) => {
  const checkedRequest = ToolCallContextSchema.safeParse(request);
  const checkedPolicy = FirewallPolicySchema.safeParse(policy);
  if (!checkedRequest.success || !checkedPolicy.success) return invalid;
  const context = checkedRequest.data;
  const rules = [
    matchDeniedTool(context, checkedPolicy.data),
    matchTaintedSession(context, checkedPolicy.data),
    matchProtectedPath(context, checkedPolicy.data),
    matchAllowedRoot(context, checkedPolicy.data),
    matchDeniedDestination(context, checkedPolicy.data),
    matchArgumentSecrets(context, checkedPolicy.data),
    matchDestructiveAction(context, checkedPolicy.data),
    matchApprovedTool(context, checkedPolicy.data),
  ];
  for (const result of rules) if (result) return result;
  if (isSensitiveToolName(context.toolName)) {
    return { decision: 'DENY', ruleId: 'DEFAULT_DENY', reason: 'Sensitive tool requires explicit approval' };
  }
  if (checkedPolicy.data.defaultDecision === 'DENY') {
    return { decision: 'DENY', ruleId: 'DEFAULT_DENY', reason: 'No policy rule approved this tool call' };
  }
  return { decision: 'ALLOW', ruleId: 'APPROVED_TOOL', reason: 'Allowed by the configured default policy' };
};
