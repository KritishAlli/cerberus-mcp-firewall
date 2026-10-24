/**
 * OWNER: Winston — deterministic policy decision (design doc §5, §7).
 *
 * SCAFFOLD STUB: denies everything. A placeholder must fail closed; never
 * replace this with an allow-all stub, even temporarily.
 *
 * Precedence to implement (§7):
 *   1. invalid input / unknown sensitive tool     → DENY  INVALID_ARGUMENTS
 *   2. explicitly denied server/tool              → DENY  DENIED_TOOL
 *   3. protected resource (path)                  → DENY  PROTECTED_PATH
 *   4. forbidden destination                      → DENY  DENIED_DESTINATION
 *   5. destructive operation                      → DENY  DESTRUCTIVE_ACTION
 *   6. explicitly approved safe tool              → ALLOW APPROVED_TOOL
 *   7. otherwise policy.defaultDecision           →       DEFAULT_DENY (MVP)
 *
 * Rules: pure and synchronous; do not import proxy, observability or the MCP SDK.
 */
import type { EvaluateToolCall } from '../shared/contracts.js';

export const evaluateToolCall: EvaluateToolCall = (_request, _policy) => ({
  decision: 'DENY',
  ruleId: 'DEFAULT_DENY',
  reason: 'Policy evaluator not implemented yet; scaffold stub denies all calls',
});
