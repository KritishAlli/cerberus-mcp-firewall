/**
 * OWNER: Aarav — the enforcement path (design doc §5, §6.3–6.5).
 *
 * SCAFFOLD STUB: the dependency shape is fixed here so the three modules
 * can be wired together and tested with fakes. The body is not implemented.
 *
 * TODO(Aarav), in this order, for each tools/call:
 *   1. validate name + argument shape → ToolCallContext (ToolCallContextSchema)
 *   2. decision = deps.evaluate(ctx, deps.policy)
 *        - if evaluate throws → DENY with ruleId EVALUATION_ERROR (fail closed)
 *   3. build a FirewallEvent and call deps.publish(event) inside try/catch
 *        - publishing can never change the decision
 *   4. ALLOW → return await deps.forward(toolName, args) (result unchanged)
 *      DENY  → return a recognizable MCP-compatible rejection; forward is NOT called
 *   5. timeouts / downstream failure → clear error, never an implicit ALLOW
 *   No secrets in error strings.
 */
import type { CallToolResult } from '@modelcontextprotocol/server';
import type { EvaluateToolCall, FirewallPolicy, PublishEvent } from '../shared/contracts.js';

export interface InterceptorDeps {
  serverId: string;
  policy: FirewallPolicy;
  evaluate: EvaluateToolCall;
  publish: PublishEvent;
  /** Calls the downstream server. Must be invoked ONLY for ALLOW decisions. */
  forward: (toolName: string, args: Record<string, unknown>) => Promise<CallToolResult>;
}

export type ToolCallHandler = (toolName: string, rawArgs: unknown) => Promise<CallToolResult>;

export function createInterceptor(_deps: InterceptorDeps): ToolCallHandler {
  throw new Error('createInterceptor: not implemented yet (Aarav)');
}
