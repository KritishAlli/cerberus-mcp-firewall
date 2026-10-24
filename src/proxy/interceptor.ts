/**
 * OWNER: Aarav — the enforcement path (design doc §5, §6.3–6.5).
 *
 * For each tools/call, in this order:
 *   1. validate name + argument shape, clone + deep-freeze the arguments → ToolCallContext
 *   2. decision = deps.evaluate(ctx, deps.policy), validated with PolicyDecisionSchema
 *        - throws or returns garbage → DENY / EVALUATION_ERROR (fail closed)
 *   3. publish exactly one FirewallEvent (validated, inside try/catch; never changes the decision)
 *   4. ALLOW → return await deps.forward(...) unchanged (the only forward call site)
 *      anything else → BLOCKED tool error; forward is NOT called
 *   5. forward throws → DOWNSTREAM ERROR tool error with a fixed message, never an implicit ALLOW
 *   With deps.staging, step 4 runs inside runStagedCall (src/proxy/staged-call.ts): the
 *   server's file changes are diffed, evaluated and applied or reverted around the forward.
 *
 * Nothing here ever puts an argument value or a downstream error message into a
 * response, event or log line: both can echo secrets.
 */
import { randomUUID } from 'node:crypto';
import type { CallToolResult } from '@modelcontextprotocol/server';
import {
  FirewallEventSchema,
  LIMITS,
  PolicyDecisionSchema,
  ToolCallContextSchema,
  type EvaluateToolCall,
  type FirewallEvent,
  type FirewallPolicy,
  type PolicyDecision,
  type PublishEvent,
  type ToolCallContext,
} from '../shared/contracts.js';
import { runStagedCall, type StagingDeps } from './staged-call.js';

/** Start of the text of every DENY result. Stable: tests and the demo match on it. */
export const BLOCKED_PREFIX = '[MCP Firewall] BLOCKED';
/** Start of the text of every result where policy allowed the call but the downstream failed. */
export const DOWNSTREAM_ERROR_PREFIX = '[MCP Firewall] DOWNSTREAM ERROR';
/** Key under CallToolResult._meta carrying the machine-readable firewall decision. */
export const FIREWALL_META_KEY = 'mcp-firewall/decision';

export interface CallOptions {
  /** Cancellation from the agent (ctx.mcpReq.signal); passed through to forward. */
  signal?: AbortSignal;
}

export interface FirewallMeta {
  decision: PolicyDecision['decision'];
  ruleId: PolicyDecision['ruleId'];
  reason: string;
  requestId: string;
  /** Only on DOWNSTREAM ERROR results. */
  downstreamError?: DownstreamErrorKind;
}

export interface InterceptorDeps {
  serverId: string;
  policy: FirewallPolicy;
  evaluate: EvaluateToolCall;
  publish: PublishEvent;
  /** Calls the downstream server. Invoked ONLY for ALLOW decisions, with the evaluated (frozen) args. */
  forward: (toolName: string, args: Record<string, unknown>, options: CallOptions) => Promise<CallToolResult>;
  /** Diagnostics sink (one line, no trailing newline). Defaults to stderr. Never stdout. */
  log?: (line: string) => void;
  /** Correlation ID generator. Defaults to crypto.randomUUID. */
  newRequestId?: () => string;
  /** Clock in epoch milliseconds. Defaults to Date.now. */
  now?: () => number;
  /** Staged writes for a sandboxed server. Without it, allowed calls are forwarded as before. */
  staging?: StagingDeps;
}

/** toolName and rawArgs are untrusted and validated here, hence `unknown`. */
export type ToolCallHandler = (toolName: unknown, rawArgs: unknown, options?: CallOptions) => Promise<CallToolResult>;

type DownstreamErrorKind = 'timeout' | 'not_connected' | 'failed';

const MAX_SUMMARY_KEYS = 8;
const MAX_KEY_LENGTH = 32;
/** Nesting cap for argument values; also stops pathological inputs before the evaluator sees them. */
const MAX_ARG_DEPTH = 64;
const INVALID_TOOL_NAME = '<invalid>';

const DOWNSTREAM_MESSAGES: Record<DownstreamErrorKind, string> = {
  timeout: 'the tool server did not respond in time; the call may or may not have run',
  not_connected: 'the connection to the tool server is closed',
  failed: 'the tool server call failed',
};

const NOT_CONNECTED_CODES = new Set(['CONNECTION_CLOSED', 'NOT_CONNECTED', 'SEND_FAILED', 'UPSTREAM_UNAVAILABLE']);

export function createInterceptor(deps: InterceptorDeps): ToolCallHandler {
  const log = deps.log ?? ((line: string) => process.stderr.write(`${line}\n`));
  const newRequestId = deps.newRequestId ?? randomUUID;
  const now = deps.now ?? Date.now;

  return async (toolName, rawArgs, options = {}) => {
    const startedAt = now();
    const requestId = newRequestId();
    const displayName = typeof toolName === 'string' && isIdentifier(toolName) ? sanitize(toolName) : INVALID_TOOL_NAME;

    const prepared = prepareContext(requestId, deps.serverId, toolName, rawArgs);
    const decision = prepared.ok ? evaluateSafely(prepared.ctx, deps, log, requestId) : prepared.decision;

    publishSafely(
      () => ({
        timestamp: new Date(now()).toISOString(),
        requestId,
        serverId: deps.serverId,
        toolName: displayName,
        decision: decision.decision,
        ruleId: decision.ruleId,
        reason: decision.reason,
        summary: buildSummary(displayName, rawArgs, decision),
        durationMs: Math.max(0, now() - startedAt),
      }),
      deps.publish,
      log,
      requestId,
    );

    if (prepared.ok && decision.decision === 'ALLOW') {
      const ctx = prepared.ctx;
      const forward = async (): Promise<CallToolResult> => {
        try {
          // The single forward call site. Same frozen object the evaluator saw.
          return await deps.forward(ctx.toolName, ctx.arguments, forwardOptions(options));
        } catch (err) {
          const kind = classifyDownstreamError(err);
          log(`[firewall] request ${sanitize(requestId)} downstream error: ${describeError(err)} → ${kind}`);
          return downstreamErrorResult(kind, decision, requestId);
        }
      };
      if (!deps.staging) return forward();
      return runStagedCall(
        deps.staging,
        {
          serverId: deps.serverId,
          requestId: sanitize(requestId),
          toolName: displayName,
          now,
          log,
          errorResult: (text) => ({
            isError: true,
            content: [{ type: 'text', text }],
            _meta: { [FIREWALL_META_KEY]: meta(decision, requestId) },
          }),
        },
        forward,
      );
    }
    return blockedResult(decision, requestId);
  };
}

// ---------------------------------------------------------------------------
// Validation + evaluation
// ---------------------------------------------------------------------------

type Prepared = { ok: true; ctx: ToolCallContext } | { ok: false; decision: PolicyDecision };

function prepareContext(requestId: string, serverId: string, toolName: unknown, rawArgs: unknown): Prepared {
  const args = rawArgs === undefined ? {} : rawArgs;
  if (!isPlainObject(args)) {
    return invalid('Tool arguments must be a JSON object');
  }

  let frozen: Record<string, unknown>;
  try {
    const copy: unknown = structuredClone(args);
    if (!isPlainObject(copy) || !freezeJson(copy, 0)) {
      return invalid('Tool arguments must be plain JSON values');
    }
    frozen = copy;
  } catch {
    return invalid('Tool arguments could not be copied');
  }

  const ctx = { requestId, serverId, toolName, arguments: frozen };
  // Validate only: the parsed output is a rebuilt copy, and the evaluator must see `frozen` itself.
  if (!ToolCallContextSchema.safeParse(ctx).success) {
    return invalid('Tool call name or identifiers are invalid');
  }
  return { ok: true, ctx: Object.freeze(ctx as ToolCallContext) };
}

function invalid(reason: string): Prepared {
  return { ok: false, decision: { decision: 'DENY', ruleId: 'INVALID_ARGUMENTS', reason } };
}

function evaluateSafely(
  ctx: ToolCallContext,
  deps: InterceptorDeps,
  log: (line: string) => void,
  requestId: string,
): PolicyDecision {
  let raw: unknown;
  try {
    raw = deps.evaluate(ctx, deps.policy);
  } catch (err) {
    log(`[firewall] request ${sanitize(requestId)} evaluator threw: ${describeError(err)}`);
    return evaluationError('Policy evaluation failed; the call was denied');
  }
  const parsed = PolicyDecisionSchema.safeParse(raw);
  if (!parsed.success) {
    log(`[firewall] request ${sanitize(requestId)} evaluator returned an invalid decision`);
    return evaluationError('Policy evaluator returned an invalid decision; the call was denied');
  }
  // parsed.data is a fresh copy, so the evaluator cannot flip it after the fact.
  return parsed.data;
}

function evaluationError(reason: string): PolicyDecision {
  return { decision: 'DENY', ruleId: 'EVALUATION_ERROR', reason };
}

function publishSafely(
  buildEvent: () => FirewallEvent,
  publish: PublishEvent,
  log: (line: string) => void,
  requestId: string,
): void {
  let event: FirewallEvent;
  try {
    event = buildEvent();
  } catch {
    log(`[firewall] request ${sanitize(requestId)} event could not be built; not published`);
    return;
  }
  const parsed = FirewallEventSchema.safeParse(event);
  if (!parsed.success) {
    log(`[firewall] request ${sanitize(requestId)} event failed validation; not published`);
    return;
  }
  try {
    publish(parsed.data);
  } catch (err) {
    log(`[firewall] request ${sanitize(requestId)} publish failed: ${describeError(err)}`);
  }
}

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

function blockedResult(decision: PolicyDecision, requestId: string): CallToolResult {
  const reason = decision.reason.replace(/[\s.]+$/, '');
  return {
    isError: true,
    content: [
      {
        type: 'text',
        text: `${BLOCKED_PREFIX} (${decision.ruleId}): ${reason}. The request was not sent to the tool server. [request ${requestId}]`,
      },
    ],
    _meta: { [FIREWALL_META_KEY]: meta(decision, requestId) },
  };
}

function downstreamErrorResult(kind: DownstreamErrorKind, decision: PolicyDecision, requestId: string): CallToolResult {
  return {
    isError: true,
    content: [{ type: 'text', text: `${DOWNSTREAM_ERROR_PREFIX}: ${DOWNSTREAM_MESSAGES[kind]}. [request ${requestId}]` }],
    _meta: { [FIREWALL_META_KEY]: { ...meta(decision, requestId), downstreamError: kind } },
  };
}

function meta(decision: PolicyDecision, requestId: string): FirewallMeta {
  return { decision: decision.decision, ruleId: decision.ruleId, reason: decision.reason, requestId };
}

function forwardOptions(options: CallOptions): CallOptions {
  return options.signal ? { signal: options.signal } : {};
}

function classifyDownstreamError(err: unknown): DownstreamErrorKind {
  const code = errorCode(err);
  if (code === 'REQUEST_TIMEOUT') return 'timeout';
  if (code !== undefined && NOT_CONNECTED_CODES.has(code)) return 'not_connected';
  return 'failed';
}

// ---------------------------------------------------------------------------
// Summary + sanitizing helpers
// ---------------------------------------------------------------------------

/** Tool name + argument KEY names (≤ 8) + outcome. Never argument values. */
function buildSummary(displayName: string, rawArgs: unknown, decision: PolicyDecision): string {
  let keys: string;
  if (rawArgs === undefined) {
    keys = '';
  } else if (isPlainObject(rawArgs)) {
    let names: string[];
    try {
      names = Object.keys(rawArgs);
    } catch {
      names = [];
    }
    const shown = names.slice(0, MAX_SUMMARY_KEYS).map((k) => sanitize(k).slice(0, MAX_KEY_LENGTH));
    const extra = names.length - shown.length;
    keys = shown.join(',') + (extra > 0 ? `,+${extra} more` : '');
  } else {
    keys = '<invalid>';
  }
  const summary = `${displayName} args=[${keys}] → ${decision.decision} ${decision.ruleId}`;
  return summary.length <= LIMITS.summary ? summary : `${summary.slice(0, LIMITS.summary - 1)}…`;
}

/** Keeps identifiers readable and log-safe: anything outside [A-Za-z0-9_./:-] becomes "_". */
function sanitize(value: string): string {
  return value.slice(0, LIMITS.identifier).replace(/[^A-Za-z0-9_./:-]/g, '_');
}

function isIdentifier(value: string): boolean {
  return value.length >= 1 && value.length <= LIMITS.identifier;
}

/** Error class and code only. Never the message: it can echo arguments. */
function describeError(err: unknown): string {
  const name = err instanceof Error ? err.constructor.name || 'Error' : typeof err;
  const code = errorCode(err);
  return code === undefined ? sanitize(name) : `${sanitize(name)} code=${sanitize(code)}`;
}

function errorCode(err: unknown): string | undefined {
  if (typeof err !== 'object' || err === null || !('code' in err)) return undefined;
  const code = (err as { code: unknown }).code;
  return typeof code === 'string' ? code : undefined;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null) return false;
  try {
    // Both can throw for a revoked Proxy.
    if (Array.isArray(value)) return false;
    const proto: unknown = Object.getPrototypeOf(value);
    return proto === Object.prototype || proto === null;
  } catch {
    return false;
  }
}

/**
 * Deep-freezes a structuredClone copy in place and checks it is plain JSON, so
 * what the evaluator inspects is exactly what goes on the wire (no Map, Date,
 * undefined, NaN, sparse arrays… that JSON would silently rewrite).
 */
function freezeJson(value: unknown, depth: number): boolean {
  if (depth > MAX_ARG_DEPTH) return false;
  switch (typeof value) {
    case 'string':
    case 'boolean':
      return true;
    case 'number':
      return Number.isFinite(value);
    case 'object':
      break;
    default:
      return false;
  }
  if (value === null) return true;
  if (Array.isArray(value)) {
    if (Object.keys(value).length !== value.length) return false;
    for (const item of value) if (!freezeJson(item, depth + 1)) return false;
  } else if (isPlainObject(value)) {
    for (const item of Object.values(value)) if (!freezeJson(item, depth + 1)) return false;
  } else {
    return false;
  }
  Object.freeze(value);
  return true;
}
