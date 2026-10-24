/**
 * SHARED INTEGRATION CONTRACT — FROZEN AT INITIAL COMMIT (design doc §5).
 *
 * Every module talks to every other module only through the types and
 * function signatures in this file. Changing anything here requires a quick
 * agreement from Aarav, Winston and Kritish (design doc §4, "Git boundaries").
 *
 * Each TypeScript type is inferred from its Zod schema, so the runtime
 * validation and the compile-time type can never drift apart.
 *
 * Additions beyond the §5 text (agreed at bootstrap, see README "Contract notes"):
 *   - RuleId is a closed enum (the 7 rule IDs from §7 + EVALUATION_ERROR).
 *   - FirewallPolicy gains pathArgs / destinationArgs / destructiveTools.
 *   - FirewallConfig wraps policy + downstream server + monitor settings.
 *   - toCanonicalToolName() is the one place "serverId/toolName" is built.
 *   - EvaluateToolCall / PublishEvent are the cross-team function signatures.
 */
import { z } from 'zod';

// ---------------------------------------------------------------------------
// Limits (contract invariant: strings and values are length-limited)
// ---------------------------------------------------------------------------

export const LIMITS = {
  /** Max length of PolicyDecision.reason / FirewallEvent.reason. */
  reason: 200,
  /** Max length of FirewallEvent.summary (redacted, bounded). */
  summary: 200,
  /** Max length of identifiers such as requestId, serverId, toolName. */
  identifier: 128,
} as const;

const identifier = z.string().min(1).max(LIMITS.identifier);

// ---------------------------------------------------------------------------
// Decision + rule IDs
// ---------------------------------------------------------------------------

export const DecisionSchema = z.enum(['ALLOW', 'DENY']);
export type Decision = z.infer<typeof DecisionSchema>;

export const RULE_IDS = [
  'INVALID_ARGUMENTS',
  'DENIED_TOOL',
  'PROTECTED_PATH',
  'DENIED_DESTINATION',
  'DESTRUCTIVE_ACTION',
  'APPROVED_TOOL',
  'DEFAULT_DENY',
  /**
   * Not produced by the evaluator. Used by the proxy when evaluation itself
   * throws or the policy is unusable, so the call still fails closed (§5, §6.4).
   */
  'EVALUATION_ERROR',
] as const;

export const RuleIdSchema = z.enum(RULE_IDS);
export type RuleId = z.infer<typeof RuleIdSchema>;

// ---------------------------------------------------------------------------
// ToolCallContext — built by the proxy, consumed by the evaluator
// ---------------------------------------------------------------------------

export const ToolCallContextSchema = z.strictObject({
  /** Generated correlation ID. */
  requestId: identifier,
  /** Stable configured server identity (FirewallConfig.server.id). */
  serverId: identifier,
  /** Exact exposed tool name (not canonical; see toCanonicalToolName). */
  toolName: identifier,
  arguments: z.record(z.string(), z.unknown()),
});
export type ToolCallContext = z.infer<typeof ToolCallContextSchema>;

// ---------------------------------------------------------------------------
// PolicyDecision — returned by the evaluator, exactly one per input
// ---------------------------------------------------------------------------

export const PolicyDecisionSchema = z.strictObject({
  decision: DecisionSchema,
  ruleId: RuleIdSchema,
  /** Safe to show the user. Never contains credentials or file contents. */
  reason: z.string().min(1).max(LIMITS.reason),
});
export type PolicyDecision = z.infer<typeof PolicyDecisionSchema>;

// ---------------------------------------------------------------------------
// FirewallEvent — built by the proxy, published to observability
// ---------------------------------------------------------------------------

export const FirewallEventSchema = z.strictObject({
  /** ISO 8601. */
  timestamp: z.iso.datetime(),
  requestId: identifier,
  serverId: identifier,
  toolName: identifier,
  decision: DecisionSchema,
  ruleId: RuleIdSchema,
  reason: z.string().min(1).max(LIMITS.reason),
  /** Redacted, bounded. NEVER full raw arguments or file contents. */
  summary: z.string().max(LIMITS.summary),
  durationMs: z.number().nonnegative().optional(),
});
export type FirewallEvent = z.infer<typeof FirewallEventSchema>;

// ---------------------------------------------------------------------------
// FirewallPolicy — semantics owned by Winston (§7)
// ---------------------------------------------------------------------------

export const FirewallPolicySchema = z.strictObject({
  /** MVP default is DENY for unclassified actions. */
  defaultDecision: DecisionSchema,
  /** Path patterns (e.g. "~/.aws/credentials", "**\/.env"). Matched path-aware, never by substring. */
  protectedPaths: z.array(z.string().min(1)).default([]),
  /** Hostnames / origins that must never receive data. */
  deniedDestinations: z.array(z.string().min(1)).default([]),
  /** Canonical "serverId/toolName" entries. */
  approvedTools: z.array(z.string().min(1)).default([]),
  /** Canonical "serverId/toolName" entries. */
  deniedTools: z.array(z.string().min(1)).default([]),

  // --- Bootstrap additions (gaps in §5 called out by §7) -------------------

  /** Argument names that carry file paths, checked against protectedPaths. */
  pathArgs: z.array(z.string().min(1)).default(['path', 'filePath', 'filename']),
  /**
   * Which argument(s) of which tool carry a destination URL/host.
   * Key: canonical "serverId/toolName". Value: argument names.
   * Tools listed here are "send/upload/post/fetch"-like: malformed URLs DENY.
   */
  destinationArgs: z.record(z.string().min(1), z.array(z.string().min(1))).default({}),
  /** Canonical tool names treated as destructive (DESTRUCTIVE_ACTION). */
  destructiveTools: z.array(z.string().min(1)).default([]),
});
export type FirewallPolicy = z.infer<typeof FirewallPolicySchema>;

// ---------------------------------------------------------------------------
// FirewallConfig — the whole YAML file (loader owned by Kritish)
// ---------------------------------------------------------------------------

export const DownstreamServerSchema = z.strictObject({
  /** Becomes ToolCallContext.serverId and the prefix of canonical tool names. */
  id: z.string().regex(/^[A-Za-z0-9_-]+$/, 'server id must be [A-Za-z0-9_-]+').max(LIMITS.identifier),
  /** Executable that starts the downstream stdio MCP server. */
  command: z.string().min(1),
  args: z.array(z.string()).default([]),
  /** Working directory for the downstream process (relative to the config file). */
  cwd: z.string().optional(),
  /** Per-call timeout before failing closed (§6.4). */
  timeoutMs: z.number().int().positive().default(10_000),
});
export type DownstreamServerConfig = z.infer<typeof DownstreamServerSchema>;

export const MonitorConfigSchema = z.strictObject({
  enabled: z.boolean().default(true),
  /** Loopback only. The monitor is not safe for remote exposure (§3). */
  host: z.literal('127.0.0.1').default('127.0.0.1'),
  port: z.number().int().min(1).max(65535).default(3000),
  /** Size of the in-memory event ring buffer (§8). */
  maxEvents: z.number().int().min(1).max(10_000).default(100),
});
export type MonitorConfig = z.infer<typeof MonitorConfigSchema>;

export const FirewallConfigSchema = z.strictObject({
  /** MVP: exactly one downstream server, stdio only (§2). */
  server: DownstreamServerSchema,
  monitor: MonitorConfigSchema.prefault({}),
  policy: FirewallPolicySchema,
});
export type FirewallConfig = z.infer<typeof FirewallConfigSchema>;

// ---------------------------------------------------------------------------
// Cross-team function signatures (§5, §11 "Dependencies")
// ---------------------------------------------------------------------------

/**
 * Winston → Aarav. Pure, fast, synchronous. No MCP SDK, no network I/O,
 * no logging. Must return exactly one decision for every input.
 */
export type EvaluateToolCall = (request: ToolCallContext, policy: FirewallPolicy) => PolicyDecision;

/**
 * Kritish → Aarav. Must never throw and must never influence the
 * allow/deny result. Responsible for redaction before persisting/streaming.
 */
export type PublishEvent = (event: FirewallEvent) => void;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/** The single definition of a canonical tool name: "serverId/toolName". */
export function toCanonicalToolName(serverId: string, toolName: string): string {
  return `${serverId}/${toolName}`;
}
