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
 *
 * Staged writes (contract/staged-writes, agreed by all three; additive only):
 *   - FileChange / ChangeDecision / StagingPolicy / FileChangeEvent and their schemas.
 *   - FirewallPolicy gains an optional `staging` section.
 *   - RuleId gains the staging rule IDs (WRITE_NOT_ALLOWED … WRITE_CONFLICT).
 *   - EvaluateFileChanges is the Winston → Aarav signature for staged changes.
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

/** Max entries in FileChangeEvent.changes; the rest are only counted in applied / rejected. */
export const MAX_FILE_CHANGE_EVENT_ENTRIES = 20;
/** Max length of a path in FileChangeEvent.changes (the publisher truncates longer paths). */
export const MAX_FILE_CHANGE_EVENT_PATH_LENGTH = 200;

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

  // --- Staged writes (EvaluateFileChanges) ---------------------------------

  /** Path is outside staging.writablePaths. */
  'WRITE_NOT_ALLOWED',
  /** Path is a persistence location (staging.protectedWritePaths: shell rc, hooks, CI, …). */
  'PERSISTENCE_PATH',
  'SYMLINK_DENIED',
  'EXECUTABLE_DENIED',
  /** FileChange.text matched a secret pattern. */
  'SECRET_DETECTED',
  /** More than staging.maxChangesPerCall changes, or a file over staging.maxFileBytes. */
  'CHANGE_LIMIT',
  /** The project file changed since the staging copy was taken. */
  'WRITE_CONFLICT',
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
// StagingPolicy — FirewallPolicy.staging, for staged writes (see below)
// ---------------------------------------------------------------------------

export const StagingPolicySchema = z.strictObject({
  /** Path patterns, relative to the project root, that changes may touch. */
  writablePaths: z.array(z.string().min(1)),
  /** Path patterns that are never written, even inside writablePaths (PERSISTENCE_PATH). */
  protectedWritePaths: z.array(z.string().min(1)),
  /** Larger files are denied (CHANGE_LIMIT) and never get FileChange.text. */
  maxFileBytes: z.number().int().positive(),
  /** A call with more changes than this has all of them denied (CHANGE_LIMIT). */
  maxChangesPerCall: z.number().int().positive(),
});
export type StagingPolicy = z.infer<typeof StagingPolicySchema>;

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

  // --- Staged writes --------------------------------------------------------

  /**
   * Rules for applying changes the sandboxed downstream server made to its
   * staging copy. Optional so existing configs keep loading. Sandbox mode
   * refuses to start if it is missing: fail closed, never a permissive default.
   */
  staging: StagingPolicySchema.optional(),
});
export type FirewallPolicy = z.infer<typeof FirewallPolicySchema>;

// ---------------------------------------------------------------------------
// Staged writes — the sandboxed server writes to a staging copy; the proxy
// diffs it after each allowed call and applies only approved changes.
// ---------------------------------------------------------------------------

/**
 * Normalized posix path relative to the project root: not absolute, no drive
 * prefix, no backslashes or NULs, and no empty, "." or ".." segments.
 */
const ProjectRelativePathSchema = z
  .string()
  .min(1)
  .refine((p) => !p.startsWith('/'), 'path must be relative to the project root')
  .refine((p) => !/^[A-Za-z]:/.test(p), 'path must not have a drive prefix')
  .refine((p) => !p.includes('\\'), 'path must use posix separators')
  .refine((p) => !p.includes('\0'), 'path must not contain NUL')
  .refine((p) => !p.split('/').includes(''), 'path must not contain empty segments')
  .refine((p) => !p.split('/').includes('.'), 'path must not contain a "." segment')
  .refine((p) => !p.split('/').includes('..'), 'path must not contain a ".." segment');

export const FileChangeKindSchema = z.enum(['add', 'modify', 'delete', 'mode', 'symlink', 'special']);
export type FileChangeKind = z.infer<typeof FileChangeKindSchema>;

export const FileChangeSchema = z.strictObject({
  /** Posix, relative to the project root, normalized. */
  path: ProjectRelativePathSchema,
  kind: FileChangeKindSchema,
  size: z.number().int().nonnegative().optional(),
  /** New or changed exec bit. */
  executable: z.boolean().optional(),
  /** Symlinks only. */
  linkTarget: z.string().optional(),
  /**
   * Content of text files under staging.maxFileBytes, for secret scanning only.
   * NEVER put it in logs, events, SSE or error messages.
   */
  text: z.string().nullable().optional(),
});
export type FileChange = z.infer<typeof FileChangeSchema>;

/** Exactly one per input FileChange, in the same order. */
export const ChangeDecisionSchema = z.strictObject({
  path: ProjectRelativePathSchema,
  decision: DecisionSchema,
  ruleId: RuleIdSchema,
  /** Safe to show the user. Never contains file contents. */
  reason: z.string().min(1).max(LIMITS.reason),
});
export type ChangeDecision = z.infer<typeof ChangeDecisionSchema>;

/** One per staged diff, published alongside the call's FirewallEvent. Never carries contents. */
export const FileChangeEventSchema = z.strictObject({
  /** ISO 8601. */
  timestamp: z.iso.datetime(),
  requestId: identifier,
  serverId: identifier,
  toolName: identifier,
  applied: z.number().int().nonnegative(),
  rejected: z.number().int().nonnegative(),
  /** At most MAX_FILE_CHANGE_EVENT_ENTRIES entries; paths truncated, never contents. */
  changes: z
    .array(
      z.strictObject({
        path: z.string().min(1).max(MAX_FILE_CHANGE_EVENT_PATH_LENGTH),
        decision: DecisionSchema,
        ruleId: RuleIdSchema,
      }),
    )
    .max(MAX_FILE_CHANGE_EVENT_ENTRIES),
});
export type FileChangeEvent = z.infer<typeof FileChangeEventSchema>;

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

/**
 * Winston → Aarav, implemented in src/security/changes.ts. Pure, synchronous,
 * no I/O. Returns exactly one decision per input change, in the same order.
 */
export type EvaluateFileChanges = (changes: FileChange[], policy: FirewallPolicy) => ChangeDecision[];

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/** The single definition of a canonical tool name: "serverId/toolName". */
export function toCanonicalToolName(serverId: string, toolName: string): string {
  return `${serverId}/${toolName}`;
}
