/**
 * OWNER: Aarav — staged writes in the enforcement path (docs/STAGED_WRITES_PLAN.md,
 * "Flow per tools/call"; DECISIONS §12).
 *
 * For an ALLOWed call with staging enabled, under the staging lock:
 *   1. catch-up: diff staging against the baseline the previous call left; late or
 *      background writes go through evaluate → apply → revert like a normal call
 *      (FileChangeEvent toolName "<late-writes>", requestId "<id>:late")
 *   2. sync staging with the real project → pre-call snapshot
 *   3. forward the call
 *   4. always (result, tool error, timeout): diff against the pre-call snapshot
 *   5. evaluateFileChanges, validated; if it throws or returns anything malformed,
 *      every change is DENY / EVALUATION_ERROR. Excluded paths (.git/, .env, …) and
 *      unsafe file names are DENY whatever it says.
 *   6. apply approved changes, revert rejected ones, remove excluded paths from staging,
 *      and set the baseline for the next catch-up to the expected state (no rescan of
 *      staging, so a write landing after step 4 is caught next time, not overwritten)
 *   7. _meta['mcp-firewall/staged'], a note listing rejected paths, and a FileChangeEvent
 *      if there were any changes
 *
 * Any error from sync/diff/apply/revert breaks staging for good: nothing more is
 * applied and every later allowed call is refused until restart. Allowed calls are
 * also refused until initStaging() has run. Decisions are read from `decision`
 * only, never from ruleId. File contents never reach results, events or logs.
 */
import type { CallToolResult } from '@modelcontextprotocol/server';
import {
  ChangeDecisionSchema,
  FileChangeEventSchema,
  LIMITS,
  MAX_FILE_CHANGE_EVENT_ENTRIES,
  MAX_FILE_CHANGE_EVENT_PATH_LENGTH,
  type ChangeDecision,
  type Decision,
  type EvaluateFileChanges,
  type FileChange,
  type FileChangeEvent,
  type FirewallPolicy,
  type RuleId,
} from '../shared/contracts.js';
import {
  StagingApplyError,
  type ApplyResult,
  type Manifest,
  type StagingArea,
  type StagingLock,
  type SyncResult,
} from './staging.js';
import { evaluateFileChangesStub } from './stubs/evaluate-file-changes.stub.js';

/** Key under CallToolResult._meta carrying the staged-writes outcome of the call. */
export const STAGED_META_KEY = 'mcp-firewall/staged';
/** Start of the text of every result where staging refused or failed the call. */
export const STAGING_ERROR_PREFIX = '[MCP Firewall] STAGING ERROR';
/** Start of the note appended to a result when some of its file changes were rejected. */
export const REJECTED_CHANGES_PREFIX = '[MCP Firewall] REJECTED FILE CHANGES';

/** Used when no evaluateFileChanges is injected. TODO: Winston's src/security/changes.ts once it lands. */
export const defaultEvaluateFileChanges: EvaluateFileChanges = evaluateFileChangesStub;

const LATE_TOOL_NAME = '<late-writes>';
const STARTUP_TOOL_NAME = '<startup>';
const STARTUP_REQUEST_ID = 'startup';
const STARTUP_REASON = 'change made before any tool call';
/** Changes listed in _meta and rejected paths listed in the result note; the rest are only counted. */
export const MAX_REPORTED_CHANGES = 100;

/** What staged-call needs from a StagingArea (an interface, so tests can wrap one). */
export type StagingAreaLike = Pick<
  StagingArea,
  'sync' | 'diff' | 'apply' | 'revert' | 'forcedDenyReason' | 'removeExcluded' | 'baselineAfter'
>;

export interface StagingDeps {
  area: StagingAreaLike;
  /** Held from the catch-up diff to the end of post-call processing. */
  lock: StagingLock;
  /** Default: defaultEvaluateFileChanges (reject-all until Winston's lands). */
  evaluateFileChanges?: EvaluateFileChanges;
  policy: FirewallPolicy;
  /** Must not throw; if it does, the error is logged and the result is unaffected. */
  onFileChangeEvent?: (event: FileChangeEvent) => void;
}

export interface StagedChange {
  path: string;
  /** ALLOW only if the change was actually applied to the project. */
  decision: Decision;
  ruleId: RuleId;
}

/** `_meta['mcp-firewall/staged']`. */
export interface StagedMeta {
  /** True totals, even when `changes` is truncated. */
  applied: number;
  rejected: number;
  /** At most MAX_REPORTED_CHANGES entries, in path order. */
  changes: StagedChange[];
  /** Present (true) only when `changes` was capped. */
  truncated?: true;
}

interface Settled {
  entries: StagedChange[];
  results: ApplyResult[];
  /** What revert() put back in staging. */
  restored: Manifest;
}

/** Per-call context the interceptor provides. */
export interface StagedCallContext {
  serverId: string;
  requestId: string;
  toolName: string;
  now: () => number;
  log: (line: string) => void;
  /** The interceptor's error result for this call, around the given text. */
  errorResult: (text: string) => CallToolResult;
}

interface StagingState {
  /** Staging and project as of the end of the last call: what the catch-up diff compares against. */
  baseline?: SyncResult;
  broken: boolean;
}

const states = new WeakMap<StagingAreaLike, StagingState>();

function stateOf(area: StagingAreaLike): StagingState {
  let state = states.get(area);
  if (!state) {
    state = { broken: false };
    states.set(area, state);
  }
  return state;
}

/**
 * For index.ts, after the sandboxed server has started on the staging dir that
 * `initial` (the first sync) describes. Reverts every change the server made
 * before any call, reports them as one "<startup>" FileChangeEvent, and enables
 * staged calls. Throws if staging fails; startup must not continue then.
 */
export async function initStaging(
  staging: StagingDeps,
  options: { serverId: string; initial: SyncResult; now?: () => number; log?: (line: string) => void },
): Promise<void> {
  const state = stateOf(staging.area);
  const log = options.log ?? ((line: string) => process.stderr.write(`${line}\n`));
  try {
    const changes = await staging.area.diff(options.initial.staging);
    const results = changes.map((c): ApplyResult => ({ path: c.path, applied: false, ruleId: 'WRITE_NOT_ALLOWED' }));
    const restored = await staging.area.revert(changes.map((c) => c.path));
    await staging.area.removeExcluded();
    if (changes.length > 0) {
      log(`[firewall] startup: reverted ${changes.length} change(s) made before any tool call (${STARTUP_REASON})`);
      emitFileChangeEvent(staging, log, {
        now: options.now ?? Date.now,
        serverId: options.serverId,
        requestId: STARTUP_REQUEST_ID,
        toolName: STARTUP_TOOL_NAME,
        entries: results.map((r) => ({ path: r.path, decision: 'DENY', ruleId: r.ruleId })),
      });
    }
    state.baseline = await staging.area.baselineAfter(options.initial, results, restored);
  } catch (err) {
    state.broken = true;
    throw err;
  }
}

/**
 * Runs one ALLOWed call with staged writes. `call` performs the forward and
 * returns the interceptor's result (downstream errors already turned into a
 * DOWNSTREAM ERROR result). Never throws unless `call` itself does.
 */
export async function runStagedCall(
  staging: StagingDeps,
  ctx: StagedCallContext,
  call: () => Promise<CallToolResult>,
): Promise<CallToolResult> {
  const state = stateOf(staging.area);
  const refusedEarly = refusal(state, ctx);
  if (refusedEarly) return refusedEarly;

  return staging.lock.run(async () => {
    // Another call may have broken staging while this one waited for the lock.
    const refused = refusal(state, ctx);
    if (refused) return refused;
    const baseline = state.baseline!;

    let pre: SyncResult;
    try {
      const late = await staging.area.diff(baseline.staging);
      const { entries } = await settleChanges(staging, late, baseline.project, ctx);
      if (entries.length > 0) {
        emitFileChangeEvent(staging, ctx.log, {
          ...ctx,
          requestId: `${ctx.requestId}:late`,
          toolName: LATE_TOOL_NAME,
          entries,
        });
      }
      pre = await staging.area.sync();
    } catch (err) {
      return fail(state, ctx, err, false);
    }

    let result: CallToolResult | undefined;
    let callError: { error: unknown } | undefined;
    try {
      result = await call();
    } catch (error) {
      callError = { error };
    }

    let entries: StagedChange[];
    try {
      const changes = await staging.area.diff(pre.staging);
      const settled = await settleChanges(staging, changes, pre.project, ctx);
      entries = settled.entries;
      // Expected state, not a rescan: a write landing from here on shows up in the next catch-up diff.
      state.baseline = await staging.area.baselineAfter(pre, settled.results, settled.restored);
    } catch (err) {
      return fail(state, ctx, err, true);
    }

    if (entries.length > 0) emitFileChangeEvent(staging, ctx.log, { ...ctx, entries });
    if (callError) throw callError.error;
    return withStagedMeta(result!, entries);
  });
}

function refusal(state: StagingState, ctx: StagedCallContext): CallToolResult | undefined {
  if (state.broken) {
    return ctx.errorResult(
      `${STAGING_ERROR_PREFIX}: staging failed earlier, so allowed calls are refused until the firewall restarts. The request was not sent to the tool server. [request ${ctx.requestId}]`,
    );
  }
  if (!state.baseline) {
    return ctx.errorResult(
      `${STAGING_ERROR_PREFIX}: staging is not initialized. The request was not sent to the tool server. [request ${ctx.requestId}]`,
    );
  }
  return undefined;
}

function fail(state: StagingState, ctx: StagedCallContext, err: unknown, forwarded: boolean): CallToolResult {
  state.broken = true;
  const applied = err instanceof StagingApplyError ? err.applied.map(displayPath) : [];
  const appliedNote = applied.length > 0 ? `; already applied before the failure: ${applied.join(', ')}` : '';
  ctx.log(
    `[firewall] request ${ctx.requestId} staging failed: ${describeError(err)}${appliedNote}; staged calls are disabled until restart`,
  );
  const changesText =
    applied.length > 0
      ? `file changes were not applied, except these, applied before the failure: ${applied.join(', ')}`
      : 'file changes were not applied';
  return ctx.errorResult(
    `${STAGING_ERROR_PREFIX}: staging failed and ${changesText}. Allowed calls are refused until the firewall restarts.${forwarded ? '' : ' The request was not sent to the tool server.'} [request ${ctx.requestId}]`,
  );
}

/**
 * Evaluate → apply approved → revert rejected → remove excluded paths from staging.
 * Returns what happened to each change, in order.
 */
async function settleChanges(
  staging: StagingDeps,
  changes: FileChange[],
  projectAtSync: Manifest,
  ctx: StagedCallContext,
): Promise<Settled> {
  let results: ApplyResult[] = [];
  let restored: Manifest = new Map();
  if (changes.length > 0) {
    // Excluded paths and unsafe names are DENY whatever the evaluator says.
    const decisions = decide(staging, changes, ctx).map((d): ChangeDecision => {
      const forced = d.decision === 'ALLOW' ? staging.area.forcedDenyReason(d.path) : undefined;
      return forced ? { ...d, decision: 'DENY', ruleId: 'WRITE_NOT_ALLOWED', reason: forced } : d;
    });
    results = await staging.area.apply(changes, decisions, projectAtSync);
    const rejected = results.filter((r) => !r.applied).map((r) => r.path);
    if (rejected.length > 0) restored = await staging.area.revert(rejected);
  }
  await staging.area.removeExcluded();
  const entries = results.map((r): StagedChange => ({ path: r.path, decision: r.applied ? 'ALLOW' : 'DENY', ruleId: r.ruleId }));
  return { entries, results, restored };
}

/** evaluateFileChanges on a frozen copy, validated. Anything unexpected → every change DENY. */
function decide(staging: StagingDeps, changes: FileChange[], ctx: StagedCallContext): ChangeDecision[] {
  const failClosed = (why: string): ChangeDecision[] => {
    ctx.log(`[firewall] request ${ctx.requestId} file change evaluator ${why}; all ${changes.length} change(s) rejected`);
    return changes.map((c) => ({
      path: c.path,
      decision: 'DENY',
      ruleId: 'EVALUATION_ERROR',
      reason: 'File change evaluation failed; the change was rejected',
    }));
  };

  let raw: unknown;
  try {
    const input = deepFreeze(structuredClone(changes));
    raw = (staging.evaluateFileChanges ?? defaultEvaluateFileChanges)(input, staging.policy);
  } catch (err) {
    return failClosed(`threw ${describeError(err)}`);
  }
  if (!Array.isArray(raw) || raw.length !== changes.length) return failClosed('returned the wrong number of decisions');
  const decisions: ChangeDecision[] = [];
  for (const [index, item] of raw.entries()) {
    const parsed = ChangeDecisionSchema.safeParse(item);
    if (!parsed.success || parsed.data.path !== changes[index]!.path) {
      return failClosed('returned an invalid or out-of-order decision');
    }
    decisions.push(parsed.data);
  }
  return decisions;
}

function withStagedMeta(result: CallToolResult, entries: StagedChange[]): CallToolResult {
  const rejected = entries.filter((e) => e.decision !== 'ALLOW');
  const staged: StagedMeta = {
    applied: entries.length - rejected.length,
    rejected: rejected.length,
    changes: entries.slice(0, MAX_REPORTED_CHANGES),
    ...(entries.length > MAX_REPORTED_CHANGES ? { truncated: true as const } : {}),
  };
  const content =
    rejected.length > 0 ? [...result.content, { type: 'text' as const, text: rejectionNote(rejected, staged.applied) }] : result.content;
  return { ...result, content, _meta: { ...result._meta, [STAGED_META_KEY]: staged } };
}

function rejectionNote(rejected: StagedChange[], applied: number): string {
  const listed = rejected.slice(0, MAX_REPORTED_CHANGES).map((e) => `${displayPath(e.path)} (${e.ruleId})`);
  const more = rejected.length > MAX_REPORTED_CHANGES ? `, ...and ${rejected.length - MAX_REPORTED_CHANGES} more` : '';
  return `${REJECTED_CHANGES_PREFIX}: ${rejected.length} file change(s) made by the tool server were rejected and not applied to the project: ${listed.join(', ')}${more}. ${applied} change(s) were applied.`;
}

function emitFileChangeEvent(
  staging: StagingDeps,
  log: (line: string) => void,
  e: { now: () => number; serverId: string; requestId: string; toolName: string; entries: StagedChange[] },
): void {
  const applied = e.entries.filter((x) => x.decision === 'ALLOW').length;
  const event: FileChangeEvent = {
    timestamp: new Date(e.now()).toISOString(),
    requestId: e.requestId.slice(0, LIMITS.identifier),
    serverId: e.serverId,
    toolName: e.toolName,
    applied,
    rejected: e.entries.length - applied,
    changes: e.entries.slice(0, MAX_FILE_CHANGE_EVENT_ENTRIES).map((x) => ({
      path: truncate(displayPath(x.path), MAX_FILE_CHANGE_EVENT_PATH_LENGTH),
      decision: x.decision,
      ruleId: x.ruleId,
    })),
  };
  const parsed = FileChangeEventSchema.safeParse(event);
  if (!parsed.success) {
    log(`[firewall] request ${e.requestId} file change event failed validation; not published`);
    return;
  }
  try {
    staging.onFileChangeEvent?.(parsed.data);
  } catch (err) {
    log(`[firewall] request ${e.requestId} file change event callback failed: ${describeError(err)}`);
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Paths come from the server; keep them on one readable line. */
function displayPath(path: string): string {
  return path.replace(/[\u0000-\u001f\u007f]/g, '_');
}

function truncate(value: string, max: number): string {
  return value.length <= max ? value : `${value.slice(0, max - 1)}…`;
}

/** Error class and code only. Never the message: it can carry paths or contents. */
function describeError(err: unknown): string {
  const name = err instanceof Error ? err.constructor.name || 'Error' : typeof err;
  const code = typeof err === 'object' && err !== null && 'code' in err ? (err as { code: unknown }).code : undefined;
  return typeof code === 'string' ? `${name} code=${code.replace(/[^A-Za-z0-9_]/g, '_')}` : name;
}

function deepFreeze<T>(value: T): T {
  if (typeof value === 'object' && value !== null) {
    for (const item of Object.values(value)) deepFreeze(item);
    Object.freeze(value);
  }
  return value;
}
