/** Interactive, one-request approvals through the parent's controlling terminal.
 * MCP stdio owns stdin/stdout, so approvals must never read from either stream.
 *
 * Off by default: when an agent client such as Claude Code launches the gateway,
 * /dev/tty is the client's own TUI, which already reads every keystroke. The prompt
 * would draw over it and could never be answered. Set CERBERUS_TTY_APPROVAL=1 only
 * when the gateway runs in a terminal of its own; client-approval.ts covers clients.
 */
import { createReadStream, createWriteStream, openSync } from 'node:fs';
import { createInterface } from 'node:readline/promises';
import type { Interface } from 'node:readline/promises';
import type { ChangeDecision, FileChange, PolicyDecision } from '../shared/contracts.js';

/** Most rejected changes a person is asked to review in one prompt. More → no override offered. */
export const MAX_REVIEW_ITEMS = 12;

export interface TerminalApproval {
  policy(requestId: string, toolName: string, decision: PolicyDecision, target?: string): Promise<boolean>;
  changes(requestId: string, toolName: string, changes: readonly FileChange[], decisions: readonly ChangeDecision[], overrideablePaths?: readonly string[]): Promise<boolean>;
}

/** One override question, already sanitized for display. */
export interface ApprovalPrompt {
  /** Kept in diagnostics for correlation; omitted from the user decision text. */
  requestId: string;
  heading: string;
  detail: string;
  question: string;
  blockLabel: string;
  allowLabel: string;
  allowOverride: boolean;
}

export interface TerminalApprovalOptions {
  /** Prompt on /dev/tty. When false, every DENY is logged and kept. */
  interactive?: boolean;
}

export function describePolicyDeny(requestId: string, toolName: string, decision: PolicyDecision, target?: string): ApprovalPrompt {
  const targetText = target ? displayPolicyTarget(target) : undefined;
  return {
    requestId,
    heading: `Cerberus blocked ${policyAction(toolName)}`,
    detail: `${targetText ? `Target: ${targetText}\n` : ''}Reason: ${policyReason(decision.ruleId, decision.reason)}`,
    question: 'Allow once applies only to this call.',
    blockLabel: 'Keep blocked (recommended)',
    allowLabel: 'Allow this call once',
    allowOverride: true,
  };
}

function displayPolicyTarget(target: string): string {
  const value = safe(target).replace(/\\/g, '/').replace(/\/+$/, '');
  if (value === '/workspace') return 'project root';
  if (value.startsWith('/workspace/')) return value.slice('/workspace/'.length);
  if (value === '.' || value === './') return 'project root';
  if (value.startsWith('/') || /^[a-z]:\//i.test(value) || value === '..' || value.startsWith('../')) return 'outside the project';
  return value.replace(/^\.\//, '');
}

function policyReason(ruleId: PolicyDecision['ruleId'], fallback: string): string {
  switch (ruleId) {
    case 'PROTECTED_PATH': return 'This project path is protected by policy.';
    case 'PATH_NOT_ALLOWED': return 'This target is outside the project paths Cerberus allows.';
    case 'PERSISTENCE_PATH': return 'Cerberus protects this project file from changes.';
    case 'WRITE_NOT_ALLOWED': return 'Writes are limited to approved project paths.';
    case 'DEFAULT_DENY': return 'This tool is not approved by policy.';
    default: return safe(fallback);
  }
}

function policyAction(toolName: string): string {
  const name = toolName.split('/').at(-1)?.toLowerCase() ?? '';
  if (name.includes('write') || name.includes('create') || name.includes('edit')) return 'write';
  if (name.includes('read') || name.includes('get')) return 'read';
  if (name.includes('list') || name.includes('search')) return 'access';
  return 'action';
}

/** The prompt for sandbox-rejected changes, or a log line when there are too many to review. */
export function describeChangesDeny(
  requestId: string,
  toolName: string,
  changes: readonly FileChange[],
  decisions: readonly ChangeDecision[],
  overrideablePaths: readonly string[] = rejectedPathsByDefault(decisions),
): ApprovalPrompt {
  const rejected = decisions.filter((decision) => decision.decision === 'DENY');
  if (rejected.length > MAX_REVIEW_ITEMS) {
    return {
      requestId,
      heading: 'Cerberus sandbox blocked changes',
      detail: `${rejected.length} changes were rejected; the review limit is ${MAX_REVIEW_ITEMS}.`,
      question: 'This change batch cannot be overridden.',
      blockLabel: 'Keep changes blocked',
      allowLabel: '',
      allowOverride: false,
    };
  }
  const list = rejected.map((decision) => {
    const change = changes.find((item) => item.path === decision.path);
    return `• ${safe(decision.path)} — ${safe(decision.reason)} (${decision.ruleId}${change ? `; ${change.kind}` : ''})`;
  }).join('\n');
  const allowOverride = rejected.some((decision) => overrideablePaths.includes(decision.path));
  return {
    requestId,
    heading: 'Cerberus blocked sandbox changes',
    detail: `${safe(toolName)}\nChanges kept out:\n${list}`,
    question: allowOverride ? 'Apply only the eligible changes once?' : 'These changes cannot be overridden.',
    blockLabel: 'Keep changes out (recommended)',
    allowLabel: 'Apply these changes once',
    allowOverride,
  };
}

const NON_OVERRIDEABLE_RULES = new Set<ChangeDecision['ruleId']>([
  'INVALID_ARGUMENTS', 'EVALUATION_ERROR', 'CHANGE_LIMIT', 'WRITE_CONFLICT', 'SYMLINK_DENIED',
]);

function rejectedPathsByDefault(decisions: readonly ChangeDecision[]): string[] {
  return decisions.filter((decision) => decision.decision === 'DENY' && !NON_OVERRIDEABLE_RULES.has(decision.ruleId))
    .map((decision) => decision.path);
}

/** Runs prompts one at a time so concurrent MCP calls cannot consume one another's answers. */
export function createSerializer(): <T>(operation: () => Promise<T>) => Promise<T> {
  let pending: Promise<unknown> = Promise.resolve();
  return <T>(operation: () => Promise<T>): Promise<T> => {
    const result = pending.then(operation, operation);
    pending = result.then(() => undefined, () => undefined);
    return result;
  };
}

/**
 * Writes every DENY to stderr and, when interactive and a controlling terminal is
 * available, offers a one-time override. Lack of a terminal always means DENY.
 */
export function createTerminalApproval(options: TerminalApprovalOptions = {}): TerminalApproval {
  const serialize = createSerializer();

  const ask = ({ requestId, heading, detail, question, allowOverride }: ApprovalPrompt): Promise<boolean> => serialize(async () => {
    process.stderr.write(`[Cerberus] request ${safe(requestId)}\n${heading}\n${heading.toLowerCase().includes('sandbox') && detail ? `${detail}\n` : ''}`);
    if (!options.interactive) return false;
    if (!allowOverride) return false;
    let terminal: Interface | undefined;
    let input: ReturnType<typeof createReadStream> | undefined;
    let output: ReturnType<typeof createWriteStream> | undefined;
    try {
      input = createReadStream('/dev/tty', { fd: openSync('/dev/tty', 'r'), autoClose: true });
      output = createWriteStream('/dev/tty', { fd: openSync('/dev/tty', 'w'), autoClose: true });
      terminal = createInterface({ input, output, terminal: true });
      const answer = await terminal.question(`${question} [y/N] `);
      const approved = /^y(?:es)?$/i.test(answer.trim());
      process.stderr.write(approved
        ? '[Cerberus] One-time override approved for this request.\n'
        : '[Cerberus] Override declined; DENY enforced.\n');
      return approved;
    } catch {
      process.stderr.write('[Cerberus] No interactive terminal is available; keeping the DENY.\n');
      return false;
    } finally {
      terminal?.close();
      input?.destroy();
      output?.end();
    }
  });

  return {
    policy: (requestId, toolName, decision, target) => ask(describePolicyDeny(requestId, toolName, decision, target)),
    changes: (requestId, toolName, changes, decisions) => {
      const prompt = describeChangesDeny(requestId, toolName, changes, decisions);
      if ('refused' in prompt) {
        process.stderr.write(`${prompt.refused}\n`);
        return Promise.resolve(false);
      }
      return ask(prompt);
    },
  };
}

export function safe(value: string): string {
  return value.replace(/[\u0000-\u001f\u007f‪-‮⁦-⁩]/g, ' ').slice(0, 200);
}
