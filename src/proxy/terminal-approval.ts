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
  policy(requestId: string, toolName: string, decision: PolicyDecision): Promise<boolean>;
  changes(requestId: string, toolName: string, changes: readonly FileChange[], decisions: readonly ChangeDecision[]): Promise<boolean>;
}

/** One override question, already sanitized for display. */
export interface ApprovalPrompt {
  heading: string;
  detail: string;
  question: string;
}

export interface TerminalApprovalOptions {
  /** Prompt on /dev/tty. When false, every DENY is logged and kept. */
  interactive?: boolean;
}

export function describePolicyDeny(requestId: string, toolName: string, decision: PolicyDecision): ApprovalPrompt {
  return {
    heading: `[Cerberus] DENY request ${safe(requestId)}: ${safe(toolName)} (${decision.ruleId})`,
    detail: `Reason: ${safe(decision.reason)}`,
    question: 'Override this firewall DENY for this request only?',
  };
}

/** The prompt for sandbox-rejected changes, or a log line when there are too many to review. */
export function describeChangesDeny(
  requestId: string,
  toolName: string,
  changes: readonly FileChange[],
  decisions: readonly ChangeDecision[],
): ApprovalPrompt | { refused: string } {
  const rejected = decisions.filter((decision) => decision.decision === 'DENY');
  if (rejected.length > MAX_REVIEW_ITEMS) {
    return { refused: `[Cerberus] SANDBOX DENY request ${safe(requestId)}: ${rejected.length} rejected changes exceed the ${MAX_REVIEW_ITEMS}-item review limit; no override offered.` };
  }
  const list = rejected.map((decision) => {
    const change = changes.find((item) => item.path === decision.path);
    return `${safe(decision.path)} (${decision.ruleId}${change ? `, ${change.kind}` : ''}: ${safe(decision.reason)})`;
  }).join(', ');
  return {
    heading: `[Cerberus] SANDBOX DENY request ${safe(requestId)}: ${safe(toolName)}`,
    detail: `Rejected changes: ${list}`,
    question: 'Apply these sandbox-rejected changes to the project for this request only?',
  };
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

  const ask = ({ heading, detail, question }: ApprovalPrompt): Promise<boolean> => serialize(async () => {
    process.stderr.write(`${heading}\n${detail}\n`);
    if (!options.interactive) return false;
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
    policy: (requestId, toolName, decision) => ask(describePolicyDeny(requestId, toolName, decision)),
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
