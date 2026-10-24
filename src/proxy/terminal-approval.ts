/** Interactive, one-request approvals through the parent's controlling terminal.
 * MCP stdio owns stdin/stdout, so approvals must never read from either stream.
 */
import { createReadStream, createWriteStream, openSync } from 'node:fs';
import { createInterface } from 'node:readline/promises';
import type { Interface } from 'node:readline/promises';
import type { ChangeDecision, FileChange, PolicyDecision } from '../shared/contracts.js';

const MAX_TERMINAL_ITEMS = 12;

export interface TerminalApproval {
  policy(requestId: string, toolName: string, decision: PolicyDecision): Promise<boolean>;
  changes(requestId: string, toolName: string, changes: readonly FileChange[], decisions: readonly ChangeDecision[]): Promise<boolean>;
}

/**
 * Writes every DENY to stderr and, when a controlling terminal is available,
 * offers a one-time override. Prompts are serialized so concurrent MCP calls
 * cannot consume one another's answers. Lack of a terminal always means DENY.
 */
export function createTerminalApproval(): TerminalApproval {
  let pending: Promise<unknown> = Promise.resolve();

  const serialize = <T>(operation: () => Promise<T>): Promise<T> => {
    const result = pending.then(operation, operation);
    pending = result.then(() => undefined, () => undefined);
    return result;
  };

  const ask = (heading: string, detail: string, question: string): Promise<boolean> => serialize(async () => {
    process.stderr.write(`${heading}\n${detail}\n`);
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
    policy: (requestId, toolName, decision) => ask(
      `[Cerberus] DENY request ${safe(requestId)}: ${safe(toolName)} (${decision.ruleId})`,
      `Reason: ${safe(decision.reason)}`,
      'Override this firewall DENY for this request only?',
    ),
    changes: (requestId, toolName, changes, decisions) => {
      const rejected = decisions.filter((decision) => decision.decision === 'DENY');
      if (rejected.length > MAX_TERMINAL_ITEMS) {
        process.stderr.write(`[Cerberus] SANDBOX DENY request ${safe(requestId)}: ${rejected.length} rejected changes exceed the ${MAX_TERMINAL_ITEMS}-item review limit; no override offered.\n`);
        return Promise.resolve(false);
      }
      const list = rejected.slice(0, MAX_TERMINAL_ITEMS).map((decision) => {
        const change = changes.find((item) => item.path === decision.path);
        return `${safe(decision.path)} (${decision.ruleId}${change ? `, ${change.kind}` : ''}: ${safe(decision.reason)})`;
      }).join(', ');
      return ask(
        `[Cerberus] SANDBOX DENY request ${safe(requestId)}: ${safe(toolName)}`,
        `Rejected changes: ${list}`,
        'Apply these sandbox-rejected changes to the project for this request only?',
      );
    },
  };
}

function safe(value: string): string {
  return value.replace(/[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/g, ' ').slice(0, 200);
}
