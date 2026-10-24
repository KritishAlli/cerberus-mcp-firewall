/**
 * One-request overrides asked through the agent client's own UI (MCP form
 * elicitation), e.g. Claude Code's dialog. Design doc (cerberus.md) §6.
 *
 * Block is the default and only an explicit "allow_once" from an accepted form
 * approves. Decline, cancel, a malformed answer, an error, a timeout, or an
 * elicitation request the client rejects all keep the DENY. Clients that do not
 * advertise form elicitation fall back to `fallback` (the terminal path).
 */
import type { ElicitRequestFormParams, ElicitResult, RequestOptions } from '@modelcontextprotocol/server';
import type { ChangeDecision, FileChange, PolicyDecision } from '../shared/contracts.js';
import {
  createSerializer,
  describeChangesDeny,
  describePolicyDeny,
  type ApprovalPrompt,
  type TerminalApproval,
} from './terminal-approval.js';

/** How long a dialog may stay open before the DENY is kept. */
export const DEFAULT_APPROVAL_TIMEOUT_MS = 120_000;

const ALLOW_ONCE = 'allow_once';

/** The connected agent client, as seen by the approval path. src/proxy/server.ts provides it. */
export interface ApprovalClient {
  supportsFormElicitation(): boolean;
  elicit(params: ElicitRequestFormParams, options: RequestOptions): Promise<ElicitResult>;
}

export interface ClientApproval extends TerminalApproval {
  /** Called once the agent client has connected. Until then every approval uses the fallback. */
  attach(client: ApprovalClient): void;
}

export interface ClientApprovalOptions {
  /** Used when no client is attached or it lacks form elicitation. Missing → DENY. */
  fallback?: TerminalApproval;
  timeoutMs?: number;
  /** Diagnostics sink (one line, no trailing newline). Defaults to stderr. Never stdout. */
  log?: (line: string) => void;
}

export function createClientApproval(options: ClientApprovalOptions = {}): ClientApproval {
  const log = options.log ?? ((line: string) => process.stderr.write(`${line}\n`));
  const timeoutMs = options.timeoutMs ?? DEFAULT_APPROVAL_TIMEOUT_MS;
  const serialize = createSerializer();
  let client: ApprovalClient | undefined;

  const usable = (): ApprovalClient | undefined => {
    try {
      return client?.supportsFormElicitation() ? client : undefined;
    } catch {
      return undefined;
    }
  };

  const ask = (target: ApprovalClient, { requestId, heading, detail, question, blockLabel, allowLabel, allowOverride }: ApprovalPrompt): Promise<boolean> => serialize(async () => {
    log(`[Cerberus] request ${requestId}\n${heading}\n${detail}`);
    let approved = false;
    try {
      const result = await target.elicit(approvalForm(heading, detail, question, blockLabel, allowLabel, allowOverride), { timeout: timeoutMs });
      approved = allowOverride && result.action === 'accept' && result.content?.decision === ALLOW_ONCE;
    } catch (err) {
      log(`[Cerberus] Approval dialog failed (${err instanceof Error ? err.constructor.name : typeof err}); keeping the DENY.`);
      return false;
    }
    log(approved
      ? '[Cerberus] One-time override approved in the client for this request.'
      : '[Cerberus] Override not approved in the client; DENY enforced.');
    return approved;
  });

  return {
    attach: (connected) => {
      client = connected;
    },
    policy: (requestId, toolName, decision: PolicyDecision, requestedTarget?: string) => {
      const target = usable();
      if (!target) return options.fallback?.policy(requestId, toolName, decision, requestedTarget) ?? Promise.resolve(false);
      return ask(target, describePolicyDeny(requestId, toolName, decision, requestedTarget));
    },
    changes: (requestId, toolName, changes: readonly FileChange[], decisions: readonly ChangeDecision[], overrideablePaths?: readonly string[]) => {
      const target = usable();
      if (!target) return options.fallback?.changes(requestId, toolName, changes, decisions, overrideablePaths) ?? Promise.resolve(false);
      const prompt = describeChangesDeny(requestId, toolName, changes, decisions, overrideablePaths);
      return ask(target, prompt);
    },
  };
}

/** A single required choice, Block preselected. Text is already sanitized by describe*Deny. */
function approvalForm(heading: string, detail: string, question: string, blockLabel: string, allowLabel: string, allowOverride: boolean): ElicitRequestFormParams {
  const userMessage = `${heading}${detail ? `\n\n${detail}` : ''}\n\n${question}`;
  return {
    mode: 'form',
    message: userMessage,
    requestedSchema: {
      type: 'object',
      properties: {
        decision: {
          type: 'string',
          title: 'Action',
          oneOf: [
            { const: 'block', title: blockLabel },
            ...(allowOverride ? [{ const: ALLOW_ONCE, title: allowLabel }] : []),
          ],
          default: 'block',
        },
      },
      required: ['decision'],
    },
  };
}
