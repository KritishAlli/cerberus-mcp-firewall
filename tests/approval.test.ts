/**
 * One-request override paths: src/proxy/client-approval.ts (MCP form elicitation,
 * the agent client's dialog) and the opt-in terminal fallback.
 *
 * 1. Unit: createClientApproval with a fake ApprovalClient. Only an accepted form
 *    with decision "allow_once" approves; everything else keeps the DENY.
 * 2. Integration: agent Client → startProxyServer (InMemoryTransport) → interceptor
 *    with a DENY evaluator and a counting forward. The client's elicitation handler
 *    plays the user.
 */
import { Client } from '@modelcontextprotocol/client';
import { InMemoryTransport, type CallToolResult, type ElicitRequestFormParams, type ElicitResult, type Tool } from '@modelcontextprotocol/server';
import { describe, expect, it } from 'vitest';
import { createClientApproval, type ApprovalClient } from '../src/proxy/client-approval.js';
import { BLOCKED_PREFIX, createInterceptor } from '../src/proxy/interceptor.js';
import { startProxyServer } from '../src/proxy/server.js';
import { MAX_REVIEW_ITEMS, createTerminalApproval, type TerminalApproval } from '../src/proxy/terminal-approval.js';
import type { UpstreamConnection } from '../src/proxy/upstream.js';
import type { ChangeDecision, FileChange, FirewallPolicy, PolicyDecision } from '../src/shared/contracts.js';

const deny: PolicyDecision = { decision: 'DENY', ruleId: 'PROTECTED_PATH', reason: 'path matches a protected pattern' };

const policy: FirewallPolicy = {
  defaultDecision: 'DENY',
  protectedPaths: [],
  deniedDestinations: [],
  allowedRoots: ['.'],
  allowedHosts: [],
  approvedTools: [],
  deniedTools: [],
  pathArgs: ['path'],
  destinationArgs: {},
  destructiveTools: [],
  writeTools: [],
};

function fakeClient(answer: () => Promise<ElicitResult> | ElicitResult, supportsForm = true) {
  const asked: ElicitRequestFormParams[] = [];
  const client: ApprovalClient = {
    supportsFormElicitation: () => supportsForm,
    elicit: async (params) => {
      asked.push(params);
      return answer();
    },
  };
  return { client, asked };
}

function countingFallback(result: boolean) {
  const calls: string[] = [];
  const fallback: TerminalApproval = {
    policy: async () => (calls.push('policy'), result),
    changes: async () => (calls.push('changes'), result),
  };
  return { fallback, calls };
}

function rejected(count: number): { changes: FileChange[]; decisions: ChangeDecision[] } {
  const paths = Array.from({ length: count }, (_, i) => `package-${i}.json`);
  return {
    changes: paths.map((path): FileChange => ({ path, kind: 'modify' })),
    decisions: paths.map((path): ChangeDecision => ({ path, decision: 'DENY', ruleId: 'WRITE_NOT_ALLOWED', reason: 'protected write path' })),
  };
}

describe('createClientApproval', () => {
  it('approves only an accepted form with decision allow_once', async () => {
    const answers: [ElicitResult, boolean][] = [
      [{ action: 'accept', content: { decision: 'allow_once' } }, true],
      [{ action: 'accept', content: { decision: 'block' } }, false],
      [{ action: 'accept', content: { decision: 'ALLOW_ONCE' } }, false],
      [{ action: 'accept', content: { decision: true } }, false],
      [{ action: 'accept' }, false],
      [{ action: 'decline' }, false],
      [{ action: 'cancel' }, false],
    ];
    for (const [answer, expected] of answers) {
      const approval = createClientApproval({ log: () => {} });
      approval.attach(fakeClient(() => answer).client);
      expect(await approval.policy('req-1', 'fs/read_text_file', deny), JSON.stringify(answer)).toBe(expected);
    }
  });

  it('keeps the DENY when the dialog throws or times out', async () => {
    const logs: string[] = [];
    const approval = createClientApproval({ log: (line) => logs.push(line) });
    approval.attach(fakeClient(() => Promise.reject(new Error('Request timed out'))).client);
    expect(await approval.policy('req-1', 'fs/read_text_file', deny)).toBe(false);
    expect(logs.at(-1)).toContain('keeping the DENY');
  });

  it('asks a single required choice with Block preselected, and sanitizes the text', async () => {
    const { client, asked } = fakeClient(() => ({ action: 'decline' }));
    const approval = createClientApproval({ log: () => {} });
    approval.attach(client);
    await approval.policy('req-\u001b[31m1', 'fs/read_text_file', { ...deny, reason: 'bad‮reason' });
    const [form] = asked;
    expect(form!.mode).toBe('form');
    expect(form!.requestedSchema.required).toEqual(['decision']);
    expect(form!.requestedSchema.properties.decision).toMatchObject({ default: 'block' });
    expect(form!.message).toContain('PROTECTED_PATH');
    expect(form!.message).toContain('fs/read_text_file');
    expect(form!.message.replace(/\n/g, '')).not.toMatch(/[\u0000-\u001f‮]/);
  });

  it('uses the fallback before a client attaches and when it lacks form elicitation', async () => {
    const { fallback, calls } = countingFallback(false);
    const approval = createClientApproval({ fallback, log: () => {} });
    expect(await approval.policy('req-1', 'fs/x', deny)).toBe(false);

    const noForm = fakeClient(() => ({ action: 'accept', content: { decision: 'allow_once' } }), false);
    approval.attach(noForm.client);
    const { changes, decisions } = rejected(1);
    expect(await approval.changes('req-2', 'fs/write_file', changes, decisions)).toBe(false);
    expect(calls).toEqual(['policy', 'changes']);
    expect(noForm.asked).toHaveLength(0);
  });

  it('keeps the DENY with no client and no fallback', async () => {
    expect(await createClientApproval({ log: () => {} }).policy('req-1', 'fs/x', deny)).toBe(false);
  });

  it('lists rejected changes, and offers no override above the review limit', async () => {
    const { client, asked } = fakeClient(() => ({ action: 'accept', content: { decision: 'allow_once' } }));
    const approval = createClientApproval({ log: () => {} });
    approval.attach(client);

    const few = rejected(2);
    expect(await approval.changes('req-1', 'fs/write_file', few.changes, few.decisions)).toBe(true);
    expect(asked[0]!.message).toContain('package-1.json (WRITE_NOT_ALLOWED, modify');

    const many = rejected(MAX_REVIEW_ITEMS + 1);
    expect(await approval.changes('req-2', 'fs/write_file', many.changes, many.decisions)).toBe(false);
    expect(asked).toHaveLength(1);
  });

  it('asks one dialog at a time', async () => {
    let open = 0;
    let maxOpen = 0;
    const approval = createClientApproval({ log: () => {} });
    approval.attach(fakeClient(async () => {
      maxOpen = Math.max(maxOpen, ++open);
      await new Promise((resolve) => setTimeout(resolve, 5));
      open--;
      return { action: 'decline' };
    }).client);
    await Promise.all([1, 2, 3].map((n) => approval.policy(`req-${n}`, 'fs/x', deny)));
    expect(maxOpen).toBe(1);
  });
});

describe('createTerminalApproval', () => {
  it('keeps every DENY without prompting unless interactive', async () => {
    const terminal = createTerminalApproval();
    expect(await terminal.policy('req-1', 'fs/x', deny)).toBe(false);
    const { changes, decisions } = rejected(1);
    expect(await terminal.changes('req-2', 'fs/write_file', changes, decisions)).toBe(false);
  });
});

describe('override dialog through the proxy server', () => {
  const fakeUpstream: UpstreamConnection = {
    serverId: 'fs',
    connected: true,
    launch: { mode: 'local' } as UpstreamConnection['launch'],
    listTools: async (): Promise<Tool[]> => [],
    callTool: async () => ({ content: [] }),
    close: async () => {},
  };

  async function stack(options: { elicitation: boolean; answer?: ElicitResult }) {
    let forwards = 0;
    const asked: unknown[] = [];
    const approval = createClientApproval({ log: () => {} });
    const handler = createInterceptor({
      serverId: 'fs',
      policy,
      evaluate: () => deny,
      publish: () => {},
      forward: async (): Promise<CallToolResult> => (forwards++, { content: [{ type: 'text', text: 'downstream ran' }] }),
      log: () => {},
      terminalApproval: approval,
    });
    const [agentSide, proxySide] = InMemoryTransport.createLinkedPair();
    const proxy = await startProxyServer(fakeUpstream, handler, { transport: proxySide, onClient: approval.attach });
    const agent = new Client(
      { name: 'dialog-agent', version: '0.0.0' },
      { capabilities: options.elicitation ? { elicitation: { form: {} } } : {} },
    );
    if (options.elicitation) {
      agent.setRequestHandler('elicitation/create', async (request) => {
        asked.push(request.params);
        return options.answer ?? { action: 'decline' };
      });
    }
    await agent.connect(agentSide);
    const call = async () => (await agent.callTool({ name: 'read_text_file', arguments: { path: '.env' } })) as CallToolResult;
    return {
      call,
      asked,
      forwards: () => forwards,
      close: async () => {
        await agent.close().catch(() => {});
        await proxy.close().catch(() => {});
      },
    };
  }

  const text = (result: CallToolResult) => result.content.map((c) => (c.type === 'text' ? c.text : '')).join('');

  it('forwards the denied call once when the user picks allow_once', async () => {
    const s = await stack({ elicitation: true, answer: { action: 'accept', content: { decision: 'allow_once' } } });
    try {
      const result = await s.call();
      expect(s.asked).toHaveLength(1);
      expect(s.forwards()).toBe(1);
      expect(text(result)).toContain('downstream ran');
    } finally {
      await s.close();
    }
  });

  it('keeps the block when the user declines', async () => {
    const s = await stack({ elicitation: true, answer: { action: 'decline' } });
    try {
      const result = await s.call();
      expect(s.asked).toHaveLength(1);
      expect(s.forwards()).toBe(0);
      expect(text(result)).toContain(BLOCKED_PREFIX);
    } finally {
      await s.close();
    }
  });

  it('blocks without a dialog when the client has no elicitation capability', async () => {
    const s = await stack({ elicitation: false });
    try {
      const result = await s.call();
      expect(s.forwards()).toBe(0);
      expect(text(result)).toContain(BLOCKED_PREFIX);
    } finally {
      await s.close();
    }
  });
});
