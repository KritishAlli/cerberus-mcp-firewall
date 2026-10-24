/**
 * Cerberus task 4.1.1 audit (docs/cerberus-proxy-audit.md): no forward on DENY, fail
 * closed, publish isolation, Docker preflight/flags/cleanup, staged-call integration.
 *
 * Tests named "GAP …" use it.fails: they assert what the plan requires and pass only
 * while the code falls short of it. When a gap is fixed, the test fails: turn it into
 * a plain it(…) then.
 */
import { mkdtemp, readFile, rm, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { InMemoryTransport, McpServer, type CallToolResult } from '@modelcontextprotocol/server';
import { afterEach, describe, expect, it } from 'vitest';
import { loadConfig, toUpstreamLaunch } from '../src/config/load.js';
import {
  BLOCKED_PREFIX,
  createInterceptor,
  DOWNSTREAM_ERROR_PREFIX,
  FIREWALL_META_KEY,
  type InterceptorDeps,
} from '../src/proxy/interceptor.js';
import { startProxyServer } from '../src/proxy/server.js';
import {
  defaultEvaluateFileChanges,
  initStaging,
  STAGED_META_KEY,
  STAGING_ERROR_PREFIX,
  type StagingAreaLike,
  type StagingDeps,
} from '../src/proxy/staged-call.js';
import { createStagingArea, StagingLock, type StagingArea } from '../src/proxy/staging.js';
import {
  buildDockerArgs,
  connectUpstream,
  SandboxUnavailableError,
  sweepOrphanedContainers,
  type ExecFileFn,
  type UpstreamConnection,
} from '../src/proxy/upstream.js';
import type {
  EvaluateFileChanges,
  FileChange,
  FirewallEvent,
  FirewallPolicy,
  PolicyDecision,
} from '../src/shared/contracts.js';
import { z } from 'zod';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const fixture = path.join(repoRoot, 'tests/fixtures/audit-stdio-server.mjs');

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

const ALLOW: PolicyDecision = { decision: 'ALLOW', ruleId: 'APPROVED_TOOL', reason: 'test allow' };
const DENY: PolicyDecision = { decision: 'DENY', ruleId: 'DENIED_TOOL', reason: 'test deny' };

const cleanups: (() => Promise<unknown>)[] = [];
afterEach(async () => {
  for (const fn of cleanups.splice(0).reverse()) await fn().catch(() => {});
});

/** Interceptor with recording spies. Every forward (default or override) is counted; the default returns a fixed success. */
function harness(overrides: Partial<InterceptorDeps> = {}) {
  const order: string[] = [];
  const events: FirewallEvent[] = [];
  let forwards = 0;
  const { forward: forwardOverride, ...rest } = overrides;
  const forward: InterceptorDeps['forward'] =
    forwardOverride ?? (async () => ({ content: [{ type: 'text', text: 'downstream ok' }] }));
  const handler = createInterceptor({
    serverId: 'fs',
    policy,
    evaluate: () => {
      order.push('evaluate');
      return ALLOW;
    },
    publish: (e) => {
      order.push('publish');
      events.push(e);
    },
    log: () => {},
    ...rest,
    forward: (...args) => {
      order.push('forward');
      forwards += 1;
      return forward(...args);
    },
  });
  return { handler, order, events, forwards: () => forwards };
}

function textOf(result: CallToolResult): string {
  return result.content.map((c) => (c.type === 'text' ? c.text : '')).join('\n');
}

// ---------------------------------------------------------------------------
// 1a. No forward on DENY
// ---------------------------------------------------------------------------

describe('1a no forward on DENY', () => {
  it('evaluates before forwarding, publishes once, forwards once on ALLOW', async () => {
    const h = harness();
    const result = await h.handler('read_text_file', { path: 'README.md' });
    expect(textOf(result)).toBe('downstream ok');
    expect(h.order).toEqual(['evaluate', 'publish', 'forward']);
  });

  it('every DENY path returns BLOCKED without calling forward', async () => {
    const cases: { name: string; deps: Partial<InterceptorDeps>; tool: unknown; args: unknown; ruleId: string }[] = [
      { name: 'policy DENY', deps: { evaluate: () => DENY }, tool: 't', args: {}, ruleId: 'DENIED_TOOL' },
      { name: 'args is an array', deps: {}, tool: 't', args: ['x'], ruleId: 'INVALID_ARGUMENTS' },
      { name: 'args is null', deps: {}, tool: 't', args: null, ruleId: 'INVALID_ARGUMENTS' },
      { name: 'non-plain object', deps: {}, tool: 't', args: new Map([['a', 1]]), ruleId: 'INVALID_ARGUMENTS' },
      { name: 'NaN value', deps: {}, tool: 't', args: { n: Number.NaN }, ruleId: 'INVALID_ARGUMENTS' },
      { name: 'function value', deps: {}, tool: 't', args: { f: () => 1 }, ruleId: 'INVALID_ARGUMENTS' },
      { name: 'empty tool name', deps: {}, tool: '', args: {}, ruleId: 'INVALID_ARGUMENTS' },
      { name: 'non-string tool name', deps: {}, tool: 42, args: {}, ruleId: 'INVALID_ARGUMENTS' },
      {
        name: 'evaluator throws',
        deps: {
          evaluate: () => {
            throw new Error('boom');
          },
        },
        tool: 't',
        args: {},
        ruleId: 'EVALUATION_ERROR',
      },
      { name: 'evaluator returns garbage', deps: { evaluate: () => ({ decision: 'MAYBE' }) as never }, tool: 't', args: {}, ruleId: 'EVALUATION_ERROR' },
      { name: 'evaluator returns a Promise', deps: { evaluate: (async () => ALLOW) as never }, tool: 't', args: {}, ruleId: 'EVALUATION_ERROR' },
    ];
    let deep: Record<string, unknown> = {};
    for (let i = 0; i < 70; i++) deep = { d: deep };
    cases.push({ name: 'nesting deeper than 64', deps: {}, tool: 't', args: deep, ruleId: 'INVALID_ARGUMENTS' });

    for (const c of cases) {
      const h = harness(c.deps);
      const result = await h.handler(c.tool, c.args);
      expect(result.isError, c.name).toBe(true);
      expect(textOf(result), c.name).toContain(`${BLOCKED_PREFIX} (${c.ruleId})`);
      expect(result._meta?.[FIREWALL_META_KEY], c.name).toMatchObject({ decision: 'DENY', ruleId: c.ruleId });
      expect(h.forwards(), c.name).toBe(0);
      expect(h.order, c.name).not.toContain('forward');
    }
  });

  it('a DENY with staging configured never touches staging or the downstream', async () => {
    let touched = 0;
    const area = new Proxy({} as StagingAreaLike, {
      get: () => () => {
        touched += 1;
        throw new Error('staging must not be used for a DENY');
      },
    });
    const h = harness({ evaluate: () => DENY, staging: { area, lock: new StagingLock(), policy } });
    const result = await h.handler('write_file', { path: 'package.json' });
    expect(textOf(result)).toContain(BLOCKED_PREFIX);
    expect(h.forwards()).toBe(0);
    expect(touched).toBe(0);
  });

  it('through the real MCP server: a denied tools/call never reaches the downstream', async () => {
    let downstreamCalls = 0;
    const server = new McpServer({ name: 'down', version: '0' });
    server.registerTool('echo', { inputSchema: { text: z.string() } }, async ({ text }) => {
      downstreamCalls += 1;
      return { content: [{ type: 'text', text }] };
    });
    const [upClient, upServer] = InMemoryTransport.createLinkedPair();
    await server.connect(upServer);
    const client = new Client({ name: 'up', version: '0' });
    await client.connect(upClient);
    const upstream: UpstreamConnection = {
      serverId: 'fs',
      connected: true,
      launch: { mode: 'local', sandboxed: false },
      listTools: async () => (await client.listTools()).tools,
      callTool: async (name, args) => (await client.callTool({ name, arguments: args })) as CallToolResult,
      close: async () => {
        await client.close();
      },
    };
    const handler = createInterceptor({
      serverId: 'fs',
      policy,
      evaluate: (ctx) => (ctx.arguments.text === 'deny me' ? DENY : ALLOW),
      publish: () => {},
      forward: (name, args) => upstream.callTool(name, args),
      log: () => {},
    });
    const [agentT, proxyT] = InMemoryTransport.createLinkedPair();
    const proxy = await startProxyServer(upstream, handler, { transport: proxyT });
    const agent = new Client({ name: 'agent', version: '0' });
    await agent.connect(agentT);
    cleanups.push(() => agent.close(), () => proxy.close(), () => upstream.close(), () => server.close());

    const denied = (await agent.callTool({ name: 'echo', arguments: { text: 'deny me' } })) as CallToolResult;
    expect(denied.isError).toBe(true);
    expect(downstreamCalls).toBe(0);
    const allowed = (await agent.callTool({ name: 'echo', arguments: { text: 'hi' } })) as CallToolResult;
    expect(textOf(allowed)).toBe('hi');
    expect(downstreamCalls).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// 1b. Fail closed (downstream side; evaluator/input cases are in 1a)
// ---------------------------------------------------------------------------

describe('1b fail closed', () => {
  it('a downstream timeout is a DOWNSTREAM ERROR (timeout), never a success', async () => {
    const server = new McpServer({ name: 'down', version: '0' });
    server.registerTool('hang', { description: 'never returns' }, () => new Promise<CallToolResult>(() => {}));
    const [a, b] = InMemoryTransport.createLinkedPair();
    await server.connect(b);
    const client = new Client({ name: 'up', version: '0' });
    await client.connect(a);
    cleanups.push(() => client.close(), () => server.close());

    const h = harness({
      forward: (name, args) => client.callTool({ name, arguments: args }, { timeout: 200 }) as Promise<CallToolResult>,
    });
    const result = await h.handler('hang', {});
    expect(result.isError).toBe(true);
    expect(textOf(result)).toContain(DOWNSTREAM_ERROR_PREFIX);
    expect(result._meta?.[FIREWALL_META_KEY]).toMatchObject({ downstreamError: 'timeout' });
  });

  it('a real downstream crash: the in-flight call and every later call fail closed (upstream.ts)', async () => {
    const upstream = await connectUpstream(
      { id: 'fs', command: process.execPath, args: [fixture], timeoutMs: 5_000 },
      { launch: { mode: 'local', command: process.execPath, args: [fixture] } },
    );
    cleanups.push(() => upstream.close());
    const h = harness({ forward: (name, args, options) => upstream.callTool(name, args, options) });

    expect(textOf(await h.handler('echo', { text: 'before' }))).toBe('before');
    const crashed = await h.handler('crash', {});
    expect(crashed.isError).toBe(true);
    expect(textOf(crashed)).toContain(DOWNSTREAM_ERROR_PREFIX);
    await expect.poll(() => upstream.connected).toBe(false);

    const after = await h.handler('echo', { text: 'after' });
    expect(after.isError).toBe(true);
    expect(after._meta?.[FIREWALL_META_KEY]).toMatchObject({ decision: 'ALLOW', downstreamError: 'not_connected' });
  });
});

// ---------------------------------------------------------------------------
// 1c. Publishing cannot change the decision
// ---------------------------------------------------------------------------

describe('1c event publishing cannot change the decision', () => {
  const throwing = () => {
    throw new Error('publish failed');
  };

  it('publish throwing on a DENY: still BLOCKED, still not forwarded', async () => {
    const h = harness({ evaluate: () => DENY, publish: throwing });
    const result = await h.handler('t', {});
    expect(textOf(result)).toContain(`${BLOCKED_PREFIX} (DENIED_TOOL)`);
    expect(h.forwards()).toBe(0);
  });

  it('publish throwing on an ALLOW: forwarded once, result unchanged', async () => {
    const h = harness({ publish: throwing });
    const result = await h.handler('t', {});
    expect(textOf(result)).toBe('downstream ok');
    expect(h.forwards()).toBe(1);
  });

  it('publish mutating the event it receives does not flip a DENY', async () => {
    const h = harness({
      evaluate: () => DENY,
      publish: (e) => {
        (e as { decision: string }).decision = 'ALLOW';
      },
    });
    const result = await h.handler('t', {});
    expect(textOf(result)).toContain(BLOCKED_PREFIX);
    expect(h.forwards()).toBe(0);
  });

  // PublishEvent is typed `(event) => void`, which an async function also satisfies.
  it('a thenable returned by publish is observed with a rejection handler', async () => {
    let observed = false;
    const thenable = {
      then(_resolve: unknown, reject: unknown) {
        observed = typeof reject === 'function';
      },
    };
    const h = harness({ evaluate: () => DENY, publish: (() => thenable) as never });
    await h.handler('t', {});
    expect(observed).toBe(true);
  });

  it('publish returning a rejected promise: same decision and result, a redacted log line, no unhandled rejection', async () => {
    const unhandled: unknown[] = [];
    const onUnhandled = (reason: unknown) => unhandled.push(reason);
    process.on('unhandledRejection', onUnhandled);
    const logs: string[] = [];
    const rejecting = (async () => {
      throw Object.assign(new Error('bus down while handling ARG-SECRET-VALUE'), { code: 'EBUSDOWN' });
    }) as never;
    try {
      const denied = harness({ evaluate: () => DENY, publish: rejecting, log: (l) => logs.push(l) });
      const deniedResult = await denied.handler('t', { path: 'ARG-SECRET-VALUE' });
      expect(textOf(deniedResult)).toContain(`${BLOCKED_PREFIX} (DENIED_TOOL)`);
      expect(denied.forwards()).toBe(0);

      const allowed = harness({ publish: rejecting, log: (l) => logs.push(l) });
      expect(textOf(await allowed.handler('t', { path: 'ARG-SECRET-VALUE' }))).toBe('downstream ok');
      expect(allowed.forwards()).toBe(1);

      await new Promise((r) => setTimeout(r, 20));
    } finally {
      process.off('unhandledRejection', onUnhandled);
    }
    expect(unhandled).toEqual([]);
    const failures = logs.filter((l) => l.includes('publish failed'));
    expect(failures).toHaveLength(2);
    expect(failures[0]).toMatch(/publish failed: Error code=EBUSDOWN$/);
    expect(logs.join('\n')).not.toContain('ARG-SECRET-VALUE');
    expect(logs.join('\n')).not.toContain('bus down');
  });
});

// ---------------------------------------------------------------------------
// 1d. Docker preflight, no local fallback
// ---------------------------------------------------------------------------

describe('1d Docker preflight and no local fallback', () => {
  async function dockerLaunchAttempt(execFile: ExecFileFn) {
    const workspaceDir = await mkdtemp(path.join(tmpdir(), 'mcpfw-audit-ws-'));
    cleanups.push(() => rm(workspaceDir, { recursive: true, force: true }));
    let spawned = 0;
    const attempt = connectUpstream(
      { id: 'fs', command: 'node', args: ['/app/server.js'], timeoutMs: 1_000 },
      {
        launch: { mode: 'docker', image: 'mcp-firewall-sandbox:dev', command: 'node', args: ['/app/server.js'], workspaceDir },
        execFile,
        createTransport: () => {
          spawned += 1;
          throw new Error('must not spawn');
        },
      },
    );
    return { attempt, spawned: () => spawned };
  }

  it('docker CLI missing or daemon down: SandboxUnavailableError, nothing spawned, nothing pulled', async () => {
    const calls: string[][] = [];
    const { attempt, spawned } = await dockerLaunchAttempt(async (_file, args) => {
      calls.push([...args]);
      throw Object.assign(new Error('spawn docker ENOENT'), { code: 'ENOENT' });
    });
    await expect(attempt).rejects.toBeInstanceOf(SandboxUnavailableError);
    expect(spawned()).toBe(0);
    expect(calls.flat()).not.toContain('pull');
  });

  it('image missing: SandboxUnavailableError, nothing spawned, nothing pulled', async () => {
    const calls: string[][] = [];
    const { attempt, spawned } = await dockerLaunchAttempt(async (_file, args) => {
      calls.push([...args]);
      if (args[0] === 'image') throw Object.assign(new Error('no such image'), { code: 1 });
      return { stdout: '29.9.2\n', stderr: '' };
    });
    await expect(attempt).rejects.toBeInstanceOf(SandboxUnavailableError);
    expect(spawned()).toBe(0);
    expect(calls.map((c) => c[0])).toEqual(['version', 'image']);
  });

  it('the runtime launch for a sandbox config is always docker, and needs a staging dir', () => {
    const config = loadConfig(path.join(repoRoot, 'config/sandbox.yaml'));
    expect(config.server.sandbox).toBeDefined();
    expect(() => toUpstreamLaunch(config.server, undefined)).toThrow();
    const stagingDir = tmpdir();
    expect(toUpstreamLaunch(config.server, stagingDir)).toMatchObject({ mode: 'docker', workspaceDir: stagingDir });
  });
});

// ---------------------------------------------------------------------------
// 1e. Docker flags
// ---------------------------------------------------------------------------

describe('1e Docker flags', () => {
  it('builds the planned argv exactly', async () => {
    const ws = await mkdtemp(path.join(tmpdir(), 'mcpfw-audit-ws-'));
    cleanups.push(() => rm(ws, { recursive: true, force: true }));
    const real = await import('node:fs').then((fs) => fs.realpathSync(ws));
    const argv = buildDockerArgs(
      { mode: 'docker', image: 'img:dev', command: 'node', args: ['/app/s.js'], workspaceDir: ws, user: '501:20' },
      { containerName: 'mcpfw-abc123', ownerPid: 777, host: 'audit-host' },
    );
    expect(argv).toEqual([
      'run', '--rm', '-i', '--pull=never',
      '--name', 'mcpfw-abc123',
      '--network', 'none',
      '--read-only',
      '--cap-drop', 'ALL',
      '--security-opt', 'no-new-privileges',
      '--user', '501:20',
      '--pids-limit', '128',
      '--memory', '512m',
      '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m',
      '--mount', `type=bind,src=${real},dst=/workspace`,
      '--label', 'mcp-firewall=1',
      '--label', 'mcp-firewall.pid=777',
      '--label', 'mcp-firewall.host=audit-host',
      '--label', `mcp-firewall.staging=${real}`,
      '-w', '/workspace',
      'img:dev', 'node', '/app/s.js',
    ]);
  });

  // Preflight checks the image with `docker image inspect`; without --pull=never, `docker run`
  // would pull an image removed between preflight and run. Real-Docker check: upstream-docker.test.ts.
  it('docker run passes --pull=never before the image, and labels the container with this process', async () => {
    const ws = await mkdtemp(path.join(tmpdir(), 'mcpfw-audit-ws-'));
    cleanups.push(() => rm(ws, { recursive: true, force: true }));
    const argv = buildDockerArgs({ mode: 'docker', image: 'img:dev', command: 'node', workspaceDir: ws });
    const beforeImage = argv.slice(0, argv.indexOf('img:dev'));
    expect(beforeImage).toContain('--pull=never');
    expect(beforeImage).toContain(`mcp-firewall.pid=${process.pid}`);
  });
});

// ---------------------------------------------------------------------------
// 1f. Container cleanup (paths with a test seam; signals and SIGKILL are manual, see the audit doc)
// ---------------------------------------------------------------------------

describe('1f container cleanup', () => {
  async function dockerUpstreamOverFixture() {
    const ws = await mkdtemp(path.join(tmpdir(), 'mcpfw-audit-ws-'));
    cleanups.push(() => rm(ws, { recursive: true, force: true }));
    const dockerCalls: string[][] = [];
    let dockerArgv: string[] = [];
    const upstream = await connectUpstream(
      { id: 'fs', command: 'node', args: [], timeoutMs: 5_000 },
      {
        launch: { mode: 'docker', image: 'mcp-firewall-sandbox:dev', command: 'node', workspaceDir: ws },
        execFile: async (_file, args) => {
          dockerCalls.push([...args]);
          return { stdout: '', stderr: '' };
        },
        // Stand-in for `docker run`: the real argv is recorded, the fixture runs locally.
        createTransport: (params) => {
          dockerArgv = params.args ?? [];
          return new StdioClientTransport({ command: process.execPath, args: [fixture], stderr: 'pipe' });
        },
      },
    );
    cleanups.push(() => upstream.close());
    const name = upstream.launch.containerName!;
    const removals = () => dockerCalls.filter((c) => c[0] === 'rm' && c[1] === '-f' && c[2] === name).length;
    return { upstream, name, dockerArgv: () => dockerArgv, removals };
  }

  it('runs with --rm and removes the container on close()', async () => {
    const { upstream, name, dockerArgv, removals } = await dockerUpstreamOverFixture();
    expect(dockerArgv().slice(0, 2)).toEqual(['run', '--rm']);
    expect(dockerArgv()).toContain(name);
    await upstream.close();
    expect(removals()).toBe(1);
  });

  it('removes the container when the downstream exits on its own', async () => {
    const { upstream, removals } = await dockerUpstreamOverFixture();
    await upstream.callTool('crash', {}).catch(() => {});
    await expect.poll(removals).toBe(1);
    expect(upstream.connected).toBe(false);
  });

  // Real Docker (SIGKILLed firewall, live instance, new instance): upstream-docker.test.ts.
  it('the sweep removes only our-labeled containers of dead firewalls on this host, never a live one', async () => {
    const listing = [
      'mcpfw-aaaaaaaaaaaa\t111\tthis-host', // dead firewall, this host → removed
      'mcpfw-bbbbbbbbbbbb\t222\tthis-host', // live firewall → kept
      `mcpfw-cccccccccccc\t${process.pid}\tthis-host`, // this process → kept
      'mcpfw-dddddddddddd\t111\tother-host', // another machine on a shared daemon → kept
      'mcpfw-eeeeeeeeeeee\t\tthis-host', // no pid label → kept
      'mcpfw-ffffffffffff\t0\tthis-host', // invalid pid → kept
      'someone-else\t111\tthis-host', // not our name → kept
      '',
    ].join('\n');
    const calls: string[][] = [];
    const logs: string[] = [];
    const removed = await sweepOrphanedContainers({
      host: 'this-host',
      isAlive: (pid) => pid !== 111,
      log: (l) => logs.push(l),
      execFile: async (_file, args) => {
        calls.push([...args]);
        return { stdout: args[0] === 'ps' ? listing : '', stderr: '' };
      },
    });
    expect(removed).toEqual(['mcpfw-aaaaaaaaaaaa']);
    expect(calls[0]?.slice(0, 4)).toEqual(['ps', '-a', '--filter', 'label=mcp-firewall=1']);
    expect(calls.filter((c) => c[0] === 'rm')).toEqual([['rm', '-f', 'mcpfw-aaaaaaaaaaaa']]);
    expect(logs).toEqual(['[firewall] removed 1 orphaned sandbox container(s) of dead firewalls: mcpfw-aaaaaaaaaaaa']);
  });

  it('a failing sweep never throws: a failed listing or removal is logged and skipped', async () => {
    const logs: string[] = [];
    await expect(
      sweepOrphanedContainers({
        log: (l) => logs.push(l),
        execFile: async () => {
          throw Object.assign(new Error('daemon gone'), { code: 'ECONNREFUSED' });
        },
      }),
    ).resolves.toEqual([]);
    expect(logs).toEqual(['[firewall] container sweep skipped: could not list containers (ECONNREFUSED)']);

    logs.length = 0;
    const removed = await sweepOrphanedContainers({
      host: 'h',
      isAlive: () => false,
      log: (l) => logs.push(l),
      execFile: async (_file, args) => {
        if (args[0] === 'rm' && args[2] === 'mcpfw-aaaaaaaaaaaa') throw Object.assign(new Error('busy'), { code: 1 });
        return { stdout: args[0] === 'ps' ? 'mcpfw-aaaaaaaaaaaa\t5\th\nmcpfw-bbbbbbbbbbbb\t6\th\n' : '', stderr: '' };
      },
    });
    expect(removed).toEqual(['mcpfw-bbbbbbbbbbbb']);
    expect(logs[0]).toBe('[firewall] could not remove orphaned container mcpfw-aaaaaaaaaaaa (exit 1)');
  });

  it('connectUpstream sweeps after preflight and before launching, and a failed sweep still launches in Docker', async () => {
    const ws = await mkdtemp(path.join(tmpdir(), 'mcpfw-audit-ws-'));
    cleanups.push(() => rm(ws, { recursive: true, force: true }));
    const order: string[] = [];
    let params: { command?: string; args?: string[] } | undefined;
    await connectUpstream(
      { id: 'fs', command: 'node', args: [], timeoutMs: 1_000 },
      {
        launch: { mode: 'docker', image: 'mcp-firewall-sandbox:dev', command: 'node', workspaceDir: ws },
        execFile: async (_file, args) => {
          order.push(args[0]!);
          if (args[0] === 'ps') throw Object.assign(new Error('ps failed'), { code: 'EIO' });
          return { stdout: '', stderr: '' };
        },
        createTransport: (p) => {
          order.push('launch');
          params = p;
          throw new Error('stop before spawning');
        },
      },
    ).catch(() => {});
    expect(order).toEqual(['version', 'image', 'ps', 'launch']);
    expect(params?.command).toBe('docker');
    expect(params?.args?.slice(0, 4)).toEqual(['run', '--rm', '-i', '--pull=never']);
  });
});

// ---------------------------------------------------------------------------
// 1g. Staged-call integration (real StagingArea on a temp project)
// ---------------------------------------------------------------------------

describe('1g staged-call integration', () => {
  async function stagedProject(evaluateFileChanges?: EvaluateFileChanges, wrap?: (a: StagingArea) => StagingAreaLike) {
    const project = await mkdtemp(path.join(tmpdir(), 'mcpfw-audit-project-'));
    await mkdir(path.join(project, 'src'));
    await writeFile(path.join(project, 'src/a.js'), 'original\n');
    await writeFile(path.join(project, 'package.json'), '{"name":"demo"}\n');
    const area = await createStagingArea({ projectRoot: project, maxFileBytes: 65_536, maxChangesPerCall: 20 });
    cleanups.push(() => rm(project, { recursive: true, force: true }), () => area.dispose());
    const initial = await area.sync();
    const deps: StagingDeps = {
      area: wrap ? wrap(area) : area,
      lock: new StagingLock(),
      policy,
      ...(evaluateFileChanges ? { evaluateFileChanges } : {}),
      onFileChangeEvent: () => {},
    };
    await initStaging(deps, { serverId: 'fs', initial, log: () => {} });
    const inStaging = (rel: string) => path.join(area.stagingRoot, rel);
    const inProject = (rel: string) => path.join(project, rel);
    return { deps, area, inStaging, inProject };
  }
  const allowAll: EvaluateFileChanges = (changes) =>
    changes.map((c) => ({ path: c.path, decision: 'ALLOW', ruleId: 'APPROVED_TOOL', reason: 'test' }));

  it('diffs and reverts after a downstream timeout; nothing reaches the project (reject-all default)', async () => {
    const s = await stagedProject();
    const h = harness({
      staging: s.deps,
      forward: async () => {
        await writeFile(s.inStaging('src/a.js'), 'written before the timeout\n');
        throw Object.assign(new Error('timed out'), { code: 'REQUEST_TIMEOUT' });
      },
    });
    const result = await h.handler('write_file', { path: 'src/a.js' });
    expect(result.isError).toBe(true);
    expect(result._meta?.[FIREWALL_META_KEY]).toMatchObject({ downstreamError: 'timeout' });
    expect(result._meta?.[STAGED_META_KEY]).toMatchObject({ applied: 0, rejected: 1 });
    expect(await readFile(s.inProject('src/a.js'), 'utf8')).toBe('original\n');
    expect(await readFile(s.inStaging('src/a.js'), 'utf8')).toBe('original\n');
  });

  it('serializes staged calls under the lock', async () => {
    const s = await stagedProject();
    let active = 0;
    let maxActive = 0;
    const h = harness({
      staging: s.deps,
      forward: async () => {
        active += 1;
        maxActive = Math.max(maxActive, active);
        await new Promise((r) => setTimeout(r, 30));
        active -= 1;
        return { content: [{ type: 'text', text: 'ok' }] };
      },
    });
    await Promise.all([h.handler('t', {}), h.handler('t', {}), h.handler('t', {})]);
    expect(h.forwards()).toBe(3);
    expect(maxActive).toBe(1);
  });

  it('WRITE_CONFLICT: an approved change is skipped when the user edited the file during the call', async () => {
    const s = await stagedProject(allowAll);
    const h = harness({
      staging: s.deps,
      forward: async () => {
        await writeFile(s.inStaging('src/a.js'), 'from the server\n');
        await writeFile(s.inProject('src/a.js'), 'user edit\n');
        return { content: [{ type: 'text', text: 'ok' }] };
      },
    });
    const result = await h.handler('write_file', { path: 'src/a.js' });
    expect(result._meta?.[STAGED_META_KEY]).toMatchObject({
      applied: 0,
      rejected: 1,
      changes: [{ path: 'src/a.js', decision: 'DENY', ruleId: 'WRITE_CONFLICT' }],
    });
    expect(await readFile(s.inProject('src/a.js'), 'utf8')).toBe('user edit\n');
  });

  it('a staging failure returns STAGING ERROR, applies nothing, and refuses later calls without forwarding', async () => {
    let failDiff = false;
    const s = await stagedProject(allowAll, (area) => ({
      sync: () => area.sync(),
      diff: (before) => (failDiff ? Promise.reject(new Error('diff failed')) : area.diff(before)),
      apply: (...a) => area.apply(...a),
      revert: (p) => area.revert(p),
      forcedDenyReason: (p) => area.forcedDenyReason(p),
      removeExcluded: () => area.removeExcluded(),
      baselineAfter: (...a) => area.baselineAfter(...a),
    }));
    const h = harness({
      staging: s.deps,
      forward: async () => {
        await writeFile(s.inStaging('src/a.js'), 'from the server\n');
        failDiff = true;
        return { content: [{ type: 'text', text: 'ok' }] };
      },
    });
    const first = await h.handler('write_file', { path: 'src/a.js' });
    expect(first.isError).toBe(true);
    expect(textOf(first)).toContain(STAGING_ERROR_PREFIX);
    expect(await readFile(s.inProject('src/a.js'), 'utf8')).toBe('original\n');

    failDiff = false;
    const second = await h.handler('write_file', { path: 'src/a.js' });
    expect(textOf(second)).toContain(STAGING_ERROR_PREFIX);
    expect(h.forwards()).toBe(1);
  });

  it('allowed calls are refused, not forwarded, before initStaging has run', async () => {
    const project = await mkdtemp(path.join(tmpdir(), 'mcpfw-audit-project-'));
    const area = await createStagingArea({ projectRoot: project, maxFileBytes: 65_536, maxChangesPerCall: 20 });
    cleanups.push(() => rm(project, { recursive: true, force: true }), () => area.dispose());
    const h = harness({ staging: { area, lock: new StagingLock(), policy } });
    const result = await h.handler('t', {});
    expect(textOf(result)).toContain(STAGING_ERROR_PREFIX);
    expect(h.forwards()).toBe(0);
  });

  // src/index.ts builds StagingDeps without evaluateFileChanges, so the runtime uses
  // defaultEvaluateFileChanges = src/security's evaluateFileChanges.
  it('1g: the runtime file-change evaluator follows policy.staging', () => {
    const { policy: sandboxPolicy } = loadConfig(path.join(repoRoot, 'config/sandbox.yaml'));
    expect(sandboxPolicy.staging?.writablePaths).toContain('src/**');
    const change = { path: 'src/greet.js', kind: 'modify' } as FileChange;
    const [decision] = defaultEvaluateFileChanges([change], sandboxPolicy) as { decision: string }[];
    expect(decision?.decision).toBe('ALLOW');
  });
});
