/**
 * AARAV — Docker launch mode in src/proxy/upstream.ts.
 *
 * Unit tests need no Docker: buildDockerArgs, launch validation, preflight
 * (mocked execFile) and container cleanup (a local fixture stands in for the
 * container). The integration block runs tests/fixtures/docker-server.mjs in
 * node:22-slim and is skipped, with the reason logged, when Docker or the
 * image is missing.
 */
import { spawnSync } from 'node:child_process';
import { mkdir, mkdtemp, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport, type StdioServerParameters } from '@modelcontextprotocol/client/stdio';
import { InMemoryTransport, type CallToolResult } from '@modelcontextprotocol/server';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createInterceptor } from '../src/proxy/interceptor.js';
import { startProxyServer, type ProxyServerHandle } from '../src/proxy/server.js';
import {
  LaunchConfigError,
  SandboxUnavailableError,
  buildDockerArgs,
  connectUpstream,
  describeLaunch,
  type DockerLaunch,
  type ExecFileFn,
  type UpstreamConnection,
} from '../src/proxy/upstream.js';
import type { FirewallPolicy } from '../src/shared/contracts.js';

const repoRoot = resolve(import.meta.dirname, '..');
const countingServer = resolve(import.meta.dirname, 'fixtures/counting-server.ts');
const server = { id: 'sandboxed', command: 'unused', args: [], timeoutMs: 10_000 };
const NAME = 'mcpfw-0123456789ab';

let tmp: string;
let workspace: string;
let serverDir: string;

beforeEach(async () => {
  tmp = await realpath(await mkdtemp(join(tmpdir(), 'mcp-firewall-docker-test-')));
  workspace = join(tmp, 'workspace');
  serverDir = join(tmp, 'server');
  await mkdir(workspace);
  await mkdir(serverDir);
});

afterEach(async () => {
  await rm(tmp, { recursive: true, force: true });
});

const launch = (extra: Partial<DockerLaunch> = {}): DockerLaunch => ({
  mode: 'docker',
  image: 'mcp-sandbox:dev',
  command: 'node',
  args: ['/server/index.mjs', '--flag-for-the-server'],
  workspaceDir: workspace,
  ...extra,
});

describe('upstream / buildDockerArgs', () => {
  it('builds the exact flag set, in order', () => {
    const args = buildDockerArgs(
      launch({ serverDir, env: { NODE_ENV: 'production' }, user: '1000:1000', memory: '256m', pidsLimit: 64 }),
      { containerName: NAME },
    );
    expect(args).toEqual([
      'run', '--rm', '-i',
      '--name', NAME,
      '--network', 'none',
      '--read-only',
      '--cap-drop', 'ALL',
      '--security-opt', 'no-new-privileges',
      '--user', '1000:1000',
      '--pids-limit', '64',
      '--memory', '256m',
      '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m',
      '--mount', `type=bind,src=${workspace},dst=/workspace`,
      '--mount', `type=bind,src=${serverDir},dst=/server,readonly`,
      '-e', 'NODE_ENV=production',
      '-w', '/workspace',
      'mcp-sandbox:dev', 'node', '/server/index.mjs', '--flag-for-the-server',
    ]);
  });

  it('defaults: host uid:gid, 128 pids, 512m, random name, and no /server mount without serverDir', () => {
    const args = buildDockerArgs(launch());
    const value = (flag: string) => args[args.indexOf(flag) + 1];
    expect(value('--user')).toBe(`${process.getuid!()}:${process.getgid!()}`);
    expect(value('--pids-limit')).toBe('128');
    expect(value('--memory')).toBe('512m');
    expect(value('--name')).toMatch(/^mcpfw-[0-9a-f]{12}$/);
    expect(args.filter((a) => a === '--mount')).toHaveLength(1);
    expect(args.join(' ')).not.toContain('/server,');
    expect(args).not.toContain('-e');
  });

  it('mounts the realpath of a symlinked directory', async () => {
    await symlink(workspace, join(tmp, 'link'));
    const args = buildDockerArgs(launch({ workspaceDir: join(tmp, 'link') }), { containerName: NAME });
    expect(args).toContain(`type=bind,src=${workspace},dst=/workspace`);
  });

  it('passes only explicit env entries, never the firewall environment', () => {
    process.env.AWS_SECRET_ACCESS_KEY = 'host-secret-should-not-pass';
    try {
      const args = buildDockerArgs(launch({ env: { ONLY_THIS: '1' } }), { containerName: NAME });
      expect(args.filter((_, i) => args[i - 1] === '-e')).toEqual(['ONLY_THIS=1']);
      expect(args.join(' ')).not.toContain('host-secret-should-not-pass');
      expect(args.join(' ')).not.toContain('AWS_SECRET_ACCESS_KEY');
    } finally {
      delete process.env.AWS_SECRET_ACCESS_KEY;
    }
  });

  it('puts nothing that looks like a docker flag value before the image', () => {
    const args = buildDockerArgs(launch({ serverDir, env: { A: '--privileged' } }), { containerName: NAME });
    const beforeImage = args.slice(0, args.indexOf('mcp-sandbox:dev'));
    const ownFlags = new Set(['--rm', '-i', '--name', '--network', '--read-only', '--cap-drop', '--security-opt', '--user',
      '--pids-limit', '--memory', '--tmpfs', '--mount', '-e', '-w']);
    expect(beforeImage.filter((a) => a.startsWith('-') && !ownFlags.has(a))).toEqual([]);
  });

  describe('rejects before launch', () => {
    it.each<[string, () => Partial<DockerLaunch>]>([
      ['relative workspaceDir', () => ({ workspaceDir: 'relative/dir' })],
      ['missing workspaceDir', () => ({ workspaceDir: join(tmp, 'missing') })],
      ['missing serverDir', () => ({ serverDir: join(tmp, 'missing') })],
      ['relative serverDir', () => ({ serverDir: 'server' })],
      ['comma in a mount path', () => ({ workspaceDir: join(tmp, 'a,b') })],
      ['newline in a mount path', () => ({ workspaceDir: join(tmp, 'a\nb') })],
      ['env key with a dash', () => ({ env: { 'BAD-KEY': 'x' } })],
      ['env key starting with a digit', () => ({ env: { '1X': 'x' } })],
      ['env key with "="', () => ({ env: { 'A=B': 'x' } })],
      ['image with whitespace', () => ({ image: 'node 22' })],
      ['image starting with "-"', () => ({ image: '--privileged' })],
      ['user that is a flag', () => ({ user: '--privileged' })],
      ['memory that is a flag', () => ({ memory: '--privileged' })],
      ['pidsLimit of 0', () => ({ pidsLimit: 0 })],
      ['unknown key', () => ({ privileged: true }) as Partial<DockerLaunch>],
    ])('%s', (_name, extra) => {
      expect(() => buildDockerArgs(launch(extra()), { containerName: NAME })).toThrow(LaunchConfigError);
    });

    it('a mount path whose realpath contains a comma', async () => {
      await mkdir(join(tmp, 'x,y'));
      await symlink(join(tmp, 'x,y'), join(tmp, 'plain'));
      expect(() => buildDockerArgs(launch({ workspaceDir: join(tmp, 'plain') }), { containerName: NAME })).toThrow(
        LaunchConfigError,
      );
    });

    it('a mount path that is a file', async () => {
      await writeFile(join(tmp, 'file'), 'x');
      expect(() => buildDockerArgs(launch({ workspaceDir: join(tmp, 'file') }))).toThrow(LaunchConfigError);
    });

    it('an invalid container name', () => {
      expect(() => buildDockerArgs(launch(), { containerName: '--privileged' })).toThrow(LaunchConfigError);
    });
  });
});

describe('upstream / docker preflight and lifecycle', () => {
  const ok: ExecFileFn = async () => ({ stdout: '', stderr: '' });

  it('refuses to start without Docker and never spawns', async () => {
    const execFile = vi.fn<ExecFileFn>(async () => {
      throw Object.assign(new Error('spawn docker ENOENT'), { code: 'ENOENT' });
    });
    const createTransport = vi.fn();
    const err = await connectUpstream(server, { launch: launch(), execFile, createTransport }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(SandboxUnavailableError);
    expect((err as Error).message).toMatch(/sandbox mode requires Docker.*refusing to start/);
    expect(execFile).toHaveBeenCalledTimes(1);
    expect(execFile.mock.calls[0]?.slice(0, 2)).toEqual(['docker', ['version', '--format', '{{.Server.Version}}']]);
    expect(createTransport).not.toHaveBeenCalled();
  });

  it('refuses to start when the image is missing, and never pulls', async () => {
    const execFile = vi.fn<ExecFileFn>(async (_file, args) => {
      if (args[0] === 'image') throw new Error('No such image');
      return { stdout: '27.0.0', stderr: '' };
    });
    const createTransport = vi.fn();
    const err = await connectUpstream(server, { launch: launch(), execFile, createTransport }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(SandboxUnavailableError);
    expect((err as Error).message).toMatch(/"mcp-sandbox:dev" was not found locally; build it first/);
    expect(execFile.mock.calls.map((c) => c[1][0])).toEqual(['version', 'image']);
    expect(createTransport).not.toHaveBeenCalled();
  });

  it('rejects an invalid launch before calling docker at all', async () => {
    const execFile = vi.fn<ExecFileFn>(ok);
    await expect(
      connectUpstream(server, { launch: launch({ workspaceDir: 'relative' }), execFile }),
    ).rejects.toThrow(LaunchConfigError);
    expect(execFile).not.toHaveBeenCalled();
  });

  it('starts `docker run` with only the safe env for the docker CLI', async () => {
    process.env.AWS_SECRET_ACCESS_KEY = 'host-secret-should-not-pass';
    let params: StdioServerParameters | undefined;
    try {
      await connectUpstream(server, {
        launch: launch(),
        execFile: ok,
        createTransport: (p) => {
          params = p;
          throw new Error('stop before spawning');
        },
      }).catch(() => {});
    } finally {
      delete process.env.AWS_SECRET_ACCESS_KEY;
    }
    expect(params?.command).toBe('docker');
    expect(params?.args?.slice(0, 3)).toEqual(['run', '--rm', '-i']);
    expect(params?.stderr).toBe('pipe');
    expect(JSON.stringify(params)).not.toContain('host-secret-should-not-pass');
  });

  it('reports launch info and removes the container on close, ignoring "no such container"', async () => {
    const execFile = vi.fn<ExecFileFn>(async (_file, args) => {
      if (args[0] === 'rm') throw Object.assign(new Error('rm failed'), { stderr: 'Error: No such container: x' });
      return { stdout: '', stderr: '' };
    });
    const sigintListeners = process.listenerCount('SIGINT');
    const stderr = vi.spyOn(process.stderr, 'write');
    // A local fixture stands in for the container: only the docker CLI calls are mocked.
    const upstream = await connectUpstream(server, {
      launch: launch(),
      execFile,
      createTransport: () =>
        new StdioClientTransport({ command: process.execPath, args: ['--import', 'tsx', countingServer], cwd: repoRoot, stderr: 'pipe' }),
    });
    try {
      expect(upstream.launch).toEqual({
        mode: 'docker',
        image: 'mcp-sandbox:dev',
        containerName: expect.stringMatching(/^mcpfw-[0-9a-f]{12}$/),
        sandboxed: true,
      });
      expect(process.listenerCount('SIGINT')).toBe(sigintListeners + 1);
    } finally {
      await upstream.close();
    }
    const rm = execFile.mock.calls.filter((c) => c[1][0] === 'rm');
    expect(rm).toEqual([['docker', ['rm', '-f', upstream.launch.containerName], expect.anything()]]);
    expect(process.listenerCount('SIGINT')).toBe(sigintListeners);
    expect(stderr.mock.calls.some(([line]) => String(line).includes('could not remove container'))).toBe(false);
    stderr.mockRestore();
  });

  it('describes local launches as not sandboxed', () => {
    expect(describeLaunch({ mode: 'local', command: 'node' })).toEqual({ mode: 'local', sandboxed: false });
  });
});

// ---------------------------------------------------------------------------
// Integration: a real container. Skipped when Docker or node:22-slim is missing.
// ---------------------------------------------------------------------------

const IMAGE = 'node:22-slim';
const dockerSkipReason = (() => {
  const version = spawnSync('docker', ['version', '--format', '{{.Server.Version}}'], { timeout: 5_000 });
  if (version.status !== 0) return 'Docker is not available';
  const image = spawnSync('docker', ['image', 'inspect', IMAGE], { timeout: 5_000 });
  if (image.status !== 0) return `image ${IMAGE} is not present locally (docker pull ${IMAGE})`;
  return undefined;
})();
if (dockerSkipReason) process.stderr.write(`[upstream-docker] skipping integration tests: ${dockerSkipReason}\n`);

describe.skipIf(dockerSkipReason !== undefined)('upstream / docker integration', () => {
  const allowAll: FirewallPolicy = {
    defaultDecision: 'DENY',
    protectedPaths: [],
    deniedDestinations: [],
    allowedRoots: ['.'],
    allowedHosts: [],
    approvedTools: [],
    deniedTools: [],
    pathArgs: [],
    destinationArgs: {},
    destructiveTools: [],
    writeTools: [],
  };
  let dir: string;
  let upstream: UpstreamConnection;
  let proxy: ProxyServerHandle;
  let agent: Client;

  const call = async (name: string, args: Record<string, unknown> = {}): Promise<string> => {
    const result = (await agent.callTool({ name, arguments: args })) as CallToolResult;
    const first = result.content[0];
    return first && first.type === 'text' ? first.text : '';
  };

  beforeAll(async () => {
    dir = await realpath(await mkdtemp(join(tmpdir(), 'mcp-firewall-docker-it-')));
    upstream = await connectUpstream(
      { ...server, timeoutMs: 30_000 },
      {
        launch: {
          mode: 'docker',
          image: IMAGE,
          command: 'node',
          args: ['/server/tests/fixtures/docker-server.mjs'],
          workspaceDir: dir,
          serverDir: repoRoot,
        },
      },
    );
    const handler = createInterceptor({
      serverId: 'sandboxed',
      policy: allowAll,
      evaluate: () => ({ decision: 'ALLOW', ruleId: 'APPROVED_TOOL', reason: 'test' }),
      publish: () => {},
      forward: (name, args, options) => upstream.callTool(name, args, options),
    });
    const [agentSide, proxySide] = InMemoryTransport.createLinkedPair();
    proxy = await startProxyServer(upstream, handler, { transport: proxySide });
    agent = new Client({ name: 'docker-it', version: '0.0.0' });
    await agent.connect(agentSide);
  }, 60_000);

  afterAll(async () => {
    await agent?.close();
    await proxy?.close();
    await upstream?.close();
    if (dir) await rm(dir, { recursive: true, force: true });
  });

  it('lists and calls tools through the proxy', async () => {
    const { tools } = await agent.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual(['ping', 'try_fetch', 'try_write']);
    expect(await call('ping')).toBe('pong');
  });

  it('has no network', async () => {
    expect(await call('try_fetch', { url: 'https://example.com' })).toMatch(/^blocked: /);
  }, 15_000);

  it('can write only inside /workspace', async () => {
    expect(await call('try_write', { path: '/workspace/ok.txt' })).toBe('written');
    expect(await call('try_write', { path: '/server/evil.txt' })).toMatch(/^failed: (EROFS|EACCES)$/);
    expect(await call('try_write', { path: '/evil.txt' })).toMatch(/^failed: (EROFS|EACCES)$/);
    expect(await call('try_write', { path: '/tmp/ok.txt' })).toBe('written');
  });
});
