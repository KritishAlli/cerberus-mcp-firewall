/**
 * AARAV — Docker launch mode in src/proxy/upstream.ts.
 *
 * Unit tests need no Docker: buildDockerArgs, launch validation, preflight
 * (mocked execFile) and container cleanup (a local fixture stands in for the
 * container). The integration block runs tests/fixtures/docker-server.mjs in
 * node:22-slim and is skipped, with the reason logged, when Docker or the
 * image is missing. With REQUIRE_DOCKER=1 (npm run test:docker) it fails with
 * that reason instead.
 */
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { chmod, mkdir, mkdtemp, readdir, readFile, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { delimiter, join, resolve } from 'node:path';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport, type StdioServerParameters } from '@modelcontextprotocol/client/stdio';
import { InMemoryTransport, type CallToolResult } from '@modelcontextprotocol/server';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createInterceptor } from '../src/proxy/interceptor.js';
import { startProxyServer, type ProxyServerHandle } from '../src/proxy/server.js';
import {
  LaunchConfigError,
  SandboxUnavailableError,
  UpstreamUnavailableError,
  buildDockerArgs,
  connectUpstream,
  describeLaunch,
  dockerSearchPath,
  preflightDocker,
  sweepOrphanedContainers,
  type DockerLaunch,
  type ExecFileFn,
  type UpstreamConnection,
} from '../src/proxy/upstream.js';
import type { FirewallPolicy } from '../src/shared/contracts.js';

const repoRoot = resolve(import.meta.dirname, '..');
const countingServer = resolve(import.meta.dirname, 'fixtures/counting-server.ts');
const server = { id: 'sandboxed', command: 'unused', args: [], timeoutMs: 10_000 };
const NAME = 'mcpfw-0123456789ab';
/** What `docker version --format '{{json .}}'` prints, trimmed to the fields preflight reads. */
const DOCKER_VERSION_JSON = JSON.stringify({ Client: { Version: '29.9.2' }, Server: { Version: '29.9.2' } });

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
      { containerName: NAME, ownerPid: 4242, host: 'dev-laptop.local' },
    );
    expect(args).toEqual([
      'run', '--rm', '-i', '--pull=never',
      '--name', NAME,
      '--network', 'none',
      '--read-only',
      '--cap-drop', 'ALL',
      '--security-opt', 'no-new-privileges',
      '--user', '1000:1000',
      '--pids-limit', '64',
      '--memory', '256m',
      '--memory-swap', '256m',
      '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m',
      '--mount', `type=bind,src=${workspace},dst=/workspace`,
      '--mount', `type=bind,src=${serverDir},dst=/server,readonly`,
      '-e', 'NODE_ENV=production',
      '--label', 'mcp-firewall=1',
      '--label', 'mcp-firewall.pid=4242',
      '--label', 'mcp-firewall.host=dev-laptop.local',
      '--label', `mcp-firewall.staging=${workspace}`,
      '-w', '/workspace',
      'mcp-sandbox:dev', 'node', '/server/index.mjs', '--flag-for-the-server',
    ]);
  });

  it('defaults: host uid:gid, 128 pids, 512m with no swap, random name, and no /server mount without serverDir', () => {
    const args = buildDockerArgs(launch());
    const value = (flag: string) => args[args.indexOf(flag) + 1];
    expect(value('--user')).toBe(`${process.getuid!()}:${process.getgid!()}`);
    expect(value('--pids-limit')).toBe('128');
    expect(value('--memory')).toBe('512m');
    expect(value('--memory-swap')).toBe('512m');
    expect(value('--name')).toMatch(/^mcpfw-[0-9a-f]{12}$/);
    expect(args.filter((a) => a === '--mount')).toHaveLength(1);
    expect(args.join(' ')).not.toContain('/server,');
    expect(args).not.toContain('-e');
  });

  it('defaults the mount target and workdir to /workspace', () => {
    const args = buildDockerArgs(launch(), { containerName: NAME });
    expect(args).toContain(`type=bind,src=${workspace},dst=/workspace`);
    expect(args[args.indexOf('-w') + 1]).toBe('/workspace');
  });

  it('uses an explicit workspaceMount as the bind-mount target and the workdir', () => {
    const target = '/Users/demo/cerberus-demo/project';
    const args = buildDockerArgs(launch({ workspaceMount: target }), { containerName: NAME });
    expect(args).toContain(`type=bind,src=${workspace},dst=${target}`);
    expect(args[args.indexOf('-w') + 1]).toBe(target);
    // The staging label still records the host source dir, not the container target.
    expect(args).toContain(`mcp-firewall.staging=${workspace}`);
    // Nothing else changed: still exactly one rw mount, and the container target is never /workspace.
    expect(args.filter((a) => a === '--mount')).toHaveLength(1);
    expect(args).not.toContain(`type=bind,src=${workspace},dst=/workspace`);
    expect(args).not.toContain('/workspace'); // as a standalone argv entry (e.g. -w)
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
    const ownFlags = new Set(['--rm', '-i', '--pull=never', '--name', '--network', '--read-only', '--cap-drop', '--security-opt',
      '--user', '--pids-limit', '--memory', '--memory-swap', '--tmpfs', '--mount', '-e', '--label', '-w']);
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
      ['relative workspaceMount', () => ({ workspaceMount: 'project' })],
      ['workspaceMount of "/"', () => ({ workspaceMount: '/' })],
      ['workspaceMount with ".."', () => ({ workspaceMount: '/a/../b' })],
      ['non-normalized workspaceMount', () => ({ workspaceMount: '/a//b' })],
      ['workspaceMount with a trailing slash', () => ({ workspaceMount: '/project/' })],
      ['workspaceMount with a comma', () => ({ workspaceMount: '/a,b' })],
      ['workspaceMount = /etc', () => ({ workspaceMount: '/etc' })],
      ['workspaceMount under /usr', () => ({ workspaceMount: '/usr/local/project' })],
      ['workspaceMount = /server', () => ({ workspaceMount: '/server' })],
      ['workspaceMount = /app', () => ({ workspaceMount: '/app' })],
      ['workspaceMount = /tmp', () => ({ workspaceMount: '/tmp' })],
      ['workspaceMount = /proc', () => ({ workspaceMount: '/proc' })],
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
  const ok: ExecFileFn = async (_file, args) => ({ stdout: args[0] === 'version' ? DOCKER_VERSION_JSON : '', stderr: '' });

  it('refuses to start without Docker and never spawns', async () => {
    const execFile = vi.fn<ExecFileFn>(async () => {
      throw Object.assign(new Error('spawn docker ENOENT'), { code: 'ENOENT' });
    });
    const createTransport = vi.fn();
    const err = await connectUpstream(server, { launch: launch(), execFile, createTransport }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(SandboxUnavailableError);
    expect((err as Error).message).toBe('sandbox mode requires Docker, and docker CLI not found; refusing to start');
    expect(execFile).toHaveBeenCalledTimes(1);
    expect(execFile.mock.calls[0]?.slice(0, 2)).toEqual(['docker', ['version', '--format', '{{json .}}']]);
    expect(createTransport).not.toHaveBeenCalled();
  });

  it.each([
    ['exits non-zero', Object.assign(new Error('Command failed: docker version'), { code: 1 })],
    ['times out', Object.assign(new Error('Command failed: docker version'), { code: null, killed: true, signal: 'SIGTERM' })],
  ])('refuses to start when the docker CLI %s (daemon down), and never spawns', async (_case, failure) => {
    const execFile = vi.fn<ExecFileFn>(async () => {
      throw failure;
    });
    const createTransport = vi.fn();
    const err = await connectUpstream(server, { launch: launch(), execFile, createTransport }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(SandboxUnavailableError);
    expect((err as Error).message).toBe(
      "sandbox mode requires Docker, and the Docker daemon isn't responding (is Docker running?); refusing to start",
    );
    expect(execFile).toHaveBeenCalledTimes(1);
    expect(createTransport).not.toHaveBeenCalled();
  });

  it('refuses to start when the image is missing, and never pulls', async () => {
    const execFile = vi.fn<ExecFileFn>(async (_file, args) => {
      if (args[0] === 'image') throw new Error('No such image');
      return { stdout: DOCKER_VERSION_JSON, stderr: '' };
    });
    const createTransport = vi.fn();
    const err = await connectUpstream(server, { launch: launch(), execFile, createTransport }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(SandboxUnavailableError);
    expect((err as Error).message).toMatch(/"mcp-sandbox:dev" was not found locally; build it first/);
    expect(execFile.mock.calls.map((c) => c[1][0])).toEqual(['version', 'image']);
    expect(createTransport).not.toHaveBeenCalled();
  });

  it.each([
    ['empty output', ''],
    ['non-JSON output', 'Saved file tree to doc-filelist.js\n'],
    ['JSON without Server', DOCKER_VERSION_JSON.replace('"Server"', '"Other"')],
    ['a null Server', '{"Client":{"Version":"29.9.2"},"Server":null}'],
    ['an empty Server.Version', '{"Client":{"Version":"29.9.2"},"Server":{"Version":" "}}'],
    ['a non-string Server.Version', '{"Server":{"Version":29}}'],
  ])('refuses to start when `docker version` exits 0 with %s, and never spawns', async (_case, stdout) => {
    const execFile = vi.fn<ExecFileFn>(async () => ({ stdout, stderr: '' }));
    const createTransport = vi.fn();
    const err = await connectUpstream(server, { launch: launch(), execFile, createTransport }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(SandboxUnavailableError);
    expect((err as Error).message).toMatch(/the docker on PATH is not the Docker CLI/);
    expect(execFile).toHaveBeenCalledTimes(1);
    expect(createTransport).not.toHaveBeenCalled();
  });

  it('dockerSearchPath drops node_modules/.bin and relative entries, keeping the rest in order', () => {
    const path = [
      '/repo/node_modules/.bin',
      '/usr/local/bin',
      '/repo/sub/node_modules/.bin/',
      '',
      '.',
      'node_modules/.bin',
      '/opt/node_modules/.bin-not/tools',
      '/usr/bin',
    ].join(delimiter);
    expect(dockerSearchPath(path)).toBe(['/usr/local/bin', '/opt/node_modules/.bin-not/tools', '/usr/bin'].join(delimiter));
    expect(dockerSearchPath(undefined)).toBe('');
  });

  it('every docker command (preflight, sweep, run, rm) gets a PATH without node_modules/.bin', async () => {
    const shadow = join(tmp, 'node_modules', '.bin');
    const originalPath = process.env.PATH;
    process.env.PATH = `${shadow}${delimiter}${originalPath ?? ''}`;
    const paths: { command: string; path: string | undefined }[] = [];
    try {
      const upstream = await connectUpstream(server, {
        launch: launch(),
        execFile: async (_file, args, options) => {
          paths.push({ command: args[0]!, path: options.env.PATH });
          return { stdout: args[0] === 'version' ? DOCKER_VERSION_JSON : '', stderr: '' };
        },
        createTransport: (p) => {
          paths.push({ command: 'run', path: p.env?.PATH });
          return new StdioClientTransport({ command: process.execPath, args: ['--import', 'tsx', countingServer], cwd: repoRoot, stderr: 'pipe' });
        },
      });
      await upstream.close();
    } finally {
      process.env.PATH = originalPath;
    }
    expect(paths.map((p) => p.command)).toEqual(['version', 'image', 'ps', 'run', 'rm']);
    for (const { path } of paths) {
      expect(path).toBeTruthy();
      expect(path!.split(delimiter)).not.toContain(shadow);
      expect(path).not.toMatch(/node_modules[\\/]\.bin/);
    }
  });

  // Real child processes: a script named docker that records every invocation.
  describe.skipIf(process.platform === 'win32')('with a fake docker executable on PATH', () => {
    async function fakeDocker(dir: string, stdout: string): Promise<{ invocations: () => Promise<string[]> }> {
      await mkdir(dir, { recursive: true });
      const log = join(tmp, `fake-docker-${Math.random().toString(16).slice(2)}.log`);
      const script = join(dir, 'docker');
      await writeFile(script, `#!/bin/sh\necho "$*" >> '${log}'\nprintf '%s' '${stdout}'\nexit 0\n`);
      await chmod(script, 0o755);
      return { invocations: async () => (await readFile(log, 'utf8').catch(() => '')).split('\n').filter(Boolean) };
    }
    let originalPath: string | undefined;
    beforeEach(() => {
      originalPath = process.env.PATH;
    });
    afterEach(() => {
      process.env.PATH = originalPath;
    });

    it('a docker in a node_modules/.bin on PATH is never run, even one that prints valid version JSON', async () => {
      const shadow = join(tmp, 'node_modules', '.bin');
      const fake = await fakeDocker(shadow, DOCKER_VERSION_JSON);
      process.env.PATH = `${shadow}${delimiter}${originalPath ?? ''}`;
      // Real execFile: whatever docker is found on the filtered PATH (the real CLI, or none) answers.
      await preflightDocker(`mcpfw-test-absent-${process.pid}:never`).catch(() => {});
      // isAlive: never remove a real container from a unit test.
      await sweepOrphanedContainers({ log: () => {}, isAlive: () => true });
      expect(await fake.invocations()).toEqual([]);
    });

    it('a docker that exits 0 with junk output fails preflight and never starts a container', async () => {
      const dir = join(tmp, 'fake-bin');
      const fake = await fakeDocker(dir, 'Saved file tree to doc-filelist.js');
      process.env.PATH = `${dir}${delimiter}${originalPath ?? ''}`;
      const createTransport = vi.fn();
      const err = await connectUpstream(server, { launch: launch(), createTransport }).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(SandboxUnavailableError);
      expect((err as Error).message).toBe(
        'sandbox mode requires Docker, and the docker on PATH is not the Docker CLI (`docker version` did not report a server version); refusing to start',
      );
      expect(createTransport).not.toHaveBeenCalled();
      expect(await fake.invocations()).toEqual(['version --format {{json .}}']);
    });
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
      return { stdout: args[0] === 'version' ? DOCKER_VERSION_JSON : '', stderr: '' };
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
// Integration: a real container. Skipped when Docker or node:22-slim is missing,
// unless REQUIRE_DOCKER=1, which fails the block with the reason instead.
// ---------------------------------------------------------------------------

const IMAGE = 'node:22-slim';
const dockerSkipReason = (() => {
  const version = spawnSync('docker', ['version', '--format', '{{.Server.Version}}'], { timeout: 5_000 });
  if (version.status !== 0) return 'Docker is not available';
  const image = spawnSync('docker', ['image', 'inspect', IMAGE], { timeout: 5_000 });
  if (image.status !== 0) return `image ${IMAGE} is not present locally (docker pull ${IMAGE})`;
  return undefined;
})();
const requireDocker = process.env.REQUIRE_DOCKER === '1';
if (dockerSkipReason && !requireDocker) {
  process.stderr.write(`[upstream-docker] skipping integration tests: ${dockerSkipReason}\n`);
}

describe.skipIf(dockerSkipReason !== undefined && !requireDocker)('upstream / docker integration', () => {
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
    if (dockerSkipReason) throw new Error(`REQUIRE_DOCKER=1, but ${dockerSkipReason}`);
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

// ---------------------------------------------------------------------------
// Integration: --pull=never and the orphaned-container sweep, with real Docker.
// ---------------------------------------------------------------------------

describe.skipIf(dockerSkipReason !== undefined && !requireDocker)('upstream / docker integration: pull and orphan sweep', () => {
  const docker = (...args: string[]) => spawnSync('docker', args, { encoding: 'utf8', timeout: 10_000 });
  const running = (name: string) => docker('ps', '--filter', `name=^${name}$`, '--format', '{{.Names}}').stdout.trim() === name;

  beforeAll(() => {
    if (dockerSkipReason) throw new Error(`REQUIRE_DOCKER=1, but ${dockerSkipReason}`);
  });

  it('an image removed after preflight fails the launch and is never pulled', async () => {
    const dir = await realpath(await mkdtemp(join(tmpdir(), 'mcp-firewall-pull-it-')));
    const image = `mcpfw-test-absent-${process.pid}:never`;
    const stderr = vi.spyOn(process.stderr, 'write');
    try {
      // Preflight and the sweep are faked to pass; `docker run` itself is real.
      const err = await connectUpstream(server, {
        launch: { mode: 'docker', image, command: 'node', workspaceDir: dir },
        execFile: async (_file, args) => ({ stdout: args[0] === 'version' ? DOCKER_VERSION_JSON : '', stderr: '' }),
      }).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(UpstreamUnavailableError);
      const lines = stderr.mock.calls.map(([line]) => String(line)).join('');
      expect(lines).toContain(`No such image: ${image}`);
      expect(lines).not.toMatch(/Unable to find image|[Pp]ulling/);
      expect(docker('image', 'inspect', image).status).not.toBe(0);
    } finally {
      stderr.mockRestore();
      await rm(dir, { recursive: true, force: true });
    }
  }, 30_000);

  it('a new firewall removes the orphan of a SIGKILLed one and leaves a live instance alone', async () => {
    const base = await realpath(await mkdtemp(join(tmpdir(), 'mcp-firewall-orphan-it-')));
    await mkdir(join(base, 'project'));
    const config = join(base, 'fw.yaml');
    await writeFile(
      config,
      [
        'server:',
        '  id: orphan-it',
        '  command: node',
        // This server keeps running after stdin EOF, so `--rm` alone cannot clean up after a SIGKILL.
        '  args: ["/server/tests/fixtures/docker-server.mjs", "--ignore-stdin-eof"]',
        '  timeoutMs: 30000',
        '  sandbox:',
        `    image: ${IMAGE}`,
        `    project: ${join(base, 'project')}`,
        `    serverDir: ${repoRoot}`,
        'monitor:',
        '  enabled: false',
        'policy:',
        '  defaultDecision: DENY',
        '  approvedTools: []',
        '  staging:',
        '    writablePaths: ["src/**"]',
        '    protectedWritePaths: []',
        '    maxFileBytes: 65536',
        '    maxChangesPerCall: 20',
        '',
      ].join('\n'),
    );

    const started: { child: ChildProcess; stderr: () => string }[] = [];
    const ours: string[] = [];
    const startFirewall = async () => {
      const child = spawn(process.execPath, ['--import', 'tsx', 'src/index.ts', '--config', config], {
        cwd: repoRoot,
        stdio: ['pipe', 'ignore', 'pipe'],
      });
      let err = '';
      child.stderr!.on('data', (d: Buffer) => (err += d.toString()));
      const entry = { child, stderr: () => err };
      started.push(entry);
      await expect.poll(() => err.includes('protecting MCP server') || child.exitCode !== null, { timeout: 45_000, interval: 200 }).toBe(true);
      if (!err.includes('protecting MCP server')) throw new Error(`firewall did not start:\n${err}`);
      const name = docker('ps', '--filter', `label=mcp-firewall.pid=${child.pid}`, '--format', '{{.Names}}').stdout.trim();
      expect(name).toMatch(/^mcpfw-[0-9a-f]{12}$/);
      ours.push(name);
      return { ...entry, name };
    };

    try {
      const victim = await startFirewall();
      const live = await startFirewall();

      victim.child.kill('SIGKILL');
      await new Promise((r) => victim.child.once('exit', r));
      await new Promise((r) => setTimeout(r, 2_000));
      // Precondition: without the sweep this container would stay up indefinitely.
      expect(running(victim.name)).toBe(true);

      const next = await startFirewall();
      expect(running(victim.name)).toBe(false);
      expect(running(live.name)).toBe(true);
      expect(running(next.name)).toBe(true);
      expect(next.stderr()).toMatch(new RegExp(`removed \\d+ orphaned sandbox container\\(s\\) of dead firewalls: .*${victim.name}`));
      expect(next.stderr()).not.toContain(live.name);
    } finally {
      for (const { child } of started) if (child.exitCode === null && child.signalCode === null) child.stdin!.end();
      await Promise.all(
        started.map(({ child }) =>
          child.exitCode !== null || child.signalCode !== null ? undefined : new Promise((r) => child.once('exit', r)),
        ),
      );
      for (const name of ours) docker('rm', '-f', name);
      // A server that ignores stdin EOF makes graceful shutdown hit index.ts's 2 s cap before
      // staging.dispose(), so remove the staging dirs owned by the firewalls this test started.
      const pids = new Set(started.map(({ child }) => child.pid));
      for (const entry of await readdir(tmpdir())) {
        if (!entry.startsWith('mcp-firewall-staging-')) continue;
        const owner = await readFile(join(tmpdir(), entry, 'owner.json'), 'utf8').then(JSON.parse, () => undefined);
        if (pids.has(owner?.pid)) await rm(join(tmpdir(), entry), { recursive: true, force: true });
      }
      await rm(base, { recursive: true, force: true });
    }
  }, 150_000);
});
