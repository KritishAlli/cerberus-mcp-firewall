/**
 * OWNER: Aarav — stdio connection to the one downstream MCP server (design doc §6.1).
 *
 * Two launch modes (UpstreamLaunch):
 *   - local:  spawns command/args directly, as before.
 *   - docker: runs the server in a locked-down container (docs/STAGED_WRITES_PLAN.md,
 *             "Sandbox"): no network, read-only root, all capabilities dropped, only
 *             the staging dir (rw) and optionally the server code (ro) mounted. Docker
 *             must be running and the image must exist locally, or this refuses to
 *             start. There is never a fallback to local mode. Containers are labeled
 *             with the firewall's pid and host; before launching, containers left by
 *             a dead firewall on this host are removed (sweepOrphanedContainers).
 *
 * Either way the child gets a safe default environment (not our full env, which
 * may hold real credentials) plus only explicitly configured variables, its
 * stderr is re-emitted on ours with a prefix, and its stdout is the protocol
 * pipe and never reaches ours. Nothing goes through a shell.
 *
 * Once the connection closes it stays closed: every later call throws
 * UpstreamUnavailableError, which the interceptor turns into a fail-closed
 * DOWNSTREAM ERROR. There is no reconnect.
 */
import { execFile as execFileCallback, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { realpathSync, statSync } from 'node:fs';
import { hostname } from 'node:os';
import { isAbsolute } from 'node:path';
import { createInterface } from 'node:readline';
import type { Readable } from 'node:stream';
import { promisify } from 'node:util';
import { Client } from '@modelcontextprotocol/client';
import { getDefaultEnvironment, StdioClientTransport, type StdioServerParameters } from '@modelcontextprotocol/client/stdio';
import type { CallToolResult, Tool } from '@modelcontextprotocol/server';
import { z } from 'zod';
import type { DownstreamServerConfig } from '../shared/contracts.js';
import { isProcessAlive } from './staging.js';

/** Cap on tools/list pages, against a server whose nextCursor never converges. */
const MAX_LIST_PAGES = 20;
const MAX_STDERR_LINE = 2_000;
/** Timeout for `docker version`, `docker image inspect` and `docker rm -f`. */
const DOCKER_CLI_TIMEOUT_MS = 5_000;
/** Docker CLI settings passed through to the docker client itself (never into the container). */
const DOCKER_CLI_ENV_VARS = ['DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_CONFIG', 'DOCKER_CERT_PATH', 'DOCKER_TLS_VERIFY'];

/** Labels on every sandbox container. sweepOrphanedContainers reads them; nothing else does. */
export const CONTAINER_LABELS = {
  /** Always "1": marks a container this firewall started. */
  owner: 'mcp-firewall',
  /** Pid of the firewall process that started it. */
  pid: 'mcp-firewall.pid',
  /** Host it was started from, so a shared or remote Docker daemon never compares another machine's pids. */
  host: 'mcp-firewall.host',
  /** Staging dir mounted at /workspace (for diagnosis only). */
  staging: 'mcp-firewall.staging',
} as const;

export class UpstreamUnavailableError extends Error {
  override name = 'UpstreamUnavailableError';
  readonly code = 'UPSTREAM_UNAVAILABLE';
}

/** The launch configuration is invalid. Thrown before anything is started. */
export class LaunchConfigError extends Error {
  override name = 'LaunchConfigError';
  readonly code = 'LAUNCH_CONFIG_INVALID';
}

/** Sandbox mode was requested but cannot run (no Docker, or no image). Never falls back to local mode. */
export class SandboxUnavailableError extends Error {
  override name = 'SandboxUnavailableError';
  readonly code = 'SANDBOX_UNAVAILABLE';
}

// ---------------------------------------------------------------------------
// Launch configuration
// ---------------------------------------------------------------------------

const ENV_KEY = /^[A-Za-z_][A-Za-z0-9_]*$/;

/** Explicit variables for the server. Nothing from the firewall's own environment is passed implicitly. */
const EnvSchema = z.record(z.string().regex(ENV_KEY, 'env keys must match [A-Za-z_][A-Za-z0-9_]*'), z.string());

/** Absolute host path for a bind mount. Commas and newlines would break `--mount` parsing. */
const MountPathSchema = z
  .string()
  .min(1)
  .refine((p) => isAbsolute(p), 'mount paths must be absolute')
  .refine((p) => !/[,\n\r]/.test(p), 'mount paths must not contain commas or newlines');

/** Run the server as a local child process (the original, unsandboxed mode). */
export const LocalLaunchSchema = z.strictObject({
  mode: z.literal('local'),
  /** Executable that starts the downstream stdio MCP server. */
  command: z.string().min(1),
  args: z.array(z.string()).default([]),
  /** Added to the safe default environment (HOME, PATH, …). */
  env: EnvSchema.optional(),
  /** Working directory for the server process. */
  cwd: z.string().min(1).optional(),
});

/**
 * Run the server in a Docker container: `--network none --read-only --cap-drop ALL
 * --security-opt no-new-privileges`, tmpfs /tmp, workspaceDir mounted rw at
 * /workspace (the working directory) and serverDir mounted ro at /server.
 */
export const DockerLaunchSchema = z.strictObject({
  mode: z.literal('docker'),
  /** Local image name. It must already exist: images are never pulled automatically. */
  image: z
    .string()
    .min(1)
    .refine((s) => !/\s/.test(s), 'image must not contain whitespace')
    .refine((s) => !s.startsWith('-'), 'image must not start with "-"'),
  /** Command run inside the container, e.g. "node". */
  command: z.string().min(1),
  /** Arguments to the command inside the container, e.g. ["/server/index.mjs"]. */
  args: z.array(z.string()).default([]),
  /** Host dir mounted read-write at /workspace: the staging copy, never the real project. Must exist. */
  workspaceDir: MountPathSchema,
  /** Host dir with the server code, mounted read-only at /server. Must exist. */
  serverDir: MountPathSchema.optional(),
  /** Explicit variables set in the container with `-e KEY=VALUE`. */
  env: EnvSchema.optional(),
  /** "uid:gid" or a user name. Default: the firewall's own uid:gid, else 1000:1000. */
  user: z
    .string()
    .regex(/^[A-Za-z0-9_][A-Za-z0-9_.-]*(?::[A-Za-z0-9_][A-Za-z0-9_.-]*)?$/, 'user must be "uid:gid" or a user name')
    .optional(),
  /** Docker memory limit, e.g. "512m", also set as --memory-swap (no swap). Default 512m. */
  memory: z
    .string()
    .regex(/^[1-9][0-9]*[bkmg]?$/i, 'memory must look like "512m"')
    .optional(),
  /** Max processes in the container. Default 128. */
  pidsLimit: z.number().int().min(1).max(32_768).optional(),
});

/**
 * How the downstream server is started. Kritish's config loader maps YAML onto
 * this; connectUpstream validates it again with UpstreamLaunchSchema. Input
 * type: `args` may be omitted and defaults to [].
 */
export const UpstreamLaunchSchema = z.discriminatedUnion('mode', [LocalLaunchSchema, DockerLaunchSchema]);
export type UpstreamLaunch = z.input<typeof UpstreamLaunchSchema>;
export type LocalLaunch = z.input<typeof LocalLaunchSchema>;
export type DockerLaunch = z.input<typeof DockerLaunchSchema>;

/** The local launch for an existing `server` config section (command / args / cwd). */
export function localLaunch(server: DownstreamServerConfig): LocalLaunch {
  return {
    mode: 'local',
    command: server.command,
    args: server.args,
    ...(server.cwd === undefined ? {} : { cwd: server.cwd }),
  };
}

/** What the monitor and /health may show about how the server runs. No paths, env or args. */
export interface LaunchInfo {
  mode: 'local' | 'docker';
  image?: string;
  containerName?: string;
  /** True only for docker mode. */
  sandboxed: boolean;
}

export function describeLaunch(launch: UpstreamLaunch, containerName?: string): LaunchInfo {
  if (launch.mode === 'local') return { mode: 'local', sandboxed: false };
  return { mode: 'docker', image: launch.image, ...(containerName ? { containerName } : {}), sandboxed: true };
}

function parseLaunch<S extends z.ZodType>(schema: S, launch: unknown): z.output<S> {
  const parsed = schema.safeParse(launch);
  if (!parsed.success) {
    // Paths and messages only; never the offending values (env values may be secrets).
    const issues = parsed.error.issues.map((i) => `${i.path.join('.') || 'launch'}: ${i.message}`);
    throw new LaunchConfigError(`invalid upstream launch config (${issues.join('; ')})`);
  }
  return parsed.data;
}

// ---------------------------------------------------------------------------
// Docker
// ---------------------------------------------------------------------------

/** A fresh container name: `mcpfw-` + 12 hex characters. */
export function newContainerName(): string {
  return `mcpfw-${randomBytes(6).toString('hex')}`;
}

/**
 * The `docker` argv for a docker launch, in a fixed order. No shell is ever
 * involved. Throws LaunchConfigError for invalid input, including mount paths
 * that do not exist or resolve to something containing a comma or newline.
 * `--pull=never`: preflight checked the image, and an image removed since then
 * must fail the launch, never be pulled. `ownerPid` and `host` default to this
 * process and this machine (test seams).
 */
export function buildDockerArgs(
  launch: DockerLaunch,
  options: { containerName?: string; ownerPid?: number; host?: string } = {},
): string[] {
  const l = parseLaunch(DockerLaunchSchema, launch);
  const name = options.containerName ?? newContainerName();
  if (!/^mcpfw-[0-9a-f]+$/.test(name)) throw new LaunchConfigError('invalid container name');
  const ownerPid = options.ownerPid ?? process.pid;
  if (!Number.isInteger(ownerPid) || ownerPid < 1) throw new LaunchConfigError('invalid owner pid');
  const workspace = mountSource(l.workspaceDir, 'workspaceDir');
  const memory = l.memory ?? '512m';

  // [flag, value] pairs before the image. Every value is checked not to look like a flag.
  const flags: [string, string][] = [
    ['--name', name],
    ['--network', 'none'],
    ['--cap-drop', 'ALL'],
    ['--security-opt', 'no-new-privileges'],
    ['--user', l.user ?? defaultUser()],
    ['--pids-limit', String(l.pidsLimit ?? 128)],
    ['--memory', memory],
    // Equal to --memory: no swap on top of the limit (Docker's default allows as much again).
    ['--memory-swap', memory],
    ['--tmpfs', '/tmp:rw,noexec,nosuid,size=64m'],
    ['--mount', `type=bind,src=${workspace},dst=/workspace`],
  ];
  if (l.serverDir !== undefined) {
    flags.push(['--mount', `type=bind,src=${mountSource(l.serverDir, 'serverDir')},dst=/server,readonly`]);
  }
  for (const [key, value] of Object.entries(l.env ?? {})) flags.push(['-e', `${key}=${value}`]);
  flags.push(
    ['--label', `${CONTAINER_LABELS.owner}=1`],
    ['--label', `${CONTAINER_LABELS.pid}=${ownerPid}`],
    ['--label', `${CONTAINER_LABELS.host}=${labelHost(options.host)}`],
    ['--label', `${CONTAINER_LABELS.staging}=${workspace}`],
    ['-w', '/workspace'],
  );

  for (const [, value] of flags) {
    if (value.startsWith('-')) throw new LaunchConfigError('a docker flag value must not start with "-"');
  }
  const [nameFlag, network, ...rest] = flags;
  return [
    'run',
    '--rm',
    '-i',
    '--pull=never',
    ...nameFlag!,
    ...network!,
    // --read-only takes no value, so it sits between the pairs.
    '--read-only',
    ...rest.flat(),
    l.image,
    l.command,
    ...l.args,
  ];
}

/** The host label value: this machine's name, limited to [A-Za-z0-9._-]. */
function labelHost(host: string = hostname()): string {
  return host.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 253) || 'unknown';
}

function defaultUser(): string {
  const uid = process.getuid?.();
  const gid = process.getgid?.();
  return uid === undefined || gid === undefined ? '1000:1000' : `${uid}:${gid}`;
}

/** Resolves symlinks so the container gets exactly the checked directory. */
function mountSource(dir: string, field: string): string {
  let real: string;
  try {
    real = realpathSync(dir);
  } catch {
    throw new LaunchConfigError(`${field} does not exist`);
  }
  if (!statSync(real).isDirectory()) throw new LaunchConfigError(`${field} must be a directory`);
  if (/[,\n\r]/.test(real)) throw new LaunchConfigError(`${field} must not contain commas or newlines`);
  return real;
}

/** Environment for the docker CLI process itself: the safe default plus docker's own settings. */
function dockerCliEnv(): Record<string, string> {
  const env = getDefaultEnvironment();
  for (const key of DOCKER_CLI_ENV_VARS) {
    const value = process.env[key];
    if (value !== undefined) env[key] = value;
  }
  return env;
}

export type ExecFileFn = (
  file: string,
  args: readonly string[],
  options: { timeout: number; env: Record<string, string> },
) => Promise<{ stdout: string; stderr: string }>;

const execFileAsync = promisify(execFileCallback);
const defaultExecFile: ExecFileFn = async (file, args, options) => {
  const { stdout, stderr } = await execFileAsync(file, [...args], { ...options, encoding: 'utf8' });
  return { stdout, stderr };
};

/** Refuses to start unless Docker answers and the image exists locally. Never pulls. */
export async function preflightDocker(image: string, execFile: ExecFileFn = defaultExecFile): Promise<void> {
  const options = { timeout: DOCKER_CLI_TIMEOUT_MS, env: dockerCliEnv() };
  try {
    await execFile('docker', ['version', '--format', '{{.Server.Version}}'], options);
  } catch (err) {
    throw new SandboxUnavailableError(
      `sandbox mode requires Docker, and ${dockerUnavailableReason(err)}; refusing to start`,
    );
  }
  try {
    await execFile('docker', ['image', 'inspect', '--format', '{{.Id}}', image], options);
  } catch {
    throw new SandboxUnavailableError(
      `sandbox image "${image}" was not found locally; build it first (images are never pulled automatically); refusing to start`,
    );
  }
}

export interface SweepContainersOptions {
  execFile?: ExecFileFn;
  /** Default: process.kill(pid, 0); only ESRCH counts as dead. */
  isAlive?: (pid: number) => boolean;
  /** Default: this machine (see buildDockerArgs). */
  host?: string;
  /** Diagnostics sink (one line, no trailing newline). Defaults to stderr. */
  log?: (line: string) => void;
}

/**
 * Removes sandbox containers left behind by a firewall that died without cleanup
 * (SIGKILL, OOM, power loss) whose server kept running after stdin EOF. A container
 * is removed only if it carries our owner label, this host's label, and a recorded
 * pid that no longer exists. A container whose firewall is alive (another session's,
 * a teammate's) is never touched, nor is one without our labels (started by an older
 * version). Never throws: failures are logged and startup continues.
 */
export async function sweepOrphanedContainers(options: SweepContainersOptions = {}): Promise<string[]> {
  const execFile = options.execFile ?? defaultExecFile;
  const isAlive = options.isAlive ?? isProcessAlive;
  const log = options.log ?? ((line: string) => process.stderr.write(`${line}\n`));
  const cli = { timeout: DOCKER_CLI_TIMEOUT_MS, env: dockerCliEnv() };
  const host = labelHost(options.host);
  const removed: string[] = [];
  let listing: string;
  try {
    const format = `{{.Names}}\t{{.Label "${CONTAINER_LABELS.pid}"}}\t{{.Label "${CONTAINER_LABELS.host}"}}`;
    ({ stdout: listing } = await execFile(
      'docker',
      ['ps', '-a', '--filter', `label=${CONTAINER_LABELS.owner}=1`, '--format', format],
      cli,
    ));
  } catch (err) {
    log(`[firewall] container sweep skipped: could not list containers (${errorCode(err)})`);
    return removed;
  }
  for (const line of listing.split('\n')) {
    const [name, pidText, labelledHost] = line.trim().split('\t');
    if (!name || !/^mcpfw-[0-9a-f]+$/.test(name) || labelledHost !== host) continue;
    if (!/^[1-9][0-9]{0,9}$/.test(pidText ?? '')) continue;
    const pid = Number(pidText);
    if (pid === process.pid || isAlive(pid)) continue;
    try {
      await execFile('docker', ['rm', '-f', name], cli);
      removed.push(name);
    } catch (err) {
      log(`[firewall] could not remove orphaned container ${name} (${errorCode(err)})`);
    }
  }
  if (removed.length > 0) {
    log(`[firewall] removed ${removed.length} orphaned sandbox container(s) of dead firewalls: ${removed.join(', ')}`);
  }
  return removed;
}

/**
 * Makes sure the container is gone: removeNow() on close, a synchronous
 * `docker rm -f` on process exit, SIGINT and SIGTERM. A signal is re-raised
 * if nothing else handles it, so the process still exits.
 */
function guardContainer(name: string, execFile: ExecFileFn): { removeNow(): Promise<void> } {
  let removed = false;
  const removeSync = (): void => {
    if (removed) return;
    removed = true;
    spawnSync('docker', ['rm', '-f', name], { stdio: 'ignore', timeout: DOCKER_CLI_TIMEOUT_MS, env: dockerCliEnv() });
  };
  const onSignal = (signal: NodeJS.Signals): void => {
    removeSync();
    if (process.listenerCount(signal) === 0) process.kill(process.pid, signal);
  };
  process.once('exit', removeSync);
  process.once('SIGINT', onSignal);
  process.once('SIGTERM', onSignal);

  return {
    async removeNow() {
      process.off('exit', removeSync);
      process.off('SIGINT', onSignal);
      process.off('SIGTERM', onSignal);
      if (removed) return;
      removed = true;
      try {
        await execFile('docker', ['rm', '-f', name], { timeout: DOCKER_CLI_TIMEOUT_MS, env: dockerCliEnv() });
      } catch (err) {
        const stderr = String((err as { stderr?: unknown }).stderr ?? '');
        if (!/no such container/i.test(stderr)) {
          process.stderr.write(`[firewall] could not remove container ${name} (${errorCode(err)})\n`);
        }
      }
    },
  };
}

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------

export interface UpstreamCallOptions {
  signal?: AbortSignal;
}

export interface UpstreamConnection {
  readonly serverId: string;
  /** False once the downstream connection has closed, for any reason. */
  readonly connected: boolean;
  /** How the server runs, for the monitor and /health. */
  readonly launch: LaunchInfo;
  listTools(): Promise<Tool[]>;
  callTool(toolName: string, args: Record<string, unknown>, options?: UpstreamCallOptions): Promise<CallToolResult>;
  close(): Promise<void>;
}

export interface ConnectUpstreamOptions {
  /** Called once when an established downstream connection closes (crash, exit, or close()). */
  onClose?: () => void;
  /** How to start the server. Default: localLaunch(server). */
  launch?: UpstreamLaunch;
  /** Test seam for the docker CLI calls (preflight, rm). */
  execFile?: ExecFileFn;
  /** Test seam for the stdio transport. */
  createTransport?: (params: StdioServerParameters) => StdioClientTransport;
}

export async function connectUpstream(
  server: DownstreamServerConfig,
  options: ConnectUpstreamOptions = {},
): Promise<UpstreamConnection> {
  const launch = parseLaunch(UpstreamLaunchSchema, options.launch ?? localLaunch(server));
  const execFile = options.execFile ?? defaultExecFile;

  let params: StdioServerParameters;
  let tag: string;
  let containerName: string | undefined;
  if (launch.mode === 'local') {
    tag = `[downstream:${server.id}]`;
    params = {
      command: launch.command,
      args: launch.args,
      ...(launch.cwd === undefined ? {} : { cwd: launch.cwd }),
      env: { ...getDefaultEnvironment(), ...launch.env },
      stderr: 'pipe',
    };
  } else {
    tag = `[upstream:${server.id}]`;
    containerName = newContainerName();
    const args = buildDockerArgs(launch, { containerName });
    await preflightDocker(launch.image, execFile);
    // Before launching ours. Never throws, so a failed sweep can neither block startup nor change the launch.
    await sweepOrphanedContainers({ execFile });
    params = { command: 'docker', args, env: dockerCliEnv(), stderr: 'pipe' };
  }
  const info = describeLaunch(launch, containerName);

  const transport = (options.createTransport ?? ((p) => new StdioClientTransport(p)))(params);
  pipeStderr(transport.stderr as Readable | null, tag);
  // The container starts with connect(); from here on it must always be removed.
  const container = containerName === undefined ? undefined : guardContainer(containerName, execFile);

  const client = new Client({ name: 'mcp-firewall', version: '0.1.0' }, { listMaxPages: MAX_LIST_PAGES });
  let connected = false;
  let established = false;
  let closeReported = false;
  client.onclose = () => {
    connected = false;
    void container?.removeNow();
    // Before connect() resolves, a close is a connect failure and is reported by the throw below.
    if (!established || closeReported) return;
    closeReported = true;
    process.stderr.write(`[firewall] ${tag} connection closed\n`);
    options.onClose?.();
  };
  client.onerror = (err) => {
    process.stderr.write(`[firewall] ${tag} transport error: ${err.constructor.name}\n`);
  };

  try {
    await client.connect(transport, { timeout: server.timeoutMs });
  } catch (err) {
    await client.close().catch(() => {});
    await container?.removeNow();
    // The cause can carry command lines or env details; report only a code.
    throw new UpstreamUnavailableError(
      `downstream MCP server "${server.id}" is unavailable (connect failed: ${errorCode(err)})`,
    );
  }
  connected = true;
  established = true;

  const requireConnected = (): void => {
    if (!connected) throw new UpstreamUnavailableError(`downstream MCP server "${server.id}" is not connected`);
  };

  return {
    serverId: server.id,
    launch: info,
    get connected() {
      return connected;
    },
    async listTools() {
      requireConnected();
      // No cursor → the SDK walks every page, capped by listMaxPages.
      const { tools } = await client.listTools(undefined, { timeout: server.timeoutMs, cacheMode: 'refresh' });
      return tools;
    },
    async callTool(toolName, args, callOptions = {}) {
      requireConnected();
      return client.callTool(
        { name: toolName, arguments: args },
        {
          timeout: server.timeoutMs,
          maxTotalTimeout: server.timeoutMs,
          ...(callOptions.signal ? { signal: callOptions.signal } : {}),
        },
      );
    },
    async close() {
      connected = false;
      // Container first: a server that ignores stdin EOF would otherwise hold client.close()
      // until shutdown's 2 s cap, before the staging dir is disposed.
      await container?.removeNow();
      await client.close();
    },
  };
}

function pipeStderr(stderr: Readable | null, tag: string): void {
  if (!stderr) return;
  stderr.on('error', () => {});
  const lines = createInterface({ input: stderr, crlfDelay: Infinity });
  lines.on('line', (line) => {
    // Strip control characters so the child cannot forge or garble our log lines.
    const clean = line.replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, '').slice(0, MAX_STDERR_LINE);
    process.stderr.write(`${tag} ${clean}\n`);
  });
}

/** A string errno code, `exit N` for a child's numeric exit status, or the error's class name. */
function errorCode(err: unknown): string {
  if (typeof err === 'object' && err !== null && 'code' in err) {
    const code = (err as { code: unknown }).code;
    if (typeof code === 'string' && /^[A-Z0-9_]{1,64}$/.test(code)) return code;
    if (typeof code === 'number' && Number.isInteger(code)) return `exit ${code}`;
  }
  return err instanceof Error ? err.constructor.name : 'unknown';
}

/** Why `docker version` failed: no CLI, or a CLI whose daemon did not answer (non-zero exit or timeout). */
function dockerUnavailableReason(err: unknown): string {
  const code = errorCode(err);
  if (code === 'ENOENT') return 'docker CLI not found';
  const timedOut = typeof err === 'object' && err !== null && (err as { killed?: unknown }).killed === true;
  if (code.startsWith('exit ') || timedOut) return "the Docker daemon isn't responding (is Docker running?)";
  return `Docker is not available (${code})`;
}
