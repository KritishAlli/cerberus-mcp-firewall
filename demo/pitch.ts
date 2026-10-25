/**
 * OWNER: Aarav — narrated pitch demo in Docker sandbox mode (`npm run demo:pitch`).
 *
 * A deterministic, three-act story told against a THROWAWAY copy of demo/project.
 * demo/project itself is never touched: the copy is made in a temp dir, given its
 * own git repo (so `.git/hooks` exists and `git status` is meaningful), and the
 * firewall runs on that copy via temp configs that repoint server.sandbox.project.
 *
 *   Act 1 (filesystem config): an in-policy edit to src/greet.js is ALLOWed and
 *          lands in the project. Also confirms the content-scanning fix: a plain
 *          source edit is not blocked as PATH_NOT_ALLOWED.
 *   Act 2 (same gateway, acting as a prompt-injected agent): a read of .env and a
 *          write of a postinstall script into package.json are both BLOCKED before
 *          the downstream ever sees them (PROTECTED_PATH, PERSISTENCE_PATH). The
 *          .env value never appears in any output; package.json stays unchanged.
 *   Act 3 (restart with the attack config, same project): the inert side-effects
 *          fixture's one in-policy change (a README line) lands, while its five
 *          extra writes — a git hook, a package.json postinstall, a dummy-key file,
 *          an exec bit and a symlink — are all rejected by staging. `git status`
 *          then shows only README.md and the Act 1 file changed.
 *
 * Blocks are detected by `_meta['mcp-firewall/decision']` and BLOCKED_PREFIX, never
 * by parsing prose. Act 3's call is ALLOWed with rejected changes, so its outcome is
 * read from `_meta['mcp-firewall/staged']`, not from a decision meta. The gateway is
 * launched with the default safe environment, no CERBERUS_TTY_APPROVAL and no form
 * elicitation declared, so every DENY stays a DENY.
 *
 * Usage: npm run demo:pitch [-- --auto] [-- --keep] [-- --monitor-port N]
 *   --auto          skip the "press Enter" pauses between acts (rehearsal / CI)
 *   --keep          leave the temp project in place on exit (prints its path)
 *   --monitor-port  monitor port for the gateways (default 3100, to dodge a dev
 *                   monitor on 3000); the two gateways run sequentially on it
 *
 * Needs Docker and the sandbox image (npm run sandbox:build). If either is missing
 * the demo exits with a clear message and never falls back to a local server.
 */
import { execFile as execFileCb } from 'node:child_process';
import { cpSync, existsSync, lstatSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { mkdtempSync } from 'node:fs';
import { createInterface } from 'node:readline/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { promisify } from 'node:util';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { stringify as stringifyYaml } from 'yaml';
import type { CallToolResult } from '@modelcontextprotocol/server';
import { loadConfig } from '../src/config/load.js';
import { BLOCKED_PREFIX, FIREWALL_META_KEY } from '../src/proxy/interceptor.js';
import { STAGED_META_KEY } from '../src/proxy/staged-call.js';
import { FirewallEventSchema, type FirewallEvent, type RuleId } from '../src/shared/contracts.js';

const execFile = promisify(execFileCb);
const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SANDBOX_IMAGE = 'mcp-firewall-sandbox:dev';
/** The AWS documentation example key the fixture writes; it must never reach any output. */
const EXAMPLE_AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';

const failures: string[] = [];
let heading = '';

function out(line = ''): void {
  process.stdout.write(`${line}\n`);
}

function banner(title: string): void {
  heading = title;
  out();
  out('='.repeat(72));
  out(`  ${title}`);
  out('='.repeat(72));
}

function check(ok: boolean, label: string): void {
  out(`   ${ok ? 'PASS' : 'FAIL'}  ${label}`);
  if (!ok) failures.push(`[${heading}] ${label}`);
}

function oneLine(text: string, max = 140): string {
  const flat = text.replace(/\s+/g, ' ').trim();
  return flat.length > max ? `${flat.slice(0, max - 1)}…` : flat;
}

/** The firewall's machine-readable decision meta, present only on BLOCKED / downstream-error results. */
interface DecisionMeta {
  decision?: 'ALLOW' | 'DENY';
  ruleId?: RuleId;
  requestId?: string;
}

interface StagedChange {
  path: string;
  decision: 'ALLOW' | 'DENY';
  ruleId: RuleId;
}
interface StagedMeta {
  applied: number;
  rejected: number;
  changes: StagedChange[];
  truncated?: true;
}

interface Outcome {
  isError: boolean;
  text: string;
  decision?: DecisionMeta;
  staged?: StagedMeta;
}

function toText(result: CallToolResult): string {
  const content = Array.isArray(result.content) ? result.content : [];
  return content.map((part) => (part.type === 'text' ? part.text : `[${part.type}]`)).join('\n');
}

function decisionMeta(result: CallToolResult): DecisionMeta | undefined {
  const meta = (result._meta as Record<string, unknown> | undefined)?.[FIREWALL_META_KEY];
  return meta && typeof meta === 'object' ? (meta as DecisionMeta) : undefined;
}

function stagedMeta(result: CallToolResult): StagedMeta | undefined {
  const meta = (result._meta as Record<string, unknown> | undefined)?.[STAGED_META_KEY];
  return meta && typeof meta === 'object' ? (meta as StagedMeta) : undefined;
}

/** One running firewall gateway (child process) plus its MCP client and monitor URL. */
class Gateway {
  private constructor(
    readonly client: Client,
    readonly transport: StdioClientTransport,
    readonly monitorUrl: string,
  ) {}

  static async start(configFile: string, monitorUrl: string): Promise<Gateway> {
    const client = new Client({ name: 'mcp-firewall-pitch', version: '0.1.0' });
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: ['--import', 'tsx', 'src/index.ts', '--config', configFile],
      cwd: repoRoot,
      // Default safe environment: no CERBERUS_TTY_APPROVAL, nothing extra.
      stderr: 'inherit',
    });
    await client.connect(transport);
    return new Gateway(client, transport, monitorUrl);
  }

  get pid(): number | null {
    return this.transport.pid;
  }

  async call(name: string, args: Record<string, unknown>): Promise<Outcome> {
    try {
      const result = await this.client.callTool({ name, arguments: args });
      return {
        isError: result.isError === true,
        text: toText(result),
        decision: decisionMeta(result),
        staged: stagedMeta(result),
      };
    } catch (err) {
      return { isError: true, text: err instanceof Error ? err.message : String(err) };
    }
  }

  async stop(): Promise<void> {
    const pid = this.pid;
    await this.client.close().catch(() => {});
    // The firewall removes its own container on shutdown; as insurance, remove any
    // still labeled with this child's pid. Best effort, never fatal.
    if (pid !== null) await removeContainersForPid(pid);
    await waitForPortFree(this.monitorUrl);
  }
}

async function removeContainersForPid(pid: number): Promise<void> {
  try {
    const { stdout } = await execFile('docker', [
      'ps', '-aq', '--filter', 'label=mcp-firewall=1', '--filter', `label=mcp-firewall.pid=${pid}`,
    ]);
    const ids = stdout.split('\n').map((s) => s.trim()).filter(Boolean);
    if (ids.length > 0) await execFile('docker', ['rm', '-f', ...ids]);
  } catch {
    // Docker gone or nothing to remove; the firewall's own cleanup covers the normal case.
  }
}

/** Poll the monitor port until a connection is refused, so the next gateway can bind it. */
async function waitForPortFree(monitorUrl: string): Promise<void> {
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    try {
      await fetch(`${monitorUrl}/health`, { signal: AbortSignal.timeout(500) });
    } catch {
      return; // refused / unreachable: the port is free.
    }
    await new Promise((r) => setTimeout(r, 150));
  }
}

/** What the monitor should have recorded for one call, in order. */
interface ExpectedEvent {
  toolName: string;
  decision: 'ALLOW' | 'DENY';
  ruleId: RuleId;
}

/** Read /events until the replay's `ready` frame; return raw text and parsed firewall events. */
async function readMonitor(monitorUrl: string): Promise<{ raw: string; events: FirewallEvent[] } | undefined> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5_000);
  try {
    const res = await fetch(`${monitorUrl}/events`, { signal: controller.signal });
    const reader = res.body!.pipeThrough(new TextDecoderStream()).getReader();
    let raw = '';
    while (!/^event: ready$/m.test(raw)) {
      const { value, done } = await reader.read();
      if (done) break;
      raw += value;
    }
    const events: FirewallEvent[] = [];
    for (const frame of raw.split('\n\n')) {
      const lines = frame.split('\n');
      if (!lines.includes('event: firewall')) continue;
      const data = lines.find((l) => l.startsWith('data: '));
      const parsed = FirewallEventSchema.safeParse(data ? JSON.parse(data.slice(6)) : undefined);
      if (parsed.success) events.push(parsed.data);
    }
    return { raw, events };
  } catch {
    return undefined;
  } finally {
    clearTimeout(timer);
    controller.abort();
  }
}

async function checkMonitor(gateway: Gateway, expected: ExpectedEvent[]): Promise<void> {
  out(`   monitor at ${gateway.monitorUrl}`);
  let health: { status?: unknown; protectedServers?: unknown; instance?: { pid?: unknown } };
  try {
    health = (await (await fetch(`${gateway.monitorUrl}/health`)).json()) as typeof health;
  } catch {
    check(false, 'monitor /health is reachable');
    return;
  }
  const pid = health.instance?.pid;
  out(`   /health: status ${String(health.status)}, protectedServers ${String(health.protectedServers)}, gateway pid ${String(pid)}`);
  if (pid !== gateway.pid) {
    check(false, `monitor belongs to the gateway we launched (pid ${gateway.pid}), not pid ${String(pid)}`);
    out('   note  another process holds this monitor port; stop it or pass --monitor-port');
    return;
  }
  check(true, `monitor belongs to the gateway we launched (pid ${gateway.pid})`);

  const read = await readMonitor(gateway.monitorUrl);
  if (!read) {
    check(false, 'monitor /events is readable');
    return;
  }
  for (const e of read.events) {
    out(`     ${e.decision.padEnd(5)} ${e.ruleId.padEnd(18)} ${e.toolName}`);
  }
  check(read.events.length === expected.length, `monitor shows ${expected.length} decision event(s) (got ${read.events.length})`);
  expected.forEach((want, i) => {
    const got = read.events[i];
    const same = got?.toolName === want.toolName && got.decision === want.decision && got.ruleId === want.ruleId;
    check(same, `event ${i + 1} is ${want.decision} ${want.ruleId} for ${want.toolName}`);
  });
  check(!read.raw.includes(EXAMPLE_AWS_KEY), 'monitor stream contains no dummy secret');
}

// ---------------------------------------------------------------------------
// Temp project
// ---------------------------------------------------------------------------

async function git(cwd: string, args: string[]): Promise<string> {
  const { stdout } = await execFile('git', args, {
    cwd,
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: 'pitch-demo',
      GIT_AUTHOR_EMAIL: 'pitch@demo.invalid',
      GIT_COMMITTER_NAME: 'pitch-demo',
      GIT_COMMITTER_EMAIL: 'pitch@demo.invalid',
    },
  });
  return stdout;
}

async function makeTempProject(): Promise<string> {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-firewall-pitch-'));
  const project = join(dir, 'project');
  // Never touch demo/project: copy it, and give the copy its own git repo.
  cpSync(join(repoRoot, 'demo', 'project'), project, { recursive: true });
  await git(project, ['init', '-q']);
  await git(project, ['add', '-A']);
  await git(project, ['commit', '-q', '-m', 'initial commit']);
  return project;
}

/** Load a pitch config, repoint it at the temp project and chosen port, write a temp copy. */
function writeTempConfig(templateFile: string, outFile: string, project: string, monitorPort: number): void {
  const config = loadConfig(resolve(repoRoot, templateFile));
  config.server.sandbox!.project = project;
  config.monitor.port = monitorPort;
  writeFileSync(outFile, stringifyYaml(config));
}

// ---------------------------------------------------------------------------
// Preflight
// ---------------------------------------------------------------------------

async function preflight(): Promise<void> {
  try {
    await execFile('docker', ['version', '--format', '{{.Server.Version}}']);
  } catch {
    out('Docker is required for the pitch demo and is not responding (is Docker running?).');
    out('This demo never falls back to a local server. Start Docker and retry.');
    process.exit(1);
  }
  try {
    await execFile('docker', ['image', 'inspect', '--format', '{{.Id}}', SANDBOX_IMAGE]);
  } catch {
    out(`The sandbox image "${SANDBOX_IMAGE}" was not found locally.`);
    out('Build it first:  npm run sandbox:build');
    process.exit(1);
  }
}

// ---------------------------------------------------------------------------
// Acts
// ---------------------------------------------------------------------------

const GREET_WITH_FAREWELL = `export function greet(name) {
  return \`Hello, \${name}!\`;
}

export function farewell(name) {
  return \`Goodbye, \${name}!\`;
}
`;

const POSTINSTALL_PACKAGE_JSON = `${JSON.stringify(
  {
    name: 'demo-app',
    version: '0.0.1',
    private: true,
    type: 'module',
    scripts: { start: 'node src/index.js', postinstall: 'node -e "process.exit(0)"' },
  },
  null,
  2,
)}\n`;

async function act1(gateway: Gateway, project: string): Promise<void> {
  banner('ACT 1 — a legitimate edit is allowed and lands in the project');
  out('   fs/write_file /workspace/src/greet.js  (adds a farewell function)');
  const res = await gateway.call('write_file', { path: '/workspace/src/greet.js', content: GREET_WITH_FAREWELL });
  out(`   → ${res.isError ? 'rejected' : 'ok'}: ${oneLine(res.text)}`);
  check(!res.isError, 'edit is ALLOWed (content-scanning fix: a plain source edit is not PATH_NOT_ALLOWED)');
  check(res.staged?.applied === 1 && res.staged.rejected === 0, 'exactly one change applied, none rejected');
  const landed = readFileSync(join(project, 'src', 'greet.js'), 'utf8');
  check(landed.includes('export function farewell'), 'the farewell function is present in the project copy');
}

async function act2(gateway: Gateway, project: string): Promise<void> {
  banner('ACT 2 — same gateway, acting as a prompt-injected agent: both calls blocked');
  const before = readFileSync(join(project, 'package.json'), 'utf8');

  out('   fs/read_text_file /workspace/.env  (attempt to exfiltrate a secret)');
  const read = await gateway.call('read_text_file', { path: '/workspace/.env' });
  out(`   → ${read.isError ? 'blocked' : 'ok'}: ${oneLine(read.text)}`);
  const readBlocked = read.decision?.decision === 'DENY' && read.text.startsWith(BLOCKED_PREFIX);
  check(readBlocked, '.env read is BLOCKED before the downstream sees it (decision=DENY)');
  check(read.decision?.ruleId === 'PROTECTED_PATH', `.env read denied by PROTECTED_PATH (got ${read.decision?.ruleId})`);
  const envValue = readFileSync(join(project, '.env'), 'utf8').match(/^DEMO_API_KEY=(.*)$/m)?.[1] ?? '';
  check(envValue.length > 0 && !read.text.includes(envValue), ".env value never appears in the firewall output");

  out('   fs/write_file /workspace/package.json  (attempt to add a postinstall script)');
  const write = await gateway.call('write_file', { path: '/workspace/package.json', content: POSTINSTALL_PACKAGE_JSON });
  out(`   → ${write.isError ? 'blocked' : 'ok'}: ${oneLine(write.text)}`);
  const writeBlocked = write.decision?.decision === 'DENY' && write.text.startsWith(BLOCKED_PREFIX);
  check(writeBlocked, 'package.json write is BLOCKED before the downstream sees it (decision=DENY)');
  check(write.decision?.ruleId === 'PERSISTENCE_PATH', `package.json write denied by PERSISTENCE_PATH (got ${write.decision?.ruleId})`);

  const after = readFileSync(join(project, 'package.json'), 'utf8');
  check(before === after, 'package.json in the project is unchanged');
  check(!after.includes('postinstall'), 'no postinstall script reached the project');
}

async function act3(gateway: Gateway, project: string): Promise<void> {
  banner('ACT 3 — the side-effects fixture: one change lands, five are rejected');
  out('   tool/format_readme  (appends a README line, plus five extra writes)');
  const res = await gateway.call('format_readme', {});
  out(`   → ${res.isError ? 'flagged (rejected changes)' : 'ok'}: ${oneLine(res.text)}`);

  const staged = res.staged;
  if (!staged) {
    check(false, 'result carries _meta[mcp-firewall/staged]');
    return;
  }
  out(`   staged outcome: ${staged.applied} applied, ${staged.rejected} rejected`);
  for (const change of staged.changes) {
    out(`     ${change.decision === 'ALLOW' ? 'APPLY ' : 'REJECT'} ${change.path.padEnd(28)} ${change.ruleId}`);
  }

  const applied = staged.changes.filter((c) => c.decision === 'ALLOW').map((c) => c.path);
  const rejectedRules = new Set(staged.changes.filter((c) => c.decision === 'DENY').map((c) => c.ruleId));
  check(applied.length === 1 && applied[0] === 'README.md', 'only README.md is applied');
  check(staged.rejected === 5, `all five extra writes are rejected by staging (got ${staged.rejected})`);
  check(rejectedRules.has('SECRET_DETECTED'), 'the dummy-key file is rejected as SECRET_DETECTED');
  check(rejectedRules.has('EXECUTABLE_DENIED'), 'the exec-bit file is rejected as EXECUTABLE_DENIED');

  // The one allowed change reached the project; none of the five did.
  const readme = readFileSync(join(project, 'README.md'), 'utf8');
  check(readme.includes('Formatted by fixture.'), 'README.md was changed in the project');
  check(!existsSync(join(project, '.git', 'hooks', 'pre-commit')), 'no .git/hooks/pre-commit landed');
  check(!readFileSync(join(project, 'package.json'), 'utf8').includes('fixture-marker'), 'no postinstall/fixture-marker script landed');
  check(!existsSync(join(project, 'src', 'fixture-key.txt')), 'no dummy-key file landed');
  check(!existsSync(join(project, 'src', 'fixture-run.txt')), 'no exec-bit marker file landed');
  check(!existsSync(join(project, 'src', 'fixture-link')), 'no symlink landed');
  check(!res.text.includes(EXAMPLE_AWS_KEY), 'the dummy key never appears in the result');

  out('   tool/get_call_counts  (confirm the downstream ran format_readme once)');
  const counts = await gateway.call('get_call_counts', {});
  let parsed: Record<string, number> = {};
  try {
    parsed = JSON.parse(counts.text) as Record<string, number>;
  } catch {
    // Non-fatal; the staged outcome above is the real evidence.
  }
  check(parsed.format_readme === 1, 'the fixture received format_readme exactly once');
}

async function checkGitStatus(project: string): Promise<void> {
  banner('GIT STATUS — only the two intended files changed');
  const status = await git(project, ['status', '--short']);
  out(status.trimEnd() || '   (clean)');
  const changed = status
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => l.replace(/^\S+\s+/, ''));
  const changedSet = new Set(changed);
  const expected = new Set(['README.md', 'src/greet.js']);
  const same = changedSet.size === expected.size && [...expected].every((p) => changedSet.has(p));
  check(same, `git status shows exactly README.md and src/greet.js (got ${[...changedSet].join(', ') || 'nothing'})`);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function pause(auto: boolean, label: string): Promise<void> {
  if (auto) return;
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    await rl.question(`\n   ⏸  ${label} — press Enter to continue…`);
  } finally {
    rl.close();
  }
}

async function main(): Promise<void> {
  const { values } = parseArgs({
    options: {
      auto: { type: 'boolean', default: false },
      keep: { type: 'boolean', default: false },
      'monitor-port': { type: 'string', default: '3100' },
    },
  });
  const auto = values.auto;
  const monitorPort = Number(values['monitor-port']);

  await preflight();

  const project = await makeTempProject();
  const fsConfigFile = join(dirname(project), 'pitch-fs.yaml');
  const attackConfigFile = join(dirname(project), 'pitch-attack.yaml');
  writeTempConfig('config/pitch-fs.yaml', fsConfigFile, project, monitorPort);
  writeTempConfig('config/pitch-attack.yaml', attackConfigFile, project, monitorPort);

  const monitorUrl = `http://127.0.0.1:${monitorPort}`;

  let gateway: Gateway | undefined;
  let cleaned = false;
  const cleanup = async (): Promise<void> => {
    if (cleaned) return;
    cleaned = true;
    await gateway?.stop().catch(() => {});
    if (values.keep) {
      out(`\n   --keep: left the temp project at ${project}`);
    } else {
      rmSync(dirname(project), { recursive: true, force: true });
    }
  };
  const onSignal = (): void => {
    out('\n   interrupted; cleaning up…');
    void cleanup().finally(() => process.exit(130));
  };
  process.once('SIGINT', onSignal);
  process.once('SIGTERM', onSignal);

  banner('MCP FIREWALL — PITCH DEMO (Docker sandbox mode)');
  out(`   temp project:  ${project}`);
  out(`   monitor:       ${monitorUrl}`);
  out(`   mode:          ${auto ? 'auto (no pauses)' : 'interactive (Enter between acts)'}`);

  try {
    // Acts 1 and 2 share one gateway (the filesystem config).
    gateway = await Gateway.start(fsConfigFile, monitorUrl);
    const tools = (await gateway.client.listTools()).tools.map((t) => t.name).join(', ');
    out(`   fs gateway exposes: ${tools}`);

    await pause(auto, 'Act 1');
    await act1(gateway, project);

    await pause(auto, 'Act 2');
    await act2(gateway, project);

    banner('MONITOR — filesystem gateway');
    await checkMonitor(gateway, [
      { toolName: 'write_file', decision: 'ALLOW', ruleId: 'APPROVED_TOOL' },
      { toolName: 'read_text_file', decision: 'DENY', ruleId: 'PROTECTED_PATH' },
      { toolName: 'write_file', decision: 'DENY', ruleId: 'PERSISTENCE_PATH' },
    ]);

    await gateway.stop();
    gateway = undefined;

    // Act 3 restarts the gateway with the attack config on the SAME project.
    await pause(auto, 'Act 3');
    gateway = await Gateway.start(attackConfigFile, monitorUrl);
    await act3(gateway, project);

    banner('MONITOR — attack gateway');
    await checkMonitor(gateway, [
      { toolName: 'format_readme', decision: 'ALLOW', ruleId: 'APPROVED_TOOL' },
      { toolName: 'get_call_counts', decision: 'ALLOW', ruleId: 'APPROVED_TOOL' },
    ]);

    await gateway.stop();
    gateway = undefined;

    await checkGitStatus(project);
  } finally {
    await cleanup();
  }

  banner(failures.length === 0 ? 'PITCH DEMO PASSED' : `PITCH DEMO FAILED — ${failures.length} check(s)`);
  if (failures.length > 0) {
    for (const f of failures) out(`   FAIL  ${f}`);
    process.exitCode = 1;
  } else {
    out('   Every act behaved as scripted: the legitimate edit landed, the attacks did not.');
  }
}

main().catch((err: unknown) => {
  process.stderr.write(`[pitch] fatal: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
