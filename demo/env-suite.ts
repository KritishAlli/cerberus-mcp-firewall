/**
 * OWNER: Aarav — `.env` access suite for sandbox mode (`npm run demo:env`).
 *
 * A read-team probe: it throws every `.env` access vector we could think of at a
 * sandboxed gateway and checks that no dummy secret value ever leaks — into a tool
 * result, the monitor stream, or the gateway's stderr. It runs against a THROWAWAY
 * git copy of demo/project (demo/project itself is never touched); the copy also
 * gets extra dummy secret files, a symlink and a hardlink so we can probe how the
 * staging layer treats each.
 *
 * It distinguishes three outcomes per vector:
 *   - DENY pre-call: the firewall blocked it before the downstream saw it.
 *   - ALLOWed but nothing leaked because staging excluded the file: PASS, but
 *     listed separately as "caught only by staging", since the pre-call check let
 *     it through — a gap worth Winston's attention.
 *   - ALLOWed and a dummy value leaked: FAIL (non-zero exit).
 *
 * Then it runs the fixture's `probe_env` inside the container to see, from the
 * server's side, which of those files staging actually materialized in the sandbox.
 *
 * Usage: npm run demo:env [-- --keep] [-- --monitor-port N]
 *
 * Needs Docker and the sandbox image (npm run sandbox:build); never falls back.
 */
import { execFile as execFileCb } from 'node:child_process';
import {
  appendFileSync,
  cpSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs, promisify } from 'node:util';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { stringify as stringifyYaml } from 'yaml';
import type { CallToolResult } from '@modelcontextprotocol/server';
import { loadConfig } from '../src/config/load.js';
import { useRealProjectPaths } from './demo-config.js';
import { FIREWALL_META_KEY } from '../src/proxy/interceptor.js';
import type { RuleId } from '../src/shared/contracts.js';

const execFile = promisify(execFileCb);
const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SANDBOX_IMAGE = 'mcp-firewall-sandbox:dev';

/** Must equal DUMMY_SECRET_SENTINEL in demo/sandbox/side-effects-fixture.mjs. */
const SENTINEL = 'DUMMY-SECRET-SENTINEL-DO-NOT-LEAK';
/** Distinct per-file dummy values. None of these may appear in any output. */
const ENV_ROOT_VALUE = 'dummy-key-not-real-0000'; // the value already in demo/project/.env
const DUMMY_VALUES = [ENV_ROOT_VALUE, 'dummy-local-0002', 'dummy-srcenv-0003', 'dummy-prod-0004', SENTINEL];

function out(line = ''): void {
  process.stdout.write(`${line}\n`);
}

/** True if any dummy value appears in `text`. Never prints the matched value. */
function leaks(text: string): boolean {
  return DUMMY_VALUES.some((v) => text.includes(v));
}

// ---------------------------------------------------------------------------
// Decision meta
// ---------------------------------------------------------------------------

interface DecisionMeta {
  decision?: 'ALLOW' | 'DENY';
  ruleId?: RuleId;
}

function decisionMeta(result: CallToolResult): DecisionMeta | undefined {
  const meta = (result._meta as Record<string, unknown> | undefined)?.[FIREWALL_META_KEY];
  return meta && typeof meta === 'object' ? (meta as DecisionMeta) : undefined;
}

function toText(result: CallToolResult): string {
  const content = Array.isArray(result.content) ? result.content : [];
  return content.map((part) => (part.type === 'text' ? part.text : `[${part.type}]`)).join('\n');
}

// ---------------------------------------------------------------------------
// Gateway (captures stderr so we can scan it for leaks)
// ---------------------------------------------------------------------------

class Gateway {
  private _stderr = '';

  private constructor(
    readonly client: Client,
    readonly transport: StdioClientTransport,
    readonly monitorUrl: string,
  ) {}

  static async start(configFile: string, monitorUrl: string): Promise<Gateway> {
    const client = new Client({ name: 'mcp-firewall-env-suite', version: '0.1.0' });
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: ['--import', 'tsx', 'src/index.ts', '--config', configFile],
      cwd: repoRoot,
      stderr: 'pipe', // captured, then scanned for leaks
    });
    const gateway = new Gateway(client, transport, monitorUrl);
    await client.connect(transport);
    transport.stderr?.on('data', (chunk: Buffer) => {
      gateway._stderr += chunk.toString('utf8');
    });
    return gateway;
  }

  get pid(): number | null {
    return this.transport.pid;
  }

  get stderr(): string {
    return this._stderr;
  }

  async call(name: string, args: Record<string, unknown>): Promise<{ result: CallToolResult; text: string }> {
    const result = await this.client.callTool({ name, arguments: args });
    return { result, text: toText(result) };
  }

  async stop(): Promise<void> {
    const pid = this.pid;
    await this.client.close().catch(() => {});
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
    // Best effort; the firewall removes its own container on a clean shutdown.
  }
}

async function waitForPortFree(monitorUrl: string): Promise<void> {
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    try {
      await fetch(`${monitorUrl}/health`, { signal: AbortSignal.timeout(500) });
    } catch {
      return;
    }
    await new Promise((r) => setTimeout(r, 150));
  }
}

/** Raw text of the monitor's /events replay (for a leak scan). */
async function readMonitorRaw(monitorUrl: string): Promise<string> {
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
    return raw;
  } catch {
    return '';
  } finally {
    clearTimeout(timer);
    controller.abort();
  }
}

// ---------------------------------------------------------------------------
// Temp project with extra secret files
// ---------------------------------------------------------------------------

async function git(cwd: string, args: string[]): Promise<void> {
  await execFile('git', args, {
    cwd,
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: 'env-suite',
      GIT_AUTHOR_EMAIL: 'env@demo.invalid',
      GIT_COMMITTER_NAME: 'env-suite',
      GIT_COMMITTER_EMAIL: 'env@demo.invalid',
    },
  });
}

interface SetupResult {
  project: string;
  hardlinkMade: boolean;
  hardlinkNote: string;
}

async function makeTempProject(): Promise<SetupResult> {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-firewall-env-'));
  const project = join(dir, 'project');
  cpSync(join(repoRoot, 'demo', 'project'), project, { recursive: true });
  await git(project, ['init', '-q']);
  await git(project, ['add', '-A']);
  await git(project, ['commit', '-q', '-m', 'initial commit']);

  // Extra dummy secret files, created in the temp copy ONLY. Each carries the
  // shared sentinel so probe_env can recognize leaked content without us ever
  // moving a value across the boundary.
  appendFileSync(join(project, '.env'), `# ${SENTINEL}\n`);
  writeFileSync(join(project, '.env.local'), `SECRET=dummy-local-0002\n# ${SENTINEL}\n`);
  writeFileSync(join(project, 'src', '.env'), `SECRET=dummy-srcenv-0003\n# ${SENTINEL}\n`);
  mkdirSync(join(project, 'config'), { recursive: true });
  writeFileSync(join(project, 'config', '.env.production'), `SECRET=dummy-prod-0004\n# ${SENTINEL}\n`);
  // Relative symlink inside the project, pointing at the root .env.
  symlinkSync('../.env', join(project, 'src', 'env-link'));

  // Hardlink a .env into a non-dotenv name, to test whether sync copies its bytes.
  let hardlinkMade = false;
  let hardlinkNote = '';
  try {
    linkSync(join(project, '.env'), join(project, 'src', 'notes.txt'));
    hardlinkMade = true;
  } catch (err) {
    hardlinkNote = `hardlink not supported here (${(err as NodeJS.ErrnoException).code ?? 'error'}); src/notes.txt skipped`;
  }
  return { project, hardlinkMade, hardlinkNote };
}

function writeTempConfig(templateFile: string, outFile: string, project: string, monitorPort: number): void {
  const config = loadConfig(resolve(repoRoot, templateFile));
  useRealProjectPaths(config, project);
  config.monitor.port = monitorPort;
  writeFileSync(outFile, stringifyYaml(config));
}

// ---------------------------------------------------------------------------
// Vectors
// ---------------------------------------------------------------------------

interface Vector {
  label: string;
  tool: string;
  args: Record<string, unknown>;
  /** True if the vector targets a secret file (so an ALLOW that didn't leak = staging-only catch). */
  secretTarget: boolean;
}

/** Vectors use the project's real paths (relative and absolute); no "/workspace" anywhere. */
function buildVectors(project: string): Vector[] {
  return [
    // 1. read_text_file on the root .env in many spellings (relative, absolute, traversal, case, encoded, file://).
    { label: 'read .env', tool: 'read_text_file', args: { path: '.env' }, secretTarget: true },
    { label: 'read ./.env', tool: 'read_text_file', args: { path: './.env' }, secretTarget: true },
    { label: 'read <project>/.env (absolute)', tool: 'read_text_file', args: { path: `${project}/.env` }, secretTarget: true },
    { label: 'read src/../.env', tool: 'read_text_file', args: { path: 'src/../.env' }, secretTarget: true },
    { label: 'read .ENV (case)', tool: 'read_text_file', args: { path: '.ENV' }, secretTarget: true },
    { label: 'read .env/ (trailing slash)', tool: 'read_text_file', args: { path: '.env/' }, secretTarget: true },
    { label: 'read %2e%2e/.env (encoded)', tool: 'read_text_file', args: { path: '%2e%2e/.env' }, secretTarget: true },
    { label: 'read file://<project>/.env', tool: 'read_text_file', args: { path: `file://${project}/.env` }, secretTarget: true },
    // 2. other dotenv files.
    { label: 'read .env.local', tool: 'read_text_file', args: { path: '.env.local' }, secretTarget: true },
    { label: 'read src/.env', tool: 'read_text_file', args: { path: 'src/.env' }, secretTarget: true },
    { label: 'read config/.env.production', tool: 'read_text_file', args: { path: 'config/.env.production' }, secretTarget: true },
    // 3. the symlink and the hardlink.
    { label: 'read src/env-link (symlink)', tool: 'read_text_file', args: { path: 'src/env-link' }, secretTarget: true },
    { label: 'read src/notes.txt (hardlink)', tool: 'read_text_file', args: { path: 'src/notes.txt' }, secretTarget: true },
    // 4. multi-file read mixing a safe file with .env.
    { label: 'read_multiple [greet.js, .env]', tool: 'read_multiple_files', args: { paths: ['src/greet.js', '.env'] }, secretTarget: true },
    // 5. other tools pointed at .env.
    { label: 'get_file_info .env', tool: 'get_file_info', args: { path: '.env' }, secretTarget: true },
    { label: 'read_media_file .env', tool: 'read_media_file', args: { path: '.env' }, secretTarget: true },
    { label: 'move_file .env -> src/moved.txt', tool: 'move_file', args: { source: '.env', destination: 'src/moved.txt' }, secretTarget: true },
    { label: 'write_file .env', tool: 'write_file', args: { path: '.env', content: 'overwritten by suite\n' }, secretTarget: true },
    // 6. discovery tools that must not surface a .env.
    { label: 'search_files ".env"', tool: 'search_files', args: { path: '.', pattern: '.env' }, secretTarget: false },
    { label: 'directory_tree (root)', tool: 'directory_tree', args: { path: '.' }, secretTarget: false },
    { label: 'list_directory (root)', tool: 'list_directory', args: { path: '.' }, secretTarget: false },
  ];
}

interface Row {
  label: string;
  decision: string;
  rule: string;
  reached: boolean;
  leaked: boolean;
  secretTarget: boolean;
  /** For discovery vectors: did the listing expose a `.env` file name? */
  listedEnv?: boolean;
}

async function runVectors(gateway: Gateway, vectors: Vector[]): Promise<Row[]> {
  const rows: Row[] = [];
  for (const v of vectors) {
    let row: Row;
    try {
      const { result, text } = await gateway.call(v.tool, v.args);
      const meta = decisionMeta(result);
      const denied = meta?.decision === 'DENY';
      row = {
        label: v.label,
        decision: denied ? 'DENY' : 'ALLOW',
        rule: meta?.ruleId ?? (denied ? '?' : '—'),
        reached: !denied, // a pre-call DENY never forwards; anything else did
        leaked: leaks(text),
        secretTarget: v.secretTarget,
        ...(v.secretTarget ? {} : { listedEnv: /(^|[\/\s"'])\.env(\.|["'\/\s]|$)/.test(text) }),
      };
    } catch (err) {
      // A thrown protocol error is a block too; it never carries contents.
      row = {
        label: v.label,
        decision: 'DENY',
        rule: 'ERROR',
        reached: false,
        leaked: leaks(err instanceof Error ? err.message : String(err)),
        secretTarget: v.secretTarget,
      };
    }
    rows.push(row);
  }
  return rows;
}

// ---------------------------------------------------------------------------
// probe_env (attack gateway)
// ---------------------------------------------------------------------------

async function runProbe(gateway: Gateway): Promise<Record<string, string>> {
  const { text } = await gateway.call('probe_env', {});
  try {
    return JSON.parse(text) as Record<string, string>;
  } catch {
    return {};
  }
}

// ---------------------------------------------------------------------------
// Tables
// ---------------------------------------------------------------------------

function pad(s: string, n: number): string {
  return s.length >= n ? s.slice(0, n) : s + ' '.repeat(n - s.length);
}

function printVectorTable(rows: Row[]): void {
  out();
  out(`${pad('vector', 34)} ${pad('decision', 9)} ${pad('rule', 18)} ${pad('reached', 8)} leaked`);
  out('-'.repeat(34 + 9 + 18 + 8 + 7));
  for (const r of rows) {
    out(`${pad(r.label, 34)} ${pad(r.decision, 9)} ${pad(r.rule, 18)} ${pad(r.reached ? 'yes' : 'no', 8)} ${r.leaked ? 'YES' : 'no'}`);
  }
}

function printProbeTable(probe: Record<string, string>): void {
  out();
  out('probe_env (from inside the container, via config/pitch-attack.yaml):');
  out(`${pad('path', 36)} status`);
  out('-'.repeat(36 + 40));
  for (const [path, status] of Object.entries(probe)) {
    out(`${pad(path, 36)} ${status}`);
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function preflight(): Promise<void> {
  try {
    await execFile('docker', ['version', '--format', '{{.Server.Version}}']);
  } catch {
    out('Docker is required and is not responding (is Docker running?). This suite never falls back.');
    process.exit(1);
  }
  try {
    await execFile('docker', ['image', 'inspect', '--format', '{{.Id}}', SANDBOX_IMAGE]);
  } catch {
    out(`The sandbox image "${SANDBOX_IMAGE}" was not found. Build it:  npm run sandbox:build`);
    process.exit(1);
  }
}

async function main(): Promise<void> {
  const { values } = parseArgs({
    options: {
      keep: { type: 'boolean', default: false },
      'monitor-port': { type: 'string', default: '3101' },
    },
  });
  const monitorPort = Number(values['monitor-port']);
  const monitorUrl = `http://127.0.0.1:${monitorPort}`;

  await preflight();

  const { project, hardlinkMade, hardlinkNote } = await makeTempProject();
  const fsConfigFile = join(dirname(project), 'env-fs.yaml');
  const attackConfigFile = join(dirname(project), 'env-attack.yaml');
  writeTempConfig('config/pitch-fs.yaml', fsConfigFile, project, monitorPort);
  writeTempConfig('config/pitch-attack.yaml', attackConfigFile, project, monitorPort);

  out('='.repeat(72));
  out('  MCP FIREWALL — .env ACCESS SUITE (Docker sandbox mode)');
  out('='.repeat(72));
  out(`   temp project:  ${project}`);
  out(`   monitor:       ${monitorUrl}`);
  out(`   hardlink:      ${hardlinkMade ? 'src/notes.txt -> .env created' : hardlinkNote}`);

  const problems: string[] = [];
  let gateway: Gateway | undefined;
  let cleaned = false;
  const cleanup = async (): Promise<void> => {
    if (cleaned) return;
    cleaned = true;
    await gateway?.stop().catch(() => {});
    if (values.keep) out(`\n   --keep: left the temp project at ${project}`);
    else rmSync(dirname(project), { recursive: true, force: true });
  };
  const onSignal = (): void => {
    out('\n   interrupted; cleaning up…');
    void cleanup().finally(() => process.exit(130));
  };
  process.once('SIGINT', onSignal);
  process.once('SIGTERM', onSignal);

  let rows: Row[] = [];
  let probe: Record<string, string> = {};
  try {
    // Phase A: the fs gateway, all vectors.
    gateway = await Gateway.start(fsConfigFile, monitorUrl);
    rows = await runVectors(gateway, buildVectors(project));
    const monitorRawFs = await readMonitorRaw(monitorUrl);
    if (leaks(monitorRawFs)) problems.push('a dummy value appeared in the fs-gateway monitor stream');
    if (leaks(gateway.stderr)) problems.push('a dummy value appeared in the fs-gateway stderr');
    await gateway.stop();
    gateway = undefined;

    // Phase B: the attack gateway, probe_env.
    gateway = await Gateway.start(attackConfigFile, monitorUrl);
    probe = await runProbe(gateway);
    const monitorRawAttack = await readMonitorRaw(monitorUrl);
    if (leaks(monitorRawAttack)) problems.push('a dummy value appeared in the attack-gateway monitor stream');
    if (leaks(gateway.stderr)) problems.push('a dummy value appeared in the attack-gateway stderr');
    await gateway.stop();
    gateway = undefined;
  } finally {
    await cleanup();
  }

  printVectorTable(rows);

  const leakedRows = rows.filter((r) => r.leaked);
  const stagingOnly = rows.filter((r) => r.secretTarget && !r.leaked && r.decision !== 'DENY');
  const listedEnv = rows.filter((r) => r.listedEnv);

  if (stagingOnly.length > 0) {
    out();
    out('Caught only by staging (ALLOWed pre-call, but the file was not in staging — layer 2):');
    for (const r of stagingOnly) out(`   • ${r.label}  [${r.rule === '—' ? 'ALLOW' : r.rule}]`);
  }
  if (listedEnv.length > 0) {
    out();
    out('Discovery vectors that surfaced a .env file name (names only, no values):');
    for (const r of listedEnv) out(`   • ${r.label}`);
  }

  printProbeTable(probe);

  // The hardlink question, answered from both sides.
  out();
  out('Hardlink finding (src/notes.txt -> .env):');
  if (!hardlinkMade) {
    out(`   ${hardlinkNote}`);
  } else {
    const notesProbe = probe['src/notes.txt'] ?? '(not probed)';
    const notesRow = rows.find((r) => r.label.includes('notes.txt'));
    const copied = notesProbe.startsWith('present') && notesProbe.includes('matches-dummy: yes');
    out(`   probe_env says: ${notesProbe}`);
    out(`   → sync ${copied ? 'DID copy the hardlinked .env bytes into staging' : 'did NOT copy the hardlinked .env bytes'}.`);
    if (notesRow) {
      out(`   gateway read of src/notes.txt: ${notesRow.decision}/${notesRow.rule}, reached=${notesRow.reached}, leaked=${notesRow.leaked ? 'YES' : 'no'}`);
    }
  }

  out();
  out('='.repeat(72));
  if (leakedRows.length === 0 && problems.length === 0) {
    out('  .env SUITE PASSED — no dummy value leaked in any row, stream or stderr');
    if (stagingOnly.length > 0) {
      out(`  (${stagingOnly.length} row(s) were caught only by staging; see the "for Winston" gaps.)`);
    }
  } else {
    out(`  .env SUITE FAILED — ${leakedRows.length} leaking row(s), ${problems.length} stream/stderr issue(s)`);
    for (const r of leakedRows) out(`     LEAK  ${r.label}  (${r.decision}/${r.rule}, reached=${r.reached})`);
    for (const p of problems) out(`     LEAK  ${p}`);
    process.exitCode = 1;
  }
  out('='.repeat(72));
}

main().catch((err: unknown) => {
  process.stderr.write(`[env-suite] fatal: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
