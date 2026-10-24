/**
 * OWNER: Kritish — client setup preview (Cerberus §4.3 task 4, §8).
 *
 * Prints the exact, machine-specific commands and config snippets that connect a
 * supported client to this gateway, and the matching removal steps. It NEVER writes
 * a client's config: Claude Code's own `claude mcp add/remove` edits only the named
 * entry, and Codex's TOML is edited by hand (see docs/SETUP.md). Generating the text
 * here removes the two mistakes seen in practice: a guessed Node path, and a bare
 * `--import tsx` that only resolves when the client starts the gateway from the repo.
 *
 * Usage (from the repo):
 *   node --import tsx src/config/client-setup.ts [--client claude|codex|all]
 *        [--config config/sandbox.yaml] [--name mcp_firewall] [--scope local|user]
 *
 * Checks before printing: the config loads, Node is 22.12+, the tsx loader exists, and in
 * sandbox mode Docker answers and the image exists. Output goes to stdout; exits 1 on a failed check.
 */
import { existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import { preflightDocker } from '../proxy/upstream.js';
import { loadConfig } from './load.js';

export const DEFAULT_SERVER_NAME = 'mcp_firewall';
const MIN_NODE: readonly [number, number] = [22, 12];

export interface GatewayCommand {
  command: string;
  args: string[];
}

export interface GatewayPaths {
  /** Absolute path of the Node 22.12+ executable the client should run. */
  nodePath: string;
  repoRoot: string;
  /** Absolute path of the firewall config. */
  configPath: string;
}

/**
 * The gateway's launch command, with every path absolute so it works whatever cwd the
 * client uses. tsx is imported by file URL: a bare `--import tsx` resolves against the
 * client's cwd and fails outside the repo.
 */
export function gatewayCommand({ nodePath, repoRoot, configPath }: GatewayPaths): GatewayCommand {
  const loader = pathToFileURL(resolve(repoRoot, 'node_modules/tsx/dist/loader.mjs')).href;
  return {
    command: nodePath,
    args: ['--import', loader, resolve(repoRoot, 'src/index.ts'), '--config', configPath],
  };
}

/** POSIX shell quoting: safe for paths with spaces, quotes or `$`. */
export function shellQuote(arg: string): string {
  return /^[A-Za-z0-9_@%+=:,./-]+$/.test(arg) ? arg : `'${arg.replace(/'/g, `'\\''`)}'`;
}

export function claudeAddCommand(name: string, scope: 'local' | 'user', cmd: GatewayCommand): string {
  return ['claude', 'mcp', 'add', '--scope', scope, name, '--', cmd.command, ...cmd.args].map(shellQuote).join(' ');
}

export function claudeRemoveCommand(name: string, scope: 'local' | 'user'): string {
  return ['claude', 'mcp', 'remove', '--scope', scope, name].map(shellQuote).join(' ');
}

/** TOML basic string. JSON escapes are a subset of TOML's, except `\/`, which JSON.stringify never emits. */
function tomlString(value: string): string {
  return JSON.stringify(value);
}

/** The `[mcp_servers.<name>]` table for ~/.codex/config.toml. */
export function codexTomlBlock(name: string, cmd: GatewayCommand): string {
  if (!/^[A-Za-z0-9_-]+$/.test(name)) throw new Error(`server name must be letters, digits, _ or -: ${name}`);
  return [
    `[mcp_servers.${name}]`,
    `command = ${tomlString(cmd.command)}`,
    'args = [',
    ...cmd.args.map((a) => `  ${tomlString(a)},`),
    ']',
  ].join('\n');
}

/** "22.12.0" → true if at least MIN_NODE. */
export function nodeVersionOk(version: string): boolean {
  const [major = 0, minor = 0] = version.replace(/^v/, '').split('.').map(Number);
  return major > MIN_NODE[0] || (major === MIN_NODE[0] && minor >= MIN_NODE[1]);
}

async function main(): Promise<void> {
  const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
  const { values } = parseArgs({
    options: {
      client: { type: 'string', default: 'all' },
      config: { type: 'string', default: resolve(repoRoot, 'config/sandbox.yaml') },
      name: { type: 'string', default: DEFAULT_SERVER_NAME },
      scope: { type: 'string', default: 'local' },
    },
  });
  const client = values.client;
  if (client !== 'claude' && client !== 'codex' && client !== 'all') throw new Error('--client must be claude, codex or all');
  const scope = values.scope;
  if (scope !== 'local' && scope !== 'user') throw new Error('--scope must be local or user');

  const out = (line = ''): void => void process.stdout.write(`${line}\n`);
  const problems: string[] = [];
  const configPath = resolve(values.config);
  const config = loadConfig(configPath);
  const cmd = gatewayCommand({ nodePath: process.execPath, repoRoot, configPath });

  out('Cerberus / MCP Firewall: client setup preview (nothing has been written)');
  out();
  out(`  config:    ${configPath}`);
  out(`  server:    ${config.server.id} (${config.server.sandbox ? `Docker sandbox, image ${config.server.sandbox.image}` : 'local process, NOT sandboxed'})`);
  out(`  monitor:   ${config.monitor.enabled ? `http://${config.monitor.host}:${config.monitor.port}` : 'disabled'}`);
  out(`  node:      ${process.execPath} (${process.version})`);
  // Homebrew's Cellar path changes on every upgrade, which silently breaks the client's entry.
  if (process.execPath.includes('/Cellar/')) {
    out('  note:      this Node path is versioned by Homebrew; /opt/homebrew/bin/node (or `which node`) survives upgrades');
  }
  if (!nodeVersionOk(process.version)) problems.push(`Node ${process.version} is older than ${MIN_NODE.join('.')}; run \`nvm use\` first`);
  if (!existsSync(fileURLToPath(cmd.args[1]!))) problems.push('tsx is not installed; run `npm ci` in the repo first');
  if (config.server.sandbox) {
    try {
      await preflightDocker(config.server.sandbox.image);
      out('  docker:    ok, image present');
    } catch (err) {
      problems.push(`${err instanceof Error ? err.message : String(err)} (build the image with \`npm run sandbox:build\`)`);
    }
  }
  out();

  if (client === 'claude' || client === 'all') {
    out(`Claude Code (${scope} scope${scope === 'local' ? ': only in the folder you run this from' : ': every folder'})`);
    out('  connect:');
    out(`    ${claudeAddCommand(values.name, scope, cmd)}`);
    out('  check:');
    out(`    claude mcp get ${shellQuote(values.name)}`);
    out('  remove (only this entry; other servers are untouched):');
    out(`    ${claudeRemoveCommand(values.name, scope)}`);
    out();
  }
  if (client === 'codex' || client === 'all') {
    out('Codex: add this table to ~/.codex/config.toml by hand (back the file up first)');
    out();
    out(codexTomlBlock(values.name, cmd));
    out();
    out(`  remove: delete only the [mcp_servers.${values.name}] table, then restart Codex.`);
    out();
  }
  out('Only calls routed through this server are protected. See docs/SETUP.md for checks and recovery.');

  if (problems.length > 0) {
    out();
    for (const p of problems) out(`NOT READY: ${p}`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((err: unknown) => {
    process.stderr.write(`[client-setup] ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(1);
  });
}
