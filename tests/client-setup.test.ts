/**
 * OWNER: Kritish — client setup preview: commands and snippets only, nothing is written.
 */
import { spawnSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';
import {
  claudeAddCommand,
  claudeRemoveCommand,
  codexTomlBlock,
  gatewayCommand,
  nodeVersionOk,
  shellQuote,
} from '../src/config/client-setup.js';

/** Parses TOML with Python's standard tomllib (3.11+), so the check is independent of our writer. */
function parseToml(text: string): unknown {
  const py = spawnSync('python3', ['-c', 'import json, sys, tomllib; print(json.dumps(tomllib.loads(sys.stdin.read())))'], {
    input: text,
    encoding: 'utf8',
  });
  if (py.status !== 0) throw new Error(`tomllib failed: ${py.stderr}`);
  return JSON.parse(py.stdout);
}
const hasTomllib = spawnSync('python3', ['-c', 'import tomllib']).status === 0;

const paths = { nodePath: '/usr/local/bin/node', repoRoot: '/home/dev/mcp firewall', configPath: '/home/dev/cfg/sandbox.yaml' };

describe('client setup preview', () => {
  it('builds a launch command with absolute paths only, importing tsx by file URL', () => {
    const cmd = gatewayCommand(paths);
    expect(cmd.command).toBe('/usr/local/bin/node');
    // A bare `--import tsx` resolves against the client's cwd and fails outside the repo.
    expect(cmd.args).toEqual([
      '--import',
      'file:///home/dev/mcp%20firewall/node_modules/tsx/dist/loader.mjs',
      '/home/dev/mcp firewall/src/index.ts',
      '--config',
      '/home/dev/cfg/sandbox.yaml',
    ]);
  });

  it('quotes shell arguments so a path with spaces or quotes stays one argument', () => {
    expect(shellQuote('/plain/path.ts')).toBe('/plain/path.ts');
    const tricky = "/tmp/it's $HOME/a b";
    const echoed = spawnSync('sh', ['-c', `printf %s ${shellQuote(tricky)}`], { encoding: 'utf8' }).stdout;
    expect(echoed).toBe(tricky);
  });

  it('adds and removes only the named Claude Code entry', () => {
    const add = claudeAddCommand('mcp_firewall', 'local', gatewayCommand(paths));
    expect(add.startsWith('claude mcp add --scope local mcp_firewall -- /usr/local/bin/node --import ')).toBe(true);
    expect(add).toContain("'/home/dev/mcp firewall/src/index.ts'");
    expect(claudeRemoveCommand('mcp_firewall', 'user')).toBe('claude mcp remove --scope user mcp_firewall');
  });

  it.skipIf(!hasTomllib)('emits a Codex TOML table that parses back to the same command', () => {
    const cmd = gatewayCommand({ ...paths, configPath: '/home/dev/"quoted"\\cfg.yaml' });
    const parsed = parseToml(codexTomlBlock('mcp_firewall', cmd));
    expect(parsed).toEqual({ mcp_servers: { mcp_firewall: { command: cmd.command, args: cmd.args } } });
  });

  it('refuses a server name that would break the TOML table header', () => {
    expect(() => codexTomlBlock('a.b]', gatewayCommand(paths))).toThrow();
  });

  it('requires Node 22.12 or newer', () => {
    expect(nodeVersionOk('v22.12.0')).toBe(true);
    expect(nodeVersionOk('v24.4.0')).toBe(true);
    expect(nodeVersionOk('v22.11.9')).toBe(false);
    expect(nodeVersionOk('v20.19.0')).toBe(false);
  });
});
