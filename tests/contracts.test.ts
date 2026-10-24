/**
 * SHARED — baseline tests for the frozen contract and scaffold invariants.
 * These must stay green on main at all times.
 */
import { mkdirSync, mkdtempSync, realpathSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { ConfigError, loadConfig, parseConfig, toUpstreamLaunch } from '../src/config/load.js';
import { UpstreamLaunchSchema } from '../src/proxy/upstream.js';
import { evaluateToolCall } from '../src/security/evaluator.js';
import { evaluateFileChangesStub } from '../src/proxy/stubs/evaluate-file-changes.stub.js';
import {
  ChangeDecisionSchema,
  FileChangeEventSchema,
  FileChangeSchema,
  FirewallEventSchema,
  FirewallPolicySchema,
  MAX_FILE_CHANGE_EVENT_ENTRIES,
  MAX_FILE_CHANGE_EVENT_PATH_LENGTH,
  PolicyDecisionSchema,
  RULE_IDS,
  toCanonicalToolName,
  type FirewallPolicy,
} from '../src/shared/contracts.js';

const examplePath = resolve(import.meta.dirname, '../config/firewall.yaml');

describe('shared contract', () => {
  it('example config/firewall.yaml loads and validates', () => {
    const config = loadConfig(examplePath);
    expect(config.server.id).toBe('demo');
    expect(config.monitor.host).toBe('127.0.0.1');
    expect(config.policy.defaultDecision).toBe('DENY');
    expect(config.server.cwd).toBe(resolve(import.meta.dirname, '..'));
  });

  it('rejects unknown config keys (no silent permissive mode)', () => {
    const text = `server: { id: demo, command: node }\npolicy: { defaultDecision: DENY, allowEverything: true }\n`;
    expect(() => parseConfig(text)).toThrow(ConfigError);
  });

  it('rejects syntactically invalid YAML', () => {
    expect(() => parseConfig('server: [unclosed')).toThrow(ConfigError);
  });

  it('rejects a non-loopback monitor host', () => {
    const text = `server: { id: demo, command: node }\nmonitor: { host: 0.0.0.0 }\npolicy: { defaultDecision: DENY }\n`;
    expect(() => parseConfig(text)).toThrow(ConfigError);
  });

  it('builds canonical tool names as serverId/toolName', () => {
    expect(toCanonicalToolName('demo', 'read_project_file')).toBe('demo/read_project_file');
  });

  it('accepts the example event from design doc §9', () => {
    const event = {
      timestamp: '2026-10-24T02:00:00Z',
      requestId: 'demo-002',
      serverId: 'demo',
      toolName: 'read_sensitive_file',
      decision: 'DENY',
      ruleId: 'PROTECTED_PATH',
      reason: 'Credential path is protected',
      summary: 'Attempted protected file read',
    };
    expect(FirewallEventSchema.parse(event)).toEqual(event);
  });

  it('rejects events with unbounded summaries or extra fields (e.g. raw arguments)', () => {
    const base = {
      timestamp: '2026-10-24T02:00:00Z',
      requestId: 'r',
      serverId: 'demo',
      toolName: 't',
      decision: 'DENY',
      ruleId: 'DEFAULT_DENY',
      reason: 'x',
      summary: 'ok',
    };
    expect(FirewallEventSchema.safeParse({ ...base, summary: 'a'.repeat(10_000) }).success).toBe(false);
    expect(FirewallEventSchema.safeParse({ ...base, arguments: { path: '/x' } }).success).toBe(false);
  });

  it('rule IDs include every ID from design doc §7', () => {
    for (const id of [
      'INVALID_ARGUMENTS',
      'DENIED_TOOL',
      'PROTECTED_PATH',
      'DENIED_DESTINATION',
      'DESTRUCTIVE_ACTION',
      'APPROVED_TOOL',
      'DEFAULT_DENY',
    ]) {
      expect(RULE_IDS).toContain(id);
    }
  });
});

describe('staged-writes contract', () => {
  it('accepts a valid FileChange', () => {
    const change = { path: 'src/app.ts', kind: 'modify', size: 12, text: 'export {};\n' };
    expect(FileChangeSchema.parse(change)).toEqual(change);
  });

  it('accepts normalized project-relative paths, including dotfiles', () => {
    for (const path of ['src/app.ts', '.env', '.git/hooks/pre-commit', 'a/b/c.txt']) {
      expect(FileChangeSchema.safeParse({ path, kind: 'add' }).success).toBe(true);
    }
  });

  it.each([
    ['empty', ''],
    ['absolute', '/etc/passwd'],
    ['parent', '../x'],
    ['nested parent', 'a/../../x'],
    ['backslash', 'src\\app.ts'],
    ['dot', '.'],
    ['leading dot segment', './x'],
    ['inner dot segment', 'a/./b'],
    ['empty segment', 'a//b'],
    ['trailing slash', 'a/'],
    ['drive-relative', 'C:x'],
    ['drive-absolute', 'C:/x'],
    ['NUL', 'a\0b'],
  ])('rejects a %s path in FileChange and ChangeDecision', (_name, path) => {
    expect(FileChangeSchema.safeParse({ path, kind: 'add' }).success).toBe(false);
    const decision = { path, decision: 'DENY', ruleId: 'WRITE_NOT_ALLOWED', reason: 'x' };
    expect(ChangeDecisionSchema.safeParse(decision).success).toBe(false);
  });

  it(`caps FileChangeEvent at ${MAX_FILE_CHANGE_EVENT_ENTRIES} entries and bounded paths`, () => {
    const entry = { path: 'src/app.ts', decision: 'DENY', ruleId: 'WRITE_NOT_ALLOWED' };
    const event = {
      timestamp: '2026-10-24T02:00:00Z',
      requestId: 'r',
      serverId: 'demo',
      toolName: 'write_file',
      applied: 0,
      rejected: 21,
      changes: Array.from({ length: MAX_FILE_CHANGE_EVENT_ENTRIES }, () => entry),
    };
    expect(FileChangeEventSchema.safeParse(event).success).toBe(true);
    expect(FileChangeEventSchema.safeParse({ ...event, changes: [...event.changes, entry] }).success).toBe(false);
    const longPath = { ...entry, path: 'a'.repeat(MAX_FILE_CHANGE_EVENT_PATH_LENGTH + 1) };
    expect(FileChangeEventSchema.safeParse({ ...event, changes: [longPath] }).success).toBe(false);
  });

  it('policy.staging is optional, and incomplete staging sections are rejected', () => {
    expect(FirewallPolicySchema.parse({ defaultDecision: 'DENY' }).staging).toBeUndefined();
    expect(FirewallPolicySchema.safeParse({ defaultDecision: 'DENY', staging: { writablePaths: ['src/**'] } }).success).toBe(
      false,
    );
  });

  it('the reject-all stub denies every change, in order', () => {
    const decisions = evaluateFileChangesStub(
      [
        { path: 'b.txt', kind: 'add' },
        { path: 'a.txt', kind: 'delete' },
      ],
      { defaultDecision: 'DENY' } as FirewallPolicy,
    );
    expect(decisions.map((d) => [d.path, d.decision, d.ruleId])).toEqual([
      ['b.txt', 'DENY', 'WRITE_NOT_ALLOWED'],
      ['a.txt', 'DENY', 'WRITE_NOT_ALLOWED'],
    ]);
    for (const d of decisions) expect(ChangeDecisionSchema.safeParse(d).success).toBe(true);
  });
});

describe('sandbox + staging config', () => {
  const staging = `  staging: { writablePaths: ["src/**"], protectedWritePaths: [".git/**"], maxFileBytes: 65536, maxChangesPerCall: 20 }\n`;
  const sandboxed = (sandbox: string, policyExtra = staging) =>
    `server:\n  id: demo\n  command: node\n  sandbox: ${sandbox}\npolicy:\n  defaultDecision: DENY\n${policyExtra}`;

  /** Temp dir with project/ and server/ next to the config file. */
  function writeSandboxConfig(sandbox: string): string {
    const dir = mkdtempSync(join(tmpdir(), 'fw-config-'));
    mkdirSync(join(dir, 'project'));
    mkdirSync(join(dir, 'server'));
    writeFileSync(join(dir, 'file.txt'), '');
    const path = join(dir, 'firewall.yaml');
    writeFileSync(path, sandboxed(sandbox));
    return path;
  }

  it('existing configs without sandbox or staging still load', () => {
    expect(loadConfig(examplePath).server.sandbox).toBeUndefined();
    expect(loadConfig(examplePath).policy.staging).toBeUndefined();
  });

  it('sandbox mode requires policy.staging', () => {
    expect(() => parseConfig(sandboxed('{ image: fw-sandbox, project: p, serverDir: s }', ''))).toThrow(
      /requires a policy.staging/,
    );
  });

  it('rejects incomplete or unknown sandbox keys', () => {
    expect(() => parseConfig(sandboxed('{ image: fw-sandbox }'))).toThrow(ConfigError);
    expect(() => parseConfig(sandboxed('{ project: p }'))).toThrow(ConfigError);
    expect(() => parseConfig(sandboxed('{ image: fw-sandbox, project: p, serverDir: s, network: host }'))).toThrow(
      ConfigError,
    );
  });

  it('rejects image values that could be read as docker flags', () => {
    expect(() => parseConfig(sandboxed('{ image: "--privileged", project: p, serverDir: s }'))).toThrow(ConfigError);
    expect(() => parseConfig(sandboxed('{ image: "img --rm", project: p, serverDir: s }'))).toThrow(ConfigError);
    expect(parseConfig(sandboxed('{ image: "node:22-slim", project: p, serverDir: s }')).server.sandbox?.image).toBe(
      'node:22-slim',
    );
  });

  it('applies resource defaults and leaves user and env unset', () => {
    const sandbox = parseConfig(sandboxed('{ image: fw-sandbox, project: p }')).server.sandbox;
    expect(sandbox).toEqual({ image: 'fw-sandbox', project: 'p', memory: '512m', pidsLimit: 128 });
  });

  it('rejects a root user, bad memory, pids or env names', () => {
    const bad = [
      '{ image: fw-sandbox, project: p, user: "0:0" }',
      '{ image: fw-sandbox, project: p, user: "node" }',
      '{ image: fw-sandbox, project: p, memory: "lots" }',
      '{ image: fw-sandbox, project: p, pidsLimit: 0 }',
      '{ image: fw-sandbox, project: p, env: { "A=B": x } }',
    ];
    for (const sandbox of bad) expect(() => parseConfig(sandboxed(sandbox)), sandbox).toThrow(ConfigError);
    expect(parseConfig(sandboxed('{ image: fw-sandbox, project: p, user: "1000:1000" }')).server.sandbox?.user).toBe(
      '1000:1000',
    );
  });

  it('refuses server.cwd in sandbox mode', () => {
    const text = sandboxed('{ image: fw-sandbox, project: p }').replace('  command: node\n', '  command: node\n  cwd: ..\n');
    expect(() => parseConfig(text)).toThrow(/server.cwd is not allowed/);
  });

  it('resolves project and serverDir against the config file', () => {
    const path = writeSandboxConfig('{ image: fw-sandbox, project: project, serverDir: server }');
    const { sandbox } = loadConfig(path).server;
    expect(sandbox?.project).toBe(realpathSync(join(dirname(path), 'project')));
    expect(sandbox?.serverDir).toBe(realpathSync(join(dirname(path), 'server')));
  });

  it('refuses a missing or non-directory project or serverDir', () => {
    expect(() => loadConfig(writeSandboxConfig('{ image: fw-sandbox, project: nope, serverDir: server }'))).toThrow(
      /does not exist/,
    );
    expect(() => loadConfig(writeSandboxConfig('{ image: fw-sandbox, project: project, serverDir: file.txt }'))).toThrow(
      /not a directory/,
    );
  });

  it('refuses a serverDir that overlaps the project', () => {
    expect(() => loadConfig(writeSandboxConfig('{ image: fw-sandbox, project: project, serverDir: . }'))).toThrow(
      /must not overlap/,
    );
    expect(() => loadConfig(writeSandboxConfig('{ image: fw-sandbox, project: project, serverDir: project }'))).toThrow(
      /must not overlap/,
    );
  });

  it('serverDir is optional', () => {
    const path = writeSandboxConfig('{ image: fw-sandbox, project: project }');
    expect(loadConfig(path).server.sandbox?.serverDir).toBeUndefined();
  });
});

describe('toUpstreamLaunch', () => {
  const staging = `  staging: { writablePaths: ["src/**"], protectedWritePaths: [".git/**"], maxFileBytes: 65536, maxChangesPerCall: 20 }\n`;

  function sandboxServer(sandbox: string) {
    const dir = realpathSync(mkdtempSync(join(tmpdir(), 'fw-launch-')));
    mkdirSync(join(dir, 'project'));
    mkdirSync(join(dir, 'server'));
    mkdirSync(join(dir, 'staging'));
    const path = join(dir, 'firewall.yaml');
    writeFileSync(
      path,
      `server:\n  id: demo\n  command: node\n  args: [/server/index.js, /workspace]\n  sandbox: ${sandbox}\npolicy:\n  defaultDecision: DENY\n${staging}`,
    );
    return { dir, server: loadConfig(path).server };
  }

  it('maps a plain server to a local launch with an absolute cwd', () => {
    const server = loadConfig(examplePath).server;
    expect(toUpstreamLaunch(server)).toEqual({
      mode: 'local',
      command: server.command,
      args: server.args,
      cwd: resolve(dirname(examplePath), '..'),
    });
  });

  it('maps server.sandbox to a docker launch with defaults', () => {
    const { dir, server } = sandboxServer('{ image: fw-sandbox, project: project, serverDir: server, env: { LOG: "1" } }');
    const launch = toUpstreamLaunch(server, join(dir, 'staging'));
    expect(launch).toMatchObject({
      mode: 'docker',
      image: 'fw-sandbox',
      command: 'node',
      args: ['/server/index.js', '/workspace'],
      workspaceDir: join(dir, 'staging'),
      serverDir: join(dir, 'server'),
      env: { LOG: '1' },
      memory: '512m',
      pidsLimit: 128,
    });
    expect(launch.mode === 'docker' && launch.user).toMatch(/^\d+:\d+$/);
    expect(launch.mode === 'docker' && launch.user).not.toMatch(/^0:/);
    expect(launch).not.toHaveProperty('cwd');
    // What upstream validates again before running docker.
    expect(UpstreamLaunchSchema.safeParse(launch).success).toBe(true);
  });

  it('keeps an explicit user and omits unset serverDir and env', () => {
    const { dir, server } = sandboxServer('{ image: fw-sandbox, project: project, user: "1234:5678" }');
    const launch = toUpstreamLaunch(server, join(dir, 'staging'));
    expect(launch).toMatchObject({ user: '1234:5678' });
    expect(launch).not.toHaveProperty('serverDir');
    expect(launch).not.toHaveProperty('env');
  });

  it('refuses sandbox mode without a staging dir, or with one overlapping the project', () => {
    const { dir, server } = sandboxServer('{ image: fw-sandbox, project: project }');
    expect(() => toUpstreamLaunch(server)).toThrow(ConfigError);
    expect(() => toUpstreamLaunch(server, join(dir, 'project'))).toThrow(/must not overlap/);
    expect(() => toUpstreamLaunch(server, join(dir, 'project', 'sub'))).toThrow(/must not overlap/);
    expect(() => toUpstreamLaunch(server, dir)).toThrow(/must not overlap/);
  });
});

describe('evaluator contract', () => {
  const policy: FirewallPolicy = loadConfig(examplePath).policy;

  it('returns a schema-valid decision', () => {
    const decision = evaluateToolCall(
      { requestId: 'r1', serverId: 'demo', toolName: 'unknown_tool', arguments: {} },
      policy,
    );
    expect(PolicyDecisionSchema.safeParse(decision).success).toBe(true);
  });

  it('denies an unknown, unapproved tool', () => {
    const decision = evaluateToolCall(
      { requestId: 'r2', serverId: 'demo', toolName: 'totally_unknown_tool', arguments: {} },
      policy,
    );
    expect(decision.decision).toBe('DENY');
  });
});
