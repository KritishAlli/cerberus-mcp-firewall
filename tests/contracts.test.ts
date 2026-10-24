/**
 * SHARED — baseline tests for the frozen contract and scaffold invariants.
 * These must stay green on main at all times.
 */
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { ConfigError, loadConfig, parseConfig } from '../src/config/load.js';
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
