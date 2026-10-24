/**
 * SHARED — baseline tests for the frozen contract and scaffold invariants.
 * These must stay green on main at all times.
 */
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { ConfigError, loadConfig, parseConfig } from '../src/config/load.js';
import { evaluateToolCall } from '../src/security/evaluator.js';
import {
  FirewallEventSchema,
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
