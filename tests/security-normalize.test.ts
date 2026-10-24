import { describe, expect, it } from 'vitest';
import { evaluateToolCall } from '../src/security/evaluator.js';
import { normalizePath, pathMatches, pathWithinRoots } from '../src/security/normalize.js';
import type { FirewallPolicy, ToolCallContext } from '../src/shared/contracts.js';

const basePolicy: FirewallPolicy = {
  defaultDecision: 'DENY',
  protectedPaths: ['**/.env'],
  deniedDestinations: [],
  allowedRoots: ['/workspace'],
  allowedHosts: [],
  approvedTools: ['fs/read_file', 'fs/send_data'],
  deniedTools: [],
  pathArgs: ['path'],
  destinationArgs: { 'fs/send_data': ['url'] },
  destructiveTools: [],
  writeTools: [],
};

function request(arguments_: Record<string, unknown>, overrides: Partial<ToolCallContext> = {}): ToolCallContext {
  return {
    requestId: 'security-test',
    serverId: 'fs',
    toolName: 'read_file',
    arguments: arguments_,
    session: { tainted: false },
    ...overrides,
  };
}

describe('path and destination security normalization', () => {
  it('normalizes trailing separators before matching protected paths', () => {
    expect(normalizePath('/workspace/.env/')).toBe('/workspace/.env');
    expect(pathMatches('/workspace/.env/', '**/.env')).toBe(true);
    expect(evaluateToolCall(request({ path: '/workspace/.env/' }), basePolicy)).toMatchObject({
      decision: 'DENY', ruleId: 'PROTECTED_PATH',
    });
  });

  it('rejects relative traversal after repeated percent decoding', () => {
    expect(pathWithinRoots('src/%252e%252e/%252e%252e/etc/passwd', ['.'])).toBe(false);
    expect(evaluateToolCall(request({ path: 'src/%252e%252e/%252e%252e/etc/passwd' }), {
      ...basePolicy,
      allowedRoots: ['.'],
    })).toMatchObject({ decision: 'DENY', ruleId: 'PATH_NOT_ALLOWED' });
  });

  it('treats local file URLs as paths and blocks protected trailing-slash paths', () => {
    expect(evaluateToolCall(request({ path: 'file:///workspace/.env/' }), basePolicy)).toMatchObject({
      decision: 'DENY', ruleId: 'PROTECTED_PATH',
    });
    expect(evaluateToolCall(request({ path: 'file://localhost/workspace/.env' }), basePolicy)).toMatchObject({
      decision: 'DENY', ruleId: 'PROTECTED_PATH',
    });
  });

  it('rejects remote file URL authorities even when the path itself is inside an allowed root', () => {
    const result = evaluateToolCall(request({ path: 'file://other-host/workspace/readme.txt' }), {
      ...basePolicy,
      allowedRoots: ['/'],
    });
    expect(result).toMatchObject({ decision: 'DENY', ruleId: 'PATH_NOT_ALLOWED' });
  });

  it('matches protected path case variants on default case-insensitive macOS volumes', () => {
    const result = evaluateToolCall(request({ path: '/workspace/.ENV' }), basePolicy);
    if (process.platform === 'darwin' || process.platform === 'win32') {
      expect(result).toMatchObject({ decision: 'DENY', ruleId: 'PROTECTED_PATH' });
    } else {
      expect(result.decision).toBe('ALLOW');
    }
  });

  it('reports protected-path denial before tainted-session denial', () => {
    expect(evaluateToolCall(request({ path: '/workspace/.env' }, {
      session: { tainted: true },
    }), basePolicy)).toMatchObject({ decision: 'DENY', ruleId: 'PROTECTED_PATH' });
  });

  it('rejects malformed or non-HTTP URL schemes for configured destination tools', () => {
    expect(evaluateToolCall(request({ url: 'javascript:alert(1)' }, { toolName: 'send_data' }), {
      ...basePolicy,
      allowedHosts: ['example.com'],
    })).toMatchObject({ decision: 'DENY', ruleId: 'INVALID_ARGUMENTS' });
  });
});
