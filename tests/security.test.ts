import { describe, expect, it } from 'vitest';
import { evaluateToolCall } from '../src/security/evaluator.js';
import type { FirewallPolicy, ToolCallContext } from '../src/shared/contracts.js';

const request = (toolName: string, args: Record<string, unknown> = {}): ToolCallContext => ({ requestId: 'test-1', serverId: 'demo', toolName, arguments: args });
const policy: FirewallPolicy = {
  defaultDecision: 'DENY', protectedPaths: ['~/.aws/credentials', '**/.env', '~/.ssh/**'], deniedDestinations: ['example-attacker.invalid'],
  approvedTools: ['demo/read_project_file'], deniedTools: ['demo/delete_file'], pathArgs: ['path', 'filePath', 'filename'],
  destinationArgs: { 'demo/send_data': ['url'] }, destructiveTools: [],
};
const decision = (tool: string, args: Record<string, unknown> = {}, p = policy) => evaluateToolCall(request(tool, args), p);

describe('security / evaluateToolCall', () => {
  it('allows an explicitly approved safe tool', () => expect(decision('read_project_file', { path: 'README.md' })).toMatchObject({ decision: 'ALLOW', ruleId: 'APPROVED_TOOL' }));
  it('blocks the configured credential path', () => expect(decision('read_sensitive_file', { path: '~/.aws/credentials' })).toMatchObject({ decision: 'DENY', ruleId: 'PROTECTED_PATH' }));
  it('blocks destinations matching a normalized denied hostname', () => expect(decision('send_data', { url: 'https://EXAMPLE-ATTACKER.INVALID/upload' })).toMatchObject({ decision: 'DENY', ruleId: 'DENIED_DESTINATION' }));
  it('denies an explicitly denied tool before any allow rule', () => expect(decision('delete_file')).toMatchObject({ decision: 'DENY', ruleId: 'DENIED_TOOL' }));
  it('defaults unclassified tools to deny', () => expect(decision('unknown_tool')).toMatchObject({ decision: 'DENY', ruleId: 'DEFAULT_DENY' }));
  it('keeps unknown sensitive operations denied even under an allow default', () => {
    const allowDefault = { ...policy, defaultDecision: 'ALLOW' as const };
    expect(decision('sendData', { url: 'https://safe.example/' }, allowDefault)).toMatchObject({ decision: 'DENY', ruleId: 'DEFAULT_DENY' });
    expect(decision('addressBookLookup', {}, allowDefault)).toMatchObject({ decision: 'ALLOW', ruleId: 'APPROVED_TOOL' });
  });
  it('rejects invalid requests and policies without throwing', () => {
    expect(evaluateToolCall({ ...request('x'), arguments: [] } as never, policy)).toMatchObject({ decision: 'DENY', ruleId: 'INVALID_ARGUMENTS' });
    expect(evaluateToolCall(request('x'), { ...policy, extra: true } as never)).toMatchObject({ decision: 'DENY', ruleId: 'INVALID_ARGUMENTS' });
  });
  it('does not overmatch similarly named benign paths', () => {
    expect(decision('read_project_file', { path: 'notes/.env.example' })).toMatchObject({ decision: 'ALLOW', ruleId: 'APPROVED_TOOL' });
    expect(decision('read_project_file', { path: 'project/.envrc' })).toMatchObject({ decision: 'ALLOW', ruleId: 'APPROVED_TOOL' });
  });
  it('normalizes traversal before checking protected paths', () => expect(decision('read_sensitive_file', { path: '/tmp/../Users/test/.aws/credentials' }, { ...policy, protectedPaths: ['/Users/test/.aws/credentials'] })).toMatchObject({ decision: 'DENY', ruleId: 'PROTECTED_PATH' }));
  it('blocks encoded hostnames and userinfo URLs by their parsed hostname', () => {
    expect(decision('send_data', { url: 'https://user:pass@example-attacker.invalid%2e/upload' })).toMatchObject({ decision: 'DENY', ruleId: 'DENIED_DESTINATION' });
    expect(decision('send_data', { url: 'https://example-attacker.invalid@safe.example/' })).toMatchObject({ decision: 'DENY', ruleId: 'DEFAULT_DENY' });
  });
  it('fails closed for malformed destinations on configured send tools', () => expect(decision('send_data', { url: 'not a url' })).toMatchObject({ decision: 'DENY', ruleId: 'INVALID_ARGUMENTS' }));
  it('checks path arguments in nested objects and arrays', () => expect(decision('read_sensitive_file', { batch: [{ options: { filename: '~/.ssh/id_rsa' } }] })).toMatchObject({ decision: 'DENY', ruleId: 'PROTECTED_PATH' }));
  it('never includes argument values in its reason', () => {
    const result = decision('read_sensitive_file', { path: '~/.aws/credentials', token: 'dummy-secret' });
    expect(result.reason).not.toContain('credentials');
    expect(result.reason).not.toContain('dummy-secret');
  });
  it('denies configured destructive operations', () => expect(decision('wipe', {}, { ...policy, destructiveTools: ['demo/wipe'] })).toMatchObject({ decision: 'DENY', ruleId: 'DESTRUCTIVE_ACTION' }));
});
