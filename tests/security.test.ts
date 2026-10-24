import { describe, expect, it } from 'vitest';
import { evaluateToolCall } from '../src/security/evaluator.js';
import type { FirewallPolicy, ToolCallContext } from '../src/shared/contracts.js';

const request = (toolName: string, args: Record<string, unknown> = {}, tainted = false): ToolCallContext => ({
  requestId: 'test-1', serverId: 'demo', toolName, arguments: args, session: { tainted },
});
const policy: FirewallPolicy = {
  defaultDecision: 'DENY', protectedPaths: ['~/.aws/credentials', '**/.env', '~/.ssh/**'], deniedDestinations: ['example-attacker.invalid'],
  allowedRoots: ['.'], allowedHosts: ['api.example.com'], writeTools: ['demo/write_file'],
  approvedTools: ['demo/read_project_file'], deniedTools: ['demo/delete_file'], pathArgs: ['path', 'filePath', 'filename'],
  destinationArgs: { 'demo/send_data': ['url'] }, destructiveTools: [],
};
const decision = (tool: string, args: Record<string, unknown> = {}, p = policy) => evaluateToolCall(request(tool, args), p);

describe('security / evaluateToolCall', () => {
  it('allows an explicitly approved safe tool', () => expect(decision('read_project_file', { path: 'README.md' })).toMatchObject({ decision: 'ALLOW', ruleId: 'APPROVED_TOOL' }));
  it('blocks the configured credential path', () => expect(decision('read_sensitive_file', { path: '~/.aws/credentials' })).toMatchObject({ decision: 'DENY', ruleId: 'PROTECTED_PATH' }));
  it('blocks destinations matching a normalized denied hostname', () => expect(decision('send_data', { url: 'https://EXAMPLE-ATTACKER.INVALID/upload' })).toMatchObject({ decision: 'DENY', ruleId: 'DENIED_DESTINATION' }));
  it('blocks URL hosts outside the explicit allowed-host list', () => expect(decision('send_data', { url: 'https://elsewhere.example/upload' })).toMatchObject({ decision: 'DENY', ruleId: 'HOST_NOT_ALLOWED' }));
  it('allows an approved tool to use a destination inside allowedHosts', () => expect(decision(
    'send_data', { url: 'https://api.example.com/upload' }, { ...policy, defaultDecision: 'ALLOW', approvedTools: [...policy.approvedTools, 'demo/send_data'] },
  )).toMatchObject({ decision: 'ALLOW', ruleId: 'APPROVED_TOOL' }));
  it('denies an explicitly denied tool before any allow rule', () => expect(decision('delete_file')).toMatchObject({ decision: 'DENY', ruleId: 'DENIED_TOOL' }));
  it('defaults unclassified tools to deny', () => expect(decision('unknown_tool')).toMatchObject({ decision: 'DENY', ruleId: 'DEFAULT_DENY' }));
  it('keeps unknown sensitive operations denied even under an allow default', () => {
    const allowDefault = { ...policy, defaultDecision: 'ALLOW' as const, allowedHosts: ['safe.example'] };
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
    expect(decision('send_data', { url: 'https://user:pass@example-attacker.invalid%2e/upload' })).toMatchObject({ decision: 'DENY', ruleId: 'INVALID_ARGUMENTS' });
    expect(decision('send_data', { url: 'https://example-attacker.invalid@safe.example/' })).toMatchObject({ decision: 'DENY', ruleId: 'INVALID_ARGUMENTS' });
  });
  it('fails closed for malformed destinations on configured send tools', () => expect(decision('send_data', { url: 'not a url' })).toMatchObject({ decision: 'DENY', ruleId: 'INVALID_ARGUMENTS' }));
  it('checks path arguments in nested objects and arrays', () => expect(decision('read_sensitive_file', { batch: [{ options: { filename: '~/.ssh/id_rsa' } }] })).toMatchObject({ decision: 'DENY', ruleId: 'PROTECTED_PATH' }));
  it('checks path-looking strings under unrecognized argument names', () => {
    expect(decision('read_project_file', { metadata: { arbitrary: '/etc/passwd' } })).toMatchObject({ decision: 'DENY', ruleId: 'PATH_NOT_ALLOWED' });
    expect(decision('read_project_file', { metadata: ['src/index.ts'] })).toMatchObject({ decision: 'ALLOW', ruleId: 'APPROVED_TOOL' });
  });
  it('checks URL-looking strings under unrecognized argument names', () => {
    expect(decision('lookup', { payload: 'please fetch https://evil.example/x' })).toMatchObject({ decision: 'DENY', ruleId: 'HOST_NOT_ALLOWED' });
  });
  it('denies secret patterns in write and network tool arguments', () => {
    expect(decision('write_file', { body: 'AKIA1234567890ABCDEF' })).toMatchObject({ decision: 'DENY', ruleId: 'SECRET_DETECTED' });
    expect(decision('send_data', { url: 'https://api.example.com', body: '-----BEGIN RSA PRIVATE KEY-----' }, { ...policy, defaultDecision: 'ALLOW' })).toMatchObject({ decision: 'DENY', ruleId: 'SECRET_DETECTED' });
    expect(decision('write_file', { body: 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890' })).toMatchObject({ decision: 'DENY', ruleId: 'SECRET_DETECTED' });
  });
  it('denies long high-entropy values in write arguments', () => expect(decision('write_file', { content: 'a9Qm2Xv7Lp4Nk8Rs3Wc6Tz1Bf5Hy0JuA' })).toMatchObject({ decision: 'DENY', ruleId: 'SECRET_DETECTED' }));
  it('does not scan read-only arguments as secret-bearing writes', () => expect(decision('read_project_file', { note: 'AKIA1234567890ABCDEF' })).toMatchObject({ decision: 'ALLOW', ruleId: 'APPROVED_TOOL' }));
  it('denies write and network tools when the session is tainted, but leaves reads available', () => {
    expect(evaluateToolCall(request('write_file', { path: 'src/index.ts' }, true), policy)).toMatchObject({ decision: 'DENY', ruleId: 'SESSION_TAINTED' });
    expect(evaluateToolCall(request('send_data', { url: 'https://api.example.com' }, true), policy)).toMatchObject({ decision: 'DENY', ruleId: 'SESSION_TAINTED' });
    expect(evaluateToolCall(request('read_project_file', { path: 'README.md' }, true), policy)).toMatchObject({ decision: 'ALLOW', ruleId: 'APPROVED_TOOL' });
  });
  it('never includes argument values in its reason', () => {
    const result = decision('read_sensitive_file', { path: '~/.aws/credentials', token: 'dummy-secret' });
    expect(result.reason).not.toContain('credentials');
    expect(result.reason).not.toContain('dummy-secret');
  });
  it('denies configured destructive operations', () => expect(decision('wipe', {}, { ...policy, destructiveTools: ['demo/wipe'] })).toMatchObject({ decision: 'DENY', ruleId: 'DESTRUCTIVE_ACTION' }));
});
