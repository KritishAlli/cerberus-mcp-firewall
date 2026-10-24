import { describe, expect, it } from 'vitest';
import type { FileChange, FirewallPolicy } from '../src/shared/contracts.js';
import { evaluateFileChanges } from '../src/security/changes.js';

const policy: FirewallPolicy = {
  defaultDecision: 'DENY',
  protectedPaths: ['**/.env', '**/credentials.json'],
  deniedDestinations: [],
  allowedRoots: ['.'],
  allowedHosts: [],
  approvedTools: [],
  deniedTools: [],
  pathArgs: ['path'],
  destinationArgs: {},
  destructiveTools: [],
  writeTools: [],
  staging: {
    writablePaths: ['src/**', 'README.md'],
    protectedWritePaths: ['.git/**', '.github/workflows/**', 'package.json'],
    maxFileBytes: 128,
    maxChangesPerCall: 3,
  },
};

function change(path: string, extra: Partial<FileChange> = {}): FileChange {
  return { path, kind: 'modify', size: 12, text: 'safe example content', ...extra };
}

describe('evaluateFileChanges', () => {
  it('allows an ordinary in-scope text edit', () => {
    expect(evaluateFileChanges([change('src/index.ts')], policy)).toMatchObject([
      { path: 'src/index.ts', decision: 'ALLOW', ruleId: 'APPROVED_TOOL' },
    ]);
  });

  it.each([
    [change('.env'), 'PROTECTED_PATH'],
    [change('src/credentials.json'), 'PROTECTED_PATH'],
    [change('package.json'), 'PERSISTENCE_PATH'],
    [change('.github/workflows/build.yml'), 'PERSISTENCE_PATH'],
    [change('docs/notes.md'), 'WRITE_NOT_ALLOWED'],
    [change('src/link', { kind: 'symlink', linkTarget: '../../.env' }), 'SYMLINK_DENIED'],
    [change('src/device', { kind: 'special' }), 'SYMLINK_DENIED'],
    [change('src/run.sh', { executable: true }), 'EXECUTABLE_DENIED'],
    [change('src/large.txt', { size: 129 }), 'CHANGE_LIMIT'],
    [change('src/secret.txt', { text: 'AWS key: AKIA1234567890ABCDEF' }), 'SECRET_DETECTED'],
  ] as const)('denies %s with %s', (fileChange, ruleId) => {
    const [decision] = evaluateFileChanges([fileChange], policy);
    expect(decision).toMatchObject({ decision: 'DENY', ruleId });
    expect(decision?.reason).not.toContain('AKIA');
  });

  it('denies every item when a batch exceeds its configured limit', () => {
    const results = evaluateFileChanges([
      change('src/a.ts'), change('src/b.ts'), change('README.md'), change('src/d.ts'),
    ], policy);
    expect(results).toHaveLength(4);
    expect(results.map((result) => result.ruleId)).toEqual(Array(4).fill('CHANGE_LIMIT'));
    expect(results.map((result) => result.decision)).toEqual(Array(4).fill('DENY'));
  });

  it('denies all changes when staging policy is absent or malformed', () => {
    const withoutStaging: FirewallPolicy = { ...policy, staging: undefined };
    expect(evaluateFileChanges([change('src/index.ts')], withoutStaging)[0]).toMatchObject({
      decision: 'DENY', ruleId: 'WRITE_NOT_ALLOWED',
    });

    const malformed = { ...policy, staging: { ...policy.staging!, maxFileBytes: -1 } } as unknown as FirewallPolicy;
    expect(evaluateFileChanges([change('src/index.ts')], malformed)[0]).toMatchObject({
      decision: 'DENY', ruleId: 'INVALID_ARGUMENTS',
    });
  });

  it('preserves input order and never puts file contents in reasons', () => {
    const values = [change('README.md'), change('package.json'), change('src/a.ts', { text: 'UNIQUE_CONTENT_SENTINEL' })];
    const results = evaluateFileChanges(values, policy);
    expect(results.map((result) => result.path)).toEqual(values.map((value) => value.path));
    expect(JSON.stringify(results)).not.toContain('UNIQUE_CONTENT_SENTINEL');
  });

  it('fails closed for a runtime-invalid path instead of approving it', () => {
    const invalid = { ...change('../outside.txt'), path: '../outside.txt' } as unknown as FileChange;
    const [result] = evaluateFileChanges([invalid], policy);
    expect(result?.decision).toBe('DENY');
  });
});
