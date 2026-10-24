/**
 * AARAV — src/proxy/staging.ts against real temp directories: sync excludes,
 * diff kinds, path safety, apply (atomic, conflict-checked, defense in depth),
 * revert, ordering and the staging lock.
 */
import { chmod, link, lstat, mkdir, mkdtemp, readdir, readFile, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  createStagingArea,
  resolveInRoot,
  StagingError,
  StagingLock,
  type StagingArea,
} from '../src/proxy/staging.js';
import type { ChangeDecision, FileChange } from '../src/shared/contracts.js';

let tmp: string;
let area: StagingArea;

async function put(root: string, rel: string, content: string | Buffer, mode?: number): Promise<void> {
  const abs = join(root, rel);
  await mkdir(dirname(abs), { recursive: true });
  await writeFile(abs, content);
  if (mode !== undefined) await chmod(abs, mode);
}

const allow = (c: FileChange): ChangeDecision => ({ path: c.path, decision: 'ALLOW', ruleId: 'APPROVED_TOOL', reason: 'ok' });
const deny = (c: FileChange): ChangeDecision => ({ path: c.path, decision: 'DENY', ruleId: 'PERSISTENCE_PATH', reason: 'no' });

async function staged(): Promise<string[]> {
  return (await readdir(area.stagingRoot, { recursive: true })).map((p) => p.split('\\').join('/')).sort();
}

beforeEach(async () => {
  tmp = await mkdtemp(join(tmpdir(), 'mcp-firewall-staging-test-'));
  await mkdir(join(tmp, 'project'));
  await mkdir(join(tmp, 'parent'));
  area = await createStagingArea({
    projectRoot: join(tmp, 'project'),
    stagingParent: join(tmp, 'parent'),
    extraExcludes: ['*.pem'],
    maxFileBytes: 64,
  });
});

afterEach(async () => {
  await rm(tmp, { recursive: true, force: true });
});

describe('staging / path safety', () => {
  it.each(['../x', '/etc/passwd', 'a/../../b', '..', '', 'a\\b', 'C:/x', 'a\0b'])('rejects %j', (p) => {
    expect(() => resolveInRoot('/root', p)).toThrow(StagingError);
  });

  it('normalizes safe paths', () => {
    expect(resolveInRoot('/root', 'src/app.ts')).toEqual({ rel: 'src/app.ts', abs: join('/root', 'src/app.ts') });
    expect(resolveInRoot('/root', './a//b/')).toEqual({ rel: 'a/b', abs: join('/root', 'a/b') });
    expect(resolveInRoot('/root', 'a/../b').rel).toBe('b');
  });

  it('refuses a staging dir inside the protected project', async () => {
    await expect(
      createStagingArea({ projectRoot: join(tmp, 'project'), stagingParent: join(tmp, 'project'), maxFileBytes: 64 }),
    ).rejects.toThrow(StagingError);
  });
});

describe('staging / sync', () => {
  it('never copies excluded files, reports server writes to them in diff and removes them on the next sync', async () => {
    const p = area.projectRoot;
    await put(p, '.git/HEAD', 'ref: refs/heads/main');
    await put(p, 'node_modules/pkg/index.js', 'x');
    await put(p, '.env', 'SECRET=1');
    await put(p, '.env.local', 'SECRET=2');
    await put(p, 'sub/.env', 'SECRET=3');
    await put(p, 'keys/id.pem', 'KEY');
    await put(p, 'src/app.ts', 'export {};');

    const { staging, project } = await area.sync();
    expect(await staged()).toEqual(['keys', 'src', 'src/app.ts', 'sub']);
    expect([...project.keys()]).toEqual(['keys', 'src', 'src/app.ts', 'sub']);

    await put(area.stagingRoot, '.env', 'planted');
    await put(area.stagingRoot, 'node_modules/evil.js', 'planted');
    await put(area.stagingRoot, 'sub/x.pem', 'planted');
    expect(await area.diff(staging)).toEqual([
      { path: '.env', kind: 'add', size: 7, executable: false, text: 'planted' },
      { path: 'node_modules/evil.js', kind: 'add', size: 7, executable: false, text: 'planted' },
      { path: 'sub/x.pem', kind: 'add', size: 7, executable: false, text: 'planted' },
    ]);

    await area.sync();
    expect(await staged()).toEqual(['keys', 'src', 'src/app.ts', 'sub']);
  });

  it('mirrors project symlinks as symlinks without reading their targets', async () => {
    await put(tmp, 'outside/secret.txt', 'host secret');
    await symlink(join(tmp, 'outside'), join(area.projectRoot, 'link'));
    const { staging } = await area.sync();
    expect((await lstat(join(area.stagingRoot, 'link'))).isSymbolicLink()).toBe(true);
    expect(staging.get('link')).toMatchObject({ type: 'symlink', linkTarget: join(tmp, 'outside') });
    expect([...staging.keys()]).toEqual(['link']);
  });
});

describe('staging / diff', () => {
  it('detects add, modify, delete and exec-bit-only mode changes', async () => {
    const p = area.projectRoot;
    await put(p, 'a.txt', 'a');
    await put(p, 'b.txt', 'b');
    await put(p, 'c.sh', 'echo hi', 0o644);
    await put(p, 'd.txt', 'unchanged');
    const { staging } = await area.sync();

    const s = area.stagingRoot;
    await put(s, 'a.txt', 'changed');
    await rm(join(s, 'b.txt'));
    await chmod(join(s, 'c.sh'), 0o755);
    await put(s, 'new/e.txt', 'new file');

    expect(await area.diff(staging)).toEqual([
      { path: 'a.txt', kind: 'modify', size: 7, text: 'changed' },
      { path: 'b.txt', kind: 'delete' },
      { path: 'c.sh', kind: 'mode', size: 7, executable: true, text: 'echo hi' },
      { path: 'new/e.txt', kind: 'add', size: 8, executable: false, text: 'new file' },
    ]);
  });

  it('reports a new symlink as "symlink" and does not follow it', async () => {
    await put(tmp, 'outside/secret.txt', 'host secret');
    const { staging } = await area.sync();
    await symlink(join(tmp, 'outside'), join(area.stagingRoot, 'dir-link'));
    await symlink(join(tmp, 'outside/secret.txt'), join(area.stagingRoot, 'file-link'));

    const changes = await area.diff(staging);
    expect(changes).toEqual([
      { path: 'dir-link', kind: 'symlink', size: expect.any(Number), linkTarget: join(tmp, 'outside') },
      { path: 'file-link', kind: 'symlink', size: expect.any(Number), linkTarget: join(tmp, 'outside/secret.txt') },
    ]);
    expect(JSON.stringify(changes)).not.toContain('host secret');
  });

  it('reports hardlinked files as "special"', async () => {
    await put(area.projectRoot, 'a.txt', 'a');
    const { staging } = await area.sync();
    await link(join(area.stagingRoot, 'a.txt'), join(area.stagingRoot, 'hard.txt'));

    expect(await area.diff(staging)).toEqual([
      { path: 'a.txt', kind: 'special', size: 1 },
      { path: 'hard.txt', kind: 'special', size: 1 },
    ]);
  });

  it('fills text only for small valid UTF-8 without NUL', async () => {
    const { staging } = await area.sync();
    const s = area.stagingRoot;
    await put(s, 'small.txt', 'héllo');
    await put(s, 'binary.dat', Buffer.from([0x41, 0x00, 0x42]));
    await put(s, 'invalid.txt', Buffer.from([0xff, 0xfe, 0x41]));
    await put(s, 'big.txt', 'x'.repeat(65));
    await put(s, 'edge.txt', 'y'.repeat(64));

    const text = Object.fromEntries((await area.diff(staging)).map((c) => [c.path, c.text]));
    expect(text).toEqual({
      'big.txt': null,
      'binary.dat': null,
      'edge.txt': 'y'.repeat(64),
      'invalid.txt': null,
      'small.txt': 'héllo',
    });
  });

  it('orders changes by path, independent of creation order', async () => {
    const { staging } = await area.sync();
    for (const rel of ['z.txt', 'm/b.txt', 'a.txt', 'm/a.txt', 'B.txt']) await put(area.stagingRoot, rel, rel);
    const first = await area.diff(staging);
    expect(first.map((c) => c.path)).toEqual(['B.txt', 'a.txt', 'm/a.txt', 'm/b.txt', 'z.txt']);
    expect(await area.diff(staging)).toEqual(first);
  });
});

describe('staging / apply', () => {
  it('writes allowed changes via temp file + rename and skips denied ones', async () => {
    const p = area.projectRoot;
    await put(p, 'a.txt', 'old', 0o600);
    await put(p, 'gone.txt', 'bye');
    await put(p, 'run.sh', 'echo', 0o644);
    const { staging, project } = await area.sync();
    const inodeBefore = (await stat(join(p, 'a.txt'))).ino;

    const s = area.stagingRoot;
    await put(s, 'a.txt', 'new');
    await put(s, 'dir/b.txt', 'added');
    await put(s, '.husky/pre-commit', 'curl evil');
    await rm(join(s, 'gone.txt'));
    await chmod(join(s, 'run.sh'), 0o755);
    const changes = await area.diff(staging);
    const decisions = changes.map((c) => (c.path.startsWith('.husky/') ? deny(c) : allow(c)));

    expect(await area.apply(changes, decisions, project)).toEqual([
      { path: '.husky/pre-commit', applied: false, ruleId: 'PERSISTENCE_PATH' },
      { path: 'a.txt', applied: true, ruleId: 'APPROVED_TOOL' },
      { path: 'dir/b.txt', applied: true, ruleId: 'APPROVED_TOOL' },
      { path: 'gone.txt', applied: true, ruleId: 'APPROVED_TOOL' },
      { path: 'run.sh', applied: true, ruleId: 'APPROVED_TOOL' },
    ]);
    expect(await readFile(join(p, 'a.txt'), 'utf8')).toBe('new');
    expect((await stat(join(p, 'a.txt'))).ino).not.toBe(inodeBefore);
    expect((await stat(join(p, 'a.txt'))).mode & 0o777).toBe(0o600);
    expect(await readFile(join(p, 'dir/b.txt'), 'utf8')).toBe('added');
    expect((await stat(join(p, 'run.sh'))).mode & 0o111).toBe(0o111);
    expect((await readdir(p, { recursive: true })).sort()).toEqual(['a.txt', 'dir', 'dir/b.txt', 'run.sh']);
  });

  it('skips with WRITE_CONFLICT when the project file changed after sync', async () => {
    await put(area.projectRoot, 'a.txt', 'v1');
    await put(area.projectRoot, 'b.txt', 'v1');
    const { staging, project } = await area.sync();
    await put(area.stagingRoot, 'a.txt', 'from server');
    await rm(join(area.stagingRoot, 'b.txt'));
    const changes = await area.diff(staging);

    await put(area.projectRoot, 'a.txt', 'edited by user');
    await put(area.projectRoot, 'b.txt', 'edited by user');
    expect(await area.apply(changes, changes.map(allow), project)).toEqual([
      { path: 'a.txt', applied: false, ruleId: 'WRITE_CONFLICT' },
      { path: 'b.txt', applied: false, ruleId: 'WRITE_CONFLICT' },
    ]);
    expect(await readFile(join(area.projectRoot, 'a.txt'), 'utf8')).toBe('edited by user');
    expect(await readFile(join(area.projectRoot, 'b.txt'), 'utf8')).toBe('edited by user');
  });

  it('never applies symlink or special changes, even when ALLOWed', async () => {
    await put(area.projectRoot, 'a.txt', 'a');
    const { staging, project } = await area.sync();
    await symlink('/etc/passwd', join(area.stagingRoot, 'link'));
    await link(join(area.stagingRoot, 'a.txt'), join(area.stagingRoot, 'hard.txt'));
    const changes = await area.diff(staging);

    expect(await area.apply(changes, changes.map(allow), project)).toEqual([
      { path: 'a.txt', applied: false, ruleId: 'WRITE_NOT_ALLOWED' },
      { path: 'hard.txt', applied: false, ruleId: 'WRITE_NOT_ALLOWED' },
      { path: 'link', applied: false, ruleId: 'SYMLINK_DENIED' },
    ]);
    expect((await readdir(area.projectRoot)).sort()).toEqual(['a.txt']);
  });

  it('throws and writes nothing if a staged file changed after diff', async () => {
    const { staging, project } = await area.sync();
    await put(area.stagingRoot, 'a.txt', 'what the policy saw');
    await put(area.stagingRoot, 'b.txt', 'b');
    const changes = await area.diff(staging);
    await put(area.stagingRoot, 'b.txt', 'swapped after the check');

    await expect(area.apply(changes, changes.map(allow), project)).rejects.toThrow(StagingError);
    expect(await readdir(area.projectRoot)).toEqual([]);
  });

  it('throws on mismatched decisions and on apply before diff', async () => {
    const { staging, project } = await area.sync();
    await expect(area.apply([], [], project)).rejects.toThrow(StagingError);
    await put(area.stagingRoot, 'a.txt', 'a');
    const changes = await area.diff(staging);
    await expect(area.apply(changes, [], project)).rejects.toThrow(StagingError);
    await expect(area.apply(changes, [{ ...allow(changes[0]!), path: 'other.txt' }], project)).rejects.toThrow(
      StagingError,
    );
  });
});

describe('staging / revert', () => {
  it('restores rejected paths in staging from the project', async () => {
    await put(area.projectRoot, 'a.txt', 'a');
    await put(area.projectRoot, 'b/c.txt', 'c');
    const { staging } = await area.sync();

    const s = area.stagingRoot;
    await put(s, 'a.txt', 'tampered');
    await put(s, 'x.txt', 'added');
    await rm(join(s, 'b'), { recursive: true });
    await put(s, 'b', 'directory replaced by a file');
    const changes = await area.diff(staging);
    expect(changes.map((c) => [c.path, c.kind])).toEqual([
      ['a.txt', 'modify'],
      ['b', 'add'],
      ['b/c.txt', 'delete'],
      ['x.txt', 'add'],
    ]);

    await area.revert(changes.map((c) => c.path));
    expect(await area.diff(staging)).toEqual([]);
    expect(await readFile(join(s, 'b/c.txt'), 'utf8')).toBe('c');
  });
});

describe('staging / lock', () => {
  it('runs one critical section at a time, in order', async () => {
    const lock = new StagingLock();
    const log: string[] = [];
    const section = (name: string, ms: number) =>
      lock.run(async () => {
        log.push(`${name}:start`);
        await new Promise((r) => setTimeout(r, ms));
        log.push(`${name}:end`);
        return name;
      });
    const failing = lock.run(async () => {
      throw new Error('boom');
    });
    expect(await Promise.all([section('a', 20), failing.catch(() => 'failed'), section('b', 0)])).toEqual([
      'a',
      'failed',
      'b',
    ]);
    expect(log).toEqual(['a:start', 'a:end', 'b:start', 'b:end']);
  });
});
