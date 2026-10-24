/**
 * AARAV — src/proxy/staging.ts against real temp directories: sync excludes,
 * diff kinds, path safety, apply (atomic, conflict-checked, defense in depth),
 * revert, ordering, the staging lock, and the owner file and stale-dir sweep.
 */
import { spawnSync } from 'node:child_process';
import { chmod, link, lstat, mkdir, mkdtemp, readdir, readFile, rm, stat, symlink, utimes, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  createStagingArea,
  resolveInRoot,
  StagingError,
  StagingLock,
  sweepStaleStagingDirs,
  type StagingArea,
} from '../src/proxy/staging.js';
import type { ChangeDecision, FileChange, FirewallPolicy } from '../src/shared/contracts.js';
import { evaluateFileChanges } from '../src/security/changes.js';

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
  it('keeps allowed empty dirs in staging only until an approved file write materializes them', async () => {
    await mkdir(join(area.projectRoot, 'src'));
    area = await createStagingArea({
      projectRoot: area.projectRoot,
      stagingParent: join(tmp, 'parent'),
      maxFileBytes: 64,
      preserveStagingDirectories: {
        writablePaths: ['src/**'],
        protectedPaths: ['**/.env'],
        protectedWritePaths: ['src/locked/**'],
      },
    });
    const policy: FirewallPolicy = {
      defaultDecision: 'DENY',
      protectedPaths: ['**/.env'],
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
        writablePaths: ['src/**'],
        protectedWritePaths: ['src/locked/**'],
        maxFileBytes: 64,
        maxChangesPerCall: 10,
      },
    };

    const first = await area.sync();
    await mkdir(join(area.stagingRoot, 'src/newdir'), { recursive: true });
    await mkdir(join(area.stagingRoot, 'docs/newdir'), { recursive: true });
    await mkdir(join(area.stagingRoot, 'src/locked/newdir'), { recursive: true });
    await mkdir(join(area.stagingRoot, '.git/newdir'), { recursive: true });

    // Directories aren't project changes and are deliberately not applied.
    expect(await area.diff(first.staging)).toEqual([]);
    const afterCreate = await area.baselineAfter(first, [], new Map());
    expect(await area.diff(afterCreate.staging)).toEqual([]);
    const next = await area.sync();

    expect((await lstat(join(area.stagingRoot, 'src/newdir'))).isDirectory()).toBe(true);
    await expect(lstat(join(area.stagingRoot, 'docs/newdir'))).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(lstat(join(area.stagingRoot, 'src/locked/newdir'))).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(lstat(join(area.stagingRoot, '.git/newdir'))).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(lstat(join(area.projectRoot, 'src/newdir'))).rejects.toMatchObject({ code: 'ENOENT' });

    await put(area.stagingRoot, 'src/newdir/example.ts', 'export const answer = 42;\n');
    const changes = await area.diff(next.staging);
    const decisions = evaluateFileChanges(changes, policy);
    expect(decisions).toMatchObject([{ path: 'src/newdir/example.ts', decision: 'ALLOW' }]);
    expect(await area.apply(changes, decisions, next.project)).toMatchObject([
      { path: 'src/newdir/example.ts', applied: true },
    ]);
    expect(await readFile(join(area.projectRoot, 'src/newdir/example.ts'), 'utf8')).toContain('answer = 42');
  });

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

  it('keeps the source of a move whose destination is denied', async () => {
    await put(area.projectRoot, 'src/index.js', 'main');
    await put(area.projectRoot, 'src/other.js', 'other');
    const { staging, project } = await area.sync();
    await rm(join(area.stagingRoot, 'src/index.js'));
    await rm(join(area.stagingRoot, 'src/other.js'));
    await put(area.stagingRoot, 'notes.js', 'main');
    const changes = await area.diff(staging);
    const decisions = changes.map((c) => (c.path === 'notes.js' ? deny(c) : allow(c)));

    expect(await area.apply(changes, decisions, project)).toEqual([
      { path: 'notes.js', applied: false, ruleId: 'PERSISTENCE_PATH' },
      { path: 'src/index.js', applied: false, ruleId: 'PERSISTENCE_PATH' },
      // Unrelated content: an ordinary delete, applied.
      { path: 'src/other.js', applied: true, ruleId: 'APPROVED_TOOL' },
    ]);
    expect(await readFile(join(area.projectRoot, 'src/index.js'), 'utf8')).toBe('main');
    expect((await readdir(area.projectRoot, { recursive: true })).sort()).toEqual(['src', 'src/index.js']);
  });

  it('applies both halves of an allowed move', async () => {
    await put(area.projectRoot, 'src/greet.js', 'greet');
    const { staging, project } = await area.sync();
    await rm(join(area.stagingRoot, 'src/greet.js'));
    await put(area.stagingRoot, 'src/hello.js', 'greet');
    const changes = await area.diff(staging);

    expect(await area.apply(changes, changes.map(allow), project)).toEqual([
      { path: 'src/greet.js', applied: true, ruleId: 'APPROVED_TOOL' },
      { path: 'src/hello.js', applied: true, ruleId: 'APPROVED_TOOL' },
    ]);
    expect((await readdir(join(area.projectRoot, 'src'))).sort()).toEqual(['hello.js']);
  });

  it('keeps the source of a move whose destination hits WRITE_CONFLICT', async () => {
    await put(area.projectRoot, 'a.txt', 'moved');
    await put(area.projectRoot, 'b.txt', 'v1');
    const { staging, project } = await area.sync();
    await rm(join(area.stagingRoot, 'a.txt'));
    await put(area.stagingRoot, 'b.txt', 'moved');
    const changes = await area.diff(staging);

    await put(area.projectRoot, 'b.txt', 'edited by user');
    expect(await area.apply(changes, changes.map(allow), project)).toEqual([
      { path: 'a.txt', applied: false, ruleId: 'WRITE_CONFLICT' },
      { path: 'b.txt', applied: false, ruleId: 'WRITE_CONFLICT' },
    ]);
    expect(await readFile(join(area.projectRoot, 'a.txt'), 'utf8')).toBe('moved');
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

describe('staging / owner file', () => {
  it('sits next to the mirror, never in it, and is never reported as a change', async () => {
    const dir = dirname(area.stagingRoot);
    expect(basename(dir)).toMatch(/^mcp-firewall-staging-[A-Za-z0-9]{6}$/);
    expect((await readdir(dir)).sort()).toEqual(['owner.json', 'tree']);
    const owner = JSON.parse(await readFile(join(dir, 'owner.json'), 'utf8')) as { pid: number; startedAt: string };
    expect(owner.pid).toBe(process.pid);
    expect(Number.isNaN(Date.parse(owner.startedAt))).toBe(false);
    expect((await stat(join(dir, 'owner.json'))).mode & 0o777).toBe(0o600);

    await put(join(tmp, 'project'), 'a.txt', 'a');
    const { staging } = await area.sync();
    expect(await staged()).toEqual(['a.txt']);
    expect(await area.diff(staging)).toEqual([]);
  });

  it('is removed with the mirror on dispose()', async () => {
    const dir = dirname(area.stagingRoot);
    await area.dispose();
    await expect(lstat(dir)).rejects.toMatchObject({ code: 'ENOENT' });
  });
});

describe('staging / stale-dir sweep', () => {
  const uid = process.getuid!();
  const DAY_MS = 24 * 60 * 60 * 1000;
  let parent: string;
  let lines: string[];
  const sweep = (extra: { uid?: number } = {}) =>
    sweepStaleStagingDirs({ parent, log: (line) => lines.push(line), ...extra });

  /** A pid that has exited and been reaped. */
  const deadPid = (): number => {
    const { pid } = spawnSync(process.execPath, ['-e', '']);
    if (pid === undefined) throw new Error('could not spawn');
    return pid;
  };

  async function stagingDir(name: string, owner?: unknown): Promise<string> {
    const dir = join(parent, name);
    await mkdir(join(dir, 'tree'), { recursive: true });
    await writeFile(join(dir, 'tree/a.txt'), 'project copy');
    if (owner !== undefined) await writeFile(join(dir, 'owner.json'), JSON.stringify(owner));
    return dir;
  }

  const exists = async (p: string): Promise<boolean> => lstat(p).then(() => true, () => false);

  beforeEach(async () => {
    parent = join(tmp, 'sweep');
    await mkdir(parent);
    lines = [];
  });

  it("removes a dir whose owner's pid is gone, and logs only the count and names", async () => {
    const dir = await stagingDir('mcp-firewall-staging-dead01', { pid: deadPid(), startedAt: '2026-01-01T00:00:00Z' });
    expect(await sweep()).toEqual(['mcp-firewall-staging-dead01']);
    expect(await exists(dir)).toBe(false);
    expect(lines).toEqual(['[firewall] staging: removed 1 stale staging dir(s): mcp-firewall-staging-dead01']);
  });

  it('keeps a dir whose owner is alive', async () => {
    const dir = await stagingDir('mcp-firewall-staging-live01', { pid: process.pid, startedAt: '2026-01-01T00:00:00Z' });
    expect(await sweep()).toEqual([]);
    expect(await exists(join(dir, 'tree/a.txt'))).toBe(true);
    expect(lines).toEqual([]);
  });

  it('never follows a symlink that matches the prefix', async () => {
    const target = await stagingDir('elsewhere', { pid: deadPid(), startedAt: '2026-01-01T00:00:00Z' });
    const link = join(parent, 'mcp-firewall-staging-LINK01');
    await symlink(target, link);
    expect(await sweep()).toEqual([]);
    expect((await lstat(link)).isSymbolicLink()).toBe(true);
    expect(await exists(join(target, 'tree/a.txt'))).toBe(true);
  });

  it("leaves another user's dirs and dirs with other names alone", async () => {
    const owner = { pid: deadPid(), startedAt: '2026-01-01T00:00:00Z' };
    const ours = await stagingDir('mcp-firewall-staging-dead02', owner);
    const others = [
      await stagingDir('mcp-firewall-staging-test-dead03', owner),
      await stagingDir('mcp-firewall-staging-dead0', owner),
      await stagingDir('other-dead04', owner),
    ];
    // As another uid, our own dir is someone else's.
    expect(await sweep({ uid: uid + 1 })).toEqual([]);
    expect(await exists(ours)).toBe(true);
    expect(await sweep()).toEqual(['mcp-firewall-staging-dead02']);
    for (const dir of others) expect(await exists(dir)).toBe(true);
  });

  it('keeps a dir without a usable owner file until it is 24 hours old', async () => {
    const missing = await stagingDir('mcp-firewall-staging-nownr1');
    const groupPid = await stagingDir('mcp-firewall-staging-nownr2', { pid: 0, startedAt: 'x' });
    const garbage = await stagingDir('mcp-firewall-staging-nownr3');
    await writeFile(join(garbage, 'owner.json'), '{not json');
    expect(await sweep()).toEqual([]);
    for (const dir of [missing, groupPid, garbage]) expect(await exists(dir)).toBe(true);

    const old = new Date(Date.now() - DAY_MS - 60_000);
    for (const dir of [missing, groupPid, garbage]) await utimes(dir, old, old);
    expect(await sweep()).toEqual(['mcp-firewall-staging-nownr1', 'mcp-firewall-staging-nownr2', 'mcp-firewall-staging-nownr3']);
  });

  it('never throws: a failed sweep is logged and returns nothing', async () => {
    await expect(sweepStaleStagingDirs({ parent: join(tmp, 'missing'), log: (line) => lines.push(line) })).resolves.toEqual([]);
    expect(lines).toEqual(['[firewall] staging: stale staging dir sweep failed (ENOENT)']);
  });
});
