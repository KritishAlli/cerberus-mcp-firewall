/**
 * OWNER: Aarav — staged writes (docs/STAGED_WRITES_PLAN.md, DECISIONS §9–§10).
 *
 * The sandboxed downstream server works on a staging copy of the protected
 * project, never the project itself. Per allowed call:
 *   1. sync()    mirrors the project into staging (minus excludes) → pre-call manifests
 *   2. the server runs against staging
 *   3. diff()    rescans staging → FileChange[] for the evaluator
 *   4. apply()   copies approved changes into the project (conflict-checked, temp file + rename)
 *   5. revert()  puts rejected paths in staging back to the project's state
 *
 * The server may keep running between and during these steps, so nothing it
 * leaves in staging is trusted: walks use lstat and never follow symlinks,
 * reads refuse symlinks and swapped files, and apply() only writes content
 * whose hash matches what diff() reported (what the policy saw). Symlink and
 * special changes are never applied, whatever the decision says.
 *
 * Every error is thrown to the caller, which must fail closed. Error messages
 * never include paths or contents.
 */
import { createHash, randomUUID } from 'node:crypto';
import { constants, type Stats } from 'node:fs';
import {
  copyFile,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readdir,
  readlink,
  realpath,
  rename,
  rm,
  rmdir,
  symlink,
  unlink,
  type FileHandle,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import type { ChangeDecision, FileChange, RuleId } from '../shared/contracts.js';

/** Never copied into staging, never reported by diff, never applied. */
export const DEFAULT_EXCLUDES: readonly string[] = ['.git/', 'node_modules/', '.env', '.env.*'];

const HASH_CHUNK_BYTES = 64 * 1024;
/** Read-only, no final symlink, and no blocking if a FIFO was swapped in after lstat. */
const SAFE_READ_FLAGS = constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK;

export class StagingError extends Error {
  override name = 'StagingError';
  readonly code = 'STAGING_ERROR';
}

/** apply() failed after it had already changed some project paths; `applied` lists them. */
export class StagingApplyError extends StagingError {
  override name = 'StagingApplyError';

  constructor(
    readonly applied: readonly string[],
    options?: ErrorOptions,
  ) {
    super('apply failed partway; some changes were already applied', options);
  }
}

export type EntryType = 'file' | 'dir' | 'symlink' | 'special';

export interface ManifestEntry {
  /** 'special': hardlinked files (nlink > 1), devices, sockets, FIFOs. */
  type: EntryType;
  size: number;
  /** Permission bits only (mode & 0o777). */
  mode: number;
  /** Regular files, including hardlinked ones. */
  sha256?: string;
  linkTarget?: string;
}

/** Normalized posix path relative to the root → entry. Excluded paths are absent. */
export type Manifest = Map<string, ManifestEntry>;

export interface SyncResult {
  /** Staging after sync: the pre-call snapshot to pass to diff(). */
  staging: Manifest;
  /** The project at sync time: what apply() checks for conflicts. */
  project: Manifest;
}

export interface ApplyResult {
  path: string;
  applied: boolean;
  /** The decision's rule when applied; otherwise why it was not. */
  ruleId: RuleId;
}

export interface StagingOptions {
  /** The protected project. Only apply() writes here. */
  projectRoot: string;
  /** Directory the staging dir is created in (fs.mkdtemp). Default os.tmpdir(). Must not be inside the project. */
  stagingParent?: string;
  /** Replaces DEFAULT_EXCLUDES. */
  excludes?: readonly string[];
  /** Added to the excludes, e.g. the policy's protected secret files. */
  extraExcludes?: readonly string[];
  /** FileChange.text is filled only for files of at most this many bytes; larger files are never applied. */
  maxFileBytes: number;
}

// ---------------------------------------------------------------------------
// Path safety
// ---------------------------------------------------------------------------

/**
 * The one check for a relative path from outside this module (a FileChange,
 * a revert request, a directory entry). Returns the normalized posix path and
 * its absolute location. Throws on NUL, backslashes, absolute or drive paths,
 * `..` segments after normalization, and anything resolving outside the root.
 */
export function resolveInRoot(root: string, relPath: string): { rel: string; abs: string } {
  if (typeof relPath !== 'string' || relPath === '' || relPath.includes('\0') || relPath.includes('\\')) {
    throw new StagingError('invalid relative path');
  }
  if (path.posix.isAbsolute(relPath) || /^[A-Za-z]:/.test(relPath)) {
    throw new StagingError('path must be relative to the root');
  }
  const rel = path.posix.normalize(relPath).replace(/\/+$/, '');
  if (rel === '' || rel === '.' || rel.split('/').includes('..')) {
    throw new StagingError('path escapes the root');
  }
  const abs = path.resolve(root, ...rel.split('/'));
  const back = path.relative(root, abs);
  if (back === '' || back.startsWith('..') || path.isAbsolute(back)) {
    throw new StagingError('path escapes the root');
  }
  return { rel, abs };
}

// ---------------------------------------------------------------------------
// Excludes: tiny glob subset (*, **, ?). A pattern without "/" matches a name
// at any depth; with "/" it is anchored to the root; a trailing "/" means
// directories only. A path is excluded if it or any ancestor matches.
// ---------------------------------------------------------------------------

interface ExcludeRule {
  re: RegExp;
  dirOnly: boolean;
  anchored: boolean;
}

function compileExcludes(globs: readonly string[]): ExcludeRule[] {
  return globs.map((glob) => {
    const dirOnly = glob.endsWith('/');
    const body = glob.replace(/\/+$/, '');
    const anchored = body.includes('/');
    return { re: globToRegExp(body.replace(/^\/+/, '')), dirOnly, anchored };
  });
}

function globToRegExp(glob: string): RegExp {
  let re = '';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i]!;
    if (c === '*' && glob[i + 1] === '*') {
      i++;
      if (glob[i + 1] === '/') {
        i++;
        re += '(?:.*/)?';
      } else {
        re += '.*';
      }
    } else if (c === '*') {
      re += '[^/]*';
    } else if (c === '?') {
      re += '[^/]';
    } else {
      re += c.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    }
  }
  return new RegExp(`^${re}$`);
}

function matchesExclude(rules: ExcludeRule[], rel: string, isDir: boolean): boolean {
  const name = rel.slice(rel.lastIndexOf('/') + 1);
  return rules.some((r) => (!r.dirOnly || isDir) && r.re.test(r.anchored ? rel : name));
}

/** For paths not met during a walk: checks every ancestor, and the path itself as a file or a directory. */
function isExcludedPath(rules: ExcludeRule[], rel: string): boolean {
  const parts = rel.split('/');
  for (let n = 1; n <= parts.length; n++) {
    const prefix = parts.slice(0, n).join('/');
    if (matchesExclude(rules, prefix, true) || (n === parts.length && matchesExclude(rules, prefix, false))) {
      return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Snapshots
// ---------------------------------------------------------------------------

/** Manifest of `root` without following symlinks. Uses DEFAULT_EXCLUDES unless excludes are given. */
export async function snapshot(root: string, excludes: readonly string[] = DEFAULT_EXCLUDES): Promise<Manifest> {
  return scan(await realpath(root), compileExcludes(excludes));
}

/** `root` must already be a realpath. Entries are in sorted pre-order: a directory before its contents. */
async function scan(root: string, rules: ExcludeRule[]): Promise<Manifest> {
  const manifest: Manifest = new Map();
  const visit = async (dirRel: string): Promise<void> => {
    const dirAbs = dirRel === '' ? root : path.join(root, ...dirRel.split('/'));
    await assertNoSymlinkInPath(dirAbs);
    for (const name of (await readdir(dirAbs)).sort()) {
      const rel = dirRel === '' ? name : `${dirRel}/${name}`;
      const { abs } = resolveInRoot(root, rel);
      const st = await lstat(abs);
      if (matchesExclude(rules, rel, st.isDirectory())) continue;
      const entry = await describe(abs, st);
      manifest.set(rel, entry);
      if (entry.type === 'dir') await visit(rel);
    }
  };
  await visit('');
  return manifest;
}

async function describe(abs: string, st: Stats): Promise<ManifestEntry> {
  const mode = st.mode & 0o777;
  if (st.isSymbolicLink()) return { type: 'symlink', size: st.size, mode, linkTarget: await readlink(abs) };
  if (st.isDirectory()) return { type: 'dir', size: 0, mode };
  if (st.isFile()) {
    return { type: st.nlink > 1 ? 'special' : 'file', size: st.size, mode, sha256: await hashFile(abs, st) };
  }
  return { type: 'special', size: st.size, mode };
}

async function describeIfPresent(abs: string): Promise<ManifestEntry | undefined> {
  const st = await lstatIfPresent(abs);
  return st && describe(abs, st);
}

function sameEntry(a: ManifestEntry | undefined, b: ManifestEntry | undefined): boolean {
  if (a === undefined || b === undefined) return a === b;
  if (a.type !== b.type) return false;
  if (a.type === 'dir') return true;
  if (a.type === 'symlink') return a.linkTarget === b.linkTarget;
  return a.size === b.size && a.mode === b.mode && a.sha256 === b.sha256;
}

const isExecutable = (mode: number): boolean => (mode & 0o111) !== 0;

/**
 * Why apply() must not write this change, or undefined. Symlink and special
 * changes are refused even when ALLOWed, and so are excluded paths.
 */
function refusal(change: FileChange, decision: ChangeDecision, rules: ExcludeRule[]): RuleId | undefined {
  if (decision.decision !== 'ALLOW') return decision.ruleId;
  if (change.kind === 'symlink') return 'SYMLINK_DENIED';
  if (change.kind === 'special' || isExcludedPath(rules, change.path)) return 'WRITE_NOT_ALLOWED';
  return undefined;
}

// ---------------------------------------------------------------------------
// Safe file reads
// ---------------------------------------------------------------------------

/** Opens the file lstat described, refusing a final symlink and anything swapped in since. */
async function openSame(abs: string, st: { dev: number; ino: number } | undefined): Promise<FileHandle> {
  await assertNoSymlinkInPath(path.dirname(abs));
  const handle = await open(abs, SAFE_READ_FLAGS);
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || (st && (opened.dev !== st.dev || opened.ino !== st.ino))) {
      throw new StagingError('file changed while it was being read');
    }
    return handle;
  } catch (err) {
    await handle.close();
    throw err;
  }
}

async function hashFile(abs: string, st: Stats): Promise<string> {
  const handle = await openSame(abs, st);
  try {
    const hash = createHash('sha256');
    const buffer = Buffer.alloc(HASH_CHUNK_BYTES);
    for (;;) {
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, null);
      if (bytesRead === 0) break;
      hash.update(buffer.subarray(0, bytesRead));
    }
    return hash.digest('hex');
  } finally {
    await handle.close();
  }
}

/** Reads a staged file and checks it is still exactly what the manifest recorded. */
async function readVerified(abs: string, entry: ManifestEntry): Promise<Buffer> {
  const handle = await openSame(abs, undefined);
  try {
    const content = await handle.readFile();
    if (content.length !== entry.size || createHash('sha256').update(content).digest('hex') !== entry.sha256) {
      throw new StagingError('staged file changed after it was scanned');
    }
    return content;
  } finally {
    await handle.close();
  }
}

/** Roots are realpaths, so a clean path under them equals its realpath unless a component is a symlink. */
async function assertNoSymlinkInPath(absDir: string): Promise<void> {
  if ((await realpath(absDir)) !== absDir) throw new StagingError('path goes through a symlink');
}

const UTF8 = new TextDecoder('utf-8', { fatal: true });

function textOrNull(content: Buffer): string | null {
  if (content.includes(0)) return null;
  try {
    return UTF8.decode(content);
  } catch {
    return null;
  }
}

async function lstatIfPresent(abs: string): Promise<Stats | undefined> {
  try {
    return await lstat(abs);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
    throw err;
  }
}

// ---------------------------------------------------------------------------
// Staging area
// ---------------------------------------------------------------------------

export async function createStagingArea(options: StagingOptions): Promise<StagingArea> {
  const projectRoot = await realpath(options.projectRoot);
  const parent = await realpath(options.stagingParent ?? tmpdir());
  const fromProject = path.relative(projectRoot, parent);
  if (fromProject === '' || (!fromProject.startsWith('..') && !path.isAbsolute(fromProject))) {
    throw new StagingError('staging dir must not be inside the protected project');
  }
  const stagingRoot = await mkdtemp(path.join(parent, 'mcp-firewall-staging-'));
  const excludes = [...(options.excludes ?? DEFAULT_EXCLUDES), ...(options.extraExcludes ?? [])];
  return new StagingArea(projectRoot, stagingRoot, compileExcludes(excludes), options.maxFileBytes);
}

export class StagingArea {
  /** Staging as of the last diff(): what apply() verifies staged content against. */
  private lastScan: Manifest | undefined;

  constructor(
    readonly projectRoot: string,
    readonly stagingRoot: string,
    private readonly rules: ExcludeRule[],
    private readonly maxFileBytes: number,
  ) {}

  /** Makes staging an exact mirror of the project minus excludes. */
  async sync(): Promise<SyncResult> {
    const project = await scan(this.projectRoot, this.rules);
    await this.pruneStaging('', project);
    const current = await scan(this.stagingRoot, this.rules);
    for (const [rel, entry] of project) {
      if (!sameEntry(entry, current.get(rel))) await this.copyToStaging(rel, entry);
    }
    this.lastScan = undefined;
    return { staging: await scan(this.stagingRoot, this.rules), project };
  }

  /**
   * Rescans staging and reports what changed since `before` (from sync()),
   * sorted by path. Directories are not reported; their contents are.
   * `executable` is set for every add, and for modify/mode when the exec bit changed.
   */
  async diff(before: Manifest): Promise<FileChange[]> {
    const after = await scan(this.stagingRoot, this.rules);
    this.lastScan = after;
    const changes: FileChange[] = [];
    for (const rel of [...new Set([...before.keys(), ...after.keys()])].sort()) {
      const change = await this.changeAt(rel, before.get(rel), after.get(rel));
      if (change) changes.push(change);
    }
    return changes;
  }

  /**
   * Applies the ALLOWed changes to the project. `decisions` must match
   * `changes` one to one (same paths, same order), as EvaluateFileChanges
   * returns them. Each write or delete first re-checks the project path
   * against `projectAtSync` and skips it with WRITE_CONFLICT if it changed.
   */
  async apply(
    changes: readonly FileChange[],
    decisions: readonly ChangeDecision[],
    projectAtSync: Manifest,
  ): Promise<ApplyResult[]> {
    const after = this.lastScan;
    if (!after) throw new StagingError('apply() needs a diff() since the last sync()');
    if (decisions.length !== changes.length) throw new StagingError('one decision per change is required');

    const results: ApplyResult[] = [];
    const deletes: { index: number; rel: string; abs: string }[] = [];
    const writes: { index: number; rel: string; abs: string; content: Buffer; executable: boolean }[] = [];

    // Phase 1: decide, and load approved content from staging. Nothing is written yet,
    // so a staged file that changed since diff() aborts the whole apply.
    for (const [index, change] of changes.entries()) {
      const decision = decisions[index]!;
      if (decision.path !== change.path) throw new StagingError('decisions do not match changes');
      const refused = refusal(change, decision, this.rules);
      if (refused) {
        results[index] = { path: change.path, applied: false, ruleId: refused };
        continue;
      }
      const { rel, abs } = resolveInRoot(this.projectRoot, change.path);
      const staged = after.get(rel);
      if (change.kind === 'delete') {
        if (staged !== undefined && staged.type !== 'dir') throw new StagingError('change does not match the staged diff');
        deletes.push({ index, rel, abs });
        continue;
      }
      if (staged?.type !== 'file') throw new StagingError('change does not match the staged diff');
      if (staged.size > this.maxFileBytes) {
        results[index] = { path: change.path, applied: false, ruleId: 'CHANGE_LIMIT' };
        continue;
      }
      const content = await readVerified(resolveInRoot(this.stagingRoot, rel).abs, staged);
      writes.push({ index, rel, abs, content, executable: isExecutable(staged.mode) });
    }

    // Phase 2: deletes deepest first (so a directory can become a file), then writes in path order.
    // A failure here throws StagingApplyError naming what was already applied.
    const applied: string[] = [];
    try {
      for (const d of deletes.sort((a, b) => (a.rel < b.rel ? 1 : -1))) {
        const blocked = await this.checkProjectPath(d.rel, d.abs, projectAtSync);
        if (blocked) {
          results[d.index] = { path: changes[d.index]!.path, applied: false, ruleId: blocked };
          continue;
        }
        if (await lstatIfPresent(d.abs)) await unlink(d.abs);
        applied.push(changes[d.index]!.path);
        await this.pruneEmptyProjectDirs(d.rel, after);
        results[d.index] = { path: changes[d.index]!.path, applied: true, ruleId: decisions[d.index]!.ruleId };
      }
      for (const w of writes.sort((a, b) => (a.rel < b.rel ? -1 : 1))) {
        const blocked = await this.checkProjectPath(w.rel, w.abs, projectAtSync);
        if (blocked) {
          results[w.index] = { path: changes[w.index]!.path, applied: false, ruleId: blocked };
          continue;
        }
        await this.writeProjectFile(w.abs, w.content, w.executable);
        applied.push(changes[w.index]!.path);
        results[w.index] = { path: changes[w.index]!.path, applied: true, ruleId: decisions[w.index]!.ruleId };
      }
    } catch (err) {
      if (applied.length === 0) throw err;
      throw new StagingApplyError(applied, { cause: err });
    }
    return results;
  }

  /** Restores these paths in staging from the project, or removes them if the project has none. */
  async revert(paths: readonly string[]): Promise<void> {
    for (const p of paths) {
      const { rel, abs } = resolveInRoot(this.stagingRoot, p);
      await this.makeStagingParentsDirs(rel);
      await rm(abs, { recursive: true, force: true });
      await this.copyTreeToStaging(rel);
    }
    this.lastScan = undefined;
  }

  /** Removes the staging dir. */
  async dispose(): Promise<void> {
    await rm(this.stagingRoot, { recursive: true, force: true });
  }

  // --- diff ---------------------------------------------------------------

  private async changeAt(
    rel: string,
    before: ManifestEntry | undefined,
    after: ManifestEntry | undefined,
  ): Promise<FileChange | undefined> {
    if (after === undefined || after.type === 'dir') {
      return before !== undefined && before.type !== 'dir' ? { path: rel, kind: 'delete' } : undefined;
    }
    if (after.type === 'symlink') {
      const same = before?.type === 'symlink' && before.linkTarget === after.linkTarget;
      return same ? undefined : { path: rel, kind: 'symlink', size: after.size, linkTarget: after.linkTarget! };
    }
    if (after.type === 'special') {
      return sameEntry(before, after) ? undefined : { path: rel, kind: 'special', size: after.size };
    }
    const executable = isExecutable(after.mode);
    if (before === undefined || before.type === 'dir') {
      return { path: rel, kind: 'add', size: after.size, executable, text: await this.textOf(rel, after) };
    }
    const execChanged = before.type !== 'file' || isExecutable(before.mode) !== executable;
    if (before.type !== 'file' || before.sha256 !== after.sha256 || before.size !== after.size) {
      return {
        path: rel,
        kind: 'modify',
        size: after.size,
        ...(execChanged ? { executable } : {}),
        text: await this.textOf(rel, after),
      };
    }
    if (execChanged) return { path: rel, kind: 'mode', size: after.size, executable, text: await this.textOf(rel, after) };
    return undefined;
  }

  /** UTF-8 text without NUL for files of at most maxFileBytes; otherwise null. */
  private async textOf(rel: string, entry: ManifestEntry): Promise<string | null> {
    if (entry.size > this.maxFileBytes) return null;
    return textOrNull(await readVerified(resolveInRoot(this.stagingRoot, rel).abs, entry));
  }

  // --- apply --------------------------------------------------------------

  /** undefined if the project path is safe to change; otherwise the rule to report. */
  private async checkProjectPath(rel: string, abs: string, projectAtSync: Manifest): Promise<RuleId | undefined> {
    const parts = rel.split('/');
    for (let n = 1; n < parts.length; n++) {
      const st = await lstatIfPresent(path.join(this.projectRoot, ...parts.slice(0, n)));
      if (st === undefined) break;
      // A symlinked parent would carry the write outside the project.
      if (!st.isDirectory()) return 'WRITE_NOT_ALLOWED';
    }
    const expected = projectAtSync.get(rel);
    const current = await describeIfPresent(abs);
    // Directories have no content to conflict on; pruneEmptyProjectDirs may have removed an empty one.
    if (expected?.type === 'dir' && (current === undefined || current.type === 'dir')) return undefined;
    return sameEntry(expected, current) ? undefined : 'WRITE_CONFLICT';
  }

  private async writeProjectFile(abs: string, content: Buffer, executable: boolean): Promise<void> {
    const dir = path.dirname(abs);
    await mkdir(dir, { recursive: true });
    const current = await lstatIfPresent(abs);
    // Keep the existing read/write bits; only the exec bit comes from staging. Never setuid/setgid/sticky.
    const base = current?.isFile() ? current.mode & 0o666 : 0o644;
    const temp = path.join(dir, `.${path.basename(abs)}.${randomUUID()}.mcp-firewall.tmp`);
    try {
      const handle = await open(temp, 'wx');
      try {
        await handle.writeFile(content);
        await handle.chmod(executable ? base | 0o111 : base);
        await handle.sync();
      } finally {
        await handle.close();
      }
      await rename(temp, abs);
    } catch (err) {
      await rm(temp, { force: true });
      throw err;
    }
  }

  /** After a delete, removes now-empty project directories that staging no longer has as directories. */
  private async pruneEmptyProjectDirs(rel: string, after: Manifest): Promise<void> {
    const parts = rel.split('/');
    for (let n = parts.length - 1; n > 0; n--) {
      if (after.get(parts.slice(0, n).join('/'))?.type === 'dir') return;
      try {
        await rmdir(path.join(this.projectRoot, ...parts.slice(0, n)));
      } catch (err) {
        const code = (err as NodeJS.ErrnoException).code;
        if (code === 'ENOTEMPTY' || code === 'EEXIST' || code === 'ENOENT' || code === 'ENOTDIR') return;
        throw err;
      }
    }
  }

  // --- sync / revert ------------------------------------------------------

  /** Removes everything in staging the project does not have in the same form, excluded paths included. */
  private async pruneStaging(dirRel: string, project: Manifest): Promise<void> {
    const dirAbs = dirRel === '' ? this.stagingRoot : path.join(this.stagingRoot, ...dirRel.split('/'));
    for (const name of await readdir(dirAbs)) {
      const rel = dirRel === '' ? name : `${dirRel}/${name}`;
      const abs = path.join(dirAbs, name);
      const st = await lstat(abs);
      const want = project.get(rel);
      const keep =
        want !== undefined &&
        (want.type === 'dir'
          ? st.isDirectory()
          : want.type === 'symlink'
            ? st.isSymbolicLink()
            : want.sha256 !== undefined && st.isFile());
      if (!keep) await rm(abs, { recursive: true, force: true });
      else if (st.isDirectory()) await this.pruneStaging(rel, project);
    }
  }

  /** Copies one project entry into staging. Symlinks are recreated, never followed; devices etc. are skipped. */
  private async copyToStaging(rel: string, entry: ManifestEntry): Promise<void> {
    const src = path.join(this.projectRoot, ...rel.split('/'));
    const dst = path.join(this.stagingRoot, ...rel.split('/'));
    if (entry.type === 'dir') {
      const st = await lstatIfPresent(dst);
      if (st?.isDirectory()) return;
      if (st) await rm(dst, { recursive: true, force: true });
      await mkdir(dst, { mode: entry.mode });
      return;
    }
    await rm(dst, { recursive: true, force: true });
    if (entry.type === 'symlink') {
      await symlink(entry.linkTarget!, dst);
    } else if (entry.sha256 !== undefined) {
      // COPYFILE_EXCL: if something reappears at dst after the rm, fail rather than write through it.
      await copyFile(src, dst, constants.COPYFILE_EXCL);
      const handle = await open(dst, SAFE_READ_FLAGS);
      try {
        await handle.chmod(entry.mode);
      } finally {
        await handle.close();
      }
    }
  }

  private async copyTreeToStaging(rel: string): Promise<void> {
    if (isExcludedPath(this.rules, rel)) return;
    const src = path.join(this.projectRoot, ...rel.split('/'));
    const entry = await describeIfPresent(src);
    if (entry === undefined) return;
    await this.copyToStaging(rel, entry);
    if (entry.type !== 'dir') return;
    for (const name of (await readdir(src)).sort()) {
      await this.copyTreeToStaging(resolveInRoot(this.projectRoot, `${rel}/${name}`).rel);
    }
  }

  /** Every ancestor of rel in staging becomes a real directory, so later removals and writes stay inside staging. */
  private async makeStagingParentsDirs(rel: string): Promise<void> {
    const parts = rel.split('/');
    for (let n = 1; n < parts.length; n++) {
      const abs = path.join(this.stagingRoot, ...parts.slice(0, n));
      const st = await lstatIfPresent(abs);
      if (st?.isDirectory()) continue;
      if (st) await rm(abs, { recursive: true, force: true });
      await mkdir(abs);
    }
  }
}

// ---------------------------------------------------------------------------
// Staging lock
// ---------------------------------------------------------------------------

/** Async mutex: sync → call → diff → apply/revert for one call must not interleave with another's. */
export class StagingLock {
  private tail: Promise<void> = Promise.resolve();

  async run<T>(fn: () => Promise<T>): Promise<T> {
    const previous = this.tail;
    let release!: () => void;
    this.tail = new Promise<void>((resolve) => (release = resolve));
    await previous;
    try {
      return await fn();
    } finally {
      release();
    }
  }
}
