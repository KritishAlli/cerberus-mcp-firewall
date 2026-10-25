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
  writeFile,
  type FileHandle,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import type { ChangeDecision, FileChange, RuleId } from '../shared/contracts.js';
import { pathMatches } from '../security/normalize.js';

/** Never copied into staging, never reported by diff, never applied. */
export const DEFAULT_EXCLUDES: readonly string[] = ['.git/', 'node_modules/', '.env', '.env.*'];

const HASH_CHUNK_BYTES = 64 * 1024;
/** Escaped paths listed in sync()'s warning about unmirrored project files. */
const MAX_LOGGED_UNSAFE = 10;
/** Read-only, no final symlink, and no blocking if a FIFO was swapped in after lstat. */
const SAFE_READ_FLAGS = constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK;

const STAGING_DIR_PREFIX = 'mcp-firewall-staging-';
/** mkdtemp appends six characters from [A-Za-z0-9]; any other name is not ours. */
const STAGING_DIR_NAME = /^mcp-firewall-staging-[A-Za-z0-9]{6}$/;
/** Next to the mirror, never inside it: { pid, startedAt } of the firewall that created the dir. */
const OWNER_FILE = 'owner.json';
/** The mirror itself: stagingRoot, mounted as /workspace. */
const TREE_DIR = 'tree';
const MAX_OWNER_FILE_BYTES = 1024;
/** A staging dir without a readable owner file is swept only once it is this old. */
const UNOWNED_MIN_AGE_MS = 24 * 60 * 60 * 1000;

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
  /**
   * Empty directories in these writable paths may remain in the disposable
   * staging tree between calls. They are never applied to the project by
   * themselves; an approved file write may create their parents in the project.
   */
  preserveStagingDirectories?: {
    writablePaths: readonly string[];
    protectedPaths?: readonly string[];
    protectedWritePaths?: readonly string[];
  };
  /** FileChange.text is filled only for files of at most this many bytes; larger files are never applied. */
  maxFileBytes: number;
  /**
   * policy.staging.maxChangesPerCall. diff() stops scanning excluded paths after
   * this many + 1 entries, so the evaluator's CHANGE_LIMIT rejects the batch. Default 1000.
   */
  maxChangesPerCall?: number;
  /** Diagnostics sink (one line, no trailing newline). Defaults to stderr. */
  log?: (line: string) => void;
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

/** Match a directory itself or a path immediately below it against a policy glob. */
function matchesDirectoryOrDescendant(dir: string, pattern: string): boolean {
  return pathMatches(dir, pattern) || pathMatches(`${dir}/__mcp_firewall_directory_probe__`, pattern);
}

// ---------------------------------------------------------------------------
// Snapshots
// ---------------------------------------------------------------------------

/** Manifest of `root` without following symlinks. Uses DEFAULT_EXCLUDES unless excludes are given. */
export async function snapshot(root: string, excludes: readonly string[] = DEFAULT_EXCLUDES): Promise<Manifest> {
  return scan(await realpath(root), compileExcludes(excludes));
}

/** Excluded entries found in staging, where they never belong. Bounded by `limit`. */
interface ExcludedScan {
  /** Non-directory entries. Not hashed: excluded paths are never in a baseline, so any entry is new. */
  entries: Manifest;
  /** Top-most excluded paths (e.g. ".git", "src/.env"): removing these removes everything. */
  roots: string[];
  limit: number;
  /** Non-directory entries seen, unsafe names included. */
  count: number;
  dirs: number;
}

/** A staging entry whose on-disk name cannot be used as a path (see entryName). */
interface UnsafeEntry {
  /** Absolute on-disk path, raw bytes. */
  raw: Buffer;
  /** Its directory, a safe path. */
  dir: string;
  size: number;
}

/** What a staging scan collects besides the manifest. */
interface ScanSink {
  excluded: ExcludedScan;
  /** Escaped display path → the entry. */
  unsafe: Map<string, UnsafeEntry>;
}

/**
 * `root` must already be a realpath. Entries are in sorted pre-order: a directory
 * before its contents. Excluded paths and unsafe names are skipped, or collected
 * into `sink` for a staging diff. Names are read as raw bytes, so even a name that
 * is not valid UTF-8 can be reported and removed.
 */
async function scan(root: string, rules: ExcludeRule[], sink?: ScanSink, skipped?: string[]): Promise<Manifest> {
  const manifest: Manifest = new Map();
  const visit = async (dirRel: string): Promise<void> => {
    const dirAbs = dirRel === '' ? root : path.join(root, ...dirRel.split('/'));
    await assertNoSymlinkInPath(dirAbs);
    for (const raw of await readNames(dirAbs)) {
      const { name, safe } = entryName(raw, dirRel === '');
      const rel = dirRel === '' ? name : `${dirRel}/${name}`;
      if (!safe) {
        if (sink) await recordUnsafe(sink, rel, dirAbs, raw);
        else skipped?.push(rel);
        continue;
      }
      const { abs } = resolveInRoot(root, rel);
      const st = await lstat(abs);
      if (matchesExclude(rules, rel, st.isDirectory())) {
        if (sink) {
          sink.excluded.roots.push(rel);
          await collectExcluded(root, rel, abs, st, sink);
        }
        continue;
      }
      const entry = await describe(abs, st);
      manifest.set(rel, entry);
      if (entry.type === 'dir') await visit(rel);
    }
  };
  await visit('');
  return manifest;
}

/** Walks an excluded subtree until `limit` entries or `limit` directories have been seen. */
async function collectExcluded(root: string, rel: string, abs: string, st: Stats, sink: ScanSink): Promise<void> {
  const ex = sink.excluded;
  const full = (): boolean => ex.count >= ex.limit || ex.dirs >= ex.limit;
  if (full()) return;
  if (!st.isDirectory()) {
    ex.entries.set(rel, await describeUnhashed(abs, st));
    ex.count++;
    return;
  }
  ex.dirs++;
  await assertNoSymlinkInPath(abs);
  for (const raw of await readNames(abs)) {
    if (full()) return;
    const { name, safe } = entryName(raw, false);
    if (!safe) {
      await recordUnsafe(sink, `${rel}/${name}`, abs, raw);
      ex.count++;
      continue;
    }
    const child = resolveInRoot(root, `${rel}/${name}`);
    await collectExcluded(root, child.rel, child.abs, await lstat(child.abs), sink);
  }
}

async function readNames(dirAbs: string): Promise<Buffer[]> {
  return (await readdir(dirAbs, { encoding: 'buffer' })).sort(Buffer.compare);
}

async function recordUnsafe(sink: ScanSink, rel: string, dir: string, name: Buffer): Promise<void> {
  const raw = Buffer.concat([Buffer.from(dir + path.sep), name]);
  sink.unsafe.set(rel, { raw, dir, size: (await lstat(raw)).size });
}

/**
 * A directory entry's name for paths and display. Unsafe names (not valid UTF-8,
 * control characters, backslashes, or a drive prefix at the root) get an escaped
 * display form instead: every byte outside printable ASCII, and "%", backslash and ":",
 * becomes %XX. The escaped form is never used to touch the file.
 */
function entryName(raw: Buffer, atRoot: boolean): { name: string; safe: boolean } {
  let decoded: string | undefined;
  try {
    decoded = UTF8.decode(raw);
  } catch {
    decoded = undefined;
  }
  if (decoded !== undefined && !/[\u0000-\u001f\u007f-\u009f\\]/.test(decoded) && !(atRoot && /^[A-Za-z]:/.test(decoded))) {
    return { name: decoded, safe: true };
  }
  let escaped = '';
  for (const byte of raw) {
    const plain = byte >= 0x20 && byte <= 0x7e && byte !== 0x25 && byte !== 0x5c && byte !== 0x3a;
    escaped += plain ? String.fromCharCode(byte) : `%${byte.toString(16).toUpperCase().padStart(2, '0')}`;
  }
  return { name: escaped, safe: false };
}

async function describe(abs: string, st: Stats): Promise<ManifestEntry> {
  const mode = st.mode & 0o777;
  if (st.isSymbolicLink()) return { type: 'symlink', size: st.size, mode, linkTarget: await readlink(abs) };
  if (st.isDirectory()) return { type: 'dir', size: 0, mode };
  if (st.isFile()) {
    // Only a plain regular file (nlink === 1) is mirrored and hashed. A hardlinked
    // file is 'special': never copied into staging, so a write through it in the
    // project (which would silently change every other link, e.g. a .env) is impossible.
    return st.nlink > 1 ? { type: 'special', size: st.size, mode } : { type: 'file', size: st.size, mode, sha256: await hashFile(abs, st) };
  }
  return { type: 'special', size: st.size, mode };
}

/** describe() without reading file contents. */
async function describeUnhashed(abs: string, st: Stats): Promise<ManifestEntry> {
  const mode = st.mode & 0o777;
  if (st.isSymbolicLink()) return { type: 'symlink', size: st.size, mode, linkTarget: await readlink(abs) };
  if (st.isFile()) return { type: st.nlink > 1 ? 'special' : 'file', size: st.size, mode };
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

/**
 * Copies a plain regular file into staging, race-safely. `dst` must already be
 * removed (caller does so, so O_EXCL can't write through something swapped in).
 * The source is opened with O_NOFOLLOW and the open fd is fstat'd: the bytes are
 * copied only if it is still a regular file with nlink === 1 and the same dev/ino
 * as the pre-open lstat. Anything else — a symlink or hardlink swapped in, the
 * file gaining a second link, or it vanishing — means it is not mirrored this
 * sync, and the function simply returns, leaving no staging entry.
 */
async function copyRegularFile(src: string, dst: string, mode: number): Promise<void> {
  const before = await lstatIfPresent(src);
  if (before === undefined || !before.isFile() || before.nlink !== 1) return;
  let handle: FileHandle;
  try {
    handle = await open(src, SAFE_READ_FLAGS);
  } catch (err) {
    // A symlink (ELOOP) or a now-missing file (ENOENT) swapped in since the lstat: not mirrored.
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'ELOOP' || code === 'ENOENT') return;
    throw err;
  }
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || opened.nlink !== 1 || opened.dev !== before.dev || opened.ino !== before.ino) return;
    const out = await open(dst, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, mode);
    try {
      const buffer = Buffer.alloc(HASH_CHUNK_BYTES);
      for (;;) {
        const { bytesRead } = await handle.read(buffer, 0, buffer.length, null);
        if (bytesRead === 0) break;
        await out.write(buffer, 0, bytesRead);
      }
      await out.chmod(mode);
    } finally {
      await out.close();
    }
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

async function lstatIfPresent(abs: string | Buffer): Promise<Stats | undefined> {
  try {
    return await lstat(abs);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
    throw err;
  }
}

// ---------------------------------------------------------------------------
// Stale staging dirs
// ---------------------------------------------------------------------------

interface StagingOwner {
  pid: number;
  startedAt: string;
}

export interface SweepOptions {
  /** Where staging dirs are created. Default os.tmpdir(). */
  parent?: string;
  /** Diagnostics sink (one line, no trailing newline). Defaults to stderr. */
  log?: (line: string) => void;
  /** Tests only: the uid that counts as ours (default process.getuid()). */
  uid?: number;
}

/**
 * Removes staging dirs left behind by firewall processes that died before
 * dispose() (e.g. SIGKILL). Call once at startup, before createStagingArea().
 * Touches only entries of `parent` named exactly like ours that are real
 * directories (never symlinks) owned by this uid, and only when their owner
 * file names a pid that no longer exists (ESRCH), or, with no readable owner
 * file, when the dir is older than 24 hours. A live instance's dir is kept,
 * and so is one whose pid was reused. Logs names only; never throws.
 * Returns the names removed.
 */
export async function sweepStaleStagingDirs(options: SweepOptions = {}): Promise<string[]> {
  const log = options.log ?? ((line: string) => process.stderr.write(`${line}\n`));
  const removed: string[] = [];
  try {
    const uid = options.uid ?? process.getuid?.();
    if (uid === undefined) return removed;
    const parent = await realpath(options.parent ?? tmpdir());
    for (const name of (await readdir(parent)).sort()) {
      if (!STAGING_DIR_NAME.test(name)) continue;
      const dir = path.join(parent, name);
      try {
        const st = await lstat(dir);
        if (!st.isDirectory() || st.uid !== uid) continue;
        const owner = await readOwner(dir);
        const stale = owner ? !isProcessAlive(owner.pid) : Date.now() - st.mtimeMs > UNOWNED_MIN_AGE_MS;
        if (!stale) continue;
        // rm() does not follow symlinks: if the dir was swapped for one since lstat, only the link goes.
        await rm(dir, { recursive: true, force: true });
        removed.push(name);
      } catch (err) {
        log(`[firewall] staging: could not sweep stale staging dir ${name} (${errnoCode(err)})`);
      }
    }
  } catch (err) {
    log(`[firewall] staging: stale staging dir sweep failed (${errnoCode(err)})`);
  }
  if (removed.length > 0) {
    log(`[firewall] staging: removed ${removed.length} stale staging dir(s): ${removed.join(', ')}`);
  }
  return removed;
}

/** The owner file of a staging dir, or undefined if it is missing, not a regular file, or malformed. */
async function readOwner(dir: string): Promise<StagingOwner | undefined> {
  let handle: FileHandle;
  try {
    handle = await open(path.join(dir, OWNER_FILE), SAFE_READ_FLAGS);
  } catch {
    return undefined;
  }
  try {
    const st = await handle.stat();
    if (!st.isFile() || st.size > MAX_OWNER_FILE_BYTES) return undefined;
    const owner = JSON.parse(await handle.readFile('utf8')) as Partial<StagingOwner> | null;
    // A pid <= 0 would make process.kill() signal a process group.
    if (typeof owner?.pid !== 'number' || !Number.isSafeInteger(owner.pid) || owner.pid <= 0) return undefined;
    return { pid: owner.pid, startedAt: String(owner.startedAt) };
  } catch {
    return undefined;
  } finally {
    await handle.close();
  }
}

/** Only ESRCH means gone; EPERM means it exists under another user. */
/** False only when the pid certainly does not exist (ESRCH). EPERM and anything else count as alive. */
export function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code !== 'ESRCH';
  }
}

function errnoCode(err: unknown): string {
  const code = (err as NodeJS.ErrnoException | undefined)?.code;
  return typeof code === 'string' && /^[A-Z0-9_]{1,64}$/.test(code) ? code : 'error';
}

// ---------------------------------------------------------------------------
// Staging area
// ---------------------------------------------------------------------------

/**
 * Layout: <parent>/mcp-firewall-staging-XXXXXX/{owner.json, tree/}. Only tree/ is
 * the mirror (stagingRoot, mounted as /workspace), so the owner file is never
 * scanned, diffed or visible to the server.
 */
export async function createStagingArea(options: StagingOptions): Promise<StagingArea> {
  const projectRoot = await realpath(options.projectRoot);
  const parent = await realpath(options.stagingParent ?? tmpdir());
  const fromProject = path.relative(projectRoot, parent);
  if (fromProject === '' || (!fromProject.startsWith('..') && !path.isAbsolute(fromProject))) {
    throw new StagingError('staging dir must not be inside the protected project');
  }
  const stagingDir = await mkdtemp(path.join(parent, STAGING_DIR_PREFIX));
  try {
    const owner: StagingOwner = { pid: process.pid, startedAt: new Date().toISOString() };
    await writeFile(path.join(stagingDir, OWNER_FILE), `${JSON.stringify(owner)}\n`, { flag: 'wx', mode: 0o600 });
    await mkdir(path.join(stagingDir, TREE_DIR), { mode: 0o700 });
  } catch (err) {
    await rm(stagingDir, { recursive: true, force: true });
    throw err;
  }
  const stagingRoot = path.join(stagingDir, TREE_DIR);
  const excludes = [...(options.excludes ?? DEFAULT_EXCLUDES), ...(options.extraExcludes ?? [])];
  return new StagingArea(
    projectRoot,
    stagingRoot,
    compileExcludes(excludes),
    options.preserveStagingDirectories,
    options.maxFileBytes,
    options.maxChangesPerCall ?? 1000,
    options.log ?? ((line: string) => process.stderr.write(`${line}\n`)),
    stagingDir,
  );
}

export class StagingArea {
  /** Staging as of the last diff(): what apply() verifies staged content against. */
  private lastScan: Manifest | undefined;
  /** Top-most excluded paths the last diff() found in staging. */
  private excludedRoots: string[] = [];
  /** Entries with unsafe names the last diff() found, by escaped display path. */
  private lastUnsafe = new Map<string, UnsafeEntry>();
  /** Project paths the last sync() did not mirror because they are not plain regular files
   *  (hardlinks, devices, …). A server write at such a path is forced to DENY: applying it
   *  would write through to the project, replacing the hardlink/node there. */
  private notMirrored = new Set<string>();

  constructor(
    readonly projectRoot: string,
    readonly stagingRoot: string,
    private readonly rules: ExcludeRule[],
    private readonly preserveStagingDirectories: StagingOptions['preserveStagingDirectories'],
    private readonly maxFileBytes: number,
    private readonly maxChangesPerCall: number,
    private readonly log: (line: string) => void,
    /** What dispose() removes: stagingRoot's parent, holding it and the owner file. */
    private readonly stagingDir: string,
  ) {}

  /**
   * Makes staging an exact mirror of the project minus excludes. Project files
   * with unsafe names are not mirrored; each sync logs one warning listing them.
   */
  async sync(): Promise<SyncResult> {
    const skipped: string[] = [];
    const project = await scan(this.projectRoot, this.rules, undefined, skipped);
    if (skipped.length > 0) {
      const listed = skipped.slice(0, MAX_LOGGED_UNSAFE).join(', ');
      const more = skipped.length > MAX_LOGGED_UNSAFE ? `, and ${skipped.length - MAX_LOGGED_UNSAFE} more` : '';
      this.log(
        `[firewall] staging: ${skipped.length} project file(s) with unsafe names are not mirrored into staging: ${listed}${more}`,
      );
    }
    // Hardlinked / special project files are scanned but not mirrored; remember them so a
    // server write landing at one of their paths is forced to DENY (never applied).
    this.notMirrored = new Set([...project].filter(([, e]) => e.type === 'special').map(([rel]) => rel));
    await this.pruneStaging('', project);
    const current = await scan(this.stagingRoot, this.rules);
    for (const [rel, entry] of project) {
      if (!sameEntry(entry, current.get(rel))) await this.copyToStaging(rel, entry);
    }
    this.lastScan = undefined;
    this.lastUnsafe = new Map();
    return { staging: await scan(this.stagingRoot, this.rules), project };
  }

  /**
   * Rescans staging and reports what changed since `before` (from sync()),
   * sorted by path. Directories are not reported; their contents are.
   * `executable` is set for every add, and for modify/mode when the exec bit changed.
   *
   * Excluded paths (.git/, node_modules/, .env, …) are never copied into staging,
   * so anything found under them is a server write and is reported too, up to
   * maxChangesPerCall + 1 entries. They are not hashed. apply() never applies
   * them, and removeExcluded() deletes all of them, including any past that bound.
   *
   * Entries whose names cannot be handled safely (see entryName) are reported as
   * kind 'special' under an escaped display path. They are never applied, and
   * revert() deletes them by their raw on-disk name.
   */
  async diff(before: Manifest): Promise<FileChange[]> {
    const sink: ScanSink = {
      excluded: { entries: new Map(), roots: [], limit: this.maxChangesPerCall + 1, count: 0, dirs: 0 },
      unsafe: new Map(),
    };
    const after = await scan(this.stagingRoot, this.rules, sink);
    for (const [rel, entry] of sink.excluded.entries) after.set(rel, entry);
    this.lastScan = after;
    this.excludedRoots = sink.excluded.roots;
    this.lastUnsafe = sink.unsafe;
    const changes: FileChange[] = [];
    for (const rel of [...new Set([...before.keys(), ...after.keys()])]) {
      const change = await this.changeAt(rel, before.get(rel), after.get(rel));
      if (change) changes.push(change);
    }
    for (const [rel, entry] of sink.unsafe) changes.push({ path: rel, kind: 'special', size: entry.size });
    return changes.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  }

  /**
   * Applies the ALLOWed changes to the project. `decisions` must match
   * `changes` one to one (same paths, same order), as EvaluateFileChanges
   * returns them. Each write or delete first re-checks the project path
   * against `projectAtSync` and skips it with WRITE_CONFLICT if it changed.
   *
   * A delete whose content reappears in an add or modify of the same batch is
   * the source half of a move. It runs after the writes, and only if one of
   * those writes was applied; otherwise it is skipped with that write's rule,
   * so rejecting a move's destination never loses the file.
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
    const deletes: { index: number; rel: string; abs: string; destinations?: number[] }[] = [];
    const writes: { index: number; rel: string; abs: string; content: Buffer; executable: boolean }[] = [];

    // sha256 → indexes of the adds and modifies whose staged content has it, for pairing moves.
    const byHash = new Map<string, number[]>();
    for (const [index, change] of changes.entries()) {
      if (change.kind !== 'add' && change.kind !== 'modify') continue;
      const hash = after.get(change.path)?.sha256;
      if (hash !== undefined) byHash.set(hash, [...(byHash.get(hash) ?? []), index]);
    }

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
        const hash = projectAtSync.get(rel)?.sha256;
        const destinations = hash === undefined ? undefined : byHash.get(hash);
        deletes.push({ index, rel, abs, ...(destinations ? { destinations } : {}) });
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

    // Phase 2: deletes deepest first (so a directory can become a file), then writes in path order,
    // then move sources. A failure here throws StagingApplyError naming what was already applied.
    const applied: string[] = [];
    const runDelete = async (d: (typeof deletes)[number]): Promise<void> => {
      const blocked = await this.checkProjectPath(d.rel, d.abs, projectAtSync);
      if (blocked) {
        results[d.index] = { path: changes[d.index]!.path, applied: false, ruleId: blocked };
        return;
      }
      if (await lstatIfPresent(d.abs)) await unlink(d.abs);
      applied.push(changes[d.index]!.path);
      await this.pruneEmptyProjectDirs(d.rel, after);
      results[d.index] = { path: changes[d.index]!.path, applied: true, ruleId: decisions[d.index]!.ruleId };
    };
    deletes.sort((a, b) => (a.rel < b.rel ? 1 : -1));
    try {
      for (const d of deletes) if (!d.destinations) await runDelete(d);
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
      // Every add and modify has a result by now.
      for (const d of deletes) {
        if (!d.destinations) continue;
        if (d.destinations.some((i) => results[i]!.applied)) {
          await runDelete(d);
        } else {
          results[d.index] = { path: changes[d.index]!.path, applied: false, ruleId: results[d.destinations[0]!]!.ruleId };
        }
      }
    } catch (err) {
      if (applied.length === 0) throw err;
      throw new StagingApplyError(applied, { cause: err });
    }
    return results;
  }

  /**
   * Restores these paths in staging from the project, or removes them if the
   * project has none (along with any directories left empty that the project
   * does not have). Returns staging's entries for what was restored, as
   * baselineAfter() expects them.
   */
  async revert(paths: readonly string[]): Promise<Manifest> {
    const restored: Manifest = new Map();
    for (const p of paths) {
      const { rel, abs } = resolveInRoot(this.stagingRoot, p);
      const unsafe = this.lastUnsafe.get(rel);
      if (unsafe) await removeUnsafe(unsafe);
      await this.makeStagingParentsDirs(rel);
      await rm(abs, { recursive: true, force: true });
      await this.copyTreeToStaging(rel, restored);
      if (!restored.has(rel)) await this.pruneEmptyStagingDirs(rel);
    }
    return restored;
  }

  /** True if the path is excluded from staging: never copied, never applied. */
  isExcluded(relPath: string): boolean {
    return isExcludedPath(this.rules, relPath);
  }

  /** Why a change at this path must be denied whatever the evaluator says, or undefined. */
  forcedDenyReason(relPath: string): string | undefined {
    if (this.lastUnsafe.has(relPath)) return 'file name cannot be handled safely';
    if (isExcludedPath(this.rules, relPath)) return 'path is excluded from staging';
    if (this.notMirrored.has(relPath)) return 'path is not mirrored into staging';
    return undefined;
  }

  /** Deletes every excluded path the last diff() found in staging, including any past its scan bound. */
  async removeExcluded(): Promise<void> {
    for (const root of this.excludedRoots) {
      const { rel, abs } = resolveInRoot(this.stagingRoot, root);
      await this.makeStagingParentsDirs(rel);
      await rm(abs, { recursive: true, force: true });
    }
    this.excludedRoots = [];
  }

  /**
   * The baseline after a call, without rescanning or touching staging: `pre.staging`
   * with each applied change as the last diff() saw it and each other changed path
   * as `restored` (from revert()) left it. A server write that lands after diff()
   * therefore still differs from this baseline and shows up in the next catch-up
   * diff, instead of being absorbed or overwritten. The project is rescanned: the
   * server cannot write there.
   */
  async baselineAfter(
    pre: SyncResult,
    results: readonly ApplyResult[],
    restored: Manifest,
  ): Promise<SyncResult> {
    const after = this.lastScan;
    if (!after) throw new StagingError('baselineAfter() needs a diff() since the last sync()');
    const staging: Manifest = new Map(pre.staging);
    for (const r of results) {
      const { rel } = resolveInRoot(this.stagingRoot, r.path);
      for (const key of [...staging.keys()]) {
        if (key === rel || key.startsWith(`${rel}/`)) staging.delete(key);
      }
      if (r.applied) {
        const entry = after.get(rel);
        if (entry) staging.set(rel, entry);
      }
    }
    for (const [rel, entry] of restored) staging.set(rel, entry);
    return { staging, project: await scan(this.projectRoot, this.rules) };
  }

  /** Removes the staging dir: the mirror and its owner file. */
  async dispose(): Promise<void> {
    await rm(this.stagingDir, { recursive: true, force: true });
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
    const { abs } = resolveInRoot(this.stagingRoot, rel);
    if (entry.sha256 !== undefined) return textOrNull(await readVerified(abs, entry));
    // Unhashed (excluded) entries are always denied: their text only informs the rule ID, so read best effort.
    try {
      const handle = await openSame(abs, undefined);
      try {
        const content = await handle.readFile();
        return content.length === entry.size ? textOrNull(content) : null;
      } finally {
        await handle.close();
      }
    } catch {
      return null;
    }
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
    // Defense in depth: a hardlinked / special file (at sync or right now) is never written
    // through — a rename over it would silently change every other link (e.g. a .env).
    if (expected?.type === 'special' || current?.type === 'special') return 'WRITE_NOT_ALLOWED';
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
    for (const raw of await readNames(dirAbs)) {
      const { name, safe } = entryName(raw, dirRel === '');
      if (!safe) {
        await removeUnsafe({ raw: Buffer.concat([Buffer.from(dirAbs + path.sep), raw]), dir: dirAbs, size: 0 });
        continue;
      }
      const rel = dirRel === '' ? name : `${dirRel}/${name}`;
      const abs = path.join(dirAbs, name);
      const st = await lstat(abs);
      const want = project.get(rel);
      const keepStagingOnlyDir =
        want === undefined && st.isDirectory() && this.shouldPreserveStagingDirectory(rel);
      const keep =
        want !== undefined &&
        (want.type === 'dir'
          ? st.isDirectory()
          : want.type === 'symlink'
            ? st.isSymbolicLink()
            : want.sha256 !== undefined && st.isFile()) || keepStagingOnlyDir;
      if (!keep) await rm(abs, { recursive: true, force: true });
      else if (st.isDirectory()) await this.pruneStaging(rel, project);
    }
  }

  private shouldPreserveStagingDirectory(rel: string): boolean {
    const policy = this.preserveStagingDirectories;
    if (!policy || isExcludedPath(this.rules, rel)) return false;
    if (!policy.writablePaths.some((pattern) => matchesDirectoryOrDescendant(rel, pattern))) return false;
    if (policy.protectedPaths?.some((pattern) => matchesDirectoryOrDescendant(rel, pattern))) return false;
    if (policy.protectedWritePaths?.some((pattern) => matchesDirectoryOrDescendant(rel, pattern))) return false;
    return true;
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
    } else if (entry.type === 'file') {
      // 'special' entries (hardlinks, devices, sockets, fifos) are never mirrored.
      await copyRegularFile(src, dst, entry.mode);
    }
  }

  /** Copies a project subtree into staging, recording in `restored` what staging now holds. */
  private async copyTreeToStaging(rel: string, restored: Manifest): Promise<void> {
    if (isExcludedPath(this.rules, rel)) return;
    const src = path.join(this.projectRoot, ...rel.split('/'));
    const entry = await describeIfPresent(src);
    if (entry === undefined) return;
    await this.copyToStaging(rel, entry);
    // 'special' entries (hardlinks, devices, …) are not mirrored, so copyToStaging left
    // nothing at dst and the baseline records nothing for this path.
    if (entry.type !== 'special') restored.set(rel, entry);
    if (entry.type !== 'dir') return;
    for (const raw of await readNames(src)) {
      const { name, safe } = entryName(raw, false);
      // Project entries with unsafe names are never mirrored, like excluded paths.
      if (safe) await this.copyTreeToStaging(resolveInRoot(this.projectRoot, `${rel}/${name}`).rel, restored);
    }
  }

  /** Removes now-empty staging directories above rel that the project does not have as directories. */
  private async pruneEmptyStagingDirs(rel: string): Promise<void> {
    const parts = rel.split('/');
    for (let n = parts.length - 1; n > 0; n--) {
      const ancestor = parts.slice(0, n);
      if ((await lstatIfPresent(path.join(this.projectRoot, ...ancestor)))?.isDirectory()) return;
      try {
        await rmdir(path.join(this.stagingRoot, ...ancestor));
      } catch (err) {
        const code = (err as NodeJS.ErrnoException).code;
        if (code === 'ENOTEMPTY' || code === 'EEXIST' || code === 'ENOENT' || code === 'ENOTDIR') return;
        throw err;
      }
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

/** Deletes an unsafe-named entry by its raw name. Throws if it is still there afterwards. */
async function removeUnsafe(entry: UnsafeEntry): Promise<void> {
  await assertNoSymlinkInPath(entry.dir);
  await rm(entry.raw, { recursive: true, force: true });
  if (await lstatIfPresent(entry.raw)) throw new StagingError('could not remove an entry with an unsafe name');
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
