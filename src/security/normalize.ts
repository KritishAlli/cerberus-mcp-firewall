/** Pure normalization helpers for policy matching. Static checks do not defend against symlink/TOCTOU tricks. */
import { homedir } from 'node:os';
import path from 'node:path';

function expandHome(value: string): string {
  if (value === '~') return homedir();
  if (value.startsWith('~/') || value.startsWith('~\\')) return path.join(homedir(), value.slice(2));
  return value;
}

/** Normalize POSIX and Windows separators and dot segments into a comparable path. */
export function normalizePath(value: string): string {
  const expanded = expandHome(value.trim()).replace(/\\/g, '/');
  const winDrive = /^([A-Za-z]):\/(.*)$/.exec(expanded);
  if (winDrive) {
    const normalized = `${winDrive[1]!.toLowerCase()}:/${path.posix.normalize(`/${winDrive[2]!}`).slice(1)}`;
    return normalized.length > 3 ? normalized.replace(/\/+$/, '') : normalized;
  }
  const normalized = path.posix.normalize(expanded);
  return normalized.length > 1 ? normalized.replace(/\/+$/, '') : normalized;
}

function globRegex(pattern: string): RegExp {
  let out = '^';
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i]!;
    if (c === '*' && pattern[i + 1] === '*') {
      i++;
      if (pattern[i + 1] === '/') { i++; out += '(?:.*/)?'; }
      else out += '.*';
    } else if (c === '*') out += '[^/]*';
    else if (c === '?') out += '[^/]';
    else out += c.replace(/[|\\{}()[\]^$+?.]/g, '\\$&');
  }
  // Default macOS volumes are case-insensitive. Matching case-insensitively
  // avoids policy bypasses for `.ENV` / `.Env` paths on those developer machines.
  return new RegExp(`${out}$`, process.platform === 'win32' || process.platform === 'darwin' ? 'i' : '');
}

/** Match a normalized path against a path-aware glob (`*` stays in one segment, `**` crosses segments). */
export function pathMatches(pathValue: string, configuredPattern: string): boolean {
  const candidate = normalizePath(pathValue);
  let pattern = normalizePath(configuredPattern);
  if (!pattern.startsWith('/') && !/^[a-z]:\//i.test(pattern) && !pattern.startsWith('**/')) {
    pattern = `**/${pattern}`;
  }
  return globRegex(pattern).test(candidate);
}

export interface DestinationMatch { malformed: boolean; hostname?: string; origin?: string }

/** Parse and canonicalize an outbound URL. Non-URL bare host values are accepted. */
export function normalizeDestination(value: string, allowBareHost = false): DestinationMatch {
  try {
    const input = value.trim();
    let url: URL;
    try {
      url = new URL(input);
    } catch {
      if (!allowBareHost || !/^[A-Za-z0-9.-]+(?::\d+)?$/.test(input)) return { malformed: true };
      url = new URL(`https://${input}`);
    }
    if (!['http:', 'https:'].includes(url.protocol)) return { malformed: true };
    if (!url.hostname || url.username || url.password) return { malformed: true };
    return { malformed: false, hostname: url.hostname.toLowerCase().replace(/\.$/, ''), origin: url.origin.toLowerCase() };
  } catch {
    return { malformed: true };
  }
}

/** Normalize configured host, origin, or wildcard-subdomain patterns. */
export function destinationMatches(destination: DestinationMatch, configured: string): boolean {
  if (destination.malformed || !destination.hostname) return false;
  const raw = configured.trim().toLowerCase();
  const hostPart = raw.includes('://') ? (() => { try { return new URL(raw).hostname.toLowerCase().replace(/\.$/, ''); } catch { return ''; } })() : raw.replace(/:\d+$/, '').replace(/\.$/, '');
  if (!hostPart) return false;
  if (hostPart.startsWith('*.')) return destination.hostname === hostPart.slice(2) || destination.hostname.endsWith(`.${hostPart.slice(2)}`);
  return destination.hostname === hostPart || destination.hostname.endsWith(`.${hostPart}`);
}

/** A URL/host is allowed only by an exact host entry or an explicit `*.domain` entry. */
export function destinationAllowed(destination: DestinationMatch, allowedHosts: readonly string[]): boolean {
  const destinationHost = destination.hostname;
  if (destination.malformed || !destinationHost) return false;
  return allowedHosts.some((entry) => {
    const raw = entry.trim().toLowerCase();
    const wildcard = raw.startsWith('*.');
    const configured = wildcard ? raw.slice(2) : raw;
    const normalized = normalizeDestination(configured, true);
    if (normalized.malformed || !normalized.hostname) return false;
    return wildcard
      ? destinationHost === normalized.hostname || destinationHost.endsWith(`.${normalized.hostname}`)
      : destinationHost === normalized.hostname;
  });
}

/** True only when a normalized path is equal to an allowed root or a descendant of it. */
export function pathWithinRoots(value: string, roots: readonly string[]): boolean {
  const candidate = normalizePath(decodePath(value));
  if (candidate === '' || candidate === '.' || candidate === '..' || candidate.startsWith('../')) return false;
  return roots.some((rootValue) => {
    const normalizedRoot = normalizePath(decodePath(rootValue));
    const root = normalizedRoot === '/' ? '/' : normalizedRoot.replace(/\/$/, '');
    if (root === '/') return candidate.startsWith('/');
    if (root === '.') return !candidate.startsWith('/') && !/^[a-z]:\//i.test(candidate);
    if (!root) return false;
    const insensitive = process.platform === 'win32' || process.platform === 'darwin' || /^[a-z]:\//i.test(root) || /^[a-z]:\//i.test(candidate);
    const left = insensitive ? candidate.toLowerCase() : candidate;
    const right = insensitive ? root.toLowerCase() : root;
    return left === right || left.startsWith(`${right}/`);
  });
}

function decodePath(value: string): string {
  let decoded = value;
  // Decode bounded layers so double-encoded dot segments and separators cannot
  // evade a root check when a downstream path consumer decodes more than once.
  for (let i = 0; i < 8; i++) {
    try {
      const next = decodeURIComponent(decoded);
      if (next === decoded) break;
      decoded = next;
    } catch {
      break;
    }
  }
  return decoded;
}

export interface StringReference { value: string; start: number; end: number }

/** Find explicit URLs in arbitrary argument strings, including once-percent-encoded URLs. */
export function extractUrlReferences(value: string): StringReference[] {
  const references: StringReference[] = [];
  const seen = new Set<string>();
  const scan = (source: string) => {
    const re = /\b(?:https?|ftp|file):\/\/[^\s"'`<>]+/gi;
    for (const match of source.matchAll(re)) {
      const start = match.index ?? 0;
      const raw = match[0].replace(/[.,;:!?\])}]+$/g, '');
      const key = `${start}:${raw}`;
      if (raw && !seen.has(key)) { seen.add(key); references.push({ value: raw, start, end: start + raw.length }); }
    }
  };
  scan(value);
  let decoded: string;
  try { decoded = decodeURIComponent(value); } catch { decoded = value; }
  if (decoded !== value) scan(decoded);
  return references;
}

/** Extract path-looking tokens from free-form strings; named path fields are handled separately. */
export function extractPathReferences(value: string): string[] {
  const withoutUrls = value.replace(/\b(?:https?|ftp|file):\/\/[^\s"'`<>]+/gi, ' ');
  let decoded = withoutUrls;
  try { decoded = decodeURIComponent(withoutUrls); } catch { /* Keep original text when it is not URL-encoded. */ }
  const paths = new Set<string>();
  const patterns = [
    /~[\\/][^\s"'`<>;,|&]+/g,
    /(?:^|[\s=:'"(])(?:\.{1,2}[\\/])[^\s"'`<>;,|&]+/g,
    /[A-Za-z]:[\\/][^\s"'`<>;,|&]+/g,
    /(?:^|[\s=:'"(])\/(?:[^\s"'`<>;,|&]+\/)*[^\s"'`<>;,|&]*/g,
    /(?:[\w.@+-]+[\\/])+[\w.@+-]+/g,
    /(?:^|[\s=:'"(])(?:\.[\w.-]+|[\w.-]+\.(?:env|json|ya?ml|toml|md|txt|ts|tsx|js|jsx|py|sh|pem|key|lock|cfg|conf|ini))(?:$|[\s"'`,;:!?)}])/g,
  ];
  for (const source of [withoutUrls, decoded]) {
    for (const pattern of patterns) {
      for (const match of source.matchAll(pattern)) {
        const raw = match[0].trim().replace(/^[\s=:'"(]+|[\s"'`,;:!?)}]+$/g, '');
        if (raw) paths.add(raw);
      }
    }
  }
  return [...paths];
}

export function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
