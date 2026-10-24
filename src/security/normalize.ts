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
  if (winDrive) return `${winDrive[1]!.toLowerCase()}:/${path.posix.normalize(`/${winDrive[2]!}`).slice(1)}`;
  return path.posix.normalize(expanded);
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
  return new RegExp(`${out}$`, process.platform === 'win32' ? 'i' : '');
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
export function normalizeDestination(value: string): DestinationMatch {
  try {
    const url = new URL(value);
    if (!['http:', 'https:'].includes(url.protocol)) return { malformed: true };
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

export function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
