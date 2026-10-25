/**
 * OWNER: Kritish — YAML parsing and validation (design doc §8).
 *
 * Validates syntax and schema at startup. There is no silent permissive
 * fallback: any problem throws ConfigError and the firewall must not start (T12).
 */
import { readFileSync, realpathSync, statSync } from 'node:fs';
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path';
import { parse as parseYaml } from 'yaml';
import { z } from 'zod';
import { localLaunch, type UpstreamLaunch } from '../proxy/upstream.js';
import { FirewallConfigSchema, type DownstreamServerConfig, type FirewallConfig } from '../shared/contracts.js';

export class ConfigError extends Error {
  override name = 'ConfigError';
}

/** Parse and validate config text. Throws ConfigError on any problem. */
export function parseConfig(text: string, source = '<config>'): FirewallConfig {
  let raw: unknown;
  try {
    raw = parseYaml(text);
  } catch (err) {
    throw new ConfigError(`${source}: invalid YAML: ${(err as Error).message}`);
  }
  const result = FirewallConfigSchema.safeParse(raw);
  if (!result.success) {
    throw new ConfigError(`${source}: invalid firewall config:\n${z.prettifyError(result.error)}`);
  }
  // Sandbox mode without staging rules must not start: a missing section never means "allow all writes".
  if (result.data.server.sandbox && !result.data.policy.staging) {
    throw new ConfigError(`${source}: server.sandbox requires a policy.staging section`);
  }
  if (result.data.server.sandbox && result.data.server.cwd !== undefined) {
    throw new ConfigError(`${source}: server.cwd is not allowed with server.sandbox (the server runs in /workspace)`);
  }
  return result.data;
}

/** Read, parse and validate a config file. Throws ConfigError on any problem. */
export function loadConfig(path: string): FirewallConfig {
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch (err) {
    throw new ConfigError(`cannot read config file ${path}: ${(err as Error).message}`);
  }
  const config = parseConfig(text, path);
  // server.cwd is written relative to the config file; hand callers an absolute path.
  const base = dirname(resolve(path));
  const sandbox = config.server.sandbox;
  if (!sandbox) {
    config.server.cwd = resolve(base, config.server.cwd ?? '.');
    return config;
  }
  // Sandbox paths are written relative to the config file too, and must exist now.
  sandbox.project = existingDir(resolve(base, sandbox.project), 'server.sandbox.project', path);
  if (sandbox.serverDir !== undefined) {
    sandbox.serverDir = existingDir(resolve(base, sandbox.serverDir), 'server.sandbox.serverDir', path);
    // serverDir is mounted into the container; if it overlapped the project, the
    // server could read the real project (secrets included) and skip staging.
    if (overlaps(sandbox.serverDir, sandbox.project)) {
      throw new ConfigError(`${path}: server.sandbox.serverDir and server.sandbox.project must not overlap`);
    }
  }
  return config;
}

/**
 * Map a loaded server config onto how upstream starts it. Sandbox mode needs
 * the staging dir (created at runtime by createStagingArea) as workspaceDir.
 */
export function toUpstreamLaunch(server: DownstreamServerConfig, workspaceDir?: string): UpstreamLaunch {
  const { sandbox } = server;
  if (!sandbox) return localLaunch(server);
  if (workspaceDir === undefined) throw new ConfigError('sandbox mode needs a staging dir to mount at /workspace');
  // Mounting the real project (or anything holding it) rw would bypass staging entirely.
  if (overlaps(workspaceDir, sandbox.project)) {
    throw new ConfigError('the staging dir must not overlap server.sandbox.project');
  }
  return {
    mode: 'docker',
    image: sandbox.image,
    command: server.command,
    args: server.args,
    workspaceDir,
    ...(sandbox.workspaceMount === undefined ? {} : { workspaceMount: sandbox.workspaceMount }),
    ...(sandbox.serverDir === undefined ? {} : { serverDir: sandbox.serverDir }),
    ...(sandbox.env === undefined ? {} : { env: sandbox.env }),
    user: sandbox.user ?? hostUser(),
    memory: sandbox.memory,
    pidsLimit: sandbox.pidsLimit,
  };
}

/** Host uid:gid, so files the server writes to staging are ours. Never root: falls back to 1000:1000. */
function hostUser(): string {
  const uid = process.getuid?.();
  const gid = process.getgid?.();
  return uid === undefined || gid === undefined || uid === 0 ? '1000:1000' : `${uid}:${gid}`;
}

/** Real path of an existing directory, or ConfigError. */
function existingDir(dir: string, key: string, source: string): string {
  let real: string;
  try {
    real = realpathSync(dir);
  } catch {
    throw new ConfigError(`${source}: ${key}: directory does not exist: ${dir}`);
  }
  if (!statSync(real).isDirectory()) throw new ConfigError(`${source}: ${key}: not a directory: ${dir}`);
  return real;
}

/** True if either path is the other or inside it. */
function overlaps(a: string, b: string): boolean {
  return contains(a, b) || contains(b, a);
}

/** True if `child` is `parent` or inside it. */
function contains(parent: string, child: string): boolean {
  const rel = relative(parent, child);
  return rel === '' || (rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
}
