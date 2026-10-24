/**
 * OWNER: Kritish — YAML parsing and validation (design doc §8).
 *
 * Validates syntax and schema at startup. There is no silent permissive
 * fallback: any problem throws ConfigError and the firewall must not start (T12).
 */
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { parse as parseYaml } from 'yaml';
import { z } from 'zod';
import { FirewallConfigSchema, type FirewallConfig } from '../shared/contracts.js';

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
  config.server.cwd = resolve(dirname(resolve(path)), config.server.cwd ?? '.');
  return config;
}
