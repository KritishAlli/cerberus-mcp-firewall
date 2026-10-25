/**
 * OWNER: Aarav — shared config shaping for the demos (demo/pitch.ts, env-suite.ts,
 * setup-claude.ts).
 *
 * /workspace is an internal detail: the staging copy's mount point. The demos point
 * the container mount at the project's own real path instead, pass that path to the
 * downstream server as its allowed directory, and set policy.allowedRoots to it — so
 * the server and the user only ever work with real project paths, never "/workspace".
 */
import type { FirewallConfig } from '../src/shared/contracts.js';

/** The placeholder a sandbox template uses for its mount point; demos replace it with the real project path. */
export const WORKSPACE_PLACEHOLDER = '/workspace';

/**
 * Repoint a loaded sandbox config at `projectPath` (an absolute real path): the staging
 * copy mounts there, the server's allowed-directory argument becomes it, and the policy
 * allows it. Mutates and returns `config`. Throws if the config isn't a sandbox config.
 */
export function useRealProjectPaths(config: FirewallConfig, projectPath: string): FirewallConfig {
  const sandbox = config.server.sandbox;
  if (!sandbox) throw new Error('useRealProjectPaths needs a server.sandbox config');
  sandbox.project = projectPath;
  // Mount the staging copy at the project's own path and make it the container workdir.
  sandbox.workspaceMount = projectPath;
  // The downstream server's allowed-directory argument (the placeholder) becomes the real path.
  config.server.args = config.server.args.map((arg) => (arg === WORKSPACE_PLACEHOLDER ? projectPath : arg));
  // Policy sees the same real root: "." for relative paths, the absolute path for absolute ones.
  config.policy.allowedRoots = ['.', projectPath];
  return config;
}
