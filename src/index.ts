/**
 * OWNER: Aarav — startup composition. Coordinate edits with the team (design doc §4).
 *
 * Usage: tsx src/index.ts [--config path/to/firewall.yaml]
 *
 * IMPORTANT: this process is a stdio MCP server. stdout carries the protocol,
 * so nothing here may use console.log. Use console.error / stderr only.
 */
import { dirname, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { loadConfig, toUpstreamLaunch } from './config/load.js';
import { publishEvent, publishFileChangeEvent } from './observability/events.js';
import { startMonitor, type MonitorHandle } from './observability/monitor.js';
import { createInterceptor } from './proxy/interceptor.js';
import { startProxyServer, type ProxyServerHandle } from './proxy/server.js';
import { initStaging, type StagingDeps } from './proxy/staged-call.js';
import { createStagingArea, StagingLock, sweepStaleStagingDirs, type StagingArea, type SyncResult } from './proxy/staging.js';
import { connectUpstream, type UpstreamConnection } from './proxy/upstream.js';
import { evaluateToolCall } from './security/evaluator.js';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
/** Upper bound on graceful shutdown before we exit anyway. */
const SHUTDOWN_TIMEOUT_MS = 2_000;

async function main(): Promise<void> {
  const { values } = parseArgs({
    options: { config: { type: 'string', default: resolve(repoRoot, 'config/firewall.yaml') } },
  });

  // Invalid config → throw → exit non-zero. No permissive fallback (T12).
  const config = loadConfig(resolve(values.config));

  // Monitor failure must not stop or bypass enforcement (§6.6).
  let monitor: MonitorHandle | undefined;
  if (config.monitor.enabled) {
    monitor = await startMonitor(config.monitor).catch((err: unknown) => {
      console.error('[firewall] monitor failed to start; enforcement continues:', err);
      return undefined;
    });
  }

  let shuttingDown = false;
  // A downstream crash does not stop the proxy: later forwards fail closed, DENYs still BLOCK.
  // Sandbox mode: the container only ever gets a staging copy of the project at /workspace,
  // synced before it starts. Without server.sandbox this is the original local launch.
  let staging: StagingArea | undefined;
  let initial: SyncResult | undefined;
  let upstream: UpstreamConnection | undefined;
  // Any startup failure (sync, launch mapping, preflight, launch, proxy) stops what already
  // started and removes the staging copy, then rethrows the original error.
  try {
    const { sandbox } = config.server;
    if (sandbox) {
      // Dirs of firewalls that died before dispose(). Never throws.
      await sweepStaleStagingDirs();
      // The loader guarantees policy.staging exists in sandbox mode.
      const { maxFileBytes, maxChangesPerCall } = config.policy.staging!;
      staging = await createStagingArea({ projectRoot: sandbox.project, maxFileBytes, maxChangesPerCall });
      initial = await staging.sync();
    }
    const connected = await connectUpstream(config.server, {
      launch: toUpstreamLaunch(config.server, staging?.stagingRoot),
      onClose: () => {
        if (!shuttingDown) console.error('[firewall] downstream server closed; allowed calls will now fail closed');
      },
    });
    upstream = connected;
    monitor?.setProtectedServers(() => (connected.connected ? 1 : 0));
    // Every allowed call is diffed against staging; only approved changes reach the project.
    // initStaging reverts anything the server wrote while starting, and until it has run
    // every allowed call is refused, so a throw here stops startup.
    let stagingDeps: StagingDeps | undefined;
    if (staging && initial) {
      stagingDeps = {
        area: staging,
        lock: new StagingLock(),
        policy: config.policy,
        onFileChangeEvent: publishFileChangeEvent,
      };
      await initStaging(stagingDeps, { serverId: config.server.id, initial });
    }
    const handleToolCall = createInterceptor({
      serverId: config.server.id,
      policy: config.policy,
      evaluate: evaluateToolCall,
      publish: publishEvent,
      forward: (toolName, args, options) => connected.callTool(toolName, args, options),
      ...(stagingDeps ? { staging: stagingDeps } : {}),
    });

    let proxy: ProxyServerHandle | undefined;
    const shutdown = (reason: string): void => {
      if (shuttingDown) return;
      shuttingDown = true;
      console.error(`[firewall] shutting down (${reason})`);
      const closing = Promise.allSettled([
        connected.close().then(() => staging?.dispose()),
        proxy?.close(),
        monitor?.close(),
      ]);
      void Promise.race([closing, delay(SHUTDOWN_TIMEOUT_MS)]).then(() => process.exit(0));
    };

    process.once('SIGINT', () => shutdown('SIGINT'));
    process.once('SIGTERM', () => shutdown('SIGTERM'));
    process.stdin.once('end', () => shutdown('stdin ended'));

    proxy = await startProxyServer(connected, handleToolCall, { onClose: () => shutdown('agent disconnected') });
  } catch (err) {
    await abandonStartup(upstream, staging);
    throw err;
  }
  console.error(`[firewall] protecting MCP server "${config.server.id}"`);
}

/**
 * After a failed startup: closes the downstream (removing its container) before
 * removing the staging copy it may still be writing to. Failures are logged with a
 * code only and never replace the startup error.
 */
async function abandonStartup(upstream: UpstreamConnection | undefined, staging: StagingArea | undefined): Promise<void> {
  const code = (err: unknown): string => {
    const c = (err as NodeJS.ErrnoException | undefined)?.code;
    return typeof c === 'string' && /^[A-Z0-9_]{1,64}$/.test(c) ? c : 'error';
  };
  await upstream?.close().catch((err: unknown) => {
    console.error(`[firewall] could not close the downstream after a failed start (${code(err)})`);
  });
  await staging?.dispose().catch((err: unknown) => {
    console.error(`[firewall] could not remove the staging dir after a failed start (${code(err)})`);
  });
}

main().catch((err: unknown) => {
  console.error('[firewall] fatal:', err instanceof Error ? err.message : err);
  process.exit(1);
});
