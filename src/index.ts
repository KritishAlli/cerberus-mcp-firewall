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
import { loadConfig } from './config/load.js';
import { publishEvent } from './observability/events.js';
import { startMonitor, type MonitorHandle } from './observability/monitor.js';
import { createInterceptor } from './proxy/interceptor.js';
import { startProxyServer, type ProxyServerHandle } from './proxy/server.js';
import { connectUpstream } from './proxy/upstream.js';
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
  const upstream = await connectUpstream(config.server, {
    onClose: () => {
      if (!shuttingDown) console.error('[firewall] downstream server closed; allowed calls will now fail closed');
    },
  });
  const handleToolCall = createInterceptor({
    serverId: config.server.id,
    policy: config.policy,
    evaluate: evaluateToolCall,
    publish: publishEvent,
    forward: (toolName, args, options) => upstream.callTool(toolName, args, options),
  });

  let proxy: ProxyServerHandle | undefined;
  const shutdown = (reason: string): void => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.error(`[firewall] shutting down (${reason})`);
    const closing = Promise.allSettled([upstream.close(), proxy?.close(), monitor?.close()]);
    void Promise.race([closing, delay(SHUTDOWN_TIMEOUT_MS)]).then(() => process.exit(0));
  };

  process.once('SIGINT', () => shutdown('SIGINT'));
  process.once('SIGTERM', () => shutdown('SIGTERM'));
  process.stdin.once('end', () => shutdown('stdin ended'));

  proxy = await startProxyServer(upstream, handleToolCall, { onClose: () => shutdown('agent disconnected') });
  console.error(`[firewall] protecting MCP server "${config.server.id}"`);
}

main().catch((err: unknown) => {
  console.error('[firewall] fatal:', err instanceof Error ? err.message : err);
  process.exit(1);
});
