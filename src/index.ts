/**
 * OWNER: Aarav — startup composition. Coordinate edits with the team (design doc §4).
 *
 * Usage: tsx src/index.ts [--config path/to/firewall.yaml]
 *
 * IMPORTANT: this process is a stdio MCP server. stdout carries the protocol,
 * so nothing here may use console.log. Use console.error / stderr only.
 */
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { loadConfig } from './config/load.js';
import { publishEvent } from './observability/events.js';
import { startMonitor } from './observability/monitor.js';
import { createInterceptor } from './proxy/interceptor.js';
import { startProxyServer } from './proxy/server.js';
import { connectUpstream } from './proxy/upstream.js';
import { evaluateToolCall } from './security/evaluator.js';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');

async function main(): Promise<void> {
  const { values } = parseArgs({
    options: { config: { type: 'string', default: resolve(repoRoot, 'config/firewall.yaml') } },
  });

  // Invalid config → throw → exit non-zero. No permissive fallback (T12).
  const config = loadConfig(resolve(values.config));

  // Monitor failure must not stop or bypass enforcement (§6.6).
  if (config.monitor.enabled) {
    await startMonitor(config.monitor).catch((err: unknown) => {
      console.error('[firewall] monitor failed to start; enforcement continues:', err);
    });
  }

  const upstream = await connectUpstream(config.server);
  const handleToolCall = createInterceptor({
    serverId: config.server.id,
    policy: config.policy,
    evaluate: evaluateToolCall,
    publish: publishEvent,
    forward: (toolName, args) => upstream.callTool(toolName, args),
  });
  await startProxyServer(upstream, handleToolCall);
  console.error(`[firewall] protecting MCP server "${config.server.id}"`);
}

main().catch((err: unknown) => {
  console.error('[firewall] fatal:', err instanceof Error ? err.message : err);
  process.exit(1);
});
