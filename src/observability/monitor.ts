/**
 * OWNER: Kritish — localhost HTTP + SSE monitor (design doc §8).
 *
 * SCAFFOLD STUB: does not start a server yet.
 *
 * TODO(Kritish), using hono + @hono/node-server:
 *   GET /         → serves ./index.html (read-only UI)
 *   GET /events   → Server-Sent Events of real FirewallEvents
 *   GET /health   → { status: 'ok', protectedServers: 1 } from live state
 *   Bind to config.host (127.0.0.1 only). A monitor failure must never
 *   bypass or block policy enforcement.
 */
import type { MonitorConfig } from '../shared/contracts.js';

export interface MonitorHandle {
  readonly url: string | undefined;
  close(): Promise<void>;
}

export async function startMonitor(config: MonitorConfig): Promise<MonitorHandle> {
  process.stderr.write(
    `[firewall] monitor not implemented yet (would listen on http://${config.host}:${config.port})\n`,
  );
  return { url: undefined, close: async () => {} };
}
