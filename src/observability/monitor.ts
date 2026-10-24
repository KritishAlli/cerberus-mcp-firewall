/**
 * OWNER: Kritish — localhost HTTP + SSE monitor (design doc §8).
 *
 *   GET /         → serves ./index.html (read-only UI)
 *   GET /events   → Server-Sent Events: the buffered recent events first, then live ones.
 *                   `firewall` frames carry FirewallEvents; `filechanges` frames carry
 *                   FileChangeEvents plus a ready-made `line` (paths and rule IDs, never contents);
 *                   `counts` frames carry EventCounts after every live event of either kind.
 *   GET /health   → { status, protectedServers } from live upstream state
 *
 * Binds to config.host (127.0.0.1 only) and rejects requests whose Host header is
 * not loopback, so a DNS-rebinding page cannot read the feed. A monitor failure must
 * never bypass or block policy enforcement: it only ever reads from the event bus.
 */
import { readFile } from 'node:fs/promises';
import type { AddressInfo } from 'node:net';
import { resolve } from 'node:path';
import { serve, type ServerType } from '@hono/node-server';
import { Hono } from 'hono';
import { streamSSE, type SSEStreamingApi } from 'hono/streaming';
import type { FileChangeEvent, FirewallEvent, MonitorConfig } from '../shared/contracts.js';
import { describeFileChanges, eventBus, type EventBus } from './events.js';

/** Upper bound on simultaneous SSE clients; the monitor is for one person's browser. */
const MAX_SSE_CLIENTS = 16;
/** Comment line sent on idle streams so proxies and browsers keep them open. */
const KEEPALIVE_MS = 15_000;

export interface MonitorOptions {
  /** Defaults to the process-wide bus that publishEvent writes to. */
  bus?: EventBus;
  /** Live count of connected downstream servers. Can also be set later via setProtectedServers. */
  protectedServers?: () => number;
}

export interface MonitorHandle {
  readonly url: string | undefined;
  /** Wire /health to live state once the upstream connection exists. */
  setProtectedServers(source: () => number): void;
  close(): Promise<void>;
}

export interface HealthBody {
  status: 'ok' | 'degraded';
  protectedServers: number;
}

export async function startMonitor(config: MonitorConfig, options: MonitorOptions = {}): Promise<MonitorHandle> {
  const bus = options.bus ?? eventBus;
  bus.setMaxEvents(config.maxEvents);

  const page = await readFile(resolve(import.meta.dirname, 'index.html'), 'utf8');
  // Until wired, report nothing protected rather than a fake green.
  let protectedServers = options.protectedServers ?? (() => 0);
  const streams = new Set<SSEStreamingApi>();
  let port = config.port;

  const app = new Hono();

  app.use('*', async (c, next) => {
    const host = c.req.header('host') ?? '';
    if (host !== `127.0.0.1:${port}` && host !== `localhost:${port}`) {
      return c.text('Forbidden', 403);
    }
    await next();
    c.header('X-Content-Type-Options', 'nosniff');
    c.header('Cache-Control', 'no-store');
  });

  app.get('/', (c) => {
    c.header(
      'Content-Security-Policy',
      "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'",
    );
    return c.html(page);
  });

  app.get('/health', (c) => {
    const body = health(protectedServers);
    return c.json(body, body.status === 'ok' ? 200 : 503);
  });

  app.get('/events', (c) => {
    if (streams.size >= MAX_SSE_CLIENTS) return c.text('Too many monitor connections', 503);

    return streamSSE(c, async (stream) => {
      streams.add(stream);
      // Writes are chained so replayed and live events go out in publish order.
      let chain: Promise<void> = Promise.resolve();
      let pending = 0;
      const send = (write: () => Promise<void>): void => {
        // A client that cannot keep up is dropped rather than buffered without bound.
        if (pending > config.maxEvents) {
          stream.abort();
          return;
        }
        pending += 1;
        chain = chain.then(write).catch(() => stream.abort()).finally(() => (pending -= 1));
      };
      const writeFirewall = (event: FirewallEvent): void =>
        send(() => stream.writeSSE({ event: 'firewall', id: event.requestId, data: JSON.stringify(event) }));
      const writeFileChanges = (event: FileChangeEvent): void =>
        send(() =>
          stream.writeSSE({
            event: 'filechanges',
            id: event.requestId,
            data: JSON.stringify({ ...event, line: describeFileChanges(event) }),
          }),
        );
      const sendEvent = (event: FirewallEvent): void => {
        writeFirewall(event);
        send(() => stream.writeSSE({ event: 'counts', data: JSON.stringify(bus.counts()) }));
      };
      // A file-change event can move writesBlocked, so live ones are followed by counts too.
      const sendFileChanges = (event: FileChangeEvent): void => {
        writeFileChanges(event);
        send(() => stream.writeSSE({ event: 'counts', data: JSON.stringify(bus.counts()) }));
      };

      // Snapshot and subscribe in the same tick: publish is synchronous, so nothing
      // can land between them, and nothing is sent twice.
      const backlog = bus.recent();
      const fileBacklog = bus.recentFileChanges();
      const unsubscribe = bus.subscribe(sendEvent);
      const unsubscribeFiles = bus.subscribeFileChanges(sendFileChanges);

      send(() => stream.writeSSE({ event: 'counts', data: JSON.stringify(bus.counts()) }));
      // Call events first, so the page can attach each file-change line to its call's row.
      for (const event of backlog) writeFirewall(event);
      for (const event of fileBacklog) writeFileChanges(event);
      send(() =>
        stream.writeSSE({
          event: 'ready',
          data: JSON.stringify({ replayed: backlog.length, replayedFileChanges: fileBacklog.length }),
        }),
      );

      const keepalive = setInterval(() => send(() => stream.write(': keepalive\n\n').then(() => {})), KEEPALIVE_MS);
      try {
        await new Promise<void>((done) => stream.onAbort(done));
      } finally {
        clearInterval(keepalive);
        unsubscribe();
        unsubscribeFiles();
        streams.delete(stream);
      }
    });
  });

  app.notFound((c) => c.text('Not found', 404));
  app.onError((_err, c) => c.text('Internal error', 500));

  const server = await listen(app, config);
  port = (server.address() as AddressInfo).port;
  const url = `http://${config.host}:${port}`;
  process.stderr.write(`[firewall] monitor listening on ${url}\n`);

  return {
    url,
    setProtectedServers(source) {
      protectedServers = source;
    },
    async close() {
      for (const stream of streams) stream.abort();
      await new Promise<void>((done) => {
        server.close(() => done());
        if ('closeAllConnections' in server) server.closeAllConnections();
      });
    },
  };
}

function health(protectedServers: () => number): HealthBody {
  let count = 0;
  try {
    count = protectedServers();
  } catch {
    // Treat a failing status source as nothing protected.
  }
  return { status: count >= 1 ? 'ok' : 'degraded', protectedServers: count };
}

function listen(app: Hono, config: MonitorConfig): Promise<ServerType> {
  return new Promise((resolvePromise, reject) => {
    const server = serve({ fetch: app.fetch, hostname: config.host, port: config.port }, () => {
      server.off('error', reject);
      resolvePromise(server);
    });
    server.once('error', reject);
  });
}
