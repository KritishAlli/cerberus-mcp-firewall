/**
 * OWNER: Kritish — localhost monitor: page, SSE replay + live, health, loopback guard.
 */
import { afterEach, describe, expect, it } from 'vitest';
import { createEventBus, type EventBus } from '../src/observability/events.js';
import { startMonitor, type MonitorHandle } from '../src/observability/monitor.js';
import type { FirewallEvent, MonitorConfig } from '../src/shared/contracts.js';

// Port 0 lets the OS pick a free port; the schema forbids it in real config.
const config: MonitorConfig = { enabled: true, host: '127.0.0.1', port: 0, maxEvents: 100 };

let seq = 0;
function event(overrides: Partial<FirewallEvent> = {}): FirewallEvent {
  seq += 1;
  return {
    timestamp: new Date().toISOString(),
    requestId: `req-${seq}`,
    serverId: 'demo',
    toolName: 'read_project_file',
    decision: 'ALLOW',
    ruleId: 'APPROVED_TOOL',
    reason: 'Tool is on the approved list',
    summary: 'read_project_file args=[path] → ALLOW APPROVED_TOOL',
    ...overrides,
  };
}

let monitor: MonitorHandle | undefined;
afterEach(async () => {
  await monitor?.close();
  monitor = undefined;
});

async function start(bus: EventBus, protectedServers?: () => number): Promise<string> {
  monitor = await startMonitor(config, { bus, protectedServers });
  return monitor.url!;
}

/** Reads SSE frames until `until` returns true for the accumulated frames. */
async function readSSE(url: string, until: (frames: { event: string; data: string }[]) => boolean, onOpen?: () => void) {
  const controller = new AbortController();
  const res = await fetch(`${url}/events`, { signal: controller.signal });
  expect(res.headers.get('content-type')).toContain('text/event-stream');
  const reader = res.body!.pipeThrough(new TextDecoderStream()).getReader();
  const frames: { event: string; data: string }[] = [];
  let buffer = '';
  onOpen?.();
  try {
    while (!until(frames)) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += value;
      let end: number;
      while ((end = buffer.indexOf('\n\n')) !== -1) {
        const raw = buffer.slice(0, end);
        buffer = buffer.slice(end + 2);
        const frame = { event: 'message', data: '' };
        for (const line of raw.split('\n')) {
          if (line.startsWith('event: ')) frame.event = line.slice(7);
          if (line.startsWith('data: ')) frame.data += line.slice(6);
        }
        if (!raw.startsWith(':')) frames.push(frame);
      }
    }
  } finally {
    controller.abort();
  }
  return frames;
}

const quietBus = () => createEventBus({ log: () => {} });

describe('monitor', () => {
  it('binds to 127.0.0.1 and serves the page', async () => {
    const url = await start(quietBus());
    expect(url).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);
    const res = await fetch(url);
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('text/html');
    expect(await res.text()).toContain("new EventSource('/events')");
  });

  it('/health reports live protected-server state', async () => {
    let connected = true;
    const url = await start(quietBus(), () => (connected ? 1 : 0));
    expect(await (await fetch(`${url}/health`)).json()).toEqual({ status: 'ok', protectedServers: 1 });
    connected = false;
    const down = await fetch(`${url}/health`);
    expect(down.status).toBe(503);
    expect(await down.json()).toEqual({ status: 'degraded', protectedServers: 0 });
  });

  it('/health is not green until a status source is wired', async () => {
    const url = await start(quietBus());
    expect(await (await fetch(`${url}/health`)).json()).toEqual({ status: 'degraded', protectedServers: 0 });
    monitor!.setProtectedServers(() => 1);
    expect(await (await fetch(`${url}/health`)).json()).toEqual({ status: 'ok', protectedServers: 1 });
  });

  it('new SSE clients get buffered events first, then live ones, in order', async () => {
    const bus = quietBus();
    const old = [event(), event({ decision: 'DENY', ruleId: 'DENIED_TOOL' })];
    for (const e of old) bus.publish(e);
    const url = await start(bus);

    const live = event();
    const frames = await readSSE(
      url,
      (f) => f.filter((x) => x.event === 'firewall').length >= 3,
      () => setTimeout(() => bus.publish(live), 50),
    );

    const ids = frames.filter((f) => f.event === 'firewall').map((f) => (JSON.parse(f.data) as FirewallEvent).requestId);
    expect(ids).toEqual([...old, live].map((e) => e.requestId));
    const readyAt = frames.findIndex((f) => f.event === 'ready');
    expect(JSON.parse(frames[readyAt]!.data)).toEqual({ replayed: 2 });
    expect(frames.findIndex((f) => f.event === 'firewall' && f.data.includes(live.requestId))).toBeGreaterThan(readyAt);
    const lastCounts = frames.filter((f) => f.event === 'counts').at(-1)!;
    expect(JSON.parse(lastCounts.data)).toEqual({ inspected: 3, allowed: 2, denied: 1 });
  });

  it('unsubscribes from the bus when a client disconnects', async () => {
    const bus = quietBus();
    const url = await start(bus);
    await readSSE(url, (f) => f.some((x) => x.event === 'ready'));
    await new Promise((r) => setTimeout(r, 50));
    expect(() => bus.publish(event())).not.toThrow();
  });

  it('rejects non-loopback Host headers (DNS rebinding)', async () => {
    const url = await start(quietBus());
    const { request } = await import('node:http');
    const status = await new Promise<number>((resolve, reject) => {
      const req = request(`${url}/health`, { headers: { host: 'evil.example:80' } }, (res) => {
        res.resume();
        resolve(res.statusCode ?? 0);
      });
      req.on('error', reject);
      req.end();
    });
    expect(status).toBe(403);
  });

  it('unknown routes are 404', async () => {
    const url = await start(quietBus());
    expect((await fetch(`${url}/nope`)).status).toBe(404);
  });

  it('fails to start (rather than hanging) when the port is taken', async () => {
    const url = await start(quietBus());
    const port = Number(new URL(url).port);
    await expect(startMonitor({ ...config, port }, { bus: quietBus() })).rejects.toThrow();
  });
});
