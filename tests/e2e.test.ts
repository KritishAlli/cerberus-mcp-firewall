/**
 * OWNER: Kritish — end-to-end through the real processes (design doc §8, §10; Cerberus §9 A1, A7, A9).
 *
 * Runs `demo/scenarios.ts`, which launches the real firewall CLI (src/index.ts) against
 * the mock server, makes allowed and blocked calls, and then reads that firewall's own
 * monitor. Nothing here uses a stub bus or synthetic UI state.
 */
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import { createEventBus } from '../src/observability/events.js';
import { startMonitor, type MonitorHandle } from '../src/observability/monitor.js';
import { DUMMY_SECRET } from '../demo/mock-server.js';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');

interface RunResult {
  code: number | null;
  stdout: string;
  stderr: string;
}

function run(args: string[], timeoutMs = 30_000): Promise<RunResult> {
  return new Promise((done, fail) => {
    const child = spawn(process.execPath, ['--import', 'tsx', ...args], { cwd: repoRoot });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => (stdout += String(d)));
    child.stderr.on('data', (d) => (stderr += String(d)));
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      fail(new Error(`timed out: ${args.join(' ')}\n${stdout}\n${stderr}`));
    }, timeoutMs);
    child.on('close', (code) => {
      clearTimeout(timer);
      done({ code, stdout, stderr });
    });
  });
}

/** A port nobody is listening on right now. */
function freePort(): Promise<number> {
  return new Promise((done, fail) => {
    const server = createServer();
    server.once('error', fail);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as { port: number };
      server.close(() => done(port));
    });
  });
}

let blocker: MonitorHandle | undefined;
afterEach(async () => {
  await blocker?.close();
  blocker = undefined;
});

describe('e2e / client → firewall → mock server → monitor', () => {
  it('A1 + A7: allowed calls are forwarded, blocked ones never are, and the same process streams both events', async () => {
    const port = await freePort();
    const { code, stdout, stderr } = await run(['demo/scenarios.ts', '--monitor-port', String(port)]);

    expect(stdout, stderr).toContain('DEMO PASSED');
    expect(code).toBe(0);
    expect(stdout).not.toMatch(/^\s+FAIL\s/m);
    // Enforcement proven by the mock's own counters (T01–T03).
    expect(stdout).toContain('PASS  blocked credential read reached the mock server zero times');
    expect(stdout).toContain('PASS  blocked send_data reached the mock server zero times');
    // Delivery proven by the firewall's own monitor, correlated by request ID (T10).
    expect(stdout).toMatch(/PASS {2}monitor belongs to the firewall we launched \(pid \d+\)/);
    expect(stdout).toContain('PASS  event 2 has the request ID the client got back');
    expect(stdout).toContain('PASS  monitor stream contains no secret or argument values');
    // T11: the dummy secret never reaches the event log on stderr either.
    expect(stderr).not.toContain(DUMMY_SECRET);
  });

  it('reproduces "protecting 1 server, zero events": a monitor held by another process is detected, not trusted', async () => {
    // A real monitor in this test process holds the port, like a firewall started earlier.
    const port = await freePort();
    blocker = await startMonitor(
      { enabled: true, host: '127.0.0.1', port, maxEvents: 100 },
      { bus: createEventBus({ log: () => {} }), protectedServers: () => 1 },
    );

    const { code, stdout, stderr } = await run(['demo/scenarios.ts', '--monitor-port', String(port)]);

    // Enforcement is unaffected by the missing monitor…
    expect(stdout).toContain('PASS  blocked credential read reached the mock server zero times');
    // …the launched firewall says its events will not show up there…
    expect(stderr).toMatch(/already in use.*will NOT appear on that monitor/);
    // …and the demo refuses to count the other process's monitor as proof of delivery.
    expect(stdout).toContain(`not pid ${process.pid}`);
    expect(stdout).toContain('DEMO FAILED');
    expect(code).toBe(1);
  });

  it('T12: an invalid policy file makes the firewall exit non-zero (no allow-all fallback)', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'mcp-firewall-e2e-'));
    try {
      const bad = join(dir, 'firewall.yaml');
      writeFileSync(bad, 'server: { id: demo, command: node }\npolicy: { defaultDecision: MAYBE, allowEverything: true }\n');
      const { code, stderr } = await run(['src/index.ts', '--config', bad]);
      expect(code).not.toBe(0);
      expect(stderr).toContain('invalid firewall config');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('A9 / T14: docs state that only routed MCP calls are protected', () => {
    const readme = readFileSync(join(repoRoot, 'README.md'), 'utf8');
    expect(readme).toContain('direct MCP connections that bypass the proxy');
    expect(readme).toMatch(/built-in tools/);
    const setup = readFileSync(join(repoRoot, 'docs/SETUP.md'), 'utf8');
    expect(setup).toMatch(/not protected/i);
  });
});
