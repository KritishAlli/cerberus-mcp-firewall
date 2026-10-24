/**
 * OWNER: Kritish — end-to-end through the real proxy to the mock server (design doc §8, §10).
 * Uses stub events until the proxy lands, then the real pipeline.
 */
import { spawnSync } from 'node:child_process';
import { cp, mkdtemp, readFile, realpath, rm, stat, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import type { CallToolResult } from '@modelcontextprotocol/server';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { parse, stringify } from 'yaml';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');

describe('e2e / client → firewall → mock server', () => {
  it.todo('T01: safe read reaches mock server exactly once with correct result');
  it.todo('T02–T05: blocked calls reach mock server zero times (received-call counter)');
  it.todo('T10: /events SSE streams actual decisions; page updates without refresh');
  it.todo('T11: logs and SSE never contain the dummy secret value or raw sensitive arguments');
  it.todo('T12: invalid policy file → firewall process exits non-zero, no allow-all mode');
  it.todo('T13: full CLI → proxy → mock server run; blocked calls never reach upstream');
  it.todo('T14: direct MCP connection bypass is documented in README as a limitation');
  it.todo('/health returns { status: "ok", protectedServers: 1 } from live state');
});

// ---------------------------------------------------------------------------
// Sandbox mode: the real CLI with config/sandbox.yaml, the real filesystem server in
// Docker, against a temp copy of demo/project. Skipped when Docker or the image is
// missing (npm run sandbox:build), unless REQUIRE_DOCKER=1.
// ---------------------------------------------------------------------------

const SANDBOX_IMAGE = 'mcp-firewall-sandbox:dev';
const sandboxSkipReason = (() => {
  const version = spawnSync('docker', ['version', '--format', '{{.Server.Version}}'], { timeout: 5_000 });
  if (version.status !== 0) return 'Docker is not available';
  const image = spawnSync('docker', ['image', 'inspect', SANDBOX_IMAGE], { timeout: 5_000 });
  if (image.status !== 0) return `image ${SANDBOX_IMAGE} is not present locally (npm run sandbox:build)`;
  return undefined;
})();
const requireDocker = process.env.REQUIRE_DOCKER === '1';
if (sandboxSkipReason && !requireDocker) {
  process.stderr.write(`[e2e] skipping sandbox tests: ${sandboxSkipReason}\n`);
}

/** The schema forbids port 0, so ask the OS for a free one. */
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

interface Staged {
  applied: number;
  rejected: number;
  changes: { path: string; decision: 'ALLOW' | 'DENY'; ruleId: string }[];
}

describe.skipIf(sandboxSkipReason !== undefined && !requireDocker)('e2e / sandbox mode (real CLI + Docker)', () => {
  let dir: string;
  let project: string;
  let monitorUrl: string;
  let agent: Client;
  const stderr: string[] = [];

  const call = (name: string, args: Record<string, unknown>) =>
    agent.callTool({ name, arguments: args }) as Promise<CallToolResult>;
  const stagedOf = (r: CallToolResult) => r._meta?.['mcp-firewall/staged'] as Staged | undefined;
  const text = (r: CallToolResult) => r.content.map((c) => (c.type === 'text' ? c.text : '')).join('\n');

  beforeAll(async () => {
    if (sandboxSkipReason) throw new Error(`REQUIRE_DOCKER=1, but ${sandboxSkipReason}`);
    dir = await realpath(await mkdtemp(join(tmpdir(), 'mcp-firewall-e2e-sandbox-')));
    project = join(dir, 'project');
    await cp(join(repoRoot, 'demo/project'), project, { recursive: true });

    const port = await freePort();
    monitorUrl = `http://127.0.0.1:${port}`;
    const config = parse(await readFile(join(repoRoot, 'config/sandbox.yaml'), 'utf8'));
    config.server.sandbox.project = project;
    config.monitor = { ...config.monitor, port };
    const configPath = join(dir, 'sandbox.yaml');
    await writeFile(configPath, stringify(config));

    const transport = new StdioClientTransport({
      command: process.execPath,
      args: ['--import', 'tsx', 'src/index.ts', '--config', configPath],
      cwd: repoRoot,
      stderr: 'pipe',
    });
    transport.stderr?.on('data', (chunk: Buffer) => stderr.push(chunk.toString()));
    agent = new Client({ name: 'e2e-sandbox', version: '0.0.0' });
    await agent.connect(transport);
  }, 60_000);

  afterAll(async () => {
    await agent?.close().catch(() => {});
    if (dir) await rm(dir, { recursive: true, force: true });
  });

  it('diffs every allowed call: only approved changes land, the rest are reported and on the monitor', async () => {
    const before = {
      greet: await readFile(join(project, 'src/greet.js'), 'utf8'),
      pkg: await readFile(join(project, 'package.json'), 'utf8'),
    };
    const greet = "export const greet = (n) => `Hi, ${n}!`;\n";

    const readme = await call('read_text_file', { path: '/workspace/README.md' });
    expect(readme.isError).toBeFalsy();
    expect(stagedOf(readme)).toEqual({ applied: 0, rejected: 0, changes: [] });

    const env = await call('read_text_file', { path: '/workspace/.env' });
    expect(env.isError).toBe(true);
    expect(text(env)).toContain('BLOCKED (PROTECTED_PATH)');

    // Allowed path: lands exactly when the call says it was applied (reject-all stub
    // today, Winston's evaluateFileChanges later).
    const edit = await call('write_file', { path: '/workspace/src/greet.js', content: greet });
    const editStaged = stagedOf(edit)!;
    expect(editStaged.changes.map((c) => c.path)).toEqual(['src/greet.js']);
    const applied = editStaged.changes[0]!.decision === 'ALLOW';
    expect(await readFile(join(project, 'src/greet.js'), 'utf8')).toBe(applied ? greet : before.greet);

    // Persistence: npm lifecycle script. Never lands, whatever the evaluator.
    const pkg = await call('write_file', {
      path: '/workspace/package.json',
      content: '{"name":"demo","scripts":{"postinstall":"echo pwned"}}\n',
    });
    expect(stagedOf(pkg)).toMatchObject({ applied: 0, rejected: 1, changes: [{ path: 'package.json', decision: 'DENY' }] });
    expect(text(pkg)).toContain('[MCP Firewall] REJECTED FILE CHANGES');
    expect(await readFile(join(project, 'package.json'), 'utf8')).toBe(before.pkg);

    // Git hook: .git/ is excluded from staging and never applied.
    await call('create_directory', { path: '/workspace/.git/hooks' });
    await call('write_file', { path: '/workspace/.git/hooks/pre-commit', content: '#!/bin/sh\necho pwned\n' });
    await expect(stat(join(project, '.git/hooks/pre-commit'))).rejects.toThrow();

    // The monitor shows one line per diff, with paths and rule IDs only.
    const lines = await fileChangeLines(monitorUrl, 2);
    expect(lines[0]).toMatch(applied ? /^1 applied, 0 rejected$/ : /^0 applied, 1 rejected: src\/greet\.js \w+$/);
    expect(lines[1]).toMatch(/^0 applied, 1 rejected: package\.json \w+$/);
    expect(lines.join('\n')).not.toContain('pwned');
    expect(stderr.join('')).not.toContain('pwned');
  }, 60_000);
});

/** Replays /events until `count` filechanges frames arrived; returns their lines. */
async function fileChangeLines(url: string, count: number): Promise<string[]> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5_000);
  const lines: string[] = [];
  try {
    const res = await fetch(`${url}/events`, { signal: controller.signal });
    const reader = res.body!.pipeThrough(new TextDecoderStream()).getReader();
    let buffer = '';
    while (lines.length < count) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += value;
      let end: number;
      while ((end = buffer.indexOf('\n\n')) !== -1) {
        const frame = buffer.slice(0, end);
        buffer = buffer.slice(end + 2);
        if (!frame.includes('event: filechanges')) continue;
        const data = /^data: (.*)$/m.exec(frame)?.[1];
        if (data) lines.push((JSON.parse(data) as { line: string }).line);
      }
    }
  } catch {
    // Aborted: return what arrived; the assertions say what was missing.
  } finally {
    clearTimeout(timer);
    controller.abort();
  }
  return lines;
}
