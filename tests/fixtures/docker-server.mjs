/**
 * OWNER: Aarav — TEST-ONLY MCP server run inside the Docker sandbox by
 * tests/upstream-docker.test.ts. Plain .mjs so it runs on stock node:22-slim:
 * the repo is mounted read-only at /server and packages resolve from
 * /server/node_modules.
 *
 * Tools report what the sandbox allowed instead of throwing, so the test can
 * assert on the text. stdout is protocol-only; log to stderr.
 */
import { writeFile } from 'node:fs/promises';
import { McpServer } from '@modelcontextprotocol/server';
import { StdioServerTransport } from '@modelcontextprotocol/server/stdio';
import { z } from 'zod';

const server = new McpServer({ name: 'docker-fixture', version: '0.0.0' });

server.registerTool('ping', { description: 'Returns pong.' }, async () => ({
  content: [{ type: 'text', text: 'pong' }],
}));

server.registerTool(
  'try_fetch',
  { description: 'Tries to fetch a URL; reports "reachable" or "blocked: <code>".', inputSchema: z.object({ url: z.string() }) },
  async ({ url }) => {
    try {
      await fetch(url, { signal: AbortSignal.timeout(3_000) });
      return { content: [{ type: 'text', text: 'reachable' }] };
    } catch (err) {
      return { content: [{ type: 'text', text: `blocked: ${err?.cause?.code ?? err?.name ?? 'error'}` }] };
    }
  },
);

server.registerTool(
  'try_write',
  { description: 'Tries to write a file; reports "written" or "failed: <code>".', inputSchema: z.object({ path: z.string() }) },
  async ({ path }) => {
    try {
      await writeFile(path, 'written from the sandbox');
      return { content: [{ type: 'text', text: 'written' }] };
    } catch (err) {
      return { content: [{ type: 'text', text: `failed: ${err?.code ?? 'error'}` }] };
    }
  },
);

await server.connect(new StdioServerTransport());
// --ignore-stdin-eof: keep running after the firewall goes away, like a buggy or hostile
// server would, so a SIGKILLed firewall leaves an orphaned container behind.
if (process.argv.includes('--ignore-stdin-eof')) setInterval(() => {}, 60_000);
process.stderr.write('[docker-fixture] ready\n');
