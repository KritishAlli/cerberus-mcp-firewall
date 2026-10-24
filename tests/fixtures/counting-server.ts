/**
 * OWNER: Aarav — TEST-ONLY downstream stdio MCP server for tests/proxy.test.ts.
 * Separate from Kritish's demo/mock-server.ts on purpose: proxy tests need
 * failure modes (hang, crash, tool errors) the demo server should not have.
 *
 * Usage: node --import tsx tests/fixtures/counting-server.ts [--counts-file <path>]
 *
 * Every tool except get_call_counts increments a per-tool received-call
 * counter as soon as it is invoked. With --counts-file, the counts JSON is
 * rewritten after every call (and once at startup), so tests can read it
 * without going through the proxy.
 *
 * DUMMY DATA ONLY. stdout is protocol-only; log to stderr.
 */
import { writeFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { McpServer } from '@modelcontextprotocol/server';
import { StdioServerTransport } from '@modelcontextprotocol/server/stdio';
import { z } from 'zod';

const DUMMY_SECRET = 'DUMMY-SECRET-DO-NOT-LEAK';

const { values } = parseArgs({ options: { 'counts-file': { type: 'string' } } });
const countsFile = values['counts-file'];
const counts: Record<string, number> = {};

function received(tool: string): void {
  counts[tool] = (counts[tool] ?? 0) + 1;
  if (countsFile) writeFileSync(countsFile, JSON.stringify(counts));
}

if (countsFile) writeFileSync(countsFile, JSON.stringify(counts));

const server = new McpServer({ name: 'counting-server', version: '0.0.0' });

server.registerTool(
  'echo',
  { description: 'Returns its text argument.', inputSchema: z.object({ text: z.string() }) },
  async ({ text }) => {
    received('echo');
    return { content: [{ type: 'text', text }] };
  },
);

server.registerTool(
  'read_file',
  { description: 'Pretends to read a file. Always returns a fake secret.', inputSchema: z.object({ path: z.string() }) },
  async () => {
    received('read_file');
    return { content: [{ type: 'text', text: DUMMY_SECRET }] };
  },
);

server.registerTool(
  'structured',
  {
    description: 'Returns structured content matching its outputSchema.',
    inputSchema: z.object({ n: z.number() }),
    outputSchema: z.object({ doubled: z.number() }),
  },
  async ({ n }) => {
    received('structured');
    const structuredContent = { doubled: n * 2 };
    return { content: [{ type: 'text', text: JSON.stringify(structuredContent) }], structuredContent };
  },
);

server.registerTool('tool_error', { description: 'Always reports a tool-level error.' }, async () => {
  received('tool_error');
  return { isError: true, content: [{ type: 'text', text: 'tool_error: deliberate failure' }] };
});

server.registerTool('hang', { description: 'Never responds.' }, () => {
  received('hang');
  return new Promise<never>(() => {});
});

server.registerTool('crash', { description: 'Exits the server process.' }, () => {
  received('crash');
  process.stderr.write('[counting-server] crash requested, exiting\n');
  process.exit(1);
});

server.registerTool('get_call_counts', { description: 'Returns received-call counts per tool (not counted).' }, async () => ({
  content: [{ type: 'text', text: JSON.stringify(counts) }],
}));

await server.connect(new StdioServerTransport());
process.stderr.write('[counting-server] ready\n');
