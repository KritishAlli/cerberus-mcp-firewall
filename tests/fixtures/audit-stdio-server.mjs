/**
 * Test-only stdio MCP server for tests/proxy-audit.test.ts.
 *   echo  → returns its text
 *   crash → exits the process (a downstream crash / disconnect)
 */
import { McpServer } from '@modelcontextprotocol/server';
import { StdioServerTransport } from '@modelcontextprotocol/server/stdio';
import { z } from 'zod';

const server = new McpServer({ name: 'audit-stdio-fixture', version: '0.0.0' });
server.registerTool('echo', { description: 'Returns its text.', inputSchema: { text: z.string() } }, async ({ text }) => ({
  content: [{ type: 'text', text }],
}));
server.registerTool('crash', { description: 'Exits the server process.' }, async () => {
  process.exit(3);
});
await server.connect(new StdioServerTransport());
