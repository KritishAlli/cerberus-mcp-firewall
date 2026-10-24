/**
 * OWNER: Kritish — controlled downstream MCP server for demos and tests (design doc §8).
 *
 * A stdio MCP server exposing harmless mock tools:
 *   read_project_file    (safe; serves an in-memory fake project, never the real disk)
 *   read_sensitive_file  (dummy credential path; returns a fake value)
 *   send_data            (simulated external destination; sends nothing)
 *   delete_file          (simulated; deletes nothing)
 *   get_call_counts      (diagnostic; not counted)
 *
 * Every mock tool increments a received-call counter BEFORE doing anything
 * else, as proof that denied calls reach this server zero times (§10). The
 * counts are exposed three ways:
 *   - in process:   createMockServer().counts()           (tests)
 *   - over MCP:     the `get_call_counts` tool            (direct connections;
 *                   through the firewall it is unapproved, so default-deny)
 *   - on disk:      --counts-file <path> or MOCK_SERVER_COUNTS_FILE
 *                   rewritten atomically after every call (demo, e2e)
 *
 * stdout is protocol-only; all diagnostics go to stderr.
 */
import { realpathSync, renameSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { McpServer, type CallToolResult } from '@modelcontextprotocol/server';
import { StdioServerTransport } from '@modelcontextprotocol/server/stdio';
import { z } from 'zod';

export const MOCK_SERVER_NAME = 'mcp-firewall-demo';

/**
 * DUMMY secret returned by read_sensitive_file. Not a real credential.
 * Tests assert this exact string never appears in firewall logs or SSE (T11).
 */
export const DUMMY_SECRET = 'AKIA-DUMMY-DO-NOT-USE-0000000000';

export const MOCK_TOOL_NAMES = ['read_project_file', 'read_sensitive_file', 'send_data', 'delete_file'] as const;
export type MockToolName = (typeof MOCK_TOOL_NAMES)[number];
export type CallCounts = Record<MockToolName, number>;

/** In-memory fake project served by read_project_file. Keys are normalized relative paths. */
const PROJECT_FILES: Readonly<Record<string, string>> = {
  'README.md': '# Demo project\n\nA harmless sample repository used by the MCP Firewall demo.\n',
  'src/index.ts': "export function greet(name: string): string {\n  return `Hello, ${name}!`;\n}\n",
  'package.json': '{\n  "name": "demo-project",\n  "version": "1.0.0"\n}\n',
};

export interface MockServerOptions {
  /** If set, counts are written here (atomically) after every received call. */
  countsFile?: string;
  /** Diagnostics sink. Defaults to stderr; never stdout. */
  log?: (line: string) => void;
}

export interface MockServer {
  readonly server: McpServer;
  /** Snapshot of received-call counts. */
  counts(): CallCounts;
}

function text(value: string, isError = false): CallToolResult {
  return isError ? { content: [{ type: 'text', text: value }], isError } : { content: [{ type: 'text', text: value }] };
}

/** "./src//index.ts" → "src/index.ts". Anything escaping the project root yields undefined. */
function normalizeProjectPath(path: string): string | undefined {
  const parts: string[] = [];
  for (const part of path.replaceAll('\\', '/').split('/')) {
    if (part === '' || part === '.') continue;
    if (part === '..') {
      if (parts.length === 0) return undefined;
      parts.pop();
    } else {
      parts.push(part);
    }
  }
  return parts.join('/');
}

function hostOf(url: string): string {
  try {
    return new URL(url).hostname || '<none>';
  } catch {
    return '<malformed>';
  }
}

export function createMockServer(options: MockServerOptions = {}): MockServer {
  const log = options.log ?? ((line: string) => process.stderr.write(`[mock-server] ${line}\n`));
  const counts = Object.fromEntries(MOCK_TOOL_NAMES.map((name) => [name, 0])) as CallCounts;

  function writeCounts(): void {
    if (!options.countsFile) return;
    const tmp = `${options.countsFile}.${process.pid}.tmp`;
    try {
      writeFileSync(tmp, `${JSON.stringify(counts)}\n`);
      renameSync(tmp, options.countsFile);
    } catch (err) {
      log(`failed to write counts file: ${(err as Error).message}`);
    }
  }

  /** Record receipt first, so even a call whose handler fails is counted. Logs tool names only, never arguments. */
  function received(tool: MockToolName): void {
    counts[tool] += 1;
    log(`received ${tool} (#${counts[tool]})`);
    writeCounts();
  }

  const server = new McpServer({ name: MOCK_SERVER_NAME, version: '0.1.0' });

  server.registerTool(
    'read_project_file',
    {
      description: 'Read a file from the demo project.',
      inputSchema: z.object({ path: z.string().describe('Project-relative file path') }),
      annotations: { readOnlyHint: true },
    },
    async ({ path }) => {
      received('read_project_file');
      const key = normalizeProjectPath(path);
      const content = key === undefined ? undefined : PROJECT_FILES[key];
      return content === undefined ? text(`File not found in demo project: ${path}`, true) : text(content);
    },
  );

  server.registerTool(
    'read_sensitive_file',
    {
      description: 'Read a credential file (DEMO: returns a dummy value, never touches disk).',
      inputSchema: z.object({ path: z.string().describe('Path to the credential file') }),
      annotations: { readOnlyHint: true },
    },
    async () => {
      received('read_sensitive_file');
      return text(`[default]\naws_access_key_id = ${DUMMY_SECRET}\n`);
    },
  );

  server.registerTool(
    'send_data',
    {
      description: 'Send data to a URL (DEMO: simulated, nothing leaves this process).',
      inputSchema: z.object({
        url: z.string().describe('Destination URL'),
        data: z.string().describe('Payload to send'),
      }),
      annotations: { openWorldHint: true },
    },
    async ({ url, data }) => {
      received('send_data');
      return text(`Simulated send of ${Buffer.byteLength(data)} bytes to ${hostOf(url)} (nothing was sent).`);
    },
  );

  server.registerTool(
    'delete_file',
    {
      description: 'Delete a file (DEMO: simulated, nothing is deleted).',
      inputSchema: z.object({ path: z.string().describe('Path of the file to delete') }),
      annotations: { destructiveHint: true },
    },
    async () => {
      received('delete_file');
      return text('Simulated delete (nothing was deleted).');
    },
  );

  server.registerTool(
    'get_call_counts',
    {
      description: 'Diagnostic: how many times each mock tool has been received by this server.',
      annotations: { readOnlyHint: true },
    },
    async () => {
      const snapshot = { ...counts };
      return { content: [{ type: 'text', text: JSON.stringify(snapshot) }], structuredContent: snapshot };
    },
  );

  writeCounts();
  return { server, counts: () => ({ ...counts }) };
}

function parseCountsFile(argv: readonly string[]): string | undefined {
  const i = argv.indexOf('--counts-file');
  const value = i >= 0 ? argv[i + 1] : process.env.MOCK_SERVER_COUNTS_FILE;
  return value ? resolve(value) : undefined;
}

async function main(): Promise<void> {
  const countsFile = parseCountsFile(process.argv.slice(2));
  const { server } = createMockServer(countsFile ? { countsFile } : {});
  await server.connect(new StdioServerTransport());
  process.stderr.write(`[mock-server] ready on stdio${countsFile ? `, counts → ${countsFile}` : ''}\n`);
}

function isEntryPoint(): boolean {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return realpathSync(entry) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (isEntryPoint()) {
  main().catch((err: unknown) => {
    process.stderr.write(`[mock-server] fatal: ${(err as Error).message}\n`);
    process.exit(1);
  });
}
