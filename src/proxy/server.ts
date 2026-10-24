/**
 * OWNER: Aarav — the MCP server that Claude Code connects to (design doc §6.2, §6.6).
 *
 * SCAFFOLD STUB.
 *
 * Verified in the pinned SDK (@modelcontextprotocol/server@2.4.0):
 *   import { Server, McpServer } from '@modelcontextprotocol/server';
 *   import { StdioServerTransport } from '@modelcontextprotocol/server/stdio';
 * The low-level Server is likely the better fit: tools/list must re-expose the
 * downstream JSON Schemas unchanged, and McpServer expects its own schemas.
 *
 * TODO(Aarav): tools/list → upstream.listTools() (names/descriptions/schemas
 * preserved; descriptions are untrusted text), tools/call → handleToolCall.
 * stdout is protocol-only; diagnostics go to stderr.
 */
import type { ToolCallHandler } from './interceptor.js';
import type { UpstreamConnection } from './upstream.js';

export interface ProxyServerHandle {
  close(): Promise<void>;
}

export async function startProxyServer(
  _upstream: UpstreamConnection,
  _handleToolCall: ToolCallHandler,
): Promise<ProxyServerHandle> {
  throw new Error('startProxyServer: not implemented yet (Aarav)');
}
