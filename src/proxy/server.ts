/**
 * OWNER: Aarav — the MCP server that Claude Code connects to (design doc §6.2, §6.6).
 *
 * Uses the low-level Server, not McpServer: McpServer builds tools/list from
 * its own registered schemas, while the proxy must re-expose the downstream
 * names, descriptions and JSON Schemas unchanged. Descriptions are untrusted
 * text; they are passed through but never used as policy input.
 *
 * The downstream server's `instructions` are NOT forwarded: they are untrusted
 * text that would otherwise land in the agent's context.
 *
 * Only tools are proxied. Resources, prompts and list_changed are not offered.
 * stdout is protocol-only; diagnostics go to stderr.
 */
import { Server, type Transport } from '@modelcontextprotocol/server';
import { StdioServerTransport } from '@modelcontextprotocol/server/stdio';
import type { ToolCallHandler } from './interceptor.js';
import type { UpstreamConnection } from './upstream.js';

export interface ProxyServerHandle {
  close(): Promise<void>;
}

export interface ProxyServerOptions {
  /** Defaults to a StdioServerTransport on this process's stdin/stdout. Tests pass an InMemoryTransport. */
  transport?: Transport;
  /** Called when the agent side disconnects. */
  onClose?: () => void;
}

export async function startProxyServer(
  upstream: UpstreamConnection,
  handleToolCall: ToolCallHandler,
  options: ProxyServerOptions = {},
): Promise<ProxyServerHandle> {
  const server = new Server({ name: 'mcp-firewall', version: '0.1.0' }, { capabilities: { tools: {} } });

  server.setRequestHandler('tools/list', async () => {
    try {
      return { tools: await upstream.listTools() };
    } catch (err) {
      process.stderr.write(`[firewall] tools/list failed: ${err instanceof Error ? err.constructor.name : typeof err}\n`);
      throw new Error('MCP Firewall: the tool server is unavailable');
    }
  });

  server.setRequestHandler('tools/call', (request, ctx) =>
    handleToolCall(request.params.name, request.params.arguments, { signal: ctx.mcpReq.signal }),
  );

  server.onclose = () => options.onClose?.();
  server.onerror = (err) => {
    process.stderr.write(`[firewall] agent connection error: ${err.constructor.name}\n`);
  };

  await server.connect(options.transport ?? new StdioServerTransport());
  return { close: () => server.close() };
}
