/**
 * OWNER: Aarav — stdio connection to the one downstream MCP server (design doc §6.1).
 *
 * SCAFFOLD STUB.
 *
 * Verified in the pinned SDK (@modelcontextprotocol/client@2.4.0):
 *   import { Client } from '@modelcontextprotocol/client';
 *   import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
 *   client.listTools(), client.callTool({ name, arguments })
 *
 * TODO(Aarav): spawn config.command/args, complete the initialize handshake,
 * capture the child's stderr as diagnostics, apply config.timeoutMs per call.
 */
import type { CallToolResult, Tool } from '@modelcontextprotocol/server';
import type { DownstreamServerConfig } from '../shared/contracts.js';

export interface UpstreamConnection {
  readonly serverId: string;
  listTools(): Promise<Tool[]>;
  callTool(toolName: string, args: Record<string, unknown>): Promise<CallToolResult>;
  close(): Promise<void>;
}

export async function connectUpstream(_server: DownstreamServerConfig): Promise<UpstreamConnection> {
  throw new Error('connectUpstream: not implemented yet (Aarav)');
}
