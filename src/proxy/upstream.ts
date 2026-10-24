/**
 * OWNER: Aarav — stdio connection to the one downstream MCP server (design doc §6.1).
 *
 * Spawns config.command/args with a safe default environment (not our full
 * env, which may hold real credentials), completes the initialize handshake,
 * and re-emits the child's stderr on our stderr as diagnostics. The child's
 * stdout is the protocol pipe and never reaches ours.
 *
 * Once the connection closes it stays closed: every later call throws
 * UpstreamUnavailableError, which the interceptor turns into a fail-closed
 * DOWNSTREAM ERROR. There is no reconnect.
 */
import { createInterface } from 'node:readline';
import type { Readable } from 'node:stream';
import { Client } from '@modelcontextprotocol/client';
import { getDefaultEnvironment, StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import type { CallToolResult, Tool } from '@modelcontextprotocol/server';
import type { DownstreamServerConfig } from '../shared/contracts.js';

/** Cap on tools/list pages, against a server whose nextCursor never converges. */
const MAX_LIST_PAGES = 20;
const MAX_STDERR_LINE = 2_000;

export class UpstreamUnavailableError extends Error {
  override name = 'UpstreamUnavailableError';
  readonly code = 'UPSTREAM_UNAVAILABLE';
}

export interface UpstreamCallOptions {
  signal?: AbortSignal;
}

export interface UpstreamConnection {
  readonly serverId: string;
  /** False once the downstream connection has closed, for any reason. */
  readonly connected: boolean;
  listTools(): Promise<Tool[]>;
  callTool(toolName: string, args: Record<string, unknown>, options?: UpstreamCallOptions): Promise<CallToolResult>;
  close(): Promise<void>;
}

export interface ConnectUpstreamOptions {
  /** Called once when an established downstream connection closes (crash, exit, or close()). */
  onClose?: () => void;
}

export async function connectUpstream(
  server: DownstreamServerConfig,
  options: ConnectUpstreamOptions = {},
): Promise<UpstreamConnection> {
  const tag = `[downstream:${server.id}]`;
  const transport = new StdioClientTransport({
    command: server.command,
    args: server.args,
    ...(server.cwd === undefined ? {} : { cwd: server.cwd }),
    env: getDefaultEnvironment(),
    stderr: 'pipe',
  });
  pipeStderr(transport.stderr as Readable | null, tag);

  const client = new Client({ name: 'mcp-firewall', version: '0.1.0' }, { listMaxPages: MAX_LIST_PAGES });
  let connected = false;
  let established = false;
  let closeReported = false;
  client.onclose = () => {
    connected = false;
    // Before connect() resolves, a close is a connect failure and is reported by the throw below.
    if (!established || closeReported) return;
    closeReported = true;
    process.stderr.write(`[firewall] ${tag} connection closed\n`);
    options.onClose?.();
  };
  client.onerror = (err) => {
    process.stderr.write(`[firewall] ${tag} transport error: ${err.constructor.name}\n`);
  };

  try {
    await client.connect(transport, { timeout: server.timeoutMs });
  } catch (err) {
    await client.close().catch(() => {});
    // The cause can carry command lines or env details; report only a code.
    throw new UpstreamUnavailableError(
      `downstream MCP server "${server.id}" is unavailable (connect failed: ${errorCode(err)})`,
    );
  }
  connected = true;
  established = true;

  const requireConnected = (): void => {
    if (!connected) throw new UpstreamUnavailableError(`downstream MCP server "${server.id}" is not connected`);
  };

  return {
    serverId: server.id,
    get connected() {
      return connected;
    },
    async listTools() {
      requireConnected();
      // No cursor → the SDK walks every page, capped by listMaxPages.
      const { tools } = await client.listTools(undefined, { timeout: server.timeoutMs, cacheMode: 'refresh' });
      return tools;
    },
    async callTool(toolName, args, callOptions = {}) {
      requireConnected();
      return client.callTool(
        { name: toolName, arguments: args },
        {
          timeout: server.timeoutMs,
          maxTotalTimeout: server.timeoutMs,
          ...(callOptions.signal ? { signal: callOptions.signal } : {}),
        },
      );
    },
    async close() {
      connected = false;
      await client.close();
    },
  };
}

function pipeStderr(stderr: Readable | null, tag: string): void {
  if (!stderr) return;
  stderr.on('error', () => {});
  const lines = createInterface({ input: stderr, crlfDelay: Infinity });
  lines.on('line', (line) => {
    // Strip control characters so the child cannot forge or garble our log lines.
    const clean = line.replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, '').slice(0, MAX_STDERR_LINE);
    process.stderr.write(`${tag} ${clean}\n`);
  });
}

function errorCode(err: unknown): string {
  if (typeof err === 'object' && err !== null && 'code' in err) {
    const code = (err as { code: unknown }).code;
    if (typeof code === 'string' && /^[A-Z0-9_]{1,64}$/.test(code)) return code;
  }
  return err instanceof Error ? err.constructor.name : 'unknown';
}
