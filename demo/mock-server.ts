/**
 * OWNER: Kritish — controlled downstream MCP server for demos and tests (design doc §8).
 *
 * SCAFFOLD STUB.
 *
 * TODO(Kritish): a stdio MCP server (McpServer + StdioServerTransport from
 * @modelcontextprotocol/server) exposing harmless mock tools:
 *   read_project_file    (safe)
 *   read_sensitive_file  (dummy credential path; returns a fake value)
 *   send_data            (simulated external destination; sends nothing)
 *   delete_file          (simulated; deletes nothing)
 * and a received-call counter per tool, exposed for tests and the demo
 * (e.g. a `get_call_counts` tool or a counts file), as proof that denied
 * calls reach the server zero times.
 *
 * stdout is protocol-only; log to stderr.
 */
process.stderr.write('[mock-server] not implemented yet\n');
process.exit(1);
