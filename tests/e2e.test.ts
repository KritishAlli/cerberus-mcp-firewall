/**
 * OWNER: Kritish — end-to-end through the real proxy to the mock server (design doc §8, §10).
 * Uses stub events until the proxy lands, then the real pipeline.
 */
import { describe, it } from 'vitest';

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
