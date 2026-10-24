/**
 * OWNER: Aarav — enforcement path tests (design doc §6, §10).
 * Use createInterceptor with fake evaluate/publish/forward to count forwards.
 */
import { describe, it } from 'vitest';

describe('proxy / interceptor', () => {
  it.todo('T01: ALLOW → forward called exactly once, result returned unchanged');
  it.todo('T02: DENY → forward called zero times, MCP-compatible rejection returned');
  it.todo('T06: invalid / unknown request → no crash, no forward');
  it.todo('T09: downstream timeout or disconnect → clear client error, no bypass');
  it.todo('evaluate throws → DENY / EVALUATION_ERROR, forward called zero times');
  it.todo('publish throws → decision unchanged');
  it.todo('error strings never contain argument values or secrets');
});
