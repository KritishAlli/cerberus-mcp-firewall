/**
 * OWNER: Kritish — event bus and redaction (design doc §8).
 *
 * SCAFFOLD STUB: writes each event as one JSON line to stderr.
 * stdout is reserved for the MCP protocol — never write to it.
 *
 * TODO(Kritish):
 *   - bounded in-memory ring buffer (config.monitor.maxEvents)
 *   - subscriber API for the SSE monitor
 *   - redaction pass before buffering / streaming / optional JSONL
 *   - counters (inspected / allowed / denied) from real events only
 */
import { FirewallEventSchema, type PublishEvent } from '../shared/contracts.js';

export const publishEvent: PublishEvent = (event) => {
  // Contract: must never throw and must never change the allow/deny result.
  try {
    const parsed = FirewallEventSchema.safeParse(event);
    if (!parsed.success) {
      process.stderr.write('[firewall] dropped malformed event\n');
      return;
    }
    process.stderr.write(`${JSON.stringify(parsed.data)}\n`);
  } catch {
    // Swallow: observability failures must not affect enforcement.
  }
};
