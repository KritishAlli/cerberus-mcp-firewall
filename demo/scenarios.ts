/**
 * OWNER: Kritish — repeatable benign / blocked scenarios (`npm run demo`, design doc §8, §13).
 *
 * SCAFFOLD STUB.
 *
 * TODO(Kritish): a deterministic MCP client that launches the firewall
 * (src/index.ts) and, through it:
 *   1. makes a normal allowed call          → succeeds, ALLOW event
 *   2. attempts the blocked credential read → DENY / PROTECTED_PATH
 *   3. attempts send_data to the attacker   → DENY / DENIED_DESTINATION
 *   4. prints the mock server's received-call counts (blocked = 0)
 *   5. repeats the normal call              → still succeeds
 * with the monitor open at http://127.0.0.1:3000.
 */
process.stderr.write('[demo] not implemented yet\n');
process.exit(1);
