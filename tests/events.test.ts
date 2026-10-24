/**
 * OWNER: Kritish — event bus, counters and redaction (design doc §8, T11).
 */
import { describe, expect, it } from 'vitest';
import { createEventBus, describeFileChanges, redactText, REDACTED } from '../src/observability/events.js';
import type { FileChangeEvent, FirewallEvent } from '../src/shared/contracts.js';

const MOCK_SECRET = 'AKIA-DUMMY-DO-NOT-USE-0000000000';
const FIXTURE_SECRET = 'DUMMY-SECRET-DO-NOT-LEAK';

let seq = 0;
function event(overrides: Partial<FirewallEvent> = {}): FirewallEvent {
  seq += 1;
  return {
    timestamp: new Date().toISOString(),
    requestId: `req-${seq}`,
    serverId: 'demo',
    toolName: 'read_project_file',
    decision: 'ALLOW',
    ruleId: 'APPROVED_TOOL',
    reason: 'Tool is on the approved list',
    summary: 'read_project_file args=[path] → ALLOW APPROVED_TOOL',
    ...overrides,
  };
}

function fileChanges(overrides: Partial<FileChangeEvent> = {}): FileChangeEvent {
  seq += 1;
  return {
    timestamp: new Date().toISOString(),
    requestId: `req-${seq}`,
    serverId: 'demo',
    toolName: 'write_file',
    applied: 2,
    rejected: 1,
    changes: [
      { path: 'src/greet.js', decision: 'ALLOW', ruleId: 'APPROVED_TOOL' },
      { path: 'src/index.js', decision: 'ALLOW', ruleId: 'APPROVED_TOOL' },
      { path: 'package.json', decision: 'DENY', ruleId: 'PERSISTENCE_PATH' },
    ],
    ...overrides,
  };
}

function quietBus(maxEvents?: number) {
  const logs: string[] = [];
  const bus = createEventBus({ maxEvents, log: (line) => logs.push(line) });
  return { bus, logs };
}

describe('event bus', () => {
  it('keeps only the most recent maxEvents events, oldest first', () => {
    const { bus } = quietBus(3);
    const ids = Array.from({ length: 5 }, () => event()).map((e) => {
      bus.publish(e);
      return e.requestId;
    });
    expect(bus.recent().map((e) => e.requestId)).toEqual(ids.slice(2));
  });

  it('defaults to 100 events and can be resized', () => {
    const { bus } = quietBus();
    for (let i = 0; i < 120; i++) bus.publish(event());
    expect(bus.recent()).toHaveLength(100);
    bus.setMaxEvents(10);
    expect(bus.recent()).toHaveLength(10);
  });

  it('counts inspected / allowed / denied from valid events only', () => {
    const { bus, logs } = quietBus();
    bus.publish(event());
    bus.publish(event({ decision: 'DENY', ruleId: 'DENIED_TOOL' }));
    bus.publish(event({ decision: 'DENY', ruleId: 'DEFAULT_DENY' }));
    bus.publish({ nonsense: true } as unknown as FirewallEvent);
    expect(bus.counts()).toEqual({ inspected: 3, allowed: 1, denied: 2, writesBlocked: 0 });
    expect(bus.recent()).toHaveLength(3);
    expect(logs).toContain('[firewall] dropped malformed event');
  });

  it('counters are lifetime totals, not limited by the ring size', () => {
    const { bus } = quietBus(2);
    for (let i = 0; i < 5; i++) bus.publish(event());
    expect(bus.counts().inspected).toBe(5);
  });

  it('notifies subscribers until they unsubscribe', () => {
    const { bus } = quietBus();
    const seen: string[] = [];
    const unsubscribe = bus.subscribe((e) => seen.push(e.requestId));
    const first = event();
    bus.publish(first);
    unsubscribe();
    bus.publish(event());
    expect(seen).toEqual([first.requestId]);
  });

  it('never throws, even when a subscriber or the log sink throws', () => {
    const bus = createEventBus({
      log: () => {
        throw new Error('log down');
      },
    });
    const seen: string[] = [];
    bus.subscribe(() => {
      throw new Error('subscriber down');
    });
    bus.subscribe((e) => seen.push(e.requestId));
    const e = event();
    expect(() => bus.publish(e)).not.toThrow();
    expect(() => bus.publish(null as unknown as FirewallEvent)).not.toThrow();
    expect(seen).toEqual([e.requestId]);
    expect(bus.counts().inspected).toBe(1);
  });

  it('stored events cannot be mutated by readers', () => {
    const { bus } = quietBus();
    bus.publish(event());
    const [stored] = bus.recent();
    expect(Object.isFrozen(stored)).toBe(true);
  });
});

describe('redaction (T11)', () => {
  it('the dummy secrets never reach the buffer, subscribers or logs', () => {
    const { bus, logs } = quietBus();
    const streamed: FirewallEvent[] = [];
    bus.subscribe((e) => streamed.push(e));
    bus.publish(event({ summary: `read_sensitive_file leaked ${MOCK_SECRET}` }));
    bus.publish(event({ reason: `token=${FIXTURE_SECRET}`, decision: 'DENY', ruleId: 'PROTECTED_PATH' }));
    const output = JSON.stringify([bus.recent(), streamed, logs]);
    expect(output).not.toContain(MOCK_SECRET);
    expect(output).not.toContain(FIXTURE_SECRET);
    expect(output).toContain(REDACTED);
  });

  it('redacts configured known secrets verbatim', () => {
    const bus = createEventBus({ knownSecrets: ['hunter2'], log: () => {} });
    bus.publish(event({ summary: 'value hunter2 appeared' }));
    expect(bus.recent()[0]?.summary).toBe(`value ${REDACTED} appeared`);
  });

  it.each([
    ['password=hunter2', `password=${REDACTED}`],
    ['Authorization: Bearer abc.def.ghi-123456', `Authorization: ${REDACTED}`],
    ['api_key: "s3cr3t"', `api_key: ${REDACTED}`],
    ['ghp_abcdefghijklmnopqrstuvwxyz0123', REDACTED],
    ['-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----', REDACTED],
  ])('redacts %j', (input, expected) => {
    expect(redactText(input)).toBe(expected);
  });

  it('leaves ordinary summaries, UUIDs and long tool names alone', () => {
    const ordinary = [
      'read_project_file args=[path,limit] → ALLOW APPROVED_TOOL',
      'Protected path ~/.aws/credentials',
      'req 3f2b6c1e-8d4a-4b8e-9c1f-2a7d5e6f8a90',
      'a_really_long_snake_case_tool_name_without_any_digits_at_all',
    ];
    for (const text of ordinary) expect(redactText(text)).toBe(text);
  });

  it('keeps fields within contract limits after redaction', () => {
    const { bus } = quietBus();
    bus.publish(event({ summary: 'password=x '.repeat(18).trim() }));
    const [stored] = bus.recent();
    expect(stored?.summary.length).toBeLessThanOrEqual(200);
    expect(stored?.summary).not.toMatch(/password=x\b/);
  });
});

describe('file-change events', () => {
  it('formats counts and rejected paths with their rule IDs', () => {
    expect(describeFileChanges(fileChanges())).toBe('2 applied, 1 rejected: package.json PERSISTENCE_PATH');
  });

  it('formats an all-applied diff without a path list', () => {
    const e = fileChanges({
      applied: 1,
      rejected: 0,
      changes: [{ path: 'src/greet.js', decision: 'ALLOW', ruleId: 'APPROVED_TOOL' }],
    });
    expect(describeFileChanges(e)).toBe('1 applied, 0 rejected');
  });

  it('says how many rejections were not listed', () => {
    const e = fileChanges({
      applied: 0,
      rejected: 3,
      changes: [
        { path: '.git/hooks/pre-commit', decision: 'DENY', ruleId: 'PERSISTENCE_PATH' },
        { path: 'run.sh', decision: 'DENY', ruleId: 'EXECUTABLE_DENIED' },
      ],
    });
    expect(describeFileChanges(e)).toBe(
      '0 applied, 3 rejected: .git/hooks/pre-commit PERSISTENCE_PATH, run.sh EXECUTABLE_DENIED, +1 more',
    );
  });

  it('keeps its own ring and subscribers, and leaves call counters alone', () => {
    const { bus } = quietBus(2);
    const seen: string[] = [];
    const unsubscribe = bus.subscribeFileChanges((e) => seen.push(e.requestId));
    const sent = [fileChanges(), fileChanges(), fileChanges()];
    for (const e of sent) bus.publishFileChanges(e);
    unsubscribe();
    bus.publishFileChanges(fileChanges());

    expect(seen).toEqual(sent.map((e) => e.requestId));
    expect(bus.recentFileChanges().map((e) => e.requestId)).toHaveLength(2);
    expect(bus.recent()).toEqual([]);
    expect(bus.counts()).toEqual({ inspected: 0, allowed: 0, denied: 0, writesBlocked: 0 });
    bus.setMaxEvents(1);
    expect(bus.recentFileChanges()).toHaveLength(1);
  });

  it('drops malformed events and events whose entries outnumber the totals', () => {
    const { bus, logs } = quietBus();
    bus.publishFileChanges({ nonsense: true } as unknown as FileChangeEvent);
    // A contents field is not part of the contract, so strict parsing rejects it.
    bus.publishFileChanges({ ...fileChanges(), text: 'file body' } as unknown as FileChangeEvent);
    bus.publishFileChanges(fileChanges({ rejected: 0 }));
    bus.publishFileChanges(fileChanges({ applied: 1 }));
    expect(bus.recentFileChanges()).toEqual([]);
    expect(logs.filter((l) => l === '[firewall] dropped malformed file-change event')).toHaveLength(4);
  });

  it('redacts secrets in paths and keeps them within the path limit', () => {
    const { bus, logs } = quietBus();
    const streamed: FileChangeEvent[] = [];
    bus.subscribeFileChanges((e) => streamed.push(e));
    bus.publishFileChanges(
      fileChanges({
        applied: 0,
        rejected: 2,
        changes: [
          { path: `notes/${MOCK_SECRET}.txt`, decision: 'DENY', ruleId: 'WRITE_NOT_ALLOWED' },
          // 196 chars, but redaction lengthens it past the 200-char path limit.
          { path: `${'a/'.repeat(93)}password=x`, decision: 'DENY', ruleId: 'WRITE_NOT_ALLOWED' },
        ],
      }),
    );
    const output = JSON.stringify([bus.recentFileChanges(), streamed, logs]);
    expect(output).not.toContain(MOCK_SECRET);
    expect(output).not.toMatch(/password=x\b/);
    for (const c of bus.recentFileChanges()[0]!.changes) expect(c.path.length).toBeLessThanOrEqual(200);
  });

  it('never throws, and stored events are frozen', () => {
    const bus = createEventBus({
      log: () => {
        throw new Error('log down');
      },
    });
    bus.subscribeFileChanges(() => {
      throw new Error('subscriber down');
    });
    expect(() => bus.publishFileChanges(fileChanges())).not.toThrow();
    expect(() => bus.publishFileChanges(null as unknown as FileChangeEvent)).not.toThrow();
    const [stored] = bus.recentFileChanges();
    expect(Object.isFrozen(stored)).toBe(true);
    expect(Object.isFrozen(stored!.changes)).toBe(true);
    expect(Object.isFrozen(stored!.changes[0])).toBe(true);
  });
});
