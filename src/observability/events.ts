/**
 * OWNER: Kritish — event bus and redaction (design doc §8).
 *
 * Everything else in the monitor reads from here:
 *   - a bounded in-memory ring of recent events (config.monitor.maxEvents, default 100)
 *   - subscribe() for the SSE endpoint
 *   - counters (inspected / allowed / denied) from real, valid events only
 *   - redaction before anything is buffered, streamed or written to stderr
 *
 * stdout is reserved for the MCP protocol — never write to it.
 */
import { FirewallEventSchema, LIMITS, type FirewallEvent, type PublishEvent } from '../shared/contracts.js';

/** Matches MonitorConfigSchema's default. */
export const DEFAULT_MAX_EVENTS = 100;
export const REDACTED = '[REDACTED]';

export interface EventCounts {
  inspected: number;
  allowed: number;
  denied: number;
}

export type EventListener = (event: FirewallEvent) => void;

export interface EventBus {
  /** Must never throw and must never influence the allow/deny result. */
  publish: PublishEvent;
  /** Redacted events currently in the ring, oldest first. */
  recent(): FirewallEvent[];
  counts(): EventCounts;
  /** Called with each new redacted event. Returns an unsubscribe function. */
  subscribe(listener: EventListener): () => void;
  /** Resize the ring (e.g. from config.monitor.maxEvents), dropping the oldest events if needed. */
  setMaxEvents(maxEvents: number): void;
}

export interface EventBusOptions {
  maxEvents?: number;
  /** Literal values that must never appear in output (e.g. a test's dummy secret). */
  knownSecrets?: readonly string[];
  /** Diagnostics sink (one line, no trailing newline). Defaults to stderr. Never stdout. */
  log?: (line: string) => void;
}

// ---------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------

/**
 * Shapes of credentials that must never leave the process. The interceptor already
 * keeps argument values out of events; this is the second line of defence.
 */
const SECRET_PATTERNS: readonly RegExp[] = [
  // PEM private key blocks.
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g,
  // AWS access key IDs (and the demo's AKIA-DUMMY-… lookalike).
  /\b(?:AKIA|ASIA)[A-Z0-9-]{12,}/g,
  // Common provider token prefixes.
  /\b(?:sk|pk|rk)-[A-Za-z0-9_-]{16,}/g,
  /\bgh[pousr]_[A-Za-z0-9]{20,}/g,
  /\bxox[abprs]-[A-Za-z0-9-]{10,}/g,
  // JWTs.
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/g,
  // Screaming-kebab markers such as DUMMY-SECRET-DO-NOT-LEAK.
  /\b(?:[A-Z0-9]+-)*(?:SECRET|TOKEN|PASSWORD|CREDENTIALS?)(?:-[A-Z0-9]+)+\b/g,
  // Long opaque runs mixing letters and digits (base64 / hex keys). UUIDs are
  // hyphenated and long snake_case tool names have no digits, so both stay intact.
  /\b(?=[A-Za-z0-9+/_]*\d)(?=[A-Za-z0-9+/_]*[A-Za-z])[A-Za-z0-9+/_]{40,}={0,2}/g,
];

/** `password=…`, `api_key: …`, `Authorization: Bearer …`: keep the name, drop the value. */
const SECRET_ASSIGNMENT =
  /\b((?:[A-Za-z0-9_-]*(?:secret|token|passw(?:or)?d|api[_-]?key|access[_-]?key|private[_-]?key|credential)s?|authorization)["']?\s*[:=]\s*)(?:bearer\s+|basic\s+)?(["']?)[^\s"',;&}]+\2/gi;
const BEARER = /\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}/gi;

export function redactText(text: string, knownSecrets: readonly string[] = []): string {
  let out = text;
  for (const secret of knownSecrets) {
    if (secret.length > 0) out = out.split(secret).join(REDACTED);
  }
  out = out.replace(SECRET_ASSIGNMENT, `$1${REDACTED}`);
  out = out.replace(BEARER, `$1 ${REDACTED}`);
  for (const pattern of SECRET_PATTERNS) out = out.replace(pattern, REDACTED);
  return out;
}

function bounded(text: string, max: number): string {
  return text.length <= max ? text : `${text.slice(0, max - 1)}…`;
}

/** Redacts every free-text field, then re-applies the contract's length limits. */
export function redactEvent(event: FirewallEvent, knownSecrets: readonly string[] = []): FirewallEvent {
  const r = (text: string, max: number): string => bounded(redactText(text, knownSecrets), max);
  return {
    ...event,
    requestId: r(event.requestId, LIMITS.identifier),
    serverId: r(event.serverId, LIMITS.identifier),
    toolName: r(event.toolName, LIMITS.identifier),
    reason: r(event.reason, LIMITS.reason),
    summary: r(event.summary, LIMITS.summary),
  };
}

// ---------------------------------------------------------------------------
// Bus
// ---------------------------------------------------------------------------

function validMaxEvents(n: number): number {
  return Number.isInteger(n) && n >= 1 ? n : DEFAULT_MAX_EVENTS;
}

export function createEventBus(options: EventBusOptions = {}): EventBus {
  const knownSecrets = options.knownSecrets ?? [];
  const log = options.log ?? ((line: string) => process.stderr.write(`${line}\n`));
  let maxEvents = validMaxEvents(options.maxEvents ?? DEFAULT_MAX_EVENTS);
  const ring: FirewallEvent[] = [];
  const listeners = new Set<EventListener>();
  const counts: EventCounts = { inspected: 0, allowed: 0, denied: 0 };

  const safeLog = (line: string): void => {
    try {
      log(line);
    } catch {
      // Swallow: observability failures must not affect enforcement.
    }
  };

  const publish: PublishEvent = (event) => {
    try {
      const parsed = FirewallEventSchema.safeParse(event);
      if (!parsed.success) {
        safeLog('[firewall] dropped malformed event');
        return;
      }
      const redacted = FirewallEventSchema.safeParse(redactEvent(parsed.data, knownSecrets));
      if (!redacted.success) {
        safeLog('[firewall] dropped event that failed validation after redaction');
        return;
      }
      const stored = Object.freeze(redacted.data);

      ring.push(stored);
      if (ring.length > maxEvents) ring.splice(0, ring.length - maxEvents);
      counts.inspected += 1;
      if (stored.decision === 'ALLOW') counts.allowed += 1;
      else counts.denied += 1;

      safeLog(JSON.stringify(stored));
      // Snapshot so listeners can unsubscribe while being notified.
      for (const listener of [...listeners]) {
        try {
          listener(stored);
        } catch {
          // A broken subscriber must not affect the others or the caller.
        }
      }
    } catch {
      // Swallow: observability failures must not affect enforcement.
    }
  };

  return {
    publish,
    recent: () => [...ring],
    counts: () => ({ ...counts }),
    subscribe(listener) {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
    setMaxEvents(n) {
      maxEvents = validMaxEvents(n);
      if (ring.length > maxEvents) ring.splice(0, ring.length - maxEvents);
    },
  };
}

/** The process-wide bus: the proxy publishes to it, the monitor reads from it. */
export const eventBus = createEventBus();

export const publishEvent: PublishEvent = eventBus.publish;
