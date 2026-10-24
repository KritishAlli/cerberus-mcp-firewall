/**
 * OWNER: Winston — pure evaluator unit tests (design doc §7, §10).
 * Target: at least 12 deterministic cases. Assert decision AND ruleId.
 * Use dummy fixture paths and destinations only.
 */
import { describe, it } from 'vitest';

describe('security / evaluateToolCall', () => {
  it.todo('T01: approved demo/read_project_file → ALLOW / APPROVED_TOOL');
  it.todo('T02: read of ~/.aws/credentials → DENY / PROTECTED_PATH');
  it.todo('T03: send_data to example-attacker.invalid → DENY / DENIED_DESTINATION');
  it.todo('T04: demo/delete_file → DENY / DENIED_TOOL or DESTRUCTIVE_ACTION');
  it.todo('T05: unknown sensitive tool → DENY / DEFAULT_DENY');
  it.todo('T06: missing, non-object, array and nested arguments → DENY / INVALID_ARGUMENTS, no throw');
  it.todo('T07: similarly named benign path (e.g. ".envrc", "notes/.env.example") → not PROTECTED_PATH');
  it.todo('T08: "../" traversal into a protected path → DENY / PROTECTED_PATH after normalization');
  it.todo('encoded / mixed-case / userinfo URLs to a denied host → DENY / DENIED_DESTINATION');
  it.todo('malformed URL on a destination tool → DENY');
  it.todo('path arrays and nested path arguments are all checked');
  it.todo('reason never contains argument values or secrets');
});
