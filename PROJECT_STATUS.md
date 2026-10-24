# Project status: proxy and enforcement (Aarav)

Branch: `aarav/proxy`. Rationale for each choice: [`docs/DECISIONS.md`](docs/DECISIONS.md).

## Done

- **`src/proxy/interceptor.ts`**: `createInterceptor(deps)` does validate → clone + deep-freeze → evaluate (schema-checked, fail closed) → publish exactly one event → forward only on ALLOW. It returns a recognizable BLOCKED tool error on DENY and a fixed-message DOWNSTREAM ERROR when the downstream fails.
- **`src/proxy/upstream.ts`**: `connectUpstream(config, { onClose? })` spawns the server over stdio with a safe default env and re-emits its stderr with a prefix. It has a connect timeout, per-call `timeout`/`maxTotalTimeout`/`signal`, paginated `listTools` (20-page cap), a `connected` getter, and `UpstreamUnavailableError` once closed. No reconnect.
- **`src/proxy/server.ts`**: `startProxyServer(upstream, handler, { transport?, onClose? })` is a low-level `Server`. `tools/list` passes through unchanged, `tools/call` goes to the interceptor with the cancellation signal, and downstream `instructions` are not forwarded.
- **`src/index.ts`**: passes the signal through, and shuts down cleanly on agent disconnect, stdin end, SIGINT or SIGTERM (2 s cap). A downstream crash keeps the proxy up and fails closed.
- **`tests/fixtures/counting-server.ts`**: test-only stdio server (`echo`, `read_file`, `structured`, `tool_error`, `hang`, `crash`, `get_call_counts`) with an optional `--counts-file`.
- **`tests/proxy.test.ts`**: 62 tests in tests/proxy.test.ts; full suite 72 passing (incl. 10 shared contract tests), 20 todo in teammates' files. Coverage:
  - unit tests (T01, T02, T06, T09, T11, fail-closed evaluator and publish, arg mutation, summary bounds, signal)
  - integration through the real stdio fixture (listing identical to direct, T01/T02 counts, structured results and tool errors, unknown tools, hang timeout, crash)
  - CLI smoke test of `src/index.ts`

## Interfaces teammates should know about

From `src/proxy/interceptor.ts`:

| Export | Use |
| --- | --- |
| `BLOCKED_PREFIX` = `'[MCP Firewall] BLOCKED'` | Every DENY result's text starts with `` `${BLOCKED_PREFIX} (<ruleId>): ` ``. Match on this in e2e and demo instead of parsing prose. |
| `DOWNSTREAM_ERROR_PREFIX` = `'[MCP Firewall] DOWNSTREAM ERROR'` | ALLOWed call whose downstream timed out, disconnected or failed. |
| `FIREWALL_META_KEY` = `'mcp-firewall/decision'` | `result._meta[FIREWALL_META_KEY]` = `{ decision, ruleId, reason, requestId, downstreamError? }`. Present on BLOCKED and DOWNSTREAM ERROR results only. Allowed results are returned untouched. |
| `ToolCallHandler` | `(toolName: unknown, rawArgs: unknown, options?: { signal?: AbortSignal }) => Promise<CallToolResult>`. The third param is **optional**. |
| `InterceptorDeps.forward` | `(toolName, args, { signal? })`. `args` is the deep-frozen object the evaluator saw. |

- **Winston:** `evaluateToolCall` receives `ctx.arguments` deep-frozen. Writing to it throws, and if that error escapes, the call is denied with `EVALUATION_ERROR`. Return values are validated with `PolicyDecisionSchema`: anything invalid (wrong ruleId, empty or over-long reason, extra keys, a Promise) is a DENY. `reason` is shown to the agent and the monitor, so it must stay value-free.
- **Kritish:** `publishEvent` is called exactly once per `tools/call`, at decision time, before forwarding, with an event already validated against `FirewallEventSchema`. No second event carries the downstream outcome. `summary` looks like `read_project_file args=[path,limit] → ALLOW APPROVED_TOOL` (key names only, never values). For e2e counts, `tests/fixtures/counting-server.ts --counts-file` shows the pattern, but the demo should keep using your own mock.

## Blockers

- **`demo/mock-server.ts` (Kritish) is a stub that exits 1**, so `npm start` with the shipped `config/firewall.yaml` fails at connect with `downstream MCP server "demo" is unavailable`. Proxy tests use the separate fixture and don't depend on it.
- **`src/security/evaluator.ts` (Winston) is the deny-all stub.** Through the real CLI, every call is BLOCKED today. The CLI smoke test checks "count goes up only if the response was not BLOCKED", which holds for both the stub and a real evaluator, but only the BLOCKED branch actually runs until Winston merges. The ALLOW path is covered by the integration tests, which use a test-only allowlist evaluator.

## Limitations

- Tools only: no resources, prompts, sampling or elicitation passthrough.
- No `notifications/tools/list_changed`. The tool list is fetched from downstream on each `tools/list`, but the agent isn't told when it changes.
- No reconnect. After a downstream crash, allowed calls fail closed until the firewall restarts.
- One downstream server, stdio only (design §2).
- A cancellation from the agent is passed to the downstream request via `signal`. Whether the downstream tool actually stops is up to that server.
- A timeout means "may or may not have run". The firewall can't tell, and the error message says so.

## Next steps

1. Merge `aarav/proxy` once reviewed, so Kritish's e2e and demo can import the real proxy.
2. Re-run the CLI smoke test after Winston's evaluator lands, to exercise the ALLOW branch end to end.
3. With Kritish: confirm the e2e/demo use `BLOCKED_PREFIX` and `FIREWALL_META_KEY`, and verify the Claude Code MCP config snippet against the real binary.
4. Optional, after acceptance tests: forward `list_changed`, and a shutdown hook for the monitor once it holds real resources.
