# Proxy and enforcement decisions

Owner: Aarav (`src/proxy/*`, `src/index.ts`). These are the choices behind the enforcement path and why we made them. The design doc (§5, §6) is the source of truth. This file covers what the design left open.

## 1. Low-level `Server` over `McpServer`

`McpServer.registerTool` builds `tools/list` from the schemas registered with it (Zod / Standard Schema). The proxy has to re-expose the downstream server's **names, descriptions, input schemas and output schemas unchanged** (§6.2). Converting those schemas would be lossy and could drift. The low-level `Server` lets us register `tools/list` and `tools/call` by method string and return the downstream `Tool[]` exactly as received.

- Capabilities: `{ tools: {} }` only. No resources, prompts or `listChanged`.
- The downstream server's `instructions` are **not** forwarded. They are untrusted text that would otherwise go straight into the agent's context. Tool descriptions are passed through, because the agent needs them, but they are also untrusted. Nothing in a descriptor is ever used as policy input.
- Results of allowed calls are returned unchanged. We do not call `server.projectCallToolResult`, because the downstream server has already shaped its result for the wire.

## 2. DENY is a tool error, not a JSON-RPC error

A blocked call returns a normal `CallToolResult`:

```text
isError: true
content: [{ type: 'text', text: '[MCP Firewall] BLOCKED (<ruleId>): <reason>. The request was not sent to the tool server. [request <id>]' }]
_meta:   { 'mcp-firewall/decision': { decision, ruleId, reason, requestId } }
```

Why: the MCP spec says tool-execution failures should be reported in the result so the model can see them and adjust. A JSON-RPC error is meant for protocol failures, and clients often surface it as "the tool is broken". A tool error tells the agent, in the conversation, that the call was refused and why. The prefix (`BLOCKED_PREFIX`) and the `_meta` key (`FIREWALL_META_KEY`) are exported so tests, the demo and the monitor can match on them without parsing prose.

Downstream failures after an ALLOW use the same shape with the prefix `[MCP Firewall] DOWNSTREAM ERROR` and `downstreamError: 'timeout' | 'not_connected' | 'failed'` in `_meta`.

## 3. Evaluated args = forwarded args

The interceptor `structuredClone`s the incoming arguments, checks that the copy is plain JSON (plain objects, arrays, strings, finite numbers, booleans and null, nesting depth 64 or less), deep-freezes it, and passes **that same object** to both `evaluate` and `forward`.

- The caller can't change the args between evaluation and forwarding (no TOCTOU inside the proxy).
- The evaluator can't change what gets forwarded. A write to the frozen object throws, and if that error escapes the evaluator the call fails closed.
- The plain-JSON check exists because JSON serialization silently rewrites some values (`Map` → `{}`, `undefined` keys dropped, `NaN` → `null`, sparse arrays filled with nulls). Without it, the evaluator could approve one value while a different value went on the wire.

This does not cover what happens *after* the downstream server receives the args (symlinks, TOCTOU on the file system, hidden I/O). See the README limitations.

## 4. Fail-closed rules

Every path that isn't an explicit, schema-valid ALLOW ends in "not forwarded":

| Situation | Result |
| --- | --- |
| `arguments` is `null`, an array, a non-object, a non-plain object, or not plain JSON | DENY `INVALID_ARGUMENTS` (evaluator not called) |
| `structuredClone` throws (functions, symbols, throwing getters, revoked proxies) | DENY `INVALID_ARGUMENTS` |
| Tool name missing, not a string, empty or longer than 128 chars; context fails `ToolCallContextSchema` | DENY `INVALID_ARGUMENTS` |
| Evaluator throws | DENY `EVALUATION_ERROR` |
| Evaluator returns something that fails `PolicyDecisionSchema` (including a Promise) | DENY `EVALUATION_ERROR` |
| `publish` throws, or the event fails `FirewallEventSchema` | Decision unchanged; the failure is logged |
| Downstream timeout / disconnect / crash / any `forward` error | `DOWNSTREAM ERROR` result; never retried, never turned into a success |
| Downstream already closed | `connected` is false; every later forward throws `UpstreamUnavailableError` → `DOWNSTREAM ERROR`. DENY still returns BLOCKED. No reconnect. |

A missing `arguments` field becomes `{}`, because MCP allows a call with no arguments.

`forward` has exactly one call site, inside `if (prepared.ok && decision.decision === 'ALLOW')`.

Nothing puts an argument value or a downstream error *message* into a response, event or log: either one can echo secrets. Logs carry only the error class and code. Downstream error results use one of three fixed messages.

## 5. One event per call, at decision time

Exactly one `FirewallEvent` is published per `tools/call`, right after the decision and **before** forwarding. It has no downstream outcome.

- The monitor shows the decision immediately, even if the downstream server hangs for `timeoutMs`.
- "One call → one event" is easy to count in tests and the UI.
- `FirewallEvent` (frozen contract) has no outcome field, so a second event per call would need a contract change.

The summary is built from the sanitized tool name, at most 8 sanitized argument **key** names (each capped at 32 chars, with `+N more` after that), and the outcome. It never includes values, and it is truncated to `LIMITS.summary`. Example: `read_project_file args=[path,limit] → ALLOW APPROVED_TOOL`.

Downstream outcomes (timeouts, crashes) go to stderr and to the agent in the result. If the monitor needs them later, that needs a contract change agreed by all three of us.

## 6. Safe default environment for the child

The downstream server is spawned with `env: getDefaultEnvironment()` from the SDK: a short allowlist (`HOME`, `PATH`, `USER`, `SHELL`, `TERM`, `LOGNAME` on POSIX). It does **not** get the firewall's full environment, which on a developer laptop can hold real credentials (`AWS_*`, `GITHUB_TOKEN`, …). If a downstream server needs a specific variable, that should be added as an explicit config field, never inherited by default.

Other child-process choices:

- `stderr: 'pipe'`. Each line is re-emitted on our stderr as `[downstream:<id>] …`, with control characters stripped and lines capped at 2,000 chars. The child's stdout is the protocol pipe and never reaches ours.
- The connect timeout is `timeoutMs`. Each call uses `timeout` and `maxTotalTimeout` = `timeoutMs`, so progress notifications can't keep a call alive forever.
- `tools/list` walks pages through the SDK with `listMaxPages: 20`.
- A connect failure throws `UpstreamUnavailableError` with only the server id and an error code (e.g. `ENOENT`). There is no command line, env or cause chain in the message.

## 7. Shutdown

`src/index.ts` shuts down on agent disconnect, stdin end, `SIGINT` or `SIGTERM`. It closes the upstream, the proxy server and the monitor in parallel, waits at most 2 s, then exits 0. A downstream crash does **not** shut the proxy down: it keeps answering so that DENYs stay visible and allowed calls fail with a clear error.
