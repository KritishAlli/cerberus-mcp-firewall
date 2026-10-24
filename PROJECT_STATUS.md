# Project status: proxy and enforcement (Aarav)

Merged to `main` (PR #2). Rationale for each choice: [`docs/DECISIONS.md`](docs/DECISIONS.md).

## Done

- **`src/proxy/interceptor.ts`**: `createInterceptor(deps)` does validate → clone + deep-freeze → evaluate (schema-checked, fail closed) → publish exactly one event → forward only on ALLOW. It returns a recognizable BLOCKED tool error on DENY and a fixed-message DOWNSTREAM ERROR when the downstream fails.
- **`src/proxy/upstream.ts`**: `connectUpstream(config, { onClose? })` spawns the server over stdio with a safe default env and re-emits its stderr with a prefix. It has a connect timeout, per-call `timeout`/`maxTotalTimeout`/`signal`, paginated `listTools` (20-page cap), a `connected` getter, and `UpstreamUnavailableError` once closed. No reconnect.
- **`src/proxy/server.ts`**: `startProxyServer(upstream, handler, { transport?, onClose? })` is a low-level `Server`. `tools/list` passes through unchanged, `tools/call` goes to the interceptor with the cancellation signal, and downstream `instructions` are not forwarded.
- **`src/index.ts`**: passes the signal through, and shuts down cleanly on agent disconnect, stdin end, SIGINT or SIGTERM (2 s cap). A downstream crash keeps the proxy up and fails closed.
- **`tests/fixtures/counting-server.ts`**: test-only stdio server (`echo`, `read_file`, `structured`, `tool_error`, `hang`, `crash`, `get_call_counts`) with an optional `--counts-file`.
- **`tests/proxy.test.ts`**: 66 tests in tests/proxy.test.ts; full suite 90 passing (incl. 10 shared contract and 12 security tests), 8 todo (all in `tests/e2e.test.ts`). Coverage:
  - unit tests (T01, T02, T06, T09, T11, fail-closed evaluator and publish, arg mutation, summary bounds, signal)
  - integration through the real stdio fixture (listing identical to direct, T01/T02 counts, structured results and tool errors, unknown tools, hang timeout, crash)
  - CLI smoke test of `src/index.ts`. With the real evaluator, its approved `fixture/echo` call now takes the forwarded (ALLOW) branch.
  - CLI run against `demo/mock-server.ts` with the shipped `config/firewall.yaml` policy and the real evaluator:
    - listing parity with a direct connection
    - T01: `read_project_file` is ALLOWed, forwarded once, and its result is identical to a direct call
    - T02–T04: PROTECTED_PATH, DENIED_DESTINATION and DENIED_TOOL are each BLOCKED with a count of 0

## Claude Code setup (verified)

**"Claude Code can connect" (design §6): verified** by Aarav in manual Claude Code sessions on 2026-10-23 (macOS), with `demo/mock-server.ts` as the downstream. The first session ran with the deny-all evaluator stub. The ALLOW re-check ran with Winston's real evaluator (PR #4) and the shipped policy.

| Check | Result |
| --- | --- |
| Connection | ✔ `/mcp` shows `mcp-firewall-dev` connected |
| Tool listing | ✔ `read_project_file`, `read_sensitive_file`, `send_data`, `delete_file` listed through the firewall |
| BLOCKED path | ✔ with the deny-all stub, `read_project_file` shows `[MCP Firewall] BLOCKED (DEFAULT_DENY)` as a tool error |
| Downstream counts | ✔ all 0 (or file absent): nothing reached the mock |
| Shutdown | ✔ after `/exit`, `pgrep -fl "counting-server\|src/index.ts"` returns nothing |
| ALLOW path (T01) | ✔ with the real evaluator, `read_project_file` on `README.md` returns the demo README as a normal result. The counts file shows `read_project_file: 1` with the other three tools at 0, and the MCP log has one `ALLOW APPROVED_TOOL` event. **T01 works end to end through a real Claude Code client.** |

The exact command that worked. It was run from the repo root, so `$PWD` is the repo:

```bash
claude mcp add --scope local mcp-firewall-dev -- "$PWD/node_modules/.bin/tsx" "$PWD/src/index.ts" --config "$HOME/.config/mcp-firewall-dev/firewall.yaml"
```

- **Local scope ties the registration to the folder it was added from**, here `~/Documents/dev/mcp-firewall`. `claude mcp list` / `/mcp` in any other folder won't show it. Use `--scope user` to make it available everywhere.
- The command expands to absolute paths for `tsx`, `src/index.ts` and the config. See [DECISIONS §8](docs/DECISIONS.md) for why it uses the repo's `tsx` rather than `npx`.
- `~/.config/mcp-firewall-dev/firewall.yaml` is a local dev config, not in the repo. It points at `demo/mock-server.ts` with `--counts-file /tmp/mcp-firewall-counts.json`, and its policy is identical to `config/firewall.yaml`.
- **For the README (Kritish):** the same command with the shipped config is `claude mcp add --scope local mcp-firewall -- "$PWD/node_modules/.bin/tsx" "$PWD/src/index.ts" --config "$PWD/config/firewall.yaml"`, run from the repo root.
- **Claude Code's own classifier can refuse a call before it reaches the firewall.** In the session, Claude Code's auto-mode classifier refused a Claude-driven `read_sensitive_file` call itself, so it never reached the firewall and isn't a firewall result. **The firewall's DENY must be shown with the direct-client demo (`npm run demo`)**, which always sends the call. Don't rely on Claude choosing to make it.
- **Where the firewall's stderr goes (macOS):** `~/Library/Caches/claude-cli-nodejs/<project-path-with-dashes>/mcp-logs-<server-name>/<timestamp>.jsonl`. Claude Code tags each stderr chunk as `"error": "Server stderr: …"`. That is its label for stderr, not a failure. Our event JSON lines and `[firewall] …` diagnostics appear there. The log also records the session `cwd`, the 30 s connection timeout, and the SIGINT sent at shutdown.
- **README is stale (Kritish):** the "Status: scaffold … The proxy, policy engine, monitor and demo are stubs" line is out of date. The proxy, mock server and demo are all on `main` now.

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

- ~~`src/security/evaluator.ts` is the deny-all stub~~: Winston's real evaluator landed on `main` in PR #4 (`40ea8e4`). With the shipped policy it returns ALLOW / PROTECTED_PATH / DENIED_DESTINATION / DENIED_TOOL for the four demo calls, consistent with design §7.
- ~~`demo/mock-server.ts` is a stub~~: landed in PR #3 (`6a7f51d`).
- **Release gate (§10): all three commands pass** on this machine: `npm run typecheck`, `npm test` (90 passed, 8 todo) and `npm run demo` (DEMO PASSED, all 12 checks).
- **Open policy issues for Winston** (found in a read-only review; no proxy change needed):
  - case-variant protected paths are allowed on macOS
  - relative-path traversal is not resolved
  - `file://` paths and trailing slashes slip past
  - one precedence edge case vs §7

  They don't affect the scripted demo, whose mock never touches the disk, but they are real holes for any downstream that does read files.
- **Still open (Kritish):**
  - the monitor is a stub
  - `tests/e2e.test.ts` is 8 todos
  - the README status line and Claude Code TODO are stale
  - the demo detects blocks by parsing prose rather than `_meta`
- **`.gitignore` on `main` is Kritish's version.** It ignores `.env` / `.env.*`, so a dummy `.env` used to demo a blocked read has to be force-added (`git add -f`) or created at demo time. `MOCK_SERVER_COUNTS_FILE` does not reach the mock through the firewall (safe default env, DECISIONS §6); use `--counts-file`, as the demo does.

## Limitations

- Tools only: no resources, prompts, sampling or elicitation passthrough.
- No `notifications/tools/list_changed`. The tool list is fetched from downstream on each `tools/list`, but the agent isn't told when it changes.
- No reconnect. After a downstream crash, allowed calls fail closed until the firewall restarts.
- One downstream server, stdio only (design §2).
- A cancellation from the agent is passed to the downstream request via `signal`. Whether the downstream tool actually stops is up to that server.
- A timeout means "may or may not have run". The firewall can't tell, and the error message says so.

## Next steps

1. ~~Merge `aarav/proxy`~~: done (PR #2). ~~Exercise the ALLOW branch end to end~~: done. It is covered by the CLI smoke test, the mock integration test and `npm run demo`.
2. ~~Re-run the manual Claude Code check with the real evaluator~~: done. T01 verified end to end in Claude Code.
3. Winston: address the policy issues above (path case-folding on macOS, relative-path handling, `file://` and trailing-slash normalization), then re-run `npm run check`. The mock integration test should keep passing unchanged.
4. Kritish:
   - implement the monitor and `tests/e2e.test.ts`
   - move "Claude Code setup (verified)" into the README and fix the stale status line
   - switch the demo's block detection to `_meta['mcp-firewall/decision']`
5. Optional, after acceptance tests: forward `list_changed`, and a shutdown hook for the monitor once it holds real resources.
