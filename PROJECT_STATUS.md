# Project status: proxy and enforcement (Aarav)

Merged to `main` (PRs #2, #7, #9, #10, #11). In progress on `aarav/docker-upstream`: Docker launch mode in `src/proxy/upstream.ts` (not yet merged). Rationale for each choice: [`docs/DECISIONS.md`](docs/DECISIONS.md).

## Done

- **`src/proxy/interceptor.ts`**: `createInterceptor(deps)` does validate → clone + deep-freeze → evaluate (schema-checked, fail closed) → publish exactly one event → forward only on ALLOW. It returns a recognizable BLOCKED tool error on DENY and a fixed-message DOWNSTREAM ERROR when the downstream fails.
- **`src/proxy/upstream.ts`**: `connectUpstream(config, { onClose? })` spawns the server over stdio with a safe default env and re-emits its stderr with a prefix. It has a connect timeout, per-call `timeout`/`maxTotalTimeout`/`signal`, paginated `listTools` (20-page cap), a `connected` getter, and `UpstreamUnavailableError` once closed. No reconnect.
  - **Docker launch mode** (on `aarav/docker-upstream`): `connectUpstream(server, { launch })` takes an exported, Zod-validated `UpstreamLaunch`. It is either `{ mode: 'local', command, args, env?, cwd? }` (the old behavior, built by `localLaunch(server)`) or `{ mode: 'docker', image, command, args, workspaceDir, serverDir?, env?, user?, memory?, pidsLimit? }`.
  - Docker mode runs the plan's locked-down container: `--network none --read-only --cap-drop ALL --security-opt no-new-privileges`, host `uid:gid`, pids 128, 512m, tmpfs `/tmp`, staging rw at `/workspace`, server code ro at `/server`, and only explicit `-e` vars. `buildDockerArgs(launch)` builds the argv. It is exported, unit-tested and never uses a shell.
  - Preflight runs `docker version`, then `docker image inspect`. If either fails it throws `SandboxUnavailableError` and refuses to start. It never pulls and never falls back to local mode.
  - The container is removed with `docker rm -f` on close, on a downstream close, on process exit, and on SIGINT/SIGTERM. Container stderr goes to our stderr as `[upstream:<id>] …`.
  - `upstream.launch` / `describeLaunch()` report `{ mode, image?, containerName?, sandboxed }` for the monitor and `/health`. Not wired in yet.
  - `src/index.ts` now passes `launch: localLaunch(config.server)` explicitly. No new config keys; behavior is unchanged.
  - See [DECISIONS §11](docs/DECISIONS.md).
- **`tests/upstream-docker.test.ts`**: 29 unit tests that need no Docker: the exact argv and its order, defaults, every rejection case, env passthrough only when explicit, preflight failures that never spawn, no pull, and container removal on close. There are also 3 integration tests (real `node:22-slim` container: tools through the proxy, no network, writes only to `/workspace` and `/tmp`). They are **skipped on this machine because Docker isn't installed, so they have never been run**. Fixture: `tests/fixtures/docker-server.mjs`.
- **`src/proxy/server.ts`**: `startProxyServer(upstream, handler, { transport?, onClose? })` is a low-level `Server`. `tools/list` passes through unchanged, `tools/call` goes to the interceptor with the cancellation signal, and downstream `instructions` are not forwarded.
- **`src/index.ts`**: passes the signal through, and shuts down cleanly on agent disconnect, stdin end, SIGINT or SIGTERM (2 s cap), closing the upstream, proxy and monitor. A downstream crash keeps the proxy up and fails closed. Kritish's PR #6 added one line wiring `/health` to live state: `monitor?.setProtectedServers(() => (upstream.connected ? 1 : 0))`. Reviewed: correct, and the optional chaining keeps enforcement independent of the monitor.
- **`tests/fixtures/counting-server.ts`**: test-only stdio server (`echo`, `read_file`, `structured`, `tool_error`, `hang`, `crash`, `get_call_counts`) with an optional `--counts-file`.
- **`src/proxy/staging.ts`** (staged writes, not yet wired into the interceptor): `createStagingArea({ projectRoot, stagingParent?, excludes?, extraExcludes?, maxFileBytes })` makes a `mkdtemp` staging dir (under `os.tmpdir()` by default, refused inside the project). The `StagingArea` it returns has:
  - `sync()`: mirrors the project into staging minus excludes (`.git/`, `node_modules/`, `.env`, `.env.*` and any extras). Symlinks are recreated, never followed. Returns the pre-call staging manifest and the project manifest.
  - `diff(before)`: rescans staging and returns `FileChange[]` (add / modify / delete / mode / symlink / special), sorted by path. `text` is set only for UTF-8 files without NUL of at most `maxFileBytes`.
  - `apply(changes, decisions, projectAtSync)`: writes ALLOWed changes via temp file + rename. It skips a path with WRITE_CONFLICT if the project changed since sync. Symlink and special changes and excluded paths are never applied. A staged file that changed after `diff()` aborts the apply before anything is written.
  - `revert(paths)`: restores those paths in staging from the project.

  Also exported: `snapshot(root)`, `resolveInRoot(root, rel)` (the single path-safety check) and `StagingLock` (async mutex for the interceptor). Every error is thrown to the caller, with no paths or contents in messages. Node built-ins only. See [DECISIONS §10](docs/DECISIONS.md).
- **`tests/staging.test.ts`**: 24 tests against real temp dirs: excludes, symlinks and hardlinks, text rules, path escapes, atomic apply, conflicts, defense in depth, revert, ordering and the lock.
- **`tests/proxy.test.ts`**: 67 tests in tests/proxy.test.ts; full suite 186 passing (67 proxy, 28 contract, 14 security, 16 events, 8 monitor, 24 staging, 29 upstream-docker), 3 skipped (Docker integration), 8 todo (all in `tests/e2e.test.ts`). Coverage:
  - unit tests (T01, T02, T06, T09, T11, fail-closed evaluator and publish, arg mutation, summary bounds, signal)
  - integration through the real stdio fixture (listing identical to direct, T01/T02 counts, structured results and tool errors, unknown tools, hang timeout, crash)
  - CLI smoke test of `src/index.ts`. With the real evaluator, its approved `fixture/echo` call now takes the forwarded (ALLOW) branch.
  - CLI run against `demo/mock-server.ts` with the shipped `config/firewall.yaml` policy and the real evaluator:
    - listing parity with a direct connection
    - T01: `read_project_file` is ALLOWed, forwarded once, and its result is identical to a direct call
    - T02–T04: PROTECTED_PATH, DENIED_DESTINATION and DENIED_TOOL are each BLOCKED with a count of 0
  - vertical slice (T10): the real CLI with its monitor on a free port. One allowed and one denied call, then `GET /events` replays exactly those two events (decision, ruleId, matching `requestId`), `counts` is `{inspected: 2, allowed: 1, denied: 1}`, `/health` is `{status: ok, protectedServers: 1}`, and no argument values or the mock's secret appear in the stream (T11)

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
| Live monitor (T10) | ✔ verified on 2026-10-23 in a real Claude Code session. `read_project_file` on `README.md` showed up at `http://127.0.0.1:3000` as ALLOW / APPROVED_TOOL without refreshing, and the counters updated. |

- **Monitor note:** the dev config at `~/.config/mcp-firewall-dev/firewall.yaml` must have `monitor.enabled: true` (an old copy had it `false`). A Claude Code session and `npm run demo -- --hold` both default to port 3000, and only one monitor can hold the port at a time. Close Claude Code before running the demo with `--hold`, or set a different port in that file, e.g. `monitor: { enabled: true, port: 3001 }`.

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
- **README is stale (Kritish):** the "Status: scaffold … The proxy, policy engine, monitor and demo are stubs" line is out of date. The proxy, evaluator, mock server, demo and monitor are all on `main` now.

## Vertical slice (proxy → evaluator → event bus → monitor SSE): verified

Verified on 2026-10-23 with `npm run demo -- --hold` on `main` at `df3c8b5`, using the shipped `config/firewall.yaml`:

- **`/health`**: `{"status":"ok","protectedServers":1}` (HTTP 200), read from live upstream state.
- **`/events`**: replayed the demo's four decisions in order, followed by `ready {replayed: 4}`. They were ALLOW APPROVED_TOOL, DENY PROTECTED_PATH, DENY DENIED_DESTINATION and ALLOW APPROVED_TOOL (the repeated read), with counts `{inspected: 4, allowed: 2, denied: 2}`. The demo never calls `delete_file`, so no DENIED_TOOL event appears there. DENIED_TOOL is covered by the mock integration test.
- **T11**: the SSE output contains none of `credentials`, `~/.aws`, `example-attacker`, `collect`, `README.md`, `stolen`, `aws_access_key_id` or `AKIA-DUMMY`. Events carry argument key names only.
- **Shutdown**: SIGINT to the demo stopped the demo, firewall and mock, and freed port 3000, with no leftover processes.
- **Port collision**: a second firewall started with the shipped config while the first held port 3000. It logged `monitor failed to start; enforcement continues: … EADDRINUSE …`, kept enforcing, returned `BLOCKED (PROTECTED_PATH)` for a protected read, and forwarded an approved read normally. Fail-safe works as §6.6 requires.
  - **Its events reach only its own stderr.** The monitor on 3000 belongs to the first instance, so the browser shows only that instance's events and its `/health`. That is easy to misread as "both sessions are monitored".

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
- **Release gate (§10): all three commands pass** on this machine: `npm run typecheck`, `npm test` (186 passed, 3 skipped without Docker, 8 todo) and `npm run demo` (DEMO PASSED, all 12 checks).
- **Open policy issues for Winston** (found in a read-only review; no proxy change needed):
  - case-variant protected paths are allowed on macOS
  - relative-path traversal is not resolved
  - `file://` paths and trailing slashes slip past
  - one precedence edge case vs §7

  They don't affect the scripted demo, whose mock never touches the disk, but they are real holes for any downstream that does read files.
- **Still open (Kritish):**
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
   - implement `tests/e2e.test.ts`
   - move "Claude Code setup (verified)" into the README and fix the stale status line
   - switch the demo's block detection to `_meta['mcp-firewall/decision']`
   - **integration:** have the config loader map `server.sandbox` onto `UpstreamLaunch` (exported from `src/proxy/upstream.ts`, with TSDoc on every field) and pass it as `connectUpstream(config.server, { launch })` in `src/index.ts`. Docker mode is selected only that way.
5. ~~Shutdown hook for the monitor~~: already in place. `src/index.ts` closes it on shutdown, and port 3000 is freed after SIGINT.
6. **Staged writes:**
   - ~~Contract PR~~: merged (PR #10). See [DECISIONS §9](docs/DECISIONS.md).
   - ~~`src/proxy/staging.ts`~~: merged (PR #11).
   - ~~Docker launch mode in upstream~~: built on `aarav/docker-upstream`. Its integration tests still need a run on a machine with Docker and `node:22-slim`.
   - **Next: interceptor integration.** Take the `StagingLock`, then sync, forward, and diff after every allowed call (including timeout and error). Then `evaluateFileChanges` (the stub until Winston's lands), apply/revert, the result note, `_meta['mcp-firewall/staged']` and the `FileChangeEvent`. Fail closed on any staging error.
7. Optional, after acceptance tests: forward `list_changed`. Consider logging a clearer warning when the monitor port is taken, e.g. "events from this instance will not appear in the browser", and logging only the error code instead of the full `EADDRINUSE` object and stack.
