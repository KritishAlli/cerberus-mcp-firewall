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

## 8. Claude Code launches the firewall via the repo's absolute `tsx`, not `npx`

The registered command is `<repo>/node_modules/.bin/tsx <repo>/src/index.ts --config <abs config>`, with every path absolute. The verified form is `claude mcp add --scope local mcp-firewall-dev -- "$PWD/node_modules/.bin/tsx" "$PWD/src/index.ts" --config "$HOME/.config/mcp-firewall-dev/firewall.yaml"`, run from the repo root. The shell expands `$PWD` and `$HOME` before Claude Code stores the command.

- Claude Code launches stdio servers from the **session's working directory**, which is whichever project you started `claude` in. Its MCP log records that `cwd` for every server event.
- `npx tsx` looks for `tsx` in the `node_modules/.bin` of that directory's project. From the firewall repo itself that works. From any other project it either finds a different `tsx` (global or the project's own) or fetches an unpinned one from the registry. Fetching adds network time against Claude Code's 30 s connection timeout (the timeout is in its MCP log; the fetch time was not measured).
- `<repo>/node_modules/.bin/tsx` is the version from `package-lock.json`, installed by `npm ci`. It gives the same result from any working directory and needs no network.
- A relative `src/index.ts`, or a relative `--config`, would also resolve against the session's working directory. `src/index.ts` calls `resolve(values.config)`, so the config path must be absolute too. Paths *inside* the config (`server.cwd`) are resolved relative to the config file by the loader, and the default config is found via `import.meta.url`.
- Registration scope is separate from path resolution. `--scope local` stores the server for the folder `claude mcp add` was run in, so it only appears in sessions started there. Absolute paths make the command correct in *any* scope.

## 9. Staged writes: sandboxed downstream, diff after each call, apply only approved changes

Decision (contract on `contract/staged-writes`): in sandbox mode the downstream server runs in a Docker container against a **staging copy** of the project, not the project itself. After every allowed call the proxy diffs the staging copy against the project, runs each change through `EvaluateFileChanges`, and applies only the approved ones. Denied changes are discarded and reported in one `FileChangeEvent` (paths and rule IDs only, never contents).

Why: argument screening (§3, §4) only sees what the agent *asked* for. A malicious or compromised server can ignore its arguments and write anywhere it can reach: shell rc files, git hooks, CI config, new executables, files with secrets in them. Nothing in a `tools/call` reveals that. Checking the resulting changes, instead of the request, catches writes the arguments never mentioned.

Tradeoffs:

- **Docker shares the host kernel.** The container is a strong boundary against ordinary file writes, not against a kernel or container-runtime exploit.
- **Network tools don't work in sandbox mode.** The container runs with no network (`--network none`), so a server that needs to fetch or send data can't be sandboxed this way.
- **Small projects only.** Copying and diffing the whole project on every call is slow and disk-heavy for large trees. `staging.maxFileBytes` and `staging.maxChangesPerCall` bound the work per call, not the project size.
- `policy.staging` is optional in the schema so existing configs keep loading, but sandbox mode refuses to start without it. A missing section never means "allow all writes".

## 10. Staging dir outside the project; revert from the real project

`src/proxy/staging.ts` implements the copy, diff and apply half of §9.

**Location.** The staging dir is a fresh `fs.mkdtemp` directory under `os.tmpdir()` by default (overridable). Creation fails if the parent is inside the protected project. A staging copy inside the project would show up in its own scans, could be picked up by the user's tools (git, editors, watchers) as project files, and would put server-written content one rename away from the real tree. Roots are resolved with `realpath` first (macOS `/var` → `/private/var`), so the containment check can't be fooled by a symlinked temp dir.

**Revert from the real project, not from a backup.** A rejected path in staging is restored by copying it again from the real project, or by removing it if the project doesn't have it. Staging is meant to be "the project minus excludes" at the start of every call, and the project is the source of truth for that, so a separate pre-call backup would only be a second copy to keep in sync. If the user edited the file in the meantime, staging picks up their version, which is what the next call should see anyway. `sync()` uses the same rule for the whole tree, so a missed revert is also corrected at the next call.

**The server is assumed hostile and still running.** It may change staging between `diff()` and `apply()`. So:

- Walks use `lstat` and never descend into symlinks. Directory reads check that the path has no symlinked component.
- Files are opened with `O_NOFOLLOW | O_NONBLOCK`, and the `dev`/`ino` of the open file must match the `lstat` result.
- `apply()` re-reads every approved file and checks it against the size and SHA-256 that `diff()` recorded. Only then does it write anything, so the project only ever gets content the policy actually saw.
- Writes into the project refuse paths whose parent is not a real directory.
- Symlink and special changes are never applied, even if a decision says ALLOW.

Residual risk: Node has no `openat`, so a symlink swapped into a *parent* directory between the check and the open is not fully excluded. Inside Docker (§9) the server only sees `/workspace`, and absolute link targets point into the container, not the host.

**Conflicts.** Every write or delete re-reads the project path just before changing it and compares type, size, mode and SHA-256 to the manifest taken at `sync()`. On any difference it skips that path with WRITE_CONFLICT and leaves the user's edit alone. Writes go to a temp file in the same directory, then `rename`, so a reader never sees a half-written file. Permission bits other than the exec bit are kept from the existing file (0644 for new files), and setuid/setgid/sticky bits are never set.

**Errors.** Nothing is swallowed. Every unexpected error is thrown to the caller, which must fail closed (apply nothing). Error messages carry no paths or contents. A file name that the contract's path schema can't represent (for example one containing a backslash) makes `diff()` throw rather than report it, and the next `sync()` removes it.

## 11. Docker launch mode for the downstream server

`connectUpstream` takes an `UpstreamLaunch`: `local` (the original child process) or `docker`. The docker argv is built by `buildDockerArgs` in a fixed order. The container runs with `--network none --read-only --cap-drop ALL --security-opt no-new-privileges`, limits on pids and memory, and a `noexec,nosuid` tmpfs at `/tmp`. Only the staging dir (read-write, at `/workspace`) and optionally the server code (read-only, at `/server`) are mounted. Nothing goes through a shell. Choices:

- **Bind mounts via `--mount`, not `-v`.** With `-v`, a missing host path is silently created as an empty root-owned directory, and the `src:dst:opts` syntax splits on colons. `--mount type=bind,...` fails if the source is missing and uses named fields. We also resolve each source with `realpath` first and reject paths containing commas or newlines, which would break `--mount`'s comma-separated syntax. The container gets exactly the directory we checked, not whatever a symlink points to later.
- **Host `uid:gid` by default** (falling back to `1000:1000` where `process.getuid` doesn't exist). Files the server writes into the staging dir are then owned by the user running the firewall, so `diff`, `apply` and `revert` can read and replace them without root. It is still a non-root user inside the container. `user` can override it.
- **No auto-pull.** Preflight runs `docker image inspect` and refuses to start if the image is missing, telling the user to build it. Pulling would fetch and run unpinned third-party code at startup and would need network access the rest of sandbox mode avoids. The image should be built from `demo/sandbox/Dockerfile`, where its contents are reviewable.
- **No fallback, ever.** If `docker version` fails, or the image is missing, `connectUpstream` throws `SandboxUnavailableError` and the firewall doesn't start. Quietly running the server unsandboxed would turn "sandbox mode" into "sandbox mode unless something is wrong", which is the case that matters most. The plan's Node permission-mode fallback stays documentation only.
- **Explicit env only.** The container gets only `-e KEY=VALUE` entries from the launch config (keys must match `[A-Za-z_][A-Za-z0-9_]*`). The docker CLI process gets the SDK's safe default env plus `DOCKER_HOST`/`DOCKER_CONTEXT`/`DOCKER_CONFIG`/TLS settings. The CLI doesn't forward its own environment into a container unless asked.
- **No injected flags.** Every value placed before the image is validated so that none starts with `-`, and the image name may not start with `-` or contain whitespace. `command` and `args` come after the image, so docker never parses them as its own flags.
- **Cleanup.** Containers get a random `mcpfw-<hex>` name. `docker rm -f <name>` runs on `close()`, when the downstream connection closes, synchronously on process `exit`, and on SIGINT/SIGTERM. A "no such container" error is ignored; other failures are logged with a code only. The signal handler re-raises the signal if nothing else handles it, so adding cleanup never stops the process from exiting.

## 12. Staged writes in the interceptor

`createInterceptor` takes an optional `staging` dependency. Without it nothing changes. With it, every ALLOWed call runs through `runStagedCall` (`src/proxy/staged-call.ts`) under the `StagingLock`. The per-call steps are listed in that file's header.

**Branch on `decision` only.** The interceptor and `staged-call.ts` decide what to do from `decision` (`ALLOW`/`DENY`) and never inspect `ruleId`. Rule IDs are reported, not interpreted, so a new rule ID from Winston can never change control flow. There is still no dedicated rule ID for an allowed file change: the meta and events carry whatever `ruleId` the evaluator returned for an ALLOW (open question, see PR #11).

**Catch-up diff.** Each call ends by recording a baseline: the staging state it *expects* after apply and revert, plus a fresh scan of the project. The next call first diffs staging against that baseline, *before* syncing. Anything found there was written outside a call's window: late writes from a timed-out call, or background writes from the server. Those changes go through the same evaluate → apply → revert path and are reported as their own FileChangeEvent (`toolName: "<late-writes>"`, `requestId: "<id>:late"`), so they are policy-checked rather than silently applied or silently wiped.

**Expected baseline, not a closing sync.** `StagingArea.baselineAfter()` builds the staging baseline without rescanning or modifying staging. It starts from the pre-call snapshot, sets each applied change as `diff()` saw it, and sets each reverted path as `revert()` restored it. An earlier version ended each call with `sync()`, which overwrote any write landing between the post-call diff and that sync, so the write was never applied and never reported. With the expected baseline, such a write is still different from the baseline and shows up in the next catch-up diff. The project is still rescanned, because the server cannot write there. `revert()` also removes directories it leaves empty when the project doesn't have them, so staging matches the project without a sync.

**Writes to excluded paths are reported.** Excluded paths (`.git/`, `node_modules/`, `.env`, `.env.*`, and configured extras) are never copied into staging, so anything found under them in staging is a server write. `diff()` reports these like any other change: add, symlink or special, with `text` filled in so secret scanning works. They go to `evaluateFileChanges` for a rule ID, but if the evaluator ALLOWs one, `staged-call.ts` forces DENY / WRITE_NOT_ALLOWED ("path is excluded from staging"). `apply()` refuses excluded paths regardless of the decision, and `removeExcluded()` deletes every excluded path found in staging after each call. Without this, a hook written to `.git/hooks/` was dropped without being reported, invisible to the policy and the monitor. The scan of excluded trees stops after `maxChangesPerCall + 1` entries (and as many directories), so a flood of `node_modules` writes can't stall the diff. Past that bound the batch is too large, and the evaluator's CHANGE_LIMIT rejects it. `removeExcluded()` still deletes the unscanned rest. Excluded entries are never hashed: they are never in a baseline, so any entry there is new, and hashing a multi-gigabyte file in `node_modules` would only slow the diff. `text` is read only up to `maxFileBytes`, best effort (it only informs the rule ID; the change is denied either way).

**Unsafe file names don't break staging.** Directory entries are read as raw bytes. A name that is not valid UTF-8, contains control characters or a backslash, or has a drive prefix at the root cannot be represented as a contract path or shown safely. Earlier this made `diff()` throw, which put staging into the broken state: one `touch $'a\\b'` from the server disabled every later call. Now such an entry is reported as kind `special` under an escaped display path (every byte outside printable ASCII, plus `%`, backslash and `:`, becomes `%XX`). It is forced to DENY whatever the evaluator says, never applied, and deleted in `revert()` by its raw on-disk name. Only a failed deletion breaks staging. The raw name never reaches logs, events or result notes. Project files with unsafe names are not mirrored into staging, the same as excluded paths. macOS (APFS) refuses to create non-UTF-8 names (`EILSEQ`), so invalid encodings only arise on Linux; the tests cover backslash and control-character names.

**Broken state.** Any error from `sync`, `diff`, `apply` or `revert` puts staging into a broken state for the life of the process. That call returns a `STAGING ERROR` tool error, and every later allowed call is refused the same way without being forwarded. After an unexpected staging failure, the staging dir and the baseline can no longer be trusted, and continuing would risk applying changes the policy never saw. A restart rebuilds both from the real project. If `apply` fails partway, `StagingApplyError` carries the paths already written, and they are named in the error result and on stderr (paths only, never contents). Calls are also refused until `initStaging()` has run, so startup tampering can't be absorbed into the first call's sync.

**Startup changes reuse WRITE_NOT_ALLOWED.** `initStaging` reverts every change the server made before the first call and reports them with `WRITE_NOT_ALLOWED`, reason "change made before any tool call". A dedicated rule ID would need a contract change agreed by all three of us. Until then the `<startup>` tool name and `startup` request ID distinguish these changes in events.

**EVALUATION_ERROR for file changes needs contract agreement.** `EVALUATION_ERROR` is in the contract's rule IDs, but documented as the proxy's rule for a tool-call evaluation failure. Using it for file changes rejected because `evaluateFileChanges` threw or returned malformed output is our extension. It is listed under "needs contract agreement" in PROJECT_STATUS.md, next to the proposed WRITE_ALLOWED. The code keeps it until the team decides.

**Evaluator output is validated.** `evaluateFileChanges` gets a deep-frozen copy of the changes, so it can't alter what `apply` uses. Its output must be an array of the same length, each item must pass `ChangeDecisionSchema`, and paths must be in the same order. If it throws or returns anything else, every change is denied with `EVALUATION_ERROR`, the proxy's existing fail-closed rule ID (§4). A buggy evaluator then costs writes, never safety.

**Events and results.** A FileChangeEvent is emitted only when a call, catch-up or startup actually produced changes. An allowed call that touched no files already appears as its FirewallEvent. Events keep at most 20 entries with paths cut to 200 characters, and `text` is never copied into them. The result's `_meta['mcp-firewall/staged']` lists at most 100 changes (`MAX_REPORTED_CHANGES`). `applied` and `rejected` stay true totals, and `truncated: true` is added when the list was cut. A downstream result is passed through with its content unchanged unless something was rejected; in that case one note block naming up to 100 rejected paths and rule IDs (then "...and N more") is appended.
