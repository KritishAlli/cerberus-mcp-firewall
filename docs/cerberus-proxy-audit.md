# Cerberus proxy audit (task 4.1.1) and client API investigation (task 4.1.2)

Owner: Aarav. Audited on 2026-10-24 at `b0aaa7d` (main). No behavior was changed. New tests: [`tests/proxy-audit.test.ts`](../tests/proxy-audit.test.ts) with fixture [`tests/fixtures/audit-stdio-server.mjs`](../tests/fixtures/audit-stdio-server.mjs).

Tests whose names start with `GAP` use `it.fails`. Each asserts what the plan requires and passes only while the code falls short. Each GAP body was also run once as a plain test to confirm it fails on its final assertion, not on setup.

**Follow-up (2026-10-24, same day):**
- 1c, 1e and 1f are fixed, and their GAP tests are now normal tests (see each section).
- Only `GAP 1g` remains; it waits on Winston's `evaluateFileChanges`.
- The deleted proxy, staging and upstream-docker suites are restored (see Test results).

## Summary

| Item | Verdict | Evidence (code) | Test |
| --- | --- | --- | --- |
| 1a No forward on DENY | **Pass** | `server.ts:47-49` → `interceptor.ts:99-155`. `forward` has one call site (`interceptor.ts:129`) behind `if (prepared.ok && decision.decision === 'ALLOW')` (`:124`). Every other path returns `blockedResult` (`:154`). `upstream.ts:432-442` is the only `callTool`. | `1a …` (4 tests); `tests/firewall.test.ts` |
| 1b Fail closed | **Pass** (2 notes) | Invalid input → `INVALID_ARGUMENTS` (`interceptor.ts:174-207`). The evaluator throwing or returning garbage gives `EVALUATION_ERROR` (`:209-229`). A downstream error gives a fixed DOWNSTREAM ERROR (`:126-134`, `:278-299`). A closed connection is never reconnected (`upstream.ts:416-418`). A staging error gives STAGING ERROR, breaks staging, and refuses later calls (`staged-call.ts:236-268`). | `1a …every DENY path`, `1b …` (2), `1g …staging failure`, `1g …before initStaging` |
| 1c Publish can't change the decision | **Pass** (gap fixed) | `publishSafely` validates, then calls `publish` inside try/catch (`interceptor.ts:235-258`). The decision is computed first and never read back. A thenable returned by `publish` is observed and its rejection logged (`interceptor.ts:236-280`). | `1c …` (5) |
| 1d Docker preflight, no fallback | **Pass** | Preflight runs `docker version`, then `docker image inspect`, and throws `SandboxUnavailableError` with no pull (`upstream.ts:266-282`). It runs before any spawn (`:376`, `:381`). The runtime launch comes only from `toUpstreamLaunch`, which returns docker when `server.sandbox` is set and throws without a staging dir (`load.ts:73-93`, `index.ts:63-64`). | `1d …` (3) |
| 1e Docker flags | **Pass** (`--pull=never` fixed; swap still open) | `buildDockerArgs` (`upstream.ts:182-222`); root refused by schema (`contracts.ts:298-302`). The live container matched (see 1e). | `1e …` (2); `upstream-docker` argv test and real-Docker `--pull=never` test |
| 1f Container cleanup | **Pass** (orphan gap fixed; one shutdown note) | `--rm` (`upstream.ts:211`); `docker rm -f` on close, downstream close, process exit, SIGINT, SIGTERM. Containers are labeled with the firewall's pid and host, and `sweepOrphanedContainers` removes those of dead firewalls on this host before each launch. | `1f …` (5); real-Docker SIGKILL/orphan test in `upstream-docker.test.ts`; signal/crash paths checked manually (below) |
| 1g Staged-call integration | **Partial: mechanism passes, runtime evaluator is a stub** | Lock (`staged-call.ts:188`, `staging.ts:1062-1076`); post-call diff after error or timeout (`staged-call.ts:212-232`); apply/revert (`:270-292`); WRITE_CONFLICT (`staging.ts:894-906`). **`src/index.ts:76-81` passes no `evaluateFileChanges`, so the runtime uses the reject-all stub** (`staged-call.ts:49,61,308`). | `1g …` (5) + `GAP 1g` |

## Test results

| Command | Result |
| --- | --- |
| `npm run typecheck` | Pass |
| `npm test` | At audit time: 2 files, `firewall.test.ts` 1 passed and `proxy-audit.test.ts` 20 passed, 3 expected-fail (GAP), 1 todo. **After the follow-up:** 5 files, 191 passed, 1 expected-fail (`GAP 1g`). |
| `npm run test:docker` | At audit time it failed with "No test files found", because `fe9db11` had deleted `tests/upstream-docker.test.ts`. **After the follow-up:** 36 passed with Docker 29.9.2, including the real-container, `--pull=never` and orphan-sweep tests. |

**Restored in the follow-up.** Aarav's suites were restored from `fa72e8e`, the main-side parent of the merge `919152d` that carried the deletion into main: `proxy.test.ts` 1,748 lines, `staging.test.ts` 432, `upstream-docker.test.ts` 370, and fixtures `counting-server.ts` 89 and `docker-server.mjs` 48. They were not restored from `fe9db11^`, which is on Winston's branch, forked before PRs #11–#18 and holds older copies (939 / 315 / 350 lines).
- **Same edits as `6893078`:** Winston's commit had also edited the old copies (the policy fields that are now required, plus a session-taint unit test), and those edits were applied again.
- **Four stale assertions updated:** they matched behavior that later commits changed on purpose, so each now asserts the new behavior just as strictly. Counts gained `writesBlocked` (`f4dd9a2`). Rejection results put the note first and set `isError` (`d11339a`, two tests). `/health` gained `instance` (`76c88f1`).
- **Not restored:** the monitor, events, contracts, security and e2e tests are not Aarav's.

**At audit time the previous suite was gone.** Commit `fe9db11` ("new test") deleted 2,653 lines of tests: `proxy.test.ts` (92 tests), `staging.test.ts`, `upstream-docker.test.ts`, `monitor.test.ts`, `events.test.ts`, `contracts.test.ts`, `security.test.ts`, `e2e.test.ts` and the `counting-server` / `docker-server` fixtures. It added the single `firewall.test.ts`. The test counts in `PROJECT_STATUS.md` before this audit describe that deleted suite. Cerberus A10 ("existing typecheck and test suite remain green; Docker integration tests run when Docker is available") cannot be met as written until the suite is restored or replaced.

## Findings by item

### 1a. No forward on DENY: pass

Path: `server.ts:47-49` passes `request.params.name/arguments` and the abort signal to the handler. In `interceptor.ts`:
1. `prepareContext` (`:104`, `:174-203`) validates and freezes the arguments.
2. `evaluateSafely` (`:105`, `:209-229`) runs the evaluator.
3. `publishSafely` (`:107-122`) publishes the event.
4. ALLOW goes to `forward` (`:124-152`); anything else goes to `blockedResult` (`:154`).

`forward` in `index.ts:89` is `connected.callTool`, which `upstream.ts:432-442` turns into the SDK's `client.callTool`. A repo-wide search finds no other `callTool` or `forward(` call. With staging configured, a DENY never reaches `runStagedCall`, so staging is not touched either.

Tests:
- `1a evaluates before forwarding…` checks the order evaluate → publish → forward.
- `1a every DENY path…` covers 12 cases: policy DENY, array, null, Map, NaN, function, empty and non-string tool name, evaluator throw, evaluator garbage, evaluator returning a Promise, and nesting over 64. Each returns BLOCKED with 0 forwards.
- `1a a DENY with staging configured…` checks that staging isn't touched.
- `1a through the real MCP server…` uses the real `startProxyServer` and checks downstream count 0 for a DENY and 1 for an ALLOW.

### 1b. Fail closed: pass, with two notes

| Situation | Code | Test |
| --- | --- | --- |
| Evaluator throws / invalid output / Promise | `interceptor.ts:209-229` | `1a every DENY path…` |
| Invalid input | `interceptor.ts:174-207`, `:366-390` | `1a every DENY path…` |
| Downstream timeout | SDK `REQUEST_TIMEOUT` → `timeout` (`interceptor.ts:294-299`) | `1b a downstream timeout…` (real SDK client, 200 ms) |
| Downstream disconnect / crash | `client.onclose` sets `connected=false` (`upstream.ts:390-398`); later calls throw `UpstreamUnavailableError` → `not_connected` | `1b a real downstream crash…` (real `connectUpstream`, real child process) |
| Staging failure | `fail()` sets `broken`; later calls are refused before forwarding (`staged-call.ts:236-268`) | `1g a staging failure…`, `1g …before initStaging` |

Notes:
- **A staging failure partway through `apply` can leave earlier approved changes applied.** `StagingApplyError` names them in the result and on stderr (`staging.ts` phase 2). No unapproved change is ever applied. This is documented in DECISIONS §12, but no test covers it now.
- **A timeout means "may or may not have run"** (`interceptor.ts:87`). The DOWNSTREAM ERROR never becomes a success.

### 1c. Publishing cannot change the decision: pass, one low gap

The decision is computed before `publishSafely` and is never read from the event. `publish` gets a parsed copy (`parsed.data`, `:254`), so mutating it has no effect.

Tests:
- `1c publish throwing on a DENY` and `1c publish throwing on an ALLOW` cover a throwing publisher.
- `1c publish mutating the event…` covers a publisher that edits the event.

**Fixed: an async publisher's rejection is handled.** `PublishEvent` is typed `(event) => void`, which an `async` function also satisfies. `publishSafely` used to catch only synchronous throws, so a returned rejected promise would have been an unhandled rejection, and Node's default for that is to exit the process.
- **The fix:** `publishSafely` now observes any returned thenable with a rejection handler (`interceptor.ts:236-280`). The handler logs `publish failed: <class> code=<code>` and never the error message, which could echo argument values. The log call itself is guarded.
- **No wait:** the result does not wait for the promise.
- **Tests:**
  - `1c a thenable returned by publish is observed…`
  - `1c publish returning a rejected promise…`: DENY and ALLOW results unchanged, no unhandled rejection, a redacted line, no secret in the logs.
- **Same pattern elsewhere:** `staged-call.ts`'s `onFileChangeEvent` callback catches only synchronous throws as well. The real `publishFileChangeEvent` is synchronous; this was out of this task's scope.

### 1d. Docker preflight and no local fallback: pass

- `preflightDocker` (`upstream.ts:266-282`) runs only `docker version` and `docker image inspect`, never `pull`.
- Either failure throws `SandboxUnavailableError`, and `connectUpstream` calls it before creating the transport (`:376` before `:381`).
- `index.ts` builds the launch only through `toUpstreamLaunch(config.server, staging?.stagingRoot)` (`:63-64`). For a sandbox config that returns docker or throws (`load.ts:75-80`). A sandbox config has no path to `localLaunch`.
- A startup failure tears down what already started and exits 1 (`index.ts:111-114`, `:136-139`).

Tests:
- `1d docker CLI missing…` and `1d image missing…` check that nothing is spawned and nothing is pulled.
- `1d the runtime launch for a sandbox config…` loads the shipped `config/sandbox.yaml`.
- `PROJECT_STATUS.md` records a manual check that startup is refused with Docker stopped and with the image missing (2026-10-24).

Note: the exported `connectUpstream` defaults to `localLaunch(server)` when `options.launch` is omitted (`upstream.ts:357`). The runtime always passes `launch`, so this is safe today. A future caller that forgets `launch` would run unsandboxed without any error. Consider requiring `launch` when `server.sandbox` is set.

### 1e. Docker flags: pass, with gaps

Built by `buildDockerArgs` (`upstream.ts:182-222`; exact argv asserted in `1e builds the planned argv exactly`). `docker inspect` of a live sandbox container on this machine (`config/sandbox.yaml`):

```
Network=none ReadonlyRootfs=true CapDrop=[ALL] CapAdd=[] SecurityOpt=[no-new-privileges] User=501:20
PidsLimit=128 Memory=536870912 MemorySwap=1073741824 Privileged=false AutoRemove=true
Tmpfs=map[/tmp:rw,noexec,nosuid,size=64m] WorkingDir=/workspace Mounts=[bind /workspace rw=true]
```

| Planned | Present |
| --- | --- |
| `--network none` | ✔ |
| `--read-only` | ✔ |
| `--cap-drop ALL` | ✔ |
| `no-new-privileges` | ✔ (`--security-opt no-new-privileges`) |
| Non-root user | ✔ Host `uid:gid`. The schema refuses uid 0 (`contracts.ts:298-302`) and the loader falls back to `1000:1000` for a root host (`load.ts:96-100`). |
| pids / memory limits | ✔ 128 / 512m |
| tmpfs `/tmp` | ✔ `rw,noexec,nosuid,size=64m` |
| Staging rw at `/workspace` | ✔ the only bind mount |
| Server code ro | ✔ by design: `config/sandbox.yaml` has no `serverDir`. The code is baked into the image under the read-only root. With `serverDir`, it is mounted `readonly` at `/server` (`upstream.ts:199-201`). |

Extra flags (all intended): `--rm`, `-i` (stdio protocol), `--name mcpfw-<hex>` (for cleanup), `-w /workspace`, `-e KEY=VALUE` only for explicit `sandbox.env`.

Gaps:
- **Fixed: `--pull=never`.** Preflight confirms the image exists, but `docker run` without `--pull` pulls a missing image. Checked with Docker 29.9.2: `docker run --rm <absent image>` printed "Unable to find image … locally" and tried a registry pull, contrary to DECISIONS §11 ("No auto-pull").
  - `buildDockerArgs` now emits `--pull=never` right after `-i`.
  - A missing image still fails at preflight with the same message ("… was not found locally; build it first …").
  - An image removed after preflight makes `docker run` fail with "No such image" and no registry request. The launch fails with `UpstreamUnavailableError` and there is no fallback.
  - Tests: `1e docker run passes --pull=never…`; `upstream-docker` "an image removed after preflight fails the launch and is never pulled" (real Docker).
- **Swap is not limited.** `MemorySwap=1073741824` is twice `--memory`, so the container can use another 512 MiB of swap. Consider `--memory-swap` equal to `--memory`. No test; this is a hardening suggestion, not a plan flag.

### 1f. Container cleanup: partial

Code:
- `--rm` (`upstream.ts:211`).
- `guardContainer` (`:289-321`) registers a synchronous `docker rm -f <name>` on process `exit`, `SIGINT` and `SIGTERM`, and removes the container on `close()` and on downstream close (`:390-398`, `:443-447`).
- `index.ts` shuts down on SIGINT, SIGTERM, stdin end and agent disconnect (`:94-110`).

Automated (with seams): `1f runs with --rm and removes the container on close()` and `1f removes the container when the downstream exits on its own`.

Manual, real Docker, `config/sandbox.yaml` copy with the monitor off. Each run tracked only its own container and staging dir.

| How the firewall ended | Its container | Its staging dir |
| --- | --- | --- |
| SIGINT | removed | removed |
| SIGTERM | removed | removed |
| stdin end (client disconnect) | removed | removed |
| Uncaught exception (real docker upstream, then `throw`) | removed (the `exit` hook) | n/a (script had no staging area) |
| SIGKILL, filesystem server (exits on stdin EOF) | removed (`--rm` after EOF) | **left**; removed by the next startup's sweep (DECISIONS §13) |
| SIGKILL, a server that **ignores** stdin EOF | **left running**, with an orphaned `docker run` CLI | (not measured) |

**Fixed: orphaned containers.** After a SIGKILL, power loss or OOM kill, the container used to live only as long as the server kept running after stdin EOF. A hostile or buggy server could stay up indefinitely, and nothing removed it.

Now:
- **Labels:** every container gets `mcp-firewall=1`, `mcp-firewall.pid=<firewall pid>`, `mcp-firewall.host=<hostname>` and `mcp-firewall.staging=<staging dir>` (`buildDockerArgs`).
- **Sweep:** before each docker launch (after preflight), `connectUpstream` runs `sweepOrphanedContainers`. It runs `docker rm -f` only on containers that meet all three conditions:
  - they carry `mcp-firewall=1`;
  - their host label matches this machine, so a shared or remote daemon never compares another machine's pids;
  - their recorded pid is dead (ESRCH, using the same `isProcessAlive` as the staging-dir sweep).
- **Never touched:**
  - a container whose pid is alive or gives EPERM;
  - this process's own containers;
  - containers without the labels, which includes those started by older firewall versions, like the two currently running here.
- **Failure handling:** a failed listing or removal is logged and skipped. The sweep never throws, so it can't block startup or change the launch, and there is no local fallback.
- **Logging:** removals are logged to stderr.

Tests:
- `1f the sweep removes only our-labeled containers of dead firewalls…`
- `1f a failing sweep never throws…`
- `1f connectUpstream sweeps after preflight and before launching…` (order version → image → ps → launch, with a failing `ps` still launching in Docker).
- **Real Docker** (`upstream-docker.test.ts`, "a new firewall removes the orphan of a SIGKILLed one and leaves a live instance alone"): three real CLI firewalls, with the fixture server run with `--ignore-stdin-eof`. It SIGKILLs one firewall, checks that its container keeps running, starts a third, and asserts the orphan is gone while the live instance's container and the new one keep running.

**Shutdown note (found in the follow-up, not fixed).** With a server that ignores stdin EOF, graceful shutdown (SIGINT, SIGTERM, disconnect) leaves the staging dir behind:
- The SDK's `StdioClientTransport.close()` waits 2 s before sending SIGTERM to the child, and `index.ts` exits at its own 2 s cap (`SHUTDOWN_TIMEOUT_MS`).
- So `staging.dispose()` never runs. The container is still removed, by the `exit` hook, and the next startup's staging sweep removes the dir.
- Possible fix: in `close()`, `docker rm -f` the container before (or alongside) closing the client. The real-Docker test removes the staging dirs of the firewalls it started.

Also noted:
- SIGINT/SIGTERM handlers in `index.ts` are registered only after `initStaging` (`:106-107`). A signal during startup still removes the container (`guardContainer` is already registered) but leaves the staging dir for the next sweep.
- There is no automated test for the signal paths now that `upstream-docker.test.ts` is deleted.

### 1g. Staged-call integration: mechanism passes, runtime evaluator is the reject-all stub

**Mechanism, all on a real `StagingArea` in a temp project:**

| What | Code | Test |
| --- | --- | --- |
| Lock | `staged-call.ts:188`, `staging.ts:1062-1076` | `1g serializes staged calls under the lock`: 3 concurrent calls, at most 1 in flight |
| Catch-up diff, then sync, before the forward | `staged-call.ts:194-207` | n/a |
| Post-call diff after error or timeout | `staged-call.ts:212-232`; the forward wrapper turns throws into results first | `1g diffs and reverts after a downstream timeout…` |
| Apply / revert | `staged-call.ts:270-292` | the timeout test above (reverted, project unchanged) |
| WRITE_CONFLICT | `staging.ts:894-906`, used in apply phase 2 | `1g WRITE_CONFLICT…`: the user's edit is kept, the approved change is skipped |
| Broken state | `staged-call.ts:236-268` | `1g a staging failure…`, `1g …before initStaging` |

**`src/security` has no `evaluateFileChanges`.** Its exports are `evaluateToolCall`, the `rules.ts` matchers, the `normalize.ts` helpers and `containsSecretPattern`.

The runtime uses the reject-all stub:
- `src/index.ts:76-81` builds `StagingDeps` without `evaluateFileChanges`.
- `runStagedCall` therefore uses `defaultEvaluateFileChanges` (`staged-call.ts:308`), which is `evaluateFileChangesStub` from `src/proxy/stubs/evaluate-file-changes.stub.ts` (`staged-call.ts:49,61`).

In sandbox mode every staged change is rejected with `WRITE_NOT_ALLOWED` ("Staging evaluator not yet implemented"). `policy.staging.writablePaths` and `protectedWritePaths` in `config/sandbox.yaml` are validated but enforce nothing. This is fail-safe: nothing unapproved reaches the project. But no approved write can reach it either. Test: `GAP 1g: the runtime file-change evaluator ignores policy.staging`. It loads the shipped config, confirms `src/**` is writable, and gets DENY for `src/greet.js`.

(The `package.json` → `WRITE_NOT_ALLOWED` seen in the earlier monitor and staged-call manual runs came from this stub, not from `protectedWritePaths`.)

### Other findings (outside 4.1.1, need owners)

- **Session taint is never set at runtime.** `6893078` (Winston) added `getSession` to the interceptor (`interceptor.ts:69-70`, `:164-172`), but `index.ts:84-91` never passes it. `readSession` returns `{ tainted: false }`, so `matchTaintedSession` / `SESSION_TAINTED` (`rules.ts:184-191`) cannot fire. Owner: Winston (rule) + Aarav (wiring).
- **New dependency without agreement.** `d566d4e` added `"docker": "^1.0.0"` to `dependencies`, with about 2,000 lockfile lines and a `doc/` directory. This is the `docker` documentation-generator package on npm, not Docker. It uses a caret range unlike every other pinned dependency, isn't imported anywhere in `src/`, `demo/` or `tests/`, and isn't installed locally (`npm ls docker` → empty). Cerberus §3 requires all three owners to agree on package changes. Not changed here.
- **Docs drift from my own commit `d11339a` (fixed in the follow-up).** DECISIONS §12 "Events and results" now describes the current shape: note first, `isError: true`, server text prefixed, `structuredContent` dropped.

## Part 2: client API investigation (task 4.1.2)

Sources were the pinned packages in `node_modules`, official Anthropic and OpenAI documentation, and the official `openai/codex` source at `970111f6cb62cc02fe36a82ea7d71b37a2889c97` (main, 2026-10-24). Third-party blog posts turned up in search were not used as evidence.

### 2a. Does `@modelcontextprotocol/server` 2.4.0 expose elicitation? Yes, on our connection type.

Installed: `@modelcontextprotocol/server` 2.4.0, `@modelcontextprotocol/client` 2.4.0, `@modelcontextprotocol/core` 2.4.0.

From `node_modules/@modelcontextprotocol/server/dist/mcp-BCJHyo7l.d.mts`:

```ts
// declare class Server (line 2941), method at line 3170
elicitInput(params: ElicitRequestFormParams | ElicitRequestURLParams, options?: RequestOptions): Promise<ElicitResult>;

// type ServerContext → mcpReq (line 2238): the request-scoped form, available inside our tools/call handler
elicitInput: (params: ElicitRequestFormParams | ElicitRequestURLParams, options?: RequestOptions) => Promise<ElicitResult>;

// RequestOptions (≈ line 2030-2061): signal?: AbortSignal; timeout?: number (default DEFAULT_REQUEST_TIMEOUT_MSEC = 60_000);
//                                     resetTimeoutOnProgress?: boolean; maxTotalTimeout?: number
```

From `node_modules/@modelcontextprotocol/core/dist/schemas-DscsoNZN.mjs`:

```ts
ElicitRequestFormParamsSchema  = { mode?: 'form', message: string,
                                   requestedSchema: { type: 'object', properties: Record<string, PrimitiveSchemaDefinition>, required?: string[] } }   // :1144
ElicitRequestURLParamsSchema   = { mode: 'url', message: string, elicitationId: string, url: string }                                               // :1156
ElicitResultSchema             = { action: 'accept' | 'decline' | 'cancel', content?: Record<string, string | number | boolean | string[]> }      // :1201
ElicitationCapabilitySchema: an empty `elicitation: {}` is treated as `{ form: {} }`                                                                 // :268
LATEST_PROTOCOL_VERSION = "2025-11-25"; SUPPORTED_PROTOCOL_VERSIONS = 2025-11-25, 2025-06-18, 2025-03-26, 2024-11-05, 2024-10-07                     // :4-12
```

**Era caveat (from the same `.d.mts`, lines 2231-2238 and 3165-3170).** `elicitInput` is marked `@deprecated`: it "Throws on a 2026-07-28-era request". On revision 2026-07-28 the replacement is returning `inputRequired(...)` / `inputRequired.elicit(...)` (line 1486, `InputRequiredBuilder`). That is a multi-round-trip result the client fulfils and then retries the call. It only works on the "legacy path".

Our stdio proxy is a low-level `Server` with `initialize`, and it negotiates `2025-11-25` (probe below). So the push-style `elicitInput` applies to us.

Runtime probe against the pinned SDK (low-level `Server` + `Client` over `InMemoryTransport`):

```
negotiated protocol: 2025-11-25
no elicitation capability    → THROWS SdkError code=CAPABILITY_NOT_SUPPORTED | Client does not support form elicitation.
capability {} + decline      → {"action":"decline"}
capability form + cancel     → {"action":"cancel"}
never answers, timeout 300ms → THROWS SdkError code=REQUEST_TIMEOUT | Request timed out
accept                       → {"action":"accept","content":{}}
```

### 2b. Claude Code

Installed here: **2.1.310**, which matches the top of the official changelog (2026-10-23).

- **Supported.** [MCP docs: "Respond to MCP elicitation requests"](https://code.claude.com/docs/en/mcp#respond-to-mcp-elicitation-requests): "When a server needs information it can't get on its own, Claude Code displays an interactive dialog and passes your response back to the server. No configuration is required on your side."
  - Form mode: "a dialog with form fields defined by the server".
  - URL mode: "asks whether to open a link in your browser".
- **Version introduced: not verified from an official source.** The official changelog was too long to read past 2.1.299 in this session. Support is documented for the installed 2.1.310.
- **What the user sees:** a modal form dialog in the terminal. The server controls only `message` and the fields; the button labels are Claude Code's.
- **Decline / cancel:** for MCP tasks the docs say "Declining or pressing `Esc` is an answer to the server" ([MCP docs, MCP tasks](https://code.claude.com/docs/en/mcp)). Per the SDK schema the server receives `decline` or `cancel`. The docs don't separately describe Esc for an ordinary (non-task) tool call; to verify in the spike.
- **Timeout:** no elicitation timeout is documented for ordinary tool calls. The docs say a call "waiting on an open elicitation dialog isn't backgrounded while the dialog is open". The changelog for 2.1.310 says Claude Code "Changed the error for an MCP tool call that times out in a non-interactive session while the server's elicitation is unanswered" ([changelog](https://code.claude.com/docs/en/changelog)). On our side, the SDK `timeout` bounds the wait (`REQUEST_TIMEOUT` in the probe).
- **Non-interactive (`-p`) and SDK sessions:** for MCP tasks, `elicitation/create` "is served only in interactive terminal sessions". In a non-interactive session Claude Code cancels instead ([MCP docs](https://code.claude.com/docs/en/mcp)).
- **Capabilities on our connection: unverified.** The docs say that on revision 2026-07-28 Claude Code "declares `elicitation: {form: {}, url: {}}`", and that its v2 runtime "asks stdio servers for that revision by default". Our server negotiates `2025-11-25`, and the docs don't state the elicitation capability declared on 2025-era connections. Next step: log `server.getClientCapabilities()` from the real Claude Code connection.
- **Hooks:** an `Elicitation` hook can answer, decline or cancel without showing the dialog. Exit 2 or `"decision": "block"` declines. Claude Code "discards `reason`, `systemMessage`, and `continue` from an Elicitation hook's JSON output" ([hooks: Elicitation](https://code.claude.com/docs/en/hooks#elicitation)). A user's own hook can therefore suppress our notice. That's acceptable, because the notice is informational.

### 2c. Codex

- **Official documentation:** the Codex MCP page ([learn.chatgpt.com/docs/extend/mcp?surface=cli](https://learn.chatgpt.com/docs/extend/mcp?surface=cli), redirected from developers.openai.com/codex/mcp) does not mention elicitation.
  - It documents per-server approval modes (`auto`, `prompt`, `writes`, `approve`) plus `tool_timeout_sec` (default 60) and `startup_timeout_sec` (default 10).
  - The [releases page](https://github.com/openai/codex/releases) (latest 0.164.0, 2026-10-23) has no elicitation entries in the visible notes.
- **Official source shows support** (`openai/codex` @ `970111f`):
  - [`core/src/config/mod.rs:1950-1958`](https://github.com/openai/codex/blob/970111f6cb62cc02fe36a82ea7d71b37a2889c97/codex-rs/core/src/config/mod.rs#L1950-L1958): Codex declares `elicitation: {}` by default (form, per the 2025-06-18 rule), and `form` + `url` when the `AuthElicitation` feature is enabled.
  - [`codex-mcp/src/elicitation.rs`](https://github.com/openai/codex/blob/970111f6cb62cc02fe36a82ea7d71b37a2889c97/codex-rs/codex-mcp/src/elicitation.rs) surfaces form and URL requests to the TUI, rendered by `tui/src/bottom_pane/mcp_server_elicitation.rs`.
- **Behavior that matters for a Block notice** (`elicitation.rs` @ `970111f`):
  - `approval_policy = never` declines every elicitation without UI (`elicitation_is_rejected_by_policy`, ≈ line 714).
  - **A form with no fields is auto-accepted without being shown** when the MCP permission prompt is auto-approved (`can_auto_accept_elicitation`, ≈ line 725, used ≈ line 580). A Block notice must have at least one field to be displayed reliably.
  - With no event channel, or no authority or permission profile, Codex declines.
- **Timeout:** none documented for elicitation. Codex's `tool_timeout_sec` (default 60) bounds the whole tool call. A notice that waits longer would turn our BLOCKED result into a client-side timeout.
- **Not tested here:** Codex is not installed on this machine (`codex --version` → not found). cerberus.md §7.2 documents it on Winston's machine.

### 2d. Can Claude Code hooks show a user-visible message for a blocked MCP call?

Yes, but only as a warning line, not a dialog, and only with a per-user hook installed.

- **`PostToolUseFailure`** "Runs when a tool that started executing fails: the tool threw an error, or an MCP tool returned an error result" ([hooks](https://code.claude.com/docs/en/hooks)). Our DENY is `isError: true`, so it fires.
  - Matcher: `mcp__<server>__.*`.
  - Input: `tool_name`, `tool_input`, `error` ("generally the same text Claude receives"), `is_interrupt?`, `duration_ms?`. **No `_meta`**, so a hook would have to parse `BLOCKED_PREFIX` from `error`.
- **`systemMessage`** is a "Warning message shown to the user" ([hooks: JSON output](https://code.claude.com/docs/en/hooks#json-output)).
  - No exception is documented for PostToolUse or PostToolUseFailure. Not observed in a live session.
  - Capped at 10,000 characters.
- **`Notification` hooks discard `systemMessage`.** They can only emit `terminalSequence` (OSC 9/777 desktop notifications, interactive sessions only).
- **Limits:**
  - Hooks run without a controlling terminal, so they can't open their own UI.
  - Default command-hook timeout is 600 s.
  - The hook has to be installed in each user's Claude Code settings: a client config change, which is Kritish's onboarding scope.
  - Codex has a hooks crate (`codex-rs/hooks/src/mcp.rs`), but the official docs I read don't document MCP hook behavior. Unverified.

### 2e. What clients show today for a DENY

The interceptor returns a **tool result, not a JSON-RPC error** (`interceptor.ts:264-276`, DECISIONS §2):

```
isError: true
content: [{ type: 'text', text: '[MCP Firewall] BLOCKED (<ruleId>): <reason>. The request was not sent to the tool server. [request <id>]' }]
_meta:   { 'mcp-firewall/decision': { decision: 'DENY', ruleId, reason, requestId } }
```

- **Claude Code:** "when a tool returns a result marked `isError: true`, Claude receives the result's text as the tool's error message", truncated past ~11,000 characters ([MCP docs, output limits](https://code.claude.com/docs/en/mcp)). PROJECT_STATUS records a manual check on 2026-10-23: `BLOCKED (DEFAULT_DENY)` shown as a tool error. No dialog appears; the user sees the failed tool call in the transcript.
- **Codex:** the official docs don't describe this. In source, the TUI marks an MCP call with `is_error` as failed (`tui/src/history_cell/mcp.rs:117-123` @ `970111f`) and renders its content blocks (`history_cell/mcp_result.rs`). Not observed in a live session from this machine.
- A JSON-RPC error would show as a failed call too, but clients treat it as a protocol or tool fault rather than a policy decision the model can reason about. DECISIONS §2 already chose the tool result.

## Recommendation: one adapter approach for a Block-only notice

**Use MCP form elicitation on the agent-facing connection. Send it from the gateway inside the denied `tools/call`, through the request-scoped `ctx.mcpReq.elicitInput`, after the DENY result has been built. Return that same result unchanged, whatever the notice does.**

Why this one:
- It is part of the protocol, so it needs no client configuration.
- Both target clients implement it: documented for Claude Code; in source for Codex.
- The pinned SDK supports it on the `2025-11-25` connection we negotiate.
- Hooks are client-specific, need per-user installation, and Claude Code shows only a warning line from them.

**The notice is informational.** The DENY is final before the notice is sent:
1. The evaluator has returned and the event is published.
2. The `BLOCKED` result object is built and frozen.
3. The forward branch is unreachable for this request.

Then:
- The notice's outcome (`accept`, `decline`, `cancel`), a timeout, an error, an unsupported client, a disconnect, or no answer at all changes nothing. The same BLOCKED result is returned. There is no retry and no forward, and the policy is not touched.
- The adapter cannot approve anything, and the gateway has no code path that reads the notice's answer.

Design constraints from the findings:
- **Only when supported:** skip the notice unless `getClientCapabilities()?.elicitation` includes form. Otherwise the BLOCKED result and the monitor are the fallback (cerberus §6).
- **Bounded wait:** use the SDK `timeout` (proposed 20 s, configurable) well under Codex's 60 s `tool_timeout_sec`. Without that, a slow dismissal would turn BLOCKED into a client timeout. The cost: the agent waits until the user answers or the timeout passes.
- **At least one field**, so Codex doesn't auto-accept it unseen. Proposed: one boolean `acknowledged` (title "I understand this call was blocked", default `true`). It is not an approval. Winston should review the wording against UI spoofing (cerberus §4.2.4), because the client's own button may read "Accept"/"Submit".
- **Message:** built only from `BlockNotice` fields, which are already bounded and redacted like events (cerberus §5). Example: "Cerberus blocked fs/read_text_file (PROTECTED_PATH): Credential path is protected. This call was not run, and answering this dialog does not change that. Details: request <id>."
- **One dialog at a time:** a deny storm must not stack dialogs. While one notice is open, later denies skip the dialog (the monitor still shows them).

Open questions for the spike (Claude Code 2.1.310, interactive):
- Does it declare `elicitation` on our `2025-11-25` connection?
- What does the dialog look like, and what do Esc and an unanswered dialog do?
- Does the SDK's cancel on timeout close the dialog?

### Proposed interface (proposal only: needs agreement from Aarav, Winston and Kritish before anything touches `src/shared/contracts.ts`)

```ts
// BlockNotice: as cerberus §5. Built from the same values as the DENY's FirewallEvent
// (already redacted and bounded), never from raw arguments.
export interface BlockNotice {
  requestId: string;
  serverId: string;
  toolName: string;
  decision: 'DENY';
  ruleId: RuleId;
  reason: string;   // ≤ LIMITS.reason, value-free
  summary: string;  // ≤ LIMITS.summary, argument key names only
}

/** What happened to the notice. Logged only; never read by enforcement. */
export type NoticeOutcome = 'acknowledged' | 'declined' | 'cancelled' | 'timeout' | 'unsupported' | 'skipped' | 'failed';

/** src/proxy (Aarav). One per agent connection; the elicitation one wraps ctx.mcpReq.elicitInput. */
export interface BlockNoticeAdapter {
  /**
   * Called only after the DENY result is final. Must not throw; the caller still
   * guards it with try/catch and a timeout. Its outcome never changes the result.
   */
  notify(notice: Readonly<BlockNotice>, options: { signal: AbortSignal; timeoutMs: number }): Promise<NoticeOutcome>;
}

// Interceptor (sketch): unchanged decision path, then
//   const result = Object.freeze(blockedResult(decision, requestId));
//   await notifySafely(adapter, notice, { timeoutMs });   // swallows everything, logs the outcome
//   return result;                                         // the same object, always
```

Until the contract is agreed, `BlockNotice` can live in `src/proxy` as a local type. `ToolCallHandler`'s options (Aarav's) would carry the per-request adapter from `server.ts`.

Tests required before calling it done (cerberus §4.1.5, A4/A5):
- The adapter throws, times out, declines, cancels, accepts, is missing, or the client disconnects mid-notice. In every case the result is identical, there are 0 forwards, and there is 1 event.
- The notice text contains no argument values.
- A client without the capability gets no elicitation request.
- A deny storm opens at most one dialog.
