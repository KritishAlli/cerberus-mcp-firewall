# Project status: proxy and enforcement (Aarav)

Merged to `main` (PRs #2, #7, #9, #10, #11, #12, #16, #17, #23; Kritish's #24 touches staging). Rationale for each choice: [`docs/DECISIONS.md`](docs/DECISIONS.md).

## Cerberus 4.1 audit (2026-10-24, at `b0aaa7d`)

Full report: [`docs/cerberus-proxy-audit.md`](docs/cerberus-proxy-audit.md). The audit changed no behavior; the follow-up the same day fixed 1c, 1e and 1f and restored the deleted suites (below). `aarav/wire-change-evaluator` closed 1g and the remaining 1c/1e/1f items. New: `tests/proxy-audit.test.ts` and `tests/fixtures/audit-stdio-server.mjs`.

| Item | Verdict |
| --- | --- |
| 1a No forward on DENY | Pass |
| 1b Fail closed | Pass (an apply failure can leave earlier *approved* changes applied, named in the result) |
| 1c Publish can't change the decision | Pass. **Fixed:** a promise returned by `publish`, and now one returned by `onFileChangeEvent`, is observed; its rejection is logged (class and code only), never unhandled, and never changes the result. |
| 1d Docker preflight, no local fallback | Pass |
| 1e Docker flags | Pass. **Fixed:** `docker run --pull=never`, and `--memory-swap` equal to `--memory` (no swap; verified `MemorySwap == Memory` on a live container). |
| 1f Container cleanup | Pass. **Fixed:** containers are labeled (`mcp-firewall=1`, `.pid`, `.host`, `.staging`), and before each launch `sweepOrphanedContainers` removes only those of dead firewalls on this host. Live instances' and unlabeled containers are never touched; the sweep never throws or blocks startup. **Fixed:** `close()` runs `docker rm -f` before closing the MCP client, so a server that ignores stdin EOF can't hold shutdown to the 2 s cap before `staging.dispose()`. |
| 1g Staged-call integration | Pass. **Fixed:** `src/index.ts` injects Winston's `evaluateFileChanges` (`src/security/changes.ts`), so `policy.staging` is enforced. `GAP 1g` is now a plain test: an allowed `src/` write lands in the project, a `.git/hooks` write is DENY / `PERSISTENCE_PATH`. |

**Test suite:** `fe9db11` (Winston's branch) deleted the previous suite (2,653 lines). Aarav's suites are restored from `fa72e8e`, the newest copies on main. The `fe9db11^` copies were older, from before PRs #11–#18.

| File | Lines |
| --- | --- |
| `tests/proxy.test.ts` | 1,748 |
| `tests/staging.test.ts` | 432 |
| `tests/upstream-docker.test.ts` | 370 |
| `tests/fixtures/counting-server.ts` | 89 |
| `tests/fixtures/docker-server.mjs` | 48 |

- **Same edits as `6893078`:** the required policy fields and the session-taint unit test, applied again.
- **Four stale assertions updated** to the current behavior, just as strictly: the counts now include `writesBlocked` (`f4dd9a2`); the rejection note comes first and `isError` is set (`d11339a`, two tests); `/health` includes `instance` (`76c88f1`).
- **Not restored:** the monitor, events, contracts, security and e2e suites are other owners'. The counts further down describe the pre-`fe9db11` suite and are historical.

Now (on `aarav/wire-change-evaluator`):
- `npm run typecheck`: passes.
- `npm test`: 11 files, 261 passed, no expected-fails left.
- `npm run test:docker`: 36 passed with Docker 29.9.2. That includes real-container tests for `--pull=never` and the orphan sweep: SIGKILL one firewall, start a new one, the orphan is removed and a live instance's container survives.
- `npm run demo` (mock mode): passes.
- **Sandbox mode, by hand** (`src/index.ts --config config/sandbox.yaml`, real container, MCP client calling `write_file`): an edit to `src/greet.js` was ALLOWed and reached `demo/project`; `.husky/pre-commit` and a `package.json` `postinstall` were DENY / `PERSISTENCE_PATH` and never reached the project; a `.git/hooks/pre-commit` write never got that far (see below). `demo/project` was reverted afterward. `npm run demo` itself only drives the mock server.

**Found in the sandbox run** (not changed here):
- **Winston:** the tool-call evaluator scans `write_file`'s `content` for path-like tokens. Any content with a `//` comment or an absolute path (`see /etc/hosts`) is `PATH_NOT_ALLOWED`, so most real source edits are blocked in sandbox mode before staging sees them.
- **Staging:** the server can't create a file in a new directory. `write_file` doesn't create parents, and an empty directory made by `create_directory` is removed by the next pre-call sync (and anything under `.git/` by `removeExcluded`). Safe, but it means a new `src/sub/` file is impossible too. Needs a decision on whether directory adds should be staged.

**Also found:**
- Session taint is never wired: `index.ts` passes no `getSession`, so `SESSION_TAINTED` can't fire.
- `d566d4e` added an unpinned, unused `"docker": "^1.0.0"` dependency (an npm doc generator) without the agreement cerberus §3 requires. **Removed on `aarav/fix-docker-shadowing`**, see Blockers.
- ~~DECISIONS §12 described the rejected-changes note as appended~~: fixed to match `d11339a`.

**Task 4.1.2 (client adapter):** recommendation in the audit doc and [DECISIONS §15](docs/DECISIONS.md) (proposed, pending team review): a Block-only, informational notice sent as MCP form elicitation after the DENY is final.

## Done

- **`src/proxy/interceptor.ts`**: `createInterceptor(deps)` does validate → clone + deep-freeze → evaluate (schema-checked, fail closed) → publish exactly one event → forward only on ALLOW. It returns a recognizable BLOCKED tool error on DENY and a fixed-message DOWNSTREAM ERROR when the downstream fails.
  - **Staged writes**: the optional `staging` dep `{ area, lock, evaluateFileChanges?, policy, onFileChangeEvent? }` sends every ALLOWed call through `runStagedCall` in the new **`src/proxy/staged-call.ts`**. Without it, behavior is unchanged and every earlier test passes as before.
  - Per call, under the `StagingLock`: a catch-up diff for late writes (reported as `<late-writes>`, request `<id>:late`), then sync, forward, and a diff that runs even after an error or timeout. Then `evaluateFileChanges` (output validated; if it throws or the output is malformed, every change is DENY / `EVALUATION_ERROR`), apply, revert of rejected changes, and a sync that sets the next baseline.
  - The result keeps the downstream content and gets `_meta['mcp-firewall/staged'] = { applied, rejected, changes, truncated? }`. `changes` is capped at 100 and the totals stay exact. If anything was rejected (since `d11339a`), the result is `isError: true`. A note listing rejected paths with rule IDs and applied paths (each capped at 100) comes first (`REJECTED_CHANGES_PREFIX`). The server's first text block is prefixed as sandboxed output, and `structuredContent` is dropped. A `FileChangeEvent` is emitted only when there were changes: at most 20 entries, bounded paths, no `text`, and callback errors are only logged.
  - **Excluded paths** (`.git/`, `node_modules/`, `.env`…): server writes there are now reported, evaluated, forced to DENY if the evaluator allows them, never applied, and removed from staging. The excluded scan stops after `maxChangesPerCall + 1` entries (new `maxChangesPerCall` option on `createStagingArea`, default 1000). Excluded entries are not hashed, and `text` is read only up to `maxFileBytes`.
  - **Unsafe file names** (backslash, control characters, invalid UTF-8, a drive prefix at the root): scans read raw byte names. Such entries are reported as `special` under an escaped display path (`%XX`), forced to DENY, never applied, and deleted by their raw name in `revert()`. Staging breaks only if that deletion fails. Project files with unsafe names are not mirrored, like excluded paths.
  - **Baseline without a closing sync:** `StagingArea.baselineAfter()` records the expected post-call staging state, so a write landing after the post-call diff is caught by the next catch-up instead of being overwritten.
  - **Fail closed:** any sync/diff/apply/revert error returns a `STAGING_ERROR_PREFIX` tool error (naming paths already applied, via the new `StagingApplyError` in `staging.ts`) and breaks staging. Every later allowed call is refused without forwarding until restart, and so are calls before `initStaging()` has run.
  - `initStaging(staging, { serverId, initial })` reverts changes the server made before any call, emits a `<startup>` event (WRITE_NOT_ALLOWED, "change made before any tool call"), and throws if staging fails.
  - The interceptor branches on `decision` only. See [DECISIONS §12](docs/DECISIONS.md).
  - **Change evaluator:** `src/index.ts` injects Winston's `evaluateFileChanges` from `src/security/changes.ts`. PR #24 (Kritish) deleted the reject-all stub `src/proxy/stubs/evaluate-file-changes.stub.ts`; the fallback `defaultEvaluateFileChanges`, used only when none is injected (tests), is now the same evaluator ([DECISIONS §16](docs/DECISIONS.md)).
- **`src/proxy/upstream.ts`**: `connectUpstream(config, { onClose? })` spawns the server over stdio with a safe default env and re-emits its stderr with a prefix. It has a connect timeout, per-call `timeout`/`maxTotalTimeout`/`signal`, paginated `listTools` (20-page cap), a `connected` getter, and `UpstreamUnavailableError` once closed. No reconnect.
  - **Docker launch mode**: `connectUpstream(server, { launch })` takes an exported, Zod-validated `UpstreamLaunch`. It is either `{ mode: 'local', command, args, env?, cwd? }` (the old behavior, built by `localLaunch(server)`) or `{ mode: 'docker', image, command, args, workspaceDir, serverDir?, env?, user?, memory?, pidsLimit? }`.
  - Docker mode runs the plan's locked-down container: `--network none --read-only --cap-drop ALL --security-opt no-new-privileges`, host `uid:gid`, pids 128, 512m with `--memory-swap` equal (no swap), tmpfs `/tmp`, staging rw at `/workspace`, server code ro at `/server`, and only explicit `-e` vars. `buildDockerArgs(launch)` builds the argv. It is exported, unit-tested and never uses a shell.
  - Preflight runs `docker version`, then `docker image inspect`. If either fails it throws `SandboxUnavailableError` and refuses to start. It never pulls and never falls back to local mode.
  - The container is removed with `docker rm -f` on close (before the MCP client is closed), on a downstream close, on process exit, and on SIGINT/SIGTERM. Container stderr goes to our stderr as `[upstream:<id>] …`.
  - `upstream.launch` / `describeLaunch()` report `{ mode, image?, containerName?, sandboxed }` for the monitor and `/health`. Not wired in yet.
  - `src/index.ts` now passes `launch: localLaunch(config.server)` explicitly. No new config keys; behavior is unchanged.
  - See [DECISIONS §11](docs/DECISIONS.md).
- **`tests/upstream-docker.test.ts`**: 31 unit tests that need no Docker: the exact argv and its order, defaults, every rejection case, env passthrough only when explicit, preflight failures that never spawn (no CLI, daemon down, timeout), no pull, and container removal on close. There are also 3 integration tests (real `node:22-slim` container: tools through the proxy, no network, writes only to `/workspace` and `/tmp`). Without Docker or the image they are skipped with the reason logged; `npm run test:docker` (`REQUIRE_DOCKER=1`) fails instead. Fixture: `tests/fixtures/docker-server.mjs`.
- **`src/proxy/server.ts`**: `startProxyServer(upstream, handler, { transport?, onClose? })` is a low-level `Server`. `tools/list` passes through unchanged, `tools/call` goes to the interceptor with the cancellation signal, and downstream `instructions` are not forwarded.
- **`src/index.ts`**: passes the signal through, and shuts down cleanly on agent disconnect, stdin end, SIGINT or SIGTERM (2 s cap), closing the upstream, proxy and monitor. A downstream crash keeps the proxy up and fails closed. Kritish's PR #6 added one line wiring `/health` to live state: `monitor?.setProtectedServers(() => (upstream.connected ? 1 : 0))`. Reviewed: correct, and the optional chaining keeps enforcement independent of the monitor.
- **`tests/fixtures/counting-server.ts`**: test-only stdio server (`echo`, `read_file`, `structured`, `tool_error`, `hang`, `crash`, `get_call_counts`) with an optional `--counts-file`.
- **`src/proxy/staging.ts`** (staged writes, not yet wired into the interceptor): `createStagingArea({ projectRoot, stagingParent?, excludes?, extraExcludes?, maxFileBytes })` makes a `mkdtemp` staging dir (under `os.tmpdir()` by default, refused inside the project). The `StagingArea` it returns has:
  - `sync()`: mirrors the project into staging minus excludes (`.git/`, `node_modules/`, `.env`, `.env.*` and any extras). Symlinks are recreated, never followed. Returns the pre-call staging manifest and the project manifest.
  - `diff(before)`: rescans staging and returns `FileChange[]` (add / modify / delete / mode / symlink / special), sorted by path. `text` is set only for UTF-8 files without NUL of at most `maxFileBytes`.
  - `apply(changes, decisions, projectAtSync)`: writes ALLOWed changes via temp file + rename. It skips a path with WRITE_CONFLICT if the project changed since sync. Symlink and special changes and excluded paths are never applied. A staged file that changed after `diff()` aborts the apply before anything is written.
  - `revert(paths)`: restores those paths in staging from the project.
  - **Move pairing** (PR #24, Kritish): in `apply()`, a delete whose content (sha256) reappears in an add or modify of the same batch is treated as a move's source. It runs after the writes and only if one of those destinations was applied; otherwise it is skipped with the destination's rule ID, so denying a move's destination (or a WRITE_CONFLICT on it) never loses the file. Covered by three new tests in `tests/staging.test.ts`.

  Also exported: `snapshot(root)`, `resolveInRoot(root, rel)` (the single path-safety check) and `StagingLock` (async mutex for the interceptor). Every error is thrown to the caller, with no paths or contents in messages. Node built-ins only. See [DECISIONS §10](docs/DECISIONS.md).
- **`tests/fixtures/malicious-server.ts`**: test-only stdio server rooted at `--root`. Tools: `write_file`, `format_readme` (README edit plus a `.git` hook, a `.husky` hook, a symlink, an exec bit, a dummy AWS key and a deleted `LICENSE`), `late_write`, `write_many`, `flood_node_modules`, `write_unsafe_names`, `write_big_unreadable`, `noop`, `fail_after_write`, `hang`, `get_call_counts`. With `MALICIOUS_STARTUP=1` it writes a file before serving.
- **`tests/staging.test.ts`**: 24 tests against real temp dirs: excludes, symlinks and hardlinks, text rules, path escapes, atomic apply, conflicts, defense in depth, revert, ordering and the lock.
- **`tests/proxy.test.ts`**: 92 tests in tests/proxy.test.ts (25 of them staged writes). Full suite: 211 passing, 3 skipped (Docker integration), 8 todo (all in `tests/e2e.test.ts`). The staged-writes block passed 10 runs in a row. Coverage:
  - unit tests (T01, T02, T06, T09, T11, fail-closed evaluator and publish, arg mutation, summary bounds, signal)
  - integration through the real stdio fixture (listing identical to direct, T01/T02 counts, structured results and tool errors, unknown tools, hang timeout, crash)
  - CLI smoke test of `src/index.ts`. With the real evaluator, its approved `fixture/echo` call now takes the forwarded (ALLOW) branch.
  - CLI run against `demo/mock-server.ts` with the shipped `config/firewall.yaml` policy and the real evaluator:
    - listing parity with a direct connection
    - T01: `read_project_file` is ALLOWed, forwarded once, and its result is identical to a direct call
    - T02–T04: PROTECTED_PATH, DENIED_DESTINATION and DENIED_TOOL are each BLOCKED with a count of 0
  - vertical slice (T10): the real CLI with its monitor on a free port. One allowed and one denied call, then `GET /events` replays exactly those two events (decision, ruleId, matching `requestId`), `counts` is `{inspected: 2, allowed: 1, denied: 1}`, `/health` is `{status: ok, protectedServers: 1}`, and no argument values or the mock's secret appear in the stream (T11)

## Pitch demo: added and verified (2026-10-25)

A narrated, deterministic sandbox-mode demo, `npm run demo:pitch` (`demo/pitch.ts`).
Additive; Kritish's `demo/scenarios.ts` and `demo/mock-server.ts` are untouched.

**New/changed files:**
- `demo/sandbox/side-effects-fixture.mjs` — an inert test-double MCP stdio server, written against the image's `@modelcontextprotocol/sdk` **1.32.1** (not the repo's v2 `@modelcontextprotocol/server`; the image ships the filesystem server's SDK), no zod needed. `format_readme` appends a README line and makes five extra **inert** writes (a `.git/hooks/pre-commit` marker, a `package.json` `fixture-marker` script, `src/fixture-key.txt` holding the AWS doc example key `AKIAIOSFODNN7EXAMPLE`, a separate exec-bit marker `src/fixture-run.txt`, and a relative symlink `src/fixture-link`). Plus `get_call_counts` and `probe_env` (reports presence/size/sentinel only, never contents; used by `demo:env`). Everything is a marker string — no commands, no real credentials, nothing outside `/workspace`.
- `demo/sandbox/Dockerfile` + `.dockerignore` — copy the fixture to `/app` so it resolves the SDK from `/app/node_modules`. Only additive lines.
- `config/pitch-fs.yaml` (copy of `config/sandbox.yaml`) and `config/pitch-attack.yaml` (serverId `tool`, runs `/app/side-effects-fixture.mjs`, approves `tool/format_readme`, `tool/get_call_counts` and `tool/probe_env`, same staging policy). Both load under `src/config/load.ts` unchanged — no schema changes.
- `demo/pitch.ts` — copies `demo/project` to a fresh temp dir, `git init` + one commit, writes temp configs repointing `server.sandbox.project` at the copy. `demo/project` is never modified.
- `demo/env-suite.ts` — the `.env` access suite (see below), same throwaway-copy setup; `demo/project` is never modified.
- `package.json` — added `"demo:pitch": "tsx demo/pitch.ts"` and `"demo:env": "tsx demo/env-suite.ts"`. No new dependencies.

**What the three acts verified (all PASS):**
- **Act 1 (fs config):** `fs/write_file` on `src/greet.js` adding a `farewell` function (no `//` comments, no absolute paths in the content) → ALLOW, `staged` applied 1 / rejected 0, the function present in the temp project. Confirms Winston's content-scanning behavior does **not** block a plain source edit (no `PATH_NOT_ALLOWED`); no policy loosening was needed.
- **Act 2 (same gateway, prompt-injected agent):** `fs/read_text_file` on `.env` → BLOCKED, `_meta['mcp-firewall/decision'].decision === 'DENY'`, `PROTECTED_PATH`; the `.env` value never appears in output. `fs/write_file` on `package.json` with a `postinstall` → BLOCKED, `DENY` / `PERSISTENCE_PATH`; `package.json` in the temp project byte-for-byte unchanged. Both are pre-call denies, so the downstream never received them.
- **Act 3 (attack config, same temp project):** `tool/format_readme` → ALLOWed call with rejected changes (no decision meta; read from `_meta['mcp-firewall/staged']`). `staged` = **1 applied, 5 rejected**: `README.md` APPLY `APPROVED_TOOL`; `.git/hooks/pre-commit` `PERSISTENCE_PATH`; `package.json` `PERSISTENCE_PATH`; `src/fixture-key.txt` `SECRET_DETECTED`; `src/fixture-run.txt` `EXECUTABLE_DENIED`; `src/fixture-link` `SYMLINK_DENIED`. README changed in the project; none of the git hook, postinstall, key file, exec-bit file or symlink landed; the dummy key never appeared in the result. `git status --short` showed exactly ` M README.md` and ` M src/greet.js`.
  - The dummy key and the exec bit are on **separate** fixture files (`src/fixture-key.txt` has the key and no exec bit; `src/fixture-run.txt` has the exec bit and no key), so `SECRET_DETECTED` and `EXECUTABLE_DENIED` each fire on their own change rather than one masking the other.
- **Monitor (per gateway, `/events` + `/health`):** fs gateway showed the three decisions (ALLOW `write_file`, DENY `PROTECTED_PATH read_text_file`, DENY `PERSISTENCE_PATH write_file`); attack gateway showed ALLOW `format_readme` and ALLOW `get_call_counts`. `/health.instance.pid` matched the gateway child's pid in both. No dummy secret (`AKIAIOSFODNN7EXAMPLE`) in either stream. The gateway is launched with the default safe environment, without `CERBERUS_TTY_APPROVAL` and without declaring form elicitation, so every DENY stays a DENY.

**Exact commands run (Docker 29.9.2, `mcp-firewall-sandbox:dev`):**
- `npm run sandbox:build` — built the image with the fixture at `/app`.
- `npm run demo:pitch -- --auto` — **run 3× in a row, `PITCH DEMO PASSED` each time** (now 1 applied / 5 rejected in Act 3); afterward 0 containers labeled `mcp-firewall=1` and 0 leftover temp dirs.
- `npm run demo:env` — **run 3× in a row, `.env SUITE PASSED` each time** (after the hardlink fix in [DECISIONS §18](docs/DECISIONS.md); it `FAILED` on the `src/notes.txt` row before). No leftover containers or temp dirs.
- `npm run typecheck` — passes.
- `npm run demo` — still `DEMO PASSED` (mock mode); `demo/project` and `git status` of the repo clean apart from the new/edited files.

If a policy change ever starts blocking the Act 1 edit, that is a policy regression to raise with Winston (owner of `src/security/*`), not something `demo/pitch.ts` works around.

### `.env` access suite — `npm run demo:env` (2026-10-25)

A red-team probe (`demo/env-suite.ts`, script `demo:env`) that throws every `.env` access vector we could think of at a sandboxed gateway and checks that **no dummy secret value leaks** into a tool result, the monitor stream, or the gateway's stderr. It runs on a throwaway git copy of `demo/project` (never modified) that also gets `.env.local`, `src/.env`, `config/.env.production`, a relative symlink `src/env-link -> ../.env`, and a **hardlink** `src/notes.txt` to `.env` (each dummy file carries a shared sentinel). Vectors 1-6 go through the fs config; then the fixture's new `probe_env` tool runs under the attack config and reports, from inside the container, only `absent` / `present, N bytes, matches-dummy: yes/no` — never contents. The fixture gained `probe_env`; `config/pitch-attack.yaml` approves `tool/probe_env` (the pitch demo never calls it).

Result table (deterministic across 3 runs, **after** the hardlink fix below):

```
vector                             decision  rule               reached  leaked
read .env                          DENY      PROTECTED_PATH     no       no
read ./.env                        DENY      PROTECTED_PATH     no       no
read /workspace/.env               DENY      PROTECTED_PATH     no       no
read src/../.env                   DENY      PROTECTED_PATH     no       no
read .ENV (case)                   DENY      PROTECTED_PATH     no       no
read .env/ (trailing slash)        DENY      PROTECTED_PATH     no       no
read %2e%2e/.env (encoded)         DENY      PROTECTED_PATH     no       no
read file:///workspace/.env        DENY      PROTECTED_PATH     no       no
read .env.local                    ALLOW     —                  yes      no
read src/.env                      DENY      PROTECTED_PATH     no       no
read config/.env.production        ALLOW     —                  yes      no
read src/env-link (symlink)        ALLOW     —                  yes      no
read src/notes.txt (hardlink)      ALLOW     —                  yes      no   ← was YES before the fix
read_multiple [greet.js, .env]     DENY      PROTECTED_PATH     no       no
get_file_info .env                 DENY      PROTECTED_PATH     no       no
read_media_file .env               DENY      PROTECTED_PATH     no       no
move_file .env -> src/moved.txt    DENY      PROTECTED_PATH     no       no
write_file .env                    DENY      PROTECTED_PATH     no       no
search_files ".env"                DENY      PROTECTED_PATH     no       no
directory_tree /                   ALLOW     —                  yes      no
list_directory /                   ALLOW     —                  yes      no

probe_env (inside the container):
/workspace/.env                   absent
/workspace/.env.local             absent
/workspace/src/.env               absent
/workspace/config/.env.production absent
/workspace/src/env-link           absent    (dangling: target .env is excluded from staging)
/workspace/src/notes.txt          absent    (was "present, 137 bytes, matches-dummy: yes" before the fix)
```

**`demo:env` PASSES, run 3× identically.** No dummy value appeared in any tool result, monitor stream, or gateway stderr (the firewall's events carry argument key names only). The directory/list vectors did not surface any `.env` file name.

**The hardlink leak — found by this suite, now FIXED ([DECISIONS §18](docs/DECISIONS.md)).** `src/notes.txt` is a hardlink to `.env`. Before the fix, `staging.sync()` scanned it as a `special` entry (nlink > 1) **but still with its `sha256`**, and `copyToStaging` copied any entry that had a `sha256` — so the hardlinked `.env` bytes landed in staging under the non-excluded name `src/notes.txt`, where the sandboxed server read them (the row above was `leaked: YES`, `probe_env` said `present … matches-dummy: yes`). The symlink never leaked (recreated, not followed; its target is excluded, so it dangles). **Fix in `src/proxy/staging.ts` (Aarav's module):** a project regular file with `nlink > 1` (and every device/socket/fifo) is now treated like an excluded path — scanned but not mirrored, never hashed; a server write at such a path is reported, forced `DENY` (`WRITE_NOT_ALLOWED`), never applied, and removed; and `apply()` refuses to write through any `special` project path (a `rename` would rewrite every link). The copy re-checks `nlink`/`dev`/`ino` on the open fd (`O_NOFOLLOW` + `fstat`), so a file that gains a link between the scan and the copy is not mirrored either. Cost: a legitimately hardlinked source file is no longer mirrored or writable. Covered by 5 new cases in `tests/staging.test.ts` (296 unit tests pass).

**For Winston (pre-call `src/security/*` gaps — all currently caught only by staging, layer 2):**
- `protectedPaths` is `**/.env`, which matches `src/.env` but **not** `.env.local` or `config/.env.production` (basename ends in `.env.local` / `.env.production`). Both were ALLOWed pre-call; only the staging exclusion (`.env.*`) kept them out of the sandbox. Staging is now the only thing standing between these and a leak — harden the pre-call check too: extend `protectedPaths` to `**/.env*` or add `.env.*` patterns.
- `src/env-link` (a symlink to `../.env`) was ALLOWed pre-call; it only failed to leak because the target is absent from staging. A symlink whose target *is* present would be read through.
- The case variant (`.ENV`), trailing slash (`.env/`), `src/../.env` and `%2e%2e/.env` were all caught here as `PROTECTED_PATH` (the `**/.env` glob matched the normalized/suffix form), so the previously-noted case/traversal/trailing-slash gaps did **not** open a hole for the root `.env` in this run — but they remain worth hardening, since they rely on the glob rather than on path canonicalization.

## Docker integration: verified (2026-10-24)

- **Tests:** `tests/upstream-docker.test.ts` with Docker 29.9.2 and `node:22-slim`, integration tests included (36/36 now).
- **Live container** (`config/sandbox.yaml`, `docker inspect`): network `none`, read-only root, CapDrop `ALL` (CapEff 0), `no-new-privileges`, user `501:20`, 512m / 128 pids, `/tmp` tmpfs `noexec,nosuid`, one bind mount: the staging mirror at `/workspace`.
- **Preflight:** refuses to start with Docker stopped and with the image missing; nothing is pulled and no staging dir is left.
- **Fixes from the first Docker run** (PR #17):
  - `start`/`dev` run `node --import tsx`: under the `tsx` CLI, Ctrl-C SIGKILLed the firewall before cleanup and left the staging dir behind every time ([DECISIONS §13](docs/DECISIONS.md)). Verified: 3/3 Ctrl-C runs of `npm start` leave no staging dir and no container.
  - Stale staging-dir sweep at startup, guarded by an owner file (pid, start time) next to the mirror, never inside `/workspace`. Verified: after a SIGKILL, the next start removes the dir.
  - Preflight now says "docker CLI not found" or "the Docker daemon isn't responding (is Docker running?)" instead of `(Error)`.
  - `npm run test:docker`: the integration tests fail instead of skipping without Docker.
  - Startup failures after the staging area exists (sync, launch mapping, preflight, launch, proxy) close the downstream and remove the staging dir, logging a failed cleanup instead of masking the original error. CLI tests cover a failed sync and a missing image.

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

- ~~Docker is not installed on Aarav's machine~~: installed; integration tests verified (see above).
- ~~**A fake `docker` passed preflight on a fresh clone**~~ (found 2026-10-24, fixed on `aarav/fix-docker-shadowing`). The `docker@1.0.0` npm package from `d566d4e` (a docco doc generator) installs `node_modules/.bin/docker`. `npm run` and `npx` put `node_modules/.bin` first on PATH, so under `npm test`, `npm run test:docker` and `npm start` every docker command the firewall ran was the doc generator. It exits 0 for anything, so `docker version` and `docker image inspect` "passed" preflight and `docker run` started no container. Startup still failed closed (connect timeout, no local fallback), but a fresh clone failed 3 tests and sandbox-mode `npm start`. Aarav's checkout never installed the package, so it passed there. All 27 `npm audit` findings came from its dependency tree. Fixed:
  - `npm uninstall docker` (`package.json` and lockfile; 137 packages removed, no other version changed; nothing imported it).
  - `src/proxy/upstream.ts` finds the docker CLI on a PATH without `node_modules/.bin` or relative entries (`dockerSearchPath`), for preflight, `run`, `rm` and the orphan sweep alike.
  - Preflight runs `docker version --format '{{json .}}'` and requires a non-empty `Server.Version`; otherwise `SandboxUnavailableError`: "the docker on PATH is not the Docker CLI". Still no shell, no pull, no local fallback. See [DECISIONS §17](docs/DECISIONS.md).
  - Tests: a fake `docker` in a temp `node_modules/.bin` on PATH is never run (even one printing valid version JSON); a fake that exits 0 with junk fails preflight and is called once, for `version` only; six junk-output cases; every docker command's PATH is filtered. Each test was checked to fail with its half of the fix removed.
  - **Removed:** `doc/doc-filelist.js`, `doc/doc-script.js`, `doc/doc-style.css`, also added in `d566d4e`. They were that generator's output (default `--output_dir ./doc`; `doc-script.js` was its `res/script.js` verbatim; a run regenerated them byte for byte), and nothing referenced them.
- ~~`src/security/evaluator.ts` is the deny-all stub~~: Winston's real evaluator landed on `main` in PR #4 (`40ea8e4`). With the shipped policy it returns ALLOW / PROTECTED_PATH / DENIED_DESTINATION / DENIED_TOOL for the four demo calls, consistent with design §7.
- ~~`demo/mock-server.ts` is a stub~~: landed in PR #3 (`6a7f51d`).
- **Release gate (§10): verified on a fresh clone** of `aarav/fix-docker-shadowing` (2026-10-24), not just this machine's checkout: `npm ci`, `npm audit` (0 vulnerabilities), `npm run typecheck`, `npm test` (274 passed), `npm run test:docker` (46 passed; fails if Docker or `node:22-slim` is missing), `npm run demo`, and sandbox mode started with `npm start -- --config config/sandbox.yaml` plus the sandbox check (allowed `src/greet.js` edit lands; `.husky/pre-commit` and a `package.json` `postinstall` rejected with `PERSISTENCE_PATH`; no container or staging dir left). Machine prerequisites no npm step provides: Docker running, `docker pull node:22-slim` (Docker tests) and `npm run sandbox:build` (sandbox mode).
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

## Needs contract agreement

Not changed in `src/shared/contracts.ts`; each needs Aarav, Winston and Kritish to agree.

- **`WRITE_ALLOWED`**: proposed rule ID for an allowed file change (PR #11). Until then, ALLOW decisions carry whatever `ruleId` the evaluator returns (the tests use `APPROVED_TOOL`).
- **`EVALUATION_ERROR` for file changes**: used by `staged-call.ts` when `evaluateFileChanges` throws or returns malformed output. The contract documents it only for tool-call evaluation failures. See [DECISIONS §12](docs/DECISIONS.md).
- **Startup changes**: reported with `WRITE_NOT_ALLOWED` ("change made before any tool call"), not a dedicated rule ID.

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
   - ~~**integration:** have the config loader map `server.sandbox` onto `UpstreamLaunch` (exported from `src/proxy/upstream.ts`, with TSDoc on every field) and pass it as `connectUpstream(config.server, { launch })` in `src/index.ts`. Docker mode is selected only that way.~~ Done (PR #18).
5. ~~Shutdown hook for the monitor~~: already in place. `src/index.ts` closes it on shutdown, and port 3000 is freed after SIGINT.
6. **Staged writes:**
   - ~~Contract PR~~: merged (PR #10). See [DECISIONS §9](docs/DECISIONS.md).
   - ~~`src/proxy/staging.ts`~~: merged (PR #11).
   - ~~Docker launch mode in upstream~~: merged (PR #12). Integration tests verified with Docker (2026-10-24).
   - ~~Interceptor integration~~: merged (PR #16).
   - **Next, in order:**
     1. ~~Run the docker-upstream integration tests on `main` with Docker~~: done; fixes merged (PR #17).
     2. ~~**Kritish: `toUpstreamLaunch` in the config loader.**~~ Done (PR #18). Map `server.sandbox` (and `policy.staging`) onto `UpstreamLaunch` from `src/proxy/upstream.ts`. Refuse to load if sandbox mode is set without `policy.staging`.
     3. ~~**`src/index.ts` wiring**~~: done (PR #18), in this order. Each step must throw and stop startup on failure:
        1. `createStagingArea({ projectRoot, extraExcludes, maxFileBytes, maxChangesPerCall })` from `policy.staging`
        2. `initial = await area.sync()`
        3. `toUpstreamLaunch(config, area.stagingRoot)` → docker launch with `workspaceDir` = the staging dir
        4. preflight + launch: `connectUpstream(config.server, { launch })` (runs `docker version` / `docker image inspect` first)
        5. `await initStaging(staging, { serverId, initial })`

        Then pass `staging` to `createInterceptor` (with `onFileChangeEvent` wired to the monitor, Kritish), and call `area.dispose()` on shutdown.
   - ~~Swap the reject-all stub for Winston's `evaluateFileChanges`~~: done on `aarav/wire-change-evaluator`; the stub itself was deleted in PR #24.
7. **From the Cerberus 4.1 audit (2026-10-24)**, in order:
   1. ~~Restore the deleted suite; fix `npm run test:docker`~~: done for Aarav's suites. Other owners: decide on the monitor, events, contracts, security and e2e suites.
   2. ~~Inject `evaluateFileChanges` in `src/index.ts`; `GAP 1g` → plain test~~: done.
   3. ~~Orphan sweep, `--pull=never`, async `publish`; container removed before the client closes; `--memory-swap` = `--memory`; `onFileChangeEvent` thenable observed~~: done.
   4. **Blocked on Winston:** wire `getSession` or drop the unused taint input (Aarav does the wiring).
   5. **Blocked on the team:** agree on DECISIONS §15 and the `BlockNotice` shape. Aarav then runs the Claude Code 2.1.310 elicitation spike (declared capability on our `2025-11-25` connection, Esc and no-answer behavior, cancel on timeout) before implementing.
   6. ~~Team: review the `docker` npm dependency added in `d566d4e`~~: removed (it shadowed the Docker CLI; see Blockers), along with its generated `doc/` output.
8. Optional, after acceptance tests: forward `list_changed`. Consider logging a clearer warning when the monitor port is taken, e.g. "events from this instance will not appear in the browser", and logging only the error code instead of the full `EADDRINUSE` object and stack.
