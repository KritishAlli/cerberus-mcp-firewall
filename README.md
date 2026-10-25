# Cerberus (MCP Firewall)

> A local firewall for AI coding agents. It intercepts MCP tool calls, evaluates explicit security policies, runs the downstream server in a Docker sandbox against a staging copy of your project, applies only the file changes policy allows, and shows humans what happened in real time.

Cal Hacks 13.0 · Aarav, Winston, Kritish · Design: [`docs/design.md`](docs/design.md) · Cerberus plan: [`docs/cerberus.md`](docs/cerberus.md)

**Status: working prototype.** Implemented and tested:

- MCP stdio gateway with policy enforcement: a denied call never reaches the downstream server.
- Docker sandbox mode with no network, a read-only root, and no fallback to running locally.
- Staged filesystem writes. Changes are diffed after every call, checked against policy, and copied back only if allowed. Conflicting or rejected changes leave your files untouched.
- Write-path checks before the call, so a protected path is denied even when the write wouldn't change anything.
- One-request overrides through the client's own dialog (MCP form elicitation). Block is the default.
- Loopback event monitor that shows which gateway process it belongs to.
- Client setup preview for Claude Code (verified) and Codex.

See [`PROJECT_STATUS.md`](PROJECT_STATUS.md) for what is verified and what is still open.

## Quick start

```bash
nvm use                 # Node 22.12+
npm ci
npm run check           # typecheck + tests (must stay green on main)
npm run demo            # must end with DEMO PASSED
npm run sandbox:build   # builds mcp-firewall-sandbox:dev locally (needs Docker; never pulled)
```

| Script | What it does |
| --- | --- |
| `npm run typecheck` | `tsc --noEmit` (strict) |
| `npm test` | Vitest, all `tests/*.test.ts` |
| `npm run test:docker` | Docker integration tests. They fail if Docker or `node:22-slim` is missing, instead of skipping |
| `npm start` | Runs the gateway as a stdio MCP server with `config/firewall.yaml`. Use `npm start -- --config config/sandbox.yaml` for sandbox mode |
| `npm run mock-server` | Runs the controlled demo MCP server on its own |
| `npm run demo` | Runs benign and blocked scenarios through a real gateway, then checks that the same request IDs arrived on **that** gateway's monitor |
| `npm run demo:pitch` | Narrated three-act demo in real Docker sandbox mode (see [Pitch demo](#pitch-demo)) |
| `npm run demo:env` | Red-team `.env` access suite in sandbox mode; fails (non-zero) if any dummy secret leaks |
| `npm run sandbox:build` | Builds the sandbox image from `demo/sandbox/Dockerfile` |

Release gate: `npm run typecheck`, `npm test` and `npm run demo` all pass on one clean laptop. Also run `npm run test:docker` when Docker is available.

## How it works

```text
Coding agent ──stdio──▶ Cerberus gateway ──stdio──▶ downstream MCP server
                          │                          (local, or Docker sandbox on a
                          │                           staging copy at /workspace)
                          │ 1. normalize request → ToolCallContext
                          │ 2. evaluateToolCall(ctx, policy)          (pure, sync)
                          │ 3. publishEvent(redacted event)           → monitor at http://127.0.0.1:3000
                          │ 4. DENY → client dialog (Block by default) → BLOCKED tool result
                          │    ALLOW, or one-request override → forward
                          └ 5. sandbox mode: diff staging → evaluateFileChanges → apply only allowed changes
```

- **Fail closed.** If evaluation throws, the config is invalid, Docker or the image is missing, or a dialog times out or is dismissed, the result is DENY. Nothing falls back to permissive behavior.
- **Overrides cover one request only.** Choosing *Allow this one request* forwards just that call, or applies just its safely applicable changes. The decision is recorded as `USER_APPROVED_OVERRIDE` and policy is not changed. Some denials, such as symlinks, oversized files and evaluator errors, never offer an override. Clients without form elicitation, and headless runs, keep every DENY. `CERBERUS_TTY_APPROVAL=1` turns on a `/dev/tty` prompt instead. Use it only when the gateway has its own terminal.
- **Blocked results** start with `[MCP Firewall] BLOCKED (<RULE_ID>)` and end with the request ID. The same ID appears on the monitor.

## Configs

| Config | Downstream | Use it for |
| --- | --- | --- |
| `config/sandbox.yaml` | `@modelcontextprotocol/server-filesystem` in Docker on a staging copy of `demo/project` | Real agent sessions |
| `config/firewall.yaml` | `demo/mock-server.ts`, local and **not sandboxed** | The demo and quick checks without Docker |
| `config/cerberus-codex-test.yaml` | Filesystem server in Docker on `demo/cerberus-codex-test`, monitor on port 3001 | Disposable Codex checks |

`src/config/load.ts` validates every config against `FirewallConfigSchema` and rejects unknown keys. Sandbox mode requires a `policy.staging` section. To protect another project, copy `config/sandbox.yaml` to `config/<name>.local.yaml` (git-ignored), back the project up, and review its paths and policy. See [`docs/SETUP.md` §2](docs/SETUP.md#2-choose-a-config).

## Configure an agent client

Follow [`docs/SETUP.md`](docs/SETUP.md). It covers prerequisites, connecting Claude Code and Codex, an allowed and a blocked check, troubleshooting (including zero events on the monitor), and removal. To print the exact commands for your machine without writing anything:

```bash
node --import tsx src/config/client-setup.ts --config config/sandbox.yaml
```

The printed command imports tsx by absolute file URL, so it also works when the agent starts outside this repo.

## Pitch demo

`npm run demo:pitch` tells the sandbox-mode story end to end against a **throwaway
git copy** of `demo/project` (the real `demo/project` is never touched). It needs
Docker and the sandbox image — build it once with `npm run sandbox:build` — and
never falls back to a local server: if Docker or the image is missing it exits
with a clear message.

Three acts, each with big PASS/FAIL output and a final `PITCH DEMO PASSED`:

1. **A legitimate edit is allowed.** An in-policy write to `src/greet.js` is
   ALLOWed and lands in the project. (This also confirms a plain source edit is
   not blocked as `PATH_NOT_ALLOWED`.)
2. **A prompt-injected agent is blocked.** On the same gateway, a read of `.env`
   and a write of a `postinstall` script into `package.json` are both BLOCKED
   before the downstream sees them (`PROTECTED_PATH`, `PERSISTENCE_PATH`); the
   `.env` value never appears in any output and `package.json` is unchanged.
3. **Silent side effects are stripped.** Restarted with an attack config, the
   gateway runs an inert test fixture (`demo/sandbox/side-effects-fixture.mjs`)
   whose `format_readme` appends one README line but also tries to install a git
   hook, a `postinstall` script, a dummy-key file, an exec-bit file and a symlink.
   Only the README line is applied; the other five are rejected by staging
   (`PERSISTENCE_PATH`, `SECRET_DETECTED`, `EXECUTABLE_DENIED`, `SYMLINK_DENIED`),
   and the result's `_meta['mcp-firewall/staged']` lists each with its rule ID.
   `git status` then shows only `README.md` and the Act 1 file changed.

Flags: `--auto` skips the between-act pauses (rehearsal / CI), `--keep` leaves the
temp project for inspection, `--monitor-port N` moves the monitor off its default.
Containers and the temp project are cleaned up on exit and on Ctrl-C.

`npm run demo:env` is a companion red-team suite: it throws ~20 `.env` access
vectors (dotenv spellings, case/trailing-slash/traversal forms, a symlink and a
hardlink to `.env`, multi-file reads, discovery tools) at a sandboxed gateway and
fails with a non-zero exit if any dummy secret value reaches a tool result, the
monitor stream, or the gateway's stderr. It also runs a `probe_env` tool inside
the container to confirm which files staging materialized.

## Rule IDs

Every decision carries one rule ID from the closed enum `RULE_IDS` in `src/shared/contracts.ts`:

- **Tool calls:** `APPROVED_TOOL`, `DENIED_TOOL`, `DEFAULT_DENY`, `PROTECTED_PATH`, `PATH_NOT_ALLOWED`, `DENIED_DESTINATION`, `HOST_NOT_ALLOWED`, `DESTRUCTIVE_ACTION`, `SESSION_TAINTED`, `INVALID_ARGUMENTS`, `EVALUATION_ERROR`
- **Staged writes:** `WRITE_NOT_ALLOWED`, `PERSISTENCE_PATH`, `SYMLINK_DENIED`, `EXECUTABLE_DENIED`, `SECRET_DETECTED`, `CHANGE_LIMIT`, `WRITE_CONFLICT`
- **Overrides:** `USER_APPROVED_OVERRIDE`

## What is protected, and what is not

Cerberus guards **only MCP tool calls that pass through it**. It does **not** intercept:

- the agent's built-in tools (Claude Code's Bash, Read, Write, …; Codex's shell and patch tools)
- direct MCP connections that bypass the proxy, such as other servers configured in the client (T14)
- network traffic or processes outside the Docker sandbox. The `config/firewall.yaml` downstream runs locally without a sandbox
- resource reads or prompts. Only tools are proxied
- malicious code that runs when a server starts

In sandbox mode the staging copy also shapes what the server can even see:

- Excluded files (`.env`, `.env.*`, `.git/`, `node_modules/`) are never copied into the sandbox, so the server cannot read them.
- **Hardlinked files are not mirrored.** A project regular file with more than one link (and any device/socket/fifo) is treated like an excluded path — not copied into staging, and never written through — so a file hardlinked to a secret like `.env` cannot smuggle its contents into the sandbox or overwrite it ([DECISIONS §18](docs/DECISIONS.md)). The cost is that a legitimately hardlinked source file is not visible or writable in sandbox mode.
- Symlinks are recreated, not followed; a link whose target is excluded simply dangles.

It blocks policy-violating calls even when an indirect prompt injection caused them, but it doesn't necessarily detect the injected text. The monitor and the dialog are presentation surfaces, not the enforcement boundary. This is a prototype, not a complete security boundary: **use only dummy secrets.**

## Docs

| Doc | Contents |
| --- | --- |
| [`docs/SETUP.md`](docs/SETUP.md) | Client setup, checks, troubleshooting, removal |
| [`docs/cerberus.md`](docs/cerberus.md) | Cerberus product plan, ownership and acceptance criteria |
| [`docs/design.md`](docs/design.md) | Original firewall design |
| [`docs/DECISIONS.md`](docs/DECISIONS.md) | Rationale for proxy and enforcement choices |
| [`docs/STAGED_WRITES_PLAN.md`](docs/STAGED_WRITES_PLAN.md) | Sandbox and staged-write design |
| [`docs/cerberus-proxy-audit.md`](docs/cerberus-proxy-audit.md) | Cerberus 4.1 proxy audit |
| [`PROJECT_STATUS.md`](PROJECT_STATUS.md) | Verified status, blockers, limitations, next steps |
