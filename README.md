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

It blocks policy-violating calls even when an indirect prompt injection caused them, but it doesn't necessarily detect the injected text. The monitor and the dialog are presentation surfaces, not the enforcement boundary. This is a prototype, not a complete security boundary: **use only dummy secrets.**

## Ownership

Edit only the files you own. Changes to **shared** files need a quick agreement from all three people.

| Area | Files | Owner |
| --- | --- | --- |
| Contract | `src/shared/contracts.ts` | **Shared** |
| Tooling | `package.json`, `package-lock.json`, `tsconfig.json`, `vitest.config.ts` | **Shared** |
| Gateway, Docker, staging, client adapter | `src/proxy/*`, `src/index.ts`, `tests/proxy*.test.ts`, `tests/staging.test.ts`, `tests/upstream-docker.test.ts` | Aarav |
| Policy and approval semantics | `src/security/*`, `tests/security*.test.ts`, `tests/approval.test.ts`, policy semantics in `config/*.yaml` | Winston |
| Monitor, config loader, setup, demo, docs | `src/observability/*`, `src/config/*`, `demo/*`, `tests/e2e.test.ts`, `tests/monitor.test.ts`, `README.md`, `docs/cerberus.md`, `docs/SETUP.md` | Kritish |
| Shared tests | `tests/firewall.test.ts`, `tests/events.test.ts`, `tests/fixtures/*` | **Shared** |

### Git workflow

- `main` always passes `npm run check`.
- Each person works on their own branches (`aarav/…`, `winston/…`, `kritish/…`). Commit often and merge small.
- Don't rewrite teammates' modules. Don't silently change request or event shapes.

## Contract notes

`src/shared/contracts.ts` implements design §5:

- **Zod schemas are the source of truth.** Every type is `z.infer` of its schema, so validation and types can't drift apart.
- **`RuleId` is a closed enum** (listed above). `EVALUATION_ERROR` is used by the proxy, never the evaluator, so a throwing evaluator still fails closed.
- **`FirewallPolicy`** adds `pathArgs`, `destinationArgs`, `destructiveTools`, `writeTools`, `allowedRoots`, `allowedHosts` and `staging` (`writablePaths`, `protectedWritePaths`, `maxFileBytes`, `maxChangesPerCall`).
- **`FirewallConfig`** wraps `server` (one downstream stdio server, with an optional `sandbox`), `monitor` (loopback host, port, ring-buffer size) and `policy`. Unknown keys are rejected.
- **Canonical tool names** are always built with `toCanonicalToolName(serverId, toolName)`, giving e.g. `"fs/read_text_file"`.
- **Cross-team signatures:** `EvaluateToolCall` and `EvaluateFileChanges` (Winston → Aarav), `PublishEvent` (Kritish → Aarav).

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
