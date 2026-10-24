# MCP Firewall

> A local firewall for AI agents. It intercepts MCP tool calls, evaluates explicit security policies, blocks unauthorized requests before they reach the downstream server, and shows humans what happened in real time.

Cal Hacks 13.0 · Aarav, Winston, Kritish · Full design: [`docs/design.md`](docs/design.md)

**Status: scaffold.** The shared contract, config loader and project tooling are in place. The proxy, policy engine, monitor and demo are stubs. The evaluator stub **denies everything** by design.

## Quick start

```bash
nvm use            # Node 22.12+
npm ci
npm run check      # typecheck + tests (must stay green on main)
```

| Script | What it does |
| --- | --- |
| `npm run typecheck` | `tsc --noEmit` (strict) |
| `npm test` | Vitest, all `tests/*.test.ts` |
| `npm start` | Runs the firewall as a stdio MCP server using `config/firewall.yaml` |
| `npm run mock-server` | Runs the controlled demo MCP server on its own |
| `npm run demo` | Deterministic benign + blocked scenarios with the live monitor |

Release gate (design §10): `npm run typecheck`, `npm test` and `npm run demo` all succeed on one clean laptop.

## How it works

```text
Claude Code ──stdio──▶ MCP Firewall ──stdio──▶ downstream MCP server (demo/mock-server.ts)
                         │  1. normalize request → ToolCallContext
                         │  2. evaluateToolCall(ctx, policy)   (pure, sync)
                         │  3. publishEvent(redacted event)    → monitor at http://127.0.0.1:3000
                         └  4. ALLOW → forward  ·  DENY → MCP error, downstream never called
```

## Ownership

Edit only the files you own. Changes to **shared** files need a quick agreement from all three people.

| Area | Files | Owner |
| --- | --- | --- |
| Contract | `src/shared/contracts.ts` | **Shared** (frozen) |
| Tooling | `package.json`, `package-lock.json`, `tsconfig.json`, `vitest.config.ts` | **Shared** |
| Proxy and enforcement | `src/proxy/*`, `src/index.ts`, `tests/proxy.test.ts` | Aarav |
| Policy engine | `src/security/*`, `tests/security.test.ts`, policy semantics in `config/firewall.yaml` | Winston |
| Monitor, config, demo | `src/observability/*`, `src/config/load.ts`, `demo/*`, `tests/e2e.test.ts`, README | Kritish |
| Baseline tests | `tests/contracts.test.ts` | **Shared** |

### Git workflow

- `main` always passes `npm run check`.
- Branch per person: `aarav/proxy`, `winston/policy`, `kritish/monitor`. Commit often and merge small.
- Don't rewrite teammates' modules. Don't silently change request or event shapes.

## Contract notes

`src/shared/contracts.ts` implements design §5, with these additions agreed at bootstrap:

- **Zod schemas are the source of truth.** Every type is `z.infer` of its schema, so validation and types can't drift apart.
- **`RuleId` is a closed enum** holding the 7 rule IDs from §7, plus `EVALUATION_ERROR`, which the proxy uses when evaluation throws (fail closed).
- **`FirewallPolicy` additions:** `pathArgs` (argument names that carry paths), `destinationArgs` (per-tool arguments that carry URLs, as §7 requires) and `destructiveTools`.
- **`FirewallConfig`** wraps `server` (the one downstream stdio server: `id`, `command`, `args`, `cwd`, `timeoutMs`), `monitor` (loopback host, port, ring-buffer size) and `policy`. Unknown keys are rejected.
- **Canonical tool names** are always built with `toCanonicalToolName(serverId, toolName)`, giving `"demo/read_project_file"`.
- **Cross-team signatures:** `EvaluateToolCall` (Winston → Aarav) and `PublishEvent` (Kritish → Aarav).

## Configure Claude Code

TODO(Kritish): verified steps for pointing Claude Code at the firewall instead of the downstream server, e.g. an MCP server entry whose command is `npx tsx /abs/path/to/mcp-firewall/src/index.ts`.

## What is protected, and what is not

The firewall guards **only MCP tool calls configured to pass through it**. It does **not** intercept:

- Claude Code's built-in tools (Bash, Read, Write, …)
- direct MCP connections that bypass the proxy (T14)
- network traffic made by an MCP server process itself
- resource reads or prompts that are not explicitly routed and evaluated
- malicious code that runs when a server starts

It blocks policy-violating calls even when an indirect prompt injection caused them, but it does not necessarily detect the injected text. Static argument screening does not defend against symlink/TOCTOU tricks or file access hidden inside a remote tool. This is a prototype, not a complete security boundary: **use only dummy secrets.**
