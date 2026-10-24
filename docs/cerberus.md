# Cerberus: Project Design and Build Plan

> Product plan for evolving `mcp-firewall` into Cerberus. Follow the numbered structure and ownership model in [`design.md`](design.md). Treat the repository code and [`PROJECT_STATUS.md`](../PROJECT_STATUS.md) as the source of truth for what already works.

**Team:** Aarav, Winston, Kritish · **Initial users:** the three team members, each on a local checkout · **Product:** local Docker-backed protection gateway and developer-facing blocked-action experience

# 1. Mission and scope

**Pitch:** Cerberus helps developers use agentic coding tools and outside MCP tools with a local protection layer. The coding agent connects to Cerberus as its MCP gateway. Cerberus checks routed tool calls and staged file changes against explicit policy, runs configured downstream servers in Docker where supported, and explains blocked actions to the developer.

**Primary use case:** An agent encounters untrusted project content or a risky outside tool request. Cerberus blocks a policy-violating action before the downstream tool receives it and gives the user a concise explanation and safe next step.

**User experience:** Cerberus should feel like a small plugin/integration in the coding workflow. When an action is blocked, the user should get a small dialog or equivalent client-native notice that names the tool, explains the policy rule safely, and offers a clear next step. The existing local monitor remains the place to review recent activity and protection status.

**Initial scope:** Local use by Aarav, Winston, and Kritish, with each person maintaining their own checkout and policy. No shared accounts, remote policy service, telemetry, marketplace, or cloud control plane in this project phase.

**Not a universal endpoint firewall:** Cerberus protects only calls that a supported client routes through it. It does not automatically intercept built-in shell/editor tools, direct MCP connections that bypass the proxy, arbitrary host processes, or network requests from servers not contained by its Docker sandbox. Do not claim otherwise.

**Current state:** The repo already has an MCP gateway, policy evaluation, Docker launch path, staged filesystem writes, and a loopback monitor. Client-side setup/onboarding and a blocked-action dialog are future product work. The monitor reporting zero events while a tool call is enforced has been observed and needs diagnosis; treat different-process explanations as hypotheses until verified.

# 2. Architecture and trust boundaries

```text
Coding agent
    │ MCP (configured by the developer)
    ▼
Cerberus gateway ──► policy evaluation ── DENY ──► blocked result + user explanation
    │                       │
    │ ALLOW                 └──► redacted event ──► local monitor / client notice
    ▼
Docker sandbox: configured outside MCP server
    │ /workspace is a staging copy; no network in sandbox mode
    ▼
Cerberus reviews staged file changes and applies only permitted changes
```

- Keep the existing stdio MCP gateway and deterministic policy engine as the enforcement path. A UI must never be the authority that decides whether a call was safe.
- A DENY is final unless a supported, explicit approval mechanism is deliberately designed and reviewed. Missing UI, timeout, disconnect, malformed response, or no user choice keeps the action denied.
- Docker sandbox mode must keep its current fail-closed behavior: if Docker or the configured image is unavailable, do not launch the downstream server locally as fallback.
- The configured filesystem server gets a staging copy, not a read-write mount of the real project. Preserve staged-change policy evaluation, conflict checks, and revert behavior.
- The monitor stays bound to `127.0.0.1` by default. It is for local visibility, not remote administration.
- MCP server descriptions and tool output are untrusted data. They never alter policy.

# 3. Technology and implementation constraints

- Preserve the repository's TypeScript/Node.js 22+, MCP SDK, Zod, YAML config, and Vitest stack unless a written design decision explains a necessary change.
- Prefer a client adapter boundary for UI notifications. An MCP server cannot assume it can open a native host dialog. Check each target client's documented extension, hook, or approval APIs before implementing an adapter.
- First support only clients for which the integration can be installed, exercised, and tested. For other clients, the MCP tool result should carry a safe blocked explanation; the local monitor remains available.
- Do not add a required external LLM, database, analytics system, or cloud service.
- Any package, shared schema, startup composition, or config-format change requires agreement from all three owners before implementation.

# 4. Team ownership and work split

Each person owns one workstream. Work in parallel only behind the shared interfaces in §5. Avoid editing another person's owned files without coordinating first.

## 4.1 Aarav — gateway, Docker boundary, client adapter

**Owns:** `src/proxy/*`, `src/index.ts`, upstream launch and shutdown behavior, client integration adapter/runtime, and proxy tests.

**Tasks:**

1. Audit and preserve the existing no-forward-on-deny path, Docker preflight, no-fallback behavior, container cleanup, and staged-call integration.
2. Design the narrow client adapter boundary for a real supported client's blocked-action dialog or notification. Verify the host API before committing to native UI behavior.
3. Pass a structured, bounded, safe blocked result to the adapter (tool name, decision, rule ID, redacted reason, request ID). Adapter failure must not resume or retry a blocked tool call.
4. Keep the MCP gateway fully usable without a UI adapter. Unsupported clients still receive an MCP error/result that explains the block.
5. Add tests proving denied calls are never forwarded and adapter timeout/failure/disconnect preserves DENY.

**Done when:** Allowed calls still work; denied calls reach no downstream tool; Docker cannot silently fall back; the client adapter has a demonstrated integration or is explicitly documented as blocked on unavailable host APIs.

## 4.2 Winston — policy, approval semantics, security review

**Owns:** `src/security/*`, policy semantics, policy-focused fixtures/tests, and review of security-sensitive contracts.

**Tasks:**

1. Audit current policy and staged-write decisions against Cerberus use cases. Keep default-deny behavior for unclassified sensitive actions.
2. Define exactly what a user can do from a blocked-action dialog. Default action is **Block**. If implementing “Allow once,” scope it to one request, make it expire, record the approval, and prevent it from changing persistent policy. Do not implement broad “trust” shortcuts in this phase.
3. Ensure paths, URLs, tool arguments, and displayed reasons are normalized/validated safely; secrets and full file contents must never appear in dialog payloads or events.
4. Threat-model UI spoofing, stale approvals, request correlation, concurrent calls, malformed adapter responses, and monitor disconnects. Record decisions in `docs/DECISIONS.md`.
5. Add tests for policy outcomes, approval scope/expiry if present, event redaction, and fail-closed handling.

**Done when:** Each allow/deny decision has a deterministic rule ID; approval cannot silently broaden policy; tests cover adversarial and malformed inputs; residual limits are documented in plain language.

## 4.3 Kritish — onboarding, monitor, user documentation, end-to-end validation

**Owns:** `src/observability/*`, `src/config/load.ts`, `config` examples/docs, `README.md`, `docs/cerberus.md`, demo and end-to-end tests, and user setup guidance.

**Tasks:**

1. Diagnose the observed “protecting 1 server, zero events” issue using request IDs and process/config diagnostics. Establish whether the fault is instance mismatch, event publication, SSE delivery, or UI rendering before changing the design.
2. Keep monitor status honest: distinguish gateway protection from monitor availability, show real events only, bound history, redact sensitive fields, and report disconnection clearly.
3. Write the setup and removal instructions for each actually supported client. Include prerequisites, Docker image build, per-developer config, a safe allowed-call check, a blocked-call check, and recovery steps.
4. Add onboarding/config preview and backup/rollback only if it can safely update the client's MCP config without overwriting unrelated settings. Otherwise document manual configuration.
5. Ensure the demo uses dummy secrets and proves both enforcement and event delivery through the actual process.

**Done when:** A teammate can follow the guide from a clean checkout, connect a supported client, see an allowed call and a real blocked event, understand unsupported coverage, and remove the integration safely.

# 5. Shared integration contract and boundaries

Before parallel implementation, the three owners agree on and freeze the smallest interface needed for an event/notice. Extend existing schemas only by agreement; do not change the enforcement decision contract just to fit the UI.

A blocked-action notice should contain only bounded, non-secret fields, conceptually:

```ts
interface BlockNotice {
  requestId: string;
  serverId: string;
  toolName: string;
  decision: 'DENY';
  ruleId: string;
  reason: string; // redacted and safe for display
  summary: string; // bounded; no raw arguments or file contents
}
```

Contract invariants:

- The policy decision is made before any downstream invocation.
- Event/notice publishing and UI rendering cannot change the decision.
- A denied request is never forwarded or retried automatically.
- User approval, if implemented, applies only to the specific pending request and does not mutate persistent policy.
- Missing or invalid adapter responses fail closed.
- Events and notices correlate to one request ID and never include full raw arguments, credentials, or file contents.
- The monitor and dialog are presentation surfaces, not enforcement boundaries.

# 6. Blocked-action dialog behavior

The dialog should be small and interrupt only when a call is blocked. It should show:

- The blocked tool/server and a short human-readable explanation.
- The policy rule ID and request correlation ID in a details area.
- A safe next step, such as “continue without this action” or “review the local policy.”
- **Block** as the default and unambiguous action.

Do not show raw arguments or secret values. Do not present a green success state for an unresolved request. Do not add an approval button unless §4.2's scoped semantics and §5's contract are implemented and tested. When the host cannot display a dialog, return a clear MCP blocked result and let the monitor show the event.

# 7. User setup for the current prototype

The repo currently provides a usable sandbox demo, not a polished installer. Use a disposable project and dummy credentials.

## 7.1 Build and run

From the inner `mcp-firewall` directory:

```bash
nvm use
npm ci
npm run sandbox:build
node --import tsx src/index.ts --config config/sandbox.yaml
```

The command runs a stdio MCP gateway and should remain active while connected. The monitor is at `http://127.0.0.1:3000/`. Stop a manually started instance with Ctrl+C after disconnecting the client. Do not run a manual process alongside a client-managed instance using the same monitor port.

`config/sandbox.yaml` targets the disposable `demo/project`. Before using another project, back it up and review `server.sandbox.project`, `policy.staging.writablePaths`, `policy.staging.protectedWritePaths`, `policy.protectedPaths`, and tool policy. Docker must be available, and the image must be built locally. The firewall refuses to start if these requirements are not met.

## 7.2 Configure Codex on the current development machine

Add this MCP server to `~/.codex/config.toml`, adapting absolute paths to the local checkout. The Node path shown is the verified executable for the current development setup:

```toml
[mcp_servers.mcp_firewall]
command = "/Users/winstonluo/.nvm/versions/node/v22.23.4/bin/node"
args = [
  "--import", "tsx",
  "/Users/winstonluo/Documents/programming/mcp-firewall/mcp-firewall/src/index.ts",
  "--config", "/Users/winstonluo/Documents/programming/mcp-firewall/mcp-firewall/config/sandbox.yaml"
]
```

Install dependencies first so `--import tsx` resolves. Restart Codex and confirm `mcp_firewall` is connected. Do not use a guessed Node path; use the Node 22 executable installed on that machine. This example is specific to this checkout and is not a general installer.

## 7.3 Verify and troubleshoot

Ask the agent to use only `mcp_firewall`:

1. List `/workspace` and summarize it. This is the safe baseline.
2. Attempt `read_text_file` on `/workspace/.env`, without trying another path. Confirm it is denied and record the rule ID.
3. List `/Users/winstonluo/Documents/programming/mcp-firewall/mcp-firewall/demo/test-downloads`. This should be outside the container's allowed root and denied.

If the monitor reports a live server but zero events, stop any manually launched process, close other Codex tasks, fully restart Codex, then repeat the safe listing while watching the monitor. If it still shows zero, capture firewall stderr and the exact MCP server configuration. Treat process mismatch as an unconfirmed hypothesis. A successful deny response proves enforcement for that request; it does not prove the monitor is receiving events.

## 7.4 Remove the current integration

Remove only the `[mcp_servers.mcp_firewall]` entry from `~/.codex/config.toml`, preserving unrelated entries, then restart Codex. Stop any manually running gateway. Removing the MCP entry disconnects the client; it does not delete project files or the repository.

# 8. Configuration and deployment model

- Each developer has a local config and local monitor. No shared credentials or policy service.
- Keep `config/sandbox.yaml` as the safe demo example. Add a separate, clearly named per-user example only after its paths and policy have been validated.
- Do not put credentials in YAML, events, command-line arguments, or logs. Only explicitly configured environment variables may be passed to a downstream container.
- Docker images are built locally from reviewed sources. Do not auto-pull and execute an image at gateway startup.
- Client setup must be reversible and preserve unrelated config. A config writer must preview changes and keep a recoverable backup.

# 9. Test plan and acceptance criteria

- **A1 Enforcement:** allowed tool is forwarded exactly once; a denied tool is forwarded zero times.
- **A2 Sandbox:** Docker constraints remain enabled; missing Docker/image fails startup and never launches locally.
- **A3 Staging:** only policy-approved staged changes reach the project; conflicts and rejected changes preserve the user's files.
- **A4 Notice:** blocked notice explains tool and rule without leaking raw arguments, credentials, or file contents.
- **A5 Fail closed:** UI timeout, adapter error, missing response, malformed response, or user dismissal leaves the call denied.
- **A6 Scope:** any approval is single-request, auditable, and does not update persistent policy.
- **A7 Monitor:** a real allowed and denied call appear with correct request IDs; event delivery is verified end to end, not with synthetic UI state.
- **A8 Client setup:** documented supported-client install and removal work from a clean config without overwriting unrelated entries.
- **A9 Limits:** docs say exactly which tools are routed, which are not, and when Docker isolation applies.
- **A10 Regression:** existing typecheck and test suite remain green; relevant Docker integration tests run when Docker is available.

Do not claim the popup feature complete until a real supported client displays it and the deny/failure behaviors are tested. If no available host API supports a dialog, deliver a clear MCP blocked result and document that the dialog is deferred.

# 10. Milestones and coordination

1. **Agree and audit:** All three owners review the current implementation and contract. Aarav maps client APIs; Winston reviews approval/threat boundaries; Kritish reproduces monitor event delivery. Record decisions before broad code changes.
2. **Vertical slice:** Aarav wires the adapter boundary and fail-closed path; Winston signs off on notice/approval semantics; Kritish validates the real event and documents the supported client. Keep the dialog action Block-only for this slice.
3. **Onboarding and hardening:** Kritish completes setup/removal guidance and monitor diagnosis; Aarav validates client lifecycle and Docker cleanup; Winston completes policy and redaction review.
4. **Release review:** All three run acceptance criteria §9 on the same revision. Report unsupported integrations and known gaps; do not ship a mock dialog as a completed feature.

Keep changes small and reviewable. Coordinate shared contract, package, config-schema, and startup changes in advance. Preserve current unrelated working-tree changes when implementing this plan.
