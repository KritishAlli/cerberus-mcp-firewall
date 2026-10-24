# MCP Firewall: Project Design (v2)

> Converted from `mcp_firewall_project_design_v2.docx`. This is the source of truth the team and coding agents read.

**Cal Hacks 13.0 \| October 23–25, 2026 \| Team: Aarav, Winston, Kritish \| Version 2.0**

# 1. Project mission and non-negotiable scope

**Pitch:** A local firewall for AI agents that intercepts MCP tool calls, evaluates explicit security policies, blocks unauthorized requests before downstream execution, and shows humans what happened in real time.

**Primary use case:** Indirect prompt injection (for example, untrusted repository content instructs an agent to read a dummy credential and send it away). The firewall does NOT need to recognize the hostile prose; it blocks the resulting unauthorized MCP action. **Secondary case:** untrusted/poisoned MCP tool calls or unapproved tools; the firewall can restrict calls routed through the proxy, but cannot sandbox arbitrary server startup code.

**Product boundaries:** This is the firewall itself. Build no skill manager, marketplace, user accounts, generic agent platform, complex analytics, cloud deployment, fine-tuned model, or required external LLM. The only human UI is a minimal, read-only local monitoring page plus clear CLI output.

**Success:** A normal MCP tool call succeeds; a forbidden call is denied and NEVER reaches the downstream server; the monitor immediately shows the decision, rule and safe summary. Tests prove all three.

# 2. Architectural decision and limits

**Chosen MVP:** TypeScript/Node.js local stdio MCP gateway (acting as the MCP server to Claude Code and as the MCP client to one controlled downstream MCP server). Use the official MCP TypeScript SDK v2 (`@modelcontextprotocol/server`, `@modelcontextprotocol/client`) and supported stdio transports. The proxy must expose tools, preserve names/schemas and forward permitted `tools/call` results. Avoid implementing generic byte-level JSON-RPC rewriting if an SDK method exists.

**Request flow:** Claude Code → local MCP gateway → normalize request → Winston's synchronous policy evaluator → ALLOW: call downstream MCP server, return result / DENY: produce MCP-compatible error or tool error, never invoke upstream tool → publish redacted event to Kritish's monitor.

**What is protected:** Only MCP requests configured to pass through this gateway. It does NOT intercept Claude Code built-in Bash/Read tools, direct MCP connections bypassing the proxy, network traffic from an MCP server process, resource reads/prompts not explicitly routed and evaluated, or malicious code executed when starting a server. Do not claim universal endpoint firewall coverage.

**MVP constraint:** One downstream server and stdio first; support multiple downstream servers, tool name collisions, HTTP transports, or Claude-specific hooks only after all acceptance tests pass. During demo use harmless mock tools and dummy secrets exclusively.

# 3. Technology choices

- Runtime: Node.js 22+; TypeScript strict; npm with committed lockfile; tsx for local dev.

- MCP: official stable TypeScript SDK v2 server + client packages; validate exact SDK APIs against the pinned installed version and docs.

- Types and validation: Zod v4 for config, boundary inputs, decisions and events.

- Policies: deterministic TypeScript rules and YAML config; no required model calls.

- Monitoring: Hono local HTTP endpoint bound to 127.0.0.1, Server-Sent Events (SSE), plain HTML/CSS/TypeScript; no React.

- Logging: Pino structured JSONL or a tiny structured writer; ensure secrets are redacted before persistence or streaming.

- Testing: Vitest; end-to-end calls through proxy to controlled mock MCP server; optional Playwright only if spare time.

- No DB, Docker, Redis, Kafka, queues, authentication service, or cloud required. Local monitor is not suitable for remote exposure.

**Example installation (verify versions before committing):** `npm install @modelcontextprotocol/server @modelcontextprotocol/client zod yaml pino hono` and `npm install -D typescript tsx vitest @types/node`.

# 4. Repository structure and file ownership

```text
mcp-firewall/
  src/
    shared/contracts.ts        # SHARED; one initial schema freeze
    proxy/server.ts            # Aarav: expose tools to client
    proxy/upstream.ts          # Aarav: stdio downstream connection
    proxy/interceptor.ts       # Aarav: enforcement path
    security/evaluator.ts      # Winston: policy decision
    security/rules.ts          # Winston: matchers and precedence
    security/normalize.ts      # Winston: paths, URLs and argument validation
    observability/events.ts    # Kritish: event bus / redaction
    observability/monitor.ts   # Kritish: localhost HTTP/SSE
    observability/index.html   # Kritish: live, read-only UI
    config/load.ts             # Kritish: YAML parsing and validation
    index.ts                   # Aarav: startup composition; coordinate edits
  config/firewall.yaml         # Winston defines policy; Kritish documents
  demo/mock-server.ts          # Kritish: fake tool server
  demo/scenarios.ts            # Kritish: repeatable benign/blocked tests
  tests/security.test.ts       # Winston
  tests/proxy.test.ts          # Aarav
  tests/e2e.test.ts            # Kritish
  README.md                    # Kritish lead; all review
  package.json                 # Shared initial setup only
```

**Git boundaries:** Each person edits only owned directories after shared scaffolding. Changes to contracts, index, package.json or config shape require a quick agreement. Integrate frequently; preserve passing code; do not rewrite teammates' modules.

# 5. Frozen integration contract (implement first)

The policy engine must be a pure, fast synchronous function: `evaluateToolCall(request: ToolCallContext, policy: FirewallPolicy): PolicyDecision`. It must not call the MCP SDK, perform network I/O, or write logs. The proxy invokes it before forwarding. Kritish consumes a redacted event derived from the same decision.

```ts
export type Decision = 'ALLOW' | 'DENY';
export interface ToolCallContext {
requestId: string; // generated correlation ID
serverId: string; // stable configured server identity
toolName: string; // exact exposed tool name
arguments: Record<string, unknown>;
}
export interface PolicyDecision {
decision: Decision;
ruleId: string; // e.g., PROTECTED_PATH
reason: string; // safe to show user; no credentials
}
export interface FirewallEvent {
timestamp: string; // ISO 8601
requestId: string;
serverId: string;
toolName: string;
decision: Decision;
ruleId: string;
reason: string;
summary: string; // redacted, bounded length
durationMs?: number;
}
export interface FirewallPolicy {
defaultDecision: Decision;
protectedPaths: string[];
deniedDestinations: string[];
approvedTools: string[]; // canonical serverId/toolName
deniedTools: string[];
}
```

**Contract invariants:** Input is validated before evaluation; policy returns one decision and rule for every input; unknown/unparseable sensitive operations DENY; event emission must not change the allow/deny result; events never include full raw arguments or file contents; JSON strings and values are length-limited. A DENY calls no upstream tool. A downstream failure cannot silently turn a DENY into an ALLOW.

# 6. Enforcement and protocol behaviors (Aarav)

1\. Connect to the approved downstream stdio MCP server; support its normal initialization handshake and tool listing. Do not allow the downstream server to write protocol-breaking output to stdio; capture diagnostics on stderr.

2\. Expose a corresponding tool listing to the agent. Preserve tool names, descriptions and input schemas for the one-server MVP. Document that descriptors are untrusted; do not elevate tool description text into a policy instruction.

3\. On each `tools/call`, validate name and argument shape, construct ToolCallContext, invoke security evaluator, record the resulting FirewallEvent, and forward ONLY if ALLOW.

4\. Return the downstream result unchanged where SDK permits; for DENY return a clearly recognizable MCP-compatible rejected response (test client behavior). No downstream invocation on DENY. Timeouts, lost downstream connections, invalid policy or exceptions fail closed for sensitive operations.

5\. Keep correlation IDs, useful errors, cancellation handling where supported, and no secrets in error strings. Record upstream invocation count in the mock server for proof.

6\. CLI launch starts proxy and monitor together (monitor failure must not bypass policy). Log protocol messages only over stdio, diagnostics to stderr. Avoid adding bypass flags in the demo.

**Aarav done when:** Safe call forwarded once with same semantics; forbidden call forwarded zero times; invalid/unknown request handled without crash; Claude Code can connect to the proxy as its configured MCP server.

# 7. Detection / policy behaviors (Winston)

**Precedence:** invalid input or unknown sensitive tool → deny; explicit denied server/tool → deny; protected resource → deny; forbidden destination → deny; destructive operation → deny; explicit approved safe tool → allow; otherwise use configured default, with DENY as MVP default for unclassified actions. Never rely on naive substring matches alone.

**Protected paths:** Normalize `/`, `..`, tilde expansion where appropriate, Windows/path separator cases as relevant to target OS, and known file arguments such as `path`, `filePath` or `filename`. Use path-aware matching, not `includes('.env')`; protect dummy `~/.aws/credentials`, `.env`, SSH keys, and any configured path. Be explicit that static argument screening does not defend against symlink/TOCTOU or hidden file access within a remote tool.

**Destinations:** Parse URLs, compare normalized hostname/origin to deny/allow patterns; reject malformed URLs on protected send/upload tools. Detect approved tools such as `upload`, `send`, `post`, `fetch` based on a configured argument map rather than assuming every MCP tool has identical semantics.

**Destructive commands:** For demo shell-like tools, block configured dangerous actions (delete of protected paths, unsafe shell execution). Parsing arbitrary shell correctly is outside MVP; constrain to mock tool schemas, not a pretend universal shell sanitizer.

**Avoid false positives:** Allow benign project read, harmless repository summary, and permitted local outputs. Add tests for similarly named paths, encoded URLs, nonexistent args, arrays, nested objects and unknown tools. Record rule IDs: `INVALID_ARGUMENTS`, `DENIED_TOOL`, `PROTECTED_PATH`, `DENIED_DESTINATION`, `DESTRUCTIVE_ACTION`, `APPROVED_TOOL`, `DEFAULT_DENY`.

**Winston done when:** Pure evaluator passes at least 12 deterministic test cases and explains every allow/deny without exposing secrets.

# 8. Local monitor, config, integration and demo (Kritish)

**Human experience:** User keeps using Claude Code. Firewall runs as its MCP gateway. Optional browser at `http://127.0.0.1:3000` shows: protection status, total inspected/allowed/denied counters, latest-first live decision feed, timestamp, tool/server, safe argument summary and rule explanation. Read-only: no accounts, charts, permission editing, security-score widgets, or admin workflows.

**Implementation:** Hono serves a static page and `/events` SSE; browser uses `EventSource`. Add `/health` with `{status:'ok', protectedServers:1}` from actual live state, not fake green indicator. Use a bounded in-memory event ring (e.g., last 100 events) for initial page load and live updates; optionally write redacted JSONL. Rate-limit/bound payload size to avoid leaking data or exhausting memory. Bind only to loopback. If no browser, CLI stderr logs still make decisions visible.

**Config:** YAML loader validates syntax and schema on startup; no silent permissive fallbacks. Ship a minimal local example with mock server command, approved tools, protected paths and denied destinations. Document how Claude Code is configured to call proxy instead of upstream; include command snippets verified on local machine.

**Demo harness:** Controlled MCP server tools include `read_project_file` (safe), `read_sensitive_file` (dummy path), `send_data` (simulated external destination) and `delete_file` (simulated). Record server-received call counts. Create a benign README and a malicious README whose content asks an agent to fetch dummy credentials; never connect to real secrets or transmit payload to a real external host. Make a deterministic direct MCP client test that always attempts the blocked call; also try an optional Claude-driven prompt injection demonstration, whose model behavior may vary.

**Kritish done when:** One command runs the demo with visible live monitor; e2e asserts safe forwarded once and block forwarded zero; browser displays real events; README and short pitch are reproducible.

# 9. Example policy, events and UX

```yaml
# config/firewall.yaml (illustrative; keep synchronized with actual parser)
defaultDecision: DENY
protectedPaths:
- ~/.aws/credentials
- '**/.env'
deniedDestinations:
- example-attacker.invalid
approvedTools:
- demo/read_project_file
deniedTools:
- demo/delete_file
```

```json
{"timestamp":"2026-10-24T02:00:00Z","requestId":"demo-002","serverId":"demo","toolName":"read_sensitive_file","decision":"DENY","ruleId":"PROTECTED_PATH","reason":"Credential path is protected","summary":"Attempted protected file read"}
```

**Read-only monitor mock:** `Protection: ACTIVE | inspected 8 | allowed 6 | blocked 2` then chronological events `[ALLOW] demo/read_project_file - approved project file` and `[DENY] demo/read_sensitive_file - PROTECTED_PATH`. These are examples, NOT prepopulated numbers in the live UI.

# 10. Test matrix and acceptance criteria

- T01: Allowed safe file read → downstream receives exactly one call, correct result, ALLOW event.

- T02: Protected credential read → downstream receives zero calls, DENY/PROTECTED_PATH event.

- T03: Unapproved data destination → zero calls, DENY/DENIED_DESTINATION.

- T04: Simulated destructive tool → zero calls, DENY/DENIED_TOOL or DESTRUCTIVE_ACTION.

- T05: Unknown sensitive tool → zero calls and DEFAULT_DENY.

- T06: Invalid/missing/nested arguments → fail safely, no crash and no forbidden forwarding.

- T07: Benign similarly named path → allow if explicitly approved; no accidental broad match.

- T08: `../` traversal attempt against protected path → deny after normalization (within defined OS model).

- T09: Downstream disconnect/timeout → clear client error, no bypass.

- T10: Event stream lists actual decisions; monitor page updates without manual refresh.

- T11: Logs and SSE never contain dummy secret value, full raw sensitive arguments, or real credentials.

- T12: Policy file invalid → startup rejects config; no silent allow-all mode.

- T13: One full CLI-to-proxy-to-mock-server test; blocked calls never reach upstream.

- T14: Direct MCP connection bypass is documented as a limitation, not counted as protected.

**Release gate:** `npm run typecheck`, `npm test`, `npm run demo` all succeed on one clean laptop. In final demo show both the proxy-side deny and the mock-server received-call counter. No project is considered done based on UI-only fake data.

# 11. Collaboration contract and milestones

**Hour 0–1:** Everyone agrees on SDK version, stdio transport, `shared/contracts.ts`, test naming and startup command. Aarav owns initial repo bootstrap; Winston and Kritish use stub interfaces while upstream work is incomplete.

**Hours 1–6:** Aarav: upstream connection, tool discovery and allow path. Winston: policy evaluator, normalization and fixtures. Kritish: mock server, config loader, basic SSE event service and monitor shell. Work separately on branches; commit frequently.

**Hours 6–10:** Merge first vertical slice. Hard-coded blocked request exercises whole pipeline and shows in browser. Integrate schema changes by agreement; do not silently change request or event shapes.

**Hours 10–16:** Complete deny rules, error paths, redaction, e2e and false-positive tests. Stop adding tools or transports if main scenario is not solid.

**Hours 16–20:** Run benign + blocked scenarios, verify zero downstream calls for blocked operation, polish README and monitor readability. Optional Claude natural-language demo only after deterministic scenario works.

**Hours 20–24:** Freeze features, regressions, rehearse 2-minute live demo, record backup video, submit. Every member participates in end-to-end testing.

**Dependencies:** Aarav consumes Winston's pure policy API and Kritish's `publishEvent(event)` function. Winston must not import proxy code. Kritish consumes shared events but may test via stubbed events; his integration suite invokes real proxy when ready. File ownership prevents collision; shared types are frozen first.

# 12. Three copy-paste coding-agent instructions

## Aarav — MCP proxy and enforcement

You are Developer Aarav on a three-person 24-hour Cal Hacks project. Read THIS WHOLE DESIGN DOCUMENT first, especially sections 4–6, 10–11. Implement only `src/proxy/*`, initial `src/index.ts` orchestration, and `tests/proxy.test.ts`. Use TypeScript, Node.js 22+, official MCP SDK v2, and stdio. Implement a real MCP proxy: expose tools from one downstream mock MCP server, intercept `tools/call`, call the shared `evaluateToolCall`, DENY without forwarding, ALLOW with faithful forwarding, and publish a redacted structured event using Kritish's interface. Do not write your own policy rules or monitor UI. Use temporary stubs until teammates merge. Preserve existing code, do not modify teammates' owned modules, and coordinate changes to shared contracts. Prove that denied calls produce zero downstream invocations. Never claim to intercept non-MCP tools.

## Winston — deterministic security policy

You are Developer Winston on a three-person 24-hour Cal Hacks project. Read THIS WHOLE DESIGN DOCUMENT first, especially sections 5, 7, 9–11. Implement `src/security/*`, security unit tests, and policy semantics used by `config/firewall.yaml`. Export pure synchronous `evaluateToolCall(request, policy): PolicyDecision` from the shared contract. Return precise ALLOW/DENY and stable rule IDs; normalize target paths and destinations; default-deny unknown/ambiguous sensitive operations; support safe tools without overblocking. Do not modify proxy or monitor code. Use dummy fixture paths and destinations. Write at least 12 robust tests. Do not use an LLM as the enforcement oracle; coordinate any schema change before editing shared types.

## Kritish — monitor, demo, integration

You are Developer Kritish on a three-person 24-hour Cal Hacks project. Read THIS WHOLE DESIGN DOCUMENT first, especially sections 5, 8–11. Implement `src/observability/*`, `src/config/load.ts`, `demo/*`, `tests/e2e.test.ts`, and README. Build a read-only localhost Hono + SSE activity monitor that displays REAL redacted firewall events and real counters/status; never show credentials. Write a mock MCP server and deterministic end-to-end scenarios proving allowed calls reach upstream and denied calls do not. Configure Claude Code to use the proxy, document exact steps, and make a one-command demo. Do not implement proxy forwarding or security decisions yourself. Use stub events while teammates work; coordinate shared-contract edits; avoid React, DBs or cloud infrastructure.

# 13. Pitch, judging and technical honesty

**15-second pitch:** “AI agents can be tricked by instructions hidden in documents and repositories. Our MCP Firewall sits between the agent and its tools, blocks unauthorized calls before they reach the tool server, and shows exactly why in a live security monitor.”

**Live sequence:** (1) normal agent task and allowed tool call, (2) malicious instructions in a controlled README or direct simulated attack call, (3) forbidden attempt intercepted, (4) browser shows DENY and rule, (5) downstream mock server reports zero received forbidden calls, (6) normal task still succeeds. Prefer deterministic direct-call demonstration for reliability; the Claude-following-the-injection step is optional.

**Honest claims:** The tool guards configured MCP calls, not all system actions. It blocks policy-violating calls even when an indirect prompt injection caused them; it does not necessarily detect the injected text. It does not ensure an inherently malicious MCP server is safe to start. It is a prototype, not a complete security boundary, and should not run on real credentials during the demonstration.

**Reference docs:** Official MCP TypeScript SDK v2: https://ts.sdk.modelcontextprotocol.io/v2/ and MCP client guide: https://ts.sdk.modelcontextprotocol.io/v2/clients/connect ; always verify the exact API exposed by the pinned dependency before coding.
