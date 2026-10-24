# Staged writes plan

Implemented contract differs slightly from this sketch: ChangeDecision.ruleId uses the closed RuleIdSchema, FirewallPolicy.staging is optional (sandbox mode requires it), and FileChange paths are strictly validated. See src/shared/contracts.ts.

Agreed direction, Fri Oct 23 2026, ~22:30. Top priority. Earlier least-privilege items (tool pinning/hiding, result redaction, session taint, allowedRoots/allowedHosts) come after this.

## Goal

The downstream MCP server never touches the real project. It runs in a sandbox against a staging copy. After every allowed call, the firewall diffs the copy, checks each change against policy, and copies only approved changes back to the real project.

## Flow per tools/call

1. Argument policy (existing). DENY means blocked and nothing runs.
2. ALLOW: take the staging lock (one call at a time).
3. Sync staging with the real project (minus excluded files).
4. Forward the call to the sandboxed server.
5. After the result, error or timeout: scan staging and diff against the pre-call snapshot.
6. `evaluateFileChanges` decides each change.
7. Apply approved changes to the real project (temp file + rename). Skip a file if the real copy changed since the snapshot (WRITE_CONFLICT).
8. Revert rejected changes in staging.
9. Return the tool result plus a note listing rejected changes. Publish a FileChangeEvent.

Any staging failure: apply nothing, fail closed.

## Sandbox

- Docker: `--network none --read-only --cap-drop ALL --security-opt no-new-privileges --user 1000:1000 --pids-limit 128 --memory 512m`, tmpfs `/tmp`, staging dir mounted rw at `/workspace`, server code mounted ro at `/server`. Nothing else from the host.
- The protected project is `demo/project/`, not our own repo.
- The staging copy excludes `.git/`, `node_modules/` and protected secret files like `.env`, so the server can't even read them.
- Changes made at server startup, before any call, are reverted and reported.
- Network tools don't work in sandbox mode. Intended for MVP.
- Sandbox mode with no Docker available: refuse to start. Node permission mode is a documented fallback only.

## Contract additions (src/shared/contracts.ts, one PR, everyone approves)

```ts
type FileChangeKind = 'add' | 'modify' | 'delete' | 'mode' | 'symlink' | 'special';

interface FileChange {
  path: string;          // posix, relative to project root, normalized
  kind: FileChangeKind;
  size?: number;
  executable?: boolean;  // new or changed exec bit
  linkTarget?: string;   // symlinks only
  text?: string | null;  // text files under maxFileBytes, for secret scanning; never logged or streamed
}

interface ChangeDecision { path: string; decision: Decision; ruleId: string; reason: string }

// pure, synchronous, one decision per change, same order
evaluateFileChanges(changes: FileChange[], policy: FirewallPolicy): ChangeDecision[];

// FirewallPolicy gains:
staging: { writablePaths: string[]; protectedWritePaths: string[]; maxFileBytes: number; maxChangesPerCall: number };

interface FileChangeEvent {
  timestamp: string; requestId: string; serverId: string; toolName: string;
  applied: number; rejected: number;
  changes: { path: string; decision: Decision; ruleId: string }[]; // max 20, paths truncated, never contents
}
```

New rule IDs: WRITE_NOT_ALLOWED, PERSISTENCE_PATH, SYMLINK_DENIED, EXECUTABLE_DENIED, SECRET_DETECTED, CHANGE_LIMIT, WRITE_CONFLICT.

## Tasks

### Aarav (src/proxy/*, src/index.ts, tests/proxy.test.ts, tests/fixtures/*)

1. Draft the contract PR.
2. `src/proxy/staging.ts`: create the staging dir, initial copy with excludes, snapshot manifest (path → type, size, mode, sha256), sync, diff into `FileChange[]`, atomic apply with conflict check, revert. Never follow symlinks while copying or diffing, refuse paths that escape the root, report hardlinks/devices as `special`.
3. Interceptor integration: staging lock, diff after every allowed call (including timeout/error), apply/revert, result note, `_meta['mcp-firewall/staged']`, FileChangeEvent.
4. Docker launch mode in upstream; refuse to start in sandbox mode without Docker.
5. Tests with `tests/fixtures/malicious-server.ts`: unsandboxed baseline shows the damage; sandboxed + staged shows an allowed write landing in the real project, while persistence writes, symlinks, exec bits, secrets and protected deletes are rejected with the real project unchanged; startup tampering reverted; conflict detected.
6. After that: tool pinning/hiding, result redaction, session taint.

### Winston (src/security/*, tests/security.test.ts)

1. `src/security/changes.ts` with `evaluateFileChanges`:
   - path must match `writablePaths`, else WRITE_NOT_ALLOWED
   - `.git/**`, `.github/workflows/**`, `.husky/**`, `.vscode/**`, `.idea/**`, `.claude/**`, `.mcp.json`, `package.json`, lockfiles, `Makefile`, shell rc files → PERSISTENCE_PATH
   - any symlink → SYMLINK_DENIED; new exec bit → EXECUTABLE_DENIED; `special` → deny
   - secret patterns in `text` → SECRET_DETECTED (share patterns with argument scanning)
   - over `maxFileBytes` → CHANGE_LIMIT; over `maxChangesPerCall` → reject all with CHANGE_LIMIT
   - deletes only inside `writablePaths` and never of persistence paths
2. 15+ tests: case variants, traversal-looking names, nested paths, empty input.
3. Afterwards: allowedRoots/allowedHosts for arguments, scan all string argument values.

### Kritish (src/observability/*, src/config/load.ts, demo/*, tests/e2e.test.ts, README)

1. Config schema + loader for `server.sandbox` (Docker image, mounts) and `policy.staging`. Invalid config refuses to start.
2. `demo/sandbox/Dockerfile`: node:22-slim, non-root user, server code only.
3. `demo/project/`: small fake project with a dummy `.env` and a `.git/hooks` dir.
4. Demo downstream: real `@modelcontextprotocol/server-filesystem /workspace` in the container, plus a malicious demo server for the attack segment.
5. Monitor shows FileChangeEvents, e.g. "2 applied, 1 rejected: .git/hooks/pre-commit PERSISTENCE_PATH". Never contents.
6. Attack suite, e2e, and `npm run demo` showing an allowed edit landing in demo/project, a hook install rejected, and the real project otherwise unchanged.
7. README: how staging works, Docker requirement, limitations.

## Order

1. Contract PR merged tonight.
2. Parallel build with stubs (reject-all evaluator stub; staging tested with fixtures).
3. Integration: Docker + real filesystem server + staging end to end.
4. Attack suite, demo, README.

Cut first if late: Node fallback, unicode lookalike cases, conflict display in the monitor.

## Honest limits

- Docker shares the host kernel; it isn't a VM-grade boundary.
- Reads inside the staged copy are allowed (excluded files aside). With no network, the server can only leak data through tool results to the agent.
- Claude Code's built-in tools still bypass all of this.
- A timed-out call's late writes are caught at the next diff and still policy-checked.
- Large projects make sync slow; MVP targets small projects.
