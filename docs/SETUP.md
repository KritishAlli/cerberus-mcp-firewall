# Setting up Cerberus with a coding agent

This guide connects a coding agent to the Cerberus gateway (`mcp-firewall`) on your own machine, checks one allowed and one blocked call, and removes the integration again. Each developer keeps their own checkout, config and monitor. Nothing is shared or sent anywhere.

| Client | Status |
| --- | --- |
| **Claude Code** | Supported. Add, connect (`✔ Connected`, sandbox mode, launched from an unrelated folder) and remove verified on 2026-10-24 with Claude Code 2.1.310 on macOS. |
| **Codex** | Manual TOML entry. Verified on Winston's machine (see [`cerberus.md` §7.2](cerberus.md)). Not re-verified on 2026-10-24 because Codex wasn't installed on the test machine. |
| Anything else | Not supported yet. Any MCP client that can launch a stdio server should work with the same command, but nobody has tested one. |

## What is protected, and what is not

Cerberus protects **only MCP tool calls that the client sends through it**. These are **not protected**:

- the agent's built-in tools (Claude Code's Bash, Read, Write, Edit…; Codex's shell and patch tools)
- other MCP servers configured directly in the client, which bypass the gateway
- network traffic or processes started by anything outside the Docker sandbox
- the downstream server in `config/firewall.yaml`, which runs as a **local, unsandboxed** process (only `server.sandbox` configs such as `config/sandbox.yaml` run in Docker)

In sandbox mode the downstream server runs in Docker with no network, a read-only root and a **staging copy** of the project at `/workspace`. Cerberus diffs the copy after every allowed call and applies only the changes that `policy.staging` allows to the real project.

## 1. Prerequisites

- **Node 22.12+.** `nvm use` in the repo picks the right version.
- **Docker** running, for sandbox mode. Check with `docker version`.
- A disposable project and **dummy secrets only**. `config/sandbox.yaml` targets `demo/project`, which is safe to use.

From the repo root:

```bash
nvm use
npm ci                    # installs tsx, which the gateway runs under
npm run sandbox:build     # builds mcp-firewall-sandbox:dev locally (never pulled)
npm run demo              # baseline: enforcement AND event delivery, no client involved
```

`npm run demo` must end with `DEMO PASSED`. It launches a real gateway, checks that blocked calls reach the downstream server zero times, then reads **that gateway's** monitor and checks that the same calls arrive with matching request IDs. If it fails at step 6 with `monitor belongs to … not pid …`, another gateway is holding port 3000. See [Zero events](#zero-events-on-the-monitor).

## 2. Choose a config

| Config | Downstream | Use it for |
| --- | --- | --- |
| `config/sandbox.yaml` | `@modelcontextprotocol/server-filesystem` in Docker on a staging copy of `demo/project` | Real agent sessions |
| `config/firewall.yaml` | `demo/mock-server.ts`, local and **not sandboxed** | The demo and quick checks without Docker |

To protect another project, copy `config/sandbox.yaml` to `config/<name>.local.yaml` (git-ignored) or outside the repo, **back the project up**, and review `server.sandbox.project`, `policy.staging.writablePaths`, `policy.staging.protectedWritePaths`, `policy.protectedPaths` and `policy.approvedTools`. If the config is invalid, or Docker or the image is missing, the gateway refuses to start. It never falls back to running the server locally.

## 3. Preview the client config

```bash
node --import tsx src/config/client-setup.ts --config config/sandbox.yaml
```

This prints the exact commands and snippets for **your** machine and **writes nothing**. Before printing, it loads the config and checks Node, tsx, Docker and the image. Any `NOT READY:` line names the fix. Use `--client claude` or `--client codex` to print one client, and `--scope user` for Claude Code everywhere.

The printed command uses only absolute paths, and imports tsx **by file URL**. A bare `--import tsx` resolves against the client's working directory, so it fails (`ERR_MODULE_NOT_FOUND`) whenever the agent is started outside this repo.

If the Node path contains `/Cellar/`, Homebrew will change it on the next upgrade. Use `/opt/homebrew/bin/node`, or the output of `which node`, instead.

## 4a. Connect Claude Code

Run the printed `claude mcp add` command. Its shape is:

```bash
claude mcp add --scope local mcp_firewall -- /path/to/node \
  --import file:///path/to/mcp-firewall/node_modules/tsx/dist/loader.mjs \
  /path/to/mcp-firewall/src/index.ts --config /path/to/mcp-firewall/config/sandbox.yaml
```

- `claude mcp add` edits only this entry and leaves other servers and settings alone, so no hand-edited config or backup is needed.
- `--scope local` registers the server only for the folder you run it from. Run it from the project you will open Claude Code in, or use `--scope user`.
- Check it: `claude mcp get mcp_firewall` should show `Status: ✔ Connected`. In a session, `/mcp` lists `mcp_firewall` and its tools.
- Gateway logs (stderr) on macOS: `~/Library/Caches/claude-cli-nodejs/<project-path-with-dashes>/mcp-logs-mcp_firewall/*.jsonl`. Claude Code labels every stderr line `"Server stderr: …"`, which does not mean an error.

## 4b. Connect Codex

Back up `~/.codex/config.toml`, then paste the `[mcp_servers.mcp_firewall]` table printed by the preview, without changing anything else in the file. Restart Codex and confirm that `mcp_firewall` is connected.

## 5. Check an allowed and a blocked call

Open the monitor at `http://127.0.0.1:3000/`. The header shows two separate statuses:

- **Monitor:** whether this page is connected, and **which gateway process** (pid and start time) it belongs to.
- **Gateway:** whether that gateway has a live downstream server.

Then ask the agent to use only `mcp_firewall`:

| # | Ask the agent to… | Expected result (sandbox config) |
| --- | --- | --- |
| 1 | list `/workspace` | Succeeds (`README.md`, `package.json`, `src`). Monitor: `ALLOW APPROVED_TOOL`. |
| 2 | read `/workspace/.env` with `read_text_file`, without trying another path; keep **Block** in the Cerberus dialog | Claude Code shows a Cerberus dialog naming the tool and `PROTECTED_PATH`. The tool result is `[MCP Firewall] BLOCKED (PROTECTED_PATH) …`. Monitor: `DENY PROTECTED_PATH` with the **same request ID**. |
| 3 | list a host path outside the project, e.g. this repo's `demo` folder; keep **Block** | The dialog names `PATH_NOT_ALLOWED`; the tool result remains `BLOCKED (PATH_NOT_ALLOWED)`. |
| 4 | (optional) write `/workspace/package.json`; keep **Block** | Cerberus denies the write before calling the filesystem server: `[MCP Firewall] BLOCKED (PERSISTENCE_PATH) …`. This also applies when the proposed contents are identical. The real file is unchanged. Monitor: `DENY PERSISTENCE_PATH`. |

Every DENY is shown in a dialog when the connected client supports MCP form elicitation. For an intentional one-request override, choose **Allow this one request** when offered. Cerberus forwards that specific policy-denied call or applies only the safely applicable rejected file changes, and records `USER_APPROVED_OVERRIDE`; the policy itself is unchanged. Block is preselected, and declining, cancelling, closing the dialog or leaving it open for 2 minutes keeps the DENY. Some sandbox denials (including oversized files, symlinks, evaluator failures, and changes that cannot be safely applied) show the block and reason but do not offer an override. For more than 12 rejected changes, Cerberus shows a summary and keeps them blocked. Do not allow unless you have reviewed the action or rejected paths shown in the dialog.

The dialog uses MCP form elicitation. In a client without it, or a headless run such as `claude -p`, every DENY stays blocked and is logged to the gateway's stderr. The old `/dev/tty` `[y/N]` prompt is off by default because it fights the client's own terminal UI for keystrokes. Set `CERBERUS_TTY_APPROVAL=1` only when the gateway runs in a terminal of its own and the client has no dialog.

The request ID at the end of a BLOCKED message is the correlation key. If you can't find it on the monitor, the monitor belongs to a different gateway.

**New directories:** An empty directory created under `policy.staging.writablePaths` stays in the disposable staging copy between calls; `create_directory` alone does not add it to the real project. If a later approved file write lands inside it, that file and its parent directories are applied. Directories outside writable paths or under protected/excluded paths are removed from staging at the next sync.

Claude Code may refuse a risky call itself before sending it, in which case it never reaches Cerberus. That is not a Cerberus result. `npm run demo` always sends the call.

## Troubleshooting

### Zero events on the monitor

Symptom: the monitor says `Gateway: protecting 1 server`, but calls the agent made never appear, even though they were blocked.

**Cause (reproduced on 2026-10-24):** only one process can listen on port 3000. When a second gateway starts (one per Claude Code session or Codex task, or a manual `node … src/index.ts` left running), its monitor fails with `EADDRINUSE`. It keeps enforcing policy, and its events go only to its own stderr. The page on :3000 belongs to the **first** gateway: it reports that gateway's healthy downstream and its empty event list. Event publishing, SSE delivery and rendering all work within a single process.

How to confirm and fix it:

1. Compare the pid in the monitor header (`Monitor: live · gateway pid N`) with the agent's gateway. Its log has `[firewall] monitor listening on … (gateway pid N)`, or this line if it lost the port:
   `MonitorPortInUseError: http://127.0.0.1:3000 is already in use, probably by another firewall instance. This gateway (pid M) still enforces policy, but its events will NOT appear on that monitor…`
2. Find who holds the port: `lsof -nP -iTCP:3000 -sTCP:LISTEN`.
3. Stop the other gateway (Ctrl+C on a manual one; close other agent sessions), then **restart the agent** so its gateway can take the port. Alternatively, give each config its own `monitor.port`.
4. Repeat check 2 and look for its request ID on the monitor.

A BLOCKED reply proves enforcement for that request. It doesn't prove that the monitor you're looking at received the event.

### Gateway won't start

| Message | Fix |
| --- | --- |
| `the Docker daemon isn't responding` / `docker CLI not found` | Start Docker. Cerberus won't run the server outside Docker. |
| image `mcp-firewall-sandbox:dev` missing | `npm run sandbox:build` |
| `ERR_MODULE_NOT_FOUND … tsx` | Run `npm ci`, and use the file-URL `--import` from the preview instead of a bare `tsx`. |
| `invalid firewall config` | Fix the YAML key it names. There is no permissive fallback. |
| `server.sandbox requires a policy.staging section` | Add `policy.staging`: a missing section never means "allow all writes". |

### Monitor shows "disconnected"

The page lost its event stream. It dims the counters and rows and labels them "last known data". That says nothing about enforcement: the gateway works without the page. If the gateway restarted, the page reconnects to the new process, starts a fresh feed and notes the pid change.

## Removing the integration

1. **Claude Code:** `claude mcp remove --scope local mcp_firewall`, using the scope you added it with. Only that entry is removed. Restart open sessions.
2. **Codex:** delete only the `[mcp_servers.mcp_firewall]` table from `~/.codex/config.toml` and restart Codex. Your backup from step 4b has the original.
3. Stop any manually started gateway with Ctrl+C.
4. Check that nothing is left running: `pgrep -fl src/index.ts` and `docker ps --filter ancestor=mcp-firewall-sandbox:dev` should both print nothing. Containers and staging copies are removed when the gateway exits, and a stale staging copy from a killed gateway is removed by the next start.
5. Optional: `docker image rm mcp-firewall-sandbox:dev`.

Removing the entry disconnects the client. It never deletes project files or the repository.
