# Cerberus Codex Test Project

Disposable project used to check Cerberus MCP enforcement from Codex. Sandbox test passed. Sandbox test passed.

- `src/hello.js` is a safe file to read or edit through the firewall.
- `/workspace/.env` is intentionally absent; attempts to read it should be denied by policy.
- `package.json` is a protected write path; Cerberus should deny write attempts before they reach the filesystem server, even if the proposed contents are unchanged.

Use only the `cerberus_test` MCP server for these checks. The Codex built-in file and shell tools do not go through Cerberus.
