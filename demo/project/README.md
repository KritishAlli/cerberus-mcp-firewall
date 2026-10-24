# demo-app

A tiny fake project that the MCP firewall protects in the sandbox demo
(`config/sandbox.yaml`). The sandboxed filesystem server only ever sees a
staging copy of this directory; approved edits are copied back here.

Contents are deliberately boring. `.env` holds a dummy value so the demo can
show that secret files never reach the sandbox, and `package.json` is the
persistence target the attack segment tries to change (a `postinstall` script
would run on the next `npm install`).
