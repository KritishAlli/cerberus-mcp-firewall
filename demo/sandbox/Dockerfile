# Sandbox image for the downstream MCP server (docs/STAGED_WRITES_PLAN.md, DECISIONS §10).
#
#   docker build -t mcp-firewall-sandbox:dev demo/sandbox     (or: npm run sandbox:build)
#
# Holds server code only: the pinned filesystem server, nothing from the project.
# The firewall never pulls this image; build it from here so its contents are reviewable.
# At run time the firewall adds --network none --read-only --cap-drop ALL, no-new-privileges,
# a non-root --user, and mounts only the staging copy at /workspace (src/proxy/upstream.ts).

# node 22, pinned by digest so a rebuilt tag can't change what runs.
FROM node:22.23.4-slim@sha256:de170b39439eb0e5a3444ad7d60b015614a381e10fecae2e30ec9e735122f38d

ENV NODE_ENV=production
WORKDIR /app
COPY package.json package-lock.json ./
# Exact versions and integrity hashes from the lockfile; no package runs install scripts.
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force

# Inert test double for the pitch demo (npm run demo:pitch). Resolves the SDK
# from /app/node_modules. The firewall runs it explicitly via server.args; it is
# never the default downstream. Nothing it writes is code or a real credential.
COPY side-effects-fixture.mjs /app/side-effects-fixture.mjs

# The firewall overrides this with the host uid:gid; never root either way.
USER node
WORKDIR /workspace

# Default only: the firewall passes server.command and server.args explicitly.
CMD ["node", "/app/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js", "/workspace"]
