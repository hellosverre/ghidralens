# The MCP server, containerised.
#
# What this image is for: letting a registry or a client start the server and
# introspect it - tools/list, resources/list - without installing anything.
# That works because the tool list is static and needs neither Ghidra nor the
# bridge.
#
# What it is NOT for: actual analysis. That needs the PyGhidra bridge, which
# needs a JDK, a Ghidra installation and the binary you want to look at, none of
# which belong in this image. Run the bridge on the host and point the container
# at it with GHIDRALENS_BRIDGE_URL - and note that 127.0.0.1 inside a container
# is the container, so it has to be host.docker.internal or a real address.

FROM node:22-alpine AS build
WORKDIR /app

# Manifests first so the dependency layer survives source-only changes.
COPY package.json package-lock.json ./
COPY server/package.json server/
COPY ui/package.json ui/
RUN npm ci

COPY . .
RUN npm run build

FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production

COPY --from=build /app/package.json /app/package-lock.json ./
# ui/dist is not optional: views.ts reads the built views from <app>/ui/dist, and
# without them every view renders a "not built yet" placeholder.
COPY --from=build /app/server/dist ./server/dist
COPY --from=build /app/ui/dist ./ui/dist
COPY --from=build /app/bridge ./bridge

RUN npm ci --omit=dev --ignore-scripts

# stdio transport: no port, no healthcheck. The client speaks JSON-RPC on stdin.
ENTRYPOINT ["node", "server/dist/index.js"]
