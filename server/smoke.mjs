/**
 * Smoke test: does the MCP server start, advertise the right tools, and serve
 * the ui:// resources with real HTML in them?
 *
 * This runs the real server over a real stdio transport with no Ghidra behind
 * it - which is exactly the state a first-time user is in, so the failure modes
 * it catches (a view that was never built, a tool whose _meta lost its
 * resourceUri, a bridge error escaping as a transport crash) are the ones that
 * actually bite.
 *
 *   node server/smoke.mjs
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { fileURLToPath } from "node:url";

const SERVER = fileURLToPath(new URL("dist/index.js", import.meta.url));

const EXPECTED_TOOLS = [
  "open_binary", "program_info", "decompile", "list_functions",
  "call_graph", "find_strings", "xrefs_to", "rename_symbol",
  "add_comment", "save_program",
];

const EXPECTED_VIEWS = [
  "ui://ghidralens/decompiler.html",
  "ui://ghidralens/functions.html",
  "ui://ghidralens/callgraph.html",
];

let failures = 0;
const check = (ok, label, detail = "") => {
  console.log(`${ok ? "  ok  " : " FAIL "} ${label}${detail ? " - " + detail : ""}`);
  if (!ok) failures++;
};

const client = new Client({ name: "ghidralens-smoke", version: "0.1.0" });
await client.connect(
  new StdioClientTransport({
    command: process.execPath,
    args: [SERVER],
    // A dummy token is enough: nothing here reaches the bridge, and without one
    // the server refuses to start at all.
    env: { ...process.env, GHIDRALENS_TOKEN: "smoke-test-token" },
    stderr: "ignore",
  }),
);

const { tools } = await client.listTools();
const names = tools.map((t) => t.name).sort();
check(
  EXPECTED_TOOLS.every((n) => names.includes(n)),
  `${tools.length} tools registered`,
  names.join(", "),
);

// Tools the UI drives must carry a resourceUri, or the host has nothing to open.
for (const tool of tools) {
  const uri = tool._meta?.ui?.resourceUri ?? tool._meta?.["ui/resourceUri"];
  if (["decompile", "list_functions", "call_graph"].includes(tool.name)) {
    check(typeof uri === "string" && uri.startsWith("ui://"), `${tool.name} -> view`, String(uri));
  }
}

// add_comment is app-only; the model must not see it as callable on its own.
const comment = tools.find((t) => t.name === "add_comment");
check(
  JSON.stringify(comment?._meta?.ui?.visibility) === '["app"]',
  "add_comment is app-only",
  JSON.stringify(comment?._meta?.ui?.visibility),
);

const { resources } = await client.listResources();
const uris = resources.map((r) => r.uri);
check(
  EXPECTED_VIEWS.every((u) => uris.includes(u)),
  `${resources.length} ui:// resources`,
  uris.join(", "),
);

for (const uri of EXPECTED_VIEWS) {
  const { contents } = await client.readResource({ uri });
  const body = contents[0];
  const built = !body.text.includes("has not been built yet");
  check(
    body.mimeType === "text/html;profile=mcp-app" && built && body.text.length > 10_000,
    `read ${uri}`,
    `${body.mimeType}, ${(body.text.length / 1024).toFixed(0)} KB${built ? "" : ", NOT BUILT"}`,
  );
}

// A dead bridge has to come back as a tool error, not as an exception that
// takes the transport down with it.
const result = await client.callTool({ name: "program_info", arguments: {} });
check(
  result.isError === true && result.content[0].text.includes("cannot reach"),
  "unreachable bridge degrades to a tool error",
  result.content[0].text.slice(0, 70),
);

await client.close();
console.log(failures ? `\n${failures} check(s) failed` : "\nall checks passed");
process.exit(failures ? 1 : 0);
