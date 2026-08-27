/**
 * End-to-end test: MCP client -> MCP server -> bridge -> Ghidra.
 *
 * smoke.mjs proves the MCP surface with no Ghidra behind it. This one needs a
 * bridge that is actually running and holding an analysed program, and proves
 * the last link - that every tool returns the shape the views expect.
 *
 *   python bridge/serve.py --binary <path>          # in another terminal
 *   GHIDRALENS_TOKEN=<printed token> node server/live.mjs
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { fileURLToPath } from "node:url";

const SERVER = fileURLToPath(new URL("dist/index.js", import.meta.url));

let failures = 0;
const check = (ok, label, detail = "") => {
  console.log(`${ok ? "  ok  " : " FAIL "} ${label}${detail ? " - " + detail : ""}`);
  if (!ok) failures++;
};

const client = new Client({ name: "ghidralens-live", version: "0.1.0" });
await client.connect(
  new StdioClientTransport({
    command: process.execPath,
    args: [SERVER],
    env: { ...process.env },
    stderr: "ignore",
  }),
);

const call = async (name, args = {}) => {
  const result = await client.callTool({ name, arguments: args });
  if (result.isError) throw new Error(`${name}: ${result.content[0].text}`);
  return result.structuredContent;
};

const info = await call("program_info");
check(info.open === true, "program_info", `${info.name}, ${info.functionCount} functions`);

const list = await call("list_functions", { limit: 5, sort: "size" });
check(list.functions.length === 5, "list_functions", `${list.total} total`);

const target = list.functions[0];
console.log(`        target: ${target.name} @ ${target.address} (${target.size} bytes)`);

// Every field the views index into, checked here rather than discovered as a
// blank pane inside somebody's chat client.
const code = await call("decompile", { address: target.address });
check(Array.isArray(code.lines) && code.lines.length > 5, "decompile lines", code.lines.length);
check(
  code.lines.every((line) => line.every((t) => typeof t.kind === "string" && typeof t.text === "string")),
  "every token has kind + text",
);
check(
  code.lines.some((line) => line.some((t) => t.address)),
  "tokens carry addresses (rename/navigate depend on this)",
);
check(Array.isArray(code.locals) && Array.isArray(code.calls) && Array.isArray(code.callers),
  "sidebar arrays present",
  `${code.locals.length} locals, ${code.calls.length} calls, ${code.callers.length} callers`);

// The decompiler view resolves a clicked call by matching the token text
// against calls[] - so those names must actually appear in the token stream.
const calleeNames = new Set(code.calls.map((c) => c.name));
const clickable = code.lines
  .flat()
  .filter((t) => t.kind === "function" && calleeNames.has(t.text));
check(clickable.length > 0, "callee names appear as clickable tokens", `${clickable.length} sites`);

const graph = await call("call_graph", { address: target.address, depth: 2 });
check(graph.nodes.length > 0 && graph.root === target.address, "call_graph",
  `${graph.nodes.length} nodes, ${graph.edges.length} edges`);
check(
  graph.edges.every((e) => graph.nodes.some((n) => n.address === e.from) &&
                           graph.nodes.some((n) => n.address === e.to)),
  "every edge endpoint exists as a node (canvas layout assumes this)",
);

const xrefs = await call("xrefs_to", { address: target.address });
check(Array.isArray(xrefs.references), "xrefs_to", `${xrefs.references.length} refs`);

const strings = await call("find_strings", { limit: 5 });
check(strings.strings.length > 0, "find_strings", JSON.stringify(strings.strings[0]?.value ?? ""));

const renamed = await call("rename_symbol", { address: target.address, new_name: "gl_live_test" });
check(renamed.newName === "gl_live_test", "rename_symbol", renamed.renamed);
const after = await call("decompile", { address: target.address });
check(after.name === "gl_live_test", "rename visible on next decompile", after.name);

const commented = await call("add_comment", { address: target.address, text: "live test" });
check(commented.address === target.address, "add_comment", commented.address);

// Put it back, so re-running the test twice is not confusing.
await call("rename_symbol", { address: target.address, new_name: target.name });

const bad = await client.callTool({ name: "decompile", arguments: { name: "nope_zzz_not_here" } });
check(bad.isError === true && /no function named/.test(bad.content[0].text),
  "unknown function -> tool error, not a crash", bad.content[0].text.slice(0, 50));

await client.close();
console.log(failures ? `\n${failures} check(s) failed` : "\nall checks passed");
process.exit(failures ? 1 : 0);
