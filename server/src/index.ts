#!/usr/bin/env node
/**
 * GhidraLens - an MCP Apps server for Ghidra.
 *
 * The existing Ghidra MCP servers hand the model a wall of text and stop there.
 * The model can read it; you cannot navigate it. This one returns the same
 * analysis as an interactive view rendered inside the client: click an
 * identifier to rename it, click a call to follow it, click a graph node to
 * refocus. Both you and the model are looking at the same program state.
 *
 * Tool visibility is the mechanism that makes that work:
 *   ["model", "app"]  the model can call it, and so can the view
 *   ["app"]           view-only - the model never sees it in tools/list
 *
 * The view-only tools are the ones a click fires. Hiding them keeps the model's
 * tool list short and stops it from renaming things on its own initiative.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { registerAppTool } from "@modelcontextprotocol/ext-apps/server";
import { z } from "zod";

import { Bridge, BridgeError, bridgeFromEnv } from "./bridge.js";
import { VIEWS, registerViews } from "./views.js";

const SERVER_INFO = { name: "ghidralens", version: "0.1.0" };

/**
 * Every tool body runs through this. A failed decompilation or a bridge that is
 * not running is an ordinary outcome here, not a crash - the model should see the
 * reason as text and be able to act on it, so nothing is thrown out to the
 * transport.
 */
type ToolResult = {
  content: { type: "text"; text: string }[];
  structuredContent?: Record<string, unknown>;
  isError?: true;
};

async function guard<T extends object>(
  work: () => Promise<T>,
  summarise: (value: T) => string,
): Promise<ToolResult> {
  try {
    const value = await work();
    return {
      content: [{ type: "text", text: summarise(value) }],
      structuredContent: value as Record<string, unknown>,
    };
  } catch (error) {
    const message =
      error instanceof BridgeError
        ? error.message
        : error instanceof Error
          ? `${error.name}: ${error.message}`
          : String(error);
    return { content: [{ type: "text", text: message }], isError: true };
  }
}

function buildServer(bridge: Bridge): McpServer {
  const server = new McpServer(SERVER_INFO, {
    capabilities: { tools: {}, resources: {} },
    instructions:
      "Reverse-engineering tools backed by a live Ghidra session. Call " +
      "open_binary once, then decompile / list_functions / call_graph. Those " +
      "three render interactive views the user can click through; prefer them " +
      "over dumping raw text back into the conversation.",
  });

  registerViews(server);

  // ------------------------------------------------------------- session setup

  server.registerTool(
    "open_binary",
    {
      title: "Open binary",
      description:
        "Load an executable into the Ghidra session and run auto-analysis. " +
        "Slow the first time for a given file (seconds to minutes); cached in " +
        "the Ghidra project afterwards. Must be called before anything else.",
      inputSchema: {
        path: z.string().describe("Absolute path to the executable"),
        analyze: z
          .boolean()
          .optional()
          .describe("Run auto-analysis. Only set false if already analysed."),
      },
      annotations: { readOnlyHint: false, openWorldHint: false },
    },
    async ({ path, analyze }) =>
      guard(
        () => bridge.openBinary(path, analyze ?? true),
        (info) =>
          `Opened ${info.name} (${info.executableFormat}, ${info.languageId}) - ` +
          `${info.functionCount} functions, image base ${info.imageBase}.`,
      ),
  );

  server.registerTool(
    "program_info",
    {
      title: "Program info",
      description: "What is currently open: format, architecture, function count.",
      inputSchema: {},
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async () =>
      guard(
        () => bridge.info(),
        (info) =>
          info.open
            ? `${info.name} - ${info.executableFormat}, ${info.languageId}, ${info.functionCount} functions.`
            : "No binary open. Call open_binary first.",
      ),
  );

  // ------------------------------------------------------------------- views

  registerAppTool(
    server,
    "decompile",
    {
      title: "Decompile function",
      description:
        "Decompile one function to C and show it in an interactive view. " +
        "Identify the function by address (hex) or by name.",
      inputSchema: {
        address: z.string().optional().describe("Entry point, e.g. 0x140001000"),
        name: z.string().optional().describe("Function name, e.g. main"),
      },
      annotations: { readOnlyHint: true, openWorldHint: false },
      _meta: {
        ui: { resourceUri: VIEWS.decompiler.uri, visibility: ["model", "app"] },
      },
    },
    async ({ address, name }) =>
      guard(
        () => bridge.decompile({ address, name }),
        (d) =>
          `${d.signature} at ${d.address} - ${d.lines.length} lines, ` +
          `${d.calls.length} calls out, ${d.callers.length} callers.`,
      ),
  );

  registerAppTool(
    server,
    "list_functions",
    {
      title: "List functions",
      description:
        "Browse the program's functions in a sortable table. Filter by " +
        "substring; sort by address, name, size or caller count.",
      inputSchema: {
        query: z.string().optional().describe("Case-insensitive name filter"),
        limit: z.number().int().min(1).max(2000).optional(),
        offset: z.number().int().min(0).optional(),
        sort: z.enum(["address", "name", "size", "callers"]).optional(),
      },
      annotations: { readOnlyHint: true, openWorldHint: false },
      _meta: {
        ui: { resourceUri: VIEWS.functions.uri, visibility: ["model", "app"] },
      },
    },
    async (args) =>
      guard(
        () => bridge.listFunctions(args),
        (list) => `${list.functions.length} of ${list.total} functions.`,
      ),
  );

  registerAppTool(
    server,
    "call_graph",
    {
      title: "Call graph",
      description:
        "Draw the callers and callees around one function as a navigable graph. " +
        "Depth is capped at 3 because call graphs fan out exponentially.",
      inputSchema: {
        address: z.string().optional(),
        name: z.string().optional(),
        depth: z.number().int().min(1).max(3).optional(),
      },
      annotations: { readOnlyHint: true, openWorldHint: false },
      _meta: {
        ui: { resourceUri: VIEWS.callgraph.uri, visibility: ["model", "app"] },
      },
    },
    async ({ address, name, depth }) =>
      guard(
        () => bridge.callGraph({ address, name, depth }),
        (g) => `${g.nodes.length} functions, ${g.edges.length} call edges around ${g.root}.`,
      ),
  );

  // -------------------------------------------------------- model-only lookups

  server.registerTool(
    "find_strings",
    {
      title: "Find strings",
      description:
        "Search defined string data. Usually the fastest way into an unknown " +
        "binary - find the message, then look at what references it.",
      inputSchema: {
        query: z.string().optional(),
        limit: z.number().int().min(1).max(1000).optional(),
      },
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async (args) =>
      guard(
        () => bridge.strings(args),
        (r) => `${r.strings.length} strings matched.`,
      ),
  );

  registerAppTool(
    server,
    "xrefs_to",
    {
      title: "Cross-references",
      description: "Everything that references an address.",
      inputSchema: {
        address: z.string().describe("Target address, e.g. 0x140001000"),
        limit: z.number().int().min(1).max(1000).optional(),
      },
      annotations: { readOnlyHint: true, openWorldHint: false },
      _meta: {
        // No view of its own - the decompiler view calls this to fill its sidebar.
        ui: { resourceUri: VIEWS.decompiler.uri, visibility: ["model", "app"] },
      },
    },
    async (args) =>
      guard(
        () => bridge.xrefsTo(args),
        (r) => `${r.references.length} references to ${r.address}.`,
      ),
  );

  // ------------------------------------------------------------------- writes

  registerAppTool(
    server,
    "rename_symbol",
    {
      title: "Rename symbol",
      description:
        "Rename a function, or a local variable inside one. Pass old_name to " +
        "rename a local; omit it to rename the function itself. This is what a " +
        "click on an identifier in the decompiler view fires.",
      inputSchema: {
        address: z.string().describe("Address of the function that owns the symbol"),
        new_name: z.string().min(1),
        old_name: z
          .string()
          .optional()
          .describe("Current local-variable name. Omit to rename the function."),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
      _meta: {
        ui: { resourceUri: VIEWS.decompiler.uri, visibility: ["model", "app"] },
      },
    },
    async (args) =>
      guard(
        () => bridge.rename(args),
        (r) => `Renamed ${r.renamed} to ${r.newName} (${r.address}).`,
      ),
  );

  registerAppTool(
    server,
    "add_comment",
    {
      title: "Add comment",
      description:
        "Attach a plate comment at an address. Persists into the Ghidra project, " +
        "so notes made here show up in the Ghidra GUI.",
      inputSchema: {
        address: z.string(),
        text: z.string(),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
      _meta: {
        ui: { resourceUri: VIEWS.decompiler.uri, visibility: ["app"] },
      },
    },
    async (args) =>
      guard(
        () => bridge.comment(args),
        (r) => `Commented at ${r.address}.`,
      ),
  );

  server.registerTool(
    "save_program",
    {
      title: "Save program",
      description:
        "Write renames and comments back to the Ghidra project on disk. Nothing " +
        "is lost without this, but nothing is durable with it either.",
      inputSchema: {},
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
    },
    async () =>
      guard(
        () => bridge.save(),
        (r) => `Saved ${r.path}.`,
      ),
  );

  return server;
}

async function main(): Promise<void> {
  const server = buildServer(bridgeFromEnv());
  await server.connect(new StdioServerTransport());
  // stdout is the MCP transport - anything printed there corrupts the stream.
  console.error("[ghidralens] ready on stdio");
}

main().catch((error: unknown) => {
  console.error("[ghidralens] fatal:", error);
  process.exit(1);
});
