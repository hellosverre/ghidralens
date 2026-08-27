/**
 * A stand-in MCP Apps host, for developing the views without Ghidra.
 *
 * This is not a mock of our own code - it speaks the real protocol. It runs an
 * `AppBridge` (the host half of MCP Apps) against the view in an iframe, so the
 * `ui/initialize` handshake, the `ui/notifications/tool-result` that carries the
 * opening payload, and every `tools/call` a click fires all go over real
 * postMessage JSON-RPC. If a view works here, the only thing left between it and
 * a real client is the data.
 *
 * Open it at http://localhost:5173/dev/harness.html
 */

import { AppBridge } from "@modelcontextprotocol/ext-apps/app-bridge";
import { PostMessageTransport } from "@modelcontextprotocol/ext-apps";
import { CALL_GRAPH, DECOMPILATION, FUNCTIONS } from "./fixtures";

const VIEWS = {
  decompiler: { file: "/decompiler.html", tool: "decompile" },
  functions: { file: "/functions.html", tool: "list_functions" },
  callgraph: { file: "/callgraph.html", tool: "call_graph" },
} as const;

type ViewName = keyof typeof VIEWS;

const frame = document.getElementById("frame") as HTMLIFrameElement;
const log = document.getElementById("log") as HTMLElement;
const picker = document.getElementById("view") as HTMLSelectElement;
const themePicker = document.getElementById("theme") as HTMLSelectElement;

let bridge: AppBridge | null = null;

function trace(direction: "in" | "out", text: string): void {
  const line = document.createElement("div");
  line.className = `trace trace-${direction}`;
  line.textContent = `${direction === "in" ? "◀" : "▶"} ${text}`;
  log.prepend(line);
  while (log.childElementCount > 120) log.lastElementChild?.remove();
}

/**
 * Live mode: forward tool calls to a running bridge through Vite's dev proxy.
 *
 * Fixtures keep the views developable with nothing installed, but they are my
 * idea of what Ghidra emits. A real function is 400 lines with 56 locals and a
 * call graph of 87 nodes, and that is where layout actually breaks - so the
 * harness can talk to the real thing when one is running.
 */
const BRIDGE_ROUTES: Record<string, { method: "GET" | "POST"; path: string }> = {
  decompile: { method: "GET", path: "/decompile" },
  list_functions: { method: "GET", path: "/functions" },
  call_graph: { method: "GET", path: "/callgraph" },
  xrefs_to: { method: "GET", path: "/xrefs" },
  find_strings: { method: "GET", path: "/strings" },
  rename_symbol: { method: "POST", path: "/rename" },
  add_comment: { method: "POST", path: "/comment" },
  save_program: { method: "POST", path: "/save" },
};

async function callBridge(name: string, args: Record<string, unknown>) {
  const route = BRIDGE_ROUTES[name];
  if (!route) throw new Error(`no bridge route for ${name}`);

  const url = new URL(`/bridge${route.path}`, location.origin);
  const init: RequestInit = { method: route.method };

  if (route.method === "GET") {
    for (const [key, value] of Object.entries(args)) {
      if (value !== undefined && value !== null && value !== "") {
        url.searchParams.set(key, String(value));
      }
    }
  } else {
    init.body = JSON.stringify(args);
    init.headers = { "Content-Type": "application/json" };
  }

  const response = await fetch(url, init);
  const data = await response.json();
  if (!response.ok) throw new Error(data.error ?? `HTTP ${response.status}`);
  return data;
}

/**
 * Answer the view's tool calls from fixtures.
 *
 * The write tools echo success without mutating anything: the harness has no
 * program to mutate, and the views re-read after a write anyway, so a rename
 * round-trips visually as a no-op rather than as a crash.
 */
function handleToolCall(name: string, args: Record<string, unknown>) {
  trace("in", `tools/call ${name} ${JSON.stringify(args)}`);

  const reply = (data: unknown, text: string) => ({
    content: [{ type: "text" as const, text }],
    structuredContent: data as Record<string, unknown>,
  });

  if (isLive()) {
    return callBridge(name, args)
      .then((data) => reply(data, "live"))
      .catch((error) => ({
        content: [{ type: "text" as const, text: String(error.message ?? error) }],
        isError: true as const,
      }));
  }

  switch (name) {
    case "decompile":
      return reply(DECOMPILATION, "decompiled");
    case "list_functions": {
      const query = String(args.query ?? "").toLowerCase();
      const matched = FUNCTIONS.functions.filter((f) =>
        f.name.toLowerCase().includes(query),
      );
      const offset = Number(args.offset ?? 0);
      const limit = Number(args.limit ?? 200);
      return reply(
        { total: matched.length, offset, functions: matched.slice(offset, offset + limit) },
        `${matched.length} functions`,
      );
    }
    case "call_graph":
      return reply(CALL_GRAPH, "graph");
    case "rename_symbol":
      return reply({ renamed: "variable", newName: String(args.new_name) }, "renamed");
    case "add_comment":
      return reply({ address: String(args.address) }, "commented");
    case "save_program":
      return reply({ saved: true }, "saved");
    case "xrefs_to":
      return reply({ address: String(args.address), references: [] }, "0 refs");
    default:
      return {
        content: [{ type: "text" as const, text: `harness has no fixture for ${name}` }],
        isError: true as const,
      };
  }
}

function isLive(): boolean {
  return (document.getElementById("source") as HTMLSelectElement).value === "live";
}

/**
 * The payload a real host would attach to the notification that opens the view.
 *
 * In live mode there is no preceding tool call to borrow a result from, so the
 * harness makes the same call the model would have made: the biggest function
 * for the decompiler and the graph, the first page for the browser.
 */
async function openingResult(view: ViewName) {
  const wrap = (data: unknown, text: string) => ({
    content: [{ type: "text" as const, text }],
    structuredContent: data as Record<string, unknown>,
  });

  if (!isLive()) {
    const data =
      view === "decompiler" ? DECOMPILATION : view === "functions" ? FUNCTIONS : CALL_GRAPH;
    return wrap(data, "fixture");
  }

  const list = await callBridge("list_functions", { limit: 1, sort: "size" });
  const target = list.functions[0];
  trace("out", `live target: ${target.name} @ ${target.address}`);

  if (view === "functions") {
    return wrap(await callBridge("list_functions", { limit: 200 }), "live");
  }
  if (view === "decompiler") {
    return wrap(await callBridge("decompile", { address: target.address }), "live");
  }
  return wrap(await callBridge("call_graph", { address: target.address, depth: 2 }), "live");
}

async function load(view: ViewName): Promise<void> {
  await bridge?.close();
  log.replaceChildren();

  await new Promise<void>((resolve) => {
    frame.addEventListener("load", () => resolve(), { once: true });
    frame.src = VIEWS[view].file;
  });

  const host = new AppBridge(
    null,
    { name: "ghidralens-harness", version: "0.1.0" },
    { serverTools: {}, serverResources: {}, openLinks: {}, logging: {} },
    { hostContext: { theme: themePicker.value as "light" | "dark", displayMode: "inline" } },
  );

  host.oncalltool = async (params) =>
    handleToolCall(params.name, (params.arguments ?? {}) as Record<string, unknown>);

  // The opening payload only lands if the view finished its handshake first;
  // a real host sends it at exactly this point too.
  host.addEventListener("initialized", () => {
    trace("in", "ui/notifications/initialized");
    void host.sendToolInput({ arguments: {} });
    void openingResult(view)
      .then((result) => {
        void host.sendToolResult(result);
        trace("out", `ui/notifications/tool-result (${isLive() ? "live" : "fixture"})`);
      })
      .catch((error) => trace("out", `opening payload failed: ${error.message ?? error}`));
  });

  host.onmessage = async (params) => {
    trace("in", `ui/message ${JSON.stringify(params.content)}`);
    return {};
  };

  host.onsizechange = (params) => {
    frame.style.height = `${Math.max(220, params.height ?? 400)}px`;
  };

  const contentWindow = frame.contentWindow!;
  await host.connect(new PostMessageTransport(contentWindow, contentWindow));
  bridge = host;
  trace("out", `mounted ${VIEWS[view].file}`);
}

picker.addEventListener("change", () => void load(picker.value as ViewName));
document
  .getElementById("source")!
  .addEventListener("change", () => void load(picker.value as ViewName));
themePicker.addEventListener("change", () => {
  bridge?.setHostContext({ theme: themePicker.value as "light" | "dark", displayMode: "inline" });
  trace("out", `host-context-changed theme=${themePicker.value}`);
});

void load(picker.value as ViewName);
