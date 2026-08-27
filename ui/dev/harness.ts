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

function openingResult(view: ViewName) {
  const data =
    view === "decompiler" ? DECOMPILATION : view === "functions" ? FUNCTIONS : CALL_GRAPH;
  return {
    content: [{ type: "text" as const, text: "fixture" }],
    structuredContent: data as unknown as Record<string, unknown>,
  };
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
    void host.sendToolResult(openingResult(view));
    trace("out", "ui/notifications/tool-result (fixture)");
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
themePicker.addEventListener("change", () => {
  bridge?.setHostContext({ theme: themePicker.value as "light" | "dark", displayMode: "inline" });
  trace("out", `host-context-changed theme=${themePicker.value}`);
});

void load(picker.value as ViewName);
