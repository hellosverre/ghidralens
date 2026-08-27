/**
 * Registration of the `ui://` HTML resources that MCP Apps hosts render.
 *
 * Each view is built by Vite into a single self-contained HTML file - all CSS
 * and JS inlined, zero external requests. That is not just tidiness: the host
 * runs these in a sandboxed iframe under a strict CSP, so anything that tried to
 * fetch a stylesheet or a CDN bundle would silently render as a blank pane.
 */

import { readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerAppResource } from "@modelcontextprotocol/ext-apps/server";

const HERE = dirname(fileURLToPath(import.meta.url));

/** server/dist/views.js -> <repo>/ui/dist */
const UI_DIST = process.env.GHIDRALENS_UI_DIST
  ? resolve(process.env.GHIDRALENS_UI_DIST)
  : resolve(HERE, "..", "..", "ui", "dist");

export const VIEWS = {
  decompiler: {
    uri: "ui://ghidralens/decompiler.html",
    title: "Decompiler",
    file: "decompiler.html",
    description:
      "Ghidra's C output with every identifier clickable - rename symbols, " +
      "follow calls, read cross-references without leaving the conversation.",
  },
  functions: {
    uri: "ui://ghidralens/functions.html",
    title: "Function Browser",
    file: "functions.html",
    description:
      "Sortable, filterable table of every function in the program.",
  },
  callgraph: {
    uri: "ui://ghidralens/callgraph.html",
    title: "Call Graph",
    file: "callgraph.html",
    description:
      "Callers and callees around one function, laid out as a navigable graph.",
  },
} as const;

export type ViewName = keyof typeof VIEWS;

/**
 * Read a view off disk on every `resources/read` rather than caching at startup.
 *
 * It costs a few hundred microseconds and it means `npm run dev:ui` changes show
 * up on the next tool call instead of after an MCP server restart - which, in a
 * client you cannot hot-reload, is the difference between a tight loop and a
 * miserable one.
 */
async function readView(name: ViewName): Promise<string> {
  const path = join(UI_DIST, VIEWS[name].file);
  try {
    return await readFile(path, "utf8");
  } catch {
    return fallbackPage(name, path);
  }
}

export function registerViews(server: McpServer): void {
  for (const name of Object.keys(VIEWS) as ViewName[]) {
    const view = VIEWS[name];
    registerAppResource(
      server,
      view.title,
      view.uri,
      { description: view.description },
      async (uri) => ({
        contents: [
          {
            uri: uri.href,
            mimeType: "text/html;profile=mcp-app",
            text: await readView(name),
          },
        ],
      }),
    );
  }
}

/**
 * Shown instead of a blank iframe when the UI has not been built yet - the most
 * common first-run mistake, and completely invisible otherwise.
 */
function fallbackPage(name: ViewName, path: string): string {
  const escaped = path.replace(/&/g, "&amp;").replace(/</g, "&lt;");
  return `<!doctype html><meta charset="utf-8">
<title>GhidraLens - view not built</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 14px/1.6 ui-monospace, "Cascadia Code", Menlo, monospace;
         margin: 0; padding: 24px; background: Canvas; color: CanvasText; }
  code { background: color-mix(in srgb, CanvasText 10%, transparent);
         padding: 2px 6px; border-radius: 4px; }
  p { max-width: 60ch; }
</style>
<h2>The <em>${name}</em> view has not been built yet.</h2>
<p>Expected it at <code>${escaped}</code>.</p>
<p>Run <code>npm run build</code> in the GhidraLens repo, then call this tool again.</p>`;
}
