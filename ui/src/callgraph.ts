/**
 * The call graph view.
 *
 * Force-directed layouts look impressive and are useless here: they scramble
 * position between renders, so the same function lands somewhere new every time
 * and you lose your place. Call graphs have an inherent axis - callers flow into
 * the function, the function flows into its callees - so this lays them out in
 * signed columns around the root. Left of centre calls you; right of centre you
 * call. Deterministic, and the geometry means something.
 *
 * Drawn on canvas rather than SVG because a depth-3 graph on a hot function is
 * easily a thousand nodes, and that many DOM elements makes hit-testing and
 * scrolling crawl.
 */

import "./theme.css";
import { el, mount, shortAddress, showError, type ViewHandle } from "./host";

interface GraphNode {
  address: string;
  name: string;
  depth: number;
  external: boolean;
  thunk: boolean;
}

interface CallGraph {
  root: string;
  nodes: GraphNode[];
  edges: { from: string; to: string }[];
}

interface Placed extends GraphNode {
  level: number;
  x: number;
  y: number;
  w: number;
  h: number;
}

const NODE_H = 24;
const COL_GAP = 190;
const ROW_GAP = 8;
const PAD = 24;
const MAX_ROWS = 14;

let view: ViewHandle<CallGraph>;
let graph: CallGraph | null = null;
let placed: Placed[] = [];
let selected: string | null = null;
let hovered: string | null = null;

const root = document.getElementById("root")!;
const canvas = document.createElement("canvas");
const ctx = canvas.getContext("2d")!;

// ------------------------------------------------------------------- layout

/**
 * Assign each node a signed level: callers negative, callees positive.
 *
 * Two independent one-directional walks, not one walk that flips direction as
 * it goes. That distinction is the whole thing. A mixed walk lets you reach a
 * caller of the root (level -1) and then step *forward* to everything that
 * caller also calls, landing all of them back on level 0 - so on a real binary,
 * where callers share callees constantly, sixty unrelated functions pile into
 * the root's own column and the layout collapses into one unreadable stack.
 *
 * Walking each direction separately keeps the sign meaningful: left of centre
 * reaches you, right of centre you reach. A node found both ways keeps whichever
 * hop count is smaller, and the root always stays alone at 0.
 */
function assignLevels(data: CallGraph): Map<string, number> {
  const out = new Map<string, string[]>();
  const incoming = new Map<string, string[]>();

  for (const edge of data.edges) {
    (out.get(edge.from) ?? out.set(edge.from, []).get(edge.from)!).push(edge.to);
    (incoming.get(edge.to) ?? incoming.set(edge.to, []).get(edge.to)!).push(edge.from);
  }

  const levels = new Map<string, number>([[data.root, 0]]);

  const walk = (adjacency: Map<string, string[]>, sign: 1 | -1) => {
    const seen = new Set([data.root]);
    let frontier = [data.root];
    let distance = 0;

    while (frontier.length) {
      distance++;
      const next: string[] = [];
      for (const at of frontier) {
        for (const neighbour of adjacency.get(at) ?? []) {
          if (seen.has(neighbour)) continue;
          seen.add(neighbour);
          const candidate = sign * distance;
          const existing = levels.get(neighbour);
          if (existing === undefined || Math.abs(candidate) < Math.abs(existing)) {
            levels.set(neighbour, candidate);
          }
          next.push(neighbour);
        }
      }
      frontier = next;
    }
  };

  walk(out, 1);
  walk(incoming, -1);

  return levels;
}

function layout(data: CallGraph): void {
  const levels = assignLevels(data);
  const columns = new Map<number, GraphNode[]>();

  for (const node of data.nodes) {
    const level = levels.get(node.address) ?? node.depth;
    const bucket = columns.get(level) ?? columns.set(level, []).get(level)!;
    bucket.push(node);
  }

  // Stable within a column so re-renders do not reshuffle.
  for (const bucket of columns.values()) {
    bucket.sort((a, b) => a.name.localeCompare(b.name));
  }

  // A hub function on a real binary has 60 direct callers. One column of 60 is
  // a 2000px scroll with the root somewhere in the middle of it, so wide levels
  // wrap into side-by-side sub-columns and stay one screen tall.
  const stripes: { level: number; nodes: GraphNode[] }[] = [];
  for (const level of [...columns.keys()].sort((a, b) => a - b)) {
    const bucket = columns.get(level)!;
    for (let i = 0; i < bucket.length; i += MAX_ROWS) {
      stripes.push({ level, nodes: bucket.slice(i, i + MAX_ROWS) });
    }
  }

  const tallest = Math.max(...stripes.map((s) => s.nodes.length), 1);
  const height = tallest * (NODE_H + ROW_GAP) + PAD * 2;
  const width = stripes.length * COL_GAP + PAD * 2;

  placed = [];
  stripes.forEach((stripe, column) => {
    const stripeHeight = stripe.nodes.length * (NODE_H + ROW_GAP);
    const top = (height - stripeHeight) / 2;

    stripe.nodes.forEach((node, row) => {
      placed.push({
        ...node,
        level: stripe.level,
        x: PAD + column * COL_GAP,
        y: top + row * (NODE_H + ROW_GAP),
        w: COL_GAP - 44,
        h: NODE_H,
      });
    });
  });

  resize(width, height);
}

function resize(width: number, height: number): void {
  const dpr = window.devicePixelRatio || 1;
  canvas.width = Math.ceil(width * dpr);
  canvas.height = Math.ceil(height * dpr);
  canvas.style.width = `${width}px`;
  canvas.style.height = `${height}px`;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
}

// -------------------------------------------------------------------- paint

function css(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

function draw(): void {
  if (!graph) return;

  const colors = {
    line: css("--gl-line") || "#26313d",
    muted: css("--gl-muted") || "#7b8ca0",
    fg: css("--gl-fg") || "#d9e3ed",
    accent: css("--gl-accent") || "#e0a75e",
    surface: css("--gl-surface") || "#141b23",
    surface2: css("--gl-surface-2") || "#1b242e",
    fn: css("--tok-function") || "#5fd3e8",
  };

  ctx.clearRect(0, 0, canvas.width, canvas.height);
  const index = new Map(placed.map((node) => [node.address, node]));

  // Edges first, so nodes sit on top of the lines that connect them.
  ctx.lineWidth = 1;
  for (const edge of graph.edges) {
    const from = index.get(edge.from);
    const to = index.get(edge.to);
    if (!from || !to) continue;

    const touchesSelection =
      selected !== null && (edge.from === selected || edge.to === selected);
    ctx.strokeStyle = touchesSelection ? colors.accent : colors.line;
    ctx.globalAlpha = touchesSelection ? 0.9 : 0.5;

    const x1 = from.x + from.w;
    const y1 = from.y + from.h / 2;
    const x2 = to.x;
    const y2 = to.y + to.h / 2;
    const bend = Math.max(24, Math.abs(x2 - x1) * 0.4);

    ctx.beginPath();
    ctx.moveTo(x1, y1);
    ctx.bezierCurveTo(x1 + bend, y1, x2 - bend, y2, x2, y2);
    ctx.stroke();
  }
  ctx.globalAlpha = 1;

  ctx.font = `11px ${css("--gl-mono") || "monospace"}`;
  ctx.textBaseline = "middle";

  for (const node of placed) {
    const isRoot = node.address === graph.root;
    const isSelected = node.address === selected;
    const isHovered = node.address === hovered;

    ctx.fillStyle = isRoot || isSelected ? colors.surface2 : colors.surface;
    ctx.strokeStyle = isRoot ? colors.accent : isHovered ? colors.muted : colors.line;
    ctx.lineWidth = isRoot || isSelected ? 1.5 : 1;

    roundRect(node.x, node.y, node.w, node.h, 4);
    ctx.fill();
    ctx.stroke();

    // Level stripe on the leading edge - a glanceable "how far from the root".
    ctx.fillStyle = node.level === 0 ? colors.accent : colors.line;
    ctx.globalAlpha = node.level === 0 ? 1 : 0.8;
    ctx.fillRect(node.x, node.y + 4, 2, node.h - 8);
    ctx.globalAlpha = 1;

    ctx.fillStyle = isRoot ? colors.fg : colors.fn;
    ctx.fillText(fit(node.name, node.w - 16), node.x + 10, node.y + node.h / 2);
  }
}

function roundRect(x: number, y: number, w: number, h: number, r: number): void {
  ctx.beginPath();
  ctx.moveTo(x + r, y);
  ctx.arcTo(x + w, y, x + w, y + h, r);
  ctx.arcTo(x + w, y + h, x, y + h, r);
  ctx.arcTo(x, y + h, x, y, r);
  ctx.arcTo(x, y, x + w, y, r);
  ctx.closePath();
}

function fit(text: string, maxWidth: number): string {
  if (ctx.measureText(text).width <= maxWidth) return text;
  let cut = text;
  while (cut.length > 4 && ctx.measureText(cut + "…").width > maxWidth) {
    cut = cut.slice(0, -1);
  }
  return cut + "…";
}

function nodeAt(x: number, y: number): Placed | undefined {
  return placed.find(
    (node) => x >= node.x && x <= node.x + node.w && y >= node.y && y <= node.y + node.h,
  );
}

// ------------------------------------------------------------------- render

function render(data: CallGraph): void {
  graph = data;
  if (selected === null || !data.nodes.some((n) => n.address === selected)) {
    selected = data.root;
  }

  const pane = el("div", { class: "gl-body cg-scroll" }, canvas);
  root.replaceChildren(el("div", { class: "gl-shell" }, toolbar(data), pane));

  layout(data);
  draw();

  // A depth-2 graph is routinely 1000px wide in a 500px pane, and the root sits
  // in the middle column - so without this the view opens on whichever callers
  // happen to be furthest left, and the function you asked about is off-screen.
  const centre = placed.find((node) => node.address === data.root);
  if (centre) {
    pane.scrollLeft = centre.x + centre.w / 2 - pane.clientWidth / 2;
    pane.scrollTop = centre.y + centre.h / 2 - pane.clientHeight / 2;
  }
}

function toolbar(data: CallGraph): HTMLElement {
  const target = data.nodes.find((node) => node.address === selected);

  const depth = el("select", { class: "gl-select", "aria-label": "Graph depth" });
  for (const value of [1, 2, 3]) {
    depth.append(
      el("option", { value: String(value), text: `depth ${value}` }),
    );
  }
  (depth as HTMLSelectElement).value = String(currentDepth);
  depth.addEventListener("change", () => {
    currentDepth = Number((depth as HTMLSelectElement).value);
    void recenter(selected ?? data.root);
  });

  const decompile = el("button", {
    class: "gl-btn",
    type: "button",
    text: "Decompile",
    disabled: !target,
  });
  decompile.addEventListener("click", () => {
    if (!target) return;
    void view
      .call("decompile", { address: target.address })
      .catch((error) => showError(root, error));
  });

  return el(
    "div",
    { class: "gl-bar" },
    el("span", { class: "gl-eyebrow", text: "call graph" }),
    el("span", {
      class: "gl-bar-title",
      text: target ? target.name : "-",
      title: target?.address ?? "",
    }),
    el("span", { class: "gl-addr", text: target ? shortAddress(target.address) : "" }),
    el("span", { class: "gl-bar-spacer" }),
    el("span", {
      class: "cg-stat",
      text: `${data.nodes.length} nodes · ${data.edges.length} edges`,
    }),
    depth,
    decompile,
  );
}

let currentDepth = 2;

async function recenter(address: string): Promise<void> {
  try {
    selected = address;
    render(await view.call<CallGraph>("call_graph", { address, depth: currentDepth }));
  } catch (error) {
    showError(root, error);
  }
}

// -------------------------------------------------------------------- input

canvas.addEventListener("mousemove", (event) => {
  const rect = canvas.getBoundingClientRect();
  const node = nodeAt(event.clientX - rect.left, event.clientY - rect.top);
  const next = node?.address ?? null;
  if (next === hovered) return;
  hovered = next;
  canvas.style.cursor = node ? "pointer" : "default";
  canvas.title = node ? `${node.name}  ${shortAddress(node.address)}` : "";
  draw();
});

canvas.addEventListener("mouseleave", () => {
  hovered = null;
  draw();
});

canvas.addEventListener("click", (event) => {
  const rect = canvas.getBoundingClientRect();
  const node = nodeAt(event.clientX - rect.left, event.clientY - rect.top);
  if (!node || !graph) return;
  // Clicking the node you are already centred on is a no-op rather than a
  // pointless round trip that redraws the identical graph.
  if (node.address === graph.root) {
    selected = node.address;
    render(graph);
    return;
  }
  void recenter(node.address);
});

// The canvas is painted from CSS custom properties, so a host theme flip has to
// repaint it - CSS alone cannot reach pixels already committed to the bitmap.
new MutationObserver(() => draw()).observe(document.documentElement, {
  attributes: true,
  attributeFilter: ["data-theme"],
});
window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => draw());

mount<CallGraph>("ghidralens-callgraph")
  .then((handle) => {
    view = handle;
    handle.onData(render);
  })
  .catch((error) => showError(root, error));
