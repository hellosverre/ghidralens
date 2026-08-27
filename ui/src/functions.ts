/**
 * The function browser.
 *
 * A binary with 40,000 functions is not something you read; it is something you
 * sift. Filtering and sorting happen server-side because the whole list never
 * comes down the wire - the model asks for a page, the user re-asks for a
 * different one by typing, and both requests go through the same tool.
 */

import "./theme.css";
import { clear, el, mount, shortAddress, showError, type ViewHandle } from "./host";

interface FunctionRow {
  name: string;
  address: string;
  size: number;
  params: number;
  callers: number;
  calls: number;
  external: boolean;
  thunk: boolean;
  signature: string;
}

interface FunctionList {
  total: number;
  offset: number;
  functions: FunctionRow[];
}

type Sort = "address" | "name" | "size" | "callers";

const COLUMNS: { key: Sort | null; label: string; align?: "right" }[] = [
  { key: "address", label: "Address" },
  { key: "name", label: "Function" },
  { key: "size", label: "Bytes", align: "right" },
  { key: null, label: "Params", align: "right" },
  { key: "callers", label: "Callers", align: "right" },
  { key: null, label: "Calls", align: "right" },
];

const PAGE = 200;

let view: ViewHandle<FunctionList>;
const state = { query: "", sort: "address" as Sort, offset: 0 };

const root = document.getElementById("root")!;

function render(data: FunctionList): void {
  clear(root);
  const shell = el("div", { class: "gl-shell" });
  shell.append(toolbar(data), table(data), footer(data));
  root.append(shell);
}

function toolbar(data: FunctionList): HTMLElement {
  const search = el("input", {
    class: "gl-input",
    type: "search",
    placeholder: "filter by name",
    value: state.query,
    "aria-label": "Filter functions by name",
  }) as HTMLInputElement;

  // Debounced: every keystroke is a round trip to Ghidra, and a fast typist
  // would otherwise queue a dozen scans of the function manager.
  let timer: ReturnType<typeof setTimeout> | undefined;
  search.addEventListener("input", () => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      state.query = search.value.trim();
      state.offset = 0;
      void refresh();
    }, 220);
  });

  return el(
    "div",
    { class: "gl-bar" },
    el("span", { class: "gl-eyebrow", text: "functions" }),
    search,
    el("span", { class: "gl-bar-spacer" }),
    el("span", {
      class: "fn-count",
      text: `${data.total.toLocaleString()} match${data.total === 1 ? "" : "es"}`,
    }),
  );
}

function table(data: FunctionList): HTMLElement {
  const pane = el("div", { class: "gl-body" });

  if (!data.functions.length) {
    pane.append(el("div", { class: "gl-empty", text: "No functions match that filter." }));
    return pane;
  }

  const head = el("tr");
  for (const column of COLUMNS) {
    const cell = el("th", { class: column.align === "right" ? "num" : "" });
    if (column.key) {
      const active = state.sort === column.key;
      const button = el("button", {
        class: "fn-sort",
        type: "button",
        "aria-pressed": active,
        text: active ? `${column.label} ↓` : column.label,
      });
      button.addEventListener("click", () => {
        state.sort = column.key as Sort;
        state.offset = 0;
        void refresh();
      });
      cell.append(button);
    } else {
      cell.textContent = column.label;
    }
    head.append(cell);
  }

  const body = el("tbody");
  for (const row of data.functions) {
    const tr = el("tr", { class: "fn-row", tabindex: "0", title: row.signature });
    tr.append(
      el("td", { class: "gl-addr", text: shortAddress(row.address) }),
      el(
        "td",
        { class: "fn-name" },
        el("span", { class: "tok tok-function", text: row.name }),
        row.thunk ? el("span", { class: "fn-tag", text: "thunk" }) : "",
        row.external ? el("span", { class: "fn-tag", text: "ext" }) : "",
      ),
      el("td", { class: "num", text: row.size.toLocaleString() }),
      el("td", { class: "num", text: String(row.params) }),
      el("td", { class: "num", text: String(row.callers) }),
      el("td", { class: "num", text: String(row.calls) }),
    );

    const open = () => {
      void view
        .call("decompile", { address: row.address })
        .catch((error) => showError(root, error));
    };
    tr.addEventListener("click", open);
    tr.addEventListener("keydown", (event) => {
      if (event.key === "Enter") open();
    });
    body.append(tr);
  }

  pane.append(el("table", { class: "fn-table" }, el("thead", {}, head), body));
  return pane;
}

function footer(data: FunctionList): HTMLElement {
  const bar = el("div", { class: "gl-bar fn-footer" });
  const shown = data.functions.length;
  const from = shown ? data.offset + 1 : 0;

  const prev = el("button", {
    class: "gl-btn",
    type: "button",
    text: "← Prev",
    disabled: data.offset === 0,
  });
  const next = el("button", {
    class: "gl-btn",
    type: "button",
    text: "Next →",
    disabled: data.offset + shown >= data.total,
  });

  prev.addEventListener("click", () => {
    state.offset = Math.max(0, state.offset - PAGE);
    void refresh();
  });
  next.addEventListener("click", () => {
    state.offset += PAGE;
    void refresh();
  });

  bar.append(
    el("span", {
      class: "fn-count",
      text: `${from.toLocaleString()}–${(data.offset + shown).toLocaleString()} of ${data.total.toLocaleString()}`,
    }),
    el("span", { class: "gl-bar-spacer" }),
    prev,
    next,
  );
  return bar;
}

async function refresh(): Promise<void> {
  try {
    render(
      await view.call<FunctionList>("list_functions", {
        query: state.query,
        sort: state.sort,
        limit: PAGE,
        offset: state.offset,
      }),
    );
  } catch (error) {
    showError(root, error);
  }
}

mount<FunctionList>("ghidralens-functions")
  .then((handle) => {
    view = handle;
    handle.onData((data) => {
      state.offset = data.offset;
      render(data);
    });
  })
  .catch((error) => showError(root, error));
