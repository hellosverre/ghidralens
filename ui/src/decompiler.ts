/**
 * The decompiler view - the reason this project exists.
 *
 * Ghidra's decompiler does not emit a string; it emits a token tree where every
 * identifier knows its address and its kind. The bridge preserves that, so here
 * a variable is a *variable*, not eight characters that happen to look like one.
 * Clicking it renames it in the live program. Clicking a call navigates to it.
 * Both write through to the same Ghidra session the model is reading from, so
 * the two of you never drift apart.
 */

import "./theme.css";
import { clear, el, mount, shortAddress, showError, type ViewHandle } from "./host";

interface Token {
  kind: string;
  text: string;
  address?: string;
}

interface FunctionRef {
  name: string;
  address: string;
  /** Imported from another module - there is no body here to navigate to. */
  external?: boolean;
}

interface Decompilation {
  name: string;
  address: string;
  signature: string;
  lines: Token[][];
  locals: { name: string; type: string; parameter: boolean }[];
  calls: FunctionRef[];
  callers: FunctionRef[];
}

const NUMERIC = /^-?(0x[0-9a-fA-F]+|\d+)$/;

let view: ViewHandle<Decompilation>;
let current: Decompilation | null = null;

const root = document.getElementById("root")!;

// ------------------------------------------------------------------- render

function render(data: Decompilation): void {
  current = data;
  clear(root);

  const shell = el("div", { class: "gl-shell" });
  shell.append(header(data), el("div", { class: "dc-split" }, code(data), sidebar(data)));
  root.append(shell);
}

function header(data: Decompilation): HTMLElement {
  const explain = el("button", {
    class: "gl-btn",
    type: "button",
    title: "Ask the model about this function",
    text: "Explain",
  });
  explain.addEventListener("click", () => {
    view.say(
      `Explain what ${data.name} at ${data.address} does, based on the decompilation you just showed me.`,
    );
  });

  const save = el("button", {
    class: "gl-btn",
    type: "button",
    title: "Write renames and comments to the Ghidra project",
    text: "Save",
  });
  save.addEventListener("click", () => {
    void view.call("save_program").catch((error) => showError(root, error));
  });

  return el(
    "div",
    { class: "gl-bar" },
    el("span", { class: "gl-eyebrow", text: "decompiled" }),
    el("span", { class: "gl-bar-title", title: data.signature, text: data.signature }),
    el("span", { class: "gl-addr", text: shortAddress(data.address) }),
    el("span", { class: "gl-bar-spacer" }),
    explain,
    save,
  );
}

/**
 * Which names in this function are navigable.
 *
 * A ClangFuncNameToken carries the address of the *call site*, not of the
 * callee - useful for the gutter, useless for navigation. The callee list that
 * came back with the decompilation has the entry points, so resolve by name
 * against that instead.
 */
function calleeIndex(data: Decompilation): Map<string, string> {
  const index = new Map<string, string>();
  // Imports are deliberately left out. FindClose lives in KERNEL32, so following
  // it leads nowhere - a link that always errors is worse than plain text.
  for (const call of data.calls) {
    if (!call.external) index.set(call.name, call.address);
  }
  return index;
}

function code(data: Decompilation): HTMLElement {
  const callees = calleeIndex(data);
  const locals = new Set(data.locals.map((local) => local.name));
  const pane = el("div", { class: "gl-body dc-code" });

  data.lines.forEach((tokens, i) => {
    const line = el("div", { class: "dc-line" });
    const address = tokens.find((token) => token.address)?.address;

    line.append(
      el("span", {
        class: "dc-gutter",
        text: address ? shortAddress(address).slice(2) : "",
        title: address ?? "",
      }),
      el("span", { class: "dc-num", text: String(i + 1) }),
    );

    const body = el("span", { class: "dc-src" });
    for (const token of tokens) body.append(span(token, data, callees, locals));
    line.append(body);
    pane.append(line);
  });

  return pane;
}

function span(
  token: Token,
  data: Decompilation,
  callees: Map<string, string>,
  locals: Set<string>,
): Node {
  // Ghidra classifies numeric literals as plain syntax. Re-tag them here so the
  // constants a reverse engineer is actually scanning for stand out.
  const kind =
    token.kind === "syntax" && NUMERIC.test(token.text.trim()) ? "number" : token.kind;

  const node = el("span", { class: `tok tok-${kind}`, text: token.text });

  const target = callees.get(token.text);
  if (kind === "function" && target) {
    node.classList.add("tok-link");
    node.setAttribute("role", "link");
    node.setAttribute("tabindex", "0");
    node.title = `Go to ${token.text} (${shortAddress(target)})`;
    const go = () => navigate(target);
    node.addEventListener("click", go);
    node.addEventListener("keydown", (event) => {
      if (event.key === "Enter") go();
    });
    return node;
  }

  const renameable =
    (kind === "variable" && locals.has(token.text)) ||
    (kind === "function" && token.text === data.name);

  if (renameable) {
    node.classList.add("tok-editable");
    node.setAttribute("tabindex", "0");
    node.title = "Click to rename";
    const start = () => beginRename(node, token.text, kind === "function");
    node.addEventListener("click", start);
    node.addEventListener("keydown", (event) => {
      if (event.key === "Enter") start();
    });
  }

  return node;
}

function sidebar(data: Decompilation): HTMLElement {
  const pane = el("aside", { class: "dc-side" });

  pane.append(refList("Called by", data.callers, "Nothing calls this."));
  pane.append(refList("Calls", data.calls, "Calls nothing."));

  if (data.locals.length) {
    const list = el("div", { class: "dc-locals" });
    for (const local of data.locals) {
      list.append(
        el(
          "div",
          { class: "dc-local" },
          el("span", { class: "tok tok-type", text: local.type }),
          " ",
          el("span", { class: "tok tok-variable", text: local.name }),
          local.parameter ? el("span", { class: "dc-tag", text: "param" }) : "",
        ),
      );
    }
    pane.append(section("Variables", list));
  }

  return pane;
}

function refList(title: string, refs: FunctionRef[], empty: string): HTMLElement {
  if (!refs.length) {
    return section(title, el("div", { class: "dc-none", text: empty }));
  }

  const list = el("div", { class: "dc-refs" });
  for (const ref of refs) {
    const item = el(
      "button",
      {
        class: ref.external ? "dc-ref dc-ref-import" : "dc-ref",
        type: "button",
        disabled: ref.external,
        title: ref.external
          ? `${ref.name} is imported - no code to show`
          : shortAddress(ref.address),
      },
      el("span", { class: "tok tok-function", text: ref.name }),
      el(
        "span",
        { class: "gl-addr dc-ref-addr" },
        ref.external ? el("span", { class: "dc-tag", text: "import" }) : "",
        ref.external ? "" : shortAddress(ref.address),
      ),
    );
    if (!ref.external) item.addEventListener("click", () => navigate(ref.address));
    list.append(item);
  }
  return section(`${title} (${refs.length})`, list);
}

function section(title: string, content: Node): HTMLElement {
  return el(
    "section",
    { class: "dc-section" },
    el("h3", { class: "gl-eyebrow dc-head", text: title }),
    content,
  );
}

// ------------------------------------------------------------------ actions

async function navigate(address: string): Promise<void> {
  try {
    render(await view.call<Decompilation>("decompile", { address }));
  } catch (error) {
    showError(root, error);
  }
}

/**
 * Swap the identifier for an input in place.
 *
 * A `prompt()` would be simpler, but views run in a sandboxed iframe that is not
 * granted `allow-modals` - the call returns null with no error and the rename
 * silently does nothing.
 */
function beginRename(node: HTMLElement, oldName: string, isFunction: boolean): void {
  if (!current || node.dataset.editing) return;
  node.dataset.editing = "1";

  const input = el("input", {
    class: "dc-rename",
    value: oldName,
    spellcheck: "false",
    "aria-label": `Rename ${oldName}`,
  });
  node.replaceWith(input);
  input.focus();
  input.select();

  // Enter commits and then re-renders, which pulls the input out of the document
  // and fires blur - so without this latch every rename is sent twice.
  let settled = false;

  const restore = () => {
    if (settled) return;
    settled = true;
    input.replaceWith(node);
    delete node.dataset.editing;
  };

  const commit = async () => {
    if (settled) return;
    const next = input.value.trim();
    if (!current || !next || next === oldName) return restore();
    settled = true;

    input.disabled = true;
    try {
      await view.call("rename_symbol", {
        address: current.address,
        new_name: next,
        ...(isFunction ? {} : { old_name: oldName }),
      });
      // Re-decompile rather than patching the DOM: a rename can change more than
      // the token that was clicked, and the program is the source of truth.
      render(await view.call<Decompilation>("decompile", { address: current.address }));
    } catch (error) {
      // The latch is already down; drop it so the token comes back and the user
      // can retry rather than being left staring at a disabled input.
      settled = false;
      restore();
      showError(root, error);
    }
  };

  input.addEventListener("keydown", (event) => {
    if (event.key === "Enter") void commit();
    if (event.key === "Escape") restore();
  });
  input.addEventListener("blur", () => void commit());
}

// -------------------------------------------------------------------- start

mount<Decompilation>("ghidralens-decompiler")
  .then((handle) => {
    view = handle;
    handle.onData(render);
  })
  .catch((error) => showError(root, error));
