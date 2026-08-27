/**
 * Shared bootstrap for every GhidraLens view.
 *
 * All three views need the same four things: connect to the host, pick up the
 * tool result that opened them, be able to call tools back, and adopt the host's
 * theme so they do not look like a foreign object pasted into the conversation.
 * That is all this file does.
 */

import { App, PostMessageTransport, applyDocumentTheme } from "@modelcontextprotocol/ext-apps";

export interface ViewHandle<T> {
  app: App;
  /** Ask the server for something. Returns `structuredContent`, already typed. */
  call<R>(name: string, args?: Record<string, unknown>): Promise<R>;
  /** Push a sentence into the conversation, so the model sees what you clicked. */
  say(text: string): void;
  /** Fires on the opening tool result and on every later one. */
  onData(handler: (data: T) => void): void;
}

/**
 * Connect, then hand back a small typed surface.
 *
 * Ordering matters and is easy to get wrong: the `toolresult` listener has to be
 * attached *before* `connect()` resolves, because the host fires the notification
 * that carries the opening payload as soon as the handshake completes. Attach it
 * afterwards and the view sits empty until the user does something else.
 */
export async function mount<T>(name: string): Promise<ViewHandle<T>> {
  const app = new App({ name, version: "0.1.0" }, {});
  const handlers: ((data: T) => void)[] = [];
  let latest: T | undefined;

  app.addEventListener("toolresult", (params) => {
    const data = params.structuredContent as T | undefined;
    if (data === undefined) return;
    latest = data;
    for (const handler of handlers) handler(data);
  });

  app.addEventListener("hostcontextchanged", (params) => {
    if (params.theme) applyDocumentTheme(params.theme);
  });

  await app.connect(new PostMessageTransport(window.parent, window.parent));

  const context = app.getHostContext();
  if (context?.theme) applyDocumentTheme(context.theme);

  return {
    app,

    async call<R>(tool: string, args: Record<string, unknown> = {}): Promise<R> {
      const result = await app.callServerTool({ name: tool, arguments: args });
      if (result.isError) {
        const text = result.content
          ?.map((part) => ("text" in part ? part.text : ""))
          .join(" ")
          .trim();
        throw new Error(text || `${tool} failed`);
      }
      return result.structuredContent as R;
    },

    say(text: string) {
      // Fire-and-forget: a failed nudge into the chat must never break the view.
      void app
        .sendMessage({ role: "user", content: [{ type: "text", text }] })
        .catch(() => {});
    },

    onData(handler: (data: T) => void) {
      handlers.push(handler);
      if (latest !== undefined) handler(latest);
    },
  };
}

// --------------------------------------------------------------- DOM helpers

type Attrs = Record<string, string | number | boolean | undefined>;

/** Terse element builder. Everything here is text-heavy; a framework would be dead weight. */
export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Attrs = {},
  ...children: (Node | string)[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined || value === false) continue;
    if (key === "class") node.className = String(value);
    else if (key === "text") node.textContent = String(value);
    else node.setAttribute(key, value === true ? "" : String(value));
  }
  for (const child of children) {
    node.append(typeof child === "string" ? document.createTextNode(child) : child);
  }
  return node;
}

export function clear(node: Element): void {
  while (node.firstChild) node.removeChild(node.firstChild);
}

/** Show a failure in the pane instead of only in a console the user cannot open. */
export function showError(root: Element, error: unknown): void {
  const message = error instanceof Error ? error.message : String(error);
  clear(root);
  root.append(el("div", { class: "gl-error" }, el("strong", { text: "Error" }), " ", message));
}

/**
 * Render an address fixed-width.
 *
 * Most are 0x-prefixed hex. Imported functions instead come back space-qualified
 * ("EXTERNAL:0000003e") because their offsets are indices into Ghidra's external
 * space rather than real addresses - those are already canonical, so pass them
 * through untouched instead of producing "0xEXTERNAL:0000003E".
 */
export function shortAddress(address: string): string {
  if (address.includes(":")) return address;
  const hex = address.replace(/^0x/, "").toUpperCase();
  return "0x" + hex.padStart(8, "0");
}
