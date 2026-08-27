/**
 * Text renderings of tool results, for the model.
 *
 * A tool result carries two payloads: `structuredContent`, which the views index
 * into, and `content[0].text`, which is what a model actually reads. It is very
 * easy to build a UI-first server and let the text half rot into a status line -
 * and then the model is blind. Watching a local model call `find_strings` three
 * times in a row, each time receiving "30 strings matched" and learning nothing,
 * is what prompted this file.
 *
 * The constraint is that a text client has no scrollbar and a finite context, so
 * these are capped and told the reader what was cut. Truncating silently is
 * worse than truncating loudly: a model that thinks it saw everything stops
 * looking.
 */

import type {
  CallGraph,
  Decompilation,
  FunctionList,
  ProgramInfo,
  StringList,
  Token,
  XrefList,
} from "./bridge.js";

const MAX_ROWS = 60;
const MAX_CODE_LINES = 220;

function truncated(shown: number, total: number, noun: string): string {
  return shown < total ? `\n… ${total - shown} more ${noun} not shown` : "";
}

export function renderProgram(info: ProgramInfo): string {
  if (!info.open) return "No binary open. Call open_binary first.";
  return [
    `${info.name} - ${info.executableFormat}, ${info.languageId}`,
    `image base ${info.imageBase}, ${info.functionCount} functions`,
    `path: ${info.path}`,
  ].join("\n");
}

export function renderFunctions(list: FunctionList): string {
  if (!list.functions.length) return "No functions matched.";

  const rows = list.functions.slice(0, MAX_ROWS).map((f) => {
    const tags = [f.external ? "import" : "", f.thunk ? "thunk" : ""].filter(Boolean);
    return `${f.address}  ${f.name}${tags.length ? ` [${tags.join(",")}]` : ""}` +
      `  ${f.size}b  ${f.callers} callers`;
  });

  return (
    `${list.total} functions matched (showing ${rows.length} from offset ${list.offset}):\n` +
    rows.join("\n") +
    truncated(rows.length, list.total, "functions")
  );
}

/**
 * Rebuild the C source from the token stream.
 *
 * The tokens exist so the *view* can be interactive; a model just needs the
 * code. Reassembling it here means one bridge response serves both, instead of
 * the model being told "395 lines" and left to guess what is in them.
 */
export function renderDecompilation(code: Decompilation): string {
  const lines = code.lines.map((line: Token[]) => line.map((t) => t.text).join(""));
  const shown = lines.slice(0, MAX_CODE_LINES);

  const names = (refs: { name: string; address: string }[]) =>
    refs.length ? refs.map((r) => r.name).join(", ") : "none";

  return [
    `${code.signature}  at ${code.address}`,
    `callers: ${names(code.callers)}`,
    `calls: ${names(code.calls)}`,
    "",
    shown.join("\n") + truncated(shown.length, lines.length, "lines"),
  ].join("\n");
}

export function renderCallGraph(graph: CallGraph): string {
  const inbound = new Set<string>();
  const outbound = new Set<string>();
  const byAddress = new Map(graph.nodes.map((n) => [n.address, n.name]));

  for (const edge of graph.edges) {
    if (edge.to === graph.root) inbound.add(byAddress.get(edge.from) ?? edge.from);
    if (edge.from === graph.root) outbound.add(byAddress.get(edge.to) ?? edge.to);
  }

  const rootName = byAddress.get(graph.root) ?? graph.root;
  return [
    `${graph.nodes.length} functions and ${graph.edges.length} call edges around ${rootName} (${graph.root}).`,
    `direct callers: ${[...inbound].join(", ") || "none"}`,
    `direct callees: ${[...outbound].join(", ") || "none"}`,
  ].join("\n");
}

export function renderStrings(list: StringList): string {
  if (!list.strings.length) return "No strings matched.";
  const rows = list.strings
    .slice(0, MAX_ROWS)
    .map((s) => `${s.address}  ${JSON.stringify(s.value)}${s.refs ? `  (${s.refs} refs)` : ""}`);
  return (
    `${list.total} strings matched:\n` +
    rows.join("\n") +
    truncated(rows.length, list.total, "strings")
  );
}

export function renderXrefs(list: XrefList): string {
  if (!list.references.length) return `Nothing references ${list.address}.`;
  const rows = list.references
    .slice(0, MAX_ROWS)
    .map((r) => `${r.from}  ${r.type}${r.inFunction ? `  in ${r.inFunction} (${r.functionAddress})` : ""}`);
  return (
    `${list.references.length} references to ${list.address}:\n` +
    rows.join("\n") +
    truncated(rows.length, list.references.length, "references")
  );
}
