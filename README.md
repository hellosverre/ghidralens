# GhidraLens

**Ghidra, rendered inside your AI client. Click a symbol to rename it. Click a call to follow it.**

Every Ghidra MCP server so far returns text. The model can read it; you cannot
navigate it. GhidraLens returns the same analysis as an **interactive view** —
built on [MCP Apps](https://modelcontextprotocol.io/seps/1865-mcp-apps-interactive-user-interfaces-for-mcp)
(`io.modelcontextprotocol/ui`), the extension that lets a server ship real HTML
into the conversation.

You and the model are looking at the same live program. When you rename a
variable by clicking it, the model's next decompile sees the new name.

---

## What you get

| View | What it does |
| --- | --- |
| **Decompiler** | Ghidra's C output as a live token stream — every identifier carries its address and its kind. Click a local to rename it, click a call to follow it. Callers, callees and variables in a sidebar. |
| **Function browser** | Every function in the binary, filterable and sortable by address, name, size or caller count. Click a row to decompile it. |
| **Call graph** | Callers to the left, callees to the right, the function you asked about in the middle. Click any node to recenter. |

Ten tools total. Three open views; the rest are lookups and writes, including
two the model never sees — they exist only so a click in a view can fire them.

## How it fits together

```
  MCP client  ──stdio──▶  server/  ──HTTP──▶  bridge/  ──JPype──▶  Ghidra (JVM)
  (Claude,                 TypeScript         PyGhidra            program stays
   Cursor, …)              MCP server         session             resident
       ▲
       │  ui:// HTML in a sandboxed iframe
       └──  ui/  three self-contained views
```

The bridge is a separate long-lived process on purpose. Ghidra's auto-analysis
is the expensive step — minutes on a real target — and it happens **once**.
Restart the MCP server or the client and the analysed program is still there.

## Setup

**Prerequisites:** Ghidra 11.3+, a JDK 21+, Python 3.9–3.13, Node 20+.
See [bridge/setup.py.md](bridge/setup.py.md) — the Python side is fussy and that
file covers every way it goes wrong.

```bash
git clone https://github.com/YOURNAME/ghidralens
cd ghidralens
npm install
npm run build
```

Then start the bridge on the binary you want to look at:

```bash
python bridge/serve.py --binary /path/to/target.exe
```

It prints a token. Put that, and the path to the built server, into your MCP
client config:

```json
{
  "mcpServers": {
    "ghidralens": {
      "command": "node",
      "args": ["/absolute/path/to/ghidralens/server/dist/index.js"],
      "env": {
        "GHIDRALENS_BRIDGE_URL": "http://127.0.0.1:8799",
        "GHIDRALENS_TOKEN": "paste-the-printed-token-here"
      }
    }
  }
}
```

Then ask your client: *"decompile the function that handles license validation"*.

## Tools

| Tool | Visible to | Renders |
| --- | --- | --- |
| `open_binary` | model | — |
| `program_info` | model | — |
| `decompile` | model + view | Decompiler |
| `list_functions` | model + view | Function browser |
| `call_graph` | model + view | Call graph |
| `find_strings` | model | — |
| `xrefs_to` | model + view | — |
| `rename_symbol` | model + view | — |
| `add_comment` | **view only** | — |
| `save_program` | model | — |

`add_comment` is hidden from the model deliberately. Visibility is how MCP Apps
separates "the agent may do this" from "a click may do this"; keeping write
tools out of the model's list keeps it short and stops the model from renaming
things on its own initiative.

Renames and comments live in memory until `save_program` writes them into the
Ghidra project — after which they show up in the Ghidra GUI like any other edit.

## Developing the views without Ghidra

```bash
npm run dev:ui
# open http://localhost:5173/dev/harness.html
```

`ui/dev/harness.ts` is a **real MCP Apps host** — it runs the SDK's `AppBridge`
against the view in an iframe, so the `ui/initialize` handshake, the opening
`ui/notifications/tool-result`, and every `tools/call` a click fires all go over
real postMessage JSON-RPC. Only the data is fake. There is a message trace down
the right-hand side, and a host-theme switch, because the views have to look
right in both.

## Tests

```bash
node server/smoke.mjs    # MCP surface: tools, ui:// resources, error handling
python bridge/test_serve.py    # bridge auth, routing, validation
```

Neither needs Ghidra. `smoke.mjs` runs the real server over a real stdio
transport with no bridge behind it, which is exactly the state a first-time user
is in.

## Security

The bridge binds `127.0.0.1` only, requires a per-run token in
`X-GhidraLens-Token`, and rejects any request carrying an `Origin` or `Referer`
header — so a page open in your browser cannot reach your decompiler. It has no
multi-user model and is not meant to be exposed; `--host` refuses anything but
loopback.

Analysing a binary does not execute it, but Ghidra will happily open malware.
Use the same isolation you would use for any other RE work.

## Licence

MIT.
