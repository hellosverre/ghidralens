# Launch plan

Not a marketing document — a checklist, in the order things have to happen, with
the copy already written so posting is a paste rather than a writing session.

## The one thing that matters

**The demo video is the product.** Two data points from projects in exactly this
niche:

| Project | Stars | How it spread |
| --- | --- | --- |
| `blender-mcp` | 26,378 | One demo video. HN post got 54 points — the video did the work. |
| `Figma-Context-MCP` | 15,723 | Never submitted to HN at all. Video only. |

Both are the same shape as this: a well-known desktop tool, wired to an AI
client, doing something visibly impossible-looking. A README nobody watches is
worth roughly nothing here.

### Recording it

Sixty seconds, no voiceover needed, no editing beyond a trim.

1. **0–5s** — the chat, empty. Type: *"what does where.exe do?"*
2. **5–20s** — the function browser appears inline. Scroll it. This is the beat
   that makes people sit up: it is a real UI, in the chat.
3. **20–40s** — click a row → the decompiler opens. Click `FUN_140004a04`,
   type `free_arg_block`, press Enter. It renames.
4. **40–50s** — ask the model about the same function. It uses the new name.
   **This is the whole pitch.** Hold on it.
5. **50–60s** — the call graph. Click one node, it recenters.

Record at 1500×1000 or larger. Post as MP4 to X/Bluesky and as a GIF in the
README — GitHub will not play an MP4 inline.

## Order of operations

1. Push the repo. Nothing below works before this.
2. Record the video.
3. Put the GIF at the top of the README, above the fold.
4. Post, in this order: X/Bluesky → r/ReverseEngineering → Show HN.
   Reddit first because the RE crowd is the actual audience; HN is a
   coin-flip and works better with a link that already has traction.
5. Submit to the MCP registry and the MCP Apps directory (a 3-week-old repo
   with 0 stars — being early in a directory nobody has filled yet is free
   placement).

## Repo settings

- **Description:** Interactive Ghidra reverse-engineering views inside your AI client. Decompile, rename, and navigate without leaving the conversation.
- **Topics:** `ghidra`, `mcp`, `model-context-protocol`, `mcp-server`, `mcp-apps`, `reverse-engineering`, `decompiler`, `binary-analysis`, `ollama`, `typescript`
- Enable Issues and Discussions. Turn Wiki off.

## Copy

### X / Bluesky

> Ghidra, inside your AI client.
>
> Not a wall of text — an actual interactive decompiler. Click a variable to
> rename it, and the model's next decompile sees the new name. You're both
> looking at the same live program.
>
> Built on MCP Apps. Runs on local models too.
>
> [video]

Reply with the repo link rather than putting it in the first post.

### r/ReverseEngineering

> **Title:** GhidraLens — interactive Ghidra views rendered inside an AI chat client (MCP Apps)

> GhidraMCP got ~10k stars and has been abandoned since June 2025. Everything in
> that space returns text: the model can read it, you can't navigate it.
>
> This renders Ghidra's decompiler output as an interactive view inside the chat
> client, using MCP Apps — the extension that lets an MCP server ship real HTML.
> Click an identifier to rename it in the live program; the model's next
> decompile sees the new name.
>
> The part I think is actually interesting: Ghidra's decompiler doesn't emit a
> string, it emits a token tree where every identifier carries its address and
> its kind. Everything else flattens that to text. Keeping it is what makes the
> view clickable.
>
> A PyGhidra process holds the analysed program resident, so analysis runs once
> — 25s for a small binary, 0.3s on every reopen after.
>
> Works with local models via Ollama. No API key, nothing leaves the machine,
> which for RE work seemed like the point.
>
> MIT. [link]

Say what it can't do, in a comment, before someone else does: MCP Apps is
supported by 11 clients but not by every client; there is no patching or
debugging; imports have no body to decompile.

### Show HN

> **Title:** Show HN: GhidraLens – interactive Ghidra views inside an AI client

Same body as Reddit, minus the star count of the incumbent — HN reads that as
positioning. Lead with the token-tree detail instead; it is the technically
interesting part and that audience rewards it.

### MCP directories

- `registry.modelcontextprotocol.io` — official registry
- The MCP Apps examples directory (small, new, mostly empty)
- `glama.ai/mcp/servers`, `mcpservers.org`

## What not to claim

Everything below has been measured on one 64 KB binary (`where.exe`, 198
functions). Do not extrapolate to a game client in the launch post; say what was
measured and let people find the rest.

| | |
| --- | --- |
| First open, with analysis | 25 s |
| Re-open | 0.3 s |
| Decompile a 2 KB function | 0.4 s |
| 87-node call graph | < 0.1 s |

Never been run inside a real MCP client yet — only against a reference host
implementation. Verify that before the video, because the video is the claim.
