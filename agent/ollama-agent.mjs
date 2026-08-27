#!/usr/bin/env node
/**
 * Drive GhidraLens from a local model, with no API key and nothing leaving the
 * machine.
 *
 * This is a small MCP host: it speaks MCP over stdio to the GhidraLens server on
 * one side, and Ollama's /api/chat on the other, and runs the tool loop between
 * them. Reverse engineering is exactly the work people would rather not send to
 * a hosted model, so "works entirely locally" is not a novelty here.
 *
 *   node agent/ollama-agent.mjs "what does this binary do?"
 *
 * Env: OLLAMA_MODEL, OLLAMA_URL, GHIDRALENS_TOKEN, GHIDRALENS_BRIDGE_URL.
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { fileURLToPath } from "node:url";

const SERVER = fileURLToPath(new URL("../server/dist/index.js", import.meta.url));
const OLLAMA = process.env.OLLAMA_URL ?? "http://127.0.0.1:11434";
// Default to the smallest model installed. The 14B and 16B are better at this,
// but a reverse engineer is usually running something else on the GPU too.
const MODEL = process.env.OLLAMA_MODEL ?? "huihui_ai/qwen3.5-abliterated:9b";
const MAX_TURNS = Number(process.env.GHIDRALENS_MAX_TURNS ?? 12);
const NUM_CTX = Number(process.env.OLLAMA_NUM_CTX ?? 16384);
// Ollama parks the model in VRAM for 5 minutes after the last request. Set
// OLLAMA_KEEP_ALIVE=0 to hand the memory back immediately - worth it on a
// machine that is also doing something else.
const KEEP_ALIVE = process.env.OLLAMA_KEEP_ALIVE;

const SYSTEM = `You are a reverse engineer working in Ghidra through tools.

A binary is already loaded. Work in small steps: look at what is there, form a
hypothesis, then check it with another tool call. Prefer find_strings and
list_functions to orient yourself before decompiling anything - decompiling a
random function tells you very little.

Ghidra names unidentified functions FUN_<address>. A name like that means nobody
has worked out what it does yet, which is what you are for. When you are
confident about one, rename it with rename_symbol so the name sticks.

Answer the user's question directly when you have enough to answer it. Do not
narrate your tool use.`;

// ---------------------------------------------------------------- formatting

const DIM = "\x1b[2m";
const BOLD = "\x1b[1m";
const CYAN = "\x1b[36m";
const AMBER = "\x1b[33m";
const OFF = "\x1b[0m";

const log = (line = "") => process.stdout.write(line + "\n");

/** Tool results are big. Show enough to follow along, not enough to drown in. */
function preview(text, limit = 160) {
  const flat = text.replace(/\s+/g, " ").trim();
  return flat.length > limit ? flat.slice(0, limit) + "…" : flat;
}

// ---------------------------------------------------------------------- MCP

/**
 * MCP tool definitions -> Ollama's OpenAI-shaped function schema.
 *
 * App-only tools are dropped. That is not tidiness: `_meta.ui.visibility`
 * exists so a server can say "a click may fire this, the model may not", and a
 * host that ignores it hands the model write tools it was never offered.
 */
function toOllamaTools(tools) {
  return tools
    .filter((tool) => {
      const visibility = tool._meta?.ui?.visibility;
      return !(Array.isArray(visibility) && visibility.length === 1 && visibility[0] === "app");
    })
    .map((tool) => ({
      type: "function",
      function: {
        name: tool.name,
        description: tool.description ?? "",
        parameters: tool.inputSchema ?? { type: "object", properties: {} },
      },
    }));
}

// ------------------------------------------------------------------- Ollama

async function chat(messages, tools) {
  const response = await fetch(`${OLLAMA}/api/chat`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      model: MODEL,
      messages,
      tools,
      stream: false,
      // Qwen3 emits a reasoning block by default. It is not useful in a trace
      // and it eats the context window a long RE session needs.
      think: false,
      options: { temperature: 0.3, num_ctx: NUM_CTX },
      ...(KEEP_ALIVE === undefined ? {} : { keep_alive: Number(KEEP_ALIVE) }),
    }),
  });

  if (!response.ok) {
    throw new Error(`ollama ${response.status}: ${(await response.text()).slice(0, 300)}`);
  }
  return (await response.json()).message;
}

// --------------------------------------------------------------------- main

async function main() {
  const question = process.argv.slice(2).join(" ") || "What does this binary do?";

  if (!process.env.GHIDRALENS_TOKEN) {
    log("GHIDRALENS_TOKEN is not set - start bridge/serve.py and copy its token.");
    process.exit(1);
  }

  const client = new Client({ name: "ghidralens-ollama-agent", version: "0.1.0" });
  await client.connect(
    new StdioClientTransport({
      command: process.execPath,
      args: [SERVER],
      env: { ...process.env },
      stderr: "ignore",
    }),
  );

  const { tools } = await client.listTools();
  const ollamaTools = toOllamaTools(tools);

  log(`${BOLD}model${OFF}  ${MODEL}`);
  log(`${BOLD}tools${OFF}  ${ollamaTools.map((t) => t.function.name).join(", ")}`);
  const hidden = tools.length - ollamaTools.length;
  if (hidden) log(`${DIM}       (${hidden} app-only tool hidden from the model)${OFF}`);
  log(`${BOLD}ask${OFF}    ${question}`);
  log();

  const messages = [
    { role: "system", content: SYSTEM },
    { role: "user", content: question },
  ];

  for (let turn = 0; turn < MAX_TURNS; turn++) {
    const started = Date.now();
    const message = await chat(messages, ollamaTools);
    const elapsed = ((Date.now() - started) / 1000).toFixed(1);
    messages.push(message);

    const calls = message.tool_calls ?? [];
    if (!calls.length) {
      log(`${BOLD}answer${OFF} ${DIM}(${elapsed}s, turn ${turn + 1})${OFF}\n`);
      log(message.content?.trim() || "(empty response)");
      break;
    }

    for (const call of calls) {
      const name = call.function.name;
      // Ollama sometimes hands back arguments already parsed, sometimes as a
      // JSON string. Both are valid per the OpenAI shape it copies.
      const args =
        typeof call.function.arguments === "string"
          ? JSON.parse(call.function.arguments || "{}")
          : (call.function.arguments ?? {});

      log(`${CYAN}→ ${name}${OFF} ${DIM}${JSON.stringify(args)}${OFF}`);

      let text;
      try {
        const result = await client.callTool({ name, arguments: args });
        text = result.content.map((part) => part.text ?? "").join("\n");
        // Structured content is what the views render; the model only needs the
        // summary, and feeding it 400 lines of tokens would blow the context.
        log(`  ${result.isError ? AMBER + "✗" : "✓"} ${preview(text)}${OFF}`);
      } catch (error) {
        text = `tool failed: ${error.message}`;
        log(`  ${AMBER}✗ ${text}${OFF}`);
      }

      messages.push({ role: "tool", tool_name: name, content: text });
    }
    log(`${DIM}  (${elapsed}s)${OFF}`);
  }

  await client.close();
}

main().catch((error) => {
  console.error("agent failed:", error);
  process.exit(1);
});
