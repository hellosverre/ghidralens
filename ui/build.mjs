/**
 * Build each view in its own Vite pass.
 *
 * See vite.config.ts for why they cannot share one: single-file output requires
 * code-splitting off, and Rollup rejects that for multi-input builds.
 */
import { fileURLToPath } from "node:url";
import { build } from "vite";

const VIEWS = ["decompiler", "functions", "callgraph"];

for (const [i, view] of VIEWS.entries()) {
  process.env.GL_VIEW = view;
  // Only the first pass wipes dist/, or each view would delete the last one.
  process.env.GL_CLEAN = i === 0 ? "1" : "0";
  await build({ configFile: fileURLToPath(new URL("vite.config.ts", import.meta.url)) });
  console.log(`  built ${view}.html`);
}
