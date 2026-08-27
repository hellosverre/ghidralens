import { resolve } from "node:path";
import { defineConfig } from "vite";
import { viteSingleFile } from "vite-plugin-singlefile";

/**
 * One view per build.
 *
 * Each view has to become a single self-contained HTML file: MCP Apps hosts
 * render them in a sandboxed iframe under a strict CSP with no route back to us,
 * so a `<script src>` would leave a blank pane and no error. Inlining that means
 * turning code-splitting off, and Rollup refuses to disable code-splitting for a
 * multi-input build - hence build.mjs, which runs this config once per view.
 */
const VIEW = process.env.GL_VIEW ?? "decompiler";

export default defineConfig({
  plugins: [viteSingleFile({ removeViteModuleLoader: true })],
  build: {
    target: "es2022",
    assetsInlineLimit: 100_000_000,
    cssCodeSplit: false,
    emptyOutDir: process.env.GL_CLEAN === "1",
    rollupOptions: {
      input: resolve(import.meta.dirname, `${VIEW}.html`),
    },
  },
});
