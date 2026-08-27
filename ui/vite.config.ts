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

const BRIDGE = process.env.GHIDRALENS_BRIDGE_URL ?? "http://127.0.0.1:8799";
const TOKEN = process.env.GHIDRALENS_TOKEN ?? "";

export default defineConfig({
  plugins: [viteSingleFile({ removeViteModuleLoader: true })],

  /**
   * `/bridge/*` in dev proxies to a running PyGhidra bridge, so the harness can
   * drive the views with a real analysed program instead of fixtures.
   *
   * The header rewriting is not optional. The bridge rejects anything carrying
   * an `Origin` or `Referer` so a random page in your browser cannot reach your
   * decompiler - and a browser attaches `Origin` to every cross-port request,
   * which is exactly what this is. Stripping them here keeps that protection
   * intact in production while letting the dev server through.
   */
  server: {
    proxy: {
      "/bridge": {
        target: BRIDGE,
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/bridge/, ""),
        configure(proxy) {
          proxy.on("proxyReq", (proxyReq) => {
            proxyReq.removeHeader("origin");
            proxyReq.removeHeader("referer");
            if (TOKEN) proxyReq.setHeader("X-GhidraLens-Token", TOKEN);
          });
        },
      },
    },
  },

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
