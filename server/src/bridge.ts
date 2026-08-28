/**
 * Typed client for the PyGhidra bridge (bridge/serve.py).
 *
 * The bridge is the only thing that ever touches the JVM. Everything in the MCP
 * server is a thin, stateless caller - which is what makes it safe to restart
 * the MCP server without losing an hour of auto-analysis.
 */

export interface BridgeConfig {
  url: string;
  token: string;
  timeoutMs: number;
}

export class BridgeError extends Error {
  constructor(
    message: string,
    readonly status?: number,
  ) {
    super(message);
    this.name = "BridgeError";
  }
}

/** One identifier as the decompiler emitted it, with where it came from. */
export interface Token {
  kind:
    | "function"
    | "variable"
    | "field"
    | "type"
    | "label"
    | "comment"
    | "operator"
    | "syntax"
    | "case";
  text: string;
  address?: string;
}

export interface FunctionRef {
  name: string;
  address: string;
}

export interface Decompilation {
  name: string;
  address: string;
  signature: string;
  lines: Token[][];
  locals: { name: string; type: string; parameter: boolean }[];
  calls: FunctionRef[];
  callers: FunctionRef[];
}

export interface FunctionRow extends FunctionRef {
  size: number;
  params: number;
  callers: number;
  calls: number;
  external: boolean;
  thunk: boolean;
  signature: string;
}

export interface FunctionList {
  total: number;
  offset: number;
  functions: FunctionRow[];
}

export interface CallGraph {
  root: string;
  nodes: {
    address: string;
    name: string;
    depth: number;
    external: boolean;
    thunk: boolean;
  }[];
  edges: { from: string; to: string }[];
}

export interface ProgramInfo {
  open: boolean;
  path?: string;
  name?: string;
  languageId?: string;
  compiler?: string;
  imageBase?: string;
  functionCount?: number;
  executableFormat?: string;
  executableSha256?: string;
}

export interface XrefList {
  address: string;
  references: {
    from: string;
    type: string;
    inFunction: string | null;
    functionAddress: string | null;
  }[];
}

export interface StringList {
  total: number;
  strings: { address: string; value: string; length: number; refs: number }[];
}

export class Bridge {
  constructor(private readonly config: BridgeConfig) {}

  /**
   * Opening a binary triggers full auto-analysis, which can run for minutes on a
   * large target. It gets its own generous deadline rather than the shared one,
   * because timing it out would leave the JVM mid-analysis with nothing to show.
   */
  openBinary(path: string, analyze = true): Promise<ProgramInfo> {
    return this.request("POST", "/open", { path, analyze }, 30 * 60_000);
  }

  info(): Promise<ProgramInfo> {
    return this.request("GET", "/info");
  }

  listFunctions(params: {
    query?: string;
    limit?: number;
    offset?: number;
    sort?: string;
  }): Promise<FunctionList> {
    return this.request("GET", "/functions", params);
  }

  decompile(params: { address?: string; name?: string }): Promise<Decompilation> {
    return this.request("GET", "/decompile", params);
  }

  callGraph(params: {
    address?: string;
    name?: string;
    depth?: number;
  }): Promise<CallGraph> {
    return this.request("GET", "/callgraph", params);
  }

  xrefsTo(params: { address: string; limit?: number }): Promise<XrefList> {
    return this.request("GET", "/xrefs", params);
  }

  strings(params: { query?: string; limit?: number }): Promise<StringList> {
    return this.request("GET", "/strings", params);
  }

  rename(params: {
    address: string;
    new_name: string;
    old_name?: string;
  }): Promise<{ renamed: string; function: string; address: string; newName: string }> {
    return this.request("POST", "/rename", params);
  }

  comment(params: {
    address: string;
    text: string;
  }): Promise<{ address: string; comment: string }> {
    return this.request("POST", "/comment", params);
  }

  save(): Promise<{ saved: boolean; path: string }> {
    return this.request("POST", "/save", {});
  }

  // ------------------------------------------------------------------ internals

  private async request<T>(
    method: "GET" | "POST",
    path: string,
    params: Record<string, unknown> = {},
    timeoutMs = this.config.timeoutMs,
  ): Promise<T> {
    if (!this.config.token) {
      throw new BridgeError(
        "GHIDRALENS_TOKEN is not set. Start the bridge with " +
          "`python bridge/serve.py --binary <path>` and put the token it prints " +
          "into this server's environment.",
      );
    }

    const url = new URL(path, this.config.url);
    const init: RequestInit = {
      method,
      headers: { "X-GhidraLens-Token": this.config.token },
    };

    if (method === "GET") {
      for (const [key, value] of Object.entries(params)) {
        if (value !== undefined && value !== null && value !== "") {
          url.searchParams.set(key, String(value));
        }
      }
    } else {
      init.body = JSON.stringify(params);
      init.headers = { ...init.headers, "Content-Type": "application/json" };
    }

    const abort = AbortSignal.timeout(timeoutMs);
    let response: Response;
    try {
      response = await fetch(url, { ...init, signal: abort });
    } catch (error) {
      // The overwhelmingly common cause is "the bridge is not running", and the
      // raw fetch error ("fetch failed") tells the user nothing actionable.
      const reason = error instanceof Error ? error.message : String(error);
      throw new BridgeError(
        `cannot reach the GhidraLens bridge at ${this.config.url} (${reason}). ` +
          `Start it with:  python bridge/serve.py --binary <path>`,
      );
    }

    const text = await response.text();
    let payload: unknown;
    try {
      payload = text ? JSON.parse(text) : {};
    } catch {
      throw new BridgeError(
        `bridge returned non-JSON (HTTP ${response.status}): ${text.slice(0, 200)}`,
        response.status,
      );
    }

    if (!response.ok) {
      const detail =
        typeof payload === "object" && payload && "error" in payload
          ? String((payload as { error: unknown }).error)
          : `HTTP ${response.status}`;
      throw new BridgeError(detail, response.status);
    }

    return payload as T;
  }
}

/**
 * Build a Bridge from the environment, missing token and all.
 *
 * Deliberately does not fail here. `tools/list` is a static, in-memory answer
 * that needs no bridge and no token, and plenty of things ask for it before
 * anyone has configured credentials - a client populating its tool picker, a
 * registry checking the server starts, a user reading what it can do before
 * deciding to install Ghidra. Exiting at startup turns all of those into "this
 * server is broken" when it is merely unconfigured.
 *
 * The missing token surfaces on the first tool call instead, as an ordinary tool
 * error with instructions, which is where the user can actually act on it.
 */
export function bridgeFromEnv(): Bridge {
  return new Bridge({
    url: process.env.GHIDRALENS_BRIDGE_URL ?? "http://127.0.0.1:8799",
    token: process.env.GHIDRALENS_TOKEN ?? "",
    timeoutMs: 120_000,
  });
}
