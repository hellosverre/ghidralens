/**
 * Fake Ghidra output, shaped exactly like the bridge's.
 *
 * Standing up a real session costs a JDK, a Ghidra install and several minutes
 * of auto-analysis. That is a fine price to pay once, and a terrible one to pay
 * on every CSS tweak - so the harness runs the views against this instead.
 *
 * If you change the JSON the bridge emits, change it here too. These fixtures
 * are the only thing keeping the views honest when Ghidra is not around.
 */

type Tok = { kind: string; text: string; address?: string };

const t = (kind: string, text: string, address?: string): Tok =>
  address ? { kind, text, address } : { kind, text };

const s = (text: string) => t("syntax", text);

export const DECOMPILATION = {
  name: "validate_license",
  address: "0x140012a40",
  signature: "int validate_license(char *key, uint len)",
  lines: [
    [t("type", "int"), s(" "), t("function", "validate_license", "0x140012a40"), s("(")],
    [
      s("  "),
      t("type", "char"), s(" *"), t("variable", "key", "0x140012a40"), s(", "),
      t("type", "uint"), s(" "), t("variable", "len", "0x140012a40"), s(")"),
    ],
    [s("{")],
    [s("  "), t("type", "uint"), s(" "), t("variable", "checksum", "0x140012a4c"), s(";")],
    [s("  "), t("type", "int"), s(" "), t("variable", "i", "0x140012a50"), s(";")],
    [s("")],
    [
      s("  "),
      t("variable", "checksum", "0x140012a54"), s(" "), t("operator", "="), s(" "),
      t("syntax", "0x1505", "0x140012a54"), s(";"),
    ],
    [
      s("  "), t("operator", "for"), s(" ("),
      t("variable", "i", "0x140012a5c"), s(" "), t("operator", "="), s(" "),
      t("syntax", "0", "0x140012a5c"), s("; "),
      t("variable", "i", "0x140012a60"), s(" "), t("operator", "<"), s(" "),
      t("variable", "len", "0x140012a60"), s("; "),
      t("variable", "i", "0x140012a64"), s("++) {"),
    ],
    [
      s("    "),
      t("variable", "checksum", "0x140012a70"), s(" "), t("operator", "="), s(" "),
      t("variable", "checksum", "0x140012a70"), s(" "), t("operator", "*"), s(" "),
      t("syntax", "33", "0x140012a70"), s(" "), t("operator", "^"), s(" "),
      t("variable", "key", "0x140012a78"), s("["), t("variable", "i", "0x140012a78"), s("];"),
    ],
    [s("  }")],
    [s("")],
    [
      s("  "), t("operator", "if"), s(" ("),
      t("function", "check_hardware_id", "0x140012a90"), s("() "),
      t("operator", "=="), s(" "), t("syntax", "0", "0x140012a90"), s(") {"),
    ],
    [
      s("    "), t("function", "report_tamper", "0x140012a9c"), s("("),
      t("variable", "checksum", "0x140012a9c"), s(");"),
    ],
    [s("    "), t("operator", "return"), s(" "), t("syntax", "-1", "0x140012aa4"), s(";")],
    [s("  }")],
    [s("")],
    [s("  "), t("comment", "/* 0xdeadbeef is the shipped key hash */", "0x140012ab0")],
    [
      s("  "), t("operator", "return"), s(" "),
      t("variable", "checksum", "0x140012ab0"), s(" "), t("operator", "=="), s(" "),
      t("syntax", "0xdeadbeef", "0x140012ab0"), s(";"),
    ],
    [s("}")],
  ] as Tok[][],
  locals: [
    { name: "key", type: "char *", parameter: true },
    { name: "len", type: "uint", parameter: true },
    { name: "checksum", type: "uint", parameter: false },
    { name: "i", type: "int", parameter: false },
  ],
  calls: [
    { name: "check_hardware_id", address: "0x140013100" },
    { name: "report_tamper", address: "0x140013280" },
  ],
  callers: [
    { name: "on_startup", address: "0x140011000" },
    { name: "recheck_timer_cb", address: "0x140011f80" },
  ],
};

const NAMES = [
  "on_startup", "recheck_timer_cb", "validate_license", "check_hardware_id",
  "report_tamper", "decrypt_blob", "inflate_stream", "hash_sha256",
  "net_send", "net_recv", "cfg_parse", "cfg_write", "log_line",
  "alloc_pool", "free_pool", "thread_main", "vm_dispatch", "vm_step",
  "anti_debug_check", "peb_walk", "resolve_import", "patch_iat",
];

export const FUNCTIONS = {
  total: NAMES.length,
  offset: 0,
  functions: NAMES.map((name, i) => ({
    name,
    address: "0x" + (0x140011000 + i * 0x180).toString(16),
    size: 96 + ((i * 137) % 900),
    params: i % 4,
    callers: (i * 7) % 11,
    calls: (i * 3) % 9,
    external: false,
    thunk: i % 9 === 0,
    signature: `undefined4 ${name}(void)`,
  })),
};

export const CALL_GRAPH = {
  root: "0x140012a40",
  nodes: [
    { address: "0x140012a40", name: "validate_license", depth: 0, external: false, thunk: false },
    { address: "0x140011000", name: "on_startup", depth: 1, external: false, thunk: false },
    { address: "0x140011f80", name: "recheck_timer_cb", depth: 1, external: false, thunk: false },
    { address: "0x140013100", name: "check_hardware_id", depth: 1, external: false, thunk: false },
    { address: "0x140013280", name: "report_tamper", depth: 1, external: false, thunk: false },
    { address: "0x140010800", name: "WinMain", depth: 2, external: false, thunk: false },
    { address: "0x140013400", name: "peb_walk", depth: 2, external: false, thunk: false },
    { address: "0x140013500", name: "cpuid_probe", depth: 2, external: false, thunk: false },
    { address: "0x140013600", name: "net_send", depth: 2, external: false, thunk: false },
    { address: "0x140013700", name: "log_line", depth: 2, external: false, thunk: false },
  ],
  edges: [
    { from: "0x140011000", to: "0x140012a40" },
    { from: "0x140011f80", to: "0x140012a40" },
    { from: "0x140012a40", to: "0x140013100" },
    { from: "0x140012a40", to: "0x140013280" },
    { from: "0x140010800", to: "0x140011000" },
    { from: "0x140013100", to: "0x140013400" },
    { from: "0x140013100", to: "0x140013500" },
    { from: "0x140013280", to: "0x140013600" },
    { from: "0x140013280", to: "0x140013700" },
  ],
};
