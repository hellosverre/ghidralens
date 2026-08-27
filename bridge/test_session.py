"""
End-to-end test of GhidraSession against a real binary.

Unlike test_serve.py, this one needs the whole stack: a JDK, a Ghidra install
and PyGhidra. It is the only thing that actually proves the Ghidra API calls in
session.py are right, so run it after touching that file.

    python bridge/test_session.py [path-to-binary]

Defaults to a small Windows system utility, which analyses in ~20 seconds.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from session import GhidraSession, SessionError  # noqa: E402

DEFAULT_BINARY = os.path.join(
    os.environ.get("SystemRoot", r"C:\Windows"), "System32", "where.exe"
)

failures = 0
results: dict = {}


def step(label: str, fn):
    """Run one call, time it, and keep going if it fails - a later step may still
    say something useful about why."""
    global failures
    started = time.time()
    try:
        value = fn()
        print(f"  ok   {label}  ({time.time() - started:.1f}s)")
        return value
    except Exception as error:  # noqa: BLE001 - a failure here is the result
        failures += 1
        print(f" FAIL  {label}: {type(error).__name__}: {error}")
        return None


def expect(condition: bool, label: str, detail: object = "") -> None:
    global failures
    print(("  ok   " if condition else " FAIL  ") + label + (f" - {detail}" if detail else ""))
    if not condition:
        failures += 1


def main() -> int:
    binary = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_BINARY
    if not os.path.isfile(binary):
        print(f"no such binary: {binary}")
        return 2

    # Copy out of System32: Ghidra writes nothing to the source, but pointing an
    # importer at a live system directory is a bad habit to encode in a test.
    workdir = tempfile.mkdtemp(prefix="ghidralens-test-")
    target = os.path.join(workdir, os.path.basename(binary))
    shutil.copy2(binary, target)

    session = GhidraSession(project_dir=os.path.join(workdir, "proj"))

    try:
        print(f"\n--- cold open: {os.path.basename(target)} ---")
        info = step("open + auto-analysis", lambda: session.open(target, analyze=True))
        if info is None:
            return 1
        print("       ", json.dumps(info)[:220])
        expect(info["open"] and info["functionCount"] > 10, "analysed", info["functionCount"])

        listing = step("list_functions", lambda: session.list_functions(limit=5, sort="size"))
        expect(bool(listing and listing["functions"]), "functions returned", listing and listing["total"])
        biggest = listing["functions"][0]
        print(f"        biggest: {biggest['name']} @ {biggest['address']} ({biggest['size']} bytes)")

        print("\n--- decompiler ---")
        code = step("decompile", lambda: session.decompile(address=biggest["address"]))
        if code:
            kinds: dict[str, int] = {}
            for line in code["lines"]:
                for token in line:
                    kinds[token["kind"]] = kinds.get(token["kind"], 0) + 1
            print(f"        {code['signature']}")
            print(f"        lines={len(code['lines'])} locals={len(code['locals'])} "
                  f"calls={len(code['calls'])} callers={len(code['callers'])}")
            print(f"        token kinds: {kinds}")
            # The token stream is the whole product. Plain text would still
            # "work" while quietly making every view non-interactive.
            expect(kinds.get("variable", 0) > 0, "variable tokens present", kinds.get("variable"))
            expect(kinds.get("type", 0) > 0, "type tokens present", kinds.get("type"))
            expect(
                any(t.get("address") for line in code["lines"] for t in line),
                "tokens carry addresses",
            )
            print("        --- first 8 lines ---")
            for line in code["lines"][1:9]:
                print("        |" + "".join(t["text"] for t in line))

        print("\n--- imported functions ---")
        # Externals live in Ghidra's EXTERNAL address space, not in memory.
        # They were invisible here once (94 of 198 functions missing) and their
        # addresses round-tripped into bogus RAM offsets, so clicking any
        # imported symbol 404'd. Both are worth pinning down.
        every = step("list all functions", lambda: session.list_functions(limit=5000))
        externals = [f for f in (every["functions"] if every else []) if f["external"]]
        expect(bool(externals), "imports are listed", f"{len(externals)} of {every['total']}")
        if externals:
            imported = externals[0]
            print(f"        e.g. {imported['name']} @ {imported['address']}")
            expect(":" in imported["address"], "import keeps its address space", imported["address"])
            resolved = step(
                f"resolve import by address {imported['address']}",
                lambda: session.resolve(address=imported["address"]),
            )
            expect(
                resolved is not None and str(resolved.getName()) == imported["name"],
                "import round-trips through its address",
                resolved and str(resolved.getName()),
            )

        print("\n--- graph ---")
        step("xrefs_to", lambda: session.xrefs_to(biggest["address"], limit=5))
        graph = step("call_graph depth=2", lambda: session.call_graph(address=biggest["address"], depth=2))
        if graph:
            print(f"        nodes={len(graph['nodes'])} edges={len(graph['edges'])}")
            expect(len(graph["nodes"]) >= 1, "graph has the root at least")
        strings = step("strings", lambda: session.strings(limit=5))
        if strings and strings["strings"]:
            print("        ", [s["value"][:36] for s in strings["strings"][:3]])

        print("\n--- writes ---")
        step("rename function", lambda: session.rename(biggest["address"], "gl_renamed_fn"))
        renamed = step("re-decompile", lambda: session.decompile(address=biggest["address"]))
        expect(bool(renamed) and renamed["name"] == "gl_renamed_fn", "function rename stuck", renamed and renamed["name"])

        locals_ = [v for v in (renamed["locals"] if renamed else []) if not v["parameter"]]
        if locals_:
            old = locals_[0]["name"]
            step(f"rename local {old} -> gl_var", lambda: session.rename(biggest["address"], "gl_var", old_name=old))
            after = step("re-decompile", lambda: session.decompile(address=biggest["address"]))
            names = [v["name"] for v in after["locals"]] if after else []
            expect("gl_var" in names, "local rename stuck", names[:6])
        else:
            print("  skip  local rename - no non-parameter locals in this function")

        step("comment", lambda: session.comment(biggest["address"], "GhidraLens was here"))
        step("save", lambda: session.save())
        step("resolve by new name", lambda: session.resolve(name="gl_renamed_fn"))

        print("\n--- error paths ---")
        for label, fn in [
            ("unknown function name", lambda: session.decompile(name="definitely_not_here_zzz")),
            ("malformed address", lambda: session.to_address("nothex")),
            ("empty rename", lambda: session.rename(biggest["address"], "   ")),
        ]:
            try:
                fn()
                expect(False, f"{label} should raise SessionError")
            except SessionError as error:
                expect(True, f"{label} -> SessionError", str(error)[:60])

        print("\n--- warm reopen (analysis must be cached) ---")
        session.close()
        reopened = GhidraSession(project_dir=os.path.join(workdir, "proj"))
        started = time.time()
        warm = step("reopen", lambda: reopened.open(target, analyze=True))
        if warm:
            elapsed = time.time() - started
            print(f"        {warm['functionCount']} functions in {elapsed:.1f}s")
            # The whole point of a resident session. If analysis silently did not
            # persist, this comes back with a fraction of the functions.
            expect(
                warm["functionCount"] == info["functionCount"],
                "reopen has the same function count",
                f"{warm['functionCount']} vs {info['functionCount']}",
            )
            expect(elapsed < 15, "reopen skipped re-analysis", f"{elapsed:.1f}s")
            expect(
                reopened.resolve(name="gl_renamed_fn") is not None,
                "rename survived the reopen",
            )
        reopened.close()

    finally:
        session.close()
        shutil.rmtree(workdir, ignore_errors=True)

    print("\nall checks passed" if not failures else f"\n{failures} check(s) failed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
