"""
A long-lived Ghidra analysis session.

The existing Ghidra MCP servers shell out to `analyzeHeadless` per request, which
re-runs auto-analysis every time - minutes of work to answer a question that
takes milliseconds once the program is in memory. This module opens the program
exactly once via PyGhidra and keeps the Program, the decompiler interface and the
project lock alive for the whole process, so every later call is a lookup rather
than a re-analysis.

Everything here is deliberately JVM-single-threaded: serve.py runs a
single-threaded HTTP server so that every Ghidra call happens on the thread that
started the JVM. Extra threads would each need attaching to the JVM by hand, and
a DecompInterface is not safe to share across threads anyway.
"""

from __future__ import annotations

import glob
import os
import threading
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

DECOMPILE_TIMEOUT_SECONDS = 60

# Where a JDK usually lives, per platform. PyGhidra refuses to start without
# JAVA_HOME or a `java` on PATH, and on Windows a freshly installed JDK is on
# neither until the shell is restarted - which produces a baffling
# "Java was not found in PATH or JAVA_HOME" on a machine that plainly has Java.
JDK_GLOBS = [
    r"C:\Program Files\Eclipse Adoptium\jdk-2*",
    r"C:\Program Files\Java\jdk-2*",
    r"C:\Program Files\Microsoft\jdk-2*",
    r"C:\Program Files\Amazon Corretto\jdk2*",
    "/Library/Java/JavaVirtualMachines/*/Contents/Home",
    "/usr/lib/jvm/*",
    os.path.expanduser("~/.jdks/*"),
]


class SessionError(RuntimeError):
    """Anything the caller did wrong - surfaced to the client as HTTP 400."""


@dataclass
class GhidraSession:
    """Holds one opened program. Opening another replaces it."""

    project_dir: str
    project_name: str = "ghidralens"

    binary_path: Optional[str] = None
    _project: Any = None
    _program: Any = None
    _consumer: Any = None
    _decompiler: Any = None
    _monitor: Any = None
    _lock: threading.RLock = field(default_factory=threading.RLock)
    _started: bool = False

    # ---------------------------------------------------------------- startup

    def start_jvm(self) -> None:
        """Boot the JVM once. Importing `ghidra` before this raises."""
        if self._started:
            return
        ensure_java_home()
        assert_no_shadowed_ghidra()

        import pyghidra

        pyghidra.start(verbose=False)
        self._started = True

    def open(self, binary_path: str, analyze: bool = True) -> dict:
        """
        Open a binary, replacing whatever was open before.

        Auto-analysis is the slow part - ~10 seconds for a 64 KB system utility,
        minutes for something like a game client - so it must happen exactly
        once. Getting that right takes more care than it looks:

          - the importer saves the program *before* analysis, so saving the load
            results is not enough; the analysed program has to be saved again or
            the next open silently re-imports a half-analysed copy (measured:
            91 functions instead of 198)
          - Ghidra's own "Analyzed" flag is what says whether that already
            happened, so a re-open reads it rather than re-running analysis and
            hoping

        `pyghidra.open_program` would do all of this in one call, but it is
        deprecated in PyGhidra 3.x and blows the Python recursion limit on the
        way out.
        """
        binary_path = os.path.abspath(binary_path)
        if not os.path.isfile(binary_path):
            raise SessionError("no such file: " + binary_path)

        self.start_jvm()

        import pyghidra
        from java.lang import Object as JavaObject

        with self._lock:
            self.close()

            os.makedirs(self.project_dir, exist_ok=True)
            self._project = pyghidra.open_project(
                self.project_dir, self.project_name, create=True
            )

            project_path = "/" + os.path.basename(binary_path)
            if self._project.getProjectData().getFile(project_path) is None:
                results = pyghidra.program_loader().project(self._project).source(
                    binary_path
                ).load()
                try:
                    results.save(pyghidra.task_monitor())
                finally:
                    # Release the importer's handles; we re-open through the
                    # project below so there is exactly one consumer to track.
                    results.close()

            self._program, self._consumer = pyghidra.consume_program(
                self._project, project_path
            )
            self.binary_path = binary_path

            if analyze and not self._is_analyzed():
                pyghidra.analyze(self._program)
                self._flush()

            self._decompiler = self._new_decompiler()

        return self.info()

    def _is_analyzed(self) -> bool:
        import pyghidra

        return bool(pyghidra.program_info(self._program).getBoolean("Analyzed", False))

    def _flush(self) -> None:
        """Write the in-memory program back into the project on disk."""
        import pyghidra

        self._program.save("GhidraLens", pyghidra.task_monitor())

    def close(self) -> None:
        with self._lock:
            if self._decompiler is not None:
                self._decompiler.dispose()
                self._decompiler = None
            if self._program is not None and self._consumer is not None:
                self._program.release(self._consumer)
            if self._project is not None:
                self._project.close()
            self._project = None
            self._program = None
            self._consumer = None
            self.binary_path = None

    def _new_decompiler(self):
        from ghidra.app.decompiler import DecompInterface, DecompileOptions

        ifc = DecompInterface()
        ifc.setOptions(DecompileOptions())
        ifc.openProgram(self._program)
        return ifc

    @property
    def monitor(self):
        if self._monitor is None:
            from ghidra.util.task import ConsoleTaskMonitor

            self._monitor = ConsoleTaskMonitor()
        return self._monitor

    def require_program(self):
        if self._program is None:
            raise SessionError("no binary open - call open_binary first")
        return self._program

    # ----------------------------------------------------------------- lookup

    def info(self) -> dict:
        if self._program is None:
            return {"open": False}
        p = self._program
        return {
            "open": True,
            "path": self.binary_path,
            "name": str(p.getName()),
            "languageId": str(p.getLanguageID()),
            "compiler": str(p.getCompilerSpec().getCompilerSpecID()),
            "imageBase": hexaddr(p.getImageBase()),
            "functionCount": int(p.getFunctionManager().getFunctionCount()),
            "executableFormat": str(p.getExecutableFormat()),
            "executableSha256": str(p.getExecutableSHA256() or ""),
        }

    def all_functions(self):
        """
        Every function, internal and imported.

        `getFunctions(True)` walks the memory address spaces, so it silently
        omits externals - on a small system utility that was 94 of 198 functions,
        i.e. every Win32 API the binary imports, which is most of what you
        actually want to search for.
        """
        program = self.require_program()
        fm = program.getFunctionManager()
        yield from fm.getFunctions(True)
        yield from fm.getExternalFunctions()

    def resolve(self, address: str = "", name: str = ""):
        """Find a function by address, or by exact then substring name match."""
        program = self.require_program()
        fm = program.getFunctionManager()

        if address:
            addr = self.to_address(address)
            func = fm.getFunctionAt(addr) or fm.getFunctionContaining(addr)
            if func is None:
                raise SessionError("no function at " + address)
            return func

        if not name:
            raise SessionError("pass either address or name")

        matches = [f for f in self.all_functions() if str(f.getName()) == name]
        if not matches:
            matches = [f for f in self.all_functions() if name in str(f.getName())]
        if not matches:
            raise SessionError("no function named " + repr(name))
        if len(matches) > 1:
            options = ", ".join(sorted(str(f.getName()) for f in matches[:8]))
            raise SessionError(repr(name) + " is ambiguous: " + options)
        return matches[0]

    def to_address(self, address: str):
        """Parse whatever `hexaddr` produced - bare hex, or a space-qualified form."""
        program = self.require_program()
        factory = program.getAddressFactory()
        text = address.strip()

        if ":" in text:
            parsed = factory.getAddress(text)
            if parsed is None:
                raise SessionError("bad address " + repr(address))
            return parsed

        if text.lower().startswith("0x"):
            text = text[2:]
        try:
            offset = int(text, 16)
        except ValueError as exc:
            raise SessionError("bad address " + repr(address)) from exc
        return factory.getDefaultAddressSpace().getAddress(offset)

    def list_functions(
        self, query: str = "", limit: int = 200, offset: int = 0, sort: str = "address"
    ) -> dict:
        program = self.require_program()
        needle = query.lower()

        rows = []
        for f in self.all_functions():
            fname = str(f.getName())
            if needle and needle not in fname.lower():
                continue
            rows.append(
                {
                    "name": fname,
                    "address": hexaddr(f.getEntryPoint()),
                    "size": 0 if f.isExternal() else int(f.getBody().getNumAddresses()),
                    "params": int(f.getParameterCount()),
                    "callers": len(list(f.getCallingFunctions(self.monitor))),
                    "calls": len(list(f.getCalledFunctions(self.monitor))),
                    "external": bool(f.isExternal()),
                    "thunk": bool(f.isThunk()),
                    "signature": str(f.getSignature().getPrototypeString()),
                }
            )

        keys = {
            # Externals sort after everything in memory rather than blowing up
            # int(); their offsets are indices, not addresses, so ordering them
            # among real addresses would be meaningless anyway.
            "address": lambda r: (1, r["address"])
            if ":" in r["address"]
            else (0, "%016x" % int(r["address"], 16)),
            "name": lambda r: r["name"].lower(),
            "size": lambda r: -r["size"],
            "callers": lambda r: -r["callers"],
        }
        rows.sort(key=keys.get(sort, keys["address"]))

        return {
            "total": len(rows),
            "offset": offset,
            "functions": rows[offset : offset + limit],
        }

    # ------------------------------------------------------------- decompiler

    def decompile(self, address: str = "", name: str = "") -> dict:
        """
        Decompile one function and return the C *as tokens*, not as a string.

        The token stream is the whole point of this project. Ghidra's decompiler
        annotates every identifier it emits with the address it came from and what
        kind of thing it is - a local, a called function, a type. A plain text blob
        throws all of that away. Keeping it is what lets the view make every symbol
        renameable and every call navigable.
        """
        func = self.resolve(address=address, name=name)

        # An import is a name and a call target, not code - it lives in another
        # module entirely. Ghidra's own answer here is "Cannot marshal address
        # space: EXTERNAL", which says nothing useful to anyone.
        if func.isExternal():
            library = str(func.getExternalLocation().getLibraryName() or "another module")
            raise SessionError(
                str(func.getName()) + " is imported from " + library
                + " - there is no code for it in this binary. Use xrefs_to to see "
                "where it is called from."
            )

        results = self._decompiler.decompileFunction(
            func, DECOMPILE_TIMEOUT_SECONDS, self.monitor
        )
        if not results.decompileCompleted():
            raise SessionError("decompilation failed: " + str(results.getErrorMessage()))

        lines: list[list[dict]] = [[]]
        for token in _flatten_markup(results.getCCodeMarkup()):
            kind = str(token.getClass().getSimpleName())
            if kind == "ClangBreak":
                indent = " " * int(token.getIndent())
                lines.append([{"kind": "syntax", "text": indent}])
                continue
            text = str(token.getText())
            if not text:
                continue
            entry: dict[str, Any] = {"kind": _token_kind(kind), "text": text}
            addr = token.getMinAddress()
            if addr is not None:
                entry["address"] = hexaddr(addr)
            lines[-1].append(entry)

        return {
            "name": str(func.getName()),
            "address": hexaddr(func.getEntryPoint()),
            "signature": str(func.getSignature().getPrototypeString()),
            "lines": lines,
            "locals": _local_symbols(results),
            "calls": [_ref(c) for c in func.getCalledFunctions(self.monitor)],
            "callers": [_ref(c) for c in func.getCallingFunctions(self.monitor)],
        }

    # ------------------------------------------------------------------ graph

    def xrefs_to(self, address: str, limit: int = 200) -> dict:
        program = self.require_program()
        target = self.to_address(address)
        fm = program.getFunctionManager()

        rows = []
        for ref in program.getReferenceManager().getReferencesTo(target):
            src = ref.getFromAddress()
            owner = fm.getFunctionContaining(src)
            rows.append(
                {
                    "from": hexaddr(src),
                    "type": str(ref.getReferenceType().getName()),
                    "inFunction": str(owner.getName()) if owner else None,
                    "functionAddress": hexaddr(owner.getEntryPoint()) if owner else None,
                }
            )
            if len(rows) >= limit:
                break

        return {"address": hexaddr(target), "references": rows}

    def call_graph(self, address: str = "", name: str = "", depth: int = 2) -> dict:
        """
        Breadth-first walk outwards from one function, in both directions.

        Depth is capped at 3 on purpose. Call graphs fan out exponentially, and
        depth 3 on a hot utility function pulls in most of the binary and renders
        as a hairball nobody can read.
        """
        root = self.resolve(address=address, name=name)
        depth = max(1, min(int(depth), 3))

        nodes: dict[str, dict] = {}
        edges: set[tuple[str, str]] = set()

        def add(func, level: int) -> str:
            key = hexaddr(func.getEntryPoint())
            existing = nodes.get(key)
            if existing is None or level < existing["depth"]:
                nodes[key] = {
                    "address": key,
                    "name": str(func.getName()),
                    "depth": level,
                    "external": bool(func.isExternal()),
                    "thunk": bool(func.isThunk()),
                }
            return key

        root_key = add(root, 0)
        frontier = [(root, 0)]
        seen = {root_key}

        while frontier:
            func, level = frontier.pop(0)
            if level >= depth:
                continue
            here = hexaddr(func.getEntryPoint())

            for callee in func.getCalledFunctions(self.monitor):
                key = add(callee, level + 1)
                edges.add((here, key))
                if key not in seen:
                    seen.add(key)
                    frontier.append((callee, level + 1))

            for caller in func.getCallingFunctions(self.monitor):
                key = add(caller, level + 1)
                edges.add((key, here))
                if key not in seen:
                    seen.add(key)
                    frontier.append((caller, level + 1))

        return {
            "root": root_key,
            "nodes": list(nodes.values()),
            "edges": [{"from": a, "to": b} for a, b in sorted(edges)],
        }

    def strings(self, query: str = "", limit: int = 300) -> dict:
        """Defined string data - where the human-readable clues in a binary live."""
        program = self.require_program()
        needle = query.lower()
        refs = program.getReferenceManager()

        rows = []
        for data in program.getListing().getDefinedData(True):
            if not data.hasStringValue():
                continue
            value = str(data.getValue())
            if needle and needle not in value.lower():
                continue
            addr = data.getAddress()
            rows.append(
                {
                    "address": hexaddr(addr),
                    "value": value,
                    "length": len(value),
                    "refs": int(refs.getReferenceCountTo(addr)),
                }
            )
            if len(rows) >= limit:
                break

        return {"total": len(rows), "strings": rows}

    # ----------------------------------------------------------------- writes

    def rename(self, address: str, new_name: str, old_name: str = "") -> dict:
        """
        Rename a function, or a local variable inside one.

        Ghidra stores these in two different places. A function name lives on the
        Function object and writes straight through. A decompiler variable exists
        only in the HighFunction and has to be pushed back into the database
        explicitly. Passing `old_name` selects the variable case - which is what a
        click on an identifier in the decompiler view sends.
        """
        from ghidra.program.model.pcode import HighFunctionDBUtil
        from ghidra.program.model.symbol import SourceType

        new_name = new_name.strip()
        if not new_name:
            raise SessionError("new_name is empty")

        program = self.require_program()
        func = self.resolve(address=address)

        tx = program.startTransaction("GhidraLens rename -> " + new_name)
        committed = False
        try:
            if not old_name:
                func.setName(new_name, SourceType.USER_DEFINED)
                target = "function"
            else:
                results = self._decompiler.decompileFunction(
                    func, DECOMPILE_TIMEOUT_SECONDS, self.monitor
                )
                high = results.getHighFunction()
                if high is None:
                    raise SessionError("could not decompile to find that variable")

                symbol = _find_local(high, old_name)
                if symbol is None:
                    raise SessionError(
                        "no local named " + repr(old_name) + " in " + str(func.getName())
                    )

                HighFunctionDBUtil.updateDBVariable(
                    symbol, new_name, None, SourceType.USER_DEFINED
                )
                target = "variable"
            committed = True
        finally:
            # Rolling back on failure keeps a half-applied rename out of the project.
            program.endTransaction(tx, committed)

        return {
            "renamed": target,
            "function": str(func.getName()),
            "address": hexaddr(func.getEntryPoint()),
            "newName": new_name,
        }

    def comment(self, address: str, text: str) -> dict:
        """Attach a plate comment. Persists in the project and shows up in the GUI."""
        program = self.require_program()
        addr = self.to_address(address)

        tx = program.startTransaction("GhidraLens comment")
        committed = False
        try:
            _set_pre_comment(program, addr, text)
            committed = True
        finally:
            program.endTransaction(tx, committed)

        return {"address": hexaddr(addr), "comment": text}

    def save(self) -> dict:
        """Flush renames and comments back to the project on disk."""
        self.require_program()
        self._flush()
        return {"saved": True, "path": self.binary_path}


# --------------------------------------------------------------------- helpers


def assert_no_shadowed_ghidra() -> None:
    """
    Refuse to start if a directory on sys.path is called `ghidra`.

    PyGhidra serves the `ghidra` package out of the JVM. A plain directory of
    that name anywhere on sys.path wins instead, as an implicit namespace
    package - and then PyGhidra's own import hook, which resolves modules by
    doing `from ghidra.framework import Application`, re-enters itself and
    recurses until the interpreter gives up.

    The failure surfaces as a bare "maximum recursion depth exceeded" with a
    thousand identical frames and no mention of the actual cause, so it is worth
    a few lines to catch. It is not hypothetical: Ghidra itself creates a
    `ghidra` directory in the system temp folder, which shadows the real package
    for any script run from there.
    """
    import sys

    for entry in sys.path:
        candidate = os.path.join(entry or os.getcwd(), "ghidra")
        if os.path.isdir(candidate) and not os.path.isfile(
            os.path.join(candidate, "__init__.py")
        ):
            raise SessionError(
                f"a directory named 'ghidra' on sys.path ({candidate}) shadows the "
                "package PyGhidra serves from the JVM. Run the bridge from "
                "somewhere else, or remove that directory from sys.path."
            )


def ensure_java_home() -> None:
    """
    Point JAVA_HOME at a JDK if the environment has not already.

    PyGhidra shells out to Ghidra's LaunchSupport, which needs either JAVA_HOME
    or a `java` on PATH. On Windows a JDK installed through winget or an MSI is
    on neither until the shell restarts, so an otherwise perfectly set up machine
    fails with "Java was not found in PATH or JAVA_HOME". Finding it ourselves
    turns that into a non-event.
    """
    if os.environ.get("JAVA_HOME"):
        return

    for pattern in JDK_GLOBS:
        # Newest first: these directory names sort lexicographically by version
        # closely enough that the last match is the highest JDK present.
        for candidate in sorted(glob.glob(pattern), reverse=True):
            launcher = os.path.join(candidate, "bin", "java.exe")
            if not os.path.isfile(launcher):
                launcher = os.path.join(candidate, "bin", "java")
            if os.path.isfile(launcher):
                os.environ["JAVA_HOME"] = candidate
                return


def hexaddr(addr) -> str:
    """
    Render an address as a string that can be handed straight back to us.

    Not every address is a RAM offset. Imported functions live in Ghidra's
    EXTERNAL space, where the offset is a small index - `FindClose` is offset
    0x3e - and flattening that to "0x3e" produces a perfectly valid RAM address
    that points at nothing. Clicking any imported symbol then 404s.

    So anything outside loaded memory keeps Ghidra's own space-qualified form
    ("EXTERNAL:0000003e"), which `to_address` round-trips exactly.
    """
    if addr.getAddressSpace().isLoadedMemorySpace():
        return "0x%x" % int(addr.getOffset())
    return str(addr)


def _flatten_markup(node) -> Iterable[Any]:
    """
    Walk Ghidra's ClangTokenGroup tree into a flat token stream.

    The markup is a tree of groups - statements, expressions, blocks - with tokens
    at the leaves. Nothing downstream cares about the nesting, only about the
    tokens and where the line breaks fall, so flatten it once here.
    """
    from ghidra.app.decompiler import ClangTokenGroup

    stack = [node]
    while stack:
        current = stack.pop()
        if isinstance(current, ClangTokenGroup):
            children = [current.Child(i) for i in range(current.numChildren())]
            stack.extend(reversed(children))
        else:
            yield current


def _ref(func) -> dict:
    return {
        "name": str(func.getName()),
        "address": hexaddr(func.getEntryPoint()),
        "external": bool(func.isExternal()),
    }


def _find_local(high_function, name: str):
    symbols = high_function.getLocalSymbolMap().getSymbols()
    while symbols.hasNext():
        candidate = symbols.next()
        if str(candidate.getName()) == name:
            return candidate
    return None


def _local_symbols(results) -> list[dict]:
    high = results.getHighFunction()
    if high is None:
        return []
    out = []
    symbols = high.getLocalSymbolMap().getSymbols()
    while symbols.hasNext():
        sym = symbols.next()
        out.append(
            {
                "name": str(sym.getName()),
                "type": str(sym.getDataType().getDisplayName()),
                "parameter": bool(sym.isParameter()),
            }
        )
    return out


_KINDS = {
    "ClangFuncNameToken": "function",
    "ClangVariableToken": "variable",
    "ClangFieldToken": "field",
    "ClangTypeToken": "type",
    "ClangLabelToken": "label",
    "ClangCommentToken": "comment",
    "ClangOpToken": "operator",
    "ClangSyntaxToken": "syntax",
    "ClangCaseToken": "case",
}


def _token_kind(java_class_name: str) -> str:
    return _KINDS.get(java_class_name, "syntax")


def _set_pre_comment(program, addr, text: str) -> None:
    """
    Ghidra 12 replaced the int comment constants with a CommentType enum. Try the
    new API first and fall back to the old one, so this file works on 11.x too.
    """
    listing = program.getListing()
    try:
        from ghidra.program.model.listing import CommentType

        listing.setComment(addr, CommentType.PRE, text)
    except ImportError:
        from ghidra.program.model.listing import CodeUnit

        listing.setComment(addr, CodeUnit.PRE_COMMENT, text)
