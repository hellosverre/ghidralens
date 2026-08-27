# Setting up the Python side

PyGhidra ships **inside** your Ghidra install rather than on PyPI, and it is
pinned to that install's version. Installing it from anywhere else gets you a
mismatched pair that fails at the first `import ghidra`.

## What you need

| Requirement | Why | Check |
| --- | --- | --- |
| **Ghidra 11.3+** | PyGhidra landed as a first-class launcher in 11.3 | `ls $GHIDRA_INSTALL_DIR/Ghidra/Features/PyGhidra/pypkg/dist` |
| **JDK 21+** | Ghidra runs on the JVM; it does not bundle one | `java -version` |
| **Python 3.9–3.13** | JPype ships wheels per CPython version; 3.14 has none yet | `python --version` |

The Python version is the one that catches people out. If your default `python`
is 3.14, make the venv with an older interpreter explicitly.

## Windows

```powershell
$env:GHIDRA_INSTALL_DIR = "C:\path\to\ghidra_12.1.2_PUBLIC"
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install --no-index -f "$env:GHIDRA_INSTALL_DIR\Ghidra\Features\PyGhidra\pypkg\dist" pyghidra
```

## macOS / Linux

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.1.2_PUBLIC
python3.12 -m venv .venv
source .venv/bin/activate
pip install --no-index -f "$GHIDRA_INSTALL_DIR/Ghidra/Features/PyGhidra/pypkg/dist" pyghidra
```

## Verify

```bash
python -c "import pyghidra; pyghidra.start(); import ghidra; print(ghidra.framework.Application.getApplicationVersion())"
```

That prints your Ghidra version if the JVM, the JDK and PyGhidra all agree. If
it hangs or throws, fix it here — every problem at this layer shows up later as
an unhelpful timeout from the MCP server.

## Common failures

| Symptom | Cause |
| --- | --- |
| `No matching distribution found for pyghidra` | Wrong `-f` path, or a Python with no JPype wheel (3.14) |
| `Unable to locate Ghidra installation` | `GHIDRA_INSTALL_DIR` unset and no `lastrun` file — run the Ghidra GUI once, or set it |
| `JVM DLL not found` / `JAVA_HOME` errors | No JDK 21+, or `JAVA_HOME` points at a JRE |
| Hangs forever on `open` | Auto-analysis on a large binary. Normal the first time; watch the bridge's stderr |
