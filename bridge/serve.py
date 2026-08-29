"""
Loopback HTTP front-end for a GhidraSession.

Why HTTP at all, when the MCP server could just spawn Python per call: because
the whole point of GhidraSession is that the JVM and the analysed program stay
resident. A process boundary that survives independently of the MCP server is
also what lets you restart the MCP server (or the client) without paying for
auto-analysis again.

Security posture, deliberately narrow:
  - binds 127.0.0.1 only, never 0.0.0.0
  - every request must carry the shared token in `X-GhidraLens-Token`
  - Origin/Referer headers are rejected outright, so a web page in the user's
    browser cannot drive it via a forged form post

Run it:  python bridge/serve.py --binary path\\to\\thing.exe
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import traceback
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from session import GhidraSession, SessionError  # noqa: E402

MAX_BODY_BYTES = 1 << 20  # 1 MiB; nothing we accept is anywhere near this


class Handler(BaseHTTPRequestHandler):
    server_version = "GhidraLens/0.1"

    # Injected by main().
    session: GhidraSession
    token: str

    # ------------------------------------------------------------- plumbing

    def log_message(self, fmt, *args):
        # Default logging writes to stderr per request, which drowns the JVM's
        # own analysis output. Keep it to one compact line.
        sys.stderr.write("[bridge] %s\n" % (fmt % args))

    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _authorised(self) -> bool:
        # A browser cannot set X-GhidraLens-Token cross-origin without a
        # preflight, and we never answer one - so a forged request from a page
        # the user happens to have open cannot reach the decompiler.
        if self.headers.get("Origin") or self.headers.get("Referer"):
            return False
        return secrets.compare_digest(
            self.headers.get("X-GhidraLens-Token", ""), self.token
        )

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        if length > MAX_BODY_BYTES:
            raise SessionError("request body too large")
        raw = self.rfile.read(length)
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SessionError("body is not valid JSON") from exc
        if not isinstance(parsed, dict):
            raise SessionError("body must be a JSON object")
        return parsed

    # ------------------------------------------------------------- dispatch

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def _dispatch(self, method: str) -> None:
        if not self._authorised():
            self._send(401, {"error": "bad or missing X-GhidraLens-Token"})
            return

        url = urlparse(self.path)
        route = url.path.rstrip("/") or "/"

        try:
            params = {k: v[0] for k, v in parse_qs(url.query).items()}
            if method == "POST":
                params.update(self._read_json())

            handler = ROUTES.get((method, route))
            if handler is None:
                self._send(404, {"error": "no route " + method + " " + route})
                return

            self._send(200, handler(self.session, params))

        except SessionError as exc:
            self._send(400, {"error": str(exc)})
        except Exception as exc:  # noqa: BLE001 - a JVM error must not kill the server
            traceback.print_exc()
            self._send(500, {"error": type(exc).__name__ + ": " + str(exc)})


# ------------------------------------------------------------------- routes


def _int(params: dict, key: str, default: int) -> int:
    """Query strings arrive as text; JSON bodies arrive typed. Accept both."""
    raw = params.get(key, default)
    try:
        return int(raw)
    except (TypeError, ValueError) as exc:
        raise SessionError(key + " must be a whole number") from exc


def _required(params: dict, key: str) -> str:
    value = str(params.get(key, "")).strip()
    if not value:
        raise SessionError("missing required field: " + key)
    return value


ROUTES = {
    ("GET", "/health"): lambda s, p: {"ok": True, "session": s.info()},
    ("GET", "/info"): lambda s, p: s.info(),
    ("POST", "/open"): lambda s, p: s.open(
        _required(p, "path"), analyze=p.get("analyze", True) is not False
    ),
    ("GET", "/functions"): lambda s, p: s.list_functions(
        query=str(p.get("query", "")),
        limit=_int(p, "limit", 200),
        offset=_int(p, "offset", 0),
        sort=str(p.get("sort", "address")),
    ),
    ("GET", "/decompile"): lambda s, p: s.decompile(
        address=str(p.get("address", "")), name=str(p.get("name", ""))
    ),
    ("GET", "/xrefs"): lambda s, p: s.xrefs_to(
        _required(p, "address"), limit=_int(p, "limit", 200)
    ),
    ("GET", "/callgraph"): lambda s, p: s.call_graph(
        address=str(p.get("address", "")),
        name=str(p.get("name", "")),
        depth=_int(p, "depth", 2),
    ),
    ("GET", "/strings"): lambda s, p: s.strings(
        query=str(p.get("query", "")), limit=_int(p, "limit", 300)
    ),
    ("POST", "/rename"): lambda s, p: s.rename(
        _required(p, "address"),
        _required(p, "new_name"),
        old_name=str(p.get("old_name", "")),
    ),
    ("POST", "/comment"): lambda s, p: s.comment(
        _required(p, "address"), str(p.get("text", ""))
    ),
    ("POST", "/save"): lambda s, p: s.save(),
}


# --------------------------------------------------------------------- main


def default_project_dir() -> str:
    """
    Somewhere to keep Ghidra projects that Ghidra will actually accept.

    Not a dotfile directory. Ghidra's ProjectLocator rejects any path element
    starting with '.' outright - "Path element starting with '.' is not
    permitted" - which rules out the obvious ~/.ghidralens as well as
    ~/.local/share. The error surfaces from deep inside the JVM at open time and
    names neither the setting nor the offending path, so it is worth not walking
    into.
    """
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        return os.path.join(base, "GhidraLens", "projects")
    return os.path.join(os.path.expanduser("~"), "GhidraLens", "projects")


def check_project_dir(path: str) -> None:
    """Fail here, with the reason, rather than inside the JVM."""
    offenders = [
        part
        for part in os.path.abspath(path).replace("\\", "/").split("/")
        if part.startswith(".") and part not in (".", "..")
    ]
    if offenders:
        raise SystemExit(
            "Ghidra will not open a project under a dot-directory "
            f"({', '.join(offenders)} in {path}). Pass --projects with a path "
            "that has no element starting with '.'"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="GhidraLens PyGhidra bridge")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8799)
    parser.add_argument("--binary", help="open this binary at startup")
    parser.add_argument("--no-analyze", action="store_true")
    parser.add_argument(
        "--projects",
        default=os.environ.get("GHIDRALENS_PROJECTS", default_project_dir()),
        help="where Ghidra project files are written",
    )
    args = parser.parse_args()

    if args.host != "127.0.0.1":
        parser.error("refusing to bind anything but 127.0.0.1 - this has no auth model")

    token = os.environ.get("GHIDRALENS_TOKEN") or secrets.token_urlsafe(24)

    check_project_dir(args.projects)
    session = GhidraSession(project_dir=args.projects)

    if args.binary:
        print("[bridge] opening " + args.binary + " (analysis may take a while)...")
        info = session.open(args.binary, analyze=not args.no_analyze)
        print("[bridge] ready: %s functions" % info["functionCount"])

    Handler.session = session
    Handler.token = token

    httpd = HTTPServer((args.host, args.port), Handler)
    url = "http://%s:%d" % (args.host, args.port)

    print("")
    print("  GhidraLens bridge listening on " + url)
    print("  GHIDRALENS_BRIDGE_URL=" + url)
    print("  GHIDRALENS_TOKEN=" + token)
    print("")
    sys.stdout.flush()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[bridge] shutting down")
    finally:
        httpd.server_close()
        session.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
