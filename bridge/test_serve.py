"""
Tests for the bridge's HTTP layer, with no JVM behind it.

Auth, routing, validation and error mapping are pure Python and worth checking
on their own - they are also the parts a contributor is most likely to break
without noticing, since running them normally costs a Ghidra install and several
minutes of auto-analysis.

    python bridge/test_serve.py
"""

from __future__ import annotations

import json
import os
import sys
import threading
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import serve  # noqa: E402
from session import SessionError  # noqa: E402

PORT = 8791
BASE = f"http://127.0.0.1:{PORT}"
TOKEN = "test-token"


class FakeSession:
    """Just enough surface for the routes under test."""

    def info(self) -> dict:
        return {"open": False}

    def list_functions(self, **_kwargs) -> dict:
        raise SessionError("no binary open - call open_binary first")

    def xrefs_to(self, address: str, limit: int = 200) -> dict:
        return {"address": address, "references": [], "limit": limit}


def request(path: str, token: str | None = TOKEN, origin: str | None = None):
    req = urllib.request.Request(BASE + path)
    if token is not None:
        req.add_header("X-GhidraLens-Token", token)
    if origin is not None:
        req.add_header("Origin", origin)
    try:
        with urllib.request.urlopen(req) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, json.load(error)


def main() -> int:
    serve.Handler.session = FakeSession()
    serve.Handler.token = TOKEN
    serve.Handler.log_message = lambda *_args, **_kwargs: None  # quiet

    httpd = serve.HTTPServer(("127.0.0.1", PORT), serve.Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    failures = 0

    def check(ok: bool, label: str, detail: object = "") -> None:
        nonlocal failures
        print(("  ok   " if ok else " FAIL  ") + label + (f" - {detail}" if detail else ""))
        if not ok:
            failures += 1

    try:
        status, body = request("/health")
        check(status == 200 and body["ok"], "authorised GET /health", status)

        status, _ = request("/health", token="wrong")
        check(status == 401, "bad token rejected", status)

        status, _ = request("/health", token=None)
        check(status == 401, "missing token rejected", status)

        # A page in the user's browser must not be able to drive the decompiler,
        # even if it somehow guessed the token.
        status, _ = request("/health", origin="https://evil.example")
        check(status == 401, "Origin header rejected (CSRF)", status)

        status, _ = request("/nope")
        check(status == 404, "unknown route -> 404", status)

        status, body = request("/functions")
        check(
            status == 400 and "no binary open" in body["error"],
            "SessionError -> 400 with its message",
            body.get("error"),
        )

        status, body = request("/xrefs")
        check(
            status == 400 and "address" in body["error"],
            "missing required field -> 400",
            body.get("error"),
        )

        status, body = request("/xrefs?address=0x1000&limit=notanumber")
        check(
            status == 400 and "whole number" in body["error"],
            "non-numeric limit -> 400",
            body.get("error"),
        )
    finally:
        httpd.shutdown()
        httpd.server_close()

    print("\nall checks passed" if not failures else f"\n{failures} check(s) failed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
