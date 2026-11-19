"""Serves the scanner for the tests with the response headers from the repo's `_headers` file.

Cloudflare Pages reads `_headers` in production. Applying the same file here means the
Content-Security-Policy under test is the one that ships, not a copy of it.

Run by hand: python3 tests/serve.py [port]
"""
import functools
import http.server
import os
import shutil
import sys
import threading
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
# The tests run against the bare page of this repository. The same tests can be pointed at
# another site that carries the scanner (the pages at helban.dev before a release), with three
# variables: SCANNER_SITE_ROOT is that site's folder, SCANNER_PAGE_PATH the page in it
# ("en/wp-backup-scanner/"), SCANNER_SERVED what a patched copy of the site has to hold.
SERVED = tuple(os.environ.get("SCANNER_SERVED", "index.html,harness.css,_headers,scanner").split(","))
PAGE_PATH = os.environ.get("SCANNER_PAGE_PATH", "")
DEFAULT_PORT = 8765


def site_root() -> Path:
    """The folder under test: the repo, or the copy run_mutations.py points the tests at."""
    return Path(os.environ.get("SCANNER_SITE_ROOT", REPO_ROOT))


def copy_site(folder: Path, patches: dict[str, tuple[str, str]] | None = None) -> Path:
    """Copies what the server hands out into `folder` and applies text replacements, given as
    {file: (find, replace)}. Tests use it to run against a scanner with one thing changed."""
    for name in SERVED:
        source = site_root() / name
        (folder / name).parent.mkdir(parents=True, exist_ok=True)
        if source.is_dir():
            shutil.copytree(source, folder / name)
        else:
            shutil.copy2(source, folder / name)
    for name, (find, replace) in (patches or {}).items():
        original = (folder / name).read_text(encoding="utf-8")
        if original.count(find) != 1:
            raise ValueError(f"the text to replace occurs {original.count(find)} times in {name}, expected 1")
        (folder / name).write_text(original.replace(find, replace), encoding="utf-8")
    return folder


def parse_headers_file(text: str) -> list[tuple[str, list[tuple[str, str]]]]:
    """Returns (path pattern, headers) blocks in file order."""
    blocks: list[tuple[str, list[tuple[str, str]]]] = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace():
            blocks.append((line.strip(), []))
            continue
        if not blocks:
            raise ValueError(f"header line before any path: {line!r}")
        name, separator, value = line.strip().partition(":")
        if not separator:
            raise ValueError(f"not a header line: {line!r}")
        blocks[-1][1].append((name.strip(), value.strip()))
    return blocks


def headers_for(blocks: list[tuple[str, list[tuple[str, str]]]], request_path: str) -> list[tuple[str, str]]:
    path = request_path.split("?", 1)[0]
    matched: list[tuple[str, str]] = []
    for pattern, headers in blocks:
        is_prefix_rule = pattern.endswith("*")
        if (is_prefix_rule and path.startswith(pattern[:-1])) or path == pattern:
            matched.extend(headers)
    return matched


class _Handler(http.server.SimpleHTTPRequestHandler):
    header_blocks: list[tuple[str, list[tuple[str, str]]]] = []

    def end_headers(self) -> None:
        for name, value in headers_for(self.header_blocks, self.path):
            self.send_header(name, value)
        super().end_headers()

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 (name fixed by the base class)
        return


class ScannerServer:
    """A local server for one site root. Use as a context manager."""

    def __init__(self, root: Path = REPO_ROOT, port: int = 0) -> None:
        handler = type("Handler", (_Handler,), {
            "header_blocks": parse_headers_file((root / "_headers").read_text(encoding="utf-8")),
        })
        self._httpd = http.server.ThreadingHTTPServer(
            ("127.0.0.1", port), functools.partial(handler, directory=str(root)),
        )
        self.origin = f"http://127.0.0.1:{self._httpd.server_address[1]}/"
        self.url = self.origin + PAGE_PATH

    def __enter__(self) -> "ScannerServer":
        threading.Thread(target=self._httpd.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT
    with ScannerServer(site_root(), port=port) as server:
        print(f"serving {site_root()} at {server.url} (Ctrl+C stops)")
        try:
            threading.Event().wait()
        except KeyboardInterrupt:
            print("stopped")


if __name__ == "__main__":
    main()
