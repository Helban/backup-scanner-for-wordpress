#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Check that a site serves the scanner exactly as this repository publishes it.

The scanner's promise ("the file never leaves your browser") holds only if the code in the
visitor's browser is the code you can read here. Run this from a checkout of the release you
want to compare with:

    python3 verify_live.py
    python3 verify_live.py --origin https://helban.dev --page /en/wp-backup-scanner/

It downloads every file of scanner/ from the site and compares it byte for byte with the
checkout, then checks the two response headers the promise rests on:

  - the page's Content-Security-Policy, which lists the only hosts the page may contact;
  - the Content-Security-Policy of the scanner's own files. A worker takes its policy from the
    response of its script, so this header is what leaves the code that reads the archive
    without any network. If it were missing, nothing on the page would look different.

Both must equal the policies in this repository's _headers file. The page's own HTML and CSS
belong to the site, not to this repository; every script the page loads from outside scanner/
is listed with its hash so that it can be read.

Needs Python 3.10 or newer and nothing else. Exit code 0: everything matches.
"""
import argparse
import hashlib
import json
import re
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlsplit

REPO_ROOT = Path(__file__).resolve().parent
SCANNER_FOLDER = "scanner"
RELEASE_NOTE = "release.json"
DEFAULT_ORIGIN = "https://helban.dev"
DEFAULT_PAGES = ("/skaner-kopii-wordpress/", "/en/wp-backup-scanner/")
POLICY_HEADER = "Content-Security-Policy"
PAGE_RULE = "/"
SCANNER_RULE = "/scanner/*"
ENTRY_SCRIPT = "main.js"
TIMEOUT_SECONDS = 30
USER_AGENT = "backup-scanner-for-wordpress verify_live"
COMMIT_FORMAT = re.compile(r"^[0-9a-f]{40}$")


@dataclass
class Served:
    status: int
    body: bytes
    headers: dict[str, str]


@dataclass
class Check:
    problems: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


class _Scripts(HTMLParser):
    """Collects the src of every script element of a page."""

    def __init__(self) -> None:
        super().__init__()
        self.sources: list[str] = []
        self.inline_scripts = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "script":
            return
        attributes = dict(attrs)
        if attributes.get("src"):
            self.sources.append(attributes["src"] or "")
        elif (attributes.get("type") or "text/javascript").lower() in ("text/javascript", "module"):
            self.inline_scripts += 1


def fetch(url: str) -> Served:
    """One GET without compression, so the body is the file as the site stores it."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept-Encoding": "identity"})
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as reply:
            return Served(reply.status, reply.read(), {name.lower(): value for name, value in reply.headers.items()})
    except urllib.error.HTTPError as error:
        return Served(error.code, b"", {name.lower(): value for name, value in error.headers.items()})


def published_policies(headers_file: Path) -> dict[str, str]:
    """The Content-Security-Policy of each rule in this repository's _headers file."""
    policies: dict[str, str] = {}
    rule = ""
    for line in headers_file.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace():
            rule = line.strip()
            continue
        name, _, value = line.strip().partition(":")
        if name.strip().lower() != POLICY_HEADER.lower():
            continue
        # An empty policy would equal a header the site does not send at all.
        if not value.strip():
            raise SystemExit(f"{headers_file.name}: the {POLICY_HEADER} of {rule} is empty, so there is nothing to compare")
        policies[rule] = value.strip()
    return policies


class NotACheckoutError(Exception):
    """This folder is not a git checkout (a downloaded zip), or git is not installed."""


def checkout_commit() -> str:
    try:
        head = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"], capture_output=True, text=True, check=False,
        )
    except FileNotFoundError as error:
        raise NotACheckoutError("git is not installed") from error
    if head.returncode != 0:
        raise NotACheckoutError(head.stderr.strip())
    return head.stdout.strip()


def check_release_note(origin: str, check: Check) -> None:
    """The site says which commit it was released from; a different checkout explains a mismatch."""
    served = fetch(urljoin(origin, f"/{SCANNER_FOLDER}/{RELEASE_NOTE}"))
    if served.status != 200:
        check.notes.append(f"the site does not say which release it serves (/{SCANNER_FOLDER}/{RELEASE_NOTE}: {served.status})")
        return
    try:
        note = json.loads(served.body)
    except ValueError:
        check.problems.append(f"/{SCANNER_FOLDER}/{RELEASE_NOTE} is not JSON")
        return
    commit = str(note.get("commit", "")) if isinstance(note, dict) else ""
    if not COMMIT_FORMAT.match(commit):
        check.problems.append(f"/{SCANNER_FOLDER}/{RELEASE_NOTE} names no commit")
        return
    check.notes.append(f"the site says it serves commit {commit}")
    try:
        here = checkout_commit()
    except NotACheckoutError:
        return
    if here != commit:
        check.notes.append(f"this checkout is at {here}: run `git checkout {commit}` to compare with what the site names")


def local_scanner_files() -> list[Path]:
    """The files of scanner/ in this checkout. None at all would make every comparison pass."""
    local_files = sorted(path for path in (REPO_ROOT / SCANNER_FOLDER).iterdir() if path.is_file())
    if not local_files:
        raise SystemExit(f"{SCANNER_FOLDER}/ holds no files in this checkout, so there is nothing to compare")
    return local_files


def check_scanner_files(origin: str, policy: str, check: Check) -> None:
    """Every file of scanner/ byte for byte, each with the policy that denies it the network."""
    for path in local_scanner_files():
        address = urljoin(origin, f"/{SCANNER_FOLDER}/{path.name}")
        served = fetch(address)
        if served.status != 200:
            check.problems.append(f"{address}: status {served.status}")
            continue
        if hashlib.sha256(served.body).digest() != hashlib.sha256(path.read_bytes()).digest():
            check.problems.append(f"{address}: differs from {SCANNER_FOLDER}/{path.name} in this checkout")
        if served.headers.get(POLICY_HEADER.lower(), "") != policy:
            check.problems.append(f"{address}: {POLICY_HEADER} is not the published one for scanner files")


def check_page(origin: str, page: str, policy: str, check: Check) -> None:
    address = urljoin(origin, page)
    served = fetch(address)
    if served.status != 200:
        check.problems.append(f"{address}: status {served.status}")
        return
    if served.headers.get(POLICY_HEADER.lower(), "") != policy:
        check.problems.append(f"{address}: {POLICY_HEADER} is not the published one for the page")
    scripts = _Scripts()
    scripts.feed(served.body.decode("utf-8", errors="replace"))
    if scripts.inline_scripts:
        check.problems.append(f"{address}: {scripts.inline_scripts} inline script(s); the published policy would block them")
    scanner_prefix = f"/{SCANNER_FOLDER}/"
    script_paths = [urlsplit(urljoin(address, source)) for source in scripts.sources]
    if not any(script.path == f"{scanner_prefix}{ENTRY_SCRIPT}" for script in script_paths):
        check.problems.append(f"{address}: does not load {scanner_prefix}{ENTRY_SCRIPT}")
    for script in script_paths:
        if script.netloc != urlsplit(address).netloc:
            check.problems.append(f"{address}: loads a script from another host, {script.geturl()}")
        elif not script.path.startswith(scanner_prefix):
            body = fetch(script.geturl()).body
            check.notes.append(
                f"{page} also loads {script.path} ({len(body)} bytes, sha256 {hashlib.sha256(body).hexdigest()}): "
                "a script of the site itself, not part of this repository"
            )


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare the scanner a site serves with this checkout.")
    parser.add_argument("--origin", default=DEFAULT_ORIGIN, help=f"the site to check (default {DEFAULT_ORIGIN})")
    parser.add_argument("--page", action="append", help="a page that carries the scanner; repeat for more (default: both at helban.dev)")
    options = parser.parse_args()

    if urlsplit(options.origin).scheme not in ("http", "https"):
        parser.error("--origin has to be an http or https address")
    policies = published_policies(REPO_ROOT / "_headers")
    compared = len(local_scanner_files())
    check = Check()
    try:
        check_release_note(options.origin, check)
        check_scanner_files(options.origin, policies[SCANNER_RULE], check)
        for page in options.page or DEFAULT_PAGES:
            check_page(options.origin, page, policies[PAGE_RULE], check)
    except urllib.error.URLError as error:
        print(f"could not reach {options.origin}: {error.reason}")
        return 2

    for note in dict.fromkeys(check.notes):
        print(f"note: {note}")
    for problem in check.problems:
        print(f"MISMATCH: {problem}")
    if check.problems:
        print(f"{len(check.problems)} mismatch(es) at {options.origin}")
        return 1
    print(f"{compared} scanner files at {options.origin} are byte for byte this checkout, and both policies are the published ones")
    return 0


if __name__ == "__main__":
    sys.exit(main())
