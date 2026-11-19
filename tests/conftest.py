"""Shared fixtures: the local server, one browser per run, one fresh page per test."""
import os
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from playwright.sync_api import Browser, ConsoleMessage, Page, sync_playwright

from samples import site_answers
from serve import ScannerServer, copy_site, site_root
from wporg import FakeWordPressOrg

# A browser logs every 404 and every answer without a CORS header as a console error. Those are
# expected from the wordpress.org stand-in; every other console error fails the test.
EXPECTED_CONSOLE_HOSTS = ("api.wordpress.org", "downloads.wordpress.org", "www.wpvulnerability.net")

SCAN_TIMEOUT_MS = int(os.environ.get("SCANNER_SCAN_TIMEOUT_MS", "120000"))
PAGE_READY_TIMEOUT_MS = 5_000
REPORT_HOOK = """() => {
  const root = document.querySelector('[data-scanner="root"]');
  window.scannerReport = new Promise((resolve) => {
    root.addEventListener('scanner:report', (event) => resolve(event.detail), { once: true });
  });
}"""
REPORT_OR_TIMEOUT = """(limit) => Promise.race([
  window.scannerReport,
  new Promise((resolve, reject) => setTimeout(() => reject(new Error('no report within the time limit')), limit)),
])"""


@pytest.fixture(scope="session")
def site_url() -> Iterator[str]:
    with ScannerServer(site_root()) as server:
        yield server.url


@pytest.fixture(scope="session")
def browser() -> Iterator[Browser]:
    engine = os.environ.get("SCANNER_BROWSER", "chromium")
    with sync_playwright() as playwright:
        launched = getattr(playwright, engine).launch()
        yield launched
        launched.close()


def is_expected_console_error(message: ConsoleMessage) -> bool:
    where = f"{message.text} {message.location.get('url', '')}"
    return any(host in where for host in EXPECTED_CONSOLE_HOSTS)


@pytest.fixture
def page(browser: Browser) -> Iterator[Page]:
    """A fresh page that fails the test if the scanner page throws or logs an error. Its
    `wordpress_org` attribute is the stand-in that answers every request to the three hosts;
    by default it knows the core files of the sample site."""
    context = browser.new_context()
    wordpress_org = FakeWordPressOrg()
    wordpress_org.answers.update(site_answers())
    wordpress_org.attach(context)
    opened = context.new_page()
    opened.wordpress_org = wordpress_org
    problems: list[str] = []
    opened.on("pageerror", lambda error: problems.append(f"uncaught: {error}"))
    opened.on("console", lambda message: problems.append(f"console: {message.text}") if message.type == "error" and not is_expected_console_error(message) else None)
    yield opened
    context.close()
    assert not problems, problems


def scan_on(page: Page, url: str, archive_path: Path, online: bool = True) -> dict:
    """Gives the page an archive and returns the report it publishes when the scan ends."""
    page.goto(url)
    # Fails in seconds, not after the scan timeout, when a script of the page did not load.
    page.wait_for_selector('[data-scanner="root"][data-state="ready"]', timeout=PAGE_READY_TIMEOUT_MS)
    page.set_checked('[data-scanner="online"]', online)
    page.evaluate(REPORT_HOOK)
    page.set_input_files('[data-scanner="input"]', str(archive_path))
    return page.evaluate(REPORT_OR_TIMEOUT, SCAN_TIMEOUT_MS)


@pytest.fixture
def scan(page: Page, site_url: str, tmp_path: Path) -> Callable[..., dict]:
    def run(archive: bytes | Path, name: str = "backup.zip", online: bool = True) -> dict:
        if isinstance(archive, bytes):
            archive_path = tmp_path / name
            archive_path.write_bytes(archive)
        else:
            archive_path = archive
        return scan_on(page, site_url, archive_path, online)

    return run


@pytest.fixture
def scan_patched(page: Page, tmp_path: Path) -> Callable[..., dict]:
    """Scans with a copy of the scanner in which one piece of text was replaced. For limits that
    cannot be reached in a test otherwise, such as a time limit measured in seconds."""

    def run(archive: bytes, patches: dict[str, tuple[str, str]]) -> dict:
        archive_path = tmp_path / "backup.zip"
        archive_path.write_bytes(archive)
        patched_root = tmp_path / "patched-site"
        patched_root.mkdir()
        with ScannerServer(copy_site(patched_root, patches)) as server:
            report = scan_on(page, server.url, archive_path)
            # A page with fonts may still be fetching one; leaving it first keeps the server's
            # shutdown from showing up as a failed request.
            page.goto("about:blank")
            return report

    return run


def finding_keys(report: dict) -> set[tuple[str, str, str]]:
    return {(found["severity"], found["rule"], found["path"]) for found in report["findings"]}
