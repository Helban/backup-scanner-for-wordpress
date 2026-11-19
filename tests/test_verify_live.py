"""verify_live.py against a local server: it has to pass on the site as published and fail on
every single departure from it. Each failing case changes one thing in a copy of the site."""
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from serve import PAGE_PATH, REPO_ROOT, ScannerServer, copy_site, site_root

VERIFY_LIVE = REPO_ROOT / "verify_live.py"
PAGE = "/" + PAGE_PATH
PAGE_FILE = PAGE_PATH + "index.html"
# The rule of the page under test, and how its policy begins. A site may carry the scanner on
# several pages, each with its own rule.
PAGE_POLICY_START = f"{PAGE}\n  Content-Security-Policy: default-src 'none';"
WORKER_POLICY = "Content-Security-Policy: default-src 'none'; script-src 'self'; connect-src 'none'"

# name -> ({file: (find, replace)}, text the report must contain)
DEPARTURES = {
    "one_byte_in_a_scanner_file": ({"scanner/rules.js": ("export const SEVERITIES", "export  const SEVERITIES")}, "rules.js"),
    "worker_allowed_the_network": ({"_headers": (WORKER_POLICY, WORKER_POLICY.replace("connect-src 'none'", "connect-src *"))}, "not the published one for scanner files"),
    "worker_left_without_a_policy": ({"_headers": (f"  {WORKER_POLICY}\n", "")}, "not the published one for scanner files"),
    "page_allowed_everything": ({"_headers": (PAGE_POLICY_START, PAGE_POLICY_START.replace("'none'", "*"))}, "not the published one for the page"),
    "page_loads_a_foreign_script": ({PAGE_FILE: ("</body>", '<script src="https://collector.example/x.js"></script></body>')}, "loads a script from another host"),
    "page_carries_an_inline_script": ({PAGE_FILE: ("</body>", "<script>window.x = 1;</script></body>")}, "inline script"),
    "page_without_the_scanner": ({PAGE_FILE: ('main.js"', 'other.js"')}, "does not load /scanner/main.js"),
}


def verify(server: ScannerServer, script: Path = VERIFY_LIVE) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(script), "--origin", server.origin, "--page", PAGE],
        capture_output=True, text=True, check=False,
    )


def checkout_with(folder: Path, headers: str) -> Path:
    """A checkout of its own: verify_live.py compares the site with the folder it lies in."""
    folder.mkdir()
    shutil.copy2(VERIFY_LIVE, folder)
    (folder / "_headers").write_text(headers, encoding="utf-8")
    return folder / VERIFY_LIVE.name


def test_the_site_as_published_passes():
    with ScannerServer(site_root()) as server:
        outcome = verify(server)
    assert outcome.returncode == 0, outcome.stdout + outcome.stderr
    assert "byte for byte this checkout" in outcome.stdout


@pytest.mark.parametrize("departure", DEPARTURES)
def test_a_site_that_departs_from_the_repository_fails(departure, tmp_path: Path):
    patches, expected_text = DEPARTURES[departure]
    with ScannerServer(copy_site(tmp_path / "site", patches)) as server:
        outcome = verify(server)
    assert outcome.returncode == 1, outcome.stdout + outcome.stderr
    assert expected_text in outcome.stdout


def test_a_checkout_without_scanner_files_says_it_compared_nothing(tmp_path: Path):
    script = checkout_with(tmp_path / "checkout", (REPO_ROOT / "_headers").read_text(encoding="utf-8"))
    (tmp_path / "checkout" / "scanner").mkdir()
    with ScannerServer(site_root()) as server:
        outcome = verify(server, script)
    assert outcome.returncode != 0
    assert "nothing to compare" in outcome.stderr


def test_an_empty_published_policy_is_not_taken_for_a_missing_header(tmp_path: Path):
    headers = (REPO_ROOT / "_headers").read_text(encoding="utf-8").replace(WORKER_POLICY, "Content-Security-Policy:")
    script = checkout_with(tmp_path / "checkout", headers)
    shutil.copytree(REPO_ROOT / "scanner", tmp_path / "checkout" / "scanner")
    site = copy_site(tmp_path / "site", {"_headers": (f"  {WORKER_POLICY}\n", "")})
    with ScannerServer(site) as server:
        outcome = verify(server, script)
    assert outcome.returncode != 0
    assert "is empty" in outcome.stderr


def test_an_address_that_is_no_web_address_is_refused():
    outcome = subprocess.run(
        [sys.executable, str(VERIFY_LIVE), "--origin", "file:///etc"], capture_output=True, text=True, check=False,
    )
    assert outcome.returncode == 2
    assert "http or https" in outcome.stderr
