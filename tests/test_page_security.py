"""The promises the page makes about itself, checked in a real browser.

Each "blocked" check has a positive control next to it: the same kind of request to an allowed
address goes through. Without the control, a dead network would look like a working policy.
"""
import os
import re
from collections.abc import Iterator
from urllib.parse import urljoin

import pytest
from playwright.sync_api import Browser, Page, Route

from serve import site_root

ALLOWED_API = "https://api.wordpress.org/core/version-check/1.7/"
FOREIGN_API = "https://collector.example/steal"
FOREIGN_IMAGE = "https://collector.example/pixel.png"
IDLE_WORKER = "self.addEventListener('message', () => {});"
# WebKit refuses the request but does not fire a securitypolicyviolation event inside a worker
# (measured on WebKit 26.5); Chromium 151 and Firefox 153 fire it.
WORKER_REPORTS_VIOLATIONS = os.environ.get("SCANNER_BROWSER", "chromium") != "webkit"
HTML_SINKS = re.compile(r"innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\s*\(|new\s+Function|DOMParser")
NETWORK_APIS = re.compile(r"\bfetch\s*\(|XMLHttpRequest|WebSocket|EventSource|sendBeacon|importScripts|\bimport\s*\(")
WORKER_SIDE_FILES = (
    "worker.js", "engine.js", "entries.js", "checksums.js", "md5.js", "spark-md5.js", "php-text.js",
    "zip-reader.js", "inflate.js", "gunzip.js", "crc32.js", "signatures.js", "rules.js", "sanitize.js",
    "php-lexer.js", "php-rules.js", "code-rules.js", "config-rules.js", "database.js", "text-rules.js",
    "indicators.js", "excerpt.js", "program-scan.js", "tar-archive.js", "tar-reader.js", "gzip-source.js",
)

FETCH_OUTCOME = """async (url) => {
  const violations = [];
  const record = (event) => violations.push(event.violatedDirective);
  self.addEventListener('securitypolicyviolation', record);
  let outcome;
  try {
    const reply = await fetch(url);
    outcome = `status ${reply.status}`;
  } catch (error) {
    outcome = 'blocked';
  }
  // The violation event arrives as a task of its own, after the fetch has already failed.
  await new Promise((resolve) => setTimeout(resolve, 250));
  self.removeEventListener('securitypolicyviolation', record);
  return { outcome, violations };
}"""


@pytest.fixture
def loose_page(browser: Browser, site_url: str) -> Iterator[Page]:
    """Like `page`, but console errors are expected here: a blocked request logs one."""
    context = browser.new_context()
    opened = context.new_page()
    reached_network: list[str] = []

    def answer_locally(route: Route) -> None:
        reached_network.append(route.request.url)
        route.fulfill(status=200, headers={"Access-Control-Allow-Origin": "*"}, body="{}")

    # Both hosts are answered here, so no test traffic leaves the machine. A request stopped by
    # the policy never gets this far, which is what `reached_network` proves.
    opened.route("https://api.wordpress.org/**", answer_locally)
    opened.route("https://collector.example/**", answer_locally)
    opened.reached_network = reached_network
    opened.goto(site_url)
    opened.wait_for_selector('[data-scanner="root"][data-state="ready"]')
    yield opened
    context.close()


def test_page_cannot_send_data_to_a_foreign_host(loose_page):
    foreign = loose_page.evaluate(FETCH_OUTCOME, FOREIGN_API)
    allowed = loose_page.evaluate(FETCH_OUTCOME, ALLOWED_API)

    assert foreign == {"outcome": "blocked", "violations": ["connect-src"]}
    assert allowed == {"outcome": "status 200", "violations": []}
    assert loose_page.reached_network == [ALLOWED_API]


def test_page_cannot_leak_through_an_image_address(loose_page):
    violation = loose_page.evaluate("""(url) => new Promise((resolve) => {
      document.addEventListener('securitypolicyviolation', (event) => resolve(event.violatedDirective), { once: true });
      setTimeout(() => resolve('no violation reported'), 3000);
      new Image().src = url;
    })""", FOREIGN_IMAGE)

    assert violation == "img-src"
    assert loose_page.reached_network == []


def test_browser_refuses_text_inserted_as_markup(loose_page):
    outcome = loose_page.evaluate("""() => {
      const attempts = {
        innerHTML: () => { document.body.firstElementChild.innerHTML = '<img src=x>'; },
        insertAdjacentHTML: () => { document.body.insertAdjacentHTML('beforeend', '<img src=x>'); },
        secondPolicy: () => { trustedTypes.createPolicy('another', { createHTML: (text) => text }); },
        otherWorker: () => { new Worker('/scanner/engine.js', { type: 'module' }); },
      };
      const thrown = {};
      for (const [name, attempt] of Object.entries(attempts)) {
        try { attempt(); thrown[name] = 'allowed'; } catch (error) { thrown[name] = error.name; }
      }
      return { thrown, images: document.images.length };
    }""")

    assert outcome == {
        "thrown": {"innerHTML": "TypeError", "insertAdjacentHTML": "TypeError", "secondPolicy": "TypeError", "otherWorker": "TypeError"},
        "images": 0,
    }


def test_worker_has_no_network_at_all(loose_page, site_url, tmp_path):
    """The worker's policy comes from the headers of its own script, so the real response is
    kept and only the body is swapped for one that stays idle and can be questioned."""

    def keep_headers_swap_body(route: Route) -> None:
        real = route.fetch()
        route.fulfill(status=200, headers=real.headers, body=IDLE_WORKER)

    loose_page.route("**/scanner/worker.js", keep_headers_swap_body)
    archive = tmp_path / "any.zip"
    archive.write_bytes(b"PK\x05\x06" + b"\x00" * 18)
    with loose_page.expect_worker() as started:
        loose_page.set_input_files('[data-scanner="input"]', str(archive))
    worker = started.value

    from_worker = worker.evaluate(FETCH_OUTCOME, ALLOWED_API)
    own_origin = worker.evaluate(FETCH_OUTCOME, urljoin(site_url, "/scanner/rules.js"))
    from_page = loose_page.evaluate(FETCH_OUTCOME, ALLOWED_API)

    # The address the page itself may call is refused inside the worker, so the worker runs
    # under its own policy, not the page's. The request to the scanner's own server cannot
    # fail for network reasons (the worker script just came from there), so that refusal is
    # the policy too.
    assert from_worker["outcome"] == "blocked"
    assert own_origin["outcome"] == "blocked"
    assert from_page == {"outcome": "status 200", "violations": []}
    assert loose_page.reached_network == [ALLOWED_API]
    reported = ["connect-src"] if WORKER_REPORTS_VIOLATIONS else []
    assert (from_worker["violations"], own_origin["violations"]) == (reported, reported)


def test_sources_never_build_markup_from_text():
    sources = sorted((site_root() / "scanner").glob("*.js"))
    assert sources, "no scanner source found, so nothing was checked"
    for source in sources:
        hit = HTML_SINKS.search(source.read_text(encoding="utf-8"))
        assert hit is None, f"{source.name}: {hit.group(0)}"


def test_worker_side_sources_have_no_network_call():
    """The second lock on the same door, for a browser that would not apply the worker's policy."""
    for name in WORKER_SIDE_FILES:
        hit = NETWORK_APIS.search((site_root() / "scanner" / name).read_text(encoding="utf-8"))
        assert hit is None, f"{name}: {hit.group(0)}"


def test_worker_side_list_is_complete():
    """Every module the worker pulls in, directly or not, must be on the list checked above."""
    imported = re.compile(r"(?:from|import) '\./([a-z0-9-]+\.js)'")
    reached, queue = set(), ["worker.js"]
    while queue:
        name = queue.pop()
        if name in reached:
            continue
        reached.add(name)
        queue.extend(imported.findall((site_root() / "scanner" / name).read_text(encoding="utf-8")))
    assert reached == set(WORKER_SIDE_FILES)
