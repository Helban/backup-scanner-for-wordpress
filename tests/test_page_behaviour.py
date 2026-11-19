"""What the visitor sees: counters, the findings list, and the states where a scan cannot finish."""
import base64

import pytest
from playwright.sync_api import Route

from conftest import finding_keys
from samples import JPEG, PROGRAM, SAMPLES_BY_NAME, UPLOADS, site
from zipcraft import Member, craft_zip

MARKUP_NAME = UPLOADS + "<img src=x onerror=alert(1)>.jpeg"
SILENT_WORKER = "self.addEventListener('message', () => {});"
# Longer than the dozen frames the log takes to write one line out.
LINE_WRITING_MS = 500
LYING_WORKERS = {
    "unknown_rule": "{ type: 'finding', severity: 'red', rule: 'made.up', path: '', params: {} }",
    "wrong_weight": "{ type: 'finding', severity: 'amber', rule: 'layout.symlink', path: '', params: {} }",
    "unknown_type": "{ type: 'navigate', url: 'https://collector.example/' }",
    "oversized_text": "{ type: 'finding', severity: 'red', rule: 'layout.symlink', path: 'x'.repeat(5000), params: {} }",
    "not_an_object": "'done'",
    "null_database": "{ type: 'facts', root: '', version: '', locale: '', plugins: [], themes: [], databases: [null] }",
}
LATE_ENGINE_FAILURE = {
    "scanner/engine.js": ("  reporter.reportOverflow();\n  emit({", "  reporter.reportOverflow();\n  throw new Error('late');\n  emit({"),
}
ADVISORIES_FAIL_TO_DRAW = {
    "scanner/main.js": ("    report.advisories = records.map(cleanAdvisory);\n", "    throw new Error('drawing failed');\n"),
}


def swap_worker(page, body: str) -> None:
    def fulfil(route: Route) -> None:
        route.fulfill(status=200, content_type="text/javascript", body=body)

    page.route("**/scanner/worker.js", fulfil)


def test_findings_are_drawn_with_counts_and_verdict(scan, page):
    scan(SAMPLES_BY_NAME["dropper"].build())

    assert page.text_content('[data-scanner="count-red"]') == "1"
    assert page.text_content('[data-scanner="count-amber"]') == "1"
    assert page.text_content('[data-scanner="count-not_checked"]') == "0"
    assert page.text_content('[data-scanner="status"]') == "Do not run this copy."
    rows = page.locator('[data-scanner="findings"] > li')
    assert rows.count() == 2
    assert rows.first.get_attribute("data-severity") == "red"
    assert rows.last.get_attribute("data-severity") == "amber"
    assert "Starts like a Windows program, but is named .jpeg" in rows.first.text_content()
    page.wait_for_function("""() => document.querySelector('[data-scanner="log"]').textContent.includes(
      '2 requests to wordpress.org and wpvulnerability.net carried names and versions only')""")


def test_an_offline_scan_says_nothing_was_sent(scan, page):
    report = scan(SAMPLES_BY_NAME["dropper"].build(), online=False)

    assert report["requests"] == []
    assert page.wordpress_org.requested == []
    page.wait_for_function("""() => document.querySelector('[data-scanner="log"]').textContent.includes('Nothing was sent anywhere')""")


def test_findings_are_listed_heaviest_first(scan, page):
    scan(craft_zip([
        *site(),
        Member(UPLOADS + "backup.7z", b"7z\xbc\xaf\x27\x1c" + b"\x00" * 64),
        Member(UPLOADS + "installer.zip", craft_zip([Member("setup.exe", PROGRAM)])),
        Member(UPLOADS + "mockup.jpeg", PROGRAM),
    ]))

    weights = page.locator('[data-scanner="findings"] > li').evaluate_all("(rows) => rows.map((row) => row.dataset.severity)")
    assert weights == ["red", "amber", "not_checked"]


def test_the_log_ends_on_its_last_line(scan, page):
    scan(SAMPLES_BY_NAME["layout_mix"].build())

    page.wait_for_function("""() => {
      const log = document.querySelector('[data-scanner="log"]');
      return log.textContent.includes('Finished in') && log.scrollHeight - log.scrollTop - log.clientHeight < 2;
    }""")
    assert page.evaluate("""() => {
      const log = document.querySelector('[data-scanner="log"]');
      return log.scrollHeight > log.clientHeight;
    }""")


def test_a_result_without_findings_is_never_called_clean(scan, page):
    scan(SAMPLES_BY_NAME["clean"].build())

    status = page.text_content('[data-scanner="status"]')
    assert "not a clean bill" in status
    assert page.locator('[data-scanner="findings"] > li').count() == 0


def test_a_file_name_with_markup_is_shown_as_text(scan, page):
    report = scan(craft_zip([*site(), Member(MARKUP_NAME, PROGRAM)]))

    assert finding_keys(report) == {("red", "layout.disguised_executable", MARKUP_NAME)}
    assert page.text_content('[data-scanner="findings"] .finding-path') == MARKUP_NAME
    assert page.locator("img").count() == 0


@pytest.mark.parametrize("lie", LYING_WORKERS)
def test_a_worker_that_breaks_the_protocol_ends_the_scan(lie, scan, page):
    swap_worker(page, f"self.addEventListener('message', () => self.postMessage({LYING_WORKERS[lie]}));")

    report = scan(craft_zip([*site(), Member(UPLOADS + "any.jpeg", JPEG)]))

    assert finding_keys(report) == {("not_checked", "scan.failed", "")}
    assert report["completed"] is False
    assert "did not finish" in page.text_content('[data-scanner="status"]')


# More amber findings than the list draws, then one red finding at the very end.
PAST_THE_DRAWN_ROWS = """async () => {
  const { collectView, drawFinding, resetView } = await import('/scanner/page-view.js');
  const view = collectView(document.querySelector('[data-scanner="root"]'));
  resetView(view);
  const amber = { severity: 'amber', rule: 'layout.not_an_image', path: '', params: {}, text: 'a' };
  for (let index = 0; index < 601; index += 1) drawFinding(view, { ...amber, path: `a${index}.jpg` });
  drawFinding(view, { ...amber, severity: 'red', path: 'late.jpg' });
  const rows = [...view.findings.querySelectorAll(':scope > .finding')];
  return { rows: rows.length, first: rows[0].dataset.severity, last: view.findings.lastElementChild.textContent };
}"""


def test_a_red_finding_past_the_drawn_rows_is_still_drawn(page, site_url):
    """The report keeps every finding, the list draws 600: the lightest row gives way, and a
    line under the list says how many are only in the report."""
    page.goto(site_url)
    page.wait_for_selector('[data-scanner="root"][data-state="ready"]')

    drawn = page.evaluate(PAST_THE_DRAWN_ROWS)

    assert drawn["rows"] == 600
    assert drawn["first"] == "red"
    # Rows are files, so the line counts files shown and findings left out.
    assert drawn["last"].startswith("The list shows the 600 files with the heaviest findings. 2 more findings are in the report")


# Three findings of one file arriving lightest first, then one of another file.
ONE_FILE_THREE_REASONS = """async () => {
  const { collectView, drawFinding, drawHashes, resetView } = await import('/scanner/page-view.js');
  const view = collectView(document.querySelector('[data-scanner="root"]'));
  resetView(view);
  const finding = (severity, path, text) => ({ severity, rule: 'layout.not_an_image', path, params: {}, text });
  drawFinding(view, finding('amber', 'other.jpg', 'other'));
  drawFinding(view, finding('amber', 'loader.php', 'amber reason'));
  drawFinding(view, finding('red', 'loader.php', 'first red reason'));
  drawFinding(view, finding('red', 'loader.php', 'second red reason'));
  drawHashes(view, [
    { path: 'loader.php', sha256: 'f'.repeat(64), findings: ['loader.php'] },
    { path: 'other.jpg', sha256: 'e'.repeat(64), findings: ['other.jpg'] },
  ]);
  return [...view.findings.querySelectorAll(':scope > .finding')].map((row) => ({
    severity: row.dataset.severity,
    path: row.querySelector('.finding-path').textContent,
    reasons: [...row.querySelectorAll('.finding-reason .finding-text')].map((text) => text.textContent),
    mixed: row.dataset.mixed,
    hashes: row.querySelectorAll('.finding-hash').length,
  }));
}"""


def test_the_findings_of_one_file_share_one_row(page, site_url):
    """One row per file, with the weight of its heaviest finding, heaviest reasons first and
    the hash once; the row moves up when a heavier finding arrives."""
    page.goto(site_url)
    page.wait_for_selector('[data-scanner="root"][data-state="ready"]')

    rows = page.evaluate(ONE_FILE_THREE_REASONS)

    assert rows == [
        {"severity": "red", "path": "loader.php", "reasons": ["first red reason", "second red reason", "amber reason"], "mixed": "true", "hashes": 1},
        {"severity": "amber", "path": "other.jpg", "reasons": ["other"], "mixed": "false", "hashes": 0},
    ]


def test_only_the_lighter_reasons_of_a_row_carry_their_own_weight(page, site_url):
    """The row says "Do not run" once; repeating it over each red reason under it was noise."""
    page.goto(site_url)
    page.wait_for_selector('[data-scanner="root"][data-state="ready"]')
    page.evaluate(ONE_FILE_THREE_REASONS)

    labels = page.locator('[data-scanner="findings"] > .finding').first.locator(".reason-weight")
    assert [label.is_visible() for label in labels.all()] == [False, False, True]
    assert labels.nth(2).text_content() == "Read first"


AMBER_ROW_WITH_AN_UNCHECKED_REASON = """async () => {
  const { collectView, drawFinding, resetView } = await import('/scanner/page-view.js');
  const view = collectView(document.querySelector('[data-scanner="root"]'));
  resetView(view);
  const finding = (severity, text) => ({ severity, rule: 'layout.not_an_image', path: 'photo.jpg', params: {}, text });
  drawFinding(view, finding('not_checked', 'unchecked reason'));
  drawFinding(view, finding('amber', 'amber reason'));
}"""


def test_an_amber_row_labels_only_its_unchecked_reason(page, site_url):
    page.goto(site_url)
    page.wait_for_selector('[data-scanner="root"][data-state="ready"]')
    page.evaluate(AMBER_ROW_WITH_AN_UNCHECKED_REASON)

    labels = page.locator('[data-scanner="findings"] > .finding').first.locator(".reason-weight")
    assert [label.is_visible() for label in labels.all()] == [False, True]
    assert labels.nth(1).text_content() == "Not checked"


SMALL_SCREEN = {"width": 390, "height": 300}


def test_a_scan_brings_its_result_into_view(scan, page):
    """On a small screen the result lies below the drop zone, where a click on the example
    changed nothing the visitor could see."""
    page.set_viewport_size(SMALL_SCREEN)
    page.emulate_media(reduced_motion="reduce")

    scan(SAMPLES_BY_NAME["clean"].build())

    top = page.evaluate("""() => document.querySelector('[data-scanner="status"]').getBoundingClientRect().top""")
    # Scrolled to the start of the result, the status line can sit a fraction of a pixel above.
    assert -1 < top < SMALL_SCREEN["height"]


def test_a_count_sent_as_text_weighs_one(scan, page):
    """A parameter may be text, so a weight that is not a number counts once."""
    swap_worker(page, "self.addEventListener('message', () => {"
                " self.postMessage({ type: 'finding', severity: 'red', rule: 'layout.symlink', path: 'a', params: { more: 'x' } });"
                " self.postMessage({ type: 'done', completed: true, bytesRead: 0, milliseconds: 0 }); });")

    report = scan(craft_zip([*site(), Member(UPLOADS + "any.jpeg", JPEG)]))

    assert report["counts"]["red"] == 1


def test_a_failure_after_the_engine_ends_the_scan_at_once(scan_patched):
    """A throw past the engine's own catch reaches the page as the worker's error, not as a
    stall noticed ten seconds later."""
    report = scan_patched(craft_zip(site()), LATE_ENGINE_FAILURE)

    assert finding_keys(report) == {("not_checked", "scan.failed", "")}
    # A type name, not English words: the Polish sentence quotes it as it is.
    assert report["findings"][0]["params"]["error"] == "ErrorEvent"


def test_a_failure_while_drawing_the_advisories_ends_the_scan(scan_patched):
    """Otherwise the report would wait for the lookup forever, with the watchdog stopped."""
    report = scan_patched(SAMPLES_BY_NAME["dropper"].build(), ADVISORIES_FAIL_TO_DRAW)

    assert ("not_checked", "scan.failed", "") in finding_keys(report)
    assert report["completed"] is False


# Keeps every message the scanner's worker sends, for tests that look at more than the report.
RECORD_WORKER_MESSAGES = """(() => {
  const Original = window.Worker;
  window.workerMessages = [];
  window.Worker = class extends Original {
    constructor(...args) {
      super(...args);
      this.addEventListener('message', (message) => window.workerMessages.push(message.data));
    }
  };
})();"""


def test_the_first_progress_names_the_first_file(scan, page):
    """A scan that stalls on its first file is reported with that file's path. The first
    progress message used to wait for 120 ms of the worker's life."""
    page.add_init_script(RECORD_WORKER_MESSAGES)
    scan(SAMPLES_BY_NAME["clean"].build())
    first = page.evaluate("() => window.workerMessages.find((event) => event.type === 'progress')")
    assert (first["stage"], first["done"]) == ("first_bytes", 0)
    assert first["path"] != ""


TWO_SCANS_IN_ONE_TASK = """(archiveBase64) => {
  window.reports = [];
  const root = document.querySelector('[data-scanner="root"]');
  root.addEventListener('scanner:report', (event) => window.reports.push(event.detail));
  const bytes = Uint8Array.from(atob(archiveBase64), (char) => char.charCodeAt(0));
  const input = document.querySelector('[data-scanner="input"]');
  for (const name of ['first-scan.zip', 'second-scan.zip']) {
    const chosen = new DataTransfer();
    chosen.items.add(new File([bytes], name));
    input.files = chosen.files;
    input.dispatchEvent(new Event('change'));
  }
}"""


def test_a_new_scan_leaves_nothing_of_the_old_one_in_the_log(page, site_url):
    """A scan replaced by another before the next frame wrote its lines into the new log."""
    page.goto(site_url)
    page.wait_for_selector('[data-scanner="root"][data-state="ready"]')

    page.evaluate(TWO_SCANS_IN_ONE_TASK, base64.b64encode(SAMPLES_BY_NAME["clean"].build()).decode())

    page.wait_for_function("() => window.reports.some((report) => report.archive.name === 'second-scan.zip')")
    page.wait_for_function("""() => document.querySelector('[data-scanner="log"]').textContent.includes('Finished in')""")
    # A line of the old scan that slipped in would still be on its way: lines are written out
    # over a dozen frames.
    page.wait_for_timeout(LINE_WRITING_MS)
    log = page.text_content('[data-scanner="log"]')
    assert "second-scan.zip" in log
    assert "first-scan.zip" not in log
    # Nor a row of the old scan that was only begun: a line is written out piece by piece.
    assert "" not in page.locator('[data-scanner="log"] > li').all_text_contents()


# A line that arrives alone is written out over a dozen frames. The second line here arrives
# while the first is half written, the way a finding follows a progress line.
TWO_LINES_A_FEW_FRAMES_APART = """async () => {
  const { createLog } = await import('/scanner/page-view.js');
  const frame = () => new Promise((resolve) => requestAnimationFrame(resolve));
  const list = document.createElement('ol');
  document.body.append(list);
  const log = createLog(list);
  log.line('the first line is long enough to take a dozen frames');
  await frame();
  await frame();
  const firstWhileWriting = list.firstElementChild.textContent;
  log.line('the second line');
  for (let waited = 0; waited < 30; waited += 1) await frame();
  const rows = Array.from(list.children, (row) => row.textContent);
  list.remove();
  return { firstWhileWriting, rows };
}"""
FIRST_LINE = "the first line is long enough to take a dozen frames"


def test_a_line_being_written_is_finished_when_the_next_one_arrives(page, site_url):
    page.goto(site_url)
    written = page.evaluate(TWO_LINES_A_FEW_FRAMES_APART)
    assert 0 < len(written["firstWhileWriting"]) < len(FIRST_LINE)
    assert written["rows"] == [FIRST_LINE, "the second line"]


def test_lines_go_in_whole_for_a_visitor_who_asked_for_less_motion(page, site_url):
    page.emulate_media(reduced_motion="reduce")
    page.goto(site_url)
    written = page.evaluate(TWO_LINES_A_FEW_FRAMES_APART)
    assert written["firstWhileWriting"] == FIRST_LINE
    assert written["rows"] == [FIRST_LINE, "the second line"]


def test_a_silent_worker_is_stopped_and_reported(scan, page):
    swap_worker(page, SILENT_WORKER)

    report = scan(craft_zip(site()))

    assert finding_keys(report) == {("not_checked", "scan.stalled", "")}
    assert report["completed"] is False


def test_a_browser_that_cannot_unpack_gets_a_message(browser, site_url):
    context = browser.new_context()
    context.add_init_script("delete window.DecompressionStream;")
    page = context.new_page()
    page.goto(site_url)

    notice = page.locator('[data-scanner="unsupported"]')
    notice.wait_for(state="visible")
    assert "Open the page in a current" in notice.text_content()
    assert page.locator('[data-scanner="input"]').is_disabled()
    context.close()
