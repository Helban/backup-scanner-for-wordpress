"""What the page makes of a finished scan: the sentences under the verdict, the lists, the
report a visitor takes away, the built-in example, and the Polish page."""
import json
from pathlib import Path

import pytest
from playwright.sync_api import Page, Route

from conftest import PAGE_READY_TIMEOUT_MS, REPORT_HOOK, REPORT_OR_TIMEOUT, SCAN_TIMEOUT_MS, finding_keys
from samples import (
    CONTENT_INDEX, CONTENT_LOOSE_PHP, CORE_TRANSLATION, DROP_IN, LANGUAGES_SUBFOLDER_HELPER, LOCALE_FILE, LOCO_TRANSLATION,
    MAINTENANCE_FILE, MU_PLUGIN, PLAIN_TRANSLATION, PLUGIN_TRANSLATION, PROGRAM, ROOT, SAMPLES_BY_NAME, SITUATIONAL_DROP_IN,
    STOCK_CONTENT_INDEX, STOCK_MAINTENANCE, THEME_TRANSLATION, TRANSLATION_PRINTING_AFTER, TRANSLATION_PRINTING_BEFORE,
    TRANSLATION_READING_A_VARIABLE, UPLOADS, code, site, tool_answers, tool_files,
)
from wporg import (
    NO_CORE_LIST, Answer, core_checksums_url, plugin_checksums_url, plugin_found, plugin_info_url, plugin_list,
    plugin_vulnerabilities_url,
)
from zipcraft import Member, craft_zip

SERVICE_UNAVAILABLE = 503

ADDRESS_IN_A_NAME = UPLOADS + "john.smith@example.com.jpeg"
MASKED_NAME = UPLOADS + "j***@example.com.jpeg"
EXAMPLE_ROOT = "site-copy/"
EXAMPLE_PHOTO = EXAMPLE_ROOT + "wp-content/uploads/2026/11/product-detail-mockup-soft-blue-background.jpeg"
EXAMPLE_LOADER = EXAMPLE_ROOT + "wp-content/mu-plugins/custom-fields-handler.php"
EXAMPLE_PLUGIN = EXAMPLE_ROOT + "wp-content/plugins/hello-dolly/"
# Keeps what the page hands to the clipboard, in every browser, without asking for a permission.
CLIPBOARD_THAT_KEEPS = "navigator.clipboard.writeText = async (text) => { window.copiedText = text; };"
CLIPBOARD_THAT_REFUSES = "navigator.clipboard.writeText = async () => { throw new DOMException('denied', 'NotAllowedError'); };"


def summary(page: Page) -> list[str]:
    return page.locator('[data-scanner="summary"] > li').all_text_contents()


def rows(page: Page, part: str) -> list[str]:
    return page.locator(f'[data-scanner="{part}"] > li').all_text_contents()


def test_the_summary_says_what_was_compared_and_what_was_sent(scan, page):
    page.wordpress_org.answers.update(tool_answers()())
    scan(craft_zip([*site(), *tool_files()]))
    lines = summary(page)
    assert lines[0].startswith("Compared with wordpress.org: WordPress 6.9.5, 1 of 1 plugin. 6 files are byte for byte the official ones.")
    assert "Linux container" in lines[-1]
    page.wait_for_function("""() => document.querySelector('[data-scanner="log"]').textContent.includes(
      'requests to wordpress.org and wpvulnerability.net carried names and versions only')""")


def test_an_offline_summary_says_nothing_was_compared(scan, page):
    scan(SAMPLES_BY_NAME["clean"].build(), online=False)
    lines = summary(page)
    assert lines[0].startswith("Nothing was compared with wordpress.org, because the comparison was switched off.")


def test_red_from_rules_alone_is_told_apart(scan, page):
    """A red finding of a code rule rests on a rule, not on a difference from an official file,
    and the summary says how many of the reds are of that kind."""
    scan(craft_zip([*site(), Member(MU_PLUGIN, code("exec($target);")), Member(UPLOADS + "mockup.jpeg", PROGRAM)]))
    lines = summary(page)
    assert any(line.startswith("1 of the 2 red findings comes from rules applied to code that has no official release") for line in lines)
    assert not any("Linux container" in line for line in lines)


def test_the_summary_keeps_quiet_about_rules_when_no_red_comes_from_them(scan, page):
    scan(SAMPLES_BY_NAME["dropper"].build())
    assert not any("from rules applied to code" in line for line in summary(page))


def test_one_file_that_always_runs_is_named_in_the_singular(scan, page):
    """wp-config.php alone is the commonest case: it is always-loaded and never official."""
    copied = scan_then_copy(scan, page, craft_zip([member for member in site() if "mu-plugins" not in member.name]))
    summary_text = " ".join(summary(page))
    assert "WordPress loads 1 file by itself" in summary_text
    assert "It is listed below. Read it," in summary_text
    assert "CODE THAT WORDPRESS LOADS BY ITSELF (read this file)" in copied.splitlines()
    # The page's own line above the list fits one file as well as many.
    above_the_list = page.locator('section:has([data-scanner="loaded-code"]) p').text_content()
    assert above_the_list.startswith("WordPress loads all of this by itself")


def test_a_core_wordpress_org_does_not_know_is_not_called_a_plugin(scan, page):
    """wordpress.org answers an unknown release or language with no list; that is no plugin."""
    page.wordpress_org.answers.update({core_checksums_url("6.9.5", "en_US"): NO_CORE_LIST})
    scan(craft_zip(site()))
    said = page.locator('[data-scanner="findings"] > li', has_text="The WordPress core").text_content()
    assert "The WordPress core was not compared with wordpress.org: wordpress.org has no checksums for this version in this language." in said
    assert "plugin" not in said


def test_a_scan_that_did_not_finish_has_no_summary(scan, page):
    page.route("**/scanner/worker.js", lambda route: route.fulfill(
        status=200, content_type="text/javascript", body="self.addEventListener('message', () => self.postMessage('done'));",
    ))
    scan(craft_zip(site()))
    assert summary(page) == []
    assert "did not finish" in page.text_content('[data-scanner="status"]')


def test_code_that_always_runs_is_listed_for_reading(scan, page):
    drop_in = Member(DROP_IN, b"<?php\n// page cache\n")
    scan(craft_zip([*site(), drop_in]))
    sizes = {member.name: len(member.body) for member in [*site(), drop_in]}
    config, mu_plugin = ROOT + "wp-config.php", ROOT + "wp-content/mu-plugins/site-preview.php"
    assert rows(page, "loaded-code") == [
        f"{config} ({sizes[config]} B)",
        f"{mu_plugin} (Preview, {sizes[mu_plugin]} B)",
        f"{DROP_IN} ({sizes[DROP_IN]} B)",
    ]
    summary_text = " ".join(summary(page))
    assert "WordPress loads 3 files by itself" in summary_text


def test_the_always_loaded_list_holds_what_wordpress_loads_by_itself(scan, page):
    """The stock wp-content/index.php of every WordPress sat on this list on practically every
    real copy. A drop-in and .maintenance belong on it; other PHP in wp-content does not, nor
    does a wp-config.php or a .maintenance in a folder WordPress never reads them from."""
    extra = [
        Member(CONTENT_INDEX, STOCK_CONTENT_INDEX),
        Member(CONTENT_LOOSE_PHP, b"<?php\n$ready = true;\n"),
        Member(SITUATIONAL_DROP_IN, b"<?php\n// maintenance page\n"),
        Member(MAINTENANCE_FILE, STOCK_MAINTENANCE),
        Member(ROOT + "backup/wp-config.php", b"<?php\ndefine('DB_NAME', 'old');\n"),
        Member(ROOT + "wp-content/uploads/.maintenance", STOCK_MAINTENANCE),
    ]
    scan(craft_zip([*site(), *extra]))
    listed = [row.split(" (")[0] for row in rows(page, "loaded-code")]
    assert listed == [ROOT + "wp-config.php", ROOT + "wp-content/mu-plugins/site-preview.php", SITUATIONAL_DROP_IN, MAINTENANCE_FILE]


def test_the_always_loaded_list_holds_language_files_that_are_more_than_texts(scan, page):
    """WordPress runs the file named after the site's language on every request, and includes
    translation files by itself. One that only returns its texts is data: listing the dozens a
    translated site has would bury the files worth reading. Only a translation file is taken
    for data that way; the locale file below holds the same shape and stays on the list."""
    quiet = b"<?php\n$ready = true;\n"
    extra = [
        Member(LOCALE_FILE, PLAIN_TRANSLATION),
        # WordPress requires "<locale>.php" only; .phtml is no name it builds.
        Member(ROOT + "wp-content/languages/pl_PL.phtml", quiet),
        Member(CORE_TRANSLATION, PLAIN_TRANSLATION),
        Member(PLUGIN_TRANSLATION, PLAIN_TRANSLATION),
        Member(THEME_TRANSLATION, TRANSLATION_READING_A_VARIABLE),
        Member(LOCO_TRANSLATION, TRANSLATION_READING_A_VARIABLE),
        Member(LANGUAGES_SUBFOLDER_HELPER, quiet),
        # Literals only between the tags, but text outside them is printed into every page.
        Member(ROOT + "wp-content/languages/plugins/shop-pl_PL.l10n.php", TRANSLATION_PRINTING_BEFORE),
        Member(ROOT + "wp-content/languages/plugins/form-pl_PL.l10n.php", TRANSLATION_PRINTING_AFTER),
        # "<?php" and a form feed is no open tag to PHP with short tags off: the file is text.
        Member(ROOT + "wp-content/languages/plugins/menu-pl_PL.l10n.php", b"<?php\x0c return ['<script>' => 'b'];\n"),
    ]
    scan(craft_zip([*site(), *extra]))
    listed = [row.split(" (")[0] for row in rows(page, "loaded-code")]
    assert listed == [
        ROOT + "wp-config.php", ROOT + "wp-content/mu-plugins/site-preview.php", LOCALE_FILE, THEME_TRANSLATION,
        ROOT + "wp-content/languages/plugins/shop-pl_PL.l10n.php", ROOT + "wp-content/languages/plugins/form-pl_PL.l10n.php",
        ROOT + "wp-content/languages/plugins/menu-pl_PL.l10n.php",
    ]


def test_loose_php_in_wp_content_is_not_said_to_lie_where_wordpress_loads_no_code(scan, page):
    """WordPress loads the drop-ins from wp-content itself and translations from its languages
    folder; a folder below it, such as a cache folder, is one it loads no code from. A copy of
    wp-content without its core has its wp-config.php on the list, so the folder of that copy
    is not one either."""
    cached = ROOT + "wp-content/cache/page.php"
    beside_copy = ROOT + "staging/shell.php"
    quiet = b"<?php\n$ready = true;\n"
    extra = [
        Member(CONTENT_LOOSE_PHP, quiet), Member(cached, quiet), Member(LANGUAGES_SUBFOLDER_HELPER, quiet),
        Member(ROOT + "staging/wp-content/index.php", STOCK_CONTENT_INDEX), Member(beside_copy, quiet),
    ]
    scan(craft_zip([*site(), *extra]), online=False)
    # One row per path: the staging/ copy also carries its "not compared" line.
    sentences = {
        row.locator(".finding-path").text_content(): [said.text_content() for said in row.locator(".finding-text").all()]
        for row in page.locator('[data-scanner="findings"] > .finding').all()
    }

    def says(path: str, opening: str) -> bool:
        return any(sentence.startswith(opening) for sentence in sentences[path])

    assert says(ROOT + "wp-content/", f"1 PHP file lying directly in wp-content is not a drop-in: {CONTENT_LOOSE_PHP}. It runs only when")
    assert says(ROOT + "wp-content/cache/", f"1 PHP file in a folder WordPress does not load code from: {cached}.")
    assert says(ROOT + "wp-content/languages/", f"1 PHP file in wp-content/languages is not a translation file: {LANGUAGES_SUBFOLDER_HELPER}. It runs only when")
    assert says(ROOT + "staging/", f"1 PHP file lies directly in a folder with a wp-content but no wp-includes: {beside_copy}. It runs only when")
    assert says(ROOT + "staging/", "This folder holds a wp-content but no wp-includes. At most one site per scan is compared with wordpress.org, and this folder is not part of it.")


def test_loose_php_beside_a_copy_at_the_top_of_the_archive_is_named_by_its_place(scan, page):
    """The copy's folder is the top of the archive itself; the sentence still says where."""
    scan(SAMPLES_BY_NAME["php_beside_a_copy_without_core_at_the_top"].build(), online=False)
    said = page.locator('[data-scanner="findings"] > .finding', has_text="helper.php").locator(".finding-text").text_content()
    assert said.startswith("1 PHP file lies directly in a folder with a wp-content but no wp-includes: helper.php.")


def test_compared_components_are_listed(scan, page):
    page.wordpress_org.answers.update(tool_answers()())
    scan(craft_zip([*site(), *tool_files()]))
    listed = rows(page, "components")
    assert listed == [
        "WordPress 6.9.5: 1 of 1 file the same as on wordpress.org, 0 different, 0 extra, 0 missing",
        "tool 2.4.1: 5 of 5 files the same as on wordpress.org, 0 different, 0 extra, 0 missing",
    ]


def test_sections_without_rows_stay_hidden(scan, page):
    scan(SAMPLES_BY_NAME["clean"].build(), online=False)
    hidden = page.locator("[data-scanner-section]").evaluate_all("(sections) => sections.map((section) => section.hidden)")
    # Findings (the switched-off comparison is one) and always-loaded code have rows; the
    # comparison and the vulnerabilities have none.
    assert hidden == [False, False, True, True]


def test_a_code_finding_is_drawn_with_its_line_and_a_red_file_with_its_hash(scan, page):
    scan(craft_zip([*site(), Member(MU_PLUGIN, code("exec($target);"))]))
    row = page.locator('[data-scanner="findings"] > li').first
    assert row.locator(".finding-excerpt").text_content() == "exec($target);"
    assert row.locator(".finding-hash").text_content().startswith("SHA-256 ")
    assert len(row.locator(".finding-hash").text_content()) == len("SHA-256 ") + 64


def test_the_log_shrinks_when_the_scan_is_over_and_opens_again(scan, page):
    scan(SAMPLES_BY_NAME["layout_mix"].build())
    log = page.locator('[data-scanner="log"]')
    toggle = page.locator('[data-scanner="log-toggle"]')
    assert log.get_attribute("data-expanded") == "false"
    assert (toggle.text_content(), toggle.get_attribute("aria-expanded")) == ("Show the whole log", "false")
    small = log.bounding_box()["height"]
    toggle.click()
    assert (toggle.text_content(), toggle.get_attribute("aria-expanded")) == ("Show less of the log", "true")
    assert log.bounding_box()["height"] > small


def test_the_page_says_what_it_waits_for_after_the_file_is_read(page, site_url, tmp_path):
    """The vulnerability lookup runs on the page and can outlast the scan on a slow network:
    the status names the wait instead of looking stuck."""
    page.wordpress_org.delay_seconds = 1.5
    archive = tmp_path / "backup.zip"
    archive.write_bytes(SAMPLES_BY_NAME["clean"].build())
    page.goto(site_url)
    page.wait_for_selector('[data-scanner="root"][data-state="ready"]', timeout=PAGE_READY_TIMEOUT_MS)
    page.evaluate(REPORT_HOOK)
    page.set_input_files('[data-scanner="input"]', str(archive))
    page.wait_for_function("""() => document.querySelector('[data-scanner="status"]').textContent.includes('Waiting for the answers about known vulnerabilities')""")
    page.wait_for_function("""() => document.querySelector('[data-scanner="log"]').textContent.includes('waiting for the answers about known vulnerabilities')""")
    page.evaluate(REPORT_OR_TIMEOUT, SCAN_TIMEOUT_MS)
    assert "waiting for the answers" not in page.text_content('[data-scanner="log"]')
    assert "not a clean bill" in page.text_content('[data-scanner="status"]')


def copy_report(page: Page) -> str:
    page.click('[data-scanner="copy-text"]')
    page.wait_for_function("""() => document.querySelector('[data-scanner="export-status"]').textContent !== ''""")
    return page.evaluate("() => window.copiedText ?? ''")


def scan_then_copy(scan, page: Page, archive: bytes, clipboard: str = CLIPBOARD_THAT_KEEPS) -> str:
    page.add_init_script(clipboard)
    scan(archive)
    return copy_report(page)


def test_the_report_can_be_copied_as_text(scan, page):
    copied = scan_then_copy(scan, page, craft_zip([*site(), Member(MU_PLUGIN, code("exec($target);"))]))
    assert page.text_content('[data-scanner="export-status"]') == "Copied to the clipboard."
    lines = copied.splitlines()
    assert lines[0].startswith("Backup Scanner for WordPress report (http://127.0.0.1")
    assert "Verdict: Do not run this copy." in lines
    assert "Do not run: 1 · Read first: 0 · Not checked: 0" in lines
    at = lines.index("DO NOT RUN")
    assert lines[at + 1] == f"- {MU_PLUGIN}"
    assert lines[at + 2].startswith("  Code that WordPress loads by itself starts a program: exec() on line")
    assert lines[at + 3] == "  in the file: exec($target);"
    assert lines[at + 4].startswith("  SHA-256 ")
    assert "CODE THAT WORDPRESS LOADS BY ITSELF (read each file)" in lines
    assert "REQUESTS SENT (names and versions only)" in lines
    assert any(line.startswith("Finished in ") and "carried names and versions only" in line for line in lines)
    assert "- https://api.wordpress.org/core/checksums/1.0/?version=6.9.5&locale=en_US" in lines


def test_addresses_are_masked_in_the_copied_report_and_shown_on_the_page(scan, page):
    copied = scan_then_copy(scan, page, craft_zip([*site(), Member(ADDRESS_IN_A_NAME, PROGRAM)]))
    assert f"- {MASKED_NAME}" in copied.splitlines()
    assert "john.smith" not in copied
    assert "E-mail addresses in this report are masked." in copied
    assert page.text_content('[data-scanner="findings"] .finding-path') == ADDRESS_IN_A_NAME


def test_a_finding_about_the_whole_copy_is_labelled_where_a_path_would_be(scan, page):
    """Switching the comparison off is a finding about the archive, not about one file in it."""
    page.add_init_script(CLIPBOARD_THAT_KEEPS)
    scan(SAMPLES_BY_NAME["clean"].build(), online=False)
    copied = copy_report(page)
    whole = page.locator('[data-scanner="findings"] .finding-no-path')
    assert whole.text_content() == "(the whole copy)"
    assert whole.evaluate("(label) => label.classList.contains('finding-path')")
    assert "- (the whole copy)" in copied.splitlines()
    assert any(line.startswith("! (the whole copy): ") for line in rows(page, "log"))


# One rule past its cap of findings, so the scan ends with the line that counts the rest.
PAST_THE_CAP = 502


def test_findings_past_a_rules_cap_name_the_file_they_resemble(scan, page):
    """Rows are per file, so "more findings of this kind" pointed at nothing on the page."""
    page.add_init_script(CLIPBOARD_THAT_KEEPS)
    photos = [Member(f"{UPLOADS}photo-{number:03}.jpeg", PROGRAM) for number in range(PAST_THE_CAP)]
    scan(craft_zip([*site(), *photos]), online=False)
    copied = copy_report(page)

    unnamed = page.locator('[data-scanner="findings"] > .finding', has_text="(other findings)")
    assert unnamed.locator(".finding-reason").count() == 1
    assert unnamed.locator(".finding-text").text_content() == (
        f"2 more findings like the one for {UPLOADS}photo-000.jpeg are not listed separately."
    )
    assert "- (other findings)" in copied.splitlines()
    assert "(the whole copy)" not in unnamed.text_content()


def test_a_finding_without_a_path_is_placed_by_what_it_counts(page, site_url):
    """Only a count past the cap that names where it began stands for other places; a count
    of a rule about the whole copy, and any other finding without a path, are the whole copy."""
    page.goto(site_url)
    page.wait_for_selector('[data-scanner="root"][data-state="ready"]', timeout=PAGE_READY_TIMEOUT_MS)
    places = page.evaluate("""async () => {
      const { placeOf } = await import('/scanner/messages.js');
      return [
        placeOf({ path: '', params: { more: 3, example: 'wp-content/cache/' } }),
        placeOf({ path: '', params: { more: 3, example: '' } }),
        placeOf({ path: '', params: { reason: 'network', example: 'tool', exampleKind: 'plugin' } }),
        placeOf({ path: 'wp-config.php', params: {} }),
      ];
    }""")
    assert places == ["(other findings)", "(the whole copy)", "(the whole copy)", "wp-config.php"]


def test_masking_can_be_switched_off(scan, page):
    page.add_init_script(CLIPBOARD_THAT_KEEPS)
    scan(craft_zip([*site(), Member(ADDRESS_IN_A_NAME, PROGRAM)]))
    page.uncheck('[data-scanner="mask"]')
    copied = copy_report(page)
    assert f"- {ADDRESS_IN_A_NAME}" in copied.splitlines()
    assert "are masked" not in copied


def test_a_refused_clipboard_puts_the_report_into_a_text_box(scan, page):
    copied = scan_then_copy(scan, page, SAMPLES_BY_NAME["dropper"].build(), clipboard=CLIPBOARD_THAT_REFUSES)
    assert copied == ""
    assert "select it and copy it by hand" in page.text_content('[data-scanner="export-status"]')
    box = page.locator('[data-scanner="report-text"]')
    assert box.is_visible()
    assert "Verdict: Do not run this copy." in box.input_value()


def test_the_report_can_be_downloaded_as_json(scan, page, tmp_path):
    scan(craft_zip([*site(), Member(ADDRESS_IN_A_NAME, PROGRAM)]))
    with page.expect_download() as started:
        page.click('[data-scanner="download-json"]')
    target = tmp_path / "report.json"
    started.value.save_as(target)
    exported = json.loads(target.read_text(encoding="utf-8"))
    assert started.value.suggested_filename == "wp-backup-scan-report.json"
    assert (exported["schema"], exported["emailsMasked"], exported["completed"]) == (2, True, True)
    assert finding_keys(exported) == {("red", "layout.disguised_executable", MASKED_NAME)}
    assert exported["hashes"][0]["path"] == MASKED_NAME
    assert exported["verdict"] == "Do not run this copy."


@pytest.mark.parametrize("text", [
    "plain text with no address",
    "@", "a@", "@b.c", "a@b", "@@@@", "a@b@c.d",
    "mail jan.kowalski+test@firma.example.pl now",
    "two: a@b.co, c.d@e.org",
    "x" * 5000 + "@" + "y" * 5000,
])
def test_masking_keeps_everything_but_the_name_before_the_at_sign(text, page, site_url):
    page.goto(site_url)
    masked = page.evaluate("async (text) => (await import('/scanner/report-export.js')).maskEmails(text)", text)
    expected = {
        "mail jan.kowalski+test@firma.example.pl now": "mail j***@firma.example.pl now",
        "two: a@b.co, c.d@e.org": "two: a***@b.co, c***@e.org",
        "a@b@c.d": "a@b***@c.d",
    }
    assert masked == expected.get(text, text)


def click_example_and_wait(page: Page, site_url: str) -> dict:
    page.goto(site_url)
    page.wait_for_selector('[data-scanner="root"][data-state="ready"]', timeout=PAGE_READY_TIMEOUT_MS)
    page.evaluate(REPORT_HOOK)
    page.click('[data-scanner="example"]')
    return page.evaluate(REPORT_OR_TIMEOUT, SCAN_TIMEOUT_MS)


def test_the_example_is_built_in_the_browser_and_scanned_like_any_file(page, site_url):
    official = {"hello.php": b"<?php\n// the release\n", "readme.txt": b"=== Hello Dolly ===\n"}
    page.wordpress_org.answers.update({
        plugin_checksums_url("hello-dolly", "1.7.2"): plugin_list("hello-dolly", "1.7.2", official),
        plugin_info_url("hello-dolly"): plugin_found("hello-dolly"),
    })
    report = click_example_and_wait(page, site_url)
    assert report["archive"]["name"] == "example-copy.zip"
    assert report["completed"] is True
    assert finding_keys(report) == {
        ("red", "layout.disguised_executable", EXAMPLE_PHOTO),
        ("amber", "indicator.known_name", EXAMPLE_PHOTO),
        ("red", "loaded.launch_call", EXAMPLE_LOADER),
        ("red", "loaded.rename_executable", EXAMPLE_LOADER),
        ("amber", "indicator.known_name", EXAMPLE_LOADER),
        ("red", "plugin.modified", EXAMPLE_PLUGIN + "hello.php"),
        ("amber", "plugin.missing_files", EXAMPLE_PLUGIN),
        ("not_checked", "component.not_compared", EXAMPLE_ROOT),
        ("amber", "db.active_plugin_missing", EXAMPLE_ROOT + "database.sql"),
        ("amber", "db.snippet_plugin_active", EXAMPLE_ROOT + "database.sql"),
    }
    # Nothing about the example is fetched: the page asked the three hosts about the plugin only.
    assert all("hello-dolly" in url for url in page.wordpress_org.requested)
    assert report["siteHosts"] == ["example.com"]
    # Both reds that rest on rules alone sit in the one mu-plugin.
    assert any(line.startswith("2 of the 4 red findings come") and line.endswith("so read that file before you decide.") for line in summary(page))


def test_the_example_needs_no_network(page, site_url):
    page.wordpress_org.unreachable = True
    report = click_example_and_wait(page, site_url)
    assert ("red", "layout.disguised_executable", EXAMPLE_PHOTO) in finding_keys(report)
    assert report["completed"] is True


def scan_in_polish(page: Page, site_url: str, archive_path: Path) -> None:
    """The address decides the language: the same scanner on a page marked lang="pl"."""

    def in_polish(route: Route) -> None:
        served = route.fetch()
        route.fulfill(response=served, body=served.text().replace('<html lang="en">', '<html lang="pl">'))

    page.route(site_url, in_polish)
    page.goto(site_url)
    page.wait_for_selector('[data-scanner="root"][data-state="ready"]', timeout=PAGE_READY_TIMEOUT_MS)
    page.evaluate(REPORT_HOOK)
    page.set_input_files('[data-scanner="input"]', str(archive_path))
    page.evaluate(REPORT_OR_TIMEOUT, SCAN_TIMEOUT_MS)


def test_the_polish_page_speaks_polish(page, site_url, tmp_path):
    page.add_init_script(CLIPBOARD_THAT_KEEPS)
    archive = tmp_path / "backup.zip"
    archive.write_bytes(craft_zip([*site(), Member(MU_PLUGIN, code("exec($target);"))]))
    scan_in_polish(page, site_url, archive)

    assert page.text_content('[data-scanner="status"]') == "Nie uruchamiaj tej kopii."
    finding = page.locator('[data-scanner="findings"] > li').first
    assert finding.locator(".finding-weight").text_content() == "Nie uruchamiaj"
    assert "uruchamia program: exec(), w linii" in finding.locator(".finding-text").text_content()
    assert page.text_content('[data-scanner="log-toggle"]') == "Pokaż cały log"
    assert any(line.startswith("Jedyne czerwone znalezisko pochodzi z reguł zastosowanych do kodu") for line in summary(page))
    page.click('[data-scanner="copy-text"]')
    page.wait_for_function("() => typeof window.copiedText === 'string'")
    assert "Werdykt: Nie uruchamiaj tej kopii." in page.evaluate("() => window.copiedText")


def test_the_polish_page_names_a_component_in_polish(page, site_url, tmp_path):
    """The kind of the component a lookup failed for is a word of the page's language."""
    page.wordpress_org.answers.update(tool_answers()() | {plugin_vulnerabilities_url("tool"): Answer(SERVICE_UNAVAILABLE, b'{"error":1}')})
    archive = tmp_path / "backup.zip"
    archive.write_bytes(craft_zip([*site(), *tool_files()]))
    scan_in_polish(page, site_url, archive)

    said = page.locator('[data-scanner="findings"] > li', has_text="Znane podatności").text_content()
    assert "dla 1 składnika (wtyczka tool)" in said
    assert "plugin" not in said


def test_the_polish_page_labels_the_whole_copy_in_polish(page, site_url, tmp_path):
    page.add_init_script(CLIPBOARD_THAT_KEEPS)
    archive = tmp_path / "backup.zip"
    archive.write_bytes(craft_zip([Member("notes.txt", b"not a site")]))
    scan_in_polish(page, site_url, archive)

    assert page.text_content('[data-scanner="findings"] .finding-no-path') == "(cała kopia)"
    assert "- (cała kopia)" in copy_report(page).splitlines()
