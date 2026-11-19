"""Known vulnerabilities and closed plugins: listed apart, never weighed, and a lookup that failed
is never shown as "none known"."""
import json
import os

import pytest
from playwright.sync_api import Browser

from conftest import finding_keys, scan_on
from samples import ROOT, TOOL_VERSION, site, tool_answers, tool_files
from serve import REPO_ROOT
from test_page_behaviour import swap_worker
from wporg import (
    Answer, as_json, core_vulnerabilities_url, plugin_closed, plugin_info_url, plugin_vulnerabilities_url,
    theme_vulnerabilities_url, vulnerability, vulnerability_list,
)
from zipcraft import Member, craft_zip

GATEWAY = "scanner/gateway.js"
THREE_REQUESTS_ONLY = {GATEWAY: ("const MAX_REQUESTS = 150;", "const MAX_REQUESTS = 3;")}
THEME = "sample-theme"
THEME_STYLE = f"{ROOT}wp-content/themes/{THEME}/style.css"
CVE_LINK = "https://www.cve.org/CVERecord?id=CVE-2025-10001"
PATCHSTACK_ID = "c930fcd63f99f80b3ee6b25cc3ae73d874ff4be4"
HIDDEN_DIRECTION = "\u202e"
SERVICE_UNAVAILABLE = 503
MANY_PLUGINS = 10
PARALLEL_REQUESTS = 4
SLOW_ANSWER_SECONDS = 0.5
AFTER_FINISH_MS = 2500
# A plugin version the database lists entries for, and a core release with known ones (the
# database's own sample in its docs is 5.8.2). Checked on the real hosts by the live test only.
LIVE_PLUGIN = ("elementor", "3.0.0")
LIVE_CORE = "6.8"
LIVE = os.environ.get("SCANNER_LIVE") == "1"


def official_tool() -> bytes:
    return craft_zip([*site(), *tool_files()])


def advisory(report: dict, kind: str, name: str) -> dict:
    return next(record for record in report["advisories"] if record["kind"] == kind and record["name"] == name)


def advisory_findings(report: dict) -> dict[str, dict]:
    return {found["params"]["reason"]: found["params"] for found in report["findings"] if found["rule"] == "advisory.not_checked"}


def theme_site(style: bytes) -> bytes:
    return craft_zip([*site(), Member(THEME_STYLE, style), Member(f"{ROOT}wp-content/themes/{THEME}/index.php", b"<?php\n")])


def test_entries_that_cover_the_version_are_listed(scan, page):
    page.wordpress_org.answers.update(tool_answers()() | {plugin_vulnerabilities_url("tool"): vulnerability_list("plugin", "tool", [
        vulnerability("2.5.0"),
        vulnerability("2.4.0", sources=(("CVE-2025-10002", CVE_LINK),)),
        vulnerability("2.4.1", "le", min_version="2.4.0", min_operator="ge", unfixed=True, sources=(("CVE-2025-10003", CVE_LINK),)),
    ])})

    report = scan(official_tool())

    tool = advisory(report, "plugin", "tool")
    assert (tool["state"], tool["version"]) == ("checked", TOOL_VERSION)
    assert [entry["ids"] for entry in tool["entries"]] == [["CVE-2025-10001"], ["CVE-2025-10003"]]
    # Never weighed: an official plugin with known vulnerabilities has no finding at all.
    assert finding_keys(report) == set()
    drawn = page.locator('[data-scanner="advisories"] .advisory-entry').all_text_contents()
    assert len(drawn) == 2
    assert "versions before 2.5.0, fixed in 2.5.0 · CVSS 6.4 · CWE-79 Cross-site Scripting" in drawn[0]
    assert "versions from 2.4.0 up to 2.4.1, no fixed release yet" in drawn[1]


def test_a_version_outside_every_range_has_none(scan, page):
    page.wordpress_org.answers.update(tool_answers()() | {plugin_vulnerabilities_url("tool"): vulnerability_list("plugin", "tool", [
        vulnerability("2.4.1"), vulnerability("2.0", "le"), vulnerability("3.0", min_version="2.5.0", min_operator="ge"),
    ])})

    report = scan(official_tool())

    assert advisory(report, "plugin", "tool")["entries"] == []
    assert advisory(report, "plugin", "tool")["state"] == "checked"
    assert page.locator('[data-scanner="advisories"] > li').count() == 0


def test_a_name_the_database_does_not_know_has_none(scan, page):
    report = scan(official_tool())

    assert {(record["kind"], record["name"], record["state"], len(record["entries"])) for record in report["advisories"]} == {
        ("core", "WordPress", "checked", 0), ("plugin", "tool", "checked", 0),
    }


def test_core_entries_apply_as_listed(scan, page):
    page.wordpress_org.answers[core_vulnerabilities_url("6.9.5")] = vulnerability_list("core", "6.9.5", [
        vulnerability(None, None, sources=(("EUVD-2025-30913", "https://euvd.enisa.europa.eu/enisa/EUVD-2025-30913"),)),
        vulnerability(None, None, sources=((PATCHSTACK_ID, "https://patchstack.com/database/wordpress/core"),), score=None, cwe=None),
    ])

    report = scan(craft_zip(site()))

    core = advisory(report, "core", "WordPress")
    assert [(entry["ids"], entry["links"]) for entry in core["entries"]] == [
        (["EUVD-2025-30913"], []), ([], ["https://patchstack.com/database/wordpress/core"]),
    ]
    assert "affects this release" in page.text_content('[data-scanner="advisories"]')


def test_a_theme_version_is_read_from_its_style_sheet(scan, page):
    page.wordpress_org.answers[theme_vulnerabilities_url(THEME)] = vulnerability_list("theme", THEME, [vulnerability("1.3")])

    report = scan(theme_site(b"/*\nTheme Name: Sample\nVersion: 1.2.0\n*/\n"))

    theme = advisory(report, "theme", THEME)
    assert (theme["version"], len(theme["entries"])) == ("1.2.0", 1)
    assert theme_vulnerabilities_url(THEME) in report["requests"]


def test_a_theme_beside_a_core_kept_in_its_own_folder_is_looked_up(scan, page):
    """WordPress kept in wp/ with its wp-content in the folder above: the themes there are the site's."""
    style = b"/*\nTheme Name: Sample\nVersion: 1.2.0\n*/\n"
    report = scan(craft_zip([
        Member(f"{ROOT}wp/wp-includes/version.php", b"<?php\n$wp_version = '6.9.5';\n"),
        Member(f"{ROOT}wp-config.php", b"<?php\ndefine('DB_NAME', 'local');\n"),
        Member(THEME_STYLE, style),
    ]))

    assert advisory(report, "theme", THEME)["state"] == "checked"
    assert advisory(report, "theme", THEME)["version"] == "1.2.0"


def test_a_theme_without_a_version_is_not_looked_up(scan, page):
    report = scan(theme_site(b"/*\nTheme Name: Sample\n*/\n"))

    assert advisory(report, "theme", THEME)["state"] == "no_version"
    assert theme_vulnerabilities_url(THEME) not in report["requests"]
    assert advisory_findings(report) == {}


def test_a_closed_plugin_is_named_even_when_its_files_match(scan, page):
    """Measured on display-widgets 2.7: closed in 2021, its checksums are still served."""
    page.wordpress_org.answers.update(tool_answers()() | {plugin_info_url("tool"): plugin_closed("tool")})

    report = scan(official_tool())

    assert advisory(report, "plugin", "tool")["closed"] == {"date": "2021-01-30", "reason": "security-issue"}
    assert finding_keys(report) == set()
    assert "wordpress.org closed this plugin on 2021-01-30 (reason given: security issue)" in page.text_content(
        '[data-scanner="advisories"]')


def test_a_closed_plugin_without_a_version_is_named(scan, page):
    """Closed is closed in any version, so the directory is asked without one too."""
    page.wordpress_org.answers.update({plugin_info_url("tool"): plugin_closed("tool")})

    report = scan(craft_zip([*site(), *tool_files({"tool.php": b"<?php\n/**\n * Plugin Name: Tool\n */\n"})]))

    record = advisory(report, "plugin", "tool")
    assert (record["state"], record["closed"]) == ("no_version", {"date": "2021-01-30", "reason": "security-issue"})
    drawn = page.text_content('[data-scanner="advisories"]')
    assert "plugin tool: known vulnerabilities not looked up" in drawn
    assert "wordpress.org closed this plugin on 2021-01-30" in drawn


def test_a_silent_directory_is_not_a_failed_vulnerability_lookup(scan, page):
    """The entries came back and only "is it closed?" did not: said apart, not as "network"."""
    page.wordpress_org.answers.update(tool_answers()() | {
        plugin_vulnerabilities_url("tool"): vulnerability_list("plugin", "tool", [vulnerability("2.5.0")]),
        plugin_info_url("tool"): Answer(404, b"Not found", cors=False),
    })

    report = scan(official_tool())

    assert advisory(report, "plugin", "tool")["state"] == "checked"
    assert len(advisory(report, "plugin", "tool")["entries"]) == 1
    assert set(advisory_findings(report)) == {"closure_unknown"}
    closure = advisory_findings(report)["closure_unknown"]
    assert (closure["exampleKind"], closure["example"]) == ("plugin", "tool")


@pytest.mark.parametrize(("answer", "reason"), [
    (Answer(SERVICE_UNAVAILABLE, b'{"error":1,"message":"Database error","data":null,"updated":0}'), "unavailable"),
    (as_json({"error": 1, "message": "No", "data": {"plugin": "tool", "vulnerability": None}, "updated": 0}), "bad_answer"),
    (as_json({"error": 0, "message": None, "data": {"plugin": "tool", "vulnerability": "many"}, "updated": 0}), "bad_answer"),
    (Answer(200, b"{not json"), "bad_answer"),
    (Answer(404, b"Not found", cors=False), "network"),
], ids=["unavailable", "error_envelope", "list_not_a_list", "not_json", "unreachable"])
def test_a_failed_lookup_has_its_own_reason(answer, reason, scan, page):
    page.wordpress_org.answers.update(tool_answers()() | {plugin_vulnerabilities_url("tool"): answer})

    report = scan(official_tool())

    assert advisory(report, "plugin", "tool")["state"] == reason
    assert finding_keys(report) == {("not_checked", "advisory.not_checked", "")}
    failed = advisory_findings(report)[reason]
    assert (failed["exampleKind"], failed["example"]) == ("plugin", "tool")


def test_an_unreachable_database_is_one_finding_for_all(scan, page):
    page.wordpress_org.answers.update(tool_answers()())
    page.wordpress_org.unreachable_hosts.add("www.wpvulnerability.net")

    report = scan(official_tool())

    assert finding_keys(report) == {("not_checked", "advisory.not_checked", "")}
    assert advisory_findings(report)["network"]["components"] == 2
    assert report["completed"] is True


def test_the_request_limit_is_named(scan_patched, page):
    page.wordpress_org.answers.update(tool_answers()())

    report = scan_patched(official_tool(), THREE_REQUESTS_ONLY)

    assert len(report["requests"]) == 3
    assert advisory(report, "plugin", "tool")["state"] == "request_limit"
    assert advisory_findings(report)["request_limit"]["components"] == 1


def test_an_entry_that_cannot_be_judged_is_counted(scan, page):
    unreadable = vulnerability("2.5.0")
    unreadable["operator"]["max_operator"] = "below"
    page.wordpress_org.answers.update(tool_answers()() | {plugin_vulnerabilities_url("tool"): vulnerability_list("plugin", "tool", [
        unreadable, vulnerability("2.5.0"),
    ])})

    report = scan(official_tool())

    assert len(advisory(report, "plugin", "tool")["entries"]) == 1
    assert advisory_findings(report)["unreadable_entries"]["entries"] == 1


def test_only_known_sources_become_links(scan, page):
    answer_with_sources(page)

    scan(official_tool())

    links = page.locator('[data-scanner="advisories"] a')
    assert links.evaluate_all("(found) => found.map((link) => [link.href, link.textContent])") == [[CVE_LINK, "CVE.org"]]
    facts = page.text_content('[data-scanner="advisories"] .advisory-facts')
    assert facts.startswith("CVE-2025-10001 ·")
    assert "Cross-site⟨U+202E⟩ Scripting" in facts


def test_a_link_opens_beside_the_report(scan, page):
    """In the same tab the report is gone: it exists only on this page."""
    answer_with_sources(page)
    scan(official_tool())
    link = page.locator('[data-scanner="advisories"] a')
    assert (link.get_attribute("target"), link.get_attribute("rel")) == ("_blank", "noopener noreferrer")


def test_links_are_read_without_url_can_parse(scan, page):
    """Safari 16.4 to 16.6 has DecompressionStream but not URL.canParse."""
    page.add_init_script("delete URL.canParse;")
    answer_with_sources(page)
    scan(official_tool())
    links = page.locator('[data-scanner="advisories"] a')
    assert links.evaluate_all("(found) => found.map((link) => link.href)") == [CVE_LINK]


def answer_with_sources(page) -> None:
    page.wordpress_org.answers.update(tool_answers()() | {plugin_vulnerabilities_url("tool"): vulnerability_list("plugin", "tool", [
        vulnerability("2.5.0", sources=(
            ("CVE-2025-10001", CVE_LINK),
            (PATCHSTACK_ID, "https://collector.example/report"),
            (PATCHSTACK_ID, "http://wpscan.com/vulnerability/1"),
            (PATCHSTACK_ID, "https://visitor@www.wordfence.com/threat-intel/1"),
            (f"CVE-2025-1{HIDDEN_DIRECTION}0004", "javascript:alert(1)"),
        ), cwe=("CWE-79", f"Cross-site{HIDDEN_DIRECTION} Scripting")),
    ])})


def test_an_offline_worker_cannot_ask_for_the_network(scan, page):
    swap_worker(page, "self.addEventListener('message', () => self.postMessage("
                      "{ type: 'inventory', core: null, plugins: [{ slug: 'tool', version: '1.0' }], themes: [] }));")

    report = scan(official_tool(), online=False)

    assert finding_keys(report) == {("not_checked", "scan.failed", "")}
    assert page.wordpress_org.requested == []


def test_a_finished_scan_starts_no_new_request(scan, page):
    """A scan that ended (here on a broken message) must not keep asking about its plugins."""
    plugins = ", ".join(f"{{ slug: 'plugin-{number}', version: '1.0' }}" for number in range(MANY_PLUGINS))
    swap_worker(page, "self.addEventListener('message', () => {"
                      f" self.postMessage({{ type: 'inventory', core: null, plugins: [{plugins}], themes: [] }});"
                      " self.postMessage({ type: 'navigate' }); });")
    page.wordpress_org.delay_seconds = SLOW_ANSWER_SECONDS

    report = scan(official_tool())
    page.wait_for_timeout(AFTER_FINISH_MS)

    assert finding_keys(report) == {("not_checked", "scan.failed", "")}
    # The lanes that had started before the end may finish; nothing new begins.
    assert len(page.wordpress_org.requested) <= PARALLEL_REQUESTS


def test_version_compare_matches_php(page, site_url):
    """tests/reference/version_compare.json is PHP 8.4's own version_compare(), recorded by
    tests/reference/version_compare.php."""
    recorded = json.loads((REPO_ROOT / "tests" / "reference" / "version_compare.json").read_text(encoding="utf-8"))
    page.goto(site_url)

    computed = page.evaluate("""async (versions) => {
      const { compareVersions } = await import('/scanner/version-compare.js');
      return versions.map((left) => versions.map((right) => compareVersions(left, right)));
    }""", recorded["versions"])

    assert computed == recorded["results"]


@pytest.mark.skipif(not LIVE, reason="talks to the real hosts; run with SCANNER_LIVE=1")
def test_live_an_old_release_has_known_vulnerabilities(browser: Browser, site_url, tmp_path):
    """The positive control of the plan: without it, a reader that never matches would look
    like a database that knows nothing."""
    slug, version = LIVE_PLUGIN
    archive = tmp_path / "live.zip"
    archive.write_bytes(craft_zip([
        Member(f"{ROOT}wp-includes/version.php", f"<?php\n$wp_version = '{LIVE_CORE}';\n".encode()),
        Member(f"{ROOT}wp-config.php", b"<?php\n"),
        Member(f"{ROOT}wp-content/plugins/{slug}/{slug}.php", f"<?php\n/*\nPlugin Name: Live\nVersion: {version}\n*/\n".encode()),
    ]))
    context = browser.new_context()
    try:
        report = scan_on(context.new_page(), site_url, archive)
    finally:
        context.close()

    assert len(advisory(report, "plugin", slug)["entries"]) > 0
    assert len(advisory(report, "core", "WordPress")["entries"]) > 0
