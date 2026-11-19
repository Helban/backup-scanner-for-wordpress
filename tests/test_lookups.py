"""The page's lookups at wordpress.org: which addresses it builds, what it does with each kind
of answer, and that it never asks for more than it may."""
import hashlib

import pytest

from conftest import finding_keys
from samples import PLUGIN, ROOT, TOOL_RELEASE, TOOL_VERSION, site, tool_answers, tool_files
from wporg import (
    Answer, as_json, core_checksums_url, core_vulnerabilities_url, plugin_checksums_url, plugin_closed, plugin_found,
    plugin_info_url, plugin_list, plugin_vulnerabilities_url,
)
from zipcraft import Member, craft_zip

GATEWAY = "scanner/gateway.js"
MAIN = "scanner/main.js"
TWO_REQUESTS_ONLY = {GATEWAY: ("const MAX_REQUESTS = 150;", "const MAX_REQUESTS = 2;")}
QUICK_WATCHDOG = {MAIN: ("const STALL_LIMIT_MS = 10_000;", "const STALL_LIMIT_MS = 1_000;")}
SLOW_ANSWER_SECONDS = 3
# RFC 1321, appendix A.5.
MD5_VECTORS = {
    "": "d41d8cd98f00b204e9800998ecf8427e",
    "a": "0cc175b9c0f1b6a831c399e269772661",
    "abc": "900150983cd24fb0d6963f7d28e17f72",
    "message digest": "f96b697d7cb7938d525a2f31aaf161d0",
    "abcdefghijklmnopqrstuvwxyz": "c3fcd3d76192e4007dfb496cca67e13b",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789": "d174ab98d277d9f5a5611c2c9f419d9f",
    "1234567890" * 8: "57edf4a22be3c955ac49da2e2107b67a",
}
BAD_DIGEST = as_json({"files": {"tool.php": {"md5": "not-a-digest", "sha256": "0" * 64}}})


def plugin_site(*plugins: tuple[str, str]) -> bytes:
    """The sample site with one minimal plugin per (folder, version)."""
    members = [
        Member(f"{ROOT}wp-content/plugins/{folder}/{folder}.php", f"<?php\n/*\nPlugin Name: X\nVersion: {version}\n*/\n".encode())
        for folder, version in plugins
    ]
    return craft_zip([*site(), *members])


def not_compared(report: dict) -> dict[str, str]:
    return {found["path"]: found["params"]["reason"] for found in report["findings"] if found["rule"] == "component.not_compared"}


@pytest.mark.parametrize(("answers", "reason"), [
    ({}, "not_listed"),
    ({plugin_info_url("tool"): plugin_found("tool")}, "version_not_listed"),
    ({plugin_info_url("tool"): plugin_closed("tool")}, "closed"),
    ({plugin_checksums_url("tool", TOOL_VERSION): BAD_DIGEST}, "bad_answer"),
    ({plugin_checksums_url("tool", TOOL_VERSION): Answer(200, b"{not json")}, "bad_answer"),
    # Should the checksum host ever send its 404 with a CORS header, it means the same.
    ({plugin_checksums_url("tool", TOOL_VERSION): Answer(404, b"Not found")}, "not_listed"),
], ids=["not_listed", "version_not_listed", "closed", "bad_digest", "not_json", "readable_404"])
def test_each_kind_of_answer_has_its_own_reason(answers, reason, scan, page):
    page.wordpress_org.answers.update(answers)
    report = scan(craft_zip([*site(), *tool_files({"docs/README.md": None, "bin/build.sh": None, "assets/bundle.zip": None})]))
    assert not_compared(report) == {PLUGIN: reason}


def test_an_unreachable_wordpress_org_is_named_for_core_and_plugins(scan, page):
    page.wordpress_org.unreachable = True
    report = scan(plugin_site(("tool", "1.0")))
    assert not_compared(report) == {ROOT: "network", PLUGIN: "network"}
    assert report["completed"] is True


def test_requests_carry_names_and_versions_only(scan, page):
    """Checksums first, then the vulnerability lookup; a plugin's version never goes to
    wpvulnerability.net, which answers with every entry for the name."""
    page.wordpress_org.answers.update(tool_answers()())
    report = scan(craft_zip([*site(), *tool_files()]))
    expected = [
        core_checksums_url("6.9.5", "en_US"), plugin_checksums_url("tool", TOOL_VERSION),
        core_vulnerabilities_url("6.9.5"), plugin_vulnerabilities_url("tool"), plugin_info_url("tool"),
    ]
    assert report["requests"] == expected
    assert page.wordpress_org.requested == expected


def test_the_directory_is_asked_once_per_plugin(scan, page):
    """Asked during the comparison because the checksums failed, and not again for the closure."""
    report = scan(plugin_site(("tool", "1.0")))
    assert report["requests"] == [
        core_checksums_url("6.9.5", "en_US"), plugin_checksums_url("tool", "1.0"), plugin_info_url("tool"),
        core_vulnerabilities_url("6.9.5"), plugin_vulnerabilities_url("tool"),
    ]


def test_a_folder_name_that_cannot_be_a_slug_is_not_sent(scan, page):
    report = scan(plugin_site(("My_Plugin", "1.0")))
    assert report["requests"] == [core_checksums_url("6.9.5", "en_US"), core_vulnerabilities_url("6.9.5")]
    assert not_compared(report) == {f"{ROOT}wp-content/plugins/My_Plugin/": "not_listed"}


def test_requests_stop_at_the_limit(scan_patched, page):
    page.wordpress_org.answers.update({plugin_checksums_url("alpha", "1.0"): plugin_list("alpha", "1.0", {})})
    report = scan_patched(plugin_site(("alpha", "1.0"), ("beta", "1.0")), TWO_REQUESTS_ONLY)
    assert len(report["requests"]) == 2
    assert not_compared(report) == {f"{ROOT}wp-content/plugins/beta/": "request_limit"}


def test_the_watchdog_waits_while_wordpress_org_answers(scan_patched, page):
    page.wordpress_org.delay_seconds = SLOW_ANSWER_SECONDS
    report = scan_patched(craft_zip(site()), QUICK_WATCHDOG)
    assert finding_keys(report) == set()
    assert report["completed"] is True


def test_components_are_reported_with_their_counts(scan, page):
    page.wordpress_org.answers.update(tool_answers()())
    report = scan(craft_zip([*site(), *tool_files({"readme.txt": b"changed\n"})]))
    tool = next(component for component in report["components"] if component["name"] == "tool")
    listed = len(TOOL_RELEASE)
    assert (tool["state"], tool["files"], tool["matched"], tool["modified"]) == ("listed", listed, listed - 1, 1)


def test_md5_matches_the_rfc_1321_vectors(page, site_url):
    page.goto(site_url)
    digests = page.evaluate("""async (vectors) => {
      const { createMd5 } = await import('/scanner/md5.js');
      const encoder = new TextEncoder();
      return vectors.map((text) => {
        const md5 = createMd5();
        md5.add(encoder.encode(text));
        return md5.hex();
      });
    }""", list(MD5_VECTORS))
    assert digests == list(MD5_VECTORS.values())


def test_md5_in_pieces_equals_md5_of_the_whole(page, site_url):
    """The hashing of large files feeds pieces of odd sizes; a view into a larger buffer must
    count only its own bytes."""
    page.goto(site_url)
    whole = bytes((index * 131 + 7) % 256 for index in range(300_001))
    digest = page.evaluate("""async (numbers) => {
      const { createMd5 } = await import('/scanner/md5.js');
      const bytes = new Uint8Array(numbers);
      const md5 = createMd5();
      for (let at = 0; at < bytes.length; at += 65_537) md5.add(bytes.subarray(at, at + 65_537));
      return md5.hex();
    }""", list(whole))
    assert digest == hashlib.md5(whole, usedforsecurity=False).hexdigest()
