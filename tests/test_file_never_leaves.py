"""The promise on the page: nothing from the visitor's file leaves the browser.

A marker that occurs nowhere else is planted in a file name, in PHP code and in the database
dump. Every request of the whole scan is recorded, from page load to report, and none may
carry the marker in its address, headers or body, or go to a host outside the four the page
names. Two positive controls stand next to it: the marker reached the page (it is in the
report), and the recording works (each of the three outside hosts was asked something).
"""
from urllib.parse import urlsplit

from playwright.sync_api import Request

from samples import PROGRAM, UPLOADS, site_with, tool_answers, tool_files
from zipcraft import Member

# Hex only, so URL encoding cannot change how it reads.
MARKER = "c0ffee5ca7f00dba11ad0e5"
OUTSIDE_HOSTS = {"api.wordpress.org", "downloads.wordpress.org", "www.wpvulnerability.net"}
DUMP = f"""INSERT INTO `wp_options` VALUES (1,'active_plugins','a:0:{{}}','yes');
INSERT INTO `wp_posts` VALUES (7,'<script src="https://{MARKER}.example/tag.js"></script>');
""".encode()


def build_marked_copy() -> bytes:
    return site_with(
        *tool_files(),
        Member(UPLOADS + f"invoice-{MARKER}.jpg", PROGRAM),
        Member("files/wp-content/mu-plugins/loader.php", f"<?php\nexec('{MARKER}');\n".encode()),
        Member("files/database.sql", DUMP),
    )()


def describe(request: Request) -> str:
    """Everything a request could carry the marker in."""
    headers = " ".join(f"{name}: {value}" for name, value in request.headers.items())
    return f"{request.url}\n{headers}\n{request.post_data or ''}"


def test_nothing_from_the_file_leaves_the_browser(page, scan):
    page.wordpress_org.answers.update(tool_answers()())
    recorded: list[Request] = []
    page.context.on("request", lambda request: recorded.append(request))

    report = scan(build_marked_copy())

    marked_findings = [found for found in report["findings"] if MARKER in f"{found['path']} {found['params']}"]
    assert {found["rule"] for found in marked_findings} >= {
        "layout.disguised_executable", "db.external_script_host",
    }, "the marker never reached the page, so the test would prove nothing"
    page_host = urlsplit(page.url).hostname
    # WebKit 26.5 records the page's reads of the visitor's file as requests to blob: addresses
    # of the page's own origin. They never leave the browser; any other address without a host
    # still fails below.
    own_blobs = f"blob:{page.url.rstrip('/')}/"
    network = [request for request in recorded if not request.url.startswith(own_blobs)]
    hosts = {urlsplit(request.url).hostname for request in network}
    others = sorted(request.url[:200] for request in network if urlsplit(request.url).hostname not in {page_host} | OUTSIDE_HOSTS)
    assert hosts == {page_host} | OUTSIDE_HOSTS, others
    leaks = [request.url for request in recorded if MARKER in describe(request)]
    assert leaks == []
