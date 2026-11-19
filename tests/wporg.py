"""A stand-in for wordpress.org and wpvulnerability.net in the tests.

The page builds its addresses from fixed templates; the same templates are written out here,
and every address is answered the way the real hosts answered on 2026-11-13 (measured with
curl and a browser): the checksum host returns a 404 WITHOUT a CORS header for an unknown
plugin or version, which a browser cannot read; the plugin directory answers both ways with
CORS; wpvulnerability.net answers an unknown name or version with 200 and `"vulnerability":
null`. No test request ever leaves the machine.
"""
import hashlib
import json
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from urllib.parse import quote, urlsplit

from playwright.sync_api import BrowserContext, Route

HOSTS = ("https://api.wordpress.org/**", "https://downloads.wordpress.org/**", "https://www.wpvulnerability.net/**")
INFO_FIELDS_OFF = "".join(
    f"&request[fields][{field}]=0"
    for field in ("sections", "versions", "reviews", "screenshots", "banners", "icons", "contributors", "tags", "description", "ratings")
)
CORE_CHECKSUMS_PREFIX = "https://api.wordpress.org/core/checksums/1.0/"
PLUGIN_CHECKSUMS_PREFIX = "https://downloads.wordpress.org/plugin-checksums/"
PLUGIN_INFO_PREFIX = "https://api.wordpress.org/plugins/info/1.2/"
VULNERABILITY_PREFIX = "https://www.wpvulnerability.net/"
VULNERABILITY_HOST = "www.wpvulnerability.net"


def _component(text: str) -> str:
    """The same escaping as JavaScript's encodeURIComponent."""
    return quote(text, safe="-_.!~*'()")


def core_checksums_url(version: str, locale: str) -> str:
    return f"{CORE_CHECKSUMS_PREFIX}?version={_component(version)}&locale={_component(locale)}"


def plugin_checksums_url(slug: str, version: str) -> str:
    return f"{PLUGIN_CHECKSUMS_PREFIX}{_component(slug)}/{_component(version)}.json"


def plugin_info_url(slug: str) -> str:
    return f"{PLUGIN_INFO_PREFIX}?action=plugin_information&request[slug]={_component(slug)}{INFO_FIELDS_OFF}"


def core_vulnerabilities_url(version: str) -> str:
    return f"{VULNERABILITY_PREFIX}core/{_component(version)}/"


def plugin_vulnerabilities_url(slug: str) -> str:
    return f"{VULNERABILITY_PREFIX}plugin/{_component(slug)}/"


def theme_vulnerabilities_url(slug: str) -> str:
    return f"{VULNERABILITY_PREFIX}theme/{_component(slug)}/"


@dataclass(frozen=True)
class Answer:
    status: int
    body: bytes
    cors: bool = True


def as_json(document: object, status: int = 200) -> Answer:
    return Answer(status, json.dumps(document).encode())


# wordpress.org publishes core checksums in MD5 only; here MD5 is a file format, not a safeguard.
def core_list(files: Mapping[str, bytes]) -> Answer:
    return as_json({"checksums": {path: hashlib.md5(body, usedforsecurity=False).hexdigest() for path, body in files.items()}})


def plugin_list(slug: str, version: str, files: Mapping[str, bytes]) -> Answer:
    listed = {
        path: {"md5": hashlib.md5(body, usedforsecurity=False).hexdigest(), "sha256": hashlib.sha256(body).hexdigest()}
        for path, body in files.items()
    }
    return as_json({"plugin": slug, "version": version, "source": "", "zip": "", "files": listed})


def plugin_found(slug: str) -> Answer:
    return as_json({"name": slug.title(), "slug": slug, "version": "9.9"})


def plugin_closed(slug: str) -> Answer:
    return as_json(
        {"error": "closed", "slug": slug, "closed": True, "closed_date": "2021-01-30", "reason": "security-issue"},
        status=404,
    )


def vulnerability(
    max_version: str | None,
    max_operator: str | None = "lt",
    *,
    min_version: str | None = None,
    min_operator: str | None = None,
    unfixed: bool = False,
    sources: Sequence[tuple[str, str]] = (("CVE-2025-10001", "https://www.cve.org/CVERecord?id=CVE-2025-10001"),),
    score: str | None = "6.4",
    cwe: tuple[str, str] | None = ("CWE-79", "Cross-site Scripting"),
) -> dict:
    """One entry in the shape wpvulnerability.net uses for plugins and themes (measured 2026-11-13).
    `sources` holds (id, link) pairs; Wordfence and Patchstack ids are 40 hex digits."""
    impact: dict | list = {}
    if score is not None:
        impact["cvss3"] = {"version": "3.1", "score": score, "severity": "medium"}
    if cwe is not None:
        impact["cwe"] = [{"cwe": cwe[0], "name": cwe[1], "description": "Sample text that is never shown."}]
    return {
        "uuid": hashlib.sha256(repr((max_version, min_version, sources)).encode()).hexdigest(),
        "name": "Sample entry",
        "description": None,
        "operator": {
            "min_version": min_version, "min_operator": min_operator, "max_version": max_version, "max_operator": max_operator,
            "unfixed": "1" if unfixed else "0", "closed": "0",
        },
        "source": [
            {"id": source_id, "name": "Sample", "link": link, "description": "Sample text that is never shown.", "date": "2025-01-01"}
            for source_id, link in sources
        ],
        "impact": impact or [],
    }


def vulnerability_list(kind: str, name: str, entries: Sequence[dict]) -> Answer:
    """A wpvulnerability.net answer for a plugin, a theme or (kind "core", name = version) the core."""
    if kind == "core":
        advisory_record = {"core": name, "link": None, "vulnerability": [_without_range(entry) for entry in entries] or None}
    else:
        advisory_record = {"name": name.title(), kind: name, "link": None, "latest": None, "closed": 0, "closed_reason": None,
                "closed_date": None, "vulnerability": list(entries) or None}
    return as_json({"error": 0, "message": None, "data": advisory_record, "updated": "1794466907"})


def _without_range(entry: dict) -> dict:
    """Core entries have no operator block."""
    return {key: value for key, value in entry.items() if key != "operator"}


NO_CORE_LIST = as_json({"checksums": False})
PLUGIN_NOT_FOUND = as_json({"error": "Plugin not found."}, status=404)
NOT_FOUND_WITHOUT_CORS = Answer(404, b"Not found", cors=False)


class FakeWordPressOrg:
    """Answers the three hosts the page may call. `answers` maps an exact address to its answer;
    anything else gets what the real host gives an unknown name. `requested` records every
    address asked for, in order. `unreachable` cuts all three hosts, `unreachable_hosts` some."""

    def __init__(self) -> None:
        self.answers: dict[str, Answer] = {}
        self.requested: list[str] = []
        self.unreachable = False
        self.unreachable_hosts: set[str] = set()
        self.delay_seconds = 0.0

    def attach(self, context: BrowserContext) -> None:
        for pattern in HOSTS:
            context.route(pattern, self._answer)

    def _answer(self, route: Route) -> None:
        url = route.request.url
        self.requested.append(url)
        time.sleep(self.delay_seconds)
        if self.unreachable or urlsplit(url).hostname in self.unreachable_hosts:
            route.abort("internetdisconnected")
            return
        answer = self.answers.get(url) or _unknown_name_answer(url)
        if not answer.cors:
            # A fulfilled response skips the browser's CORS check (seen in Chromium 151), while
            # the real answer without the header makes fetch() fail. Failing it is the faithful copy.
            route.abort("failed")
            return
        headers = {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"}
        route.fulfill(status=answer.status, headers=headers, body=answer.body)


def _unknown_name_answer(url: str) -> Answer:
    if url.startswith(CORE_CHECKSUMS_PREFIX):
        return NO_CORE_LIST
    if url.startswith(PLUGIN_INFO_PREFIX):
        return PLUGIN_NOT_FOUND
    if url.startswith(VULNERABILITY_PREFIX):
        kind, name = url.removeprefix(VULNERABILITY_PREFIX).strip("/").split("/", 1)
        return vulnerability_list(kind, name, [])
    return NOT_FOUND_WITHOUT_CORS
