"""One large file can take longer to read than the page waits in silence (the end of
a 1 GB film took 1.2 s, and the page gives up after 10 s, less on a slow disk). The reading loops
say they are alive in between, and the page does not take the wait for a stall."""
import base64
import re

from conftest import finding_keys
from samples import UPLOADS, packed_zeros, site
from serve import site_root
from zipcraft import Member, craft_zip

FILM = UPLOADS + "film.mp4"
FILM_ZERO_BYTES = 1024 * 1024 * 1024
STALL_LIMIT_IN_TEST_MS = 400
# The watchdog looks once a second; a silence of 400-1,400 ms could fall between two looks.
QUICK_WATCHDOG = {
    "scanner/main.js": (
        "const STALL_LIMIT_MS = 10_000;\nconst WATCHDOG_INTERVAL_MS = 1000;",
        f"const STALL_LIMIT_MS = {STALL_LIMIT_IN_TEST_MS};\nconst WATCHDOG_INTERVAL_MS = 20;",
    ),
    "scanner/engine.js": ("const HEARTBEAT_INTERVAL_MS = 1_000;", "const HEARTBEAT_INTERVAL_MS = 50;"),
}
# The page has to hear from a long read several times before it would give up on it.
HEARTBEATS_PER_STALL_LIMIT = 4
BIG_FILE_BYTES = 8 * 1024 * 1024
COUNT_HEARTBEATS = """async (archiveBase64) => {
  const { openZip } = await import('/scanner/zip-reader.js');
  const { ArchiveSource, locateData, readThrough, streamWholeFile } = await import('/scanner/entries.js');
  const blob = new Blob([Uint8Array.from(atob(archiveBase64), (char) => char.charCodeAt(0))]);
  const archive = await openZip(blob);
  let calls = 0;
  const container = { source: new ArchiveSource(blob), archive, alive: () => { calls += 1; } };
  const entry = archive.entries.find((found) => found.name === 'big.bin');
  const failure = await streamWholeFile(container, entry, () => {});
  const whole = calls;
  calls = 0;
  const located = await locateData(container, entry, { wantPacked: 0, readAhead: 0 });
  const dataStart = entry.headerOffset + located.header.headerBytes;
  const { tail } = await readThrough(container, { entry, dataStart }, { tailBytes: 64, deadline: Infinity, inspect: () => {} });
  return { failure, whole, tailLength: tail.length, tail: calls };
}"""


def constant_ms(file: str, name: str) -> int:
    source = (site_root() / file).read_text(encoding="utf-8")
    return int(re.search(rf"const {name} = ([\d_]+);", source).group(1).replace("_", ""))


def test_both_long_reading_loops_say_they_are_alive(page, site_url):
    page.goto(site_url)
    archive = craft_zip([Member("big.bin", b"\x00" * BIG_FILE_BYTES)])

    counted = page.evaluate(COUNT_HEARTBEATS, base64.b64encode(archive).decode())

    assert (counted["failure"], counted["tailLength"]) == ("", 64)
    assert counted["whole"] > 0
    assert counted["tail"] > 0


def test_one_long_read_does_not_end_the_scan(scan_patched):
    packed, sizes = packed_zeros(b"", FILM_ZERO_BYTES)
    report = scan_patched(craft_zip([*site(), Member(FILM, packed=packed, local=sizes, central=sizes)]), QUICK_WATCHDOG)

    # Otherwise the read was too quick to prove anything.
    assert report["stats"]["milliseconds"] > STALL_LIMIT_IN_TEST_MS
    assert report["completed"] is True
    assert finding_keys(report) == set()


def test_the_heartbeat_comes_well_inside_the_stall_limit():
    stall_limit = constant_ms("scanner/main.js", "STALL_LIMIT_MS")
    heartbeat = constant_ms("scanner/engine.js", "HEARTBEAT_INTERVAL_MS")
    assert heartbeat * HEARTBEATS_PER_STALL_LIMIT <= stall_limit
