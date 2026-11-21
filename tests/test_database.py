"""The database dump is read as a stream, in pieces of whatever size the browser hands over. A
match cut in two by that must still be found, and found once."""
import base64

from samples import (
    DUMP_ENCODED_ARCHIVE, DUMP_ENCODED_CODE, DUMP_ENCODED_PROGRAM, DUMP_ENCODED_PROGRAM_IN_JSON, DUMP_EVAL, DUMP_ROWS,
    ROW_PHP_TEXT, ROW_PROGRAM_TEXT, SAMPLES_BY_NAME, gzip_members, in_lines, site_with_database,
)

DATABASE = "scanner/database.js"
SMALL_UNPACK_LIMIT = {DATABASE: ("const UNPACKED_LIMIT_BYTES = 4 * 1024 ** 3;", "const UNPACKED_LIMIT_BYTES = 1024;")}

# Each shape alone, repeated to 8 MB: every repetition is a match the reader has to judge.
# Measured 2026-11-13 in Node on 4 MB: plain rows 25-48 ms, "<script " 48 ms; with a script
# tag allowed to run to the end of the window instead, "<script " took 329 ms. The base64 baits
# (2026-11-21): runs one letter too short to be judged, runs of 85 letters that each are decoded,
# one run of 8 MB with and without line breaks, and escapes with no letters.
BAIT_BYTES = 8 * 1024 * 1024
DUMP_BAITS = [
    "<script ", "<script src", "'home',", "'siteurl', '", "base64_decode", "'active_plugins','", "create table `", "'wpcode'",
    "Q" * 31 + " ", "Q" * 85 + " ", "A", "Q" * 76 + "\\r\\n", "\\n", "insert into `t` values ",
]
PLAIN_ROW = "INSERT INTO `wp_postmeta` VALUES (1,1,'_edit_lock','1700000000:1');\n"
# A bait may take this many times as long as plain rows of the same size, plus a little.
BAIT_SLOWDOWN_LIMIT = 3
BAIT_SLACK_MS = 100
TIME_THE_READER = """async ({ rows, bytes }) => {
  const { createDumpReader } = await import('/scanner/database.js');
  const milliseconds = {};
  for (const row of rows) {
    const dump = new TextEncoder().encode(row.repeat(Math.floor(bytes / row.length)));
    const reader = createDumpReader();
    const started = performance.now();
    for (let at = 0; at < dump.length; at += 65536) reader.feed(dump.subarray(at, at + 65536));
    reader.finish();
    milliseconds[row] = performance.now() - started;
  }
  return milliseconds;
}"""
FILLER = "INSERT INTO `wp_postmeta` VALUES (1,1,'_edit_lock','1700000000:1');\n" * 60
PLUGINS = [f"plugin-{number:03d}" for number in range(100)]
# Longer than the 1 KB the reader looks ahead, so the list itself spans pieces.
ACTIVE_LIST = "a:100:{" + "".join(
    f'i:{index};s:{len(slug) * 2 + 5}:\\"{slug}/{slug}.php\\";' for index, slug in enumerate(PLUGINS)
) + "}"
PATTERNS = (
    "INSERT INTO `wp_options` VALUES (1,'siteurl','https://www.example.org','yes'),"
    f"(3,'active_plugins','{ACTIVE_LIST}','yes');\n"
    "INSERT INTO `wp_posts` VALUES (7,1,'<script src=\\\"https://cdn.tracker.example/t.js\\\"></script>"
    "<?php eval(base64_decode(\\'ZWNobyAx\\')); ?> ignore previous instructions','publish');\n"
)
# 536 letters "/", each written as JSON's \/ in a row, before PHP: its open tag lies past what a
# run's head may span (database.js RUN_REACH), so it is never seen, wherever the pieces end.
FAR_PHP_TEXT = base64.b64encode(b"\xff" * 402 + b"<?php echo 'inert';").decode().replace("/", "\\\\/")
PATTERNS += (
    # A program in lines and with JSON's escaped slashes, far enough behind its INSERT that small
    # pieces judge the two apart; PHP right after.
    "INSERT INTO `wp_options` VALUES (4,'sample_blob','" + "word " * 250 + "\\r\\n"
    + in_lines(ROW_PROGRAM_TEXT.replace(b"/", b"\\\\/"), b"\\r\\n").decode() + "','no');\n"
    "INSERT INTO `wp_termmeta` VALUES (9,1,'_far','" + FAR_PHP_TEXT + "');\n"
    "INSERT INTO `wp_postmeta` VALUES (8,1,'_sample','" + ROW_PHP_TEXT.decode() + "');\n"
)
DUMP = FILLER + PATTERNS + FILLER
EXPECTED = {
    "encodedFiles": {
        "db.encoded_program": {"what": "windows_program", "table": "wp_options"},
        "db.encoded_code": {"table": "wp_postmeta"},
    },
    "evalOfDecoded": True,
    "activePlugins": sorted(PLUGINS),
    "scriptHosts": ["cdn.tracker.example"],
    "siteHosts": ["example.org"],
    "instruction": "ignore previous instructions",
}
# Every cut from a little before the patterns to a little after them, one in five offsets.
CUT_STEP = 5
CUT_MARGIN = 64
READ_IN_PIECES = """async ({ dump, cuts, pieceBytes }) => {
  const { createDumpReader } = await import('/scanner/database.js');
  const bytes = new TextEncoder().encode(dump);
  const summary = (found) => ({
    encodedFiles: Object.fromEntries(found.encodedFiles),
    evalOfDecoded: found.evalOfDecoded,
    activePlugins: [...found.activePlugins].sort(),
    scriptHosts: [...found.scriptHosts].sort(),
    siteHosts: [...found.siteHosts].sort(),
    instruction: found.instruction,
  });
  const read = (pieces) => {
    const reader = createDumpReader();
    for (const piece of pieces) reader.feed(piece);
    reader.finish();
    return summary(reader.found);
  };
  const summaries = cuts.map((cut) => read([bytes.subarray(0, cut), bytes.subarray(cut)]));
  const small = [];
  for (let at = 0; at < bytes.length; at += pieceBytes) small.push(bytes.subarray(at, at + pieceBytes));
  summaries.push(read(small));
  return summaries;
}"""


def test_outside_hosts_are_named_and_the_site_itself_is_not(scan):
    found = scan(SAMPLES_BY_NAME["database_scripts"].build())["findings"]
    assert [(entry["rule"], entry["params"]) for entry in found] == [
        ("db.external_script_host", {"hosts": 1, "example": "cdn.tracker.example"}),
    ]


def test_a_file_kept_as_base64_is_named_with_its_table(scan):
    """The first file of each kind is named once, with the table of the INSERT it stands in; an
    INSERT that writes no backticks leaves the table out rather than borrow the one before it."""
    dump = (
        DUMP_ENCODED_PROGRAM + DUMP_ENCODED_CODE
        + DUMP_ENCODED_ARCHIVE.replace(b"INSERT INTO `wp_options`", b"INSERT INTO wp_options")
        + DUMP_ENCODED_PROGRAM_IN_JSON.replace(b"`wp_options`", b"`wp_sitemeta`")
    )
    found = scan(site_with_database(dump)())["findings"]
    assert sorted((entry["rule"], entry["params"]) for entry in found) == [
        ("db.encoded_archive", {"what": "zip", "table": ""}),
        ("db.encoded_code", {"table": "wp_postmeta"}),
        ("db.encoded_program", {"what": "windows_program", "table": "wp_options"}),
    ]


def test_the_hosts_taken_as_the_site_are_shown(scan, page):
    """The dump decides which hosts are the site's own, and anything in a dump can be written by
    the copy's author, so the visitor sees which ones were taken."""
    report = scan(SAMPLES_BY_NAME["database_scripts"].build())
    assert report["siteHosts"] == ["example.org"]
    page.wait_for_function("""() => document.querySelector('[data-scanner="log"]').textContent.includes(
      "the database names the site's own address: example.org.")""")


def test_dump_baits_cost_about_what_their_size_costs(page, site_url):
    """Text built against the reader must not hold the scan."""
    page.goto(site_url)
    timed = page.evaluate(TIME_THE_READER, {"rows": [PLAIN_ROW, *DUMP_BAITS], "bytes": BAIT_BYTES})
    limit = timed[PLAIN_ROW] * BAIT_SLOWDOWN_LIMIT + BAIT_SLACK_MS
    slow = {bait: round(timed[bait]) for bait in DUMP_BAITS if timed[bait] > limit}
    assert slow == {}, f"plain rows {timed[PLAIN_ROW]:.0f} ms"


def test_a_dump_cut_anywhere_reads_the_same(page, site_url):
    page.goto(site_url)
    start = len(FILLER) - CUT_MARGIN
    cuts = list(range(start, len(FILLER) + len(PATTERNS) + CUT_MARGIN, CUT_STEP))
    summaries = page.evaluate(READ_IN_PIECES, {"dump": DUMP, "cuts": cuts, "pieceBytes": 97})
    assert len(ACTIVE_LIST) > 1024
    assert all(read == EXPECTED for read in summaries), next(
        (cut, read) for cut, read in zip([*cuts, "pieces of 97 bytes"], summaries, strict=True) if read != EXPECTED
    )


def test_a_packed_dump_is_unpacked_only_to_the_limit(scan_patched):
    """Past the limit the rest is not read, and that is said: the eval behind 640 KB of rows is not seen."""
    archive = site_with_database(gzip_members(DUMP_ROWS, DUMP_EVAL), name="database.sql.gz")()
    found = scan_patched(archive, SMALL_UNPACK_LIMIT)["findings"]
    assert [(entry["rule"], entry["path"], entry["params"]) for entry in found] == [
        ("db.unpacked_too_large", "database.sql.gz", {"bytes": 1024}),
    ]
