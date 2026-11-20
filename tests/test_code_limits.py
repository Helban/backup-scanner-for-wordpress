"""Reading PHP as code: what the visitor is shown to read, and the limits that keep a file built
against the scanner from holding the scan."""
from conftest import finding_keys
from samples import (
    CODE_TOKEN_LIMIT, CORE_TRANSLATION, DROP_IN, LOCALE_FILE, MAINTENANCE_FILE, MU_PLUGIN, OWN_THEME, ROOT, SAMPLES_BY_NAME, code, site,
)
from zipcraft import Member, craft_zip

# The clock is read every 1024 steps; with no time left, the first reading stops the file.
NO_TIME_PER_FILE = {
    "scanner/engine.js": ("const CODE_FILE_TIME_MS = 2000;", "const CODE_FILE_TIME_MS = -1;"),
}
STEPS_PAST_ONE_CLOCK_READING = 4000
# Shapes that make a careless reader slow: work that grows with the square of the length, or
# one object per character. Each one alone stayed under 200 ms in Node on 2026-11-13.
STALL_BAITS = {
    "parentheses.php": b"<?php " + b"(" * (CODE_TOKEN_LIMIT + 2),
    "concatenation.php": b"<?php $a = " + b"'a'." * 300_000 + b"'a';",
    "spaces-in-string.php": b"<?php $a = '" + b" " * 4_000_000 + b"x';",
    "dots-and-spaces.php": b"<?php rename($a, '" + b". " * 2_000_000 + b"x');",
    "nested-renames.php": b"<?php " + b"rename($a, " * 100_000 + b"'b'" + b")" * 100_000 + b";",
    "nested-strrev.php": b"<?php $f = " + b"strrev(" * 50_000 + b"'x'" + b")" * 50_000 + b";",
    "open-heredoc.php": b"<?php $a = <<<EOT\n" + b"line $x {$y}\n" * 400_000,
    "comments-without-closing-tag.php": b"<?php " + b"/* x */ // y\n" * 400_000,
    "long-base64.php": b"<?php $f = base64_decode('" + b"QUFB" * 1_000_000 + b"');",
    "octal-escapes.php": b'<?php $a = "' + b"\\101" * 1_000_000 + b'";',
    # No closing brace anywhere: looking for one from every escape took 4.9 s for 1.9 MB.
    "unicode-escapes.php": b'<?php $a = "' + b"\\u{" * 2_000_000,
    # Every include looks for the end of its expression; a walk per include took 4 times as
    # long as plain code of the same size, and one shared bracket run walked per include would
    # be 90 billion steps.
    "includes.php": b"<?php " + b"include " * 990_000,
    "includes-before-brackets.php": b"<?php " + b"include " * 300_000 + b"(" * 300_000 + b"'x'" + b")" * 300_000 + b";",
    "braces-in-string.php": b'<?php $a = "' + b"{$b " * 300_000,
    "strings-in-strings.php": b"<?php $a = " + b'"{$b[' * 500_000,
}


# Server settings files are read line by line, every line cut to 4 KB before an expression sees
# it. Lines built to make the expressions backtrack, filling the 1 MB a settings file may have.
SETTINGS_BAIT_LINE = b"<FilesMatch " + b"> " * 2000 + b"x\n"
SETTINGS_BAITS = {
    "sections": SETTINGS_BAIT_LINE,
    "prepend": b"php_value auto_prepend_file " + b"\t" * 4000 + b"x\n",
    "redirect": b"RewriteRule " + b"https://" * 500 + b"\n",
}
SETTINGS_LIMIT_BYTES = 1024 * 1024
SETTINGS_TIME_LIMIT_MS = 2000

# PHP outside the code folders is first asked whether it holds only comments.
COMMENTS_ONLY = b"<?php\n" + b"//a\n" * 400_000
INERT_CHECK_TIME_LIMIT_MS = 2000


def test_settings_file_baits_do_not_hold_the_scan(scan):
    files = [
        Member(f"{ROOT}wp-content/uploads/{name}/.htaccess", line * (SETTINGS_LIMIT_BYTES // len(line)))
        for name, line in SETTINGS_BAITS.items()
    ]
    plain = scan(craft_zip(site()))
    report = scan(craft_zip([*site(), *files]))
    assert report["completed"] is True
    assert report["stats"]["milliseconds"] - plain["stats"]["milliseconds"] < SETTINGS_TIME_LIMIT_MS


def test_a_file_of_comments_does_not_hold_the_scan(scan):
    """One comment after another must not make the "only comments?" question take the square
    of the file's length: before the fix, 1.6 MB of them took seconds."""
    plain = scan(craft_zip(site()))
    report = scan(craft_zip([*site(), Member(ROOT + "wp-content/cache/notes.php", COMMENTS_ONLY)]))
    assert report["completed"] is True
    assert finding_keys(report) == set()
    assert report["stats"]["milliseconds"] - plain["stats"]["milliseconds"] < INERT_CHECK_TIME_LIMIT_MS


def test_every_always_loaded_file_is_listed_for_reading(scan):
    archive = craft_zip([
        *site(),
        Member(DROP_IN, b"<?php\n// page cache\n"),
        Member(OWN_THEME + "functions.php", b"<?php\n"),
    ])
    listed = scan(archive)["loadedCode"]
    assert listed["total"] == 3
    assert {(file["path"], file["name"]) for file in listed["files"]} == {
        (ROOT + "wp-config.php", ""),
        (ROOT + "wp-content/mu-plugins/site-preview.php", "Preview"),
        (DROP_IN, ""),
    }


def test_a_file_that_takes_too_long_is_named_and_the_scan_goes_on(scan_patched):
    slow = code("$a = 1;\n" * STEPS_PAST_ONE_CLOCK_READING)
    report = scan_patched(craft_zip([*site(), Member(OWN_THEME + "functions.php", slow)]), NO_TIME_PER_FILE)
    assert finding_keys(report) == {("not_checked", "code.time_limit", OWN_THEME + "functions.php")}
    assert report["completed"] is True


def test_always_loaded_code_that_takes_too_long_is_red(scan_patched):
    """WordPress runs a mu-plugin on every request, so one that could not be read in time is red,
    with the limit named."""
    slow = code("$a = 1;\n" * STEPS_PAST_ONE_CLOCK_READING)
    report = scan_patched(craft_zip([*site(), Member(MU_PLUGIN, slow)]), NO_TIME_PER_FILE)
    assert finding_keys(report) == {("red", "loaded.code_not_read", MU_PLUGIN)}
    assert [found["params"]["reason"] for found in report["findings"]] == ["time"]
    assert report["completed"] is True


def test_the_unpatched_scanner_reads_that_file(scan):
    """Control for the test above: with two seconds the same file is read to the end."""
    slow = code("$a = 1;\n" * STEPS_PAST_ONE_CLOCK_READING)
    report = scan(craft_zip([*site(), Member(MU_PLUGIN, slow)]))
    assert finding_keys(report) == set()


def test_stall_baits_do_not_hold_the_scan(scan):
    archive = craft_zip([*site(), *(Member(OWN_THEME + name, body) for name, body in STALL_BAITS.items())])
    report = scan(archive)
    assert report["completed"] is True
    assert finding_keys(report) == {
        ("not_checked", "code.too_large", OWN_THEME + "parentheses.php"),
        ("not_checked", "code.too_large", OWN_THEME + "strings-in-strings.php"),
    }


def test_the_token_limit_is_named_as_such(scan):
    report = scan(SAMPLES_BY_NAME["code_past_token_limit"].build())
    assert [found["params"]["reason"] for found in report["findings"]] == ["tokens"]


def test_the_nesting_limit_is_named_as_such(scan):
    report = scan(SAMPLES_BY_NAME["code_past_nesting_limit"].build())
    assert [found["params"]["reason"] for found in report["findings"]] == ["nesting"]


def test_the_size_limit_is_named_as_such(scan):
    report = scan(SAMPLES_BY_NAME["code_past_size_limit"].build())
    assert [found["params"]["reason"] for found in report["findings"]] == ["bytes"]


def test_always_loaded_code_past_a_limit_stays_listed_for_reading(scan):
    """Red, and still on the list of files WordPress loads by itself, translation file included."""
    listed = scan(SAMPLES_BY_NAME["always_loaded_code_past_limits"].build())["loadedCode"]
    assert {file["path"] for file in listed["files"]} >= {MAINTENANCE_FILE, DROP_IN, LOCALE_FILE, CORE_TRANSLATION}


def test_a_finding_names_the_line(scan):
    report = scan(SAMPLES_BY_NAME["launch_path[exec]"].build())
    assert [(found["params"]["what"], found["params"]["line"]) for found in report["findings"]] == [("exec", 6)]
