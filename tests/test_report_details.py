"""What a finding carries besides its rule and path: the line of the file it points at, and the
SHA-256 of a file that came out red."""
import hashlib

from playwright.sync_api import Page

from samples import JPEG, MU_PLUGIN, PHP_STATEMENT, PROGRAM, ROOT, SAMPLES_BY_NAME, UPLOADS, code, program_as_photo_zip, site
from zipcraft import Member, craft_zip

HANDLER_LINE = "AddHandler application/x-httpd-php .gif"
EXCERPT_LIMIT = 202
ONE_LONG_LINE = "$padding = '" + "a" * 5000 + "'; exec($target); $rest = '" + "b" * 5000 + "';"
PROTOCOL_BREAKING_HASH = "{ type: 'hashes', files: [{ path: 'photo.jpeg', sha256: 'not a hash', findings: ['photo.jpeg'] }] }"


def excerpts(report: dict) -> dict[str, str]:
    return {found["rule"]: found["params"].get("excerpt", "") for found in report["findings"]}


def test_a_code_finding_shows_its_line(scan):
    report = scan(SAMPLES_BY_NAME["launch_path[exec]"].build())
    assert excerpts(report) == {"loaded.launch_call": "@exec($target, $out, $code);"}


def test_a_settings_finding_shows_its_line(scan):
    settings = f"# media\n  {HANDLER_LINE}  \n".encode()
    report = scan(craft_zip([*site(), Member(UPLOADS + ".htaccess", settings)]))
    assert excerpts(report) == {"config.php_handler": HANDLER_LINE}


def test_a_long_line_is_shown_as_a_window_around_the_place(scan):
    """Packed code is one line of many kilobytes; the whole line would bury the call."""
    report = scan(craft_zip([*site(), Member(MU_PLUGIN, code(ONE_LONG_LINE))]))
    shown = excerpts(report)["loaded.launch_call"]
    assert "exec($target);" in shown
    assert shown.startswith("…") and shown.endswith("…")
    assert len(shown) <= EXCERPT_LIMIT


def test_an_excerpt_keeps_letters_outside_ascii(scan):
    report = scan(craft_zip([*site(), Member(MU_PLUGIN, code("exec($target); // zażółć gęślą jaźń"))]))
    assert excerpts(report)["loaded.launch_call"] == "exec($target); // zażółć gęślą jaźń"


def hashed(path: str, body: bytes, findings: list[str]) -> dict:
    return {"path": path, "sha256": hashlib.sha256(body).hexdigest(), "findings": findings}


def rule_paths(report: dict) -> set[tuple[str, str]]:
    return {(found["rule"], found["path"]) for found in report["findings"]}


def loose_php_examples(report: dict) -> dict[str, str]:
    return {found["path"]: found["params"]["example"] for found in report["findings"] if found["rule"] == "layout.php_outside_code_folders"}


def shown_hash(page: Page, row_text: str) -> str:
    return page.locator('[data-scanner="findings"] > .finding', has_text=row_text).locator(".finding-hash").text_content()


def sha256_label(body: bytes) -> str:
    return "SHA-256 " + hashlib.sha256(body).hexdigest()


def test_red_files_are_hashed(scan):
    report = scan(SAMPLES_BY_NAME["dropper"].build())
    mockup = UPLOADS + "product-detail-mockup.jpeg"
    assert report["hashes"] == [hashed(mockup, PROGRAM, [mockup])]


def test_a_copy_without_red_has_no_hashes(scan):
    assert scan(SAMPLES_BY_NAME["clean"].build())["hashes"] == []


def test_a_red_file_inside_an_archive_gives_the_hash_of_that_archive(scan):
    """The visitor can find the zip in the copy; the file inside it has no path of its own."""
    pack = program_as_photo_zip()
    report = scan(craft_zip([*site(), Member(UPLOADS + "pack.zip", pack)]))
    assert report["hashes"] == [hashed(UPLOADS + "pack.zip", pack, [UPLOADS + "pack.zip » mockup.jpeg"])]


def test_a_part_of_wp_content_is_reported_under_the_names_it_holds(scan, page):
    """A part of a split backup is checked with wp-content/ in front of its names. Everything the
    visitor reads names the files as the zip holds them: findings, examples, the list of code
    WordPress loads by itself, the hashes, archives inside it and the database dumps in the log."""
    pack = program_as_photo_zip()
    report = scan(craft_zip([
        Member("mu-plugins/loader.php", code("shell_exec($target);")),
        Member("cache-settings.php", PHP_STATEMENT),
        Member("cache/old/settings.php", PHP_STATEMENT),
        Member("uploads/2025/12/pack.zip", pack),
        Member("backup.sql", b"INSERT INTO `wp_options` VALUES (1,'siteurl','https://example.com','yes');\n"),
    ]))
    assert [loaded["path"] for loaded in report["loadedCode"]["files"]] == ["mu-plugins/loader.php"]
    assert {hash_record["path"] for hash_record in report["hashes"]} == {"mu-plugins/loader.php", "uploads/2025/12/pack.zip"}
    assert loose_php_examples(report) == {"./": "cache-settings.php", "cache/": "cache/old/settings.php"}
    assert ("layout.disguised_executable", "uploads/2025/12/pack.zip » mockup.jpeg") in rule_paths(report)
    log = page.locator('[data-scanner="log"]').inner_text()
    assert "backup.sql" in log and "wp-content/" not in log


def test_names_with_dot_segments_are_reported_as_written(scan):
    """Every check reads "uploads/./pack.zip" as unpackers write it, uploads/pack.zip; the report
    names it as the zip holds it, also as the outer half of a finding inside it, and as the
    example of loose PHP."""
    pack = program_as_photo_zip()
    report = scan(craft_zip([
        *site(),
        Member(UPLOADS + "./pack.zip", pack),
        Member(ROOT + "wp-content/./cache/old/settings.php", PHP_STATEMENT),
    ]))
    assert report["hashes"] == [hashed(UPLOADS + "./pack.zip", pack, [UPLOADS + "./pack.zip » mockup.jpeg"])]
    assert ("layout.disguised_executable", UPLOADS + "./pack.zip » mockup.jpeg") in rule_paths(report)
    assert loose_php_examples(report) == {ROOT + "wp-content/cache/": ROOT + "wp-content/./cache/old/settings.php"}


def test_a_decoy_named_like_a_finding_inside_an_archive_does_not_take_its_hash(scan):
    """A picture named "pack.zip » mockup.jpeg" lies beside pack.zip. The red finding inside
    pack.zip names pack.zip, so the hash is pack.zip's, not the decoy's."""
    pack = program_as_photo_zip()
    report = scan(craft_zip([*site(), Member(UPLOADS + "pack.zip", pack), Member(UPLOADS + "pack.zip » mockup.jpeg", JPEG)]))
    assert report["hashes"] == [hashed(UPLOADS + "pack.zip", pack, [UPLOADS + "pack.zip » mockup.jpeg"])]


def test_an_archive_named_with_the_separator_is_hashed_and_named_as_written(scan, page):
    """With an entry "a" and an archive "a » b/./pack.zip", the finding inside the archive names
    the archive as the zip writes it, and its row on the page shows that archive's hash."""
    pack = program_as_photo_zip()
    report = scan(craft_zip([*site(), Member("./a", JPEG), Member("a » b/./pack.zip", pack)]))
    inside = "a » b/./pack.zip » mockup.jpeg"
    assert report["hashes"] == [hashed("a » b/./pack.zip", pack, [inside])]
    assert ("layout.disguised_executable", inside) in rule_paths(report)
    assert shown_hash(page, "mockup.jpeg") == sha256_label(pack)


def test_a_red_file_named_like_a_finding_inside_an_archive_keeps_its_own_hash(scan, page):
    """A red PHP file named "photo.jpeg » shell.php" lies beside an honest photo.jpeg. Its row
    shows its own hash, not the photo's."""
    shell = code("shell_exec($target);")
    report = scan(craft_zip([*site(), Member(UPLOADS + "photo.jpeg", JPEG), Member(UPLOADS + "photo.jpeg » shell.php", shell)]))
    named = UPLOADS + "photo.jpeg » shell.php"
    assert report["hashes"] == [hashed(named, shell, [named])]
    assert shown_hash(page, "shell.php") == sha256_label(shell)


def test_a_finding_inside_an_archive_shows_the_archive_hash_beside_a_red_entry_it_starts_with(scan, page):
    """A red "x.php" and an archive "x.php » pack.zip": the row of the file inside the archive
    shows the archive's hash."""
    shell = code("shell_exec($target);")
    pack = program_as_photo_zip()
    scan(craft_zip([*site(), Member(UPLOADS + "x.php", shell), Member(UPLOADS + "x.php » pack.zip", pack)]))
    assert shown_hash(page, "mockup.jpeg") == sha256_label(pack)


def test_a_red_path_two_files_share_shows_no_hash(scan):
    """A program named "pack.zip » mockup.jpeg" beside a pack.zip holding a program named
    mockup.jpeg: both findings have one path, and neither file's hash is the row's."""
    report = scan(craft_zip([
        *site(), Member(UPLOADS + "pack.zip", program_as_photo_zip()), Member(UPLOADS + "pack.zip » mockup.jpeg", PROGRAM),
    ]))
    assert ("layout.disguised_executable", UPLOADS + "pack.zip » mockup.jpeg") in rule_paths(report)
    assert report["hashes"] == []


def test_a_red_file_named_like_an_entry_is_shown_as_written(scan):
    """An entry "./a." lands on "a", and "a » b/./shell.php" on "a » b/shell.php". The finding on
    the second is shown under its own written name, not glued to the written name of the first.
    The folder "a » b/" it lies in is no entry, and is read as a name inside "a" (a limit in docs/rules.md)."""
    report = scan(craft_zip([*site(), Member("./a.", JPEG), Member("a » b/./shell.php", code("shell_exec($target);"))]))
    assert ("unproven.launch_call", "a » b/./shell.php") in rule_paths(report)


def test_two_files_under_one_name_are_not_hashed(scan):
    """Which of the two lands on disk depends on the unzip program, so neither hash is 'the' file's."""
    twice = ROOT + "wp-content/uploads/twice.jpeg"
    report = scan(craft_zip([*site(), Member(twice, PROGRAM), Member(twice, PROGRAM + b"\x01")]))
    assert any(found["rule"] == "zip.duplicate_name" for found in report["findings"])
    assert report["hashes"] == []


def test_a_worker_sending_a_bad_hash_ends_the_scan(scan, page):
    page.route("**/scanner/worker.js", lambda route: route.fulfill(
        status=200, content_type="text/javascript",
        body=f"self.addEventListener('message', () => self.postMessage({PROTOCOL_BREAKING_HASH}));",
    ))
    report = scan(craft_zip(site()))
    assert [found["rule"] for found in report["findings"]] == ["scan.failed"]
