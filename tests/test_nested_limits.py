"""Archives inside the copy: every limit that stops the scanner must be named in the finding,
so the visitor knows why a file was left unread."""
import pytest

from conftest import finding_keys
from samples import ARCHIVE_HEADS, NESTED, NESTED_FILLERS, NESTED_NAMED_SKIPPED, NESTED_OPENED, NESTED_PACKS, PADDING, SAMPLES_BY_NAME, UPLOADS

ENGINE = "scanner/engine.js"
# A limit of -1 ms is already over when the clock is first read.
NO_TIME_PER_ARCHIVE = {ENGINE: ("const NESTED_ARCHIVE_TIME_MS = 10_000;", "const NESTED_ARCHIVE_TIME_MS = -1;")}
NO_TIME_IN_TOTAL = {ENGINE: ("const NESTED_TOTAL_TIME_MS = 60_000;", "const NESTED_TOTAL_TIME_MS = -1;")}
NO_TIME_FOR_TAILS = {ENGINE: ("const TAIL_TOTAL_TIME_MS = 60_000;", "const TAIL_TOTAL_TIME_MS = -1;")}
REASON_BY_SAMPLE = {
    "nested_two_levels": "depth",
    "nested_unpacks_past_limit": "too_large",
    "nested_bomb": "too_large",
    "nested_past_total_size": "budget_size",
    "archive_signature[zip]": "damaged",
    "archive_signature[rar]": "format",
}


def not_opened(report: dict) -> list[dict]:
    return [found for found in report["findings"] if found["rule"] == "archive.not_opened"]


@pytest.mark.parametrize("sample_name", REASON_BY_SAMPLE)
def test_the_finding_names_what_stopped_the_scanner(sample_name, scan):
    report = scan(SAMPLES_BY_NAME[sample_name].build())
    reasons = {found["params"]["reason"] for found in not_opened(report)}
    assert reasons == {REASON_BY_SAMPLE[sample_name]}


def test_an_unopened_archive_is_listed_with_kind_and_size(scan):
    report = scan(SAMPLES_BY_NAME["archive_signature[sevenzip]"].build())
    listed = {found["path"]: found["params"] for found in not_opened(report)}
    size = len(ARCHIVE_HEADS["sevenzip"][0] + PADDING)
    assert listed[UPLOADS + "pack.7z"] == {"kind": "sevenzip", "bytes": size, "reason": "format"}


def test_archives_past_the_count_are_named_then_grouped(scan):
    report = scan(SAMPLES_BY_NAME["nested_past_archive_count"].build())
    assert {found["params"]["reason"] for found in not_opened(report)} == {"budget_count"}
    groups = [found["params"] for found in report["findings"] if found["rule"] == "archive.not_opened_group"]
    grouped = NESTED_PACKS - NESTED_OPENED - NESTED_NAMED_SKIPPED
    assert [(group["extension"], group["files"], group["reason"]) for group in groups] == [(".zip", grouped, "budget_count")]
    assert report["counts"]["not_checked"] == NESTED_PACKS - NESTED_OPENED


def test_only_the_archive_past_the_total_size_is_left_out(scan):
    report = scan(SAMPLES_BY_NAME["nested_past_total_size"].build())
    assert [found["path"] for found in not_opened(report)] == [UPLOADS + f"filler-{NESTED_FILLERS}.zip"]


def test_a_nested_zip_that_takes_too_long_is_cut(scan_patched):
    report = scan_patched(SAMPLES_BY_NAME["nested_program_as_photo"].build(), NO_TIME_PER_ARCHIVE)
    assert finding_keys(report) == {("not_checked", "archive.not_opened", UPLOADS + "assets.zip")}
    assert not_opened(report)[0]["params"]["reason"] == "time"
    assert report["completed"] is True


def test_nested_zips_past_the_total_time_are_named(scan_patched):
    report = scan_patched(SAMPLES_BY_NAME["nested_program_as_photo"].build(), NO_TIME_IN_TOTAL)
    assert finding_keys(report) == {("not_checked", "archive.not_opened", UPLOADS + "assets.zip")}
    assert not_opened(report)[0]["params"]["reason"] == "budget_time"


def test_media_ends_past_the_time_allowed_are_counted(scan_patched):
    """A deflated picture is unpacked whole to reach its end; when the allowance for that runs
    out, the files left unread are counted instead of passing as checked."""
    sample = SAMPLES_BY_NAME["zip_behind_deflated_picture"]
    report = scan_patched(sample.build(), NO_TIME_FOR_TAILS)
    assert finding_keys(report) == {("not_checked", "archive.tail_not_checked", "")}
    [skipped] = [found["params"] for found in report["findings"] if found["rule"] == "archive.tail_not_checked"]
    # Only hero.jpg: the site's 68-byte photo is read whole together with its first bytes.
    assert skipped["files"] == 1
    assert report["completed"] is True


def test_a_stored_picture_out_of_time_still_shows_the_zip_behind_it(scan_patched):
    """The end of a file stored without packing can be read on its own. What the missing time
    costs there is the search for a program inside, and the count says so."""
    sample = SAMPLES_BY_NAME["zip_behind_stored_picture"]
    report = scan_patched(sample.build(), NO_TIME_FOR_TAILS)
    assert finding_keys(report) == set(sample.expected) | {("not_checked", "archive.tail_not_checked", "")}


def test_the_unpatched_scanner_does_open_that_zip(scan):
    """Control for the two tests above: with the real limits the same archive is read."""
    report = scan(SAMPLES_BY_NAME["nested_program_as_photo"].build())
    assert finding_keys(report) == {("red", "layout.disguised_executable", UPLOADS + "assets.zip" + NESTED + "mockup.jpeg")}
