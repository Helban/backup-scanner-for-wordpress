"""The limits of the tar reader that no sample can reach at their real size (16 GB unpacked, a
million entries), reached with the limit patched down; and the name of the file not deciding."""
from conftest import finding_keys
from samples import LONG_FILM, LONG_FILM_BYTES, SAMPLES_BY_NAME, long_film_ending_in_php, tar_site_with, unchecked
from tarcraft import TarMember

TAR_ARCHIVE = "scanner/tar-archive.js"
ENGINE = "scanner/engine.js"
SMALL_UNPACK_LIMIT_BYTES = 1024 * 1024
SMALL_UNPACK_LIMIT = {TAR_ARCHIVE: (
    "export const TAR_UNPACKED_LIMIT_BYTES = 16 * 1024 * 1024 * 1024;",
    f"export const TAR_UNPACKED_LIMIT_BYTES = {SMALL_UNPACK_LIMIT_BYTES};",
)}
FEW_ENTRIES = 3
FEW_ENTRIES_LIMIT = {ENGINE: (
    "opened = await openTar(file, packing, { maxEntries: MAX_ENTRIES, alive });",
    f"opened = await openTar(file, packing, {{ maxEntries: {FEW_ENTRIES}, alive }});",
)}


def test_unpacking_stops_at_the_limit_and_says_so(scan_patched):
    """Past the limit nothing more is unpacked: the film is cut there, so its data (and the PHP at
    its end) is never reached, and the archive is said to unpack to more than was checked."""
    # The film must reach past the patched limit, or nothing is cut.
    assert LONG_FILM_BYTES > SMALL_UNPACK_LIMIT_BYTES
    archive = tar_site_with(TarMember(LONG_FILM, long_film_ending_in_php()), packed=True)()
    report = scan_patched(archive, SMALL_UNPACK_LIMIT)
    assert finding_keys(report) == {unchecked("tar.gzip_too_large"), unchecked("zip.entry_unreadable", LONG_FILM)}


def test_too_many_entries_stop_the_scan(scan_patched):
    report = scan_patched(tar_site_with()(), FEW_ENTRIES_LIMIT)
    assert finding_keys(report) == {unchecked("tar.too_many_entries")}
    assert report["completed"] is False


def test_a_nested_archive_not_opened_says_why(scan):
    """A gzip holding no tar is a format the scanner does not open; a tar that cannot be listed is damaged."""
    found = scan(SAMPLES_BY_NAME["nested_gzip_without_tar"].build())["findings"]
    assert [entry["params"]["reason"] for entry in found if entry["rule"] == "archive.not_opened"] == ["format"]
    found = scan(SAMPLES_BY_NAME["archive_signature[tar]"].build())["findings"]
    reasons = {entry["path"]: entry["params"]["reason"] for entry in found if entry["rule"] == "archive.not_opened"}
    assert reasons and set(reasons.values()) == {"damaged"}


def test_the_name_does_not_decide_the_format(scan):
    """A .tar.gz named like a photo is still read as one."""
    sample = SAMPLES_BY_NAME["tar_gz_dropper"]
    report = scan(sample.build(), name="holiday.jpg")
    assert finding_keys(report) == set(sample.expected)
