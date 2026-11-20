"""Known attacks, by content. The real rows are the SHA-256 of a password stealer and of the zip it
was sent in, and no file with either hash is ever built here, so a row is pointed at an inert
stand-in of its own size."""
import hashlib
import random

from conftest import finding_keys
from samples import NESTED, UPLOADS, site
from zipcraft import STORED, Member, craft_zip, deflate

STAND_IN = b"inert stand-in for a file from a known attack\n" * 4
REAL_ROW = "    bytes: 4_643_720,\n    sha256: '3c3d0c4a00fb325dad6623813dabd07eb8e715fdd29230d2a3b9fed8f9c474bf',"
POINTED_AT_STAND_IN = {
    "scanner/indicators.js": (
        REAL_ROW,
        f"    bytes: {len(STAND_IN)},\n    sha256: '{hashlib.sha256(STAND_IN).hexdigest()}',",
    ),
}
CACHE_FILE = UPLOADS + "cache.bin"

# The campaign's zip stands in as the small sample site, zipped: a real zip, so the scan of it
# goes on after the match. The comment makes a twin of the same size with other bytes.
STAND_IN_ARCHIVE = craft_zip(site(), comment=b"A")
SAME_SIZE_OTHER_ARCHIVE = craft_zip(site(), comment=b"B")
REAL_ARCHIVE_ROW = "    bytes: 89_770_565,\n    sha256: '49163178348bd8f41c293c47e814d3c50de8ba66ba69e453110d9a3b4014245c',"
ARCHIVE_POINTED_AT_STAND_IN = {
    "scanner/indicators.js": (
        REAL_ARCHIVE_ROW,
        f"    bytes: {len(STAND_IN_ARCHIVE)},\n    sha256: '{hashlib.sha256(STAND_IN_ARCHIVE).hexdigest()}',",
    ),
}
ARCHIVE_IN_COPY = UPLOADS + "Archive.zip"


def test_a_known_file_is_red_by_its_content(scan_patched):
    report = scan_patched(craft_zip([*site(), Member(CACHE_FILE, STAND_IN)]), POINTED_AT_STAND_IN)
    assert finding_keys(report) == {("red", "indicator.known_file", CACHE_FILE)}


def test_a_file_of_the_known_size_that_cannot_be_unpacked_is_named(scan_patched):
    """Its packed data is longer than its size could need, so it is never hashed; that must not
    pass as "not the known file". Named like a program, the file gets no first-bytes reading,
    which would otherwise name the damage first."""
    program = UPLOADS + "cache.exe"
    packed = deflate(STAND_IN + random.Random(7).randbytes(4096))
    report = scan_patched(craft_zip([*site(), Member(program, STAND_IN, packed=packed)]), POINTED_AT_STAND_IN)
    assert finding_keys(report) == {("red", "layout.executable_extension", program), ("not_checked", "entry.corrupt_data", program)}


def test_the_same_size_with_other_content_is_not_known(scan_patched):
    """Control: the size only picks which files get hashed; the hash decides."""
    other = STAND_IN.replace(b"inert", b"other")
    report = scan_patched(craft_zip([*site(), Member(CACHE_FILE, other)]), POINTED_AT_STAND_IN)
    assert len(other) == len(STAND_IN)
    assert finding_keys(report) == set()


def test_the_known_archive_chosen_on_the_page_is_red(scan_patched):
    """The visitor drops the campaign's zip itself: the finding is about the whole copy, says it
    is the archive, and the copy inside is scanned as usual."""
    report = scan_patched(STAND_IN_ARCHIVE, ARCHIVE_POINTED_AT_STAND_IN)
    assert finding_keys(report) == {("red", "indicator.known_upload", "")}
    assert report["findings"][0]["params"] == {"campaign": "fake_backup_2026_11", "role": "archive"}
    assert report["completed"] is True


def test_a_chosen_file_of_the_known_size_with_other_content_is_not_known(scan_patched):
    """Control for the test above: the same size, one byte of the zip comment changed."""
    assert len(SAME_SIZE_OTHER_ARCHIVE) == len(STAND_IN_ARCHIVE)
    report = scan_patched(SAME_SIZE_OTHER_ARCHIVE, ARCHIVE_POINTED_AT_STAND_IN)
    assert finding_keys(report) == set()


def test_only_a_chosen_file_of_a_listed_size_is_read_whole(scan, scan_patched):
    """The same zip is read once more, whole, only while its size is on the list: a copy of 2 GB
    must not be hashed on top of its scan."""
    unlisted = scan(STAND_IN_ARCHIVE)
    listed = scan_patched(SAME_SIZE_OTHER_ARCHIVE, ARCHIVE_POINTED_AT_STAND_IN)
    assert listed["stats"]["bytesRead"] - unlisted["stats"]["bytesRead"] == len(STAND_IN_ARCHIVE)


def test_the_known_archive_lying_in_the_copy_is_red(scan_patched):
    """A zip in the copy is compared as a file, packed or stored, before it is opened. Its own
    dump is named as one the database checks do not read inside a zip."""
    stored = UPLOADS + "Archive-stored.zip"
    copy = craft_zip([*site(), Member(ARCHIVE_IN_COPY, STAND_IN_ARCHIVE), Member(stored, STAND_IN_ARCHIVE, method=STORED)])
    report = scan_patched(copy, ARCHIVE_POINTED_AT_STAND_IN)
    assert finding_keys(report) == {
        ("red", "indicator.known_file", ARCHIVE_IN_COPY),
        ("red", "indicator.known_file", stored),
        ("not_checked", "db.in_nested_archive", ARCHIVE_IN_COPY + NESTED + "database.sql"),
        ("not_checked", "db.in_nested_archive", stored + NESTED + "database.sql"),
    }
    assert {found["params"]["role"] for found in report["findings"] if found["rule"] == "indicator.known_file"} == {"archive"}


def test_the_known_archive_inside_a_zip_in_the_copy_is_red(scan_patched):
    """One level further down the zip is not opened, but it is still hashed."""
    pack = UPLOADS + "pack.zip"
    copy = craft_zip([*site(), Member(pack, craft_zip([Member("Archive.zip", STAND_IN_ARCHIVE)]))])
    report = scan_patched(copy, ARCHIVE_POINTED_AT_STAND_IN)
    assert finding_keys(report) == {
        ("red", "indicator.known_file", pack + NESTED + "Archive.zip"),
        ("not_checked", "archive.not_opened", pack + NESTED + "Archive.zip"),
    }
