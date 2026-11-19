"""Known attacks, by content. The real row is the SHA-256 of a password stealer, and no file with that
hash is ever built here, so the table is pointed at an inert stand-in of its own size."""
import hashlib
import random

from conftest import finding_keys
from samples import UPLOADS, site
from zipcraft import Member, craft_zip, deflate

STAND_IN = b"inert stand-in for a file from a known attack\n" * 4
REAL_ROW = "    bytes: 4_643_720,\n    sha256: '3c3d0c4a00fb325dad6623813dabd07eb8e715fdd29230d2a3b9fed8f9c474bf',"
POINTED_AT_STAND_IN = {
    "scanner/indicators.js": (
        REAL_ROW,
        f"    bytes: {len(STAND_IN)},\n    sha256: '{hashlib.sha256(STAND_IN).hexdigest()}',",
    ),
}
CACHE_FILE = UPLOADS + "cache.bin"


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
