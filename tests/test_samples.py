"""Every sample archive must produce exactly its stated findings: nothing missing, nothing extra."""
import pytest

from conftest import finding_keys
from samples import MANY_ENTRIES, PROGRAM, SAMPLES, SAMPLES_BY_NAME, UPLOADS, ZERO_BOMB_BYTES, site
from zipcraft import Member, write_zip_with_hole

# Reading the first 4 KB of every file must not turn into unpacking the archive.
ZERO_BOMB_READ_LIMIT_BYTES = 4 * 1024 * 1024
# An 8 MB settings file declaring 18 bytes must not be read whole to find that out.
IMPOSSIBLE_PACKING_READ_LIMIT_BYTES = 4 * 1024 * 1024
HOLE_BYTES = 4_300_000_000


@pytest.mark.parametrize("sample", SAMPLES, ids=lambda sample: sample.name)
def test_sample_findings(sample, scan, page):
    page.wordpress_org.answers.update(sample.answers())
    report = scan(sample.build(), name=sample.file_name, online=sample.online)
    assert finding_keys(report) == set(sample.expected)
    assert report["completed"] is sample.completed
    # A line that stands for several findings (a group of archives) carries their number.
    assert sum(report["counts"].values()) == sum(found["params"].get("files", 1) for found in report["findings"])


def test_every_file_of_a_large_archive_is_counted(scan):
    report = scan(SAMPLES_BY_NAME["many_entries"].build())
    site_files = 5
    assert report["archive"]["files"] == MANY_ENTRIES + site_files


def test_zero_bomb_is_not_unpacked(scan):
    archive = SAMPLES_BY_NAME["zero_bomb"].build()
    report = scan(archive)
    assert ZERO_BOMB_BYTES > 200 * len(archive)
    assert report["stats"]["bytesRead"] < ZERO_BOMB_READ_LIMIT_BYTES


def test_a_long_extension_is_named_by_its_first_characters(scan):
    """The worker cuts any text to 4,096 characters, but a finding that names a file kind should
    read like one."""
    report = scan(SAMPLES_BY_NAME["code_shape[include_of_very_long_extension]"].build())
    named = [found["params"]["what"] for found in report["findings"] if found["rule"] == "loaded.include_not_php"]
    assert named == ["." + "x" * 15]


def test_packed_data_longer_than_possible_is_not_read(scan):
    archive = SAMPLES_BY_NAME["impossibly_packed_settings"].build()
    report = scan(archive)
    assert len(archive) > 2 * IMPOSSIBLE_PACKING_READ_LIMIT_BYTES
    assert report["stats"]["bytesRead"] < IMPOSSIBLE_PACKING_READ_LIMIT_BYTES


def test_files_beyond_the_4_gb_mark_are_read(scan, tmp_path):
    """Past 4 GB a zip switches to 64-bit offsets. The 'program' here lies behind that mark."""
    archive_path = tmp_path / "past-4gb.zip"
    behind_the_mark = UPLOADS + "after-4gb.jpeg"
    write_zip_with_hole(archive_path, site(), UPLOADS + "video.bin", HOLE_BYTES, [Member(behind_the_mark, PROGRAM)])

    report = scan(archive_path)

    assert archive_path.stat().st_size > 2**32
    assert finding_keys(report) == {("red", "layout.disguised_executable", behind_the_mark)}
    assert report["completed"] is True
    assert report["archive"]["files"] == len(site()) + 2


def test_wordpress_identity_is_read_from_the_copy(scan):
    report = scan(SAMPLES_BY_NAME["clean"].build())
    assert report["wordpress"] == {"root": "files/", "version": "6.9.5", "locale": "en_US", "plugins": 0, "themes": 0}
