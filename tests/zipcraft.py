"""Builds zip files field by field.

A zip describes each file twice: in a header in front of its data and in the table of contents
at the end. `zipfile` always writes both consistently, which is exactly what the samples here
must not do, so this module writes the structures by hand and lets a test override any field
of either copy.
"""
import struct
import zlib
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

STORED = 0
DEFLATED = 8
FLAG_ENCRYPTED = 0x0001
FLAG_DESCRIPTOR = 0x0008
FLAG_UTF8 = 0x0800
SYMLINK_ATTRIBUTES = 0o120777 << 16
UINT16_MAX = 0xFFFF
UINT32_MAX = 0xFFFFFFFF
EXTRA_ZIP64 = 0x0001
EXTRA_UNICODE_PATH = 0x7075

SIGNATURE_LOCAL = 0x04034B50
SIGNATURE_CENTRAL = 0x02014B50
SIGNATURE_DESCRIPTOR = 0x08074B50
SIGNATURE_END = 0x06054B50
SIGNATURE_END64 = 0x06064B50
SIGNATURE_END64_LOCATOR = 0x07064B50
VERSION_PLAIN = 20
VERSION_ZIP64 = 45
MADE_ON_UNIX = 0x0314
# 1980-01-01, the first day a zip date can name; every member carries it.
DOS_DATE = 0x21
# The size field of the 64-bit end record leaves out the signature and the field itself.
END64_UNCOUNTED_BYTES = 12
UNICODE_PATH_VERSION = 1

_LOCAL = struct.Struct("<IHHHHHIIIHH")
_CENTRAL = struct.Struct("<IHHHHHHIIIHHHHHII")
_END = struct.Struct("<IHHHHIIH")
_END64 = struct.Struct("<IQHHIIQQQQ")
_END64_LOCATOR = struct.Struct("<IIQI")
_DESCRIPTOR = struct.Struct("<IIII")


@dataclass
class Member:
    """One file in the archive. `local` and `central` override single fields of the header in
    front of the data and of the row in the table of contents: name, flags, method, crc,
    compressed_size, uncompressed_size, extra; `central` also takes external_attr, offset, disk."""

    name: str | bytes
    body: bytes = b""
    method: int = DEFLATED
    flags: int = 0
    external_attr: int = 0
    packed: bytes | None = None
    local: dict = field(default_factory=dict)
    central: dict = field(default_factory=dict)
    listed: bool = True
    stored_in_file: bool = True
    descriptor: bool = False
    zip64: bool = False
    before: bytes = b""


def deflate(body: bytes) -> bytes:
    compressor = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    return compressor.compress(body) + compressor.flush()


def unicode_path_extra(header_name: bytes, other_name: str) -> bytes:
    payload = struct.pack("<BI", UNICODE_PATH_VERSION, zlib.crc32(header_name)) + other_name.encode("utf-8")
    return struct.pack("<HH", EXTRA_UNICODE_PATH, len(payload)) + payload


def craft_zip(
    members: Sequence[Member],
    *,
    comment: bytes = b"",
    trailing: bytes = b"",
    after_directory: bytes = b"",
    end: dict | None = None,
    zip64_end: bool = False,
    end64: dict | None = None,
    stale_prefix: bytes = b"",
) -> bytes:
    """`end` and `end64` override fields of the end record and of its 64-bit twin.
    `stale_prefix` is glued in front WITHOUT correcting the stored offsets."""
    out = bytearray()
    rows = []
    for member in members:
        out += member.before
        encoded, row = _encode_member(member, len(out))
        out += encoded
        if member.listed:
            rows.append(row)

    directory_offset = len(out)
    for row in rows:
        out += _central_header(row)
    directory_size = len(out) - directory_offset
    out += after_directory

    real = {
        "disk": 0, "directory_disk": 0, "entries_on_disk": len(rows), "entries_total": len(rows),
        "directory_size": directory_size, "directory_offset": directory_offset,
    }
    short = dict(real)
    if zip64_end or end64 is not None or len(rows) > UINT16_MAX:
        wide = real | (end64 or {})
        record_offset = len(out)
        out += _END64.pack(
            SIGNATURE_END64, _END64.size - END64_UNCOUNTED_BYTES, VERSION_ZIP64, VERSION_ZIP64, wide["disk"], wide["directory_disk"],
            wide["entries_on_disk"], wide["entries_total"], wide["directory_size"], wide["directory_offset"],
        )
        out += _END64_LOCATOR.pack(SIGNATURE_END64_LOCATOR, 0, record_offset, 1)
        short = {
            "disk": 0, "directory_disk": 0, "entries_on_disk": UINT16_MAX, "entries_total": UINT16_MAX,
            "directory_size": UINT32_MAX, "directory_offset": UINT32_MAX,
        }
    short |= end or {}
    out += _END.pack(
        SIGNATURE_END, short["disk"], short["directory_disk"], short["entries_on_disk"], short["entries_total"],
        short["directory_size"], short["directory_offset"], len(comment),
    )
    return stale_prefix + bytes(out) + comment + trailing


def write_zip_with_hole(path: Path, before: Sequence[Member], hole_name: str, hole_bytes: int, after: Sequence[Member]) -> None:
    """Writes a zip64 archive to `path` with one stored member of `hole_bytes` zeros between
    the `before` and `after` members. The zeros are a hole in a sparse file, so an archive with
    data beyond the 4 GB mark costs a few kilobytes of disk and no memory."""
    head = bytearray()
    rows = []
    for member in before:
        encoded, row = _encode_member(member, len(head))
        head += encoded
        rows.append(row)

    megabyte = b"\x00" * (1024 * 1024)
    checksum = 0
    for _ in range(hole_bytes // len(megabyte)):
        checksum = zlib.crc32(megabyte, checksum)
    checksum = zlib.crc32(megabyte[: hole_bytes % len(megabyte)], checksum)
    name = hole_name.encode("utf-8")
    sizes = struct.pack("<QQ", hole_bytes, hole_bytes)
    extra = struct.pack("<HH", EXTRA_ZIP64, len(sizes)) + sizes
    rows.append({
        "name": name, "flags": 0, "method": STORED, "crc": checksum, "compressed_size": UINT32_MAX,
        "uncompressed_size": UINT32_MAX, "extra": extra, "external_attr": 0, "offset": len(head), "disk": 0,
    })
    head += _LOCAL.pack(SIGNATURE_LOCAL, VERSION_ZIP64, 0, STORED, 0, DOS_DATE, checksum, UINT32_MAX, UINT32_MAX, len(name), len(extra))
    head += name + extra

    tail_offset = len(head) + hole_bytes
    tail = bytearray()
    for member in after:
        encoded, row = _encode_member(member, tail_offset + len(tail))
        tail += encoded
        rows.append(row)
    directory = b"".join(_central_header(row) for row in rows)
    directory_offset = tail_offset + len(tail)
    record_offset = directory_offset + len(directory)
    tail += directory
    tail += _END64.pack(
        SIGNATURE_END64, _END64.size - END64_UNCOUNTED_BYTES, VERSION_ZIP64, VERSION_ZIP64, 0, 0,
        len(rows), len(rows), len(directory), directory_offset,
    )
    tail += _END64_LOCATOR.pack(SIGNATURE_END64_LOCATOR, 0, record_offset, 1)
    tail += _END.pack(SIGNATURE_END, 0, 0, UINT16_MAX, UINT16_MAX, UINT32_MAX, UINT32_MAX, 0)
    with path.open("wb") as archive:
        archive.write(head)
        archive.seek(tail_offset)
        archive.write(tail)


def _encode_member(member: Member, offset: int) -> tuple[bytes, dict]:
    """The bytes of one member as they lie in the archive, starting at `offset`, and its row of
    the table of contents."""
    name = member.name.encode("utf-8") if isinstance(member.name, str) else member.name
    flags = member.flags | (FLAG_UTF8 if isinstance(member.name, str) and not member.name.isascii() else 0)
    if member.descriptor:
        flags |= FLAG_DESCRIPTOR
    if member.packed is not None:
        packed = member.packed
    else:
        packed = deflate(member.body) if member.method == DEFLATED else member.body
    true = {
        "name": name, "flags": flags, "method": member.method, "crc": zlib.crc32(member.body),
        "compressed_size": len(packed), "uncompressed_size": len(member.body), "extra": b"",
    }
    local = dict(true)
    central = true | {"external_attr": member.external_attr, "offset": offset, "disk": 0}
    if member.descriptor:
        local |= {"crc": 0, "compressed_size": 0, "uncompressed_size": 0}
    if member.zip64:
        sizes = struct.pack("<QQ", len(member.body), len(packed))
        local |= {
            "compressed_size": UINT32_MAX, "uncompressed_size": UINT32_MAX,
            "extra": struct.pack("<HH", EXTRA_ZIP64, len(sizes)) + sizes,
        }
        wide = sizes + struct.pack("<Q", offset)
        central |= {
            "compressed_size": UINT32_MAX, "uncompressed_size": UINT32_MAX, "offset": UINT32_MAX,
            "extra": struct.pack("<HH", EXTRA_ZIP64, len(wide)) + wide,
        }
    local |= member.local
    central |= member.central

    if not member.stored_in_file:
        return b"", central
    encoded = _LOCAL.pack(
        SIGNATURE_LOCAL, VERSION_PLAIN, local["flags"], local["method"], 0, DOS_DATE, local["crc"],
        local["compressed_size"], local["uncompressed_size"], len(local["name"]), len(local["extra"]),
    ) + local["name"] + local["extra"] + packed
    if member.descriptor:
        encoded += _DESCRIPTOR.pack(SIGNATURE_DESCRIPTOR, true["crc"], len(packed), len(member.body))
    return encoded, central


def _central_header(row: dict) -> bytes:
    if row["offset"] > UINT32_MAX:
        # An offset past 4 GB does not fit the 32-bit field: the marker goes there and the real
        # value into the 64-bit extra field, after any sizes that are already in it.
        wide_offset = struct.pack("<Q", row["offset"])
        row = row | {"offset": UINT32_MAX, "extra": row["extra"] + struct.pack("<HH", EXTRA_ZIP64, len(wide_offset)) + wide_offset}
    return _CENTRAL.pack(
        SIGNATURE_CENTRAL, MADE_ON_UNIX, VERSION_PLAIN, row["flags"], row["method"], 0, DOS_DATE, row["crc"],
        row["compressed_size"], row["uncompressed_size"], len(row["name"]), len(row["extra"]), 0,
        row["disk"], 0, row["external_attr"], row["offset"],
    ) + row["name"] + row["extra"]
