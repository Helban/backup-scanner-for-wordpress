"""Tar archives built header by header, so that a test can write what no honest tool writes.

A `TarMember` is one header and its data. Its fields are written as given, so a member can declare
data on a symlink, carry a wrong checksum or a size field nobody can read. `craft_tar` joins the
members and the end marker; `with_gzip` packs the result the way `tar czf` does.
"""
import gzip
from dataclasses import dataclass

from zipcraft import Member

BLOCK = 512
END_MARKER = b"\x00" * (2 * BLOCK)
FILE = b"0"
HARD_LINK = b"1"
SYMLINK = b"2"
DIRECTORY = b"5"


@dataclass(frozen=True)
class TarMember:
    name: str
    body: bytes = b""
    type_flag: bytes = FILE
    link: str = ""
    # Written instead of the octal size of `body` (12 bytes).
    size_field: bytes | None = None
    checksum_shift: int = 0


def header(member: TarMember) -> bytes:
    name = member.name.encode()
    if len(name) > 100:
        raise ValueError(f"name longer than a ustar name field: {member.name}")
    block = bytearray(BLOCK)
    block[0:len(name)] = name
    block[100:108] = b"0000644\x00"
    block[108:116] = b"0000000\x00"
    block[116:124] = b"0000000\x00"
    block[124:136] = member.size_field if member.size_field is not None else f"{len(member.body):011o}\x00".encode()
    block[136:148] = b"00000000000\x00"
    block[156:157] = member.type_flag
    link = member.link.encode()
    block[157:157 + len(link)] = link
    block[257:263] = b"ustar\x00"
    block[263:265] = b"00"
    block[148:156] = b" " * 8
    checksum = sum(block) + member.checksum_shift
    block[148:156] = f"{checksum:06o}\x00 ".encode()
    return bytes(block)


def record(member: TarMember) -> bytes:
    """The header and its data padded to whole blocks."""
    return header(member) + member.body + b"\x00" * (-len(member.body) % BLOCK)


def craft_tar(members: list[TarMember], end: bytes = END_MARKER) -> bytes:
    return b"".join(record(member) for member in members) + end


def from_zip_members(members: list[Member]) -> list[TarMember]:
    """The sample site of samples.py, as files of a tar."""
    return [TarMember(member.name if isinstance(member.name, str) else member.name.decode(), member.body) for member in members]


def with_gzip(archive: bytes) -> bytes:
    return gzip.compress(archive, mtime=0)
