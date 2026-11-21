"""The scanner's own gzip reader against zlib, in the browser under test: every block type, several
members, zero padding, and input in pieces of any size. The browser's DecompressionStream is not
used for this because it ends at the first member (see scanner/gunzip.js)."""
import base64
import hashlib
import random
import zlib

import pytest

SEED = 20261121
PIECE_SIZES = [1, 97, 65536]


def deflated(body: bytes, strategy: int, level: int) -> bytes:
    compressor = zlib.compressobj(level, zlib.DEFLATED, 31, 8, strategy)
    return compressor.compress(body) + compressor.flush()


def with_wrong_checksum(packed: bytes) -> bytes:
    broken = bytearray(packed)
    broken[-8] ^= 0xFF
    return bytes(broken)


def member_reaching_back(first: bytes, second: bytes) -> bytes:
    """Two members, the second packed with the first's text as its dictionary: its matches reach
    into the member before, which no member may do. Its checksum fits the text that a reader
    allowing it would put out."""
    compressor = zlib.compressobj(9, zlib.DEFLATED, -15, 9, zlib.Z_DEFAULT_STRATEGY, zdict=first)
    raw = compressor.compress(second) + compressor.flush()
    trailer = zlib.crc32(second).to_bytes(4, "little") + len(second).to_bytes(4, "little")
    return deflated(first, zlib.Z_DEFAULT_STRATEGY, 9) + b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03" + raw + trailer


def named_bodies() -> dict[str, bytes]:
    picker = random.Random(SEED)
    rows = b"".join(f"INSERT INTO `wp_options` VALUES ({row},'option_{row % 50}','{row * 7919}','yes');\n".encode() for row in range(6000))
    return {"empty": b"", "noise": picker.randbytes(70_000), "rows": rows, "zeros": b"\x00" * 300_000}


def bodies() -> list[bytes]:
    return list(named_bodies().values())


def stored_without_complement(body: bytes) -> bytes:
    """A stored block whose length is not followed by its complement. zlib's level 0 writes the
    block header in byte 10, the length in 11-12 and the complement in 13-14."""
    broken = bytearray(deflated(body, zlib.Z_DEFAULT_STRATEGY, 0))
    broken[13] ^= 0x01
    return bytes(broken)


# (label, packed, unpacked, members, state)
CASES = [
    *(
        (f"{body_name}, {name}, level {level}", deflated(body, strategy, level), body, 1, "ended")
        for body_name, body in named_bodies().items()
        for name, strategy in (("default", zlib.Z_DEFAULT_STRATEGY), ("fixed codes", zlib.Z_FIXED), ("huffman only", zlib.Z_HUFFMAN_ONLY))
        for level in (0, 6)
    ),
    ("stored length without its complement", stored_without_complement(named_bodies()["rows"]), None, 0, "damaged"),
    ("four members", b"".join(deflated(body, zlib.Z_DEFAULT_STRATEGY, 6) for body in bodies()), b"".join(bodies()), 4, "ended"),
    ("member then zeros", deflated(bodies()[2], zlib.Z_DEFAULT_STRATEGY, 6) + b"\x00" * 9, bodies()[2], 1, "ended"),
    ("member then text", deflated(bodies()[2], zlib.Z_DEFAULT_STRATEGY, 6) + b"more", None, 1, "damaged"),
    ("member then zeros and text", deflated(bodies()[2], zlib.Z_DEFAULT_STRATEGY, 6) + b"\x00\x00more", None, 1, "damaged"),
    ("cut in the middle", deflated(bodies()[2], zlib.Z_DEFAULT_STRATEGY, 6)[:5000], None, 0, "truncated"),
    ("wrong checksum", with_wrong_checksum(deflated(bodies()[2], zlib.Z_DEFAULT_STRATEGY, 6)), None, 0, "damaged"),
    ("match reaches the member before", member_reaching_back(bodies()[2][:20_000], bodies()[2][5_000:9_000] * 3), None, 1, "damaged"),
]

UNPACK = """async ({ packedBase64, pieceBytes }) => {
  const { createGunzip } = await import('/scanner/gunzip.js');
  const packed = Uint8Array.from(atob(packedBase64), (char) => char.charCodeAt(0));
  const parts = [];
  const gunzip = createGunzip({ onBytes: (view) => parts.push(view.slice()), limitBytes: 2 ** 40 });
  for (let at = 0; at < packed.length; at += pieceBytes) gunzip.push(packed.subarray(at, at + pieceBytes));
  const outcome = gunzip.finish();
  const digest = await crypto.subtle.digest('SHA-256', await new Blob(parts).arrayBuffer());
  const sha256 = [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
  return { ...outcome, sha256 };
}"""


@pytest.mark.parametrize("label, packed, unpacked, members, state", CASES, ids=[case[0] for case in CASES])
def test_gzip_unpacks_like_zlib(page, site_url, label, packed, unpacked, members, state):
    page.goto(site_url)
    encoded = base64.b64encode(packed).decode()
    # One-byte pieces of the large cases would take most of a minute in the browser.
    sizes = PIECE_SIZES if len(packed) < 20_000 else PIECE_SIZES[1:]
    for piece_bytes in sizes:
        outcome = page.evaluate(UNPACK, {"packedBase64": encoded, "pieceBytes": piece_bytes})
        assert (outcome["state"], outcome["members"]) == (state, members), piece_bytes
        if unpacked is not None:
            assert (outcome["bytes"], outcome["sha256"]) == (len(unpacked), hashlib.sha256(unpacked).hexdigest()), piece_bytes
