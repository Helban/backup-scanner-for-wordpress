"""The browser's decompressor unpacks every written piece whole before anyone can stop it. The
packed data therefore goes in slices, and no more is written once enough came out (once
8.3 MB of a PHP file that unpacked to 8 GB, written in one piece, took the tab to 8.9 GB)."""
import base64
import zlib

BOMB_ZERO_BYTES = 256 * 1024 * 1024
WANTED_BYTES = 1024
# The slice that gave enough and the one or two the pipe holds behind it, 16 KB each. Written
# whole, the bomb would be about 256 KB.
WRITTEN_LIMIT_BYTES = 64 * 1024

COUNT_WHAT_IS_WRITTEN = """async ({ packedBase64, wantBytes }) => {
  const Original = globalThis.DecompressionStream;
  let written = 0;
  globalThis.DecompressionStream = class {
    constructor(format) {
      const real = new Original(format);
      const counter = new TransformStream({
        transform(chunk, controller) {
          written += chunk.length;
          controller.enqueue(chunk);
        },
      });
      counter.readable.pipeTo(real.writable).catch(() => {});
      this.writable = counter.writable;
      this.readable = real.readable;
    }
  };
  try {
    const { inflateHeadOfStream } = await import('/scanner/inflate.js');
    const packed = Uint8Array.from(atob(packedBase64), (char) => char.charCodeAt(0));
    const unpacked = await inflateHeadOfStream(packed, wantBytes);
    return { written, packedBytes: packed.length, state: unpacked.state, length: unpacked.bytes.length };
  } finally {
    globalThis.DecompressionStream = Original;
  }
}"""


def zero_bomb(zero_bytes: int) -> bytes:
    compressor = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    megabyte = b"\x00" * (1024 * 1024)
    packed = bytearray()
    for _ in range(zero_bytes // len(megabyte)):
        packed += compressor.compress(megabyte)
    packed += compressor.flush()
    return bytes(packed)


def test_a_bomb_is_fed_only_until_enough_came_out(page, site_url):
    page.goto(site_url)
    packed = zero_bomb(BOMB_ZERO_BYTES)

    fed = page.evaluate(COUNT_WHAT_IS_WRITTEN, {"packedBase64": base64.b64encode(packed).decode(), "wantBytes": WANTED_BYTES})

    assert fed["packedBytes"] > 2 * WRITTEN_LIMIT_BYTES
    assert (fed["state"], fed["length"]) == ("enough", WANTED_BYTES)
    assert fed["written"] <= WRITTEN_LIMIT_BYTES
