// SPDX-License-Identifier: GPL-3.0-or-later

const POLYNOMIAL = 0xedb88320;
const TABLE = new Uint32Array(256);
for (let byte = 0; byte < 256; byte += 1) {
  let remainder = byte;
  for (let bit = 0; bit < 8; bit += 1) {
    remainder = remainder & 1 ? POLYNOMIAL ^ (remainder >>> 1) : remainder >>> 1;
  }
  TABLE[byte] = remainder >>> 0;
}

// `previous` is the checksum of the data that came before, for data arriving in pieces.
export const crc32 = (bytes, previous = 0) => {
  let crc = (previous ^ 0xffffffff) >>> 0;
  for (let at = 0; at < bytes.length; at += 1) {
    crc = TABLE[(crc ^ bytes[at]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
};
