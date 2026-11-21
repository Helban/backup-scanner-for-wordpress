// SPDX-License-Identifier: GPL-3.0-or-later
//
// Reading the data of one entry of the visitor's archive: its first bytes, or all of it.
// Worker side only.

import { inflateHeadOfStream, inflaterFor } from './inflate.js';
import { LOCAL_HEADER_BYTES, METHOD_DEFLATE, METHOD_STORED, parseLocalHeader } from './zip-reader.js';

const LOCAL_EXTRA_SLACK = 64;
const SMALL_FILE_LIMIT_BYTES = 64 * 1024;
// Text packs well, so this much packed data covers the first 8 KB of any honest header file.
const PREFIX_PACKED_BYTES = 16 * 1024;

export const READ_AHEAD_BYTES = 1024 * 1024;
// How often a walk over many entries, or one long read, tells the page how far it got.
export const PROGRESS_INTERVAL_MS = 120;

export const isSupportedMethod = (entry) => entry.method === METHOD_STORED || entry.method === METHOD_DEFLATE;

export const isReadable = (entry) => !entry.unreadable && !entry.isEncrypted && isSupportedMethod(entry);

// The entry's local header and the first `wantPacked` bytes of its data. `readAhead` is how
// much of the file the source window may take in on the way, for the entries that follow.
export const locateData = async ({ source, archive }, entry, { wantPacked, readAhead }) => {
  if (BARE_FORMATS.has(archive.format)) return locateBareData(source, entry, { wantPacked, readAhead });
  const room = archive.directoryStart - entry.headerOffset;
  if (room < LOCAL_HEADER_BYTES) return { unreadable: 'out_of_bounds' };
  const guess = LOCAL_HEADER_BYTES + entry.nameBytes.length + entry.extraLength + LOCAL_EXTRA_SLACK + wantPacked;
  let bytes = await source.view(entry.headerOffset, Math.min(room, guess), readAhead);
  let header = parseLocalHeader(bytes, entry);
  if (!header.signatureFound) return { unreadable: 'no_local_header' };
  if (header.headerBytes + entry.compressedSize > room) return { unreadable: 'out_of_bounds' };
  const needed = header.headerBytes + wantPacked;
  if (bytes.length < needed) {
    bytes = await source.view(entry.headerOffset, needed, 0);
    if (!header.complete) header = parseLocalHeader(bytes, entry);
  }
  return { header, packed: bytes.subarray(header.headerBytes, needed) };
};

// Entries with no header of their own in front of the data: a tar's (tar-archive.js; the reader
// of the archive already checked each header) and a dump dropped by itself (engine.js
// dumpAlone). Their data starts at headerOffset, and there is nothing to compare.
const BARE_FORMATS = new Set(['tar', 'dump']);
const NO_HEADER = Object.freeze({ signatureFound: true, headerBytes: 0, complete: true, differences: [], localName: '' });

const locateBareData = async (source, entry, { wantPacked, readAhead }) => {
  if (entry.headerOffset + entry.compressedSize > source.size) return { unreadable: 'out_of_bounds' };
  const packed = wantPacked === 0 ? new Uint8Array(0) : await source.view(entry.headerOffset, wantPacked, readAhead);
  return { header: NO_HEADER, packed };
};

export const readSmallFile = async (container, entry) => {
  const isSmallAndReadable = isReadable(entry)
    && entry.compressedSize <= SMALL_FILE_LIMIT_BYTES && entry.uncompressedSize <= SMALL_FILE_LIMIT_BYTES;
  if (!isSmallAndReadable) return null;
  return (await readWholeFile(container, entry)).bytes;
};

// The first `length` bytes, or fewer when the file is shorter or cannot be unpacked that far.
export const readPrefix = async (container, entry, length) => {
  if (!isReadable(entry)) return new Uint8Array(0);
  const wantPacked = Math.min(entry.compressedSize, PREFIX_PACKED_BYTES);
  const located = await locateData(container, entry, { wantPacked, readAhead: READ_AHEAD_BYTES });
  if (located.unreadable) return new Uint8Array(0);
  if (entry.method === METHOD_STORED) return located.packed.subarray(0, length);
  const unpacked = await inflaterFor(wantPacked, entry.compressedSize)(located.packed, length);
  return unpacked.bytes;
};

// Why a file could not be read whole:
//   unreachable - no data where the table of contents points, or a method not unpacked here;
//                 the first-bytes check reports these already, so callers pass over it
//   data        - the data is damaged, or unpacks to another size than declared
const UNREACHABLE = 'unreachable';
export const DAMAGED = 'data';

// Packed data far longer than the declared size cannot unpack to that size. It is refused before
// it is read: the packed data of a whole file is read into memory, and a caller's size limit
// usually looks at the declared size only (a settings file declaring 100 bytes over 2 GB).
// How much longer honest deflate data gets depends on the encoder: zlib grows data that does
// not pack by 0.03% with its defaults and by 3.9% with memLevel 1 (measured 2026-11-14), and
// an encoder that writes fixed codes only spends nine bits on a byte at worst, 12.5%. A quarter
// is twice that and still bounds the read by the declared size. The first bound here, 0.1%,
// called an official plugin's file from the memLevel 1 encoder damaged.
const PACKED_SLACK_BYTES = 64 * 1024;
const PACKED_GROWTH_DIVISOR = 4;

const isPackedSizePossible = (entry) => (
  entry.compressedSize <= entry.uncompressedSize + Math.ceil(entry.uncompressedSize / PACKED_GROWTH_DIVISOR) + PACKED_SLACK_BYTES
);

// The whole file in memory. Callers keep the declared size within reason.
export const readWholeFile = async (container, entry) => {
  if (!isReadable(entry)) return { bytes: null, failure: UNREACHABLE };
  if (!isPackedSizePossible(entry)) return { bytes: null, failure: DAMAGED };
  const located = await locateData(container, entry, { wantPacked: entry.compressedSize, readAhead: READ_AHEAD_BYTES });
  if (located.unreadable) return { bytes: null, failure: UNREACHABLE };
  if (entry.method === METHOD_STORED) {
    const isWhole = located.packed.length === entry.uncompressedSize;
    return isWhole ? { bytes: located.packed, failure: '' } : { bytes: null, failure: DAMAGED };
  }
  // One byte more than declared is asked for, so a stream that runs longer is caught.
  const unpacked = await inflateHeadOfStream(located.packed, entry.uncompressedSize + 1);
  const isWhole = unpacked.state === 'ended' && unpacked.bytes.length === entry.uncompressedSize;
  return isWhole ? { bytes: unpacked.bytes, failure: '' } : { bytes: null, failure: DAMAGED };
};

// Hands the unpacked file to `consume` piece by piece, for files too large to hold at once.
// Returns '' when the whole file went through, otherwise the reason it did not. This and
// readThrough can run for many seconds on one file, so both call `container.alive()`.
export const streamWholeFile = async (container, entry, consume) => {
  if (!isReadable(entry)) return UNREACHABLE;
  const located = await locateData(container, entry, { wantPacked: 0, readAhead: 0 });
  if (located.unreadable) return UNREACHABLE;
  const dataStart = entry.headerOffset + located.header.headerBytes;
  let stream = container.source.stream(dataStart, dataStart + entry.compressedSize);
  if (entry.method === METHOD_DEFLATE) stream = stream.pipeThrough(new DecompressionStream('deflate-raw'));
  const reader = stream.getReader();
  let bytes = 0;
  try {
    for (;;) {
      const step = await reader.read();
      if (step.done) break;
      bytes += step.value.length;
      if (bytes > entry.uncompressedSize) {
        await reader.cancel();
        return DAMAGED;
      }
      consume(step.value);
      container.alive();
    }
  } catch (error) {
    // DecompressionStream reports bad or truncated deflate data as a TypeError.
    if (!(error instanceof TypeError)) throw error;
    return DAMAGED;
  }
  return bytes === entry.uncompressedSize ? '' : DAMAGED;
};

export const TIME = 'time';

// Reads a file from its first byte to its last and returns the last `tailBytes` of it. Every
// piece goes to `inspect` on the way and is dropped; only the end is kept. Deflate has no
// random access, so for a packed file this is also the only way to its end. `failure` is ''
// when the tail came back, DAMAGED as above, or TIME when `deadline` passed first. `dataStart`
// is where the entry's data begins, behind its local header.
export const readThrough = async (container, { entry, dataStart }, { tailBytes, deadline, inspect }) => {
  let stream = container.source.stream(dataStart, dataStart + entry.compressedSize);
  if (entry.method === METHOD_DEFLATE) stream = stream.pipeThrough(new DecompressionStream('deflate-raw'));
  const reader = stream.getReader();
  // The data a stored file really has; a size that disagrees is a red finding of its own.
  const expectedBytes = entry.method === METHOD_STORED ? entry.compressedSize : entry.uncompressedSize;
  const kept = [];
  let keptBytes = 0;
  let unpacked = 0;
  try {
    for (;;) {
      if (performance.now() > deadline) {
        await reader.cancel();
        return { tail: null, failure: TIME };
      }
      const step = await reader.read();
      if (step.done) break;
      unpacked += step.value.length;
      if (unpacked > expectedBytes) {
        await reader.cancel();
        return { tail: null, failure: DAMAGED };
      }
      inspect(step.value);
      kept.push(step.value);
      keptBytes += step.value.length;
      while (keptBytes - kept[0].length >= tailBytes) keptBytes -= kept.shift().length;
      container.alive();
    }
  } catch (error) {
    if (!(error instanceof TypeError)) throw error;
    return { tail: null, failure: DAMAGED };
  }
  if (unpacked !== expectedBytes) return { tail: null, failure: DAMAGED };
  const joined = new Uint8Array(keptBytes);
  let at = 0;
  for (const chunk of kept) {
    joined.set(chunk, at);
    at += chunk.length;
  }
  return { tail: joined.subarray(keptBytes - Math.min(tailBytes, keptBytes)), failure: '' };
};

// Reads from the visitor's file through one sliding window, so thousands of small files
// lying next to each other cost a handful of reads.
export class ArchiveSource {
  constructor(blob) {
    this.blob = blob;
    this.window = new Uint8Array(0);
    this.windowStart = 0;
    this.bytesRead = 0;
  }

  get size() {
    return this.blob.size;
  }

  // The bytes from `start` to `end` as a stream, read in place. Counted as read when asked for,
  // whether or not the reader goes to the end. (GzipSource counts the packed bytes it reads.)
  stream(start, end) {
    this.bytesRead += end - start;
    return this.blob.slice(start, end).stream();
  }

  async view(offset, length, readAhead) {
    if (offset < 0 || offset + length > this.blob.size) {
      throw new RangeError('read outside the archive');
    }
    const isInWindow = offset >= this.windowStart && offset + length <= this.windowStart + this.window.length;
    if (!isInWindow) {
      const span = Math.min(Math.max(length, readAhead), this.blob.size - offset);
      this.window = new Uint8Array(await this.blob.slice(offset, offset + span).arrayBuffer());
      this.windowStart = offset;
      this.bytesRead += span;
    }
    const from = offset - this.windowStart;
    return this.window.subarray(from, from + length);
  }

  // Like view, but a read outside the window leaves the window where it is: the end of a large
  // file must not throw away the read-ahead the next small files are about to use.
  async peek(offset, length) {
    const isInWindow = offset >= this.windowStart && offset + length <= this.windowStart + this.window.length;
    if (isInWindow) return this.view(offset, length, 0);
    if (offset < 0 || offset + length > this.blob.size) {
      throw new RangeError('read outside the archive');
    }
    this.bytesRead += length;
    return new Uint8Array(await this.blob.slice(offset, offset + length).arrayBuffer());
  }
}
