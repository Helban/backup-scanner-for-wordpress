// SPDX-License-Identifier: GPL-3.0-or-later
//
// The unpacked bytes of a gzip file (a .tar.gz), read by offset like the bytes of a file, without
// ever holding the unpacked file. Firefox and WebKit keep a Blob in memory however large it is
// (measured 2026-11-21, tools/wp-zip-scan/tar-stage1/README.md), so unpacking a backup of a few
// GB into one would take the visitor's whole memory. Instead one pass over the file (index) keeps
// a resume point of the inflater every POINT_EVERY_BYTES of output, and a read starts at the
// nearest point before it. The scan reads files mostly in the order they lie, so most reads go on
// from where the last one stopped (the idle cursor) and unpack nothing twice.
//
// Same reading contract as ArchiveSource (entries.js): view, peek, stream, size, bytesRead.

import { createGunzip } from './gunzip.js';

// A point keeps 32 KB of window and the code lengths of its block (316 bytes at most): one per
// 4 MB costs about 8 MB of memory per GB of unpacked archive, and a read far from the cursor
// unpacks 2 MB on average before its first byte. (Until the second review a point kept the
// built code tables, up to 288 KB: 24 MB per GB measured, 74 MB per GB at worst.)
export const POINT_EVERY_BYTES = 4 * 1024 * 1024;
// Small pieces of input keep how far a cursor runs past the end of a read short.
const PACKED_PIECE_BYTES = 64 * 1024;
const SMALLEST_PIECE_BYTES = 1024;
const INDEX_PIECE_BYTES = 1024 * 1024;
// What a cursor keeps of its latest output, for a read that starts a little behind it.
const RECENT_BYTES = 4 * 1024 * 1024;

export class GzipSource {
  constructor(blob) {
    this.blob = blob;
    this.size = 0;
    this.bytesRead = 0;
    this.points = [];
    this.idle = null;
    this.window = new Uint8Array(0);
    this.windowStart = 0;
  }

  // Unpacks the whole file once, handing every piece to `consume` (which must not keep it), and
  // returns the state createGunzip's finish() gives. Only after this can the bytes be read.
  async index(consume, { limitBytes, alive }) {
    const gunzip = createGunzip({
      onBytes: consume,
      limitBytes,
      onPoint: (point) => this.points.push(point),
      pointEvery: POINT_EVERY_BYTES,
    });
    for (let at = 0; at < this.blob.size; at += INDEX_PIECE_BYTES) {
      const piece = new Uint8Array(await this.blob.slice(at, at + INDEX_PIECE_BYTES).arrayBuffer());
      this.bytesRead += piece.length;
      gunzip.push(piece);
      alive();
    }
    const unpacking = gunzip.finish();
    this.size = unpacking.bytes;
    return unpacking;
  }

  async view(offset, length, readAhead) {
    if (offset < 0 || offset + length > this.size) {
      throw new RangeError('read outside the archive');
    }
    const isInWindow = offset >= this.windowStart && offset + length <= this.windowStart + this.window.length;
    if (!isInWindow) {
      const span = Math.min(Math.max(length, readAhead), this.size - offset);
      this.window = await this.collect(offset, offset + span);
      this.windowStart = offset;
    }
    const from = offset - this.windowStart;
    return this.window.subarray(from, from + length);
  }

  async peek(offset, length) {
    const isInWindow = offset >= this.windowStart && offset + length <= this.windowStart + this.window.length;
    if (isInWindow) return this.view(offset, length, 0);
    if (offset < 0 || offset + length > this.size) {
      throw new RangeError('read outside the archive');
    }
    return this.collect(offset, offset + length);
  }

  // The bytes from `start` to `end` as a stream, for a file too large to read at once.
  stream(start, end) {
    const pieces = this.pieces(start, end);
    return new ReadableStream({
      async pull(controller) {
        const step = await pieces.next();
        if (step.done) controller.close();
        else controller.enqueue(step.value);
      },
      async cancel() {
        await pieces.return();
      },
    });
  }

  // Fewer bytes than asked for only where the file holds fewer.
  async collect(start, end) {
    const joined = new Uint8Array(end - start);
    let filled = 0;
    for await (const piece of this.pieces(start, end)) {
      joined.set(piece, filled);
      filled += piece.length;
    }
    return filled === joined.length ? joined : joined.subarray(0, filled);
  }

  // The unpacked bytes from `start` to `end`, in order: views of a cursor's own copies, which a
  // caller must not change.
  async* pieces(start, end) {
    const cursor = this.cursorFor(start);
    let next = start;
    try {
      next = yield* cursor.recentFrom(next, end);
      while (next < end && !cursor.isOver) {
        const fresh = await this.advance(cursor, end);
        next = yield* overlapOf(fresh, next, end);
      }
    } finally {
      this.idle = cursor;
    }
  }

  // The idle cursor when it holds `start` or reaches it sooner than a fresh start would; otherwise
  // a new one at the last point at or before `start`.
  cursorFor(start) {
    const point = lastPointAtOrBefore(this.points, start);
    const pointOffset = point === null ? 0 : point.outputOffset;
    const idle = this.idle;
    if (idle !== null && !idle.isOver && idle.recentStart() <= start && pointOffset <= idle.produced) {
      this.idle = null;
      return idle;
    }
    return new Cursor(point);
  }

  // `readEnd` is where the read under way stops: what comes out past it is kept for the next one.
  async advance(cursor, readEnd) {
    const piece = new Uint8Array(await this.blob.slice(cursor.packedAt, cursor.packedAt + cursor.pieceBytes).arrayBuffer());
    this.bytesRead += piece.length;
    return cursor.feed(piece, readEnd);
  }
}

// One unpacking under way: where it stands in the packed file and in the output, and the latest
// output it keeps.
class Cursor {
  constructor(point) {
    this.packedAt = point === null ? 0 : point.inputOffset;
    this.produced = point === null ? 0 : point.outputOffset;
    this.pieceBytes = PACKED_PIECE_BYTES;
    this.isOver = false;
    this.recent = [];
    this.recentBytes = 0;
    this.fresh = [];
    this.gunzip = createGunzip({
      onBytes: (view) => {
        this.fresh.push({ offset: this.produced, bytes: view.slice() });
        this.produced += view.length;
      },
      limitBytes: Infinity,
      from: point,
    });
  }

  recentStart() {
    return this.recent.length === 0 ? this.produced : this.recent[0].offset;
  }

  // The output of one piece of input, also kept as the latest output. An unpacking that stopped
  // (damaged data) or ran out of input is over. Output past `readEnd` is never dropped here: the
  // next read in order starts there, and dropping it made that read start a new cursor.
  feed(piece, readEnd) {
    this.packedAt += piece.length;
    if (piece.length === 0) {
      this.gunzip.finish();
    } else {
      this.gunzip.push(piece);
    }
    this.isOver = piece.length === 0 || this.gunzip.hasStopped();
    const fresh = this.fresh;
    this.fresh = [];
    // Data that packs better than 64:1 gives more from one piece than the cursor keeps, and the
    // next read in order then started a new cursor every time (4,777 reads of the packed file
    // for 20 MB at 134:1, the second Fable review). Smaller pieces keep the output within reach.
    const freshBytes = fresh.reduce((total, chunk) => total + chunk.bytes.length, 0);
    if (freshBytes > RECENT_BYTES / 4) this.pieceBytes = Math.max(SMALLEST_PIECE_BYTES, this.pieceBytes >> 1);
    for (const chunk of fresh) {
      this.recent.push(chunk);
      this.recentBytes += chunk.bytes.length;
    }
    while (this.recent.length > 1 && this.recentBytes - this.recent[0].bytes.length >= RECENT_BYTES && endOf(this.recent[0]) <= readEnd) {
      this.recentBytes -= this.recent.shift().bytes.length;
    }
    return fresh;
  }

  // Yields what the kept output holds of the range from `next` to `end`; returns where it stopped.
  * recentFrom(next, end) {
    return yield* overlapOf(this.recent, next, end);
  }
}

// Yields the parts of `chunks` that lie from `next` to `end`; returns where the yielded bytes end.
// `chunks` follow on without a gap, the first one starting at or before `next`: a cursor starts
// at a point at or before the read and its output is one run (cursorFor).
function* overlapOf(chunks, next, end) {
  let reached = next;
  for (const { offset, bytes } of chunks) {
    const chunkEnd = offset + bytes.length;
    if (chunkEnd <= reached || reached >= end) continue;
    const part = bytes.subarray(reached - offset, Math.min(bytes.length, end - offset));
    reached += part.length;
    yield part;
  }
  return reached;
}

const endOf = (chunk) => chunk.offset + chunk.bytes.length;

const lastPointAtOrBefore = (points, offset) => {
  let low = 0;
  let high = points.length - 1;
  let found = null;
  while (low <= high) {
    const middle = (low + high) >> 1;
    if (points[middle].outputOffset <= offset) {
      found = points[middle];
      low = middle + 1;
    } else {
      high = middle - 1;
    }
  }
  return found;
};
