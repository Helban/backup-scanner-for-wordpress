// SPDX-License-Identifier: GPL-3.0-or-later
//
// The table of contents of a tar archive, read from its bytes in order. A tar has no directory
// at the end like a zip: each file is a 512-byte header followed by its data, padded to 512, and
// the archive ends with zero blocks. So whether the bytes come from a .tar read in place or from
// a .tar.gz unpacked on the way, the list is built in one pass. File data is counted, not kept:
// each entry carries the offset of its data in the (unpacked) archive.
//
// Header variants read: v7, POSIX ustar (name split into prefix and name), GNU (long names in
// 'L'/'K' records, sizes in base-256), pax ('x' records: path, linkpath, size). What an archive
// does is decided the way GNU tar 1.35 and Python's tarfile extract it: the first zero block ends
// the archive, links and directories carry no data whatever their size field says, an unknown
// type is a regular file. Where the format leaves room to show one thing to a lister and another
// to an extractor, the entry or the archive carries an anomaly instead of a guess.

import { decodeName } from './zip-reader.js';

const BLOCK_BYTES = 512;
const NAME_AT = 0;
const NAME_BYTES = 100;
const MODE_AT = 100;
const SIZE_AT = 124;
const SIZE_BYTES = 12;
const CHECKSUM_AT = 148;
const CHECKSUM_BYTES = 8;
const TYPE_AT = 156;
const LINK_AT = 157;
const MAGIC_AT = 257;
const PREFIX_AT = 345;
const PREFIX_BYTES = 155;
const GNU_REAL_SIZE_AT = 483;
const ASCII_SPACE = 0x20;
const SLASH = 0x2f;
const ASCII_ZERO = 0x30;
const BASE_256_MARK = 0x80;
// "ustar\0" at MAGIC_AT is POSIX (version "00"); GNU writes "ustar  \0" and keeps other fields
// where POSIX has the name's prefix.
const POSIX_MAGIC = [0x75, 0x73, 0x74, 0x61, 0x72, 0x00];
// A long name or a pax record larger than this is not a name an honest archive writes.
const META_LIMIT_BYTES = 1024 * 1024;

const TYPE_FILE = 0x30;
const TYPE_OLD_FILE = 0x00;
const TYPE_HARD_LINK = 0x31;
const TYPE_SYMLINK = 0x32;
const TYPE_DIRECTORY = 0x35;
const TYPE_GNU_LONG_NAME = 0x4c;
const TYPE_GNU_LONG_LINK = 0x4b;
const TYPE_GNU_SPARSE = 0x53;
const TYPE_GNU_DUMPDIR = 0x44;
const TYPE_PAX = 0x78;
const TYPE_PAX_GLOBAL = 0x67;
// Character device, block device, FIFO: no data, nothing to read.
const DEVICE_TYPES = new Set([0x33, 0x34, 0x36]);
// The types that carry no data whatever the size field says (GNU tar, Python's tarfile).
const TYPES_WITHOUT_DATA = new Set([TYPE_HARD_LINK, TYPE_SYMLINK, TYPE_DIRECTORY, ...DEVICE_TYPES]);

// Entry kinds: 'file', 'directory', 'symlink', 'hardlink', 'device'. A file is `readable` unless
// its data is sparse (holes the archive does not store, rebuilt only by an extractor).
//
// createTarIndexer({ onEntry, maxEntries }) -> { push(bytes), finish() }
//   onEntry({ name, nameBytes, kind, size, dataOffset, headerOffset, linkName, readable, anomalies })
//   finish() -> { state, entries, endOffset, anomalies }, state one of
//     ended     - the end marker was found (bytes after it that are not zero: anomaly 'data_after_end')
//     no_end    - the data stopped at a header boundary without the end marker
//     truncated - it stopped inside a header or a file's data
//     damaged   - a header's checksum or size is wrong; nothing after it is listed
//     too_many  - more than maxEntries entries; the rest is not listed
export const createTarIndexer = ({ onEntry, maxEntries }) => {
  let pending = new Uint8Array(0);
  let offset = 0;
  let state = 'header';
  let skipLeft = 0;
  // Zero bytes after the first zero block, before anything else: a proper end has a block more.
  let zerosAfterEnd = 0;
  let entries = 0;
  let endOffset = -1;
  let outcome = '';
  const archiveAnomalies = new Set();
  // What 'L', 'K' and 'x' records said about the next header, and what 'g' said about all.
  let next = { ...NOTHING_NEXT };
  let globalPax = new Map();
  let meta = null;

  const stop = (reason) => {
    outcome = reason;
    state = 'over';
  };

  const take = (count) => {
    const bytes = pending.subarray(0, count);
    pending = pending.subarray(count);
    offset += count;
    return bytes;
  };

  const readHeader = () => {
    if (pending.length < BLOCK_BYTES) return false;
    const headerOffset = offset;
    const header = take(BLOCK_BYTES);
    if (header.every((byte) => byte === 0)) {
      // The first zero block ends the archive for GNU tar and Python; a second one is the
      // proper end. A header after a lone zero block is not extracted, so it is no entry.
      endOffset = headerOffset;
      state = 'after_end';
      return true;
    }
    if (!hasValidChecksum(header)) {
      stop('damaged');
      return true;
    }
    const sizeField = readNumber(header.subarray(SIZE_AT, SIZE_AT + SIZE_BYTES));
    if (sizeField === null) {
      stop('damaged');
      return true;
    }
    const type = header[TYPE_AT];
    if (type === TYPE_GNU_LONG_NAME || type === TYPE_GNU_LONG_LINK || type === TYPE_PAX || type === TYPE_PAX_GLOBAL) {
      if (sizeField > META_LIMIT_BYTES) {
        stop('damaged');
        return true;
      }
      meta = { type, size: sizeField, padded: padded(sizeField) };
      state = 'meta';
      return true;
    }
    const entry = describe(header, { headerOffset, sizeField, type });
    next = { ...NOTHING_NEXT };
    entries += 1;
    if (entries > maxEntries) {
      stop('too_many');
      return true;
    }
    onEntry(entry);
    skipLeft = padded(entry.storedBytes);
    state = 'data';
    return true;
  };

  const describe = (header, { headerOffset, sizeField, type: writtenType }) => {
    let type = writtenType;
    const anomalies = [];
    const isPosix = startsWith(header, MAGIC_AT, POSIX_MAGIC);
    let nameBytes = fieldBytes(header, NAME_AT, NAME_BYTES);
    // The prefix exists in POSIX ustar only; GNU keeps other fields in those bytes.
    if (isPosix) {
      const prefix = fieldBytes(header, PREFIX_AT, PREFIX_BYTES);
      if (prefix.length > 0) nameBytes = joinPath(prefix, nameBytes);
    }
    const paxPath = next.name ?? globalPax.get('path') ?? null;
    if (paxPath !== null) nameBytes = paxPath;
    // v7 has no folder type: a folder is a file whose name ends in "/". GNU tar reads it so for
    // both file types, Python's tarfile for the old one (NUL) only, so the new one is flagged.
    const endsInSlash = nameBytes.length > 0 && nameBytes[nameBytes.length - 1] === SLASH;
    if (endsInSlash && (type === TYPE_OLD_FILE || type === TYPE_FILE)) {
      if (type === TYPE_FILE) anomalies.push('file_named_as_folder');
      type = TYPE_DIRECTORY;
    }
    const linkBytes = next.linkName ?? globalPax.get('linkpath') ?? fieldBytes(header, LINK_AT, NAME_BYTES);
    const size = next.size ?? sizeField;
    const hasNoData = TYPES_WITHOUT_DATA.has(type);
    if (hasNoData && size > 0) anomalies.push('size_without_data');
    const isSparse = next.sparse || type === TYPE_GNU_SPARSE;
    const storedBytes = hasNoData ? 0 : size;
    // A sparse file's stored data is not its contents; its size as extracted is kept apart.
    const gnuRealSize = type === TYPE_GNU_SPARSE ? readNumber(header.subarray(GNU_REAL_SIZE_AT, GNU_REAL_SIZE_AT + SIZE_BYTES)) : null;
    return {
      name: decodeName(nameBytes),
      nameBytes,
      kind: kindOf(type),
      size: next.realSize ?? gnuRealSize ?? size,
      storedBytes,
      dataOffset: headerOffset + BLOCK_BYTES,
      headerOffset,
      linkName: decodeName(linkBytes),
      mode: readNumber(header.subarray(MODE_AT, MODE_AT + 8)) ?? 0,
      readable: !isSparse,
      anomalies,
    };
  };

  const readMeta = () => {
    if (pending.length < meta.padded) return false;
    const content = take(meta.padded).subarray(0, meta.size);
    if (meta.type === TYPE_GNU_LONG_NAME) next.name = fieldBytes(content, 0, content.length);
    if (meta.type === TYPE_GNU_LONG_LINK) next.linkName = fieldBytes(content, 0, content.length);
    if (meta.type === TYPE_PAX || meta.type === TYPE_PAX_GLOBAL) {
      const records = readPaxRecords(content);
      if (records === null) {
        stop('damaged');
        return true;
      }
      if (meta.type === TYPE_PAX_GLOBAL) {
        globalPax = new Map([...globalPax, ...records]);
      } else {
        applyPax(records);
      }
    }
    meta = null;
    state = 'header';
    return true;
  };

  const applyPax = (records) => {
    const encoder = new TextEncoder();
    if (records.has('path')) next.name = encoder.encode(records.get('path'));
    if (records.has('linkpath')) next.linkName = encoder.encode(records.get('linkpath'));
    if (records.has('size')) {
      const size = Number(records.get('size'));
      if (Number.isSafeInteger(size) && size >= 0) next.size = size;
    }
    if ([...records.keys()].some((key) => key.startsWith('GNU.sparse.'))) next.sparse = true;
    // GNU's pax sparse formats: 1.0 names the file in GNU.sparse.name, 0.x and 1.0 give its size.
    if (records.has('GNU.sparse.name')) next.name = encoder.encode(records.get('GNU.sparse.name'));
    const realSize = Number(records.get('GNU.sparse.realsize') ?? records.get('GNU.sparse.size'));
    if (Number.isSafeInteger(realSize) && realSize >= 0) next.realSize = realSize;
  };

  const skipData = () => {
    const count = Math.min(skipLeft, pending.length);
    take(count);
    skipLeft -= count;
    if (skipLeft > 0) return false;
    state = 'header';
    return true;
  };

  // Once something other than zeros shows up, the rest is only noted.
  const readAfterEnd = () => {
    if (archiveAnomalies.has('data_after_end')) {
      take(pending.length);
      return false;
    }
    const zeros = pending.findIndex((byte) => byte !== 0);
    const zeroBytes = zeros < 0 ? pending.length : zeros;
    zerosAfterEnd += zeroBytes;
    take(zeroBytes);
    if (zeros >= 0) {
      archiveAnomalies.add('data_after_end');
      take(pending.length);
    }
    return false;
  };

  const STEPS = { header: readHeader, meta: readMeta, data: skipData, after_end: readAfterEnd };

  const run = () => {
    let moved = true;
    while (moved && state !== 'over') moved = STEPS[state]();
  };

  return {
    push(bytes) {
      if (state === 'over') return;
      if (state === 'data' && pending.length === 0) {
        // File data is only counted, so most of the archive never gets copied here.
        const skipped = Math.min(skipLeft, bytes.length);
        offset += skipped;
        skipLeft -= skipped;
        bytes = bytes.subarray(skipped);
        if (skipLeft === 0) state = 'header';
      }
      if (bytes.length === 0) return;
      const joined = new Uint8Array(pending.length + bytes.length);
      joined.set(pending);
      joined.set(bytes, pending.length);
      pending = joined;
      run();
    },
    finish() {
      run();
      if (outcome === '') {
        if (state === 'after_end') {
          outcome = 'ended';
          if (zerosAfterEnd < BLOCK_BYTES) archiveAnomalies.add('lone_zero_block');
        } else if (state === 'header' && pending.length === 0) {
          outcome = 'no_end';
        } else {
          outcome = 'truncated';
        }
      }
      return { state: outcome, entries: Math.min(entries, maxEntries), endOffset, anomalies: [...archiveAnomalies] };
    },
  };
};

const NOTHING_NEXT = Object.freeze({ name: null, linkName: null, size: null, realSize: null, sparse: false });

const kindOf = (type) => {
  if (type === TYPE_DIRECTORY || type === TYPE_GNU_DUMPDIR) return 'directory';
  if (type === TYPE_SYMLINK) return 'symlink';
  if (type === TYPE_HARD_LINK) return 'hardlink';
  if (DEVICE_TYPES.has(type)) return 'device';
  return 'file';
};

const padded = (bytes) => Math.ceil(bytes / BLOCK_BYTES) * BLOCK_BYTES;

const startsWith = (bytes, at, expected) => expected.every((byte, index) => bytes[at + index] === byte);

// The bytes of a NUL-terminated field.
const fieldBytes = (bytes, at, length) => {
  const field = bytes.subarray(at, at + length);
  const end = field.indexOf(0);
  return end < 0 ? field : field.subarray(0, end);
};

const joinPath = (prefix, name) => {
  const joined = new Uint8Array(prefix.length + 1 + name.length);
  joined.set(prefix);
  joined[prefix.length] = SLASH;
  joined.set(name, prefix.length + 1);
  return joined;
};

// The checksum is the sum of the header's bytes with its own field counted as spaces. Old tars
// summed signed bytes; GNU tar and Python accept either.
const hasValidChecksum = (header) => {
  const stored = readNumber(header.subarray(CHECKSUM_AT, CHECKSUM_AT + CHECKSUM_BYTES));
  if (stored === null) return false;
  let unsigned = 0;
  let signed = 0;
  for (let index = 0; index < BLOCK_BYTES; index += 1) {
    const byte = index >= CHECKSUM_AT && index < CHECKSUM_AT + CHECKSUM_BYTES ? ASCII_SPACE : header[index];
    unsigned += byte;
    signed += byte > 127 ? byte - 256 : byte;
  }
  return stored === unsigned || stored === signed;
};

// An octal field (digits, padded with spaces or NULs), or GNU's base-256 when its first byte
// has the high bit set. null when it is neither, or past 2^53 (a negative base-256 number starts
// with 0xff, so it is always that far).
const readNumber = (field) => {
  if (field[0] & BASE_256_MARK) {
    let value = field[0] & ~BASE_256_MARK;
    for (let index = 1; index < field.length; index += 1) value = value * 256 + field[index];
    return Number.isSafeInteger(value) ? value : null;
  }
  let index = 0;
  while (index < field.length && (field[index] === ASCII_SPACE || field[index] === 0)) index += 1;
  let value = 0;
  for (; index < field.length; index += 1) {
    const byte = field[index];
    if (byte === 0 || byte === ASCII_SPACE) break;
    const digit = byte - ASCII_ZERO;
    if (digit < 0 || digit > 7) return null;
    value = value * 8 + digit;
  }
  return value;
};

// "<length> <key>=<value>\n" records, the length counting the whole record. null when a record
// does not add up.
const readPaxRecords = (content) => {
  const records = new Map();
  const decoder = new TextDecoder('utf-8');
  let at = 0;
  while (at < content.length) {
    if (content[at] === 0) break;
    const space = content.indexOf(ASCII_SPACE, at);
    if (space < 0) return null;
    const length = Number(decoder.decode(content.subarray(at, space)));
    if (!Number.isSafeInteger(length) || length <= space - at || at + length > content.length || content[at + length - 1] !== 0x0a) return null;
    const record = decoder.decode(content.subarray(space + 1, at + length - 1));
    const equals = record.indexOf('=');
    if (equals < 0) return null;
    records.set(record.slice(0, equals), record.slice(equals + 1));
    at += length;
  }
  return records;
};
