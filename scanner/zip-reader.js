// SPDX-License-Identifier: GPL-3.0-or-later
//
// Reads the table of contents of a zip. A zip describes every file twice (once in the table
// at the end, once in a header in front of the file's data), and unzip programs disagree on
// which copy wins. An archive can be built so that this reader and the program that later
// unpacks it see different files. So every disagreement found here is returned as a problem;
// the reader never settles one silently.

import { crc32 } from './crc32.js';

const SIGNATURE_LOCAL = 0x04034b50;
const SIGNATURE_CENTRAL = 0x02014b50;
const SIGNATURE_END = 0x06054b50;
const SIGNATURE_END64 = 0x06064b50;
const SIGNATURE_END64_LOCATOR = 0x07064b50;

const END_RECORD_BYTES = 22;
// The end record's last field, the length of the comment that follows it.
const END_COMMENT_LENGTH_AT = 20;
const END64_LOCATOR_BYTES = 20;
const END64_RECORD_BYTES = 56;
const CENTRAL_HEADER_BYTES = 46;
const MAX_COMMENT_BYTES = 0xffff;
const SIGNATURE_FIRST_BYTE = 0x50;

// How far from the end of a file the end record of a zip can start: itself plus the longest
// comment it may carry.
export const END_RECORD_REACH = END_RECORD_BYTES + MAX_COMMENT_BYTES;
const SENTINEL_16 = 0xffff;
const SENTINEL_32 = 0xffffffff;
const EXTRA_ZIP64 = 0x0001;
const EXTRA_UNICODE_PATH = 0x7075;
// That field holds a version byte, the CRC-32 of the plain name, then the name in UTF-8.
const UNICODE_PATH_CHECKSUM_AT = 1;
const UNICODE_PATH_NAME_AT = 5;
const FLAG_ENCRYPTED = 0x0001;
const FLAG_DATA_DESCRIPTOR = 0x0008;
const UNIX_FILE_TYPE_MASK = 0o170000;
const UNIX_SYMLINK = 0o120000;

export const LOCAL_HEADER_BYTES = 30;
export const METHOD_STORED = 0;
export const METHOD_DEFLATE = 8;
// A data descriptor after the file data is 12 to 24 bytes, depending on its optional
// signature and on zip64 sizes.
export const MAX_DESCRIPTOR_BYTES = 24;
export const MAX_ENTRIES = 1_000_000;
const MAX_DIRECTORY_BYTES = 256 * 1024 * 1024;

export class ZipFormatError extends Error {
  constructor(code, params = {}) {
    super(code);
    this.name = 'ZipFormatError';
    this.code = code;
    this.params = params;
  }
}

export const openZip = async (blob, maxEntries = MAX_ENTRIES) => {
  const problems = [];
  const end = await locateEndRecord(blob, problems);
  if (end.disk !== 0 || end.directoryDisk !== 0 || end.entriesOnDisk !== end.entriesTotal) {
    throw new ZipFormatError('multi_disk');
  }
  if (end.entriesTotal > maxEntries || end.directoryBytes > MAX_DIRECTORY_BYTES) {
    throw new ZipFormatError('too_many_entries', { entries: end.entriesTotal });
  }
  const table = await resolveDirectory(blob, end, problems);
  const directory = new Uint8Array(
    await blob.slice(table.directoryStart, table.directoryStart + table.directoryBytes).arrayBuffer(),
  );
  const entries = parseDirectory(directory, table, problems);
  flagDuplicateNames(entries, problems);
  return { entries, problems, directoryStart: table.directoryStart };
};

// Compares the header in front of a file's data with that file's row in the table of contents.
// `bytes` starts at the local header and may be shorter than the header turns out to be; the
// caller then reads more and calls again.
export const parseLocalHeader = (bytes, entry) => {
  const view = viewOf(bytes);
  if (view.getUint32(0, true) !== SIGNATURE_LOCAL) {
    return { signatureFound: false, headerBytes: 0, complete: true, differences: [], localName: '' };
  }
  const nameLength = view.getUint16(26, true);
  const extraLength = view.getUint16(28, true);
  const headerBytes = LOCAL_HEADER_BYTES + nameLength + extraLength;
  if (bytes.length < headerBytes) {
    return { signatureFound: true, headerBytes, complete: false, differences: [], localName: '' };
  }
  const flags = view.getUint16(6, true);
  const localNameBytes = bytes.subarray(LOCAL_HEADER_BYTES, LOCAL_HEADER_BYTES + nameLength);
  const sizes = localSizes(view, bytes.subarray(LOCAL_HEADER_BYTES + nameLength, headerBytes));
  // With a data descriptor the real sizes and checksum follow the data, and the local header
  // legitimately holds zeros.
  const deferred = (flags & FLAG_DATA_DESCRIPTOR) !== 0;
  const sizesAgree = sizes !== null
    && sizes.compressed === entry.compressedSize && sizes.uncompressed === entry.uncompressedSize;
  const sizesDeferred = deferred && sizes !== null && sizes.compressed === 0 && sizes.uncompressed === 0;
  const checksum = view.getUint32(14, true);

  const differences = [];
  if (!sameBytes(localNameBytes, entry.nameBytes)) differences.push('name');
  if (view.getUint16(8, true) !== entry.method) differences.push('method');
  if (((flags & FLAG_ENCRYPTED) !== 0) !== entry.isEncrypted) differences.push('encryption');
  if (!sizesAgree && !sizesDeferred) differences.push('size');
  if (checksum !== entry.crc32 && !(deferred && checksum === 0)) differences.push('checksum');
  return {
    signatureFound: true,
    headerBytes,
    complete: true,
    differences,
    localName: differences.includes('name') ? decodeName(localNameBytes) : '',
  };
};

// True when `tail` holds an end record that fits inside it, its comment included. Not only one
// that ends exactly at the end: Python's zipfile and Info-ZIP's unzip both unpack a zip glued
// behind a JPEG with 1 or 1,024 bytes after it (measured 2026-11-13), so one byte added would
// be enough to slip past that test. The signature alone turns up by chance in
// about one scan in seven of a 10,000-picture library, so this only picks the files worth
// opening; openZip still has to find the table of contents where the record points.
export const holdsEndRecord = (tail) => {
  const view = viewOf(tail);
  let at = tail.length - END_RECORD_BYTES;
  while (at >= 0) {
    at = tail.lastIndexOf(SIGNATURE_FIRST_BYTE, at);
    if (at < 0) return false;
    const isRecord = view.getUint32(at, true) === SIGNATURE_END;
    if (isRecord && endOfRecord(view, at) <= tail.length) return true;
    at -= 1;
  }
  return false;
};

// Where the end record that starts at `at` ends, its comment included.
const endOfRecord = (view, at) => at + END_RECORD_BYTES + view.getUint16(at + END_COMMENT_LENGTH_AT, true);

const locateEndRecord = async (blob, problems) => {
  if (blob.size < END_RECORD_BYTES) throw new ZipFormatError('not_a_zip');
  const tailStart = Math.max(0, blob.size - END_RECORD_BYTES - MAX_COMMENT_BYTES);
  const tail = new Uint8Array(await blob.slice(tailStart).arrayBuffer());
  const view = viewOf(tail);

  // A record whose comment runs exactly to the end of the file is what every reader accepts.
  // Two of those (one hidden inside the other's comment) mean readers that search from the
  // back and readers that search from the front open different archives.
  const endingAtFileEnd = [];
  let lastFitting = -1;
  for (let at = tail.length - END_RECORD_BYTES; at >= 0; at -= 1) {
    if (view.getUint32(at, true) !== SIGNATURE_END) continue;
    const recordEnd = endOfRecord(view, at);
    if (recordEnd === tail.length) endingAtFileEnd.push(at);
    else if (recordEnd < tail.length && lastFitting < 0) lastFitting = at;
  }
  if (endingAtFileEnd.length > 1) throw new ZipFormatError('ambiguous_end_record');
  const at = endingAtFileEnd.length === 1 ? endingAtFileEnd[0] : lastFitting;
  if (at < 0) throw new ZipFormatError('not_a_zip');
  if (holdsSecondArchive(view, at)) throw new ZipFormatError('ambiguous_end_record');
  if (endingAtFileEnd.length === 0) {
    const recordEnd = endOfRecord(view, at);
    problems.push({ code: 'trailing_data', path: '', params: { bytes: tail.length - recordEnd } });
  }

  const short = {
    position: tailStart + at,
    disk: view.getUint16(at + 4, true),
    directoryDisk: view.getUint16(at + 6, true),
    entriesOnDisk: view.getUint16(at + 8, true),
    entriesTotal: view.getUint16(at + 10, true),
    directoryBytes: view.getUint32(at + 12, true),
    directoryOffset: view.getUint32(at + 16, true),
  };
  return applyZip64EndRecord(blob, short);
};

// A whole second archive inside the comment of the chosen end record: another record there,
// with a table of contents right before it. Readers that take the last record in the file
// (Python's zipfile) open that archive and never list this one's files (a mu-plugin hidden
// that way once showed in zipfile and nowhere here). Only the bytes already read are looked
// at, so a comment full of signatures costs no extra reads.
const holdsSecondArchive = (view, at) => {
  const commentEnd = endOfRecord(view, at);
  for (let inner = commentEnd - END_RECORD_BYTES; inner > at; inner -= 1) {
    if (view.getUint32(inner, true) !== SIGNATURE_END) continue;
    const tableStart = inner - view.getUint32(inner + 12, true);
    if (tableStart >= 0 && view.getUint32(tableStart, true) === SIGNATURE_CENTRAL) return true;
  }
  return false;
};

// For an archive found behind a picture that openZip refused before it looked for the table of
// contents (too many entries, several disks): whether that table is where the end record
// points, right before the record or at the declared offset. If it is, the archive is real and
// not a chance signature among the picture's bytes (one with 50,001 entries once went unreported).
export const endRecordFindsTable = async (blob) => {
  let end;
  try {
    end = await locateEndRecord(blob, []);
  } catch (error) {
    if (error instanceof ZipFormatError) return false;
    throw error;
  }
  const tableBeforeRecord = await hasSignature(blob, end.structuresStart - end.directoryBytes, SIGNATURE_CENTRAL);
  return tableBeforeRecord || hasSignature(blob, end.directoryOffset, SIGNATURE_CENTRAL);
};

const applyZip64EndRecord = async (blob, short) => {
  const locatorAt = short.position - END64_LOCATOR_BYTES;
  if (locatorAt < 0) return { ...short, structuresStart: short.position };
  const locator = viewOf(new Uint8Array(await blob.slice(locatorAt, short.position).arrayBuffer()));
  if (locator.getUint32(0, true) !== SIGNATURE_END64_LOCATOR) {
    return { ...short, structuresStart: short.position };
  }

  // Data glued in front of the archive shifts every stored offset, so the record may sit
  // right before its locator instead of where the locator says.
  const declaredAt = readUint64(locator, 8);
  const candidates = [...new Set([declaredAt, locatorAt - END64_RECORD_BYTES])];
  const found = [];
  for (const candidate of candidates) {
    if (await hasSignature(blob, candidate, SIGNATURE_END64)) found.push(candidate);
  }
  if (found.length === 0) throw new ZipFormatError('directory_unreadable');
  if (found.length > 1) throw new ZipFormatError('ambiguous_end_record');
  const recordAt = found[0];
  const record = viewOf(new Uint8Array(await blob.slice(recordAt, recordAt + END64_RECORD_BYTES).arrayBuffer()));
  if (record.byteLength < END64_RECORD_BYTES) throw new ZipFormatError('directory_unreadable');
  const wide = {
    disk: record.getUint32(16, true),
    directoryDisk: record.getUint32(20, true),
    entriesOnDisk: readUint64(record, 24),
    entriesTotal: readUint64(record, 32),
    directoryBytes: readUint64(record, 40),
    directoryOffset: readUint64(record, 48),
  };

  // Some readers take the 64-bit record whenever it exists, others only when the short field
  // holds the "look in the 64-bit record" marker. If both carry real, different numbers,
  // those readers see different archives.
  const merged = { position: short.position, structuresStart: recordAt };
  for (const [field, marker] of [
    ['disk', SENTINEL_16], ['directoryDisk', SENTINEL_16], ['entriesOnDisk', SENTINEL_16],
    ['entriesTotal', SENTINEL_16], ['directoryBytes', SENTINEL_32], ['directoryOffset', SENTINEL_32],
  ]) {
    if (short[field] !== marker && short[field] !== wide[field]) {
      throw new ZipFormatError('ambiguous_end_record');
    }
    merged[field] = wide[field];
  }
  return merged;
};

// The end record plus where its table of contents really starts (`directoryStart`) and how far
// data glued in front of the archive shifts every stored offset (`baseOffset`).
const resolveDirectory = async (blob, end, problems) => {
  const startBeforeEndRecord = end.structuresStart - end.directoryBytes;
  const shift = startBeforeEndRecord - end.directoryOffset;
  if (startBeforeEndRecord < 0 || shift < 0) throw new ZipFormatError('directory_unreadable');
  if (end.entriesTotal === 0) {
    if (end.directoryBytes !== 0) throw new ZipFormatError('directory_unreadable');
    return { ...end, directoryStart: startBeforeEndRecord, baseOffset: 0 };
  }

  const declaredHolds = await hasSignature(blob, end.directoryOffset, SIGNATURE_CENTRAL);
  const shiftedHolds = shift > 0 && await hasSignature(blob, startBeforeEndRecord, SIGNATURE_CENTRAL);
  if (declaredHolds && shiftedHolds) throw new ZipFormatError('ambiguous_directory');
  if (shiftedHolds) return { ...end, directoryStart: startBeforeEndRecord, baseOffset: shift };
  if (!declaredHolds) throw new ZipFormatError('directory_unreadable');
  if (shift > 0) {
    // Readers that walk the table by its declared size stop here; readers that walk until the
    // signature runs out would go on and list more files.
    const tableContinues = await hasSignature(blob, end.directoryOffset + end.directoryBytes, SIGNATURE_CENTRAL);
    problems.push(tableContinues
      ? { code: 'directory_mismatch', path: '', params: {} }
      : { code: 'unlisted_bytes', path: '', params: { bytes: shift, offset: end.directoryOffset + end.directoryBytes } });
  }
  return { ...end, directoryStart: end.directoryOffset, baseOffset: 0 };
};

const parseDirectory = (directory, { entriesTotal, baseOffset }, problems) => {
  const view = viewOf(directory);
  const entries = [];
  let at = 0;
  for (let index = 0; index < entriesTotal; index += 1) {
    if (at + CENTRAL_HEADER_BYTES > directory.length || view.getUint32(at, true) !== SIGNATURE_CENTRAL) {
      throw new ZipFormatError('directory_unreadable');
    }
    const nameLength = view.getUint16(at + 28, true);
    const extraLength = view.getUint16(at + 30, true);
    const commentLength = view.getUint16(at + 32, true);
    const nameStart = at + CENTRAL_HEADER_BYTES;
    const next = nameStart + nameLength + extraLength + commentLength;
    if (next > directory.length) throw new ZipFormatError('directory_unreadable');

    const nameBytes = directory.subarray(nameStart, nameStart + nameLength);
    const extra = directory.subarray(nameStart + nameLength, nameStart + nameLength + extraLength);
    const flags = view.getUint16(at + 8, true);
    const externalAttributes = view.getUint32(at + 38, true);
    const wide = readZip64Extra(extra, {
      uncompressed: view.getUint32(at + 24, true),
      compressed: view.getUint32(at + 20, true),
      offset: view.getUint32(at + 42, true),
      disk: view.getUint16(at + 34, true),
    });
    const name = decodeName(nameBytes);
    const entry = {
      index,
      name,
      nameBytes,
      extraLength,
      method: view.getUint16(at + 10, true),
      crc32: view.getUint32(at + 16, true),
      compressedSize: wide ? wide.compressed : 0,
      uncompressedSize: wide ? wide.uncompressed : 0,
      headerOffset: wide ? wide.offset + baseOffset : 0,
      isDirectory: name.endsWith('/'),
      isSymlink: ((externalAttributes >>> 16) & UNIX_FILE_TYPE_MASK) === UNIX_SYMLINK,
      isEncrypted: (flags & FLAG_ENCRYPTED) !== 0,
      hasDescriptor: (flags & FLAG_DATA_DESCRIPTOR) !== 0,
      unreadable: unreadableReason(wide),
    };
    entries.push(entry);

    const unicodeName = readUnicodePath(extra, nameBytes);
    if (unicodeName !== null && unicodeName !== name) {
      // Info-ZIP and 7-Zip extract under this second name, most other tools under the first.
      problems.push({ code: 'unicode_path_differs', path: name, params: { otherName: unicodeName } });
    }
    at = next;
  }
  if (at !== directory.length) problems.push({ code: 'directory_mismatch', path: '', params: {} });
  return entries;
};

const unreadableReason = (wide) => {
  if (wide === null) return 'zip64';
  return wide.disk === 0 ? '' : 'other_disk';
};

const flagDuplicateNames = (entries, problems) => {
  const seen = new Set();
  for (const entry of entries) {
    if (seen.has(entry.name)) problems.push({ code: 'duplicate_name', path: entry.name, params: {} });
    seen.add(entry.name);
  }
};

// Each 64-bit value is present only when its short field holds the marker, in a fixed order.
const readZip64Extra = (extra, short) => {
  const wanted = [
    ['uncompressed', SENTINEL_32, 8], ['compressed', SENTINEL_32, 8],
    ['offset', SENTINEL_32, 8], ['disk', SENTINEL_16, 4],
  ].filter(([field, marker]) => short[field] === marker);
  if (wanted.length === 0) return short;
  const block = findExtraBlock(extra, EXTRA_ZIP64);
  const needed = wanted.reduce((total, [, , width]) => total + width, 0);
  if (block === null || block.length < needed) return null;
  const view = viewOf(block);
  const resolved = { ...short };
  let at = 0;
  for (const [field, , width] of wanted) {
    if (width === 4) {
      resolved[field] = view.getUint32(at, true);
    } else {
      const wide = view.getBigUint64(at, true);
      if (wide > BigInt(Number.MAX_SAFE_INTEGER)) return null;
      resolved[field] = Number(wide);
    }
    at += width;
  }
  return resolved;
};

const localSizes = (view, extra) => {
  const short = {
    uncompressed: view.getUint32(22, true),
    compressed: view.getUint32(18, true),
    offset: 0,
    disk: 0,
  };
  return readZip64Extra(extra, short);
};

// The "Unicode Path" extra field only applies while its stored checksum still matches the
// plain name; a stale one is ignored by the tools that honour the field.
const readUnicodePath = (extra, nameBytes) => {
  const block = findExtraBlock(extra, EXTRA_UNICODE_PATH);
  if (block === null || block.length < UNICODE_PATH_NAME_AT) return null;
  if (viewOf(block).getUint32(UNICODE_PATH_CHECKSUM_AT, true) !== crc32(nameBytes)) return null;
  return decodeName(block.subarray(UNICODE_PATH_NAME_AT));
};

const findExtraBlock = (extra, wantedId) => {
  const view = viewOf(extra);
  let at = 0;
  while (at + 4 <= extra.length) {
    const id = view.getUint16(at, true);
    const length = view.getUint16(at + 2, true);
    if (at + 4 + length > extra.length) return null;
    if (id === wantedId) return extra.subarray(at + 4, at + 4 + length);
    at += 4 + length;
  }
  return null;
};

const STRICT_UTF8 = new TextDecoder('utf-8', { fatal: true });

// Names that are not valid UTF-8 are mapped one byte to one character, so two different byte
// strings never collapse into the same invalid-character placeholder.
const decodeName = (bytes) => {
  try {
    return STRICT_UTF8.decode(bytes);
  } catch (error) {
    if (!(error instanceof TypeError)) throw error;
    return Array.from(bytes, (byte) => String.fromCharCode(byte)).join('');
  }
};

const hasSignature = async (blob, at, signature) => {
  if (at < 0 || at + 4 > blob.size) return false;
  const bytes = new Uint8Array(await blob.slice(at, at + 4).arrayBuffer());
  return viewOf(bytes).getUint32(0, true) === signature;
};

const readUint64 = (view, at) => {
  const wide = view.getBigUint64(at, true);
  if (wide > BigInt(Number.MAX_SAFE_INTEGER)) throw new ZipFormatError('directory_unreadable');
  return Number(wide);
};

const sameBytes = (left, right) => {
  if (left.length !== right.length) return false;
  for (let at = 0; at < left.length; at += 1) {
    if (left[at] !== right[at]) return false;
  }
  return true;
};

const viewOf = (bytes) => new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
