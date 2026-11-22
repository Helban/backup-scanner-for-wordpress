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

import {
  TYPE_DIRECTORY, TYPE_FILE, TYPE_GNU_LONG_LINK, TYPE_GNU_LONG_NAME, TYPE_HARD_LINK, TYPE_OLD_FILE, TYPE_PAX, TYPE_PAX_GLOBAL, TYPE_SYMLINK,
  byteString, globalPaxIssue, headerFormIssue, headerSums, isFolderSpelling, localPaxIssue, longNameIssue, mightBeHeader, nameKey, pathIssue,
} from './tar-form.js';
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

const TYPE_GNU_SPARSE = 0x53;
const TYPE_GNU_DUMPDIR = 0x44;
// Solaris writes a pax extended header as 'X'. GNU tar 1.35, bsdtar and Python's tarfile apply it
// like 'x'; read as a file, it let an 'X' record name a mu-plugin the scan never listed
// (2026-11-21, tools/wp-zip-scan/tar-stage2/probe_extractors.py).
const TYPE_PAX_SOLARIS = 0x58;
const LOCAL_PAX_TYPES = new Set([TYPE_PAX, TYPE_PAX_SOLARIS]);
const DECIMAL = /^[0-9]+$/;
// Character device, block device, FIFO: no data, nothing to read.
const DEVICE_TYPES = new Set([0x33, 0x34, 0x36]);
// The types that carry no data whatever the size field says (GNU tar, Python's tarfile).
const TYPES_WITHOUT_DATA = new Set([TYPE_HARD_LINK, TYPE_SYMLINK, TYPE_DIRECTORY, ...DEVICE_TYPES]);

// Entry kinds: 'file', 'directory', 'symlink', 'hardlink', 'device'. A file is `readable` unless
// its data is sparse (holes the archive does not store, rebuilt only by an extractor).
//
// createTarIndexer({ onEntry, maxEntries }) -> { push(bytes), finish() }
//   onEntry({ name, nameBytes, kind, size, dataOffset, headerOffset, linkName, readable, otherNames, anomalies })
//     otherNames - names other tar programs write the same data under, where they read the
//                  records in front of the header differently (anomaly 'read_differently');
//                  'size_read_differently' when they read a different length of data
//   finish() -> { state, entries, endOffset, damagedAt, anomalies, unusual }, state one of
//     ended     - the end marker was found (bytes after it that are not zero: anomaly 'data_after_end')
//     no_end    - the data stopped at a header boundary without the end marker
//     truncated - it stopped inside a header or a file's data
//     damaged   - a long name or pax header is larger than META_LIMIT_BYTES; nothing after it
//                 is listed
//     too_many  - more than maxEntries entries; the rest is not listed
//   A block that should be a header and whose checksum or size is unreadable is skipped (anomaly
//   'damaged_header', the first such block at `damagedAt`), and listing goes on at the next
//   block that is one. A pax header whose records do not add up, or a pax size that is not a
//   decimal number, is ignored the way GNU tar, bsdtar and busybox ignore it (anomaly
//   'malformed_pax'; Python's tarfile refuses such an archive).
//   `unusual` is null for an archive written wholly in the canonical form of tar-form.js, else
//   { reason, offset } of the first place that is not: there the readings above are a best
//   effort, and the archive is reported for it (tar.unusual_form).
export const createTarIndexer = ({ onEntry, maxEntries }) => {
  let pending = new Uint8Array(0);
  let offset = 0;
  let state = 'header';
  let skipLeft = 0;
  // Zero bytes after the first zero block, before anything else: a proper end has a block more.
  let zerosAfterEnd = 0;
  let entries = 0;
  let endOffset = -1;
  let damagedAt = -1;
  let outcome = '';
  const archiveAnomalies = new Set();
  // What 'L', 'K' and 'x' records said about the next header, and what 'g' said about all.
  let next = nothingNext();
  let globalPax = new Map();
  // A global header that tar programs apply differently marks every file after it.
  let globalIrregular = false;
  let globalSizeDiffers = false;
  let meta = null;
  let unusual = null;
  // Names listed so far (tar-form.js nameKey -> whether every entry of it was a folder), and the
  // exact names of regular files, which are all a canonical hard link may point to.
  const seenNames = new Map();
  const fileNames = new Set();
  const symlinkNames = createFolderSet();

  const noteUnusual = (reason, at) => {
    if (unusual === null) unusual = { reason, offset: at };
  };

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
      if (hasOverride(next) || next.hasLongLink) noteUnusual('records_without_file', headerOffset);
      state = 'after_end';
      return true;
    }
    const form = headerFormIssue(header);
    // GNU tar 1.35 and bsdtar (the tar.exe of Windows) skip block by block to the next header
    // that adds up and unpack what follows; Python's tarfile and busybox stop (measured
    // 2026-11-21, tools/wp-zip-scan/tar-stage2/probe_damaged_header.py). Listing on as the first
    // two do keeps those files in the scan. A size nobody can read is skipped the same way: GNU
    // tar does ("Skipping to next header"), and busybox wrote the file behind such a header.
    const sizeField = hasValidChecksum(header) ? readNumber(header.subarray(SIZE_AT, SIZE_AT + SIZE_BYTES)) : null;
    if (sizeField === null) {
      // A block no tar program takes for a header is damage, or a dump that is no tar at all.
      if (mightBeHeader(header)) noteUnusual('header_read_differently', headerOffset);
      if (damagedAt < 0) damagedAt = headerOffset;
      archiveAnomalies.add('damaged_header');
      // GNU tar forgets a long name or pax record waiting for its header; the others keep it.
      if (hasOverride(next)) next.irregular = true;
      return true;
    }
    if (form !== '') noteUnusual(form, headerOffset);
    const type = header[TYPE_AT];
    if (type === TYPE_GNU_LONG_NAME || type === TYPE_GNU_LONG_LINK || LOCAL_PAX_TYPES.has(type) || type === TYPE_PAX_GLOBAL) {
      if (sizeField > META_LIMIT_BYTES) {
        noteUnusual('records_too_large', headerOffset);
        stop('damaged');
        return true;
      }
      // Canonical: one pax header, or a long name and a long link, in front of one file; a
      // global header only between files.
      const hasRecords = next.paxHeaders > 0 || next.longName !== null || next.hasLongLink;
      const isRepeated = (type === TYPE_GNU_LONG_NAME && next.longName !== null) || (type === TYPE_GNU_LONG_LINK && next.hasLongLink);
      const isMixed = (LOCAL_PAX_TYPES.has(type) || type === TYPE_PAX_GLOBAL) ? hasRecords : next.paxHeaders > 0;
      if (isRepeated || isMixed) noteUnusual('records', headerOffset);
      meta = { type, size: sizeField, padded: padded(sizeField), headerOffset };
      state = 'meta';
      return true;
    }
    const entry = describe(header, { headerOffset, sizeField, type });
    next = nothingNext();
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
    let isV7Folder = false;
    const anomalies = [];
    const isPosix = startsWith(header, MAGIC_AT, POSIX_MAGIC);
    let ownName = fieldBytes(header, NAME_AT, NAME_BYTES);
    // The prefix exists in POSIX ustar only; GNU keeps other fields in those bytes.
    if (isPosix) {
      const prefix = fieldBytes(header, PREFIX_AT, PREFIX_BYTES);
      if (prefix.length > 0) ownName = joinPath(prefix, ownName);
    }
    const globalPath = globalPax.has('path') ? ENCODER.encode(globalPax.get('path')) : null;
    let nameBytes = next.name ?? globalPath ?? ownName;
    // Where tar programs read the records in front of this header differently, every name one of
    // them writes the data under is kept: the archive checks the data under each of them.
    const isIrregular = next.irregular || globalIrregular;
    const otherNames = isIrregular ? otherNamesOf(nameBytes, [...next.otherNames, ownName, ...(globalPath ? [globalPath] : [])]) : [];
    if (isIrregular) anomalies.push('read_differently');
    if (next.sizeDiffers || globalSizeDiffers) anomalies.push('size_read_differently');
    // v7 has no folder type: a folder is a file whose name ends in "/". GNU tar reads it so for
    // both file types, Python's tarfile for the old one (NUL) only, so the new one is flagged.
    const endsInSlash = nameBytes.length > 0 && nameBytes[nameBytes.length - 1] === SLASH;
    if (endsInSlash && (type === TYPE_OLD_FILE || type === TYPE_FILE)) {
      if (type === TYPE_FILE) anomalies.push('file_named_as_folder');
      // v7's folder, read so by every program; the new file type with a slash is not.
      if (type === TYPE_OLD_FILE) isV7Folder = true;
      type = TYPE_DIRECTORY;
    }
    // A copy: the name is a view into the piece of input the header came in, and an entry that
    // kept the view kept that whole piece (256 KB to 1 MB). Over 58,478 entries that held 1.5 GB
    // of a 2.6 GB archive in memory until the scan ended (measured 2026-11-21, probe_memory.py).
    nameBytes = nameBytes.slice();
    const globalLink = globalPax.has('linkpath') ? ENCODER.encode(globalPax.get('linkpath')) : null;
    const linkField = fieldBytes(header, LINK_AT, NAME_BYTES);
    const linkBytes = next.linkName ?? globalLink ?? linkField;
    const size = next.size ?? sizeField;
    // busybox ignores a pax size: where it differs from the header's, programs read different
    // lengths. node-tar writes an equal one on every header, which is read alike.
    if (next.size !== null && next.size !== sizeField) anomalies.push('size_read_differently');
    const hasNoData = TYPES_WITHOUT_DATA.has(type);
    if (hasNoData && size > 0) anomalies.push('size_without_data');
    const entry = {
      nameBytes, linkBytes, writtenType, isDirectory: writtenType === TYPE_DIRECTORY || isV7Folder,
      hasData: !hasNoData, sizeField, size, hasOwnLink: linkField.length > 0 || next.linkName !== null,
    };
    const entryIssue = canonicalEntryIssue(entry);
    if (entryIssue !== '') noteUnusual(entryIssue, headerOffset);
    rememberEntry(entry);
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
      otherNames: otherNames.map((other) => decodeName(other)),
      anomalies,
    };
  };

  // The entry against tar-form.js's form and against the entries before it: a name each program
  // writes alike, no data on a link or folder, a pax size equal to the header's, a link name on
  // links only, a hard link to a regular file listed before it, and no name twice (folders
  // aside), so that which copy of a name ends up on disk never depends on the program.
  const canonicalEntryIssue = ({ nameBytes, linkBytes, writtenType, isDirectory, hasData, sizeField, size, hasOwnLink }) => {
    const pathProblem = pathIssue(nameBytes);
    if (pathProblem !== '') return pathProblem;
    if (!isDirectory && isFolderSpelling(nameBytes)) return 'name';
    if ((!hasData && sizeField !== 0) || size !== sizeField) return 'size';
    const isLink = writtenType === TYPE_HARD_LINK || writtenType === TYPE_SYMLINK;
    if (isLink ? linkBytes.length === 0 || linkBytes.includes(0) : hasOwnLink) return 'link';
    if (writtenType === TYPE_HARD_LINK && !fileNames.has(byteString(linkBytes))) return 'link';
    const key = nameKey(nameBytes);
    const wasFolder = seenNames.get(key);
    if (wasFolder !== undefined && !(wasFolder && isDirectory)) return 'duplicate_name';
    // A file under the name of an earlier symbolic link lands wherever that link points: tarfile
    // and busybox follow it (the third review's l18).
    return symlinkNames.passedBy(key) ? 'through_link' : '';
  };

  const rememberEntry = ({ nameBytes, writtenType, isDirectory }) => {
    const key = nameKey(nameBytes);
    seenNames.set(key, isDirectory && seenNames.get(key) !== false);
    if (writtenType === TYPE_SYMLINK) symlinkNames.add(key);
    if (!isDirectory && (writtenType === TYPE_FILE || writtenType === TYPE_OLD_FILE)) fileNames.add(byteString(nameBytes));
  };

  const readMeta = () => {
    if (pending.length < meta.padded) return false;
    const content = take(meta.padded).subarray(0, meta.size);
    const isLong = meta.type === TYPE_GNU_LONG_NAME || meta.type === TYPE_GNU_LONG_LINK;
    const paxIssue = meta.type === TYPE_PAX_GLOBAL ? globalPaxIssue : localPaxIssue;
    const issue = isLong ? longNameIssue(content) : paxIssue(content);
    if (issue !== '') noteUnusual(issue, meta.headerOffset);
    if (meta.type === TYPE_GNU_LONG_NAME) readLongName(fieldBytes(content, 0, content.length).slice());
    if (meta.type === TYPE_GNU_LONG_LINK) next.hasLongLink = true;
    if (meta.type === TYPE_GNU_LONG_LINK && !next.hasPaxLink) next.linkName = fieldBytes(content, 0, content.length).slice();
    if (LOCAL_PAX_TYPES.has(meta.type)) readLocalPax(readPaxHeader(content));
    if (meta.type === TYPE_PAX_GLOBAL) readGlobalPax(readPaxHeader(content));
    meta = null;
    state = 'header';
    return true;
  };

  // A long name after a pax path: GNU tar and tarfile keep the pax path, bsdtar and busybox take
  // the long name (2026-11-21). Before a pax path, every program lets the pax path win.
  const readLongName = (longName) => {
    next.longName = longName;
    if (next.hasPaxPath) {
      next.otherNames.push(longName);
      next.irregular = true;
    } else {
      next.name = longName;
    }
  };

  // GNU tar (and busybox) apply the records before the first malformed one; bsdtar applies none
  // of a malformed header; GNU tar alone reads a length followed by more than one blank. A second
  // pax header before one file replaces the first for GNU tar, adds to it for busybox and
  // tarfile, and stops bsdtar. Each reading's path is kept as a name of the file.
  const readLocalPax = (pax) => {
    next.paxHeaders += 1;
    if (next.paxHeaders > 1) {
      if (next.name !== null) next.otherNames.push(next.name);
      next.name = next.longName ?? null;
      next.hasPaxPath = false;
      next.irregular = true;
    }
    if (pax.isMalformed) {
      archiveAnomalies.add('malformed_pax');
      next.irregular = true;
    }
    for (const reading of pax.otherReadings) {
      const otherPath = usablePath(reading.get('path'));
      if (otherPath !== null) next.otherNames.push(otherPath);
      next.irregular = true;
    }
    applyPax(pax.records);
  };

  const readGlobalPax = (pax) => {
    if (pax.isMalformed || pax.otherReadings.length > 0) archiveAnomalies.add('malformed_pax');
    globalPax = new Map([...globalPax, ...pax.records]);
    // GNU tar and tarfile apply a global path or link name to every later file, bsdtar and
    // busybox ignore it; GNU tar alone applies a global size (2026-11-21).
    if (globalPax.has('path') || globalPax.has('linkpath') || pax.isMalformed) globalIrregular = true;
    if (globalPax.has('size')) globalSizeDiffers = true;
  };

  const applyPax = (records) => {
    if (records.has('path')) {
      const path = usablePath(records.get('path'));
      // An empty path or one holding NUL is read differently: GNU tar and bsdtar keep the
      // header's name for an empty one and cut at the NUL, tarfile takes it as it is.
      if (path === null || path.length !== ENCODER.encode(records.get('path')).length) next.irregular = true;
      if (path !== null) {
        next.name = path;
        next.hasPaxPath = true;
      }
    }
    if (records.has('linkpath')) {
      next.linkName = ENCODER.encode(records.get('linkpath'));
      next.hasPaxLink = true;
    }
    if (records.has('size')) {
      // GNU tar ignores a size that is not decimal ("invalid size=0x10") and busybox ignores
      // every pax size; describe() compares a decimal one with the header's.
      const size = decimalOrNull(records.get('size'));
      if (size === null) {
        archiveAnomalies.add('malformed_pax');
        next.sizeDiffers = true;
      } else {
        next.size = size;
      }
    }
    if ([...records.keys()].some((key) => key.startsWith('GNU.sparse.'))) next.sparse = true;
    // GNU's pax sparse formats: 1.0 names the file in GNU.sparse.name, 0.x and 1.0 give its size.
    if (records.has('GNU.sparse.name')) {
      const sparseName = usablePath(records.get('GNU.sparse.name'));
      if (records.has('path') || sparseName === null) next.irregular = true;
      if (next.name !== null && sparseName !== null) next.otherNames.push(next.name);
      if (sparseName !== null) next.name = sparseName;
    }
    const realSize = decimalOrNull(records.get('GNU.sparse.realsize') ?? records.get('GNU.sparse.size') ?? '');
    if (realSize !== null) next.realSize = realSize;
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
      if (outcome !== 'ended' && (hasOverride(next) || next.hasLongLink)) noteUnusual('records_without_file', offset);
      // Damage among entries: GNU tar and bsdtar read on behind it, and what they find there
      // depends on how each reads the damaged block. Damage with no entry at all is no tar (a
      // dump, engine.js), which is why it is noted only here.
      if (entries > 0 && damagedAt >= 0 && (unusual === null || damagedAt < unusual.offset)) {
        unusual = { reason: 'damaged_header', offset: damagedAt };
      }
      // Past a lone zero block busybox unpacks on and the rest stop (tar.data_after_lone_end).
      if (archiveAnomalies.has('lone_zero_block') && archiveAnomalies.has('data_after_end')) noteUnusual('lone_end', endOffset);
      return {
        state: outcome, entries: Math.min(entries, maxEntries), endOffset, damagedAt, anomalies: [...archiveAnomalies], unusual,
      };
    },
  };
};

// The first block of a file is a tar header: POSIX or GNU magic, or (v7, which has none) a
// checksum that adds up as this scanner or any tar program reads it.
export const looksLikeTar = (firstBlock) => (
  firstBlock.length >= BLOCK_BYTES
  && (startsWith(firstBlock, MAGIC_AT, POSIX_MAGIC.slice(0, 5)) || hasValidChecksum(firstBlock) || mightBeHeader(firstBlock))
);

// What the records in front of a header have said about it so far. `otherNames` are names some
// tar program writes the file under instead; `irregular` says the programs read those records
// differently; `sizeDiffers` that they read a different length of data.
const nothingNext = () => ({
  name: null, longName: null, linkName: null, size: null, realSize: null, sparse: false, hasPaxPath: false, hasPaxLink: false,
  hasLongLink: false, paxHeaders: 0, otherNames: [], irregular: false, sizeDiffers: false,
});

// Names, and whether one of them is a folder a given name lies in ("a/b" for "a/b/c"). A hash of
// each prefix, grown character by character, keeps that one pass over the name: looking up every
// prefix as a string costs its length each time, depth times length for a deep name.
const createFolderSet = () => {
  const byHash = new Map();
  return {
    add(key) {
      const hash = hashOf(key);
      if (!byHash.has(hash)) byHash.set(hash, []);
      byHash.get(hash).push(key);
    },
    passedBy(key) {
      if (byHash.size === 0) return false;
      let hash = 0;
      for (let at = 0; at < key.length; at += 1) {
        const candidates = key.charCodeAt(at) === SLASH && at > 0 ? byHash.get(hash) : undefined;
        if (candidates !== undefined && candidates.some((folder) => folder.length === at && key.startsWith(folder))) return true;
        hash = hashStep(hash, key.charCodeAt(at));
      }
      return false;
    },
  };
};

const PREFIX_HASH_BASE = 0x01000193;

const hashStep = (hash, code) => (Math.imul(hash, PREFIX_HASH_BASE) + code) | 0;

const hashOf = (key) => {
  let hash = 0;
  for (let at = 0; at < key.length; at += 1) hash = hashStep(hash, key.charCodeAt(at));
  return hash;
};

const hasOverride = (next) => next.name !== null || next.linkName !== null || next.size !== null || next.paxHeaders > 0;

const ENCODER = new TextEncoder();

// A name as GNU tar, bsdtar and busybox write it: cut at the first NUL. null when nothing is left.
const usablePath = (value) => {
  if (value === undefined) return null;
  const bytes = ENCODER.encode(value);
  const end = bytes.indexOf(0);
  const cut = end < 0 ? bytes : bytes.subarray(0, end);
  return cut.length === 0 ? null : cut.slice();
};

// The names in `candidates` that differ from `primary` and from each other, NUL-cut, none empty.
const otherNamesOf = (primary, candidates) => {
  const seen = new Set([PAX_DECODER.decode(primary)]);
  const others = [];
  for (const candidate of candidates) {
    const end = candidate.indexOf(0);
    const cut = end < 0 ? candidate : candidate.subarray(0, end);
    const text = PAX_DECODER.decode(cut);
    if (cut.length === 0 || seen.has(text)) continue;
    seen.add(text);
    others.push(cut.slice());
  }
  return others;
};

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
  const { unsigned, signed } = headerSums(header);
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
// A non-negative decimal number below 2^53, or null.
const decimalOrNull = (text) => {
  if (!DECIMAL.test(text)) return null;
  const number = Number(text);
  return Number.isSafeInteger(number) ? number : null;
};

// A pax header read twice ("<length> <key>=<value>\n" records, the length counting the whole
// record), because the tar programs part ways on what is not clean (measured 2026-11-21,
// tools/wp-zip-scan/tar-stage2/probe_extractors.py and the second Fable review's cases):
//   records       - GNU tar's reading, the one applied: blanks and tabs around the length are
//                   skipped, and the records before the first malformed one (or the first key
//                   holding NUL) count;
//   otherReadings - the reading of bsdtar, busybox and tarfile where it differs: exactly one
//                   blank after the length, a record whose key holds NUL passed over;
//   isMalformed   - a record whose length or form does not add up (bsdtar then applies none).
// Lengths are decimal digits only: Number() took "0x29", "+41" and "41e0". A byte order mark is
// kept: TextDecoder would drop it, and so turn "﻿path", a key nobody knows, into "path".
const readPaxHeader = (content) => {
  const gnu = readPaxRecords(content, { isLenient: true });
  const strict = readPaxRecords(content, { isLenient: false });
  const differs = gnu.records.size !== strict.records.size
    || [...gnu.records].some(([key, value]) => strict.records.get(key) !== value);
  return { records: gnu.records, otherReadings: differs ? [strict.records] : [], isMalformed: gnu.isMalformed || strict.isMalformed };
};

const PAX_DECODER = new TextDecoder('utf-8', { ignoreBOM: true });
const ASCII_TAB = 0x09;
const ASCII_NEWLINE = 0x0a;
const isBlank = (byte) => byte === ASCII_SPACE || byte === ASCII_TAB;

const readPaxRecords = (content, { isLenient }) => {
  const records = new Map();
  let at = 0;
  while (at < content.length && content[at] !== 0) {
    let digitsAt = at;
    if (isLenient) while (digitsAt < content.length && isBlank(content[digitsAt])) digitsAt += 1;
    let digitsEnd = digitsAt;
    while (digitsEnd < content.length && content[digitsEnd] >= ASCII_ZERO && content[digitsEnd] <= ASCII_ZERO + 9) digitsEnd += 1;
    const length = decimalOrNull(PAX_DECODER.decode(content.subarray(digitsAt, digitsEnd)));
    let keyAt = digitsEnd;
    if (isLenient) while (keyAt < content.length && isBlank(content[keyAt])) keyAt += 1;
    else if (content[keyAt] === ASCII_SPACE) keyAt += 1;
    const recordEnd = at + (length ?? 0);
    const isWellFormed = length !== null && keyAt > digitsEnd && recordEnd <= content.length && recordEnd > keyAt
      && content[recordEnd - 1] === ASCII_NEWLINE;
    if (!isWellFormed) return { records, isMalformed: true };
    const record = content.subarray(keyAt, recordEnd - 1);
    const equals = record.indexOf(0x3d);
    if (equals < 0) return { records, isMalformed: true };
    const key = record.subarray(0, equals);
    // GNU tar stops reading the header at a key holding NUL ("missing equal sign"); bsdtar and
    // busybox pass over that record and read on.
    if (key.includes(0)) {
      if (isLenient) return { records, isMalformed: false };
      at = recordEnd;
      continue;
    }
    records.set(PAX_DECODER.decode(key), PAX_DECODER.decode(record.subarray(equals + 1)));
    at = recordEnd;
  }
  return { records, isMalformed: false };
};
