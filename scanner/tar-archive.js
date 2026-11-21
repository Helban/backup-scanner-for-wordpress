// SPDX-License-Identifier: GPL-3.0-or-later
//
// A .tar or .tar.gz opened as the archive the checks walk. The checks were written for a zip, so
// each tar entry is given the shape of a stored zip entry: its data lies in place (in the .tar,
// or in the unpacked .tar.gz that GzipSource reads by offset), `headerOffset` is where that data
// starts and the header in front of it counts as zero bytes. What tar has and zip has not (links
// that take another entry's data, an end marker, a lister and an extractor that may disagree)
// becomes the archive's `problems`, reported as tar.* findings. Worker side only.

import { ArchiveSource } from './entries.js';
import { GzipSource } from './gzip-source.js';
import { createTarIndexer } from './tar-reader.js';
import { MAX_ENTRIES, METHOD_STORED, ZipFormatError, openZip } from './zip-reader.js';

// A plain .tar is read whole once to find its headers; its data is not kept.
const INDEX_PIECE_BYTES = 1024 * 1024;
// A .tar.gz built to unpack forever (a few MB that unpack to terabytes) is stopped here: the
// largest honest backup we expect is a few GB, and one unpacking pass of 16 GB takes minutes.
export const TAR_UNPACKED_LIMIT_BYTES = 16 * 1024 * 1024 * 1024;

// The indexer's anomalies -> the problem codes the checks report as tar.<code>.
const ENTRY_PROBLEMS = new Map([['size_without_data', 'size_without_data'], ['file_named_as_folder', 'file_named_as_folder']]);

export class TarFormatError extends Error {
  constructor(code, params = {}) {
    super(code);
    this.name = 'TarFormatError';
    this.code = code;
    this.params = params;
  }
}

// `file` is the visitor's Blob, `packing` 'gzip' or 'none'. Returns { source, archive }.
export const openTar = async (file, packing, { maxEntries, alive }) => {
  const tarEntries = [];
  const indexer = createTarIndexer({ onEntry: (entry) => tarEntries.push(entry), maxEntries });
  const problems = [];
  let source;
  if (packing === 'gzip') {
    source = new GzipSource(file);
    const unpacking = await source.index((bytes) => indexer.push(bytes), { limitBytes: TAR_UNPACKED_LIMIT_BYTES, alive });
    if (unpacking.state === 'too_large') problems.push({ code: 'gzip_too_large', path: '', params: { bytes: TAR_UNPACKED_LIMIT_BYTES } });
    if (unpacking.state === 'damaged' || unpacking.state === 'truncated') {
      problems.push({ code: 'gzip_damaged', path: '', params: { offset: unpacking.bytes } });
    }
  } else {
    source = await indexInPlace(file, indexer, alive);
  }
  const listing = indexer.finish();
  if (listing.state === 'too_many') throw new TarFormatError('too_many_entries', { entries: maxEntries });
  if (tarEntries.length === 0 && listing.state !== 'ended') throw new TarFormatError('not_a_tar');
  // What the gzip layer already explains is not said a second time.
  const isUnpackingCut = problems.length > 0;
  if (listing.state === 'damaged') problems.push({ code: 'damaged', path: '', params: { entries: tarEntries.length } });
  if (!isUnpackingCut && listing.state === 'truncated') problems.push({ code: 'truncated', path: '', params: {} });
  if (!isUnpackingCut && listing.state === 'no_end') problems.push({ code: 'no_end', path: '', params: {} });
  if (listing.anomalies.includes('damaged_header')) problems.push({ code: 'damaged_header', path: '', params: { offset: listing.damagedAt } });
  const hidesEntries = listing.anomalies.includes('lone_zero_block') && listing.anomalies.includes('data_after_end');
  if (hidesEntries) problems.push({ code: 'data_after_lone_end', path: '', params: { offset: listing.endOffset } });
  else if (listing.anomalies.includes('data_after_end')) problems.push({ code: 'data_after_end', path: '', params: { offset: listing.endOffset } });

  const entries = asZipShaped(tarEntries, problems);
  const zipSide = await zipSideOf(file, packing, tarEntries);
  if (zipSide !== null) problems.push({ code: 'also_a_zip', path: zipSide, params: { zip_place: zipSide === '' ? 'outside' : 'near_end' } });
  return { source, archive: { format: 'tar', entries, problems, directoryStart: source.size } };
};

// A file can be a tar and a zip at once: an unzip program finds a zip's end record near the end
// of the file and unpacks that zip, a tar program unpacks the tar (Info-ZIP's unzip and Python's
// zipfile, measured 2026-11-21, tools/wp-zip-scan/tar-stage2/probe_polyglot.py). Until then this
// scanner read such a file as the zip. Returns null when the file opens as no zip; the name of
// the tar's file that holds the zip's table of contents (a zip near the end of the tar, which is
// also checked as a zip found in the copy, but there by gentler rules than the copy's own files);
// '' for a zip outside the tar's files, which is not checked at all. In a .tar.gz every zip
// structure lies in the packed file, outside the tar.
const zipSideOf = async (file, packing, tarEntries) => {
  let zip;
  try {
    zip = await openZip(file, MAX_ENTRIES);
  } catch (error) {
    if (!(error instanceof ZipFormatError)) throw error;
    // Two end records or two tables: unzip programs open one of them, so there is a zip.
    return error.code.startsWith('ambiguous_') ? '' : null;
  }
  if (packing === 'gzip') return '';
  const tableAt = zip.directoryStart;
  const holder = tarEntries.find((entry) => entry.dataOffset <= tableAt && tableAt < entry.dataOffset + entry.storedBytes);
  return holder === undefined ? '' : holder.name;
};

// Ceiling: the whole .tar is read to find its headers, 1-2 s per GB from a local disk. Reading
// only the headers (a slice per header, skipping the data) is the upgrade if that ever matters.
const indexInPlace = async (file, indexer, alive) => {
  const source = new ArchiveSource(file);
  for (let at = 0; at < file.size; at += INDEX_PIECE_BYTES) {
    const piece = new Uint8Array(await file.slice(at, at + INDEX_PIECE_BYTES).arrayBuffer());
    source.bytesRead += piece.length;
    indexer.push(piece);
    alive();
  }
  return source;
};

// Tar entries in the shape of stored zip entries (see the top of the file). A hard link takes the
// data of the entry it names, as an extractor gives it: the last one of that name before it.
const asZipShaped = (tarEntries, problems) => {
  const latestOf = new Map();
  const seen = new Set();
  return tarEntries.map((tarEntry, index) => {
    for (const anomaly of tarEntry.anomalies) {
      if (ENTRY_PROBLEMS.has(anomaly)) problems.push({ code: ENTRY_PROBLEMS.get(anomaly), path: tarEntry.name, params: {} });
    }
    const isDirectory = tarEntry.kind === 'directory';
    const { name } = tarEntry;
    if (!isDirectory && seen.has(name)) problems.push({ code: 'duplicate_name', path: name, params: {} });
    if (!isDirectory) seen.add(name);
    const data = tarEntry.kind === 'hardlink' ? latestOf.get(tarEntry.linkName) ?? null : tarEntry;
    // What an extractor writes: the stored data, which a link or a folder never has whatever its
    // size field says (tar.size_without_data). A sparse file is never read, and its size as
    // extracted stands for both sizes, which keeps it off the stored-size check.
    let size = 0;
    if (data !== null) size = data.readable ? data.storedBytes : data.size;
    const entry = {
      index,
      name,
      nameBytes: tarEntry.nameBytes,
      extraLength: 0,
      method: METHOD_STORED,
      crc32: null,
      compressedSize: size,
      uncompressedSize: size,
      headerOffset: data === null ? 0 : data.dataOffset,
      isDirectory,
      isSymlink: tarEntry.kind === 'symlink',
      isEncrypted: false,
      hasDescriptor: false,
      unreadable: unreadableReason(data),
    };
    if (data !== null && (tarEntry.kind === 'file' || tarEntry.kind === 'hardlink')) latestOf.set(tarEntry.name, data);
    return entry;
  });
};

// Data cut off by the end of the archive is found where it is read (entries.js locateTarData).
const unreadableReason = (data) => {
  if (data === null) return 'link_target_missing';
  return data.readable ? '' : 'sparse';
};
