// SPDX-License-Identifier: GPL-3.0-or-later
//
// The scan itself. Runs inside the worker: it is the only code that touches bytes from the
// archive, and all it hands out are events of a fixed shape (see protocol.js).

import { sha256Hex, verifyComponents } from './checksums.js';
import { chooseCodeFindings } from './code-rules.js';
import { CONFIG_FILE_NAMES, findApacheSignals, findIniSignals } from './config-rules.js';
import { crc32 } from './crc32.js';
import { checkDatabases, isDatabaseDump } from './database.js';
import {
  ArchiveSource, DAMAGED, PROGRESS_INTERVAL_MS, READ_AHEAD_BYTES, TIME, isReadable, isSupportedMethod, locateData, readPrefix,
  readThrough, readSmallFile, readWholeFile,
} from './entries.js';
import { excerptOfLine } from './excerpt.js';
import { KNOWN_FILES, KNOWN_NAMES } from './indicators.js';
import { inflateAll, inflaterFor } from './inflate.js';
import { CodeTimeLimitError, CodeTooLargeError, createClock } from './php-lexer.js';
import { findCodeSignals, holdsOnlyLiterals } from './php-rules.js';
import { createProgramScanner } from './program-scan.js';
import { exitsAtOnce, isInertPhp } from './php-text.js';
import { NESTED_SEPARATOR, RULES } from './rules.js';
import { deceptiveCharacters } from './sanitize.js';
import { findInstruction } from './text-rules.js';
import {
  EXECUTABLE_EXTENSIONS, IMAGE_EXTENSIONS, PASSIVE_EXTENSIONS, PHP_EXTENSIONS, SCRIPT_EXTENSIONS, SERVER_SCRIPT_EXTENSIONS,
  TEXT_FILE_EXTENSIONS,
  archiveKind, archiveNameClass, doubleExtensionKind, executableKind, extensionOf, holdsPhpOpenTag, isZipKind,
  startsLikeAnImage, stripTrailingDotsAndSpaces,
} from './signatures.js';
import {
  END_RECORD_REACH, MAX_DESCRIPTOR_BYTES, MAX_ENTRIES, METHOD_DEFLATE, METHOD_STORED, ZipFormatError, endRecordFindsTable,
  holdsEndRecord, openZip,
} from './zip-reader.js';

const HEAD_BYTES = 4096;
// Deflate can make data a little longer, so more packed bytes than HEAD_BYTES are fetched.
const HEAD_PACKED_BYTES = 6144;
// A stream built to emit nothing for a long stretch gets this much input before the scanner
// gives up on its first bytes and says so.
const HEAD_PACKED_LIMIT = 1024 * 1024;
const DENSE_LOOKAHEAD_ENTRIES = 16;
// The page ends a scan after 10 s without a message (main.js STALL_LIMIT_MS). Unpacking the end
// of one large film or hashing one large file can take longer than that, so the reading loop
// says it is alive in between (a 1 GB film took 1.2 s on a fast disk, a slower one takes more).
const HEARTBEAT_INTERVAL_MS = 1_000;
const FINDINGS_PER_RULE = 500;
const GAP_INSPECT_BUDGET_BYTES = 64 * 1024 * 1024;
const GAP_CHUNK_BYTES = 1024 * 1024;
const LISTED_COMPONENTS = 300;
const LISTED_DATABASES = 20;
const LISTED_SITE_HOSTS = 20;
// A name built to deceive can hold any number of such characters; a few say what they are.
const LISTED_DECEPTIVE_CODES = 5;
// WordPress reads the header of a plugin's main file and of a theme's style.css from the first 8 KB.
const FILE_HEADER_BYTES = 8192;

// PHP read as code. The largest honest PHP file in the test copies has 1.1 MB, so 8 MB leaves
// room. Two seconds per file keeps a file built to stall the reader from holding the scan; honest files take
// milliseconds.
const CODE_FILE_LIMIT_BYTES = 8 * 1024 * 1024;
const CODE_FILE_TIME_MS = 2000;
const LISTED_LOADED_FILES = 300;
// An honest .htaccess is a few kilobytes; security plugins' block lists reach a few hundred.
const CONFIG_FILE_LIMIT_BYTES = 1024 * 1024;
// Files whose first bytes are read for sentences aimed at an AI assistant.
const TEXT_EXTENSIONS = new Set(['.txt', '.md', '.html', '.htm', '.json', '.xml', '.js', '.css', '.svg', '.csv', '.log']);

// Archives inside the copy: one level deep, zip only, inside hard limits. Whatever falls
// outside a limit is reported as not opened, with the limit that stopped it.
const NESTED_MAX_ARCHIVES = 200;
const NESTED_MAX_ENTRIES = 50_000;
const NESTED_UNPACKED_LIMIT_BYTES = 64 * 1024 * 1024;
const NESTED_TOTAL_UNPACKED_BYTES = 512 * 1024 * 1024;
const NESTED_ARCHIVE_TIME_MS = 10_000;
const NESTED_TOTAL_TIME_MS = 60_000;
const NESTED_SKIPPED_LISTED = 20;
// A zip glued behind a real picture (or font, film, PDF) keeps its table of contents at the
// end of the file, so the end of every such file is read. A deflated one has to be unpacked
// whole to get there: 12 s for the 1.8 GB of pictures in the 2 GB test copy, measured
// 2026-11-12. Past this allowance the rest is counted as not read to the end.
const TAIL_TOTAL_TIME_MS = 60_000;
const BEHIND_MEDIA_KIND = 'zip_behind_media';
// Files with a red finding get their SHA-256 into the report, so that a visitor can look one
// up or report it without handing the file to anybody. A file is hashed in memory, hence the
// size limit; the count and the time keep an archive built of red files from holding the scan.
const HASHED_FILE_LIMIT_BYTES = 64 * 1024 * 1024;
const HASHED_FILES = 50;
// The page takes at most this many paths in one list (protocol.js); rows past it show no hash.
const HASHED_FINDINGS_PER_FILE = 300;
const HASHING_TOTAL_TIME_MS = 15_000;

const VERSION_FILE = 'wp-includes/version.php';
const CONFIG_FILE = 'wp-config.php';
const SETTINGS_FILE = 'wp-settings.php';
const LOCAL_HEADER_SIGNATURE = [0x50, 0x4b, 0x03, 0x04];
const LOCALE_FORMAT = /^[a-z]{2,3}(_[A-Z]{2})?(_[a-z0-9]+)?$/;
const VERSION_FORMAT = /^[0-9A-Za-z.+-]{1,32}$/;
const NOT_OPENED_REASONS = new Map([
  ['not_a_zip', 'damaged'], ['directory_unreadable', 'damaged'],
  ['multi_disk', 'multi_part'], ['too_many_entries', 'too_many_entries'],
]);
const REFUSED_BEFORE_TABLE = new Set(['multi_disk', 'too_many_entries']);

class TimeLimitError extends Error {
  constructor() {
    super('time limit for one nested archive');
    this.name = 'TimeLimitError';
  }
}

// `lookup(question)` asks the page to fetch the official checksum lists and resolves with the
// answers; it is the worker's only way to learn anything from the network. With `online` off
// it is never called.
export const scanArchive = async (file, { emit, lookup, online }) => {
  const started = performance.now();
  const names = createWrittenNames(emit);
  const reporter = createReporter(names.emit);
  const source = new ArchiveSource(file);
  let completed = true;
  try {
    // Before the zip is opened: the file is what it is even when it opens as no zip at all.
    await checkChosenFile(source, reporter);
    await scanCopy(source, reporter, { emit: names.emit, lookup, online, names });
  } catch (error) {
    completed = false;
    if (error instanceof ZipFormatError) {
      reporter.report(`zip.${error.code}`, '', error.params);
    } else {
      reporter.report('scan.failed', '', { error: String(error.name), detail: String(error.message) });
    }
  }
  reporter.reportOverflow();
  emit({
    type: 'done',
    completed,
    bytesRead: source.bytesRead,
    milliseconds: Math.round(performance.now() - started),
  });
};

const scanCopy = async (source, reporter, options) => {
  const { emit, names } = options;
  const unpacked = asUnpacked(await openZip(source.blob, MAX_ENTRIES));
  const part = contentPartOf(unpacked);
  const isPart = part !== null;
  const archive = part ?? unpacked;
  names.show(archive, isPart ? CONTENT_PART_FOLDER : '');
  const files = archive.entries.filter((entry) => !entry.isDirectory);
  emit({
    type: 'opened',
    files: files.length,
    folders: archive.entries.length - files.length,
    declaredBytes: files.reduce((total, entry) => total + entry.uncompressedSize, 0),
  });

  const copy = {
    source,
    archive,
    reporter,
    isNested: false,
    isBehindMedia: false,
    deadline: Infinity,
    nestedCandidates: [],
    tails: { until: performance.now() + TAIL_TOTAL_TIME_MS, skippedFiles: 0, skippedBytes: 0 },
    progress: (update) => emit({ type: 'progress', ...update }),
    alive: createHeartbeat(emit),
  };
  const described = describeSite(archive.entries);
  const core = described.versionEntry ? await readCoreIdentity(copy, described.versionEntry) : null;
  const site = { ...described, core };
  emit({
    type: 'facts',
    root: site.root,
    version: core ? core.version : '',
    locale: core ? core.locale : '',
    plugins: site.plugins,
    themes: site.themes,
    databases: site.databases,
  });
  if (isPart) reporter.report('scan.content_part', '', {});
  if (!site.looksLikeWordPress) reporter.report('scan.not_wordpress', '', {});
  for (const otherRoot of site.otherRoots) reporter.report('scan.other_wordpress', otherRoot, {});
  for (const otherCopy of site.otherCopies) reporter.report('scan.other_copy', otherCopy, {});

  const comparison = site.looksLikeWordPress ? await startComparison(copy, site, options) : null;
  await checkContainer(copy);
  const verified = comparison ? await finishComparison(copy, comparison, emit) : new Set();
  const loaded = await checkCode(copy, site, verified);
  emit({ type: 'loaded_code', total: loaded.length, files: loaded.slice(0, LISTED_LOADED_FILES) });
  const siteHosts = await checkDatabase(copy, site);
  // Scripts and redirects to these hosts are not reported, and the dump decides which they are,
  // so the visitor is shown them: a copy's author can add a host of their own.
  emit({ type: 'site_hosts', hosts: [...siteHosts].slice(0, LISTED_SITE_HOSTS) });
  await checkConfigFiles(copy, verified, siteHosts);
  await openNestedArchives(copy, emit, verified);
  const { skippedFiles, skippedBytes } = copy.tails;
  if (skippedFiles > 0) copy.reporter.report('archive.tail_not_checked', '', { files: skippedFiles, bytes: skippedBytes });
  emit({ type: 'hashes', files: await hashRedFiles(copy, reporter.redFiles()) });
};

// UpdraftPlus splits a backup into zips of its own for plugins, themes, uploads and the rest of
// wp-content ("others"), each holding its folder by name with no wp-content above it
// (make_zipfile in updraftplus/backup.php: plugins/<slug>/..., mu-plugins/..., drop-ins at the
// top). Such a part is checked as the inside of wp-content: every check reads its names with
// CONTENT_PART_FOLDER in front, and the names leave the worker as written (createWrittenNames).
// Read without it, the plugins of such a part were compared with nothing and their README files
// with PHP examples were red, while its mu-plugins were not taken for mu-plugins.
const CONTENT_PART_FOLDER = 'wp-content/';
const CONTENT_PART_MARKS = new Set(['plugins', 'themes', 'uploads', 'mu-plugins', 'languages']);
// A plugin or a theme can ship a wp-content folder of its own (W3 Total Cache and Query Monitor do,
// for their drop-ins), also when a host keeps the plugin in mu-plugins.
const FOLDERS_SHIPPING_CONTENT = new Set(['plugins', 'themes', 'mu-plugins']);

// The archive read as the inside of wp-content (asContentPart), or null when it is no such part.
// Read that way it keeps on the list of code WordPress loads by itself every file the archive
// read as written puts there, so a site kept in a folder named plugins/, or a wp-config.php
// written as ./wp-config.php, stays a site. The only files it may take off are those lying in the
// folder of one plugin, theme or mu-plugin: a template wp-config.php (Duplicator ships one) or the
// drop-ins W3 Total Cache keeps in its own wp-content, which WordPress never loads from there. A
// wp-config.php or .maintenance lying directly in such a folder is a site's (no plugin or theme
// in the test archives keeps one there), and so is anything in a "plugin" named wp-content.
const contentPartOf = (written) => {
  if (!isContentPart(written.entries)) return null;
  const part = asContentPart(written);
  const siteAsWritten = describeSite(written.entries);
  const siteAsPart = describeSite(part.entries);
  const takesOffTheList = written.entries.some((entry, index) => (
    isCodeFile(entry) && !liesInAPackage(entry.name)
    && isAlwaysLoaded(entry.name, siteAsWritten) && !isAlwaysLoaded(part.entries[index].name, siteAsPart)
  ));
  return takesOffTheList ? null : part;
};

const liesInAPackage = (name) => {
  const parts = name.split('/');
  if (parts.length < 3 || !FOLDERS_SHIPPING_CONTENT.has(parts[0]) || ['', CONTENT_FOLDER].includes(parts[1].toLowerCase())) return false;
  return parts.length > 3 || !(isSiteConfig(name) || isMaintenanceFile(name));
};

// A part holds at least one of those folders at its top, with something in it, or a drop-in,
// named as UpdraftPlus writes them, and no core. A name that climbs out of the archive leaves it
// as written, since a folder put in front of it would hide the climb. A copy of wp-content kept
// somewhere in a part is left to contentPartOf: it refuses the part when such a copy has code on
// the list.
const isContentPart = (entries) => {
  let isMarked = false;
  for (const entry of entries) {
    const logical = entry.name.replaceAll('\\', '/');
    const lower = logical.toLowerCase();
    if (isPathTraversal(logical) || endsWithPathPart(lower, VERSION_FILE)) return false;
    // The "others" part of a site with no mu-plugins and no translations holds its drop-ins alone.
    const written = entry.name.split('/');
    const marks = written.length === 1 ? DROP_INS.has(written[0]) : written[1] !== '' && CONTENT_PART_MARKS.has(written[0]);
    if (marks) isMarked = true;
  }
  return isMarked;
};

// The same archive, every name with CONTENT_PART_FOLDER in front. Only names change: the bytes are
// found by offset, and the local headers are compared with the bytes of the written name.
const asContentPart = (archive) => ({
  ...archive,
  entries: archive.entries.map((entry) => ({ ...entry, name: CONTENT_PART_FOLDER + entry.name, writtenName: entry.writtenName ?? entry.name })),
  problems: archive.problems.map((problem) => (problem.path === '' ? problem : { ...problem, path: CONTENT_PART_FOLDER + problem.path })),
});

// Info-ZIP's unzip, Python's zipfile, PowerShell's Expand-Archive and Windows' tar.exe all write
// "mu-plugins/./loader.php" and "mu-plugins//loader.php" as mu-plugins/loader.php (and on Windows
// "mu-plugins\.\loader.php" too). Python's zipfile and tar.exe write "mu-plugins/loader.php/." as
// mu-plugins/loader.php, and tar.exe writes "mu-plugins./loader.php" and "mu-plugins/loader.php "
// there as well (all measured 2026-11-18). Read as written, such a mu-plugin was never listed and its
// program launch was amber. So every check reads the name the file gets from the program that
// unpacks the most of these, and the names leave the worker as written (createWrittenNames). Two
// entries that land on one name are two entries under one name.
const asUnpacked = (archive) => {
  const tidied = new Map();
  for (const entry of archive.entries) {
    const name = unpackedNameOf(entry.name);
    if (name !== entry.name && name !== '') tidied.set(entry, name);
  }
  if (tidied.size === 0) return archive;
  const entries = archive.entries.map((entry) => (tidied.has(entry) ? { ...entry, name: tidied.get(entry), writtenName: entry.name } : entry));
  const unpackedName = new Map([...tidied].map(([entry, name]) => [entry.name, name]));
  const problems = archive.problems.map((problem) => (unpackedName.has(problem.path) ? { ...problem, path: unpackedName.get(problem.path) } : problem));
  const seen = new Set(archive.entries.filter((entry) => !tidied.has(entry)).map((entry) => entry.name));
  for (const name of tidied.values()) {
    if (seen.has(name)) problems.push({ code: 'duplicate_name', path: name, params: {} });
    seen.add(name);
  }
  return { ...archive, entries, problems };
};

// Strips the dots and spaces that end each segment and drops the segments left empty with the
// separator that follows them; a final one goes with the separator before it. A leading empty
// segment makes the name absolute and stays, and so does "..", so a name that climbs out of the
// archive still does; the separator that marks a folder entry stays too.
const unpackedNameOf = (name) => {
  if (!MAY_CHANGE_WHEN_UNPACKED.test(name)) return name;
  // A run of separators is one separator (the empty segments go, the first one keeps a name
  // absolute), and "./" is nothing. Both go first in one pass each, because a name can be 65,000
  // slashes or 32,000 "./" long; what is left to split is short.
  const flattened = name.replace(SEPARATOR_RUNS, '$1').replace(DOT_SEGMENTS, '$1');
  if (!MAY_CHANGE_WHEN_UNPACKED.test(flattened)) return flattened;
  const pieces = flattened.split(/([\\/])/);
  const kept = [];
  for (let at = 0; at < pieces.length; at += 2) {
    const segment = pieces[at];
    const separator = pieces[at + 1] ?? '';
    const unpacked = segment === '..' ? segment : stripTrailingDotsAndSpaces(segment);
    // Runs are collapsed, so an empty segment is the first (an absolute name) or the last (a
    // folder entry).
    const staysEmpty = segment === '';
    if (unpacked !== '' || staysEmpty) {
      kept.push(unpacked + separator);
    } else if (separator === '' && kept.length > 0) {
      kept.push(kept.pop().slice(0, -1));
    }
  }
  return kept.join('');
};

// Two separators in a row, or a segment ending in a dot or a space.
const MAY_CHANGE_WHEN_UNPACKED = /[\\/][\\/]|[. ](?:[\\/]|$)/;
const SEPARATOR_RUNS = /([\\/])[\\/]+/g;
const DOT_SEGMENTS = /(^|[\\/])(?:\.[\\/])+/g;

// The emit every event passes through. Every path an event carries that names an entry is shown
// as the zip writes it (asUnpacked, asContentPart). A folder a check names loses the folder a part
// is read under (CONTENT_PART_FOLDER), and that folder itself, where loose PHP at the top of a part
// is reported, is the top of the archive.
const createWrittenNames = (emit) => {
  let hidden = '';
  let writtenOf = new Map();
  let entryNames = new Set();
  // A finding's path may name a file inside an archive ("outer » inner"); the paths of the
  // listed, hashed and read files name an entry. A finding's path that is an entry's name is that
  // entry, shown as written; otherwise the longest entry it starts with is the archive.
  const writtenEntry = (path) => writtenOf.get(path) ?? withoutHidden(path);
  const written = (path) => {
    if (entryNames.has(path)) return writtenEntry(path);
    const outer = outerEntryOf(path, (candidate) => entryNames.has(candidate));
    if (outer !== null) return writtenEntry(outer) + path.slice(outer.length);
    return writtenEntry(path);
  };
  const withoutHidden = (path) => {
    if (hidden === '' || !path.startsWith(hidden)) return path;
    return path === hidden ? TOP_OF_ARCHIVE : path.slice(hidden.length);
  };
  const withPaths = (files) => files.map((file) => (
    file.findings ? { ...file, path: writtenEntry(file.path), findings: file.findings.map(written) } : { ...file, path: writtenEntry(file.path) }
  ));
  return {
    show: (archive, folder) => {
      hidden = folder;
      writtenOf = writtenNamesOf(archive.entries);
      entryNames = new Set(archive.entries.map((entry) => entry.name));
    },
    emit: (event) => {
      if (hidden === '' && writtenOf.size === 0) {
        emit(event);
        return;
      }
      const shown = { ...event };
      if (typeof shown.path === 'string') shown.path = shown.type === 'progress' ? writtenEntry(shown.path) : written(shown.path);
      if (typeof shown.params?.example === 'string') shown.params = { ...shown.params, example: written(shown.params.example) };
      if (Array.isArray(shown.files)) shown.files = withPaths(shown.files);
      if (Array.isArray(shown.databases)) shown.databases = withPaths(shown.databases);
      emit(shown);
    },
  };
};

// The name each entry is checked under -> the name the zip writes, for entries whose two names
// differ. A name two entries share stands for neither of them and is shown as it is checked. An
// empty written name is no name to show.
const writtenNamesOf = (entries) => {
  const seen = new Set();
  const shared = new Set();
  for (const { name } of entries) {
    if (seen.has(name)) shared.add(name);
    seen.add(name);
  }
  const writtenOf = new Map();
  for (const entry of entries) {
    const isShown = !shared.has(entry.name) && entry.writtenName;
    if (isShown && entry.writtenName !== entry.name) writtenOf.set(entry.name, entry.writtenName);
  }
  return writtenOf;
};

// The SHA-256 of every file a red finding is about (the reporter's `file`): for a finding inside an
// archive found in the copy, that archive, the file the visitor can find. Each hash carries the
// paths of its findings, so the page puts it on those rows and nowhere else; until 2026-11-18 the
// page and this function each guessed the file back from the "archive » file" path, and an entry
// named like such a path took the hash of another file. Two entries under one name have no single
// answer and are left out.
const hashRedFiles = async (copy, redFiles) => {
  const entries = new Map();
  const ambiguous = new Set();
  for (const entry of copy.archive.entries) {
    if (entry.isDirectory) continue;
    if (entries.has(entry.name)) ambiguous.add(entry.name);
    entries.set(entry.name, entry);
  }
  const findingsOf = new Map();
  for (const [path, file] of redFiles) {
    if (file === null || !entries.has(file) || ambiguous.has(file)) continue;
    const findings = findingsOf.get(file) ?? [];
    if (findings.length < HASHED_FINDINGS_PER_FILE) findings.push(path);
    findingsOf.set(file, findings);
  }
  const deadline = performance.now() + HASHING_TOTAL_TIME_MS;
  const hashed = [];
  for (const [name, findings] of findingsOf) {
    const entry = entries.get(name);
    if (hashed.length >= HASHED_FILES || performance.now() > deadline) break;
    if (entry.uncompressedSize > HASHED_FILE_LIMIT_BYTES) continue;
    const { bytes } = await readWholeFile(copy, entry);
    if (bytes !== null) hashed.push({ path: name, sha256: await sha256Hex(bytes), findings });
    copy.alive();
  }
  return hashed;
};

// The archive a finding inside an archive names: the longest part of the path before a
// NESTED_SEPARATOR that is an entry, since an entry's name can hold the separator too. Null for a
// path that names no such archive.
const outerEntryOf = (path, isEntry) => {
  for (let at = path.lastIndexOf(NESTED_SEPARATOR); at > 0; at = path.lastIndexOf(NESTED_SEPARATOR, at - 1)) {
    if (isEntry(path.slice(0, at))) return path.slice(0, at);
  }
  return null;
};

// Called for every piece a long read goes through; sends a message at most once a second.
const createHeartbeat = (emit) => {
  let lastSent = performance.now();
  return () => {
    const now = performance.now();
    if (now - lastSent < HEARTBEAT_INTERVAL_MS) return;
    lastSent = now;
    emit({ type: 'alive' });
  };
};

// The dumps in the copy, read as streams. A WordPress copy without one is said to be so: the
// database checks did not run, which is not the same as finding nothing there.
const checkDatabase = async (copy, site) => {
  const dumps = copy.archive.entries.filter((entry) => !entry.isDirectory && isReadable(entry) && isDatabaseDump(entry.name));
  if (dumps.length === 0) {
    if (site.looksLikeWordPress) copy.reporter.report('db.not_found', '', {});
    return new Set();
  }
  return checkDatabases(copy, dumps, new Set(site.allPlugins));
};

// Server settings: .htaccess, .user.ini and php.ini that no official release proved, read whole.
const checkConfigFiles = async (copy, verified, siteHosts) => {
  const { reporter } = copy;
  for (const entry of copy.archive.entries) {
    const base = entry.name.replaceAll('\\', '/').split('/').pop().toLowerCase();
    if (entry.isDirectory || entry.isSymlink || !CONFIG_FILE_NAMES.has(base) || verified.has(entry.name)) continue;
    if (entry.uncompressedSize > CONFIG_FILE_LIMIT_BYTES) {
      reporter.report('config.too_large', entry.name, { bytes: entry.uncompressedSize });
      continue;
    }
    const { bytes, failure } = await readWholeFile(copy, entry);
    // Data that cannot be reached has its finding from the first-bytes check; data that is
    // there but does not unpack to the declared size is named here. Chromium and Firefox refuse
    // bytes after the end of a deflate stream, so their first-bytes reading usually names such a
    // file first (measured 2026-11-14); this line is for a browser that takes them.
    if (bytes === null) {
      if (failure === DAMAGED) reporter.report('entry.corrupt_data', entry.name, { reason: 'config' });
      continue;
    }
    const settings = new TextDecoder('latin1').decode(bytes);
    const signals = base === '.htaccess' ? findApacheSignals(settings, siteHosts) : findIniSignals(settings);
    for (const [signal, params] of signals) {
      reporter.report(CONFIG_FINDINGS.get(signal), entry.name, { ...params, excerpt: excerptOfLine(settings, params.line) });
    }
  }
};

const CONFIG_FINDINGS = new Map([
  ['prepend_unusual', 'config.prepend_unusual'],
  ['prepend', 'config.prepend'],
  ['php_handler', 'config.php_handler'],
  ['redirect', 'config.redirect'],
  ['cgi_handler', 'config.cgi_handler'],
  ['ssi', 'config.server_side_includes'],
]);

// Known attacks, by content: files of exactly the size of a known one are hashed whole. Every
// entry counts, whatever its kind, so a zip lying in the copy is compared as a file too.
const KNOWN_SIZES = new Set(KNOWN_FILES.map((known) => known.bytes));

const checkKnownFiles = async (container) => {
  for (const entry of container.archive.entries) {
    if (entry.isDirectory || !KNOWN_SIZES.has(entry.uncompressedSize)) continue;
    const { bytes, failure } = await readWholeFile(container, entry);
    if (bytes === null) {
      if (failure === DAMAGED) container.reporter.report('entry.corrupt_data', entry.name, { reason: 'indicator' });
      continue;
    }
    const known = await knownFileOf(bytes);
    if (known) container.reporter.report('indicator.known_file', entry.name, { campaign: known.campaign, role: known.role });
  }
};

// The file the visitor chose can itself be one of the listed files: a campaign's archive is
// listed by its hash, and its name is too common to list. Only a file of exactly a listed size is
// read for that, so a copy of 2 GB is never hashed. The finding is about the whole copy.
const checkChosenFile = async (source, reporter) => {
  if (!KNOWN_SIZES.has(source.blob.size)) return;
  const bytes = new Uint8Array(await source.blob.arrayBuffer());
  source.bytesRead += bytes.length;
  const known = await knownFileOf(bytes);
  if (known) reporter.report('indicator.known_upload', '', { campaign: known.campaign, role: known.role });
};

const knownFileOf = async (bytes) => {
  const digest = await sha256Hex(bytes);
  return KNOWN_FILES.find((row) => row.bytes === bytes.length && row.sha256 === digest) ?? null;
};

const knownName = (logicalName) => {
  const lower = logicalName.toLowerCase();
  return KNOWN_NAMES.find(({ pathEnd }) => lower === pathEnd || lower.endsWith(`/${pathEnd}`)) ?? null;
};

// The question goes out before the first-bytes check, so the page fetches while the worker
// reads. Until the answers are in, what the checks say about a file that may turn out to be
// an official one is held back. The inventory follows it: the page looks up known
// vulnerabilities on its own and never sends anything about them back here.
const startComparison = async (copy, site, { emit, lookup, online }) => {
  const { reporter } = copy;
  const { core } = site;
  if (!online) {
    reporter.report('lookup.off', '', { plugins: site.allPlugins.length });
    return null;
  }
  // One scan asks about LISTED_COMPONENTS plugins; the rest is named, not dropped.
  const pastLimit = site.allPlugins.slice(LISTED_COMPONENTS);
  if (pastLimit.length > 0) {
    reporter.report('component.not_compared_past_limit', `${site.contentRoot}wp-content/plugins/`, { plugins: pastLimit.length, example: pastLimit[0] });
  }
  const question = { core: null, plugins: [] };
  if (core && core.version) {
    question.core = { version: core.version, locale: core.locale };
  } else {
    reporter.report('component.not_compared', site.root, { kind: 'core', reason: 'no_version' });
  }
  const plugins = await readPluginIdentities(copy, site);
  for (const plugin of plugins) {
    if (plugin.version) {
      question.plugins.push(plugin);
    } else {
      reporter.report('component.not_compared', `${site.contentRoot}wp-content/plugins/${plugin.slug}/`, { kind: 'plugin', reason: 'no_version' });
    }
  }
  let comparison = null;
  if (question.core || question.plugins.length > 0) {
    const holding = createHoldingReporter(reporter, (path) => mayBeOfficial(site, path));
    copy.reporter = holding;
    comparison = { site, question, reporter, holding, answers: lookup(question) };
  }
  emit({ type: 'inventory', core: question.core ? { version: question.core.version } : null, plugins, themes: await readThemeIdentities(copy, site) });
  return comparison;
};

const finishComparison = async (copy, { site, question, reporter, holding, answers }, emit) => {
  const verified = await verifyComponents(copy, { site, question, answers: await answers }, emit);
  holding.release(verified);
  copy.reporter = reporter;
  return verified;
};

// Everything under the WordPress root, and the wp-content above a core kept apart from it, can be
// listed by the core or a plugin list, except what a site writes itself: uploads, and the
// always-loaded code in mu-plugins.
const mayBeOfficial = ({ root, contentRoot }, path) => {
  const base = path.startsWith(root) ? root : contentRoot;
  if (!path.startsWith(base)) return false;
  const relative = path.slice(base.length).toLowerCase();
  return !relative.startsWith('wp-content/uploads/') && !relative.startsWith('wp-content/mu-plugins/');
};

// The plugin's main file is the PHP file at the top of its folder whose header names it.
// Its version is read the way WordPress reads it (get_file_data), and only kept when it fits
// the format a URL may carry.
const readPluginIdentities = async (copy, site) => {
  const base = `${site.contentRoot}wp-content/plugins/`;
  const candidates = new Map(site.plugins.map((slug) => [slug, []]));
  for (const entry of copy.archive.entries) {
    if (entry.isDirectory || !entry.name.startsWith(base) || extensionOf(entry.name) !== '.php') continue;
    const [slug, file, ...deeper] = entry.name.slice(base.length).split('/');
    if (deeper.length === 0 && file && candidates.has(slug)) candidates.get(slug).push(entry);
  }
  const plugins = [];
  for (const [slug, files] of candidates) {
    // WordPress lists the folder in no fixed order; the file named after the folder is the
    // usual main file, so it is tried first.
    files.sort((left, right) => Number(right.name.endsWith(`/${slug}.php`)) - Number(left.name.endsWith(`/${slug}.php`)));
    let version = '';
    for (const entry of files) {
      const header = new TextDecoder('latin1').decode(await readPrefix(copy, entry, FILE_HEADER_BYTES));
      if (!headerField(header, 'Plugin Name')) continue;
      const declared = headerField(header, 'Version');
      version = VERSION_FORMAT.test(declared) ? declared : '';
      break;
    }
    plugins.push({ slug, version });
  }
  return plugins;
};

// A theme's version stands in the header of its style.css, which WordPress requires and reads
// from the first 8 KB, as it does a plugin's main file.
const readThemeIdentities = async (copy, site) => {
  const base = `${site.contentRoot}wp-content/themes/`;
  const styles = new Map();
  for (const entry of copy.archive.entries) {
    if (entry.isDirectory || !entry.name.startsWith(base)) continue;
    const [slug, file, ...deeper] = entry.name.slice(base.length).split('/');
    if (deeper.length === 0 && file === 'style.css' && !styles.has(slug)) styles.set(slug, entry);
  }
  const themes = [];
  for (const slug of site.themes) {
    let version = '';
    if (styles.has(slug)) {
      const header = new TextDecoder('latin1').decode(await readPrefix(copy, styles.get(slug), FILE_HEADER_BYTES));
      const declared = headerField(header, 'Theme Name') ? headerField(header, 'Version') : '';
      version = VERSION_FORMAT.test(declared) ? declared : '';
    }
    themes.push({ slug, version });
  }
  return themes;
};

const HEADER_FIELDS = new Map(['Plugin Name', 'Theme Name', 'Version'].map((field) => (
  [field, new RegExp(`^(?:[ \\t]*<\\?php)?[ \\t/*#@]*${field}:(.*)$`, 'mi')]
)));

const headerField = (header, field) => {
  const match = HEADER_FIELDS.get(field).exec(header.replaceAll('\r', '\n'));
  return match ? match[1].replace(/\s*(?:\*\/|\?>).*/, '').trim() : '';
};

// The checks that apply to any zip, the copy itself or an archive found inside it.
const checkContainer = async (container) => {
  for (const problem of container.archive.problems) {
    container.reporter.report(`zip.${problem.code}`, problem.path, problem.params);
  }
  // Small PHP files in uploads whose content decides: judged when their first bytes are read,
  // and reported unjudged if that never happens.
  container.uploadsPhpToJudge = new Set();
  checkNames(container);
  await checkFirstBytes(container);
  for (const entry of container.uploadsPhpToJudge) container.reporter.report('layout.php_in_uploads', entry.name, {});
  await checkKnownFiles(container);
};

// A copy can hold more than one WordPress: a blog/, staging/ or old/ folder with a site of its
// own is common on shared hosting. The copy's own site is the one nearest the top of the
// archive, whatever order the zip lists its files in; the others are named as not compared.
// Taking the first version.php in the table instead let one decoy file, or an honest
// sub-install, turn the main site into loose files.
const describeSite = (entries) => {
  const versionEntries = entries.filter((entry) => endsWithPathPart(entry.name, VERSION_FILE));
  const versionEntry = shallowest(versionEntries);
  // A wp-config.php inside a wp-content is a plugin's template (Duplicator ships one), not a site's.
  const configEntry = shallowest(entries.filter((entry) => endsWithPathPart(entry.name, CONFIG_FILE) && !isInsideContent(entry.name)));
  let root = '';
  if (versionEntry) root = versionEntry.name.slice(0, -VERSION_FILE.length);
  else if (configEntry) root = configEntry.name.slice(0, -CONFIG_FILE.length);
  const otherRoots = new Set(versionEntries.map((entry) => entry.name.slice(0, -VERSION_FILE.length)));
  otherRoots.delete(root);
  const siteEntries = entries.filter((entry) => !isMacMetadata(entry.name));
  const blockers = blockersOf(siteEntries);
  const coreFolders = coreFoldersOf(siteEntries);
  const { contentFolders } = contentFoldersOf(siteEntries);
  const { languageFolders } = contentFoldersOf(blockers);
  const keptApart = keptApartContentOf(coreFolders, contentFolders);
  const siteCopy = coreFolders.size > 0 ? null : siteCopyOf(configEntry ? root : null, contentFolders);
  // A wp-config.php names the site's folder as written; the copy's spelling is that of whichever
  // of its entries came first, and a decoy SITE/ before site/ would move the plugins out of reach.
  const contentRoot = contentRootOf({ root, keptApart, contentFolders, siteCopy: configEntry ? null : siteCopy });
  const allPlugins = folderNames(entries, `${contentRoot}wp-content/plugins/`);
  const siteFolders = new Set([...[root, ...otherRoots].map((folder) => folder.toLowerCase()), ...coreFolders, ...contentFolders.keys()]);
  const { runFolders, otherCopies } = runFoldersOf({ coreFolders, contentFolders, keptApart, siteCopy });
  return {
    root,
    contentRoot,
    otherRoots: [...otherRoots],
    otherCopies,
    siteFolders,
    coreFolders,
    contentFolders: new Set(contentFolders.keys()),
    languageFolders,
    keptApart,
    configFolders: configFoldersOf(runFolders, fileNamesOf(blockers)),
    // WordPress reads .maintenance from the folder it runs from only (ABSPATH).
    maintenanceFolders: runFolders,
    versionEntry: versionEntry ?? null,
    // A backup of wp-content alone, and a part of one (asContentPart), has neither of the first
    // two, and its plugins are still compared. Its wp-content has to be written the way the
    // comparison reads it, so a copy named with backslashes or as WP-Content is still said to
    // look like no WordPress rather than to have had nothing to compare.
    looksLikeWordPress: Boolean(versionEntry || configEntry || entries.some((entry) => entry.name.startsWith(`${contentRoot}wp-content/`))),
    plugins: allPlugins.slice(0, LISTED_COMPONENTS),
    allPlugins,
    themes: folderNames(entries, `${contentRoot}wp-content/themes/`).slice(0, LISTED_COMPONENTS),
    databases: entries
      .filter((entry) => !entry.isDirectory && isDatabaseDump(entry.name))
      .slice(0, LISTED_DATABASES)
      .map((entry) => ({ path: entry.name, bytes: entry.uncompressedSize })),
  };
};

// A zip made by macOS Finder repeats every folder under __MACOSX/ with "._" twins holding file
// attributes: no copy of a site, so they take no part in describing one. Anything else kept
// there is a file like any other.
const isMacMetadata = (name) => {
  const logical = name.replaceAll('\\', '/');
  const fileName = logical.slice(logical.lastIndexOf('/') + 1);
  return logical.toLowerCase().startsWith(MAC_METADATA_FOLDER) && (fileName === '' || fileName.startsWith(MAC_TWIN_PREFIX));
};
const MAC_METADATA_FOLDER = '__macosx/';
const MAC_TWIN_PREFIX = '._';

const isInsideContent = (name) => name.replaceAll('\\', '/').toLowerCase().split('/').slice(0, -1).includes(CONTENT_FOLDER);

// With no core, the site's own folder: the folder of the site's wp-config.php, or with none the
// shallowest copy of wp-content, or with neither the top of the archive (lower case, "/" for "\").
const siteCopyOf = (configRoot, contentFolders) => {
  if (configRoot !== null) return configRoot.replaceAll('\\', '/').toLowerCase();
  const byDepth = [...contentFolders.keys()].sort((left, right) => left.split('/').length - right.split('/').length || left.localeCompare(right));
  return byDepth[0] ?? '';
};

// The site folders (siteFolders in describeSite) are the copy's own site, any other WordPress in
// it (with "/" or "\" names), and any folder holding a wp-content (a site copied without its
// core); loose PHP is judged from the one it lies in. This returns the last kind, lower case ->
// as written with "/" (Windows, where these copies get run, finds WP-Content under the name
// wp-content; a file named wp-content is no folder), and the folders whose wp-content holds a
// languages folder under exactly those two names, the only ones wp_set_lang_dir() finds on Linux.
const contentFoldersOf = (entries) => {
  const contentFolders = new Map();
  const languageFolders = new Set();
  for (const entry of entries) {
    const logical = entry.name.replaceAll('\\', '/');
    const parts = logical.split('/');
    const contentAt = parts.findIndex((part) => part.toLowerCase() === CONTENT_FOLDER);
    if (contentAt < 0 || contentAt === parts.length - 1) continue;
    const folder = parts.slice(0, contentAt).map((part) => `${part.toLowerCase()}/`).join('');
    if (!contentFolders.has(folder)) contentFolders.set(folder, logical.slice(0, folder.length));
    const isLanguages = parts[contentAt] === CONTENT_FOLDER && parts[contentAt + 1] === LANGUAGES_FOLDER_NAME;
    if (isLanguages && parts.length > contentAt + 2) languageFolders.add(folder);
  }
  return { contentFolders, languageFolders };
};

// WordPress kept in a folder of its own (wp/ holding no wp-content) with its wp-content in the
// folder above, where wp-config.php points WP_CONTENT_DIR: core folder -> that folder above, for
// every such core whose folder above holds no core itself.
const keptApartContentOf = (coreFolders, contentFolders) => {
  const keptApart = new Map();
  for (const core of coreFolders) {
    const above = parentFolderOf(core);
    if (!contentFolders.has(core) && contentFolders.has(above) && !coreFolders.has(above)) keptApart.set(core, above);
  }
  return keptApart;
};

// The folder whose wp-content holds the site's plugins and themes, as written in the archive:
// the root, the folder above a core kept apart from its content, or with no core and no
// wp-config.php the site's own copy of wp-content (siteCopyOf), which a backup of wp-content
// alone keeps anywhere below the top.
const contentRootOf = ({ root, keptApart, contentFolders, siteCopy }) => {
  const folder = siteCopy ?? keptApart.get(root.replaceAll('\\', '/').toLowerCase());
  return folder === undefined ? root : contentFolders.get(folder) ?? root;
};

// The folders WordPress runs from (its ABSPATH): every folder holding a core, and every copy of
// wp-content without its core, where its core would go; with no core at all, the site's own
// folder as well (siteCopyOf). Not run from: the folder above a core kept apart from its content
// (keptApartContentOf), which only holds that core's wp-content. The copies other than the site's
// own are named as not compared (otherCopies, as written in the archive, the top of it as "./"):
// nothing in them is compared with wordpress.org.
const runFoldersOf = ({ coreFolders, contentFolders, keptApart, siteCopy }) => {
  const contentOfCoresBelow = new Set(keptApart.values());
  const copies = [...contentFolders.keys()].filter((folder) => !coreFolders.has(folder) && !contentOfCoresBelow.has(folder));
  const runFolders = new Set([...coreFolders, ...copies]);
  if (siteCopy !== null) runFolders.add(siteCopy);
  const others = copies.filter((folder) => folder !== siteCopy);
  return { runFolders, otherCopies: others.map((folder) => contentFolders.get(folder) || TOP_OF_ARCHIVE) };
};

// The entries that may keep a file off the list (the run folder's own wp-config.php, a
// wp-settings.php above it, a wp-content/languages folder): those every unpacker writes where the
// scanner reads them. Python's zipfile and Info-ZIP on Linux write "wp-config.php." and "wp./" as
// named and keep a "\" inside a name, while on Windows each of them lands on the plain name. Read
// only the Windows way, one empty decoy so named took the site's real wp-config.php, the one
// WordPress on Linux runs, off the list and its red off the page (measured 2026-11-18). "//" and "./" every unpacker flattens alike. A
// name with "\" still counts in an archive that writes no name with "/", as a Windows tool writes
// all of them: an unpacker that keeps "\" then makes neither the core's folder nor the file in it.
// Folders that differ only in letter case are still one folder here (a limit in docs/rules.md):
// a tree of every folder to tell them apart took 642 MB for a 6.4 MB zip of deep names.
const blockersOf = (entries) => {
  const writesSlashes = entries.some((entry) => (entry.writtenName ?? entry.name).includes('/'));
  return entries.filter((entry) => isWrittenAlike(entry, writesSlashes));
};

const isWrittenAlike = (entry, writesSlashes) => {
  const written = entry.writtenName ?? entry.name;
  if (writesSlashes && written.includes('\\')) return false;
  const flattened = written.replace(SEPARATOR_RUNS, '$1').replace(DOT_SEGMENTS, '$1');
  return unpackedNameOf(written) === flattened;
};

// Every file name of the archive with "/" for "\", its folders in lower case and its own name as
// written. Taking a file off the list needs a name both Windows and Linux read: a WP-Config.php
// in the core's folder stops nothing on Linux.
const fileNamesOf = (entries) => new Set(entries.map((entry) => {
  const logical = entry.name.replaceAll('\\', '/');
  const nameAt = logical.lastIndexOf('/') + 1;
  return logical.slice(0, nameAt).toLowerCase() + logical.slice(nameAt);
}));

// The folders holding a WordPress core, lower case and with "/" for "\". describeSite picks the
// copy's root among "/" names only; an archive written on Windows can name its core with "\",
// and that folder is still where its wp-config.php and .maintenance are read from.
const coreFoldersOf = (entries) => {
  const folders = new Set();
  for (const entry of entries) {
    const logical = entry.name.replaceAll('\\', '/').toLowerCase();
    if (endsWithPathPart(logical, VERSION_FILE)) folders.add(logical.slice(0, -VERSION_FILE.length));
  }
  return folders;
};

// WordPress takes wp-config.php from the folder it runs from or, when that has none and the folder
// above holds no wp-settings.php, from the folder above (wp-load.php:47-55).
const configFoldersOf = (runFolders, fileNames) => {
  const folders = new Set(runFolders);
  for (const folder of runFolders) {
    const above = parentFolderOf(folder);
    if (above === null) continue;
    if (!fileNames.has(`${folder}${CONFIG_FILE}`) && !fileNames.has(`${above}${SETTINGS_FILE}`)) folders.add(above);
  }
  return folders;
};

const folderOf = (path) => {
  const logical = path.replaceAll('\\', '/').toLowerCase();
  return logical.slice(0, logical.lastIndexOf('/') + 1);
};

// 'a/b/' -> 'a/', 'a/' -> '', '' -> null (nothing above the top of the archive).
const parentFolderOf = (folder) => {
  if (folder === '') return null;
  const inner = folder.slice(0, -1);
  return inner.slice(0, inner.lastIndexOf('/') + 1);
};

const endsWithPathPart = (name, part) => name === part || name.endsWith(`/${part}`);

// The entry with the fewest folders above it; of two as deep, the first in the table.
const shallowest = (entries) => {
  let best = null;
  let bestDepth = Infinity;
  for (const entry of entries) {
    const depth = entry.name.split('/').length;
    if (depth < bestDepth) {
      best = entry;
      bestDepth = depth;
    }
  }
  return best;
};

const folderNames = (entries, base) => {
  const names = new Set();
  for (const entry of entries) {
    if (!entry.name.startsWith(base)) continue;
    const rest = entry.name.slice(base.length);
    const slash = rest.indexOf('/');
    if (slash > 0) names.add(rest.slice(0, slash));
  }
  return [...names].sort();
};

// Version and package language, read the way WordPress reads them: from version.php.
// Both values end up in a URL in a later stage, so anything off-format is dropped here.
const readCoreIdentity = async (copy, versionEntry) => {
  const body = await readSmallFile(copy, versionEntry);
  if (body === null) return null;
  const text = new TextDecoder('latin1').decode(body);
  const version = /\$wp_version\s*=\s*'([^']{1,32})'/.exec(text);
  const localPackage = /\$wp_local_package\s*=\s*'([^']{1,32})'/.exec(text);
  return {
    version: version && VERSION_FORMAT.test(version[1]) ? version[1] : '',
    locale: localPackage && LOCALE_FORMAT.test(localPackage[1]) ? localPackage[1] : 'en_US',
  };
};

const checkNames = ({ archive, reporter, isNested, uploadsPhpToJudge }) => {
  for (const entry of archive.entries) {
    const { name } = entry;
    // Windows reads a backslash as a folder separator, so the checks do too.
    const logicalName = name.replaceAll('\\', '/');
    if (isPathTraversal(logicalName)) reporter.report('layout.path_traversal', name, {});
    if (entry.isSymlink) reporter.report('layout.symlink', name, {});
    const deceptive = deceptiveCharacters(name);
    if (deceptive.length > 0) {
      reporter.report('name.deceptive_characters', name, { codes: deceptive.slice(0, LISTED_DECEPTIVE_CODES).join(' ') });
    }
    if (entry.isDirectory) continue;

    // Judged on the name as written: the checks read it without those dots (asUnpacked).
    const writtenName = entry.writtenName ?? name;
    if (stripTrailingDotsAndSpaces(writtenName) !== writtenName) reporter.report('name.trailing_dot_or_space', name, {});
    const extension = extensionOf(logicalName);
    if (EXECUTABLE_EXTENSIONS.has(extension)) {
      reporter.report(runnableNameRule(isNested, logicalName, extension), name, { extension });
    }
    if (SERVER_SCRIPT_EXTENSIONS.has(extension)) reporter.report(serverScriptRule(isNested, logicalName), name, { extension });
    if (isInUploads(logicalName) && PHP_EXTENSIONS.has(extension)) {
      if (mayBeGuardFile(entry)) uploadsPhpToJudge.add(entry);
      else reporter.report('layout.php_in_uploads', name, {});
    }
    const double = doubleExtensionKind(logicalName);
    if (double === 'php_first') reporter.report('layout.php_named_as_media', name, {});
    if (double === 'image_first') reporter.report('layout.image_named_php', name, {});
    const known = knownName(logicalName);
    if (known !== null) reporter.report('indicator.known_name', name, { campaign: known.campaign });
    if (entry.method === METHOD_STORED && entry.compressedSize !== entry.uncompressedSize) {
      // Some tools unpack a stored file by one size, some by the other.
      reporter.report('zip.stored_size_mismatch', name, {});
    }
    if (entry.unreadable) reporter.report('zip.entry_unreadable', name, { reason: entry.unreadable });
    else if (entry.isEncrypted) reporter.report('zip.encrypted_entry', name, {});
    else if (!isSupportedMethod(entry)) reporter.report('zip.unsupported_compression', name, { method: entry.method });
  }
};

// A program packed inside an archive does not start by itself, and software shops keep
// installers exactly like that, so there it is a thing to read about, not a verdict. The same
// goes for a build script lying among a plugin's or a theme's code: three official plugins of
// the 30 in the test copy ship one. A program (.exe, .dll, .scr ...) stays red wherever it is.
const runnableNameRule = (isNested, logicalName, extension) => {
  if (isNested) return 'layout.executable_in_archive';
  const isShippedScript = SCRIPT_EXTENSIONS.has(extension) && isInCodeFolder(logicalName);
  return isShippedScript ? 'layout.script_in_code_folder' : 'layout.executable_extension';
};

// A script the web server runs by itself (SERVER_SCRIPT_EXTENSIONS). Coloured like a build
// script: amber among a plugin's or a theme's code, where UpdraftPlus ships
// one, red anywhere else. Packed in an archive it starts nothing.
const serverScriptRule = (isNested, logicalName) => {
  if (isNested) return 'layout.executable_in_archive';
  return isInCodeFolder(logicalName) ? 'layout.server_script_in_code_folder' : 'layout.server_script';
};

// PHP inside a file that a web server hands out without running. See TEXT_FILE_EXTENSIONS for
// why a text file among code, or packed in an archive, is amber.
const phpInPassiveFileRule = (isNested, logicalName, extension) => {
  const runsOnlyWhenIncluded = TEXT_FILE_EXTENSIONS.has(extension) && (isNested || isInCodeFolder(logicalName));
  return runsOnlyWhenIncluded ? 'layout.php_in_text' : 'layout.php_in_media';
};

// Folders that hold the code of a core, a plugin or a theme, wherever the site lies in the
// archive. Uploads is never one, also when a path names both.
const CODE_HOLDING_FOLDERS = [
  '/wp-admin/', '/wp-includes/', '/wp-content/plugins/', '/wp-content/themes/', '/wp-content/mu-plugins/', '/wp-content/languages/',
];

const isInCodeFolder = (logicalName) => {
  const lower = `/${logicalName.toLowerCase()}`;
  return !isInUploads(logicalName) && CODE_HOLDING_FOLDERS.some((folder) => lower.includes(folder));
};

const isPathTraversal = (logicalName) => (
  logicalName.startsWith('/') || /^[a-zA-Z]:/.test(logicalName) || logicalName.split('/').includes('..')
);

const isInUploads = (logicalName) => {
  const lower = logicalName.toLowerCase();
  return lower.startsWith('wp-content/uploads/') || lower.includes('/wp-content/uploads/');
};

// Plugins put an index.php into their folders in uploads so the folder cannot be listed: 27 B
// ("Silence is golden") and 5 B ("<?php") on the test copies. Such a file is judged
// by its content, and only when the first bytes cover the whole of it.
const mayBeGuardFile = (entry) => isReadable(entry) && !entry.isSymlink;

// Walks the archive in the order the data lies in the file. That keeps the reads sequential,
// and it is also how the space between files gets accounted for: every byte before the table
// of contents has to belong to a listed file, or it is reported.
const checkFirstBytes = async (container) => {
  const { archive, reporter } = container;
  const order = archive.entries
    .filter((entry) => !entry.unreadable)
    .sort((left, right) => left.headerOffset - right.headerOffset || left.index - right.index);
  const gaps = [];
  let coveredUntil = 0;
  let descriptorSlack = 0;
  let lastProgress = -Infinity;

  for (let position = 0; position < order.length; position += 1) {
    const entry = order[position];
    const now = performance.now();
    if (now > container.deadline) throw new TimeLimitError();
    if (now - lastProgress > PROGRESS_INTERVAL_MS) {
      lastProgress = now;
      container.progress({ stage: 'first_bytes', done: position, total: order.length, path: entry.name });
    }

    const wantsHead = !entry.isDirectory && isReadable(entry)
      && !EXECUTABLE_EXTENSIONS.has(extensionOf(entry.name.replaceAll('\\', '/')));
    const wantPacked = wantsHead ? Math.min(entry.compressedSize, HEAD_PACKED_BYTES) : 0;
    const ahead = order[position + DENSE_LOOKAHEAD_ENTRIES];
    const isDenseRegion = ahead !== undefined && ahead.headerOffset - entry.headerOffset < READ_AHEAD_BYTES;
    const located = await locateData(container, entry, { wantPacked, readAhead: isDenseRegion ? READ_AHEAD_BYTES : 0 });
    if (located.unreadable) {
      reporter.report('zip.entry_unreadable', entry.name, { reason: located.unreadable });
      continue;
    }
    // Only entries that really have a header here take part in the accounting of space.
    if (entry.headerOffset < coveredUntil) {
      reporter.report('zip.overlapping_entries', entry.name, {});
    } else if (entry.headerOffset - coveredUntil > descriptorSlack) {
      gaps.push({ start: coveredUntil, bytes: entry.headerOffset - coveredUntil });
    }
    if (located.header.differences.length > 0) {
      reporter.report('zip.header_mismatch', entry.name, {
        fields: located.header.differences.join(' '),
        localName: located.header.localName,
      });
    }
    const dataStart = entry.headerOffset + located.header.headerBytes;
    coveredUntil = Math.max(coveredUntil, dataStart + entry.compressedSize);
    descriptorSlack = entry.hasDescriptor ? MAX_DESCRIPTOR_BYTES : 0;

    if (wantsHead) {
      const file = { entry, dataStart, extension: extensionOf(entry.name.replaceAll('\\', '/')), head: null };
      file.head = await readHead(container, file, located.packed);
      checkHead(container, file);
      if (mayHideZipAtEnd(file)) await checkTail(container, file);
    }
  }

  if (archive.directoryStart - coveredUntil > descriptorSlack) {
    gaps.push({ start: coveredUntil, bytes: archive.directoryStart - coveredUntil });
  }
  container.progress({ stage: 'first_bytes', done: order.length, total: order.length, path: '' });
  // In front of a zip glued behind a picture lies the picture itself, which the finding on
  // the outer file already names. A file header hidden inside it is still looked for.
  await reportGaps(container, gaps);
};

// Reads every PHP file and every .maintenance that was not proven official and judges its code.
// Where the file lies sets the weight: code that WordPress loads by itself (isAlwaysLoaded:
// wp-config.php, .maintenance, mu-plugins, drop-ins, language files) runs with nothing to switch on in wp-admin, so
// there a launch path is red; elsewhere most launch paths have honest users and are amber.
// `root` is null inside a nested archive, where WordPress loads nothing by itself. Returns
// those files, for the visitor to read.
const checkCode = async (container, site, verified) => {
  const { root } = site;
  // Entries that cannot be read at all come in too: on the list they are red (readCode), and
  // elsewhere the zip checks have named them already.
  const files = container.archive.entries
    .filter((entry) => isCodeName(entry) && !verified.has(entry.name))
    .sort((left, right) => left.headerOffset - right.headerOffset);
  const loaded = [];
  const outside = new Map();
  let lastProgress = -Infinity;
  for (const [position, entry] of files.entries()) {
    const now = performance.now();
    if (now > container.deadline) throw new TimeLimitError();
    if (now - lastProgress > PROGRESS_INTERVAL_MS) {
      lastProgress = now;
      container.progress({ stage: 'php_code', done: position, total: files.length, path: entry.name });
    }
    // A file that cannot be read is no translation holding only texts, so it keeps the scope
    // its path gives it.
    const isOnTheList = root !== null && isAlwaysLoaded(entry.name, site);
    const code = await readCode(container, { entry, scope: isOnTheList ? 'loaded' : 'unproven' });
    const scope = isOnTheList && !isPlainTranslation(container, entry.name, code) ? 'loaded' : 'unproven';
    if (scope === 'loaded') {
      const name = code === null ? '' : headerField(code.slice(0, FILE_HEADER_BYTES), 'Plugin Name');
      loaded.push({ path: entry.name, bytes: entry.uncompressedSize, name });
    }
    if (code === null) continue;
    judgeCode(container, { entry, scope, code });
    const instruction = findInstruction(code.toLowerCase());
    if (instruction !== null) container.reporter.report('text.ai_instruction', entry.name, { what: instruction });
    // A guard file of comments only, or a data file that exits first, does nothing wherever
    // it lies. A file on the list, such as a wp-config.php in the folder above the site, is no
    // loose PHP either. Each WordPress in the copy, and each copy of wp-content without its core,
    // is judged from its own folder: their plugins and core files are where code belongs.
    const isListed = scope === 'loaded';
    const siteFolder = root === null ? null : siteFolderOf(site, entry.name);
    const folder = root === null || isListed ? null : outsideCodeFolder(site, entry.name);
    if (folder !== null && !isInertPhp(code) && !exitsAtOnce(code)) {
      // Not `files`: the page counts a finding with `files` as that many findings.
      const group = outside.get(folder) ?? { phpFiles: 0, example: entry.name, place: loosePlace(siteFolder, folder) };
      group.phpFiles += 1;
      outside.set(folder, group);
    }
  }
  container.progress({ stage: 'php_code', done: files.length, total: files.length, path: '' });
  for (const [folder, group] of outside) container.reporter.report('layout.php_outside_code_folders', folder, group);
  return loaded;
};

// WordPress loads PHP from core's folders, from plugins, themes and mu-plugins, and from
// translation files. Uploads stands here because PHP there has a finding of its own.
const CODE_FOLDERS = [
  'wp-admin/', 'wp-includes/', 'wp-content/plugins/', 'wp-content/themes/', 'wp-content/mu-plugins/',
  'wp-content/languages/', 'wp-content/uploads/',
];

const TOP_OF_ARCHIVE = './';

// The deepest site folder (siteFolders in describeSite) the path lies in, spelled as in the path with "/" for
// "\"; the root when it lies in none. A copy of wp-content without its core is a site folder of
// its own: its plugins are not loose PHP, and the folder is not called one WordPress loads
// nothing from while its wp-config.php is on the list.
const siteFolderOf = ({ root, siteFolders }, path) => {
  const logical = path.replaceAll('\\', '/');
  const lower = logical.toLowerCase();
  let deepest = null;
  for (const folder of siteFolders) {
    if (lower.startsWith(folder) && (deepest === null || folder.length > deepest.length)) deepest = folder;
  }
  return deepest === null ? root : logical.slice(0, deepest.length);
};

// PHP lying directly in a site folder is the core's own (index.php, wp-login.php) where a core
// lies. In a folder that holds a wp-content and no core (a staging/ copy of wp-content, the folder
// above a core kept in wp/, a copy of the site without its core) nothing of WordPress lies there
// but wp-config.php, which is on the list, so any other such file is named.
const namesFilesLyingInIt = ({ coreFolders, contentFolders }, siteFolder) => {
  const lower = siteFolder.toLowerCase();
  return contentFolders.has(lower) && !coreFolders.has(lower);
};
// What checkCode is told about an archive found inside the copy: no root, so nothing in it is
// always loaded or outside a code folder.
const NOT_A_SITE = {
  root: null,
  siteFolders: new Set(),
  coreFolders: new Set(),
  contentFolders: new Set(),
  languageFolders: new Set(),
  keptApart: new Map(),
  configFolders: new Set(),
  maintenanceFolders: new Set(),
};

// The drop-ins: files of these names lying straight in wp-content, which WordPress loads by
// itself, with nothing to switch on in wp-admin (_get_dropins() in
// wp-admin/includes/plugin.php; the copy read on 2026-11-16 lists these thirteen). Six run on
// every request: db.php, object-cache.php, secrets.php (from WordPress 7.2, unreleased on 2026-11-16) and
// fatal-error-handler.php whenever present, advanced-cache.php with WP_CACHE on, sunrise.php on a
// multisite with SUNRISE defined. The rest run in a situation of their own: db-error.php when
// the database cannot be reached (dead_db()), maintenance.php while the site's .maintenance
// file says an update began less than ten minutes ago, install.php whenever core's upgrade code
// is loaded (wp-admin/includes/upgrade.php: installation, the database upgrade, a plugin that
// pulls it in), php-error.php on a fatal PHP error (WP_Fatal_Error_Handler), the blog-*.php
// three for a site of a network that is deleted, not activated, archived or marked as spam
// (ms_site_check()). A copy started on a new machine is in the first situation until its database is
// connected, and .maintenance is PHP the copy itself brings (see MAINTENANCE_FILE), so it can
// say "an update began just now" on every request. So all thirteen count.
// Compared in lower case, like wp-config.php: Windows finds OBJECT-CACHE.PHP under that name.
const DROP_INS = new Set([
  'advanced-cache.php', 'blog-deleted.php', 'blog-inactive.php', 'blog-suspended.php', 'db-error.php', 'db.php',
  'fatal-error-handler.php', 'install.php', 'maintenance.php', 'object-cache.php', 'php-error.php', 'secrets.php',
  'sunrise.php',
]);

const isDropIn = (name) => DROP_INS.has(name.toLowerCase());

// WordPress requires the .maintenance lying beside wp-settings.php as PHP on every request
// except during installation, before the rest of the site and whatever the file says
// (wp_maintenance() from wp-settings.php, then wp_is_maintenance_mode() in wp-includes/load.php);
// core writes one line there during an update. It has no PHP extension, so it is named here to
// be read as code at all. On the list only in a folder WordPress runs from (beside a core, or in
// a copy of wp-content without its core; runFoldersOf), in any letter case.
const MAINTENANCE_FILE = '.maintenance';

const isMaintenanceFile = (path) => path.replaceAll('\\', '/').split('/').pop().toLowerCase() === MAINTENANCE_FILE;

// WordPress loads PHP from its languages folder by itself (wp-content/languages, or
// wp-includes/languages in a site without the first; wp_set_lang_dir() in wp-includes/load.php):
// - "<locale>.php" on every request (wp-settings.php), so any PHP lying directly in the folder
//   counts, the scanner cannot know the site's language;
// - translation files "<domain>-<locale>.l10n.php" there and in its plugins/ and themes/
//   folders: load_textdomain() turns every .mo name into that name and includes the file, on
//   every request for the site's language, and the update checks include every one of them
//   (wp_get_installed_translations() in wp-includes/l10n.php).
// A translation file that only returns its texts is data and stays off the list
// (isPlainTranslation). Any other PHP in a subfolder runs only when something includes it.
const LANGUAGES_FOLDER = 'wp-content/languages/';
const LANGUAGES_FOLDER_NAME = 'languages';
const CORE_INCLUDES_FOLDER = 'wp-includes';
const TRANSLATION_SUBFOLDERS = new Set(['plugins', 'themes']);
const TRANSLATION_ENDING = '.l10n.php';
const LOCALE_FILE_ENDING = '.php';

const isTranslationName = (path) => path.toLowerCase().endsWith(TRANSLATION_ENDING);

// wp-includes/languages is the languages folder only of a site whose wp-content has none
// (wp_set_lang_dir() in wp-includes/load.php). The wp-content looked at is the one beside the
// core or, for a core kept apart from its content (keptApartContentOf), the one in the folder
// above; a site that moves wp-content anywhere else in wp-config.php is a known limit (docs/rules.md).
const isInCoreLanguages = (parts, { languageFolders, keptApart }) => {
  const includesAt = parts.findIndex((part) => part.toLowerCase() === CORE_INCLUDES_FOLDER);
  if (includesAt < 0 || parts[includesAt + 1]?.toLowerCase() !== LANGUAGES_FOLDER_NAME) return false;
  const coreFolder = parts.slice(0, includesAt).map((part) => `${part.toLowerCase()}/`).join('');
  if (languageFolders.has(keptApart.get(coreFolder) ?? coreFolder)) return false;
  return isLanguageFile(parts.slice(includesAt + 2));
};

// `inside` is the path below the languages folder, split at its separators.
const isLanguageFile = (inside) => {
  if (inside.length === 0) return false;
  const name = inside[inside.length - 1].toLowerCase();
  if (inside.length === 1) return name.endsWith(LOCALE_FILE_ENDING);
  return inside.length === 2 && TRANSLATION_SUBFOLDERS.has(inside[0].toLowerCase()) && name.endsWith(TRANSLATION_ENDING);
};

// A translation file holding nothing but its texts is no code to read. Anything more (a call, a
// variable, a second statement) and it stays on the list, judged as code WordPress loads by
// itself. A file that cannot be read whole, or whose reading runs out of its limits, stays on the
// list too: judgeCode then says why it was not read.
const isPlainTranslation = (container, path, code) => {
  if (code === null || !isTranslationName(path)) return false;
  try {
    return holdsOnlyLiterals(code, createClock(Math.min(performance.now() + CODE_FILE_TIME_MS, container.deadline)));
  } catch (error) {
    if (error instanceof CodeTooLargeError || error instanceof CodeTimeLimitError) return false;
    throw error;
  }
};

// Besides CODE_FOLDERS, WordPress loads the drop-ins lying straight in wp-content and the files
// of its languages folder (isLanguageFile), which are on the list and never get here. Any other
// PHP (lying straight in wp-content too, a file in a languages subfolder that is no translation,
// or one in a cache folder, a backup folder, .well-known, a folder next to the site) runs only
// when something includes it or a request names it. Returns the folder to report it under, or
// null for a usual place. It is judged from the site folder the path lies in (siteFolderOf); a
// file lying directly in it is named only when `namesFilesLyingInIt` says so. Uploads has its own
// findings.
const outsideCodeFolder = (site, path) => {
  const siteFolder = siteFolderOf(site, path);
  const logical = path.replaceAll('\\', '/');
  // A name that leaves the archive's folder is red already, and it has no folder here.
  if (isPathTraversal(logical)) return null;
  // A file lying at the very top of the archive, beside the site's folder, has no folder to name.
  if (!logical.startsWith(siteFolder)) return logical.includes('/') ? `${logical.split('/')[0]}/` : TOP_OF_ARCHIVE;
  const relative = logical.slice(siteFolder.length);
  const lower = relative.toLowerCase();
  const parts = relative.split('/');
  if (lower.startsWith(LANGUAGES_FOLDER) && !lower.endsWith(TRANSLATION_ENDING)) return `${siteFolder}${parts.slice(0, 2).join('/')}/`;
  if (parts.length === 1) return namesFilesLyingInIt(site, siteFolder) ? siteFolder || TOP_OF_ARCHIVE : null;
  if (CODE_FOLDERS.some((folder) => lower.startsWith(folder))) return null;
  if (lower.startsWith('wp-content/')) {
    if (parts.length > 2) return `${siteFolder}${parts.slice(0, 2).join('/')}/`;
    return isDropIn(parts[1]) ? null : `${siteFolder}${parts[0]}/`;
  }
  return `${siteFolder}${parts[0]}/`;
};

// wp-content itself and its languages folder are folders WordPress does load code from (the
// drop-ins, the translations), and a site folder (the '' below: the file lies directly in it)
// holds the wp-config.php on the list, so the sentence about loose PHP there cannot say it
// loads nothing.
const LOOSE_IN_FOLDER = 'folder';
const LOOSE_PLACES = new Map([['wp-content/', 'content'], [LANGUAGES_FOLDER, 'languages'], ['', 'site']]);

const loosePlace = (siteFolder, folder) => {
  const lower = folder.toLowerCase();
  const siteLower = siteFolder.toLowerCase();
  // A site folder at the very top of the archive is named like a file lying there.
  if (siteLower === '' && folder === TOP_OF_ARCHIVE) return 'site';
  if (!lower.startsWith(siteLower)) return LOOSE_IN_FOLDER;
  return LOOSE_PLACES.get(lower.slice(siteLower.length)) ?? LOOSE_IN_FOLDER;
};

const isCodeName = (entry) => (
  !entry.isDirectory && !entry.isSymlink
  && (PHP_EXTENSIONS.has(extensionOf(entry.name.replaceAll('\\', '/'))) || isMaintenanceFile(entry.name))
);

const isCodeFile = (entry) => isCodeName(entry) && isReadable(entry);

// wp-config.php, .maintenance, mu-plugins, the drop-ins (DROP_INS above) and the files of the
// languages folder (isLanguageFile): the code WordPress loads by itself. The list of every include
// in WordPress 7.1.4's core, read on 2026-11-16 by PHP's own tokenizer, names no other file outside
// core, plugins and themes that WordPress reads code from. Until 2026-11-16 every
// PHP file lying straight in wp-content counted, so the stock wp-content/index.php of every
// WordPress was on the list; any other PHP there is now judged as unproven code and reported as
// lying outside the code folders.
//
// Of mu-plugins WordPress runs only the files lying directly in the folder whose names end in
// ".php", case as written (wp_get_mu_plugins in wp-includes/load.php). A file in a subfolder
// runs only when one of those includes it, so it is judged like other unproven code: hosting
// mu-plugins keep most of their code there (WordPress VIP's test runners and its copy of Query
// Monitor call proc_open and exec, measured 2026-11-13).
//
// Mu-plugins, drop-ins and language files are judged by the path alone, wherever the wp-content
// folder lies in the archive: under the copy's own site, under a second WordPress in a
// subfolder, or in a copy of wp-content with no core beside it (contentFoldersOf; such a copy
// is also named as not compared, runFoldersOf). A backslash counts as a folder separator, as it
// will for the Windows program that unpacks the copy.
//
// wp-config.php is the first file of the site WordPress runs, on every request, and no release
// has one to compare it with. It counts in a folder WordPress runs from and in the folder above
// one when wp-load.php reads it there (configFoldersOf); a wp-config.php anywhere else (a
// plugin's folder, a backup folder) is never read as the site's settings and is judged like
// other unproven code. Any letter case counts: Windows, where these copies get run, finds
// WP-CONFIG.PHP under the name wp-config.php.
const CONTENT_FOLDER = 'wp-content';
const MU_PLUGINS_FOLDER = 'mu-plugins';
const MU_PLUGIN_ENDING = '.php';

const isSiteConfig = (path) => path.replaceAll('\\', '/').split('/').pop().toLowerCase() === CONFIG_FILE;

const isAlwaysLoaded = (path, { configFolders, maintenanceFolders, languageFolders, keptApart }) => {
  if (isSiteConfig(path)) return configFolders.has(folderOf(path));
  if (isMaintenanceFile(path)) return maintenanceFolders.has(folderOf(path));
  const parts = path.replaceAll('\\', '/').split('/');
  const contentAt = parts.findIndex((part) => part.toLowerCase() === CONTENT_FOLDER);
  if (contentAt < 0) return isInCoreLanguages(parts, { languageFolders, keptApart });
  const inside = parts.slice(contentAt + 1);
  if (inside.length === 1) return isDropIn(inside[0]);
  if (inside[0].toLowerCase() === LANGUAGES_FOLDER_NAME) return isLanguageFile(inside.slice(1));
  return inside.length === 2 && inside[0].toLowerCase() === MU_PLUGINS_FOLDER && inside[1].endsWith(MU_PLUGIN_ENDING);
};

// The file as text, one character per byte, or null when it cannot be read as a whole. Packed
// data longer than the declared size explains is refused by readWholeFile as damaged; judged
// by the packed size here, a 6-byte file was called "6 B, more than 8 MB".
const readCode = async (container, { entry, scope }) => {
  if (!isReadable(entry)) {
    reportLoadedUnreadable(container, { entry, scope }, '');
    return null;
  }
  if (entry.uncompressedSize > CODE_FILE_LIMIT_BYTES) {
    reportCodeNotRead(container, { entry, scope }, 'bytes');
    return null;
  }
  const { bytes, failure } = await readWholeFile(container, entry);
  if (bytes !== null) return new TextDecoder('latin1').decode(bytes);
  if (failure === DAMAGED) container.reporter.report('entry.corrupt_data', entry.name, { reason: 'code' });
  reportLoadedUnreadable(container, { entry, scope }, failure);
  return null;
};

// Code WordPress loads by itself whose bytes cannot be had at all is red for the same reason as a
// file past a reading limit: whatever an unzip program writes for it would run, and nobody has
// read it. None of the honest copies measured on 2026-11-21 holds such an entry. The zip checks
// have already named the entry (encrypted, packed with another method, damaged, no data where
// the table of contents points), and elsewhere that line is all there is. `failure` is
// readWholeFile's, '' when the entry was never read.
const reportLoadedUnreadable = ({ reporter }, { entry, scope }, failure) => {
  if (scope !== 'loaded') return;
  reporter.report('loaded.code_not_read', entry.name, { bytes: entry.uncompressedSize, reason: unreadableReason(entry, failure) });
};

// In the order the zip checks name an entry (checkNames).
const unreadableReason = (entry, failure) => {
  if (entry.unreadable) return 'unreachable';
  if (entry.isEncrypted) return 'encrypted';
  if (!isSupportedMethod(entry)) return 'method';
  return failure === DAMAGED ? 'damaged' : 'unreachable';
};

// `code` is the file's text, one character per byte; `scope` is 'loaded' or 'unproven'.
const judgeCode = (container, { entry, scope, code }) => {
  const { reporter } = container;
  let signals;
  try {
    signals = findCodeSignals(code, createClock(Math.min(performance.now() + CODE_FILE_TIME_MS, container.deadline)));
  } catch (error) {
    if (error instanceof CodeTooLargeError) {
      reportCodeNotRead(container, { entry, scope }, error.reason);
      return;
    }
    if (!(error instanceof CodeTimeLimitError)) throw error;
    if (performance.now() > container.deadline) throw new TimeLimitError();
    reportCodeNotRead(container, { entry, scope }, TIME_LIMIT_REASON);
    return;
  }
  // One finding per group, the strongest: the visitor reads the file either way.
  for (const [rule, params] of chooseCodeFindings(scope, signals)) reporter.report(rule, entry.name, params);
};

const TIME_LIMIT_REASON = 'time';

// A file the reader gives up on (`reason`: bytes, tokens, nesting, time). Code WordPress loads by
// itself runs on every request with nothing to switch on, so there "not read" means not knowing
// what will run, and it is red: none of the honest always-loaded files measured on 2026-11-20
// ran into a limit (the slowest took 17.5 ms), while a file built to stall a scanner runs into one
// on purpose. Elsewhere the file is only named as not checked. The red finding says that its code
// was not checked, so the file is not named a second time under "Not checked".
const reportCodeNotRead = ({ reporter }, { entry, scope }, reason) => {
  if (scope === 'loaded') {
    reporter.report('loaded.code_not_read', entry.name, { bytes: entry.uncompressedSize, reason });
  } else if (reason === TIME_LIMIT_REASON) {
    reporter.report('code.time_limit', entry.name, {});
  } else {
    reporter.report('code.too_large', entry.name, { bytes: entry.uncompressedSize, reason });
  }
};

const readHead = async ({ source, reporter }, { entry, dataStart }, packed) => {
  let content = packed;
  let isWholeFile = packed.length === entry.compressedSize;
  if (entry.method === METHOD_DEFLATE) {
    // One byte past the head: a file that declares 4 KB or less but unpacks to more is caught
    // here, because its head is all the tail reading looks at.
    let unpacked = await inflaterFor(packed.length, entry.compressedSize)(packed, HEAD_BYTES + 1);
    if (unpacked.state === 'starved') {
      const more = Math.min(entry.compressedSize, HEAD_PACKED_LIMIT);
      const morePacked = await source.view(dataStart, more, 0);
      unpacked = await inflaterFor(more, entry.compressedSize)(morePacked, HEAD_BYTES + 1);
    }
    if (unpacked.state === 'starved') reporter.report('entry.head_unreadable', entry.name, {});
    if (unpacked.state === 'corrupt') reporter.report('entry.corrupt_data', entry.name, { reason: 'stream' });
    content = unpacked.bytes;
    isWholeFile = unpacked.state === 'ended';
  }
  // A file small enough to be read whole gets the full check the zip format offers. A stored
  // file whose two sizes differ has its own finding (zip.stored_size_mismatch).
  if (entry.method === METHOD_DEFLATE && content.length > entry.uncompressedSize) {
    reporter.report('entry.corrupt_data', entry.name, { reason: 'size' });
  } else if (isWholeFile && content.length !== entry.uncompressedSize) {
    reporter.report('entry.corrupt_data', entry.name, { reason: 'size' });
  } else if (isWholeFile && crc32(content) !== entry.crc32) {
    reporter.report('entry.corrupt_data', entry.name, { reason: 'checksum' });
  }
  return content.subarray(0, HEAD_BYTES);
};

const checkHead = (container, file) => {
  const { reporter } = container;
  const { entry, extension, head } = file;
  const bytes = entry.uncompressedSize;
  const program = executableKind(head);
  // "#!" opens every honest shell or Python script, so it only counts where no script belongs.
  const isDisguisedProgram = program !== null && (program !== 'script' || PASSIVE_EXTENSIONS.has(extension));
  if (isDisguisedProgram) {
    reporter.report('layout.disguised_executable', entry.name, { kind: program, extension, bytes });
  }
  const logicalName = entry.name.replaceAll('\\', '/');
  const holdsPhp = PASSIVE_EXTENSIONS.has(extension) && holdsPhpOpenTag(head);
  if (holdsPhp) reporter.report(phpInPassiveFileRule(container.isNested, logicalName, extension), entry.name, { extension });
  if (container.uploadsPhpToJudge.delete(entry)) {
    const isWholeAndInert = head.length === entry.uncompressedSize && isInertPhp(new TextDecoder('latin1').decode(head));
    if (!isWholeAndInert) reporter.report('layout.php_in_uploads', entry.name, {});
  }
  const kind = archiveKind(head, extension);
  if (kind !== null) {
    checkArchiveHead(container, file, kind);
    return;
  }
  if (TEXT_EXTENSIONS.has(extension)) {
    const instruction = findInstruction(new TextDecoder('latin1').decode(head).toLowerCase());
    if (instruction !== null) reporter.report('text.ai_instruction', entry.name, { what: instruction });
  }
  // Only said when nothing above already named what the file really is. A symlink's "content"
  // is its target path, and an empty or unreadable file has nothing to compare.
  const isUnexplained = !isDisguisedProgram && !holdsPhp && !entry.isSymlink && head.length > 0;
  if (isUnexplained && IMAGE_EXTENSIONS.has(extension) && !startsLikeAnImage(head)) {
    reporter.report('layout.not_an_image', entry.name, { extension, bytes });
  }
};

// A file named like media whose first bytes are not an archive: an archive at the front has
// its own findings, and is opened from there.
const mayHideZipAtEnd = ({ entry, extension, head }) => (
  !entry.isSymlink && archiveNameClass(extension) === 'never' && archiveKind(head, extension) === null
);

// Reads the end of the file. An end record there makes the file a candidate; it is opened
// with the other archives, and only a table of contents found where the record points turns
// it into a finding.
const checkTail = async (container, file) => {
  const { entry, dataStart, extension } = file;
  const inside = createProgramScanner(Math.max(entry.compressedSize, entry.uncompressedSize));
  const tail = await readTail(container, file, inside);
  if (inside.found !== null) {
    const { kind, offset } = inside.found;
    container.reporter.report('layout.program_inside_media', entry.name, { kind, extension, offset, bytes: entry.uncompressedSize });
  }
  if (inside.gaveUp) container.reporter.report('layout.inside_not_searched', entry.name, { extension, bytes: entry.uncompressedSize });
  if (tail === null) return;
  // The end is in hand anyway, and PHP glued behind a real picture runs as soon as a loader
  // includes the file. What lies between the first bytes and the end stays unread.
  if (holdsPhpOpenTag(tail)) container.reporter.report('layout.php_in_media', entry.name, { extension });
  if (!holdsEndRecord(tail)) return;
  if (container.isNested) {
    container.reporter.report('archive.not_opened', entry.name, { kind: BEHIND_MEDIA_KIND, bytes: entry.uncompressedSize, reason: 'depth' });
    return;
  }
  container.nestedCandidates.push({
    entry, dataStart, kind: BEHIND_MEDIA_KIND, extension, isDisguised: true, isBehindMedia: true,
  });
};

// The last bytes of the file, or null when they could not be had (the reason is reported, or
// counted for the summary at the end).
// The whole file passes through `inside` on the way, which looks for a program in it.
const readTail = async (container, file, inside) => {
  const { entry, dataStart, head } = file;
  const tailBytes = Math.min(entry.uncompressedSize, END_RECORD_REACH);
  if (head.length === entry.uncompressedSize) {
    inside.feed(head);
    return head.subarray(head.length - tailBytes);
  }
  const { tails } = container;
  const deadline = Math.min(tails.until, container.deadline);
  const { tail, failure } = performance.now() > deadline
    ? { tail: null, failure: TIME }
    : await readThrough(container, file, { tailBytes, deadline, inspect: inside.feed });
  if (failure === TIME) {
    if (performance.now() > container.deadline) throw new TimeLimitError();
    tails.skippedFiles += 1;
    tails.skippedBytes += entry.uncompressedSize;
    // The end of a stored file can be had without what lies before it, so a zip glued behind
    // it is still found.
    return entry.method === METHOD_STORED ? storedTail(container, entry, dataStart) : null;
  }
  if (failure !== '') container.reporter.report('entry.corrupt_data', entry.name, { reason: 'stream' });
  return tail;
};

// The data a stored file really has; a size that disagrees is a red finding of its own.
const storedTail = (container, entry, dataStart) => {
  const tailBytes = Math.min(entry.compressedSize, END_RECORD_REACH);
  return container.source.peek(dataStart + entry.compressedSize - tailBytes, tailBytes);
};

const checkArchiveHead = (container, { entry, dataStart, extension }, kind) => {
  const { reporter } = container;
  const bytes = entry.uncompressedSize;
  const nameClass = archiveNameClass(extension);
  if (nameClass === 'never') {
    reporter.report('layout.archive_as_media', entry.name, { kind, extension, bytes });
  } else if (nameClass === 'other') {
    reporter.report('layout.archive_unexpected_extension', entry.name, { kind, extension, bytes });
  }
  // A packed database dump is unpacked by the database check, or named by it when it lies in a
  // zip found in the copy.
  if (kind === 'gzip' && isDatabaseDump(entry.name)) return;
  if (!isZipKind(kind)) {
    reporter.report('archive.not_opened', entry.name, { kind, bytes, reason: 'format' });
  } else if (container.isNested) {
    reporter.report('archive.not_opened', entry.name, { kind, bytes, reason: 'depth' });
  } else {
    container.nestedCandidates.push({ entry, dataStart, kind, extension, isDisguised: nameClass !== 'container' });
  }
};

// Opens the zips found inside the copy and runs the same checks on their contents. The ones
// behind a false name go first, then the smallest, because the budget can run out. A zip that
// is byte for byte the one in an official release is not opened and costs no budget.
const openNestedArchives = async (copy, emit, verified) => {
  const unproven = copy.nestedCandidates.filter((candidate) => !verified.has(candidate.entry.name));
  const candidates = unproven.sort((left, right) => (
    Number(right.isDisguised) - Number(left.isDisguised) || left.entry.uncompressedSize - right.entry.uncompressedSize
  ));
  const started = performance.now();
  const skipped = [];
  let unpackedBudget = NESTED_TOTAL_UNPACKED_BYTES;

  for (const [position, candidate] of candidates.entries()) {
    const { entry } = candidate;
    const progress = () => emit({
      type: 'progress', stage: 'nested_archives', done: position, total: candidates.length, path: entry.name,
    });
    progress();
    const totalDeadline = started + NESTED_TOTAL_TIME_MS;
    if (position >= NESTED_MAX_ARCHIVES) {
      skipped.push({ candidate, reason: 'budget_count' });
      continue;
    }
    if (performance.now() > totalDeadline) {
      skipped.push({ candidate, reason: 'budget_time' });
      continue;
    }
    const unpacked = await unpackNested(copy, candidate, unpackedBudget);
    unpackedBudget -= unpacked.memoryBytes;
    if (unpacked.reason === 'budget_size') {
      skipped.push({ candidate, reason: 'budget_size' });
      continue;
    }
    if (unpacked.reason) {
      reportNotOpened(copy.reporter, candidate, unpacked.reason);
      continue;
    }
    const deadline = Math.min(totalDeadline, performance.now() + NESTED_ARCHIVE_TIME_MS);
    await checkNested(copy, candidate, { blob: unpacked.blob, deadline, progress });
  }
  reportSkipped(copy.reporter, skipped);
};

// A nested zip stored without compression is read straight from the visitor's file, a slice
// with no copy in memory. A compressed one has to be unpacked whole, because its table of
// contents sits at its end; that is what the size limits are for.
const unpackNested = async (copy, { entry, dataStart }, unpackedBudget) => {
  const packed = copy.source.blob.slice(dataStart, dataStart + entry.compressedSize);
  if (entry.method === METHOD_STORED) return { blob: packed, memoryBytes: 0, reason: '' };
  // Whatever is left of the total allowance caps this archive too, down to zero.
  const limit = Math.min(NESTED_UNPACKED_LIMIT_BYTES, unpackedBudget);
  const unpacked = await inflateAll(packed, limit);
  if (unpacked.state === 'too_large') {
    const reason = limit < NESTED_UNPACKED_LIMIT_BYTES ? 'budget_size' : 'too_large';
    return { blob: null, memoryBytes: 0, reason };
  }
  if (unpacked.state === 'corrupt') {
    copy.reporter.report('entry.corrupt_data', entry.name, { reason: 'stream' });
    return { blob: null, memoryBytes: 0, reason: 'damaged' };
  }
  const checksum = unpacked.chunks.reduce((previous, chunk) => crc32(chunk, previous), 0);
  if (unpacked.bytes !== entry.uncompressedSize) {
    copy.reporter.report('entry.corrupt_data', entry.name, { reason: 'size' });
  } else if (checksum !== entry.crc32) {
    copy.reporter.report('entry.corrupt_data', entry.name, { reason: 'checksum' });
  }
  return { blob: new Blob(unpacked.chunks), memoryBytes: unpacked.bytes, reason: '' };
};

// `blob` is the unpacked archive, `deadline` when its checks must stop, `progress` what the
// page is told while they run.
const checkNested = async (copy, candidate, { blob, deadline, progress }) => {
  const outerName = candidate.entry.name;
  // Its entries are checked as unpacked and named as written (asUnpacked), like the copy's own.
  let writtenOf = new Map();
  const reporter = {
    report: (rule, path, params) => (
      copy.reporter.report(rule, path === '' ? outerName : `${outerName}${NESTED_SEPARATOR}${writtenOf.get(path) ?? path}`, params, { file: outerName })
    ),
  };
  const source = new ArchiveSource(blob);
  const { isBehindMedia = false } = candidate;
  try {
    const archive = asUnpacked(await openZip(blob, NESTED_MAX_ENTRIES));
    writtenOf = writtenNamesOf(archive.entries);
    if (isBehindMedia) {
      copy.reporter.report('layout.archive_behind_media', outerName, { extension: candidate.extension, bytes: candidate.entry.uncompressedSize });
    }
    const nested = {
      source, archive, reporter, isNested: true, isBehindMedia, deadline, nestedCandidates: [], tails: copy.tails, progress,
      alive: copy.alive,
    };
    await checkContainer(nested);
    await checkCode(nested, NOT_A_SITE, new Set());
    // The database checks lean on the site around the dump (its plugins, its address), which a
    // zip found in the copy does not give, so a dump inside one is named instead.
    for (const entry of archive.entries) {
      if (!entry.isDirectory && isDatabaseDump(entry.name)) reporter.report('db.in_nested_archive', entry.name, { bytes: entry.uncompressedSize });
    }
  } catch (error) {
    if (error instanceof TimeLimitError) {
      reportNotOpened(copy.reporter, candidate, 'time');
    } else if (error instanceof ZipFormatError && isBehindMedia && !error.code.startsWith('ambiguous_')) {
      // The end record was chance unless a table of contents lies where it points. Two
      // records or two tables that both fit are no chance, and are reported below. The reader
      // refuses some archives before it looks for that table, so the look is made here.
      if (REFUSED_BEFORE_TABLE.has(error.code) && await endRecordFindsTable(blob)) {
        copy.reporter.report('layout.archive_behind_media', outerName, { extension: candidate.extension, bytes: candidate.entry.uncompressedSize });
        reportNotOpened(copy.reporter, candidate, NOT_OPENED_REASONS.get(error.code));
      }
    } else if (error instanceof ZipFormatError && NOT_OPENED_REASONS.has(error.code)) {
      reportNotOpened(copy.reporter, candidate, NOT_OPENED_REASONS.get(error.code));
    } else if (error instanceof ZipFormatError) {
      copy.reporter.report(`zip.${error.code}`, outerName, error.params);
    } else {
      throw error;
    }
  } finally {
    copy.source.bytesRead += source.bytesRead;
  }
};

const reportNotOpened = (reporter, { entry, kind }, reason) => {
  reporter.report('archive.not_opened', entry.name, { kind, bytes: entry.uncompressedSize, reason });
};

// Archives the budget did not reach: the first ones by name, the rest counted per extension,
// so two thousand zips in uploads do not become two thousand lines nobody reads.
const reportSkipped = (reporter, skipped) => {
  for (const { candidate, reason } of skipped.slice(0, NESTED_SKIPPED_LISTED)) {
    reportNotOpened(reporter, candidate, reason);
  }
  const groups = new Map();
  for (const { candidate, reason } of skipped.slice(NESTED_SKIPPED_LISTED)) {
    const key = `${candidate.extension} ${reason}`;
    const group = groups.get(key) ?? { extension: candidate.extension, reason, files: 0, bytes: 0 };
    group.files += 1;
    group.bytes += candidate.entry.uncompressedSize;
    groups.set(key, group);
  }
  for (const group of groups.values()) reporter.report('archive.not_opened_group', '', group);
};

// Bytes that no listed file accounts for. A tool that unpacks by walking the file from the
// front (instead of reading the table at the end) extracts whatever file headers it meets
// there, so a header found in such a stretch is a file this scanner was not shown.
const reportGaps = async ({ source, reporter, isBehindMedia }, gaps) => {
  let budget = GAP_INSPECT_BUDGET_BYTES;
  for (const gap of gaps) {
    const inspectBytes = Math.min(gap.bytes, budget);
    budget -= inspectBytes;
    const lead = await source.view(gap.start, Math.min(gap.bytes, HEAD_BYTES), 0);
    const params = {
      bytes: gap.bytes,
      offset: gap.start,
      inspectedBytes: inspectBytes,
      kind: executableKind(lead) ?? archiveKind(lead, '') ?? '',
    };
    if (gap.start !== 0) reporter.report('zip.unlisted_bytes', '', params);
    else if (!isBehindMedia) reporter.report('zip.prepended_data', '', params);
    const headerAt = await findLocalHeader(source, gap.start, inspectBytes);
    if (headerAt >= 0) reporter.report('zip.unlisted_entry', '', { offset: headerAt });
  }
};

const findLocalHeader = async (source, start, length) => {
  const overlap = LOCAL_HEADER_SIGNATURE.length - 1;
  for (let at = start; at < start + length; at += GAP_CHUNK_BYTES) {
    const chunkBytes = Math.min(GAP_CHUNK_BYTES + overlap, start + length - at);
    const found = indexOfBytes(await source.view(at, chunkBytes, 0), LOCAL_HEADER_SIGNATURE);
    if (found >= 0) return at + found;
  }
  return -1;
};

const indexOfBytes = (haystack, needle) => {
  let from = 0;
  for (;;) {
    const at = haystack.indexOf(needle[0], from);
    if (at < 0 || at + needle.length > haystack.length) return -1;
    if (needle.every((byte, offset) => haystack[at + offset] === byte)) return at;
    from = at + 1;
  }
};

// Findings past the cap are counted, not sent one by one: an archive built to produce a
// million findings must not be able to choke the page. A rule names a file once, even when
// two passes over the archive both run into the same problem.
const createReporter = (emit) => {
  const reported = new Map();
  // The first file each rule named. The page draws one row per file, so a rule's findings lie
  // scattered among the rows, and the line that counts the ones past the cap names this file
  // to say which finding it counts.
  const firstPaths = new Map();
  const named = new Set();
  // Red finding path -> the entry the visitor can find for it, null when two entries share one path.
  const red = new Map();
  return {
    redFiles: () => red,
    // `file` is the entry the finding is about: the path itself, or for a file inside an archive
    // found in the copy, that archive (checkNested). The path alone cannot say which: an entry may
    // be named "pack.zip » mockup.jpeg" itself.
    report(rule, path, params, { file = path } = {}) {
      const severity = RULES.get(rule);
      if (severity === undefined) throw new Error(`rule missing from rules.js: ${rule}`);
      if (path !== '') {
        // Before the repeat is dropped: a second file reported under the same path and rule
        // still makes the path ambiguous.
        if (severity === 'red') red.set(path, red.has(path) && red.get(path) !== file ? null : file);
        const key = `${rule}\u{0}${path}`;
        if (named.has(key)) return;
        named.add(key);
        if (!firstPaths.has(rule)) firstPaths.set(rule, path);
      }
      const count = (reported.get(rule) ?? 0) + 1;
      reported.set(rule, count);
      if (count <= FINDINGS_PER_RULE) emit({ type: 'finding', severity, rule, path, params });
    },
    reportOverflow() {
      for (const [rule, count] of reported) {
        if (count > FINDINGS_PER_RULE) {
          emit({
            type: 'finding',
            severity: RULES.get(rule),
            rule,
            path: '',
            params: { more: count - FINDINGS_PER_RULE, example: firstPaths.get(rule) ?? '' },
          });
        }
      }
    },
  };
};

// What the file-type checks say about a file that may be an official one waits for the
// checksums: a README with a PHP example or a build script shipped in a wordpress.org plugin is
// what its authors published, not a trap. Everything else goes straight through.
const createHoldingReporter = (reporter, mayBeHeld) => {
  const held = [];
  return {
    report(rule, path, params) {
      if (rule.startsWith('layout.') && mayBeHeld(path)) held.push({ rule, path, params });
      else reporter.report(rule, path, params);
    },
    release(verified) {
      for (const { rule, path, params } of held) {
        if (!verified.has(path)) reporter.report(rule, path, params);
      }
    },
  };
};

