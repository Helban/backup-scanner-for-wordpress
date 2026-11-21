// SPDX-License-Identifier: GPL-3.0-or-later
//
// The database dump read as a stream: a dump of a gigabyte never sits in memory whole. What
// this module looks for is what this scanner's private prototype looked for in the dump:
//   eval of base64_decode stored anywhere, the classic hidden PHP in options or posts;
//   a file kept in a row as base64 text (a program, PHP code, an archive), told by its first
//     bytes once decoded, the way php-rules.js judges such a string in a PHP file;
//   PHP kept by snippet plugins (WPCode rows, a Code Snippets table), which a clean file tree
//     says nothing about;
//   plugins the dump calls active whose folder the copy lacks (a partial export);
//   <script src> pointing at outside hosts;
//   sentences written for an AI assistant reading the copy.
// It also reads the site's own address (siteurl, home), which the settings check needs to tell the
// site's redirects from redirects elsewhere. Worker side only.
//
// The text is searched with indexOf and, for base64, with one loop over its characters that
// skips ahead, and the few regular expressions only ever see a slice of at most LOOKAHEAD
// characters, so the cost grows with the size of the dump and nothing else.
// A dump packed with gzip is unpacked on the way (gunzip.js), whatever its name says.

import { ENCODED_MIN_LENGTH } from './code-rules.js';
import { withoutWww } from './config-rules.js';
import { DAMAGED, PROGRESS_INTERVAL_MS, streamWholeFile } from './entries.js';
import { createGunzip } from './gunzip.js';
import { bytesOf, decodeBase64, packedFileIn } from './php-rules.js';
import { holdsPhpOpenTag } from './signatures.js';
import { LONGEST_INSTRUCTION, findInstruction } from './text-rules.js';

// Every match is judged with this many characters after it and LOOKBEHIND before it. The tail
// of one piece is carried into the next, so a match cut in two by the stream is still seen,
// and seen once.
const LOOKAHEAD = 1024;
const LOOKBEHIND = 64;
const ACTIVE_PLUGINS_LIMIT = 64 * 1024;
const HOSTS_LISTED = 5;
// WPCode keeps snippets as posts of this type; Code Snippets in its own table (checked in
// both plugins' sources on 2026-11-09). Both run the PHP they store.
const SNIPPET_PLUGINS = new Set(['insert-headers-and-footers', 'code-snippets']);
const SNIPPET_POST_TYPE = '\'wpcode\'';
const TABLE_START = 'create table `';
const SNIPPET_TABLE_END = 'snippets';
// A backtick further than this from `create table` closes something else than a table name.
const TABLE_NAME_REACH = 128;
const EVAL_BEFORE_DECODE = /eval\s*\(\s*(?:gzinflate\s*\(\s*)?$/;
// Run on one tag only (tagEnd), never on the text around it.
const SCRIPT_SOURCE = /\ssrc=\\?["']?https?:\/\/([^/\\'"\s>]{1,253})/;
const SITE_ADDRESS = /^'(?:siteurl|home)'\s*,\s*'https?:\/\/([^/'\\:]{1,253})/;
const ACTIVE_LIST_KEYS = ['\'active_plugins\'', '\'active_sitewide_plugins\''];
// 'active_plugins', 'a:2:{...}': the value opens a few characters after the key.
const KEY_TO_VALUE = 64;
// A serialized plugin path: s:19:"akismet/akismet.php" (mysqldump writes the quotes as \").
const PLUGIN_PATH = /s:\d+:\\?"([^"/\\]+)\//g;

// Base64 kept in a row. A run is base64 letters, and inside it escaped line breaks (mysqldump
// writes \n, JSON inside a row \\n; chunk_split puts one every 76 letters) and escaped slashes
// (JSON writes \/, which mysqldump makes \\/). PHP's base64_decode skips the breaks, so they
// are skipped here too. Only the head of a run is decoded: 768 letters are 576 bytes, which
// reach the PE header of a Windows program at its usual place (byte 128 to 280) and the
// "ustar" of a tar at byte 257. A run is also judged from behind its first group of line
// breaks: a mail keeps its attachment behind a header line that ends in letters
// ("filename=setup.exe\r\n\r\nTVqQ"), and read as one run the two decode out of step.
const BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const IS_BASE64_LETTER = new Uint8Array(256);
for (const letter of BASE64_ALPHABET) IS_BASE64_LETTER[letter.charCodeAt(0)] = 1;
const BACKSLASH = 0x5c;
const SLASH = 0x2f;
// The n and r of an escaped line break.
const isBreakLetter = (code) => code === 0x6e || code === 0x72;
// Escaping inside escaping doubles the backslashes each time: four levels are 8.
const ESCAPE_BACKSLASHES_MAX = 8;
const HEAD_LETTERS = 768;
// A run, and the second head judged behind its first line breaks, are read no further than this
// from the run's start, so whatever the piece it starts in, both are read the same (an escape
// is up to ESCAPE_BACKSLASHES_MAX + 1 characters).
const RUN_REACH = LOOKAHEAD - ESCAPE_BACKSLASHES_MAX - 1;
// What a base64 letter is, told by the backslashes right in front of it.
const DATA_LETTER = 0;
// The n, r or / of an escaped line break or slash: part of a run, never its first letter.
const ESCAPE_LETTER = 1;
// The 0 of \0, the Z of \Z, the t of \t: mysqldump's escapes of characters that are no base64
// letters at all. They belong to their backslash, so a run starts behind them.
const ESCAPED_CHARACTER = 2;
// The statement at the start of a line, read this far (a database name, the IGNORE and
// LOW_PRIORITY words and a 64-character table name in backticks fit).
const STATEMENT_HEAD = 256;
const ROW_LINE = /^[ \t]*\(/;
// INSERT or REPLACE, its optional words, then `db`.`table` or `table`, with or without backticks.
const INSERT_STATEMENT = /^[ \t]*(?:insert|replace)[ \t]+(?:(?:low_priority|delayed|high_priority|ignore)[ \t]+)*(?:into[ \t]+)?(?:(?:`[^`]*`|[\w$]+)[ \t]*\.[ \t]*)?(`[^`]*`|[\w$]+)/i;
const TABLE_NAME = /^[A-Za-z0-9_$]{1,64}$/;
// The breaks of a run taken out before decoding; the backslashes of \/ go with the other
// characters base64_decode skips.
const ESCAPED_BREAK = /\\+[nr]/g;

// mysqldump's .sql, the same packed with gzip, and the database file of UpdraftPlus,
// backup_<date>-<site>-db.gz (-db1.gz and on for further databases; its backup.php).
const DUMP_NAME = /(?:\.sql|\.sql\.gz|-db\d*\.gz)$/i;
export const isDatabaseDump = (name) => DUMP_NAME.test(name);

// A packed dump is unpacked no further than this; the rest is named as not checked. A zero bomb
// of 4 MB reaches it, an honest dump of a site someone runs at home rarely does.
const UNPACKED_LIMIT_BYTES = 4 * 1024 ** 3;
const GZIP_START = [0x1f, 0x8b];

// Reads every dump in `dumps` and reports what it finds. Returns the site's host names.
export const checkDatabases = async (container, dumps, presentPlugins) => {
  const siteHosts = new Set();
  for (const entry of dumps) {
    const reading = createDumpReader();
    const input = createDumpInput(reading, container.alive);
    const reportProgress = createProgress(entry, container.progress);
    const failure = await streamWholeFile(container, entry, (piece) => {
      input.push(piece);
      reportProgress(piece.length);
    });
    const unpacking = input.finish();
    reading.finish();
    container.progress({ stage: 'database', done: entry.uncompressedSize, total: entry.uncompressedSize, path: '' });
    // Data that cannot be reached at all was reported by the first-bytes check already.
    if (failure === DAMAGED || unpacking === 'damaged' || unpacking === 'truncated') {
      container.reporter.report('entry.corrupt_data', entry.name, { reason: 'database' });
    }
    if (unpacking === 'too_large') container.reporter.report('db.unpacked_too_large', entry.name, { bytes: UNPACKED_LIMIT_BYTES });
    reportDump(container.reporter, { path: entry.name, found: reading.found }, presentPlugins);
    for (const host of reading.found.siteHosts) siteHosts.add(host);
  }
  return siteHosts;
};

// The first two bytes decide whether the dump is unpacked, not its name, which can be wrong
// either way. finish() returns the state of the unpacking ('ended' for a dump that was not
// packed).
const createDumpInput = (reading, alive) => {
  let start = new Uint8Array(0);
  let gunzip = null;
  let isDecided = false;
  const feed = (piece) => (gunzip === null ? reading.feed(piece) : gunzip.push(piece));
  return {
    push(piece) {
      if (isDecided) {
        feed(piece);
        return;
      }
      const joined = new Uint8Array(start.length + piece.length);
      joined.set(start);
      joined.set(piece, start.length);
      start = joined;
      if (start.length < GZIP_START.length) return;
      isDecided = true;
      if (GZIP_START.every((byte, index) => start[index] === byte)) {
        gunzip = createGunzip({
          onBytes: (bytes) => {
            reading.feed(bytes);
            alive();
          },
          limitBytes: UNPACKED_LIMIT_BYTES,
        });
      }
      feed(start);
    },
    finish() {
      if (!isDecided) reading.feed(start);
      return gunzip === null ? 'ended' : gunzip.finish().state;
    },
  };
};

// Progress counts the bytes of the file as stored, which for a packed dump is not what the
// reader sees.
const createProgress = (entry, progress) => {
  let bytes = 0;
  let lastProgress = -Infinity;
  return (pieceBytes) => {
    bytes += pieceBytes;
    const now = performance.now();
    if (now - lastProgress <= PROGRESS_INTERVAL_MS) return;
    lastProgress = now;
    progress({ stage: 'database', done: bytes, total: entry.uncompressedSize, path: entry.name });
  };
};

const reportDump = (reporter, { path, found }, presentPlugins) => {
  if (found.evalOfDecoded) reporter.report('db.eval_base64', path, {});
  for (const [rule, params] of found.encodedFiles) reporter.report(rule, path, params);
  if (found.snippetRows) reporter.report('db.snippet_rows', path, {});
  const activeSnippets = [...found.activePlugins].filter((slug) => SNIPPET_PLUGINS.has(slug));
  if (activeSnippets.length > 0) reporter.report('db.snippet_plugin_active', path, { plugins: activeSnippets.join(', ') });
  const missing = [...found.activePlugins].filter((slug) => !presentPlugins.has(slug)).sort();
  if (missing.length > 0) reporter.report('db.active_plugin_missing', path, { missing: missing.length, example: missing.slice(0, HOSTS_LISTED).join(', ') });
  // The site's own address may stand later in the dump than the posts that load its scripts.
  const hosts = [...found.scriptHosts].filter((host) => !found.siteHosts.has(withoutWww(host))).sort();
  if (hosts.length > 0) {
    reporter.report('db.external_script_host', path, { hosts: hosts.length, example: hosts.slice(0, HOSTS_LISTED).join(', ') });
  }
  if (found.instruction !== null) reporter.report('text.ai_instruction', path, { what: found.instruction });
};

// Takes the dump piece by piece (feed), then finish(); `found` holds the result. Exported for
// the test that cuts one dump at every offset. A piece is read at once and never kept.
export const createDumpReader = () => {
  const decoder = new TextDecoder('latin1');
  const found = {
    evalOfDecoded: false,
    // Rule -> { what, table } of the first file of that kind found as base64 text.
    encodedFiles: new Map(),
    snippetRows: false,
    activePlugins: new Set(),
    scriptHosts: new Set(),
    siteHosts: new Set(),
    instruction: null,
  };
  let carry = '';
  // How many characters at the start of `carry` were judged already (they are only there to
  // be looked back at).
  let judged = 0;
  // The value of active_plugins, while it is still being read across pieces.
  let activeList = null;
  // The table of the rows on the last line judged so far, '' before the first statement, on a
  // line of another statement or when its name could not be read.
  let lineTable = '';

  // Matches from `judged` on are judged; those starting in the last LOOKAHEAD characters wait
  // for the next piece, which starts with those characters (and LOOKBEHIND before them), so
  // every match is judged exactly once, with its full context on both sides.
  const searchPiece = (text) => searchUntil(text, Math.max(judged, text.length - LOOKAHEAD));
  // The last text has no next piece to leave anything to.
  const searchLast = (text) => searchUntil(text, text.length);

  const searchUntil = (text, until) => {
    const lower = text.toLowerCase();
    const span = { from: judged, until };
    // An open list has read up to the end of the previous text, the carried part included.
    if (activeList !== null) activeList = continueActiveList(activeList, text.slice(carry.length), found);
    findEvalOfDecoded(lower, span, found);
    findSnippets(lower, span, found);
    findScripts(lower, span, found);
    findSiteAddress(lower, span, found);
    // Base64 is case-sensitive, so the runs are read from the text as it is.
    lineTable = findEncodedFiles({ text, span, found, lineTable });
    activeList = findActiveList(text, span, found) ?? activeList;
    found.instruction ??= findInstruction(lower.slice(span.from, span.until + LONGEST_INSTRUCTION));
    const keepFrom = Math.max(0, span.until - LOOKBEHIND);
    judged = span.until - keepFrom;
    carry = text.slice(keepFrom);
  };

  return {
    found,
    feed(piece) {
      searchPiece(carry + decoder.decode(piece, { stream: true }));
    },
    finish() {
      searchLast(carry + decoder.decode());
    },
  };
};

// Where `needle` stands in `text`, for every place that starts inside the span.
const indexesIn = function* indexesIn(text, needle, { from, until }) {
  for (let at = text.indexOf(needle, from); at >= 0 && at < until; at = text.indexOf(needle, at + 1)) yield at;
};

const occursIn = (text, needle, { from, until }) => {
  const at = text.indexOf(needle, from);
  return at >= 0 && at < until;
};

const findEvalOfDecoded = (lower, span, found) => {
  if (found.evalOfDecoded) return;
  for (const at of indexesIn(lower, 'base64_decode', span)) {
    if (EVAL_BEFORE_DECODE.test(lower.slice(Math.max(0, at - LOOKBEHIND), at))) found.evalOfDecoded = true;
  }
};

const findSnippets = (lower, span, found) => {
  if (found.snippetRows) return;
  if (occursIn(lower, SNIPPET_POST_TYPE, span)) found.snippetRows = true;
  for (const at of indexesIn(lower, TABLE_START, span)) {
    const nameStart = at + TABLE_START.length;
    const nameEnd = lower.indexOf('`', nameStart);
    if (nameEnd > nameStart && nameEnd - nameStart < TABLE_NAME_REACH && lower.slice(nameStart, nameEnd).endsWith(SNIPPET_TABLE_END)) {
      found.snippetRows = true;
    }
  }
};

const findScripts = (lower, span, found) => {
  for (const at of indexesIn(lower, '<script', span)) {
    // The tag ends at its ">" or at the next "<", so tags never overlap and a dump made of
    // "<script" over and over costs no more than its length.
    const source = SCRIPT_SOURCE.exec(lower.slice(at, tagEnd(lower, at)));
    if (source) found.scriptHosts.add(source[1]);
  }
};

const tagEnd = (lower, at) => {
  const limit = Math.min(lower.length, at + LOOKAHEAD);
  for (let end = at + 1; end < limit; end += 1) {
    if (lower[end] === '>' || lower[end] === '<') return end;
  }
  return limit;
};

const findSiteAddress = (lower, span, found) => {
  for (const key of ['\'siteurl\'', '\'home\'']) {
    for (const at of indexesIn(lower, key, span)) {
      const address = SITE_ADDRESS.exec(lower.slice(at, at + LOOKAHEAD));
      if (address) found.siteHosts.add(withoutWww(address[1]));
    }
  }
};

// Every base64 run that starts inside the span is judged once, by its head and by the head behind
// its first line breaks. Returns the table of the last line judged, for runs in the pieces after.
//
// A run of ENCODED_MIN_LENGTH letters spans at least that many characters, each a letter or a
// backslash. So the search checks the last character of such a stretch first and jumps past any
// other character it meets, the way a string search skips (Horspool): honest rows, with a
// space or a quote every few characters, are crossed in steps of up to that length.
const findEncodedFiles = (reading) => {
  const { text, span, lineTable } = reading;
  let at = span.from;
  while (at < span.until) {
    const breaker = lastBreakerBefore(text, at, at + ENCODED_MIN_LENGTH);
    at = breaker >= 0 ? breaker + 1 : judgeStretch(reading, at);
  }
  return span.until > span.from ? tableOfLine(reading, lineStartOf(text, span.until - 1)) : lineTable;
};

// The last character in [from, to) that cannot be part of a run, or -1.
const lastBreakerBefore = (text, from, to) => {
  for (let at = to - 1; at >= from; at -= 1) {
    if (!canBeInRun(text.charCodeAt(at))) return at;
  }
  return -1;
};

const canBeInRun = (code) => IS_BASE64_LETTER[code] === 1 || code === BACKSLASH;

// Judges the runs that start from `start` up to the end of its stretch of run characters (or the
// end of the span), and returns where the stretch ends.
const judgeStretch = (reading, start) => {
  const { text, span } = reading;
  let at = start;
  for (; at < span.until && canBeInRun(text.charCodeAt(at)); at += 1) {
    if (!startsRun(text, at)) continue;
    const reachEnd = Math.min(text.length, at + RUN_REACH);
    const run = readRun(text, at, reachEnd);
    noteEncodedFile(reading, at, run);
    if (run.afterBreaks >= 0) noteEncodedFile(reading, at, readRun(text, run.afterBreaks, reachEnd));
    // No place inside a run starts another, so the search goes on from its end.
    at = run.end - 1;
  }
  return at;
};

const noteEncodedFile = (reading, runStart, head) => {
  if (head.letters < ENCODED_MIN_LENGTH) return;
  const file = encodedFileIn(reading.text.slice(head.start, head.end).replace(ESCAPED_BREAK, ''));
  if (file === null || reading.found.encodedFiles.has(file.rule)) return;
  const { rule, ...params } = file;
  reading.found.encodedFiles.set(rule, { ...params, table: tableOfLine(reading, lineStartOf(reading.text, runStart)) });
};

// A run starts at a letter or an escape that does not go on from a run before it.
const startsRun = (text, at) => {
  const before = text.charCodeAt(at - 1);
  if (IS_BASE64_LETTER[before] === 1 && letterRole(text, at - 1) !== ESCAPED_CHARACTER) return false;
  const code = text.charCodeAt(at);
  if (code === BACKSLASH) return before !== BACKSLASH && escapeLength(text, at) > 0;
  return IS_BASE64_LETTER[code] === 1 && letterRole(text, at) === DATA_LETTER;
};

// An escaped line break or slash takes 1 to ESCAPE_BACKSLASHES_MAX backslashes. Otherwise an odd
// number escapes the letter (mysqldump's \0, \Z, \t), and an even one is that many backslashes
// kept in the row, the letter after them a letter of its own. The count stops one past
// ESCAPE_BACKSLASHES_MAX, an odd number, so a longer run of backslashes escapes the letter too.
const letterRole = (text, at) => {
  let backslashes = 0;
  while (backslashes <= ESCAPE_BACKSLASHES_MAX && text.charCodeAt(at - backslashes - 1) === BACKSLASH) backslashes += 1;
  if (backslashes === 0) return DATA_LETTER;
  const code = text.charCodeAt(at);
  const isEscapable = code === SLASH || isBreakLetter(code);
  if (backslashes <= ESCAPE_BACKSLASHES_MAX && isEscapable) return ESCAPE_LETTER;
  return backslashes % 2 === 0 ? DATA_LETTER : ESCAPED_CHARACTER;
};

// The run's head from `start`: where it ends, how many base64 letters it holds, and where the
// letters behind its first group of line breaks start (-1 when there are none). Breaks before the
// first letter do not count: a value that opens with a blank line keeps its second start for the
// breaks behind its first line. It ends at the first character that is neither a letter nor an
// escape, at `reachEnd`, or where the head is complete.
const readRun = (text, start, reachEnd) => {
  let at = start;
  let letters = 0;
  let afterBreaks = -1;
  let isInBreaks = false;
  while (at < reachEnd && letters < HEAD_LETTERS) {
    const isLetter = IS_BASE64_LETTER[text.charCodeAt(at)] === 1;
    const length = isLetter ? 1 : escapeLength(text, at);
    if (length === 0) break;
    if (!isLetter && isBreakLetter(text.charCodeAt(at + length - 1))) {
      isInBreaks = letters > 0 && afterBreaks < 0;
    } else {
      if (isInBreaks) afterBreaks = at;
      isInBreaks = false;
      letters += 1;
    }
    at += length;
  }
  return { start, end: at, letters, afterBreaks };
};

// The length of the escape whose backslashes start at `at`, 0 when none starts there.
const escapeLength = (text, at) => {
  let backslashes = 0;
  while (backslashes <= ESCAPE_BACKSLASHES_MAX && text.charCodeAt(at + backslashes) === BACKSLASH) backslashes += 1;
  if (backslashes === 0 || backslashes > ESCAPE_BACKSLASHES_MAX) return 0;
  const letter = text.charCodeAt(at + backslashes);
  return letter === SLASH || isBreakLetter(letter) ? backslashes + 1 : 0;
};

// The judgment of a base64 string in a PHP file (php-rules.js), reused: a program by its full
// header, PHP by its open tag, an archive by its first bytes in a head long enough to be one.
const encodedFileIn = (letters) => {
  const decoded = decodeBase64(letters);
  const packed = packedFileIn(decoded);
  if (packed?.signal === 'encoded_program') return { rule: 'db.encoded_program', what: packed.kind };
  if (holdsPhpOpenTag(bytesOf(decoded))) return { rule: 'db.encoded_code' };
  return packed === null ? null : { rule: 'db.encoded_archive', what: packed.kind };
};

const lineStartOf = (text, at) => (at <= 0 ? 0 : text.lastIndexOf('\n', at - 1) + 1);

// The table whose rows the line starting at `lineStart` holds. Every dumper escapes a line break
// inside a value, so a real one ends a statement or a row: mysqldump writes a statement with its
// rows on one line, MariaDB's dump and UpdraftPlus a row per line starting with "(" (the dumps of
// the test copies). A line of any other statement (CREATE, LOCK, a comment) holds no rows. A line
// before the span was judged with an earlier piece: its table is `lineTable` ('' before the dump's
// first line).
const tableOfLine = ({ text, span, lineTable }, lineStart) => {
  for (let at = lineStart; at >= span.from; at = at > 0 ? lineStartOf(text, at - 1) : -1) {
    const head = text.slice(at, at + STATEMENT_HEAD);
    if (!ROW_LINE.test(head)) return insertedTable(head);
  }
  return lineTable;
};

// The table an INSERT or REPLACE at the start of `head` writes to, the last part of a name with
// its database in front; '' for any other statement or a name of other characters than a
// table's (letters, digits, _ and $, at most 64).
const insertedTable = (head) => {
  const statement = INSERT_STATEMENT.exec(head);
  if (statement === null) return '';
  const name = statement[1].replaceAll('`', '');
  return TABLE_NAME.test(name) ? name : '';
};

// The serialized list is read from the quote that opens it to the quote that closes it; it
// can be longer than LOOKAHEAD, so it may continue in the next piece. Returns what is still
// open, or null.
const findActiveList = (text, span, found) => {
  let open = null;
  for (const key of ACTIVE_LIST_KEYS) {
    for (const at of indexesIn(text, key, span)) {
      // Both marks are looked for near the key only. A search of the whole piece found, for a
      // key with no comma after it, the first quote of the piece, before the key itself.
      const near = text.slice(at + key.length, at + KEY_TO_VALUE + 1);
      const comma = near.indexOf(',');
      const quote = comma < 0 ? -1 : near.indexOf('\'', comma + 1);
      if (quote >= 0) open = continueActiveList('', text.slice(at + key.length + quote + 1), found);
    }
  }
  return open;
};

const continueActiveList = (serializedSoFar, text, found) => {
  const close = text.indexOf('\'');
  const serialized = serializedSoFar + (close < 0 ? text : text.slice(0, close));
  if (close < 0 && serialized.length < ACTIVE_PLUGINS_LIMIT) return serialized;
  for (const match of serialized.slice(0, ACTIVE_PLUGINS_LIMIT).matchAll(PLUGIN_PATH)) found.activePlugins.add(match[1]);
  return null;
};
