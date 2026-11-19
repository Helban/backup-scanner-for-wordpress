// SPDX-License-Identifier: GPL-3.0-or-later
//
// The database dump read as a stream: a dump of a gigabyte never sits in memory whole. What
// this module looks for is what this scanner's private prototype looked for in the dump:
//   eval of base64_decode stored anywhere, the classic hidden PHP in options or posts;
//   PHP kept by snippet plugins (WPCode rows, a Code Snippets table), which a clean file tree
//     says nothing about;
//   plugins the dump calls active whose folder the copy lacks (a partial export);
//   <script src> pointing at outside hosts;
//   sentences written for an AI assistant reading the copy.
// It also reads the site's own address (siteurl, home), which the settings check needs to tell the
// site's redirects from redirects elsewhere. Worker side only.
//
// The text is searched with indexOf, and the few regular expressions only ever see a slice of
// at most LOOKAHEAD characters, so the cost grows with the size of the dump and nothing else.

import { withoutWww } from './config-rules.js';
import { DAMAGED, PROGRESS_INTERVAL_MS, streamWholeFile } from './entries.js';
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

export const isDatabaseDump = (name) => name.toLowerCase().endsWith('.sql');

// Reads every dump in `dumps` and reports what it finds. Returns the site's host names.
export const checkDatabases = async (container, dumps, presentPlugins) => {
  const siteHosts = new Set();
  for (const entry of dumps) {
    const reading = createDumpReader(entry, container.progress);
    const failure = await streamWholeFile(container, entry, (piece) => reading.feed(piece));
    reading.finish();
    // Data that cannot be reached at all was reported by the first-bytes check already.
    if (failure === DAMAGED) container.reporter.report('entry.corrupt_data', entry.name, { reason: 'database' });
    reportDump(container.reporter, { path: entry.name, found: reading.found }, presentPlugins);
    for (const host of reading.found.siteHosts) siteHosts.add(host);
  }
  return siteHosts;
};

const reportDump = (reporter, { path, found }, presentPlugins) => {
  if (found.evalOfDecoded) reporter.report('db.eval_base64', path, {});
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
// the test that cuts one dump at every offset. `progress({ stage, done, total, path })` is the
// container's.
export const createDumpReader = (entry, progress) => {
  const decoder = new TextDecoder('latin1');
  const found = {
    evalOfDecoded: false,
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
  let bytes = 0;
  let lastProgress = -Infinity;
  // The value of active_plugins, while it is still being read across pieces.
  let activeList = null;

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
    activeList = findActiveList(text, span, found) ?? activeList;
    found.instruction ??= findInstruction(lower.slice(span.from, span.until + LONGEST_INSTRUCTION));
    const keepFrom = Math.max(0, span.until - LOOKBEHIND);
    judged = span.until - keepFrom;
    carry = text.slice(keepFrom);
  };

  return {
    found,
    feed(piece) {
      bytes += piece.length;
      searchPiece(carry + decoder.decode(piece, { stream: true }));
      const now = performance.now();
      if (now - lastProgress > PROGRESS_INTERVAL_MS) {
        lastProgress = now;
        progress({ stage: 'database', done: bytes, total: entry.uncompressedSize, path: entry.name });
      }
    },
    finish() {
      searchLast(carry + decoder.decode());
      progress({ stage: 'database', done: bytes, total: entry.uncompressedSize, path: '' });
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
