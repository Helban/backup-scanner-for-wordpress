// SPDX-License-Identifier: GPL-3.0-or-later
//
// Answers from wpvulnerability.net, read into a small fixed shape before anything is shown.
// They are foreign data, like the archive. What is kept are facts: identifiers, the version
// range, the score, the weakness type and links to four known sources. Descriptions are left
// out on purpose, because each source keeps its own terms for its texts.

import { OPERATORS, versionSatisfies } from './version-compare.js';

// The largest answer measured (2026-11-13, 39 plugins and 12 themes) has 132 entries.
const MAX_ENTRIES = 2000;
const MAX_SOURCES = 16;
const MAX_IDS = 4;
const MAX_LINKS = 4;
const MAX_LINK_LENGTH = 2048;
const MAX_WEAKNESS_NAME = 200;
const MAX_SCORE = 10;
const BOUND_FORMAT = /^[0-9A-Za-z.+_-]{1,64}$/;
// CVE, and the EU database's own number, which some entries carry instead (5 of 69 for 6.8).
const IDENTIFIER_FORMAT = /^(?:CVE|EUVD)-\d{4}-\d{4,7}$/;
const CWE_FORMAT = /^CWE-\d{1,5}$/;
// Threat model item 5: a link from the database is drawn only when it points to one of these.
const LINK_HOSTS = new Set(['www.cve.org', 'www.wordfence.com', 'patchstack.com', 'wpscan.com']);
// The newest scoring first; the legacy block is CVSS 3 under an older name.
const SCORE_BLOCKS = ['cvss3', 'cvss4', 'cvss'];

export class UnusableAnswerError extends Error {
  constructor(reason) {
    super(reason);
    this.name = 'UnusableAnswerError';
  }
}

class UnreadableEntryError extends Error {
  constructor(reason) {
    super(reason);
    this.name = 'UnreadableEntryError';
  }
}

// The core answer lists the entries of the very version asked about, without ranges.
export const readCoreAdvisories = (body) => collect(answerEntries(body), readCoreEntry, () => true);

// A plugin or theme answer lists everything known for the name, and the range decides. It is
// read the way the database's own WordPress plugin reads it (wpvulnerability-general.php):
// both bounds when both are given, otherwise the one that is.
export const readComponentAdvisories = (body, version) => (
  collect(answerEntries(body), readRangedEntry, (entry) => inRange(entry.range, version))
);

const answerEntries = (body) => {
  if (body === null || typeof body !== 'object' || body.error !== 0) throw new UnusableAnswerError('not a usable answer');
  const { data } = body;
  if (data === null || typeof data !== 'object' || Array.isArray(data)) throw new UnusableAnswerError('no data');
  // A name or version the database does not know is answered with `null` here.
  if (data.vulnerability === null) return [];
  if (!Array.isArray(data.vulnerability) || data.vulnerability.length > MAX_ENTRIES) {
    throw new UnusableAnswerError('bad list of entries');
  }
  return data.vulnerability;
};

// An entry this reader cannot judge is counted, never dropped in silence.
const collect = (rawEntries, readEntry, applies) => {
  const entries = [];
  let unreadable = 0;
  for (const raw of rawEntries) {
    let entry;
    try {
      entry = readEntry(raw);
    } catch (error) {
      if (!(error instanceof UnreadableEntryError)) throw error;
      unreadable += 1;
      continue;
    }
    if (applies(entry)) entries.push(entry);
  }
  return { entries, unreadable };
};

const readCoreEntry = (raw) => {
  if (raw === null || typeof raw !== 'object') throw new UnreadableEntryError('not an object');
  return { ...readFacts(raw), range: null, unfixed: false };
};

const readRangedEntry = (raw) => {
  const entry = readCoreEntry(raw);
  const { operator } = raw;
  if (operator === null || typeof operator !== 'object') throw new UnreadableEntryError('no range');
  const range = { ...readBound(operator.min_operator, operator.min_version, 'min'), ...readBound(operator.max_operator, operator.max_version, 'max') };
  if (range.minOperator === '' && range.maxOperator === '') throw new UnreadableEntryError('range without bounds');
  return { ...entry, range, unfixed: operator.unfixed === '1' || operator.unfixed === 1 };
};

const readBound = (operator, version, side) => {
  if (operator === null && version === null) return { [`${side}Operator`]: '', [side]: '' };
  if (!OPERATORS.has(operator) || typeof version !== 'string' || !BOUND_FORMAT.test(version)) {
    throw new UnreadableEntryError('bad bound');
  }
  return { [`${side}Operator`]: operator, [side]: version };
};

const inRange = (range, version) => (
  (range.minOperator === '' || versionSatisfies(version, range.minOperator, range.min))
  && (range.maxOperator === '' || versionSatisfies(version, range.maxOperator, range.max))
);

// Sources, score and weakness only decorate an entry: a malformed one is left out, the entry stays.
const readFacts = (raw) => {
  const sources = Array.isArray(raw.source) ? raw.source.slice(0, MAX_SOURCES).filter(isObject) : [];
  const impact = isObject(raw.impact) ? raw.impact : {};
  return {
    ids: unique(sources.map((source) => source.id).filter((id) => typeof id === 'string' && IDENTIFIER_FORMAT.test(id))).slice(0, MAX_IDS),
    links: unique(sources.map((source) => allowedLink(source.link)).filter(Boolean)).slice(0, MAX_LINKS),
    score: readScore(impact),
    weakness: readWeakness(impact.cwe),
  };
};

const allowedLink = (link) => {
  if (typeof link !== 'string' || link.length > MAX_LINK_LENGTH) return '';
  let address;
  // Not URL.canParse: Safari has it from 17, DecompressionStream from 16.4, and in between the
  // scan would fail at this step.
  try {
    address = new URL(link);
  } catch (error) {
    if (error instanceof TypeError) return '';
    throw error;
  }
  const isPlain = address.protocol === 'https:' && address.username === '' && address.password === '' && address.port === '';
  return isPlain && LINK_HOSTS.has(address.hostname) ? address.href : '';
};

// -1 when no block carries a usable score.
const readScore = (impact) => {
  for (const name of SCORE_BLOCKS) {
    const block = impact[name];
    if (!isObject(block) || (typeof block.score !== 'string' && typeof block.score !== 'number')) continue;
    const score = Number(block.score);
    if (block.score !== '' && Number.isFinite(score) && score >= 0 && score <= MAX_SCORE) return Math.round(score * 10) / 10;
  }
  return -1;
};

const readWeakness = (list) => {
  const isUsable = (weakness) => isObject(weakness) && typeof weakness.cwe === 'string' && CWE_FORMAT.test(weakness.cwe);
  const first = Array.isArray(list) ? list.find(isUsable) : undefined;
  if (first === undefined) return null;
  const name = typeof first.name === 'string' ? first.name.slice(0, MAX_WEAKNESS_NAME) : '';
  return { id: first.cwe, name };
};

const isObject = (candidate) => candidate !== null && typeof candidate === 'object' && !Array.isArray(candidate);
const unique = (values) => [...new Set(values)];
