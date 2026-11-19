// SPDX-License-Identifier: GPL-3.0-or-later
//
// The page treats the worker as untrusted: the worker parses hostile bytes, so whatever it
// sends is checked against this fixed shape before anything is drawn. A message that does
// not fit ends the scan.

import { RULES } from './rules.js';

const MAX_TEXT = 4096;
const MAX_PARAMS = 8;
const MAX_LISTED = 300;
const STAGES = new Set(['first_bytes', 'checksums', 'php_code', 'database', 'nested_archives']);
const COMPONENT_KINDS = new Set(['core', 'plugin']);
const SHA256_FORMAT = /^[0-9a-f]{64}$/;

export class ProtocolError extends Error {
  constructor(reason) {
    super(reason);
    this.name = 'ProtocolError';
  }
}

export const parseWorkerEvent = (raw) => {
  if (raw === null || typeof raw !== 'object') throw new ProtocolError('message is not an object');
  const parse = PARSERS.get(raw.type);
  if (parse === undefined) throw new ProtocolError('unknown message type');
  return parse(raw);
};

const text = (field) => {
  if (typeof field !== 'string' || field.length > MAX_TEXT) throw new ProtocolError('bad text field');
  return field;
};

const count = (field) => {
  if (!Number.isSafeInteger(field) || field < 0) throw new ProtocolError('bad number field');
  return field;
};

const textList = (field) => {
  if (!Array.isArray(field) || field.length > MAX_LISTED) throw new ProtocolError('bad list field');
  return field.map(text);
};

const namedVersions = (field) => {
  if (!Array.isArray(field) || field.length > MAX_LISTED) throw new ProtocolError('bad list of components');
  return field.map((component) => {
    if (component === null || typeof component !== 'object') throw new ProtocolError('bad component');
    return { slug: text(component.slug), version: text(component.version) };
  });
};

const params = (field) => {
  if (field === null || typeof field !== 'object') throw new ProtocolError('bad params');
  const pairs = Object.entries(field);
  if (pairs.length > MAX_PARAMS) throw new ProtocolError('too many params');
  // A Map, not an object: a key such as "__proto__" stays a plain key.
  return new Map(pairs.map(([name, param]) => [text(name), typeof param === 'number' ? count(param) : text(param)]));
};

const PARSERS = new Map([
  ['opened', (raw) => ({
    type: 'opened',
    files: count(raw.files),
    folders: count(raw.folders),
    declaredBytes: count(raw.declaredBytes),
  })],
  ['facts', (raw) => {
    if (!Array.isArray(raw.databases) || raw.databases.length > MAX_LISTED) throw new ProtocolError('bad databases');
    return {
      type: 'facts',
      root: text(raw.root),
      version: text(raw.version),
      locale: text(raw.locale),
      plugins: textList(raw.plugins),
      themes: textList(raw.themes),
      databases: raw.databases.map((database) => {
        if (database === null || typeof database !== 'object') throw new ProtocolError('bad database');
        return { path: text(database.path), bytes: count(database.bytes) };
      }),
    };
  }],
  // What the worker wants looked up. The gateway checks the formats; here only the shape.
  ['lookup', (raw) => {
    const isCoreAsked = raw.core !== null && typeof raw.core === 'object';
    if (!isCoreAsked && raw.core !== null) throw new ProtocolError('bad core question');
    return {
      type: 'lookup',
      core: isCoreAsked ? { version: text(raw.core.version), locale: text(raw.core.locale) } : null,
      plugins: namedVersions(raw.plugins),
    };
  }],
  // Names and versions for the vulnerability lookup; the gateway checks the formats.
  ['inventory', (raw) => {
    const isCoreGiven = raw.core !== null && typeof raw.core === 'object';
    if (!isCoreGiven && raw.core !== null) throw new ProtocolError('bad core in inventory');
    return {
      type: 'inventory',
      core: isCoreGiven ? { version: text(raw.core.version) } : null,
      plugins: namedVersions(raw.plugins),
      themes: namedVersions(raw.themes),
    };
  }],
  ['component', (raw) => {
    if (!COMPONENT_KINDS.has(raw.kind)) throw new ProtocolError('unknown component kind');
    return {
      type: 'component',
      kind: raw.kind,
      name: text(raw.name),
      version: text(raw.version),
      state: text(raw.state),
      files: count(raw.files),
      matched: count(raw.matched),
      modified: count(raw.modified),
      extra: count(raw.extra),
      missing: count(raw.missing),
    };
  }],
  // Code that WordPress loads by itself (wp-config.php, .maintenance, mu-plugins, drop-ins and language files):
  // listed for reading whatever the rules said about it.
  ['loaded_code', (raw) => {
    if (!Array.isArray(raw.files) || raw.files.length > MAX_LISTED) throw new ProtocolError('bad loaded code list');
    return {
      type: 'loaded_code',
      total: count(raw.total),
      files: raw.files.map((file) => {
        if (file === null || typeof file !== 'object') throw new ProtocolError('bad loaded code file');
        return { path: text(file.path), bytes: count(file.bytes), name: text(file.name) };
      }),
    };
  }],
  // The hosts the database names as the site's own address.
  ['site_hosts', (raw) => ({ type: 'site_hosts', hosts: textList(raw.hosts) })],
  // Sent while one large file is read, so that the page does not take the wait for a stall.
  ['alive', () => ({ type: 'alive' })],
  ['progress', (raw) => {
    if (!STAGES.has(raw.stage)) throw new ProtocolError('unknown stage');
    return { type: 'progress', stage: raw.stage, done: count(raw.done), total: count(raw.total), path: text(raw.path) };
  }],
  ['finding', (raw) => {
    if (!RULES.has(raw.rule) || RULES.get(raw.rule) !== raw.severity) throw new ProtocolError('unknown rule or weight');
    return { type: 'finding', severity: raw.severity, rule: raw.rule, path: text(raw.path), params: params(raw.params) };
  }],
  // The SHA-256 of files with a red finding, for the report, each with the paths of the findings
  // it belongs to.
  ['hashes', (raw) => {
    if (!Array.isArray(raw.files) || raw.files.length > MAX_LISTED) throw new ProtocolError('bad list of hashes');
    return {
      type: 'hashes',
      files: raw.files.map((file) => {
        if (file === null || typeof file !== 'object') throw new ProtocolError('bad hashed file');
        if (typeof file.sha256 !== 'string' || !SHA256_FORMAT.test(file.sha256)) throw new ProtocolError('bad hash');
        return { path: text(file.path), sha256: file.sha256, findings: textList(file.findings) };
      }),
    };
  }],
  ['done', (raw) => ({
    type: 'done',
    completed: raw.completed === true,
    bytesRead: count(raw.bytesRead),
    milliseconds: count(raw.milliseconds),
  })],
]);
