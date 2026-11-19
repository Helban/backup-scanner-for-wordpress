// SPDX-License-Identifier: GPL-3.0-or-later
//
// The copy compared with what wordpress.org publishes: the core checksum list (MD5) and one
// list per plugin (MD5 and SHA-256). A file that matches is proven to be the official file, and
// what the other checks said about it is withdrawn. The lists reach the worker through the page,
// which fetched them; this module never sees the network.

import { DAMAGED, PROGRESS_INTERVAL_MS, isReadable, readWholeFile, streamWholeFile } from './entries.js';
import { createMd5 } from './md5.js';
import { PHP_EXTENSIONS, extensionOf, holdsPhpOpenTag } from './signatures.js';

// Above this a file is hashed in pieces, and pieces only work for MD5 (Web Crypto has no
// streaming SHA-256). No official plugin file comes near it.
const IN_MEMORY_LIMIT_BYTES = 32 * 1024 * 1024;
const PHP_TAG_START = [0x3c, 0x3f];
// Files a site keeps in its root folder that no release ships.
const SITE_FILES = new Set(['wp-config.php']);

const COMPONENT_STATES = new Set([
  'listed', 'not_listed', 'version_not_listed', 'closed', 'network', 'request_limit', 'bad_answer',
]);

// `site` is the copy's WordPress (engine.js describeSite), `question` what the worker asked
// for, `answers` what the page found out:
// { core: { state, files: Map(path -> [md5]) } | null,
//   plugins: Map(slug -> { state, files: Map(path -> { md5: [..], sha256: [..] }) }) }
export const verifyComponents = async (container, { site, question, answers }, emit) => {
  // What each official list expects of the copy's files, gathered list by list.
  const comparison = { container, site, files: indexFiles(container.archive.entries), expectations: new Map() };
  const components = [];
  if (question.core) {
    components.push(planCore(comparison, question.core, answerOf(answers.core)));
  }
  for (const plugin of question.plugins) {
    const answer = answerOf(answers.plugins instanceof Map ? answers.plugins.get(plugin.slug) : null);
    components.push(planPlugin(comparison, plugin, answer));
  }

  const verified = await compareFiles(container, comparison.expectations, emit);
  for (const component of components) {
    await reportComponent(container, component, verified);
    emit({
      type: 'component',
      kind: component.kind,
      name: component.name,
      version: component.version,
      state: component.state,
      files: component.listed,
      matched: component.matched,
      modified: component.modified.length,
      extra: component.extra.length,
      missing: component.missing.length,
    });
  }
  return verified;
};

const answerOf = (answer) => {
  const isUsable = answer !== null && typeof answer === 'object' && COMPONENT_STATES.has(answer.state);
  if (!isUsable) return { state: 'bad_answer', files: new Map() };
  if (answer.state === 'listed' && !(answer.files instanceof Map)) return { state: 'bad_answer', files: new Map() };
  return answer;
};

// The first entry of a name wins; a second one is reported by the zip reader already.
const indexFiles = (entries) => {
  const files = new Map();
  for (const entry of entries) {
    if (!entry.isDirectory && !files.has(entry.name)) files.set(entry.name, entry);
  }
  return files;
};

const newComponent = ({ kind, name, version, path, state }) => ({
  kind, name, version, path, state, listed: 0, matched: 0, modified: [], extra: [], missing: [],
});

const planCore = ({ container, site, files, expectations }, core, answer) => {
  const component = newComponent({ kind: 'core', name: 'WordPress', version: core.version, path: site.root, state: answer.state });
  if (answer.state !== 'listed') {
    container.reporter.report('component.not_compared', site.root, { kind: 'core', reason: answer.state });
    return component;
  }
  for (const [relative, md5] of answer.files) {
    component.listed += 1;
    // The list also covers the bundled themes, Akismet and language packs, which update on
    // their own schedule: missing or different there is normal, and the plugin list judges.
    // They lie in the site's wp-content, above the core when the core is kept in wp/.
    const isCoreCode = !relative.startsWith('wp-content/');
    const name = (isCoreCode ? site.root : site.contentRoot) + relative;
    const entry = files.get(name);
    if (entry === undefined) {
      if (isCoreCode) component.missing.push(name);
      continue;
    }
    expect(expectations, entry, { component, md5, sha256: [], countsAsModified: isCoreCode });
  }
  for (const [name, entry] of files) {
    if (!name.startsWith(site.root)) continue;
    const relative = name.slice(site.root.length);
    if (answer.files.has(relative)) continue;
    if (relative.startsWith('wp-admin/') || relative.startsWith('wp-includes/')) {
      component.extra.push({ entry, rule: '' });
    } else if (!relative.includes('/') && PHP_EXTENSIONS.has(extensionOf(relative)) && !SITE_FILES.has(relative)) {
      component.extra.push({ entry, rule: 'core.extra_root_php' });
    }
  }
  return component;
};

const planPlugin = ({ container, site, files, expectations }, plugin, answer) => {
  const folder = `${site.contentRoot}wp-content/plugins/${plugin.slug}/`;
  const component = newComponent({ kind: 'plugin', name: plugin.slug, version: plugin.version, path: folder, state: answer.state });
  if (answer.state !== 'listed') {
    container.reporter.report('component.not_compared', folder, { kind: 'plugin', reason: answer.state });
    return component;
  }
  for (const [relative, digests] of answer.files) {
    component.listed += 1;
    const entry = files.get(folder + relative);
    if (entry === undefined) component.missing.push(folder + relative);
    else expect(expectations, entry, { component, md5: digests.md5, sha256: digests.sha256, countsAsModified: true });
  }
  for (const [name, entry] of files) {
    if (name.startsWith(folder) && !answer.files.has(name.slice(folder.length))) {
      component.extra.push({ entry, rule: '' });
    }
  }
  return component;
};

const expect = (expectations, entry, expectation) => {
  const list = expectations.get(entry) ?? [];
  list.push(expectation);
  expectations.set(entry, list);
};

// One pass in the order the data lies in the file. An entry listed by two components (Akismet
// is in the core list and has its own) is proven when either list matches.
const compareFiles = async (container, expectations, emit) => {
  const verified = new Set();
  const order = [...expectations.keys()].sort((left, right) => left.headerOffset - right.headerOffset);
  let lastProgress = -Infinity;
  for (const [position, entry] of order.entries()) {
    const now = performance.now();
    if (now - lastProgress > PROGRESS_INTERVAL_MS) {
      lastProgress = now;
      emit({ type: 'progress', stage: 'checksums', done: position, total: order.length, path: entry.name });
    }
    const listedBy = expectations.get(entry);
    const digests = await digestEntry(container, entry, listedBy);
    if (digests === null) continue;
    const matching = listedBy.filter((expectation) => matches(expectation, digests));
    if (matching.length > 0) {
      verified.add(entry.name);
      for (const expectation of listedBy) expectation.component.matched += 1;
      continue;
    }
    for (const expectation of listedBy) {
      if (expectation.countsAsModified) expectation.component.modified.push(entry.name);
    }
  }
  emit({ type: 'progress', stage: 'checksums', done: order.length, total: order.length, path: '' });
  return verified;
};

// SHA-256 wherever the list has it and the file fits in memory: MD5 is only as good as its
// resistance to collisions, and a plugin author could publish one half of a colliding pair.
const digestEntry = async (container, entry, listedBy) => {
  if (!isReadable(entry)) return null;
  const wantsSha256 = listedBy.some((expectation) => expectation.sha256.length > 0);
  const fitsInMemory = entry.uncompressedSize <= IN_MEMORY_LIMIT_BYTES && entry.compressedSize <= IN_MEMORY_LIMIT_BYTES;
  if (fitsInMemory) {
    const { bytes, failure } = await readWholeFile(container, entry);
    if (bytes === null) return reportUnreadable(container, entry, failure);
    const md5 = createMd5();
    md5.add(bytes);
    return { md5: md5.hex(), sha256: wantsSha256 ? await sha256Hex(bytes) : '' };
  }
  const md5 = createMd5();
  const failure = await streamWholeFile(container, entry, (piece) => md5.add(piece));
  return failure === '' ? { md5: md5.hex(), sha256: '' } : reportUnreadable(container, entry, failure);
};

// Data that cannot be reached was reported by the first-bytes check already.
const reportUnreadable = (container, entry, failure) => {
  if (failure === DAMAGED) container.reporter.report('entry.corrupt_data', entry.name, { reason: 'whole' });
  return null;
};

export const sha256Hex = async (content) => {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', content));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join('');
};

const matches = (expectation, digests) => {
  if (digests.sha256 !== '' && expectation.sha256.length > 0) return expectation.sha256.includes(digests.sha256);
  return expectation.md5.includes(digests.md5);
};

const reportComponent = async (container, component, verified) => {
  const { reporter } = container;
  const rulePrefix = component.kind === 'core' ? 'core' : 'plugin';
  for (const name of component.modified) reporter.report(`${rulePrefix}.modified`, name, {});
  for (const { entry, rule } of component.extra) {
    if (verified.has(entry.name)) continue;
    const judge = component.kind === 'core' ? judgeExtraCoreFile : judgeExtraPluginFile;
    reporter.report(rule || await judge(container, entry), entry.name, {});
  }
  if (component.missing.length > 0) {
    reporter.report(`${rulePrefix}.missing_files`, component.path, {
      missing: component.missing.length,
      example: component.missing[0],
    });
  }
};

// Plugins write guard files such as an index.php that only says "Silence is golden" into
// their own folders at run time. Without a PHP tag such a file runs nothing.
const judgeExtraPluginFile = async (container, entry) => {
  if (!PHP_EXTENSIONS.has(extensionOf(entry.name))) return 'plugin.extra_file';
  const holdsCode = entry.uncompressedSize > IN_MEMORY_LIMIT_BYTES || await holdsPhpTag(container, entry);
  return holdsCode ? 'plugin.extra_php' : 'plugin.extra_file';
};

// A file in wp-admin or wp-includes that the release does not have. With a PHP name or with
// PHP inside it is the shape of a backdoor. Without either it is what hosts and plugins leave
// there (PHP's own error_log, an .htaccess with a password prompt), which cannot run; the
// server settings check reads the .htaccess on its own.
const judgeExtraCoreFile = async (container, entry) => {
  if (PHP_EXTENSIONS.has(extensionOf(entry.name))) return 'core.extra_file';
  if (entry.uncompressedSize > IN_MEMORY_LIMIT_BYTES || entry.compressedSize > IN_MEMORY_LIMIT_BYTES) return 'core.extra_other';
  const { bytes } = await readWholeFile(container, entry);
  // Unreadable content has its own "not checked" finding; here it counts as possible code.
  return bytes === null || holdsPhpOpenTag(bytes) ? 'core.extra_file' : 'core.extra_other';
};

const holdsPhpTag = async (container, entry) => {
  const { bytes } = await readWholeFile(container, entry);
  // Unreadable content has its own "not checked" finding; here it counts as possible code.
  if (bytes === null) return true;
  for (let at = bytes.indexOf(PHP_TAG_START[0]); at >= 0; at = bytes.indexOf(PHP_TAG_START[0], at + 1)) {
    if (bytes[at + 1] === PHP_TAG_START[1]) return true;
  }
  return false;
};
