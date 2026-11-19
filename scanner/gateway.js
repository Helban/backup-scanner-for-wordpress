// SPDX-License-Identifier: GPL-3.0-or-later
//
// The only code on the page that talks to the network. The worker hands it names and versions
// read from the archive; they are checked against fixed formats and filled into fixed address
// templates, so no other address can be built here. What comes back is foreign data as well and
// is checked before the worker or the page uses it.

import { UnusableAnswerError, readComponentAdvisories, readCoreAdvisories } from './advisories.js';

const SLUG_FORMAT = /^[a-z0-9-]{1,200}$/;
const VERSION_FORMAT = /^[0-9A-Za-z.+-]{1,32}$/;
const LOCALE_FORMAT = /^[a-z]{2,3}(_[A-Z]{2})?(_[a-z0-9]+)?$/;
const MD5_FORMAT = /^[0-9a-f]{32}$/;
const SHA256_FORMAT = /^[0-9a-f]{64}$/;
const MAX_REQUESTS = 150;
const PARALLEL_REQUESTS = 4;
const REQUEST_TIMEOUT_MS = 30_000;
// The largest list measured is WooCommerce 11.3.0: 5,452 files, 978 KB.
const MAX_ANSWER_BYTES = 16 * 1024 * 1024;
const MAX_LISTED_FILES = 100_000;
const MAX_LISTED_PATH = 1024;
const MAX_DIGESTS_PER_FILE = 8;
const DATE_FORMAT = /^\d{4}-\d{2}-\d{2}$/;
const CLOSURE_REASON_FORMAT = /^[a-z0-9-]{1,64}$/;
const SERVER_ERROR_STATUS = 500;
// Everything else about a plugin is left out of the answer; only "found or not" is needed.
const INFO_FIELDS_OFF = [
  'sections', 'versions', 'reviews', 'screenshots', 'banners', 'icons', 'contributors', 'tags', 'description', 'ratings',
].map((field) => `&request[fields][${field}]=0`).join('');

const ADDRESSES = {
  core_checksums: ({ version, locale }) => (
    `https://api.wordpress.org/core/checksums/1.0/?version=${encodeURIComponent(version)}&locale=${encodeURIComponent(locale)}`
  ),
  plugin_checksums: ({ slug, version }) => (
    `https://downloads.wordpress.org/plugin-checksums/${encodeURIComponent(slug)}/${encodeURIComponent(version)}.json`
  ),
  plugin_info: ({ slug }) => (
    `https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]=${encodeURIComponent(slug)}${INFO_FIELDS_OFF}`
  ),
  // The plugin and theme answers list every known entry for the name, so the version stays here.
  core_vulnerabilities: ({ version }) => `https://www.wpvulnerability.net/core/${encodeURIComponent(version)}/`,
  plugin_vulnerabilities: ({ slug }) => `https://www.wpvulnerability.net/plugin/${encodeURIComponent(slug)}/`,
  theme_vulnerabilities: ({ slug }) => `https://www.wpvulnerability.net/theme/${encodeURIComponent(slug)}/`,
};

// `onRequest({ kind, url, slug, version, locale })` is called before every request, so the
// page can show each one. The limit counts per gateway, and the page makes one per scan.
export const createGateway = (onRequest) => {
  let requestsLeft = MAX_REQUESTS;
  // The plugin directory is asked about a name once per scan, whichever step asks first.
  const directory = new Map();
  const request = async (kind, subject) => {
    if (requestsLeft === 0) return { outcome: 'request_limit' };
    requestsLeft -= 1;
    const url = ADDRESSES[kind](subject);
    onRequest({ kind, url, ...subject });
    return fetchJson(url);
  };
  const askDirectory = (slug) => {
    if (!directory.has(slug)) directory.set(slug, request('plugin_info', { slug }).then(readDirectory));
    return directory.get(slug);
  };
  return {
    lookup: async (question) => {
      const core = question.core ? await lookupCore(question.core, request) : null;
      const pluginAnswers = await inLanes(question.plugins, (plugin) => lookupPlugin(plugin, request, askDirectory));
      return { core, plugins: new Map(question.plugins.map((plugin, at) => [plugin.slug, pluginAnswers[at]])) };
    },
    // Known vulnerabilities of what the copy holds, and whether wordpress.org closed a plugin.
    // Asked after the checksums, so the comparison never waits for this or loses requests to it.
    advisories: async (inventory) => {
      const core = inventory.core ? [await coreAdvisory(inventory.core, request)] : [];
      const plugins = await inLanes(inventory.plugins, (plugin) => pluginAdvisory(plugin, request, askDirectory));
      const themes = await inLanes(inventory.themes, (theme) => componentAdvisory('theme', theme, request));
      return [...core, ...plugins, ...themes];
    },
    // A finished or abandoned scan starts no new request.
    stop: () => {
      requestsLeft = 0;
    },
  };
};

const lookupCore = async (core, request) => {
  if (!VERSION_FORMAT.test(core.version) || !LOCALE_FORMAT.test(core.locale)) return { state: 'not_listed' };
  const reply = await request('core_checksums', { version: core.version, locale: core.locale });
  if (reply.outcome !== 'answer') return { state: reply.outcome };
  if (reply.status !== 200 || reply.body === null || typeof reply.body !== 'object') return { state: 'bad_answer' };
  // An unknown version or language is answered with 200 and { "checksums": false }.
  if (reply.body.checksums === false) return { state: 'not_listed' };
  return listed(() => readCoreList(reply.body.checksums));
};

// downloads.wordpress.org answers an unknown plugin or version with a 404 that carries no CORS
// header, which a browser cannot tell from a dead network. Only then is the plugin directory
// asked, which answers both ways readably.
const lookupPlugin = async (plugin, request, askDirectory) => {
  // Slugs on wordpress.org are lower-case letters, digits and hyphens; any other folder name
  // cannot be one of them.
  if (!SLUG_FORMAT.test(plugin.slug) || !VERSION_FORMAT.test(plugin.version)) return { state: 'not_listed' };
  const checksums = await request('plugin_checksums', { slug: plugin.slug, version: plugin.version });
  const isUnknownThere = checksums.outcome === 'network' || (checksums.outcome === 'answer' && checksums.status === 404);
  if (!isUnknownThere) {
    if (checksums.outcome !== 'answer') return { state: checksums.outcome };
    return checksums.status === 200 ? listed(() => readPluginList(checksums.body)) : { state: 'bad_answer' };
  }
  const entry = await askDirectory(plugin.slug);
  return { state: entry.state === 'listed' ? 'version_not_listed' : entry.state };
};

// state: listed, closed (with the date and reason wordpress.org gives), not_listed, or the
// outcome of a failed request.
const readDirectory = (reply) => {
  if (reply.outcome !== 'answer') return { state: reply.outcome };
  const { status, body } = reply;
  if (body === null || typeof body !== 'object') return { state: 'bad_answer' };
  if (status === 200 && body.slug !== undefined) return { state: 'listed' };
  if (status === 404 && body.closed === true) return { state: 'closed', closed: closure(body) };
  if (status === 404 && typeof body.error === 'string') return { state: 'not_listed' };
  return { state: 'bad_answer' };
};

const closure = (body) => ({
  date: typeof body.closed_date === 'string' && DATE_FORMAT.test(body.closed_date) ? body.closed_date : '',
  reason: typeof body.reason === 'string' && CLOSURE_REASON_FORMAT.test(body.reason) ? body.reason : '',
});

// state: checked, no_version, bad_name, or why the database gave no usable answer. A closed
// plugin is asked about too: its checksums may still be served (measured on display-widgets
// 2.7, closed in 2021 for a security issue), so the comparison alone would call it official.
// So is one whose version the copy does not show: closed is closed in any version.
// When the vulnerabilities came back and only the directory did not, that is said apart
// (closureUnknown): the entries were looked up, whether the plugin is closed was not.
const pluginAdvisory = async (plugin, request, askDirectory) => {
  const advisory = await componentAdvisory('plugin', plugin, request);
  if (!['checked', 'no_version', 'network', 'unavailable', 'bad_answer'].includes(advisory.state)) return advisory;
  const entry = await askDirectory(plugin.slug);
  if (entry.state === 'closed') return { ...advisory, closed: entry.closed };
  const directoryFailed = ['network', 'request_limit', 'bad_answer'].includes(entry.state);
  return { ...advisory, closureUnknown: directoryFailed && advisory.state === 'checked' };
};

const componentAdvisory = async (kind, component, request) => {
  const advisory = newAdvisory(kind, component.slug, component.version);
  if (!SLUG_FORMAT.test(component.slug)) return { ...advisory, state: 'bad_name' };
  if (!VERSION_FORMAT.test(component.version)) return { ...advisory, state: 'no_version' };
  const reply = await request(`${kind}_vulnerabilities`, { slug: component.slug });
  return readAdvisoryReply(advisory, reply, (body) => readComponentAdvisories(body, component.version));
};

const coreAdvisory = async (core, request) => {
  const advisory = newAdvisory('core', 'WordPress', core.version);
  if (!VERSION_FORMAT.test(core.version)) return { ...advisory, state: 'no_version' };
  const reply = await request('core_vulnerabilities', { version: core.version });
  return readAdvisoryReply(advisory, reply, readCoreAdvisories);
};

const newAdvisory = (kind, name, version) => ({
  kind, name, version, state: '', closed: null, closureUnknown: false, entries: [], unreadable: 0,
});

const readAdvisoryReply = (advisory, reply, readBody) => {
  if (reply.outcome !== 'answer') return { ...advisory, state: reply.outcome };
  if (reply.status >= SERVER_ERROR_STATUS) return { ...advisory, state: 'unavailable' };
  if (reply.status !== 200) return { ...advisory, state: 'bad_answer' };
  try {
    return { ...advisory, state: 'checked', ...readBody(reply.body) };
  } catch (error) {
    if (!(error instanceof UnusableAnswerError)) throw error;
    return { ...advisory, state: 'bad_answer' };
  }
};

const listed = (readList) => {
  try {
    return { state: 'listed', files: readList() };
  } catch (error) {
    if (!(error instanceof UnusableAnswerError)) throw error;
    return { state: 'bad_answer' };
  }
};

const readCoreList = (checksums) => {
  const files = new Map();
  for (const [path, md5] of listedEntries(checksums)) files.set(path, digestList(md5, MD5_FORMAT));
  return files;
};

const readPluginList = (body) => {
  if (body === null || typeof body !== 'object') throw new UnusableAnswerError('not an object');
  const files = new Map();
  for (const [path, digests] of listedEntries(body.files)) {
    if (digests === null || typeof digests !== 'object') throw new UnusableAnswerError('file without digests');
    const md5 = digestList(digests.md5, MD5_FORMAT);
    const sha256 = digests.sha256 === undefined ? [] : digestList(digests.sha256, SHA256_FORMAT);
    files.set(path, { md5, sha256 });
  }
  return files;
};

const listedEntries = (list) => {
  if (list === null || typeof list !== 'object' || Array.isArray(list)) throw new UnusableAnswerError('not a list');
  const entries = Object.entries(list);
  if (entries.length > MAX_LISTED_FILES) throw new UnusableAnswerError('too many files');
  for (const [path] of entries) {
    if (path.length === 0 || path.length > MAX_LISTED_PATH || path.includes('\u{0}')) throw new UnusableAnswerError('bad path');
  }
  return entries;
};

// wordpress.org writes one digest as a string and several (a file that changed between
// builds of one version) as a list.
const digestList = (listed, format) => {
  const digests = Array.isArray(listed) ? listed : [listed];
  const isValid = digests.length > 0 && digests.length <= MAX_DIGESTS_PER_FILE
    && digests.every((digest) => typeof digest === 'string' && format.test(digest));
  if (!isValid) throw new UnusableAnswerError('bad digest');
  return digests;
};

// outcome: 'answer' (with status and parsed body), 'network' or 'bad_answer'. Only a 200 has
// to be JSON; the body of any other status is null when it is not.
const fetchJson = async (url) => {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const reply = await fetch(url, { credentials: 'omit', redirect: 'error', signal: controller.signal });
    const text = await readCapped(reply);
    const body = reply.status === 200 ? JSON.parse(text) : parseJsonOrNull(text);
    return { outcome: 'answer', status: reply.status, body };
  } catch (error) {
    if (error instanceof UnusableAnswerError || error instanceof SyntaxError) return { outcome: 'bad_answer' };
    // A refused or failed connection is a TypeError, the time limit an AbortError.
    if (error instanceof TypeError || error.name === 'AbortError') return { outcome: 'network' };
    throw error;
  } finally {
    clearTimeout(timer);
  }
};

// An error page or a 404 note need not be JSON; its body is then null.
const parseJsonOrNull = (text) => {
  try {
    return JSON.parse(text);
  } catch (error) {
    if (error instanceof SyntaxError) return null;
    throw error;
  }
};

const readCapped = async (reply) => {
  if (reply.body === null) return '';
  const reader = reply.body.getReader();
  const pieces = [];
  let bytes = 0;
  for (;;) {
    const step = await reader.read();
    if (step.done) break;
    bytes += step.value.length;
    if (bytes > MAX_ANSWER_BYTES) {
      await reader.cancel();
      throw new UnusableAnswerError('answer too large');
    }
    pieces.push(step.value);
  }
  return new TextDecoder().decode(await new Blob(pieces).arrayBuffer());
};

// A few requests at a time, answers kept in the order of the components asked about.
const inLanes = async (components, ask) => {
  const answers = new Array(components.length);
  let next = 0;
  const lane = async () => {
    while (next < components.length) {
      const at = next;
      next += 1;
      answers[at] = await ask(components[at]);
    }
  };
  await Promise.all(Array.from({ length: Math.min(PARALLEL_REQUESTS, components.length) }, lane));
  return answers;
};
