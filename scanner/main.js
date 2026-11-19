// SPDX-License-Identifier: GPL-3.0-or-later
//
// The page side: starts the worker, checks what it sends, fetches the official checksum lists
// the worker asks for, looks up known vulnerabilities of the components it names, and keeps the
// report. This file never sees a byte of the archive, only the events described in protocol.js.
// What gets drawn is in page-view.js, what gets exported in report-export.js.

import { buildExampleCopy } from './example-copy.js';
import { createGateway } from './gateway.js';
import { LOG_TEXT, STATUS_TEXT, SUMMARY_TEXT, UI_TEXT, describeFinding, placeOf } from './messages.js';
import {
  collapseLog, collectView, createLog, drawAdvisories, drawComponent, drawFinding, drawHashes, drawLoadedCode, expandLog,
  resetView, setCount, showFinished,
} from './page-view.js';
import { ProtocolError, parseWorkerEvent } from './protocol.js';
import { reportAsJson, reportAsText } from './report-export.js';
import { SEVERITIES } from './rules.js';
import { displayText } from './sanitize.js';

const WORKER_URL = new URL('./worker.js', import.meta.url).href;
const TRUSTED_TYPES_POLICY = 'wp-backup-scanner';
const STALL_LIMIT_MS = 10_000;
const WATCHDOG_INTERVAL_MS = 1000;
const REPORT_TEXT_LIMIT = 4096;
const REPORT_SCHEMA = 2;
const REVOKE_DELAY_MS = 60_000;
// A lookup that ended in one of these states is reported as not checked.
const ADVISORY_FAILURES = new Set(['network', 'unavailable', 'request_limit', 'bad_answer']);
// Findings of these rule families come from rules applied to code that no official release
// exists for. They can be wrong about honest code in a way a failed comparison cannot.
const RULE_ONLY_FAMILIES = ['loaded.', 'unproven.'];

// With Trusted Types enforced, a worker can only be started from a URL this policy returns,
// and the policy returns exactly one. It defines no way to produce HTML or script text, so
// every attempt to insert markup anywhere on the page throws.
const workerUrlPolicy = globalThis.trustedTypes?.createPolicy(TRUSTED_TYPES_POLICY, {
  createScriptURL: (url) => {
    if (url !== WORKER_URL) throw new TypeError('not the scanner worker');
    return url;
  },
});

const start = (root) => {
  const view = collectView(root);
  if (!canUnpack()) {
    view.unsupported.hidden = false;
    view.input.disabled = true;
    view.example.disabled = true;
    return;
  }
  let scan = null;
  const begin = (file) => {
    if (scan) scan.stop();
    scan = createScan(file, view);
  };

  view.input.addEventListener('change', () => {
    if (view.input.files.length > 0) begin(view.input.files[0]);
  });
  // Without these two, a file dropped beside the drop zone makes the browser open it.
  for (const type of ['dragover', 'drop']) {
    window.addEventListener(type, (event) => event.preventDefault());
  }
  view.drop.addEventListener('drop', (event) => {
    const file = event.dataTransfer?.files[0];
    if (file) begin(file);
  });
  // For the style sheet: a file is being held over the drop zone.
  view.drop.addEventListener('dragover', () => {
    view.drop.dataset.over = 'true';
  });
  for (const type of ['dragleave', 'drop']) {
    view.drop.addEventListener(type, () => {
      delete view.drop.dataset.over;
    });
  }
  view.example.addEventListener('click', () => begin(buildExampleCopy(UI_TEXT.exampleName)));
  view.logToggle.addEventListener('click', () => {
    if (view.log.dataset.expanded === 'true') collapseLog(view);
    else expandLog(view);
  });
  view.copyText.addEventListener('click', () => {
    if (scan) copyReport(view, scan.report);
  });
  view.downloadJson.addEventListener('click', () => {
    if (scan) downloadReport(view, scan.report);
  });
  root.dataset.state = 'ready';
};

const canUnpack = () => {
  if (typeof DecompressionStream === 'undefined' || typeof Worker === 'undefined') return false;
  try {
    new DecompressionStream('deflate-raw');
    return true;
  } catch (error) {
    // Older browsers know DecompressionStream but not the raw deflate that zip files use.
    if (error instanceof TypeError) return false;
    throw error;
  }
};

const createScan = (file, view) => {
  const worker = new Worker(workerUrlPolicy ? workerUrlPolicy.createScriptURL(WORKER_URL) : WORKER_URL, { type: 'module' });
  const report = {
    schema: REPORT_SCHEMA,
    archive: { name: displayText(file.name, REPORT_TEXT_LIMIT), bytes: file.size, files: 0 },
    wordpress: { root: '', version: '', locale: '', plugins: 0, themes: 0 },
    online: view.online.checked,
    completed: false,
    verdict: '',
    summary: [],
    stats: { bytesRead: 0, milliseconds: 0 },
    counts: Object.fromEntries(SEVERITIES.map((severity) => [severity, 0])),
    components: [],
    loadedCode: { total: 0, files: [] },
    siteHosts: [],
    requests: [],
    findings: [],
    hashes: [],
    advisories: [],
  };
  resetView(view);
  const log = createLog(view.log);
  const gateway = createGateway((request) => {
    report.requests.push(request.url);
    log.line(LOG_TEXT.request(request));
  });
  let lastSignal = performance.now();
  let lastPath = '';
  let finished = false;
  // While the page waits for wordpress.org, the worker's silence is not the worker's fault.
  let awaitingNetwork = false;
  let checksumsDone = Promise.resolve();
  let advisoriesDone = Promise.resolve();
  let advisoriesPending = false;

  view.status.textContent = STATUS_TEXT.scanning;
  log.line(LOG_TEXT.reading(report.archive.name, file.size));

  const addFinding = (event) => {
    const params = new Map([...event.params].map(([name, param]) => (
      [name, typeof param === 'string' ? displayText(param, REPORT_TEXT_LIMIT) : param]
    )));
    const finding = {
      severity: event.severity,
      rule: event.rule,
      path: displayText(event.path, REPORT_TEXT_LIMIT),
      params: Object.fromEntries(params),
      text: describeFinding({ rule: event.rule, params }),
    };
    report.counts[finding.severity] += weightOf(finding);
    report.findings.push(finding);
    setCount(view, finding.severity, report.counts[finding.severity]);
    drawFinding(view, finding);
    log.line(`! ${displayText(placeOf(finding))}: ${finding.text}`, finding.severity);
  };

  // A request of a scan that has already finished can still fail; the view belongs to the
  // next scan by then.
  const failOn = (error) => {
    if (finished) return;
    addFinding({ severity: 'not_checked', rule: 'scan.failed', path: '', params: new Map([['error', String(error.name)]]) });
    finish(false);
  };

  // The worker parses hostile bytes, so it is not trusted to respect the visitor's switch.
  const requireOnline = () => {
    if (!report.online) throw new ProtocolError('network asked for while the comparison is off');
  };

  const recordAdvisories = (records) => {
    advisoriesPending = false;
    if (finished) return;
    report.advisories = records.map(cleanAdvisory);
    log.line(LOG_TEXT.advisories(report.advisories));
    drawAdvisories(view, report.advisories);
    for (const finding of advisoryFindings(report.advisories)) addFinding(finding);
  };

  const finish = (completed) => {
    if (finished) return;
    finished = true;
    clearInterval(watchdog);
    gateway.stop();
    worker.terminate();
    log.endStatus();
    report.completed = completed;
    const outcome = outcomeOf(report);
    report.verdict = STATUS_TEXT[VERDICT_SENTENCES.get(outcome)];
    report.summary = completed ? summaryLines(report) : [];
    view.status.textContent = report.verdict;
    showFinished(view, outcome, report.summary);
    view.root.dispatchEvent(new CustomEvent('scanner:report', { detail: report }));
  };

  const handlers = {
    opened: (event) => {
      report.archive.files = event.files;
      log.line(LOG_TEXT.opened(event));
    },
    facts: (event) => {
      const facts = {
        root: displayText(event.root),
        version: displayText(event.version),
        locale: displayText(event.locale),
        plugins: event.plugins.length,
        themes: event.themes.length,
      };
      report.wordpress = facts;
      log.line(LOG_TEXT.core(facts));
      log.line(LOG_TEXT.plugins(event.plugins.map((name) => displayText(name))));
      log.line(LOG_TEXT.themes(event.themes.map((name) => displayText(name))));
      for (const database of event.databases) {
        log.line(LOG_TEXT.database({ path: displayText(database.path), bytes: database.bytes }));
      }
    },
    lookup: (event) => {
      requireOnline();
      awaitingNetwork = true;
      checksumsDone = gateway.lookup(event).then((answers) => {
        awaitingNetwork = false;
        lastSignal = performance.now();
        if (!finished) worker.postMessage({ type: 'lookup_answers', answers });
      }, failOn);
    },
    // Arrives after `lookup`, so the checksums keep the first claim on the request limit.
    inventory: (event) => {
      requireOnline();
      advisoriesPending = true;
      // A throw inside recordAdvisories ends the scan too; left alone it would keep the report
      // waiting for advisoriesDone after the watchdog has stopped.
      advisoriesDone = checksumsDone.then(() => gateway.advisories(event)).then(recordAdvisories).catch(failOn);
    },
    component: (event) => {
      const component = { ...event, name: displayText(event.name), version: displayText(event.version) };
      report.components.push(component);
      log.line(LOG_TEXT.component(component));
      drawComponent(view, component);
    },
    loaded_code: (event) => {
      const files = event.files.map((file) => ({
        path: displayText(file.path, REPORT_TEXT_LIMIT), bytes: file.bytes, name: displayText(file.name, REPORT_TEXT_LIMIT),
      }));
      report.loadedCode = { total: event.total, files };
      log.line(LOG_TEXT.loadedCode({ total: event.total, files }));
      drawLoadedCode(view, files);
    },
    progress: (event) => {
      lastPath = event.path;
      log.status(LOG_TEXT.progress(event));
    },
    // Arriving is all it does: every message resets the watchdog below.
    alive: () => {},
    site_hosts: (event) => {
      report.siteHosts = event.hosts.map((host) => displayText(host, REPORT_TEXT_LIMIT));
      if (report.siteHosts.length > 0) log.line(LOG_TEXT.siteHosts(report.siteHosts));
    },
    finding: addFinding,
    hashes: (event) => {
      report.hashes = event.files.map((hashed) => ({
        path: displayText(hashed.path, REPORT_TEXT_LIMIT),
        sha256: hashed.sha256,
        // The paths as addFinding stores them, so the rows and the report find their hash.
        findings: hashed.findings.map((path) => displayText(path, REPORT_TEXT_LIMIT)),
      }));
      drawHashes(view, report.hashes);
    },
    // The worker is done; the report waits for the vulnerability lookup, which runs on the page.
    // A slow network can keep it waiting for a while, and the page says what it is waiting for.
    done: (event) => {
      report.stats = { bytesRead: event.bytesRead, milliseconds: event.milliseconds };
      clearInterval(watchdog);
      if (advisoriesPending) {
        view.status.textContent = STATUS_TEXT.lookingUp;
        log.status(LOG_TEXT.waitingForAdvisories);
      }
      advisoriesDone.then(() => {
        if (finished) return;
        log.line(LOG_TEXT.done(report.stats, report.requests));
        finish(event.completed);
      });
    },
  };

  worker.addEventListener('message', (message) => {
    if (finished) return;
    lastSignal = performance.now();
    try {
      const event = parseWorkerEvent(message.data);
      handlers[event.type](event);
    } catch (error) {
      if (!(error instanceof ProtocolError)) throw error;
      addFinding({ severity: 'not_checked', rule: 'scan.failed', path: '', params: new Map([['error', error.name]]) });
      finish(false);
    }
  });
  worker.addEventListener('error', (event) => {
    event.preventDefault();
    // The sentence quotes this slot as a type name, the way the two catches above fill it, so
    // it reads the same on a page in any language.
    addFinding({ severity: 'not_checked', rule: 'scan.failed', path: '', params: new Map([['error', 'ErrorEvent']]) });
    finish(false);
  });

  // A worker stuck in a tight loop cannot report anything, so the page watches for silence.
  const watchdog = setInterval(() => {
    if (awaitingNetwork || performance.now() - lastSignal < STALL_LIMIT_MS) return;
    addFinding({ severity: 'not_checked', rule: 'scan.stalled', path: lastPath, params: new Map() });
    finish(false);
  }, WATCHDOG_INTERVAL_MS);

  worker.postMessage({ type: 'scan', file, online: report.online });
  return {
    report,
    stop: () => {
      finish(false);
      log.close();
    },
  };
};

// One line can stand for many findings: the overflow of a rule, or a group of archives. The
// worker is not trusted to send those counts as numbers (protocol.js lets a parameter be text).
const weightOf = (finding) => {
  const weight = finding.params.more ?? finding.params.files;
  return typeof weight === 'number' ? weight : 1;
};

// One file can hold several findings; a line that stands for more findings of its rule stands
// for as many other files, since a code rule names a file once.
const filesHolding = (findings) => {
  const named = new Set(findings.filter((finding) => weightOf(finding) === 1).map((finding) => finding.path)).size;
  return findings.filter((finding) => weightOf(finding) > 1).reduce((total, finding) => total + weightOf(finding), named);
};

// How a scan ended, as the page's style sheet reads it (data-verdict), and the sentence for each.
const VERDICT_SENTENCES = new Map([
  ['incomplete', 'incomplete'], ['red', 'withRed'], ['no-red', 'withoutRed'], ['nothing', 'nothingFound'],
]);

const outcomeOf = (report) => {
  if (!report.completed) return 'incomplete';
  if (report.counts.red > 0) return 'red';
  return report.findings.length > 0 ? 'no-red' : 'nothing';
};

// The sentences under the verdict: what the result rests on, in the order a reader needs it.
// What was sent and what was not is the last line of the log, which stays in view below them.
const summaryLines = (report) => {
  const lines = [SUMMARY_TEXT.compared(comparisonOf(report))];
  const ruleOnly = report.findings
    .filter((finding) => finding.severity === 'red' && RULE_ONLY_FAMILIES.some((family) => finding.rule.startsWith(family)));
  const ruleOnlyRed = ruleOnly.reduce((total, finding) => total + weightOf(finding), 0);
  if (ruleOnlyRed > 0) lines.push(SUMMARY_TEXT.ruleOnlyRed(ruleOnlyRed, report.counts.red, filesHolding(ruleOnly)));
  if (report.loadedCode.total > 0) lines.push(SUMMARY_TEXT.loadedCode(report.loadedCode.total));
  if (report.counts.red === 0) lines.push(SUMMARY_TEXT.container);
  return lines;
};

const comparisonOf = (report) => {
  const compared = report.components.filter((component) => component.state === 'listed');
  return {
    online: report.online,
    core: compared.some((component) => component.kind === 'core'),
    version: report.wordpress.version,
    pluginsCompared: compared.filter((component) => component.kind === 'plugin').length,
    pluginsTotal: report.wordpress.plugins,
    matchedFiles: compared.reduce((total, component) => total + component.matched, 0),
  };
};

// Identifiers, bounds, dates and links were checked against fixed formats in the gateway; the
// names come from the archive and the weakness name is free text, so those pass the sanitizer.
const cleanAdvisory = (record) => ({
  ...record,
  name: displayText(record.name, REPORT_TEXT_LIMIT),
  version: displayText(record.version, REPORT_TEXT_LIMIT),
  entries: record.entries.map((entry) => ({
    ...entry,
    weakness: entry.weakness && { id: entry.weakness.id, name: displayText(entry.weakness.name) },
  })),
});

// One finding per reason, not one per plugin: a dead network would otherwise fill the list.
const advisoryFindings = (records) => {
  const groups = new Map();
  const count = (reason, record, entries) => {
    const group = groups.get(reason) ?? { components: 0, entries: 0, ...exampleOf(record) };
    group.components += 1;
    group.entries += entries;
    groups.set(reason, group);
  };
  for (const record of records) {
    if (ADVISORY_FAILURES.has(record.state)) count(record.state, record, 0);
    if (record.unreadable > 0) count('unreadable_entries', record, record.unreadable);
    if (record.closureUnknown) count('closure_unknown', record, 0);
  }
  return Array.from(groups, ([reason, group]) => ({
    severity: 'not_checked',
    rule: 'advisory.not_checked',
    path: '',
    params: new Map([
      ['reason', reason], ['components', group.components], ['entries', group.entries],
      ['example', group.example], ['exampleKind', group.exampleKind],
    ]),
  }));
};

// The kind travels apart from the name: the word for it belongs to the page's language.
const exampleOf = (record) => ({
  exampleKind: record.kind,
  example: record.kind === 'core' ? record.version : record.name,
});

const exportOptions = (view) => ({
  maskAddresses: view.mask.checked,
  pageUrl: `${location.origin}${location.pathname}`,
  time: new Date().toISOString(),
});

// When the browser refuses the clipboard (no permission, or a page not served over https),
// the report is put into a text box to be copied by hand.
const copyReport = async (view, report) => {
  const text = reportAsText(report, exportOptions(view));
  try {
    await navigator.clipboard.writeText(text);
    view.exportStatus.textContent = UI_TEXT.copied;
  } catch (error) {
    if (!(error instanceof DOMException) && !(error instanceof TypeError)) throw error;
    view.reportText.value = text;
    view.reportText.hidden = false;
    view.reportText.select();
    view.exportStatus.textContent = UI_TEXT.copyRefused;
  }
};

const downloadReport = (view, report) => {
  const address = URL.createObjectURL(new Blob([reportAsJson(report, exportOptions(view))], { type: 'application/json' }));
  const link = document.createElement('a');
  link.href = address;
  link.download = `${UI_TEXT.reportFileName}.json`;
  link.click();
  // The download reads the address after this function returns.
  setTimeout(() => URL.revokeObjectURL(address), REVOKE_DELAY_MS);
};

const root = document.querySelector('[data-scanner="root"]');
if (root) start(root);
