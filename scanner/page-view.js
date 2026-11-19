// SPDX-License-Identifier: GPL-3.0-or-later
//
// Everything the scanner draws. main.js decides what there is to show; this file puts it into
// the elements the page marks with data-scanner="...". Text that comes from the archive or
// from a remote answer has passed the display sanitizer before it gets here, and whatever
// arrives is set as text, never as markup.

import { ADVISORY_TEXT, LIST_TEXT, SEVERITY_LABELS, UI_TEXT, formatCount, placeOf } from './messages.js';
import { hashesByFinding } from './report-export.js';
import { SEVERITIES } from './rules.js';
import { displayText } from './sanitize.js';

const LOG_LINES_KEPT = 400;
const FOLLOW_SLACK_PX = 24;
const FINDINGS_DRAWN = 600;
const ADVISORY_ENTRIES_DRAWN = 50;
// A line that arrives alone is written out over this many frames; lines that arrive together
// go in whole. The scan never waits for either.
const TYPING_FRAMES = 12;
const LESS_MOTION = '(prefers-reduced-motion: reduce)';

// The lists of the result. Each sits in a section that is shown only while the list has rows.
const RESULT_LISTS = ['findings', 'loaded-code', 'components', 'advisories'];
const PARTS = [
  'input', 'online', 'drop', 'example', 'unsupported', 'result', 'status', 'summary', 'log', 'log-toggle',
  'export', 'copy-text', 'download-json', 'mask', 'export-status', 'report-text', ...RESULT_LISTS,
];

export const collectView = (root) => {
  const part = (name) => {
    const marked = root.querySelector(`[data-scanner="${name}"]`);
    if (!marked) throw new Error(`the page lacks data-scanner="${name}"`);
    return marked;
  };
  return {
    root,
    ...Object.fromEntries(PARTS.map((name) => [camelCase(name), part(name)])),
    counts: new Map(SEVERITIES.map((severity) => [severity, part(`count-${severity}`)])),
    findingRows: new Map(),
    rowsByKey: new Map(),
    undrawnFindings: 0,
  };
};

const camelCase = (name) => name.replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());

// A new scan starts from an empty result. The phase is what the page's style sheet reads.
export const resetView = (view) => {
  view.root.dataset.phase = 'scanning';
  delete view.root.dataset.verdict;
  view.result.hidden = false;
  view.export.hidden = true;
  view.reportText.hidden = true;
  view.exportStatus.textContent = '';
  view.summary.replaceChildren();
  view.log.replaceChildren();
  view.findingRows.clear();
  view.rowsByKey.clear();
  view.undrawnFindings = 0;
  for (const name of RESULT_LISTS) {
    const list = view[camelCase(name)];
    list.replaceChildren();
    showSection(list);
  }
  for (const counter of view.counts.values()) counter.textContent = '0';
  expandLog(view);
  // The result sits under the drop zone, below the fold on a phone and on most laptops: without
  // this a click on the example changed nothing the visitor could see.
  view.result.scrollIntoView({ block: 'start', behavior: matchMedia(LESS_MOTION).matches ? 'auto' : 'smooth' });
};

export const showFinished = (view, outcome, summaryLines) => {
  view.root.dataset.phase = 'done';
  view.root.dataset.verdict = outcome;
  view.summary.replaceChildren(...summaryLines.map((line) => textElement('li', 'summary-line', line)));
  view.export.hidden = false;
  collapseLog(view);
};

export const setCount = (view, severity, count) => {
  view.counts.get(severity).textContent = formatCount(count);
};

export const expandLog = (view) => showLog(view, 'true', UI_TEXT.logHide);

// Collapsed, the log shows its end: the line that says what was sent and what was not.
export const collapseLog = (view) => showLog(view, 'false', UI_TEXT.logShow);

const showLog = (view, expanded, toggleLabel) => {
  view.log.dataset.expanded = expanded;
  view.logToggle.setAttribute('aria-expanded', expanded);
  view.logToggle.textContent = toggleLabel;
  view.log.scrollTop = view.log.scrollHeight;
};

const showSection = (list) => {
  const section = list.closest('[data-scanner-section]');
  if (section) section.hidden = list.children.length === 0;
};

// One row per file: the weight of its heaviest finding, the path, every reason under it, and
// later the hash, once. Past FINDINGS_DRAWN rows a new file still goes in when it is heavier
// than the lightest row, which then leaves with its reasons; a red finding that comes last is
// never the one left out. The report keeps every finding, and a line under the list says how
// many are only there.
export const drawFinding = (view, finding) => {
  const key = rowKeyOf(finding);
  const listed = view.rowsByKey.get(key);
  if (listed !== undefined) {
    addReason(listed, finding);
    if (rankOf(finding.severity) < rankOf(listed.dataset.severity)) placeRow(view, listed, finding.severity);
    return;
  }
  const drawn = findingRowsOf(view);
  if (drawn.length >= FINDINGS_DRAWN) {
    const lightest = drawn[drawn.length - 1];
    if (rankOf(lightest.dataset.severity) <= rankOf(finding.severity)) {
      countUndrawn(view, 1);
      return;
    }
    countUndrawn(view, lightest.querySelectorAll('.finding-reason').length);
    lightest.remove();
    view.rowsByKey.delete(view.findingRows.get(lightest));
    view.findingRows.delete(lightest);
  }
  const row = document.createElement('li');
  row.className = 'finding';
  const reasons = document.createElement('ul');
  reasons.className = 'finding-reasons';
  row.append(
    textElement('span', 'finding-weight', ''),
    finding.path === ''
      ? textElement('span', 'finding-path finding-no-path', placeOf(finding))
      : textElement('span', 'finding-path', displayText(finding.path)),
    reasons,
  );
  view.findingRows.set(row, key);
  view.rowsByKey.set(key, row);
  addReason(row, finding);
  placeRow(view, row, finding.severity);
  showSection(view.findings);
};

const UNDRAWN_CLASS = 'findings-undrawn';

// A file's row is keyed by its path. The two kinds of finding without one get a row each,
// under a key no path can take: a NUL never survives into a file name the page shows.
const rowKeyOf = (finding) => (finding.path === '' ? `\u{0}${placeOf(finding)}` : finding.path);

const rankOf = (severity) => SEVERITIES.indexOf(severity);

const findingRowsOf = (view) => Array.from(view.findings.querySelectorAll(':scope > .finding'));

// Heaviest first: a row goes in front of the first row of a lighter weight.
const placeRow = (view, row, severity) => {
  row.dataset.severity = severity;
  row.querySelector('.finding-weight').textContent = SEVERITY_LABELS.get(severity);
  const lighter = findingRowsOf(view).find((drawnRow) => drawnRow !== row && rankOf(drawnRow.dataset.severity) > rankOf(severity));
  view.findings.insertBefore(row, lighter ?? view.findings.querySelector(`:scope > .${UNDRAWN_CLASS}`));
};

const addReason = (row, finding) => {
  const reason = document.createElement('li');
  reason.className = 'finding-reason';
  reason.dataset.severity = finding.severity;
  reason.append(
    textElement('span', 'reason-weight', SEVERITY_LABELS.get(finding.severity)),
    textElement('span', 'finding-text', finding.text),
  );
  const excerpt = finding.params.excerpt ?? '';
  if (excerpt !== '') reason.append(textElement('code', 'finding-excerpt', excerpt));
  const reasons = row.querySelector('.finding-reasons');
  const lighter = Array.from(reasons.children).find((listed) => rankOf(listed.dataset.severity) > rankOf(finding.severity));
  reasons.insertBefore(reason, lighter ?? null);
  // A weight per reason says something only when the reasons of one file differ in weight.
  row.dataset.mixed = String(new Set(Array.from(reasons.children, (listed) => listed.dataset.severity)).size > 1);
};

const countUndrawn = (view, findings) => {
  view.undrawnFindings += findings;
  let line = view.findings.querySelector(`:scope > .${UNDRAWN_CLASS}`);
  if (line === null) {
    line = textElement('li', UNDRAWN_CLASS, '');
    view.findings.append(line);
  }
  line.textContent = LIST_TEXT.undrawnFindings(FINDINGS_DRAWN, view.undrawnFindings);
};

// The hashes arrive when the worker is done, each with the paths of its findings. A red finding
// inside an archive found in the copy shows the hash of that archive, the file the visitor can find.
export const drawHashes = (view, hashes) => {
  const byFinding = hashesByFinding(hashes);
  for (const [row, rowKey] of view.findingRows) {
    if (row.dataset.severity !== 'red') continue;
    const sha256 = byFinding.get(rowKey);
    if (sha256 !== undefined) row.append(textElement('span', 'finding-hash', LIST_TEXT.hash(sha256)));
  }
};

export const drawLoadedCode = (view, files) => {
  view.loadedCode.replaceChildren(...files.map((file) => textElement('li', 'loaded-file', LIST_TEXT.loadedFile(file))));
  showSection(view.loadedCode);
};

export const drawComponent = (view, component) => {
  const row = textElement('li', 'component', LIST_TEXT.component(component));
  row.dataset.state = component.state === 'listed' ? 'compared' : 'not-compared';
  view.components.append(row);
  showSection(view.components);
};

export const drawAdvisories = (view, records) => {
  for (const record of records) {
    if (record.entries.length === 0 && record.closed === null) continue;
    const row = document.createElement('li');
    row.className = 'advisory';
    row.append(textElement('p', 'advisory-heading', ADVISORY_TEXT.heading(record)));
    if (record.closed) row.append(textElement('p', 'advisory-closed', ADVISORY_TEXT.closed(record.closed)));
    if (record.entries.length > 0) {
      const entries = document.createElement('ul');
      entries.append(...record.entries.slice(0, ADVISORY_ENTRIES_DRAWN).map(drawAdvisoryEntry));
      const unlisted = record.entries.length - ADVISORY_ENTRIES_DRAWN;
      if (unlisted > 0) entries.append(textElement('li', 'advisory-more', ADVISORY_TEXT.more(unlisted)));
      row.append(entries);
    }
    view.advisories.append(row);
  }
  showSection(view.advisories);
};

const drawAdvisoryEntry = (entry) => {
  const row = textElement('li', 'advisory-entry', '');
  row.append(textElement('span', 'advisory-facts', ADVISORY_TEXT.entry(entry)));
  for (const url of entry.links) {
    const link = document.createElement('a');
    link.href = url;
    // In the same tab the report would be gone; it exists nowhere but on this page.
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    link.textContent = ADVISORY_TEXT.sourceLabel(url);
    row.append(' ', link);
  }
  return row;
};

const textElement = (tag, className, text) => {
  const created = document.createElement(tag);
  created.className = className;
  created.textContent = text;
  return created;
};

// Lines are added once per frame, however fast they arrive, and old ones are dropped: the
// log shows what is happening now, the findings list keeps the result. A visitor who asked the
// system for less motion gets every line whole.
export const createLog = (list) => {
  const animate = !matchMedia(LESS_MOTION).matches;
  const waiting = [];
  let statusRow = null;
  let typing = null;
  let scheduled = false;
  let closed = false;

  const isAtEnd = () => list.scrollHeight - list.scrollTop - list.clientHeight < FOLLOW_SLACK_PX;

  const finishTyping = () => {
    if (typing === null) return;
    typing.row.textContent = typing.text;
    typing = null;
  };

  const typeNextPiece = () => {
    if (typing === null || closed) return;
    const wasAtEnd = isAtEnd();
    typing.shown = Math.min(typing.text.length, typing.shown + Math.ceil(typing.text.length / TYPING_FRAMES));
    typing.row.textContent = typing.text.slice(0, typing.shown);
    if (wasAtEnd) list.scrollTop = list.scrollHeight;
    if (typing.shown >= typing.text.length) typing = null;
    else requestAnimationFrame(typeNextPiece);
  };

  const flush = () => {
    scheduled = false;
    if (closed) return;
    finishTyping();
    const lines = waiting.splice(0);
    // Follow the newest line, unless the visitor has scrolled up to read something.
    const wasAtEnd = isAtEnd();
    const fragment = document.createDocumentFragment();
    for (const { text, severity } of lines) {
      const row = document.createElement('li');
      row.textContent = text;
      if (severity) row.dataset.severity = severity;
      fragment.append(row);
    }
    if (animate && lines.length === 1) {
      const row = fragment.firstElementChild;
      typing = { row, text: lines[0].text, shown: 0 };
      row.textContent = '';
      requestAnimationFrame(typeNextPiece);
    }
    list.insertBefore(fragment, statusRow);
    while (list.children.length > LOG_LINES_KEPT) list.firstElementChild.remove();
    if (wasAtEnd) list.scrollTop = list.scrollHeight;
  };

  const schedule = () => {
    if (scheduled) return;
    scheduled = true;
    requestAnimationFrame(flush);
  };

  return {
    line(text, severity = '') {
      waiting.push({ text, severity });
      schedule();
    },
    // One row at the end that is rewritten in place: the counter of the stage under way.
    status(text) {
      if (closed) return;
      if (!statusRow) {
        statusRow = document.createElement('li');
        statusRow.className = 'log-status';
        list.append(statusRow);
      }
      statusRow.textContent = text;
    },
    endStatus() {
      if (statusRow) statusRow.remove();
      statusRow = null;
    },
    // A newer scan owns the list now. Without this, lines the old one still had waiting for the
    // next frame went into the new log, or threw when their status row had been removed.
    close() {
      closed = true;
    },
  };
};
