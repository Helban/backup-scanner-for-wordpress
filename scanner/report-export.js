// SPDX-License-Identifier: GPL-3.0-or-later
//
// The report as text and as JSON: the one thing the page lets a visitor take away. It is
// written from what the page already shows, so it holds no byte of the archive, only names,
// lines the findings quote, and hashes. E-mail addresses are masked unless the visitor
// switches that off: a report gets pasted into tickets and chats, and an address in a file
// name or in a quoted line belongs to somebody.

import { ADVISORY_TEXT, EXPORT_TEXT, LIST_TEXT, placeOf } from './messages.js';
import { SEVERITIES } from './rules.js';

const MASK = '***';
const LOCAL_PART_CHARACTER = /[A-Za-z0-9._%+-]/;
const DOMAIN_CHARACTER = /[A-Za-z0-9.-]/;
const JSON_INDENT = 2;

// "john.smith@example.com" becomes "j***@example.com". Walks out from each "@", so a text built
// to make a search run long costs one pass.
export const maskEmails = (text) => {
  const pieces = [];
  let copiedUntil = 0;
  for (let at = text.indexOf('@'); at >= 0; at = text.indexOf('@', at + 1)) {
    let start = at;
    while (start > copiedUntil && LOCAL_PART_CHARACTER.test(text[start - 1])) start -= 1;
    let end = at + 1;
    while (end < text.length && DOMAIN_CHARACTER.test(text[end])) end += 1;
    const isAddress = start < at && text.slice(at + 1, end).includes('.');
    if (!isAddress) continue;
    pieces.push(text.slice(copiedUntil, start + 1), MASK, text.slice(at, end));
    copiedUntil = end;
  }
  pieces.push(text.slice(copiedUntil));
  return pieces.join('');
};

// `options`: { maskAddresses, pageUrl, time }
export const reportAsJson = (report, options) => {
  const exported = { ...report, generator: options.pageUrl, generated: options.time, emailsMasked: options.maskAddresses };
  return JSON.stringify(options.maskAddresses ? withMaskedText(exported) : exported, null, JSON_INDENT);
};

// Finding path -> the hash of the file it is about. The worker ties each red path to one file
// (hashRedFiles), so neither the page nor the report guesses the file back from the path.
export const hashesByFinding = (hashes) => new Map(hashes.flatMap((file) => file.findings.map((path) => [path, file.sha256])));

export const reportAsText = (report, options) => {
  const hashes = hashesByFinding(report.hashes);
  const lines = [
    EXPORT_TEXT.title(options.pageUrl),
    EXPORT_TEXT.generated(options.time),
    EXPORT_TEXT.archive(report.archive),
    EXPORT_TEXT.wordpress(report.wordpress),
    '',
    EXPORT_TEXT.verdict(report.verdict),
    EXPORT_TEXT.counts(report.counts),
    ...report.summary,
  ];
  if (report.completed) lines.push(EXPORT_TEXT.finished(report.stats, report.requests));
  for (const severity of SEVERITIES) {
    const findings = report.findings.filter((finding) => finding.severity === severity);
    if (findings.length === 0) continue;
    lines.push('', EXPORT_TEXT.severityTitles.get(severity));
    for (const finding of findings) lines.push(...findingLines(finding, hashes));
  }
  lines.push(...section(EXPORT_TEXT.advisories, report.advisories.flatMap(advisoryLines)));
  lines.push(...section(EXPORT_TEXT.components, report.components.map((component) => `- ${LIST_TEXT.component(component)}`)));
  lines.push(...section(EXPORT_TEXT.loadedCode(report.loadedCode.total), report.loadedCode.files.map((file) => `- ${LIST_TEXT.loadedFile(file)}`)));
  lines.push('', EXPORT_TEXT.requests, ...(report.requests.length > 0 ? report.requests.map((url) => `- ${url}`) : [EXPORT_TEXT.noRequests]));
  if (options.maskAddresses) lines.push('', EXPORT_TEXT.masked);
  const text = `${lines.join('\n')}\n`;
  return options.maskAddresses ? maskEmails(text) : text;
};

const section = (title, rows) => (rows.length > 0 ? ['', title, ...rows] : []);

const findingLines = (finding, hashes) => {
  const lines = [`- ${placeOf(finding)}`, `  ${finding.text}`];
  const excerpt = finding.params.excerpt ?? '';
  if (excerpt !== '') lines.push(`  ${EXPORT_TEXT.excerpt(excerpt)}`);
  const sha256 = finding.severity === 'red' ? hashes.get(finding.path) : undefined;
  if (sha256 !== undefined) lines.push(`  ${LIST_TEXT.hash(sha256)}`);
  return lines;
};

const advisoryLines = (record) => {
  if (record.entries.length === 0 && record.closed === null) return [];
  const lines = [`- ${ADVISORY_TEXT.heading(record)}`];
  if (record.closed) lines.push(`  ${ADVISORY_TEXT.closed(record.closed)}`);
  for (const entry of record.entries) lines.push(`  ${[ADVISORY_TEXT.entry(entry), ...entry.links].join(' ')}`);
  return lines;
};

// The same structure with every text in it masked.
const withMaskedText = (exported) => {
  if (typeof exported === 'string') return maskEmails(exported);
  if (Array.isArray(exported)) return exported.map(withMaskedText);
  if (exported === null || typeof exported !== 'object') return exported;
  return Object.fromEntries(Object.entries(exported).map(([key, held]) => [key, withMaskedText(held)]));
};
