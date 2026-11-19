// SPDX-License-Identifier: GPL-3.0-or-later
//
// The worker is the only place where bytes of the visitor's archive are read. It has no DOM,
// and its own Content-Security-Policy (set on this file's response) leaves it no network: the
// official checksum lists reach it as a message from the page, which fetched them.

import { scanArchive } from './engine.js';

let answerLookup = null;

// The page refuses a message with a text field longer than this and ends the scan
// (protocol.js), while a name in a zip may run to 65,535 bytes. One such file name hid every
// other finding of the scan (measured 2026-11-14). Longer text is cut in the middle, so the
// start of a path and the file name with its extension at the end both survive.
const MAX_SENT_TEXT = 4096;
const CUT_MARK = '...';
const KEPT_EACH_SIDE = Math.floor((MAX_SENT_TEXT - CUT_MARK.length) / 2);

const shorten = (field) => {
  if (typeof field === 'string') {
    return field.length > MAX_SENT_TEXT ? `${field.slice(0, KEPT_EACH_SIDE)}${CUT_MARK}${field.slice(-KEPT_EACH_SIDE)}` : field;
  }
  if (Array.isArray(field)) return field.map(shorten);
  if (field === null || typeof field !== 'object') return field;
  return Object.fromEntries(Object.entries(field).map(([name, nested]) => [name, shorten(nested)]));
};

const emit = (event) => self.postMessage(shorten(event));

const lookup = (question) => new Promise((resolve) => {
  answerLookup = resolve;
  emit({ type: 'lookup', core: question.core, plugins: question.plugins });
});

self.addEventListener('message', (message) => {
  const request = message.data;
  if (request === null || typeof request !== 'object') return;
  if (request.type === 'scan' && request.file instanceof Blob) {
    // scanArchive reports its own failures. One past that (in the last report or the last
    // message) would be a rejection nobody hears; thrown from a task it reaches the page as the
    // worker's error event, which ends the scan at once instead of after the stall watchdog.
    scanArchive(request.file, { emit, lookup, online: request.online === true }).catch((failure) => {
      setTimeout(() => {
        throw failure;
      });
    });
  } else if (request.type === 'lookup_answers' && answerLookup !== null) {
    const resolve = answerLookup;
    answerLookup = null;
    resolve(request.answers);
  }
});
