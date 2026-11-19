// SPDX-License-Identifier: GPL-3.0-or-later
//
// Every sentence the scanner generates at run time, in the language of the page. The worker
// sends rule names and numbers; the words are chosen here, on the page, so no text from the
// worker is ever shown as prose. The address decides the language: a page marked lang="pl"
// speaks Polish, any other page English. Both sets are written on their own, neither is a
// translation of the other, and tests/test_messages.py checks that they cover the same rules.

import * as english from './messages-en.js';
import * as polish from './messages-pl.js';

const texts = document.documentElement.lang === 'pl' ? polish : english;

export const {
  ADVISORY_TEXT, EXPORT_TEXT, LIST_TEXT, LOG_TEXT, SEVERITY_LABELS, STATUS_TEXT, SUMMARY_TEXT, UI_TEXT,
  describeFinding, formatCount,
} = texts;

// What the list, the report and the log show where a finding's file would be. A finding with
// no file is about the copy as a whole, unless it is the line that counts a rule's findings
// past the cap and names the first place they were found: those are about other files or
// folders, just not named. A count without a place belongs to a rule about the whole copy.
export const placeOf = (finding) => {
  if (finding.path !== '') return finding.path;
  const countsOtherPlaces = finding.params.more !== undefined && (finding.params.example ?? '') !== '';
  return countsOtherPlaces ? LIST_TEXT.moreFindings : LIST_TEXT.wholeCopy;
};
