// SPDX-License-Identifier: GPL-3.0-or-later
//
// Questions about PHP source that need no parser. Worker side only.

const OPEN_TAG = '<?';
const CLOSE_TAG = '?>';
// PHP's own open tag: "<?php" and a space, a tab or a line break, or the end of the text.
const LONG_OPEN_TAG = /^<\?php(?:[ \t\r\n]|$)/i;
// Whether PHP takes a bare "<?" as an open tag depends on short_open_tag, a setting of the
// computer the copy lands on (php-lexer.js). Every answer here has to hold under both.
const READINGS = [{ shortTags: true }, { shortTags: false }];

// True when the text cannot do anything when PHP runs it: no PHP tag at all, or PHP blocks that
// hold only comments and white space. Plugins drop such files (an index.php saying "Silence is
// golden") into uploads so the folder cannot be listed. Any statement makes it false, and so
// does "<?=" (it prints an expression) or a short "<?" tag, whose content is read as code.
export const isInertPhp = (text) => READINGS.every((reading) => isInertWhenRead(text, reading));

// True when the first statement of the file's first PHP block is exit or die: whatever follows
// never runs, it is data the file keeps for whoever reads it. Wordfence keeps its firewall
// data this way (`<?php exit('Access denied'); __halt_compiler(); ?>`), W3 Total Cache its
// settings (`<?php exit; ?>` and JSON). A file with no PHP block under one setting runs nothing
// under it.
export const exitsAtOnce = (text) => READINGS.every((reading) => {
  const codeStart = nextCodeStart(text, 0, reading);
  if (codeStart === null) return true;
  const statement = endOfCommentsAndSpace(text, codeStart);
  return EXIT_STATEMENT.test(text.slice(statement, statement + 8));
});

const isInertWhenRead = (text, reading) => {
  for (let codeStart = nextCodeStart(text, 0, reading); codeStart !== null;) {
    // "<?=" prints the expression after it.
    if (text[codeStart - 1] === '=') return false;
    const codeEnd = endOfCommentsAndSpace(text, codeStart);
    if (codeEnd < text.length && !text.startsWith(CLOSE_TAG, codeEnd)) return false;
    codeStart = codeEnd < text.length ? nextCodeStart(text, codeEnd + CLOSE_TAG.length, reading) : null;
  }
  return true;
};

// Where the code after the next open tag from `start` begins, or null when no tag follows.
const nextCodeStart = (text, start, { shortTags }) => {
  for (let at = text.indexOf(OPEN_TAG, start); at >= 0; at = text.indexOf(OPEN_TAG, at + OPEN_TAG.length)) {
    if (text[at + 2] === '=') return at + 3;
    if (LONG_OPEN_TAG.test(text.slice(at, at + 6))) return at + 5;
    if (shortTags) return at + 2;
  }
  return null;
};

const EXIT_STATEMENT = /^(?:exit|die)(?![a-z0-9_])/i;

// Skips white space and comments from `at` and returns where something else begins: the
// closing tag, a statement, or the end of the text.
const endOfCommentsAndSpace = (text, start) => {
  let at = start;
  while (at < text.length) {
    if (/\s/.test(text[at])) {
      at += 1;
    } else if (text.startsWith('/*', at)) {
      const close = text.indexOf('*/', at + 2);
      at = close < 0 ? text.length : close + 2;
    } else if (text.startsWith('//', at) || (text[at] === '#' && text[at + 1] !== '[')) {
      // "#[" opens an attribute in PHP 8, not a comment; whatever follows it on the line runs.
      at = endOfLineComment(text, at);
    } else {
      return at;
    }
  }
  return at;
};

// A one-line comment ends at the line break or at a closing tag, whichever comes first. PHP
// takes a lone "\r" for a line break too, so `// note\rcode();` runs the code. One walk to that
// end: a search per kind of end ran to the end of the file for each comment when that kind was
// missing, and a file of one comment after another took the square of its length.
const endOfLineComment = (text, start) => {
  let at = start;
  while (at < text.length && text[at] !== '\n' && text[at] !== '\r' && !text.startsWith(CLOSE_TAG, at)) at += 1;
  return at;
};
