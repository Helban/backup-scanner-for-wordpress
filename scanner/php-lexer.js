// SPDX-License-Identifier: GPL-3.0-or-later
//
// Splits PHP source into the tokens the code rules look at: names, variables, strings with
// their decoded text, numbers, commands in backticks and punctuation. Comments and the HTML
// around PHP blocks are dropped. Worker side only.
//
// Plain loops over the characters, no regular expression ever runs over the file: the text
// comes from an attacker, and a loop costs time in proportion to the length of the file and
// nothing else. The caller's clock is still consulted, so a file can never hold the scan.
//
// Token kinds:
//   name     - an identifier as written, namespace separators included (`\exec`, `Foo\bar`)
//   variable - `$name`, text without the dollar
//   string   - text = decoded value; `interpolated` when a double-quoted string or heredoc
//              holds a variable (its place is marked with VARIABLE_MARK), `escaped` when the
//              value was spelled with \x, \u or octal escapes
//   command  - a string in backticks, which PHP hands to the shell
//   number   - integer = the integer it stands for, NaN for anything else
//   symbol   - punctuation, the multi-character ones that matter kept whole (-> ?-> :: => .= ...)
// `at` is the offset of the token in the source, for line numbers.

export class CodeTimeLimitError extends Error {
  constructor() {
    super('time limit for reading one PHP file');
    this.name = 'CodeTimeLimitError';
  }
}

// A file that splits into more tokens than this is not read as code: every token is an object
// in memory, and eight megabytes of single brackets would be eight million of them.
const MAX_TOKENS = 1_000_000;

// A string may hold code ("{$object->run()}"), that code may hold a string, and so on. PHP
// sets no limit to that; honest files stop at one or two levels. A file past this depth is not
// read as code, and says so.
const MAX_EMBEDDED_DEPTH = 32;

// `reason` is 'tokens' or 'nesting', for the sentence the page shows.
export class CodeTooLargeError extends Error {
  constructor(reason) {
    super(`one PHP file with too many ${reason}`);
    this.name = 'CodeTooLargeError';
    this.reason = reason;
  }
}

// Stands for a variable inside a double-quoted string: the value is no longer a constant, but
// what surrounds the variable ("$dir/setup.exe") still says something.
export const VARIABLE_MARK = '\u{0}';

// PHP keeps only the low byte of a character code: chr(321) and "\501" are both "A".
export const BYTE_VALUES = 256;

const CLOCK_EVERY_STEPS = 1024;
export const HALT_COMPILER = '__halt_compiler';

// A clock that throws once `deadline` (a performance.now() value) has passed. Reading the time
// on every step would cost more than the step, so it is read every 1024 steps.
export const createClock = (deadline) => {
  let steps = 0;
  return () => {
    steps += 1;
    if (steps % CLOCK_EVERY_STEPS === 0 && performance.now() > deadline) throw new CodeTimeLimitError();
  };
};

// A closer no character equals: decoding runs to the end of the text.
const TO_THE_END = '';
const SYMBOLS_BY_LENGTH = [['?->', '...'], ['->', '::', '=>', '.=']];
const SIMPLE_ESCAPES = new Map([
  ['n', '\n'], ['t', '\t'], ['r', '\r'], ['v', '\v'], ['e', '\u{1b}'], ['f', '\f'],
  ['\\', '\\'], ['$', '$'], ['"', '"'],
]);

// PHP opens code at "<?php" followed by a space, a tab or a line break (or the end of the text),
// at "<?=", and at a bare "<?" only when short_open_tag is on. That is a setting of the computer
// the copy lands on, which the scanner cannot know: production php.ini files keep it off, the
// official WordPress Docker image has it on. A file can be built to read differently under the
// two (`<? /* ?><?php code(); // */` runs code() only with short tags off), so the rules read such
// a file both ways (readsTheSameWithoutShortTags tells when there is no need).
export const tokenizePhp = (source, tick) => tokenize(source, tick, SHORT_TAGS_ON);

export const tokenizePhpWithoutShortTags = (source, tick) => tokenize(source, tick, SHORT_TAGS_OFF);

// True when every "<?" in the text is an open tag under both settings, so one reading is enough.
// A "<?" that is text in both (inside a string or a comment) costs a second reading for nothing.
// Walked with indexOf, like the rest of this file: no regular expression runs over the text.
export const readsTheSameWithoutShortTags = (source) => {
  for (let at = source.indexOf('<?'); at >= 0; at = source.indexOf('<?', at + 2)) {
    if (!isTagUnderBothSettings(source, at)) return false;
  }
  return true;
};

const SHORT_TAGS_ON = { shortTags: true };
const SHORT_TAGS_OFF = { shortTags: false };

const tokenize = (source, tick, { shortTags }) => {
  const context = { tokens: [], tick, depth: 0 };
  let at = 0;
  while (at < source.length) {
    at = skipInlineHtml(source, at, shortTags);
    at = lexCode(source, at, context);
  }
  return context.tokens;
};

// Returns where the code after the next PHP open tag begins, or the end of the text.
// "<?xml" gets no special treatment: with short tags on, PHP reads what follows as code
// (`<?xml_parser_create(); ...` runs), and the official WordPress Docker image has them on.
const skipInlineHtml = (source, start, shortTags) => {
  for (let at = source.indexOf('<?', start); at >= 0; at = source.indexOf('<?', at + 2)) {
    if (source[at + 2] === '=') return at + 3;
    if (isLongTag(source, at)) return at + 5;
    if (shortTags) return at + 2;
  }
  return source.length;
};

// PHP's scanner takes "<?php" with exactly these after it (Zend/zend_language_scanner.l:
// "<?php"([ \t]|{NEWLINE})); a form feed after it leaves "<?php" text, printed as it stands.
const isLongTag = (source, at) => (
  startsWithIgnoringCase(source, at + 2, 'php') && (at + 5 >= source.length || isOpenTagSpace(source[at + 5]))
);

const isTagUnderBothSettings = (source, at) => source[at + 2] === '=' || isLongTag(source, at);

const isOpenTagSpace = (char) => char === ' ' || char === '\t' || char === '\n' || char === '\r';

// Reads code until the closing tag; returns the offset just past it, or the end of the text.
// At any depth above 0 the code is an expression inside a string ("{$...}", "${...}"):
// lexEmbedded raised the depth, and the expression ends at the brace that closes it.
const lexCode = (source, start, context) => {
  const { tokens, tick } = context;
  const isEmbedded = context.depth > 0;
  let at = start;
  let openBraces = 0;
  while (at < source.length) {
    tick();
    if (tokens.length > MAX_TOKENS) throw new CodeTooLargeError('tokens');
    const char = source[at];
    const next = source[at + 1];
    if (isSpace(char)) {
      at += 1;
    } else if (char === '?' && next === '>') {
      // PHP reads the closing tag as the end of a statement: `require 'x.bin' ?>` is complete.
      if (!isEmbedded) tokens.push({ kind: 'symbol', text: ';', at });
      return at + 2;
    } else if ((char === '#' && next !== '[') || (char === '/' && next === '/')) {
      at = endOfLineComment(source, at);
    } else if (char === '/' && next === '*') {
      const close = source.indexOf('*/', at + 2);
      at = close < 0 ? source.length : close + 2;
    } else if (char === '\'') {
      at = readSingleQuoted(source, at, tokens);
    } else if (char === '"') {
      at = readDoubleQuoted(source, at, context);
    } else if (char === '`') {
      at = readCommand(source, at, tokens);
    } else if (source.startsWith('<<<', at)) {
      at = readHeredoc(source, at, context);
    } else if (char === '$' && isNameStart(next)) {
      const end = endOfName(source, at + 1);
      tokens.push({ kind: 'variable', text: source.slice(at + 1, end), at });
      at = end;
    } else if (isNameStart(char) || (char === '\\' && isNameStart(next))) {
      at = readName(source, at, tokens);
      // PHP stops compiling the file here; what follows is data the code may read itself.
      if (!isEmbedded && isHaltStatement(source, at, tokens)) return source.length;
    } else if (isDigit(char) || (char === '.' && isDigit(next))) {
      at = readNumber(source, at, tokens);
    } else {
      if (isEmbedded && char === '}') {
        if (openBraces === 0) return at + 1;
        openBraces -= 1;
      }
      if (isEmbedded && char === '{') openBraces += 1;
      at = readSymbol(source, at, tokens);
    }
  }
  return at;
};

const MEMBER_ACCESS = new Set(['->', '?->', '::']);

// PHP stops only at the statement `__halt_compiler();`. Behind "->" or "::" the word is a
// member's name like any other, and the code after it runs.
const isHaltStatement = (source, afterName, tokens) => {
  if (tokens[tokens.length - 1].text.toLowerCase() !== HALT_COMPILER) return false;
  const before = tokens[tokens.length - 2];
  if (before !== undefined && before.kind === 'symbol' && MEMBER_ACCESS.has(before.text)) return false;
  const open = skipSpaces(source, afterName);
  return source[open] === '(' && source[skipSpaces(source, open + 1)] === ')';
};

const skipSpaces = (source, start) => {
  let at = start;
  while (at < source.length && isSpace(source[at])) at += 1;
  return at;
};

// A one-line comment ends at the line break (PHP takes a lone "\r" for one too) or at a
// closing tag, whichever comes first.
// Walked character by character: searching the whole rest of the file for "?>" after every
// comment would cost the square of the file's length when the file has no closing tag.
const endOfLineComment = (source, start) => {
  let at = start;
  while (at < source.length && !isLineBreak(source[at]) && !(source[at] === '?' && source[at + 1] === '>')) at += 1;
  return at;
};

// Pieces between escapes are copied whole: a string of megabytes must not be built one
// character at a time.
const readSingleQuoted = (source, start, tokens) => {
  const pieces = [];
  let pieceStart = start + 1;
  let at = pieceStart;
  while (at < source.length && source[at] !== '\'') {
    if (source[at] === '\\' && (source[at + 1] === '\\' || source[at + 1] === '\'')) {
      pieces.push(source.slice(pieceStart, at), source[at + 1]);
      at += 2;
      pieceStart = at;
    } else {
      at += 1;
    }
  }
  pieces.push(source.slice(pieceStart, at));
  tokens.push({ kind: 'string', text: pieces.join(''), interpolated: false, escaped: false, at: start });
  return at + 1;
};

const readDoubleQuoted = (source, start, context) => {
  const decoded = decodeInterpolating(source, { start: start + 1, closer: '"' }, context);
  context.tokens.push({ kind: 'string', ...decoded.token, at: start });
  return decoded.end + 1;
};

const readCommand = (source, start, tokens) => {
  let at = start + 1;
  while (at < source.length && source[at] !== '`') at += source[at] === '\\' ? 2 : 1;
  tokens.push({ kind: 'command', text: source.slice(start + 1, at), at: start });
  return at + 1;
};

// <<<NAME, <<<"NAME" (both read like a double-quoted string) and <<<'NAME' (read like a
// single-quoted one). Since PHP 7.3 the closing name may be indented and followed by more code.
// Lines end with "\n", "\r\n" or a lone "\r" (PHP accepts all three), here and at the closing name.
const readHeredoc = (source, start, context) => {
  const { tokens } = context;
  let at = start + 3;
  while (source[at] === ' ' || source[at] === '\t') at += 1;
  const quote = source[at] === '\'' || source[at] === '"' ? source[at] : '';
  if (quote) at += 1;
  const nameEnd = endOfName(source, at);
  const label = source.slice(at, nameEnd);
  const firstBreak = nextLineBreak(source, nameEnd);
  if (label === '' || firstBreak < 0) return readSymbol(source, start, tokens);
  // Of "\r\n" the "\n" is the break the body starts behind.
  const bodyStart = source[firstBreak] === '\r' && source[firstBreak + 1] === '\n' ? firstBreak + 1 : firstBreak;
  const closing = findHeredocEnd(source, bodyStart, label);
  const body = removeIndent(source.slice(bodyStart + 1, closing.bodyEnd), closing.indent);
  if (quote === '\'') {
    tokens.push({ kind: 'string', text: body, interpolated: false, escaped: false, at: start });
  } else {
    const firstEmbedded = tokens.length;
    const decoded = decodeInterpolating(body, { start: 0, closer: TO_THE_END }, context);
    // Code inside the body was read at offsets of the body; moved to offsets of the file.
    for (let index = firstEmbedded; index < tokens.length; index += 1) tokens[index].at += bodyStart + 1;
    tokens.push({ kind: 'string', ...decoded.token, at: start });
  }
  return closing.end;
};

// `bodyEnd` leaves out the line break in front of the closing name, as PHP does.
const findHeredocEnd = (source, bodyStart, label) => {
  for (let lineStart = bodyStart; lineStart >= 0; lineStart = nextLineBreak(source, lineStart + 1)) {
    let at = lineStart + 1;
    while (source[at] === ' ' || source[at] === '\t') at += 1;
    if (source.startsWith(label, at) && !isNameChar(source[at + label.length])) {
      const isAfterCarriageReturn = source[lineStart] === '\n' && source[lineStart - 1] === '\r' && lineStart > bodyStart;
      const bodyEnd = Math.max(bodyStart + 1, isAfterCarriageReturn ? lineStart - 1 : lineStart);
      return { bodyEnd, end: at + label.length, indent: source.slice(lineStart + 1, at) };
    }
  }
  return { bodyEnd: source.length, end: source.length, indent: '' };
};

// The next "\r" or "\n" from `start` on, or -1. One walk, so a file without "\r" is not
// searched to its end for one at every line.
const nextLineBreak = (source, start) => {
  let at = start;
  while (at < source.length && !isLineBreak(source[at])) at += 1;
  return at < source.length ? at : -1;
};

// PHP 7.3+ takes the closing marker's indentation off every line of the body.
const removeIndent = (body, indent) => {
  if (indent === '') return body;
  return body.split(/\r\n|\n|\r/).map((line) => (line.startsWith(indent) ? line.slice(indent.length) : line)).join('\n');
};

// Decodes a double-quoted string or heredoc body from `start` to the `closer` character, or to
// the end of the text when the closer is TO_THE_END (a heredoc body, already cut out of the file).
// "{$...}" and "${...}" hold an expression that PHP runs ("{$logger->write(system($command))}"
// starts the program), so what stands between the braces is read as code into the same tokens.
const decodeInterpolating = (source, { start, closer }, context) => {
  const pieces = [];
  let interpolated = false;
  let escaped = false;
  let pieceStart = start;
  let at = start;
  while (at < source.length && source[at] !== closer) {
    const char = source[at];
    let replacement = null;
    let end = at + 1;
    if (char === '\\') {
      const escape = decodeEscape(source, at);
      replacement = escape.text;
      escaped ||= escape.isSpelled;
      end = escape.end;
    } else if (char === '$' && isNameStart(source[at + 1])) {
      replacement = VARIABLE_MARK;
      interpolated = true;
      end = endOfName(source, at + 1);
    } else if ((char === '{' && source[at + 1] === '$') || (char === '$' && source[at + 1] === '{')) {
      replacement = VARIABLE_MARK;
      interpolated = true;
      end = lexEmbedded(source, char === '{' ? at + 1 : at + 2, context);
    }
    if (replacement !== null) {
      pieces.push(source.slice(pieceStart, at), replacement);
      pieceStart = end;
    }
    at = end;
  }
  pieces.push(source.slice(pieceStart, at));
  return { token: { text: pieces.join(''), interpolated, escaped }, end: at };
};

const decodeEscape = (source, at) => {
  const next = source[at + 1];
  if (SIMPLE_ESCAPES.has(next)) return { text: SIMPLE_ESCAPES.get(next), isSpelled: false, end: at + 2 };
  if (next === 'x' && isHexDigit(source[at + 2])) {
    const digits = isHexDigit(source[at + 3]) ? 2 : 1;
    return { text: String.fromCharCode(parseInt(source.slice(at + 2, at + 2 + digits), 16)), isSpelled: true, end: at + 2 + digits };
  }
  if (isOctalDigit(next)) {
    let end = at + 1;
    while (end < at + 4 && isOctalDigit(source[end])) end += 1;
    return { text: String.fromCharCode(parseInt(source.slice(at + 1, end), 8) % BYTE_VALUES), isSpelled: true, end };
  }
  if (next === 'u' && source[at + 2] === '{') {
    // PHP takes any number of leading zeros ("\u{0000065}"). The digits are walked up to a
    // fixed reach: looking for the brace in the whole rest of the file would cost the square
    // of its length in a file made of "\u{" alone.
    let close = at + 3;
    while (close < at + 3 + UNICODE_ESCAPE_REACH && isHexDigit(source[close])) close += 1;
    const codePoint = close > at + 3 && source[close] === '}' ? parseInt(source.slice(at + 3, close), 16) : NaN;
    if (Number.isInteger(codePoint) && codePoint <= MAX_CODE_POINT) {
      return { text: String.fromCodePoint(codePoint), isSpelled: true, end: close + 1 };
    }
  }
  return { text: `\\${next ?? ''}`, isSpelled: false, end: at + 2 };
};

const UNICODE_ESCAPE_REACH = 64;
// The last code point Unicode has; a "\u{...}" past it is not decoded.
const MAX_CODE_POINT = 0x10ffff;

// The expression of "{$...}" or "${...}", from its first character to the closing brace.
// Returns the offset just past that brace.
const lexEmbedded = (source, start, context) => {
  if (context.depth >= MAX_EMBEDDED_DEPTH) throw new CodeTooLargeError('nesting');
  context.depth += 1;
  const end = lexCode(source, start, context);
  context.depth -= 1;
  return end;
};

const readName = (source, start, tokens) => {
  let at = start;
  // Namespace parts: Foo\Bar\baz, \exec.
  while (at < source.length && (isNameChar(source[at]) || (source[at] === '\\' && isNameStart(source[at + 1])))) at += 1;
  tokens.push({ kind: 'name', text: source.slice(start, at), at: start });
  return at;
};

const readNumber = (source, start, tokens) => {
  let at = start;
  while (at < source.length && (isNameChar(source[at]) || (source[at] === '.' && continuesNumber(source, at + 1)))) at += 1;
  tokens.push({ kind: 'number', integer: integerValue(source.slice(start, at).replaceAll('_', '')), at: start });
  return at;
};

// After the dot of a number: more digits (1.5), or an exponent straight away (1.e-4, which
// WooCommerce writes). Without the second, the "e" would be read as a name.
const continuesNumber = (source, at) => {
  if (isDigit(source[at])) return true;
  if (source[at] !== 'e' && source[at] !== 'E') return false;
  const afterSign = source[at + 1] === '-' || source[at + 1] === '+' ? at + 2 : at + 1;
  return isDigit(source[afterSign]);
};

const integerValue = (literal) => {
  const lower = literal.toLowerCase();
  if (/^0x[0-9a-f]+$/.test(lower)) return parseInt(lower.slice(2), 16);
  if (/^0b[01]+$/.test(lower)) return parseInt(lower.slice(2), 2);
  if (/^0o?[0-7]+$/.test(lower)) return parseInt(lower.replace(/^0o?/, ''), 8);
  if (/^[0-9]+$/.test(lower)) return parseInt(lower, 10);
  return NaN;
};

const readSymbol = (source, at, tokens) => {
  for (const symbols of SYMBOLS_BY_LENGTH) {
    const symbol = symbols.find((candidate) => source.startsWith(candidate, at));
    if (symbol) {
      tokens.push({ kind: 'symbol', text: symbol, at });
      return at + symbol.length;
    }
  }
  tokens.push({ kind: 'symbol', text: source[at], at });
  return at + 1;
};

const endOfName = (source, start) => {
  let at = start;
  while (at < source.length && isNameChar(source[at])) at += 1;
  return at;
};

const startsWithIgnoringCase = (source, at, word) => source.slice(at, at + word.length).toLowerCase() === word;

// PHP names: letters, digits, underscore and every byte from 0x80 up (the text is decoded as
// latin1, one character per byte).
const isLetter = (char) => (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z');
const isNameStart = (char) => char !== undefined && (isLetter(char) || char === '_' || char >= '\u{80}');
const isNameChar = (char) => isNameStart(char) || isDigit(char);
const isDigit = (char) => char !== undefined && char >= '0' && char <= '9';
const isHexDigit = (char) => isDigit(char) || (char !== undefined && ((char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F')));
const isOctalDigit = (char) => char !== undefined && char >= '0' && char <= '7';
const isSpace = (char) => char === ' ' || char === '\n' || char === '\r' || char === '\t' || char === '\v' || char === '\f';
const isLineBreak = (char) => char === '\n' || char === '\r';
