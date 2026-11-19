// SPDX-License-Identifier: GPL-3.0-or-later
//
// The piece of a file a finding points at, for the visitor to read on the page. Worker side.
// It is the archive author's text, so the page shows it like a file name: through the display
// sanitizer, as text.

const BEFORE_CHARACTERS = 60;
const EXCERPT_CHARACTERS = 200;
const CUT_MARK = '…';

// `source` is the file with one character per byte (as the engine decodes it), `at` an offset into it. Packed
// code is often one line of many kilobytes, so the excerpt is a window around the place and
// never the whole line.
export const excerptAround = (source, at) => {
  const lineStart = at === 0 ? 0 : source.lastIndexOf('\n', at - 1) + 1;
  const lineEnd = endOfLine(source, at);
  const from = Math.max(lineStart, at - BEFORE_CHARACTERS);
  const to = Math.min(lineEnd, from + EXCERPT_CHARACTERS);
  return `${from > lineStart ? CUT_MARK : ''}${asUtf8(source.slice(from, to)).trim()}${to < lineEnd ? CUT_MARK : ''}`;
};

// `line` counts from 1 and a line ends at "\n", "\r\n" or a lone "\r", the way the settings
// files are read (config-rules.js).
export const excerptOfLine = (source, line) => {
  const text = source.split(/\r\n|\r|\n/, line)[line - 1] ?? '';
  const shown = text.trim();
  return shown.length > EXCERPT_CHARACTERS ? `${asUtf8(shown.slice(0, EXCERPT_CHARACTERS))}${CUT_MARK}` : asUtf8(shown);
};

const endOfLine = (source, at) => {
  const newline = source.indexOf('\n', at);
  return newline < 0 ? source.length : newline;
};

// A browser reads the label "latin1" as windows-1252: the bytes 0x80 to 0x9F come out as
// characters above U+00FF (0x82 as U+201A), so the way back to bytes needs their table.
const WINDOWS_1252_BLOCK_START = 0x80;
const WINDOWS_1252_BLOCK_BYTES = 32;
const BYTE_OF_CHARACTER = new Map(Array.from({ length: WINDOWS_1252_BLOCK_BYTES }, (_, index) => {
  const byte = WINDOWS_1252_BLOCK_START + index;
  return [new TextDecoder('latin1').decode(Uint8Array.of(byte)), byte];
}));

// The bytes back as UTF-8, which is what nearly every PHP file is written in. A character cut
// in half by the window becomes U+FFFD.
const asUtf8 = (oneCharacterPerByte) => new TextDecoder().decode(Uint8Array.from(
  oneCharacterPerByte,
  (character) => BYTE_OF_CHARACTER.get(character) ?? character.charCodeAt(0),
));
