// SPDX-License-Identifier: GPL-3.0-or-later
//
// The one place where text from the archive is made fit to show. File names are written by
// whoever built the archive: control characters and direction overrides can make a name look
// different on screen from what it is ("photo<U+202E>gpj.exe" renders as "photoexe.jpg").

const DISPLAY_LIMIT = 240;

// Shown as a code instead of being drawn: control, format, private-use and unassigned
// characters, line and paragraph separators, and every space that is not the plain one.
// The two joiners U+200C and U+200D stay, because Persian and Indic words need them.
const NOT_DRAWN = /(?![\u{200C}\u{200D}])[\p{C}\p{Zl}\p{Zp}]|(?! )\p{Zs}/gu;

// Characters with no honest use in a file name: control characters, direction overrides and
// isolates, line and paragraph separators, the byte order mark.
const DECEPTIVE = /[\p{Cc}\u{202A}-\u{202E}\u{2066}-\u{2069}\u{2028}\u{2029}\u{FEFF}]/gu;

export const displayText = (raw, limit = DISPLAY_LIMIT) => {
  const visible = String(raw).replace(NOT_DRAWN, codeLabel);
  const characters = Array.from(visible);
  if (characters.length <= limit) return visible;
  // The end of a path carries the file name and extension, so the cut goes in the middle.
  const half = Math.floor((limit - 1) / 2);
  return `${characters.slice(0, half).join('')}…${characters.slice(-half).join('')}`;
};

export const deceptiveCharacters = (text) => (
  [...new Set(Array.from(text.matchAll(DECEPTIVE), (match) => codeName(match[0])))]
);

const codeLabel = (character) => `⟨${codeName(character)}⟩`;

const codeName = (character) => (
  `U+${character.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}`
);
