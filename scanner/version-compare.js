// SPDX-License-Identifier: GPL-3.0-or-later
//
// PHP's version_compare(), step for step (php-src ext/standard/versioning.c). The vulnerability
// database states its version ranges in these terms, and its own WordPress plugin decides with
// this function, so any other notion of "older" would list a different set of vulnerabilities.
// tests/reference/version_compare.json holds PHP's answers for 3,136 pairs; the tests compare.

const SPECIAL_FORMS = [
  ['dev', 0], ['alpha', 1], ['a', 1], ['beta', 2], ['b', 2], ['RC', 3], ['rc', 3], ['#', 4], ['pl', 5], ['p', 5],
];
// PHP reads each number with strtol, which stops at the largest long.
const LONG_MAX = 2n ** 63n - 1n;
const NUMBER_MARK = '#N#';

export const OPERATORS = new Map([
  ['lt', (order) => order === -1],
  ['le', (order) => order !== 1],
  ['eq', (order) => order === 0],
  ['ne', (order) => order !== 0],
  ['gt', (order) => order === 1],
  ['ge', (order) => order !== -1],
]);

export const versionSatisfies = (version, operator, bound) => OPERATORS.get(operator)(compareVersions(version, bound));

export const compareVersions = (left, right) => {
  if (left === '' || right === '') {
    if (left === right) return 0;
    return left === '' ? -1 : 1;
  }
  const first = left.startsWith('#') ? left : canonicalize(left);
  const second = right.startsWith('#') ? right : canonicalize(right);
  let at1 = 0;
  let at2 = 0;
  // Where the current part ends; -1 once a string has no dot left (the C code's NULL).
  let dot1 = 0;
  let dot2 = 0;
  let order = 0;
  while (at1 < first.length && at2 < second.length && dot1 !== -1 && dot2 !== -1) {
    dot1 = first.indexOf('.', at1);
    dot2 = second.indexOf('.', at2);
    order = compareParts(partAt(first, at1, dot1), partAt(second, at2, dot2));
    if (order !== 0) break;
    if (dot1 !== -1) at1 = dot1 + 1;
    if (dot2 !== -1) at2 = dot2 + 1;
  }
  if (order !== 0) return order;
  if (dot1 !== -1) return isDigit(first[at1]) ? 1 : compareVersions(first.slice(at1), NUMBER_MARK);
  if (dot2 !== -1) return isDigit(second[at2]) ? -1 : compareVersions(NUMBER_MARK, second.slice(at2));
  return 0;
};

const partAt = (text, start, dot) => (dot === -1 ? text.slice(start) : text.slice(start, dot));

const compareParts = (part1, part2) => {
  const isNumber1 = isDigit(part1[0]);
  const isNumber2 = isDigit(part2[0]);
  if (isNumber1 && isNumber2) return Math.sign(Number(leadingNumber(part1) - leadingNumber(part2)));
  if (!isNumber1 && !isNumber2) return compareSpecialForms(part1, part2);
  return isNumber1 ? compareSpecialForms(NUMBER_MARK, part2) : compareSpecialForms(part1, NUMBER_MARK);
};

const leadingNumber = (part) => {
  const digits = /^[0-9]+/.exec(part)[0];
  const number = BigInt(digits);
  return number > LONG_MAX ? LONG_MAX : number;
};

// A name that matches no form ranks below "dev". Forms match by prefix, so "abc" counts as "a".
const compareSpecialForms = (form1, form2) => Math.sign(specialOrder(form1) - specialOrder(form2));

const specialOrder = (form) => {
  const found = SPECIAL_FORMS.find(([name]) => form.startsWith(name));
  return found ? found[1] : -1;
};

// "1.0rc1-2" becomes "1.0.rc.1.2": separators turn into dots, and a dot goes between a digit and
// a letter. The first character is kept as it is, a dot at the end is dropped. Versions reach
// this function ASCII only (both formats are checked before), as the C code reads bytes.
const canonicalize = (version) => {
  let canonical = version[0];
  let previous = version[0];
  for (const character of version.slice(1)) {
    const lastWritten = canonical[canonical.length - 1];
    const dot = lastWritten === '.' ? '' : '.';
    if (SEPARATORS.has(character)) {
      canonical += dot;
    } else if ((isNonDigit(previous) && isDigit(character)) || (isDigit(previous) && isNonDigit(character))) {
      canonical += dot + character;
    } else if (!isAlphanumeric(character)) {
      canonical += dot;
    } else {
      canonical += character;
    }
    previous = character;
  }
  return canonical.endsWith('.') ? canonical.slice(0, -1) : canonical;
};

const SEPARATORS = new Set(['-', '_', '+']);
const isDigit = (character) => character !== undefined && character >= '0' && character <= '9';
const isNonDigit = (character) => !isDigit(character) && character !== '.';
const isAlphanumeric = (character) => /^[0-9A-Za-z]$/.test(character);
