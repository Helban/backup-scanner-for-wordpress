// SPDX-License-Identifier: GPL-3.0-or-later
//
// The one form of tar this scanner vouches for. Three reviews in a row found headers that tar
// programs read in different ways (a pax record, a number field with a tab in it, a prefix under
// a magic nobody expects), and each fix met a new kind (2026-11-21). So instead of a list of
// known disagreements, this is a list of what honest writers produce and every program reads
// alike: GNU tar 1.35, bsdtar 3.8, busybox tar and Python's tarfile, measured on the archives of
// GNU tar, bsdtar, busybox, tarfile, node-tar and git archive. Whatever falls outside it is
// reported (tar.unusual_form), because outside it the list the scanner shows and the files a
// program writes may part ways.
//
// Each function returns '' for the canonical form, or the reason it is not.

const BLOCK_BYTES = 512;
const NUL = 0x00;
const ASCII_TAB = 0x09;
const ASCII_NEWLINE = 0x0a;
const ASCII_CARRIAGE_RETURN = 0x0d;
const ASCII_SPACE = 0x20;
const ASCII_PLUS = 0x2b;
const ASCII_MINUS = 0x2d;
const DOT = 0x2e;
const SLASH = 0x2f;
const ASCII_ZERO = 0x30;
const ASCII_SEVEN = 0x37;
const ASCII_EQUALS = 0x3d;
const BACKSLASH = 0x5c;
const LAST_PRINTABLE = 0x7e;
const LAST_ASCII = 0x7f;
const HIGH_BIT = 0x80;

const CHECKSUM_AT = 148;
const CHECKSUM_BYTES = 8;
const TYPE_AT = 156;
const MAGIC_AT = 257;
// Fields every header has, read as numbers by every program: mode, uid, gid, size, mtime.
const NUMBER_FIELDS = [[100, 8], [108, 8], [116, 8], [124, 12], [136, 12]];
// Device numbers (ustar and GNU).
const DEVICE_FIELDS = [[329, 8], [337, 8]];
// Text fields: after the first NUL, only NULs.
const NAME_FIELD = [0, 100];
const LINK_FIELD = [157, 100];
// GNU keeps access and change times, sparse maps and a real size from byte 345 on; an archive
// that uses them is not one every program reads alike (old GNU sparse files, incremental dumps).
const GNU_EXTRA_AT = 345;
const POSIX_PAD_AT = 500;

const POSIX_MAGIC = [0x75, 0x73, 0x74, 0x61, 0x72, 0x00, 0x30, 0x30];
const GNU_MAGIC = [0x75, 0x73, 0x74, 0x61, 0x72, 0x20, 0x20, 0x00];

export const TYPE_FILE = 0x30;
export const TYPE_OLD_FILE = 0x00;
export const TYPE_HARD_LINK = 0x31;
export const TYPE_SYMLINK = 0x32;
export const TYPE_DIRECTORY = 0x35;
export const TYPE_GNU_LONG_NAME = 0x4c;
export const TYPE_GNU_LONG_LINK = 0x4b;
export const TYPE_PAX = 0x78;
export const TYPE_PAX_GLOBAL = 0x67;

const ENTRY_TYPES = [TYPE_FILE, TYPE_OLD_FILE, TYPE_HARD_LINK, TYPE_SYMLINK, TYPE_DIRECTORY];
const TYPES_BY_MAGIC = new Map([
  ['posix', new Set([...ENTRY_TYPES, TYPE_PAX, TYPE_PAX_GLOBAL])],
  ['gnu', new Set([...ENTRY_TYPES, TYPE_GNU_LONG_NAME, TYPE_GNU_LONG_LINK])],
  ['v7', new Set(ENTRY_TYPES)],
]);

// One header block, on its own.
export const headerFormIssue = (header) => {
  const magic = magicOf(header);
  if (magic === '') return 'magic';
  const checksum = canonicalNumber(header, CHECKSUM_AT, CHECKSUM_BYTES);
  if (checksum === null || checksum !== headerSums(header).unsigned) return 'checksum';
  const numberFields = magic === 'v7' ? NUMBER_FIELDS : [...NUMBER_FIELDS, ...DEVICE_FIELDS];
  // A field of NULs only is 0 to every program (node-tar's portable mode, PHP's PharData).
  if (numberFields.some(([at, length]) => !isZero(header, at, at + length) && canonicalNumber(header, at, length) === null)) return 'number';
  if (!TYPES_BY_MAGIC.get(magic).has(header[TYPE_AT])) return 'type';
  // Every program cuts these at the first NUL. The prefix is left out: node-tar keeps access
  // and change times behind its NUL, and GNU tar's star layout (prefix cut at 131) reads alike.
  if ([NAME_FIELD, LINK_FIELD].some(([at, length]) => !isPaddedText(header, at, length))) return 'padding';
  if (magic === 'gnu' && !isZero(header, GNU_EXTRA_AT, BLOCK_BYTES)) return 'gnu_fields';
  if (magic === 'posix' && !isZero(header, POSIX_PAD_AT, BLOCK_BYTES)) return 'padding';
  return '';
};

// The sums a checksum field is compared with: of the block's bytes with the field itself counted
// as spaces, unsigned and (as old tars wrote it) signed.
export const headerSums = (block) => {
  let unsigned = 0;
  let signed = 0;
  for (let index = 0; index < BLOCK_BYTES; index += 1) {
    const byte = index >= CHECKSUM_AT && index < CHECKSUM_AT + CHECKSUM_BYTES ? ASCII_SPACE : block[index];
    unsigned += byte;
    signed += byte & HIGH_BIT ? byte - 256 : byte;
  }
  return { unsigned, signed };
};

// Whether some tar program may take this block for a header: its checksum field, read the way
// any of GNU tar, tarfile, busybox or bsdtar reads it, matches the block. A block nobody takes
// for a header is damage (or a database dump that is not a tar at all); one that some program
// takes and this scanner cannot read is where the scanner's list and that program part ways.
export const mightBeHeader = (block) => {
  if (block.length < BLOCK_BYTES) return false;
  const readings = checksumReadings(block.subarray(CHECKSUM_AT, CHECKSUM_AT + CHECKSUM_BYTES));
  if (readings.size === 0) return false;
  const { unsigned, signed } = headerSums(block);
  return readings.has(unsigned) || readings.has(signed);
};

// The data of a GNU long name or long link record: the name, one NUL, nothing else.
export const longNameIssue = (content) => {
  const end = content.indexOf(NUL);
  return content.length >= 2 && end === content.length - 1 ? '' : 'long_name';
};

// Pax keys an honest writer puts in a file's own header, and in a global one. None of them
// changes which file a program writes or how much data it takes, except path, linkpath and size,
// which the reader checks against the rest (tar-reader.js).
const LOCAL_KEYS = new Set([
  'path', 'linkpath', 'size', 'mtime', 'atime', 'ctime', 'uid', 'gid', 'uname', 'gname', 'hdrcharset', 'charset', 'comment',
  'SCHILY.fflags', 'SCHILY.dev', 'SCHILY.ino', 'SCHILY.nlink', 'LIBARCHIVE.creationtime',
]);
const LOCAL_KEY_PREFIXES = ['SCHILY.xattr.', 'SCHILY.acl.', 'LIBARCHIVE.xattr.'];
const GLOBAL_KEYS = new Set(['comment', 'charset', 'hdrcharset', 'mtime']);
const DECIMAL = /^(0|[1-9][0-9]*)$/;
const TIME = /^-?[0-9]+(\.[0-9]+)?$/;
const VALUE_FORMS = new Map([
  ['size', DECIMAL], ['uid', DECIMAL], ['gid', DECIMAL], ['mtime', TIME], ['atime', TIME], ['ctime', TIME],
]);
const NAME_KEYS = ['path', 'linkpath', 'uname', 'gname'];
const NON_EMPTY_KEYS = ['path', 'linkpath'];
const UTF8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

const isLocalKey = (key) => LOCAL_KEYS.has(key) || LOCAL_KEY_PREFIXES.some((prefix) => key.startsWith(prefix));
const isGlobalKey = (key) => GLOBAL_KEYS.has(key);

// A pax header: "<length> <key>=<value>\n" records that fill the data exactly, the length in
// plain decimal followed by one space, each key once and known, and the values in the forms
// paxValueIssue allows. Returns the issue ('' for none).
export const localPaxIssue = (content) => paxIssue(content, isLocalKey);
export const globalPaxIssue = (content) => paxIssue(content, isGlobalKey);

const paxIssue = (content, isKnownKey) => {
  if (content.length === 0) return 'pax_records';
  const records = new Map();
  for (let at = 0; at < content.length;) {
    const space = content.indexOf(ASCII_SPACE, at);
    if (space < 0) return 'pax_records';
    const lengthText = asciiOf(content.subarray(at, space));
    if (!DECIMAL.test(lengthText) || lengthText === '0') return 'pax_records';
    const recordEnd = at + Number(lengthText);
    if (recordEnd > content.length || recordEnd <= space + 1 || content[recordEnd - 1] !== ASCII_NEWLINE) return 'pax_records';
    const record = content.subarray(space + 1, recordEnd - 1);
    const equals = record.indexOf(ASCII_EQUALS);
    if (equals <= 0) return 'pax_records';
    const key = asciiOf(record.subarray(0, equals));
    if (key === null || records.has(key)) return 'pax_records';
    if (!isKnownKey(key)) return 'pax_key';
    records.set(key, record.subarray(equals + 1));
    at = recordEnd;
  }
  return paxValueIssue(records);
};

// Path and link path not empty; the four names without NUL and in UTF-8 unless the header says
// hdrcharset=BINARY; numbers and times in plain decimal.
const paxValueIssue = (records) => {
  const isBinary = records.has('hdrcharset') && asciiOf(records.get('hdrcharset')) === 'BINARY';
  if (NON_EMPTY_KEYS.some((key) => records.has(key) && records.get(key).length === 0)) return 'pax_value';
  for (const key of NAME_KEYS.filter((name) => records.has(name))) {
    const nameBytes = records.get(key);
    if (nameBytes.includes(NUL) || (!isBinary && !isUtf8(nameBytes))) return 'pax_value';
  }
  for (const [key, form] of VALUE_FORMS) {
    if (records.has(key) && !form.test(asciiOf(records.get(key)) ?? '')) return 'pax_value';
  }
  return '';
};

// The name a file is written under, whatever record gave it: relative, components neither
// empty nor "." nor "..", no NUL and no backslash (Windows tar takes it for a folder break).
// One leading "./" is what `tar -C dir .` writes, and "." or "./" alone is that folder. A
// trailing slash is judged by the caller, which knows whether the entry is a folder.
export const pathIssue = (nameBytes) => {
  let name = nameBytes;
  if (name.includes(NUL) || name.includes(BACKSLASH)) return 'name';
  if (isBytes(name, [DOT]) || isBytes(name, [DOT, SLASH])) return '';
  if (name.length > 2 && name[0] === DOT && name[1] === SLASH) name = name.subarray(2);
  if (name.length > 1 && name[name.length - 1] === SLASH) name = name.subarray(0, name.length - 1);
  if (name.length === 0 || name[0] === SLASH) return 'name';
  let start = 0;
  for (let index = 0; index <= name.length; index += 1) {
    if (index < name.length && name[index] !== SLASH) continue;
    const part = name.subarray(start, index);
    if (part.length === 0 || isBytes(part, [DOT]) || isBytes(part, [DOT, DOT])) return 'name';
    start = index + 1;
  }
  return '';
};

// Whether the name is spelled as a folder: ending in a slash, or "." itself.
export const isFolderSpelling = (nameBytes) => (
  nameBytes[nameBytes.length - 1] === SLASH || isBytes(nameBytes, [DOT])
);

// A name as one key for "seen before": the bytes without a leading "./" and a trailing slash,
// one character per byte so that no two byte strings meet.
export const nameKey = (nameBytes) => {
  let name = nameBytes;
  if (name.length > 2 && name[0] === DOT && name[1] === SLASH) name = name.subarray(2);
  if (name.length > 1 && name[name.length - 1] === SLASH) name = name.subarray(0, name.length - 1);
  return byteString(name);
};

export const byteString = (bytes) => {
  let text = '';
  for (let at = 0; at < bytes.length; at += STRING_PIECE) text += String.fromCharCode(...bytes.subarray(at, at + STRING_PIECE));
  return text;
};

const STRING_PIECE = 4096;

// 'posix', 'gnu', 'v7' (no magic, the rest of the block empty), or '' for anything else.
const magicOf = (header) => {
  if (startsWith(header, MAGIC_AT, POSIX_MAGIC)) return 'posix';
  if (startsWith(header, MAGIC_AT, GNU_MAGIC)) return 'gnu';
  return isZero(header, MAGIC_AT, BLOCK_BYTES) ? 'v7' : '';
};

// The canonical number: optional leading spaces, octal digits, then only spaces or NULs. Every
// program reads this the same; GNU's base-256 and the forms some program alone accepts (a tab,
// a sign, "0o", an underscore, a digit after the terminator) are left out.
const canonicalNumber = (bytes, at, length) => {
  let index = at;
  const end = at + length;
  while (index < end && bytes[index] === ASCII_SPACE) index += 1;
  const run = octalRun(bytes.subarray(0, end), index);
  if (run.digits === 0) return null;
  for (index = run.end; index < end; index += 1) if (bytes[index] !== ASCII_SPACE && bytes[index] !== NUL) return null;
  return run.number;
};

// The numbers tar programs read from a checksum field (2026-11-21, the third review's cases):
//   GNU tar 1.35  - leading white space, octal digits, then end, NUL or white space;
//   tarfile       - cut at NUL, white space stripped, int(text, 8): a sign, "0o", underscores;
//                   base-256 when the first byte is 0x80 or 0xff;
//   busybox       - strtoull(text, 8) with a sign, ended by NUL or space;
//   bsdtar        - leading spaces and tabs, a minus, octal digits up to the first other byte;
//                   base-256 when the first byte has its high bit set.
// Generous on purpose: a reading too many costs a finding on a damaged tar, one too few hides one.
const checksumReadings = (field) => {
  const candidates = [readGnu(field), readTarfile(field), readBusybox(field), readBsdtar(field)];
  if (field[0] & HIGH_BIT) candidates.push(readBase256(field));
  return new Set(candidates.filter((number) => number !== null && Number.isSafeInteger(number)));
};

const isWhite = (byte) => byte === ASCII_SPACE || (byte >= ASCII_TAB && byte <= ASCII_CARRIAGE_RETURN);
const isOctal = (byte) => byte >= ASCII_ZERO && byte <= ASCII_SEVEN;

// The octal digits from `start` on: their number, where they end, how many there were.
const octalRun = (field, start) => {
  let index = start;
  let number = 0;
  while (index < field.length && isOctal(field[index])) {
    number = number * 8 + (field[index] - ASCII_ZERO);
    index += 1;
  }
  return { number, end: index, digits: index - start };
};

const readGnu = (field) => {
  let index = 0;
  while (index < field.length && isWhite(field[index])) index += 1;
  const run = octalRun(field, index);
  if (run.digits === 0) return null;
  return run.end === field.length || field[run.end] === NUL || isWhite(field[run.end]) ? run.number : null;
};

// Python's str.strip() and int() take \x1c-\x1f for white space too.
const PYTHON_WHITE = /^[\t\n\v\f\r\x1c-\x1f ]+|[\t\n\v\f\r\x1c-\x1f ]+$/g;

const readTarfile = (field) => {
  const end = field.indexOf(NUL);
  const cut = end < 0 ? field : field.subarray(0, end);
  if (cut.some((byte) => byte > LAST_ASCII)) return null;
  let body = String.fromCharCode(...cut).replace(PYTHON_WHITE, '');
  if (body === '') return 0;
  let sign = 1;
  if (body[0] === '+' || body[0] === '-') {
    sign = body[0] === '-' ? -1 : 1;
    body = body.slice(1);
  }
  if (/^0[oO]/.test(body)) body = body.slice(2).replace(/^_/, '');
  if (!/^[0-7]+(_[0-7]+)*$/.test(body)) return null;
  return sign * parseInt(body.replaceAll('_', ''), 8);
};

const readBusybox = (field) => {
  let index = 0;
  while (index < field.length && isWhite(field[index])) index += 1;
  let sign = 1;
  if (field[index] === ASCII_PLUS || field[index] === ASCII_MINUS) {
    sign = field[index] === ASCII_MINUS ? -1 : 1;
    index += 1;
  }
  const run = octalRun(field, index);
  if (run.digits === 0) return null;
  if (run.end < field.length && field[run.end] !== NUL && field[run.end] !== ASCII_SPACE) return null;
  return sign * run.number;
};

const readBsdtar = (field) => {
  let index = 0;
  while (index < field.length && (field[index] === ASCII_SPACE || field[index] === ASCII_TAB)) index += 1;
  let sign = 1;
  if (field[index] === ASCII_MINUS) {
    sign = -1;
    index += 1;
  }
  if (field[index] === ASCII_PLUS) index += 1;
  return sign * octalRun(field, index).number;
};

const readBase256 = (field) => {
  let number = field[0] & ~HIGH_BIT;
  for (let index = 1; index < field.length; index += 1) number = number * 256 + field[index];
  return number;
};

const isUtf8 = (bytes) => {
  try {
    UTF8.decode(bytes);
  } catch (error) {
    if (error instanceof TypeError) return false;
    throw error;
  }
  return true;
};

// ASCII text of the bytes, or null when one of them is not printable ASCII.
const asciiOf = (bytes) => {
  let text = '';
  for (const byte of bytes) {
    if (byte < ASCII_SPACE || byte > LAST_PRINTABLE) return null;
    text += String.fromCharCode(byte);
  }
  return text;
};

const isPaddedText = (bytes, at, length) => {
  const end = bytes.subarray(at, at + length).indexOf(NUL);
  return end < 0 || isZero(bytes, at + end, at + length);
};

const isZero = (bytes, from, to) => {
  for (let index = from; index < to; index += 1) if (bytes[index] !== 0) return false;
  return true;
};

const isBytes = (bytes, expected) => bytes.length === expected.length && expected.every((byte, index) => bytes[index] === byte);

const startsWith = (bytes, at, expected) => expected.every((byte, index) => bytes[at + index] === byte);
