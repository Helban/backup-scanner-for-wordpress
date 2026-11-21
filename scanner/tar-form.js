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
const ASCII_SPACE = 0x20;
const ASCII_ZERO = 0x30;
const NUL = 0x00;
const SLASH = 0x2f;
const BACKSLASH = 0x5c;
const DOT = 0x2e;

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

// 'posix', 'gnu', 'v7' (no magic, the rest of the block empty), or '' for anything else.
export const magicOf = (header) => {
  if (startsWith(header, MAGIC_AT, POSIX_MAGIC)) return 'posix';
  if (startsWith(header, MAGIC_AT, GNU_MAGIC)) return 'gnu';
  return isZero(header, MAGIC_AT, BLOCK_BYTES) ? 'v7' : '';
};

// One header block, on its own.
export const headerFormIssue = (header) => {
  const magic = magicOf(header);
  if (magic === '') return 'magic';
  const checksum = canonicalNumber(header, CHECKSUM_AT, CHECKSUM_BYTES);
  if (checksum === null || checksum !== unsignedSum(header)) return 'checksum';
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

// Whether some tar program may take this block for a header: its checksum field, read the way
// any of GNU tar, tarfile, busybox or bsdtar reads it, matches the block. A block nobody takes
// for a header is damage (or a database dump that is not a tar at all); one that some program
// takes and this scanner cannot read is where the scanner's list and that program part ways.
export const mightBeHeader = (block) => {
  if (block.length < BLOCK_BYTES) return false;
  const readings = checksumReadings(block.subarray(CHECKSUM_AT, CHECKSUM_AT + CHECKSUM_BYTES));
  if (readings.size === 0) return false;
  let unsigned = 0;
  let signed = 0;
  for (let index = 0; index < BLOCK_BYTES; index += 1) {
    const byte = index >= CHECKSUM_AT && index < CHECKSUM_AT + CHECKSUM_BYTES ? ASCII_SPACE : block[index];
    unsigned += byte;
    signed += byte > 127 ? byte - 256 : byte;
  }
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
const UTF8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const LAST_PRINTABLE = 0x7e;

// A pax header: "<length> <key>=<value>\n" records that fill the data exactly, the length in
// plain decimal followed by one space, each key once and known, path and linkpath non-empty,
// without NUL and in UTF-8 unless the header says hdrcharset=BINARY. Returns { issue, records }.
export const readCanonicalPax = (content, { isGlobal }) => {
  const records = new Map();
  let at = 0;
  if (content.length === 0) return { issue: 'pax_records', records };
  while (at < content.length) {
    const space = content.indexOf(ASCII_SPACE, at);
    if (space < 0) return { issue: 'pax_records', records };
    const lengthText = asciiOf(content.subarray(at, space));
    if (!DECIMAL.test(lengthText) || lengthText === '0') return { issue: 'pax_records', records };
    const recordEnd = at + Number(lengthText);
    if (recordEnd > content.length || recordEnd <= space + 1 || content[recordEnd - 1] !== 0x0a) return { issue: 'pax_records', records };
    const record = content.subarray(space + 1, recordEnd - 1);
    const equals = record.indexOf(0x3d);
    if (equals <= 0) return { issue: 'pax_records', records };
    const key = asciiOf(record.subarray(0, equals));
    if (key === null || records.has(key)) return { issue: 'pax_records', records };
    if (!(isGlobal ? GLOBAL_KEYS.has(key) : LOCAL_KEYS.has(key) || LOCAL_KEY_PREFIXES.some((prefix) => key.startsWith(prefix)))) {
      return { issue: 'pax_key', records };
    }
    records.set(key, record.subarray(equals + 1));
    at = recordEnd;
  }
  const isBinary = records.has('hdrcharset') && asciiOf(records.get('hdrcharset')) === 'BINARY';
  for (const key of ['path', 'linkpath', 'uname', 'gname']) {
    if (records.has(key) && !isNameValue(records.get(key), { isBinary, mayBeEmpty: key === 'uname' || key === 'gname' })) {
      return { issue: 'pax_value', records };
    }
  }
  for (const [key, form] of VALUE_FORMS) {
    if (records.has(key) && !form.test(asciiOf(records.get(key)) ?? '')) return { issue: 'pax_value', records };
  }
  return { issue: '', records };
};

// The name a file is written under, whatever record gave it: relative, components neither
// empty nor "." nor "..", no NUL and no backslash (Windows tar takes it for a folder break),
// a trailing slash on folders only. One leading "./" is what `tar -C dir .` writes.
export const pathIssue = (nameBytes, { isDirectory }) => {
  let name = nameBytes;
  if (name.includes(NUL) || name.includes(BACKSLASH)) return 'name';
  if (isDirectory && (isBytes(name, [DOT]) || isBytes(name, [DOT, SLASH]))) return '';
  if (name.length > 2 && name[0] === DOT && name[1] === SLASH) name = name.subarray(2);
  if (name.length === 0 || name[0] === SLASH) return 'name';
  if (name[name.length - 1] === SLASH) {
    if (!isDirectory) return 'name';
    name = name.subarray(0, name.length - 1);
  }
  let start = 0;
  for (let index = 0; index <= name.length; index += 1) {
    if (index < name.length && name[index] !== SLASH) continue;
    const part = name.subarray(start, index);
    if (part.length === 0 || isBytes(part, [DOT]) || isBytes(part, [DOT, DOT])) return 'name';
    start = index + 1;
  }
  return '';
};

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

// The canonical number: optional leading spaces, octal digits, then only spaces or NULs. Every
// program reads this the same; GNU's base-256 and the forms some program alone accepts (a tab,
// a sign, "0o", an underscore, a digit after the terminator) are left out.
const canonicalNumber = (bytes, at, length) => {
  let index = at;
  const end = at + length;
  while (index < end && bytes[index] === ASCII_SPACE) index += 1;
  let value = 0;
  let digits = 0;
  while (index < end && bytes[index] >= ASCII_ZERO && bytes[index] <= ASCII_ZERO + 7) {
    value = value * 8 + (bytes[index] - ASCII_ZERO);
    digits += 1;
    index += 1;
  }
  if (digits === 0) return null;
  for (; index < end; index += 1) if (bytes[index] !== ASCII_SPACE && bytes[index] !== NUL) return null;
  return value;
};

// The values tar programs read from a checksum field (2026-11-21, the third review's cases):
//   GNU tar 1.35  - leading white space, octal digits, then end, NUL or white space;
//   tarfile       - cut at NUL, white space stripped, int(text, 8): a sign, "0o", underscores;
//                   base-256 when the first byte is 0x80 or 0xff;
//   busybox       - strtoull(text, 8) with a sign, ended by NUL or space;
//   bsdtar        - leading spaces and tabs, a sign, octal digits up to the first other byte;
//                   base-256 when the first byte has its high bit set.
// Generous on purpose: a reading too many costs a finding on a damaged tar, one too few hides one.
const checksumReadings = (field) => {
  const readings = new Set();
  const add = (value) => {
    if (value !== null && Number.isSafeInteger(value)) readings.add(value);
  };
  add(readGnu(field));
  add(readTarfile(field));
  add(readBusybox(field));
  add(readBsdtar(field));
  if ((field[0] & 0x80) !== 0) add(readBase256(field));
  return readings;
};

const isWhite = (byte) => byte === ASCII_SPACE || (byte >= 0x09 && byte <= 0x0d);
const isOctal = (byte) => byte >= ASCII_ZERO && byte <= ASCII_ZERO + 7;

const octalRun = (field, start) => {
  let index = start;
  let value = 0;
  while (index < field.length && isOctal(field[index])) {
    value = value * 8 + (field[index] - ASCII_ZERO);
    index += 1;
  }
  return { value, end: index, digits: index - start };
};

const readGnu = (field) => {
  let index = 0;
  while (index < field.length && isWhite(field[index])) index += 1;
  const run = octalRun(field, index);
  if (run.digits === 0) return null;
  return run.end === field.length || field[run.end] === NUL || isWhite(field[run.end]) ? run.value : null;
};

// Python's str.strip() and int() take \x1c-\x1f for white space too.
const PYTHON_WHITE = /^[\t\n\v\f\r\x1c-\x1f ]+|[\t\n\v\f\r\x1c-\x1f ]+$/g;

const readTarfile = (field) => {
  const end = field.indexOf(NUL);
  const cut = end < 0 ? field : field.subarray(0, end);
  if (cut.some((byte) => byte > 0x7f)) return null;
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
  if (field[index] === 0x2b || field[index] === 0x2d) {
    sign = field[index] === 0x2d ? -1 : 1;
    index += 1;
  }
  const run = octalRun(field, index);
  if (run.digits === 0) return null;
  if (run.end < field.length && field[run.end] !== NUL && field[run.end] !== ASCII_SPACE) return null;
  return sign * run.value;
};

const readBsdtar = (field) => {
  let index = 0;
  while (index < field.length && (field[index] === ASCII_SPACE || field[index] === 0x09)) index += 1;
  let sign = 1;
  if (field[index] === 0x2d) {
    sign = -1;
    index += 1;
  }
  if (field[index] === 0x2b) index += 1;
  return sign * octalRun(field, index).value;
};

const readBase256 = (field) => {
  let value = field[0] & 0x7f;
  for (let index = 1; index < field.length; index += 1) value = value * 256 + field[index];
  return value;
};

const unsignedSum = (header) => {
  let sum = 0;
  for (let index = 0; index < BLOCK_BYTES; index += 1) {
    sum += index >= CHECKSUM_AT && index < CHECKSUM_AT + CHECKSUM_BYTES ? ASCII_SPACE : header[index];
  }
  return sum;
};

const isNameValue = (value, { isBinary, mayBeEmpty }) => {
  if (value.length === 0) return mayBeEmpty;
  if (value.includes(NUL)) return false;
  if (isBinary) return true;
  try {
    UTF8.decode(value);
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
