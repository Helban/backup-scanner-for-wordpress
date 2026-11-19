// SPDX-License-Identifier: GPL-3.0-or-later
//
// What a file is, judged by its first bytes and by its name. One table row per signature, so
// a row can be removed in a test to prove that its sample depends on it.

const EXECUTABLE_SIGNATURES = [
  { kind: 'windows_program', offset: 0, bytes: [0x4d, 0x5a] },
  { kind: 'linux_program', offset: 0, bytes: [0x7f, 0x45, 0x4c, 0x46] },
  { kind: 'script', offset: 0, bytes: [0x23, 0x21] },
  { kind: 'java_or_macos_program', offset: 0, bytes: [0xca, 0xfe, 0xba, 0xbe] },
  { kind: 'macos_program', offset: 0, bytes: [0xcf, 0xfa, 0xed, 0xfe] },
  { kind: 'windows_shortcut', offset: 0, bytes: [0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00] },
];

const ARCHIVE_SIGNATURES = [
  { kind: 'zip', offset: 0, bytes: [0x50, 0x4b, 0x03, 0x04] },
  { kind: 'zip_empty', offset: 0, bytes: [0x50, 0x4b, 0x05, 0x06] },
  { kind: 'zip_spanned', offset: 0, bytes: [0x50, 0x4b, 0x07, 0x08] },
  { kind: 'sevenzip', offset: 0, bytes: [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c] },
  { kind: 'rar', offset: 0, bytes: [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07] },
  { kind: 'gzip', offset: 0, bytes: [0x1f, 0x8b] },
  { kind: 'bzip2', offset: 0, bytes: [0x42, 0x5a, 0x68] },
  { kind: 'xz', offset: 0, bytes: [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00] },
  { kind: 'zstd', offset: 0, bytes: [0x28, 0xb5, 0x2f, 0xfd] },
  { kind: 'cab', offset: 0, bytes: [0x4d, 0x53, 0x43, 0x46] },
  { kind: 'tar', offset: 257, bytes: [0x75, 0x73, 0x74, 0x61, 0x72] },
];

// The image formats, used the other way round from the two tables above: a file named like
// an image has to match one of these rows. That catches what no list of bad signatures can,
// a payload that is encrypted or of a kind nobody listed. Any row will do for any image
// extension, because a PNG saved as "photo.jpg" is common and harmless.
const IMAGE_SIGNATURES = [
  { kind: 'jpeg', offset: 0, bytes: [0xff, 0xd8, 0xff] },
  { kind: 'png', offset: 0, bytes: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] },
  { kind: 'gif', offset: 0, bytes: [0x47, 0x49, 0x46, 0x38] },
  { kind: 'webp', offset: 8, bytes: [0x57, 0x45, 0x42, 0x50] },
  { kind: 'bmp', offset: 0, bytes: [0x42, 0x4d] },
  { kind: 'icon', offset: 0, bytes: [0x00, 0x00, 0x01, 0x00] },
  { kind: 'cursor', offset: 0, bytes: [0x00, 0x00, 0x02, 0x00] },
  { kind: 'tiff_intel', offset: 0, bytes: [0x49, 0x49, 0x2a, 0x00] },
  { kind: 'tiff_motorola', offset: 0, bytes: [0x4d, 0x4d, 0x00, 0x2a] },
  { kind: 'avif_or_heic', offset: 4, bytes: [0x66, 0x74, 0x79, 0x70] },
];

export const IMAGE_EXTENSIONS = new Set([
  '.jpg', '.jpeg', '.jpe', '.png', '.gif', '.webp', '.avif', '.heic', '.bmp', '.ico', '.tif', '.tiff',
]);

// These two formats have no fixed first bytes, so the name is all there is to go on.
const ARCHIVE_KIND_BY_EXTENSION = new Map([['.wpress', 'wpress'], ['.phar', 'phar']]);

// File names of programs: everything Windows starts when the file is opened (the list
// PROGRAM_EXTENSIONS in code-rules.js, which a test keeps inside this one), plus libraries and
// programs of other systems that no WordPress copy needs either. The code rules keep to the
// first half: a rename in PHP matters when it makes a file Windows will start.
export const EXECUTABLE_EXTENSIONS = new Set([
  '.exe', '.dll', '.scr', '.bat', '.cmd', '.vbs', '.vbe', '.jse', '.hta', '.lnk',
  '.ps1', '.msi', '.jar', '.com', '.pif', '.wsf', '.sh', '.elf', '.so',
]);

export const PHP_EXTENSIONS = new Set([
  '.php', '.php3', '.php4', '.php5', '.php7', '.php8', '.phtml', '.pht', '.phar', '.inc',
]);

// Extensions behind which neither a program nor PHP has any business. Wider than "media":
// text formats are here too, because a web server hands them out without running them.
export const PASSIVE_EXTENSIONS = new Set([
  '.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg', '.ico', '.bmp', '.avif',
  '.woff', '.woff2', '.ttf', '.otf', '.eot', '.mp4', '.mp3', '.pdf', '.css',
  '.txt', '.json', '.xml', '.md', '.mo', '.po', '.pot', '.html', '.map',
]);

// The text formats among them. A plugin ships documentation with PHP examples in such files
// (14 .md, 3 .txt and 2 .html among the 30 plugins of the test copy, most in composer
// libraries), and a text file runs only when code includes it. So PHP inside one is red in
// uploads and amber in a folder of code; inside a picture, a font, a film or a PDF it is red
// everywhere.
export const TEXT_FILE_EXTENSIONS = new Set(['.css', '.txt', '.json', '.xml', '.md', '.mo', '.po', '.pot', '.html', '.map']);

// Scripts that developers ship beside their code (build and release helpers, composer's
// vendor/bin). Nothing runs them unless a person does.
export const SCRIPT_EXTENSIONS = new Set(['.sh', '.bat', '.cmd', '.ps1']);

// Scripts the web server runs by itself when their address is opened, with no .htaccess
// needed. XAMPP 8.2.12's httpd.conf has "AddHandler cgi-script .cgi .pl .asp" and
// "AddOutputFilter INCLUDES .shtml", with ExecCGI and Includes allowed in its web folder (read
// 2026-11-14). The test copies hold one such file, a Perl script UpdraftPlus ships.
export const SERVER_SCRIPT_EXTENSIONS = new Set(['.cgi', '.pl', '.asp', '.shtml']);

// PHP reads its open tag in any letter case, so "<?PHP" counts like "<?php".
export const holdsPhpOpenTag = (bytes) => {
  const LESS_THAN = 0x3c;
  const QUESTION_MARK = 0x3f;
  const TO_LOWER_CASE = 0x20;
  for (let at = bytes.indexOf(LESS_THAN); at >= 0; at = bytes.indexOf(LESS_THAN, at + 1)) {
    const isTag = bytes[at + 1] === QUESTION_MARK
      && (bytes[at + 2] | TO_LOWER_CASE) === 0x70 && (bytes[at + 3] | TO_LOWER_CASE) === 0x68 && (bytes[at + 4] | TO_LOWER_CASE) === 0x70;
    if (isTag) return true;
  }
  return false;
};

// An archive named like one of these has no honest reason to exist.
const ARCHIVE_NEVER_EXTENSIONS = new Set([
  '.jpg', '.jpeg', '.png', '.gif', '.webp', '.avif', '.bmp', '.ico',
  '.woff', '.woff2', '.ttf', '.otf', '.eot',
  '.mp3', '.mp4', '.wav', '.ogg', '.webm', '.mov', '.pdf',
]);

// Extensions that say "container" out loud, office documents included (they are zips).
const CONTAINER_EXTENSIONS = new Set([
  '.zip', '.gz', '.tgz', '.7z', '.rar', '.bz2', '.xz', '.zst', '.tar', '.cab', '.jar',
  '.phar', '.wpress', '.svgz', '.docx', '.xlsx', '.pptx', '.odt', '.ods', '.epub',
]);

export const NO_EXTENSION = '(none)';

// Two extensions in one name, read from the name Windows would write:
//   php_first   - "photo.php.jpg": Apache configured with AddHandler runs it as PHP whatever
//                 comes last, and there is no honest reason to name a script like that (0 in
//                 the test copies)
//   image_first - "photo.jpg.php": PHP made to look like an image to a person; core's getID3
//                 ships module.audio.mp3.php, so audio and video names are left out
// null for any other name.
export const doubleExtensionKind = (logicalName) => {
  const base = stripTrailingDotsAndSpaces(logicalName).toLowerCase().split('/').pop();
  const parts = base.split('.');
  if (parts.length < 3) return null;
  const [before, last] = parts.slice(-2).map((part) => `.${part}`);
  if (PHP_EXTENSIONS.has(before) && ARCHIVE_NEVER_EXTENSIONS.has(last)) return 'php_first';
  if (IMAGE_EXTENSIONS.has(before) && PHP_EXTENSIONS.has(last)) return 'image_first';
  return null;
};

// Windows drops trailing dots and spaces when it creates a file, so "x.php." lands on disk
// as "x.php". The extension is taken from the name Windows would write.
export const extensionOf = (name) => {
  const lower = stripTrailingDotsAndSpaces(name).toLowerCase();
  const dot = lower.lastIndexOf('.');
  return dot > lower.lastIndexOf('/') ? lower.slice(dot) : NO_EXTENSION;
};

// A loop from the end, not /[. ]+$/: the regex retries from every dot of a long run that does not
// end the name, and a 65,535-byte name of dots took over a second.
export const stripTrailingDotsAndSpaces = (name) => {
  let end = name.length;
  while (end > 0 && (name[end - 1] === '.' || name[end - 1] === ' ')) end -= 1;
  return name.slice(0, end);
};

export const executableKind = (head) => kindOf(head, EXECUTABLE_SIGNATURES);

export const archiveKind = (head, extension) => (
  kindOf(head, ARCHIVE_SIGNATURES) ?? ARCHIVE_KIND_BY_EXTENSION.get(extension) ?? null
);

export const startsLikeAnImage = (head) => kindOf(head, IMAGE_SIGNATURES) !== null;

// A program header that can be believed anywhere, not only at the start of a file named like a
// program. "MZ" alone are two letters that any data holds once in 64 KB, so a Windows program
// counts when the field at byte 60 of its header leads to "PE\0\0", the way Windows itself
// checks it. A Linux program has seven fixed bytes: the magic number, 32 or 64 bit, byte
// order, version 1.
const DOS_HEADER_BYTES = 0x40;
const PE_OFFSET_FIELD = 0x3c;
// The PE header may overlap the DOS header, but not its first four bytes.
const PE_OFFSET_MIN = 4;
const PE_SIGNATURE = [0x50, 0x45, 0x00, 0x00];
const ELF_IDENT_BYTES = 7;

export const PROGRAM_HEADER_REACH = DOS_HEADER_BYTES;
export const PE_SIGNATURE_BYTES = PE_SIGNATURE.length;

// Where the "PE\0\0" of a Windows program starting at `at` has to stand, counted from `at`; null
// when no program header starts there. The caller needs PROGRAM_HEADER_REACH bytes from `at`.
export const peSignatureDistance = (bytes, at) => {
  if (bytes[at] !== 0x4d || bytes[at + 1] !== 0x5a || at + DOS_HEADER_BYTES > bytes.length) return null;
  const field = at + PE_OFFSET_FIELD;
  const distance = (bytes[field] | (bytes[field + 1] << 8) | (bytes[field + 2] << 16) | (bytes[field + 3] << 24)) >>> 0;
  return distance < PE_OFFSET_MIN ? null : distance;
};

export const holdsPeSignature = (bytes, at) => (
  at + PE_SIGNATURE.length <= bytes.length && PE_SIGNATURE.every((byte, offset) => bytes[at + offset] === byte)
);

export const holdsElfHeader = (bytes, at) => (
  at + ELF_IDENT_BYTES <= bytes.length
  && bytes[at] === 0x7f && bytes[at + 1] === 0x45 && bytes[at + 2] === 0x4c && bytes[at + 3] === 0x46
  && (bytes[at + 4] === 1 || bytes[at + 4] === 2) && (bytes[at + 5] === 1 || bytes[at + 5] === 2) && bytes[at + 6] === 1
);

// The kind of program these bytes begin with, by the strict reading above, or null.
export const programHeaderKind = (bytes) => {
  if (holdsElfHeader(bytes, 0)) return 'linux_program';
  const distance = peSignatureDistance(bytes, 0);
  return distance !== null && holdsPeSignature(bytes, distance) ? 'windows_program' : null;
};

export const isZipKind = (kind) => kind === 'zip' || kind === 'zip_empty' || kind === 'zip_spanned';

// 'never' = an archive must not carry this name, 'container' = the name announces an archive,
// 'other' = everything else, text formats included.
export const archiveNameClass = (extension) => {
  if (ARCHIVE_NEVER_EXTENSIONS.has(extension)) return 'never';
  return CONTAINER_EXTENSIONS.has(extension) ? 'container' : 'other';
};

const kindOf = (head, signatures) => {
  const match = signatures.find((signature) => startsWithAt(head, signature));
  return match ? match.kind : null;
};

const startsWithAt = (head, { offset, bytes }) => (
  head.length >= offset + bytes.length && bytes.every((byte, at) => head[offset + at] === byte)
);
