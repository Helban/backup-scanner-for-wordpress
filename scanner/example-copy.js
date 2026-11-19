// SPDX-License-Identifier: GPL-3.0-or-later
//
// The copy behind the "show me on an example" button. It is put together in the visitor's
// browser, from the harmless bytes below, and then scanned like any dropped file: nothing
// about its result is prepared. It has the shape of the fake backup this scanner was written
// after (a "photo" that starts like a Windows program, a mu-plugin that would rename and start
// it), under the file names of that attack. Nothing in it can run: the "program" is two
// letters and zeros, and the PHP is text that no PHP ever sees.
//
// No server holds this archive, and no file with a program header lies on the site.

import { crc32 } from './crc32.js';

const ROOT = 'site-copy/';
const UPLOADS = `${ROOT}wp-content/uploads/2026/11/`;
const PROGRAM_HEAD = [0x4d, 0x5a, 0x90, 0x00];
const JPEG_HEAD = [0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00];
const PADDED_BYTES = 2048;

const LOADER = `<?php
/**
 * Plugin Name: Custom Fields Handler
 * Description: Part of the built-in example of Backup Scanner for WordPress. It copies the shape of the loader found in a fake backup in November 2026 and never runs.
 */
$photo   = WP_CONTENT_DIR . '/uploads/2026/11/product-detail-mockup-soft-blue-background.jpeg';
$program = WP_CONTENT_DIR . '/uploads/2026/11/product-detail-mockup-soft-blue-background.exe';
if ( file_exists( $photo ) && rename( $photo, $program ) ) {
	@exec( '"' . $program . '"', $output, $code );
}
`;

const SITE_CONFIG = `<?php
define( 'DB_NAME', 'example' );
define( 'DB_USER', 'example' );
$table_prefix = 'wp_';
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}
require_once ABSPATH . 'wp-settings.php';
`;

// A real plugin of wordpress.org with one line changed, so the comparison has something to find.
const CHANGED_PLUGIN = `<?php
/**
 * Plugin Name: Hello Dolly
 * Version: 1.7.2
 */
// The example changed this file: the release on wordpress.org reads differently.
add_action( 'admin_notices', 'hello_dolly' );
`;

// Quotes escaped the way mysqldump writes them. The second plugin has no folder in the copy.
const DATABASE = `INSERT INTO \`wp_options\` VALUES (1,'siteurl','https://example.com','yes'),(2,'home','https://example.com','yes'),(3,'active_plugins','a:2:{i:0;s:21:\\"hello-dolly/hello.php\\";i:1;s:35:\\"insert-headers-and-footers/ihaf.php\\";}','yes');
`;

const padded = (head) => {
  const bytes = new Uint8Array(PADDED_BYTES);
  bytes.set(head);
  return bytes;
};

const exampleFiles = () => [
  [`${ROOT}wp-config.php`, SITE_CONFIG],
  [`${ROOT}wp-content/mu-plugins/custom-fields-handler.php`, LOADER],
  [`${ROOT}wp-content/plugins/hello-dolly/hello.php`, CHANGED_PLUGIN],
  [`${UPLOADS}product-detail-mockup-soft-blue-background.jpeg`, padded(PROGRAM_HEAD)],
  [`${UPLOADS}team-photo.jpeg`, padded(JPEG_HEAD)],
  [`${ROOT}database.sql`, DATABASE],
];

export const buildExampleCopy = (fileName) => new File([zipOf(exampleFiles())], fileName, { type: 'application/zip' });

// A zip of stored (unpacked) files: headers of fixed layout around the data, then the table of
// contents, then the end record. APPNOTE.TXT sections 4.3.7, 4.3.12 and 4.3.16.
const VERSION_NEEDED = 20;
const FLAG_UTF8_NAMES = 0x0800;
const METHOD_STORED = 0;
// 2026-11-01 00:00 in the two-word DOS format; the files have no real time of their own.
const DOS_TIME = 0;
const DOS_DATE = ((2026 - 1980) << 9) | (11 << 5) | 1;
const LOCAL_SIGNATURE = 0x04034b50;
const CENTRAL_SIGNATURE = 0x02014b50;
const END_SIGNATURE = 0x06054b50;

const zipOf = (files) => {
  const encoder = new TextEncoder();
  const parts = [];
  const table = [];
  let offset = 0;
  for (const [path, content] of files) {
    const name = encoder.encode(path);
    const body = typeof content === 'string' ? encoder.encode(content) : content;
    const shared = [VERSION_NEEDED, FLAG_UTF8_NAMES, METHOD_STORED, DOS_TIME, DOS_DATE];
    const sizes = [crc32(body), body.length, body.length];
    const local = record([[4, LOCAL_SIGNATURE], ...words(shared), ...longs(sizes), [2, name.length], [2, 0]]);
    table.push(record([
      [4, CENTRAL_SIGNATURE], [2, VERSION_NEEDED], ...words(shared), ...longs(sizes), [2, name.length],
      [2, 0], [2, 0], [2, 0], [2, 0], [4, 0], [4, offset],
    ]), name);
    parts.push(local, name, body);
    offset += local.length + name.length + body.length;
  }
  const tableBytes = table.reduce((total, part) => total + part.length, 0);
  const end = record([[4, END_SIGNATURE], [2, 0], [2, 0], [2, files.length], [2, files.length], [4, tableBytes], [4, offset], [2, 0]]);
  return new Blob([...parts, ...table, end]);
};

const words = (numbers) => numbers.map((number) => [2, number]);
const longs = (numbers) => numbers.map((number) => [4, number]);

// Little-endian fields, given as [width in bytes, number].
const record = (fields) => {
  const bytes = new Uint8Array(fields.reduce((total, [width]) => total + width, 0));
  const view = new DataView(bytes.buffer);
  let at = 0;
  for (const [width, number] of fields) {
    if (width === 2) view.setUint16(at, number, true);
    else view.setUint32(at, number, true);
    at += width;
  }
  return bytes;
};
