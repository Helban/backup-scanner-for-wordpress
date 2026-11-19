// SPDX-License-Identifier: GPL-3.0-or-later
//
// The server and PHP settings a copy carries with it. Apache (XAMPP) reads every
// .htaccess, PHP under FastCGI (LocalWP) reads .user.ini, and both can make code run that no
// mu-plugin names: a file prepended to every request, or images handed to PHP. Worker side only.
//
// Signals:
//   prepend_unusual - auto_prepend_file or auto_append_file pointing into uploads, at a file
//                     that is not PHP, or at a stream wrapper or address
//   prepend         - auto_prepend_file or auto_append_file at an ordinary PHP file (Wordfence's
//                     firewall is set up exactly like this)
//   php_handler     - a PHP handler given to extensions that are not PHP, or to every file of a
//                     folder
//   redirect        - a redirect to a host that is not the site's own
//   cgi_handler     - files handed to the server to run as programs (CGI), in a file that does
//                     not switch ExecCGI off
//   ssi             - server-side includes switched on, in a file that does not switch their
//                     commands off
// XAMPP 8.2.12 allows both in its web folder by default (httpd.conf: "Options Indexes
// FollowSymLinks Includes ExecCGI", "AllowOverride All", mod_cgi and mod_include loaded), and
// Apache 2.4 with those options ran a .gif shell script and an <!--#exec --> in .html from
// nothing but an .htaccess line (measured 2026-11-14). No .htaccess, .user.ini or
// php.ini of the test copies (154 files) mentions CGI or server-side includes at all.
//
// The text is read one line at a time and every line is cut to LINE_LIMIT characters before a
// regular expression sees it, so no line can make an expression run long.

import { PHP_EXTENSIONS } from './signatures.js';

const LINE_LIMIT = 4096;
export const CONFIG_FILE_NAMES = new Set(['.htaccess', '.user.ini', 'php.ini']);

const PREPEND_SETTINGS = new Set(['auto_prepend_file', 'auto_append_file']);
const COMMENT_LINE = /^\s*[#;]/;
const INI_SETTING = /^\s*([a-z_.]+)\s*=\s*(.*)$/i;
const APACHE_PHP_SETTING = /^\s*php_(?:admin_)?value\s+([a-z_.]+)\s+(.*)$/i;
const HANDLER_DIRECTIVE = /^\s*(addhandler|addtype|sethandler|forcetype)\s+(.*)$/i;
const REDIRECT_DIRECTIVE = /^\s*(redirect|redirectmatch|redirectpermanent|redirecttemp|rewriterule)\s+(.*)$/i;
const SECTION_OPEN = /^\s*<(files|filesmatch)\s+(.*)>\s*$/i;
const SECTION_CLOSE = /^\s*<\/(files|filesmatch)\s*>\s*$/i;
const ANY_SECTION_OPEN = /^\s*<[a-z]/i;
const ANY_SECTION_CLOSE = /^\s*<\//;
const ADDRESS = /^["']?https?:\/\/([^/"'\s?#]+)/i;
// A handler name that runs PHP: mod_php, cPanel's ea-php, LiteSpeed, php-fpm through a proxy.
// "-source" handlers print the source instead of running it.
const PHP_HANDLER = /php|proxy:fcgi|proxy:unix|lsapi/i;
const SOURCE_HANDLER = /source/i;
const REMOTE_TARGET = /^(?:[a-z][a-z0-9+.-]*:\/\/|data:)/i;
const OPTIONS_DIRECTIVE = /^\s*options\s+(.*)$/i;
const OUTPUT_FILTER_DIRECTIVE = /^\s*(addoutputfilter|setoutputfilter|addoutputfilterbytype)\s+(.*)$/i;
const XBITHACK = /^\s*xbithack\s+(?:on|full)\b/i;
const CGI_HANDLER = 'cgi-script';
const SSI_HANDLERS = new Set(['server-parsed', 'text/x-server-parsed-html']);
const SSI_FILTER = 'includes';

// Both return Map(signal -> { what, line }), the first place each signal shows up.
// An .htaccess, read by Apache. `siteHosts` are the host names the database gives for the
// site (empty when unknown).
export const findApacheSignals = (text, siteHosts) => {
  const { found, note } = createFindings();
  // Inside <Files> or <FilesMatch>: the pattern that limits the directives to some files.
  let section = null;
  // What the file asks the server to run, and whether its Options let it. XAMPP's defaults
  // let both, so they start switched on. `...InSection`: some section switches it on again.
  const runners = { cgi: null, ssi: null, execCgi: true, commandsInIncludes: true, execCgiInSection: false, commandsInSection: false };
  // How many sections of any kind (<Files>, <IfModule>, <If>...) are open.
  let openSections = 0;
  for (const { line, number } of joinContinuedLines(splitLines(text))) {
    if (COMMENT_LINE.test(line)) continue;
    readSetting(APACHE_PHP_SETTING.exec(line), number, note);
    const opened = SECTION_OPEN.exec(line);
    if (opened) section = opened[2];
    if (SECTION_CLOSE.test(line)) section = null;
    const handler = HANDLER_DIRECTIVE.exec(line);
    if (handler) {
      const directive = directiveOf(handler, number);
      readHandler(directive, section, note);
      readRunnerHandler(directive, runners);
    }
    const filter = OUTPUT_FILTER_DIRECTIVE.exec(line);
    if (filter) readOutputFilter(directiveOf(filter, number), runners);
    if (XBITHACK.test(line)) runners.ssi ??= { what: '*', line: number };
    if (ANY_SECTION_CLOSE.test(line)) openSections = Math.max(0, openSections - 1);
    else if (ANY_SECTION_OPEN.test(line)) openSections += 1;
    const options = OPTIONS_DIRECTIVE.exec(line);
    if (options) {
      const readSwitches = openSections > 0 ? readOptionsInSection : readOptions;
      readSwitches(words(options[1]), runners);
    }
    const redirect = REDIRECT_DIRECTIVE.exec(line);
    if (redirect) readRedirect(directiveOf(redirect, number), siteHosts, note);
  }
  if (runners.cgi && (runners.execCgi || runners.execCgiInSection)) note('cgi_handler', runners.cgi.what, runners.cgi.line);
  if (runners.ssi && (runners.commandsInIncludes || runners.commandsInSection)) note('ssi', runners.ssi.what, runners.ssi.line);
  return found;
};

// A .user.ini or php.ini, read by PHP alone: only the prepend settings apply.
export const findIniSignals = (text) => {
  const { found, note } = createFindings();
  for (const { line, number } of cutLines(splitLines(text))) {
    if (COMMENT_LINE.test(line)) continue;
    readSetting(INI_SETTING.exec(line), number, note);
  }
  return found;
};

const createFindings = () => {
  const found = new Map();
  const note = (signal, what, line) => {
    if (!found.has(signal)) found.set(signal, { what, line });
  };
  return { found, note };
};

const splitLines = (text) => text.split(/\r\n|\r|\n/);

// One directive of the file: its name in lower case, its words, and the line it starts on.
const directiveOf = (match, line) => ({ name: match[1].toLowerCase(), args: words(match[2]), line });

// A setting in either syntax (`php_value auto_prepend_file x`, `auto_prepend_file = x`).
const readSetting = (setting, line, note) => {
  if (setting && PREPEND_SETTINGS.has(setting[1].toLowerCase())) readPrepend(setting[2], line, note);
};

// `AddHandler cgi-script .gif`, `SetHandler cgi-script`, `AddHandler server-parsed .html`.
const readRunnerHandler = ({ args: [handlerName, ...extensions], line }, runners) => {
  const name = (handlerName ?? '').toLowerCase();
  const what = extensions.length > 0 ? asExtension(extensions[0]) : '*';
  if (name === CGI_HANDLER) runners.cgi ??= { what, line };
  if (SSI_HANDLERS.has(name)) runners.ssi ??= { what, line };
};

// `AddOutputFilter INCLUDES .html`, `SetOutputFilter INCLUDES`, filters chained with ";".
const readOutputFilter = ({ name, args: [filters, ...targets], line }, runners) => {
  if (filters === undefined || !filters.toLowerCase().split(';').includes(SSI_FILTER)) return;
  const what = name === 'addoutputfilter' && targets.length > 0 ? asExtension(targets[0]) : '*';
  runners.ssi ??= { what, line };
};

// With + and - an Options line changes what the folder inherits; without them it replaces it,
// and "All" holds both ExecCGI and Includes. IncludesNOEXEC allows includes without commands.
//
// Only a line outside every section switches something off for the folder. Inside a section it
// covers what the section covers, and that may be nothing: Apache 2.4.71 ran the .gif with
// `Options -ExecCGI` wrapped in <IfModule mod_nonexistent.c> or in <Files decoy.txt>, and with
// a switch-off at the top that <Files "*.gif"> switched on again (measured 2026-11-14). So a
// section can only switch on here. The shape Wordfence writes into uploads (handler and
// `Options -ExecCGI` both outside any section) gave 403 in the same run and stays silent.
const readOptions = (optionWords, runners) => {
  const change = optionChange(optionWords);
  if (change.execCgi !== null) runners.execCgi = change.execCgi;
  if (change.commandsInIncludes !== null) runners.commandsInIncludes = change.commandsInIncludes;
};

const readOptionsInSection = (optionWords, runners) => {
  const change = optionChange(optionWords);
  runners.execCgiInSection ||= change.execCgi === true;
  runners.commandsInSection ||= change.commandsInIncludes === true;
};

// What one Options line sets: true or false, or null where it leaves the option alone.
const optionChange = (optionWords) => {
  const lower = optionWords.map((word) => word.toLowerCase());
  const change = { execCgi: null, commandsInIncludes: null };
  if (!lower.every((word) => word.startsWith('+') || word.startsWith('-'))) {
    change.execCgi = lower.includes('all') || lower.includes('execcgi');
    change.commandsInIncludes = lower.includes('all') || lower.includes('includes');
  }
  for (const word of lower) {
    const isOn = word.startsWith('+');
    const option = word.slice(1);
    if (!isOn && !word.startsWith('-')) continue;
    if (option === 'execcgi') change.execCgi = isOn;
    if (option === 'includes') change.commandsInIncludes = isOn;
    if (option === 'includesnoexec' && isOn) change.commandsInIncludes = false;
  }
  return change;
};

const cutLines = (lines) => lines.map((line, index) => ({ line: fitLine(line, LINE_LIMIT), number: index + 1 }));

// Apache and PHP skip any run of blanks between words, so a line that does not fit has its runs
// folded before it is cut. Otherwise 5,000 spaces in front of a directive, or between a setting
// and its value, pushed it past the cut and the line said nothing (found 2026-11-15).
const fitLine = (line, room) => (line.length > room ? line.replace(/\s+/g, ' ') : line).slice(0, room);

// Apache reads a line that ends in a backslash together with the next one: `php_value \`, a
// line break and `auto_prepend_file "pre.jpg"` prepends the file (measured on
// 2026-11-13 in the wordpress:php8.4-apache image). Apache 2.4.71 joins a comment line that
// ends in a backslash too, and the next line is then part of the comment (measured
// 2026-11-14). Here a comment is not joined: other servers read .htaccess with a parser of
// their own, and naming a directive that Apache skips costs less than missing one that another
// server obeys. None of the 154 .htaccess files of the test copies has such a comment.
// `number` is the first line of the joined ones.
const joinContinuedLines = (lines) => {
  const joined = [];
  let pieces = [];
  let length = 0;
  let first = 0;
  for (const [index, line] of lines.entries()) {
    if (pieces.length === 0) first = index;
    const continues = line.endsWith('\\') && !(pieces.length === 0 && /^\s*#/.test(line.slice(0, LINE_LIMIT)));
    const piece = fitLine(continues ? line.slice(0, -1) : line, Math.max(0, LINE_LIMIT - length));
    pieces.push(piece);
    length += piece.length;
    if (continues) continue;
    joined.push({ line: pieces.join(''), number: first + 1 });
    pieces = [];
    length = 0;
  }
  if (pieces.length > 0) joined.push({ line: pieces.join(''), number: first + 1 });
  return joined;
};

const readPrepend = (rawValue, line, note) => {
  // One blank before the ";" is enough to find it; `\s+;` tried every start in a long run.
  const target = unquote(rawValue.trim().split(/\s;/)[0]).trim();
  if (target === '' || target.toLowerCase() === 'none') return;
  const lower = target.toLowerCase().replaceAll('\\', '/');
  const extension = lower.includes('.') ? lower.slice(lower.lastIndexOf('.')) : '';
  const isUnusual = lower.includes('/uploads/') || lower.startsWith('uploads/') || REMOTE_TARGET.test(lower)
    || !PHP_EXTENSIONS.has(extension);
  note(isUnusual ? 'prepend_unusual' : 'prepend', target, line);
};

// AddHandler and AddType name the extensions they apply to; SetHandler and ForceType apply to
// every file in reach, unless a <Files> section narrows them to PHP names.
const readHandler = ({ name, args, line }, section, note) => {
  const [handlerName, ...extensions] = args;
  // "SetHandler none" and "default-handler" name no PHP handler, so they end here too.
  if (handlerName === undefined || !PHP_HANDLER.test(handlerName) || SOURCE_HANDLER.test(handlerName)) return;
  if (name === 'addhandler' || name === 'addtype') {
    const other = extensions.map(asExtension).find((extension) => !PHP_EXTENSIONS.has(extension));
    if (other !== undefined) note('php_handler', other, line);
    return;
  }
  if (section === null || !namesOnlyPhp(section)) note('php_handler', section === null ? '*' : unquote(section), line);
};

const readRedirect = ({ args, line }, siteHosts, note) => {
  // RewriteRule pattern target [flags], Redirect [status] path target, RedirectMatch [status] regex target.
  for (const argument of args) {
    const address = ADDRESS.exec(argument);
    if (!address) continue;
    const host = address[1].toLowerCase();
    if (host.includes('%{') || host.includes('$')) continue;
    if (!siteHosts.has(withoutWww(host.replace(/:\d+$/, '')))) note('redirect', host, line);
  }
};

export const withoutWww = (host) => (host.startsWith('www.') ? host.slice(4) : host);

// "\.(php4|php3|php2|php|phtml)$" (the shape hosting panels write) or "*.php": every word of
// the pattern is a PHP extension. A pattern that names anything else, an image above all, is
// exactly what this check is about.
const PHP_PATTERN_WORD = /^ph(?:p\d*|tml|ar|t|ps)$/;

const namesOnlyPhp = (pattern) => {
  const names = pattern.toLowerCase().match(/[a-z0-9]+/g) ?? [];
  return names.length > 0 && names.every((name) => PHP_PATTERN_WORD.test(name));
};

const asExtension = (word) => {
  const lower = word.toLowerCase();
  return lower.startsWith('.') ? lower : `.${lower}`;
};

const words = (text) => text.trim().split(/\s+/).filter((word) => word !== '');

const unquote = (text) => text.replace(/^["']|["']$/g, '');
