// SPDX-License-Identifier: GPL-3.0-or-later
//
// The English sentences. messages.js picks between this file and messages-pl.js.

const PROGRAM_KINDS = new Map([
  ['windows_program', 'a Windows program'],
  ['linux_program', 'a Linux program'],
  ['script', 'a script with a "#!" line'],
  ['java_or_macos_program', 'a Java class or macOS program'],
  ['macos_program', 'a macOS program'],
  ['windows_shortcut', 'a Windows shortcut'],
]);

// The article goes with the name because it follows the sound: "an xz archive".
const ARCHIVE_KINDS = new Map([
  ['zip', 'a zip archive'], ['zip_empty', 'an empty zip archive'], ['zip_spanned', 'a multi-part zip archive'],
  ['sevenzip', 'a 7z archive'], ['rar', 'a RAR archive'], ['gzip', 'a gzip archive'], ['bzip2', 'a bzip2 archive'],
  ['xz', 'an xz archive'], ['zstd', 'a zstd archive'], ['cab', 'a cab archive'], ['tar', 'a tar archive'],
  ['wpress', 'a .wpress archive'], ['phar', 'a phar archive'],
]);
const UNKNOWN_ARCHIVE = 'a packed archive';

const sentenceStart = (phrase) => phrase[0].toUpperCase() + phrase.slice(1);

const HEADER_FIELDS = new Map([
  ['name', 'name'], ['method', 'compression'], ['encryption', 'encryption'],
  ['size', 'size'], ['checksum', 'checksum'],
]);

const UNREADABLE_REASONS = new Map([
  ['zip64', 'its size fields cannot be read'],
  ['other_disk', 'it points to another part of a multi-part archive'],
  ['out_of_bounds', 'its data would lie outside the archive'],
  ['no_local_header', 'there is no file header where the table of contents points'],
]);

const CORRUPT_REASONS = new Map([
  ['stream', 'the packed data is damaged'],
  ['size', 'the unpacked size differs from the one in the table of contents'],
  ['checksum', 'the checksum does not match'],
  ['whole', 'it could not be unpacked whole for the comparison with wordpress.org'],
  ['code', 'it could not be unpacked whole to read its code'],
  ['config', 'it could not be unpacked whole to read its server settings'],
  ['indicator', 'it could not be unpacked whole to compare it with files from known attacks'],
  ['database', 'the database dump could not be unpacked to its end, so only the part before the damage was checked'],
]);

// Campaigns of indicators.js, by id.
const CAMPAIGN_TEXT = new Map([
  ['fake_backup_2026_11', 'the fake WordPress backup sent to freelancers in November 2026 (a password stealer posing as a JPEG)'],
]);
// What a listed file was in its campaign (the `role` of indicators.js).
const KNOWN_FILE_ROLES = new Map([
  ['payload', 'a file from a known attack'],
  ['archive', 'the archive from a publicly described attack'],
]);
const knownFile = (params) => (
  `${KNOWN_FILE_ROLES.get(params.get('role')) ?? 'a file from a known attack'}: ${CAMPAIGN_TEXT.get(params.get('campaign')) ?? 'a published campaign'}`
);

// How the code rules name what they found (php-rules.js). A plain function name is shown as
// a call, an extension as a file name.
const MECHANISMS = new Map([
  ['backtick', 'a command in backticks'],
  ['new_com', 'new COM'],
  ['new_dotnet', 'new DOTNET'],
  ['ffi', 'FFI, which calls native functions'],
  ['putenv_loader', 'putenv() with a library loader variable'],
  ['wscript.shell', 'the WScript.Shell object'],
  ['shell.application', 'the Shell.Application object'],
  ['expect://', 'the expect:// wrapper'],
  ['variable_call', 'a call through a variable'],
  ['expression_call', 'a call of what another expression returns'],
]);

const mechanism = (params) => {
  const what = String(params.get('what') ?? '');
  if (MECHANISMS.has(what)) return MECHANISMS.get(what);
  return what.startsWith('.') ? `a ${what} file name` : `${what}()`;
};

const onLine = (params) => `line ${formatCount(params.get('line') ?? 0)}`;

// The file an include names, by its extension (php-rules.js includedExtension).
const includedFile = (params) => {
  const extension = String(params.get('what') ?? '');
  return extension.startsWith('.') ? `a file ending in ${extension}` : 'a file with no extension';
};

// What a decoded string turned out to hold (php-rules.js hiddenCodeIn).
const hiddenText = (params) => {
  const what = String(params.get('what') ?? '');
  return what === 'base64' ? 'a long base64 text that decodes to PHP code' : `text that reads "${what}" only once decoded`;
};

const ALWAYS_LOADED = 'Code that WordPress loads by itself';
// What that code is, in the log and in the summary.
const LOADED_SOURCES = '(wp-config.php, .maintenance, mu-plugins, drop-ins, language files)';

// Where loose PHP lies (the `place` of layout.php_outside_code_folders): one file, many files.
const LOOSE_PLACE_TEXT = new Map([
  ['content', ['lying directly in wp-content is not a drop-in', 'lying directly in wp-content are not drop-ins']],
  ['languages', ['in wp-content/languages is not a translation file', 'in wp-content/languages are not translation files']],
  ['site', ['lies directly in a folder with a wp-content but no wp-includes', 'lie directly in a folder with a wp-content but no wp-includes']],
]);
const LOOSE_FOLDER_TEXT = ['in a folder WordPress does not load code from', 'in a folder WordPress does not load code from'];

// A program or an archive kept in PHP as base64 or other encoded text (php-rules.js packedFileIn).
const packedProgram = (params) => `${PROGRAM_KINDS.get(params.get('what')) ?? 'a program'} written as encoded text (${onLine(params)}).`;
const packedArchive = (params) => `${ARCHIVE_KINDS.get(params.get('what')) ?? UNKNOWN_ARCHIVE} written as encoded text (${onLine(params)}).`;
const PACKED_PROGRAM_NOTE = 'Decoded and saved, it is a program that no file in the copy shows.';
const PACKED_ARCHIVE_NOTE = 'What it unpacks to is in no file of the copy, so this scanner did not see it.';

// Why the files of the core or of a plugin were not compared with wordpress.org.
const NOT_COMPARED_REASONS = new Map([
  ['no_version', 'its version could not be read from the copy'],
  ['not_listed', 'wordpress.org does not list it, which is the case for premium and custom plugins'],
  // A browser cannot tell a 404 from downloads.wordpress.org (sent without CORS) from a dropped
  // connection; a run over the test copies on 2026-11-13 hit the second for four plugins whose lists exist.
  ['version_not_listed', 'wordpress.org lists it, but its checksums for this version did not come back (none are published, or the request failed)'],
  ['closed', 'wordpress.org has closed it and publishes no checksums for it'],
  ['network', 'wordpress.org could not be reached'],
  ['request_limit', 'the limit of 150 requests per scan was used up before it'],
  ['bad_answer', 'wordpress.org sent an answer this scanner could not use'],
]);

const COMPONENT_LABELS = new Map([['core', 'The WordPress core'], ['plugin', 'This plugin']]);

// wordpress.org answers a core release or language it does not know with no list. The reason
// above speaks of plugins, so the core gets its own words.
const CORE_NOT_LISTED = 'wordpress.org has no checksums for this version in this language';
const notComparedReason = (kind, reason) => (
  kind === 'core' && reason === 'not_listed' ? CORE_NOT_LISTED : NOT_COMPARED_REASONS.get(reason) ?? 'unknown reason'
);

const REQUEST_LABELS = new Map([
  ['core_checksums', (request) => `checksums of WordPress ${request.version} (${request.locale})`],
  ['plugin_checksums', (request) => `checksums of ${request.slug} ${request.version}`],
  ['plugin_info', (request) => `is ${request.slug} listed?`],
  ['core_vulnerabilities', (request) => `known vulnerabilities of WordPress ${request.version}`],
  ['plugin_vulnerabilities', (request) => `known vulnerabilities of the plugin ${request.slug} (name only)`],
  ['theme_vulnerabilities', (request) => `known vulnerabilities of the theme ${request.slug} (name only)`],
]);

// Why known vulnerabilities were not looked up (gateway.js advisory states).
const ADVISORY_REASONS = new Map([
  ['network', 'wpvulnerability.net or the wordpress.org plugin directory could not be reached'],
  ['unavailable', 'wpvulnerability.net answered that it is out of service'],
  ['request_limit', 'the limit of 150 requests per scan was used up earlier'],
  ['bad_answer', 'wpvulnerability.net or wordpress.org sent an answer this scanner could not use'],
]);

const BOUND_WORDS = new Map([['lt', 'before'], ['le', 'up to'], ['eq', 'exactly'], ['ne', 'other than'], ['gt', 'after'], ['ge', 'from']]);
const SOURCE_LABELS = new Map([
  ['www.cve.org', 'CVE.org'], ['www.wordfence.com', 'Wordfence'], ['patchstack.com', 'Patchstack'], ['wpscan.com', 'WPScan'],
]);
// The core's heading names it by version alone, so the core has no entry here.
const ADVISORY_KINDS = new Map([['plugin', 'plugin'], ['theme', 'theme']]);

// The component an advisory finding names as its example: "plugin tool", "WordPress 6.9.5".
const advisoryExample = (params) => {
  const name = params.get('example') ?? '';
  const kind = params.get('exampleKind');
  return kind === 'core' ? `WordPress ${name}` : `${ADVISORY_KINDS.get(kind) ?? ''} ${name}`.trim();
};

const NOT_OPENED_REASONS = new Map([
  ['format', 'This scanner opens zip archives only, so the contents were not checked.'],
  ['depth', 'It sits inside another archive, and only one level is opened.'],
  ['too_large', 'It unpacks to more than 64 MB, so it was not opened.'],
  ['too_many_entries', 'It lists more than 50,000 entries, so it was not opened.'],
  ['damaged', 'It starts like a zip but cannot be read as one.'],
  ['multi_part', 'It is one part of a multi-part zip, so it was not opened.'],
  ['time', 'Reading it took longer than 10 seconds, so the rest of it was not checked.'],
  // The three budget reasons also close a line about a group of archives, so they name none.
  ['budget_count', 'The copy holds more than 200 archives, and only the first 200 are opened.'],
  ['budget_size', 'The archives opened earlier used up the 512 MB allowed for unpacking.'],
  ['budget_time', 'The 60 seconds allowed for archives inside the copy ran out earlier.'],
]);

const numberFormat = new Intl.NumberFormat('en');

export const formatCount = (value) => numberFormat.format(value);

// "1 file", "2 files": the noun follows the count.
const withNoun = (count, one, many) => `${formatCount(count)} ${count === 1 ? one : many}`;

const formatBytes = (bytes) => {
  if (bytes < 1024) return `${formatCount(bytes)} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
};

const programKind = (params) => PROGRAM_KINDS.get(params.get('kind')) ?? 'a program';
const archiveKind = (params) => ARCHIVE_KINDS.get(params.get('kind')) ?? UNKNOWN_ARCHIVE;
const sizeOf = (params) => formatBytes(params.get('bytes') ?? 0);

// The limit the code reader ran into (loaded.code_not_read).
const CODE_LIMITS = new Map([
  ['bytes', 'that is more than the 8 MB this scanner reads as code'],
  ['tokens', 'it splits into more than a million pieces of code, more than this scanner reads'],
  ['nesting', 'it nests code inside strings more than 32 levels deep, deeper than this scanner follows'],
  ['time', 'reading it took longer than 2 seconds'],
]);
const codeLimit = (params) => CODE_LIMITS.get(params.get('reason')) ?? 'it ran into a limit of this scanner';

// What a server setting applies to: '*' for every file of the folder, else an extension.
const configTarget = (params) => (params.get('what') === '*' ? 'every file in this folder' : `files ending in ${params.get('what')}`);

const missingFiles = (params, release) => {
  const missing = params.get('missing') ?? 0;
  if (missing === 1) return `1 file of ${release} is missing: ${params.get('example')}.`;
  return `${formatCount(missing)} files of ${release} are missing, for example ${params.get('example')}.`;
};

const FINDING_TEXT = new Map([
  ['layout.path_traversal', () => 'The name points outside the folder the archive is unpacked into.'],
  ['layout.symlink', () => 'A symbolic link. Unpacked, it can point at any file on the computer.'],
  ['layout.executable_extension', (params) => `A file with a runnable extension (${params.get('extension')}).`],
  ['layout.disguised_executable', (params) => (
    `Starts like ${programKind(params)}, but is named ${params.get('extension')}. ${sizeOf(params)}.`
  )],
  ['layout.php_in_media', (params) => `PHP code inside a ${params.get('extension')} file.`],
  ['layout.php_in_text', (params) => (
    `PHP code inside a ${params.get('extension')} file that could not be compared with an official release. Documentation often holds such examples. A text file does not run by itself, only when code includes it, so read what it is.`
  )],
  ['layout.script_in_code_folder', (params) => (
    `A script (${params.get('extension')}) among code that could not be compared with an official release. Developers ship build scripts like this. Nothing starts it unless you do; read it before you would.`
  )],
  ['layout.server_script', (params) => (
    `A ${params.get('extension')} file. With XAMPP's default settings the web server does not hand such a file out, it runs it when its address is opened. WordPress itself ships none.`
  )],
  ['layout.server_script_in_code_folder', (params) => (
    `A ${params.get('extension')} file among code that could not be compared with an official release. With XAMPP's default settings the web server runs such a file when its address is opened. UpdraftPlus ships one, so read it before you take it for a trap.`
  )],
  ['layout.php_in_uploads', () =>'A PHP file in the uploads folder, where only media belong.'],
  ['layout.archive_as_media', (params) => (
    `${sentenceStart(archiveKind(params))} named ${params.get('extension')}. ${sizeOf(params)}.`
  )],
  ['layout.archive_behind_media', (params) => (
    `A ${params.get('extension')} file with a zip archive glued to its end. A viewer shows the file, an unzip tool unpacks the archive behind it. ${sizeOf(params)}.`
  )],
  ['layout.program_inside_media', (params) => (
    `A ${params.get('extension')} file with ${programKind(params)} inside it, starting at byte ${formatCount(params.get('offset') ?? 0)}. `
    + `Nothing runs it under this name, but code that copies those bytes into a new file gets a program that no file in the copy shows. ${sizeOf(params)}.`
  )],
  ['layout.inside_not_searched', (params) => (
    `A ${params.get('extension')} file of ${sizeOf(params)} with thousands of headers shaped like the start of a Windows program, each pointing further into the file. `
    + 'The search for a program inside it was stopped. Honest media do not look like this.'
  )],
  ['layout.archive_unexpected_extension', (params) => (
    `${sentenceStart(archiveKind(params))} behind the extension ${params.get('extension')}. ${sizeOf(params)}.`
  )],
  ['name.deceptive_characters', (params) => (
    `The name holds invisible or direction-changing characters (${params.get('codes')}), shown here as codes.`
  )],
  ['name.trailing_dot_or_space', () => (
    'The name ends with a dot or a space. Windows drops those, so the file lands under a different name.'
  )],
  ['layout.executable_in_archive', (params) => (
    `A file with a runnable extension (${params.get('extension')}) packed inside an archive.`
  )],
  ['layout.not_an_image', (params) => (
    `Named ${params.get('extension')}, but it does not start like any image format. ${sizeOf(params)}.`
  )],
  ['layout.php_named_as_media', () => (
    'The name carries a PHP extension before its last one. Apache set up with AddHandler runs such a file as PHP, whatever the last extension says.'
  )],
  ['layout.image_named_php', () => 'A PHP file named like an image. It runs as PHP; only the name looks like a picture.'],
  ['layout.php_outside_code_folders', (params) => {
    const phpFiles = params.get('phpFiles') ?? 0;
    // WordPress does load code from wp-content itself (the drop-ins), from its languages folder
    // (the translations) and from a site folder (its wp-config.php), so none is called a folder it
    // loads nothing from.
    const [one, many] = LOOSE_PLACE_TEXT.get(params.get('place')) ?? LOOSE_FOLDER_TEXT;
    if (phpFiles === 1) {
      return `1 PHP file ${one}: ${params.get('example')}. It runs only when something includes it or a request names it, so read what it is.`;
    }
    return `${formatCount(phpFiles)} PHP files ${many}, for example ${params.get('example')}. They run only when something includes them or a request names them, so read what they are.`;
  }],
  ['archive.not_opened', (params) => (
    `${params.get('kind') === 'zip_behind_media' ? 'The end of this file looks like a zip archive glued to it' : sentenceStart(archiveKind(params))}, ${sizeOf(params)}. ${NOT_OPENED_REASONS.get(params.get('reason')) ?? 'It was not opened.'}`
  )],
  ['archive.tail_not_checked', (params) => {
    const files = params.get('files') ?? 0;
    if (files === 1) {
      return `1 media file (${sizeOf(params)}) was not read through: the 60 seconds allowed for that ran out. A program inside it would not be seen, and if it is packed, neither would a zip glued behind it.`;
    }
    return `${formatCount(files)} media files, ${sizeOf(params)} in total, were not read through: the 60 seconds allowed for that ran out. A program inside one of them would not be seen, and in a packed one neither would a zip glued behind it.`;
  }],
  ['archive.not_opened_group', (params) => {
    const files = params.get('files') ?? 0;
    const group = files === 1
      ? `1 more archive named ${params.get('extension')} (${sizeOf(params)}).`
      : `${formatCount(files)} more archives named ${params.get('extension')}, ${sizeOf(params)} in total.`;
    return `${group} ${NOT_OPENED_REASONS.get(params.get('reason')) ?? 'Not opened.'}`;
  }],

  ['core.modified', () => 'Differs from the same file in the official WordPress release.'],
  ['core.extra_file', () => 'A file with PHP code in a WordPress core folder that the official release does not have.'],
  ['core.extra_other', () => (
    'A file in a WordPress core folder that the official release does not have. It holds no PHP code. Hosts leave logs here and security plugins add settings files, so read what it is.'
  )],
  ['core.extra_root_php', () => (
    'A PHP file in the root folder that is not part of WordPress. It runs only when something loads it, so read it.'
  )],
  ['core.missing_files', (params) => missingFiles(params, 'the official WordPress release')],
  ['plugin.modified', () => 'Differs from the same file in this plugin\'s release on wordpress.org.'],
  ['plugin.extra_php', () => 'PHP code in a file that this plugin\'s release on wordpress.org does not have.'],
  ['plugin.extra_file', () => 'A file that this plugin\'s release on wordpress.org does not have.'],
  ['plugin.missing_files', (params) => missingFiles(params, 'this plugin\'s release on wordpress.org')],
  ['component.not_compared', (params) => (
    `${COMPONENT_LABELS.get(params.get('kind')) ?? 'This part'} was not compared with wordpress.org: ${notComparedReason(params.get('kind'), params.get('reason'))}. Its files are judged as unknown code.`
  )],
  ['db.in_nested_archive', (params) => (
    `A database dump of ${sizeOf(params)} inside an archive in the copy. The database checks run only on dumps that lie in the copy itself, so this one was not read.`
  )],
  ['component.not_compared_past_limit', (params) => {
    const plugins = params.get('plugins') ?? 0;
    const which = plugins === 1
      ? `1 plugin after the first 300 was not compared with wordpress.org and not looked up for known vulnerabilities: ${params.get('example')}.`
      : `${formatCount(plugins)} plugins after the first 300 were not compared with wordpress.org and not looked up for known vulnerabilities, for example ${params.get('example')}.`;
    return `${which} One scan asks about 300 plugins at most. ${plugins === 1 ? 'Its' : 'Their'} files are judged as unknown code.`;
  }],
  ['lookup.off', (params) => (
    `Comparison with wordpress.org is switched off, so the core and ${withNoun(params.get('plugins') ?? 0, 'plugin', 'plugins')} were not compared, `
    + 'and no known vulnerabilities were looked up. Their files are judged as unknown code.'
  )],
  ['advisory.not_checked', (params) => {
    const components = params.get('components') ?? 0;
    const example = advisoryExample(params);
    if (params.get('reason') === 'closure_unknown') {
      // Only plugins can be closed, so the plugin's name is enough.
      const plugin = params.get('example') ?? '';
      return components === 1
        ? `The scanner could not ask wordpress.org whether it has closed the plugin ${plugin}. Its known vulnerabilities were looked up, but a closed plugin gets no more security fixes.`
        : `The scanner could not ask wordpress.org whether it has closed ${formatCount(components)} plugins, for example ${plugin}. `
          + 'Their known vulnerabilities were looked up, but a closed plugin gets no more security fixes.';
    }
    const where = components === 1 ? `1 component (${example})` : `${formatCount(components)} components, for example ${example}`;
    if (params.get('reason') === 'unreadable_entries') {
      const entries = params.get('entries') ?? 0;
      return `${withNoun(entries, 'entry', 'entries')} of the vulnerability database could not be matched with the version `
        + `in ${where}. Read ${entries === 1 ? 'it' : 'them'} at wpvulnerability.net.`;
    }
    return `Known vulnerabilities were not looked up for ${where}: `
      + `${ADVISORY_REASONS.get(params.get('reason')) ?? 'unknown reason'}. That is not the same as "none known".`;
  }],

  ['loaded.launch_call', (params) => (
    `${ALWAYS_LOADED} starts a program: ${mechanism(params)} on ${onLine(params)}.`
  )],
  ['loaded.launch_name_text', (params) => (
    `${ALWAYS_LOADED} holds the name of a program-starting function as text (${mechanism(params)}, ${onLine(params)}). That is how a call through a variable or a callback begins.`
  )],
  ['loaded.launch_name_composed', (params) => (
    `${ALWAYS_LOADED} puts the name of a program-starting function together from pieces (${mechanism(params)}, ${onLine(params)}).`
  )],
  ['loaded.dynamic_call', (params) => (
    `${ALWAYS_LOADED} calls a function whose name the file does not spell out (${mechanism(params)}, ${onLine(params)}). Read what it calls.`
  )],
  ['loaded.rename_executable', (params) => (
    `${ALWAYS_LOADED} renames or copies files and names a program (${mechanism(params)}). The first rename or copy is on ${onLine(params)}.`
  )],
  ['loaded.rename_uploads', (params) => (
    `${ALWAYS_LOADED} renames, copies or moves files and refers to the uploads folder (${onLine(params)}). Read what it moves.`
  )],
  ['loaded.include_uploads', (params) => (
    `${ALWAYS_LOADED} includes PHP files and refers to the uploads folder (${onLine(params)}). Read what it includes.`
  )],
  ['loaded.include_not_php', (params) => (
    `${ALWAYS_LOADED} includes ${includedFile(params)} as PHP on ${onLine(params)}. PHP runs the code in such a file `
    + 'whatever its name, and this scanner reads only files named like PHP as code, so read that file.'
  )],
  ['unproven.launch_rare', (params) => (
    `Starts a program in a way that the honest code measured for this scanner never used: ${mechanism(params)} on ${onLine(params)}.`
  )],
  ['unproven.launch_call', (params) => (
    `Can start a program: ${mechanism(params)} on ${onLine(params)}. Some honest plugins do this, so read what it runs.`
  )],
  ['unproven.launch_name_text', (params) => (
    `Holds the name of a program-starting function as text (${mechanism(params)}, ${onLine(params)}), the way an indirect call begins.`
  )],
  ['unproven.launch_name_composed', (params) => (
    `Puts the name of a program-starting function together from pieces (${mechanism(params)}, ${onLine(params)}).`
  )],
  ['unproven.rename_executable_call', (params) => (
    `Renames or copies a file to a program name (${mechanism(params)}) in a single call on ${onLine(params)}.`
  )],
  ['unproven.rename_executable', (params) => (
    `Renames or copies files and names a program or a way to start one (${mechanism(params)}). The first rename or copy is on ${onLine(params)}.`
  )],
  ['loaded.eval_decoded', (params) => (
    `${ALWAYS_LOADED} runs decoded text as PHP: ${mechanism(params)} with a decoding call inside, ${onLine(params)}.`
  )],
  ['loaded.encoded_code', (params) => `${ALWAYS_LOADED} holds ${hiddenText(params)}, ${onLine(params)}.`],
  ['loaded.encoded_program', (params) => `${ALWAYS_LOADED} holds ${packedProgram(params)} ${PACKED_PROGRAM_NOTE}`],
  ['loaded.encoded_archive', (params) => `${ALWAYS_LOADED} holds ${packedArchive(params)} ${PACKED_ARCHIVE_NOTE}`],
  ['unproven.encoded_program', (params) => (
    `Holds ${packedProgram(params)} ${PACKED_PROGRAM_NOTE} Honest code measured for this scanner never did this.`
  )],
  ['unproven.encoded_archive', (params) => `Holds ${packedArchive(params)} ${PACKED_ARCHIVE_NOTE} Read where the code puts it.`],
  ['loaded.halt_compiler_payload', (params) => (
    `${ALWAYS_LOADED} stops at __halt_compiler() and reads the data hidden behind it (${onLine(params)}).`
  )],
  ['loaded.decoder_chain', (params) => (
    `${ALWAYS_LOADED} decodes stored text twice in a row, ${params.get('what')}(…)), ${onLine(params)}. Packed code is usually hidden this way.`
  )],
  ['loaded.char_chain', (params) => (
    `${ALWAYS_LOADED} spells a string one character at a time with chr(), ${onLine(params)}.`
  )],
  ['loaded.eval_call', (params) => `${ALWAYS_LOADED} runs text as PHP: ${mechanism(params)} on ${onLine(params)}.`],
  ['loaded.variable_variable', (params) => (
    `${ALWAYS_LOADED} uses a variable whose name is computed ($$name), ${onLine(params)}. Read what it points at.`
  )],
  ['loaded.creates_admin', (params) => (
    `${ALWAYS_LOADED} writes a user with the administrator role: ${mechanism(params)} on ${onLine(params)}.`
  )],
  ['loaded.hides_plugins', (params) => (
    `${ALWAYS_LOADED} changes the list of plugins that wp-admin shows (the ${params.get('what')} filter, ${onLine(params)}). Read whether it hides one.`
  )],
  ['unproven.eval_decoded', (params) => (
    `Runs decoded text as PHP: ${mechanism(params)} with a decoding call inside, ${onLine(params)}. Honest code measured for this scanner never did this.`
  )],
  ['unproven.encoded_code', (params) => (
    `Holds ${hiddenText(params)}, ${onLine(params)}. Honest code measured for this scanner never did this.`
  )],
  ['unproven.halt_compiler_payload', (params) => (
    `Stops at __halt_compiler() and reads the data hidden behind it (${onLine(params)}).`
  )],
  ['unproven.decoder_chain', (params) => (
    `Decodes stored text twice in a row, ${params.get('what')}(…)), ${onLine(params)}. Packed code is usually hidden this way; packed data sometimes is too.`
  )],
  ['unproven.char_chain', (params) => `Spells a string one character at a time with chr(), ${onLine(params)}.`],
  ['unproven.creates_admin', (params) => (
    `Writes a user with the administrator role: ${mechanism(params)} on ${onLine(params)}. Importers and installers do this too, so read when it runs.`
  )],
  ['loaded.code_not_read', (params) => (
    `${ALWAYS_LOADED} (a file of ${sizeOf(params)}) could not be read: ${codeLimit(params)}. `
    + 'WordPress runs it with nothing to switch on, so what it would do is unknown. '
    + 'None of the honest files of this kind measured for this scanner ran into a limit; a file built to stall a scanner does.'
  )],
  ['code.too_large', (params) => {
    if (params.get('reason') === 'tokens') {
      return `A PHP file of ${sizeOf(params)} that splits into more than a million pieces of code, more than this scanner reads. Its code was not checked.`;
    }
    if (params.get('reason') === 'nesting') {
      return `A PHP file of ${sizeOf(params)} that nests code inside strings more than 32 levels deep, deeper than this scanner follows. Its code was not checked.`;
    }
    return `A PHP file of ${sizeOf(params)}, more than the 8 MB this scanner reads as code. Its code was not checked.`;
  }],
  ['code.time_limit', () => (
    'Reading this file as code took longer than 2 seconds, so its code was not checked. Honest files take milliseconds; a file built to stall a scanner looks like this.'
  )],

  ['config.prepend_unusual', (params) => (
    `Makes PHP run ${params.get('what')} before or after every page (line ${formatCount(params.get('line') ?? 0)}). That file is in uploads, is not a PHP file, or is an address.`
  )],
  ['config.prepend', (params) => (
    `Makes PHP run ${params.get('what')} before or after every page (line ${formatCount(params.get('line') ?? 0)}). Firewall plugins such as Wordfence do this; read that file.`
  )],
  ['config.php_handler', (params) => (params.get('what') === '*'
    ? `Hands every file in this folder to PHP (line ${formatCount(params.get('line') ?? 0)}), images included.`
    : `Hands ${params.get('what')} files to PHP (line ${formatCount(params.get('line') ?? 0)}), so such a file runs as code.`
  )],
  ['config.cgi_handler', (params) => (
    `Makes the server run ${configTarget(params)} as programs (CGI), line ${formatCount(params.get('line') ?? 0)}. `
    + 'XAMPP allows CGI in its web folder by default, so such a file starts a program when its address is opened.'
  )],
  ['config.server_side_includes', (params) => (
    `Turns on server-side includes for ${configTarget(params)}, line ${formatCount(params.get('line') ?? 0)}. `
    + 'XAMPP allows them in its web folder by default, and an include can run a command, so read what those files hold.'
  )],
  ['config.redirect', (params) => (
    `Redirects visitors to ${params.get('what')}, which is not the site's own address in the database (line ${formatCount(params.get('line') ?? 0)}).`
  )],
  ['config.too_large', (params) => `A server settings file of ${sizeOf(params)}, more than this scanner reads. It was not checked.`],

  ['db.eval_base64', () => 'The database stores PHP that runs base64-decoded text through eval, a way to hide what it runs.'],
  ['db.snippet_rows', () => 'The database stores code snippets, which run as PHP on the site. Read every one before you run the copy.'],
  ['db.snippet_plugin_active', (params) => {
    // The slugs of the active snippet plugins, joined with ", ".
    const plugins = String(params.get('plugins') ?? '');
    return plugins.includes(', ')
      ? `Snippet plugins are active (${plugins}): they run PHP kept in the database, which no file in the copy shows.`
      : `A snippet plugin is active (${plugins}): it runs PHP kept in the database, which no file in the copy shows.`;
  }],
  ['db.active_plugin_missing', (params) => (
    `The database lists ${withNoun(params.get('missing') ?? 0, 'active plugin whose folder', 'active plugins whose folders')} the copy lacks (${params.get('example')}). The copy is not the whole site.`
  )],
  ['db.external_script_host', (params) => (
    params.get('hosts') === 1
      ? `Pages in the database load scripts from 1 outside host: ${params.get('example')}. Check that it belongs there.`
      : `Pages in the database load scripts from ${formatCount(params.get('hosts') ?? 0)} outside hosts: ${params.get('example')}. Check that each one belongs there.`
  )],
  ['db.not_found', () => 'The copy holds no database dump (.sql), so the database was not checked.'],
  ['text.ai_instruction', (params) => (
    `Holds a sentence aimed at an AI assistant reading the copy ("${params.get('what')}"). What a file says about itself proves nothing; somebody expected an AI to read this.`
  )],

  ['indicator.known_file', (params) => `Byte for byte ${knownFile(params)}.`],
  ['indicator.known_upload', (params) => (
    `The file you chose is byte for byte ${knownFile(params)}. Do not unpack it or run anything from it.`
  )],
  ['indicator.known_name', (params) => (
    `Carries the name of a file from a known attack: ${CAMPAIGN_TEXT.get(params.get('campaign')) ?? 'a published campaign'}. The content may differ; read it.`
  )],

  ['zip.not_a_zip', () => 'This is not a zip archive this scanner can read. Nothing was checked.'],
  ['zip.multi_disk', () => 'A multi-part zip. Nothing was checked.'],
  ['zip.directory_unreadable', () => 'The table of contents of the zip is damaged. Nothing was checked.'],
  ['zip.too_many_entries', (params) => (
    `The archive lists ${withNoun(params.get('entries') ?? 0, 'entry', 'entries')}, more than this scanner takes. Nothing was checked.`
  )],
  ['zip.ambiguous_end_record', () => (
    'The zip has two competing end records. Different unzip programs will open different archives. Nothing was checked.'
  )],
  ['zip.ambiguous_directory', () => (
    'The zip has two tables of contents. Different unzip programs will open different archives. Nothing was checked.'
  )],
  ['zip.directory_mismatch', () => (
    'The table of contents is longer or shorter than the zip declares. Some unzip programs will list other files than shown here.'
  )],
  ['zip.duplicate_name', () => 'Two entries share this name. Which one ends up on disk depends on the unzip program.'],
  ['zip.header_mismatch', (params) => {
    const fields = String(params.get('fields') ?? '').split(' ').map((field) => HEADER_FIELDS.get(field) ?? '?').join(', ');
    const other = params.get('localName');
    return `The header in front of the data disagrees with the table of contents (${fields}).${other ? ` Name in the header: ${other}` : ''}`;
  }],
  ['zip.unicode_path_differs', (params) => (
    `The entry carries a second name that some unzip programs use instead: ${params.get('otherName')}`
  )],
  ['zip.stored_size_mismatch', () => 'An unpacked entry with two different sizes. Unzip programs disagree on which one to use.'],
  ['zip.overlapping_entries', () => 'The data of this entry overlaps the data of another one.'],
  ['zip.unlisted_entry', (params) => (
    `A file header at byte ${formatCount(params.get('offset') ?? 0)} that the table of contents does not list. Some unzip programs will unpack it.`
  )],
  ['zip.prepended_data', (params) => (
    `${sizeOf(params)} in front of the archive that belong to no listed file${leadKind(params)}.`
  )],
  ['zip.unlisted_bytes', (params) => (
    `${sizeOf(params)} at byte ${formatCount(params.get('offset') ?? 0)} that belong to no listed file${leadKind(params)}.`
  )],
  ['zip.trailing_data', (params) => `${sizeOf(params)} after the end of the archive.`],
  ['zip.encrypted_entry', () => 'Password-protected, so it could not be read.'],
  ['zip.unsupported_compression', (params) => (
    `Packed with a method this scanner does not unpack (number ${params.get('method')}).`
  )],
  ['zip.entry_unreadable', (params) => (
    `Could not be read: ${UNREADABLE_REASONS.get(params.get('reason')) ?? 'unknown reason'}.`
  )],

  ['entry.corrupt_data', (params) => `Could not be read in full: ${CORRUPT_REASONS.get(params.get('reason')) ?? 'unknown reason'}.`],
  ['entry.head_unreadable', () => 'The first bytes could not be unpacked within the limit.'],

  ['scan.not_wordpress', () => 'No wp-includes/version.php, no wp-config.php and no wp-content folder. This does not look like a WordPress copy.'],
  ['scan.content_part', () => (
    'What this zip holds looks like the inside of wp-content, with no wp-content folder above it. UpdraftPlus saves a backup as several zips like this one: the plugins, the themes, the uploads and the rest, each on its own. The scanner checked this zip as the inside of wp-content and did not see the other zips of the backup, so scan them too.'
  )],
  ['scan.other_wordpress', () => (
    'Another WordPress lies in this folder. One site per scan is compared with wordpress.org, the one nearest the top of the archive; this one was not, and neither were its plugins. Its files are judged as unknown code.'
  )],
  ['scan.other_copy', () => (
    'This folder holds a wp-content but no wp-includes. At most one site per scan is compared with wordpress.org, and this folder is not part of it. The plugins in its wp-content were not compared, and its files are judged as unknown code.'
  )],
  ['scan.stalled', () =>'The scanner stopped responding while reading this file. The scan was cut short.'],
  ['scan.failed', (params) => `The scan stopped on an internal error (${params.get('error') ?? 'unknown'}). The result is incomplete.`],
]);

const leadKind = (params) => {
  const kind = params.get('kind');
  if (PROGRAM_KINDS.has(kind)) return `, starting like ${PROGRAM_KINDS.get(kind)}`;
  return ARCHIVE_KINDS.has(kind) ? `, starting like ${ARCHIVE_KINDS.get(kind)}` : '';
};

// Past the cap a rule's findings are only counted. Rows on the page are per file, so "of this
// kind" would point at nothing: the line names the first place the rule found instead, a file
// or a folder. A rule about the copy as a whole has no place; its line sits in that row.
const describeOverflow = (more, example) => {
  if (example === '') return `${withNoun(more, 'more finding of this kind is', 'more findings of this kind are')} not listed separately.`;
  return more === 1
    ? `One more finding like the one for ${example} is not listed separately.`
    : `${formatCount(more)} more findings like the one for ${example} are not listed separately.`;
};

export const describeFinding = (finding) => {
  const more = finding.params.get('more');
  if (more !== undefined) return describeOverflow(more, finding.params.get('example') ?? '');
  return FINDING_TEXT.get(finding.rule)(finding.params);
};

export const SEVERITY_LABELS = new Map([
  ['red', 'Do not run'],
  ['amber', 'Read first'],
  ['not_checked', 'Not checked'],
]);

const STAGE_LABELS = new Map([
  ['first_bytes', 'first bytes'],
  ['checksums', 'comparison with wordpress.org'],
  ['php_code', 'PHP code'],
  ['database', 'database'],
  ['nested_archives', 'archives inside the copy'],
]);
// Stages counted in bytes, not files.
const BYTE_STAGES = new Set(['database']);

const describeLoadedFile = (file) => `${file.path} (${file.name ? `${file.name}, ` : ''}${formatBytes(file.bytes)})`;

const describeComponent = (event) => {
  const name = event.kind === 'core' ? `WordPress ${event.version}` : `${event.name} ${event.version}`;
  if (event.state !== 'listed') return `${name}: not compared, ${notComparedReason(event.kind, event.state)}`;
  return `${name}: ${formatCount(event.matched)} of ${withNoun(event.files, 'file', 'files')} the same as on wordpress.org, `
    + `${formatCount(event.modified)} different, ${formatCount(event.extra)} extra, ${formatCount(event.missing)} missing`;
};

const listed = (names) => (names.length === 0 ? 'none' : names.join(', '));

export const LOG_TEXT = {
  reading: (name, bytes) => `${name}, ${formatBytes(bytes)}`,
  opened: (event) => (
    `${withNoun(event.files, 'file', 'files')} in ${withNoun(event.folders, 'folder', 'folders')}, ${formatBytes(event.declaredBytes)} unpacked (as the archive declares)`
  ),
  core: (facts) => (facts.version
    ? `WordPress ${facts.version}, package ${facts.locale}, root folder "${facts.root}"`
    : 'WordPress version not found'),
  plugins: (names) => `plugins: ${listed(names)}`,
  themes: (names) => `themes: ${listed(names)}`,
  database: (database) => `database: ${database.path}, ${formatBytes(database.bytes)}`,
  siteHosts: (hosts) => `the database names the site's own address: ${hosts.join(', ')}. Scripts and redirects pointing there are not reported.`,
  progress: (event) => {
    const amount = BYTE_STAGES.has(event.stage) ? formatBytes : formatCount;
    return `${STAGE_LABELS.get(event.stage)}: ${amount(event.done)} of ${amount(event.total)}`;
  },
  request: (request) => `→ ${new URL(request.url).host}: ${REQUEST_LABELS.get(request.kind)(request)}`,
  component: describeComponent,
  waitingForAdvisories: 'the file has been read; waiting for the answers about known vulnerabilities',
  loadedCode: (event) => {
    if (event.total === 0) return `code that WordPress loads by itself ${LOADED_SOURCES}: none`;
    const unlisted = event.total - event.files.length;
    const more = unlisted > 0 ? `, and ${formatCount(unlisted)} more` : '';
    const read = event.total === 1 ? 'read this file' : 'read each file';
    return `code that WordPress loads by itself ${LOADED_SOURCES}, ${read}: ${event.files.map(describeLoadedFile).join(', ')}${more}`;
  },
  advisories: (records) => {
    const asked = records.filter((record) => record.state === 'checked');
    const affected = asked.filter((record) => record.entries.length > 0);
    const entries = affected.reduce((total, record) => total + record.entries.length, 0);
    const closed = records.filter((record) => record.closed !== null).length;
    const closedText = closed > 0 ? `, ${formatCount(closed)} closed by wordpress.org` : '';
    return `known vulnerabilities: ${formatCount(entries)} in ${formatCount(affected.length)} of ${withNoun(asked.length, 'component', 'components')} looked up${closedText}`;
  },
  done: (stats, requestUrls) => {
    const timing = `Finished in ${(stats.milliseconds / 1000).toFixed(1)} s. Read ${formatBytes(stats.bytesRead)} of the file.`;
    if (requestUrls.length === 0) return `${timing} Nothing was sent anywhere.`;
    const counted = requestUrls.length === 1 ? 'One request' : `${formatCount(requestUrls.length)} requests`;
    const sites = [...new Set(requestUrls.map(siteOf))].join(' and ');
    return `${timing} The file itself stayed in this browser. ${counted} to ${sites} carried names and versions only, as listed above.`;
  },
};

const siteOf = (url) => {
  const { hostname } = new URL(url);
  return hostname.endsWith('.wordpress.org') ? 'wordpress.org' : hostname.replace(/^www\./, '');
};

// The known-vulnerabilities list. Every string in a record has passed the display sanitizer.
export const ADVISORY_TEXT = {
  heading: (record) => {
    const name = record.kind === 'core' ? `WordPress ${record.version}` : `${ADVISORY_KINDS.get(record.kind)} ${record.name} ${record.version}`.trim();
    // A closed plugin is drawn even when its vulnerabilities were never looked up (no version).
    if (record.state !== 'checked') return `${name}: known vulnerabilities not looked up`;
    const counted = record.entries.length === 1 ? 'one known vulnerability' : `${formatCount(record.entries.length)} known vulnerabilities`;
    return `${name}: ${counted} for this version`;
  },
  closed: (closed) => {
    const when = closed.date ? ` on ${closed.date}` : '';
    const why = closed.reason ? ` (reason given: ${closed.reason.replaceAll('-', ' ')})` : '';
    return `wordpress.org closed this plugin${when}${why}. A closed plugin gets no updates from there, security fixes included.`;
  },
  entry: (entry) => {
    const parts = [entry.ids.length > 0 ? entry.ids.join(', ') : 'no CVE number', rangeText(entry)];
    if (entry.score >= 0) parts.push(`CVSS ${entry.score.toFixed(1)}`);
    if (entry.weakness) parts.push(`${entry.weakness.id} ${entry.weakness.name}`.trim());
    return parts.join(' · ');
  },
  more: (count) => `${formatCount(count)} more, not listed separately.`,
  sourceLabel: (url) => SOURCE_LABELS.get(new URL(url).hostname) ?? new URL(url).hostname,
};

const rangeText = (entry) => {
  if (entry.range === null) return 'affects this release';
  const { range } = entry;
  const bounds = [
    range.minOperator ? `${BOUND_WORDS.get(range.minOperator)} ${range.min}` : '',
    range.maxOperator ? `${BOUND_WORDS.get(range.maxOperator)} ${range.max}` : '',
  ].filter(Boolean).join(' ');
  if (entry.unfixed) return `versions ${bounds}, no fixed release yet`;
  return range.maxOperator === 'lt' ? `versions ${bounds}, fixed in ${range.max}` : `versions ${bounds}`;
};

export const STATUS_TEXT = {
  scanning: 'Scanning…',
  lookingUp: 'The file has been read. Waiting for the answers about known vulnerabilities…',
  incomplete: 'The scan did not finish. See "Not checked" below.',
  withRed: 'Do not run this copy.',
  withoutRed: 'No red finding. That is not a clean bill: read the amber and not-checked lists before you run this copy.',
  nothingFound: 'None of the shapes this scanner looks for was found. That is not a clean bill, and running the copy on Windows is still a risk.',
};

// How many of the red findings rest on rules alone, as the subject of a sentence.
const ruleOnlyShare = (count, total) => {
  if (total === 1) return 'The only red finding comes';
  if (count === total) return `All ${formatCount(total)} red findings come`;
  return `${formatCount(count)} of the ${formatCount(total)} red findings ${count === 1 ? 'comes' : 'come'}`;
};

// The lines under the verdict. `comparison` is what main.js counted from the component events.
export const SUMMARY_TEXT = {
  compared: (comparison) => {
    const rest = 'Themes, uploads and the code that WordPress loads by itself have no official list, so they were judged by the rules alone.';
    if (!comparison.online) return 'Nothing was compared with wordpress.org, because the comparison was switched off. Every file was judged by the rules alone.';
    if (comparison.matchedFiles === 0 && !comparison.core && comparison.pluginsCompared === 0) {
      return 'Nothing in this copy could be compared with wordpress.org. Every file was judged by the rules alone.';
    }
    const core = comparison.core ? `WordPress ${comparison.version}` : 'not the core';
    const plugins = `${formatCount(comparison.pluginsCompared)} of ${withNoun(comparison.pluginsTotal, 'plugin', 'plugins')}`;
    const matched = withNoun(comparison.matchedFiles, 'file is byte for byte the official one', 'files are byte for byte the official ones');
    return `Compared with wordpress.org: ${core}, ${plugins}. ${matched}. ${rest}`;
  },
  // `files`: how many files those findings sit in (one file can hold several).
  ruleOnlyRed: (count, total, files) => (
    `${ruleOnlyShare(count, total)} from rules applied to code that has no official release to be compared with. `
    + `A rule can be wrong about honest code, so read ${files === 1 ? 'that file' : 'those files'} before you decide.`
  ),
  loadedCode: (total) => (total === 1
    ? `WordPress loads 1 file by itself ${LOADED_SOURCES}, with nothing to switch on in wp-admin. `
      + 'It is listed below. Read it, whatever the rules said about it.'
    : `WordPress loads ${formatCount(total)} files by itself ${LOADED_SOURCES}, with nothing to switch on in wp-admin. `
      + 'They are listed below. Read each one, whatever the rules said about it.'
  ),
  container: 'If you do run this copy, run it in a Linux container, not on Windows with XAMPP or LocalWP. The trap this scanner was written after starts a Windows program.',
};

// Rows of the lists under the findings.
export const LIST_TEXT = {
  loadedFile: describeLoadedFile,
  component: describeComponent,
  hash: (sha256) => `SHA-256 ${sha256}`,
  // Stand where a path would: a finding about the archive itself, not one file in it, and the
  // line that counts a rule's findings past the cap, which are about files it does not name.
  wholeCopy: '(the whole copy)',
  moreFindings: '(other findings)',
  // `shown` counts rows, one per file; `other` counts the findings left out.
  undrawnFindings: (shown, other) => (
    `The list shows the ${withNoun(shown, 'file', 'files')} with the heaviest findings. `
    + `${other === 1 ? 'One more finding is' : `${formatCount(other)} more findings are`} in the report: copy or download it below.`
  ),
};

// The report a visitor copies or downloads.
export const EXPORT_TEXT = {
  title: (pageUrl) => `Backup Scanner for WordPress report (${pageUrl})`,
  generated: (time) => `Generated: ${time}`,
  archive: (archive) => `Archive: ${archive.name}, ${formatBytes(archive.bytes)}, ${withNoun(archive.files, 'file', 'files')}`,
  wordpress: (facts) => LOG_TEXT.core(facts),
  finished: (stats, requestUrls) => LOG_TEXT.done(stats, requestUrls),
  verdict: (sentence) => `Verdict: ${sentence}`,
  counts: (counts) => `Do not run: ${formatCount(counts.red)} · Read first: ${formatCount(counts.amber)} · Not checked: ${formatCount(counts.not_checked)}`,
  severityTitles: new Map([['red', 'DO NOT RUN'], ['amber', 'READ FIRST'], ['not_checked', 'NOT CHECKED']]),
  excerpt: (line) => `in the file: ${line}`,
  advisories: 'KNOWN VULNERABILITIES (an old version is not a trap, so nothing here counts as red)',
  components: 'COMPARED WITH WORDPRESS.ORG',
  loadedCode: (total) => (total === 1 ? 'CODE THAT WORDPRESS LOADS BY ITSELF (read this file)' : 'CODE THAT WORDPRESS LOADS BY ITSELF (read each file)'),
  requests: 'REQUESTS SENT (names and versions only)',
  noRequests: 'No request was sent.',
  masked: 'E-mail addresses in this report are masked.',
};

// What the page's own controls say back.
export const UI_TEXT = {
  exampleName: 'example-copy.zip',
  reportFileName: 'wp-backup-scan-report',
  copied: 'Copied to the clipboard.',
  copyRefused: 'The browser refused access to the clipboard. The report is in the box below: select it and copy it by hand.',
  logShow: 'Show the whole log',
  logHide: 'Show less of the log',
};
