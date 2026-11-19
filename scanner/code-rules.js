// SPDX-License-Identifier: GPL-3.0-or-later
//
// The data behind the code rules: which names start a program, which functions the scanner
// folds when a name is put together from pieces, which extensions make a file a program, and
// which finding each signal becomes in which kind of code. Data, plus the one function that
// reads the table; php-rules.js reads PHP and engine.js reports. A data module and not a JSON file because the worker may
// load scripts but has no network at all (connect-src 'none'), and a JSON file is a fetch.
//
// Where the numbers come from: the honest test copies the README speaks of (WordPress packages
// from wordpress.org, a Docker install, a site with 30 popular plugins; 35,092 distinct PHP
// files) and the engine's own runs on them.

// Functions that hand a command to the operating system. PHP ignores the letter case of
// function names, so the comparison does too.
export const LAUNCH_FUNCTIONS = new Set([
  'exec', 'shell_exec', 'system', 'passthru', 'popen', 'proc_open', 'pcntl_exec', 'expect_popen',
]);

// Ways that honest code in the test copies never used (FFI 0, putenv with a loader
// variable 0, expect 0, the two Windows object names 0). They are red in any code that
// cannot be compared with an official release, not only in always-loaded code.
export const RARE_LAUNCH_FUNCTIONS = new Set(['expect_popen']);
export const RARE_TEXT = ['wscript.shell', 'shell.application', 'expect://'];
export const LOADER_VARIABLES = ['ld_preload', 'ld_library_path', 'ld_audit'];
// `new COM(...)` and `new DOTNET(...)` reach Windows programs; FFI reaches any native function.
export const LAUNCH_CLASSES = new Set(['com', 'dotnet']);
export const FFI_CLASS = 'ffi';
export const FFI_ENTRY_POINTS = new Set(['cdef', 'load', 'scope']);
// Loads a PHP extension, which is native code.
export const EXTENSION_LOADER = 'dl';
export const ENVIRONMENT_SETTER = 'putenv';

// A launch function named in a string is how every indirect call starts (call_user_func,
// array_map, ob_start, ReflectionFunction, `$f = 'exec'; $f()`), so the string alone is the
// signal. Not when the string only asks whether the function exists or is used as a key.
export const AVAILABILITY_CHECKS = new Set(['function_exists', 'is_callable', 'in_array']);

// A launch name that is also an everyday word. As a bare string 'system' was 67 of the 79
// name-as-text hits in the test copies (an HTML doctype, the "system" role of an AI chat
// request, log categories), so it only counts where it can be what runs: inside the arguments
// of a function that takes a callback, or in a file that calls something through a variable.
export const COMMON_WORD_NAMES = new Set(['system']);
export const CALLBACK_TAKERS = new Set([
  'call_user_func', 'call_user_func_array', 'forward_static_call', 'forward_static_call_array',
  'array_map', 'array_filter', 'array_walk', 'array_walk_recursive', 'array_reduce', 'iterator_apply',
  'usort', 'uasort', 'uksort', 'ob_start', 'register_shutdown_function', 'register_tick_function',
  'set_error_handler', 'set_exception_handler', 'spl_autoload_register',
  'preg_replace_callback', 'preg_replace_callback_array', 'reflectionfunction', 'fromcallable',
  // WordPress's own callback takers: add_filter('hook', 'system') and apply_filters('hook',
  // $command) is the most natural way to write an indirect call in a WordPress file.
  'add_filter', 'add_action', 'add_shortcode', 'register_activation_hook', 'register_deactivation_hook',
  // The comparison functions call theirs with two values, which system() accepts.
  'array_udiff', 'array_uintersect', 'array_diff_ukey', 'array_intersect_ukey', 'array_diff_uassoc', 'array_intersect_uassoc',
]);
// Where the callback stands among the arguments, counted from 0, when it is not the first.
export const CALLBACK_POSITIONS = new Map([
  ['array_filter', 1], ['array_walk', 1], ['array_walk_recursive', 1], ['array_reduce', 1], ['usort', 1], ['uasort', 1],
  ['uksort', 1], ['iterator_apply', 1], ['preg_replace_callback', 1], ['add_filter', 1], ['add_action', 1], ['add_shortcode', 1],
  ['register_activation_hook', 1], ['register_deactivation_hook', 1],
]);
// `(int) ($total / 2)` and `if ($ready) ($done = true)` put ")" before "(" without calling anything.
export const CAST_TYPES = new Set(['int', 'integer', 'bool', 'boolean', 'float', 'double', 'real', 'string', 'array', 'object', 'unset', 'binary']);
export const CONTROL_KEYWORDS = new Set(['if', 'elseif', 'while', 'for', 'foreach', 'switch', 'catch', 'declare', 'match']);
// `return ['exec'];` holds a list of one name, `$disabled['exec']` only looks a key up. The
// bracket opens a list when one of these words stands in front of it.
export const WORDS_BEFORE_A_LIST = new Set(['return', 'echo', 'print', 'yield', 'case', 'throw', 'else', 'and', 'or', 'xor']);

// Functions folded on constant arguments before names are compared ('ex' . 'ec',
// strrev('metsys'), chr(101), base64_decode('ZXhlYw==')).
export const FOLDED_FUNCTIONS = new Set([
  'strrev', 'str_rot13', 'base64_decode', 'hex2bin', 'strtolower', 'strtoupper',
]);
export const CHARACTER_FUNCTION = 'chr';
// The folds above that only change letter case. Every other fold decodes something, and a
// string that needed decoding to say "<?php" or to call eval was written to hide it.
export const CASE_FOLDING = new Set(['strtoupper', 'strtolower']);

// Code that hides what it runs. Calls that run PHP handed to them as text, and the
// functions that turn stored text back into code; one inside the other is the classic shape,
// eval of gzinflate of base64_decode. A decoder nested directly in another decoder is the
// same shape with the eval moved to another line.
// URL decoding is left out: urldecode(base64_decode(...)) sits in five honest files of the
// test copies (Elementor, UpdraftPlus, WP Mail SMTP, WP-Optimize), the chains below in none.
export const CODE_RUNNERS = new Set(['eval', 'assert', 'create_function']);
export const DECODERS = new Set([
  'base64_decode', 'gzinflate', 'gzuncompress', 'gzdecode', 'str_rot13', 'strrev', 'hex2bin', 'convert_uudecode',
]);
// Text that is PHP code, looked for in strings that had to be decoded first. The names of
// CODE_RUNNERS and LAUNCH_FUNCTIONS followed by "(" are added in php-rules.js.
export const CODE_MARKERS = ['<?php', 'base64_decode(', 'gzinflate('];
// A literal this long made only of base64 characters is decoded and read for CODE_MARKERS.
// Shorter ones are words, keys and hashes.
export const ENCODED_MIN_LENGTH = 32;
export const ENCODED_MAX_DECODED = 1024 * 1024;
// chr(101) . chr(120) . ... spelling one string; a handful is a delimiter or a byte order mark.
export const CHARACTER_CHAIN_MIN = 8;
// Reads the data that follows __halt_compiler() in its own file.
export const HALT_OFFSET_CONSTANT = '__compiler_halt_offset__';

// Writing a user with the administrator role, and hiding plugins from wp-admin's list.
// add_role() is left out: it defines a role (core's schema.php does that at install), it
// creates no account.
export const USER_WRITERS = new Set(['wp_insert_user', 'wp_create_user', 'wp_update_user', 'set_role']);
export const ADMIN_ROLE = 'administrator';
export const HOOK_ADDERS = new Set(['add_filter', 'add_action']);
export const PLUGIN_LIST_HOOKS = new Set(['all_plugins', 'show_advanced_plugins']);

// Calls whose first argument is the function to run; with a variable there, nothing in the
// file says what runs.
export const CALLBACK_RUNNERS = new Set(['call_user_func', 'call_user_func_array']);

export const MOVE_FUNCTIONS = new Set(['rename', 'copy']);
export const UPLOAD_MOVER = 'move_uploaded_file';
export const INCLUDE_KEYWORDS = new Set(['include', 'include_once', 'require', 'require_once']);
export const UPLOADS_FUNCTIONS = new Set(['wp_upload_dir', 'wp_get_upload_dir']);
// The constant WordPress reads for a custom uploads folder; constants are case-sensitive.
export const UPLOADS_CONSTANT = 'UPLOADS';

// Extensions that make Windows run a file. EXECUTABLE_EXTENSIONS in
// signatures.js, for file names, holds all of these and libraries and other systems' programs too.
export const PROGRAM_EXTENSIONS = new Set([
  'exe', 'bat', 'cmd', 'com', 'scr', 'pif', 'ps1', 'vbs', 'vbe', 'jse', 'wsf', 'hta', 'msi', 'lnk',
]);
// ".com" is also how a domain ends. Away from a rename call it only counts in a string that
// is a path ("/uploads/x.com"), not in an address or a bare host name.
export const DOMAIN_LIKE_EXTENSION = 'com';

// What each signal becomes. `loaded` = code that WordPress loads by itself, with nothing to
// switch on in wp-admin (wp-config.php, .maintenance, mu-plugins, drop-ins and language files; isAlwaysLoaded in
// engine.js). `unproven` = any other PHP that could not be compared with an official release:
// premium plugins, own themes, everything offline.
// A signal missing from a scope gives no finding there. A file gets at most one finding per
// group, the first signal of the group that applies, so each group is listed strongest first.
//
// Honest files of the test copies per signal (measured 2026-11-16 through this module, 35,094
// files): eval_decoded 0, encoded_code 0, halt_compiler_payload 0, decoder_chain 0,
// char_chain 1, eval_call 28 outside the code WordPress loads by itself (and 3 wp-config.php
// files of the official Docker image), variable_variable 44, creates_admin 4 (core's installer
// in three versions, All-in-One WP Migration's user import), hides_plugins 5 (Akismet in three
// versions, two files of WooCommerce). include_not_php: 20 files, all plugin templates and core
// (.css, .svg, .html, .js, .json, core's own .maintenance), none of them loaded by WordPress
// itself; 0 among the 701 files of the always-loaded set.
// Outside the code WordPress loads by itself a signal with honest hits is amber at most.
//
// That code was measured on the same day: 64 honest drop-ins and mu-plugins that WordPress
// loads by itself, from 21 wordpress.org plugins, Bedrock, Kinsta and WordPress VIP (the set the
// README describes). Batcache's advanced-cache.php runs create_function on its own settings and
// the Docker image's wp-config.php runs eval on a setting, so eval_call is amber there as well;
// the forms that decode something first stay red. No other red signal had an honest hit.
export const FINDING_GROUPS = [
  ['launch_rare', 'launch_call', 'launch_name_text', 'launch_name_composed', 'dynamic_call'],
  ['rename_executable_call', 'rename_executable', 'rename_uploads'],
  ['include_not_php', 'include_uploads'],
  ['encoded_program', 'eval_decoded', 'encoded_code', 'halt_compiler_payload', 'encoded_archive', 'decoder_chain', 'char_chain', 'eval_call', 'variable_variable'],
  ['creates_admin'],
  ['hides_plugins'],
];

export const FINDINGS_BY_SCOPE = {
  loaded: new Map([
    ['launch_rare', 'loaded.launch_call'],
    ['launch_call', 'loaded.launch_call'],
    ['launch_name_text', 'loaded.launch_name_text'],
    ['launch_name_composed', 'loaded.launch_name_composed'],
    ['dynamic_call', 'loaded.dynamic_call'],
    ['rename_executable_call', 'loaded.rename_executable'],
    ['rename_executable', 'loaded.rename_executable'],
    ['rename_uploads', 'loaded.rename_uploads'],
    ['include_not_php', 'loaded.include_not_php'],
    ['include_uploads', 'loaded.include_uploads'],
    ['eval_decoded', 'loaded.eval_decoded'],
    ['encoded_code', 'loaded.encoded_code'],
    ['encoded_program', 'loaded.encoded_program'],
    ['encoded_archive', 'loaded.encoded_archive'],
    ['halt_compiler_payload', 'loaded.halt_compiler_payload'],
    ['decoder_chain', 'loaded.decoder_chain'],
    ['char_chain', 'loaded.char_chain'],
    ['eval_call', 'loaded.eval_call'],
    ['variable_variable', 'loaded.variable_variable'],
    ['creates_admin', 'loaded.creates_admin'],
    ['hides_plugins', 'loaded.hides_plugins'],
  ]),
  unproven: new Map([
    ['launch_rare', 'unproven.launch_rare'],
    ['launch_call', 'unproven.launch_call'],
    ['launch_name_text', 'unproven.launch_name_text'],
    ['launch_name_composed', 'unproven.launch_name_composed'],
    ['rename_executable_call', 'unproven.rename_executable_call'],
    ['rename_executable', 'unproven.rename_executable'],
    ['eval_decoded', 'unproven.eval_decoded'],
    ['encoded_code', 'unproven.encoded_code'],
    ['encoded_program', 'unproven.encoded_program'],
    ['encoded_archive', 'unproven.encoded_archive'],
    ['halt_compiler_payload', 'unproven.halt_compiler_payload'],
    ['decoder_chain', 'unproven.decoder_chain'],
    ['char_chain', 'unproven.char_chain'],
    ['creates_admin', 'unproven.creates_admin'],
  ]),
};

// The findings for one file: [rule, { what, line }] pairs, one per group at most. The engine
// and the measurement tool both call this, so a measured count is the count the page shows.
export const chooseCodeFindings = (scope, signals) => {
  const findings = FINDINGS_BY_SCOPE[scope];
  const applies = (signal) => signals.has(signal) && findings.has(signal);
  return FINDING_GROUPS
    .map((group) => group.find(applies))
    .filter((signal) => signal !== undefined)
    .map((signal) => [findings.get(signal), signals.get(signal)]);
};
