// SPDX-License-Identifier: GPL-3.0-or-later
//
// Every finding the scanner can report, with its weight. The worker may only send a rule
// from this list, and the page refuses anything else.
//
// red         = do not run this copy
// amber       = read it yourself before you decide
// not_checked = the scanner could not judge it; never the same as "nothing found"

export const SEVERITIES = ['red', 'amber', 'not_checked'];

// Between an archive found in the copy and a file inside it, in the path of a finding.
export const NESTED_SEPARATOR = ' » ';

export const RULES = new Map([
  ['layout.path_traversal', 'red'],
  ['layout.symlink', 'red'],
  ['layout.executable_extension', 'red'],
  ['layout.disguised_executable', 'red'],
  ['layout.php_in_media', 'red'],
  ['layout.php_in_text', 'amber'],
  ['layout.script_in_code_folder', 'amber'],
  ['layout.server_script', 'red'],
  ['layout.server_script_in_code_folder', 'amber'],
  ['layout.php_in_uploads', 'red'],
  ['layout.archive_as_media', 'red'],
  ['layout.archive_behind_media', 'red'],
  ['layout.program_inside_media', 'red'],
  ['layout.inside_not_searched', 'not_checked'],
  ['layout.archive_unexpected_extension', 'amber'],
  ['layout.executable_in_archive', 'amber'],
  ['layout.not_an_image', 'amber'],
  ['layout.php_named_as_media', 'red'],
  ['layout.image_named_php', 'amber'],
  ['layout.php_outside_code_folders', 'amber'],
  ['name.deceptive_characters', 'amber'],
  ['name.trailing_dot_or_space', 'amber'],
  ['archive.not_opened', 'not_checked'],
  ['archive.not_opened_group', 'not_checked'],
  ['archive.tail_not_checked', 'not_checked'],

  ['core.modified', 'red'],
  ['core.extra_file', 'red'],
  ['core.extra_other', 'amber'],
  ['core.extra_root_php', 'amber'],
  ['core.missing_files', 'amber'],
  ['plugin.modified', 'red'],
  ['plugin.extra_php', 'red'],
  ['plugin.extra_file', 'amber'],
  ['plugin.missing_files', 'amber'],
  ['component.not_compared', 'not_checked'],
  ['lookup.off', 'not_checked'],
  ['component.not_compared_past_limit', 'not_checked'],
  ['db.in_nested_archive', 'not_checked'],
  // Known vulnerabilities are listed apart and never weigh: an old version is not a trap. Only
  // a lookup that failed is a finding, because "none known" and "not asked" must not look alike.
  ['advisory.not_checked', 'not_checked'],

  // Code rules (code-rules.js, php-rules.js). `loaded` = code that WordPress loads by itself
  // (wp-config.php, .maintenance, mu-plugins, drop-ins and language files), `unproven` = other PHP that could not
  // be compared with an official release.
  ['loaded.launch_call', 'red'],
  ['loaded.launch_name_text', 'red'],
  ['loaded.launch_name_composed', 'red'],
  ['loaded.dynamic_call', 'amber'],
  ['loaded.rename_executable', 'red'],
  ['loaded.rename_uploads', 'amber'],
  ['loaded.include_uploads', 'amber'],
  ['loaded.include_not_php', 'amber'],
  ['unproven.launch_rare', 'red'],
  ['unproven.launch_call', 'amber'],
  ['unproven.launch_name_text', 'amber'],
  ['unproven.launch_name_composed', 'amber'],
  ['unproven.rename_executable_call', 'red'],
  ['unproven.rename_executable', 'amber'],
  // Hidden code, accounts and plugins.
  ['loaded.eval_decoded', 'red'],
  ['loaded.encoded_code', 'red'],
  ['loaded.encoded_program', 'red'],
  ['loaded.encoded_archive', 'red'],
  ['loaded.halt_compiler_payload', 'red'],
  ['loaded.decoder_chain', 'red'],
  ['loaded.char_chain', 'red'],
  ['loaded.eval_call', 'amber'],
  ['loaded.variable_variable', 'amber'],
  ['loaded.creates_admin', 'red'],
  ['loaded.hides_plugins', 'amber'],
  ['unproven.eval_decoded', 'red'],
  ['unproven.encoded_code', 'red'],
  ['unproven.encoded_program', 'red'],
  ['unproven.encoded_archive', 'amber'],
  ['unproven.halt_compiler_payload', 'red'],
  ['unproven.decoder_chain', 'amber'],
  ['unproven.char_chain', 'amber'],
  ['unproven.creates_admin', 'amber'],
  // A file the reader gave up on (size, tokens, nesting, time): red where WordPress loads it by
  // itself, not checked elsewhere.
  ['loaded.code_not_read', 'red'],
  ['code.too_large', 'not_checked'],
  ['code.time_limit', 'not_checked'],

  // Server and PHP settings (config-rules.js).
  ['config.prepend_unusual', 'red'],
  ['config.prepend', 'amber'],
  ['config.php_handler', 'red'],
  ['config.cgi_handler', 'red'],
  ['config.server_side_includes', 'red'],
  ['config.redirect', 'amber'],
  ['config.too_large', 'not_checked'],

  // The database dump (database.js) and text aimed at an AI reader (text-rules.js).
  ['db.eval_base64', 'red'],
  ['db.snippet_rows', 'amber'],
  ['db.snippet_plugin_active', 'amber'],
  ['db.active_plugin_missing', 'amber'],
  ['db.external_script_host', 'amber'],
  ['db.not_found', 'not_checked'],
  ['text.ai_instruction', 'amber'],

  // Known attacks (indicators.js).
  ['indicator.known_file', 'red'],
  // The file the visitor chose is itself a listed file, such as a campaign's archive.
  ['indicator.known_upload', 'red'],
  ['indicator.known_name', 'amber'],

  ['zip.not_a_zip', 'not_checked'],
  ['zip.multi_disk', 'not_checked'],
  ['zip.directory_unreadable', 'not_checked'],
  ['zip.too_many_entries', 'not_checked'],
  ['zip.ambiguous_end_record', 'red'],
  ['zip.ambiguous_directory', 'red'],
  ['zip.directory_mismatch', 'red'],
  ['zip.duplicate_name', 'red'],
  ['zip.header_mismatch', 'red'],
  ['zip.unicode_path_differs', 'red'],
  ['zip.stored_size_mismatch', 'red'],
  ['zip.overlapping_entries', 'red'],
  ['zip.unlisted_entry', 'red'],
  ['zip.prepended_data', 'amber'],
  ['zip.unlisted_bytes', 'amber'],
  ['zip.trailing_data', 'amber'],
  ['zip.encrypted_entry', 'not_checked'],
  ['zip.unsupported_compression', 'not_checked'],
  ['zip.entry_unreadable', 'not_checked'],

  ['entry.corrupt_data', 'not_checked'],
  ['entry.head_unreadable', 'not_checked'],

  ['scan.not_wordpress', 'not_checked'],
  ['scan.other_wordpress', 'not_checked'],
  ['scan.other_copy', 'not_checked'],
  ['scan.content_part', 'not_checked'],
  ['scan.stalled', 'not_checked'],
  ['scan.failed', 'not_checked'],
]);
