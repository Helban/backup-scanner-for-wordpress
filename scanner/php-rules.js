// SPDX-License-Identifier: GPL-3.0-or-later
//
// Reads the tokens of one PHP file and names the signals the code rules know.
// Which finding a signal becomes depends on where the file lies; that choice
// is made in engine.js from the table in code-rules.js. Worker side only.
//
// Launch signals, from the rarest way to the most indirect:
//   launch_rare          - a way honest code never used in the measurement (FFI, putenv with a
//                          loader variable, expect, the WScript.Shell and Shell.Application objects)
//   launch_call          - a launch function called by its name, `new COM`, `new DOTNET`, `dl()`,
//                          a command in backticks
//   launch_name_text     - a launch function's name standing in a string ('exec')
//   launch_name_composed - a launch function's name put together ('ex' . 'ec', strrev('metsys'))
//   dynamic_call         - a call whose target the file does not spell ($f(), call_user_func($f))
// Pair signals:
//   rename_executable_call - rename() or copy() with a program name among its arguments
//   rename_executable      - rename() or copy() plus a program name or a launch anywhere in the file
//   rename_uploads         - rename(), copy() or move_uploaded_file() plus a reference to uploads
//   include_uploads        - include or require plus a reference to uploads
// Loading a file that is not named like PHP:
//   include_not_php        - include or require of a path that ends in another extension
//                            ('/cache/object.bin'), so the code it runs is in a file that no rule
//                            reads as PHP
// Hidden code:
//   eval_decoded          - eval, assert or create_function with a decoding call or a decoded
//                           string among its arguments
//   encoded_code          - a string that says "<?php", calls eval or starts a program only
//                           once decoded
//   encoded_program       - a string that is a Windows or Linux program once decoded
//   encoded_archive       - a string that is a zip, gzip, 7z or other archive once decoded
//   decoder_chain         - a decoding call fed straight into another (gzinflate(base64_decode(...)))
//   halt_compiler_payload - __halt_compiler() plus code that reads the data behind it
//   char_chain            - a string spelled with many chr() calls
//   eval_call             - eval or create_function at all
//   variable_variable     - $$name or ${...}, a variable whose name is computed
// Accounts and plugins:
//   creates_admin  - a user written with the administrator role
//   hides_plugins  - a filter on the list of plugins wp-admin shows

import {
  ADMIN_ROLE, AVAILABILITY_CHECKS, CALLBACK_POSITIONS, CALLBACK_RUNNERS, CALLBACK_TAKERS, CASE_FOLDING, CAST_TYPES,
  CHARACTER_CHAIN_MIN, CHARACTER_FUNCTION, CODE_MARKERS, CODE_RUNNERS, COMMON_WORD_NAMES, CONTROL_KEYWORDS, DECODERS,
  DOMAIN_LIKE_EXTENSION, ENCODED_MAX_DECODED, ENCODED_MIN_LENGTH, ENVIRONMENT_SETTER, EXTENSION_LOADER, FFI_CLASS,
  FFI_ENTRY_POINTS, FOLDED_FUNCTIONS, HALT_OFFSET_CONSTANT, HOOK_ADDERS, INCLUDE_KEYWORDS, LAUNCH_CLASSES, LAUNCH_FUNCTIONS,
  LOADER_VARIABLES, MOVE_FUNCTIONS, PLUGIN_LIST_HOOKS, PROGRAM_EXTENSIONS, RARE_LAUNCH_FUNCTIONS, RARE_TEXT, UPLOADS_CONSTANT,
  UPLOADS_FUNCTIONS, UPLOAD_MOVER, USER_WRITERS, WORDS_BEFORE_A_LIST,
} from './code-rules.js';
import { excerptAround } from './excerpt.js';
import {
  BYTE_VALUES, HALT_COMPILER, VARIABLE_MARK, readsTheSameWithoutShortTags, tokenizePhp, tokenizePhpWithoutShortTags,
} from './php-lexer.js';
import { NO_EXTENSION, PHP_EXTENSIONS, archiveKind, programHeaderKind } from './signatures.js';

const ALL_CODE_MARKERS = [...CODE_MARKERS, ...[...CODE_RUNNERS, ...LAUNCH_FUNCTIONS].map((name) => `${name}(`)];
// assert() runs a string only up to PHP 7; with an expression it is an ordinary check, so on
// its own it says nothing. With a decoder inside it still counts (eval_decoded).
const CONDITION_CHECKER = 'assert';

// Folding stops here: an expression longer than this is not a name anybody types, and the
// limits keep one attempt cheap however the file is built.
const FOLD_MAX_TERMS = 256;
const FOLD_MAX_DEPTH = 16;
const FOLD_MAX_LENGTH = 64 * 1024;
const MEMBER_ACCESS = new Set(['->', '?->', '::']);
const NOT_A_CALL_BEFORE = new Set(['function', 'new']);
// `namespace\system()` in a file that declares no namespace is the global system().
const NAMESPACE_PREFIX = 'namespace\\';
// An import statement is a line; nothing honest runs longer, and the reach keeps a file made
// of imports without a semicolon cheap.
const IMPORT_REACH = 64;
// How far a callback is looked for in a call's arguments. Past the reach the callback counts as
// one the file does not show, like a bare variable: before that, a first argument padded with
// 600 empty strings hid `add_filter('h', $f)` from every rule (found 2026-11-15).
const ARGUMENT_REACH = 512;
const OUT_OF_REACH = -2;
const SHOWN_EXTENSION_LENGTH = 16;
const STRONG_LAUNCH_SIGNALS = ['launch_rare', 'launch_call', 'launch_name_text', 'launch_name_composed'];

// Returns Map(signal -> { what, line, excerpt }), the first place each signal shows up. `tick`
// is the caller's clock (php-lexer.js createClock) and throws when the file has taken too long.
export const findCodeSignals = (source, tick) => {
  const found = new Map();
  const note = (signal, what, at) => {
    const earlier = found.get(signal);
    if (earlier === undefined || at < earlier.at) found.set(signal, { what, at });
  };
  readSignals(tokenizePhp(source, tick), { found, note, tick });
  // Where PHP with short tags off would read other code (php-lexer.js), the file is read that
  // way too, and a signal of either reading counts.
  if (!readsTheSameWithoutShortTags(source)) readSignals(tokenizePhpWithoutShortTags(source, tick), { found, note, tick });
  return new Map([...found].map(([signal, { what, at }]) => (
    [signal, { what, line: lineOf(source, at), excerpt: excerptAround(source, at) }]
  )));
};

// What every reader below shares about one reading of the file. Made once per reading: the
// readers run for every token, and an object per call would be garbage per token.
const readSignals = (tokens, { found, note, tick }) => {
  const file = {
    tokens, strings: collectStrings(tokens, tick), places: createPlaces(tokens, tick), found, note, tick,
  };
  readTokens(file);
  readStrings(file);
  readPairs(file);
};

// True when every token of the file is one a translation file in WordPress's own form is made
// of: `<?php return ['messages' => ['a' => 'b' . "\0" . 'c']];`. Measured on the 314 such files
// of the 71 test archives (GlotPress's and the plugins' own, 2026-11-16): the words return and
// NULL, strings, and the symbols below, nothing else; every one starts with "<?php" and none
// closes the tag. Such a file runs nothing and prints nothing. Text outside the PHP tags is
// printed into the page as it stands (a <script> line before "<?php", anything after a "?>"),
// and the lexer reads no token there, so the file has to start as code and never stop being it.
// A string with a variable in it is code: "Witaj $user->name" can call a method of the object.
export const holdsOnlyLiterals = (source, tick) => (
  STARTS_AS_CODE.test(source) && tokenizePhp(source, tick).every((token) => isLiteralToken(token) && !closesTag(source, token))
);

// Text before the open tag is printed. What follows "<?php" other than PHP's own white space (a
// form feed: the file is text with short tags off) the lexer reads as a short tag and the name
// "php" (php-lexer.js isLongTag), which is no literal. So such a file reads the same under both
// settings, and with no closing tag it never leaves code.
const STARTS_AS_CODE = /^<\?php/i;
const LITERAL_NAMES = new Set(['return', 'null']);
const LITERAL_SYMBOLS = new Set(['[', ']', '=>', ',', '.', ';']);

// The lexer turns a closing tag into ';', as PHP does; its place in the text tells them apart.
const closesTag = (source, token) => token.kind === 'symbol' && source[token.at] === '?';

const isLiteralToken = (token) => {
  if (token.kind === 'string') return !token.interpolated;
  if (token.kind === 'name') return LITERAL_NAMES.has(token.text.toLowerCase());
  return token.kind === 'symbol' && LITERAL_SYMBOLS.has(token.text);
};

// Every string the file holds: each literal, and each expression made only of constants,
// folded to its text. `index` is the token where it starts.
const collectStrings = (tokens, tick) => {
  const strings = [];
  // One fold state for the file; its allowance starts afresh with every expression.
  const fold = { tokens, terms: 0, characters: 0 };
  let foldedUntil = 0;
  for (let index = 0; index < tokens.length; index += 1) {
    tick();
    const token = tokens[index];
    if (token.kind === 'string') {
      strings.push({
        text: token.text, index, composed: token.escaped, decoded: token.escaped, interpolated: token.interpolated, characters: 0,
      });
    }
    // An expression is folded from its first term only, and once: the terms inside it are
    // not folded again on their own.
    if (index < foldedUntil || isSymbol(tokens[index - 1], '.') || !canStartTerm(tokens, index)) continue;
    fold.terms = FOLD_MAX_TERMS;
    fold.characters = 0;
    const folded = foldExpression(fold, index, 0);
    if (folded === null || folded.end === index + 1) continue;
    foldedUntil = folded.end;
    // A literal in parentheses is still the literal, already listed above.
    if (folded.composed) {
      strings.push({
        text: folded.text, index, composed: true, decoded: folded.decoded, interpolated: false, characters: fold.characters,
      });
    }
  }
  return strings;
};

const canStartTerm = (tokens, index) => {
  const token = tokens[index];
  if (token.kind === 'string' || isSymbol(token, '(')) return true;
  return token.kind === 'name' && isSymbol(tokens[index + 1], '(');
};

const foldExpression = (fold, start, depth) => {
  const { tokens } = fold;
  const first = foldTerm(fold, start, depth);
  if (first === null) return null;
  const pieces = [first.text];
  let { composed, decoded, end } = first;
  let length = first.text.length;
  while (isSymbol(tokens[end], '.')) {
    const next = foldTerm(fold, end + 1, depth);
    // One term that is not a constant makes the whole expression a non-constant.
    if (next === null) return null;
    pieces.push(next.text);
    length += next.text.length;
    if (length > FOLD_MAX_LENGTH) return null;
    composed = true;
    decoded ||= next.decoded;
    end = next.end;
  }
  return { text: pieces.join(''), composed, decoded, end };
};

// `fold.terms` is what is left of the expression's allowance, `fold.characters` counts its
// chr() calls.
const foldTerm = (fold, start, depth) => {
  const { tokens } = fold;
  fold.terms -= 1;
  const token = tokens[start];
  if (fold.terms < 0 || depth > FOLD_MAX_DEPTH || token === undefined) return null;
  if (token.kind === 'string') {
    return token.interpolated ? null : { text: token.text, composed: token.escaped, decoded: token.escaped, end: start + 1 };
  }
  if (isSymbol(token, '(')) {
    const inner = foldExpression(fold, start + 1, depth + 1);
    if (inner === null || !isSymbol(tokens[inner.end], ')')) return null;
    return { ...inner, end: inner.end + 1 };
  }
  if (token.kind !== 'name' || !isSymbol(tokens[start + 1], '(')) return null;
  const name = functionName(token);
  if (name === CHARACTER_FUNCTION) {
    const code = tokens[start + 2];
    if (code?.kind !== 'number' || !Number.isInteger(code.integer) || !isSymbol(tokens[start + 3], ')')) return null;
    fold.characters += 1;
    return { text: String.fromCharCode(((code.integer % BYTE_VALUES) + BYTE_VALUES) % BYTE_VALUES), composed: true, decoded: true, end: start + 4 };
  }
  if (!FOLDED_FUNCTIONS.has(name)) return null;
  const argument = foldExpression(fold, start + 2, depth + 1);
  if (argument === null || !isSymbol(tokens[argument.end], ')')) return null;
  const text = applyFolded(name, argument.text);
  if (text === null) return null;
  return { text, composed: true, decoded: argument.decoded || !CASE_FOLDING.has(name), end: argument.end + 1 };
};

// What PHP returns for a constant argument; null where PHP would return false.
const applyFolded = (name, text) => {
  if (name === 'strrev') return text.split('').reverse().join('');
  if (name === 'str_rot13') return text.replace(/[A-Za-z]/g, rotate13);
  if (name === 'strtolower') return text.replace(/[A-Z]/g, (letter) => letter.toLowerCase());
  if (name === 'strtoupper') return text.replace(/[a-z]/g, (letter) => letter.toUpperCase());
  if (name === 'hex2bin') return decodeHex(text);
  return decodeBase64(text);
};

const rotate13 = (letter) => {
  const base = letter <= 'Z' ? 65 : 97;
  return String.fromCharCode(((letter.charCodeAt(0) - base + 13) % 26) + base);
};

const decodeHex = (text) => {
  if (text.length % 2 !== 0 || !/^[0-9A-Fa-f]*$/.test(text)) return null;
  const characters = [];
  for (let at = 0; at < text.length; at += 2) characters.push(String.fromCharCode(parseInt(text.slice(at, at + 2), 16)));
  return characters.join('');
};

// PHP's base64_decode without the strict flag skips every character outside the alphabet.
// database.js decodes base64 kept in the dump with this too.
export const decodeBase64 = (text) => {
  const clean = text.replace(/[^A-Za-z0-9+/]/g, '');
  // One character left over after the last whole group holds less than a byte.
  const usable = clean.length % BASE64_GROUP_CHARACTERS === 1 ? clean.slice(0, -1) : clean;
  return atob(usable.padEnd(Math.ceil(usable.length / BASE64_GROUP_CHARACTERS) * BASE64_GROUP_CHARACTERS, '='));
};

// Base64 writes every 3 bytes as 4 characters.
const BASE64_GROUP_BYTES = 3;
const BASE64_GROUP_CHARACTERS = 4;
// The longest base64 literal decoded: what gives ENCODED_MAX_DECODED bytes, in whole groups.
const ENCODED_MAX_CHARACTERS = Math.ceil(ENCODED_MAX_DECODED / BASE64_GROUP_BYTES) * BASE64_GROUP_CHARACTERS;

// Where the pair rules' ingredients are; readTokens fills it in.
const createPlaces = (tokens, tick) => ({
  ...matchParentheses(tokens, tick),
  moveCalls: [],
  callbackArguments: [],
  runnerCalls: [],
  decoderCalls: [],
  userWrites: [],
  adminRoles: [],
  includes: [],
  uploadMover: -1,
  uploads: -1,
  include: -1,
  halt: -1,
  haltOffset: -1,
  programName: null,
});

// Walks the tokens once for everything that is a name, a call, a variable or a command.
const readTokens = (file) => {
  const { tokens, note, places, tick } = file;
  for (let index = 0; index < tokens.length; index += 1) {
    tick();
    const token = tokens[index];
    if (token.kind === 'command') {
      note('launch_call', 'backtick', token.at);
    } else if (token.kind === 'variable' && isSymbol(tokens[index + 1], '(') && isPlainCall(tokens, index)) {
      note('dynamic_call', 'variable_call', token.at);
    } else if (isSymbol(token, '$') && (tokens[index + 1]?.kind === 'variable' || isSymbol(tokens[index + 1], '{'))) {
      note('variable_variable', '', token.at);
    } else if (isSymbol(token, '(') && isCallOfExpression(tokens, index, places.openers)) {
      note('dynamic_call', 'expression_call', token.at);
    } else if (token.kind === 'name') {
      readName(file, index);
    }
  }
};

const readName = (file, index) => {
  const { tokens, note, places } = file;
  const token = tokens[index];
  const name = functionName(token);
  const next = tokens[index + 1];
  // `$view->include('x.html')` is a method and `f(require: true)` a named argument; PHP allows
  // both words there.
  if (INCLUDE_KEYWORDS.has(name) && isPlainCall(tokens, index) && !isSymbol(next, ':')) {
    firstPlace(places, 'include', token.at);
    places.includes.push(index);
  }
  if (name === HALT_COMPILER) firstPlace(places, 'halt', token.at);
  if (name === HALT_OFFSET_CONSTANT) firstPlace(places, 'haltOffset', token.at);
  // set_role() and add_role() are methods of WP_User and WP_Roles, so methods count here.
  if (USER_WRITERS.has(name) && isSymbol(next, '(')) places.userWrites.push(index);
  if (token.text.replace(/^\\/, '') === UPLOADS_CONSTANT && !isSymbol(next, '(') && !isMember(tokens[index - 1])) {
    firstPlace(places, 'uploads', token.at);
  }
  if (name === 'new' && next?.kind === 'name') {
    const created = functionName(next);
    if (LAUNCH_CLASSES.has(created)) note('launch_call', `new_${created}`, token.at);
    if (created === FFI_CLASS) note('launch_rare', 'ffi', token.at);
  }
  if (name === FFI_CLASS && isSymbol(next, '::') && FFI_ENTRY_POINTS.has(functionName(tokens[index + 2] ?? {}))) {
    note('launch_rare', 'ffi', token.at);
  }
  // `use function system as tidy;` makes tidy() the launch, and no rule would know the alias.
  if (name === 'use' && functionName(next ?? {}) === 'function') readFunctionImport(tokens, index + 2, note);
  // Methods and constructors count here: new ReflectionFunction(...), Closure::fromCallable(...).
  if (CALLBACK_TAKERS.has(name) && isSymbol(next, '(')) {
    places.callbackArguments.push({ open: index + 1, close: places.closers[index + 1] });
    // A bare variable where the callback goes: the file does not say what runs. The two
    // CALLBACK_RUNNERS have their own, wider test in readCall.
    const callback = argumentStart(tokens, index + 1, CALLBACK_POSITIONS.get(name) ?? 0);
    const isBareVariable = tokens[callback]?.kind === 'variable' && (isSymbol(tokens[callback + 1], ',') || isSymbol(tokens[callback + 1], ')'));
    if (!CALLBACK_RUNNERS.has(name) && (isBareVariable || callback === OUT_OF_REACH)) note('dynamic_call', name, token.at);
  }
  if (!isSymbol(next, '(') || !isPlainCall(tokens, index)) return;
  readCall(file, index, name);
};

// The names between `use function` and the semicolon.
const readFunctionImport = (tokens, start, note) => {
  for (let index = start; index < Math.min(tokens.length, start + IMPORT_REACH) && !isSymbol(tokens[index], ';'); index += 1) {
    const imported = functionName(tokens[index]);
    if (LAUNCH_FUNCTIONS.has(imported)) note(RARE_LAUNCH_FUNCTIONS.has(imported) ? 'launch_rare' : 'launch_call', imported, tokens[index].at);
    if (imported === EXTENSION_LOADER) note('launch_call', imported, tokens[index].at);
  }
};

// The token index where argument number `position` of the call opened at `open` begins, -1
// when the call has fewer arguments, or OUT_OF_REACH when it lies past ARGUMENT_REACH tokens.
const argumentStart = (tokens, open, position) => {
  let depth = 0;
  let commas = 0;
  const end = Math.min(tokens.length, open + ARGUMENT_REACH);
  for (let index = open + 1; index < end; index += 1) {
    if (depth === 0 && commas === position) return isSymbol(tokens[index], ')') ? -1 : index;
    const token = tokens[index];
    if (token.kind !== 'symbol') continue;
    if (token.text === '(' || token.text === '[' || token.text === '{') depth += 1;
    else if (token.text === ')' || token.text === ']' || token.text === '}') {
      if (depth === 0) return -1;
      depth -= 1;
    } else if (token.text === ',' && depth === 0) commas += 1;
  }
  return end < tokens.length ? OUT_OF_REACH : -1;
};

// `$handlers[0](...)`, `get_handler()(...)`, `($this->callback)(...)`: a call of whatever the
// expression in front of the bracket gives. A cast or a condition in front of it is not one.
const isCallOfExpression = (tokens, index, openers) => {
  const before = tokens[index - 1];
  if (isSymbol(before, ']')) return true;
  if (!isSymbol(before, ')')) return false;
  const open = openers[index - 1];
  if (open < 0) return false;
  const inside = tokens[open + 1];
  const isCast = index - 1 - open === 2 && inside.kind === 'name' && CAST_TYPES.has(inside.text.toLowerCase());
  const opener = tokens[open - 1];
  const isCondition = opener?.kind === 'name' && CONTROL_KEYWORDS.has(opener.text.toLowerCase());
  return !isCast && !isCondition;
};

const readCall = (file, index, name) => {
  const { tokens, note, places } = file;
  const { at } = tokens[index];
  if (LAUNCH_FUNCTIONS.has(name)) note(RARE_LAUNCH_FUNCTIONS.has(name) ? 'launch_rare' : 'launch_call', name, at);
  if (name === EXTENSION_LOADER) note('launch_call', name, at);
  // A variable, `$$name` or what another call returns as the callback: what runs is decided
  // somewhere else. A string there is a spelled name and goes through the name rules.
  const callback = tokens[index + 2];
  const isUnspelled = callback?.kind === 'variable' || isSymbol(callback, '$')
    || (callback?.kind === 'name' && isSymbol(tokens[index + 3], '('));
  if (CALLBACK_RUNNERS.has(name) && isUnspelled) note('dynamic_call', name, at);
  if (name === ENVIRONMENT_SETTER) {
    const sets = stringsInArguments(file, index).some((entry) => (
      LOADER_VARIABLES.some((variable) => entry.text.toLowerCase().includes(variable))
    ));
    if (sets) note('launch_rare', 'putenv_loader', at);
  }
  if (MOVE_FUNCTIONS.has(name)) places.moveCalls.push(index);
  if (name === UPLOAD_MOVER) firstPlace(places, 'uploadMover', at);
  if (UPLOADS_FUNCTIONS.has(name)) firstPlace(places, 'uploads', at);
  if (CODE_RUNNERS.has(name)) {
    places.runnerCalls.push(index);
    if (name !== CONDITION_CHECKER) note('eval_call', name, at);
  }
  if (DECODERS.has(name)) {
    places.decoderCalls.push(index);
    const inner = tokens[index + 2];
    const innerName = functionName(inner ?? {});
    // strrev(strrev(...)) undoes itself; a chain is two different decodings.
    if (innerName !== name && DECODERS.has(innerName) && isSymbol(tokens[index + 3], '(')) {
      note('decoder_chain', `${name}(${functionName(inner)}`, at);
    }
  }
  const hook = tokens[index + 2];
  if (HOOK_ADDERS.has(name) && hook?.kind === 'string' && PLUGIN_LIST_HOOKS.has(hook.text.toLowerCase())) {
    note('hides_plugins', hook.text.toLowerCase(), at);
  }
};

const readStrings = (file) => {
  const { tokens, strings, found, note, places, tick } = file;
  const callsThroughVariable = found.has('dynamic_call');
  const isInCallback = markCallbackArguments(tokens.length, places.callbackArguments);
  const canRun = (entry, named) => !COMMON_WORD_NAMES.has(named) || callsThroughVariable || isInCallback[entry.index] > 0;
  for (const entry of strings) {
    tick();
    const { at } = tokens[entry.index];
    const lower = entry.text.toLowerCase();
    const rare = RARE_TEXT.find((text) => lower.includes(text));
    if (rare !== undefined) note('launch_rare', rare, at);
    if (isUploadsPath(lower)) firstPlace(places, 'uploads', at);
    const extension = programExtensionInText(entry.text);
    if (extension !== null && places.programName === null) places.programName = extension;
    if (entry.characters >= CHARACTER_CHAIN_MIN) note('char_chain', CHARACTER_FUNCTION, at);
    const decoded = decodedText(entry);
    if (decoded !== null) {
      const marker = codeMarkerIn(entry.decoded ? lower : decoded.text.toLowerCase());
      if (marker !== null) note('encoded_code', decoded.encoding ?? marker, at);
      const packedFile = packedFileIn(decoded.text);
      if (packedFile !== null) note(packedFile.signal, packedFile.kind, at);
    }
    if (lower === ADMIN_ROLE) places.adminRoles.push(entry.index);
    if (entry.interpolated) continue;
    const named = lower.startsWith('\\') ? lower.slice(1) : lower;
    if (!LAUNCH_FUNCTIONS.has(named)) continue;
    if (entry.composed) note('launch_name_composed', named, at);
    else if (!isAvailabilityCheckOrKey(tokens, entry.index) && canRun(entry, named) && !namesMethodOnly(file, entry.index)) {
      note('launch_name_text', named, at);
    }
  }
};

// 'exec' put into a variable that the file only ever uses as a method name. Redis, PDO and
// SQLite3 all have an exec method, and the Redis Object Cache drop-in (3.0.0) picks it with
// `$method = $this->is_predis() ? 'execute' : 'exec'` and calls `$tx->{$method}()`. One use of
// the variable anywhere else (called, passed on, glued to more text) and the name counts.
const namesMethodOnly = (file, index) => {
  const { tokens, places } = file;
  places.statements ??= describeStatements(tokens, file.tick);
  const { start, depth, variables, memberOnly } = places.statements;
  const first = start[index];
  const target = tokens[first];
  const isAssigned = target?.kind === 'variable' && isSymbol(tokens[first + 1], '=') && !isSymbol(tokens[first + 2], '=');
  // Inside a call's parentheses or an array the string is not what lands in the variable.
  if (!isAssigned || depth[index] !== depth[first]) return false;
  if (!memberOnly.has(target.text)) {
    const uses = variables.get(target.text).filter((at) => !(start[at] === at && isSymbol(tokens[at + 1], '=')));
    memberOnly.set(target.text, uses.length > 0 && uses.every((at) => isMemberName(tokens, at)));
  }
  return memberOnly.get(target.text);
};

const isMemberName = (tokens, at) => isMember(tokens[at - 1]) || (isSymbol(tokens[at - 1], '{') && isMember(tokens[at - 2]));

// Per token: where its statement starts and how deep in brackets it sits; per variable name:
// where it occurs. One pass, made only for a file that holds a launch name as a string.
const describeStatements = (tokens, tick) => {
  const start = new Int32Array(tokens.length);
  const depth = new Int32Array(tokens.length);
  const variables = new Map();
  let statement = 0;
  let level = 0;
  for (let index = 0; index < tokens.length; index += 1) {
    tick();
    const token = tokens[index];
    start[index] = statement;
    depth[index] = level;
    if (token.kind === 'variable') {
      const occurrences = variables.get(token.text) ?? [];
      occurrences.push(index);
      variables.set(token.text, occurrences);
    } else if (token.kind === 'symbol') {
      if (token.text === '(' || token.text === '[') level += 1;
      else if (token.text === ')' || token.text === ']') level = Math.max(0, level - 1);
      else if (token.text === ';' || token.text === '{' || token.text === '}') statement = index + 1;
    }
  }
  return { start, depth, variables, memberOnly: new Map() };
};

const readPairs = (file) => {
  const { tokens, found, note, places, tick } = file;
  for (const index of places.moveCalls) {
    for (const entry of stringsInArguments(file, index)) {
      tick();
      const extension = programExtensionOfPath(entry.text);
      if (extension !== null) note('rename_executable_call', extension, tokens[index].at);
    }
  }
  const firstMove = places.moveCalls.length > 0 ? tokens[places.moveCalls[0]].at : -1;
  const launch = STRONG_LAUNCH_SIGNALS.find((signal) => found.has(signal));
  if (firstMove >= 0 && (places.programName !== null || launch !== undefined)) {
    note('rename_executable', places.programName ?? found.get(launch).what, firstMove);
  }
  const moves = [firstMove, places.uploadMover].filter((at) => at >= 0);
  if (moves.length > 0 && places.uploads >= 0) note('rename_uploads', '', Math.min(...moves));
  if (places.include >= 0 && places.uploads >= 0) note('include_uploads', '', places.include);
  if (places.halt >= 0 && places.haltOffset >= 0) note('halt_compiler_payload', '', places.halt);
  readIncludeTargets(file);
  readRunnerArguments(file);
  readUserWrites(file);
};

// PHP runs whatever file include is given, whatever its name. The name is judged by the last
// term of the expression, the part that ends the path; a variable, a constant or a call there
// leaves it unknown and says nothing.
const readIncludeTargets = (file) => {
  const { tokens, note, places, tick } = file;
  const ends = includeEnds(tokens, places.includes, tick);
  // Includes nested in one another end at the same token, so the term in front of an end is
  // looked up once however many of them share it.
  const lastTerms = new Map();
  for (const index of places.includes) {
    tick();
    const end = ends.get(index);
    if (end === undefined) continue;
    if (!lastTerms.has(end)) lastTerms.set(end, lastTermBefore(file, end));
    const last = lastTerms.get(end);
    if (last <= index || tokens[last].kind !== 'string') continue;
    const extension = includedExtension(tokens[last].text);
    if (extension !== null) note('include_not_php', extension, tokens[index].at);
  }
};

// For each include keyword, the token where the expression after it stops: a ";" or "," at its
// own level, or the bracket that closes the level it stands in. One pass over the tokens for all
// of them. A walk per include with a fixed reach was both slower and blind: a million "include"
// words took four times as long as plain code, and a path with 600 empty strings glued in
// front of it lay past the reach.
const includeEnds = (tokens, includes, tick) => {
  const ends = new Map();
  // The includes whose expression is still open, innermost last, each with the bracket depth it
  // stands at. Those at the current depth are always on top.
  const open = [];
  let depth = 0;
  let next = 0;
  for (let at = includes[0] ?? tokens.length; at < tokens.length && (next < includes.length || open.length > 0); at += 1) {
    tick();
    if (includes[next] === at) {
      open.push({ index: at, depth });
      next += 1;
      continue;
    }
    const token = tokens[at];
    if (token.kind !== 'symbol') continue;
    const isOpener = token.text === '(' || token.text === '[' || token.text === '{';
    const isCloser = token.text === ')' || token.text === ']' || token.text === '}';
    if (isOpener) depth += 1;
    if (isCloser || token.text === ';' || token.text === ',') {
      while (open.length > 0 && open[open.length - 1].depth === depth) ends.set(open.pop().index, at);
    }
    if (isCloser) depth -= 1;
  }
  return ends;
};

// The token in front of `end`, with grouping brackets peeled off (`require( $dir . '/x.bin' );`).
const lastTermBefore = (file, end) => {
  const { tokens, tick } = file;
  const { openers } = file.places;
  let last = end - 1;
  while (last >= 0 && isSymbol(tokens[last], ')') && isGrouping(tokens, openers[last])) {
    tick();
    last -= 1;
  }
  return last;
};

// A "(" that only groups: after the include keyword itself or after an operator. After a name,
// a variable or another bracket it opens the arguments of a call.
const isGrouping = (tokens, open) => {
  if (open < 0) return false;
  const before = tokens[open - 1];
  if (before === undefined) return true;
  if (before.kind === 'name') return INCLUDE_KEYWORDS.has(functionName(before));
  if (before.kind !== 'symbol') return false;
  return before.text !== ')' && before.text !== ']' && before.text !== '}';
};

// The extension of the file an include names ('.bin', or '(none)'), or null when it is a PHP
// extension or not known: a variable after the last dot ("x.$type") leaves it open. Trailing
// dots and spaces go, as Windows drops them.
const includedExtension = (path) => {
  let end = path.length;
  while (end > 0 && (path[end - 1] === '.' || path[end - 1] === ' ')) end -= 1;
  const folder = Math.max(path.lastIndexOf('/', end - 1), path.lastIndexOf('\\', end - 1));
  const fileName = path.slice(folder + 1, end);
  const dot = fileName.lastIndexOf('.');
  if (fileName.lastIndexOf(VARIABLE_MARK) > dot) return null;
  if (dot < 0) return NO_EXTENSION;
  const extension = fileName.slice(dot).toLowerCase();
  // The file decides how long this is; a few characters say what kind of file it names.
  return PHP_EXTENSIONS.has(extension) ? null : extension.slice(0, SHOWN_EXTENSION_LENGTH);
};

// eval of base64_decode and its relatives: a decoding call or a decoded string between the
// parentheses of a call that runs PHP.
const readRunnerArguments = (file) => {
  const { tokens, note, places, tick } = file;
  for (const index of places.runnerCalls) {
    tick();
    const close = places.closers[index + 1];
    const decodes = places.decoderCalls.some((call) => call > index && call < close)
      || stringsInArguments(file, index).some((entry) => entry.decoded);
    if (decodes) note('eval_decoded', functionName(tokens[index]), tokens[index].at);
  }
};

// A user written with the administrator role: the role among the arguments of the call, or
// 'role' => 'administrator' anywhere in a file that writes users (the array is often built
// a few lines above the call).
const readUserWrites = (file) => {
  const { tokens, note, places, tick } = file;
  if (places.userWrites.length === 0 || places.adminRoles.length === 0) return;
  const isRoleValue = (index) => isSymbol(tokens[index - 1], '=>') && tokens[index - 2]?.kind === 'string'
    && tokens[index - 2].text.toLowerCase() === 'role';
  for (const index of places.userWrites) {
    tick();
    const close = places.closers[index + 1];
    const inCall = places.adminRoles.some((role) => role > index && role < close);
    if (inCall || places.adminRoles.some(isRoleValue)) {
      note('creates_admin', functionName(tokens[index]), tokens[index].at);
      return;
    }
  }
};

// A string as it stands once decoded, for the strings a file had to decode: one the fold
// already decoded (base64_decode('...'), chr(), escapes) is taken as it is; a long literal of
// base64 characters is decoded here, the way the payload would be at run time. null for a
// plain string.
const decodedText = (entry) => {
  if (entry.decoded) return { text: entry.text, encoding: null };
  if (entry.interpolated || entry.text.length < ENCODED_MIN_LENGTH || !isBase64Text(entry.text)) return null;
  const usable = entry.text.slice(0, ENCODED_MAX_CHARACTERS);
  return { text: decodeBase64(usable), encoding: 'base64' };
};

const codeMarkerIn = (lower) => ALL_CODE_MARKERS.find((marker) => lower.includes(marker)) ?? null;

// A program or an archive kept as text: decoded and written to a file, it becomes a file no
// check of the copy's files ever saw. A program is told by its full header, an archive by its
// first bytes in a string long enough to be one ("PK\x03\x04" alone is how honest code asks
// whether a file is a zip). database.js judges base64 kept in the dump with the same function.
export const packedFileIn = (decodedText) => {
  if (decodedText.startsWith('MZ') || decodedText.startsWith('\x7fELF')) {
    const kind = programHeaderKind(bytesOf(decodedText));
    if (kind !== null) return { signal: 'encoded_program', kind };
  }
  if (decodedText.length < PACKED_ARCHIVE_MIN_LENGTH) return null;
  const kind = archiveKind(bytesOf(decodedText.slice(0, ARCHIVE_HEAD_BYTES)), '');
  if (kind === null) return null;
  const confirms = WEAK_ARCHIVE_NEXT_BYTE.get(kind);
  return confirms === undefined || confirms(decodedText) ? { signal: 'encoded_archive', kind } : null;
};

// A loop, not Uint8Array.from with a mapper: the dump judges every base64 run of 32 letters or
// more, and the mapper took half of the time of a dump made of such runs.
export const bytesOf = (binaryText) => {
  const bytes = new Uint8Array(binaryText.length);
  for (let at = 0; at < binaryText.length; at += 1) bytes[at] = binaryText.charCodeAt(at);
  return bytes;
};

const PACKED_ARCHIVE_MIN_LENGTH = 64;
// A tar is told by "ustar" at byte 257.
const ARCHIVE_HEAD_BYTES = 262;
// Two-byte and three-byte signatures get one more byte checked: gzip's method (always 8,
// deflate) and bzip2's block size digit.
const WEAK_ARCHIVE_NEXT_BYTE = new Map([
  ['gzip', (text) => text.charCodeAt(2) === 8],
  ['bzip2', (text) => text[3] >= '1' && text[3] <= '9'],
]);

const isBase64Text = (text) => {
  let end = text.length;
  while (end > 0 && text[end - 1] === '=') end -= 1;
  if (text.length - end > 2) return false;
  for (let at = 0; at < end; at += 1) {
    const char = text[at];
    const isAlphabet = (char >= 'A' && char <= 'Z') || (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char === '+' || char === '/';
    if (!isAlphabet) return false;
  }
  return true;
};

// For every token, how many callback-taking calls it sits inside. One pass however many such
// calls the file makes: +1 where the arguments open, -1 where they close, then a running sum.
const markCallbackArguments = (tokenCount, ranges) => {
  const depth = new Int32Array(tokenCount + 1);
  for (const { open, close } of ranges) {
    depth[open + 1] += 1;
    depth[close] -= 1;
  }
  for (let index = 1; index <= tokenCount; index += 1) depth[index] += depth[index - 1];
  return depth;
};

// The strings that start inside the parentheses of the call whose name is at `index`.
const stringsInArguments = ({ strings, places }, index) => {
  const open = index + 1;
  const close = places.closers[open];
  const first = firstStringFrom(strings, open);
  const inside = [];
  for (let position = first; position < strings.length && strings[position].index < close; position += 1) {
    inside.push(strings[position]);
  }
  return inside;
};

// `closers`: for every "(" the index of its ")", or the end of the tokens when it is never
// closed. `openers`: for every ")" the index of its "(", or -1. One pass with a stack, so a
// file of a hundred thousand calls costs no more than its length.
const matchParentheses = (tokens, tick) => {
  const closers = new Int32Array(tokens.length).fill(tokens.length);
  const openers = new Int32Array(tokens.length).fill(-1);
  const open = [];
  for (let index = 0; index < tokens.length; index += 1) {
    tick();
    if (isSymbol(tokens[index], '(')) {
      open.push(index);
    } else if (isSymbol(tokens[index], ')') && open.length > 0) {
      openers[index] = open.pop();
      closers[openers[index]] = index;
    }
  }
  return { closers, openers };
};

// `strings` is in token order, so the first one at or after a token is found by halving.
const firstStringFrom = (strings, tokenIndex) => {
  let low = 0;
  let high = strings.length;
  while (low < high) {
    const middle = (low + high) >> 1;
    if (strings[middle].index < tokenIndex) low = middle + 1;
    else high = middle;
  }
  return low;
};

// The program extension ('.exe') a string handed to rename() or copy() ends with, or null.
// Such a string is a file name whatever it looks like.
const programExtensionOfPath = (path) => {
  const extension = lastExtension(path);
  return PROGRAM_EXTENSIONS.has(extension) ? `.${extension}` : null;
};

// The same for any other string of the file, where ".com" may also end a domain name.
const programExtensionInText = (text) => {
  const extension = lastExtension(text);
  if (!PROGRAM_EXTENSIONS.has(extension)) return null;
  if (extension === DOMAIN_LIKE_EXTENSION && !looksLikePath(text)) return null;
  return `.${extension}`;
};

// What follows the last dot, in lower case, or '' without a dot. Windows drops trailing dots
// and spaces from a file name, so they are dropped here too.
const lastExtension = (name) => {
  let end = name.length;
  while (end > 0 && (name[end - 1] === '.' || name[end - 1] === ' ')) end -= 1;
  const dot = name.lastIndexOf('.', end - 1);
  return dot < 0 ? '' : name.slice(dot + 1, end).toLowerCase();
};

const looksLikePath = (text) => (
  (text.includes('/') || text.includes('\\')) && !text.includes('://') && !text.includes('@')
);

const UPLOADS_FOLDER = 'uploads';

// "uploads" as a whole part of a path: 'wp-content/uploads/x', '/uploads', "$dir/uploads/".
const isUploadsPath = (lower) => {
  for (let at = lower.indexOf(UPLOADS_FOLDER); at >= 0; at = lower.indexOf(UPLOADS_FOLDER, at + 1)) {
    const end = at + UPLOADS_FOLDER.length;
    const before = at === 0 ? '/' : lower[at - 1];
    const after = end === lower.length ? '/' : lower[end];
    if (isPathEdge(before) && isPathEdge(after)) return true;
  }
  return false;
};

const isPathEdge = (char) => char === '/' || char === '\\' || char === VARIABLE_MARK;

// 'exec' that only asks whether the function exists, or is a key of an array.
const isAvailabilityCheckOrKey = (tokens, index) => {
  const before = tokens[index - 1];
  const after = tokens[index + 1];
  if (isSymbol(after, '=>')) return true;
  if (isSymbol(before, '[') && isSymbol(after, ']') && isIndexed(tokens[index - 2])) return true;
  const caller = tokens[index - 2];
  return isSymbol(before, '(') && caller?.kind === 'name' && AVAILABILITY_CHECKS.has(functionName(caller));
};

// What stands in front of a "[" that looks something up: a variable, a constant, or the end
// of another lookup or call. Anything else in front (`=`, `(`, `return`) and the bracket opens
// a list, so `['exec']` is a list of one name.
const isIndexed = (token) => {
  if (token === undefined) return false;
  if (token.kind === 'variable') return true;
  if (token.kind === 'name') return !WORDS_BEFORE_A_LIST.has(token.text.toLowerCase());
  return isSymbol(token, ']') || isSymbol(token, ')') || isSymbol(token, '}');
};

// A call of a global function: not a method (`$x->exec(`, `X::exec(`), not a definition
// (`function exec(`, `function &exec(`), not `new X(`.
const isPlainCall = (tokens, index) => {
  const before = tokens[index - 1];
  if (before === undefined) return true;
  if (before.kind === 'symbol' && MEMBER_ACCESS.has(before.text)) return false;
  if (before.kind === 'name' && NOT_A_CALL_BEFORE.has(before.text.toLowerCase())) return false;
  return !(isSymbol(before, '&') && tokens[index - 2]?.kind === 'name' && tokens[index - 2].text.toLowerCase() === 'function');
};

// Lower case, without the leading backslash of a fully qualified name and without the
// `namespace\` that means "this file's namespace". A name inside another namespace (Foo\exec)
// is not the global function and gives ''.
const functionName = (token) => {
  if (token.kind !== 'name') return '';
  const written = (token.text.startsWith('\\') ? token.text.slice(1) : token.text).toLowerCase();
  const name = written.startsWith(NAMESPACE_PREFIX) ? written.slice(NAMESPACE_PREFIX.length) : written;
  return name.includes('\\') ? '' : name;
};

const firstPlace = (places, key, at) => {
  if (places[key] < 0 || at < places[key]) places[key] = at;
};

const isSymbol = (token, text) => token !== undefined && token.kind === 'symbol' && token.text === text;

const isMember = (token) => token !== undefined && token.kind === 'symbol' && MEMBER_ACCESS.has(token.text);

const lineOf = (source, at) => {
  let line = 1;
  for (let newline = source.indexOf('\n'); newline >= 0 && newline < at; newline = source.indexOf('\n', newline + 1)) line += 1;
  return line;
};
