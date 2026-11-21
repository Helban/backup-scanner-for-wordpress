// SPDX-License-Identifier: GPL-3.0-or-later
//
// gzip unpacked piece by piece, in the worker. A dump packed as .sql.gz is one gzip member;
// UpdraftPlus's -db.gz is many, written one after another (its backup.php: "Concatenating gz
// files produces a valid gz file"). The browser's DecompressionStream('gzip') ends at the first
// member and throws on whatever follows (Chromium 151 and Firefox 153, measured 2026-11-21), and
// Firefox also drops up to 32 KB of that member's output when the next member arrives in the
// same piece, so the members cannot be cut apart around it. Hence an inflater of our own
// (RFC 1951) and a reader of gzip members (RFC 1952).
//
// Every step (a member header, a block header with its code tables, one literal or match, a
// member's trailer) runs only once the input holds all of it; otherwise the bytes left over
// wait for the next piece. A step is never left halfway, so a piece may end at any byte.

import { crc32 } from './crc32.js';

const WINDOW_BYTES = 32 * 1024;
const OUTPUT_BYTES = 256 * 1024;
const LONGEST_MATCH = 258;
// The name and comment fields have no length; a header is read no further than this, whether it
// arrives in one piece or in many. Until 2026-11-21 the limit held only across pieces: the index
// pass (1 MB pieces) took a 140 KB name that a reader of 64 KB pieces refused, and the archive
// then read as nothing. gzip itself sets no limit; 16 MB of name is no honest file's.
const HEADER_LIMIT_BYTES = 16 * 1024 * 1024;

const GZIP_ID1 = 0x1f;
const GZIP_ID2 = 0x8b;
const METHOD_DEFLATE = 8;
const FLAG_HEADER_CRC = 0x02;
const FLAG_EXTRA = 0x04;
const FLAG_NAME = 0x08;
const FLAG_COMMENT = 0x10;
const FLAGS_RESERVED = 0xe0;
const FIXED_HEADER_BYTES = 10;

const LENGTH_BASE = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
const LENGTH_EXTRA = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const DISTANCE_BASE = [
  1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193,
  12289, 16385, 24577,
];
const DISTANCE_EXTRA = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
const END_OF_BLOCK = 256;
const FIRST_LENGTH_SYMBOL = 257;
const CODE_LENGTH_ORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];
// In the code lengths of a dynamic block, symbols below 16 are a length; 16 repeats the previous
// length, 17 and 18 repeat zero: [extra bits, base count] for each.
const FIRST_REPEAT_SYMBOL = 16;
const REPEAT_PREVIOUS = 16;
const REPEATS = new Map([[16, [2, 3]], [17, [3, 3]], [18, [7, 11]]]);
const MAX_LITERAL_CODES = 286;
const MAX_DISTANCE_CODES = 30;
const MAX_CODE_BITS = 15;
// The fixed codes of RFC 1951, 3.2.6.
const FIXED_LITERAL_COUNT = 288;
const FIXED_DISTANCE_COUNT = 32;
const FIXED_DISTANCE_BITS = 5;

// A code table is indexed by the next `bits` input bits, lowest first. An entry is
// symbol << SYMBOL_SHIFT | code length; 0 where the lengths left that code unused. null when the
// lengths ask for more codes than there are.
const SYMBOL_SHIFT = 4;
const LENGTH_MASK = (1 << SYMBOL_SHIFT) - 1;
const buildTable = (lengths) => {
  const counts = new Uint16Array(MAX_CODE_BITS + 1);
  let bits = 0;
  for (const length of lengths) {
    counts[length] += 1;
    if (length > bits) bits = length;
  }
  counts[0] = 0;
  let left = 1;
  for (let length = 1; length <= MAX_CODE_BITS; length += 1) {
    left = (left << 1) - counts[length];
    if (left < 0) return null;
  }
  const nextCode = new Uint16Array(MAX_CODE_BITS + 1);
  for (let length = 1, code = 0; length <= MAX_CODE_BITS; length += 1) {
    code = (code + counts[length - 1]) << 1;
    nextCode[length] = code;
  }
  const table = new Int32Array(1 << bits);
  for (let symbol = 0; symbol < lengths.length; symbol += 1) {
    const length = lengths[symbol];
    if (length === 0) continue;
    const code = nextCode[length];
    nextCode[length] += 1;
    let reversed = 0;
    for (let bit = 0; bit < length; bit += 1) reversed |= ((code >>> bit) & 1) << (length - 1 - bit);
    for (let index = reversed; index < table.length; index += 1 << length) table[index] = (symbol << SYMBOL_SHIFT) | length;
  }
  return { table, bits };
};

const FIXED_LITERALS = buildTable(Uint8Array.from({ length: FIXED_LITERAL_COUNT }, (_, symbol) => {
  if (symbol < 144) return 8;
  if (symbol < 256) return 9;
  return symbol < 280 ? 7 : 8;
}));
const FIXED_DISTANCES = buildTable(new Uint8Array(FIXED_DISTANCE_COUNT).fill(FIXED_DISTANCE_BITS));

const HEADER = 'header';
const BLOCK = 'block';
const STORED = 'stored';
const CODES = 'codes';
const TRAILER = 'trailer';
const PADDING = 'padding';
const OVER = 'over';

// What the hot loop stops for.
const BLOCK_ENDED = 1;
const WAITING = 2;
const OUTPUT_FULL = 3;
const FAILED = 4;

// The steps between which the whole state is a handful of numbers, the code tables in use and
// the last 32 KB of output: a point taken there restarts the unpacking in the middle of a file.
const RESUMABLE_STATES = new Set([HEADER, BLOCK, STORED, CODES]);

// `onBytes(view)` gets the unpacked bytes in order and must not keep the view: the buffer
// behind it is written again. Unpacking stops once more than `limitBytes` came out.
// finish() returns { state, members, bytes }, state one of:
//   ended     - every member was whole and its checksum right (zero bytes after the last are
//               allowed, the way gzip itself allows them)
//   truncated - the data stops inside a member, or there was none
//   damaged   - not gzip, a broken code, a wrong checksum or size, other bytes after a member
//   too_large - the limit was reached; what came out until then was handed over
//
// Random access (a .tar.gz read without holding it unpacked): with `onPoint` and `pointEvery`,
// a point is handed over each time at least `pointEvery` bytes came out since the last one.
// `from: point` starts a new unpacking there; its input must then begin at `point.inputOffset`
// of the packed file, and its output begins at `point.outputOffset`. Byte counts (`bytes`,
// `limitBytes`) are counted from the start of the file either way.
export const createGunzip = ({ onBytes, limitBytes, onPoint = null, pointEvery = Infinity, from = null }) => {
  const window = new Uint8Array(WINDOW_BYTES + OUTPUT_BYTES);
  const fullAt = window.length - LONGEST_MATCH;
  let input = new Uint8Array(0);
  // Where input[0] lies in the packed file.
  let inputStart = 0;
  let at = 0;
  let bitBuffer = 0;
  let bitCount = 0;
  let state = HEADER;
  let failure = '';
  let out = 0;
  let emittedAt = 0;
  let emittedBytes = 0;
  let members = 0;
  // The member being read: its checksum so far, its size, where its output starts in the window
  // (0 once older bytes than the window holds are its own).
  let checkedAt = 0;
  let memberCrc = 0;
  let memberBytes = 0;
  let memberStart = 0;
  let isFinalBlock = false;
  let storedLeft = 0;
  let literals = FIXED_LITERALS;
  let distances = FIXED_DISTANCES;
  // What the tables of the current dynamic block were built from (null for the fixed codes): a
  // point keeps these 316 bytes at most, not the tables, which take up to 288 KB.
  let codeLengths = null;
  let lastPointAt = 0;

  const fail = (reason) => {
    failure = reason;
    state = OVER;
  };

  const emit = () => {
    if (out === emittedAt) return;
    const fresh = window.subarray(emittedAt, out);
    emittedAt = out;
    emittedBytes += fresh.length;
    onBytes(fresh);
    if (emittedBytes > limitBytes) fail('too_large');
  };

  const checkMember = () => {
    const fresh = window.subarray(checkedAt, out);
    memberCrc = crc32(fresh, memberCrc);
    memberBytes += fresh.length;
    checkedAt = out;
  };

  // The window keeps the last 32 KB, which is as far back as a match may reach.
  const flush = () => {
    checkMember();
    emit();
    const shift = out - WINDOW_BYTES;
    window.copyWithin(0, shift, out);
    out = WINDOW_BYTES;
    emittedAt = out;
    checkedAt = out;
    memberStart = Math.max(0, memberStart - shift);
  };

  // n bits (at most 16) from the input, or -1 when it does not hold them yet.
  const take = (n) => {
    while (bitCount < n) {
      if (at >= input.length) return -1;
      bitBuffer |= input[at] << bitCount;
      at += 1;
      bitCount += 8;
    }
    const bits = bitBuffer & ((1 << n) - 1);
    bitBuffer >>>= n;
    bitCount -= n;
    return bits;
  };

  const dropToByte = () => {
    bitBuffer >>>= bitCount & 7;
    bitCount -= bitCount & 7;
  };

  // A symbol of `code`, -1 when the input does not hold it yet, -2 for a code nobody defined.
  const decodeSlowly = (code) => {
    while (bitCount < code.bits && at < input.length) {
      bitBuffer |= input[at] << bitCount;
      at += 1;
      bitCount += 8;
    }
    const entry = code.table[bitBuffer & ((1 << code.bits) - 1)];
    const length = entry & LENGTH_MASK;
    if (length === 0) return bitCount >= code.bits ? -2 : -1;
    if (length > bitCount) return -1;
    bitBuffer >>>= length;
    bitCount -= length;
    return entry >>> SYMBOL_SHIFT;
  };

  const readHeader = () => {
    const available = input.length - at;
    if (available === 0) return false;
    if (members > 0 && input[at] === 0) {
      state = PADDING;
      return true;
    }
    const isOther = input[at] !== GZIP_ID1 || (available > 1 && input[at + 1] !== GZIP_ID2) || (available > 2 && input[at + 2] !== METHOD_DEFLATE);
    if (isOther) {
      fail('damaged');
      return true;
    }
    if (available < FIXED_HEADER_BYTES) return false;
    const flags = input[at + 3];
    if (flags & FLAGS_RESERVED) {
      fail('damaged');
      return true;
    }
    let end = at + FIXED_HEADER_BYTES;
    if (flags & FLAG_EXTRA) {
      if (end + 2 > input.length) return waitForHeader();
      end += 2 + (input[end] | (input[end + 1] << 8));
    }
    for (const flag of [FLAG_NAME, FLAG_COMMENT]) {
      if (!(flags & flag)) continue;
      const zero = end < input.length ? input.indexOf(0, end) : -1;
      if (zero < 0) return waitForHeader();
      end = zero + 1;
    }
    if (flags & FLAG_HEADER_CRC) end += 2;
    if (end > input.length) return waitForHeader();
    if (end - at > HEADER_LIMIT_BYTES) {
      fail('damaged');
      return true;
    }
    at = end;
    memberCrc = 0;
    memberBytes = 0;
    checkedAt = out;
    memberStart = out;
    state = BLOCK;
    return true;
  };

  const waitForHeader = () => {
    if (input.length - at > HEADER_LIMIT_BYTES) fail('damaged');
    return state === OVER;
  };

  const skipPadding = () => {
    while (at < input.length) {
      if (input[at] !== 0) {
        fail('damaged');
        return true;
      }
      at += 1;
    }
    return false;
  };

  const readBlockHeader = () => {
    const saved = [at, bitBuffer, bitCount];
    const final = take(1);
    const type = take(2);
    if (type < 0) return restore(saved);
    isFinalBlock = final === 1;
    if (type === 0) {
      dropToByte();
      const length = take(16);
      const complement = take(16);
      if (complement < 0) return restore(saved);
      if ((length ^ 0xffff) !== complement) {
        fail('damaged');
        return true;
      }
      storedLeft = length;
      state = STORED;
    } else if (type === 1) {
      literals = FIXED_LITERALS;
      distances = FIXED_DISTANCES;
      codeLengths = null;
      state = CODES;
    } else if (type === 2) {
      const tables = readCodeTables();
      if (tables === null) return restore(saved);
      if (state === OVER) return true;
      [literals, distances, codeLengths] = tables;
      state = CODES;
    } else {
      fail('damaged');
    }
    return true;
  };

  const restore = ([savedAt, savedBuffer, savedCount]) => {
    at = savedAt;
    bitBuffer = savedBuffer;
    bitCount = savedCount;
    return false;
  };

  // The code tables of a dynamic block: [literals, distances], null when the input does not
  // hold them yet. A broken table ends the unpacking.
  const readCodeTables = () => {
    const counts = [take(5), take(5), take(4)];
    if (counts.some((bits) => bits < 0)) return null;
    const literalCount = counts[0] + FIRST_LENGTH_SYMBOL;
    const distanceCount = counts[1] + 1;
    const lengthCodeCount = counts[2] + 4;
    if (literalCount > MAX_LITERAL_CODES || distanceCount > MAX_DISTANCE_CODES) return broken();
    const lengthCodeLengths = new Uint8Array(CODE_LENGTH_ORDER.length);
    for (let index = 0; index < lengthCodeCount; index += 1) {
      const length = take(3);
      if (length < 0) return null;
      lengthCodeLengths[CODE_LENGTH_ORDER[index]] = length;
    }
    const lengthCode = buildTable(lengthCodeLengths);
    if (lengthCode === null) return broken();
    const lengths = new Uint8Array(literalCount + distanceCount);
    for (let index = 0; index < lengths.length;) {
      const symbol = decodeSlowly(lengthCode);
      if (symbol === -1) return null;
      if (symbol === -2) return broken();
      if (symbol < FIRST_REPEAT_SYMBOL) {
        lengths[index] = symbol;
        index += 1;
        continue;
      }
      const [extraBits, base] = REPEATS.get(symbol);
      const extra = take(extraBits);
      if (extra < 0) return null;
      if (symbol === REPEAT_PREVIOUS && index === 0) return broken();
      const repeated = symbol === REPEAT_PREVIOUS ? lengths[index - 1] : 0;
      const count = base + extra;
      if (index + count > lengths.length) return broken();
      lengths.fill(repeated, index, index + count);
      index += count;
    }
    if (lengths[END_OF_BLOCK] === 0) return broken();
    const literalTable = buildTable(lengths.subarray(0, literalCount));
    const distanceTable = buildTable(lengths.subarray(literalCount));
    if (literalTable === null || distanceTable === null) return broken();
    return [literalTable, distanceTable, { lengths: lengths.slice(), literalCount }];
  };

  const broken = () => {
    fail('damaged');
    return [];
  };

  const copyStored = () => {
    while (storedLeft > 0 && bitCount >= 8) {
      window[out] = bitBuffer & 0xff;
      out += 1;
      bitBuffer >>>= 8;
      bitCount -= 8;
      storedLeft -= 1;
    }
    for (;;) {
      if (storedLeft === 0) {
        state = isFinalBlock ? TRAILER : BLOCK;
        return true;
      }
      if (out >= fullAt) {
        flush();
        // flush() hands the output over and may hit the limit; the block must not go on after it
        // (it did, and a stream of tiny stored blocks ran 150 times past a 1 MB limit).
        if (state === OVER) return true;
      }
      const count = Math.min(storedLeft, input.length - at, fullAt - out);
      if (count === 0) return false;
      window.set(input.subarray(at, at + count), out);
      at += count;
      out += count;
      storedLeft -= count;
    }
  };

  // Literals and matches, until the block ends, the input runs short or the window is full.
  // State lives in locals here and is written back on the way out: this loop is the cost.
  const decodeCodes = () => {
    let position = at;
    let bits = bitBuffer;
    let count = bitCount;
    let written = out;
    const bytes = input;
    const end = bytes.length;
    const literalTable = literals.table;
    const literalBits = literals.bits;
    const literalMask = (1 << literalBits) - 1;
    const distanceTable = distances.table;
    const distanceBits = distances.bits;
    const distanceMask = (1 << distanceBits) - 1;
    let stop = WAITING;
    for (;;) {
      if (written >= fullAt) {
        stop = OUTPUT_FULL;
        break;
      }
      const stepAt = position;
      const stepBits = bits;
      const stepCount = count;
      while (count < literalBits && position < end) {
        bits |= bytes[position] << count;
        position += 1;
        count += 8;
      }
      let entry = literalTable[bits & literalMask];
      let length = entry & LENGTH_MASK;
      if (length === 0 && count >= literalBits) {
        stop = FAILED;
        break;
      }
      if (length === 0 || length > count) {
        [position, bits, count] = [stepAt, stepBits, stepCount];
        break;
      }
      bits >>>= length;
      count -= length;
      const symbol = entry >>> SYMBOL_SHIFT;
      if (symbol < END_OF_BLOCK) {
        window[written] = symbol;
        written += 1;
        continue;
      }
      if (symbol === END_OF_BLOCK) {
        stop = BLOCK_ENDED;
        break;
      }
      const lengthIndex = symbol - FIRST_LENGTH_SYMBOL;
      if (lengthIndex >= LENGTH_BASE.length) {
        stop = FAILED;
        break;
      }
      let extraBits = LENGTH_EXTRA[lengthIndex];
      while (count < extraBits && position < end) {
        bits |= bytes[position] << count;
        position += 1;
        count += 8;
      }
      if (count < extraBits) {
        [position, bits, count] = [stepAt, stepBits, stepCount];
        break;
      }
      const matchLength = LENGTH_BASE[lengthIndex] + (bits & ((1 << extraBits) - 1));
      bits >>>= extraBits;
      count -= extraBits;
      while (count < distanceBits && position < end) {
        bits |= bytes[position] << count;
        position += 1;
        count += 8;
      }
      entry = distanceTable[bits & distanceMask];
      length = entry & LENGTH_MASK;
      if (length === 0 && count >= distanceBits) {
        stop = FAILED;
        break;
      }
      if (length === 0 || length > count) {
        [position, bits, count] = [stepAt, stepBits, stepCount];
        break;
      }
      bits >>>= length;
      count -= length;
      const distanceSymbol = entry >>> SYMBOL_SHIFT;
      if (distanceSymbol >= DISTANCE_BASE.length) {
        stop = FAILED;
        break;
      }
      extraBits = DISTANCE_EXTRA[distanceSymbol];
      while (count < extraBits && position < end) {
        bits |= bytes[position] << count;
        position += 1;
        count += 8;
      }
      if (count < extraBits) {
        [position, bits, count] = [stepAt, stepBits, stepCount];
        break;
      }
      const distance = DISTANCE_BASE[distanceSymbol] + (bits & ((1 << extraBits) - 1));
      bits >>>= extraBits;
      count -= extraBits;
      if (distance > written - memberStart) {
        stop = FAILED;
        break;
      }
      const from = written - distance;
      if (distance >= matchLength) {
        window.copyWithin(written, from, from + matchLength);
      } else {
        // The match overlaps what it writes: byte by byte, as deflate means it.
        for (let index = 0; index < matchLength; index += 1) window[written + index] = window[from + index];
      }
      written += matchLength;
    }
    at = position;
    bitBuffer = bits;
    bitCount = count;
    out = written;
    return stop;
  };

  const readCodes = () => {
    const stop = decodeCodes();
    if (stop === OUTPUT_FULL) {
      flush();
    } else if (stop === BLOCK_ENDED) {
      state = isFinalBlock ? TRAILER : BLOCK;
    } else if (stop === FAILED) {
      fail('damaged');
    }
    return stop !== WAITING;
  };

  const readTrailer = () => {
    const saved = [at, bitBuffer, bitCount];
    dropToByte();
    const parts = [take(16), take(16), take(16), take(16)];
    if (parts.some((bits) => bits < 0)) return restore(saved);
    checkMember();
    const crc = (parts[0] | (parts[1] << 16)) >>> 0;
    const size = (parts[2] | (parts[3] << 16)) >>> 0;
    if (crc !== memberCrc || size !== memberBytes % 2 ** 32) {
      fail('damaged');
      return true;
    }
    members += 1;
    state = HEADER;
    return true;
  };

  const STEPS = {
    [HEADER]: readHeader, [BLOCK]: readBlockHeader, [STORED]: copyStored, [CODES]: readCodes, [TRAILER]: readTrailer, [PADDING]: skipPadding,
  };

  const producedBytes = () => emittedBytes + (out - emittedAt);

  const takePoint = () => {
    checkMember();
    const kept = window.slice(Math.max(memberStart, out - WINDOW_BYTES), out);
    lastPointAt = producedBytes();
    onPoint({
      inputOffset: inputStart + at,
      outputOffset: lastPointAt,
      state,
      bitBuffer,
      bitCount,
      window: kept,
      codeLengths,
      isFinalBlock,
      storedLeft,
      memberCrc,
      memberBytes,
      members,
    });
  };

  const resumeFrom = (point) => {
    window.set(point.window, WINDOW_BYTES - point.window.length);
    out = WINDOW_BYTES;
    emittedAt = out;
    checkedAt = out;
    memberStart = WINDOW_BYTES - point.window.length;
    inputStart = point.inputOffset;
    emittedBytes = point.outputOffset;
    lastPointAt = point.outputOffset;
    ({ state, bitBuffer, bitCount, codeLengths, isFinalBlock, storedLeft, memberCrc, memberBytes, members } = point);
    // The point was taken from tables that were built from these lengths, so they build again.
    literals = codeLengths === null ? FIXED_LITERALS : buildTable(codeLengths.lengths.subarray(0, codeLengths.literalCount));
    distances = codeLengths === null ? FIXED_DISTANCES : buildTable(codeLengths.lengths.subarray(codeLengths.literalCount));
  };

  if (from !== null) resumeFrom(from);

  const run = () => {
    let moved = true;
    while (moved && state !== OVER) {
      moved = STEPS[state]();
      if (onPoint !== null && RESUMABLE_STATES.has(state) && producedBytes() - lastPointAt >= pointEvery) takePoint();
    }
    // Handed over at the end of every piece, not only when the window fills, so that a reader
    // waiting for one range gets it as soon as the input covers it.
    emit();
  };

  return {
    push(piece) {
      if (state === OVER) return;
      inputStart += at;
      input = at < input.length ? concatenate(input.subarray(at), piece) : piece;
      at = 0;
      run();
    },
    hasStopped() {
      return state === OVER;
    },
    finish() {
      if (state !== OVER) run();
      if (state === OVER) return { state: failure, members, bytes: emittedBytes };
      emit();
      const isWhole = (state === HEADER && at === input.length && members > 0) || state === PADDING;
      return { state: isWhole ? 'ended' : 'truncated', members, bytes: emittedBytes };
    },
  };
};

const concatenate = (first, second) => {
  const joined = new Uint8Array(first.length + second.length);
  joined.set(first);
  joined.set(second, first.length);
  return joined;
};
