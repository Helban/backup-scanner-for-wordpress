// SPDX-License-Identifier: GPL-3.0-or-later
//
// Looks for a program lying inside a file, away from its first bytes: a real picture with an
// .exe glued behind it, or put into its middle. Nothing runs such a file under its own name,
// but two lines of PHP that copy the bytes out make a program that no file in the copy shows.
// Worker side. The file passes through in pieces as it is read, so nothing is held but a few
// dozen bytes and the places still waiting for their "PE" mark.

import { PE_SIGNATURE_BYTES, PROGRAM_HEADER_REACH, holdsElfHeader, holdsPeSignature, peSignatureDistance } from './signatures.js';

const MZ_FIRST_BYTE = 0x4d;
const ELF_FIRST_BYTE = 0x7f;
// Every "MZ" whose header points at a place inside the file waits for that place to come by.
// Random data makes such a header once in tens of megabytes; a file built to make one every few
// bytes is cut off here and reported as not read through.
const WAITING_LIMIT = 4096;
const STEP_BYTES = 64 * 1024;

// `fileBytes` is the size of the whole file. Feed it the file in order, then read `found`
// ({ kind, offset } or null) and `gaveUp`.
export const createProgramScanner = (fileBytes) => {
  // Bytes from the end of what was fed so far that may still begin a header.
  let kept = new Uint8Array(0);
  let keptAt = 0;
  // offset of the expected "PE\0\0" -> offset of the "MZ" that points at it
  const waiting = new Map();
  const state = { found: null, gaveUp: false };

  const settleWaiting = (bytes, bytesAt) => {
    const end = bytesAt + bytes.length;
    for (const [signatureAt, programAt] of waiting) {
      if (signatureAt + PE_SIGNATURE_BYTES > end) continue;
      waiting.delete(signatureAt);
      if (signatureAt >= bytesAt && holdsPeSignature(bytes, signatureAt - bytesAt)) {
        state.found = { kind: 'windows_program', offset: programAt };
        return;
      }
    }
  };

  const readHeaders = (bytes, bytesAt) => {
    // A header that starts in the last bytes is read with the next piece.
    const lastStart = bytes.length - PROGRAM_HEADER_REACH;
    for (let at = bytes.indexOf(MZ_FIRST_BYTE); at >= 0 && at <= lastStart; at = bytes.indexOf(MZ_FIRST_BYTE, at + 1)) {
      const distance = peSignatureDistance(bytes, at);
      const programAt = bytesAt + at;
      // At byte 0 it is the file's own kind, which the first-bytes check names.
      if (distance === null || programAt === 0 || programAt + distance + PE_SIGNATURE_BYTES > fileBytes) continue;
      if (at + distance + PE_SIGNATURE_BYTES <= bytes.length) {
        if (holdsPeSignature(bytes, at + distance)) return { kind: 'windows_program', offset: programAt };
      } else if (waiting.size < WAITING_LIMIT) {
        waiting.set(programAt + distance, programAt);
      } else {
        state.gaveUp = true;
      }
    }
    for (let at = bytes.indexOf(ELF_FIRST_BYTE); at >= 0 && at <= lastStart; at = bytes.indexOf(ELF_FIRST_BYTE, at + 1)) {
      if (bytesAt + at > 0 && holdsElfHeader(bytes, at)) return { kind: 'linux_program', offset: bytesAt + at };
    }
    return null;
  };

  const readStep = (step) => {
    const bytes = new Uint8Array(kept.length + step.length);
    bytes.set(kept);
    bytes.set(step, kept.length);
    settleWaiting(bytes, keptAt);
    state.found ??= readHeaders(bytes, keptAt);
    const keep = Math.min(bytes.length, PROGRAM_HEADER_REACH - 1);
    kept = bytes.slice(bytes.length - keep);
    keptAt += bytes.length - keep;
  };

  return {
    // Browsers hand a file over in pieces of their own size, WebKit a whole unpacked file at
    // once. Reading in steps of one size makes the result the same everywhere and keeps the
    // copy made for each step small.
    feed(piece) {
      for (let at = 0; at < piece.length && state.found === null && !state.gaveUp; at += STEP_BYTES) {
        readStep(piece.subarray(at, at + STEP_BYTES));
      }
    },
    get found() {
      return state.found;
    },
    get gaveUp() {
      return state.gaveUp;
    },
  };
};
