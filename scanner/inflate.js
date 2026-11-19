// SPDX-License-Identifier: GPL-3.0-or-later
//
// Unpacks the beginning of one deflate stream with the browser's own DecompressionStream.
// Sizes written in zip headers are never trusted: the output is counted and cut here.

const INPUT_CONSUMED = Symbol('input consumed');

// DecompressionStream unpacks every written piece whole before anyone can stop it, so packed
// data goes in slices and stops once enough came out. Written in one piece, 8.3 MB of a PHP
// file that unpacks to 8 GB took the tab from 0.5 to 8.9 GB (measured 2026-11-13); deflate
// packs at most about 1,000 to 1, so a slice this size unpacks to some 16 MB.
const FEED_SLICE_BYTES = 16 * 1024;

// Both return the first `wantBytes` of the unpacked data and how the stream behaved:
//   enough  - at least wantBytes came out
//   ended   - the stream finished cleanly with fewer bytes; `bytes` is the whole file
//   starved - the given input was a prefix and did not produce wantBytes
//   corrupt - the data is not valid deflate; `bytes` holds what came out before the error
// `compressed` is a whole deflate stream here, so it can end.
export const inflateHeadOfStream = (compressed, wantBytes) => inflateStart(compressed, wantBytes, { inputIsWhole: true });

// `compressedPrefix` is only the start of a stream, so it never ends; it can starve.
const inflateHeadOfPrefix = (compressedPrefix, wantBytes) => inflateStart(compressedPrefix, wantBytes, { inputIsWhole: false });

// The packed bytes asked for are the whole stream when they are as many as the entry declares.
export const inflaterFor = (askedBytes, declaredBytes) => (askedBytes === declaredBytes ? inflateHeadOfStream : inflateHeadOfPrefix);

const inflateStart = async (compressed, wantBytes, { inputIsWhole }) => {
  const stream = new DecompressionStream('deflate-raw');
  const writer = stream.writable.getWriter();
  const reader = stream.readable.getReader();
  const chunks = [];
  let total = 0;
  let state = 'enough';
  let feedFailed = false;

  // Each write waits until the reader has taken what the previous slice gave; once the reader
  // stops, the abort below rejects the waiting write and the loop ends there.
  const feed = async () => {
    for (let at = 0; at < compressed.length; at += FEED_SLICE_BYTES) {
      await writer.write(compressed.subarray(at, at + FEED_SLICE_BYTES));
    }
    if (inputIsWhole) await writer.close();
  };
  // A failed write also errors the readable side, where the loop below records it.
  const inputConsumed = feed().then(
    () => INPUT_CONSUMED,
    () => { feedFailed = true; return INPUT_CONSUMED; },
  );

  try {
    while (total < wantBytes) {
      const pending = reader.read();
      // With a prefix the stream never ends, so "no more output" has to be seen another way.
      // Once the write has settled, everything this input can produce is already queued, and
      // a read from a non-empty queue is resolved on the spot. `pending` is listed first, so
      // it wins the race whenever a chunk is there; the marker wins only on an empty queue.
      const step = inputIsWhole ? await pending : await Promise.race([pending, inputConsumed]);
      if (step === INPUT_CONSUMED) {
        state = feedFailed ? 'corrupt' : 'starved';
        break;
      }
      if (step.done) {
        state = 'ended';
        break;
      }
      chunks.push(step.value);
      total += step.value.length;
    }
  } catch (error) {
    // DecompressionStream reports bad or truncated deflate data as a TypeError.
    if (!(error instanceof TypeError)) throw error;
    state = 'corrupt';
  }

  await Promise.allSettled([reader.cancel(), writer.abort()]);
  return { state, bytes: joinChunks(chunks, Math.min(total, wantBytes)) };
};

// Unpacks a whole deflate stream into memory and gives up as soon as the output passes
// `limitBytes`. The pieces are returned as they came, so the caller can wrap them in a Blob
// without copying them into one block first.
//   whole     - the stream ended cleanly within the limit
//   too_large - cut at the limit; `bytes` is how far it got
//   corrupt   - not valid deflate data
export const inflateAll = async (packed, limitBytes) => {
  const reader = packed.stream().pipeThrough(new DecompressionStream('deflate-raw')).getReader();
  const chunks = [];
  let bytes = 0;
  try {
    for (;;) {
      const step = await reader.read();
      if (step.done) return { state: 'whole', chunks, bytes };
      bytes += step.value.length;
      if (bytes > limitBytes) {
        await reader.cancel();
        return { state: 'too_large', chunks: [], bytes };
      }
      chunks.push(step.value);
    }
  } catch (error) {
    if (!(error instanceof TypeError)) throw error;
    return { state: 'corrupt', chunks: [], bytes };
  }
};

const joinChunks = (chunks, length) => {
  const joined = new Uint8Array(length);
  let at = 0;
  for (const chunk of chunks) {
    if (at >= length) break;
    const part = chunk.subarray(0, length - at);
    joined.set(part, at);
    at += part.length;
  }
  return joined;
};
