// SPDX-License-Identifier: GPL-3.0-or-later
//
// MD5, needed because wordpress.org publishes the core checksum list in MD5 only. The hashing
// itself is spark-md5 3.0.2, kept byte for byte as published (source and hash in README.md).
// It puts itself on the global object instead of exporting, so this module hands it on.

import './spark-md5.js';

const { SparkMD5 } = self;

export const createMd5 = () => {
  const state = new SparkMD5.ArrayBuffer();
  return {
    // spark-md5 reads the whole ArrayBuffer behind a view, so each piece is copied out exactly.
    add(bytes) {
      state.append(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength));
    },
    hex: () => state.end(),
  };
};
