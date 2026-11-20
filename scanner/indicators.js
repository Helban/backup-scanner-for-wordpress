// SPDX-License-Identifier: GPL-3.0-or-later
//
// Files and names from attacks that have been described in public. Data only; the
// table is a module and not a JSON file for the same reason as code-rules.js (the
// worker has no network). Every row names where it was published.
//
// A hash says "this exact file"; a name says "this campaign's habit" and is weaker, because
// renaming costs nothing. So a hash is red and a name is amber.

// The campaign behind the fake WordPress backup sent to freelancers in November 2026:
// https://helban.dev/en/case-studies/fake-wordpress-backup-malware/
// Its sentence is in messages-en.js and messages-pl.js (CAMPAIGN_TEXT), on the page side.
const FAKE_BACKUP_2026 = 'fake_backup_2026_11';

// SHA-256 of whole files. The size comes first, so only files of exactly that size are hashed:
// files inside the copy (also a zip lying in it) and the file the visitor chose.
// `role` is what the file was in its campaign, for the sentence: the archive that was sent, or
// a file found inside it.
export const KNOWN_FILES = [
  {
    campaign: FAKE_BACKUP_2026,
    role: 'payload',
    bytes: 4_643_720,
    sha256: '3c3d0c4a00fb325dad6623813dabd07eb8e715fdd29230d2a3b9fed8f9c474bf',
  },
  // The zip that was sent (named Archive.zip, too common a name to list), from VirusTotal's
  // report of this hash on 2026-11-20, which 24 of 59 engines flagged.
  {
    campaign: FAKE_BACKUP_2026,
    role: 'archive',
    bytes: 89_770_565,
    sha256: '49163178348bd8f41c293c47e814d3c50de8ba66ba69e453110d9a3b4014245c',
  },
];

// The end of a path, compared in lower case at a folder boundary.
export const KNOWN_NAMES = [
  { campaign: FAKE_BACKUP_2026, pathEnd: 'wp-content/mu-plugins/custom-fields-handler.php' },
  { campaign: FAKE_BACKUP_2026, pathEnd: 'product-detail-mockup-soft-blue-background.jpeg' },
];
