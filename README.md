# Backup Scanner for WordPress

Checks a WordPress backup zip in the browser before you run the copy on your own computer.
The file is read in the tab. There is no server to upload it to.

It exists because of one job offer. A "client" sent a site export and asked for it to be run
locally. A file in `mu-plugins` renamed a 4.6 MB "JPEG" from uploads to `.exe` and started it.
Core and plugins matched the wordpress.org checksums byte for byte, so a checksum tool alone
would have said the copy was fine. The write-up is at
https://helban.dev/en/case-studies/fake-wordpress-backup-malware/.

It runs at https://helban.dev/en/wp-backup-scanner/ and, in Polish, at
https://helban.dev/skaner-kopii-wordpress/. Both pages serve the files of `scanner/` from this
repository, and `verify_live.py` lets you check that they do.

This README is the short version. [`docs/rules.md`](docs/rules.md) says how each check
decides and what was measured to back it.

## What leaves your browser

Only a worker touches bytes from the archive, and the browser gives that worker no network
at all (`Content-Security-Policy: connect-src 'none'` on its response).

To compare the copy with wordpress.org and look up known vulnerabilities, the page sends the
names and versions of WordPress, plugins and themes to api.wordpress.org,
downloads.wordpress.org and www.wpvulnerability.net, and to no other host. Every request is a
line in the scan log. One switch turns the comparison and the lookup off; with it off, nothing
at all leaves the page. A test puts a marker into a file name, PHP code and the database dump
and fails if the marker shows up in any request
([details](docs/rules.md#how-the-page-keeps-its-promise)).

## What it checks

- A file whose content does not match its name: a program, a shortcut or a script behind an
  image or text extension, PHP inside a picture, a font, a film or a PDF, PHP in uploads, a
  symlink, a path that climbs out of the folder. A file named like an image that does not start like any image
  format is amber, whatever it is. Names like `photo.php.jpg` are red.
  ([files and names](docs/rules.md#files-and-names))
- PHP lying where WordPress loads no code from, such as a cache or backup folder: amber, one
  line per folder.
- Archives inside the copy. Zips are opened one level deep and get the same checks. The end
  of every picture, font, film, sound file and PDF is read for a zip glued behind it, and the
  whole file for a program hidden inside it.
  ([archives](docs/rules.md#archives-inside-the-copy))
- The zip itself, read by a strict parser of its own: two entries with one name, a header that
  disagrees with the table of contents, a second zip in the comment. Names are read the way
  unzip programs write them, so `mu-plugins/./loader.php` is a mu-plugin.
  ([details](docs/rules.md#how-the-zip-itself-is-read))
- Core and plugin files are checked against the official checksums of wordpress.org. A changed
  core or plugin file is red; a file that matches is the official one and its other findings
  are dropped. Backups split into parts, as UpdraftPlus makes them, are
  understood too. ([details](docs/rules.md#comparison-with-wordpressorg))
- Known vulnerabilities of the core, plugins and themes, from wpvulnerability.net, and
  plugins that wordpress.org has closed. They get a list of their own and never count as red or
  amber. ([details](docs/rules.md#known-vulnerabilities))
- PHP code, read with a tokenizer checked against PHP 8.4's own on 35,771 files: ways to
  start a program (`exec()` and its relatives, callbacks, hooks, names put together at run
  time), renaming files to program names, code that decodes and runs itself, writing an
  administrator account. ([details](docs/rules.md#php-code))
- Code that WordPress loads by itself: `wp-config.php`, `.maintenance`, mu-plugins, the
  thirteen drop-ins and language files that hold more than texts. The rules are strictest
  there, and every such file is listed on the page for you to read, whatever the rules found.
  Such a file that is too large or too slow to read as code is red, because it would run
  unread. ([details](docs/rules.md#code-that-wordpress-loads-by-itself))
- Server settings in `.htaccess`, `.user.ini` and `php.ini`: a picture handed to PHP or run
  as a program, a file prepended to every request, server-side includes switched on, redirects
  to other hosts. ([details](docs/rules.md#server-settings))
- The database dump: `eval` of `base64_decode`, PHP kept by snippet plugins, scripts loaded
  from other hosts, text written for an AI assistant that reads the copy.
  ([details](docs/rules.md#the-database))
- Files from attacks described in public, matched by SHA-256 (`scanner/indicators.js`). The
  zip the original attack was sent in is on the list too, found in the copy or as the file you
  drop on the page. ([details](docs/rules.md#known-attacks))

## What the colours mean

Red means do not run this copy until you know what that file is. Amber means read that file.
"Not checked" is a list of its own: what the scanner could not look at and why (an encrypted
entry, an archive it does not open, a limit reached). Code that WordPress loads by itself is
the exception: there a file past a limit is red. "Not checked" is never folded into "nothing
found", and a result with no findings is not shown in green or called clean.

## The result

Under the verdict the page says what the result rests on: what was compared with
wordpress.org and what only the rules judged, how many of the red findings come from rules
alone (a rule can be wrong about honest code, a failed comparison cannot), and which files
always run. A finding from code or from a settings file shows the line it points at. A file
with a red finding shows its SHA-256, so it can be looked up or reported without handing the
file to anyone; a finding inside a zip found in the copy shows the hash of that zip.

The report can be copied as text or downloaded as JSON. It holds what the page shows and no
byte of the archive. E-mail addresses in it are masked (`j***@example.com`) unless you switch
that off: a file name or a quoted line can carry somebody's address, and reports get pasted
into tickets.

The button "Show me on an example" builds a small copy in the browser and scans it like any
file: a "photo" that starts like a Windows program (two letters and zeros), a mu-plugin whose
text would rename and start it, one plugin file that differs from wordpress.org. No server
holds that archive.

The sentences exist in English and in Polish (`scanner/messages-en.js`,
`scanner/messages-pl.js`), each written on its own. A page marked `lang="pl"` gets the Polish
ones.

## What it does not catch

- A payload that has to be decoded before it shows: encrypted, packed into the pixels of a real
  picture, split across PHP variables and glued at run time, or fetched from the database. The
  scanner looks for the code that would decode it, and flags `gzinflate(base64_decode(...))` as a
  shape without unpacking it.
- A way of starting a program that is not on its list. That is why every mu-plugin and drop-in
  is listed for you to read.
- Most of what a database can hide: administrator accounts added by hand, scheduled tasks,
  options holding code. A dump packed as `.sql.gz` is not opened at all.
- Code WordPress loads by itself from folders that `wp-config.php` moves elsewhere
  (`WP_CONTENT_DIR`, Bedrock's `app/`). There it is judged as code that cannot be compared.
- A mu-plugin that hands the work to another file. A file in its own subfolder is judged as
  unknown code, so a program started there is amber, not red. A file with no PHP extension,
  loaded through a variable, is not read as code at all. The mu-plugin is listed either way.
- A zip behind a compressed media file that unpacks to more than 64 MB. It lands under "Not
  checked".

A zip built on purpose to fool how names and folders are read (a decoy core named so that only
Windows unpacks it into place, folders that differ only in letter case, entries no unpacker
writes as a usable file) can take a file off the list of code WordPress loads by itself. These
cases and a few unusual site layouts make up the rest of the list, in
[docs/rules.md](docs/rules.md#what-it-does-not-catch-the-full-list).

## Check the page against this code

`verify_live.py` downloads every file of `scanner/` from a site and compares it byte for byte
with your checkout, then compares the page's security policy and the policy on the scanner's
own files with `_headers`. At helban.dev the page also loads two small scripts of the site (one
remembers in the tab where a visitor came from, one opens the mobile menu); the script lists
them with their hashes so that you can read them.

    python3 verify_live.py

## Run it

    python3 tests/serve.py

and open the address it prints. `serve.py` applies the response headers from `_headers`, the
same file Cloudflare Pages reads. `index.html` is the bare page the tests use. A page that
carries the scanner needs the elements marked `data-scanner="..."` in it and nothing else.
There is no build step: the files in `scanner/` are the files the browser runs.

## Tests

    python3 -m venv tests/.venv
    tests/.venv/bin/pip install -r tests/requirements.txt
    tests/.venv/bin/playwright install chromium firefox
    tests/.venv/bin/python -m pytest tests
    tests/.venv/bin/python tests/run_mutations.py

The tests drive the real page in a real browser. `tests/samples.py` builds every sample
archive from inert bytes: a "program" is the letters MZ and zeros. No real malware is used
anywhere. Each sample lists the exact findings it must produce. `run_mutations.py` then
switches off one check at a time in a copy of the scanner and expects the matching test to
fail, which is the proof that the test guards that check. Before the first mutation it runs
every one of those tests on the untouched scanner and stops if any fails there: a test that
fails anyway would make every mutation it guards look caught.

`SCANNER_BROWSER=firefox` or `webkit` runs the same suite there. Measured on 2026-11-18 with
Chromium 151, Firefox 153 and WebKit 26.5: 551 tests pass in all three (the one live test is
off by default), and 661 of 661 mutations are caught. The same suite can be pointed at a site
that carries the scanner, with that site's own header rules (`SCANNER_SITE_ROOT`,
`SCANNER_PAGE_PATH` and `SCANNER_SERVED`, described in `tests/serve.py`); the pages at
helban.dev are tested that way before a release. The tests never reach wordpress.org or
wpvulnerability.net; `tests/wporg.py` answers in their place, the way the real hosts answer.
One test does go out, and only when asked: `SCANNER_LIVE=1` checks that an old Elementor
release and WordPress 6.8 really come back with known vulnerabilities.

A 2 GB copy with 58,478 files took about 26 seconds in Chromium with the comparison on
([measurements](docs/rules.md#speed)).

## Third-party code

One file is not ours: `scanner/spark-md5.js` is spark-md5 3.0.2 (WTFPL or MIT), because
wordpress.org publishes core checksums in MD5 only and browsers do not compute MD5. It is the
file from https://registry.npmjs.org/spark-md5/-/spark-md5-3.0.2.tgz, unchanged, SHA-256
`87f7f7804f9e5d55782065d799d75fc8d3b324100b198d1a415632255552736d`. Plugin files are compared
by SHA-256 through the browser's own Web Crypto.

## License

GPL-3.0-or-later. See `LICENSE`.
