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
repository, and `verify_live.py` lets you check that they do (see "How the page keeps its
promise").

## What it checks today

Every file's first 4 KB are unpacked and compared with what the name promises. A Windows,
Linux or macOS program, a shortcut or a script behind an image or text extension is red. So is
PHP inside a picture, a font, a film or a PDF (at its start or at its end, in any letter case
of the `<?php` tag), PHP in uploads, a symlink, a path that climbs out of the folder, and
an archive named like a photo, a font, a video or a PDF. PHP inside a text file (`.md`,
`.txt`, `.html` and the like) is red in uploads and amber among the code of a plugin, a theme
or the core: documentation is full of PHP examples, and a text file runs only when code
includes it. A build script (`.sh`, `.bat`, `.cmd`, `.ps1`) among such code is amber as well;
a program is red wherever it lies. The same colours go to `.cgi`, `.pl`, `.asp` and `.shtml`
files: XAMPP's web server runs those by itself when their address is opened (its `httpd.conf`
hands the first three to CGI and filters the fourth for include commands), no `.htaccess`
needed. UpdraftPlus ships one Perl script, which is why such a file is amber among a plugin's
code and red anywhere else. One exception for uploads: plugins
write an `index.php` there that holds only a comment ("Silence is golden"), so nobody can list
the folder. A PHP file with no statement in it runs nothing and is left alone.

The same question is also asked the other way round. A file named like an image has to start
like some image format, any of ten. If it does not, it is amber, whatever it is. That covers
what no list of known signatures can: a payload that is encrypted, or of a kind nobody listed.
A PNG saved as `photo.jpg` passes, because that is common and harmless.

Names are read for two more tricks. `photo.php.jpg` is red: Apache set up with `AddHandler`
runs it as PHP whatever comes last, and none of the 52,000 files in the test copies is named
like that. `banner.jpg.php` is amber, because only a person is fooled by it. Audio and video
names are left out of the second rule: WordPress itself ships `module.audio.mp3.php`.

PHP that lies outside the folders WordPress loads code from (a cache folder, a backup folder,
`.well-known`, a folder next to the site) is amber, one line per folder. So is PHP lying
directly in `wp-content` that is not a drop-in, and PHP in a folder below `wp-content/languages`
unless its name ends in `.l10n.php`, the ending of translation files. It runs only when
something includes it or a request names it, so it is something to read. A file that only
holds comments, or exits before anything else (Wordfence and W3 Total Cache keep their data
that way), is left alone. A copy of `wp-content` without its core, such as a `staging` folder,
is judged from its own folder: its plugins are not loose PHP, but a PHP file lying beside its
`wp-content` is, since no part of WordPress lies there. A site that keeps WordPress in a folder
of its own (`wp/`) has its front `index.php` in the folder above, a `define` and a `require`
that load `wp/`. That file gets an amber line too.

Zips found inside the copy are opened one level deep and their contents get the same checks.
A finding there reads `uploads/2025/12/assets.zip » mockup.jpeg`. Office documents are zips
too, so they are opened as well.

A zip can also sit behind a real picture. The file starts as a JPEG and a viewer shows the
photo, while an unzip tool finds the archive at the end. So the end of every picture, font,
film, sound file and PDF is read as well. The four bytes that mark the end of a zip turn up
by chance in about one scan in seven of a library with 10,000 photos, so on their own they
only make a candidate. It turns red once the table of contents lies where those bytes point,
and the archive's contents then get the same checks as any zip inside the copy
(`hero.jpg » setup.exe`). Bytes added after the zip do not hide it: Python's zipfile and
Info-ZIP's unzip both open such a file anyway. Neither does an archive too big to open (more
than 50,000 entries): it is red and listed under "Not checked" with the reason.

A program can sit behind a real picture the same way, or in the middle of one. Nothing runs
it under that name, but two lines of PHP that copy the bytes into a new file make a program
that no file of the copy shows. So every such file is read from its first byte to its last,
and a program header anywhere in it is red. The two letters `MZ` that open a Windows program
turn up in any data once in 64 KB, so they are not enough: the field at byte 60 of the header
has to lead to the mark `PE\0\0`, the way Windows itself checks it. A Linux program is told by
seven fixed bytes. None of the 4,240 pictures in the test copies has either. A file built to
wear this search out, with thousands of headers that each point further on, is listed under
"Not checked".

The zip itself is read by a parser written for this purpose, because the usual libraries are
forgiving and a scanner must not be. A zip describes each file twice, and an archive can be
built so that the scanner sees one file and your unzip program writes another. Two entries
with one name, a header that disagrees with the table of contents, a second name in an extra
field, two end records, a whole second zip hidden in the comment of the end record (Python's
zipfile opens that one instead), bytes that belong to no listed file: each of these is a finding.

Names are read the way an unzip program writes them. Info-ZIP's `unzip`, Python's zipfile,
PowerShell's `Expand-Archive` and the `tar.exe` of Windows all write `mu-plugins/./loader.php`
and `mu-plugins//loader.php` as `mu-plugins/loader.php`, and the two from Windows do the same
with `mu-plugins\.\loader.php`. Python's zipfile and `tar.exe` also write `loader.php/.` as
`loader.php`, and `tar.exe` drops the dot of a folder named `mu-plugins.` and the space at the
end of `loader.php `. Where the programs disagree (Info-ZIP writes `loader.php/.` as
`loader.php/_`), the scanner reads the name the way that puts a file where WordPress runs it. So
the checks see a mu-plugin there, while the page names the file as the zip holds it. The same goes
for the names inside a zip found in the copy. Two entries that land on one name count as two
entries under one name. A name with `..` keeps it: such a file is red anyway, as a name that
climbs out of the archive, though Info-ZIP and Python drop the `..` and write it lower down.

The other direction matters as much. A file that keeps another off the list below, such as the
`wp-config.php` of the folder WordPress runs from, counts only where every one of those programs
writes it. On Linux, Info-ZIP and Python write `wp-config.php.` and `wp./wp-config.php` as named
and keep a backslash inside a name. So a decoy spelled one of those ways cannot take off the list
the `wp-config.php` that WordPress on Linux runs. Until
2026-11-18 one empty file named `wp/wp-config.php.` did that, and the red finding of the
real one went with it. A name with a backslash still counts in a zip that writes every name that
way, as Windows tools do.

## Comparison with wordpress.org

wordpress.org publishes a checksum for every file of every WordPress release and of every
plugin version in its directory. The scanner reads the core version and language from
`wp-includes/version.php` and each plugin's version from its main file, asks for those lists,
and hashes the files in the copy. A core file that differs is red. So is a file in `wp-admin`
or `wp-includes` that the release does not have, when it is named as PHP or holds PHP; a log
or a settings file left there by a host is amber. A changed plugin file is red, and so is a
file with PHP code that the plugin's release does not have. Missing files and extra files
without code are amber.

A file that matches is the official file, and what the other checks said about it is dropped.
On a test site with 30 popular plugins, 22 official files draw a finding by type alone: 19
README and documentation files with PHP examples, three build scripts. All 22 match
wordpress.org, so none of them is shown.

A plugin wordpress.org does not know (premium, custom, or closed) cannot be compared. It is
listed under "Not checked" with the reason, and its files keep the verdict of the other
checks. The same happens when wordpress.org cannot be reached, answers with something
unusable, or the limit of 150 requests per scan runs out. Each case has its own sentence.
One scan compares 300 plugins at most; a copy with more gets one line under "Not checked"
with the number left out.
Those 22 files are why documentation and build scripts among code are amber and not red:
scanned with the comparison off, the same healthy site has no red finding.

A copy can hold more than one WordPress, a `blog/` or `staging/` folder with a site of its
own. The one nearest the top of the archive is compared. Every other one is named under "Not
checked", and its mu-plugins and drop-ins are judged as code that WordPress loads by itself all the same.
A copy of `wp-content` without its core, a folder holding a `wp-content` but no `wp-includes`,
gets the same line too: its plugins are compared with nothing. In an archive with no core at all,
the site is the folder holding the shallowest `wp-config.php` outside any `wp-content`. With no
such file, it is the shallowest copy of `wp-content`. Either way it gets no such line, and its
plugins are compared. A backup of `wp-content` alone is compared too; until 2026-11-18 the page
said it did not look like WordPress and compared nothing in it. A site that
keeps its core in
a folder of its own (`wp/`) with `wp-content` in the folder above has its plugins and the themes
bundled with the core compared from there.

A backup can also come in parts. UpdraftPlus packs the plugins, the themes, the uploads and the
rest of `wp-content` into a zip each, and every zip holds its folder by name with no `wp-content`
above it: `plugins/akismet/...`, `mu-plugins/...`, drop-ins at the top. A zip whose top holds a
folder named `plugins`, `themes`, `uploads`, `mu-plugins` or `languages`, or a file named like a
drop-in, is checked as the inside of `wp-content`. Its plugins are compared, its mu-plugins and
drop-ins count as code that WordPress loads by itself, and PHP in its `uploads` is red. The page
names it under "Not checked", because the other parts were not in the file. Cut from the test
site with 30 plugins, the plugins part used to give 23 red findings and compare nothing; now all
31 plugin folders in it are compared and nothing is red. A zip that also holds a core, or a name
that climbs out of the archive, is read as written. So is a zip that, read as the inside of
`wp-content`, would take any file off the list of code WordPress loads by itself, such as a
`./wp-config.php` beside a `plugins` folder or a site without its core kept in a folder named
`plugins`. The one exception is a file inside the folder of a single plugin, theme or mu-plugin:
Duplicator keeps a template `wp-config.php` deep in its folder, and W3 Total Cache keeps the
drop-ins it installs in a `wp-content` folder of its own. WordPress loads neither from there. A
`wp-config.php` or `.maintenance` lying directly in such a folder does not count as the plugin's,
since no plugin or theme in the test archives keeps one there.

The comparison and the vulnerability lookup below share one switch. With it off, nothing at
all leaves the page.

## Known vulnerabilities

The core version and every plugin and theme with a readable version are looked up at
wpvulnerability.net, a free database that gathers entries from CVE, EUVD, JVN, Patchstack,
Wordfence and WPScan. For a plugin or a theme only the name is sent. The database answers with every
entry it holds for that name, and the browser decides which ones cover the version in the
copy. It decides the way PHP's `version_compare()` does, because the database states its
ranges in those terms and its own WordPress plugin uses that function. The tests hold PHP
8.4's answers for 3,136 pairs of versions, and the scanner has to give the same ones.

These entries get a list of their own and never count as red or amber. An old plugin is a
reason to update, not a trap. Each entry shows its CVE or EUVD number, the affected versions
and the release that fixed them, the CVSS score, the weakness type, and links to cve.org,
Wordfence, Patchstack or WPScan. Descriptions are left out on purpose: each source keeps its
own terms for its texts.

The plugin directory is asked about every plugin as well. A closed plugin can still have its
checksums served: display-widgets was closed in 2021 for a security issue, and wordpress.org
still returns the checksums of its version 2.7. Such a plugin is named as closed, with the
date and the reason wordpress.org gives, also when the copy does not show its version. When
the vulnerabilities come back but the directory does not answer, only "is it closed?" goes
under "Not checked".

If the database cannot be reached, says it is out of service, sends something unusable, or
the request limit runs out first, that goes under "Not checked" with the reason. "None
known" and "not asked" never look the same.

The database also publishes audits of plugins whose ownership was hijacked. The scanner
leaves those out for now. On 2026-11-13 two of the 39 plugins measured had one, and one of
the two was WPForms Lite: marked suspicious for every release since 1.10.2.1, with no
indicator of compromise found. Shown as it stands, that would put a warning on every WPForms
Lite release from 1.10.2.1 on, with nothing found to back it.

## PHP code

Every PHP file that was not proven official is read as code. The scanner splits it into
tokens with its own small reader, so `exec()` inside a comment, a method that happens to be
called `exec` and a function merely defined under that name do not count. No regular
expression runs over the file.

The reader has to agree with PHP about what is code. If it takes a call for part of a comment
or a string, no rule sees that call. It is checked against PHP itself: PHP 8.4's own
`token_get_all` and this reader are run over 35,771 honest PHP files, and the names and
variables each of them reads as code must be the same list (7.9 million of them; they are).
The places where they once differed are test samples now: a one-line comment ended by a lone
carriage return, quotes inside `{$...}` in a string, code inside those braces,
`__halt_compiler` used as a property name, a short tag that starts with `xml`.

What PHP takes for code also depends on one setting of the computer the copy lands on.
With `short_open_tag` on (the official WordPress Docker image), a bare `<?` opens code; with it
off (the `php.ini` meant for production), it is text, and so is `<?php` followed by a form feed.
A file can be built so that its code sits in a comment under one setting and runs under the
other: `<? /* ?><?php system('id'); // */` runs `system` only with short tags off. So a file
whose tags could be read both ways is read both ways, and a finding in either reading counts.
The check against PHP runs under both settings too, on the same 35,771 files.

What it looks for is a way to start a program on the computer the copy lands on. There are
more ways than names. `exec()` and six similar functions by name, a command in backticks,
`new COM`, `new DOTNET`, FFI, `putenv()` with `LD_PRELOAD`, `expect`. Or the same function
reached sideways: `call_user_func('system', ...)`, `array_map`, `ob_start`, a shutdown
callback, `ReflectionFunction`, a WordPress hook (`add_filter('hook', 'system')`), a
function imported under another name (`use function exec as tidy`), a variable that holds
the name. Most sideways routes have to spell the name somewhere, so the name standing as a
string counts too. Names
are put together before they are compared: `'ex' . 'ec'`, `strrev('metsys')`, `chr(115)`,
`base64_decode`, `str_rot13`, `hex2bin` and escapes such as `"\x65"`.

Where the file lies decides the colour. `wp-config.php`, the site's `.maintenance`, a mu-plugin,
a drop-in or a language file is code that WordPress loads by itself, with nothing to switch on
in wp-admin. The text below says "mu-plugin" for all five. Any of these routes there is red,
and a call whose target the file never spells is amber: `$handler()` with `$handler` read
from the database, `$handlers[0]()`, `get_handler()()`, or a variable handed to `array_map`
as the callback.
WordPress runs only the `.php` files that lie directly in `mu-plugins`. A file in a subfolder
runs when one of them includes it, so it is judged like other code that cannot be compared.
WordPress requires the `.maintenance` lying beside `wp-settings.php` as PHP on every request
except during installation, before the rest of the site and whatever the file says. It has no
PHP extension, so the scanner names it to read it as code. It counts in a folder WordPress runs
from: one with a core in it, wherever it lies, or one holding a `wp-content` without a core,
where the core would go. The folder above a core kept in a folder of its own (`wp/`) is not one
of them. `wp-config.php` counts in the same folders. It also counts in the folder above one of
them when `wp-load.php` reads it from there, which it does when the folder WordPress runs from
has no `wp-config.php` of its own and the folder above holds no `wp-settings.php`. Both names
count in any letter case, since Windows finds the files that way. A file that keeps the one above
off the list, the folder's own `wp-config.php` or a `wp-settings.php` above, has to carry the
file name in lower case, because Linux reads no `WP-Config.php`, and has to be written the way
every unpacker writes it (see the names, above). A file of either name anywhere else, a
plugin's folder or a backup folder, is never read that way and is judged like other code that
cannot be compared.
A drop-in is a file of one of thirteen names lying straight in `wp-content` (`_get_dropins()`
in `wp-admin/includes/plugin.php`). Six run on every request: `db.php`, `object-cache.php`,
`secrets.php` (from WordPress 7.2, not yet released on 2026-11-16) and
`fatal-error-handler.php`, plus `advanced-cache.php` with `WP_CACHE` on and `sunrise.php` on a multisite with `SUNRISE` defined. The other seven run
in a situation of their own: `db-error.php` when the database cannot be reached,
`maintenance.php` while `.maintenance` says an update began less than ten minutes ago,
`install.php` whenever WordPress or a plugin loads core's upgrade code (installation and the
database upgrade both do), `php-error.php` on a fatal PHP error, and three `blog-*.php` files for
a site of a network that is deleted, not activated, archived or marked as spam. A copy started
on a new machine has no database until you
connect one, and its `.maintenance` says whatever its author wrote, so all thirteen count. Any
other PHP lying in `wp-content` runs only when something includes it or a request names it, and
is judged like PHP outside the code folders.
WordPress also runs PHP from its languages folder: `wp-content/languages`, or
`wp-includes/languages` when the first does not exist (`wp_set_lang_dir()`). The scanner counts
the second only when the site's `wp-content` has no `languages` folder in lower case, the only
spelling Linux finds. An empty `languages` folder kept in the archive counts as one. For a core kept in a folder of its own (`wp/`), the
`wp-content` looked at is the one in the folder above.
WordPress requires the file named
after the site's language, such as `pl_PL.php`, on every request. The scanner cannot know the
language, so any PHP lying directly in the folder counts. Translation files (`.l10n.php`) there
and in its `plugins` and `themes` folders are included whenever their texts are needed, and the
update checks include every one of them. A translation file holding only its texts is data and
stays off the list: the words `return` and `NULL`, strings, and the symbols `[ ] => , . ;`,
which is all that the 314 translation files in the test archives hold. Each of them starts with
`<?php` and none closes the tag, and so must a file taken for data: text outside the tags is
printed into every page, a `<script>` line included. A translation file with anything more in
it, such as a call or a string that reads a variable, counts like a mu-plugin.
These places come from a list of every `include` and `require` in WordPress 7.1.4, read with
PHP's own tokenizer: 1,397 of them, 101 with a path that is not written out, each read by hand.
Apart from the files named above, WordPress runs nothing outside its core, plugins and themes by
itself. One more file looks like it, `wp-content/upgrade/version-current.php`, but a core update
deletes the copy's own file before it writes and runs one of its own.
In other code that cannot be compared, such as a premium plugin or your own theme, honest
authors do use some of them: backup and file-manager plugins call `exec()`. There they are
amber. Red is kept for the routes that no honest file in the measurement below used: FFI, a
loader variable in `putenv()`, `expect`, and the WScript.Shell and Shell.Application objects.

Renaming is the other half. A mu-plugin that renames or copies files and names a program
file (`.exe`, `.bat`, `.scr` and eleven more extensions) anywhere in its code is red. That is
the shape of the original attack, where the names sat in variables and no single line looked
like "rename to exe". In any other unknown code a rename or copy to a program name within one
call is red. A mu-plugin that only moves files around in uploads is amber.

A mu-plugin that loads a file not named like PHP is amber, as in
`require WP_CONTENT_DIR . '/cache/object.bin'`. PHP runs the code in an included file whatever
its name, and the scanner reads only files with a PHP extension as code. It looks at the end of
the path written in the `include`; when the path ends in a variable or a function call, the
name is not in the file and nothing is said. Of the 35,094 honest PHP files, 20 include
something else: stylesheets, SVG icons, HTML and JSON in plugin templates, and core's own
`.maintenance` file. None of those 20 is a mu-plugin or a drop-in.

Every `wp-config.php` and `.maintenance` that counts as above, every mu-plugin and drop-in, and
every language file that is more than texts, is also listed on the page, whatever the rules
said. PHP can start a program in more ways than any list holds, and these files are where it
matters.

These colours were checked against 64 honest files of that kind: the drop-ins of 21 plugins
from wordpress.org (page cache, object cache, database) and the mu-plugins that Bedrock,
Kinsta and WordPress VIP publish. None of them is red. Those drop-ins are `advanced-cache.php`,
`object-cache.php` and `db.php`. The 71 test archives hold no file of the other ten drop-in
names, no `.maintenance` and no language file named like `pl_PL.php`, so their colours rest on
the rules alone. All 314 translation files in them are data, 32 of them in a languages folder.
WP Super Cache keeps its
settings in `wp-content/wp-cache-config.php`, which is PHP but not a drop-in, so a copy with that
plugin shows one amber line for the `wp-content` folder. Three changes got it there: the
subfolder rule above, `eval` on its own going to amber, and one narrowing. The Redis Object
Cache drop-in writes `'exec'` into a variable and only ever calls it as a method
(`$tx->{$method}()`), because Redis has a command of that name. A name used only like that no
longer counts.

Code that hides itself is the third part. Red, wherever the file lies: `eval`, `assert` or
`create_function` with a decoding call or a decoded string inside; a string that reads
`<?php`, calls `eval` or starts a program only once it is decoded (a long run of base64
characters is decoded to find out); `__halt_compiler()` together with the constant that points
at the data behind it. None of the 35,094 honest PHP files measured did any of these. The
same goes for a string that is a Windows or Linux program once decoded, with the full header
described above: red wherever it lies, no honest file had one. A string that decodes to a zip,
gzip, 7z or other archive is red in a mu-plugin and amber elsewhere. A
decoder fed straight into another one (`gzinflate(base64_decode(...))`) and a string spelled
with eight or more `chr()` calls are red in a mu-plugin and amber elsewhere. In a mu-plugin,
`eval` on its own and a variable with a computed name (`$$name`) are amber. The Batcache
drop-in runs `create_function` on its own settings, and the `wp-config.php` of the official
WordPress Docker image runs `eval` on its `WORDPRESS_CONFIG_EXTRA` setting, so a copy made from
that image shows that amber. Elsewhere honest code uses both often enough (28 and 44 files) that
they say nothing.

Two things a backdoor tends to do: write an account with the administrator role, and hide
itself from the plugin list in wp-admin. The first is red in a mu-plugin and amber in other
unknown code, where WordPress's own installer and a migration plugin's user import do it too.
The second, a filter on `all_plugins`, is amber in a mu-plugin and ignored elsewhere, because
Akismet and WooCommerce both use that filter.

## Server settings

The copy brings its own `.htaccess`, `.user.ini` and `php.ini` files. Apache, which XAMPP
runs, obeys `.htaccess`; PHP run through FastCGI obeys `.user.ini`. Both can make code run
that no mu-plugin names. The scanner reads every such file that no official release proved:

- `auto_prepend_file` or `auto_append_file` pointing into uploads, at a file that is not PHP,
  or at an address is red. Pointing at an ordinary PHP file is amber; that is exactly how
  Wordfence sets up its firewall.
- A PHP handler given to other extensions (`AddHandler application/x-httpd-php .jpg`), or to
  every file of a folder (`SetHandler` outside a `<FilesMatch>` that names only PHP), is red.
  The lines hosting panels write to choose a PHP version pass.
- Files handed to the server to run as programs (`AddHandler cgi-script .gif`, `SetHandler
  cgi-script`) are red, and so are server-side includes switched on (`AddOutputFilter INCLUDES
  .html`). XAMPP 8.2.12 allows both in its web folder by default (`Options ... Includes ExecCGI`,
  `AllowOverride All`), and Apache with those options ran a `.gif` shell script and an
  `<!--#exec -->` line from nothing but the `.htaccess`. A file that switches `ExecCGI` or include
  commands off outside any section gives nothing: Wordfence writes exactly that into uploads.
  A switch-off inside a section does not count. Apache ran the `.gif` with `Options -ExecCGI`
  wrapped in an `<IfModule>` for a module it lacks, in `<Files decoy.txt>`, and with a
  `<Files "*.gif">` section switching on again what the top of the file switched off.
- A redirect to a host other than the site's own address in the database is amber. The log
  names the hosts the dump gave as the site's own, because whoever made the copy can add one.

A line that ends in a backslash continues on the next one, as Apache reads it.

The test site with 30 plugins holds 45 `.htaccess` files, written by WordPress and by cache,
backup, form and firewall plugins. With the comparison switched off the scanner reads all 45,
and none of them gives a finding. None of the 154 settings files in the test copies mentions
CGI or server-side includes at all.

## The database

The dump is read as a stream, piece by piece, so a dump of a gigabyte is never held whole.
Red: `eval` of `base64_decode` stored anywhere in it. Amber: PHP kept by snippet plugins
(WPCode rows, a Code Snippets table, either plugin active), plugins the database calls active
whose folder the copy lacks, `<script src>` pointing at hosts other than the site's own, and
sentences written for an AI assistant that reads the copy ("ignore previous instructions").
Those sentences are looked for in PHP files and in the first bytes of text files too. The
names of AI models are not: WordPress 7 ships an AI client of its own and translations that
name them.

A copy without a dump gets that said under "Not checked", and so does a dump inside a zip found
in the copy: the database checks need the site around the dump, its plugins and its address.

## Known attacks

`scanner/indicators.js` lists files from attacks that have been described in public. A file
of the listed size is hashed with SHA-256, and a match is red. A listed name is amber, because
renaming costs nothing. The list starts with the attack this scanner was written after.

A PHP file is read up to 8 MB and a million tokens, for at most 2 seconds. Past a limit it
lands under "Not checked" with the limit named. Files built to slow a scanner down (a million
brackets, a string of megabytes, comments with no closing tag after them) are part of the
tests, and in all three browsers each must finish inside the 2 seconds. Run through the same
code in Node, none of them took more than 200 ms.

## What it says when it could not look

"Not checked" is its own list, next to red and amber, and it is never folded into "nothing
found". An encrypted entry lands there. So does a 7z, RAR, tar, gzip, bzip2, xz, zstd, cab,
`.wpress` or phar archive (only zip is opened), a zip inside a zip inside the copy, and
anything past a limit: 64 MB unpacked per nested zip, 512 MB and 60 seconds for all of them,
200 nested zips, 50,000 entries in one. The finding names the limit. Reading media files
through has 60 seconds of its own; files it did not reach are counted there too.

A result with no findings is not shown in green and is not called clean.

## What it does not catch

- A zip glued behind a compressed media file that unpacks to more than 64 MB. It has to be
  unpacked whole to be opened, so it lands under "Not checked" instead.
- A payload hidden inside a file that really is what its name says, when it is encrypted,
  compressed or packed into the pixels. A program with its header intact, a zip at the end and
  PHP at the start or the end are found; anything that has to be decoded first is not. The
  code that would decode it is what the PHP checks look for.
- A program kept in PHP in a form the scanner does not decode: split across several variables
  and glued at run time, compressed before it was encoded, or fetched from the database.
- PHP in a file whose extension says nothing (`.bin`, `.dat`, no extension), loaded by a
  mu-plugin through a variable (`include $file;`) or a function call. A path written out in the
  `include` itself is amber. The mu-plugin is listed for reading either way.
- A mu-plugin that hands the work to a file in its own subfolder. That file is judged as
  unknown code, so a program started there is amber, not red. The mu-plugin itself is listed
  for reading.
- A site whose core in `wp/` keeps a `wp-content` of its own while `wp-config.php` points
  WordPress at the `wp-content` in the folder above, as Composer setups do. The archive cannot
  say which one is live, so the folder above is named as a copy that was not compared, and its
  `.maintenance` is listed.
- A WordPress kept inside another one's `wp-content`. Its `wp-config.php` and `.maintenance` are
  listed, but its mu-plugins and drop-ins are judged as code that cannot be compared.
- Folder names that differ only in letter case, such as `Files/` and `files/`, are taken for one
  folder, as Windows takes them. On Linux they are two, and a `wp-config.php` in one of them can
  take off the list a file that WordPress on Linux reads.
- A file that keeps another off the list but that no unpacker writes as a usable file: an entry
  with a broken local header, a compression method or encryption the unpacker refuses, a name
  in the Unicode path field that differs from the main one, or a file named `languages` before a
  folder of that name. Most of these are named on the page as not checked; the last one is not.
- An archive that mixes entries made on Windows and on Linux. Info-ZIP turns `\` into `/` only
  for entries marked as made on Windows, so a name with `\` can keep a file off the list that
  Info-ZIP still writes where WordPress runs it.
- A decoy core, a `version.php` named so that only Windows writes it into `wp-includes`, can move
  the folder WordPress runs from and take that folder's `.maintenance` or `wp-config.php` off the
  list.
- A zip made by macOS Finder. Its `._` twins under `__MACOSX/` take no part in finding the site,
  but the twin of a mu-plugin or a language file is listed, and the twin of a picture gets the
  amber line for a picture that is not one.
- A site with no core whose `wp-config.php` lies in the folder above its `wp-content`, out of the
  web root. The folder of the `wp-config.php` is taken for the site, and the `wp-content` below it
  is named as not compared.
- A site with its core in `wp/` and a second WordPress at the same depth, such as `blog/`. The
  one the zip lists first is compared, and the other is named as another WordPress.
- A zip that is no WordPress at all but holds a folder named `plugins`, `themes`, `uploads`,
  `mu-plugins` or `languages`, or a file named like a drop-in (`db.php`, `install.php`), at its
  top. It is checked as the inside of `wp-content`, and the page says it looks like one.
- A part of a split backup whose plugin keeps a copy of the WordPress core in its folder, or
  that holds a name climbing out of the archive. The part is read as written: its plugins are
  not compared, and its mu-plugins and drop-ins are judged as code that cannot be compared.
- Two entries that land on one name once unpacked, such as `tool.php` and `./tool.php`. The
  pair is red as two entries under one name. Their other findings share that one name, a twin of
  a file that matches wordpress.org is passed over with it, and neither gets a SHA-256.
- A file whose own name holds ` » `, the separator this page puts between an archive and a file
  inside it. Where both readings are possible, the page takes the name for a file inside an
  archive. A finding about such a file names it as the zip writes it, but one about a folder with
  ` » ` in its name can be shown glued to the written name of another entry. Two files built to
  be shown under one such path can both show the hash of one of them.
- The SHA-256 of an archive found in the copy is shown on the first 300 red findings inside it;
  rows past that show none.
- A `wp-content` folder kept inside the folder of a plugin or a theme in such a part, as W3 Total
  Cache keeps one. Its mu-plugins and drop-ins are that plugin's files, the same as in a full
  copy, so they are judged as code that cannot be compared and are not listed.
- A part of a split backup whose names are written with backslashes. It is checked as the inside
  of `wp-content`, but its plugins are not compared.
- Code WordPress loads by itself from a folder that `wp-config.php` moves elsewhere
  (`WP_CONTENT_DIR`, `WPMU_PLUGIN_DIR`, `WP_LANG_DIR`; Bedrock's `app/` is one). The scanner
  knows those files by the folder names `wp-content`, `mu-plugins` and `languages`, so in a moved
  folder they are judged as code that cannot be compared. `wp-config.php` itself is listed.
- A copy whose zip names every folder with a backslash, as some Windows tools write it. It is
  not compared with wordpress.org and the page says it does not look like WordPress, though its
  `wp-config.php`, `.maintenance`, mu-plugins, drop-ins and language files are still judged as
  code that WordPress loads by itself.
- A launch name kept for a method whose class turns method calls into function calls
  (`__call`). The call through a variable inside it is still amber in a mu-plugin.
- A way of starting a program that is not on the list. That is why every mu-plugin and
  drop-in is listed for reading, whatever the rules found.
- What packed code says once unpacked. `gzinflate(base64_decode('...'))` is flagged as a
  shape, but the scanner does not inflate the payload to read it.
- Most of what a database can hide: administrator accounts added by hand, scheduled tasks,
  options holding code. Only the checks listed above run on the dump. A dump packed as
  `.sql.gz` is not opened at all and lands under "Not checked".

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

## How the page keeps its promise

Only a worker touches bytes from the archive. Its response carries
`Content-Security-Policy: connect-src 'none'`, so the code that reads your file has no way to
talk to the network. The page's own policy allows three hosts (api.wordpress.org,
downloads.wordpress.org, www.wpvulnerability.net) and nothing else: no analytics, no fonts
from a CDN, no images from elsewhere.

A test holds the page to that. It puts a marker into a file name, into PHP code and into the
database dump, records every request the page makes from loading to the report, and fails if
the marker shows up in any address, header or body, or if a request goes to any other host. A
copy of the page altered to send file names to api.wordpress.org, a host it may call, fails
that test.

All requests go through one function in `scanner/gateway.js`. It gets a plugin's folder name
and version from the worker, checks them against fixed formats (a folder name that cannot be
a wordpress.org slug is never sent), and fills them into one of six fixed address templates.
Every request is a line in the scan log, and the report lists the addresses. What comes back
is checked against a fixed shape too, before the worker or the page uses any of it.

The worker sends the page events of a fixed shape, and the page rejects any other. File names
come from whoever built the archive, so they are shown as text only, with control and
direction-override characters replaced by visible codes. Trusted Types are enforced, which
makes the browser itself throw on any attempt to insert text as markup.

`verify_live.py` checks a site against this repository. It downloads every file of `scanner/`
from the site and compares it byte for byte with your checkout, then compares two response
headers with `_headers`: the page's policy, and the policy on the scanner's own files. The
second is what leaves the worker without a network, and if a site lost it nothing on the page
would look different. The page's own HTML and CSS belong to the site. At helban.dev the page
also loads two small scripts of the site (one remembers in the tab where a visitor came from,
one opens the mobile menu); the script lists them with their hashes so that you can read them.

    python3 verify_live.py

There is no build step. The files in `scanner/` are the files the browser runs. One of them
is not ours: `scanner/spark-md5.js` is spark-md5 3.0.2 (WTFPL or MIT), because wordpress.org
publishes core checksums in MD5 only and browsers do not compute MD5. It is the file from
https://registry.npmjs.org/spark-md5/-/spark-md5-3.0.2.tgz, unchanged, SHA-256
`87f7f7804f9e5d55782065d799d75fc8d3b324100b198d1a415632255552736d`. Plugin files are compared
by SHA-256 through the browser's own Web Crypto.

## Run it

    python3 tests/serve.py

and open the address it prints. `serve.py` applies the response headers from `_headers`, the
same file Cloudflare Pages reads. `index.html` is the bare page the tests use. A page that
carries the scanner needs the elements marked `data-scanner="..."` in it and nothing else.

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
off by default), and 661 of 661 mutations are caught. The same suite can be pointed at a site that carries the scanner, with
that site's own header rules (`SCANNER_SITE_ROOT`, `SCANNER_PAGE_PATH` and `SCANNER_SERVED`,
described in `tests/serve.py`); the pages at helban.dev are tested that way before a release.
The tests never
reach wordpress.org or wpvulnerability.net; `tests/wporg.py` answers in their place, the way
the real hosts answer. One test does go out, and only when asked: `SCANNER_LIVE=1` checks
that an old Elementor release and WordPress 6.8 really come back with known vulnerabilities.

Speed, 2026-11-14, Chromium, a 2 GB copy with 58,478 files (WordPress, 30 plugins, a database
dump, random "photos"): with the comparison and the vulnerability lookup on, file count on
screen after 0.13 to 0.14 s, scan finished in 25.7 to 26.2 s and the report at once, 101
requests, browser memory 0.53 to 0.56 GB above its level before the scan. The scan read 2.4 GB
from the 2 GB file: every picture is read from start to end, which for a compressed one means
unpacking all of it. With the pictures stored uncompressed the same copy took 23.2 to 24.2 s.
Before media files were read through (2026-11-13) the compressed copy took 17.3 to 18.9 s;
with the comparison off, every one of the copy's 35,398 PHP files is read as code, 18.3 s
measured then.

## License

GPL-3.0-or-later. See `LICENSE`.
