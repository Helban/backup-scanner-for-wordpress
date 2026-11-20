"""The two languages of the scanner's sentences are written apart, so nothing but these tests
keeps them saying something about the same rules, reasons and states."""
import pytest

# Every name a module exports, with the keys of what it holds. A reason one language knows and
# the other lacks would show as a sentence ending in "unknown reason" on one page only.
MODULE_SHAPES = """async () => {
  const shapeOf = (exported) => {
    if (exported instanceof Map) return [...exported.keys()].sort();
    if (typeof exported === 'object') return Object.keys(exported).sort();
    return typeof exported;
  };
  const shapes = {};
  for (const language of ['en', 'pl']) {
    const module = await import(`/scanner/messages-${language}.js`);
    shapes[language] = Object.fromEntries(Object.entries(module).map(([name, exported]) => [name, shapeOf(exported)]));
  }
  return shapes;
}"""

# Calls the sentence of every rule with every value a parameter can take, in one language.
# `variants` holds, per parameter that selects words, the values the scanner sends for it.
EVERY_SENTENCE = """async ([language, variants]) => {
  const { describeFinding } = await import(`/scanner/messages-${language}.js`);
  const { RULES } = await import('/scanner/rules.js');
  const base = {
    what: 'exec', line: 12, extension: '.jpeg', bytes: 2048, files: 3, phpFiles: 3, example: 'folder/file.php', missing: 2,
    plugins: 4, hosts: 2, entries: 70000, codes: 'U+202E', campaign: 'fake_backup_2026_11', fields: 'name size',
    localName: 'other.php', otherName: 'other.php', offset: 10, method: 99, error: 'TypeError', components: 2, kind: 'zip', reason: 'format',
  };
  const sentences = [];
  for (const rule of RULES.keys()) {
    for (const [parameter, values] of Object.entries(variants)) {
      for (const value of values) {
        sentences.push([rule, describeFinding({ rule, params: new Map(Object.entries({ ...base, [parameter]: value })) })]);
      }
    }
  }
  sentences.push(['overflow', describeFinding({ rule: 'layout.symlink', params: new Map([['more', 5]]) })]);
  return sentences;
}"""

# Counts take 1, 2, 5 and 22 because English says "1 file" and Polish says "1 plik, 2 pliki,
# 5 plików, 22 pliki": a sentence that keeps one form for every count is wrong for some of them.
# 0 is real too: a copy without plugins.
COUNTS = [0, 1, 2, 5, 22]
VARIANTS = {
    "kind": [
        "windows_program", "linux_program", "script", "java_or_macos_program", "macos_program", "windows_shortcut",
        "zip", "zip_empty", "zip_spanned", "sevenzip", "rar", "gzip", "bzip2", "xz", "zstd", "cab", "tar", "wpress",
        "phar", "zip_behind_media", "core", "plugin", "",
    ],
    "reason": [
        "format", "depth", "too_large", "too_many_entries", "damaged", "multi_part", "time", "budget_count",
        "budget_size", "budget_time", "no_version", "not_listed", "version_not_listed", "closed", "network",
        "request_limit", "bad_answer", "closure_unknown", "unreadable_entries", "unavailable", "tokens", "nesting",
        "bytes", "zip64", "other_disk", "out_of_bounds", "no_local_header", "stream", "size", "checksum", "whole",
        "code", "config", "indicator", "database", "a_reason_no_language_knows",
    ],
    "what": [
        "exec", "backtick", "new_com", "new_dotnet", "ffi", "putenv_loader", "wscript.shell", "shell.application",
        "expect://", "variable_call", "expression_call", ".exe", "*", "base64",
    ],
    "fields": ["name size", "method encryption checksum"],
    "campaign": ["fake_backup_2026_11", "a_campaign_no_language_knows"],
    "role": ["payload", "archive", "a_role_no_language_knows"],
    "exampleKind": ["core", "plugin", "theme", ""],
    "error": ["TypeError", None],
    "localName": ["other.php", ""],
    "place": ["content", "languages", "site", "folder"],
    **{parameter: COUNTS for parameter in ["files", "phpFiles", "missing", "plugins", "hosts", "entries", "components"]},
}
BROKEN_TEXT = ("undefined", "NaN", "[object", "null")


def test_both_languages_cover_the_same_things(page, site_url):
    page.goto(site_url)
    shapes = page.evaluate(MODULE_SHAPES)
    assert shapes["pl"] == shapes["en"]
    assert "describeFinding" in shapes["en"]


@pytest.mark.parametrize("language", ["en", "pl"])
def test_every_sentence_can_be_said(language, page, site_url):
    page.goto(site_url)
    sentences = page.evaluate(EVERY_SENTENCE, [language, VARIANTS])
    assert len(sentences) > 1000
    broken = [(rule, sentence) for rule, sentence in sentences if not sentence or any(mark in sentence for mark in BROKEN_TEXT)]
    assert broken == []


# The sentences whose words depend on a count, said with the counts that pick each form.
COUNTED_SENTENCES = """async (language) => {
  const texts = await import(`/scanner/messages-${language}.js`);
  const finding = (rule, params) => texts.describeFinding({ rule, params: new Map(Object.entries(params)) });
  const component = { reason: 'network', components: 1, example: 'tool', exampleKind: 'plugin' };
  return {
    missing: [finding('core.missing_files', { missing: 1, example: 'x.php' })],
    outside: [finding('layout.php_outside_code_folders', { phpFiles: 1, example: 'x.php' })],
    outsideContent: [1, 2].map((phpFiles) => finding('layout.php_outside_code_folders', { phpFiles, example: 'x.php', place: 'content' })),
    outsideLanguages: [1, 2].map((phpFiles) => finding('layout.php_outside_code_folders', { phpFiles, example: 'x.php', place: 'languages' })),
    outsideSite: [1, 2].map((phpFiles) => finding('layout.php_outside_code_folders', { phpFiles, example: 'x.php', place: 'site' })),
    tail: [finding('archive.tail_not_checked', { files: 1, bytes: 2048 })],
    group: [finding('archive.not_opened_group', { files: 1, extension: '.zip', bytes: 2048, reason: 'budget_count' })],
    pastLimit: [finding('component.not_compared_past_limit', { plugins: 1, example: 'tool' })],
    closure: [1, 2].map((components) => finding('advisory.not_checked', { ...component, reason: 'closure_unknown', components })),
    unreadable: [finding('advisory.not_checked', { ...component, reason: 'unreadable_entries', entries: 1 })],
    failed: [finding('advisory.not_checked', component)],
    hosts: [finding('db.external_script_host', { hosts: 1, example: 'cdn.example' })],
    more: [1, 2].map((more) => finding('layout.symlink', { more })),
    moreNamed: [1, 2, 5].map((more) => finding('layout.symlink', { more, example: 'a.php' })),
    advisoryMore: [texts.ADVISORY_TEXT.more(2)],
    tooMany: [50002, 50005, 50022].map((entries) => finding('zip.too_many_entries', { entries })),
    undrawn: [texts.LIST_TEXT.undrawnFindings(600, 1)],
    allRed: [texts.SUMMARY_TEXT.ruleOnlyRed(3, 3, 2)],
    onlyRed: [texts.SUMMARY_TEXT.ruleOnlyRed(1, 1, 1)],
    logLoaded: [texts.LOG_TEXT.loadedCode({ total: 1, files: [{ path: 'wp-config.php', name: '', bytes: 100 }] })],
    sent: [texts.LOG_TEXT.done({ milliseconds: 1000, bytesRead: 100 }, ['https://api.wordpress.org/core/checksums/1.0/'])],
    heading: [texts.ADVISORY_TEXT.heading({ kind: 'plugin', name: 'tool', version: '1', state: 'checked', entries: [1], closed: null })],
    loaded: [texts.SUMMARY_TEXT.loadedCode(1)],
    exportLoaded: [texts.EXPORT_TEXT.loadedCode(1)],
    rows: [1, 2, 5].map((files) => texts.LIST_TEXT.component({
      kind: 'plugin', name: 'tool', version: '1', state: 'listed', matched: files, files, modified: 0, extra: 0, missing: 0,
    })),
    looked: [1, 2, 5].map((count) => texts.LOG_TEXT.advisories(Array.from({ length: count }, () => ({ state: 'checked', entries: [], closed: null })))),
  };
}"""

# Per sentence, what each said form must contain, in the order the counts above were given.
COUNTED_FORMS = {
    "en": {
        "missing": ["1 file of the official WordPress release is missing: x.php."],
        "outside": ["1 PHP file in a folder WordPress does not load code from: x.php. It runs only when something includes it"],
        "outsideContent": [
            "1 PHP file lying directly in wp-content is not a drop-in: x.php. It runs only when something includes it",
            "2 PHP files lying directly in wp-content are not drop-ins, for example x.php. They run only when",
        ],
        "outsideLanguages": [
            "1 PHP file in wp-content/languages is not a translation file: x.php. It runs only when",
            "2 PHP files in wp-content/languages are not translation files, for example x.php. They run only when",
        ],
        "outsideSite": [
            "1 PHP file lies directly in a folder with a wp-content but no wp-includes: x.php. It runs only when",
            "2 PHP files lie directly in a folder with a wp-content but no wp-includes, for example x.php. They run only when",
        ],
        "tail": ["1 media file (2.0 KB) was not read through", "A program inside it would not be seen"],
        "group": ["1 more archive named .zip (2.0 KB). The copy holds more than 200 archives, and only the first 200 are opened."],
        "pastLimit": ["1 plugin after the first 300 was not compared", "Its files are judged"],
        "closure": [
            "The scanner could not ask wordpress.org whether it has closed the plugin tool. Its known vulnerabilities",
            "The scanner could not ask wordpress.org whether it has closed 2 plugins, for example tool. Their known vulnerabilities",
        ],
        "unreadable": ["1 entry of the vulnerability database could not be matched with the version in 1 component (plugin tool). Read it at"],
        "failed": ["Known vulnerabilities were not looked up for 1 component (plugin tool):"],
        "hosts": ["from 1 outside host: cdn.example. Check that it belongs there."],
        "more": ["1 more finding of this kind is not listed separately.", "2 more findings of this kind are not listed separately."],
        "moreNamed": [
            "One more finding like the one for a.php is not listed separately.",
            "2 more findings like the one for a.php are not listed separately.",
            "5 more findings like the one for a.php are not listed separately.",
        ],
        "advisoryMore": ["2 more, not listed separately."],
        "tooMany": ["50,002 entries", "50,005 entries", "50,022 entries"],
        "undrawn": ["One more finding is in the report"],
        "allRed": ["All 3 red findings come from rules", "so read those files"],
        "onlyRed": ["The only red finding comes from rules", "so read that file"],
        "logLoaded": ["language files), read this file: wp-config.php"],
        "sent": ["One request to wordpress.org carried names and versions only"],
        "heading": ["plugin tool 1: one known vulnerability for this version"],
        "loaded": ["WordPress loads 1 file by itself (wp-config.php, .maintenance, mu-plugins, drop-ins, language files), with nothing to switch on in wp-admin.", "It is listed below. Read it,"],
        "exportLoaded": ["CODE THAT WORDPRESS LOADS BY ITSELF (read this file)"],
        "rows": ["tool 1: 1 of 1 file the same", "tool 1: 2 of 2 files the same", "tool 1: 5 of 5 files the same"],
        "looked": ["in 0 of 1 component looked up", "in 0 of 2 components looked up", "in 0 of 5 components looked up"],
    },
    "pl": {
        "missing": ["Brakuje 1 pliku z oficjalnego wydania WordPressa: x.php."],
        "outside": ["1 plik PHP w folderze, z którego WordPress nie ładuje kodu: x.php."],
        "outsideContent": [
            "1 plik PHP bezpośrednio w wp-content, nie licząc drop-inów: x.php. Taki plik",
            "2 pliki PHP bezpośrednio w wp-content, nie licząc drop-inów, na przykład x.php. Taki plik",
        ],
        "outsideLanguages": [
            "1 plik PHP w wp-content/languages, nie licząc plików tłumaczeń: x.php. Taki plik",
            "2 pliki PHP w wp-content/languages, nie licząc plików tłumaczeń, na przykład x.php. Taki plik",
        ],
        "outsideSite": [
            "1 plik PHP bezpośrednio w folderze z wp-content, ale bez wp-includes: x.php. Taki plik",
            "2 pliki PHP bezpośrednio w folderze z wp-content, ale bez wp-includes, na przykład x.php. Taki plik",
        ],
        "tail": ["1 plik mediów (2,0 KB) nie został przeczytany do końca", "Program schowany w nim"],
        "group": ["Jeszcze 1 archiwum pod nazwą .zip (2,0 KB). Kopia ma ponad 200 archiwów"],
        "pastLimit": ["Jednej wtyczki ponad pierwsze 300 (tool)", "Jej pliki są oceniane"],
        "closure": ["czy wordpress.org zamknął 1 wtyczkę (tool).", "czy wordpress.org zamknął 2 wtyczki, na przykład tool."],
        "unreadable": ["dopasować do wersji: 1 (składnik: wtyczka tool). Przeczytaj go na"],
        "failed": ["Znane podatności nie zostały sprawdzone dla 1 składnika (wtyczka tool):"],
        "hosts": ["ładują skrypty z obcego hosta: cdn.example. Sprawdź, czy powinien tam być."],
        "more": ["Jeszcze 1 znalezisko tego rodzaju, niewypisane osobno.", "Jeszcze 2 znaleziska tego rodzaju, niewypisane osobno."],
        "moreNamed": [
            "Jeszcze jedno znalezisko takie jak przy a.php. Skaner nie wypisuje go osobno.",
            "Jeszcze 2 znaleziska takie jak przy a.php. Skaner nie wypisuje ich osobno.",
            "Jeszcze 5 znalezisk takich jak przy a.php. Skaner nie wypisuje ich osobno.",
        ],
        "advisoryMore": ["Jeszcze 2, niewypisane osobno."],
        "tooMany": ["002 pozycje,", "005 pozycji,", "022 pozycje,"],
        "undrawn": ["Jeszcze jedno znalezisko jest w raporcie"],
        "allRed": ["Wszystkie czerwone znaleziska (3) pochodzą z reguł", "przeczytaj te pliki"],
        "onlyRed": ["Jedyne czerwone znalezisko pochodzi z reguł", "przeczytaj ten plik"],
        "logLoaded": ["pliki językowe), przeczytaj ten plik: wp-config.php"],
        "sent": ["Do wordpress.org poszło jedno zapytanie"],
        "heading": ["wtyczka tool 1: jedna znana podatność w tej wersji"],
        "loaded": ["WordPress sam wczytuje 1 plik (wp-config.php, .maintenance, mu-pluginy, drop-iny, pliki językowe), którego nie trzeba włączać w panelu.", "Jest na liście niżej. Przeczytaj go,"],
        "exportLoaded": ["KOD, KTÓRY WORDPRESS WCZYTUJE SAM (przeczytaj ten plik)"],
        "rows": ["1 z 1 pliku,", "2 z 2 plików,", "5 z 5 plików,"],
        "looked": ["w 0 z 1 sprawdzonego składnika", "w 0 z 2 sprawdzonych składników", "w 0 z 5 sprawdzonych składników"],
    },
}


@pytest.mark.parametrize("language", ["en", "pl"])
def test_words_follow_their_count(language, page, site_url):
    """Each form a count picks: one sentence per form, so a branch that breaks breaks this test."""
    page.goto(site_url)
    said = page.evaluate(COUNTED_SENTENCES, language)
    expected = COUNTED_FORMS[language]
    assert said.keys() == expected.keys()
    wrong = [
        (name, form, sentence)
        for name, forms in expected.items()
        for form, sentence in forms_and_sentences(forms, said[name])
        if form not in sentence
    ]
    assert wrong == []


def forms_and_sentences(forms: list[str], sentences: list[str]) -> list[tuple[str, str]]:
    """One sentence may have to hold several parts; several sentences hold one part each."""
    if len(sentences) == 1:
        return [(form, sentences[0]) for form in forms]
    return list(zip(forms, sentences, strict=True))


SNIPPET_PLUGINS = """async ([language, plugins]) => {
  const { describeFinding } = await import(`/scanner/messages-${language}.js`);
  return describeFinding({ rule: 'db.snippet_plugin_active', params: new Map([['plugins', plugins]]) });
}"""


@pytest.mark.parametrize(("language", "one", "two"), [
    ("en", "A snippet plugin is active (code-snippets)", "Snippet plugins are active (code-snippets, insert-php)"),
    ("pl", "Aktywna jest wtyczka do snippetów (code-snippets)", "Aktywne są wtyczki do snippetów (code-snippets, insert-php)"),
])
def test_two_active_snippet_plugins_are_named_in_the_plural(language, one, two, page, site_url):
    """The engine sends the slugs joined with ", ", not a count."""
    page.goto(site_url)
    assert page.evaluate(SNIPPET_PLUGINS, [language, "code-snippets"]).startswith(one)
    assert page.evaluate(SNIPPET_PLUGINS, [language, "code-snippets, insert-php"]).startswith(two)
