// SPDX-License-Identifier: GPL-3.0-or-later
//
// The Polish sentences. messages.js picks between this file and messages-en.js. Written on
// their own, not translated line by line: the two files say the same things about the same
// rules, each the way its language says them.

const PROGRAM_KINDS = new Map([
  ['windows_program', 'program Windows'],
  ['linux_program', 'program Linuksa'],
  ['script', 'skrypt z linią „#!”'],
  ['java_or_macos_program', 'klasa Javy albo program macOS'],
  ['macos_program', 'program macOS'],
  ['windows_shortcut', 'skrót Windows'],
]);

const ARCHIVE_KINDS = new Map([
  ['zip', 'zip'], ['zip_empty', 'zip (puste)'], ['zip_spanned', 'zip (wieloczęściowe)'],
  ['sevenzip', '7z'], ['rar', 'RAR'], ['gzip', 'gzip'], ['bzip2', 'bzip2'], ['xz', 'xz'],
  ['zstd', 'zstd'], ['cab', 'cab'], ['tar', 'tar'], ['wpress', '.wpress'], ['phar', 'phar'],
]);

const HEADER_FIELDS = new Map([
  ['name', 'nazwa'], ['method', 'kompresja'], ['encryption', 'szyfrowanie'],
  ['size', 'rozmiar'], ['checksum', 'suma kontrolna'],
]);

const UNREADABLE_REASONS = new Map([
  ['zip64', 'nie da się odczytać pól z rozmiarem'],
  ['other_disk', 'wskazuje na inną część archiwum wieloczęściowego'],
  ['out_of_bounds', 'dane leżałyby poza archiwum'],
  ['no_local_header', 'w miejscu, które wskazuje spis treści, nie ma nagłówka pliku'],
]);

const CORRUPT_REASONS = new Map([
  ['stream', 'spakowane dane są uszkodzone'],
  ['size', 'po rozpakowaniu rozmiar jest inny niż w spisie treści'],
  ['checksum', 'suma kontrolna się nie zgadza'],
  ['whole', 'nie udało się rozpakować całego pliku do porównania z wordpress.org'],
  ['code', 'nie udało się rozpakować całego pliku, żeby przeczytać kod'],
  ['config', 'nie udało się rozpakować całego pliku, żeby przeczytać ustawienia serwera'],
  ['indicator', 'nie udało się rozpakować całego pliku, żeby porównać go z plikami ze znanych ataków'],
  ['database', 'zrzutu bazy nie udało się rozpakować do końca, więc sprawdzona jest tylko część przed uszkodzeniem'],
]);

// Campaigns of indicators.js, by id.
const CAMPAIGN_TEXT = new Map([
  ['fake_backup_2026_11', 'fałszywa kopia WordPressa rozsyłana freelancerom w listopadzie 2026 (złodziej haseł udający JPEG)'],
]);

// How the code rules name what they found (php-rules.js).
const MECHANISMS = new Map([
  ['backtick', 'polecenie w odwróconych apostrofach'],
  ['new_com', 'new COM'],
  ['new_dotnet', 'new DOTNET'],
  ['ffi', 'FFI, czyli wywołanie funkcji natywnych'],
  ['putenv_loader', 'putenv() ze zmienną programu ładującego biblioteki'],
  ['wscript.shell', 'obiekt WScript.Shell'],
  ['shell.application', 'obiekt Shell.Application'],
  ['expect://', 'adres expect://'],
  ['variable_call', 'wywołanie przez zmienną'],
  ['expression_call', 'wywołanie tego, co zwraca inne wyrażenie'],
]);

const pluralRules = new Intl.PluralRules('pl');

// Polish counts things three ways: 1 plik, 2 pliki, 5 plików.
const plural = (count, { one, few, many }) => ({ one, few })[pluralRules.select(count)] ?? many;

const numberFormat = new Intl.NumberFormat('pl');
const fractionFormat = new Intl.NumberFormat('pl', { minimumFractionDigits: 1, maximumFractionDigits: 1 });
const sizeFormat = new Intl.NumberFormat('pl', { minimumFractionDigits: 2, maximumFractionDigits: 2 });

export const formatCount = (value) => numberFormat.format(value);

const formatBytes = (bytes) => {
  if (bytes < 1024) return `${formatCount(bytes)} B`;
  if (bytes < 1024 * 1024) return `${fractionFormat.format(bytes / 1024)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${fractionFormat.format(bytes / 1024 / 1024)} MB`;
  return `${sizeFormat.format(bytes / 1024 / 1024 / 1024)} GB`;
};

const mechanism = (params) => {
  const what = String(params.get('what') ?? '');
  if (MECHANISMS.has(what)) return MECHANISMS.get(what);
  return what.startsWith('.') ? `nazwa pliku ${what}` : `${what}()`;
};

const lineNumber = (params) => formatCount(params.get('line') ?? 0);
const inLine = (params) => `w linii ${lineNumber(params)}`;
const line = (params) => `linia ${lineNumber(params)}`;

// The file an include names, by its extension (php-rules.js includedExtension).
const includedFile = (params) => {
  const extension = String(params.get('what') ?? '');
  return extension.startsWith('.') ? `plik z końcówką ${extension}` : 'plik bez rozszerzenia';
};

// What a decoded string turned out to hold (php-rules.js hiddenCodeIn).
const hiddenText = (params) => {
  const what = String(params.get('what') ?? '');
  return what === 'base64' ? 'długi tekst base64, który po zdekodowaniu jest kodem PHP' : `tekst, który dopiero po zdekodowaniu brzmi „${what}”`;
};

const ALWAYS_LOADED = 'Kod, który WordPress wczytuje sam,';
// What that code is, in the log and in the summary.
const LOADED_SOURCES = '(wp-config.php, .maintenance, mu-pluginy, drop-iny, pliki językowe)';
// Where loose PHP lies (the `place` of layout.php_outside_code_folders).
const LOOSE_PLACE_TEXT = new Map([
  ['content', 'bezpośrednio w wp-content, nie licząc drop-inów'],
  ['languages', 'w wp-content/languages, nie licząc plików tłumaczeń'],
  ['site', 'bezpośrednio w folderze z wp-content, ale bez wp-includes'],
]);
const LOOSE_FOLDER_TEXT = 'w folderze, z którego WordPress nie ładuje kodu';
const NEVER_IN_HONEST_CODE = 'Uczciwy kod zmierzony dla tego skanera nie robił tego ani razu.';

// A program or an archive kept in PHP as base64 or other encoded text (php-rules.js packedFileIn).
const packedProgram = (params) => `${PROGRAM_KINDS.get(params.get('what')) ?? 'program'} zapisany jako zakodowany tekst (${line(params)}).`;
const packedArchive = (params) => `archiwum ${ARCHIVE_KINDS.get(params.get('what')) ?? 'nieznanego rodzaju'} zapisane jako zakodowany tekst (${line(params)}).`;
const PACKED_PROGRAM_NOTE = 'Po zdekodowaniu i zapisaniu to program, którego nie pokazuje żaden plik z kopii.';
const PACKED_ARCHIVE_NOTE = 'Tego, co z niego wyjdzie, nie ma w żadnym pliku kopii, więc ten skaner tego nie widział.';

// Why the files of the core or of a plugin were not compared with wordpress.org. The same
// reason has to fit "rdzeń" and "wtyczka", so none of them names the thing.
const NOT_COMPARED_REASONS = new Map([
  ['no_version', 'z kopii nie dało się odczytać wersji'],
  ['not_listed', 'nie ma tej wtyczki na wordpress.org (tak jest ze wtyczkami premium i pisanymi na zamówienie)'],
  // A browser cannot tell a 404 from downloads.wordpress.org (sent without CORS) from a dropped
  // connection, so the sentence claims neither.
  ['version_not_listed', 'sumy kontrolne tej wersji nie przyszły z wordpress.org (nie są opublikowane albo zapytanie się nie udało)'],
  ['closed', 'wordpress.org zamknął tę wtyczkę i nie publikuje jej sum kontrolnych'],
  ['network', 'nie udało się połączyć z wordpress.org'],
  ['request_limit', 'limit 150 zapytań na skan skończył się wcześniej'],
  ['bad_answer', 'wordpress.org przysłał odpowiedź, której ten skaner nie umie użyć'],
]);

const COMPONENT_LABELS = new Map([['core', 'Rdzenia WordPressa'], ['plugin', 'Tej wtyczki']]);

// wordpress.org answers a core release or language it does not know with no list. The reason
// above speaks of plugins, so the core gets its own words.
const CORE_NOT_LISTED = 'wordpress.org nie ma sum kontrolnych tej wersji w tym języku';
const notComparedReason = (kind, reason) => (
  kind === 'core' && reason === 'not_listed' ? CORE_NOT_LISTED : NOT_COMPARED_REASONS.get(reason) ?? 'powód nieznany'
);

const REQUEST_LABELS = new Map([
  ['core_checksums', (request) => `sumy kontrolne WordPressa ${request.version} (${request.locale})`],
  ['plugin_checksums', (request) => `sumy kontrolne ${request.slug} ${request.version}`],
  ['plugin_info', (request) => `czy ${request.slug} jest w katalogu wtyczek?`],
  ['core_vulnerabilities', (request) => `znane podatności WordPressa ${request.version}`],
  ['plugin_vulnerabilities', (request) => `znane podatności wtyczki ${request.slug} (sama nazwa)`],
  ['theme_vulnerabilities', (request) => `znane podatności motywu ${request.slug} (sama nazwa)`],
]);

// Why known vulnerabilities were not looked up (gateway.js advisory states).
const ADVISORY_REASONS = new Map([
  ['network', 'nie udało się połączyć z wpvulnerability.net albo z katalogiem wtyczek wordpress.org'],
  ['unavailable', 'wpvulnerability.net odpowiedział, że nie działa'],
  ['request_limit', 'limit 150 zapytań na skan skończył się wcześniej'],
  ['bad_answer', 'wpvulnerability.net albo wordpress.org przysłał odpowiedź, której ten skaner nie umie użyć'],
]);

const BOUND_WORDS = new Map([['lt', 'przed'], ['le', 'do'], ['eq', 'dokładnie'], ['ne', 'inne niż'], ['gt', 'po'], ['ge', 'od']]);
const SOURCE_LABELS = new Map([
  ['www.cve.org', 'CVE.org'], ['www.wordfence.com', 'Wordfence'], ['patchstack.com', 'Patchstack'], ['wpscan.com', 'WPScan'],
]);
// The core's heading names it by version alone, so the core has no entry here.
const ADVISORY_KINDS = new Map([['plugin', 'wtyczka'], ['theme', 'motyw']]);

// The component an advisory finding names as its example: "wtyczka tool", "WordPress 6.9.5".
const advisoryExample = (params) => {
  const name = params.get('example') ?? '';
  const kind = params.get('exampleKind');
  return kind === 'core' ? `WordPress ${name}` : `${ADVISORY_KINDS.get(kind) ?? ''} ${name}`.trim();
};

const NOT_OPENED_REASONS = new Map([
  ['format', 'Ten skaner otwiera tylko archiwa zip, więc zawartość nie została sprawdzona.'],
  ['depth', 'Leży w innym archiwum, a skaner otwiera tylko jeden poziom.'],
  ['too_large', 'Po rozpakowaniu ma ponad 64 MB, więc skaner go nie otworzył.'],
  ['too_many_entries', 'Ma w spisie ponad 50 000 pozycji, więc skaner go nie otworzył.'],
  ['damaged', 'Zaczyna się jak zip, ale nie da się go przeczytać jako zip.'],
  ['multi_part', 'To jedna część wieloczęściowego zipa, więc skaner jej nie otworzył.'],
  ['time', 'Czytanie trwało ponad 10 sekund, więc reszta nie została sprawdzona.'],
  ['budget_count', 'Kopia ma ponad 200 archiwów, a skaner otwiera pierwsze 200.'],
  ['budget_size', 'Archiwa otwarte wcześniej zużyły 512 MB przewidziane na rozpakowywanie.'],
  ['budget_time', 'Wcześniej skończyło się 60 sekund przewidziane na archiwa w kopii.'],
]);
const NOT_OPENED = 'Skaner go nie otworzył.';

const programKind = (params) => PROGRAM_KINDS.get(params.get('kind')) ?? 'program';
const archiveKind = (params) => ARCHIVE_KINDS.get(params.get('kind')) ?? 'nieznanego rodzaju';
const sizeOf = (params) => formatBytes(params.get('bytes') ?? 0);
const filesWord = (count) => plural(count, { one: 'plik', few: 'pliki', many: 'plików' });

// What a server setting applies to: '*' for every file of the folder, else an extension.
const configTarget = (params) => (params.get('what') === '*' ? 'każdy plik w tym folderze' : `pliki z końcówką ${params.get('what')}`);

const missingFiles = (params, release) => {
  const missing = params.get('missing') ?? 0;
  if (missing === 1) return `Brakuje 1 pliku z ${release}: ${params.get('example')}.`;
  return `Brakuje ${formatCount(missing)} ${plural(missing, { one: 'pliku', few: 'plików', many: 'plików' })} z ${release}, na przykład ${params.get('example')}.`;
};

const FINDING_TEXT = new Map([
  ['layout.path_traversal', () => 'Nazwa wskazuje miejsce poza folderem, do którego rozpakowuje się archiwum.'],
  ['layout.symlink', () => 'Dowiązanie symboliczne. Po rozpakowaniu może wskazywać dowolny plik na komputerze.'],
  ['layout.executable_extension', (params) => `Plik z rozszerzeniem programu (${params.get('extension')}).`],
  ['layout.disguised_executable', (params) => (
    `Zaczyna się jak ${programKind(params)}, a nazywa się ${params.get('extension')}. ${sizeOf(params)}.`
  )],
  ['layout.php_in_media', (params) => `Kod PHP w pliku ${params.get('extension')}.`],
  ['layout.php_in_text', (params) => (
    `Kod PHP w pliku ${params.get('extension')}, którego nie było z czym porównać. W dokumentacji takie przykłady są częste. Plik tekstowy sam się nie uruchomi, zrobi to dopiero kod, który go dołączy, więc przeczytaj, co to za plik.`
  )],
  ['layout.script_in_code_folder', (params) => (
    `Skrypt (${params.get('extension')}) wśród kodu, którego nie było z czym porównać. Programiści dołączają tak skrypty do budowania. Nic go nie uruchomi, dopóki nie zrobisz tego sam, więc najpierw go przeczytaj.`
  )],
  ['layout.server_script', (params) => (
    `Plik ${params.get('extension')}. Przy domyślnych ustawieniach XAMPP serwer takiego pliku nie wysyła, tylko go uruchamia, gdy ktoś otworzy jego adres. Sam WordPress takich plików nie ma.`
  )],
  ['layout.server_script_in_code_folder', (params) => (
    `Plik ${params.get('extension')} wśród kodu, którego nie było z czym porównać. Przy domyślnych ustawieniach XAMPP serwer uruchamia taki plik, gdy ktoś otworzy jego adres. UpdraftPlus ma jeden taki plik, więc przeczytaj go, zanim uznasz to za pułapkę.`
  )],
  ['layout.php_in_uploads', () => 'Plik PHP w folderze uploads, gdzie powinny leżeć tylko media.'],
  ['layout.archive_as_media', (params) => (
    `Archiwum ${archiveKind(params)} pod nazwą ${params.get('extension')}. ${sizeOf(params)}.`
  )],
  ['layout.archive_behind_media', (params) => (
    `Plik ${params.get('extension')} z archiwum zip doklejonym na końcu. Przeglądarka zdjęć pokaże plik, a program do rozpakowywania wyjmie archiwum zza niego. ${sizeOf(params)}.`
  )],
  ['layout.program_inside_media', (params) => (
    `Plik ${params.get('extension')}, w którym od bajtu ${formatCount(params.get('offset') ?? 0)} siedzi ${programKind(params)}. `
    + `Pod tą nazwą nic go nie uruchomi, ale kod, który przepisze te bajty do nowego pliku, dostanie program, którego nie pokazuje żaden plik z kopii. ${sizeOf(params)}.`
  )],
  ['layout.inside_not_searched', (params) => (
    `Plik ${params.get('extension')} (${sizeOf(params)}) z tysiącami nagłówków wyglądających jak początek programu Windows, z których każdy wskazuje dalej w głąb pliku. `
    + 'Szukanie programu w środku zostało przerwane. Uczciwe media tak nie wyglądają.'
  )],
  ['layout.archive_unexpected_extension', (params) => (
    `Archiwum ${archiveKind(params)} pod rozszerzeniem ${params.get('extension')}. ${sizeOf(params)}.`
  )],
  ['name.deceptive_characters', (params) => (
    `W nazwie są znaki niewidoczne albo zmieniające kierunek pisma (${params.get('codes')}), pokazane tu jako kody.`
  )],
  ['name.trailing_dot_or_space', () => (
    'Nazwa kończy się kropką albo spacją. Windows je obcina, więc plik zapisze się pod inną nazwą.'
  )],
  ['layout.executable_in_archive', (params) => (
    `Plik z rozszerzeniem programu (${params.get('extension')}) spakowany w archiwum.`
  )],
  ['layout.not_an_image', (params) => (
    `Nazywa się ${params.get('extension')}, ale nie zaczyna się jak żaden format obrazu. ${sizeOf(params)}.`
  )],
  ['layout.php_named_as_media', () => (
    'W nazwie przed ostatnim rozszerzeniem stoi rozszerzenie PHP. Apache ustawiony przez AddHandler uruchomi taki plik jako PHP, cokolwiek mówi ostatnie rozszerzenie.'
  )],
  ['layout.image_named_php', () => 'Plik PHP nazwany jak obrazek. Uruchamia się jako PHP, tylko nazwa wygląda na zdjęcie.'],
  ['layout.php_outside_code_folders', (params) => {
    const phpFiles = params.get('phpFiles') ?? 0;
    const which = phpFiles === 1 ? `: ${params.get('example')}` : `, na przykład ${params.get('example')}`;
    // WordPress does load code from wp-content itself (the drop-ins), from its languages folder
    // (the translations) and from a site folder (its wp-config.php), so none is called a folder it
    // loads nothing from.
    const where = LOOSE_PLACE_TEXT.get(params.get('place')) ?? LOOSE_FOLDER_TEXT;
    return `${formatCount(phpFiles)} ${filesWord(phpFiles)} PHP ${where}${which}. `
      + 'Taki plik uruchamia się dopiero wtedy, gdy coś go dołączy albo ktoś otworzy jego adres, więc przeczytaj, co to jest.';
  }],
  ['archive.not_opened', (params) => (
    `${params.get('kind') === 'zip_behind_media' ? 'Koniec tego pliku wygląda jak doklejone archiwum zip' : `Archiwum ${archiveKind(params)}`}, ${sizeOf(params)}. ${NOT_OPENED_REASONS.get(params.get('reason')) ?? NOT_OPENED}`
  )],
  ['archive.tail_not_checked', (params) => {
    const files = params.get('files') ?? 0;
    if (files === 1) {
      return `1 plik mediów (${sizeOf(params)}) nie został przeczytany do końca, bo skończyło się 60 sekund przewidziane na to czytanie. Program schowany w nim nie zostałby zauważony, a jeśli plik jest spakowany, także zip doklejony na końcu.`;
    }
    return `Plików mediów nieprzeczytanych do końca: ${formatCount(files)}, razem ${sizeOf(params)}. Skończyło się 60 sekund przewidziane na to czytanie. Program schowany w którymś z nich nie zostałby zauważony, a w spakowanym także zip doklejony na końcu.`;
  }],
  ['archive.not_opened_group', (params) => {
    const files = params.get('files') ?? 0;
    const size = files === 1 ? ` (${sizeOf(params)})` : `, razem ${sizeOf(params)}`;
    return `Jeszcze ${formatCount(files)} ${plural(files, { one: 'archiwum', few: 'archiwa', many: 'archiwów' })} pod nazwą ${params.get('extension')}${size}. ${NOT_OPENED_REASONS.get(params.get('reason')) ?? NOT_OPENED}`;
  }],

  ['core.modified', () => 'Różni się od tego samego pliku w oficjalnym wydaniu WordPressa.'],
  ['core.extra_file', () => 'Plik z kodem PHP w folderze rdzenia WordPressa, którego oficjalne wydanie nie ma.'],
  ['core.extra_other', () => (
    'Plik w folderze rdzenia WordPressa, którego oficjalne wydanie nie ma. Nie ma w nim kodu PHP. Hostingi zostawiają tu logi, a wtyczki bezpieczeństwa dopisują pliki ustawień, więc przeczytaj, co to jest.'
  )],
  ['core.extra_root_php', () => (
    'Plik PHP w głównym folderze, który nie należy do WordPressa. Uruchomi się dopiero wtedy, gdy coś go załaduje, więc go przeczytaj.'
  )],
  ['core.missing_files', (params) => missingFiles(params, 'oficjalnego wydania WordPressa')],
  ['plugin.modified', () => 'Różni się od tego samego pliku w wydaniu tej wtyczki z wordpress.org.'],
  ['plugin.extra_php', () => 'Kod PHP w pliku, którego wydanie tej wtyczki z wordpress.org nie ma.'],
  ['plugin.extra_file', () => 'Plik, którego wydanie tej wtyczki z wordpress.org nie ma.'],
  ['plugin.missing_files', (params) => missingFiles(params, 'wydania tej wtyczki z wordpress.org')],
  ['component.not_compared', (params) => (
    `${COMPONENT_LABELS.get(params.get('kind')) ?? 'Tej części'} nie porównano z wordpress.org: ${notComparedReason(params.get('kind'), params.get('reason'))}. Te pliki są oceniane jak nieznany kod.`
  )],
  ['db.in_nested_archive', (params) => (
    `Zrzut bazy (${sizeOf(params)}) w archiwum leżącym w kopii. Baza jest sprawdzana tylko w zrzutach leżących wprost w kopii, więc ten nie został przeczytany.`
  )],
  ['component.not_compared_past_limit', (params) => {
    const plugins = params.get('plugins') ?? 0;
    if (plugins === 1) {
      return `Jednej wtyczki ponad pierwsze 300 (${params.get('example')}) skaner nie porównał z wordpress.org `
        + 'i nie sprawdził pod kątem znanych podatności, bo jeden skan pyta najwyżej o 300 wtyczek. Jej pliki są oceniane jak nieznany kod.';
    }
    return `Wtyczek ponad pierwsze 300 (${formatCount(plugins)}, na przykład ${params.get('example')}) skaner nie porównał z wordpress.org `
      + 'i nie sprawdził pod kątem znanych podatności, bo jeden skan pyta najwyżej o 300 wtyczek. Ich pliki są oceniane jak nieznany kod.';
  }],
  ['lookup.off', (params) => (
    `Porównanie z wordpress.org jest wyłączone, więc rdzeń i wtyczki (${formatCount(params.get('plugins') ?? 0)}) nie zostały porównane, `
    + 'a znane podatności nie były sprawdzane. Te pliki są oceniane jak nieznany kod.'
  )],
  ['advisory.not_checked', (params) => {
    const components = params.get('components') ?? 0;
    const example = advisoryExample(params);
    const which = components === 1 ? ` (${example})` : `, na przykład ${example}`;
    if (params.get('reason') === 'closure_unknown') {
      // Only plugins can be closed, so the plugin's name is enough.
      const plugin = params.get('example') ?? '';
      const named = components === 1 ? ` (${plugin})` : `, na przykład ${plugin}`;
      return `Nie udało się zapytać, czy wordpress.org zamknął ${formatCount(components)} ${plural(components, { one: 'wtyczkę', few: 'wtyczki', many: 'wtyczek' })}${named}. `
        + 'Znane podatności zostały sprawdzone, ale zamknięta wtyczka nie dostaje już poprawek bezpieczeństwa.';
    }
    if (params.get('reason') === 'unreadable_entries') {
      const entries = params.get('entries') ?? 0;
      const where = components === 1 ? `składnik: ${example}` : `składników: ${formatCount(components)}, na przykład ${example}`;
      return `Wpisów z bazy podatności, których nie dało się dopasować do wersji: ${formatCount(entries)} `
        + `(${where}). Przeczytaj ${entries === 1 ? 'go' : 'je'} na wpvulnerability.net.`;
    }
    return `Znane podatności nie zostały sprawdzone dla ${formatCount(components)} ${plural(components, { one: 'składnika', few: 'składników', many: 'składników' })}${which}: `
      + `${ADVISORY_REASONS.get(params.get('reason')) ?? 'powód nieznany'}. To nie to samo co „brak znanych podatności”.`;
  }],

  ['loaded.launch_call', (params) => `${ALWAYS_LOADED} uruchamia program: ${mechanism(params)}, ${inLine(params)}.`],
  ['loaded.launch_name_text', (params) => (
    `${ALWAYS_LOADED} trzyma jako tekst nazwę funkcji, która uruchamia programy (${mechanism(params)}, ${line(params)}). Tak zaczyna się wywołanie przez zmienną albo przez callback.`
  )],
  ['loaded.launch_name_composed', (params) => (
    `${ALWAYS_LOADED} składa z kawałków nazwę funkcji, która uruchamia programy (${mechanism(params)}, ${line(params)}).`
  )],
  ['loaded.dynamic_call', (params) => (
    `${ALWAYS_LOADED} wywołuje funkcję, której nazwy nie ma w pliku (${mechanism(params)}, ${line(params)}). Przeczytaj, co wywołuje.`
  )],
  ['loaded.rename_executable', (params) => (
    `${ALWAYS_LOADED} zmienia nazwy plików albo je kopiuje i wymienia program (${mechanism(params)}). Pierwsza zmiana nazwy albo kopia jest ${inLine(params)}.`
  )],
  ['loaded.rename_uploads', (params) => (
    `${ALWAYS_LOADED} zmienia nazwy plików, kopiuje je albo przenosi i odwołuje się do folderu uploads (${line(params)}). Przeczytaj, co przenosi.`
  )],
  ['loaded.include_uploads', (params) => (
    `${ALWAYS_LOADED} dołącza pliki PHP i odwołuje się do folderu uploads (${line(params)}). Przeczytaj, co dołącza.`
  )],
  ['loaded.include_not_php', (params) => (
    `${ALWAYS_LOADED} dołącza jako PHP ${includedFile(params)} (${line(params)}). PHP wykona kod z takiego pliku bez względu na nazwę, `
    + 'a ten skaner czyta jako kod tylko pliki nazwane jak PHP, więc przeczytaj ten plik.'
  )],
  ['unproven.launch_rare', (params) => (
    `Uruchamia program w sposób, którego uczciwy kod zmierzony dla tego skanera nie użył ani razu: ${mechanism(params)}, ${inLine(params)}.`
  )],
  ['unproven.launch_call', (params) => (
    `Może uruchomić program: ${mechanism(params)}, ${inLine(params)}. Część uczciwych wtyczek tak robi, więc przeczytaj, co uruchamia.`
  )],
  ['unproven.launch_name_text', (params) => (
    `Trzyma jako tekst nazwę funkcji, która uruchamia programy (${mechanism(params)}, ${line(params)}). Tak zaczyna się wywołanie pośrednie.`
  )],
  ['unproven.launch_name_composed', (params) => (
    `Składa z kawałków nazwę funkcji, która uruchamia programy (${mechanism(params)}, ${line(params)}).`
  )],
  ['unproven.rename_executable_call', (params) => (
    `Jednym wywołaniem ${inLine(params)} zmienia nazwę pliku na nazwę programu albo kopiuje go pod taką nazwę (${mechanism(params)}).`
  )],
  ['unproven.rename_executable', (params) => (
    `Zmienia nazwy plików albo je kopiuje i wymienia program albo sposób jego uruchomienia (${mechanism(params)}). Pierwsza zmiana nazwy albo kopia jest ${inLine(params)}.`
  )],
  ['loaded.eval_decoded', (params) => (
    `${ALWAYS_LOADED} wykonuje zdekodowany tekst jako PHP: ${mechanism(params)} z dekodowaniem w środku, ${inLine(params)}.`
  )],
  ['loaded.encoded_code', (params) => `${ALWAYS_LOADED} zawiera ${hiddenText(params)} (${line(params)}).`],
  ['loaded.encoded_program', (params) => `${ALWAYS_LOADED} trzyma ${packedProgram(params)} ${PACKED_PROGRAM_NOTE}`],
  ['loaded.encoded_archive', (params) => `${ALWAYS_LOADED} trzyma ${packedArchive(params)} ${PACKED_ARCHIVE_NOTE}`],
  ['unproven.encoded_program', (params) => `Trzyma ${packedProgram(params)} ${PACKED_PROGRAM_NOTE} ${NEVER_IN_HONEST_CODE}`],
  ['unproven.encoded_archive', (params) => `Trzyma ${packedArchive(params)} ${PACKED_ARCHIVE_NOTE} Przeczytaj, gdzie kod je zapisuje.`],
  ['loaded.halt_compiler_payload', (params) => (
    `${ALWAYS_LOADED} zatrzymuje się na __halt_compiler() i czyta dane schowane za tym miejscem (${line(params)}).`
  )],
  ['loaded.decoder_chain', (params) => (
    `${ALWAYS_LOADED} dekoduje zapisany tekst dwa razy z rzędu, ${params.get('what')}(…)), ${inLine(params)}. Tak zwykle chowa się spakowany kod.`
  )],
  ['loaded.char_chain', (params) => `${ALWAYS_LOADED} składa napis po jednym znaku przez chr(), ${inLine(params)}.`],
  ['loaded.eval_call', (params) => `${ALWAYS_LOADED} wykonuje tekst jako PHP: ${mechanism(params)}, ${inLine(params)}.`],
  ['loaded.variable_variable', (params) => (
    `${ALWAYS_LOADED} używa zmiennej, której nazwa jest wyliczana ($$nazwa), ${inLine(params)}. Przeczytaj, na co wskazuje.`
  )],
  ['loaded.creates_admin', (params) => (
    `${ALWAYS_LOADED} zapisuje użytkownika z rolą administratora: ${mechanism(params)}, ${inLine(params)}.`
  )],
  ['loaded.hides_plugins', (params) => (
    `${ALWAYS_LOADED} zmienia listę wtyczek, którą pokazuje panel (filtr ${params.get('what')}, ${line(params)}). Przeczytaj, czy którejś nie ukrywa.`
  )],
  ['unproven.eval_decoded', (params) => (
    `Wykonuje zdekodowany tekst jako PHP: ${mechanism(params)} z dekodowaniem w środku, ${inLine(params)}. ${NEVER_IN_HONEST_CODE}`
  )],
  ['unproven.encoded_code', (params) => `Zawiera ${hiddenText(params)} (${line(params)}). ${NEVER_IN_HONEST_CODE}`],
  ['unproven.halt_compiler_payload', (params) => (
    `Zatrzymuje się na __halt_compiler() i czyta dane schowane za tym miejscem (${line(params)}).`
  )],
  ['unproven.decoder_chain', (params) => (
    `Dekoduje zapisany tekst dwa razy z rzędu, ${params.get('what')}(…)), ${inLine(params)}. Tak zwykle chowa się spakowany kod, czasem też spakowane dane.`
  )],
  ['unproven.char_chain', (params) => `Składa napis po jednym znaku przez chr(), ${inLine(params)}.`],
  ['unproven.creates_admin', (params) => (
    `Zapisuje użytkownika z rolą administratora: ${mechanism(params)}, ${inLine(params)}. Importery i instalatory też to robią, więc przeczytaj, kiedy ten kod działa.`
  )],
  ['code.too_large', (params) => {
    if (params.get('reason') === 'tokens') {
      return `Plik PHP (${sizeOf(params)}), który dzieli się na ponad milion kawałków kodu, więcej, niż ten skaner czyta. Kod nie został sprawdzony.`;
    }
    if (params.get('reason') === 'nesting') {
      return `Plik PHP (${sizeOf(params)}), w którym kod w napisach jest zagnieżdżony głębiej niż na 32 poziomy, a dalej ten skaner nie schodzi. Kod nie został sprawdzony.`;
    }
    return `Plik PHP (${sizeOf(params)}), większy niż 8 MB, które ten skaner czyta jako kod. Kod nie został sprawdzony.`;
  }],
  ['code.time_limit', () => (
    'Czytanie tego pliku jako kodu trwało ponad 2 sekundy, więc kod nie został sprawdzony. Uczciwe pliki zajmują milisekundy, a tak wygląda plik zbudowany po to, żeby zawiesić skaner.'
  )],

  ['config.prepend_unusual', (params) => (
    `Każe PHP wykonać ${params.get('what')} przed każdą stroną albo po niej (${line(params)}). Ten plik leży w uploads, nie jest plikiem PHP albo jest adresem.`
  )],
  ['config.prepend', (params) => (
    `Każe PHP wykonać ${params.get('what')} przed każdą stroną albo po niej (${line(params)}). Tak działają zapory, na przykład Wordfence, więc przeczytaj ten plik.`
  )],
  ['config.php_handler', (params) => (params.get('what') === '*'
    ? `Oddaje PHP każdy plik z tego folderu (${line(params)}), także obrazki.`
    : `Oddaje PHP pliki ${params.get('what')} (${line(params)}), więc taki plik wykona się jako kod.`
  )],
  ['config.cgi_handler', (params) => (
    `Każe serwerowi uruchamiać jako program CGI ${configTarget(params)} (${line(params)}). `
    + 'XAMPP domyślnie pozwala na CGI w swoim folderze stron, więc taki plik uruchomi program, gdy ktoś otworzy jego adres.'
  )],
  ['config.server_side_includes', (params) => (
    `Włącza wstawki po stronie serwera (SSI) dla: ${configTarget(params)} (${line(params)}). `
    + 'XAMPP domyślnie pozwala na nie w swoim folderze stron, a taka wstawka potrafi uruchomić polecenie, więc przeczytaj, co jest w tych plikach.'
  )],
  ['config.redirect', (params) => (
    `Przekierowuje odwiedzających na ${params.get('what')}, a to nie jest adres tej strony zapisany w bazie (${line(params)}).`
  )],
  ['config.too_large', (params) => `Plik ustawień serwera (${sizeOf(params)}), większy, niż ten skaner czyta. Nie został sprawdzony.`],

  ['db.eval_base64', () => 'W bazie leży kod PHP, który wykonuje przez eval tekst zdekodowany z base64. Tak ukrywa się to, co naprawdę się uruchamia.'],
  ['db.snippet_rows', () => 'W bazie są zapisane snippety kodu, które strona wykonuje jako PHP. Przeczytaj każdy, zanim uruchomisz kopię.'],
  ['db.snippet_plugin_active', (params) => {
    // The slugs of the active snippet plugins, joined with ", ".
    const plugins = String(params.get('plugins') ?? '');
    return plugins.includes(', ')
      ? `Aktywne są wtyczki do snippetów (${plugins}). Wykonują kod PHP trzymany w bazie, którego nie pokaże żaden plik z kopii.`
      : `Aktywna jest wtyczka do snippetów (${plugins}). Wykonuje kod PHP trzymany w bazie, którego nie pokaże żaden plik z kopii.`;
  }],
  ['db.active_plugin_missing', (params) => (
    `Aktywne wtyczki z bazy, których folderu nie ma w kopii: ${formatCount(params.get('missing') ?? 0)} (${params.get('example')}). Kopia nie jest całą stroną.`
  )],
  ['db.external_script_host', (params) => (
    params.get('hosts') === 1
      ? `Strony zapisane w bazie ładują skrypty z obcego hosta: ${params.get('example')}. Sprawdź, czy powinien tam być.`
      : `Strony zapisane w bazie ładują skrypty z obcych hostów (${formatCount(params.get('hosts') ?? 0)}): ${params.get('example')}. Sprawdź, czy każdy z nich powinien tam być.`
  )],
  ['db.not_found', () => 'W kopii nie ma zrzutu bazy (.sql), więc baza nie została sprawdzona.'],
  ['text.ai_instruction', (params) => (
    `Zawiera zdanie skierowane do asystenta AI, który czyta kopię („${params.get('what')}”). To, co plik mówi sam o sobie, niczego nie dowodzi. Ktoś liczył na to, że przeczyta to AI.`
  )],

  ['indicator.known_file', (params) => `Co do bajta plik ze znanego ataku: ${CAMPAIGN_TEXT.get(params.get('campaign')) ?? 'kampania opisana publicznie'}.`],
  ['indicator.known_name', (params) => (
    `Nosi nazwę pliku ze znanego ataku: ${CAMPAIGN_TEXT.get(params.get('campaign')) ?? 'kampania opisana publicznie'}. Zawartość może być inna, więc go przeczytaj.`
  )],

  ['zip.not_a_zip', () => 'To nie jest archiwum zip, które ten skaner umie przeczytać. Nic nie zostało sprawdzone.'],
  ['zip.multi_disk', () => 'Zip wieloczęściowy. Nic nie zostało sprawdzone.'],
  ['zip.directory_unreadable', () => 'Spis treści zipa jest uszkodzony. Nic nie zostało sprawdzone.'],
  ['zip.too_many_entries', (params) => (
    `Archiwum ma w spisie ${formatCount(params.get('entries') ?? 0)} ${plural(params.get('entries') ?? 0, { one: 'pozycję', few: 'pozycje', many: 'pozycji' })}, więcej, niż ten skaner przyjmuje. Nic nie zostało sprawdzone.`
  )],
  ['zip.ambiguous_end_record', () => (
    'Zip ma dwa konkurujące rekordy końca. Różne programy otworzą z niego różne archiwa. Nic nie zostało sprawdzone.'
  )],
  ['zip.ambiguous_directory', () => (
    'Zip ma dwa spisy treści. Różne programy otworzą z niego różne archiwa. Nic nie zostało sprawdzone.'
  )],
  ['zip.directory_mismatch', () => (
    'Spis treści jest dłuższy albo krótszy, niż deklaruje zip. Część programów pokaże inne pliki niż tutaj.'
  )],
  ['zip.duplicate_name', () => 'Dwie pozycje mają tę samą nazwę. Od programu rozpakowującego zależy, która trafi na dysk.'],
  ['zip.header_mismatch', (params) => {
    const fields = String(params.get('fields') ?? '').split(' ').map((field) => HEADER_FIELDS.get(field) ?? '?').join(', ');
    const other = params.get('localName');
    return `Nagłówek przed danymi nie zgadza się ze spisem treści (${fields}).${other ? ` Nazwa w nagłówku: ${other}` : ''}`;
  }],
  ['zip.unicode_path_differs', (params) => (
    `Pozycja ma drugą nazwę, której część programów użyje zamiast pierwszej: ${params.get('otherName')}`
  )],
  ['zip.stored_size_mismatch', () => 'Niespakowana pozycja z dwoma różnymi rozmiarami. Programy rozpakowujące nie są zgodne, którego użyć.'],
  ['zip.overlapping_entries', () => 'Dane tej pozycji nachodzą na dane innej.'],
  ['zip.unlisted_entry', (params) => (
    `Nagłówek pliku w bajcie ${formatCount(params.get('offset') ?? 0)}, którego nie ma w spisie treści. Część programów go rozpakuje.`
  )],
  ['zip.prepended_data', (params) => (
    `Przed archiwum leży ${sizeOf(params)} danych, które nie należą do żadnego pliku ze spisu${leadKind(params)}.`
  )],
  ['zip.unlisted_bytes', (params) => (
    `W bajcie ${formatCount(params.get('offset') ?? 0)} leży ${sizeOf(params)} danych, które nie należą do żadnego pliku ze spisu${leadKind(params)}.`
  )],
  ['zip.trailing_data', (params) => `Za końcem archiwum leży jeszcze ${sizeOf(params)} danych.`],
  ['zip.encrypted_entry', () => 'Zabezpieczony hasłem, więc nie dało się go przeczytać.'],
  ['zip.unsupported_compression', (params) => (
    `Spakowany metodą, której ten skaner nie rozpakowuje (numer ${params.get('method')}).`
  )],
  ['zip.entry_unreadable', (params) => (
    `Nie dało się przeczytać: ${UNREADABLE_REASONS.get(params.get('reason')) ?? 'powód nieznany'}.`
  )],

  ['entry.corrupt_data', (params) => `Nie dało się przeczytać w całości: ${CORRUPT_REASONS.get(params.get('reason')) ?? 'powód nieznany'}.`],
  ['entry.head_unreadable', () => 'Pierwszych bajtów nie dało się rozpakować w ramach limitu.'],

  ['scan.not_wordpress', () => 'Nie ma wp-includes/version.php, wp-config.php ani folderu wp-content. To nie wygląda na kopię WordPressa.'],
  ['scan.content_part', () => (
    'Zawartość tego zipa wygląda jak wnętrze folderu wp-content, ale samego folderu wp-content w nim nie ma. UpdraftPlus zapisuje kopię w kilku takich zipach: osobno wtyczki, motywy, uploads i resztę. Skaner sprawdził ten zip jako wnętrze wp-content i nie widział pozostałych zipów tej kopii, więc zeskanuj je osobno.'
  )],
  ['scan.other_wordpress', () => (
    'W tym folderze leży drugi WordPress. Jeden skan porównuje z wordpress.org jedną stronę, tę najbliżej początku archiwum. Ta nie została porównana, jej wtyczki też nie. Jej pliki są oceniane jak nieznany kod.'
  )],
  ['scan.other_copy', () => (
    'W tym folderze jest wp-content, ale nie ma wp-includes. Jeden skan porównuje z wordpress.org najwyżej jedną stronę, a ten folder do niej nie należy. Wtyczek z jego wp-content nie porównano. Jego pliki są oceniane jak nieznany kod.'
  )],
  ['scan.stalled', () => 'Skaner przestał odpowiadać przy czytaniu tego pliku. Skan został przerwany.'],
  ['scan.failed', (params) => `Skan zatrzymał się na błędzie wewnętrznym (${params.get('error') ?? 'nieznanym'}). Wynik jest niepełny.`],
]);

const leadKind = (params) => {
  const kind = params.get('kind');
  if (PROGRAM_KINDS.has(kind)) return `, a zaczynają się jak ${PROGRAM_KINDS.get(kind)}`;
  return ARCHIVE_KINDS.has(kind) ? `, a zaczynają się jak archiwum ${ARCHIVE_KINDS.get(kind)}` : '';
};

// Past the cap a rule's findings are only counted. Rows on the page are per file, so "tego
// rodzaju" would point at nothing: the line names the first place the rule found instead, a
// file or a folder. A rule about the copy as a whole has no place; its line sits in that row.
const describeOverflow = (more, example) => {
  if (example === '') {
    return `Jeszcze ${formatCount(more)} ${plural(more, { one: 'znalezisko', few: 'znaleziska', many: 'znalezisk' })} tego rodzaju, niewypisane osobno.`;
  }
  return more === 1
    ? `Jeszcze jedno znalezisko takie jak przy ${example}. Skaner nie wypisuje go osobno.`
    : `Jeszcze ${formatCount(more)} ${plural(more, { one: 'znalezisko takie', few: 'znaleziska takie', many: 'znalezisk takich' })} jak przy ${example}. Skaner nie wypisuje ich osobno.`;
};

export const describeFinding = (finding) => {
  const more = finding.params.get('more');
  if (more !== undefined) return describeOverflow(more, finding.params.get('example') ?? '');
  return FINDING_TEXT.get(finding.rule)(finding.params);
};

export const SEVERITY_LABELS = new Map([
  ['red', 'Nie uruchamiaj'],
  ['amber', 'Przeczytaj najpierw'],
  ['not_checked', 'Niesprawdzone'],
]);

const STAGE_LABELS = new Map([
  ['first_bytes', 'pierwsze bajty'],
  ['checksums', 'porównanie z wordpress.org'],
  ['php_code', 'kod PHP'],
  ['database', 'baza'],
  ['nested_archives', 'archiwa w kopii'],
]);
// Stages counted in bytes, not files.
const BYTE_STAGES = new Set(['database']);

const describeLoadedFile = (file) => `${file.path} (${file.name ? `${file.name}, ` : ''}${formatBytes(file.bytes)})`;

const describeComponent = (event) => {
  const name = event.kind === 'core' ? `WordPress ${event.version}` : `${event.name} ${event.version}`;
  if (event.state !== 'listed') return `${name}: nie porównano, ${notComparedReason(event.kind, event.state)}`;
  return `${name}: zgodnych z wordpress.org ${formatCount(event.matched)} z ${formatCount(event.files)} ${plural(event.files, { one: 'pliku', few: 'plików', many: 'plików' })}, `
    + `różnych ${formatCount(event.modified)}, dodatkowych ${formatCount(event.extra)}, brakujących ${formatCount(event.missing)}`;
};

const listed = (names) => (names.length === 0 ? 'brak' : names.join(', '));

const requestsSent = (count) => plural(count, {
  one: 'poszło jedno zapytanie',
  few: `poszły ${formatCount(count)} zapytania`,
  many: `poszło ${formatCount(count)} zapytań`,
});

export const LOG_TEXT = {
  reading: (name, bytes) => `${name}, ${formatBytes(bytes)}`,
  opened: (event) => (
    `${formatCount(event.files)} ${filesWord(event.files)} w ${formatCount(event.folders)} ${plural(event.folders, { one: 'folderze', few: 'folderach', many: 'folderach' })}, `
    + `po rozpakowaniu ${formatBytes(event.declaredBytes)} (według archiwum)`
  ),
  core: (facts) => (facts.version
    ? `WordPress ${facts.version}, paczka ${facts.locale}, folder główny „${facts.root}”`
    : 'nie znaleziono wersji WordPressa'),
  plugins: (names) => `wtyczki: ${listed(names)}`,
  themes: (names) => `motywy: ${listed(names)}`,
  database: (database) => `baza: ${database.path}, ${formatBytes(database.bytes)}`,
  siteHosts: (hosts) => `w bazie zapisany jest własny adres strony: ${hosts.join(', ')}. Skrypty i przekierowania prowadzące pod ten adres nie są zgłaszane.`,
  progress: (event) => {
    const amount = BYTE_STAGES.has(event.stage) ? formatBytes : formatCount;
    return `${STAGE_LABELS.get(event.stage)}: ${amount(event.done)} z ${amount(event.total)}`;
  },
  request: (request) => `→ ${new URL(request.url).host}: ${REQUEST_LABELS.get(request.kind)(request)}`,
  component: describeComponent,
  waitingForAdvisories: 'plik przeczytany, czekam na odpowiedzi o znanych podatnościach',
  loadedCode: (event) => {
    if (event.total === 0) return `kod, który WordPress wczytuje sam ${LOADED_SOURCES}: brak`;
    const unlisted = event.total - event.files.length;
    const more = unlisted > 0 ? `, i jeszcze ${formatCount(unlisted)}` : '';
    const read = event.total === 1 ? 'przeczytaj ten plik' : 'przeczytaj każdy plik';
    return `kod, który WordPress wczytuje sam ${LOADED_SOURCES}, ${read}: ${event.files.map(describeLoadedFile).join(', ')}${more}`;
  },
  advisories: (records) => {
    const asked = records.filter((record) => record.state === 'checked');
    const affected = asked.filter((record) => record.entries.length > 0);
    const entries = affected.reduce((total, record) => total + record.entries.length, 0);
    const closed = records.filter((record) => record.closed !== null).length;
    const closedText = closed > 0 ? `, zamkniętych przez wordpress.org: ${formatCount(closed)}` : '';
    const checked = plural(asked.length, { one: 'sprawdzonego składnika', few: 'sprawdzonych składników', many: 'sprawdzonych składników' });
    return `znane podatności: ${formatCount(entries)}, w ${formatCount(affected.length)} z ${formatCount(asked.length)} ${checked}${closedText}`;
  },
  done: (stats, requestUrls) => {
    const timing = `Koniec po ${fractionFormat.format(stats.milliseconds / 1000)} s. Z pliku przeczytane ${formatBytes(stats.bytesRead)}.`;
    if (requestUrls.length === 0) return `${timing} Nic nigdzie nie zostało wysłane.`;
    const sites = [...new Set(requestUrls.map(siteOf))].join(' i ');
    return `${timing} Sam plik został w tej przeglądarce. Do ${sites} ${requestsSent(requestUrls.length)}, tylko z nazwami i wersjami, wypisane wyżej.`;
  },
};

const siteOf = (url) => {
  const { hostname } = new URL(url);
  return hostname.endsWith('.wordpress.org') ? 'wordpress.org' : hostname.replace(/^www\./, '');
};

// The known-vulnerabilities list. Every string in a record has passed the display sanitizer.
export const ADVISORY_TEXT = {
  heading: (record) => {
    const name = record.kind === 'core' ? `WordPress ${record.version}` : `${ADVISORY_KINDS.get(record.kind)} ${record.name} ${record.version}`.trim();
    // A closed plugin is drawn even when its vulnerabilities were never looked up (no version).
    if (record.state !== 'checked') return `${name}: znane podatności niesprawdzone`;
    const count = record.entries.length;
    const counted = count === 1
      ? 'jedna znana podatność'
      : `${formatCount(count)} ${plural(count, { one: 'znana podatność', few: 'znane podatności', many: 'znanych podatności' })}`;
    return `${name}: ${counted} w tej wersji`;
  },
  closed: (closed) => {
    const when = closed.date ? ` (${closed.date})` : '';
    const why = closed.reason ? ` Podany powód: ${closed.reason.replaceAll('-', ' ')}.` : '';
    return `wordpress.org zamknął tę wtyczkę${when}.${why} Zamknięta wtyczka nie dostaje stamtąd aktualizacji, także poprawek bezpieczeństwa.`;
  },
  entry: (entry) => {
    const parts = [entry.ids.length > 0 ? entry.ids.join(', ') : 'bez numeru CVE', rangeText(entry)];
    if (entry.score >= 0) parts.push(`CVSS ${entry.score.toFixed(1)}`);
    if (entry.weakness) parts.push(`${entry.weakness.id} ${entry.weakness.name}`.trim());
    return parts.join(' · ');
  },
  more: (count) => `Jeszcze ${formatCount(count)}, niewypisane osobno.`,
  sourceLabel: (url) => SOURCE_LABELS.get(new URL(url).hostname) ?? new URL(url).hostname,
};

const rangeText = (entry) => {
  if (entry.range === null) return 'dotyczy tego wydania';
  const { range } = entry;
  const bounds = [
    range.minOperator ? `${BOUND_WORDS.get(range.minOperator)} ${range.min}` : '',
    range.maxOperator ? `${BOUND_WORDS.get(range.maxOperator)} ${range.max}` : '',
  ].filter(Boolean).join(' ');
  if (entry.unfixed) return `wersje ${bounds}, poprawionego wydania jeszcze nie ma`;
  return range.maxOperator === 'lt' ? `wersje ${bounds}, poprawione w ${range.max}` : `wersje ${bounds}`;
};

export const STATUS_TEXT = {
  scanning: 'Skanuję…',
  lookingUp: 'Plik przeczytany. Czekam na odpowiedzi o znanych podatnościach…',
  incomplete: 'Skan nie doszedł do końca. Zobacz „Niesprawdzone” niżej.',
  withRed: 'Nie uruchamiaj tej kopii.',
  withoutRed: 'Nie ma czerwonych znalezisk. To nie znaczy, że kopia jest czysta: zanim ją uruchomisz, przeczytaj listy bursztynowe i niesprawdzone.',
  nothingFound: 'Żaden ze sprawdzanych kształtów nie trafił. To nie znaczy, że kopia jest czysta, a uruchomienie jej pod Windowsem dalej jest ryzykiem.',
};

// How many of the red findings rest on rules alone, as the start of a sentence.
const ruleOnlyShare = (count, total) => {
  if (total === 1) return 'Jedyne czerwone znalezisko pochodzi';
  if (count === total) return `Wszystkie czerwone znaleziska (${formatCount(total)}) pochodzą`;
  return `Czerwonych znalezisk jest ${formatCount(total)}, z tego ${formatCount(count)} ${plural(count, { one: 'pochodzi', few: 'pochodzą', many: 'pochodzi' })}`;
};

// The lines under the verdict. `comparison` is what main.js counted from the component events.
export const SUMMARY_TEXT = {
  compared: (comparison) => {
    if (!comparison.online) return 'Nic nie zostało porównane z wordpress.org, bo porównanie było wyłączone. Każdy plik oceniały same reguły.';
    if (comparison.matchedFiles === 0 && !comparison.core && comparison.pluginsCompared === 0) {
      return 'Niczego w tej kopii nie dało się porównać z wordpress.org. Każdy plik oceniały same reguły.';
    }
    const core = comparison.core ? `WordPress ${comparison.version}` : 'bez rdzenia';
    return `Porównane z wordpress.org: ${core}, wtyczki: ${formatCount(comparison.pluginsCompared)} z ${formatCount(comparison.pluginsTotal)}. `
      + `Plików zgodnych co do bajta z oficjalnymi wydaniami: ${formatCount(comparison.matchedFiles)}. `
      + 'Motywy, uploads i kod, który WordPress wczytuje sam, nie mają oficjalnej listy, więc oceniały je same reguły.';
  },
  // `files`: how many files those findings sit in (one file can hold several).
  ruleOnlyRed: (count, total, files) => (
    `${ruleOnlyShare(count, total)} z reguł zastosowanych do kodu, którego nie było z czym porównać. `
    + `Reguła może się mylić co do uczciwego kodu, więc przeczytaj ${files === 1 ? 'ten plik' : 'te pliki'}, zanim zdecydujesz.`
  ),
  loadedCode: (total) => (total === 1
    ? `WordPress sam wczytuje 1 plik ${LOADED_SOURCES}, którego nie trzeba włączać w panelu. `
      + 'Jest na liście niżej. Przeczytaj go, cokolwiek powiedziały o nim reguły.'
    : `WordPress sam wczytuje ${formatCount(total)} ${filesWord(total)} ${LOADED_SOURCES}, których nie trzeba włączać w panelu. `
      + 'Lista jest niżej. Przeczytaj każdy, cokolwiek powiedziały o nim reguły.'
  ),
  container: 'Jeśli jednak uruchamiasz tę kopię, rób to w kontenerze z Linuksem, nie na Windowsie z XAMPP-em albo LocalWP. Pułapka, po której powstał ten skaner, uruchamia program dla Windows.',
};

// Rows of the lists under the findings.
export const LIST_TEXT = {
  loadedFile: describeLoadedFile,
  component: describeComponent,
  hash: (sha256) => `SHA-256 ${sha256}`,
  // Stand where a path would: a finding about the archive itself, not one file in it, and the
  // line that counts a rule's findings past the cap, which are about files it does not name.
  wholeCopy: '(cała kopia)',
  moreFindings: '(pozostałe znaleziska)',
  // `shown` counts rows, one per file; `other` counts the findings left out.
  undrawnFindings: (shown, other) => (
    `Lista pokazuje ${formatCount(shown)} ${filesWord(shown)} z najcięższymi znaleziskami. `
    + `${other === 1 ? 'Jeszcze jedno znalezisko jest' : `Pozostałe znaleziska (${formatCount(other)}) są`} w raporcie, który możesz niżej skopiować albo pobrać.`
  ),
};

// The report a visitor copies or downloads.
export const EXPORT_TEXT = {
  title: (pageUrl) => `Raport ze Skanera kopii zapasowych dla WordPressa (${pageUrl})`,
  generated: (time) => `Wygenerowany: ${time}`,
  archive: (archive) => `Archiwum: ${archive.name}, ${formatBytes(archive.bytes)}, ${formatCount(archive.files)} ${filesWord(archive.files)}`,
  wordpress: (facts) => LOG_TEXT.core(facts),
  finished: (stats, requestUrls) => LOG_TEXT.done(stats, requestUrls),
  verdict: (sentence) => `Werdykt: ${sentence}`,
  counts: (counts) => `Nie uruchamiaj: ${formatCount(counts.red)} · Przeczytaj najpierw: ${formatCount(counts.amber)} · Niesprawdzone: ${formatCount(counts.not_checked)}`,
  severityTitles: new Map([['red', 'NIE URUCHAMIAJ'], ['amber', 'PRZECZYTAJ NAJPIERW'], ['not_checked', 'NIESPRAWDZONE']]),
  excerpt: (text) => `w pliku: ${text}`,
  advisories: 'ZNANE PODATNOŚCI (stara wersja to nie pułapka, więc nic z tej sekcji nie liczy się do czerwonych)',
  components: 'PORÓWNANE Z WORDPRESS.ORG',
  loadedCode: (total) => (total === 1 ? 'KOD, KTÓRY WORDPRESS WCZYTUJE SAM (przeczytaj ten plik)' : 'KOD, KTÓRY WORDPRESS WCZYTUJE SAM (przeczytaj każdy plik)'),
  requests: 'WYSŁANE ZAPYTANIA (tylko nazwy i wersje)',
  noRequests: 'Nie zostało wysłane żadne zapytanie.',
  masked: 'Adresy e-mail w tym raporcie są zamaskowane.',
};

// What the page's own controls say back.
export const UI_TEXT = {
  exampleName: 'kopia-przykladowa.zip',
  reportFileName: 'raport-skanera-kopii-wordpress',
  copied: 'Skopiowane do schowka.',
  copyRefused: 'Przeglądarka nie dała dostępu do schowka. Raport jest w polu niżej: zaznacz go i skopiuj ręcznie.',
  logShow: 'Pokaż cały log',
  logHide: 'Zwiń log',
};
