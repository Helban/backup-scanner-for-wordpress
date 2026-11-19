"""The search for a program inside a file sees the file in pieces, wherever the reader happens to
cut it. A header split across two pieces, or a PE mark that arrives many pieces after the header
pointing at it, has to be found exactly as in one piece."""
import pytest

from samples import LINUX_PROGRAM, WINDOWS_PROGRAM, far_header_program, waiting_headers

LEAD_BYTES = 200
# Far enough that the header has left the scanner's hands before its PE mark comes by.
DISTANT_HEADER_PROGRAM = far_header_program(distance=1500)

# Returns every way of cutting the file into pieces for which the program was not reported at
# its place.
MISSED_CUTS = """async ([programHex, leadBytes]) => {
  const { createProgramScanner } = await import('/scanner/program-scan.js');
  const program = Uint8Array.from(programHex.match(/../g), (pair) => parseInt(pair, 16));
  const file = new Uint8Array(leadBytes + program.length + 100).fill(0x20);
  file.set(program, leadBytes);
  const foundAt = (pieces) => {
    const scanner = createProgramScanner(file.length);
    for (const piece of pieces) scanner.feed(piece);
    return scanner.found === null ? null : scanner.found.offset;
  };
  const missed = [];
  for (let cut = 1; cut < file.length; cut += 1) {
    if (foundAt([file.subarray(0, cut), file.subarray(cut)]) !== leadBytes) missed.push(cut);
  }
  const byteByByte = Array.from(file, (_, at) => file.subarray(at, at + 1));
  if (foundAt(byteByByte) !== leadBytes) missed.push('byte by byte');
  if (foundAt([file]) !== leadBytes) missed.push('one piece');
  return missed;
}"""

PROGRAM_AT_BYTE_ZERO = """async (programHex) => {
  const { createProgramScanner } = await import('/scanner/program-scan.js');
  const program = Uint8Array.from(programHex.match(/../g), (pair) => parseInt(pair, 16));
  const scanner = createProgramScanner(program.length);
  scanner.feed(program);
  return scanner.found;
}"""


@pytest.mark.parametrize("program", [WINDOWS_PROGRAM, LINUX_PROGRAM, DISTANT_HEADER_PROGRAM], ids=["windows", "linux", "pe_mark_far_from_header"])
def test_a_program_is_found_however_the_file_is_cut(program, page, site_url):
    page.goto(site_url)
    assert page.evaluate(MISSED_CUTS, [program.hex(), LEAD_BYTES]) == []


def test_a_program_at_the_very_start_is_left_to_the_first_bytes_check(page, site_url):
    """A file that IS a program has its own finding; here only a program inside another file counts."""
    page.goto(site_url)
    assert page.evaluate(PROGRAM_AT_BYTE_ZERO, WINDOWS_PROGRAM.hex()) is None


# Feeds the file whole, the way WebKit hands over an unpacked file, and in small pieces.
GAVE_UP = """async (fileHex) => {
  const { createProgramScanner } = await import('/scanner/program-scan.js');
  const file = Uint8Array.from(fileHex.match(/../g), (pair) => parseInt(pair, 16));
  const whole = createProgramScanner(file.length);
  whole.feed(file);
  const inPieces = createProgramScanner(file.length);
  for (let at = 0; at < file.length; at += 1000) inPieces.feed(file.subarray(at, at + 1000));
  return { whole: [whole.gaveUp, whole.found], inPieces: [inPieces.gaveUp, inPieces.found] };
}"""


def test_a_flood_of_headers_stops_the_search_however_the_file_arrives(page, site_url):
    """Thousands of headers that each point megabytes ahead: the search stops and says so, and
    it does so whether the browser hands the file over in one piece or in many."""
    page.goto(site_url)
    # A lead in front: a header at the very start of a file is not counted as one inside it.
    outcome = page.evaluate(GAVE_UP, (b" " * LEAD_BYTES + waiting_headers()).hex())
    assert outcome == {"whole": [True, None], "inPieces": [True, None]}
