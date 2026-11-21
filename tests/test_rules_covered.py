"""A rule nobody can trigger in a test is a rule nobody knows to work."""
import re

import pytest

from samples import SAMPLES
from serve import site_root

RULE_ROW = re.compile(r"\['([a-z]+\.[a-z0-9_]+)', '(red|amber|not_checked)'\]")
# Rules that no archive can trigger: they describe the scanner failing, and their tests break
# the worker on purpose.
COVERED_IN_PAGE_BEHAVIOUR = {"scan.stalled", "scan.failed"}
# Reached only with a time limit patched down to nothing (test_code_limits.py,
# test_nested_limits.py), or with the table of known files pointed at an inert sample
# (test_indicators.py): the real row is the hash of a password stealer, and no such file is
# ever built here.
COVERED_BY_PATCHED_SCANNER = {"code.time_limit", "archive.tail_not_checked", "indicator.known_file", "indicator.known_upload", "db.unpacked_too_large"}


def declared_rules() -> dict[str, str]:
    rows = RULE_ROW.findall((site_root() / "scanner" / "rules.js").read_text(encoding="utf-8"))
    assert len(rows) == len(dict(rows)), "a rule is listed twice in rules.js"
    return dict(rows)


def sampled_rules() -> dict[str, set[str]]:
    weights: dict[str, set[str]] = {}
    for sample in SAMPLES:
        for weight, rule, _ in sample.expected:
            weights.setdefault(rule, set()).add(weight)
    return weights


def test_every_rule_has_a_sample():
    without_sample = set(declared_rules()) - set(sampled_rules()) - COVERED_IN_PAGE_BEHAVIOUR - COVERED_BY_PATCHED_SCANNER
    assert without_sample == set()


def test_samples_expect_the_declared_weight():
    declared = declared_rules()
    for rule, weights in sampled_rules().items():
        assert weights == {declared.get(rule)}, rule


def extensions_in(file: str, list_name: str) -> set[str]:
    # The served copy, so that a mutation run sees the list it changed.
    source = (site_root() / "scanner" / file).read_text(encoding="utf-8")
    listed = re.search(rf"{list_name} = new Set\(\[(.*?)\]\)", source, re.DOTALL).group(1)
    return {extension.lstrip(".") for extension in re.findall(r"'([.a-z0-9]+)'", listed)}


def test_programs_the_code_rules_know_are_programs_by_name_too():
    """A rename to .jse in PHP was red while a file named .jse in the copy passed."""
    in_code = extensions_in("code-rules.js", "PROGRAM_EXTENSIONS")
    by_name = extensions_in("signatures.js", "EXECUTABLE_EXTENSIONS")
    assert in_code and in_code <= by_name


@pytest.mark.parametrize("sentences", ["messages-en.js", "messages-pl.js"])
def test_every_rule_has_a_sentence(sentences):
    messages = (site_root() / "scanner" / sentences).read_text(encoding="utf-8")
    without_sentence = {rule for rule in declared_rules() if f"['{rule}', " not in messages}
    assert without_sentence == set()
