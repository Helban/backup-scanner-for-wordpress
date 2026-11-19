"""The structural checks were ported from a Python prototype. For the checks both have, the
browser engine must reach the prototype's verdict on the same sample archives.

reference/layout_findings.json holds the prototype's findings, recorded once. The engine
reports more than the prototype did, so only the rules the two share are compared.
"""
import json
from pathlib import Path

import pytest

from conftest import finding_keys
from samples import SAMPLES

REFERENCE = json.loads((Path(__file__).parent / "reference" / "layout_findings.json").read_text(encoding="utf-8"))
SHARED_RULES = set(REFERENCE["rules"])
REFERENCE_SAMPLES = [sample for sample in SAMPLES if sample.in_reference]
# Where the engine departs from the prototype on purpose: (sample, the prototype's finding) ->
# what the engine reports instead. A build script among a plugin's code is amber since
# 2026-11-13: three official plugins of the 30 in the test copy ship one.
DELIBERATE_DIFFERENCES = {
    ("layout_mix", ("red", "layout.executable_extension", "files/wp-content/plugins/tool/run.sh")):
        ("amber", "layout.script_in_code_folder", "files/wp-content/plugins/tool/run.sh"),
}


def test_reference_covers_the_marked_samples():
    assert set(REFERENCE["samples"]) == {sample.name for sample in REFERENCE_SAMPLES}


@pytest.mark.parametrize("sample", REFERENCE_SAMPLES, ids=lambda sample: sample.name)
def test_engine_agrees_with_the_prototype(sample, scan):
    recorded = {tuple(found) for found in REFERENCE["samples"][sample.name]}
    replaced = {old: new for (name, old), new in DELIBERATE_DIFFERENCES.items() if name == sample.name}
    assert replaced.keys() <= recorded
    everything = finding_keys(scan(sample.build()))
    assert {found for found in everything if found[1] in SHARED_RULES} == recorded - replaced.keys()
    assert set(replaced.values()) <= everything
