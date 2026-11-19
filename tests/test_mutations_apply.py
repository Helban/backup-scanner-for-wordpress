"""Every mutation in run_mutations.py still finds the text it replaces, exactly once.

An edit to the scanner can leave a mutation pointing at a line that is gone. run_mutations.py
then reports it as not caught, but only in a full run of several minutes, after everything else
looked green. Checking the text here costs no browser and runs with every suite.
"""
from serve import REPO_ROOT
from run_mutations import MUTATIONS


def test_every_mutation_finds_its_text_exactly_once():
    sources = {mutation.file: (REPO_ROOT / mutation.file).read_text() for mutation in MUTATIONS}
    counts = [(mutation.name, sources[mutation.file].count(mutation.find)) for mutation in MUTATIONS]
    assert [(name, count) for name, count in counts if count != 1] == []
