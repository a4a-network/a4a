"""The specification kind registry must match code constants.

The specification is what OTHER implementations are built from. When it diverges
from code, it does more than become stale: outsiders build a broken client and look
for the defect on their side. That is exactly what happened with the agreement digest
(finding 48, 2026-08-30): it was not documented at all, leaving our code as the only
effective specification.

This is a mechanical comparison: every code kind appears in the registry, every
registry number exists in code, and names match. It also verifies that the parser
found something to compare; otherwise a broken regular expression would pass green.
"""
import re
from pathlib import Path

from a4a import giftwrap, types

SPEC = Path(__file__).resolve().parent.parent.parent / "docs" / "spec" / "a4a-protocol-v0.4.md"


def _kinds_in_code() -> dict[int, str]:
    found = {v: n[5:] for n, v in vars(types).items()
             if n.startswith("KIND_") and isinstance(v, int)}
    # Gift wrap and seal live in giftwrap.py: they belong to NIP-59, not A4A models.
    found[giftwrap.KIND_SEAL] = "SEAL"
    found[giftwrap.KIND_GIFT_WRAP] = "GIFT_WRAP"
    return found


def _kinds_in_spec() -> dict[int, str]:
    rows = re.findall(r"^\| (\d+) \| (\w+) \|", SPEC.read_text(encoding="utf-8"), re.M)
    return {int(num): name for num, name in rows}


def _normalise(name: str) -> str:
    return name.replace("_", "").casefold()


def test_every_kind_from_code_is_in_the_registry():
    missing = sorted(set(_kinds_in_code()) - set(_kinds_in_spec()))
    assert not missing, (
        f"kinds exist in code but not in the specification registry: {missing}. "
        f"Third-party implementations cannot discover them")


def test_registry_does_not_invent_kinds():
    """Conversely, a number absent from code is a false interoperability promise."""
    phantom = sorted(set(_kinds_in_spec()) - set(_kinds_in_code()))
    assert not phantom, f"registry names kinds that do not exist in code: {phantom}"


def test_names_match():
    code, spec = _kinds_in_code(), _kinds_in_spec()
    wrong = [(k, code[k], spec[k]) for k in set(code) & set(spec)
             if _normalise(code[k]) != _normalise(spec[k])]
    assert not wrong, f"kind names differ (number, code, specification): {wrong}"


def test_there_is_something_to_compare():
    """The preceding checks would pass on an empty registry if parsing broke."""
    assert len(_kinds_in_spec()) >= 20, "specification registry was not parsed"
    assert len(_kinds_in_code()) >= 20, "kind constants were not found in code"


#: Kinds declared as format-only in the registry. This list is duplicated
#: INTENTIONALLY: if someone implements one and forgets the specification, the test
#: must fail. The converse matters too: a format-only label on an implemented kind
#: misleads readers into believing the protocol supports less than it does.
FORMAT_ONLY = {31006: "Invoice", 31010: "SearchIntent", 31985: "Report"}
FORMAT_ONLY_MARKER = "format only"


def test_format_only_kinds_really_have_no_implementation():
    """A reserved kind must have neither publication nor reading support in Agent.

    "Format without code" is a promise to readers: the label tells them they would be
    first to implement it. If implementation appears while the label remains, the
    promise becomes false in the opposite direction.
    """
    import inspect

    from a4a.agent import Agent

    methods = {n: inspect.getsource(m)
               for n, m in inspect.getmembers(Agent, predicate=inspect.isfunction)
               if not n.startswith("_")}
    for kind, name in FORMAT_ONLY.items():
        users = [m for m, src in methods.items() if f"types.{name}" in src]
        assert not users, (
            f"kind {kind} ({name}) is marked format-only, but Agent implements it in "
            f"methods {users}. Remove the registry label or remove the methods")


def test_format_only_kinds_are_marked_in_the_registry():
    """Conversely, registry labels must remain or readers will assume support."""
    text = SPEC.read_text(encoding="utf-8")
    for kind in FORMAT_ONLY:
        row = re.search(rf"^\| {kind} \|.*$", text, re.M)
        assert row, f"kind {kind} disappeared from the registry"
        assert FORMAT_ONLY_MARKER in row.group(0), (
            f"kind {kind} is not marked format-only in the registry: {row.group(0)[:110]}")
