"""Protect substring-based advice selection from silent contract drift.

WHAT THIS PROTECTS. `_unverifiable_advice` examines text returned by the SDK and
chooses advice when it finds a substring. The selectors are fragments of human prose,
such as "awaiting block" or "mandate not found". Translating, rephrasing, or adding a
comma in the SDK can remove the match and replace specific advice such as "retry in
1-3 hours" with a generic response. Nothing crashes; the branch simply becomes dead.

WHAT THIS TEST ASSERTS, and the boundary matters: every substring used to select an
advice branch is still produced by an SDK runtime string. It does not prove that the
correct branch runs for a live response. Paired behavioral tests establish that, and
neither form of coverage replaces the other.

THE FIRST VERSION HAD GAPS IN BOTH DIRECTIONS (review finding RTSTR-004). It extracted
selectors with a regular expression matching `if "..." in detail`:

  * changing the consumer to single quotes made it find five selectors instead of six,
    yet it passed after silently losing one;
  * leaving an old phrase only in an SDK comment also passed despite the dead branch;
  * a correctly coordinated review change using English single-quoted selectors failed
    the test even though behavior was correct.

Selectors are now read from the syntax tree, making quote style irrelevant, and
checked against an explicit minimum so a missing selector is visible. Only SDK runtime
strings count as producers; a comment is not evidence of a live contract.
"""
import ast
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
SERVER = ROOT / "mcp-server" / "a4a_mcp" / "server.py"
SDK = ROOT / "sdk-python" / "a4a"

#: Minimum number of expected advice branches. This must be explicit: deriving it from
#: the result would make a missing selector look like the intended count.
EXPECTED_AT_LEAST = 5


def _selectors_from_ast() -> list[str]:
    """Extract advice selectors from the syntax tree instead of with a regex."""
    tree = ast.parse(SERVER.read_text(encoding="utf-8"))
    function = next(
        (n for n in ast.walk(tree)
         if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
         and n.name == "_unverifiable_advice"), None)
    assert function is not None, "advice function not found; the test would be vacuous"
    found = []
    for node in ast.walk(function):
        if not isinstance(node, ast.Compare) or len(node.ops) != 1:
            continue
        if not isinstance(node.ops[0], ast.In):
            continue
        right = node.comparators[0]
        if not (isinstance(right, ast.Name) and right.id == "detail"):
            continue
        if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
            found.append(node.left.value)
    return found


def _sdk_runtime_strings() -> str:
    """Collect SDK runtime strings, excluding comments and docstrings.

    A phrase left only in a comment cannot be produced by a response, but plain text
    search makes it look live. That gap let the first version pass incorrectly.
    """
    parts = []
    for path in sorted(SDK.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        docs = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                body = getattr(node, "body", None)
                if (body and isinstance(body[0], ast.Expr)
                        and isinstance(body[0].value, ast.Constant)
                        and isinstance(body[0].value.value, str)):
                    docs.add(id(body[0].value))
        for node in ast.walk(tree):
            if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                    and id(node) not in docs):
                parts.append(node.value)
    return "\n".join(parts)


def test_every_advice_selector_is_still_produced_by_sdk_runtime_text():
    selectors = _selectors_from_ast()
    assert len(selectors) >= EXPECTED_AT_LEAST, (
        f"found {len(selectors)} substring branches; expected at least "
        f"{EXPECTED_AT_LEAST}. A selector is missing or extraction is broken. "
        "A lower count is a finding, not a reason to lower the expectation.")
    sources = _sdk_runtime_strings()
    missing = [s for s in selectors if s not in sources]
    assert not missing, (
        "The SDK no longer produces these runtime strings, but advice still selects "
        f"on them: {missing}. The advice will silently fall back to the generic branch. "
        "Update the selectors in the same commit as the message: the consistency unit "
        "is the cross-module contract, not an individual file.")


def test_quote_style_does_not_change_what_is_extracted():
    """Keep syntax-tree extraction independent of quote style.

    The first regular expression lost single-quoted selectors and still passed after
    losing sight of them. This encodes the requirement as a property.
    """
    double = ast.parse('def f(detail):\n    if "a" in detail:\n        return 1\n')
    single = ast.parse("def f(detail):\n    if 'a' in detail:\n        return 1\n")

    def pull(tree):
        return [n.left.value for n in ast.walk(tree)
                if isinstance(n, ast.Compare) and len(n.ops) == 1
                and isinstance(n.ops[0], ast.In)
                and isinstance(n.comparators[0], ast.Name) and n.comparators[0].id == "detail"
                and isinstance(n.left, ast.Constant)]

    assert pull(double) == pull(single) == ["a"]
