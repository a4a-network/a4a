"""An install log alone cannot establish the expected dependency closure."""

from copy import deepcopy
import importlib.util
from pathlib import Path
import sys

import pytest


SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location("install_replay", SCRIPTS / "debian_install_replay.py")
REPLAY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPLAY)
BASE = "libbase:amd64\t1\tamd64\ndata\t1\tall\n"


def record(name="tool", version="2", architecture="amd64"):
    return {"Package": name, "Version": version, "Architecture": architecture,
            "Filename": f"pool/main/t/{name}/{name}.deb", "Size": "1", "SHA256": "a" * 64}


def check(before=BASE, after=BASE + "tool\t2\tamd64\n", locked=None, expected=BASE):
    return REPLAY.validate_install_inventory(before, after, [record()] if locked is None else locked, expected_base=expected)


def test_exact_addition_is_accepted_with_counts():
    assert check() == {"base_package_count": 2, "installed_package_count": 3,
                       "added_packages": 1, "changed_existing_packages": 0, "unchanged_packages": 2}


def test_exact_existing_change_and_alias_normalization_are_accepted():
    after = "libbase\t1\tamd64\ndata\t2\tall\n"
    assert check(after=after, locked=[record("data", "2", "all")])["changed_existing_packages"] == 1


@pytest.mark.parametrize("before", [BASE.replace("\t1\tamd64", "\t2\tamd64"),
                                     BASE + "extra\t1\tall\n", BASE.splitlines()[0] + "\n"])
def test_different_inherited_base_is_rejected(before):
    with pytest.raises(REPLAY.LockContractError, match="base"):
        check(before=before)


@pytest.mark.parametrize("after", [BASE, BASE + "tool\t3\tamd64\n", BASE + "tool\t2\tarm64\n",
                                    BASE + "tool\t2\tamd64\nextra\t1\tall\n",
                                    "data\t1\tall\ntool\t2\tamd64\n",
                                    BASE.replace("\t1\tamd64", "\t9\tamd64") + "tool\t2\tamd64\n"])
def test_missing_unexpected_or_wrong_final_inventory_is_rejected(after):
    with pytest.raises(REPLAY.LockContractError, match="inventory"):
        check(after=after)


@pytest.mark.parametrize("inventory", ["", "missing tabs", "pkg\t1\tamd64\textra\n",
                                        "pkg:arm64\t1\tamd64\n", "pkg\t1\ti386\n",
                                        "pkg\t1\tamd64\npkg:amd64\t1\tamd64\n", None])
def test_malformed_inventory_is_rejected(inventory):
    with pytest.raises(REPLAY.LockContractError):
        check(before=inventory)


def test_duplicate_lock_packages_are_rejected():
    package = record()
    with pytest.raises(REPLAY.LockContractError, match="duplicate"):
        check(locked=[package, deepcopy(package)])


def test_unchanged_target_does_not_count_as_an_upgrade():
    assert check(after=BASE, locked=[record("data", "1", "all")])["unchanged_packages"] == 2


def test_crlf_inventory_is_equivalent_to_lf():
    assert check(before=BASE.replace("\n", "\r\n"))["added_packages"] == 1
