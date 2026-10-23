"""Verify image metadata without putting installers back into runtime images."""

from copy import deepcopy
import importlib.util
from pathlib import Path

from packaging.markers import default_environment
import pytest


ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "runtime_graph_check", ROOT / "scripts/check-python-runtime-graph.py")
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def fixture():
    return {
        "environment": {**default_environment(), "python_version": "3.11",
                        "python_full_version": "3.11.14", "sys_platform": "linux"},
        "distributions": {
            "a4a-sdk": {"version": "0.3.3", "requires": ["transport[tls]>=1"]},
            "transport": {"version": "1.0", "requires": ['crypto>=2; extra == "tls"',
                'missing>=1; python_version >= "3.12"']},
            "crypto": {"version": "2.0", "requires": []},
        },
        "modules": {name: False for name in checker.BOOTSTRAP_MODULES},
        "crypto_licenses": {name: True for name in checker.CRYPTO_LICENSES},
    }


LOCK = {"transport": "1.0", "crypto": "2.0"}


def test_valid_graph_uses_image_markers_and_dependency_requested_extras():
    data = fixture()
    before = deepcopy(data)
    assert checker.verify(data, LOCK)["runtime_distributions"] == 3
    assert data == before


def test_stdlib_snapshot_captures_actual_markers_and_license_files():
    data = checker.snapshot()
    assert data["environment"] == default_environment()
    assert data["distributions"]["cryptography"]["version"]
    assert all(data["crypto_licenses"].values())


def test_retained_python_base_package_requires_an_exact_declared_pin():
    data = fixture()
    data["distributions"]["packaging"] = {"version": "26.3", "requires": []}
    base_lock = checker.read_lock(ROOT / "scripts/container-build-requirements.lock")
    assert checker.verify(data, LOCK, base_lock)["base_distributions"] == {"packaging": "26.3"}
    with pytest.raises(RuntimeError, match="unlocked runtime"):
        checker.verify(data, LOCK)
    data["distributions"]["packaging"]["version"] = "26.2"
    with pytest.raises(RuntimeError, match="differs from lock: packaging"):
        checker.verify(data, LOCK, base_lock)


def test_build_lock_does_not_allow_other_build_tooling_into_the_runtime():
    data = fixture()
    base_lock = checker.read_lock(ROOT / "scripts/container-build-requirements.lock")
    data["distributions"]["hatchling"] = {"version": base_lock["hatchling"], "requires": []}
    with pytest.raises(RuntimeError, match="unlocked runtime"):
        checker.verify(data, LOCK, base_lock)


@pytest.mark.parametrize("failure", ["missing", "incompatible"])
def test_requested_extra_is_checked_after_dependency_activation(failure):
    data = fixture()
    data["distributions"]["transport"]["requires"][0] = (
        ('absent>=2' if failure == "missing" else 'crypto>=3') + '; extra == "tls"')
    with pytest.raises(RuntimeError, match=failure + " runtime dependency"):
        checker.verify(data, LOCK)


@pytest.mark.parametrize("target", ["distribution", "module", "license", "lock", "unlocked", "marker"])
def test_runtime_contract_rejects_retained_or_missing_material(target):
    data = fixture()
    if target == "distribution":
        data["distributions"]["pip"] = {"version": "26.2.1", "requires": []}
    elif target == "module":
        data["modules"]["ensurepip"] = True
    elif target == "license":
        data["crypto_licenses"]["LICENSE.BSD"] = False
    elif target == "lock":
        data["distributions"]["crypto"]["version"] = "2.1"
    elif target == "unlocked":
        data["distributions"]["unexpected"] = {"version": "1", "requires": []}
    else:
        data["environment"].pop("sys_platform")
    with pytest.raises(RuntimeError):
        checker.verify(data, LOCK)


@pytest.mark.parametrize("component", ["mcp-server", "notary"])
def test_ci_verifier_reads_the_hashed_runtime_lock(component):
    locked = checker.read_lock(ROOT / component / "requirements.container.lock")
    assert locked["cryptography"] == "50.0.2"
