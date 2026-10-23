"""Metadata-only refresh; mocked signatures here are not native trust proof."""
from copy import deepcopy
from datetime import timedelta
import importlib
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from test_debian_acquire import acquisition
from test_debian_build_lock import bundle, NOW
from debian_lock_contract import LockContractError


def refresh_module():
    return importlib.import_module("debian_refresh")


def test_refresh_creates_explicit_candidate_preserving_install_inputs(acquisition):
    _, manifest, root, _, calls = acquisition
    before = deepcopy(manifest)
    output = root / "candidate"
    module = refresh_module()
    proof = module.refresh_candidate(manifest, root, output, now=NOW)
    candidate = json.loads((output / "lock.json").read_text())
    for stage in manifest["stages"]:
        for field in ("base_image", "base_inventory", "packages", "resolved_requests"):
            assert candidate["stages"][stage][field] == before["stages"][stage][field]
    assert manifest == before
    assert proof["packages_installed"] is False
    assert proof["candidate_only"] is True
    assert all(repo["signature_verified"] for repo in proof["repositories"])
    assert all(not url.endswith(".deb") for url in calls)
    assert module.validate_policy(candidate, json.loads((output / "policy.json").read_text()), now=NOW)
    assert (root / "builder/packages/tool.deb").read_bytes() == b"deb"


def test_policy_expires_at_observation_limit(acquisition):
    _, manifest, root, _, _ = acquisition
    module = refresh_module()
    output = root / "candidate"
    module.refresh_candidate(manifest, root, output, now=NOW)
    candidate, policy = [json.loads((output / name).read_text()) for name in ("lock.json", "policy.json")]
    module.validate_policy(candidate, policy, now=NOW + timedelta(hours=24) - timedelta(seconds=1))
    with pytest.raises(LockContractError, match="expired"):
        module.validate_policy(candidate, policy, now=NOW + timedelta(hours=24))


def test_policy_cannot_extend_signed_expiry(acquisition):
    _, manifest, root, remote, _ = acquisition
    for url in list(remote):
        if url.endswith("InRelease"):
            remote[url] = remote[url].replace(b"Thu, 08 Oct 2026 00:00:00 UTC",
                                              b"Fri, 02 Oct 2026 12:00:00 UTC")
    module = refresh_module()
    output = root / "candidate"
    module.refresh_candidate(manifest, root, output, now=NOW)
    policy = json.loads((output / "policy.json").read_text())
    assert policy["usable_until_utc"] == "2026-10-02T12:00:00+00:00"


def test_refresh_rejects_authenticated_date_rollback(acquisition):
    _, manifest, root, remote, _ = acquisition
    for url in list(remote):
        if url.endswith("InRelease"):
            remote[url] = remote[url].replace(b"Thu, 01 Oct 2026", b"Wed, 30 Sep 2026")
    output = root / "rollback"
    with pytest.raises(LockContractError, match="rollback"):
        refresh_module().refresh_candidate(manifest, root, output, now=NOW)
    assert not (output / "policy.json").exists()


@pytest.mark.parametrize("kind", ["signature", "keyring", "oversized", "expired", "missing-package"])
def test_failed_refresh_never_emits_usable_policy(acquisition, monkeypatch, kind):
    acquire, manifest, root, remote, _ = acquisition
    if kind == "signature":
        def bad(payload):
            raise LockContractError("bad signature")
        monkeypatch.setattr(acquire.auth, "authenticate_inrelease", bad)
    elif kind == "keyring":
        manifest["keyring_sha256"] = "d" * 64
    elif kind == "oversized":
        remote[next(url for url in remote if url.endswith("InRelease"))] = b"x" * (2 * 1024 * 1024 + 1)
    elif kind == "expired":
        for url in list(remote):
            if url.endswith("InRelease"):
                remote[url] = remote[url].replace(b"Thu, 08 Oct 2026", b"Fri, 02 Oct 2026")
    else:
        manifest["stages"]["runtime"]["packages"][0]["record"]["Version"] = "3"
        manifest["stages"]["runtime"]["resolved_requests"] = ["tool=3"]
    output = root / "failed"
    with pytest.raises(LockContractError):
        refresh_module().refresh_candidate(manifest, root, output, now=NOW)
    assert not (output / "policy.json").exists()


def test_existing_refresh_destination_is_preserved(acquisition):
    _, manifest, root, _, _ = acquisition
    output = root / "existing"
    output.mkdir()
    (output / "marker").write_text("preserved")
    with pytest.raises(LockContractError, match="destination"):
        refresh_module().refresh_candidate(manifest, root, output, now=NOW)
    assert (output / "marker").read_text() == "preserved"


@pytest.mark.parametrize("change", ["future", "extended", "wrong-lock", "unknown-field", "naive"])
def test_policy_rejects_unbound_or_ambiguous_lifetime(acquisition, change):
    _, manifest, root, _, _ = acquisition
    module = refresh_module()
    output = root / "candidate"
    module.refresh_candidate(manifest, root, output, now=NOW)
    candidate, policy = [json.loads((output / name).read_text()) for name in ("lock.json", "policy.json")]
    if change == "future":
        policy["observed_at_utc"] = (NOW + timedelta(seconds=1)).isoformat()
    elif change == "extended":
        policy["usable_until_utc"] = (NOW + timedelta(days=2)).isoformat()
    elif change == "wrong-lock":
        policy["lock_sha256"] = "a" * 64
    elif change == "unknown-field":
        policy["skip_expiry"] = True
    else:
        policy["observed_at_utc"] = "2026-10-02T00:00:00"
    with pytest.raises(LockContractError):
        module.validate_policy(candidate, policy, now=NOW)


@pytest.mark.parametrize("change", ["redirect", "encoding", "status", "length", "io"])
def test_observed_metadata_refuses_http_ambiguity(acquisition, monkeypatch, change):
    acquire, manifest, root, _, _ = acquisition
    original = acquire._open
    def altered(url, timeout):
        if change == "io":
            raise OSError("unavailable")
        response = original(url, timeout)
        if change == "redirect":
            response.url = "https://untrusted.invalid/InRelease"
        elif change == "encoding":
            response.headers = {"Content-Encoding": "gzip"}
        elif change == "status":
            response.status = 206
        else:
            response.headers = {"Content-Length": "999999999"}
        return response
    monkeypatch.setattr(acquire, "_open", altered)
    output = root / "bad-http"
    with pytest.raises(LockContractError):
        refresh_module().refresh_candidate(manifest, root, output, now=NOW)
    assert not (output / "policy.json").exists()


def test_refresh_reserves_network_budget_before_observation(acquisition, monkeypatch):
    acquire, manifest, root, _, calls = acquisition
    monkeypatch.setattr(acquire, "_MAX_NETWORK", 1024)
    with pytest.raises(LockContractError, match="network limit"):
        refresh_module().refresh_candidate(manifest, root, root / "limited", now=NOW)
    assert not calls


def test_failed_publication_does_not_leave_a_success_policy(acquisition, monkeypatch):
    _, manifest, root, _, _ = acquisition
    module = refresh_module()
    def unavailable(source, destination):
        raise OSError("publication unavailable")
    monkeypatch.setattr(module.os, "link", unavailable)
    output = root / "failed-publication"
    with pytest.raises(OSError, match="publication"):
        module.refresh_candidate(manifest, root, output, now=NOW)
    assert not (output / "policy.json").exists()
    assert (output / "policy.pending.json").exists()
