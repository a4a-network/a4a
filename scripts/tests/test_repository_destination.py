"""Local destination preparation must be explicit, bounded, and reproducible."""

import importlib.util
import json
import os
import re
import tomllib
from pathlib import Path
from urllib.parse import urlsplit

import pytest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("repository_destination", ROOT / "scripts/prepare-repository-destination.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


@pytest.fixture
def tree(tmp_path, monkeypatch):
    for relative in MODULE.FILES:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if relative in MODULE.METADATA_FILES:
            content = '[project.urls]\nSource = "https://github.com/a4a-network/a4a-protocol"\nIssues = "https://github.com/a4a-network/a4a-protocol/issues"\n'
        else:
            content = ('https://github.com/a4a-network/a4a/blob/main/README.md\n'
                       'https://github.com/a4a-network/a4a-protocol.git\n'
                       '`github.com/a4a-network/a4a-protocol`\n'
                       'https://github.com/a4a-network/a4a-elsewhere\n'
                       'https://github.com/nostr-protocol/nips\n')
        path.write_text(content, encoding="utf-8")
    monkeypatch.setattr(MODULE, "ROOT", tmp_path)
    return tmp_path


def snapshot(tree):
    return {relative: (tree / relative).read_bytes() for relative in MODULE.FILES}


def test_destination_has_no_implicit_default(tree):
    before = snapshot(tree)
    with pytest.raises(SystemExit) as error:
        MODULE.main([])
    assert error.value.code == 2
    assert snapshot(tree) == before


def test_dry_plan_changes_nothing_and_never_grants_release_consent(tree, capsys):
    before = snapshot(tree)
    assert MODULE.main(["--repository", "Owner-Selected/protocol"]) == 0
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["mode"] == "plan"
    assert receipt["release_approved"] is False
    assert receipt["network_access"] is False
    assert receipt["destination_ownership_verified"] is False
    assert len(receipt["files"]) == len(MODULE.FILES)
    assert snapshot(tree) == before


def test_apply_preserves_paths_third_party_routes_and_is_idempotent(tree, capsys):
    destination = "Owner-Selected/protocol"
    assert MODULE.main(["--repository", destination, "--apply"]) == 0
    first = json.loads(capsys.readouterr().out)
    content = (tree / "site/index.html").read_text(encoding="utf-8")
    assert f"https://github.com/{destination}/blob/main/README.md" in content
    assert f"https://github.com/{destination}.git" in content
    assert f"`github.com/{destination}`" in content
    assert "https://github.com/a4a-network/a4a-elsewhere" in content
    assert "https://github.com/nostr-protocol/nips" in content
    for record in first["files"]:
        assert record["before_sha256"] != record["after_sha256"]
    assert MODULE.main(["--repository", destination, "--check"]) == 0
    assert json.loads(capsys.readouterr().out)["files"] == []
    assert MODULE.main(["--repository", destination, "--apply"]) == 0
    assert json.loads(capsys.readouterr().out)["files"] == []


def test_check_rejects_unprepared_destination_without_writing(tree):
    before = snapshot(tree)
    assert MODULE.main(["--repository", "Owner-Selected/protocol", "--check"]) == 1
    assert snapshot(tree) == before


@pytest.mark.parametrize("slug", ["", "owner", "owner/repo/extra", "https://github.com/owner/repo",
                                   "../repo", "owner/..", "owner/repo.git", "owner/repo?other", "owner/repo#other", "owner/repo\\other"])
def test_invalid_destination_is_refused_before_writing(tree, slug):
    before = snapshot(tree)
    assert MODULE.main(["--repository", slug, "--apply"]) == 2
    assert snapshot(tree) == before


def test_unrecognized_component_mismatch_is_not_rewritten_silently(tree):
    path = tree / "mcp-server/pyproject.toml"
    path.write_text('[project.urls]\nSource = "https://github.com/unrelated/wrong-project"\n', encoding="utf-8")
    before = snapshot(tree)
    assert MODULE.main(["--repository", "Owner-Selected/protocol", "--apply"]) == 2
    assert snapshot(tree) == before


def test_missing_required_file_fails_before_any_write(tree):
    path = tree / "site/index.html"
    path.rename(tree / "site/index.saved.html")
    before = {p: p.read_bytes() for p in tree.rglob("*") if p.is_file()}
    assert MODULE.main(["--repository", "Owner-Selected/protocol", "--apply"]) == 2
    assert {p: p.read_bytes() for p in tree.rglob("*") if p.is_file()} == before


def test_hardlinked_source_cannot_write_to_an_external_file(tree, capsys):
    source = tree / "site/index.html"
    external = tree.parent / (tree.name + "-external-index.html")
    source.rename(external)
    os.link(external, source)
    assert source.stat().st_nlink == 2
    before = snapshot(tree)
    outside_before = external.read_bytes()
    assert MODULE.main(["--repository", "Owner-Selected/protocol", "--apply"]) == 2
    assert "unlinked regular source file" in capsys.readouterr().err
    assert snapshot(tree) == before
    assert external.read_bytes() == outside_before


def test_unrecognized_issue_destination_is_not_hidden_by_matching_source(tree):
    path = tree / "mcp-server/pyproject.toml"
    text = path.read_text(encoding="utf-8").replace("a4a-protocol/issues", "unrelated/issues")
    path.write_text(text, encoding="utf-8")
    before = snapshot(tree)
    assert MODULE.main(["--repository", "Owner-Selected/protocol", "--apply"]) == 2
    assert snapshot(tree) == before


def test_actual_source_has_no_obsolete_site_destination_and_blob_paths_exist():
    current = MODULE.metadata_source(ROOT)
    site = (ROOT / "site/index.html").read_text(encoding="utf-8")
    project_hrefs = re.findall(r'href="(https://github.com/[^\"]+)"', site)
    assert len(project_hrefs) == 5
    for href in project_hrefs:
        assert href.startswith("https://github.com/" + current)
        parsed = urlsplit(href)
        prefix = "/" + current + "/blob/main/"
        if parsed.path.startswith(prefix):
            assert (ROOT / parsed.path.removeprefix(prefix)).is_file(), href


def test_actual_source_distinguishes_launch_approval_and_host_acceptance():
    for relative in ("docs/onboarding/safe-connect.md",):
        content = " ".join((ROOT / relative).read_text(encoding="utf-8").split())
        assert "not a universal installer" in content
        assert "public release bundle and host support are" not in content.lower()


def test_all_declared_component_sources_agree_with_actual_source():
    expected = "https://github.com/" + MODULE.metadata_source(ROOT)
    for relative in MODULE.METADATA_FILES:
        record = tomllib.loads((ROOT / relative).read_text(encoding="utf-8"))
        urls = record.get("project", {}).get("urls", {})
        if "Source" in urls:
            assert urls["Source"] == expected
            assert urls["Issues"] == expected + "/issues"
