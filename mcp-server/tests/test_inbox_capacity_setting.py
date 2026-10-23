"""Let owners configure inbox capacity without changing the default (2026-09-08).

Processed messages are retained as protocol evidence. The 64 MiB ceiling will
eventually fill with history and stop receipt. Production profiles measured 275 and
496 KiB per day, projecting exhaustion in May and January 2027 respectively.

Raising the ceiling buys time rather than solving retention. On a terabyte disk,
512 MiB is negligible and moves the limit years away. The setting therefore exists but
does not change the default: an installation must not silently retain half a gigabyte
of correspondence without saying so. Our profiles opt in explicitly.

Malformed values must fail instead of silently falling back to the default; otherwise
a typo looks like an active setting.
"""
import importlib
import importlib.util
import json
from types import SimpleNamespace

import pytest


@pytest.fixture
def runtime():
    assert importlib.util.find_spec("a4a_mcp.inbox_runtime") is not None
    return importlib.import_module("a4a_mcp.inbox_runtime")


def test_default_ceiling_is_unchanged(runtime, monkeypatch):
    monkeypatch.delenv("A4A_INBOX_MAX_MB", raising=False)
    assert runtime._inbox_max_bytes() == 64 * 1024 * 1024


def test_owner_can_raise_the_ceiling(runtime, monkeypatch):
    monkeypatch.setenv("A4A_INBOX_MAX_MB", "512")
    assert runtime._inbox_max_bytes() == 512 * 1024 * 1024


@pytest.mark.parametrize("raw", ["", "gig", "64MB", "0", "-5", "64.5", "99999"])
def test_unusable_value_is_refused_not_silently_defaulted(runtime, monkeypatch, raw):
    """A typo must stop startup instead of looking like an enabled setting."""
    monkeypatch.setenv("A4A_INBOX_MAX_MB", raw)
    with pytest.raises(ValueError, match="A4A_INBOX_MAX_MB"):
        runtime._inbox_max_bytes()


def test_ceiling_reaches_the_store_not_just_the_setting(runtime, monkeypatch, tmp_path):
    """Propagate the setting to storage rather than merely parsing the string.

    Testing only the parser checks the guard through its own door, the exact mistake
    behind three findings in the original audit. Open a real store and inspect it.
    """
    from a4a import Keys
    from a4a_mcp import identity

    monkeypatch.setenv("A4A_INBOX_MAX_MB", "256")
    monkeypatch.setattr(identity, "IDENTITY_DIR", tmp_path)
    policy = SimpleNamespace(recipient=Keys().pubkey_hex, consumer="session-a")
    with runtime._open_store(policy) as store:
        assert store.max_bytes == 256 * 1024 * 1024
        assert store.status()["capacity_bytes"] == 256 * 1024 * 1024


def test_default_ceiling_reaches_the_store_too(runtime, monkeypatch, tmp_path):
    """Negative control: without the variable, storage keeps the 64 MiB default."""
    from a4a import Keys
    from a4a_mcp import identity

    monkeypatch.delenv("A4A_INBOX_MAX_MB", raising=False)
    monkeypatch.setattr(identity, "IDENTITY_DIR", tmp_path)
    policy = SimpleNamespace(recipient=Keys().pubkey_hex, consumer="session-a")
    with runtime._open_store(policy) as store:
        assert store.max_bytes == 64 * 1024 * 1024


def test_prune_requires_a_positive_age(runtime, monkeypatch, tmp_path):
    """Reject zero age because "older than zero days" means every message."""
    from a4a.inbox import InboxError
    for days in (0, -1):
        with pytest.raises(InboxError, match="days"):
            runtime.prune(days, str(tmp_path / "a.json"))


def test_prune_passes_a_cutoff_derived_from_days(runtime, monkeypatch, tmp_path):
    """Derive the cutoff from the current time rather than using days as a timestamp.

    This uses real storage; otherwise the test would confirm only its own arithmetic.
    """
    import time
    from a4a import Keys
    from a4a_mcp import identity

    monkeypatch.setattr(identity, "IDENTITY_DIR", tmp_path)
    policy = SimpleNamespace(recipient=Keys().pubkey_hex, consumer="session-a")
    monkeypatch.setattr(runtime, "active_policy", lambda: policy)
    monkeypatch.setattr(runtime, "_existing_keys", lambda: None, raising=False)
    archive = tmp_path / "out.json"
    report = runtime.prune(30, str(archive))
    assert report["exported"] == 0
    assert report["mode"] == "export-only", "the default is no longer export-only"
    assert archive.exists(), "even an empty export is required as evidence of pruning"
    saved = json.loads(archive.read_text("utf-8"))
    assert time.time() - 31 * 86400 < saved["before"] < time.time() - 29 * 86400


def test_one_effective_cap_reaches_the_dialogue_store_too(runtime, monkeypatch, tmp_path):
    """OPS-007: the effective capacity must reach every storage constructor.

    The original change incorrectly claimed there was only one constructor.
    Dialogue storage opened without the configured cap: ``A4A_INBOX_MAX_MB=1``
    limited the inbox to 1 MiB but left dialogue storage at its measured 64 MiB
    default. Testing only ``_open_store`` checked the guard through its own door.
    """
    from a4a import Keys
    from a4a_mcp import identity, dialogue_runtime

    policy = SimpleNamespace(recipient=Keys().pubkey_hex, consumer="session-a")
    for mb, expected in ((1, 1), (256, 256)):
        monkeypatch.setenv("A4A_INBOX_MAX_MB", str(mb))
        home = tmp_path / f"home{mb}"
        monkeypatch.setattr(identity, "IDENTITY_DIR", home)
        with runtime._open_store(policy) as inbox:
            assert inbox.max_bytes == expected * 1024 * 1024
        with dialogue_runtime._open_dialogues(policy) as dialogues:
            assert dialogues.max_bytes == expected * 1024 * 1024, \
                f"dialogue storage remained at its default with A4A_INBOX_MAX_MB={mb}"


def test_dialogue_store_keeps_the_default_without_the_variable(runtime, monkeypatch, tmp_path):
    """Negative control: without the variable, both stores retain 64 MiB."""
    from a4a import Keys
    from a4a_mcp import identity, dialogue_runtime

    monkeypatch.delenv("A4A_INBOX_MAX_MB", raising=False)
    monkeypatch.setattr(identity, "IDENTITY_DIR", tmp_path)
    policy = SimpleNamespace(recipient=Keys().pubkey_hex, consumer="session-a")
    with dialogue_runtime._open_dialogues(policy) as dialogues:
        assert dialogues.max_bytes == 64 * 1024 * 1024


def test_owner_can_raise_the_letter_count_ceiling_and_it_reaches_both_stores(runtime, monkeypatch, tmp_path):
    """26.09.2026: the representative's pod took 1207 letters in a day; 10 000 letters is a
    hard stop about a week away, and unlike bytes it could not be configured. Same rules as
    the byte ceiling: explicit opt-in, the default unchanged, a typo refused."""
    from a4a import Keys
    from a4a_mcp import identity, dialogue_runtime

    policy = SimpleNamespace(recipient=Keys().pubkey_hex, consumer="session-a")
    monkeypatch.setenv("A4A_INBOX_MAX_ITEMS", "50000")
    monkeypatch.setattr(identity, "IDENTITY_DIR", tmp_path)
    with runtime._open_store(policy) as inbox:
        assert inbox.max_items == 50000 and inbox.status()["capacity_items"] == 50000
    with dialogue_runtime._open_dialogues(policy) as dialogues:
        assert dialogues.max_items == 50000
    monkeypatch.delenv("A4A_INBOX_MAX_ITEMS")
    assert runtime._inbox_max_items() == 10_000


@pytest.mark.parametrize("raw", ["", "many", "0", "-1", "1e5", "100001"])
def test_unusable_letter_count_is_refused(runtime, monkeypatch, raw):
    monkeypatch.setenv("A4A_INBOX_MAX_ITEMS", raw)
    with pytest.raises(ValueError, match="A4A_INBOX_MAX_ITEMS"):
        runtime._inbox_max_items()
