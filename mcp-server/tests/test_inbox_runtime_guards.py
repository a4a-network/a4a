"""Direct negative controls for managed-inbox runtime guards."""
import contextlib
import json

import pytest

from a4a import Keys
from a4a.inbox import InboxError
from a4a_mcp import identity, inbox_runtime


@pytest.fixture
def home(tmp_path, monkeypatch):
    root = tmp_path / "profile"
    monkeypatch.setattr(identity, "IDENTITY_DIR", root)
    monkeypatch.setattr(identity, "IDENTITY_FILE", root / "identity.json")
    monkeypatch.setenv("A4A_RELAY", "ws://127.0.0.1:17404")
    monkeypatch.setenv("A4A_MANDATE_AUTO", "0")
    return root


def _policy_data():
    return {
        "version": 1,
        "recipient": Keys().pubkey_hex,
        "consumer": "guard-test",
        "relay": "ws://127.0.0.1:17404",
        "allowed_peers": [],
        "start_after": 0,
        "enabled": True,
        "notify_interval": 60,
        "notify_per_hour": 12,
    }


@pytest.mark.parametrize("field,value,message", [
    ("version", 2, "unsupported inbox policy version"),
    ("recipient", "not-a-public-key", "invalid inbox policy recipient"),
    ("relay", 7, "invalid inbox relay"),
])
def test_policy_scalar_guards_name_the_rejected_field(field, value, message):
    data = _policy_data()
    data[field] = value

    with pytest.raises(InboxError, match=message):
        inbox_runtime._validate(data)


def test_missing_policy_dangling_symlink_is_not_treated_as_absence(home):
    path = home / "inbox-policy.json"
    home.mkdir()
    try:
        path.symlink_to(home / "missing-target.json")
    except OSError as exc:
        pytest.skip(f"filesystem does not support symlinks: {exc}")

    with pytest.raises(InboxError, match="must not be a symlink"):
        inbox_runtime.load_policy()


def test_oversized_policy_is_rejected_before_permissions_or_json(home, monkeypatch):
    path = home / "inbox-policy.json"
    home.mkdir()
    path.write_bytes(b"{" + b" " * (32 * 1024))
    monkeypatch.setattr(inbox_runtime.keyfile, "is_private",
                        lambda _path: pytest.fail("oversized policy reached permissions"))

    with pytest.raises(InboxError, match="invalid inbox policy file"):
        inbox_runtime.load_policy()


def test_configure_requires_identity_before_loading_keys(home, monkeypatch):
    monkeypatch.setattr(inbox_runtime, "_existing_keys",
                        lambda: pytest.fail("missing identity reached key loading"))

    with pytest.raises(InboxError, match="create and verify the intended identity"):
        inbox_runtime.configure("guard-test", [])


def test_configure_requires_explicit_replace_before_writing(home):
    identity.load_or_create_identity()
    inbox_runtime.configure("guard-test", [], start_after=0)
    before = (home / "inbox-policy.json").read_bytes()

    with pytest.raises(InboxError, match="explicit --replace is required"):
        inbox_runtime.configure("guard-test", [], start_after=0)
    assert (home / "inbox-policy.json").read_bytes() == before


def test_configure_replace_refuses_symlink_policy(home):
    identity.load_or_create_identity()
    path = home / "inbox-policy.json"
    target = home / "outside.json"
    target.write_bytes(b"outside")
    try:
        path.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"filesystem does not support symlinks: {exc}")

    with pytest.raises(InboxError, match="must not be a symlink"):
        inbox_runtime.configure("guard-test", [], start_after=0, replace=True)
    assert target.read_bytes() == b"outside"
    assert path.is_symlink()


def test_configure_aborts_when_temporary_policy_cannot_be_hardened(home, monkeypatch):
    identity.load_or_create_identity()

    def harden(path, *_args, **_kwargs):
        return (False, "synthetic") if str(path).endswith(".tmp") else (True, "")

    monkeypatch.setattr(inbox_runtime.keyfile, "harden_and_check", harden)
    monkeypatch.setattr(inbox_runtime, "_private_directory", lambda _path: None)

    with pytest.raises(InboxError, match="cannot protect inbox policy"):
        inbox_runtime.configure("guard-test", [], start_after=0)
    assert not (home / "inbox-policy.json").exists()
    assert not list(home.glob("inbox-policy-*.tmp"))


def test_existing_keys_rejects_missing_identity_before_permission_probe(home, monkeypatch):
    monkeypatch.setattr(inbox_runtime.keyfile, "is_private",
                        lambda _path: pytest.fail("missing identity reached permissions"))

    with pytest.raises(InboxError, match="identity is missing or linked"):
        inbox_runtime._existing_keys()


def test_require_peer_rejects_unknown_address(monkeypatch):
    policy = inbox_runtime.InboxPolicy(
        1, "a" * 64, "guard-test", "ws://127.0.0.1:17404", frozenset(), 0)
    monkeypatch.setattr(inbox_runtime, "active_policy", lambda: policy)

    with pytest.raises(InboxError, match="not authorized by the owner") as exc:
        inbox_runtime.require_peer("b" * 64)
    # The refusal must say who can open the contact; an agent cannot find that out alone.
    assert "ask the owner" in str(exc.value)


def test_legacy_send_refuses_dialogue_mode(monkeypatch):
    policy = inbox_runtime.InboxPolicy(
        1, "a" * 64, "guard-test", "ws://127.0.0.1:17404", frozenset(), 0)

    class Store:
        def dialogue_enabled(self):
            return True

    @contextlib.contextmanager
    def opened(_policy):
        yield Store()

    monkeypatch.setattr(inbox_runtime, "require_peer", lambda _peer: policy)
    monkeypatch.setattr(inbox_runtime, "_open_store", opened)

    with pytest.raises(InboxError, match="dialogue mode is enabled"):
        inbox_runtime.require_legacy_send("b" * 64)


def test_escape_peeler_reports_no_change_for_plain_text():
    assert inbox_runtime._peel_json_escapes("ordinary text") is None


def test_character_limit_refuses_before_utf8_encoding():
    class EncodeForbidden(str):
        def encode(self, *_args, **_kwargs):
            pytest.fail("character-oversized content reached UTF-8 encoding")

    assert inbox_runtime._is_file_reference_attempt(
        EncodeForbidden("x" * (inbox_runtime._MAX_FILE_MARKER_TEXT + 1))) is True


def test_utf8_byte_limit_catches_short_non_ascii_text():
    content = "é" * (inbox_runtime._MAX_FILE_MARKER_TEXT // 2 + 1)
    assert len(content) <= inbox_runtime._MAX_FILE_MARKER_TEXT
    assert len(content.encode("utf-8")) > inbox_runtime._MAX_FILE_MARKER_TEXT
    assert inbox_runtime._is_file_reference_attempt(content) is True


def test_decoded_object_guard_does_not_depend_on_raw_key_scanner(monkeypatch):
    monkeypatch.setattr(inbox_runtime, "_contains_encoded_file_marker", lambda _text: False)
    content = json.dumps({"a4a_file": {"secret": "value"}})

    assert inbox_runtime._is_file_reference_attempt(content) is True


def test_decoded_token_budget_failure_is_fail_closed(monkeypatch):
    huge = "x" * (inbox_runtime._MAX_FILE_MARKER_DECODED_BYTES + 1)
    monkeypatch.setattr(inbox_runtime, "_contains_encoded_file_marker", lambda _text: False)
    monkeypatch.setattr(inbox_runtime, "_peel_json_escapes", lambda _text: None)
    monkeypatch.setattr(inbox_runtime, "_decoded_json_string_tokens",
                        lambda _text: iter((huge,)))

    assert inbox_runtime._is_file_reference_attempt("not-json") is True


def test_open_runtime_rechecks_identity_before_agent_or_store(monkeypatch):
    policy = inbox_runtime.InboxPolicy(
        1, "a" * 64, "guard-test", "ws://127.0.0.1:17404", frozenset(), 0)
    keys = Keys()
    assert keys.pubkey_hex != policy.recipient
    monkeypatch.setattr(inbox_runtime, "active_policy", lambda: policy)
    monkeypatch.setattr(inbox_runtime, "_existing_keys", lambda: keys)
    monkeypatch.setattr(inbox_runtime, "Agent",
                        lambda *_args, **_kwargs: pytest.fail("mismatched identity opened agent"))

    with pytest.raises(InboxError, match="identity differs"):
        with inbox_runtime.open_runtime():
            pytest.fail("mismatched identity opened runtime")


def test_existing_keys_waits_out_a_briefly_busy_identity(home):
    """A session CLI holding the identity lock must not stop the receiver.

    26.09.2026: a project mailbox's receiver refreshed its policy while the session was in
    inbox-next; the non-blocking lock said "busy", that surfaced as "identity unreadable"
    and the receiver stopped for 15 minutes until the scheduled restart.
    """
    import threading
    from a4a_mcp.profile_lock import profile_lock
    expected = identity.load_or_create_identity().pubkey_hex
    held, release = threading.Event(), threading.Event()

    def hold():
        with profile_lock(home):
            held.set()
            release.wait(5)

    holder = threading.Thread(target=hold)
    holder.start()
    held.wait(5)
    threading.Timer(0.3, release.set).start()
    try:
        assert inbox_runtime._existing_keys().pubkey_hex == expected
    finally:
        release.set()
        holder.join(5)


def test_existing_keys_still_fails_when_the_identity_stays_busy(home, monkeypatch):
    import threading
    from a4a_mcp.profile_lock import profile_lock
    identity.load_or_create_identity()
    monkeypatch.setattr(inbox_runtime, "_IDENTITY_BUSY_WAIT_SECONDS", 0.3)
    held, release = threading.Event(), threading.Event()

    def hold():
        with profile_lock(home):
            held.set()
            release.wait(5)

    holder = threading.Thread(target=hold)
    holder.start()
    held.wait(5)
    try:
        with pytest.raises(InboxError, match="busy"):
            inbox_runtime._existing_keys()
    finally:
        release.set()
        holder.join(5)
