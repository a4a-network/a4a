"""Negative controls for the local identity writer lock."""
import pytest

from a4a_mcp.profile_lock import profile_lock


def test_identity_lock_refuses_a_non_regular_lock_path(tmp_path):
    identity = tmp_path / "identity"
    identity.mkdir()
    (identity / ".identity.lock").mkdir()

    with pytest.raises(ValueError, match="unsafe identity lock"):
        with profile_lock(identity):
            raise AssertionError("unsafe lock path was accepted")
