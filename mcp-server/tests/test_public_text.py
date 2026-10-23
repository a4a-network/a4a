"""Finding 117: tools must not expose a client's work subject to the public network.

Public data includes not only amounts and addresses but also text: requests, offers, tasks,
statuses, results, reviews, and connection requests. An agent works for a person whose work
subject is their business. A conscientious task description such as "a landing page for a
dental clinic in Zelenograd, 45,000, by Friday" identifies the client without a single name,
while an A4A event cannot be deleted globally.

These tests verify three properties, of which the third is the most important:
1. without strict mode, text can still be published (compatibility and a reasonable default
   for an individual user on their own machine);
2. in strict mode, publishing tools refuse and name a private alternative;
3. **strict build mode cannot be relaxed from inside** by either an environment variable or
   a tool call. The integrator was promised a guarantee, not a request.
"""
import asyncio
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sdk-python"))

from a4a import Keys, types                                    # noqa: E402
from a4a_mcp import identity, inbox_runtime, policy, server      # noqa: E402
from tests.fake_relay import FakeRelay                         # noqa: E402


@pytest.fixture
def build_deny(monkeypatch):
    """An image built with strict policy."""
    monkeypatch.setattr(policy, "BUILD_POLICY", {"public_text": "deny", "locked": True})


@pytest.fixture
def env_deny(monkeypatch):
    monkeypatch.setattr(policy, "BUILD_POLICY", {})
    monkeypatch.setenv("A4A_PUBLIC_TEXT", "deny")


# --- policy --------------------------------------------------------------------------

def test_default_is_allow(monkeypatch):
    monkeypatch.setattr(policy, "BUILD_POLICY", {})
    monkeypatch.delenv("A4A_PUBLIC_TEXT", raising=False)
    assert policy.public_text_mode() == "allow"


def test_env_can_turn_it_on(env_deny):
    assert policy.public_text_mode() == "deny"
    assert "A4A_PUBLIC_TEXT" in policy.source()


def test_build_policy_cannot_be_relaxed_by_environment(build_deny, monkeypatch):
    """Core property: `A4A_PUBLIC_TEXT=allow` does NOT relax a build-time restriction.

    Otherwise the integrator guarantee would be worthless: one manifest line would remove
    protection. The build is stricter than the runtime environment.
    """
    monkeypatch.setenv("A4A_PUBLIC_TEXT", "allow")
    assert policy.public_text_mode() == "deny"
    assert "build" in policy.source()


def test_build_policy_can_be_declared_unlocked(monkeypatch):
    """An unlocked policy is an explicit builder choice rather than an accidental default."""
    monkeypatch.setattr(policy, "BUILD_POLICY", {"public_text": "deny", "locked": False})
    monkeypatch.setenv("A4A_PUBLIC_TEXT", "allow")
    assert policy.public_text_mode() == "allow"


def test_broken_policy_file_is_loud(tmp_path):
    """A build typo must not SILENTLY remove the protection for which the image was built."""
    bad = tmp_path / "policy.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(RuntimeError, match="unreadable"):
        policy._read_policy(bad)
    bad.write_text(json.dumps({"public_text": "maybe"}), encoding="utf-8")
    with pytest.raises(RuntimeError, match="public_text"):
        policy._read_policy(bad)


def test_policy_file_lives_outside_the_agent_home():
    """The policy file must not live where tools can write.

    `a4a_open_file` accepts a destination path FROM THE MODEL. A policy stored in the agent
    data directory could be removed by one tool call, so it lives beside the installed package,
    which is installed by root.
    """
    home = Path(server.identity._home()) if hasattr(server.identity, "_home") else Path.home() / ".a4a"
    assert not str(policy.POLICY_FILE).startswith(str(home.resolve())), \
        "a policy in the agent directory can be removed from inside"
    assert policy.POLICY_FILE.parent.name == "a4a_mcp"


# --- tool behavior --------------------------------------------------------------------

async def _mcp_agent(monkeypatch, relay_url, *, agent_keys=None):
    monkeypatch.setenv("A4A_MANDATE_AUTO", "1")
    owner = Keys()
    agent_keys = agent_keys if agent_keys is not None else Keys()
    monkeypatch.setattr(server, "_relay_url", lambda: relay_url)
    monkeypatch.setattr(server, "load_or_create_identity", lambda: agent_keys)
    monkeypatch.setattr(server, "load_or_create_owner_identity", lambda: owner)
    return owner, agent_keys


async def test_strict_mode_refuses_every_public_text(build_deny, monkeypatch, tmp_path):
    monkeypatch.setattr(identity, "IDENTITY_DIR", tmp_path / ".a4a")
    monkeypatch.setattr(identity, "IDENTITY_FILE", tmp_path / ".a4a" / "identity.json")
    async with FakeRelay() as relay:
        await _mcp_agent(monkeypatch, relay.url,
                         agent_keys=identity.load_or_create_identity())
        inbox_runtime.configure("public-text", ["b" * 64], start_after=0)
        calls = [
            (server.a4a_publish_intent,
             dict(category="development", need="landing_page",
                  text="\u043B\u0435\u043D\u0434\u0438\u043D\u0433 \u0434\u043B\u044F \u0441\u0442\u043E\u043C\u0430\u0442\u043E\u043B\u043E\u0433\u0438\u0438 \u0432 \u0417\u0435\u043B\u0435\u043D\u043E\u0433\u0440\u0430\u0434\u0435")),
            (server.a4a_publish_offer,
             dict(intent_id="a" * 64, price=45000, text="\u0434\u0435\u043B\u0430\u043B\u0438 \u0442\u0430\u043A\u043E\u0435 \u0434\u043B\u044F \u043A\u043B\u0438\u043D\u0438\u043A\u0438")),
            (server.a4a_send_task,
             dict(agreement_id="a" * 64, description="\u0441\u0432\u0435\u0440\u0441\u0442\u0430\u0442\u044C \u0441\u0430\u0439\u0442 \u043A\u043B\u0438\u043D\u0438\u043A\u0438 N",
                  executor="b" * 64)),
            (server.a4a_update_task_status,
             dict(task_id="t", agreement_id="a" * 64, status="in_progress",
                  note="\u0436\u0434\u0443 \u043C\u0430\u043A\u0435\u0442\u044B \u043E\u0442 \u043A\u043B\u0438\u043D\u0438\u043A\u0438")),
            (server.a4a_submit_task_result,
             dict(task_id="t", agreement_id="a" * 64, result_url="https://x/y",
                  note="\u0433\u043E\u0442\u043E\u0432\u043E \u0434\u043B\u044F \u043A\u043B\u0438\u043D\u0438\u043A\u0438 N")),
            (server.a4a_publish_review,
             dict(agreement_id="a" * 64, peer_pubkey="b" * 64, rating=5,
                  text="\u043E\u0442\u043B\u0438\u0447\u043D\u043E \u0441\u0434\u0435\u043B\u0430\u043B\u0438 \u0441\u0430\u0439\u0442 \u0434\u043B\u044F \u043A\u043B\u0438\u043D\u0438\u043A\u0438 N")),
            (server.a4a_request_connection,
             dict(peer_pubkey="b" * 64, intro="\u0438\u0449\u0443 \u0432\u0435\u0440\u0441\u0442\u0430\u043B\u044C\u0449\u0438\u043A\u0430 \u0434\u043B\u044F \u043A\u043B\u0438\u043D\u0438\u043A\u0438 N")),
        ]
        for tool, kwargs in calls:
            out = await tool(**kwargs)
            assert "is not published" in out, f"{tool.__name__} published text: {out}"
            assert "a4a_send_private" in out or "privately" in out, \
                f"{tool.__name__} refused but did not name an alternative: {out}"
            assert "build" in out, f"{tool.__name__} did not identify build policy"
        # None of these attempts reached the relay.
        assert not relay.events, "strict mode published an event"


async def test_strict_mode_still_lets_the_deal_happen(build_deny, monkeypatch):
    """Blocking text must not block work: a description-free request can be published and found.

    Otherwise strict mode is a product kill switch rather than protection and will be disabled
    on the first day.
    """
    async with FakeRelay() as relay:
        await _mcp_agent(monkeypatch, relay.url)
        out = await server.a4a_publish_intent(
            category="development", need="landing_page",
            budget_min=30000, budget_max=50000, deadline_days=5)
        assert "published" in out.lower(), out
        intents = [e for e in relay.events if e["kind"] == types.KIND_INTENT]
        assert len(intents) == 1
        assert intents[0]["content"] == "", "work subject still reached the network"
        found = await server.a4a_search_intents(category="development")
        assert "landing_page" in found, "description-free request cannot be found, making the mode useless"


async def test_slug_field_cannot_be_used_as_a_smuggling_channel(build_deny, monkeypatch):
    """A model prevented from putting the subject in `text` will put it in `need`.

    In strict mode, a label must therefore remain a label: no spaces, Cyrillic, or sentence
    length. This was the only hole left by the free-text restriction.
    """
    async with FakeRelay() as relay:
        await _mcp_agent(monkeypatch, relay.url)
        out = await server.a4a_publish_intent(
            category="development", need="\u043B\u0435\u043D\u0434\u0438\u043D\u0433 \u0434\u043B\u044F \u0441\u0442\u043E\u043C\u0430\u0442\u043E\u043B\u043E\u0433\u0438\u0438 \u0432 \u0417\u0435\u043B\u0435\u043D\u043E\u0433\u0440\u0430\u0434\u0435")
        assert "impersonal label" in out, out
        assert not relay.events
        ok = await server.a4a_publish_intent(category="development", need="landing_page")
        assert "published" in ok.lower()


async def test_permissive_mode_keeps_working(monkeypatch):
    """Do not restrict an individual user on their own machine; they are their own client."""
    monkeypatch.setattr(policy, "BUILD_POLICY", {})
    monkeypatch.delenv("A4A_PUBLIC_TEXT", raising=False)
    async with FakeRelay() as relay:
        await _mcp_agent(monkeypatch, relay.url)
        out = await server.a4a_publish_intent(
            category="development", need="landing_page", text="\u043D\u0443\u0436\u0435\u043D \u043B\u0435\u043D\u0434\u0438\u043D\u0433 \u043D\u0430 \u043F\u044F\u0442\u044C \u0431\u043B\u043E\u043A\u043E\u0432")
        assert "published" in out.lower(), out
        intents = [e for e in relay.events if e["kind"] == types.KIND_INTENT]
        assert intents[0]["content"] == "\u043D\u0443\u0436\u0435\u043D \u043B\u0435\u043D\u0434\u0438\u043D\u0433 \u043D\u0430 \u043F\u044F\u0442\u044C \u0431\u043B\u043E\u043A\u043E\u0432"


async def test_free_text_no_longer_lands_in_the_indexed_tag(monkeypatch):
    """Even in permissive mode, the description must not enter the `need` tag.

    Previously `need=text`, so the entire job description entered the indexed tag used for
    relay discovery. A tag is the event's most public location.
    """
    monkeypatch.setattr(policy, "BUILD_POLICY", {})
    monkeypatch.delenv("A4A_PUBLIC_TEXT", raising=False)
    async with FakeRelay() as relay:
        await _mcp_agent(monkeypatch, relay.url)
        await server.a4a_publish_intent(
            category="development", need="landing_page",
            text="\u043B\u0435\u043D\u0434\u0438\u043D\u0433 \u0434\u043B\u044F \u0441\u0442\u043E\u043C\u0430\u0442\u043E\u043B\u043E\u0433\u0438\u0438 \u0432 \u0417\u0435\u043B\u0435\u043D\u043E\u0433\u0440\u0430\u0434\u0435")
        ev = [e for e in relay.events if e["kind"] == types.KIND_INTENT][0]
        need = [t[1] for t in ev["tags"] if t[0] == "need"]
        assert need == ["landing_page"], f"unexpected value in need tag: {need}"


async def test_text_is_optional_for_every_publishing_tool(monkeypatch):
    """A required `text` parameter itself suggested that text was necessary.

    Check signatures: free-text fields on publishing tools must have defaults, or the model is
    forced to invent something and will invent the work subject.
    """
    import inspect
    expected = {
        "a4a_publish_intent": "text",
        "a4a_publish_offer": "text",
        "a4a_send_task": "description",
        "a4a_update_task_status": "note",
        "a4a_submit_task_result": "note",
        "a4a_publish_review": "text",
        "a4a_request_connection": "intro",
    }
    for tool_name, field in expected.items():
        sig = inspect.signature(getattr(server, tool_name))
        param = sig.parameters[field]
        assert param.default == "", f"{tool_name}.{field} is required, so the model will fill it with the work subject"
