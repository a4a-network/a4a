"""Service-loop tests against FakeRelay: triage precedes text reading and blocks floods."""
import asyncio
import importlib.util
import pathlib
import tempfile
import tomllib

import pytest
from a4a.agent import Agent

from a4a_agent.config import Config
from a4a_agent.policy import Policy
from a4a_agent.service import ProjectAgent, _renew_mandate_loop
from tests.fake_relay import FakeRelay


def test_live_acceptance_deadlines_cover_default_relay_pacing(tmp_path, monkeypatch):
    root = pathlib.Path(__file__).resolve().parents[2]
    config = tomllib.loads((root / "relay/config.toml").read_text(encoding="utf-8"))
    interval = 60.0 / config["limits"]["subscriptions_per_min"]
    monkeypatch.setattr(tempfile, "mkdtemp", lambda **kwargs: str(tmp_path))
    monkeypatch.setenv("A4A_AGENT_HOME", str(tmp_path))
    spec = importlib.util.spec_from_file_location("live_acceptance_deadline", root / "agent-service/live_check.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    checked = module._check_agent(["ws://127.0.0.1:8080"])
    assert interval < checked.relay.read_deadline <= 10.0
    assert all(interval < client.timeout <= 10.0 for client in checked.relay.clients)
    assert Agent(["ws://127.0.0.1:8080"]).relay.read_deadline == 5.0


@pytest.fixture(autouse=True)
def agent_home(tmp_path, monkeypatch):
    """The processed log lives in the identity directory, so isolate it."""
    monkeypatch.setenv("A4A_AGENT_HOME", str(tmp_path / "home"))


class Recorder:
    def __init__(self):
        self.sent = []

    def __call__(self, text):
        self.sent.append(text)
        return True


async def test_stranger_request_is_archived_without_notifying_owner():
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as project, Agent([relay.url]) as stranger:
            await stranger.request_connection(project.pubkey, "\u043A\u0443\u043F\u043B\u044E \u0441\u0441\u044B\u043B\u043A\u0438 \u043D\u0435\u0434\u043E\u0440\u043E\u0433\u043E")
            notifier = Recorder()
            svc = ProjectAgent(project, Config(policy=Policy()), notifier)
            report = await svc.process_connection_requests()
            assert report["archived"] == 1 and report["escalated"] == 0
            assert notifier.sent == [], "a stranger must not disturb the owner"


async def test_request_passing_policy_is_escalated_with_facts():
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as project, Agent([relay.url]) as issuer, \
                Agent([relay.url]) as sender:
            await issuer.attest_identity(sender.pubkey, level="account:telegram")
            notifier = Recorder()
            cfg = Config(policy=Policy(trusted_issuers=(issuer.pubkey,)))
            await sender.request_connection(project.pubkey, "\u0445\u043E\u0442\u0438\u043C \u043E\u0431\u0441\u0443\u0434\u0438\u0442\u044C \u0438\u043D\u0442\u0435\u0433\u0440\u0430\u0446\u0438\u044E")
            svc = ProjectAgent(project, cfg, notifier)
            report = await svc.process_connection_requests()
            assert report["escalated"] == 1
            assert "verified by issuer" in notifier.sent[0]
            assert "\u0445\u043E\u0442\u0438\u043C \u043E\u0431\u0441\u0443\u0434\u0438\u0442\u044C \u0438\u043D\u0442\u0435\u0433\u0440\u0430\u0446\u0438\u044E" in notifier.sent[0]


async def test_flood_of_strangers_costs_nothing_and_notifies_nobody():
    """A thousand requests must not become a thousand notifications."""
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as project:
            for _ in range(50):
                async with Agent([relay.url]) as spammer:
                    await spammer.request_connection(project.pubkey, "\u0441\u043F\u0430\u043C")
            notifier = Recorder()
            svc = ProjectAgent(project, Config(policy=Policy()), notifier)
            report = await svc.process_connection_requests()
            assert report["archived"] == 50 and notifier.sent == []


async def test_typical_question_gets_scripted_answer():
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as project, Agent([relay.url]) as asker:
            await asker.send_private_message(project.pubkey, "\u0447\u0442\u043E \u0442\u0430\u043A\u043E\u0435 A4A?")
            svc = ProjectAgent(project, Config(policy=Policy()), Recorder())
            report = await svc.process_messages()
            assert report["answered"] == 1
            replies = await asker.read_private_messages()
            assert any("protocol" in m["content"].lower() for m in replies)


# --- deviations from the plan: processed log and per-sender limit -----------------

async def test_same_message_is_answered_only_once():
    """The message stays on the relay while the service checks it every 30 seconds.
    Without a processed log, every pass would create another reply—an endless ping-pong
    with the same peer at our expense.
    """
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as project, Agent([relay.url]) as asker:
            await asker.send_private_message(project.pubkey, "\u0447\u0442\u043E \u0442\u0430\u043A\u043E\u0435 A4A?")
            svc = ProjectAgent(project, Config(policy=Policy()), Recorder())
            assert (await svc.process_messages())["answered"] == 1
            assert (await svc.process_messages())["answered"] == 0


async def test_same_request_wakes_the_owner_only_once():
    """The same holds for requests: one request means one notification, not one every 30 seconds."""
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as project, Agent([relay.url]) as issuer, \
                Agent([relay.url]) as sender:
            await issuer.attest_identity(sender.pubkey, level="account:telegram")
            await sender.request_connection(project.pubkey, "\u0437\u0434\u0440\u0430\u0432\u0441\u0442\u0432\u0443\u0439\u0442\u0435")
            notifier = Recorder()
            cfg = Config(policy=Policy(trusted_issuers=(issuer.pubkey,)))
            svc = ProjectAgent(project, cfg, notifier)
            assert (await svc.process_connection_requests())["escalated"] == 1
            assert (await svc.process_connection_requests())["escalated"] == 0
            assert len(notifier.sent) == 1


async def test_processed_log_survives_restart():
    """Restarting the service must not resend replies."""
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as project, Agent([relay.url]) as asker:
            await asker.send_private_message(project.pubkey, "\u0447\u0442\u043E \u0442\u0430\u043A\u043E\u0435 A4A?")
            cfg = Config(policy=Policy())
            assert (await ProjectAgent(project, cfg, Recorder())
                    .process_messages())["answered"] == 1
            fresh = ProjectAgent(project, cfg, Recorder())   # as after a restart
            assert (await fresh.process_messages())["answered"] == 0


async def test_replies_to_one_sender_are_capped():
    """The design requires a per-sender limit (the relay has only global messages_per_sec).
    Otherwise, one key asking 500 recognized questions could force us to publish 500 events.
    """
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as project, Agent([relay.url]) as flooder:
            for _ in range(10):
                await flooder.send_private_message(project.pubkey, "\u0447\u0442\u043E \u0442\u0430\u043A\u043E\u0435 A4A?")
            cfg = Config(policy=Policy(), max_replies_per_sender=3)
            report = await ProjectAgent(project, cfg, Recorder()).process_messages()
            assert report["answered"] == 3
            assert report["throttled"] == 7


# --- adversarial check of triage cost ----------------------------------------------

class CountingRelay:
    """Relay wrapper that counts queries by event kind."""

    def __init__(self, inner):
        self.inner = inner
        self.calls = []

    async def query(self, filters):
        self.calls.append(tuple(filters.get("kinds", ())))
        return await self.inner.query(filters)

    def __getattr__(self, name):
        return getattr(self.inner, name)

    def count_of_kind(self, kind):
        return sum(1 for kinds in self.calls if kind in kinds)


async def test_stranger_triage_does_not_amplify_load():
    """The design promises that "a thousand requests cost nothing." That is true in tokens,
    but if every cheap stranger event causes half a dozen queries, two of which download the
    ENTIRE trust graph, we have built a load amplifier against ourselves: the spammer pays for
    one event while we pay for six queries.

    Threshold: spend at most two queries (mutual-connection checks) on a sender that policy
    cannot possibly admit, and perform NO trust-graph downloads.
    """
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as project:
            for _ in range(10):
                async with Agent([relay.url]) as spammer:
                    await spammer.request_connection(project.pubkey, "\u0441\u043F\u0430\u043C")
            counting = CountingRelay(project.relay)
            project.relay = counting
            svc = ProjectAgent(project, Config(policy=Policy()), Recorder())
            report = await svc.process_connection_requests()
            assert report["archived"] == 10

            per_sender = [c for c in counting.calls if c != (31022,)]
            assert counting.count_of_kind(31020) == 0, \
                f"trust graph downloaded {counting.count_of_kind(31020)} times for archived requests"
            assert len(per_sender) <= 20, \
                f"{len(per_sender)} queries for 10 strangers is a load amplifier"


async def test_trust_graph_is_fetched_once_per_cycle():
    """The trust graph is global and sender-independent. Fetching it per sender creates the
    same amplification for callers that policy considers seriously.
    """
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as project, Agent([relay.url]) as issuer:
            senders = []
            for i in range(5):
                s = Agent([relay.url])
                await s.__aenter__()
                senders.append(s)
                await issuer.attest_identity(s.pubkey, level="account:telegram")
                await s.request_connection(project.pubkey, f"\u0437\u0434\u0440\u0430\u0432\u0441\u0442\u0432\u0443\u0439\u0442\u0435 {i}")
            counting = CountingRelay(project.relay)
            project.relay = counting
            cfg = Config(policy=Policy(trusted_issuers=(issuer.pubkey,)))
            await ProjectAgent(project, cfg, Recorder()).process_connection_requests()
            for s in senders:
                await s.__aexit__(None, None, None)
            assert counting.count_of_kind(31020) <= 1, \
                f"trust graph downloaded {counting.count_of_kind(31020)} times for 5 senders"


async def test_failed_notification_is_retried_not_lost():
    """If a notification is not delivered (Telegram is unavailable), the event MUST NOT be
    marked processed. Otherwise, the only request that passed policy disappears forever and
    the owner never learns it existed. Silent loss is worse than delay.
    """
    class Failing:
        def __init__(self):
            self.attempts = 0

        def __call__(self, text):
            self.attempts += 1
            return self.attempts > 1        # first delivery fails; second succeeds

    async with FakeRelay() as relay:
        async with Agent([relay.url]) as project, Agent([relay.url]) as issuer, \
                Agent([relay.url]) as sender:
            await issuer.attest_identity(sender.pubkey, level="account:telegram")
            await sender.request_connection(project.pubkey, "\u0437\u0434\u0440\u0430\u0432\u0441\u0442\u0432\u0443\u0439\u0442\u0435")
            notifier = Failing()
            cfg = Config(policy=Policy(trusted_issuers=(issuer.pubkey,)))
            svc = ProjectAgent(project, cfg, notifier)
            first = await svc.process_connection_requests()
            assert first["escalated"] == 0 and first["undelivered"] == 1
            second = await svc.process_connection_requests()
            assert second["escalated"] == 1, "request was lost after delivery failure"
            assert notifier.attempts == 2


async def test_inbox_window_bounds_what_is_read():
    """Reading all inbox history on every public-address cycle creates a growing cost paid by
    us rather than the spammer (see audit L1 from 2026-08-28). The service uses a window and
    never processes entries older than it.
    """
    import time as _t

    from a4a import giftwrap, types
    from a4a.event import Event

    now = int(_t.time())
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as project, Agent([relay.url]) as asker:
            old_inner = Event(kind=types.KIND_PRIVATE_RUMOR,
                              tags=[["p", project.pubkey], ["d", "old"]],
                              content="\u0447\u0442\u043E \u0442\u0430\u043A\u043E\u0435 A4A?", created_at=now - 40 * 86400)
            old_inner.sign(asker.keys)
            await asker.relay.publish(
                giftwrap.wrap(old_inner, project.pubkey, asker.keys,
                              now=now - 40 * 86400))
            cfg = Config(policy=Policy(), inbox_window_days=7)
            report = await ProjectAgent(project, cfg, Recorder()).process_messages()
            assert report["answered"] == 0, "a message older than the window was read"

            wide = Config(policy=Policy(), inbox_window_days=90)
            report = await ProjectAgent(project, wide, Recorder()).process_messages()
            assert report["answered"] == 1, "a wider window must find the message"


# --- streaming instead of polling -------------------------------------------------

async def test_serve_handles_events_arriving_after_start():
    """The main saving: the agent streams events instead of polling the relay.
    Verify that an event arriving AFTER startup is handled without a single poll.
    """
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as project, Agent([relay.url]) as asker:
            svc = ProjectAgent(project, Config(policy=Policy()), Recorder())
            stop = asyncio.Event()
            task = asyncio.create_task(svc.serve(stop=stop))
            await asyncio.sleep(0.3)
            await asker.send_private_message(project.pubkey, "\u0447\u0442\u043E \u0442\u0430\u043A\u043E\u0435 A4A?")
            for _ in range(50):
                await asyncio.sleep(0.1)
                replies = await asker.read_private_messages()
                if any("protocol" in m["content"].lower() for m in replies):
                    break
            else:
                raise AssertionError("no reply arrived: the stream did not process the message")
            stop.set()
            await asyncio.wait_for(task, timeout=5)


async def test_reply_throttle_resets_with_window():
    """Streaming has no polling cycles, so the per-sender limit must use a time window;
    otherwise it either never resets or never works.
    """
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as project, Agent([relay.url]) as flooder:
            cfg = Config(policy=Policy(), max_replies_per_sender=2,
                         reply_window_seconds=0)   # zero window resets every time
            svc = ProjectAgent(project, cfg, Recorder())
            for _ in range(5):
                await flooder.send_private_message(project.pubkey, "\u0447\u0442\u043E \u0442\u0430\u043A\u043E\u0435 A4A?")
            report = await svc.process_messages()
            assert report["answered"] == 5, "a zero window must not throttle anything"


# --- review findings from 2026-08-28 ----------------------------------------------

async def test_relay_failure_does_not_archive_forever():
    """A relay failure means "facts were unavailable", not "no facts exist." Treating it as
    rejection and marking the event processed would permanently lose a connected partner's
    request after a momentary outage. This is the same defect class already fixed for Telegram
    but previously left open for the relay.
    """
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as project, Agent([relay.url]) as sender:
            await sender.request_connection(project.pubkey, "\u0437\u0434\u0440\u0430\u0432\u0441\u0442\u0432\u0443\u0439\u0442\u0435")
            svc = ProjectAgent(project, Config(policy=Policy()), Recorder())

            broken, calls = project.is_connected, []

            async def failing(pubkey):
                calls.append(pubkey)
                raise RuntimeError("relay unavailable")

            project.is_connected = failing
            first = await svc.process_connection_requests()
            assert first["archived"] == 0, "relay failure was treated as a verified rejection"
            assert first["deferred"] == 1

            project.is_connected = broken          # relay recovered
            second = await svc.process_connection_requests()
            assert second["archived"] == 1, "request was lost after relay failure"


async def test_trust_graph_cache_expires():
    """Streaming has no polling cycles, so an immortal trust-graph cache would prevent an
    owner's published distrust from taking effect until restart.
    """
    from a4a_agent import facts

    class CountingRelay:
        def __init__(self):
            self.queries = 0

        async def query(self, filters):
            self.queries += 1
            return []

    class Stub:
        def __init__(self):
            self.relay = CountingRelay()

    agent = Stub()
    cache = facts.TrustGraphCache(ttl_seconds=0)
    await cache.graph(agent)
    await cache.graph(agent)
    assert agent.relay.queries == 2, "cache never expires, so the graph is not reread"


def test_processed_log_survives_garbage_file(tmp_path):
    """A corrupt log must not crash the service: the key may contain anything, not a list.
    A reviewer reproduced the previous crash.
    """
    from a4a_agent.service import ProcessedLog

    for junk in ("null", '{"a": 1}', '"\u0441\u0442\u0440\u043E\u043A\u0430"', "\u043D\u0435 json \u0432\u043E\u0432\u0441\u0435"):
        p = tmp_path / "processed.json"
        p.write_text(junk, encoding="utf-8")
        log = ProcessedLog(path=p)
        assert "\u043B\u044E\u0431\u043E\u0439-id" not in log
        log.add("\u043D\u043E\u0432\u044B\u0439-id")
        log.save()
        assert "\u043D\u043E\u0432\u044B\u0439-id" in ProcessedLog(path=p)


async def test_serve_survives_relay_outage():
    """A public QR address must not silently stop until manual intervention. SDK reconnect
    makes three attempts and gives up, after which the subscription raises. If uncaught, the
    process exits, and nothing in the repository restarts it (2026-08-28 review finding).
    """
    from a4a.relay import RelayError

    async with FakeRelay() as relay:
        async with Agent([relay.url]) as project:
            attempts = []
            original = project.subscribe_private_messages

            def flaky(*args, **kwargs):
                attempts.append(1)
                if len(attempts) == 1:
                    async def boom():
                        raise RelayError("connection lost")
                        yield   # pragma: no cover
                    return boom()
                return original(*args, **kwargs)

            project.subscribe_private_messages = flaky
            cfg = Config(policy=Policy(), reconnect_delay_seconds=0)
            svc = ProjectAgent(project, cfg, Recorder())
            stop = asyncio.Event()
            task = asyncio.create_task(svc.serve(stop=stop))
            for _ in range(50):
                await asyncio.sleep(0.05)
                if len(attempts) >= 2:
                    break
            stop.set()
            await asyncio.wait_for(task, timeout=5)
            assert len(attempts) >= 2, "subscription was not re-established after disconnection"


async def test_throttled_question_is_answered_later_not_swallowed():
    """A6: a throttled question was marked processed and NEVER answered, neither after the
    window reopened nor after restart. To the user, the agent swallowed the question. This
    contradicts the "mark only after delivery" rule already applied to escalations.
    """
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as project, Agent([relay.url]) as asker:
            for _ in range(3):
                await asker.send_private_message(project.pubkey, "\u0447\u0442\u043E \u0442\u0430\u043A\u043E\u0435 A4A?")
            cfg = Config(policy=Policy(), max_replies_per_sender=1,
                         reply_window_seconds=3600)
            svc = ProjectAgent(project, cfg, Recorder())
            first = await svc.process_messages()
            assert first["answered"] == 1 and first["throttled"] == 2

            cfg.reply_window_seconds = 0          # window reopened
            later = await svc.process_messages()
            assert later["answered"] == 2, "throttled questions were lost forever"


async def test_failed_reply_is_retried_not_swallowed():
    """A7: an exception while replying must neither drop the subscription nor consume the
    message. The relay may simply have failed to return OK before timeout.
    """
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as project, Agent([relay.url]) as asker:
            await asker.send_private_message(project.pubkey, "\u0447\u0442\u043E \u0442\u0430\u043A\u043E\u0435 A4A?")
            svc = ProjectAgent(project, Config(policy=Policy()), Recorder())
            original, calls = project.send_private_message, []

            async def flaky(*a, **kw):
                calls.append(1)
                if len(calls) == 1:
                    raise RuntimeError("relay did not return OK")
                return await original(*a, **kw)

            project.send_private_message = flaky
            first = await svc.process_messages()
            assert first["answered"] == 0 and first["undelivered"] == 1

            second = await svc.process_messages()
            assert second["answered"] == 1, "message was consumed after send failure"


def test_escalation_fits_telegram_limit():
    """A9: truncate long requests so Telegram can deliver them."""
    from a4a_agent import notify
    msg = notify.format_escalation(
        "ab" * 32,
        "very long " * 2000,
        ("verified by issuer x",),
    )
    assert len(msg) <= 4096
    assert "truncated" in msg
    assert "verified by issuer x" in msg, "facts must survive truncation"


async def test_reply_preserves_wrapping():
    """S2: a peer used wrapping to hide metadata. A plaintext reply exposes the relationship
    they asked to hide, so replies must preserve the mode.
    """
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as project, Agent([relay.url]) as asker:
            await asker.send_private_message(project.pubkey, "\u0447\u0442\u043E \u0442\u0430\u043A\u043E\u0435 A4A?", wrap=True)
            svc = ProjectAgent(project, Config(policy=Policy()), Recorder())
            assert (await svc.process_messages())["answered"] == 1

            plain = await project.relay.query({"kinds": [31033]})
            assert not [e for e in plain if e.pubkey == project.pubkey], \
                "reply was sent in plaintext, exposing metadata"
            replies = await asker.read_private_messages()
            answer = [m for m in replies if "protocol" in m["content"].lower()]
            assert answer and answer[0]["wrapped"] is True


async def test_global_reply_limit_survives_key_rotation():
    """A12: scripted replies occur BEFORE policy, while the limit is keyed by sender. A
    spammer can rotate keys and force us to publish an event for every question. The whole
    stream needs a ceiling in addition to the per-sender limit.
    """
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as project:
            askers = [Agent([relay.url]) for _ in range(8)]
            for a in askers:
                await a.__aenter__()
            try:
                for a in askers:
                    await a.send_private_message(project.pubkey, "\u0447\u0442\u043E \u0442\u0430\u043A\u043E\u0435 A4A?")
                cfg = Config(policy=Policy(), max_replies_per_sender=3,
                             max_replies_total=4, reply_window_seconds=3600)
                report = await ProjectAgent(project, cfg, Recorder()).process_messages()
                assert report["answered"] == 4, "global reply ceiling is not enforced"
                assert report["throttled"] == 4
            finally:
                for a in askers:
                    await a.__aexit__(None, None, None)


# --- mandate renewal in a running agent (2026-08-29 audit) ------------------------

async def test_service_renews_the_mandate_while_running():
    """The mandate used to be issued only at STARTUP. A long-running agent eventually crossed
    the renewal threshold, its mandate expired, and the relay silently rejected everything it
    published while subscriptions continued working. The agent stopped replying without
    telling anyone.
    """
    calls = []

    class _Agent:
        pubkey = "aa" * 32
        delegation_id = "d1"

        async def ensure_registered(self, owner, name, **kw):
            calls.append(kw.get("days"))
            return "d1"

    svc_agent = _Agent()
    stop = asyncio.Event()
    task = asyncio.create_task(
        _renew_mandate_loop(svc_agent, object(), interval_seconds=0.01, stop=stop))
    await asyncio.sleep(0.05)
    stop.set()
    await task
    assert len(calls) >= 2, f"mandate was not renewed while running (calls: {len(calls)})"


async def test_archived_stranger_leaves_a_trace_in_the_log(caplog):
    """Archive strangers quietly but log the sender and rejection reason."""
    import logging

    async with FakeRelay() as relay:
        async with Agent([relay.url]) as project, Agent([relay.url]) as stranger:
            await stranger.request_connection(project.pubkey, "cheap backlinks for sale")
            svc = ProjectAgent(project, Config(policy=Policy()), Recorder())
            with caplog.at_level(logging.INFO, logger="a4a_agent.service"):
                report = await svc.process_connection_requests()
            assert report["archived"] == 1
            msgs = " | ".join(caplog.messages)
            assert stranger.pubkey[:12] in msgs, f"sender missing from log: {msgs}"
            assert "archived" in msgs.lower(), f"reason missing from log: {msgs}"


async def test_startup_pass_reports_counts_to_the_log(caplog):
    """The startup backlog pass exposes counts to the operator."""
    import asyncio
    import logging

    async with FakeRelay() as relay:
        async with Agent([relay.url]) as project, Agent([relay.url]) as stranger:
            await stranger.request_connection(project.pubkey, "hello")
            svc = ProjectAgent(project, Config(policy=Policy()), Recorder())
            stop = asyncio.Event()
            stop.set()  # Startup pass only, with no live subscriptions.
            with caplog.at_level(logging.INFO, logger="a4a_agent.service"):
                await svc.serve(stop=stop)
            msgs = " | ".join(caplog.messages)
            assert "requests" in msgs.lower() and "archived" in msgs.lower(), msgs
            assert "1" in msgs, msgs
