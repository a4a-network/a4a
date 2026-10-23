"""Relay regression in a disposable, loopback-only Docker container.

By default this uses the offline builder volume. ``--image`` instead exercises a
prebuilt release image, including its Docker healthcheck and forced-termination
recovery, an online-backup restore into a second container, and a two-relay
failover/rejoin drill. No production URL is accepted. The test removes only the
containers and volumes it creates.

Without ``--image``, the relay binary must already be in the ``a4a-relay-target``
volume (``/build/debug/nostr-rs-relay``). If another checkout's ``relay/dev.sh``
removed it, this exits before creating a container and names ``bash relay/dev.sh build``.
"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
from functools import cache
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import sysconfig
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid
from urllib.parse import urlsplit
from xml.etree import ElementTree
from collections.abc import Callable

ROOT = Path(__file__).resolve().parents[1]
DIAGNOSTICS = None
sys.path.insert(0, str(ROOT / "sdk-python"))

from a4a.agent import Agent  # noqa: E402
from a4a.delegation import create_delegation, create_revocation  # noqa: E402
from a4a.dialogue import DialogueStore  # noqa: E402
from a4a.event import Event  # noqa: E402
from a4a.inbox import InboxConflict, InboxStore  # noqa: E402
from a4a.inbox_receiver import InboxReceiver  # noqa: E402
from a4a.keys import Keys  # noqa: E402
from a4a.relay import (  # noqa: E402
    FanOutRelayClient,
    InsufficientCopies,
    RelayClient,
    RelayError,
)


@cache
def _docker_connection() -> tuple[str, dict[str, str]]:
    # Resolve once, before the first daemon operation; cleanup uses the same daemon.
    env = dict(os.environ)
    context = env.get("DOCKER_CONTEXT")
    endpoint = env.get("DOCKER_HOST") if not context else None
    if not endpoint:
        command = ["docker", "context", "inspect"]
        if context:
            command.append(context)
        command.extend(["--format", "{{json .Endpoints.docker.Host}}"])
        endpoint = json.loads(subprocess.check_output(command, text=True, env=env, timeout=10))
    parsed = urlsplit(endpoint)
    local_unix = (parsed.scheme == "unix" and not parsed.netloc
                  and parsed.path.startswith("/") and not parsed.query and not parsed.fragment)
    pipe_prefix = "npipe:////./pipe/"
    pipe_name = endpoint.removeprefix(pipe_prefix)
    local_pipe = (endpoint.startswith(pipe_prefix) and bool(pipe_name)
                  and all(c.isascii() and (c.isalnum() or c in "_.-") for c in pipe_name))
    if not (local_unix or local_pipe):
        raise RuntimeError("this check requires a local Docker Unix socket or named pipe")
    for key in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"):
        env.pop(key, None)
    return endpoint, env


def docker(*args: str) -> str:
    endpoint, env = _docker_connection()
    return subprocess.check_output(["docker", "--host", endpoint, *args], text=True, env=env).strip()


class FixtureDiagnostics:
    """Read only this run's named DB volumes; write only its backup fixture."""

    def __init__(self, image: str, prefix: str):
        self.image = docker("image", "inspect", "--format", "{{.Id}}", image)
        if not self.image.startswith("sha256:") or len(self.image) != 71:
            raise RuntimeError("diagnostic image must already exist in the local daemon")
        self.prefix = prefix

    def sqlite(self, container: str, database: str, statement: str, *, backup: bool = False) -> str:
        if container != self.prefix and not container.startswith(self.prefix + "-"):
            raise RuntimeError("diagnostic container is outside this run")
        state = json.loads(docker("inspect", container))[0]
        allowed = {"/usr/src/app/db", "/usr/src/app/backup"}
        if database not in {"/usr/src/app/db/nostr.db", "/usr/src/app/backup/recovery-backup.db"}:
            raise RuntimeError("diagnostic database is outside the fixture paths")
        mounts = []
        for mount in state["Mounts"]:
            destination = mount["Destination"]
            if destination not in allowed:
                continue
            if mount["Type"] != "volume" or not mount["Name"].startswith(self.prefix + "-"):
                raise RuntimeError("diagnostic volume is outside this run")
            writable = backup and destination == "/usr/src/app/backup"
            mounts.extend(["-v", f"{mount['Name']}:{destination}" + ("" if writable else ":ro")])
            allowed.remove(destination)
        required = {"/usr/src/app/db"} if database.endswith("nostr.db") else {"/usr/src/app/backup"}
        if backup:
            required.add("/usr/src/app/backup")
        if required & allowed:
            raise RuntimeError("diagnostic fixture volume is missing")
        # A completed .backup has no writer. Its read-only inspection must not
        # create WAL/SHM files; immutable must never be used for the live DB.
        filename = ("file:" + database + "?immutable=1&mode=ro"
                    if database == "/usr/src/app/backup/recovery-backup.db" else database)
        return docker("run", "--rm", "--pull", "never", "--network", "none", "--read-only",
                      "--memory", "128m", "--cpus", "1", "--pids-limit", "64",
                      "--cap-drop", "ALL", "--security-opt", "no-new-privileges", *mounts,
                      "--entrypoint", "sqlite3", self.image, "-readonly", filename, statement)


def sqlite(container: str, database: str, statement: str, *, backup: bool = False) -> str:
    if DIAGNOSTICS is not None:
        return DIAGNOSTICS.sqlite(container, database, statement, backup=backup)
    return docker("exec", container, "sqlite3", database, statement)


def diagnostic_image(runtime: str) -> str:
    return DIAGNOSTICS.image if DIAGNOSTICS is not None else runtime


def check_pilot_report(path: Path) -> None:
    error = "private pilot requires one executed passing test"
    try:
        root = ElementTree.parse(path).getroot()
    except (OSError, ElementTree.ParseError) as exc:
        raise RuntimeError(error) from exc
    cases = root.findall(".//testcase")
    if (len(cases) != 1 or cases[0].get("name") != "test_private_pilot_on_disposable_relay"
            or any(root.find(f".//{tag}") is not None for tag in ("failure", "error", "skipped"))):
        raise RuntimeError(error)


def check_notary_report(path: Path) -> None:
    error = "notary history requires one executed passing test"
    try:
        root = ElementTree.parse(path).getroot()
    except (OSError, ElementTree.ParseError) as exc:
        raise RuntimeError(error) from exc
    cases = root.findall(".//testcase")
    if (len(cases) != 1
            or cases[0].get("name") != "test_real_history_pages_reach_notary_store_across_restart"
            or any(root.find(f".//{tag}") is not None for tag in ("failure", "error", "skipped"))):
        raise RuntimeError(error)


def run_notary_history_check(container: str, *, image: str, packages: Path) -> Path:
    """Check the 26-event fixture and retain its log/JUnit in an owned host directory.

    Return artifacts through stdout so the image's unprivileged user never needs
    write access to a host bind mount. Pure-Python test tools are appended after
    the image's own dependencies; the source SDK and notary are mounted read-only.
    """
    if not packages.is_dir():
        raise ValueError("notary test packages directory does not exist")
    directory = Path(tempfile.mkdtemp(prefix="a4a-notary-history-"))
    print(f"LOCAL NOTARY ARTIFACTS: {directory}", flush=True)
    bootstrap = """import contextlib, io, json, pathlib, sys, traceback
sys.path.append('/host-packages')
sys.path.insert(0, '/app/sdk-python')
log = io.StringIO()
report = pathlib.Path('/tmp/a4a-history-result.xml')
with contextlib.redirect_stdout(log), contextlib.redirect_stderr(log):
    try:
        import pytest
        code = int(pytest.main(['-p', 'pytest_asyncio.plugin', '-p', 'no:cacheprovider',
            '-q', '--local-history-check', '--local-history-relay', 'ws://127.0.0.1:8080',
            '--junitxml=' + str(report),
            'tests/test_live_history.py::test_real_history_pages_reach_notary_store_across_restart']))
    except BaseException:
        traceback.print_exc()
        code = 2
print(json.dumps({'exit_code': code, 'log': log.getvalue(),
    'junit': report.read_text(encoding='utf-8') if report.exists() else ''}))
sys.exit(code)
"""
    failure = None
    try:
        output = docker(
            "run", "--rm", "--pull", "never", "--network", f"container:{container}",
            "--entrypoint", "python", "-v", f"{packages}:/host-packages:ro",
            "-v", f"{ROOT / 'notary'}:/app/notary:ro",
            "-v", f"{ROOT / 'sdk-python'}:/app/sdk-python:ro", "-w", "/app/notary",
            "-e", "PYTEST_DISABLE_PLUGIN_AUTOLOAD=1", image, "-B", "-c", bootstrap)
    except subprocess.CalledProcessError as exc:
        output, failure = exc.output or "", exc
    if isinstance(output, bytes):
        output = output.decode("utf-8", errors="replace")
    (directory / "container-output.log").write_text(output, encoding="utf-8")
    try:
        result = json.loads(output)
        if (not isinstance(result, dict) or type(result.get("exit_code")) is not int
                or not isinstance(result.get("log"), str)
                or not isinstance(result.get("junit"), str)):
            raise ValueError("invalid notary test result")
    except (ValueError, TypeError) as exc:
        raise RuntimeError(f"notary history returned no usable result; artifacts: {directory}") from exc
    (directory / "pytest.log").write_text(result["log"], encoding="utf-8")
    report = directory / "result.xml"
    report.write_text(result["junit"], encoding="utf-8")
    print(result["log"], flush=True)
    if failure is not None or result["exit_code"] != 0:
        raise RuntimeError(f"notary history test failed; artifacts: {directory}") from failure
    check_notary_report(report)
    return directory


def get(base: str, path: str) -> tuple[bytes, object]:
    with urllib.request.urlopen(base + path, timeout=10) as response:
        body = response.read(2 * 1024 * 1024 + 1)
    assert len(body) <= 2 * 1024 * 1024, "HTTP history exceeded the byte cap"
    return body, json.loads(body)


def wait_ready(base: str) -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            get(base, "/v1/health")
            return
        except (OSError, ValueError):
            time.sleep(0.1)
    raise RuntimeError("local test relay did not become ready")


def wait_container_healthy(container: str, *, allow_recovery: bool = False) -> None:
    deadline = time.monotonic() + 30
    last = "unknown"
    while time.monotonic() < deadline:
        last = docker(
            "inspect", "--format",
            "{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}",
            container,
        )
        if last == "healthy":
            return
        if last == "unhealthy" and not allow_recovery:
            break
        time.sleep(0.1)
    raise RuntimeError(f"release container healthcheck did not become healthy (status={last})")


def verify_sqlite_integrity(container: str, database: str) -> None:
    result = sqlite(container, database, "PRAGMA integrity_check;")
    if result.strip() != "ok":
        raise RuntimeError(f"SQLite integrity check failed after forced termination: {result!r}")


async def history_ids(base: str) -> tuple[set[str], list[int]]:
    after, after_id, seen, sizes = 0, "", set(), []
    for _ in range(20):
        body, page = await asyncio.to_thread(
            get, base, f"/v1/history?after={after}&after_id={after_id}&limit=5000&page=2")
        assert page["version"] == 2
        rows = page["rows"]
        if not rows:
            assert page["next_cursor"] is None
            return seen, sizes
        sizes.append(len(body))
        for row in rows:
            position = (row["first_seen"], row["event"]["id"])
            assert position > (after, after_id)
            assert position[1] not in seen
            seen.add(position[1])
            after, after_id = position
        assert page["next_cursor"] == {"first_seen": after, "id": after_id}
    raise AssertionError("history cursor failed to reach the end")


async def verify_multi_relay_inbox(
    *, primary_url: str, secondary_url: str, secondary_container: str,
    owner: Keys,
) -> None:
    """Prove durable per-relay cursors and one-time processing across an outage."""
    recipient_keys = Keys()
    recipient = Agent([primary_url, secondary_url], keys=recipient_keys)
    allowed = {owner.pubkey_hex}
    with tempfile.TemporaryDirectory(prefix="a4a-multi-inbox-") as directory:
        with InboxStore(
            Path(directory) / "inbox", recipient.pubkey, "failover-check",
        ) as store:
            receiver = InboxReceiver(
                recipient, store, lambda: allowed, start_after=0, poll_seconds=5)

            async with Agent([primary_url, secondary_url], keys=owner) as sender:
                common = await sender.send_private_message_receipt(
                    recipient.pubkey, "same encrypted letter on both relays",
                    delivery_id="multi-relay-common", expires_in=300,
                )
            await asyncio.sleep(1.1)
            assert await receiver.sync_once() == 1
            assert store.cursor(primary_url)[1] == common["outer_id"]
            assert store.cursor(secondary_url)[1] == common["outer_id"]
            assert store.status()["pending"] == store.status()["total"] == 1
            claimed = store.claim(
                recipient, "failover-check", allowed, lease_seconds=60)
            assert claimed is not None
            assert claimed["inner_id"] == common["inner_id"]
            assert claimed["content"] == "same encrypted letter on both relays"
            store.finish(
                claimed["seq"], claimed["lease_token"], "failover-check", "processed")

            async with Agent([secondary_url], keys=owner) as sender:
                late = await sender.send_private_message_receipt(
                    recipient.pubkey, "letter held by the unavailable relay",
                    delivery_id="multi-relay-late", expires_in=300,
                )
            await asyncio.sleep(1.1)
            await asyncio.to_thread(
                docker, "kill", "--signal", "KILL", secondary_container)
            exit_code = await asyncio.to_thread(
                docker, "inspect", "--format", "{{.State.ExitCode}}", secondary_container)
            assert exit_code == "137", f"inbox failover returned exit code {exit_code}"

            assert await receiver.sync_once() == 0
            assert store.health()["state"] == "ready"
            assert store.cursor(primary_url)[1] == common["outer_id"]
            assert store.cursor(secondary_url)[1] == common["outer_id"]
            assert store.status()["total"] == store.status()["processed"] == 1

            await asyncio.to_thread(docker, "start", secondary_container)
            address = await asyncio.to_thread(
                docker, "port", secondary_container, "8080/tcp")
            assert secondary_url == "ws://" + address, (
                "fixture relay address changed across inbox rejoin")
            await asyncio.to_thread(wait_ready, "http://" + address)
            await asyncio.to_thread(wait_container_healthy, secondary_container)

            assert await receiver.sync_once() == 1
            assert store.cursor(primary_url)[1] == common["outer_id"]
            assert store.cursor(secondary_url)[1] == late["outer_id"]
            status = store.status()
            assert status["pending"] == 1 and status["processed"] == 1
            assert status["total"] == 2
            claimed = store.claim(
                recipient, "failover-check", allowed, lease_seconds=60)
            assert claimed is not None
            assert claimed["inner_id"] == late["inner_id"]
            assert claimed["content"] == "letter held by the unavailable relay"
            store.finish(
                claimed["seq"], claimed["lease_token"], "failover-check", "processed")
            assert await receiver.sync_once() == 0
            status = store.status()
            assert status["total"] == status["processed"] == 2

            # Keep the real receiver attached while one WebSocket disappears. A
            # prompt notice proves that the live sibling supplied the wake hint;
            # later, a prompt secondary-only notice proves that its subscription
            # reconnected instead of relying on the 30-second recovery timer.
            receiver.poll_seconds = 5
            source = receiver.notices(interval=10, per_hour=60)
            first_notice = asyncio.create_task(anext(source))
            pending_notice = None
            try:
                deadline = time.monotonic() + 10
                while not receiver.stream_connected and time.monotonic() < deadline:
                    await asyncio.sleep(0.05)
                assert receiver.stream_connected, "inbox WebSocket streams did not connect"
                await asyncio.sleep(0.5)

                await asyncio.to_thread(
                    docker, "kill", "--signal", "KILL", secondary_container)
                exit_code = await asyncio.to_thread(
                    docker, "inspect", "--format", "{{.State.ExitCode}}",
                    secondary_container,
                )
                assert exit_code == "137"
                async with Agent([primary_url], keys=owner) as sender:
                    primary_wake = await sender.send_private_message_receipt(
                        recipient.pubkey, "wake through the surviving relay",
                        delivery_id="continuous-primary", expires_in=300,
                    )
                notice = await asyncio.wait_for(first_notice, timeout=10)
                assert notice == {
                    "consumer": "failover-check", "pending": 1, "seq_hint": 3,
                }
                assert "wake through" not in json.dumps(notice)
                claimed = store.claim(
                    recipient, "failover-check", allowed, lease_seconds=60)
                assert claimed is not None and claimed["inner_id"] == primary_wake["inner_id"]
                store.finish(
                    claimed["seq"], claimed["lease_token"],
                    "failover-check", "processed",
                )

                await asyncio.to_thread(docker, "start", secondary_container)
                address = await asyncio.to_thread(
                    docker, "port", secondary_container, "8080/tcp")
                assert secondary_url == "ws://" + address
                await asyncio.to_thread(wait_ready, "http://" + address)
                await asyncio.to_thread(wait_container_healthy, secondary_container)
                # The failed stream retries every five seconds. Waiting also clears
                # the durable ten-second wake budget before the positive control.
                await asyncio.sleep(10.1)
                receiver.poll_seconds = 30
                pending_notice = asyncio.create_task(anext(source))
                await asyncio.sleep(0.2)
                started = time.monotonic()
                async with Agent([secondary_url], keys=owner) as sender:
                    secondary_wake = await sender.send_private_message_receipt(
                        recipient.pubkey, "wake after secondary subscription rejoin",
                        delivery_id="continuous-secondary", expires_in=300,
                    )
                notice = await asyncio.wait_for(pending_notice, timeout=6)
                pending_notice = None
                secondary_wake_seconds = time.monotonic() - started
                assert secondary_wake_seconds < 6
                assert notice == {
                    "consumer": "failover-check", "pending": 1, "seq_hint": 4,
                }
                assert "subscription rejoin" not in json.dumps(notice)
                claimed = store.claim(
                    recipient, "failover-check", allowed, lease_seconds=60)
                assert claimed is not None and claimed["inner_id"] == secondary_wake["inner_id"]
                store.finish(
                    claimed["seq"], claimed["lease_token"],
                    "failover-check", "processed",
                )

                # Let the wake budget become available, then replay the same delivery
                # under a fresh gift wrap. Its relay cursor must advance, but the
                # completed dedup tombstone must not produce another notice.
                await asyncio.sleep(10.1)
                pending_notice = asyncio.create_task(anext(source))
                await asyncio.sleep(0.2)
                async with Agent([secondary_url], keys=owner) as sender:
                    replay = await sender.send_private_message_receipt(
                        recipient.pubkey, "wake after secondary subscription rejoin",
                        delivery_id="continuous-secondary", expires_in=300,
                    )
                deadline = time.monotonic() + 8
                while (store.cursor(secondary_url)[1] != replay["outer_id"]
                       and time.monotonic() < deadline):
                    await asyncio.sleep(0.05)
                assert store.cursor(secondary_url)[1] == replay["outer_id"]
                assert not pending_notice.done(), (
                    "a replay of processed work emitted a second wake notice")
                status = store.status()
                assert status["total"] == status["processed"] == 4
                database = store.path.read_bytes()
                for plaintext in (
                    b"same encrypted letter on both relays",
                    b"letter held by the unavailable relay",
                    b"wake through the surviving relay",
                    b"wake after secondary subscription rejoin",
                ):
                    assert plaintext not in database
                print(
                    "PASS continuous inbox wake: metadata-only primary notice during "
                    f"outage, secondary subscription rejoined in {secondary_wake_seconds:.2f}s, "
                    "processed replay advanced cursor without a second notice",
                    flush=True,
                )
            finally:
                for task in (first_notice, pending_notice):
                    if task is not None and not task.done():
                        task.cancel()
                        with contextlib.suppress(asyncio.CancelledError):
                            await task
                await source.aclose()

            # Simulate losing the consumer process after it decrypted and claimed a
            # message but before it recorded the external effect. The next process
            # must preserve both relay cursors and classify the expired lease as
            # UNKNOWN. Automatically retrying it would risk repeating that effect.
            async with Agent([primary_url, secondary_url], keys=owner) as sender:
                restart_work = await sender.send_private_message_receipt(
                    recipient.pubkey, "work abandoned across receiver restart",
                    delivery_id="receiver-restart", expires_in=300,
                )
            await asyncio.sleep(1.1)
            assert await receiver.sync_once() == 1
            saved_cursors = {
                primary_url: store.cursor(primary_url),
                secondary_url: store.cursor(secondary_url),
            }
            assert all(cursor[1] == restart_work["outer_id"]
                       for cursor in saved_cursors.values())
            abandoned = store.claim(
                recipient, "failover-check", allowed, lease_seconds=1)
            assert abandoned is not None
            assert abandoned["inner_id"] == restart_work["inner_id"]
            assert abandoned["content"] == "work abandoned across receiver restart"

        # The old connection and all in-memory receiver state are now gone. Waiting
        # also clears the durable wake budget, so a missing notice cannot be mistaken
        # for ordinary throttling.
        await asyncio.sleep(10.1)
        with InboxStore(
            Path(directory) / "inbox", recipient.pubkey, "failover-check",
        ) as restarted_store:
            restarted = InboxReceiver(
                recipient, restarted_store, lambda: allowed,
                start_after=0, poll_seconds=30,
            )
            assert {
                primary_url: restarted_store.cursor(primary_url),
                secondary_url: restarted_store.cursor(secondary_url),
            } == saved_cursors
            assert restarted_store.unknown_bindings("failover-check") == {
                "unknown": [{
                    "seq": abandoned["seq"],
                    "inner_id": abandoned["inner_id"],
                }],
                "truncated": False,
                "limit": 100,
            }
            status = restarted_store.status()
            assert status["unknown"] == 1 and status["pending"] == 0
            assert status["processed"] == 4 and status["total"] == 5
            try:
                restarted_store.finish(
                    abandoned["seq"], abandoned["lease_token"],
                    "failover-check", "processed",
                )
            except InboxConflict:
                pass
            else:
                raise AssertionError("expired pre-restart lease completed work")

            resolution = restarted_store.reconcile_unknown(
                abandoned["seq"], abandoned["inner_id"], "failover-check",
                "retry", allowed_senders=allowed,
            )
            assert resolution == {
                "state": "pending", "resolution": "retry",
                "seq": abandoned["seq"], "inner_id": abandoned["inner_id"],
                "network_ack_sent": False,
            }
            restart_source = restarted.notices(interval=10, per_hour=60)
            next_notice = asyncio.create_task(anext(restart_source))
            try:
                notice = await asyncio.wait_for(next_notice, timeout=10)
                assert notice == {
                    "consumer": "failover-check", "pending": 1,
                    "seq_hint": abandoned["seq"],
                }
                retried = restarted_store.claim(
                    recipient, "failover-check", allowed, lease_seconds=60)
                assert retried is not None
                assert retried["inner_id"] == abandoned["inner_id"]
                assert retried["content"] == abandoned["content"]
                assert retried["lease_token"] != abandoned["lease_token"]
                restarted_store.finish(
                    retried["seq"], retried["lease_token"],
                    "failover-check", "processed",
                )
                assert restarted_store.status()["processed"] == 5
                assert {
                    primary_url: restarted_store.cursor(primary_url),
                    secondary_url: restarted_store.cursor(secondary_url),
                } == saved_cursors
                assert b"work abandoned across receiver restart" not in (
                    restarted_store.path.read_bytes())

                # Resuming the iterator after its only notice must not replay the
                # unchanged fingerprint merely because a new receiver owns it.
                next_notice = asyncio.create_task(anext(restart_source))
                await asyncio.sleep(1)
                assert not next_notice.done(), (
                    "completed work emitted another notice after receiver restart")
            finally:
                if not next_notice.done():
                    next_notice.cancel()
                    with contextlib.suppress(asyncio.CancelledError):
                        await next_notice
                await restart_source.aclose()
            print(
                "PASS inbox receiver restart: relay cursors persisted, expired lease "
                "became metadata-only unknown work, stale completion was rejected, "
                "explicit retry completed once without another notice",
                flush=True,
            )
    print(
        "PASS multi-relay inbox: duplicate envelope stored once, independent cursors, "
        "live sibling tolerated outage, late relay-only letter processed once after rejoin",
        flush=True,
    )


async def verify_dialogue_restart(
    *, primary_url: str, secondary_url: str,
) -> None:
    """Lose a real sender process after relay acceptance, then reconcile once."""
    dialogue_keys, peer_keys = Keys(), Keys()
    allowed = {peer_keys.pubkey_hex}
    child = r'''
import asyncio
import json
import os
import sys

sys.path.insert(0, os.environ["A4A_DIALOGUE_SDK"])
from a4a import Agent, Keys
from a4a.dialogue import DialogueStore

agent = Agent(json.loads(os.environ["A4A_DIALOGUE_RELAYS"]),
              keys=Keys(os.environ["A4A_DIALOGUE_KEY"]))
peer = os.environ["A4A_DIALOGUE_PEER"]
allowed = {peer}

async def run():
    async with agent:
        with DialogueStore(os.environ["A4A_DIALOGUE_STORE"], agent.pubkey,
                           "dialogue-restart") as store:
            store.activate()
            lease = store.acquire(peer, "old-worker", allowed, lease_seconds=1)
            store.checkpoint(agent, lease["token"], "old-worker", allowed,
                             "checkpoint before uncertain send")
            prepared = store.prepare_send(
                agent, lease["token"], "old-worker", allowed,
                "crash-after-accept", "dialogue send survives process loss",
            )
            print(json.dumps({"lease": lease, "prepared": prepared}), flush=True)
            publish = agent.relay.publish
            async def exit_after_acceptance(event, **kwargs):
                await publish(event, **kwargs)
                os._exit(23)
            agent.relay.publish = exit_after_acceptance
            await store.dispatch(agent, lease["token"], "old-worker", allowed,
                                 "crash-after-accept")

asyncio.run(run())
'''
    with tempfile.TemporaryDirectory(prefix="a4a-dialogue-restart-") as directory:
        store_path = Path(directory) / "sender"
        # The crash probe needs only its synthetic identity and local relay URLs.
        # Do not copy a real A4A profile/relay policy from the invoking shell into
        # a disposable worker merely because both variables share a prefix.
        child_env = {
            key: value for key, value in os.environ.items()
            if not key.upper().startswith("A4A_")
        }
        child_env.update({
            "A4A_DIALOGUE_SDK": str(ROOT / "sdk-python"),
            "A4A_DIALOGUE_RELAYS": json.dumps([primary_url, secondary_url]),
            "A4A_DIALOGUE_KEY": dialogue_keys.privkey_hex,
            "A4A_DIALOGUE_PEER": peer_keys.pubkey_hex,
            "A4A_DIALOGUE_STORE": str(store_path),
        })
        process = await asyncio.create_subprocess_exec(
            sys.executable, "-c", child,
            cwd=ROOT, env=child_env,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=30)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            raise AssertionError("dialogue crash child did not finish") from None
        assert process.returncode == 23, stderr.decode("utf-8", errors="replace")
        lines = stdout.decode("utf-8", errors="strict").splitlines()
        assert len(lines) == 1, lines
        child_state = json.loads(lines[0])
        old_lease = child_state["lease"]
        prepared = child_state["prepared"]

        # The child committed `dispatching`, published to the real release relays,
        # and died before it could record the response. Let its one-second lease
        # expire; takeover must preserve uncertainty rather than guessing success.
        await asyncio.sleep(1.2)
        restarted_agent = Agent(
            [primary_url, secondary_url], keys=dialogue_keys)
        async with restarted_agent:
            with DialogueStore(
                store_path, restarted_agent.pubkey, "dialogue-restart",
            ) as store:
                [work] = store.work(allowed)
                assert work["peer"] == peer_keys.pubkey_hex
                assert work["lease_active"] is False
                assert work["outgoing"] == {"unknown": 1}
                assert store.notice(allowed, interval=10, per_hour=60) == {
                    "consumer": "dialogue-restart", "pending": 0,
                    "seq_hint": 0, "needs_reconciliation": 1,
                    "outgoing_prepared": 0,
                }
                try:
                    store.validate_lease(
                        old_lease["token"], "old-worker", allowed)
                except InboxConflict:
                    pass
                else:
                    raise AssertionError("expired dialogue worker retained ownership")

                replacement = store.acquire(
                    peer_keys.pubkey_hex, "replacement-worker", allowed)
                assert replacement["conversation_id"] == old_lease["conversation_id"]
                assert replacement["epoch"] > old_lease["epoch"]
                history = store.history(
                    restarted_agent, replacement["token"],
                    "replacement-worker", allowed,
                )
                assert history["checkpoint"] == "checkpoint before uncertain send"
                assert len(history["items"]) == 1
                assert history["items"][0]["direction"] == "out"
                assert history["items"][0]["state"] == "unknown"
                assert history["items"][0]["content"] == (
                    "dialogue send survives process loss")
                try:
                    store.prepare_send(
                        restarted_agent, replacement["token"],
                        "replacement-worker", allowed,
                        "blocked-before-reconcile", "must not overtake uncertainty",
                    )
                except InboxConflict:
                    pass
                else:
                    raise AssertionError("new dialogue send bypassed uncertain work")

                publish_calls = 0
                async def unexpected_publish(*args, **kwargs):
                    nonlocal publish_calls
                    publish_calls += 1
                    raise AssertionError("unknown dialogue operation was republished")
                restarted_agent.relay.publish = unexpected_publish
                unchanged = await store.dispatch(
                    restarted_agent, replacement["token"],
                    "replacement-worker", allowed, "crash-after-accept",
                )
                assert unchanged["state"] == "unknown"
                assert publish_calls == 0

                receipt = await store.reconcile(
                    restarted_agent, replacement["token"],
                    "replacement-worker", allowed, "crash-after-accept",
                )
                assert receipt["state"] == "relay_observed"
                assert receipt["outer_id"] == prepared["outer_id"]
                again = await store.dispatch(
                    restarted_agent, replacement["token"],
                    "replacement-worker", allowed, "crash-after-accept",
                )
                assert again == receipt and publish_calls == 0
                next_operation = store.prepare_send(
                    restarted_agent, replacement["token"],
                    "replacement-worker", allowed,
                    "after-reconcile", "new work is unblocked after readback",
                )
                assert next_operation["state"] == "prepared"
                assert store.abandon(
                    restarted_agent, replacement["token"],
                    "replacement-worker", allowed, "after-reconcile",
                )["state"] == "abandoned"
                assert store.work(allowed) == []
                database = store.path.read_bytes()
                for plaintext in (
                    b"dialogue send survives process loss",
                    b"checkpoint before uncertain send",
                    b"new work is unblocked after readback",
                ):
                    assert plaintext not in database

        # A distinct recipient proves the crash-time envelope is readable once from
        # the real two-relay history even though both nodes retained a copy.
        recipient = Agent([primary_url, secondary_url], keys=peer_keys)
        with InboxStore(
            Path(directory) / "recipient", recipient.pubkey,
            "dialogue-recipient",
        ) as inbox:
            receiver = InboxReceiver(
                recipient, inbox, lambda: {dialogue_keys.pubkey_hex},
                start_after=0, poll_seconds=5,
            )
            assert await receiver.sync_once() == 1
            assert inbox.cursor(primary_url)[1] == prepared["outer_id"]
            assert inbox.cursor(secondary_url)[1] == prepared["outer_id"]
            claimed = inbox.claim(
                recipient, "dialogue-recipient", {dialogue_keys.pubkey_hex})
            assert claimed is not None
            assert claimed["inner_id"] == prepared["inner_id"]
            assert claimed["content"] == "dialogue send survives process loss"
            inbox.finish(
                claimed["seq"], claimed["lease_token"],
                "dialogue-recipient", "processed",
            )
            assert await receiver.sync_once() == 0
            assert inbox.status()["processed"] == inbox.status()["total"] == 1
            assert b"dialogue send survives process loss" not in inbox.path.read_bytes()
    print(
        "PASS dialogue process restart: child died after two-relay acceptance, "
        "expired worker was fenced, unknown send blocked overtaking, readback "
        "reconciled without republish, recipient processed one deduplicated copy",
        flush=True,
    )


async def verify_incoming_dialogue_restart(
    *, primary_url: str, secondary_url: str,
) -> None:
    """Lose a dialogue worker after it exposes real incoming work."""
    dialogue_keys, peer_keys = Keys(), Keys()
    allowed = {peer_keys.pubkey_hex}
    urls = [primary_url, secondary_url]
    child = r'''
import json
import os
import sys

sys.path.insert(0, os.environ["A4A_DIALOGUE_SDK"])
from a4a import Agent, Keys
from a4a.dialogue import DialogueStore

agent = Agent(json.loads(os.environ["A4A_DIALOGUE_RELAYS"]),
              keys=Keys(os.environ["A4A_DIALOGUE_KEY"]))
peer = os.environ["A4A_DIALOGUE_PEER"]
allowed = {peer}
with DialogueStore(os.environ["A4A_DIALOGUE_STORE"], agent.pubkey,
                   "incoming-dialogue-restart") as store:
    lease = store.acquire(peer, "incoming-old-worker", allowed, lease_seconds=1)
    history = store.history(agent, lease["token"], "incoming-old-worker", allowed)
    item = history["items"][0]
    print(json.dumps({
        "lease": lease,
        "inbox_seq": item["inbox_seq"],
        "inner_id": item["inner_id"],
        "state": item["state"],
    }), flush=True)
    os._exit(24)
'''
    with tempfile.TemporaryDirectory(
        prefix="a4a-incoming-dialogue-restart-",
    ) as directory:
        store_path = Path(directory) / "dialogue"
        recipient = Agent(urls, keys=dialogue_keys)
        async with Agent(urls, keys=peer_keys) as sender:
            incoming = await sender.send_private_message_receipt(
                recipient.pubkey, "incoming dialogue work survives process loss",
                delivery_id="incoming-dialogue-crash", expires_in=300,
            )
        await asyncio.sleep(1.1)
        with DialogueStore(
            store_path, recipient.pubkey, "incoming-dialogue-restart",
        ) as store:
            store.activate()
            receiver = InboxReceiver(
                recipient, store, lambda: allowed,
                start_after=0, poll_seconds=5,
            )
            assert await receiver.sync_once() == 1
            saved_cursors = {
                primary_url: store.cursor(primary_url),
                secondary_url: store.cursor(secondary_url),
            }
            assert all(cursor[1] == incoming["outer_id"]
                       for cursor in saved_cursors.values())
            assert store.status()["pending"] == 1

        child_env = {
            key: value for key, value in os.environ.items()
            if not key.upper().startswith("A4A_")
        }
        child_env.update({
            "A4A_DIALOGUE_SDK": str(ROOT / "sdk-python"),
            "A4A_DIALOGUE_RELAYS": json.dumps(urls),
            "A4A_DIALOGUE_KEY": dialogue_keys.privkey_hex,
            "A4A_DIALOGUE_PEER": peer_keys.pubkey_hex,
            "A4A_DIALOGUE_STORE": str(store_path),
        })
        process = await asyncio.create_subprocess_exec(
            sys.executable, "-c", child,
            cwd=ROOT, env=child_env,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=30)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            raise AssertionError("incoming dialogue crash child did not finish") from None
        assert process.returncode == 24, stderr.decode("utf-8", errors="replace")
        lines = stdout.decode("utf-8", errors="strict").splitlines()
        assert len(lines) == 1, lines
        child_state = json.loads(lines[0])
        old_lease = child_state["lease"]
        assert child_state["inner_id"] == incoming["inner_id"]
        assert child_state["state"] == "processing"

        await asyncio.sleep(1.2)
        restarted_agent = Agent(urls, keys=dialogue_keys)
        with DialogueStore(
            store_path, restarted_agent.pubkey, "incoming-dialogue-restart",
        ) as store:
            [work] = store.work(allowed)
            assert work["peer"] == peer_keys.pubkey_hex
            assert work["lease_active"] is False
            assert work["pending"] == 0
            assert work["processing"] == 0
            assert work["unknown"] == 1
            assert work["outgoing"] == {}
            assert store.notice(allowed, interval=10, per_hour=60) == {
                "consumer": "incoming-dialogue-restart", "pending": 0,
                "seq_hint": child_state["inbox_seq"],
                "needs_reconciliation": 1, "outgoing_prepared": 0,
            }
            try:
                store.validate_lease(
                    old_lease["token"], "incoming-old-worker", allowed)
            except InboxConflict:
                pass
            else:
                raise AssertionError("expired incoming worker retained ownership")

            replacement = store.acquire(
                peer_keys.pubkey_hex, "incoming-replacement", allowed)
            assert replacement["conversation_id"] == old_lease["conversation_id"]
            assert replacement["epoch"] > old_lease["epoch"]
            history = store.history(
                restarted_agent, replacement["token"],
                "incoming-replacement", allowed,
            )
            assert len(history["items"]) == 1
            item = history["items"][0]
            assert item["direction"] == "in"
            assert item["state"] == "unknown"
            assert item["inbox_seq"] == child_state["inbox_seq"]
            assert item["inner_id"] == incoming["inner_id"]
            assert item["content"] == (
                "incoming dialogue work survives process loss")
            try:
                store.finish_incoming(
                    replacement["token"], "incoming-replacement", allowed,
                    item["inbox_seq"], "processed",
                )
            except InboxConflict:
                pass
            else:
                raise AssertionError(
                    "unknown incoming dialogue work completed without reconciliation")
            completion = store.finish_incoming(
                replacement["token"], "incoming-replacement", allowed,
                item["inbox_seq"], "processed", reconciled=True,
            )
            assert completion == {
                "state": "processed", "seq": item["inbox_seq"],
                "network_ack_sent": False,
            }
            assert store.work(allowed) == []
            assert store.notice(allowed, interval=10, per_hour=60) is None
            assert {
                primary_url: store.cursor(primary_url),
                secondary_url: store.cursor(secondary_url),
            } == saved_cursors
            receiver = InboxReceiver(
                restarted_agent, store, lambda: allowed,
                start_after=0, poll_seconds=5,
            )
            assert await receiver.sync_once() == 0
            status = store.status()
            assert status["processed"] == status["total"] == 1
            assert b"incoming dialogue work survives process loss" not in (
                store.path.read_bytes())
    print(
        "PASS incoming dialogue process restart: child died with processing work, "
        "expired lease became metadata-only reconciliation, stale worker was fenced, "
        "and replacement completed once only with explicit reconciled=True",
        flush=True,
    )


async def verify_prepared_dialogue_restart(
    *, primary_url: str, secondary_url: str,
) -> None:
    """Lose a worker after durable preparation but before its first publish."""
    dialogue_keys, peer_keys = Keys(), Keys()
    allowed = {peer_keys.pubkey_hex}
    urls = [primary_url, secondary_url]
    child = r'''
import json
import os
import sys

sys.path.insert(0, os.environ["A4A_DIALOGUE_SDK"])
from a4a import Agent, Keys
from a4a.dialogue import DialogueStore

agent = Agent(json.loads(os.environ["A4A_DIALOGUE_RELAYS"]),
              keys=Keys(os.environ["A4A_DIALOGUE_KEY"]))
peer = os.environ["A4A_DIALOGUE_PEER"]
allowed = {peer}
with DialogueStore(os.environ["A4A_DIALOGUE_STORE"], agent.pubkey,
                   "prepared-dialogue-restart") as store:
    store.activate()
    lease = store.acquire(peer, "prepared-old-worker", allowed, lease_seconds=1)
    prepared = store.prepare_send(
        agent, lease["token"], "prepared-old-worker", allowed,
        "prepared-before-crash", "prepared dialogue work survives process loss",
    )
    print(json.dumps({"lease": lease, "prepared": prepared}), flush=True)
    os._exit(25)
'''
    with tempfile.TemporaryDirectory(
        prefix="a4a-prepared-dialogue-restart-",
    ) as directory:
        store_path = Path(directory) / "dialogue"
        child_env = {
            key: value for key, value in os.environ.items()
            if not key.upper().startswith("A4A_")
        }
        child_env.update({
            "A4A_DIALOGUE_SDK": str(ROOT / "sdk-python"),
            "A4A_DIALOGUE_RELAYS": json.dumps(urls),
            "A4A_DIALOGUE_KEY": dialogue_keys.privkey_hex,
            "A4A_DIALOGUE_PEER": peer_keys.pubkey_hex,
            "A4A_DIALOGUE_STORE": str(store_path),
        })
        process = await asyncio.create_subprocess_exec(
            sys.executable, "-c", child,
            cwd=ROOT, env=child_env,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=30)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            raise AssertionError("prepared dialogue crash child did not finish") from None
        assert process.returncode == 25, stderr.decode("utf-8", errors="replace")
        lines = stdout.decode("utf-8", errors="strict").splitlines()
        assert len(lines) == 1, lines
        child_state = json.loads(lines[0])
        old_lease = child_state["lease"]
        prepared = child_state["prepared"]
        assert prepared["state"] == "prepared"

        await asyncio.sleep(1.2)
        restarted_agent = Agent(urls, keys=dialogue_keys)
        async with restarted_agent:
            with DialogueStore(
                store_path, restarted_agent.pubkey, "prepared-dialogue-restart",
            ) as store:
                [work] = store.work(allowed)
                assert work["peer"] == peer_keys.pubkey_hex
                assert work["lease_active"] is False
                assert work["pending"] == work["processing"] == work["unknown"] == 0
                assert work["outgoing"] == {"prepared": 1}
                assert store.notice(allowed, interval=10, per_hour=60) == {
                    "consumer": "prepared-dialogue-restart", "pending": 0,
                    "seq_hint": 0, "needs_reconciliation": 0,
                    "outgoing_prepared": 1,
                }
                try:
                    store.validate_lease(
                        old_lease["token"], "prepared-old-worker", allowed)
                except InboxConflict:
                    pass
                else:
                    raise AssertionError("expired prepared worker retained ownership")

                replacement = store.acquire(
                    peer_keys.pubkey_hex, "prepared-replacement", allowed)
                assert replacement["conversation_id"] == old_lease["conversation_id"]
                assert replacement["epoch"] > old_lease["epoch"]
                history = store.history(
                    restarted_agent, replacement["token"],
                    "prepared-replacement", allowed,
                )
                assert len(history["items"]) == 1
                item = history["items"][0]
                assert item["direction"] == "out"
                assert item["state"] == "prepared"
                assert item["operation_id"] == prepared["operation_id"]
                assert item["inner_id"] == prepared["inner_id"]
                assert item["outer_id"] == prepared["outer_id"]
                assert item["delivery_id"] == prepared["delivery_id"]
                assert item["content"] == (
                    "prepared dialogue work survives process loss")

                absent = await restarted_agent.relay.query_bounded(
                    {"ids": [prepared["outer_id"]], "limit": 1}, max_events=2)
                assert absent.events == []
                assert absent.relays_responded == 2

                publish_calls = []
                publish = restarted_agent.relay.publish
                async def counted_publish(event, **kwargs):
                    publish_calls.append((event.id, dict(kwargs)))
                    return await publish(event, **kwargs)
                restarted_agent.relay.publish = counted_publish
                receipt = await store.dispatch(
                    restarted_agent, replacement["token"],
                    "prepared-replacement", allowed, "prepared-before-crash",
                )
                assert receipt == {
                    **prepared, "state": "relay_accepted",
                }
                assert publish_calls == [(
                    prepared["outer_id"], {"replay_on_reconnect": False},
                )]
                again = await store.dispatch(
                    restarted_agent, replacement["token"],
                    "prepared-replacement", allowed, "prepared-before-crash",
                )
                assert again == receipt
                assert len(publish_calls) == 1
                assert store.work(allowed) == []
                assert store.notice(allowed, interval=10, per_hour=60) is None
                assert b"prepared dialogue work survives process loss" not in (
                    store.path.read_bytes())

        await asyncio.sleep(1.1)
        recipient = Agent(urls, keys=peer_keys)
        with InboxStore(
            Path(directory) / "recipient", recipient.pubkey,
            "prepared-dialogue-recipient",
        ) as inbox:
            receiver = InboxReceiver(
                recipient, inbox, lambda: {dialogue_keys.pubkey_hex},
                start_after=0, poll_seconds=5,
            )
            assert await receiver.sync_once() == 1
            assert inbox.cursor(primary_url)[1] == prepared["outer_id"]
            assert inbox.cursor(secondary_url)[1] == prepared["outer_id"]
            claimed = inbox.claim(
                recipient, "prepared-dialogue-recipient",
                {dialogue_keys.pubkey_hex},
            )
            assert claimed is not None
            assert claimed["inner_id"] == prepared["inner_id"]
            assert claimed["delivery_id"] == prepared["delivery_id"]
            assert claimed["content"] == (
                "prepared dialogue work survives process loss")
            inbox.finish(
                claimed["seq"], claimed["lease_token"],
                "prepared-dialogue-recipient", "processed",
            )
            assert await receiver.sync_once() == 0
            assert inbox.status()["processed"] == inbox.status()["total"] == 1
            assert b"prepared dialogue work survives process loss" not in (
                inbox.path.read_bytes())
    print(
        "PASS prepared dialogue process restart: child died before network, "
        "replacement recovered immutable IDs, both relays proved absence before "
        "one publish, repeated dispatch stayed local, recipient processed one copy",
        flush=True,
    )


async def verify_dialogue_relay_set_changes(
    *, primary_url: str, secondary_url: str,
) -> None:
    """Exercise the relay-set safety boundary against two real release relays.

    A prepared envelope is bound to the complete relay set because every added node
    learns communication metadata and every removed node changes durability. Ordering
    is configuration noise, however, so reversing the same set must not strand work.
    """
    all_urls = [primary_url, secondary_url]

    async def relay_has(url: str, event_id: str) -> bool:
        async with RelayClient(url) as relay:
            result = await relay.query_bounded(
                {"ids": [event_id], "limit": 1}, max_events=2)
        return [event.id for event in result.events] == [event_id]

    def make_legacy(store, agent, operation_id: str, relay_url: str) -> None:
        """Recreate an authenticated row written before relay-set fingerprints."""
        row = store.db.execute(
            "SELECT * FROM dialogue_outbox WHERE operation_id=?", (operation_id,),
        ).fetchone()
        body = store._unseal(agent, row["local_body"])
        body["relay"] = relay_url
        with store._transaction():
            store.db.execute(
                "UPDATE dialogue_outbox SET relay=?,local_body=? WHERE seq=?",
                (relay_url, store._seal(agent, body), row["seq"]),
            )

    cases = [
        ("reordered", all_urls, list(reversed(all_urls)), all_urls, False, False),
        ("removed", all_urls, [primary_url], [primary_url], True, False),
        ("added", [primary_url], all_urls, all_urls, True, False),
        ("legacy-added", [primary_url], all_urls, all_urls, True, True),
    ]
    with tempfile.TemporaryDirectory(prefix="a4a-dialogue-relay-set-") as directory:
        for label, prepared_urls, resumed_urls, delivery_urls, changed, legacy in cases:
            dialogue_keys, peer_keys = Keys(), Keys()
            allowed = {peer_keys.pubkey_hex}
            store_path = Path(directory) / label / "sender"
            prepared_agent = Agent(prepared_urls, keys=dialogue_keys)
            with DialogueStore(
                store_path, prepared_agent.pubkey, f"relay-set-{label}",
            ) as store:
                store.activate()
                old_lease = store.acquire(
                    peer_keys.pubkey_hex, "preparing-worker", allowed)
                prepared = store.prepare_send(
                    prepared_agent, old_lease["token"], "preparing-worker", allowed,
                    f"{label}-before-change",
                    f"dialogue relay set {label} before dispatch",
                )
                assert prepared["state"] == "prepared"
                if legacy:
                    make_legacy(
                        store, prepared_agent, prepared["operation_id"], primary_url)
                assert store.release(
                    old_lease["token"], "preparing-worker", allowed,
                )["state"] == "released"

            assert not any([
                await relay_has(url, prepared["outer_id"]) for url in all_urls
            ]), f"{label} preparation reached a relay before dispatch"

            resumed_agent = Agent(resumed_urls, keys=dialogue_keys)
            async with resumed_agent:
                with DialogueStore(
                    store_path, resumed_agent.pubkey, f"relay-set-{label}",
                ) as store:
                    try:
                        store.validate_lease(
                            old_lease["token"], "preparing-worker", allowed)
                    except InboxConflict:
                        pass
                    else:
                        raise AssertionError(
                            f"{label} configuration restart retained the released lease")
                    replacement = store.acquire(
                        peer_keys.pubkey_hex, "replacement-worker", allowed)
                    assert replacement["conversation_id"] == old_lease["conversation_id"]
                    assert replacement["epoch"] > old_lease["epoch"]
                    history = store.history(
                        resumed_agent, replacement["token"],
                        "replacement-worker", allowed,
                    )
                    assert len(history["items"]) == 1
                    assert history["items"][0]["operation_id"] == prepared["operation_id"]
                    assert history["items"][0]["outer_id"] == prepared["outer_id"]
                    assert history["items"][0]["state"] == "prepared"

                    publish_calls = []
                    publish = resumed_agent.relay.publish

                    async def counted_publish(event, **kwargs):
                        publish_calls.append((event.id, dict(kwargs)))
                        return await publish(event, **kwargs)

                    resumed_agent.relay.publish = counted_publish
                    if changed:
                        try:
                            await store.dispatch(
                                resumed_agent, replacement["token"],
                                "replacement-worker", allowed,
                                prepared["operation_id"],
                            )
                        except InboxConflict as exc:
                            assert "different relay" in str(exc)
                        else:
                            raise AssertionError(
                                f"{label} relay-set change sent a prepared envelope")
                        assert publish_calls == []
                        assert not any([
                            await relay_has(url, prepared["outer_id"])
                            for url in all_urls
                        ])
                        abandoned = store.abandon(
                            resumed_agent, replacement["token"],
                            "replacement-worker", allowed,
                            prepared["operation_id"],
                        )
                        assert abandoned == {**prepared, "state": "abandoned"}
                        replacement_operation = f"{label}-after-change"
                        sent = store.prepare_send(
                            resumed_agent, replacement["token"],
                            "replacement-worker", allowed,
                            replacement_operation,
                            f"dialogue relay set {label} after explicit reprepare",
                        )
                    else:
                        sent = prepared

                    receipt = await store.dispatch(
                        resumed_agent, replacement["token"],
                        "replacement-worker", allowed, sent["operation_id"],
                    )
                    assert receipt == {**sent, "state": "relay_accepted"}
                    assert publish_calls == [(
                        sent["outer_id"], {"replay_on_reconnect": False},
                    )]
                    again = await store.dispatch(
                        resumed_agent, replacement["token"],
                        "replacement-worker", allowed, sent["operation_id"],
                    )
                    assert again == receipt and len(publish_calls) == 1
                    final_history = store.history(
                        resumed_agent, replacement["token"],
                        "replacement-worker", allowed,
                    )
                    assert final_history["items"][0]["state"] == "relay_accepted"
                    if changed:
                        assert [item["state"] for item in final_history["items"]] == [
                            "relay_accepted", "abandoned",
                        ]
                        # Even restoring the old relay set later cannot revive the
                        # abandoned envelope; the historical row is terminal.
                        old_agent = Agent(prepared_urls, keys=dialogue_keys)
                        old_agent.relay.publish = lambda *_args, **_kwargs: (_ for _ in ()).throw(
                            AssertionError("abandoned envelope was republished"))
                        closed = await store.dispatch(
                            old_agent, replacement["token"],
                            "replacement-worker", allowed,
                            prepared["operation_id"],
                        )
                        assert closed["state"] == "abandoned"
                    assert store.work(allowed) == []

            await asyncio.sleep(1.1)
            for url in all_urls:
                assert await relay_has(url, sent["outer_id"]) is (url in delivery_urls)
                if changed:
                    assert not await relay_has(url, prepared["outer_id"])

            recipient = Agent(delivery_urls, keys=peer_keys)
            with InboxStore(
                Path(directory) / label / "recipient", recipient.pubkey,
                f"relay-set-recipient-{label}",
            ) as inbox:
                receiver = InboxReceiver(
                    recipient, inbox, lambda: {dialogue_keys.pubkey_hex},
                    start_after=0, poll_seconds=5,
                )
                assert await receiver.sync_once() == 1
                for url in delivery_urls:
                    assert inbox.cursor(url)[1] == sent["outer_id"]
                claimed = inbox.claim(
                    recipient, f"relay-set-recipient-{label}",
                    {dialogue_keys.pubkey_hex},
                )
                assert claimed is not None
                assert claimed["inner_id"] == sent["inner_id"]
                assert claimed["delivery_id"] == sent["delivery_id"]
                inbox.finish(
                    claimed["seq"], claimed["lease_token"],
                    f"relay-set-recipient-{label}", "processed",
                )
                assert await receiver.sync_once() == 0
                assert inbox.status()["processed"] == inbox.status()["total"] == 1

        uncertain_cases = [
            ("unknown-removed", all_urls, [primary_url], False),
            ("unknown-added", [primary_url], all_urls, False),
            ("legacy-unknown-added", [primary_url], all_urls, True),
        ]
        for label, original_urls, changed_urls, legacy in uncertain_cases:
            dialogue_keys, peer_keys = Keys(), Keys()
            allowed = {peer_keys.pubkey_hex}
            store_path = Path(directory) / label / "sender"
            original_agent = Agent(original_urls, keys=dialogue_keys)
            async with original_agent:
                with DialogueStore(
                    store_path, original_agent.pubkey, f"relay-set-{label}",
                ) as store:
                    store.activate()
                    old_lease = store.acquire(
                        peer_keys.pubkey_hex, "uncertain-worker", allowed)
                    uncertain = store.prepare_send(
                        original_agent, old_lease["token"],
                        "uncertain-worker", allowed,
                        f"{label}-before-change",
                        f"unknown dialogue relay set {label}",
                    )
                    if legacy:
                        make_legacy(
                            store, original_agent, uncertain["operation_id"],
                            primary_url,
                        )
                    publish = original_agent.relay.publish

                    async def lose_result_after_acceptance(event, **kwargs):
                        await publish(event, **kwargs)
                        raise ConnectionError("synthetic loss after relay acceptance")

                    original_agent.relay.publish = lose_result_after_acceptance
                    try:
                        await store.dispatch(
                            original_agent, old_lease["token"],
                            "uncertain-worker", allowed,
                            uncertain["operation_id"],
                        )
                    except ConnectionError as exc:
                        assert str(exc) == "synthetic loss after relay acceptance"
                    else:
                        raise AssertionError("unknown relay-set probe kept its result")
                    assert store.history(
                        original_agent, old_lease["token"],
                        "uncertain-worker", allowed,
                    )["items"][0]["state"] == "unknown"
                    assert store.release(
                        old_lease["token"], "uncertain-worker", allowed,
                    )["state"] == "released"

            for url in all_urls:
                assert await relay_has(url, uncertain["outer_id"]) is (
                    url in original_urls)

            changed_agent = Agent(changed_urls, keys=dialogue_keys)
            with DialogueStore(
                store_path, changed_agent.pubkey, f"relay-set-{label}",
            ) as store:
                replacement = store.acquire(
                    peer_keys.pubkey_hex, "replacement-worker", allowed)
                assert replacement["conversation_id"] == old_lease["conversation_id"]
                assert replacement["epoch"] > old_lease["epoch"]
                changed_network = []
                changed_publish = changed_agent.relay.publish
                changed_query = changed_agent.relay.query_bounded

                async def forbidden_changed_publish(*args, **kwargs):
                    changed_network.append("publish")
                    raise AssertionError("changed set republished uncertain work")

                async def forbidden_changed_query(*args, **kwargs):
                    changed_network.append("query")
                    raise AssertionError("changed set queried uncertain work")

                changed_agent.relay.publish = forbidden_changed_publish
                changed_agent.relay.query_bounded = forbidden_changed_query
                try:
                    await store.dispatch(
                        changed_agent, replacement["token"],
                        "replacement-worker", allowed,
                        uncertain["operation_id"],
                    )
                except InboxConflict as exc:
                    assert "different relay" in str(exc)
                else:
                    raise AssertionError("changed set dispatched uncertain work")
                try:
                    await store.reconcile(
                        changed_agent, replacement["token"],
                        "replacement-worker", allowed,
                        uncertain["operation_id"],
                    )
                except InboxConflict as exc:
                    assert "different relay" in str(exc)
                else:
                    raise AssertionError("changed set reconciled uncertain work")
                assert changed_network == []
                try:
                    store.abandon(
                        changed_agent, replacement["token"],
                        "replacement-worker", allowed,
                        uncertain["operation_id"],
                    )
                except InboxConflict as exc:
                    assert "only a prepared operation" in str(exc)
                else:
                    raise AssertionError("unknown work was abandoned")
                try:
                    store.prepare_send(
                        changed_agent, replacement["token"],
                        "replacement-worker", allowed,
                        f"{label}-overtake", "must wait for reconciliation",
                    )
                except InboxConflict as exc:
                    assert "requires reconciliation" in str(exc)
                else:
                    raise AssertionError("new work overtook relay-set uncertainty")
                changed_agent.relay.publish = changed_publish
                changed_agent.relay.query_bounded = changed_query

            reconciliation_agent = Agent(original_urls, keys=dialogue_keys)
            async with reconciliation_agent:
                with DialogueStore(
                    store_path, reconciliation_agent.pubkey, f"relay-set-{label}",
                ) as store:
                    observed = await store.reconcile(
                        reconciliation_agent, replacement["token"],
                        "replacement-worker", allowed,
                        uncertain["operation_id"],
                    )
                    assert observed == {**uncertain, "state": "relay_observed"}
                    no_republish = []

                    async def forbidden_republish(*args, **kwargs):
                        no_republish.append(True)
                        raise AssertionError("reconciled work was republished")

                    reconciliation_agent.relay.publish = forbidden_republish
                    assert await store.dispatch(
                        reconciliation_agent, replacement["token"],
                        "replacement-worker", allowed,
                        uncertain["operation_id"],
                    ) == observed
                    assert no_republish == []

            async with changed_agent:
                with DialogueStore(
                    store_path, changed_agent.pubkey, f"relay-set-{label}",
                ) as store:
                    next_operation = store.prepare_send(
                        changed_agent, replacement["token"],
                        "replacement-worker", allowed,
                        f"{label}-after-reconcile",
                        f"new dialogue work after {label} reconciliation",
                    )
                    sent = await store.dispatch(
                        changed_agent, replacement["token"],
                        "replacement-worker", allowed,
                        next_operation["operation_id"],
                    )
                    assert sent == {
                        **next_operation, "state": "relay_accepted",
                    }
                    states = [item["state"] for item in store.history(
                        changed_agent, replacement["token"],
                        "replacement-worker", allowed,
                    )["items"]]
                    assert states == ["relay_accepted", "relay_observed"]
                    assert store.work(allowed) == []

            await asyncio.sleep(1.1)
            for url in all_urls:
                assert await relay_has(url, uncertain["outer_id"]) is (
                    url in original_urls)
                assert await relay_has(url, sent["outer_id"]) is (
                    url in changed_urls)

            recipient = Agent(all_urls, keys=peer_keys)
            with InboxStore(
                Path(directory) / label / "recipient", recipient.pubkey,
                f"relay-set-recipient-{label}",
            ) as inbox:
                receiver = InboxReceiver(
                    recipient, inbox, lambda: {dialogue_keys.pubkey_hex},
                    start_after=0, poll_seconds=5,
                )
                assert await receiver.sync_once() == 2
                contents = set()
                for _ in range(2):
                    claimed = inbox.claim(
                        recipient, f"relay-set-recipient-{label}",
                        {dialogue_keys.pubkey_hex},
                    )
                    assert claimed is not None
                    contents.add(claimed["content"])
                    inbox.finish(
                        claimed["seq"], claimed["lease_token"],
                        f"relay-set-recipient-{label}", "processed",
                    )
                assert contents == {
                    f"unknown dialogue relay set {label}",
                    f"new dialogue work after {label} reconciliation",
                }
                assert await receiver.sync_once() == 0
                assert inbox.status()["processed"] == inbox.status()["total"] == 2
    print(
        "PASS dialogue relay-set changes: prepared work handled reorder, removal and "
        "addition including legacy rows; unknown fresh and legacy work rejected changed-"
        "set send and readback before network, reconciled only on the original set "
        "without republish, then admitted new work",
        flush=True,
    )


async def verify_multi_relay_failover(
    *, image: str, primary_container: str, primary_url: str, owner: Keys,
) -> None:
    """Prove bounded reads, honest copy counts, deduplication, and rejoin locally."""
    secondary_container = f"{primary_container}-failover"
    secondary_volume = f"{secondary_container}-db"
    volume_created = container_created = paused = False
    try:
        await asyncio.to_thread(docker, "volume", "create", secondary_volume)
        volume_created = True
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            secondary_port = reservation.getsockname()[1]
        await asyncio.to_thread(
            docker, "create", "--pull", "never", "--name", secondary_container,
            "--memory", "256m", "--cpus", "2",
            "-p", f"127.0.0.1:{secondary_port}:8080",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--health-interval", "1s", "--health-timeout", "5s",
            "--health-start-period", "1s",
            "-v", f"{secondary_volume}:/usr/src/app/db",
            "-v", f"{ROOT / 'relay' / 'config.toml'}:/usr/src/app/config.toml:ro",
            image,
        )
        container_created = True
        await asyncio.to_thread(docker, "start", secondary_container)
        address = await asyncio.to_thread(docker, "port", secondary_container, "8080/tcp")
        assert address.startswith("127.0.0.1:"), address
        secondary_base, secondary_url = "http://" + address, "ws://" + address
        await asyncio.to_thread(wait_ready, secondary_base)
        await asyncio.to_thread(wait_container_healthy, secondary_container)

        baseline = Event(kind=1, content="two-relay baseline").sign(owner)
        fanout = FanOutRelayClient([primary_url, secondary_url])
        fanout.read_deadline = 2.0
        await fanout.connect()
        try:
            accepted = await fanout.publish(
                baseline, min_accepted=2, replay_on_reconnect=False)
            assert accepted == 2
            merged = await fanout.query_bounded({"ids": [baseline.id]}, max_events=10)
            assert [event.id for event in merged.events] == [baseline.id]
            assert merged.relays_responded == 2

            # Pausing leaves the TCP connection established but prevents a response.
            # This exercises the global fan-out deadline rather than the fast
            # connection-refused path produced by a stopped container.
            await asyncio.to_thread(docker, "pause", secondary_container)
            paused = True
            started = time.monotonic()
            timed_read = await fanout.query_bounded(
                {"ids": [baseline.id]}, max_events=10)
            timeout_seconds = time.monotonic() - started
            assert [event.id for event in timed_read.events] == [baseline.id]
            assert timed_read.relays_responded == 1
            assert fanout.read_deadline * 0.75 <= timeout_seconds
            assert timeout_seconds < fanout.read_deadline + 1.0, timeout_seconds
        finally:
            if paused:
                await asyncio.to_thread(docker, "unpause", secondary_container)
                paused = False
            await fanout.aclose()
        await asyncio.to_thread(
            wait_container_healthy, secondary_container, allow_recovery=True)

        fanout = FanOutRelayClient([primary_url, secondary_url])
        fanout.read_deadline = 2.0
        await fanout.connect()
        try:
            recovered_read = await fanout.query_bounded(
                {"ids": [baseline.id]}, max_events=10)
            assert [event.id for event in recovered_read.events] == [baseline.id]
            assert recovered_read.relays_responded == 2

            await asyncio.to_thread(
                docker, "kill", "--signal", "KILL", secondary_container)
            exit_code = await asyncio.to_thread(
                docker, "inspect", "--format", "{{.State.ExitCode}}", secondary_container)
            assert exit_code == "137", f"failover termination returned exit code {exit_code}"

            started = time.monotonic()
            degraded_read = await fanout.query_bounded(
                {"ids": [baseline.id]}, max_events=10)
            degraded_seconds = time.monotonic() - started
            assert [event.id for event in degraded_read.events] == [baseline.id]
            assert degraded_read.relays_responded == 1
            assert degraded_seconds < fanout.read_deadline + 1.0, degraded_seconds

            degraded = Event(kind=1, content="write during relay outage").sign(owner)
            accepted = await fanout.publish(
                degraded, min_accepted=1, replay_on_reconnect=False)
            assert accepted == 1
            strict = Event(kind=1, content="strict write during relay outage").sign(owner)
            try:
                await fanout.publish(strict, min_accepted=2, replay_on_reconnect=False)
            except InsufficientCopies as exc:
                assert exc.accepted == 1 and exc.required == 2
            else:
                raise AssertionError("two-copy requirement passed while one relay was down")
        finally:
            await fanout.aclose()

        await asyncio.to_thread(docker, "start", secondary_container)
        address = await asyncio.to_thread(
            docker, "port", secondary_container, "8080/tcp")
        assert address.startswith("127.0.0.1:"), address
        secondary_base, secondary_url = "http://" + address, "ws://" + address
        await asyncio.to_thread(wait_ready, secondary_base)
        await asyncio.to_thread(wait_container_healthy, secondary_container)
        _, stored = await asyncio.to_thread(
            get, secondary_base, "/v1/event/" + baseline.id)
        assert stored["id"] == baseline.id

        rejoined = FanOutRelayClient([primary_url, secondary_url])
        rejoined.read_deadline = 2.0
        await rejoined.connect()
        try:
            accepted = await rejoined.publish(
                degraded, min_accepted=2, replay_on_reconnect=False)
            assert accepted == 2
            merged = await rejoined.query_bounded({"ids": [degraded.id]}, max_events=10)
            assert [event.id for event in merged.events] == [degraded.id]
            assert merged.relays_responded == 2
        finally:
            await rejoined.aclose()
        for base in ("http://" + primary_url.removeprefix("ws://"), secondary_base):
            _, stored = await asyncio.to_thread(get, base, "/v1/event/" + degraded.id)
            assert stored["id"] == degraded.id
        await verify_multi_relay_inbox(
            primary_url=primary_url, secondary_url=secondary_url,
            secondary_container=secondary_container, owner=owner,
        )
        await verify_dialogue_restart(
            primary_url=primary_url, secondary_url=secondary_url,
        )
        await verify_incoming_dialogue_restart(
            primary_url=primary_url, secondary_url=secondary_url,
        )
        await verify_prepared_dialogue_restart(
            primary_url=primary_url, secondary_url=secondary_url,
        )
        await verify_dialogue_relay_set_changes(
            primary_url=primary_url, secondary_url=secondary_url,
        )
        print(
            "PASS two-relay failover: 2/2 initial copies, one merged event, "
            f"1/2 timeout read in {timeout_seconds:.2f}s, "
            f"1/2 stopped-node read in {degraded_seconds:.2f}s, honest 1/2 write, "
            "2/2 copies after rejoin",
            flush=True,
        )
    except BaseException:
        if container_created:
            print(
                await asyncio.to_thread(docker, "logs", "--tail", "30", secondary_container),
                file=sys.stderr,
            )
        raise
    finally:
        try:
            if paused and container_created:
                await asyncio.to_thread(docker, "unpause", secondary_container)
            if container_created:
                await asyncio.to_thread(docker, "rm", "-f", secondary_container)
        finally:
            if volume_created:
                await asyncio.to_thread(docker, "volume", "rm", secondary_volume)


async def restore_backup(
    *, image: str, source_container: str, source_volume: str, backup_volume: str,
    destroy_source: bool, cleanup: dict[str, object],
    confirmed: set[str], owner: Keys, refused,
) -> None:
    backup = "/usr/src/app/backup/recovery-backup.db"
    await asyncio.to_thread(
        sqlite, source_container, "/usr/src/app/db/nostr.db", f".backup '{backup}'", backup=True,
    )
    await asyncio.to_thread(verify_sqlite_integrity, source_container, backup)

    if destroy_source:
        await asyncio.to_thread(docker, "rm", "-f", source_container)
        cleanup["container_created"] = False
        await asyncio.to_thread(docker, "volume", "rm", source_volume)
        cleanup["database_volume"] = None

    restore_volume = f"{source_container}-restore-db"
    restore_container = f"{source_container}-restore"
    volume_created = container_created = False
    try:
        await asyncio.to_thread(docker, "volume", "create", restore_volume)
        volume_created = True
        await asyncio.to_thread(
            docker, "run", "--rm", "--pull", "never", "--network", "none",
            "--read-only", "--memory", "128m", "--cpus", "1", "--pids-limit", "64",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "-v", f"{backup_volume}:/source:ro",
            "-v", f"{restore_volume}:/usr/src/app/db",
            "--entrypoint", "cp", diagnostic_image(image),
            "/source/recovery-backup.db", "/usr/src/app/db/nostr.db",
        )
        await asyncio.to_thread(
            docker, "create", "--pull", "never", "--name", restore_container,
            "--memory", "256m", "--cpus", "2", "-p", "127.0.0.1::8080",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--health-interval", "1s", "--health-timeout", "5s",
            "--health-start-period", "1s",
            "-v", f"{restore_volume}:/usr/src/app/db",
            "-v", f"{ROOT / 'relay' / 'config.toml'}:/usr/src/app/config.toml:ro",
            image,
        )
        container_created = True
        await asyncio.to_thread(docker, "start", restore_container)
        address = await asyncio.to_thread(docker, "port", restore_container, "8080/tcp")
        assert address.startswith("127.0.0.1:"), address
        restored_base, restored_url = "http://" + address, "ws://" + address
        await asyncio.to_thread(wait_ready, restored_base)
        await asyncio.to_thread(wait_container_healthy, restore_container)
        await asyncio.to_thread(
            verify_sqlite_integrity, restore_container, "/usr/src/app/db/nostr.db")

        for event_id in confirmed:
            _, stored = await asyncio.to_thread(
                get, restored_base, "/v1/event/" + event_id)
            assert stored["id"] == event_id
        async with RelayClient(restored_url) as relay:
            await refused(relay)
            marker = Event(
                kind=31021, tags=[["d", "restored-backup"]],
                content="write after backup restore",
            ).sign(owner)
            await relay.publish(marker)
        _, stored = await asyncio.to_thread(get, restored_base, "/v1/event/" + marker.id)
        assert stored["id"] == marker.id
        await asyncio.sleep(1.1)
        restored_history, _ = await history_ids(restored_base)
        assert confirmed | {marker.id} <= restored_history
        await verify_multi_relay_failover(
            image=image, primary_container=restore_container,
            primary_url=restored_url, owner=owner,
        )
        memory = await asyncio.to_thread(
            docker, "stats", "--no-stream", "--format", "memory={{.MemUsage}}",
            restore_container,
        )
        print(
            f"PASS backup restore: {len(confirmed)} durable events restored, "
            f"revocation enforced, post-restore write accepted, {memory}",
            flush=True,
        )
    except BaseException:
        if container_created:
            print(
                await asyncio.to_thread(docker, "logs", "--tail", "30", restore_container),
                file=sys.stderr,
            )
        raise
    finally:
        try:
            if container_created:
                await asyncio.to_thread(docker, "rm", "-f", restore_container)
        finally:
            if volume_created:
                await asyncio.to_thread(docker, "volume", "rm", restore_volume)


async def check(
    url: str, base: str, container: str, database: str,
    *, image: str | None = None, source_volume: str | None = None,
    backup_volume: str | None = None, destroy_source: bool = False,
    cleanup: dict[str, object] | None = None,
    notary_check: Callable[[], object] | None = None,
) -> None:
    owner, agent = Keys(), Keys()
    delegation = create_delegation(owner, agent.pubkey_hex, "local-check", int(time.time()) + 3600)

    def intent(label: str) -> Event:
        return Event(kind=31002, tags=[["d", uuid.uuid4().hex], ["delegation", delegation.id]],
                     content=label).sign(agent)

    async def refused(relay: RelayClient) -> None:
        try:
            await relay.publish(intent("after revocation"))
        except RelayError as exc:
            assert "revoked" in str(exc), str(exc)
        else:
            raise AssertionError("revoked agent was accepted")

    async with RelayClient(url) as relay:
        await relay.publish(delegation)
        await relay.publish(intent("positive control before revocation"))
        revoked = create_revocation(owner, delegation)
        revoked.tags.append(["d", agent.pubkey_hex])
        revoked.sign(owner)
        await relay.publish(revoked)
        _, stored = await asyncio.to_thread(get, base, "/v1/event/" + revoked.id)
        assert stored["id"] == revoked.id, "ACK without durable revocation"
        await refused(relay)

        newer = revoked.model_copy(deep=True)
        newer.created_at += 1
        newer.sign(owner)
        await relay.publish(newer)
        _, stored = await asyncio.to_thread(get, base, "/v1/event/" + newer.id)
        assert stored["id"] == newer.id
        try:
            await asyncio.to_thread(get, base, "/v1/event/" + revoked.id)
        except urllib.error.HTTPError as exc:
            assert exc.code == 404
        else:
            raise AssertionError("old revocation was not replaced")
    print("PASS duplicate d: ACK, reread, replacement and warm-cache rejection", flush=True)

    await asyncio.to_thread(docker, "restart", container)
    address = await asyncio.to_thread(docker, "port", container, "8080/tcp")
    assert address.startswith("127.0.0.1:"), address
    base, url = "http://" + address, "ws://" + address
    print(f"LOCAL RESTART: {url}", flush=True)
    await asyncio.to_thread(wait_ready, base)
    _, stored = await asyncio.to_thread(get, base, "/v1/event/" + newer.id)
    assert stored["id"] == newer.id
    async with RelayClient(url) as relay:
        await refused(relay)
        expected = {delegation.id, newer.id}
        for i in range(24):
            event = Event(kind=31021, tags=[["d", str(i)]], content="x" * 120_000).sign(owner)
            await relay.publish(event)
            expected.add(event.id)
    print("PASS restart: revocation stored and revoked agent still rejected", flush=True)

    # Paging deliberately waits until the reception second has closed.
    await asyncio.sleep(1.1)
    seen, sizes = await history_ids(base)
    assert seen == expected, (len(seen), len(expected))
    assert len(sizes) >= 2, "test failed to cross the byte limit"
    print(f"PASS bounded history: {len(seen)} events, {len(sizes)} pages, largest {max(sizes)} bytes")
    if notary_check is not None:
        # Notary restart/paging expects this exact 26-event corpus. The durability
        # drill below adds a nondeterministic number of signed historical events.
        await asyncio.to_thread(notary_check)

    # A crash test must distinguish acknowledged durability from an in-flight
    # outcome. Several independent clients keep write pressure on SQLite; once
    # the first ACK arrives, SIGKILL stops the process without a graceful flush.
    # Every ACKed event must survive. An event whose ACK raced the kill may exist
    # or not exist, and neither result is data loss.
    control = Event(kind=31021, tags=[["d", "crash-control"]], content="durable control").sign(owner)
    async with RelayClient(url) as relay:
        await relay.publish(control)
    _, stored = await asyncio.to_thread(get, base, "/v1/event/" + control.id)
    assert stored["id"] == control.id
    expected.add(control.id)

    start_writes, first_ack = asyncio.Event(), asyncio.Event()
    relay_paused = asyncio.Event()
    wire_sent = threading.Event()
    post_pause_attempts: set[str] = set()
    wire_sent_ids: set[str] = set()
    wire_pending_at_kill: set[str] = set()
    crash_clients: list[RelayClient] = []
    loop = asyncio.get_running_loop()
    kill_signal = threading.Event()
    kill_errors: list[BaseException] = []
    ready: asyncio.Queue[None] = asyncio.Queue()
    attempted: set[str] = set()
    acknowledged: set[str] = set()

    def kill_after_first_ack() -> None:
        if not kill_signal.wait(timeout=10):
            kill_errors.append(RuntimeError("crash-load publisher produced no ACK"))
            return
        try:
            # Pause only our disposable relay. Confirm it cannot process a new
            # unique publication before observing its pending Nostr OK future.
            docker("pause", container)
            paused = docker("inspect", "--format", "{{.State.Paused}}", container)
            if paused != "true":
                raise RuntimeError("crash fixture relay pause was not confirmed")
            loop.call_soon_threadsafe(relay_paused.set)
            if not wire_sent.wait(timeout=10):
                raise RuntimeError("paused relay received no confirmed wire submission")
            wire_pending_at_kill.update(
                event_id for client in crash_clients
                for event_id, future in list(client._pending_ok.items())
                if event_id in wire_sent_ids and not future.done())
            if not wire_pending_at_kill or wire_pending_at_kill & acknowledged:
                raise RuntimeError("crash fixture has no unacknowledged wire submission at kill")
            docker("kill", "--signal", "KILL", container)
        except BaseException as exc:
            kill_errors.append(exc)

    killer = threading.Thread(target=kill_after_first_ack, daemon=True)
    killer.start()

    class CrashRelayClient(RelayClient):
        async def _safe_send(self, payload) -> None:
            await super()._safe_send(payload)
            if (payload[0] == "EVENT" and payload[1]["id"] in post_pause_attempts):
                event_id = payload[1]["id"]
                future = self._pending_ok.get(event_id)
                if future is not None and not future.done():
                    wire_sent_ids.add(event_id)
                    wire_sent.set()

    async def writer(worker: int) -> None:
        try:
            async with CrashRelayClient(url) as relay:
                crash_clients.append(relay)
                ready.put_nowait(None)
                await start_writes.wait()
                # At most one acknowledged control and one post-pause attempt
                # per client. Pausing makes the pending publication deterministic
                # without a high-volume batch or a Docker startup timing race.
                for index in range(2):
                    if index:
                        await asyncio.wait_for(relay_paused.wait(), timeout=10)
                    event = Event(
                        kind=31021,
                        tags=[["d", f"crash-{worker}-{index}"]],
                        content="z" * 120_000,
                    ).sign(owner)
                    attempted.add(event.id)
                    if index:
                        post_pause_attempts.add(event.id)
                    await relay.publish(event)
                    acknowledged.add(event.id)
                    kill_signal.set()
                    first_ack.set()
        except (OSError, RelayError):
            return

    writers = [asyncio.create_task(writer(number)) for number in range(8)]
    for _ in writers:
        await asyncio.wait_for(ready.get(), timeout=10)
    start_writes.set()
    await asyncio.wait_for(first_ack.wait(), timeout=10)
    await asyncio.to_thread(killer.join, 10)
    assert not killer.is_alive(), "forced-termination helper did not finish"
    if kill_errors:
        raise RuntimeError("forced termination failed") from kill_errors[0]
    exit_code = await asyncio.to_thread(
        docker, "inspect", "--format", "{{.State.ExitCode}}", container)
    assert exit_code == "137", f"forced termination returned exit code {exit_code}"
    await asyncio.wait_for(asyncio.gather(*writers), timeout=10)
    assert acknowledged < attempted, "forced termination did not interrupt active publishers"
    assert wire_pending_at_kill, "forced termination lacked a confirmed pending wire publication"
    assert wire_pending_at_kill <= attempted and not wire_pending_at_kill & acknowledged

    await asyncio.to_thread(docker, "start", container)
    address = await asyncio.to_thread(docker, "port", container, "8080/tcp")
    assert address.startswith("127.0.0.1:"), address
    base, url = "http://" + address, "ws://" + address
    await asyncio.to_thread(wait_ready, base)
    await asyncio.to_thread(verify_sqlite_integrity, container, database)

    confirmed = expected | acknowledged
    for event_id in confirmed:
        _, stored = await asyncio.to_thread(get, base, "/v1/event/" + event_id)
        assert stored["id"] == event_id
    async with RelayClient(url) as relay:
        await refused(relay)
        recovery = Event(
            kind=31021, tags=[["d", "post-crash"]], content="post-crash write"
        ).sign(owner)
        await relay.publish(recovery)
    _, stored = await asyncio.to_thread(get, base, "/v1/event/" + recovery.id)
    assert stored["id"] == recovery.id
    confirmed.add(recovery.id)

    await asyncio.sleep(1.1)
    recovered, _ = await history_ids(base)
    assert confirmed <= recovered, (len(confirmed), len(recovered))
    uncertain = recovered - confirmed
    print(
        f"PASS forced termination: SQLite ok, {len(acknowledged)}/{len(attempted)} "
        "crash-load attempts ACKed and durable, "
        f"{len(wire_pending_at_kill)} confirmed pre-kill wire publications pending, "
        f"{len(uncertain)} in-flight outcomes retained, post-crash write accepted",
        flush=True,
    )
    if image and source_volume and backup_volume and cleanup is not None:
        await restore_backup(
            image=image, source_container=container, source_volume=source_volume,
            backup_volume=backup_volume, destroy_source=destroy_source, cleanup=cleanup,
            confirmed=confirmed, owner=owner, refused=refused,
        )


def require_source_relay_binary() -> None:
    """Refuse to start when the shared build volume has no relay binary.

    The binary is not a host file: it lives at /build/debug/nostr-rs-relay in
    the Docker volume a4a-relay-target. relay/dev.sh deletes that binary when
    another checkout built last, and docker start then reports only an OCI
    exec failure. Exit code 1 from ``test -x`` is that absence. Any other
    docker failure stays a docker failure.
    """
    try:
        docker(
            "run", "--rm", "--pull", "never", "--network", "none",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "-v", "a4a-relay-target:/build:ro",
            "--entrypoint", "/usr/bin/test", "a4a-relay-builder",
            "-x", "/build/debug/nostr-rs-relay",
        )
    except subprocess.CalledProcessError as exc:
        if exc.returncode != 1:
            raise
        raise SystemExit(
            "relay binary is missing from the a4a-relay-target volume; "
            "build it from this checkout with `bash relay/dev.sh build`."
        ) from exc


def main(argv: list[str] | None = None) -> None:
    global DIAGNOSTICS
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-pilot-python", help="Python with the MCP test dependencies")
    parser.add_argument("--image", help="Test this prebuilt relay image instead of the builder volume")
    parser.add_argument("--diagnostic-image", help="Local runtime-tools image for SQLite/fixture tools")
    parser.add_argument("--relay-only", action="store_true", help="Skip the separate notary check")
    parser.add_argument("--notary-image", default="a4a-notary:0.1.4",
                        help="Local notary image for the pre-crash history acceptance check")
    parser.add_argument("--notary-test-packages", type=Path,
                        default=Path(sysconfig.get_path("purelib")),
                        help="Host site-packages containing pure-Python pytest/pytest-asyncio tooling")
    args = parser.parse_args(argv if argv is not None else [])
    for option in ("image", "diagnostic_image", "notary_image"):
        value = getattr(args, option)
        if value and (value.startswith("-") or len(value) > 255 or any(c.isspace() for c in value)):
            parser.error(f"--{option.replace('_', '-')} must be a bounded Docker image reference without whitespace")
    if args.diagnostic_image and not args.image:
        parser.error("--diagnostic-image requires --image")
    if not args.notary_test_packages.is_dir():
        parser.error("--notary-test-packages must be an existing directory")
    args.notary_test_packages = args.notary_test_packages.resolve()
    name = f"a4a-safety-check-{os.getpid()}-{uuid.uuid4().hex[:8]}"
    DIAGNOSTICS = FixtureDiagnostics(args.diagnostic_image, name) if args.diagnostic_image else None
    database_volume = f"{name}-db" if args.image else None
    backup_volume = f"{name}-backup" if args.image else None
    cleanup: dict[str, object] = {
        "container_created": False,
        "database_volume": None,
        "backup_volume": None,
    }
    try:
        if not args.image:
            require_source_relay_binary()
        if database_volume:
            docker("volume", "create", database_volume)
            cleanup["database_volume"] = database_volume
        if backup_volume:
            docker("volume", "create", backup_volume)
            cleanup["backup_volume"] = backup_volume
            # Docker creates a new named volume as root. Prepare only this empty,
            # uniquely owned volume so the unprivileged relay process can write
            # the online SQLite backup without granting the relay extra rights.
            docker(
                "run", "--rm", "--pull", "never", "--network", "none",
                "--read-only", "--memory", "128m", "--cpus", "1", "--pids-limit", "64",
                "--user", "root", "--cap-drop", "ALL", "--cap-add", "CHOWN",
                "--security-opt", "no-new-privileges",
                "-v", f"{backup_volume}:/backup",
                "--entrypoint", "chown", diagnostic_image(args.image),
                "appuser:appuser", "/backup",
            )
        create = [
            "create", "--pull", "never", "--name", name, "--memory", "256m", "--cpus", "2",
            "-p", "127.0.0.1::8080", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
        ]
        if args.image:
            create.extend([
                "--health-interval", "1s", "--health-timeout", "5s", "--health-start-period", "1s",
                "-v", f"{ROOT / 'relay' / 'config.toml'}:/usr/src/app/config.toml:ro",
                "-v", f"{database_volume}:/usr/src/app/db",
                "-v", f"{backup_volume}:/usr/src/app/backup",
                args.image,
            ])
        else:
            create.extend([
                "-v", "a4a-relay-target:/build:ro",
                "-v", f"{ROOT / 'relay' / 'config.toml'}:/check.toml:ro",
                "--entrypoint", "/build/debug/nostr-rs-relay", "a4a-relay-builder",
                "--config", "/check.toml", "--db", "/tmp",
            ])
        docker(*create)
        cleanup["container_created"] = True
        docker("start", name)
        address = docker("port", name, "8080/tcp")
        assert address.startswith("127.0.0.1:"), address
        base, url = "http://" + address, "ws://" + address
        wait_ready(base)
        _, info = get(base, "/v1/health")
        if args.image:
            wait_container_healthy(name)
        source = f"release image {args.image}" if args.image else "source build"
        print(f"LOCAL {source}: {name}, {url}, health={info}; no production access", flush=True)
        if args.private_pilot_python:
            env = {key: value for key, value in os.environ.items() if not key.startswith("PYTEST_")}
            env.update(A4A_LOCAL_PRIVATE_PILOT_RELAY=url, PYTHONDONTWRITEBYTECODE="1",
                       PYTEST_DISABLE_PLUGIN_AUTOLOAD="1")
            with tempfile.TemporaryDirectory(prefix="a4a-private-pilot-") as directory:
                report = Path(directory) / "result.xml"
                subprocess.run(
                    [args.private_pilot_python, "-X", "utf8", "-B", "-m", "pytest", "-q",
                     "-o", "addopts=", "-p", "pytest_asyncio.plugin", "-p", "no:cacheprovider",
                     f"--junitxml={report}",
                     "tests/test_private_pilot.py::test_private_pilot_on_disposable_relay"],
                    cwd=ROOT / "mcp-server", check=True, timeout=120, env=env)
                check_pilot_report(report)
            return
        database = "/usr/src/app/db/nostr.db" if args.image else "/tmp/nostr.db"
        asyncio.run(check(
            url, base, name, database, image=args.image, source_volume=database_volume,
            backup_volume=backup_volume, destroy_source=bool(args.image and args.relay_only),
            cleanup=cleanup,
            notary_check=None if args.relay_only else lambda: run_notary_history_check(
                name, image=args.notary_image, packages=args.notary_test_packages),
        ))
        if args.image and cleanup["container_created"]:
            wait_container_healthy(name)
        if args.relay_only:
            if cleanup["container_created"]:
                print(docker("stats", "--no-stream", "--format", "memory={{.MemUsage}}", name))
            return
        print(docker("stats", "--no-stream", "--format", "memory={{.MemUsage}}", name))
    except BaseException:
        if cleanup["container_created"]:
            print(docker("logs", "--tail", "30", name), file=sys.stderr)
        raise
    finally:
        try:
            if cleanup["container_created"]:
                docker("rm", "-f", name)
        finally:
            try:
                if cleanup["database_volume"]:
                    docker("volume", "rm", str(cleanup["database_volume"]))
            finally:
                if cleanup["backup_volume"]:
                    docker("volume", "rm", str(cleanup["backup_volume"]))


if __name__ == "__main__":
    main(sys.argv[1:])
