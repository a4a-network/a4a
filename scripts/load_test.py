"""Load-test a relay to measure what it actually sustains.

WHY. Earlier capacity figures (the 2026-08-28 cost model summarized in specification
section 2.8) derive from measured event sizes. That model answers "how much traffic" but
not "how many connections," "how much memory per connection," or "where degradation
begins." Only measurement answers those questions.

WHAT IT DOES:
  1. Open N concurrent connections. Each first grants itself an owner mandate (kind 31000)
     because since 2026-08-29 the relay rejects agent events without one; the original
     script would otherwise receive zero accepted events (verified 2026-09-04).
  2. Publish M signed events per connection, or `--rate` events per second for
     `--duration` seconds, and measure OK-response latency.
  3. Hold live subscriptions on `--subscribers` separate connections and measure delivery
     latency from send to receive.
  4. Capture relay metrics before and after, plus container memory when requested.

USAGE (the relay must be running; NEVER target production):

    python scripts/load_test.py --relay ws://localhost:8083 --connections 100 --events 20
    python scripts/load_test.py --relay ws://localhost:8083 --connections 50 --duration 300 --rate 1 \\
        --container a4a-relay-test

The report uses ASCII-friendly English and is also written to a file.
"""
import argparse
import asyncio
import json
import statistics
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sdk-python"))

import websockets  # noqa: E402

from a4a.delegation import create_delegation  # noqa: E402
from a4a.event import Event  # noqa: E402
from a4a.keys import Keys  # noqa: E402

TEST_KIND = 31002  # Ordinary intent, processed through the relay's standard path.
MANDATE_SECONDS = 2 * 3600


def _event(keys: Keys, i: int, delegation_id: str, mark: str) -> Event:
    ev = Event(kind=TEST_KIND,
               tags=[["d", f"load-{keys.pubkey_hex[:8]}-{i}"],
                     ["t", "a4a:cat:development"],
                     ["delegation", delegation_id],
                     ["expiration", str(int(time.time()) + 3600)]],
               content=f"load test {mark} {i}")
    return ev.sign(keys)


async def _metrics(relay_http: str) -> dict:
    """Snapshot relay metrics, or return an empty dict when /metrics is unavailable."""
    try:
        import urllib.request
        with urllib.request.urlopen(relay_http + "/metrics", timeout=5) as r:
            body = r.read().decode("utf-8", "replace")
    except Exception:
        return {}
    out = {}
    for line in body.splitlines():
        if line.startswith("#") or " " not in line:
            continue
        name, _, value = line.rpartition(" ")
        try:
            out[name] = float(value)
        except ValueError:
            pass
    return out


def _container_memory_mb(container: str) -> float | None:
    try:
        raw = subprocess.check_output(
            ["docker", "stats", "--no-stream", "--format", "{{.MemUsage}}", container],
            text=True, timeout=20).strip()
        import re
        m = re.match(r"\s*([0-9.]+)\s*([KMG]i?B)", raw)     # '46.37MiB / 125.7GiB'
        if not m:
            return None
        value, unit = float(m.group(1)), m.group(2)
        return value / 1024 if unit.startswith("K") else value * 1024 if unit.startswith("G") else value
    except Exception:
        return None


async def _publish(ws, ev: Event, timeout: float = 30) -> tuple[bool, float, str]:
    started = time.perf_counter()
    await ws.send(json.dumps(["EVENT", ev.model_dump()]))
    while True:
        reply = json.loads(await asyncio.wait_for(ws.recv(), timeout=timeout))
        if reply[0] == "OK" and reply[1] == ev.id:
            return bool(reply[2] is True), time.perf_counter() - started, (reply[3] if len(reply) > 3 else "")


async def _worker(url: str, events: int, duration: float, rate: float, results: list,
                  mark: str, sent_at: dict) -> None:
    owner, keys = Keys(), Keys()
    started = time.perf_counter()
    try:
        async with websockets.connect(url, open_timeout=30, close_timeout=5) as ws:
            connected = time.perf_counter()
            deleg = create_delegation(owner, keys.pubkey_hex, "load", int(time.time()) + MANDATE_SECONDS)
            ok, _, reason = await _publish(ws, deleg)
            if not ok:
                results.append({"error": "mandate rejected: " + reason[:60]})
                return
            accepted, rejected, latencies, reasons = 0, 0, [], {}
            deadline = connected + duration if duration else None
            i = 0
            while (deadline is None and i < events) or (deadline is not None and time.perf_counter() < deadline):
                ev = _event(keys, i, deleg.id, mark)
                sent_at[ev.id] = time.perf_counter()
                try:
                    ok, dt, reason = await _publish(ws, ev)
                except (asyncio.TimeoutError, json.JSONDecodeError, IndexError):
                    rejected += 1
                    reasons["no OK within timeout"] = reasons.get("no OK within timeout", 0) + 1
                    i += 1
                    continue
                if ok:
                    accepted += 1
                    latencies.append(dt)
                else:
                    rejected += 1
                    reasons[reason[:50]] = reasons.get(reason[:50], 0) + 1
                i += 1
                if deadline is not None and rate:
                    await asyncio.sleep(max(0.0, 1.0 / rate - dt))
            results.append({"connect": connected - started, "accepted": accepted, "rejected": rejected,
                            "latencies": latencies, "reasons": reasons,
                            "total": time.perf_counter() - started})
    except Exception as e:
        results.append({"error": type(e).__name__ + ": " + str(e)[:80]})


async def _subscriber(url: str, mark: str, stop: asyncio.Event, sent_at: dict, seen: dict) -> None:
    """Subscribe to our events; latency is receive time minus send time."""
    try:
        async with websockets.connect(url, open_timeout=30, close_timeout=5) as ws:
            await ws.send(json.dumps(["REQ", "load", {"kinds": [TEST_KIND], "since": int(time.time()) - 5}]))
            while not stop.is_set():
                try:
                    msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=1))
                except asyncio.TimeoutError:
                    continue
                if msg[0] == "EVENT" and mark in msg[2].get("content", ""):
                    eid = msg[2]["id"]
                    if eid in sent_at and eid not in seen:
                        seen[eid] = time.perf_counter() - sent_at[eid]
    except Exception as e:  # noqa: BLE001 - subscriber is auxiliary
        seen["__error__"] = str(e)[:80]


def _pct(values: list, p: float) -> float:
    if not values:
        return float("nan")
    values = sorted(values)
    return values[min(len(values) - 1, max(0, int(len(values) * p) - 1))]


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--relay", default="ws://localhost:8080")
    ap.add_argument("--connections", type=int, default=100)
    ap.add_argument("--events", type=int, default=10, help="events per connection in count mode")
    ap.add_argument("--duration", type=float, default=0, help="seconds per connection in duration mode")
    ap.add_argument("--rate", type=float, default=1.0, help="events per second per connection with --duration")
    ap.add_argument("--subscribers", type=int, default=3, help="connections holding live subscriptions")
    ap.add_argument("--container", default=None, help="container name for memory measurement")
    ap.add_argument("--report", default="load-test-report.txt")
    args = ap.parse_args()
    if "eu1.a4a.network" in args.relay:
        print("refusing to load-test the production relay")
        return 2

    http = args.relay.replace("ws://", "http://").replace("wss://", "https://")
    before = await _metrics(http)
    mem_before = _container_memory_mb(args.container) if args.container else None
    mark = f"run-{int(time.time())}"
    sent_at: dict = {}
    seen: dict = {}
    stop = asyncio.Event()
    subs = [asyncio.create_task(_subscriber(args.relay, mark, stop, sent_at, seen))
            for _ in range(args.subscribers)]
    await asyncio.sleep(0.5)

    results: list = []
    started = time.perf_counter()
    await asyncio.gather(*[_worker(args.relay, args.events, args.duration, args.rate, results, mark, sent_at)
                           for _ in range(args.connections)])
    elapsed = time.perf_counter() - started
    await asyncio.sleep(1.0)
    stop.set()
    await asyncio.gather(*subs, return_exceptions=True)

    after = await _metrics(http)
    mem_after = _container_memory_mb(args.container) if args.container else None

    ok = [r for r in results if "error" not in r]
    failed = [r for r in results if "error" in r]
    accepted = sum(r["accepted"] for r in ok)
    rejected = sum(r["rejected"] for r in ok)
    latencies = [x for r in ok for x in r["latencies"]]
    reasons: dict = {}
    for r in ok:
        for k, v in r["reasons"].items():
            reasons[k] = reasons.get(k, 0) + v
    delivered = [v for k, v in seen.items() if k != "__error__"]
    lines = [
        "LOAD TEST",
        f"  relay            : {args.relay}",
        f"  mode             : {'duration %.0fs @ %.2f ev/s per conn' % (args.duration, args.rate) if args.duration else 'count %d per conn' % args.events}",
        f"  connections      : {args.connections} (ok {len(ok)}, failed {len(failed)}), subscribers {args.subscribers}",
        f"  accepted events  : {accepted}   rejected: {rejected}",
        f"  wall time        : {elapsed:.2f} s",
        f"  throughput       : {accepted / elapsed:.0f} accepted events/s" if elapsed else "",
    ]
    if latencies:
        lines += [f"  OK latency       : median {statistics.median(latencies) * 1000:.0f} ms, "
                  f"p95 {_pct(latencies, 0.95) * 1000:.0f} ms, max {max(latencies) * 1000:.0f} ms"]
    if delivered:
        lines += [f"  subscription     : {len(delivered)} delivered of {len(sent_at)} sent; "
                  f"latency median {statistics.median(delivered) * 1000:.0f} ms, "
                  f"p95 {_pct(delivered, 0.95) * 1000:.0f} ms, max {max(delivered) * 1000:.0f} ms"]
    elif args.subscribers:
        lines += [f"  subscription     : nothing delivered ({seen.get('__error__', 'no error reported')})"]
    if reasons:
        lines += ["  rejections:"] + [f"      {n:6}x {e}" for e, n in reasons.items()]
    if ok:
        conn_times = sorted(r["connect"] for r in ok)
        lines += [
            f"  connect  median  : {conn_times[len(conn_times) // 2] * 1000:.0f} ms",
            f"  connect  p95     : {_pct(conn_times, 0.95) * 1000:.0f} ms",
            f"  connect  max     : {conn_times[-1] * 1000:.0f} ms",
        ]
    if failed:
        kinds: dict = {}
        for r in failed:
            kinds[r["error"]] = kinds.get(r["error"], 0) + 1
        lines += ["  failures:"] + [f"      {n:5}x {e}" for e, n in kinds.items()]
    if before and after:
        lines += [
            "  relay metrics (delta):",
            f"      connections_total  +{after.get('nostr_connections_total', 0) - before.get('nostr_connections_total', 0):.0f}",
            f"      cmd_event_total    +{after.get('nostr_cmd_event_total', 0) - before.get('nostr_cmd_event_total', 0):.0f}",
            f"      connections_active  {after.get('nostr_connections_active', float('nan')):.0f} (after)",
        ]
        w_sum = after.get("nostr_events_write_seconds_sum", 0) - before.get("nostr_events_write_seconds_sum", 0)
        w_cnt = after.get("nostr_events_write_seconds_count", 0) - before.get("nostr_events_write_seconds_count", 0)
        if w_cnt:
            lines.append(f"      write mean          {w_sum / w_cnt * 1000:.1f} ms over {w_cnt:.0f} writes")
    if mem_before is not None and mem_after is not None:
        lines += [f"  container memory : {mem_before:.1f} -> {mem_after:.1f} MiB"]
    text = "\n".join(x for x in lines if x)
    Path(args.report).write_text(text, encoding="utf-8")
    print(text)
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
