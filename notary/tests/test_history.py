"""REST /v1/history adapter: node response parsing, cursors, and legacy 404s."""
import json
import urllib.error

import pytest
from a4a.event import Event
from a4a.keys import Keys

from a4a_notary.history import RelayWithHistory, rest_base


def test_rest_base_maps_ws_schemes():
    assert rest_base("ws://127.0.0.1:8080") == "http://127.0.0.1:8080"
    assert rest_base("wss://eu1.a4a.network/") == "https://eu1.a4a.network"


async def test_history_parses_rows_and_passes_cursor():
    ev = Event(kind=31004, tags=[["d", "x"]], content="history").sign(Keys())
    urls = []

    def opener(url):
        urls.append(url)
        return json.dumps({"version": 2,
                           "rows": [{"first_seen": 1_800_000_007, "event": ev.model_dump()}],
                           "next_cursor": {"first_seen": 1_800_000_007, "id": ev.id}})

    rows = await RelayWithHistory(relay=None, relay_url="ws://h:1", opener=opener).history(1_800_000_000, 50)
    assert urls == ["http://h:1/v1/history?after=1800000000&limit=50&page=2&after_id="]
    assert rows == [(1_800_000_007, ev)]
    assert rows[0][1].verify()


async def test_old_relay_without_history_is_named_not_silent():
    def opener(url):
        raise urllib.error.HTTPError(url, 404, "Not Found", None, None)

    with pytest.raises(RuntimeError, match="0.3.14"):
        await RelayWithHistory(relay=None, relay_url="ws://h:1", opener=opener).history(0, 10)


async def test_unversioned_relay_response_is_refused_not_treated_as_pagination():
    with pytest.raises(RuntimeError, match="page=2"):
        await RelayWithHistory(None, "ws://h:1", opener=lambda _: "[]").history(0, 10)


@pytest.mark.parametrize("problem", ["repeated", "unordered", "wrong_cursor", "too_many"])
async def test_invalid_pagination_cannot_move_the_cursor(problem):
    events = sorted([Event(kind=31004, content=str(i)).sign(Keys()) for i in range(2)], key=lambda e: e.id)
    rows = [{"first_seen": 100, "event": ev.model_dump()} for ev in events]
    cursor = {"first_seen": 100, "id": events[-1].id}
    after_id, limit = "", 10
    if problem == "repeated":
        after_id = events[0].id
    elif problem == "unordered":
        rows.reverse()
    elif problem == "wrong_cursor":
        cursor["id"] = "f" * 64
    else:
        limit = 1
    page = json.dumps({"version": 2, "rows": rows, "next_cursor": cursor})
    with pytest.raises(RuntimeError):
        await RelayWithHistory(None, "ws://h:1", opener=lambda _: page).history(100, limit, after_id)


async def test_http_oversize_response_is_not_decoded(monkeypatch):
    from a4a_notary import history

    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, size):
            assert size == history.MAX_HISTORY_PAGE_BYTES + 1
            return b"x" * size

    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: Response())
    with pytest.raises(RuntimeError, match="2 MiB"):
        await RelayWithHistory(None, "ws://h:1").history(0, 10)
