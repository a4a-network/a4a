"""Opt-in integration against the disposable local relay safety fixture only."""
from a4a.keys import Keys

from a4a_notary.history import RelayWithHistory
from a4a_notary.service import NotaryService
from a4a_notary.store import Store
from tests.test_calendar import FakeCalendar


async def test_real_history_pages_reach_notary_store_across_restart(tmp_path, local_history_relay):
    url = local_history_relay
    calendar = FakeCalendar("https://fake")
    path = tmp_path / "notary.db"
    store = Store(path)

    def service():
        return NotaryService(RelayWithHistory(None, url), store, Keys(), url,
                             calendars=["https://fake"], factory=lambda _: calendar)

    notary = service()
    first = await notary.collect()
    assert 0 < first < 26, "fixture must cross the actual relay byte cap"
    store.close()
    store = Store(path)
    notary = service()
    total = first
    for _ in range(8):
        count = await notary.collect()
        total += count
        if count == 0:
            break
    assert total == 26
    assert store.stats()["leaves"] == 26
    assert len(calendar.submits) == 2
    store.close()
