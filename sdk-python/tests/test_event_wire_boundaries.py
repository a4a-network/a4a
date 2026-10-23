"""Nostr wire integers and Unicode must agree with the relay parser."""
import json

import pytest
from pydantic import ValidationError

from a4a import crypto
from a4a.event import Event
from a4a.keys import Keys
from a4a.relay import RelayClient


@pytest.mark.parametrize('field', ['created_at', 'kind'])
@pytest.mark.parametrize('value', [True, False, 1.0, '1', -1, 2 ** 64])
def test_event_wire_integers_reject_coercion_and_unsigned_overflow(field, value):
    fields = {'kind': 1, 'created_at': 1}
    fields[field] = value
    with pytest.raises(ValidationError):
        Event(**fields)


@pytest.mark.parametrize('field', ['created_at', 'kind'])
@pytest.mark.parametrize('value', [True, 1.0, '1'])
def test_network_parser_rejects_wire_type_even_when_coerced_signature_matches(field, value):
    wire = Event(kind=1, created_at=1).sign(Keys()).model_dump()
    wire[field] = value
    assert RelayClient._parse_event(wire) is None


@pytest.mark.parametrize('value', [0, 2 ** 64 - 1])
def test_event_wire_unsigned_integer_endpoints_roundtrip(value):
    event = Event(kind=value, created_at=value, tags=[[], ['e']]).sign(Keys())
    assert event.verify()
    assert RelayClient._parse_event(event.model_dump()) is not None


@pytest.mark.parametrize('field', ['created_at', 'kind'])
@pytest.mark.parametrize('value', [True, -1, 2 ** 64])
def test_wire_boundary_is_rechecked_after_unvalidated_model_copy(field, value):
    event = Event(kind=1, created_at=1).sign(Keys()).model_copy(update={field: value})
    assert event.verify() is False
    with pytest.raises(ValueError, match='unsigned'):
        event.sign(Keys())


def _raw_sign(event, keys):
    """Manufacture malformed wire signatures without using the supported sender API."""
    event.pubkey = keys.pubkey_hex
    event.id = crypto.compute_event_id(event.pubkey, event.created_at, event.kind,
                                       event.tags, event.content)
    event.sig = crypto.sign(event.id, keys.privkey_hex)
    return event


@pytest.mark.parametrize('value', ['\ud800', '\udfff'])
@pytest.mark.parametrize('location', ['content', 'tag_name', 'tag_value'])
def test_real_signature_does_not_make_invalid_unicode_a_valid_event(value, location):
    keys = Keys()
    event = Event(kind=1, content=value if location == 'content' else 'text',
        tags=[[value if location == 'tag_name' else 't',
               value if location == 'tag_value' else 'text']])
    _raw_sign(event, keys)
    assert crypto.verify(event.id, event.sig, event.pubkey)
    assert event.verify() is False
    assert RelayClient._parse_event(event.model_dump()) is None
    with pytest.raises(ValueError, match='Unicode'):
        event.sign(keys)


def test_non_bmp_unicode_and_empty_short_tags_remain_valid():
    event = Event(kind=1, created_at=1,
        content='emoji \U0001f600 and composed \u00e9',
        tags=[[], ['e'], ['t', '\U0001f680']]).sign(Keys())
    escaped_wire = json.dumps(event.model_dump(), ensure_ascii=True)
    parsed = RelayClient._parse_event(json.loads(escaped_wire))
    assert parsed is not None and parsed.verify()
    assert parsed.content == event.content
    assert parsed.tags == event.tags
