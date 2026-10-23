"""Identity attestations (kind 31021): model, validation, issuance, and reading (§2.1)."""
import time

from a4a import types
from a4a.agent import Agent
from a4a.identity import verify_identity_attestation
from a4a.keys import Keys
from a4a.types import IdentityAttestation, KIND_IDENTITY_ATTESTATION
from tests.fake_relay import FakeRelay


def _att(issuer, subject, level="person:gosklyuch", name="", expiration=0):
    ev = IdentityAttestation(subject=subject, level=level, name=name,
                             issuer_name="verifier.example", expiration=expiration).to_event()
    return ev.sign(issuer)   # signed by ISSUER, so ev.pubkey identifies issuer


# --- model --------------------------------------------------------------------

def test_identity_attestation_roundtrip():
    s = "a" * 64
    att = IdentityAttestation(subject=s, level="org:kep", name="Acme LLC",
                              issuer_name="kyc.example", expiration=123)
    ev = att.to_event()
    assert ev.kind == KIND_IDENTITY_ATTESTATION
    assert ev.tag_value("p") == s and ev.tag_value("d") == s   # addressable by subject
    assert ev.tag_value("level") == "org:kep"
    assert ev.tag_value("name") == "Acme LLC"
    back = IdentityAttestation.from_event(ev)
    assert (back.subject, back.level, back.name, back.expiration) == (s, "org:kep", "Acme LLC", 123)


# --- attestation verification -------------------------------------------------

def test_verify_valid():
    issuer, subject = Keys(), Keys()
    assert verify_identity_attestation(_att(issuer, subject.pubkey_hex), subject.pubkey_hex)


def test_verify_rejects_other_event_kind_even_when_signature_is_valid():
    issuer, subject = Keys(), Keys()
    ev = _att(issuer, subject.pubkey_hex)
    ev.kind = 1
    ev.sign(issuer)

    assert not verify_identity_attestation(ev, subject.pubkey_hex)


def test_verify_wrong_subject():
    issuer, subject, other = Keys(), Keys(), Keys()
    assert not verify_identity_attestation(_att(issuer, subject.pubkey_hex), other.pubkey_hex)


def test_verify_expired():
    issuer, subject = Keys(), Keys()
    ev = _att(issuer, subject.pubkey_hex, expiration=int(time.time()) - 10)
    assert not verify_identity_attestation(ev, subject.pubkey_hex)
    future = _att(issuer, subject.pubkey_hex, expiration=int(time.time()) + 3600)
    assert verify_identity_attestation(future, subject.pubkey_hex)


def test_verify_rejects_tampered():
    issuer, subject = Keys(), Keys()
    ev = _att(issuer, subject.pubkey_hex, level="account:email")
    # Tamper with level after signing; issuer signature must fail.
    ev.tags = [t if t[0] != "level" else ["level", "person:gosklyuch"] for t in ev.tags]
    assert not verify_identity_attestation(ev, subject.pubkey_hex)


# --- relay integration --------------------------------------------------------

async def test_attest_and_get_identity_over_relay():
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as issuer, Agent([relay.url]) as subject, \
                Agent([relay.url]) as observer:
            await issuer.attest_identity(subject.pubkey, level="person:gosklyuch",
                                         name="John Smith", issuer_name="gosuslugi-bridge")
            ids = await observer.get_identity(subject.pubkey)
            assert len(ids) == 1
            assert ids[0]["issuer"] == issuer.pubkey
            assert ids[0]["level"] == "person:gosklyuch"
            assert ids[0]["name"] == "John Smith"
            # Trust this issuer, so the attestation is returned.
            assert await observer.get_identity(subject.pubkey, trusted_issuers=[issuer.pubkey])
            # Trust none of the returned issuers, so the result is empty.
            assert await observer.get_identity(subject.pubkey, trusted_issuers=["f" * 64]) == []


async def test_expired_attestation_excluded_by_get_identity():
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as issuer, Agent([relay.url]) as subject:
            await issuer.attest_identity(subject.pubkey, level="account:email",
                                         expiration=int(time.time()) - 10)
            assert await issuer.get_identity(subject.pubkey) == []


# --- F3: self-issued attestations ---------------------------------------------

def test_verify_rejects_self_issued():
    """Issuer equal to subject is a self-claim, not an attestation."""
    subject = Keys()
    ev = _att(subject, subject.pubkey_hex, level="person:gosklyuch", name="John Smith")
    assert not verify_identity_attestation(ev, subject.pubkey_hex)


def test_verify_self_issued_allowed_explicitly():
    """An explicit flag restores legacy behavior for callers who understand it."""
    subject = Keys()
    ev = _att(subject, subject.pubkey_hex, level="person:gosklyuch")
    assert verify_identity_attestation(ev, subject.pubkey_hex, allow_self_issued=True)


async def test_get_identity_drops_self_issued_by_default():
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as subject, Agent([relay.url]) as observer:
            await subject.attest_identity(subject.pubkey, level="person:gosklyuch",
                                          name="John Smith", issuer_name="Gosuslugi")
            assert await observer.get_identity(subject.pubkey) == []


async def test_get_identity_marks_self_issued_when_requested():
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as subject, Agent([relay.url]) as observer:
            await subject.attest_identity(subject.pubkey, level="person:gosklyuch")
            ids = await observer.get_identity(subject.pubkey, include_self_issued=True)
            assert len(ids) == 1 and ids[0]["self_issued"] is True


async def test_get_identity_marks_trust_decision():
    """Without a trusted-issuer list, mark trust as unverified.

    Consumers must not display a verification badge merely because a signature exists.
    """
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as issuer, Agent([relay.url]) as subject, \
                Agent([relay.url]) as observer:
            await issuer.attest_identity(subject.pubkey, level="account:email")
            [untrusted] = await observer.get_identity(subject.pubkey)
            assert untrusted["self_issued"] is False and untrusted["trusted"] is False
            [trusted] = await observer.get_identity(subject.pubkey,
                                                    trusted_issuers=[issuer.pubkey])
            assert trusted["trusted"] is True


async def test_second_key_of_same_owner_is_indistinguishable():
    """HONEST LIMITATION: self-signature filtering cannot detect a second owner key.

    An owner can issue itself a level from another key. `trusted_issuers` is the only
    real protection. This test prevents claiming a stronger property than exists.
    """
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as sock_puppet, Agent([relay.url]) as subject, \
                Agent([relay.url]) as observer:
            await sock_puppet.attest_identity(subject.pubkey, level="person:bank",
                                              issuer_name="Example Bank ID")
            [att] = await observer.get_identity(subject.pubkey)
            assert att["self_issued"] is False        # formally not self-issued
            assert att["trusted"] is False            # issuer remains untrusted
            # A trusted-issuer policy removes the forged claim.
            assert await observer.get_identity(
                subject.pubkey, trusted_issuers=["f" * 64]) == []
