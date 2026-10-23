"""File exchange (§2.3): encrypted-blob references and integrity verification."""
import hashlib

from a4a import files
from a4a.agent import Agent
from tests.fake_relay import FakeRelay


def test_build_parse_roundtrip():
    h = files.sha256_hex(b"tz")
    ref = files.build_file_reference("https://store.example/x", h, key="k",
                                     name="tz.pdf", mime="application/pdf", size=1024)
    p = files.parse_file_reference(ref)
    assert p["url"] == "https://store.example/x" and p["sha256"] == h and p["key"] == "k"
    assert p["name"] == "tz.pdf" and p["mime"] == "application/pdf" and p["size"] == 1024


def test_parse_rejects_non_file():
    assert files.parse_file_reference("ordinary message text") is None
    assert files.parse_file_reference('{"foo":"bar"}') is None
    assert files.parse_file_reference('{"a4a_file":{"url":"u"}}') is None   # no sha256


# --- F4/F5: parsing must not invite downloads from arbitrary locations -----------

def _ref(url, sha256=None):
    return files.build_file_reference(
        url, files.sha256_hex(b"x") if sha256 is None else sha256)


def test_parse_rejects_dangerous_schemes():
    """A network-supplied scheme is not just text; it drives a request (audit F4)."""
    for url in ("file:///C:/Windows/win.ini", "javascript:alert(1)",
                "http://store.example/x", "data:text/html,<script>"):
        assert files.parse_file_reference(_ref(url)) is None, url


def test_parse_rejects_internal_hosts():
    """SSRF: a stranger must not make us contact hosts inside the perimeter."""
    for url in ("https://169.254.169.254/latest/meta-data/",   # cloud metadata
                "https://127.0.0.1/secret", "https://localhost/secret",
                "https://[::1]/secret", "https://10.0.0.5/x", "https://192.168.1.1/x"):
        assert files.parse_file_reference(_ref(url)) is None, url


def test_parse_allows_internal_hosts_explicitly():
    """Allow an explicit opt-in for a caller's private network."""
    ref = _ref("https://10.0.0.5/x")
    assert files.parse_file_reference(ref, allow_private_hosts=True)["url"]


def test_parse_allows_content_addressed_storage():
    for url in ("ipfs://QmHash", "ar://txid", "https://store.example/blob"):
        assert files.parse_file_reference(_ref(url)) is not None, url


def test_parse_rejects_malformed_sha256():
    """F5: reject a malformed hash during parsing, before integrity verification."""
    for bad in ("not-a-hash", "abc123", "z" * 64, ""):
        assert files.parse_file_reference(_ref("https://store.example/x", bad)) is None, bad


def test_parse_without_validation_returns_raw():
    """Diagnostic escape hatch: explicitly disabled validation returns raw input."""
    ref = _ref("file:///etc/passwd", "not-a-hash")
    raw = files.parse_file_reference(ref, validate=False)
    assert raw["url"] == "file:///etc/passwd"


def test_verify_file_integrity():
    data = b"contract attachment bytes"
    h = hashlib.sha256(data).hexdigest()
    assert files.sha256_hex(data) == h
    assert files.verify_file(data, h)
    assert not files.verify_file(data, "deadbeef")           # tampered file must fail


async def test_send_file_over_relay():
    data = "contract.pdf contents".encode("utf-8")
    h = files.sha256_hex(data)
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as alice, Agent([relay.url]) as bob:
            await alice.send_file(bob.pubkey, url="ipfs://Qm123", sha256=h,
                                  key="deckey", name="dogovor.pdf",
                                  mime="application/pdf", size=len(data))
            inbox = await bob.read_private_messages()
            assert len(inbox) == 1
            ref = files.parse_file_reference(inbox[0]["content"])
            assert ref is not None
            assert ref["sha256"] == h and ref["name"] == "dogovor.pdf" and ref["key"] == "deckey"
            # Recipient has "downloaded" data and verifies its integrity.
            assert files.verify_file(data, ref["sha256"])


async def test_send_file_wrapped_hides_metadata():
    h = files.sha256_hex(b"secret file")
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as alice, Agent([relay.url]) as bob:
            await alice.send_file(bob.pubkey, url="ipfs://Qm", sha256=h, key="k", wrap=True)
            inbox = await bob.read_private_messages()
            assert inbox and inbox[0]["wrapped"] is True
            assert files.parse_file_reference(inbox[0]["content"])["sha256"] == h


def test_parse_rejects_short_and_decimal_loopback_forms():
    """Reject classic internal-address bypass forms.

    Decimal notation, abbreviated addresses, bare zero, and a trailing hostname dot
    bypassed the first version, which recognized only canonical `127.0.0.1`. Found
    during review on 2026-08-28.
    """
    for url in ("https://2130706433/x",   # decimal 127.0.0.1
                "https://127.1/x",        # abbreviated form
                "https://0/x",            # 0.0.0.0
                "https://localhost./x",   # trailing dot, same hostname
                "https://0x7f.1/x"):      # hexadecimal notation
        assert files.parse_file_reference(_ref(url)) is None, url


def test_parse_still_allows_ordinary_hosts():
    """Hardening must not reject ordinary public addresses."""
    for url in ("https://store.example/blob", "https://cdn.example.com/x",
                "ipfs://QmHash"):
        assert files.parse_file_reference(_ref(url)) is not None, url


def test_internal_host_treats_absent_and_empty_normalized_hosts_as_unsafe():
    assert files.is_internal_host(None) is True
    assert files.is_internal_host(".") is True


def test_content_addressed_path_form_does_not_require_a_dns_hostname():
    assert files._is_acceptable_url("ipfs:QmPathOnly", allow_private_hosts=False)


def test_https_without_hostname_is_rejected_even_with_private_opt_in():
    assert not files._is_acceptable_url("https:///missing-host",
                                        allow_private_hosts=True)


async def test_send_file_without_a_key_warns_that_nothing_is_encrypted(caplog):
    """A keyless reference points to an unencrypted stored file and must say so.

    Before 2026-09-04 the SDK did not encrypt files at all (finding 51), so a sender
    trusting the README silently distributed a public blob URL (measured 2026-08-30).
    `files.encrypt_file` now exists, but the protocol still cannot verify that a URL
    serves ciphertext. Without `key`, retain a warning that names the remedy. Do not
    forbid the operation because public links are a legitimate use case.
    """
    from a4a.agent import Agent
    from a4a.keys import Keys
    from tests.fake_relay import FakeRelay

    async with FakeRelay() as relay:
        async with Agent([relay.url]) as sender:
            with caplog.at_level("WARNING"):
                await sender.send_file(Keys().pubkey_hex,
                                       url="https://storage.example/a.pdf",
                                       sha256="a" * 64)
    assert any("NOT encrypted" in r.message and "encrypt_file" in r.message
               for r in caplog.records), "keyless send was silent or gave no remedy"


async def test_send_file_with_a_key_is_silent():
    """Control: a keyed reference must not warn or warnings become ignored noise."""
    from a4a.agent import Agent
    from a4a.keys import Keys
    from tests.fake_relay import FakeRelay

    import logging
    records = []
    handler = logging.Handler()
    handler.emit = records.append
    logging.getLogger("a4a.agent").addHandler(handler)
    try:
        async with FakeRelay() as relay:
            async with Agent([relay.url]) as sender:
                await sender.send_file(Keys().pubkey_hex,
                                       url="https://storage.example/a.pdf",
                                       sha256="a" * 64, key="ff" * 32)
    finally:
        logging.getLogger("a4a.agent").removeHandler(handler)
    assert not [r for r in records if "NOT encrypted" in r.getMessage()], \
        "unencrypted-file warning appeared even though a key was supplied"
