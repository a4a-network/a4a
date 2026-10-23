"""Exercise MCP file tools through `call_tool` without exposing file secrets.

The file key must not enter the model conversation, no plaintext may go over the wire,
and inbound references must be fully redacted. Decisions from 2026-09-04: persist the
key in `~/.a4a/file-keys.json` between encryption and sending (A2), and keep blob
retrieval through MCP disabled until a safe downloader exists.
"""
import json
import socket

import pytest
from a4a import Agent, Keys, files
from a4a.sanitize import wrap_untrusted

from a4a_mcp import identity, inbox_runtime, server
from fake_relay import FakeRelay
from tool_call import call_text
from wire_cases import wrapped_with_escaped_content

DATA = "\u0430\u043A\u0442 \u043F\u0440\u0438\u0451\u043C\u043A\u0438 №3 — \u0441\u043E\u0434\u0435\u0440\u0436\u0438\u043C\u043E\u0435".encode("utf-8") * 50
HASH = "c" * 64
KEY = "b" * 64
REDACTION = "Receiving files through MCP is not supported"
SAFE_REDACTION = (
    "[A4A attachment hidden] Receiving files through MCP is not supported. "
    "The URL and metadata were not exposed to the model. a4a_open_file operates only "
    "on an existing local blob supplied outside MCP by the owner or a trusted host."
)
MARKER = "a4a_file"


def _escape_marker_character(index):
    return MARKER[:index] + f"\\u{ord(MARKER[index]):04x}" + MARKER[index + 1:]


TRUNCATED_ESCAPED_MARKERS = [
    f'{{"{_escape_marker_character(index)}":{{"url":"https://public-looking.example/blob"'
    for index in range(len(MARKER))
]
ALL_ESCAPED_MARKER = "".join(f"\\u{ord(character):04x}" for character in MARKER)
REFERENCE = files.build_file_reference(
    "https://public-looking.example/blob", HASH, KEY, name="secret-name.pdf")


def _json_layers(value, count):
    for _ in range(count):
        value = json.dumps(value)
    return value


ENCODED_REFERENCE_ATTEMPTS = (
    json.dumps(REFERENCE),
    json.dumps({"payload": REFERENCE}),
    json.dumps([REFERENCE]),
    json.dumps({REFERENCE: 1}),
    _json_layers(REFERENCE, 4),
    '{"payload":' + json.dumps(REFERENCE),
    '[' + json.dumps(REFERENCE),
    'prefix ' + json.dumps(REFERENCE),
    'prefix ' + json.dumps(REFERENCE)[:-1],
    json.dumps(REFERENCE)[1:],
    json.dumps(REFERENCE)[1:-1],
    'prefix ' + json.dumps(REFERENCE)[1:-1],
    '\n' + json.dumps(REFERENCE)[1:-1],
    json.dumps(REFERENCE)[1:-1] + ' suffix',
    '{"payload":' + json.dumps(REFERENCE)[1:-1],
)


def _assert_reference_hidden(value, *secrets):
    output = (value if isinstance(value, str) else json.dumps(value, ensure_ascii=False))
    encoded = output.casefold().encode("utf-8")
    assert REDACTION.casefold().encode("utf-8") in encoded
    for secret in secrets:
        assert secret.casefold().encode("utf-8") not in encoded
    for instruction in ("\u0441\u043A\u0430\u0447", "download", "curl", "fetch"):
        assert instruction.encode("utf-8") not in encoded


FILE_REFERENCE_ATTEMPTS = [
    REFERENCE,
    files.build_file_reference("ipfs://QmSensitive", HASH, KEY),
    files.build_file_reference("ar://ArSensitive", HASH, KEY),
    json.dumps({"a4a_file": {"url": "https://169.254.169.254/latest", "sha256": HASH}}),
    json.dumps({"a4a_file": {"url": "https://127.0.0.1/private", "sha256": HASH}}),
    json.dumps({"a4a_file": {"url": "http://public-looking.example/blob", "sha256": HASH}}),
    json.dumps({"a4a_file": {"url": "file:///private", "sha256": HASH}}),
    json.dumps({"a4a_file": {"url": "https://public-looking.example/blob",
                              "sha256": "not-a-hash", "key": KEY}}),
    json.dumps({"a4a_file": {"url": "https://public-looking.example/blob", "key": KEY}}),
    json.dumps({"a4a_file": {"sha256": HASH, "key": KEY}}),
    json.dumps({"a4a_file": "https://public-looking.example/blob"}),
    json.dumps({"nested": {"a4a_file": {"url": "https://public-looking.example/blob"}}}),
    '{"a4a_file":{"url":"https://public-looking.example/blob"',
    '{"a4a\\u005ffile":{"url":"https://public-looking.example/blob"}}',
    '{"a4a\\u005ffile":{"url":"https://public-looking.example/blob"',
    f'{{"{ALL_ESCAPED_MARKER}":{{"url":"https://public-looking.example/blob"}}}}',
    f'{{"{ALL_ESCAPED_MARKER}":{{"url":"https://public-looking.example/blob"',
    *TRUNCATED_ESCAPED_MARKERS,
    *ENCODED_REFERENCE_ATTEMPTS,
]


@pytest.fixture
def mcp_home(tmp_path, monkeypatch):
    monkeypatch.setenv("A4A_MANDATE_AUTO", "1")
    # File references now travel through the ACK-waiting journaled delivery; nobody
    # acknowledges in these tests, so do not wait the production twenty seconds.
    monkeypatch.setattr(server, "_DELIVER_RETRIES", 0)
    monkeypatch.setattr(server, "_DELIVER_ACK_TIMEOUT", 0.2)
    monkeypatch.setattr(identity, "IDENTITY_DIR", tmp_path / ".a4a")
    monkeypatch.setattr(identity, "IDENTITY_FILE", tmp_path / ".a4a" / "identity.json")


async def _call(name: str, args: dict) -> str:
    return await call_text(server.mcp, name, args)


async def _encrypt(tmp_path):
    src = tmp_path / "akt.pdf"
    src.write_bytes(DATA)
    out = await _call("a4a_encrypt_file", {"path": str(src)})
    blob_path = tmp_path / "akt.pdf.a4a"
    return src, blob_path, out


@pytest.mark.parametrize("content", FILE_REFERENCE_ATTEMPTS)
def test_every_structured_file_reference_attempt_is_redacted_without_dns_or_fetch(
        content, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("model-facing file redaction must not resolve or fetch a target")

    monkeypatch.setattr(files, "resolve_download_target", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    output = inbox_runtime.shown_content({"from_pubkey": "d" * 64, "content": content})
    assert output == wrap_untrusted(SAFE_REDACTION, source="d" * 12)
    _assert_reference_hidden(
        output, "public-looking.example", "169.254.169.254", "127.0.0.1",
        "QmSensitive", "ArSensitive", "secret-name.pdf", HASH, KEY)


BENIGN_URL = "https://example.org/help"
BENIGN_ENCODED_URL = json.dumps(BENIGN_URL)


@pytest.mark.parametrize("text", [
    f"\u041E\u0431\u044B\u0447\u043D\u0430\u044F \u0441\u043F\u0440\u0430\u0432\u043A\u0430: {BENIGN_URL} — \u044D\u0442\u043E \u0447\u0430\u0441\u0442\u044C \u0441\u043E\u043E\u0431\u0449\u0435\u043D\u0438\u044F.",
    BENIGN_ENCODED_URL,
    json.dumps({"payload": BENIGN_URL}),
    json.dumps([BENIGN_URL]),
    json.dumps({BENIGN_URL: 1}),
    '{"payload":' + BENIGN_ENCODED_URL,
    '[' + BENIGN_ENCODED_URL,
    'prefix ' + BENIGN_ENCODED_URL,
    'prefix ' + BENIGN_ENCODED_URL[:-1],
    BENIGN_ENCODED_URL[1:],
    BENIGN_ENCODED_URL[1:-1],
    'prefix ' + BENIGN_ENCODED_URL[1:-1],
    '\n' + BENIGN_ENCODED_URL[1:-1],
    BENIGN_ENCODED_URL[1:-1] + ' suffix',
    '{"payload":' + BENIGN_ENCODED_URL[1:-1],
])
def test_ordinary_private_text_with_a_url_remains_visible(text):
    output = inbox_runtime.shown_content({"from_pubkey": "d" * 64, "content": text})
    assert text in output and "UNTRUSTED" in output
    assert REDACTION not in output


@pytest.mark.parametrize("content", ENCODED_REFERENCE_ATTEMPTS)
async def test_manual_read_redacts_json_encoded_file_reference(
        mcp_home, monkeypatch, content):
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        me, peer = identity.load_or_create_identity(), Keys()
        inbox_runtime.configure("file-tools", [peer.pubkey_hex], start_after=0)
        async with Agent([relay.url], keys=peer) as author:
            await author.send_private_message(me.pubkey_hex, content)
        output = await _call("a4a_read_private", {})
    _assert_reference_hidden(
        output, "public-looking.example", "secret-name.pdf", HASH, KEY)


def test_unexpected_oversized_direct_content_fails_closed_without_scanning_unbounded_text():
    output = inbox_runtime.shown_content({"from_pubkey": "d" * 64, "content": "x" * 32769})
    assert output == wrap_untrusted(SAFE_REDACTION, source="d" * 12)


def _budget_exhaustion_payloads():
    deep = "ordinary"
    for _ in range(17):
        deep = [deep]
    byte_heavy = "x" * 20000
    for _ in range(12):
        byte_heavy = json.dumps(byte_heavy)
    assert len(byte_heavy.encode("utf-8")) <= 32768
    parser_recursion = "[" * 1100 + json.dumps(REFERENCE) + "]" * 1100
    integer_limit = "[" + "9" * 5000 + "," + json.dumps(REFERENCE) + "]"
    parser_recursion_without_marker = "[" * 1100 + json.dumps("ordinary") + "]" * 1100
    integer_limit_without_marker = "[" + "9" * 5000 + "]"
    return (json.dumps(deep), json.dumps([0] * 1100), byte_heavy,
            parser_recursion, integer_limit, parser_recursion_without_marker,
            integer_limit_without_marker)


@pytest.mark.parametrize("content", _budget_exhaustion_payloads(),
                         ids=("depth", "nodes", "decoded-bytes",
                              "parser-recursion", "integer-limit",
                              "parser-recursion-without-marker",
                              "integer-limit-without-marker"))
def test_nested_json_budget_exhaustion_fails_closed(content):
    output = inbox_runtime.shown_content({"from_pubkey": "d" * 64, "content": content})
    assert output == wrap_untrusted(SAFE_REDACTION, source="d" * 12)


def test_lone_surrogate_fails_closed_before_utf8_bound_check():
    output = inbox_runtime.shown_content({"from_pubkey": "d" * 64, "content": "\ud800"})
    assert output == wrap_untrusted(SAFE_REDACTION, source="d" * 12)


async def test_manual_read_refuses_wire_surrogate_and_redacts_adapter_poison(monkeypatch):
    sender, recipient = Keys(), Keys()
    outer, inner = wrapped_with_escaped_content(
        sender, recipient, "\ud800", delivery="manual-surrogate")
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    assert outer.verify() and not inner.verify()
    assert agent._decode_incoming(outer) is None
    # The normal decoder refuses this signed malformed wire event. Independently
    # test the MCP output boundary against a broken adapter supplying decoded text.
    good_outer, _ = wrapped_with_escaped_content(
        sender, recipient, "valid adapter fixture", delivery="manual-valid")
    decoded = agent._decode_incoming(good_outer)
    assert decoded is not None
    decoded["content"] = "\ud800"

    class Messages:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def read_private_messages(self):
            return [decoded]

    monkeypatch.setattr(server.inbox_runtime, "active_policy", lambda: object())
    async def allow(_agent, messages):
        return messages

    monkeypatch.setattr(server.inbox_runtime, "allowed_messages_authorized", allow)
    monkeypatch.setattr(server, "_make_agent", Messages)
    server._last_unreachable = None

    output = await server.a4a_read_private()
    assert SAFE_REDACTION in output and "\ud800" not in output
    output.encode("utf-8")


@pytest.mark.parametrize("content", [None, b'{"a4a_file":{}}', {"a4a_file": {}}, []])
def test_unexpected_non_text_content_fails_closed(content):
    output = inbox_runtime.shown_content({"from_pubkey": "d" * 64, "content": content})
    assert output == wrap_untrusted(SAFE_REDACTION, source="d" * 12)


async def test_model_facing_file_contract_has_no_receive_or_download_instruction():
    instructions = server.mcp.instructions
    assert "Receiving inbound files from arbitrary links is unsupported" in instructions
    assert "recipient downloads" not in instructions

    registered = {tool.name: tool.description for tool in await server.mcp.list_tools()}
    for name in ("a4a_read_private", "a4a_inbox_next", "a4a_dialogue_open",
                 "a4a_dialogue_history", "a4a_dialogue_checkpoint"):
        description = registered[name]
        assert "file" in description.lower() or "\u0444\u0430\u0439\u043B" in description.lower(), name
        assert "url=" not in description.lower() and "\u0441\u043A\u0430\u0447\u0430\u0439\u0442\u0435" not in description.lower(), name
        if name != "a4a_dialogue_checkpoint":
            assert "gateway" in description.lower(), name
            assert "attachment handle" in description.lower(), name
            assert "a4a_open_file" in description, name
    open_description = registered["a4a_open_file"]
    assert "existing local blob" in open_description
    assert "owner or trusted host" in open_description
    for forbidden in ("url=", "\u0441\u043A\u0430\u0447\u0430\u0439\u0442\u0435", "curl", "https://", "ipfs://", "ar://"):
        assert forbidden not in open_description.lower()


async def test_encrypt_writes_blob_and_keeps_key_off_the_transcript(mcp_home, tmp_path):
    src, blob_path, out = await _encrypt(tmp_path)
    assert blob_path.is_file() and len(blob_path.read_bytes()) == len(DATA) + 28
    sha = files.sha256_hex(blob_path.read_bytes())
    assert f"sha256: {sha}" in out and str(blob_path) in out
    stored = json.loads((tmp_path / ".a4a" / "file-keys.json").read_text(encoding="utf-8"))
    key = stored[sha]["key"]
    assert len(key) == 64 and key not in out, "the key was exposed to the model"
    assert stored[sha]["size"] == len(DATA) and stored[sha]["name"] == "akt.pdf"


async def test_encrypt_missing_file_is_a_message_not_a_traceback(mcp_home, tmp_path):
    assert "not found" in await _call("a4a_encrypt_file", {"path": str(tmp_path / "\u043D\u0435\u0442")})


async def test_send_then_open_end_to_end(mcp_home, monkeypatch, tmp_path):
    src, blob_path, _ = await _encrypt(tmp_path)
    sha = files.sha256_hex(blob_path.read_bytes())
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        me = identity.load_or_create_identity().pubkey_hex
        inbox_runtime.configure("file-tools", [me], start_after=0)
        out = await _call("a4a_send_file", {"to_pubkey": me, "blob_path": str(blob_path),
                                            "url": "https://files.example/akt", "mime": "application/pdf"})
        assert "sent" in out and "key was removed" in out
        # The wire must contain no plaintext key, name, hash, or address.
        wire = json.dumps(relay.events, ensure_ascii=False)
        stored = json.loads((tmp_path / ".a4a" / "file-keys.json").read_text(encoding="utf-8"))
        assert sha not in stored, "the key was not removed after sending"
        assert sha not in wire and "akt.pdf" not in wire and "files.example" not in wire
        # A repeated send has no key left and must report that explicitly.
        again = await _call("a4a_send_file", {"to_pubkey": me, "blob_path": str(blob_path),
                                              "url": "https://files.example/akt"})
        assert "No key" in again and "a4a_encrypt_file" in again
        # The recipient, which is us here, sees only a fail-closed placeholder. No URL,
        # internal fields, or network next step reaches the model.
        inbox = await _call("a4a_read_private", {})
        _assert_reference_hidden(inbox, "akt.pdf", sha, "files.example/akt")
        # A pre-existing local blob supplied by the owner outside MCP can still be
        # verified and opened without retrieving anything from the inbound reference.
        out_path = tmp_path / "\u043F\u043E\u043B\u0443\u0447\u0435\u043D\u043E.pdf"
        opened = await _call("a4a_open_file", {"blob_path": str(blob_path),
                                               "out_path": str(out_path)})
        assert "written" in opened and out_path.read_bytes() == DATA
        # Never overwrite an existing output file.
        assert "already exists" in await _call(
            "a4a_open_file", {"blob_path": str(blob_path), "out_path": str(out_path)})


async def test_open_reports_what_it_searched_when_reference_is_missing(mcp_home, monkeypatch,
                                                                        tmp_path):
    _, blob_path, _ = await _encrypt(tmp_path)
    sha = files.sha256_hex(blob_path.read_bytes())
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        me = identity.load_or_create_identity().pubkey_hex
        inbox_runtime.configure("file-tools", [me], start_after=0)
        out = await _call("a4a_open_file", {"blob_path": str(blob_path),
                                            "out_path": str(tmp_path / "x"), "since_days": 7})
    assert sha in out and "last 7 days" in out and "messages inspected: 0" in out
    assert "\u0441\u043A\u0430\u0447" not in out.casefold()
    assert not (tmp_path / "x").exists()


async def test_tampered_blob_does_not_open(mcp_home, monkeypatch, tmp_path):
    _, blob_path, _ = await _encrypt(tmp_path)
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        me = identity.load_or_create_identity().pubkey_hex
        inbox_runtime.configure("file-tools", [me], start_after=0)
        await _call("a4a_send_file", {"to_pubkey": me, "blob_path": str(blob_path),
                                      "url": "ipfs://QmAkt"})
        # A substituted blob has another SHA-256, so no reference is found for it.
        # Substitution while keeping the reference is impossible without a new hash.
        # Verify both layers: (1) an unrelated blob finds no reference; (2) tampering
        # inside the blob with a supplied reference fails the AEAD tag in open_file.
        blob = blob_path.read_bytes()
        bad = blob[:-1] + bytes([blob[-1] ^ 1])
        bad_path = tmp_path / "bad.a4a"
        bad_path.write_bytes(bad)
        out = await _call("a4a_open_file", {"blob_path": str(bad_path),
                                            "out_path": str(tmp_path / "y")})
        assert "No incoming file reference" in out
        async with Agent([relay.url], identity.load_or_create_identity()) as reader:
            ref = files.parse_file_reference((await reader.read_private_messages())[0]["content"])
    with pytest.raises(files.FileCryptoError):
        files.open_file(bad, {**ref, "sha256": files.sha256_hex(bad)})


async def test_send_refuses_internal_or_plain_http_url_before_publishing(mcp_home, monkeypatch,
                                                                         tmp_path):
    _, blob_path, _ = await _encrypt(tmp_path)
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        identity.load_or_create_identity()
        inbox_runtime.configure("file-tools", ["c" * 64], start_after=0)
        for url in ("http://files.example/akt", "https://127.0.0.1/akt", "file:///etc/passwd"):
            out = await _call("a4a_send_file", {"to_pubkey": "c" * 64,
                                                "blob_path": str(blob_path), "url": url})
            assert "was rejected" in out, url
        assert [e for e in relay.events if e["kind"] in (31033, 1059)] == []
    sha = files.sha256_hex(blob_path.read_bytes())
    stored = json.loads((tmp_path / ".a4a" / "file-keys.json").read_text(encoding="utf-8"))
    assert sha in stored, "the key must remain when nothing was sent"


async def test_relay_refusal_on_send_file_keeps_the_key(mcp_home, monkeypatch, tmp_path):
    _, blob_path, _ = await _encrypt(tmp_path)
    sha = files.sha256_hex(blob_path.read_bytes())
    async with FakeRelay(reject_reason="blocked: delegation required for kind 1059") as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        identity.load_or_create_identity()
        inbox_runtime.configure("file-tools", ["c" * 64], start_after=0)
        out = await _call("a4a_send_file", {"to_pubkey": "c" * 64, "blob_path": str(blob_path),
                                            "url": "https://files.example/akt"})
    assert "relay rejected publication" in out
    stored = json.loads((tmp_path / ".a4a" / "file-keys.json").read_text(encoding="utf-8"))
    assert sha in stored, "the key must remain after relay rejection so sending can retry"


def _gateway_stub(monkeypatch, status=201, reason=""):
    """Stand in for the file gateway at the HTTP layer and record what reached it."""
    import httpx
    from a4a import file_gateway
    seen = []

    def handler(request):
        seen.append(request)
        if status >= 400:
            return httpx.Response(status, text=reason)
        return httpx.Response(status, json={"sha256": files.sha256_hex(request.content),
                                            "status": "stored"})

    monkeypatch.setattr(file_gateway, "_client", lambda client: (
        httpx.AsyncClient(transport=httpx.MockTransport(handler)), True))
    return seen


async def test_send_without_url_uploads_through_the_configured_gateway(mcp_home, monkeypatch,
                                                                      tmp_path):
    """The sender no longer uploads by hand: one call encrypts-then-uploads-then-sends."""
    _, blob_path, _ = await _encrypt(tmp_path)
    blob = blob_path.read_bytes()
    sha = files.sha256_hex(blob)
    seen = _gateway_stub(monkeypatch)
    sent = {}
    original = Agent.deliver_with_ack

    async def recording(self, to_pubkey, content, **kwargs):
        sent.update(files.parse_file_reference(content))
        return await original(self, to_pubkey, content, **kwargs)

    monkeypatch.setattr(Agent, "deliver_with_ack", recording)
    monkeypatch.setenv("A4A_FILE_GATEWAY", "https://files.test")
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        me = identity.load_or_create_identity().pubkey_hex
        inbox_runtime.configure("file-tools", [me], start_after=0)
        out = await _call("a4a_send_file", {"to_pubkey": me, "blob_path": str(blob_path)})
    assert "sent" in out, out
    assert len(seen) == 1 and seen[0].method == "PUT"
    assert str(seen[0].url) == f"https://files.test/v1/blobs?recipient={me}"
    assert seen[0].content == blob and seen[0].headers["Authorization"].startswith("Nostr ")
    assert sent["url"] == f"https://files.test/v1/blobs/{sha}" and sent["sha256"] == sha
    # The reference is a delivery like any letter: journaled, with a delivery_id.
    from a4a_mcp import outbox_runtime
    assert "delivery_id=" in out
    assert len(outbox_runtime.list_records()) == 1


async def test_send_without_url_and_without_a_gateway_sends_nothing(mcp_home, monkeypatch,
                                                                   tmp_path):
    _, blob_path, _ = await _encrypt(tmp_path)
    sha = files.sha256_hex(blob_path.read_bytes())
    monkeypatch.delenv("A4A_FILE_GATEWAY", raising=False)
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        me = identity.load_or_create_identity().pubkey_hex
        inbox_runtime.configure("file-tools", [me], start_after=0)
        out = await _call("a4a_send_file", {"to_pubkey": me, "blob_path": str(blob_path)})
        assert relay.events == [] or all(e.get("kind") != 1059 for e in relay.events)
    assert "A4A_FILE_GATEWAY" in out
    stored = json.loads((tmp_path / ".a4a" / "file-keys.json").read_text(encoding="utf-8"))
    assert sha in stored, "nothing was sent, so the key must stay"


async def test_a_gateway_refusal_is_reported_and_keeps_the_key(mcp_home, monkeypatch, tmp_path):
    _, blob_path, _ = await _encrypt(tmp_path)
    sha = files.sha256_hex(blob_path.read_bytes())
    _gateway_stub(monkeypatch, status=403, reason="sender is not allowed to upload")
    monkeypatch.setenv("A4A_FILE_GATEWAY", "https://files.test")
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        me = identity.load_or_create_identity().pubkey_hex
        inbox_runtime.configure("file-tools", [me], start_after=0)
        out = await _call("a4a_send_file", {"to_pubkey": me, "blob_path": str(blob_path)})
    assert "403" in out and "sender is not allowed to upload" in out
    stored = json.loads((tmp_path / ".a4a" / "file-keys.json").read_text(encoding="utf-8"))
    assert sha in stored


def _gateway_store(monkeypatch):
    """A stand-in gateway that keeps uploaded blobs and serves them back by name."""
    import httpx
    from a4a import file_gateway
    stored, seen = {}, []

    def handler(request):
        seen.append(request)
        if request.method == "PUT":
            digest = files.sha256_hex(request.content)
            stored[digest] = request.content
            return httpx.Response(201, json={"sha256": digest, "status": "stored"})
        digest = request.url.path.rsplit("/", 1)[-1]
        if digest in stored:
            return httpx.Response(200, content=stored[digest])
        return httpx.Response(404, text="blob not found")

    monkeypatch.setattr(file_gateway, "_client", lambda client: (
        httpx.AsyncClient(transport=httpx.MockTransport(handler)), True))
    return stored, seen


async def test_a_gateway_attachment_is_named_by_handle_and_opened_on_request(
        mcp_home, monkeypatch, tmp_path):
    """The model sees a handle, never an address; opening fetches only from our gateway."""
    _, blob_path, _ = await _encrypt(tmp_path)
    sha = files.sha256_hex(blob_path.read_bytes())
    stored, seen = _gateway_store(monkeypatch)
    monkeypatch.setenv("A4A_FILE_GATEWAY", "https://files.test")
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        me = identity.load_or_create_identity().pubkey_hex
        inbox_runtime.configure("file-tools", [me], start_after=0)
        assert "sent" in await _call("a4a_send_file",
                                     {"to_pubkey": me, "blob_path": str(blob_path)})
        blob_path.unlink()  # the recipient has no local copy; the gateway has one
        inbox = await _call("a4a_read_private", {})
        assert f"attachment={sha}" in inbox and "files.test" not in inbox
        out_path = tmp_path / "received.pdf"
        opened = await _call("a4a_open_file", {"attachment": sha, "out_path": str(out_path)})
    assert "written" in opened, opened
    assert out_path.read_bytes() == DATA
    assert [r.method for r in seen] == ["PUT", "GET"]
    assert str(seen[1].url) == f"https://files.test/v1/blobs/{sha}"
    assert seen[1].headers["Authorization"].startswith("Nostr ")


async def test_an_attachment_on_a_foreign_gateway_is_never_fetched(mcp_home, monkeypatch,
                                                                   tmp_path):
    """A reference naming somebody else's server gets the old placeholder and no request."""
    _, blob_path, _ = await _encrypt(tmp_path)
    sha = files.sha256_hex(blob_path.read_bytes())
    _stored, seen = _gateway_store(monkeypatch)
    monkeypatch.setenv("A4A_FILE_GATEWAY", "https://files.test")
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        me = identity.load_or_create_identity().pubkey_hex
        inbox_runtime.configure("file-tools", [me], start_after=0)
        await _call("a4a_send_file", {"to_pubkey": me, "blob_path": str(blob_path),
                                      "url": f"https://elsewhere.test/v1/blobs/{sha}"})
        inbox = await _call("a4a_read_private", {})
        assert f"attachment={sha}" not in inbox
        out = await _call("a4a_open_file", {"attachment": sha,
                                            "out_path": str(tmp_path / "x.pdf")})
    assert seen == [] and not (tmp_path / "x.pdf").exists()
    assert "not on a configured file gateway" in out


async def test_gateway_save_does_not_overwrite_a_destination_created_during_fetch(
        mcp_home, monkeypatch, tmp_path):
    """The preflight check is not an exclusive write: another process can win later."""
    from a4a import file_gateway
    _, blob_path, _ = await _encrypt(tmp_path)
    sha = files.sha256_hex(blob_path.read_bytes())
    _gateway_store(monkeypatch)
    monkeypatch.setenv("A4A_FILE_GATEWAY", "https://files.test")
    destination = tmp_path / "concurrent-output.pdf"
    existing = b"another process already saved this file"
    original_fetch = file_gateway.fetch

    async def fetched_before_other_writer(*args, **kwargs):
        blob = await original_fetch(*args, **kwargs)
        destination.write_bytes(existing)
        return blob

    monkeypatch.setattr(file_gateway, "fetch", fetched_before_other_writer)
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        me = identity.load_or_create_identity().pubkey_hex
        inbox_runtime.configure("file-tools", [me], start_after=0)
        assert "sent" in await _call("a4a_send_file",
                                     {"to_pubkey": me, "blob_path": str(blob_path)})
        result = await _call("a4a_open_file", {"attachment": sha, "out_path": str(destination)})
    assert destination.read_bytes() == existing
    assert "already exists" in result and "will not be overwritten" in result


def test_cli_file_status_reports_what_the_gateway_says(mcp_home, monkeypatch, capsys):
    """The sender sees fetched / expired_unfetched without asking the recipient."""
    import httpx
    from a4a import file_gateway
    from a4a_mcp.__main__ import _inbox_admin
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json={"sha256": "d" * 64, "status": "expired_unfetched"})

    monkeypatch.setattr(file_gateway, "_client", lambda client: (
        httpx.AsyncClient(transport=httpx.MockTransport(handler)), True))
    monkeypatch.setenv("A4A_FILE_GATEWAY", "https://files.test")
    identity.load_or_create_identity()
    _inbox_admin(["file-status", "--sha256", "d" * 64])
    assert '"expired_unfetched"' in capsys.readouterr().out
    assert str(seen[0].url) == f"https://files.test/v1/blobs/{'d' * 64}/status"


def test_cli_file_status_without_a_gateway_says_so(mcp_home, monkeypatch):
    from a4a_mcp.__main__ import _inbox_admin
    monkeypatch.delenv("A4A_FILE_GATEWAY", raising=False)
    with pytest.raises(SystemExit, match="A4A_FILE_GATEWAY"):
        _inbox_admin(["file-status", "--sha256", "d" * 64])
