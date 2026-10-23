"""Malformed attachment addresses must be rejected before any network access."""
import pytest

from a4a import file_gateway, files


INVALID_URLS = [
    "https://[bad",
    "https://[::1/blob",
    "https://files.example:bad/blob",
    "https://files.example:70000/blob",
    "https://files.example:-1/blob",
    "https://files.example\uff0fother/blob",
]
DIGEST = "a" * 64


@pytest.mark.parametrize("url", INVALID_URLS)
@pytest.mark.parametrize("allow_private", [False, True])
def test_invalid_url_is_rejected_even_with_private_host_permission(url, allow_private):
    content = files.build_file_reference(url, DIGEST)
    assert files.parse_file_reference(content, allow_private_hosts=allow_private) is None
    # Explicit diagnostic parsing still returns the original reference.
    assert files.parse_file_reference(content, validate=False)["url"] == url


@pytest.mark.parametrize("url", INVALID_URLS)
def test_gateway_reference_rejects_malformed_addresses(url):
    assert file_gateway.gateway_blob(
        {"url": url, "sha256": DIGEST}, ["https://files.example"]) is None


@pytest.mark.parametrize("url", INVALID_URLS)
def test_malformed_gateway_configuration_has_a_domain_error(url):
    with pytest.raises(file_gateway.FileGatewayError) as caught:
        file_gateway.blob_url(url, DIGEST)
    assert caught.value.status == 0


@pytest.mark.parametrize("url", INVALID_URLS)
def test_invalid_download_url_is_refused_before_resolution(url):
    def forbidden(host):
        pytest.fail("an invalid URL must not reach DNS resolution")

    with pytest.raises(files.DownloadTargetError):
        files.resolve_download_target(url, _resolver=forbidden)


@pytest.mark.parametrize("origin,normalized", [
    ("https://files.example", "https://files.example"),
    ("https://files.example:443", "https://files.example"),
    ("https://files.example:8443", "https://files.example:8443"),
    ("https://[2606:4700:4700::1111]:8443", "https://[2606:4700:4700::1111]:8443"),
])
def test_valid_attachment_and_gateway_addresses_keep_working(origin, normalized):
    url = origin + "/v1/blobs/" + DIGEST
    content = files.build_file_reference(url, DIGEST)
    assert files.parse_file_reference(content)["url"] == url
    assert file_gateway.gateway_blob({"url": url, "sha256": DIGEST}, [normalized]) == DIGEST
    assert file_gateway.blob_url(origin, DIGEST) == normalized + "/v1/blobs/" + DIGEST
