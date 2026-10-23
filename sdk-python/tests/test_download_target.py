"""Validate the address BEFORE downloading a file from a network URL.

`parse_file_reference` rejects an invalid scheme and an obviously internal host, but
does not access the network, so it cannot detect a domain name that RESOLVES to an
internal address. The `send_file` docstring explicitly delegated that validation to
the caller without providing a way to perform it: every integrator would have written
their own check, and in this context "custom" checks usually mean no check at all.
"""
import pytest

from a4a.files import DownloadTargetError, resolve_download_target


def test_public_host_resolves_to_an_address():
    """A public name resolves and is returned together with its address.

    The resolver is stubbed, which is a fix rather than a simplification. The test
    previously queried real DNS for example.com: the suite stopped working offline,
    and every run sent an external request that the test boundary correctly flagged
    as escaping its perimeter. This test must verify that the function returns the
    address and name, not that an external resolver works; `_resolver` is the seam
    provided for that purpose.

    The former assertion was also a tautology: `ip and ":" not in ip or ":" in ip`
    is true for every non-empty string, so it only checked that something was returned.
    """
    ip, host = resolve_download_target("https://example.com/file.bin",
                                       _resolver=lambda name: ["93.184.216.34"])
    assert host == "example.com"
    assert ip == "93.184.216.34"


def test_hostname_resolving_into_the_perimeter_is_refused():
    """Reject a seemingly public name that resolves inside the perimeter.

    This is the primary case that `parse_file_reference` cannot detect.
    """
    with pytest.raises(DownloadTargetError):
        resolve_download_target("https://localhost/secret", _resolver=lambda h: ["127.0.0.1"])
    with pytest.raises(DownloadTargetError):
        # Any address from an RFC 1918 private range works as long as it is internal.
        # This used to contain the INTERNAL ADDRESS OF A PRODUCTION NODE: the public
        # slice readiness audit flagged it on 2026-08-28, but the fix was applied only
        # to a neighboring file and this copy would have reached the public repository.
        # The slice builder caught it on its first run (2026-08-31).
        resolve_download_target("https://looks-external.example/x",
                                _resolver=lambda h: ["10.0.0.7"])
    with pytest.raises(DownloadTargetError):
        resolve_download_target("https://cloud.example/x",
                                _resolver=lambda h: ["169.254.169.254"])


def test_mixed_answer_is_refused_entirely():
    """Reject all answers if any address is internal.

    The client chooses the address, and it may choose the unsafe one.
    """
    with pytest.raises(DownloadTargetError):
        resolve_download_target("https://mixed.example/x",
                                _resolver=lambda h: ["93.184.216.34", "127.0.0.1"])


def test_unresolvable_host_is_refused_not_silently_allowed():
    def _boom(host):
        raise OSError("cannot resolve")
    with pytest.raises(DownloadTargetError):
        resolve_download_target("https://nowhere.invalid/x", _resolver=_boom)


def test_scheme_is_checked_too():
    with pytest.raises(DownloadTargetError):
        resolve_download_target("file:///etc/passwd")
    with pytest.raises(DownloadTargetError):
        resolve_download_target("http://example.com/x")   # HTTPS only
