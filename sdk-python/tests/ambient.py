"""Sanitize ambient state so test runs do not depend on outside settings.

Why. The product reads seventeen `A4A_*` variables, including ones that change the
RECIPIENT or storage location: `A4A_RELAY` controls where to connect; `A4A_HOME` and
`A4A_AGENT_HOME` locate the owner's identity; `A4A_HEADERS_URL` selects the block-
header source; and `A4A_TELEGRAM_TOKEN` selects the message destination. One variable
left in a developer shell is enough to send a test somewhere other than its stated
target, while the run still looks ordinary.

The most dangerous case is not an override but the DEFAULT. `A4A_RELAY` defaults to
a live public relay. A test that forgets to inject an address targets production;
only a network boundary can reveal this, and only if one is installed. Removing the
variables makes failure deterministic across machines instead of shell-dependent.

Proxies are a separate, worse case. `urllib` reads them from the environment and,
when none are present, FROM THE WINDOWS REGISTRY. A setting invisible in the process
environment can therefore route test requests through an outside host. We must not
modify the owner's registry, so proxy discovery is neutralized INSIDE this process.

One exception exists and is listed rather than implied: `OWNED_BY_THE_HARNESS` names a
variable whose owner is a test runner instead of an outside setting, with the reason it
is safe. It is still withheld from product children.

This cleanup explicitly does NOT touch global settings, owner profiles, the firewall,
or unrelated programs. It removes variables only from THIS process's memory and the
future children that inherit it.
"""
from __future__ import annotations

import os
import shutil
import tempfile

#: Product variable prefixes. Remove the whole family rather than known names; a name
#: list would silently become stale when the first new variable is added. The one
#: exception is a HARNESS-owned setting (below), kept as an excused entry with its own
#: reason rather than folded into a prefix rule.
_PRODUCT_PREFIXES = ("A4A_",)

#: Proxy variables in every spelling understood by `urllib`.
_PROXY_NAMES = tuple(
    name + case for name in ("http_proxy", "https_proxy", "ftp_proxy", "all_proxy",
                             "no_proxy", "ws_proxy", "wss_proxy")
    for case in ("",)
) + tuple(name.upper() for name in ("http_proxy", "https_proxy", "ftp_proxy",
                                    "all_proxy", "no_proxy", "ws_proxy", "wss_proxy"))

#: Variables that cannot simply be REMOVED because their defaults are more dangerous
#: than any value. `A4A_HOME` defaults to `~/.a4a`, the owner's real identity directory.
#: It exists and contains live keys. A test that forgot to inject a path could read or
#: write them, so redirect these variables to a disposable directory instead.
_REDIRECTED = ("A4A_HOME", "A4A_AGENT_HOME")

#: The address that `scripts/local-relay-safety-check.py` hands to
#: `mcp-server/tests/test_private_pilot.py::test_private_pilot_on_disposable_relay`.
PRIVATE_PILOT_RELAY = "A4A_LOCAL_PRIVATE_PILOT_RELAY"

#: The only ambient names a test HARNESS owns, and the reason each one is kept.
#:
#: This is deliberately not the "known names" list the prefix rule exists to avoid. It
#: holds one entry, a test locks it, and adding a second name is a reviewed change,
#: because a name here survives into the test process.
#:
#: `PRIVATE_PILOT_RELAY` qualifies because its owner is that runner and nothing else:
#: the runner creates a throwaway relay, waits for `/v1/health`, and passes the address
#: so ONE test can rehearse against that exact node. The test's `_local_relay` accepts
#: only `ws://127.0.0.1:<port>`, so even a shell that sets the variable cannot name a
#: remote node, and `child_environment` still withholds it from product children.
OWNED_BY_THE_HARNESS = {
    PRIVATE_PILOT_RELAY: "address of the disposable relay owned by "
                         "scripts/local-relay-safety-check.py",
}

_removed: dict[str, str] = {}
_scratch: str | None = None
_sanitized = False


def sanitize() -> dict[str, str]:
    """Remove outside settings and neutralize proxy discovery.

    Call BEFORE importing the product. Some values are read at import time (for
    example, `identity.IDENTITY_DIR` is computed from `A4A_HOME` once), so removing
    a variable after import would change nothing.

    Return removed values so the run can report them instead of staying silent.
    `OWNED_BY_THE_HARNESS` names are kept, and are not reported as removed, because
    the harness that reads them is the value's owner rather than an outside setting.
    """
    global _sanitized
    if _sanitized:
        return dict(_removed)

    global _scratch
    for name in list(os.environ):
        if name in OWNED_BY_THE_HARNESS:
            continue
        if name.startswith(_PRODUCT_PREFIXES) or name in _PROXY_NAMES:
            _removed[name] = os.environ.pop(name)

    # The default is more dangerous than an override: without `A4A_HOME`, the
    # product uses `~/.a4a`, which holds the owner's real identity. Redirect callers
    # that did not inject their own path to this run's disposable directory.
    _scratch = tempfile.mkdtemp(prefix="a4a-test-home-")
    for name in _REDIRECTED:
        os.environ[name] = _scratch

    import urllib.request
    # On Windows, an empty environment means "query the registry". The registry is
    # an owner-machine setting we must not change, so answer the query in-process.
    urllib.request.getproxies = lambda: {}
    urllib.request.getproxies_environment = lambda: {}
    if hasattr(urllib.request, "getproxies_registry"):
        urllib.request.getproxies_registry = lambda: {}

    _sanitized = True
    return dict(_removed)


def scratch_home() -> str | None:
    """Return the disposable directory replacing the default, or `None` before setup."""
    return _scratch


def discard_scratch_home() -> None:
    """Remove the disposable directory without ever touching the owner's real profile."""
    if _scratch:
        shutil.rmtree(_scratch, ignore_errors=True)


def removed() -> dict[str, str]:
    """Return removed settings, empty when no outside configuration was present."""
    return dict(_removed)


def child_environment(extra: dict[str, str] | None = None) -> dict[str, str]:
    """Build a child environment with only explicitly supplied outside settings.

    A child inherits the entire environment, and removed variables stay absent only
    because we deleted them BEFORE launch. This helper makes that fact explicit at
    the call site instead of leaving it implied.

    Remove `PYTHON*` variables too, especially `PYTHONPATH`, which can inject an
    outside `sitecustomize` executed BEFORE any of our code. The launcher's `-I`
    flag provides the same protection; duplication is intentional so the boundary
    does not depend on one command-line argument.

    `OWNED_BY_THE_HARNESS` names are filtered here as well: the harness may read
    them, the product must not inherit them.
    """
    env = {name: value for name, value in os.environ.items()
           if not name.startswith(_PRODUCT_PREFIXES) and name not in _PROXY_NAMES
           and not name.startswith("PYTHON")}
    for name in _REDIRECTED:
        if _scratch:
            env[name] = _scratch
    env.update(extra or {})
    return env
