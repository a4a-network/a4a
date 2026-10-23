"""Publication policy: what this server may release to the public network.

Why this requires a module rather than a single environment variable:

Integration testing showed that public events expose not only amounts and
addresses but also the SUBJECT of the work. That belongs to our user's customer,
not to the network. The first defense was soft: an optional parameter and a tool
description warning. The integrator rejected it with measured evidence: 25 of 30
skills were never invoked until made mandatory, showing that models retain tool
description guidance poorly. Here the model also has an incentive to violate it:
a request without detail attracts fewer offers, so perceived usefulness can
override the warning.

The restriction must therefore be a BUILD property, not a runtime preference:

* ``policy.json`` is installed beside the package while building the image. Root
  installs the package, while the server runs as UID 10001 and cannot write there;
  neither can a model limited to these tools.
* The file is read ONCE at import time. Replacing it at runtime changes nothing.
* ``A4A_PUBLIC_TEXT`` remains available but can only TIGHTEN policy. It cannot
  weaken a build restriction, or one manifest line would nullify the guarantee.

Without a build policy file, local operation remains backward compatible: the
default is ``allow`` and the environment variable can enable strict mode. The
strict image is built by ``mcp-server/Dockerfile``.
"""
import json
import os
from pathlib import Path

#: The policy file lives BESIDE THE PACKAGE, not in the agent data directory
#: (``A4A_HOME``). Tools write to the data directory during normal work, and
#: ``a4a_open_file`` accepts a model-supplied destination. A policy stored there
#: could therefore be removed with one tool call.
POLICY_FILE = Path(__file__).with_name("policy.json")

MODES = ("allow", "deny")


def _read_policy(path: Path) -> dict:
    """Return build policy or an empty mapping when no policy file exists.

    A malformed file fails startup. Silently allowing publication would let a
    build typo disable the very protection the image was built to provide.
    """
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise RuntimeError(f"build policy {path} is unreadable: {e}") from e
    if not isinstance(data, dict):
        raise RuntimeError(f"build policy {path}: expected a JSON object")
    mode = data.get("public_text", "allow")
    if mode not in MODES:
        raise RuntimeError(f"build policy {path}: public_text must be "
                           f"{' or '.join(MODES)}, got {mode!r}")
    return data


#: Read at import time: policy is an image property, not mutable process state.
BUILD_POLICY = _read_policy(POLICY_FILE)


def _env_mode() -> str | None:
    raw = os.environ.get("A4A_PUBLIC_TEXT")
    if raw is None:
        return None
    raw = raw.strip().lower()
    if raw not in MODES:
        raise ValueError(f"A4A_PUBLIC_TEXT must be {' or '.join(MODES)}, got {raw!r}")
    return raw


def locked() -> bool:
    """Return whether runtime configuration may not weaken build policy."""
    return bool(BUILD_POLICY) and BUILD_POLICY.get("locked", True)


def public_text_mode() -> str:
    """Return effective mode; ``deny`` blocks free text in public events.

    Build policy takes precedence when stricter than the environment.
    ``A4A_PUBLIC_TEXT=allow`` cannot weaken a locked ``deny`` build policy.
    """
    build = BUILD_POLICY.get("public_text", "allow") if BUILD_POLICY else "allow"
    env = _env_mode()
    if build == "deny" and locked():
        return "deny"
    if env is not None:
        return env
    return build


def source() -> str:
    """Explain the policy source so a tool refusal does not look arbitrary.

    A model must know this is an image property rather than a transient failure or
    a setting to hunt for, so it chooses a private channel instead of attempting
    to bypass the restriction.
    """
    if BUILD_POLICY.get("public_text") == "deny" and locked():
        return ("publication is denied by this server build (image policy file) "
                "and cannot be enabled from inside the process")
    if _env_mode() == "deny":
        return "publication is denied by runtime setting A4A_PUBLIC_TEXT=deny"
    return "publication is not denied"
