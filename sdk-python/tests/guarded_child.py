"""Run child Python processes with the network boundary already installed.

The boundary lives in process memory and is not inherited. A `subprocess`
interpreter inherits the environment, but not our monkeypatches. This limitation
is stated explicitly in `network_guard.SCOPE` and cannot be fixed from inside the
process. We can protect one class of children: Python processes that we launch
ourselves. They install the boundary in their own process before importing the
product.

What IS enforced here:

* the interpreter starts in isolated mode (`-I`), so an external `PYTHONPATH`,
  the user package directory, and `PYTHON*` variables cannot affect it. Otherwise
  an inherited `sitecustomize` would run BEFORE the bootstrap and its boundary;
* the child installs the boundary and clears unrelated settings FIRST, then proves
  readiness with a one-time secret supplied by the parent. Without this handshake,
  the result is rejected outright;
* the child receives ONLY endpoints that are currently allowed in the parent. A
  request for anything else is rejected at launch rather than inside the child;
* crossing the boundary terminates the child, and the parent sees both the return
  code and the endpoint list.

What is NOT enforced is equally explicit. Startup isolation uses Python flags,
not operating-system isolation. Foreign interpreter paths and settings are
blocked, but the filesystem, kernel-level network, process privileges, and
external executables are not. `curl`, another interpreter, or any binary will not
inherit our monkeypatches and must not be treated as protected. Tests must either
forbid such launches or isolate them separately. The test run does not own the
host machine, so it must not alter owner settings, profiles, or firewall rules.
"""
from __future__ import annotations

import json
import os
import secrets
import subprocess
import tempfile
import time
import sys
from pathlib import Path

import ambient
import network_guard

_TESTS_DIR = str(Path(__file__).resolve().parent)

#: Child bootstrap. Line order is the policy: sanitize and install the boundary
#: BEFORE any product code enters the process.
_BOOTSTRAP = r'''
import json, os, sys

# Read bootstrap variables BEFORE sanitizing: sanitization removes all `A4A_*`
# variables, including these. The first implementation read them afterwards, so
# the child erased its own handshake configuration and then failed.
tests_dir = os.environ["A4A_CHILD_TESTS_DIR"]
token = os.environ["A4A_CHILD_TOKEN"]
permitted = json.loads(os.environ["A4A_CHILD_ALLOWED"])
dead = json.loads(os.environ.get("A4A_CHILD_UNREACHABLE") or "[]")
home = os.environ["A4A_CHILD_HOME"]
relay = os.environ.get("A4A_CHILD_RELAY") or ""
ready_path = os.environ["A4A_CHILD_READY"]
violations_path = os.environ["A4A_CHILD_VIOLATIONS"]
sys.path.insert(0, tests_dir)

import ambient
ambient.sanitize()
# The PARENT supplies the data directory; the child's sanitization must not create
# it. Otherwise the child would allocate an unknown temporary directory that the
# fixture neither owns nor can clean up.
os.environ["A4A_HOME"] = os.environ["A4A_AGENT_HOME"] = home
if relay:
    # The FIXTURE supplies the destination explicitly. A value inherited from
    # the parent cannot reach this point because sanitization removed it above.
    os.environ["A4A_RELAY"] = relay

import network_guard
network_guard.install()
for host, port in permitted:
    network_guard.allow(host, port)
for host, port in dead:
    network_guard.unreachable(host, port)

# --- Child violation audit -------------------------------------------------
# Open ONCE during setup and keep the handle open. The first implementation
# called `open()` on each denial; a reviewer broke that call, leaving the child
# to print GUARD-CROSSED and exit with code 4 while the parent saw no records and
# considered it clean. An audit-write failure must never look like cleanliness.
#
# Write the `open` marker immediately so the parent can prove auditing worked.
# A missing marker is failure, not evidence that no violation occurred.
_audit = open(violations_path, "a", encoding="utf-8")
_audit.write(json.dumps({"audit": "open"}) + chr(10))
_audit.flush()
os.fsync(_audit.fileno())


def _audit_broken(reason):
    # Report audit failure through TWO independent channels. The return code is
    # unavailable when another library owns the process (stdio), while a marker
    # file cannot survive a filesystem failure. Emit both and exit irreversibly.
    try:
        with open(violations_path + ".broken", "w", encoding="utf-8") as flag:
            flag.write(reason)
            flag.flush()
            os.fsync(flag.fileno())
    except BaseException:
        pass
    try:
        sys.stderr.write("GUARD-AUDIT-BROKEN " + reason + chr(10))
        sys.stderr.flush()
    except BaseException:
        pass
    os._exit(6)


def _remember(host, port):
    # Write through the ALREADY OPEN descriptor without buffering. Another
    # `open()` would add a failure point precisely where one is unacceptable.
    #
    # Check the byte count. The first implementation ignored it, allowing a short
    # or zero write to leave neither a failure marker nor a violation record.
    # An incomplete write is an audit failure, not a minor condition.
    payload = (json.dumps([host, port]) + chr(10)).encode("utf-8")
    written = 0
    try:
        while written < len(payload):
            step = os.write(_audit.fileno(), payload[written:])
            if not step:
                _audit_broken("zero-length write")
            written += step
        os.fsync(_audit.fileno())
    except BaseException as error:
        _audit_broken(type(error).__name__)


network_guard.on_denial(_remember)

leaked = [name for name in sys.modules if name == "a4a" or name.startswith(("a4a.", "a4a_"))]
if leaked:
    print("GUARD-FAILED product imported before boundary: " + ",".join(sorted(leaked)),
          flush=True)
    raise SystemExit(3)

# Use a FILE handshake just like module launches: the parent consumes child output
# at the end, but readiness must be proven before the first action. Keep the print
# for human diagnostics.
with open(ready_path, "w", encoding="utf-8") as _handshake:
    _handshake.write(token)
    _handshake.flush()
    os.fsync(_handshake.fileno())
print("GUARD-READY " + token, flush=True)

try:
    exec(compile(sys.argv[1], "<guarded-child>", "exec"), {"__name__": "__main__"})
finally:
    crossings = network_guard.unexpected()
    if crossings:
        print("GUARD-CROSSED " + json.dumps(sorted(set(crossings))), flush=True)
        os._exit(4)
'''


#: Every child launched by this test. Teardown checks them automatically because
#: callers have already proved twice that an optional check will be forgotten.
launched: list = []


def assert_all_clean() -> None:
    """Assert that no launched child crossed the boundary, then clear the list."""
    children, launched[:] = list(launched), []
    for child in children:
        child.assert_clean()


class ChildRefused(AssertionError):
    """A child failed readiness or requested an endpoint outside our fixtures."""


def run_guarded(code: str, *, allow=(), relay: str = "", env: dict | None = None,
                timeout: float = 60):
    """Execute `code` in a guarded child and return `CompletedProcess`.

    Every endpoint in `allow` must ALREADY be allowed in the parent. Granting a
    child an endpoint unavailable to us would exceed the fixture's authority.

    `relay` is a destination set EXPLICITLY by the fixture. Inherited parent
    environment has already been removed, so an external value cannot replace it:
    the destination is either declared here or absent altogether.
    """
    endpoints = [(host, int(port)) for host, port in allow]
    foreign = [pair for pair in endpoints if pair not in network_guard._allowed]
    if foreign:
        raise ChildRefused(
            f"child requested endpoints not owned by this run's fixtures: {foreign}. "
            f"Start them through a fixture before passing them to the child.")

    directory = Path(tempfile.mkdtemp(prefix="a4a-guarded-body-"))
    ready = ChildReadiness(directory / "ready.token", secrets.token_hex(16),
                           directory / "violations.jsonl")
    launched.append(ready)
    token = ready.token
    child_env = ambient.child_environment({
        "A4A_CHILD_TOKEN": token,
        "A4A_CHILD_READY": str(ready.path),
        "A4A_CHILD_VIOLATIONS": str(ready.violations),
        "A4A_CHILD_ALLOWED": json.dumps([[host, port] for host, port in endpoints]),
        "A4A_CHILD_UNREACHABLE": json.dumps(sorted([host, port] for host, port
                                                   in network_guard._unreachable)),
        "A4A_CHILD_TESTS_DIR": _TESTS_DIR,
        "A4A_CHILD_HOME": ambient.scratch_home() or _TESTS_DIR,
        "A4A_CHILD_RELAY": relay,
    })
    child_env.update(env or {})

    # `-I` isolates interpreter startup from `PYTHON*` variables and the user
    # package directory. Without it, an inherited `PYTHONPATH` can inject a
    # `sitecustomize` that executes BEFORE our bootstrap and its boundary. A
    # reviewer demonstrated this: the injected module reached its listener and
    # `run_guarded` returned zero without a record. Boundary readiness alone does
    # not prove STARTUP isolation.
    #
    # Use `-X utf8` and `-u` instead of `PYTHONIOENCODING`/`PYTHONUNBUFFERED`,
    # because isolated mode intentionally ignores those variables.
    #
    # This does NOT provide operating-system isolation. The flags protect Python
    # paths and settings, not files, kernel-level networking, or external binaries.
    result = subprocess.run([sys.executable, "-I", "-X", "utf8", "-u", "-c", _BOOTSTRAP, code],
                            env=child_env, capture_output=True, timeout=timeout)
    out = result.stdout.decode("utf-8", "replace")
    if f"GUARD-READY {token}" not in out:
        raise ChildRefused(
            "child did not prove boundary readiness with its one-time secret; "
            "its result is rejected. "
            f"Output: {out[:400]} | errors: {result.stderr.decode('utf-8', 'replace')[:400]}")
    # Track code-body children just like module children. Previously they were
    # never registered, so a body that caught a denial and used `os._exit` lost
    # its record entirely. A real product check uses exactly that pattern.
    result.guard = ready
    ready.note_exit(result.returncode)
    return result


#: Bootstrap for children launched as a MODULE (`-m a4a_mcp ...`) rather than
#: as an inline code body.
#:
#: This was originally a `sitecustomize`, which Python imports before the target
#: module. A reviewer showed that design fails open: when `sitecustomize` raises,
#: Python prints "Error in sitecustomize" and CONTINUES executing `-m`. The failure
#: was reproduced: setup raised, the body ran, and the return code was zero. Any
#: setup failure therefore launched the product without a boundary, while the
#: handshake failure arrived only AFTER product actions.
#:
#: The wrapper now launches the product through `runpy`. This is a critical
#: distinction: execution reaches `runpy` only after successful setup. The entry
#: point remains authentic because `alter_sys=True` gives the module the same
#: `sys.argv[0]` as a `-m` launch.
_MODULE_BOOTSTRAP = r"""
import json, os, sys


def _flush():
    # `os._exit` does not flush buffers, so unflushed product output would vanish.
    # Without this, tests that verify denial text receive an empty stream and make
    # the assertion appear faulty instead of the wrapper.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.flush()
        except Exception:
            pass


def _fail(reason, code):
    sys.stderr.write("GUARD-FAILED " + reason + chr(10))
    _flush()
    os._exit(code)


try:
    tests_dir = os.environ["A4A_CHILD_TESTS_DIR"]
    token = os.environ["A4A_CHILD_TOKEN"]
    ready_path = os.environ["A4A_CHILD_READY"]
    violations_path = os.environ["A4A_CHILD_VIOLATIONS"]
    permitted = json.loads(os.environ["A4A_CHILD_ALLOWED"])
    dead = json.loads(os.environ.get("A4A_CHILD_UNREACHABLE") or "[]")
    home = os.environ["A4A_CHILD_HOME"]
    relay = os.environ.get("A4A_CHILD_RELAY") or ""
    extra = json.loads(os.environ.get("A4A_CHILD_EXTRA") or "{}")
    roots = json.loads(os.environ.get("A4A_CHILD_ROOTS") or "[]")
    module = os.environ["A4A_CHILD_MODULE"]
    arguments = json.loads(os.environ["A4A_CHILD_ARGV"])

    sys.path[:0] = [tests_dir, *roots]

    import ambient
    ambient.sanitize()

    import network_guard
    network_guard.install()
    for host, port in permitted:
        network_guard.allow(host, port)
    # The child inherits endpoints that the parent DECLARED unreachable. Otherwise
    # the suite's canonical non-responsive endpoint would look like a violation:
    # the parent knows it is an expected failure, but the child would not.
    for host, port in dead:
        network_guard.unreachable(host, port)

    # --- Child violation audit ---------------------------------------------
    # Open ONCE during setup and retain the handle. The first implementation
    # called `open()` on every denial. A reviewer broke that call: the denial
    # occurred and the child printed GUARD-CROSSED and exited with code 4, yet the
    # parent saw no records and considered it clean. Audit failure cannot look clean.
    #
    # Write the `open` marker immediately so the parent can prove auditing ran.
    # A missing marker is failure, not "no violations."
    _audit = open(violations_path, "a", encoding="utf-8")
    _audit.write(json.dumps({"audit": "open"}) + chr(10))
    _audit.flush()
    os.fsync(_audit.fileno())


    def _audit_broken(reason):
        # Report audit failure through TWO independent paths. The return code is
        # unavailable when another library owns the process (stdio), while a marker
        # cannot survive a filesystem failure. Emit both and exit irreversibly.
        try:
            with open(violations_path + ".broken", "w", encoding="utf-8") as flag:
                flag.write(reason)
                flag.flush()
                os.fsync(flag.fileno())
        except BaseException:
            pass
        try:
            sys.stderr.write("GUARD-AUDIT-BROKEN " + reason + chr(10))
            sys.stderr.flush()
        except BaseException:
            pass
        os._exit(6)


    def _remember(host, port):
        # Write through the ALREADY OPEN descriptor without buffering. Reopening
        # would add a failure point precisely where one is unacceptable.
        #
        # Check the byte count. The first implementation ignored it, allowing a
        # short or zero write to leave no failure marker and no violation record.
        # An incomplete write is an audit failure, not a minor condition.
        payload = (json.dumps([host, port]) + chr(10)).encode("utf-8")
        written = 0
        try:
            while written < len(payload):
                step = os.write(_audit.fileno(), payload[written:])
                if not step:
                    _audit_broken("zero-length write")
                written += step
            os.fsync(_audit.fileno())
        except BaseException as error:
            _audit_broken(type(error).__name__)


    network_guard.on_denial(_remember)

    os.environ["A4A_HOME"] = os.environ["A4A_AGENT_HOME"] = home
    if relay:
        os.environ["A4A_RELAY"] = relay
    for name, value in extra.items():
        os.environ[name] = value

    leaked = [name for name in sys.modules
              if name == "a4a" or name.startswith(("a4a.", "a4a_"))]
    if leaked:
        _fail("product imported before boundary: " + ",".join(sorted(leaked)), 3)

    with open(ready_path, "w", encoding="utf-8") as handle:
        handle.write(token)
        handle.flush()
        os.fsync(handle.fileno())
except BaseException as error:
    _fail("setup failed: " + repr(error), 5)

import runpy

status = 0
try:
    sys.argv = ["", *arguments]
    runpy.run_module(module, run_name="__main__", alter_sys=True)
except SystemExit as stop:
    # `sys.exit("text")` prints the text only when the exception reaches the
    # interpreter. We intercept it, so print it here; otherwise product denial
    # loses its reason and the assertion appears faulty instead of the wrapper.
    if stop.code is None:
        status = 0
    elif isinstance(stop.code, int):
        status = stop.code
    else:
        sys.stderr.write(str(stop.code) + chr(10))
        status = 1
except BaseException:
    import traceback
    traceback.print_exc()
    status = 1

crossed = network_guard.unexpected()
if crossed:
    sys.stderr.write("GUARD-CROSSED " + json.dumps(sorted(set(crossed))) + chr(10))
    _flush()
    os._exit(4)
_flush()
os._exit(status)
"""


class ChildReadiness:
    """Child handshake backed by a file that only the child can write.

    The handshake used to be printed to a stream and checked by the caller when
    they remembered. A reviewer showed that callers did not: one launch stored
    the secret in a process field nobody read, while another discarded it. A
    check that can be forgotten is not a check.

    A separate file also supports long-lived children (`stdio`, `Popen`) whose
    streams are consumed only at the end: waiting for readiness through the
    stream before the first request would consume product output.
    """

    #: Dedicated, irreversible exit code for broken auditing. Product code cannot
    #: intercept it or claim it as its own result.
    AUDIT_BROKEN = 6

    def __init__(self, path: Path, token: str, violations: Path):
        self.path = path
        self.token = token
        self.violations = violations
        self.broken_flag = violations.with_name(violations.name + ".broken")
        self._process = None
        self._exit_status = None

    def attach(self, proc) -> None:
        """Attach the process so the boundary can inspect its actual outcome.

        A reviewer required the REAL exit code to reach the shared boundary: a
        documented limitation does not close the finding while code 6 is treated
        as clean. Attachment enforces this without caller participation; by test
        teardown the caller has already waited for the child and the code is known.
        """
        self._process = proc

    def note_exit(self, status) -> None:
        """Record the outcome where no process object is retained, such as `run`."""
        self._exit_status = status

    def exit_status(self):
        if self._exit_status is not None:
            return self._exit_status
        return getattr(self._process, "returncode", None)

    def _records(self) -> list:
        if not self.violations.exists():
            return []
        return [json.loads(line) for line
                in self.violations.read_text(encoding="utf-8").splitlines() if line.strip()]

    def audited(self) -> bool:
        """Return whether auditing started and was visible to the parent."""
        return any(record == {"audit": "open"} for record in self._records())

    def crossings(self) -> list:
        """Return violations recorded by the child at denial time."""
        return [tuple(record) for record in self._records() if isinstance(record, list)]

    def acknowledge(self) -> list:
        """Remove a child from automatic checks when violation is EXPECTED.

        This is only for tests of the wrapper itself that deliberately trigger a
        violation. Never use it in ordinary tests: it disables the automatic
        boundary rather than configuring it.
        """
        if self in launched:
            launched.remove(self)
        return self.crossings()

    def assert_clean(self) -> None:
        """Assert cleanliness in the PARENT, including after forced termination.

        No records does NOT imply cleanliness. A reviewer broke opening the audit
        file in the child: denial occurred, the child reported it and exited with
        code 4, yet the parent saw no records and considered the child clean. First
        prove that auditing worked; only then inspect its findings.
        """
        assert self.audited(), (
            "child violation audit did not start or is unavailable; its behavior "
            "is unknown and cannot be considered clean")
        # Auditing may fail AFTER startup, leaving the marker but losing later
        # records. Detect this through two independent paths because neither covers
        # every caller: a marker for processes owned by another library, and the
        # return code when the marker itself could not be written.
        if self.broken_flag.exists():
            try:
                reason = self.broken_flag.read_text(encoding="utf-8", errors="replace")[:200]
            except OSError as error:      # The marker may not be a regular file.
                reason = f"marker is unreadable: {error}"
            raise AssertionError(
                f"child violation audit failed during execution: {reason}")
        assert self.exit_status() != self.AUDIT_BROKEN, (
            f"child exited with code {self.AUDIT_BROKEN}: violation auditing failed, "
            f"so its behavior is unknown")
        crossed = self.crossings()
        assert not crossed, (
            f"child crossed the test-run boundary: {sorted(set(crossed))}")

    def check(self) -> None:
        """Perform an immediate check for a child that has already exited.

        There is nothing to wait for: failed setup will never create the file, so
        waiting for a timeout would only delay failure.
        """
        if not self.path.exists() or self.path.read_text(encoding="utf-8") != self.token:
            raise ChildRefused(
                "child did not prove boundary readiness; its result is rejected")

    def wait(self, proc=None, timeout: float = 30) -> None:
        """Wait for readiness and fail immediately if the child exits first."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.path.exists() and self.path.read_text(encoding="utf-8") == self.token:
                return
            if proc is not None and proc.poll() is not None:
                raise ChildRefused(
                    f"child exited before proving boundary readiness, code {proc.returncode}")
            time.sleep(0.05)
        raise ChildRefused(
            f"child did not prove boundary readiness within {timeout}s; "
            "its result is rejected")


def module_command(args, *, allow=(), relay: str = "", home: str = "",
                   source_roots=(), env: dict | None = None, tmp_path=None):
    """Prepare to launch the PRODUCT with the boundary already installed.

    Return `(argv, env, ready)`. `ready` is the handshake; callers MUST wait for it
    before the first child request, or a setup failure could remain unnoticed.

    `args` uses interpreter form: `["-m", "a4a_mcp", ...]`. The entry point is
    authentic: the same module, `__main__` name, and `sys.argv[0]`.
    """
    if len(args) < 2 or args[0] != "-m":
        raise ValueError("only module launches are supported: ['-m', '<module>', ...]")
    module, arguments = args[1], list(args[2:])

    endpoints = [(host, int(port)) for host, port in allow]
    foreign = [pair for pair in endpoints if pair not in network_guard._allowed]
    if foreign:
        raise ChildRefused(
            f"child requested endpoints not owned by this run's fixtures: {foreign}")

    directory = Path(tmp_path or tempfile.mkdtemp(prefix="a4a-guarded-child-"))
    directory.mkdir(parents=True, exist_ok=True)
    ready = ChildReadiness(directory / "ready.token", secrets.token_hex(16),
                           directory / "violations.jsonl")
    launched.append(ready)

    child_env = ambient.child_environment({
        "A4A_CHILD_TOKEN": ready.token,
        "A4A_CHILD_READY": str(ready.path),
        "A4A_CHILD_VIOLATIONS": str(ready.violations),
        "A4A_CHILD_ALLOWED": json.dumps([[host, port] for host, port in endpoints]),
        "A4A_CHILD_UNREACHABLE": json.dumps(sorted([host, port] for host, port
                                                   in network_guard._unreachable)),
        "A4A_CHILD_TESTS_DIR": _TESTS_DIR,
        "A4A_CHILD_ROOTS": json.dumps([str(root) for root in source_roots]),
        "A4A_CHILD_MODULE": module,
        "A4A_CHILD_ARGV": json.dumps(arguments),
        # The caller supplies the data directory. Default to the run's temporary
        # directory, never the owner's `~/.a4a`.
        "A4A_CHILD_HOME": home or ambient.scratch_home() or _TESTS_DIR,
        "A4A_CHILD_RELAY": relay,
        "A4A_CHILD_EXTRA": json.dumps(env or {}),
    })
    return ([sys.executable, "-I", "-X", "utf8", "-u", "-c", _MODULE_BOOTSTRAP],
            child_env, ready)


def crossings(result) -> list:
    """Return endpoints the child tried to reach outside the test boundary."""
    for line in result.stdout.decode("utf-8", "replace").splitlines():
        if line.startswith("GUARD-CROSSED "):
            return [tuple(pair) for pair in json.loads(line[len("GUARD-CROSSED "):])]
    return []
