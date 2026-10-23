"""Ambient settings and guarded children: only fixtures choose test destinations.

Two distinct mechanisms can silently redirect a test run.

First, the environment. The product reads seventeen variables, several of which
change its destination or storage. A variable left in a developer shell can redirect
the run silently, while the default `A4A_HOME` points at the owner's real identity
directory. Tests therefore verify WHERE the product actually connects, not merely
that a value changed. Comparing values proves only that something was rewritten, not
that the destination changed.

Second, child processes. In-memory monkeypatches are not inherited. We can protect
only Python children that we launch ourselves: each installs the boundary in its own
process before importing product code, then proves readiness with a handshake.
External executables are out of scope, and this suite asserts that limitation
explicitly so it is documented rather than implied.
"""
import importlib.util
import json
import socket
import subprocess
import time
from pathlib import Path

import ambient
import guarded_child
import network_guard
import pytest

#: The four checks below launch a child that imports `a4a_mcp`, which reads the
#: environment, allows relay endpoints, and chooses the identity directory. An
#: SDK-only environment lacks that package. Before 2026-09-08 such a run produced
#: four failures saying only that the child did not print a line, describing a
#: symptom rather than the cause. There is nothing to guard when MCP is absent.
#: Project convention requires an explained skip (see integration skips in
#: conftest.py) that identifies the missing dependency and how to enable it.
needs_mcp = pytest.mark.skipif(
    importlib.util.find_spec("a4a_mcp") is None,
    reason=("the child imports a4a_mcp, but this environment contains only the SDK. "
            "This is not a product failure: install MCP with the same interpreter "
            "using `pip install -e ./mcp-server` to run this check."))

#: Fully poisoned configuration: a primary relay, a secondary relay, and its duplicate.
POISON = ("ws://poison-primary.invalid:9/x,"
          "ws://127.0.0.1:31337/secondary,"
          "ws://127.0.0.1:31337/secondary")

#: Build child code line by line. Combining escaped literals is an easy way to
#: produce a newline where two literal characters were intended.
RESOLVE = "\n".join([
    "import json",
    "from a4a_mcp import server",
    'print("RESOLVED " + json.dumps(server._relay_urls()))',
])

REACH = "\n".join([
    "import json, socket",
    "from urllib.parse import urlsplit",
    "from a4a_mcp import server",
    "urls = server._relay_urls()",
    'print("RESOLVED " + json.dumps(urls))',
    "parts = urlsplit(urls[0])",
    "socket.socket().connect((parts.hostname, parts.port))",
    'print("REACHED")',
])


def _line(result, prefix: str) -> str:
    for line in result.stdout.decode("utf-8", "replace").splitlines():
        if line.startswith(prefix):
            return line[len(prefix):].strip()
    raise AssertionError(f"child did not print line {prefix!r}; output: "
                         f"{result.stdout.decode('utf-8', 'replace')[:400]}")


@pytest.fixture
def listener():
    """A fixture-owned listener: the only valid destination below."""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    network_guard.allow("127.0.0.1", port)
    yield port
    network_guard.forget("127.0.0.1", port)
    server.close()


@needs_mcp
def test_poisoned_relay_configuration_does_not_change_destinations():
    """A poisoned primary, secondary, and duplicate cannot change destinations.

    REAL product code (`server._relay_urls`) allows the destination, not the test;
    otherwise the check would prove only that the test itself did not connect.
    Verify the endpoints that the product intends to contact rather than a rewritten
    variable, which would prove only that rewriting happened.
    """
    result = guarded_child.run_guarded(RESOLVE, env={"A4A_RELAY": POISON})
    resolved = json.loads(_line(result, "RESOLVED "))
    assert resolved, "product reported no destinations, so the check is empty"
    for url in resolved:
        assert "poison-primary.invalid" not in url and "31337" not in url, (
            f"poisoned configuration became a product destination: {resolved}")


@needs_mcp
def test_the_fixture_can_name_the_destination_and_the_child_reaches_it(listener):
    """Positive control: the product receives a fixture-supplied destination.

    Without this, "poisoning had no effect" is indistinguishable from "configuration
    does not work at all" because both make the negative test pass.
    """
    url = f"ws://127.0.0.1:{listener}"
    result = guarded_child.run_guarded(REACH, allow=[("127.0.0.1", listener)],
                                       relay=url, env={"A4A_RELAY": POISON})
    assert json.loads(_line(result, "RESOLVED ")) == [url]
    assert b"REACHED" in result.stdout, "fixture-supplied destination was unreachable"
    assert guarded_child.crossings(result) == []


def test_the_child_never_inherits_ambient_product_settings():
    """Never pass ambient product settings to a child."""
    code = "\n".join([
        "import json, os",
        "names = sorted(k for k in os.environ",
        '               if k.startswith("A4A_") and not k.startswith("A4A_CHILD_"))',
        'print("SEEN " + json.dumps(names))',
    ])
    result = guarded_child.run_guarded(
        code, env={"A4A_RELAY": POISON, "A4A_TRUSTED_ISSUERS": "anyone",
                   "A4A_HEADERS_URL": "http://foreign.invalid"})
    seen = json.loads(_line(result, "SEEN "))
    assert seen == ["A4A_AGENT_HOME", "A4A_HOME"], (
        f"child inherited ambient settings: {seen}")


def test_only_one_harness_owned_setting_is_kept():
    """The exception stays a single, named setting instead of becoming a name list.

    `sanitize` removes the whole `A4A_*` family because a list of known names silently
    goes stale. One name is excused, because its owner is a test runner rather than an
    outside setting. Locking the list here means widening the guard shows up as a
    deliberate, reviewed change.
    """
    assert tuple(ambient.OWNED_BY_THE_HARNESS) == (ambient.PRIVATE_PILOT_RELAY,)
    assert ambient.OWNED_BY_THE_HARNESS[ambient.PRIVATE_PILOT_RELAY].strip()


def test_a_harness_owned_setting_never_reaches_a_child(monkeypatch):
    """Keep the exception inside the harness: the product must not inherit the address.

    The harness reads the value, and `child_environment` withholds the whole `A4A_*`
    family from launched children. Verified with a real child rather than by comparing
    strings, because the filter has to hold for a process that starts later.
    """
    code = "\n".join([
        "import json, os",
        f'print("SEEN " + json.dumps(os.environ.get({ambient.PRIVATE_PILOT_RELAY!r})))',
    ])
    monkeypatch.setenv(ambient.PRIVATE_PILOT_RELAY, "ws://127.0.0.1:12345")
    result = guarded_child.run_guarded(code)
    assert json.loads(_line(result, "SEEN ")) is None, "the harness setting reached a child"


@needs_mcp
def test_the_dangerous_default_home_points_away_from_the_owner_profile():
    """Redirect default `A4A_HOME` so a test cannot reach production keys.

    Verify this by creating an identity and inspecting its LOCATION, not by comparing
    strings. The file must appear in the run's temporary directory. If it appeared
    in the real profile, the temporary directory would remain empty and the assertion
    would fail.
    """
    code = "\n".join([
        "from a4a_mcp import identity",
        "identity.load_or_create_identity()",
        'print("WROTE " + str(identity.identity_path()))',
    ])
    result = guarded_child.run_guarded(code)
    written = Path(_line(result, "WROTE "))
    assert written.is_file(), "identity was not created, so the check proved nothing"
    assert Path(ambient.scratch_home()) in written.parents, (
        f"identity was written outside the run's temporary directory: {written}")
    assert (Path.home() / ".a4a") not in written.parents, "write reached the owner's profile"


def test_proxy_resolution_is_neutralised_inside_the_process():
    """Neutralize proxies INSIDE the process, not only in its launch environment.

    The risk is not poisoned launch variables, which are filtered before reaching
    the child, but MACHINE configuration. With an empty environment, `urllib` asks
    the Windows registry, which cannot be observed through the environment. We may
    not modify the registry, so the process must answer that query safely itself.

    The first version injected a proxy at LAUNCH and therefore tested filtering,
    not neutralization; it passed even with neutralization disabled. Here the child
    sets the variable ITSELF after sanitization, so an unpatched `getproxies` would
    observe it.
    """
    code = "\n".join([
        "import os, urllib.request",
        'os.environ["HTTP_PROXY"] = "http://foreign.invalid:8080"',
        'os.environ["HTTPS_PROXY"] = "http://foreign.invalid:8080"',
        'print("PROXIES " + repr(urllib.request.getproxies()))',
        # The registry path exists only on Windows. Make that platform dependency
        # explicit rather than hiding it behind `hasattr`.
        'registry = getattr(urllib.request, "getproxies_registry", None)',
        'print("REGISTRY " + (repr(registry()) if registry else "unsupported"))',
    ])
    result = guarded_child.run_guarded(code)
    assert _line(result, "PROXIES ") == "{}", "environment proxy was honored"
    if _line(result, "REGISTRY ") != "unsupported":
        assert _line(result, "REGISTRY ") == "{}", "machine proxy remained active"


def test_a_permitted_endpoint_reaches_the_child(listener):
    """Positive control: a child can reach an allowed endpoint.

    Without this, "the child boundary works" is indistinguishable from "nothing
    works in the child."
    """
    code = "\n".join([
        "import socket",
        f'socket.socket().connect(("127.0.0.1", {listener}))',
        'print("CONNECTED")',
    ])
    result = guarded_child.run_guarded(code, allow=[("127.0.0.1", listener)])
    assert b"CONNECTED" in result.stdout
    assert result.returncode == 0
    assert guarded_child.crossings(result) == []


def test_a_child_may_not_be_given_endpoints_the_fixtures_do_not_own():
    """A child cannot receive permissions that its fixture does not own."""
    with pytest.raises(guarded_child.ChildRefused, match="not owned by this run's fixtures"):
        guarded_child.run_guarded("pass", allow=[("127.0.0.1", 31337)])


def test_a_child_crossing_the_boundary_fails_loudly():
    """A child boundary crossing must fail loudly rather than remain private."""
    code = "\n".join([
        "import socket",
        "try:",
        '    socket.socket().connect(("192.0.2.7", 443))',
        "except Exception:",
        "    pass",
        'print("FINISHED")',
    ])
    result = guarded_child.run_guarded(code)
    assert b"FINISHED" in result.stdout, "probe did not run, so the control is empty"
    assert result.returncode == 4, f"child exited with {result.returncode}, not a denial"
    assert ("192.0.2.7", 443) in guarded_child.crossings(result)
    # The parent sees the same denial in a durable record, not only in the stream.
    assert result.guard.acknowledge() == [("192.0.2.7", 443)]


def test_the_limit_for_foreign_executables_is_written_down_not_implied():
    """State explicitly that external executables are not covered."""
    assert network_guard.SCOPE["subprocesses"].startswith("not enforced")
    assert "external executables" in guarded_child.__doc__.lower()


def test_a_poisoned_interpreter_startup_never_runs(tmp_path):
    """Isolated child startup must not execute a foreign `sitecustomize`.

    A reviewer reproduced the exploit: a `sitecustomize` injected through
    `PYTHONPATH` reached its listener BEFORE the first bootstrap line, while
    `run_guarded` returned zero without a record. Boundary readiness did not prove
    STARTUP isolation because the boundary was not yet installed.

    This probe is harmless: foreign code only writes a marker file. An isolation
    control does not need to use the network to prove its point.
    """
    poison = tmp_path / "startup"
    poison.mkdir()
    marker = tmp_path / "triggered.txt"
    (poison / "sitecustomize.py").write_text("\n".join([
        "import pathlib",
        f"pathlib.Path({str(marker)!r}).write_text('before boundary', encoding='utf-8')",
    ]), encoding="utf-8")

    result = guarded_child.run_guarded(
        'print("BODY")', env={"PYTHONPATH": str(poison)})
    assert b"BODY" in result.stdout, "child body did not run, so the control is empty"
    assert not marker.exists(), (
        "foreign startup code ran before the boundary; startup isolation failed")


@needs_mcp
def test_the_isolated_child_still_imports_the_product_and_reaches_its_endpoint(listener):
    """Positive control: an isolated child remains functional.

    Without this, "poisoning failed" is indistinguishable from "the isolated child
    cannot import anything."
    """
    code = "\n".join([
        "import socket",
        "from a4a import Agent, Keys",
        "from a4a_mcp import server",
        f'socket.socket().connect(("127.0.0.1", {listener}))',
        'print("WORKS " + str(bool(Agent and Keys and server)))',
    ])
    result = guarded_child.run_guarded(code, allow=[("127.0.0.1", listener)])
    assert _line(result, "WORKS ") == "True"
    assert result.returncode == 0
    assert guarded_child.crossings(result) == []


#: Python child launches that do NOT use `guarded_child`, with their justification.
#: This inventory makes coverage auditable: every new uncovered launch must appear
#: here with a reason rather than silently entering the suite.
OWN_BOOTSTRAP = {
    "guarded_child.py": "the helper itself",
    "test_distribution_metadata.py": "launches the `-m build` tool, which has no product network path",
    "test_docs_match_tools.py": "verifies a README command verbatim (`-I -c import ...`); wrapping would change the subject",
    "test_channel_adapter.py": "uses an isolated bootstrap with its own socket audit hook",
    "test_connect_plan.py": "uses a child audit hook; a plan may neither connect nor launch processes",
    "test_identity_continuity.py": "installs its own `_loopback_only` audit hook before product import",
    "test_inbox_lock.py": "uses `_socket_guard` under `__main__` to block sockets and name resolution",
    "test_quiet_channel_runtime.py": "uses isolated `-I` startup with its own bootstrap",
}


#: Direct interpreter launches that bypass the wrapper. Search for the LAUNCH itself,
#: not a mention of the helper elsewhere in the file: a reviewer correctly noted
#: that one use of `guarded_child` does not protect every other launch in that file.
#: Treat ANY code reference to these process-launching names as a marker, not only a
#: parenthesized call.
#:
#: The first version searched for the `sys.executable` substring, guarding spelling
#: rather than behavior: assign the interpreter to a variable and it stayed silent.
#: The second required a parenthesized call and missed aliases (`runner =
#: subprocess.run`, then `runner([...])`) and passing the function as a value
#: (`to_thread(subprocess.run, ...)`). Targeted controls confirmed that both launches
#: passed SILENTLY, so the guard failed open.
#:
#: Keep the marker broad and require an explanation. A false positive costs one
#: annotation; a miss creates an unexplained path to the network.
LAUNCH_MARKS = ("subprocess.run", "subprocess.Popen", "subprocess.check_output",  # unguarded-launch: marker inventory
                "subprocess.check_call", "subprocess.call", "create_subprocess_exec")  # unguarded-launch: marker inventory

#: Annotation for an intentional unguarded launch. Put the reason AT THE LAUNCH,
#: not in a distant inventory that can become stale unnoticed.
ALLOWED_MARK = "unguarded-launch:"

def _code_part(line: str) -> str:
    """Return a line without its trailing comment.

    Otherwise a launch marker MENTIONED in an explanation would raise an alert where
    there is no code. A targeted check confirmed that a sample inside a comment used
    to trip the guard. That fails closed but creates noise, and noisy guards are
    eventually ignored.

    Splitting at the first hash is intentionally simple. A hash inside a string near
    a launch marker could make the check stay silent; the scenario is contrived and
    documented here rather than hidden.
    """
    return line.split("#", 1)[0]


def _raw_launches(text: str):
    """Return unannotated lines that launch a process or alias a launcher."""
    found = []
    for number, line in enumerate(text.splitlines(), 1):
        if ALLOWED_MARK in line:
            continue
        code = _code_part(line)
        if any(mark in code for mark in LAUNCH_MARKS):
            found.append(number)
    return found

def test_every_child_launcher_is_guarded_or_carries_its_reason():
    """Audit every launcher by behavior rather than spelling.

    This check has had three versions, each correcting a separate flaw.

    The first considered a file covered if `guarded_child` appeared once, allowing
    one protected launch to excuse every unprotected launch in the same file.

    The second matched complete lines and found NOTHING because launches span several
    lines. The check was green but empty; the self-check below caught this.

    The third searched for the `sys.executable` substring. It stayed silent when the
    interpreter was assigned to a variable and raised on irrelevant spelling, so it
    guarded text rather than behavior. The current check finds process launchers.

    External executables are not excluded. They are outside the boundary, which is
    exactly why every such launch must identify itself. A limit documented in one
    place becomes stale; a limit stated at every door does not.
    """
    root = Path(__file__).resolve().parents[2]
    offenders = []
    seen_any = 0
    for suite in ("sdk-python", "mcp-server", "notary", "agent-service", "file-gateway"):
        for path in sorted((root / suite / "tests").glob("*.py")):
            text = path.read_text(encoding="utf-8")
            if path.name in OWN_BOOTSTRAP:
                # Also prove that detection works at all: these files contain
                # launches by construction. Without this cross-check, "no offenders"
                # could mean "nothing detected," and the states would be indistinguishable.
                seen_any += len(_raw_launches(text))
                continue
            for number in _raw_launches(text):
                offenders.append(f"{suite}/tests/{path.name}:{number}")
    assert seen_any >= 3, (
        f"launch marker found only {seen_any} occurrences in files known to contain them; "
        f"the check is ineffective rather than clean")
    assert not offenders, (
        "these process launches are unexplained: "
        f"{offenders}. Route them through `guarded_child` or annotate the line with "
        f"`{ALLOWED_MARK} reason`.")

def test_the_reasons_list_does_not_outlive_its_files():
    """An exception whose file vanished is stale policy, not protection."""
    root = Path(__file__).resolve().parents[2]
    known = {path.name for suite in ("sdk-python", "mcp-server", "notary", "agent-service", "file-gateway")
             for path in (root / suite / "tests").glob("*.py")}
    stale = sorted(set(OWN_BOOTSTRAP) - known)
    assert not stale, f"reason inventory contains missing files: {stale}"

# -- MODULE-launch path controls --------------------------------------------
# A reviewer found three gaps in the first implementation; each has a dedicated
# control. The subject is `child_probe`, not the product, because this tests the
# wrapper and should not depend on an installed tool server.


def _module(tmp_path, action, allow=(), extra=None):
    marker = tmp_path / "telo.txt"
    argv, env, ready = guarded_child.module_command(
        ["-m", "child_probe"], allow=allow, tmp_path=tmp_path / "startup",
        env={"PROBE_ACTION": action, "PROBE_MARKER": str(marker), **(extra or {})})
    return argv, env, ready, marker


def test_a_module_child_reports_its_boundary_crossings(tmp_path, listener):
    """A denial CAUGHT by product code must still reach the child's outcome.

    The first version never inspected violations at exit. The child caught the
    denial, printed its own output, and exited zero. A silent boundary crossing is
    no better than silent external access; the attempt must be reported.
    """
    argv, env, ready, marker = _module(
        tmp_path, "connect",
        extra={"PROBE_HOST": "192.0.2.11", "PROBE_PORT": "443"})
    result = subprocess.run(argv, env=env, capture_output=True, timeout=60)  # unguarded-launch: argv comes from module_command
    ready.check()
    assert b"PROBE caught" in result.stdout, "probe did not run, so the control is empty"
    assert result.returncode == 4, f"child exited with {result.returncode}, not a denial"
    # The record is written AT DENIAL TIME, so the parent can read it regardless of
    # how the child ended: normal return, forced termination, or a silent crash.
    assert ready.acknowledge() == [("192.0.2.11", 443)]


def test_a_broken_setup_never_lets_the_product_run(tmp_path):
    """Setup failure must block the PRODUCT, not report after product actions.

    The boundary used to be installed through `sitecustomize`, which failed open:
    Python printed "Error in sitecustomize" and CONTINUED executing the module. A
    dedicated probe confirmed that the body ran and returned zero. Handshake failure
    arrived after product actions, which was too late.
    """
    argv, env, ready, marker = _module(tmp_path, "mark")
    env = {**env, "A4A_CHILD_ALLOWED": "not json"}
    result = subprocess.run(argv, env=env, capture_output=True, timeout=60)  # unguarded-launch: argv comes from module_command
    assert not marker.exists(), "product ran after setup failure"
    assert result.returncode == 5, f"child exited with {result.returncode}, not a denial"
    assert b"GUARD-FAILED" in result.stderr
    with pytest.raises(guarded_child.ChildRefused):
        ready.check()
    # Auditing never started in this child; that is failure, not cleanliness.
    assert not ready.audited()
    ready.acknowledge()


def test_a_module_child_reaches_its_permitted_endpoint(tmp_path, listener):
    """Positive control: a module child can reach an allowed endpoint cleanly.

    Without this, "the child could do nothing" is indistinguishable from "the
    boundary works."
    """
    argv, env, ready, marker = _module(
        tmp_path, "connect", allow=[("127.0.0.1", listener)],
        extra={"PROBE_HOST": "127.0.0.1", "PROBE_PORT": str(listener)})
    result = subprocess.run(argv, env=env, capture_output=True, timeout=60)  # unguarded-launch: argv comes from module_command
    ready.check()
    assert b"PROBE connected" in result.stdout
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
    assert marker.exists()


def test_readiness_refuses_a_child_that_died_before_confirming(tmp_path):
    """A child death must fail immediately rather than wait for a timeout.

    A wait that ends only on timeout turns a clear failure into a hang and loses
    the reason.
    """
    argv, env, ready, marker = _module(tmp_path, "mark")
    env = {**env, "A4A_CHILD_ALLOWED": "not json"}
    proc = subprocess.Popen(argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)  # unguarded-launch: argv comes from module_command
    started = time.monotonic()
    try:
        with pytest.raises(guarded_child.ChildRefused, match="exited before proving"):
            ready.wait(proc, timeout=30)
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.communicate(timeout=10)
    assert time.monotonic() - started < 20, "denial waited instead of failing immediately"
    assert not ready.audited(), "audit started for a child that died before setup"
    ready.acknowledge()

def test_a_terminated_child_still_reports_what_it_did(tmp_path, listener):
    """A violation record must survive FORCED child termination.

    The parent normally terminates a long-lived child itself. Exit-time reporting
    vanishes with such termination because the child never gets to report. The
    record is therefore written at denial time.
    """
    argv, env, ready, marker = _module(
        tmp_path, "connect",
        extra={"PROBE_HOST": "192.0.2.14", "PROBE_PORT": "443", "PROBE_HOLD": "1"})
    proc = subprocess.Popen(argv, env=env, stdout=subprocess.PIPE,  # unguarded-launch: argv comes from module_command
                            stderr=subprocess.PIPE)
    try:
        ready.wait(proc, timeout=30)
        deadline = time.monotonic() + 30
        while not ready.crossings() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert ready.crossings(), "child never reached denial, so the control is empty"
    finally:
        proc.kill()
        proc.communicate(timeout=10)
    assert ready.acknowledge() == [("192.0.2.14", 443)], (
        "forced termination erased the violation record")

def test_a_body_child_that_exits_abruptly_still_reports_its_denial():
    """Track a code-body child that catches denial and uses `os._exit`.

    This is not hypothetical. A real product check terminates with code 23 to verify
    that storage survives sudden death. Before code-body launches were audited, a
    caught violation in that check disappeared without a trace.
    """
    code = chr(10).join([
        "import os, socket",
        "try:",
        '    socket.socket().connect(("192.0.2.21", 443))',
        "except Exception:",
        "    pass",
        "os._exit(23)",
    ])
    result = guarded_child.run_guarded(code)
    assert result.returncode == 23, "probe did not terminate itself; control is empty"
    assert result.guard.audited(), "audit did not start"
    assert result.guard.acknowledge() == [("192.0.2.21", 443)], (
        "abrupt exit erased the violation record")


def test_a_broken_audit_is_never_reported_as_clean(tmp_path):
    """A failed audit write is failure, not cleanliness.

    A reviewer broke opening the child's audit file. Denial occurred, the child
    reported it and exited with code 4, but the parent saw no records and considered
    it clean. No records and no violations are different states; confusing them here
    is especially dangerous because the confusion produces a green result.
    """
    argv, env, ready, marker = _module(tmp_path, "mark")
    # Point auditing at a DIRECTORY so opening for write fails. Setup must fail
    # closed rather than continue without auditing.
    broken = tmp_path / "unwritable-target"
    broken.mkdir()
    env = {**env, "A4A_CHILD_VIOLATIONS": str(broken)}
    result = subprocess.run(argv, env=env, capture_output=True, timeout=60)  # unguarded-launch: argv comes from module_command
    assert not marker.exists(), "product ran despite unavailable auditing"
    assert result.returncode == 5, f"child exited with {result.returncode}, not a denial"
    assert not ready.audited(), "audit was reported active even though it could not start"
    with pytest.raises(AssertionError, match="violation audit"):
        ready.assert_clean()
    ready.acknowledge()

@pytest.mark.parametrize("breakage, expected", [("error", "OSError"), ("zero", "zero-length")],
                         ids=["write-error", "zero-length-write"])
def test_an_audit_that_breaks_mid_flight_is_never_reported_as_clean(tmp_path, breakage, expected):
    """Auditing that fails AFTER startup must not look clean.

    The "audit started" marker already exists while later records cannot arrive. A
    reviewer reproduced both failures: a write error and a zero-length write. The
    latter was worse because the first implementation ignored the byte count, so it
    left neither a failure trace nor the violation itself.
    """
    argv, env, ready, marker = _module(
        tmp_path, "connect",
        extra={"PROBE_HOST": "192.0.2.31", "PROBE_PORT": "443",
               "PROBE_BREAK_AUDIT": breakage})
    result = subprocess.run(argv, env=env, capture_output=True, timeout=60)  # unguarded-launch: argv comes from module_command
    ready.note_exit(result.returncode)

    assert result.returncode == ready.AUDIT_BROKEN, (
        f"child exited with {result.returncode}, not the broken-audit code")
    assert b"GUARD-AUDIT-BROKEN" in result.stderr
    assert ready.broken_flag.exists(), "audit failure marker was not written"
    assert expected in ready.broken_flag.read_text(encoding="utf-8")
    assert ready.crossings() == [], "record succeeded, so the probe did not reproduce failure"
    with pytest.raises(AssertionError, match="failed"):
        ready.assert_clean()
    ready.acknowledge()


def test_a_healthy_child_and_an_intentional_crash_stay_clean(tmp_path):
    """Positive control for both a healthy exit and an intentional crash.

    Without this, "the boundary detects failure" is indistinguishable from "the
    boundary always fails." Intentional process termination is a normal test
    technique and remains CLEAN when no violation occurred; a nonzero code alone
    does not mean auditing failed.
    """
    argv, env, ready, marker = _module(tmp_path, "mark")
    result = subprocess.run(argv, env=env, capture_output=True, timeout=60)  # unguarded-launch: argv comes from module_command
    ready.note_exit(result.returncode)
    assert result.returncode == 0 and marker.exists()
    ready.assert_clean()

    crash = guarded_child.run_guarded(chr(10).join([
        "import os",
        'print("BODY")',
        "os._exit(23)",
    ]))
    assert crash.returncode == 23, "probe did not terminate itself; control is empty"
    crash.guard.assert_clean()
