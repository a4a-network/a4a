"""Installer boundaries: real preserving transactions, hashes and inert refusal."""
import json
import os
from pathlib import Path
import sys
import tomllib
import zipfile

import pytest

from a4a_mcp.setup_cli import cli, select_host
from a4a_mcp.setup_hosts import apply_file_plan, host_plan, merge_proposal, rollback_file_plan
from a4a_mcp.setup_runtime import load_bundle, runtime_inventory
from a4a_mcp.setup_storage import digest, read_regular, persistent_path, child_environment


def plan_for(tmp_path, client):
    project = tmp_path / 'project with spaces'
    project.mkdir(exist_ok=True)
    return host_plan(client=client, python=Path(sys.executable),
        home=tmp_path / 'persistent identity', project=project,
        relay='ws://127.0.0.1:17404', consumer='test-client',
        config_path=tmp_path / 'Desktop/config.json' if client == 'claude-desktop' else None)


@pytest.mark.parametrize('client', ['claude-code', 'claude-desktop', 'codex', 'cursor'])
def test_transaction_preserves_other_servers_backs_up_and_repeats(tmp_path, client):
    plan = plan_for(tmp_path, client)
    path = Path(plan['host_configuration']['path'])
    path.parent.mkdir(parents=True, exist_ok=True)
    old = ('# owner comment\nmodel = "owner-model"\n[mcp_servers.other]\ncommand = "other"\n'
           if client == 'codex' else '{"mcpServers":{"other":{"command":"other"}},"owner":true,"number":0.125}')
    original = old.encode()
    path.write_bytes(original)
    state = tmp_path / 'private transactions'
    result = apply_file_plan(plan, state)
    assert result['changed'] and not result['native_tools_verified']
    parsed = tomllib.loads(path.read_text()) if client == 'codex' else json.loads(path.read_text())
    section = 'mcp_servers' if client == 'codex' else 'mcpServers'
    assert parsed[section]['other']['command'] == 'other'
    assert parsed[section]['a4a']['command'] == sys.executable
    if client == 'codex':
        assert path.read_bytes().startswith(original)
    else:
        assert parsed['owner'] and parsed['number'] == 0.125
    journal = json.loads(Path(result['transaction']).read_text())
    assert journal['state'] == 'committed'
    assert read_regular(journal['backup']) == original
    before = path.read_bytes()
    assert apply_file_plan(plan, state)['changed'] is False
    assert path.read_bytes() == before
    assert not (tmp_path / 'persistent identity').exists()


@pytest.mark.parametrize('client', ['claude-code', 'claude-desktop', 'codex', 'cursor'])
def test_conflict_never_replaces_existing_connection(tmp_path, client):
    plan = plan_for(tmp_path, client)
    path = Path(plan['host_configuration']['path'])
    path.parent.mkdir(parents=True, exist_ok=True)
    original = (b'[mcp_servers.a4a]\ncommand="existing"\n' if client == 'codex'
                else b'{"mcpServers":{"a4a":{"command":"existing"}}}')
    path.write_bytes(original)
    with pytest.raises(ValueError, match='differs'):
        apply_file_plan(plan, tmp_path / 'transactions')
    assert path.read_bytes() == original


@pytest.mark.parametrize('client', ['claude-code', 'claude-desktop'])
@pytest.mark.parametrize('bad', ['1e999', '1e-999', '0.12345678901234567890123456789', 'NaN'])
def test_claude_preserving_merge_refuses_lossy_numbers_even_when_idempotent(tmp_path, client, bad):
    plan = plan_for(tmp_path, client)
    entry = json.dumps(plan['mcp_server'])
    for original in ('{"owner":' + bad + '}',
                     '{"owner":' + bad + ',"mcpServers":{"a4a":' + entry + '}}'):
        with pytest.raises(ValueError):
            merge_proposal(plan, original)


def test_concurrent_owner_edit_is_preserved(tmp_path, monkeypatch):
    import a4a_mcp.setup_hosts as hosts
    plan = plan_for(tmp_path, 'cursor')
    path = Path(plan['host_configuration']['path'])
    path.parent.mkdir(parents=True)
    path.write_text('{}')
    journal_write = hosts.write_json
    def intervening_edit(journal, document):
        journal_write(journal, document)
        path.write_text('{"ownerEdit":true}')
    monkeypatch.setattr(hosts, 'write_json', intervening_edit)
    with pytest.raises(ValueError, match='concurrent'):
        apply_file_plan(plan, tmp_path / 'transactions')
    assert json.loads(path.read_text()) == {'ownerEdit': True}


def test_stale_configuration_hash_prevents_write(tmp_path):
    plan = plan_for(tmp_path, 'cursor')
    path = Path(plan['host_configuration']['path'])
    path.parent.mkdir(parents=True)
    path.write_text('{"owner":true}')
    with pytest.raises(ValueError, match='changed since planning'):
        apply_file_plan(plan, tmp_path / 'transactions', expected_hash=digest(b'{}'))
    assert path.read_text() == '{"owner":true}'


def bundle_for(tmp_path):
    wheels = []
    for name in ('a4a-sdk', 'a4a-mcp'):
        filename = name.replace('-', '_') + '-0.3.3-py3-none-any.whl'
        path = tmp_path / filename
        with zipfile.ZipFile(path, 'w') as wheel:
            wheel.writestr(name.replace('-', '_') + '-0.3.3.dist-info/METADATA',
                           'Name: ' + name + '\nVersion: 0.3.3\n')
        wheels.append({'filename': filename, 'name': name, 'version': '0.3.3',
                       'sha256': digest(path.read_bytes())})
    path = tmp_path / 'bundle.json'
    path.write_text(json.dumps({'schema': 1, 'platform': sys.platform,
        'python': f'{sys.version_info.major}.{sys.version_info.minor}', 'wheels': wheels}))
    return path, digest(path.read_bytes())


def test_bundle_hash_bound_wheels_and_metadata(tmp_path):
    path, sha = bundle_for(tmp_path)
    _, files = load_bundle(path, sha)
    files[0].write_bytes(files[0].read_bytes() + b'tamper')
    with pytest.raises(ValueError, match='wheel hash mismatch'):
        load_bundle(path, sha)


def test_bundle_manifest_hash_cannot_be_replaced_by_embedded_hash(tmp_path):
    path, sha = bundle_for(tmp_path)
    path.write_bytes(path.read_bytes() + b' ')
    with pytest.raises(ValueError, match='manifest hash mismatch'):
        load_bundle(path, sha)


@pytest.mark.parametrize('mutation', ['traversal', 'duplicate', 'metadata', 'platform'])
def test_approved_hash_still_requires_safe_structure(tmp_path, mutation):
    path, _ = bundle_for(tmp_path)
    data = json.loads(path.read_text())
    if mutation == 'traversal':
        data['wheels'][0]['filename'] = '../escape.whl'
    elif mutation == 'duplicate':
        data['wheels'].append(data['wheels'][0])
    elif mutation == 'metadata':
        data['wheels'][0]['version'] = '99.0'
    else:
        data['platform'] = 'incompatible'
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        load_bundle(path, digest(path.read_bytes()))


def test_noninteractive_ambiguity_never_guesses(monkeypatch):
    monkeypatch.setattr(sys.stdin, 'isatty', lambda: False)
    with pytest.raises(ValueError, match='multiple or uncertain'):
        select_host(None, [{'client': 'codex', 'evidence': 'launcher_on_path'},
                           {'client': 'claude-code', 'evidence': 'launcher_on_path'}])


def test_unaccepted_public_bundle_refuses_before_mutation(tmp_path, capsys):
    assert cli(['connect', '--client', 'codex', '--apply',
                '--runtime-root', str(tmp_path / 'runtime')]) == 2
    assert json.loads(capsys.readouterr().err)['ready'] is False
    assert not list(tmp_path.iterdir())


def test_private_state_cannot_be_inside_another_checkout_or_cache(tmp_path, monkeypatch):
    checkout = tmp_path / 'other checkout'
    checkout.mkdir()
    (checkout / '.git').write_text('gitdir: isolated-worktree')
    with pytest.raises(ValueError, match='every Git checkout'):
        persistent_path(checkout / 'runtime')
    monkeypatch.setenv('UV_CACHE_DIR', str(tmp_path / 'explicit cache'))
    with pytest.raises(ValueError, match='uv cache'):
        persistent_path(tmp_path / 'explicit cache/runtime')


def test_child_does_not_inherit_owner_identity_or_python_installer_overrides(monkeypatch):
    for key in ('A4A_HOME', 'A4A_MANDATE_AUTO', 'PYTHONPATH', 'PYTHONHOME',
                'UV_INDEX_URL', 'PIP_INDEX_URL'):
        monkeypatch.setenv(key, 'must-not-be-inherited')
    env = child_environment({'A4A_HOME': 'explicit-diagnostic-home'})
    assert env['A4A_HOME'] == 'explicit-diagnostic-home'
    assert not any(key in env for key in ('A4A_MANDATE_AUTO', 'PYTHONPATH',
        'PYTHONHOME', 'UV_INDEX_URL', 'PIP_INDEX_URL'))


def test_rollback_restores_exact_backup_and_keeps_it(tmp_path):
    plan = plan_for(tmp_path, 'cursor')
    path = Path(plan['host_configuration']['path'])
    path.parent.mkdir(parents=True)
    original = b'{"owner":true,"mcpServers":{"other":{"command":"other"}}}'
    path.write_bytes(original)
    result = apply_file_plan(plan, tmp_path / 'state')
    rollback_file_plan(result['transaction'])
    assert path.read_bytes() == original
    assert rollback_file_plan(result['transaction'])['changed'] is False
    journal = json.loads(Path(result['transaction']).read_text())
    assert Path(journal['backup']).read_bytes() == original


def test_rollback_never_overwrites_later_owner_edits(tmp_path):
    plan = plan_for(tmp_path, 'cursor')
    path = Path(plan['host_configuration']['path'])
    result = apply_file_plan(plan, tmp_path / 'state')
    path.write_text('{"ownerEdit":true}')
    with pytest.raises(ValueError, match='edited after setup'):
        rollback_file_plan(result['transaction'])
    assert path.read_text() == '{"ownerEdit":true}'


def test_rollback_of_new_config_quarantines_instead_of_deleting(tmp_path):
    plan = plan_for(tmp_path, 'cursor')
    path = Path(plan['host_configuration']['path'])
    result = apply_file_plan(plan, tmp_path / 'state')
    installed = path.read_bytes()
    rollback_file_plan(result['transaction'])
    assert not path.exists()
    quarantined, = (tmp_path / 'state/_trash').glob('*.new-config')
    assert quarantined.read_bytes() == installed


def test_inventory_binds_bytecode_and_rejects_hardlinks(tmp_path):
    cache = tmp_path / '__pycache__'
    cache.mkdir()
    bytecode = cache / 'module.cpython-311.pyc'
    bytecode.write_bytes(b'bytecode sentinel')
    before = runtime_inventory(tmp_path)
    assert '__pycache__/module.cpython-311.pyc' in before
    bytecode.write_bytes(b'changed executable cache')
    assert runtime_inventory(tmp_path) != before
    os.link(bytecode, tmp_path / 'hard-linked.pyc')
    with pytest.raises(ValueError, match='single-link'):
        runtime_inventory(tmp_path)


def test_checked_read_rejects_replacement_between_stat_and_open(tmp_path, monkeypatch):
    path = tmp_path / 'configuration.json'
    path.write_bytes(b'owner configuration')
    replacement = tmp_path / 'replacement.json'
    replacement.write_bytes(b'other configuration')
    original_open = Path.open
    def replacing_open(self, *args, **kwargs):
        if self == path:
            os.replace(replacement, path)
        return original_open(self, *args, **kwargs)
    monkeypatch.setattr(Path, 'open', replacing_open)
    with pytest.raises(ValueError, match='changed during'):
        read_regular(path)


@pytest.mark.skipif(sys.platform != 'linux', reason='actual Linux venv alias boundary')
def test_linux_inventory_binds_only_standard_root_lib64_alias(tmp_path):
    environment = tmp_path / 'runtime'
    (environment / 'lib').mkdir(parents=True)
    (environment / 'lib/module.py').write_bytes(b'approved source')
    (environment / 'lib64').symlink_to('lib', target_is_directory=True)
    before = runtime_inventory(environment)
    assert before['lib64'] == {'kind': 'symlink', 'target': 'lib'}
    assert before['lib/module.py'] == digest(b'approved source')
    assert not any(name.startswith('lib64/') for name in before)
    (environment / 'lib64').rename(tmp_path / 'retained-alias')
    assert runtime_inventory(environment) != before


@pytest.mark.skipif(sys.platform != 'linux', reason='actual Linux venv alias boundary')
@pytest.mark.parametrize('target', ['./lib', '../outside', '/usr/lib'])
def test_linux_inventory_rejects_changed_lib64_target(tmp_path, target):
    (tmp_path / 'lib').mkdir()
    (tmp_path.parent / 'outside').mkdir(exist_ok=True)
    (tmp_path / 'lib64').symlink_to(target, target_is_directory=True)
    with pytest.raises(ValueError, match='alias'):
        runtime_inventory(tmp_path)


@pytest.mark.skipif(sys.platform != 'linux', reason='actual Linux symlink boundary')
@pytest.mark.parametrize('name,directory', [('other', True), ('linked.py', False), ('lib/lib64', True)])
def test_linux_inventory_rejects_other_links(tmp_path, name, directory):
    (tmp_path / 'lib').mkdir()
    target = tmp_path / ('lib' if directory else 'source.py')
    if not directory:
        target.write_bytes(b'approved source')
    (tmp_path / name).symlink_to(target, target_is_directory=directory)
    with pytest.raises(ValueError):
        runtime_inventory(tmp_path)


@pytest.mark.skipif(sys.platform != 'linux', reason='actual Linux doctor mutation boundary')
def test_doctor_rejects_removed_alias_before_executing_runtime(tmp_path, monkeypatch):
    from a4a_mcp.setup_runtime import doctor_runtime
    environment = tmp_path / 'runtime-test'
    (environment / 'lib').mkdir(parents=True)
    (environment / 'bin').mkdir()
    python = environment / 'bin/python'
    python.write_bytes(b'never execute this sentinel')
    base = tmp_path / 'base-python'
    base.write_bytes(b'approved base sentinel')
    alias = environment / 'lib64'
    alias.symlink_to('lib', target_is_directory=True)
    receipt = {'schema': 1, 'state': 'runtime_installed', 'environment': str(environment),
               'python': str(python), 'base_python': str(base),
               'base_python_sha256': digest(base.read_bytes()),
               'inventory': runtime_inventory(environment)}
    receipt_path = tmp_path / 'runtime-test.json'
    receipt_path.write_text(json.dumps(receipt))
    alias.rename(tmp_path / 'retained-alias')
    monkeypatch.setattr('a4a_mcp.setup_runtime.inspect_packages',
                        lambda *a, **k: pytest.fail('must refuse before runtime execution'))
    with pytest.raises(ValueError, match='runtime files changed'):
        doctor_runtime(receipt_path)


# Focused installer regressions. These use inert controllers, not native acceptance.
import ast
from contextlib import ExitStack, nullcontext
import errno
import hashlib
import importlib.util
import re
import signal
import stat
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch


def _macreg_source_root():
    value = os.environ.get('A4A_INSTALLER_REGRESSION_SOURCE_ROOT')
    return Path(value) if value else Path(__file__).resolve().parents[2]


def _macreg_bootstrap_source():
    value = os.environ.get('A4A_INSTALLER_REGRESSION_BOOTSTRAP_SOURCE')
    return Path(value) if value else _macreg_source_root() / 'scripts/installer/macos/bootstrap_macos.py'


def _macreg_runtime_source():
    value = os.environ.get('A4A_INSTALLER_REGRESSION_RUNTIME_SOURCE')
    return Path(value) if value else _macreg_source_root() / 'mcp-server/a4a_mcp/setup_runtime.py'


def _macreg_fixture(label):
    value = os.environ.get('A4A_INSTALLER_REGRESSION_FIXTURE_ROOT')
    parent = Path(value) if value else Path(tempfile.gettempdir()).resolve(strict=True)
    if not parent.is_absolute() or not parent.is_dir() or parent.is_symlink():
        raise ValueError('Existing absolute regression fixture root required')
    # mkdtemp creates a new owned private fixture. Nothing is automatically removed.
    return Path(tempfile.mkdtemp(prefix='a4a-' + label, dir=parent))


def _macreg_load_bootstrap():
    source = _macreg_bootstrap_source()
    if not source.is_file():
        raise unittest.SkipTest('macOS installer bootstrap source is not included')
    spec = importlib.util.spec_from_file_location('installer_bootstrap_regression', source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _macreg_seed_branch():
    tree = ast.parse(_macreg_bootstrap_source().read_bytes())
    main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
    branch = next(node for node in main.body if isinstance(node, ast.If) and ast.unparse(node.test) == 'exists(seed)')
    return compile(ast.fix_missing_locations(ast.Module(body=[branch], type_ignores=[])), '<actual-new-seed-branch>', 'exec')


def _macreg_runtime_function():
    tree = ast.parse(_macreg_runtime_source().read_bytes())
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'install_runtime')
    return compile(ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[])), '<actual-install-runtime-function>', 'exec')


def _macreg_digest(value):
    return hashlib.sha256(value).hexdigest()


class TestMacBootstrapSupervisorRegression(unittest.TestCase):

    def setUp(self):
        self.root = _macreg_fixture('supervisor-')
        self.bootstrap = _macreg_load_bootstrap()
        self.calls = []
        self.waits = []
        self.signals = []
        self.mode = 'ok'
        self.checks = []
        self.guard = self.root / 'not-executed-guard'
        self.guard.write_bytes(b'inert fixture marker, never executed')
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(self.bootstrap, 'NATIVE_GUARD', self.guard))
        self.bound = self.stack.enter_context(patch.object(self.bootstrap, 'verified_run_guard'))
        self.stack.enter_context(patch.object(self.bootstrap, 'private_directory', side_effect=lambda path: self.checks.append(path)))
        self.stack.enter_context(patch.dict(os.environ, {'HOME': str(self.root), 'OWNER_SECRET_NOT_FOR_CHILD': 'inert-unused'}))
        self.stack.enter_context(patch.object(self.bootstrap, 'read_regular', side_effect=self.read))
        self.popen = self.stack.enter_context(patch.object(self.bootstrap.subprocess, 'Popen', side_effect=self.launch))
        if not hasattr(os, 'O_NOFOLLOW'):
            self.stack.enter_context(patch.object(os, 'O_NOFOLLOW', 0, create=True))

    def read(self, path, limit, *, private):
        self.assertTrue(private)
        if path.stat().st_size > limit:
            raise ValueError('bounded read exceeded')
        return path.read_bytes()

    def launch(self, command, **kwargs):
        self.calls.append((command, kwargs))
        logs = Path(command[3])
        label = command[5]
        (logs / (label + '-Abc123.stdout')).write_bytes(b'{"actual_child":true}\n')
        if self.mode != 'missing':
            (logs / (label + '-Abc123.stderr')).write_bytes(b'child diagnostic retained\n')
        if self.mode == 'extra':
            (logs / 'unexpected').write_bytes(b'not selected')
        if self.mode == 'oversize':
            with (logs / (label + '-Abc123.stdout')).open('r+b') as stream:
                stream.truncate(self.bootstrap.MAX_RECEIPT + 1)
        kwargs['stdout'].write(b'not actual child output\n')
        kwargs['stderr'].write(b'native guard: group kill failed\n')
        owner = self

        class InertProcess:
            pid = 424242

            def wait(self, *, timeout):
                owner.waits.append(timeout)
                if owner.mode in ('unknown', 'signal-fails') or (owner.mode == 'timeout' and len(owner.waits) == 1):
                    raise subprocess.TimeoutExpired(command, timeout)
                return 124 if owner.mode in ('nonzero', 'timeout') else 0

            def send_signal(self, number):
                owner.signals.append(number)
                if owner.mode == 'signal-fails':
                    raise PermissionError('inert signal denial')
        return InertProcess()

    def invoke(self, label='fixture'):
        return self.bootstrap.run([sys.executable, '-I', '-c', 'INERT-NOT-EXECUTED'], root=self.root, label=label)

    def test_exact_guard_route_return_child_output_and_unique_retention(self):
        self.assertEqual(self.invoke(), b'{"actual_child":true}\n')
        self.assertEqual(self.invoke(), b'{"actual_child":true}\n')
        self.assertEqual(self.bound.call_count, 2)
        self.assertEqual(len(list(self.root.glob('fixture-run-*'))), 2)
        command, options = self.calls[0]
        self.assertEqual(command[:3], [str(self.guard), 'run', '240'])
        self.assertEqual(command[4:7], [str(self.root), 'fixture', '--'])
        self.assertEqual(command[7:], [sys.executable, '-I', '-c', 'INERT-NOT-EXECUTED'])
        self.assertEqual(options['cwd'], self.root)
        self.assertEqual(set(options['env']), {'HOME', 'PATH', 'LANG', 'LC_CTYPE'})
        self.assertEqual(options['stdin'], subprocess.DEVNULL)
        self.assertTrue(options['start_new_session'])
        self.assertIn(Path(command[3]), self.checks)
        self.assertEqual(self.waits, [285, 285])

    def test_nonzero_guard_never_returns_output_and_retains_diagnostics(self):
        self.mode = 'nonzero'
        with self.assertRaisesRegex(RuntimeError, 'supervisor exit=124'):
            self.invoke()
        self.assertEqual(len(list(self.root.glob('fixture-run-*/*'))), 4)

    def test_missing_child_log_refused(self):
        self.mode = 'missing'
        with self.assertRaisesRegex(ValueError, 'one exclusive'):
            self.invoke()

    def test_unexpected_entry_refused(self):
        self.mode = 'extra'
        with self.assertRaisesRegex(ValueError, 'unexpected supervisor log entry'):
            self.invoke()

    def test_oversize_child_output_refused_bounded_read(self):
        self.mode = 'oversize'
        with self.assertRaisesRegex(ValueError, 'bounded read'):
            self.invoke()

    def test_outer_timeout_terminates_guard_and_waits_cleanup_grace(self):
        self.mode = 'timeout'
        with self.assertRaisesRegex(RuntimeError, 'interrupted supervisor; exit=124'):
            self.invoke()
        self.assertEqual(self.waits, [285, 15])
        self.assertEqual(self.signals, [signal.SIGTERM])

    def test_unresponsive_guard_explicit_unknown_cleanup_no_kill_fallback(self):
        self.mode = 'unknown'
        with self.assertRaisesRegex(RuntimeError, 'cleanup UNPROVEN; guard pid=424242'):
            self.invoke()
        self.assertEqual(self.waits, [285, 15])
        self.assertEqual(self.signals, [signal.SIGTERM])

    def test_invalid_guard_binding_before_any_launch(self):
        self.bound.side_effect = ValueError('pinned supervisor changed')
        with self.assertRaisesRegex(ValueError, 'pinned supervisor changed'):
            self.invoke()
        self.popen.assert_not_called()
        self.assertEqual(list(self.root.glob('*-run-*')), [])

    def test_guard_signal_denial_explicit_unknown_cleanup(self):
        self.mode = 'signal-fails'
        with self.assertRaisesRegex(RuntimeError, 'cleanup UNPROVEN; cannot signal guard pid=424242'):
            self.invoke()
        self.assertEqual(self.signals, [signal.SIGTERM])

    def test_argument_refusal_before_launch(self):
        for label in ('../escape', 'UPPER', 'space here'):
            with self.assertRaises(ValueError):
                self.invoke(label)
        with self.assertRaises(ValueError):
            self.bootstrap.run(['relative-command'], root=self.root, label='fixture')
        self.popen.assert_not_called()

    def test_source_no_python_waitid_or_killpg_and_ascii(self):
        raw = _macreg_bootstrap_source().read_bytes()
        raw.decode('ascii')
        tree = ast.parse(raw)
        calls = [node.func for node in ast.walk(tree) if isinstance(node, ast.Call)]
        self.assertFalse(any((isinstance(fn, ast.Attribute) and fn.attr in ('waitid', 'killpg', 'kill', 'terminate') for fn in calls)))
        self.assertNotIn('selectors', raw.decode())

@unittest.skipUnless(os.name == 'posix', 'Real POSIX mode/nofollow primitives required; no native Darwin claim')
class TestMacSeedLockRegression(unittest.TestCase):

    def setUp(self):
        self.root = _macreg_fixture('seed-')
        self.bootstrap = _macreg_load_bootstrap()
        self.branch_code = _macreg_seed_branch()
        self.seed = self.root / 'seed'
        self.receipt = self.root / 'seed-files.json'
        self.events = []
        self.lock_records = []
        self.unexpected = False
        self.space = {'seed': self.seed, 'seed_python': self.seed / 'bin/python', 'seed_receipt': self.receipt, 'root': self.root, 'base': self.root / 'not-executed-python', 'uv': self.root / 'not-executed-uv', 'manifest': self.root / 'wheelhouse/bundle.json', 'requirements': ['inert-fixture==1 --hash=sha256:' + '1' * 64 + '\n'], 'exists': self.bootstrap.exists, 'run': self.observe_run, 'exclusive': self.exclusive, 'checked_inventory': self.inventory}

    def exclusive(self, path, raw):
        self.events.append(('exclusive', path.relative_to(self.root).as_posix()))
        return self.bootstrap.exclusive(path, raw)

    def observe_run(self, argv, *, root, label):
        self.events.append(('run', label))
        self.assertEqual(root, self.root)
        if label == 'seed-venv':
            self.assertEqual(argv[-1], self.seed)
            self.seed.mkdir(mode=448)
            if self.unexpected:
                (self.seed / '.lock').write_bytes(b'unexpected retained fixture')
                (self.seed / '.lock').chmod(438)
        else:
            lock = self.seed / '.lock'
            info = lock.lstat()
            self.assertTrue(stat.S_ISREG(info.st_mode))
            self.assertEqual(stat.S_IMODE(info.st_mode), 384)
            self.assertEqual(info.st_nlink, 1)
            self.assertEqual(lock.read_bytes(), b'')
            self.lock_records.append((info.st_dev, info.st_ino))
        return b'inert only'

    def inventory(self, seed, receipt):
        self.events.append(('inventory', seed.relative_to(self.root).as_posix()))
        self.assertEqual(receipt, self.receipt)
        self.assertEqual(stat.S_IMODE((seed / '.lock').stat().st_mode), 384)

    def execute(self):
        exec(self.branch_code, self.space)

    def test_new_lock0600_exists_before_uv_and_keeps_inode_under_permissive_umask(self):
        previous = os.umask(0)
        try:
            self.execute()
        finally:
            os.umask(previous)
        self.assertEqual(self.events, [('run', 'seed-venv'), ('exclusive', 'seed/.lock'), ('exclusive', 'requirements.txt'), ('run', 'seed-install'), ('run', 'seed-check'), ('run', 'compile-seed'), ('inventory', 'seed')])
        self.assertEqual(len(set(self.lock_records)), 1)
        self.assertEqual(len(self.lock_records), 3)

    def test_unexpected_preexisting_lock_refused_before_uv_and_preserved(self):
        self.unexpected = True
        with self.assertRaisesRegex(ValueError, 'existing file retained'):
            self.execute()
        self.assertEqual(self.events, [('run', 'seed-venv'), ('exclusive', 'seed/.lock')])
        self.assertEqual((self.seed / '.lock').read_bytes(), b'unexpected retained fixture')
        self.assertEqual(stat.S_IMODE((self.seed / '.lock').stat().st_mode), 438)
        self.assertFalse((self.root / 'requirements.txt').exists())

    def test_existing_complete_seed_is_readonly_and_does_not_precreate_or_run_uv(self):
        self.seed.mkdir(mode=448)
        self.bootstrap.exclusive(self.seed / '.lock', b'')
        self.receipt.write_bytes(b'inert inventory marker')
        before = (self.seed / '.lock').stat()
        self.execute()
        after = (self.seed / '.lock').stat()
        self.assertEqual(self.events, [('inventory', 'seed')])
        self.assertEqual((before.st_ino, before.st_size, before.st_mode, before.st_mtime_ns), (after.st_ino, after.st_size, after.st_mode, after.st_mtime_ns))
        self.assertEqual(self.receipt.read_bytes(), b'inert inventory marker')

    def test_existing_incomplete_seed_still_refused_without_mutation(self):
        self.seed.mkdir(mode=448)
        (self.seed / 'marker').write_bytes(b'incomplete retained')
        with self.assertRaisesRegex(ValueError, 'incomplete seed retained'):
            self.execute()
        self.assertEqual(self.events, [])
        self.assertEqual((self.seed / 'marker').read_bytes(), b'incomplete retained')
        self.assertFalse((self.seed / '.lock').exists())

    def test_existing_unsafe_seed_not_normalized(self):
        self.seed.mkdir(mode=448)
        (self.seed / '.lock').write_bytes(b'')
        (self.seed / '.lock').chmod(438)
        self.receipt.write_bytes(b'inert receipt')
        with self.assertRaises(AssertionError):
            self.execute()
        self.assertEqual(self.events, [('inventory', 'seed')])
        self.assertEqual(stat.S_IMODE((self.seed / '.lock').stat().st_mode), 438)

@unittest.skipUnless(os.name == 'posix', 'Real POSIX mode/nofollow primitives required; no native Darwin claim')
class TestMacRuntimeLockRegression(unittest.TestCase):

    def setUp(self):
        self.root = _macreg_fixture('runtime-')
        self.base = self.root / 'base-python-not-executed'
        self.uv = self.root / 'uv-not-executed'
        self.base.write_bytes(b'inert base')
        self.uv.write_bytes(b'inert uv')
        self.state = self.root / 'state'
        self.state.mkdir(mode=448)
        self.bundle_hash = '1' * 64
        identity = _macreg_digest((self.bundle_hash + '\n' + str(self.base) + '\n' + _macreg_digest(self.base.read_bytes())).encode())[:24]
        self.environment = self.state / ('runtime-' + identity)
        self.receipt = self.state / ('runtime-' + identity + '.json')
        self.events = []
        self.observed = []
        self.venv_extra = None
        self.platform = types.SimpleNamespace(platform='darwin')
        self.document = {'python': '3.11', 'wheels': [{'name': 'a4a-sdk', 'version': '0.3.3', 'sha256': '2' * 64}, {'name': 'a4a-mcp', 'version': '0.3.3', 'sha256': '3' * 64}]}
        storage = types.ModuleType('installer_runtime_inert.setup_storage')
        storage.atomic_private_write = lambda path, raw: path.write_bytes(raw)
        probe = types.ModuleType('installer_runtime_inert.setup_probe')
        probe.probe_stdio = lambda python, root: {'inert': True}
        package = types.ModuleType('installer_runtime_inert')
        package.__path__ = []
        self.modules = patch.dict(sys.modules, {'installer_runtime_inert': package, 'installer_runtime_inert.setup_storage': storage, 'installer_runtime_inert.setup_probe': probe})
        self.modules.start()
        self.addCleanup(self.modules.stop)
        self.space = {'__package__': 'installer_runtime_inert', 'os': os, 'sys': self.platform, 'Path': Path, 're': re, 'json': json, 'load_bundle': lambda *args: (self.document, [self.root / 'wheelhouse/inert.whl']), 'persistent_path': Path, 'checked_path': Path, 'private_directory': Path, 'read_regular': lambda path, *args: path.read_bytes(), 'digest': _macreg_digest, 'profile_lock': lambda root: nullcontext(), 'run_checked': self.observe_run, 'doctor_runtime': lambda path: self.events.append('doctor-existing'), 'inspect_packages': lambda python, versions, **kw: {'modules': [str(self.environment / 'inert.py')]}, 'runtime_inventory': self.inventory, 'write_json': lambda path, value: path.write_text(json.dumps(value))}
        exec(_macreg_runtime_function(), self.space)

    def observe_run(self, argv, *, cwd):
        if '-c' in argv:
            self.events.append('base-version')
            return b'3.11\n'
        if 'venv' in argv:
            self.events.append('new-venv')
            self.environment.mkdir(mode=448)
            if self.venv_extra:
                self.venv_extra(self.environment / '.lock')
            return b''
        label = 'uv-install' if 'install' in argv else 'uv-check' if 'check' in argv else 'compile-runtime'
        self.events.append(label)
        lock = self.environment / '.lock'
        if self.platform.platform == 'darwin':
            info = lock.lstat()
            self.assertEqual(stat.S_IMODE(info.st_mode), 384)
            self.assertTrue(stat.S_ISREG(info.st_mode))
            self.assertEqual(info.st_nlink, 1)
            self.assertEqual(lock.read_bytes(), b'')
            self.observed.append((info.st_dev, info.st_ino))
        else:
            self.assertFalse(lock.exists())
        return b''

    def inventory(self, environment):
        self.events.append('inventory')
        if self.platform.platform == 'darwin':
            self.assertEqual(stat.S_IMODE((environment / '.lock').stat().st_mode), 384)
        return {'inert': 'no actual package inventory performed'}

    def invoke(self):
        return self.space['install_runtime'](bundle=self.root / 'bundle.json', bundle_sha256=self.bundle_hash, root=self.state, base_python=self.base, uv=self.uv, uv_sha256=_macreg_digest(self.uv.read_bytes()))

    def assert_no_uv(self):
        self.assertFalse(any((value in self.events for value in ('uv-install', 'uv-check', 'compile-runtime', 'inventory'))))

    def test_new_darwin_lock_private_empty_before_uv_with_permissive_umask(self):
        previous = os.umask(0)
        try:
            with patch.object(os, 'fsync', wraps=os.fsync) as sync, patch.object(os, 'close', wraps=os.close) as close:
                result = self.invoke()
        finally:
            os.umask(previous)
        self.assertEqual(self.events, ['base-version', 'new-venv', 'uv-install', 'uv-check', 'compile-runtime', 'inventory'])
        self.assertEqual(len(self.observed), 3)
        self.assertEqual(len(set(self.observed)), 1)
        self.assertEqual(sync.call_count, 1)
        self.assertEqual(close.call_count, 1)
        self.assertEqual(result['state'], 'runtime_installed')

    def test_unexpected_existing_lock_refused_before_uv_and_retained(self):

        def unexpected(lock):
            lock.write_bytes(b'unexpected retained')
            lock.chmod(438)
        self.venv_extra = unexpected
        with self.assertRaises(FileExistsError):
            self.invoke()
        self.assert_no_uv()
        self.assertEqual((self.environment / '.lock').read_bytes(), b'unexpected retained')
        self.assertEqual(stat.S_IMODE((self.environment / '.lock').stat().st_mode), 438)

    def test_unexpected_alias_refused_without_target_mutation(self):
        target = self.root / 'owned-sentinel'
        target.write_bytes(b'unchanged')
        self.venv_extra = lambda lock: lock.symlink_to(target)
        with self.assertRaises(OSError):
            self.invoke()
        self.assert_no_uv()
        self.assertTrue((self.environment / '.lock').is_symlink())
        self.assertEqual(target.read_bytes(), b'unchanged')

    def test_fsync_failure_closes_and_retains_new_empty_lock_before_uv(self):
        descriptors = []

        def fail_sync(fd):
            descriptors.append(fd)
            raise OSError(errno.EIO, 'inert fsync failure')
        with patch.object(os, 'fsync', side_effect=fail_sync), patch.object(os, 'close', wraps=os.close) as close:
            with self.assertRaisesRegex(OSError, 'inert fsync'):
                self.invoke()
        self.assert_no_uv()
        self.assertEqual(close.call_count, 1)
        with self.assertRaises(OSError):
            os.fstat(descriptors[0])
        self.assertEqual((self.environment / '.lock').read_bytes(), b'')

    def test_close_failure_retains_lock_and_prevents_uv(self):
        actual_close = os.close

        def fail_close(fd):
            actual_close(fd)
            raise OSError(errno.EIO, 'inert close failure after close')
        with patch.object(os, 'close', side_effect=fail_close):
            with self.assertRaisesRegex(OSError, 'inert close'):
                self.invoke()
        self.assert_no_uv()
        self.assertEqual((self.environment / '.lock').read_bytes(), b'')

    def test_existing_complete_runtime_unchanged_and_readonly_delegated(self):
        self.environment.mkdir(mode=448)
        lock = self.environment / '.lock'
        lock.write_bytes(b'preexisting retained')
        lock.chmod(438)
        expected = {'bundle_sha256': self.bundle_hash, 'state': 'runtime_installed'}
        self.receipt.write_text(json.dumps(expected))
        before = lock.stat()
        self.assertEqual(self.invoke(), expected)
        after = lock.stat()
        self.assertEqual(self.events, ['base-version', 'doctor-existing'])
        self.assertEqual((before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns), (after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns))
        self.assertEqual(lock.read_bytes(), b'preexisting retained')

    def test_existing_incomplete_runtime_refused_without_new_lock(self):
        self.environment.mkdir(mode=448)
        marker = self.environment / 'retained'
        marker.write_bytes(b'incomplete')
        with self.assertRaisesRegex(ValueError, 'incomplete runtime retained'):
            self.invoke()
        self.assertEqual(self.events, ['base-version'])
        self.assertEqual(marker.read_bytes(), b'incomplete')
        self.assertFalse((self.environment / '.lock').exists())

    def test_linux_dispatch_does_not_change_new_lock_behavior(self):
        self.platform.platform = 'linux'
        with patch.object(os, 'open', side_effect=AssertionError('new lock code must not run')):
            self.invoke()

    def test_windows_dispatch_does_not_create_posix_lock(self):
        self.platform.platform = 'win32'
        with patch.object(os, 'open', side_effect=AssertionError('new lock code must not run')):
            self.invoke()
