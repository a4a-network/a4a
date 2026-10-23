"""Defaults must not guess identities, alter policies or use disposable caches."""
import json
import os
from pathlib import Path
import sys

import pytest

from a4a_mcp.setup_cli import cli
from a4a_mcp.setup_defaults import application_data, profile_name, resolve_settings
from a4a_mcp.setup_storage import private_directory, write_json


@pytest.fixture
def os_data(tmp_path, monkeypatch):
    base = tmp_path / 'OS application data'
    # Stub the location only: permission verification must use the real OS.
    monkeypatch.setattr('a4a_mcp.setup_defaults.application_data', lambda: base / 'A4A')
    return base


def test_named_profile_is_explicit_stable_and_separate(os_data):
    first = resolve_settings(profile='personal', relay='ws://127.0.0.1:11111')
    second = resolve_settings(profile='personal', relay='ws://127.0.0.1:11111')
    other = resolve_settings(profile='work', relay='ws://127.0.0.1:11111')
    assert first == second
    assert first['home'] == os_data / 'A4A/profiles/personal'
    assert first['runtime_root'] == os_data / 'A4A/runtime'
    assert first['consumer'] != other['consumer']
    assert not os_data.exists()  # Planning creates neither profiles nor state.


def test_neither_profile_nor_first_relay_is_guessed(os_data):
    with pytest.raises(ValueError, match='select a new or existing profile'):
        resolve_settings(relay='ws://127.0.0.1:11111')
    with pytest.raises(ValueError, match='first connection needs --relay'):
        resolve_settings(profile='personal')
    assert not os_data.exists()


@pytest.mark.parametrize('name', ['../other', 'Upper', 'con', 'com1', 'nul', 'a.b', '', 'x'*65])
def test_profile_names_cannot_traverse_or_use_reserved_windows_paths(name):
    with pytest.raises(ValueError, match='portable lowercase'):
        profile_name(name)


def test_existing_policy_is_reused_without_reconfiguration(tmp_path, os_data):
    home = private_directory(tmp_path / 'existing agent')
    identity_bytes = b'{"pubkey_hex":"' + b'a'*64 + b'","test_sentinel":true}'
    (home / 'identity.json').write_bytes(identity_bytes)
    policy = {'version': 1, 'recipient': 'a'*64, 'consumer': 'existing-consumer',
        'relay': 'ws://127.0.0.1:11111', 'allowed_peers': [], 'start_after': 1,
        'enabled': True, 'notify_interval': 60, 'notify_per_hour': 12}
    write_json(home / 'inbox-policy.json', policy)
    before = (home / 'inbox-policy.json').read_bytes()
    chosen = resolve_settings(home=home)
    assert chosen['consumer'] == policy['consumer'] and chosen['relay'] == policy['relay']
    assert chosen['profile_policy_reused']
    for extra in ({'relay': 'ws://127.0.0.1:22222'}, {'consumer': 'different'}):
        with pytest.raises(ValueError, match='reconfigure'):
            resolve_settings(home=home, **extra)
    assert (home / 'identity.json').read_bytes() == identity_bytes
    assert (home / 'inbox-policy.json').read_bytes() == before


def test_damaged_policy_cannot_be_reinterpreted_as_new_profile(tmp_path, os_data):
    home = private_directory(tmp_path / 'damaged agent')
    write_json(home / 'inbox-policy.json', {'version': 99})
    with pytest.raises(ValueError, match='policy is invalid'):
        resolve_settings(home=home, relay='ws://127.0.0.1:11111')


def test_existing_policy_without_identity_cannot_trigger_a_new_address(tmp_path, os_data):
    home = private_directory(tmp_path / 'incomplete agent')
    policy = {'version': 1, 'recipient': 'a'*64, 'consumer': 'retained-consumer',
        'relay': 'ws://127.0.0.1:11111', 'allowed_peers': [], 'start_after': 1,
        'enabled': True, 'notify_interval': 60, 'notify_per_hour': 12}
    write_json(home / 'inbox-policy.json', policy)
    before = (home / 'inbox-policy.json').read_bytes()
    with pytest.raises(ValueError, match='restore it before connecting'):
        resolve_settings(home=home)
    assert not (home / 'identity.json').exists()
    assert (home / 'inbox-policy.json').read_bytes() == before


def test_default_data_cannot_fall_in_git_or_uv_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, 'platform', 'win32')
    checkout = tmp_path / 'checkout'
    checkout.mkdir()
    (checkout / '.git').write_text('gitdir: other')
    monkeypatch.setenv('LOCALAPPDATA', str(checkout))
    with pytest.raises(ValueError, match='Git checkout'):
        application_data()
    monkeypatch.setenv('LOCALAPPDATA', str(tmp_path / 'cache'))
    monkeypatch.setenv('UV_CACHE_DIR', str(tmp_path / 'cache'))
    with pytest.raises(ValueError, match='uv cache'):
        application_data()


def test_runtime_and_profile_trees_cannot_overlap(tmp_path, os_data):
    with pytest.raises(ValueError, match='separate trees'):
        resolve_settings(home=tmp_path / 'state', runtime_root=tmp_path / 'state/runtime',
            relay='ws://127.0.0.1:11111')


def test_read_only_plan_needs_no_bundle_and_makes_no_changes(tmp_path, os_data, capsys):
    monkey_project = tmp_path / 'project'
    monkey_project.mkdir()
    assert cli(['connect', '--plan', '--client', 'codex', '--project', str(monkey_project),
        '--profile', 'personal', '--relay', 'ws://127.0.0.1:11111']) == 0
    result = json.loads(capsys.readouterr().out)
    assert result['state'] == 'setup_plan' and result['requires_approved_bundle']
    assert not result['changes_made'] and not result['ready']
    assert result['choices']['profile'] == 'personal'
    assert not os_data.exists() and not list(monkey_project.iterdir())


def test_defaults_do_not_turn_unaccepted_bundle_into_install(tmp_path, os_data, capsys):
    assert cli(['connect', '--apply', '--client', 'codex', '--project', str(tmp_path),
        '--profile', 'personal', '--relay', 'ws://127.0.0.1:11111']) == 2
    assert 'approved local --bundle' in json.loads(capsys.readouterr().err)['reason']
    assert not os_data.exists()


def test_interactive_choice_is_visible_and_still_does_not_create_identity(os_data, monkeypatch):
    prompts = []
    def answer(prompt):
        prompts.append(prompt)
        return 'my-agent' if 'profile' in prompt else 'ws://127.0.0.1:11111'
    monkeypatch.setattr('builtins.input', answer)
    chosen = resolve_settings(interactive=True)
    assert chosen['profile'] == 'my-agent' and len(prompts) == 2
    assert not chosen['home'].exists()


@pytest.mark.skipif(os.name != 'posix', reason='actual POSIX interpreter aliases')
def test_implicit_current_base_leaf_alias_resolves_without_creating_state(tmp_path, os_data, monkeypatch):
    real = tmp_path / 'python3.11'
    real.write_bytes(b'never execute this interpreter sentinel')
    alias = tmp_path / 'python'
    alias.symlink_to(real.name)
    monkeypatch.setattr(sys, '_base_executable', str(alias))
    chosen = resolve_settings(profile='personal', relay='ws://127.0.0.1:11111')
    assert chosen['base_python'] == real
    assert 'base_python_from_current_interpreter' in chosen['defaulted_fields']
    assert not os_data.exists()


@pytest.mark.skipif(os.name != 'posix', reason='actual POSIX interpreter aliases')
def test_explicit_base_alias_still_refuses(tmp_path, os_data):
    real = tmp_path / 'python3.11'
    real.write_bytes(b'never execute this interpreter sentinel')
    alias = tmp_path / 'python'
    alias.symlink_to(real.name)
    with pytest.raises(ValueError, match='linked paths'):
        resolve_settings(profile='personal', relay='ws://127.0.0.1:11111', base_python=alias)
    assert not os_data.exists()


@pytest.mark.skipif(os.name != 'posix', reason='actual POSIX interpreter aliases')
@pytest.mark.parametrize('forbidden', ['git', 'cache'])
def test_implicit_base_alias_cannot_resolve_to_git_or_cache(tmp_path, os_data, monkeypatch, forbidden):
    target_root = tmp_path / forbidden
    target_root.mkdir()
    if forbidden == 'git':
        (target_root / '.git').write_text('gitdir: another worktree')
    else:
        monkeypatch.setenv('UV_CACHE_DIR', str(target_root))
    real = target_root / 'python3.11'
    real.write_bytes(b'never execute this interpreter sentinel')
    alias = tmp_path / 'python'
    alias.symlink_to(real)
    monkeypatch.setattr(sys, '_base_executable', str(alias))
    with pytest.raises(ValueError, match='Git checkout' if forbidden == 'git' else 'uv cache'):
        resolve_settings(profile='personal', relay='ws://127.0.0.1:11111')
    assert not os_data.exists()


@pytest.mark.skipif(os.name != 'posix', reason='actual POSIX interpreter aliases')
@pytest.mark.parametrize('forbidden', ['git', 'cache'])
def test_implicit_base_alias_cannot_start_in_git_or_cache(tmp_path, os_data, monkeypatch, forbidden):
    real = tmp_path / 'python3.11'
    real.write_bytes(b'never execute this interpreter sentinel')
    alias_root = tmp_path / forbidden
    alias_root.mkdir()
    if forbidden == 'git':
        (alias_root / '.git').write_text('gitdir: another worktree')
    else:
        monkeypatch.setenv('UV_CACHE_DIR', str(alias_root))
    alias = alias_root / 'python'
    alias.symlink_to(real)
    monkeypatch.setattr(sys, '_base_executable', str(alias))
    with pytest.raises(ValueError, match='Git checkout' if forbidden == 'git' else 'uv cache'):
        resolve_settings(profile='personal', relay='ws://127.0.0.1:11111')
    assert not os_data.exists()


@pytest.mark.skipif(os.name != 'posix', reason='actual POSIX interpreter aliases')
def test_implicit_base_alias_to_directory_refuses(tmp_path, os_data, monkeypatch):
    directory = tmp_path / 'not-an-interpreter'
    directory.mkdir()
    alias = tmp_path / 'python'
    alias.symlink_to(directory, target_is_directory=True)
    monkeypatch.setattr(sys, '_base_executable', str(alias))
    with pytest.raises(ValueError, match='not a regular executable file'):
        resolve_settings(profile='personal', relay='ws://127.0.0.1:11111')
    assert not os_data.exists()


@pytest.mark.skipif(os.name != 'posix', reason='actual POSIX interpreter aliases')
@pytest.mark.parametrize('damage', ['broken', 'cycle', 'linked-parent'])
def test_implicit_base_damaged_alias_or_linked_parent_refuses(tmp_path, os_data, monkeypatch, damage):
    alias = tmp_path / 'python'
    if damage == 'broken':
        alias.symlink_to('missing-python')
    elif damage == 'cycle':
        alias.symlink_to(alias.name)
    else:
        directory = tmp_path / 'real-base'
        directory.mkdir()
        (directory / 'python').write_bytes(b'never execute this interpreter sentinel')
        linked = tmp_path / 'linked-base'
        linked.symlink_to(directory, target_is_directory=True)
        alias = linked / 'python'
    monkeypatch.setattr(sys, '_base_executable', str(alias))
    with pytest.raises(ValueError, match='linked paths' if damage == 'linked-parent' else 'could not be resolved'):
        resolve_settings(profile='personal', relay='ws://127.0.0.1:11111')
    assert not os_data.exists()


@pytest.mark.parametrize('invalid', [None, '', 'relative/python', '/untrusted/../python', '//network/python'])
def test_implicit_base_invalid_path_refuses(tmp_path, os_data, monkeypatch, invalid):
    monkeypatch.setattr(sys, '_base_executable', invalid)
    with pytest.raises(ValueError, match='current base interpreter'):
        resolve_settings(profile='personal', relay='ws://127.0.0.1:11111')
    assert not os_data.exists()


@pytest.mark.skipif(os.name != 'posix', reason='actual POSIX linked launcher preflight')
def test_read_only_plan_uses_real_base_instead_of_linked_current_launcher(tmp_path, os_data, monkeypatch, capsys):
    import a4a_mcp.setup_cli as setup
    real = tmp_path / 'python3.11'
    real.write_bytes(b'never execute this interpreter sentinel')
    launcher = tmp_path / 'venv-python'
    launcher.symlink_to(real)
    project = tmp_path / 'project'
    project.mkdir()
    monkeypatch.setattr(sys, 'executable', str(launcher))
    planned = []
    original = setup.host_plan
    def inspect_preflight(**kwargs):
        planned.append(kwargs['python'])
        return original(**kwargs)
    monkeypatch.setattr(setup, 'host_plan', inspect_preflight)
    assert cli(['connect', '--plan', '--client', 'codex', '--project', str(project),
        '--base-python', str(real), '--profile', 'personal', '--relay', 'ws://127.0.0.1:11111']) == 0
    assert planned == [real]
    assert json.loads(capsys.readouterr().out)['changes_made'] is False
    assert not os_data.exists() and not list(project.iterdir())
