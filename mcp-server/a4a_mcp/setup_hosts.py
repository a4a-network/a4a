"""Host selection and conservative configuration transactions for the installer."""
import json
import os
from pathlib import Path
import shutil
import time

from .onboarding import connection_plan, merge_host_config, validate_json_config
from .profile_lock import profile_lock
from .setup_storage import checked_path, private_directory, read_regular, digest, atomic_private_write, write_json


def detect_hosts():
    result = []
    for client, family, command in [('claude-code', 'claude', 'claude'),
                                     ('codex', 'codex', 'codex'),
                                     ('cursor', 'cursor', 'cursor'),
                                     ('kimi', 'kimi', 'kimi'),
                                     ('agy', 'gemini', 'agy')]:
        executable = shutil.which(command)
        if executable:
            result.append({'client': client, 'family': family, 'executable': executable,
                           'evidence': 'launcher_on_path', 'native_verified': False})
    config = desktop_config_path()
    if config is not None and config.is_file():
        result.append({'client': 'claude-desktop', 'family': 'claude',
                       'config': str(config), 'evidence': 'configuration_file', 'native_verified': False})
    return result


def desktop_config_path():
    import sys
    if sys.platform == 'win32':
        base = os.environ.get('APPDATA')
        return Path(base) / 'Claude/claude_desktop_config.json' if base else None
    if sys.platform == 'darwin':
        return Path.home() / 'Library/Application Support/Claude/claude_desktop_config.json'
    return None


def host_plan(*, client, python, home, project, relay, consumer, config_path=None,
              host_executable=None):
    if config_path is not None and client != 'claude-desktop':
        raise ValueError('explicit configuration destination is supported only for Desktop')
    if client in ('claude-desktop', 'claude-code'):
        config_path = (config_path or desktop_config_path()) if client == 'claude-desktop' else Path(project) / '.mcp.json'
        if config_path is None:
            raise ValueError('Claude Desktop is unsupported on this platform')
        config_path = checked_path(config_path)
        result = connection_plan(client='cursor', executable=str(python), home=str(home),
                                 project=str(project), relay=relay, consumer=consumer)
        result['client'] = client
        result['host_configuration'].update(path=str(config_path),
            scope='user' if client == 'claude-desktop' else 'project',
            requires_project_trust=client == 'claude-code')
        result['host_configuration']['content'] = json.dumps(
            {'mcpServers': {'a4a': result['mcp_server']}}, indent=2) + '\n'
        return result
    return connection_plan(client=client, executable=str(python), home=str(home),
                           project=str(project), relay=relay, consumer=consumer,
                           host_executable=host_executable)


def merge_proposal(plan, existing):
    if plan['client'] in ('claude-desktop', 'claude-code'):
        # Use the exact same strict JSON preservation logic; only the entry differs.
        data = validate_json_config(existing)
        if not isinstance(data, dict) or not isinstance(data.get('mcpServers', {}), dict):
            raise ValueError('invalid Claude configuration')
        if 'a4a' in data.get('mcpServers', {}):
            if data['mcpServers']['a4a'] != plan['mcp_server']:
                raise ValueError('existing Claude A4A entry differs; no replacement performed')
            return existing
        data.setdefault('mcpServers', {})['a4a'] = plan['mcp_server']
        return json.dumps(data, ensure_ascii=False, indent=2, allow_nan=False) + '\n'
    return merge_host_config(plan, existing)


def apply_file_plan(plan, state_root, *, expected_hash=None):
    config = plan.get('host_configuration')
    if not config:
        raise ValueError('this host requires native CLI registration, not a file transaction')
    path = checked_path(config['path'])
    state = private_directory(state_root)
    if path.is_relative_to(state):
        raise ValueError('host configuration must be outside installer state')
    with profile_lock(state):
        original = read_regular(path) if path.exists() else None
        old_hash = digest(original) if original is not None else None
        if expected_hash is not None and old_hash != expected_hash:
            raise ValueError('configuration changed since planning')
        proposal = merge_proposal(plan, original.decode('utf-8-sig') if original else '').encode('utf-8')
        if proposal == original:
            return {'state': 'host_configured', 'changed': False, 'path': str(path),
                    'native_tools_verified': False}
        # Backups may contain other servers' secrets. Protect before writing; retain.
        identifier = digest((str(path) + str(time.time_ns())).encode())[:24]
        backup = state / (identifier + '.config-backup')
        if original is not None:
            atomic_private_write(backup, original)
        journal = state / (identifier + '.transaction.json')
        transaction = {'schema': 1, 'state': 'prepared', 'path': str(path),
                       'original_sha256': old_hash, 'proposal_sha256': digest(proposal),
                       'backup': str(backup) if original is not None else None}
        write_json(journal, transaction)
        path.parent.mkdir(parents=True, exist_ok=True)
        current = read_regular(path) if path.exists() else None
        if current != original:
            raise ValueError('concurrent configuration edit; proposal not applied')
        atomic_private_write(path, proposal)
        if read_regular(path) != proposal:
            raise ValueError('host configuration changed after write; retained backup, no rollback over other edits')
        transaction['state'] = 'committed'
        write_json(journal, transaction)
        return {'state': 'host_configured', 'changed': True, 'path': str(path),
                'transaction': str(journal), 'native_tools_verified': False}


def rollback_file_plan(journal_path):
    """Restore only an unchanged installer proposal; retain backups and runtime."""
    journal = checked_path(journal_path)
    state = private_directory(journal.parent)
    with profile_lock(state):
        transaction = json.loads(read_regular(journal))
        if transaction.get('schema') != 1 or transaction.get('state') not in ('prepared', 'committed', 'rolled_back'):
            raise ValueError('unsupported configuration transaction')
        path = checked_path(transaction['path'])
        if path.is_relative_to(state):
            raise ValueError('configuration destination is inside installer state')
        backup = transaction.get('backup')
        old = None
        if backup is not None:
            expected = state / (journal.name.removesuffix('.transaction.json') + '.config-backup')
            if checked_path(backup) != expected:
                raise ValueError('backup does not belong to this transaction')
            old = read_regular(expected)
        if (digest(old) if old is not None else None) != transaction['original_sha256']:
            raise ValueError('backup hash does not match the original configuration')
        current = read_regular(path) if path.exists() else None
        if current == old:
            transaction['state'] = 'rolled_back'
            write_json(journal, transaction)
            return {'state': 'configuration_restored', 'changed': False, 'path': str(path)}
        if current is None or digest(current) != transaction['proposal_sha256']:
            raise ValueError('configuration edited after setup; rollback refused without replacing owner edits')
        if old is not None:
            atomic_private_write(path, old)
        else:
            quarantine = private_directory(state / '_trash')
            destination = quarantine / (journal.name.removesuffix('.transaction.json') + '.new-config')
            if destination.exists():
                raise ValueError('rollback quarantine already exists; no overwrite performed')
            os.replace(path, destination)
            write_json(quarantine / (destination.name + '.note.json'), {
                'source': str(path), 'quarantined': str(destination), 'time_ns': time.time_ns(),
                'reason': 'Explicit rollback of installer-created configuration',
                'restore': 'Move back only after verifying the destination remains absent.'})
        transaction['state'] = 'rolled_back'
        write_json(journal, transaction)
        return {'state': 'configuration_restored', 'changed': True, 'path': str(path),
                'runtime_removed': False, 'identity_changed': False}
