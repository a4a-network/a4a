"""Visible persistent defaults; selecting a profile never creates an identity."""
import hashlib
import os
from pathlib import Path
import re
import sys

from .onboarding import _relay, validate_json_config
from .setup_storage import persistent_path, private_directory, read_regular


def application_data():
    """Use the OS data location, never cwd, a checkout or a transient uv cache."""
    if sys.platform == 'win32':
        base = Path(os.environ.get('LOCALAPPDATA', str(Path.home() / 'AppData/Local')))
        return persistent_path(base / 'A4A')
    if sys.platform == 'darwin':
        return persistent_path(Path.home() / 'Library/Application Support/A4A')
    base = Path(os.environ.get('XDG_DATA_HOME', str(Path.home() / '.local/share')))
    return persistent_path(base / 'a4a')


def current_base_python():
    """Resolve only the running interpreter's default leaf alias, never inputs."""
    value = sys._base_executable
    if not isinstance(value, (str, os.PathLike)):
        raise ValueError('the current base interpreter is unavailable; use an explicit real --base-python')
    path = Path(value)
    if (not path.is_absolute() or '..' in path.parts
            or str(path).replace('\\', '/').startswith('//')):
        raise ValueError('the current base interpreter must have an absolute local path')
    # POSIX venvs can report bin/python as an alias to the real versioned base.
    # Accept that implicit leaf only: its parent and the resolved destination
    # must still satisfy the unchanged persistent path policy.
    persistent_path(path.parent)
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError('the current base interpreter could not be resolved; use an explicit real --base-python') from exc
    resolved = persistent_path(resolved)
    if not resolved.is_file():
        raise ValueError('the current base interpreter is not a regular executable file')
    return resolved


def profile_name(value):
    if (type(value) is not str or not re.fullmatch(r'[a-z][a-z0-9_-]{0,63}', value)
            or value in {'con', 'prn', 'aux', 'nul'}
            or re.fullmatch(r'(?:com|lpt)[1-9]', value)):
        raise ValueError('profile must be a portable lowercase name, 1..64 characters; use --home for an existing directory')
    return value


def resolve_settings(*, home=None, profile=None, runtime_root=None, relay=None,
                     consumer=None, base_python=None, interactive=False):
    if home is not None and profile is not None:
        raise ValueError('choose --home or --profile, not both')
    if home is None and profile is None:
        if not interactive:
            raise ValueError('select a new or existing profile with --profile NAME or --home PATH; no identity selected')
        profile = input('Choose a new or existing profile name [personal]: ').strip() or 'personal'
    defaults = []
    if profile is not None:
        profile = profile_name(profile)
        home = application_data() / 'profiles' / profile
        defaults.append('home_from_selected_profile')
    home = persistent_path(home)
    if home.exists():
        private_directory(home)  # Verify existing protection; do not change it.
    policy_path = home / 'inbox-policy.json'
    policy = None
    if policy_path.exists() or policy_path.is_symlink():
        from .inbox_runtime import _validate
        try:
            policy = _validate(validate_json_config(read_regular(policy_path).decode('utf-8-sig')))
        except Exception as exc:
            raise ValueError('selected profile policy is invalid; no settings changed') from exc
        if not (home / 'identity.json').is_file():
            raise ValueError('selected profile has policy but no identity; restore it before connecting')
        if consumer is not None and consumer != policy.consumer:
            raise ValueError('selected profile already has another consumer; preserve its policy or reconfigure it separately')
        if relay is not None and _relay(relay) != policy.relay:
            raise ValueError('selected profile is bound to another relay; reconfigure it separately')
    if relay is None:
        if policy is not None:
            relay = policy.relay
            defaults.append('relay_from_selected_profile_policy')
        elif interactive:
            relay = input('Relay URL (wss://, or an explicit local test ws://): ').strip()
        else:
            raise ValueError('first connection needs --relay URL; no accepted public default relay is embedded yet')
    relay = _relay(relay)
    if consumer is None:
        if policy is not None:
            consumer = policy.consumer
            defaults.append('consumer_from_selected_profile_policy')
        else:
            normalized = os.path.normcase(os.path.normpath(str(home)))
            consumer = 'agent-' + hashlib.sha256(normalized.encode('utf-8')).hexdigest()[:20]
            defaults.append('consumer_from_selected_profile_path')
    if type(consumer) is not str or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,96}', consumer):
        raise ValueError('consumer must be a bounded local identifier')
    if runtime_root is None:
        runtime_root = application_data() / 'runtime'
        defaults.append('runtime_root_from_os_data')
    runtime_root = persistent_path(runtime_root)
    if home.is_relative_to(runtime_root) or runtime_root.is_relative_to(home):
        raise ValueError('profile data and installed runtime must be separate trees')
    if base_python is None:
        base_python = current_base_python()
        defaults.append('base_python_from_current_interpreter')
    base_python = persistent_path(base_python)
    return {'home': home, 'profile': profile, 'runtime_root': runtime_root,
            'relay': relay, 'consumer': consumer, 'base_python': base_python,
            'profile_exists': home.exists(), 'profile_policy_reused': policy is not None,
            'defaulted_fields': defaults}
