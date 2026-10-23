"""Permanent, hash-bound offline runtime installation from an approved bundle."""
import email
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import zipfile

from .profile_lock import profile_lock
from .setup_storage import (checked_path, child_environment, digest, private_directory,
                            persistent_path, read_regular, write_json, _read_in_checked_directory)


def load_bundle(manifest_path, expected_sha256):
    if not re.fullmatch(r'[0-9a-f]{64}', expected_sha256 or ''):
        raise ValueError('the approved bundle manifest SHA256 is required')
    manifest_path = checked_path(manifest_path)
    raw = read_regular(manifest_path)
    if digest(raw) != expected_sha256:
        raise ValueError('bundle manifest hash mismatch')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate manifest field')
            result[key] = value
        return result
    document = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(document, dict) or document.get('schema') != 1 or document.get('platform') != sys.platform:
        raise ValueError('bundle schema or platform is incompatible')
    if document.get('python') != f'{sys.version_info.major}.{sys.version_info.minor}':
        raise ValueError('bundle Python version is incompatible')
    wheels = document.get('wheels')
    if not isinstance(wheels, list) or not 2 <= len(wheels) <= 256:
        raise ValueError('bounded wheel list required')
    seen, files = {}, []
    for item in wheels:
        if not isinstance(item, dict):
            raise ValueError('wheel entry must be an object')
        filename, name, version, sha = (item.get(k) for k in ('filename', 'name', 'version', 'sha256'))
        if (not isinstance(filename, str) or not re.fullmatch(r'[A-Za-z0-9_.+-]+\.whl', filename)
                or not isinstance(name, str) or not re.fullmatch(r'[a-z0-9]+(?:-[a-z0-9]+)*', name)
                or not isinstance(version, str) or not re.fullmatch(r'[A-Za-z0-9_.+!-]+', version)
                or not isinstance(sha, str) or not re.fullmatch(r'[0-9a-f]{64}', sha) or name in seen):
            raise ValueError('unsafe or duplicate wheel entry')
        path = checked_path(manifest_path.parent / filename)
        data = read_regular(path, 200 * 1024 * 1024)
        if digest(data) != sha:
            raise ValueError('wheel hash mismatch: ' + filename)
        with zipfile.ZipFile(path) as archive:
            entries = [n for n in archive.namelist() if n.endswith('.dist-info/METADATA')]
            if len(entries) != 1:
                raise ValueError('wheel metadata is ambiguous')
            if archive.getinfo(entries[0]).file_size > 2 * 1024 * 1024:
                raise ValueError('wheel metadata exceeds its size limit')
            meta = email.message_from_bytes(archive.read(entries[0]))
            normalized = re.sub(r'[-_.]+', '-', meta.get('Name', '')).lower()
            if normalized != name or meta.get('Version') != version:
                raise ValueError('wheel metadata does not match manifest')
        seen[name] = version
        files.append(path)
    if not {'a4a-sdk', 'a4a-mcp'} <= set(seen):
        raise ValueError('both A4A distributions are required')
    return document, files


def run_checked(argv, *, cwd, timeout=180):
    result = subprocess.run([str(a) for a in argv], cwd=cwd, env=child_environment(),
                            capture_output=True, timeout=timeout)
    if result.returncode:
        # Commands/outputs can contain paths or sensitive host values: do not echo them.
        raise ValueError('installation subprocess failed (exit ' + str(result.returncode) + ')')
    return result.stdout


def runtime_inventory(environment):
    checked_path(environment)
    result = {}
    # Check each directory once rather than repeating its ancestors for every
    # package file. State is private; a noncooperating edit still has the usual
    # filesystem race limits and is not an atomic snapshot guarantee.
    for directory, folders, files in os.walk(environment, followlinks=False):
        directory = checked_path(directory)
        for folder in folders:
            path = directory / folder
            if path.is_symlink() and sys.platform == 'linux' and path == environment / 'lib64':
                # CPython's 64-bit Linux venv creates this alias even with
                # --copies. Bind its exact type/target and never traverse it.
                # Every other link remains subject to strict checked_path.
                if os.readlink(path) != 'lib' or not checked_path(environment / 'lib').is_dir():
                    raise ValueError('unexpected runtime lib64 alias')
                result['lib64'] = {'kind': 'symlink', 'target': 'lib'}
            else:
                checked_path(path)
        for name in sorted(files):
            path = directory / name
            result[path.relative_to(environment).as_posix()] = digest(
                _read_in_checked_directory(path, 200 * 1024 * 1024))
    return result


def inspect_packages(python, versions, *, cwd):
    code = ('import json,sys; from importlib.metadata import version; import a4a,a4a_mcp; '
            'print(json.dumps({"versions":{n:version(n) for n in ' + repr(list(versions)) +
            '},"modules":[a4a.__file__,a4a_mcp.__file__],"prefix":sys.prefix}))')
    result = json.loads(run_checked([python, '-I', '-c', code], cwd=cwd))
    if result['versions'] != versions or any(not Path(p).is_relative_to(Path(result['prefix']))
                                            for p in result['modules']):
        raise ValueError('installed modules or package versions do not match the accepted bundle')
    return result


def install_runtime(*, bundle, bundle_sha256, root, base_python, uv, uv_sha256, project=None):
    document, files = load_bundle(bundle, bundle_sha256)  # Validate before mutation.
    root = persistent_path(root)
    base_python, uv = (checked_path(p) for p in (base_python, uv))
    if project is not None and root.is_relative_to(checked_path(project)):
        raise ValueError('runtime must be outside the target project')
    if not base_python.is_file() or not uv.is_file():
        raise ValueError('verified absolute Python and uv executables are required')
    if (not isinstance(uv_sha256, str) or not re.fullmatch(r'[0-9a-f]{64}', uv_sha256)
            or digest(read_regular(uv, 200 * 1024 * 1024)) != uv_sha256):
        raise ValueError('uv executable does not match its approved SHA256')
    actual_python = run_checked([base_python, '-I', '-c',
        'import sys; print(str(sys.version_info.major)+"."+str(sys.version_info.minor))'], cwd=base_python.parent).decode().strip()
    if actual_python != document['python']:
        raise ValueError('base Python does not match the approved bundle')
    root = private_directory(root)
    # The runtime id also binds the base interpreter, not only dependency wheels.
    identity = digest((bundle_sha256 + '\n' + str(base_python) + '\n' +
                       digest(read_regular(base_python, 200 * 1024 * 1024))).encode())[:24]
    environment = root / ('runtime-' + identity)
    receipt_path = root / ('runtime-' + identity + '.json')
    with profile_lock(root):
        if environment.exists() or receipt_path.exists():
            if not receipt_path.exists():
                raise ValueError('incomplete runtime retained; inspect it before choosing a new root')
            receipt = json.loads(read_regular(receipt_path, 16 * 1024 * 1024))
            if receipt.get('bundle_sha256') != bundle_sha256 or receipt.get('state') != 'runtime_installed':
                raise ValueError('runtime receipt does not match the approved bundle')
            doctor_runtime(receipt_path)
            return receipt
        checked_path(environment)
        run_checked([base_python, '-I', '-m', 'venv', '--copies', '--without-pip', environment], cwd=root)
        if sys.platform == 'darwin':
            lock = checked_path(environment / '.lock')
            descriptor = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        python = environment / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
        requirements = root / ('requirements-' + identity + '.txt')
        from .setup_storage import atomic_private_write
        atomic_private_write(requirements, ''.join(
            f"{w['name']}=={w['version']} --hash=sha256:{w['sha256']}\n"
            for w in document['wheels']).encode())
        run_checked([uv, '--no-config', '--no-cache', 'pip', 'install', '--python', python, '--no-index',
                     '--find-links', files[0].parent, '--require-hashes', '--link-mode', 'copy', '--only-binary', ':all:',
                     '-r', requirements], cwd=root)
        run_checked([uv, '--no-config', 'pip', 'check', '--python', python], cwd=root)
        versions = {w['name']: w['version'] for w in document['wheels']}
        installed = inspect_packages(python, versions, cwd=root)
        from .setup_probe import probe_stdio
        probe = probe_stdio(python, root)
        # Cache files are executable code too. Precompile the complete approved
        # package tree, then bind bytecode in the inventory rather than ignoring
        # injected or modified __pycache__ entries on subsequent diagnostics.
        package_tree = environment / ('Lib/site-packages' if os.name == 'nt' else
            f'lib/python{document["python"]}/site-packages')
        run_checked([python, '-I', '-m', 'compileall', '-q', '-f', package_tree], cwd=root)
        receipt = {'schema': 1, 'state': 'runtime_installed', 'bundle_sha256': bundle_sha256,
                   'environment': str(environment), 'python': str(python), 'base_python': str(base_python),
                   'uv_sha256': uv_sha256,
                   'base_python_sha256': digest(read_regular(base_python, 200 * 1024 * 1024)),
                   'stdio': probe,
                   'versions': versions, 'modules': installed['modules'],
                   'inventory': runtime_inventory(environment), 'receipt_path': str(receipt_path),
                   'native_tools_verified': False, 'network_verified': False,
                   'background_verified': False}
        write_json(receipt_path, receipt)
        return receipt


def doctor_runtime(receipt_path):
    receipt_path = checked_path(receipt_path)
    receipt = json.loads(read_regular(receipt_path, 16 * 1024 * 1024))
    environment = checked_path(receipt['environment'])
    if (receipt.get('schema') != 1 or receipt.get('state') != 'runtime_installed'
            or environment.parent != receipt_path.parent
            or receipt_path.name != environment.name + '.json'):
        raise ValueError('runtime receipt path or schema is invalid')
    private_directory(receipt_path.parent)
    base = checked_path(receipt['base_python'])
    if digest(read_regular(base, 200 * 1024 * 1024)) != receipt['base_python_sha256']:
        raise ValueError('base interpreter changed; no repair performed')
    python = checked_path(receipt['python'])
    if python != environment / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python'):
        raise ValueError('runtime launcher is outside its environment')
    if runtime_inventory(environment) != receipt['inventory']:
        raise ValueError('runtime files changed; no repair performed')
    inspect_packages(python, receipt['versions'], cwd=receipt_path.parent)
    from .setup_probe import probe_stdio
    probe = probe_stdio(python, receipt_path.parent)
    return {'state': 'runtime_verified', 'runtime': str(environment), 'stdio': probe,
            'native_tools_verified': False, 'network_verified': False, 'background_verified': False}
