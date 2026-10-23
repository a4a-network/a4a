"""Common installer front door; reported readiness never substitutes for host tests."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from .setup_hosts import detect_hosts, host_plan, apply_file_plan, rollback_file_plan
from .setup_runtime import install_runtime, doctor_runtime
from .setup_storage import checked_path, persistent_path
from .setup_defaults import resolve_settings


def parser():
    root = argparse.ArgumentParser(prog='a4a-mcp', allow_abbrev=False)
    commands = root.add_subparsers(dest='operation', required=True)
    connect = commands.add_parser('connect', allow_abbrev=False)
    connect.add_argument('--client', choices=['claude-code', 'claude-desktop', 'codex', 'cursor', 'kimi', 'kimi-code', 'gemini', 'antigravity', 'agy', 'generic'])
    connect.add_argument('--project', type=Path, default=Path.cwd())
    connect.add_argument('--bundle', type=Path)
    connect.add_argument('--bundle-sha256')
    connect.add_argument('--runtime-root', type=Path)
    connect.add_argument('--base-python', type=Path)
    connect.add_argument('--uv', type=Path)
    connect.add_argument('--uv-sha256', help='Approved SHA256 of the uv executable')
    profiles = connect.add_mutually_exclusive_group()
    profiles.add_argument('--home', type=Path, help='Explicit existing or new profile directory')
    profiles.add_argument('--profile', help='Explicit new or existing profile name in OS application data')
    connect.add_argument('--relay')
    connect.add_argument('--consumer')
    connect.add_argument('--config-path', type=Path, help='Explicit Desktop configuration destination')
    connect.add_argument('--host-executable', type=Path)
    actions = connect.add_mutually_exclusive_group()
    actions.add_argument('--apply', action='store_true', help='Authorize this concrete local installation/configuration')
    actions.add_argument('--detect', action='store_true', help='Read available host hints without installing')
    actions.add_argument('--plan', action='store_true', help='Show resolved setup choices without installing or configuring')
    doctor = commands.add_parser('doctor', allow_abbrev=False)
    doctor.add_argument('--receipt', type=Path, required=True)
    rollback = commands.add_parser('rollback', allow_abbrev=False)
    rollback.add_argument('--transaction', type=Path, required=True)
    return root


def select_host(explicit, hints):
    if explicit:
        return explicit
    if not hints:
        raise ValueError('no supported host was identified; select the intended application with --client')
    if len(hints) == 1 and hints[0]['evidence'] == 'launcher_on_path':
        return hints[0]['client']
    if not sys.stdin.isatty():
        raise ValueError('multiple or uncertain host hints; supply --client, no settings changed')
    print('Choose the intended application (one shared A4A installer):', file=sys.stderr)
    for i, hint in enumerate(hints, 1):
        print(f"{i}. {hint['family']} / {hint['client']}", file=sys.stderr)
    answer = input('Application number: ').strip()
    if not answer.isdigit() or not 1 <= int(answer) <= len(hints):
        raise ValueError('no application selected')
    return hints[int(answer) - 1]['client']


def cli(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.operation == 'doctor':
            result = doctor_runtime(args.receipt)
        elif args.operation == 'rollback':
            result = rollback_file_plan(args.transaction)
        elif args.detect:
            result = {'state': 'discovery_only', 'hosts': detect_hosts(), 'ready': False}
        else:
            # Current prerelease accepts explicit approved offline bundles only.
            # It never guesses a registry namespace or downloads a same-named package.
            if not args.plan and (not args.bundle or not args.bundle_sha256):
                raise ValueError('no accepted public installer bundle is embedded yet; provide an approved local --bundle and --bundle-sha256')
            client = select_host(args.client, detect_hosts())
            project = checked_path(args.project)
            if not project.is_dir():
                raise ValueError('the intended project does not exist')
            settings = resolve_settings(home=args.home, profile=args.profile,
                runtime_root=args.runtime_root, relay=args.relay, consumer=args.consumer,
                base_python=args.base_python, interactive=sys.stdin.isatty())
            home = settings['home']
            runtime_root = settings['runtime_root']
            if home.is_relative_to(project) or runtime_root.is_relative_to(project):
                raise ValueError('identity must be outside both the project and runtime')
            # Validate host inputs using the checked base, not a transient uvx
            # or linked venv launcher. This plan is discarded; registration
            # below uses only the accepted permanent runtime path.
            host_plan(client=client, python=settings['base_python'], home=home,
                project=project, relay=settings['relay'], consumer=settings['consumer'],
                config_path=args.config_path, host_executable=args.host_executable)
            choices = {key: str(value) if isinstance(value, Path) else value for key, value in settings.items()}
            if args.plan:
                result = {'state': 'setup_plan', 'client': client, 'project': str(project),
                    'choices': choices, 'changes_made': False, 'ready': False,
                    'requires_approved_bundle': True,
                    'next_action': 'Review these exact choices; apply only with an approved bundle and uv hash. Host trust and permissions remain separate.'}
                print(json.dumps(result, ensure_ascii=True, indent=2))
                return 0
            if not args.apply:
                if not sys.stdin.isatty():
                    raise ValueError('installation not authorized; review the explicit paths and use --apply')
                print(f'Install A4A and merge its entry for {client} in the selected scope. '
                      'No keys, mandates, contacts or messages will be created.', file=sys.stderr)
                print(json.dumps(choices, ensure_ascii=True, indent=2), file=sys.stderr)
                if input('Apply this setup? [y/N] ').strip().lower() != 'y':
                    raise ValueError('installation declined; no changes made')
            uv = args.uv or shutil.which('uv')
            if uv is None:
                raise ValueError('uv is not installed; use its official installation process')
            receipt = install_runtime(bundle=args.bundle, bundle_sha256=args.bundle_sha256,
                root=runtime_root, base_python=settings['base_python'],
                uv=uv, uv_sha256=args.uv_sha256, project=project)
            plan = host_plan(client=client, python=receipt['python'], home=home,
                             project=project, relay=settings['relay'], consumer=settings['consumer'],
                             config_path=args.config_path, host_executable=args.host_executable)
            configured = apply_file_plan(plan, runtime_root / 'host-transactions')
            result = {**configured, 'client': client, 'runtime_receipt': receipt['receipt_path'],
                      'stdio': receipt['stdio'],
                      'choices': choices,
                      'native_tools_verified': False, 'network_verified': False,
                      'background_verified': False, 'ready': False,
                      'next_action': 'Reconnect the selected host, verify native A4A tools, then authorize identity/contacts and test an exchange.'}
        print(json.dumps(result, ensure_ascii=True, indent=2))
        return 0
    except subprocess.TimeoutExpired:
        print(json.dumps({'state': 'setup_refused', 'ready': False,
                          'reason': 'installation or diagnostic subprocess timed out; retained state'}), file=sys.stderr)
        return 2
    except (ValueError, OSError, KeyError, TypeError) as exc:
        print(json.dumps({'state': 'setup_refused', 'ready': False, 'reason': str(exc)}, ensure_ascii=True), file=sys.stderr)
        return 2
