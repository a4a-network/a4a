"""Missing or substituted corresponding sources must fail delivered verification."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import tarfile

import pytest

SPEC = importlib.util.spec_from_file_location('release_notices', Path(__file__).resolve().parents[1] / 'release_notices.py')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def tar_bytes(files, unsafe=False):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w:gz') as archive:
        for name, raw in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(raw)
            archive.addfile(member, io.BytesIO(raw))
        if unsafe:
            member = tarfile.TarInfo('Python-3.11.16/redirect')
            member.type = tarfile.SYMTYPE
            member.linkname = '/outside'
            archive.addfile(member)
    return output.getvalue()


def fixture(monkeypatch, *, missing_member=False, unsafe=False):
    version = '3.11.16'
    source_files = {'Python-' + version + '/' + name: name.encode() for name in
                    ('LICENSE', 'configure', 'Makefile.pre.in', 'Include/patchlevel.h',
                     'Modules/readline.c', 'Modules/_gdbmmodule.c')}
    if missing_member:
        del source_files['Python-' + version + '/configure']
    source = tar_bytes(source_files, unsafe)
    commit = 'a' * 40
    dockerfile = ('ENV PYTHON_VERSION ' + version + '\nENV PYTHON_SHA256 ' + MODULE.sha(source) + '\n').encode()
    licence = b'full packaging licence'
    recipe = tar_bytes({'python-' + commit + '/3.11/slim-trixie/Dockerfile': dockerfile,
                        'python-' + commit + '/LICENSE': licence})
    artifacts = [{'filename': name, 'size': len(raw), 'sha256': MODULE.sha(raw), 'url': 'https://example.test/' + name}
                 for name, raw in (('Python.tar.xz', source), ('recipe.tar.gz', recipe))]
    lock = {'base_reference': 'python@sha256:' + 'b' * 64, 'platform': 'linux/amd64', 'python_version': version,
            'source_archive': 'Python.tar.xz', 'recipe_archive': 'recipe.tar.gz', 'recipe_commit': commit,
            'recipe_path': '3.11/slim-trixie/Dockerfile', 'dockerfile_sha256': MODULE.sha(dockerfile),
            'recipe_license_sha256': MODULE.sha(licence), 'debian_build_context': 'docker-image://debian@sha256:' + 'c' * 64,
            'artifacts': artifacts, 'modules': []}
    nodes = {'/usr/local/include/python3.11/patchlevel.h': {'kind': 'file', 'data': source_files['Python-' + version + '/Include/patchlevel.h']},
             '/usr/local/lib/python3.11/LICENSE.txt': {'kind': 'file', 'data': source_files['Python-' + version + '/LICENSE']}}
    edges = []
    for name, needed, source_member in [('readline', 'libreadline.so.8', 'Modules/readline.c'),
                                        ('_gdbm', 'libgdbm.so.6', 'Modules/_gdbmmodule.c')]:
        raw = b'\x7fELF' + name.encode()
        path = '/usr/local/lib/python3.11/lib-dynload/' + name + '.cpython-311-x86_64-linux-gnu.so'
        lock['modules'].append({'path': path, 'size': len(raw), 'sha256': MODULE.sha(raw),
                                'needed': needed, 'source_member': source_member})
        nodes[path] = {'kind': 'file', 'data': raw}
        library = '/usr/lib/' + needed
        nodes[library] = {'kind': 'file', 'data': b'\x7fELFlibrary'}
        edges.append({'from': path, 'needed': needed, 'resolved': library})
    inventory = {'images': {image: {'image_id': 'sha256:' + str(n) * 64} for n, image in enumerate(('mcp', 'notary'))}}
    inventory_raw = json.dumps(inventory).encode()
    observations = {image: {'nodes': copy.deepcopy(nodes), 'selection': {'elf_edges': copy.deepcopy(edges)}}
                    for image in inventory['images']}
    bindings = []
    for image in observations:
        for item in lock['modules']:
            bindings.append({'image': image, **item, 'source_member_sha256': MODULE.sha(source_files['Python-' + version + '/' + item['source_member']]),
                             'resolved_library': next(e['resolved'] for e in edges if e['from'] == item['path'])})
    record = {'schema': 'a4a-cpython-corresponding-source-v1', 'inventory_sha256': MODULE.sha(inventory_raw),
              'base_reference': lock['base_reference'], 'platform': lock['platform'], 'python_version': version,
              'images': {image: item['image_id'] for image, item in inventory['images'].items()},
              'artifacts': copy.deepcopy(artifacts), 'modules': bindings,
              'independent_rebuild_proven': False, 'signature_authenticated': False}
    provenance = {'SLSA': {'invocation': {'configSource': {'entryPoint': 'Dockerfile', 'uri':
        'https://github.com/docker-library/python.git#' + commit + ':3.11/slim-trixie'},
        'environment': {'platform': lock['platform']}, 'parameters': {'args': {'context:debian:trixie-slim': lock['debian_build_context']}}}}}
    files = {'cpython-source/Python.tar.xz': source, 'cpython-source/recipe.tar.gz': recipe,
             'cpython-source/Dockerfile': dockerfile, 'cpython-source/docker-library-python.LICENSE': licence,
             'cpython-source/registry-provenance.json': json.dumps(provenance).encode()}
    base = {'schema': 'a4a-cpython-base-file-measurement-v1', 'base_reference': lock['base_reference'],
            'platform': lock['platform'], 'python_version': version,
            'files': [{'path': path, 'size': len(node['data']), 'sha256': MODULE.sha(node['data'])}
                      for path, node in nodes.items() if path.startswith('/usr/local/')]}
    files['cpython-source/base-binding.json'] = json.dumps(base).encode()
    monkeypatch.setattr(MODULE, 'cpython_source_lock', lambda: lock)
    return lock, record, files, inventory, inventory_raw, observations


@pytest.mark.parametrize('mutation', ['none', 'missing_archive', 'archive_bytes', 'recipe_bytes', 'version', 'base',
    'inventory', 'image', 'omit_module', 'duplicate_module', 'module_bytes', 'missing_edge', 'version_header',
    'licence', 'provenance_context', 'source_member', 'unsafe_archive', 'missing_source_member',
    'missing_base_measurement', 'base_file_hash', 'base_file_omitted', 'base_file_duplicate'])
def test_cpython_sources_bound_to_saved_modules(monkeypatch, mutation):
    lock, record, files, inventory, raw, observations = fixture(monkeypatch,
        missing_member=mutation == 'missing_source_member', unsafe=mutation == 'unsafe_archive')
    if mutation == 'missing_archive': del files['cpython-source/Python.tar.xz']
    elif mutation == 'archive_bytes': files['cpython-source/Python.tar.xz'] += b'changed'
    elif mutation == 'recipe_bytes': files['cpython-source/Dockerfile'] += b'changed'
    elif mutation == 'version': record['python_version'] = '3.11.15'
    elif mutation == 'base': record['base_reference'] = 'python@sha256:' + 'd' * 64
    elif mutation == 'inventory': record['inventory_sha256'] = '0' * 64
    elif mutation == 'image': record['images']['mcp'] = 'sha256:' + 'f' * 64
    elif mutation == 'omit_module': record['modules'].pop()
    elif mutation == 'duplicate_module': record['modules'].append(record['modules'][0])
    elif mutation == 'module_bytes': observations['mcp']['nodes'][lock['modules'][0]['path']]['data'] += b'changed'
    elif mutation == 'missing_edge': observations['mcp']['selection']['elf_edges'].pop()
    elif mutation == 'version_header': observations['mcp']['nodes']['/usr/local/include/python3.11/patchlevel.h']['data'] = b'older'
    elif mutation == 'licence': files['cpython-source/docker-library-python.LICENSE'] = b'partial'
    elif mutation == 'provenance_context':
        value = json.loads(files['cpython-source/registry-provenance.json'])
        value['SLSA']['invocation']['parameters']['args']['context:debian:trixie-slim'] = 'floating'
        files['cpython-source/registry-provenance.json'] = json.dumps(value).encode()
    elif mutation == 'source_member': record['modules'][0]['source_member_sha256'] = '0' * 64
    elif mutation == 'missing_base_measurement': del files['cpython-source/base-binding.json']
    elif mutation in ('base_file_hash', 'base_file_omitted', 'base_file_duplicate'):
        base = json.loads(files['cpython-source/base-binding.json'])
        if mutation == 'base_file_hash': base['files'][0]['sha256'] = '0' * 64
        elif mutation == 'base_file_omitted': base['files'].pop()
        else: base['files'].append(base['files'][0])
        files['cpython-source/base-binding.json'] = json.dumps(base).encode()
    files['cpython-source/manifest.json'] = json.dumps(record).encode()

    def read(path):
        if path not in files:
            raise FileNotFoundError(path)
        return files[path]

    if mutation == 'none':
        assert MODULE.validate_cpython_source(read, raw, inventory, observations) == {
            'images': 2, 'files': 4, 'archives': 2, 'source_version': '3.11.16'}
    else:
        with pytest.raises((MODULE.NoticeError, FileNotFoundError)):
            MODULE.validate_cpython_source(read, raw, inventory, observations)
