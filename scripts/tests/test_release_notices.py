"""Reject omitted packages and altered portable notice evidence."""
import hashlib
import importlib.util
import io
import json
import tarfile
from pathlib import Path
import pytest

SPEC=importlib.util.spec_from_file_location('release_notices',Path(__file__).resolve().parents[1]/'release_notices.py')
MODULE=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(MODULE)

def python_fixture():
    metadata=b'Name: example\nVersion: 1.0\nLicense-Expression: MIT\nLicense-File: LICENSE\n\n'
    license=b'Original complete notice'
    paths={'/site/example-1.0.dist-info/METADATA':metadata,'/site/example-1.0.dist-info/LICENSE':license}
    record={'packages':[{'name':'example','version':'1.0','license_expression':'MIT','license_metadata':None,
                         'metadata_files':['/site/example-1.0.dist-info/METADATA'],
                         'license_files':['/site/example-1.0.dist-info/LICENSE']}],
            'files':[{'path':p,'sha256':hashlib.sha256(v).hexdigest(),'size':len(v)} for p,v in paths.items()]}
    sbom={'packages':[{'name':'example','versionInfo':'1.0','externalRefs':[{'referenceType':'purl','referenceLocator':'pkg:pypi/example@1.0'}]}]}
    return record,sbom,lambda p:paths['/'+p.split('/',2)[2]]

def test_python_notice_identity_and_declared_text():
    record,sbom,read=python_fixture()
    assert MODULE.validate_python('mcp',record,sbom,read)==1

@pytest.mark.parametrize('mutation',['omit','version','license','notice_hash','declared_file','duplicate'])
def test_python_rejects_missing_changed_or_duplicate_package_notice(mutation):
    record,sbom,read=python_fixture()
    if mutation=='omit':record['packages'].clear()
    elif mutation=='version':record['packages'][0]['version']='0.9'
    elif mutation=='license':record['packages'][0]['license_expression']='BSD-2-Clause'
    elif mutation=='notice_hash':record['files'][1]['sha256']='0'*64
    elif mutation=='declared_file':record['packages'][0]['license_files'].clear()
    else:record['packages'].append(record['packages'][0])
    with pytest.raises(MODULE.NoticeError):MODULE.validate_python('mcp',record,sbom,read)

def test_portable_material_index_changes_when_notice_changes(tmp_path):
    (tmp_path/'LICENSE').write_bytes(b'original')
    first=MODULE.index_materials(tmp_path)
    assert first==[{'path':'LICENSE','sha256':hashlib.sha256(b'original').hexdigest(),'size':8}]
    (tmp_path/'LICENSE').write_bytes(b'changed')
    assert MODULE.index_materials(tmp_path)!=first

def test_materials_reject_reserved_snapshot_manifest(tmp_path):
    (tmp_path/'manifest.json').write_bytes(b'{}')
    with pytest.raises(MODULE.NoticeError):MODULE.index_materials(tmp_path)


@pytest.mark.parametrize("image_family", ["relay", "mcp", "notary"])
@pytest.mark.parametrize("mutation", ["none", "bytes", "hidden", "sbom", "mode", "user", "lower_layer"])
def test_selected_runtime_checks_saved_payload_and_complete_sbom(mutation, image_family):
    python = image_family != "relay"
    binary = b"measured relay binary"
    selection = {"schema": "a4a-selected-python-runtime-v1" if python else "a4a-selected-relay-runtime-v1",
                 "whole_usr_local_retained": True, "installed_packages": [{"Package": "relay-lib", "Version": "1"}],
                 "files": [{"path": "/usr/src/app/nostr-rs-relay", "kind": "file", "uid": 1000, "gid": 1000,
                            "mode": 0o755, "size": len(binary), "sha256": MODULE.sha(binary)}]}
    selected = json.dumps(selection).encode()
    layer = io.BytesIO()
    with tarfile.open(fileobj=layer, mode="w") as archive:
        files = {"usr/src/app/nostr-rs-relay": b"changed bytes" if mutation == "bytes" else binary,
                 "usr/local/share/" + ("a4a-python-runtime-selection" if python else "a4a-runtime-selection") + "/manifest.json": selected,
                 "etc/ld.so.cache": b"cache"}
        if mutation == "hidden":
            files["usr/bin/hidden"] = b"unindexed payload"
        for name, data in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            member.mode = 0o4755 if mutation == "mode" else 0o755
            member.uid = member.gid = 1000
            archive.addfile(member, io.BytesIO(data))
    layers = {"layer.tar": layer.getvalue()}
    if mutation == "lower_layer":
        old = io.BytesIO()
        with tarfile.open(fileobj=old, mode="w") as archive:
            member = tarfile.TarInfo("usr/src/app/nostr-rs-relay")
            member.size = len(b"hidden replaced payload")
            member.uid = member.gid = 1000
            member.mode = 0o755
            archive.addfile(member, io.BytesIO(b"hidden replaced payload"))
        layers = {"old.tar": old.getvalue(), **layers}
    config = json.dumps({"config": {"User": "root" if mutation == "user" else "10001" if python else "appuser"},
                         "rootfs": {"diff_ids": ["sha256:" + MODULE.sha(data) for data in layers.values()]}}).encode()
    image = "sha256:" + MODULE.sha(config)
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name, data in {"config.json": config, **layers,
                           "manifest.json": json.dumps([{"Config": "config.json", "Layers": list(layers)}]).encode()}.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    raw = output.getvalue()
    record = {"schema": "a4a-selected-python-runtime-layer-evidence-v1" if python else "a4a-selected-runtime-layer-evidence-v1",
              "image_archive": "runtime/image.tar", "image_id" if python else "relay_image_id": image,
              "image_archive_sha256": MODULE.sha(raw), "selection_manifest_sha256": MODULE.sha(selected)}
    sbom = {"packages": [] if mutation == "sbom" else [{"name": "relay-lib", "versionInfo": "1", "externalRefs": [
        {"referenceType": "purl", "referenceLocator": "pkg:deb/debian/relay-lib@1?arch=amd64"}]}]}
    inventory = {"images": {image_family: {"image_id": image}}}
    action = lambda: MODULE.validate_selected_runtime(record, sbom, inventory, lambda name: raw, image=image_family)
    if mutation == "none":
        assert action() == 1
    else:
        with pytest.raises(MODULE.NoticeError):
            action()

@pytest.mark.parametrize('mutation',['none','bytes','extra','head','scope','coverage'])
def test_snapshot_preserves_exact_files_version_and_pending_grants(tmp_path, monkeypatch, mutation):
    source=tmp_path/'materials';source.mkdir();(source/'LICENSE').write_bytes(b'notice')
    inventory=b'{"retained":true}'
    coverage={'pending_notice_grants':[{'name':'example','version':'1.0'}]}
    monkeypatch.setattr(MODULE,'validate_materials',lambda read,raw,**kwargs:coverage)
    git={'commit':'1'*40,'dirty':False,'changed_paths':[]}
    output=tmp_path/'snapshot'
    snapshot=MODULE.build_snapshot(source,output,inventory,git)
    actual={'LICENSE'}
    if mutation=='bytes':(output/'LICENSE').write_bytes(b'forged')
    elif mutation=='extra':actual.add('extra')
    elif mutation=='head':git={**git,'commit':'2'*40}
    elif mutation=='scope':snapshot['complete_legal_acceptance']=True
    elif mutation=='coverage':snapshot['coverage']={}
    (output/'manifest.json').write_text(json.dumps(snapshot))
    verify=lambda:MODULE.verify_snapshot(lambda p:(output/p).read_bytes(),inventory,actual,git['commit'])
    if mutation=='none':assert verify()['file_count']==1
    else:
        with pytest.raises(MODULE.NoticeError):verify()


def tar_bytes(files):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w:gz') as archive:
        for name, raw in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(raw)
            archive.addfile(member, io.BytesIO(raw))
    return output.getvalue()


def native_python_fixture():
    import base64
    root = '/site/'
    parent = 'example-1.0.dist-info/'
    paths = {root + parent + 'METADATA': b'Name: example\nVersion: 1.0\nLicense-Expression: MIT\nLicense-File: LICENSE\n\n',
             root + parent + 'LICENSE': b'Complete license',
             root + parent + 'sboms/nested.json': b'{"bomFormat":"CycloneDX","components":[]}',
             root + 'example/native.so': b'\x7fELFactual library'}
    record_path = root + parent + 'RECORD'
    lines = []
    for path, raw in paths.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b'=').decode()
        lines.append(path.removeprefix(root) + ',sha256=' + digest + ',' + str(len(raw)))
    paths[record_path] = ('\n'.join(lines) + '\n' + parent + 'RECORD,,\n').encode()
    metadata = [root + parent + 'METADATA', record_path]
    notices = [root + parent + 'LICENSE']
    sboms = [root + parent + 'sboms/nested.json']
    native = [{'path': root + 'example/native.so', 'sha256': MODULE.sha(paths[root + 'example/native.so']),
               'size': len(paths[root + 'example/native.so'])}]
    collected = set(metadata + notices + sboms)
    record = {'schema': 'a4a-python-notices-v2', 'packages': [
        {'name': 'example', 'version': '1.0', 'license_expression': 'MIT', 'license_metadata': None,
         'metadata_files': metadata, 'license_files': notices, 'sbom_files': sboms, 'native_files': native}],
        'files': [{'path': p, 'sha256': MODULE.sha(paths[p]), 'size': len(paths[p])} for p in collected]}
    sbom = {'packages': [{'name': 'example', 'versionInfo': '1.0', 'externalRefs': [
        {'referenceType': 'purl', 'referenceLocator': 'pkg:pypi/example@1.0'}]}]}
    return record, sbom, paths, lambda p: paths['/' + p.split('/', 2)[2]]


@pytest.mark.parametrize('mutation', ['none', 'omit_sbom', 'omit_native', 'changed_sbom', 'changed_native', 'duplicate_record', 'legacy'])
def test_native_python_record_prevents_silent_omissions(mutation):
    record, sbom, paths, read = native_python_fixture()
    package = record['packages'][0]
    if mutation == 'omit_sbom': package['sbom_files'] = []
    elif mutation == 'omit_native': package['native_files'] = []
    elif mutation == 'changed_native': package['native_files'][0]['sha256'] = '0' * 64
    elif mutation == 'legacy': record.pop('schema')
    elif mutation in ('changed_sbom', 'duplicate_record'):
        path = package['sbom_files'][0] if mutation == 'changed_sbom' else package['metadata_files'][1]
        paths[path] += b' ' if mutation == 'changed_sbom' else paths[path].splitlines()[0] + b'\n'
        entry = next(v for v in record['files'] if v['path'] == path)
        entry.update(size=len(paths[path]), sha256=MODULE.sha(paths[path]))
    action = lambda: MODULE.validate_python('mcp', record, sbom, read, require_native=True)
    if mutation == 'none': assert action() == 1
    else:
        with pytest.raises(MODULE.NoticeError): action()


def dependency_fixture(repository=False, local=False):
    commit = '1' * 40
    source = tar_bytes({'crate-1.0/.cargo_vcs_info.json': json.dumps({'git': {'sha1': commit}}).encode()}
                       if repository else {'crate-1.0/LICENSE': b'Complete upstream grant'})
    component = {'name': 'crate', 'version': '1.0', 'purl': 'pkg:cargo/crate@1.0',
                 'licenses': [{'expression': 'MIT'}], 'hashes': [{'alg': 'SHA-256', 'content': MODULE.sha(source)}]}
    if local: component['purl'] += '?download_url=file://crate'
    sbom_path = '/site/example-1.0.dist-info/sboms/nested.json'
    raw = json.dumps({'bomFormat': 'CycloneDX', 'components': [component]}).encode()
    package = {'name': 'example', 'version': '1.0', 'sbom_files': [sbom_path], 'native_files': [],
               'license_expression': 'MIT', 'license_files': ['/site/example-1.0.dist-info/LICENSE']}
    records = {'mcp': {'packages': [package]}}
    inventory = {'images': {'mcp': {'image_id': 'sha256:' + '2' * 64}}}
    inventory_raw = json.dumps(inventory).encode()
    item = {'image': 'mcp', 'sbom': sbom_path, 'sbom_sha256': MODULE.sha(raw),
            'purl': component['purl'], 'name': 'crate', 'version': '1.0', 'licenses': component['licenses'],
            'source_archive': 'native/source.tar.gz', 'notices': [{'path': 'native/LICENSE', 'member': 'crate-1.0/LICENSE'}]}
    files = {'files/mcp' + sbom_path: raw, 'native/source.tar.gz': source, 'native/LICENSE': b'Complete upstream grant'}
    if repository:
        repo = tar_bytes({'repo-' + commit + '/LICENSE': files['native/LICENSE']})
        files['native/repo.tar.gz'] = repo
        item['notice_repository'] = {'archive': 'native/repo.tar.gz', 'commit': commit, 'sha256': MODULE.sha(repo)}
        item['notices'][0]['member'] = 'repo-' + commit + '/LICENSE'
    if local: item['distribution_notices'] = package['license_files']
    evidence = {'schema': 'a4a-python-native-dependencies-v1', 'inventory_sha256': MODULE.sha(inventory_raw),
                'images': {'mcp': inventory['images']['mcp']['image_id']}, 'components': [item], 'without_sbom': [],
                'complete_link_closure_proven': False, 'complete_legal_acceptance': False, 'release_approved': False}
    return records, inventory, inventory_raw, evidence, files


@pytest.mark.parametrize('mutation', ['none', 'omit', 'duplicate', 'source', 'notice', 'license', 'sbom_hash', 'image', 'approved'])
def test_native_component_grants_are_complete_and_source_bound(mutation):
    records, inventory, raw, evidence, files = dependency_fixture()
    if mutation == 'omit': evidence['components'] = []
    elif mutation == 'duplicate': evidence['components'] *= 2
    elif mutation == 'source': files['native/source.tar.gz'] = b'wrong source'
    elif mutation == 'notice': files['native/LICENSE'] = b'substituted grant'
    elif mutation == 'license': evidence['components'][0]['licenses'] = [{'expression': 'Apache-2.0'}]
    elif mutation == 'sbom_hash': evidence['components'][0]['sbom_sha256'] = '0' * 64
    elif mutation == 'image': evidence['images']['mcp'] = 'sha256:' + '3' * 64
    elif mutation == 'approved': evidence['complete_legal_acceptance'] = True
    files['python-native-dependencies.json'] = json.dumps(evidence).encode()
    action = lambda: MODULE.validate_native_dependencies(records, inventory, raw, files.__getitem__)
    if mutation == 'none': assert action()['component_occurrences'] == 1
    else:
        with pytest.raises(MODULE.NoticeError): action()


@pytest.mark.parametrize('mutation', ['none', 'commit', 'bytes'])
def test_native_repository_notice_uses_crate_recorded_commit(mutation):
    records, inventory, raw, evidence, files = dependency_fixture(repository=True)
    if mutation == 'commit': evidence['components'][0]['notice_repository']['commit'] = '4' * 40
    elif mutation == 'bytes': files['native/repo.tar.gz'] = b'wrong repository'
    files['python-native-dependencies.json'] = json.dumps(evidence).encode()
    action = lambda: MODULE.validate_native_dependencies(records, inventory, raw, files.__getitem__)
    if mutation == 'none': assert action()['component_occurrences'] == 1
    else:
        with pytest.raises(MODULE.NoticeError): action()


def test_native_local_project_cannot_substitute_parent_grant():
    records, inventory, raw, evidence, files = dependency_fixture(local=True)
    files['python-native-dependencies.json'] = json.dumps(evidence).encode()
    assert MODULE.validate_native_dependencies(records, inventory, raw, files.__getitem__)['component_occurrences'] == 1
    records['mcp']['packages'][0]['license_expression'] = 'BSD-3-Clause'
    with pytest.raises(MODULE.NoticeError): MODULE.validate_native_dependencies(records, inventory, raw, files.__getitem__)


def test_new_snapshot_refuses_legacy_materials_before_creating_output(tmp_path):
    source = tmp_path / 'materials'; source.mkdir()
    raw = b'{}'
    (source / 'materials.json').write_text(json.dumps({'schema': 'a4a-release-notice-materials-v2',
        'inventory_sha256': MODULE.sha(raw), 'complete_legal_acceptance': False, 'signature_authenticated': False}))
    output = tmp_path / 'snapshot'
    with pytest.raises(MODULE.NoticeError, match='v3 native component coverage'):
        MODULE.build_snapshot(source, output, raw, {'commit': '1' * 40, 'dirty': False, 'changed_paths': []})
    assert not output.exists()


@pytest.mark.parametrize('mutation', ['none', 'omitted', 'forged_hash', 'hidden_elf', 'changed_sbom', 'omitted_sbom', 'forged_metadata'])
def test_native_coverage_is_checked_against_saved_payload(mutation):
    prefix = '/usr/local/lib/python3.11/site-packages/'
    binary_path = prefix + 'example/native.so'
    sbom_path = prefix + 'example-1.0.dist-info/sboms/nested.json'
    data = {binary_path: b'\x7fELFactual library', sbom_path: b'{"components":[]}'}
    if mutation == 'hidden_elf': data[prefix + 'example/hidden.bin'] = b'\x7fELFhidden library'
    selection = {'schema': 'a4a-selected-python-runtime-v1', 'whole_usr_local_retained': True,
                 'installed_packages': [], 'files': [
        {'path': p, 'kind': 'file', 'uid': 10001, 'gid': 10001, 'mode': 0o644,
         'size': len(raw), 'sha256': MODULE.sha(raw)} for p, raw in data.items()]}
    selected = json.dumps(selection).encode()
    layer = io.BytesIO()
    with tarfile.open(fileobj=layer, mode='w') as t:
        for path, raw in {**data, '/usr/local/share/a4a-python-runtime-selection/manifest.json': selected,
                          '/etc/ld.so.cache': b'cache'}.items():
            member = tarfile.TarInfo(path.lstrip('/')); member.size = len(raw)
            member.uid = member.gid = 10001; member.mode = 0o644
            t.addfile(member, io.BytesIO(raw))
    config = json.dumps({'config': {'User': '10001'}, 'rootfs': {'diff_ids': ['sha256:' + MODULE.sha(layer.getvalue())]}}).encode()
    image = 'sha256:' + MODULE.sha(config)
    saved = tar_bytes({'config.json': config, 'layer.tar': layer.getvalue(),
                       'manifest.json': json.dumps([{'Config': 'config.json', 'Layers': ['layer.tar']}]).encode()})
    record = {'schema': 'a4a-selected-python-runtime-layer-evidence-v1', 'image_id': image,
              'image_archive': 'image.tar', 'image_archive_sha256': MODULE.sha(saved),
              'selection_manifest_sha256': MODULE.sha(selected)}
    python = {'files': [{'path': sbom_path, 'size': len(data[sbom_path]), 'sha256': MODULE.sha(data[sbom_path])}],
              'packages': [{'sbom_files': [sbom_path], 'native_files': [
        {'path': binary_path, 'size': len(data[binary_path]), 'sha256': MODULE.sha(data[binary_path])}]}]}
    if mutation == 'omitted': python['packages'][0]['native_files'] = []
    elif mutation == 'forged_hash': python['packages'][0]['native_files'][0]['sha256'] = '0' * 64
    elif mutation == 'omitted_sbom': python['packages'][0]['sbom_files'] = []; python['files'] = []
    elif mutation == 'forged_metadata': python['files'][0]['sha256'] = '0' * 64
    read = lambda path: saved if path == 'image.tar' else b'{"components":[{}]}' if mutation == 'changed_sbom' else data[sbom_path]
    action = lambda: MODULE.validate_selected_runtime(record, {'packages': []}, {'images': {'mcp': {'image_id': image}}},
                                                       read, image='mcp', python_notices=python)
    if mutation == 'none': assert action() == 0
    else:
        with pytest.raises(MODULE.NoticeError): action()


def test_native_packages_without_sbom_cannot_disappear_from_coverage():
    records, inventory, raw, evidence, files = dependency_fixture()
    package = {'name': 'unknown-native', 'version': '1.0', 'sbom_files': [],
               'native_files': [{'path': '/site/native.so', 'size': 10, 'sha256': '0' * 64}]}
    records['mcp']['packages'].append(package)
    files['python-native-dependencies.json'] = json.dumps(evidence).encode()
    with pytest.raises(MODULE.NoticeError, match='without SBOM'):
        MODULE.validate_native_dependencies(records, inventory, raw, files.__getitem__)
    evidence['without_sbom'] = [{'image': 'mcp', 'name': 'unknown-native', 'version': '1.0',
                                 'native_files': package['native_files'], 'state': 'requires-file-level-review'}]
    files['python-native-dependencies.json'] = json.dumps(evidence).encode()
    assert MODULE.validate_native_dependencies(records, inventory, raw, files.__getitem__)['without_sbom'] == evidence['without_sbom']


def test_collector_preserves_nested_sbom_without_importing_package(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location('python_notice_collector', Path(__file__).parents[1] / 'collect-python-notices.py')
    collector = importlib.util.module_from_spec(spec); spec.loader.exec_module(collector)
    record, _, paths, _ = native_python_fixture()
    site = tmp_path / 'site'; site.mkdir()
    for path, raw in paths.items():
        target = site / path.removeprefix('/site/'); target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(raw)
    (site / 'example/__init__.py').write_text('raise RuntimeError("package code must not execute")')
    metadata = MODULE.BytesParser().parsebytes(b'Name: example\nVersion: 1.0\nLicense-Expression: MIT\nLicense-File: LICENSE\n')
    class Distribution:
        version = '1.0'
        files = [p.removeprefix('/site/') for p in paths] + ['example/__init__.py']
        def locate_file(self, path): return site / path
    distribution = Distribution(); distribution.metadata = metadata
    monkeypatch.setattr(collector.importlib.metadata, 'distributions', lambda: [distribution])
    stdlib = tmp_path / 'stdlib'; stdlib.mkdir(); (stdlib / 'LICENSE.txt').write_bytes(b'CPython license')
    monkeypatch.setattr(collector.sysconfig, 'get_path', lambda _: str(stdlib))
    collected = collector.collect_installed()
    package = collected['packages'][0]
    assert package['sbom_files'] == [(site / 'example-1.0.dist-info/sboms/nested.json').as_posix()]
    assert package['native_files'][0]['sha256'] == record['packages'][0]['native_files'][0]['sha256']
