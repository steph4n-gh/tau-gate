#!/usr/bin/env python3
"""Check replay inventories with Python JSON/PyYAML and the official Yarn readers.

This is an external experiment oracle, not runtime parsing or execution qualification.
"""
import argparse
from collections import defaultdict
import json
from pathlib import Path
import posixpath
import subprocess

import yaml

from parser_corpus import save


def edges(report):
    return {(e['from'], e['to']): set(e['kinds']) for e in report['edges']}


def npm(case, report):
    lock = json.loads(Path(case['lock']).read_text())
    packages = {}
    names = {}
    legacy = lock['lockfileVersion'] == 1
    if legacy:
        entry = next(f for f in case['files'] if f['path'] == 'package.json')
        packages[''] = json.loads((Path(case['index']).parent / entry['file']).read_text())
        def visit(parent, items):
            for name, record in items.items():
                path = '/'.join(filter(None, [parent, 'node_modules', name]))
                packages[path] = record
                names[path] = name
                visit(path, record.get('dependencies', {}))
        visit('', lock.get('dependencies', {}))
    else:
        packages = lock['packages']
    actual = {p['path']: p for p in report['packages']}
    assert set(actual) == set(packages), 'npm record identities'
    expected_edges = defaultdict(set)
    def target(path, name):
        parts = path.split('/') if path else []
        for stop in range(len(parts), -1, -1):
            if stop and parts[stop - 1] == 'node_modules':
                continue
            candidate = '/'.join(parts[:stop] + ['node_modules', name])
            if candidate in packages:
                return candidate
        return None
    for path, record in packages.items():
        version = record.get('version', '')
        name = record.get('name', names.get(path, path.split('node_modules/')[-1]))
        source = record.get('resolved', '')
        if legacy and path:
            if version.startswith('npm:'):
                name, version = version[4:].rsplit('@', 1)
            if not source and record.get('version', '').startswith(('file:', 'git', 'http:', 'https:')):
                source = record['version']
        p = actual[path]
        assert (p['name'], p['version'], p['source'], p['integrity']) == (
            name, version, source, record.get('integrity', '')), ('npm artifact identity', path)
        if record.get('link') and record.get('resolved') in packages:
            expected_edges[path or 'root', record['resolved'] or 'root'].add('workspaceLink')
        kinds = ['requires'] if legacy and path else ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']
        for kind in kinds:
            for name in record.get(kind, {}):
                if kind == 'dependencies' and name in record.get('optionalDependencies', {}):
                    continue
                resolved = target(path, name)
                if resolved is not None:
                    expected_edges[path or 'root', resolved or 'root'].add(kind)
    assert edges(report) == expected_edges, 'npm typed edges'
    return {'records_checked': len(actual), 'edges_checked': len(expected_edges)}


def resolution_scalars(value):
    if isinstance(value, dict):
        return {k: resolution_scalars(v) for k, v in value.items()}
    if isinstance(value, list):
        return [resolution_scalars(v) for v in value]
    if isinstance(value, bool):
        return str(value).lower()
    return str(value)


def pnpm(case, report):
    documents = list(yaml.safe_load_all(Path(case['lock']).read_text()))
    actual = {p['path']: p for p in report['packages']}
    expected_edges = defaultdict(set)
    checked = set()
    for index, doc in enumerate(documents):
        scope = 'project' if index == len(documents) - 1 else 'environment'
        importers = doc['importers']
        records = doc.get('snapshots', doc.get('packages', {}))
        metadata = doc.get('packages', {})
        def importer_label(path):
            return 'root' if path == '.' and scope == 'project' else f'pnpm:{scope}:importer:{path}'
        def snapshot_label(key):
            return f'pnpm:{scope}:snapshot:{key}'
        def resolve(importer, name, version):
            if version.startswith('link:'):
                path = posixpath.normpath(posixpath.join(importer, version[5:]))
                candidates = [key for key, info in importers.items() if key == path or (
                    info.get('publishDirectory') and info.get('linkDirectory') is not False and
                    posixpath.normpath(posixpath.join(key, info['publishDirectory'])) == path)]
                assert len(candidates) <= 1
                return importer_label(candidates[0]) if candidates else f'pnpm:{scope}:link:{path}'
            candidates = [version[4:]] if version.startswith('npm:') else [version, f'{name}@{version}']
            for key in candidates + ['/' + k for k in candidates]:
                if key in records:
                    return snapshot_label(key)
            return None
        for key, record in records.items():
            label = snapshot_label(key)
            assert label in actual, ('pnpm missing snapshot', label)
            checked.add(label)
            candidates = [k for k in metadata if key == k or key.startswith(k + '(')]
            raw = metadata[max(candidates, key=len)] if candidates else {}
            identity = key.split('(', 1)[0].removeprefix('/')
            split = identity.find('@', 1)
            inferred_name, inferred_version = (identity[:split], identity[split + 1:]) if split >= 0 else (identity, '')
            assert actual[label]['name'] == raw.get('name', inferred_name), ('pnpm name', label)
            assert actual[label]['version'] == str(raw.get('version', inferred_version)), ('pnpm version', label)
            resolution = dict(raw.get('resolution', {}))
            integrity = resolution.pop('integrity', '')
            assert actual[label]['integrity'] == integrity, ('pnpm integrity', label)
            source = json.loads(actual[label]['source']) if actual[label]['source'] else {}
            assert source == resolution_scalars(resolution), ('pnpm source', label)
            for kind in ['dependencies', 'optionalDependencies']:
                for name, version in record.get(kind, {}).items():
                    dest = resolve('.', name, str(version))
                    if dest in actual:
                        expected_edges[label, dest].add(kind)
                        if str(version).startswith('link:'):
                            expected_edges[label, dest].add('workspaceLink')
        for path, importer in importers.items():
            label = importer_label(path)
            assert label in actual, ('pnpm importer identity', label)
            checked.add(label)
            for kind in ['dependencies', 'devDependencies', 'optionalDependencies', 'configDependencies', 'packageManagerDependencies']:
                for name, requirement in importer.get(kind, {}).items():
                    version = str(requirement['version'] if isinstance(requirement, dict) else requirement)
                    dest = resolve(path, name, version)
                    if dest in actual:
                        expected_edges[label, dest].add(kind)
                        if version.startswith('link:'):
                            expected_edges[label, dest].add('workspaceLink')
                            checked.add(dest)
    supplied = {f['path']: f for f in case['files']}
    for label in checked:
        if ':link:' not in label:
            continue
        logical = label.split(':link:', 1)[1] + '/package.json'
        entry = supplied[logical]
        source = json.loads((Path(case['index']).parent / entry['file']).read_text())
        assert actual[label]['name'] == source['name'], ('pnpm linked source name', label)
        assert actual[label]['version'] == source.get('version', ''), ('pnpm linked source version', label)
        assert report['resolution_metadata'][label + ':manifest'] == source, ('pnpm retained linked manifest', label)
    assert set(actual) == checked, 'pnpm unexpected records'
    observed = edges(report)
    missing = [(key, sorted(value)) for key, value in expected_edges.items() if observed.get(key) != value]
    extra = [(key, sorted(value)) for key, value in observed.items() if expected_edges.get(key) != value]
    assert not missing and not extra, ('pnpm typed edges', missing[:4], extra[:4])
    return {'records_checked': len(actual), 'edges_checked': len(expected_edges)}


def yarn(case, report, reference):
    actual = {p['path']: p for p in report['packages']}
    metadata = report['resolution_metadata']
    selectors = {}
    for label, info in metadata.items():
        for descriptor in info.get('descriptors', []):
            assert descriptor not in selectors
            selectors[descriptor] = label
    if reference['format'] == 'classic':
        records = reference['records']
        assert set(records) == set(selectors), 'Classic descriptor coverage'
        for descriptor, record in records.items():
            p = actual[selectors[descriptor]]
            assert p['version'] == record['version'], ('Classic version', descriptor)
            assert p['integrity'] == record.get('integrity', ''), ('Classic integrity', descriptor)
            if 'resolved' in record:
                assert p['source'] == record['resolved'], ('Classic source', descriptor)
        count = len(set(selectors.values()))
    else:
        groups = {k: v for k, v in reference['records'].items() if k != '__metadata'}
        expected = {d.strip() for group in groups for d in group.split(',')}
        assert expected == set(selectors), 'Berry descriptor coverage'
        for group, record in groups.items():
            labels = {selectors[d.strip()] for d in group.split(',')}
            assert len(labels) == 1
            label = labels.pop()
            p = actual[label]
            assert p['source'] == record['resolution'], ('Berry resolution', group)
            assert p['version'] == str(record['version']), ('Berry version', group)
            assert not p['integrity'], 'Yarn cache checksum must not become npm SRI'
            if 'checksum' in record:
                assert metadata[label]['checksum'] == record['checksum']
                assert metadata[label]['checksumKind'] == 'yarn-cache-checksum'
        count = len(groups)
    # Source-added workspace edges are tested separately; descriptor/artifact coverage
    # here is independent of Tau-Gate's YAML grammar and resolution implementation.
    return {'records_checked': count, 'descriptors_checked': len(selectors), 'edges_checked': 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--node-modules', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    subprocess.run(['node', str(Path(__file__).with_suffix('.cjs')), str(output / 'sources.json'),
                    str(args.node_modules.resolve()), str(output / 'yarn-reference.json')], check=True)
    references = json.loads((output / 'yarn-reference.json').read_text())
    results = []
    for case in json.loads((output / 'sources.json').read_text()):
        report = json.loads((output / 'audits' / (case['id'] + '.json')).read_text())
        assert 'error' not in report, (case['repository'], report)
        if report['format'].startswith('npm_'):
            facts = npm(case, report)
        elif report['format'].startswith('pnpm_'):
            facts = pnpm(case, report)
        else:
            facts = yarn(case, report, references[case['id']])
        results.append({'id': case['id'], 'repository': case['repository'], 'format': report['format'], **facts})
    save(output / 'independent-inventories.json', {'cases': results,
         'reference_versions': {'PyYAML': yaml.__version__, **{name: json.loads((args.node_modules / name / 'package.json').read_text())['version'] for name in ['@yarnpkg/lockfile', '@yarnpkg/parsers']}},
         'limits': 'npm/pnpm full graph edge comparison; Yarn official-reader descriptor/artifact comparison, not an independent edge resolver; no host installation or execution qualification'})
    print(json.dumps({'cases_passed': len(results), 'records_checked': sum(r['records_checked'] for r in results),
                      'edges_checked': sum(r['edges_checked'] for r in results),
                      'descriptors_checked': sum(r.get('descriptors_checked', 0) for r in results)}))


if __name__ == '__main__':
    main()
