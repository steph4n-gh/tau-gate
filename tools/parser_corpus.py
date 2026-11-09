#!/usr/bin/env python3
"""Acquire explicit source context and replay the frozen parser corpus. Never installs projects."""
import argparse
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import fnmatch
import hashlib
import json
from pathlib import Path, PurePosixPath
import posixpath
import re
import subprocess
import time

import yaml
import npm_repo_experiment as acquisition


def sha(data):
    return hashlib.sha256(data).hexdigest()


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def case_id(repo, lock):
    return sha((repo + '\0' + lock).encode())[:16]


def matches(path, pattern):
    """Workspace glob matching; a single star does not cross a directory."""
    bits, pats = path.split('/'), pattern.rstrip('/').split('/')
    def walk(i, j):
        if j == len(pats):
            return i == len(bits)
        if pats[j] == '**':
            return walk(i, j + 1) or (i < len(bits) and walk(i + 1, j))
        return i < len(bits) and fnmatch.fnmatchcase(bits[i], pats[j]) and walk(i + 1, j + 1)
    return walk(0, 0)


def relative_target(base, target):
    path = posixpath.normpath(posixpath.join(base, target))
    if path.startswith('/') or path == '..' or path.startswith('../') or '\\' in path:
        return None
    return path


def documents(text):
    return list(yaml.safe_load_all(text))


def source_case(corpus, output, audit, snapshot):
    repo, lock = audit['repository'], audit['lockfile']
    cid = case_id(repo, lock)
    folder = output / 'sources' / cid
    done = folder / 'receipt.json'
    if done.exists():
        return json.loads(done.read_text())
    origin = corpus / 'repositories' / repo.replace('/', '__')
    base = str(PurePosixPath(lock).parent)
    base = '' if base == '.' else base
    records, errors, inputs = [], [], {}
    listed = {f['path']: f for f in snapshot.get('files', [])}
    lock_bytes = (origin / 'source' / lock).read_bytes()
    assert sha(lock_bytes) == listed[lock]['sha256']
    folder.mkdir(parents=True, exist_ok=True)
    (folder / PurePosixPath(lock).name).write_bytes(lock_bytes)
    def add(logical):
        gitpath = posixpath.join(base, logical)
        try:
            frozen = origin / 'source' / gitpath
            if gitpath in listed:
                data = frozen.read_bytes()
                assert sha(data) == listed[gitpath]['sha256']
                url = listed[gitpath]['url']
            else:
                data, url = acquisition.raw(repo, snapshot['commit'], gitpath, snapshot.get('host', 'github.com'))
            if len(data) > 1024 * 1024:
                raise ValueError('source exceeds 1 MiB')
            locator = 'files/' + sha(data)
            (folder / 'files').mkdir(exist_ok=True)
            (folder / locator).write_bytes(data)
            inputs[logical] = data
            records.append({'path': logical, 'git_path': gitpath, 'file': locator,
                            'sha256': sha(data), 'bytes': len(data), 'url': url})
        except Exception as error:
            errors.append({'path': logical, 'error': str(error)})
    manifest_path = posixpath.join(base, 'package.json')
    if manifest_path in listed:
        add('package.json')
    root = json.loads(inputs.get('package.json', b'{}'))
    # JSON locks need only the explicit root manifest for this experiment.
    if not lock_bytes.lstrip().startswith(b'{'):
        cache = output / 'trees' / (repo.replace('/', '__') + '.json')
        try:
            if cache.exists():
                tree = json.loads(cache.read_text())
            elif (origin / 'recursive-tree.json').exists():
                tree = json.loads((origin / 'recursive-tree.json').read_text())
                save(cache, tree)
            else:
                tree = acquisition.api(snapshot, 'git/trees/' + snapshot['commit'] + '?recursive=1')
                save(cache, tree)
            tree_complete = not tree.get('truncated', False)
            if not tree_complete:
                errors.append({'path': '<tree>', 'error': 'recursive tree truncated; explicit pnpm targets fetched directly'})
            paths = {item['path'][len(base) + 1:] if base else item['path']
                     for item in tree['tree'] if item['type'] == 'blob'
                     and (not base or item['path'].startswith(base + '/'))}
            selected = set()
            for config in ['pnpm-workspace.yaml', '.yarnrc.yml']:
                if config in paths or not tree_complete:
                    add(config)
            workspaces = root.get('workspaces', [])
            if isinstance(workspaces, dict):
                workspaces = workspaces.get('packages', [])
            for path in paths:
                if path.endswith('/package.json'):
                    directory = path[:-len('/package.json')]
                    if any(matches(directory, p) for p in workspaces if not p.startswith('!')) and not any(
                            matches(directory, p[1:]) for p in workspaces if p.startswith('!')):
                        selected.add(path)
            text = lock_bytes.decode()
            if PurePosixPath(lock).name == 'pnpm-lock.yaml':
                for doc in documents(text):
                    if not isinstance(doc, dict):
                        continue
                    for importer, info in doc.get('importers', {}).items():
                        if importer != '.':
                            selected.add(importer.rstrip('/') + '/package.json')
                        for kind in ['dependencies', 'devDependencies', 'optionalDependencies']:
                            for value in (info or {}).get(kind, {}).values():
                                ref = value.get('version', '') if isinstance(value, dict) else str(value)
                                if ref.startswith('link:'):
                                    target = relative_target(importer, ref[5:])
                                    if target:
                                        selected.add(target.rstrip('/') + '/package.json')
            else:
                if '__metadata:' in text:
                    locked = yaml.safe_load(text)
                    for value in locked.values():
                        if not isinstance(value, dict):
                            continue
                        ref = value.get('resolution', '')
                        for protocol in ['workspace:', 'link:', 'portal:']:
                            if '@' + protocol in ref:
                                target = relative_target('', ref.split('@' + protocol, 1)[1].split('::')[0])
                                if target is not None:
                                    selected.add('package.json' if target == '.' else target + '/package.json')
                else:
                    for match in re.finditer(r'@(?:link|file):([^\s"\',#]+)', text):
                        target = match[1].split('::')[0]
                        if target.endswith(('.tgz', '.tar.gz')):
                            continue
                        target = relative_target('', target)
                        if target is not None:
                            selected.add('package.json' if target == '.' else target + '/package.json')
            for path in sorted(selected - inputs.keys()):
                if path in paths or not tree_complete:
                    add(path)
                else:
                    errors.append({'path': path, 'error': 'referenced source manifest absent from frozen Git tree'})
        except Exception as error:
            errors.append({'path': '<tree>', 'error': str(error)})
    save(folder / 'project-inputs.json', {'schema_version': 1, 'files': [
        {'path': r['path'], 'file': r['file']} for r in sorted(records, key=lambda r: r['path'])]})
    result = {'id': cid, 'repository': repo, 'commit': snapshot['commit'], 'lockfile': lock,
              'lock_sha256': sha(lock_bytes), 'files': records, 'errors': errors,
              'index': str((folder / 'project-inputs.json').resolve()),
              'lock': str((folder / PurePosixPath(lock).name).resolve())}
    save(done, result)
    return result


def acquire(corpus, output):
    receipt = json.loads((corpus / 'receipt.json').read_text())
    snapshots = {r['repository']: r for r in receipt['snapshots']}
    results = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        jobs = [pool.submit(source_case, corpus, output, a, snapshots[a['repository']]) for a in receipt['audits']]
        for future in as_completed(jobs):
            result = future.result()
            results.append(result)
            print(json.dumps({k: result[k] for k in ['repository', 'lockfile']}), flush=True)
    save(output / 'sources.json', sorted(results, key=lambda r: (r['repository'], r['lockfile'])))


def replay(corpus, output, binary):
    sources = json.loads((output / 'sources.json').read_text())
    results = []
    for case in sources:
        command = [str(binary.resolve()), 'audit', '--lock', case['lock'], '--project-inputs', case['index'], '--json']
        start = time.monotonic()
        run = subprocess.run(command, cwd=corpus, capture_output=True, text=True, timeout=240)
        report = json.loads(run.stdout)
        save(output / 'audits' / (case['id'] + '.json'), report)
        assert sha(Path(case['lock']).read_bytes()) == case['lock_sha256']
        for item in case['files']:
            assert sha((Path(case['index']).parent / item['file']).read_bytes()) == item['sha256']
        results.append({**{k: case[k] for k in ['id', 'repository', 'commit', 'lockfile', 'lock_sha256']},
                        'exit_code': run.returncode, 'seconds': time.monotonic() - start,
                        'command': command, 'format': report.get('format'),
                        'error': report.get('error'), 'issues': report.get('issues', []),
                        'topology_status': report.get('topology_status'),
                        'packages': len(report.get('packages', [])), 'edges': len(report.get('edges', [])),
                        'report': 'audits/' + case['id'] + '.json'})
        print(json.dumps({k: results[-1][k] for k in ['repository', 'error', 'topology_status']}), flush=True)
    save(output / 'replay.json', {'binary_sha256': sha(binary.read_bytes()), 'cases': results})


def summarize(corpus, output):
    baseline = json.loads((corpus / 'receipt.json').read_text())
    cohort = json.loads((corpus / 'cohort.json').read_text())
    replay = json.loads((output / 'replay.json').read_text())
    cases = replay['cases']
    assert len(cases) == len(baseline['audits']) == 152
    assert {(r['repository'], r['lockfile']) for r in cases} == {(r['repository'], r['lockfile']) for r in baseline['audits']}
    sources = {r['id']: r for r in json.loads((output / 'sources.json').read_text())}
    old = {(r['repository'], r['lockfile']): r for r in baseline['audits']}
    by_repo = defaultdict(list)
    formats = defaultdict(Counter)
    math_converged = 0
    findings = []
    for row in cases:
        by_repo[row['repository']].append(row)
        previous = old[row['repository'], row['lockfile']]
        f = formats[row['format']]
        f['locks'] += 1
        f['baseline_parsed'] += not bool(previous.get('error'))
        f['baseline_complete_topology'] += previous.get('topology_status') == 'complete'
        f['parsed'] += not bool(row['error'])
        f['complete_topology'] += row['topology_status'] == 'complete'
        report = json.loads((output / row['report']).read_text())
        assert report['lock_sha256'] == previous['lock_sha256'] == sources[row['id']]['lock_sha256']
        assert report['project_input_hashes'] == {i['path']: i['sha256'] for i in sources[row['id']]['files']}
        assert report['project_inputs_index_sha256'] == sha(Path(sources[row['id']]['index']).read_bytes())
        math_converged += report.get('topology', {}).get('residual_converged') is True
        if row['topology_status'] != 'complete':
            finding = {k: row[k] for k in ['id', 'repository', 'commit', 'lockfile', 'issues']}
            if row['format'] in ['npm_v2', 'npm_v3']:
                lock = json.loads(Path(sources[row['id']]['lock']).read_text())
                root = next(f for f in sources[row['id']]['files'] if f['path'] == 'package.json')
                manifest = json.loads((Path(sources[row['id']]['index']).parent / root['file']).read_text())
                differences = {}
                for kind in ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']:
                    declared = manifest.get(kind, {})
                    locked = lock['packages'][''].get(kind, {})
                    if declared != locked:
                        differences[kind] = {n: {'manifest': declared.get(n), 'lock': locked.get(n)}
                                             for n in sorted(declared.keys() | locked.keys()) if declared.get(n) != locked.get(n)}
                finding['root_differences'] = differences
            findings.append(finding)
    checked = 0
    for snapshot in baseline['snapshots']:
        for file in snapshot.get('files', []):
            frozen = corpus / 'repositories' / snapshot['repository'].replace('/', '__') / 'source' / file['path']
            assert sha(frozen.read_bytes()) == file['sha256']
            checked += 1
    rows = []
    for item in cohort['repositories']:
        resolution = item['resolution']
        repo = resolution.get('repository', resolution['input_url'].removeprefix('https://github.com/'))
        locks = by_repo.get(repo, [])
        complete = sum(r['topology_status'] == 'complete' for r in locks)
        parsed = sum(not bool(r['error']) for r in locks)
        state = ('all_topology_complete' if complete == len(locks) else 'some_topology_complete' if complete else 'incomplete_topology') if locks else ('unavailable' if resolution['status'] != 'resolved' else 'no_project_lockfile_found')
        rows.append({'rank': item['repository_rank'], 'repository': repo, 'lockfiles': len(locks),
                     'parsed': parsed, 'complete_topology': complete, 'state': state,
                     'commit': locks[0]['commit'] if locks else None})
    assert len(rows) == 200
    summary = {'projects': len(rows), 'project_states': dict(Counter(r['state'] for r in rows)),
               'locks': len(cases), 'parsed': sum(not bool(r['error']) for r in cases),
               'complete_topology': sum(r['topology_status'] == 'complete' for r in cases),
               'baseline_parsed': sum(not bool(r.get('error')) for r in baseline['audits']),
               'baseline_complete_topology': sum(r.get('topology_status') == 'complete' for r in baseline['audits']),
               'math_residual_converged': math_converged, 'original_source_files_rehashed': checked,
               'package_records': sum(r['packages'] for r in cases), 'edges': sum(r['edges'] for r in cases),
               'project_input_files': sum(len(s['files']) for s in sources.values()),
               'formats': {k: dict(v) for k, v in formats.items()}, 'binary_sha256': replay['binary_sha256']}
    save(output / 'summary.json', summary)
    save(output / 'projects.json', rows)
    save(output / 'findings.json', findings)
    lines = ['# Frozen 200-project parser replay', '',
             f"{summary['parsed']}/{summary['locks']} lockfiles parsed; {summary['complete_topology']} topology complete; {math_converged} residual-converged math reports.", '',
             f"Topology completeness does not qualify execution or establish safety. {len(findings)} input disagreements or unresolved-reference cases remain visible.", '',
             '| Format | Locks | Parsed before | Parsed now | Topology complete before | Topology complete now |',
             '| --- | ---: | ---: | ---: | ---: | ---: |']
    for name, f in sorted(formats.items()):
        lines.append(f"| {name} | {f['locks']} | {f['baseline_parsed']} | {f['parsed']} | {f['baseline_complete_topology']} | {f['complete_topology']} |")
    lines += ['', 'All 200 repository identities are accounted for below. No-lock and unavailable entries retain the original frozen discovery result.', '',
              '| Rank | Repository | Locks | Parsed | Complete topology | State |', '| ---: | --- | ---: | ---: | ---: | --- |']
    for row in rows:
        lines.append(f"| {row['rank']} | {row['repository']} | {row['lockfiles']} | {row['parsed']} | {row['complete_topology']} | {row['state']} |")
    (output / 'REPORT.md').write_text('\n'.join(lines) + '\n')
    print(json.dumps(summary))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['acquire', 'replay', 'summarize'])
    parser.add_argument('--corpus', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--binary', type=Path)
    args = parser.parse_args()
    if args.mode == 'acquire':
        acquire(args.corpus.resolve(), args.output.resolve())
    elif args.mode == 'replay':
        if not args.binary:
            parser.error('replay requires --binary')
        replay(args.corpus.resolve(), args.output.resolve(), args.binary.resolve())
    else:
        summarize(args.corpus.resolve(), args.output.resolve())


if __name__ == '__main__':
    main()
