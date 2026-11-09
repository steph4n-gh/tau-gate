#!/usr/bin/env python3
"""Rerun the fixed math/basic comparison on every expanded-parser lock inventory."""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import statistics
import subprocess
import urllib.parse

import numpy as np
import scipy

import math_corpus as graphs
import math_update_study as history
import parser_corpus as context


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read(path):
    return json.loads(path.read_text())


def split_for(repo):
    return 'development' if int(sha(repo.lower().encode())[:8], 16) % 4 == 0 else 'holdout'


def structural_outcome(spectral, basic):
    if spectral is None or basic is None:
        return 'unavailable'
    if abs(spectral - basic) <= 1e-10 * max(1, abs(spectral), abs(basic)):
        return 'equal'
    return 'math_better' if spectral < basic else 'basic_better'


def cut_summary(cases):
    groups = {
        'all_152': cases,
        'complete_connected': [c for c in cases if c['topology_complete'] and c['components'] == 1 and c['nodes'] > 1],
        'complete_connected_holdout': [c for c in cases if c['topology_complete'] and c['components'] == 1 and c['nodes'] > 1 and c['split'] == 'holdout'],
        'new_or_changed_complete_connected': [c for c in cases if c['topology_complete'] and c['components'] == 1 and c['nodes'] > 1 and c['graph_changed_since_first_study']],
    }
    result = {}
    for group, selected in groups.items():
        result[group] = {'cases': len(selected)}
        for objective in ['ratio_cut', 'conductance']:
            result[group][objective] = dict(Counter(structural_outcome(
                c['spectral_metrics'][objective] if c['spectral_metrics'] else None,
                c['basic'][objective]['metrics'][objective] if c['basic'][objective] else None) for c in selected))
    return result


def snapshots(parser_run, previous, output, repeats):
    output.mkdir(parents=True, exist_ok=True)
    replay_bytes = (parser_run / 'replay.json').read_bytes()
    replay = json.loads(replay_bytes)
    original_receipt = read(parser_run / 'candidate' / 'receipt.json')
    library = parser_run / 'candidate' / 'libtau_gate.dylib'
    binary = parser_run / 'candidate' / 'tau-gate'
    assert sha(binary.read_bytes()) == replay['binary_sha256'] == original_receipt['candidate']['tau-gate']
    assert sha(library.read_bytes()) == original_receipt['candidate']['libtau_gate.dylib']
    assert len(replay['cases']) == 152
    for path in [binary, library]:
        destination = output / 'candidate' / path.name
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            assert sha(destination.read_bytes()) == sha(path.read_bytes())
        else:
            shutil.copy2(path, destination)
    settings = {'parser_run': str(parser_run), 'previous_study': str(previous),
                'parser_replay_sha256': sha(replay_bytes), 'source_commit': original_receipt['source_commit'],
                'binary_sha256': sha(binary.read_bytes()), 'library_sha256': sha(library.read_bytes()),
                'numpy': np.__version__, 'scipy': scipy.__version__, 'repeats': repeats,
                'split_rule': 'sha256(lowercase canonical repository) first32bits modulo4; zero=development',
                'connectivity_alert_threshold': 'abs(delta)>1e-8+1e-6*max(abs(base),abs(head))'}
    if (output / 'settings.json').exists():
        assert read(output / 'settings.json') == settings
    else:
        graphs.save(output / 'settings.json', settings)
    solver = graphs.Native(output / 'candidate' / library.name)
    old_ids = {c['id'] for c in read(previous / 'graphs.json')['cases']}
    results = []
    for item in replay['cases']:
        report_path = parser_run / item['report']
        report = read(report_path)
        assert report.get('parsing_status') == 'complete' and not item['error']
        graph = history.graph_from_report(report)
        assert len(set(graph['nodes'])) == len(graph['nodes']) == item['packages']
        assert len(graph['edges']) == item['edges']
        graph.update({k: item[k] for k in ['id', 'repository', 'commit', 'lockfile']})
        graph.update(roots=report['introducer_roots'], typed_edges=report['edges'])
        graph_path = output / 'graphs' / (item['id'] + '.json')
        if graph_path.exists():
            assert read(graph_path) == graph
        else:
            graphs.save(graph_path, graph)
        reference_path = output / 'references' / (item['id'] + '.json')
        if reference_path.exists():
            reference = read(reference_path)
        else:
            reference = graphs.reference(graph)
            graphs.save(reference_path, reference)
        runs = [solver.run(graph) for _ in range(repeats)]
        assert all('error' not in r and r['converged'] and r['residual'] < 1e-9 for r in runs), item
        deterministic = len({json.dumps({k: v for k, v in r.items() if k != 'seconds'}, sort_keys=True) for r in runs}) == 1
        assert deterministic, item
        score_error = abs(runs[0]['score'] - reference['score'])
        assert score_error <= max(1e-9, abs(reference['score']) * 1e-6), (item['repository'], score_error)
        adjacency = [[] for _ in graph['nodes']]
        for u, v in graph['edges']:
            if u != v:
                adjacency[u].append(v)
                adjacency[v].append(u)
        basic, counts = graphs.simple_partitions(graph, adjacency)
        positions = {label: i for i, label in enumerate(graph['nodes'])}
        metrics = graphs.partition_metrics({positions[label] for label in runs[0]['partition']}, adjacency)
        changed = item['id'] not in old_ids
        if not changed:
            old_graph = read(previous / 'graphs' / (item['id'] + '.json'))
            changed = old_graph['nodes'] != graph['nodes'] or sorted(old_graph['edges']) != sorted(graph['edges']) or old_graph['roots'] != graph['roots']
        row = {**{k: item[k] for k in ['id', 'repository', 'commit', 'lockfile', 'format']},
               'split': split_for(item['repository']), 'nodes': len(graph['nodes']), 'edges': len(graph['edges']),
               'topology_complete': item['topology_status'] == 'complete', 'input_issues': report['issues'],
               'graph_changed_since_first_study': changed, 'components': reference['components'],
               'graph_sha256': sha(graph_path.read_bytes()), 'parser_report_sha256': sha(report_path.read_bytes()),
               'reference': {k: v for k, v in reference.items() if k != 'vector'},
               'eigenvalue_absolute_error': score_error, 'native_runs': runs, 'deterministic': deterministic,
               'native_median_seconds': statistics.median(r['seconds'] for r in runs),
               'native_range_seconds': [min(r['seconds'] for r in runs), max(r['seconds'] for r in runs)],
               'spectral_metrics': metrics, 'basic': basic, 'basic_candidate_counts': counts}
        results.append(row)
        graphs.save(output / 'snapshots' / (item['id'] + '.json'), row)
        print(json.dumps({'measured': len(results), 'repository': item['repository'], 'components': reference['components']}), flush=True)
    summary = {'cases': len(results), 'complete_topology': sum(c['topology_complete'] for c in results),
               'disconnected_or_singleton': sum(c['components'] > 1 or c['nodes'] == 1 for c in results),
               'converged_and_reference_matched': len(results), 'deterministic': all(c['deterministic'] for c in results),
               'max_eigenvalue_absolute_error': max(c['eigenvalue_absolute_error'] for c in results),
               'structural': cut_summary(results)}
    graphs.save(output / 'snapshots.json', {'summary': summary, 'cases': results})
    print(json.dumps(summary), flush=True)


def capture_update(case, output, previous, binary):
    folder = output / 'updates' / case['id']
    receipt_path = folder / 'receipt.json'
    if receipt_path.exists():
        return read(receipt_path)
    folder.mkdir(parents=True, exist_ok=True)
    result = {k: case[k] for k in ['id', 'repository', 'lockfile', 'split']}
    try:
        old_folder = previous / 'updates' / case['id']
        old_receipt = read(old_folder / 'receipt.json') if (old_folder / 'receipt.json').exists() else None
        discovery_path = old_folder / 'commit-discovery.json'
        if discovery_path.exists():
            discovery = read(discovery_path)
        else:
            query = urllib.parse.urlencode({'sha': case['commit'], 'path': case['lockfile'], 'per_page': 1})
            discovery = history.gh(f"repos/{case['repository']}/commits?{query}")
        graphs.save(folder / 'commit-discovery.json', discovery)
        if not discovery or not discovery[0]['parents']:
            raise ValueError('no parent snapshot for the latest lock-changing commit')
        change = discovery[0]
        result.update(head=change['sha'], base=change['parents'][0]['sha'], commit_url=change['html_url'],
                      frozen_cohort_head=case['commit'], message=change['commit']['message'], files=[])
        for side in ['base', 'head']:
            files = []
            missing = False
            for git_path in [case['lockfile'], str(PurePosixPath(case['lockfile']).parent / 'package.json')]:
                old = next((f for f in (old_receipt or {}).get('files', []) if f['side'] == side and f['path'] == git_path), None)
                if old and old.get('sha256'):
                    data = (old_folder / side / PurePosixPath(git_path).name).read_bytes()
                    assert sha(data) == old['sha256']
                elif old and old.get('status') == 'missing':
                    data = None
                else:
                    data = history.fetch(case['repository'], result[side], git_path)
                if data is None:
                    result['files'].append({'side': side, 'path': git_path, 'status': 'missing'})
                    missing |= git_path == case['lockfile']
                    continue
                source = folder / side / 'source' / git_path
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_bytes(data)
                # Existing independent archive/root-label helper consumes flat lock/manifest files.
                shutil.copyfile(source, folder / side / PurePosixPath(git_path).name)
                file = {'path': git_path, 'sha256': sha(data), 'bytes': len(data),
                        'url': f"https://raw.githubusercontent.com/{case['repository']}/{result[side]}/{git_path}"}
                files.append(file)
                result['files'].append({'side': side, **file})
            if missing:
                result[side + '_report'] = {'error': 'lockfile absent', 'topology_status': 'missing'}
                continue
            snapshot = {'repository': case['repository'], 'commit': result[side], 'files': files}
            bundle = context.source_case(output, folder / (side + '-context'), case, snapshot, origin=folder / side)
            result[side + '_context'] = bundle
            command = [str(binary), 'audit', '--lock', bundle['lock'], '--project-inputs', bundle['index'], '--json']
            run = subprocess.run(command, cwd=output, capture_output=True, text=True, timeout=180)
            report = json.loads(run.stdout)
            graphs.save(folder / (side + '-report.json'), report)
            result[side + '_report'] = {'error': report.get('error'), 'topology_status': report.get('topology_status'),
                                       'root_attribution_status': report.get('root_attribution_status'), 'format': report.get('format'),
                                       'packages': len(report.get('packages', [])), 'command': command, 'exit_code': run.returncode,
                                       'report_sha256': sha((folder / (side + '-report.json')).read_bytes())}
        if all(result[s + '_report']['topology_status'] == 'complete' for s in ['base', 'head']):
            result['status'] = 'complete_graph_pair' if result['base_report']['format'] == result['head_report']['format'] else 'cross_format_graph_pair'
        else:
            result['status'] = 'incomplete_graph_pair'
    except Exception as error:
        result.update(status='acquisition_or_input_failure', error=str(error))
    graphs.save(receipt_path, result)
    return result


def collect(output):
    settings = read(output / 'settings.json')
    previous = Path(settings['previous_study'])
    binary = output / 'candidate' / 'tau-gate'
    assert sha(binary.read_bytes()) == settings['binary_sha256']
    subprocess.run([str(binary), '--verify'], check=True, capture_output=True)
    cases = read(output / 'snapshots.json')['cases']
    results = []
    with ThreadPoolExecutor(max_workers=6) as pool:
        jobs = [pool.submit(capture_update, c, output, previous, binary) for c in cases]
        for job in as_completed(jobs):
            result = job.result()
            results.append(result)
            print(json.dumps({'collected': len(results), 'repository': result['repository'], 'status': result['status']}), flush=True)
    graphs.save(output / 'updates.json', {'scope': 'latest lock-changing commit at/before each frozen head vs first parent; all152 attempted',
                                        'pairs': sorted(results, key=lambda r: (r['repository'], r['lockfile']))})


def signal_counts(records, truth, signal):
    counts = Counter()
    for record in records:
        prediction = record[signal]
        if prediction is None:
            counts['unavailable'] += 1
        elif prediction and truth(record):
            counts['known_event_flagged'] += 1
        elif not prediction and truth(record):
            counts['known_event_missed'] += 1
        elif prediction:
            counts['alert_outside_scoped_target'] += 1
        else:
            counts['no_alert_no_scoped_event'] += 1
    return dict(counts)


def analyze_updates(output):
    settings = read(output / 'settings.json')
    previous = Path(settings['previous_study'])
    # Reuse the original, independently verified artifact-label and Rust cross-check procedure.
    library = output / 'candidate' / 'libtau_gate.dylib'
    assert sha(library.read_bytes()) == settings['library_sha256']
    history.analyze(output, library, corpus=Path(read(previous / 'graphs.json')['corpus']))
    values = read(output / 'update-value.json')
    for result in values['pairs']:
        folder = output / 'updates' / result['id']
        partitions = {}
        reference_scores = {}
        for side in ['base', 'head']:
            report = read(folder / (side + '-report.json'))
            graph = history.graph_from_report(report)
            graph['repository'] = result['repository']
            reference_path = folder / (side + '-reference.json')
            oracle = read(reference_path) if reference_path.exists() else graphs.reference(graph)
            if not reference_path.exists():
                graphs.save(reference_path, oracle)
            native = result['math'][side]
            if native.get('converged'):
                error = abs(native['score'] - oracle['score'])
                assert error <= max(1e-9, abs(oracle['score']) * 1e-6), (result['repository'], side, error)
            reference_scores[side] = oracle['score']
            selected = set(native['partition'])
            universe = set(graph['nodes'])
            assert selected <= universe
            partitions[side] = min(tuple(sorted(selected)), tuple(sorted(universe - selected)))
        reference_alert = abs(reference_scores['head'] - reference_scores['base']) > 1e-8 + 1e-6 * max(abs(reference_scores['head']), abs(reference_scores['base']))
        if result['math_change_signal'] is not None:
            assert reference_alert == result['math_change_signal'], result['repository']
        result['historical_reference_alert_agreement'] = result['math_change_signal'] is not None and reference_alert == result['math_change_signal']
        result['partition_membership_changed'] = partitions['base'] != partitions['head']
        result['math_scalar_or_partition_signal'] = bool(result['math_change_signal'] or result['partition_membership_changed'])
        manifests = {side: read(folder / side / 'package.json') for side in ['base', 'head']
                     if (folder / side / 'package.json').exists()}
        if len(manifests) != 2:
            result['root_label_available'] = False
            continue
        events = ['preinstall', 'install', 'postinstall', 'prepublish', 'preprepare', 'prepare', 'postprepare']
        changes = {event: {side: manifests[side].get('scripts', {}).get(event) for side in ['base', 'head']}
                   for event in events if manifests['base'].get('scripts', {}).get(event) != manifests['head'].get('scripts', {}).get(event)}
        result.update(root_label_available=True, root_lifecycle_changes=changes,
                      root_lifecycle_event=bool(changes), basic_root_signal=bool(changes))
    summaries = {}
    for group in ['all', 'holdout']:
        selected = [r for r in values['pairs'] if group == 'all' or r['split'] == group]
        labelled = [r for r in selected if r['labels']['available']]
        root_labelled = [r for r in selected if r.get('root_label_available')]
        summaries[group] = {
            'complete_compatible_pairs': len(selected),
            'math_signal_unavailable': sum(r['math_change_signal'] is None for r in selected),
            'independently_labelled_npm_v3_pairs': len(labelled),
            'known_npm_review_events': sum(r['labels']['positive'] for r in labelled),
            'basic_review_signal': signal_counts(labelled, lambda r: r['labels']['positive'], 'basic_review_signal'),
            'math_signal_on_npm_target': signal_counts(labelled, lambda r: r['labels']['positive'], 'math_change_signal'),
            'exploratory_partition_signal_on_npm_target': signal_counts(labelled, lambda r: r['labels']['positive'], 'partition_membership_changed'),
            'exploratory_scalar_or_partition_on_npm_target': signal_counts(labelled, lambda r: r['labels']['positive'], 'math_scalar_or_partition_signal'),
            'historical_reference_alert_agreement': sum(r['historical_reference_alert_agreement'] for r in selected),
            'root_labelled_pairs_all_formats': len(root_labelled),
            'root_lifecycle_events': sum(r['root_lifecycle_event'] for r in root_labelled),
            'basic_root_signal': signal_counts(root_labelled, lambda r: r['root_lifecycle_event'], 'basic_root_signal'),
            'math_signal_on_root_target': signal_counts(root_labelled, lambda r: r['root_lifecycle_event'], 'math_change_signal'),
            'exploratory_scalar_or_partition_on_root_target': signal_counts(root_labelled, lambda r: r['root_lifecycle_event'], 'math_scalar_or_partition_signal'),
            'basic_exact_change_alerts': sum(r['basic_change_signal'] for r in selected),
            'math_change_alerts': sum(r['math_change_signal'] is True for r in selected),
        }
    values['full_comparison_summary'] = summaries
    graphs.save(output / 'update-value.json', values)
    print(json.dumps(summaries), flush=True)


def report(output):
    settings = read(output / 'settings.json')
    snapshots = read(output / 'snapshots.json')
    updates = read(output / 'updates.json')
    values = read(output / 'update-value.json')
    pair_by_id = {p['id']: p for p in updates['pairs']}
    assert sha((output / 'candidate' / 'tau-gate').read_bytes()) == settings['binary_sha256']
    assert sha((output / 'candidate' / 'libtau_gate.dylib').read_bytes()) == settings['library_sha256']
    assert sha((Path(settings['parser_run']) / 'replay.json').read_bytes()) == settings['parser_replay_sha256']
    context_files = 0
    for pair in updates['pairs']:
        folder = output / 'updates' / pair['id']
        for file in pair.get('files', []):
            if file.get('sha256'):
                assert sha((folder / file['side'] / 'source' / file['path']).read_bytes()) == file['sha256']
        for side in ['base', 'head']:
            bundle = pair.get(side + '_context')
            if not bundle:
                continue
            audit = read(folder / (side + '-report.json'))
            assert sha((folder / (side + '-report.json')).read_bytes()) == pair[side + '_report']['report_sha256']
            assert sha(Path(bundle['lock']).read_bytes()) == bundle['lock_sha256']
            if not audit.get('error'):
                assert audit.get('lock_sha256') == bundle['lock_sha256']
            for file in bundle['files']:
                assert sha((Path(bundle['index']).parent / file['file']).read_bytes()) == file['sha256']
                context_files += 1
            if 'project_input_hashes' in audit:
                assert audit['project_input_hashes'] == {f['path']: f['sha256'] for f in bundle['files']}
    assert len(snapshots['cases']) == len(updates['pairs']) == 152
    assert {c['id'] for c in snapshots['cases']} == set(pair_by_id)
    assert all(sha((output / 'graphs' / (c['id'] + '.json')).read_bytes()) == c['graph_sha256'] for c in snapshots['cases'])
    outcomes = dict(Counter(c['status'] for c in updates['pairs']))
    result = {'settings': settings, 'snapshots': snapshots['summary'], 'historical_outcomes': outcomes, 'historical_context_files_rehashed': context_files,
              'historical_value': values['full_comparison_summary'],
              'scope': 'descriptive structural cut quality and observed review facts; no harmfulness, runtime or human-review labels',
              'secondary_partition_metric': 'post-hoc diagnostic added after inspection; no primary solver or threshold tuning',
              'unique_math_alerts_beyond_basic_exact_diff': sum(bool(r['math_scalar_or_partition_signal']) and not r['basic_change_signal'] for r in values['pairs'])}
    graphs.save(output / 'results.json', result)
    summary = snapshots['summary']
    lines = ['# Math versus basic dependency graphs: all 152 locks', '',
             'The measured math adds occasional structural grouping. This experiment does not establish better dependency-risk decisions or human review outcomes.', '',
             f"All {summary['cases']} frozen inventories were measured; {summary['complete_topology']} are topology complete. The main comparison uses {summary['structural']['complete_connected']['cases']} complete connected graphs. {summary['disconnected_or_singleton']} disconnected/singleton inputs and {summary['cases']-summary['complete_topology']} incomplete inputs remain in the table (these categories overlap).", '',
             '| Main structural objective | Math better | Equal | Basic better |', '| --- | ---: | ---: | ---: |']
    primary = snapshots['summary']['structural']['complete_connected']
    for objective in ['ratio_cut', 'conductance']:
        counts = primary[objective]
        lines.append(f"| {objective} | {counts.get('math_better',0)} | {counts.get('equal',0)} | {counts.get('basic_better',0)} |")
    all_values = values['full_comparison_summary']['all']
    known = all_values['known_npm_review_events']
    root_events = all_values['root_lifecycle_events']
    lines += ['', f"Historical scope:152 attempted;{all_values['complete_compatible_pairs']} complete compatible pairs. {outcomes}", '',
              '| Observed review fact | Exact metadata checks | Scalar connectivity alert | Exploratory scalar or partition alert |', '| --- | ---: | ---: | ---: |',
              f"| Changed verified executable artifacts ({known} known cases in {all_values['independently_labelled_npm_v3_pairs']} npm-v3 pairs) | {all_values['basic_review_signal'].get('known_event_flagged',0)}/{known} | {all_values['math_signal_on_npm_target'].get('known_event_flagged',0)}/{known} | {all_values['exploratory_scalar_or_partition_on_npm_target'].get('known_event_flagged',0)}/{known} |",
              f"| Root lifecycle command changed ({root_events} known cases in {all_values['root_labelled_pairs_all_formats']} pairs) | {all_values['basic_root_signal'].get('known_event_flagged',0)}/{root_events} | {all_values['math_signal_on_root_target'].get('known_event_flagged',0)}/{root_events} | {all_values['exploratory_scalar_or_partition_on_root_target'].get('known_event_flagged',0)}/{root_events} |", '',
              'Artifact labels are limited to changed marker-positive npm-v3 instances, verified against original archives. Other formats and marker-negative artifacts do not become negative safety labels. No human-review or runtime impact test occurred. The partition alert is post-hoc and cannot be presented as a preregistered accuracy result.', '',
              '## All152 lockfiles', '',
              '| Repository | Lock | Nodes | Components | Topology | Ratio cut outcome | Conductance outcome | Historical pair |',
              '| --- | --- | ---: | ---: | --- | --- | --- | --- |']
    for c in snapshots['cases']:
        comparisons = []
        for objective in ['ratio_cut','conductance']:
            a = c['spectral_metrics'][objective] if c['spectral_metrics'] else None
            b = c['basic'][objective]['metrics'][objective] if c['basic'][objective] else None
            comparisons.append(structural_outcome(a,b))
        lines.append(f"| {c['repository']} | {c['lockfile']} | {c['nodes']} | {c['components']} | {'complete' if c['topology_complete'] else 'incomplete'} | {comparisons[0]} | {comparisons[1]} | {pair_by_id[c['id']]['status']} |")
    (output / 'REPORT.md').write_text('\n'.join(lines) + '\n')
    print(json.dumps(result), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['snapshots', 'collect', 'analyze-updates', 'report'])
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--parser-run', type=Path)
    parser.add_argument('--previous-study', type=Path)
    parser.add_argument('--repeats', type=int, default=5)
    args = parser.parse_args()
    if args.mode == 'snapshots':
        if not args.parser_run or not args.previous_study or args.repeats < 5:
            parser.error('snapshots requires parser-run, previous-study and at least5 repeats')
        snapshots(args.parser_run.resolve(), args.previous_study.resolve(), args.output.resolve(), args.repeats)
    elif args.mode == 'collect':
        collect(args.output.resolve())
    elif args.mode == 'analyze-updates':
        analyze_updates(args.output.resolve())
    else:
        report(args.output.resolve())


if __name__ == '__main__':
    main()
