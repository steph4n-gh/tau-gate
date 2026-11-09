#!/usr/bin/env python3
"""Development-only diagnosis of spectral rounding, then frozen-candidate replay."""
import argparse
from collections import Counter
import json
from pathlib import Path
import subprocess
import statistics

import numpy as np

import math_corpus as core
from math_full_comparison import structural_outcome, canonical_partition
import math_update_study as history


def read(path):
    return json.loads(path.read_text())


def adjacency(graph):
    result = [[] for _ in graph['nodes']]
    for u, v in graph['edges']:
        if u != v:
            result[u].append(v)
            result[v].append(u)
    return result


def thresholds(vector, adj):
    order = sorted(range(len(vector)), key=lambda i: (vector[i], i))
    selected = set()
    cut = volume = 0
    total = sum(map(len, adj))
    results = []
    for index, u in enumerate(order[:-1]):
        cut += len(adj[u]) - 2 * sum(v in selected for v in adj[u])
        volume += len(adj[u])
        selected.add(u)
        if vector[u] == vector[order[index + 1]]:
            continue
        size = index + 1
        denominator = min(volume, total - volume)
        results.append({'index': index, 'size': size, 'cut_edges': cut,
                        'ratio_cut': cut * (1 / size + 1 / (len(vector) - size)),
                        'volume_denominator': denominator,
                        'conductance': cut / denominator if denominator else None})
    return order, results


def vector_probe(output):
    baseline = output / 'baseline'
    probe = output / 'vector-probe.rs'
    text = '''#![allow(dead_code)]
#[path = "BASE/error.rs"] mod error;
#[path = "BASE/graph_impl.rs"] mod graph_impl;
mod math {
    include!("BASE/math.rs");
    pub fn vector(n: usize, edges: &[(usize, usize)]) -> (Vec<f64>, f64, f64, usize) {
        let mut adj = vec![Vec::new(); n];
        for &(u,v) in edges { if u != v {adj[u].push(v); adj[v].push(u);} }
        let degrees: Vec<_> = adj.iter().map(|r| r.len() as f64).collect();
        let limit = 5000.min((20_000_000usize / (n + edges.len()).max(1)).max(1));
        let value = solve(&adj, &degrees, limit);
        (value.vector, value.value, value.residual, value.iterations)
    }
}
fn main() {
    use std::io::Read;
    let mut input = String::new(); std::io::stdin().read_to_string(&mut input).unwrap();
    let mut values = input.split_whitespace().map(|s| s.parse::<usize>().unwrap());
    let n = values.next().unwrap(); let m = values.next().unwrap();
    let edges: Vec<_> = (0..m).map(|_| (values.next().unwrap(), values.next().unwrap())).collect();
    assert!(values.next().is_none());
    let (v, score, residual, iterations) = math::vector(n, &edges);
    println!("{{\\\"vector\\\":[{}],\\\"score\\\":{},\\\"residual\\\":{},\\\"iterations\\\":{}}}", v.iter().map(ToString::to_string).collect::<Vec<_>>().join(","), score, residual, iterations);
}
'''.replace('BASE', str(baseline))
    probe.write_text(text)
    binary = output / 'vector-probe'
    subprocess.run(['rustc', '--edition=2021', '-O', str(probe), '-o', str(binary)], check=True)
    return binary


def native_vector(probe, graph):
    data = f"{len(graph['nodes'])} {len(graph['edges'])}\n" + '\n'.join(f'{u} {v}' for u, v in graph['edges'])
    result = subprocess.run([str(probe)], input=data, capture_output=True, text=True, check=True)
    return json.loads(result.stdout)


def max_gap(vector):
    order = sorted(range(len(vector)), key=lambda i: (vector[i], i))
    index = max(range(len(order) - 1), key=lambda k: vector[order[k + 1]] - vector[order[k]])
    side = set(order[:index + 1])
    return side if len(side) <= len(order) - len(side) else set(order) - side


def diagnose(study, output):
    output.mkdir(parents=True, exist_ok=True)
    probe = vector_probe(output)
    cases = [c for c in read(study / 'snapshots.json')['cases'] if c['split'] == 'development'
             and c['topology_complete'] and c['components'] == 1 and c['nodes'] > 1]
    assert len(cases) == 36
    results = []
    for case in cases:
        graph = read(study / 'graphs' / (case['id'] + '.json'))
        native = native_vector(probe, graph)
        vector = np.array(native['vector'])
        matrix, _, _ = core.laplacian(graph)
        measured_residual = float(np.linalg.norm(matrix @ vector - native['score'] * vector))
        assert measured_residual < 1e-9
        assert abs(native['score'] - case['native_runs'][0]['score']) < 1e-12
        observed = {graph['nodes'].index(label) for label in case['native_runs'][0]['partition']}
        reproduced = max_gap(vector)
        assert reproduced == observed or set(graph['nodes'][i] for i in set(range(len(vector))) - reproduced) == set(case['native_runs'][0]['partition']), case['repository']
        adj = adjacency(graph)
        order, cuts = thresholds(vector, adj)
        selected = {}
        for objective in ['ratio_cut', 'conductance']:
            best = min((c for c in cuts if c[objective] is not None),
                       key=lambda c: (c[objective], c['ratio_cut'] if objective == 'conductance' else c['conductance'], c['index']))
            side = set(order[:best['index'] + 1])
            selected[objective] = {'metrics': core.partition_metrics(side, adj),
                                   'partition': sorted(graph['nodes'][i] for i in side),
                                   'index': best['index']}
            check = core.partition_metrics(side, adj)
            assert abs(check[objective] - best[objective]) < 1e-12
        row = {'id': case['id'], 'repository': case['repository'], 'nodes': case['nodes'],
               'native_vector': native, 'independent_native_vector_residual': measured_residual,
               'shipped': case['spectral_metrics'], 'basic': case['basic'], 'sweeps': selected,
               'threshold_candidates': len(cuts)}
        results.append(row)
        print(json.dumps({'diagnosed': len(results), 'repository': case['repository']}), flush=True)
    summary = {}
    for method in ['shipped', 'ratio_cut', 'conductance']:
        summary[method] = {}
        for objective in ['ratio_cut', 'conductance']:
            compared = Counter()
            regressions = 0
            rescued = remaining = 0
            for row in results:
                metrics = row['shipped'] if method == 'shipped' else row['sweeps'][method]['metrics']
                basic = row['basic'][objective]['metrics'][objective]
                result = structural_outcome(metrics[objective], basic)
                compared[result] += 1
                regressions += structural_outcome(metrics[objective], row['shipped'][objective]) == 'basic_better'
                old_loss = structural_outcome(row['shipped'][objective], basic) == 'basic_better'
                rescued += old_loss and result != 'basic_better'
                remaining += old_loss and result == 'basic_better'
            summary[method][objective] = {'versus_basic': dict(compared),
                                          'worse_than_shipped': regressions,
                                          'old_losses_rescued': rescued, 'old_losses_remaining': remaining}
    core.save(output / 'development-diagnosis.json', {'scope': '36 development graphs only; exact frozen native vectors',
                                                     'summary': summary, 'cases': results})
    print(json.dumps(summary), flush=True)


def evaluate(study, output, library, split, repeats, objective):
    if split == 'all':
        frozen = read(output / 'frozen-method.json')
        assert core.digest(Path('src/math.rs').read_bytes()) == frozen['math_source_sha256']
        assert core.digest(library.read_bytes()) == frozen['library_sha256']
        assert frozen['objective']==objective
    baseline = core.Native(output / 'baseline' / 'libtau_gate.dylib')
    candidate = core.Native(library)
    cases = read(study / 'snapshots.json')['cases']
    if split == 'development':
        cases = [c for c in cases if c['split'] == 'development' and c['topology_complete'] and c['components'] == 1 and c['nodes'] > 1]
        assert len(cases) == 36
    probe = output / 'vector-probe'
    rows = []
    for case in cases:
        path = study / 'graphs' / (case['id'] + '.json')
        assert core.digest(path.read_bytes()) == case['graph_sha256']
        graph = read(path)
        adj = adjacency(graph)
        positions = {label: i for i,label in enumerate(graph['nodes'])}
        runs = {'before': [], 'after': []}
        for repetition in range(repeats):
            order = [('before',baseline),('after',candidate)]
            if repetition % 2: order.reverse()
            for side, solver in order:runs[side].append(solver.run(graph))
        row = {k:case[k] for k in ['id','repository','lockfile','split','topology_complete','components','nodes','edges']}
        row['runs'] = runs
        row['basic'] = case['basic']
        for side in ['before','after']:
            values = runs[side]
            assert all('error' not in r and r['converged'] and r['residual']<1e-9 for r in values), case['repository']
            assert len({json.dumps({k:v for k,v in r.items() if k!='seconds'},sort_keys=True) for r in values})==1
            result = values[0]
            assert abs(result['score']-case['reference']['score'])<=max(1e-9,abs(case['reference']['score'])*1e-6)
            metrics = core.partition_metrics({positions[p] for p in result['partition']},adj)
            row[side] = {'result':{k:v for k,v in result.items() if k!='seconds'},'metrics':metrics,
                         'median_seconds':statistics.median(r['seconds'] for r in values),
                         'range_seconds':[min(r['seconds'] for r in values),max(r['seconds'] for r in values)]}
        for field in ['score','converged','residual','iterations']:
            assert row['before']['result'][field] == row['after']['result'][field], (case['repository'],field)
        if case['components']==1 and case['nodes']>1:
            native = native_vector(probe,graph)
            vector = native['vector']
            order, cuts = thresholds(vector,adj)
            best = min(cuts,key=lambda c:(c[objective],c['conductance'] if objective=='ratio_cut' else c['ratio_cut'],c['index']))
            measured = row['after']['metrics']
            assert abs(measured['conductance']-best['conductance'])<1e-12, case['repository']
            assert abs(measured['ratio_cut']-best['ratio_cut'])<1e-10, case['repository']
            expected = {graph['nodes'][i] for i in order[:best['index']+1]}
            selected = set(row['after']['result']['partition'])
            assert selected==expected or selected==set(graph['nodes'])-expected,case['repository']
            row['native_threshold_oracle_matched']=True
            assert measured[objective]<=row['before']['metrics'][objective]+1e-12
        else:
            assert row['before']['result']==row['after']['result']
            row['native_threshold_oracle_matched']=None
        rows.append(row)
        print(json.dumps({'evaluated':len(rows),'repository':case['repository'],'scope':split}),flush=True)
    summary = {}
    groups = {'all_evaluated':rows,
              'complete_connected':[r for r in rows if r['topology_complete'] and r['components']==1 and r['nodes']>1],
              'complete_connected_holdout':[r for r in rows if r['topology_complete'] and r['components']==1 and r['nodes']>1 and r['split']=='holdout']}
    for name, selected in groups.items():
        summary[name]={'cases':len(selected)}
        for objective in ['ratio_cut','conductance']:
            record={}
            for side in ['before','after']:
                record[side]=dict(Counter(structural_outcome(r[side]['metrics'][objective] if r[side]['metrics'] else None,
                        r['basic'][objective]['metrics'][objective] if r['basic'][objective] else None) for r in selected))
            record['candidate_vs_shipped']=dict(Counter(structural_outcome(r['after']['metrics'][objective] if r['after']['metrics'] else None,
                    r['before']['metrics'][objective] if r['before']['metrics'] else None) for r in selected))
            summary[name][objective]=record
    core.save(output/(split+'-evaluation.json'),{'scope':split,'before_library_sha256':baseline.sha256,
              'after_library_sha256':candidate.sha256,'repeats':repeats,'objective':objective,'summary':summary,'cases':rows})
    print(json.dumps(summary),flush=True)


def audit_replay(study, output, binary):
    settings=read(study/'settings.json')
    parser_run=Path(settings['parser_run'])
    original_corpus=Path(read(Path(settings['previous_study'])/'graphs.json')['corpus'])
    receipt=read(parser_run/'replay.json')
    results=[]
    for case in receipt['cases']:
        command=[str(binary),*case['command'][1:]]
        run=subprocess.run(command,cwd=original_corpus,capture_output=True,text=True,timeout=180)
        before=read(parser_run/case['report'])
        after=json.loads(run.stdout)
        core.save(output/'candidate-audits'/(case['id']+'.json'),after)
        assert run.returncode==case['exit_code'],case['repository']
        for key in ['score','residual','residual_converged','iterations']:
            assert before['topology'].get(key)==after['topology'].get(key),(case['repository'],key)
        before.pop('topology');after.pop('topology')
        assert before==after,case['repository']
        results.append({'id':case['id'],'repository':case['repository'],'lockfile':case['lockfile'],
                        'exit_code':run.returncode,'non_math_report_unchanged':True,'connectivity_diagnostics_unchanged':True})
    core.save(output/'audit-replay.json',{'binary_sha256':core.digest(binary.read_bytes()),'cases':results})
    print(json.dumps({'unchanged_non_math_audits':len(results)}),flush=True)


def historical(study, output, library):
    original=read(study/'update-value.json')
    solver=core.Native(library)
    results=[]
    for pair in original['pairs']:
        folder=study/'updates'/pair['id']
        maths={};partitions={}
        for side in ['base','head']:
            report=read(folder/(side+'-report.json'))
            graph=history.graph_from_report(report)
            value=solver.run(graph)
            assert value['converged'] and value['residual']<1e-9
            for key in ['score','converged','residual','iterations']:
                assert value[key]==pair['math'][side][key],(pair['repository'],side,key)
            maths[side]=value
            partitions[side]=canonical_partition(set(graph['nodes']),set(value['partition']))
        a,b=maths['base']['score'],maths['head']['score']
        scalar=abs(a-b)>1e-8+1e-6*max(abs(a),abs(b))
        assert scalar==pair['math_change_signal']
        changed=partitions['base']!=partitions['head']
        results.append({'id':pair['id'],'repository':pair['repository'],'split':pair['split'],
                        'label_available':pair['labels']['available'],'known_artifact_event':pair['labels'].get('positive'),
                        'root_event':pair.get('root_lifecycle_event'),
                        'basic_review_signal':pair['basic_review_signal'],'basic_exact_change':pair['basic_change_signal'],
                        'before_scalar':pair['math_change_signal'],'before_combined':pair['math_scalar_or_partition_signal'],
                        'after_scalar':scalar,'after_partition_changed':changed,'after_combined':scalar or changed,
                        'math':maths})
    def counts(rows,key,truth):
        result=Counter()
        for row in rows:
            result[('known_flagged' if row[key] else 'known_missed') if row[truth] else ('outside_scoped_target' if row[key] else 'no_scoped_event_no_alert')]+=1
        return dict(result)
    summary={}
    for split in ['all','holdout']:
        selected=[r for r in results if split=='all' or r['split']==split]
        labelled=[r for r in selected if r['label_available']]
        root=[r for r in selected if r['root_event'] is not None]
        summary[split]={'complete_pairs':len(selected),'labelled_npm_pairs':len(labelled),
                       'known_artifact_events':sum(bool(r['known_artifact_event']) for r in labelled),
                       'before_scalar':counts(labelled,'before_scalar','known_artifact_event'),
                       'before_combined':counts(labelled,'before_combined','known_artifact_event'),
                       'after_scalar':counts(labelled,'after_scalar','known_artifact_event'),
                       'after_combined':counts(labelled,'after_combined','known_artifact_event'),
                       'root_events':sum(bool(r['root_event']) for r in root),
                       'after_combined_root':counts(root,'after_combined','root_event'),
                       'scalar_alerts':sum(r['after_scalar'] for r in selected),
                       'combined_alerts':sum(r['after_combined'] for r in selected),
                       'extra_alerts_beyond_exact_changes':sum(r['after_combined'] and not r['basic_exact_change'] for r in selected)}
    core.save(output/'historical-value.json',{'library_sha256':solver.sha256,'summary':summary,'cases':results})
    print(json.dumps(summary),flush=True)


def report(output):
    evaluation=read(output/'all-evaluation.json')
    frozen=read(output/'frozen-method.json')
    assert evaluation['after_library_sha256']==frozen['library_sha256']
    assert len(evaluation['cases'])==152
    primary=[c for c in evaluation['cases'] if c['topology_complete'] and c['components']==1 and c['nodes']>1]
    tradeoffs=[];remaining=[]
    for case in primary:
        before=case['before']['metrics'];after=case['after']['metrics']
        if structural_outcome(after['conductance'],before['conductance'])=='basic_better':
            tradeoffs.append({'id':case['id'],'repository':case['repository'],'old_conductance':before['conductance'],
                             'new_conductance':after['conductance'],'old_ratio_cut':before['ratio_cut'],'new_ratio_cut':after['ratio_cut']})
        if structural_outcome(after['ratio_cut'],case['basic']['ratio_cut']['metrics']['ratio_cut'])=='basic_better':
            remaining.append(case['repository'])
    audit=read(output/'audit-replay.json');historical=read(output/'historical-value.json')
    assert len(audit['cases'])==152
    assert all(c['non_math_report_unchanged'] and c['connectivity_diagnostics_unchanged'] for c in audit['cases'])
    result={'method':frozen,'summary':evaluation['summary'],'conductance_tradeoffs':tradeoffs,
            'remaining_ratio_losses':remaining,'unchanged_non_math_audits':len(audit['cases']),
            'historical_summary':historical['summary'],
            'limits':['Fixed repo split on an already studied cohort; method chosen using development cases before new holdout outcomes',
                      'Ratio-cut grouping improvement does not establish better security or human review outcomes',
                      'The scalar ignores package contents and stays zero for disconnected graphs',
                      'Conductance may worsen because the chosen primary objective is ratio cut']}
    core.save(output/'results.json',result)
    lines=['# Spectral cut improvement: all152 inventories','',
           'The selected rule sweeps every distinct-coordinate threshold for minimum ratio cut, with conductance as a tiebreaker. Eigenvalue solver and execution evidence are unchanged.','',
           '| Primary objective | Before: math/equal/basic wins | After: math/equal/basic wins |', '| --- | --- | --- |']
    for objective in ['ratio_cut','conductance']:
        data=evaluation['summary']['complete_connected'][objective]
        def counts(side):return '/'.join(str(data[side].get(k,0)) for k in ['math_better','equal','basic_better'])
        lines.append(f"| {objective} | {counts('before')} | {counts('after')} |")
    lines+=['','Primary scope:118completeconnected graphs. All152 appear below, including32disconnected/singletons and4incomplete inventories (categories overlap).', '',
            '| Repository | Lock | Split | Nodes | Components | Topology | Old ratio cut | New ratio cut | Old conductance | New conductance |',
            '| --- | --- | --- | ---: | ---: | --- | ---: | ---: | ---: | ---: |']
    for case in evaluation['cases']:
        def metric(side,key):
            value=case[side]['metrics'][key] if case[side]['metrics'] else None
            return 'undefined' if value is None else f'{value:.8g}'
        lines.append(f"| {case['repository']} | {case['lockfile']} | {case['split']} | {case['nodes']} | {case['components']} | {'complete' if case['topology_complete'] else 'incomplete'} | {metric('before','ratio_cut')} | {metric('after','ratio_cut')} | {metric('before','conductance')} | {metric('after','conductance')} |")
    (output/'REPORT.md').write_text('\n'.join(lines)+'\n')
    print(json.dumps({'cases':len(evaluation['cases']),'primary':len(primary),'conductance_regressions':len(tradeoffs),'remaining_ratio_losses':len(remaining)}),flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['diagnose','evaluate-development','evaluate-all','audit-replay','historical','report'])
    parser.add_argument('--study', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--library',type=Path)
    parser.add_argument('--binary',type=Path)
    parser.add_argument('--repeats',type=int,default=5)
    parser.add_argument('--objective',choices=['ratio_cut','conductance'],default='ratio_cut')
    args = parser.parse_args()
    if args.mode=='diagnose':
        diagnose(args.study.resolve(), args.output.resolve())
    elif args.mode=='report':
        report(args.output.resolve())
    elif args.mode=='audit-replay':
        if not args.binary:parser.error('audit replay requires binary')
        audit_replay(args.study.resolve(),args.output.resolve(),args.binary.resolve())
    elif args.mode=='historical':
        if not args.library:parser.error('historical requires library')
        historical(args.study.resolve(),args.output.resolve(),args.library.resolve())
    else:
        if not args.library or args.repeats<5:parser.error('evaluation requires library and at least5 repetitions')
        evaluate(args.study.resolve(),args.output.resolve(),args.library.resolve(), 'development' if args.mode=='evaluate-development' else 'all',args.repeats,args.objective)


if __name__ == '__main__':
    main()
