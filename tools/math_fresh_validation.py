#!/usr/bin/env python3
"""Diagnose on old data, freeze a method, then evaluate disjoint project inputs."""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import json
import math
from pathlib import Path
import subprocess
import re
import statistics
import urllib.parse

import numpy as np
from scipy.optimize import linprog

import math_corpus as core
from math_cut_experiment import adjacency, native_vector
from math_remaining_losses import best_cut
from math_full_comparison import structural_outcome
import npm_repo_experiment as acquisition
import parser_corpus as context
import math_update_study as history
from math_remaining_losses import bridge_cuts


def read(path):
    return json.loads(path.read_text())


def vector_probe(output):
    code=r'''#![allow(dead_code)]
#[path="BASE/error.rs"] mod error;
#[path="BASE/graph_impl.rs"] mod graph_impl;
mod math {
 include!("BASE/math.rs");
 pub fn inspect(n:usize,edges:&[(usize,usize)]) {
  let mut adj=vec![Vec::new();n];
  for &(u,v) in edges {if u!=v {adj[u].push(v);adj[v].push(u);}}
  let degrees:Vec<_>=adj.iter().map(|r|r.len() as f64).collect();
  let e=solve(&adj,&degrees,5000.min((20_000_000usize/(n+edges.len()).max(1)).max(1)));
  let list=|v:&[f64]|v.iter().map(ToString::to_string).collect::<Vec<_>>().join(",");
  println!(r#"{{"vector":[{}],"secondary":[{}],"score":{},"residual":{},"iterations":{}}}"#,
   list(&e.vector),list(e.secondary.as_deref().unwrap_or(&[])),e.value,e.residual,e.iterations);
 }
}
fn main(){use std::io::Read;let mut input=String::new();std::io::stdin().read_to_string(&mut input).unwrap();let mut data=input.split_whitespace().map(|s|s.parse::<usize>().unwrap());let n=data.next().unwrap();let m=data.next().unwrap();let edges:Vec<_>=(0..m).map(|_|(data.next().unwrap(),data.next().unwrap())).collect();assert!(data.next().is_none());math::inspect(n,&edges);}
'''.replace('BASE',str((output/'baseline').resolve()))
    path=output/'vector-probe.rs';path.write_text(code)
    binary=output/'vector-probe'
    subprocess.run(['rustc','--edition=2021','-O',str(path),'-o',str(binary)],check=True)
    return binary


def components_within(side, adj):
    remaining=set(side)
    result=[]
    while remaining:
        first=min(remaining)
        remaining.remove(first)
        component={first};stack=[first]
        while stack:
            for v in adj[stack.pop()]:
                if v in remaining:
                    remaining.remove(v);component.add(v);stack.append(v)
        result.append(component)
    return result


def diagnose(output):
    probe=vector_probe(output)
    prior=read(Path('ecosystem_audit/math-remaining-losses-20261109/verified/evaluation.json'))
    source=Path('ecosystem_audit/math-comparison-152-20261109')
    rows=[]
    for case in prior['cases']:
        if not (case['topology_complete'] and case['components']==1 and case['nodes']>1):
            continue
        graph=read(source/'graphs'/(case['id']+'.json'));adj=adjacency(graph)
        vectors=native_vector(probe,graph)
        x=np.array(vectors['vector']);y=np.array(vectors['secondary'])
        axes=[x,y,x+y,x-y]
        four=[best_cut(v,adj) for v in axes]
        key=lambda c:(c['metrics']['ratio_cut'],c['metrics']['conductance'])
        current=min(four,key=key)
        assert abs(current['metrics']['ratio_cut']-case['after']['metrics']['ratio_cut'])<1e-12
        extended=four+[best_cut(math.cos(k*math.pi/16)*x+math.sin(k*math.pi/16)*y,adj)
                       for k in range(16) if k%4]
        refined=[]
        for cut in four:
            side=set(cut['indices'])
            for half in [side,set(range(len(adj)))-side]:
                for component in components_within(half,adj):
                    refined.append({'indices':sorted(component),'metrics':core.partition_metrics(component,adj)})
        loss=structural_outcome(current['metrics']['ratio_cut'],case['basic']['ratio_cut']['metrics']['ratio_cut'])=='basic_better'
        row={'id':case['id'],'repository':case['repository'],'current':current,
             'basic':case['basic'],'sixteen_axes':min(extended,key=key),
             'component_refinement':min(four+refined,key=key),'loss':loss}
        if loss:
            index={p:i for i,p in enumerate(graph['nodes'])}
            side=[index[p] for p in case['basic']['ratio_cut']['partition']]
            other=sorted(set(range(len(adj)))-set(side))
            points=np.column_stack((x,y))
            delta=(points[side,None,:]-points[other][None,:,:]).reshape((-1,2))
            constraints=np.column_stack((delta,np.ones(len(delta))))
            fit=linprog([0,0,-1],A_ub=constraints,b_ub=np.zeros(len(delta)),
                        bounds=[(-1,1),(-1,1),(None,None)],method='highs')
            assert fit.success
            row['best_basic_linear_separation_margin']=float(fit.x[2])
            row['current_side_component_counts']=[len(components_within(set(current['indices']),adj)),
                len(components_within(set(range(len(adj)))-set(current['indices']),adj))]
        rows.append(row)
        if loss:
            print(json.dumps({k:v for k,v in row.items() if k in ['repository','best_basic_linear_separation_margin','current_side_component_counts']} | {
                k:row[k]['metrics']['ratio_cut'] for k in ['current','sixteen_axes','component_refinement']}),flush=True)
    summary={}
    for variant in ['current','sixteen_axes','component_refinement']:
        summary[variant]=dict(Counter(structural_outcome(r[variant]['metrics']['ratio_cut'],r['basic']['ratio_cut']['metrics']['ratio_cut']) for r in rows))
    core.save(output/'diagnosis.json',{'summary':summary,'cases':rows})
    print(json.dumps(summary),flush=True)


def fingerprint(graph):
    edges=sorted(tuple(sorted((graph['nodes'][u],graph['nodes'][v])))
                 for u,v in graph['edges'] if u!=v)
    return core.digest(json.dumps([sorted(graph['nodes']),edges],separators=(',',':')).encode())


def verify_freeze(output):
    frozen=read(output/'frozen.json')
    for file,digest in frozen['source_files'].items():
        assert core.digest(Path(file).read_bytes())==digest, file
    for file,digest in frozen['candidate_files'].items():
        assert core.digest((output/'candidate'/file).read_bytes())==digest, file
    for file,digest in frozen['baseline_files'].items():
        assert core.digest((output/'baseline'/file).read_bytes())==digest, file
    return frozen


def select(output):
    frozen=verify_freeze(output)
    prior=Path(frozen['protocol']['original_corpus'])
    old=read(prior/'cohort.json')
    assert core.digest((prior/'critical-source.json').read_bytes())==old['source_sha256']
    canonical=lambda resolution: resolution.get('repository',urllib.parse.urlparse(resolution['input_url']).path.strip('/').removesuffix('.git')).lower()
    excluded={canonical(x['resolution']) for x in old['repositories']}
    packages=sorted((p for p in read(prior/'critical-source.json')['projects'] if p['ecosystem']=='npm'),key=lambda p:(p['rankings_average'],p['name']))
    seen_urls=set();ranked=[]
    for rank,p in enumerate(packages,1):
        url=p.get('repository_url','')
        if re.fullmatch(r'https://github.com/[\w.-]+/[\w.-]+(?:\.git)?/?',url) and url not in seen_urls:
            seen_urls.add(url);ranked.append((rank,p))
    folder=output/'fresh';folder.mkdir(exist_ok=True)
    cache=read(prior/'selection-resolution-cache.json')
    if (folder/'resolution-cache.json').exists():cache.update(read(folder/'resolution-cache.json'))
    chosen=[];seen=set(excluded);overlaps=[]
    for start in range(0,len(ranked),32):
        batch=ranked[start:start+32]
        needed=[p['repository_url'] for _,p in batch if p['repository_url'] not in cache]
        with ThreadPoolExecutor(max_workers=6) as pool:
            for item in pool.map(acquisition.resolve,needed):cache[item['input_url']]=item
        core.save(folder/'resolution-cache.json',cache)
        for rank,p in batch:
            item=cache[p['repository_url']]
            identity=canonical(item)
            if identity in seen:
                if identity in excluded:overlaps.append(identity)
                continue
            seen.add(identity)
            # Preserve failed named GitHub repositories in the denominator.
            item={**item,'repository':item.get('repository',identity)}
            chosen.append({'rank':len(chosen)+1,'package_rank':rank,'package':p['name'],
                           'identity':identity,'resolution':item})
            if len(chosen)==frozen['protocol']['fresh_repositories']:break
        if len(chosen)==frozen['protocol']['fresh_repositories']:break
    assert len(chosen)==frozen['protocol']['fresh_repositories']
    assert not ({x['identity'] for x in chosen}&excluded)
    core.save(folder/'cohort.json',{'source_sha256':old['source_sha256'],'source_url':old['source_url'],
                                  'excluded_original_identities':sorted(excluded),'excluded_aliases':overlaps,
                                  'repositories':chosen,'freeze_sha256':core.digest((output/'frozen.json').read_bytes())})
    print(json.dumps({'selected':len(chosen),'old_identity_overlap':0,'last_package_rank':chosen[-1]['package_rank']}),flush=True)


def collect(output):
    verify_freeze(output)
    folder=output/'fresh';cohort=read(folder/'cohort.json')
    def capture(item):
        if item['resolution']['status']!='resolved':
            return {**item['resolution'],'status':'capture_unavailable'}
        return acquisition.capture(item['resolution'],folder)
    with ThreadPoolExecutor(max_workers=6) as pool:
        snapshots=list(pool.map(capture,cohort['repositories']))
    core.save(folder/'snapshots.json',{'snapshots':snapshots,'status_counts':dict(Counter(s['status'] for s in snapshots))})
    print(json.dumps({'snapshots':len(snapshots),'status_counts':dict(Counter(s['status'] for s in snapshots))}),flush=True)
    def sources(snapshot):
        records=[]
        if snapshot['status']!='captured':return records
        for lock in snapshot['lockfiles']:
            try:
                case={'repository':snapshot['repository'],'lockfile':lock}
                records.append(context.source_case(folder,folder/'context',case,snapshot))
            except Exception as error:
                records.append({'repository':snapshot['repository'],'lockfile':lock,'error':str(error)})
        return records
    with ThreadPoolExecutor(max_workers=6) as pool:
        cases=[case for group in pool.map(sources,snapshots) for case in group]
    core.save(folder/'sources.json',cases)
    print(json.dumps({'source_cases':len(cases),'source_failures':sum('error' in c for c in cases)}),flush=True)


def graph_from_report(report):
    graph=history.graph_from_report(report)
    graph['roots']=report.get('introducer_roots',[])
    return graph


def compare_graph(graph, baseline, candidate):
    adj=adjacency(graph);runs={'spectral':[],'hybrid':[]}
    for repeat in range(5):
        for name in (['spectral','hybrid'] if repeat%2==0 else ['hybrid','spectral']):
            runs[name].append((baseline if name=='spectral' else candidate).run(graph))
    result={}
    for name,values in runs.items():
        value={k:v for k,v in values[0].items() if k!='seconds'}
        assert all({k:v for k,v in r.items() if k!='seconds'}==value for r in values)
        assert 'error' not in value
        positions={p:i for i,p in enumerate(graph['nodes'])}
        result[name]={'result':value,'metrics':core.partition_metrics({positions[p] for p in value['partition']},adj),
                      'seconds_median':statistics.median(r['seconds'] for r in values),
                      'seconds_range':[min(r['seconds'] for r in values),max(r['seconds'] for r in values)]}
    for key in ['score','converged','residual','iterations']:
        assert result['spectral']['result'][key]==result['hybrid']['result'][key],key
    result['basic'],result['basic_counts']=core.simple_partitions(graph,adj)
    count,_=core.csgraph.connected_components(core.laplacian(graph)[1],directed=False)
    result['components']=int(count)
    if count==1 and len(adj)>1:
        bridges=bridge_cuts(graph)
        expected=min([result['spectral']['metrics']['ratio_cut']]+[float(c['ratio_fraction']) for c in bridges])
        assert abs(expected-result['hybrid']['metrics']['ratio_cut'])<1e-10
    return result


def summary(rows):
    result={'cases':len(rows)}
    for metric in ['ratio_cut','conductance']:
        result[metric]={name:dict(Counter(structural_outcome(r[name]['metrics'][metric],r['basic'][metric]['metrics'][metric]) for r in rows)) for name in ['spectral','hybrid']}
        result[metric]['hybrid_versus_spectral']=dict(Counter(structural_outcome(r['hybrid']['metrics'][metric],r['spectral']['metrics'][metric]) for r in rows))
    gains=[(r['basic']['ratio_cut']['metrics']['ratio_cut']-r['spectral']['metrics']['ratio_cut'])/r['basic']['ratio_cut']['metrics']['ratio_cut'] for r in rows
           if structural_outcome(r['spectral']['metrics']['ratio_cut'],r['basic']['ratio_cut']['metrics']['ratio_cut'])=='math_better']
    result['pure_spectral_ratio_gain_over_basic']={'wins':len(gains),'more_than_one_percent':sum(g>.01 for g in gains),'median_relative_gain_on_wins':statistics.median(gains) if gains else None}
    return result


def evaluate_old(output):
    verify_freeze(output)
    source=Path('ecosystem_audit/math-comparison-152-20261109')
    baseline=core.Native(output/'baseline/libtau_gate.dylib');candidate=core.Native(output/'candidate/libtau_gate.dylib')
    prior=read(Path('ecosystem_audit/math-remaining-losses-20261109/verified/evaluation.json'))
    rows=[]
    for case in prior['cases']:
        graph=read(source/'graphs'/(case['id']+'.json'))
        row={k:case[k] for k in ['id','repository','lockfile','nodes','topology_complete']}
        row.update(compare_graph(graph,baseline,candidate))
        assert row['basic']==case['basic']
        rows.append(row)
    selected=[r for r in rows if r['topology_complete'] and r['components']==1 and r['nodes']>1]
    core.save(output/'old-evaluation.json',{'summary':summary(selected),'cases':rows})
    print(json.dumps(summary(selected)),flush=True)


def evaluate_fresh(output):
    frozen=verify_freeze(output)
    folder=output/'fresh'
    snapshots=read(folder/'snapshots.json')['snapshots'];cohort=read(folder/'cohort.json')
    excluded=set(read(folder/'cohort.json')['excluded_original_identities'])
    assert not ({r['identity'] for r in cohort['repositories']}&excluded)
    original_hashes={fingerprint(read(p)) for p in Path('ecosystem_audit/math-comparison-152-20261109/graphs').glob('*.json')}
    primary_locks={s['repository']:min(s.get('lockfiles',[]),key=lambda p: (frozen['protocol']['lock_priority'].index(Path(p).name),p)) for s in snapshots if s.get('lockfiles')}
    baseline=core.Native(output/'baseline/libtau_gate.dylib');candidate=core.Native(output/'candidate/libtau_gate.dylib')
    rows=[];seen=set()
    rank={r['identity']:r['rank'] for r in cohort['repositories']}
    cases=sorted(read(folder/'sources.json'),key=lambda c:(rank[c['repository'].lower()],c['lockfile']))
    for case in cases:
        row={k:case[k] for k in ['repository','lockfile']}
        row['preselected_repository_lock']=primary_locks.get(case['repository'])==case['lockfile']
        row['id']=context.case_id(case['repository'],case['lockfile'])
        try:
            if 'error' in case:
                row.update(status='source_failure',error=case['error'])
                rows.append(row);continue
            reports={};exits={}
            for name in ['baseline','candidate']:
                cmd=[str(output/name/'tau-gate'),'audit','--lock',case['lock'],'--project-inputs',case['index'],'--json']
                run=subprocess.run(cmd,capture_output=True,text=True,timeout=180)
                reports[name]=json.loads(run.stdout);exits[name]=run.returncode
                core.save(folder/'audits'/name/(row['id']+'.json'),reports[name])
            before,after=[{k:v for k,v in reports[s].items() if k!='topology'} for s in ['baseline','candidate']]
            assert before==after and exits['baseline']==exits['candidate']
            row.update(status='audited',exit_code=exits['candidate'],topology_complete=after.get('topology_status')=='complete',
                       non_math_report_unchanged=True,issues=after.get('issues'),format=after.get('format'))
            if not after.get('packages'):
                row['status']='no_graph';row['error']=after.get('error');rows.append(row);continue
            graph=graph_from_report(after);graph['repository']=case['repository']
            core.save(folder/'graphs'/(row['id']+'.json'),graph)
            row.update(nodes=len(graph['nodes']),topology_fingerprint=fingerprint(graph))
            if len(graph['nodes'])>frozen['protocol']['max_nodes'] or len(graph['edges'])>frozen['protocol']['max_edges']:
                row['status']='study_resource_limit';rows.append(row);continue
            row.update(compare_graph(graph,baseline,candidate))
            row['cli_cut_diagnostics']=reports['candidate']['topology'].get('cut_diagnostics')
            if row['components']==1 and row['nodes']>1:
                positions={p:i for i,p in enumerate(graph['nodes'])}
                profiles={}
                for name in ['baseline','candidate']:
                    topology=reports[name]['topology'];diagnostics=topology['cut_diagnostics']
                    alternative=diagnostics['conductance_alternative']
                    part=alternative['partition'] if alternative else topology['partition']
                    profiles[name]=core.partition_metrics({positions[p] for p in part},adjacency(graph))
                row['cli_conductance_profiles']=profiles
                assert profiles['candidate']['conductance']<=profiles['baseline']['conductance']+1e-12
                metrics=[row[name]['metrics'] for name in ['spectral','hybrid']]
                origin='bridge' if (metrics[1]['ratio_cut'],metrics[1]['conductance'])<(metrics[0]['ratio_cut'],metrics[0]['conductance']) else 'spectral'
                row['canonical_selected_source']=origin
                cli_before=reports['baseline']['topology']['cut_diagnostics']
                cli_after=row['cli_cut_diagnostics']
                cli_origin='bridge' if (cli_after['ratio_cut'],cli_after['conductance'])<(cli_before['ratio_cut'],cli_before['conductance']) else 'spectral'
                assert cli_after['source']==cli_origin
                cli_primary=core.partition_metrics({positions[p] for p in reports['candidate']['topology']['partition']},adjacency(graph))
                assert abs(cli_primary['ratio_cut']-cli_after['ratio_cut'])<1e-10
                assert abs(cli_primary['conductance']-cli_after['conductance'])<1e-10
                row['cli_primary_metrics']=cli_primary
            row['overlaps_original_topology']=row['topology_fingerprint'] in original_hashes
            row['duplicate_fresh_primary_topology']=row['topology_fingerprint'] in seen
            row['primary_eligible']=row['preselected_repository_lock'] and row['topology_complete'] and row['components']==1 and row['nodes']>1 and not row['overlaps_original_topology'] and not row['duplicate_fresh_primary_topology']
            reference=core.reference(graph)
            core.save(folder/'references'/(row['id']+'.json'),reference)
            row['reference_score']=reference['score']
            row['reference_score_error']=abs(reference['score']-row['hybrid']['result']['score'])
            row['math_validated']=row['spectral']['result']['converged'] and row['spectral']['result']['residual']<1e-9 and row['reference_score_error']<=max(1e-9,abs(reference['score'])*1e-6)
            row['primary_eligible']=row['primary_eligible'] and row['math_validated']
            if row['primary_eligible']:seen.add(row['topology_fingerprint'])
            rows.append(row)
            print(json.dumps({'evaluated':len(rows),'repository':case['repository'],'eligible':row['primary_eligible']}),flush=True)
        except Exception as error:
            row.update(status='evaluation_failure',primary_eligible=False,math_validated=False,
                       error=type(error).__name__+': '+str(error))
            rows.append(row)
        finally:
            core.save(folder/'case-receipts'/(row['id']+'.json'),row)

    all_eligible=[r for r in rows if r.get('status')=='audited' and r.get('topology_complete') and r.get('components')==1 and r.get('nodes',0)>1 and r.get('math_validated')]
    primary=[r for r in rows if r.get('primary_eligible')]
    result={'frozen_sha256':core.digest((output/'frozen.json').read_bytes()),'repository_count':len(cohort['repositories']),
            'snapshot_status_counts':dict(Counter(s['status'] for s in snapshots)),
            'case_status_counts':dict(Counter(r['status'] for r in rows)),
            'old_repository_overlap':0,'all_eligible_locks':summary(all_eligible),'fresh_primary':summary(primary),'cases':rows}
    result['fresh_primary']['canonical_selected_sources']=dict(Counter(r['canonical_selected_source'] for r in primary))
    result['fresh_primary']['cli_selected_sources']=dict(Counter(r['cli_cut_diagnostics']['source'] for r in primary))
    result['fresh_primary']['cli_conductance_profile_versus_basic']=dict(Counter(structural_outcome(r['cli_conductance_profiles']['candidate']['conductance'],r['basic']['conductance']['metrics']['conductance']) for r in primary))
    core.save(output/'fresh-evaluation.json',result)
    print(json.dumps({k:v for k,v in result.items() if k!='cases'}),flush=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',choices=['diagnose','select','collect','evaluate-old','evaluate-fresh'])
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    artifact={'diagnose':'diagnosis.json','select':'fresh/cohort.json','collect':'fresh/sources.json',
              'evaluate-old':'old-evaluation.json','evaluate-fresh':'fresh-evaluation.json'}[args.mode]
    assert not (args.output/artifact).exists(), 'use a new output; never overwrite evidence'
    functions={'diagnose':diagnose,'select':select,'collect':collect,'evaluate-old':evaluate_old,'evaluate-fresh':evaluate_fresh}
    functions[args.mode](args.output.resolve())


if __name__=='__main__':
    main()
