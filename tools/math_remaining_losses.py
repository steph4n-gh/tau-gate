#!/usr/bin/env python3
"""Diagnose the residual loss cases without mutating earlier experiment evidence."""
import argparse
from collections import Counter
import json
from pathlib import Path
import subprocess
from fractions import Fraction
import statistics

import numpy as np

import math_corpus as core
from math_cut_experiment import adjacency, thresholds, native_vector
from math_full_comparison import structural_outcome


def read(path):
    return json.loads(path.read_text())


def best_cut(vector, adj, metric='ratio_cut'):
    order,cuts=thresholds(vector,adj)
    other='conductance' if metric=='ratio_cut' else 'ratio_cut'
    cut=min(cuts,key=lambda c:(c[metric],c[other],c['index']))
    chosen=set(order[:cut['index']+1])
    return {'metrics':core.partition_metrics(chosen,adj),'indices':sorted(chosen)}


def probe(output, tolerance='1e-9'):
    baseline=output/'baseline'
    text=(baseline/'math.rs').read_text()
    # Retain the already computed second direction, after the solver has stopped.
    text=text.replace('struct Estimate {','struct Estimate {\n    secondary: Vec<f64>,',1)
    text=text.replace('    let vector = vectors.remove(0);','    let secondary = if vectors.len()>1 { vectors[1].clone() } else { Vec::new() };\n    let vector = vectors.remove(0);',1)
    text=text.replace('    Estimate {\n        vector,','    Estimate {\n        secondary,\n        vector,',1)
    text=text.replace('dot(&residuals[0], &residuals[0]).sqrt() < 1e-9','dot(&residuals[0], &residuals[0]).sqrt() < '+tolerance)
    suffix='current' if tolerance=='1e-9' else 'tight'
    source=output/('probe-math-'+suffix+'.rs');source.write_text(text)
    main='''#![allow(dead_code)]
#[path="BASE/error.rs"] mod error;
#[path="BASE/graph_impl.rs"] mod graph_impl;
mod math {
 include!("SOURCE");
 pub fn inspect(n:usize, edges:&[(usize,usize)]) -> String {
  let mut adj=vec![Vec::new();n];
  for &(u,v) in edges { if u!=v {adj[u].push(v);adj[v].push(u);} }
  let degrees:Vec<_>=adj.iter().map(|r|r.len() as f64).collect();
  let value=solve(&adj,&degrees,5000.min((20_000_000usize/(n+edges.len()).max(1)).max(1)));
  let secondary_image=if value.secondary.is_empty() { Vec::new() } else { multiply(&adj,&value.secondary) };
  let secondary_value=dot(&value.secondary,&secondary_image);
  let secondary_residual=secondary_image.iter().zip(&value.secondary).map(|(av,v)|(av-secondary_value*v).powi(2)).sum::<f64>().sqrt();
  let list=|v:&[f64]|v.iter().map(ToString::to_string).collect::<Vec<_>>().join(",");
  format!("{{\\\"vector\\\":[{}],\\\"score\\\":{},\\\"residual\\\":{},\\\"iterations\\\":{},\\\"secondary\\\":[{}],\\\"secondary_score\\\":{},\\\"secondary_residual\\\":{}}}",list(&value.vector),value.value,value.residual,value.iterations,list(&value.secondary),secondary_value,secondary_residual)
 }
}
fn main(){use std::io::Read;let mut input=String::new();std::io::stdin().read_to_string(&mut input).unwrap();let mut data=input.split_whitespace().map(|s|s.parse::<usize>().unwrap());let n=data.next().unwrap();let m=data.next().unwrap();let edges:Vec<_>=(0..m).map(|_|(data.next().unwrap(),data.next().unwrap())).collect();assert!(data.next().is_none());println!("{}",math::inspect(n,&edges));}
'''.replace('BASE',str(baseline)).replace('SOURCE',str(source))
    main_path=output/('probe-'+suffix+'.rs');main_path.write_text(main)
    executable=output/('probe-'+suffix)
    subprocess.run(['rustc','--edition=2021','-O',str(main_path),'-o',str(executable)],check=True)
    return executable


def overlap(vector, side):
    side=set(side);other=set(range(len(vector)))-side
    a=max(vector[i] for i in side)-min(vector[i] for i in other)
    b=max(vector[i] for i in other)-min(vector[i] for i in side)
    return min(a,b)


def diagnose(study, source, output):
    output.mkdir(parents=True,exist_ok=True)
    executable=probe(output)
    cases=read(study/'all-evaluation.json')['cases']
    results=[]
    for case in cases:
        if not case['topology_complete'] or case['components']!=1 or case['nodes']<=1:continue
        ratio_loss=structural_outcome(case['after']['metrics']['ratio_cut'],case['basic']['ratio_cut']['metrics']['ratio_cut'])=='basic_better'
        regression=structural_outcome(case['after']['metrics']['conductance'],case['before']['metrics']['conductance'])=='basic_better'
        if not (ratio_loss or regression):continue
        graph=read(source/'graphs'/(case['id']+'.json'));adj=adjacency(graph)
        native=native_vector(executable,graph)
        assert native['score']==case['after']['result']['score']
        current=best_cut(native['vector'],adj)
        assert abs(current['metrics']['ratio_cut']-case['after']['metrics']['ratio_cut'])<1e-12
        reference=read(source/'references'/(case['id']+'.json'))
        exact=best_cut(reference['vector'],adj)
        positions={name:i for i,name in enumerate(graph['nodes'])}
        best_basic=[positions[p] for p in case['basic']['ratio_cut']['partition']]
        a=np.asarray(native['vector']);b=np.asarray(reference['vector'])
        error=float(min(np.linalg.norm(a-b),np.linalg.norm(a+b)))
        row={'id':case['id'],'repository':case['repository'],'split':case['split'],'nodes':case['nodes'],
             'ratio_loss':ratio_loss,'conductance_regression':regression,
             'current':current,'reference_order':exact,'basic':case['basic'],
             'basic_cut_coordinate_overlap_native':overlap(a,best_basic),
             'basic_cut_coordinate_overlap_reference':overlap(b,best_basic),
             'native_reference_vector_distance':error,'native':native,
             'old_maxgap_metrics':case['before']['metrics']}
        results.append(row)
        print(json.dumps({'diagnosed':len(results),'repository':case['repository'],'reference_recovers_ratio_loss':ratio_loss and structural_outcome(exact['metrics']['ratio_cut'],case['basic']['ratio_cut']['metrics']['ratio_cut'])!='basic_better'}),flush=True)
    assert len(results)==22
    summary={'target_cases':len(results),'ratio_losses':sum(c['ratio_loss'] for c in results),
             'conductance_regressions':sum(c['conductance_regression'] for c in results),
             'ratio_losses_recovered_by_reference_order':sum(c['ratio_loss'] and structural_outcome(c['reference_order']['metrics']['ratio_cut'],c['basic']['ratio_cut']['metrics']['ratio_cut'])!='basic_better' for c in results),
             'splits':dict(Counter(c['split'] for c in results))}
    core.save(output/'diagnosis.json',{'summary':summary,'cases':results})
    print(json.dumps(summary),flush=True)


def development(study,source,output):
    executable=output/'probe-current'
    cases=[c for c in read(study/'all-evaluation.json')['cases'] if c['split']=='development'
           and c['topology_complete'] and c['components']==1 and c['nodes']>1]
    rows=[]
    for case in cases:
        graph=read(source/'graphs'/(case['id']+'.json'));adj=adjacency(graph)
        native=native_vector(executable,graph)
        x=np.asarray(native['vector']);y=np.asarray(native['secondary'])
        axes={'primary':x,'secondary':y,'sum':x+y,'difference':x-y}
        cuts={name:best_cut(vector,adj) for name,vector in axes.items()}
        sets={'primary':['primary'],'two_axes':['primary','secondary'],'four_projections':list(axes)}
        variants={name:min((cuts[k] for k in keys),key=lambda c:(c['metrics']['ratio_cut'],c['metrics']['conductance'])) for name,keys in sets.items()}
        row={k:case[k] for k in ['id','repository','nodes','split']}
        row.update(native=native,cuts=cuts,variants=variants,basic=case['basic'],old_maxgap=case['before']['metrics'],current=case['after']['metrics'])
        # Can the expanded family avoid the previous conductance loss while
        # retaining the ratio quality already achieved by the current rule?
        feasible=[]
        for name,vector in axes.items():
            order,candidates=thresholds(vector,adj)
            for cut in candidates:
                if cut['ratio_cut']<=case['after']['metrics']['ratio_cut']+1e-12 and cut['conductance']<=case['before']['metrics']['conductance']+1e-12:
                    feasible.append({'projection':name,**cut})
        row['joint_nonregression_candidate']=min(feasible,key=lambda c:(c['ratio_cut'],c['conductance'])) if feasible else None
        rows.append(row)
        print(json.dumps({'development':len(rows),'repository':case['repository']}),flush=True)
    summaries={}
    for name in ['primary','two_axes','four_projections']:
        summary={}
        for metric in ['ratio_cut','conductance']:
            summary[metric]={'versus_basic':dict(Counter(structural_outcome(c['variants'][name]['metrics'][metric],c['basic'][metric]['metrics'][metric]) for c in rows)),
                             'versus_current':dict(Counter(structural_outcome(c['variants'][name]['metrics'][metric],c['current'][metric]) for c in rows)),
                             'versus_original_maxgap':dict(Counter(structural_outcome(c['variants'][name]['metrics'][metric],c['old_maxgap'][metric]) for c in rows))}
        summaries[name]=summary
    core.save(output/'development.json',{'scope':'36 original development cases; secondary direction is an existing Ritz vector, not asserted converged lambda3','summary':summaries,'cases':rows})
    print(json.dumps(summaries),flush=True)


def bridge_cuts(graph):
    n=len(graph['nodes']);adj=[[] for _ in range(n)]
    for edge,(u,v) in enumerate(graph['edges']):
        if u!=v:adj[u].append((v,edge));adj[v].append((u,edge))
    discovery=[-1]*n;low=[0]*n;parent=[None]*n;parent_edge=[None]*n
    sizes=[1]*n;volumes=[len(r) for r in adj];order=[];bridges=[]
    for root in range(n):
        if discovery[root]>=0:continue
        discovery[root]=low[root]=len(order);order.append(root)
        stack=[(root,iter(adj[root]))]
        while stack:
            u,neighbors=stack[-1]
            try:v,edge=next(neighbors)
            except StopIteration:
                stack.pop();p=parent[u]
                if p is not None:
                    if low[u]>discovery[p]:bridges.append((u,p,parent_edge[u]))
                    low[p]=min(low[p],low[u]);sizes[p]+=sizes[u];volumes[p]+=volumes[u]
                continue
            if edge==parent_edge[u]:continue
            if discovery[v]<0:
                parent[v]=u;parent_edge[v]=edge;discovery[v]=low[v]=len(order);order.append(v)
                stack.append((v,iter(adj[v])))
            else:low[u]=min(low[u],discovery[v])
    total=sum(map(len,adj));result=[]
    for child,p,edge in bridges:
        size=sizes[child];volume=volumes[child]
        result.append({'edge':edge,'child':child,'parent':p,'nodes':size,'volume':volume,
                       'ratio_fraction':Fraction(n,size*(n-size)),
                       'conductance_fraction':Fraction(1,min(volume,total-volume)),
                       'indices':order[discovery[child]:discovery[child]+size]})
    return result


def tradeoffs(study,source,output):
    cases=read(study/'all-evaluation.json')['cases'];rows=[]
    for case in cases:
        if not case['topology_complete'] or case['components']!=1 or case['nodes']<=1:continue
        old=case['before']['metrics'];current=case['after']['metrics']
        if structural_outcome(current['conductance'],old['conductance'])!='basic_better':continue
        graph=read(source/'graphs'/(case['id']+'.json'))
        bridges=bridge_cuts(graph)
        n=case['nodes'];k=current['nodes'];ratio=Fraction(current['cut_edges']*n,k*(n-k))
        old_conductance=Fraction(old['cut_edges'],old['volume'] if old['volume']<=sum(len(r) for r in adjacency(graph))-old['volume'] else sum(len(r) for r in adjacency(graph))-old['volume'])
        acceptable=[b for b in bridges if b['ratio_fraction']<=ratio and b['conductance_fraction']<=old_conductance]
        # Any b-edge cut has ratio >= 4b/n. If current ratio <8/n,
        # every no-worse candidate is a one-edge bridge cut: exhaustive here.
        one_edge_only=ratio<Fraction(8,n)
        row={'id':case['id'],'repository':case['repository'],'nodes':n,'ratio_bound':str(ratio),
             'old_conductance_bound':str(old_conductance),'bridge_count':len(bridges),
             'bridge_joint_candidates':len(acceptable),'one_edge_only_bound_applies':one_edge_only,
             'joint_nonregression_globally_impossible':one_edge_only and not acceptable}
        rows.append(row)
    core.save(output/'tradeoffs.json',{'scope':'all6regressions; exactbridgeoracle/globalproofonlywhenone-edge bound applies','cases':rows})
    print(json.dumps(rows),flush=True)


def profile_probe(output):
    candidate=output/'candidate'
    code=r'''#![allow(dead_code)]
#[path="CANDIDATE/error.rs"] mod error;
#[path="CANDIDATE/graph_impl.rs"] mod graph_impl;
#[path="CANDIDATE/math.rs"] mod math;
fn main() {
 use std::io::Read;
 let mut input=String::new(); std::io::stdin().read_to_string(&mut input).unwrap();
 let mut data=input.split_whitespace().map(|s|s.parse::<usize>().unwrap());
 let n=data.next().unwrap(); let m=data.next().unwrap(); let mut g=graph_impl::DiGraph::new();
 for i in 0..n { g.add_node(i.to_string()); }
 for _ in 0..m { g.add_edge(data.next().unwrap(),data.next().unwrap()); }
 assert!(data.next().is_none());
 let r=math::analyze_graph(&g).unwrap();
 let diagnostics=r.cut_diagnostics.map(|d| {
  let alt=d.conductance_alternative.map(|a| format!(r#"{{"partition":{:?},"tau":{},"projection":"{}","ratio_cut":{},"conductance":{}}}"#,a.partition_b,a.tau,a.projection,a.ratio_cut,a.conductance)).unwrap_or("null".into());
  format!(r#"{{"projection":"{}","ratio_cut":{},"conductance":{},"secondary_direction_residual":{},"conductance_alternative":{}}}"#,d.projection,d.ratio_cut,d.conductance,d.secondary_direction_residual.map(|v|v.to_string()).unwrap_or("null".into()),alt)
 }).unwrap_or("null".into());
 println!(r#"{{"partition":{:?},"tau":{},"cut_diagnostics":{}}}"#,r.partition_b,r.tau,diagnostics);
}
'''.replace('CANDIDATE',str(candidate))
    source=output/'profile-probe.rs';source.write_text(code)
    binary=output/'profile-probe'
    subprocess.run(['rustc','--edition=2021','-O',str(source),'-o',str(binary)],check=True)
    return binary


def evaluate(study,source,output,repeats):
    assert repeats>=3
    frozen=read(output/'frozen-candidate.json')
    candidate=core.Native(output/'candidate/libtau_gate.dylib')
    baseline=core.Native(output/'baseline/libtau_gate.dylib')
    assert frozen['library_sha256']==candidate.sha256
    assert frozen['math_source_sha256']==core.digest((output/'candidate/math.rs').read_bytes())
    assert not (output/'evaluation.json').exists(), 'use a new output directory; never overwrite a run'
    profile=profile_probe(output);rows=[]
    for case in read(study/'all-evaluation.json')['cases']:
        graph=read(source/'graphs'/(case['id']+'.json'));adj=adjacency(graph)
        runs={'before':[],'after':[]}
        for repeat in range(repeats):
            for name in (['before','after'] if repeat%2==0 else ['after','before']):
                runs[name].append((baseline if name=='before' else candidate).run(graph))
        row={k:case[k] for k in ['id','repository','lockfile','split','nodes','components','topology_complete','basic']}
        row['original_maxgap']=case['before']['metrics']
        for name,values in runs.items():
            selected={k:v for k,v in values[0].items() if k!='seconds'}
            assert all({k:v for k,v in v.items() if k!='seconds'}==selected for v in values)
            side={graph['nodes'].index(p) for p in selected['partition']}
            row[name]={'result':selected,'metrics':core.partition_metrics(side,adj),
                       'seconds_median':statistics.median(v['seconds'] for v in values),
                       'seconds_range':[min(v['seconds'] for v in values),max(v['seconds'] for v in values)]}
        for field in ['score','residual','converged','iterations']:
            assert row['before']['result'][field]==row['after']['result'][field]
        measured=native_vector(profile,graph)
        assert [graph['nodes'][int(p)] for p in measured['partition']]==row['after']['result']['partition']
        assert measured['tau']==row['after']['result']['tau']
        row['cut_diagnostics']=measured['cut_diagnostics']
        if case['components']==1 and case['nodes']>1:
            vectors=native_vector(output/'probe-current',graph)
            x=np.array(vectors['vector']);y=np.array(vectors['secondary'])
            axes={'primary':x}
            if len(y):axes.update(secondary=y,sum=x+y,difference=x-y)
            oracle={name:{metric:best_cut(v,adj,metric) for metric in ['ratio_cut','conductance']}
                    for name,v in axes.items()}
            for metric in ['ratio_cut','conductance']:
                other='conductance' if metric=='ratio_cut' else 'ratio_cut'
                expected=min((c[metric] for c in oracle.values()),key=lambda c:(c['metrics'][metric],c['metrics'][other]))
                diag=measured['cut_diagnostics']
                actual=row['after']['metrics'] if metric=='ratio_cut' else (
                    core.partition_metrics({int(p) for p in diag['conductance_alternative']['partition']},adj)
                    if diag['conductance_alternative'] else row['after']['metrics'])
                for key in ['ratio_cut','conductance']:
                    assert abs(actual[key]-expected['metrics'][key])<1e-10,(case['repository'],metric,key)
                if metric=='conductance':row['conductance_profile']=actual
            for key in ['ratio_cut','conductance']:
                assert abs(measured['cut_diagnostics'][key]-row['after']['metrics'][key])<1e-10
            assert row['after']['metrics']['ratio_cut']<=row['before']['metrics']['ratio_cut']+1e-12
            assert row['conductance_profile']['conductance']<=row['original_maxgap']['conductance']+1e-12
            row['independent_threshold_oracle_matched']=True
        else:
            assert row['before']['result']==row['after']['result']
            assert measured['cut_diagnostics'] is None
            row['conductance_profile']=row['after']['metrics']
        rows.append(row)
        print(json.dumps({'evaluated':len(rows),'repository':case['repository']}),flush=True)
    groups={'primary':[r for r in rows if r['topology_complete'] and r['components']==1 and r['nodes']>1]}
    groups.update({split:[r for r in groups['primary'] if r['split']==split] for split in ['development','holdout']})
    summary={}
    for name,selected in groups.items():
        data={'cases':len(selected)}
        for metric in ['ratio_cut','conductance']:
            data[metric]={side:dict(Counter(structural_outcome(r[side]['metrics'][metric],r['basic'][metric]['metrics'][metric]) for r in selected)) for side in ['before','after']}
            data[metric]['versus_current']=dict(Counter(structural_outcome(r['after']['metrics'][metric],r['before']['metrics'][metric]) for r in selected))
        data['conductance_profile_versus_basic']=dict(Counter(structural_outcome(r['conductance_profile']['conductance'],r['basic']['conductance']['metrics']['conductance']) for r in selected))
        data['default_conductance_versus_original_maxgap']=dict(Counter(structural_outcome(r['after']['metrics']['conductance'],r['original_maxgap']['conductance']) for r in selected))
        data['timing']={'repeats':repeats,'before_total_medians':sum(r['before']['seconds_median'] for r in selected),
                        'after_total_medians':sum(r['after']['seconds_median'] for r in selected)}
        summary[name]=data
    core.save(output/'evaluation.json',{'frozen':frozen,'summary':summary,'cases':rows})
    print(json.dumps(summary),flush=True)


def report(output):
    final=output/'verified'
    evaluation=read(final/'evaluation.json')
    selected=read(output/'evaluation.json')
    def without_timing(rows):
        rows=json.loads(json.dumps(rows))
        for row in rows:
            for side in ['before','after']:
                row[side].pop('seconds_median')
                row[side].pop('seconds_range')
        return rows
    assert without_timing(evaluation['cases'])==without_timing(selected['cases'])
    audit=read(final/'audit-replay.json')
    historical=read(final/'historical-value.json')
    assert audit['cases']==read(output/'audit-replay.json')['cases']
    def historical_without_timing(rows):
        rows=json.loads(json.dumps(rows))
        for row in rows:
            for value in row['math'].values():
                value.pop('seconds')
        return rows
    assert historical_without_timing(historical['cases'])==historical_without_timing(read(output/'historical-value.json')['cases'])
    assert len(evaluation['cases'])==len(audit['cases'])==152
    assert len(historical['cases'])==145
    assert all(r['after_scalar']==r['before_scalar'] and r['after_combined']==r['before_combined']
               for r in historical['cases'])
    frozen=read(final/'frozen-candidate.json')
    assert frozen['library_sha256']==audit.get('library_sha256',evaluation['frozen']['library_sha256'])
    assert frozen['binary_sha256']==audit['binary_sha256']
    assert frozen['library_sha256']==historical['library_sha256']
    primary=[r for r in evaluation['cases'] if r['topology_complete'] and r['components']==1 and r['nodes']>1]
    losses=[r['repository'] for r in primary if structural_outcome(r['after']['metrics']['ratio_cut'],r['basic']['ratio_cut']['metrics']['ratio_cut'])=='basic_better']
    regressions=[r['repository'] for r in primary if structural_outcome(r['after']['metrics']['conductance'],r['original_maxgap']['conductance'])=='basic_better']
    results={'method':frozen,'summary':evaluation['summary'],'remaining_ratio_losses':losses,
             'default_conductance_regressions_versus_original':regressions,
             'unchanged_non_math_audits':len(audit['cases']),'historical_summary':historical['summary'],
             'limits':['Already studied cohort; reused validation split is descriptive',
                       'Secondary Ritz search direction is not asserted converged lambda3',
                       'Conductance profile is a separate partition, not default regression removal',
                       'No demonstrated historical event-detection or human-review improvement']}
    core.save(output/'results.json',results)
    core.save(final/'equivalence.json',{'selected_and_final_non_timing_inventory_results_equal':152,
              'selected_and_final_non_math_audit_receipts_equal':152,'historical_results_equal':145,
              'scalar_and_combined_alert_booleans_unchanged':145,
              'final_freeze_sha256':core.digest((final/'frozen-candidate.json').read_bytes()),
              'evaluation_sha256':core.digest((final/'evaluation.json').read_bytes()),
              'audit_receipt_sha256':core.digest((final/'audit-replay.json').read_bytes()),
              'historical_receipt_sha256':core.digest((final/'historical-value.json').read_bytes())})
    lines=['# All152 inventories: four fixed Ritz projections','',
           'Primary ratio-cut partition and separately selected conductance profile. Reused cohort; no security-detection improvement is established.','',
           '|Repository|Lock|Split|Nodes|Components|Complete|Previous ratio|Primary ratio|Previous conductance|Primary conductance|Conductance profile|',
           '|---|---|---|---:|---:|---|---:|---:|---:|---:|---:|']
    for row in evaluation['cases']:
        def value(metrics,metric):
            x=metrics[metric] if metrics else None
            return 'undefined' if x is None else f'{x:.8g}'
        cells=[row['repository'],row['lockfile'],row['split'],str(row['nodes']),str(row['components']),str(row['topology_complete'])]
        cells.extend([value(row['before']['metrics'],'ratio_cut'),value(row['after']['metrics'],'ratio_cut'),
                      value(row['before']['metrics'],'conductance'),value(row['after']['metrics'],'conductance'),
                      value(row['conductance_profile'],'conductance')])
        lines.append('|'+ '|'.join(cells)+'|')
    (output/'REPORT.md').write_text('\n'.join(lines)+'\n')
    print(json.dumps({'inventories':152,'eligible':len(primary),'ratio_losses':len(losses),
                      'default_conductance_regressions':len(regressions),'unchanged_pairs':145}),flush=True)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode',choices=['diagnose','development','tradeoffs','evaluate','report'])
    p.add_argument('--study',required=True,type=Path)
    p.add_argument('--source',required=True,type=Path)
    p.add_argument('--output',required=True,type=Path)
    p.add_argument('--repeats',type=int,default=5)
    a=p.parse_args()
    assert a.output.resolve() not in (a.study.resolve(),a.source.resolve()), 'input studies are immutable'
    artifact={'diagnose':'diagnosis.json','development':'development.json',
              'tradeoffs':'tradeoffs.json','evaluate':'evaluation.json','report':'results.json'}[a.mode]
    assert not (a.output/artifact).exists(), 'use a new output directory; never overwrite a run'
    if a.mode=='diagnose':diagnose(a.study.resolve(),a.source.resolve(),a.output.resolve())
    elif a.mode=='development':development(a.study.resolve(),a.source.resolve(),a.output.resolve())
    elif a.mode=='tradeoffs':tradeoffs(a.study.resolve(),a.source.resolve(),a.output.resolve())
    elif a.mode=='evaluate':evaluate(a.study.resolve(),a.source.resolve(),a.output.resolve(),a.repeats)
    else:report(a.output.resolve())


if __name__=='__main__':main()
