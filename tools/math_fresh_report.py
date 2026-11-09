#!/usr/bin/env python3
"""Validate completed fresh-study receipts and write a report without rerunning it."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

from math_fresh_validation import summary, verify_freeze, fingerprint


def read(path):
    return json.loads(path.read_text())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def report(output):
    assert not (output/'results.json').exists(), 'never overwrite a completed report'
    frozen=verify_freeze(output)
    fresh=read(output/'fresh-evaluation.json')
    old=read(output/'old-evaluation.json')
    cohort=read(output/'fresh/cohort.json')
    assert fresh['frozen_sha256']==digest(output/'frozen.json')
    assert cohort['freeze_sha256']==digest(output/'frozen-before-outcomes.json')
    assert frozen['pre_evaluation_amendment']['prior_sha256']==cohort['freeze_sha256']
    identities={r['identity'] for r in cohort['repositories']}
    assert len(identities)==len(cohort['repositories'])==200
    assert not identities.intersection(cohort['excluded_original_identities'])
    sources=read(output/'fresh/sources.json')
    snapshots=read(output/'fresh/snapshots.json')['snapshots']
    assert len(snapshots)==200
    assert sum(len(s.get('lockfiles',[])) for s in snapshots)==len(sources)==len(fresh['cases'])
    for row in fresh['cases']:
        assert read(output/'fresh/case-receipts'/(row['id']+'.json'))==row
        assert row.get('non_math_report_unchanged')
    files=0
    for snapshot in snapshots:
        folder=output/'fresh/repositories'/snapshot['repository'].replace('/','__')/'source'
        for file in snapshot.get('files',[]):
            assert digest(folder/file['path'])==file['sha256']
            files+=1
    contexts=0
    for case in sources:
        for file in case.get('files',[]):
            path=output/'fresh/context/sources'/case['id']/file['file']
            assert digest(path)==file['sha256']
            contexts+=1
    primary=[r for r in fresh['cases'] if r.get('primary_eligible')]
    assert len({r['repository'] for r in primary})==len(primary)
    counts=Counter()
    for row in fresh['cases']:
        if row['status']!='audited':reason=row['status']
        elif not row.get('topology_complete'):reason='incomplete_topology'
        elif row['nodes']<=1:reason='singleton'
        elif row['components']!=1:reason='disconnected'
        elif not row.get('math_validated'):reason='numeric_unqualified'
        elif not row['preselected_repository_lock']:reason='other_lock_same_repository'
        elif row['overlaps_original_topology']:reason='exact_old_topology'
        elif row['duplicate_fresh_primary_topology']:reason='duplicate_fresh_topology'
        else:reason='primary'
        counts[reason]+=1
        assert (reason=='primary')==bool(row.get('primary_eligible'))
        if row.get('math_validated'):
            graph=read(output/'fresh/graphs'/(row['id']+'.json'))
            assert fingerprint(graph)==row['topology_fingerprint']
    recomputed=summary(primary)
    for key,value in recomputed.items():assert fresh['fresh_primary'][key]==value
    audit=read(output/'audit-replay.json')
    historical=read(output/'historical-value.json')
    assert len(audit['cases'])==152 and len(historical['cases'])==145
    assert all(r['after_scalar']==r['before_scalar'] and r['after_combined']==r['before_combined'] for r in historical['cases'])
    result={'frozen_sha256':digest(output/'frozen.json'),'repository_count':200,
            'captured_snapshot_status_counts':fresh['snapshot_status_counts'],
            'lock_inventory_count':len(sources),'exclusion_accounting':dict(counts),
            'old_primary':old['summary'],'fresh_primary':fresh['fresh_primary'],
            'fresh_all_eligible_locks':fresh['all_eligible_locks'],
            'source_files_verified':files,'context_records_verified':contexts,
            'unchanged_fresh_non_math_reports':len(fresh['cases']),
            'unchanged_old_non_math_reports':len(audit['cases']),
            'unchanged_old_scalar_and_combined_decisions':len(historical['cases']),
            'limitations':['Only the later slice of the same critical npm ranking; shared packages and isomorphic graphs may remain',
                           'Canonical C-ABI scores and parser-order CLI profiles use different node orderings and are reported separately',
                           'Hybrid bridge recovery is structural; pure spectral strict wins measure the math contribution',
                           'Fresh structural evidence does not establish security detection or human review value']}
    (output/'results.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    receipt={'freeze_sha256':digest(output/'frozen.json'),'fresh_evaluation_sha256':digest(output/'fresh-evaluation.json'),
             'old_evaluation_sha256':digest(output/'old-evaluation.json'),'cohort_sha256':digest(output/'fresh/cohort.json'),
             'old_audit_receipt_sha256':digest(output/'audit-replay.json'),'historical_receipt_sha256':digest(output/'historical-value.json'),
             'results_sha256':digest(output/'results.json'),'per_case_receipts':len(fresh['cases']),
             'source_files':files,'context_records':contexts}
    (output/'receipt.json').write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n')
    lines=['# Fresh cohort: all lock inventories','',
           'Fixed200 repository identities;105with locks and95without a project lock in the fixed discovery scope. Canonical C-ABI primary scores below. CLI provenance/profile evidence is separately labeled in JSON.','',
           '|Repository|Lock|Status|Primary eligible|Spectral ratio|Hybrid ratio|Basic ratio|',
           '|---|---|---|---|---:|---:|---:|']
    for row in fresh['cases']:
        def value(name):
            metrics=row.get(name,{}).get('metrics')
            number=metrics.get('ratio_cut') if metrics else None
            return f'{number:.8g}' if number is not None else 'undefined'
        basic=(row.get('basic',{}).get('ratio_cut') or {}).get('metrics',{}).get('ratio_cut')
        lines.append('|'+ '|'.join([row['repository'],row['lockfile'],row['status'],str(row.get('primary_eligible',False)),value('spectral'),value('hybrid'),f'{basic:.8g}' if basic is not None else 'undefined'])+'|')
    (output/'REPORT.md').write_text('\n'.join(lines)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ['old_primary','fresh_primary','fresh_all_eligible_locks']}),flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',required=True,type=Path)
    report(parser.parse_args().output.resolve())
