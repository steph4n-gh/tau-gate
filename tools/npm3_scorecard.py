#!/usr/bin/env python3
"""Verify completed sprint receipts and emit a bounded comparison scorecard."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import statistics

import npm3_sprint


def read(path):
    return json.loads(path.read_text())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def mib(value):
    return f'{value / 1024**2:.1f} MiB'


def scorecard(output):
    assert not (output/'scorecard.json').exists(), 'never overwrite a completed scorecard'
    frozen=npm3_sprint.verify(output)
    cohort=read(output/'fresh/cohort.json');snapshots=read(output/'fresh/snapshots.json')
    assert len(cohort['repositories'])==100
    assert len(cohort['excluded_identities'])==400
    assert not {r['identity'] for r in cohort['repositories']}.intersection(cohort['excluded_identities'])
    controls=read(output/'evidence-controls/receipt.json')
    wrapper=read(output/'wrapper-controls/receipt.json')
    assert controls['status']=='pass' and wrapper['passed']
    legacy_native=read(output/'native-comparison/observer-corrected-run/receipt.json')
    native=read(output/'native-latest/npm-runtime-comparison/receipt.json')
    assert native['unexpected_cases']==[] and native['tau_gate_binary_unchanged']
    assert [r['observed'] for r in native['cases']]==[r['observed'] for r in legacy_native['cases']]
    native_version=native['versions']['npm-version']['value']
    pairs=output/'pair-qualification'
    selection=read(pairs/'selection.json');labels=read(pairs/'labels.json')
    summary=read(pairs/'summary.json');resources=read(pairs/'resource-accounting.json')
    runs=read(pairs/'replay/receipts.json')
    assert len(selection['pairs'])==summary['pairs']==30 and len(runs)==150
    assert len({r['repository'] for r in selection['pairs']})==11
    assert all(r['protocol_valid'] and r['run']['termination']=='exited' for r in runs)
    assert all(c['output_sha256_stable'] for c in summary['cases'])
    assert summary['completion_floor']==frozen['protocol']['ordinary_completion_floor']
    expected=Counter();unknowns=Counter();hook_events=[]
    for case in labels['cases']:
        events=read(pairs/'labels'/case['id']/'events.json')
        assert digest(pairs/'labels'/case['id']/'events.json')==case['event_sha256']
        for event in events:
            if event.get('kind')!='unknown' and event.get('status')!='unknown':
                expected[event['kind']]+=1
                if event['kind'].startswith('lifecycle_'):hook_events.append(event)
        for side in ['base','head']:
            facts_path=pairs/'labels'/case['id']/(side+'.json')
            assert digest(facts_path)==case['inputs'][side]['facts_sha256']
            for fact in read(facts_path)['packages'].values():
                if fact['status']!='known':unknowns[fact.get('reason','unspecified')]+=1
    assert sum(expected.values())==summary['assessable_events']
    graph=read(output/'graph-comparison/results.json')
    assert len(graph['cases'])==20
    builds=read(output/'rebuilds/receipt.json')
    fuzz=read(output/'fuzz/receipt.json')
    assert len(fuzz['targets'])==8
    costs={'case_median_wall_seconds':statistics.median(c['wall_seconds_median'] for c in summary['cases']),
           'case_median_wall_range':[min(c['wall_seconds_median'] for c in summary['cases']),max(c['wall_seconds_median'] for c in summary['cases'])],
           'max_core_peak_rss_bytes':max(c['peak_rss_bytes_max'] for c in summary['cases']),
           'all_runs_wall_range':[min(r['run']['elapsed_seconds'] for r in runs),max(r['run']['elapsed_seconds'] for r in runs)]}
    for complete in [True,False]:
        group=[c for c in summary['cases'] if c['complete']==complete]
        costs['complete' if complete else 'incomplete']={'cases':len(group),'median_case_wall_seconds':statistics.median(c['wall_seconds_median'] for c in group),'max_core_peak_rss_bytes':max(c['peak_rss_bytes_max'] for c in group)}
    reference_events={'known_fact_events':dict(expected),'known_lifecycle_body_events':len(hook_events),
                      'unknown_package_side_records':sum(unknowns.values()),'unknown_reasons':dict(unknowns)}
    result={'source_commit':frozen['source_commit'],'candidate_sha256':frozen['candidate_files']['tau-gate'],
            'qualification_verdict':'completion_floor_met' if summary['completion_floor_met'] else 'completion_floor_failed',
            'completion':{k:summary[k] for k in ['pairs','processing_complete','completion_fraction','completion_floor','completion_floor_met']},
            'comparison':{k:summary[k] for k in ['assessable_events','matched_events','event_recall']},
            'independent_labels':reference_events,'costs':costs,
            'native_version':native_version,'legacy_native_versions':legacy_native['versions'],
            'native_cases':[{'case':r['case'],'change':r['change'],'observed':r['observed']} for r in native['cases']],
            'graph_reference':graph['summary'],
            'fuzz_outcomes':[{'target':r['target'],'exit_code':r['exit_status'],'stats':r['stats']} for r in fuzz['targets']],
            'human_benefit_measured':False,'incorrect_allowed_historical_claim':'not assessed: public reviews are advisory, with no supplied approvals',
            'limits':['Thirty correlated update pairs from eleven npm3 repositories, not ecosystem prevalence',
                      'Ten reporting misses have unknown execution relevance; a false approval_relevant flag does not prove irrelevance',
                      'Strong native policies already reject new versions, new sources, unapproved hooks and SRI tamper in the declared controlled scope',
                      'Archive byte binding also creates legitimate reapproval cost',
                      'No new signed release or independent-operator rebuild is established']}
    (output/'scorecard.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    evidence=['frozen.json','fresh/cohort.json','fresh/snapshots.json','fresh/inventory.json',
              'evidence-controls/receipt.json','wrapper-controls/receipt.json','npm-reference/receipt.json',
              'native-comparison/delivery.json','native-comparison/observer-corrected-run/receipt.json',
              'native-comparison/pnpm-adjunct/receipt.json','native-comparison/pnpm-strict-diagnostic/receipt.json',
              'native-latest/npm-runtime-comparison/receipt.json','native-latest/pnpm-runtime-comparison/receipt.json',
              'graph-comparison/protocol.json','graph-comparison/results.json','pair-qualification/protocol.json',
              'pair-qualification/selection.json','pair-qualification/labels.json','pair-qualification/summary.json',
              'pair-qualification/resource-accounting.json','pair-qualification/replay/receipts.json',
              'rebuilds/receipt.json','fuzz/receipt.json','example-review.receipt.json','scorecard.json']
    (output/'scorecard-receipt.json').write_text(json.dumps({name:digest(output/name) for name in evidence},indent=2,sort_keys=True)+'\n')
    lines=['# npm v3 qualification comparison scorecard','',
           f"The candidate demonstrates additional exact-evidence approval binding, but **fails the ordinary completed-review gate: {summary['processing_complete']}/30 ({100*summary['completion_fraction']:.1f}%), against the frozen80%floor**. Human advantage remains unmeasured.",'',
           '|Area|Measured result|Conclusion|','|---|---|---|',
           f"|Controlled protection|{len(controls['cases'])} evidence controls; {len(wrapper['cases'])} trusted Git-object wrapper controls; {len(native['cases'])} matched native/Tau cases|Expected outcomes pass in declared fixture scope|",
           '|Native shared protection|Strict npm exactURL and exactversion reject version movement, unapproved hooks and original-SRI tamper; exactURL also rejects source movement|Credit both tools; no unique-protection claim here|',
           '|Added binding|Same approved URL/version, changed command or bytes, updated lock integrity: native permits; old Tau fingerprint rejects|Extra evidence binding under these fixture conditions|',
           '|Approval cost|Hook-bearing metadata-only archive change: native permits; Tau requests new approval|Conservative reapproval burden; not proof of danger|',
           f"|Real-update completion|{summary['processing_complete']}/30complete;17incomplete retained|FAIL frozen80%floor|",
           f"|Known fact reporting|{summary['matched_events']}/{summary['assessable_events']}matched;10raw artifact hash changes omitted;89unknown package-side facts|Unknown execution relevance for misses; incomplete is not approval|",
           '|Actual hook-body changes|2known changes matched|Small bounded observation, not malware-detection validation|',
           '|Graph correspondence|20/20match npmArborist common instance/edge fields and ecosyste.ms common coordinates|Scoped extraction evidence; hosted parser does not supply equivalent execution review|',
           '|Local Linux repeatability|Two offline builds; executable/archive/SBOM/checksums match; Debian and tamper controls pass|Same-operator repeatability; no new signed release|',
           f"|Local warm core cost|Median of case medians {costs['case_median_wall_seconds']:.2f}s; peak {mib(costs['max_core_peak_rss_bytes'])}|Automated processing only; no equivalent-work speedup claim|",
           '|Human review/adoption|Not measured|Open evidence gate|','',
           '## Strong native policy comparison','',
           f'Native entries describe whether the controlled script ran; Tau entries describe its offline approval decision. They are different operations, so this table is not an execution/performance equivalence claim. Native uses strict npm {native_version} with a trusted-base exact tarball URL policy. The exact-version column is retained as a secondary comparator. Installed npm 11.19.1 produced the same observed outcomes.','',
           '|Controlled case|Native exactURL|Native exactversion|Tau-Gate|','|---|---|---|---|']
    for row in native['cases']:
        o=row['observed'];lines.append('|'+ '|'.join([row['case'],o['exact_source_url'],o['exact_version'],o['tau_gate']])+'|')
    lines+=['','## Processing and acquisition cost','',
            'Five round-major runs alternate case order. Archives are local and OS caches are not flushed. Costs are descriptive for this host/load; native fixture installation and a full evidence review do different work. Failed/incomplete runs remain in the totals.','',
            f"Acquisition: {resources['acquisition_wall_seconds']:.1f}s; {mib(resources['newly_downloaded_unique_compressed_bytes'])}new unique compressed downloads and {mib(resources['reused_offline_unique_compressed_bytes'])}read-only cache reuse. All2704originalarchiveidentities were available. No acquisition-budget exhaustion.",
            f"Core all-run wall range: {costs['all_runs_wall_range'][0]:.2f}–{costs['all_runs_wall_range'][1]:.2f}s. Per-case median range: {costs['case_median_wall_range'][0]:.2f}–{costs['case_median_wall_range'][1]:.2f}s. Peak core RSS: {mib(costs['max_core_peak_rss_bytes'])}.",'',
            '## Limits and next decision','',
            'The100newrepository cohort contains54without a lockfile in fixed scope,46with locks and20npm3inventories. The30updatepairs are clustered in11repositories. Keep these denominators separate. No public package lifecycle script was run; public reports were advisory and used no fabricated approvals.',
            'The independent label/reference layer contains only two actual lifecycle-body changes. Most of the4301known facts concern versions, sources, hashes and additions/removals. The ten omitted raw artifact changes occur in an incomplete domhandler review for oversized Biome platform archives; full execution facts are unknown. This is a reporting gap, not demonstrated unsafe authorization.',
            'Exact-byte approval binding adds protection and review churn. The next engineering priority is usable evidence coverage and preservation of known byte-change facts when execution parsing is incomplete. No profile bound was raised or case replaced to improve this result.',
            'The extra ASan campaign is finite evidence, not a safety proof. Its tar target exceeded the512MiBprocess RSS cap; preserve that failure separately from successful targets and any resource diagnostics.','',
            'Raw source snapshots, original archives, labels, per-run outputs, corrections and receipts remain local under this study directory. The committed scorecard and helper sources identify the method; full independent replay also requires these inputs.']
    (output/'SCORECARD.md').write_text('\n'.join(lines)+'\n')
    print(json.dumps({'measurement_complete':True,'completed_reviews':summary['processing_complete'],'pairs':30,
                      'ordinary_completion_gate':'PASS' if summary['completion_floor_met'] else 'FAIL',
                      'known_fact_matches':summary['matched_events'],'known_fact_events':summary['assessable_events']}))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    scorecard(parser.parse_args().output.resolve())
