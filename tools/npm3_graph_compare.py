#!/usr/bin/env python3
"""Compare frozen npm3 inventories with npm Arborist and ecosyste.ms, without installs."""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import subprocess
import shutil
import time
import urllib.parse
import urllib.request

import npm_repo_experiment as acquisition

def read(path):
    return json.loads(path.read_text())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def remote(url):
    query='https://parser.ecosyste.ms/api/v1/jobs?'+urllib.parse.urlencode({'url':url})
    request=urllib.request.Request(query,data=b'',method='POST',headers={'User-Agent':'tau-gate-qualification/1'})
    started=time.monotonic()
    with urllib.request.urlopen(request,timeout=30) as response:
        value=json.loads(response.read(16*1024*1024));location=response.url
    for _ in range(30):
        if value.get('status') not in ('pending','working','processing'):break
        time.sleep(1)
        with urllib.request.urlopen(location,timeout=30) as response:
            value=json.loads(response.read(16*1024*1024))
    return {'job_url':location,'seconds':time.monotonic()-started,'response':value}


def compare(output, node, npm):
    node=node.resolve();npm=npm.resolve().parent.parent
    folder=output/'graph-comparison';folder.mkdir(exist_ok=True)
    assert not (folder/'results.json').exists(), 'never overwrite completed evidence'
    fresh=output/'fresh';snapshots={s['repository']:s for s in read(fresh/'snapshots.json')['snapshots']}
    cases=[c for c in read(fresh/'inventory.json')['lockfiles'] if c['npm3']]
    candidate=output/'candidate/tau-gate'
    protocol={'candidate_sha256':digest(candidate),'node_sha256':digest(node),
              'npm_version':read(npm/'package.json')['version'],
              'arborist_version':read(npm/'node_modules/@npmcli/arborist/package.json')['version'],
              'files':{name:digest(Path(name)) for name in ['tools/npm3_graph_compare.py','tools/npm3_arborist_reference.cjs']},
              'cases':cases,'scope':'Arborist installed paths, names/versions and resolved dependency edge pairs, excluding workspaceLink structural edges; ecosyste.ms deduplicated nonlocal name/locked-version coordinates only, not graph edges or evidence enforcement',
              'service_version':'hosted version unspecified; retain exact response and input sha256'}
    acquisition.save(folder/'protocol.json',protocol)
    def one(case):
        result={**case};name=case['repository'].replace('/','__')
        target=folder/name;target.mkdir(exist_ok=True)
        lock=fresh/'repositories'/name/'source'/case['lockfile']
        assert digest(lock)==case['sha256']
        source=next(f for f in snapshots[case['repository']]['files'] if f['path']==case['lockfile'])
        try:
            run=subprocess.run([str(node),'tools/npm3_arborist_reference.cjs',str(npm),str(lock.parent)],capture_output=True,text=True,timeout=90)
            (target/'arborist.stdout').write_text(run.stdout);(target/'arborist.stderr').write_text(run.stderr)
            result['arborist_exit']=run.returncode
            if run.returncode==0:reference=json.loads(run.stdout)
            else:reference=None
        except Exception as error:
            reference=None;result['arborist_error']=type(error).__name__+': '+str(error)
        try:
            ecosystem=remote(source['url']);acquisition.save(target/'ecosystems.json',ecosystem)
            response=ecosystem['response']
            result['ecosystems_status']=response.get('status')
            assert response.get('sha256')==case['sha256'], 'remote input bytes differ'
            deps=[d for m in response.get('results',{}).get('manifests',[]) if m['ecosystem']=='npm' for d in m['dependencies'] if not d.get('local')]
            coordinates={(d['name'],d['requirement']) for d in deps}
        except Exception as error:
            coordinates=None;result['ecosystems_error']=type(error).__name__+': '+str(error)
        # All independent references are captured before opening this candidate report.
        command=[str(candidate),'audit','--lock',str(lock),'--json']
        manifest=lock.parent/'package.json'
        if manifest.exists():command+=['--manifest',str(manifest)]
        run=subprocess.run(command,capture_output=True,text=True,timeout=180)
        report=json.loads(run.stdout);acquisition.save(target/'tau-gate.json',report)
        result.update(candidate_exit=run.returncode,topology_status=report.get('topology_status'),
                      parsing_status=report.get('parsing_status'),error=report.get('error'))
        if report.get('packages') is not None:
            packages={p['path']:p for p in report['packages']}
            if reference is not None:
                expected={p['path']:p for p in reference['nodes']}
                result['instance_paths_match']=set(packages)==set(expected)
                errors=[]
                for path in packages.keys()&expected.keys():
                    if path=='' or expected[path]['link']:continue
                    if (packages[path]['name'],packages[path]['version'] or None)!=(expected[path]['name'],expected[path]['version']):errors.append(path)
                result['name_version_mismatches']=errors
                native_edges={(e['from'] or 'root',e['to'] or 'root') for e in reference['edges']}
                actual_edges={(e['from'],e['to']) for e in report['edges'] if e['kinds']!=['workspaceLink']}
                result['resolved_dependency_edges_match']=native_edges==actual_edges
                result['edge_difference']={'tau_only':sorted(actual_edges-native_edges),'arborist_only':sorted(native_edges-actual_edges)}
                result['instances_checked']=len(expected);result['resolved_edge_pairs_checked']=len(native_edges)
            if coordinates is not None:
                records=read(lock)['packages']
                actual={(p['name'],p['version']) for path,p in packages.items() if 'node_modules/' in path and not records[path].get('link') and not records[path].get('resolved','').startswith('file:')}
                result['ecosystems_coordinates_match']=actual==coordinates
                result['coordinate_difference']={'tau_only':sorted(actual-coordinates),'ecosystems_only':sorted(coordinates-actual)}
                result['coordinates_checked']=len(coordinates)
        acquisition.save(target/'receipt.json',result)
        print(json.dumps({'repository':case['repository'],'arborist_paths':result.get('instance_paths_match'),'arborist_edges':result.get('resolved_dependency_edges_match'),'ecosystems_coordinates':result.get('ecosystems_coordinates_match')}),flush=True)
        return result
    with ThreadPoolExecutor(max_workers=4) as pool:results=list(pool.map(one,cases))
    summary={'cases':len(results),'arborist_paths':dict(Counter(str(r.get('instance_paths_match')) for r in results)),
             'arborist_edges':dict(Counter(str(r.get('resolved_dependency_edges_match')) for r in results)),
             'name_version_mismatch_cases':sum(bool(r.get('name_version_mismatches')) for r in results),
             'ecosystems_coordinates':dict(Counter(str(r.get('ecosystems_coordinates_match')) for r in results)),
             'topology_status':dict(Counter(r['topology_status'] for r in results))}
    acquisition.save(folder/'results.json',{'protocol_sha256':digest(folder/'protocol.json'),'summary':summary,'cases':results})
    print(json.dumps(summary),flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--node',type=Path,default=shutil.which('node'))
    parser.add_argument('--npm',type=Path,default=shutil.which('npm'),help='npm CLI path; module root is resolved from its symlink')
    args=parser.parse_args()
    if args.node is None or args.npm is None:parser.error('node and npm paths are required')
    compare(args.output.resolve(),Path(args.node),Path(args.npm))
