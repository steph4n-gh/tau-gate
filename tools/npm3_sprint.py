#!/usr/bin/env python3
"""Freeze and acquire a repo-disjoint npm qualification cohort without installs."""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import re
import urllib.parse

import npm_repo_experiment as acquisition


def read(path):
    return json.loads(path.read_text())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def identity(resolution):
    return resolution.get('repository', urllib.parse.urlparse(resolution['input_url']).path.strip('/').removesuffix('.git')).lower()


def verify(output):
    frozen=read(output/'frozen.json')
    for path,expected in frozen['source_files'].items():
        assert digest(Path(path))==expected,path
    for name,expected in frozen['candidate_files'].items():
        assert digest(output/'candidate'/name)==expected,name
    return frozen


def select(output):
    frozen=verify(output)
    old=Path(frozen['protocol']['original_corpus'])
    previous=Path(frozen['protocol']['previous_fresh_corpus'])
    first=read(old/'cohort.json')
    second=read(previous/'cohort.json')
    assert digest(old/'critical-source.json')==first['source_sha256']==second['source_sha256']
    excluded={identity(r['resolution']) for r in first['repositories']}
    excluded.update(r['identity'] for r in second['repositories'])
    assert len(excluded)==400
    packages=sorted((p for p in read(old/'critical-source.json')['projects'] if p['ecosystem']=='npm'),key=lambda p:(p['rankings_average'],p['name']))
    seen_urls=set();ranked=[]
    for rank,package in enumerate(packages,1):
        url=package.get('repository_url','')
        if re.fullmatch(r'https://github.com/[\w.-]+/[\w.-]+(?:\.git)?/?',url) and url not in seen_urls:
            seen_urls.add(url);ranked.append((rank,package))
    folder=output/'fresh';folder.mkdir(exist_ok=True)
    cache=read(previous/'resolution-cache.json')
    cache.update(read(folder/'resolution-cache.json') if (folder/'resolution-cache.json').exists() else {})
    seen=set(excluded);selected=[]
    for start in range(0,len(ranked),32):
        batch=ranked[start:start+32]
        needed=[p['repository_url'] for _,p in batch if p['repository_url'] not in cache]
        with ThreadPoolExecutor(max_workers=6) as pool:
            for item in pool.map(acquisition.resolve,needed):cache[item['input_url']]=item
        acquisition.save(folder/'resolution-cache.json',cache)
        for rank,package in batch:
            resolved=cache[package['repository_url']]
            key=identity(resolved)
            if key in seen:continue
            seen.add(key)
            resolved={**resolved,'repository':resolved.get('repository',key)}
            selected.append({'rank':len(selected)+1,'package_rank':rank,'package':package['name'],
                             'identity':key,'resolution':resolved})
            if len(selected)==frozen['protocol']['repository_count']:break
        if len(selected)==frozen['protocol']['repository_count']:break
    assert len(selected)==frozen['protocol']['repository_count']
    assert not {r['identity'] for r in selected}.intersection(excluded)
    acquisition.save(folder/'cohort.json',{'repositories':selected,'excluded_identities':sorted(excluded),
        'source_url':first['source_url'],'source_sha256':first['source_sha256'],
        'freeze_sha256':digest(output/'frozen.json')})
    print(json.dumps({'selected':len(selected),'old_repository_overlap':0,'last_package_rank':selected[-1]['package_rank']}),flush=True)


def capture(output):
    verify(output)
    folder=output/'fresh';cohort=read(folder/'cohort.json')
    def one(item):
        if item['resolution']['status']!='resolved':
            return {**item['resolution'],'status':'capture_unavailable'}
        return acquisition.capture(item['resolution'],folder)
    with ThreadPoolExecutor(max_workers=6) as pool:
        snapshots=list(pool.map(one,cohort['repositories']))
    inventories=[]
    for item in snapshots:
        if item['status']!='captured':continue
        for lock in item['lockfiles']:
            path=folder/'repositories'/item['repository'].replace('/','__')/'source'/lock
            try:
                value=read(path);version=value.get('lockfileVersion')
            except (ValueError,UnicodeError,AttributeError):version=None
            inventories.append({'repository':item['repository'],'lockfile':lock,'sha256':digest(path),
                                'lockfile_version':version,'npm3':Path(lock).name in ('package-lock.json','npm-shrinkwrap.json') and version==3})
    acquisition.save(folder/'snapshots.json',{'snapshots':snapshots,'status_counts':dict(Counter(s['status'] for s in snapshots))})
    acquisition.save(folder/'inventory.json',{'lockfiles':inventories,'npm3_lockfiles':sum(c['npm3'] for c in inventories)})
    print(json.dumps({'repositories':len(snapshots),'status_counts':dict(Counter(s['status'] for s in snapshots)),
                      'lockfiles':len(inventories),'npm3_lockfiles':sum(c['npm3'] for c in inventories)}),flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',choices=['select','capture'])
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args();output=args.output.resolve()
    target=output/'fresh'/('cohort.json' if args.mode=='select' else 'snapshots.json')
    assert not target.exists(), 'never overwrite a completed experiment'
    (select if args.mode=='select' else capture)(output)
