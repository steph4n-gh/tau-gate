#!/usr/bin/env python3
"""Render one evidence-bound real update; this does not make an approval decision."""
import argparse
import hashlib
import html
import json
from pathlib import Path


def read(path):
    return json.loads(path.read_text())


def escape(value):
    return html.escape(str(value),quote=True)


def render(root, case_id, package_path, destination):
    assert not destination.exists(), 'never overwrite a recorded case view'
    selection=read(root/'selection.json')
    case=next(c for c in selection['pairs'] if c['id']==case_id)
    report_path=root/'replay/round-1'/case_id/'stdout.bin'
    report=read(report_path)
    event=next(e for e in read(root/'labels'/case_id/'events.json')
               if e['path']==package_path and e['kind']=='lifecycle_changed')
    change=next(c for c in report['execution_evidence_changes'] if c['path']==package_path)
    candidate=next(c for c in report['head']['execution_candidates'] if c['package']['path']==package_path)
    hook=event['after']['event']
    snapshots={side:next(p for p in report[side]['packages'] if p['path']==package_path) for side in ['base','head']}
    for side,label in [('base','before'),('head','after')]:
        assert change[label]['state']=='qualified'
        assert change[label]['facts']['lifecycle'][hook]==hashlib.sha256(event[label]['body'].encode()).hexdigest()
    assert change['before']['approval_fingerprint']!=change['after']['approval_fingerprint']
    edges=candidate['introducer_edges']
    path=candidate['introducer_path']
    assert path==change['after_introducer_path']
    assert [(e['from'],e['to']) for e in edges]==list(zip(path,path[1:]))
    route=''.join('<li><strong>'+escape(e['from'])+'</strong><span>'+escape(', '.join(e['kinds']))+'</span>→ '+escape(e['to'])+'</li>' for e in edges)
    unqualified=sum(item['state']!='qualified' for side in ('base','head')
                    for item in report[side]['execution_evidence'])
    evidence=[]
    for side,label in [('base','before'),('head','after')]:
        facts=change[label]['facts'];package=snapshots[side]
        source=package['source']
        source_html='<a href="'+escape(source)+'">'+escape(source)+'</a>' if source.startswith('https://') else escape(source)
        evidence.append('<section><h3>'+label.title()+' · '+escape(package['version'])+'</h3><dl>'+
            '<dt>Locked artifact</dt><dd>'+source_html+'</dd><dt>Lock integrity</dt><dd><code>'+escape(package['integrity'])+'</code></dd>'+
            '<dt>Verified archive SHA512</dt><dd><code>'+escape(facts['artifact_sha512'])+'</code></dd>'+
            '<dt>Package manifest SHA256</dt><dd><code>'+escape(facts['manifest_sha256'])+'</code></dd>'+
            '<dt>Evidence approval fingerprint</dt><dd><code>'+escape(change[label]['approval_fingerprint'])+'</code></dd></dl></section>')
    document='''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Dependency update evidence review</title><style>
*{box-sizing:border-box}body{margin:0;background:#f3f5f7;color:#172632;font:16px/1.55 system-ui,sans-serif}main{max-width:1020px;margin:36px auto;padding:0 24px 48px}header,panel,article,section{display:block}header{margin-bottom:28px}.eyebrow{font-weight:650;color:#426079;font-size:13px}h1{font-size:32px;line-height:1.2;max-width:850px}h2{font-size:22px}h3{font-size:17px}.card{background:white;border:1px solid #d9e0e5;border-radius:12px;padding:24px;margin:18px 0}.status{display:inline-block;padding:5px 12px;background:#e8f4ed;color:#265a3d;border-radius:20px;font-weight:600}.commands{display:grid;grid-template-columns:1fr 1fr;gap:18px}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f6f8;padding:16px;border-radius:8px;font:14px/1.6 ui-monospace,monospace}li{padding:10px 0;border-bottom:1px solid #edf0f3;overflow-wrap:anywhere}li span{display:block;color:#536778;font-size:13px}code,dd{overflow-wrap:anywhere}dt{font-weight:650;margin-top:16px}dd{margin:5px 0;color:#435667;font-size:13px}a{color:#155e98}small{color:#526575}details{margin-top:16px}summary{cursor:pointer;font-weight:650}@media(max-width:700px){.commands{grid-template-columns:1fr}h1{font-size:26px}main{padding:0 16px}}
</style><main>'''
    status='Evidence complete for this pair' if report['status']=='complete' else 'Review incomplete; inspect the unknowns'
    document+='<header><div class="eyebrow">TAU-GATE · REAL UPDATE · READ-ONLY EVIDENCE</div><h1>'+escape(snapshots['head']['name'])+' changes its '+escape(hook)+' command in this project</h1><p>'+escape(case['repository'])+' · <a href="'+escape(case['commit_url'])+'">Inspect the source commit</a></p><span class="status">'+status+'</span></header>'
    document+='<article class="card"><h2>What changed</h2><p>The locked package changes from <strong>'+escape(snapshots['base']['version'])+'</strong> to <strong>'+escape(snapshots['head']['version'])+'</strong>. Its '+escape(hook)+' command also changes.</p><div class="commands"><div><h3>Before</h3><pre>'+escape(event['before']['body'])+'</pre></div><div><h3>After</h3><pre>'+escape(event['after']['body'])+'</pre></div></div><p>This change enters through the proposed update. No package script was executed, and this observation does not establish malicious behavior.</p></article>'
    document+='<article class="card"><h2>How it reaches this project</h2><p>Each step below comes from the locked dependency graph.</p><ol>'+route+'</ol></article>'
    document+='<article class="card"><h2>What needs review</h2><p>Both shown archives match their lockfile integrity, and the command hashes match the independently read package manifests. The new exact-evidence fingerprint differs from the old one.</p><p>A workflow enforcing Tau-Gate approvals would require a matching approval for this new evidence. This public-project replay is advisory: it supplied no trusted approvals and grants no permission.</p><p>The verified before/after command, project-specific path, and exact evidence support review. Native package-manager approval behavior is a separate comparison.</p><details><summary>Inspect artifact and fingerprint evidence</summary>'+''.join(evidence)+'</details></article>'
    if unqualified:
        document+='<article class="card"><h2>What remains unknown</h2><p>'+escape(unqualified)+' package-side evidence records in this pair remain unqualified. This example explains the verified change above; the full project review is incomplete.</p></article>'
    document+='<article class="card"><h2>Scope of this example</h2><p>This view highlights one real command change from the frozen 30-pair qualification cohort. It does not measure human review speed or establish a safe update. The source files came from pinned GitHub commit URLs; archive verification binds package bytes to the supplied lockfile.</p><small>Source report SHA256: '+hashlib.sha256(report_path.read_bytes()).hexdigest()+'<br>Case: '+escape(case_id)+' · Package instance: '+escape(package_path)+'</small></article></main></html>'
    destination.write_text(document)
    return {'case':case_id,'package':package_path,'status':report['status'],'policy':report['policy']['outcome'],
            'source_report_sha256':hashlib.sha256(report_path.read_bytes()).hexdigest(),
            'html_sha256':hashlib.sha256(destination.read_bytes()).hexdigest()}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--case',required=True)
    parser.add_argument('--package',required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    result=render(args.root,args.case,args.package,args.output)
    args.output.with_suffix('.receipt.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result))
