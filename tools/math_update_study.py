#!/usr/bin/env python3
"""Acquire historical lock changes from the frozen cohort without executing projects."""
import argparse
import collections
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import urllib.error
import urllib.parse
import urllib.request

from math_corpus import Native, save
import npm_evidence


def sha(data):
    return hashlib.sha256(data).hexdigest()


def gh(route):
    result = subprocess.run(["gh", "api", route], capture_output=True, text=True, timeout=60)
    if result.returncode:
        raise ValueError(result.stderr[:500])
    return json.loads(result.stdout)


def fetch(repo, commit, path):
    url = f"https://raw.githubusercontent.com/{repo}/{commit}/" + urllib.parse.quote(path)
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            raw = response.read(32 * 1024 * 1024 + 1)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise
    if len(raw) > 32 * 1024 * 1024:
        raise ValueError("source exceeds 32 MiB")
    return raw


def capture(case, output, binary):
    folder = output / "updates" / case["id"]
    receipt = folder / "receipt.json"
    if receipt.exists():
        return json.loads(receipt.read_text())
    folder.mkdir(parents=True, exist_ok=True)
    item = {k: case[k] for k in ("id", "repository", "lockfile", "split")}
    try:
        graph = json.loads((output / "graphs" / (case["id"] + ".json")).read_text())
        repo = case["repository"]
        query = urllib.parse.urlencode({"sha": graph["commit"], "path": case["lockfile"], "per_page": 1})
        commits = gh(f"repos/{repo}/commits?{query}")
        save(folder / "commit-discovery.json", commits)
        if not commits or not commits[0]["parents"]:
            raise ValueError("no earlier parent snapshot for latest lock-changing commit")
        change = commits[0]
        item.update(head=change["sha"], base=change["parents"][0]["sha"],
                    commit_url=change["html_url"], message=change["commit"]["message"],
                    frozen_cohort_head=graph["commit"], files=[])
        for side in ("base", "head"):
            relative_manifest = str(PurePosixPath(case["lockfile"]).parent / "package.json")
            for path in (case["lockfile"], relative_manifest):
                raw = fetch(repo, item[side], path)
                if raw is None:
                    item["files"].append({"side": side, "path": path, "status": "missing"})
                    continue
                destination = folder / side / PurePosixPath(path).name
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(raw)
                item["files"].append({"side": side, "path": path, "sha256": sha(raw), "bytes": len(raw)})
            lock = folder / side / PurePosixPath(case["lockfile"]).name
            manifest = folder / side / "package.json"
            if not lock.exists():
                raise ValueError(f"{side} lockfile missing")
            command = [str(binary), "audit", "--lock", str(lock), "--json"]
            if manifest.exists():
                command += ["--manifest", str(manifest)]
            proc = subprocess.run(command, cwd=output, capture_output=True, text=True, timeout=180)
            report = json.loads(proc.stdout)
            save(folder / (side + "-report.json"), report)
            item[side + "_report"] = {"exit_code": proc.returncode, "command": command,
                                       "status": report.get("status"), "error": report.get("error"),
                                       "topology_status": report.get("topology_status"),
                                       "packages": len(report.get("packages", []))}
        item["status"] = "complete_graph_pair" if all(item[s + "_report"]["topology_status"] == "complete"
                                                        for s in ("base", "head")) else "incomplete_graph_pair"
    except Exception as error:
        item.update(status="acquisition_or_input_failure", error=str(error))
    save(receipt, item)
    return item


def collect(output, binary):
    index = json.loads((output / "graphs.json").read_text())
    cases = [c for c in index["cases"] if c["topology_complete"]]
    items = []
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(capture, case, output, binary.resolve()) for case in cases]
        for future in as_completed(futures):
            item = future.result()
            items.append(item)
            print(json.dumps({"collected": len(items), "repository": item["repository"], "status": item["status"]}), flush=True)
    items.sort(key=lambda item: (item["repository"], item["lockfile"]))
    save(output / "updates.json", {"scope": "latest lock-changing commit at or before each frozen eligible head, versus first parent",
                                    "eligible_graph_snapshots": len(cases), "cohort_projects": 200,
                                    "binary_sha256": sha(binary.read_bytes()), "pairs": items})


def graph_from_report(report):
    nodes = sorted("root" if p["path"] == "" else p["path"] for p in report["packages"])
    positions = {name: i for i, name in enumerate(nodes)}
    return {"nodes": nodes, "edges": [[positions[e["from"]], positions[e["to"]]] for e in report["edges"]]}


def metadata_labels(folder, lock_name, output, cache):
    manifests = {}
    for side in ("base", "head"):
        path = folder / side / "package.json"
        if not path.exists():
            return {"available": False, "reason": "root manifest missing"}
        manifests[side] = json.loads(path.read_bytes())
    events = ("preinstall", "install", "postinstall", "prepublish", "preprepare", "prepare", "postprepare")
    root_changes = {name: {side: manifests[side].get("scripts", {}).get(name) for side in ("base", "head")}
                    for name in events if manifests["base"].get("scripts", {}).get(name)
                    != manifests["head"].get("scripts", {}).get(name)}
    if not lock_name.endswith(".json"):
        return {"available": False, "root_lifecycle_changes": root_changes,
                "reason": "independent transitive labels limited to npm v3 JSON"}
    locks = {side: json.loads((folder / side / lock_name).read_bytes()) for side in ("base", "head")}
    if any(lock.get("lockfileVersion") != 3 for lock in locks.values()):
        return {"available": False, "reason": "independent transitive labels require npm v3"}
    before, after = locks["base"]["packages"], locks["head"]["packages"]
    marker_added = [path for path, value in after.items() if value.get("hasInstallScript") is True
                    and before.get(path, {}).get("hasInstallScript") is not True]
    marked_changed = []
    verified = []
    unknown = []
    for path, record in after.items():
        if not npm_evidence.is_registry_path(path) or record.get("hasInstallScript") is not True:
            continue
        if not any(before.get(path, {}).get(key) != record.get(key)
                   for key in ("name", "version", "resolved", "integrity", "hasInstallScript")):
            continue
        marked_changed.append(path)
        key = (record.get("resolved", ""), record.get("integrity", ""))
        try:
            if key in cache:
                source = cache[key]
                archive = source.read_bytes()
            else:
                archive = npm_evidence.fetch_archive(key[0])
                source = output / "update-archives" / (sha(archive) + ".tgz")
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_bytes(archive)
                cache[key] = source
            data, manifest, binding, _ = npm_evidence.archive_facts(archive, key[1])
            npm_evidence.check_identity(path, record, manifest)
            scripts = manifest.get("scripts", {})
            hooks = {event: scripts[event] for event in npm_evidence.DEPENDENCY_EVENTS if scripts.get(event)}
            implicit = bool(binding and manifest.get("gypfile") is not False
                            and not scripts.get("preinstall") and not scripts.get("install"))
            dest = output / "update-archives" / (sha(archive) + ".tgz")
            dest.parent.mkdir(parents=True, exist_ok=True)
            if not dest.exists():
                shutil.copyfile(source, dest)
            verified.append({"path": path, "name": manifest["name"], "version": manifest["version"],
                             "candidate": bool(hooks or implicit), "lifecycle": hooks, "implicit_node_gyp": implicit,
                             "source": key[0], "integrity": key[1], "archive_sha256": sha(archive),
                             "manifest_sha256": sha(data), "archive": str(dest.relative_to(output))})
        except Exception as error:
            unknown.append({"path": path, "error": str(error)})
    same_version = []
    for path in before.keys() & after.keys():
        a, b = before[path], after[path]
        if (a.get("name"), a.get("version")) == (b.get("name"), b.get("version")) and any(
                a.get(key) != b.get(key) for key in ("resolved", "integrity")):
            same_version.append(path)
    return {"available": not unknown, "scope": "changed marker-positive candidates verified against original archives; root lifecycle bodies and same-version locator metadata; no harmfulness labels",
            "root_lifecycle_changes": root_changes, "positive_install_marker_added": sorted(marker_added),
            "changed_positive_marker_instances": sorted(marked_changed),
            "verified_marked_archives": verified, "unknown_marked_archives": unknown,
            "same_version_locator_changed": sorted(same_version),
            "positive": bool(root_changes or any(r["candidate"] for r in verified) or same_version)}


def analyze(output, library):
    index = json.loads((output / "updates.json").read_text())
    solver = Native(library)
    corpus = Path(json.loads((output / "graphs.json").read_text())["corpus"])
    marked = json.loads((corpus / "marked-artifacts.json").read_text())["records"]
    cache = {(r["source"], r["integrity"]): corpus / r["archive"]
             for r in marked if r["status"] == "sri_verified_and_inspected"}
    results = []
    for item in index["pairs"]:
        if item["status"] != "complete_graph_pair":
            continue
        folder = output / "updates" / item["id"]
        for file in item["files"]:
            if file.get("sha256"):
                path = folder / file["side"] / PurePosixPath(file["path"]).name
                assert sha(path.read_bytes()) == file["sha256"]
        reports = {side: json.loads((folder / (side + "-report.json")).read_text()) for side in ("base", "head")}
        numerical = {side: solver.run(graph_from_report(reports[side])) for side in ("base", "head")}
        labels = metadata_labels(folder, PurePosixPath(item["lockfile"]).name, output, cache)
        inspected = labels.get("verified_marked_archives", [])
        evidence_report = None
        if inspected:
            lock = folder / "head" / PurePosixPath(item["lockfile"]).name
            index_path = output / ("update-evidence-index-" + item["id"] + ".json")
            save(index_path, {"schema_version": 1, "lock_sha256": sha(lock.read_bytes()),
                              "packages": [{"path": r["path"], "artifact": r["archive"]} for r in inspected]})
            executable = library.resolve().with_name("tau-gate")
            command = [str(executable), "audit", "--lock", str(lock), "--manifest", str(lock.parent / "package.json"),
                       "--evidence", str(index_path), "--json"]
            proc = subprocess.run(command, cwd=output, capture_output=True, text=True, timeout=180)
            derived = json.loads(proc.stdout)
            assert proc.returncode == 2 and derived["status"] == "incomplete"
            evidence_path = folder / "targeted-head-evidence.json"
            save(evidence_path, derived)
            evidence_report = str(evidence_path.relative_to(output))
            facts = {e["path"]: e for e in derived["execution_evidence"]}
            for record in inspected:
                evidence = facts[record["path"]]
                assert evidence["state"] == "qualified" and evidence["candidate"] == record["candidate"]
                assert evidence["facts"]["manifest_sha256"] == record["manifest_sha256"]
                assert evidence["facts"]["lifecycle"] == {k: sha(v.encode()) for k, v in record["lifecycle"].items()}
                record["approval_fingerprint"] = evidence["approval_fingerprint"]
        packages = {side: {p["path"]: p for p in reports[side]["packages"]} for side in ("base", "head")}
        changed = [path for path in packages["base"].keys() | packages["head"].keys()
                   if packages["base"].get(path) != packages["head"].get(path)]
        edges = {side: {json.dumps(e, sort_keys=True) for e in reports[side]["edges"]} for side in ("base", "head")}
        edge_changes = len(edges["base"] ^ edges["head"])
        valid = all(r.get("converged") is True for r in numerical.values())
        a, b = numerical["base"].get("score"), numerical["head"].get("score")
        delta = abs(a - b) if valid else None
        math_signal = delta > 1e-8 + 1e-6 * max(abs(a), abs(b)) if valid else None
        basic_signal = bool(changed or edge_changes or labels.get("root_lifecycle_changes"))
        basic_review_signal = bool(labels.get("root_lifecycle_changes")
                                   or labels.get("changed_positive_marker_instances")
                                   or labels.get("same_version_locator_changed"))
        result = {"id": item["id"], "repository": item["repository"], "split": item["split"],
                  "commit_url": item["commit_url"], "base": item["base"], "head": item["head"],
                  "message": item["message"], "labels": labels,
                  "changed_package_records": len(changed), "changed_edges": edge_changes,
                  "basic_change_signal": basic_signal, "math_change_signal": math_signal,
                  "basic_review_signal": basic_review_signal,
                  "math": numerical, "absolute_score_change": delta}
        result["targeted_evidence_report"] = evidence_report
        results.append(result)
        print(json.dumps({"repository": item["repository"], "basic_signal": basic_signal,
                          "math_signal": math_signal, "metadata_positive": labels.get("positive")}), flush=True)
    summary = {"cohort_projects": 200, "historical_pairs_attempted": len(index["pairs"]),
               "complete_graph_pairs": len(results),
               "acquisition_outcomes": dict(collections.Counter(p["status"] for p in index["pairs"]))}
    for split in ("development", "holdout"):
        selected = [r for r in results if r["split"] == split]
        labelled = [r for r in selected if r["labels"]["available"]]
        summary[split] = {"complete_graph_pairs": len(selected), "independently_labelled_npm_pairs": len(labelled),
                          "metadata_positive": sum(r["labels"]["positive"] for r in labelled),
                          "math_unavailable": sum(r["math_change_signal"] is None for r in selected)}
        for method in ("basic_review_signal", "math_change_signal"):
            outcomes = collections.Counter()
            for result in labelled:
                signal = result[method]
                if signal is None:
                    outcomes["unavailable"] += 1
                else:
                    truth = result["labels"]["positive"]
                    outcomes[("true_" if signal == truth else "false_") + ("positive" if signal else "negative")] += 1
            summary[split][method] = dict(outcomes)
    save(output / "update-value.json", {"candidate_library_sha256": solver.sha256,
                                        "candidate_binary_sha256": sha(library.resolve().with_name("tau-gate").read_bytes()), "summary": summary,
                                        "limits": ["Labels describe independently observed npm metadata, not actual installation impact or maliciousness",
                                                   "The scoped target was corrected after an initial zero-positive metadata check to include changed versions of already-marked artifacts, consistent with evidence-bound approvals; value results are exploratory",
                                                   "Basic snapshot comparisons directly observe the metadata used to select artifact checks; this is an explanatory capability check, not a predictive security benchmark",
                                                   "A changed connectivity estimate is structural context; an unchanged estimate does not approve a dependency change"],
                                        "pairs": results})
    print(json.dumps(summary, indent=2), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("collect", "analyze"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--library", type=Path)
    args = parser.parse_args()
    if args.mode == "collect":
        collect(args.output.resolve(), args.binary)
    else:
        analyze(args.output.resolve(), args.library)


if __name__ == "__main__":
    main()
