#!/usr/bin/env python3
"""Behavioral controls for frozen historical pair selection and replay."""
import argparse
import contextlib
import io
import json
from pathlib import Path
import shutil
import threading
from types import SimpleNamespace
from unittest.mock import patch

import npm3_sprint_pairs as sprint
import qualification as q
from verify_npm_evidence import encoded, sri, tar_for, zipped


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists():
        raise ValueError("control output must be new")
    output.mkdir(parents=True)
    roots = {"base": {"name": "control", "version": "1.0.0", "scripts": {"postinstall": "echo never-execute-before"}},
             "head": {"name": "control", "version": "1.0.0", "scripts": {"postinstall": "echo never-execute-after"}}}
    blob = zipped(tar_for({"name": "pkg", "version": "1.0.0", "scripts": {"install": "echo never-execute-dependency"}}))
    lock = {"lockfileVersion": 3, "packages": {"": {"name": "control", "version": "1.0.0"},
            "node_modules/pkg": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz", "integrity": sri(blob)}}}
    commits = [str(n) * 40 for n in range(1, 9)]
    histories = {"a/one": [(commits[0], commits[1]), (commits[2], commits[3]), (commits[4], commits[5])],
                 "b/two": [(commits[6], commits[7])]}
    raw = {}
    for repo, changes in histories.items():
        for number, (head, base) in enumerate(changes):
            for side, commit in (("base", base), ("head", head)):
                value = dict(lock)
                value["control_revision"] = commit
                raw[q.raw_url(repo, commit, "nested/package-lock.json")] = encoded(value)
                raw[q.raw_url(repo, commit, "nested/package.json")] = encoded(roots[side])
                raw[q.raw_url(repo, commit, "nested/binding.gyp")] = None
    raw[q.raw_url("a/one", commits[1], "nested/package-lock.json")] = encoded({"lockfileVersion": 2, "packages": {"": {}}})
    raw[q.raw_url("a/one", commits[3], "nested/package-lock.json")] = None
    cohort = {"repositories": [{"repository_rank": i, "resolution": {"repository": repo, "host": "github.com"}} for i, repo in enumerate(histories, 1)]}
    snapshots = [{"repository": repo, "commit": commits[0], "lockfiles": ["nested/package-lock.json"]} for repo in histories]
    q.save(output / "cohort.json", cohort)
    q.save(output / "snapshots.json", snapshots)
    def github(route):
        repo = route.split("/commits?")[0][6:]
        return [{"sha": head, "parents": [{"sha": base}], "html_url": "https://github.com/" + repo + "/commit/" + head,
                 "commit": {"committer": {"date": f"2026-11-{9-number:02d}T00:00:00Z"}}} for number, (head, base) in enumerate(histories[repo])]
    case_output = output / "study"
    with patch.object(sprint.npm_repo_experiment, "gh", github), patch.object(q, "raw_source", lambda url: raw[url]), contextlib.redirect_stdout(io.StringIO()):
        sprint.freeze(SimpleNamespace(output=case_output, cohort=output / "cohort.json", snapshots=output / "snapshots.json", count=2))
        selection = q.load(case_output / "selection.json")
        assert [a["status"] for a in selection["attempts"]] == ["non3", "input_unavailable_or_invalid", "npm3_eligible", "npm3_eligible"]
        assert len(selection["pairs"]) == 2
        assert not (case_output / "replay").exists()
        cache = output / "cache"
        cache.mkdir()
        (cache / (q.digest(blob, "sha512") + ".tgz")).write_bytes(blob)
        sprint.acquire(SimpleNamespace(output=case_output, offline_cache=cache))
        sprint.label(SimpleNamespace(output=case_output))
    labels = q.load(case_output / "labels.json")
    assert all(row["status"] == "complete" for row in labels["cases"])
    assert any(event["kind"] == "lifecycle_changed" for event in q.load(case_output / "labels" / selection["pairs"][0]["id"] / "events.json"))
    with contextlib.redirect_stdout(io.StringIO()):
        sprint.validate(SimpleNamespace(output=case_output, timeout=180))
        sprint.replay(SimpleNamespace(output=case_output, binary=args.binary, rounds=5, timeout=180))
        sprint.resources(SimpleNamespace(output=case_output))
    summary = q.load(case_output / "summary.json")
    assert summary["processing_complete"] == 2, summary
    assert summary["matched_events"] == summary["assessable_events"]
    assert summary["unexpected_allowed_outcomes"] == 0
    assert all(row["output_sha256_stable"] for row in summary["cases"])
    resource = q.load(case_output / "resource-accounting.json")
    assert resource["newly_downloaded_unique_compressed_bytes"] == 0
    assert resource["reused_offline_unique_compressed_bytes"] == len(blob)
    assert resource["other_or_failed_charged_archive_bytes"] == 0
    assert "Real historical changed-hook case" in (case_output / "report.html").read_text()
    parallel = output / "parallel-study"
    parallel.mkdir()
    for name in ("selection.json", "acquisition.json", "protocol.json", "labels.json"):
        shutil.copyfile(case_output / name, parallel / name)
    shutil.copytree(case_output / "labels", parallel / "labels")
    (parallel / "inputs").symlink_to(case_output / "inputs", target_is_directory=True)
    simultaneous = threading.Barrier(2, timeout=5)
    original_run = q.run_bounded

    def simultaneous_run(*args):
        simultaneous.wait()
        return original_run(*args)

    with patch.object(q, "run_bounded", simultaneous_run), contextlib.redirect_stdout(io.StringIO()):
        sprint.replay(SimpleNamespace(output=parallel, binary=args.binary, rounds=2, timeout=180, jobs=2))
    assert q.load(parallel / "replay/plan.json")["jobs"] == 2
    assert q.load(parallel / "summary.json")["processing_complete"] == 2
    for case in selection["pairs"]:
        serial_hash = q.digest(q.read(case_output / "replay/round-1" / case["id"] / "stdout.bin"))
        for round_number in (1, 2):
            assert serial_hash == q.digest(q.read(parallel / f"replay/round-{round_number}" / case["id"] / "stdout.bin"))
    first = selection["pairs"][0]
    index_path = case_output / "inputs" / first["id"] / "base/evidence/index.json"
    index = q.load(index_path)
    index["packages"] = [row for row in index["packages"] if row["path"] != "node_modules/pkg"]
    q.save(output / "partial-index.json", index)
    for item in index["packages"]:
        if "project_manifest" in item:
            source = index_path.parent / item["project_manifest"]
            target = output / item["project_manifest"]
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read_bytes())
    facts = sprint.oracle.snapshot_facts(case_output / "inputs" / first["id"] / "base/project/package-lock.json", output / "partial-index.json")
    assert facts["status"] == "partial"
    assert facts["packages"]["node_modules/pkg"]["status"] == "unknown"
    assert "scripts" not in facts["packages"]["node_modules/pkg"]
    changed = case_output / "inputs" / first["id"] / "base/project/package.json"
    changed.write_bytes(changed.read_bytes() + b" ")
    try:
        sprint.verified_labels(case_output, first, labels["cases"][0])
    except ValueError:
        pass
    else:
        raise AssertionError("changed source accepted after independent labels")
    q.save(output / "controls.json", {"status": "passed", "scope": "controlled synthetic histories and archives; no dependency code executed", "controls": ["non3 and missing attempts retained", "two both-sides npm3 pairs selected", "nested project scope", "independent changed-hook label", "five interleaved real core runs", "parallel output matches serial", "assessable event recall", "unknown archive is not clean", "source mutation rejected", "standalone report"]})
    print(json.dumps(q.load(output / "controls.json"), sort_keys=True))


if __name__ == "__main__":
    main()
