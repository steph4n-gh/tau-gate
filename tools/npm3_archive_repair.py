#!/usr/bin/env python3
"""Reuse the frozen 30-pair sprint inputs and audit the archive repair replay."""

import argparse
import collections
import json
from pathlib import Path
import shutil

import npm3_sprint_pairs as pairs
import qualification as q


def prepare(args):
    original, output = args.original.resolve(), args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    for name in ("selection.json", "acquisition.json", "protocol.json"):
        destination = output / name
        if destination.exists():
            raise ValueError(f"already prepared: {destination}")
        shutil.copyfile(original / name, destination)
    (output / "inputs").symlink_to(original / "inputs", target_is_directory=True)
    pairs.frozen(output / "repair-profile.json", {
        "original": str(original), "selection_sha256": q.digest(q.read(output / "selection.json")),
        "acquisition_sha256": q.digest(q.read(output / "acquisition.json")),
        "original_labels_sha256": q.digest(q.read(original / "labels.json")),
        "profile": "128MiB expanded archive; streaming full validation; all other caps unchanged",
        "evaluation": "Known-case repair regression, not a fresh holdout; no reselection or acquisition",
        "measurement": "Five candidate runs per pair; original frozen runs are correctness references, not a paired speed benchmark",
        "paired_cost_case": "r051-cf32167f6bca; five alternating baseline/candidate runs; candidate performs additional formerly rejected work",
    })
    pairs.label(argparse.Namespace(output=output))


def summarize(args):
    original, output = args.original.resolve(), args.output.resolve()
    selection = q.load(output / "selection.json")
    profile = q.load(output / "repair-profile.json")
    assert profile["selection_sha256"] == q.digest(q.read(original / "selection.json"))
    assert profile["acquisition_sha256"] == q.digest(q.read(original / "acquisition.json"))
    assert profile["original_labels_sha256"] == q.digest(q.read(original / "labels.json"))
    labels = {case["id"]: case for case in q.load(output / "labels.json")["cases"]}
    original_labels = {case["id"]: case for case in q.load(original / "labels.json")["cases"]}
    compatibility = collections.Counter()
    old_events, old_matches, old_misses, old_mismatches = 0, 0, 0, 0
    remaining = collections.Counter()
    cases = []
    for pair in selection["pairs"]:
        case = pair["id"]
        facts = pairs.verified_labels(output, pair, labels[case])
        old_facts = pairs.verified_labels(original, pair, original_labels[case])
        for side in ("base", "head"):
            assert labels[case]["inputs"][side]["hashes"] == original_labels[case]["inputs"][side]["hashes"], (case, side)
        before = q.load(original / "replay/round-1" / case / "stdout.bin")
        after = q.load(output / "replay/round-1" / case / "stdout.bin")
        _, score = q.score_case(old_facts, after)
        comparison = score["comparison"]
        old_events += len(comparison["matched"]) + comparison["misses"]
        old_matches += len(comparison["matched"])
        old_misses += comparison["misses"]
        old_mismatches += len(comparison["fact_mismatches"])
        unknowns = []
        for side in ("base", "head"):
            previous = {entry["path"]: entry for entry in before[side]["execution_evidence"]}
            current = {entry["path"]: entry for entry in after[side]["execution_evidence"]}
            assert previous.keys() == current.keys(), (case, side)
            for path, old in previous.items():
                new = current[path]
                if old["state"] == "qualified":
                    for key in ("state", "facts", "approval_fingerprint", "candidate"):
                        assert old[key] == new[key], (case, side, path, key)
                    compatibility["previously_qualified_records_unchanged"] += 1
                if new["state"] == "qualified":
                    assert new["verified_artifact_sha512"] == new["facts"]["artifact_sha512"], (case, side, path)
                    compatibility["qualified_records"] += 1
                else:
                    assert new["facts"] is None and new["approval_fingerprint"] is None
                    remaining[new["reason"]] += 1
                    unknowns.append({"side": side, "path": path, "reason": new["reason"]})
                observation = new["verified_artifact_sha512"]
                if observation is not None:
                    assert observation == facts[side]["packages"][path]["artifact_sha512"], (case, side, path)
                    compatibility["verified_observations_match_independent_bytes"] += 1
        cases.append({"id": case, "repository": pair["repository"], "unknowns": unknowns})
    receipt = {
        "schema_version": 1, "profile": profile, "summary": q.load(output / "summary.json"),
        "original_summary": q.load(original / "summary.json"),
        "original_label_comparison": {"assessable_events": old_events, "matches": old_matches,
                                      "misses": old_misses, "fact_mismatches": old_mismatches},
        "compatibility": dict(compatibility), "remaining_unknown_reasons": dict(remaining), "cases": cases,
    }
    pairs.frozen(output / "repair-comparison.json", receipt)
    print(json.dumps({key: receipt[key] for key in ("original_label_comparison", "compatibility", "remaining_unknown_reasons")}))


def cost(args):
    output = args.output.resolve()
    case = "r051-cf32167f6bca"
    destination = output / "paired-cost"
    destination.mkdir()
    binaries = {"baseline": args.baseline.resolve(), "candidate": args.binary.resolve()}
    hashes = {key: q.digest(q.read(binary)) for key, binary in binaries.items()}
    records = []
    for number in range(1, 6):
        for kind, binary in binaries.items():
            folder = destination / f"round-{number}" / kind
            argv = [str(binary), "review", "--json"]
            for side in ("base", "head"):
                root = output / "inputs" / case / side
                argv.extend(["--" + side, str(root / "project/package-lock.json"), "--" + side + "-manifest", str(root / "project/package.json"), "--" + side + "-evidence", str(root / "evidence/index.json")])
            run = q.run_bounded(argv, folder, 180)
            report = q.load(folder / "stdout.bin")
            assert run["termination"] == "exited" and run["exit_code"] == (2 if report["status"] == "incomplete" else 0)
            reference = (args.original.resolve() if kind == "baseline" else output) / "replay/round-1" / case / "stdout.bin"
            assert run["output_sha256"]["stdout"] == q.digest(q.read(reference))
            records.append({"round": number, "kind": kind, "run": run})
            print(json.dumps({"round": number, "kind": kind, "seconds": run["elapsed_seconds"]}), flush=True)
    assert hashes == {key: q.digest(q.read(binary)) for key, binary in binaries.items()}
    pairs.frozen(destination / "receipt.json", {"case": case, "binary_sha256": hashes, "runs": records,
        "scope": "One known large-archive case; candidate validates additional formerly rejected archives; no global speed claim"})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "summarize", "cost"))
    parser.add_argument("--original", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--binary", type=Path)
    args = parser.parse_args()
    if args.mode == "cost" and (args.baseline is None or args.binary is None):
        parser.error("cost requires --baseline and --binary")
    {"prepare": prepare, "summarize": summarize, "cost": cost}[args.mode](args)


if __name__ == "__main__":
    main()
