#!/usr/bin/env python3
"""Assemble and audit the frozen third npm v3 cohort without rescoring it."""

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import statistics


def load(path):
    return json.loads(path.read_bytes())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(output):
    pair = output / "pair-qualification"
    frozen = load(output / "frozen.json")
    selection = load(pair / "selection.json")
    labels = load(pair / "labels.json")
    summary = load(pair / "summary.json")
    acquisition = load(pair / "acquisition.json")
    resources = load(pair / "resource-accounting.json")
    runs = load(pair / "replay/receipts.json")
    graph = load(output / "graph-comparison/results.json")
    controls = load(output / "control-reuse.json")
    collector = load(pair / "collector-validation/receipts.json")

    assert all(digest(Path(path)) == expected for path, expected in frozen["source_files"].items())
    assert digest(output / "candidate/tau-gate") == frozen["candidate_files"]["tau-gate"]
    assert digest(pair / "protocol.json") == frozen["pair_protocol_sha256"] == selection["protocol_sha256"]
    assert digest(pair / "selection.json") == labels["selection_sha256"] == acquisition["selection_sha256"]
    assert digest(pair / "acquisition.json") == labels["acquisition_sha256"] == resources["acquisition_sha256"]
    assert digest(pair / "labels.json") == summary["labels_sha256"]
    assert len(selection["pairs"]) == summary["pairs"] == 30 and len(runs) == 150
    assert summary["completion_floor"] == frozen["protocol"]["ordinary_completion_floor"]
    assert summary["unexpected_allowed_outcomes"] == 0
    assert all(case["output_sha256_stable"] for case in summary["cases"])

    outputs = defaultdict(set)
    for item in runs:
        folder = pair / "replay" / f"round-{item['round']}" / item["id"]
        assert item["protocol_valid"] and not item["unexpected_allowed_outcome"]
        for stream in ("stdout", "stderr"):
            assert digest(folder / f"{stream}.bin") == item["run"]["output_sha256"][stream]
        assert digest(folder / "process-metrics.txt") == item["run"]["metrics_sha256"]
        outputs[item["id"]].add(item["run"]["output_sha256"]["stdout"])
    assert len(outputs) == 30 and all(len(value) == 1 for value in outputs.values())

    label_unknown = Counter()
    event_kinds = Counter()
    for case in labels["cases"]:
        folder = pair / "labels" / case["id"]
        assert digest(folder / "events.json") == case["event_sha256"]
        for side in ("base", "head"):
            assert digest(folder / f"{side}.json") == case["inputs"][side]["facts_sha256"]
            for fact in load(folder / f"{side}.json")["packages"].values():
                if fact["status"] != "known":
                    label_unknown[fact.get("reason", "unspecified")] += 1
        for event in load(folder / "events.json"):
            if event.get("kind") != "unknown" and event.get("status") != "unknown":
                event_kinds[event["kind"]] += 1
    assert sum(event_kinds.values()) == summary["assessable_events"]

    assert len(collector["snapshots"]) == 60
    assert len(graph["cases"]) == load(output / "fresh/inventory.json")["npm3_lockfiles"]
    assert controls["candidate_binary_sha256"] == frozen["candidate_files"]["tau-gate"]
    for control in controls["controls"].values():
        assert digest(Path(control["source_receipt"])) == control["receipt_sha256"]
        assert control["passed"]

    missed = []
    for item in runs:
        if item["round"] == 1 and item["comparison"]["misses"]:
            missed.append({"id": item["id"], "events": item["comparison"]["missed"]})
    assert sum(len(item["events"]) for item in missed) == summary["assessable_events"] - summary["matched_events"]
    assert all(not case["fact_mismatches"] for case in summary["cases"])

    result = {
        "schema_version": 1,
        "scope": "Third disjoint cohort, frozen candidate and protocol before outcomes; public advisory reviews",
        "frozen_sha256": digest(output / "frozen.json"),
        "candidate_sha256": frozen["candidate_files"]["tau-gate"],
        "assembly_script_sha256": digest(Path(__file__)),
        "cohort": {
            "repositories": len(load(output / "fresh/cohort.json")["repositories"]),
            "previous_identities_excluded": len(load(output / "fresh/cohort.json")["excluded_identities"]),
            "snapshot_statuses": load(output / "fresh/snapshots.json")["status_counts"],
            "npm3_lockfiles": len(graph["cases"]),
            "pairs": len(selection["pairs"]),
            "pair_repositories": selection["projectCount"],
            "attempt_statuses": summary["attempt_statuses"],
        },
        "qualification": {key: summary[key] for key in (
            "pairs", "processing_complete", "independent_labels_complete", "completion_fraction",
            "completion_floor", "completion_floor_met", "assessable_events", "matched_events",
            "event_recall", "unknown_packages_by_side", "unexpected_allowed_outcomes")},
        "label_unknown_reasons": dict(label_unknown),
        "independent_event_kinds": dict(event_kinds),
        "missed_events": missed,
        "cases": [{key: case[key] for key in (
            "id", "repository", "complete", "assessable_events", "event_matches", "event_misses",
            "fact_mismatches", "output_sha256_stable", "wall_seconds_median", "peak_rss_bytes_max")}
            for case in summary["cases"]],
        "graph_reference": graph["summary"],
        "collector_statuses": dict(Counter(item["status"] for item in collector["snapshots"])),
        "controlled_approval_evidence": controls,
        "tar_fuzz": {
            "source_receipt_sha256": digest(Path("ecosystem_audit/npm3-gap-repair-20261109/tar-memory/reference-fixed/receipt.json")),
            "continuous_60_seconds": "RSS failure retained",
            "bounded_12_by_5_seconds": "passed separately; not equivalent to continuous profile",
        },
        "resources": {key: value for key, value in resources.items() if not isinstance(value, (list, dict))},
        "local_cost": {
            "median_of_case_median_seconds": statistics.median(case["wall_seconds_median"] for case in summary["cases"]),
            "maximum_process_peak_rss_bytes": max(case["peak_rss_bytes_max"] for case in summary["cases"]),
            "scope": "cached local replay, three concurrent workers; no speed comparison",
        },
        "run_hashes": [{"id": item["id"], "round": item["round"],
                        "stdout": item["run"]["output_sha256"]["stdout"],
                        "stderr": item["run"]["output_sha256"]["stderr"],
                        "metrics": item["run"]["metrics_sha256"]} for item in runs],
        "raw_receipt_sha256": {str(path.relative_to(output)): digest(path) for path in [
            output / "fresh/cohort.json", output / "fresh/snapshots.json", output / "fresh/inventory.json",
            pair / "protocol.json", pair / "selection.json", pair / "acquisition.json",
            pair / "labels.json", pair / "summary.json", pair / "replay/receipts.json",
            pair / "resource-accounting.json", pair / "collector-validation/receipts.json",
            output / "graph-comparison/results.json", output / "control-reuse.json",
            output / "heldout-gap-diagnostic.json"]},
        "limits": ["Known-label ceiling is 23/30; 80% completion is unreachable on this frozen cohort",
                   "No observed lifecycle-command changes; user benefit on such changes is untested",
                   "Public advisory outcomes do not measure incorrect approvals",
                   "Continuous tar ASan resource gate remains failed", "No new signed release"],
    }
    target = output / "scorecard.json"
    raw = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if target.exists():
        assert target.read_text() == raw, "refusing to replace completed scorecard"
    else:
        target.write_text(raw)
    print(json.dumps({"pairs": result["qualification"]["pairs"],
                      "complete": result["qualification"]["processing_complete"],
                      "events_matched": result["qualification"]["matched_events"],
                      "events_assessable": result["qualification"]["assessable_events"],
                      "floor_met": result["qualification"]["completion_floor_met"]}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    main(parser.parse_args().output.resolve())
