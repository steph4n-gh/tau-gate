#!/usr/bin/env python3
"""Freeze, independently label, and replay historical npm v3 update pairs."""
import argparse
import collections
from concurrent.futures import ThreadPoolExecutor
import html
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import statistics
import sys
import time
import urllib.parse

import npm_evidence
import npm_repo_experiment
import qualification as q
import qualification_oracle as oracle


PROTOCOL = {
    "schema_version": 1,
    "selection": "ascending frozen cohort repository_rank; newest lock-changing commit timestamp then SHA then lock path; first parent; at most three attempted commits per repository; first 30 both-sides npm v3 eligible attempts",
    "lock_paths": "captured package-lock.json or npm-shrinkwrap.json paths, ordered by depth then path; merge histories by commit SHA and retain the first path for duplicate commits",
    "eligibility": "independent strict JSON; integer lockfileVersion 3, packages object including root on both sides; unequal lock bytes; no product output is consulted",
    "exclusions": "unavailable history, no parent, missing input, non3, unchanged or invalid input remain in attempts; no replacement after product output",
    "labels": "qualification_oracle.snapshot_facts and events on original bytes before any candidate case output; unknown facts remain unknown; exact scripts, source, integrity, archive, manifest and binding hashes are retained",
    "label_scope": "all locked records; root lifecycle ROOT_EVENTS, workspace install lifecycle plus prepare, archive install lifecycle; independent tarfile reader, without executing code; runtime behavior and npm host selection are not labels",
    "scoring": "qualification.score_case exact before/after facts and assessable event matches; complete means complete oracle, complete product report, no unknown events, no misses and no fact mismatches; valid blocked outcomes may complete; advisory is not permission to execute",
    "completion_floor": 0.8,
    "incorrect_allowed_tolerance": 0,
    "mandatory_fixture_gate": "owned separately by native/core sprint checks; public advisory pairs cannot establish incorrect-allowed rate",
    "byte_budget": 4 * 1024 ** 3,
    "per_file_limit": 64 * 1024 ** 2,
    "existing_bounds": "npm_evidence and qualification_oracle existing per-snapshot, expanded, record and reference bounds remain in force",
    "network": "GitHub API and pinned raw GitHub source only for source; artifact downloads only HTTPS registry.npmjs.org port 443 without redirects; existing offline cache is read-only",
    "measurement": "five interleaved per-case local core runs, preserving stdout/stderr and hashes; run_bounded wall time and process peak RSS; acquisition and cache states reported separately; no human review-time estimate",
    "public_policy": "review --json without --enforce or approvals; no fabricated approvals; no public runtime-safety conclusion",
}


def frozen(path, value):
    path = Path(path)
    if path.exists():
        if q.load(path) != value:
            raise ValueError(f"refusing to replace frozen receipt {path}")
    else:
        q.save(path, value)


def protocol(output):
    frozen(output / "protocol.json", PROTOCOL)
    return q.digest(q.read(output / "protocol.json"))


def project_prefix(lockfile):
    q.relative(lockfile)
    parent = PurePosixPath(lockfile).parent
    return "" if str(parent) == "." else str(parent) + "/"


def source_file(repository, commit, repository_path, destination, budget):
    q.relative(repository_path)
    url = q.raw_url(repository, commit, repository_path)
    if destination.exists():
        raw = q.read(destination)
    else:
        raw = q.raw_source(url)
    if raw is None:
        return {"path": repository_path, "url": url, "status": "http_404"}
    budget.account(len(raw))
    destination.parent.mkdir(parents=True, exist_ok=True)
    if not destination.exists():
        destination.write_bytes(raw)
    return {"path": repository_path, "url": url, "status": "captured", "bytes": len(raw), "sha256": q.digest(raw)}


def npm3(raw):
    value = oracle._json(raw)
    return (isinstance(value, dict) and type(value.get("lockfileVersion")) is int
            and value["lockfileVersion"] == 3 and isinstance(value.get("packages"), dict)
            and "" in value["packages"])


def history(repository, commit, lockfile, receipt):
    if receipt.exists():
        return q.load(receipt)
    query = urllib.parse.urlencode({"sha": commit, "path": lockfile, "per_page": 3})
    value = npm_repo_experiment.gh(f"repos/{repository}/commits?{query}")
    frozen(receipt, value)
    return value


def freeze(args):
    output = args.output.resolve()
    protocol_hash = protocol(output)
    if (output / "selection.json").exists():
        raise ValueError("selection already frozen; use acquire on this output")
    cohort = q.load(args.cohort)
    captured = q.load(args.snapshots)
    captured = captured["snapshots"] if isinstance(captured, dict) else captured
    snapshots = {row["repository"].lower(): row for row in captured}
    ranked = [{**row, "repository_rank": row.get("repository_rank", row.get("rank"))} for row in cohort["repositories"]]
    budget = q.Budget(PROTOCOL["byte_budget"])
    attempts, pairs = [], []
    started = time.monotonic()
    for item in sorted(ranked, key=lambda row: row["repository_rank"]):
        resolution = item["resolution"]
        repo = resolution.get("repository")
        snapshot = snapshots.get((repo or "").lower(), {})
        common = {"repository_rank": item["repository_rank"], "repository": repo,
                  "frozen_cohort_head": snapshot.get("commit")}
        if not repo or resolution.get("host", "github.com") != "github.com" or not snapshot.get("commit"):
            attempts.append({**common, "status": "unavailable_snapshot"})
            continue
        locks = sorted((p for p in snapshot.get("lockfiles", []) if PurePosixPath(p).name in ("package-lock.json", "npm-shrinkwrap.json")), key=lambda p: (p.count("/"), p))
        if not locks:
            attempts.append({**common, "status": "no_captured_npm_json_lock"})
            continue
        changes = {}
        for lockfile in locks:
            receipt = output / "history" / repo.replace("/", "__") / (q.digest(lockfile.encode()) + ".json")
            try:
                for change in history(repo, snapshot["commit"], lockfile, receipt):
                    changes.setdefault(change["sha"], (change, lockfile))
            except (OSError, ValueError, KeyError, TypeError) as exc:
                attempts.append({**common, "lockfile": lockfile, "status": "history_unavailable", "reason": str(exc)})
        ordered = sorted(changes.values(), key=lambda entry: (entry[0]["commit"]["committer"]["date"], entry[0]["sha"]), reverse=True)[:3]
        if not ordered and not any(a.get("repository") == repo for a in attempts):
            attempts.append({**common, "status": "no_historical_changes"})
        for change, lockfile in ordered:
            case_id = f"r{item['repository_rank']:03d}-{change['sha'][:12]}"
            attempt = {**common, "id": case_id, "lockfile": lockfile, "head": change["sha"],
                       "commit_url": change.get("html_url"), "committed_at": change["commit"]["committer"]["date"],
                       "files": {}, "status": "pending"}
            attempts.append(attempt)
            if not change.get("parents"):
                attempt["status"] = "no_parent"
                continue
            attempt["base"] = change["parents"][0]["sha"]
            prefix = project_prefix(lockfile)
            side_locks = {}
            try:
                for side in ("base", "head"):
                    root = output / "inputs" / case_id / side / "project"
                    specs = []
                    for path, normalized in ((lockfile, "package-lock.json"), (prefix + "package.json", "package.json")):
                        spec = source_file(repo, attempt[side], path, root / normalized, budget)
                        specs.append({**spec, "path": normalized, "repository_path": path})
                    attempt["files"][side] = specs
                    lock_spec = specs[0]
                    if lock_spec["status"] != "captured":
                        raise ValueError(f"{side} lockfile missing")
                    raw = q.read(root / "package-lock.json")
                    if not npm3(raw):
                        attempt["status"] = "non3"
                    side_locks[side] = raw
                if attempt["status"] == "non3":
                    continue
                if side_locks["base"] == side_locks["head"]:
                    attempt["status"] = "unchanged_lock"
                    continue
                attempt["status"] = "npm3_eligible"
                pairs.append({**attempt, "split": "holdout"})
            except (OSError, ValueError, KeyError, TypeError) as exc:
                attempt.update(status="input_unavailable_or_invalid", reason=str(exc))
            if len(pairs) == args.count:
                break
        if len(pairs) == args.count:
            break
    frozen(output / "selection.json", {"schema_version": 1, "protocol_sha256": protocol_hash,
           "cohort_sha256": q.digest(q.read(args.cohort)), "snapshots_sha256": q.digest(q.read(args.snapshots)),
           "helper_sha256": q.digest(q.read(__file__)), "target_eligible_pairs": args.count,
           "pairCount": len(pairs), "projectCount": len({p["repository"] for p in pairs}),
           "attempts": attempts, "pairs": pairs, "source_input_bytes": budget.used,
           "acquisition_elapsed_seconds": time.monotonic() - started})
    print(json.dumps({"eligible_pairs": len(pairs), "attempts": len(attempts)}))


def copy_original(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if q.digest(q.read(destination)) != q.digest(q.read(source)):
            raise ValueError("existing original evidence differs")
        return
    try:
        os.link(source, destination)
    except OSError:
        shutil.copyfile(source, destination)


def capture_extra(pair, side, output, budget):
    root = output / "inputs" / pair["id"] / side
    project = root / "project"
    prefix = project_prefix(pair["lockfile"])
    files, absent, issues = {}, [], []
    for spec in pair["files"][side]:
        if spec["status"] == "captured":
            raw = q.read(project / spec["path"])
            if q.digest(raw) != spec["sha256"]:
                raise ValueError("frozen primary source hash mismatch")
            files[spec["path"]] = {k: spec[k] for k in ("sha256", "bytes", "url", "repository_path")}
        else:
            absent.append(spec)
    lock = oracle._lock(q.read(project / "package-lock.json"))
    for path, record in sorted(lock["packages"].items()):
        if record.get("link") or npm_evidence.is_registry_path(path):
            continue
        for name, optional in (("package.json", False), ("binding.gyp", True)):
            relative = (path + "/" if path else "") + name
            if relative in files:
                continue
            try:
                spec = source_file(pair["repository"], pair[side], prefix + relative, project / relative, budget)
                if spec["status"] == "captured":
                    files[relative] = {k: spec[k] for k in ("sha256", "bytes", "url")}
                    files[relative]["repository_path"] = prefix + relative
                elif optional:
                    absent.append({**spec, "path": relative})
                else:
                    issues.append({"path": relative, "reason": "required source HTTP 404"})
            except (OSError, ValueError, TypeError) as exc:
                issues.append({"path": relative, "reason": str(exc)})
    receipt = {"repository": pair["repository"], "commit": pair[side], "files": files,
               "absent": absent, "issues": issues, "status": "partial" if issues else "complete",
               "trust": "caller-trusted exact raw GitHub commit URL; source scope is lock directory"}
    frozen(root / "source.json", receipt)
    return root, lock, receipt


def acquire(args):
    output = args.output.resolve()
    protocol(output)
    selection = q.load(output / "selection.json")
    if (output / "acquisition.json").exists():
        raise ValueError("acquisition already frozen; use label")
    budget = q.Budget(PROTOCOL["byte_budget"])
    budget.account(selection["source_input_bytes"])
    started = time.monotonic()
    snapshots = []
    cache = output / "archive-cache"
    cache.mkdir(parents=True, exist_ok=True)
    archives = {}
    for pair in selection["pairs"]:
        for side in ("base", "head"):
            root, lock, source = capture_extra(pair, side, output, budget)
            snapshots.append((root, lock, source))
            for path, record in sorted(lock["packages"].items()):
                if record.get("link") or not npm_evidence.is_registry_path(path):
                    continue
                try:
                    key = q.archive_identity(record)
                except (ValueError, TypeError):
                    continue
                if key in archives:
                    continue
                destination = cache / (key + ".tgz")
                offline = args.offline_cache / (key + ".tgz")
                begin = time.monotonic()
                mode = "offline_read_only_reuse" if offline.is_file() else "new_registry_download"
                try:
                    remaining = budget.limit - budget.used
                    if remaining == 0:
                        raise ValueError("declared aggregate byte budget exhausted")
                    read_budget = npm_evidence.WorkBudget(read=remaining)
                    try:
                        raw = npm_evidence.read_limited(offline, budget=read_budget) if offline.is_file() else npm_evidence.fetch_archive(record.get("resolved"), budget=read_budget)
                    finally:
                        budget.account(remaining - read_budget.read_remaining)
                    if q.digest(raw, "sha512") != key:
                        raise ValueError("original archive SHA512 mismatch")
                    if offline.is_file():
                        copy_original(offline, destination)
                    else:
                        destination.write_bytes(raw)
                    archives[key] = {"status": "available", "mode": mode, "bytes": len(raw), "sha256": q.digest(raw),
                                     "sha512": key, "url": record.get("resolved"), "elapsed_seconds": time.monotonic() - begin}
                except (OSError, ValueError, TypeError) as exc:
                    archives[key] = {"status": "unavailable", "mode": mode, "url": record.get("resolved"),
                                     "reason": str(exc), "elapsed_seconds": time.monotonic() - begin}
            print(json.dumps({"case": pair["id"], "side": side, "unique_archives": len(archives), "accounted_bytes": budget.used}), flush=True)
    for root, lock, source in snapshots:
        evidence, entries, packages = root / "evidence", [], {}
        for path, record in sorted(lock["packages"].items()):
            if record.get("link"):
                continue
            if npm_evidence.is_registry_path(path):
                try:
                    key = q.archive_identity(record)
                    receipt = archives[key]
                except (ValueError, TypeError, KeyError) as exc:
                    receipt = {"status": "unavailable", "reason": str(exc)}
                packages[path] = receipt
                if receipt["status"] == "available":
                    relative = "artifacts/" + key + ".tgz"
                    copy_original(cache / (key + ".tgz"), evidence / relative)
                    entries.append({"path": path, "artifact": relative})
            else:
                relative = (path + "/" if path else "") + "package.json"
                binding = (path + "/" if path else "") + "binding.gyp"
                known = relative in source["files"] and (binding in source["files"] or any(i["path"] == binding for i in source["absent"]))
                packages[path] = {"status": "available" if known else "unavailable", "reason": None if known else "source manifest or binding presence unknown"}
                if known:
                    copy_original(root / "project" / relative, evidence / "projects" / relative)
                    if binding in source["files"]:
                        copy_original(root / "project" / binding, evidence / "projects" / binding)
                    entries.append({"path": path, "project_manifest": "projects/" + relative})
        frozen(evidence / "index.json", {"schema_version": 1, "lock_sha256": q.digest(q.read(root / "project/package-lock.json")), "packages": entries})
        frozen(root / "acquisition.json", {"status": "complete" if source["status"] == "complete" and all(p["status"] == "available" for p in packages.values()) else "partial", "packages": packages, "source_sha256": q.digest(q.read(root / "source.json"))})
    frozen(output / "acquisition.json", {"selection_sha256": q.digest(q.read(output / "selection.json")),
           "archives": archives, "accounted_input_bytes": budget.used, "byte_budget": budget.limit,
           "elapsed_seconds": time.monotonic() - started, "network_concurrency": 1,
           "budget_overshoot_bound_bytes": PROTOCOL["per_file_limit"],
           "cache_scope": "original offline cache read only; new registry cache unique to this output"})


def label(args):
    output = args.output.resolve()
    protocol(output)
    if (output / "labels.json").exists():
        raise ValueError("labels already frozen; use replay")
    if (output / "replay").exists():
        raise ValueError("cannot first label after candidate outputs exist")
    selection = q.load(output / "selection.json")
    labels = []
    for pair in selection["pairs"]:
        facts, inputs = {}, {}
        for side in ("base", "head"):
            root = output / "inputs" / pair["id"] / side
            frozen_files = [i for i in pair["files"][side] if i["status"] == "captured"]
            acquisition, hashes = q.verify_snapshot(root, pair["repository"], pair[side], frozen_files)
            result = oracle.snapshot_facts(root / "project/package-lock.json", root / "evidence/index.json", root / "project/package.json")
            frozen(output / "labels" / pair["id"] / (side + ".json"), result)
            facts[side] = result
            inputs[side] = {"hashes": hashes, "acquisition_status": acquisition["status"],
                            "facts_sha256": q.digest(q.read(output / "labels" / pair["id"] / (side + ".json")))}
        expected = oracle.events(facts["base"], facts["head"])
        frozen(output / "labels" / pair["id"] / "events.json", expected)
        labels.append({"id": pair["id"], "inputs": inputs, "status": "complete" if all(f["status"] == "complete" for f in facts.values()) else "partial",
                       "assessable_events": len(expected), "unknown_packages": {s: sum(p["status"] != "known" for p in f["packages"].values()) for s, f in facts.items()},
                       "event_sha256": q.digest(q.read(output / "labels" / pair["id"] / "events.json"))})
    frozen(output / "labels.json", {"selection_sha256": q.digest(q.read(output / "selection.json")),
           "acquisition_sha256": q.digest(q.read(output / "acquisition.json")), "oracle_sha256": q.digest(q.read(oracle.__file__)),
           "scoring_helper_sha256": q.digest(q.read(q.__file__)), "cases": labels,
           "scope": PROTOCOL["label_scope"], "human_review_minutes": None})
    print(json.dumps({"labeled": len(labels), "complete": sum(i["status"] == "complete" for i in labels)}))


def verified_labels(output, pair, record):
    facts = {}
    for side in ("base", "head"):
        root = output / "inputs" / pair["id"] / side
        _, hashes = q.verify_snapshot(root, pair["repository"], pair[side], [i for i in pair["files"][side] if i["status"] == "captured"])
        if hashes != record["inputs"][side]["hashes"]:
            raise ValueError("input changed after independent labeling")
        path = output / "labels" / pair["id"] / (side + ".json")
        if q.digest(q.read(path)) != record["inputs"][side]["facts_sha256"]:
            raise ValueError("independent label changed")
        facts[side] = q.load(path)
    if q.digest(q.read(output / "labels" / pair["id"] / "events.json")) != record["event_sha256"]:
        raise ValueError("independent events changed")
    return facts


def validate(args):
    output = args.output.resolve()
    labels = q.load(output / "labels.json")
    selection = q.load(output / "selection.json")
    destination = output / "collector-validation"
    destination.mkdir()
    receipts = []
    for pair in selection["pairs"]:
        for side in ("base", "head"):
            root = output / "inputs" / pair["id"] / side
            folder = destination / pair["id"] / side
            argv = [sys.executable, str(Path(npm_evidence.__file__).resolve()), "validate",
                    "--lock", str(root / "project/package-lock.json"), "--index", str(root / "evidence/index.json"),
                    "--manifest", str(root / "project/package.json")]
            run = q.run_bounded(argv, folder, args.timeout)
            receipt = {"id": pair["id"], "side": side, "run": run,
                       "status": "validated" if run["termination"] == "exited" and run["exit_code"] == 0 else "rejected_or_incomplete"}
            frozen(folder / "receipt.json", receipt)
            receipts.append(receipt)
            print(json.dumps({"id": pair["id"], "side": side, "collector": receipt["status"]}), flush=True)
    frozen(destination / "receipts.json", {"labels_sha256": q.digest(q.read(output / "labels.json")),
           "collector_sha256": q.digest(q.read(npm_evidence.__file__)), "snapshots": receipts})


def resources(args):
    output = args.output.resolve()
    selection, acquisition = q.load(output / "selection.json"), q.load(output / "acquisition.json")
    by_mode = collections.Counter()
    for archive in acquisition["archives"].values():
        if archive["status"] == "available":
            by_mode[archive["mode"]] += archive["bytes"]
    extra_source = 0
    reference_bytes = 0
    materialized_bytes = 0
    project_evidence_bytes = 0
    cases = []
    labels = {r["id"]: r for r in q.load(output / "labels.json")["cases"]} if (output / "labels.json").exists() else {}
    for pair in selection["pairs"]:
        record = {"id": pair["id"], "snapshots": {}}
        for side in ("base", "head"):
            root = output / "inputs" / pair["id"] / side
            source, acquired, index = q.load(root / "source.json"), q.load(root / "acquisition.json"), q.load(root / "evidence/index.json")
            primary = {i["path"] for i in pair["files"][side] if i["status"] == "captured"}
            extra_source += sum(i["bytes"] for path, i in source["files"].items() if path not in primary)
            artifacts = {}
            for item in index["packages"]:
                if "artifact" in item:
                    size = (root / "evidence" / item["artifact"]).stat().st_size
                    reference_bytes += size
                    artifacts[item["artifact"]] = size
                else:
                    manifest = root / "evidence" / item["project_manifest"]
                    project_evidence_bytes += manifest.stat().st_size
                    binding = manifest.parent / "binding.gyp"
                    if binding.exists():
                        project_evidence_bytes += binding.stat().st_size
            materialized_bytes += sum(artifacts.values())
            missing = [p for p, value in acquired["packages"].items() if value["status"] != "available"]
            budget_missing = [p for p in missing if "budget" in str(acquired["packages"][p].get("reason", "")) or "reads exceed" in str(acquired["packages"][p].get("reason", ""))]
            collector = output / "collector-validation" / pair["id"] / side / "receipt.json"
            record["snapshots"][side] = {"source_status": source["status"], "acquisition_status": acquired["status"],
                 "missing_evidence_instances": len(missing), "acquisition_budget_unknown_instances": len(budget_missing),
                 "other_acquisition_unknown_instances": len(missing) - len(budget_missing),
                 "collector_status": q.load(collector)["status"] if collector.exists() else "not_run"}
        record["independent_label_status"] = labels.get(pair["id"], {}).get("status", "not_run")
        core = output / "replay/round-1" / pair["id"] / "receipt.json"
        if core.exists():
            receipt = q.load(core)
            record["core"] = {key: receipt[key] for key in ("report_status", "policy_outcome", "protocol_valid", "processing_complete")}
            report = q.load(core.parent / "stdout.bin")
            record["core"]["reasons"] = {side: {"issues": report.get(side, {}).get("issues"),
                 "unqualified_evidence": [{"path": i["path"], "state": i["state"], "reason": i.get("reason")} for i in report.get(side, {}).get("execution_evidence", []) if i.get("state") != "qualified"]} for side in ("base", "head")}
        cases.append(record)
    source_bytes = selection["source_input_bytes"] + extra_source
    unique_bytes = sum(by_mode.values())
    frozen(output / "resource-accounting.json", {"acquisition_sha256": q.digest(q.read(output / "acquisition.json")),
           "source_bytes_including_excluded_attempts": source_bytes,
           "newly_downloaded_unique_compressed_bytes": by_mode["new_registry_download"],
           "reused_offline_unique_compressed_bytes": by_mode["offline_read_only_reuse"],
           "other_or_failed_charged_archive_bytes": acquisition["accounted_input_bytes"] - source_bytes - unique_bytes,
           "combined_acquisition_charged_bytes": acquisition["accounted_input_bytes"], "combined_budget_bytes": acquisition["byte_budget"],
           "snapshot_artifact_locator_reference_bytes": reference_bytes,
           "snapshot_unique_artifact_materialized_logical_bytes": materialized_bytes,
           "snapshot_source_evidence_logical_bytes": project_evidence_bytes,
           "repeated_snapshot_materialized_archive_bytes_above_unique_cache": materialized_bytes - unique_bytes,
           "storage_note": "snapshot artifacts use hardlinks when possible, otherwise copies; logical bytes are not physical disk usage; repeated core/collector/oracle read bytes were not instrumented",
           "acquisition_wall_seconds": acquisition["elapsed_seconds"], "cases": cases})


def replay(args):
    output = args.output.resolve()
    protocol(output)
    selection, labels = q.load(output / "selection.json"), q.load(output / "labels.json")
    if q.digest(q.read(output / "selection.json")) != labels["selection_sha256"] or q.digest(q.read(output / "acquisition.json")) != labels["acquisition_sha256"]:
        raise ValueError("selection or acquisition changed after labeling")
    if q.digest(q.read(oracle.__file__)) != labels["oracle_sha256"] or q.digest(q.read(q.__file__)) != labels["scoring_helper_sha256"]:
        raise ValueError("oracle or scoring helper changed after labeling")
    label_by_id = {i["id"]: i for i in labels["cases"]}
    facts = {p["id"]: verified_labels(output, p, label_by_id[p["id"]]) for p in selection["pairs"]}
    destination = output / "replay"
    destination.mkdir()
    binary = args.binary.resolve()
    binary_hash = q.digest(q.read(binary))
    frozen(destination / "plan.json", {"binary": str(binary), "binary_sha256": binary_hash,
           "labels_sha256": q.digest(q.read(output / "labels.json")), "rounds": args.rounds, "jobs": getattr(args, "jobs", 1),
           "order": "round-major submission and receipt order; ascending frozen pair order, even rounds reversed", "cache": "all artifacts local; operating-system cache not flushed; acquisition excluded",
           "timing_scope": "per-review process measurements; concurrent jobs are not a sequential latency comparison"})
    jobs = getattr(args, "jobs", 1)
    if not 1 <= jobs <= 4:
        raise ValueError("replay jobs must be between 1 and 4")
    if len({pair["id"] for pair in selection["pairs"]}) != len(selection["pairs"]):
        raise ValueError("duplicate replay case ids")

    def run_pair(item):
        number, pair = item
        folder = destination / f"round-{number}" / pair["id"]
        argv = [str(binary), "review", "--json"]
        for side in ("base", "head"):
            root = output / "inputs" / pair["id"] / side
            argv.extend(["--" + side, str(root / "project/package-lock.json"), "--" + side + "-manifest", str(root / "project/package.json"), "--" + side + "-evidence", str(root / "evidence/index.json")])
        run = q.run_bounded(argv, folder, args.timeout)
        report, error = {}, None
        try:
            report = q.load(folder / "stdout.bin")
        except (OSError, ValueError) as exc:
            error = str(exc)
        expected, scores = q.score_case(facts[pair["id"]], report)
        comparison = scores["comparison"]
        status = report.get("status")
        outcome = report.get("policy", {}).get("outcome")
        expected_exit = 2 if status == "incomplete" or outcome == "incomplete" else 1 if outcome == "blocked" else 0
        valid = run["termination"] == "exited" and run["exit_code"] == expected_exit and status in ("complete", "incomplete")
        complete = valid and comparison["status"] == "complete" and not comparison["misses"] and not comparison["fact_mismatches"]
        receipt = {"id": pair["id"], "round": number, "run": run, "report_status": status, "policy_outcome": outcome,
                   "protocol_valid": valid, "processing_complete": complete, "comparison": comparison,
                   "unexpected_allowed_outcome": outcome == "allowed", "parse_error": error,
                   "label_status": label_by_id[pair["id"]]["status"]}
        frozen(folder / "receipt.json", receipt)
        return receipt

    receipts = []
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        for number in range(1, args.rounds + 1):
            ordered = selection["pairs"] if number % 2 else list(reversed(selection["pairs"]))
            for receipt in pool.map(run_pair, ((number, pair) for pair in ordered)):
                receipts.append(receipt)
                print(json.dumps({"round": number, "id": receipt["id"], "complete": receipt["processing_complete"], "status": receipt["report_status"], "misses": receipt["comparison"]["misses"]}), flush=True)
    if q.digest(q.read(binary)) != binary_hash:
        raise ValueError("candidate binary changed during replay")
    frozen(destination / "receipts.json", receipts)
    summarize(output, selection, labels, receipts)


def summarize(output, selection, labels, receipts):
    by_case = collections.defaultdict(list)
    for record in receipts:
        by_case[record["id"]].append(record)
    cases = []
    for pair in selection["pairs"]:
        runs = by_case[pair["id"]]
        times = [r["run"]["elapsed_seconds"] for r in runs]
        rss = [r["run"]["peak_rss_bytes"] for r in runs if r["run"]["peak_rss_bytes"] is not None]
        cases.append({"id": pair["id"], "repository": pair["repository"], "complete": all(r["processing_complete"] for r in runs),
                      "statuses": sorted({str(r["report_status"]) for r in runs}), "policy_outcomes": sorted({str(r["policy_outcome"]) for r in runs}),
                      "wall_seconds_median": statistics.median(times), "wall_seconds_range": [min(times), max(times)],
                      "peak_rss_bytes_max": max(rss) if rss else None,
                      "assessable_events": len(runs[0]["comparison"]["matched"]) + runs[0]["comparison"]["misses"],
                      "event_matches": len(runs[0]["comparison"]["matched"]), "event_misses": runs[0]["comparison"]["misses"],
                      "approval_relevant_misses": runs[0]["comparison"]["approval_relevant_misses"],
                      "fact_mismatches": len(runs[0]["comparison"]["fact_mismatches"]),
                      "output_sha256_stable": len({r["run"]["output_sha256"]["stdout"] for r in runs}) == 1})
    count = len(cases)
    complete = sum(c["complete"] for c in cases)
    events = sum(c["assessable_events"] for c in cases)
    matched = sum(c["event_matches"] for c in cases)
    frozen(output / "summary.json", {"protocol_sha256": q.digest(q.read(output / "protocol.json")),
           "selection_sha256": q.digest(q.read(output / "selection.json")), "labels_sha256": q.digest(q.read(output / "labels.json")),
           "attempt_statuses": dict(collections.Counter(a["status"] for a in selection["attempts"])),
           "pairs": count, "independent_labels_complete": sum(c["status"] == "complete" for c in labels["cases"]),
           "processing_complete": complete, "completion_fraction": complete / count if count else None,
           "completion_floor": PROTOCOL["completion_floor"], "completion_floor_met": bool(count and complete / count >= PROTOCOL["completion_floor"]),
           "assessable_events": events, "matched_events": matched, "event_recall": matched / events if events else None,
           "unknown_packages_by_side": {s: sum(c["unknown_packages"][s] for c in labels["cases"]) for s in ("base", "head")},
           "unexpected_allowed_outcomes": sum(r["unexpected_allowed_outcome"] for r in receipts),
           "incorrect_allowed_fixture_gate": "not assessed here; separate mandatory controlled gate",
           "human_review_minutes": None, "safety_claim": "none; historical public reports are advisory", "cases": cases})
    render_html(output)


def render_html(output):
    summary = q.load(output / "summary.json")
    selection = q.load(output / "selection.json")
    selected = None
    for pair in selection["pairs"]:
        events = q.load(output / "labels" / pair["id"] / "events.json")
        if any(e["kind"] in ("lifecycle_added", "lifecycle_changed", "lifecycle_removed") for e in events):
            selected = pair
            break
    detail = "<p>No eligible historical pair was available.</p>"
    if selected:
        events = q.load(output / "labels" / selected["id"] / "events.json")
        report = q.load(output / "replay/round-1" / selected["id"] / "stdout.bin")
        hook = [e for e in events if e["kind"].startswith("lifecycle_")]
        title = "Real historical changed-hook case" if hook else "Real historical update; no independently observed changed hook"
        detail = f"<h2>{title}</h2><p>{html.escape(selected['repository'])}, {html.escape(selected['base'])} to {html.escape(selected['head'])}.</p>"
        detail += "<p>The report below is the preserved review JSON. Hook bodies are original evidence, not executed commands. Human review time was not measured.</p>"
        detail += "<h3>Independent events</h3><pre>" + html.escape(json.dumps(events, indent=2)) + "</pre>"
        detail += "<h3>TauGate review JSON</h3><pre>" + html.escape(json.dumps(report, indent=2)) + "</pre>"
    elif selection["pairs"]:
        events, report = controlled_demo(output)
        detail = "<h2>Controlled changed-hook demonstration</h2><p>No changed hook was independently observed in the selected public histories. This separate local demonstration changes the root postinstall command. It is not a public update and does not contribute to the 30-pair score. Neither command was executed.</p>"
        detail += "<h3>Independent events</h3><pre>" + html.escape(json.dumps(events, indent=2)) + "</pre>"
        detail += "<h3>TauGate review JSON</h3><pre>" + html.escape(json.dumps(report, indent=2)) + "</pre>"
    rows = "".join(f"<tr><td>{html.escape(c['repository'])}</td><td>{html.escape(c['id'])}</td><td>{c['complete']}</td><td>{c['event_matches']}/{c['assessable_events']}</td><td>{c['wall_seconds_median']:.4f}</td><td>{c['peak_rss_bytes_max']}</td></tr>" for c in summary["cases"])
    document = "<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>Historical npm v3 pair qualification</title><style>body{font:16px system-ui;max-width:1100px;margin:2rem auto;padding:0 1rem;line-height:1.5;color:#18212b}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccd3da;padding:.4rem;text-align:left}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f3f5f7;padding:1rem}h1,h2,h3{line-height:1.2}</style><h1>Historical npm v3 pair qualification</h1>"
    document += f"<p>{summary['processing_complete']} of {summary['pairs']} eligible pairs completed comparison. Event recall is {summary['matched_events']} of {summary['assessable_events']} assessable events. Unknown facts remain excluded from recall and visible in the JSON summary.</p>"
    document += "<p>All historical reviews are advisory. Complete extraction does not establish package safety or approval. The mandatory incorrect-allowed fixture gate is separate. Acquisition time and local processing time are separate. No human review-time savings are claimed.</p><table><thead><tr><th>Repository</th><th>Case</th><th>Complete</th><th>Event matches</th><th>Median wall seconds</th><th>Max RSS bytes</th></tr></thead><tbody>" + rows + "</tbody></table>" + detail + "</html>"
    (output / "report.html").write_text(document)


def controlled_demo(output):
    destination = output / "controlled-demo"
    facts = {}
    argv = [q.load(output / "replay/plan.json")["binary"], "review", "--json"]
    for side, body in (("base", "echo controlled-before-never-executed"), ("head", "echo controlled-after-never-executed")):
        root = destination / side
        manifest = {"name": "controlled-root", "version": "1.0.0", "scripts": {"postinstall": body}}
        lock = {"lockfileVersion": 3, "packages": {"": {"name": "controlled-root", "version": "1.0.0"}}}
        frozen(root / "package.json", manifest)
        frozen(root / "package-lock.json", lock)
        frozen(root / "index.json", {"schema_version": 1, "lock_sha256": q.digest(q.read(root / "package-lock.json")), "packages": [{"path": "", "project_manifest": "package.json"}]})
        facts[side] = oracle.snapshot_facts(root / "package-lock.json", root / "index.json", root / "package.json")
        frozen(root / "facts.json", facts[side])
        argv.extend(["--" + side, str(root / "package-lock.json"), "--" + side + "-manifest", str(root / "package.json"), "--" + side + "-evidence", str(root / "index.json")])
    expected = oracle.events(facts["base"], facts["head"])
    frozen(destination / "events.json", expected)
    if not (destination / "core/receipt.json").exists():
        run = q.run_bounded(argv, destination / "core", 180)
        frozen(destination / "core/receipt.json", run)
    report = q.load(destination / "core/stdout.bin")
    _, scores = q.score_case(facts, report)
    frozen(destination / "comparison.json", scores)
    return expected, report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("freeze", "acquire", "label", "validate", "resources", "replay"):
        command = sub.add_parser(name)
        command.add_argument("--output", type=Path, required=True)
        if name == "freeze":
            command.add_argument("--cohort", type=Path, required=True)
            command.add_argument("--snapshots", type=Path, required=True)
            command.add_argument("--count", type=int, default=30)
        elif name == "acquire":
            command.add_argument("--offline-cache", type=Path, default=Path("/Volumes/Storage/taugate-qualification/archives"))
        elif name == "replay":
            command.add_argument("--binary", type=Path, required=True)
            command.add_argument("--rounds", type=int, default=5)
            command.add_argument("--jobs", type=int, default=1)
            command.add_argument("--timeout", type=float, default=180)
        elif name == "validate":
            command.add_argument("--timeout", type=float, default=180)
    args = parser.parse_args(argv)
    try:
        if args.command == "freeze" and not 1 <= args.count <= 30:
            raise ValueError("pair count must be between 1 and 30")
        if args.command == "replay" and (args.rounds < 1 or args.timeout <= 0 or not 1 <= args.jobs <= 4):
            raise ValueError("rounds and timeout must be positive; jobs must be between 1 and 4")
        globals()[args.command](args)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(2, str(exc) + "\n")


if __name__ == "__main__":
    main()
