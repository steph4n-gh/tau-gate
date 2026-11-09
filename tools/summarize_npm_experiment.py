#!/usr/bin/env python3
"""Reconcile experiment coverage and verify its frozen evidence before reporting."""
import argparse
import base64
import collections
import hashlib
import json
from pathlib import Path

from npm_repo_experiment import save, sha


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.output.resolve()
    receipt = json.loads((root / "receipt.json").read_text())
    cohort = json.loads((root / "cohort.json").read_text())
    marked = json.loads((root / "marked-artifacts.json").read_text()) if (root / "marked-artifacts.json").exists() else {"records": []}
    partial_audits = json.loads((root / "partial-evidence-receipt.json").read_text())
    partial_statuses = collections.Counter(a["status"] for a in partial_audits)
    for audit in partial_audits:
        if any(state != "qualified" for state in audit["states"]):
            assert audit["status"] == "incomplete", audit
    snapshots = {s["repository"]: s for s in receipt["snapshots"]}
    audits = collections.defaultdict(list)
    for audit in receipt["audits"]:
        audits[audit["repository"]].append(audit)
    checked_files = 0
    math_reports = []
    assert sha((root / "critical-source.json").read_bytes()) == cohort["source_sha256"]
    assert sha((root / "input.csv").read_bytes()) == receipt["csv_sha256"]
    assert sha(Path(__file__).with_name("npm_repo_experiment.py").read_bytes()) == receipt["runner_sha256"]
    binary = Path(receipt["audits"][0]["command"][0])
    assert sha(binary.read_bytes()) == receipt["binary_sha256"]
    for snapshot in snapshots.values():
        folder = root / "repositories" / snapshot["repository"].replace("/", "__")
        for file in snapshot.get("files", []):
            assert sha((folder / "source" / file["path"]).read_bytes()) == file["sha256"], file
            checked_files += 1
    for audit in receipt["audits"]:
        if "report" not in audit:
            continue
        report = json.loads((root / audit["report"]).read_text())
        if report.get("lock_sha256"):
            assert report["lock_sha256"] == audit["lock_sha256"]
        assert len(report.get("packages", [])) == audit["package_records"]
        if audit["package_records"]:
            labels = {p["path"] for p in report["packages"]}
            # Edges label npm's empty root path as 'root'.
            if "" in labels:
                labels.remove("")
                labels.add("root")
            adjacency = {label: set() for label in labels}
            for edge in report["edges"]:
                adjacency[edge["from"]].add(edge["to"])
                adjacency[edge["to"]].add(edge["from"])
            unseen = set(labels)
            components = 0
            while unseen:
                components += 1
                stack = [unseen.pop()]
                while stack:
                    for target in adjacency[stack.pop()]:
                        if target in unseen:
                            unseen.remove(target)
                            stack.append(target)
            diagnostic = report["topology"]
            n, edges = len(labels), len(report["edges"])
            limit = min(5000, max(1, 20_000_000 // max(1, n + edges)))
            if components > 1 or n == 1:
                assert diagnostic["score"] == 0 and diagnostic["iterations"] == 0
            if diagnostic.get("residual_converged") is False:
                assert diagnostic["iterations"] == limit, diagnostic
            math_reports.append({"repository": audit["repository"], "lockfile": audit["lockfile"],
                                 "report": audit["report"], "report_sha256": sha((root / audit["report"]).read_bytes()),
                                 "topology_complete": audit["topology_status"] == "complete",
                                 "nodes": n, "edges": edges, "undirected_components": components,
                                 "iteration_limit": limit,
                                 **{k: v for k, v in diagnostic.items() if k != "partition"}})
    archives = set()
    for record in marked["records"]:
        if record["status"] != "sri_verified_and_inspected":
            continue
        path = root / record["archive"]
        archive = path.read_bytes()
        assert sha(archive) == record["archive_sha256"]
        assert "sha512-" + base64.b64encode(hashlib.sha512(archive).digest()).decode() == record["integrity"]
        archives.add(str(path))
        name = record["repository"].replace("/", "__")
        partial = json.loads((root / "repositories" / name / "audits" / "partial-evidence.json").read_text())
        evidence = next(e for e in partial["execution_evidence"] if e["path"] == record["path"])
        assert evidence["state"] == "qualified", evidence
        assert evidence["candidate"] == record["execution_candidate"], evidence
        facts = evidence["facts"]
        assert facts["manifest_sha256"] == record["manifest_sha256"]
        assert facts["implicit_node_gyp"] == record["implicit_node_gyp"]
        assert facts["lifecycle"] == {event: sha(body.encode()) for event, body in record["lifecycle_scripts"].items()}
    rows = []
    findings = []
    for member in cohort["repositories"]:
        resolution = member["resolution"]
        repo = resolution.get("repository", resolution["input_url"].removeprefix("https://github.com/"))
        snapshot = snapshots.get(repo)
        reports = audits.get(repo, [])
        graphs = [a for a in reports if a.get("topology_status") == "complete"]
        inspected = [r for r in marked["records"] if r["repository"] == repo]
        notes = []
        observations = []
        for audit in reports:
            if audit.get("package_records"):
                obs = json.loads((root / audit["report"]).with_suffix(".observations.json").read_text())
                observations.append(obs)
                for key, label in (("external_or_non_https_sources", "nonstandard source"),
                                   ("integrity_without_sha512", "integrity without SHA-512"),
                                   ("http_sources_without_integrity", "HTTP source without SRI")):
                    if obs[key]:
                        notes.append(f"{len(obs[key])} {label} record(s)")
                        findings.append({"repository": repo, "lockfile": audit["lockfile"],
                                         "kind": key, "records": obs[key], "report": audit["report"]})
        if resolution["status"] != "resolved":
            status = "repository_unavailable"
            notes.append(resolution.get("error", resolution["status"]))
        elif not snapshot or snapshot["status"] == "capture_failed":
            status = "capture_failed"
            notes.append((snapshot or {}).get("error", "missing snapshot"))
        elif not reports:
            status = "no_project_lockfile_found"
            notes.append("No root or nearest non-fixture lock found")
            if snapshot.get("tree_truncated"):
                notes.append("Git tree listing truncated")
        elif len(graphs) == len(reports):
            status = "all_discovered_graphs_extracted"
        elif graphs:
            status = "some_discovered_graphs_extracted"
        else:
            status = "no_discovered_graph_extracted"
        incomplete = [a.get("error") for a in reports if a.get("error")]
        graph_issues = [issue for a in reports for issue in a.get("issues", [])
                        if not issue.startswith("Execution capabilities unknown:")]
        hooks = sum(r.get("execution_candidate") is True for r in inspected)
        no_hook = sum(r.get("execution_candidate") is False for r in inspected)
        unknown = sum(r["status"] != "sri_verified_and_inspected" for r in inspected)
        if no_hook:
            notes.append(f"{no_hook} positive install marker(s) resolved to no hook")
        rows.append({"rank": member["repository_rank"], "repository": repo,
                     "representative_package": member["package"]["name"],
                     "best_npm_package_rank": member["npm_package_rank"],
                     "rankings_average": member["package"]["rankings_average"],
                     "commit": snapshot.get("commit") if snapshot else None,
                     "status": status, "lockfiles": [a["lockfile"] for a in reports],
                     "graphs_extracted": len(graphs), "lockfiles_audited": len(reports),
                     "package_records_per_lockfile": {a["lockfile"]: a["package_records"] for a in reports},
                     "verified_marked_hooks": hooks, "verified_marked_no_hook": no_hook,
                     "marked_instances_not_verified": unknown, "notes": notes,
                     "audit_errors": incomplete, "graph_issues": graph_issues,
                     "execution_metadata_statuses": sorted({a["execution_metadata_status"] for a in reports
                                                            if a.get("execution_metadata_status")}),
                     "reports": [a.get("report") for a in reports]})
    assert len(rows) == 200
    assert len({r["repository"].lower() for r in rows}) == 200
    counts = collections.Counter(r["status"] for r in rows)
    assert sum(counts.values()) == 200
    blockers = collections.Counter()
    for audit in receipt["audits"]:
        error = audit.get("error") or ""
        if "only npm lockfileVersion" in error:
            folder = root / "repositories" / audit["repository"].replace("/", "__") / "source"
            version = json.loads((folder / audit["lockfile"]).read_bytes()).get("lockfileVersion")
            blockers[f"npm v{version}"] += 1
        elif "Yarn Berry" in error:
            blockers["Yarn Berry"] += 1
        elif "pnpm" in error:
            folder = root / "repositories" / audit["repository"].replace("/", "__") / "source"
            text = (folder / audit["lockfile"]).read_text()
            version = next(line.split(":", 1)[1].strip().strip("\"'")
                           for line in text.splitlines() if line.startswith("lockfileVersion:"))
            blockers["pnpm v9 fields" if version == "9.0" else f"pnpm v{version}"] += 1
        elif "unsupported record field uid" in error:
            blockers["Yarn Classic uid"] += 1
    verified = [r for r in marked["records"] if r["status"] == "sri_verified_and_inspected"]
    math_summary = {"reports": len(math_reports),
                    "not_converged": sum(r.get("residual_converged") is False for r in math_reports),
                    "zero_score_without_iteration": sum(r.get("score") == 0 and r.get("iterations") == 0 for r in math_reports),
                    "iterative_reports": sum(r.get("iterations", 0) > 0 for r in math_reports),
                    "iterative_reports_converged": sum(r.get("iterations", 0) > 0 and r.get("residual_converged") is True for r in math_reports)}
    save(root / "math-diagnostics.json", {"summary": math_summary, "reports": math_reports})
    summary = {"projects": 200, "project_outcomes": dict(counts),
               "lockfiles_attempted": len(receipt["audits"]),
               "lockfiles_with_complete_topology": sum(a.get("topology_status") == "complete" for a in receipt["audits"]),
               "lockfiles_rejected_before_inventory": sum(not a["package_records"] for a in receipt["audits"]),
               "lockfiles_read_with_incomplete_topology": sum(bool(a["package_records"]) and a.get("topology_status") != "complete" for a in receipt["audits"]),
               "advisory_report_statuses": receipt["status_counts"],
               "package_records_across_reports": sum(a["package_records"] for a in receipt["audits"]),
               "marked_registry_instances": len(marked["records"]),
               "marked_registry_instances_verified": len(verified),
               "marked_registry_instances_with_hooks": sum(r["execution_candidate"] for r in verified),
               "marked_registry_instances_without_hooks": sum(not r["execution_candidate"] for r in verified),
               "marked_registry_instances_unknown": len(marked["records"]) - len(verified),
               "verified_unique_archives": len(archives), "frozen_source_files_rehashed": checked_files,
               "parser_blockers": dict(blockers),
               "targeted_evidence_audit_statuses": dict(partial_statuses),
               "topology_math_diagnostics": math_summary,
               "rows": rows, "source_integrity_observations": findings}
    save(root / "summary.json", summary)
    lines = ["# Tau-Gate experiment on 200 distinct npm repositories", "",
             "Experiment date: November 9, 2026. Each acquired snapshot is pinned to its recorded default-branch Git commit.", "",
             "The cohort contains 200 distinct repository identities, selected by each repository's highest-ranked npm package in the pinned heatmap dataset. Unavailable repositories remain in the cohort. This is a repository development-lockfile experiment, not a reconstruction of the runtime tree installed by consumers of each published npm package.", "",
             f"Source: [{cohort['source_url']}]({cohort['source_url']}). Selection reaches npm package rank {cohort['repositories'][-1]['npm_package_rank']} of {cohort['npm_packages_in_source']:,}. Repository metrics are not summed across package names.", "",
             "## Coverage", "", "| Project outcome | Repositories |", "|---|---:|"]
    labels = {"repository_unavailable": "Repository URL unavailable",
              "capture_failed": "Snapshot acquisition failed",
              "no_project_lockfile_found": "No project lockfile found",
              "all_discovered_graphs_extracted": "Graphs extracted for every discovered lockfile",
              "some_discovered_graphs_extracted": "Graphs extracted for some discovered lockfiles",
              "no_discovered_graph_extracted": "No complete graph report for discovered lockfiles"}
    lines += [f"| {labels[k]} | {v} |" for k, v in sorted(counts.items())]
    lines += [f"| Total | 200 |", "",
              f"Tau-Gate attempted {summary['lockfiles_attempted']} lockfiles and extracted complete topology from {summary['lockfiles_with_complete_topology']}. The resulting reports contain {summary['package_records_across_reports']:,} records across different identity models. Records are not unique packages or installed production dependencies.", "",
              f"Of the lockfiles without complete topology, {summary['lockfiles_rejected_before_inventory']} were rejected before package inventory and {summary['lockfiles_read_with_incomplete_topology']} were read but retained graph or input-consistency issues. The latter are not syntax failures.", "",
              f"Advisory report statuses: `{json.dumps(receipt['status_counts'], sort_keys=True)}`. A complete advisory report does not establish package safety or complete execution evidence.", "",
              "Parser blockers, counted per lockfile:", "", "| Format or feature | Lockfiles rejected |", "|---|---:|"]
    lines += [f"| {name} | {count} |" for name, count in blockers.most_common()]
    lines += ["", "Supporting these formats is separate from verifying installation behavior. A parser change may reveal additional unsupported constructs, so these counts are starting inputs rather than a guaranteed coverage gain.", "",
              "## Graph math diagnostics", "",
              f"The {math_summary['reports']} reports with a package inventory include connectivity diagnostics. {math_summary['not_converged']} report that the bounded solver did not reach its convergence tolerance. Each stopped at the declared iteration or total-work limit. Another {math_summary['zero_score_without_iteration']} return exact zero without iteration because the graph is disconnected or has one node. {math_summary['iterative_reports_converged']} iterative solves reached the tolerance.", "",
              "The independent report check reconstructs undirected connected components from emitted edges and verifies the zero-score shortcut and bounded stopping counts. [Per-lockfile numerical diagnostics](math-diagnostics.json) preserve the input report hashes, residuals, iteration counts, and component counts. These statistics measure solver behavior on this corpus, not security detection quality or the accuracy of a second eigenpair. No comparison has established that the spectral partition improves review findings beyond ordinary graph traversal, diffs, and artifact checks. Approval policy does not use the connectivity score or partition.", "",
              "## Install markers checked against archives", "",
              f"The targeted check covered {len(marked['records'])} registry instances with positive npm install markers. It verified {len(verified)} instances using {len(archives)} distinct SHA-512-matching archives. Rust independently rechecked those archives and derived the same lifecycle hashes and candidate outcomes as the Python inspector.", "",
              f"Of those verified instances, {summary['marked_registry_instances_with_hooks']} contain active lifecycle hooks or an implicit native build, and {summary['marked_registry_instances_without_hooks']} contain neither. {summary['marked_registry_instances_unknown']} marked instances remain unknown. Unmarked artifacts were not inspected. These are execution candidates, not malware findings. Targeted-evidence audit statuses are `{json.dumps(dict(partial_statuses), sort_keys=True)}`. Missing evidence preserves an incomplete outcome. Husky's root-only lock has no registry artifacts to acquire and completes with its source manifest.", "",
              "## Source and integrity observations", ""]
    for finding in findings:
        examples = ", ".join(f"`{p['name']}@{p['version']}`" for p in finding["records"][:5])
        lines.append(f"- **{finding['repository']}**: {len(finding['records'])} `{finding['kind']}` records, including {examples}. [Frozen report]({finding['report']}).")
    lines += ["", "These observations identify review work. Git sources may be commit-pinned, alternate registries may be intentional, and an older integrity algorithm does not establish compromise. A missing explicit integrity field may coexist with a SHA-1 hash in the resolved URL fragment. No vulnerability database or package runtime behavior was evaluated.", "",
              "Two manifest comparisons also merit follow-up. Less declares pnpm as its package manager, while its alternate npm lock lacks three declared lint dependencies. Webpack dev middleware's npm lock declares `ws: 8.22.1` as a root dependency that is absent from the supplied manifest. These are frozen-byte disagreements, not verified installation failures. pnpm overrides, catalogs, and local test fixtures can also cause current Tau-Gate incompleteness and require format-aware triage.", "",
              "## All 200 projects", "",
              "`Graphs` is the number of completely extracted dependency graphs divided by the number of discovered lockfiles audited. A dash means no lockfile audit was possible. `Hooks / no hook / unknown` covers only positive npm registry install markers inspected in this experiment. A dash means that check was not applicable, not zero execution exposure.", "",
              "| Rank | Repository | Graphs | Verified hooks / no hook / unknown | Result or observation |",
              "|---:|---|---:|---:|---|"]
    for row in rows:
        graph = f"{row['graphs_extracted']}/{row['lockfiles_audited']}" if row["lockfiles_audited"] else "—"
        marked_total = row["verified_marked_hooks"] + row["verified_marked_no_hook"] + row["marked_instances_not_verified"]
        hooks = f"{row['verified_marked_hooks']} / {row['verified_marked_no_hook']} / {row['marked_instances_not_verified']}" if marked_total else "—"
        notes = row["notes"] + row["audit_errors"] + row["graph_issues"][:3]
        note = "; ".join(notes) if notes else labels[row["status"]]
        note = note.replace("|", "\\|").replace("\n", " ")
        target = row["reports"][0] if row["reports"] else "snapshots.json"
        lines.append(f"| {row['rank']} | [{row['repository']}]({target}) | {graph} | {hooks} | {note} |")
    lines += ["", "## Evidence and rerun", "",
              "[Cohort and source rankings](cohort.json), [all snapshot identities](snapshots.json), [commands and input hashes](receipt.json), [archive inspection](marked-artifacts.json), [Rust partial-evidence receipts](partial-evidence-receipt.json), and [machine-readable summary](summary.json).", "",
              f"Verification rehashed {checked_files} frozen source files and {len(archives)} distinct inspected archives. It reconciled all 200 cohort rows and compared archive-derived lifecycle hashes with the Rust auditor.", "",
              "```sh", "python3 tools/npm_repo_experiment.py \\",
              f"  --csv {root / 'repository-input.csv'} \\",
              f"  --output {root} \\", "  --binary target/release/tau-gate --inspect-marked-archives",
              f"python3 tools/summarize_npm_experiment.py --output {root}", "```", "",
              "The runner reuses frozen source snapshots. It never installs packages or executes package lifecycle scripts. Lockfile discovery checks root files first, then nearest non-fixture project locks if no root lock exists. A truncated Git tree remains an explicit discovery limit. Unsupported input stays incomplete. The Rust core and package-manager format support were not changed.", ""]
    (root / "REPORT.md").write_text("\n".join(lines))
    print(json.dumps({k: v for k, v in summary.items() if k not in ("rows", "source_integrity_observations")}, indent=2))


if __name__ == "__main__":
    main()
