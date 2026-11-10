#!/usr/bin/env python3
"""Replay frozen dependency graphs against native solvers and a numerical oracle."""
import argparse
import collections
import ctypes
import hashlib
import json
import os
from pathlib import Path
import statistics
import subprocess
import time
import warnings

import numpy as np
import scipy
from scipy import sparse
from scipy.sparse import csgraph
from scipy.sparse.linalg import eigsh, lobpcg


def digest(data):
    return hashlib.sha256(data).hexdigest()


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


class Result(ctypes.Structure):
    _fields_ = [("nodes", ctypes.POINTER(ctypes.c_char_p)), ("nodes_count", ctypes.c_size_t),
                ("tau", ctypes.c_double), ("score", ctypes.c_double),
                ("converged", ctypes.c_int), ("residual", ctypes.c_double),
                ("iterations", ctypes.c_size_t)]


class Native:
    def __init__(self, path):
        self.path = str(path.resolve())
        self.sha256 = digest(path.read_bytes())
        self.lib = ctypes.CDLL(self.path)
        self.lib.tau_gate_analyze.argtypes = [ctypes.POINTER(ctypes.c_int), ctypes.c_size_t,
                                            ctypes.POINTER(ctypes.c_char_p), ctypes.c_size_t]
        self.lib.tau_gate_analyze.restype = ctypes.POINTER(Result)
        self.lib.tau_gate_free_result.argtypes = [ctypes.POINTER(Result)]
        self.lib.tau_gate_free_result.restype = None

    def run(self, graph):
        labels = [label.encode() for label in graph["nodes"]]
        names = (ctypes.c_char_p * len(labels))(*labels)
        edges = (ctypes.c_int * (2 * len(graph["edges"])))(
            *(endpoint for pair in graph["edges"] for endpoint in pair))
        start = time.perf_counter()
        pointer = self.lib.tau_gate_analyze(edges, len(graph["edges"]), names, len(labels))
        if not pointer:
            return {"error": "native analysis returned NULL", "seconds": time.perf_counter() - start}
        try:
            r = pointer.contents
            result = {"score": r.score, "converged": bool(r.converged),
                      "residual": r.residual, "iterations": r.iterations,
                      "partition": [r.nodes[i].decode() for i in range(r.nodes_count)], "tau": r.tau}
        finally:
            self.lib.tau_gate_free_result(pointer)
        result["seconds"] = time.perf_counter() - start
        return result


def laplacian(graph):
    n = len(graph["nodes"])
    edges = [(u, v) for u, v in graph["edges"] if u != v]
    rows = [u for u, v in edges] + [v for u, v in edges]
    columns = [v for u, v in edges] + [u for u, v in edges]
    adjacency = sparse.coo_matrix((np.ones(len(rows)), (rows, columns)), shape=(n, n)).tocsr()
    degrees = np.asarray(adjacency.sum(axis=1)).ravel()
    return sparse.diags(degrees, format="csr") - adjacency, adjacency, degrees


def reference(graph):
    matrix, adjacency, _ = laplacian(graph)
    n = matrix.shape[0]
    count, components = csgraph.connected_components(adjacency, directed=False)
    if count > 1 or n == 1:
        return {"score": 0.0, "residual": 0.0, "components": int(count),
                "method": "exact_component_count", "vector": None}
    if n <= 32:
        values, vectors = np.linalg.eigh(matrix.toarray())
        method = "numpy_dense_eigh"
    else:
        values, vectors = eigsh(matrix, k=min(4, n - 1), sigma=-1e-5, which="LM", tol=1e-12,
                                v0=np.random.default_rng(84619).normal(size=n))
        order = np.argsort(values)
        values, vectors = values[order], vectors[:, order]
        method = "scipy_arpack_shift_invert"
    value, vector = float(values[1]), vectors[:, 1]
    residual = float(np.linalg.norm(matrix @ vector - value * vector))
    assert residual < 1e-8, (graph["repository"], residual)
    assert abs(float(np.mean(vector))) < 1e-8
    return {"score": value, "residual": residual, "components": int(count), "method": method,
            "third_eigenvalue": float(values[2]) if len(values) > 2 else None,
            "vector": vector.tolist()}


def prepare(corpus, output, library):
    output.mkdir(parents=True, exist_ok=True)
    index = output / "graphs.json"
    if index.exists():
        raise SystemExit("frozen graph index already exists; reuse it")
    receipt_bytes = (corpus / "receipt.json").read_bytes()
    receipt = json.loads(receipt_bytes)
    native = Native(library)
    cases = []
    for audit in receipt["audits"]:
        if not audit.get("package_records"):
            continue
        report_path = corpus / audit["report"]
        raw = report_path.read_bytes()
        report = json.loads(raw)
        nodes = sorted("root" if p["path"] == "" else p["path"] for p in report["packages"])
        mapping = {name: i for i, name in enumerate(nodes)}
        assert len(mapping) == len(nodes)
        edges = [[mapping[e["from"]], mapping[e["to"]]] for e in report["edges"]]
        assert len(edges) == audit["edges"]
        repo = audit["repository"]
        case_id = digest((repo + "\0" + audit["lockfile"]).encode())[:16]
        graph = {"id": case_id, "repository": repo, "commit": audit["commit"],
                 "lockfile": audit["lockfile"], "nodes": nodes, "edges": edges,
                 "roots": report["introducer_roots"], "typed_edges": report["edges"],
                 "topology_complete": audit["topology_status"] == "complete",
                 "report_sha256": digest(raw),
                 "split": "development" if int(digest(repo.lower().encode())[:8], 16) % 4 == 0 else "holdout"}
        path = output / "graphs" / (case_id + ".json")
        save(path, graph)
        baseline = native.run(graph)
        oracle = reference(graph)
        save(output / "references" / (case_id + ".json"), oracle)
        cases.append({k: graph[k] for k in ("id", "repository", "lockfile", "topology_complete", "split")})
        cases[-1].update(graph_sha256=digest(path.read_bytes()), baseline=baseline,
                         original_order_diagnostic=report["topology"],
                         reference_score=oracle["score"], reference_residual=oracle["residual"],
                         components=oracle["components"])
        print(json.dumps({"prepared": len(cases), "repository": repo, "split": graph["split"],
                          "baseline_converged": baseline.get("converged")}), flush=True)
    save(index, {"corpus": str(corpus.resolve()), "corpus_receipt_sha256": digest(receipt_bytes),
                 "cohort_projects": 200, "baseline_library": native.path, "baseline_library_sha256": native.sha256,
                 "numpy_version": np.__version__, "scipy_version": scipy.__version__,
                 "node_order": "canonical label order; identical for every compared solver",
                 "split_rule": "sha256(lowercase canonical repository) first 32 bits modulo 4; zero is development",
                 "cases": cases})


def prototypes(output):
    index = json.loads((output / "graphs.json").read_text())
    results = []
    for case in index["cases"]:
        if case["split"] != "development" or case["components"] != 1:
            continue
        graph = json.loads((output / "graphs" / (case["id"] + ".json")).read_text())
        matrix, _, degree = laplacian(graph)
        n = len(degree)
        if n < 12:
            continue
        vectors = np.random.default_rng(321).normal(size=(n, 2))
        with warnings.catch_warnings(record=True) as warnings_seen:
            values, eigenvectors, history = lobpcg(matrix, vectors, M=sparse.diags(1 / degree),
                                                  Y=np.ones((n, 1)), largest=False,
                                                  tol=1e-9, maxiter=2000, retResidualNormsHistory=True)
        residual = float(np.linalg.norm(matrix @ eigenvectors[:, 0] - values[0] * eigenvectors[:, 0]))
        result = {"repository": case["repository"], "iterations": len(history) - 3,
                  "residual": residual, "score": float(values[0]), "oracle": case["reference_score"],
                  "warnings": len(warnings_seen)}
        results.append(result)
        print(json.dumps(result), flush=True)
    save(output / "scipy-lobpcg-development.json", results)


def compare(output, candidate, repeats, split):
    index = json.loads((output / "graphs.json").read_text())
    before = Native(Path(index["baseline_library"]))
    assert before.sha256 == index["baseline_library_sha256"]
    after = Native(candidate)
    results = []
    for case in index["cases"]:
        if split and case["split"] != split:
            continue
        path = output / "graphs" / (case["id"] + ".json")
        assert digest(path.read_bytes()) == case["graph_sha256"]
        graph = json.loads(path.read_text())
        runs = {"before": [], "after": []}
        for repetition in range(repeats):
            order = [("before", before), ("after", after)]
            if repetition % 2:
                order.reverse()
            for name, solver in order:
                runs[name].append(solver.run(graph))
        result = {**{k: v for k, v in case.items() if k != "baseline"}, "runs": runs}
        for name, values in runs.items():
            valid = [r for r in values if "error" not in r]
            errors = len(values) - len(valid)
            deterministic = len({json.dumps({k: v for k, v in r.items() if k != "seconds"}, sort_keys=True)
                                 for r in valid}) == 1
            result[name] = {"errors": errors, "deterministic": deterministic,
                            "median_seconds": statistics.median(r["seconds"] for r in values),
                            "range_seconds": [min(r["seconds"] for r in values), max(r["seconds"] for r in values)]}
            if valid:
                r = valid[0]
                result[name].update({k: v for k, v in r.items() if k != "seconds"})
                error = abs(r["score"] - case["reference_score"])
                result[name].update(eigenvalue_absolute_error=error,
                                    oracle_agreement=error <= max(1e-9, abs(case["reference_score"]) * 1e-6),
                                    residual_below_tolerance=r["residual"] < 1e-9)
        results.append(result)
        print(json.dumps({"repository": case["repository"], "after": {k: result["after"].get(k) for k in
                          ("converged", "residual", "oracle_agreement", "iterations")}}), flush=True)
    summary = {}
    for scope in ("all", "development", "holdout", "complete_holdout"):
        cases = [r for r in results if scope == "all" or r["split"] == scope
                 or scope == "complete_holdout" and r["split"] == "holdout" and r["topology_complete"]]
        summary[scope] = {"reports": len(cases)}
        for side in ("before", "after"):
            summary[scope][side] = {"converged": sum(r[side].get("converged", False) for r in cases),
                                     "oracle_agreement": sum(r[side].get("oracle_agreement", False) for r in cases),
                                     "errors": sum(r[side]["errors"] for r in cases),
                                     "deterministic": all(r[side]["deterministic"] for r in cases)}
    save(output / ("comparison-" + split + ".json" if split else "comparison.json"), {"baseline_sha256": before.sha256, "candidate_sha256": after.sha256,
                                       "repeats": repeats, "summary": summary, "cases": results})
    print(json.dumps(summary, indent=2), flush=True)


def partition_metrics(side, adjacency):
    n = len(adjacency)
    size = len(side)
    if size == 0 or size == n:
        return None
    volume = sum(len(adjacency[u]) for u in side)
    total = sum(map(len, adjacency))
    cut = sum(v not in side for u in side for v in adjacency[u])
    denominator = min(volume, total - volume)
    return {"nodes": size, "smaller_fraction": min(size, n - size) / n,
            "cut_edges": cut, "volume": volume,
            "ratio_cut": cut * (1 / size + 1 / (n - size)),
            "conductance": cut / denominator if denominator else None}


def simple_partitions(graph, adjacency):
    n = len(adjacency)
    mapping = {label: i for i, label in enumerate(graph["nodes"])}
    roots = [mapping[r] for r in graph["roots"] if r in mapping]
    parent = [None] * n
    seen = set()
    order = []
    for root in roots + list(range(n)):
        if root in seen:
            continue
        seen.add(root)
        queue = collections.deque([root])
        while queue:
            u = queue.popleft()
            order.append(u)
            for v in sorted(set(adjacency[u])):
                if v not in seen:
                    seen.add(v)
                    parent[v] = u
                    queue.append(v)
    subtrees = [{i} for i in range(n)]
    best = {"ratio_cut": None, "conductance": None}
    counts = collections.Counter()

    def consider(side, method):
        metrics = partition_metrics(side, adjacency)
        if metrics is None:
            return
        if method == "bfs_subtree" and metrics["cut_edges"] <= 1:
            method = "component" if metrics["cut_edges"] == 0 else "bridge"
        counts[method] += 1
        for objective in best:
            value = metrics[objective]
            if value is not None and (best[objective] is None or value < best[objective]["metrics"][objective]):
                best[objective] = {"method": method, "metrics": metrics,
                                   "partition": sorted(graph["nodes"][i] for i in side)}

    for u in reversed(order):
        consider(subtrees[u], "bfs_subtree")
        if parent[u] is not None:
            subtrees[parent[u]].update(subtrees[u])
    side = set()
    degrees = sorted(range(n), key=lambda i: (len(adjacency[i]), graph["nodes"][i]))
    for offset, u in enumerate(degrees):
        side.add(u)
        if offset + 1 < n and len(adjacency[u]) != len(adjacency[degrees[offset + 1]]):
            consider(side, "degree_threshold")
    return best, dict(counts)


def structural(output):
    comparison = json.loads((output / "comparison.json").read_text())
    rows = []
    for case in comparison["cases"]:
        graph = json.loads((output / "graphs" / (case["id"] + ".json")).read_text())
        mapping = {name: i for i, name in enumerate(graph["nodes"])}
        adjacency = [[] for _ in graph["nodes"]]
        for u, v in graph["edges"]:
            if u != v:
                adjacency[u].append(v)
                adjacency[v].append(u)
        baseline, counts = simple_partitions(graph, adjacency)
        row = {"id": case["id"], "repository": case["repository"], "lockfile": case["lockfile"],
               "split": case["split"], "topology_complete": case["topology_complete"],
               "components": case["components"], "baseline_candidates": counts, "basic": baseline}
        for name in ("before", "after"):
            row[name] = partition_metrics({mapping[label] for label in case[name]["partition"]}, adjacency)
        rows.append(row)
        print(json.dumps({"repository": case["repository"], "structural": "measured"}), flush=True)
    summaries = {}
    for split in ("development", "holdout"):
        selected = [r for r in rows if r["split"] == split and r["topology_complete"] and r["components"] == 1]
        summaries[split] = {"connected_complete_graphs": len(selected)}
        for objective in ("ratio_cut", "conductance"):
            outcomes = collections.Counter()
            improvements = []
            for row in selected:
                a = row["after"][objective] if row["after"] else None
                b = row["basic"][objective]["metrics"][objective] if row["basic"][objective] else None
                if a is None or b is None:
                    outcomes["unavailable"] += 1
                elif abs(a - b) <= 1e-10 * max(1, abs(a), abs(b)):
                    outcomes["tie"] += 1
                elif a < b:
                    outcomes["spectral_better"] += 1
                    improvements.append({"repository": row["repository"], "relative_reduction": 1 - a / b,
                                         "basic": b, "spectral": a})
                else:
                    outcomes["basic_better"] += 1
            summaries[split][objective] = {"outcomes": dict(outcomes),
                                           "spectral_improvements": sorted(improvements, key=lambda r: -r["relative_reduction"])}
    save(output / "structural.json", {"scope": "structural cut quality; no human review or security labels",
                                       "baselines": "all rooted BFS spanning-tree subtree cuts, including bridges/components, plus degree thresholds",
                                       "summary": summaries, "cases": rows})
    print(json.dumps(summaries, indent=2), flush=True)


def controls(output, library):
    solver = Native(library)
    results = []
    for seed in range(40):
        rng = np.random.default_rng(seed + 7821)
        n = 8 + seed * 2
        edges = {(i, int(rng.integers(i))) for i in range(1, n)}
        for _ in range(n * (seed % 5)):
            u, v = map(int, rng.integers(n, size=2))
            if u != v:
                edges.add((u, v))
        permutation = rng.permutation(n)
        graph = {"repository": f"numerical-control-{seed}", "nodes": [str(i) for i in range(n)],
                 "edges": [[int(permutation[u]), int(permutation[v])] for u, v in sorted(edges)]}
        oracle = reference(graph)
        result = solver.run(graph)
        assert result.get("converged") and result["residual"] < 1e-9, (seed, result)
        error = abs(result["score"] - oracle["score"])
        assert error < max(1e-9, 1e-6 * abs(oracle["score"])), (seed, error)
        results.append({"seed": seed, "nodes": n, "edges": len(edges), "residual": result["residual"],
                        "absolute_eigenvalue_error": error, "iterations": result["iterations"]})
    save(output / "numerical-controls.json", {"library_sha256": solver.sha256, "cases": results})
    print(json.dumps({"numerical_controls_passed": len(results)}), flush=True)


def audit_replay(output, binary):
    index = json.loads((output / "graphs.json").read_text())
    corpus = Path(index["corpus"])
    receipt = json.loads((corpus / "receipt.json").read_text())
    results = []
    for audit in receipt["audits"]:
        command = [str(binary.resolve()), *audit["command"][1:]]
        proc = subprocess.run(command, cwd=corpus, capture_output=True, text=True, timeout=180)
        before = json.loads((corpus / audit["report"]).read_text())
        after = json.loads(proc.stdout)
        path = output / "candidate-audits" / (digest((audit["repository"] + "\0" + audit["lockfile"]).encode())[:16] + ".json")
        save(path, after)
        before.pop("topology", None)
        after.pop("topology", None)
        assert before == after, (audit["repository"], audit["lockfile"])
        assert proc.returncode == audit["exit_code"], (audit["repository"], proc.returncode)
        results.append({"repository": audit["repository"], "lockfile": audit["lockfile"],
                        "exit_code": proc.returncode, "non_math_report_unchanged": True,
                        "candidate_report": str(path.relative_to(output)), "command": command})
    for snapshot in receipt["snapshots"]:
        folder = corpus / "repositories" / snapshot["repository"].replace("/", "__") / "source"
        for file in snapshot.get("files", []):
            assert digest((folder / file["path"]).read_bytes()) == file["sha256"]
    save(output / "audit-replay.json", {"binary_sha256": digest(binary.read_bytes()),
                                        "cohort_projects": 200, "audits": len(results), "cases": results})
    print(json.dumps({"audit_reports_unchanged_outside_math": len(results), "source_input_hashes": "unchanged"}), flush=True)


def end_to_end(output, binary):
    index = json.loads((output / "graphs.json").read_text())
    corpus = Path(index["corpus"])
    receipt = json.loads((corpus / "receipt.json").read_text())
    by_pair = {(a["repository"], a["lockfile"]): a for a in receipt["audits"]}
    cases = sorted((c for c in index["cases"] if c["topology_complete"] and c["components"] == 1), key=lambda c: c["id"])[:10]
    baseline = Path(index["baseline_library"]).with_name("tau-gate")
    assert digest(baseline.read_bytes()) == receipt["binary_sha256"]
    results = []
    for case in cases:
        audit = by_pair[case["repository"], case["lockfile"]]
        times = {"before": [], "after": []}
        for repetition in range(5):
            order = [("before", baseline), ("after", binary)]
            if repetition % 2:
                order.reverse()
            for side, executable in order:
                start = time.perf_counter()
                proc = subprocess.run([str(executable.resolve()), *audit["command"][1:]], cwd=corpus,
                                      capture_output=True, text=True, timeout=180)
                report = json.loads(proc.stdout)
                times[side].append(time.perf_counter() - start)
                assert proc.returncode == audit["exit_code"]
                assert report["lock_sha256"] == audit["lock_sha256"]
                assert len(report["packages"]) == audit["package_records"]
                if side == "after":
                    assert report["topology"]["residual_converged"]
                    assert abs(report["topology"]["score"] - case["reference_score"]) < max(1e-9, abs(case["reference_score"]) * 1e-6)
        results.append({"repository": case["repository"], "lockfile": case["lockfile"], "seconds": times})
    save(output / "end-to-end-timing.json", {"scope": "10 deterministic connected complete cases; five alternating process-level audit runs per binary",
                                             "quality_caveat": "baseline and candidate have different numerical accuracy; no accuracy-equivalent speedup is claimed",
                                             "candidate_binary_sha256": digest(binary.read_bytes()), "cases": results})
    print(json.dumps({"end_to_end_cases": len(results), "runs_per_case_and_binary": 5}), flush=True)


def profile(output, library):
    index = json.loads((output / "graphs.json").read_text())
    graphs = [json.loads((output / "graphs" / (case["id"] + ".json")).read_text())
              for case in index["cases"] if case["topology_complete"] and case["components"] == 1]
    graph = max(graphs, key=lambda graph: len(graph["nodes"]))
    native = Native(library)
    (output / "profile-pid.txt").write_text(str(os.getpid()))
    start = time.perf_counter()
    calls = 0
    while time.perf_counter() - start < 8:
        result = native.run(graph)
        assert result.get("converged")
        calls += 1
    save(output / "profile-run.json", {"repository": graph["repository"], "nodes": len(graph["nodes"]),
                                        "edges": len(graph["edges"]), "native_calls": calls,
                                        "candidate_sha256": native.sha256,
                                        "scope": "instrumented profiling run excluded from reported timings"})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "prototype", "compare", "structural", "controls", "audit-replay", "end-to-end", "profile"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--corpus", type=Path)
    parser.add_argument("--library", type=Path)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--split", choices=("development", "holdout"))
    args = parser.parse_args()
    if args.mode == "prepare":
        prepare(args.corpus, args.output, args.library)
    elif args.mode == "prototype":
        prototypes(args.output)
    elif args.mode == "structural":
        structural(args.output)
    elif args.mode == "controls":
        controls(args.output, args.library)
    elif args.mode == "audit-replay":
        audit_replay(args.output, args.binary)
    elif args.mode == "end-to-end":
        end_to_end(args.output, args.binary)
    elif args.mode == "profile":
        profile(args.output, args.library)
    else:
        compare(args.output, args.library, args.repeats, args.split)


if __name__ == "__main__":
    main()
