#!/usr/bin/env python3
"""Measure pnpm's version-pinned build approvals on controlled marker archives."""

import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import sys
import tempfile
import threading

sys.dont_write_bytecode = True

from npm3_native_comparison import (Case, NAME, environment, fixture, run,
                                    snapshot_canaries, write_json)
from npm_evidence import EvidenceError, sha256
from npm_reference import registry


CASES = (
    Case("unchanged_approved", "Unchanged version-pinned approved build."),
    Case("same_url_hook_changed", "Same version and URL, changed hook and updated lock integrity.", command="changed"),
    Case("new_version_unapproved", "New version with only the baseline version approved.", version="2.0.0", expected_version="blocked"),
    Case("old_sri_tamper", "Changed archive against the baseline integrity token. Shared integrity control.", payload="changed", stale_integrity=True, expected_version="blocked"),
    Case("fresh_version_approved", "New version with its exact version explicitly approved.", version="2.0.0", fresh=True),
)


def workspace_policy(version):
    return ("packages: []\nallowBuilds:\n  " + json.dumps(NAME + "@" + version) +
            ": true\nstrictDepBuilds: true\nverifyStoreIntegrity: true\n")


def compare(output, pnpm, node):
    if output.exists() and any(output.iterdir()):
        raise EvidenceError("output must be absent or empty")
    output.mkdir(parents=True, exist_ok=True)
    pnpm, node = pnpm.resolve(), node.resolve()
    implementation = pnpm.parent.parent / "dist/pnpm.cjs"
    implementation_bytes = implementation.read_bytes()
    (output / "pnpm-implementation.cjs").write_bytes(implementation_bytes)
    source_lines = implementation_bytes.decode().splitlines()
    fragments = ("if (pnpmSettings.allowBuilds)", "function createAllowBuildFunction(opts)",
                 "onlyBuiltDependencies.has(`${pkgName}@${version2}`)", "opts.strictDepBuilds && ignoredBuilds")
    references = {fragment: [i + 1 for i, line in enumerate(source_lines) if fragment in line] for fragment in fragments}
    if not all(references.values()):
        raise EvidenceError("installed source does not expose the qualified policy rules")
    source_receipt = {"pnpm_cli": {"path": str(pnpm), "sha256": sha256(pnpm.read_bytes())},
                      "implementation": {"path": str(implementation), "sha256": sha256(implementation_bytes), "references": references},
                      "node": {"path": str(node), "sha256": sha256(node.read_bytes())},
                      "helper_sha256": sha256(Path(__file__).read_bytes()),
                      "reused_helper_sha256": sha256(Path(__file__).with_name("npm3_native_comparison.py").read_bytes())}
    write_json(output / "source-receipt.json", source_receipt)
    packages, requests = {}, []
    server = registry(packages, requests)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}/"
    results = []
    try:
        with tempfile.TemporaryDirectory(prefix="tau-pnpm-native-") as temp:
            private = Path(temp)
            probe = private / "probe"
            probe.mkdir()
            env = environment(probe, node, url, probe / "canaries")
            command = [node, pnpm]
            version_receipt, stdout = run(command + ["--version"], probe, env, output / "capability", "pnpm-version")
            version = stdout.decode().strip()
            if version_receipt["returncode"] or version != "10.33.4":
                raise EvidenceError("this adjunct pins installed pnpm 10.33.4")
            frozen = {"schema_version": 1, "frozen_at": datetime.now(timezone.utc).isoformat(),
                      "cases": [{"fixture": asdict(case), "expected_native": case.expected_version} for case in CASES],
                      "pnpm_version": version, "policy": workspace_policy("1.0.0"),
                      "install_flags": ["--frozen-lockfile", "--ignore-scripts=false", "--reporter=append-only"],
                      "protocol": "IPv4 loopback HTTP controlled registry archives only.",
                      "store": "Unique private store per case, emptied after scripts-disabled lock generation. No cross-case side-effect cache reuse.",
                      "trust_boundary": "Workspace policy comes from controlled baseline, except explicitly fresh positive control. Strict missing approval and store integrity remain enabled.",
                      "scope": "Native pnpm permission granularity only. Tau-Gate pnpm execution enforcement remains unqualified. No full pnpm comparison or production claim."}
            write_json(output / "frozen-matrix.json", frozen)
            frozen_hash = sha256((output / "frozen-matrix.json").read_bytes())
            for case in CASES:
                directory = output / "cases" / case.name
                project = private / case.name
                project.mkdir()
                canaries = project / "canaries"
                canaries.mkdir()
                env = environment(project / "private", node, url, canaries)
                env["CI"] = "true"
                env["PNPM_UPDATE_NOTIFICATION"] = "false"
                package = fixture(case)
                packages.clear()
                packages[NAME + "@" + case.version] = package
                write_json(project / "package.json", {"name": "tau-pnpm-control-root", "version": "1.0.0", "private": True,
                                                      "dependencies": {NAME: case.version}})
                policy = workspace_policy(case.version if case.fresh else "1.0.0")
                (project / "pnpm-workspace.yaml").write_text(policy)
                store = project / "private/store"
                common = ["--store-dir", store, "--reporter=append-only"]
                lock_receipt, _ = run(command + ["install", "--lockfile-only", "--ignore-scripts", *common],
                                      project, env, directory, "generate-lock")
                if lock_receipt["returncode"] or snapshot_canaries(canaries):
                    raise EvidenceError("scripts-disabled pnpm lock generation failed or executed code")
                lock_path = project / "pnpm-lock.yaml"
                if case.stale_integrity:
                    lock = lock_path.read_text()
                    current = package["integrity"]
                    if lock.count(current) != 1:
                        raise EvidenceError("pnpm lock integrity token was not uniquely identified")
                    lock_path.write_text(lock.replace(current, fixture(Case("base", ""))["integrity"]))
                if store.exists():
                    shutil.rmtree(store)
                for name in ("package.json", "pnpm-workspace.yaml", "pnpm-lock.yaml"):
                    shutil.copyfile(project / name, directory / name)
                (directory / "fixture.tgz").write_bytes(package["archive"])
                receipt, _ = run(command + ["install", "--frozen-lockfile", "--ignore-scripts=false", *common],
                                 project, env, directory, "pnpm-install")
                markers = snapshot_canaries(canaries)
                outcome = "executed" if markers else "blocked" if receipt["returncode"] else "no_execution"
                installed = project / "node_modules" / NAME / "package.json"
                installed_hash = sha256(installed.read_bytes()) if installed.exists() else None
                expected_markers = {case.command + "-install": "executed"} if outcome == "executed" else {}
                result = {"case": case.name, "change": case.change, "expected": case.expected_version,
                          "outcome": outcome, "exit_code": receipt["returncode"], "markers": markers,
                          "markers_match": markers == expected_markers,
                          "installed_manifest_sha256": installed_hash,
                          "installed_manifest_matches_fixture": installed_hash == sha256(package["manifest_bytes"]) if receipt["returncode"] == 0 else None,
                          "lock_sha256": sha256(lock_path.read_bytes()), "fixture_archive_sha256": sha256(package["archive"]),
                          "policy": policy}
                result["pass"] = (outcome == case.expected_version and result["markers_match"] and
                                  result["installed_manifest_matches_fixture"] is not False)
                write_json(directory / "result.json", result)
                results.append(result)
                print(case.name + " " + outcome + " exit=" + str(receipt["returncode"]), flush=True)
            if sha256((output / "frozen-matrix.json").read_bytes()) != frozen_hash:
                raise EvidenceError("frozen adjunct matrix changed")
            receipt = {"schema_version": 1, "pnpm_version": version, "frozen_matrix_sha256": frozen_hash,
                       "results": results, "unexpected_cases": [row["case"] for row in results if not row["pass"]],
                       "loopback_requests": requests, "scope": frozen["scope"]}
            write_json(output / "receipt.json", receipt)
            lines = ["# pnpm native approval adjunct", "",
                     "Measured pnpm 10.33.4 with an exact-version `allowBuilds` policy, `strictDepBuilds: true` and `verifyStoreIntegrity: true`. "
                     "Only private loopback fixture hooks wrote marker files. Each install had a fresh private store.", "",
                     "| Controlled change | Native outcome | Exit |", "|---|---|---|"]
            lines += [f"| {row['case']} | {row['outcome']} | {row['exit_code']} |" for row in results]
            lines += ["", "These observations describe native pnpm approval granularity. Tau-Gate pnpm execution evidence remains unqualified. "
                      "This adjunct makes no claim that Tau-Gate replaces pnpm build approvals. "
                      "Unchanged-integrity archive rejection is shared package-manager integrity protection.", "",
                      f"Completed {len(results)} controls with {len(receipt['unexpected_cases'])} unexpected outcomes. "
                      "Raw logs, exact tarballs, lockfiles, workspace policies, marker observations and the installed implementation are retained."]
            (output / "summary.md").write_text("\n".join(lines) + "\n")
            write_json(output / "artifact-sha256.json", {str(path.relative_to(output)): sha256(path.read_bytes()) for path in sorted(output.rglob("*")) if path.is_file()})
            return receipt
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--pnpm", type=Path, required=True, help="Exact installed pnpm bin/pnpm.cjs")
    parser.add_argument("--node", type=Path, required=True)
    args = parser.parse_args()
    try:
        receipt = compare(args.output, args.pnpm, args.node)
    except (EvidenceError, OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0 if not receipt["unexpected_cases"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
