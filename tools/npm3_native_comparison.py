#!/usr/bin/env python3
"""Compare exact npm native approvals and Tau-Gate using private marker fixtures."""

import argparse
import base64
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import threading

sys.dont_write_bytecode = True

from npm_evidence import EvidenceError, collect_evidence, json_bytes, sha256
from npm_reference import canary_scripts, registry, tarball_path
from verify_npm_evidence import encoded, tar_for, zipped


NAME = "tau-native-control"
INSTANCE = "node_modules/" + NAME
POLICIES = ("exact_version", "exact_source_url")


@dataclass(frozen=True)
class Case:
    name: str
    change: str
    baseline: str = "hook"
    version: str = "1.0.0"
    command: str = "approved"
    payload: str = "original"
    metadata: str = "original"
    source: str = "original"
    fresh: bool = False
    missing_evidence: bool = False
    stale_integrity: bool = False
    self_edit: bool = False
    root_command: str = ""
    expected_version: str = "executed"
    expected_source: str = "executed"
    expected_tau: str = "allowed"


CASES = (
    Case("unchanged", "Unchanged approved dependency."),
    Case("command_changed", "Same version and URL, changed install body and updated lock integrity.", command="changed", expected_tau="blocked"),
    Case("version_changed", "New version with unchanged install body.", version="2.0.0", expected_version="blocked", expected_source="blocked", expected_tau="blocked"),
    Case("archive_payload_changed", "Same manifest and lifecycle, changed non-lifecycle archive payload and updated integrity.", payload="changed", expected_tau="blocked"),
    Case("hook_metadata_changed", "Hook-bearing package description changes without changing the lifecycle body. Conservative reapproval cost.", metadata="changed", expected_tau="blocked"),
    Case("source_changed", "Identical artifact at another resolved URL.", source="mirror", expected_source="blocked", expected_tau="blocked"),
    Case("integrity_tamper", "Changed archive served against unchanged lock integrity. Shared integrity control.", payload="changed", stale_integrity=True, expected_version="blocked", expected_source="blocked", expected_tau="incomplete"),
    Case("missing_evidence", "Original archive remains available to npm, but Tau-Gate bundle omits its locator.", missing_evidence=True, expected_tau="incomplete"),
    Case("no_hook_metadata_changed", "Non-executing package metadata and archive change.", baseline="plain", command="", metadata="changed", expected_version="no_execution", expected_source="no_execution"),
    Case("no_hook_version_changed", "Non-executing package version change.", baseline="plain", version="2.0.0", command="", expected_version="no_execution", expected_source="no_execution"),
    Case("new_unapproved_hook", "A formerly script-free package gains an install hook with no native or Tau-Gate approval.", baseline="plain", command="changed", expected_version="blocked", expected_source="blocked", expected_tau="blocked"),
    Case("legitimate_command_approved", "Changed command explicitly receives a fresh approval.", command="changed", fresh=True),
    Case("legitimate_version_approved", "New version explicitly receives a fresh native policy and Tau-Gate approval.", version="2.0.0", fresh=True),
    Case("policy_self_edit", "Head adds its own new-version approvals; trusted-base wrapper restores both native policy and Tau-Gate approvals.", version="2.0.0", self_edit=True, expected_version="blocked", expected_source="blocked", expected_tau="blocked"),
    Case("root_unchanged", "Unchanged approved root-source install body.", baseline="root", command="", root_command="root-approved"),
    Case("root_command_changed", "Root-source install body changes with old source approval.", baseline="root", command="", root_command="root-changed", expected_tau="blocked"),
    Case("legitimate_root_approved", "Root-source command change receives fresh source approval.", baseline="root", command="", root_command="root-changed", fresh=True),
)


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(json_bytes(value))


def run(argv, cwd, env, output, label):
    result = subprocess.run([str(value) for value in argv], cwd=cwd, env=env,
                            capture_output=True, timeout=90, check=False)
    output.mkdir(parents=True, exist_ok=True)
    (output / (label + ".stdout")).write_bytes(result.stdout)
    (output / (label + ".stderr")).write_bytes(result.stderr)
    receipt = {"argv": [str(value) for value in argv], "returncode": result.returncode,
               "stdout_sha256": sha256(result.stdout), "stderr_sha256": sha256(result.stderr)}
    write_json(output / (label + ".json"), receipt)
    return receipt, result.stdout


def fixture(case):
    manifest = {"name": NAME, "version": case.version, "description": case.metadata}
    if case.command:
        manifest["scripts"] = canary_scripts(["install"], case.command)
    archive = zipped(tar_for(manifest, case.payload.encode()))
    return {"manifest": manifest, "manifest_bytes": encoded(manifest), "archive": archive,
            "integrity": "sha512-" + base64.b64encode(hashlib.sha512(archive).digest()).decode()}


def native_policy(kind, case, base_url):
    if case.baseline != "hook" and not case.fresh:
        return {}
    key = NAME + "@" + case.version if kind == "exact_version" else base_url + tarball_path(fixture(case)["manifest"])
    return {key: True}


def root_manifest(case, policy):
    root = {"name": "tau-native-control-root", "version": "1.0.0", "private": True,
            "dependencies": {NAME: case.version}, "allowScripts": policy}
    if case.root_command:
        root["scripts"] = canary_scripts(["install"], case.root_command)
    return root


def environment(private, node, registry_url, canaries):
    for child in ("home", "cache", "tmp"):
        (private / child).mkdir(parents=True, exist_ok=True)
    for child in ("user.npmrc", "global.npmrc"):
        (private / child).write_text("")
    return {"PATH": str(node.parent) + ":/usr/bin:/bin", "HOME": str(private / "home"),
            "TMPDIR": str(private / "tmp"), "npm_config_cache": str(private / "cache"),
            "npm_config_userconfig": str(private / "user.npmrc"),
            "npm_config_globalconfig": str(private / "global.npmrc"),
            "npm_config_prefix": str(private / "prefix"), "npm_config_registry": registry_url,
            "npm_config_update_notifier": "false", "npm_config_audit": "false",
            "npm_config_fund": "false", "npm_config_fetch_retries": "0",
            "TAU_GATE_CANARY_DIR": str(canaries)}


def tau_audit(binary, project, index, approvals, env, output, label, enforce=False):
    args = [binary, "audit", "--lock", project / "package-lock.json", "--manifest", project / "package.json",
            "--evidence", index, "--approvals", approvals, "--json"]
    if enforce:
        args.append("--enforce")
    receipt, stdout = run(args, project, env, output, label)
    report = json.loads(stdout)
    return receipt, report


def policy_from_report(report):
    return {"schema_version": 2, "approvals": [
        {"path": item["path"], "fingerprints": [item["approval_fingerprint"]]}
        for item in report["execution_evidence"] if item["candidate"] and item["approval_fingerprint"]]}


def source_receipt(npm, node, binary, output):
    source = npm.parent.parent
    files = ("package.json", "lib/commands/ci.js", "lib/utils/resolve-allow-scripts.js",
             "lib/utils/strict-allow-scripts-preflight.js", "node_modules/@npmcli/arborist/lib/script-allowed.js",
             "node_modules/@npmcli/arborist/lib/unreviewed-scripts.js", "node_modules/@npmcli/arborist/lib/install-scripts.js",
             "node_modules/@npmcli/arborist/lib/arborist/rebuild.js")
    receipts = []
    for relative in files:
        data = (source / relative).read_bytes()
        target = output / "npm-source" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        receipts.append({"relative_path": relative, "source": str(source / relative), "sha256": sha256(data)})
    return {"npm_source": receipts, "node": {"path": str(node), "sha256": sha256(node.read_bytes())},
            "npm_cli": {"path": str(npm), "sha256": sha256(npm.read_bytes())},
            "tau_gate": {"path": str(binary), "sha256": sha256(binary.read_bytes())},
            "helper_sha256": sha256(Path(__file__).read_bytes()),
            "reused_helpers": {name: sha256(Path(__file__).with_name(name).read_bytes())
                               for name in ("npm_evidence.py", "npm_reference.py", "verify_npm_evidence.py")}}


def prepare(case, private, output, npm_cmd, node, base_url, packages):
    project = private / "project"
    project.mkdir(parents=True)
    canaries = private / "canaries"
    canaries.mkdir()
    env = environment(private, node, base_url, canaries)
    package = fixture(case)
    packages.clear()
    packages[NAME + "@" + case.version] = package
    write_json(project / "package.json", root_manifest(case, native_policy("exact_source_url", case, base_url)))
    receipt, _ = run(npm_cmd + ["install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"],
                     project, env, output, "generate-lock")
    if receipt["returncode"] != 0:
        raise EvidenceError("fixture lock generation failed, inspect " + str(output))
    if list(canaries.iterdir()):
        raise EvidenceError("scripts-disabled lock generation executed a canary")
    lock = json.loads((project / "package-lock.json").read_bytes())
    if case.source == "mirror":
        lock["packages"][INSTANCE]["resolved"] = base_url + "mirror/" + tarball_path(package["manifest"])
    if case.stale_integrity:
        lock["packages"][INSTANCE]["integrity"] = fixture(Case("base", ""))["integrity"]
    write_json(project / "package-lock.json", lock)
    output.mkdir(parents=True, exist_ok=True)
    for filename in ("package.json", "package-lock.json"):
        shutil.copyfile(project / filename, output / filename)
    (output / "fixture.tgz").write_bytes(package["archive"])
    return project, canaries, env


def acquire(project, output):
    try:
        return collect_evidence(project / "package-lock.json", project, output / "evidence", allow_loopback=True), None
    except EvidenceError as exc:
        return output / "evidence/index.json", str(exc)


def snapshot_canaries(canaries):
    return {path.name: path.read_text() for path in sorted(canaries.iterdir())}


def native_run(case, kind, project, canaries, env, output, npm_cmd, trusted_policy):
    head = json.loads((project / "package.json").read_bytes())
    if case.self_edit:
        head["allowScripts"] = native_policy(kind, Case("head", "", version=case.version, fresh=True), env["npm_config_registry"])
    else:
        head["allowScripts"] = trusted_policy
    write_json(output / "proposed-package.json", head)
    head["allowScripts"] = trusted_policy
    write_json(project / "package.json", head)
    write_json(output / "effective-package.json", head)
    before = snapshot_canaries(canaries)
    for path in canaries.iterdir():
        path.unlink()
    receipt, _ = run(npm_cmd + ["ci", "--strict-allow-scripts", "--foreground-scripts", "--ignore-scripts=false", "--no-audit", "--no-fund"],
                     project, env, output, "npm-ci")
    markers = snapshot_canaries(canaries)
    installed_manifest = project / INSTANCE / "package.json"
    installed_hash = sha256(installed_manifest.read_bytes()) if installed_manifest.exists() else None
    expected_hash = sha256(fixture(case)["manifest_bytes"])
    for path in canaries.iterdir():
        path.unlink()
    outcome = "executed" if markers else "blocked" if receipt["returncode"] else "no_execution"
    result = {"outcome": outcome, "exit_code": receipt["returncode"], "markers": markers,
              "trusted_policy": trusted_policy, "head_policy_replaced": case.self_edit,
              "installed_manifest_sha256": installed_hash,
              "installed_manifest_matches_fixture": installed_hash == expected_hash if receipt["returncode"] == 0 else None,
              "pre_run_canaries": before, "command_receipt": "npm-ci.json"}
    write_json(output / "result.json", result)
    return result


def write_summary(output, receipt):
    lines = ["# Controlled native approval comparison", "",
             "This local experiment ran npm 11.19.1 with Node v26.9.0 against private loopback tarballs. "
             "Every executed lifecycle body only wrote a named marker file. No public package script ran.", "",
             "Both native policies used `npm ci --strict-allow-scripts` with isolated configuration and cache. "
             "The first pins `name@version`. The stronger comparator pins the exact resolved tarball URL, which also contains its version. "
             "The controlled trusted wrapper supplies baseline `allowScripts` and baseline Tau-Gate approvals. "
             "Fresh approval rows intentionally use a separately generated fixture policy.", "",
             "| Controlled change | Exact version | Exact source URL | Tau-Gate |", "|---|---|---|---|"]
    for row in receipt["cases"]:
        observed = row["observed"]
        lines.append("| " + row["case"] + " | " + " | ".join(observed[key] for key in (*POLICIES, "tau_gate")) + " |")
    lines += ["", "`executed` requires actual marker files. `blocked` means a nonzero native exit with no markers. "
              "`no_execution` means native exit 0 without markers. Tau-Gate outcomes are its reported enforcement decisions and exit codes.", "",
              "The exact URL native policy already rejects version and source movement. Both native policies reject unchanged-integrity archive substitution. "
              "That integrity protection is shared and is not a Tau-Gate-exclusive result. The stale command, payload and metadata rows update lock integrity deliberately.", "",
              "Tau-Gate adds approval binding to archive bytes and lifecycle facts under an unchanged package version and URL. "
              "It also checks separately supplied evidence and root source approvals. npm treats root scripts as owner-managed code. "
              "The missing-evidence row removes a Tau-Gate locator while leaving the archive available to npm, so it demonstrates an evidence requirement rather than an npm integrity bypass.", "",
              "The archive-payload and hook-metadata rows also measure the cost of strict byte binding. "
              "Neither fixture changes the lifecycle command, but both require a fresh Tau-Gate fingerprint. "
              "Script-free metadata and version changes remain allowed. Explicitly approved command, version and root-source changes remain allowed.", "",
              "These synthetic cases do not estimate prevalence, malicious intent, review time, performance, public registry mutability, "
              "or production CI behavior. The wrapper uses private baseline snapshots, not a live pull request. "
              "pnpm, workspaces, optional selection and implicit native builds are outside this comparison. "
              "npm 11.19.1 is the installed comparator; no claim about a newer release is made.", "",
              "The primary expectations were frozen before its first install. A separate development pilot established helper plumbing. "
              "All primary mismatches remain in receipt.json without changing the frozen matrix.", "",
              f"Completed {len(receipt['cases'])} cases with {len(receipt['unexpected_cases'])} unexpected cases. "
              f"The frozen matrix SHA256 is `{receipt['frozen_matrix_sha256']}`. "
              "The candidate hash, runtime hashes, installed npm source snapshots, commands, marker observations, input tarballs, lockfiles, policies and raw Tau-Gate reports are retained beside this file."]
    (output / "summary.md").write_text("\n".join(lines) + "\n")


def run_comparison(output, npm, node, binary):
    if output.exists() and any(output.iterdir()):
        raise EvidenceError("output must be absent or empty; prior experiments are never overwritten")
    output.mkdir(parents=True, exist_ok=True)
    npm, node, binary = npm.resolve(), node.resolve(), binary.resolve()
    receipts = source_receipt(npm, node, binary, output)
    packages, requests, original_requests = {}, [], []
    server = registry(packages, requests)
    original_handler = server.RequestHandlerClass
    class MirrorHandler(original_handler):
        def do_GET(self):
            original_requests.append(self.path)
            self.path = self.path.removeprefix("/mirror") if self.path.startswith("/mirror/") else self.path
            return super().do_GET()
    server.RequestHandlerClass = MirrorHandler
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}/"
    npm_cmd = [node, npm]
    results = []
    try:
        with tempfile.TemporaryDirectory(prefix="tau-native-comparison-") as temp:
            private = Path(temp)
            probe = private / "probe"
            probe.mkdir()
            env = environment(probe, node, base_url, probe / "canaries")
            versions = {}
            for label, command in (("node-version", [node, "--version"]), ("npm-version", npm_cmd + ["--version"]),
                                   ("strict-capability", npm_cmd + ["config", "get", "strict-allow-scripts"])):
                receipt, stdout = run(command, probe, env, output / "capability", label)
                versions[label] = {"value": stdout.decode().strip(), "exit_code": receipt["returncode"]}
            write_json(output / "source-receipt.json", dict(receipts, versions=versions, host={"system": platform.system(), "machine": platform.machine()}))
            if versions["strict-capability"]["value"] != "false":
                raise EvidenceError("installed npm strict-allow-scripts capability is unavailable")
            frozen = {"schema_version": 1, "frozen_at": datetime.now(timezone.utc).isoformat(),
                      "cases": [asdict(case) for case in CASES], "policies": list(POLICIES),
                      "native_flags": ["--strict-allow-scripts", "--foreground-scripts", "--ignore-scripts=false"],
                      "trust_boundary": "Trusted wrapper replaces head allowScripts with base policy and supplies base Tau-Gate approvals. Fresh approvals are controlled positive fixtures, never production approvals.",
                      "development_pilot": "A separate development run preceded the final primary matrix. Expectations are informed by installed source and pilot observations. The primary matrix is not retuned after any primary outcome.",
                      "candidate_sha256": receipts["tau_gate"]["sha256"],
                      "oracle": "Case inputs independently determine intended changed bytes and marker labels; native outcomes come only from actual npm exit status and marker files. Tau-Gate output supplies its decision and fingerprints, never fixture ground truth.",
                      "network": "Only controlled IPv4 loopback registry and original fixture archives. No public lifecycle scripts.",
                      "scope": "Controlled sequential fixtures, not prevalence, speed, malicious-code detection, or production safety."}
            write_json(output / "frozen-matrix.json", frozen)
            matrix_hash = sha256((output / "frozen-matrix.json").read_bytes())
            baselines = {}
            for family in ("hook", "plain", "root"):
                base = Case("baseline-" + family, "", baseline=family,
                            command="approved" if family == "hook" else "",
                            root_command="root-approved" if family == "root" else "")
                directory = output / "baselines" / family
                project, _, env = prepare(base, private / ("baseline-" + family), directory, npm_cmd, node, base_url, packages)
                index, error = acquire(project, directory)
                if error:
                    raise EvidenceError("baseline acquisition failed: " + error)
                empty = directory / "empty-approvals.json"
                write_json(empty, {"schema_version": 2, "approvals": []})
                _, report = tau_audit(binary, project, index, empty, env, directory / "tau", "discovery")
                approvals = policy_from_report(report)
                write_json(directory / "approvals.json", approvals)
                for kind in POLICIES:
                    write_json(directory / (kind + "-policy.json"), native_policy(kind, base, base_url))
                baselines[family] = {"case": base, "approvals_path": directory / "approvals.json", "directory": directory}
            for case in CASES:
                directory = output / "cases" / case.name
                project, canaries, env = prepare(case, private / case.name, directory, npm_cmd, node, base_url, packages)
                canonical_manifest = (project / "package.json").read_bytes()
                index, error = acquire(project, directory)
                if error:
                    evidence = directory / "evidence"
                    (evidence / "artifacts").mkdir(parents=True, exist_ok=True)
                    (evidence / "projects").mkdir(exist_ok=True)
                    (evidence / "artifacts/fixture.tgz").write_bytes(fixture(case)["archive"])
                    (evidence / "projects/package.json").write_bytes(canonical_manifest)
                    write_json(index, {"schema_version": 1, "lock_sha256": sha256((project / "package-lock.json").read_bytes()),
                                       "packages": [{"path": "", "project_manifest": "projects/package.json"}, {"path": INSTANCE, "artifact": "artifacts/fixture.tgz"}]})
                if case.missing_evidence:
                    bundle = json.loads(index.read_bytes())
                    bundle["packages"] = [item for item in bundle["packages"] if item["path"] != INSTANCE]
                    write_json(index, bundle)
                approvals = json.loads(baselines[case.baseline]["approvals_path"].read_bytes())
                policy_path = directory / "effective-approvals.json"
                write_json(policy_path, approvals)
                if case.fresh or case.self_edit:
                    _, discovered = tau_audit(binary, project, index, policy_path, env, directory / "tau", "fresh-discovery")
                    proposed = policy_from_report(discovered)
                    write_json(directory / "proposed-approvals.json", proposed)
                    if case.fresh:
                        approvals = proposed
                        write_json(policy_path, approvals)
                tau_receipt, tau_report = tau_audit(binary, project, index, policy_path, env, directory / "tau", "enforce", True)
                tau_result = {"outcome": tau_report["policy"]["outcome"], "exit_code": tau_receipt["returncode"],
                              "acquisition_error": error, "head_policy_replaced": case.self_edit}
                native = {}
                for kind in POLICIES:
                    trusted = native_policy(kind, case, base_url) if case.fresh else json.loads((baselines[case.baseline]["directory"] / (kind + "-policy.json")).read_bytes())
                    native[kind] = native_run(case, kind, project, canaries, env, directory / kind, npm_cmd, trusted)
                (project / "package.json").write_bytes(canonical_manifest)
                expected = {"exact_version": case.expected_version, "exact_source_url": case.expected_source, "tau_gate": case.expected_tau}
                observed = {kind: value["outcome"] for kind, value in native.items()} | {"tau_gate": tau_result["outcome"]}
                mismatches = {key: {"expected": expected[key], "observed": value} for key, value in observed.items() if expected[key] != value}
                markers = [case.command + "-install"] if case.command else []
                if case.root_command:
                    markers.append(case.root_command + "-install")
                marker_checks = {kind: sorted(result["markers"]) == sorted(markers) if result["outcome"] == "executed" else not result["markers"] for kind, result in native.items()}
                installed_checks = {kind: result["installed_manifest_matches_fixture"] is not False for kind, result in native.items()}
                result = {"case": case.name, "change": case.change, "expected": expected, "observed": observed,
                          "native": native, "tau_gate": tau_result, "mismatches": mismatches,
                          "expected_execution_markers": markers, "marker_checks": marker_checks,
                          "installed_manifest_checks": installed_checks,
                          "fixture_archive_sha256": sha256(fixture(case)["archive"]),
                          "lock_sha256": sha256((project / "package-lock.json").read_bytes())}
                write_json(directory / "result.json", result)
                results.append(result)
                write_json(output / "progress.json", {"completed": len(results), "total": len(CASES), "last_case": case.name})
                print(case.name + " " + json.dumps(observed, sort_keys=True), flush=True)
            if sha256((output / "frozen-matrix.json").read_bytes()) != matrix_hash:
                raise EvidenceError("frozen matrix changed during experiment")
            receipt = {"schema_version": 1, "completed_at": datetime.now(timezone.utc).isoformat(),
                       "frozen_matrix_sha256": matrix_hash, "source_receipt_sha256": sha256((output / "source-receipt.json").read_bytes()),
                       "tau_gate_binary_unchanged": sha256(binary.read_bytes()) == receipts["tau_gate"]["sha256"],
                       "cases": results, "unexpected_cases": [row["case"] for row in results if row["mismatches"] or not all(row["marker_checks"].values()) or not all(row["installed_manifest_checks"].values())],
                       "loopback_requests": original_requests, "versions": versions}
            write_json(output / "receipt.json", receipt)
            write_summary(output, receipt)
            write_json(output / "artifact-sha256.json", {str(path.relative_to(output)): sha256(path.read_bytes()) for path in sorted(output.rglob("*")) if path.is_file()})
            return receipt
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--npm", type=Path, required=True, help="Exact installed npm-cli.js or symlink to it")
    parser.add_argument("--node", type=Path, required=True)
    parser.add_argument("--tau-gate", type=Path, required=True)
    args = parser.parse_args()
    try:
        receipt = run_comparison(args.output, args.npm, args.node, args.tau_gate)
    except (EvidenceError, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps({"cases": len(receipt["cases"]), "unexpected_cases": receipt["unexpected_cases"]}))
    return 0 if not receipt["unexpected_cases"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
