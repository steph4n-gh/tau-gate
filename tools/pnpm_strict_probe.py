#!/usr/bin/env python3
"""Keep script suppression separate from pnpm's strict-build CI exit behavior."""

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import threading

from npm3_native_comparison import Case, NAME, environment, fixture, run, snapshot_canaries, write_json
from npm_evidence import sha256
from npm_reference import registry
from pnpm_native_comparison import workspace_policy
from verify_npm_evidence import encoded, tar_for, zipped


def probe(output, pnpm, node):
    if output.exists() and any(output.iterdir()):
        raise ValueError("diagnostic output must be absent or empty")
    output.mkdir(parents=True, exist_ok=True)
    cases = [
        {"case": "same_name_new_version", "name": NAME, "version": "2.0.0", "policy": workspace_policy("1.0.0"), "expected_exit": 0},
        {"case": "unrelated_unapproved_name", "name": "tau-unapproved-control", "version": "1.0.0", "policy": workspace_policy("1.0.0"), "expected_exit": 1},
        {"case": "empty_approval_map", "name": NAME, "version": "2.0.0", "policy": "packages: []\nallowBuilds: {}\nstrictDepBuilds: true\nverifyStoreIntegrity: true\n", "expected_exit": 1},
    ]
    flags = ["install", "--frozen-lockfile", "--ignore-scripts=false", "--config.strict-dep-builds=true", "--reporter=append-only"]
    write_json(output / "frozen-matrix.json", {"frozen_at": datetime.now(timezone.utc).isoformat(), "cases": cases,
                                              "flags": flags, "expected_script_execution": False,
                                              "purpose": "Replicate retained same-name version mismatch and contrast unrelated and empty approval controls. First expectation follows the preceding unexpected observation. No execution bypass is hypothesized."})
    packages, requests = {}, []
    server = registry(packages, requests)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    command = [node.resolve(), pnpm.resolve()]
    results = []
    try:
        with tempfile.TemporaryDirectory(prefix="tau-pnpm-strict-probe-") as temp:
            for case in cases:
                directory = output / case["case"]
                private = Path(temp) / case["case"]
                private.mkdir()
                canaries = private / "canaries"
                canaries.mkdir()
                env = environment(private / "private", node.resolve(), f"http://127.0.0.1:{server.server_port}/", canaries)
                env["CI"] = "true"
                env["PNPM_UPDATE_NOTIFICATION"] = "false"
                package = fixture(Case(case["case"], "", version=case["version"]))
                package["manifest"]["name"] = case["name"]
                package["manifest_bytes"] = encoded(package["manifest"])
                package["archive"] = zipped(tar_for(package["manifest"], b"original"))
                package["integrity"] = "sha512-" + base64.b64encode(hashlib.sha512(package["archive"]).digest()).decode()
                packages.clear()
                packages[case["name"] + "@" + case["version"]] = package
                write_json(private / "package.json", {"name": "tau-strict-probe", "version": "1.0.0", "private": True,
                                                       "dependencies": {case["name"]: case["version"]}})
                (private / "pnpm-workspace.yaml").write_text(case["policy"])
                store = private / "private/store"
                receipt, _ = run(command + ["install", "--lockfile-only", "--ignore-scripts", "--store-dir", store, "--reporter=append-only"],
                                 private, env, directory, "generate-lock")
                if receipt["returncode"] or snapshot_canaries(canaries):
                    raise ValueError("diagnostic lock generation failed or executed a marker")
                if store.exists():
                    shutil.rmtree(store)
                configs = {}
                for key in ("strict-dep-builds", "allow-builds"):
                    _, value = run(command + ["config", "get", key, "--json"], private, env, directory, "config-" + key)
                    configs[key] = value.decode().strip()
                receipt, _ = run(command + [*flags, "--store-dir", store], private, env, directory, "install")
                markers = snapshot_canaries(canaries)
                for name in ("package.json", "pnpm-workspace.yaml", "pnpm-lock.yaml"):
                    shutil.copyfile(private / name, directory / name)
                modules = private / "node_modules/.modules.yaml"
                if modules.exists():
                    shutil.copyfile(modules, directory / "modules.yaml")
                (directory / "fixture.tgz").write_bytes(package["archive"])
                result = {"case": case["case"], "script_executed": bool(markers), "markers": markers,
                          "ci_exit_code": receipt["returncode"], "ci_failed": receipt["returncode"] != 0,
                          "expected_exit": case["expected_exit"], "effective_config_query": configs}
                result["matches_diagnostic_expectation"] = not markers and receipt["returncode"] == case["expected_exit"]
                write_json(directory / "result.json", result)
                results.append(result)
                print(json.dumps(result, sort_keys=True), flush=True)
        write_json(output / "receipt.json", {"results": results, "loopback_requests": requests,
                                            "node": str(node.resolve()), "pnpm": str(pnpm.resolve()),
                                            "helper_sha256": sha256(Path(__file__).read_bytes()),
                                            "interpretation": "Marker suppression is execution protection regardless of CI exit. These controls compare strict exit behavior only; source-based causes remain hypotheses."})
        write_json(output / "artifact-sha256.json", {str(path.relative_to(output)): sha256(path.read_bytes()) for path in sorted(output.rglob("*")) if path.is_file()})
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--pnpm", type=Path, required=True)
    parser.add_argument("--node", type=Path, required=True)
    args = parser.parse_args()
    probe(args.output, args.pnpm, args.node)
