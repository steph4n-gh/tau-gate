#!/usr/bin/env python3
"""Run a controlled npm installation and independent artifact correspondence checks."""

import argparse
import base64
import copy
import gzip
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import urllib.parse

sys.dont_write_bytecode = True

from npm_evidence import (EvidenceError, archive_facts, collect_evidence, json_bytes,
                          manifest_facts, read_limited, sha256, sri_digest,
                          strict_json, validate_bundle)


MATRIX = Path(__file__).resolve().parents[1] / "tests/fixtures/npm-reference/matrix.json"


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


def make_archive(manifest_bytes, binding_gyp=False):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        files = {"package/package.json": manifest_bytes}
        if binding_gyp:
            files["package/binding.gyp"] = b'{"targets": []}\n'
        for name, data in sorted(files.items()):
            member = tarfile.TarInfo(name)
            member.size = len(data)
            member.mode = 0o644
            member.mtime = 0
            archive.addfile(member, io.BytesIO(data))
    return gzip.compress(stream.getvalue(), mtime=0)


def canary_scripts(events, label):
    return {event: 'node -e "require(\'fs\').writeFileSync(process.env.TAU_GATE_CANARY_DIR + \'/' + label + '-' + event + '\', \'executed\')"' for event in events}


def package_fixtures(matrix):
    packages = {}
    for item in matrix["packages"]:
        manifest = {key: value for key, value in item.items() if key not in ("events", "binding_gyp")}
        if item.get("events"):
            manifest["scripts"] = canary_scripts(item["events"], item["name"] + "-" + item["version"])
        data = json_bytes(manifest)
        archive = make_archive(data, item.get("binding_gyp", False))
        coordinate = item["name"] + "@" + item["version"]
        packages[coordinate] = {"manifest": manifest, "manifest_bytes": data, "archive": archive, "integrity": "sha512-" + base64.b64encode(hashlib.sha512(archive).digest()).decode(), "binding_gyp": item.get("binding_gyp", False)}
    return packages


def registry(packages, requests):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            path = urllib.parse.unquote(urllib.parse.urlsplit(self.path).path).lstrip("/")
            requests.append(path)
            selected = next((item for item in packages.values() if path == tarball_path(item["manifest"])), None)
            if selected is not None:
                body = selected["archive"]
                content_type = "application/octet-stream"
            else:
                versions = {}
                for item in packages.values():
                    manifest = item["manifest"]
                    if manifest["name"] == path:
                        version = copy.deepcopy(manifest)
                        version["dist"] = {"tarball": f"http://127.0.0.1:{self.server.server_port}/" + tarball_path(manifest), "integrity": item["integrity"], "shasum": hashlib.sha1(item["archive"]).hexdigest()}
                        versions[manifest["version"]] = version
                if not versions:
                    self.send_error(404)
                    return
                body = json_bytes({"name": path, "dist-tags": {"latest": sorted(versions)[-1]}, "versions": versions})
                content_type = "application/json"
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            pass

    return ThreadingHTTPServer(("127.0.0.1", 0), Handler)


def tarball_path(manifest):
    return manifest["name"] + "/-/" + manifest["name"] + "-" + manifest["version"] + ".tgz"


def run_command(args, cwd, env, log_dir, label):
    result = subprocess.run([str(arg) for arg in args], cwd=cwd, env=env, capture_output=True, timeout=120, check=False)
    log_dir.mkdir(parents=True, exist_ok=True)
    (log_dir / (label + ".stdout")).write_bytes(result.stdout)
    (log_dir / (label + ".stderr")).write_bytes(result.stderr)
    receipt = {"argv": [str(arg) for arg in args], "cwd": str(cwd), "returncode": result.returncode, "stdout_sha256": sha256(result.stdout), "stderr_sha256": sha256(result.stderr)}
    require(result.returncode == 0, f"{label} failed with {result.returncode}: {result.stderr.decode(errors='replace')}")
    return receipt, result.stdout


def npm_source_receipt(npm, node, version, output):
    source_root = npm.parent.parent
    metadata = strict_json(read_limited(source_root / "package.json"))
    require(metadata.get("name") == "npm" and metadata.get("version") == version, "npm executable and source package version disagree; pass an exact npm-cli.js path")
    rules = {
        "lib/commands/ci.js": ["const ignoreScripts", "'preinstall'", "'postprepare'"],
        "node_modules/@npmcli/arborist/lib/arborist/rebuild.js": ["type === 'links'", "this.#runScripts('prepare')", "const isGyp = gypfile !== false"],
        "node_modules/@npmcli/run-script/lib/run-script-pkg.js": ["pkg.scripts[event]", "!scripts.preinstall", "gypfile !== false"],
    }
    sources = []
    for relative, fragments in rules.items():
        data = read_limited(source_root / relative)
        lines = data.decode().splitlines()
        references = []
        for fragment in fragments:
            matches = [index + 1 for index, line in enumerate(lines) if fragment in line]
            require(bool(matches), f"npm source rule not found: {relative}: {fragment}")
            references.append({"fragment": fragment, "lines": matches})
        destination = output / "npm-source" / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        sources.append({"path": str(source_root / relative), "relative_path": relative, "sha256": sha256(data), "references": references})
    def file_hash(path):
        with path.open("rb") as stream:
            return hashlib.file_digest(stream, "sha256").hexdigest()
    return {"kind": "installed_npm_source_inspection", "package_version": version, "npm_cli": str(npm), "npm_cli_sha256": file_hash(npm), "node": str(node), "node_sha256": file_hash(node), "sources": sources, "rules": {"root_ci_events": ["preinstall", "install", "postinstall", "prepublish", "preprepare", "prepare", "postprepare"], "registry_dependency_events": ["preinstall", "install", "postinstall"], "workspace_link_events": ["preinstall", "prepare", "install", "postinstall"], "implicit_node_gyp": "binding.gyp exists, gypfile is not false, and preinstall/install bodies are both falsy"}, "limitation": "Scripts-disabled npm runs establish installed-byte correspondence. Lifecycle scheduling is qualified by the separately hashed npm implementation sources."}


def create_project(project, matrix, packages, registry_url):
    project.mkdir(parents=True)
    dependencies = {"alias-leaf": "npm:tau-ref-leaf@1.0.0", "tau-ref-hooks": registry_url + tarball_path(packages["tau-ref-hooks@1.0.0"]["manifest"]), "tau-ref-leaf": "1.0.0", "tau-ref-parent": "1.0.0", "tau-ref-plain": "1.0.0", "tau-ref-native": "1.0.0", "tau-ref-native-override": "1.0.0", "tau-ref-native-disabled": "1.0.0"}
    root = {"name": "tau-reference-root", "version": "1.0.0", "private": True, "workspaces": ["packages/*"], "dependencies": dependencies, "optionalDependencies": {"tau-ref-selected": "1.0.0", "tau-ref-excluded": "1.0.0"}, "scripts": canary_scripts(matrix["root_events"], "root")}
    (project / "package.json").write_bytes(json_bytes(root))
    workspace = matrix["workspace"]
    workspace_dir = project / workspace["path"]
    workspace_dir.mkdir(parents=True)
    local = {"name": workspace["name"], "version": workspace["version"], "dependencies": {"tau-ref-plain": "1.0.0"}, "scripts": canary_scripts(["prepare"], "workspace")}
    (workspace_dir / "package.json").write_bytes(json_bytes(local))
    (workspace_dir / "binding.gyp").write_bytes(b'{"targets": []}\n')


def negative_controls(lock_path, bundle, output, packages):
    results = []
    source_index = strict_json(read_limited(bundle / "index.json"))
    lock_bytes = read_limited(lock_path)
    controls = ("corrupt_archive", "same_identity_substitution", "wrong_version", "duplicate_instance", "wrong_lock_hash", "missing_evidence", "supplied_manifest_substitution", "wrong_workspace_identity", "unsafe_locator", "unknown_assertion")
    for control in controls:
        directory = output / control
        shutil.copytree(bundle, directory)
        index = copy.deepcopy(source_index)
        control_lock = directory / "package-lock.json"
        control_lock.write_bytes(lock_bytes)
        selected = next(item for item in index["packages"] if item["path"] == "node_modules/tau-ref-hooks")
        if control in ("corrupt_archive", "same_identity_substitution"):
            archive_path = directory / selected["artifact"]
            if control == "corrupt_archive":
                original = archive_path.read_bytes()
                archive_path.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
            else:
                manifest = copy.deepcopy(packages["tau-ref-hooks@1.0.0"]["manifest"])
                manifest["scripts"]["install"] = "node malicious-substitute.js"
                archive_path.write_bytes(make_archive(json_bytes(manifest)))
        elif control == "wrong_version":
            selected = next(item for item in index["packages"] if item["path"] == "node_modules/tau-ref-leaf")
            wrong = packages["tau-ref-leaf@2.0.0"]
            selected["artifact"] = "artifacts/wrong-version.tgz"
            (directory / selected["artifact"]).write_bytes(wrong["archive"])
            lock = strict_json(lock_bytes)
            lock["packages"][selected["path"]]["integrity"] = wrong["integrity"]
            control_lock.write_bytes(json_bytes(lock))
            index["lock_sha256"] = sha256(control_lock.read_bytes())
        elif control == "duplicate_instance":
            index["packages"].append(copy.deepcopy(selected))
        elif control == "wrong_lock_hash":
            index["lock_sha256"] = "0" * 64
        elif control == "missing_evidence":
            index["packages"].remove(selected)
        elif control == "supplied_manifest_substitution":
            selected.pop("artifact")
            selected["project_manifest"] = "substitute.json"
            (directory / "substitute.json").write_bytes(packages["tau-ref-hooks@1.0.0"]["manifest_bytes"])
        elif control == "wrong_workspace_identity":
            selected = next(item for item in index["packages"] if item["path"] == "packages/local")
            manifest_path = directory / selected["project_manifest"]
            manifest = strict_json(manifest_path.read_bytes())
            manifest["name"] = "substituted-workspace"
            manifest_path.write_bytes(json_bytes(manifest))
        elif control == "unsafe_locator":
            selected["artifact"] = "../outside.tgz"
        elif control == "unknown_assertion":
            selected["verified"] = True
        (directory / "index.json").write_bytes(json_bytes(index))
        try:
            validate_bundle(control_lock, directory / "index.json")
        except EvidenceError as exc:
            if control == "wrong_version":
                require("manifest version does not match" in str(exc), "wrong-version control did not reach identity validation")
            results.append({"control": control, "outcome": "rejected", "reason": str(exc)})
        else:
            raise EvidenceError(f"negative control accepted: {control}")
    return results


def compare_tau_gate(binary, project, env, output, matrix, expected):
    command = [binary, "audit", "--lock", project / "package-lock.json", "--manifest", project / "package.json", "--json"]
    receipt, stdout = run_command(command, project, env, output / "commands", "tau-gate-baseline")
    report = strict_json(stdout)
    (output / "tau-gate-baseline.json").write_bytes(stdout)
    records = {item["path"]: item for item in report["packages"]}
    expected_paths = set(expected) | {"", matrix["workspace"]["path"], "node_modules/" + matrix["workspace"]["name"]}
    require(set(records) == expected_paths, f"Tau-Gate inventory mismatch: {set(records) ^ expected_paths}")
    for path, coordinate in expected.items():
        name, version = coordinate.rsplit("@", 1)
        require((records[path]["name"], records[path]["version"]) == (name, version), f"Tau-Gate identity mismatch: {path}")
    root = strict_json(read_limited(project / "package.json"))
    expected_edges = {( "root", "node_modules/" + name, (kind,)) for kind in ("dependencies", "optionalDependencies") for name in root[kind]}
    expected_edges.update({("node_modules/tau-ref-parent", "node_modules/tau-ref-parent/node_modules/tau-ref-leaf", ("dependencies",)), ("node_modules/" + matrix["workspace"]["name"], matrix["workspace"]["path"], ("workspaceLink",)), (matrix["workspace"]["path"], "node_modules/tau-ref-plain", ("dependencies",))})
    actual_edges = {(item["from"], item["to"], tuple(item["kinds"])) for item in report["edges"]}
    require(actual_edges == expected_edges, f"Tau-Gate typed edges differ from independent fixture graph: {actual_edges ^ expected_edges}")
    locked = strict_json(read_limited(project / "package-lock.json"))["packages"]
    marker_candidates = {path for path, record in locked.items() if record.get("hasInstallScript")}
    candidates = {item["package"]["path"] for item in report["execution_candidates"]}
    require(candidates == marker_candidates, f"Tau-Gate marker candidates differ from independent lock observations: {candidates ^ marker_candidates}")
    require(not report.get("issues"), f"Tau-Gate required-edge issues: {report.get('issues')}")
    return {"command": receipt, "report_sha256": sha256(stdout), "checks": ["exact_locked_inventory", "alias_actual_identity", "nested_version_identity", "exact_typed_edges", "marker_candidates", "no_required_edge_issues"], "scope": "Baseline marker-only audit. Artifact lifecycle refinement is checked separately by the evidence-policy milestone."}


def run_reference(output, npm, node, tau_gate=None):
    require(not output.exists() or not any(output.iterdir()), "reference output directory must be empty")
    output.mkdir(parents=True, exist_ok=True)
    matrix_bytes = read_limited(MATRIX)
    matrix = strict_json(matrix_bytes)
    packages = package_fixtures(matrix)
    npm = Path(npm).resolve()
    node = Path(node).resolve()
    requests = []
    server = registry(packages, requests)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="tau-gate-npm-reference-") as temporary:
            private = Path(temporary)
            project = private / "project"
            home = private / "home"
            home.mkdir()
            cache = private / "npm-cache"
            canaries = private / "canaries"
            canaries.mkdir()
            user_config = private / "user.npmrc"
            global_config = private / "global.npmrc"
            user_config.write_text("")
            global_config.write_text("")
            registry_url = f"http://127.0.0.1:{server.server_port}/"
            env = {"PATH": os.pathsep.join(dict.fromkeys([str(Path(node).parent), str(Path(npm).parent), "/usr/bin", "/bin"])), "HOME": str(home), "TMPDIR": str(private), "npm_config_cache": str(cache), "npm_config_userconfig": str(user_config), "npm_config_globalconfig": str(global_config), "npm_config_prefix": str(private / "prefix"), "npm_config_registry": registry_url, "npm_config_update_notifier": "false", "npm_config_ignore_scripts": "true", "npm_config_audit": "false", "npm_config_fund": "false", "npm_config_fetch_retries": "0", "TAU_GATE_CANARY_DIR": str(canaries)}
            create_project(project, matrix, packages, registry_url)
            commands = []
            versions = {}
            for executable, name in ((node, "node"), (npm, "npm")):
                receipt, stdout = run_command([executable, "--version"], project, env, output / "commands", name + "-version")
                commands.append(receipt)
                versions[name] = stdout.decode().strip()
            npm_sources = npm_source_receipt(npm, node, versions["npm"], output)
            for label, args in (("lock", [npm, "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"]), ("ci", [npm, "ci", "--ignore-scripts", "--no-audit", "--no-fund"])):
                receipt, _ = run_command(args, project, env, output / "commands", label)
                commands.append(receipt)
                require(not any(canaries.iterdir()), f"lifecycle canary ran during {label}")
            lock_path = project / "package-lock.json"
            lock_bytes = read_limited(lock_path)
            lock = strict_json(lock_bytes)
            expected = matrix["instances"]
            locked = {path for path, record in lock["packages"].items() if path and not record.get("link") and path != matrix["workspace"]["path"]}
            require(locked == set(expected), f"npm locked inventory differs from fixture oracle: {locked ^ set(expected)}")
            observations = []
            for path, coordinate in sorted(expected.items()):
                fixture = packages[coordinate]
                record = lock["packages"][path]
                data, manifest, binding, binding_hash = archive_facts(fixture["archive"], record.get("integrity"))
                require(manifest == fixture["manifest"], f"artifact does not match independent fixture {path}")
                installed_path = project / path / "package.json"
                selected = path not in matrix["excluded"]
                require(installed_path.exists() == selected, f"npm platform selection differs from oracle: {path}")
                if selected:
                    require(read_limited(installed_path) == data, f"installed manifest differs from original archive: {path}")
                facts = manifest_facts(data, binding, binding_hash=binding_hash)
                facts.update({"path": path, "selected": selected, "selection_reason": "installed" if selected else "incompatible_os_optional", "coordinate": coordinate, "integrity": fixture["integrity"], "artifact_sha256": sha256(fixture["archive"]), "installed_manifest_sha256": sha256(read_limited(installed_path)) if selected else None, "locked_install_marker": record.get("hasInstallScript")})
                observations.append(facts)
            observed_by_coordinate = {item["coordinate"]: item for item in observations}
            require(observed_by_coordinate["tau-ref-native@1.0.0"]["implicit_node_gyp"], "binding.gyp native default missing")
            require(not observed_by_coordinate["tau-ref-native-override@1.0.0"]["implicit_node_gyp"], "explicit install did not suppress native default")
            require(not observed_by_coordinate["tau-ref-native-disabled@1.0.0"]["implicit_node_gyp"], "gypfile:false did not suppress native default")
            require(not observed_by_coordinate["tau-ref-plain@1.0.0"]["lifecycle"] and not observed_by_coordinate["tau-ref-plain@1.0.0"]["binding_gyp"], "script-free fixture contains execution evidence")
            workspace = matrix["workspace"]
            link = project / "node_modules" / workspace["name"]
            require(link.is_symlink() and link.resolve() == (project / workspace["path"]).resolve(), "workspace link target differs from source project")
            require((link / "package.json").read_bytes() == (project / workspace["path"] / "package.json").read_bytes(), "workspace linked manifest differs from source")
            require(not any(path.name == "tau-ref-absent" for path in (project / "node_modules").rglob("*")), "absent optional peer was installed")
            captured_project = output / "project"
            captured_project.mkdir()
            for relative in ("package.json", "package-lock.json", workspace["path"] + "/package.json", workspace["path"] + "/binding.gyp"):
                destination = captured_project / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes((project / relative).read_bytes())
            archive_cache = output / "archive-cache"
            archive_cache.mkdir()
            for fixture in packages.values():
                (archive_cache / (sri_digest(fixture["integrity"]).hex() + ".tgz")).write_bytes(fixture["archive"])
            bundle = output / "evidence"
            index_path = collect_evidence(lock_path, project, bundle, allow_loopback=True)
            verified = validate_bundle(lock_path, index_path, project / "package.json")
            require(not any(item.get("marker_conflict") for item in verified), "normal matrix contains contradictory install markers")
            source_projects = []
            for relative in ("", workspace["path"]):
                binding_path = project / relative / "binding.gyp"
                facts = manifest_facts(read_limited(project / relative / "package.json"), binding_path.exists(), "root" if relative == "" else "workspace", sha256(read_limited(binding_path)) if binding_path.exists() else None)
                source_projects.append(dict(facts, path=relative))
            require(set(source_projects[0]["lifecycle"]) == set(matrix["root_events"]), "root lifecycle coverage is incomplete")
            oracle = {"schema_version": 1, "matrix_sha256": sha256(matrix_bytes), "packages": observations, "source_projects": source_projects, "workspace_links": [{"path": "node_modules/" + workspace["name"], "target": workspace["path"]}], "absent_optional_peers": ["tau-ref-absent"]}
            (output / "oracle.json").write_bytes(json_bytes(oracle))
            controls = negative_controls(lock_path, bundle, output / "negative-controls", packages)
            marker_directory = output / "negative-controls" / "false_install_marker"
            shutil.copytree(bundle, marker_directory)
            marker_lock = copy.deepcopy(lock)
            marker_lock["packages"]["node_modules/tau-ref-hooks"]["hasInstallScript"] = False
            marker_lock_path = marker_directory / "package-lock.json"
            marker_lock_path.write_bytes(json_bytes(marker_lock))
            marker_index = strict_json(read_limited(marker_directory / "index.json"))
            marker_index["lock_sha256"] = sha256(read_limited(marker_lock_path))
            (marker_directory / "index.json").write_bytes(json_bytes(marker_index))
            marker_facts = validate_bundle(marker_lock_path, marker_directory / "index.json")
            require(next(item for item in marker_facts if item["path"] == "node_modules/tau-ref-hooks")["marker_conflict"], "hidden lifecycle script did not produce a marker conflict")
            controls.append({"control": "false_install_marker", "outcome": "conflict_observed"})
            tau_check = compare_tau_gate(str(Path(tau_gate).resolve()), project, env, output, matrix, expected) if tau_gate else {"status": "not_requested"}
            require(not any(canaries.iterdir()), "lifecycle canary executed")
            receipt = {"schema_version": 1, "status": "pass", "versions": versions, "npm_scheduling_source": npm_sources, "host": {"system": platform.system(), "machine": platform.machine()}, "commands": commands, "acquisition": {"mode": "controlled_loopback_registry", "registry": registry_url, "requests": sorted(requests), "external_network": False}, "scope": "Controlled npm v3 installation correspondence. No script execution, arbitrary publisher safety claim, or npm-wide format qualification.", "lock_sha256": sha256(lock_bytes), "root_manifest_sha256": sha256(read_limited(project / "package.json")), "index_sha256": sha256(read_limited(index_path)), "oracle_sha256": sha256(read_limited(output / "oracle.json")), "verified_instances": len(verified), "selected_instances": sorted(item["path"] for item in observations if item["selected"]), "excluded_instances": matrix["excluded"], "checks": ["fixture_inventory_exact", "artifact_sri_verified", "installed_manifests_byte_equal_to_original_artifacts", "alias_real_identity", "nested_versions_distinct", "workspace_link_target_and_manifest", "selected_and_platform_excluded_optionals", "absent_optional_peer", "implicit_native_and_explicit_install_override", "gypfile_false_suppresses_implicit_build", "script_free_package", "seven_root_lifecycle_events", "no_lifecycle_canary_executed"], "negative_controls": controls, "tau_gate": tau_check}
            (output / "receipt.json").write_bytes(json_bytes(receipt))
            return receipt
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=5)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="empty directory for original artifacts, oracle, locator index, and receipt")
    parser.add_argument("--npm", default=shutil.which("npm"), help="npm executable")
    parser.add_argument("--node", default=shutil.which("node"), help="Node executable")
    parser.add_argument("--tau-gate", type=Path, help="optional existing binary for baseline graph correspondence")
    args = parser.parse_args(argv)
    try:
        require(args.npm and args.node, "npm and Node executables are required")
        if args.output:
            output = args.output.resolve()
            receipt = run_reference(output, args.npm, args.node, args.tau_gate)
            print(json.dumps({"status": receipt["status"], "receipt": str(output / "receipt.json"), "versions": receipt["versions"]}, sort_keys=True))
        else:
            with tempfile.TemporaryDirectory(prefix="tau-gate-reference-output-") as temporary:
                receipt = run_reference(Path(temporary), args.npm, args.node, args.tau_gate)
                print(json.dumps({"status": receipt["status"], "versions": receipt["versions"], "output": "disposable; use --output to retain receipts"}, sort_keys=True))
        return 0
    except (EvidenceError, OSError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({"status": "fail", "error": str(exc)}, sort_keys=True))
        return 2


if __name__ == "__main__":
    sys.exit(main())
