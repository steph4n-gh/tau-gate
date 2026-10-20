#!/usr/bin/env python3
"""Qualify the PR wrapper with independent archives and Git object fixtures."""
import argparse
import base64
import copy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def run(args, *, cwd=None, check=True):
    result = subprocess.run([str(arg) for arg in args], cwd=cwd, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    if check and result.returncode:
        raise AssertionError(f"command exited {result.returncode}: {args}\n{result.stderr.decode(errors='replace')}")
    return result


def tree_hashes(root, include_git=False):
    found = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if not include_git and ".git" in relative.parts:
            continue
        if path.is_symlink():
            found[str(relative)] = "symlink:" + os.readlink(path)
        elif path.is_file():
            found[str(relative)] = sha(path.read_bytes())
    return found


def archive(manifest, native=b"{ 'targets': [] }\n"):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for name, data in [("package/package.json", encoded(manifest)), ("package/binding.gyp", native)]:
            entry = tarfile.TarInfo(name)
            entry.mode = 0o644
            entry.size = len(data)
            entry.mtime = 0
            tar.addfile(entry, io.BytesIO(data))
    return gzip.compress(buffer.getvalue(), mtime=0)


class Qualification:
    def __init__(self, wrapper, binary, output):
        self.wrapper = wrapper.resolve()
        self.binary = binary.resolve()
        self.output = output.resolve()
        self.repo = self.output / "repo"
        self.cache = self.output / "cache"
        self.cases = []
        self.repo.mkdir()
        self.cache.mkdir()
        run(["git", "init", "-q", self.repo])
        run(["git", "config", "user.name", "Independent fixture"], cwd=self.repo)
        run(["git", "config", "user.email", "fixture@example.invalid"], cwd=self.repo)
        run(["git", "config", "core.symlinks", "true"], cwd=self.repo)
        self.prefix = "apps/example"
        self.project = self.repo / self.prefix
        self.project.mkdir(parents=True)
        self.root = {"name": "fixture-project", "version": "1.0.0", "private": True,
                     "dependencies": {"worker": "1.0.0", "localpkg": "file:packages/local"},
                     "workspaces": ["packages/local"], "scripts": {"preinstall": "touch SHOULD_NOT_RUN"}}
        self.local = {"name": "localpkg", "version": "1.0.0", "scripts": {"prepare": "touch SHOULD_NOT_RUN"}}
        self.package = {"name": "worker", "version": "1.0.0", "scripts": {"postinstall": "touch SHOULD_NOT_RUN"}}
        self.original_archive = archive(self.package)
        self.put_archive(self.original_archive)
        self.lock = {"name": self.root["name"], "version": "1.0.0", "lockfileVersion": 3,
                     "requires": True, "packages": {
                         "": copy.deepcopy(self.root),
                         "node_modules/worker": {"name": "worker", "version": "1.0.0",
                             "resolved": "https://registry.npmjs.org/worker/-/worker-1.0.0.tgz",
                             "integrity": self.sri(self.original_archive), "hasInstallScript": True},
                         "node_modules/localpkg": {"resolved": "packages/local", "link": True},
                         "packages/local": copy.deepcopy(self.local)}}
        self.write("package.json", encoded(self.root))
        self.write("package-lock.json", encoded(self.lock))
        self.write("packages/local/package.json", encoded(self.local))
        self.write("packages/local/binding.gyp", b"{ 'targets': [] }\n")
        self.write("tools/pr_review.py", b"from pathlib import Path\nPath('HEAD_HELPER_EXECUTED').write_text('bad')\nraise RuntimeError('HEAD CODE EXECUTED')\n")
        self.write(".tau-gate-approvals.json", encoded({"schema_version": 1, "approvals": []}))
        self.initial = self.commit("Initial fixture")
        self.approvals = self.discover_approvals()
        self.write(".tau-gate-approvals.json", encoded(self.approvals))
        self.base = self.commit("Trusted baseline approvals")
        self.refs = {"base": self.base, "initial": self.initial}

    @staticmethod
    def sri(data):
        return "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()

    def put_archive(self, data):
        (self.cache / (hashlib.sha512(data).hexdigest() + ".tgz")).write_bytes(data)

    def write(self, relative, data):
        path = self.project / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def git(self, *args):
        return run(["git", *args], cwd=self.repo).stdout.decode().strip()

    def commit(self, message):
        self.git("add", "--all")
        self.git("commit", "-q", "--allow-empty", "-m", message)
        return self.git("rev-parse", "HEAD")

    def reset(self):
        self.git("reset", "--hard", self.base)
        self.git("clean", "-fdq")

    def variant(self, label, change):
        self.reset()
        change()
        self.refs[label] = self.commit(label)
        return self.refs[label]

    def discover_approvals(self, label="approval-discovery"):
        location = self.output / label
        location.mkdir()
        sources = location / "sources"
        shutil.copytree(self.project, sources)
        artifact_path = location / "original.tgz"
        current_lock = json.loads((self.project / "package-lock.json").read_bytes())
        archive_hash = base64.b64decode(current_lock["packages"]["node_modules/worker"]["integrity"].split("-", 1)[1]).hex()
        artifact_path.write_bytes((self.cache / (archive_hash + ".tgz")).read_bytes())
        index = {"schema_version": 1, "lock_sha256": sha((self.project / "package-lock.json").read_bytes()),
                 "packages": [{"path": "", "project_manifest": "sources/package.json"},
                              {"path": "packages/local", "project_manifest": "sources/packages/local/package.json"},
                              {"path": "node_modules/worker", "artifact": "original.tgz"}]}
        (location / "index.json").write_bytes(encoded(index))
        command = [self.binary, "audit", "--lock", sources / "package-lock.json", "--manifest", sources / "package.json",
                   "--evidence", location / "index.json", "--json"]
        result = run(command)
        (location / "report.json").write_bytes(result.stdout)
        report = json.loads(result.stdout)
        candidates = report["execution_candidates"]
        assert len(candidates) == 3, candidates
        return {"schema_version": 1, "approvals": [{"path": item["package"]["path"], "fingerprint": item["approval_fingerprint"]}
                                                     for item in candidates]}

    def blob(self, ref, relative):
        return run(["git", "show", f"{ref}:{self.prefix}/{relative}"], cwd=self.repo).stdout

    def execute(self, label, base, head, expected, reason=(), **options):
        destination = self.output / "runs" / label
        before_repo = tree_hashes(self.repo, include_git=True)
        before_cache = tree_hashes(self.cache)
        command = [sys.executable, self.wrapper, "--repo", self.repo, "--base", base,
                   "--head", head, "--tau-gate", self.binary, "--output", destination,
                   "--project", self.prefix, "--approvals", self.prefix + "/.tau-gate-approvals.json",
                   "--archive-cache", self.cache]
        result = run(command, check=False)
        assert result.returncode == expected, (label, result.returncode, expected,
                                              result.stdout.decode(errors="replace"), result.stderr.decode(errors="replace"))
        report_bytes = (destination / "report.json").read_bytes()
        report = json.loads(report_bytes)
        assert report["outcome"] == {0: "allowed", 1: "blocked", 2: "incomplete"}[expected], report
        assert report["exit_code"] == expected, report
        after_repo = tree_hashes(self.repo, include_git=True)
        after_cache = tree_hashes(self.cache)
        assert after_repo == before_repo, label + " changed repository input"
        assert after_cache == before_cache, label + " changed archive cache"
        assert not list(self.repo.rglob("*SHOULD_NOT_RUN")), label + " ran a lifecycle"
        assert not list(self.repo.rglob("HEAD_HELPER_EXECUTED")), label + " ran a head helper"
        messages = " ".join(str(error.get("stage", "")) + " " + str(error.get("message", ""))
                            for error in report.get("errors", [])).lower()
        for fragment in reason:
            assert fragment.lower() in messages, (label, fragment, report.get("errors"))
        if expected < 2:
            assert not report.get("errors"), report.get("errors")
            assert report["base"]["commit"] == base and report["head"]["commit"] == head, report
            policy = report["policy"]
            assert policy["origin"] == "base" and policy["commit"] == base, policy
            assert policy["sha256"] == sha(self.blob(base, ".tau-gate-approvals.json")), policy
            self.exact_capture(report, base, head)
        self.cases.append({"case": label, "passed": True, "exit_code": result.returncode,
                           "report_sha256": sha(report_bytes), "command": [str(arg) for arg in command],
                           "errors": report.get("errors", []), "base": base, "head": head,
                           "input_repo_files": len(before_repo),
                           "input_repo_before_sha256": sha(encoded(before_repo)),
                           "input_repo_after_sha256": sha(encoded(after_repo)),
                           "archive_cache_before_sha256": sha(encoded(before_cache)),
                           "archive_cache_after_sha256": sha(encoded(after_cache))})
        return report

    def exact_capture(self, report, base, head):
        expected_files = ["package-lock.json", "package.json", "packages/local/package.json", "packages/local/binding.gyp"]
        for side, commit in (("base", base), ("head", head)):
            files = report[side]["files"]
            for relative in expected_files:
                raw = self.blob(commit, relative)
                path = self.prefix + "/" + relative
                actual = files[path]
                assert actual["sha256"] == sha(raw), (path, actual)
                assert actual["git_oid"] == self.git("rev-parse", commit + ":" + path), actual
                assert actual["size"] == len(raw) and actual["mode"] == "100644", actual
            assert self.prefix + "/binding.gyp" in report[side]["absent"], report[side]
        evidence = {item["path"]: item for item in report["core"]["head"]["execution_evidence"]}
        assert evidence["packages/local"]["facts"]["binding_gyp_sha256"] == sha(self.blob(head, "packages/local/binding.gyp"))
        assert evidence["node_modules/localpkg"]["candidate"] is False
        assert evidence["packages/local"]["candidate"] is True
        for path, relative, event in (("", "package.json", "preinstall"), ("packages/local", "packages/local/package.json", "prepare")):
            manifest = self.blob(head, relative)
            assert evidence[path]["facts"]["manifest_sha256"] == sha(manifest)
            body = json.loads(manifest)["scripts"][event]
            assert evidence[path]["facts"]["lifecycle"][event] == sha(body.encode())
        lock = json.loads(self.blob(head, "package-lock.json"))
        digest = base64.b64decode(lock["packages"]["node_modules/worker"]["integrity"].split("-", 1)[1]).hex()
        archive_bytes = (self.cache / (digest + ".tgz")).read_bytes()
        facts = evidence["node_modules/worker"]["facts"]
        assert facts["artifact_sha512"] == hashlib.sha512(archive_bytes).hexdigest()
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as package:
            manifest = package.extractfile("package/package.json").read()
            native = package.extractfile("package/binding.gyp").read()
        assert facts["manifest_sha256"] == sha(manifest)
        assert facts["binding_gyp_sha256"] == sha(native)
        body = json.loads(manifest)["scripts"]["postinstall"]
        assert facts["lifecycle"]["postinstall"] == sha(body.encode())

    def qualify(self):
        baseline = self.execute("allowed-nested-exact-capture", self.base, self.base, 0)
        self.exact_capture(baseline, self.base, self.base)
        blocked = self.execute("unapproved-baseline-blocked", self.initial, self.base, 1)
        assert {item["path"] for item in blocked["core"]["policy"]["unapproved_execution_candidates"]} == {"", "node_modules/worker", "packages/local"}
        self.write("package.json", b"DIRTY ROOT BYTES\n")
        self.write("packages/local/package.json", b"DIRTY WORKSPACE BYTES\n")
        self.write("packages/local/binding.gyp", b"DIRTY NATIVE BYTES\n")
        dirty = self.execute("dirty-tree-ignored", self.base, self.base, 0)
        self.exact_capture(dirty, self.base, self.base)
        assert encoded(dirty) == encoded(baseline), "dirty tree changed report"
        self.execute("deterministic-second-output", self.base, self.base, 0)
        first = self.output / "runs/allowed-nested-exact-capture"
        second = self.output / "runs/deterministic-second-output"
        assert (first / "report.json").read_bytes() == (second / "report.json").read_bytes(), "JSON report differs across output directories"
        assert (first / "summary.md").read_bytes() == (second / "summary.md").read_bytes(), "summary differs across output directories"

        def self_approve():
            root = copy.deepcopy(self.root)
            root["scripts"]["preinstall"] = "touch CHANGED_ROOT_SHOULD_NOT_RUN"
            self.write("package.json", encoded(root))
            self.write(".tau-gate-approvals.json", encoded(self.discover_approvals("head-policy-discovery")))
        changed = self.variant("head-self-approval", self_approve)
        report = self.execute("head-policy-cannot-self-authorize", self.base, changed, 1)
        unapproved = report["core"]["policy"]["unapproved_execution_candidates"]
        assert [item["path"] for item in unapproved] == [""], unapproved
        assert sha(self.blob(changed, ".tau-gate-approvals.json")) != report["policy"]["sha256"]
        assert report["core"]["execution_evidence_changes"], report["core"]
        head_deleted_policy = self.variant("head-policy-deleted", lambda: (self.project / ".tau-gate-approvals.json").unlink())
        self.execute("head-policy-deletion-ignored", self.base, head_deleted_policy, 0)

        def change_lock(transform):
            lock = copy.deepcopy(self.lock)
            transform(lock)
            self.write("package-lock.json", encoded(lock))

        changed = self.variant("changed-source", lambda: change_lock(lambda lock: lock["packages"]["node_modules/worker"].update(
            {"resolved": "https://registry.npmjs.org/worker/-/worker-republished.tgz"})))
        report = self.execute("source-change-invalidates-approval", self.base, changed, 1)
        assert [item["path"] for item in report["core"]["policy"]["unapproved_execution_candidates"]] == ["node_modules/worker"]

        def changed_artifact():
            package = copy.deepcopy(self.package)
            package["scripts"]["postinstall"] = "touch CHANGED_ARCHIVE_SHOULD_NOT_RUN"
            data = archive(package)
            self.put_archive(data)
            change_lock(lambda lock: lock["packages"]["node_modules/worker"].update({"integrity": self.sri(data)}))
        changed = self.variant("changed-archive", changed_artifact)
        report = self.execute("archive-change-invalidates-approval", self.base, changed, 1)
        assert [item["path"] for item in report["core"]["policy"]["unapproved_execution_candidates"]] == ["node_modules/worker"]

        def changed_integrity():
            raw = bytearray(self.original_archive)
            raw[4:8] = (1).to_bytes(4, "little")
            data = bytes(raw)
            self.put_archive(data)
            change_lock(lambda lock: lock["packages"]["node_modules/worker"].update({"integrity": self.sri(data)}))
        changed = self.variant("changed-integrity", changed_integrity)
        report = self.execute("recompression-invalidates-approval", self.base, changed, 1)
        assert [item["path"] for item in report["core"]["policy"]["unapproved_execution_candidates"]] == ["node_modules/worker"]

        changed = self.variant("changed-native", lambda: self.write("packages/local/binding.gyp", b"{ 'targets': [{'target_name':'changed'}] }\n"))
        report = self.execute("native-source-invalidates-approval", self.base, changed, 1)
        assert [item["path"] for item in report["core"]["policy"]["unapproved_execution_candidates"]] == ["packages/local"]
        self.exact_capture(report, self.base, changed)

        def add_candidate():
            package = {"name": "addon", "version": "1.0.0", "scripts": {"install": "touch ADDON_SHOULD_NOT_RUN"}}
            data = archive(package)
            self.put_archive(data)
            root = copy.deepcopy(self.root)
            root["dependencies"]["addon"] = "1.0.0"
            self.write("package.json", encoded(root))
            lock = copy.deepcopy(self.lock)
            lock["packages"][""] = copy.deepcopy(root)
            lock["packages"]["node_modules/addon"] = {"name": "addon", "version": "1.0.0", "hasInstallScript": True,
                "resolved": "https://registry.npmjs.org/addon/-/addon-1.0.0.tgz", "integrity": self.sri(data)}
            self.write("package-lock.json", encoded(lock))
        changed = self.variant("introduced-candidate", add_candidate)
        report = self.execute("introduced-candidate-path", self.base, changed, 1)
        candidate = next(item for item in report["core"]["head"]["execution_candidates"] if item["package"]["path"] == "node_modules/addon")
        assert candidate["introducer_path"] == ["root", "node_modules/addon"], candidate
        assert "node_modules/addon" in {item["path"] for item in report["core"]["policy"]["unapproved_execution_candidates"]}
        assert any(item["to"] == "node_modules/addon" for item in report["core"]["added_edges"]), report["core"]["added_edges"]
        assert report["core"]["execution_evidence_changes"], report["core"]

        changed = self.variant("unsupported-lock", lambda: change_lock(lambda lock: lock.update({"lockfileVersion": 2})))
        self.execute("unsupported-lock-version-incomplete", self.base, changed, 2, ("npm",))

        changed = self.variant("removed-lock", lambda: (self.project / "package-lock.json").unlink())
        self.execute("removed-head-lock-incomplete", self.base, changed, 2, ("package-lock.json",))
        changed = self.variant("removed-manifest", lambda: (self.project / "package.json").unlink())
        self.execute("removed-head-manifest-incomplete", self.base, changed, 2, ("package.json",))

        def symlink_manifest():
            (self.project / "package.json").unlink()
            (self.project / "package.json").symlink_to("packages/local/package.json")
        changed = self.variant("symlink-manifest", symlink_manifest)
        self.execute("head-manifest-symlink-incomplete", self.base, changed, 2, ("package.json", "symlink"))
        missing = self.variant("missing-policy", lambda: (self.project / ".tau-gate-approvals.json").unlink())
        self.execute("missing-base-policy-incomplete", missing, self.base, 2, ("approval",))
        self.execute("invalid-revision-operator-incomplete", self.base, "HEAD^", 2, ("ref",))
        blob_oid = self.git("rev-parse", self.base + ":" + self.prefix + "/package.json")
        self.execute("blob-ref-incomplete", self.base, blob_oid, 2, ("commit",))

        def alias_manifest():
            oid = self.git("rev-parse", self.base + ":" + self.prefix + "/package.json")
            self.git("update-index", "--add", "--cacheinfo", "100644," + oid + "," + self.prefix + "/Package.json")
            self.git("commit", "-q", "-m", "case alias")
        self.reset()
        alias_manifest()
        alias_ref = self.git("rev-parse", "HEAD")
        self.refs["case-alias"] = alias_ref
        self.execute("head-case-alias-incomplete", self.base, alias_ref, 2, ("case",))

    def receipt(self):
        result = {"schema_version": 1, "passed": all(case["passed"] for case in self.cases),
                  "cases": self.cases, "refs": self.refs, "binary_sha256": sha(self.binary.read_bytes()),
                  "wrapper_sha256": sha(self.wrapper.read_bytes()), "verifier_sha256": sha(Path(__file__).read_bytes()),
                  "archives": tree_hashes(self.cache), "git_version": self.git("--version"),
                  "python_version": sys.version.split()[0]}
        (self.output / "receipt.json").write_bytes(encoded(result))
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wrapper", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    if any(args.output.iterdir()):
        parser.error("output must be empty")
    qualification = Qualification(args.wrapper, args.binary, args.output)
    try:
        qualification.qualify()
    except Exception as error:
        qualification.cases.append({"case": "qualification-aborted", "passed": False,
                                    "error": type(error).__name__ + ": " + str(error)})
        qualification.receipt()
        raise
    receipt = qualification.receipt()
    print(json.dumps({"passed": receipt["passed"], "cases": len(receipt["cases"]), "receipt": str(args.output / "receipt.json")}))


if __name__ == "__main__":
    main()
