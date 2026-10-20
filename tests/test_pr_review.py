import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get("TAU_GATE", ROOT / "target/release/tau-gate")).resolve()
WRAPPER = ROOT / "tools/pr_review.py"
sys.path.insert(0, str(ROOT / "tools"))
from npm_evidence import collect_evidence


def json_data(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


class PullRequestReview(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="tau-pr-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repository"
        self.repo.mkdir()
        self.project = self.repo / "apps/example"
        self.project.mkdir(parents=True)
        self.cache = self.root / "archive-cache"
        self.cache.mkdir()
        self.sequence = 0
        self.git("init", "-q")
        self.git("config", "user.name", "Tau fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        self.git("config", "core.filemode", "true")
        self.manifest = {"name": "fixture", "version": "1.0.0", "workspaces": ["packages/local"],
                         "dependencies": {"pkg": "1.0.0", "local": "file:packages/local"},
                         "scripts": {"prepare": "echo root-canary > CANARY_EXECUTED"}}
        self.workspace = {"name": "local", "version": "1.0.0", "scripts": {"prepare": "echo workspace-canary > CANARY_EXECUTED"}}
        package = {"name": "pkg", "version": "1.0.0", "scripts": {"install": "echo dependency-canary > CANARY_EXECUTED"}}
        archive = self.archive(package)
        digest = hashlib.sha512(archive).digest()
        self.integrity = "sha512-" + base64.b64encode(digest).decode()
        (self.cache / (digest.hex() + ".tgz")).write_bytes(archive)
        self.lock = {"name": "fixture", "version": "1.0.0", "lockfileVersion": 3,
                     "packages": {"": {"name": "fixture", "version": "1.0.0", "workspaces": ["packages/local"], "dependencies": self.manifest["dependencies"]},
                                  "node_modules/pkg": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz", "integrity": self.integrity, "hasInstallScript": True},
                                  "node_modules/local": {"resolved": "packages/local", "link": True},
                                  "packages/local": {"name": "local", "version": "1.0.0"}}}
        self.write("package.json", json_data(self.manifest))
        self.write("package-lock.json", json_data(self.lock))
        self.write("packages/local/package.json", json_data(self.workspace))
        self.write("packages/local/binding.gyp", b"native-source-v1\n")
        self.policy_path = self.project / ".tau-gate-approvals.json"
        self.policy_path.write_bytes(json_data({"schema_version": 1, "approvals": []}))
        self.commit("initial fixture")
        self.policy = self.approvals()
        self.policy_bytes = json_data(self.policy)
        self.policy_path.write_bytes(self.policy_bytes)
        self.base = self.commit("trusted approvals")

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.repo), *args], stderr=subprocess.PIPE).decode().strip()

    def write(self, path, data):
        destination = self.project / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)

    def commit(self, message):
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)
        return self.git("rev-parse", "HEAD")

    def archive(self, manifest):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as tar:
            data = json_data(manifest)
            info = tarfile.TarInfo("package/package.json")
            info.size = len(data)
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(data))
        return gzip.compress(stream.getvalue(), mtime=0)

    def approvals(self):
        self.sequence += 1
        index = collect_evidence(self.project / "package-lock.json", self.project,
                                 self.root / f"bootstrap-{self.sequence}", self.cache)
        result = subprocess.run([str(BINARY), "audit", "--lock", str(self.project / "package-lock.json"),
                                 "--manifest", str(self.project / "package.json"), "--evidence", str(index), "--json"],
                                capture_output=True, check=True)
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], "complete")
        return {"schema_version": 1, "approvals": [{"path": item["path"], "fingerprint": item["approval_fingerprint"]}
                                                    for item in report["execution_evidence"] if item["candidate"]]}

    def run_review(self, head=None, base=None, expected=0, extra=()):
        self.sequence += 1
        output = self.root / f"review-{self.sequence}"
        command = [sys.executable, str(WRAPPER), "--repo", str(self.repo), "--base", base or self.base,
                   "--head", head or self.base, "--project", "apps/example", "--approvals", "apps/example/.tau-gate-approvals.json",
                   "--tau-gate", str(BINARY), "--archive-cache", str(self.cache), "--output", str(output), *extra]
        result = subprocess.run(command, capture_output=True, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
        report = json.loads(result.stdout)
        self.assertEqual(result.returncode, expected, report)
        self.assertEqual(report["exit_code"], expected)
        self.assertEqual(report["outcome"], {0: "allowed", 1: "blocked", 2: "incomplete"}[expected])
        if output.exists():
            self.assertEqual(json.loads((output / "report.json").read_bytes()), report)
        self.assertFalse(list(self.repo.rglob("CANARY_EXECUTED")))
        return report, output

    def test_exact_git_bytes_ignore_dirty_worktree_and_repeat_deterministically(self):
        committed = (self.project / "package.json").read_bytes()
        self.write("package.json", b"dirty third manifest is not JSON\n")
        before = self.git("status", "--porcelain")
        first, first_output = self.run_review()
        second, second_output = self.run_review()
        self.assertEqual(first, second)
        self.assertEqual((first_output / "report.json").read_bytes(), (second_output / "report.json").read_bytes())
        self.assertEqual((first_output / "summary.md").read_bytes(), (second_output / "summary.md").read_bytes())
        entry = first["head"]["files"]["apps/example/package.json"]
        self.assertEqual(entry["sha256"], hashlib.sha256(committed).hexdigest())
        self.assertEqual(entry["git_oid"], self.git("rev-parse", self.base + ":apps/example/package.json"))
        self.assertEqual((first_output / "head/project/package.json").read_bytes(), committed)
        self.assertEqual(first["core"]["head"]["manifest_sha256"], entry["sha256"])
        self.assertEqual(first["policy"]["sha256"], hashlib.sha256(self.policy_bytes).hexdigest())
        self.assertEqual(first["policy"]["origin"], "base")
        self.assertEqual(self.git("status", "--porcelain"), before)

    def test_changed_lifecycle_and_forged_head_approval_remain_blocked(self):
        self.manifest["scripts"]["prepare"] = "echo changed-root-canary > CANARY_EXECUTED"
        self.write("package.json", json_data(self.manifest))
        forged = self.approvals()
        self.policy_path.write_bytes(json_data(forged))
        head = self.commit("head attempts self approval")
        report, output = self.run_review(head=head, expected=1)
        candidates = report["core"]["policy"]["unapproved_execution_candidates"]
        self.assertEqual([item["path"] for item in candidates], [""])
        self.assertEqual((output / "base/approvals.json").read_bytes(), self.policy_bytes)
        self.assertEqual(report["policy"]["commit"], self.base)
        text = (output / "summary.md").read_text()
        self.assertIn(candidates[0]["fingerprint"], text)
        self.assertIn("lifecycle", text)
        self.assertIn("Introducer", text)

    def test_native_input_and_same_version_source_change_invalidate_approval(self):
        self.write("packages/local/binding.gyp", b"native-source-v2\n")
        self.lock["packages"]["node_modules/pkg"]["resolved"] = "https://registry.npmjs.org/other/-/pkg-1.0.0.tgz"
        self.write("package-lock.json", json_data(self.lock))
        report, output = self.run_review(head=self.commit("native and source changes"), expected=1)
        paths = {item["path"] for item in report["core"]["policy"]["unapproved_execution_candidates"]}
        self.assertEqual(paths, {"node_modules/pkg", "packages/local"})
        text = (output / "summary.md").read_text()
        self.assertIn("binding_gyp_sha256", text)
        self.assertIn("https://registry.npmjs.org/other/-/pkg-1.0.0.tgz", text)

    def test_source_url_preserved_across_checkout_locations(self):
        source = "https://registry.npmjs.org" + str(self.repo.resolve()) + "/pkg.tgz"
        self.lock["packages"]["node_modules/pkg"]["resolved"] = source
        self.write("package-lock.json", json_data(self.lock))
        head = self.commit("source URL contains checkout path")
        first, first_output = self.run_review(head=head, expected=1)
        original_repo = self.repo
        self.repo = self.root / "relocated-repository"
        try:
            subprocess.check_call(["git", "clone", "-q", "--no-hardlinks", str(original_repo), str(self.repo)])
            second, second_output = self.run_review(head=head, expected=1)
        finally:
            self.repo = original_repo
        for report, output in ((first, first_output), (second, second_output)):
            packages = {item["path"]: item for item in report["core"]["head"]["packages"]}
            self.assertEqual(packages["node_modules/pkg"]["source"], source)
            self.assertIn(source, (output / "report.json").read_text())
            self.assertIn(source, (output / "summary.md").read_text())
        self.assertEqual(first["core"], second["core"])
        self.assertEqual((first_output / "summary.md").read_bytes(), (second_output / "summary.md").read_bytes())

    def test_missing_base_policy_is_incomplete_even_if_head_contains_policy(self):
        self.policy_path.unlink()
        base = self.commit("base without approvals")
        self.policy_path.write_bytes(self.policy_bytes)
        head = self.commit("head supplies policy")
        report, _ = self.run_review(base=base, head=head, expected=2)
        self.assertEqual(report["errors"][0]["stage"], "base_policy")
        self.assertIn("missing Git path", report["errors"][0]["message"])

    def test_missing_workspace_manifest_is_incomplete_with_stable_error(self):
        (self.project / "packages/local/package.json").unlink()
        head = self.commit("remove workspace manifest")
        first, first_output = self.run_review(head=head, expected=2)
        _, second_output = self.run_review(head=head, expected=2)
        self.assertEqual(first["errors"][0]["stage"], "head_capture")
        self.assertIn("package.json", first["errors"][0]["message"])
        self.assertEqual((first_output / "report.json").read_bytes(), (second_output / "report.json").read_bytes())

    def test_removed_npm_lock_and_cross_format_are_incomplete(self):
        (self.project / "package-lock.json").unlink()
        self.write("pnpm-lock.yaml", b"lockfileVersion: '9.0'\n")
        report, _ = self.run_review(head=self.commit("different format"), expected=2)
        self.assertEqual(report["errors"][0]["stage"], "head_capture")
        self.assertIn("package-lock.json", report["errors"][0]["message"])

    def test_missing_and_noncommit_revisions_are_incomplete(self):
        for ref in ("unavailable-reference", "0" * 40, self.git("rev-parse", self.base + ":apps/example/package.json"), self.git("rev-parse", self.base + "^{tree}")):
            with self.subTest(ref=ref):
                report, _ = self.run_review(head=ref, expected=2)
                self.assertEqual(report["errors"][0]["stage"], "head_revision")

    def test_revision_option_and_project_traversal_rejected(self):
        report, _ = self.run_review(head="HEAD~1", expected=2)
        self.assertIn("revision", report["errors"][0]["message"])
        report, _ = self.run_review(expected=2, extra=("--project", "../example"))
        self.assertIn("path", report["errors"][0]["message"])

    def test_manifest_and_binding_symlinks_are_incomplete(self):
        for name in ("package.json", "packages/local/binding.gyp"):
            with self.subTest(name=name):
                self.git("reset", "--hard", self.base)
                path = self.project / name
                path.unlink()
                path.symlink_to("untrusted-target")
                report, _ = self.run_review(head=self.commit("symlink source"), expected=2)
                self.assertIn("regular Git blob", report["errors"][0]["message"])

    def test_case_aliases_and_nonportable_directory_entries_are_incomplete(self):
        for name in ("Binding.gyp", "Package.json", "bïnding.gyp"):
            with self.subTest(name=name):
                self.git("reset", "--hard", self.base)
                blob = subprocess.check_output(["git", "-C", str(self.repo), "hash-object", "-w", "--stdin"], input=b"case-aliased lifecycle input\n").decode().strip()
                self.git("update-index", "--add", "--cacheinfo", "100644," + blob + ",apps/example/" + name)
                self.git("commit", "-q", "-m", "aliased source input")
                report, _ = self.run_review(head=self.git("rev-parse", "HEAD"), expected=2)
                self.assertTrue(any(word in report["errors"][0]["message"] for word in ("alias", "non-ASCII")))

    def test_gitlink_mode_rejected_and_regular_executable_mode_preserved(self):
        path = "apps/example/packages/local/binding.gyp"
        self.git("update-index", "--add", "--cacheinfo", "160000," + self.base + "," + path)
        self.git("commit", "-q", "-m", "gitlink input")
        report, _ = self.run_review(head=self.git("rev-parse", "HEAD"), expected=2)
        self.assertIn("regular Git blob", report["errors"][0]["message"])
        self.git("reset", "--hard", self.base)
        self.git("update-index", "--chmod=+x", "apps/example/package.json")
        self.git("commit", "-q", "-m", "regular executable source")
        report, _ = self.run_review(head=self.git("rev-parse", "HEAD"))
        self.assertEqual(report["head"]["files"]["apps/example/package.json"]["mode"], "100755")

    def test_output_cannot_overwrite_repository_or_cache(self):
        before = self.git("status", "--porcelain")
        for output in (self.repo / "review", self.cache / "review"):
            result = subprocess.run([sys.executable, str(WRAPPER), "--repo", str(self.repo), "--base", self.base, "--head", self.base,
                                     "--tau-gate", str(BINARY), "--archive-cache", str(self.cache), "--output", str(output)], capture_output=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn("separate", json.loads(result.stdout)["errors"][0]["message"])
            self.assertFalse(output.exists())
        self.assertEqual(self.git("status", "--porcelain"), before)


if __name__ == "__main__":
    unittest.main()
