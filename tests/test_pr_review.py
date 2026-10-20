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
from pr_review import GitObjects


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
                         "scripts": {"prepare": "node scripts/prepare.mjs"}}
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
        self.write("scripts/prepare.mjs", b"import { writeFileSync } from 'node:fs'; writeFileSync('CANARY_EXECUTED', 'executed');\n")
        self.policy_path = self.project / ".tau-gate-approvals.json"
        self.source_policy_path = self.project / ".tau-gate-source-approvals.json"
        self.policy_path.write_bytes(json_data({"schema_version": 1, "approvals": []}))
        self.commit("initial fixture")
        self.policy = self.approvals()
        self.policy_bytes = json_data(self.policy)
        self.policy_path.write_bytes(self.policy_bytes)
        trusted = self.commit("trusted approvals")
        self.source_policy_path.write_bytes(json_data({"schema_version": 1, "digests": [self.source_digest(trusted)]}))
        self.base = self.commit("trusted source approval")

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

    def source_digest(self, commit):
        excluded = {b"apps/example/.tau-gate-approvals.json", b"apps/example/.tau-gate-source-approvals.json"}
        return GitObjects(self.repo).source_tree(commit, excluded)["sha256"]

    def script_free_base(self):
        self.manifest.pop("scripts")
        self.workspace.pop("scripts")
        self.write("package.json", json_data(self.manifest))
        self.write("packages/local/package.json", json_data(self.workspace))
        (self.project / "packages/local/binding.gyp").unlink()
        archive = self.archive({"name": "pkg", "version": "1.0.0"})
        digest = hashlib.sha512(archive).digest()
        (self.cache / (digest.hex() + ".tgz")).write_bytes(archive)
        self.lock["packages"]["node_modules/pkg"]["integrity"] = "sha512-" + base64.b64encode(digest).decode()
        self.lock["packages"]["node_modules/pkg"].pop("hasInstallScript")
        self.write("package-lock.json", json_data(self.lock))
        return self.commit("script-free base")

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
                   "--source-approvals", "apps/example/.tau-gate-source-approvals.json",
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
        self.assertEqual(first["source_approval"]["status"], "allowed")
        self.assertEqual(self.git("status", "--porcelain"), before)

    def test_changed_lifecycle_and_forged_head_approval_remain_blocked(self):
        self.manifest["scripts"]["prepare"] = "echo changed-root-canary > CANARY_EXECUTED"
        self.write("package.json", json_data(self.manifest))
        forged = self.approvals()
        self.policy_path.write_bytes(json_data(forged))
        for name, body in (("tools/pr_review.py", b"print('allowed')\n"),
                           ("tools/npm_evidence.py", b"print('allowed')\n"),
                           ("bin/tau-gate", b"forged binary\n"),
                           (".github/workflows/npm-pr-review.yml", b"jobs: {}\n")):
            destination = self.repo / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(body)
        head = self.commit("head attempts self approval and replaces tools")
        report, output = self.run_review(head=head, expected=1)
        candidates = report["core"]["policy"]["unapproved_execution_candidates"]
        self.assertEqual([item["path"] for item in candidates], [""])
        self.assertEqual((output / "base/approvals.json").read_bytes(), self.policy_bytes)
        self.assertEqual(report["policy"]["commit"], self.base)
        text = (output / "summary.md").read_text()
        self.assertIn(candidates[0]["fingerprint"], text)
        self.assertIn("lifecycle", text)
        self.assertIn("Introducer", text)

    def test_approval_transition_stays_valid_through_policy_update_and_cleanup(self):
        old_manifest = json_data(self.manifest)
        self.manifest["scripts"]["prepare"] = "echo approved-change > CANARY_EXECUTED"
        new_manifest = json_data(self.manifest)
        self.write("package.json", new_manifest)
        candidate_policy = self.approvals()
        candidate_preview = self.commit("candidate digest preview")
        candidate_digest = self.source_digest(candidate_preview)
        self.write("package.json", old_manifest)
        old_by_path = {item["path"]: item["fingerprint"] for item in self.policy["approvals"]}
        new_by_path = {item["path"]: item["fingerprint"] for item in candidate_policy["approvals"]}
        self.assertNotEqual(old_by_path[""], new_by_path[""])

        staged = {"schema_version": 2, "approvals": [
            {"path": path, "fingerprints": sorted({old_by_path[path], new_by_path[path]})}
            for path in sorted(old_by_path)]}
        self.policy_path.write_bytes(json_data(staged))
        self.source_policy_path.write_bytes(json_data({"schema_version": 1, "digests": sorted({self.source_digest(self.base), candidate_digest})}))
        staged_commit = self.commit("stage old and new fingerprints")
        blocked, _ = self.run_review(base=self.base, head=staged_commit, expected=1)
        self.assertEqual(blocked["source_approval"]["changed_trusted_paths"], [
            "apps/example/.tau-gate-approvals.json", "apps/example/.tau-gate-source-approvals.json"])
        self.run_review(base=staged_commit, head=staged_commit)

        self.write("package.json", new_manifest)
        candidate_commit = self.commit("update reviewed lifecycle")
        self.run_review(base=staged_commit, head=candidate_commit)

        cleaned = {"schema_version": 2, "approvals": [
            {"path": path, "fingerprints": [new_by_path[path]]}
            for path in sorted(new_by_path)]}
        self.policy_path.write_bytes(json_data(cleaned))
        self.source_policy_path.write_bytes(json_data({"schema_version": 1, "digests": [candidate_digest]}))
        cleaned_commit = self.commit("remove old fingerprints")
        self.run_review(base=candidate_commit, head=cleaned_commit, expected=1)
        self.run_review(base=cleaned_commit, head=cleaned_commit)
        self.write("package.json", old_manifest)
        rollback_commit = self.commit("attempt rollback to removed evidence")
        blocked, _ = self.run_review(base=cleaned_commit, head=rollback_commit, expected=1)
        self.assertEqual([item["path"] for item in blocked["core"]["policy"]["unapproved_execution_candidates"]], [""])

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
        report, _ = self.run_review(head=self.git("rev-parse", "HEAD"), expected=1)
        self.assertEqual(report["head"]["files"]["apps/example/package.json"]["mode"], "100755")

    def test_local_script_and_imported_file_changes_require_new_tree_digest(self):
        self.write("scripts/prepare.mjs", b"import './helper.mjs';\n")
        self.write("scripts/helper.mjs", b"process.stdout.write('changed');\n")
        head = self.commit("change local script and imported helper")
        report, output = self.run_review(head=head, expected=1)
        self.assertEqual(report["core"]["policy"]["outcome"], "allowed")
        self.assertEqual(report["source_approval"]["status"], "blocked")
        self.assertEqual(report["source_approval"]["unapproved_head_digest"], self.source_digest(head))
        self.assertIn("Unapproved source tree digest", (output / "summary.md").read_text())

    def test_untrusted_source_policy_edit_cannot_approve_script_change(self):
        self.write("scripts/prepare.mjs", b"process.stdout.write('changed');\n")
        changed = self.commit("change local script")
        self.source_policy_path.write_bytes(json_data({"schema_version": 1, "digests": [self.source_digest(changed)]}))
        report, _ = self.run_review(head=self.commit("forge source approval"), expected=1)
        self.assertEqual(report["source_approval"]["changed_trusted_paths"], ["apps/example/.tau-gate-source-approvals.json"])
        self.assertFalse(report["source_approval"]["matched"])

    def test_missing_and_malformed_trusted_source_policy_are_incomplete(self):
        for data in (None, b'{"schema_version":1,"digests":["BAD"]}', b'{"schema_version":1,"digests":[],"extra":1}'):
            with self.subTest(data=data):
                self.git("reset", "--hard", self.base)
                if data is None:
                    self.source_policy_path.unlink()
                else:
                    self.source_policy_path.write_bytes(data)
                base = self.commit("invalid trusted source policy")
                report, _ = self.run_review(base=base, head=base, expected=2)
                self.assertEqual(report["errors"][0]["stage"], "source_policy")

    def test_outside_project_change_and_symlink_fail_closed(self):
        outside = self.repo / "docs" / "note.md"
        outside.parent.mkdir()
        outside.write_text("new tracked file\n")
        report, _ = self.run_review(head=self.commit("outside project change"), expected=1)
        self.assertEqual(report["core"]["policy"]["outcome"], "allowed")
        self.assertEqual(report["source_approval"]["status"], "blocked")
        self.git("reset", "--hard", self.base)
        outside.parent.mkdir(parents=True, exist_ok=True)
        outside.unlink(missing_ok=True)
        outside.symlink_to("/tmp/outside-tree")
        report, _ = self.run_review(head=self.commit("symlink source"), expected=2)
        self.assertIn("symlink", report["errors"][0]["message"])

    def test_gitlink_oid_is_bound_without_reading_submodule_contents(self):
        self.git("update-index", "--add", "--cacheinfo", "160000," + self.base + ",third_party/example")
        self.git("commit", "-q", "-m", "add pinned submodule")
        head = self.git("rev-parse", "HEAD")
        report, _ = self.run_review(head=head, expected=1)
        self.assertEqual(report["core"]["policy"]["outcome"], "allowed")
        self.assertEqual(report["source_approval"]["base"]["gitlinks"], 0)
        self.assertEqual(report["source_approval"]["head"]["gitlinks"], 1)
        self.assertNotEqual(report["source_approval"]["base"]["sha256"], report["source_approval"]["head"]["sha256"])

    def test_policy_change_blocks_even_without_source_candidates(self):
        candidate_free = self.script_free_base()
        self.source_policy_path.write_bytes(json_data({"schema_version": 1, "digests": ["0" * 64]}))
        head = self.commit("head changes future source policy")
        report, _ = self.run_review(base=candidate_free, head=head, expected=1)
        self.assertEqual(report["core"]["policy"]["outcome"], "allowed")
        self.assertFalse(report["source_approval"]["required"])
        self.assertEqual(report["source_approval"]["changed_trusted_paths"], ["apps/example/.tau-gate-source-approvals.json"])

    def test_trusted_helper_and_workflow_edits_block_without_source_candidates(self):
        candidate_free = self.script_free_base()
        for path in ("tools/pr_review.py", "tools/npm_evidence.py", "tools/hashlib.py", ".github/workflows/other.yml"):
            with self.subTest(path=path):
                self.git("reset", "--hard", candidate_free)
                target = self.repo / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(b"changed trusted gate input\n")
                report, _ = self.run_review(base=candidate_free, head=self.commit("edit trusted gate input"), expected=1)
                self.assertEqual(report["core"]["policy"]["outcome"], "allowed")
                self.assertEqual(report["source_approval"]["changed_trusted_paths"], [path])

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
