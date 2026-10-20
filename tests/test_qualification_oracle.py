import base64
import gzip
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import qualification_oracle as oracle


def encoded(value):
    return json.dumps(value, sort_keys=True).encode()


def archive(manifest, extra=(), format=tarfile.USTAR_FORMAT, mtime=0, root="package"):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=format) as stream:
        for name, data in [(root + "/package.json", encoded(manifest)), *extra]:
            member = tarfile.TarInfo(name)
            member.size = len(data)
            stream.addfile(member, io.BytesIO(data))
    return gzip.compress(raw.getvalue(), mtime=mtime)


class OracleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)

    def snapshot(self, manifest=None, extra=(), archive_bytes=None, source=None, missing=False, root=None, workspace=None, integrity=None):
        number = len(list(self.root.iterdir()))
        directory = self.root / str(number)
        directory.mkdir()
        manifest = {"name": "pkg", "version": "1.0.0"} if manifest is None else manifest
        root = {"name": "app", "version": "1.0.0"} if root is None else root
        packages = {"": {key: value for key, value in root.items() if key in ("name", "version", "dependencies", "devDependencies", "optionalDependencies", "peerDependencies")}}
        locators = [{"path": "", "project_manifest": "package.json"}]
        (directory / "package.json").write_bytes(encoded(root))
        if manifest is not False:
            artifact = archive(manifest, extra) if archive_bytes is None else archive_bytes
            (directory / "artifact.tgz").write_bytes(artifact)
            packages["node_modules/pkg"] = {"version": manifest["version"], "resolved": source or "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz", "integrity": integrity or "sha512-" + base64.b64encode(hashlib.sha512(artifact).digest()).decode()}
            if not missing:
                locators.append({"path": "node_modules/pkg", "artifact": "artifact.tgz"})
        if workspace is not None:
            target = "packages/pkg"
            packages[target] = {"name": workspace["name"], "version": workspace["version"]}
            packages["node_modules/workspace"] = {"resolved": target, "link": True}
            (directory / target).mkdir(parents=True)
            (directory / target / "package.json").write_bytes(encoded(workspace))
            locators.append({"path": target, "project_manifest": target + "/package.json"})
        lock_bytes = encoded({"lockfileVersion": 3, "packages": packages})
        (directory / "package-lock.json").write_bytes(lock_bytes)
        index = {"schema_version": 1, "lock_sha256": hashlib.sha256(lock_bytes).hexdigest(), "packages": locators}
        (directory / "index.json").write_bytes(encoded(index))
        return oracle.snapshot_facts(directory / "package-lock.json", directory / "index.json", directory / "package.json"), directory

    def test_unchanged_known_and_unknown_snapshots_have_no_events(self):
        for missing in (False, True):
            facts, _ = self.snapshot(missing=missing)
            self.assertEqual(oracle.events(facts, facts), [])

    def test_hook_changes_have_execution_obligation(self):
        before, _ = self.snapshot({"name": "pkg", "version": "1.0.0", "scripts": {"install": "old", "postinstall": "remove"}})
        after, _ = self.snapshot({"name": "pkg", "version": "1.0.0", "scripts": {"install": "new", "preinstall": "add"}})
        events = oracle.events(before, after)
        hooks = {event["kind"] for event in events if event["obligation"] == "execution_change"}
        self.assertEqual(hooks, {"lifecycle_added", "lifecycle_removed", "lifecycle_changed"})
        self.assertTrue(all(event["approval_relevant"] for event in events))

    def test_source_change_is_visible_for_script_free_packages(self):
        before, _ = self.snapshot()
        after, _ = self.snapshot(source="https://other.example/pkg.tgz")
        event = next(event for event in oracle.events(before, after) if event["kind"] == "source_changed")
        self.assertEqual(event["obligation"], "package_change")
        self.assertFalse(event["approval_relevant"])

    def test_implicit_native_and_binding_changes(self):
        before, _ = self.snapshot()
        after, _ = self.snapshot(extra=[("package/binding.gyp", b"one")])
        events = oracle.events(before, after)
        self.assertIn("implicit_native_changed", {event["kind"] for event in events})
        self.assertIn("binding_changed", {event["kind"] for event in events})
        newer, _ = self.snapshot(extra=[("package/binding.gyp", b"two")])
        self.assertIn("binding_changed", {event["kind"] for event in oracle.events(after, newer)})

    def test_native_suppression_and_empty_install(self):
        for scripts, disabled, expected in [({}, False, True), ({"install": ""}, False, True), ({"preinstall": "run"}, False, False), ({}, True, False)]:
            manifest = {"name": "pkg", "version": "1.0.0", "scripts": scripts}
            if disabled:
                manifest["gypfile"] = False
            facts, _ = self.snapshot(manifest, extra=[("package/binding.gyp", b"{}")])
            self.assertEqual(facts["packages"]["node_modules/pkg"]["implicit_native"], expected)

    def test_root_workspace_and_link_event_scopes(self):
        scripts = {event: event for event in oracle.ROOT_EVENTS}
        facts, _ = self.snapshot(manifest=False, root={"name": "app", "version": "1.0.0", "scripts": scripts}, workspace={"name": "work", "version": "1.0.0", "scripts": scripts})
        self.assertEqual(facts["status"], "complete")
        self.assertEqual(set(facts["packages"][""]["scripts"]), set(oracle.ROOT_EVENTS))
        self.assertEqual(set(facts["packages"]["packages/pkg"]["scripts"]), set(oracle.INSTALL_EVENTS) | {"prepare"})
        self.assertFalse(facts["packages"]["node_modules/workspace"]["install_candidate"])

    def test_binary_entrypoints_do_not_establish_automatic_execution(self):
        facts, _ = self.snapshot({"name": "pkg", "version": "1.0.0", "bin": {"pkg": "run.js"}, "scripts": {"prepare": "not registry install"}})
        package = facts["packages"]["node_modules/pkg"]
        self.assertFalse(package["install_candidate"])
        self.assertEqual(package["binary_entrypoints"], {"pkg": "run.js"})
        self.assertEqual(package["scripts"], {})

    def test_tolerates_pax_gnu_unicode_spaces_and_long_paths(self):
        manifest = {"name": "pkg", "version": "1.0.0", "scripts": {"postinstall": "visible"}}
        for format in (tarfile.PAX_FORMAT, tarfile.GNU_FORMAT):
            data = archive(manifest, [("package/ordinary spaced file", b""), ("package/" + "x" * 160, b""), ("package/caf\u00e9.txt", b"ok")], format=format)
            facts, _ = self.snapshot(manifest, archive_bytes=data)
            self.assertEqual(facts["status"], "complete")
            self.assertEqual(facts["packages"]["node_modules/pkg"]["scripts"]["postinstall"], "visible")
            self.assertIn("nonportable_tar_path", facts["packages"]["node_modules/pkg"]["profile_conditions"])

    def test_duplicate_and_case_alias_inputs_are_unknown(self):
        for extra in [[("package/package.json", b"{}")], [("package/Binding.gyp", b"{}")], [("package/A", b""), ("package/a", b"")]]:
            facts, _ = self.snapshot(extra=extra)
            package = facts["packages"]["node_modules/pkg"]
            self.assertEqual(package["status"], "unknown")
            self.assertNotIn("scripts", package)

    def test_legacy_archive_roots_preserve_lifecycle_facts_and_actual_root(self):
        manifest = {"name": "pkg", "version": "1.0.0", "scripts": {"postinstall": "visible"}}
        for root in ("json5", "cacheable-request"):
            data = archive(manifest, [(root + "/binding.gyp", b"{}")], root=root)
            facts, _ = self.snapshot(manifest, archive_bytes=data)
            package = facts["packages"]["node_modules/pkg"]
            self.assertEqual(package["status"], "known")
            self.assertEqual(package["archive_root"], root)
            self.assertEqual(package["scripts"], {"postinstall": "visible"})
            self.assertTrue(package["implicit_native"])
            self.assertIn("legacy_archive_root", package["profile_conditions"])

    def test_legacy_ustar_padding_after_prefix_nul_is_not_integrity_failure(self):
        manifest = {"name": "pkg", "version": "1.0.0"}
        raw = bytearray(gzip.decompress(archive(manifest, root="cacheable-request")))
        raw[345:360] = b"\0" + b"1460914891531" + b"\0"
        raw[148:156] = b"        "
        raw[148:156] = (f"{sum(raw[:512]):06o}\0 ").encode()
        facts, _ = self.snapshot(manifest, archive_bytes=gzip.compress(bytes(raw), mtime=0))
        package = facts["packages"]["node_modules/pkg"]
        self.assertEqual(package["status"], "known")
        self.assertEqual(package["archive_root"], "cacheable-request")

    def test_legacy_root_ambiguities_and_lifecycle_special_entries_are_unknown(self):
        manifest = {"name": "pkg", "version": "1.0.0"}
        extras = [
            [("legacy/Package.json", b"{}")],
            [("Legacy/binding.gyp", b"{}")],
            [("other/package.json", encoded(manifest))],
            [("legacy/path", b"file"), ("legacy/path/child", b"child")],
            [("legacy/binding.gyp", b"one"), ("legacy/binding.gyp", b"two")],
        ]
        for extra in extras:
            facts, _ = self.snapshot(archive_bytes=archive(manifest, extra, root="legacy"))
            self.assertEqual(facts["packages"]["node_modules/pkg"]["status"], "unknown")
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as stream:
            member = tarfile.TarInfo("legacy/package.json")
            member.type = tarfile.SYMTYPE
            member.linkname = "elsewhere"
            stream.addfile(member)
        facts, _ = self.snapshot(archive_bytes=gzip.compress(raw.getvalue(), mtime=0))
        self.assertEqual(facts["packages"]["node_modules/pkg"]["status"], "unknown")

    def test_legacy_archive_identity_still_matches_lock(self):
        data = archive({"name": "different", "version": "1.0.0"}, root="legacy")
        facts, _ = self.snapshot(archive_bytes=data)
        self.assertIn("manifest name differs", facts["packages"]["node_modules/pkg"]["reason"])

    def test_missing_evidence_keeps_identity_without_claiming_script_removal(self):
        before, _ = self.snapshot({"name": "pkg", "version": "1.0.0", "scripts": {"install": "run"}})
        after, _ = self.snapshot(missing=True, source="https://other.example/pkg.tgz")
        self.assertEqual(after["status"], "partial")
        package = after["packages"]["node_modules/pkg"]
        self.assertEqual(package["version"], "1.0.0")
        self.assertNotIn("scripts", package)
        events = oracle.events(before, after)
        self.assertIn("source_changed", {event["kind"] for event in events})
        self.assertFalse(any(event["kind"].startswith("lifecycle_") for event in events))

    def test_git_and_file_sources_are_unknown_even_with_matching_archive(self):
        for source in ("git+https://github.com/a/b.git", "https://github.com/a/b/archive/main.tar.gz", "file:local.tgz"):
            facts, _ = self.snapshot(source=source)
            self.assertEqual(facts["packages"]["node_modules/pkg"]["status"], "unknown")

    def test_wrong_integrity_is_unknown_but_sha1_is_known_noncanonical(self):
        artifact = archive({"name": "pkg", "version": "1.0.0"})
        wrong = "sha512-" + base64.b64encode(b"x" * 64).decode()
        facts, _ = self.snapshot(archive_bytes=artifact, integrity=wrong)
        self.assertIn("integrity mismatch", facts["packages"]["node_modules/pkg"]["reason"])
        sha1 = "sha1-" + base64.b64encode(hashlib.sha1(artifact).digest()).decode()
        facts, _ = self.snapshot(archive_bytes=artifact, integrity=sha1)
        self.assertEqual(facts["status"], "complete")
        self.assertEqual(facts["packages"]["node_modules/pkg"]["profile_conditions"], ["noncanonical_integrity"])

    def test_recompression_changes_artifact_without_inventing_hook_change(self):
        manifest = {"name": "pkg", "version": "1.0.0", "scripts": {"install": "same"}}
        before, _ = self.snapshot(manifest, archive_bytes=archive(manifest, mtime=1))
        after, _ = self.snapshot(manifest, archive_bytes=archive(manifest, mtime=2))
        events = oracle.events(before, after)
        kinds = {event["kind"] for event in events}
        self.assertEqual(kinds, {"artifact_changed", "integrity_changed"})
        event = next(event for event in events if event["kind"] == "artifact_changed")
        self.assertEqual(event["before"], before["packages"]["node_modules/pkg"]["artifact_sha512"])
        self.assertEqual(event["after"], after["packages"]["node_modules/pkg"]["artifact_sha512"])

    def test_invalid_index_and_changed_root_bytes_do_not_supply_facts(self):
        _, directory = self.snapshot()
        (directory / "different.json").write_text("{}")
        facts = oracle.snapshot_facts(directory / "package-lock.json", directory / "index.json", directory / "different.json")
        self.assertEqual(facts["packages"][""]["status"], "unknown")
        index = json.loads((directory / "index.json").read_bytes())
        index["lock_sha256"] = "bad"
        (directory / "index.json").write_bytes(encoded(index))
        facts = oracle.snapshot_facts(directory / "package-lock.json", directory / "index.json")
        self.assertEqual(facts["status"], "partial")
        self.assertTrue(all(package["status"] == "unknown" for package in facts["packages"].values()))

    def test_resource_limits_and_deep_json_become_unknown(self):
        facts, directory = self.snapshot(extra=[("package/huge", b"x" * 30000)])
        with patch.object(oracle, "MAX_FILE", 20000):
            facts = oracle.snapshot_facts(directory / "package-lock.json", directory / "index.json")
        self.assertIn("expanded limit", facts["packages"]["node_modules/pkg"]["reason"])
        with self.assertRaises(oracle.OracleError):
            oracle._json(b"[" * 129 + b"0" + b"]" * 129)

    def test_duplicate_json_and_locator_paths_are_unknown(self):
        _, directory = self.snapshot()
        index = json.loads((directory / "index.json").read_bytes())
        index["packages"].append(index["packages"][0])
        (directory / "index.json").write_bytes(encoded(index))
        facts = oracle.snapshot_facts(directory / "package-lock.json", directory / "index.json")
        self.assertEqual(facts["status"], "partial")
        with self.assertRaises(oracle.OracleError):
            oracle._json(b'{"scripts":{},"scripts":{"install":"bad"}}')

    def test_nonfinite_json_numbers_and_concatenated_tar_are_unknown(self):
        for value in (b'{"value":NaN}', b'{"value":Infinity}', b'{"value":1e9999}'):
            with self.assertRaises(oracle.OracleError):
                oracle._json(value)
        manifest = {"name": "pkg", "version": "1.0.0"}
        first = archive(manifest)
        second = archive({**manifest, "scripts": {"install": "hidden"}})
        facts, _ = self.snapshot(manifest, archive_bytes=first + second)
        self.assertEqual(facts["packages"]["node_modules/pkg"]["status"], "unknown")
        self.assertNotIn("scripts", facts["packages"]["node_modules/pkg"])

    def test_added_removed_instances_are_package_obligations(self):
        before, _ = self.snapshot(manifest=False)
        after, _ = self.snapshot()
        added = next(event for event in oracle.events(before, after) if event["kind"] == "added")
        self.assertEqual(added["path"], "node_modules/pkg")
        self.assertEqual(added["obligation"], "package_change")
        self.assertEqual(next(event for event in oracle.events(after, before) if event["kind"] == "removed")["after"], None)


if __name__ == "__main__":
    unittest.main()
