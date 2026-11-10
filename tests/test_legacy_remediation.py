import base64
import copy
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
import npm_evidence as evidence
import npm3_legacy_remediation as remediation


def sri(data, algorithm):
    return algorithm + "-" + base64.b64encode(hashlib.new(algorithm, data).digest()).decode()


def observation(name="is-extglob", version="2.1.1", *, manifest=None, source_http=False):
    manifest = manifest or {"name": name, "version": version}
    manifest_bytes = evidence.json_bytes(manifest)
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        entry = tarfile.TarInfo("package/package.json")
        entry.size = len(manifest_bytes)
        tar.addfile(entry, io.BytesIO(manifest_bytes))
    archive = gzip.compress(output.getvalue(), mtime=0)
    _, url = remediation.registry_urls(name, version)
    metadata = {"name": name, "version": version, "dist": {"tarball": url,
        "integrity": sri(archive, "sha512"), "shasum": hashlib.sha1(archive).hexdigest()}}
    record = {"version": version, "resolved": url.replace("https://", "http://", 1) if source_http else url,
              "integrity": sri(archive, "sha1")}
    return record, metadata, archive


class LegacyRemediationTests(unittest.TestCase):
    def test_original_sha1_is_still_unqualified(self):
        record, _, archive = observation()
        with self.assertRaisesRegex(evidence.EvidenceError, "canonical SHA512"):
            evidence.archive_facts(archive, record["integrity"])

    def test_valid_proposal_keeps_observation_distinct_from_authorization(self):
        record, metadata, archive = observation("lodash", "3.9.3", source_http=True)
        new, result = remediation.verify_observation("node_modules/lodash", record, evidence.json_bytes(metadata), archive)
        self.assertTrue(new["resolved"].startswith("https://"))
        self.assertTrue(record["resolved"].startswith("http://"))
        self.assertEqual(new["integrity"], metadata["dist"]["integrity"])
        self.assertIn("not trusted enrollment", result["authority"])
        self.assertEqual(result["original_integrity"], record["integrity"])

    def test_old_sha1_and_current_sha512_mismatches_are_rejected(self):
        record, metadata, archive = observation()
        wrong_old = dict(record, integrity=sri(b"other", "sha1"))
        with self.assertRaisesRegex(evidence.EvidenceError, "original locked SHA1"):
            remediation.verify_observation("node_modules/is-extglob", wrong_old, evidence.json_bytes(metadata), archive)
        metadata["dist"]["integrity"] = sri(b"other", "sha512")
        with self.assertRaisesRegex(evidence.EvidenceError, "observed SHA512"):
            remediation.verify_observation("node_modules/is-extglob", record, evidence.json_bytes(metadata), archive)

    def test_observation_cannot_supply_a_weak_digest_or_change_identity_source(self):
        record, metadata, archive = observation()
        weak = copy.deepcopy(metadata)
        weak["dist"]["integrity"] = record["integrity"]
        with self.assertRaisesRegex(evidence.EvidenceError, "canonical SHA512"):
            remediation.verify_observation("node_modules/is-extglob", record, evidence.json_bytes(weak), archive)
        wrong_source = dict(record, resolved="https://example.com/is-extglob-2.1.1.tgz")
        with self.assertRaisesRegex(evidence.EvidenceError, "legacy source"):
            remediation.verify_observation("node_modules/is-extglob", wrong_source, evidence.json_bytes(metadata), archive)
        metadata["dist"]["tarball"] = "https://registry.npmjs.org/is-extglob/-/is-extglob-9.tgz"
        with self.assertRaisesRegex(evidence.EvidenceError, "canonical HTTPS"):
            remediation.verify_observation("node_modules/is-extglob", record, evidence.json_bytes(metadata), archive)

    def test_metadata_and_manifest_identity_must_match(self):
        for field, value in (("name", "other"), ("version", "9")):
            with self.subTest(field=field):
                record, metadata, archive = observation()
                metadata[field] = value
                with self.assertRaisesRegex(evidence.EvidenceError, "name/version"):
                    remediation.verify_observation("node_modules/is-extglob", record, evidence.json_bytes(metadata), archive)
                manifest = {"name": "is-extglob", "version": "2.1.1", field: value}
                record, metadata, archive = observation(manifest=manifest)
                with self.assertRaisesRegex(evidence.EvidenceError, "manifest .* does not match"):
                    remediation.verify_observation("node_modules/is-extglob", record, evidence.json_bytes(metadata), archive)

    def test_valid_digests_do_not_bypass_a_corrupt_gzip_tail(self):
        record, metadata, archive = observation()
        corrupt = bytearray(archive)
        corrupt[-8] ^= 1
        record["integrity"] = sri(corrupt, "sha1")
        metadata["dist"]["integrity"] = sri(corrupt, "sha512")
        metadata["dist"]["shasum"] = hashlib.sha1(corrupt).hexdigest()
        with self.assertRaises(evidence.EvidenceError):
            remediation.verify_observation("node_modules/is-extglob", record, evidence.json_bytes(metadata), corrupt)

    def test_http_is_never_fetched_and_metadata_cannot_redirect_it(self):
        with patch.object(remediation.urllib.request, "build_opener") as opener:
            with self.assertRaisesRegex(evidence.EvidenceError, "canonical HTTPS"):
                remediation.fetch_https("http://registry.npmjs.org/lodash/3.9.3", evidence.WorkBudget())
            opener.assert_not_called()
        record, metadata, archive = observation()
        metadata["dist"]["tarball"] = record["resolved"].replace("https://", "http://")
        with self.assertRaisesRegex(evidence.EvidenceError, "canonical HTTPS"):
            remediation.verify_observation("node_modules/is-extglob", record, evidence.json_bytes(metadata), archive)

    def test_patch_changes_only_the_two_selected_json_values(self):
        record, metadata, _ = observation("lodash", "3.9.3", source_http=True)
        lock = {"lockfileVersion": 3, "note": record["integrity"], "packages": {"": {}, "node_modules/lodash": record}}
        raw = json.dumps(lock, indent=4).replace("\n", "\r\n").encode() + b"\r\n"
        replacement = dict(record, integrity=metadata["dist"]["integrity"], resolved=metadata["dist"]["tarball"])
        result = remediation.patch_lock(raw, {"node_modules/lodash": replacement})
        expected = raw.replace(json.dumps(record["resolved"]).encode(), json.dumps(replacement["resolved"]).encode())
        position = expected.rfind(json.dumps(record["integrity"]).encode())
        expected = expected[:position] + json.dumps(replacement["integrity"]).encode() + expected[position + len(json.dumps(record["integrity"])):]
        self.assertEqual(result, expected)
        self.assertEqual(evidence.strict_json(result)["note"], record["integrity"])
        with self.assertRaisesRegex(evidence.EvidenceError, "outside source/integrity"):
            remediation.patch_lock(raw, {"node_modules/lodash": dict(replacement, version="9")})

    def test_existing_archives_are_independent_copies(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, destination = root / "original", root / "proposal"
            (source / "evidence").mkdir(parents=True)
            artifact = source / "evidence/existing.tgz"
            artifact.write_bytes(b"original archive")
            for name in ("source.json", "acquisition.json"):
                (source / name).write_bytes(b"{}")
            remediation.copy_snapshot(source, destination, {"evidence/existing.tgz": evidence.sha256(artifact.read_bytes())})
            copied = destination / "evidence/existing.tgz"
            self.assertNotEqual(artifact.stat().st_ino, copied.stat().st_ino)
            copied.write_bytes(b"tampered proposal")
            self.assertEqual(artifact.read_bytes(), b"original archive")

    def test_proposals_do_not_write_original_files_or_generate_approvals(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original, output = root / "original", root / "proposals"
            record, metadata, archive = observation()
            manifest = {"name": "root", "version": "1", "dependencies": {"is-extglob": "2.1.1"}}
            lock = {"lockfileVersion": 3, "packages": {"": manifest, "node_modules/is-extglob": record}}
            files, sides = {}, {}
            for side in ("base", "head"):
                source = original / "inputs/legacy-one" / side
                for directory in ("project", "evidence/projects"):
                    (source / directory).mkdir(parents=True)
                payloads = {"package.json": evidence.json_bytes(manifest), "package-lock.json": evidence.json_bytes(lock)}
                for name, data in payloads.items():
                    (source / "project" / name).write_bytes(data)
                (source / "evidence/projects/package.json").write_bytes(payloads["package.json"])
                index = {"schema_version": 1, "lock_sha256": evidence.sha256(payloads["package-lock.json"]),
                    "packages": [{"path": "", "project_manifest": "projects/package.json"}]}
                (source / "evidence/index.json").write_bytes(evidence.json_bytes(index))
                receipt = {"repository": "example/project", "commit": "1" * 40,
                    "files": {name: {"sha256": evidence.sha256(data)} for name, data in payloads.items()}, "absent": []}
                (source / "source.json").write_bytes(evidence.json_bytes(receipt))
                (source / "acquisition.json").write_bytes(evidence.json_bytes({"source_sha256": evidence.sha256(evidence.json_bytes(receipt)),
                    "packages": {"node_modules/is-extglob": {"status": "unavailable"}}}))
                files[side] = [{"path": name, "status": "captured", "sha256": evidence.sha256(data), "bytes": len(data)} for name, data in payloads.items()]
                sides[side] = "1" * 40
            selection = {"schema_version": 1, "pairs": [{"id": "legacy-one", "repository": "example/project", "files": files, **sides}]}
            (original / "selection.json").write_bytes(evidence.json_bytes(selection))
            inventory = lambda: {str(p.relative_to(original)): (p.read_bytes(), p.stat().st_mtime_ns) for p in original.rglob("*") if p.is_file()}
            before = inventory()
            result = remediation.prepare(original, output, observations={("is-extglob", "2.1.1"): (evidence.json_bytes(metadata), archive)})
            self.assertEqual(inventory(), before)
            self.assertEqual(result["legacy_records"], 2)
            self.assertFalse(result["approvals_created"])
            self.assertFalse(result["scripts_executed"])
            proposal = output / "proposals/legacy-one/base"
            self.assertFalse((proposal / "source.json").exists())
            self.assertEqual((proposal / "original-receipts/source.json").read_bytes(), (original / "inputs/legacy-one/base/source.json").read_bytes())
            self.assertEqual(evidence.strict_json((original / "inputs/legacy-one/base/project/package-lock.json").read_bytes())["packages"]["node_modules/is-extglob"]["integrity"], record["integrity"])
            with self.assertRaisesRegex(evidence.EvidenceError, "missing evidence"):
                evidence.validate_bundle(original / "inputs/legacy-one/base/project/package-lock.json", original / "inputs/legacy-one/base/evidence/index.json")
            with self.assertRaisesRegex(evidence.EvidenceError, "separate"):
                remediation.prepare(original, original / "nested-output")
            failed = root / "failed-proposal"
            with self.assertRaisesRegex(evidence.EvidenceError, "original locked SHA1"):
                remediation.prepare(original, failed, observations={("is-extglob", "2.1.1"): (evidence.json_bytes(metadata), archive + b"x")})
            self.assertEqual(inventory(), before)
            self.assertFalse((failed / "proposals").exists())
            self.assertEqual((failed / "registry-observations/is-extglob-2.1.1/artifact.tgz").read_bytes(), archive + b"x")


if __name__ == "__main__":
    unittest.main()
