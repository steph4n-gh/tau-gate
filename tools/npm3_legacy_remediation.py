#!/usr/bin/env python3
"""Prepare unapproved lock/evidence proposals for two frozen legacy npm versions."""

import argparse
import base64
import copy
import difflib
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import urllib.parse
import urllib.request

import npm_evidence as evidence
import qualification as q


VERSIONS = {"is-extglob": "2.1.1", "lodash": "3.9.3"}


def registry_urls(name, version):
    if name not in VERSIONS or VERSIONS[name] != version:
        raise evidence.EvidenceError("outside the two-version legacy remediation scope")
    origin = "https://registry.npmjs.org/"
    return origin + name + "/" + version, origin + name + "/-/" + name + "-" + version + ".tgz"


def fetch_https(url, budget, limit=evidence.MAX_FILE):
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != "https" or parsed.netloc != "registry.npmjs.org"
            or parsed.query or parsed.fragment or parsed.username is not None):
        raise evidence.EvidenceError("observation requires canonical HTTPS registry.npmjs.org")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), evidence.NoRedirect())
    request = urllib.request.Request(url, headers={"Accept-Encoding": "identity", "User-Agent": "tau-gate-remediation/1"})
    with opener.open(request, timeout=30) as response:
        if response.status != 200:
            raise evidence.EvidenceError("registry observation must return HTTP 200")
        raw = response.read(min(limit, budget.read_remaining) + 1)
    budget.charge("read_remaining", len(raw), "remediation observation read budget exceeded")
    if len(raw) > limit:
        raise evidence.EvidenceError("registry observation exceeds file limit")
    return raw


def legacy_records(lock):
    found = {}
    for path, record in lock["packages"].items():
        if not evidence.is_registry_path(path):
            continue
        name = evidence.expected_name(path, record)
        if name not in VERSIONS or VERSIONS[name] != record.get("version") or not str(record.get("integrity", "")).startswith("sha1-"):
            continue
        _, url = registry_urls(name, record["version"])
        if record.get("resolved") not in (url, url.replace("https://", "http://", 1)):
            raise evidence.EvidenceError("legacy source differs from exact registry version URL")
        found[path] = record
    return found


def verify_observation(path, record, metadata_bytes, archive, *, budget=None):
    name = evidence.expected_name(path, record)
    version = record.get("version")
    metadata_url, archive_url = registry_urls(name, version)
    if legacy_records({"packages": {path: record}}) != {path: record}:
        raise evidence.EvidenceError("requires an exact supported legacy record")
    integrity = record.get("integrity")
    if not isinstance(integrity, str) or not re.fullmatch(r"sha1-[A-Za-z0-9+/]{27}=", integrity):
        raise evidence.EvidenceError("requires one canonical legacy SHA1 token")
    locked_sha1 = base64.b64decode(integrity[5:], validate=True)
    if base64.b64encode(locked_sha1).decode() != integrity[5:] or hashlib.sha1(archive).digest() != locked_sha1:
        raise evidence.EvidenceError("original locked SHA1 does not match observed bytes")
    metadata = evidence.strict_json(metadata_bytes)
    if not isinstance(metadata, dict) or metadata.get("name") != name or metadata.get("version") != version:
        raise evidence.EvidenceError("registry observation name/version differs from locked identity")
    dist = metadata.get("dist")
    if not isinstance(dist, dict) or dist.get("tarball") != archive_url:
        raise evidence.EvidenceError("registry tarball is not the canonical HTTPS version URL")
    observed_integrity = dist.get("integrity")
    if hashlib.sha512(archive).digest() != evidence.sri_digest(observed_integrity):
        raise evidence.EvidenceError("registry observed SHA512 does not match archive")
    if dist.get("shasum") != hashlib.sha1(archive).hexdigest():
        raise evidence.EvidenceError("registry observed SHA1 does not match archive")
    manifest_bytes, manifest, _, _ = evidence.archive_facts(archive, observed_integrity, budget=budget)
    evidence.check_identity(path, record, manifest)
    proposed = dict(record, integrity=observed_integrity, resolved=archive_url)
    return proposed, {
        "path": path, "name": name, "version": version,
        "metadata_url": metadata_url, "metadata_sha256": evidence.sha256(metadata_bytes),
        "acquisition_url": archive_url, "archive_sha256": evidence.sha256(archive),
        "archive_sha512": hashlib.sha512(archive).hexdigest(),
        "manifest_sha256": evidence.sha256(manifest_bytes),
        "original_integrity": integrity, "observed_registry_integrity": observed_integrity,
        "original_source": record["resolved"], "proposed_source": archive_url,
        "original_sha1_consistent": True, "registry_sha512_verified": True,
        "authority": "current registry observation, not trusted enrollment or execution approval",
    }


def patch_lock(raw, replacements):
    old = evidence.strict_json(raw)
    expected = copy.deepcopy(old)
    text = raw.decode("utf-8")
    decoder = json.JSONDecoder()
    edits = []
    for path, new_record in replacements.items():
        old_record = old["packages"][path]
        matches = []
        for match in re.finditer(re.escape(json.dumps(path)) + r"\s*:\s*(\{)", text):
            start = match.start(1)
            value, end = decoder.raw_decode(text, start)
            if value == old_record:
                matches.append((start, end))
        if len(matches) != 1:
            raise evidence.EvidenceError("ambiguous locked record text; no proposal written")
        start, end = matches[0]
        record_text = text[start:end]
        if old_record.keys() != new_record.keys():
            raise evidence.EvidenceError("proposal may only replace existing source/integrity values")
        for field in old_record:
            if old_record[field] == new_record[field]:
                continue
            if field not in ("integrity", "resolved"):
                raise evidence.EvidenceError("proposal changes a field outside source/integrity")
            pattern = re.escape(json.dumps(field)) + r'\s*:\s*("(?:[^"\\]|\\.)*")'
            values = [m for m in re.finditer(pattern, record_text) if json.loads(m.group(1)) == old_record[field]]
            if len(values) != 1:
                raise evidence.EvidenceError("ambiguous locked field text; no proposal written")
            match = values[0]
            edits.append((start + match.start(1), start + match.end(1), json.dumps(new_record[field])))
        expected["packages"][path] = new_record
    for start, end, replacement in sorted(edits, reverse=True):
        text = text[:start] + replacement + text[end:]
    result = text.encode("utf-8")
    if evidence.strict_json(result) != expected:
        raise evidence.EvidenceError("proposal changed bytes outside intended record values")
    return result


def copy_snapshot(source, destination, verified_files):
    for relative in sorted(verified_files):
        if not relative.startswith(("project/", "evidence/")):
            continue
        item, target = source / relative, destination / relative
        if item.is_symlink() or not item.is_file():
            raise evidence.EvidenceError("source snapshot file is no longer regular")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(item, target)
    originals = destination / "original-receipts"
    originals.mkdir()
    for name in ("source.json", "acquisition.json"):
        shutil.copyfile(source / name, originals / name)


def prepare(original, output, *, observations=None):
    original, output = Path(original).resolve(), Path(output).resolve()
    if output == original or output.is_relative_to(original) or original.is_relative_to(output):
        raise evidence.EvidenceError("proposal output must be separate from original snapshots")
    if output.exists() and any(output.iterdir()):
        raise evidence.EvidenceError("proposal output must be absent or empty")
    output.mkdir(parents=True, exist_ok=True)
    observed_at = datetime.now(timezone.utc).isoformat()
    selection_bytes = q.read(original / "selection.json")
    selection = evidence.strict_json(selection_bytes)
    if not isinstance(selection, dict) or selection.get("schema_version") != 1 or not isinstance(selection.get("pairs"), list):
        raise evidence.EvidenceError("requires a frozen pair selection")
    targets = []
    seen = set()
    for pair in selection["pairs"]:
        case = pair["id"]
        if not isinstance(case, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", case) or case in seen:
            raise evidence.EvidenceError("invalid or duplicate frozen pair ID")
        seen.add(case)
        sides = []
        for side in ("base", "head"):
            source = original / "inputs" / case / side
            _, lock = evidence.load_lock(source / "project/package-lock.json")
            sides.append((side, source, legacy_records(lock)))
        if any(records for _, _, records in sides):
            targets.append((pair, sides))
    observed = {} if observations is None else dict(observations)
    acquisition_budget = evidence.WorkBudget(read=4 * 1024 ** 3)
    proposals = []
    for pair, sides in targets:
        for side, source, records in sides:
            captured = [item for item in pair["files"][side] if item["status"] == "captured"]
            _, before = q.verify_snapshot(source, pair["repository"], pair[side], captured)
            replacements, checks, archives = {}, [], {}
            for path, record in records.items():
                name, version = evidence.expected_name(path, record), record["version"]
                key = (name, version)
                if key not in observed:
                    metadata_url, archive_url = registry_urls(name, version)
                    observed[key] = (fetch_https(metadata_url, acquisition_budget, evidence.MAX_MANIFEST),
                                     evidence.fetch_archive(archive_url, budget=acquisition_budget))
                metadata, archive = observed[key]
                observation = output / "registry-observations" / (name + "-" + version)
                observation.mkdir(parents=True, exist_ok=True)
                (observation / "metadata.json").write_bytes(metadata)
                (observation / "artifact.tgz").write_bytes(archive)
                (observation / "observation.json").write_bytes(evidence.json_bytes({
                    "observed_at_utc": observed_at, "metadata_url": registry_urls(name, version)[0],
                    "acquisition_url": registry_urls(name, version)[1],
                    "metadata_sha256": evidence.sha256(metadata), "archive_sha256": evidence.sha256(archive),
                    "authority": "raw observation only; original binding and approval status unchanged"}))
                proposed, check = verify_observation(path, record, metadata, archive)
                replacements[path] = proposed
                checks.append(check)
                archives[path] = archive
            destination = output / "proposals" / pair["id"] / side
            copy_snapshot(source, destination, before)
            original_lock = q.read(source / "project/package-lock.json")
            proposed_lock = patch_lock(original_lock, replacements)
            (destination / "project/package-lock.json").write_bytes(proposed_lock)
            index_path = destination / "evidence/index.json"
            index = evidence.strict_json(evidence.read_limited(index_path))
            index["lock_sha256"] = evidence.sha256(proposed_lock)
            paths = {item["path"] for item in index["packages"]}
            for path, archive in archives.items():
                if path in paths:
                    raise evidence.EvidenceError("legacy evidence already exists; refusing ambiguous proposal")
                relative = "artifacts/" + evidence.sha256(archive) + ".tgz"
                artifact_path = destination / "evidence" / relative
                artifact_path.parent.mkdir(parents=True, exist_ok=True)
                if artifact_path.exists():
                    if evidence.read_limited(artifact_path) != archive:
                        raise evidence.EvidenceError("proposed archive path already contains different bytes")
                else:
                    artifact_path.write_bytes(archive)
                index["packages"].append({"path": path, "artifact": relative})
            index["packages"].sort(key=lambda entry: entry["path"])
            index_path.write_bytes(evidence.json_bytes(index))
            facts = evidence.validate_bundle(destination / "project/package-lock.json", index_path, destination / "project/package.json")
            diff = "".join(difflib.unified_diff(original_lock.decode().splitlines(True), proposed_lock.decode().splitlines(True), fromfile="original/package-lock.json", tofile="proposed/package-lock.json"))
            (destination / "lock.diff").write_text(diff)
            _, after = q.verify_snapshot(source, pair["repository"], pair[side], captured)
            if before != after or q.read(original / "selection.json") != selection_bytes:
                raise evidence.EvidenceError("original snapshot changed during proposal preparation")
            receipt = {"id": pair["id"], "repository": pair["repository"], "side": side,
                "original_commit": pair[side], "original_input_sha256": before,
                "original_inputs_unchanged": True, "original_lock_sha256": evidence.sha256(original_lock),
                "proposed_lock_sha256": evidence.sha256(proposed_lock), "proposed_index_sha256": evidence.sha256(index_path.read_bytes()),
                "observations": checks, "collector_facts_sha256": evidence.sha256(evidence.json_bytes(facts)),
                "scope": "counterfactual lock/evidence proposal; not the original historical snapshot",
                "authorization": "not activated; no artifact trust enrollment or execution approvals created",
                "original_legacy_status": ("original SHA1 bindings remain unqualified; source inputs unchanged"
                    if records else "no legacy record edits required on this side; original inputs unchanged")}
            (destination / "proposal.json").write_bytes(evidence.json_bytes(receipt))
            proposals.append(receipt)
    receipt = {"schema_version": 1, "original_selection_sha256": evidence.sha256(selection_bytes),
        "observed_at_utc": observed_at,
        "original": str(original), "proposals": proposals, "pairs": len(targets),
        "legacy_records": sum(len(p["observations"]) for p in proposals),
        "scope": "observed current registry bytes and proposed lock edits; no original qualification completion credit",
        "scripts_executed": False, "approvals_created": False, "network_read_bytes": 4 * 1024 ** 3 - acquisition_budget.read_remaining}
    (output / "receipt.json").write_bytes(evidence.json_bytes(receipt))
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--original", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        receipt = prepare(args.original, args.output)
    except (evidence.EvidenceError, OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(2, str(error) + "\n")
    print(json.dumps({"pairs": receipt["pairs"], "legacy_records": receipt["legacy_records"],
                      "status": "unapproved proposals only"}))


if __name__ == "__main__":
    main()
