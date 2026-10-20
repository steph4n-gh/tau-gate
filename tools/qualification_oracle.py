#!/usr/bin/env python3
import base64
import gzip
import hashlib
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import urllib.parse


MAX_FILE = 64 * 1024 * 1024
MAX_MANIFEST = 1024 * 1024
MAX_MEMBERS = 10000
MAX_DEPTH = 128
ROOT_EVENTS = ("preinstall", "install", "postinstall", "prepublish", "preprepare", "prepare", "postprepare")
INSTALL_EVENTS = ("preinstall", "install", "postinstall")
SCOPED_EVENTS = {"root": ROOT_EVENTS, "workspace": INSTALL_EVENTS + ("prepare",), "archive": INSTALL_EVENTS}
IDENTITY_FIELDS = ("name", "version", "source", "integrity")
BYTE_FIELDS = (("manifest_sha256", "manifest_changed"), ("artifact_sha256", "artifact_changed"), ("binding_sha256", "binding_changed"))


class OracleError(ValueError):
    pass


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise OracleError(f"duplicate JSON key {key!r}")
            result[key] = value
        return result

    def constant(value):
        raise OracleError(f"invalid JSON constant {value}")

    def finite_float(value):
        number = float(value)
        if not math.isfinite(number):
            raise OracleError("JSON number exceeds finite range")
        return number

    try:
        value = json.loads(data, object_pairs_hook=pairs, parse_constant=constant, parse_float=finite_float)
        pending = [(value, 1)]
        while pending:
            item, depth = pending.pop()
            if isinstance(item, (dict, list)):
                if depth > MAX_DEPTH:
                    raise OracleError("JSON nesting exceeds 128")
                pending.extend((child, depth + 1) for child in (item.values() if isinstance(item, dict) else item))
        return value
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise OracleError(f"invalid JSON: {exc}") from exc


def _read(path, limit=MAX_FILE):
    try:
        with Path(path).open("rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise OracleError("input is not a regular file")
            data = stream.read(limit + 1)
    except OSError as exc:
        raise OracleError(f"cannot read input: {exc}") from exc
    if len(data) > limit:
        raise OracleError(f"input exceeds {limit} bytes")
    return data


def _relative(value, empty=False):
    if not isinstance(value, str) or (not value and not empty) or "\\" in value or any(ord(c) < 32 for c in value):
        raise OracleError("unsafe relative path")
    if value and (value.startswith("/") or any(part in ("", ".", "..") for part in value.split("/"))):
        raise OracleError("unsafe relative path")
    return PurePosixPath(value)


def _locator(root, value):
    relative = _relative(value)
    current = Path(root).resolve()
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise OracleError("symlink in evidence locator")
    return current


def _integrity(data, value):
    if not isinstance(value, str):
        raise OracleError("missing integrity")
    supported = {"sha1": 1, "sha256": 2, "sha384": 3, "sha512": 4}
    tokens = []
    for token in value.split():
        match = re.fullmatch(r"(sha1|sha256|sha384|sha512)-([A-Za-z0-9+/]+={0,2})", token)
        if not match:
            raise OracleError("unsupported or malformed integrity token")
        algorithm, encoded = match.groups()
        try:
            digest = base64.b64decode(encoded, validate=True)
        except ValueError as exc:
            raise OracleError("invalid integrity base64") from exc
        if len(digest) != hashlib.new(algorithm).digest_size:
            raise OracleError("invalid integrity digest length")
        tokens.append((algorithm, digest))
    if not tokens:
        raise OracleError("empty integrity")
    strongest = max(supported[algorithm] for algorithm, _ in tokens)
    if not any(hashlib.new(algorithm, data).digest() == digest for algorithm, digest in tokens if supported[algorithm] == strongest):
        raise OracleError("artifact integrity mismatch")
    canonical = "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()
    return [] if value == canonical else ["noncanonical_integrity"]


class _ExpandedStream:
    def __init__(self, source):
        self.source = source
        self.count = 0

    def read(self, size=-1):
        remaining = MAX_FILE - self.count
        if size < 0 or size > remaining + 1:
            size = remaining + 1
        data = self.source.read(size)
        self.count += len(data)
        if self.count > MAX_FILE:
            raise OracleError("archive exceeds expanded limit")
        return data


def _archive(data, integrity):
    conditions = _integrity(data, integrity)
    found = {}
    seen = {}
    ambiguous = []
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as compressed:
            stream = _ExpandedStream(compressed)
            with tarfile.open(fileobj=stream, mode="r|", bufsize=512) as archive:
                for count, member in enumerate(archive, 1):
                    if count > MAX_MEMBERS:
                        raise OracleError("archive exceeds member count")
                    name = member.name.rstrip("/") if member.isdir() else member.name
                    _relative(name)
                    canonical = name.casefold()
                    if canonical in seen:
                        ambiguous.append("duplicate or case-folded archive path")
                    ancestors = ["/".join(name.split("/")[:n]).casefold() for n in range(1, len(name.split("/")))]
                    if any(ancestor in seen and seen[ancestor] != "directory" for ancestor in ancestors):
                        ambiguous.append("archive ancestor is not a directory")
                    if not member.isdir() and any(prior.startswith(canonical + "/") for prior in seen):
                        ambiguous.append("archive file overlaps an ancestor")
                    seen[canonical] = "directory" if member.isdir() else "file"
                    if member.pax_headers or member.offset_data - member.offset > 512:
                        conditions.append("extended_tar_metadata")
                    if not re.fullmatch(r"[A-Za-z0-9._@+/-]+", name):
                        conditions.append("nonportable_tar_path")
                    if not member.isfile() and not member.isdir():
                        conditions.append("special_tar_entry")
                    if canonical in ("package/package.json", "package/binding.gyp"):
                        if name != canonical or not member.isfile():
                            ambiguous.append("ambiguous lifecycle input path")
                            continue
                        limit = MAX_MANIFEST if canonical.endswith("package.json") else MAX_FILE
                        if member.size < 0 or member.size > limit:
                            raise OracleError("lifecycle input exceeds size limit")
                        member_stream = archive.extractfile(member)
                        value = member_stream.read(limit + 1)
                        if len(value) != member.size:
                            raise OracleError("truncated lifecycle input")
                        found[name] = value
            while remainder := stream.read(65536):
                if any(remainder):
                    raise OracleError("nonzero data after tar terminator")
    except (OSError, EOFError, tarfile.TarError, UnicodeError) as exc:
        raise OracleError(f"invalid archive: {exc}") from exc
    if ambiguous:
        raise OracleError("; ".join(sorted(set(ambiguous))))
    if "package/package.json" not in found:
        raise OracleError("archive has no package/package.json")
    return found["package/package.json"], found.get("package/binding.gyp"), sorted(set(conditions))


def _manifest(data, binding, scope, record, path):
    value = _json(data)
    if not isinstance(value, dict):
        raise OracleError("manifest must be an object")
    scripts = value.get("scripts", {})
    if not isinstance(scripts, dict) or any(not isinstance(body, str) for body in scripts.values()):
        raise OracleError("invalid manifest scripts")
    expected_name = record.get("name")
    if scope == "archive" and expected_name is None:
        expected_name = path.rsplit("node_modules/", 1)[-1]
    if expected_name is not None and value.get("name") != expected_name:
        raise OracleError("manifest name differs from lock identity")
    if value.get("version") != record.get("version"):
        raise OracleError("manifest version differs from lock identity")
    if scope != "archive":
        for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            if value.get(key, {}) != record.get(key, {}):
                raise OracleError(f"manifest {key} differs from lock")
    lifecycle = {event: scripts[event] for event in SCOPED_EVENTS[scope] if event in scripts}
    implicit = binding is not None and value.get("gypfile") is not False and not any(scripts.get(event) for event in ("preinstall", "install"))
    return {"name": value.get("name"), "version": value.get("version"), "manifest_sha256": _sha256(data), "scripts": lifecycle, "implicit_native": implicit, "install_candidate": implicit or any(lifecycle.values()), "binding_sha256": _sha256(binding) if binding is not None else None, "binary_entrypoints": value.get("bin", {})}


def _archive_source(value):
    if not isinstance(value, str):
        return False
    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError:
        return False
    git_hosts = ("github.com", "gist.github.com", "gitlab.com", "bitbucket.org", "git.sr.ht")
    host = (parsed.hostname or "").lower()
    return parsed.scheme in ("http", "https") and bool(host) and not any(host == domain or host.endswith("." + domain) for domain in git_hosts)


def _lock(data):
    lock = _json(data)
    if not isinstance(lock, dict) or type(lock.get("lockfileVersion")) is not int or lock["lockfileVersion"] != 3 or not isinstance(lock.get("packages"), dict) or "" not in lock["packages"]:
        raise OracleError("requires npm lockfileVersion 3 packages including root")
    for path, record in lock["packages"].items():
        _relative(path, empty=True)
        if not isinstance(record, dict):
            raise OracleError("lock package must be an object")
        for field in ("link", "hasInstallScript"):
            if field in record and type(record[field]) is not bool:
                raise OracleError(f"lock {field} must be boolean")
        for field in ("name", "version", "resolved", "integrity"):
            if field in record and not isinstance(record[field], str):
                raise OracleError(f"lock {field} must be a string")
    return lock


def _index(data, lock_data, packages):
    value = _json(data)
    if not isinstance(value, dict) or set(value) != {"schema_version", "lock_sha256", "packages"} or type(value["schema_version"]) is not int or value["schema_version"] != 1 or not isinstance(value["packages"], list):
        raise OracleError("invalid locator index schema")
    if value["lock_sha256"] != _sha256(lock_data):
        raise OracleError("locator lock hash mismatch")
    locators = {}
    for item in value["packages"]:
        if not isinstance(item, dict) or set(item) not in ({"path", "artifact"}, {"path", "project_manifest"}):
            raise OracleError("invalid locator entry")
        path = item["path"]
        if not isinstance(path, str) or path not in packages or path in locators or packages[path].get("link", False):
            raise OracleError("duplicate, unknown, or link locator")
        kind = "artifact" if "artifact" in item else "project_manifest"
        _relative(item[kind])
        locators[path] = (kind, item[kind])
    return locators


def snapshot_facts(lock_path: Path, index_path: Path, manifest: Path | None = None) -> dict:
    result = {"status": "unavailable", "packages": {}, "issues": []}
    try:
        lock_data = _read(lock_path)
        lock = _lock(lock_data)
    except OracleError as exc:
        result["issues"].append(str(exc))
        return result
    packages = lock["packages"]
    try:
        locators = _index(_read(index_path), lock_data, packages)
        index_issue = None
    except OracleError as exc:
        locators = {}
        index_issue = str(exc)
        result["issues"].append(index_issue)
    for path, record in sorted(packages.items()):
        scope = "root" if not path else "archive" if "node_modules/" in path else "workspace"
        facts = {"status": "unknown", "scope": scope, "name": record.get("name", path.rsplit("node_modules/", 1)[-1] if scope == "archive" else None), "version": record.get("version"), "source": record.get("resolved"), "integrity": record.get("integrity")}
        result["packages"][path] = facts
        if record.get("link", False):
            target = record.get("resolved")
            if target in packages and target != path and not packages[target].get("link", False):
                facts.update({"status": "known", "scope": "link", "link_target": target, "scripts": {}, "implicit_native": False, "install_candidate": False})
            else:
                facts["reason"] = "invalid workspace link target"
            continue
        try:
            if index_issue:
                raise OracleError(index_issue)
            if path not in locators:
                raise OracleError("missing evidence locator")
            kind, relative = locators[path]
            source_path = _locator(Path(index_path).parent, relative)
            if scope == "archive":
                if kind != "artifact" or not _archive_source(record.get("resolved")):
                    raise OracleError("non-archive source execution semantics are unknown")
                archive = _read(source_path)
                facts.update({"artifact_sha256": _sha256(archive), "artifact_sha512": hashlib.sha512(archive).hexdigest()})
                data, binding, conditions = _archive(archive, record.get("integrity"))
            else:
                if kind != "project_manifest":
                    raise OracleError("source project requires a project manifest")
                data = _read(source_path, MAX_MANIFEST)
                if not path and manifest is not None and data != _read(manifest, MAX_MANIFEST):
                    raise OracleError("root manifest bytes differ from supplied input")
                binding_path = source_path.parent / "binding.gyp"
                if binding_path.is_symlink():
                    raise OracleError("source binding.gyp is a symlink")
                binding = _read(binding_path) if binding_path.exists() else None
                conditions = []
                if any(child.name.casefold() in ("package.json", "binding.gyp") and child.name not in ("package.json", "binding.gyp") for child in source_path.parent.iterdir()):
                    raise OracleError("case alias of source lifecycle input")
            facts.update(_manifest(data, binding, scope, record, path))
            facts.update({"status": "known", "profile_conditions": conditions})
        except (OracleError, OSError) as exc:
            facts["reason"] = str(exc)
    unknown = [path for path, facts in result["packages"].items() if facts["status"] != "known"]
    result["status"] = "partial" if unknown else "complete"
    result["issues"].extend({"path": path, "reason": result["packages"][path]["reason"]} for path in unknown)
    return result


def events(base_facts: dict, head_facts: dict) -> list:
    result = []
    base_packages, head_packages = base_facts["packages"], head_facts["packages"]

    def emit(path, kind, before, after, obligation, relevant):
        result.append({"path": path, "kind": kind, "before": before, "after": after, "obligation": obligation, "approval_relevant": relevant})

    for path in sorted(base_packages.keys() | head_packages.keys()):
        before, after = base_packages.get(path), head_packages.get(path)
        relevant = any(package is not None and package.get("status") == "known" and package.get("install_candidate", False) for package in (before, after))
        if before is None or after is None:
            emit(path, "added" if before is None else "removed", before, after, "package_change", relevant)
            continue
        for field in IDENTITY_FIELDS:
            if field == "name" and (before["status"] != "known" or after["status"] != "known") and (before[field] is None or after[field] is None):
                continue
            if before[field] != after[field]:
                emit(path, field + "_changed", before[field], after[field], "package_change", relevant)
        for field, kind in BYTE_FIELDS:
            if field in before and field in after and before[field] != after[field]:
                emit(path, kind, before[field], after[field], "package_change", relevant)
        if before["status"] != "known" or after["status"] != "known":
            continue
        if before["implicit_native"] != after["implicit_native"]:
            emit(path, "implicit_native_changed", before["implicit_native"], after["implicit_native"], "execution_change", relevant)
        for event in sorted(before["scripts"].keys() | after["scripts"].keys()):
            old, new = before["scripts"].get(event), after["scripts"].get(event)
            if old != new:
                kind = "lifecycle_added" if old is None else "lifecycle_removed" if new is None else "lifecycle_changed"
                emit(path, kind, {"event": event, "body": old}, {"event": event, "body": new}, "execution_change", relevant)
    return result
