#!/usr/bin/env python3
"""Preview or enforce an npm PR review from exact Git snapshots."""

import argparse
from dataclasses import dataclass, field
import hashlib
import html
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from npm_evidence import (
    EvidenceError, MAX_FILE, MAX_MANIFEST, archive_facts, archive_facts_nested, collect_evidence,
    confined_file, declared_bundles, direct_bundle_name, is_registry_path, json_bytes, load_lock, manifest_facts,
    read_limited, safe_relative, sha256, strict_json,
)


@dataclass
class Snapshot:
    commit: str
    project: str
    files: dict = field(default_factory=dict)
    absent: list = field(default_factory=list)

    def report(self):
        return {"commit": self.commit, "project": self.project,
                "files": self.files, "absent": sorted(self.absent)}


class GitObjects:
    def __init__(self, repository):
        self.repository = Path(repository).resolve(strict=True)
        self.env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        self.env.update(GIT_NO_REPLACE_OBJECTS="1", GIT_NO_LAZY_FETCH="1", GIT_OPTIONAL_LOCKS="0",
                        GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        self.repository = Path(self.run("rev-parse", "--show-toplevel").decode().strip())
        self.trees = {}
        self.commit_trees = {}
        self.source_content = {}
        self.source_trees = {}

    def run(self, *args):
        result = subprocess.run(["git", "--no-replace-objects", "--literal-pathspecs", "-C", str(self.repository), *args],
                                env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode:
            raise EvidenceError("Git object lookup failed: " + result.stderr.decode("utf-8", "replace").strip())
        if len(result.stdout) > MAX_FILE:
            raise EvidenceError("Git object output exceeds 64 MiB")
        return result.stdout

    def commit(self, ref):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,255}", ref):
            raise EvidenceError("revision must be a commit hash or ordinary Git ref without revision operators")
        oid = self.run("rev-parse", "--verify", "--end-of-options", ref).decode().strip()
        if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", oid):
            raise EvidenceError("Git returned an invalid object ID")
        if self.run("cat-file", "-t", oid).strip() != b"commit":
            raise EvidenceError("revision must identify a commit object")
        return oid

    def tree(self, oid):
        if oid not in self.trees:
            if int(self.run("cat-file", "-s", oid).strip()) > 16 * 1024 * 1024:
                raise EvidenceError("Git tree exceeds 16 MiB")
            entries = {}
            for entry in self.run("ls-tree", "-z", oid).split(b"\0"):
                if not entry:
                    continue
                metadata, raw_name = entry.split(b"\t", 1)
                try:
                    name = raw_name.decode("utf-8")
                except UnicodeError as exc:
                    raise EvidenceError("non-UTF-8 Git tree name is outside the source profile") from exc
                mode, kind, child = metadata.decode("ascii").split()
                entries[name] = (mode, kind, child)
            self.trees[oid] = entries
        return self.trees[oid]

    def commit_tree(self, oid):
        if oid not in self.commit_trees:
            if int(self.run("cat-file", "-s", oid).strip()) > MAX_FILE:
                raise EvidenceError("Git commit exceeds 64 MiB")
            header = self.run("cat-file", "commit", oid).split(b"\n", 1)[0]
            if not re.fullmatch(rb"tree (?:[0-9a-f]{40}|[0-9a-f]{64})", header):
                raise EvidenceError("invalid Git commit tree header")
            self.commit_trees[oid] = header[5:].decode("ascii")
        return self.commit_trees[oid]

    def entry(self, commit, path, optional=False):
        parts = portable_path(path).split("/")
        tree = self.commit_tree(commit)
        for position, part in enumerate(parts):
            entries = self.tree(tree)
            aliases = [name for name in entries if name.rstrip(". ").casefold() == part.casefold() and name != part]
            if aliases:
                raise EvidenceError(f"case or filesystem alias of Git path {path!r}")
            if part not in entries:
                if optional and position == len(parts) - 1:
                    return None
                raise EvidenceError(f"missing Git path {path!r}")
            mode, kind, child = entries[part]
            if position < len(parts) - 1:
                if mode != "040000" or kind != "tree":
                    raise EvidenceError(f"source parent is not a Git directory: {path!r}")
                tree = child
            else:
                if mode not in ("100644", "100755") or kind != "blob":
                    raise EvidenceError(f"source must be a regular Git blob; symlink and gitlink modes are unsupported: {path!r}")
                return mode, child

    def source_directory(self, commit, directory):
        tree = self.commit_tree(commit)
        if directory:
            for part in portable_path(directory).split("/"):
                mode, kind, tree = self.tree(tree).get(part, (None, None, None))
                if mode != "040000" or kind != "tree":
                    raise EvidenceError(f"source directory is not a Git tree: {directory!r}")
        if any(not name.isascii() for name in self.tree(tree)):
            raise EvidenceError(f"source directory has non-ASCII names outside the portable profile: {directory!r}")

    def blob(self, commit, path, limit=MAX_FILE, optional=False):
        entry = self.entry(commit, path, optional)
        if entry is None:
            return None
        mode, oid = entry
        size = int(self.run("cat-file", "-s", oid).strip())
        if size > limit:
            raise EvidenceError(f"Git blob exceeds {limit} bytes: {path!r}")
        data = self.run("cat-file", "blob", oid)
        if len(data) != size:
            raise EvidenceError("Git blob size changed during capture")
        return data, {"git_oid": oid, "mode": mode, "size": size, "sha256": sha256(data)}

    def source_tree(self, commit, excluded):
        """Bind every tracked regular file, including paths and executable modes."""
        key = (commit, tuple(sorted(excluded)))
        if key in self.source_trees:
            return self.source_trees[key]
        digest = hashlib.sha256(b"tau-gate-source-tree-v1\0")
        total = 0
        count = 0
        gitlinks = 0
        for record in self.run("ls-tree", "-r", "-l", "-z", commit).split(b"\0"):
            if not record:
                continue
            metadata, path = record.split(b"\t", 1)
            mode, kind, oid, declared_size = metadata.split()
            if path in excluded:
                continue
            if kind == b"commit" and mode == b"160000":
                size, content = len(oid), hashlib.sha256(oid).digest()
                gitlinks += 1
            elif kind == b"blob" and mode in (b"100644", b"100755"):
                if oid not in self.source_content:
                    object_id = oid.decode("ascii")
                    size = int(declared_size)
                    if size > MAX_FILE:
                        raise EvidenceError("source tree exceeds 64 MiB per file")
                    data = self.run("cat-file", "blob", object_id)
                    if len(data) != size:
                        raise EvidenceError("Git blob size changed during source-tree capture")
                    self.source_content[oid] = (size, hashlib.sha256(data).digest())
                size, content = self.source_content[oid]
                if total + size > 512 * 1024 * 1024:
                    raise EvidenceError("source tree exceeds 512 MiB total")
                total += size
                count += 1
            else:
                raise EvidenceError(f"source tree contains an unsupported symlink or Git mode: {path!r}")
            digest.update(len(path).to_bytes(8, "big"))
            digest.update(path)
            digest.update(mode)
            digest.update(size.to_bytes(8, "big"))
            digest.update(content)
        self.source_trees[key] = {"sha256": digest.hexdigest(), "files": count, "bytes": total,
                                  "gitlinks": gitlinks}
        return self.source_trees[key]

    def tracked_entries(self, commit, paths, prefixes):
        found = {}
        for record in self.run("ls-tree", "-r", "-z", commit).split(b"\0"):
            if not record:
                continue
            metadata, path = record.split(b"\t", 1)
            if path in paths or any(path.startswith(prefix) for prefix in prefixes):
                mode, kind, oid = metadata.split()
                found[path] = (mode, kind, oid)
        return found


def portable_path(value):
    safe_relative(value)
    for part in value.split("/"):
        if (not re.fullmatch(r"[A-Za-z0-9._@+-]+", part) or part.endswith(".")
                or re.fullmatch(r"(?:con|prn|aux|nul|com[1-9]|lpt[1-9])", part.split(".", 1)[0], re.IGNORECASE)):
            raise EvidenceError(f"nonportable source path {value!r}")
    return value


def join_project(project, path):
    return project + "/" + path if project else path


def capture(git, snapshot, output):
    project_output = output / "project"
    project_output.mkdir(parents=True)

    def copy(path, limit=MAX_FILE, optional=False):
        full_path = join_project(snapshot.project, path)
        blob = git.blob(snapshot.commit, full_path, limit, optional)
        if blob is None:
            snapshot.absent.append(full_path)
            return
        data, metadata = blob
        destination = project_output / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        snapshot.files[full_path] = metadata

    copy("package-lock.json")
    _, lock = load_lock(project_output / "package-lock.json")
    for path, record in sorted(lock["packages"].items()):
        if record.get("link", False) or is_registry_path(path):
            continue
        if path:
            portable_path(path)
        directory = join_project(snapshot.project, path) if path else snapshot.project
        git.source_directory(snapshot.commit, directory)
        prefix = path + "/" if path else ""
        copy(prefix + "package.json", MAX_MANIFEST)
        copy(prefix + "binding.gyp", optional=True)
    return project_output


def markdown_text(value):
    return html.escape(str(value), quote=False).replace("\n", " ").replace("\r", " ").replace("`", "&#96;")


def introducer(change):
    route = change.get("after_introducer_path") or change.get("before_introducer_path")
    return " -> ".join(map(str, route)) if isinstance(route, list) else "unreachable or unavailable"


def typed_route(snapshot, route):
    if not isinstance(route, list) or not route:
        return None
    edges = {(edge["from"], edge["to"]): edge["kinds"] for edge in snapshot.get("edges", [])}
    hops = []
    for origin, target in zip(route, route[1:]):
        kinds = edges.get((origin, target))
        if not kinds:
            return None
        hops.append({"from": origin, "to": target, "kinds": kinds})
    return hops


def command_text(output, label, evidence):
    if not evidence or evidence.get("state") != "qualified":
        return None
    facts = evidence.get("facts") or {}
    if facts.get("kind") == "workspace_link":
        return {}
    path = evidence["path"]
    evidence_dir = output / label / "evidence"
    index = strict_json(read_limited(evidence_dir / "index.json"))
    entry = next((item for item in index["packages"] if item["path"] == path), None)
    if entry is None and facts.get("kind") != "bundled_artifact":
        raise EvidenceError(f"qualified instance lacks a locator: {path!r}")
    if facts.get("kind") == "bundled_artifact":
        parent = facts["bundle_parent"]
        parent_entry = next((item for item in index["packages"] if item["path"] == parent), None)
        if parent_entry is None or "artifact" not in parent_entry or not path.startswith(parent + "/"):
            raise EvidenceError(f"qualified bundled instance lacks a parent locator: {path!r}")
        lock = strict_json(read_limited(output / label / "project" / "package-lock.json"))
        parent_record = lock["packages"][parent]
        child_record = lock["packages"].get(path, {})
        if (parent_record.get("resolved") != facts.get("bundle_parent_source")
                or parent_record.get("integrity") != facts.get("bundle_parent_integrity")
                or child_record.get("inBundle") is not True):
            raise EvidenceError(f"bundled source binding disagrees with reviewer view: {path!r}")
        archive = read_limited(confined_file(evidence_dir, parent_entry["artifact"]))
        relative = path[len(parent) + 1:]
        _, parent_manifest, _, _, nested = archive_facts_nested(archive, parent_record["integrity"], {relative})
        name = direct_bundle_name(relative)
        if name is None or name not in declared_bundles(parent_manifest):
            raise EvidenceError(f"bundled declaration disagrees with reviewer view: {path!r}")
        selected = nested.get(relative, {})
        data = selected.get("manifest")
        if data is None or hashlib.sha512(archive).hexdigest() != facts.get("artifact_sha512"):
            raise EvidenceError(f"bundled archive bytes disagree with reviewer view: {path!r}")
        manifest = strict_json(data)
        binding_hash = selected.get("binding_hash")
        binding_gyp = binding_hash is not None
        source_project = False
    elif facts.get("kind") == "artifact" and "artifact" in entry:
        archive = read_limited(confined_file(evidence_dir, entry["artifact"]))
        lock = strict_json(read_limited(output / label / "project" / "package-lock.json"))
        integrity = lock["packages"][path]["integrity"]
        data, manifest, binding_gyp, binding_hash = archive_facts(archive, integrity)
        if hashlib.sha512(archive).hexdigest() != facts.get("artifact_sha512"):
            raise EvidenceError(f"qualified archive digest disagrees with reviewer view: {path!r}")
        source_project = False
    elif facts.get("kind") == "source_project" and "project_manifest" in entry:
        data = read_limited(confined_file(evidence_dir, entry["project_manifest"]), MAX_MANIFEST)
        manifest = strict_json(data)
        binding_gyp = facts.get("binding_gyp")
        binding_hash = facts.get("binding_gyp_sha256")
        source_project = "root" if path == "" else "workspace"
    else:
        raise EvidenceError(f"qualified locator kind disagrees with reviewer view: {path!r}")
    observed = manifest_facts(data, binding_gyp, source_project, binding_hash)
    if observed["manifest_sha256"] != facts.get("manifest_sha256") or observed["lifecycle"] != facts.get("lifecycle"):
        raise EvidenceError(f"qualified lifecycle bytes disagree with reviewer view: {path!r}")
    scripts = manifest.get("scripts", {})
    return {event: scripts[event] for event in sorted(observed["lifecycle"])}


def next_action(reason):
    message = str(reason or "").lower()
    if "sha512 sri mismatch" in message:
        return "Do not use these archive bytes. Resolve the lock/archive mismatch before rerunning."
    if "sha512 sri" in message:
        return "Restore a lock entry with canonical SHA512 integrity for the original archive, then rerun; otherwise review this package manually."
    if "download requires https registry.npmjs.org" in message or "artifact redirects are unsupported" in message:
        return "Have the repository owner supply the exact SHA512-bound archive through a trusted offline cache, then rerun."
    if "artifact acquisition failed" in message:
        return "Retry acquisition of the same lock-bound archive or provide it through a trusted offline cache."
    if "unsupported artifact source" in message:
        return "Review this source manually or replace it with a supported archive and canonical SHA512 lock entry."
    if "compressed limit" in message or "decompressed limit" in message or "tar exceeds 10000 entries" in message:
        return "Review this archive manually; it exceeds the supported inspection bounds."
    if "nonportable tar path" in message or "pax" in message or "unsupported tar" in message:
        return "Review the archive manually or obtain a package with a supported portable tar layout."
    if "manifest" in message and ("does not match" in message or "differs" in message):
        return "Resolve the lockfile/manifest disagreement from the original sources, then rerun."
    if "missing locator" in message or "bundle parent lacks qualified" in message:
        return "Supply the original verified package evidence and rerun; review manually until it is available."
    if "source approval" in message or "approval file" in message:
        return "Ask a trusted administrator to repair the base policy, then rerun this head."
    return "Resolve this exact input or evidence gap and rerun this head; use manual review until then."


def review_view(report, output):
    core = report.get("core") or {}
    changes = core.get("execution_evidence_changes", [])
    def priority(change):
        before = (change.get("before") or {}).get("facts") or {}
        after = (change.get("after") or {}).get("facts") or {}
        command_change = before.get("lifecycle") != after.get("lifecycle")
        candidate = (change.get("before") or {}).get("candidate") or (change.get("after") or {}).get("candidate")
        return (not command_change, not candidate, change.get("path", ""))
    ordered = sorted(changes, key=priority)
    selected = ordered[:30]
    rows = []
    for change in selected:
        row = {"path": change["path"]}
        for label, side in (("base", "before"), ("head", "after")):
            item = change.get(side)
            route = typed_route(core.get(label, {}), change.get(side + "_introducer_path"))
            verified_archive = item.get("verified_artifact_sha512") if item else None
            if (verified_archive is None and item and item.get("state") == "qualified"
                    and (item.get("facts") or {}).get("kind") == "artifact"):
                verified_archive = item["facts"].get("artifact_sha512")
            row[side] = {"state": item.get("state") if item else "absent",
                         "reason": item.get("reason") if item else None,
                         "facts": item.get("facts") if item else None,
                         "fingerprint": item.get("approval_fingerprint") if item else None,
                         "verified_artifact_sha512": verified_archive,
                         "commands": command_text(output, label, item),
                         "route": route}
        rows.append(row)
    unknowns = []
    for label in ("base", "head"):
        for item in core.get(label, {}).get("execution_evidence", []):
            if item.get("state") != "qualified":
                unknowns.append({"side": label, "path": item.get("path"), "state": item.get("state"),
                                 "reason": item.get("reason"), "next_action": next_action(item.get("reason"))})
    return {"execution_changes": rows, "remaining_execution_changes": len(changes) - len(rows),
            "unknowns": unknowns}


def route_text(route, path):
    if route is None:
        return "dependency route unavailable"
    if not route:
        return "root project" if not path else "introducer is the project root"
    text = f"`{markdown_text(route[0]['from'])}`"
    for hop in route:
        text += f" --{markdown_text(', '.join(hop['kinds']))}--> `{markdown_text(hop['to'])}`"
    return text


def decision_text(report):
    if report.get("mode") == "preview":
        if report["outcome"] == "incomplete":
            return "Preview incomplete. Resolve the listed input or evidence gaps before relying on this review."
        return "Preview complete. Inspect the changes below; this preview is not an approval or merge gate."
    if report["outcome"] == "incomplete":
        return "Review incomplete. Resolve the listed input or evidence gaps and rerun this exact head."
    core_policy = (report.get("core") or {}).get("policy") or {}
    source = report.get("source_approval") or {}
    if source.get("changed_trusted_paths"):
        return "Blocked. A trusted administrator must review the protected policy or tool change."
    if report["outcome"] == "blocked":
        if core_policy.get("unapproved_execution_candidates") or source.get("unapproved_head_digest"):
            return "Blocked. A trusted maintainer must approve the exact proposed evidence and rerun this head."
        return "Blocked. Review the policy issues below."
    return "Allowed by this evidence gate. Review the PR and other required checks before merge."


def approval_request(report):
    core = report.get("core") or {}
    source = report.get("source_approval") or {}
    if (core.get("status") != "complete" or core.get("policy", {}).get("outcome") not in ("allowed", "blocked")
            or core.get("policy", {}).get("issues") or report["errors"] or source.get("changed_trusted_paths")
            or (report.get("review") or {}).get("unknowns")
            or (report.get("review") or {}).get("remaining_execution_changes")):
        return None
    candidates = core.get("policy", {}).get("unapproved_execution_candidates", [])
    source_digest = source.get("unapproved_head_digest")
    if not candidates and not source_digest:
        return None
    approvals = sorted(({"path": item["path"], "fingerprint": item["fingerprint"]}
                        for item in candidates), key=lambda item: item["path"])
    subject = {"domain": "tau-gate-pr-approval-v1", "base": report["base"], "head": report["head"],
               "policy": report["policy"], "source_approval": source,
               "trusted_tools": report["trusted_tools"], "review": report["review"],
               "core": {key: value for key, value in core.items() if key != "policy"}}
    return {"schema_version": 1, "subject_sha256": sha256(json_bytes(subject)),
            "base_commit": report["base"]["commit"], "head_commit": report["head"]["commit"],
            "approvals": approvals, "source_tree_sha256": source_digest}


def approval_store(path, repository, output, cache):
    if path.is_symlink():
        raise EvidenceError("trusted approval store must not be a symlink")
    root = path.resolve(strict=True)
    if not root.is_dir():
        raise EvidenceError("trusted approval store must be a directory")
    stat = root.stat()
    if stat.st_uid != os.geteuid() or stat.st_mode & 0o022:
        raise EvidenceError("trusted approval store must be owned by the caller and not writable by group or others")
    protected = [repository, output]
    if cache is not None:
        protected.append(cache.resolve())
    if any(root.is_relative_to(item) or item.is_relative_to(root) for item in protected):
        raise EvidenceError("trusted approval store must be separate from repository, output, and cache")
    return root


def stored_approval(store, request):
    path = store / (request["subject_sha256"] + ".json")
    if not path.exists() and not path.is_symlink():
        return False
    if path.is_symlink() or read_limited(path, MAX_MANIFEST) != json_bytes(request):
        raise EvidenceError("trusted approval record differs from the exact request")
    return True


def record_approval(store, request):
    name = request["subject_sha256"] + ".json"
    data = json_bytes(request)
    directory = os.open(store, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        try:
            file = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        except FileExistsError:
            if stored_approval(store, request):
                return False
            raise EvidenceError("trusted approval record already exists")
        try:
            with os.fdopen(file, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            os.unlink(name, dir_fd=directory)
            raise
        os.fsync(directory)
        return True
    finally:
        os.close(directory)


def effective_approvals(base_data, additions):
    policy = strict_json(base_data)
    version = policy["schema_version"]
    by_path = {}
    for item in policy["approvals"]:
        values = [item["fingerprint"]] if version == 1 else item["fingerprints"]
        by_path[item["path"]] = set(values)
    for item in additions:
        by_path.setdefault(item["path"], set()).add(item["fingerprint"])
    return json_bytes({"schema_version": 2, "approvals": [
        {"path": path, "fingerprints": sorted(values)} for path, values in sorted(by_path.items())]})


def approvals_from_base(core):
    base = core.get("base") or {}
    if base.get("status") != "complete":
        raise EvidenceError("protected base evidence must be complete before it can serve as the approval baseline")
    approvals = {}
    for item in base.get("execution_evidence", []):
        if not item.get("candidate"):
            continue
        path, fingerprint = item.get("path"), item.get("approval_fingerprint")
        if (item.get("state") != "qualified" or not isinstance(path, str)
                or not isinstance(fingerprint, str) or not re.fullmatch(r"[0-9a-f]{64}", fingerprint)
                or path in approvals):
            raise EvidenceError("protected base has an invalid execution candidate")
        approvals[path] = fingerprint
    data = json_bytes({"schema_version": 2, "approvals": [
        {"path": path, "fingerprints": [fingerprint]} for path, fingerprint in sorted(approvals.items())]})
    return data, len(approvals)


def core_review(binary, output, approvals=None):
    command = [str(binary), "review", "--base", "base/project/package-lock.json",
               "--head", "head/project/package-lock.json", "--base-manifest", "base/project/package.json",
               "--head-manifest", "head/project/package.json", "--base-evidence", "base/evidence/index.json",
               "--head-evidence", "head/evidence/index.json", "--json"]
    if approvals is not None:
        command.extend(("--approvals", approvals, "--enforce"))
    result = subprocess.run(command, cwd=output, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if len(result.stdout) > MAX_FILE:
        raise EvidenceError("core report exceeds 64 MiB")
    core = strict_json(result.stdout)
    if not isinstance(core, dict):
        raise EvidenceError("core report must be a JSON object")
    outcome = core.get("policy", {}).get("outcome", "incomplete")
    expected = {"allowed": 0, "blocked": 1, "incomplete": 2}
    if approvals is None:
        expected = {"advisory": 2 if core.get("status") == "incomplete" else 0}
        if core.get("status") == "incomplete":
            expected["incomplete"] = 2
    if outcome not in expected or result.returncode != expected[outcome]:
        raise EvidenceError(f"core outcome or exit code is inconsistent: {result.returncode}")
    return core, outcome


def summary(report):
    if report.get("mode") == "preview":
        title = "# Tau-Gate PR preview: " + ("incomplete" if report["outcome"] == "incomplete" else "complete")
    else:
        title = f"# Tau-Gate PR review: {report['outcome']}"
    lines = [title, "", decision_text(report), ""]
    if report.get("approval_request"):
        request = report["approval_request"]
        if report.get("trusted_approval", {}).get("matched"):
            lines.append(f"Exact approval subject `{request['subject_sha256']}` was recorded by the trusted store.")
        else:
            lines.append(f"Exact approval subject: `{request['subject_sha256']}`. A trusted maintainer can record this subject with `--approval-store` and `--approve-subject`; rerun the exact head afterward.")
            lines.append(f"GitHub pilot approval comment: `tau-gate approve {request['subject_sha256']}` from a different maintainer with write access.")
        lines.append("")
    for label in ("base", "head"):
        if report[label] is not None:
            lines.append(f"{label.capitalize()} commit `{report[label]['commit']}`.")
    if report["policy"] is not None:
        policy = report["policy"]
        if policy["origin"] == "protected_base":
            lines.extend(["", f"Existing verified execution candidates are baselined from protected commit `{policy['commit']}`. New or changed candidates need exact approval."])
        else:
            lines.extend(["", f"Base approvals come from `{policy['commit']}` at `{markdown_text(policy['path'])}`."])
    source = report.get("source_approval")
    if source is not None:
        lines.extend(["", f"Trusted gate and source-tree approval: {source['status']}."])
        for label in ("base", "head"):
            if label in source:
                lines.append(f"{label.capitalize()} tracked-tree SHA-256 `{source[label]['sha256']}` ({source[label]['files']} files, {source[label]['bytes']} bytes, {source[label]['gitlinks']} gitlinks).")
        if source.get("changed_trusted_paths"):
            lines.append("Head changes trusted gate files: " + ", ".join(f"`{markdown_text(path)}`" for path in source["changed_trusted_paths"]) + ". Use a trusted administrative update.")
        if source.get("unapproved_head_digest") and not source.get("approved_by_store"):
            lines.append(f"Unapproved source tree digest `{source['unapproved_head_digest']}`.")
        elif source.get("approved_by_store"):
            lines.append(f"Proposed source tree digest `{source['head']['sha256']}` was approved by the trusted store.")
    core = report.get("core") or {}
    changes = core.get("execution_evidence_changes", [])
    packages = core.get("package_changes", [])
    view = report.get("review") or {}
    unknowns = view.get("unknowns", [])
    if core.get("base") and core.get("head"):
        lines.append("")
        for label, title in (("base", "Current"), ("head", "Proposed")):
            snapshot = core[label]
            qualified = sum(item.get("state") == "qualified" for item in snapshot.get("execution_evidence", []))
            lines.append(f"{title}: {len(snapshot.get('packages', []))} locked instances; {qualified} qualified execution-evidence records.")
    lines.extend(["", f"{len(packages)} package changes. {len(changes)} execution evidence changes. {len(unknowns)} unqualified package sides."])
    lifecycle_changes = sum(((change.get("before") or {}).get("facts") or {}).get("lifecycle")
                            != ((change.get("after") or {}).get("facts") or {}).get("lifecycle")
                            for change in changes)
    candidate_changes = sum(bool((change.get("before") or {}).get("candidate")
                                 or (change.get("after") or {}).get("candidate")) for change in changes)
    lines.append(f"{lifecycle_changes} changed lifecycle command sets; {candidate_changes} changed evidence rows with automatic install execution potential.")
    direct = [change for change in packages
              if len(change.get("after_introducer_path") or change.get("before_introducer_path") or []) == 2]
    if direct:
        lines.extend(["", "## Direct dependency changes", ""])
        for change in direct[:8]:
            before, after = change.get("before") or {}, change.get("after") or {}
            old = f"{before.get('name', '?')}@{before.get('version', '?')}" if before else "absent"
            new = f"{after.get('name', '?')}@{after.get('version', '?')}" if after else "absent"
            lines.append(f"- `{markdown_text(change['path'])}`: `{markdown_text(old)}` to `{markdown_text(new)}`.")
        if len(direct) > 8:
            lines.append(f"- {len(direct) - 8} more direct changes are in `report.json`.")
    if view.get("execution_changes"):
        lines.extend(["", "## Execution evidence, current to proposed", ""])
    for row in view.get("execution_changes", []):
        path = markdown_text(row["path"] or "<root>")
        before, after = row["before"], row["after"]
        old_facts, new_facts = before.get("facts") or {}, after.get("facts") or {}
        fields = [key for key in ("kind", "bundle_parent", "bundle_parent_source", "bundle_parent_integrity",
                                  "artifact_sha512", "manifest_sha256", "lifecycle",
                                  "binding_gyp_sha256", "implicit_node_gyp", "binary_entrypoints")
                  if old_facts.get(key) != new_facts.get(key)]
        lines.extend([f"### `{path}`", "", f"Changed: {', '.join(fields) or 'qualification or fingerprint'}.",
                      f"Introducer, proposed: {route_text(after['route'], row['path'])}.", ""])
        for label, item in (("Current", before), ("Proposed", after)):
            facts = item.get("facts") or {}
            evidence = f"manifest SHA-256 `{markdown_text(facts.get('manifest_sha256'))}`"
            if facts.get("kind") == "artifact":
                evidence += f"; verified archive SHA-512 `{markdown_text(item.get('verified_artifact_sha512'))}`"
            elif facts.get("kind") == "bundled_artifact":
                evidence += (f"; bundled in `{markdown_text(facts.get('bundle_parent'))}`"
                             f"; verified parent archive SHA-512 `{markdown_text(facts.get('artifact_sha512'))}`")
            elif facts.get("kind") == "source_project":
                evidence += "; captured Git source manifest"
            elif facts.get("kind") == "workspace_link":
                evidence = "workspace link to its source target"
            elif not facts:
                evidence = "no qualified execution facts"
            fingerprint = (f"; fingerprint `{item['fingerprint']}`" if item.get("fingerprint") else "")
            lines.append(f"**{label}:** {markdown_text(item['state'])}; {evidence}{fingerprint}.")
            if item.get("reason"):
                lines.append(f"Reason: {markdown_text(item['reason'])}.")
            commands = item.get("commands")
            if commands is None:
                lines.append("Lifecycle command text unavailable from qualified evidence.")
            elif not commands:
                lines.append("No lifecycle commands in the qualified manifest.")
            else:
                for event, command in commands.items():
                    lines.extend([f"{label} `{markdown_text(event)}` command:",
                                  f"<pre><code>{html.escape(command)}</code></pre>"])
            if facts.get("implicit_node_gyp"):
                lines.append("Implicit `node-gyp rebuild` is indicated by qualified binding.gyp evidence.")
            lines.append("")
    if view.get("remaining_execution_changes"):
        lines.append(f"{view['remaining_execution_changes']} more execution evidence changes are in `report.json`.")
        lines.append("Trusted one-action approval is unavailable while this view is truncated.")
    if packages:
        lines.extend(["", "## Locked package changes", ""])
    for change in packages[:30]:
        before = change.get("before") or {}
        after = change.get("after") or {}
        coordinate = lambda item: str(item.get("name", "?")) + "@" + str(item.get("version", "?"))
        fields = change.get("changed_fields") or [change["change"]]
        text = f"- Package `{markdown_text(change['path'] or '<root>')}` changed {', '.join(fields)}. `{markdown_text(coordinate(before))}` to `{markdown_text(coordinate(after))}`. Introducer `{markdown_text(introducer(change))}`."
        for field in ("source", "integrity"):
            if field in fields:
                text += f" {field.capitalize()} `{markdown_text(before.get(field))}` to `{markdown_text(after.get(field))}`."
        lines.append(text)
    if len(packages) > 30 or len(changes) > 30:
        lines.append("- Change lists show the first 30 entries each. Read `report.json` for every change.")
    policy = core.get("policy", {})
    for candidate in policy.get("unapproved_execution_candidates", []):
        lines.append(f"- Unapproved `{markdown_text(candidate['path'] or '<root>')}` fingerprint `{candidate['fingerprint']}`.")
    if unknowns:
        lines.extend(["", "## Evidence gaps", ""])
        for item in unknowns[:20]:
            lines.append(f"- {item['side']} `{markdown_text(item['path'] or '<root>')}`: {markdown_text(item['state'])}; {markdown_text(item['reason'])}. Next: {markdown_text(item['next_action'])}")
        if len(unknowns) > 20:
            lines.append(f"- {len(unknowns) - 20} more package sides and their next actions are in `report.json`.")
    reasons = list(report["errors"])
    for label in ("base", "head"):
        snapshot = core.get(label, {})
        for issue in snapshot.get("issues", []):
            reasons.append({"stage": label, "message": issue})
        for evidence in snapshot.get("execution_evidence") or []:
            if evidence.get("state") != "qualified" and not unknowns:
                reasons.append({"stage": label, "message": {"path": evidence.get("path"), "state": evidence.get("state"), "reason": evidence.get("reason")}})
            elif evidence.get("reason"):
                lines.append(f"- Note {label} evidence `{markdown_text(evidence.get('path') or '<root>')}`: {markdown_text(evidence['reason'])}")
    for issue in policy.get("issues", []):
        reasons.append({"stage": "policy", "message": issue})
    if "error" in core:
        reasons.append({"stage": "core", "message": core["error"]})
    if "review_input_issue" in policy:
        reasons.append({"stage": "policy", "message": policy["review_input_issue"]})
    if reasons:
        lines.extend(["", "## Input and policy gaps", ""])
        for reason in reasons:
            text = reason["message"] if isinstance(reason["message"], str) else json.dumps(reason["message"], sort_keys=True)
            lines.append(f"- {reason['stage']}: {markdown_text(text)}. Next: {markdown_text(next_action(text))}")
    lines.extend(["", "Artifact integrity binds bytes to the lock. Source snapshots retain caller trust. This report does not prove scripts safe or predict host installation selection.", ""])
    return "\n".join(lines)


def prepare_output(path, repository, cache):
    path = Path(path).absolute()
    if path.is_symlink():
        raise EvidenceError("output directory must not be a symlink")
    resolved = path.resolve()
    protected = [repository]
    if cache is not None:
        protected.append(Path(cache).resolve())
    if any(resolved.is_relative_to(root) or root.is_relative_to(resolved) for root in protected):
        raise EvidenceError("output must be separate from the repository and archive cache")
    if resolved.exists() and (not resolved.is_dir() or any(resolved.iterdir())):
        raise EvidenceError("output directory must be new or empty")
    resolved.mkdir(parents=True, exist_ok=True)
    return resolved


def review(args):
    report = {"schema_version": 1, "outcome": "incomplete", "exit_code": 2,
              "base": None, "head": None, "policy": None, "source_approval": None, "core": None, "errors": []}
    if args.preview:
        report["mode"] = "preview"
    output = None
    replacements = []
    stage = "inputs"
    snapshots = {}
    store = None
    try:
        git = GitObjects(args.repo)
        output = prepare_output(args.output, git.repository, args.archive_cache)
        replacements = [(str(output), "<output>"), (str(git.repository), "<repo>")]
        if args.archive_cache is not None:
            replacements.append((str(args.archive_cache.resolve()), "<archive-cache>"))
        if args.approval_store is not None:
            store = approval_store(args.approval_store, git.repository, output, args.archive_cache)
            replacements.append((str(store), "<approval-store>"))
        project = "" if args.project == "." else portable_path(args.project)
        if not args.preview and not args.baseline_from_base:
            approval_path = portable_path(args.approvals)
            source_approval_path = portable_path(args.source_approvals)
            if approval_path == source_approval_path:
                raise EvidenceError("approval paths must be distinct")
        binary = args.tau_gate.resolve(strict=True)
        report["trusted_tools"] = {
            "tau_gate_sha256": sha256(read_limited(binary)),
            "pr_review_sha256": sha256(read_limited(Path(__file__))),
            "npm_evidence_sha256": sha256(read_limited(Path(__file__).with_name("npm_evidence.py"))),
        }
        github_bridge = Path(__file__).with_name("github_pr_approval.py")
        if github_bridge.is_file():
            report["trusted_tools"]["github_pr_approval_sha256"] = sha256(read_limited(github_bridge))
        for label in ("base", "head"):
            stage = label + "_revision"
            snapshots[label] = Snapshot(git.commit(getattr(args, label)), project)
            report[label] = snapshots[label].report()
        for label, snapshot in snapshots.items():
            stage = label + "_capture"
            source = capture(git, snapshot, output / label)
            stage = label + "_evidence"
            collect_evidence(source / "package-lock.json", source, output / label / "evidence", args.archive_cache)
        if args.preview:
            stage = "core_preview"
            core, _ = core_review(binary, output)
            outcome = "incomplete" if core.get("status") == "incomplete" else "preview"
            core.pop("policy", None)
            report["core"] = core
            report["review"] = review_view(report, output)
            report.update(outcome=outcome, exit_code={"preview": 0, "incomplete": 2}[outcome])
            for label, snapshot in snapshots.items():
                report[label] = snapshot.report()
            (output / "report.json").write_bytes(json_bytes(report))
            (output / "summary.md").write_text(summary(report), encoding="utf-8")
            return report
        stage = "base_policy"
        if args.baseline_from_base:
            advisory, _ = core_review(binary, output)
            advisory.pop("policy", None)
            report["core"] = advisory
            report["review"] = review_view(report, output)
            data, count = approvals_from_base(advisory)
            report["policy"] = {"origin": "protected_base", "commit": snapshots["base"].commit,
                                "sha256": sha256(data), "candidate_count": count}
        else:
            data, metadata = git.blob(snapshots["base"].commit, approval_path)
            report["policy"] = {"origin": "base", "commit": snapshots["base"].commit,
                                "path": approval_path, **metadata}
        base_policy_data = data
        (output / "base" / "approvals.json").write_bytes(data)
        stage = "core_review"
        core, outcome = core_review(binary, output, "base/approvals.json")
        if args.baseline_from_base and {key: value for key, value in core.items() if key != "policy"} != {key: value for key, value in advisory.items() if key != "policy"}:
            raise EvidenceError("core evidence changed while applying protected-base approvals")
        report["core"] = core
        source_required = any(
            item.get("candidate") and (item.get("facts") or {}).get("kind") == "source_project"
            for label in ("base", "head")
            for item in core.get(label, {}).get("execution_evidence", []))
        excluded = (set() if args.baseline_from_base else
                    {path.encode("utf-8") for path in (approval_path, source_approval_path)})
        protected_prefixes = ((b".github/workflows/",) if args.baseline_from_base else
                              (b"tools/", b".github/workflows/"))
        stage = "policy_changes"
        base_entries = git.tracked_entries(snapshots["base"].commit, excluded, protected_prefixes)
        head_entries = git.tracked_entries(snapshots["head"].commit, excluded, protected_prefixes)
        changed_paths = sorted(path.decode("utf-8") for path in base_entries.keys() | head_entries.keys()
                               if base_entries.get(path) != head_entries.get(path))
        if source_required or changed_paths:
            source = {"status": "incomplete", "required": source_required,
                      "origin": "protected_base" if args.baseline_from_base else "base",
                      "commit": snapshots["base"].commit,
                      "excluded_paths": [] if args.baseline_from_base else sorted((approval_path, source_approval_path)),
                      "changed_trusted_paths": changed_paths}
            if not args.baseline_from_base:
                source["path"] = source_approval_path
            report["source_approval"] = source
        if source_required:
            for label in ("base", "head"):
                stage = label + "_source_tree"
                source[label] = git.source_tree(snapshots[label].commit, excluded)
            stage = "source_policy"
            if args.baseline_from_base:
                source["matched"] = source["head"]["sha256"] == source["base"]["sha256"]
            else:
                data, metadata = git.blob(snapshots["base"].commit, source_approval_path, MAX_MANIFEST)
                source["policy_sha256"] = metadata["sha256"]
                policy = strict_json(data)
                if (not isinstance(policy, dict) or set(policy) != {"schema_version", "digests"}
                        or type(policy["schema_version"]) is not int or policy["schema_version"] != 1
                        or not isinstance(policy["digests"], list)
                        or any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)
                               for value in policy["digests"])
                        or len(set(policy["digests"])) != len(policy["digests"])):
                    raise EvidenceError("source approval file must contain schema_version 1 and unique lowercase SHA-256 digests")
                source["matched"] = source["head"]["sha256"] in policy["digests"]
            if changed_paths or not source["matched"]:
                source["status"] = "blocked"
                if not source["matched"]:
                    source["unapproved_head_digest"] = source["head"]["sha256"]
                if outcome == "allowed":
                    outcome = "blocked"
            else:
                source["status"] = "allowed"
        elif changed_paths:
            source["status"] = "blocked"
            if outcome == "allowed":
                outcome = "blocked"
        stage = "review_view"
        report["review"] = review_view(report, output)
        if store is not None:
            stage = "approval_request"
            request = approval_request(report)
            if request is not None:
                report["approval_request"] = request
                stage = "trusted_approval"
                if stored_approval(store, request):
                    if request["approvals"]:
                        effective = effective_approvals(base_policy_data, request["approvals"])
                        (output / "trusted-approvals.json").write_bytes(effective)
                        approved_core, approved_outcome = core_review(binary, output, "trusted-approvals.json")
                        if {key: value for key, value in approved_core.items() if key != "policy"} != {key: value for key, value in core.items() if key != "policy"}:
                            raise EvidenceError("core evidence changed while applying trusted approval")
                        if approved_outcome != "allowed":
                            raise EvidenceError("exact trusted approval did not allow the proposed evidence")
                        report["core"] = approved_core
                        outcome = approved_outcome
                    if request["source_tree_sha256"]:
                        source["approved_by_store"] = True
                        source["status"] = "allowed"
                    if outcome == "blocked" and source.get("status") == "allowed":
                        outcome = "allowed"
                    report["trusted_approval"] = {"origin": "external_store", "subject_sha256": request["subject_sha256"],
                                                  "matched": True}
        report.update(outcome=outcome, exit_code={"allowed": 0, "blocked": 1, "incomplete": 2}[outcome])
    except (EvidenceError, OSError, ValueError) as exc:
        message = str(exc)
        for original, replacement in replacements:
            message = message.replace(original, replacement)
        report["errors"].append({"stage": stage, "message": message, "next_action": next_action(message)})
    for label, snapshot in snapshots.items():
        report[label] = snapshot.report()
    if output is not None:
        (output / "report.json").write_bytes(json_bytes(report))
        (output / "summary.md").write_text(summary(report), encoding="utf-8")
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preview", action="store_true", help="show exact PR changes without approval policy or an allow decision")
    parser.add_argument("--baseline-from-base", action="store_true",
                        help="treat qualified candidates in the protected base as the approval baseline")
    parser.add_argument("--repo", type=Path, default=Path.cwd(), help="Git repository (default: current directory)")
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--project", default=".", help="portable repository-relative npm project directory")
    parser.add_argument("--approvals", help="repository-relative approval file read from base only")
    parser.add_argument("--source-approvals", help="repository-relative source-tree approval file read from base only")
    parser.add_argument("--tau-gate", type=Path, default=Path(__file__).resolve().parents[1] / "tau-gate",
                        help="caller-trusted executable (default: checker beside packaged tools)")
    parser.add_argument("--archive-cache", type=Path, help="offline SHA512-hex.tgz cache; omission permits constrained downloads")
    parser.add_argument("--approval-store", type=Path, help="administrator-controlled approval records outside the PR repository")
    parser.add_argument("--approve-subject", help="record this exact reviewed subject in the trusted approval store")
    parser.add_argument("--output", type=Path, help="new or empty directory outside repository and cache")
    args = parser.parse_args(argv)
    if args.preview:
        if args.baseline_from_base or any(value is not None for value in (args.approvals, args.source_approvals, args.approval_store, args.approve_subject)):
            parser.error("--preview cannot use approval options")
        if args.output is None:
            args.output = Path(tempfile.mkdtemp(prefix="tau-gate-preview-"))
    else:
        if args.output is None:
            parser.error("--output is required for an enforced review")
        if args.baseline_from_base:
            if args.approvals is not None or args.source_approvals is not None:
                parser.error("--baseline-from-base cannot use repository approval files")
        else:
            args.approvals = args.approvals or "tau-gate.approvals.json"
            args.source_approvals = args.source_approvals or "tau-gate.source-approvals.json"
    report = review(args)
    if args.approve_subject is not None:
        try:
            request = report.get("approval_request")
            if (args.approval_store is None or not re.fullmatch(r"[0-9a-f]{64}", args.approve_subject)
                    or request is None or request["subject_sha256"] != args.approve_subject
                    or report["errors"] or report["outcome"] == "incomplete"):
                raise EvidenceError("approval requires the exact subject from a complete blocked review and a trusted store")
            store = approval_store(args.approval_store, GitObjects(args.repo).repository,
                                   args.output.resolve(), args.archive_cache)
            created = record_approval(store, request)
        except (EvidenceError, OSError, ValueError) as exc:
            print(json.dumps({"approval_recorded": False, "error": str(exc)}, sort_keys=True))
            return 2
        print(json.dumps({"approval_recorded": True, "created": created,
                          "subject_sha256": request["subject_sha256"]}, sort_keys=True))
        return 0
    if args.preview:
        state = "complete" if report["outcome"] == "preview" else "incomplete"
        print(f"Tau-Gate PR preview: {state}")
        print("Informational only; no approval decision.")
        if (args.output / "summary.md").is_file():
            print(f"Summary: {args.output.resolve() / 'summary.md'}")
            print(f"JSON report: {args.output.resolve() / 'report.json'}")
            core = report.get("core") or {}
            view = report.get("review") or {}
            print(f"{len(core.get('package_changes', []))} package changes; "
                  f"{len(core.get('execution_evidence_changes', []))} evidence changes; "
                  f"{len(view.get('unknowns', []))} evidence gaps.")
            if report["errors"]:
                print(f"Reason: {report['errors'][0]['message']}")
        elif report["errors"]:
            print(report["errors"][0]["message"])
        return report["exit_code"]
    print(json.dumps(report, sort_keys=True, ensure_ascii=False))
    return report["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
