#!/usr/bin/env python3
"""Freeze and audit the distinct repositories named by a package CSV.

No package installation, lifecycle execution, or modification of source inputs.
Run again with the same output directory to reuse the frozen snapshots.
"""
import argparse
import collections
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
import datetime
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import urllib.parse
import urllib.request

import npm_evidence

LOCKS = {"package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml",
         "yarn.lock", "bun.lock", "bun.lockb"}
EXCLUDE = {"node_modules", "fixtures", "__fixtures__", "test", "tests",
           "examples", "example", "benchmark", "benchmarks", "vendor"}
LIMIT = 32 * 1024 * 1024


def sha(data):
    return hashlib.sha256(data).hexdigest()


def save(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def gh(route):
    result = subprocess.run(["gh", "api", route], capture_output=True,
                            text=True, timeout=90)
    if result.returncode:
        raise ValueError(result.stderr.strip()[:1000])
    return json.loads(result.stdout)


def api(item, suffix):
    if item.get("host", "github.com") == "github.com":
        return gh("repos/" + item["repository"] + "/" + suffix)
    url = "https://git.coolaj86.com/api/v1/repos/" + item["repository"] + "/" + suffix
    with urllib.request.urlopen(url, timeout=30) as response:
        return json.load(response)


def raw(repo, commit, path, host="github.com"):
    parts = PurePosixPath(path).parts
    if not parts or path.startswith("/") or any(p in (".", "..") for p in parts):
        raise ValueError("unsafe Git path")
    url = f"https://raw.githubusercontent.com/{repo}/{commit}/" + urllib.parse.quote(path)
    if host == "git.coolaj86.com":
        url = f"https://git.coolaj86.com/{repo}/raw/commit/{commit}/" + urllib.parse.quote(path)
    request = urllib.request.Request(url, headers={"User-Agent": "tau-gate-repo-experiment/1"})
    with urllib.request.urlopen(request, timeout=45) as response:
        data = response.read(LIMIT + 1)
    if len(data) > LIMIT:
        raise ValueError("source file exceeds 32 MiB")
    return data, url


def resolve(url):
    if url == "git://git.coolaj86.com/coolaj86/atob.js.git":
        try:
            item = {"input_url": url, "repository": "coolaj86/atob.js", "host": "git.coolaj86.com"}
            info = api(item, "")
            return {**item, "default_branch": info["default_branch"],
                    "archived": info["archived"], "status": "resolved"}
        except Exception as error:
            return {"input_url": url, "status": "lookup_failed", "error": str(error)}
    match = re.fullmatch(r"https://github.com/([\w.-]+/[\w.-]+?)(?:\.git)?/?", url)
    if not match:
        return {"input_url": url, "status": "unsupported_host"}
    try:
        info = gh("repos/" + match[1])
        return {"input_url": url, "repository": info["full_name"],
                "default_branch": info["default_branch"],
                "archived": info["archived"], "status": "resolved"}
    except Exception as error:
        return {"input_url": url, "status": "lookup_failed", "error": str(error)}


def capture(item, output):
    repo = item["repository"]
    folder = output / "repositories" / repo.replace("/", "__")
    receipt = folder / "snapshot.json"
    if receipt.exists():
        return json.loads(receipt.read_text())
    item = dict(item)
    item["captured_at_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    try:
        branch = urllib.parse.quote(item["default_branch"], safe="")
        if item.get("host", "github.com") == "github.com":
            commit = api(item, "commits/" + branch)["sha"]
        else:
            commit = api(item, "branches/" + branch)["commit"]["id"]
        item["commit"] = commit
        root = api(item, f"git/trees/{commit}")
        save(folder / "root-tree.json", root)
        paths = {e["path"] for e in root["tree"] if e["type"] == "blob"}
        locks = sorted(paths & LOCKS)
        item["discovery_scope"] = "root_lockfiles"
        item["tree_truncated"] = bool(root.get("truncated"))
        if not locks:
            tree = api(item, f"git/trees/{commit}?recursive=1")
            save(folder / "recursive-tree.json", tree)
            paths = {e["path"] for e in tree["tree"] if e["type"] == "blob"}
            locks = sorted(p for p in paths if PurePosixPath(p).name in LOCKS
                           and not (set(PurePosixPath(p).parts[:-1]) & EXCLUDE))
            # Use every nearest project lock, without counting its fixtures as projects.
            if locks:
                depth = min(p.count("/") for p in locks)
                locks = [p for p in locks if p.count("/") == depth]
            item["discovery_scope"] = "nearest_non_fixture_lockfiles"
            item["tree_truncated"] = bool(tree.get("truncated"))
        item["lockfiles"] = locks
        wanted = set(locks)
        for lock in locks:
            parent = PurePosixPath(lock).parent
            for name in ("package.json", "binding.gyp"):
                candidate = str(parent / name)
                if candidate in paths:
                    wanted.add(candidate)
        if "package.json" in paths:
            wanted.add("package.json")
        item["files"] = []
        for path in sorted(wanted):
            data, url = raw(repo, commit, path, item.get("host", "github.com"))
            dest = folder / "source" / path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            item["files"].append({"path": path, "sha256": sha(data), "bytes": len(data), "url": url})
        item["status"] = "captured" if locks else "no_project_lockfile_found"
    except Exception as error:
        item["status"] = "capture_failed"
        item["error"] = str(error)
    save(receipt, item)
    return item


def observations(report):
    packages = report.get("packages", [])
    versions = collections.defaultdict(set)
    external = []
    weak = []
    missing = []
    for package in packages:
        if package["path"] in ("root", ""):
            continue
        versions[package["name"]].add(package["version"])
        source = package.get("source", "")
        integrity = package.get("integrity", "")
        host = urllib.parse.urlparse(source).hostname
        if source and host and host not in {"registry.npmjs.org", "registry.yarnpkg.com"}:
            external.append(package)
        if source.startswith(("http:", "git:", "git+", "github:", "file:")):
            if package not in external:
                external.append(package)
        if integrity and not any(s.startswith("sha512-") for s in integrity.split()):
            weak.append(package)
        if source.startswith(("https://", "http://")) and not integrity:
            missing.append(package)
    return {"multiple_versions": {n: sorted(v) for n, v in sorted(versions.items()) if len(v) > 1},
            "external_or_non_https_sources": external, "integrity_without_sha512": weak,
            "http_sources_without_integrity": missing}


def inspect_marked(audits, output):
    """Inspect only positive registry install markers, retaining partial coverage."""
    receipt = output / "marked-artifacts.json"
    cache = {}
    if receipt.exists():
        for prior in json.loads(receipt.read_text())["records"]:
            fields = {k: v for k, v in prior.items() if k not in {
                "repository", "path", "expected_name", "expected_version", "lockfile"}}
            if prior["status"] == "sri_verified_and_inspected":
                archive = output / prior["archive"]
                if not archive.exists() or sha(archive.read_bytes()) != prior["archive_sha256"]:
                    continue
            cache[(prior["source"], prior["integrity"])] = fields
    records = []
    for audit_result in audits:
        if not audit_result["lockfile"].endswith(".json") or not audit_result["package_records"]:
            continue
        repo = audit_result["repository"]
        folder = output / "repositories" / repo.replace("/", "__")
        lock = json.loads((folder / "source" / audit_result["lockfile"]).read_bytes())
        for path, record in sorted(lock.get("packages", {}).items()):
            if not path.startswith("node_modules/") or not record.get("hasInstallScript"):
                continue
            key = (record.get("resolved", ""), record.get("integrity", ""))
            if key not in cache:
                facts = {"source": key[0], "integrity": key[1]}
                try:
                    npm_evidence.archive_source(key[0])
                    npm_evidence.sri_digest(key[1])
                    archive = npm_evidence.fetch_archive(key[0])
                    dest = output / "marked-archives" / (sha(archive) + ".tgz")
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes(archive)
                    # Rust and this independent helper impose the same narrow archive profile.
                    data, manifest, binding, binding_hash = npm_evidence.archive_facts(archive, key[1])
                    npm_evidence.check_identity(path, record, manifest)
                    scripts = manifest.get("scripts", {})
                    events = {name: scripts[name] for name in npm_evidence.DEPENDENCY_EVENTS
                              if scripts.get(name)}
                    implicit = bool(binding and manifest.get("gypfile") is not False
                                    and not scripts.get("install") and not scripts.get("preinstall"))
                    facts.update(status="sri_verified_and_inspected", archive=str(dest.relative_to(output)),
                                 archive_sha256=sha(archive), manifest_sha256=sha(data),
                                 name=manifest.get("name"), version=manifest.get("version"),
                                 lifecycle_scripts=events, binding_gyp=binding,
                                 binding_gyp_sha256=binding_hash, implicit_node_gyp=implicit,
                                 execution_candidate=bool(events or implicit))
                except Exception as error:
                    facts.update(status="incomplete", error=str(error))
                cache[key] = facts
            facts = cache[key]
            expected = npm_evidence.expected_name(path, record)
            if facts["status"] == "sri_verified_and_inspected" and (
                    facts["name"] != expected or facts["version"] != record.get("version")):
                facts = {**facts, "status": "incomplete", "error": "cached archive identity differs from lock instance"}
            records.append({"repository": repo, "path": path, "lockfile": audit_result["lockfile"],
                            "expected_name": expected,
                            "expected_version": record.get("version"), **facts})
    result = {"scope": "positive npm registry hasInstallScript markers only; other artifacts not inspected",
              "unique_source_integrity_pairs": len(cache), "records": records}
    save(receipt, result)
    return result


def audit_partial(audits, marked, output, binary):
    results = []
    for item in audits:
        if not item["package_records"] or not item["lockfile"].endswith(".json"):
            continue
        repo = item["repository"]
        name = repo.replace("/", "__")
        source = output / "repositories" / name / "source"
        manifest = (source / item["lockfile"]).parent / "package.json"
        packages = [{"path": "", "project_manifest": str(manifest.relative_to(output))}] if manifest.exists() else []
        packages += [{"path": r["path"], "artifact": r["archive"]} for r in marked["records"]
                     if r["repository"] == repo and r["lockfile"] == item["lockfile"]
                     and r["status"] == "sri_verified_and_inspected"]
        index = output / ("partial-index-" + name + ".json")
        save(index, {"schema_version": 1, "lock_sha256": item["lock_sha256"], "packages": packages})
        command = [str(binary), "audit", "--lock", str(source / item["lockfile"]),
                   "--evidence", str(index), "--json"]
        if manifest.exists():
            command += ["--manifest", str(manifest)]
        proc = subprocess.run(command, cwd=output, capture_output=True, text=True, timeout=180)
        report = json.loads(proc.stdout)
        dest = output / "repositories" / name / "audits" / "partial-evidence.json"
        save(dest, report)
        evidence = report.get("execution_evidence") or []
        results.append({"repository": repo, "exit_code": proc.returncode,
                        "status": report.get("status"), "error": report.get("error"),
                        "states": dict(collections.Counter(e["state"] for e in evidence)),
                        "report": str(dest.relative_to(output)), "command": command})
    save(output / "partial-evidence-receipt.json", results)
    return results


def audit(item, output, binary):
    folder = output / "repositories" / item["repository"].replace("/", "__")
    results = []
    for path in item.get("lockfiles", []):
        lock = folder / "source" / path
        manifest = lock.parent / "package.json"
        command = [str(binary), "audit", "--lock", str(lock), "--json"]
        if manifest.exists():
            command += ["--manifest", str(manifest)]
        result = {"repository": item["repository"], "commit": item["commit"], "lockfile": path,
                  "command": command, "lock_sha256": sha(lock.read_bytes())}
        try:
            proc = subprocess.run(command, cwd=output, capture_output=True, text=True, timeout=180)
            report = json.loads(proc.stdout)
            result.update(exit_code=proc.returncode, status=report.get("status"),
                          topology_status=report.get("topology_status"),
                          execution_metadata_status=report.get("execution_metadata_status"),
                          error=report.get("error"), issues=report.get("issues", []),
                          package_records=len(report.get("packages", [])),
                          edges=len(report.get("edges", [])),
                          execution_candidates=len(report.get("execution_candidates", [])))
            dest = folder / "audits" / (path.replace("/", "__") + ".json")
            save(dest, report)
            result["report"] = str(dest.relative_to(output))
            save(dest.with_suffix(".observations.json"), observations(report))
            if proc.stderr:
                result["stderr"] = proc.stderr[:2000]
        except Exception as error:
            result.update(status="audit_failed", error=str(error))
        results.append(result)
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--inspect-marked-archives", action="store_true")
    args = parser.parse_args()
    output = args.output.resolve()
    binary = args.binary.resolve()
    output.mkdir(parents=True, exist_ok=True)
    rows = list(csv.DictReader(args.csv.open(newline="")))
    original = output / "input.csv"
    if original.exists() and original.read_bytes() != args.csv.read_bytes():
        raise SystemExit("input differs from the frozen experiment")
    if not original.exists():
        shutil.copyfile(args.csv, original)
    resolution_path = output / "repository-resolution.json"
    if resolution_path.exists():
        resolved = json.loads(resolution_path.read_text())
        resolved = [resolve(r["input_url"]) if r["status"] == "unsupported_host" else r for r in resolved]
        save(resolution_path, resolved)
    else:
        urls = sorted({r["repository_url"] for r in rows if r["repository_url"]})
        with ThreadPoolExecutor(max_workers=6) as pool:
            resolved = list(pool.map(resolve, urls))
        save(resolution_path, resolved)
    groups = {}
    for item in resolved:
        if item["status"] != "resolved":
            continue
        name = item["repository"]
        groups.setdefault(name, dict(item, input_urls=[], csv_packages=[]))
        groups[name]["input_urls"].append(item["input_url"])
        groups[name]["csv_packages"] += [r["name"] for r in rows if r["repository_url"] == item["input_url"]]
    snapshots = []
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {pool.submit(capture, item, output): name for name, item in sorted(groups.items())}
        for future in as_completed(futures):
            item = future.result()
            snapshots.append(item)
            print(json.dumps({"repository": item["repository"], "status": item["status"],
                              "lockfiles": item.get("lockfiles", [])}), flush=True)
    snapshots.sort(key=lambda item: item["repository"])
    save(output / "snapshots.json", snapshots)
    audits = []
    for item in snapshots:
        results = audit(item, output, binary)
        audits.extend(results)
        for result in results:
            print(json.dumps({k: result.get(k) for k in ("repository", "lockfile", "status", "package_records", "error")}), flush=True)
    receipt = {"csv_sha256": sha(original.read_bytes()), "input_packages": len(rows),
               "listed_repository_urls": len(resolved),
               "canonical_accessible_repositories": len(groups),
               "canonical_github_repositories": sum(g.get("host", "github.com") == "github.com" for g in groups.values()),
               "packages_without_repository": [r["name"] for r in rows if not r["repository_url"]],
               "unresolved_repositories": [r for r in resolved if r["status"] != "resolved"],
               "binary_sha256": sha(binary.read_bytes()),
               "binary_version": subprocess.run([str(binary), "--verify"], capture_output=True, text=True).stdout,
               "runner_sha256": sha(Path(__file__).read_bytes()),
               "snapshots": snapshots, "audits": audits,
               "status_counts": dict(collections.Counter(r["status"] for r in audits))}
    save(output / "receipt.json", receipt)
    if args.inspect_marked_archives:
        marked = inspect_marked(audits, output)
        audit_partial(audits, marked, output, binary)
        print(json.dumps({"marked_records": len(marked["records"]),
                          "statuses": dict(collections.Counter(r["status"] for r in marked["records"]))}), flush=True)
    print(json.dumps({"receipt": str(output / "receipt.json"), "status_counts": receipt["status_counts"]}), flush=True)


if __name__ == "__main__":
    main()
