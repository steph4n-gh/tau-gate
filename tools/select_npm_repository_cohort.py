#!/usr/bin/env python3
"""Select distinct repository identities by their best-ranked npm package."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import csv
import hashlib
import json
from pathlib import Path
import shutil
import urllib.request

from npm_repo_experiment import resolve, save


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-url", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--pilot", type=Path, required=True)
    parser.add_argument("--count", type=int, default=200)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    source = output / "critical-source.json"
    if not source.exists():
        with urllib.request.urlopen(args.source_url, timeout=60) as response:
            data = response.read(32 * 1024 * 1024 + 1)
        if len(data) > 32 * 1024 * 1024:
            raise SystemExit("critical dataset exceeds 32 MiB")
        source.write_bytes(data)
    data = json.loads(source.read_bytes())
    packages = sorted((p for p in data["projects"] if p["ecosystem"] == "npm"),
                      key=lambda p: (p["rankings_average"], p["name"]))
    ranked = []
    seen_urls = set()
    for rank, package in enumerate(packages, 1):
        url = package.get("repository_url")
        if url and url not in seen_urls:
            seen_urls.add(url)
            ranked.append((rank, package))
    cache_file = output / "selection-resolution-cache.json"
    cache = {}
    if cache_file.exists():
        cache.update(json.loads(cache_file.read_text()))
    else:
        old = json.loads((args.pilot / "repository-resolution.json").read_text())
        cache.update({r["input_url"]: r for r in old})
    selected, identities, duplicates = [], set(), []
    for start in range(0, len(ranked), 32):
        batch = ranked[start:start + 32]
        needed = [p["repository_url"] for _, p in batch if p["repository_url"] not in cache]
        with ThreadPoolExecutor(max_workers=6) as pool:
            for item in pool.map(resolve, needed):
                cache[item["input_url"]] = item
        save(cache_file, cache)
        for rank, package in batch:
            resolution = cache[package["repository_url"]]
            # Unavailable named repositories remain in the cohort, not replaced by easier projects.
            identity = (resolution.get("host", "github.com"),
                        resolution.get("repository", resolution["input_url"]).lower())
            if identity in identities:
                duplicates.append(resolution)
                continue
            identities.add(identity)
            selected.append({"repository_rank": len(selected) + 1,
                             "npm_package_rank": rank, "package": package,
                             "resolution": resolution})
            if len(selected) == args.count:
                break
        print(json.dumps({"selected": len(selected), "candidate_urls_resolved": len(cache)}), flush=True)
        if len(selected) == args.count:
            break
    if len(selected) != args.count:
        raise SystemExit("not enough distinct repositories in source")
    save(output / "cohort.json", {"source_url": args.source_url,
                                  "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                                  "npm_packages_in_source": len(packages),
                                  "selection_rule": "ascending ecosyste.ms rankings_average of best-ranked package; canonical repository redirects deduplicated; unavailable repositories retained",
                                  "confirmed_duplicate_urls": duplicates, "repositories": selected})
    fields = ["rank", "name", "downloads", "dependent_packages", "repository_url",
              "latest_release_at", "rankings_average"]
    with (output / "repository-input.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for item in selected:
            p = item["package"]
            writer.writerow({"rank": item["repository_rank"], "name": p["name"],
                             "downloads": p.get("downloads"),
                             "dependent_packages": p.get("dependent_packages_count"),
                             "repository_url": p["repository_url"],
                             "latest_release_at": p.get("latest_release_at"),
                             "rankings_average": p["rankings_average"]})
    save(output / "repository-resolution.json", [x["resolution"] for x in selected])
    # Reuse already frozen pilot snapshots rather than moving their observation date.
    for item in selected:
        repo = item["resolution"].get("repository")
        if not repo:
            continue
        relative = Path("repositories") / repo.replace("/", "__")
        old, new = args.pilot / relative, output / relative
        if old.exists() and not new.exists():
            shutil.copytree(old, new)


if __name__ == "__main__":
    main()
