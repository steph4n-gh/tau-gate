# Unchanged v4.1 baseline

The frozen cohort contains 30 public npm projects and 90 historical update pairs. Every pair produced a receipt. All 180 pair sides passed captured-input byte verification. The preserved native macOS arm64 binary identifies commit `4fcf535fd1b52922fd4b0d2584bc0d2fb8bbbbe0`. Its SHA256 and all three helper hashes remained unchanged throughout the run.

All 90 core reviews returned incomplete with exit 2. None establishes a qualified allowed result. All 180 collector validations were incomplete. Acquisition was complete on 132 pair sides and partial on 48. The independent oracle was complete on 53 sides and partial on 127. Counts include reused snapshots. The cohort is purposively selected and does not estimate npm-wide coverage.

The independent raw-execution audit found no input, output, command, exit, or hash-binding errors. It hashed holdout report bodies without interpreting their contents. [The raw receipt](evidence/baseline-raw.json) binds each case and preserves the original score. That score is preliminary. Its comparator incorrectly counted some absent source and integrity additions as misses because the core renders absent metadata as an empty string and the oracle preserves null. A separate verified rescore must resolve this defect before accepting event counts. The original run remains unchanged.

Peak measured core RSS was 1,496,825,856 bytes across 90 measurements. This is a native macOS observation. It does not qualify Linux memory use. Profiling a development case identified retained empty allocator regions during sequential archive processing. A buffer-reuse repair must preserve report bytes and pass a paired resource comparison before any improvement is claimed.

## Development limitations

The 72 development pairs expose several separate limitations. Missing or noncanonical SHA512, absent artifact sources, unsupported sources, unavailable source manifests, and oversized artifacts prevent complete evidence. The checker also rejects ordinary legacy archive roots and header layouts. Additional archives contain names outside the portable profile, extensions or special records. Some lock install markers contradict inspected facts. These classes overlap and remain in the denominator.

[Development resource counts](evidence/development-resources.json) measure actual decompressed bytes, including bounded failed attempts. [Input maxima and archive classes](evidence/development-inputs.json) distinguish snapshot totals from a base-plus-head review. They do not treat a gzip size footer as measured work. Twenty-four unique archives exceeded the existing 64 MiB expanded limit. Their unrestricted expansion and member totals remain lower bounds.

Repeat the development resource census after acquiring the frozen inputs.

```sh
python3 tools/qualification_census.py \
  --corpus docs/qualification/corpus.json \
  --sources /path/to/sources \
  --output /path/to/fresh-census
```

The script deduplicates decompression by content while charging every archive locator in each snapshot. It uses Python zlib and tarfile without extraction or package execution. The census describes resource inputs. It is not a security acceptance gate or a speed benchmark.

The controlled npm reference and negative-control matrices remain separate from historical coverage. Missing facts are unknown. A failed closed result is useful behavior, but it does not establish usable coverage or general malware detection. Human review minutes and sustained pilot use have not been measured.
