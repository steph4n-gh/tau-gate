#!/usr/bin/env python3
"""Regenerate the large ustar fixture using only Python's standard library."""
import gzip
import io
from pathlib import Path
import tarfile

buffer = io.BytesIO()
with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
    for name, data in [
        ("package/package.json", b'{"name":"large","version":"1"}'),
        ("package/data.bin", bytes(65 * 1024 * 1024)),
    ]:
        entry = tarfile.TarInfo(name)
        entry.size = len(data)
        archive.addfile(entry, io.BytesIO(data))
Path(__file__).with_name("large-nonlifecycle.tgz").write_bytes(
    gzip.compress(buffer.getvalue(), mtime=0)
)
