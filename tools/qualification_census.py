#!/usr/bin/env python3
import argparse
import base64
import collections
import hashlib
import io
import json
import math
import os
import pathlib
import struct
import sys
import tarfile
import zlib

LIMIT = 64 * 1024 * 1024
MEMBERS = 10000
CHUNK = 65536


def digest(data):
    return hashlib.sha256(data).hexdigest()


def load(path):
    data = path.read_bytes()
    return json.loads(data), digest(data)


def archive(data):
    result = {'compressed_bytes': len(data), 'produced_bytes': 0,
              'produced_bytes_exact': True, 'gzip_status': 'invalid',
              'raw_tar_headers': 0, 'raw_tar_headers_exact': False,
              'logical_tar_members': 0, 'logical_tar_members_exact': False}
    if len(data) > LIMIT:
        result['gzip_reason'] = 'compressed limit exceeded before decompression'
        return result
    if len(data) < 18 or data[:3] != b'\x1f\x8b\x08' or data[3] & 0xe0:
        result['gzip_reason'] = 'invalid gzip header'
        return result
    flags = data[3]
    start = 10
    try:
        if flags & 4:
            length, = struct.unpack_from('<H', data, start)
            start += 2 + length
        for flag in (8, 16):
            if flags & flag:
                start = data.index(0, start) + 1
        if flags & 2:
            expected, = struct.unpack_from('<H', data, start)
            if zlib.crc32(data[:start]) & 0xffff != expected:
                raise ValueError('gzip header CRC mismatch')
            start += 2
        if start > len(data) - 8:
            raise ValueError('truncated gzip header')
    except (ValueError, struct.error) as error:
        result['gzip_reason'] = str(error)
        return result
    inflater = zlib.decompressobj(-zlib.MAX_WBITS)
    output = bytearray()
    position = start
    pending = b''
    try:
        while not inflater.eof:
            if not pending:
                pending = data[position:position + CHUNK]
                position += len(pending)
                if not pending:
                    raise ValueError('truncated DEFLATE stream')
            chunk = inflater.decompress(pending, min(CHUNK, LIMIT - len(output) + 1))
            output.extend(chunk)
            pending = inflater.unconsumed_tail
            if len(output) > LIMIT:
                result['produced_bytes_exact'] = False
                raise ValueError('expanded limit exceeded; observed lower bound')
        trailer = inflater.unused_data + data[position:]
        if len(trailer) != 8:
            raise ValueError('trailer is not exactly eight bytes; additional member or trailing data')
        crc, size = struct.unpack('<II', trailer)
        if zlib.crc32(output) & 0xffffffff != crc:
            raise ValueError('gzip CRC mismatch')
        if len(output) & 0xffffffff != size:
            raise ValueError('gzip ISIZE mismatch')
        result['gzip_status'] = 'valid'
    except zlib.error as error:
        result['produced_bytes_exact'] = False
        result['gzip_reason'] = str(error) + '; only returned output is counted'
    except (ValueError, struct.error) as error:
        result['gzip_reason'] = str(error)
    result['produced_bytes'] = len(output)
    if len(output) > LIMIT:
        return result
    position = 0
    try:
        while position + 512 <= len(output):
            block = bytes(output[position:position + 512])
            if block == bytes(512):
                result['raw_tar_headers_exact'] = True
                break
            header = tarfile.TarInfo.frombuf(block, 'utf-8', 'surrogateescape')
            result['raw_tar_headers'] += 1
            if result['raw_tar_headers'] > MEMBERS:
                raise ValueError('raw tar header limit exceeded; observed lower bound')
            if header.size < 0:
                raise ValueError('negative tar header size')
            position += 512 + ((header.size + 511) // 512) * 512
            if position > len(output):
                raise ValueError('tar body truncated')
        else:
            raise ValueError('tar terminator absent')
    except (ValueError, tarfile.TarError) as error:
        result['raw_tar_reason'] = str(error)
    try:
        with tarfile.open(fileobj=io.BytesIO(output), mode='r|') as stream:
            for member in stream:
                result['logical_tar_members'] += 1
                if result['logical_tar_members'] > MEMBERS:
                    raise ValueError('logical tar member limit exceeded; observed lower bound')
            result['logical_tar_members_exact'] = True
    except (ValueError, tarfile.TarError, OSError) as error:
        result['logical_tar_reason'] = str(error)
    return result


def distribution(rows, key):
    ordered = sorted(rows, key=lambda row: (row[key], row['repository'], row['revision']))
    return {'min': ordered[0][key], 'median': ordered[len(ordered) // 2][key],
            'p90': ordered[math.ceil(len(ordered) * .90) - 1][key],
            'p95': ordered[math.ceil(len(ordered) * .95) - 1][key],
            'max': ordered[-1][key],
            'maximum_snapshots': [{'repository': row['repository'], 'revision': row['revision']}
                                  for row in ordered if row[key] == ordered[-1][key]]}


def main():
    args = argparse.ArgumentParser()
    args.add_argument('--corpus', type=pathlib.Path, required=True)
    args.add_argument('--sources', type=pathlib.Path, required=True)
    args.add_argument('--output', type=pathlib.Path, required=True)
    options = args.parse_args()
    os.nice(10)
    options.output.mkdir(parents=True, exist_ok=False)
    corpus, corpus_hash = load(options.corpus)
    selected = sorted({(pair['repository'], pair[key]) for pair in corpus['pairs']
                       if pair['split'] == 'development' for key in ('base', 'head')})
    archives = {}
    identities = {}
    snapshots = []
    inputs = []
    failures = []
    for sequence, (repository, revision) in enumerate(selected, 1):
        directory = options.sources / repository.replace('/', '__') / revision
        lock, lock_hash = load(directory / 'project/package-lock.json')
        index, index_hash = load(directory / 'evidence/index.json')
        acquisition, acquisition_hash = load(directory / 'acquisition.json')
        inputs.extend([(str(directory / 'project/package-lock.json'), lock_hash),
                       (str(directory / 'evidence/index.json'), index_hash),
                       (str(directory / 'acquisition.json'), acquisition_hash)])
        records = lock['packages']
        row = {'repository': repository, 'revision': revision,
               'lock_sha256': lock_hash, 'index_sha256': index_hash,
               'acquisition_sha256': acquisition_hash, 'lock_bytes': (directory / 'project/package-lock.json').stat().st_size,
               'record_count': len(records), 'archive_attempts': 0, 'compressed_bytes': 0,
               'produced_bytes': 0, 'produced_bytes_exact': True,
               'raw_tar_headers': 0, 'raw_tar_headers_exact': True,
               'logical_tar_members': 0, 'logical_tar_members_exact': True,
               'archive_failure_attempts': 0, 'source_modes': collections.Counter(),
               'sri_modes': collections.Counter(), 'acquisition_modes': collections.Counter(),
               'declared_edges_by_field': collections.Counter(), 'archive_multiplicities': collections.Counter()}
        for path, record in records.items():
            for field in ('dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'):
                if isinstance(record.get(field), dict):
                    row['declared_edges_by_field'][field] += len(record[field])
            if record.get('link') is True:
                mode = 'workspace_link'
            elif not path or 'node_modules/' not in path:
                mode = 'project_manifest'
            else:
                resolved = record.get('resolved')
                mode = 'missing' if not resolved else 'http' if resolved.startswith(('http://', 'https://')) else 'other'
            row['source_modes'][mode] += 1
            sri = record.get('integrity')
            if sri is None:
                sri_mode = 'missing'
            else:
                try:
                    prefix, encoded = sri.split('-', 1)
                    decoded = base64.b64decode(encoded, validate=True)
                    canonical = prefix == 'sha512' and len(decoded) == 64 and base64.b64encode(decoded).decode() == encoded
                except (ValueError, TypeError):
                    canonical = False
                sri_mode = 'canonical_single_sha512' if canonical else 'noncanonical_or_other'
            row['sri_modes'][sri_mode] += 1
        row['declared_edge_count'] = sum(row['declared_edges_by_field'].values())
        for path, value in acquisition['packages'].items():
            row['acquisition_modes'][value['status'] + (': ' + value['reason'] if value.get('reason') else '')] += 1
        for entry in index['packages']:
            if 'artifact' not in entry:
                continue
            row['archive_attempts'] += 1
            relative = pathlib.PurePosixPath(entry['artifact'])
            if relative.is_absolute() or '..' in relative.parts:
                raise ValueError('unsafe artifact locator')
            path = directory / 'evidence' / relative
            stat = path.stat()
            identity = (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)
            key = path.stem
            if identity not in identities:
                data = path.read_bytes()
                actual = hashlib.sha512(data).hexdigest()
                if actual != key:
                    raise ValueError('archive filename SHA512 mismatch ' + str(path))
                identities[identity] = actual
                if actual not in archives:
                    archives[actual] = archive(data)
                    archives[actual]['first_source'] = str(path)
                    archives[actual]['sha256'] = digest(data)
            elif identities[identity] != key:
                raise ValueError('archive inode has conflicting content keys')
            value = archives[key]
            row['archive_multiplicities'][key] += 1
            for field in ('compressed_bytes', 'produced_bytes', 'raw_tar_headers', 'logical_tar_members'):
                row[field] += value[field]
            for field in ('produced_bytes_exact', 'raw_tar_headers_exact', 'logical_tar_members_exact'):
                row[field] &= value[field]
            invalid = value['gzip_status'] != 'valid' or not value['raw_tar_headers_exact'] or not value['logical_tar_members_exact']
            if invalid:
                row['archive_failure_attempts'] += 1
                failures.append({'repository': repository, 'revision': revision,
                                 'package_path': entry['path'], 'archive_sha512': key})
        snapshots.append(row)
        (options.output / 'snapshots.jsonl').open('a').write(json.dumps(row, sort_keys=True) + '\n')
        print(json.dumps({'snapshot': sequence, 'of': len(selected), 'repository': repository,
                          'revision': revision, 'archive_attempts': row['archive_attempts'],
                          'unique_archives_measured': len(archives)}), flush=True)
    changed = []
    for path, expected in inputs:
        if digest(pathlib.Path(path).read_bytes()) != expected:
            changed.append(path)
    if digest(options.corpus.read_bytes()) != corpus_hash:
        changed.append(str(options.corpus))
    fields = ('record_count', 'declared_edge_count', 'archive_attempts', 'compressed_bytes',
              'produced_bytes', 'raw_tar_headers', 'logical_tar_members', 'lock_bytes')
    summary = {'schema_version': 1, 'corpus_sha256': corpus_hash,
               'split': 'development', 'pair_count': sum(p['split'] == 'development' for p in corpus['pairs']),
               'snapshot_count': len(snapshots), 'unique_archive_count': len(archives),
               'unique_archive_inodes_read': len(identities),
               'per_archive_produced_limit': LIMIT, 'per_archive_tar_header_limit': MEMBERS,
               'counting': 'Each snapshot charges each artifact locator, including repeated content. Unique content is decompressed once. Actual returned raw-DEFLATE bytes are counted before independent gzip CRC/ISIZE checks. No ISIZE estimates.',
               'scope': 'Diagnostic input accounting. No speed benchmark, policy coverage, parser qualification, or holdout evaluation.',
               'script_sha256': digest(pathlib.Path(__file__).read_bytes()),
               'python': sys.version, 'zlib_compile_version': zlib.ZLIB_VERSION,
               'zlib_runtime_version': zlib.ZLIB_RUNTIME_VERSION,
               'input_files_changed_during_run': changed,
               'distributions': {field: distribution(snapshots, field) for field in fields},
               'archive_failures_unique': sum(v['gzip_status'] != 'valid' or not v['raw_tar_headers_exact'] or not v['logical_tar_members_exact'] for v in archives.values()),
               'archive_failure_attempts': len(failures),
               'snapshot_totals': {field: sum(row[field] for row in snapshots) for field in fields},
               'all_snapshot_produced_byte_totals_exact': all(row['produced_bytes_exact'] for row in snapshots),
               'all_snapshot_raw_tar_header_totals_exact': all(row['raw_tar_headers_exact'] for row in snapshots),
               'all_snapshot_logical_tar_member_totals_exact': all(row['logical_tar_members_exact'] for row in snapshots)}
    for name, value in [('archives.json', archives), ('failures.json', failures), ('summary.json', summary)]:
        (options.output / name).write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')
    print(json.dumps(summary, sort_keys=True), flush=True)
    if changed:
        raise SystemExit('input metadata changed')


if __name__ == '__main__':
    main()
