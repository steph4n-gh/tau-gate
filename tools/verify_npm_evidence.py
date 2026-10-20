#!/usr/bin/env python3
"""Independent black-box controls for the v4.1 offline evidence reader."""
import argparse
import base64
import copy
import dataclasses
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import random
import struct
import subprocess
import sys
import tarfile
import zlib

SEED = 0x544155_0401
STARTING_COMMIT = '39a6a183a78068994053dc89546feed4f6474f0b'
MIB = 1024 * 1024
MANIFEST = {'name': 'pkg', 'version': '1.0.0', 'scripts': {'install': 'echo tau-gate-control-never-execute'}}
ROOT = {'name': 'controls-root', 'version': '1.0.0', 'dependencies': {'pkg': '1.0.0'}}


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def sri(data):
    return 'sha512-' + base64.b64encode(hashlib.sha512(data).digest()).decode()


def archive(entries):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as output:
        for name, data, kind, link in entries:
            info = tarfile.TarInfo(name)
            info.uid = info.gid = info.mtime = 0
            info.mode = 0o755 if kind == tarfile.DIRTYPE else 0o644
            info.type = kind
            info.linkname = link
            info.size = len(data)
            output.addfile(info, io.BytesIO(data))
    return stream.getvalue()


def regular(name, data):
    return name, data, tarfile.REGTYPE, ''


def tar_for(manifest=None, payload=b'', extra=()):
    return archive([regular('package/package.json', encoded(manifest or MANIFEST)),
                    regular('package/blob.bin', payload), *extra])


def raw_compress(data, level=6, strategy=zlib.Z_DEFAULT_STRATEGY):
    compressor = zlib.compressobj(level, zlib.DEFLATED, -15, 8, strategy)
    return compressor.compress(data) + compressor.flush()


def gzip_raw(data, raw):
    return b'\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff' + raw + struct.pack('<II', zlib.crc32(data), len(data) & 0xffffffff)


def zipped(data, level=6, strategy=zlib.Z_DEFAULT_STRATEGY):
    result = gzip_raw(data, raw_compress(data, level, strategy))
    assert gzip.decompress(result) == data
    return result


def stored_blocks(data, chunk=997):
    result = bytearray()
    for offset in range(0, len(data), chunk):
        block = data[offset:offset + chunk]
        result.append(int(offset + chunk >= len(data)))
        result.extend(struct.pack('<HH', len(block), 0xffff ^ len(block)))
        result.extend(block)
    return bytes(result)


class Bits:
    def __init__(self, data):
        self.data, self.offset = data, 0

    def read(self, width):
        if self.offset + width > 8 * len(self.data):
            raise ValueError('Truncated independent DEFLATE analysis')
        value = sum(((self.data[(self.offset + n) // 8] >> ((self.offset + n) % 8)) & 1) << n for n in range(width))
        self.offset += width
        return value

    def align(self):
        self.offset = (self.offset + 7) // 8 * 8


def huffman(lengths):
    counts = [0] + [lengths.count(n) for n in range(1, 16)]
    code, next_code = 0, [0] * 16
    for width in range(1, 16):
        code = (code + counts[width - 1]) << 1
        next_code[width] = code
    table = {}
    for symbol, width in enumerate(lengths):
        if width:
            reverse = int(f'{next_code[width]:0{width}b}'[::-1], 2)
            table[reverse, width] = symbol
            next_code[width] += 1
    return table


def symbol(bits, table):
    value = 0
    for width in range(1, 16):
        value |= bits.read(1) << (width - 1)
        if (value, width) in table:
            return table[value, width]
    raise ValueError('Invalid independent Huffman code')


def deflate_facts(raw):
    bits, output, blocks, overlaps = Bits(raw), 0, [], 0
    length_base = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258]
    length_extra = [0] * 8 + [1] * 4 + [2] * 4 + [3] * 4 + [4] * 4 + [5] * 4 + [0]
    distance_base = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577]
    distance_extra = [0] * 4 + [n for n in range(1, 14) for _ in range(2)]
    while True:
        final, kind = bits.read(1), bits.read(2)
        blocks.append(kind)
        if kind == 0:
            bits.align()
            length, complement = bits.read(16), bits.read(16)
            assert length ^ complement == 0xffff
            bits.offset += length * 8
            assert bits.offset <= len(raw) * 8
            output += length
        elif kind in (1, 2):
            if kind == 1:
                literals = huffman([8] * 144 + [9] * 112 + [7] * 24 + [8] * 8)
                distances = huffman([5] * 32)
            else:
                literal_count, distance_count, code_count = bits.read(5) + 257, bits.read(5) + 1, bits.read(4) + 4
                order = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]
                code_lengths = [0] * 19
                for n in range(code_count):
                    code_lengths[order[n]] = bits.read(3)
                codes, lengths = huffman(code_lengths), []
                while len(lengths) < literal_count + distance_count:
                    item = symbol(bits, codes)
                    if item < 16:
                        lengths.append(item)
                    elif item == 16:
                        lengths.extend([lengths[-1]] * (bits.read(2) + 3))
                    elif item == 17:
                        lengths.extend([0] * (bits.read(3) + 3))
                    else:
                        lengths.extend([0] * (bits.read(7) + 11))
                assert len(lengths) == literal_count + distance_count
                literals, distances = huffman(lengths[:literal_count]), huffman(lengths[literal_count:])
            while True:
                item = symbol(bits, literals)
                if item < 256:
                    output += 1
                elif item == 256:
                    break
                else:
                    n = item - 257
                    length = length_base[n] + bits.read(length_extra[n])
                    n = symbol(bits, distances)
                    distance = distance_base[n] + bits.read(distance_extra[n])
                    assert distance <= output
                    overlaps += int(distance < length)
                    output += length
        else:
            raise ValueError('Reserved independent DEFLATE block')
        if final:
            break
    assert zlib.decompress(raw, -15).__len__() == output
    return {'block_types': blocks, 'expanded_bytes': output, 'overlapping_copies': overlaps}


@dataclasses.dataclass
class Case:
    name: str
    method: str
    expected: str = 'complete'
    artifact: bytes | None = None
    manifest: dict | None = None
    payload: bytes = b''
    setup: object = None
    compression: dict | None = None
    expected_reason: str | None = None
    enforce_empty: bool = False


def tar_checksum(data, offset=0):
    result = bytearray(data)
    result[offset + 148:offset + 156] = b'        '
    checksum = sum(result[offset:offset + 512])
    result[offset + 148:offset + 156] = f'{checksum:06o}\0 '.encode()
    return bytes(result)


def changed(data, offset, replacement, checksum=False):
    result = data[:offset] + replacement + data[offset + len(replacement):]
    return tar_checksum(result) if checksum else result


def default_lock(artifact, name='pkg', version='1.0.0'):
    return {'name': ROOT['name'], 'version': ROOT['version'], 'lockfileVersion': 3, 'requires': True,
            'packages': {'': copy.deepcopy(ROOT), 'node_modules/pkg': {
                'name': name, 'version': version, 'resolved': f'https://registry.npmjs.org/{name}/-/{name}-{version}.tgz',
                'integrity': sri(artifact), 'hasInstallScript': True}}}


def write_case(folder, case):
    folder.mkdir()
    evidence = folder / 'evidence'
    (evidence / 'artifacts').mkdir(parents=True)
    (evidence / 'project').mkdir()
    artifact = case.artifact if case.artifact is not None else zipped(tar_for(case.manifest, case.payload))
    lock = default_lock(artifact)
    root = copy.deepcopy(ROOT)
    index = {'schema_version': 1, 'lock_sha256': '', 'packages': [
        {'path': '', 'project_manifest': 'project/package.json'},
        {'path': 'node_modules/pkg', 'artifact': 'artifacts/pkg.tgz'}]}
    (evidence / 'artifacts/pkg.tgz').write_bytes(artifact)
    if case.setup:
        case.setup(folder, lock, root, index)
    raw_lock = encoded(lock)
    index['lock_sha256'] = sha256(raw_lock)
    if case.name == 'index_wrong_lock_hash':
        index['lock_sha256'] = '0' * 64
    (folder / 'package-lock.json').write_bytes(raw_lock)
    (folder / 'package.json').write_bytes(encoded(root))
    if not (evidence / 'project/package.json').exists():
        (evidence / 'project/package.json').write_bytes(encoded(root))
    (evidence / 'index.json').write_bytes(encoded(index))
    if case.name == 'index_duplicate_json_key':
        raw = (evidence / 'index.json').read_bytes()
        (evidence / 'index.json').write_bytes(raw.replace(b'"schema_version":1', b'"schema_version":1,"schema_version":1'))
    if case.name == 'index_malformed_json':
        (evidence / 'index.json').write_bytes(b'{')
    if case.name == 'source_manifest_invalid_json':
        (evidence / 'project/package.json').write_bytes(b'{')
    if case.name == 'missing_evidence_index':
        (evidence / 'index.json').unlink()
    return folder


def inventory(folder):
    result = {}
    for path in sorted(folder.rglob('*')):
        relative = str(path.relative_to(folder))
        stat = path.lstat()
        if path.is_symlink():
            result[relative] = {'kind': 'symlink', 'target': os.readlink(path), 'mode': stat.st_mode}
        elif path.is_file():
            result[relative] = {'kind': 'file', 'sha256': sha256(path.read_bytes()), 'bytes': stat.st_size, 'mode': stat.st_mode}
        elif path.is_dir():
            result[relative] = {'kind': 'directory', 'mode': stat.st_mode}
        else:
            result[relative] = {'kind': 'special', 'mode': stat.st_mode}
    return result


def report_status(report):
    return report.get('status') if isinstance(report, dict) else None


def policy_status(report):
    policy = report.get('policy') if isinstance(report, dict) else None
    if isinstance(policy, dict):
        return policy.get('outcome') or policy.get('decision') or policy.get('status') or policy.get('result')
    return policy


def fingerprint_rows(value):
    result = []
    if isinstance(value, dict):
        fingerprint = value.get('approval_fingerprint', value.get('fingerprint'))
        path = value.get('path', value.get('package_path', value.get('identity')))
        if isinstance(fingerprint, str) and isinstance(path, str):
            result.append((path, fingerprint))
        for item in value.values():
            result.extend(fingerprint_rows(item))
    elif isinstance(value, list):
        for item in value:
            result.extend(fingerprint_rows(item))
    return sorted(set(result))


def run(binary, folder, case, logs, timeout, approvals=None):
    command = [str(binary), 'audit', '--lock', str(folder / 'package-lock.json'),
               '--manifest', str(folder / 'package.json'), '--evidence', str(folder / 'evidence/index.json'), '--json']
    if case.enforce_empty:
        approvals = folder / 'approvals.json'
        approvals.write_bytes(encoded({'schema_version': 1, 'approvals': []}))
    if approvals is not None:
        command += ['--enforce', '--approvals', str(approvals)]
    before = inventory(folder)
    result = {'case': case.name, 'expected': case.expected, 'method': case.method, 'command': command,
              'compression': case.compression, 'input_tree_sha256': sha256(encoded(before))}
    try:
        process = subprocess.run(command, cwd=folder, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout)
        result['exit'] = process.returncode
        stdout, stderr = process.stdout, process.stderr
        try:
            report = json.loads(stdout)
            result['status'] = report_status(report)
            result['policy'] = policy_status(report)
        except (json.JSONDecodeError, UnicodeDecodeError):
            report = None
            result['json_error'] = True
    except subprocess.TimeoutExpired as error:
        stdout, stderr = error.stdout or b'', error.stderr or b''
        report = None
        result['timeout'] = True
    after = inventory(folder)
    result['inputs_unchanged'] = before == after
    if before != after:
        result['changed_paths'] = [p for p in sorted(set(before) | set(after)) if before.get(p) != after.get(p)]
    (logs / f'{case.name}.stdout').write_bytes(stdout)
    (logs / f'{case.name}.stderr').write_bytes(stderr)
    result['stdout_sha256'], result['stderr_sha256'] = sha256(stdout), sha256(stderr)
    if case.expected == 'complete':
        classified = result.get('exit') == 0 and result.get('status') == 'complete'
    elif case.expected == 'incomplete':
        classified = result.get('exit') == 2 and result.get('status') == 'incomplete'
    elif case.expected == 'allowed':
        classified = result.get('exit') == 0 and result.get('status') == 'complete' and result.get('policy') == 'allowed'
    elif case.expected == 'blocked':
        classified = result.get('exit') == 1 and result.get('status') == 'complete' and result.get('policy') == 'blocked'
    else:
        classified = False
    result['reason_proven'] = case.expected_reason is None or case.expected_reason in json.dumps(report)
    if case.expected_reason:
        result['expected_reason'] = case.expected_reason
    result['diagnostics'] = [entry.get('reason') for entry in (report or {}).get('execution_evidence', []) if entry.get('reason')]
    if isinstance(report, dict) and 'error' in report:
        result['diagnostics'].append(report['error'])
    result['evidence_consistent'] = all(row.get('state') == 'qualified' or row.get('approval_fingerprint') is None for row in (report or {}).get('execution_evidence', []))
    if result.get('status') == 'incomplete':
        result['evidence_consistent'] &= result.get('policy') in (None, 'incomplete')
    result['positive_facts_match'] = verify_positive_facts(folder, report) if case.expected in ('complete', 'allowed', 'blocked') and result.get('status') == 'complete' else True
    result['pass'] = classified and result['inputs_unchanged'] and report is not None and result['reason_proven'] and result['positive_facts_match'] and result['evidence_consistent']
    return result, report


def verify_positive_facts(folder, report):
    evidence = {item['path']: item for item in report.get('execution_evidence', [])}
    if 'node_modules/pkg' not in evidence or '' not in evidence:
        return False
    compressed = (folder / 'evidence/artifacts/pkg.tgz').read_bytes()
    with tarfile.open(fileobj=io.BytesIO(compressed), mode='r:gz') as source:
        raw_manifest = source.extractfile('package/package.json').read()
        names = [member.name for member in source]
        binding = 'package/binding.gyp' in names
        binding_raw = source.extractfile('package/binding.gyp').read() if binding else None
    manifest = json.loads(raw_manifest)
    package = evidence['node_modules/pkg']
    facts = package.get('facts') or {}
    graph_package = next((item for item in report.get('packages', []) if item.get('path') == 'node_modules/pkg'), {})
    root = evidence['']
    root_facts = root.get('facts') or {}
    expected_lifecycle = {key: sha256(value.encode()) for key, value in manifest.get('scripts', {}).items() if key in ('preinstall', 'install', 'postinstall')}
    root_raw = (folder / 'evidence/project/package.json').read_bytes()
    root_manifest = json.loads(root_raw)
    root_binding = folder / 'evidence/project/binding.gyp'
    root_binding_raw = root_binding.read_bytes() if root_binding.is_file() else None
    root_lifecycle = {key: sha256(value.encode()) for key, value in root_manifest.get('scripts', {}).items() if key in ('preinstall', 'install', 'postinstall', 'prepublish', 'preprepare', 'prepare', 'postprepare')}
    install_candidate = bool(facts.get('implicit_node_gyp')) or any(manifest.get('scripts', {}).get(key) for key in ('preinstall', 'install', 'postinstall'))
    checks = [package.get('state') == 'qualified', facts.get('kind') == 'artifact',
              package.get('candidate') is bool(install_candidate),
              'install-lifecycle-script (body not inspected)' not in graph_package.get('capabilities', []),
              facts.get('artifact_sha512') == hashlib.sha512(compressed).hexdigest(),
              facts.get('manifest_sha256') == sha256(raw_manifest),
              facts.get('name') == manifest['name'], facts.get('version') == manifest['version'],
              facts.get('lifecycle') == expected_lifecycle, facts.get('binding_gyp') is binding,
              facts.get('binding_gyp_sha256') == (sha256(binding_raw) if binding else None),
              facts.get('gypfile_false') is (manifest.get('gypfile') is False),
              facts.get('implicit_node_gyp') is (binding and manifest.get('gypfile') is not False and not any(manifest.get('scripts', {}).get(key) for key in ('preinstall', 'install'))),
              root.get('state') == 'qualified', root_facts.get('kind') == 'source_project',
              root_facts.get('manifest_sha256') == sha256(root_raw), root_facts.get('lifecycle') == root_lifecycle,
              root_facts.get('name') == root_manifest['name'], root_facts.get('version') == root_manifest['version'],
              root_facts.get('binding_gyp') is (root_binding_raw is not None),
              root_facts.get('binding_gyp_sha256') == (sha256(root_binding_raw) if root_binding_raw is not None else None)]
    return all(checks)


def cases():
    baseline = tar_for()
    compressed = zipped(baseline)
    result = [Case('valid_default', 'Python tarfile USTAR and zlib default.', artifact=compressed)]
    for name, level, strategy, wanted in [('stored', 0, zlib.Z_DEFAULT_STRATEGY, 0), ('fixed', 6, zlib.Z_FIXED, 1), ('dynamic', 6, zlib.Z_DEFAULT_STRATEGY, 2)]:
        tar = tar_for(payload=(b'abcde0123456789' * 4096))
        raw = raw_compress(tar, level, strategy)
        facts = deflate_facts(raw)
        assert wanted in facts['block_types'], (name, facts)
        if name != 'stored':
            assert facts['overlapping_copies'] > 0
        result.append(Case(f'valid_{name}_deflate', f'zlib level {level}, strategy {strategy}, asserted block type {wanted}.', artifact=gzip_raw(tar, raw), compression=facts))
    raw = stored_blocks(baseline)
    facts = deflate_facts(raw)
    assert len(facts['block_types']) > 1 and set(facts['block_types']) == {0}
    result.append(Case('valid_multiblock_stored', 'Independently framed stored DEFLATE blocks with 997-byte boundaries.', artifact=gzip_raw(baseline, raw), compression=facts))
    compressor = zlib.compressobj(6, zlib.DEFLATED, -15)
    raw = compressor.compress(baseline[:4093]) + compressor.flush(zlib.Z_SYNC_FLUSH) + compressor.compress(baseline[4093:]) + compressor.flush()
    facts = deflate_facts(raw)
    assert len(facts['block_types']) > 1
    result.append(Case('valid_multiblock_mixed', 'zlib stream split by Z_SYNC_FLUSH across a tar block.', artifact=gzip_raw(baseline, raw), compression=facts))
    result.append(Case('valid_ustar_prefix', 'tarfile generates a USTAR prefix for a long regular filename.', artifact=zipped(tar_for(extra=[regular('package/' + 'subdir/' * 16 + 'blob.bin', b'x')]))))
    result.append(Case('valid_directory', 'Regular USTAR directory plus package manifest.', artifact=zipped(archive([('package/', b'', tarfile.DIRTYPE, ''), regular('package/package.json', encoded(MANIFEST))]))))
    result.append(Case('valid_nul_regular_type', 'USTAR NUL regular-file type.', artifact=zipped(archive([('package/package.json', encoded(MANIFEST), tarfile.AREGTYPE, '')]))))
    rng = random.Random(SEED)
    sizes = [0, 1, 2, 3, 4, 7, 8, 31, 32, 255, 256, 257, 258, 259, 511, 512, 513, 32767, 32768, 32769, 65535]
    strategies = [zlib.Z_DEFAULT_STRATEGY, zlib.Z_FIXED, zlib.Z_HUFFMAN_ONLY, zlib.Z_RLE]
    seen_sizes = set()
    for number in range(100):
        size, level, strategy = rng.choice(sizes), rng.choice([0, 1, 6, 9]), rng.choice(strategies)
        seen_sizes.add(size)
        mode = rng.randrange(3)
        if mode == 0:
            payload = rng.randbytes(size)
        elif mode == 1:
            pattern = rng.randbytes(rng.randint(1, 64))
            payload = (pattern * (size // len(pattern) + 1))[:size]
        else:
            payload = bytes(rng.randrange(65, 71) for _ in range(size))
        tar = tar_for(payload=payload)
        raw = raw_compress(tar, level, strategy)
        facts = deflate_facts(raw)
        result.append(Case(f'valid_seeded_{number:03d}', f'Seed {SEED}, case {number}, payload {size}, mode {mode}, zlib level {level}, strategy {strategy}.', artifact=gzip_raw(tar, raw), compression=facts))
    assert seen_sizes == set(sizes), 'The seeded valid corpus must cover every declared length boundary'
    negative_gzip = {
        'gzip_bad_magic': b'\0' + compressed[1:],
        'gzip_unknown_method': changed(compressed, 2, b'\x09'),
        'gzip_reserved_flags': changed(compressed, 3, b'\x20'),
        'gzip_crc_mismatch': changed(compressed, len(compressed) - 8, bytes([compressed[-8] ^ 1])),
        'gzip_isize_mismatch': changed(compressed, len(compressed) - 4, bytes([compressed[-4] ^ 1])),
        'gzip_header_truncated': compressed[:9],
        'gzip_body_truncated': compressed[:len(compressed) // 2],
        'gzip_trailer_truncated': compressed[:-1],
        'gzip_second_member': compressed + compressed,
        'gzip_trailing_junk': compressed + b'trailing',
        'gzip_trailing_zero': compressed + b'\0',
        'gzip_unterminated_filename': changed(compressed[:10], 3, b'\x08') + b'unterminated',
        'gzip_truncated_extra': changed(compressed[:10], 3, b'\x04') + b'\xff\xffshort',
        'gzip_bad_header_crc': changed(compressed[:10], 3, b'\x02') + b'\0\0' + compressed[10:],
        'deflate_reserved_block': gzip_raw(baseline, b'\x07'),
        'deflate_stored_bad_nlen': gzip_raw(baseline, b'\x01\x01\x00\x00\x00x'),
        'deflate_dynamic_truncated': gzip_raw(baseline, b'\x05\x00'),
        'deflate_empty_payload': gzip_raw(baseline, b''),
    }
    result.extend(Case(name, 'Targeted gzip/DEFLATE invalid input. Outer lock SRI matches the mutated bytes.', 'incomplete', artifact=data) for name, data in negative_gzip.items())
    manifest_end = 512 + (len(encoded(MANIFEST)) + 511) // 512 * 512
    data_end = manifest_end + 512
    malformed_tar = {
        'tar_bad_checksum': changed(baseline, 0, b'x'),
        'tar_invalid_size_octal': changed(baseline, 124, b'0000000000x\0', True),
        'tar_size_overflow': changed(baseline, 124, b'77777777777\0', True),
        'tar_base256_size': changed(baseline, 124, b'\x80' + b'\0' * 10 + b'\x01', True),
        'tar_payload_truncated': baseline[:512 + len(encoded(MANIFEST)) - 1],
        'tar_header_truncated': baseline[:511],
        'tar_missing_terminator': baseline[:data_end],
        'tar_one_terminator': baseline[:data_end + 512],
        'tar_trailing_nonzero': baseline + b'x' + b'\0' * 511,
        'tar_nonzero_after_terminator': changed(baseline, data_end + 1024, b'x'),
        'tar_wrong_magic': changed(baseline, 257, b'zzzzz\0', True),
        'tar_wrong_version': changed(baseline, 263, b'99', True),
    }
    result.extend(Case(name, 'Targeted invalid USTAR with a valid gzip CRC/ISIZE and recomputed outer SRI.', 'incomplete', artifact=zipped(data)) for name, data in malformed_tar.items())
    for name, path in [('duplicate', 'package/package.json'), ('dot_alias', 'package/./package.json'), ('slash_alias', 'package//package.json'), ('dot_prefix_alias', './package/package.json'), ('parent_alias', 'package/x/../package.json'), ('absolute', '/package/package.json'), ('parent_escape', '../package/package.json'), ('backslash', 'package\\package.json')]:
        result.append(Case(f'tar_path_{name}', 'Extra manifest entry tests strict path and duplicate interpretation.', 'incomplete', artifact=zipped(archive([regular('package/package.json', encoded(MANIFEST)), regular(path, encoded(MANIFEST))]))))
    for name, kind in [('symlink', tarfile.SYMTYPE), ('hardlink', tarfile.LNKTYPE), ('fifo', tarfile.FIFOTYPE), ('character', tarfile.CHRTYPE), ('block', tarfile.BLKTYPE), ('pax', tarfile.XHDTYPE), ('pax_global', tarfile.XGLTYPE), ('gnu_longname', tarfile.GNUTYPE_LONGNAME), ('gnu_longlink', tarfile.GNUTYPE_LONGLINK), ('unknown_type', b'Z')]:
        result.append(Case(f'tar_type_{name}', f'Unsupported archive entry type {kind!r} with a valid manifest also present.', 'incomplete', artifact=zipped(archive([regular('package/package.json', encoded(MANIFEST)), ('package/unsupported', b'', kind, 'package/package.json')]))))
    result.append(Case('tar_duplicate_prefix_path', 'Duplicate manifest encoded once in name and once with USTAR prefix.', 'incomplete', artifact=zipped(archive([regular('package/package.json', encoded(MANIFEST))])[:manifest_end] + changed(archive([regular('package.json', encoded(MANIFEST))]), 345, b'package', True))))
    result.append(Case('tar_missing_manifest', 'Archive has no package/package.json.', 'incomplete', artifact=zipped(archive([regular('package/README', b'x')]))))
    result.append(Case('manifest_invalid_json', 'Archive manifest is not valid JSON.', 'incomplete', artifact=zipped(archive([regular('package/package.json', b'{')]))))
    for field, value in [('name', 'substitute'), ('version', '9.9.9')]:
        manifest = {**MANIFEST, field: value}
        result.append(Case(f'manifest_wrong_{field}', f'Archive manifest {field} disagrees with locked instance despite matching SRI.', 'incomplete', manifest=manifest))
    for number in range(40):
        mutated = bytearray(compressed)
        offset = len(mutated) - 8 + rng.randrange(8)
        mutated[offset] ^= 1 << rng.randrange(8)
        result.append(Case(f'mutation_trailer_{number:03d}', f'Seed {SEED}, bounded trailer mutation {number}, byte {offset}. Recomputed SRI reaches gzip validation.', 'incomplete', artifact=bytes(mutated)))
    for number in range(32):
        mutated = bytearray(compressed)
        offset = rng.randrange(10, len(mutated) - 8)
        mutated[offset] ^= 1 << rng.randrange(8)
        try:
            decoded = gzip.decompress(mutated)
            assert decoded == baseline, 'A mutation with valid CRC changed decoded content and needs separate classification'
            expected, oracle = 'complete', 'Python gzip accepted unchanged tar bytes'
        except (OSError, EOFError, zlib.error) as error:
            expected, oracle = 'incomplete', type(error).__name__
        result.append(Case(f'mutation_deflate_{number:03d}', f'Seed {SEED}, bounded interior DEFLATE mutation {number}, byte {offset}. Independent gzip outcome {oracle}. Outer SRI recomputed.', expected, artifact=bytes(mutated)))
    def index_mutator(callback):
        return lambda folder, lock, root, index: callback(index)
    index_cases = {
        'index_unknown_verified_flag': lambda i: i.update(verified=True),
        'index_package_verified_flag': lambda i: i['packages'][1].update(verified=True),
        'index_duplicate_instance': lambda i: i['packages'].append(copy.deepcopy(i['packages'][1])),
        'index_unknown_instance': lambda i: i['packages'][1].update(path='node_modules/unknown'),
        'index_missing_dependency': lambda i: i['packages'].pop(),
        'index_missing_root': lambda i: i['packages'].pop(0),
        'index_registry_manifest_only': lambda i: i['packages'][1].update({'project_manifest': 'project/package.json', 'artifact': None}),
        'index_both_locators': lambda i: i['packages'][1].update(project_manifest='project/package.json'),
        'index_absolute_locator': lambda i: i['packages'][1].update(artifact='/etc/passwd'),
        'index_parent_locator': lambda i: i['packages'][1].update(artifact='../outside.tgz'),
        'index_dot_locator': lambda i: i['packages'][1].update(artifact='./artifacts/pkg.tgz'),
        'index_backslash_locator': lambda i: i['packages'][1].update(artifact='artifacts\\pkg.tgz'),
        'index_wrong_schema': lambda i: i.update(schema_version=2),
        'index_packages_wrong_type': lambda i: i.update(packages={}),
        'index_wrong_lock_hash': lambda i: None,
        'index_duplicate_json_key': lambda i: None,
        'index_malformed_json': lambda i: None,
        'source_manifest_invalid_json': lambda i: None,
        'missing_evidence_index': lambda i: None,
    }
    result.extend(Case(name, 'Malformed or incomplete locator bundle. Lock hash otherwise recomputed.', 'incomplete', setup=index_mutator(callback)) for name, callback in index_cases.items())
    def symlink_file(folder, lock, root, index):
        artifact = folder / 'evidence/artifacts/pkg.tgz'
        data = artifact.read_bytes()
        artifact.unlink()
        (folder / 'outside.tgz').write_bytes(data)
        artifact.symlink_to('../../outside.tgz')
    def symlink_directory(folder, lock, root, index):
        artifacts = folder / 'evidence/artifacts'
        artifacts.rename(folder / 'outside-artifacts')
        artifacts.symlink_to('../outside-artifacts')
    def source_symlink(folder, lock, root, index):
        (folder / 'outside-source.json').write_bytes(encoded(root))
        (folder / 'evidence/project/package.json').symlink_to('../../outside-source.json')
    def internal_symlink(folder, lock, root, index):
        artifact = folder / 'evidence/artifacts/pkg.tgz'
        artifact.rename(folder / 'evidence/artifacts/real.tgz')
        artifact.symlink_to('real.tgz')
    result += [Case('index_source_symlink_escape', 'Source manifest locator resolves through a symlink outside bundle.', 'incomplete', setup=source_symlink), Case('index_internal_symlink', 'Artifact locator resolves through a symlink even though its target remains inside bundle.', 'incomplete', setup=internal_symlink)]
    result += [Case('index_symlink_file_escape', 'Artifact locator resolves through a file symlink outside bundle.', 'incomplete', setup=symlink_file), Case('index_symlink_directory_escape', 'Artifact locator resolves through a directory symlink outside bundle.', 'incomplete', setup=symlink_directory)]
    def lock_edit(callback):
        return lambda folder, lock, root, index: callback(lock)
    result += [Case('sri_missing_padding', 'SHA512 SRI is noncanonical base64 without padding.', 'incomplete', setup=lock_edit(lambda lock: lock['packages']['node_modules/pkg'].update(integrity=sri(compressed).rstrip('=')))),
               Case('sri_multiple_digests', 'SRI contains two tokens outside the single SHA512 profile.', 'incomplete', setup=lock_edit(lambda lock: lock['packages']['node_modules/pkg'].update(integrity=sri(compressed) + ' ' + sri(compressed)))),
               Case('sri_sha256_only', 'The lock provides SHA256 rather than the qualified SHA512 profile.', 'incomplete', setup=lock_edit(lambda lock: lock['packages']['node_modules/pkg'].update(integrity='sha256-' + base64.b64encode(hashlib.sha256(compressed).digest()).decode()))),
               Case('sri_wrong_digest', 'SRI does not match the original compressed bytes.', 'incomplete', setup=lock_edit(lambda lock: lock['packages']['node_modules/pkg'].update(integrity='sha512-' + base64.b64encode(bytes(64)).decode()))),
               Case('marker_false_conflict', 'Explicit false install marker conflicts with an install lifecycle body.', 'incomplete', setup=lock_edit(lambda lock: lock['packages']['node_modules/pkg'].update(hasInstallScript=False)))]
    return result


def portable_profile_cases():
    plain = {'name': 'pkg', 'version': '1.0.0'}
    def no_marker(folder, lock, root, index):
        lock['packages']['node_modules/pkg'].pop('hasInstallScript')
    native = [regular('package/package.json', encoded(plain)), regular('package/binding.gyp', b'{}\n')]
    result = [Case('stale_positive_install_marker', 'A verified script-free archive resolves a stale positive npm install hint.', 'allowed', manifest=plain, enforce_empty=True),
              Case('portable_canonical_native_blocked', 'Canonical binding.gyp without a lock marker requires approval under the npm implicit build rule.', 'blocked', artifact=zipped(archive(native)), setup=no_marker, enforce_empty=True)]
    result.append(Case('portable_native_case_alias', 'A regular Binding.gyp aliases npm native evidence on case-insensitive filesystems. Matching SRI cannot authorize it.', 'incomplete', artifact=zipped(archive([native[0], regular('package/Binding.gyp', b'{}\n')])), setup=no_marker, expected_reason='noncanonical lifecycle evidence tar path', enforce_empty=True))
    result.append(Case('portable_manifest_case_overwrite', 'A later Package.json can overwrite the inspected script-free package.json on a case-insensitive filesystem.', 'incomplete', artifact=zipped(archive([regular('package/package.json', encoded(plain)), regular('package/Package.json', encoded(MANIFEST))])), setup=no_marker, expected_reason='noncanonical lifecycle evidence tar path', enforce_empty=True))
    paths = [
        ('ancestor_file_first', [regular('package/Output', b'x'), regular('package/output/data', b'x')], 'tar file conflicts with a parent directory'),
        ('ancestor_child_first', [regular('package/Output/data', b'x'), regular('package/output', b'x')], 'tar file conflicts with a parent directory'),
        ('duplicate_casefold', [regular('package/README', b'x'), regular('package/readme', b'y')], 'duplicate case-folded tar path'),
        ('trailing_dot', [regular('package/binding.gyp.', b'{}\n')], 'unsupported nonportable tar path'),
        ('trailing_space', [regular('package/binding.gyp ', b'{}\n')], 'unsupported nonportable tar path'),
        ('unicode_filename', [regular('package/caf\u00e9.txt', b'x')], 'unsupported nonportable tar path'),
    ]
    for name, extra, reason in paths:
        result.append(Case('portable_' + name, 'Original SRI-bound USTAR archive has an unsupported portable-path interpretation. It must fail at the path check.', 'incomplete', artifact=zipped(archive([regular('package/package.json', encoded(plain)), *extra])), setup=no_marker, expected_reason=reason, enforce_empty=True))
    prepare = {**plain, 'scripts': {'prepare': 'node prepare-never-execute.js'}}
    for name, source in [('git_prepare', 'git+https://github.com/example/package.git#' + 'a' * 40), ('hosted_https_git', 'https://github.com/example/package.git'), ('file_directory', 'file:../local-package')]:
        def source_setup(folder, lock, root, index, resolved=source):
            no_marker(folder, lock, root, index)
            lock['packages']['node_modules/pkg']['resolved'] = resolved
        result.append(Case('unsupported_source_' + name, 'The locked source has npm Git or directory semantics. A supplied matching SHA512 archive does not bind its preparation behavior.', 'incomplete', manifest=prepare, setup=source_setup, expected_reason='artifact source requires a supported direct HTTP(S) archive URL', enforce_empty=True))
    return result


def resource_cases():
    result = []
    large_manifest = {**MANIFEST, 'padding': 'x' * MIB}
    result.append(Case('limit_archive_manifest', 'Archived package.json exceeds the declared 1MiB limit.', 'incomplete', manifest=large_manifest, expected_reason='package manifest exceeds 1 MiB'))
    def large_source(folder, lock, root, index):
        root['padding'] = 'x' * MIB
    result.append(Case('limit_source_manifest', 'Source package.json exceeds the declared 1MiB limit.', 'incomplete', setup=large_source, expected_reason='input exceeds 1048576 bytes'))
    entries = [regular('package/package.json', encoded(MANIFEST))] + [regular(f'package/f{n:05d}', b'') for n in range(10000)]
    result.append(Case('limit_entry_count', 'Archive contains 10001 entries, exceeding the declared 10000 limit.', 'incomplete', artifact=zipped(archive(entries)), expected_reason='tar exceeds 10000 entries'))
    baseline = tar_for()
    tar = baseline + bytes(64 * MIB - len(baseline))
    compressed = gzip_raw(tar, stored_blocks(tar, 65535))
    assert len(tar) == 64 * MIB and len(compressed) > 64 * MIB
    result.append(Case('limit_compressed', 'Expanded tar is exactly 64MiB. Stored block overhead makes compressed bytes exceed 64MiB.', 'incomplete', artifact=compressed, expected_reason='input exceeds 67108864 bytes'))
    tar += bytes(512)
    result.append(Case('limit_expanded', 'Expanded tar exceeds 64MiB while compressed bytes remain below the compressed limit.', 'incomplete', artifact=zipped(tar), expected_reason='expanded artifact exceeds 64 MiB'))
    return result


def packed_case():
    base = Path(__file__).resolve().parents[1] / '.audit/v4.1'
    artifact = (base / 'npm-packed.tgz').read_bytes()
    expectations = json.loads((base / 'npm-packed.expected.json').read_bytes())
    def setup(folder, lock, root, index):
        package = lock['packages']['node_modules/pkg']
        package['name'] = expectations['manifest']['name']
        root['dependencies']['pkg'] = 'npm:' + package['name'] + '@1.0.0'
        lock['packages']['']['dependencies']['pkg'] = root['dependencies']['pkg']
    return Case('valid_actual_npm_packed', 'Original milestone1 npm-packed artifact with alias path and independently recorded manifest expectations.', artifact=artifact, setup=setup)


def approval_controls(binary, output, logs, timeout, results, reports):
    baseline_name = 'valid_default'
    rows = fingerprint_rows(reports.get(baseline_name))
    if not rows:
        results.append({'case': 'approval_fingerprint_discovery', 'pass': False, 'method': 'Read candidate fingerprints from complete audit JSON.', 'error': 'No path/fingerprint records found. This is a coverage gap, not a pass.'})
        return
    approvals = {'schema_version': 1, 'approvals': [{'path': path, 'fingerprint': fingerprint} for path, fingerprint in rows]}
    cases_to_run = [Case('approval_bound_allowed', 'Approval entries copied from the independently generated baseline report.', 'allowed'),
                    Case('approval_empty_blocked', 'An explicit empty approval file cannot authorize an execution candidate.', 'blocked'),
                    Case('approval_legacy_coordinate_blocked', 'Coordinate-only metadata cannot authorize stronger evidence policy.', 'blocked'),
                    Case('approval_source_invalidated', 'Same path/name/version with a different locked source must invalidate baseline approval.', 'blocked', setup=lambda f, l, r, i: l['packages']['node_modules/pkg'].update(resolved='https://registry.npmjs.org/pkg/-/changed.tgz')),
                    Case('approval_integrity_invalidated', 'Same manifest with independently recompressed artifact bytes must invalidate baseline approval.', 'blocked', artifact=zipped(tar_for(), level=0)),
                    Case('approval_lifecycle_invalidated', 'Same path/name/version with changed install body must invalidate baseline approval.', 'blocked', manifest={**MANIFEST, 'scripts': {'install': 'echo changed-body'}}),
                    Case('approval_missing_evidence_incomplete', 'Missing required package evidence takes precedence over approval.', 'incomplete', setup=lambda f, l, r, i: i['packages'].pop()),
                    Case('approval_conflict_incomplete', 'Explicit false marker conflicts with install evidence even under a previously approved coordinate.', 'incomplete', setup=lambda f, l, r, i: l['packages']['node_modules/pkg'].update(hasInstallScript=False))]
    for case in cases_to_run:
        folder = write_case(output / 'cases' / case.name, case)
        approval_file = folder / 'approvals.json'
        supplied = {'schema_version': 1, 'approvals': []} if case.name in ('approval_empty_blocked', 'approval_legacy_coordinate_blocked') else approvals
        approval_file.write_bytes(encoded(supplied))
        if case.name == 'approval_legacy_coordinate_blocked':
            (folder / 'tau-gate.toml').write_text('whitelist = ["pkg@1.0.0"]\n')
        result, report = run(binary, folder, case, logs, timeout, approval_file)
        results.append(result)
        reports[case.name] = report


def root_approval_controls(binary, output, logs, timeout, results):
    def source_setup(changed_body=False, native=False, changed_native=False):
        def setup(folder, lock, root, index):
            if native:
                body = b'changed build bytes\n' if changed_native else b'original build bytes\n'
                (folder / 'evidence/project/binding.gyp').write_bytes(body)
            else:
                root['scripts'] = {'postinstall': 'echo changed-root' if changed_body else 'echo original-root'}
        return setup
    for label, native in [('lifecycle', False), ('binding_gyp', True)]:
        baseline = Case(f'approval_root_{label}_reference', 'Qualify a root source execution candidate independently before approval.', setup=source_setup(native=native))
        folder = write_case(output / 'cases' / baseline.name, baseline)
        result, report = run(binary, folder, baseline, logs, timeout)
        results.append(result)
        rows = fingerprint_rows(report)
        if not rows:
            results.append({'case': f'approval_root_{label}_discovery', 'pass': False, 'error': 'No root approval fingerprint. Coverage gap.'})
            continue
        approval = {'schema_version': 1, 'approvals': [{'path': path, 'fingerprint': fingerprint} for path, fingerprint in rows]}
        for changed_source, expected in [(False, 'allowed'), (True, 'blocked')]:
            case = Case(f'approval_root_{label}_' + ('invalidated' if changed_source else 'allowed'), 'Root manifest or adjacent binding.gyp change must invalidate its exact bound approval.', expected, setup=source_setup(changed_body=changed_source, native=native, changed_native=changed_source))
            folder = write_case(output / 'cases' / case.name, case)
            approval_file = folder / 'approvals.json'
            approval_file.write_bytes(encoded(approval))
            result, unused = run(binary, folder, case, logs, timeout, approval_file)
            results.append(result)


def reference_controls(binary, bundle, output, logs, timeout, results):
    if not bundle.is_dir():
        results.append({'case': 'm1_reference_missing', 'pass': False, 'error': 'Required M1 bundle is absent. This is a coverage gap, not a pass.'})
        return
    oracle = json.loads((bundle / 'oracle.json').read_bytes())
    working_directory = output / 'reference-cwd'
    working_directory.mkdir()
    scans = [('m1_reference_oracle', bundle / 'project/package-lock.json', bundle / 'evidence/index.json', 'complete')]
    scans += [('m1_negative_' + path.name, path / 'package-lock.json', path / 'index.json', 'incomplete') for path in sorted((bundle / 'negative-controls').iterdir()) if path.is_dir()]
    for name, lock, index, expected in scans:
        before = inventory(bundle)
        output_paths_before = {str(path.relative_to(working_directory)) for path in working_directory.rglob('*')}
        command = [str(binary), 'audit', '--lock', str(lock), '--manifest', str(bundle / 'project/package.json'), '--evidence', str(index), '--json']
        result = {'case': name, 'method': 'Direct CLI comparison with sealed M1 npm installation oracle and original negative locator bundles.', 'expected': expected, 'command': command, 'input_tree_sha256': sha256(encoded(before))}
        report = None
        try:
            process = subprocess.run(command, cwd=working_directory, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout)
            stdout, stderr = process.stdout, process.stderr
            result['exit'] = process.returncode
            report = json.loads(stdout)
            result['status'] = report_status(report)
        except subprocess.TimeoutExpired as error:
            stdout, stderr = error.stdout or b'', error.stderr or b''
            result['timeout'] = True
        except (json.JSONDecodeError, UnicodeDecodeError):
            result['json_error'] = True
        result['inputs_unchanged'] = before == inventory(bundle)
        output_paths_after = {str(path.relative_to(working_directory)) for path in working_directory.rglob('*')}
        result['no_new_working_directory_files'] = output_paths_before == output_paths_after
        result['new_working_directory_paths'] = sorted(output_paths_after - output_paths_before)
        result['removed_working_directory_paths'] = sorted(output_paths_before - output_paths_after)
        result['stdout_sha256'], result['stderr_sha256'] = sha256(stdout), sha256(stderr)
        (logs / f'{name}.stdout').write_bytes(stdout)
        (logs / f'{name}.stderr').write_bytes(stderr)
        result['pass'] = result.get('exit') == (0 if expected == 'complete' else 2) and result.get('status') == expected and result['inputs_unchanged'] and result['no_new_working_directory_files']
        if name == 'm1_reference_oracle' and report is not None:
            evidence = {row['path']: row for row in report.get('execution_evidence', [])}
            comparisons = []
            fields = ('manifest_sha256', 'name', 'version', 'lifecycle', 'binding_gyp', 'binding_gyp_sha256', 'gypfile_false', 'implicit_node_gyp')
            for category, kind in [('packages', 'artifact'), ('source_projects', 'source_project')]:
                for expected_row in oracle[category]:
                    actual = evidence.get(expected_row['path'], {})
                    facts = actual.get('facts') or {}
                    checks = {field: expected_row[field] == facts.get(field) for field in fields}
                    checks['state'] = actual.get('state') == 'qualified'
                    checks['kind'] = facts.get('kind') == kind
                    checks['fingerprint'] = isinstance(actual.get('approval_fingerprint'), str) and len(actual['approval_fingerprint']) == 64
                    if kind == 'artifact':
                        checks['locked_install_marker'] = actual.get('locked_install_marker') == expected_row['locked_install_marker']
                        checks['artifact_sha512'] = facts.get('artifact_sha512') == base64.b64decode(expected_row['integrity'].removeprefix('sha512-')).hex()
                    comparisons.append({'path': expected_row['path'], 'checks': checks, 'pass': all(checks.values())})
            for expected_row in oracle['workspace_links']:
                actual = evidence.get(expected_row['path'], {})
                facts = actual.get('facts') or {}
                checks = {'state': actual.get('state') == 'qualified', 'not_separate_candidate': actual.get('candidate') is False, 'workspace_target': facts.get('workspace_target') == expected_row['target']}
                comparisons.append({'path': expected_row['path'], 'checks': checks, 'pass': all(checks.values())})
            candidate_paths = [row.get('package', {}).get('path') for row in report.get('execution_candidates', [])]
            expected_candidates = sorted([row['path'] for row in oracle['packages'] + oracle['source_projects'] if row['lifecycle'] or row['implicit_node_gyp']])
            result['candidate_paths'] = candidate_paths
            result['expected_candidate_paths'] = expected_candidates
            result['oracle_comparisons'] = comparisons
            result['pass'] &= all(row['pass'] for row in comparisons) and sorted(candidate_paths) == expected_candidates and len(candidate_paths) == 8
        if isinstance(report, dict):
            result['diagnostics'] = [row.get('reason') for row in report.get('execution_evidence', []) if row.get('reason')]
            if 'error' in report:
                result['diagnostics'].append(report['error'])
        intended_reasons = {
            'm1_negative_corrupt_archive': 'matching canonical SHA512 integrity',
            'm1_negative_duplicate_instance': 'duplicate or unknown index instance',
            'm1_negative_false_install_marker': 'hasInstallScript contradicts',
            'm1_negative_missing_evidence': 'missing locator',
            'm1_negative_same_identity_substitution': 'matching canonical SHA512 integrity',
            'm1_negative_supplied_manifest_substitution': 'cannot establish registry artifact binding',
            'm1_negative_unknown_assertion': 'one supported evidence source',
            'm1_negative_unsafe_locator': 'unsafe relative path',
            'm1_negative_wrong_lock_hash': 'index lock hash mismatch',
            'm1_negative_wrong_version': 'manifest version does not match lock instance',
            'm1_negative_wrong_workspace_identity': 'manifest name does not match lock instance',
        }
        if name in intended_reasons:
            result['expected_reason'] = intended_reasons[name]
            result['intended_reason_proven'] = intended_reasons[name] in json.dumps(report)
            result['pass'] &= result['intended_reason_proven']
        results.append(result)
        if not result['pass']:
            print(json.dumps({'case': name, 'pass': False, 'exit': result.get('exit'), 'status': result.get('status')}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--timeout', type=float, default=10.0)
    parser.add_argument('--generate-only', action='store_true')
    parser.add_argument('--reference-bundle', type=Path, required=True)
    arguments = parser.parse_args()
    binary, output = arguments.binary.resolve(), arguments.output.resolve()
    initial_verifier_hash = sha256(Path(__file__).read_bytes())
    initial_binary_hash = sha256(binary.read_bytes()) if binary.is_file() else None
    if initial_binary_hash is None and not arguments.generate_only:
        parser.error('--binary must name an existing executable')
    if output.exists() and any(output.iterdir()):
        parser.error('--output must name an empty directory')
    output.mkdir(parents=True, exist_ok=True)
    (output / 'cases').mkdir()
    logs = output / 'commands'
    logs.mkdir()
    selected = cases() + portable_profile_cases() + [packed_case()] + resource_cases()
    results, reports = [], {}
    for case in selected:
        folder = write_case(output / 'cases' / case.name, case)
        if arguments.generate_only:
            results.append({'case': case.name, 'expected': case.expected, 'method': case.method, 'compression': case.compression, 'input_tree_sha256': sha256(encoded(inventory(folder))), 'executed': False})
        else:
            result, report = run(binary, folder, case, logs, arguments.timeout)
            results.append(result)
            reports[case.name] = report
            if not result['pass']:
                print(json.dumps({'case': case.name, 'exit': result.get('exit'), 'status': result.get('status'), 'policy': result.get('policy'), 'timeout': result.get('timeout'), 'inputs_unchanged': result.get('inputs_unchanged')}), flush=True)
    if not arguments.generate_only:
        approval_controls(binary, output, logs, arguments.timeout, results, reports)
        root_approval_controls(binary, output, logs, arguments.timeout, results)
        reference_controls(binary, arguments.reference_bundle.resolve(), output, logs, arguments.timeout, results)
    try:
        commit = subprocess.run(['git', '-C', str(binary.parent), 'rev-parse', 'HEAD'], capture_output=True, text=True, check=True).stdout.strip()
    except subprocess.CalledProcessError:
        commit = None
    final_binary_hash = sha256(binary.read_bytes()) if binary.is_file() else None
    if not arguments.generate_only and initial_binary_hash != final_binary_hash:
        results.append({'case': 'binary_immutable_during_run', 'pass': False, 'error': 'Binary bytes changed during this run.'})
    final_verifier_hash = sha256(Path(__file__).read_bytes())
    if initial_verifier_hash != final_verifier_hash:
        results.append({'case': 'verifier_immutable_during_run', 'pass': False, 'error': 'Verifier source changed during this run.'})
    receipt = {'schema_version': 1, 'status': 'generated-not-executed' if arguments.generate_only else ('pass' if all(r['pass'] for r in results) else 'fail'),
               'seed': SEED, 'source_starting_commit': STARTING_COMMIT, 'binary': str(binary), 'binary_sha256': final_binary_hash, 'binary_sha256_before': initial_binary_hash, 'verifier_sha256': final_verifier_hash, 'verifier_sha256_before': initial_verifier_hash,
               'binary_source_commit_if_accessible': commit, 'python': sys.version, 'zlib': zlib.ZLIB_VERSION,
               'method': 'Independent Python stdlib generation, exact CLI invocation per case, strict exit/status classification, timeout, and before/after complete input-tree hashes. Every malformed artifact has a recomputed lock SRI and index lock hash unless SRI or index binding is the named negative control.',
               'coverage_limits': ['Synthetic and one npm-packed USTAR/gzip artifacts. This is not exhaustive DEFLATE or tar fuzzing.', 'No package manager, network, lifecycle scripts, benchmark, publisher authentication, or artifact safety claims.', 'Expected profile limits are 64MiB compressed/expanded, 1MiB manifest, and 10000 tar entries.', 'A JSON parse failure, unknown outcome, crash, timeout, or input write fails its case. Missing fingerprint discovery fails the approval slice.'],
               'counts': {'total': len(results), 'complete': sum(r.get('expected') == 'complete' for r in results), 'incomplete': sum(r.get('expected') == 'incomplete' for r in results), 'pass': sum(r.get('pass', False) for r in results), 'fail': sum(not r.get('pass', False) for r in results) if not arguments.generate_only else 0},
               'cases': results}
    (output / 'receipt.json').write_bytes(json.dumps(receipt, indent=2, sort_keys=True).encode() + b'\n')
    print(json.dumps({'status': receipt['status'], 'counts': receipt['counts'], 'receipt': str(output / 'receipt.json')}, sort_keys=True))
    return int(receipt['status'] == 'fail')


if __name__ == '__main__':
    raise SystemExit(main())
