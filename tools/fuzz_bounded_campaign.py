#!/usr/bin/env python3
"""Run twelve five-second ASan windows, preserving the evolving corpus and failures."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil

import qualification as q

WINDOWS = 12
SECONDS = 5
RSS = 512 * 1024 * 1024


def inventory(folder):
    return {str(path.relative_to(folder)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(folder.rglob('*')) if path.is_file()}


def run(binary, seeds, output):
    binary, seeds, output = binary.resolve(), seeds.resolve(), output.resolve()
    if output.exists() and any(output.iterdir()):
        raise ValueError('output must be empty; previous campaigns are retained')
    output.mkdir(parents=True, exist_ok=True)
    initial = inventory(seeds)
    if not initial:
        raise ValueError('seed directory must contain files')
    shutil.copytree(seeds, output / 'corpus')
    binary_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
    receipt = {'schema_version': 1, 'profile': 'bounded-process operational campaign',
        'continuous_process_profile': 'not qualified by this campaign',
        'binary': str(binary), 'binary_sha256': binary_hash, 'seed_sha256': initial,
        'helper_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'limits': {'windows': WINDOWS, 'window_seconds': SECONDS, 'scheduled_fuzzer_seconds': WINDOWS * SECONDS,
                   'max_len_bytes': 65536, 'input_timeout_seconds': 2, 'rss_limit_bytes': RSS},
        'ASAN_OPTIONS': 'detect_odr_violation=0',
        'asan_provenance': 'Matches cargo-fuzz0.13.2 effective default; quarantine and all other defaults unchanged',
        'limitations': ['Fresh processes reset allocator retention, mutation history and unsaved dictionaries',
                       'Saved corpus is retained and replayed; temporal behavior across windows is not tested',
                       'Scheduled fuzzer time includes each process startup and seed replay'],
        'windows': [], 'status': 'incomplete'}
    for number in range(1, WINDOWS + 1):
        folder = output / f'window-{number:02d}'
        artifacts = folder / 'artifacts'
        artifacts.mkdir(parents=True)
        before = inventory(output / 'corpus')
        argv = ['/usr/bin/env', 'ASAN_OPTIONS=detect_odr_violation=0', '/usr/bin/nice', '-n', '10', str(binary),
                '-max_len=65536', '-timeout=2', '-rss_limit_mb=512', f'-max_total_time={SECONDS}',
                f'-seed={20261108 + number}', '-print_final_stats=1', f'-artifact_prefix={artifacts}/',
                str(output / 'corpus')]
        process = q.run_bounded(argv, folder, 20)
        stderr = (folder / 'stderr.bin').read_text(errors='replace')
        stats = {key: int(value) for key, value in re.findall(r'stat::(\S+):\s*(\d+)', stderr)}
        init = re.search(r'#(\d+)\s+INITED\b', stderr)
        initial_units = int(init[1]) if init else None
        units = stats.get('number_of_executed_units', 0)
        passed = (process['termination'] == 'exited' and process['exit_code'] == 0
                  and process['peak_rss_bytes'] is not None and process['peak_rss_bytes'] <= RSS
                  and initial_units is not None and units > initial_units
                  and not re.search(r'(?:ERROR: (?:AddressSanitizer|libFuzzer)|SUMMARY: .*Sanitizer)', stderr))
        row = {'number': number, 'process': process, 'stats': stats, 'initialization_units': initial_units,
               'mutation_units_after_initialization': units - initial_units if initial_units is not None else None,
               'corpus_before_sha256': before, 'corpus_after_sha256': inventory(output / 'corpus'),
               'artifact_sha256': inventory(artifacts), 'passed': passed}
        receipt['windows'].append(row)
        immutable = (hashlib.sha256(binary.read_bytes()).hexdigest() == binary_hash and inventory(seeds) == initial)
        receipt['binary_and_seeds_unchanged'] = immutable
        receipt['status'] = 'running' if passed and immutable else 'failed'
        q.save(output / 'receipt.json', receipt)
        print(json.dumps({'window': number, 'passed': passed, 'executed_units': units,
                          'peak_rss_bytes': process['peak_rss_bytes']}), flush=True)
        if not passed or not immutable:
            return receipt
    receipt['status'] = 'passed_bounded_windows'
    receipt['total_executed_units'] = sum(row['stats']['number_of_executed_units'] for row in receipt['windows'])
    receipt['total_mutation_units_after_initialization'] = sum(row['mutation_units_after_initialization'] for row in receipt['windows'])
    q.save(output / 'receipt.json', receipt)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--seeds', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    receipt = run(args.binary, args.seeds, args.output)
    return 0 if receipt['status'] == 'passed_bounded_windows' else 1


if __name__ == '__main__':
    raise SystemExit(main())
