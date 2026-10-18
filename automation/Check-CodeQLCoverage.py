#!/usr/bin/env python3
"""Reject missing translation units and crashed C/C++ extractor invocations."""
import csv
import pathlib
import subprocess
import sys


def check(rows, sources):
    files = {}
    failures = []
    for row in rows:
        path = row['path']
        if path in files:
            raise ValueError(f'Duplicate extraction row: {path}')
        counts = {key: int(row[key]) for key in ('completed', 'crashed', 'parsed', 'functions')}
        if any(value < 0 for value in counts.values()):
            raise ValueError(f'Invalid extraction counts: {path}')
        files[path] = counts
        if counts['crashed']:
            failures.append(f"{path}: {counts['crashed']} crashed extractor invocations")
    if not sources:
        raise ValueError('No tracked C/C++ sources found')
    for source in sorted(sources):
        # sphlib deliberately includes this implementation template from its
        # hash translation unit. It must contain extracted functions, but must
        # not be compiled as an independent C source.
        if source == 'Algorithms/extended/sphlib/md_helper.c':
            if not files.get(source, {}).get('functions'):
                failures.append(f'{source}: no extracted functions from included implementation')
            continue
        if not files.get(source, {}).get('completed') or not files.get(source, {}).get('parsed'):
            failures.append(f'{source}: no completed source extraction')
    # The JSON adapter is shared by both network entry points and is header-only.
    json_header = 'OpenHashTab/OpenHashTab/json.h'
    if not files.get(json_header, {}).get('functions'):
        failures.append(f'{json_header}: no extracted functions')
    for failure in failures:
        print(failure)
    print(f'CodeQL coverage: {len(sources)} tracked sources; {len(failures)} failures.')
    return 1 if failures else 0


def main(filename):
    root = pathlib.Path(__file__).resolve().parents[1]
    output = subprocess.check_output(
        ['git', 'ls-files', '-z', '--', '*.c', '*.cpp', '*.cc', '*.cxx'], cwd=root)
    sources = set(output.decode('utf-8').rstrip('\0').split('\0')) - {''}
    with pathlib.Path(filename).open(encoding='utf-8-sig', newline='') as stream:
        return check(csv.DictReader(stream), sources)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1]))
