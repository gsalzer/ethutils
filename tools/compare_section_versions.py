#!/usr/bin/env python3
"""Compare code-section counts from current ethutils and ethutils 0.1.3.

The historic decomposition below is vendored from commit b2c349a so this script
can be copied into and run from a current ethutils checkout without installing a
second version of the package.
"""

from __future__ import annotations

import argparse
import io
import multiprocessing
import os
from pathlib import Path
import re
import sys

import cbor2
import ethutils


# Vendored from ethutils/metadata.py and ethutils/section.py at b2c349a.
_PUSHPOP = (b'(\x60.|\x61..|\x62...|\x63.{4}|\x64.{5}|\x65.{6}|\x66.{7}|'
            b'\x67.{8}|\x68.{9}|\x69.{10}|\x6a.{11}|\x6b.{12}|\x6c.{13}|'
            b'\x6d.{14}|\x6e.{15}|\x6f.{16}|\x70.{17}|\x71.{18}|\x72.{19}|'
            b'\x73.{20}|\x74.{21}|\x75.{22}|\x76.{23}|\x77.{24}|\x78.{25}|'
            b'\x79.{26}|\x7a.{27}|\\\x7b.{28}|\\\x7c.{29}|\\\x7d.{30}|'
            b'\x7e.{31}|\x7f.{32})\x50')
_CONTRACT_OLD = b'\x60\x60\x60\x40(\x81\x90|\x90\x81)?\x52'
_CONTRACT_NEW = b'\x60\x80\x60\x40(\x81\x90|\x90\x81)?\x52'
_CONTRACT_NEW2 = b'(?<=\x56[\x00\xfe])\x60.\x60\x40'
_LIBRARY_CHECK = b'\x73.{20}\x30\x14'
_SOLIDITY_START = (b'(' + _PUSHPOP + b'|' + _LIBRARY_CHECK + b')?('
                   + _CONTRACT_OLD + b'|' + _CONTRACT_NEW + b')|' + _CONTRACT_NEW2)
_DEPLOYMENT1 = b'(?<=\x80\x60.\x60\x00\x39\x60\x00\xf3\x00)(\x60\x00\x35|\x36)'
_DEPLOYMENT2 = b'(?<=\x80\x61..\x60\x00\x39\x60\x00\xf3\x00)(\x60\x00\x35|\x36)'
_DEPLOYMENT3 = b'(?<=\x80\x61..\x60\x00\x39\x61..\x56)\x60\x00\x61..\x53'
_DEPLOYMENT4 = b'(?<=\x56)\x60\x00\x35'
_DEPLOYMENT5 = b'(?<=\x80\x60.\x60\x00\x39\x60\x00\xf3)\x60'
_CODE_START = re.compile(
    _SOLIDITY_START + b'|' + _DEPLOYMENT1 + b'|' + _DEPLOYMENT2 + b'|'
    + _DEPLOYMENT3 + b'|' + _DEPLOYMENT4 + b'|' + _DEPLOYMENT5,
    re.DOTALL,
)
_META_ANY = ('bzzr0', 'bzzr1', 'ipfs', 'solc')
_META_ALL = ('bzzr0', 'bzzr1', 'ipfs', 'solc', 'experimental')
_META_MAX = 5
_TERMINATORS = (b'\x00', b'\x56', b'\xf3', b'\xfe', b'\xff')


def _historic_metadata(code: bytes):
    """Return Solidity metadata records using the 0.1.3 implementation."""
    length, offset, records = len(code), 0, []
    while offset < length:
        if not 0xA1 <= code[offset] <= 0xA0 + _META_MAX:
            offset += 1
            continue
        try:
            stream = io.BytesIO(code[offset:])
            decoded = cbor2.load(stream)
            rest = stream.read()
            metadata_length = int.from_bytes(rest[:2], 'big')
        except Exception:
            offset += 1
            continue
        if (metadata_length == length - len(rest) - offset
                and any(key in decoded for key in _META_ANY)):
            if not all(key in _META_ALL for key in decoded):
                raise ValueError(f'unknown key in {decoded}')
            records.append((offset, metadata_length + 2, decoded))
            offset += metadata_length + 2
        else:
            offset += 1
    return records


def _historic_split(code: bytes):
    """Split at detected code starts exactly as ethutils 0.1.3 did."""
    cursor, parts = 0, []
    for match in _CODE_START.finditer(code):
        parts.append(code[cursor:match.start()])
        cursor = match.start()
    if cursor < len(code):
        parts.append(code[cursor:])
    return parts


def historic_decompose(code: bytes):
    """Return the decomposition produced by ethutils 0.1.3 at b2c349a."""
    code_start, sections, initial_kind = 0, [], 'code'
    for metadata_start, metadata_length, _ in _historic_metadata(code):
        parts = _historic_split(code[code_start:metadata_start])
        if parts:
            if parts[0]:
                sections.append((initial_kind, parts[0]))
            sections.extend(('code', part) for part in parts[1:])
        code_start = metadata_start + metadata_length
        sections.append(('meta', code[metadata_start:code_start]))
        initial_kind = 'data'

    parts = _historic_split(code[code_start:])
    if parts:
        if parts[0]:
            sections.append((initial_kind, parts[0]))
        sections.extend(('code', part) for part in parts[1:])

    sanitized, pending = [], b''
    for kind, content in sections:
        if not content:
            continue
        if kind == 'code':
            pending += content
            if pending[-1:] not in _TERMINATORS:
                continue
        if pending:
            sanitized.append(('code', pending))
            pending = b''
        if kind != 'code':
            sanitized.append((kind, content))
    if pending:
        sanitized.append(('code', pending))
    assert len(code) == sum(len(content) for _, content in sanitized)
    return sanitized


def _compare_file(path_text: str):
    path = Path(path_text)
    try:
        code = ethutils.parse_hex(path.read_text())
        old_count = sum(kind == 'code' for kind, _ in historic_decompose(code))
        new_count = sum(kind == 'code' for kind, _ in ethutils.decompose(code))
    except Exception as error:
        return 'ERROR', path_text, None, None, f'{type(error).__name__}: {error}'
    status = 'EQUAL' if new_count == old_count else 'NEW_MORE' if new_count > old_count else 'NEW_LESS'
    return status, path_text, old_count, new_count, None


def _default_processes() -> int:
    return max(1, os.cpu_count() or 1)


def _arguments(argv=None):
    parser = argparse.ArgumentParser(
        description='Compare current ethutils code-section counts with version 0.1.3.',
    )
    parser.add_argument('folder', type=Path, help='folder recursively searched for *.hex files')
    parser.add_argument('-j', '--processes', type=int, default=_default_processes(),
                        help='worker processes (default: all available processors)')
    parser.add_argument('--log-directory', type=Path, default=Path.cwd(),
                        help='directory for new_more.txt and new_less.txt (default: current directory)')
    args = parser.parse_args(argv)
    if not args.folder.is_dir():
        parser.error(f'not a directory: {args.folder}')
    if args.processes < 1:
        parser.error('--processes must be at least 1')
    if not args.log_directory.is_dir():
        parser.error(f'not a directory: {args.log_directory}')
    return args


def main(argv=None) -> int:
    args = _arguments(argv)
    paths = (str(path) for path in args.folder.rglob('*.hex') if path.is_file())
    counts = {'total': 0, 'equal': 0, 'new_more': 0, 'new_less': 0, 'errors': 0}
    log_paths = {status: args.log_directory / f'{status.lower()}.txt'
                 for status in ('NEW_MORE', 'NEW_LESS')}
    with (multiprocessing.Pool(args.processes) as pool,
          log_paths['NEW_MORE'].open('w', encoding='utf-8') as more_log,
          log_paths['NEW_LESS'].open('w', encoding='utf-8') as less_log):
        logs = {'NEW_MORE': more_log, 'NEW_LESS': less_log}
        for status, path, old_count, new_count, error in pool.imap_unordered(
                _compare_file, paths, chunksize=16):
            counts['total'] += 1
            if status == 'EQUAL':
                counts['equal'] += 1
            elif status == 'ERROR':
                counts['errors'] += 1
                print(f'ERROR\t{path}\t{error}', flush=True)
            else:
                counts[status.lower()] += 1
                print(path, file=logs[status], flush=True)
                print(f'{status}\t{path}\told={old_count}\tnew={new_count}', flush=True)
    print('SUMMARY\t' + '\t'.join(f'{key}={value}' for key, value in counts.items()))
    print('LOGS\t' + '\t'.join(f'{status.lower()}={path}'
                                for status, path in log_paths.items()))
    return 1 if counts['errors'] else 0


if __name__ == '__main__':
    sys.exit(main())
