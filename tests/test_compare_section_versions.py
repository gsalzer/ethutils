"""Regression tests for the bulk historic/current section comparison script."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import ethutils
from tools import compare_section_versions as comparison
from tests.helpers import hex_fixture


class CompareSectionVersionsTests(unittest.TestCase):
    def test_vendored_historic_decomposition_on_contract_fixtures(self):
        for name in ('0xa39394d3447c1dbd386b92b4d1fcc22ca85eae67-src.hex',
                     '0xa39394d3447c1dbd386b92b4d1fcc22ca85eae67.hex'):
            with self.subTest(fixture=name):
                code = hex_fixture(name)
                old_count = sum(kind == 'code'
                                for kind, _ in comparison.historic_decompose(code))
                new_count = sum(kind == 'code' for kind, _ in ethutils.decompose(code))
                self.assertEqual((old_count, new_count), (3, 6))

    def test_file_comparison_statuses_and_hex_prefix(self):
        with tempfile.TemporaryDirectory() as directory:
            equal = Path(directory) / 'equal.hex'
            equal.write_text('0x00\n')
            self.assertEqual(comparison._compare_file(str(equal))[:4],
                             ('EQUAL', str(equal), 1, 1))

            invalid = Path(directory) / 'invalid.hex'
            invalid.write_text('not hexadecimal')
            status, path, old_count, new_count, error = comparison._compare_file(str(invalid))
            self.assertEqual((status, path, old_count, new_count),
                             ('ERROR', str(invalid), None, None))
            self.assertIn('ValueError', error)

    def test_default_process_count_uses_all_available_processors(self):
        with patch.object(comparison.os, 'cpu_count', return_value=12):
            self.assertEqual(comparison._default_processes(), 12)
        with patch.object(comparison.os, 'cpu_count', return_value=1):
            self.assertEqual(comparison._default_processes(), 1)
        with patch.object(comparison.os, 'cpu_count', return_value=None):
            self.assertEqual(comparison._default_processes(), 1)

    def test_main_logs_more_and_less_filenames(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            samples = root / 'samples'
            logs = root / 'logs'
            samples.mkdir();logs.mkdir()
            (samples / 'equal.hex').write_text('00')
            results = [
                ('NEW_MORE', str(samples / 'more.hex'), 1, 2, None),
                ('NEW_LESS', str(samples / 'less.hex'), 2, 1, None),
                ('EQUAL', str(samples / 'equal.hex'), 1, 1, None),
            ]

            class Pool:
                def __init__(self, processes): self.processes = processes
                def __enter__(self): return self
                def __exit__(self, *args): pass
                def imap_unordered(self, function, paths, chunksize): return iter(results)

            with patch.object(comparison.multiprocessing, 'Pool', Pool):
                self.assertEqual(comparison.main([
                    '--processes', '2', '--log-directory', str(logs), str(samples)]), 0)
            self.assertEqual((logs / 'new_more.txt').read_text(),
                             str(samples / 'more.hex') + '\n')
            self.assertEqual((logs / 'new_less.txt').read_text(),
                             str(samples / 'less.hex') + '\n')
if __name__ == '__main__':
    unittest.main()
