"""Lossless labeled chunks built from overlapping section records."""
from pathlib import Path
import unittest
from unittest.mock import patch

import cbor2
import ethutils
from ethutils import opcodes as op, sectioning
from tests.helpers import Assembly


class DecomposeTests(unittest.TestCase):
    def assert_partition(self, code, result):
        self.assertEqual(b''.join(data for tag, data in result), code)
        self.assertTrue(all(tag in {'code', 'data', 'meta', ''} and data for tag, data in result))

    def from_sections(self, code, records):
        with patch.object(sectioning, 'section', return_value=records) as scan, \
             patch.object(sectioning.Analyzer, 'run', side_effect=AssertionError('extra analysis')):
            result = ethutils.decompose(code)
        scan.assert_called_once_with(code)
        self.assert_partition(code, result)
        return result

    def test_nested_code_and_metadata_leave_outer_bytes_unclassified(self):
        code = b'abcdefghijkl'
        records = [dict(kind='data', start=1, end=11),
                   dict(kind='code', start=3, end=6),
                   dict(kind='meta', start=8, end=10)]
        expected = [('', b'a'), ('', b'bc'), ('code', b'def'), ('', b'gh'),
                    ('meta', b'ij'), ('', b'k'), ('', b'l')]
        for order in (records, records[::-1]):
            self.assertEqual(self.from_sections(code, order), expected)

    def test_overlapping_decomposed_data_ranges_leave_unclassified_bytes(self):
        records = [dict(kind='data', start=1, end=6),
                   dict(kind='data', start=4, end=9),
                   dict(kind='code', start=3, end=7)]
        self.assertEqual(self.from_sections(b'abcdefghij', records),
                         [('', b'a'), ('', b'bc'), ('code', b'd'), ('code', b'ef'),
                          ('code', b'g'), ('', b'hi'), ('', b'j')])

    def test_code_precedes_data_across_partial_overlap(self):
        records = [dict(kind='code', start=0, end=5), dict(kind='data', start=3, end=8)]
        self.assertEqual(self.from_sections(b'abcdefgh', records),
                         [('code', b'abc'), ('code', b'de'), ('', b'fgh')])

    def test_data_touching_code_and_metadata_remains_data(self):
        records = [dict(kind='code', start=0, end=2),
                   dict(kind='data', start=2, end=6),
                   dict(kind='meta', start=6, end=8)]
        self.assertEqual(self.from_sections(b'abcdefgh', records),
                         [('code', b'ab'), ('data', b'cdef'), ('meta', b'gh')])

    def test_overlapping_intact_data_sections_keep_their_label(self):
        records = [dict(kind='data', start=1, end=5), dict(kind='data', start=3, end=7)]
        self.assertEqual(self.from_sections(b'abcdefgh', records),
                         [('', b'a'), ('data', b'bc'), ('data', b'de'), ('data', b'fg'), ('', b'h')])

    def test_intact_inner_data_section_survives_decomposed_outer_section(self):
        records = [dict(kind='data', start=0, end=10),
                   dict(kind='code', start=2, end=4),
                   dict(kind='data', start=6, end=8)]
        self.assertEqual(self.from_sections(b'abcdefghij', records),
                         [('', b'ab'), ('code', b'cd'), ('', b'ef'), ('data', b'gh'), ('', b'ij')])

    def test_partial_metadata_overlap_decomposes_data_section(self):
        records = [dict(kind='data', start=0, end=5), dict(kind='meta', start=3, end=8)]
        self.assertEqual(self.from_sections(b'abcdefgh', records),
                         [('', b'abc'), ('meta', b'de'), ('meta', b'fgh')])

    def test_returned_range_alone_keeps_data_intact(self):
        records = [dict(kind='data', start=0, end=6),
                   dict(kind='returned', start=2, end=4, origin=0, via=0, copy=0)]
        self.assertEqual(self.from_sections(b'abcdef', records), [('data', b'abcdef')])

    def test_adjacent_and_nested_code_boundaries_remain_separate(self):
        records = [dict(kind='code', start=0, end=4),
                   dict(kind='code', start=1, end=3),
                   dict(kind='code', start=4, end=6)]
        self.assertEqual(self.from_sections(b'abcdef', records),
                         [('code', b'a'), ('code', b'bc'), ('code', b'd'), ('code', b'ef')])

    def test_adjacent_data_and_metadata_sections_remain_separate(self):
        for kind in ('data', 'meta'):
            with self.subTest(kind=kind):
                records = [dict(kind=kind, start=0, end=2), dict(kind=kind, start=2, end=4)]
                self.assertEqual(self.from_sections(b'abcd', records), [(kind, b'ab'), (kind, b'cd')])

    def test_adjacent_code_from_different_origins_remains_separate(self):
        records = [dict(kind='code', start=0, end=2, origin=0),
                   dict(kind='code', start=2, end=4, origin=2)]
        self.assertEqual(self.from_sections(b'abcd', records), [('code', b'ab'), ('code', b'cd')])

    def test_touching_decomposed_data_sections_preserve_unclassified_boundary(self):
        records = [dict(kind='data', start=0, end=4), dict(kind='data', start=4, end=8),
                   dict(kind='code', start=0, end=2), dict(kind='meta', start=6, end=8)]
        self.assertEqual(self.from_sections(b'abcdefgh', records),
                         [('code', b'ab'), ('', b'cd'), ('', b'ef'), ('meta', b'gh')])

    def test_returned_records_supply_no_label_or_boundary(self):
        records = [dict(kind='returned', start=1, end=4, origin=0, via=0, copy=0)]
        self.assertEqual(self.from_sections(b'abcdef', records), [('', b'abcdef')])

    def test_all_unclassified_and_empty_input(self):
        self.assertEqual(self.from_sections(b'abcdef', []), [('', b'abcdef')])
        self.assertEqual(ethutils.decompose(b''), [])

    def test_actual_sections_and_public_export(self):
        encoded = cbor2.dumps({'solc': b'\x00\x08\x1e'})
        metadata = encoded + len(encoded).to_bytes(2, 'big')
        payload = op.STOP + b'\xaa\xbb' + metadata + b'\xcc'
        assembly = Assembly().push(len(payload)).target('runtime').emit(op.PUSH0, op.CODECOPY)
        assembly.push(len(payload)).emit(op.PUSH0, op.RETURN)
        entry = len(assembly.code)
        assembly.labels['runtime'] = entry
        assembly.code.extend(payload)
        code = assembly.build()
        self.assertIs(ethutils.decompose, sectioning.decompose)
        with patch.object(sectioning, 'section', wraps=sectioning.section) as scan:
            result = ethutils.decompose(code)
        scan.assert_called_once_with(code)
        self.assertEqual(result, [('code', code[:entry]), ('code', op.STOP), ('', b'\xaa\xbb'),
                                  ('meta', metadata), ('', b'\xcc')])
        self.assert_partition(code, result)

    def test_actual_unclassified_gap(self):
        code = b'\x00\xaa\xbb'
        self.assertEqual(ethutils.decompose(code), [('code', b'\x00'), ('', b'\xaa\xbb')])

    def test_compiler_fixtures_preserve_bytes_and_section_labels(self):
        fixtures = Path(ethutils.__file__).resolve().parent.parent / 'tests' / 'fixtures'
        for path in sorted(fixtures.glob('*.hex')):
            with self.subTest(fixture=path.name):
                code = bytes.fromhex(path.read_text())
                sections = sectioning.section(code)
                result = ethutils.decompose(code)
                self.assert_partition(code, result)
                expected_boundaries = {0, len(code)}
                for part in sections:
                    if part['kind'] in {'code', 'data', 'meta'}:
                        expected_boundaries.update((part['start'], part['end']))
                actual_boundaries = {0}
                end = 0
                for _, data in result:
                    end += len(data)
                    actual_boundaries.add(end)
                self.assertEqual(actual_boundaries, expected_boundaries)
                occupied = {pc for part in sections if part['kind'] in {'code', 'meta'}
                            for pc in range(part['start'], part['end'])}
                sections = [part for part in sections if part['kind'] != 'data'
                            or occupied.isdisjoint(range(part['start'], part['end']))]
                # Verify each label against whole eligible sections at every byte.
                offset = 0
                for tag, data in result:
                    for pc in range(offset, offset + len(data)):
                        covering = {part['kind'] for part in sections if part['start'] <= pc < part['end']}
                        expected = next((kind for kind in ('meta', 'code', 'data') if kind in covering), '')
                        self.assertEqual(tag, expected, pc)
                    offset += len(data)

    def test_section_errors_propagate(self):
        with self.assertRaises(TypeError):
            ethutils.decompose('6000')
        encoded = cbor2.dumps({'solc': b'', 'unknown': 0})
        with self.assertRaises(ValueError):
            ethutils.decompose(encoded + len(encoded).to_bytes(2, 'big'))


if __name__ == '__main__':
    unittest.main()
