"""Runtime extraction from creation-bytecode section records."""
import unittest
from unittest.mock import patch

import cbor2
import ethutils
from ethutils import opcodes as op, sectioning
from tests.helpers import Assembly


def return_copy(assembly, label, size):
    assembly.push(size).target(label).emit(op.PUSH0, op.CODECOPY)
    assembly.push(size).emit(op.PUSH0, op.RETURN)


def append_payload(assembly, label, payload):
    assembly.labels[label] = len(assembly.code)
    assembly.code.extend(payload)


def creation(payload, *, patch_byte=False):
    assembly = Assembly()
    assembly.push(len(payload)).target('runtime').emit(op.PUSH0, op.CODECOPY)
    if patch_byte:
        assembly.push(42).emit(op.PUSH0, op.MSTORE8)
    assembly.push(len(payload)).emit(op.PUSH0, op.RETURN)
    append_payload(assembly, 'runtime', payload)
    return assembly.build()


def conditional_creation(first, second, *, shared_source=False):
    assembly = Assembly().emit(op.CALLVALUE).target('other').emit(op.JUMPI)
    return_copy(assembly, 'first', len(first))
    assembly.label('other')
    return_copy(assembly, 'first' if shared_source else 'second', len(second))
    append_payload(assembly, 'first', first)
    if not shared_source:
        append_payload(assembly, 'second', second)
    return assembly.build()


class RuntimeTests(unittest.TestCase):
    def test_public_export_and_single_sectioning_pass(self):
        payload = bytes.fromhex('6003565b00')
        code = creation(payload)
        self.assertIs(ethutils.runtime, sectioning.runtime)
        with patch.object(sectioning, 'section', wraps=sectioning.section) as scan:
            self.assertEqual(ethutils.runtime(code), payload)
        scan.assert_called_once_with(code)

    def test_preserves_runtime_data_and_metadata_and_excludes_creation_arguments(self):
        encoded = cbor2.dumps({'solc': b'\x00\x08\x1e'})
        payload = bytes.fromhex('60006000fd') + b'\xaa\xbb' + encoded + len(encoded).to_bytes(2, 'big')
        code = creation(payload) + b'\x11' * 32
        self.assertEqual(ethutils.runtime(code), payload)

    def test_identical_bytes_returned_by_different_instructions(self):
        for shared in (False, True):
            with self.subTest(shared_source=shared):
                code = conditional_creation(op.STOP, op.STOP, shared_source=shared)
                returned = [part for part in sectioning.section(code)
                            if part['kind'] == 'returned' and part['origin'] == 0]
                self.assertEqual(len(returned), 2)
                self.assertEqual(len({part['via'] for part in returned}), 2)
                self.assertEqual(ethutils.runtime(code), op.STOP)

    def test_distinct_returned_programs_are_ambiguous(self):
        code = conditional_creation(op.STOP, op.PUSH0 + op.STOP)
        self.assertIsNone(ethutils.runtime(code))

    def test_unrecognized_return_does_not_hide_ambiguity(self):
        code = conditional_creation(op.STOP, b'\xaa')
        sections = sectioning.section(code)
        returned = [part for part in sections if part['kind'] == 'returned' and part['origin'] == 0]
        self.assertEqual(len(returned), 2)
        self.assertIsNone(ethutils.runtime(code))

    def test_nested_program_returns_do_not_replace_outer_runtime(self):
        payload = creation(op.STOP)
        code = creation(payload)
        self.assertTrue(any(part['kind'] == 'returned' and part['origin'] != 0
                            for part in sectioning.section(code)))
        self.assertEqual(ethutils.runtime(code), payload)

    def test_missing_returns_or_unrecognized_runtime_entry(self):
        for code in (b'', op.STOP, creation(b'\xaa'), creation(b'')):
            with self.subTest(code=code.hex()):
                self.assertIsNone(ethutils.runtime(code))

    def test_internal_code_alone_does_not_establish_runtime_entry(self):
        payload = bytes.fromhex('3460ff573460fe575f5ffd5b5f5ffd')
        code = creation(payload)
        sections = sectioning.section(code)
        returned = next(part for part in sections if part['kind'] == 'returned' and part['origin'] == 0)
        self.assertTrue(any(part['kind'] == 'code' and part['origin'] == returned['start']
                            for part in sections))
        self.assertFalse(any(part['kind'] == 'code' and part['start'] == part['origin'] == returned['start']
                             for part in sections))
        self.assertIsNone(ethutils.runtime(code))

    def test_patched_return_has_insufficient_evidence(self):
        self.assertIsNone(ethutils.runtime(creation(op.STOP, patch_byte=True)))

    def test_requires_creation_entry_at_zero(self):
        sections = [dict(kind='returned', start=2, end=3, origin=0),
                    dict(kind='code', start=2, end=3, origin=2)]
        for root in ([], [dict(kind='code', start=1, end=2, origin=0)]):
            with self.subTest(root=root), patch.object(sectioning, 'section', return_value=root + sections):
                self.assertIsNone(ethutils.runtime(b'\x00\x00\x00'))

    def test_invalid_inputs_and_metadata_errors_propagate(self):
        with self.assertRaises(TypeError):
            ethutils.runtime('6000')
        encoded = cbor2.dumps({'solc': b'', 'unknown': 0})
        with self.assertRaises(ValueError):
            ethutils.runtime(encoded + len(encoded).to_bytes(2, 'big'))


if __name__ == '__main__':
    unittest.main()
