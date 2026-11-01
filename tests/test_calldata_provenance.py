"""Selector-only calldata use across stack words and byte-addressed memory."""
import unittest
import weakref
from unittest.mock import patch

from ethutils._engine import symbolic as e
from ethutils import analysis as api, opcodes as op
from ethutils._engine.calldata import CACHE_SIZE, uses_arguments
from tests.helpers import Assembly, selector, compare, length_guard, properties_with_evidence


class CalldataProvenanceTests(unittest.TestCase):
    def finish(self, code, *, word=True):
        if word:
            code.push(224).emit(op.SHR)
        compare(code, 0x12345678, 'function')
        return code.reject().label('function').emit(op.STOP).build()

    def assert_selector(self, code):
        self.assertEqual(api.selectors(code), [bytes.fromhex('12345678')])

    def assert_argument_boundary(self, code):
        vm = e.Interpreter(code, e.Limits(trace_length=0),
                           stop_at_selected_entry=True, include_short_calldata_routes=False)
        result = vm.run()
        self.assertTrue(result.complete)
        self.assertEqual(result.functions, [])
        self.assertTrue(any(o['reason'] == 'argument_calldata' and o['kind'] == 'body'
                            for o in vm.outcomes))
        return vm

    def test_demanded_bits_and_overlapping_words(self):
        word = e.Expr(op.CALLDATALOAD, (0,))
        high = ((1 << 32) - 1) << 224
        cases = [(word, True), (e.SEL, False),
                 (e.Expr(op.BYTE, (3, word)), False),
                 (e.Expr(op.BYTE, (4, word)), True),
                 (e.Expr(op.BYTE, (32, word)), False),
                 (e.Expr(op.AND, (word, high)), False),
                 (e.Expr(op.AND, (word, 255)), True),
                 (e.Expr(op.SHR, (224, word)), False),
                 (e.Expr(op.DIV, (word, 1 << 224)), False),
                 (e.Expr(op.SHR, (232, e.Expr(op.CALLDATALOAD, (1,)))), False),
                 (e.Expr(op.BYTE, (0, e.Expr(op.CALLDATALOAD, (4,)))), True),
                 (e.Expr(op.ADD, (word, 1)), True)]
        for value, expected in cases:
            with self.subTest(value=value):
                self.assertEqual(uses_arguments(value), expected)

    def test_selector_extraction_from_whole_word_load_store_and_overlapping_mcopy(self):
        code = Assembly().push(0).emit(op.CALLDATALOAD).push(7).emit(op.MSTORE)
        code.push(32).push(7).push(10).emit(op.MCOPY).push(10).emit(op.MLOAD)
        self.assert_selector(self.finish(code))

    def test_whole_word_calldatacopy_is_not_an_argument_use(self):
        # The negative control from the experiment must now retain its selector.
        code = Assembly().push(32).push(0).push(0).emit(op.CALLDATACOPY)
        code.push(0).emit(op.MLOAD)
        self.assert_selector(self.finish(code))

    def test_calldatacopy_mcopy_and_unaligned_memory_retain_selector(self):
        code = Assembly().push(64).push(0).push(7).emit(op.CALLDATACOPY)
        code.push(32).push(7).push(40).emit(op.MCOPY).push(40).emit(op.MLOAD)
        self.assert_selector(self.finish(code))

    def test_four_selector_bytes_can_be_right_aligned_in_memory(self):
        code = Assembly().push(4).push(0).push(28).emit(op.CALLDATACOPY)
        code.push(0).emit(op.MLOAD)
        self.assert_selector(self.finish(code, word=False))

    def test_historical_division_and_mask_extract_only_selector(self):
        code = Assembly().push(0).emit(op.CALLDATALOAD)
        code.push(0).emit(op.MSTORE).push(1 << 224).push(0).emit(op.MLOAD, op.DIV)
        code.push((1 << 32) - 1).emit(op.AND)
        self.assert_selector(self.finish(code, word=False))

    def test_each_argument_byte_boundary_survives_memory_transfers(self):
        for index in (3, 4, 31):
            with self.subTest(index=index):
                code = Assembly().push(32).push(0).push(0).emit(op.CALLDATACOPY)
                code.push(32).push(0).push(40).emit(op.MCOPY)
                code.push(40).emit(op.MLOAD).push(index).emit(op.BYTE, op.POP)
                selector(code)
                raw = self.finish(code, word=False)
                if index == 3:
                    self.assert_selector(raw)
                else:
                    self.assert_argument_boundary(raw)

    def test_argument_only_copy_is_tracked_until_consumed(self):
        code = Assembly().push(32).push(4).push(0).emit(op.CALLDATACOPY)
        code.push(0).emit(op.MLOAD).push(224).emit(op.SHR)
        self.assert_argument_boundary(self.finish(code, word=False))

    def test_overwrite_removes_old_argument_provenance(self):
        code = Assembly().push(32).push(4).push(0).emit(op.CALLDATACOPY)
        code.push(0).push(0).emit(op.MSTORE).push(0).emit(op.MLOAD, op.POP)
        selector(code)
        self.assert_selector(self.finish(code, word=False))

    def test_mstore8_retains_the_origin_of_the_low_byte(self):
        code = Assembly().push(0).emit(op.CALLDATALOAD).push(0).emit(op.MSTORE8)
        code.push(0).emit(op.MLOAD).push(0).emit(op.BYTE, op.POP)
        selector(code)
        self.assert_argument_boundary(self.finish(code, word=False))

    def test_partial_overwrite_clears_only_the_replaced_byte(self):
        for index in (0, 1):
            with self.subTest(index=index):
                code = Assembly().push(32).push(4).push(0).emit(op.CALLDATACOPY)
                code.push(42).push(0).emit(op.MSTORE8)
                code.push(0).emit(op.MLOAD).push(index).emit(op.BYTE, op.POP)
                selector(code)
                raw = self.finish(code, word=False)
                if index == 0:
                    self.assert_selector(raw)
                else:
                    self.assert_argument_boundary(raw)

    def test_direct_argument_branch_and_argument_address_stop_dispatch(self):
        code = Assembly().push(4).emit(op.CALLDATALOAD).target('dispatch').emit(op.JUMPI)
        code.reject().label('dispatch')
        selector(code)
        self.assert_argument_boundary(self.finish(code, word=False))
        code = Assembly().push(4).emit(op.CALLDATALOAD, op.MLOAD)
        vm = self.assert_argument_boundary(code.build())
        self.assertEqual(vm.states, 1)  # No finite-address rescheduling.

    def test_calldata_size_checks_remain_supported(self):
        code = Assembly()
        length_guard(code)
        selector(code)
        compare(code, 0x12345678, 'function')
        code.label('fallback').reject().label('function').emit(op.STOP)
        self.assert_selector(code.build())

    def test_selected_body_still_analyzes_argument_arithmetic_and_returns(self):
        code = Assembly()
        selector(code)
        compare(code, 0x12345678, 'function')
        code.reject().label('function').push(4).emit(op.CALLDATALOAD)
        code.push(1).emit(op.ADD).push(0).emit(op.MSTORE).push(32).push(0).emit(op.RETURN)
        _, values = properties_with_evidence(api, code.build())
        props = values[bytes.fromhex('12345678')]
        self.assertTrue(props['analysis']['complete'])
        self.assertTrue(props['read_only'])
        self.assertTrue(props['state_independent'])
        self.assertFalse(props['scalar_storage_getter'])
        self.assertEqual(props['return_size'], 32)
        self.assertTrue(any(o['argument_reads'] and o['kind'] == 'return'
                            for o in props['analysis']['outcomes']))

    def test_provenance_cache_is_bounded_and_dies_with_interpreter(self):
        memo = {}
        for offset in range(CACHE_SIZE + 10):
            uses_arguments(e.Expr(op.CALLDATALOAD, (offset,)), memo=memo)
        self.assertLessEqual(len(memo), CACHE_SIZE)
        value = e.Expr(op.AND, (e.Expr(op.CALLDATALOAD, (0,)), ((1 << 32)-1) << 224))
        reference = weakref.ref(value)
        vm = e.Interpreter(b'', e.Limits())
        vm.check_calldata_use(value)
        del value, vm
        # No cyclic collection should be needed to release the graph.
        self.assertIsNone(reference())

    def test_cache_never_compares_expression_graphs_structurally(self):
        first, second = e.Expr(op.SLOAD, (1,)), e.Expr(op.SLOAD, (2,))
        # Hash collisions must not invoke potentially exponential DAG equality.
        object.__setattr__(first, '_hash', 1)
        object.__setattr__(second, '_hash', 1)
        memo = {}
        with patch.object(e.Expr, '__eq__', side_effect=AssertionError('structural comparison')):
            self.assertFalse(uses_arguments(first, memo=memo))
            self.assertFalse(uses_arguments(second, memo=memo))
            self.assertFalse(uses_arguments(first, memo=memo))


if __name__ == '__main__':
    unittest.main()
