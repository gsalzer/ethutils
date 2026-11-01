"""Dispatcher storage-write boundaries and independent body evidence."""
import unittest

from ethutils._engine import symbolic as e
from ethutils import analysis, opcodes as op
from tests.helpers import Assembly, selector, compare, properties_with_evidence


class StorageBoundaryTests(unittest.TestCase):
    def test_unmatched_write_stops_before_execution_in_all_dispatch_modes(self):
        code = Assembly()
        selector(code)
        compare(code, 0x12345678, 'function')
        code.push(7).push(0)
        write_pc = len(code.code)
        code.emit(op.SSTORE)
        # This selector deliberately occurs beyond the supported scope.
        compare(code, 0xabcdef01, 'function')
        code.reject().label('function').emit(op.STOP)
        raw = code.build()
        for body_limits in (None, e.BodyLimits()):
            with self.subTest(body_limits=body_limits):
                result = e.analyze(raw, body_limits=body_limits)
                self.assertEqual({f['selector'] for f in result.functions}, {'12345678'})
                unmatched = next(r for r in result.routes if r['category'] == 'unmatched')
                self.assertTrue(any(o['reason'] == 'SSTORE' and o['kind'] == 'body'
                                    and o['stop_pc'] == write_pc for o in unmatched['outcomes']))
                self.assertTrue(result.complete)
        self.assertEqual(analysis.selectors(raw), [bytes.fromhex('12345678')])

    def test_write_before_dispatch_stops_every_calldata_route_without_mutation(self):
        code = Assembly().push(7).push(0)
        write_pc = len(code.code)
        code.emit(op.SSTORE)
        selector(code)
        compare(code, 0x12345678, 'function')
        code.reject().label('function').emit(op.STOP)
        class Probe(e.Interpreter):
            def finish(self, state, *args, **kwargs):
                self.assert_unchanged(state)
                super().finish(state, *args, **kwargs)
        vm = Probe(code.build(), e.Limits())
        vm.assert_unchanged = lambda state: self.assertEqual(state.storage, {})
        result = vm.run()
        self.assertEqual(result.functions, [])
        self.assertEqual(len(vm.outcomes), 5)
        self.assertTrue(all(o['stop_pc'] == write_pc and o['reason'] == 'SSTORE'
                            for o in vm.outcomes))

    def test_storage_read_guard_before_dispatch_remains_supported(self):
        code = Assembly().push(0).emit(op.SLOAD, op.ISZERO).target('dispatch').emit(op.JUMPI)
        code.reject().label('dispatch')
        selector(code)
        compare(code, 0x12345678, 'function')
        code.reject().label('function').emit(op.STOP)
        self.assertEqual(analysis.selectors(code.build()), [bytes.fromhex('12345678')])

    def test_selected_write_is_still_reported_by_body_analysis(self):
        code = Assembly()
        selector(code)
        compare(code, 0x12345678, 'function')
        code.reject().label('function').push(7).push(0).emit(op.SSTORE, op.STOP)
        _, values = properties_with_evidence(analysis, code.build())
        result = values[bytes.fromhex('12345678')]
        self.assertFalse(result['read_only'])
        self.assertFalse(result['state_independent'])
        self.assertIn('SSTORE', result['analysis']['potential_effects'])
        self.assertTrue(any(o['reason'] == 'potential_effect_SSTORE'
                            for o in result['analysis']['outcomes']))


if __name__ == '__main__':
    unittest.main()
