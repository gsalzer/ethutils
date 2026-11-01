"""Length predicates versus calculations after dispatch has begun."""
import unittest
import weakref
from unittest.mock import patch
from ethutils._engine import symbolic as e
from ethutils import analysis as api, opcodes as op
from ethutils._engine.calldata_size import uses_size_arithmetic, CACHE_SIZE
from tests.helpers import Assembly, selector, compare, properties_with_evidence

FIRST = bytes.fromhex('12345678')
SECOND = bytes.fromhex('abcdef01')


def prefix():
    code = Assembly()
    selector(code)
    compare(code, int.from_bytes(FIRST), 'first')
    return code


def finish(code, first=True):
    selector(code)
    compare(code, int.from_bytes(SECOND), 'second')
    code.reject().label('second').emit(op.STOP)
    if first:
        code.label('first').emit(op.STOP)
    return code.build()


def analyze(raw):
    vm = e.Interpreter(raw, e.Limits(), stop_at_selected_entry=True,
                       include_short_calldata_routes=False)
    return vm, vm.run()


class CalldataSizeTests(unittest.TestCase):
    def test_direct_length_checks_and_boolean_composition_after_dispatch(self):
        checks = [
            lambda c: c.push(4).emit(op.CALLDATASIZE, op.LT, op.ISZERO),
            lambda c: c.push(36).emit(op.CALLDATASIZE, op.EQ),
            lambda c: c.emit(op.CALLDATASIZE, op.ISZERO, op.ISZERO),
            lambda c: c.push(4).emit(op.CALLDATASIZE, op.LT, op.ISZERO)
                       .push(36).emit(op.CALLDATASIZE, op.EQ, op.OR),
        ]
        for check in checks:
            code = prefix()
            check(code).target('continue').emit(op.JUMPI).reject().label('continue')
            self.assertEqual(api.selectors(finish(code)), [FIRST, SECOND])

    def test_length_arithmetic_before_dispatch_is_preserved(self):
        code = Assembly().push(4).emit(op.CALLDATASIZE, op.SUB).push(32).emit(op.EQ)
        code.target('dispatch').emit(op.JUMPI).reject().label('dispatch')
        self.assertEqual(api.selectors(finish(code, first=False)), [SECOND])

    def test_interleaved_arithmetic_can_hide_later_selectors(self):
        # Deliberate scope limitation in a custom interleaved dispatcher.
        for operation in (op.ADD, op.SUB, op.MUL, op.DIV, op.MOD, op.AND, op.SHR):
            with self.subTest(operation=operation):
                code = prefix().push(3).emit(op.CALLDATASIZE, operation, op.POP)
                vm, result = analyze(finish(code))
                self.assertEqual({f['selector'] for f in result.functions}, {FIRST.hex()})
                self.assertTrue(result.complete)  # Scope stop, not a budget failure.
                self.assertTrue(any(o['reason'] == 'calldata_size_computation'
                                    and o['kind'] == 'body' for o in vm.outcomes))

    def test_precomputed_expression_is_checked_after_dispatch(self):
        code = Assembly().push(4).emit(op.CALLDATASIZE, op.SUB)
        selector(code)
        compare(code, int.from_bytes(FIRST), 'first')
        code.emit(op.POP).push(32).emit(op.EQ).target('continue').emit(op.JUMPI)
        code.reject().label('continue')
        vm, result = analyze(finish(code))
        self.assertEqual({f['selector'] for f in result.functions}, {FIRST.hex()})
        self.assertTrue(any(o['reason'] == 'calldata_size_computation' for o in vm.outcomes))

    def test_dispatch_flag_is_path_local(self):
        code = Assembly().push(36).emit(op.CALLDATASIZE, op.EQ).target('no_dispatch').emit(op.JUMPI)
        selector(code)
        compare(code, int.from_bytes(FIRST), 'first')
        code.push(1).emit(op.CALLDATASIZE, op.SUB, op.POP).reject()
        code.label('no_dispatch').push(1).emit(op.CALLDATASIZE, op.SUB, op.POP)
        self.assertEqual(api.selectors(finish(code)), [FIRST, SECOND])

    def test_selected_body_length_arithmetic_is_unchanged(self):
        code = prefix().reject().label('first').push(1).emit(op.CALLDATASIZE, op.SUB)
        code.push(0).emit(op.MSTORE).push(32).push(0).emit(op.RETURN)
        _, values = properties_with_evidence(api, code.build())
        props = values[FIRST]
        self.assertTrue(props['analysis']['complete'])
        self.assertTrue(props['read_only'])
        self.assertTrue(props['state_independent'])
        self.assertEqual(props['return_size'], 32)
        self.assertTrue(any(o['kind'] == 'return' for o in props['analysis']['outcomes']))

    def test_later_value_guard_is_retained_from_complete_body(self):
        code = prefix().reject().label('first').push(1).emit(op.CALLDATASIZE, op.SUB, op.POP)
        code.emit(op.CALLVALUE, op.ISZERO).target('return').emit(op.JUMPI).reject()
        code.label('return').emit(op.STOP)
        _, values = properties_with_evidence(api, code.build())
        props = values[FIRST]
        self.assertTrue(props['rejects_nonzero_value'])
        self.assertTrue(props['analysis']['complete'])
        self.assertTrue(props['read_only'])
        self.assertTrue(any(o['kind'] == 'stop' for o in props['analysis']['outcomes']))

    def test_identity_cache_is_bounded_and_has_no_retention_cycle(self):
        memo = {}
        for n in range(CACHE_SIZE + 10):
            uses_size_arithmetic(e.Expr(op.SUB, (e.Expr(op.CALLDATASIZE), n)), memo)
        self.assertLessEqual(len(memo), CACHE_SIZE)
        value = e.Expr(op.SUB, (e.Expr(op.CALLDATASIZE), 4))
        with patch.object(e.Expr, '__eq__', side_effect=AssertionError('structural equality')):
            self.assertTrue(uses_size_arithmetic(value, memo))
            self.assertTrue(uses_size_arithmetic(value, memo))
        ref = weakref.ref(value)
        vm = e.Interpreter(b'', e.Limits())
        uses_size_arithmetic(value, vm.calldata_size_shapes)
        del memo, value, vm
        self.assertIsNone(ref())


if __name__ == '__main__':
    unittest.main()
