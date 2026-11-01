"""Storage-expression dispatcher boundaries and independent body execution."""
import unittest
import weakref
from unittest.mock import patch
from ethutils._engine import symbolic as e
from ethutils import analysis as api, opcodes as op
from ethutils.analysis import selectors
from ethutils._engine.storage import classify, CACHE_SIZE
from tests.helpers import Assembly, selector, compare, properties_with_evidence


def make_vm(raw):
    return e.Interpreter(raw, e.Limits(trace_length=0), stop_at_selected_entry=True,
                         include_short_calldata_routes=False)


def finish(code):
    selector(code)
    compare(code,0x12345678,'function')
    return code.reject().label('function').emit(op.STOP).build()


class StorageExpressionTests(unittest.TestCase):
    def test_owner_pause_packed_reads_and_shared_subroutine(self):
        for role in ['owner','pause','sub_owner','xor_owner','combined']:
            for packed in ['raw','shr','div','mod','byte','signextend','sar','leftshift']:
                code=Assembly().push(3).emit(op.SLOAD)
                if packed=='shr':code.push(8).emit(op.SHR)
                elif packed=='div':code.push(256).emit(op.SWAP1,op.DIV)
                elif packed=='mod':code.push(256).emit(op.SWAP1,op.MOD)
                elif packed=='byte':code.push(0).emit(op.BYTE)
                elif packed=='signextend':code.push(0).emit(op.SIGNEXTEND)
                elif packed=='sar':code.push(8).emit(op.SAR)
                elif packed=='leftshift':code.push(8).emit(op.SHL).push(8).emit(op.SHR)
                code.push((1<<160)-1 if role!='pause' else 255).emit(op.AND)
                if role in {'owner','sub_owner','xor_owner','combined'}:
                    code.emit(op.CALLER,{'owner':op.EQ,'sub_owner':op.SUB,'xor_owner':op.XOR,'combined':op.EQ}[role])
                if role in {'sub_owner','xor_owner','pause'}:code.emit(op.ISZERO)
                if role=='combined':code.push(4).emit(op.SLOAD,op.ISZERO,op.AND)
                code.target('dispatch').emit(op.JUMPI).reject().label('dispatch')
                raw=finish(code);vm=make_vm(raw);r=vm.run()
                actual=sorted({f['selector'] for f in r.functions})
                assert actual==[x.hex() for x in selectors(raw)]==['12345678'],(role,packed,actual)
                self.assertFalse(any(o['reason'].startswith('storage_') for o in vm.outcomes), (role,packed))
                
        # Owner SUB comparison returned through a shared subroutine before dispatch.
        code=Assembly().target('checked').target('guard').emit(op.JUMP).label('checked')
        code.target('dispatch').emit(op.JUMPI).reject().label('dispatch')
        selector(code);compare(code,0x12345678,'function');code.reject().label('function').emit(op.STOP)
        code.label('guard').push(3).emit(op.SLOAD).push(8).emit(op.SHR).push((1<<160)-1).emit(op.AND,op.CALLER,op.SUB,op.ISZERO,op.SWAP1,op.JUMP)
        vm=make_vm(code.build());r=vm.run()
        assert sorted({f['selector'] for f in r.functions})==['12345678']
        

    def test_calculations_stop_on_unmatched_routes(self):
        for operation in (op.ADD, op.MUL, op.DIV, op.EXP):
            with self.subTest(operation=operation):
                code = Assembly()
                selector(code)
                compare(code, 0xabcdef01, 'first')
                code.push(3).emit(op.SLOAD).push(3).emit(op.SWAP1, operation, op.POP)
                selector(code)
                compare(code, 0x12345678, 'function')
                raw = code.reject().label('function').emit(op.STOP).label('first').emit(op.STOP).build()
                vm = make_vm(raw)
                result = vm.run()
                self.assertEqual({f['selector'] for f in result.functions}, {'abcdef01'})
                self.assertTrue(any(o['reason'] == 'storage_calculation' and o['kind'] == 'body'
                                    for o in vm.outcomes))
                self.assertTrue(result.complete)

    def test_subtraction_and_computed_comparison_operands(self):
        value = e.Expr(op.SUB, (e.Expr(op.SLOAD, (3,)), e.Expr(op.CALLER)))
        self.assertEqual(classify(value, {}), ('zero_test', True))
        self.assertEqual(classify(e.Expr(op.ISZERO, (value,)), {}), ('predicate', True))
        self.assertEqual(classify(e.Expr(op.MUL, (value, 8)), {}), ('calculation', True))
        self.assertEqual(classify(e.Expr(op.GT, (value, 3)), {}), ('calculation', True))
        computed = e.Expr(op.MUL, (e.Expr(op.CALLVALUE), 3))
        self.assertEqual(classify(e.Expr(op.EQ, (e.Expr(op.SLOAD, (3,)), computed)), {}),
                         ('calculation', True))
        self.assertEqual(classify(computed, {}), ('free_computation', False))

    def test_storage_derived_address_stops_before_enumeration(self):
        for operation in (op.MLOAD, op.SLOAD, op.JUMP):
            with self.subTest(operation=operation):
                raw = Assembly().push(3).emit(op.SLOAD).push(3).emit(op.AND, operation).build()
                vm = make_vm(raw)
                vm.run()
                self.assertEqual(vm.states, 1)
                self.assertEqual(vm.outcomes[0]['reason'], 'storage_derived_address')

    def test_selected_body_storage_calculations_remain_supported(self):
        for operation in (op.ADD, op.MUL, op.DIV):
            code = Assembly()
            selector(code)
            compare(code, 0x12345678, 'function')
            code.reject().label('function').push(3).emit(op.SLOAD).push(3)
            code.emit(op.SWAP1, operation).push(0).emit(op.MSTORE).push(32).push(0).emit(op.RETURN)
            _, values = properties_with_evidence(api, code.build())
            props = values[bytes.fromhex('12345678')]
            self.assertTrue(props['analysis']['complete'])
            self.assertTrue(props['read_only'])
            self.assertFalse(props['state_independent'])
            self.assertFalse(props['scalar_storage_getter'])
            self.assertEqual(props['return_size'], 32)
            self.assertTrue(any(o['kind'] == 'return' for o in props['analysis']['outcomes']))

    def test_identity_cache_is_bounded_and_released_without_gc(self):
        memo = {}
        for slot in range(CACHE_SIZE + 10):
            classify(e.Expr(op.SLOAD, (slot,)), memo)
        self.assertLessEqual(len(memo), CACHE_SIZE)
        first, second = e.Expr(op.SLOAD, (1,)), e.Expr(op.SLOAD, (2,))
        with patch.object(e.Expr, '__eq__', side_effect=AssertionError('structural equality')):
            self.assertEqual(classify(first, memo), ('term', True))
            self.assertEqual(classify(second, memo), ('term', True))
            self.assertEqual(classify(first, memo), ('term', True))
        value = e.Expr(op.SLOAD, (3,))
        ref = weakref.ref(value)
        vm = make_vm(b'')
        vm.check_storage_use(value)
        del value, vm
        self.assertIsNone(ref())


if __name__ == '__main__':
    unittest.main()
