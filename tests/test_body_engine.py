"""Body evidence is deliberately separate from ABI/source mutability recovery."""
import json
from pathlib import Path
import unittest
from ethutils._engine import symbolic as e
from ethutils import opcodes as op
from tests.helpers import Assembly, selector, compare, guard

class BodyTests(unittest.TestCase):

    def entry(self, prefix=None):
        a = prefix or Assembly()
        selector(a)
        compare(a, 305419896, 'f')
        a.reject().label('f')
        return a

    def return_word(self, a):
        return a.emit(op.PUSH0, op.MSTORE).push(32).emit(op.PUSH0, op.RETURN)

    def body(self, a, **limits):
        code = a.build()
        original = e.analyze(code).to_dict()
        extended = e.analyze(code, body_limits=e.BodyLimits(**limits)).to_dict()
        summaries = [f.pop('body_analysis') for f in extended['functions']]
        for entry in extended['functions']:
            entry.pop('delegatecall_only', None)
        self.assertEqual(original, extended)
        return summaries[0]

    def test_scalar_slot_and_packed_getters(self):
        for packed in (False, True):
            a = self.entry().push(3).emit(op.SLOAD)
            if packed:
                a.push(8).emit(op.SHR).push(255).emit(op.AND)
            b = self.body(self.return_word(a))
            self.assertTrue(b['complete'])
            self.assertTrue(b['scalar_getter_candidate'])
            self.assertEqual(b['mutability_evidence'], 'read_only')
            self.assertIn('sload(0x3)', next((o['return_data']['word'] for o in b['outcomes'] if o['kind'] == 'return')))

    def test_constant_and_immutable_like_code_is_not_a_storage_getter(self):
        b = self.body(self.return_word(self.entry().push(42)))
        self.assertTrue(b['complete'])
        self.assertEqual(b['mutability_evidence'], 'no_state_reads')
        self.assertFalse(b['scalar_getter_candidate'])

    def test_environment_read_on_reverting_path_is_retained(self):
        a = self.entry().emit(op.CALLER).target('reject').emit(op.JUMPI)
        self.return_word(a.push(42))
        a.label('reject').reject()
        b = self.body(a)
        self.assertTrue(b['complete'])
        self.assertEqual(b['mutability_evidence'], 'read_only')
        self.assertIn('CALLER', b['reads'])
        self.assertEqual(b['successful_paths'], 1)

    def test_discarded_read_is_still_a_read(self):
        a = self.entry().emit(op.PUSH0, op.SLOAD, op.POP).push(42)
        b = self.body(self.return_word(a))
        self.assertEqual(b['mutability_evidence'], 'read_only')
        self.assertFalse(b['scalar_getter_candidate'])

    def test_argument_branch_cannot_hide_a_write(self):
        a = self.entry().push(4).emit(op.CALLDATALOAD).target('write').emit(op.JUMPI)
        self.return_word(a.push(42))
        a.label('write').emit(op.PUSH0, op.PUSH0, op.SSTORE).reject()
        b = self.body(a)
        self.assertFalse(b['complete'])
        self.assertEqual(b['mutability_evidence'], 'potentially_modifying')
        self.assertEqual(b['potential_effects'], ['SSTORE'])
        self.assertEqual(b['successful_paths'], 1)

    def test_argument_reads_and_environment_guards_disqualify_getter(self):
        for opcode in (op.CALLER, op.CALLDATALOAD):
            a = self.entry()
            if opcode == op.CALLDATALOAD:
                a.push(4)
            a.emit(opcode, op.POP, op.PUSH0, op.SLOAD)
            b = self.body(self.return_word(a))
            self.assertFalse(b['scalar_getter_candidate'])

    def test_pre_dispatch_reads_and_memory_are_preserved(self):
        a = Assembly().push(3).emit(op.SLOAD).push(128).emit(op.MSTORE)
        a.emit(op.CALLER, op.POP)
        self.entry(a).push(128).emit(op.MLOAD)
        b = self.body(self.return_word(a))
        self.assertIn('SLOAD', b['reads'])
        self.assertIn('CALLER', b['reads'])
        self.assertEqual(next((o['return_data']['word'] for o in b['outcomes'] if o['kind'] == 'return')), 'sload(0x3)')
        self.assertFalse(b['scalar_getter_candidate'])

    def test_calls_hashing_and_transient_reads_remain_unknown(self):
        for opcode in (op.STATICCALL, op.KECCAK256, op.TLOAD):
            b = self.body(self.entry().emit(opcode))
            self.assertFalse(b['complete'])
            self.assertEqual(b['mutability_evidence'], 'unknown')
            self.assertFalse(b['scalar_getter_candidate'])

    def test_all_modifying_opcodes_are_reported_conservatively(self):
        for opcode in e.EFFECT_OPS:
            with self.subTest(op=e.OP_NAMES[opcode]):
                b = self.body(self.entry().emit(*([op.PUSH0] * op.INFO[opcode].required), opcode))
                self.assertEqual(b['potential_effects'], [e.OP_NAMES[opcode]])
                self.assertEqual(b['mutability_evidence'], 'potentially_modifying')
                self.assertFalse(b['complete'])

    def test_unresolved_slot_and_return_region_are_incomplete(self):
        a = self.entry().push(4).emit(op.CALLDATALOAD, op.SLOAD)
        self.assertFalse(self.body(a)['complete'])
        a = self.entry().push(32).push(4).emit(op.CALLDATALOAD, op.RETURN)
        self.assertFalse(self.body(a)['complete'])

    def test_budgets_are_independent_and_nonvacuous(self):
        for limits in ({'max_steps': 1}, {'max_path_steps': 1}, {'max_memory': 16}):
            b = self.body(self.return_word(self.entry().emit(op.PUSH0, op.SLOAD)), **limits)
            self.assertFalse(b['complete'])
            self.assertEqual(b['mutability_evidence'], 'unknown')
        a = self.entry().emit(op.CALLER).target('other').emit(op.JUMPI, op.STOP).label('other').emit(op.STOP)
        b = self.body(a, max_states=1)
        self.assertFalse(b['complete'])
        self.assertTrue(any((i['reason'] == 'state_budget' for i in b['issues'])))
        a = self.entry().label('loop').target('loop').emit(op.JUMP)
        self.assertFalse(self.body(a, max_path_steps=20)['complete'])

    def test_always_reverting_is_not_a_getter_or_purity_claim(self):
        b = self.body(self.entry().reject())
        self.assertTrue(b['complete'])
        self.assertEqual(b['successful_paths'], 0)
        self.assertEqual(b['mutability_evidence'], 'unknown')
        self.assertFalse(b['scalar_getter_candidate'])

    def test_incomplete_dispatch_prevents_complete_body_claim(self):
        a = self.return_word(self.entry().emit(op.PUSH0, op.SLOAD))
        r = e.analyze(a.build(), limits=e.Limits(max_states=6), body_limits=e.BodyLimits())
        self.assertFalse(r.complete)
        for f in r.functions:
            self.assertFalse(f['body_analysis']['complete'])

    def test_pure_argument_computation_is_not_a_getter(self):
        a = self.entry().push(4).emit(op.CALLDATALOAD).push(1).emit(op.ADD)
        b = self.body(self.return_word(a))
        self.assertTrue(b['complete'])
        self.assertEqual(b['mutability_evidence'], 'no_state_reads')
        self.assertFalse(b['scalar_getter_candidate'])

    def test_abi_length_guard_prevents_zero_argument_getter_candidate(self):
        a = self.entry().push(36).emit(op.CALLDATASIZE, op.LT).target('reject').emit(op.JUMPI)
        self.return_word(a.emit(op.PUSH0, op.SLOAD))
        a.label('reject').reject()
        b = self.body(a)
        self.assertTrue(b['complete'])
        self.assertFalse(b['scalar_getter_candidate'])

    def test_independent_budget_for_each_function(self):
        a = Assembly()
        selector(a)
        compare(a, 305419896, 'loop')
        compare(a, 2271560481, 'getter')
        a.reject().label('loop').emit(op.PUSH0, op.SLOAD, op.POP).target('loop').emit(op.JUMP)
        a.label('getter')
        self.return_word(a.emit(op.PUSH0, op.SLOAD))
        r = e.analyze(a.build(), body_limits=e.BodyLimits(max_steps=30))
        self.assertTrue(r.complete)
        bodies = {f['selector']: f['body_analysis'] for f in r.functions}
        self.assertFalse(bodies['12345678']['complete'])
        self.assertTrue(bodies['87654321']['complete'])
        self.assertTrue(bodies['87654321']['scalar_getter_candidate'])

    def test_non_scalar_return_and_signed_packed_scalar(self):
        a = self.entry().emit(op.PUSH0, op.SLOAD, op.PUSH0, op.MSTORE)
        a.push(64).emit(op.PUSH0, op.RETURN)
        b = self.body(a)
        self.assertTrue(b['complete'])
        self.assertFalse(b['scalar_getter_candidate'])
        a = self.entry().emit(op.PUSH0, op.SLOAD).push(0).emit(op.SIGNEXTEND)
        b = self.body(self.return_word(a))
        self.assertTrue(b['scalar_getter_candidate'])

    def test_one_incomplete_branch_prevents_read_only_claim(self):
        a = self.entry().emit(op.CALLER).target('unsupported').emit(op.JUMPI)
        self.return_word(a.emit(op.PUSH0, op.SLOAD))
        a.label('unsupported').emit(op.STATICCALL)
        b = self.body(a)
        self.assertEqual(b['successful_paths'], 1)
        self.assertFalse(b['complete'])
        self.assertEqual(b['mutability_evidence'], 'unknown')
        self.assertFalse(b['scalar_getter_candidate'])

    def test_body_budget_validation(self):
        with self.assertRaises(ValueError):
            e.analyze(b'', body_limits=e.BodyLimits(max_steps=0))

    def test_compiler_scalar_getters_and_dispatch_invariance(self):
        fixtures = list(Path(__file__).with_name('fixtures').glob('solidity*.hex'))
        self.assertEqual(len(fixtures), 10)
        for file in fixtures:
            with self.subTest(fixture=file.name):
                code = bytes.fromhex(file.read_text())
                expected = json.loads(file.with_suffix('.expected.json').read_text())
                sel = expected['method_identifiers']['saved()'].removeprefix('0x').zfill(8)
                baseline = e.analyze(code).to_dict()
                extended = e.analyze(code, body_limits=e.BodyLimits()).to_dict()
                for f in extended['functions']:
                    b = f.pop('body_analysis')
                    f.pop('delegatecall_only', None)
                    if f['selector'] == sel:
                        self.assertTrue(b['complete'], b['issues'])
                        self.assertTrue(b['scalar_getter_candidate'], b)
                        self.assertEqual(b['mutability_evidence'], 'read_only')
                self.assertEqual(baseline, extended)
if __name__ == '__main__':
    unittest.main()
