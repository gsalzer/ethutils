"""Complete body evidence supplements dispatcher value-rejection proofs."""
from copy import deepcopy
from pathlib import Path
import unittest
from ethutils._engine import symbolic as e
from ethutils import analysis as api, opcodes as op
from tests.helpers import Assembly, selector, compare, properties_with_evidence

SELECTOR = bytes.fromhex('12345678')


def bytecode(*, guard=False, effect=False, always_reject=False, early_guard=False):
    code = Assembly()
    selector(code)
    compare(code, int.from_bytes(SELECTOR), 'entry')
    code.reject().label('entry')
    if early_guard:
        code.emit(op.CALLVALUE, op.ISZERO).target('early').emit(op.JUMPI).reject().label('early')
    # Dispatcher scope ends here, independently of subsequent body execution.
    code.push(1).emit(op.CALLDATASIZE, op.SUB, op.POP)
    if guard:
        code.emit(op.CALLVALUE, op.ISZERO).target('ok').emit(op.JUMPI).reject().label('ok')
    if effect:
        code.push(1).push(0).emit(op.SSTORE)
    if always_reject:
        code.reject()
    else:
        code.emit(op.STOP)
    return code.build()


def entries(raw, limits=None):
    result = e.analyze(raw, body_limits=limits or e.BodyLimits())
    return result.functions


class ValueEvidenceTests(unittest.TestCase):
    def test_complete_later_guard_and_unconditional_rejection(self):
        for raw in (bytecode(guard=True), bytecode(always_reject=True)):
            with self.subTest(raw=raw.hex()):
                _, values = properties_with_evidence(api, raw)
                props = values[SELECTOR]
                self.assertTrue(props['rejects_nonzero_value'])
                self.assertTrue(props['analysis']['complete'])
                result = e.analyze(raw, body_limits=e.BodyLimits())
                self.assertEqual(result.functions[0]['value_policy'], 'no_value_guard_observed')
                self.assertTrue(any(o['reason'] == 'calldata_size_computation'
                                    for o in result.functions[0]['outcomes']))

    def test_payable_success_still_refutes_rejection(self):
        props = api.properties(bytecode())[SELECTOR]
        self.assertFalse(props['rejects_nonzero_value'])

    def test_incomplete_body_does_not_establish_rejection(self):
        for raw, limits in ((bytecode(effect=True), e.BodyLimits()),
                            (bytecode(guard=True), e.BodyLimits(max_steps=1))):
            _, values = properties_with_evidence(api, raw, body_limits=limits)
            props = values[SELECTOR]
            self.assertIsNone(props['rejects_nonzero_value'])
            self.assertFalse(props['analysis']['complete'])

    def test_proof_required_for_every_entry_without_mutating_outcomes(self):
        guarded = entries(bytecode(guard=True))
        unknown = entries(bytecode(effect=True))
        payable = entries(bytecode())
        # The dispatcher proof can cover an entry with incomplete body analysis.
        early = entries(bytecode(early_guard=True), e.BodyLimits(max_steps=1))
        self.assertEqual(early[0]['value_policy'], 'nonzero_rejected')
        for combined, expected in ((guarded + unknown, None),
                                   (guarded + payable, False),
                                   (guarded + early, True)):
            original = deepcopy(combined)
            actual, _ = api._summarize(combined, True, [])
            self.assertIs(actual['rejects_nonzero_value'], expected)
            self.assertEqual(combined, original)
        actual, _ = api._summarize(guarded, False, [])
        self.assertIsNone(actual['rejects_nonzero_value'])

    def test_vyper_dense_dispatch_retains_all_later_guard_evidence(self):
        fixture_dir = Path(__file__).parent / 'fixtures'
        affected = {'9b7c2962', 'dfaf8317', '2ae1431c', 'd7531d91', 'bf3724af', '68dd531a'}
        for name in ('vyper_040_codesize.hex', 'vyper_040_gas.hex'):
            raw = bytes.fromhex((fixture_dir / name).read_text())
            props = api.properties(raw)
            for sel in affected:
                self.assertTrue(props[bytes.fromhex(sel)]['rejects_nonzero_value'], (name, sel))


if __name__ == '__main__':
    unittest.main()
