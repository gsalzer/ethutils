"""Public contracts, diagnostic equivalence and instruction-level regressions."""
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
import cbor2
import ethutils as evm
from ethutils import opcodes as op
from ethutils import analysis
from ethutils._engine import symbolic as engine
from tests.helpers import Assembly, selector, compare


class PublicApiTests(unittest.TestCase):
    def test_tvm_opcode_configuration_exports(self):
        self.assertIs(evm.set_tvm_opcodes_enabled,
                      op.set_tvm_opcodes_enabled)
        self.assertIs(evm.tvm_opcodes_enabled,
                      op.tvm_opcodes_enabled)
        self.assertTrue(evm.tvm_opcodes_enabled())

    def code(self):
        a = Assembly()
        selector(a); compare(a, 0x12345678, 'f')
        a.reject().label('f').push(42).emit(op.PUSH0, op.MSTORE).push(32).emit(op.PUSH0, op.RETURN)
        return a.build()

    def test_public_exports_resolve(self):
        namespace = {}
        exec('from ethutils import *', namespace)
        for name in evm.__all__:
            self.assertIs(namespace[name], getattr(evm, name))
        self.assertFalse(hasattr(op, 'regex'))

    def test_selectors_returns_semantic_result_and_traces_diagnostics(self):
        code = self.code()
        limits = evm.DispatchLimits(trace_length=3)
        events = []
        original = engine.analyze
        with patch.object(engine, 'analyze', wraps=original) as run, \
             patch.object(engine, 'analyze_body', side_effect=AssertionError('body pass')):
            report = evm.selectors(code, limits=limits, trace=events.append)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(report, evm.selectors(code, limits=limits))
        self.assertEqual(limits.trace_length, 3)
        self.assertTrue(report.complete)
        diagnostics = events[-1]
        paths = [path for entry in diagnostics['entries'] for path in entry['outcomes']]
        self.assertTrue(paths)
        self.assertTrue(all(len(path['trace']) <= 3 for path in paths))
        self.assertTrue(all(path['kind'] == 'selected_entry' for path in paths))
        self.assertTrue(all(not route['outcomes'] for route in diagnostics['routes']
                            if route['category'] != 'unmatched'))
        self.assertEqual(diagnostics['entries'][0]['selector'], bytes.fromhex('12345678'))
        self.assertEqual(report.to_dict()['selectors'], ['12345678'])
        json.dumps(report.to_dict())

    def test_results_report_why_no_selector_was_found(self):
        limits = evm.DispatchLimits(max_steps=1)
        self.assertEqual(evm.selectors(self.code(), limits=limits), [])
        report = evm.selectors(self.code(), limits=limits)
        self.assertEqual(report.selectors, [])
        self.assertFalse(report.complete)
        self.assertTrue(report.issues)
        report = evm.properties(self.code(), limits=limits)
        self.assertEqual(report.properties, {})
        self.assertFalse(report.dispatch_complete)
        self.assertFalse(report.complete)
        self.assertTrue(report.issues)

    def test_properties_returns_semantic_summary_and_traces_diagnostics(self):
        code = self.code()
        events = []
        original = engine.analyze
        with patch.object(engine, 'analyze', wraps=original) as run:
            report = evm.properties(code, trace=events.append)
        self.assertEqual(run.call_count, 1)
        self.assertTrue(report.complete)
        self.assertTrue(report.dispatch_complete)
        diagnostics = next(event for event in events if event['kind'] == 'property_diagnostics')
        self.assertTrue(diagnostics['entries'][0]['body_analysis']['outcomes'])
        self.assertEqual(report.to_dict()['properties']['12345678'],
                         report[bytes.fromhex('12345678')])
        json.dumps(report.to_dict())

    def test_property_result_separates_dispatch_and_body_completeness(self):
        report = evm.properties(self.code(), body_limits=evm.BodyLimits(max_steps=1))
        self.assertTrue(report.dispatch_complete)
        self.assertFalse(report.complete)
        self.assertTrue(report.issues)
        self.assertIsNone(report.properties[bytes.fromhex('12345678')]['read_only'])

    def test_properties_rejects_non_callback_trace(self):
        with self.assertRaises(TypeError):
            evm.properties(self.code(), trace=[])

    def test_selectors_rejects_non_callback_trace(self):
        with self.assertRaises(TypeError):
            evm.selectors(self.code(), trace=[])

    def test_trace_does_not_expand_budgets_or_change_fixture_discoveries(self):
        for p in sorted(Path(__file__).with_name('fixtures').glob('*.hex')):
            code = bytes.fromhex(p.read_text())
            with self.subTest(fixture=p.name):
                plain = evm.selectors(code)
                diagnostic = evm.selectors(code, trace=lambda _event: None)
                self.assertEqual(diagnostic, plain)
                self.assertEqual(evm.properties(code).properties, evm.properties(code))
                expected = json.loads(p.with_suffix('.expected.json').read_text())
                wanted = sorted(bytes.fromhex(value.removeprefix('0x').zfill(8))
                                for name, value in expected['method_identifiers'].items()
                                if not name.startswith(('__default__', '__init__')))
                self.assertEqual(plain, wanted)

    def test_duplicate_selector_entries_are_traced(self):
        a = Assembly().emit(op.CALLVALUE).target('positive').emit(op.JUMPI)
        selector(a); compare(a, 0x12345678, 'first'); a.reject()
        a.label('positive'); selector(a); compare(a, 0x12345678, 'second'); a.reject()
        a.label('first').emit(op.STOP).label('second').emit(op.STOP)
        events = []
        report = evm.selectors(a.build(), trace=events.append)
        self.assertEqual(report.selectors, [bytes.fromhex('12345678')])
        self.assertEqual(len(events[-1]['entries']), 2)

    def test_selector_import_does_not_require_third_party_modules(self):
        root = Path(evm.__file__).resolve().parent.parent
        script = f'import sys; sys.path.insert(0, {str(root)!r}); from ethutils import selectors, properties; assert selectors(b"\\x00") == []; assert properties(b"\\x00") == {{}}'
        subprocess.run([sys.executable, '-S', '-B', '-c', script], check=True, capture_output=True)


class BytecodeUtilityTests(unittest.TestCase):
    def test_disassembly_reports_offsets_unknown_and_truncated_push(self):
        rows = list(evm.disassemble(bytes.fromhex('605b0c6101')))
        self.assertEqual([(i.pc,i.name,i.immediate,i.end,i.truncated) for i in rows],
                         [(0,'PUSH1',b'\x5b',2,False),(2,None,b'',3,False),(3,'PUSH2',b'\x01',5,True)])
        self.assertEqual(evm.instruction_boundaries(bytes.fromhex('605b0c6101')), [0,2,3])
        self.assertEqual(evm.instruction_boundaries(b''), [0])

    def test_hex_conversion_is_explicit(self):
        self.assertEqual(evm.parse_hex('0x60 01\n00'), b'\x60\x01\x00')
        with self.assertRaises(ValueError): evm.parse_hex('0xabc')
        for function in (evm.selectors,evm.properties,evm.section,evm.extract_metadata,evm.normalize_pushes):
            with self.subTest(function=function.__name__), self.assertRaises(TypeError):function('6000')
        with self.assertRaises(TypeError):list(evm.disassemble('6000'))

    def test_metadata_normalization_preserves_length_and_other_bytes(self):
        obj = {'solc':b'\x00\x08\x1e'}
        encoded = cbor2.dumps(obj); record = encoded+len(encoded).to_bytes(2,'big')
        code = b'\x60\x01'+record+b'\x5b\x00'
        self.assertEqual(evm.extract_metadata(code), [(2,len(record),obj)])
        self.assertEqual(evm.zero_metadata(code), b'\x60\x01'+b'\x00'*len(record)+b'\x5b\x00')
        self.assertEqual(evm.skeleton(code), op.PUSH0+op.JUMPDEST+op.STOP)

    def test_section_trace_uses_the_same_structural_sections(self):
        runtime=bytes.fromhex('6003565b00')
        code=bytes.fromhex('6005600c60003960056000f3')+runtime
        result = evm.analyze_sections(code, trace=True)
        self.assertEqual(result.sections, evm.section(code))
        child = next(p for p in result.programs if p.origin==12)
        self.assertEqual(child.image, runtime)
        self.assertEqual(child.parent, 0)
        self.assertEqual(child.evidence, 'returned_copy')
        self.assertTrue(child.entry_accepted)
        self.assertEqual([(f.start,f.end,f.offset) for f in child.fragments], [(12,17,0)])
        json.dumps(result.to_dict())

    def test_returned_provenance_does_not_assert_patched_images(self):
        # This older prototype fixture remains valuable as a negative guarantee:
        # an overwritten copy is not evidence of an unchanged returned image.
        runtime = bytes.fromhex('60005000')
        a = Assembly().push(len(runtime)).target('runtime').push(0).emit(op.CODECOPY)
        a.push(42).push(1).emit(op.MSTORE8)
        a.push(len(runtime)).push(0).emit(op.RETURN)
        a.labels['runtime'] = len(a.code); a.code.extend(runtime)
        self.assertFalse(any(s['kind']=='returned' for s in evm.section(a.build())))

    def test_selector_shaped_push_data_is_not_executed(self):
        fake = self.selector_bytes()
        code = op.PUSH32+fake.ljust(32,b'\x00')+op.POP+op.STOP
        self.assertEqual(evm.selectors(code), [])

    def test_observed_selector_boundary_regressions(self):
        paths = sorted(Path(__file__).with_name('fixtures').joinpath('selector_boundaries').glob('*.hex'))
        self.assertEqual(len(paths), 3)
        wanted = [bytes.fromhex(s) for s in ('2fc39764','48a6ea3b','7a05a2c7')]
        for path in paths:
            with self.subTest(path=path.name):
                self.assertEqual(evm.selectors(bytes.fromhex(path.read_text())), wanted)

    def test_bounded_decoding_retains_absolute_offsets(self):
        code = bytes.fromhex('00605b6101')
        rows = list(evm.disassemble(code, start=1, end=4))
        self.assertEqual([(i.pc,i.end,i.truncated) for i in rows], [(1,3,False),(3,4,True)])
        with self.assertRaises(ValueError):list(evm.disassemble(code, end=6))

    @staticmethod
    def selector_bytes():
        return bytes.fromhex('5f3560e01c8063deadbeef14600057')


if __name__ == '__main__':
    unittest.main()
