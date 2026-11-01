import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from ethutils import analysis as a, opcodes
from ethutils._engine import symbolic as engine
from ethutils import opcodes as old
from tests.helpers import Assembly, selector, compare, guard, properties_with_evidence


class LibraryTests(unittest.TestCase):
    def entry(self):
        code = Assembly()
        selector(code)
        compare(code, 0x12345678, 'f')
        return code.reject().label('f')

    def ret(self, code):
        return code.emit(old.PUSH0, old.MSTORE).push(32).emit(old.PUSH0, old.RETURN)

    def props(self, code, **kwargs):
        _, values = properties_with_evidence(a, code.build(), **kwargs)
        return values[bytes.fromhex('12345678')]

    def test_bytes_registry_is_shared(self):
        self.assertIs(engine.SLOAD, opcodes.SLOAD)
        for opcode, operation in engine.OPERATIONS.items():
            info = opcodes.INFO[opcode]
            self.assertEqual((operation.pops, operation.pushes, operation.required),
                             (info.pops, info.pushes, info.required))

    def test_constant_storage_packed_and_argument_returns(self):
        for kind in ('constant', 'slot', 'packed', 'argument'):
            code = self.entry()
            if kind == 'constant': code.push(42)
            elif kind == 'argument': code.push(4).emit(old.CALLDATALOAD)
            else:
                code.push(3).emit(old.SLOAD)
                if kind == 'packed': code.push(8).emit(old.SHR).push(255).emit(old.AND)
            p = self.props(self.ret(code))
            self.assertTrue(p['analysis']['complete'], p)
            self.assertTrue(p['read_only'], p)
            self.assertEqual(p['state_independent'], kind in {'constant','argument'})
            self.assertEqual(p['scalar_storage_getter'], kind in {'slot','packed'})
            self.assertEqual(p['return_size'], 32)
            self.assertFalse(p['rejects_nonzero_value'])

    def test_nonpayable_guard_does_not_count_as_state_read(self):
        code = self.entry()
        guard(code, 'body')
        p = self.props(self.ret(code.push(42)))
        self.assertTrue(p['rejects_nonzero_value'])
        self.assertTrue(p['state_independent'])
        self.assertNotIn('CALLVALUE',p['analysis']['reads'])
        self.assertEqual(p['analysis']['scope'], 'all_call_values')

    def test_callvalue_return_is_an_input(self):
        p = self.props(self.ret(self.entry().emit(old.CALLVALUE)))
        self.assertTrue(p['state_independent'])
        self.assertFalse(p['rejects_nonzero_value'])

    def test_positive_value_write_is_detected(self):
        code = self.entry().emit(old.CALLVALUE).target('write').emit(old.JUMPI)
        self.ret(code.push(42))
        code.label('write').emit(old.PUSH0,old.PUSH0,old.SSTORE).reject()
        p = self.props(code)
        self.assertFalse(p['read_only'], p)
        self.assertFalse(p['state_independent'])
        self.assertFalse(p['analysis']['complete'])
        self.assertIsNone(p['rejects_nonzero_value'])

    def test_symbolic_infeasible_path_is_not_a_counterexample(self):
        # Unknown calldata is intentionally outside the simple witness checker.
        code = self.entry().push(4).emit(old.CALLDATALOAD).target('write').emit(old.JUMPI)
        self.ret(code.push(42))
        code.label('write').emit(old.PUSH0,old.PUSH0,old.SSTORE,old.STOP)
        p = self.props(code)
        self.assertIsNone(p['read_only'])
        self.assertIn('SSTORE',p['analysis']['potential_effects'])

    def test_discarded_and_reverting_reads(self):
        code = self.entry().emit(old.CALLER,old.POP).push(42)
        p = self.props(self.ret(code))
        self.assertTrue(p['read_only'])
        self.assertFalse(p['state_independent'])
        code = self.entry().emit(old.CALLVALUE).target('reject').emit(old.JUMPI)
        self.ret(code.push(42))
        code.label('reject').emit(old.CALLER,old.POP).reject()
        p = self.props(code)
        self.assertFalse(p['state_independent'])

    def test_calls_are_unknown_even_with_concrete_operands(self):
        for opcode, count in [(old.CALL,7),(old.DELEGATECALL,6),(old.STATICCALL,6)]:
            code = self.entry().emit(*([old.PUSH0]*count),opcode,old.STOP)
            p = self.props(code)
            self.assertIsNone(p['read_only'])
            self.assertIsNone(p['state_independent'])
            self.assertIsNone(p['scalar_storage_getter'])

    def test_budget_none_and_separate_entry_budgets(self):
        code = self.ret(self.entry().emit(old.PUSH0,old.SLOAD))
        p = self.props(code, body_limits=a.BodyLimits(max_steps=1))
        self.assertIsNone(p['read_only'])
        self.assertIsNone(p['scalar_storage_getter'])
        self.assertIsNone(p['return_size'])
        self.assertTrue(p['analysis']['dispatch_complete'])
        self.assertFalse(p['analysis']['complete'])
        code = Assembly(); selector(code)
        compare(code, 0x12345678, 'loop');compare(code,0x87654321,'getter')
        code.reject().label('loop').emit(old.PUSH0,old.SLOAD,old.POP).target('loop').emit(old.JUMP)
        code.label('getter');self.ret(code.emit(old.PUSH0,old.SLOAD))
        _, p = properties_with_evidence(a, code.build(), body_limits=a.BodyLimits(max_steps=30))
        self.assertFalse(p[bytes.fromhex('12345678')]['analysis']['complete'])
        self.assertTrue(p[bytes.fromhex('87654321')]['scalar_storage_getter'])

    def test_rejecting_and_empty_code(self):
        self.assertEqual(a.selectors(b''),[])
        self.assertEqual(a.properties(b''),{})
        p = self.props(self.entry().reject())
        self.assertTrue(p['rejects_nonzero_value'])
        self.assertIsNone(p['read_only'])
        self.assertIsNone(p['scalar_storage_getter'])

    def test_selectors_returns_discovered_subset_without_body_pass(self):
        code = self.entry().emit(old.PUSH0,old.SLOAD,old.STOP).build()
        with patch.object(engine, 'analyze_body', side_effect=AssertionError('body pass')):
            self.assertEqual(a.selectors(code),[bytes.fromhex('12345678')])
            self.assertEqual(a.selectors(code, limits=a.DispatchLimits(max_steps=1)),[])
        partial=engine.analyze(code,limits=engine.Limits(max_states=6))
        self.assertFalse(partial.complete)
        self.assertTrue(partial.functions)
        self.assertEqual(a.selectors(code,limits=a.DispatchLimits(max_states=6)),
                         sorted({bytes.fromhex(f['selector']) for f in partial.functions}))

    def test_paths_are_emitted_to_trace(self):
        code = self.entry().emit(old.STATICCALL)
        events = []
        report = a.properties(code.build(), trace=events.append)
        evidence = next(event for event in events if event['kind'] == 'function_analysis')
        self.assertTrue(evidence['outcomes'])
        self.assertNotIn('analysis', report[bytes.fromhex('12345678')])
        self.assertIn('null', json.dumps(report.to_dict()))

    def test_limit_and_type_validation(self):
        for fun in (a.selectors,a.properties):
            with self.assertRaises(TypeError):fun('6000')
            with self.assertRaises(TypeError):fun(b'', origin=True)
            with self.assertRaises(TypeError):fun(b'', origin=1.0)
            with self.assertRaises(ValueError):fun(b'', origin=-1)
            with self.assertRaises(ValueError):fun(b'', origin=1)
            with self.assertRaises(ValueError):fun(b'',limits=a.DispatchLimits(max_states=0))
        with self.assertRaises(ValueError):a.properties(b'',body_limits=a.BodyLimits(max_steps=0))

    def test_origin_analyzes_suffix_as_separate_program(self):
        code = self.ret(self.entry().emit(old.PUSH0, old.SLOAD)).build()
        prefix = bytes.fromhex('615678600039')
        embedded = prefix + code
        origin = len(prefix)

        self.assertEqual(a.selectors(embedded, origin=origin), a.selectors(code))
        self.assertEqual(a.selectors(embedded, origin=origin), a.selectors(code))
        self.assertEqual(a.properties(embedded, origin=origin), a.properties(code))
        self.assertEqual(engine.analyze(embedded, origin=origin,
                                        body_limits=a.BodyLimits()).to_dict(),
                         engine.analyze(code, body_limits=a.BodyLimits()).to_dict())
        self.assertEqual(a.properties(embedded, origin=len(embedded)), {})

    def test_symbolic_codesize_splits_length_check_and_stops_on_copied_data(self):
        code = Assembly().push(64).emit(old.CODESIZE, old.SUB, old.DUP1)
        code.push(64).push(128).emit(old.CODECOPY)
        code.push(32).emit(old.DUP2, old.LT, old.ISZERO).target('enough').emit(old.JUMPI)
        code.reject().label('enough').emit(old.POP).push(128).emit(old.MLOAD, old.STOP)
        events = []
        result = a.properties(code.build(), trace=events.append)
        route = next(route for route in events[-1]['routes'] if route['category'] == 'empty')
        self.assertEqual(route['behavior'], 'unknown')
        self.assertEqual({outcome['reason'] for outcome in route['outcomes']},
                         {'REVERT', 'codecopied_data_access'})
        self.assertTrue(any('codesize' in condition
                            for outcome in route['outcomes']
                            for condition in outcome['conditions']))

    def test_opaque_codecopy_can_flow_to_return_without_being_read(self):
        code = Assembly().push(32).push(100).push(0).emit(old.CODECOPY)
        code.push(32).push(0).emit(old.RETURN)
        events = []
        result = a.properties(code.build(), trace=events.append)
        route = next(route for route in events[-1]['routes'] if route['category'] == 'empty')
        self.assertEqual(route['behavior'], 'reaches_code')
        self.assertEqual({outcome['kind'] for outcome in route['outcomes']}, {'return'})

    def test_codesize_occurrences_share_one_symbolic_value(self):
        code = Assembly().emit(old.CODESIZE, old.CODESIZE, old.EQ)
        code.target('same').emit(old.JUMPI).reject().label('same').emit(old.STOP)
        events = []
        result = a.properties(code.build(), trace=events.append)
        route = next(route for route in events[-1]['routes'] if route['category'] == 'empty')
        self.assertEqual(route['behavior'], 'reaches_code')
        self.assertEqual({outcome['kind'] for outcome in route['outcomes']}, {'stop'})

    def test_msize_is_fresh_after_symbolic_memory_expansion(self):
        code = Assembly().emit(old.CODESIZE).push(100).push(0).emit(old.CODECOPY)
        code.emit(old.MSIZE, old.MSIZE, old.EQ).target('equal').emit(old.JUMPI)
        code.reject().label('equal').emit(old.STOP)
        events = []
        result = a.properties(code.build(), trace=events.append)
        route = next(route for route in events[-1]['routes'] if route['category'] == 'empty')
        self.assertEqual(route['behavior'], 'reaches_code')
        self.assertEqual({outcome['kind'] for outcome in route['outcomes']},
                         {'revert', 'stop'})

    def test_compiler_fixtures_and_public_selector_results(self):
        for file in Path(__file__).with_name('fixtures').glob('*.hex'):
            with self.subTest(fixture=file.name):
                code=bytes.fromhex(file.read_text())
                before=engine.analyze(code)
                self.assertEqual(a.selectors(code),sorted({bytes.fromhex(f['selector']) for f in before.functions}))
                if file.name.startswith('solidity'):
                    expected=json.loads(file.with_suffix('.expected.json').read_text())
                    sel=bytes.fromhex(expected['method_identifiers']['saved()'].removeprefix('0x').zfill(8))
                    p=a.properties(code)[sel]
                    self.assertTrue(p['scalar_storage_getter'],p)
                    self.assertTrue(p['rejects_nonzero_value'])

    def test_duplicate_selector_entries_are_merged(self):
        code=Assembly().emit(old.CALLVALUE).target('positive').emit(old.JUMPI)
        selector(code);compare(code,0x12345678,'zero_body');code.reject()
        code.label('positive');selector(code);compare(code,0x12345678,'positive_body');code.reject()
        code.label('zero_body');self.ret(code.push(42))
        code.label('positive_body').emit(old.PUSH0,old.PUSH0,old.SSTORE,old.STOP)
        raw=engine.analyze(code.build(),body_limits=a.BodyLimits())
        self.assertEqual(len(raw.functions),2)
        props=a.properties(code.build())
        self.assertEqual(len(props),1)
        p=props[bytes.fromhex('12345678')]
        self.assertFalse(p['read_only'])
        self.assertIsNone(p['return_size'])
        self.assertEqual(a.selectors(code.build()),list(props))

    def test_different_return_lengths_and_incomplete_dispatch(self):
        code=self.entry().emit(old.CALLVALUE).target('empty').emit(old.JUMPI)
        self.ret(code.push(42));code.label('empty').emit(old.STOP)
        p=self.props(code)
        self.assertTrue(p['read_only'])
        self.assertTrue(p['state_independent'])
        self.assertIsNone(p['return_size'])
        self.assertFalse(p['scalar_storage_getter'])
        p=self.props(code,limits=a.DispatchLimits(max_states=6))
        self.assertFalse(p['analysis']['complete'])
        self.assertIsNone(p['read_only'])

    def test_budget_summary_union_cannot_inherit_a_witness(self):
        vm=engine.BodyInterpreter(b'',engine.Limits(max_states=1))
        state=engine.State(selector=0x12345678,dispatch_entry=0)
        vm.record_state_budget(state)
        unknown=state.fork()
        unknown.reads=frozenset({engine.CALLER})
        unknown.predicates=((engine.Expr(engine.CALLER),True),)
        vm.record_state_budget(unknown)
        self.assertIn('CALLER',vm.outcomes[0]['reads'])
        self.assertFalse(vm.outcomes[0]['witnessed'])
        self.assertFalse(vm.outcomes[0]['witnessed_nonzero'])

    def test_module_import_has_no_third_party_dependency(self):
        script = ('import sys; sys.path.insert(0, '+repr(str(Path(a.__file__).resolve().parent.parent))+'); '
                  'from ethutils.analysis import selectors; assert selectors(b"\\x00") == []')
        subprocess.run([sys.executable,'-S','-B','-c',script],check=True,capture_output=True)


class EngineScopeTests(unittest.TestCase):
    def dispatch(self, opcode=old.EQ, invert=False):
        code = Assembly()
        selector(code).push(0x12345678).emit(opcode)
        if invert:
            code.emit(old.ISZERO)
        mismatch = (opcode != old.EQ) != invert
        code.target('reject' if mismatch else 'function').emit(old.JUMPI)
        if mismatch:
            code.emit(old.PUSH0, old.SLOAD, old.STOP).label('reject').reject()
        else:
            code.reject().label('function').emit(old.PUSH0, old.SLOAD, old.STOP)
        return code.build()

    def test_stops_matching_child_for_both_jump_polarities(self):
        for opcode in (old.EQ, old.SUB, old.XOR):
            for invert in (False, True):
                with self.subTest(opcode=opcodes.INFO[opcode].name, invert=invert):
                    code = self.dispatch(opcode, invert)
                    result = engine.analyze(code, stop_at_selected_entry=True,
                                            include_short_calldata_routes=False)
                    self.assertTrue(result.complete, result.issues)
                    self.assertEqual([f['selector'] for f in result.functions], ['12345678'])
                    outcomes = result.functions[0]['outcomes']
                    self.assertTrue(outcomes)
                    self.assertTrue(all(o['kind'] == 'selected_entry' for o in outcomes))
                    self.assertEqual(result.functions[0]['value_policy'], 'unknown')
                    baseline = engine.analyze(code)
                    self.assertTrue(any(o['reason'] == 'SLOAD'
                                        for o in baseline.functions[0]['outcomes']))

    def test_binary_partition_branches_are_both_explored(self):
        code = Assembly()
        selector(code).emit(old.DUP1).push(0x80000000).emit(old.GT).target('low').emit(old.JUMPI)
        compare(code, 0x90000000, 'f1')
        code.reject().label('low')
        compare(code, 0x12345678, 'f2')
        code.reject().label('f1').emit(old.STOP).label('f2').emit(old.STOP)
        result = engine.analyze(code.build(), stop_at_selected_entry=True,
                                include_short_calldata_routes=False)
        self.assertEqual({f['selector'] for f in result.functions}, {'12345678', '90000000'})
        self.assertTrue(result.complete)

    def test_skipping_short_routes_changes_only_requested_input_lengths(self):
        code = opcodes.PUSH0 + opcodes.POP + opcodes.STOP
        defaults = engine.analyze(code)
        explicit = engine.analyze(code, stop_at_selected_entry=False,
                                  include_short_calldata_routes=True)
        long_only = engine.analyze(code, include_short_calldata_routes=False)
        self.assertEqual(defaults.to_dict(), explicit.to_dict())
        self.assertEqual(defaults.statistics['instructions_executed'], 15)
        self.assertEqual(long_only.statistics['instructions_executed'], 3)
        self.assertTrue(all(r['outcomes'] for r in defaults.routes))
        self.assertTrue(all(not r['outcomes'] for r in long_only.routes if r['category'] != 'unmatched'))
        self.assertEqual(long_only.routes[-1], defaults.routes[-1])

    def test_selected_loop_is_an_intentional_boundary_not_budget_exhaustion(self):
        code = Assembly()
        selector(code); compare(code, 0x12345678, 'loop')
        code.reject().label('loop').target('loop').emit(old.JUMP)
        limits = a.DispatchLimits(initial_path_budget=64, max_path_budget=64)
        baseline = engine.analyze(code.build(), limits=limits)
        selected = engine.analyze(code.build(), limits=limits, stop_at_selected_entry=True)
        self.assertFalse(baseline.complete)
        self.assertTrue(any(i['reason'] == 'path_budget' for i in baseline.issues))
        self.assertTrue(selected.complete)
        self.assertEqual(selected.issues, [])
        self.assertTrue(all(r['outcomes'] for r in selected.routes))
        self.assertEqual(limits.initial_path_budget, 64)
        self.assertEqual(limits.max_path_budget, 64)

    def test_public_functions_choose_scope_without_changing_supplied_limits(self):
        code = self.dispatch()
        limits = a.DispatchLimits(max_steps=1000, trace_length=0)
        with patch.object(engine, 'analyze', wraps=engine.analyze) as analyze:
            a.selectors(code, limits=limits)
            kwargs = analyze.call_args.kwargs
            self.assertIs(kwargs['limits'], limits)
            self.assertIs(kwargs['stop_at_selected_entry'], True)
            self.assertIs(kwargs['include_short_calldata_routes'], False)
        with patch.object(engine, 'analyze', wraps=engine.analyze) as analyze:
            a.properties(code, limits=limits)
            kwargs = analyze.call_args.kwargs
            self.assertIs(kwargs['limits'], limits)
            self.assertNotIn('stop_at_selected_entry', kwargs)
            self.assertNotIn('include_short_calldata_routes', kwargs)
        self.assertEqual(limits.max_steps, 1000)

    def test_scope_parameters_are_forwarded_to_body_seed_dispatcher(self):
        code = self.dispatch()
        result = engine.analyze(code, body_limits=a.BodyLimits(),
                                stop_at_selected_entry=True,
                                include_short_calldata_routes=False)
        self.assertTrue(all(o['kind'] == 'selected_entry'
                            for f in result.functions for o in f['outcomes']))
        self.assertTrue(all(not r['outcomes'] for r in result.routes if r['category'] != 'unmatched'))
        self.assertTrue(result.functions[0]['body_analysis']['complete'])
        self.assertIn('SLOAD', result.functions[0]['body_analysis']['reads'])


class LibraryAddressBranchTests(unittest.TestCase):
    library_address = 0x1234567890123456789012345678901234567890
    view_selector = bytes.fromhex('11223344')
    restricted_selector = bytes.fromhex('55667788')

    def return_constant(self, code):
        return code.push(7).emit(old.PUSH0, old.MSTORE).push(32).emit(old.PUSH0, old.RETURN)

    def mixed_library(self):
        # Branch before any selector comparison: directly called libraries
        # expose the view function; delegated execution can use both functions.
        code = Assembly().push(self.library_address, 20).emit(old.ADDRESS, old.EQ)
        code.target('direct').emit(old.JUMPI)
        selector(code)
        compare(code, int.from_bytes(self.view_selector, 'big'), 'view')
        compare(code, int.from_bytes(self.restricted_selector, 'big'), 'restricted')
        code.reject().label('direct')
        selector(code)
        compare(code, int.from_bytes(self.view_selector, 'big'), 'view')
        code.reject().label('view')
        self.return_constant(code)
        code.label('restricted').emit(old.PUSH0, old.PUSH0, old.SSTORE, old.STOP)
        return code.build()

    def concrete_address(self, address):
        return patch.dict(engine.OPERATIONS, {
            engine.ADDRESS: engine.Operation(engine.ADDRESS, lambda ctx: ctx.push(address))})

    def test_symbolic_address_before_dispatch_discovers_both_contexts(self):
        code = self.mixed_library()
        result = engine.analyze(code, stop_at_selected_entry=True,
                                include_short_calldata_routes=False)
        self.assertTrue(result.complete, result.issues)
        self.assertEqual(a.selectors(code), [self.view_selector, self.restricted_selector])
        functions = {f['selector']: f for f in result.functions}
        self.assertEqual(len(functions[self.view_selector.hex()]['outcomes']), 2)
        self.assertEqual(len(functions[self.restricted_selector.hex()]['outcomes']), 1)
        self.assertTrue(all(o['kind'] == 'selected_entry'
                            for f in result.functions for o in f['outcomes']))
        self.assertFalse(any(i['reason'] == 'contract_specific_condition_before_dispatch'
                             for i in result.issues))

    def test_concrete_direct_and_delegated_contexts(self):
        code = self.mixed_library()
        for address, expected in (
                (self.library_address, [self.view_selector]),
                (self.library_address + 1, [self.view_selector, self.restricted_selector])):
            with self.subTest(address=address), self.concrete_address(address):
                self.assertEqual(a.selectors(code), expected)
                _, props = properties_with_evidence(a, code)
                self.assertEqual(list(props), expected)
                self.assertTrue(props[self.view_selector]['read_only'])
                self.assertEqual(props[self.view_selector]['return_size'], 32)
                if self.restricted_selector in props:
                    self.assertFalse(props[self.restricted_selector]['read_only'])
                    self.assertEqual(props[self.restricted_selector]['analysis']['potential_effects'], ['SSTORE'])

    def test_properties_keep_address_evidence_and_unresolved_context(self):
        _, props = properties_with_evidence(a, self.mixed_library())
        self.assertEqual(list(props), [self.view_selector, self.restricted_selector])
        self.assertTrue(props[self.view_selector]['analysis']['complete'])
        self.assertTrue(props[self.view_selector]['read_only'])
        self.assertIn('ADDRESS', props[self.view_selector]['analysis']['reads'])
        # A write behind a symbolic address condition remains potential evidence,
        # since the simple witness checker does not certify address predicates.
        restricted = props[self.restricted_selector]
        self.assertIsNone(restricted['read_only'])
        self.assertIn('SSTORE', restricted['analysis']['potential_effects'])

    def test_cached_library_flag_is_checked_only_on_restricted_entry(self):
        # The usual library layout computes a flag before shared dispatch and
        # tests it inside non-view entries. The view entry discards that flag.
        code = Assembly().push(self.library_address, 20).emit(old.ADDRESS, old.EQ)
        selector(code)
        compare(code, int.from_bytes(self.view_selector, 'big'), 'view')
        compare(code, int.from_bytes(self.restricted_selector, 'big'), 'restricted')
        code.reject().label('view').emit(old.POP, old.POP)
        self.return_constant(code)
        code.label('restricted').emit(old.POP).target('reject').emit(old.JUMPI)
        code.emit(old.PUSH0, old.PUSH0, old.SSTORE, old.STOP).label('reject').reject()
        bytecode = code.build()
        self.assertEqual(a.selectors(bytecode), [self.view_selector, self.restricted_selector])
        for address, rejects in ((self.library_address, True), (self.library_address+1, False)):
            with self.subTest(address=address), self.concrete_address(address):
                # Selector extraction includes an entry even if its guard later
                # rejects in this context; full analysis observes that guard.
                self.assertEqual(a.selectors(bytecode), [self.view_selector, self.restricted_selector])
                result = engine.analyze(bytecode)
                functions = {f['selector']: f for f in result.functions}
                self.assertEqual(functions[self.restricted_selector.hex()]['value_policy'] == 'always_rejects', rejects)
                self.assertTrue(any(o['kind'] == 'return'
                                    for o in functions[self.view_selector.hex()]['outcomes']))

    def test_contradictory_address_checks_do_not_add_selectors(self):
        code = Assembly().push(self.library_address, 20).emit(old.ADDRESS, old.EQ)
        code.target('direct').emit(old.JUMPI).reject().label('direct')
        code.push(self.library_address, 20).emit(old.ADDRESS, old.EQ, old.ISZERO)
        code.target('impossible').emit(old.JUMPI)
        selector(code); compare(code, int.from_bytes(self.view_selector, 'big'), 'view')
        code.reject().label('impossible')
        selector(code); compare(code, 0xdeadbeef, 'restricted')
        code.reject().label('view').emit(old.STOP).label('restricted').emit(old.STOP)
        self.assertEqual(a.selectors(code.build()), [self.view_selector])

    def test_general_prologue_still_stops_at_post_selection_address_branch(self):
        code = Assembly()
        selector(code); compare(code, int.from_bytes(self.view_selector, 'big'), 'view')
        code.reject().label('view').emit(old.ADDRESS).target('end').emit(old.JUMPI, old.STOP)
        code.label('end').emit(old.STOP)
        result = engine.analyze(code.build())
        outcomes = result.functions[0]['outcomes']
        self.assertTrue(any(o['kind'] == 'body' and o['reason'] == 'contract_specific_condition'
                            for o in outcomes))


class DelegatecallOnlyTests(unittest.TestCase):
    address = LibraryAddressBranchTests.library_address
    view = bytes.fromhex('11223344')
    protected = bytes.fromhex('55667788')
    unrelated = bytes.fromhex('99aabbcc')

    def return_constant(self, code):
        return code.push(7).emit(old.PUSH0, old.MSTORE).push(32).emit(old.PUSH0, old.RETURN)

    def mixed_code(self, *, via_ir=False, inverted=False, address=None,
                   extra_address_check=False, unlinked=False, prefix_extra=False,
                   rejecting_guard=True, delegate_reverts=False):
        address = self.address if address is None else address
        if unlinked:
            address = 0
        code = Assembly()
        if prefix_extra:
            code.emit(old.JUMPDEST)
        if via_ir:
            code.push(128).push(64).emit(old.MSTORE, old.ADDRESS).push(address, 32).emit(old.EQ)
        else:
            code.push(address, 20).emit(old.ADDRESS, old.EQ)
        selector(code)
        compare(code, int.from_bytes(self.view, 'big'), 'view')
        compare(code, int.from_bytes(self.protected, 'big'), 'protected')
        if extra_address_check:
            compare(code, int.from_bytes(self.unrelated, 'big'), 'unrelated')
        code.reject().label('view').emit(old.POP, old.POP)
        self.return_constant(code)
        if extra_address_check:
            code.label('unrelated').emit(old.POP, old.POP, old.ADDRESS)
            code.push(address + 1, 20).emit(old.EQ).target('reject').emit(old.JUMPI)
            self.return_constant(code)
        code.label('protected').emit(old.POP)
        if inverted:
            code.emit(old.ISZERO).target('allowed').emit(old.JUMPI)
            code.reject() if rejecting_guard else code.emit(old.STOP)
            code.label('allowed')
        else:
            code.target('reject').emit(old.JUMPI)
        if delegate_reverts:
            code.reject()
        else:
            code.emit(old.PUSH0, old.PUSH0, old.SSTORE, old.STOP)
        code.label('reject')
        code.reject() if rejecting_guard else code.emit(old.STOP)
        return code.build()

    def test_legacy_and_via_ir_mixed_libraries(self):
        for via_ir in (False, True):
            for inverted in (False, True):
                with self.subTest(via_ir=via_ir, inverted=inverted):
                    code = self.mixed_code(via_ir=via_ir, inverted=inverted)
                    _, props = properties_with_evidence(a, code)
                    self.assertEqual(a.selectors(code), [self.view, self.protected])
                    self.assertIs(props[self.view]['delegatecall_only'], False)
                    self.assertIs(props[self.protected]['delegatecall_only'], True)
                    # Entry eligibility survives an incomplete body analysis:
                    # the bounded body interpreter stops at the storage write.
                    self.assertFalse(props[self.protected]['analysis']['complete'])

    def test_unrelated_address_check_in_recognized_library_is_unknown(self):
        props = a.properties(self.mixed_code(extra_address_check=True))
        self.assertIs(props[self.view]['delegatecall_only'], False)
        self.assertIs(props[self.protected]['delegatecall_only'], True)
        self.assertIsNone(props[self.unrelated]['delegatecall_only'])

    def test_predispatch_address_gate_is_not_assumed_to_be_a_library_guard(self):
        props = a.properties(LibraryAddressBranchTests().mixed_library())
        self.assertTrue(props)
        self.assertTrue(all(p['delegatecall_only'] is None for p in props.values()))

    def test_ordinary_function_and_unused_library_shaped_prefix_are_unknown(self):
        code = Assembly()
        selector(code); compare(code, int.from_bytes(self.view, 'big'), 'view')
        code.reject().label('view')
        self.return_constant(code)
        self.assertIsNone(a.properties(code.build())[self.view]['delegatecall_only'])
        code = Assembly().push(self.address, 20).emit(old.ADDRESS, old.EQ)
        selector(code); compare(code, int.from_bytes(self.view, 'big'), 'view')
        code.reject().label('view').emit(old.POP, old.POP)
        self.return_constant(code)
        # Prefix alone provides no corroborating call-protection guard.
        self.assertIsNone(a.properties(code.build())[self.view]['delegatecall_only'])

    def test_unlinked_unsupported_and_nonrejecting_layouts_are_unknown(self):
        for options in ({'unlinked': True}, {'prefix_extra': True},
                        {'rejecting_guard': False}, {'delegate_reverts': True}):
            with self.subTest(options=options):
                props = a.properties(self.mixed_code(**options))
                self.assertTrue(all(p['delegatecall_only'] is None for p in props.values()))

    def test_probe_budget_exhaustion_is_unknown(self):
        props = a.properties(self.mixed_code(), body_limits=a.BodyLimits(max_steps=1))
        self.assertTrue(all(p['delegatecall_only'] is None for p in props.values()))

    def test_incomplete_dispatch_cannot_establish_delegatecall_only(self):
        _, props = properties_with_evidence(
            a, self.mixed_code(), limits=a.DispatchLimits(max_steps=22))
        self.assertIn(self.protected, props)
        self.assertFalse(props[self.protected]['analysis']['dispatch_complete'])
        self.assertIsNone(props[self.protected]['delegatecall_only'])

    def test_unrecognized_flag_transformation_is_unknown(self):
        code = Assembly().push(self.address, 20).emit(old.ADDRESS, old.EQ)
        selector(code)
        compare(code, int.from_bytes(self.view, 'big'), 'unknown')
        compare(code, int.from_bytes(self.protected, 'big'), 'protected')
        code.reject().label('unknown').emit(old.POP).push(0).emit(old.XOR)
        code.target('reject').emit(old.JUMPI)
        self.return_constant(code)
        code.label('protected').emit(old.POP).target('reject').emit(old.JUMPI)
        code.emit(old.PUSH0, old.PUSH0, old.SSTORE, old.STOP).label('reject').reject()
        props = a.properties(code.build())
        self.assertIs(props[self.protected]['delegatecall_only'], True)
        self.assertIsNone(props[self.view]['delegatecall_only'])

    def test_unknown_is_json_null(self):
        value = a.properties(self.mixed_code(unlinked=True))[self.protected]['delegatecall_only']
        self.assertEqual(json.dumps({'delegatecall_only': value}), '{"delegatecall_only": null}')

    def test_multiple_entries_for_same_selector_merge_conservatively(self):
        # CALLVALUE chooses two dispatchers. The same selector has both a
        # protected entry and an unprotected entry in a recognized library.
        code = Assembly().push(self.address, 20).emit(old.ADDRESS, old.EQ)
        code.emit(old.CALLVALUE).target('second').emit(old.JUMPI)
        selector(code); compare(code, int.from_bytes(self.view, 'big'), 'view')
        code.reject().label('second')
        selector(code); compare(code, int.from_bytes(self.view, 'big'), 'protected')
        compare(code, int.from_bytes(self.protected, 'big'), 'protected')
        code.reject().label('view').emit(old.POP, old.POP)
        self.return_constant(code)
        code.label('protected').emit(old.POP).target('reject').emit(old.JUMPI)
        code.emit(old.PUSH0, old.PUSH0, old.SSTORE, old.STOP).label('reject').reject()
        props = a.properties(code.build())
        self.assertIs(props[self.view]['delegatecall_only'], False)
        self.assertIs(props[self.protected]['delegatecall_only'], True)


if __name__=='__main__':unittest.main()
