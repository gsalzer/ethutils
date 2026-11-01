import unittest
import json
import gc
import weakref
from pathlib import Path
from unittest.mock import patch
from ethutils._engine import symbolic as e
from ethutils import parse_hex, opcodes as op
from tests.helpers import Assembly, selector, compare, length_guard, guard, raw_bytes

def functions(result):
    return {f['selector']: f for f in result.functions}

class DispatcherTests(unittest.TestCase):

    def test_solidity_global_guard(self):
        a = Assembly()
        guard(a, 'dispatch')
        length_guard(a)
        selector(a)
        compare(a, 305419896, 'f')
        a.label('fallback').reject().label('f').emit(op.STOP)
        r = e.analyze(a.build())
        self.assertTrue(r.complete)
        f = functions(r)['12345678']
        self.assertEqual(f['entry_pc'], a.labels['f'])
        self.assertEqual(f['value_policy'], 'nonzero_rejected')
        self.assertTrue(all((route['value_policy'] == 'always_rejects' for route in r.routes)))

    def test_mixed_payability_and_receive(self):
        a = Assembly().emit(op.CALLDATASIZE, op.ISZERO).target('receive').emit(op.JUMPI)
        length_guard(a)
        selector(a)
        compare(a, 287454020, 'nonpayable')
        compare(a, 1432778632, 'payable')
        a.label('fallback').reject().label('nonpayable')
        guard(a, 'body')
        a.emit(op.PUSH0, op.SLOAD, op.STOP).label('payable').emit(op.STOP).label('receive').emit(op.STOP)
        r = e.analyze(a.build())
        self.assertEqual(functions(r)['11223344']['value_policy'], 'nonzero_rejected')
        self.assertEqual(functions(r)['55667788']['value_policy'], 'no_value_guard_observed')
        self.assertEqual(r.routes[0]['value_policy'], 'no_value_guard_observed')
        self.assertEqual(r.routes[-1]['value_policy'], 'always_rejects')

    def test_binary_tree_and_zero_selector(self):
        a = Assembly()
        length_guard(a)
        selector(a).emit(op.DUP1).push(2147483648).emit(op.GT).target('low').emit(op.JUMPI)
        compare(a, 4275878552, 'high')
        a.target('fallback').emit(op.JUMP).label('low')
        compare(a, 0, 'zero')
        a.label('fallback').reject().label('high').emit(op.STOP).label('zero').emit(op.STOP)
        r = e.analyze(a.build())
        self.assertEqual(set(functions(r)), {'00000000', 'fedcba98'})

    def test_inverted_xor_fallthrough(self):
        a = Assembly()
        length_guard(a)
        selector(a).push(305419896).emit(op.XOR).target('fallback').emit(op.JUMPI)
        entry = len(a.code)
        a.emit(op.STOP).label('fallback').reject()
        f = functions(e.analyze(a.build()))['12345678']
        self.assertEqual(f['entry_pc'], entry)

    def test_division_selector(self):
        a = Assembly()
        length_guard(a)
        a.push(1 << 224, 29).emit(op.PUSH0, op.CALLDATALOAD, op.DIV)
        compare(a, 2882400001, 'f')
        a.label('fallback').reject().label('f').emit(op.STOP)
        self.assertEqual(set(functions(e.analyze(a.build()))), {'abcdef01'})

    def test_calldatacopy_selector(self):
        a = Assembly()
        length_guard(a)
        a.push(4).emit(op.PUSH0).push(28).emit(op.CALLDATACOPY, op.PUSH0, op.MLOAD)
        compare(a, 2864434397, 'f')
        a.label('fallback').reject().label('f').emit(op.STOP)
        self.assertEqual(set(functions(e.analyze(a.build()))), {'aabbccdd'})

    def test_calldataload_memory_roundtrip(self):
        a = Assembly()
        length_guard(a)
        a.emit(op.PUSH0, op.CALLDATALOAD).push(64).emit(op.MSTORE).push(64).emit(op.MLOAD)
        a.push(224).emit(op.SHR)
        compare(a, 42, 'f')
        a.label('fallback').reject().label('f').emit(op.STOP)
        self.assertEqual(set(functions(e.analyze(a.build()))), {'0000002a'})

    def test_short_calldata_zero_padding(self):
        a = Assembly()
        selector(a)
        compare(a, 287454020, 'f')
        a.reject().label('f').emit(op.STOP)
        r = e.analyze(a.build())
        for route in r.routes[:4]:
            self.assertEqual(route['value_policy'], 'always_rejects')

    def test_argument_condition_stops(self):
        a = Assembly()
        length_guard(a)
        selector(a)
        compare(a, 1, 'f')
        a.label('fallback').reject().label('f').push(4).emit(op.CALLDATALOAD)
        a.target('end').emit(op.JUMPI).reject().label('end').emit(op.STOP)
        r = e.analyze(a.build())
        self.assertTrue(r.complete)
        self.assertEqual(functions(r)['00000001']['outcomes'][0]['reason'], 'argument_calldata')

    def test_nonstandard_value_guard_is_conditional(self):
        a = Assembly()
        length_guard(a)
        selector(a)
        compare(a, 3, 'f')
        a.label('fallback').reject().label('f').push(10).emit(op.CALLVALUE, op.LT)
        a.target('fail').emit(op.JUMPI, op.STOP).label('fail').reject()
        self.assertEqual(functions(e.analyze(a.build()))['00000003']['value_policy'], 'conditional')

    def test_jumpdest_inside_push_is_invalid(self):
        r = e.analyze(raw_bytes([op.PUSH1, op.JUMPDEST, op.PUSH1, 1, op.JUMP]))
        self.assertTrue(all((o['kind'] == 'exception' for route in r.routes for o in route['outcomes'])))

    def test_untaken_jump_does_not_resolve_target(self):
        r = e.analyze(raw_bytes([op.PUSH0, op.CALLER, op.JUMPI, op.STOP]))
        self.assertTrue(r.complete)

    def test_budgets_are_reported(self):
        r = e.analyze(raw_bytes([op.JUMPDEST, op.PUSH0, op.JUMP]), limits=e.Limits(max_steps=10))
        self.assertFalse(r.complete)
        self.assertEqual(r.statistics['instructions_executed'], 10)
        self.assertTrue(all((i['reason'] == 'instruction_budget' for i in r.issues)))

    def test_selector_discovery_precedes_expensive_short_routes_and_prologues(self):
        a = Assembly()
        length_guard(a)
        selector(a)
        compare(a, 305419896, 'first')
        compare(a, 2271560481, 'second')
        a.emit(op.STOP)
        a.label('fallback').target('fallback').emit(op.JUMP)
        a.label('first').target('first').emit(op.JUMP)
        a.label('second').emit(op.STOP)
        result = e.analyze(a.build(), limits=e.Limits(max_steps=100))
        self.assertEqual(set(functions(result)), {'12345678', '87654321'})
        self.assertFalse(result.complete)
        self.assertEqual(result.statistics['instructions_executed'], 100)
        self.assertTrue(any((i['category'] == 'short_1' for i in result.issues)))

    def test_loop_runs_until_path_budget(self):
        r = e.analyze(raw_bytes([op.JUMPDEST, op.PUSH0, op.JUMP]), limits=e.Limits(initial_path_budget=12))
        self.assertEqual(r.statistics['instructions_executed'], 60)
        self.assertEqual(len(r.issues), 5)
        self.assertTrue(all((i['reason'] == 'path_budget' for i in r.issues)))

    def test_total_instruction_budget_is_disabled_by_default(self):
        self.assertIsNone(e.Limits().max_steps)
        result = e.analyze(raw_bytes([op.JUMPDEST, op.PUSH0, op.JUMP]), limits=e.Limits(initial_path_budget=21000, max_path_budget=21000))
        self.assertEqual(result.statistics['instructions_executed'], 105000)
        self.assertTrue(all((i['reason'] == 'path_budget' for i in result.issues)))

    def test_address_enumeration_stops_constructing_states_at_budget(self):
        from unittest.mock import patch
        interpreter = e.Interpreter(b'', e.Limits(max_states=2))
        state = e.State()
        address = e.Expr(op.MOD, (e.SEL, 256))
        with patch.object(state, 'fork', wraps=state.fork) as fork:
            with self.assertRaises(e.Halt) as halted:
                interpreter.address(state, address, 'jump_target')
        self.assertEqual(halted.exception.reason, 'rescheduled')
        self.assertEqual(fork.call_count, 2)
        self.assertEqual(interpreter.states, 2)
        self.assertEqual(len(interpreter.issues), 1)
        self.assertEqual(interpreter.issues[0]['reason'], 'state_budget')
        for _ in range(100):
            interpreter.enqueue(state)
        self.assertEqual(len(interpreter.outcomes), 1)
        self.assertEqual(interpreter.outcomes[0]['budget_events'], 101)

    def test_unknown_jump_not_silently_followed(self):
        r = e.analyze(raw_bytes([op.CALLER, op.JUMP]))
        self.assertFalse(r.complete)
        self.assertTrue(any(('unresolved_jump_target' in i['reason'] for i in r.issues)))

    def test_unsupported_opcode(self):
        self.assertFalse(e.analyze(raw_bytes([170])).complete)

    def test_all_log_opcodes_stop_at_body_boundary(self):
        for opcode in (op.LOG0, op.LOG1, op.LOG2, op.LOG3, op.LOG4):
            with self.subTest(opcode=opcode):
                result = e.analyze(raw_bytes([opcode]))
                self.assertTrue(result.complete)
                for route in result.routes:
                    for outcome in route['outcomes']:
                        self.assertEqual(outcome['kind'], 'body')
                        self.assertEqual(outcome['reason'], e.OP_NAMES[opcode])

    def test_unexplored_gate_before_dispatch_is_incomplete(self):
        a = Assembly().emit(op.TIMESTAMP).target('dispatch').emit(op.JUMPI).reject().label('dispatch')
        selector(a)
        compare(a, 1, 'f')
        a.reject().label('f').emit(op.STOP)
        self.assertFalse(e.analyze(a.build()).complete)

    def test_storage_and_caller_authorization_before_dispatch(self):
        a = Assembly().push(1).emit(op.SLOAD, op.CALLER, op.EQ)
        a.target('dispatch').emit(op.JUMPI).reject().label('dispatch')
        selector(a)
        compare(a, 305419896, 'f')
        a.reject().label('f').emit(op.STOP)
        result = e.analyze(a.build())
        self.assertTrue(result.complete)
        self.assertEqual(set(functions(result)), {'12345678'})

    def test_initial_storage_is_unknown_and_repeated_reads_are_consistent(self):
        a = Assembly().push(1).emit(op.SLOAD).push(7).emit(op.EQ)
        a.target('check').emit(op.JUMPI).emit(op.STOP).label('check')
        a.push(1).emit(op.SLOAD).push(7).emit(op.EQ, op.ISZERO)
        a.target('bad').emit(op.JUMPI)
        selector(a)
        compare(a, 1, 'f')
        a.reject().label('f').emit(op.STOP).label('bad').emit(170)
        result = e.analyze(a.build())
        self.assertTrue(result.complete)
        self.assertEqual(set(functions(result)), {'00000001'})

    def test_storage_is_copied_on_fork(self):
        state = e.State(storage={1: 7})
        child = state.fork()
        child.storage[1] = 8
        self.assertEqual(state.storage, {1: 7})
        self.assertEqual(child.storage, {1: 8})

    def test_unresolved_storage_slot_is_incomplete(self):
        result = e.analyze(raw_bytes([op.CALLER, op.SLOAD, op.STOP]))
        self.assertFalse(result.complete)
        self.assertTrue(all((i['reason'].startswith('unresolved_storage_slot') for i in result.issues)))

    def test_storage_still_stops_selected_function(self):
        for opcode in (op.SLOAD, op.SSTORE):
            a = Assembly()
            selector(a)
            compare(a, 1, 'f')
            a.reject().label('f').push(0).push(0).emit(opcode, 170)
            result = e.analyze(a.build())
            self.assertTrue(result.complete)
            self.assertEqual(functions(result)['00000001']['outcomes'][0]['reason'], e.OP_NAMES[opcode])

    def test_sparse_table(self):
        a = Assembly()
        length_guard(a)
        selector(a)
        a.push(2).push(2).emit(op.DUP3, op.MOD).push(1).emit(op.SHL).target('table').emit(op.ADD)
        a.push(30).emit(op.CODECOPY, op.PUSH0, op.MLOAD, op.JUMP)
        a.label('bucket0')
        compare(a, 287454020, 'f0')
        a.target('fallback').emit(op.JUMP).label('bucket1')
        compare(a, 1432778633, 'f1')
        a.label('fallback').reject().label('f0').emit(op.STOP).label('f1').emit(op.STOP)
        a.labels['table'] = len(a.code)
        a.code.extend(a.labels['bucket0'].to_bytes(2, 'big'))
        a.code.extend(a.labels['bucket1'].to_bytes(2, 'big'))
        r = e.analyze(a.build())
        self.assertTrue(r.complete, r.issues)
        self.assertEqual(set(functions(r)), {'11223344', '55667789'})

class ExecutionTests(unittest.TestCase):

    def test_registered_arithmetic_executes_evm_edge_cases(self):
        cases = [(op.ADD, (e.MASK, 1), 0), (op.MUL, (1 << 255, 2), 0), (op.SUB, (3, 5), e.MASK - 1), (op.DIV, (7, 3), 2), (op.DIV, (7, 0), 0), (op.SDIV, (1 << 255, e.MASK), 1 << 255), (op.MOD, (7, 3), 1), (op.SMOD, (e.MASK - 6, 3), e.MASK), (op.ADDMOD, (e.MASK, 1, e.MASK), 1), (op.MULMOD, (e.MASK, e.MASK, 7), 1), (op.EXP, (2, 256), 0), (op.SIGNEXTEND, (0, 128), e.MASK - 127), (op.LT, (3, 5), 1), (op.GT, (5, 3), 1), (op.SLT, (e.MASK, 0), 1), (op.SGT, (0, e.MASK), 1), (op.EQ, (2, 2), 1), (op.ISZERO, (0,), 1), (op.AND, (240, 15), 0), (op.OR, (160, 11), 171), (op.XOR, (165, 255), 90), (op.NOT, (0,), e.MASK), (op.BYTE, (0, 18 << 248), 18), (op.BYTE, (32, e.MASK), 0), (op.SHL, (256, 1), 0), (op.SHR, (224, 305419896 << 224), 305419896), (op.SAR, (256, 1 << 255), e.MASK)]
        self.assertEqual({op for op, _, _ in cases}, {op.opcode for op in e.ARITHMETIC})
        for opcode, operands, expected in cases:
            with self.subTest(opcode=e.OP_NAMES[opcode], operands=operands):
                vm = e.Interpreter(raw_bytes([opcode]), e.Limits())
                state = e.State(stack=list(reversed(operands)))
                vm.step(state)
                self.assertEqual(state.stack, [expected])
                self.assertEqual(state.pc, 1)

    def test_symbolic_operations_retain_shared_opcode_bytes(self):
        vm = e.Interpreter(raw_bytes([op.ADD]), e.Limits())
        state = e.State(stack=[1, e.SEL])
        vm.step(state)
        result = state.stack[0]
        self.assertIsInstance(result.op, bytes)
        self.assertEqual(result.op, op.ADD)
        self.assertEqual(result.args, (e.SEL, 1))
        self.assertEqual(e.dependencies(result), {e.SELECTOR})
        self.assertEqual(e.format_word(result), 'add(selector, 0x1)')

    def test_dup16_requires_depth_but_consumes_nothing(self):
        vm = e.Interpreter(raw_bytes([op.DUP16]), e.Limits())
        state = e.State(stack=list(range(1, 17)))
        vm.step(state)
        self.assertEqual(state.stack, list(range(1, 17)) + [1])
        with self.assertRaises(e.Halt) as error:
            vm.step(e.State(stack=list(range(15))))
        self.assertEqual(error.exception.reason, 'stack_underflow')

    def test_swap16_changes_positions_without_changing_depth(self):
        vm = e.Interpreter(raw_bytes([op.SWAP16]), e.Limits())
        state = e.State(stack=list(range(1, 18)))
        vm.step(state)
        self.assertEqual(state.stack, [17] + list(range(2, 17)) + [1])
        with self.assertRaises(e.Halt) as error:
            vm.step(e.State(stack=list(range(16))))
        self.assertEqual(error.exception.reason, 'stack_underflow')

    def test_metadata_checks_depth_before_handler_side_effects(self):
        vm = e.Interpreter(raw_bytes([op.MSTORE]), e.Limits())
        state = e.State(stack=[e.Expr(op.CALLER)])
        with self.assertRaises(e.Halt) as error:
            vm.step(state)
        self.assertEqual(error.exception.reason, 'stack_underflow')
        self.assertEqual(state.stack, [e.Expr(op.CALLER)])
        self.assertEqual(state.memory, {})

    def test_mcopy_handler_preserves_overlapping_source(self):
        vm = e.Interpreter(raw_bytes([op.MCOPY]), e.Limits())
        state = e.State(stack=[3, 0, 1], memory={0: 1, 1: 2, 2: 3})
        vm.step(state)
        self.assertEqual(state.memory, {0: 1, 1: 1, 2: 2, 3: 3})
        self.assertEqual(state.stack, [])

    def test_operand_order_and_wraparound(self):
        self.assertEqual(e.concrete(op.SUB, (3, 5)), e.MASK - 1)
        self.assertEqual(e.concrete(op.DIV, (100, 3)), 33)
        self.assertEqual(e.concrete(op.LT, (3, 5)), 1)
        self.assertEqual(e.concrete(op.SHR, (224, 305419896 << 224)), 305419896)
        self.assertEqual(e.concrete(op.SDIV, (e.MASK - 6, 3)), e.MASK - 1)

    def test_overlapping_memory_and_zero_initialization(self):
        interpreter = e.Interpreter(b'', e.Limits())
        s = e.State()
        self.assertEqual(interpreter.load_memory(s, 0), 0)
        s.memory[31] = 18
        s.memory[32] = 52
        self.assertEqual(interpreter.load_memory(s, 0), 18)
        self.assertEqual(interpreter.load_memory(s, 1), 4660)

    def test_parse_hex(self):
        self.assertEqual(parse_hex('0x60 01\n00'), raw_bytes([96, 1, 0]))
        with self.assertRaises(ValueError):
            parse_hex('abc')

    def test_empty_code(self):
        r = e.analyze(b'')
        self.assertTrue(r.complete)
        self.assertEqual(r.functions, [])
        self.assertEqual(r.routes[0]['value_policy'], 'no_value_guard_observed')

class CompilerFixtureTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.fixtures = []
        for file in sorted(Path(__file__).with_name('fixtures').glob('*.hex')):
            expected = json.loads(file.with_suffix('.expected.json').read_text())
            cls.fixtures.append((file, expected, e.analyze(bytes.fromhex(file.read_text()))))

    def test_selectors_against_compiler_identifiers(self):
        self.assertGreaterEqual(len(self.fixtures), 13)
        for file, expected, result in self.fixtures:
            with self.subTest(file=file.name):
                identifiers = {name: value for name, value in expected['method_identifiers'].items() if not name.startswith(('__default__', '__init__'))}
                wanted = {value.removeprefix('0x').zfill(8) for value in identifiers.values()}
                self.assertEqual(set(functions(result)), wanted)
                self.assertTrue(result.complete, result.issues)

    def test_fallback_and_receive_routes(self):
        for file, expected, result in self.fixtures:
            with self.subTest(file=file.name):
                routes = {r['category']: r['behavior'] for r in result.routes}
                has_receive = any((a['type'] == 'receive' for a in expected['abi']))
                self.assertEqual(routes['empty'], 'reaches_code')
                for category in ('short_1', 'short_2', 'short_3', 'unmatched'):
                    self.assertEqual(routes[category], 'rejects' if has_receive else 'reaches_code')

    def test_dispatch_offsets_against_recorded_independent_oracle(self):
        root = Path(__file__).parent
        reference = json.loads((root / 'fixtures/validation/compiler_validation.json').read_text())
        offsets = {row['fixture']: row['evmole_entry_pcs'] for row in reference['fixtures']}
        for file, _, result in self.fixtures:
            with self.subTest(file=file.name):
                actual = {f['selector']: f['dispatch_entry_pc'] for f in result.functions}
                self.assertEqual(actual, offsets[file.name])

class SelectorBitsTests(unittest.TestCase):

    def test_bytewise_dispatch(self):
        for value in (305419896, 0, 4278255360):
            with self.subTest(value=value):
                a = Assembly()
                for i, byte in enumerate(value.to_bytes(4, 'big')):
                    a.push(0).emit(op.CALLDATALOAD).push(i).emit(op.BYTE)
                    a.push(byte).emit(op.EQ, op.ISZERO).target('reject').emit(op.JUMPI)
                entry = len(a.code)
                a.emit(op.STOP).label('reject').reject()
                result = e.analyze(raw_bytes(a.build()))
                self.assertEqual(set(functions(result)), {f'{value:08x}'})
                self.assertEqual(functions(result)[f'{value:08x}']['entry_pc'], entry)
                self.assertTrue(result.complete)

    def test_partial_selector_is_not_registered(self):
        a = Assembly()
        a.push(0).emit(op.CALLDATALOAD).push(0).emit(op.BYTE)
        a.push(18).emit(op.EQ).target('yes').emit(op.JUMPI)
        a.reject().label('yes').emit(op.STOP)
        self.assertEqual(e.analyze(raw_bytes(a.build())).functions, [])

    def test_final_byte_ties_taken_branch_to_selector(self):
        a = Assembly()
        for i, byte in enumerate(bytes.fromhex('123456')):
            a.push(0).emit(op.CALLDATALOAD).push(i).emit(op.BYTE)
            a.push(byte).emit(op.EQ, op.ISZERO).target('reject').emit(op.JUMPI)
        a.push(0).emit(op.CALLDATALOAD).push(3).emit(op.BYTE)
        a.push(120).emit(op.EQ).target('entry').emit(op.JUMPI)
        a.label('reject').reject().label('entry').emit(op.STOP)
        result = e.analyze(raw_bytes(a.build()))
        self.assertEqual(set(functions(result)), {'12345678'})
        self.assertEqual(functions(result)['12345678']['entry_pc'], a.labels['entry'])

    def test_masked_bits_merge_and_conflicts_are_rejected(self):
        state = e.State()
        high = e.simplify(op.AND, e.SEL, 4294901760)
        low = e.simplify(op.AND, e.SEL, 65535)
        self.assertTrue(e.assume(state, e.simplify(op.EQ, high, 305397760), True))
        conflict = state.fork()
        overlap = e.simplify(op.AND, e.SEL, 4278190080)
        self.assertFalse(e.assume(conflict, e.simplify(op.EQ, overlap, 1442840576), True))
        self.assertTrue(e.assume(state, e.simplify(op.EQ, low, 22136), True))
        self.assertEqual(e.evaluate(e.SEL, state), 305419896)
        impossible = e.simplify(op.EQ, low, 65536)
        self.assertFalse(e.assume(e.State(), impossible, True))

    def test_invalid_jump_still_registers_selector(self):
        code = bytes.fromhex('606060405260e060020a600035046360fe47b1811460005780636d4ce63c146000575b9056')
        result = e.analyze(code)
        self.assertEqual(set(functions(result)), {'60fe47b1', '6d4ce63c'})
        for entry in result.functions:
            self.assertEqual(entry['entry_pc'], 0)
            self.assertTrue(entry['outcomes'])
            self.assertTrue(all((o['reason'] == 'invalid_jump' for o in entry['outcomes'])))

class PathBudgetTests(unittest.TestCase):

    def branch(self, remaining, budgeted=frozenset(), condition=None):
        vm = e.Interpreter(raw_bytes([op.JUMPI, op.JUMPDEST, op.STOP]), e.Limits())
        state = e.State(remaining_steps=remaining, budgeted_selectors=budgeted, stack=[condition if condition is not None else e.Expr(op.EQ, (e.SEL, 305419896)), 1])
        with self.assertRaises(e.Halt) as halted:
            vm.step(state)
        self.assertEqual(halted.exception.kind, 'internal')
        return list(vm.dispatch_queue) + list(vm.queue)

    def test_both_children_receive_bonus_after_jump_cost(self):
        children = self.branch(100)
        self.assertEqual(len(children), 2)
        self.assertEqual({s.selector for s in children}, {None, 305419896})
        for child in children:
            self.assertEqual(child.remaining_steps, 611)
            self.assertEqual(child.steps, 1)
            self.assertEqual(child.budgeted_selectors, frozenset({305419896}))

    def test_bonus_is_capped_and_can_replenish_last_instruction(self):
        self.assertTrue(all((s.remaining_steps == 1024 for s in self.branch(1000))))
        self.assertTrue(all((s.remaining_steps == 512 for s in self.branch(1))))

    def test_repeated_selector_and_partial_comparison_do_not_replenish(self):
        self.assertTrue(all((s.remaining_steps == 99 for s in self.branch(100, frozenset({305419896})))))
        partial = e.Expr(op.EQ, (e.Expr(op.AND, (e.SEL, 255)), 120))
        self.assertTrue(all((s.remaining_steps == 99 for s in self.branch(100, condition=partial))))

    def test_configured_budget_limits_straight_line_paths(self):
        code = raw_bytes([op.PUSH0, op.POP] * 10 + [op.STOP])
        result = e.analyze(code, limits=e.Limits(initial_path_budget=5))
        self.assertEqual(result.statistics['instructions_executed'], 25)
        self.assertEqual(len(result.issues), 5)
        self.assertTrue(all((i['reason'] == 'path_budget' for i in result.issues)))
        with self.assertRaises(ValueError):
            e.analyze(code, limits=e.Limits(initial_path_budget=1025))

class DependencyTraversalTests(unittest.TestCase):

    def test_shared_subgraphs(self):
        expr = e.Expr(op.ADD, (e.SEL, e.VALUE))
        for _ in range(60):
            expr = e.Expr(op.ADD, (expr, expr))
        self.assertEqual(e.dependencies(expr), {e.SELECTOR, op.CALLVALUE})

    def test_deep_expression(self):
        expr = e.SIZE
        for _ in range(2000):
            expr = e.Expr(op.ISZERO, (expr,))
        self.assertEqual(e.dependencies(expr), {op.CALLDATASIZE})

    def test_calldataload_is_a_leaf_and_constants_have_no_dependencies(self):
        self.assertEqual(e.dependencies(e.Expr(op.CALLDATALOAD, (e.SIZE,))), {op.CALLDATALOAD})
        self.assertEqual(e.dependencies(42), set())

class DiagnosticFormattingTests(unittest.TestCase):

    def test_small_expression_is_not_abbreviated(self):
        self.assertEqual(e.format_word(e.Expr(op.ADD, (e.SEL, 1))), 'add(selector, 0x1)')

    def test_shared_expression_expansion_is_bounded(self):
        expr = e.VALUE
        for _ in range(60):
            expr = e.Expr(op.ADD, (expr, expr))
        text = e.format_word(expr)
        self.assertIn('...', text)
        self.assertLessEqual(len(text), 512)

    def test_deep_expression_does_not_exhaust_recursion(self):
        expr = e.VALUE
        for _ in range(2000):
            expr = e.Expr(op.ISZERO, (expr,))
        self.assertIn('...', e.format_word(expr))

class EvaluationMemoizationTests(unittest.TestCase):

    def test_evaluation_and_address_resolution_release_state_without_gc(self):

        def evaluate_state():
            state = e.State()
            ref = weakref.ref(state)
            e.evaluate(e.Expr(op.ADD, (e.SIZE, 1)), state)
            return ref

        def resolve_address():
            vm = e.Interpreter(b'', e.Limits())
            state = e.State()
            refs = (weakref.ref(vm), weakref.ref(state))
            try:
                vm.address(state, e.Expr(op.MOD, (e.SEL, 2)), 'jump_target')
            except e.Halt:
                pass
            return refs
        enabled = gc.isenabled()
        gc.disable()
        try:
            self.assertIsNone(evaluate_state()())
            for ref in resolve_address():
                self.assertIsNone(ref())
        finally:
            if enabled:
                gc.enable()

    def test_shared_expressions_are_evaluated_once_and_preserved(self):
        expr = e.SIZE
        for _ in range(20):
            expr = e.Expr(op.MULMOD, (expr, expr, 97))
        with patch.object(e, 'simplify', wraps=e.simplify) as simplify:
            self.assertIs(e.evaluate(expr, e.State()), expr)
            self.assertEqual(simplify.call_count, 20)

    def test_cache_does_not_survive_state_or_fact_mode_changes(self):
        expr = e.Expr(op.ADD, (e.SIZE, 1))
        state = e.State()
        self.assertEqual(e.evaluate(expr, state), expr)
        state.ranges[e.SIZE] = e.Interval(4, 4)
        self.assertEqual(e.evaluate(expr, state), 5)
        state.ranges[e.SIZE] = e.Interval(8, 8)
        self.assertEqual(e.evaluate(expr, state), 9)
        state.facts[expr] = 12
        self.assertEqual(e.evaluate(expr, state), 12)
        self.assertEqual(e.evaluate(expr, state, use_facts=False), 9)
if __name__ == '__main__':
    unittest.main()
