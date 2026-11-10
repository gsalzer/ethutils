import unittest
import cbor2
from ethutils import opcodes
from ethutils.sectioning import (Analyzer, CreatedEvidence, ReturnEvidence,
                                 analyze_sections, decompose, runtime, section,
                                 _abi_byte_candidates, _constant)
from tests.helpers import Assembly, hex_fixture

class SectionTests(unittest.TestCase):
    def test_abi_byte_candidates_require_canonical_bounds_and_padding(self):
        payload=bytes.fromhex('600556005b00')
        encoded=(32).to_bytes(32,'big')+len(payload).to_bytes(32,'big')
        encoded+=payload+b'\x00'*(-len(payload)%32)
        self.assertEqual(_abi_byte_candidates(encoded), [(0,32,64,70)])
        self.assertEqual(_abi_byte_candidates(encoded[:-1]+b'\x01'), [])
        self.assertEqual(_abi_byte_candidates(encoded[:32]+(99).to_bytes(32,'big')+encoded[64:]), [])

    def test_abi_bytes_seed_init_and_returned_runtime_detection(self):
        embedded_runtime=bytes.fromhex('5f5ffd')
        init=bytes([0x60,len(embedded_runtime)])+bytes.fromhex('600c600039')
        init+=bytes([0x60,len(embedded_runtime)])+bytes.fromhex('6000f3')+embedded_runtime
        tail=(32).to_bytes(32,'big')+len(init).to_bytes(32,'big')
        tail+=init+b'\x00'*(-len(init)%32)
        # Copy the complete ABI tail as constructor data, then return a one-byte
        # outer runtime. The ABI payload begins at absolute input offset 84.
        prefix=bytes.fromhex(
            f'61{len(tail):04x}6100145f3960016100135f3960015ff3')
        code=prefix+opcodes.STOP+tail
        analyzer=Analyzer(code);parts=analyzer.run()
        init_start=20+64;runtime_start=init_start+12
        self.assertIn(init_start,analyzer.abi_programs)
        self.assertIn(ReturnEvidence(init_start,runtime_start,runtime_start+len(embedded_runtime),
                                     init_start+11,init_start+6),
                      analyzer.returned_copies)
        self.assertIn(dict(kind='code',start=init_start,end=runtime_start,
                           origin=init_start),parts)
        self.assertIn(dict(kind='code',start=runtime_start,
                           end=runtime_start+len(embedded_runtime),origin=runtime_start),parts)
        self.assertEqual(sum(kind=='code' for kind,_ in decompose(code)),4)
        self.assertEqual(runtime(code),opcodes.STOP)
        program=next(p for p in analyze_sections(code).programs
                     if p.origin==init_start)
        self.assertEqual((program.evidence,program.parent),('abi_bytes',0))

    def test_tvm_stack_producers_keep_runtime_code_contiguous(self):
        code = opcodes.CALLTOKENVALUE + opcodes.POP + opcodes.CALLTOKENID + opcodes.POP + opcodes.STOP
        self.assertEqual(section(code), [dict(kind='code', start=0, end=5, origin=0)])
        try:
            opcodes.set_tvm_opcodes_enabled(False)
            self.assertNotEqual(section(code), [dict(kind='code', start=0, end=5, origin=0)])
        finally:
            opcodes.set_tvm_opcodes_enabled(True)

    def test_nested_creation_contract_fixtures(self):
        expected = {
            '0xa39394d3447c1dbd386b92b4d1fcc22ca85eae67-src.hex': [
                ('code', 0, 472, 0), ('code', 472, 1175, 472),
                ('data', 472, 10147, 0), ('code', 1175, 3744, 1175),
                ('data', 1175, 3776, 472), ('data', 3744, 3776, 1175),
                ('code', 3776, 4479, 3776),
                ('code', 4479, 7048, 4479), ('data', 4479, 7080, 3776),
                ('data', 7048, 7080, 4479), ('code', 7080, 10147, 7080),
            ],
            '0xa39394d3447c1dbd386b92b4d1fcc22ca85eae67.hex': [
                ('code', 0, 724, 0), ('code', 724, 1421, 724),
                ('data', 724, 9879, 0), ('code', 1421, 3733, 1421),
                ('data', 1421, 3765, 724), ('data', 3733, 3765, 1421),
                ('code', 3765, 4462, 3765),
                ('code', 4462, 6774, 4462), ('data', 4462, 6806, 3765),
                ('data', 6774, 6806, 4462), ('code', 6806, 9879, 6806),
            ],
        }
        for name, ranges in expected.items():
            with self.subTest(fixture=name):
                parts = section(hex_fixture(name))
                actual = [(part['kind'], part['start'], part['end'], part['origin'])
                          for part in parts if part['kind'] in {'code', 'data'}]
                self.assertEqual(actual, ranges)
                returned = [(part['start'], part['end'], part['origin'],
                             part['via'], part['copy'])
                            for part in parts if part['kind'] == 'returned']
                expected_returned = {
                    '0xa39394d3447c1dbd386b92b4d1fcc22ca85eae67-src.hex': [
                        (1175, 3776, 472, 1174, 1171),
                        (4479, 7080, 3776, 4478, 4475),
                        (7080, 10147, 0, 471, 468),
                    ],
                    '0xa39394d3447c1dbd386b92b4d1fcc22ca85eae67.hex': [
                        (1421, 3765, 724, 1420, 1417),
                        (4462, 6806, 3765, 4461, 4458),
                        (6806, 9879, 0, 723, 720),
                    ],
                }
                self.assertEqual(returned, expected_returned[name])

    def test_push_data_not_jumpdest(self):
        r = Analyzer(bytes.fromhex('615b00600156')).explore(0,0)
        self.assertEqual(r.invalid_jump_targets, {1})
    def test_computed_jump(self):
        r = Analyzer(bytes.fromhex('600460030156005b00')).explore(0,0)
        self.assertEqual(r.valid_jump_count,1)
        self.assertFalse(r.invalid_jump_targets)
        self.assertIn((7,8),r.spans)
    def test_copy_and_nested_origin(self):
        code = bytes.fromhex('6005600c60003960056000f36003565b00')
        sections = section(code)
        self.assertIn(dict(kind='data',start=12,end=17,origin=0),sections)
        self.assertIn(dict(kind='code',start=12,end=17,origin=12),sections)
    def test_rejected_candidate_isolated(self):
        a = Analyzer(bytes.fromhex('600450005b600156'))
        a.run()
        self.assertIn((4,5),a.accepted[0])
    def test_truncated_push_and_falloff(self):
        self.assertTrue(Analyzer(b'\x61\x00').explore(0,0).truncated_push_pcs)
        self.assertTrue(Analyzer(b'\x5f').explore(0,0).terminated)
    def test_metadata_independent(self):
        blob=cbor2.dumps({'solc':b'\x00\x08\x00'})
        code=b'\x00'+blob+len(blob).to_bytes(2,'big')
        meta=[s for s in section(code) if s['kind']=='meta']
        self.assertEqual(meta,[dict(kind='meta',start=1,end=len(code),cbor={'solc':b'\x00\x08\x00'})])
    def test_loop_converges(self):
        r=Analyzer(bytes.fromhex('5b5f600056')).explore(0,0)
        self.assertEqual(r.valid_jump_count,1)
    def test_literal_jump_through_stack_operations(self):
        r = Analyzer(bytes.fromhex('60aa60079050565b00')).explore(0,0)
        self.assertEqual(r.valid_jump_count,1)
        self.assertIn((7,8),r.spans)
    def test_both_conditional_paths(self):
        for condition in ('00','01'):
            with self.subTest(condition=condition):
                r=Analyzer(bytes.fromhex('60'+condition+'60075700005b00')).explore(0,0)
                self.assertEqual(r.valid_jump_count,1)
                self.assertIn((5,6),r.spans)
                self.assertIn((7,8),r.spans)
    def test_zero_condition_does_not_hide_bad_destination(self):
        r=Analyzer(bytes.fromhex('5f60ff5700')).explore(0,0)
        self.assertEqual(r.invalid_jump_targets,{255})
        self.assertIn((4,5),r.spans)
    def test_computed_copy_length(self):
        r=Analyzer(bytes.fromhex('600260030160005f3900')).explore(0,0)
        self.assertEqual(r.copied_ranges,{(0,5)})
    def test_environment_values_resolve(self):
        for instruction in ('38','58'):
            with self.subTest(instruction=instruction):
                r=Analyzer(bytes.fromhex(instruction+'60005f3900')).explore(0,0)
                self.assertEqual(r.copied_ranges,{(0,6)} if instruction == '38' else set())
    def test_computed_zero_condition_keeps_both_paths(self):
        r=Analyzer(bytes.fromhex('6001600103600a5700005b00')).explore(0,0)
        self.assertEqual(r.valid_jump_count,1)
        self.assertIn((8,9),r.spans)
        self.assertIn((10,11),r.spans)
    def test_operand_order_and_wraparound(self):
        self.assertEqual(_constant('SUB',[3,5]),(1<<256)-2)
        self.assertEqual(_constant('SHL',[4,3]),48)
    def test_join_preserves_both_jump_literals(self):
        for first, second in (('11','13'),('13','11')):
            with self.subTest(first=first):
                code=bytes.fromhex('3460095760'+first+'600f565b60'+second+'600f565b565b005b00')
                r=Analyzer(code).explore(0,0)
                self.assertFalse(r.invalid_jump_targets)
                self.assertIn((17,18),r.spans)
                self.assertIn((19,20),r.spans)
                self.assertEqual(section(code),[dict(kind='code',start=0,end=21,origin=0)])
    def test_arithmetic_preserves_join_alternatives(self):
        code=bytes.fromhex('346009576013600f565b6015600f565b5f01565b005b00')
        r=Analyzer(code).explore(0,0)
        self.assertIn((19,20),r.spans)
        self.assertIn((21,22),r.spans)
        self.assertFalse(r.invalid_jump_targets)
    def test_copied_zero_padded_address_is_not_code(self):
        data=bytes.fromhex('000000000000000000000000fb3065f71973987704e76aa5b1d0851c7c0fd583')
        code=bytes.fromhex('6020600860003900')+data
        self.assertEqual(section(code),[
            dict(kind='code',start=0,end=8,origin=0),
            dict(kind='data',start=8,end=40,origin=0)])
    def test_copied_error_string_is_not_code(self):
        data=b'ImpossibleWrapper: TRANSFERFROM_FAILEDIF Wrapper: UNDERLYING_TRANSFER_FAIL'
        code=bytes([0x60,len(data)])+bytes.fromhex('600860003900')+data
        self.assertEqual(section(code),[
            dict(kind='code',start=0,end=8,origin=0),
            dict(kind='data',start=8,end=len(code),origin=0)])
    def test_copied_strong_terminator_is_data_not_a_program(self):
        for data in (bytes.fromhex('ff'), bytes.fromhex('5b5f5ffd')):
            with self.subTest(data=data.hex()):
                code=bytes([0x60,len(data)])+bytes.fromhex('600860003900')+data
                self.assertEqual(section(code),[
                    dict(kind='code',start=0,end=8,origin=0),
                    dict(kind='data',start=8,end=len(code),origin=0)])
    def test_copied_create_input_is_an_explicit_program(self):
        code=bytes.fromhex('6001600f600039600160006000f00000')
        analyzer=Analyzer(code)
        parts=analyzer.run()
        self.assertEqual(analyzer.created_copies,
                         {CreatedEvidence(0,15,16,13,6)})
        self.assertIn(dict(kind='code',start=15,end=16,origin=15),parts)
        self.assertIn(dict(kind='data',start=15,end=16,origin=0),parts)
    def test_copied_create_prefix_with_appended_arguments_is_a_program(self):
        # Copy one byte of init code, append one constructor-argument byte, and
        # pass both to CREATE.  Only the unchanged copied prefix has source
        # provenance, but it is sufficient to establish the embedded program.
        code=bytes.fromhex('600160115f3960aa60015360025f5ff00000')
        analyzer=Analyzer(code)
        parts=analyzer.run()
        self.assertEqual(analyzer.created_copies,
                         {CreatedEvidence(0,17,18,15,5)})
        self.assertIn(dict(kind='code',start=17,end=18,origin=17),parts)
        self.assertIn(dict(kind='data',start=17,end=18,origin=0),parts)
    def test_create_prefix_resolves_solidity_free_memory_pointer(self):
        # Solidity obtains both the CODECOPY destination and CREATE offset by
        # loading the constant free-memory pointer stored at memory address 0x40.
        code=bytes.fromhex('60606040526001601a6040513960aa60615360026040515ff00000')
        analyzer=Analyzer(code)
        parts=analyzer.run()
        self.assertEqual(analyzer.created_copies,
                         {CreatedEvidence(0,26,27,24,12)})
        self.assertIn(dict(kind='code',start=26,end=27,origin=26),parts)
    def test_created_init_prefix_discovers_its_returned_runtime(self):
        init=bytes.fromhex('6005600c60003960056000f36003565b00')
        # The outer constructor copies init, appends one byte, then CREATEs the
        # composite payload.  Analysis of init must recursively find its runtime.
        outer=bytes.fromhex('601160115f3960aa60115360125f5ff000')
        analyzer=Analyzer(outer+init)
        parts=analyzer.run()
        self.assertIn(CreatedEvidence(0,17,34,15,5), analyzer.created_copies)
        self.assertIn(ReturnEvidence(17,29,34,28,23), analyzer.returned_copies)
        self.assertIn(dict(kind='code',start=29,end=34,origin=29),parts)
    def test_referenced_helper_can_return_to_unknown_destination(self):
        code=bytes.fromhex('6006500000005b5056')
        self.assertEqual(section(code),[
            dict(kind='code',start=0,end=4,origin=0),
            dict(kind='code',start=6,end=9,origin=0)])
    def test_touching_unknown_return_is_helper_code(self):
        self.assertEqual(section(bytes.fromhex('005b5056')),
                         [dict(kind='code',start=0,end=4,origin=0)])
    def test_residual_search_skips_bad_prefix(self):
        self.assertEqual(section(bytes.fromhex('00aa5b600256')),[
            dict(kind='code',start=0,end=1,origin=0),
            dict(kind='code',start=2,end=6,origin=0)])
    def test_residual_search_does_not_enter_push_operand(self):
        self.assertEqual(section(bytes.fromhex('00635b600256')),
                         [dict(kind='code',start=0,end=1,origin=0)])
    def test_growing_constant_loop_widens_and_terminates(self):
        r=Analyzer(bytes.fromhex('5f5b600101600156')).explore(0,0)
        self.assertEqual(r.valid_jump_count,1)
        self.assertFalse(r.invalid_jump_targets)
    def test_distinct_bad_targets_at_join(self):
        code=bytes.fromhex('3460095760aa600f565b60bb600f565b56')
        r=Analyzer(code).explore(0,0)
        self.assertEqual(r.invalid_jump_targets,{170,187})
    def test_arithmetic_noncommutative_and_modular(self):
        for name,args,expected in [('DIV',[9,2],4),('DIV',[9,0],0),
                ('MOD',[9,4],1),('LT',[2,9],1),('GT',[2,9],0),
                ('SHR',[4,48],3),('BYTE',[0,1<<248],1),
                ('ADDMOD',[(1<<256)-1,1,3],1),('MULMOD',[7,9,5],3)]:
            with self.subTest(name=name,args=args):
                self.assertEqual(_constant(name,args),expected)
    def test_join_preserves_correlated_operands(self):
        # Both branches compute 1. Mixing operands across branches would
        # invent other lengths, including a wrapped negative subtraction.
        code=bytes.fromhex('34600b57600260036013565b600460056013565b0360005f3900')
        r=Analyzer(code).explore(0,0)
        self.assertEqual(r.copied_ranges,{(0,1)})
        self.assertFalse(r.invalid_jump_targets)
    def returned_exploration(self, suffix):
        prefix=bytes.fromhex('60086080602039')
        code=prefix+bytes.fromhex(suffix)
        code+=b'\x00'*(128-len(code))+bytes(range(8))
        return Analyzer(code).explore(0,0)
    def test_returned_full_copy_and_evidence(self):
        r=self.returned_exploration('60086020f3')
        self.assertEqual(r.returned_copies,{ReturnEvidence(0,128,136,11,6)})
        sections=section(bytes.fromhex('6005600c60003960056000f36003565b00'))
        self.assertIn(dict(kind='returned',start=12,end=17,origin=0,via=11,copy=6),sections)
    def test_returned_copy_subrange(self):
        self.assertEqual(self.returned_exploration('60036022f3').returned_copies,{ReturnEvidence(0,130,133,11,6)})
    def test_overlapping_writes_invalidate_returned(self):
        for write in ('6001602253','5f602052','60016000602237',
                      '6001600060223e','6001600060225e','6001600060225f3c',
                      '600160225f5f5f5f5ff1','600160225f5f5f5f5ff2',
                      '600160225f5f5f5ff4','600160225f5f5f5ffa'):
            with self.subTest(write=write):
                self.assertFalse(self.returned_exploration(write+'60086020f3').returned_copies)
    def test_overwritten_return_copy_still_seeds_program_detection(self):
        # Exact return provenance is lost when the copied runtime is patched,
        # but the CODECOPY source remains a useful candidate program origin.
        payload=opcodes.PUSH0+opcodes.STOP
        a=Assembly().push(len(payload)+1).target('payload').emit(
            opcodes.PUSH0,opcodes.CODECOPY)
        a.push(42).push(2).emit(opcodes.MSTORE8).push(len(payload)+1).emit(
            opcodes.PUSH0,opcodes.RETURN)
        a.label('payload').emit(payload)
        code=a.build()
        analyzer=Analyzer(code)
        parts=analyzer.run()
        self.assertFalse(analyzer.returned_copies)
        start=a.labels['payload']
        self.assertIn(dict(kind='code',start=start,end=len(code),origin=start),parts)
    def test_exactly_returned_runtime_entry_is_trusted(self):
        # Both selector branches deliberately jump to non-JUMPDEST offset zero
        # to trigger an exceptional halt, and the final dynamic jump cannot be
        # resolved statically.  Exact constructor-return provenance still
        # establishes the deployed program entry.
        code=bytes.fromhex(
            '606060405260258060116000396000f300'
            '606060405260e060020a600035046360fe47b18114600057'
            '80636d4ce63c146000575b9056')
        parts=section(code)
        self.assertIn(dict(kind='code',start=17,end=54,origin=17),parts)
        self.assertIn(dict(kind='returned',start=17,end=54,origin=0,
                           via=15,copy=12),parts)
    def test_create_discovers_copy_from_internal_memory_helper(self):
        payload=opcodes.PUSH0+opcodes.PUSH0+opcodes.RETURN
        a=Assembly().target('after').target('helper').emit(opcodes.JUMP)
        copied_length=len(payload)+1  # payload label contributes its JUMPDEST
        a.label('after').emit(opcodes.POP).push(copied_length).emit(
            opcodes.PUSH0,opcodes.PUSH0,opcodes.CREATE,opcodes.STOP)
        a.label('helper').push(0x40).emit(opcodes.MLOAD).push(copied_length).emit(
            opcodes.DUP1).target('payload').emit(opcodes.DUP4,opcodes.CODECOPY,
                                              opcodes.ADD,opcodes.SWAP1,opcodes.JUMP)
        a.label('payload').emit(payload)
        code=a.build()
        parts=section(code)
        start=a.labels['payload']
        self.assertIn(dict(kind='code',start=start,end=len(code),origin=start),parts)

    def test_plain_codecopy_source_is_a_weak_program_reference(self):
        # No CREATE or RETURN consumes this copy.  Its source nevertheless has
        # independent CFG evidence and is therefore accepted as a program.
        a=Assembly().push(7).target('payload').emit(
            opcodes.PUSH0,opcodes.CODECOPY,opcodes.STOP)
        a.label('payload').emit(bytes.fromhex('600556005b00'))
        code=a.build();start=a.labels['payload']
        parts=section(code)
        self.assertIn(start, {part['origin'] for part in parts if part['kind']=='code'})
        self.assertTrue(any(part['kind']=='code' and part['start']==start
                            for part in parts))

    def test_plain_codecopy_reference_alone_does_not_make_data_code(self):
        # A clean-looking copied fragment without jumps or nested program flow
        # remains data; the CODECOPY reference is supporting, not conclusive.
        a=Assembly().push(4).target('payload').emit(
            opcodes.PUSH0,opcodes.CODECOPY,opcodes.STOP)
        a.label('payload').emit(opcodes.PUSH0,opcodes.PUSH0,opcodes.REVERT)
        code=a.build();start=a.labels['payload']
        parts=section(code)
        self.assertFalse(any(part['kind']=='code' and part['origin']==start
                             for part in parts))
    def test_nonoverlapping_write_preserves_returned(self):
        self.assertTrue(self.returned_exploration('5f60405260086020f3').returned_copies)
    def test_partial_overwrite_preserves_unaffected_subrange(self):
        r=self.returned_exploration('600160225360036023f3')
        self.assertEqual({(record.start,record.end) for record in r.returned_copies},{(131,134)})
    def test_unknown_write_forgets_provenance(self):
        self.assertFalse(self.returned_exploration('5f345260086020f3').returned_copies)
    def test_zero_length_unknown_write_preserves_provenance(self):
        self.assertTrue(self.returned_exploration('5f5f343760086020f3').returned_copies)
    def test_returned_excludes_padding_and_revert(self):
        self.assertFalse(self.returned_exploration('60096020f3').returned_copies)
        self.assertFalse(self.returned_exploration('60086020fd').returned_copies)
    def test_memory_does_not_cross_branches(self):
        code=bytes.fromhex('34600c5760086080602039005b60086020f3')
        code+=b'\x00'*(128-len(code))+bytes(range(8))
        self.assertFalse(Analyzer(code).explore(0,0).returned_copies)
        analyzer=Analyzer(code);analyzer.run()
        self.assertNotIn(128,analyzer.accepted)
    def test_same_stack_different_memory_at_join(self):
        # One branch overwrites byte 34. Both reach the same RETURN with
        # identical stacks; the other branch still has valid provenance.
        code=bytes.fromhex('60086080602039346012575f6022536013565b5b60086020f3')
        code+=b'\x00'*(128-len(code))+bytes(range(8))
        r=Analyzer(code).explore(0,0)
        self.assertFalse(r.invalid_jump_targets)
        self.assertTrue(r.returned_copies)
    def test_returned_source_offsets_include_nonzero_origin(self):
        local=bytes.fromhex('6005600c60003960056000f36003565b00')
        code=b'\x00'*10+local
        self.assertEqual(Analyzer(code).explore(10,10).returned_copies,{ReturnEvidence(10,22,27,21,16)})
    def test_copy_past_code_end_cannot_prove_padded_return(self):
        code=bytes.fromhex('6009608060203960096020f3')
        code+=b'\x00'*(128-len(code))+bytes(range(8))
        r=Analyzer(code).explore(0,0)
        self.assertEqual(r.copied_ranges,{(128,8)})
        self.assertFalse(r.returned_copies)
    def test_unreferenced_meaningful_terminators(self):
        for body in ('5f5ff3','5f5ffd','5fff'):
            with self.subTest(body=body):
                code=bytes.fromhex('00aa5b'+body)
                self.assertEqual(section(code),[
                    dict(kind='code',start=0,end=1,origin=0),
                    dict(kind='code',start=2,end=len(code),origin=0)])
    def test_unreferenced_stop_and_invalid_remain_weak(self):
        for terminal in ('00','fe'):
            with self.subTest(terminal=terminal):
                self.assertEqual(section(bytes.fromhex('00aa5b'+terminal)),
                                 [dict(kind='code',start=0,end=1,origin=0)])
    def test_returned_stop_is_code(self):
        code=bytes.fromhex('6001600c5f3960015ff3000000')
        self.assertIn(dict(kind='returned',start=12,end=13,origin=0,via=9,copy=5),section(code))
        self.assertIn(dict(kind='code',start=12,end=13,origin=12),section(code))
    def test_returned_revert_program_with_metadata_is_code(self):
        # Body from the previously missed short contracts; metadata independent.
        blob=cbor2.dumps({'solc':b'\x00\x08\x00'})
        runtime=bytes.fromhex('6080604052600080fd00')+blob+len(blob).to_bytes(2,'big')
        code=bytes([0x60,len(runtime)])+bytes.fromhex('600c5f39')+bytes([0x60,len(runtime)])+bytes.fromhex('5ff30000')+runtime
        self.assertIn(dict(kind='code',start=12,end=21,origin=12),section(code))
    def test_meaningful_terminator_allows_one_bad_target(self):
        r=Analyzer(bytes.fromhex('3460ff575f5ffd')).explore(0,0)
        self.assertTrue(r.plausible())
        self.assertIn('REVERT',r.terminators)
    def test_returned_subrange_is_a_new_origin(self):
        # Copy eight bytes, return a STOP at source offset 34 inside the copy.
        code=bytes.fromhex('6008602060203960016022f3')
        code+=b'\x00'*(32-len(code))+b'\xaa\xbb\x00\xcc\xdd\xee\xaa\xbb'
        sections=section(code)
        self.assertIn(dict(kind='code',start=34,end=35,origin=34),sections)
    def test_bounded_jumpdest_stop_is_code(self):
        code=bytes.fromhex('6005565b005b00')
        self.assertEqual(section(code),[dict(kind='code',start=0,end=len(code),origin=0)])
    def test_bounded_unresolved_return_is_code(self):
        code=bytes.fromhex('6007565b5090565b00')
        self.assertEqual(section(code),[dict(kind='code',start=0,end=len(code),origin=0)])
    def test_context_does_not_cross_origins(self):
        a=Analyzer(bytes.fromhex('6005565b005b00'))
        a.accepted={0:{(0,2)},5:{(5,7)}}
        self.assertFalse(a.region(0,3))
    def test_bounded_fragment_requires_jumpdest_entry(self):
        code=bytes.fromhex('600456005b00')
        self.assertEqual(section(code),[
            dict(kind='code',start=0,end=3,origin=0),
            dict(kind='code',start=4,end=6,origin=0)])
    def test_touching_fragment_need_not_be_short(self):
        code=bytes.fromhex('61002856')+b'\x5b'+b'\x50'*34+b'\x56\x5b\x00'
        a=Analyzer(code);a.run()
        self.assertIn((4,5),a.accepted[0])
    def test_touching_fragment_may_use_one_bad_jump(self):
        a=Analyzer(bytes.fromhex('6008565b60ff56005b00'))
        a.accepted={0:{(0,3),(7,10)}}
        self.assertTrue(a.region(0,3))

    def test_touching_jumpdest_helper_extends_code(self):
        for terminal in ('00', 'fe'):
            with self.subTest(terminal=terminal):
                code=bytes.fromhex('00'+'5b'+terminal)
                parts=section(code)
                self.assertEqual(parts,[dict(kind='code',start=0,end=3,origin=0)])

    def test_touching_helper_can_use_one_exception_target(self):
        code=bytes.fromhex('005b60ff56')
        self.assertEqual(section(code),[
            dict(kind='code',start=0,end=len(code),origin=0)])

    def test_touching_helper_cannot_exceed_exception_budget(self):
        code=bytes.fromhex('005b3460ff573460fe5756')
        self.assertEqual(section(code),[
            dict(kind='code',start=0,end=1,origin=0)])

    def test_touching_helper_still_rejects_undefined_opcode(self):
        code=bytes.fromhex('005baa')
        self.assertEqual(section(code),[
            dict(kind='code',start=0,end=1,origin=0)])
    def test_repeated_exception_destination_counts_once(self):
        r=Analyzer(bytes.fromhex('3460ff573460ff575f5ffd')).explore(0,0)
        self.assertEqual(r.invalid_jump_targets,{255})
        self.assertEqual(len(r.invalid_jump_sources),2)
        self.assertTrue(r.plausible())
    def test_two_exception_destinations_are_rejected(self):
        r=Analyzer(bytes.fromhex('3460ff573460fe575f5ffd')).explore(0,0)
        self.assertEqual(r.invalid_jump_targets,{254,255})
        self.assertFalse(r.plausible())
    def test_one_bad_target_still_requires_positive_evidence(self):
        r=Analyzer(bytes.fromhex('60ff56')).explore(0,0)
        self.assertEqual(r.invalid_jump_targets,{255})
        self.assertFalse(r.plausible())
    def test_exception_tolerance_does_not_allow_invalid_or_truncation(self):
        for suffix in ('aa','61ff'):
            with self.subTest(suffix=suffix):
                r=Analyzer(bytes.fromhex('3460ff5734600b575f5ffd5b'+suffix)).explore(0,0)
                self.assertEqual(r.invalid_jump_targets,{255})
                self.assertIn('REVERT',r.terminators)
                self.assertTrue(r.invalid_opcode_pcs or r.truncated_push_pcs)
                self.assertFalse(r.plausible(returned=True))
    def test_bad_target_budget_is_shared_by_origin(self):
        a=Analyzer(bytes.fromhex('3460ff575f5ffd3460fe575f5ffd'))
        self.assertTrue(a.region(0,0))
        self.assertEqual(a.bad_targets[0],{255})
        self.assertFalse(a.region(0,7))
        self.assertEqual(a.bad_targets[0],{255})
    def test_speculation_can_reuse_existing_exception_destination(self):
        a=Analyzer(bytes.fromhex('3460ff575f5ffd3460ff575f5ffd'))
        self.assertTrue(a.region(0,0))
        self.assertTrue(a.region(0,7))
        self.assertEqual(a.bad_targets[0],{255})

    def test_over_budget_trusted_entry_does_not_poison_clean_fragments(self):
        prefix = bytes.fromhex('3460ff573460fe575f5ffd')
        a = Analyzer(prefix + bytes.fromhex('005b5f5ffd'))
        self.assertTrue(a.region(0, 0, trusted=True))
        self.assertEqual(a.bad_targets[0], {254, 255})
        self.assertTrue(a.region(0, len(prefix)+1))
        self.assertEqual(a.bad_targets[0], {254, 255})

    def test_over_budget_trusted_entry_cannot_add_an_exception(self):
        prefix = bytes.fromhex('3460ff573460fe575f5ffd')
        a = Analyzer(prefix + bytes.fromhex('3460fd575f5ffd'))
        self.assertTrue(a.region(0, 0, trusted=True))
        self.assertFalse(a.region(0, len(prefix)))
        self.assertEqual(a.bad_targets[0], {254, 255})

    def test_trusted_returned_entry_retains_bad_target_diagnostics(self):
        runtime = bytes.fromhex('3460ff573460fe575f5ffd5b5f5ffd')
        header = bytes([0x60, len(runtime)]) + bytes.fromhex('600c600039')
        header += bytes([0x60, len(runtime)]) + bytes.fromhex('6000f3')
        a = Analyzer(header + runtime)
        parts = a.run()
        entry = next(d for d in a.diagnostics if d['origin']==12 and d['start']==12)
        self.assertTrue(entry['accepted'])
        self.assertEqual(entry['B'], [266, 267])
        self.assertIn(dict(kind='code',start=12,end=27,origin=12), parts)
        self.assertEqual(set(a.accepted), {0,12})

    def test_bad_jump_diagnostics_identify_literal_and_stack(self):
        a = Analyzer(bytes.fromhex('60aa60ff56'))
        a.region(0,0,trusted=True)
        detail = a.diagnostics[0]['bad_jumps'][0]
        self.assertEqual((detail['jump'], detail['target']), (4,255))
        self.assertEqual(detail['matching_literal_pushes'], [2])
        self.assertEqual(detail['stack'], [170])
        self.assertFalse(detail['analysis_has_widened'])

    def test_optional_trace_tracks_computed_target_provenance(self):
        code=bytes.fromhex('60f0600f0156')
        traced=Analyzer(code,trace=True).explore(0,0)
        ordinary=Analyzer(code).explore(0,0)
        self.assertEqual(traced.invalid_jump_targets,ordinary.invalid_jump_targets)
        self.assertEqual(traced.spans,ordinary.spans)
        self.assertEqual(traced.invalid_jump_details[(5,255)]['value_sources'],[0,2,4])

    def test_copy_backed_constructor_arguments_have_explicit_evidence(self):
        code=bytes.fromhex('602060146000396001601360003960016000f3')
        code+=b'\x00'+b'\x00'*31+b'\x74'
        parts=section(code)
        tail=next(s for s in parts if s['kind']=='data' and s['start']==20)
        self.assertEqual(tail,dict(kind='data',start=20,end=52,origin=0,
                                  role='constructor_arguments_candidate',evidence='copied_tail_after_returned_program',
                                  copies=[6],after_returned=20))
        self.assertIn(dict(kind='code',start=19,end=20,origin=19),parts)

    def test_position_alone_does_not_classify_constructor_arguments(self):
        code=bytes.fromhex('6001600c60003960016000f3')+b'\x00'+b'\x00'*32
        self.assertFalse(any(s.get('role')=='constructor_arguments_candidate' for s in section(code)))

    def test_executable_looking_copied_tail_remains_data(self):
        code=bytes.fromhex('600460146000396001601360003960016000f3')
        code+=b'\x00'+bytes.fromhex('5b5f5ffd')
        parts=section(code)
        self.assertFalse(any(s['kind']=='code' and s['start']>=20 for s in parts))
        self.assertTrue(any(s['kind']=='data' and s['start']==20 and s['end']==len(code)
                            for s in parts))

    def test_trusted_returned_entry_follows_reachable_blocks(self):
        runtime=bytes.fromhex('34600557005b3460ff573460fe575f5ffd')
        header=bytes([0x60,len(runtime)])+bytes.fromhex('600c600039')
        header+=bytes([0x60,len(runtime)])+bytes.fromhex('6000f3')
        a=Analyzer(header+runtime);parts=a.run()
        self.assertTrue(any(s['kind']=='code' and s['origin']==12 and s['start']==12 for s in parts))
        self.assertNotIn(17,a.accepted)  # internal block is not a fresh origin
        self.assertTrue(any(d['origin']==12 and d['start']==12 and d['recovery'] is None
                            and d['accepted'] for d in a.diagnostics))

    def test_copied_image_extent_does_not_limit_control_flow_exploration(self):
        # The short copied extent is useful to interpret CODESIZE, but reachable
        # code beyond it must still be found. Relative address 7 is absolute 11.
        code=bytes.fromhex('000000006007565b005b005b00')
        a=Analyzer(code);a.limits[4]=10;a.program_regions[4]=10
        self.assertTrue(a.region(4,4,trusted=True))
        self.assertIn((11,12),a.accepted[4])

    def test_trusted_return_accepts_undefined_but_not_empty_truncated_entry(self):
        for suffix,accepted in (('aa',True),('61ff',False)):
            with self.subTest(suffix=suffix):
                runtime=bytes.fromhex(suffix)
                header=bytes([0x60,len(runtime)])+bytes.fromhex('600c600039')
                header+=bytes([0x60,len(runtime)])+bytes.fromhex('6000f3')
                a=Analyzer(header+runtime);a.run()
                self.assertEqual(12 in a.accepted,accepted)

    def test_referenced_constructor_block_can_overlap_a_returned_program(self):
        code=bytearray(b'\xaa'*13);code[0]=0
        code[6:12]=bytes.fromhex('5b600a565b00')
        a=Analyzer(bytes(code))
        a.program_regions={4:12};a.limits[4]=12
        a.accepted={0:{(10,11),(11,12)}};a.references={0:{6}}
        parts=a.run()
        self.assertTrue(any(s['kind']=='code' and s['origin']==0 and s['start']<=6 and s['end']>=12 for s in parts))

    def test_constructor_fallthrough_can_overlap_end_of_returned_program(self):
        code=bytearray(b'\xaa'*13);code[:3]=bytes.fromhex('0039f3')
        code[6:12]=bytes.fromhex('5b6000505b00')
        a=Analyzer(bytes(code))
        a.program_regions={4:10};a.limits[4]=10
        a.returned_copies={ReturnEvidence(0,4,10,2,1)}
        a.accepted={0:{(10,11),(11,12)}}
        parts=a.run()
        self.assertTrue(any(s['kind']=='code' and s['origin']==0 and s['start']<=6 and s['end']>=12 for s in parts))

if __name__=='__main__': unittest.main()
