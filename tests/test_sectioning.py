import unittest
import cbor2
from ethutils.sectioning import Analyzer, ReturnEvidence, section, _constant

class SectionTests(unittest.TestCase):
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
        self.assertNotIn((4,5),a.accepted[0])
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
    def test_referenced_helper_can_return_to_unknown_destination(self):
        code=bytes.fromhex('6006500000005b5056')
        self.assertEqual(section(code),[
            dict(kind='code',start=0,end=4,origin=0),
            dict(kind='code',start=6,end=9,origin=0)])
    def test_unreferenced_unknown_return_is_not_sufficient(self):
        self.assertEqual(section(bytes.fromhex('005b5056')),
                         [dict(kind='code',start=0,end=1,origin=0)])
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
        a.accepted={0:{(0,3)},5:{(5,7)}}
        self.assertFalse(a.region(0,3))
    def test_bounded_fragment_requires_jumpdest_entry(self):
        code=bytes.fromhex('600456005b00')
        self.assertEqual(section(code),[
            dict(kind='code',start=0,end=3,origin=0),
            dict(kind='code',start=4,end=6,origin=0)])
    def test_context_fragment_size_is_bounded(self):
        code=bytes.fromhex('61002856')+b'\x5b'+b'\x50'*34+b'\x56\x5b\x00'
        a=Analyzer(code);a.run()
        self.assertNotIn((4,5),a.accepted[0])
    def test_context_and_bad_jump_alone_are_not_sufficient(self):
        a=Analyzer(bytes.fromhex('6008565b60ff56005b00'))
        a.accepted={0:{(0,3),(7,10)}}
        self.assertFalse(a.region(0,3))
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

    def test_rejected_returned_entry_retains_program_coordinates(self):
        runtime = bytes.fromhex('3460ff573460fe575f5ffd5b5f5ffd')
        header = bytes([0x60, len(runtime)]) + bytes.fromhex('600c600039')
        header += bytes([0x60, len(runtime)]) + bytes.fromhex('6000f3')
        a = Analyzer(header + runtime)
        parts = a.run()
        entry = next(d for d in a.diagnostics if d['origin']==12 and d['start']==12)
        self.assertFalse(entry['accepted'])
        self.assertEqual(entry['B'], [266, 267])
        self.assertIn(dict(kind='code',start=23,end=27,origin=12), parts)
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

    def test_executable_tail_is_not_labeled_as_arguments(self):
        code=bytes.fromhex('600460146000396001601360003960016000f3')
        code+=b'\x00'+bytes.fromhex('5b5f5ffd')
        parts=section(code)
        self.assertTrue(any(s['kind']=='code' and s['end']==len(code) for s in parts))
        self.assertFalse(any(s.get('role')=='constructor_arguments_candidate' for s in parts))

    def test_returned_block_recovery_does_not_follow_other_blocks_failures(self):
        # The first block has a valid conditional edge. Its successor has two
        # distinct bad targets. Recover the first without trusting the successor.
        runtime=bytes.fromhex('34600557005b3460ff573460fe575f5ffd')
        header=bytes([0x60,len(runtime)])+bytes.fromhex('600c600039')
        header+=bytes([0x60,len(runtime)])+bytes.fromhex('6000f3')
        a=Analyzer(header+runtime);parts=a.run()
        self.assertTrue(any(s['kind']=='code' and s['origin']==12 and s['start']==12 for s in parts))
        self.assertNotIn(17,a.accepted)  # internal block is not a fresh origin
        self.assertTrue(any(d['recovery']=='basic_block' and d['accepted'] for d in a.diagnostics))

    def test_block_recovery_still_rejects_invalid_and_truncated_instructions(self):
        for suffix in ('aa','61ff'):
            runtime=bytes.fromhex(suffix)
            header=bytes([0x60,len(runtime)])+bytes.fromhex('600c600039')
            header+=bytes([0x60,len(runtime)])+bytes.fromhex('6000f3')
            a=Analyzer(header+runtime);a.run()
            self.assertNotIn(12,a.accepted)

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
