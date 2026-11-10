import unittest
from ethutils import opcodes as o
from ethutils import disassemble, normalize_pushes, instruction_boundaries


class OpcodeTests(unittest.TestCase):
    def test_bytes_and_derived_views(self):
        self.assertFalse(hasattr(o, 'OpCode'))
        for opcode, info in o.INFO.items():
            self.assertIs(type(opcode), bytes)
            self.assertEqual(len(opcode), 1)
            self.assertIs(getattr(o, info.name), opcode)
            self.assertIs(o.BY_VALUE[opcode[0]], info)
            self.assertEqual(o.BY_NAME[info.name], opcode)
        self.assertEqual(o.BLOBHASH, b'\x49')
        self.assertEqual(o.PUSH1 + b'\x00' + o.CALLDATALOAD, b'\x60\x00\x35')

    def test_stack_consumption_and_required_depth(self):
        for n in range(1, 17):
            dup = o.INFO[getattr(o, f'DUP{n}')]
            swap = o.INFO[getattr(o, f'SWAP{n}')]
            self.assertEqual((dup.pops, dup.pushes, dup.required), (0, 1, n))
            self.assertEqual((swap.pops, swap.pushes, swap.required), (0, 0, n+1))
        self.assertEqual(o.INFO[o.ADD].required, 2)
        self.assertEqual(o.INFO[o.CREATE2].pops, 4)

    def test_skeleton_all_push_widths_and_unknown_bytes(self):
        for width in range(33):
            push = getattr(o, f'PUSH{width}')
            code = push + o.JUMPDEST * width + o.ADD + b'\x0c'
            self.assertEqual(normalize_pushes(code), o.PUSH0 + o.ADD + b'\x0c')
            self.assertEqual(instruction_boundaries(code), [0, width+1, width+2, width+3])
        self.assertEqual(normalize_pushes(o.PUSH32 + b'\x01'), o.PUSH0)
        self.assertEqual(instruction_boundaries(o.PUSH32 + b'\x01'), [0])
        self.assertEqual(instruction_boundaries(b''), [0])

    def test_tvm_opcodes_are_enabled_by_default_with_official_stack_effects(self):
        expected = {
            o.CALLTOKEN: (8, 1), o.TOKENBALANCE: (2, 1),
            o.CALLTOKENVALUE: (0, 1), o.CALLTOKENID: (0, 1),
            o.ISCONTRACT: (1, 1), o.FREEZE: (3, 1),
            o.UNFREEZE: (2, 1), o.FREEZEEXPIRETIME: (2, 1),
            o.VOTEWITNESS: (4, 1), o.WITHDRAWREWARD: (0, 1),
            o.FREEZEBALANCEV2: (2, 1), o.UNFREEZEBALANCEV2: (2, 1),
            o.CANCELALLUNFREEZEV2: (0, 1), o.WITHDRAWEXPIREUNFREEZE: (0, 1),
            o.DELEGATERESOURCE: (3, 1), o.UNDELEGATERESOURCE: (3, 1),
        }
        self.assertTrue(o.tvm_opcodes_enabled())
        for opcode, stack_effect in expected.items():
            with self.subTest(opcode=opcode.hex()):
                info = o.INFO[opcode]
                self.assertEqual((info.pops, info.pushes), stack_effect)
                self.assertIs(o.BY_VALUE[opcode[0]], info)
                self.assertEqual(o.BY_NAME[info.name], opcode)

    def test_tvm_opcode_toggle_updates_existing_shared_views(self):
        by_value = o.BY_VALUE
        try:
            o.set_tvm_opcodes_enabled(False)
            self.assertFalse(o.tvm_opcodes_enabled())
            self.assertIs(by_value, o.BY_VALUE)
            self.assertIsNone(by_value[o.CALLTOKENVALUE[0]])
            self.assertNotIn(o.CALLTOKENVALUE, o.INFO)
            self.assertNotIn('CALLTOKENVALUE', o.BY_NAME)
            self.assertIsNone(next(disassemble(o.CALLTOKENVALUE)).name)
            with self.assertRaises(TypeError):
                o.set_tvm_opcodes_enabled(1)
        finally:
            o.set_tvm_opcodes_enabled(True)
        self.assertEqual(next(disassemble(o.CALLTOKENVALUE)).name, 'CALLTOKENVALUE')



if __name__ == '__main__': unittest.main()
