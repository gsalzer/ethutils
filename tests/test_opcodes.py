import unittest
from ethutils import opcodes as o
from ethutils import normalize_pushes, instruction_boundaries


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



if __name__ == '__main__': unittest.main()
