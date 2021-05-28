import re
from ethutils import section

DIV    = b'\x04'
GT     = b'\x11'
EQ     = b'\x14'
ISZERO = b'\x15'
AND    = b'\x16'
SHR    = b'\x1c'
DUP1   = b'\x80'
DUP2   = b'\x81'
SWAP1  = b'\x90'

# Push signature constant
PSIG = b'(?:\x60(.)|\x61(..)|\x62(...)|\x63(....))' # PUSH1/PUSH2/PUSH3/PUSH4 signature

# Duplicate top of stack and push signature constant
PSIGDUP = b'(?:'+ PSIG + DUP2 + b'|' + DUP1 + PSIG + b')'

# Jumps
JMP = b'(?:\x60.|\x61..|\x62...)\x56' # PUSH1/PUSH2/PUSH3 offset, JUMP
JMPI = b'(?:\x60.|\x61..|\x62...)\x57' # PUSH1/PUSH2/PUSH3 offset, JUMPI
JMPEQ = EQ+JMPI
JMPNE = EQ+ISZERO+JMPI
JMPXX = EQ+ISZERO+b'?'+JMPI
JMPGT = GT+JMPI
JMPDEST = b'\\\x5b'

# Push 256^14 (for selecting 4 bytes from input)
# V1: PUSH1 0xe0, PUSH1 0x02, EXP
P256P14v1=b'\x60\xe0\x60\x02\x0a'
# V2: PUSH29 0x100000000000000000000000000000000000000000000000000000000
P256P14v2=b'\\\x7c\x01\x00{28}'
# V3: get constant from code area
#     PUSH1 0x00, DUP1, MLOAD, PUSH1 0x20, PUSHx ..., DUP4, CODECOPY, DUP2, MLOAD, SWAP2, MSTORE
P256P14v3=b'\x60\x00\x80\x51\x60\x20(?:\x60.|\x61..|\x62...)\x83\x39\x81\x51\x91\x52'
#P256P14=b'(?:' + P256P14v1 + b'|' + P256P14v2 + b'|' + P256P14v3 + b'|' + b')' ????
P256P14=b'(?:' + P256P14v1 + b'|' + P256P14v2 + b'|' + P256P14v3 + b')'

# Push input data
PIN = b'\x60\x00\x35' # PUSH1 0x00, CALLDATALOAD

# Push 4 byte mask
P4F = b'\x63\xff\xff\xff\xff' # PUSH4 0xffffffff

# Take the signature from the input and put it on the stack
PINSIG1 = b'(?:'+P256P14+PIN+b'|'+PIN+P256P14+SWAP1+b')' + DIV
PINSIG2 = PIN + b'\x60\xe0' + SHR
PINSIG = b'('+P4F+b')?' + b'(?:' + PINSIG1 + b'|' + PINSIG2 + b')' + b'('+P4F+AND+b')?' + b'(?(1)'+AND+b'|)'

# store input signature at memory address 00
# PUSH1  0x00, PUSH1  0x00, MSTORE, PUSH1  0x04, PUSH1 0x00, PUSH1 0x1c, (optional: PUSH1 0x00, ADD), CALLDATACOPY 
# or
# PUSH1  0x00, CALLDATALOAD, PUSH1 0x1c, MSTORE
INSIG00 = b'(?:' + b'\x60\x00\x60\x00\x52\x60\x04\x60\x00\x60\x1c(?:\x60\x00\x01)?\x37' + b'|' + PIN + b'\x60\x1c\x52' + b')'

MSTORE00 = b'\x60\x00\x52' # PUSH1 0x00, MSTORE
MSTORE20 = b'\x60\x20\x52' # PUSH1 0x20, MSTORE
MSTORE80 = b'\x60\x80\x52' # PUSH1 0x80, MSTORE

MLOAD00 = b'\x60\x00\x51' # PUSH1 0x00, MLOAD
MLOAD20 = b'\x60\x20\x51' # PUSH1 0x20, MLOAD
MLOAD80 = b'\x60\x80\x51' # PUSH1 0x80, MLOAD

DUPMSTORE80 = b'\x60\x80\x81\x90\x52' # PUSH1 0x80, DUP2, SWAP1, MSTORE

SOMETHING = b'.{,128}?'
ANYTHING = b'.*?'
NOTHING  = b''

# Solidity
# store input signature on stack
ST1 = re.compile( SOMETHING + PINSIG, re.DOTALL)
# duplicate input signature on stack, push signature constant, and jump on equal
SI1 = re.compile( PSIGDUP + JMPEQ, re.DOTALL)

# store input signature at memory address 20
ST2 = re.compile( SOMETHING + PINSIG + MSTORE20, re.DOTALL)
# get input signature from memory address 20, push signature constant and jump on equal or unequal
SI2 = re.compile( ANYTHING + b'(?:' + PSIG + MLOAD20 + b'|' + MLOAD20 + PSIG + b')' + JMPXX, re.DOTALL)

# signature on stack, immediately consumed, optionally stored in memory 0x80
ST3 = re.compile( NOTHING, re.DOTALL)
SI3 = re.compile( ANYTHING + PINSIG + b'(?:' + DUPMSTORE80 + b')?' + PSIG + JMPXX, re.DOTALL)

# store input signature at memory address 00
ST4 = re.compile( SOMETHING + INSIG00, re.DOTALL)
# get input signature from memory address 00, push signature constant and jump on equal or unequal
SI4 = re.compile( ANYTHING + b'(?:' + PSIG + MLOAD00 + b'|' + MLOAD00 + PSIG + b')' + JMPXX, re.DOTALL)

# store input signature at memory address 80
ST5 = re.compile( SOMETHING + PINSIG + MSTORE80, re.DOTALL)
# get input signature from memory address 20, push signature constant and jump on equal or unequal
SI5 = re.compile( ANYTHING + b'(?:' + PSIG + MLOAD80 + b'|' + MLOAD80 + PSIG + b')' + JMPXX, re.DOTALL)

# store input signature on stack
ST6 = ST1
# duplicate input signature on stack, push signature constant, and jump on unequal
SI6 = re.compile( ANYTHING + PSIGDUP + JMPNE, re.DOTALL)
### THIS IS NOT SAFE, MAY CATCH TOO MANY SIGNATURES, redo if you have time
### Between DIV and comparison there may be instructions that are stack-neutral
### Further instances are most probably always preceded by 5b

# Solidity >= ca. 0.5.6
ST7 = ST1 
# duplicate input signature on stack, push signature constant, and jump on equal
SI7 = re.compile(b'(?:' + JMP + JMPDEST + b')?'+ b'(?:' + PSIGDUP + JMPGT + b')*' + PSIGDUP + JMPEQ, re.DOTALL)

# Vyper?
ST8 = re.compile(NOTHING, re.DOTALL)
SI8 = re.compile(b'(?:^|' + ANYTHING + JMPDEST + b')' + PSIG + PINSIG + JMPNE, re.DOTALL)

def signatures(code):
    sections = section.decompose(code)
    if len(sections) == 0 or sections[0][0] != section.CODE:
        return []
    code = sections[0][1]
    signatures = set()
    for reStart,reSignature,id in [(ST7,SI7,7), (ST1,SI1,1), (ST2,SI2,2), (ST3,SI3,3), (ST4,SI4,4), (ST5,SI5,5), (ST6,SI6,6), (ST8,SI8,8)]:
        c = code
        result = reStart.match(c)
        while result:
            c = c[result.end():]
            result = reSignature.match(c)
            if result:
                signatures = signatures | {x.rjust(4,b'\x00') for x in result.groups() if x is not None}
        if signatures:
            break
    return sorted(signatures)
