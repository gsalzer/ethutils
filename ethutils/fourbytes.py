import re
from ethutils import section

# regular expressions for single instructions
ADD    = "\x01"
DIV    = "\x04"
EXP    = "\x0a"
GT     = "\x11"
EQ     = "\x14"
ISZERO = "\x15"
AND    = "\x16"
SHR    = "\x1c"
CALLDATALOAD="\x35"
CALLDATACOPY="\x37"
CODECOPY="\x39"
MLOAD  = "\x51"
MSTORE = "\x52"
JUMP   = "\x56"
JUMPI  = "\x57"
JUMPDEST="\\\x5b"
PUSH1  = "\x60"
PUSH2  = "\x61"
PUSH3  = "\x62"
PUSH4  = "\x63"
PUSH29 = "\\\x7c"
PUSH0  = f"(?:\x5f|{PUSH1}\x00)"
DUP1   = "\x80"
DUP2   = "\x81"
DUP3   = "\x82"
DUP4   = "\x83"
SWAP1  = "\x90"
SWAP2  = "\x91"
REVERT = "\xfd"

# Push signature constant
PSIG = f"(?:{PUSH1}(.)|{PUSH2}(..)|{PUSH3}(...)|{PUSH4}(....))"

# Duplicate top of stack and push signature constant
PSIGDUP = f"(?:{PSIG}{DUP2}|{DUP1}{PSIG})"

# push code address or length
PADDR = f"(?:{PUSH1}.|{PUSH2}..|{PUSH3}...)"

# Jumps
JMP   = f"{PADDR}{JUMP}"
JMPI  = f"{PADDR}{JUMPI}"
JMPEQ = f"{EQ}{JMPI}"
JMPNE = f"{EQ}{ISZERO}{JMPI}"
JMPXX = f"{EQ}{ISZERO}?{JMPI}"
JMPGT = f"{GT}{JMPI}"

# Push 256^14 (for selecting 4 bytes from input)
P256P14v1=f"{PUSH1}\xe0{PUSH1}\x02{EXP}"
P256P14v2=f"{PUSH29}\x01\x00{{28}}"
# V3: get constant from code area
P256P14v3=f"{PUSH0}{DUP1}{MLOAD}{PUSH1}\x20{PADDR}{DUP4}{CODECOPY}{DUP2}{MLOAD}{SWAP2}{MSTORE}"
P256P14  =f"(?:{P256P14v1}|{P256P14v2}|{P256P14v3})"

# Push input data
PIN = f"{PUSH0}{CALLDATALOAD}"
PINDUP = f"{PUSH0}{DUP1}?{CALLDATALOAD}"

# Push 4 byte mask
PFFFFFFFF = f"{PUSH4}\xff\xff\xff\xff"

# Take the signature from the input and put it on the stack
PINSIG1 = f"(?:{P256P14}{PIN}|{PINDUP}{P256P14}{SWAP1}){DIV}"
PINSIG2 = f"{PINDUP}{PUSH1}\xe0{SHR}"
PINSIG  = f"({PFFFFFFFF})?(?:{PINSIG1}|{PINSIG2})({PFFFFFFFF}{AND})?(?(1){AND}|)"

# store input signature at memory address 00
INSIG00 = f"(?:{PUSH0}{PUSH0}{MSTORE}{PUSH1}\x04{PUSH0}{PUSH1}\x1c(?:{PUSH0}{ADD})?{CALLDATACOPY}|{PIN}{PUSH1}\x1c{MSTORE})"

MSTORE00 = f"{PUSH0}{MSTORE}"
MSTORE20 = f"{PUSH1}\x20{MSTORE}"
MSTORE80 = f"{PUSH1}\x80{MSTORE}"

MLOAD00 = f"{PUSH0}{MLOAD}"
MLOAD20 = f"{PUSH1}\x20{MLOAD}"
MLOAD80 = f"{PUSH1}\x80{MLOAD}"

DUPMSTORE80 = f"{PUSH1}\x80{DUP2}{SWAP1}{MSTORE}"
REVERT0 = f"{PUSH0}{DUP1}{REVERT}"

SOMETHING = ".{,128}?"
ANYTHING  = ".*?"
NOTHING   = ""

def regexp(s):
    return re.compile(s.encode("latin1"), re.DOTALL)

# Solidity
# store input signature on stack
ST1 = regexp(f"{SOMETHING}{PINSIG}")
# duplicate input signature on stack, push signature constant, and jump on equal
SI1 = regexp(f"{PSIGDUP}{JMPEQ}")

# store input signature at memory address 20
ST2 = regexp(f"{SOMETHING}{PINSIG}{MSTORE20}")
# get input signature from memory address 20, push signature constant and jump on equal or unequal
SI2 = regexp(f"{ANYTHING}(?:{PSIG}{MLOAD20}|{MLOAD20}{PSIG}){JMPXX}")

# signature on stack, immediately consumed, optionally stored in memory 0x80
ST3 = regexp(NOTHING)
SI3 = regexp(f"{ANYTHING}{PINSIG}(?:{DUPMSTORE80})?{PSIG}{JMPXX}")

# store input signature at memory address 00
ST4 = regexp(f"{SOMETHING}{INSIG00}")
# get input signature from memory address 00, push signature constant and jump on equal or unequal
SI4 = regexp(f"{ANYTHING}(?:{PSIG}{MLOAD00}|{MLOAD00}{PSIG}){JMPXX}")

# store input signature at memory address 80
ST5 = regexp(f"{SOMETHING}{PINSIG}{MSTORE80}")
# get input signature from memory address 20, push signature constant and jump on equal or unequal
SI5 = regexp(f"{ANYTHING}(?:{PSIG}{MLOAD80}|{MLOAD80}{PSIG}){JMPXX}")

# store input signature on stack
ST6 = regexp(f"{SOMETHING}{PINSIG}")
# duplicate input signature on stack, push signature constant, and jump on unequal
SI6 = regexp(f"{ANYTHING}{PSIGDUP}{JMPNE}")
### THIS IS NOT SAFE, MAY CATCH TOO MANY SIGNATURES, redo one day
### Between DIV and comparison, there may be instructions that are stack-neutral
### Further instances are most probably always preceded by 5b

# Solidity >= ca. 0.5.6
ST7 = regexp(f"{SOMETHING}{PINSIG}")
# duplicate input signature on stack, push signature constant, and jump on equal
SI7 = regexp(f"(?:{JMP}{JUMPDEST})?(?:{PSIGDUP}{JMPGT}|{REVERT0}{JUMPDEST})*{PSIGDUP}{JMPEQ}")

# Vyper?
ST8 = regexp(NOTHING)
SI8 = regexp(f"(?:^|{ANYTHING}{JUMPDEST}){PSIG}{PINSIG}{JMPNE}")

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
                signatures = signatures | {x.rjust(4,b"\x00") for x in result.groups() if x is not None}
        if signatures:
            break
    return sorted(signatures)
