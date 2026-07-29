import re
from ethutils import section

# regular expressions for single instructions
ADD    = "\x01"
DIV    = "\x04"
MOD    = "\x06"
EXP    = "\x0a"
GT     = "\x11"
EQ     = "\x14"
ISZERO = "\x15"
AND    = "\x16"
XOR    = "\x18"
SHL    = "\x1b"
SHR    = "\x1c"
CALLDATALOAD="\x35"
CALLDATACOPY="\x37"
CODECOPY="\x39"
POP    = "\x50"
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

# Push selector
PVALUE = f"(?:{PUSH1}(.)|{PUSH2}(..)|{PUSH3}(...)|{PUSH4}(....))"

# Duplicate top of stack and push selector
PSIGDUP = f"(?:{PVALUE}{DUP2}|(?:{DUP1}?|{SWAP1}{DUP2}){PVALUE})"

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
PINDUP = f"{PUSH0}{DUP1}?(?:{SWAP2}{DUP2})?{CALLDATALOAD}"
# Push 4 byte mask
PFFFFFFFF = f"{PUSH4}\xff\xff\xff\xff"

# Take the selector from the input and put it on the stack
PINSIG1 = f"(?:{P256P14}{PIN}|{PINDUP}{P256P14}{SWAP1}){DIV}"
PINSIG2 = f"{PINDUP}{PUSH1}\xe0{SHR}"
PINSIG  = f"({PFFFFFFFF})?(?:{PINSIG1}|{PINSIG2})({PFFFFFFFF}{AND})?(?(1){AND}|)"

# store input selector at memory address 00
INSIG00 = f"(?:{PUSH0}{PUSH0}{MSTORE}{PUSH1}\x04{PUSH0}{PUSH1}\x1c(?:{PUSH0}{ADD})?{CALLDATACOPY}|{PIN}{PUSH1}\x1c{MSTORE})"

MSTORE00 = f"{PUSH0}{MSTORE}"
MSTORE20 = f"{PUSH1}\x20{MSTORE}"
MSTORE80 = f"{PUSH1}\x80{MSTORE}"

MLOAD00 = f"{PUSH0}{MLOAD}"
MLOAD20 = f"{PUSH1}\x20{MLOAD}"
MLOAD80 = f"{PUSH1}\x80{MLOAD}"

DUPMSTORE80 = f"{PUSH1}\x80{DUP2}{SWAP1}{MSTORE}"
REVERT0 = f"{PUSH0}(?:{PUSH0}|{DUP1}){REVERT}"

SOMETHING = ".{,128}?"
ANYTHING  = ".*?"
NOTHING   = ""

def regexp(s):
    return re.compile(s.encode("latin1"), re.DOTALL)

# Solidity

# store input selector on stack [subsumed by ST7/SI7 which is tried first]
#ST1 = regexp(f"{SOMETHING}{PINSIG}")
# duplicate input selector, push selector, and jump on equal
#SI1 = regexp(f"{PSIGDUP}{JMPEQ}")

# store input selector at memory address 20
ST2 = regexp(f"{SOMETHING}{PINSIG}{MSTORE20}")
# get input selector from memory address 20, push selector and jump on equal or unequal
SI2 = regexp(f"{ANYTHING}(?:{PVALUE}{MLOAD20}|{MLOAD20}{PVALUE}){JMPXX}")

# selector on stack, immediately consumed, optionally stored in memory 0x80
ST3 = regexp(NOTHING)
SI3 = regexp(f"{ANYTHING}{PINSIG}(?:{DUPMSTORE80})?{PVALUE}{JMPXX}")

# store input selector at memory address 00
ST4 = regexp(f"{SOMETHING}{INSIG00}")
# get input selector from memory address 00, push selector and jump on equal or unequal
SI4 = regexp(f"{ANYTHING}(?:{PVALUE}{MLOAD00}|{MLOAD00}{PVALUE}){JMPXX}")

# store input selector at memory address 80
ST5 = regexp(f"{SOMETHING}{PINSIG}{MSTORE80}")
# get input selector from memory address 20, push selector and jump on equal or unequal
SI5 = regexp(f"{ANYTHING}(?:{PVALUE}{MLOAD80}|{MLOAD80}{PVALUE}){JMPXX}")

# store input selector on stack
ST6 = regexp(f"{SOMETHING}{PINSIG}")
# duplicate input selector on stack, push selector, and jump on unequal
SI6 = regexp(f"{ANYTHING}{PSIGDUP}{JMPNE}")
### THIS IS NOT SAFE, MAY CATCH TOO MANY SELECTORS, redo one day
### Between DIV and comparison, there may be instructions that are stack-neutral
### Further instances are most probably always preceded by 5b

# Solidity >= ca. 0.5.6
ST7 = regexp(f"{SOMETHING}{PINSIG}")
# duplicate input selector on stack, push selector, and jump on equal
SI7 = regexp(f"(?:{JMP}{JUMPDEST})?(?:{PSIGDUP}{JMPGT}|{REVERT0}{JUMPDEST})*(?:{POP})?{PSIGDUP}{JMPEQ}")

# Vyper?
ST8 = regexp(NOTHING)
SI8 = regexp(f"(?:^|{ANYTHING}{JUMPDEST}){PVALUE}{PINSIG}{JMPNE}")



# compatibility to old version
def signatures(code):
    return selectors(code)

def selectors(code):
    sections = section.decompose(code)
    if len(sections) == 0 or sections[0][0] != section.CODE:
        return []
    code = sections[0][1]
    selectors = set()
    for reStart,reSelector,id in [(ST7,SI7,7), (ST2,SI2,2), (ST3,SI3,3), (ST4,SI4,4), (ST5,SI5,5), (ST6,SI6,6), (ST8,SI8,8)]:
        c = code
        result = reStart.match(c)
        while result:
            c = c[result.end():]
            result = reSelector.match(c)
            if result:
                selectors = selectors | {x.rjust(4,b"\x00") for x in result.groups() if x is not None}
        if selectors:
            break
    if not selectors:
        selectors = vyper_selectors(code)
    return sorted(selectors)


VYPER_JUMP_TABLE = regexp(
    f"{PUSH0}{CALLDATALOAD}{PUSH1}\xe0{SHR}"
    f"{PUSH1}\x02{PVALUE}{DUP3}{MOD}{PUSH1}\x01{SHL}{PVALUE}{ADD}"
    f"{PUSH1}\x1e{CODECOPY}{PUSH0}{MLOAD}{JUMP}"
    )
VYPER_SELECTOR = regexp(f"{JUMPDEST}{PVALUE}{DUP2}{XOR}{PVALUE}{JUMPI}")

def vyper_selectors(code):
    selectors = set()
    m = VYPER_JUMP_TABLE.match(code)
    if not m:
        return selectors
    table_size, table_pos = tuple(int.from_bytes(g, "big") for g in m.groups() if g is not None)
    for _ in range(table_size):
        pos = code[table_pos:table_pos+2]
        while True:
            m = VYPER_SELECTOR.match(code, int.from_bytes(pos, "big"))
            if not m:
                break
            sig, pos = tuple(g for g in m.groups() if g is not None)
            selectors.add(sig.rjust(4,b"\x00"))
        table_pos += 2
    return selectors
