import re
import ethutils.metadata

PUSHPOP = b'(\x60.|\x61..|\x62...|\x63.{4}|\x64.{5}|\x65.{6}|\x66.{7}|\x67.{8}|\x68.{9}|\x69.{10}|\x6a.{11}|\x6b.{12}|\x6c.{13}|\x6d.{14}|\x6e.{15}|\x6f.{16}|\x70.{17}|\x71.{18}|\x72.{19}|\x73.{20}|\x74.{21}|\x75.{22}|\x76.{23}|\x77.{24}|\x78.{25}|\x79.{26}|\x7a.{27}|\\\x7b.{28}|\\\x7c.{29}|\\\x7d.{30}|\x7e.{31}|\x7f.{32})\x50'
CONTRACT_OLD = b'\x60\x60\x60\x40(\x81\x90|\x90\x81)?\x52'
CONTRACT_NEW = b'\x60\x80\x60\x40(\x81\x90|\x90\x81)?\x52'
CONTRACT_NEW2 = b'(?<=\x56[\x00\xfe])\x60.\x60\x40'
LIBRARY_CHECK  = b'\x73.{20}\x30\x14'
SOLIDITY_START = b'(' + PUSHPOP + b'|' + LIBRARY_CHECK + b')?(' + CONTRACT_OLD + b'|' + CONTRACT_NEW + b')' + b'|' + CONTRACT_NEW2

# DUP1 PUSH1 . PUSH1 00 CODECOPY PUSH1 00 RETURN STOP (PUSH1 00 CALLDATALOAD | CALLDATASIZE)
DEPLOYMENT1 = b'(?<=\x80\x60.\x60\x00\x39\x60\x00\xf3\x00)(\x60\x00\x35|\x36)'
# DUP1 PUSH2 .. PUSH1 00 CODECOPY PUSH1 00 RETURN STOP (PUSH1 00 CALLDATALOAD | CALLDATASIZE)
DEPLOYMENT2 = b'(?<=\x80\x61..\x60\x00\x39\x60\x00\xf3\x00)(\x60\x00\x35|\xe6)'
# DUP1 PUSH2 .. PUSH1 00 CODECOPY PUSH2 .. JUMP PUSH1 00 PUSH2 .. MSTORE8
DEPLOYMENT3 = b'(?<=\x80\x61..\x60\x00\x39\x61..\x56)\x60\x00\x61..\x53'
# JUMP PUSH1 00 DATALOAD
DEPLOYMENT4 = b'(?<=\x56)\x60\x00\x35'
# DUP1 PUSH1 . PUSH1 00 CODECOPY PUSH1 00 RETURN PUSH1 
DEPLOYMENT5 = b'(?<=\x80\x60.\x60\x00\x39\x60\x00\xf3)\x60'

RE_CODE_START = re.compile(SOLIDITY_START + b'|' + DEPLOYMENT1 + b'|' + DEPLOYMENT2 + b'|' + DEPLOYMENT3 + b'|' + DEPLOYMENT4 + b'|' + DEPLOYMENT5, re.DOTALL)

STOP = b'\x00'
JUMP = b'\x56'
RETURN = b'\xf3'
INVALID = b'\xfe'
SELFDESTRUCT = b'\xff'

CODE = 'code'
META = 'meta'
DATA = 'data'

def splitCode(code):
    i = 0
    parts = []
    for m in RE_CODE_START.finditer(code):
        parts.append(code[i:m.start()])
        i = m.start()
    if i < len(code):
        parts.append(code[i:])
    return parts

def decompose(code):
    metadatas = ethutils.metadata.metadata(code)
    code_start = 0
    sections = []
    CODE_DATA = CODE # the very first section is code
    for meta_start,meta_length,_ in metadatas:
        parts = splitCode(code[code_start:meta_start])
        if len(parts) > 0:
            if parts[0] != b'':
                sections.append( (CODE_DATA, parts[0]) )
            sections.extend( (CODE,p) for p in parts[1:] )
        code_start = meta_start + meta_length
        sections.append( (META,code[meta_start:code_start]) )
        CODE_DATA = DATA
    parts = splitCode(code[code_start:])
    if len(parts) > 0:
        if parts[0] != b'':
            sections.append( (CODE_DATA, parts[0]) )
        sections.extend( (CODE,p) for p in parts[1:] )

    sanitized_sections = []
    last = b''
    for t,c in sections:
        if len(c) == 0:
            continue
        if t == CODE:
            last += c
            if last[-1:] not in (STOP,JUMP,RETURN,INVALID,SELFDESTRUCT):
                continue
        if last != b'':
            sanitized_sections.append((CODE,last))
            last = b''
        if t != CODE:
            sanitized_sections.append((t,c))
    if last != b'':
        sanitized_sections.append((CODE,last))
    assert len(code) == sum(len(c) for _,c in sanitized_sections)
    return sanitized_sections
