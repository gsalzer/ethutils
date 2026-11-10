"""EVM and optionally TVM opcode constants and instruction descriptions.

Each mnemonic is a one-byte bytes value. INFO maps these values to names,
stack requirements and operand sizes. BY_VALUE accepts integer byte values;
BY_NAME maps instruction names to their opcode bytes. TRON TVM extensions are
enabled by default and can be controlled with set_tvm_opcodes_enabled().
"""
from dataclasses import dataclass
from types import MappingProxyType


@dataclass(frozen=True)
class InstructionInfo:
    """Instruction name, stack requirements and immediate operand width.

    pops/pushes describe stack removal/addition; required is the minimum stack
    depth, which also accounts for DUP and SWAP. immediate is a byte count.
    """
    name: str
    pops: int
    pushes: int
    required: int
    immediate: int = 0
    family: str | None = None


_info = {}


def _define(name, opcode, pops, pushes, *, required=None, immediate=0, family=None):
    """Register one unique opcode and return its one-byte encoding."""
    if type(opcode) is not bytes or len(opcode) != 1 or opcode in _info:
        raise ValueError("opcode must be a unique single byte")
    _info[opcode] = InstructionInfo(name, pops, pushes,
        pops if required is None else required, immediate, family)
    return opcode


STOP = _define("STOP", b"\x00", 0, 0)
ADD = _define("ADD", b"\x01", 2, 1)
MUL = _define("MUL", b"\x02", 2, 1)
SUB = _define("SUB", b"\x03", 2, 1)
DIV = _define("DIV", b"\x04", 2, 1)
SDIV = _define("SDIV", b"\x05", 2, 1)
MOD = _define("MOD", b"\x06", 2, 1)
SMOD = _define("SMOD", b"\x07", 2, 1)
ADDMOD = _define("ADDMOD", b"\x08", 3, 1)
MULMOD = _define("MULMOD", b"\x09", 3, 1)
EXP = _define("EXP", b"\x0a", 2, 1)
SIGNEXTEND = _define("SIGNEXTEND", b"\x0b", 2, 1)
LT = _define("LT", b"\x10", 2, 1)
GT = _define("GT", b"\x11", 2, 1)
SLT = _define("SLT", b"\x12", 2, 1)
SGT = _define("SGT", b"\x13", 2, 1)
EQ = _define("EQ", b"\x14", 2, 1)
ISZERO = _define("ISZERO", b"\x15", 1, 1)
AND = _define("AND", b"\x16", 2, 1)
OR = _define("OR", b"\x17", 2, 1)
XOR = _define("XOR", b"\x18", 2, 1)
NOT = _define("NOT", b"\x19", 1, 1)
BYTE = _define("BYTE", b"\x1a", 2, 1)
SHL = _define("SHL", b"\x1b", 2, 1)
SHR = _define("SHR", b"\x1c", 2, 1)
SAR = _define("SAR", b"\x1d", 2, 1)
KECCAK256 = _define("KECCAK256", b"\x20", 2, 1)
ADDRESS = _define("ADDRESS", b"\x30", 0, 1)
BALANCE = _define("BALANCE", b"\x31", 1, 1)
ORIGIN = _define("ORIGIN", b"\x32", 0, 1)
CALLER = _define("CALLER", b"\x33", 0, 1)
CALLVALUE = _define("CALLVALUE", b"\x34", 0, 1)
CALLDATALOAD = _define("CALLDATALOAD", b"\x35", 1, 1)
CALLDATASIZE = _define("CALLDATASIZE", b"\x36", 0, 1)
CALLDATACOPY = _define("CALLDATACOPY", b"\x37", 3, 0)
CODESIZE = _define("CODESIZE", b"\x38", 0, 1)
CODECOPY = _define("CODECOPY", b"\x39", 3, 0)
GASPRICE = _define("GASPRICE", b"\x3a", 0, 1)
EXTCODESIZE = _define("EXTCODESIZE", b"\x3b", 1, 1)
EXTCODECOPY = _define("EXTCODECOPY", b"\x3c", 4, 0)
RETURNDATASIZE = _define("RETURNDATASIZE", b"\x3d", 0, 1)
RETURNDATACOPY = _define("RETURNDATACOPY", b"\x3e", 3, 0)
EXTCODEHASH = _define("EXTCODEHASH", b"\x3f", 1, 1)
BLOCKHASH = _define("BLOCKHASH", b"\x40", 1, 1)
COINBASE = _define("COINBASE", b"\x41", 0, 1)
TIMESTAMP = _define("TIMESTAMP", b"\x42", 0, 1)
NUMBER = _define("NUMBER", b"\x43", 0, 1)
PREVRANDAO = _define("PREVRANDAO", b"\x44", 0, 1)
GASLIMIT = _define("GASLIMIT", b"\x45", 0, 1)
CHAINID = _define("CHAINID", b"\x46", 0, 1)
SELFBALANCE = _define("SELFBALANCE", b"\x47", 0, 1)
BASEFEE = _define("BASEFEE", b"\x48", 0, 1)
BLOBHASH = _define("BLOBHASH", b"\x49", 1, 1)
BLOBBASEFEE = _define("BLOBBASEFEE", b"\x4a", 0, 1)
POP = _define("POP", b"\x50", 1, 0)
MLOAD = _define("MLOAD", b"\x51", 1, 1)
MSTORE = _define("MSTORE", b"\x52", 2, 0)
MSTORE8 = _define("MSTORE8", b"\x53", 2, 0)
SLOAD = _define("SLOAD", b"\x54", 1, 1)
SSTORE = _define("SSTORE", b"\x55", 2, 0)
JUMP = _define("JUMP", b"\x56", 1, 0)
JUMPI = _define("JUMPI", b"\x57", 2, 0)
PC = _define("PC", b"\x58", 0, 1)
MSIZE = _define("MSIZE", b"\x59", 0, 1)
GAS = _define("GAS", b"\x5a", 0, 1)
JUMPDEST = _define("JUMPDEST", b"\x5b", 0, 0)
TLOAD = _define("TLOAD", b"\x5c", 1, 1)
TSTORE = _define("TSTORE", b"\x5d", 2, 0)
MCOPY = _define("MCOPY", b"\x5e", 3, 0)
PUSH0 = _define("PUSH0", b"\x5f", 0, 1, immediate=0, family="push")
PUSH1 = _define("PUSH1", b"\x60", 0, 1, immediate=1, family="push")
PUSH2 = _define("PUSH2", b"\x61", 0, 1, immediate=2, family="push")
PUSH3 = _define("PUSH3", b"\x62", 0, 1, immediate=3, family="push")
PUSH4 = _define("PUSH4", b"\x63", 0, 1, immediate=4, family="push")
PUSH5 = _define("PUSH5", b"\x64", 0, 1, immediate=5, family="push")
PUSH6 = _define("PUSH6", b"\x65", 0, 1, immediate=6, family="push")
PUSH7 = _define("PUSH7", b"\x66", 0, 1, immediate=7, family="push")
PUSH8 = _define("PUSH8", b"\x67", 0, 1, immediate=8, family="push")
PUSH9 = _define("PUSH9", b"\x68", 0, 1, immediate=9, family="push")
PUSH10 = _define("PUSH10", b"\x69", 0, 1, immediate=10, family="push")
PUSH11 = _define("PUSH11", b"\x6a", 0, 1, immediate=11, family="push")
PUSH12 = _define("PUSH12", b"\x6b", 0, 1, immediate=12, family="push")
PUSH13 = _define("PUSH13", b"\x6c", 0, 1, immediate=13, family="push")
PUSH14 = _define("PUSH14", b"\x6d", 0, 1, immediate=14, family="push")
PUSH15 = _define("PUSH15", b"\x6e", 0, 1, immediate=15, family="push")
PUSH16 = _define("PUSH16", b"\x6f", 0, 1, immediate=16, family="push")
PUSH17 = _define("PUSH17", b"\x70", 0, 1, immediate=17, family="push")
PUSH18 = _define("PUSH18", b"\x71", 0, 1, immediate=18, family="push")
PUSH19 = _define("PUSH19", b"\x72", 0, 1, immediate=19, family="push")
PUSH20 = _define("PUSH20", b"\x73", 0, 1, immediate=20, family="push")
PUSH21 = _define("PUSH21", b"\x74", 0, 1, immediate=21, family="push")
PUSH22 = _define("PUSH22", b"\x75", 0, 1, immediate=22, family="push")
PUSH23 = _define("PUSH23", b"\x76", 0, 1, immediate=23, family="push")
PUSH24 = _define("PUSH24", b"\x77", 0, 1, immediate=24, family="push")
PUSH25 = _define("PUSH25", b"\x78", 0, 1, immediate=25, family="push")
PUSH26 = _define("PUSH26", b"\x79", 0, 1, immediate=26, family="push")
PUSH27 = _define("PUSH27", b"\x7a", 0, 1, immediate=27, family="push")
PUSH28 = _define("PUSH28", b"\x7b", 0, 1, immediate=28, family="push")
PUSH29 = _define("PUSH29", b"\x7c", 0, 1, immediate=29, family="push")
PUSH30 = _define("PUSH30", b"\x7d", 0, 1, immediate=30, family="push")
PUSH31 = _define("PUSH31", b"\x7e", 0, 1, immediate=31, family="push")
PUSH32 = _define("PUSH32", b"\x7f", 0, 1, immediate=32, family="push")
DUP1 = _define("DUP1", b"\x80", 0, 1, required=1, family="dup")
DUP2 = _define("DUP2", b"\x81", 0, 1, required=2, family="dup")
DUP3 = _define("DUP3", b"\x82", 0, 1, required=3, family="dup")
DUP4 = _define("DUP4", b"\x83", 0, 1, required=4, family="dup")
DUP5 = _define("DUP5", b"\x84", 0, 1, required=5, family="dup")
DUP6 = _define("DUP6", b"\x85", 0, 1, required=6, family="dup")
DUP7 = _define("DUP7", b"\x86", 0, 1, required=7, family="dup")
DUP8 = _define("DUP8", b"\x87", 0, 1, required=8, family="dup")
DUP9 = _define("DUP9", b"\x88", 0, 1, required=9, family="dup")
DUP10 = _define("DUP10", b"\x89", 0, 1, required=10, family="dup")
DUP11 = _define("DUP11", b"\x8a", 0, 1, required=11, family="dup")
DUP12 = _define("DUP12", b"\x8b", 0, 1, required=12, family="dup")
DUP13 = _define("DUP13", b"\x8c", 0, 1, required=13, family="dup")
DUP14 = _define("DUP14", b"\x8d", 0, 1, required=14, family="dup")
DUP15 = _define("DUP15", b"\x8e", 0, 1, required=15, family="dup")
DUP16 = _define("DUP16", b"\x8f", 0, 1, required=16, family="dup")
SWAP1 = _define("SWAP1", b"\x90", 0, 0, required=2, family="swap")
SWAP2 = _define("SWAP2", b"\x91", 0, 0, required=3, family="swap")
SWAP3 = _define("SWAP3", b"\x92", 0, 0, required=4, family="swap")
SWAP4 = _define("SWAP4", b"\x93", 0, 0, required=5, family="swap")
SWAP5 = _define("SWAP5", b"\x94", 0, 0, required=6, family="swap")
SWAP6 = _define("SWAP6", b"\x95", 0, 0, required=7, family="swap")
SWAP7 = _define("SWAP7", b"\x96", 0, 0, required=8, family="swap")
SWAP8 = _define("SWAP8", b"\x97", 0, 0, required=9, family="swap")
SWAP9 = _define("SWAP9", b"\x98", 0, 0, required=10, family="swap")
SWAP10 = _define("SWAP10", b"\x99", 0, 0, required=11, family="swap")
SWAP11 = _define("SWAP11", b"\x9a", 0, 0, required=12, family="swap")
SWAP12 = _define("SWAP12", b"\x9b", 0, 0, required=13, family="swap")
SWAP13 = _define("SWAP13", b"\x9c", 0, 0, required=14, family="swap")
SWAP14 = _define("SWAP14", b"\x9d", 0, 0, required=15, family="swap")
SWAP15 = _define("SWAP15", b"\x9e", 0, 0, required=16, family="swap")
SWAP16 = _define("SWAP16", b"\x9f", 0, 0, required=17, family="swap")
LOG0 = _define("LOG0", b"\xa0", 2, 0, family="log")
LOG1 = _define("LOG1", b"\xa1", 3, 0, family="log")
LOG2 = _define("LOG2", b"\xa2", 4, 0, family="log")
LOG3 = _define("LOG3", b"\xa3", 5, 0, family="log")
LOG4 = _define("LOG4", b"\xa4", 6, 0, family="log")

# TRON TVM extensions. These constants always exist, while their entries in
# INFO, BY_VALUE and BY_NAME are controlled as one dialect group below.
CALLTOKEN = b"\xd0"
TOKENBALANCE = b"\xd1"
CALLTOKENVALUE = b"\xd2"
CALLTOKENID = b"\xd3"
ISCONTRACT = b"\xd4"
FREEZE = b"\xd5"
UNFREEZE = b"\xd6"
FREEZEEXPIRETIME = b"\xd7"
VOTEWITNESS = b"\xd8"
WITHDRAWREWARD = b"\xd9"
FREEZEBALANCEV2 = b"\xda"
UNFREEZEBALANCEV2 = b"\xdb"
CANCELALLUNFREEZEV2 = b"\xdc"
WITHDRAWEXPIREUNFREEZE = b"\xdd"
DELEGATERESOURCE = b"\xde"
UNDELEGATERESOURCE = b"\xdf"

_tvm_info = {
    CALLTOKEN: InstructionInfo("CALLTOKEN", 8, 1, 8),
    TOKENBALANCE: InstructionInfo("TOKENBALANCE", 2, 1, 2),
    CALLTOKENVALUE: InstructionInfo("CALLTOKENVALUE", 0, 1, 0),
    CALLTOKENID: InstructionInfo("CALLTOKENID", 0, 1, 0),
    ISCONTRACT: InstructionInfo("ISCONTRACT", 1, 1, 1),
    FREEZE: InstructionInfo("FREEZE", 3, 1, 3),
    UNFREEZE: InstructionInfo("UNFREEZE", 2, 1, 2),
    FREEZEEXPIRETIME: InstructionInfo("FREEZEEXPIRETIME", 2, 1, 2),
    VOTEWITNESS: InstructionInfo("VOTEWITNESS", 4, 1, 4),
    WITHDRAWREWARD: InstructionInfo("WITHDRAWREWARD", 0, 1, 0),
    FREEZEBALANCEV2: InstructionInfo("FREEZEBALANCEV2", 2, 1, 2),
    UNFREEZEBALANCEV2: InstructionInfo("UNFREEZEBALANCEV2", 2, 1, 2),
    CANCELALLUNFREEZEV2: InstructionInfo("CANCELALLUNFREEZEV2", 0, 1, 0),
    WITHDRAWEXPIREUNFREEZE: InstructionInfo("WITHDRAWEXPIREUNFREEZE", 0, 1, 0),
    DELEGATERESOURCE: InstructionInfo("DELEGATERESOURCE", 3, 1, 3),
    UNDELEGATERESOURCE: InstructionInfo("UNDELEGATERESOURCE", 3, 1, 3),
}

CREATE = _define("CREATE", b"\xf0", 3, 1)
CALL = _define("CALL", b"\xf1", 7, 1)
CALLCODE = _define("CALLCODE", b"\xf2", 7, 1)
RETURN = _define("RETURN", b"\xf3", 2, 0)
DELEGATECALL = _define("DELEGATECALL", b"\xf4", 6, 1)
CREATE2 = _define("CREATE2", b"\xf5", 4, 1)
STATICCALL = _define("STATICCALL", b"\xfa", 6, 1)
REVERT = _define("REVERT", b"\xfd", 2, 0)
INVALID = _define("INVALID", b"\xfe", 0, 0)
SELFDESTRUCT = _define("SELFDESTRUCT", b"\xff", 1, 0)

_by_name = {info.name: opcode for opcode, info in _info.items()}
INFO = MappingProxyType(_info)
BY_VALUE = [INFO.get(bytes([value])) for value in range(256)]
BY_NAME = MappingProxyType(_by_name)
TVM_OPCODES_ENABLED = False


def set_tvm_opcodes_enabled(enabled: bool) -> None:
    """Activate or deactivate TRON TVM opcodes in the shared lookup tables.

    Configure the dialect before starting analysis; changing it concurrently
    with analysis in another thread is unsupported. Opcode byte constants remain
    available while disabled, but their lookup entries become undefined.
    """
    if type(enabled) is not bool:
        raise TypeError("enabled must be a boolean")
    global TVM_OPCODES_ENABLED
    if enabled == TVM_OPCODES_ENABLED:
        return
    if enabled:
        _info.update(_tvm_info)
        _by_name.update((info.name, opcode) for opcode, info in _tvm_info.items())
    else:
        for opcode, info in _tvm_info.items():
            _info.pop(opcode, None)
            _by_name.pop(info.name, None)
    for opcode in _tvm_info:
        BY_VALUE[opcode[0]] = _info.get(opcode)
    TVM_OPCODES_ENABLED = enabled


def tvm_opcodes_enabled() -> bool:
    """Return whether TRON TVM opcode extensions are active."""
    return TVM_OPCODES_ENABLED


set_tvm_opcodes_enabled(True)
del _define
