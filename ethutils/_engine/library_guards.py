"""Recognize Solidity library checks that require calls through DELEGATECALL.

A known prefix compares ADDRESS with a nonzero linked library address. Short
execution probes then check whether direct calls revert and delegated calls
pass the entry check. Unrecognized layouts and exhausted probes yield None.
"""
from .. import opcodes as op
from . import symbolic as e

_MEMORY_PROLOGUES = (
    b'',
    op.PUSH1 + b'\x80' + op.PUSH1 + b'\x40' + op.MSTORE,
    op.PUSH1 + b'\x80' + op.DUP1 + op.PUSH1 + b'\x40' + op.MSTORE,
)
_SCAFFOLD = frozenset({op.JUMPDEST, op.POP, op.ISZERO, op.EQ, op.JUMP})
_ARITHMETIC = frozenset(operation.opcode for operation in e.ARITHMETIC)


def _prefix_check(code):
    """Recognize a library address comparison at the start of code.

    Return the ADDRESS-equality expression, or None for other prefix layouts.
    """
    for prefix in _MEMORY_PROLOGUES:
        if not code.startswith(prefix):
            continue
        pc = len(prefix)
        for width in (20, 32):
            push = op.PUSH20 if width == 20 else op.PUSH32
            # Legacy PUSH20 <self> ADDRESS EQ; via-IR ADDRESS PUSH32 <self> EQ.
            for address_first in (False, True):
                start = pc + (1 if address_first else 0)
                if address_first and code[pc:pc+1] != op.ADDRESS:
                    continue
                if code[start:start+1] != push:
                    continue
                end = start + 1 + width
                suffix = op.EQ if address_first else op.ADDRESS + op.EQ
                if code[end:end+len(suffix)] != suffix:
                    continue
                address = int.from_bytes(code[start+1:end], 'big')
                if 0 < address < 1 << 160:
                    return e.simplify(op.EQ, e.Expr(op.ADDRESS), address)
    return None


class _Probe(e.Interpreter):
    """Execute the stack operations and jumps used in a library entry check."""
    def before_instruction(self, state, opcode):
        pass

    def on_jump(self, state, pc, target, unconditional):
        pass


def _scaffold(opcode):
    """Return whether an opcode belongs to the supported stack and control-flow entry checks."""
    info = op.INFO.get(opcode)
    return info is not None and (info.family in {'push', 'dup', 'swap'} or opcode in _SCAFFOLD)


def _step(vm, state, budget):
    """Execute one instruction within the shared step budget; return whether execution continues."""
    if budget[0] <= 0:
        return False
    budget[0] -= 1
    opcode = vm.code[state.pc:state.pc+1]
    if opcode in {op.JUMP, op.JUMPI} and (
            not state.stack or not isinstance(e.evaluate(state.stack[-1], state), int)):
        # Continue a probe only when its jump destination resolves to an integer.
        return False
    try:
        vm.step(state)
    except e.Halt:
        return False
    return True


def _after_guard(vm, state, check, direct, budget, *, rejection):
    """Follow an entry check with the address comparison fixed for a direct or delegated call.

    Return whether the branch reaches REVERT when rejection is requested, or
    passes into function work otherwise.
    """
    state = state.fork()
    state.facts[check] = int(direct)
    # Execute the recognized JUMPI with a concrete call-protection flag.
    if not _step(vm, state, budget):
        return False
    while state.pc < len(vm.code):
        opcode = vm.code[state.pc:state.pc+1]
        if opcode == op.REVERT:
            return rejection and len(state.stack) >= 2
        if opcode in {op.INVALID, op.JUMPI}:
            return False
        if opcode in {op.RETURN, op.STOP}:
            return not rejection and len(state.stack) >= op.INFO[opcode].required
        if not _scaffold(opcode):
            # Function work marks passage through the allowed branch. Confirming
            # direct-call rejection requires following entry checks through REVERT.
            return not rejection and opcode in op.INFO and len(state.stack) >= op.INFO[opcode].required
        if not _step(vm, state, budget):
            return False
    return False


def _entry_status(vm, seed, check, budget):
    """Return True for a confirmed delegatecall guard, False for an unguarded entry, or None."""
    # An earlier ADDRESS-dependent branch makes the library context ambiguous.
    if any(op.ADDRESS in e.dependencies(expr) for expr, _ in seed.predicates):
        return None
    state = seed.fork()
    while state.pc < len(vm.code):
        opcode = vm.code[state.pc:state.pc+1]
        if opcode == op.JUMPI:
            if len(state.stack) < 2:
                return None
            target = e.evaluate(state.stack[-1], state)
            if not isinstance(target, int) or target not in vm.jumpdests:
                return None
            condition = e.evaluate(state.stack[-2], state)
            if condition in (check, e.simplify(op.ISZERO, check)):
                direct = _after_guard(vm, state, check, True, budget, rejection=True)
                delegated = _after_guard(vm, state, check, False, budget, rejection=False)
                return True if direct and delegated else None
            # Argument and call-value checks begin after the library guard.
            # A different ADDRESS-dependent check leaves the entry unresolved.
            return None if op.ADDRESS in e.dependencies(condition) else False
        if opcode in {op.REVERT, op.INVALID, op.ADDRESS}:
            return None
        if opcode in _ARITHMETIC and opcode not in _SCAFFOLD:
            # Further arithmetic may transform the protection flag; keep its status unknown.
            return None
        if opcode in {op.STOP, op.RETURN}:
            return False if len(state.stack) >= op.INFO[opcode].required else None
        if not _scaffold(opcode):
            return False if opcode in op.INFO and len(state.stack) >= op.INFO[opcode].required else None
        if not _step(vm, state, budget):
            return None
    return None


def classify_entries(code, seeds, limits, dispatch_complete):
    """Determine which function entries require DELEGATECALL.

    Return a mapping from (selector, entry offset) to True for a confirmed guard,
    False for an unguarded library entry, or None when unresolved. A confirmed
    guard establishes that the address prefix belongs to a library. Each entry
    gets at most 64 probe steps, further restricted by the supplied limits.
    """
    check = _prefix_check(code)
    if check is None:
        return {}
    vm = _Probe(code, e.Limits(trace_length=0))
    results = {}
    for key, states in seeds.items():
        budget = [min(64, limits.max_steps, limits.max_path_steps)]
        statuses = [_entry_status(vm, seed, check, budget) for seed in states]
        results[key] = (False if False in statuses else
                        True if statuses and all(s is True for s in statuses) else None)
    # Confirm the library interpretation with at least one rejecting entry guard.
    if not any(status is True for status in results.values()):
        return {}
    if not dispatch_complete:
        results = {key: None if value is True else value for key, value in results.items()}
    return results
