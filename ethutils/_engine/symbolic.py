"""Explore EVM execution paths using symbolic values for unknown inputs.

The interpreter tracks stack values, memory bytes and conditions on call data
and call value. It records function entries, return values, state reads and
potential effects. Instruction and state limits bound the search; unresolved
operations and exhausted limits are reported in the results.
"""
from collections import deque
from itertools import product
from dataclasses import asdict, dataclass, field, replace
from typing import Callable
from .calldata import uses_arguments
from .calldata_size import uses_size_arithmetic
from .storage import classify as storage_shape

INITIAL_PATH_BUDGET = 1024
SELECTOR_BUDGET_BONUS = 512
MAX_PATH_BUDGET = 1024

from ..decoding import instruction_boundaries
from ..arithmetic import MASK, EVALUATORS, signed, signed_divide, signed_modulo, sign_extend

from ..opcodes import (
    STOP, ADD, MUL, SUB, DIV, SDIV, MOD, SMOD,
    ADDMOD, MULMOD, EXP, SIGNEXTEND, LT, GT, SLT, SGT,
    EQ, ISZERO, AND, OR, XOR, NOT, BYTE, SHL,
    SHR, SAR, KECCAK256, ADDRESS, BALANCE, ORIGIN, CALLER, CALLVALUE,
    CALLDATALOAD, CALLDATASIZE, CALLDATACOPY, CODESIZE, CODECOPY, GASPRICE, EXTCODESIZE, EXTCODECOPY,
    RETURNDATASIZE, RETURNDATACOPY, EXTCODEHASH, BLOCKHASH, COINBASE, TIMESTAMP, NUMBER, PREVRANDAO,
    GASLIMIT, CHAINID, SELFBALANCE, BASEFEE, BLOBHASH, BLOBBASEFEE, POP, MLOAD,
    MSTORE, MSTORE8, SLOAD, SSTORE, JUMP, JUMPI, PC, MSIZE,
    GAS, JUMPDEST, TLOAD, TSTORE, MCOPY, LOG0, LOG1, LOG2,
    LOG3, LOG4, CREATE, CALL, CALLCODE, RETURN, DELEGATECALL, CREATE2,
    STATICCALL, REVERT, INVALID, SELFDESTRUCT, INFO,
)

OP_NAMES = {op: info.name for op, info in INFO.items()}

BOOLEAN_OPS = frozenset({EQ, LT, GT, SLT, SGT, ISZERO})
COMMUTATIVE_OPS = frozenset({ADD, MUL, AND, OR, XOR, EQ})
ABSORBING_OPS = frozenset({AND, MUL, DIV, MOD})
SELF_ANNIHILATING_OPS = frozenset({XOR, SUB})
ZERO_RIGHT_IDENTITY_OPS = frozenset({ADD, OR, XOR, SUB})
ZERO_LEFT_IDENTITY_OPS = frozenset({SHL, SHR, SAR})
ONE_RIGHT_IDENTITY_OPS = frozenset({MUL, DIV})
IDEMPOTENT_OPS = frozenset({AND, OR})
SH_OPS = frozenset({SHL, SHR})
# Expression tag representing the first four calldata bytes.
SELECTOR = -1

SELECTOR_MASK = (1 << 32) - 1

@dataclass(frozen=True)
class Expr:
    """An expression representing an unknown 256-bit value.

    op identifies the operation and args holds its operands in stack-pop order.
    SELECTOR represents the first four calldata bytes. Expressions are immutable
    and may share child expressions; a cached hash supports dictionary lookup.
    """
    op: bytes | int
    args: tuple = ()
    _hash: int = field(init=False, repr=False, compare=False)

    def __post_init__(self):
        object.__setattr__(self, "_hash", hash((self.op, self.args)))

    def __hash__(self): return self._hash

SEL, SIZE, VALUE = Expr(SELECTOR), Expr(CALLDATASIZE), Expr(CALLVALUE)
CODE_SIZE = Expr(CODESIZE)
Word = int | Expr


def concrete(opcode, operands):
    """Evaluate the registered integer operation with EVM word wraparound."""
    operation = OPERATIONS.get(opcode)
    if operation is None or operation.evaluate is None:
        raise ValueError(f"no concrete arithmetic operation for {opcode!r}")
    return operation.evaluate(*operands) & MASK


def boolean(x):
    return isinstance(x, Expr) and x.op in BOOLEAN_OPS

def simplify(op, *args):
    """Fold constants and supported identities, retaining unknown expressions.

    Operands are in stack-pop order. Recognized extraction of calldata
    bytes 0 through 3 becomes the dedicated selector expression.
    """
    if all(isinstance(a, int) for a in args):
        return concrete(op, args)
    x = args[0]
    y = args[1] if len(args) > 1 else None
    # Canonicalize commutative operations with a constant on the right.
    if op in COMMUTATIVE_OPS and isinstance(x, int):
        x, y = y, x
        args = (x, y)
    if op in ABSORBING_OPS and y == 0: return 0
    if op == MOD and y == 1: return 0
    if op in SELF_ANNIHILATING_OPS and x == y: return 0
    if op == EQ and x == y: return 1
    if op in ZERO_RIGHT_IDENTITY_OPS and y == 0: return x
    if op in ONE_RIGHT_IDENTITY_OPS and y == 1: return x
    if op in IDEMPOTENT_OPS and x == y: return x
    if op == AND and y == MASK: return x
    # shifts
    if op in ZERO_LEFT_IDENTITY_OPS and x==0: return y
    if op in SH_OPS and isinstance(x, int) and x >= 256: return 0
    if op == ISZERO and boolean(x) and x.op == ISZERO and boolean(x.args[0]): return x.args[0]
    # Recognize extraction of the first four calldata bytes by shifting or division.
    if ((op == SHR and x == 224 and y == Expr(CALLDATALOAD, (0,))) or
        (op == DIV and x == Expr(CALLDATALOAD, (0,)) and y == 1 << 224) or
        (op == AND and y == SELECTOR_MASK and x == SEL)):
        return SEL
    if op == SHR and isinstance(x, int) and isinstance(y, Expr) and y.op == SHL:
        shift, inner = y.args
        if shift == x and (inner == SEL and x <= 224): return inner
    if op == BYTE and isinstance(x, int) and y == Expr(CALLDATALOAD, (0,)) and x < 4:
        return simplify(AND, simplify(SHR, 8 * (3 - x), SEL), 255)
    return Expr(op, args)


def dependencies(x):
    """Collect the input and storage-read operations on which a value depends."""
    found, seen, todo = set(), set(), [x]
    while todo:
        value = todo.pop()
        if not isinstance(value, Expr) or id(value) in seen: continue
        seen.add(id(value))
        if value.op in {CALLDATALOAD, SLOAD, MSIZE} or not value.args:
            found.add(value.op)
        else:
            todo.extend(a for a in value.args if isinstance(a, Expr))
    return found


def format_word(x):
    """Render small expressions exactly; abbreviate large diagnostics with ... ."""
    remaining = 32

    def render(value, depth):
        nonlocal remaining
        if remaining == 0: return "..."
        remaining -= 1
        if isinstance(value, int): return hex(value)
        name = "selector" if value.op == SELECTOR else "calldata" if value.op == CALLDATALOAD else OP_NAMES[value.op].lower()
        if not value.args: return name
        if depth == 4: return f"{name}(...)"
        return f"{name}({', '.join(render(a, depth+1) for a in value.args)})"

    # Limit both the expression traversal and the resulting diagnostic text.
    text = render(x, 0)
    return text if len(text) <= 512 else text[:509] + "..."


@dataclass(frozen=True)
class Interval:
    """Inclusive unsigned-word bounds with explicitly excluded values."""
    lo: int = 0
    hi: int = MASK
    excluded: frozenset = frozenset()

    def narrow(self, lo=0, hi=MASK, exclude=None):
        """Intersect bounds and exclusions; return None when no value remains."""
        low, high = max(lo, self.lo), min(hi, self.hi)
        excluded = self.excluded | ({exclude} if exclude is not None else set())
        while low <= high and low in excluded: low += 1
        while low <= high and high in excluded: high -= 1
        if low > high: return None
        return Interval(low, high, frozenset(n for n in excluded if low <= n <= high))


@dataclass
class State:
    """One execution path: stack, byte-addressed memory, constraints and evidence.

    Missing memory bytes are zero; unknown storage slots become SLOAD
    expressions. ranges bound input values, facts assign exact expression
    values, and predicates retain branch conditions for feasibility checks.
    """
    pc: int = 0
    stack: list = field(default_factory=list)
    memory: dict = field(default_factory=dict)
    code_copies: tuple = ()
    storage: dict = field(default_factory=dict)
    msize: int = 0
    msize_unknown: bool = False
    ranges: dict = field(default_factory=lambda: {
        SEL: Interval(0, SELECTOR_MASK), SIZE: Interval(), VALUE: Interval(),
        CODE_SIZE: Interval()})
    facts: dict = field(default_factory=dict)
    predicates: tuple = ()
    category: str = "unmatched"
    selector: int | None = None
    selector_mask: int = 0
    selector_bits: int = 0
    entry: int = 0
    dispatch_entry: int | None = None
    awaiting_entry_jump: bool = False
    dispatch_seen: bool = False
    guards: tuple = ()
    trace: tuple = ()
    jumps: tuple = ()
    steps: int = 0
    remaining_steps: int = INITIAL_PATH_BUDGET
    budgeted_selectors: frozenset = frozenset()

    reads: frozenset = frozenset()
    effects: frozenset = frozenset()
    argument_reads: bool = False
    body_seeded: bool = False
    return_data: dict | None = None

    def fork(self):
        """Copy mutable path containers while sharing immutable expressions and evidence."""
        return replace(self, stack=self.stack.copy(), memory=self.memory.copy(),
                       ranges=self.ranges.copy(), facts=self.facts.copy(),
                       storage=self.storage.copy())


@dataclass(frozen=True)
class OpaqueCodeCopy:
    """A CODECOPY result whose bytes or extent cannot be materialized safely."""
    start: int
    source: int
    size: Word


def evaluate(x, state, *, use_facts=True):
    """Evaluate each shared expression once for this state snapshot."""
    # Cache by expression identity for this evaluation; later calls may use changed facts.
    return _evaluate(x, state, use_facts, {})


def _evaluate(value, state, use_facts, memo):
    if isinstance(value, int): return value
    key = id(value)
    if key in memo: return memo[key]
    if use_facts and value in state.facts:
        result = state.facts[value]
    elif value in state.ranges:
        r = state.ranges[value]
        result = r.lo if r.lo == r.hi else value
    elif value.op == CALLDATALOAD:
        result = 0 if value.args[0] >= state.ranges[SIZE].hi else value
    elif value.op in {SLOAD, MSIZE} or not value.args:
        # SLOAD expressions name the unknown initial value of a concrete slot.
        result = value
    else:
        result = simplify(value.op, *(_evaluate(a, state, use_facts, memo) for a in value.args))
        # Reuse unchanged expressions so repeated evaluations share their child nodes.
        if (isinstance(result, Expr) and result.op == value.op
                and len(result.args) == len(value.args)
                and all(a is b for a, b in zip(result.args, value.args))):
            result = value
    memo[key] = result
    return result


def bounds(x, state):
    """Return conservative inclusive unsigned bounds under the current path constraints."""
    x = evaluate(x, state)
    if isinstance(x, int): return x, x
    if x in state.ranges: return state.ranges[x].lo, state.ranges[x].hi
    if boolean(x): return 0, 1
    if x.op == MOD and isinstance(x.args[1], int): return 0, max(0, x.args[1] - 1)
    if x.op == AND:
        for a in x.args:
            if isinstance(a, int): return 0, a
    if x.op == BYTE: return 0, 255
    if x.op == SHR and isinstance(x.args[0], int):
        lo, hi = bounds(x.args[1], state)
        return lo >> x.args[0], hi >> x.args[0]
    if x.op in (ADD,MUL):
        al, ah = bounds(x.args[0], state)
        bl, bh = bounds(x.args[1], state)
        lo, hi = (al + bl, ah + bh) if x.op == ADD else (al * bl, ah * bh)
        if hi <= MASK: return lo, hi
    return 0, MASK


def feasible(state):
    """Check stored values and branch conditions for contradictions.

    False identifies a contradiction. True means the path remains a candidate
    under the supported expression and interval checks.
    """
    # Check stored facts using input ranges, then use those facts to check branches.
    # Separate caches keep these two evaluation contexts distinct.
    without_facts, with_facts = {}, {}
    for expr, value in state.facts.items():
        actual = _evaluate(expr, state, False, without_facts)
        if isinstance(actual, int) and actual != value: return False
    for expr, truth in state.predicates:
        actual = _evaluate(expr, state, True, with_facts)
        if isinstance(actual, int) and bool(actual) != truth: return False
    return True


def restrict(state, var, lo=0, hi=MASK, exclude=None):
    """Narrow a tracked input in place; return False on an empty or conflicting range."""
    r = state.ranges[var].narrow(lo, hi, exclude)
    if r is None: return False
    if var == SEL and r.lo == r.hi:
        if (r.lo ^ state.selector_bits) & state.selector_mask: return False
    state.ranges[var] = r
    return True


def selector_projection(expr):
    """Return (output mask, right shift) for masked/shifted selector bits."""
    if expr == SEL: return SELECTOR_MASK, 0
    if not isinstance(expr, Expr): return None
    if expr.op == AND:
        x, mask = expr.args
        if isinstance(x, int): x, mask = mask, x
        projection = selector_projection(x)
        if projection is not None and isinstance(mask, int):
            return projection[0] & mask, projection[1]
    if expr.op in (SHR, SHL):
        shift, x = expr.args
        if isinstance(shift, int):
            projection = selector_projection(x)
            if projection is not None:
                mask, previous = projection
                if shift >= 256: return 0, 0
                if expr.op == SHR: return mask >> shift, previous + shift
                return (mask << shift) & MASK, previous - shift
    return None


def constrain_selector_bits(state, projection, value):
    """Apply a projected selector equality in place; return False on contradiction."""
    mask, shift = projection
    if value & ~mask: return False
    if shift >= 0:
        mask, value = mask << shift, value << shift
    else:
        mask, value = mask >> -shift, value >> -shift
    mask &= SELECTOR_MASK
    value &= mask
    if (state.selector_bits ^ value) & state.selector_mask & mask: return False
    state.selector_bits |= value
    state.selector_mask |= mask
    return restrict(state, SEL, state.selector_bits,
                    state.selector_bits | (SELECTOR_MASK ^ state.selector_mask))


def assume(state, expr, truth):
    """Add a branch condition to the state, narrow input ranges and check for contradictions."""
    original = expr
    expr = evaluate(expr, state)
    if isinstance(expr, int): return bool(expr) == truth and feasible(state)
    duplicate = False
    for previous, previous_truth in state.predicates:
        if previous == original:
            if previous_truth != truth: return False
            duplicate = True
    if not duplicate:
        state.predicates += ((original, truth),)
    # Repeat refinement even for an existing predicate: ranges/facts may have
    # changed since it was first assumed. Only its diagnostic copy is omitted.
    if expr in state.ranges:
        ok = restrict(state, expr, lo=1) if truth else restrict(state, expr, hi=0)
        return ok and feasible(state)
    if not truth:
        projection = selector_projection(expr)
        if projection is not None:
            return constrain_selector_bits(state, projection, 0) and feasible(state)
    op, a = expr.op, expr.args
    if op == ISZERO: return assume(state, a[0], not truth)
    if op in {SUB, XOR}:
        return assume(state, simplify(EQ, *a), not truth)
    if op in {EQ, LT, GT}:
        x, y = a
        if isinstance(x, int):
            x, y = y, x
            op = {EQ: EQ, LT: GT, GT: LT}[op]
        if op == EQ and truth and isinstance(y, int):
            projection = selector_projection(x)
            if projection is not None and not constrain_selector_bits(state, projection, y):
                return False
        if x in state.ranges and isinstance(y, int):
            if op == EQ: ok = restrict(state, x, y, y) if truth else restrict(state, x, exclude=y)
            elif op == LT: ok = restrict(state, x, hi=y-1) if truth else restrict(state, x, lo=y)
            else: ok = restrict(state, x, lo=y+1) if truth else restrict(state, x, hi=y)
            return ok and feasible(state)
        if op == EQ and isinstance(y, int):
            if truth:
                if x in state.facts and state.facts[x] != y: return False
                state.facts[x] = y
    if op == OR and not truth:
        return assume(state, a[0], False) and assume(state, a[1], False)
    if op == AND and truth and all(boolean(v) for v in a):
        return assume(state, a[0], True) and assume(state, a[1], True)
    lo, hi = bounds(expr, state)
    if (truth and hi == 0) or (not truth and lo > 0): return False
    return feasible(state)


class Halt(Exception):
    """End or reschedule a path with an outcome kind and diagnostic reason."""
    def __init__(self, reason, kind="incomplete"):
        self.reason, self.kind = reason, kind


@dataclass
class Limits:
    """Dispatcher exploration budgets and diagnostic trace length.

    max_steps caps total instructions (None leaves that total uncapped);
    max_states caps admitted states. Each path starts with initial_path_budget
    and may receive selector_budget_bonus, capped at max_path_budget.
    max_table_values bounds address enumeration; max_memory is in bytes;
    max_expression_nodes bounds stack expressions. trace_length=0 disables traces.
    """
    max_steps: int | None = None
    max_states: int = 4096
    initial_path_budget: int = INITIAL_PATH_BUDGET
    selector_budget_bonus: int = SELECTOR_BUDGET_BONUS
    max_path_budget: int = MAX_PATH_BUDGET
    max_table_values: int = 256
    max_memory: int = 65_536
    max_expression_nodes: int = 256
    trace_length: int = 24


@dataclass
class Analysis:
    """Discovered function entries, call routes, value checks and search diagnostics."""
    functions: list
    routes: list
    value_guards: list
    complete: bool
    issues: list
    statistics: dict

    def to_dict(self): return asdict(self)


@dataclass(frozen=True)
class Operation:
    """An opcode's execution handler, optional arithmetic evaluator and stack requirements."""
    opcode: bytes
    execute: Callable
    evaluate: Callable | None = None
    check_expressions: bool = False

    @property
    def pops(self): return INFO[self.opcode].pops

    @property
    def pushes(self): return INFO[self.opcode].pushes

    @property
    def required(self): return INFO[self.opcode].required


@dataclass(slots=True)
class Execution:
    """The instruction, state and interpreter passed to an execution handler.

    next_pc determines where execution resumes. Addresses are resolved before
    stack values are removed so the instruction can restart for each candidate
    address when a symbolic value has several possibilities.
    """
    interpreter: "Interpreter"
    state: State
    operation: Operation
    pc: int
    next_pc: int

    @property
    def opcode(self): return self.operation.opcode

    @property
    def code(self): return self.interpreter.code

    def pop(self, count=1): return self.interpreter.pop(self.state, count)

    def push(self, *values): self.state.stack.extend(values)

    def address(self, depth, purpose):
        return self.interpreter.address(self.state, self.state.stack[-depth], purpose)

    def jump(self, target):
        if target not in self.interpreter.jumpdests:
            raise Halt("invalid_jump", "exception")
        self.next_pc = target
        self.interpreter.on_jump(self.state, self.pc, target, self.opcode == JUMP)


def execute_arithmetic(ctx):
    result = simplify(ctx.opcode, *ctx.pop(ctx.operation.pops))
    ctx.interpreter.check_calldata_use(result)
    ctx.interpreter.check_storage_use(result)
    ctx.interpreter.check_calldata_size_use(ctx.state, result)
    ctx.push(result)


def execute_push(ctx):
    size = INFO[ctx.opcode].immediate
    data = ctx.code[ctx.pc+1:ctx.pc+1+size]
    ctx.push(int.from_bytes(data.ljust(size, b"\0"), "big"))
    ctx.next_pc += size


def execute_dup(ctx):
    ctx.push(ctx.state.stack[-(INFO[ctx.opcode].required)])


def execute_swap(ctx):
    stack, depth = ctx.state.stack, INFO[ctx.opcode].required
    stack[-1], stack[-depth] = stack[-depth], stack[-1]


def execute_environment(ctx):
    ctx.push(Expr(ctx.opcode))


def execute_calldataload(ctx):
    offset = ctx.address(1, "calldata_offset")
    ctx.pop()
    ctx.push(0 if offset >= ctx.state.ranges[SIZE].hi else Expr(CALLDATALOAD, (offset,)))


def execute_sload(ctx):
    slot = ctx.address(1, "storage_slot")
    ctx.pop()
    ctx.push(ctx.state.storage.get(slot, Expr(SLOAD, (slot,))))


def execute_sstore(ctx):
    # Resolve before popping so bounded address enumeration can retry safely.
    slot = ctx.address(1, "storage_slot")
    _, value = ctx.pop(2)
    ctx.state.storage[slot] = value


def execute_mload(ctx):
    offset = ctx.address(1, "memory_offset")
    ctx.pop()
    ctx.push(ctx.interpreter.load_memory(ctx.state, offset))


def _opaque_overlap(state, start, size):
    """Return whether a concrete memory range may overlap an opaque code copy."""
    end = start + size
    for copied in state.code_copies:
        copied_end = copied.start + copied.size if isinstance(copied.size, int) else None
        if end > copied.start and (copied_end is None or start < copied_end):
            return True
    return False


def _invalidate_code_copies(state, start, size):
    """Trim concrete lazy copies after writes; retain symbolic copies conservatively."""
    end = start + size if isinstance(size, int) else None
    kept = []
    for copied in state.code_copies:
        copied_end = copied.start + copied.size if isinstance(copied.size, int) else None
        disjoint = ((end is not None and end <= copied.start) or
                    (copied_end is not None and copied_end <= start))
        if disjoint:
            kept.append(copied)
        elif copied_end is None or end is None:
            # Splitting a symbolic extent would require subtracting possibly
            # larger words. Keeping it opaque loses precision without inventing
            # readable bytes after a partial overwrite.
            kept.append(copied)
        else:
            if copied.start < start:
                kept.append(OpaqueCodeCopy(copied.start, copied.source,
                                           start - copied.start))
            if end < copied_end:
                kept.append(OpaqueCodeCopy(end, copied.source + end - copied.start,
                                           copied_end - end))
    state.code_copies = tuple(kept)


def store_memory(ctx, count):
    offset = ctx.address(1, "memory_offset")
    ctx.pop()
    value = ctx.pop()[0]
    _invalidate_code_copies(ctx.state, offset, count)
    ctx.interpreter.touch(ctx.state, offset, count)
    for i in range(count):
        ctx.state.memory[offset+i] = simplify(BYTE, 31 if count == 1 else i, value)


def copy_region(ctx):
    offset = ctx.address(1, "copy_destination")
    source = ctx.address(2, "copy_source")
    size = ctx.address(3, "copy_size")
    ctx.pop(3)
    _invalidate_code_copies(ctx.state, offset, size)
    ctx.interpreter.touch(ctx.state, offset, size)
    return offset, source, size


def execute_codecopy(ctx):
    offset = ctx.address(1, "copy_destination")
    source = ctx.address(2, "copy_source")
    size = evaluate(ctx.state.stack[-3], ctx.state)
    ctx.pop(3)
    _invalidate_code_copies(ctx.state, offset, size)
    if isinstance(size, int) and source + size <= len(ctx.code):
        ctx.interpreter.touch(ctx.state, offset, size)
        ctx.state.memory.update((offset+i, v)
                                for i, v in enumerate(ctx.code[source:source+size]))
        return
    # The copy may include bytes in an optional suffix. Keep its provenance and
    # extent without inventing byte values or allocating a symbolic-size buffer.
    if isinstance(size, int):
        ctx.interpreter.touch(ctx.state, offset, size)
        for address in range(offset, offset + size):
            ctx.state.memory.pop(address, None)
    else:
        ctx.interpreter.region(offset, 0)
        for address in tuple(ctx.state.memory):
            if address >= offset:
                ctx.state.memory.pop(address)
        ctx.state.msize_unknown = True
    ctx.state.code_copies += (OpaqueCodeCopy(offset, source, size),)


def execute_calldatacopy(ctx):
    offset, source, size = copy_region(ctx)
    ctx.state.memory.update((offset+i, ctx.interpreter.calldata_byte(ctx.state, source+i))
                            for i in range(size))


def execute_mcopy(ctx):
    offset, source, size = copy_region(ctx)
    if _opaque_overlap(ctx.state, source, size):
        raise Halt("codecopied_data_access")
    ctx.interpreter.touch(ctx.state, source, size)
    data = [ctx.state.memory.get(source+i, 0) for i in range(size)]
    ctx.state.memory.update((offset+i, v) for i, v in enumerate(data))


def execute_returndatacopy(ctx):
    _, source, size = copy_region(ctx)
    # External calls are stopping boundaries, so the return-data buffer is empty.
    if size or source: raise Halt("returndata_out_of_bounds", "exception")


def execute_jump(ctx):
    target = ctx.address(1, "jump_target")
    ctx.pop()
    ctx.jump(target)


def execute_jumpi(ctx):
    condition = evaluate(ctx.state.stack[-2], ctx.state)
    if isinstance(condition, int) and condition == 0:
        # A false condition continues directly to the instruction after JUMPI.
        ctx.pop(2)
        if ctx.state.selector is None: ctx.state.entry = ctx.next_pc
        return
    target = ctx.address(1, "jump_target")
    ctx.pop(2)
    if isinstance(condition, int):
        ctx.jump(target)
    else:
        ctx.interpreter.branch(ctx.state, ctx.pc, condition, target)
        raise Halt("rescheduled", "internal")


def execute_jumpdest(ctx):
    ctx.state.awaiting_entry_jump = False


def execute_stop(ctx):
    raise Halt("STOP", "stop")


def execute_msize(ctx):
    if ctx.state.msize_unknown:
        ctx.push(ctx.interpreter.fresh_msize())
    else:
        ctx.push(ctx.state.msize)


def execute_return(ctx):
    ctx.pop(2)
    raise Halt(OP_NAMES[ctx.opcode], "revert" if ctx.opcode == REVERT else "return")


def execute_invalid(ctx):
    raise Halt("INVALID", "exception")


def execute_body_boundary(ctx):
    raise Halt(OP_NAMES[ctx.opcode], "body")


def arithmetic(opcode, function):
    """Create an instruction handler that evaluates concrete operands or builds a symbolic expression."""
    return Operation(opcode, execute_arithmetic,
                     evaluate=function, check_expressions=True)


# Register each arithmetic evaluator with its symbolic instruction handler.
ARITHMETIC = tuple(arithmetic(opcode, function) for opcode, function in EVALUATORS.items())

STATE_OPERATIONS = (
    Operation(STOP, execute_stop),
    Operation(POP, lambda c: c.pop()),
    Operation(PC, lambda c: c.push(c.pc)),
    Operation(MSIZE, execute_msize),
    Operation(CODESIZE, lambda c: c.push(CODE_SIZE)),
    Operation(RETURNDATASIZE, lambda c: c.push(0)),
    Operation(CALLVALUE, lambda c: c.push(VALUE)),
    Operation(CALLDATASIZE, lambda c: c.push(SIZE)),
    Operation(CALLDATALOAD, execute_calldataload),
    Operation(SLOAD, execute_sload, check_expressions=True),
    Operation(SSTORE, execute_sstore),
    Operation(MLOAD, execute_mload, check_expressions=True),
    Operation(MSTORE, lambda c: store_memory(c, 32)),
    Operation(MSTORE8, lambda c: store_memory(c, 1)),
    Operation(CODECOPY, execute_codecopy),
    Operation(CALLDATACOPY, execute_calldatacopy),
    Operation(MCOPY, execute_mcopy),
    Operation(RETURNDATACOPY, execute_returndatacopy),
    Operation(JUMP, execute_jump),
    Operation(JUMPI, execute_jumpi),
    Operation(JUMPDEST, execute_jumpdest),
    Operation(RETURN, execute_return),
    Operation(REVERT, execute_return),
    Operation(INVALID, execute_invalid),
)

ENVIRONMENT_OPS = frozenset({ADDRESS, ORIGIN, CALLER, GASPRICE, COINBASE, TIMESTAMP, NUMBER, PREVRANDAO,
                   GASLIMIT, CHAINID, SELFBALANCE, BASEFEE, BLOBBASEFEE, GAS})

# Instructions that end dispatcher exploration before execution. Body analysis
# records their reads/effects, then stops because their semantics are unsupported.
BODY_OPS = frozenset({KECCAK256, TLOAD, TSTORE, BALANCE, EXTCODESIZE,
    EXTCODECOPY, EXTCODEHASH, BLOCKHASH, BLOBHASH, CREATE, CREATE2, CALL,
    CALLCODE, DELEGATECALL, STATICCALL, SELFDESTRUCT, LOG0, LOG1, LOG2, LOG3, LOG4})

OPERATIONS = {definition.opcode: definition for definition in (
    *ARITHMETIC, *STATE_OPERATIONS,
    *(Operation(op, execute_environment) for op in ENVIRONMENT_OPS),
    *(Operation(op, execute_body_boundary) for op in BODY_OPS),
    *(Operation(op, execute_push) for op, info in INFO.items() if info.family == "push"),
    *(Operation(op, execute_dup) for op, info in INFO.items() if info.family == "dup"),
    *(Operation(op, execute_swap) for op, info in INFO.items() if info.family == "swap"),
)}




def jump_destinations(code):
    """Find JUMPDEST instruction offsets, excluding bytes inside PUSH operands."""
    return {pc for pc in instruction_boundaries(code) if code[pc:pc+1] == JUMPDEST}


class Interpreter:
    """Follow function-selection code and record selectors, entry offsets and path outcomes.

    Paths still searching for a selector receive priority over selected functions
    and short-calldata routes. Each path stops at a configured function boundary,
    an unresolved instruction, a completed execution or an exhausted limit.
    """
    def __init__(self, code, limits, *, stop_at_selected_entry=False,
                 include_short_calldata_routes=True):
        self.code, self.limits = code, limits
        self.stop_at_selected_entry = stop_at_selected_entry
        self.include_short_calldata_routes = include_short_calldata_routes
        self.jumpdests = jump_destinations(code)
        self.dispatch_queue = deque()
        self.queue = deque()
        self.outcomes, self.entries, self.guards, self.issues = [], {}, {}, []
        self.steps, self.states, self.pruned = 0, 0, 0
        self.msize_reads = 0
        self.state_budget_outcomes = {}
        self.calldata_provenance = {}
        self.storage_shapes = {}
        self.calldata_size_shapes = {}

    def fresh_msize(self):
        """Return a distinct unknown word for one MSIZE read after symbolic expansion."""
        result = Expr(MSIZE, (self.msize_reads,))
        self.msize_reads += 1
        return result

    def check_calldata_use(self, value):
        """Stop function discovery when a computed value depends on argument bytes."""
        if uses_arguments(value, memo=self.calldata_provenance):
            raise Halt("argument_calldata", "body")

    def check_calldata_size_use(self, state, value):
        """Stop discovery at length arithmetic after a branch that depends on the function selector."""
        if state.dispatch_seen and uses_size_arithmetic(value, self.calldata_size_shapes):
            raise Halt("calldata_size_computation", "body")

    def check_storage_use(self, value):
        """Stop discovery when an expression calculates with storage beyond field extraction or checks."""
        kind, storage = storage_shape(value, self.storage_shapes)
        if storage and kind == "calculation":
            raise Halt("storage_calculation", "body")

    def check_storage_address(self, value):
        """Stop discovery when a memory, jump or other address depends on storage."""
        if storage_shape(value, self.storage_shapes)[1]:
            raise Halt("storage_derived_address", "body")

    def record_state_budget(self, state):
        # Combine exhausted-state reports by route and function entry, counting each event.
        key = (state.category, state.selector, state.dispatch_entry)
        if key not in self.state_budget_outcomes:
            self.finish(state, "state_budget", "incomplete")
            self.state_budget_outcomes[key] = self.outcomes[-1]
            self.outcomes[-1]["budget_events"] = 0
        self.state_budget_outcomes[key]["budget_events"] += 1

    def enqueue(self, state):
        if self.stop_at_selected_entry and state.selector is not None:
            # Selecting an entry completes this path's requested search.
            self.finish(state, "selected_entry", "selected_entry")
            return
        if self.states >= self.limits.max_states:
            self.record_state_budget(state)
            return
        self.states += 1
        # Prioritize paths still choosing a function; process each queue in arrival order.
        if state.category == "unmatched" and state.selector is None:
            self.dispatch_queue.append(state)
        else:
            self.queue.append(state)

    def finish(self, s, reason, kind, pc=None):
        at = s.pc if pc is None else pc
        outcome = {
            "category": s.category, 'selector': f"{s.selector:08x}" if s.selector is not None else None,
            "entry_pc": s.dispatch_entry if s.selector is not None else s.entry,
            "post_guard_entry_pc": s.entry if s.dispatch_entry is not None and s.entry != s.dispatch_entry else None,
            "dispatch_entry_pc": s.dispatch_entry,
            "stop_pc": at, "kind": kind, "reason": reason,
            'callvalue': self.range_json(s.ranges[VALUE]),
            'calldatasize': self.range_json(s.ranges[SIZE]),
            "conditions": [f"{format_word(e)} {'!= 0' if t else '== 0'}" for e, t in s.predicates],
            "guard_pcs": list(s.guards), "trace": list(s.trace),
            "jumps": [{"pc": pc, "target_pc": target} for pc, target in s.jumps],
        }
        self.outcomes.append(outcome)
        if kind == "incomplete":
            self.issues.append({"pc": at, "reason": reason, 'selector': outcome['selector'],
                                "category": s.category})

    @staticmethod
    def range_json(r):
        return {"min": r.lo, "max": r.hi, "excluded": sorted(r.excluded)}

    def pop(self, s, count=1):
        if len(s.stack) < count: raise Halt("stack_underflow")
        return [evaluate(s.stack.pop(), s) for _ in range(count)]

    def address(self, s, x, purpose):
        """Resolve an address to an integer under the current path conditions.

        For a small range of possible values, queue one state per candidate and
        restart the instruction in each state.
        """
        value = evaluate(x, s)
        self.check_storage_address(value)
        self.check_calldata_use(value)
        self.check_storage_use(value)
        self.check_calldata_size_use(s, value)
        if isinstance(value, int): return value
        # Prefer finite leaf computations (e.g. selector % N) over enumerating
        # the entire address range. Preserve the equality as a path constraint.
        found = self.address_candidate(value, s)
        if found is None: raise Halt(f"unresolved_{purpose}: {format_word(value)}")
        expr, low, high = found
        for n in range(low, high+1):
            if self.states >= self.limits.max_states:
                # Record the exhausted state limit and stop enumerating addresses.
                self.record_state_budget(s)
                break
            child = s.fork()
            child.facts[expr] = n
            if feasible(child): self.enqueue(child)
        raise Halt("rescheduled", "internal")

    def address_candidate(self, value, state):
        """Find an expression whose possible values fit the address-enumeration limit.

        Return (expression, low, high), preferring operands over their enclosing
        operations. Return None when every candidate range exceeds max_table_values.
        """
        if isinstance(value, int) or value in state.facts: return None
        for arg in value.args:
            if isinstance(arg, Expr):
                found = self.address_candidate(arg, state)
                if found is not None: return found
        lo, hi = bounds(value, state)
        if hi - lo + 1 <= self.limits.max_table_values: return value, lo, hi
        return None

    def region(self, offset, size):
        """Reject a memory range extending beyond the configured byte budget."""
        if offset > self.limits.max_memory or size > self.limits.max_memory - offset:
            raise Halt("memory_budget")

    def touch(self, s, offset, size):
        """Check the memory budget and update MSIZE in 32-byte allocation units."""
        self.region(offset, size)
        if size: s.msize = max(s.msize, ((offset + size + 31)//32)*32)

    def calldata_byte(self, s, index):
        if index >= s.ranges[SIZE].hi: return 0
        # Represent each memory byte by its position in the source calldata word.
        base = (index // 32)*32
        return simplify(BYTE, index-base, Expr(CALLDATALOAD, (base,)))

    def load_memory(self, s, offset):
        """Read a 32-byte word, preserving symbolic source words where reconstructible."""
        if _opaque_overlap(s, offset, 32):
            raise Halt("codecopied_data_access")
        self.touch(s, offset, 32)
        values = [s.memory.get(offset+i, 0) for i in range(32)]
        if all(isinstance(v, int) for v in values): return int.from_bytes(values, "big")
        origins = {v.args[1] for v in values if isinstance(v, Expr) and v.op == BYTE}
        for word in origins:
            if values == [simplify(BYTE, i, word) for i in range(32)]: return word
        # Common case: exact MSTORE/MLOAD round trip, including unknown words.
        if all(isinstance(v, Expr) and v.op == BYTE and v.args[0] == i
               for i, v in enumerate(values)):
            words = [v.args[1] for v in values]
            if all(w == words[0] for w in words): return words[0]
        # Reassemble exact byte arithmetic; the selector right-alignment case
        # is recognized separately to avoid a large expression.
        selector_bytes = [simplify(AND, simplify(SHR, 8*(3-i), SEL), 255) for i in range(4)]
        if values[:28] == [0]*28 and values[28:] == selector_bytes: return SEL
        if values[:4] == selector_bytes and values[4:] == [0]*28: return simplify(SHL, 224, SEL)
        result = 0
        for i, v in enumerate(values): result = simplify(OR, result, simplify(SHL, 8*(31-i), v))
        return result

    def check_expressions(self, s):
        # Visit each distinct expression once and stop when the node limit is exceeded.
        seen, todo = set(), list(s.stack)
        while todo:
            x = todo.pop()
            if isinstance(x, int) or x in seen: continue
            seen.add(x)
            if len(seen) > self.limits.max_expression_nodes: raise Halt("expression_budget")
            todo.extend(a for a in x.args if isinstance(a, Expr))

    def branch(self, s, pc, condition, target):
        self.check_calldata_use(condition)
        self.check_storage_use(condition)
        self.check_calldata_size_use(s, condition)
        deps = dependencies(condition)
        permitted = {SELECTOR, CALLDATASIZE, CALLVALUE, CODESIZE, MSIZE}
        if s.selector is None:
            # Access checks can precede function selection. Keep their storage,
            # caller and execution-address values symbolic while exploring branches.
            permitted |= {SLOAD, CALLER, ORIGIN, ADDRESS}
        if not deps <= permitted:
            if s.selector is None and not s.dispatch_seen:
                raise Halt("contract_specific_condition_before_dispatch")
            raise Halt("contract_specific_condition", "body")
        if s.selector is not None and SELECTOR in deps:
            # Further selector-dependent decisions belong to function-body
            # analysis once an entry has been selected.
            raise Halt("selector_condition_after_entry", "body")
        guard_id = None
        if SELECTOR in deps: s.dispatch_seen = True
        if CALLVALUE in deps:
            guard_id = pc
            record = self.guards.setdefault(pc, {"pc": pc, "variants": []})
            variant = {"condition": format_word(condition), "taken_pc": target,
                       "fallthrough_pc": pc+1, 'selector': f"{s.selector:08x}" if s.selector is not None else None,
                       "category": s.category}
            if variant not in record["variants"]: record["variants"].append(variant)
        children, discovered = [], set()
        for truth in (False, True):
            child = s.fork()
            if not assume(child, condition, truth):
                self.pruned += 1
                continue
            dest = target if truth else pc+1
            if guard_id is not None: child.guards += (guard_id,)
            child.pc = dest
            # A uniquely selected branch counts even when its target is invalid.
            # Record it before validating the jump, retaining the exception outcome.
            if child.selector is None:
                child.entry = dest
                r = child.ranges[SEL]
                if child.category == "unmatched" and SELECTOR in deps and r.lo == r.hi:
                    child.selector, child.entry = r.lo, dest
                    child.dispatch_entry = dest
                    child.awaiting_entry_jump = dest not in self.jumpdests
                    discovered.add(r.lo)
                    self.entries.setdefault((r.lo, dest), {'selector': f"{r.lo:08x}",
                        "entry_pc": dest, "dispatch_entry_pc": dest,
                        "entry_basis": "selector_branch", "comparison_pc": pc})
            children.append((child, truth, dest))
        newly_discovered = discovered - s.budgeted_selectors
        for child, truth, dest in children:
            if newly_discovered:
                child.remaining_steps = min(child.remaining_steps + self.limits.selector_budget_bonus,
                                            self.limits.max_path_budget)
                child.budgeted_selectors |= newly_discovered
            if truth and dest not in self.jumpdests:
                self.finish(child, "invalid_jump", "exception", pc)
                continue
            if truth: child.jumps += ((pc, dest),)
            self.enqueue(child)

    def before_instruction(self, state, opcode):
        """Check for the end of function-selection code and record the current instruction offset."""
        # Storage writes begin function or fallback work. Storage reads can
        # participate in access checks before a function is selected.
        if opcode in BODY_OPS or opcode == SSTORE or (opcode == SLOAD and state.selector is not None):
            raise Halt(OP_NAMES[opcode], "body")
        if self.limits.trace_length:
            state.trace = (state.trace + (state.pc,))[-self.limits.trace_length:]

    def on_jump(self, state, pc, target, unconditional):
        """Record an executed jump and update the selected function entry when appropriate."""
        if unconditional and state.selector is not None and state.awaiting_entry_jump:
            # Table dispatch validates a selector in shared straight-line code,
            # checks entry conditions, then jumps to the function-specific entry.
            found = self.entries[(state.selector, state.dispatch_entry)]
            previous = found.get("post_guard_target_pcs", [])
            found["post_guard_target_pcs"] = sorted(set(previous) | {target})
            found["post_guard_target_basis"] = "first_jump_before_next_jumpdest"
            state.entry, state.awaiting_entry_jump = target, False
        state.jumps += ((pc, target),)
        if state.selector is None:
            state.entry = target

    def step(self, state):
        pc = state.pc
        if pc >= len(self.code):
            raise Halt("end_of_code", "stop")
        opcode = self.code[pc:pc+1]
        self.before_instruction(state, opcode)
        operation = OPERATIONS.get(opcode)
        if operation is None:
            raise Halt(f"unsupported_opcode_0x{opcode.hex()}")
        if len(state.stack) < operation.required:
            raise Halt("stack_underflow")
        if len(state.stack)-operation.pops+operation.pushes > 1024:
            raise Halt("stack_overflow", "exception")
        context = Execution(self, state, operation, pc, pc+1)
        # Charge before execution so branch children inherit the JUMPI cost.
        state.steps += 1
        state.remaining_steps -= 1
        operation.execute(context)
        state.pc = context.next_pc
        if operation.check_expressions:
            self.check_expressions(state)

    def run(self):
        # Separate short lengths preserve zero-padding constraints on selectors.
        lengths = (0, 1, 2, 3, None) if self.include_short_calldata_routes else (None,)
        for length in lengths:
            s = State(category="unmatched" if length is None else "empty" if length == 0 else f"short_{length}")
            s.remaining_steps = self.limits.initial_path_budget
            s.ranges[SIZE] = Interval(4, MASK) if length is None else Interval(length, length)
            if length == 0: s.ranges[SEL] = Interval(0, 0)
            elif length is not None:
                s.predicates = ((simplify(AND, SEL, (1 << (8*(4-length)))-1), False),)
            self.enqueue(s)
        return self.drain()

    def drain(self):
        """Run queued paths to termination or a scope/budget boundary and summarize them."""
        while self.dispatch_queue or self.queue:
            s = (self.dispatch_queue or self.queue).popleft()
            while True:
                if self.limits.max_steps is not None and self.steps >= self.limits.max_steps:
                    self.finish(s, "instruction_budget", "incomplete")
                    for remaining in self.dispatch_queue: self.finish(remaining, "instruction_budget", "incomplete")
                    self.dispatch_queue.clear()
                    for remaining in self.queue: self.finish(remaining, "instruction_budget", "incomplete")
                    self.queue.clear()
                    break
                if s.remaining_steps <= 0:
                    self.finish(s, "path_budget", "incomplete")
                    break
                self.steps += 1
                try: self.step(s)
                except Halt as halt:
                    if halt.kind != "internal": self.finish(s, halt.reason, halt.kind)
                    break
        return self.result()

    @staticmethod
    def value_policy(outcomes):
        """Classify value rejection from path endings, call-value ranges and recorded value checks."""
        if not outcomes: return "unknown"
        continuations = [o for o in outcomes if o["kind"] not in {"revert", "exception"}]
        if not continuations: return "always_rejects"
        if all(o['callvalue']["max"] == 0 for o in continuations): return "nonzero_rejected"
        if any(o["kind"] in {"incomplete", "selected_entry"} for o in continuations): return "unknown"
        if any(o["guard_pcs"] for o in outcomes): return "conditional"
        return "no_value_guard_observed"

    def result(self):
        """Group outcomes by selector entry and fallback route, preserving partial results."""
        functions = []
        for (selector, entry), found in sorted(self.entries.items()):
            outcomes = [o for o in self.outcomes if o['selector'] == f"{selector:08x}" and o["dispatch_entry_pc"] == entry]
            functions.append({**found, "value_policy": self.value_policy(outcomes),
                              "guard_pcs": sorted({pc for o in outcomes for pc in o["guard_pcs"]}),
                              "outcomes": outcomes})
        routes = []
        for category in ("empty", "short_1", "short_2", "short_3", "unmatched"):
            outcomes = [o for o in self.outcomes if o['selector'] is None and o["category"] == category]
            behavior = "unknown" if not outcomes or any(o["kind"] == "incomplete" for o in outcomes) else (
                "rejects" if all(o["kind"] in {"revert", "exception"} for o in outcomes) else "reaches_code")
            routes.append({"category": category, "behavior": behavior,
                           "value_policy": self.value_policy(outcomes),
                           "entry_pcs": sorted({o["entry_pc"] for o in outcomes}),
                           "outcomes": outcomes})
        return Analysis(functions, routes, [self.guards[k] for k in sorted(self.guards)],
                        not self.issues, self.issues,
                        {"instructions_executed": self.steps, "states_enqueued": self.states,
                         "branches_pruned": self.pruned, "bytecode_bytes": len(self.code)})


@dataclass
class BodyLimits:
    """Instruction, state, memory and expression limits for exploring one function entry."""
    max_steps: int = 4096
    max_states: int = 128
    max_path_steps: int = 1024
    max_memory: int = 4096
    max_expression_nodes: int = 256


READ_OPS = ENVIRONMENT_OPS | {SLOAD, TLOAD, BALANCE, EXTCODESIZE,
    EXTCODECOPY, EXTCODEHASH, BLOCKHASH, BLOBHASH}
EFFECT_OPS = frozenset({SSTORE, TSTORE, CREATE, CREATE2, SELFDESTRUCT,
    CALL, CALLCODE, DELEGATECALL, LOG0, LOG1, LOG2, LOG3, LOG4})


def observe_body_instruction(state, opcode):
    # Record every encountered read and effect, including discarded reads,
    # rejecting paths and instructions before function selection.
    if opcode in READ_OPS: state.reads |= {opcode}
    if opcode in EFFECT_OPS: state.effects |= {opcode}
    if opcode == CALLDATACOPY:
        state.argument_reads = True  # deliberately conservative
    if opcode == CALLDATALOAD and state.stack:
        if evaluate(state.stack[-1], state) != 0: state.argument_reads = True


class BodySeedDispatcher(Interpreter):
    """Save execution states at function entries and collect reads and effects observed before entry."""
    def __init__(self, code, limits, *, stop_at_selected_entry=False,
                 include_short_calldata_routes=True):
        super().__init__(code, limits, stop_at_selected_entry=stop_at_selected_entry,
                         include_short_calldata_routes=include_short_calldata_routes)
        self.body_seeds = {}

    def before_instruction(self, state, opcode):
        super().before_instruction(state, opcode)
        observe_body_instruction(state, opcode)

    def enqueue(self, state):
        if state.selector is not None and not state.body_seeded:
            state.body_seeded = True
            key = (state.selector, state.dispatch_entry)
            self.body_seeds.setdefault(key, []).append(state.fork())
        super().enqueue(state)


def scalar_storage_expression(word):
    """Recognize a storage-slot value with optional masking, shifting or sign extension."""
    if not isinstance(word, Expr): return False
    if word.op == SLOAD: return isinstance(word.args[0], int)
    if word.op == AND:
        a, b = word.args
        return ((isinstance(a, int) and scalar_storage_expression(b)) or
                (isinstance(b, int) and scalar_storage_expression(a)))
    if word.op in {SHR, SAR, SIGNEXTEND}:
        return isinstance(word.args[0], int) and scalar_storage_expression(word.args[1])
    return False


def input_witness(state):
    """Try sample selector, calldata-length and call-value combinations against a path's conditions.

    Return True when a combination satisfies every condition and stored fact.
    Return False when the samples fail or conditions depend on other inputs.
    """
    if any(not dependencies(expr) <= {SELECTOR, CALLDATASIZE, CALLVALUE}
           for expr, _ in state.predicates): return False
    candidates = []
    for var in (SEL, SIZE, VALUE):
        r = state.ranges[var]
        candidates.append([v for v in sorted({r.lo, r.hi, 0, 1, 4, 36})
                           if r.lo <= v <= r.hi and v not in r.excluded])
    for values in product(*candidates):
        trial = State()
        trial.ranges = {v: Interval(n, n) for v, n in zip((SEL, SIZE, VALUE), values)}
        if all(isinstance(actual := evaluate(expr, trial), int) and bool(actual) == truth
               for expr, truth in state.predicates):
            if all(evaluate(expr, trial) == value for expr, value in state.facts.items()):
                return True
    return False


def nonzero_witness(state):
    """Check for a sampled input satisfying the path conditions with a positive call value."""
    trial = state.fork()
    return restrict(trial, VALUE, lo=1) and input_witness(trial)


class BodyInterpreter(Interpreter):
    """Explore a function from its entry and collect returns, reads and potential effects.

    Execution supports argument, length and storage calculations. An effectful
    or unsupported instruction ends a path after its observations are recorded.
    Sampled inputs identify paths that can supply counterexamples to properties.
    """
    def check_calldata_size_use(self, state, value):
        """Allow calldata-length calculations during body exploration."""
        pass

    def check_storage_use(self, value):
        """Allow storage calculations during body exploration."""
        pass

    def check_storage_address(self, value):
        """Allow storage-derived addresses, subject to bounded address resolution."""
        pass

    def check_calldata_use(self, value):
        pass  # Function bodies may consume argument bytes.

    def before_instruction(self, state, opcode):
        operation = OPERATIONS.get(opcode)
        if operation is not None and len(state.stack) < operation.required:
            raise Halt("stack_underflow")
        observe_body_instruction(state, opcode)
        if opcode == CALLDATALOAD:
            state.argument_reads = True  # even offset zero overlaps argument bytes
        if opcode in EFFECT_OPS:
            raise Halt("potential_effect_" + OP_NAMES[opcode])
        if opcode in BODY_OPS:
            raise Halt("unsupported_body_" + OP_NAMES[opcode])
        if opcode == RETURN:
            if len(state.stack) < 2: raise Halt("stack_underflow")
            offset = self.address(state, state.stack[-1], "return_offset")
            size = self.address(state, state.stack[-2], "return_size")
            self.touch(state, offset, size)
            word = (self.load_memory(state, offset)
                    if size == 32 and not _opaque_overlap(state, offset, size) else None)
            state.return_data = {"size": size,
                "word": format_word(word) if word is not None else None,
                "scalar_storage": scalar_storage_expression(word)}

    def branch(self, state, pc, condition, target):
        # Explore each branch consistent with the stored conditions.
        # Input sampling later checks which paths have concrete witnesses.
        for truth in (False, True):
            child = state.fork()
            if not assume(child, condition, truth):
                self.pruned += 1
                continue
            child.pc = target if truth else pc + 1
            if truth and target not in self.jumpdests:
                self.finish(child, "invalid_jump", "exception", pc)
            else:
                self.enqueue(child)

    def on_jump(self, state, pc, target, unconditional):
        pass  # Entry discovery belongs exclusively to the dispatcher.

    def record_state_budget(self, state):
        super().record_state_budget(state)
        outcome = self.state_budget_outcomes[(state.category, state.selector, state.dispatch_entry)]
        outcome["reads"] = sorted(set(outcome["reads"]) | {OP_NAMES[op] for op in state.reads})
        outcome["potential_effects"] = sorted(set(outcome["potential_effects"]) |
                                             {OP_NAMES[op] for op in state.effects})
        outcome["argument_reads"] |= state.argument_reads
        # The combined observations represent several states, so clear the
        # flags that certified a concrete input for the original single state.
        outcome["witnessed"] = False
        outcome["witnessed_nonzero"] = False

    def finish(self, state, reason, kind, pc=None):
        super().finish(state, reason, kind, pc)
        self.outcomes[-1].update(
            reads=sorted(OP_NAMES[op] for op in state.reads),
            potential_effects=sorted(OP_NAMES[op] for op in state.effects),
            argument_reads=state.argument_reads, return_data=state.return_data,
            witnessed=input_witness(state),
            witnessed_nonzero=nonzero_witness(state))


def analyze_body(code, seeds, limits, dispatch_complete):
    """Explore one function entry from saved execution states and summarize its behavior.

    Return path outcomes, reads, effects, return-pattern information and completion
    status. The states share total instruction and state limits; each starts with
    a fresh per-path limit.
    """
    vm = BodyInterpreter(code, Limits(max_steps=limits.max_steps,
        max_states=limits.max_states, initial_path_budget=limits.max_path_steps,
        max_path_budget=limits.max_path_steps, max_memory=limits.max_memory,
        max_expression_nodes=limits.max_expression_nodes, trace_length=0))
    for seed in seeds:
        state = seed.fork()
        state.remaining_steps = limits.max_path_steps
        state.steps = 0
        vm.enqueue(state)
    vm.drain()
    outcomes = vm.outcomes
    complete = bool(outcomes) and dispatch_complete and not vm.issues
    reads = sorted({op for o in outcomes for op in o["reads"]})
    effects = sorted({op for o in outcomes for op in o["potential_effects"]})
    successes = [o for o in outcomes if o["kind"] in {"return", "stop"}]
    mutability = ("potentially_modifying" if effects else "unknown" if not complete or not successes
                  else "read_only" if set(reads) - {"CALLVALUE"} else "no_state_reads")
    getter = (complete and bool(successes) and not effects
              and not (set(reads) - {"SLOAD", "CALLVALUE"})
              and all(not o["argument_reads"] for o in outcomes)
              and all(o["calldatasize"]["min"] == 4
                      and o["return_data"] and o["return_data"]["scalar_storage"]
                      for o in successes))
    return {"scope": "all_call_values", "complete": complete,
        "dispatch_complete": dispatch_complete, "mutability_evidence": mutability,
        "reads": reads, "potential_effects": effects,
        "scalar_getter_candidate": getter,
        "successful_paths": len(successes), "outcomes": outcomes,
        "issues": vm.issues,
        "statistics": {"instructions_executed": vm.steps, "states_enqueued": vm.states}}


def analyze(code: bytes, *, origin: int = 0, limits: Limits | None = None,
            body_limits: BodyLimits | None = None,
            stop_at_selected_entry: bool = False,
            include_short_calldata_routes: bool = True) -> Analysis:
    """Find function selectors and entries, and optionally analyze their bodies.

    Return entries, call routes, call-value checks and search diagnostics.
    origin selects the suffix to execute as a separate code image. Its first byte
    has program counter zero, and all reported instruction offsets are relative
    to that byte.
    stop_at_selected_entry ends a path as soon as its function entry is selected;
    include_short_calldata_routes adds calls with lengths zero through three.
    Supplying body_limits adds a separately limited body analysis for each entry.
    complete records whether the requested discovery finished within its limits.
    """
    if not isinstance(code, bytes): raise TypeError("code must be bytes")
    if not isinstance(origin, int) or isinstance(origin, bool):
        raise TypeError("origin must be an integer")
    if not 0 <= origin <= len(code):
        raise ValueError("origin must satisfy 0 <= origin <= len(code)")
    code = code[origin:]
    configured = limits or Limits()
    if any(v <= 0 for k, v in asdict(configured).items()
           if k != "trace_length" and not (k == "max_steps" and v is None)) or configured.trace_length < 0:
        raise ValueError("budgets must be positive; trace_length must be nonnegative")
    if configured.initial_path_budget > configured.max_path_budget:
        raise ValueError("initial_path_budget must not exceed max_path_budget")
    if body_limits is None:
        return Interpreter(code, configured,
            stop_at_selected_entry=stop_at_selected_entry,
            include_short_calldata_routes=include_short_calldata_routes).run()
    if any(v <= 0 for v in asdict(body_limits).values()):
        raise ValueError("body budgets must be positive")
    dispatcher = BodySeedDispatcher(code, configured,
        stop_at_selected_entry=stop_at_selected_entry,
        include_short_calldata_routes=include_short_calldata_routes)
    result = dispatcher.run()
    from .library_guards import classify_entries
    library_entries = classify_entries(code, dispatcher.body_seeds, body_limits, result.complete)
    for function in result.functions:
        key = (int(function["selector"], 16), function["dispatch_entry_pc"])
        function["delegatecall_only"] = library_entries.get(key)
        function["body_analysis"] = analyze_body(code,
            dispatcher.body_seeds.get(key, []), body_limits, result.complete)
    return result
