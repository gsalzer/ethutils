"""Classify EVM bytecode into code, copied data, returned bytes and compiler metadata.

Jump targets and memory copies help identify embedded programs and code fragments.
Sections use offsets into the input, with exclusive end offsets. Their ranges may
overlap when the same bytes serve several purposes.
"""
from dataclasses import dataclass, field
from collections import deque
from typing import NamedTuple
from .opcodes import BY_VALUE, BY_NAME
from .arithmetic import evaluate
from .decoding import disassemble, require_bytes
from .metadata import extract_metadata
from .models import SectionAnalysis, Program, Fragment

TERMINATORS = {'STOP', 'RETURN', 'REVERT', 'INVALID', 'SELFDESTRUCT'}
STRONG_TERMINATORS = {'RETURN', 'REVERT', 'SELFDESTRUCT'}


def intervals(spans):
    """Merge overlapping or adjacent half-open ranges, discarding empty ranges."""
    result = []
    for a, b in sorted(spans):
        if a >= b:
            continue
        if result and a <= result[-1][1]:
            result[-1] = (result[-1][0], max(b, result[-1][1]))
        else:
            result.append((a, b))
    return result


MAX_BAD_TARGETS = 1
MAX_CONTEXT_FRAGMENT = 32
MAX_STACK_STATES = 16


class _TracedConstant(int):
    """An integer carrying the instruction offsets that contributed to its value."""
    def __new__(cls, value, sources):
        result = int.__new__(cls, value)
        result.sources = tuple(sorted(set(sources)))[:16]
        return result


_CONSTANT_NAMES = frozenset(('ADD','MUL','SUB','DIV','MOD','EXP','ADDMOD','MULMOD',
                            'AND','OR','XOR','NOT','ISZERO','EQ','LT','GT','SHL','SHR','BYTE'))


def _constant(name, args):
    """Fold supported operations on known words; return None for unknown results."""
    if name not in _CONSTANT_NAMES or any(value is None for value in args):
        return None
    return evaluate(BY_NAME[name], args)


def _merge_stacks(stacks):
    """Align stack tops and retain only constants shared by every alternative."""
    depth = min(map(len, stacks))
    if not depth:
        return ()
    return tuple(values[0] if all(x == values[0] for x in values) else None
                 for values in zip(*(stack[-depth:] for stack in stacks)))


class CopiedRange(NamedTuple):
    """Input offset and byte count of a CODECOPY source within the program bounds."""
    start: int
    length: int


class MemoryCopy(NamedTuple):
    """Map memory bytes [start, end) to input bytes at source, copied at copy_pc."""
    start: int
    end: int
    source: int
    copy_pc: int


class CopyEvidence(NamedTuple):
    """Record which program and CODECOPY instruction copied input bytes [start, end)."""
    origin: int
    start: int
    end: int
    copy_pc: int


class ReturnEvidence(NamedTuple):
    """Record input bytes copied to memory and returned unchanged by a RETURN instruction."""
    origin: int
    start: int
    end: int
    return_pc: int
    copy_pc: int


class CreatedEvidence(NamedTuple):
    """Record input bytes copied to memory and passed unchanged to CREATE/CREATE2."""
    origin: int
    start: int
    end: int
    create_pc: int
    copy_pc: int


class ProgramRange(NamedTuple):
    """Input range to examine as a program, with the origin of the program that copied it."""
    parent: int
    start: int
    end: int


class ProgramCandidate(NamedTuple):
    """A copied input range to examine as a program; is_returned marks RETURN evidence."""
    parent: int
    start: int
    end: int
    is_returned: bool


def _invalidate_memory(memory, start, length):
    """Remove overwritten memory ranges from the copy records, preserving unaffected bytes."""
    if length == 0:
        return memory
    if start is None or length is None:
        return ()
    end = start + length
    kept = []
    for copied in memory:
        if end <= copied.start or copied.end <= start:
            kept.append(copied)
            continue
        if copied.start < start:
            kept.append(copied._replace(end=start))
        if end < copied.end:
            kept.append(copied._replace(start=end, source=copied.source + end - copied.start))
    return tuple(kept)


@dataclass
class Exploration:
    """Instruction ranges, jump targets and memory-copy records found from one starting offset."""
    spans: set = field(default_factory=set)
    invalid_jump_targets: set = field(default_factory=set)
    invalid_jump_sources: set = field(default_factory=set)
    invalid_jump_details: dict = field(default_factory=dict)
    invalid_opcode_pcs: set = field(default_factory=set)
    truncated_push_pcs: set = field(default_factory=set)
    valid_jump_pcs: set[int] = field(default_factory=set)
    candidate_entries: set = field(default_factory=set)
    copied_ranges: set[CopiedRange] = field(default_factory=set)
    copy_evidence: set[CopyEvidence] = field(default_factory=set)
    returned_copies: set[ReturnEvidence] = field(default_factory=set)
    created_copies: set[CreatedEvidence] = field(default_factory=set)
    referenced_entries: set = field(default_factory=set)
    unresolved_jump: bool = False
    joined: bool = False
    terminated: bool = False
    terminators: set = field(default_factory=set)

    @property
    def valid_jump_count(self):
        """Number of distinct jump instructions with a valid resolved destination."""
        return len(self.valid_jump_pcs)

    def plausible(self, referenced=False, returned=False, bounded=False,
                  touching=False, known_bad=()):
        """Decide whether a candidate region has enough evidence to classify it as code.

        Valid jumps, terminating instructions and connections to known code provide
        support. referenced, returned, bounded and touching add context about the
        candidate.  A touching candidate is a JUMPDEST-led helper immediately
        adjacent to accepted code.  known_bad lists invalid jump targets already
        counted against the allowance.
        """
        known_bad = set(known_bad)
        # Charge the remaining allowance only for newly encountered invalid targets.
        return (len(self.invalid_jump_targets - known_bad) <= max(0, MAX_BAD_TARGETS-len(known_bad))
                and not (self.invalid_opcode_pcs or self.truncated_push_pcs)
                and bool(self.valid_jump_pcs or self.joined
                         or self.terminators & STRONG_TERMINATORS
                         or (returned and self.terminators)
                         or (bounded and (self.terminators or self.unresolved_jump))
                         or touching
                         or (referenced and (self.terminated or self.unresolved_jump))))


class Analyzer:
    """Find code regions and track which input bytes they copy and return.

    An origin is the input offset corresponding to program counter zero. A jump
    to v therefore points to input offset origin + v. Accepted regions contribute
    code ranges, jump references and copy records to subsequent searches.
    """
    def __init__(self, code, trace=False):
        require_bytes(code)
        self.code = code
        self.code_size = len(code)
        self.metadata = extract_metadata(code)
        self.meta_ranges = intervals((s, s+l) for s, l, _ in self.metadata)
        self.boundaries = {}
        self.limits = {0: self.code_size}
        self.accepted = {}  # origin -> exact decoded spans
        self.copied_regions: set[ProgramRange] = set()
        self.returned_copies: set[ReturnEvidence] = set()
        self.created_copies: set[CreatedEvidence] = set()
        self.diagnostics = []
        self.references = {}
        self.bad_targets = {}
        self.program_regions = {}  # returned origins, including rejected entries
        self.copy_evidence: set[CopyEvidence] = set()
        self.trace = trace

    def in_meta(self, pc):
        """Return whether an absolute input offset lies in recognized metadata."""
        return any(a <= pc < b for a, b in self.meta_ranges)

    def in_copied_data(self, origin, pc):
        """Return whether pc was copied as data by the program at origin."""
        return any(region.parent == origin and region.start <= pc < region.end
                   for region in self.copied_regions)

    def decoding(self, origin):
        """Return cached sets of instruction starts and JUMPDEST offsets for a program origin."""
        if origin not in self.boundaries:
            starts, destinations = set(), set()
            for instruction in disassemble(self.code, start=origin, end=self.limits.get(origin, self.code_size)):
                starts.add(instruction.pc)
                if instruction.name == 'JUMPDEST':
                    destinations.add(instruction.pc)
            self.boundaries[origin] = starts, destinations
        return self.boundaries[origin]

    def explore(self, origin, start, accepted=(), follow_jumps=True,
                accepted_intervals=None):
        """Follow instructions from start and collect code ranges, jumps and memory copies.

        Jumps use origin as program counter zero; accepted ranges end a path when
        reached. follow_jumps=False limits the search to the starting basic block.
        The search keeps the top 64 stack values and merges alternatives after 16
        states at one offset, retaining constants shared by those alternatives.
        """
        result = Exploration()
        limit = self.limits.get(origin, self.code_size)
        _, destinations = self.decoding(origin)
        work = deque([(start, (), ())])
        states = {}
        widened = {}
        accepted = (intervals(accepted) if accepted_intervals is None
                    else accepted_intervals)
        literal_pushes = None
        while work:
            pc, stack, memory = work.popleft()
            if pc >= limit:
                result.terminated = True
                continue
            if pc < origin or self.in_meta(pc):
                continue
            if any(a <= pc < b for a, b in accepted):
                result.joined = True
                continue
            if not follow_jumps and pc != start and pc in destinations:
                continue  # A JUMPDEST begins the next basic block.
            if pc in widened:
                memory = ()  # Merged stack states start with empty memory-copy records.
                merged = _merge_stacks((widened[pc], stack))
                if merged == widened[pc]:
                    continue
                stack = widened[pc] = merged
            else:
                seen = states.setdefault(pc, set())
                if (stack, memory) in seen:
                    continue
                if len(seen) < MAX_STACK_STATES:
                    seen.add((stack, memory))
                else:
                    stack = widened[pc] = _merge_stacks(tuple(state[0] for state in seen) + (stack,))
                    memory = ()
                    del states[pc]
            stack = list(stack)
            info = BY_VALUE[self.code[pc]]
            end = pc + 1 + (info.immediate if info else 0)
            if info is None:
                result.invalid_opcode_pcs.add(pc)
                result.spans.add((pc, pc+1))
                continue
            if end > limit:
                result.truncated_push_pcs.add(pc)
                continue
            if any(pc < b and a < end for a, b in self.meta_ranges):
                continue
            result.spans.add((pc, end))
            name = info.name
            def pop():
                return stack.pop() if stack else None
            if info.family == 'push':
                value = int.from_bytes(self.code[pc+1:end], 'big')
                if self.trace:
                    value = _TracedConstant(value, [pc])
                stack.append(value)
                target = origin + value
                next_info = BY_VALUE[self.code[end]] if end < limit else None
                if target in destinations:
                    result.referenced_entries.add(target)
                    if not (next_info and next_info.name in {'JUMP', 'JUMPI'}):
                        result.candidate_entries.add(target)
            elif info.family == 'dup':
                depth = info.required
                stack.append(stack[-depth] if len(stack) >= depth else None)
            elif info.family == 'swap':
                depth = info.required
                if len(stack) < depth:
                    stack[:0] = [None] * (depth-len(stack))
                stack[-1], stack[-depth] = stack[-depth], stack[-1]
            elif name in {'JUMP', 'JUMPI'}:
                target = pop()
                value_sources = getattr(target, 'sources', ())
                if name == 'JUMPI':
                    pop()  # Both branch paths are explored below.
                if target is None:
                    if name == 'JUMP':
                        result.unresolved_jump = True
                else:
                    target += origin
                    if target in destinations:
                        result.valid_jump_pcs.add(pc)
                        if follow_jumps:
                            work.append((target, tuple(stack[-64:]), memory))
                        else:
                            result.candidate_entries.add(target)
                    else:
                        result.invalid_jump_targets.add(target)
                        result.invalid_jump_sources.add((pc, target))
                        if literal_pushes is None:
                            literal_pushes = {}
                            for site in self.decoding(origin)[0]:
                                instruction = BY_VALUE[self.code[site]]
                                if instruction and instruction.family == 'push':
                                    value = int.from_bytes(self.code[site+1:site+1+instruction.immediate], 'big')
                                    literal_pushes.setdefault(value, []).append(site)
                        result.invalid_jump_details.setdefault((pc, target), dict(
                            jump=pc, target=target, relative_target=target-origin,
                            matching_literal_pushes=sorted(literal_pushes.get(target-origin, [])),
                            value_sources=list(value_sources),
                            stack=list(stack[-8:]), analysis_has_widened=bool(widened),
                            widened_at_jump=pc in widened))
                if name == 'JUMPI':
                    # Both branches are structural candidates, regardless of condition.
                    work.append((end, tuple(stack[-64:]), memory))
                elif end in destinations:
                    result.candidate_entries.add(end)
                continue
            else:
                args = [pop() for _ in range(info.pops)]
                if name == 'CODECOPY':
                    destination, source, length = args
                    memory = _invalidate_memory(memory, destination, length)
                    if source is not None and length is not None and length > 0:
                        a = origin + source
                        if origin <= a < limit:
                            result.copied_ranges.add(CopiedRange(a, min(length, limit-a)))
                            result.copy_evidence.add(CopyEvidence(origin, a, min(a+length, limit), pc))
                            if destination is not None:
                                copied = MemoryCopy(destination, destination+min(length, limit-a), a, pc)
                                memory = tuple(sorted((*memory, copied)))
                elif name in {'MSTORE', 'MSTORE8'}:
                    memory = _invalidate_memory(memory, args[0], 32 if name == 'MSTORE' else 1)
                elif name in {'CALLDATACOPY', 'RETURNDATACOPY', 'MCOPY'}:
                    memory = _invalidate_memory(memory, args[0], args[2])
                elif name == 'EXTCODECOPY':
                    memory = _invalidate_memory(memory, args[1], args[3])
                elif name in {'CALL', 'CALLCODE'}:
                    memory = _invalidate_memory(memory, args[5], args[6])
                elif name in {'DELEGATECALL', 'STATICCALL'}:
                    memory = _invalidate_memory(memory, args[4], args[5])
                elif name == 'RETURN':
                    offset, length = args
                    if offset is not None and length is not None and length > 0:
                        for copied in memory:
                            if copied.start <= offset and offset+length <= copied.end:
                                first = copied.source + offset - copied.start
                                result.returned_copies.add(ReturnEvidence(
                                    origin, first, first+length, pc, copied.copy_pc))
                elif name in {'CREATE', 'CREATE2'}:
                    offset, length = args[1], args[2]
                    if offset is not None and length is not None and length > 0:
                        for copied in memory:
                            if copied.start <= offset and offset+length <= copied.end:
                                first = copied.source + offset - copied.start
                                result.created_copies.add(CreatedEvidence(
                                    origin, first, first+length, pc, copied.copy_pc))
                if len(memory) > 32:
                    memory = ()  # Discard copy records when their count exceeds the memory-tracking limit.
                if name == 'PC': stack.append(_TracedConstant(pc-origin, [pc]) if self.trace else pc-origin)
                elif name == 'CODESIZE': stack.append(_TracedConstant(limit-origin, [pc]) if self.trace else limit-origin)
                elif info.pushes:
                    value = _constant(name, args) if info.pushes == 1 else None
                    if self.trace and value is not None:
                        value = _TracedConstant(value, [pc] + [s for arg in args for s in getattr(arg, 'sources', ())])
                    stack.extend([value] * info.pushes)
            if name in TERMINATORS:
                result.terminated = True
                result.terminators.add(name)
                if end in destinations:
                    result.candidate_entries.add(end)
            else:
                work.append((end, tuple(stack[-64:]), memory))
        return result

    def commit(self, origin, result):
        """Add a candidate's instruction ranges, jump references and copy records to the results."""
        self.accepted.setdefault(origin, set()).update(result.spans)
        self.bad_targets.setdefault(origin, set()).update(result.invalid_jump_targets)
        self.references.setdefault(origin, set()).update(result.referenced_entries)
        self.returned_copies.update(result.returned_copies)
        self.created_copies.update(result.created_copies)
        self.copy_evidence.update(result.copy_evidence)
        for copied in result.copied_ranges:
            self.copied_regions.add(ProgramRange(origin, copied.start, copied.start + copied.length))

    def bounded_fragment(self, origin, start, result, covered=None):
        """Check whether a short JUMPDEST-led region fills a gap between known code ranges."""
        if not result.spans:
            return False
        left = min(a for a, b in result.spans)
        end = max(b for a, b in result.spans)
        # Instruction spans do not overlap.  Equal total and enclosing lengths
        # therefore mean that they form one contiguous interval.
        contiguous = sum(b-a for a, b in result.spans) == end-left
        if left != start or not contiguous:
            return False
        if end-start > MAX_CONTEXT_FRAGMENT or start not in self.decoding(origin)[1]:
            return False
        if covered is None:
            covered = intervals(self.accepted.get(origin, ()))
        return any(b == start for a, b in covered) and any(a == end for a, b in covered)

    def touching_fragment(self, origin, start, result, covered=None):
        """Return whether a JUMPDEST-led candidate touches accepted code.

        This is the block-connectivity evidence used by the experimental
        sectioner: a helper may extend code on either side even when a weak
        STOP, INVALID or constant exceptional jump would not be sufficient in
        isolation.  Ordinary plausibility checks still reject undefined
        opcodes, truncated pushes and excess new invalid jump targets.
        """
        if start not in self.decoding(origin)[1] or not result.spans:
            return False
        if covered is None:
            covered = intervals(self.accepted.get(origin, ()))
        return any(b == start for a, b in covered) or any(
            right == a for left, right in result.spans for a, b in covered)

    def promote_bounded_fragments(self):
        """Examine short gaps between known code ranges; return whether any become code."""
        changed = False
        for origin, spans in sorted(self.accepted.items()):
            covered = intervals(spans)
            for (_, start), (end, _) in zip(covered, covered[1:]):
                if 0 < end-start <= MAX_CONTEXT_FRAGMENT and start in self.decoding(origin)[1]:
                    changed |= self.region(origin, start)
        return changed

    def region(self, origin, start, trusted=False, returned=False, block=False):
        """Classify code starting at start, then examine additional entry points it references.

        trusted accepts the initial region directly. returned supplies contextual
        program evidence for bytes obtained from RETURN, CREATE or CREATE2;
        block restricts exploration to one basic block. Return True when a new
        region is accepted.
        """
        accepted = self.accepted.get(origin, set())
        if any(a <= start < b for a, b in accepted) or self.in_meta(start):
            return False
        # A constant CODECOPY is positive data evidence for its owning program.
        # Reinterpretation under a new origin requires an explicit RETURN,
        # CREATE or CREATE2 program relation.
        if not trusted and not returned and self.in_copied_data(origin, start):
            return False
        covered = intervals(accepted)
        result = self.explore(origin, start, follow_jumps=not block,
                              accepted_intervals=covered)
        bounded = self.bounded_fragment(origin, start, result, covered)
        touching = self.touching_fragment(origin, start, result, covered)
        referenced = start in self.references.get(origin, set())
        is_accepted = bool(result.spans) and (trusted or result.plausible(
            referenced, returned=returned, bounded=bounded, touching=touching,
            known_bad=self.bad_targets.get(origin, ())))
        # G counts valid jumps; B lists invalid targets; I lists undefined opcodes.
        self.diagnostics.append({
            'origin': origin, 'start': start, 'accepted': is_accepted,
            'recovery': 'basic_block' if block else None,
            'G': result.valid_jump_count, 'bounded_fragment': bounded,
            'touching_fragment': touching,
            'returned_entry': returned, 'terminators': sorted(result.terminators),
            'referenced': referenced, 'unresolved_jump': result.unresolved_jump,
            'B': sorted(result.invalid_jump_targets),
            'known_bad_targets': sorted(self.bad_targets.get(origin, ())),
            'bad_jumps': [result.invalid_jump_details[key]
                          for key in sorted(result.invalid_jump_details)],
            'I': sorted(result.invalid_opcode_pcs),
            'truncated': sorted(result.truncated_push_pcs),
        })
        if not is_accepted:
            if not block and origin in self.program_regions:
                return self.region(origin, start, returned=returned, block=True)
            return False
        self.commit(origin, result)
        pending = set(result.candidate_entries)
        attempted = set()
        covered = intervals(self.accepted[origin])
        while pending:
            entry = min(pending)
            pending.remove(entry)
            if entry in attempted or any(a <= entry < b for a, b in covered):
                continue
            attempted.add(entry)
            if self.in_copied_data(origin, entry):
                continue
            candidate = self.explore(origin, entry, accepted_intervals=covered)
            touching = self.touching_fragment(origin, entry, candidate, covered)
            if candidate.plausible(
                    entry in self.references.get(origin, set()),
                    bounded=self.bounded_fragment(origin, entry, candidate, covered),
                    touching=touching,
                    known_bad=self.bad_targets.get(origin, ())):
                self.commit(origin, candidate)
                # Extend the already merged coverage instead of repeatedly
                # sorting every historical instruction span for this origin.
                covered = intervals((*covered, *candidate.spans))
                pending.update(candidate.candidate_entries - attempted)
        return True

    def gaps(self):
        """Yield input ranges still available for code discovery after marking code and metadata."""
        spans = self.meta_ranges + [span for group in self.accepted.values() for span in group]
        cursor = 0
        for a, b in intervals(spans):
            if cursor < a: yield cursor, a
            cursor = max(cursor, b)
        if cursor < self.code_size: yield cursor, self.code_size

    def _discover_copied_programs(self, attempted):
        """Examine explicitly returned or created bytes as programs; report code growth.

        Plain CODECOPY establishes data, not a program origin. CODECOPY bytes
        passed unchanged to RETURN, CREATE or CREATE2 establish one explicitly.
        """
        candidates = {ProgramCandidate(record.origin, record.start, record.end, True)
                      for record in self.returned_copies}
        candidates.update(ProgramCandidate(record.origin, record.start, record.end, False)
                          for record in self.created_copies)
        changed = False
        # Returned subranges define a more precise extent than enclosing copies.
        for candidate in sorted(candidates - attempted, key=lambda item: (
                not item.is_returned, item.start, item.end, item.parent)):
            attempted.add(candidate)
            start = candidate.start
            if any(a < start < b for spans in self.accepted.values() for a, b in spans):
                continue  # Keep the operand bytes within their existing instruction.
            if start not in self.limits:
                self.limits[start] = candidate.end
                self.boundaries.pop(start, None)
            self.program_regions[start] = self.limits[start]
            # Both returned runtime and CREATE input are explicit program
            # relations.  `returned` here supplies that contextual evidence to
            # plausibility; output returned records remain separate.
            changed |= self.region(start, start, returned=True)
        return changed

    def _candidate_origins(self, start, gap_end, origins):
        """Choose program origins for interpreting jumps from start, in preferred search order."""
        owners = [origin for origin, end in self.program_regions.items() if origin <= start < end]
        if not owners:
            return origins + ([start] if start not in origins else [])

        # Interpret internal blocks relative to the start of their enclosing program.
        candidates = sorted(owners, reverse=True)
        # Constructor continuations can overlap a returned range (e.g. Vyper).
        candidates += [origin for origin in sorted(self.accepted) if origin not in candidates
                       and start in self.references.get(origin, ())]
        # Include parent code that continues directly past the returned range.
        candidates += [record.origin for record in sorted(self.returned_copies)
                       if record.start in owners and record.end == gap_end
                       and record.origin not in candidates
                       and any(a == record.end for a, b in self.accepted.get(record.origin, ()))]
        return candidates

    def _discover_gap_fragments(self, attempted):
        """Search unclassified ranges and their JUMPDESTs for additional code regions."""
        changed = False
        for gap_start, gap_end in list(self.gaps()):
            # Search past rejected prefixes while excluding PUSH operand bytes.
            entries = {gap_start}
            origins = sorted(set(self.accepted) | set(self.program_regions))
            for origin in origins:
                entries.update(pc for pc in self.decoding(origin)[1]
                               if gap_start <= pc < gap_end and not self.in_meta(pc))
            for start in sorted(entries):
                program_owners = [origin for origin, end in self.program_regions.items()
                                  if origin <= start < end]
                data_owners = {region.parent for region in self.copied_regions
                               if region.start <= start < region.end}
                # Copied bytes are not an invitation to invent a fresh origin.
                # They remain eligible only inside an explicitly established
                # returned program, and never as speculative code for the
                # program that copied them.
                if data_owners and not program_owners:
                    continue
                candidate_origins = self._candidate_origins(start, gap_end, origins)
                for origin in candidate_origins:
                    if origin in data_owners:
                        continue
                    key = (origin, start)
                    if key in attempted or origin > start or start >= self.limits.get(origin, self.code_size):
                        continue
                    attempted.add(key)
                    if start not in self.decoding(origin)[0]:
                        continue
                    if self.region(origin, start):
                        changed = True
                        break
        return changed

    def discover(self):
        """Find code at the input entry, in copied programs and in gaps until coverage stabilizes."""
        if self.code_size:
            self.region(0, 0, trusted=True)
        tried_programs = set()
        tried_fragments = set()
        while True:
            if self._discover_copied_programs(tried_programs):
                continue  # Examine newly found copies before searching the remaining gaps.
            changed = self._discover_gap_fragments(tried_fragments)
            changed |= self.promote_bounded_fragments()
            if not changed:
                break

    def _data_sections(self, origin, protected):
        """Yield data sections, marking copied bytes after a returned program as possible arguments."""
        returned_end = max((record.end for record in self.returned_copies
                            if record.origin == origin), default=None)
        data_spans = intervals((region.start, region.end) for region in self.copied_regions
                               if region.parent == origin)
        # Preserve the boundary between returned code and a copied argument tail.
        if returned_end is not None:
            data_spans = [(start, end) for a, b in data_spans
                          for start, end in ([(a, returned_end), (returned_end, b)]
                                             if a < returned_end < b else [(a, b)])]
        for start, end in data_spans:
            part = dict(kind='data', start=start, end=end, origin=origin)
            copies = sorted(record.copy_pc for record in self.copy_evidence
                            if record.origin == origin and record.start <= start and end <= record.end)
            if (returned_end is not None and start >= returned_end and copies
                    and not any(a < end and start < b for a, b in protected)):
                part.update(role='constructor_arguments_candidate',
                            evidence='copied_tail_after_returned_program',
                            copies=copies, after_returned=returned_end)
            yield part

    def build_sections(self):
        """Convert collected code, copy, return and metadata records into sorted section dictionaries."""
        sections = []
        for origin, spans in self.accepted.items():
            sections.extend(dict(kind='code', start=start, end=end, origin=origin)
                            for start, end in intervals(spans))
        protected = self.meta_ranges + [span for group in self.accepted.values() for span in group]
        protected += [(record.start, record.end) for record in self.returned_copies]
        for origin in sorted({region.parent for region in self.copied_regions}):
            sections.extend(self._data_sections(origin, protected))
        sections.extend(dict(kind='returned', start=record.start, end=record.end,
                             origin=record.origin, via=record.return_pc, copy=record.copy_pc)
                        for record in sorted(self.returned_copies))
        sections.extend(dict(kind='meta', start=start, end=start+length, cbor=cbor)
                        for start, length, cbor in self.metadata)
        return sorted(sections, key=lambda part: (
            part['start'], part['end'], part['kind'], part.get('origin', -1),
            part.get('via', -1), part.get('copy', -1)))

    def run(self):
        """Find code, data and metadata regions and return their sorted section dictionaries."""
        self.discover()
        return self.build_sections()


def section(code: bytes) -> list[dict]:
    """Find code, copied data, returned bytes and compiler metadata in EVM bytecode.

    Return dictionaries with kind, start and exclusive end offsets into code.
    Ranges can overlap. Returned-byte records also identify the returning program
    by origin and the RETURN and CODECOPY instructions by via and copy.
    """
    return Analyzer(code).run()


def decompose(code: bytes) -> list[tuple[str, bytes]]:
    """Split bytecode into consecutive code, data, meta and unclassified chunks.

    Section boundaries atomize overlapping classifications. Metadata takes
    precedence over code, and code over copied data; non-overlapping portions
    of a broader data section retain their data label. Unclassified bytes use
    the empty tag. Concatenating the bytes reproduces the original input.
    """
    sections = section(code)
    priority = ('meta', 'code', 'data')
    events = {0: [], len(code): []}
    for part in sections:
        tag = part['kind']
        if tag not in priority:
            continue
        events.setdefault(part['start'], [])
        events.setdefault(part['end'], [])
        events[part['start']].append((tag, 1))
        events[part['end']].append((tag, -1))

    active = dict.fromkeys(priority, 0)
    result = []
    start, current_tag = 0, ''
    for offset in sorted(events):
        if start < offset:
            result.append((current_tag, code[start:offset]))
        # Counts retain a label while any overlapping section of that kind remains.
        for tag, change in events[offset]:
            active[tag] += change
        current_tag = next((tag for tag in priority if active[tag]), '')
        start = offset
    return result


def runtime(code: bytes) -> bytes | None:
    """Extract the presumed deployed runtime from creation bytecode.

    Use section records to identify one distinct byte sequence returned by
    origin zero, with recognized code at its entry. Return the complete bytes,
    including data and metadata, or None for missing or ambiguous evidence.
    """
    sections = section(code)
    code_origins = {part['origin'] for part in sections
                    if part['kind'] == 'code' and part['start'] == part['origin']}
    if 0 not in code_origins:
        return None
    returned = [part for part in sections
                if part['kind'] == 'returned' and part['origin'] == 0]
    candidates = {code[part['start']:part['end']] for part in returned}
    # Consider every returned sequence before checking whether its entry is code.
    if len(candidates) != 1:
        return None
    if any(part['start'] in code_origins for part in returned):
        return candidates.pop()
    return None


def analyze_sections(code: bytes, *, trace: bool = False) -> SectionAnalysis:
    """Find bytecode sections and embedded programs, with explanations of the classifications.

    Return a SectionAnalysis containing section ranges, the original bytes for
    each detected program, and decisions about candidate code regions. Offsets
    refer to the input bytecode. trace=True also records which instructions
    contributed to invalid jump targets.
    """
    analyzer = Analyzer(code, trace=trace)
    sections = analyzer.run()
    programs = []
    for origin in sorted(set(analyzer.accepted) | set(analyzer.program_regions)):
        end = analyzer.limits.get(origin, len(code))
        returned = sorted(ProgramRange(record.origin, record.start, record.end)
                          for record in analyzer.returned_copies if record.start == origin)
        created = sorted(ProgramRange(record.origin, record.start, record.end)
                         for record in analyzer.created_copies if record.start == origin)
        evidence = ('entry' if origin == 0 else 'returned_copy' if returned
                    else 'created_copy' if created else 'fragment')
        parents = returned or created
        decisions = [d for d in analyzer.diagnostics if d['origin'] == origin and d['start'] == origin]
        programs.append(Program(origin, code[origin:end], (Fragment(origin, end, 0),),
                                evidence, parents[0].parent if parents else None,
                                any(d['accepted'] for d in decisions),
                                tuple(intervals(analyzer.accepted.get(origin, ())))))
    return SectionAnalysis(sections, programs, analyzer.diagnostics)
