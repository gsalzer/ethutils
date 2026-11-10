"""Compare program subtrees using recursively compatible child correspondences.

Code ranges sharing an origin form one program. Immediate CODECOPY and RETURN
records connect programs; returned code is a special case of copied data.
Child correspondences are inclusion-minimal edge covers: disjoint one-to-one,
one-to-many or many-to-one groups. Collapsing can change direction between
groups and at different depths. Shared physical programs are compared in each
parent context, with code-check decisions cached by their original origins.

Program properties are computed at origin zero for each effective sectioned
image and cached by image bytes during a comparison.
"""
from collections import Counter, defaultdict, deque
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from itertools import combinations

from . import analysis, sectioning
from .decoding import require_bytes

CodeMapping = tuple[tuple[int, int], ...]
TraceCallback = Callable[[dict], None]

__all__ = ['compatible', 'code_mappings', 'properties_compatible']

_DATA = 'data'
_RETURNED = 'returned'
_ROOT = -1


@dataclass
class _Graph:
    origins: tuple[int, ...]
    edges: dict[tuple[int, int], str]
    images: dict[int, bytes] = field(default_factory=dict)

    def prepare(self, allow_reuse):
        """Build typed child lists and structural signatures from leaves upwards.

        A virtual root keeps origin zero fixed and accounts for detached program
        components. Multiple parents represent distinct uses of a shared image.
        Cycles raise ValueError because subtree comparison requires finite depth.
        """
        children = {origin: [] for origin in self.origins}
        incoming = dict.fromkeys(self.origins, 0)
        for (parent, child), kind in sorted(self.edges.items()):
            children[parent].append((child, kind))
            incoming[child] += 1
        remaining = incoming.copy()
        queue = deque(origin for origin, degree in remaining.items() if degree == 0)
        order = []
        while queue:
            parent = queue.popleft()
            order.append(parent)
            for child, _ in children[parent]:
                remaining[child] -= 1
                if remaining[child] == 0:
                    queue.append(child)
        if len(order) != len(self.origins):
            raise ValueError('program copy/return relationships must be acyclic')
        if incoming.get(0, 0):
            raise ValueError('origin zero must be a root program')
        children[_ROOT] = ([(0, 'entry')] if 0 in children else []) + [
            (origin, 'detached') for origin in self.origins if origin != 0 and incoming[origin] == 0]
        shapes = {}
        for origin in [*reversed(order), _ROOT]:
            values = [(kind, shapes[child]) for child, kind in children[origin]]
            shapes[origin] = (frozenset(values) if allow_reuse else
                              frozenset(Counter(values).items()))
        return {node: tuple(values) for node, values in children.items()}, shapes


def _graph(bytecode, ignore_constructor_args=False):
    """Group code by origin and retain immediate copy/return relationships.

    Individual sectioning records identify the program beginning at each copied
    or returned source offset. This retains shared uses and avoids adding edges
    to every deeper program merely contained in the copied bytes. A return edge
    supersedes the ordinary data edge between the same programs. Copied constants
    and metadata contribute no program nodes.
    """
    analyzer = sectioning.Analyzer(bytecode)
    sections = analyzer.run()
    ranges = defaultdict(list)
    for part in sections:
        if part['kind'] == 'code':
            ranges[part['origin']].append((part['start'], part['end']))

    def covers(parent, start, end):
        return parent in ranges and start in ranges and all(
            start <= a and b <= end for a, b in ranges[start])

    edges = {(record.parent, record.start): _DATA for record in analyzer.copied_regions
             if covers(record.parent, record.start, record.end)}
    # ABI decoding finds a program inside a broader copied data range, so there
    # is no ProgramRange beginning at the payload itself. Retain the immediate
    # data-parent relation explicitly instead of making the embedded program a
    # detached component of the comparison graph.
    edges.update({(record.parent, record.start): _DATA
                  for record in getattr(analyzer, 'abi_programs', {}).values()
                  if covers(record.parent, record.start, record.end)})
    edges.update({(record.origin, record.start): _RETURNED for record in analyzer.returned_copies
                  if covers(record.origin, record.start, record.end)})
    def argument_tail(origin):
        """Return the copied trailing-data boundary after origin's returned image."""
        candidates = [part['start'] for part in sections
                      if part.get('origin') == origin
                      and part.get('role') == 'constructor_arguments_candidate']
        returned_end = max((record.end for record in analyzer.returned_copies
                            if record.origin == origin), default=None)
        if returned_end is not None:
            candidates.extend(
                record.start for record in getattr(analyzer, 'copy_evidence', ())
                if record.origin == origin and record.start >= returned_end
                and not any(a < record.end and record.start < b
                            for a, b in ranges.get(origin, ())))
        return min(candidates, default=None)

    constructor_tail = argument_tail(0)
    excluded = set()
    if ignore_constructor_args and constructor_tail is not None:
        # Ignore every program image physically contained in the initial
        # constructor's trailing arguments, irrespective of how it was found.
        excluded.update(origin for origin in ranges if origin >= constructor_tail)
        while True:
            descendants = {child for (parent, child) in edges if parent in excluded}
            if descendants <= excluded:
                break
            excluded.update(descendants)
        edges = {(parent, child): kind for (parent, child), kind in edges.items()
                 if parent not in excluded and child not in excluded}
    limits = getattr(analyzer, 'limits', {})
    image_ends = {origin: limits.get(origin, len(bytecode)) for origin in ranges}
    for part in sections:
        if part.get('role') == 'constructor_arguments_candidate' and part.get('origin') in image_ends:
            origin = part['origin']
            image_ends[origin] = min(image_ends[origin], part['start'])
    # An embedded ABI program overlaps its enclosing data record, which keeps
    # that record from receiving the constructor_arguments_candidate role.
    # Recover the same boundary from the parent's own return/copy evidence.
    # Child-program code does not make constructor arguments part of the
    # parent's image; only code accepted under the parent origin prevents trim.
    for origin in image_ends:
        tail = argument_tail(origin)
        if tail is not None:
            image_ends[origin] = min(image_ends[origin], tail)
    images = {origin: bytecode[origin:image_ends[origin]] for origin in ranges
              if origin not in excluded}
    return _Graph(tuple(sorted(set(ranges) - excluded)), edges, images)


def _minimal_covers(left, right, edges, allow_reuse=True):
    """Yield every inclusion-minimal bipartite edge cover exactly once.

    Take the first remaining left vertex. Its star either has that vertex as
    centre, or has a right centre with at least two left leaves. Remove the
    star's vertices and recurse. Singleton stars are tried first. With reuse
    disabled, only singleton stars are eligible, yielding perfect matchings.
    """
    if not left and not right:
        yield ()
        return
    if not left or not right or (not allow_reuse and len(left) != len(right)):
        return
    if any(not any((a, b) in edges for b in right) for a in left) or any(
            not any((a, b) in edges for a in left) for b in right):
        return
    first = left[0]
    neighbors = tuple(b for b in right if (first, b) in edges)
    for size in range(1, len(neighbors) + 1 if allow_reuse else 2):
        for selected in combinations(neighbors, size):
            tail = tuple(b for b in right if b not in selected)
            star = tuple((first, b) for b in selected)
            for rest in _minimal_covers(left[1:], tail, edges, allow_reuse):
                yield tuple(sorted(star + rest))
    if allow_reuse:
        for centre in neighbors:
            leaves = tuple(a for a in left[1:] if (a, centre) in edges)
            for size in range(1, len(leaves) + 1):
                for selected in combinations(leaves, size):
                    tail = tuple(a for a in left[1:] if a not in selected)
                    star = tuple((a, centre) for a in (first, *selected))
                    for rest in _minimal_covers(tail, tuple(b for b in right if b != centre), edges, True):
                        yield tuple(sorted(star + rest))


def _perfect_matching_exists(left, right, edges):
    """Decide whether every vertex can have one distinct partner."""
    if len(left) != len(right):
        return False
    matched = {}

    def augment(a, seen):
        for b in right:
            if (a, b) in edges and b not in seen:
                seen.add(b)
                if b not in matched or augment(matched[b], seen):
                    matched[b] = a
                    return True
        return False

    return all(augment(a, set()) for a in left)


def _bijective(mapping):
    return len({a for a, _ in mapping}) == len(mapping) == len({b for _, b in mapping})


class _Comparison:
    """Memoize subtree feasibility and lazily combine its local edge covers."""
    def __init__(self, first, second, allow_reuse, programs_compatible=None, emit=None):
        self.allow_reuse = allow_reuse
        self.programs_compatible = programs_compatible or (lambda _a, _b: True)
        self.emit = emit or (lambda _kind, **_fields: None)
        self.children1, self.shapes1 = first.prepare(allow_reuse)
        self.children2, self.shapes2 = second.prepare(allow_reuse)
        self.feasible = {}
        self.existence = {}
        self.program_feasible = {}
        self.child_graphs = {}
        self.rooted = (not first.origins or 0 in first.origins) and (not second.origins or 0 in second.origins)

    def _program_possible(self, a, b):
        """Check one physical program pair once across existence and enumeration."""
        pair = (a, b)
        if pair not in self.program_feasible:
            answer = self.programs_compatible(a, b)
            if not isinstance(answer, bool):
                raise TypeError('programs_compatible must return a boolean')
            self.program_feasible[pair] = answer
        return self.program_feasible[pair]

    def _ordered_bijection(self, left, right, index=0, used=frozenset()):
        """Try ordered one-to-one child assignments, evaluating pairs only as needed."""
        if index == len(left):
            return True
        child, kind = left[index]
        for partner, other_kind in right:
            if (partner not in used and kind == other_kind
                    and self.lazy_possible(child, partner)
                    and self._ordered_bijection(left, right, index+1, used | {partner})):
                return True
        return False

    def _reuse_cover_exists(self, left, right):
        """Check lazily that every child has a partner when partners may be reused."""
        for child, kind in left:
            if not any(kind == other_kind and self.lazy_possible(child, partner)
                       for partner, other_kind in right):
                return False
        for partner, kind in right:
            if not any(kind == other_kind and self.lazy_possible(child, partner)
                       for child, other_kind in left):
                return False
        return True

    def lazy_possible(self, a, b):
        """Check subtree existence, preferring an ordered bijection before reuse."""
        pair = (a, b)
        if pair in self.existence:
            return self.existence[pair]
        if not self.rooted or self.shapes1[a] != self.shapes2[b]:
            self.emit('structural_pair', origin1=None if a == _ROOT else a,
                      origin2=None if b == _ROOT else b, compatible=False,
                      reason='missing_root' if not self.rooted else 'subtree_shape')
            self.existence[pair] = False
            return False
        if a != _ROOT:
            if not self._program_possible(a, b):
                self.existence[pair] = False
                return False
        left, right = self.children1[a], self.children2[b]
        answer = (len(left) == len(right)
                  and self._ordered_bijection(left, right))
        reason = 'ordered_bijection'
        if not answer and self.allow_reuse:
            answer = self._reuse_cover_exists(left, right)
            reason = 'children_covered' if answer else 'children_without_cover'
        elif not answer:
            reason = 'children_without_cover'
        self.emit('structural_pair', origin1=None if a == _ROOT else a,
                  origin2=None if b == _ROOT else b, compatible=answer, reason=reason)
        self.existence[pair] = answer
        return answer

    def possible(self, a, b):
        """Check the code pair and require a partner for every child on both sides."""
        pair = (a, b)
        if pair in self.feasible:
            return self.feasible[pair]
        if not self.rooted or self.shapes1[a] != self.shapes2[b]:
            self.emit('structural_pair', origin1=None if a == _ROOT else a,
                      origin2=None if b == _ROOT else b, compatible=False,
                      reason='missing_root' if not self.rooted else 'subtree_shape')
            self.feasible[pair] = False
            return False
        if a != _ROOT:
            if not self._program_possible(a, b):
                self.feasible[pair] = False
                return False
        left, right = self.children1[a], self.children2[b]
        edges = set()
        for x, kind in left:
            matches = {(x, y) for y, other_kind in right
                       if kind == other_kind and self.possible(x, y)}
            if not matches:
                self.emit('structural_pair', origin1=None if a == _ROOT else a,
                          origin2=None if b == _ROOT else b, compatible=False,
                          reason='child_without_partner')
                self.feasible[pair] = False
                return False
            edges.update(matches)
        left_nodes, right_nodes = tuple(x for x, _ in left), tuple(y for y, _ in right)
        answer = all(any((x, y) in edges for x in left_nodes) for y in right_nodes)
        if answer and not self.allow_reuse:
            answer = _perfect_matching_exists(left_nodes, right_nodes, edges)
        self.emit('structural_pair', origin1=None if a == _ROOT else a,
                  origin2=None if b == _ROOT else b, compatible=answer,
                  reason='children_covered' if answer else 'children_without_cover')
        self.feasible[pair] = answer
        if answer:
            self.child_graphs[pair] = (left_nodes, right_nodes, edges)
        return answer

    def _combine(self, cover, index, mapping):
        """Form a lazy Cartesian product of the chosen child-pair generators."""
        if index == len(cover):
            yield mapping
            return
        for subtree in self._mappings(*cover[index]):
            merged = mapping | subtree
            if self.allow_reuse or _bijective(merged):
                yield from self._combine(cover, index + 1, merged)

    def _mappings(self, a, b):
        if not self.possible(a, b):
            return
        left, right, edges = self.child_graphs[a, b]
        initial = frozenset() if a == _ROOT else frozenset({(a, b)})
        for cover in _minimal_covers(left, right, edges, self.allow_reuse):
            yield from self._combine(cover, 0, initial)

    def mappings(self):
        """Yield distinct physical-origin correspondences from contextual witnesses."""
        seen = set()
        for mapping in self._mappings(_ROOT, _ROOT):
            if mapping not in seen:
                seen.add(mapping)
                yield tuple(sorted(mapping))

    def exists(self):
        if not self.allow_reuse:
            # Shared physical nodes can impose additional global bijection constraints.
            return next(self.mappings(), None) is not None
        return self.lazy_possible(_ROOT, _ROOT)


_FUNCTION_PROPERTIES = (
    'delegatecall_only',
    'rejects_nonzero_value',
    'read_only',
    'state_independent',
    'scalar_storage_getter',
    'return_size',
)
_REJECTS_NONZERO = frozenset(('always_rejects', 'nonzero_rejected'))
_MAY_ACCEPT_NONZERO = frozenset(('conditional', 'no_value_guard_observed'))


def _emitter(trace):
    if trace is not None and not callable(trace):
        raise TypeError('trace must be callable')

    def emit(kind, **fields):
        if trace is not None:
            trace({'kind': kind, **fields})
    return emit


def _function_compatible(selector, first, second, emit, context):
    """Reject established disagreements in one selector's merged summaries."""
    for name in _FUNCTION_PROPERTIES:
        value1, value2 = first.get(name), second.get(name)
        compared = value1 is not None and value2 is not None
        answer = not compared or value1 == value2
        emit('function_property', **context, selector=selector.hex(), property=name,
             value1=value1, value2=value2, compared=compared, compatible=answer)
        if not answer:
            return False
    return True


def _route_value_compatible(first, second):
    if 'unknown' in (first, second):
        return True, False
    conflict = ((first in _REJECTS_NONZERO and second in _MAY_ACCEPT_NONZERO) or
                (second in _REJECTS_NONZERO and first in _MAY_ACCEPT_NONZERO))
    return not conflict, True


def _routes_compatible(first, second, emit, context):
    """Compare normalized behavior for each non-selector calldata category."""
    routes1 = {route['category']: route for route in first}
    routes2 = {route['category']: route for route in second}
    for category in sorted(set(routes1) | set(routes2)):
        route1, route2 = routes1.get(category, {}), routes2.get(category, {})
        behavior1, behavior2 = route1.get('behavior', 'unknown'), route2.get('behavior', 'unknown')
        compared = 'unknown' not in (behavior1, behavior2)
        answer = not compared or behavior1 == behavior2
        emit('route_behavior', **context, category=category, property='behavior',
             value1=behavior1, value2=behavior2, compared=compared, compatible=answer)
        if not answer:
            return False

        value1 = route1.get('value_policy', 'unknown')
        value2 = route2.get('value_policy', 'unknown')
        answer, compared = _route_value_compatible(value1, value2)
        emit('route_behavior', **context, category=category, property='value_policy',
             value1=value1, value2=value2, compared=compared, compatible=answer)
        if not answer:
            return False
    return True


def properties_compatible(first, second, *, trace: TraceCallback | None = None,
                          origin1: int | None = None, origin2: int | None = None) -> bool:
    """Return whether two property analyses have no established contradiction.

    Discovered selector sets must be equal. For each selector, known merged
    function properties must agree. Non-selector routes are compared by calldata
    category, behavior and positive-value acceptance. Unknown values do not
    conflict. trace receives structured records for the checks that are made.
    """
    emit = _emitter(trace)
    context = {'origin1': origin1, 'origin2': origin2}
    selectors1, selectors2 = set(first.properties), set(second.properties)
    answer = selectors1 == selectors2
    emit('selector_sets', **context,
         selectors1=[value.hex() for value in sorted(selectors1)],
         selectors2=[value.hex() for value in sorted(selectors2)], compatible=answer)
    if not answer:
        return False
    for selector in sorted(selectors1):
        if not _function_compatible(selector, first.properties[selector],
                                    second.properties[selector], emit, context):
            return False
    return _routes_compatible(first.routes, second.routes, emit, context)


def _comparison(bytecode1, bytecode2, allow_reuse,
                ignore_constructor_args=False, trace=None):
    require_bytes(bytecode1)
    require_bytes(bytecode2)
    if not isinstance(allow_reuse, bool):
        raise TypeError('allow_reuse must be a boolean')
    if not isinstance(ignore_constructor_args, bool):
        raise TypeError('ignore_constructor_args must be a boolean')
    emit = _emitter(trace)

    graph1 = _graph(bytecode1, ignore_constructor_args)
    graph2 = _graph(bytecode2, ignore_constructor_args)
    property_cache = {}

    def program_properties(graph, origin):
        image = graph.images[origin]
        if image not in property_cache:
            property_cache[image] = analysis.properties(image)
        return property_cache[image]

    def programs_compatible(origin1, origin2):
        first = program_properties(graph1, origin1)
        second = program_properties(graph2, origin2)
        answer = properties_compatible(first, second, trace=trace,
                                       origin1=origin1, origin2=origin2)
        emit('program_pair', origin1=origin1, origin2=origin2, compatible=answer)
        return answer

    return _Comparison(graph1, graph2, allow_reuse, programs_compatible, emit)


def code_mappings(bytecode1: bytes, bytecode2: bytes, *,
                  allow_reuse: bool = True,
                  ignore_constructor_args: bool = False,
                  trace: TraceCallback | None = None) -> Iterator[CodeMapping]:
    """Yield recursive correspondences as tuples of (origin1, origin2) pairs.

    Section each input once and group code by origin. Start at (0, 0), matching
    immediate copy/return relationships. At each paired parent, select a minimal
    child edge cover; each group is one-to-one, one-to-many or many-to-one.
    Direction can vary between groups and depths. Child pairs must themselves
    admit complete subtree correspondences. All detected programs are covered;
    detached components are matched separately from the origin-zero subtree.

    Each origin is analyzed with properties() at most once per input. The local
    programs_compatible predicate passes the resulting analyses to
    properties_compatible, and subtree feasibility is cached per origin pair.
    allow_reuse=False requires a one-to-one correspondence of physical origins.
    Shared physical children are compared in each parent context; duplicate
    projected results are yielded once. Cyclic program relationships raise
    ValueError. Empty inputs yield (). trace receives structured records as the
    returned iterator is consumed. ignore_constructor_args=True removes every
    program in the initial constructor's trailing argument data, together with
    its descendants, from both program graphs.
    """
    comparison = _comparison(bytecode1, bytecode2, allow_reuse,
                             ignore_constructor_args, trace)
    emit = _emitter(trace)

    def traced_mappings():
        for mapping in comparison.mappings():
            emit('mapping', mapping=list(mapping), compatible=True)
            yield mapping
    return traced_mappings()


def compatible(runtime1: bytes, runtime2: bytes, *, allow_reuse: bool = True,
               ignore_constructor_args: bool = False,
               trace: TraceCallback | None = None) -> bool:
    """Decide whether some recursively compatible program correspondence exists.

    Memoized subtree comparison checks every required child has a compatible
    partner. Reuse mode decides existence without enumerating all mappings;
    code_mappings exposes those mappings when needed. Strict mode additionally
    enforces a global physical-origin bijection. Each input is sectioned once.

    Each program origin is analyzed with properties() at most once per input.
    properties_compatible decides whether each structurally possible program
    pair remains eligible. Cyclic copy/return relationships raise ValueError, as
    their unfolding has infinite depth. trace receives structured records for
    property checks, program pairs and the overall decision.
    ignore_constructor_args=True excludes the initial constructor's complete
    trailing argument area, including every program in it and its descendants,
    from structural comparison.
    """
    answer = _comparison(runtime1, runtime2, allow_reuse,
                         ignore_constructor_args, trace).exists()
    _emitter(trace)('overall_result', compatible=answer)
    return answer
