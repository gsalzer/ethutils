"""Recursive subtree matching and locally minimal child correspondences."""
from collections import Counter
from itertools import combinations, permutations
import random
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import cbor2
import ethutils as evm
from ethutils import comparison as c, opcodes as op
from ethutils.sectioning import ProgramRange, ReturnEvidence
from tests.helpers import hex_fixture
from tests.test_runtime import creation, conditional_creation


def graph(nodes, data=(), returned=()):
    edges = {pair: c._DATA for pair in data}
    edges.update({pair: c._RETURNED for pair in returned})
    return c._Graph(tuple(nodes), edges)


def minimal_cover(left, right, pairs):
    """Independent cover definition: each edge has an endpoint covered only once."""
    a, b = Counter(x for x, _ in pairs), Counter(y for _, y in pairs)
    return set(a) == set(left) and set(b) == set(right) and all(
        a[x] == 1 or b[y] == 1 for x, y in pairs)


def valid_tree_mapping(first, second, mapping, allowed):
    """Check parent correspondence, coverage and local minimality directly."""
    if (0, 0) not in mapping or not mapping <= allowed:
        return False
    if {a for a, _ in mapping} != set(first.origins) or {b for _, b in mapping} != set(second.origins):
        return False
    parents1 = {child: (parent, kind) for (parent, child), kind in first.edges.items()}
    parents2 = {child: (parent, kind) for (parent, child), kind in second.edges.items()}
    for a, b in mapping:
        if (a == 0) != (b == 0):
            return False
        if a:
            pa, ka = parents1[a]
            pb, kb = parents2[b]
            if ka != kb or (pa, pb) not in mapping:
                return False
        left = {child for parent, child in first.edges if parent == a}
        right = {child for parent, child in second.edges if parent == b}
        selected = {(x, y) for x, y in mapping if x in left and y in right}
        if not minimal_cover(left, right, selected):
            return False
    return True


class GraphTests(unittest.TestCase):
    def scan(self, sections, copies=(), returned=()):
        analyzer = SimpleNamespace(run=Mock(return_value=sections),
            copied_regions={ProgramRange(*r) for r in copies},
            returned_copies={ReturnEvidence(*r, 0, 0) for r in returned})
        return patch.object(c.sectioning, 'Analyzer', return_value=analyzer)

    def test_code_ranges_share_one_origin_and_return_specializes_data(self):
        sections = [dict(kind='code', origin=0, start=0, end=10),
                    dict(kind='code', origin=0, start=20, end=30),
                    dict(kind='code', origin=100, start=100, end=130),
                    dict(kind='code', origin=100, start=150, end=180),
                    dict(kind='meta', start=180, end=200)]
        with self.scan(sections, [(0, 40, 50), (0, 100, 200)], [(0, 100, 200)]):
            result = c._graph(bytes(200))
        self.assertEqual(result.origins, (0, 100))
        self.assertEqual(result.edges, {(0, 100): c._RETURNED})

    def test_immediate_edges_omit_transitive_containment(self):
        sections = [dict(kind='code', origin=o, start=o, end=o+5) for o in (0, 20, 40)]
        with self.scan(sections, [(0, 20, 50), (20, 40, 50)], [(20, 40, 50)]):
            result = c._graph(bytes(50))
        self.assertEqual(result.edges, {(0, 20): c._DATA, (20, 40): c._RETURNED})

    def test_all_users_of_a_shared_program_are_retained(self):
        sections = [dict(kind='code', origin=o, start=o, end=o+5) for o in (0, 20, 100)]
        with self.scan(sections, [(0, 20, 30), (0, 100, 110), (20, 100, 110)]):
            result = c._graph(bytes(110))
        self.assertEqual(result.edges, {(0, 20): c._DATA, (0, 100): c._DATA, (20, 100): c._DATA})

    def test_partial_program_copy_is_not_a_whole_program_edge(self):
        sections = [dict(kind='code', origin=0, start=0, end=10),
                    dict(kind='code', origin=100, start=100, end=110),
                    dict(kind='code', origin=100, start=130, end=140)]
        with self.scan(sections, [(0, 100, 120)]):
            self.assertEqual(c._graph(bytes(140)).edges, {})

    def test_program_images_are_bounded_and_exclude_constructor_argument_tail(self):
        sections = [dict(kind='code', origin=0, start=0, end=5),
                    dict(kind='code', origin=20, start=20, end=25),
                    dict(kind='data', origin=0, start=30, end=40,
                         role='constructor_arguments_candidate')]
        with self.scan(sections, [(0, 20, 30)]):
            result = c._graph(bytes(range(40)))
        self.assertEqual(result.images[0], bytes(range(30)))
        self.assertEqual(result.images[20], bytes(range(20, 40)))

    def test_ignoring_constructor_args_removes_every_program_in_tail(self):
        sections = [dict(kind='code', origin=0, start=0, end=5),
                    dict(kind='code', origin=20, start=20, end=25),
                    dict(kind='data', origin=0, start=30, end=40,
                         role='constructor_arguments_candidate'),
                    dict(kind='code', origin=35, start=35, end=40)]
        with self.scan(sections, [(0, 20, 30), (0, 35, 40)], [(0, 20, 30)]):
            result = c._graph(bytes(range(40)), ignore_constructor_args=True)
        self.assertEqual(result.origins, (0, 20))
        self.assertEqual(result.edges, {(0, 20): c._RETURNED})
        self.assertEqual(result.images[0], bytes(range(30)))

    def test_cycles_are_reported_instead_of_recursing(self):
        for g in (graph((0,), data=[(0, 0)]), graph((0, 1), data=[(0, 1), (1, 0)])):
            with self.assertRaisesRegex(ValueError, 'acyclic'):
                c._Comparison(g, g, True)


class CoverTests(unittest.TestCase):
    def test_two_children_give_only_the_two_bijections(self):
        edges = {(a, b) for a in (1, 2) for b in (10, 20)}
        found = list(c._minimal_covers((1, 2), (10, 20), edges))
        self.assertEqual(found, [((1, 10), (2, 20)), ((1, 20), (2, 10))])

    def test_both_star_directions(self):
        self.assertEqual(list(c._minimal_covers((1,), (10, 20), {(1, 10), (1, 20)})),
                         [((1, 10), (1, 20))])
        self.assertEqual(list(c._minimal_covers((1, 2), (10,), {(1, 10), (2, 10)})),
                         [((1, 10), (2, 10))])

    def test_opposite_collapses_can_occur_in_separate_sibling_groups(self):
        edges = {(1, 10), (2, 10), (3, 20), (3, 30)}
        self.assertEqual(list(c._minimal_covers((1, 2, 3), (10, 20, 30), edges)), [tuple(sorted(edges))])
        self.assertFalse(c._perfect_matching_exists((1, 2, 3), (10, 20, 30), edges))

    def test_complete_three_by_three_has_fifteen_minimal_covers(self):
        edges = {(a, b) for a in (1, 2, 3) for b in (10, 20, 30)}
        found = list(c._minimal_covers((1, 2, 3), (10, 20, 30), edges))
        self.assertEqual(len(found), 15)
        self.assertEqual(len(set(found)), 15)
        self.assertEqual(Counter(map(len, found)), {3: 6, 4: 9})

    def test_covers_agree_with_exhaustive_edge_subsets_for_all_two_by_three_graphs(self):
        left, right = (1, 2), (10, 20, 30)
        universe = tuple((a, b) for a in left for b in right)
        for count in range(len(universe)+1):
            for chosen in combinations(universe, count):
                edges = set(chosen)
                expected = {tuple(sorted(subset)) for n in range(len(chosen)+1)
                            for subset in combinations(chosen, n) if minimal_cover(left, right, subset)}
                actual = list(c._minimal_covers(left, right, edges))
                self.assertEqual(set(actual), expected)
                self.assertEqual(len(actual), len(set(actual)))

    def test_empty_sides_and_isolated_vertices(self):
        self.assertEqual(list(c._minimal_covers((), (), set())), [()])
        self.assertEqual(list(c._minimal_covers((1,), (), set())), [])
        self.assertEqual(list(c._minimal_covers((1, 2), (10,), {(1, 10)})), [])


class SubtreeTests(unittest.TestCase):
    def test_users_example_allows_opposite_collapses_at_different_depths(self):
        first = graph((0, 2, 3, 4, 5, 6), data=[(0, 2), (0, 3), (2, 4), (3, 5), (3, 6)])
        second = graph((0, 20, 30, 40), data=[(0, 20), (20, 30), (20, 40)])
        comparison = c._Comparison(first, second, True)
        expected = ((0, 0), (2, 20), (3, 20), (4, 30), (4, 40), (5, 30), (6, 40))
        found = list(comparison.mappings())
        self.assertTrue(comparison.exists())
        self.assertIn(expected, found)
        self.assertEqual(len(found), 2)
        self.assertFalse(c._Comparison(first, second, False).exists())

    def test_old_three_pair_overlap_is_excluded(self):
        first = graph((0, 1, 2), data=[(0, 1), (0, 2)])
        second = graph((0, 10, 20), data=[(0, 10), (0, 20)])
        self.assertEqual(list(c._Comparison(first, second, True).mappings()),
            [((0, 0), (1, 10), (2, 20)), ((0, 0), (1, 20), (2, 10))])

    def test_returned_and_ordinary_data_children_are_distinct(self):
        first, second = graph((0, 1), data=[(0, 1)]), graph((0, 10), returned=[(0, 10)])
        check = Mock(return_value=True)
        self.assertFalse(c._Comparison(first, second, True, check).exists())
        check.assert_not_called()

    def test_whole_subtrees_must_match(self):
        first = graph((0, 1, 2, 3), data=[(0, 1), (0, 2)], returned=[(1, 3)])
        second = graph((0, 10, 20), data=[(0, 10)], returned=[(10, 20)])
        self.assertFalse(c._Comparison(first, second, True).exists())

    def test_reuse_feasibility_does_not_enumerate_witnesses(self):
        first = graph((0, 1, 2, 3), data=[(0, 1), (0, 2), (0, 3)])
        second = graph((0, 10, 20, 30), data=[(0, 10), (0, 20), (0, 30)])
        allowed = {(0, 0), (1, 10), (2, 10), (3, 20), (3, 30)}
        comparison = c._Comparison(first, second, True, lambda a, b: (a, b) in allowed)
        with patch.object(c, '_minimal_covers', side_effect=AssertionError('enumeration')):
            self.assertTrue(comparison.exists())
        self.assertFalse(c._Comparison(first, second, False, lambda a, b: (a, b) in allowed).exists())

    def test_shared_images_are_compared_in_each_parent_context(self):
        shared = graph((0, 1, 2, 3), data=[(0, 1), (0, 2)], returned=[(1, 3), (2, 3)])
        copies = graph((0, 10, 20, 30, 40), data=[(0, 10), (0, 20)], returned=[(10, 30), (20, 40)])
        comparison = c._Comparison(shared, copies, True)
        self.assertTrue(comparison.exists())
        self.assertTrue(list(comparison.mappings()))
        self.assertFalse(c._Comparison(shared, copies, False).exists())

    def test_shared_subtree_pair_is_checked_once_across_parent_contexts_and_enumeration(self):
        first = graph((0, 1, 2, 3), data=[(0, 1), (0, 2)], returned=[(1, 3), (2, 3)])
        second = graph((0, 10, 20, 30), data=[(0, 10), (0, 20)], returned=[(10, 30), (20, 30)])
        checker = Mock(return_value=True)
        comparison = c._Comparison(first, second, True, checker)
        self.assertTrue(comparison.exists())
        calls = list(checker.call_args_list)
        self.assertEqual(sum(call.args == (3, 30) for call in calls), 1)
        self.assertEqual(len(calls), len({call.args for call in calls}))
        self.assertEqual(len(list(comparison.mappings())), 2)
        self.assertTrue({call.args for call in calls}
                        <= {call.args for call in checker.call_args_list})
        self.assertEqual(sum(call.args == (3, 30) for call in checker.call_args_list), 1)
        self.assertEqual(len(checker.call_args_list),
                         len({call.args for call in checker.call_args_list}))

    def test_global_bijection_is_preserved_when_shared_graphs_have_equal_node_counts(self):
        first = graph((0, 1, 2, 3, 4), data=[(0, 1), (0, 2)],
                      returned=[(1, 3), (1, 4), (2, 3), (2, 4)])
        second = graph((0, 10, 20, 30, 40), data=[(0, 10), (0, 20)],
                       returned=[(10, 30), (10, 40), (20, 30), (20, 40)])
        found = list(c._Comparison(first, second, False).mappings())
        self.assertEqual(len(found), 4)
        self.assertTrue(all(c._bijective(frozenset(m)) for m in found))

    def test_subtree_enumeration_agrees_with_exhaustive_relations_on_small_trees(self):
        rng = random.Random(649)
        for _ in range(70):
            n = rng.randrange(1, 5)
            edges = {(rng.randrange(child), child): rng.choice((c._DATA, c._RETURNED)) for child in range(1, n)}
            first = c._Graph(tuple(range(n)), edges)
            order = [0] + rng.sample(list(range(1, n)), n-1)
            second = c._Graph(tuple(range(n)), {(order[a], order[b]): kind for (a, b), kind in edges.items()})
            optional = [(a, b) for a in range(1, n) for b in range(1, n)]
            allowed = {(0, 0)} | {pair for pair in optional if rng.randrange(4)}
            expected = set()
            for size in range(len(optional)+1):
                for extra in combinations(optional, size):
                    relation = {(0, 0), *extra}
                    if valid_tree_mapping(first, second, relation, allowed):
                        expected.add(tuple(sorted(relation)))
            comparison = c._Comparison(first, second, True, lambda a, b: (a, b) in allowed)
            found = list(comparison.mappings())
            self.assertEqual(set(found), expected)
            self.assertEqual(len(found), len(set(found)))
            self.assertEqual(comparison.exists(), bool(expected))

    def test_strict_tree_matching_agrees_with_exhaustive_permutations(self):
        rng = random.Random(777)
        for _ in range(70):
            n = rng.randrange(1, 6)
            edges = {(rng.randrange(child), child): rng.choice((c._DATA, c._RETURNED)) for child in range(1, n)}
            first = c._Graph(tuple(range(n)), edges)
            order = [0] + rng.sample(list(range(1, n)), n-1)
            second = c._Graph(tuple(range(n)), {(order[a], order[b]): kind for (a, b), kind in edges.items()})
            expected = set()
            for tail in permutations(range(1, n)):
                mapping = ((0, 0), *zip(range(1, n), tail))
                if all(first.edges.get((a, x)) == second.edges.get((b, y)) for a, b in mapping for x, y in mapping):
                    expected.add(mapping)
            self.assertEqual(set(c._Comparison(first, second, False).mappings()), expected)

    def test_detached_programs_remain_accounted_for(self):
        first, second = graph((0, 1)), graph((0, 10))
        self.assertEqual(list(c._Comparison(first, second, True).mappings()), [((0, 0), (1, 10))])
        self.assertFalse(c._Comparison(first, graph((0,)), True).exists())


class CompatibleTests(unittest.TestCase):
    def test_nested_creation_contract_compatibility(self):
        source = hex_fixture('0xa39394d3447c1dbd386b92b4d1fcc22ca85eae67-src.hex')
        deployed = hex_fixture('0xa39394d3447c1dbd386b92b4d1fcc22ca85eae67.hex')
        events = []
        self.assertTrue(c.compatible(deployed, deployed, trace=events.append))
        self.assertEqual([(event['origin1'], event['origin2']) for event in events
                          if event['kind'] == 'program_pair'],
                         [(0, 0), (724, 724), (1421, 1421),
                          (3765, 3765), (4462, 4462), (6806, 6806)])
        self.assertFalse(c.compatible(deployed, source))

    def test_public_exports_and_one_sectioning_pass_per_input(self):
        code = creation(op.STOP)
        self.assertIs(evm.compatible, c.compatible)
        self.assertIs(evm.code_mappings, c.code_mappings)
        self.assertIs(evm.properties_compatible, c.properties_compatible)
        with patch.object(c.sectioning, 'Analyzer', wraps=c.sectioning.Analyzer) as scan:
            self.assertTrue(c.compatible(code, code))
        self.assertEqual(scan.call_count, 2)

    def test_alternative_child_pairs_are_checked_and_filter_the_iterator(self):
        first = graph((0, 1, 2), data=[(0, 1), (0, 2)])
        second = graph((0, 10, 20), data=[(0, 10), (0, 20)])
        first.images = {0: b'L0', 1: b'L1', 2: b'L2'}
        second.images = {0: b'R0', 10: b'R10', 20: b'R20'}
        calls = []
        def analyze(bytecode):
            return bytecode
        def check(first_properties, second_properties, **_context):
            x = int(first_properties[1:])
            y = int(second_properties[1:])
            calls.append((x, y))
            return (x, y) in {(0, 0), (1, 20), (2, 10)}
        left, right = b'left', b'right'
        with (patch.object(c, '_graph', side_effect=[first, second]),
              patch.object(c.analysis, 'properties', side_effect=analyze),
              patch.object(c, 'properties_compatible', side_effect=check)):
            found = list(c.code_mappings(left, right))
        self.assertEqual(found, [((0, 0), (1, 20), (2, 10))])
        self.assertIn((1, 10), calls)
        self.assertEqual(len(calls), len(set(calls)))

    def test_each_distinct_image_is_analyzed_once_and_each_pair_is_checked_once(self):
        first = graph((0, 1, 2), data=[(0, 1), (0, 2)])
        second = graph((0, 10, 20), data=[(0, 10), (0, 20)])
        first.images = {0: b'L0', 1: b'L1', 2: b'L2'}
        second.images = {0: b'R0', 10: b'R10', 20: b'R20'}
        analyzed = []
        checked = []

        def analyze(bytecode):
            analyzed.append(bytecode)
            return bytecode

        def check(left, right, **_context):
            checked.append((left, right))
            return True

        with (patch.object(c, '_graph', side_effect=[first, second]),
              patch.object(c.analysis, 'properties', side_effect=analyze),
              patch.object(c, 'properties_compatible', side_effect=check)):
            self.assertTrue(c.compatible(b'left', b'right'))
        self.assertEqual(analyzed, [b'L0', b'R0', b'L1', b'R10', b'L2', b'R20'])
        self.assertEqual(len(checked), len(set(checked)))

    def test_compatible_prefers_ordered_bijection_without_cross_pairs(self):
        first = graph((0, 1, 2), data=[(0, 1), (0, 2)])
        second = graph((0, 10, 20), data=[(0, 10), (0, 20)])
        checked = []
        comparison = c._Comparison(first, second, True,
                                   lambda a, b: not checked.append((a, b)))
        self.assertTrue(comparison.exists())
        self.assertEqual(checked, [(0, 0), (1, 10), (2, 20)])

    def test_identical_images_share_property_analysis_across_inputs(self):
        first, second = graph((0,)), graph((0,))
        first.images = {0: b'same image'}
        second.images = {0: b'same image'}
        report = SimpleNamespace(properties={}, routes=[])
        with (patch.object(c, '_graph', side_effect=[first, second]),
              patch.object(c.analysis, 'properties', return_value=report) as analyze):
            self.assertTrue(c.compatible(b'left', b'right'))
        analyze.assert_called_once_with(b'same image')

    def test_property_conflicts_and_unknown_values(self):
        names = ('delegatecall_only', 'rejects_nonzero_value', 'read_only',
                 'state_independent', 'scalar_storage_getter')

        def report(values):
            summary = {name: None for name in names}
            summary.update(return_size=None)
            summary.update(values)
            return SimpleNamespace(properties={b'\x12\x34\x56\x78': summary}, routes=[])

        for name in names:
            with self.subTest(property=name):
                self.assertFalse(c.properties_compatible(report({name: True}),
                                                          report({name: False})))
                self.assertTrue(c.properties_compatible(report({name: None}),
                                                         report({name: False})))
        self.assertFalse(c.properties_compatible(report({'return_size': 32}),
                                                  report({'return_size': 64})))
        self.assertTrue(c.properties_compatible(report({'return_size': None}),
                                                 report({'return_size': 64})))

    def test_selector_and_non_selector_route_conflicts(self):
        empty = SimpleNamespace(properties={}, routes=[])
        selected = SimpleNamespace(properties={b'\x12\x34\x56\x78': {}}, routes=[])
        self.assertFalse(c.properties_compatible(empty, selected))

        def report(behavior, value_policy):
            route = {'category': 'unmatched', 'behavior': behavior,
                     'value_policy': value_policy}
            return SimpleNamespace(properties={}, routes=[route])

        self.assertFalse(c.properties_compatible(report('rejects', 'always_rejects'),
                                                  report('reaches_code', 'nonzero_rejected')))
        self.assertFalse(c.properties_compatible(report('reaches_code', 'nonzero_rejected'),
                                                  report('reaches_code', 'no_value_guard_observed')))
        self.assertTrue(c.properties_compatible(report('unknown', 'unknown'),
                                                 report('reaches_code', 'no_value_guard_observed')))

    def test_trace_records_boolean_decisions(self):
        events = []
        first = SimpleNamespace(properties={}, routes=[])
        second = SimpleNamespace(properties={b'\x12\x34\x56\x78': {}}, routes=[])
        self.assertIs(c.properties_compatible(first, second, trace=events.append,
                                              origin1=3, origin2=7), False)
        self.assertEqual(events, [{
            'kind': 'selector_sets', 'origin1': 3, 'origin2': 7,
            'selectors1': [], 'selectors2': ['12345678'], 'compatible': False,
        }])
        with self.assertRaises(TypeError):
            c.properties_compatible(first, first, trace=[])

        events.clear()
        self.assertFalse(c.compatible(creation(op.STOP), op.STOP, trace=events.append))
        self.assertTrue(any(event['kind'] == 'structural_pair' and
                            event['compatible'] is False for event in events))
        self.assertEqual(events[-1], {'kind': 'overall_result', 'compatible': False})

    def test_root_failure_stops_comparison(self):
        code = conditional_creation(op.STOP, op.STOP)
        with patch.object(c, 'properties_compatible', return_value=False) as checker:
            self.assertFalse(c.compatible(code, code))
        checker.assert_called_once()

    def test_structural_conflict_needs_no_code_checks(self):
        with patch.object(c.analysis, 'properties') as analyze:
            self.assertFalse(c.compatible(creation(op.STOP), op.STOP))
        analyze.assert_not_called()

    def test_actual_duplicated_and_shared_payloads(self):
        duplicated = conditional_creation(op.STOP, op.STOP)
        shared = conditional_creation(op.STOP, op.STOP, shared_source=True)
        self.assertTrue(c.compatible(duplicated, shared))
        self.assertTrue(c.compatible(shared, duplicated))
        self.assertFalse(c.compatible(duplicated, shared, allow_reuse=False))

    def test_abi_programs_are_data_children_not_detached_roots(self):
        runtime=bytes.fromhex('5f5ffd')
        init=bytes([0x60,len(runtime)])+bytes.fromhex('600c600039')
        init+=bytes([0x60,len(runtime)])+bytes.fromhex('6000f3')+runtime
        tail=(32).to_bytes(32,'big')+len(init).to_bytes(32,'big')
        tail+=init+b'\x00'*(-len(init)%32)
        prefix=bytes.fromhex(
            f'61{len(tail):04x}6100145f3960016100135f3960015ff3')
        code=prefix+op.STOP+tail
        result=c._graph(code)
        self.assertEqual(result.origins,(0,19,84,96))
        self.assertEqual(result.edges,{
            (0,19):c._RETURNED,
            (0,84):c._DATA,
            (84,96):c._RETURNED,
        })
        without_data=prefix+op.STOP
        self.assertEqual(result.images[0],without_data)
        self.assertFalse(c.compatible(code,without_data))
        ignored=c._graph(code,ignore_constructor_args=True)
        self.assertEqual((ignored.origins,ignored.edges),
                         ((0,19),{(0,19):c._RETURNED}))
        self.assertTrue(c.compatible(
            code,without_data,ignore_constructor_args=True))
        self.assertEqual(list(c.code_mappings(
            code,without_data,ignore_constructor_args=True)),
            [((0,0),(19,19))])

    def test_code_splitting_and_metadata_do_not_change_program_count(self):
        fragmented = bytes.fromhex('6006500000005b5056')
        blob = cbor2.dumps({'solc': b'\x00\x08\x1e'})
        for code in (fragmented, op.STOP + blob + len(blob).to_bytes(2, 'big')):
            self.assertEqual(list(c.code_mappings(op.STOP, code)), [((0, 0),)])

    def test_empty_inputs_and_invalid_arguments(self):
        self.assertEqual(list(c.code_mappings(b'', b'')), [()])
        self.assertTrue(c.compatible(b'', b''))
        self.assertFalse(c.compatible(b'', op.STOP))
        for a, b in [('00', b''), (b'', '00')]:
            with self.assertRaises(TypeError): c.code_mappings(a, b)
        with self.assertRaises(TypeError): c.compatible(op.STOP, op.STOP, allow_reuse=1)
        with self.assertRaises(TypeError): c.compatible(
            op.STOP,op.STOP,ignore_constructor_args=1)
        with self.assertRaises(TypeError): c.code_mappings(
            op.STOP,op.STOP,ignore_constructor_args=1)
        with self.assertRaises(TypeError): c.compatible(op.STOP, op.STOP, trace=[])
        self.assertFalse(c._Comparison(graph((1,)), graph((2,)), True).exists())


if __name__ == '__main__':
    unittest.main()
