"""Feasibility memo lifetimes and idempotent predicate recording."""
import unittest
from unittest.mock import patch

from ethutils._engine import symbolic as e


class FeasibilityTests(unittest.TestCase):
    def test_shared_subexpression_is_evaluated_once_per_check(self):
        shared = e.Expr(e.ADD, (e.VALUE, 7))
        state = e.State(predicates=((e.Expr(e.LT, (shared, 30)), True),
                                    (e.Expr(e.GT, (shared, 2)), True)))
        with patch.object(e, 'simplify', wraps=e.simplify) as simplify:
            self.assertTrue(e.feasible(state))
        additions = [call for call in simplify.call_args_list if call.args[0] == e.ADD]
        self.assertEqual(len(additions), 1)

    def test_fact_checks_share_a_memo_without_assuming_their_own_answers(self):
        shared = e.Expr(e.ADD, (e.VALUE, 7))
        left, right = e.Expr(e.LT, (shared, 30)), e.Expr(e.GT, (shared, 2))
        state = e.State(facts={left: 1, right: 1})
        with patch.object(e, 'simplify', wraps=e.simplify) as simplify:
            self.assertTrue(e.feasible(state))
        self.assertEqual(sum(call.args[0] == e.ADD for call in simplify.call_args_list), 1)
        state.ranges[e.VALUE] = e.Interval(40, 40)
        self.assertFalse(e.feasible(state))

    def test_fact_and_predicate_evaluations_use_separate_memos(self):
        # Unknown storage cannot refute this fact, but the predicate must use it.
        storage = e.Expr(e.SLOAD, (0,))
        shared = e.Expr(e.ADD, (storage, 1))
        state = e.State(facts={storage: 5, shared: 6}, predicates=((shared, False),))
        self.assertFalse(e.feasible(state))

    def test_memos_do_not_survive_state_changes_or_forks(self):
        condition = e.Expr(e.LT, (e.VALUE, 10))
        state = e.State(predicates=((condition, True),))
        self.assertTrue(e.feasible(state))
        child = state.fork()
        child.ranges[e.VALUE] = e.Interval(20, 20)
        self.assertFalse(e.feasible(child))
        self.assertTrue(e.feasible(state))
        state.ranges[e.VALUE] = e.Interval(30, 30)
        self.assertFalse(e.feasible(state))

    def test_equal_predicates_are_not_duplicated_and_opposites_still_reject(self):
        condition = e.Expr(e.LT, (e.Expr(e.SLOAD, (0,)), 10))
        state = e.State()
        self.assertTrue(e.assume(state, condition, True))
        self.assertTrue(e.assume(state, e.Expr(condition.op, condition.args), True))
        self.assertEqual(state.predicates, ((condition, True),))
        self.assertFalse(e.assume(state, condition, False))

    def test_duplicate_assumption_still_refines_changed_ranges(self):
        state = e.State()
        condition = e.Expr(e.LT, (e.VALUE, 10))
        self.assertTrue(e.assume(state, condition, True))
        state.ranges[e.VALUE] = e.Interval()
        self.assertTrue(e.assume(state, condition, True))
        self.assertEqual(state.ranges[e.VALUE].hi, 9)
        self.assertEqual(len(state.predicates), 1)
        state.ranges[e.VALUE] = e.Interval(20, 20)
        self.assertFalse(e.assume(state, condition, True))

    def test_recursive_assumptions_do_not_duplicate_derived_predicates(self):
        condition = e.Expr(e.ISZERO, (e.Expr(e.SLOAD, (0,)),))
        state = e.State()
        self.assertTrue(e.assume(state, condition, True))
        before = state.predicates
        self.assertTrue(e.assume(state, condition, True))
        self.assertEqual(state.predicates, before)


if __name__ == '__main__':
    unittest.main()
