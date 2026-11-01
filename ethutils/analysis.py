"""Find function selectors and summarize function behavior in EVM runtime bytecode.

A selector is the first four bytes of call data, used to choose a function.
The dispatcher is the code that makes this choice. Analysis follows possible
execution paths while tracking input conditions, storage reads and effects.

Selector discovery ends at function entries or operations treated as function
work: storage writes, argument use, storage calculations and storage-derived
addresses. Length calculations also end discovery after a selector-dependent
branch. Direct length comparisons and fixed storage-field checks remain part
of the search. These boundaries define the scope reported as complete.

Function bodies are explored with separate limits for each selector and entry.
Boolean properties use True for established behavior, False for a demonstrated
counterexample, and None for unresolved behavior. Read and effect summaries
include instructions encountered on rejecting paths. CALLVALUE is treated as
a call input; storage and environmental information count as state reads.

CODESIZE is one shared symbolic value for each program analysis. CODECOPY keeps
copies lazy when their size is symbolic or their source extends beyond the known
image. Such copies may flow to a terminating operation, while reading their
unknown bytes ends that path as incomplete. Once a symbolic copy makes the
memory extent unknown, every subsequent MSIZE read produces a fresh unknown word.

Results retain discoveries made before a limit is reached. A trace callback can
receive entry offsets, path outcomes, value guards, statistics and configured limits.
"""
from collections import defaultdict
from collections.abc import Callable
from dataclasses import asdict, replace
from copy import deepcopy
from .models import SelectorAnalysis, PropertyAnalysis

from ._engine import symbolic as _engine
from ._engine.symbolic import Limits as DispatchLimits, BodyLimits

__all__ = ['selectors', 'properties', 'DispatchLimits', 'BodyLimits', 'SelectorAnalysis', 'PropertyAnalysis']


def _entries(result):
    """Copy engine entries and convert hexadecimal selector strings to bytes."""
    entries = deepcopy(result.functions)
    for entry in entries:
        entry['selector'] = bytes.fromhex(entry['selector'])
    return entries


def selectors(bytecode: bytes, *, origin: int = 0, limits: DispatchLimits | None = None,
              trace: Callable[[dict], None] | None = None) -> SelectorAnalysis:
    """Return the sorted four-byte function selectors found in runtime bytecode.

    origin selects a program beginning at that input offset and extending through
    the rest of bytecode. Program counters and reported instruction offsets are
    relative to origin. Explore calls with at least four calldata bytes, stopping
    when a function entry is selected. limits controls the search budget. The
    result contains the selectors, issues and completeness within the supported
    function-selection patterns and search limits. trace, when supplied, receives
    entries, path outcomes, value guards, statistics and configured limits.
    """
    if trace is not None and not callable(trace):
        raise TypeError('trace must be callable')
    configured = limits if limits is not None else DispatchLimits(
        trace_length=24 if trace is not None else 0)
    result = _engine.analyze(bytecode, origin=origin, limits=configured,
                             stop_at_selected_entry=True,
                             include_short_calldata_routes=False)
    values = sorted({bytes.fromhex(f['selector']) for f in result.functions})
    report = SelectorAnalysis(values, result.complete, deepcopy(result.issues))
    if trace is not None:
        trace({'kind': 'selector_diagnostics', 'entries': _entries(result),
               'routes': deepcopy(result.routes),
               'value_guards': deepcopy(result.value_guards),
               'statistics': dict(result.statistics), 'limits': asdict(configured)})
    return report


def _tri_property(outcomes, complete, successes, forbidden, *, calls_unknown=False):
    """Decide whether all explored paths satisfy a restriction on reads or effects.

    Return False for a violation on a path with a concrete input witness. Return
    True for complete exploration with successful paths and every path clear of
    forbidden observations. Otherwise return None. calls_unknown treats external
    calls as unresolved effects.
    """
    if any(o.get('witnessed') and set(o[forbidden]) - (
            {'CALL', 'CALLCODE', 'DELEGATECALL'} if calls_unknown else set())
           for o in outcomes):
        return False
    if complete and successes and not any(o[forbidden] for o in outcomes):
        return True
    return None


def _summarize_value_rejection(entries, dispatch_complete, successes):
    """Determine whether every entry rejects positive-value calls; successful calls refute rejection."""
    if any(outcome.get('witnessed_nonzero') for outcome in successes):
        return False
    rejecting_policies = {'nonzero_rejected', 'always_rejects'}
    # A rejection check may appear either before or inside the function body.
    if dispatch_complete and all(
            entry['value_policy'] in rejecting_policies or (
                entry['body_analysis']['complete'] and
                _engine.Interpreter.value_policy(entry['body_analysis']['outcomes'])
                in rejecting_policies)
            for entry in entries):
        return True
    return None


def _summarize_getter(bodies, outcomes, complete, successes, read_only):
    """Determine whether successful calls return one storage value, including masked or shifted fields."""
    if read_only is False or any(outcome.get('witnessed') and (
            outcome['argument_reads'] or set(outcome['reads']) - {'SLOAD'} or
            (outcome['kind'] in {'return', 'stop'} and (
                not outcome['return_data'] or not outcome['return_data']['scalar_storage'])))
            for outcome in outcomes):
        return False
    if (complete and successes and read_only is True
            and all(body['scalar_getter_candidate'] for body in bodies if body['successful_paths'])
            and all(not outcome['argument_reads'] and not (set(outcome['reads']) - {'SLOAD'})
                    for outcome in outcomes)):
        return True
    return None


def _summarize_body_evidence(bodies, outcomes, successes, dispatch_complete,
                            dispatch_issues):
    """Combine completion status, reads, effects and issues for one selector's entries.

    Each body's completion status includes discovery of its entry.
    """
    analysis = {
        'scope': 'all_call_values', 'complete': all(body['complete'] for body in bodies),
        'dispatch_complete': dispatch_complete,
        'issues': [*dispatch_issues, *(issue for body in bodies for issue in body['issues'])],
        'reads': sorted({read for outcome in outcomes for read in outcome['reads']}),
        'potential_effects': sorted({effect for outcome in outcomes
                                    for effect in outcome['potential_effects']}),
        'successful_paths': len(successes),
        'statistics': {key: sum(body['statistics'][key] for body in bodies)
                       for key in ('instructions_executed', 'states_enqueued')},
    }
    if not outcomes:
        analysis['issues'].append({'reason': 'no_body_entry'})
    analysis['outcomes'] = outcomes
    return analysis


def _summarize_library_protection(entries, dispatch_complete):
    """Determine whether all known entries require delegatecall, using their library-guard results."""
    values = [entry.get('delegatecall_only') for entry in entries]
    if False in values:
        return False
    if dispatch_complete and all(value is True for value in values):
        return True
    return None


def _summarize(entries, dispatch_complete, dispatch_issues):
    """Combine the behavior of all entry points associated with one function selector."""
    bodies = [entry['body_analysis'] for entry in entries]
    outcomes = [outcome for body in bodies for outcome in body['outcomes']]
    successes = [outcome for outcome in outcomes if outcome['kind'] in {'stop', 'return'}]
    analysis = _summarize_body_evidence(bodies, outcomes, successes, dispatch_complete,
                                        dispatch_issues)
    complete = analysis['complete']
    read_only = _tri_property(outcomes, complete, successes, 'potential_effects', calls_unknown=True)
    no_reads = _tri_property(outcomes, complete, successes, 'reads')
    independent = (False if read_only is False or no_reads is False else
                   True if read_only is True and no_reads is True else None)
    sizes = {outcome['return_data']['size'] if outcome['return_data'] else 0
             for outcome in successes}
    summary = {
        'delegatecall_only': _summarize_library_protection(entries, dispatch_complete),
        'rejects_nonzero_value': _summarize_value_rejection(entries, dispatch_complete, successes),
        'read_only': read_only,
        'state_independent': independent,
        'scalar_storage_getter': _summarize_getter(bodies, outcomes, complete, successes, read_only),
        'return_size': next(iter(sizes)) if complete and len(sizes) == 1 else None,
    }
    return summary, analysis


def properties(bytecode: bytes, *, origin: int = 0, limits: DispatchLimits | None = None,
               body_limits: BodyLimits | None = None,
               trace: Callable[[dict], None] | None = None) -> PropertyAnalysis:
    """Return a behavior summary for each discovered four-byte function selector.

    The summary describes positive-value rejection, read-only behavior, dependence
    on storage or the environment, scalar storage returns, return size and library
    delegatecall protection. Boolean properties use True, False or None (unknown).
    return_size is the common successful return length, or None when unresolved.

    origin selects a program beginning at that input offset and extending through
    the rest of bytecode. Program counters and reported instruction offsets are
    relative to origin. limits controls function discovery; body_limits applies separately to each
    function entry. The result always includes function summaries, normalized
    non-selector routes, issues and completion status. trace, when supplied,
    receives structured diagnostic records containing the full entries and path
    outcomes, value guards, statistics and configured limits.
    """
    if trace is not None and not callable(trace):
        raise TypeError('trace must be callable')
    configured = limits if limits is not None else replace(DispatchLimits(), max_states=8192,
        initial_path_budget=2048, max_path_budget=2048, max_steps=200000,
        trace_length=24 if trace is not None else 0)
    configured_body = body_limits if body_limits is not None else BodyLimits()
    result = _engine.analyze(bytecode, origin=origin, limits=configured,
                             body_limits=configured_body)
    groups = defaultdict(list)
    for entry in result.functions:
        groups[bytes.fromhex(entry['selector'])].append(entry)
    summarized = {selector: _summarize(entries, result.complete, result.issues)
                  for selector, entries in sorted(groups.items())}
    values = {selector: summary for selector, (summary, _) in summarized.items()}
    body_complete = all(entry['body_analysis']['complete'] for entry in result.functions)
    issues = [*deepcopy(result.issues), *(deepcopy(issue) for entry in result.functions
                                       for issue in entry['body_analysis']['issues'])]
    routes = [{key: deepcopy(route[key]) for key in ('category', 'behavior', 'value_policy')}
              for route in result.routes]
    report = PropertyAnalysis(values, routes, result.complete and body_complete,
                              result.complete, issues)
    if trace is not None:
        for selector, (_, evidence) in summarized.items():
            trace({'kind': 'function_analysis', 'selector': selector, **deepcopy(evidence)})
        trace({'kind': 'property_diagnostics', 'entries': _entries(result),
               'routes': deepcopy(result.routes),
               'value_guards': deepcopy(result.value_guards),
               'statistics': dict(result.statistics),
               'limits': asdict(configured), 'body_limits': asdict(configured_body)})
    return report
