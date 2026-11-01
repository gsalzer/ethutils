"""Utilities for decoding, classifying and analyzing Ethereum Virtual Machine bytecode.

Functions and result types are imported on first access. Metadata extraction,
section classification and metadata-aware fingerprints load the cbor2 decoder.
"""
from importlib import import_module
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .analysis import selectors, properties, DispatchLimits, BodyLimits
    from .comparison import compatible, code_mappings, properties_compatible
    from .sectioning import section, analyze_sections, runtime, decompose
    from .decoding import disassemble, instruction_boundaries, Instruction, parse_hex
    from .metadata import extract_metadata, zero_metadata
    from .normalization import normalize_pushes, skeleton
    from .models import SelectorAnalysis, PropertyAnalysis, SectionAnalysis, Program, Fragment

__version__ = '0.2.0'

_EXPORTS = {
    'selectors': ('analysis', 'selectors'),
    'properties': ('analysis', 'properties'),
    'compatible': ('comparison', 'compatible'),
    'code_mappings': ('comparison', 'code_mappings'),
    'properties_compatible': ('comparison', 'properties_compatible'),
    'DispatchLimits': ('analysis', 'DispatchLimits'),
    'BodyLimits': ('analysis', 'BodyLimits'),
    'section': ('sectioning', 'section'),
    'decompose': ('sectioning', 'decompose'),
    'runtime': ('sectioning', 'runtime'),
    'analyze_sections': ('sectioning', 'analyze_sections'),
    'disassemble': ('decoding', 'disassemble'),
    'instruction_boundaries': ('decoding', 'instruction_boundaries'),
    'Instruction': ('decoding', 'Instruction'),
    'parse_hex': ('decoding', 'parse_hex'),
    'extract_metadata': ('metadata', 'extract_metadata'),
    'zero_metadata': ('metadata', 'zero_metadata'),
    'normalize_pushes': ('normalization', 'normalize_pushes'),
    'skeleton': ('normalization', 'skeleton'),
    **{name: ('models', name) for name in
       ('SelectorAnalysis', 'PropertyAnalysis', 'SectionAnalysis', 'Program', 'Fragment')},
}
__all__ = list(_EXPORTS)


def __getattr__(name):
    if name not in _EXPORTS:
        raise AttributeError(f'module {__name__!r} has no attribute {name!r}')
    module, attribute = _EXPORTS[name]
    value = getattr(import_module(f'.{module}', __name__), attribute)
    globals()[name] = value
    return value


def __dir__():
    return sorted(set(globals()) | set(__all__))
