"""Public analysis results; all offsets are byte offsets and ends are exclusive."""
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, fields, is_dataclass


def _json_value(value):
    """Recursively convert result dataclasses and byte values to JSON-ready data."""
    if isinstance(value, bytes):
        return value.hex()
    if is_dataclass(value):
        return {field.name: _json_value(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, dict):
        return {(key.hex() if isinstance(key, bytes) else str(key)): _json_value(item)
                for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    return value


class JsonResult:
    def to_dict(self) -> dict:
        """JSON-ready copy: bytes and byte dictionary keys become bare hex strings."""
        return _json_value(self)


@dataclass(eq=False)
class SelectorAnalysis(JsonResult, Sequence):
    """Discovered selectors and whether discovery completed within its scope."""
    selectors: list[bytes]
    complete: bool
    issues: list[dict]
    scope: str = 'selector_discovery; calldata_length>=4; stop_at_selected_entry'

    def __getitem__(self, index):
        return self.selectors[index]

    def __len__(self) -> int:
        return len(self.selectors)

    def __eq__(self, other) -> bool:
        if isinstance(other, SelectorAnalysis):
            return vars(self) == vars(other)
        if isinstance(other, Sequence):
            return self.selectors == list(other)
        return NotImplemented


@dataclass(eq=False)
class PropertyAnalysis(JsonResult, Mapping):
    """Semantic function and non-selector-route observations.

    The object behaves as a mapping of selector bytes to function summaries.
    complete covers function discovery and body exploration; dispatch_complete
    covers the search for selectors and function entries. issues explains
    incomplete analysis without retaining path-level diagnostic evidence.
    """
    properties: dict[bytes, dict]
    routes: list[dict]
    complete: bool
    dispatch_complete: bool
    issues: list[dict]
    scope: str = 'function_properties; all_call_values; bounded_dispatch_and_bodies'

    def __getitem__(self, selector: bytes) -> dict:
        return self.properties[selector]

    def __iter__(self) -> Iterator[bytes]:
        return iter(self.properties)

    def __len__(self) -> int:
        return len(self.properties)

    def __eq__(self, other) -> bool:
        if isinstance(other, PropertyAnalysis):
            return vars(self) == vars(other)
        if isinstance(other, Mapping):
            return self.properties == dict(other)
        return NotImplemented


@dataclass(frozen=True)
class Fragment:
    """Map input bytes [start, end) to bytes beginning at offset within a program."""
    start: int
    end: int
    offset: int


@dataclass(frozen=True)
class Program:
    """A detected program's original bytes and their positions in the input.

    origin is the input offset corresponding to program counter zero. image
    contains the program's code, data and metadata; code_ranges marks recognized
    instructions using input offsets. fragments maps input ranges into image.
    evidence describes how the program was found, parent identifies the program
    that copied or returned it, and entry_accepted records its entry classification.
    """
    origin: int
    image: bytes
    fragments: tuple[Fragment, ...]
    evidence: str
    parent: int | None
    entry_accepted: bool
    code_ranges: tuple[tuple[int, int], ...]


@dataclass
class SectionAnalysis(JsonResult):
    """Classified byte ranges, detected programs and explanations of code-region decisions."""
    sections: list[dict]
    programs: list[Program]
    diagnostics: list[dict]
    scope: str = 'structural_discovery; both_conditional_branches; not_entry_validation'
