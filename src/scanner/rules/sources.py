from dataclasses import dataclass


@dataclass(frozen=True)
class SourcePattern:
    call_name: str
    description: str


SOURCES: list[SourcePattern] = [
    SourcePattern("input", "Direct user input via input()"),
]

SOURCE_NAMES: set[str] = {s.call_name for s in SOURCES}
