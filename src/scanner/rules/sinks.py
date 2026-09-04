from dataclasses import dataclass


@dataclass(frozen=True)
class SinkPattern:
    call_name: str
    rule_id: str
    title: str
    description: str
    cwe: str
    owasp: str
    severity: str
    tainted_arg_indexes: tuple[int, ...] | None = None


SINKS: list[SinkPattern] = [
    SinkPattern(
        call_name="cursor.execute",
        rule_id="PY-SQL-001",
        title="Possible SQL Injection",
        description="Untrusted data is used to construct an SQL query through string concatenation or f-strings, without using bound parameters (placeholders).",
        cwe="CWE-89",
        owasp="A05:2025 Injection",
        severity="HIGH",
        tainted_arg_indexes=(0,),
    )
]

SINK_BY_NAME: dict[str, SinkPattern] = {s.call_name: s for s in SINKS}
