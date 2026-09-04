from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Confidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass(frozen=True)
class TraceStep:
    kind: str
    description: str
    line: int
    symbol: str | None = None


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    cwe: str
    owasp: str
    file: str
    sink_line: int
    sink_symbol: str
    source_line: int
    source_symbol: str
    trace: list[TraceStep] = field(default_factory=list)

    def fingerprint(self) -> str:
        return f"{self.rule_id}|{self.file}|{self.sink_line}|{self.source_line}"

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "file": self.file,
            "sink_line": self.sink_line,
            "sink_symbol": self.sink_symbol,
            "source_line": self.source_line,
            "source_symbol": self.source_symbol,
            "trace": [
                {"kind": t.kind, "description": t.description, "line": t.line, "symbol": t.symbol}
                for t in self.trace
            ],
        }
