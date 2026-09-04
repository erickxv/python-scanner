import ast
from dataclasses import dataclass, field

from scanner.frontend.parser import ParsedModule, call_qualified_name
from scanner.model.finding import Confidence, Finding, Severity, TraceStep
from scanner.rules.sanitizers import SANITIZERS
from scanner.rules.sinks import SINK_BY_NAME, SinkPattern
from scanner.rules.sources import SOURCE_NAMES

_SEVERITY_MAP = {
    "LOW": Severity.LOW,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
}


@dataclass
class TaintInfo:
    source_line: int
    source_symbol: str
    steps: list[TraceStep] = field(default_factory=list)


class TaintEngine:
    def analyze(self, module: ParsedModule) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._analyze_scope(module.file, module.tree.body))

        for node in ast.walk(module.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                findings.extend(self._analyze_scope(module.file, node.body))
        return _dedupe(findings)

    def _analyze_scope(self, file: str, body: list[ast.stmt]) -> list[Finding]:
        findings: list[Finding] = []
        tainted: dict[str, TaintInfo] = {}
        for stmt in body:
            findings.extend(self._visit_stmt(file, stmt, tainted))
        return findings

    def _visit_stmt(
        self, file: str, stmt: ast.stmt, tainted: dict[str, TaintInfo]
    ) -> list[Finding]:
        findings: list[Finding] = []

        if isinstance(stmt, ast.Assign):
            info = self._eval_expr(file, stmt.value, tainted, findings)
            if info is not None:
                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        tainted[target.id] = info
            else:
                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        tainted.pop(target.id, None)

        elif isinstance(stmt, ast.AugAssign):
            info = self._eval_expr(file, stmt.value, tainted, findings)
            if info is not None and isinstance(stmt.target, ast.Name):
                tainted[stmt.target.id] = info

        elif isinstance(stmt, ast.Expr):
            self._eval_expr(file, stmt.value, tainted, findings)

        elif isinstance(stmt, (ast.If, ast.While)):
            self._eval_expr(file, stmt.test, tainted, findings)
            for inner in stmt.body:
                findings.extend(self._visit_stmt(file, inner, tainted))
            for inner in stmt.orelse:
                findings.extend(self._visit_stmt(file, inner, tainted))

        elif isinstance(stmt, ast.For):
            for inner in stmt.body:
                findings.extend(self._visit_stmt(file, inner, tainted))

        elif isinstance(stmt, ast.With):
            for item in stmt.items:
                self._eval_expr(file, item.context_expr, tainted, findings)
            for inner in stmt.body:
                findings.extend(self._visit_stmt(file, inner, tainted))

        elif isinstance(stmt, ast.Return) and stmt.value is not None:
            self._eval_expr(file, stmt.value, tainted, findings)

        return findings

    def _eval_expr(
        self,
        file: str,
        node: ast.expr,
        tainted: dict[str, TaintInfo],
        findings: list[Finding],
    ) -> TaintInfo | None:

        if isinstance(node, ast.Name):
            return tainted.get(node.id)

        if isinstance(node, ast.Constant):
            return None

        if isinstance(node, ast.JoinedStr):
            combined: TaintInfo | None = None
            for value in node.values:
                info = self._eval_expr(file, value, tainted, findings)
                combined = _merge(combined, info)
            return combined

        if isinstance(node, ast.FormattedValue):
            return self._eval_expr(file, node.value, tainted, findings)

        if isinstance(node, ast.BinOp):
            left = self._eval_expr(file, node.left, tainted, findings)
            right = self._eval_expr(file, node.right, tainted, findings)
            return _merge(left, right)

        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            combined = None
            for elt in node.elts:
                info = self._eval_expr(file, elt, tainted, findings)
                combined = _merge(combined, info)
            return combined

        if isinstance(node, ast.Call):
            return self._eval_call(file, node, tainted, findings)

        combined = None
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                info = self._eval_expr(file, child, tainted, findings)
                combined = _merge(combined, info)
        return combined

    def _eval_call(
        self,
        file: str,
        node: ast.Call,
        tainted: dict[str, TaintInfo],
        findings: list[Finding],
    ) -> TaintInfo | None:
        name = call_qualified_name(node)

        arg_infos: list[TaintInfo | None] = [
            self._eval_expr(file, arg, tainted, findings) for arg in node.args
        ]
        for kw in node.keywords:
            if kw.value is not None:
                self._eval_expr(file, kw.value, tainted, findings)

        sink = SINK_BY_NAME.get(name) if name else None
        if sink is not None:
            self._check_sink(file, node, sink, arg_infos, findings)

        if name in SANITIZERS:
            return None

        if name in SOURCE_NAMES:
            step = TraceStep(
                kind="source",
                description=f"Untrusted data obtained via {name}()",
                line=node.lineno,
                symbol=name,
            )
            return TaintInfo(source_line=node.lineno, source_symbol=name, steps=[step])

        combined: TaintInfo | None = None
        for info in arg_infos:
            combined = _merge(combined, info)
        return combined

    def _check_sink(
        self,
        file: str,
        node: ast.Call,
        sink: SinkPattern,
        arg_infos: list[TaintInfo | None],
        findings: list[Finding],
    ) -> None:
        indexes = sink.tainted_arg_indexes
        candidates = (
            range(len(arg_infos)) if indexes is None else [i for i in indexes if i < len(arg_infos)]
        )
        for i in candidates:
            info = arg_infos[i]
            if info is None:
                continue
            trace = list(info.steps)
            trace.append(
                TraceStep(
                    kind="sink",
                    description=f"Untrusted data reaches {sink.title} in {sink.call_name}()",
                    line=node.lineno,
                    symbol=sink.call_name,
                )
            )
            findings.append(
                Finding(
                    rule_id=sink.rule_id,
                    title=sink.title,
                    description=sink.description,
                    severity=_SEVERITY_MAP[sink.severity],
                    confidence=Confidence.MEDIUM,
                    cwe=sink.cwe,
                    owasp=sink.owasp,
                    file=file,
                    sink_line=node.lineno,
                    sink_symbol=sink.call_name,
                    source_line=info.source_line,
                    source_symbol=info.source_symbol,
                    trace=trace,
                )
            )
            break


def _merge(a: TaintInfo | None, b: TaintInfo | None) -> TaintInfo | None:
    if a is None:
        return b
    if b is None:
        return a
    return TaintInfo(
        source_line=a.source_line,
        source_symbol=a.source_symbol,
        steps=a.steps + [s for s in b.steps if s not in a.steps],
    )


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: dict[str, Finding] = {}
    for f in findings:
        seen.setdefault(f.fingerprint(), f)
    return sorted(seen.values(), key=lambda f: (f.file, f.sink_line, f.rule_id))
