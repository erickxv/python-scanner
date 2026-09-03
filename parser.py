import ast
from dataclasses import dataclass


@dataclass(frozen=True)
class ParsedModule:
    file: str
    source: str
    tree: ast.Module


class ParseError(Exception):
    pass


def parse_file(path: str) -> ParsedModule:
    with open(path, "r", encoding="utf-8") as fh:
        source = fh.read()
    return parse_source(path, source)


def parse_source(file: str, source: str) -> ParsedModule:
    try:
        tree = ast.parse(source, filename=file)
    except SyntaxError as exc:
        raise ParseError(f"Syntax error in {file}: {exc}") from exc
    return ParsedModule(file=file, source=source, tree=tree)


def call_qualified_name(node: ast.Call) -> str | None:
    return _dotted_name(node.func)


def _dotted_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        if base is None:
            return None
        return f"{base}.{node.attr}"
    return None
