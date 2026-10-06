import sys
from pathlib import Path

sys.dont_write_bytecode = True

from src.scanner.analysis.taint_engine import TaintEngine
from src.scanner.frontend.parser import ParseError, parse_file
from src.scanner.model.finding import Finding
from src.scanner.report.terminal_reporter import print_findings


TARGET_FILE = Path("./tests/")

def discover_python_files(target: Path) -> list[Path]:
    if target.is_file():
        return [target] if target.suffix == ".py" else []
    return sorted(p for p in target.rglob("*.py") if p.is_file())


def scan(target: Path) -> list[Finding]:
    engine = TaintEngine()
    findings: list[Finding] = []
    for file_path in discover_python_files(target):
        try:
            module = parse_file(str(file_path))
        except ParseError as exc:
            print(f"[aviso] {exc}", file=sys.stderr)
            continue
        findings.extend(engine.analyze(module))
    return findings


def main() -> int:
    print(f"Target file: {TARGET_FILE}\n")
    findings = scan(TARGET_FILE)
    print_findings(findings)
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())