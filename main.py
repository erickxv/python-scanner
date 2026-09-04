import sys
from pathlib import Path

from scanner.analysis.taint_engine import TaintEngine
from scanner.frontend.parser import ParseError, parse_file
from scanner.model.finding import Finding
from scanner.report.terminal_reporter import print_findings


TARGET_FILE = Path("sql_injection_01.py")


def scan(file_path: Path) -> list[Finding]:
    engine = TaintEngine()

    try:
        module = parse_file(str(file_path))
    except ParseError as exc:
        print(f"[warning] {exc}", file=sys.stderr)
        return []

    return engine.analyze(module)


def main() -> int:
    print(f"Analisando: {TARGET_FILE}\n")
    findings = scan(TARGET_FILE)
    print_findings(findings)
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())