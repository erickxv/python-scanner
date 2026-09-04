from scanner.model.finding import Finding


def print_findings(findings: list[Finding]) -> None:
    if not findings:
        print("No vulnerabilities found.")
        return

    for f in findings:
        print(f"{f.severity.value} {f.title} ({f.rule_id})")
        print(f"File: {f.file}:{f.sink_line}")
        print(f"CWE: {f.cwe}  OWASP: {f.owasp}  Confidence: {f.confidence.value}")
        print(f"{f.description}")
        print("Trace:")
        for step in f.trace:
            print(f"- [{step.kind}] line {step.line}: {step.description}")
        print()

    print(f"Total: {len(findings)} found.")
