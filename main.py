from parser import parse_file, call_qualified_name
import ast

target_file = "sql_injection_01.py"

module = parse_file(target_file)

print(f"File: {module.file}")

for node in ast.walk(module.tree):
    if isinstance(node, ast.Call):
        name = call_qualified_name(node)

        if name:
            print(f"Line {node.lineno}: {name}")