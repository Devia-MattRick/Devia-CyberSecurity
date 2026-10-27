#!/usr/bin/env python3
"""AST-Based Deterministic Safety Linter for Generated Python PoC Code.

Replaces fragile, bypassable regular expression filters (such as safetyScan in Pentest-Swarm-AI)
with a robust Abstract Syntax Tree (ast.parse) validator. Identifies unsafe subprocess launches,
host shell commands, file modifications, socket connections, and reflective execution primitives.

Compliant with Devia-CyberSecurity Tri-Tier Capa 3 Standards (Python 3.11+ stdlib, CLI --json).
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional


DISALLOWED_MODULES = {
    "subprocess": "Subprocess execution module is disallowed in safe PoCs",
    "pty": "PTY spawning module is disallowed",
    "posix": "Direct POSIX bindings are disallowed",
    "winreg": "Windows registry access is disallowed",
    "multiprocessing": "Multiprocessing primitives are restricted"
}

DISALLOWED_CALLS = {
    # System / Process execution
    "os.system": "Shell command execution via os.system",
    "os.popen": "Piped command execution via os.popen",
    "os.execv": "Process image replacement via os.execv",
    "os.execve": "Process image replacement via os.execve",
    "os.execl": "Process image replacement via os.execl",
    "os.spawn": "Process spawning via os.spawn",
    "subprocess.run": "Subprocess execution via subprocess.run",
    "subprocess.Popen": "Subprocess execution via subprocess.Popen",
    "subprocess.call": "Subprocess execution via subprocess.call",
    "subprocess.check_call": "Subprocess execution via subprocess.check_call",
    "subprocess.check_output": "Subprocess execution via subprocess.check_output",
    "pty.spawn": "Interactive shell spawning via pty.spawn",
    
    # Filesystem destruction / modification
    "os.remove": "File deletion via os.remove",
    "os.unlink": "File unlinking via os.unlink",
    "os.rmdir": "Directory removal via os.rmdir",
    "shutil.rmtree": "Recursive directory deletion via shutil.rmtree",
    "shutil.move": "Filesystem modification via shutil.move",
    
    # Dynamic code evaluation
    "eval": "Dynamic code evaluation via eval()",
    "exec": "Dynamic code execution via exec()",
    "compile": "Dynamic compilation via compile()",
    "__import__": "Dynamic reflective import via __import__()",
    
    # Raw socket egress (unscoped networking)
    "socket.socket": "Raw socket creation is restricted in PoC runner",
    "socket.create_connection": "Raw socket connection is restricted"
}

WRITE_MODES = {"w", "w+", "wb", "a", "a+", "ab", "x", "xb"}


class PoCSafetyVisitor(ast.NodeVisitor):
    def __init__(self, filename: str = "<input>"):
        self.filename = filename
        self.violations: List[Dict[str, Any]] = []

    def _get_call_name(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            base = self._get_call_name(node.value)
            if base:
                return f"{base}.{node.attr}"
            return node.attr
        return None

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            base_module = alias.name.split(".")[0]
            if base_module in DISALLOWED_MODULES:
                self.violations.append({
                    "line": node.lineno,
                    "col": node.col_offset,
                    "rule": "DISALLOWED_IMPORT",
                    "target": alias.name,
                    "message": DISALLOWED_MODULES[base_module]
                })
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            base_module = node.module.split(".")[0]
            if base_module in DISALLOWED_MODULES:
                self.violations.append({
                    "line": node.lineno,
                    "col": node.col_offset,
                    "rule": "DISALLOWED_IMPORT",
                    "target": node.module,
                    "message": DISALLOWED_MODULES[base_module]
                })
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        call_name = self._get_call_name(node.func)
        if call_name:
            # Check disallowed calls
            if call_name in DISALLOWED_CALLS:
                self.violations.append({
                    "line": node.lineno,
                    "col": node.col_offset,
                    "rule": "DISALLOWED_FUNCTION_CALL",
                    "target": call_name,
                    "message": DISALLOWED_CALLS[call_name]
                })
            # Also check matches like os.exec*
            elif call_name.startswith("os.exec") or call_name.startswith("os.spawn"):
                self.violations.append({
                    "line": node.lineno,
                    "col": node.col_offset,
                    "rule": "DISALLOWED_FUNCTION_CALL",
                    "target": call_name,
                    "message": f"Disallowed process execution: {call_name}"
                })

            # Check open() calls for write or append mode
            if call_name in {"open", "io.open"} and len(node.args) >= 2:
                mode_arg = node.args[1]
                if isinstance(mode_arg, ast.Constant) and isinstance(mode_arg.value, str):
                    mode_val = mode_arg.value.strip().lower()
                    if any(m in mode_val for m in WRITE_MODES):
                        self.violations.append({
                            "line": node.lineno,
                            "col": node.col_offset,
                            "rule": "UNSAFE_FILE_WRITE",
                            "target": call_name,
                            "message": f"File opened for writing/appending with mode '{mode_arg.value}'"
                        })

        self.generic_visit(node)


def lint_python_code(code_str: str, filename: str = "<input>") -> Dict[str, Any]:
    """Parse and lint a Python code snippet using AST."""
    try:
        tree = ast.parse(code_str, filename=filename)
    except SyntaxError as e:
        return {
            "valid": False,
            "syntaxError": {
                "line": e.lineno,
                "col": e.offset,
                "message": e.msg
            },
            "totalViolations": 1,
            "violations": [{
                "line": e.lineno or 1,
                "col": e.offset or 0,
                "rule": "PYTHON_SYNTAX_ERROR",
                "target": "parser",
                "message": f"Syntax error in Python code: {e.msg}"
            }]
        }

    visitor = PoCSafetyVisitor(filename=filename)
    visitor.visit(tree)

    is_valid = len(visitor.violations) == 0
    return {
        "valid": is_valid,
        "filename": filename,
        "totalViolations": len(visitor.violations),
        "violations": visitor.violations
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Deterministic AST-Based PoC Code Safety Linter")
    parser.add_argument("target", nargs="?", help="Path to Python script or '-' for stdin")
    parser.add_argument("--code", help="Inline Python code snippet to check")
    parser.add_argument("--json", action="store_true", help="Output results strictly as JSON")
    args = parser.parse_args()

    if args.code:
        content = args.code
        source_name = "<inline_code>"
    elif args.target == "-" or (not args.target and not sys.stdin.isatty()):
        content = sys.stdin.read()
        source_name = "<stdin>"
    elif args.target:
        p = Path(args.target)
        if not p.is_file():
            print(f"Error: file not found: {args.target}", file=sys.stderr)
            return 2
        content = p.read_text(encoding="utf-8")
        source_name = str(p)
    else:
        parser.print_help(sys.stderr)
        return 2

    report = lint_python_code(content, filename=source_name)

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        if report["valid"]:
            print(f"✓ PASSED: '{source_name}' contains no prohibited execution or modification primitives.")
        else:
            print(f"✗ FAILED: '{source_name}' has {report['totalViolations']} security violation(s):")
            for v in report["violations"]:
                print(f"  - Line {v['line']}:{v['col']} [{v['rule']}] {v['message']}")

    return 0 if report["valid"] else 1


if __name__ == "__main__":
    sys.exit(main())
