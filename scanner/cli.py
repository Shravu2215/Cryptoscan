#!/usr/bin/env python3
"""
CryptoScan CLI - real-time crypto vulnerability scanner.

Usage:
    python3 cli.py <path-to-repo-or-file> [--json out.json] [--no-color] [--ext .py,.js]

No hardcoded target repo, no predefined findings: it walks whatever path you
give it, parses each file into a real AST (Python `ast` for .py, esprima for
.js/.mjs/.cjs), runs the shared rule table against the tree, dedupes, and
reports whatever it actually finds - zero findings on a clean repo is a
correct result, not a bug.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from python_analyzer import PythonAnalyzer
from js_analyzer import JSAnalyzer
from dedup import dedup
import report

PY_EXT = {".py"}
JS_EXT = {".js", ".mjs", ".cjs", ".jsx"}
SKIP_DIRS = {"node_modules", ".git", "__pycache__", "venv", ".venv", "dist", "build"}


def iter_source_files(root, extensions):
    if os.path.isfile(root):
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            ext = os.path.splitext(fn)[1]
            if ext in extensions:
                yield os.path.join(dirpath, fn)


def scan(root, extensions=None):
    extensions = extensions or (PY_EXT | JS_EXT)
    py = PythonAnalyzer()
    js = JSAnalyzer()
    findings = []
    for path in iter_source_files(root, extensions):
        ext = os.path.splitext(path)[1]
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                source = fh.read()
        except OSError:
            continue
        if ext in PY_EXT:
            findings.extend(py.analyze(path, source))
        elif ext in JS_EXT:
            findings.extend(js.analyze(path, source))
    return dedup(findings)


def main():
    ap = argparse.ArgumentParser(description="CryptoScan - AST-based cryptographic vulnerability scanner")
    ap.add_argument("path", help="Repo directory or single source file to scan")
    ap.add_argument("--json", help="Write full JSON report to this path")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--ext", help="Comma-separated extensions to restrict scanning to, e.g. .py,.js")
    args = ap.parse_args()

    extensions = None
    if args.ext:
        extensions = {e if e.startswith(".") else f".{e}" for e in args.ext.split(",")}

    findings = scan(args.path, extensions)
    report.print_console(findings, use_color=not args.no_color)

    if args.json:
        with open(args.json, "w") as fh:
            fh.write(report.to_json(findings))
        print(f"\nFull JSON report written to {args.json}")

    # non-zero exit if any Critical/High finding, for CI use
    if any(f.severity.value in ("Critical", "High") for f in findings):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
