import sys
import json
import uuid
import tempfile
import zipfile
import os
import shutil

# Make sure we can import from scanner
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.python_analyzer import PythonAnalyzer
from scanner.js_analyzer import JSAnalyzer
from scanner.dedup import dedup

def scan_repo(repo_path, scan_id=None):
    scan_id = scan_id or str(uuid.uuid4())
    temp_dir = None
    target_dir = repo_path

    if repo_path.lower().endswith(".zip"):
        temp_dir = tempfile.TemporaryDirectory()
        target_dir = temp_dir.name
        try:
            with zipfile.ZipFile(repo_path, 'r') as z:
                z.extractall(target_dir)
        except Exception as e:
            if temp_dir:
                temp_dir.cleanup()
            return {"status": "FAILED", "error": str(e)}

    py = PythonAnalyzer()
    js = JSAnalyzer()
    findings = []
    
    for root, dirs, files in os.walk(target_dir):
        # exclude common dirs
        dirs[:] = [d for d in dirs if d not in {"node_modules", ".git", "venv", ".venv", "__pycache__", "vendor", "vendors", "bower_components"}]
        for fn in files:
            path = os.path.join(root, fn)
            ext = os.path.splitext(fn)[1]
            norm_path = path.replace("\\", "/")
            if fn.endswith(".min.js") or "/static/js/" in norm_path or "/vendor/" in norm_path or "/vendors/" in norm_path:
                continue

            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    source = fh.read()
            except OSError:
                continue
            
            if ext == ".py":
                findings.extend(py.analyze(path, source))
            elif ext in {".js", ".mjs", ".cjs", ".jsx"}:
                findings.extend(js.analyze(path, source))
                
    findings = dedup(findings)
    
    out_findings = []
    for i, f in enumerate(findings):
        rel_path = os.path.relpath(f.file, target_dir)

        out_findings.append({
            "id": f"f{i+1}",
            "file": rel_path,
            "line": f.line,
            "algorithm": f.algorithm,
            "category": f.category,
            "severity": f.severity.value,
            "quantum_risk": f.quantum_risk.value,
            "message": f.message,
            "recommendation": f.recommendation,
            "raw_call": getattr(f, 'code_snippet', '')
        })

    if temp_dir:
        temp_dir.cleanup()
        
    return {
        "status": "COMPLETED",
        "findings": out_findings
    }

if __name__ == "__main__":
    repo = sys.argv[1] if len(sys.argv) > 1 else ""
    print(json.dumps(scan_repo(repo), indent=2))
