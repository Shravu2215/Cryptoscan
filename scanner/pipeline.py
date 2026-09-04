import sys
import json
import uuid
import tempfile
import zipfile
import os
import shutil

# Make sure we can import from scanner
_scanner_dir = os.path.dirname(os.path.abspath(__file__))
_parent_dir = os.path.dirname(_scanner_dir)
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)
if _scanner_dir not in sys.path:
    sys.path.insert(0, _scanner_dir)

from scanner.python_analyzer import PythonAnalyzer
from scanner.js_analyzer import JSAnalyzer
from scanner.dedup import dedup
from scanner.regex_analyzer import RegexAnalyzer
from scanner.entropy_analyzer import EntropyAnalyzer
from scanner.confidence import promote_confirmed
from scanner.sca_analyzer import SCAAnalyzer
from scanner.config_infra_analyzer import ConfigInfraAnalyzer
from scanner.sca_correlation import correlate_sca_with_source
from scanner.suppression import load_suppressions, apply_suppressions

def _infer_library(f) -> str:
    tags = getattr(f, "tags", []) or []
    if "sca" in tags:
        for t in tags:
            if t not in {"sca", "npm", "pip", "maven"}:
                return t
    if "crypto-js" in str(tags) or "cryptojs" in f.rule_id:
        return "crypto-js"
    if "jsrsasign" in f.rule_id or "jsrsasign" in str(tags):
        return "jsrsasign"
    if "dockerfile" in tags:
        return "Dockerfile"
    if "nginx" in tags:
        return "nginx"
    if "apache" in tags:
        return "apache"
    if "terraform" in tags:
        return "terraform"
    if "k8s" in tags:
        return "kubernetes"
    if f.language == "python":
        if "pycryptodome" in str(tags) or "aes" in f.rule_id:
            return "pycryptodome"
        return "hashlib"
    if f.language in ("javascript", "typescript"):
        return "Node Builtin crypto"
    return "Standard Crypto API"


def _infer_key_size(f):
    alg = (f.algorithm or "").upper()
    if "1024" in alg or "1024" in f.rule_id:
        return 1024
    if "2048" in alg or "2048" in f.rule_id:
        return 2048
    if "4096" in alg or "4096" in f.rule_id:
        return 4096
    if "256" in alg:
        return 256
    if "128" in alg:
        return 128
    if "192" in alg:
        return 192
    if "512" in alg:
        return 512
    if "DES" in alg and "3DES" not in alg:
        return 56
    if "3DES" in alg:
        return 112
    if "BLOWFISH" in alg:
        return 128
    if "RC4" in alg:
        return 128
    return None


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
    rx = RegexAnalyzer()
    ent = EntropyAnalyzer()
    sca = SCAAnalyzer()
    infra = ConfigInfraAnalyzer()
    findings = []
    
    for root, dirs, files in os.walk(target_dir):
        # exclude common dirs
        dirs[:] = [d for d in dirs if d not in {"node_modules", ".git", "venv", ".venv", "__pycache__", "vendor", "vendors", "bower_components", "dist", "build"}]
        for fn in files:
            path = os.path.join(root, fn)
            ext = os.path.splitext(fn)[1].lower()
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    source = fh.read()
            except OSError:
                continue
            
            # 1. SCA Manifest Layer
            if fn.lower() in {"package.json", "requirements.txt", "pom.xml"} or (fn.lower().startswith("requirements") and fn.lower().endswith(".txt")):
                findings.extend(sca.analyze(path, source))

            # 2. Infra / Config Layer
            if ext in {".tf", ".conf", ".yaml", ".yml"} or fn.lower() in {"nginx.conf", "httpd.conf", "apache2.conf"}:
                findings.extend(infra.analyze(path, source))

            # 3. Source Code / Regex / Entropy Layers
            if ext == ".py":
                findings.extend(py.analyze(path, source))
                findings.extend(ent.analyze(path, source))
            elif ext in {".js", ".mjs", ".cjs", ".jsx"}:
                findings.extend(js.analyze(path, source))
                findings.extend(ent.analyze(path, source))
            elif (ext in {".yml", ".yaml", ".json", ".ini", ".conf", ".env"}
                  or fn.startswith(".env")
                  or fn == "Dockerfile" or fn.startswith("Dockerfile.")):
                findings.extend(rx.analyze(path, source))
                findings.extend(ent.analyze(path, source))
                
    findings = dedup(findings)
    findings = promote_confirmed(findings)
    findings = correlate_sca_with_source(findings)

    # Apply allow-list / suppressions from .cryptoscan-ignore
    suppressions = load_suppressions(target_dir)
    _, suppressed_count = apply_suppressions(findings, suppressions, repo_path=target_dir)
    
    out_findings = []
    for i, f in enumerate(findings):
        rel_path = os.path.relpath(f.file, target_dir)

        out_findings.append({
            "id": f"f{i+1}",
            "file": rel_path,
            "line": f.line,
            "algorithm": f.algorithm,
            "category": f.category,
            "library": _infer_library(f),
            "key_size": _infer_key_size(f),
            "severity": f.severity.value,
            "quantum_risk": f.quantum_risk.value,
            "message": f.message,
            "recommendation": f.recommendation,
            "raw_call": getattr(f, 'code_snippet', ''),
            "confidence": f.confidence.value,
            "detection_method": f.detection_method,
            "suppressed": f.suppressed,
            "suppression_reason": f.suppression_reason,
        })

    if temp_dir:
        temp_dir.cleanup()
        
    return {
        "status": "COMPLETED",
        "findings": out_findings,
        "suppressed_count": suppressed_count,
    }

if __name__ == "__main__":
    repo = sys.argv[1] if len(sys.argv) > 1 else ""
    print(json.dumps(scan_repo(repo), indent=2))
