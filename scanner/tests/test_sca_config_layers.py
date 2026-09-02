"""
Unit tests for SCA Analyzer, Config & Infra Analyzer, and SCA Correlation.
"""
import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from scanner.sca_analyzer import SCAAnalyzer
from scanner.config_infra_analyzer import ConfigInfraAnalyzer
from scanner.sca_correlation import correlate_sca_with_source
from scanner.models import Finding, Severity, Confidence, QuantumRisk


FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
SCA_DIR = os.path.join(FIXTURES_DIR, "sca")
INFRA_DIR = os.path.join(FIXTURES_DIR, "infra")


class TestSCALayer:
    def setup_method(self):
        self.analyzer = SCAAnalyzer()

    def test_npm_vulnerable_package_json(self):
        path = os.path.join(SCA_DIR, "package-vuln.json")
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        findings = self.analyzer.analyze(path, content)
        rule_ids = {f.rule_id for f in findings}
        assert "sca-npm-md5" in rule_ids
        assert "sca-npm-node-rsa" in rule_ids
        assert "sca-npm-jsonwebtoken" in rule_ids

        # Check jsonwebtoken version bump from LOW to MEDIUM (since 8.5.1 < 9.0.0)
        jwt_finding = next(f for f in findings if f.rule_id == "sca-npm-jsonwebtoken")
        assert jwt_finding.severity == Severity.MEDIUM
        assert jwt_finding.confidence == Confidence.LIKELY

    def test_npm_clean_package_json(self):
        path = os.path.join(SCA_DIR, "package-clean.json")
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        findings = self.analyzer.analyze(path, content)
        assert len(findings) == 0

    def test_pip_vulnerable_requirements(self):
        path = os.path.join(SCA_DIR, "requirements-vuln.txt")
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        findings = self.analyzer.analyze(path, content)
        rule_ids = {f.rule_id for f in findings}
        assert "sca-pip-pycrypto" in rule_ids
        assert "sca-pip-rsa" in rule_ids
        assert "sca-pip-pycryptodome" in rule_ids

        pycrypto_finding = next(f for f in findings if f.rule_id == "sca-pip-pycrypto")
        assert pycrypto_finding.severity == Severity.CRITICAL

    def test_pip_clean_requirements(self):
        path = os.path.join(SCA_DIR, "requirements-clean.txt")
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        findings = self.analyzer.analyze(path, content)
        assert len(findings) == 0

    def test_maven_vulnerable_pom(self):
        path = os.path.join(SCA_DIR, "pom-vuln.xml")
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        findings = self.analyzer.analyze(path, content)
        assert len(findings) == 1
        assert findings[0].rule_id == "sca-maven-bcprov-jdk15on"

    def test_maven_clean_pom(self):
        path = os.path.join(SCA_DIR, "pom-clean.xml")
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        findings = self.analyzer.analyze(path, content)
        assert len(findings) == 0


class TestConfigInfraLayer:
    def setup_method(self):
        self.analyzer = ConfigInfraAnalyzer()

    def test_nginx_vulnerable_config(self):
        path = os.path.join(INFRA_DIR, "nginx-vuln.conf")
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        findings = self.analyzer.analyze(path, content)
        rule_ids = {f.rule_id for f in findings}
        assert "infra-weak-tls-protocol" in rule_ids
        assert "infra-weak-cipher-suite" in rule_ids
        assert all(f.confidence == Confidence.LIKELY for f in findings)

    def test_nginx_clean_config(self):
        path = os.path.join(INFRA_DIR, "nginx-clean.conf")
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        findings = self.analyzer.analyze(path, content)
        assert len(findings) == 0

    def test_k8s_vulnerable_secret(self):
        path = os.path.join(INFRA_DIR, "k8s-secret-vuln.yaml")
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        findings = self.analyzer.analyze(path, content)
        assert len(findings) >= 1
        assert any(f.rule_id == "infra-k8s-secret-plaintext" for f in findings)
        assert any(f.confidence == Confidence.POSSIBLE for f in findings)

    def test_k8s_clean_deployment(self):
        path = os.path.join(INFRA_DIR, "k8s-secret-clean.yaml")
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        findings = self.analyzer.analyze(path, content)
        assert len(findings) == 0

    def test_terraform_vulnerable_file(self):
        path = os.path.join(INFRA_DIR, "terraform-vuln.tf")
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        findings = self.analyzer.analyze(path, content)
        assert len(findings) == 1
        assert findings[0].rule_id == "infra-terraform-hardcoded-secret"

    def test_terraform_clean_file(self):
        path = os.path.join(INFRA_DIR, "terraform-clean.tf")
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        findings = self.analyzer.analyze(path, content)
        assert len(findings) == 0


class TestSCACorrelation:
    def test_corroborates_matching_sca_and_ast_algorithms(self):
        ast_finding = Finding(
            file="src/auth.js",
            line=25,
            column=0,
            language="javascript",
            rule_id="rsa-small-key",
            rule_name="RSA with small key length",
            category="asymmetric",
            algorithm="RSA",
            severity=Severity.HIGH,
            quantum_risk=QuantumRisk.QUANTUM_BROKEN,
            message="RSA key generation with 1024-bit modulus",
            recommendation="Use ML-KEM or at least RSA-3072",
            confidence=Confidence.LIKELY,
        )
        sca_finding = Finding(
            file="package.json",
            line=12,
            column=0,
            language="manifest",
            rule_id="sca-npm-node-rsa",
            rule_name="SCA: node-rsa (npm)",
            category="asymmetric",
            algorithm="RSA",
            severity=Severity.MEDIUM,
            quantum_risk=QuantumRisk.QUANTUM_BROKEN,
            message="Declared dependency 'node-rsa' identified",
            recommendation="Migrate to PQC",
            confidence=Confidence.LIKELY,
        )
        unrelated_sca = Finding(
            file="package.json",
            line=15,
            column=0,
            language="manifest",
            rule_id="sca-npm-bcryptjs",
            rule_name="SCA: bcryptjs (npm)",
            category="hash",
            algorithm="bcrypt",
            severity=Severity.INFO,
            quantum_risk=QuantumRisk.SAFE,
            message="Bcrypt library",
            recommendation="Ensure work factor >= 12",
            confidence=Confidence.LIKELY,
        )

        all_findings = [ast_finding, sca_finding, unrelated_sca]
        correlated = correlate_sca_with_source(all_findings)

        assert correlated[0].confidence == Confidence.CONFIRMED
        assert correlated[1].confidence == Confidence.CONFIRMED
        assert correlated[2].confidence == Confidence.LIKELY
