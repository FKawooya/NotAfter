"""Tests for HTML report output (QA-L4)."""

from datetime import datetime, timezone, timedelta
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from notafter.cli import cli
from notafter.checks.engine import AuditReport, Finding, Severity
from notafter.scanner.tls import CertInfo, ScanResult
from notafter.pqc.scorer import PQCReport, PQCFinding
from notafter.pqc.oids import QuantumSafety
from notafter.revocation.checker import (
    RevocationReport,
    RevocationStatus,
    OCSPResult,
    CRLResult,
    CTResult,
)
from notafter.output.html import generate_scan_html, generate_fleet_html


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_cert_info(**kwargs) -> CertInfo:
    now = datetime.now(timezone.utc)
    defaults = dict(
        subject="CN=test.example.com",
        issuer="CN=Test CA",
        not_before=(now - timedelta(days=30)).isoformat(),
        not_after=(now + timedelta(days=365)).isoformat(),
        serial="abc123",
        sig_algorithm_oid="1.2.840.113549.1.1.11",
        sig_algorithm_name="sha256WithRSAEncryption",
        key_type="RSA",
        key_size=2048,
        san_names=["test.example.com"],
    )
    defaults.update(kwargs)
    return CertInfo(**defaults)


def _make_scan_result(**kwargs) -> ScanResult:
    defaults = dict(
        host="test.example.com",
        port=443,
        tls_version="TLSv1.3",
        cipher_suite="TLS_AES_256_GCM_SHA384",
        chain=[_make_cert_info()],
    )
    defaults.update(kwargs)
    return ScanResult(**defaults)


def _make_audit_report(target="test.example.com:443") -> AuditReport:
    return AuditReport(
        target=target,
        findings=[
            Finding(check="expiry", severity=Severity.PASS, component="CN=test", message="Valid"),
        ],
    )


def _make_pqc_report() -> PQCReport:
    return PQCReport(
        score=3,
        overall_safety=QuantumSafety.QUANTUM_VULNERABLE,
        cnsa2_compliant=False,
        cnsa2_next_deadline="test deadline",
        cnsa2_days_remaining=100,
        recommendations=["Migrate to PQC"],
        findings=[
            PQCFinding(
                component="Leaf",
                algorithm="RSA-2048",
                quantum_safety=QuantumSafety.QUANTUM_VULNERABLE,
                points_earned=0,
                points_possible=2,
            ),
        ],
    )


def _make_revocation_report() -> RevocationReport:
    return RevocationReport(
        ocsp=OCSPResult(
            status=RevocationStatus.GOOD,
            responder_url="http://ocsp.example.com",
            message="Not revoked",
        ),
        crl=CRLResult(status=RevocationStatus.GOOD, message="Not in CRL"),
        ct=CTResult(logged=True, ct_entries=5, message="Found 5 entries"),
    )


# ===========================================================================
# Scan HTML tests
# ===========================================================================


class TestScanHtml:
    def test_scan_html_basic(self):
        scan = _make_scan_result()
        audit = _make_audit_report()
        pqc = _make_pqc_report()
        revocation = _make_revocation_report()

        html = generate_scan_html(scan, audit, pqc, revocation)

        assert html.startswith("<!DOCTYPE html>")
        assert "test.example.com:443" in html
        assert "Audit Findings" in html
        assert "<table" in html

    def test_scan_html_no_pqc_no_revocation(self):
        scan = _make_scan_result()
        audit = _make_audit_report()

        html = generate_scan_html(scan, audit, pqc_report=None, revocation_report=None)

        assert html.startswith("<!DOCTYPE html>")
        assert "PQC Readiness" not in html
        assert "Revocation Status" not in html

    def test_scan_html_xss_escape(self):
        cert = _make_cert_info(subject='<script>alert(1)</script>')
        scan = _make_scan_result(chain=[cert])
        audit = _make_audit_report()

        html = generate_scan_html(scan, audit)

        assert "&lt;script&gt;" in html
        assert "<script>alert(1)</script>" not in html


# ===========================================================================
# Fleet HTML tests
# ===========================================================================


class TestFleetHtml:
    def test_fleet_html_basic(self):
        entries = [
            {
                "host": "host1.example.com",
                "port": 443,
                "tls_version": "TLSv1.3",
                "critical": 0,
                "warnings": 1,
                "pqc_score": 5,
                "pqc_grade": "C",
            },
            {
                "host": "host2.example.com",
                "port": 443,
                "tls_version": "TLSv1.2",
                "critical": 1,
                "warnings": 0,
            },
        ]

        html = generate_fleet_html(entries)

        assert html.startswith("<!DOCTYPE html>")
        assert "Fleet Scan Report" in html
        assert "host1.example.com" in html
        assert "host2.example.com" in html

    def test_fleet_html_empty(self):
        html = generate_fleet_html([])

        assert html.startswith("<!DOCTYPE html>")
        assert "No hosts scanned." in html

    def test_fleet_html_error_host(self):
        entries = [
            {
                "host": "bad.example.com",
                "port": 443,
                "error": "Connection refused",
            },
        ]

        html = generate_fleet_html(entries)

        assert "Connection refused" in html
        assert "ERROR" in html


# ===========================================================================
# CLI integration tests
# ===========================================================================


class TestCliHtml:
    @patch("notafter.scanner.tls.scan_host")
    def test_cli_html_flag(self, mock_scan_host):
        mock_scan_host.return_value = _make_scan_result()

        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", "test.example.com", "--html",
            "--no-revocation", "--no-pqc",
        ])

        assert result.exit_code in (0, 1)
        assert "<!DOCTYPE html>" in result.output

    def test_cli_html_json_mutual_exclusion(self):
        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", "test.example.com", "--html", "--json",
        ])

        assert result.exit_code == 2
