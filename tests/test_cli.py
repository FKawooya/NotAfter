"""Tests for CLI integration (Q-M1, Q-M3) and terminal output (Q-L1)."""

import io
import json
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

import pytest
from click.testing import CliRunner
from rich.console import Console

from notafter.cli import cli, _build_json
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


# ===========================================================================
# Q-M1: CLI integration tests via CliRunner
# ===========================================================================


class TestCLIScanCommand:
    @patch("notafter.scanner.tls.scan_host")
    @patch("notafter.scanner.tls.scan_file")
    def test_scan_json_flag(self, mock_scan_file, mock_scan_host):
        mock_scan_host.return_value = _make_scan_result()

        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "test.example.com", "--json", "--no-revocation", "--no-pqc"])
        # May exit with code 0 or 1 depending on audit
        assert result.exit_code in (0, 1)
        output = result.output
        parsed = json.loads(output)
        assert "target" in parsed
        assert "audit" in parsed

    @patch("notafter.scanner.tls.scan_host")
    def test_scan_no_revocation_flag(self, mock_scan_host):
        mock_scan_host.return_value = _make_scan_result()

        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "test.example.com", "--json", "--no-revocation", "--no-pqc"])
        assert result.exit_code in (0, 1)
        parsed = json.loads(result.output)
        assert "revocation" not in parsed

    @patch("notafter.scanner.tls.scan_host")
    def test_scan_no_pqc_flag(self, mock_scan_host):
        mock_scan_host.return_value = _make_scan_result()

        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "test.example.com", "--json", "--no-pqc", "--no-revocation"])
        assert result.exit_code in (0, 1)
        parsed = json.loads(result.output)
        assert "pqc" not in parsed

    @patch("notafter.scanner.tls.scan_host")
    def test_scan_cbom_flag(self, mock_scan_host):
        mock_scan_host.return_value = _make_scan_result()

        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "test.example.com", "--cbom"])
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert parsed["bomFormat"] == "CycloneDX"

    @patch("notafter.scanner.tls.scan_host")
    def test_scan_error_exit_code_2(self, mock_scan_host):
        mock_scan_host.return_value = ScanResult(
            host="bad.example.com", port=443, error="Connection refused"
        )

        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "bad.example.com"])
        assert result.exit_code == 2

    @patch("notafter.scanner.tls.scan_file")
    def test_scan_file_flag(self, mock_scan_file):
        mock_scan_file.return_value = _make_scan_result(host="cert.pem", port=0)

        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--file", "cert.pem", "--json", "--no-revocation", "--no-pqc"])
        assert result.exit_code in (0, 1)
        parsed = json.loads(result.output)
        assert "target" in parsed


class TestCLIFleetCommand:
    @patch("notafter.scanner.fleet.load_targets")
    @patch("notafter.scanner.fleet.scan_fleet")
    def test_fleet_json_flag(self, mock_scan_fleet, mock_load_targets):
        import asyncio
        mock_load_targets.return_value = ["host1.example.com", "host2.example.com"]

        # scan_fleet is async, so asyncio.run expects a coroutine
        async def fake_scan_fleet(*args, **kwargs):
            return [
                _make_scan_result(host="host1.example.com"),
                _make_scan_result(host="host2.example.com"),
            ]

        mock_scan_fleet.side_effect = fake_scan_fleet

        runner = CliRunner()
        result = runner.invoke(cli, ["fleet", "hosts.txt", "--json", "--no-pqc"])
        assert result.exit_code in (0, 1, 2)

    @patch("notafter.scanner.fleet.load_targets")
    def test_fleet_invalid_source(self, mock_load_targets):
        mock_load_targets.side_effect = ValueError("Cannot parse 'bad' as CIDR or host file")

        runner = CliRunner()
        result = runner.invoke(cli, ["fleet", "bad"])
        assert result.exit_code == 2


# ===========================================================================
# Q-M3: _build_json with None pqc_report and None revocation
# ===========================================================================


class TestBuildJson:
    def test_build_json_none_pqc_and_revocation(self):
        """Should not KeyError when both pqc_report and revocation are None."""
        scan = _make_scan_result()
        audit = _make_audit_report()
        output = _build_json(scan, audit, pqc_report=None, revocation_report=None)
        assert "pqc" not in output
        assert "revocation" not in output
        assert "audit" in output
        assert "chain" in output

    def test_build_json_with_pqc_report(self):
        scan = _make_scan_result()
        audit = _make_audit_report()
        pqc = PQCReport(
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
        output = _build_json(scan, audit, pqc_report=pqc, revocation_report=None)
        assert "pqc" in output
        assert output["pqc"]["score"] == 3

    def test_build_json_with_revocation_report(self):
        scan = _make_scan_result()
        audit = _make_audit_report()
        revocation = RevocationReport(
            ocsp=OCSPResult(
                status=RevocationStatus.GOOD,
                responder_url="http://ocsp.example.com",
                message="Not revoked",
            ),
            crl=CRLResult(status=RevocationStatus.GOOD, message="Not in CRL"),
            ct=CTResult(logged=True, ct_entries=5, message="Found 5 entries"),
        )
        output = _build_json(scan, audit, pqc_report=None, revocation_report=revocation)
        assert "revocation" in output
        assert output["revocation"]["ocsp"]["status"] == "good"


# ===========================================================================
# Q-L1: Terminal output rendering — should not crash
# ===========================================================================


class TestTerminalOutput:
    def test_print_audit_no_crash(self):
        from notafter.output.terminal import print_audit
        report = _make_audit_report()
        # Capture output by using a file-backed Console
        buf = io.StringIO()
        console = Console(file=buf, force_terminal=True)
        with patch("notafter.output.terminal.console", console):
            print_audit(report)
        output = buf.getvalue()
        assert "Certificate Audit" in output

    def test_print_pqc_no_crash(self):
        from notafter.output.terminal import print_pqc
        report = PQCReport(
            score=5,
            overall_safety=QuantumSafety.QUANTUM_VULNERABLE,
            recommendations=["Migrate to PQC"],
            cnsa2_next_deadline="test",
            cnsa2_days_remaining=100,
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
        buf = io.StringIO()
        console = Console(file=buf, force_terminal=True)
        with patch("notafter.output.terminal.console", console):
            print_pqc(report)
        output = buf.getvalue()
        assert "PQC" in output

    def test_print_revocation_no_crash(self):
        from notafter.output.terminal import print_revocation
        report = RevocationReport(
            ocsp=OCSPResult(
                status=RevocationStatus.GOOD,
                responder_url="http://ocsp.example.com",
                message="Not revoked",
            ),
            crl=CRLResult(
                status=RevocationStatus.SKIPPED,
                message="No CRL dist points",
            ),
            ct=CTResult(logged=True, ct_entries=3, message="Found 3 entries"),
        )
        buf = io.StringIO()
        console = Console(file=buf, force_terminal=True)
        with patch("notafter.output.terminal.console", console):
            print_revocation(report)
        output = buf.getvalue()
        assert "Revocation" in output

    def test_print_revocation_revoked_no_crash(self):
        from notafter.output.terminal import print_revocation
        report = RevocationReport(
            ocsp=OCSPResult(status=RevocationStatus.REVOKED, message="REVOKED"),
        )
        buf = io.StringIO()
        console = Console(file=buf, force_terminal=True)
        with patch("notafter.output.terminal.console", console):
            print_revocation(report)
        output = buf.getvalue()
        assert "REVOKED" in output
