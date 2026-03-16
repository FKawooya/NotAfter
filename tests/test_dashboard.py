"""Tests for interactive dashboard output."""

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
from notafter.output.dashboard import HostReport, generate_dashboard


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_cert(**kwargs) -> CertInfo:
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


def _make_scan(**kwargs) -> ScanResult:
    defaults = dict(
        host="test.example.com",
        port=443,
        tls_version="TLSv1.3",
        cipher_suite="TLS_AES_256_GCM_SHA384",
        key_exchange="ECDHE",
        chain=[_make_cert()],
    )
    defaults.update(kwargs)
    return ScanResult(**defaults)


def _make_audit(target="test.example.com:443", findings=None) -> AuditReport:
    if findings is None:
        findings = [
            Finding(check="expiry", severity=Severity.PASS, component="CN=test", message="Valid"),
        ]
    return AuditReport(target=target, findings=findings)


def _make_pqc() -> PQCReport:
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


def _make_revocation() -> RevocationReport:
    return RevocationReport(
        ocsp=OCSPResult(
            status=RevocationStatus.GOOD,
            responder_url="http://ocsp.example.com",
            message="Not revoked",
        ),
        crl=CRLResult(status=RevocationStatus.GOOD, message="Not in CRL"),
        ct=CTResult(logged=True, ct_entries=5, message="Found 5 entries"),
    )


def _host_report(**kwargs) -> HostReport:
    defaults = dict(
        scan=_make_scan(),
        audit=_make_audit(),
    )
    defaults.update(kwargs)
    return HostReport(**defaults)


# ===========================================================================
# Dashboard structure tests
# ===========================================================================


class TestDashboardStructure:
    def test_single_host_basic(self):
        html = generate_dashboard([_host_report()])
        assert html.startswith("<!DOCTYPE html>")
        assert "NotAfter Dashboard" in html
        assert "test.example.com:443" in html

    def test_single_host_has_tabs(self):
        html = generate_dashboard([_host_report(pqc=_make_pqc(), revocation=_make_revocation())])
        assert 'data-tab="overview"' in html
        assert 'data-tab="inventory"' in html
        assert 'data-tab="pqc"' in html
        assert 'data-tab="revocation"' in html
        assert 'data-tab="hosts"' in html

    def test_single_host_no_hosts_stat_card(self):
        """Single-host mode should not show the 'Hosts' stat card."""
        html = generate_dashboard([_host_report()])
        assert ">Hosts</div>" not in html

    def test_fleet_mode(self):
        hr1 = _host_report(scan=_make_scan(host="host1.example.com"))
        hr2 = _host_report(scan=_make_scan(host="host2.example.com"))
        html = generate_dashboard([hr1, hr2])
        assert "Fleet Dashboard" in html
        assert "host1.example.com" in html
        assert "host2.example.com" in html
        assert ">Hosts</div>" in html  # fleet shows Hosts stat card

    def test_has_javascript(self):
        html = generate_dashboard([_host_report()])
        assert "<script>" in html
        assert "tab-btn" in html
        assert "addEventListener" in html

    def test_csp_allows_inline_script(self):
        html = generate_dashboard([_host_report()])
        assert "script-src 'unsafe-inline'" in html


# ===========================================================================
# Tab content tests
# ===========================================================================


class TestDashboardTabs:
    def test_action_items_tab(self):
        audit = _make_audit(findings=[
            Finding(
                check="key_strength", severity=Severity.WARNING,
                component="CN=test", message="RSA-2048 weak",
                remediation="Use RSA-3072+",
            ),
        ])
        html = generate_dashboard([_host_report(audit=audit)])
        assert "Action Items" in html
        assert "RSA-2048 weak" in html
        assert "Use RSA-3072+" in html

    def test_no_action_items_tab_when_all_pass(self):
        html = generate_dashboard([_host_report()])
        assert 'data-tab="actions"' not in html

    def test_inventory_tab(self):
        html = generate_dashboard([_host_report()])
        assert "Certificate Inventory" in html
        assert "test.example.com" in html
        assert "sha256WithRSAEncryption" in html

    def test_pqc_tab(self):
        html = generate_dashboard([_host_report(pqc=_make_pqc())])
        assert "PQC Readiness Posture" in html
        assert "Grade D" in html  # score 3 = D
        assert "Migrate to PQC" in html
        assert "CNSA 2.0" in html

    def test_no_pqc_tab_when_none(self):
        html = generate_dashboard([_host_report(pqc=None)])
        assert 'data-tab="pqc"' not in html

    def test_revocation_tab(self):
        html = generate_dashboard([_host_report(revocation=_make_revocation())])
        assert "Revocation Status" in html
        assert "OCSP" in html
        assert "CRL" in html
        assert "CT" in html

    def test_no_revocation_tab_when_none(self):
        html = generate_dashboard([_host_report(revocation=None)])
        assert 'data-tab="revocation"' not in html

    def test_host_details_tab(self):
        html = generate_dashboard([_host_report()])
        assert "Host Details" in html
        assert "host-detail-block" in html


# ===========================================================================
# XSS protection
# ===========================================================================


class TestDashboardXSS:
    def test_xss_in_subject(self):
        cert = _make_cert(subject='<script>alert("xss")</script>')
        scan = _make_scan(chain=[cert])
        html = generate_dashboard([_host_report(scan=scan)])
        assert "&lt;script&gt;" in html
        assert '<script>alert("xss")</script>' not in html

    def test_xss_in_host(self):
        scan = _make_scan(host='<img src=x onerror=alert(1)>')
        html = generate_dashboard([_host_report(scan=scan)])
        assert "&lt;img" in html

    def test_xss_in_finding_message(self):
        audit = _make_audit(findings=[
            Finding(
                check="test", severity=Severity.WARNING,
                component="test", message='<b>evil</b>',
                remediation='<script>',
            ),
        ])
        html = generate_dashboard([_host_report(audit=audit)])
        assert "&lt;b&gt;" in html
        assert "&lt;script&gt;" in html


# ===========================================================================
# Fleet with errors
# ===========================================================================


class TestDashboardFleetErrors:
    def test_error_host(self):
        hr_ok = _host_report(scan=_make_scan(host="good.example.com"))
        hr_err = _host_report(
            scan=_make_scan(host="bad.example.com", error="Connection refused", chain=[]),
            audit=_make_audit(target="bad.example.com:443", findings=[
                Finding(check="connection", severity=Severity.CRITICAL,
                        component="TLS", message="Connection refused"),
            ]),
        )
        html = generate_dashboard([hr_ok, hr_err])
        assert "Connection refused" in html
        assert "ERROR" in html
        assert "good.example.com" in html

    def test_stat_cards_counts(self):
        hr1 = _host_report(
            scan=_make_scan(host="h1"),
            audit=_make_audit(findings=[
                Finding(check="x", severity=Severity.CRITICAL, component="x", message="bad"),
            ]),
        )
        hr2 = _host_report(scan=_make_scan(host="h2"))
        html = generate_dashboard([hr1, hr2])
        # Should have at least the critical and clean counts
        assert ">Critical</div>" in html
        assert ">Clean</div>" in html


# ===========================================================================
# Filtering and interactivity
# ===========================================================================


class TestDashboardInteractivity:
    def test_filter_inputs_present(self):
        html = generate_dashboard([_host_report()])
        assert 'id="overview-filter"' in html
        assert 'id="hosts-filter"' in html

    def test_sortable_headers(self):
        html = generate_dashboard([_host_report()])
        assert 'class="sortable"' in html

    def test_host_link_drill_down(self):
        html = generate_dashboard([_host_report()])
        assert 'class="mono host-link"' in html


# ===========================================================================
# Review round fixes
# ===========================================================================


class TestDashboardReviewFixes:
    def test_empty_hosts_raises(self):
        """QA-D2/CQ-D9: generate_dashboard([]) must not crash with IndexError."""
        with pytest.raises(ValueError, match="At least one HostReport"):
            generate_dashboard([])

    def test_total_clean_never_negative(self):
        """QA-D4: total_clean should never be negative."""
        # Error host with critical finding — should not double-subtract
        hr = _host_report(
            scan=_make_scan(host="err", error="refused", chain=[]),
            audit=_make_audit(findings=[
                Finding(check="conn", severity=Severity.CRITICAL, component="TLS", message="err"),
            ]),
        )
        html = generate_dashboard([hr])
        # The clean stat card should show 0, not -1
        assert html.count(">Clean</div>") <= 1  # at most one clean card
        assert ">-1</div>" not in html

    def test_revocation_table_no_extra_cells_fleet(self):
        """QA-D1/CQ-D7: Revocation rows should not have extra cells from rowspan."""
        hr1 = _host_report(
            scan=_make_scan(host="h1"),
            revocation=_make_revocation(),
        )
        hr2 = _host_report(
            scan=_make_scan(host="h2"),
            revocation=_make_revocation(),
        )
        html = generate_dashboard([hr1, hr2])
        # After the rowspan="3" OCSP row, CRL and CT rows should NOT have extra <td></td>
        # Count cells in revocation table — each row should have 4 data cols (or 5 for OCSP with rowspan)
        assert 'rowspan="3"' in html
        # The CRL/CT rows must not start with an empty <td></td>
        assert "<tr><td></td>" not in html

    def test_inventory_sort_indices_single_host(self):
        """QA-D5/CQ-D8: Sort indices should match actual columns in single-host mode."""
        html = generate_dashboard([_host_report()])
        # In single-host mode, no Host column. Subject should be col 1, Expires col 2
        assert 'data-col="1">Subject' in html
        assert 'data-col="2">Expires' in html

    def test_inventory_sort_indices_fleet(self):
        hr1 = _host_report(scan=_make_scan(host="h1"))
        hr2 = _host_report(scan=_make_scan(host="h2"))
        html = generate_dashboard([hr1, hr2])
        # In fleet mode, Host col 0, Subject col 2, Expires col 3
        assert 'data-col="0">Host' in html
        assert 'data-col="2">Subject' in html
        assert 'data-col="3">Expires' in html

    def test_overview_title_single_host(self):
        """QA-D6: Single host should say 'Overview' not 'Fleet Overview'."""
        html = generate_dashboard([_host_report()])
        assert "<h2>Overview</h2>" in html
        assert "Fleet Overview" not in html

    def test_overview_title_fleet(self):
        hr1 = _host_report(scan=_make_scan(host="h1"))
        hr2 = _host_report(scan=_make_scan(host="h2"))
        html = generate_dashboard([hr1, hr2])
        assert "Fleet Overview" in html

    def test_revoked_cert_rendering(self):
        """QA-D9: Revoked certificate should show REVOKED badge."""
        rev = RevocationReport(
            ocsp=OCSPResult(status=RevocationStatus.REVOKED, message="Certificate revoked"),
            crl=CRLResult(status=RevocationStatus.GOOD, message="OK"),
            ct=CTResult(logged=True, ct_entries=1, message="Found"),
        )
        html = generate_dashboard([_host_report(revocation=rev)])
        assert "REVOKED" in html

    def test_pill_escapes_label(self):
        """SEC-D2: _pill should escape its label parameter."""
        from notafter.output.dashboard import _pill
        result = _pill('<script>alert(1)</script>', '#fff')
        assert '&lt;script&gt;' in result
        assert '<script>alert(1)</script>' not in result

    def test_mixed_pqc_fleet(self):
        """QA-D12: Some hosts with PQC, some without."""
        hr1 = _host_report(scan=_make_scan(host="h1"), pqc=_make_pqc())
        hr2 = _host_report(scan=_make_scan(host="h2"), pqc=None)
        html = generate_dashboard([hr1, hr2])
        assert 'data-tab="pqc"' in html  # PQC tab exists because h1 has it
        assert "&mdash;" in html  # h2's PQC column shows dash


# ===========================================================================
# CLI integration with dashboard
# ===========================================================================


class TestCliDashboard:
    @patch("notafter.scanner.tls.scan_host")
    def test_scan_html_produces_dashboard(self, mock_scan):
        mock_scan.return_value = _make_scan()
        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", "test.example.com", "--html",
            "--no-revocation", "--no-pqc",
        ])
        assert result.exit_code in (0, 1)
        # Should be the new dashboard, not old report
        assert "NotAfter Dashboard" in result.output

    def test_html_json_mutual_exclusion(self):
        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", "test.example.com", "--html", "--json",
        ])
        assert result.exit_code == 2


# ===========================================================================
# HostReport dataclass
# ===========================================================================


class TestHostReport:
    def test_host_report_defaults(self):
        hr = HostReport(scan=_make_scan(), audit=_make_audit())
        assert hr.pqc is None
        assert hr.revocation is None

    def test_host_report_with_all(self):
        hr = HostReport(
            scan=_make_scan(),
            audit=_make_audit(),
            pqc=_make_pqc(),
            revocation=_make_revocation(),
        )
        assert hr.pqc.score == 3
        assert hr.revocation.ocsp.status == RevocationStatus.GOOD
