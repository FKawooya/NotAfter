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
    def test_findings_in_overview_expand(self):
        audit = _make_audit(findings=[
            Finding(
                check="key_strength", severity=Severity.WARNING,
                component="CN=test", message="RSA-2048 weak",
                remediation="Use RSA-3072+",
            ),
        ])
        html = generate_dashboard([_host_report(audit=audit)])
        assert "RSA-2048 weak" in html
        assert "Use RSA-3072+" in html
        assert "overview-expand" in html

    def test_overview_finding_count_in_tab_label(self):
        audit = _make_audit(findings=[
            Finding(
                check="key_strength", severity=Severity.WARNING,
                component="CN=test", message="RSA-2048 weak",
                remediation="Use RSA-3072+",
            ),
        ])
        html = generate_dashboard([_host_report(audit=audit)])
        assert "Overview (1 findings)" in html

    def test_no_finding_count_when_all_pass(self):
        html = generate_dashboard([_host_report()])
        # No action items tab, overview label has no count
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
# Batch 2 features: CSV export, print, CBOM tab
# ===========================================================================


class TestCSVExport:
    def test_csv_export_button_inventory(self):
        html = generate_dashboard([_host_report()])
        assert "export-btn" in html
        assert "exportCSV" in html
        assert "notafter-inventory" in html

    def test_csv_export_js_function(self):
        html = generate_dashboard([_host_report()])
        assert "function exportCSV" in html
        assert "text/csv" in html


class TestPrintStylesheet:
    def test_print_media_query(self):
        html = generate_dashboard([_host_report()])
        assert "@media print" in html

    def test_print_hides_tabs_and_filters(self):
        html = generate_dashboard([_host_report()])
        assert ".tab-nav { display: none" in html or ".tab-nav{display:none" in html
        assert ".filter-bar { display: none" in html or ".filter-bar{display:none" in html

    def test_print_shows_all_tabs(self):
        html = generate_dashboard([_host_report()])
        assert ".tab-content { display: block !important" in html

    def test_print_hides_export_buttons(self):
        html = generate_dashboard([_host_report()])
        assert ".export-btn { display: none" in html


class TestCBOMTab:
    def test_cbom_tab_present(self):
        html = generate_dashboard([_host_report()])
        assert 'data-tab="cbom"' in html
        assert "Cryptographic Bill of Materials" in html

    def test_cbom_tab_absent_no_certs(self):
        hr = _host_report(
            scan=_make_scan(host="err", error="refused", chain=[]),
            audit=_make_audit(findings=[
                Finding(check="conn", severity=Severity.CRITICAL, component="TLS", message="err"),
            ]),
        )
        html = generate_dashboard([hr])
        assert 'data-tab="cbom"' not in html

    def test_cbom_has_asset_table(self):
        html = generate_dashboard([_host_report()])
        assert "cbom-table" in html
        assert "cryptographic-asset" in html or "CERTIFICATE" in html

    def test_cbom_raw_json(self):
        html = generate_dashboard([_host_report()])
        assert "CycloneDX" in html
        assert "View raw CycloneDX JSON" in html

    def test_cbom_quantum_readiness(self):
        html = generate_dashboard([_host_report()])
        assert "Vulnerable" in html or "quantum-vulnerable" in html

    def test_cbom_csv_export(self):
        html = generate_dashboard([_host_report()])
        assert "notafter-cbom" in html

    def test_cbom_fleet_has_host_column(self):
        hr1 = _host_report(scan=_make_scan(host="h1"))
        hr2 = _host_report(scan=_make_scan(host="h2"))
        html = generate_dashboard([hr1, hr2])
        assert "h1:443" in html
        assert "h2:443" in html


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


# ===========================================================================
# Batch 2 review fixes — additional coverage
# ===========================================================================


class TestCBOMSortIndices:
    """QA-B2-1/SEC-B2-14: CBOM table sort column indices in single vs fleet mode."""

    def test_cbom_single_host_sort_col(self):
        """In single-host mode, Algorithm should use data-col=2 (no Host column)."""
        html = generate_dashboard([_host_report()])
        # Should NOT have data-col="3" for Algorithm in single-host CBOM
        # Algorithm is at cell index 2 (Asset=0, Type=1, Algorithm=2)
        assert 'data-col="2">Algorithm' in html

    def test_cbom_fleet_sort_col(self):
        """In fleet mode, Algorithm should use data-col=3 (Host column present)."""
        hr1 = _host_report(scan=_make_scan(host="h1"))
        hr2 = _host_report(scan=_make_scan(host="h2"))
        html = generate_dashboard([hr1, hr2])
        assert 'data-col="3">Algorithm' in html

    def test_cbom_csv_export_button(self):
        """QA-B2-13: Verify CSV export button calls exportCSV with correct args."""
        html = generate_dashboard([_host_report()])
        assert "exportCSV('cbom-table'" in html
        assert "export-btn" in html


class TestARIAAttributes:
    """QA-B2-4: ARIA attributes for accessibility."""

    def test_tablist_role(self):
        html = generate_dashboard([_host_report()])
        assert 'role="tablist"' in html

    def test_tab_role_and_selected(self):
        html = generate_dashboard([_host_report()])
        assert 'role="tab"' in html
        assert 'aria-selected="true"' in html

    def test_tabpanel_role(self):
        html = generate_dashboard([_host_report()])
        assert 'role="tabpanel"' in html

    def test_filter_aria_labels(self):
        html = generate_dashboard([_host_report()])
        assert 'aria-label="Filter hosts"' in html
        assert 'aria-label="Filter certificates"' in html
        assert 'aria-label="Filter CBOM assets"' in html


class TestPrintExpand:
    """QA-B2-12: Print stylesheet expands collapsed details."""

    def test_beforeprint_handler(self):
        html = generate_dashboard([_host_report()])
        assert "beforeprint" in html
        assert "afterprint" in html


class TestHostLabelEscaping:
    """SEC-B2-1: Host label escaping consistency."""

    def test_xss_host_name_in_overview(self):
        """Malicious hostname should be escaped in overview table."""
        scan = _make_scan(host='<script>alert("xss")</script>')
        audit = _make_audit(target='<script>alert("xss")</script>:443')
        hr = HostReport(scan=scan, audit=audit)
        html = generate_dashboard([hr])
        assert '<script>alert' not in html
        assert '&lt;script&gt;alert' in html


class TestInputValidation:
    """SEC-B2-5/SEC-B2-6: CLI input validation."""

    def test_port_range_validation(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "example.com", "--port", "0"])
        assert result.exit_code == 2

    def test_port_range_too_high(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "example.com", "--port", "99999"])
        assert result.exit_code == 2

    def test_concurrency_range_validation(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["fleet", "hosts.txt", "--concurrency", "0"])
        assert result.exit_code == 2


# ===========================================================================
# Batch 3: Timeline, Light Theme, Terminal Polish
# ===========================================================================


class TestTimelineTab:
    """Feature 1: Certificate timeline visualization."""

    def test_timeline_tab_present(self):
        html = generate_dashboard([_host_report()])
        assert 'data-tab="timeline"' in html

    def test_timeline_has_today_marker(self):
        html = generate_dashboard([_host_report()])
        assert "tl-today" in html

    def test_timeline_has_bars(self):
        html = generate_dashboard([_host_report()])
        assert "tl-bar" in html
        assert "tl-track" in html

    def test_timeline_shows_host_label(self):
        html = generate_dashboard([_host_report()])
        assert "test.example.com:443" in html

    def test_timeline_expired_cert_color(self):
        """Expired cert should have red bar."""
        now = datetime.now(timezone.utc)
        cert = _make_cert(
            not_before=(now - timedelta(days=400)).isoformat(),
            not_after=(now - timedelta(days=30)).isoformat(),
        )
        scan = _make_scan(chain=[cert])
        hr = _host_report(scan=scan)
        html = generate_dashboard([hr])
        # The red color constant
        assert "#f85149" in html

    def test_timeline_fleet_multiple_bars(self):
        hr1 = _host_report(scan=_make_scan(host="h1"))
        hr2 = _host_report(scan=_make_scan(host="h2"))
        html = generate_dashboard([hr1, hr2])
        assert html.count("tl-row") >= 2

    def test_timeline_naive_datetime(self):
        """QA-B3-1: Timezone-naive cert dates should not crash."""
        cert = _make_cert(
            not_before="2025-01-01T00:00:00",
            not_after="2026-06-01T00:00:00",
        )
        scan = _make_scan(chain=[cert])
        hr = _host_report(scan=scan)
        html = generate_dashboard([hr])
        assert "tl-bar" in html

    def test_timeline_no_certs_omits_tab(self):
        """QA-B3-12: All-error fleet should omit timeline tab."""
        scan = _make_scan(chain=[], error="Connection refused")
        hr = _host_report(scan=scan)
        html = generate_dashboard([hr])
        assert 'data-tab="timeline"' not in html


class TestLightTheme:
    """Feature 2: Light theme toggle."""

    def test_theme_toggle_button(self):
        html = generate_dashboard([_host_report()])
        assert "theme-toggle" in html

    def test_css_variables(self):
        html = generate_dashboard([_host_report()])
        assert "--bg-primary" in html
        assert "--text-primary" in html

    def test_light_theme_class(self):
        html = generate_dashboard([_host_report()])
        assert "light-theme" in html

    def test_localstorage_persistence(self):
        html = generate_dashboard([_host_report()])
        assert "localStorage" in html
        assert "notafter-theme" in html

    def test_toggle_function(self):
        html = generate_dashboard([_host_report()])
        assert "function toggleTheme" in html
