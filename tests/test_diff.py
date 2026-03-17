"""Tests for the diff module."""

import json

import pytest
from click.testing import CliRunner

from notafter.cli import cli
from notafter.diff import (
    CertChange,
    DiffReport,
    FindingChanges,
    HostDiff,
    PQCChanges,
    detect_format,
    diff_reports,
    diff_to_json,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _single_scan(**overrides) -> dict:
    base = {
        "target": "example.com:443",
        "tls_version": "TLSv1.3",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "key_exchange": "ECDHE",
        "chain": [
            {
                "subject": "CN=example.com",
                "issuer": "CN=Test CA",
                "not_before": "2025-01-01T00:00:00+00:00",
                "not_after": "2026-01-01T00:00:00+00:00",
                "sig_algorithm": "sha256WithRSAEncryption",
                "key_type": "RSA",
                "key_size": 2048,
                "san": ["example.com"],
                "is_ca": False,
                "self_signed": False,
            },
        ],
        "audit": {
            "critical": 0,
            "warnings": 1,
            "passed": 5,
            "exit_code": 1,
            "findings": [
                {
                    "check": "key_strength",
                    "severity": "warning",
                    "component": "CN=example.com",
                    "message": "RSA-2048: weak",
                    "remediation": "Use RSA-3072+",
                },
            ],
        },
        "pqc": {
            "score": 2,
            "max_score": 10,
            "grade": "F",
            "ready": False,
            "overall_safety": "quantum-vulnerable",
        },
    }
    base.update(overrides)
    return base


def _fleet_entry(host="example.com", port=443, **overrides) -> dict:
    base = {
        "host": host,
        "port": port,
        "error": None,
        "tls_version": "TLSv1.3",
        "critical": 0,
        "warnings": 1,
        "pqc_score": 2,
        "pqc_grade": "F",
    }
    base.update(overrides)
    return base


# ===========================================================================
# Format Detection
# ===========================================================================


class TestFormatDetection:
    def test_single_format(self):
        assert detect_format(_single_scan()) == "single"

    def test_fleet_format(self):
        assert detect_format([_fleet_entry()]) == "fleet"

    def test_invalid_format(self):
        with pytest.raises(ValueError, match="Unrecognized"):
            detect_format({"not": "a scan"})

    def test_format_mismatch(self):
        with pytest.raises(ValueError, match="Format mismatch"):
            diff_reports(_single_scan(), [_fleet_entry()])


# ===========================================================================
# Single Scan Diff
# ===========================================================================


class TestSingleDiff:
    def test_no_changes(self):
        scan = _single_scan()
        report = diff_reports(scan, scan.copy())
        assert not report.has_changes
        assert report.total_changes == 0

    def test_cert_renewed(self):
        old = _single_scan()
        new = _single_scan()
        new["chain"][0]["not_after"] = "2027-06-01T00:00:00+00:00"
        report = diff_reports(old, new)
        assert report.has_changes
        hd = report.host_diffs[0]
        assert hd.status == "changed"
        assert len(hd.cert_changes) == 1
        assert hd.cert_changes[0].type == "renewed"
        assert "2027-06-01" in hd.cert_changes[0].details["new_expiry"]

    def test_cert_added(self):
        old = _single_scan()
        new = _single_scan()
        new["chain"].append({
            "subject": "CN=New Intermediate",
            "issuer": "CN=Root",
            "not_before": "2025-01-01T00:00:00+00:00",
            "not_after": "2030-01-01T00:00:00+00:00",
            "sig_algorithm": "sha256WithRSAEncryption",
            "key_type": "RSA",
            "key_size": 2048,
        })
        report = diff_reports(old, new)
        assert report.has_changes
        added = [c for c in report.host_diffs[0].cert_changes if c.type == "added"]
        assert len(added) == 1
        assert "New Intermediate" in added[0].subject

    def test_cert_removed(self):
        old = _single_scan()
        old["chain"].append({
            "subject": "CN=Old Intermediate",
            "issuer": "CN=Root",
            "not_before": "2024-01-01T00:00:00+00:00",
            "not_after": "2025-01-01T00:00:00+00:00",
            "sig_algorithm": "sha256WithRSAEncryption",
            "key_type": "RSA",
            "key_size": 2048,
        })
        new = _single_scan()
        report = diff_reports(old, new)
        removed = [c for c in report.host_diffs[0].cert_changes if c.type == "removed"]
        assert len(removed) == 1

    def test_finding_added(self):
        old = _single_scan()
        new = _single_scan()
        new["audit"]["findings"].append({
            "check": "expiry",
            "severity": "critical",
            "component": "CN=example.com",
            "message": "Expired",
            "remediation": "Renew",
        })
        report = diff_reports(old, new)
        assert report.has_changes
        fc = report.host_diffs[0].finding_changes
        assert len(fc.new_findings) == 1
        assert fc.new_findings[0]["check"] == "expiry"

    def test_finding_resolved(self):
        old = _single_scan()
        new = _single_scan()
        new["audit"]["findings"] = []  # all findings resolved
        report = diff_reports(old, new)
        assert report.has_changes
        fc = report.host_diffs[0].finding_changes
        assert len(fc.resolved_findings) == 1

    def test_pqc_improved(self):
        old = _single_scan()
        new = _single_scan()
        new["pqc"]["score"] = 7
        new["pqc"]["grade"] = "B"
        report = diff_reports(old, new)
        assert report.has_changes
        pc = report.host_diffs[0].pqc_changes
        assert pc.direction == "improved"
        assert pc.old_score == 2
        assert pc.new_score == 7

    def test_tls_version_change(self):
        old = _single_scan()
        new = _single_scan()
        new["tls_version"] = "TLSv1.2"
        report = diff_reports(old, new)
        hd = report.host_diffs[0]
        assert hd.tls_old == "TLSv1.3"
        assert hd.tls_new == "TLSv1.2"

    def test_algorithm_change(self):
        old = _single_scan()
        new = _single_scan()
        new["chain"][0]["sig_algorithm"] = "sha384WithRSAEncryption"
        report = diff_reports(old, new)
        cc = report.host_diffs[0].cert_changes[0]
        assert cc.type == "modified"
        assert "sha384" in cc.details["new_algorithm"]


# ===========================================================================
# Fleet Diff
# ===========================================================================


class TestFleetDiff:
    def test_no_changes(self):
        fleet = [_fleet_entry()]
        report = diff_reports(fleet, fleet.copy())
        assert not report.has_changes

    def test_host_added(self):
        old = [_fleet_entry("h1")]
        new = [_fleet_entry("h1"), _fleet_entry("h2")]
        report = diff_reports(old, new)
        assert report.has_changes
        added = [h for h in report.host_diffs if h.status == "added"]
        assert len(added) == 1
        assert added[0].host == "h2:443"

    def test_host_removed(self):
        old = [_fleet_entry("h1"), _fleet_entry("h2")]
        new = [_fleet_entry("h1")]
        report = diff_reports(old, new)
        removed = [h for h in report.host_diffs if h.status == "removed"]
        assert len(removed) == 1

    def test_score_change(self):
        old = [_fleet_entry("h1", pqc_score=2, pqc_grade="F")]
        new = [_fleet_entry("h1", pqc_score=5, pqc_grade="C")]
        report = diff_reports(old, new)
        hd = [h for h in report.host_diffs if h.status == "changed"][0]
        assert hd.pqc_changes.direction == "improved"

    def test_critical_count_increase(self):
        old = [_fleet_entry("h1", critical=0)]
        new = [_fleet_entry("h1", critical=2)]
        report = diff_reports(old, new)
        hd = [h for h in report.host_diffs if h.status == "changed"][0]
        assert len(hd.finding_changes.new_findings) == 1


# ===========================================================================
# JSON Serialization
# ===========================================================================


class TestDiffJson:
    def test_serialize_roundtrip(self):
        old = _single_scan()
        new = _single_scan()
        new["chain"][0]["not_after"] = "2027-06-01T00:00:00+00:00"
        report = diff_reports(old, new)
        result = diff_to_json(report)
        assert result["total_changes"] == 1
        assert result["format"] == "single"
        assert len(result["host_diffs"]) == 1
        # Should be JSON-serializable
        json.dumps(result)

    def test_no_changes_json(self):
        scan = _single_scan()
        report = diff_reports(scan, scan.copy())
        result = diff_to_json(report)
        assert result["total_changes"] == 0


# ===========================================================================
# CLI Integration
# ===========================================================================


class TestDiffCli:
    def test_diff_command_exists(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["diff", "--help"])
        assert result.exit_code == 0
        assert "Compare two NotAfter JSON" in result.output

    def test_diff_no_changes_exit_0(self, tmp_path):
        scan = _single_scan()
        f1 = tmp_path / "baseline.json"
        f2 = tmp_path / "current.json"
        f1.write_text(json.dumps(scan))
        f2.write_text(json.dumps(scan))
        runner = CliRunner()
        result = runner.invoke(cli, ["diff", str(f1), str(f2)])
        assert result.exit_code == 0
        assert "No changes" in result.output

    def test_diff_with_changes_exit_1(self, tmp_path):
        old = _single_scan()
        new = _single_scan()
        new["chain"][0]["not_after"] = "2027-06-01T00:00:00+00:00"
        f1 = tmp_path / "baseline.json"
        f2 = tmp_path / "current.json"
        f1.write_text(json.dumps(old))
        f2.write_text(json.dumps(new))
        runner = CliRunner()
        result = runner.invoke(cli, ["diff", str(f1), str(f2)])
        assert result.exit_code == 1
        assert "change" in result.output.lower()

    def test_diff_json_output(self, tmp_path):
        old = _single_scan()
        new = _single_scan()
        new["pqc"]["score"] = 8
        new["pqc"]["grade"] = "B"
        f1 = tmp_path / "baseline.json"
        f2 = tmp_path / "current.json"
        f1.write_text(json.dumps(old))
        f2.write_text(json.dumps(new))
        runner = CliRunner()
        result = runner.invoke(cli, ["diff", str(f1), str(f2), "--json"])
        assert result.exit_code == 1
        output = json.loads(result.output)
        assert output["total_changes"] == 1


# ===========================================================================
# Edge Cases
# ===========================================================================


class TestDiffEdgeCases:
    def test_empty_chains(self):
        old = _single_scan()
        old["chain"] = []
        new = _single_scan()
        new["chain"] = []
        report = diff_reports(old, new)
        assert report.host_diffs[0].cert_changes == []

    def test_missing_pqc_both(self):
        old = _single_scan()
        del old["pqc"]
        new = _single_scan()
        del new["pqc"]
        report = diff_reports(old, new)
        assert report.host_diffs[0].pqc_changes is None

    def test_missing_audit(self):
        old = _single_scan()
        old["audit"]["findings"] = []
        new = _single_scan()
        new["audit"]["findings"] = []
        report = diff_reports(old, new)
        fc = report.host_diffs[0].finding_changes
        assert len(fc.new_findings) == 0
        assert len(fc.resolved_findings) == 0

    def test_empty_fleet(self):
        report = diff_reports([], [])
        assert not report.has_changes
        assert report.host_diffs == []

    def test_pqc_degraded(self):
        pc = PQCChanges(old_score=8, new_score=3, old_grade="B", new_grade="D")
        assert pc.direction == "degraded"

    def test_pqc_unchanged(self):
        pc = PQCChanges(old_score=5, new_score=5, old_grade="C", new_grade="C")
        assert pc.direction == "unchanged"

    def test_duplicate_subjects_in_chain(self):
        """QA-D4-1: Duplicate subjects should not silently drop certs."""
        old = _single_scan()
        old["chain"].append({
            "subject": "CN=example.com",
            "issuer": "CN=Other CA",
            "not_before": "2024-01-01T00:00:00+00:00",
            "not_after": "2025-06-01T00:00:00+00:00",
            "sig_algorithm": "sha256WithRSAEncryption",
            "key_type": "RSA",
            "key_size": 2048,
        })
        new = _single_scan()
        # new has only 1 cert with that subject — should detect removal
        report = diff_reports(old, new)
        removed = [c for c in report.host_diffs[0].cert_changes if c.type == "removed"]
        assert len(removed) == 1

    def test_empty_subject_skipped(self):
        """QA-D4-5: Empty subject certs should not create false matches."""
        old = _single_scan()
        old["chain"][0]["subject"] = ""
        new = _single_scan()
        new["chain"][0]["subject"] = ""
        report = diff_reports(old, new)
        assert report.host_diffs[0].cert_changes == []

    def test_malformed_json_baseline(self, tmp_path):
        """SEC-D4-4: Malformed JSON should give clean error."""
        f1 = tmp_path / "bad.json"
        f1.write_text("not json {{{")
        f2 = tmp_path / "good.json"
        f2.write_text(json.dumps(_single_scan()))
        runner = CliRunner()
        result = runner.invoke(cli, ["diff", str(f1), str(f2)])
        assert result.exit_code != 0
        assert "Invalid JSON" in result.output

    def test_malformed_json_current(self, tmp_path):
        f1 = tmp_path / "good.json"
        f1.write_text(json.dumps(_single_scan()))
        f2 = tmp_path / "bad.json"
        f2.write_text("oops")
        runner = CliRunner()
        result = runner.invoke(cli, ["diff", str(f1), str(f2)])
        assert result.exit_code != 0
        assert "Invalid JSON" in result.output

    def test_fleet_missing_host_key(self):
        """QA-D4-4: Fleet entries missing host should not crash."""
        old = [{"port": 443, "critical": 0, "warnings": 0}]
        new = [{"port": 443, "critical": 0, "warnings": 0}]
        report = diff_reports(old, new)
        assert report.format == "fleet"

    def test_multi_port_same_host(self):
        """QA-D4-14: Same host on different ports tracked independently."""
        old = [_fleet_entry("h1", port=443), _fleet_entry("h1", port=8443)]
        new = [_fleet_entry("h1", port=443)]
        report = diff_reports(old, new)
        removed = [h for h in report.host_diffs if h.status == "removed"]
        assert len(removed) == 1
        assert removed[0].host == "h1:8443"
