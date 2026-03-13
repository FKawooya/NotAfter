"""Tests for fleet scanner utilities."""

import asyncio
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from notafter.scanner.fleet import load_targets, parse_target, scan_fleet
from notafter.scanner.tls import ScanResult


class TestLoadTargets:
    def test_cidr_small(self):
        targets = load_targets("192.168.1.0/30")
        assert len(targets) == 2  # .1 and .2 (excludes network and broadcast)

    def test_cidr_24(self):
        targets = load_targets("10.0.0.0/24")
        assert len(targets) == 254

    def test_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("example.com\n")
            f.write("# comment\n")
            f.write("google.com:8443\n")
            f.write("\n")
            f.write("github.com\n")
            f.name
        targets = load_targets(f.name)
        assert targets == ["example.com", "google.com:8443", "github.com"]
        Path(f.name).unlink()

    def test_cidr_too_large(self):
        with pytest.raises(ValueError, match="too large"):
            load_targets("10.0.0.0/8")

    def test_invalid_source(self):
        with pytest.raises(ValueError, match="Cannot parse"):
            load_targets("not_a_file_or_cidr")


class TestParseTarget:
    def test_host_only(self):
        assert parse_target("example.com", 443) == ("example.com", 443)

    def test_host_port(self):
        assert parse_target("example.com:8443", 443) == ("example.com", 8443)

    def test_ipv4(self):
        assert parse_target("10.0.0.1", 443) == ("10.0.0.1", 443)

    def test_ipv4_port(self):
        assert parse_target("10.0.0.1:8443", 443) == ("10.0.0.1", 8443)

    def test_ipv6_brackets(self):
        assert parse_target("[::1]:8443", 443) == ("::1", 8443)

    def test_ipv6_brackets_no_port(self):
        assert parse_target("[::1]", 443) == ("::1", 443)

    def test_ipv6_bare(self):
        assert parse_target("::1", 443) == ("::1", 443)

    def test_whitespace_stripped(self):
        assert parse_target("  example.com  ", 443) == ("example.com", 443)


# ===========================================================================
# Q-H4: scan_fleet tests (pytest-asyncio + mocked scan_host)
# ===========================================================================


def _mock_scan_host(host, port=443, timeout=10.0):
    """Return a fake ScanResult."""
    return ScanResult(host=host, port=port, tls_version="TLSv1.3")


def _mock_scan_host_error(host, port=443, timeout=10.0):
    """Return a ScanResult with an error."""
    return ScanResult(host=host, port=port, error=f"Connection refused on {host}:{port}")


class TestScanFleet:
    @pytest.mark.asyncio
    @patch("notafter.scanner.fleet.scan_host", side_effect=_mock_scan_host)
    async def test_multiple_hosts(self, mock_sh):
        targets = ["host1.example.com", "host2.example.com", "host3.example.com"]
        results = await scan_fleet(targets, port=443, concurrency=10, timeout=5.0)
        assert len(results) == 3
        hosts = {r.host for r in results}
        assert hosts == {"host1.example.com", "host2.example.com", "host3.example.com"}

    @pytest.mark.asyncio
    @patch("notafter.scanner.fleet.scan_host", side_effect=_mock_scan_host)
    async def test_concurrency_limiting(self, mock_sh):
        """With concurrency=2 and 5 targets, all should still complete."""
        targets = [f"host{i}.example.com" for i in range(5)]
        results = await scan_fleet(targets, concurrency=2, timeout=5.0)
        assert len(results) == 5

    @pytest.mark.asyncio
    @patch("notafter.scanner.fleet.scan_host", side_effect=_mock_scan_host_error)
    async def test_error_handling(self, mock_sh):
        targets = ["bad1.example.com", "bad2.example.com"]
        results = await scan_fleet(targets, timeout=5.0)
        assert len(results) == 2
        assert all(r.error is not None for r in results)

    @pytest.mark.asyncio
    @patch("notafter.scanner.fleet.scan_host", side_effect=_mock_scan_host)
    async def test_on_result_callback(self, mock_sh):
        callback_calls = []

        def on_result(result, index, total):
            callback_calls.append((result.host, index, total))

        targets = ["a.example.com", "b.example.com"]
        results = await scan_fleet(targets, on_result=on_result, timeout=5.0)
        assert len(results) == 2
        assert len(callback_calls) == 2
        # All callbacks should have total=2
        assert all(total == 2 for _, _, total in callback_calls)
