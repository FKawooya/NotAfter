"""Tests for fleet scanner utilities."""

import tempfile
from pathlib import Path

from notafter.scanner.fleet import load_targets, parse_target


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
        import pytest
        with pytest.raises(ValueError, match="too large"):
            load_targets("10.0.0.0/8")

    def test_invalid_source(self):
        import pytest
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
