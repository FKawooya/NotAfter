"""Tests for certificate check engine."""

from datetime import datetime, timezone, timedelta

from notafter.checks.engine import (
    AuditReport,
    Finding,
    Severity,
    run_checks,
    _check_expiry,
    _check_key_strength,
    _check_signature,
    _check_san,
    _check_self_signed,
    _check_chain,
    _check_tls_version,
)
from notafter.scanner.tls import CertInfo, ScanResult


def _make_cert(
    not_before: str | None = None,
    not_after: str | None = None,
    key_type: str = "RSA",
    key_size: int = 2048,
    sig_name: str = "sha256WithRSAEncryption",
    sig_oid: str = "1.2.840.113549.1.1.11",
    san_names: list[str] | None = None,
    is_self_signed: bool = False,
    is_ca: bool = False,
) -> CertInfo:
    now = datetime.now(timezone.utc)
    return CertInfo(
        subject="CN=test.example.com",
        issuer="CN=Test CA" if not is_self_signed else "CN=test.example.com",
        not_before=not_before or (now - timedelta(days=30)).isoformat(),
        not_after=not_after or (now + timedelta(days=365)).isoformat(),
        serial="abc123",
        sig_algorithm_oid=sig_oid,
        sig_algorithm_name=sig_name,
        key_type=key_type,
        key_size=key_size,
        san_names=san_names if san_names is not None else ["test.example.com"],
        is_self_signed=is_self_signed,
        is_ca=is_ca,
    )


def _make_scan(certs: list[CertInfo] | None = None, **kwargs) -> ScanResult:
    return ScanResult(
        host="test.example.com",
        port=443,
        tls_version=kwargs.get("tls_version", "TLSv1.3"),
        cipher_suite=kwargs.get("cipher_suite"),
        chain=certs or [_make_cert()],
        error=kwargs.get("error"),
    )


class TestExpiry:
    def test_valid_cert(self):
        scan = _make_scan()
        findings = _check_expiry(scan, 30)
        assert findings[0].severity == Severity.PASS

    def test_expired_cert(self):
        now = datetime.now(timezone.utc)
        cert = _make_cert(not_after=(now - timedelta(days=1)).isoformat())
        findings = _check_expiry(_make_scan([cert]), 30)
        assert findings[0].severity == Severity.CRITICAL
        assert "EXPIRED" in findings[0].message

    def test_expiring_soon(self):
        now = datetime.now(timezone.utc)
        cert = _make_cert(not_after=(now + timedelta(days=10)).isoformat())
        findings = _check_expiry(_make_scan([cert]), 30)
        assert findings[0].severity == Severity.WARNING

    def test_not_yet_valid(self):
        now = datetime.now(timezone.utc)
        cert = _make_cert(not_before=(now + timedelta(days=10)).isoformat())
        findings = _check_expiry(_make_scan([cert]), 30)
        assert findings[0].severity == Severity.CRITICAL
        assert "Not yet valid" in findings[0].message


class TestKeyStrength:
    def test_rsa_2048(self):
        cert = _make_cert(key_type="RSA", key_size=2048)
        findings = _check_key_strength(_make_scan([cert]), 30)
        assert findings[0].severity == Severity.WARNING  # meets minimum but 3072 recommended

    def test_rsa_1024(self):
        cert = _make_cert(key_type="RSA", key_size=1024)
        findings = _check_key_strength(_make_scan([cert]), 30)
        assert findings[0].severity == Severity.CRITICAL

    def test_rsa_4096(self):
        cert = _make_cert(key_type="RSA", key_size=4096)
        findings = _check_key_strength(_make_scan([cert]), 30)
        assert findings[0].severity == Severity.PASS

    def test_ec_p256(self):
        cert = _make_cert(key_type="EC-secp256r1", key_size=256)
        findings = _check_key_strength(_make_scan([cert]), 30)
        assert findings[0].severity == Severity.PASS

    def test_ed25519(self):
        cert = _make_cert(key_type="Ed25519", key_size=256)
        findings = _check_key_strength(_make_scan([cert]), 30)
        assert findings[0].severity == Severity.PASS

    def test_dsa_deprecated(self):
        cert = _make_cert(key_type="DSA", key_size=2048)
        findings = _check_key_strength(_make_scan([cert]), 30)
        assert findings[0].severity == Severity.CRITICAL


class TestSignature:
    def test_sha256(self):
        findings = _check_signature(_make_scan(), 30)
        assert findings[0].severity == Severity.PASS

    def test_sha1(self):
        cert = _make_cert(sig_name="sha1WithRSAEncryption")
        findings = _check_signature(_make_scan([cert]), 30)
        assert findings[0].severity == Severity.CRITICAL

    def test_md5(self):
        cert = _make_cert(sig_name="md5WithRSAEncryption")
        findings = _check_signature(_make_scan([cert]), 30)
        assert findings[0].severity == Severity.CRITICAL


class TestSAN:
    def test_has_san(self):
        findings = _check_san(_make_scan(), 30)
        assert any(f.severity == Severity.PASS for f in findings)

    def test_no_san(self):
        cert = _make_cert(san_names=[])
        findings = _check_san(_make_scan([cert]), 30)
        assert findings[0].severity == Severity.WARNING

    def test_wildcard_san(self):
        cert = _make_cert(san_names=["*.example.com"])
        findings = _check_san(_make_scan([cert]), 30)
        assert any(f.severity == Severity.INFO for f in findings)


class TestSelfSigned:
    def test_not_self_signed(self):
        findings = _check_self_signed(_make_scan(), 30)
        assert len(findings) == 0

    def test_self_signed_leaf(self):
        cert = _make_cert(is_self_signed=True, is_ca=False)
        findings = _check_self_signed(_make_scan([cert]), 30)
        assert findings[0].severity == Severity.WARNING


class TestChain:
    def test_single_cert_not_self_signed(self):
        findings = _check_chain(_make_scan(), 30)
        assert findings[0].severity == Severity.WARNING
        assert "missing" in findings[0].message.lower()

    def test_full_chain(self):
        certs = [_make_cert(), _make_cert(is_ca=True)]
        findings = _check_chain(_make_scan(certs), 30)
        assert findings[0].severity == Severity.PASS


class TestTLSVersion:
    def test_tls13(self):
        scan = _make_scan(tls_version="TLSv1.3")
        findings = _check_tls_version(scan, 30)
        assert findings[0].severity == Severity.PASS

    def test_tls12(self):
        scan = _make_scan(tls_version="TLSv1.2")
        findings = _check_tls_version(scan, 30)
        assert findings[0].severity == Severity.PASS

    def test_tls10(self):
        scan = _make_scan(tls_version="TLSv1.0")
        findings = _check_tls_version(scan, 30)
        assert findings[0].severity == Severity.CRITICAL

    def test_tls11(self):
        scan = _make_scan(tls_version="TLSv1.1")
        findings = _check_tls_version(scan, 30)
        assert findings[0].severity == Severity.WARNING


class TestAuditReport:
    def test_exit_code_clean(self):
        report = AuditReport(target="test", findings=[
            Finding(check="test", severity=Severity.PASS, component="test", message="ok"),
        ])
        assert report.exit_code == 0

    def test_exit_code_warning(self):
        report = AuditReport(target="test", findings=[
            Finding(check="test", severity=Severity.WARNING, component="test", message="warn"),
        ])
        assert report.exit_code == 1

    def test_exit_code_critical(self):
        report = AuditReport(target="test", findings=[
            Finding(check="test", severity=Severity.CRITICAL, component="test", message="crit"),
        ])
        assert report.exit_code == 2

    def test_connection_error(self):
        scan = ScanResult(host="bad", port=443, error="Connection refused")
        report = run_checks(scan)
        assert report.critical_count == 1
