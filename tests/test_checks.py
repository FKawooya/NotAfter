"""Tests for certificate check engine."""

from datetime import datetime, timezone, timedelta

from notafter.checks.engine import (
    AuditReport,
    Finding,
    Severity,
    run_checks,
    check_expiry,
    check_key_strength,
    check_signature,
    check_san,
    check_self_signed,
    check_chain,
    check_tls_version,
)
from notafter.scanner.tls import CertInfo, ScanResult


def _make_cert(
    not_before: str | None = None,
    not_after: str | None = None,
    key_type: str = "RSA",
    key_size: int | None = 2048,
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
        findings = check_expiry(scan, 30)
        assert findings[0].severity == Severity.PASS

    def test_expired_cert(self):
        now = datetime.now(timezone.utc)
        cert = _make_cert(not_after=(now - timedelta(days=1)).isoformat())
        findings = check_expiry(_make_scan([cert]), 30)
        assert findings[0].severity == Severity.CRITICAL
        assert "EXPIRED" in findings[0].message

    def test_expiring_soon(self):
        now = datetime.now(timezone.utc)
        cert = _make_cert(not_after=(now + timedelta(days=10)).isoformat())
        findings = check_expiry(_make_scan([cert]), 30)
        assert findings[0].severity == Severity.WARNING

    def test_not_yet_valid(self):
        now = datetime.now(timezone.utc)
        cert = _make_cert(not_before=(now + timedelta(days=10)).isoformat())
        findings = check_expiry(_make_scan([cert]), 30)
        assert findings[0].severity == Severity.CRITICAL
        assert "Not yet valid" in findings[0].message


class TestKeyStrength:
    def test_rsa_2048(self):
        cert = _make_cert(key_type="RSA", key_size=2048)
        findings = check_key_strength(_make_scan([cert]), 30)
        assert findings[0].severity == Severity.WARNING  # meets minimum but 3072 recommended

    def test_rsa_1024(self):
        cert = _make_cert(key_type="RSA", key_size=1024)
        findings = check_key_strength(_make_scan([cert]), 30)
        assert findings[0].severity == Severity.CRITICAL

    def test_rsa_4096(self):
        cert = _make_cert(key_type="RSA", key_size=4096)
        findings = check_key_strength(_make_scan([cert]), 30)
        assert findings[0].severity == Severity.PASS

    def test_ec_p256(self):
        cert = _make_cert(key_type="EC-secp256r1", key_size=256)
        findings = check_key_strength(_make_scan([cert]), 30)
        assert findings[0].severity == Severity.PASS

    def test_ed25519(self):
        cert = _make_cert(key_type="Ed25519", key_size=256)
        findings = check_key_strength(_make_scan([cert]), 30)
        assert findings[0].severity == Severity.PASS

    def test_dsa_deprecated(self):
        cert = _make_cert(key_type="DSA", key_size=2048)
        findings = check_key_strength(_make_scan([cert]), 30)
        assert findings[0].severity == Severity.CRITICAL


class TestSignature:
    def test_sha256(self):
        findings = check_signature(_make_scan(), 30)
        assert findings[0].severity == Severity.PASS

    def test_sha1(self):
        cert = _make_cert(sig_name="sha1WithRSAEncryption")
        findings = check_signature(_make_scan([cert]), 30)
        assert findings[0].severity == Severity.CRITICAL

    def test_md5(self):
        cert = _make_cert(sig_name="md5WithRSAEncryption")
        findings = check_signature(_make_scan([cert]), 30)
        assert findings[0].severity == Severity.CRITICAL


class TestSAN:
    def test_has_san(self):
        findings = check_san(_make_scan(), 30)
        assert any(f.severity == Severity.PASS for f in findings)

    def test_no_san(self):
        cert = _make_cert(san_names=[])
        findings = check_san(_make_scan([cert]), 30)
        assert findings[0].severity == Severity.WARNING

    def test_wildcard_san(self):
        cert = _make_cert(san_names=["*.example.com"])
        findings = check_san(_make_scan([cert]), 30)
        assert any(f.severity == Severity.INFO for f in findings)


class TestSelfSigned:
    def test_not_self_signed(self):
        findings = check_self_signed(_make_scan(), 30)
        assert len(findings) == 0

    def test_self_signed_leaf(self):
        cert = _make_cert(is_self_signed=True, is_ca=False)
        findings = check_self_signed(_make_scan([cert]), 30)
        assert findings[0].severity == Severity.WARNING


class TestChain:
    def test_single_cert_not_self_signed(self):
        findings = check_chain(_make_scan(), 30)
        assert findings[0].severity == Severity.WARNING
        assert "missing" in findings[0].message.lower()

    def test_full_chain(self):
        certs = [_make_cert(), _make_cert(is_ca=True)]
        findings = check_chain(_make_scan(certs), 30)
        assert findings[0].severity == Severity.PASS


class TestTLSVersion:
    def test_tls13(self):
        scan = _make_scan(tls_version="TLSv1.3")
        findings = check_tls_version(scan, 30)
        assert findings[0].severity == Severity.PASS

    def test_tls12(self):
        scan = _make_scan(tls_version="TLSv1.2")
        findings = check_tls_version(scan, 30)
        assert findings[0].severity == Severity.PASS

    def test_tls10(self):
        scan = _make_scan(tls_version="TLSv1.0")
        findings = check_tls_version(scan, 30)
        assert findings[0].severity == Severity.CRITICAL

    def test_tls11(self):
        scan = _make_scan(tls_version="TLSv1.1")
        findings = check_tls_version(scan, 30)
        assert findings[0].severity == Severity.WARNING


class TestKeyStrengthRSANoneSize:
    """Q-H5: RSA cert with key_size=None should produce a WARNING finding."""

    def test_rsa_key_size_none_produces_warning(self):
        cert = _make_cert(key_type="RSA", key_size=None)
        scan = _make_scan([cert])
        findings = check_key_strength(scan, 30)
        # When key_size is None, the condition `kt == "RSA" and ks is not None`
        # is False, so no finding is produced for the RSA branch.
        # Per Q-H5: the expected behavior is a WARNING finding.
        # The code fix is being done in parallel — this test asserts expected behavior.
        has_warning = any(f.severity == Severity.WARNING for f in findings)
        assert has_warning, (
            "RSA cert with key_size=None should produce a WARNING finding. "
            f"Got findings: {[(f.severity, f.message) for f in findings]}"
        )


class TestRunChecksEmptyChain:
    """Q-M4: run_checks with empty chain but no error should return CRITICAL."""

    def test_empty_chain_no_error(self):
        scan = ScanResult(host="test.example.com", port=443, chain=[], error=None)
        report = run_checks(scan)
        assert report.critical_count >= 1
        crit_findings = [f for f in report.findings if f.severity == Severity.CRITICAL]
        assert any("No certificates" in f.message for f in crit_findings)


class TestSelfSignedRootCA:
    """Q-M5: self-signed root CA (is_self_signed=True, is_ca=True) should NOT warn."""

    def test_root_ca_self_signed_no_warning(self):
        root = _make_cert(is_self_signed=True, is_ca=True)
        scan = _make_scan([root])
        findings = check_self_signed(scan, 30)
        assert len(findings) == 0, (
            "Root CA (self-signed + is_ca) should not produce a self_signed warning"
        )


class TestTLSVersionNone:
    """Q-M6: check_tls_version with None tls_version should return empty."""

    def test_none_tls_version(self):
        scan = _make_scan(tls_version=None)
        findings = check_tls_version(scan, 30)
        assert len(findings) == 0


class TestCertLabelNoCN:
    """Q-L2: _cert_label with no CN in subject — should fallback to 'Leaf certificate'."""

    def test_cert_label_no_cn(self):
        from notafter.checks.engine import _cert_label
        cert = _make_cert()
        # Override subject to have no CN
        cert.subject = "O=Test Org,C=US"
        label = _cert_label(cert, 0)
        assert label == "Leaf certificate"


class TestShortCNLongSubject:
    """Q-L3: _short_cn with very long subject (>40 chars, no CN) — verify truncation."""

    def test_short_cn_truncation(self):
        from notafter.checks.engine import _short_cn
        long_rdn = "O=A Very Long Organization Name That Exceeds Forty Characters Easily And Keeps Going"
        result = _short_cn(long_rdn)
        assert len(result) <= 40


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
