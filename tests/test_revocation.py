"""Tests for revocation checking — OCSP, CRL, and CT (Q-H3)."""

import asyncio
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import (
    AuthorityInformationAccessOID,
    NameOID,
    ExtensionOID,
)
from cryptography.x509 import ocsp

from notafter.revocation.checker import (
    RevocationStatus,
    OCSPResult,
    CRLResult,
    CTResult,
    RevocationReport,
    check_revocation,
    _check_ocsp_async,
    _check_crl_async,
    _check_ct_async,
)
from notafter.scanner.tls import CertInfo


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_cert_info(
    san_names: list[str] | None = None,
    subject: str = "CN=test.example.com",
    cert: x509.Certificate | None = None,
) -> CertInfo:
    return CertInfo(
        subject=subject,
        issuer="CN=Test CA",
        not_before=datetime.now(timezone.utc).isoformat(),
        not_after=(datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
        serial="abc123",
        sig_algorithm_oid="1.2.840.113549.1.1.11",
        sig_algorithm_name="sha256WithRSAEncryption",
        key_type="RSA",
        key_size=2048,
        san_names=san_names if san_names is not None else ["test.example.com"],
        cert=cert,
    )


def _make_real_cert_and_issuer():
    """Generate a real leaf cert + issuer cert for OCSP/CRL testing."""
    # Issuer (CA)
    ca_key = rsa.generate_private_key(65537, 2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    now = datetime.now(timezone.utc)

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    # Leaf
    leaf_key = rsa.generate_private_key(65537, 2048)
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])

    leaf_builder = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.AuthorityInformationAccess([
                x509.AccessDescription(
                    AuthorityInformationAccessOID.OCSP,
                    x509.UniformResourceIdentifier("http://ocsp.example.com"),
                ),
            ]),
            critical=False,
        )
        .add_extension(
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier("http://crl.example.com/crl.der")],
                    relative_name=None,
                    crl_issuer=None,
                    reasons=None,
                ),
            ]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("test.example.com")]),
            critical=False,
        )
    )

    leaf_cert = leaf_builder.sign(ca_key, hashes.SHA256())

    return leaf_cert, ca_cert


def _make_async_client_mock(method="post", response=None, side_effect=None):
    """Create a mock httpx.AsyncClient for async wrapper tests."""
    mock_client = AsyncMock()
    if side_effect is not None:
        getattr(mock_client, method).side_effect = side_effect
    elif response is not None:
        getattr(mock_client, method).return_value = response
    return mock_client


# ===========================================================================
# OCSP tests
# ===========================================================================


class TestOCSPGood:
    def test_ocsp_good(self):
        leaf_cert, ca_cert = _make_real_cert_and_issuer()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b"fake-ocsp-response"
        mock_response.raise_for_status = MagicMock()

        mock_client = _make_async_client_mock(method="post", response=mock_response)

        with patch("notafter.revocation.checker.ocsp.load_der_ocsp_response") as mock_load:
            mock_ocsp_resp = MagicMock()
            mock_ocsp_resp.response_status = ocsp.OCSPResponseStatus.SUCCESSFUL
            mock_ocsp_resp.certificate_status = ocsp.OCSPCertStatus.GOOD
            mock_load.return_value = mock_ocsp_resp

            result = asyncio.run(_check_ocsp_async(leaf_cert, ca_cert, mock_client))

        assert result.status == RevocationStatus.GOOD
        assert "not revoked" in result.message.lower()


class TestOCSPRevoked:
    def test_ocsp_revoked(self):
        leaf_cert, ca_cert = _make_real_cert_and_issuer()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b"fake-ocsp-response"
        mock_response.raise_for_status = MagicMock()

        mock_client = _make_async_client_mock(method="post", response=mock_response)

        with patch("notafter.revocation.checker.ocsp.load_der_ocsp_response") as mock_load:
            mock_ocsp_resp = MagicMock()
            mock_ocsp_resp.response_status = ocsp.OCSPResponseStatus.SUCCESSFUL
            mock_ocsp_resp.certificate_status = ocsp.OCSPCertStatus.REVOKED
            mock_ocsp_resp.revocation_time = datetime(2025, 6, 15, tzinfo=timezone.utc)
            mock_load.return_value = mock_ocsp_resp

            result = asyncio.run(_check_ocsp_async(leaf_cert, ca_cert, mock_client))

        assert result.status == RevocationStatus.REVOKED
        assert "REVOKED" in result.message


class TestOCSPError:
    def test_ocsp_request_network_error(self):
        leaf_cert, ca_cert = _make_real_cert_and_issuer()

        mock_client = _make_async_client_mock(
            method="post",
            side_effect=Exception("network failure"),
        )

        result = asyncio.run(_check_ocsp_async(leaf_cert, ca_cert, mock_client))
        assert result.status == RevocationStatus.ERROR
        assert "failed" in result.message.lower()


class TestOCSPNoIssuer:
    def test_ocsp_no_issuer(self):
        leaf_cert, _ = _make_real_cert_and_issuer()
        mock_client = _make_async_client_mock()
        result = asyncio.run(_check_ocsp_async(leaf_cert, None, mock_client))
        assert result.status == RevocationStatus.UNKNOWN
        assert "issuer" in result.message.lower()


# ===========================================================================
# CRL tests
# ===========================================================================


class TestCRLGood:
    def test_crl_good(self):
        leaf_cert, ca_cert = _make_real_cert_and_issuer()

        # Build a real empty CRL (no revoked certs)
        from cryptography.x509 import CertificateRevocationListBuilder
        crl_builder = CertificateRevocationListBuilder()
        ca_key = rsa.generate_private_key(65537, 2048)
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
        now = datetime.now(timezone.utc)
        crl = (
            crl_builder
            .issuer_name(ca_name)
            .last_update(now)
            .next_update(now + timedelta(days=7))
            .sign(ca_key, hashes.SHA256())
        )
        crl_der = crl.public_bytes(serialization.Encoding.DER)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = crl_der
        mock_response.raise_for_status = MagicMock()

        mock_client = _make_async_client_mock(method="get", response=mock_response)

        result = asyncio.run(_check_crl_async(leaf_cert, mock_client))
        assert result.status == RevocationStatus.GOOD
        assert "not revoked" in result.message.lower()


class TestCRLRevoked:
    def test_crl_revoked(self):
        leaf_cert, ca_cert = _make_real_cert_and_issuer()

        # Build a CRL that includes the leaf's serial number
        from cryptography.x509 import (
            CertificateRevocationListBuilder,
            RevokedCertificateBuilder,
        )
        ca_key = rsa.generate_private_key(65537, 2048)
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
        now = datetime.now(timezone.utc)

        revoked_cert = (
            RevokedCertificateBuilder()
            .serial_number(leaf_cert.serial_number)
            .revocation_date(now - timedelta(days=1))
            .build()
        )

        crl = (
            CertificateRevocationListBuilder()
            .issuer_name(ca_name)
            .last_update(now)
            .next_update(now + timedelta(days=7))
            .add_revoked_certificate(revoked_cert)
            .sign(ca_key, hashes.SHA256())
        )
        crl_der = crl.public_bytes(serialization.Encoding.DER)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = crl_der
        mock_response.raise_for_status = MagicMock()

        mock_client = _make_async_client_mock(method="get", response=mock_response)

        result = asyncio.run(_check_crl_async(leaf_cert, mock_client))
        assert result.status == RevocationStatus.REVOKED
        assert "REVOKED" in result.message


class TestCRLDownloadFail:
    def test_crl_download_failure(self):
        leaf_cert, _ = _make_real_cert_and_issuer()

        mock_client = _make_async_client_mock(
            method="get",
            side_effect=Exception("connection reset"),
        )

        result = asyncio.run(_check_crl_async(leaf_cert, mock_client))
        assert result.status == RevocationStatus.ERROR
        assert "download failed" in result.message.lower()


# ===========================================================================
# CT tests
# ===========================================================================


class TestCTSuccess:
    def test_ct_found_entries(self):
        cert_info = _make_cert_info(san_names=["test.example.com"])

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b'[{"id": 1}, {"id": 2}]'
        mock_response.json.return_value = [{"id": 1}, {"id": 2}]

        mock_client = _make_async_client_mock(method="get", response=mock_response)

        result = asyncio.run(_check_ct_async(cert_info, mock_client))
        assert result.logged is True
        assert result.ct_entries == 2


class TestCTEmpty:
    def test_ct_no_entries(self):
        cert_info = _make_cert_info(san_names=["nolog.example.com"])

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b'[]'
        mock_response.json.return_value = []

        mock_client = _make_async_client_mock(method="get", response=mock_response)

        result = asyncio.run(_check_ct_async(cert_info, mock_client))
        assert result.logged is False
        assert result.ct_entries == 0


class TestCTError:
    def test_ct_network_error(self):
        cert_info = _make_cert_info(san_names=["fail.example.com"])

        mock_client = _make_async_client_mock(
            method="get",
            side_effect=Exception("DNS resolution failed"),
        )

        result = asyncio.run(_check_ct_async(cert_info, mock_client))
        assert "failed" in result.message.lower()


class TestCTNoDomain:
    def test_ct_no_domain_available(self):
        cert_info = _make_cert_info(san_names=[], subject="O=No CN Org")
        mock_client = _make_async_client_mock()
        result = asyncio.run(_check_ct_async(cert_info, mock_client))
        assert "No domain" in result.message


# ===========================================================================
# check_revocation integration (high level)
# ===========================================================================


class TestCheckRevocationNoCert:
    def test_no_parsed_cert(self):
        cert_info = _make_cert_info(cert=None)
        report = check_revocation(cert_info)
        assert "No parsed certificate" in report.ocsp.message
        assert "No parsed certificate" in report.crl.message


class TestRevocationReportIsRevoked:
    def test_is_revoked_property(self):
        report = RevocationReport()
        assert report.is_revoked is False

        report.ocsp.status = RevocationStatus.REVOKED
        assert report.is_revoked is True

        report.ocsp.status = RevocationStatus.GOOD
        report.crl.status = RevocationStatus.REVOKED
        assert report.is_revoked is True
