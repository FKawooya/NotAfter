"""Revocation checking — OCSP, CRL, and Certificate Transparency in one pass."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.x509 import ocsp

from notafter.scanner.tls import CertInfo

MAX_OCSP_RESPONSE_SIZE = 1 * 1024 * 1024   # 1MB
MAX_CRL_RESPONSE_SIZE = 20 * 1024 * 1024    # 20MB
MAX_CT_RESPONSE_SIZE = 10 * 1024 * 1024     # 10MB
ALLOWED_URL_SCHEMES = {"http", "https"}


class RevocationStatus(Enum):
    GOOD = "good"
    REVOKED = "revoked"
    UNKNOWN = "unknown"
    ERROR = "error"
    SKIPPED = "skipped"


@dataclass
class OCSPResult:
    status: RevocationStatus = RevocationStatus.SKIPPED
    responder_url: str = ""
    message: str = ""


@dataclass
class CRLResult:
    status: RevocationStatus = RevocationStatus.SKIPPED
    crl_url: str = ""
    message: str = ""


@dataclass
class CTResult:
    logged: bool | None = None
    ct_entries: int = 0
    message: str = ""
    crt_sh_url: str = ""


@dataclass
class RevocationReport:
    ocsp: OCSPResult = field(default_factory=OCSPResult)
    crl: CRLResult = field(default_factory=CRLResult)
    ct: CTResult = field(default_factory=CTResult)

    @property
    def is_revoked(self) -> bool:
        return (
            self.ocsp.status == RevocationStatus.REVOKED
            or self.crl.status == RevocationStatus.REVOKED
        )


def _validate_url(url: str) -> str | None:
    """Validate that a URL uses an allowed scheme. Returns error message or None."""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ALLOWED_URL_SCHEMES:
            return f"Rejected URL scheme '{parsed.scheme}' (only http/https allowed)"
    except Exception:
        return f"Invalid URL: {url}"
    return None


def check_revocation(
    cert_info: CertInfo,
    issuer_info: CertInfo | None = None,
    check_ct: bool = True,
    timeout: float = 10.0,
) -> RevocationReport:
    """Check revocation status via OCSP, CRL, and CT logs."""
    report = RevocationReport()

    cert = cert_info.cert
    issuer_cert = issuer_info.cert if issuer_info else None

    if cert is None:
        report.ocsp.message = "No parsed certificate available"
        report.crl.message = "No parsed certificate available"
        return report

    # OCSP
    report.ocsp = _check_ocsp(cert, issuer_cert, timeout)

    # CRL
    report.crl = _check_crl(cert, timeout)

    # CT
    if check_ct:
        report.ct = _check_ct(cert_info, timeout)

    return report


def _check_ocsp(
    cert: x509.Certificate,
    issuer: x509.Certificate | None,
    timeout: float,
) -> OCSPResult:
    """Check OCSP responder for revocation status."""
    result = OCSPResult()

    # Extract OCSP responder URL from AIA extension
    try:
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
        ocsp_urls = [
            desc.access_location.value
            for desc in aia.value
            if desc.access_method == x509.oid.AuthorityInformationAccessOID.OCSP
        ]
    except x509.ExtensionNotFound:
        result.message = "No AIA extension — OCSP not available"
        return result

    if not ocsp_urls:
        result.message = "No OCSP responder in AIA"
        return result

    result.responder_url = ocsp_urls[0]

    # Validate URL scheme
    url_error = _validate_url(result.responder_url)
    if url_error:
        result.status = RevocationStatus.ERROR
        result.message = url_error
        return result

    if issuer is None:
        result.status = RevocationStatus.UNKNOWN
        result.message = "No issuer certificate — cannot build OCSP request"
        return result

    # Build OCSP request
    try:
        builder = ocsp.OCSPRequestBuilder()
        builder = builder.add_certificate(cert, issuer, SHA1())
        ocsp_request = builder.build()
        request_data = ocsp_request.public_bytes(serialization.Encoding.DER)
    except Exception as e:
        result.status = RevocationStatus.ERROR
        result.message = f"Failed to build OCSP request: {e}"
        return result

    # Send OCSP request
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True, max_redirects=5) as client:
            response = client.post(
                result.responder_url,
                content=request_data,
                headers={"Content-Type": "application/ocsp-request"},
            )
            response.raise_for_status()

            if len(response.content) > MAX_OCSP_RESPONSE_SIZE:
                result.status = RevocationStatus.ERROR
                result.message = f"OCSP response too large ({len(response.content)} bytes)"
                return result
    except Exception as e:
        result.status = RevocationStatus.ERROR
        result.message = f"OCSP request failed: {e}"
        return result

    # Parse OCSP response
    try:
        ocsp_response = ocsp.load_der_ocsp_response(response.content)
        if ocsp_response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
            result.status = RevocationStatus.ERROR
            result.message = f"OCSP response status: {ocsp_response.response_status.name}"
            return result

        cert_status = ocsp_response.certificate_status
        if cert_status == ocsp.OCSPCertStatus.GOOD:
            result.status = RevocationStatus.GOOD
            result.message = "Certificate is not revoked (OCSP)"
        elif cert_status == ocsp.OCSPCertStatus.REVOKED:
            result.status = RevocationStatus.REVOKED
            revocation_time = ocsp_response.revocation_time
            result.message = f"REVOKED via OCSP (revocation time: {revocation_time})"
        else:
            result.status = RevocationStatus.UNKNOWN
            result.message = "OCSP status unknown"
    except Exception as e:
        result.status = RevocationStatus.ERROR
        result.message = f"Failed to parse OCSP response: {e}"

    return result


def _check_crl(cert: x509.Certificate, timeout: float) -> CRLResult:
    """Download and check CRL for revocation."""
    result = CRLResult()

    # Extract CRL distribution points
    try:
        cdp = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
        crl_urls = []
        for dp in cdp.value:
            if dp.full_name:
                for name in dp.full_name:
                    if isinstance(name, x509.UniformResourceIdentifier):
                        crl_urls.append(name.value)
    except x509.ExtensionNotFound:
        result.message = "No CRL distribution points"
        return result

    if not crl_urls:
        result.message = "No HTTP CRL URLs found"
        return result

    result.crl_url = crl_urls[0]

    # Validate URL scheme
    url_error = _validate_url(result.crl_url)
    if url_error:
        result.status = RevocationStatus.ERROR
        result.message = url_error
        return result

    # Download CRL
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True, max_redirects=5) as client:
            response = client.get(result.crl_url)
            response.raise_for_status()

            if len(response.content) > MAX_CRL_RESPONSE_SIZE:
                result.status = RevocationStatus.ERROR
                result.message = f"CRL too large ({len(response.content)} bytes, max {MAX_CRL_RESPONSE_SIZE})"
                return result
    except Exception as e:
        result.status = RevocationStatus.ERROR
        result.message = f"CRL download failed: {e}"
        return result

    # Parse CRL and check serial
    try:
        crl = x509.load_der_x509_crl(response.content)
        revoked = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
        if revoked is not None:
            result.status = RevocationStatus.REVOKED
            result.message = f"REVOKED via CRL (serial {format(cert.serial_number, 'x')})"
        else:
            result.status = RevocationStatus.GOOD
            result.message = "Certificate not found in CRL (not revoked)"
    except Exception:
        # Try PEM format
        try:
            crl = x509.load_pem_x509_crl(response.content)
            revoked = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
            if revoked is not None:
                result.status = RevocationStatus.REVOKED
                result.message = "REVOKED via CRL"
            else:
                result.status = RevocationStatus.GOOD
                result.message = "Certificate not found in CRL (not revoked)"
        except Exception as e:
            result.status = RevocationStatus.ERROR
            result.message = f"Failed to parse CRL: {e}"

    return result


def _check_ct(cert_info: CertInfo, timeout: float) -> CTResult:
    """Check Certificate Transparency logs via crt.sh."""
    result = CTResult()

    # Use the first SAN or subject CN to query crt.sh
    query = None
    if cert_info.san_names:
        query = cert_info.san_names[0]
    else:
        for part in cert_info.subject.split(","):
            if "CN=" in part:
                query = part.strip().replace("CN=", "")
                break

    if not query:
        result.message = "No domain name to query CT logs"
        return result

    # Strip wildcard prefix
    if query.startswith("*."):
        query = query[2:]

    result.crt_sh_url = f"https://crt.sh/?q={query}"

    try:
        with httpx.Client(timeout=timeout, follow_redirects=True, max_redirects=5) as client:
            response = client.get(
                "https://crt.sh/",
                params={"q": query, "output": "json"},
                headers={"Accept": "application/json"},
            )
            if len(response.content) > MAX_CT_RESPONSE_SIZE:
                result.message = "CT response too large"
                return result
            if response.status_code == 200:
                entries = response.json()
                result.ct_entries = len(entries)
                result.logged = result.ct_entries > 0
                result.message = (
                    f"Found {result.ct_entries} CT log entries for {query}"
                    if result.logged
                    else f"No CT log entries found for {query}"
                )
            else:
                result.message = f"crt.sh returned HTTP {response.status_code}"
    except Exception as e:
        result.message = f"CT log query failed: {e}"

    return result
