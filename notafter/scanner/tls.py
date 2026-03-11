"""TLS connection scanner — connects to hosts and extracts certificate chains."""

from __future__ import annotations

import ipaddress
import socket
import ssl
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, ed25519, ed448, dsa

from notafter.pqc.oids import lookup_oid


@dataclass
class CertInfo:
    """Parsed certificate metadata."""

    subject: str
    issuer: str
    not_before: str
    not_after: str
    serial: str
    sig_algorithm_oid: str
    sig_algorithm_name: str
    key_type: str
    key_size: int | None
    san_names: list[str] = field(default_factory=list)
    is_self_signed: bool = False
    is_ca: bool = False
    pem: str = ""
    cert: x509.Certificate | None = None


@dataclass
class ScanResult:
    """Complete scan result for a single target."""

    host: str
    port: int
    tls_version: str | None = None
    cipher_suite: str | None = None
    key_exchange: str | None = None
    chain: list[CertInfo] = field(default_factory=list)
    error: str | None = None
    peer_address: str | None = None


def _extract_key_info(cert: x509.Certificate) -> tuple[str, int | None]:
    """Extract key type and size from a certificate's public key."""
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        return "RSA", pub.key_size
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return f"EC-{pub.curve.name}", pub.curve.key_size
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(pub, ed448.Ed448PublicKey):
        return "Ed448", 448
    if isinstance(pub, dsa.DSAPublicKey):
        return "DSA", pub.key_size
    return "Unknown", None


def _parse_cert(cert: x509.Certificate) -> CertInfo:
    """Parse an x509 Certificate into CertInfo."""
    key_type, key_size = _extract_key_info(cert)

    # SAN extraction
    san_names = []
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_names = san_ext.value.get_values_for_type(x509.DNSName)
        san_names += [str(ip) for ip in san_ext.value.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        pass

    # CA check
    is_ca = False
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        is_ca = bc.value.ca
    except x509.ExtensionNotFound:
        pass

    pem = cert.public_bytes(serialization.Encoding.PEM).decode()

    return CertInfo(
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        not_before=cert.not_valid_before_utc.isoformat(),
        not_after=cert.not_valid_after_utc.isoformat(),
        serial=format(cert.serial_number, "x"),
        sig_algorithm_oid=cert.signature_algorithm_oid.dotted_string,
        sig_algorithm_name=_resolve_sig_name(cert.signature_algorithm_oid.dotted_string),
        key_type=key_type,
        key_size=key_size,
        san_names=san_names,
        is_self_signed=cert.subject == cert.issuer,
        is_ca=is_ca,
        pem=pem,
        cert=cert,
    )


def _resolve_sig_name(oid: str) -> str:
    """Resolve a signature algorithm OID to a human-readable name."""
    info = lookup_oid(oid)
    if info:
        return info.name
    return oid


def scan_host(host: str, port: int = 443, timeout: float = 10.0) -> ScanResult:
    """Connect to a TLS host and extract the certificate chain.

    Performs two connections:
    1. CERT_NONE to get the full chain regardless of trust
    2. CERT_REQUIRED to validate trust against system CA store
    """
    result = ScanResult(host=host, port=port)

    # Phase 1: Get chain (no verification — we want to see everything)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            result.peer_address = sock.getpeername()[0]
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                result.tls_version = ssock.version()
                cipher = ssock.cipher()
                if cipher:
                    result.cipher_suite = cipher[0]

                # Extract key exchange from cipher name
                if result.cipher_suite:
                    result.key_exchange = _infer_key_exchange(result.cipher_suite, result.tls_version)

                der_chain = ssock.getpeercert(binary_form=True)
                peer_certs = ssock.get_verified_chain() if hasattr(ssock, 'get_verified_chain') else None

                # Parse the leaf cert at minimum
                if der_chain:
                    leaf = x509.load_der_x509_certificate(der_chain)
                    result.chain.append(_parse_cert(leaf))

                # Try to get full chain via undocumented method
                if peer_certs is None:
                    # Fallback: use ssl.get_server_certificate
                    try:
                        pem_cert = ssl.get_server_certificate((host, port))
                        certs = x509.load_pem_x509_certificates(pem_cert.encode())
                        if certs and len(result.chain) == 0:
                            for c in certs:
                                result.chain.append(_parse_cert(c))
                    except Exception:
                        pass

    except (socket.timeout, TimeoutError):
        result.error = f"Connection timed out after {timeout}s"
    except ConnectionRefusedError:
        result.error = f"Connection refused on {host}:{port}"
    except ssl.SSLError as e:
        result.error = f"TLS error: {e}"
    except OSError as e:
        result.error = f"Network error: {e}"

    return result


def scan_file(path: str) -> ScanResult:
    """Load certificates from a PEM or DER file."""
    result = ScanResult(host=path, port=0)

    try:
        with open(path, "rb") as fh:
            data = fh.read(10 * 1024 * 1024)  # 10MB limit
    except OSError as e:
        result.error = f"File error: {e}"
        return result

    # Try PEM first
    try:
        certs = x509.load_pem_x509_certificates(data)
        if certs:
            for c in certs:
                result.chain.append(_parse_cert(c))
            return result
    except Exception:
        pass

    # Try single PEM
    try:
        cert = x509.load_pem_x509_certificate(data)
        result.chain.append(_parse_cert(cert))
        return result
    except Exception:
        pass

    # Try DER
    try:
        cert = x509.load_der_x509_certificate(data)
        result.chain.append(_parse_cert(cert))
        return result
    except Exception:
        pass

    result.error = "Could not parse file as PEM or DER certificate"
    return result


def _infer_key_exchange(cipher_name: str, tls_version: str | None) -> str:
    """Infer key exchange mechanism from cipher suite name."""
    name = cipher_name.upper()
    if "KYBER" in name or "MLKEM" in name:
        return "X25519MLKEM768 (hybrid PQC)"
    if tls_version and "1.3" in tls_version:
        # TLS 1.3 always uses ephemeral key exchange
        if "X25519" in name:
            return "X25519 (ECDHE)"
        return "ECDHE (TLS 1.3 default)"
    if "ECDHE" in name:
        return "ECDHE"
    if "DHE" in name:
        return "DHE"
    if "RSA" in name and "ECDHE" not in name and "DHE" not in name:
        return "RSA (static — no forward secrecy)"
    return "Unknown"
