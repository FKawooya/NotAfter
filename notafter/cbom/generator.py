"""Cryptographic Bill of Materials (CBOM) generator.

Outputs CycloneDX 1.6 format with cryptographic asset inventory.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from notafter.pqc.oids import classify_algorithm, QuantumSafety
from notafter.scanner.tls import ScanResult, CertInfo


def generate_cbom(scan: ScanResult) -> dict:
    """Generate a CycloneDX 1.6 CBOM from a scan result."""
    components = []

    for i, cert in enumerate(scan.chain):
        component = _cert_to_component(cert, i, scan.host)
        components.append(component)

    # Add TLS connection properties
    if scan.tls_version or scan.cipher_suite:
        components.append(_tls_component(scan))

    cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "notafter",
                        "version": "0.1.0",
                        "description": "PKI certificate auditor with PQC readiness scoring",
                    }
                ]
            },
            "component": {
                "type": "application",
                "name": scan.host,
                "description": f"TLS endpoint {scan.host}:{scan.port}",
            },
        },
        "components": components,
    }

    return cbom


def cbom_to_json(cbom: dict, indent: int = 2) -> str:
    """Serialize CBOM to JSON string."""
    return json.dumps(cbom, indent=indent, default=str)


def _cert_to_component(cert: CertInfo, index: int, host: str) -> dict:
    """Convert a certificate to a CycloneDX component."""
    label = "leaf" if index == 0 else f"intermediate-{index}" if not cert.is_self_signed else "root"
    safety = classify_algorithm(cert.sig_algorithm_oid)

    component = {
        "type": "cryptographic-asset",
        "name": f"{host}-{label}",
        "description": cert.subject,
        "cryptoProperties": {
            "assetType": "certificate",
            "algorithmProperties": {
                "algorithm": cert.key_type,
                "keySize": cert.key_size,
                "signatureAlgorithm": cert.sig_algorithm_name,
                "signatureAlgorithmOID": cert.sig_algorithm_oid,
            },
            "certificateProperties": {
                "subjectName": cert.subject,
                "issuerName": cert.issuer,
                "notBefore": cert.not_before,
                "notAfter": cert.not_after,
                "serialNumber": cert.serial,
                "subjectAlternativeNames": cert.san_names,
                "isSelfSigned": cert.is_self_signed,
                "isCA": cert.is_ca,
            },
            "quantumReadiness": safety.value,
        },
    }

    return component


def _tls_component(scan: ScanResult) -> dict:
    """Create a component for the TLS connection itself."""
    safety = QuantumSafety.QUANTUM_VULNERABLE
    if scan.key_exchange and ("kyber" in scan.key_exchange.lower() or "mlkem" in scan.key_exchange.lower()):
        safety = QuantumSafety.HYBRID

    return {
        "type": "cryptographic-asset",
        "name": f"{scan.host}-tls-connection",
        "description": f"TLS connection to {scan.host}:{scan.port}",
        "cryptoProperties": {
            "assetType": "protocol",
            "protocolProperties": {
                "tlsVersion": scan.tls_version,
                "cipherSuite": scan.cipher_suite,
                "keyExchange": scan.key_exchange,
            },
            "quantumReadiness": safety.value,
        },
    }
