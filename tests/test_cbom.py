"""Tests for CBOM generation."""

import json

from notafter.cbom.generator import generate_cbom, cbom_to_json
from notafter.scanner.tls import CertInfo, ScanResult


def _make_scan() -> ScanResult:
    return ScanResult(
        host="example.com",
        port=443,
        tls_version="TLSv1.3",
        cipher_suite="TLS_AES_256_GCM_SHA384",
        key_exchange="ECDHE (TLS 1.3 default)",
        chain=[
            CertInfo(
                subject="CN=example.com",
                issuer="CN=DigiCert TLS RSA SHA256 2020 CA1",
                not_before="2025-01-01T00:00:00+00:00",
                not_after="2026-01-01T00:00:00+00:00",
                serial="abc123",
                sig_algorithm_oid="1.2.840.113549.1.1.11",
                sig_algorithm_name="sha256WithRSAEncryption",
                key_type="RSA",
                key_size=2048,
                san_names=["example.com", "www.example.com"],
                is_self_signed=False,
                is_ca=False,
            ),
        ],
    )


class TestCBOM:
    def test_generates_valid_structure(self):
        cbom = generate_cbom(_make_scan())
        assert cbom["bomFormat"] == "CycloneDX"
        assert cbom["specVersion"] == "1.6"
        assert "components" in cbom
        assert len(cbom["components"]) >= 1

    def test_cert_component(self):
        cbom = generate_cbom(_make_scan())
        cert_comp = cbom["components"][0]
        assert cert_comp["type"] == "cryptographic-asset"
        assert "cryptoProperties" in cert_comp
        props = cert_comp["cryptoProperties"]
        assert props["assetType"] == "certificate"
        assert props["quantumReadiness"] == "quantum-vulnerable"

    def test_tls_component_included(self):
        cbom = generate_cbom(_make_scan())
        tls_comps = [c for c in cbom["components"] if "tls-connection" in c.get("name", "")]
        assert len(tls_comps) == 1

    def test_json_serializable(self):
        cbom = generate_cbom(_make_scan())
        json_str = cbom_to_json(cbom)
        parsed = json.loads(json_str)
        assert parsed["bomFormat"] == "CycloneDX"

    def test_metadata_includes_tool(self):
        cbom = generate_cbom(_make_scan())
        tools = cbom["metadata"]["tools"]["components"]
        assert any(t["name"] == "notafter" for t in tools)


class TestCBOMPQCAlgorithm:
    """Q-M7: CBOM with PQC algorithms — test _cert_to_component with quantum-safe sig OID."""

    def test_cert_to_component_pqc_algorithm(self):
        from notafter.cbom.generator import _cert_to_component
        cert = CertInfo(
            subject="CN=pqc.example.com",
            issuer="CN=PQC CA",
            not_before="2025-01-01T00:00:00+00:00",
            not_after="2026-01-01T00:00:00+00:00",
            serial="pqc123",
            sig_algorithm_oid="2.16.840.1.101.3.4.3.18",  # ML-DSA-65
            sig_algorithm_name="ML-DSA-65",
            key_type="ML-DSA",
            key_size=None,
            san_names=["pqc.example.com"],
            is_self_signed=False,
            is_ca=False,
        )
        component = _cert_to_component(cert, 0, "pqc.example.com")
        assert component["cryptoProperties"]["quantumReadiness"] == "quantum-safe"
        assert component["cryptoProperties"]["algorithmProperties"]["signatureAlgorithm"] == "ML-DSA-65"


class TestCBOMLabelLogic:
    """Q-L4: _cert_to_component label logic — self-signed intermediate should be labeled 'root'."""

    def test_self_signed_intermediate_labeled_root(self):
        from notafter.cbom.generator import _cert_to_component
        cert = CertInfo(
            subject="CN=Root CA",
            issuer="CN=Root CA",
            not_before="2025-01-01T00:00:00+00:00",
            not_after="2035-01-01T00:00:00+00:00",
            serial="root123",
            sig_algorithm_oid="1.2.840.113549.1.1.11",
            sig_algorithm_name="sha256WithRSAEncryption",
            key_type="RSA",
            key_size=4096,
            is_self_signed=True,
            is_ca=True,
        )
        # Index > 0 (would normally be "intermediate") but is_self_signed=True -> "root"
        component = _cert_to_component(cert, 2, "example.com")
        assert "root" in component["name"]

    def test_leaf_labeled_leaf(self):
        from notafter.cbom.generator import _cert_to_component
        cert = CertInfo(
            subject="CN=leaf.example.com",
            issuer="CN=CA",
            not_before="2025-01-01T00:00:00+00:00",
            not_after="2026-01-01T00:00:00+00:00",
            serial="leaf123",
            sig_algorithm_oid="1.2.840.113549.1.1.11",
            sig_algorithm_name="sha256WithRSAEncryption",
            key_type="RSA",
            key_size=2048,
            is_self_signed=False,
            is_ca=False,
        )
        component = _cert_to_component(cert, 0, "example.com")
        assert "leaf" in component["name"]

    def test_non_self_signed_intermediate(self):
        from notafter.cbom.generator import _cert_to_component
        cert = CertInfo(
            subject="CN=Intermediate CA",
            issuer="CN=Root CA",
            not_before="2025-01-01T00:00:00+00:00",
            not_after="2030-01-01T00:00:00+00:00",
            serial="inter123",
            sig_algorithm_oid="1.2.840.113549.1.1.11",
            sig_algorithm_name="sha256WithRSAEncryption",
            key_type="RSA",
            key_size=4096,
            is_self_signed=False,
            is_ca=True,
        )
        component = _cert_to_component(cert, 1, "example.com")
        assert "intermediate" in component["name"]
