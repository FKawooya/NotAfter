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
