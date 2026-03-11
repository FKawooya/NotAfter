"""Tests for PQC OID database and classification."""

from notafter.pqc.oids import (
    AlgorithmType,
    QuantumSafety,
    all_algorithms,
    classify_algorithm,
    is_pqc_safe,
    lookup_oid,
)


class TestOIDLookup:
    def test_rsa_sha256(self):
        info = lookup_oid("1.2.840.113549.1.1.11")
        assert info is not None
        assert info.name == "SHA256WithRSAEncryption"
        assert info.quantum_safety == QuantumSafety.QUANTUM_VULNERABLE

    def test_ml_dsa_65(self):
        info = lookup_oid("2.16.840.1.101.3.4.3.18")
        assert info is not None
        assert info.name == "ML-DSA-65"
        assert info.quantum_safety == QuantumSafety.QUANTUM_SAFE
        assert info.cnsa2_approved is True
        assert info.nist_level == 3

    def test_ml_dsa_87(self):
        info = lookup_oid("2.16.840.1.101.3.4.3.19")
        assert info is not None
        assert info.cnsa2_approved is True
        assert info.nist_level == 5

    def test_ml_kem_768(self):
        info = lookup_oid("2.16.840.1.101.3.4.4.2")
        assert info is not None
        assert info.name == "ML-KEM-768"
        assert info.algo_type == AlgorithmType.KEY_EXCHANGE

    def test_slh_dsa_sha2_256s(self):
        info = lookup_oid("2.16.840.1.101.3.4.3.24")
        assert info is not None
        assert "SLH-DSA" in info.name
        assert info.quantum_safety == QuantumSafety.QUANTUM_SAFE

    def test_composite_ml_dsa_65_ecdsa(self):
        info = lookup_oid("2.16.840.1.114027.80.8.1.23")
        assert info is not None
        assert info.quantum_safety == QuantumSafety.HYBRID

    def test_ecdsa_sha256(self):
        info = lookup_oid("1.2.840.10045.4.3.2")
        assert info is not None
        assert info.quantum_safety == QuantumSafety.QUANTUM_VULNERABLE

    def test_ed25519(self):
        info = lookup_oid("1.3.101.112")
        assert info is not None
        assert info.name == "Ed25519"
        assert info.quantum_safety == QuantumSafety.QUANTUM_VULNERABLE

    def test_sha1_rsa_deprecated(self):
        info = lookup_oid("1.2.840.113549.1.1.5")
        assert info is not None
        assert "DEPRECATED" in info.notes

    def test_unknown_oid(self):
        assert lookup_oid("9.9.9.9.9") is None


class TestClassification:
    def test_classify_rsa(self):
        assert classify_algorithm("1.2.840.113549.1.1.11") == QuantumSafety.QUANTUM_VULNERABLE

    def test_classify_ml_dsa(self):
        assert classify_algorithm("2.16.840.1.101.3.4.3.18") == QuantumSafety.QUANTUM_SAFE

    def test_classify_hybrid(self):
        assert classify_algorithm("2.16.840.1.114027.80.8.1.23") == QuantumSafety.HYBRID

    def test_classify_unknown(self):
        assert classify_algorithm("9.9.9.9") == QuantumSafety.UNKNOWN

    def test_is_pqc_safe_quantum(self):
        assert is_pqc_safe("2.16.840.1.101.3.4.3.18") is True

    def test_is_pqc_safe_hybrid(self):
        assert is_pqc_safe("2.16.840.1.114027.80.8.1.23") is True

    def test_is_pqc_safe_classical(self):
        assert is_pqc_safe("1.2.840.113549.1.1.11") is False

    def test_all_algorithms_not_empty(self):
        algos = all_algorithms()
        assert len(algos) > 20
