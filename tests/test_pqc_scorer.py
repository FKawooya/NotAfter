"""Tests for PQC readiness scoring."""

from notafter.pqc.oids import QuantumSafety
from notafter.pqc.scorer import score_chain


def _classical_chain():
    """Typical RSA chain — zero PQC."""
    return [
        {"sig_oid": "1.2.840.113549.1.1.11", "key_type": "RSA", "key_size": 2048, "label": "Leaf"},
        {"sig_oid": "1.2.840.113549.1.1.11", "key_type": "RSA", "key_size": 2048, "label": "Intermediate"},
        {"sig_oid": "1.2.840.113549.1.1.12", "key_type": "RSA", "key_size": 4096, "label": "Root"},
    ]


def _pqc_chain():
    """Fully PQC chain with ML-DSA-65."""
    return [
        {"sig_oid": "2.16.840.1.101.3.4.3.18", "key_type": "ML-DSA", "key_size": None, "label": "Leaf"},
        {"sig_oid": "2.16.840.1.101.3.4.3.18", "key_type": "ML-DSA", "key_size": None, "label": "Intermediate"},
        {"sig_oid": "2.16.840.1.101.3.4.3.19", "key_type": "ML-DSA", "key_size": None, "label": "Root"},
    ]


def _hybrid_chain():
    """Hybrid chain with composite signatures."""
    return [
        {"sig_oid": "2.16.840.1.114027.80.8.1.23", "key_type": "Composite", "key_size": None, "label": "Leaf"},
        {"sig_oid": "1.2.840.113549.1.1.11", "key_type": "RSA", "key_size": 2048, "label": "Root"},
    ]


class TestPQCScoring:
    def test_classical_chain_low_score(self):
        report = score_chain(_classical_chain(), tls_version="TLSv1.2", key_exchange="ECDHE")
        assert report.score <= 3
        assert report.overall_safety == QuantumSafety.QUANTUM_VULNERABLE
        assert report.grade in ("D", "F")

    def test_classical_with_tls13(self):
        report = score_chain(_classical_chain(), tls_version="TLSv1.3", key_exchange="ECDHE")
        # Gets 1 point for TLS 1.3 + 1 for clean baseline
        assert report.score >= 1
        assert not report.ready

    def test_pqc_chain_high_score(self):
        report = score_chain(
            _pqc_chain(),
            tls_version="TLSv1.3",
            key_exchange="X25519MLKEM768",
        )
        assert report.score >= 8
        assert report.ready
        assert report.cnsa2_compliant

    def test_hybrid_chain_medium_score(self):
        report = score_chain(
            _hybrid_chain(),
            tls_version="TLSv1.3",
            key_exchange="X25519Kyber768Draft00",
        )
        assert report.score >= 4
        assert report.overall_safety in (QuantumSafety.HYBRID, QuantumSafety.QUANTUM_SAFE)

    def test_no_chain(self):
        report = score_chain([], tls_version="TLSv1.3")
        assert report.score >= 0

    def test_cnsa2_not_compliant_classical(self):
        report = score_chain(_classical_chain())
        assert report.cnsa2_compliant is False

    def test_cnsa2_compliant_pqc(self):
        report = score_chain(
            _pqc_chain(),
            tls_version="TLSv1.3",
            key_exchange="X25519MLKEM768",
        )
        assert report.cnsa2_compliant is True

    def test_recommendations_generated(self):
        report = score_chain(_classical_chain(), tls_version="TLSv1.2")
        assert len(report.recommendations) > 0

    def test_grade_mapping(self):
        report = score_chain(_pqc_chain(), tls_version="TLSv1.3", key_exchange="X25519MLKEM768")
        assert report.grade in ("A", "B")

        report2 = score_chain(_classical_chain(), tls_version="TLSv1.2")
        assert report2.grade in ("D", "F")

    def test_cnsa2_deadline_populated(self):
        report = score_chain(_classical_chain())
        assert report.cnsa2_days_remaining > 0
        assert report.cnsa2_next_deadline != ""


class TestPQCScorerDeprecatedDetection:
    """Q-M9: SHA-1 in chain should deduct baseline point."""

    def test_sha1_deducts_baseline_point(self):
        chain_with_sha1 = [
            {"sig_oid": "1.2.840.113549.1.1.11", "key_type": "RSA", "key_size": 2048, "label": "Leaf"},
            # SHA-1 signature — OID 1.2.840.113549.1.1.5 has "DEPRECATED" in notes
            {"sig_oid": "1.2.840.113549.1.1.5", "key_type": "RSA", "key_size": 2048, "label": "Intermediate"},
        ]
        report_with_sha1 = score_chain(chain_with_sha1, tls_version="TLSv1.3", key_exchange="ECDHE")

        chain_without_sha1 = [
            {"sig_oid": "1.2.840.113549.1.1.11", "key_type": "RSA", "key_size": 2048, "label": "Leaf"},
            {"sig_oid": "1.2.840.113549.1.1.11", "key_type": "RSA", "key_size": 2048, "label": "Intermediate"},
        ]
        report_without_sha1 = score_chain(chain_without_sha1, tls_version="TLSv1.3", key_exchange="ECDHE")

        # The chain with SHA-1 should score strictly lower due to baseline deduction
        assert report_with_sha1.score < report_without_sha1.score, (
            f"SHA-1 in chain should deduct from score. "
            f"With SHA-1: {report_with_sha1.score}, without: {report_without_sha1.score}"
        )


class TestPQCGradeBoundaries:
    """Q-L6: PQC grade boundary values — test score 0-10 produce correct grades."""

    def test_grade_boundaries(self):
        from notafter.pqc.scorer import PQCReport
        expected = {
            0: "F", 1: "F", 2: "F",
            3: "D", 4: "D",
            5: "C", 6: "C",
            7: "B", 8: "B",
            9: "A", 10: "A",
        }
        for score, expected_grade in expected.items():
            report = PQCReport(score=score)
            assert report.grade == expected_grade, (
                f"Score {score} should produce grade '{expected_grade}', got '{report.grade}'"
            )
