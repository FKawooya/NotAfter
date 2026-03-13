"""PQC and classical algorithm OID database.

Maps X.509 OIDs to algorithm metadata for classification and PQC readiness scoring.
Sources: NIST FIPS 203/204/205, IETF LAMPS WG drafts, CNSA 2.0.
"""

from dataclasses import dataclass
from enum import Enum


class QuantumSafety(Enum):
    """Quantum safety classification."""

    QUANTUM_SAFE = "quantum-safe"
    QUANTUM_VULNERABLE = "quantum-vulnerable"
    HYBRID = "hybrid"
    UNKNOWN = "unknown"


class AlgorithmType(Enum):
    """Algorithm type classification."""

    SIGNATURE = "signature"
    KEY_EXCHANGE = "key-exchange"
    HASH = "hash"
    SYMMETRIC = "symmetric"


@dataclass(frozen=True)
class AlgorithmInfo:
    """Metadata for a cryptographic algorithm."""

    name: str
    oid: str
    algo_type: AlgorithmType
    quantum_safety: QuantumSafety
    key_size: int | None = None
    nist_level: int | None = None  # NIST security level (1-5)
    cnsa2_approved: bool = False
    notes: str = ""


# --- NIST PQC Standards (FIPS 203, 204, 205) ---

ML_DSA_44 = AlgorithmInfo(
    name="ML-DSA-44",
    oid="2.16.840.1.101.3.4.3.17",
    algo_type=AlgorithmType.SIGNATURE,
    quantum_safety=QuantumSafety.QUANTUM_SAFE,
    nist_level=2,
    cnsa2_approved=False,
    notes="FIPS 204. Not CNSA 2.0 (level too low).",
)

ML_DSA_65 = AlgorithmInfo(
    name="ML-DSA-65",
    oid="2.16.840.1.101.3.4.3.18",
    algo_type=AlgorithmType.SIGNATURE,
    quantum_safety=QuantumSafety.QUANTUM_SAFE,
    nist_level=3,
    cnsa2_approved=True,
    notes="FIPS 204. CNSA 2.0 approved for software/firmware signing.",
)

ML_DSA_87 = AlgorithmInfo(
    name="ML-DSA-87",
    oid="2.16.840.1.101.3.4.3.19",
    algo_type=AlgorithmType.SIGNATURE,
    quantum_safety=QuantumSafety.QUANTUM_SAFE,
    nist_level=5,
    cnsa2_approved=True,
    notes="FIPS 204. CNSA 2.0 approved.",
)

SLH_DSA_SHA2_128S = AlgorithmInfo(
    name="SLH-DSA-SHA2-128s",
    oid="2.16.840.1.101.3.4.3.20",
    algo_type=AlgorithmType.SIGNATURE,
    quantum_safety=QuantumSafety.QUANTUM_SAFE,
    nist_level=1,
    cnsa2_approved=False,
    notes="FIPS 205. Hash-based, conservative choice.",
)

SLH_DSA_SHA2_128F = AlgorithmInfo(
    name="SLH-DSA-SHA2-128f",
    oid="2.16.840.1.101.3.4.3.21",
    algo_type=AlgorithmType.SIGNATURE,
    quantum_safety=QuantumSafety.QUANTUM_SAFE,
    nist_level=1,
    cnsa2_approved=False,
)

SLH_DSA_SHA2_192S = AlgorithmInfo(
    name="SLH-DSA-SHA2-192s",
    oid="2.16.840.1.101.3.4.3.22",
    algo_type=AlgorithmType.SIGNATURE,
    quantum_safety=QuantumSafety.QUANTUM_SAFE,
    nist_level=3,
    cnsa2_approved=True,
    notes="FIPS 205. CNSA 2.0 approved for firmware signing.",
)

SLH_DSA_SHA2_192F = AlgorithmInfo(
    name="SLH-DSA-SHA2-192f",
    oid="2.16.840.1.101.3.4.3.23",
    algo_type=AlgorithmType.SIGNATURE,
    quantum_safety=QuantumSafety.QUANTUM_SAFE,
    nist_level=3,
    cnsa2_approved=True,
)

SLH_DSA_SHA2_256S = AlgorithmInfo(
    name="SLH-DSA-SHA2-256s",
    oid="2.16.840.1.101.3.4.3.24",
    algo_type=AlgorithmType.SIGNATURE,
    quantum_safety=QuantumSafety.QUANTUM_SAFE,
    nist_level=5,
    cnsa2_approved=True,
)

SLH_DSA_SHA2_256F = AlgorithmInfo(
    name="SLH-DSA-SHA2-256f",
    oid="2.16.840.1.101.3.4.3.25",
    algo_type=AlgorithmType.SIGNATURE,
    quantum_safety=QuantumSafety.QUANTUM_SAFE,
    nist_level=5,
    cnsa2_approved=True,
)

SLH_DSA_SHAKE_128S = AlgorithmInfo(
    name="SLH-DSA-SHAKE-128s",
    oid="2.16.840.1.101.3.4.3.26",
    algo_type=AlgorithmType.SIGNATURE,
    quantum_safety=QuantumSafety.QUANTUM_SAFE,
    nist_level=1,
    cnsa2_approved=False,
)

SLH_DSA_SHAKE_128F = AlgorithmInfo(
    name="SLH-DSA-SHAKE-128f",
    oid="2.16.840.1.101.3.4.3.27",
    algo_type=AlgorithmType.SIGNATURE,
    quantum_safety=QuantumSafety.QUANTUM_SAFE,
    nist_level=1,
    cnsa2_approved=False,
)

SLH_DSA_SHAKE_192S = AlgorithmInfo(
    name="SLH-DSA-SHAKE-192s",
    oid="2.16.840.1.101.3.4.3.28",
    algo_type=AlgorithmType.SIGNATURE,
    quantum_safety=QuantumSafety.QUANTUM_SAFE,
    nist_level=3,
    cnsa2_approved=True,
)

SLH_DSA_SHAKE_192F = AlgorithmInfo(
    name="SLH-DSA-SHAKE-192f",
    oid="2.16.840.1.101.3.4.3.29",
    algo_type=AlgorithmType.SIGNATURE,
    quantum_safety=QuantumSafety.QUANTUM_SAFE,
    nist_level=3,
    cnsa2_approved=True,
)

SLH_DSA_SHAKE_256S = AlgorithmInfo(
    name="SLH-DSA-SHAKE-256s",
    oid="2.16.840.1.101.3.4.3.30",
    algo_type=AlgorithmType.SIGNATURE,
    quantum_safety=QuantumSafety.QUANTUM_SAFE,
    nist_level=5,
    cnsa2_approved=True,
)

SLH_DSA_SHAKE_256F = AlgorithmInfo(
    name="SLH-DSA-SHAKE-256f",
    oid="2.16.840.1.101.3.4.3.31",
    algo_type=AlgorithmType.SIGNATURE,
    quantum_safety=QuantumSafety.QUANTUM_SAFE,
    nist_level=5,
    cnsa2_approved=True,
)

ML_KEM_512 = AlgorithmInfo(
    name="ML-KEM-512",
    oid="2.16.840.1.101.3.4.4.1",
    algo_type=AlgorithmType.KEY_EXCHANGE,
    quantum_safety=QuantumSafety.QUANTUM_SAFE,
    nist_level=1,
    cnsa2_approved=False,
    notes="FIPS 203. Not CNSA 2.0 (level too low).",
)

ML_KEM_768 = AlgorithmInfo(
    name="ML-KEM-768",
    oid="2.16.840.1.101.3.4.4.2",
    algo_type=AlgorithmType.KEY_EXCHANGE,
    quantum_safety=QuantumSafety.QUANTUM_SAFE,
    nist_level=3,
    cnsa2_approved=True,
    notes="FIPS 203. CNSA 2.0 approved for key establishment.",
)

ML_KEM_1024 = AlgorithmInfo(
    name="ML-KEM-1024",
    oid="2.16.840.1.101.3.4.4.3",
    algo_type=AlgorithmType.KEY_EXCHANGE,
    quantum_safety=QuantumSafety.QUANTUM_SAFE,
    nist_level=5,
    cnsa2_approved=True,
    notes="FIPS 203. CNSA 2.0 approved.",
)

# --- Hybrid / Composite OIDs (IETF LAMPS WG drafts) ---

COMPOSITE_ML_DSA_65_RSA = AlgorithmInfo(
    name="MLDSA65-RSA3072-PSS-SHA512",
    oid="2.16.840.1.114027.80.8.1.21",
    algo_type=AlgorithmType.SIGNATURE,
    quantum_safety=QuantumSafety.HYBRID,
    notes="Composite: ML-DSA-65 + RSA-3072. IETF draft-ietf-lamps-pq-composite-sigs.",
)

COMPOSITE_ML_DSA_65_ECDSA_P256 = AlgorithmInfo(
    name="MLDSA65-ECDSA-P256-SHA512",
    oid="2.16.840.1.114027.80.8.1.23",
    algo_type=AlgorithmType.SIGNATURE,
    quantum_safety=QuantumSafety.HYBRID,
    notes="Composite: ML-DSA-65 + ECDSA-P256.",
)

COMPOSITE_ML_DSA_65_Ed25519 = AlgorithmInfo(
    name="MLDSA65-Ed25519-SHA512",
    oid="2.16.840.1.114027.80.8.1.26",
    algo_type=AlgorithmType.SIGNATURE,
    quantum_safety=QuantumSafety.HYBRID,
    notes="Composite: ML-DSA-65 + Ed25519.",
)

COMPOSITE_ML_DSA_87_ECDSA_P384 = AlgorithmInfo(
    name="MLDSA87-ECDSA-P384-SHA512",
    oid="2.16.840.1.114027.80.8.1.24",
    algo_type=AlgorithmType.SIGNATURE,
    quantum_safety=QuantumSafety.HYBRID,
    notes="Composite: ML-DSA-87 + ECDSA-P384.",
)

COMPOSITE_ML_DSA_87_Ed448 = AlgorithmInfo(
    name="MLDSA87-Ed448-SHA512",
    oid="2.16.840.1.114027.80.8.1.27",
    algo_type=AlgorithmType.SIGNATURE,
    quantum_safety=QuantumSafety.HYBRID,
    notes="Composite: ML-DSA-87 + Ed448.",
)

# --- Classical Algorithms ---

RSA_WITH_SHA256 = AlgorithmInfo(
    name="SHA256WithRSAEncryption",
    oid="1.2.840.113549.1.1.11",
    algo_type=AlgorithmType.SIGNATURE,
    quantum_safety=QuantumSafety.QUANTUM_VULNERABLE,
)

RSA_WITH_SHA384 = AlgorithmInfo(
    name="SHA384WithRSAEncryption",
    oid="1.2.840.113549.1.1.12",
    algo_type=AlgorithmType.SIGNATURE,
    quantum_safety=QuantumSafety.QUANTUM_VULNERABLE,
)

RSA_WITH_SHA512 = AlgorithmInfo(
    name="SHA512WithRSAEncryption",
    oid="1.2.840.113549.1.1.13",
    algo_type=AlgorithmType.SIGNATURE,
    quantum_safety=QuantumSafety.QUANTUM_VULNERABLE,
)

RSA_WITH_SHA1 = AlgorithmInfo(
    name="SHA1WithRSAEncryption",
    oid="1.2.840.113549.1.1.5",
    algo_type=AlgorithmType.SIGNATURE,
    quantum_safety=QuantumSafety.QUANTUM_VULNERABLE,
    notes="DEPRECATED. SHA-1 is broken.",
)

RSA_WITH_MD5 = AlgorithmInfo(
    name="MD5WithRSAEncryption",
    oid="1.2.840.113549.1.1.4",
    algo_type=AlgorithmType.SIGNATURE,
    quantum_safety=QuantumSafety.QUANTUM_VULNERABLE,
    notes="DEPRECATED. MD5 is broken.",
)

RSA_PSS = AlgorithmInfo(
    name="RSASSA-PSS",
    oid="1.2.840.113549.1.1.10",
    algo_type=AlgorithmType.SIGNATURE,
    quantum_safety=QuantumSafety.QUANTUM_VULNERABLE,
    notes="RSA-PSS. Hash determined by parameters.",
)

ECDSA_WITH_SHA256 = AlgorithmInfo(
    name="ECDSA-with-SHA256",
    oid="1.2.840.10045.4.3.2",
    algo_type=AlgorithmType.SIGNATURE,
    quantum_safety=QuantumSafety.QUANTUM_VULNERABLE,
)

ECDSA_WITH_SHA384 = AlgorithmInfo(
    name="ECDSA-with-SHA384",
    oid="1.2.840.10045.4.3.3",
    algo_type=AlgorithmType.SIGNATURE,
    quantum_safety=QuantumSafety.QUANTUM_VULNERABLE,
)

ECDSA_WITH_SHA512 = AlgorithmInfo(
    name="ECDSA-with-SHA512",
    oid="1.2.840.10045.4.3.4",
    algo_type=AlgorithmType.SIGNATURE,
    quantum_safety=QuantumSafety.QUANTUM_VULNERABLE,
)

ED25519 = AlgorithmInfo(
    name="Ed25519",
    oid="1.3.101.112",
    algo_type=AlgorithmType.SIGNATURE,
    quantum_safety=QuantumSafety.QUANTUM_VULNERABLE,
)

ED448 = AlgorithmInfo(
    name="Ed448",
    oid="1.3.101.113",
    algo_type=AlgorithmType.SIGNATURE,
    quantum_safety=QuantumSafety.QUANTUM_VULNERABLE,
)

DSA_WITH_SHA256 = AlgorithmInfo(
    name="DSA-with-SHA256",
    oid="2.16.840.1.101.3.4.3.2",
    algo_type=AlgorithmType.SIGNATURE,
    quantum_safety=QuantumSafety.QUANTUM_VULNERABLE,
    notes="DEPRECATED. DSA is legacy.",
)

# --- TLS Key Exchange (identified by TLS cipher suite, not OID) ---

X25519_KYBER768 = AlgorithmInfo(
    name="X25519Kyber768Draft00",
    oid="",
    algo_type=AlgorithmType.KEY_EXCHANGE,
    quantum_safety=QuantumSafety.HYBRID,
    notes="TLS 1.3 hybrid key exchange. Draft IETF standard.",
)

X25519_MLKEM768 = AlgorithmInfo(
    name="X25519MLKEM768",
    oid="",
    algo_type=AlgorithmType.KEY_EXCHANGE,
    quantum_safety=QuantumSafety.HYBRID,
    cnsa2_approved=True,
    notes="TLS 1.3 hybrid key exchange with FIPS ML-KEM-768.",
)

SECP256R1_MLKEM768 = AlgorithmInfo(
    name="SecP256r1MLKEM768",
    oid="",
    algo_type=AlgorithmType.KEY_EXCHANGE,
    quantum_safety=QuantumSafety.HYBRID,
    cnsa2_approved=True,
    notes="TLS 1.3 hybrid key exchange.",
)


# --- Registry ---

# Explicit algorithm registry. Every AlgorithmInfo defined above must be listed here.
_ALL_ALGORITHMS: list[AlgorithmInfo] = [
    # NIST PQC signatures (FIPS 204)
    ML_DSA_44,
    ML_DSA_65,
    ML_DSA_87,
    # NIST PQC signatures (FIPS 205 — hash-based)
    SLH_DSA_SHA2_128S,
    SLH_DSA_SHA2_128F,
    SLH_DSA_SHA2_192S,
    SLH_DSA_SHA2_192F,
    SLH_DSA_SHA2_256S,
    SLH_DSA_SHA2_256F,
    SLH_DSA_SHAKE_128S,
    SLH_DSA_SHAKE_128F,
    SLH_DSA_SHAKE_192S,
    SLH_DSA_SHAKE_192F,
    SLH_DSA_SHAKE_256S,
    SLH_DSA_SHAKE_256F,
    # NIST PQC key exchange (FIPS 203)
    ML_KEM_512,
    ML_KEM_768,
    ML_KEM_1024,
    # Hybrid / composite (IETF LAMPS WG)
    COMPOSITE_ML_DSA_65_RSA,
    COMPOSITE_ML_DSA_65_ECDSA_P256,
    COMPOSITE_ML_DSA_65_Ed25519,
    COMPOSITE_ML_DSA_87_ECDSA_P384,
    COMPOSITE_ML_DSA_87_Ed448,
    # Classical signatures
    RSA_WITH_SHA256,
    RSA_WITH_SHA384,
    RSA_WITH_SHA512,
    RSA_WITH_SHA1,
    RSA_WITH_MD5,
    RSA_PSS,
    ECDSA_WITH_SHA256,
    ECDSA_WITH_SHA384,
    ECDSA_WITH_SHA512,
    ED25519,
    ED448,
    DSA_WITH_SHA256,
    # TLS key exchange (no OIDs — identified by cipher suite name)
    X25519_KYBER768,
    X25519_MLKEM768,
    SECP256R1_MLKEM768,
]

# OID-keyed lookup map built from the explicit registry.
_OID_MAP: dict[str, AlgorithmInfo] = {
    algo.oid: algo for algo in _ALL_ALGORITHMS if algo.oid
}


def _build_oid_map() -> dict[str, AlgorithmInfo]:
    """Returns the pre-built OID map. Kept for backward compatibility."""
    return _OID_MAP


def lookup_oid(oid: str) -> AlgorithmInfo | None:
    """Look up algorithm info by OID string (dotted notation)."""
    return _OID_MAP.get(oid)


def classify_algorithm(oid: str) -> QuantumSafety:
    """Classify an algorithm's quantum safety by its OID."""
    info = lookup_oid(oid)
    return info.quantum_safety if info else QuantumSafety.UNKNOWN


def is_pqc_safe(oid: str) -> bool:
    """Check if an algorithm OID is quantum-safe or hybrid."""
    safety = classify_algorithm(oid)
    return safety in (QuantumSafety.QUANTUM_SAFE, QuantumSafety.HYBRID)


def all_algorithms() -> list[AlgorithmInfo]:
    """Return all known algorithms, including those without OIDs (e.g. TLS key exchange)."""
    return list(_ALL_ALGORITHMS)
