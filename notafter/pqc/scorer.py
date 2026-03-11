"""PQC readiness scoring engine.

Evaluates a certificate chain and TLS connection against PQC readiness criteria.
Produces a score from 0-10 with actionable recommendations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date

from notafter.pqc.oids import AlgorithmInfo, QuantumSafety, lookup_oid


# CNSA 2.0 key milestones
CNSA2_MILESTONES = [
    (date(2025, 12, 31), "Software/firmware signing must support CNSA 2.0"),
    (date(2026, 12, 31), "Networking equipment must support CNSA 2.0"),
    (date(2027, 1, 1), "New NSS acquisitions must be CNSA 2.0 compliant"),
    (date(2030, 1, 1), "Software signing + networking exclusively CNSA 2.0"),
    (date(2033, 1, 1), "Web browsers/servers exclusively CNSA 2.0"),
    (date(2035, 1, 1), "All National Security Systems quantum-resistant"),
]


@dataclass
class PQCFinding:
    """A single PQC readiness finding."""

    component: str  # e.g., "leaf certificate", "key exchange", "intermediate #1"
    algorithm: str
    quantum_safety: QuantumSafety
    points_earned: int
    points_possible: int
    recommendation: str = ""


@dataclass
class PQCReport:
    """Complete PQC readiness assessment."""

    score: int = 0
    max_score: int = 10
    findings: list[PQCFinding] = field(default_factory=list)
    cnsa2_compliant: bool = False
    cnsa2_next_deadline: str = ""
    cnsa2_days_remaining: int = 0
    overall_safety: QuantumSafety = QuantumSafety.QUANTUM_VULNERABLE
    recommendations: list[str] = field(default_factory=list)

    @property
    def grade(self) -> str:
        if self.score >= 9:
            return "A"
        if self.score >= 7:
            return "B"
        if self.score >= 5:
            return "C"
        if self.score >= 3:
            return "D"
        return "F"

    @property
    def ready(self) -> bool:
        return self.score >= 7


def _classify_cert_algorithm(sig_oid: str, key_type: str, key_size: int | None) -> PQCFinding:
    """Classify a certificate's signature algorithm."""
    info = lookup_oid(sig_oid)
    if info and info.quantum_safety == QuantumSafety.QUANTUM_SAFE:
        return PQCFinding(
            component="",
            algorithm=info.name,
            quantum_safety=QuantumSafety.QUANTUM_SAFE,
            points_earned=2,
            points_possible=2,
        )
    if info and info.quantum_safety == QuantumSafety.HYBRID:
        return PQCFinding(
            component="",
            algorithm=info.name,
            quantum_safety=QuantumSafety.HYBRID,
            points_earned=2,
            points_possible=2,
            recommendation="Hybrid is good — plan migration to pure PQC before 2033.",
        )

    algo_name = info.name if info else f"{key_type}-{key_size or '?'}"
    return PQCFinding(
        component="",
        algorithm=algo_name,
        quantum_safety=QuantumSafety.QUANTUM_VULNERABLE,
        points_earned=0,
        points_possible=2,
        recommendation=f"Migrate to ML-DSA-65 or composite (ML-DSA-65 + {key_type}).",
    )


def score_chain(
    chain_algorithms: list[dict],
    tls_version: str | None = None,
    key_exchange: str | None = None,
) -> PQCReport:
    """Score a certificate chain for PQC readiness.

    Args:
        chain_algorithms: List of dicts with keys:
            - sig_oid: signature algorithm OID
            - key_type: "RSA", "EC", "Ed25519", etc.
            - key_size: key size in bits (None if not applicable)
            - label: "leaf", "intermediate #1", "root", etc.
        tls_version: TLS protocol version string (e.g., "TLSv1.3")
        key_exchange: Key exchange algorithm name from TLS handshake
    """
    report = PQCReport()
    total_points = 0
    earned_points = 0
    all_safe = True

    # 1. TLS version check (1 point) — TLS 1.3 required for PQC KEMs
    tls_points = 1
    total_points += tls_points
    if tls_version and "1.3" in tls_version:
        earned_points += tls_points
        report.findings.append(PQCFinding(
            component="TLS version",
            algorithm=tls_version,
            quantum_safety=QuantumSafety.QUANTUM_VULNERABLE,  # TLS version itself isn't PQC
            points_earned=tls_points,
            points_possible=tls_points,
        ))
    else:
        all_safe = False
        report.findings.append(PQCFinding(
            component="TLS version",
            algorithm=tls_version or "unknown",
            quantum_safety=QuantumSafety.QUANTUM_VULNERABLE,
            points_earned=0,
            points_possible=tls_points,
            recommendation="Upgrade to TLS 1.3 — required for PQC key exchange.",
        ))

    # 2. Key exchange check (3 points) — biggest quantum risk
    kex_points = 3
    total_points += kex_points
    if key_exchange:
        kex_lower = key_exchange.lower()
        if "kyber" in kex_lower or "mlkem" in kex_lower:
            earned_points += kex_points
            safety = QuantumSafety.HYBRID if "x25519" in kex_lower else QuantumSafety.QUANTUM_SAFE
            report.findings.append(PQCFinding(
                component="Key exchange",
                algorithm=key_exchange,
                quantum_safety=safety,
                points_earned=kex_points,
                points_possible=kex_points,
            ))
        else:
            all_safe = False
            report.findings.append(PQCFinding(
                component="Key exchange",
                algorithm=key_exchange,
                quantum_safety=QuantumSafety.QUANTUM_VULNERABLE,
                points_earned=0,
                points_possible=kex_points,
                recommendation="Enable X25519MLKEM768 hybrid key exchange.",
            ))
    else:
        all_safe = False
        report.findings.append(PQCFinding(
            component="Key exchange",
            algorithm="unknown",
            quantum_safety=QuantumSafety.UNKNOWN,
            points_earned=0,
            points_possible=kex_points,
            recommendation="Could not determine key exchange. Ensure TLS 1.3 with hybrid KEM.",
        ))

    # 3. Leaf certificate (2 points)
    if chain_algorithms:
        leaf = chain_algorithms[0]
        leaf_finding = _classify_cert_algorithm(
            leaf["sig_oid"], leaf["key_type"], leaf.get("key_size")
        )
        leaf_finding.component = leaf.get("label", "Leaf certificate")
        total_points += leaf_finding.points_possible
        earned_points += leaf_finding.points_earned
        if leaf_finding.quantum_safety == QuantumSafety.QUANTUM_VULNERABLE:
            all_safe = False
        report.findings.append(leaf_finding)

    # 4. Chain certificates (2 points combined)
    chain_points = 2
    if len(chain_algorithms) > 1:
        chain_safe_count = 0
        chain_total = len(chain_algorithms) - 1
        for cert_info in chain_algorithms[1:]:
            finding = _classify_cert_algorithm(
                cert_info["sig_oid"], cert_info["key_type"], cert_info.get("key_size")
            )
            finding.component = cert_info.get("label", "Chain certificate")
            finding.points_possible = 0  # rolled into chain total
            if finding.quantum_safety in (QuantumSafety.QUANTUM_SAFE, QuantumSafety.HYBRID):
                chain_safe_count += 1
            else:
                all_safe = False
            report.findings.append(finding)

        chain_earned = chain_points if chain_safe_count == chain_total else 0
        total_points += chain_points
        earned_points += chain_earned
    else:
        total_points += chain_points

    # 5. Clean baseline (1 point) — no deprecated algorithms
    baseline_points = 1
    total_points += baseline_points
    has_deprecated = False
    for cert_info in chain_algorithms:
        info = lookup_oid(cert_info["sig_oid"])
        if info and info.notes and "DEPRECATED" in info.notes:
            has_deprecated = True
            break
    if not has_deprecated:
        earned_points += baseline_points
    else:
        all_safe = False

    # 6. CNSA 2.0 check (1 point)
    cnsa_points = 1
    total_points += cnsa_points
    cnsa_compliant = True
    for cert_info in chain_algorithms:
        info = lookup_oid(cert_info["sig_oid"])
        if not info or not info.cnsa2_approved:
            cnsa_compliant = False
            break
    if cnsa_compliant:
        earned_points += cnsa_points
    else:
        all_safe = False

    report.cnsa2_compliant = cnsa_compliant

    # CNSA 2.0 timeline
    today = date.today()
    for deadline, description in CNSA2_MILESTONES:
        if today < deadline:
            report.cnsa2_next_deadline = description
            report.cnsa2_days_remaining = (deadline - today).days
            break

    # Final scoring — normalize to 0-10
    report.max_score = 10
    if total_points > 0:
        report.score = round((earned_points / total_points) * 10)
    else:
        report.score = 0

    # Determine overall safety based on whether any PQC/hybrid algorithms are present
    has_pqc = any(
        f.quantum_safety in (QuantumSafety.QUANTUM_SAFE, QuantumSafety.HYBRID)
        for f in report.findings
    )
    if all_safe:
        report.overall_safety = QuantumSafety.QUANTUM_SAFE
    elif has_pqc:
        report.overall_safety = QuantumSafety.HYBRID
    else:
        report.overall_safety = QuantumSafety.QUANTUM_VULNERABLE

    # Generate top-level recommendations
    report.recommendations = _generate_recommendations(report)

    return report


def _generate_recommendations(report: PQCReport) -> list[str]:
    recs = []
    for f in report.findings:
        if f.recommendation:
            recs.append(f.recommendation)

    if not report.cnsa2_compliant and report.cnsa2_days_remaining > 0:
        recs.append(
            f"CNSA 2.0 deadline in {report.cnsa2_days_remaining} days: "
            f"{report.cnsa2_next_deadline}"
        )

    if report.score <= 2:
        recs.insert(0, "CRITICAL: No quantum protection. Begin PQC migration planning now.")
    elif report.score <= 5:
        recs.insert(0, "Partial protection. Prioritize hybrid key exchange and cert migration.")

    return recs
