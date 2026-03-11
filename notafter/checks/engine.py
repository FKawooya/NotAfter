"""Certificate check engine — runs all lint checks against a scan result."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum

from notafter.scanner.tls import CertInfo, ScanResult


class Severity(Enum):
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"
    PASS = "pass"


@dataclass
class Finding:
    """A single check finding."""

    check: str
    severity: Severity
    component: str  # which cert or connection property
    message: str
    remediation: str = ""


@dataclass
class AuditReport:
    """Aggregated findings from all checks."""

    target: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def warning_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.WARNING)

    @property
    def pass_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.PASS)

    @property
    def exit_code(self) -> int:
        if self.critical_count > 0:
            return 2
        if self.warning_count > 0:
            return 1
        return 0


def run_checks(scan: ScanResult, warn_days: int = 30) -> AuditReport:
    """Run all certificate checks against a scan result."""
    report = AuditReport(target=f"{scan.host}:{scan.port}")

    if scan.error:
        report.findings.append(Finding(
            check="connection",
            severity=Severity.CRITICAL,
            component="TLS connection",
            message=scan.error,
        ))
        return report

    if not scan.chain:
        report.findings.append(Finding(
            check="connection",
            severity=Severity.CRITICAL,
            component="TLS connection",
            message="No certificates received",
        ))
        return report

    # Run each check
    for check_fn in _ALL_CHECKS:
        findings = check_fn(scan, warn_days)
        report.findings.extend(findings)

    return report


# --- Individual checks ---


def _check_expiry(scan: ScanResult, warn_days: int) -> list[Finding]:
    findings = []
    now = datetime.now(timezone.utc)
    warn_threshold = now + timedelta(days=warn_days)

    for i, cert in enumerate(scan.chain):
        label = _cert_label(cert, i)
        not_after = datetime.fromisoformat(cert.not_after)
        not_before = datetime.fromisoformat(cert.not_before)

        if now < not_before:
            findings.append(Finding(
                check="expiry",
                severity=Severity.CRITICAL,
                component=label,
                message=f"Not yet valid. Validity starts {cert.not_before}.",
                remediation="Check system clock or certificate issuance date.",
            ))
        elif now > not_after:
            findings.append(Finding(
                check="expiry",
                severity=Severity.CRITICAL,
                component=label,
                message=f"EXPIRED on {cert.not_after}.",
                remediation="Renew certificate immediately.",
            ))
        elif now > not_after - timedelta(days=warn_days):
            days_left = (not_after - now).days
            findings.append(Finding(
                check="expiry",
                severity=Severity.WARNING,
                component=label,
                message=f"Expires in {days_left} days ({cert.not_after}).",
                remediation="Renew before expiry.",
            ))
        else:
            days_left = (not_after - now).days
            findings.append(Finding(
                check="expiry",
                severity=Severity.PASS,
                component=label,
                message=f"Valid for {days_left} more days.",
            ))

    return findings


def _check_key_strength(scan: ScanResult, _warn_days: int) -> list[Finding]:
    findings = []
    for i, cert in enumerate(scan.chain):
        label = _cert_label(cert, i)
        kt = cert.key_type
        ks = cert.key_size

        if kt == "RSA" and ks is not None:
            if ks < 2048:
                findings.append(Finding(
                    check="key_strength",
                    severity=Severity.CRITICAL,
                    component=label,
                    message=f"RSA key too small: {ks} bits.",
                    remediation="Minimum RSA key size is 2048 bits. Prefer 3072+ or EC.",
                ))
            elif ks < 3072:
                findings.append(Finding(
                    check="key_strength",
                    severity=Severity.WARNING,
                    component=label,
                    message=f"RSA-{ks}: meets minimum but 3072+ recommended.",
                    remediation="Consider RSA-3072 or ECDSA P-256 for better security margin.",
                ))
            else:
                findings.append(Finding(
                    check="key_strength",
                    severity=Severity.PASS,
                    component=label,
                    message=f"RSA-{ks}: strong key.",
                ))
        elif "DSA" in kt and kt != "Ed25519" and kt != "Ed448":
            findings.append(Finding(
                check="key_strength",
                severity=Severity.CRITICAL,
                component=label,
                message=f"DSA key ({kt}): deprecated algorithm.",
                remediation="Migrate to ECDSA or Ed25519.",
            ))
        elif kt in ("Ed25519", "Ed448") or kt.startswith("EC-"):
            findings.append(Finding(
                check="key_strength",
                severity=Severity.PASS,
                component=label,
                message=f"{kt}: good key type.",
            ))

    return findings


def _check_signature(scan: ScanResult, _warn_days: int) -> list[Finding]:
    findings = []
    deprecated = {"sha1", "md5", "md2"}

    for i, cert in enumerate(scan.chain):
        label = _cert_label(cert, i)
        sig_name = cert.sig_algorithm_name.lower()

        if any(d in sig_name for d in deprecated):
            findings.append(Finding(
                check="signature",
                severity=Severity.CRITICAL,
                component=label,
                message=f"Weak signature: {cert.sig_algorithm_name}.",
                remediation="Re-issue with SHA-256 or stronger.",
            ))
        else:
            findings.append(Finding(
                check="signature",
                severity=Severity.PASS,
                component=label,
                message=f"Signature: {cert.sig_algorithm_name}.",
            ))

    return findings


def _check_san(scan: ScanResult, _warn_days: int) -> list[Finding]:
    findings = []
    if scan.chain:
        leaf = scan.chain[0]
        if not leaf.san_names:
            findings.append(Finding(
                check="san",
                severity=Severity.WARNING,
                component=_cert_label(leaf, 0),
                message="No Subject Alternative Name (SAN) extension.",
                remediation="Add SAN — browsers require it since 2017.",
            ))
        else:
            # Check for wildcards
            wildcards = [n for n in leaf.san_names if n.startswith("*.")]
            if wildcards:
                findings.append(Finding(
                    check="san",
                    severity=Severity.INFO,
                    component=_cert_label(leaf, 0),
                    message=f"Wildcard SAN(s): {', '.join(wildcards)}",
                ))
            findings.append(Finding(
                check="san",
                severity=Severity.PASS,
                component=_cert_label(leaf, 0),
                message=f"SAN present: {', '.join(leaf.san_names[:5])}"
                + (f" (+{len(leaf.san_names)-5} more)" if len(leaf.san_names) > 5 else ""),
            ))
    return findings


def _check_self_signed(scan: ScanResult, _warn_days: int) -> list[Finding]:
    findings = []
    if scan.chain:
        leaf = scan.chain[0]
        if leaf.is_self_signed and not leaf.is_ca:
            findings.append(Finding(
                check="self_signed",
                severity=Severity.WARNING,
                component=_cert_label(leaf, 0),
                message="Leaf certificate is self-signed.",
                remediation="Use a certificate from a trusted CA.",
            ))
    return findings


def _check_chain(scan: ScanResult, _warn_days: int) -> list[Finding]:
    findings = []
    if len(scan.chain) == 1 and not scan.chain[0].is_self_signed:
        findings.append(Finding(
            check="chain",
            severity=Severity.WARNING,
            component="Chain",
            message="Only leaf certificate received — intermediates may be missing.",
            remediation="Configure the server to send the full certificate chain.",
        ))
    elif len(scan.chain) > 1:
        findings.append(Finding(
            check="chain",
            severity=Severity.PASS,
            component="Chain",
            message=f"Chain has {len(scan.chain)} certificate(s).",
        ))
    return findings


def _check_tls_version(scan: ScanResult, _warn_days: int) -> list[Finding]:
    findings = []
    if scan.tls_version:
        version = scan.tls_version
        if "1.0" in version or "SSL" in version.upper():
            findings.append(Finding(
                check="tls_version",
                severity=Severity.CRITICAL,
                component="TLS",
                message=f"Insecure protocol: {version}.",
                remediation="Disable TLS 1.0/1.1 and SSLv3. Use TLS 1.2+.",
            ))
        elif "1.1" in version:
            findings.append(Finding(
                check="tls_version",
                severity=Severity.WARNING,
                component="TLS",
                message=f"Deprecated protocol: {version}.",
                remediation="Disable TLS 1.1. Use TLS 1.2+.",
            ))
        elif "1.2" in version:
            findings.append(Finding(
                check="tls_version",
                severity=Severity.PASS,
                component="TLS",
                message=f"Protocol: {version} (acceptable, TLS 1.3 preferred).",
            ))
        elif "1.3" in version:
            findings.append(Finding(
                check="tls_version",
                severity=Severity.PASS,
                component="TLS",
                message=f"Protocol: {version} (optimal).",
            ))
    return findings


def _cert_label(cert: CertInfo, index: int) -> str:
    """Generate a human-readable label for a certificate."""
    if index == 0:
        # Try to extract CN for leaf
        for part in cert.subject.split(","):
            if "CN=" in part:
                return part.strip()
        return "Leaf certificate"
    if cert.is_ca and cert.is_self_signed:
        return f"Root: {_short_cn(cert.subject)}"
    return f"Intermediate #{index}: {_short_cn(cert.subject)}"


def _short_cn(rdn: str) -> str:
    """Extract CN from an RDN string."""
    for part in rdn.split(","):
        if "CN=" in part:
            return part.strip().replace("CN=", "")
    return rdn[:40]


_ALL_CHECKS = [
    _check_expiry,
    _check_key_strength,
    _check_signature,
    _check_san,
    _check_self_signed,
    _check_chain,
    _check_tls_version,
]
