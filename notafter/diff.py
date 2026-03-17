"""Compare two NotAfter JSON scan outputs and produce a structured diff."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class CertChange:
    """A single certificate-level change."""
    type: str  # "renewed", "added", "removed", "modified"
    subject: str
    details: dict = field(default_factory=dict)


@dataclass
class FindingChanges:
    """Aggregated finding-level changes."""
    new_findings: list[dict] = field(default_factory=list)
    resolved_findings: list[dict] = field(default_factory=list)


@dataclass
class PQCChanges:
    """PQC score/grade change."""
    old_score: float
    new_score: float
    old_grade: str
    new_grade: str

    @property
    def direction(self) -> str:
        if self.new_score > self.old_score:
            return "improved"
        elif self.new_score < self.old_score:
            return "degraded"
        return "unchanged"


@dataclass
class HostDiff:
    """Per-host diff result."""
    host: str
    status: str  # "added", "removed", "changed", "unchanged"
    cert_changes: list[CertChange] = field(default_factory=list)
    finding_changes: FindingChanges | None = None
    pqc_changes: PQCChanges | None = None
    tls_old: str = ""
    tls_new: str = ""


@dataclass
class DiffReport:
    """Top-level diff result."""
    format: str  # "single" or "fleet"
    host_diffs: list[HostDiff] = field(default_factory=list)

    @property
    def total_changes(self) -> int:
        return sum(1 for h in self.host_diffs if h.status != "unchanged")

    @property
    def has_changes(self) -> bool:
        return self.total_changes > 0


def detect_format(data: object) -> str:
    """Detect whether JSON is single-scan or fleet format."""
    if isinstance(data, list):
        return "fleet"
    if isinstance(data, dict) and ("target" in data or "chain" in data or "audit" in data):
        return "single"
    raise ValueError("Unrecognized JSON format. Expected single-scan object or fleet array.")


def diff_reports(baseline: dict | list, current: dict | list) -> DiffReport:
    """Compare two NotAfter JSON outputs and return a DiffReport."""
    fmt_b = detect_format(baseline)
    fmt_c = detect_format(current)
    if fmt_b != fmt_c:
        raise ValueError(
            f"Format mismatch: baseline is {fmt_b}, current is {fmt_c}. "
            "Both files must be the same format."
        )

    if fmt_b == "single":
        return _diff_single(baseline, current)
    return _diff_fleet(baseline, current)


def _diff_single(baseline: dict, current: dict) -> DiffReport:
    """Diff two single-scan JSON objects."""
    host = current.get("target", baseline.get("target", "unknown"))
    hd = _diff_host_detail(baseline, current, host)
    return DiffReport(format="single", host_diffs=[hd])


def _diff_fleet(baseline: list, current: list) -> DiffReport:
    """Diff two fleet JSON arrays."""
    def _fleet_key(e: dict) -> str:
        host = e.get("host", "unknown")
        port = e.get("port", 443)
        return f"{host}:{port}"

    base_map = {_fleet_key(e): e for e in baseline}
    curr_map = {_fleet_key(e): e for e in current}

    all_hosts = sorted(set(base_map) | set(curr_map))
    diffs: list[HostDiff] = []

    for host in all_hosts:
        old = base_map.get(host)
        new = curr_map.get(host)

        if old is None:
            diffs.append(HostDiff(host=host, status="added"))
            continue
        if new is None:
            diffs.append(HostDiff(host=host, status="removed"))
            continue

        # Fleet JSON is summary-level — compare counts and scores
        hd = HostDiff(host=host, status="unchanged")

        old_tls = old.get("tls_version") or ""
        new_tls = new.get("tls_version") or ""
        if old_tls != new_tls:
            hd.tls_old = old_tls
            hd.tls_new = new_tls
            hd.status = "changed"

        old_crit = old.get("critical", 0)
        new_crit = new.get("critical", 0)
        old_warn = old.get("warnings", 0)
        new_warn = new.get("warnings", 0)
        if old_crit != new_crit or old_warn != new_warn:
            hd.finding_changes = FindingChanges()
            if new_crit > old_crit:
                hd.finding_changes.new_findings.append(
                    {"detail": f"Critical: {old_crit} -> {new_crit}"}
                )
            elif new_crit < old_crit:
                hd.finding_changes.resolved_findings.append(
                    {"detail": f"Critical: {old_crit} -> {new_crit}"}
                )
            if new_warn > old_warn:
                hd.finding_changes.new_findings.append(
                    {"detail": f"Warnings: {old_warn} -> {new_warn}"}
                )
            elif new_warn < old_warn:
                hd.finding_changes.resolved_findings.append(
                    {"detail": f"Warnings: {old_warn} -> {new_warn}"}
                )
            hd.status = "changed"

        old_pqc = old.get("pqc_score")
        new_pqc = new.get("pqc_score")
        if old_pqc is not None and new_pqc is not None and old_pqc != new_pqc:
            hd.pqc_changes = PQCChanges(
                old_score=old_pqc, new_score=new_pqc,
                old_grade=old.get("pqc_grade", "?"),
                new_grade=new.get("pqc_grade", "?"),
            )
            hd.status = "changed"

        diffs.append(hd)

    return DiffReport(format="fleet", host_diffs=diffs)


def _diff_host_detail(baseline: dict, current: dict, host: str) -> HostDiff:
    """Diff two single-scan JSON objects with full detail."""
    hd = HostDiff(host=host, status="unchanged")

    # TLS version
    old_tls = baseline.get("tls_version") or ""
    new_tls = current.get("tls_version") or ""
    if old_tls != new_tls:
        hd.tls_old = old_tls
        hd.tls_new = new_tls
        hd.status = "changed"

    # Certificate chain
    hd.cert_changes = _diff_chain(
        baseline.get("chain", []),
        current.get("chain", []),
    )
    if hd.cert_changes:
        hd.status = "changed"

    # Findings
    hd.finding_changes = _diff_findings(
        baseline.get("audit", {}).get("findings", []),
        current.get("audit", {}).get("findings", []),
    )
    if hd.finding_changes.new_findings or hd.finding_changes.resolved_findings:
        hd.status = "changed"

    # PQC
    old_pqc = baseline.get("pqc")
    new_pqc = current.get("pqc")
    if old_pqc and new_pqc:
        old_s, new_s = old_pqc.get("score", 0), new_pqc.get("score", 0)
        old_g, new_g = old_pqc.get("grade", "?"), new_pqc.get("grade", "?")
        if old_s != new_s or old_g != new_g:
            hd.pqc_changes = PQCChanges(old_s, new_s, old_g, new_g)
            hd.status = "changed"

    return hd


def _diff_chain(old_chain: list[dict], new_chain: list[dict]) -> list[CertChange]:
    """Compare certificate chains by subject.

    Certs are first matched by exact subject. If multiple certs share the same
    subject, they are distinguished by not_after to avoid silent data loss.
    """
    def _group_by_subject(chain: list[dict]) -> dict[str, list[dict]]:
        groups: dict[str, list[dict]] = {}
        for c in chain:
            subj = c.get("subject") or ""
            groups.setdefault(subj, []).append(c)
        return groups

    old_groups = _group_by_subject(old_chain)
    new_groups = _group_by_subject(new_chain)

    changes: list[CertChange] = []
    all_subjects = sorted(set(old_groups) | set(new_groups))

    for subj in all_subjects:
        if not subj:
            continue  # skip empty subjects
        old_certs = old_groups.get(subj, [])
        new_certs = new_groups.get(subj, [])

        if not old_certs:
            for c in new_certs:
                changes.append(CertChange(type="added", subject=subj))
            continue
        if not new_certs:
            for c in old_certs:
                changes.append(CertChange(type="removed", subject=subj))
            continue

        # Match old vs new by position (usually 1:1)
        old_cert = old_certs[0]
        new_cert = new_certs[0]

        details: dict = {}
        old_na = old_cert.get("not_after", "")
        new_na = new_cert.get("not_after", "")
        old_algo = old_cert.get("sig_algorithm", "")
        new_algo = new_cert.get("sig_algorithm", "")

        if old_na != new_na:
            details["old_expiry"] = old_na[:10] if old_na else "?"
            details["new_expiry"] = new_na[:10] if new_na else "?"

        if old_algo != new_algo:
            details["old_algorithm"] = old_algo
            details["new_algorithm"] = new_algo

        if details:
            change_type = "renewed" if "old_expiry" in details else "modified"
            changes.append(CertChange(type=change_type, subject=subj, details=details))

        # Handle extras (cross-signed intermediates, etc.)
        if len(new_certs) > len(old_certs):
            for _ in range(len(new_certs) - len(old_certs)):
                changes.append(CertChange(type="added", subject=subj))
        elif len(old_certs) > len(new_certs):
            for _ in range(len(old_certs) - len(new_certs)):
                changes.append(CertChange(type="removed", subject=subj))

    return changes


def _diff_findings(old_findings: list[dict], new_findings: list[dict]) -> FindingChanges:
    """Compare findings by (check, component, severity) key."""
    def _key(f: dict) -> tuple:
        return (f.get("check", ""), f.get("component", ""), f.get("severity", ""))

    old_map = {_key(f): f for f in old_findings}
    new_map = {_key(f): f for f in new_findings}

    result = FindingChanges()

    for key, f in new_map.items():
        if key not in old_map:
            result.new_findings.append(f)

    for key, f in old_map.items():
        if key not in new_map:
            result.resolved_findings.append(f)

    return result


def diff_to_json(report: DiffReport) -> dict:
    """Serialize a DiffReport to a JSON-compatible dict."""
    return {
        "format": report.format,
        "total_changes": report.total_changes,
        "host_diffs": [
            {
                "host": hd.host,
                "status": hd.status,
                "cert_changes": [
                    {"type": cc.type, "subject": cc.subject, "details": cc.details}
                    for cc in hd.cert_changes
                ],
                "finding_changes": {
                    "new": hd.finding_changes.new_findings,
                    "resolved": hd.finding_changes.resolved_findings,
                } if hd.finding_changes else None,
                "pqc_changes": {
                    "old_score": hd.pqc_changes.old_score,
                    "new_score": hd.pqc_changes.new_score,
                    "old_grade": hd.pqc_changes.old_grade,
                    "new_grade": hd.pqc_changes.new_grade,
                    "direction": hd.pqc_changes.direction,
                } if hd.pqc_changes else None,
                "tls_change": {
                    "old": hd.tls_old, "new": hd.tls_new,
                } if hd.tls_old or hd.tls_new else None,
            }
            for hd in report.host_diffs
        ],
    }
