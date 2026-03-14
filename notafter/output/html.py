"""Self-contained HTML report (fonts loaded from Google Fonts CDN; falls back to system fonts offline)."""

from __future__ import annotations

from datetime import datetime, timezone
from html import escape

from notafter import __version__
from notafter.checks.engine import AuditReport, Finding, Severity
from notafter.pqc.scorer import PQCReport
from notafter.pqc.oids import QuantumSafety
from notafter.revocation.checker import RevocationReport, RevocationStatus
from notafter.scanner.tls import ScanResult


# ── Color constants ──

_GREEN = "#3fb950"
_RED = "#f85149"
_YELLOW = "#d29922"
_ORANGE = "#db6d28"
_BLUE = "#58a6ff"
_PURPLE = "#bc8cff"
_MUTED = "#8b949e"

_SEVERITY_COLORS = {
    Severity.CRITICAL: _RED,
    Severity.WARNING: _YELLOW,
    Severity.PASS: _GREEN,
    Severity.INFO: _BLUE,
}

_SEVERITY_LABELS = {
    Severity.CRITICAL: "CRIT",
    Severity.WARNING: "WARN",
    Severity.PASS: "PASS",
    Severity.INFO: "INFO",
}

_SEVERITY_ICONS = {
    Severity.CRITICAL: "&#x2716;",  # heavy X
    Severity.WARNING: "&#x26A0;",   # warning triangle
    Severity.PASS: "&#x2714;",      # check mark
    Severity.INFO: "&#x2139;",      # info circle
}

_GRADE_COLORS = {
    "A": _GREEN,
    "B": "#58d68d",
    "C": _YELLOW,
    "D": _ORANGE,
    "F": _RED,
}

_QUANTUM_LABELS = {
    QuantumSafety.QUANTUM_SAFE: "Quantum-Safe",
    QuantumSafety.QUANTUM_VULNERABLE: "Vulnerable",
    QuantumSafety.HYBRID: "Hybrid",
    QuantumSafety.UNKNOWN: "Unknown",
}

_QUANTUM_COLORS = {
    QuantumSafety.QUANTUM_SAFE: _GREEN,
    QuantumSafety.QUANTUM_VULNERABLE: _RED,
    QuantumSafety.HYBRID: _YELLOW,
    QuantumSafety.UNKNOWN: _MUTED,
}

_REVOCATION_COLORS = {
    RevocationStatus.GOOD: _GREEN,
    RevocationStatus.REVOKED: _RED,
    RevocationStatus.UNKNOWN: _YELLOW,
    RevocationStatus.ERROR: _RED,
    RevocationStatus.SKIPPED: _MUTED,
}


# ── CSS ──

_CSS = """\
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html { scroll-behavior: smooth; }
body {
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  background: #0d1117; color: #e6edf3; line-height: 1.6;
  -webkit-font-smoothing: antialiased; padding: 0; margin: 0;
}
.container { max-width: 1060px; margin: 0 auto; padding: 0 24px; }
h1, h2, h3 { letter-spacing: -0.02em; }
code, .mono { font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace; }

/* Header */
.report-header {
  background: #161b22; border-bottom: 1px solid #30363d;
  padding: 32px 0; margin-bottom: 32px;
}
.report-header h1 { font-size: 1.75rem; font-weight: 800; margin-bottom: 4px; }
.report-header .meta { color: #8b949e; font-size: 0.85rem; }
.report-header .meta span { margin-right: 18px; }

/* Section */
.section { margin-bottom: 32px; }
.section h2 {
  font-size: 1.2rem; font-weight: 700; margin-bottom: 16px;
  padding-bottom: 8px; border-bottom: 1px solid #30363d;
}

/* Summary bar */
.summary-bar {
  display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 24px;
}
.summary-badge {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 6px 16px; border-radius: 20px; font-size: 0.85rem;
  font-weight: 600; border: 1px solid #30363d; background: #161b22;
}

/* Tables */
table {
  width: 100%; border-collapse: collapse; font-size: 0.88rem;
  margin-bottom: 8px;
}
th, td {
  text-align: left; padding: 10px 14px;
  border-bottom: 1px solid #21262d;
}
th {
  color: #8b949e; font-weight: 600; font-size: 0.78rem;
  text-transform: uppercase; letter-spacing: 0.04em;
  background: #161b22;
}
.table-wrap { overflow-x: auto; -webkit-overflow-scrolling: touch; }

/* Severity row backgrounds */
.row-critical { background: rgba(248,81,73,0.08); }
.row-warning  { background: rgba(210,153,34,0.08); }
.row-pass     { background: rgba(63,185,80,0.06); }
.row-info     { background: rgba(88,166,255,0.06); }

/* Badges / pills */
.pill {
  display: inline-block; padding: 2px 10px; border-radius: 12px;
  font-size: 0.78rem; font-weight: 600; white-space: nowrap;
}
.icon-cell { text-align: center; font-size: 1.1rem; width: 36px; }

/* PQC panel */
.pqc-panel {
  background: #161b22; border: 1px solid #30363d; border-radius: 10px;
  padding: 24px; margin-bottom: 24px;
}
.pqc-score-row {
  display: flex; align-items: center; gap: 24px; margin-bottom: 20px;
  flex-wrap: wrap;
}
.pqc-score-circle {
  width: 80px; height: 80px; border-radius: 50%;
  display: flex; flex-direction: column; align-items: center;
  justify-content: center; font-weight: 800; border: 3px solid;
}
.pqc-score-circle .score { font-size: 1.3rem; line-height: 1; }
.pqc-score-circle .max { font-size: 0.7rem; color: #8b949e; }
.pqc-grade {
  font-size: 2rem; font-weight: 800;
  font-family: 'JetBrains Mono', monospace;
}
.pqc-info { color: #8b949e; font-size: 0.88rem; }
.rec-list { list-style: none; padding: 0; margin-top: 12px; }
.rec-list li {
  padding: 6px 0; color: #e6edf3; font-size: 0.88rem;
  border-bottom: 1px solid #21262d;
}
.rec-list li::before { content: "> "; color: #8b949e; font-family: 'JetBrains Mono', monospace; }

/* Cert details */
.cert-grid {
  display: grid; grid-template-columns: 140px 1fr;
  gap: 4px 16px; font-size: 0.88rem; margin-bottom: 16px;
}
.cert-grid dt { color: #8b949e; font-weight: 600; }
.cert-grid dd { color: #e6edf3; word-break: break-all; }

/* Fleet stat cards */
.stat-cards {
  display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 24px;
}
.stat-card {
  flex: 1; min-width: 140px; background: #161b22;
  border: 1px solid #30363d; border-radius: 10px;
  padding: 20px; text-align: center;
}
.stat-card .stat-value {
  font-size: 2rem; font-weight: 800;
  font-family: 'JetBrains Mono', monospace; line-height: 1;
}
.stat-card .stat-label {
  font-size: 0.82rem; color: #8b949e; margin-top: 4px; font-weight: 500;
}

/* Fleet host details */
details { margin-bottom: 2px; }
details summary {
  cursor: pointer; list-style: none; padding: 0;
}
details summary::-webkit-details-marker { display: none; }
details summary::marker { display: none; }
details[open] .host-details { padding: 16px 20px; background: #0d1117; border-bottom: 1px solid #21262d; }

/* Footer */
.report-footer {
  margin-top: 48px; padding: 24px 0; border-top: 1px solid #30363d;
  text-align: center; color: #8b949e; font-size: 0.82rem;
}

/* Responsive */
@media (max-width: 768px) {
  .report-header h1 { font-size: 1.3rem; }
  .pqc-score-row { flex-direction: column; align-items: flex-start; }
  .cert-grid { grid-template-columns: 1fr; }
  .stat-cards { flex-direction: column; }
  th, td { padding: 8px 10px; font-size: 0.82rem; }
}
"""


# ── Helpers ──

def _e(text: str | None) -> str:
    """HTML-escape a string, returning empty string for None."""
    if text is None:
        return ""
    return escape(str(text))


def _pill(label: str, color: str) -> str:
    """Return a styled pill/badge ``<span>``."""
    return f'<span class="pill" style="color:{color};border:1px solid {color}">{label}</span>'


def _severity_pill(severity: Severity) -> str:
    color = _SEVERITY_COLORS.get(severity, _MUTED)
    label = _SEVERITY_LABELS.get(severity, "?")
    return _pill(label, color)


def _severity_icon(severity: Severity) -> str:
    color = _SEVERITY_COLORS.get(severity, _MUTED)
    icon = _SEVERITY_ICONS.get(severity, "?")
    return f'<span style="color:{color}">{icon}</span>'


def _revocation_pill(status: RevocationStatus) -> str:
    color = _REVOCATION_COLORS.get(status, _MUTED)
    label = status.value.upper()
    return _pill(label, color)


def _quantum_pill(safety: QuantumSafety) -> str:
    color = _QUANTUM_COLORS.get(safety, _MUTED)
    label = _QUANTUM_LABELS.get(safety, "Unknown")
    return _pill(label, color)


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _severity_row_class(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "row-critical",
        Severity.WARNING: "row-warning",
        Severity.PASS: "row-pass",
        Severity.INFO: "row-info",
    }.get(severity, "")


def _page_wrapper(title: str, body: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'none'; script-src 'none'">
<title>{_e(title)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;700;800&display=swap" rel="stylesheet">
<style>
{_CSS}
</style>
</head>
<body>
{body}
</body>
</html>"""


# ── Scan report ──

def generate_scan_html(
    scan: ScanResult,
    report: AuditReport,
    pqc_report: PQCReport | None = None,
    revocation_report: RevocationReport | None = None,
) -> str:
    """Generate a self-contained HTML report for a single scan."""
    timestamp = _timestamp()
    parts: list[str] = []

    # Header
    parts.append(f"""
<div class="report-header">
  <div class="container">
    <h1>Certificate Audit Report</h1>
    <div class="meta">
      <span>Target: <strong class="mono">{_e(scan.host)}:{scan.port}</strong></span>
      <span>Scanned: {timestamp}</span>
      <span>notafter v{_e(__version__)}</span>
    </div>
  </div>
</div>
""")

    parts.append('<div class="container">')

    # Summary bar
    crit_color = _SEVERITY_COLORS[Severity.CRITICAL]
    warn_color = _SEVERITY_COLORS[Severity.WARNING]
    pass_color = _SEVERITY_COLORS[Severity.PASS]
    parts.append(f"""
<div class="summary-bar">
  <span class="summary-badge" style="color:{crit_color}">{report.critical_count} Critical</span>
  <span class="summary-badge" style="color:{warn_color}">{report.warning_count} Warnings</span>
  <span class="summary-badge" style="color:{pass_color}">{report.pass_count} Passed</span>
</div>
""")

    # Audit findings table
    parts.append('<div class="section"><h2>Audit Findings</h2>')
    parts.append('<div class="table-wrap"><table>')
    parts.append("<thead><tr><th style='width:36px'></th><th>Check</th><th>Component</th><th>Finding</th><th>Remediation</th></tr></thead>")
    parts.append("<tbody>")
    for f in report.findings:
        row_cls = _severity_row_class(f.severity)
        parts.append(f"<tr class='{row_cls}'>")
        parts.append(f"<td class='icon-cell'>{_severity_icon(f.severity)}</td>")
        parts.append(f"<td class='mono' style='white-space:nowrap'>{_e(f.check)}</td>")
        parts.append(f"<td>{_e(f.component)}</td>")
        parts.append(f"<td>{_e(f.message)}</td>")
        parts.append(f"<td style='color:#8b949e'>{_e(f.remediation) if f.remediation else '&mdash;'}</td>")
        parts.append("</tr>")
    parts.append("</tbody></table></div></div>")

    # PQC panel
    if pqc_report is not None:
        grade_color = _GRADE_COLORS.get(pqc_report.grade, _MUTED)
        parts.append('<div class="section"><h2>PQC Readiness</h2>')
        parts.append('<div class="pqc-panel">')

        # Score row
        parts.append('<div class="pqc-score-row">')
        parts.append(
            f'<div class="pqc-score-circle" style="border-color:{grade_color};color:{grade_color}">'
            f'<span class="score">{pqc_report.score}/{pqc_report.max_score}</span>'
            f'</div>'
        )
        parts.append(f'<span class="pqc-grade" style="color:{grade_color}">Grade {pqc_report.grade}</span>')

        safety_color = _QUANTUM_COLORS.get(pqc_report.overall_safety, _MUTED)
        safety_label = _QUANTUM_LABELS.get(pqc_report.overall_safety, "Unknown")
        parts.append(f'<span class="pqc-info">Overall: <strong style="color:{safety_color}">{safety_label}</strong></span>')
        parts.append('</div>')

        # Component breakdown table
        parts.append('<div class="table-wrap"><table>')
        parts.append("<thead><tr><th>Component</th><th>Algorithm</th><th>Quantum Safety</th><th style='text-align:center'>Points</th></tr></thead>")
        parts.append("<tbody>")
        for pf in pqc_report.findings:
            pts = f"{pf.points_earned}/{pf.points_possible}" if pf.points_possible > 0 else "&mdash;"
            parts.append(
                f"<tr><td>{_e(pf.component)}</td>"
                f"<td class='mono'>{_e(pf.algorithm)}</td>"
                f"<td>{_quantum_pill(pf.quantum_safety)}</td>"
                f"<td style='text-align:center' class='mono'>{pts}</td></tr>"
            )
        parts.append("</tbody></table></div>")

        # CNSA 2.0
        if pqc_report.cnsa2_next_deadline:
            cnsa_color = _GREEN if pqc_report.cnsa2_compliant else _RED
            cnsa_label = "COMPLIANT" if pqc_report.cnsa2_compliant else "NOT COMPLIANT"
            parts.append(
                f'<p style="margin-top:12px">CNSA 2.0: '
                f'<strong style="color:{cnsa_color}">{cnsa_label}</strong> '
                f'<span style="color:#8b949e">&mdash; Next deadline ({pqc_report.cnsa2_days_remaining} days): '
                f'{_e(pqc_report.cnsa2_next_deadline)}</span></p>'
            )

        # Recommendations
        if pqc_report.recommendations:
            parts.append('<ul class="rec-list">')
            for rec in pqc_report.recommendations:
                parts.append(f"<li>{_e(rec)}</li>")
            parts.append("</ul>")

        parts.append("</div></div>")

    # Revocation status
    if revocation_report is not None:
        parts.append('<div class="section"><h2>Revocation Status</h2>')
        if revocation_report.is_revoked:
            parts.append(f'<p style="color:{_RED};font-weight:700;margin-bottom:12px">WARNING: Certificate has been REVOKED</p>')

        parts.append('<div class="table-wrap"><table>')
        parts.append("<thead><tr><th>Method</th><th>Status</th><th>Details</th><th>URL</th></tr></thead>")
        parts.append("<tbody>")

        # OCSP
        parts.append(
            f"<tr><td>OCSP</td>"
            f"<td>{_revocation_pill(revocation_report.ocsp.status)}</td>"
            f"<td>{_e(revocation_report.ocsp.message)}</td>"
            f"<td class='mono' style='font-size:0.78rem;color:#8b949e'>{_e(revocation_report.ocsp.responder_url) or '&mdash;'}</td></tr>"
        )

        # CRL
        parts.append(
            f"<tr><td>CRL</td>"
            f"<td>{_revocation_pill(revocation_report.crl.status)}</td>"
            f"<td>{_e(revocation_report.crl.message)}</td>"
            f"<td class='mono' style='font-size:0.78rem;color:#8b949e'>{_e(revocation_report.crl.crl_url) or '&mdash;'}</td></tr>"
        )

        # CT
        ct_logged = revocation_report.ct.logged
        if ct_logged:
            ct_label, ct_color = "LOGGED", _GREEN
        elif ct_logged is False:
            ct_label, ct_color = "NOT FOUND", _YELLOW
        else:
            ct_label, ct_color = "N/A", _MUTED
        ct_pill = _pill(ct_label, ct_color)
        ct_url = _e(revocation_report.ct.crt_sh_url) if revocation_report.ct.crt_sh_url else "&mdash;"
        parts.append(
            f"<tr><td>CT</td>"
            f"<td>{ct_pill}</td>"
            f"<td>{_e(revocation_report.ct.message)}</td>"
            f"<td class='mono' style='font-size:0.78rem;color:#8b949e'>{ct_url}</td></tr>"
        )

        parts.append("</tbody></table></div></div>")

    # Certificate details
    if scan.chain:
        parts.append('<div class="section"><h2>Certificate Details</h2>')
        for i, cert in enumerate(scan.chain):
            if i == 0:
                label = "Leaf Certificate"
            elif cert.is_self_signed and cert.is_ca:
                label = f"Root Certificate (#{i})"
            else:
                label = f"Intermediate Certificate #{i}"

            parts.append(f'<h3 style="font-size:1rem;margin:16px 0 8px;color:{_BLUE}">{label}</h3>')
            parts.append('<dl class="cert-grid">')
            parts.append(f"<dt>Subject</dt><dd class='mono'>{_e(cert.subject)}</dd>")
            parts.append(f"<dt>Issuer</dt><dd class='mono'>{_e(cert.issuer)}</dd>")
            parts.append(f"<dt>Not Before</dt><dd>{_e(cert.not_before)}</dd>")
            parts.append(f"<dt>Not After</dt><dd>{_e(cert.not_after)}</dd>")
            key_label = f"{cert.key_type}" + (f" ({cert.key_size} bits)" if cert.key_size else "")
            parts.append(f"<dt>Key Type</dt><dd>{_e(key_label)}</dd>")
            parts.append(f"<dt>Signature</dt><dd class='mono'>{_e(cert.sig_algorithm_name)}</dd>")
            parts.append(f"<dt>Serial</dt><dd class='mono'>{_e(cert.serial)}</dd>")
            if cert.san_names:
                san_str = ", ".join(cert.san_names[:10])
                if len(cert.san_names) > 10:
                    san_str += f" (+{len(cert.san_names) - 10} more)"
                parts.append(f"<dt>SAN</dt><dd>{_e(san_str)}</dd>")
            parts.append("</dl>")
        parts.append("</div>")

    # TLS connection info
    if scan.tls_version or scan.cipher_suite or scan.key_exchange:
        parts.append('<div class="section"><h2>TLS Connection</h2>')
        parts.append('<dl class="cert-grid">')
        if scan.tls_version:
            parts.append(f"<dt>Protocol</dt><dd>{_e(scan.tls_version)}</dd>")
        if scan.cipher_suite:
            parts.append(f"<dt>Cipher Suite</dt><dd class='mono'>{_e(scan.cipher_suite)}</dd>")
        if scan.key_exchange:
            parts.append(f"<dt>Key Exchange</dt><dd>{_e(scan.key_exchange)}</dd>")
        if scan.peer_address:
            parts.append(f"<dt>Peer Address</dt><dd class='mono'>{_e(scan.peer_address)}</dd>")
        parts.append("</dl></div>")

    # Footer
    parts.append(f"""
<div class="report-footer">
  Generated by <strong>notafter v{_e(__version__)}</strong> &mdash; {timestamp}
</div>
""")

    parts.append("</div>")  # close container

    return _page_wrapper(f"Certificate Audit: {scan.host}:{scan.port}", "\n".join(parts).lstrip("\n"))


# ── Fleet report ──

def generate_fleet_html(results: list[dict]) -> str:
    """Generate a self-contained HTML report for a fleet scan.

    Args:
        results: List of dicts with keys: host, port, error, tls_version,
                 critical, warnings, pqc_score (optional), pqc_grade (optional),
                 audit (optional AuditReport), scan (optional ScanResult),
                 pqc_report (optional PQCReport).
    """
    timestamp = _timestamp()
    total = len(results)
    total_critical = sum(r.get("critical", 0) for r in results)
    total_warning = sum(r.get("warnings", 0) for r in results)
    total_clean = sum(
        1 for r in results
        if not r.get("error") and r.get("critical", 0) == 0 and r.get("warnings", 0) == 0
    )
    total_errors = sum(1 for r in results if r.get("error"))

    parts: list[str] = []

    # Header
    parts.append(f"""
<div class="report-header">
  <div class="container">
    <h1>Fleet Scan Report</h1>
    <div class="meta">
      <span>Hosts: <strong>{total}</strong></span>
      <span>Scanned: {timestamp}</span>
      <span>notafter v{_e(__version__)}</span>
    </div>
  </div>
</div>
""")

    parts.append('<div class="container">')

    # Stat cards
    parts.append('<div class="stat-cards">')
    parts.append(
        f'<div class="stat-card">'
        f'<div class="stat-value" style="color:{_BLUE}">{total}</div>'
        f'<div class="stat-label">Total Hosts</div></div>'
    )
    parts.append(
        f'<div class="stat-card">'
        f'<div class="stat-value" style="color:{_RED}">{total_critical}</div>'
        f'<div class="stat-label">Critical</div></div>'
    )
    parts.append(
        f'<div class="stat-card">'
        f'<div class="stat-value" style="color:{_YELLOW}">{total_warning}</div>'
        f'<div class="stat-label">Warnings</div></div>'
    )
    parts.append(
        f'<div class="stat-card">'
        f'<div class="stat-value" style="color:{_GREEN}">{total_clean}</div>'
        f'<div class="stat-label">Clean</div></div>'
    )
    if total_errors:
        parts.append(
            f'<div class="stat-card">'
            f'<div class="stat-value" style="color:{_RED}">{total_errors}</div>'
            f'<div class="stat-label">Errors</div></div>'
        )
    parts.append("</div>")

    # Fleet table
    parts.append('<div class="section"><h2>Fleet Results</h2>')
    parts.append('<div class="table-wrap"><table>')
    parts.append(
        "<thead><tr>"
        "<th>Host</th><th>TLS Version</th>"
        "<th style='text-align:center'>Critical</th>"
        "<th style='text-align:center'>Warnings</th>"
        "<th style='text-align:center'>PQC Score</th>"
        "<th>Status</th>"
        "</tr></thead>"
    )
    parts.append("<tbody>")

    if not results:
        parts.append('<tr><td colspan="6" style="text-align:center;color:#8b949e;padding:24px;">No hosts scanned.</td></tr>')

    for entry in results:
        host_label = f"{_e(str(entry['host']))}:{entry['port']}"

        if entry.get("error"):
            parts.append(
                f"<tr class='row-critical'>"
                f"<td><details><summary class='mono'>{host_label}</summary>"
                f"<div class='host-details'><p style='color:{_RED}'>{_e(str(entry['error']))}</p></div>"
                f"</details></td>"
                f"<td>&mdash;</td><td style='text-align:center'>&mdash;</td>"
                f"<td style='text-align:center'>&mdash;</td>"
                f"<td style='text-align:center'>&mdash;</td>"
                f"<td>{_pill('ERROR', _RED)}</td></tr>"
            )
            continue

        crit = entry.get("critical", 0)
        warns = entry.get("warnings", 0)
        crit_color = _RED if crit > 0 else _GREEN
        warn_color = _YELLOW if warns > 0 else _GREEN

        pqc_score = entry.get("pqc_score")
        pqc_grade = entry.get("pqc_grade", "")
        if pqc_score is not None:
            pqc_g_color = _GRADE_COLORS.get(pqc_grade, _MUTED)
            pqc_cell = f"<span style='color:{pqc_g_color}' class='mono'>{pqc_score}/10 {pqc_grade}</span>"
        else:
            pqc_cell = "&mdash;"

        if crit > 0:
            status_pill = _pill("CRITICAL", _RED)
            row_class = "row-critical"
        elif warns > 0:
            status_pill = _pill("WARNING", _YELLOW)
            row_class = "row-warning"
        else:
            status_pill = _pill("CLEAN", _GREEN)
            row_class = "row-pass"

        # Build the host details section if audit data is available
        detail_html = ""
        audit: AuditReport | None = entry.get("audit")
        if audit and audit.findings:
            detail_html += '<div class="host-details"><table style="font-size:0.82rem">'
            detail_html += "<thead><tr><th style='width:30px'></th><th>Check</th><th>Component</th><th>Finding</th></tr></thead><tbody>"
            for f in audit.findings:
                rc = _severity_row_class(f.severity)
                detail_html += (
                    f"<tr class='{rc}'>"
                    f"<td class='icon-cell'>{_severity_icon(f.severity)}</td>"
                    f"<td class='mono'>{_e(f.check)}</td>"
                    f"<td>{_e(f.component)}</td>"
                    f"<td>{_e(f.message)}</td></tr>"
                )
            detail_html += "</tbody></table></div>"

        tls_ver = _e(entry.get("tls_version") or "") or "&mdash;"

        if detail_html:
            host_cell = (
                f"<details><summary class='mono' style='padding:2px 0'>{host_label}</summary>"
                f"{detail_html}</details>"
            )
        else:
            host_cell = f"<span class='mono'>{host_label}</span>"

        parts.append(
            f"<tr class='{row_class}'>"
            f"<td>{host_cell}</td>"
            f"<td>{tls_ver}</td>"
            f"<td style='text-align:center;color:{crit_color}'>{crit}</td>"
            f"<td style='text-align:center;color:{warn_color}'>{warns}</td>"
            f"<td style='text-align:center'>{pqc_cell}</td>"
            f"<td>{status_pill}</td></tr>"
        )

    parts.append("</tbody></table></div></div>")

    # Footer
    parts.append(f"""
<div class="report-footer">
  Generated by <strong>notafter v{_e(__version__)}</strong> &mdash; {timestamp}
</div>
""")

    parts.append("</div>")  # close container

    return _page_wrapper(f"Fleet Scan Report ({total} hosts)", "\n".join(parts).lstrip("\n"))
