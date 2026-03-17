"""Interactive HTML dashboard — single-page report with tabs, drill-down, and filtering.

Replaces the static scan/fleet HTML reports with a unified interactive dashboard.
Fonts loaded from Google Fonts CDN; falls back to system fonts offline.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from html import escape

from notafter import __version__
from notafter.cbom.generator import generate_cbom
from notafter.checks.engine import AuditReport, Finding, Severity
from notafter.pqc.scorer import PQCReport
from notafter.pqc.oids import QuantumSafety
from notafter.revocation.checker import RevocationReport, RevocationStatus
from notafter.scanner.tls import ScanResult


@dataclass
class HostReport:
    """Unified per-host bundle for dashboard rendering."""

    scan: ScanResult
    audit: AuditReport
    pqc: PQCReport | None = None
    revocation: RevocationReport | None = None


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

_SEVERITY_ICONS = {
    Severity.CRITICAL: "&#x2716;",
    Severity.WARNING: "&#x26A0;",
    Severity.PASS: "&#x2714;",
    Severity.INFO: "&#x2139;",
}


# ── Helpers ──

def _e(text: object) -> str:
    if text is None:
        return ""
    return escape(str(text))


def _pill(label: str, color: str) -> str:
    return f'<span class="pill" style="color:{color};border:1px solid {color}">{_e(label)}</span>'


def _severity_icon(severity: Severity) -> str:
    color = _SEVERITY_COLORS.get(severity, _MUTED)
    icon = _SEVERITY_ICONS.get(severity, "?")
    return f'<span style="color:{color}">{icon}</span>'


def _severity_row_class(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "row-critical",
        Severity.WARNING: "row-warning",
        Severity.PASS: "row-pass",
        Severity.INFO: "row-info",
    }.get(severity, "")


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


# ── Dashboard generator ──

def generate_dashboard(hosts: list[HostReport]) -> str:
    """Generate a self-contained interactive HTML dashboard.

    Works for both single-host scans and fleet scans. When ``hosts`` has
    one entry the dashboard automatically focuses on that host's details.

    Raises:
        ValueError: If ``hosts`` is empty.
    """
    if not hosts:
        raise ValueError("At least one HostReport is required")

    ts = _timestamp()
    is_fleet = len(hosts) > 1

    # Aggregate stats
    total_hosts = len(hosts)
    total_critical = sum(h.audit.critical_count for h in hosts)
    total_warning = sum(h.audit.warning_count for h in hosts)
    total_errors = sum(1 for h in hosts if h.scan.error)
    total_clean = sum(
        1 for h in hosts
        if not h.scan.error and h.audit.critical_count == 0 and h.audit.warning_count == 0
    )

    # Collect all action items (non-PASS findings with remediation)
    action_items: list[tuple[str, Finding]] = []
    for h in hosts:
        host_label = f"{h.scan.host}:{h.scan.port}"
        for f in h.audit.findings:
            if f.severity in (Severity.CRITICAL, Severity.WARNING, Severity.INFO) and f.remediation:
                action_items.append((host_label, f))

    # Collect certificate inventory
    cert_rows: list[dict] = []
    for h in hosts:
        if not h.scan.chain:
            continue
        host_label = f"{h.scan.host}:{h.scan.port}"
        for i, c in enumerate(h.scan.chain):
            role = "Leaf" if i == 0 else ("Root" if c.is_self_signed and c.is_ca else f"Int #{i}")
            cert_rows.append({
                "host": host_label,
                "role": role,
                "subject": c.subject,
                "issuer": c.issuer,
                "not_after": c.not_after,
                "key_type": c.key_type,
                "key_size": c.key_size,
                "sig": c.sig_algorithm_name,
                "san": ", ".join(c.san_names[:5]) + (f" (+{len(c.san_names)-5} more)" if len(c.san_names) > 5 else "") if c.san_names else "",
                "serial": c.serial,
            })

    # Determine which tabs to show
    has_pqc = any(h.pqc is not None for h in hosts)
    has_revocation = any(h.revocation is not None for h in hosts)
    has_certs = any(h.scan.chain for h in hosts)

    # Build tab list
    tabs = ["overview"]
    tabs.append("inventory")
    if has_certs:
        tabs.append("timeline")
    if has_pqc:
        tabs.append("pqc")
    if has_revocation:
        tabs.append("revocation")
    if has_certs:
        tabs.append("cbom")
    tabs.append("hosts")

    # Title
    if is_fleet:
        title = f"Fleet Dashboard ({total_hosts} hosts)"
        header_subtitle = f"{total_hosts} hosts scanned"
    else:
        h0 = hosts[0]
        title = f"Certificate Audit: {h0.scan.host}:{h0.scan.port}"
        header_subtitle = f"Target: {_e(h0.scan.host)}:{h0.scan.port}"

    parts: list[str] = []

    # ── Header ──
    parts.append(f"""
<div class="report-header">
  <div class="container">
    <h1>NotAfter Dashboard</h1>
    <div class="meta">
      <span>{header_subtitle}</span>
      <span>Scanned: {ts}</span>
      <span>notafter v{_e(__version__)}</span>
    </div>
    <button class="theme-toggle" onclick="toggleTheme()" title="Toggle light/dark theme">&#x263E;</button>
  </div>
</div>
""")

    parts.append('<div class="container">')

    # ── Stat cards ──
    parts.append('<div class="stat-cards">')
    if is_fleet:
        parts.append(f'<div class="stat-card"><div class="stat-value" style="color:{_BLUE}">{total_hosts}</div><div class="stat-label">Hosts</div></div>')
    parts.append(f'<div class="stat-card"><div class="stat-value" style="color:{_RED}">{total_critical}</div><div class="stat-label">Critical</div></div>')
    parts.append(f'<div class="stat-card"><div class="stat-value" style="color:{_YELLOW}">{total_warning}</div><div class="stat-label">Warnings</div></div>')
    parts.append(f'<div class="stat-card"><div class="stat-value" style="color:{_GREEN}">{total_clean}</div><div class="stat-label">Clean</div></div>')
    if total_errors:
        parts.append(f'<div class="stat-card"><div class="stat-value" style="color:{_RED}">{total_errors}</div><div class="stat-label">Errors</div></div>')

    # PQC fleet average
    pqc_scores = [h.pqc.score for h in hosts if h.pqc is not None]
    if pqc_scores:
        avg_pqc = sum(pqc_scores) / len(pqc_scores)
        avg_color = _GREEN if avg_pqc >= 7 else _YELLOW if avg_pqc >= 4 else _RED
        parts.append(f'<div class="stat-card"><div class="stat-value" style="color:{avg_color}">{avg_pqc:.1f}</div><div class="stat-label">Avg PQC Score</div></div>')
    parts.append('</div>')

    # ── Tab nav ──
    tab_labels = {
        "overview": f"Overview ({len(action_items)} findings)" if action_items else "Overview",
        "inventory": f"Certificates ({len(cert_rows)})",
        "timeline": "Timeline",
        "pqc": "PQC Posture",
        "revocation": "Revocation",
        "cbom": "CBOM",
        "hosts": "Host Details",
    }
    parts.append('<div class="tab-nav" role="tablist">')
    for i, tab in enumerate(tabs):
        active = " active" if i == 0 else ""
        selected = "true" if i == 0 else "false"
        parts.append(f'<button class="tab-btn{active}" data-tab="{tab}" role="tab" aria-selected="{selected}" aria-controls="tab-{tab}">{tab_labels[tab]}</button>')
    parts.append('</div>')

    # ── Tab: Overview ──
    parts.append('<div class="tab-content active" id="tab-overview" role="tabpanel">')
    overview_title = "Fleet Overview" if is_fleet else "Overview"
    parts.append(f'<div class="section"><h2>{overview_title}</h2>')
    parts.append('<div class="filter-bar"><input type="text" id="overview-filter" placeholder="Filter hosts..." class="filter-input" aria-label="Filter hosts"></div>')
    parts.append('<div class="table-wrap"><table id="overview-table">')
    parts.append('<thead><tr>')
    parts.append('<th class="sortable" data-col="0">Host</th>')
    parts.append('<th class="sortable" data-col="1">TLS</th>')
    parts.append('<th class="sortable" data-col="2" style="text-align:center">Critical</th>')
    parts.append('<th class="sortable" data-col="3" style="text-align:center">Warnings</th>')
    if has_pqc:
        parts.append('<th class="sortable" data-col="4" style="text-align:center">PQC</th>')
    parts.append('<th>Status</th>')
    parts.append('</tr></thead><tbody>')

    overview_colspan = 6 if has_pqc else 5

    for h in hosts:
        host_label = f"{h.scan.host}:{h.scan.port}"
        if h.scan.error:
            pqc_cell = '<td style="text-align:center">&mdash;</td>' if has_pqc else ''
            parts.append(
                f'<tr class="row-critical">'
                f'<td class="mono">{_e(host_label)}</td>'
                f'<td>&mdash;</td>'
                f'<td style="text-align:center">&mdash;</td>'
                f'<td style="text-align:center">&mdash;</td>'
                f'{pqc_cell}'
                f'<td>{_pill("ERROR", _RED)}</td></tr>'
            )
            # Inline expand for error hosts
            parts.append(
                f'<tr class="overview-expand" data-expand="{_e(host_label)}" style="display:none">'
                f'<td colspan="{overview_colspan}"><div class="inline-findings">'
                f'<div class="finding-row"><span style="color:{_RED}">{_e(h.scan.error)}</span></div>'
                f'<a class="detail-link" data-target="{_e(host_label)}">Full details &rarr;</a>'
                f'</div></td></tr>'
            )
            continue

        crit = h.audit.critical_count
        warns = h.audit.warning_count
        crit_color = _RED if crit > 0 else _GREEN
        warn_color = _YELLOW if warns > 0 else _GREEN

        pqc_cell = ""
        if has_pqc:
            if h.pqc:
                gc = _GRADE_COLORS.get(h.pqc.grade, _MUTED)
                pqc_cell = f'<td style="text-align:center"><span style="color:{gc}" class="mono">{h.pqc.score}/10 {h.pqc.grade}</span></td>'
            else:
                pqc_cell = '<td style="text-align:center">&mdash;</td>'

        if crit > 0:
            status = _pill("CRITICAL", _RED)
            row_cls = "row-critical"
        elif warns > 0:
            status = _pill("WARNING", _YELLOW)
            row_cls = "row-warning"
        else:
            status = _pill("CLEAN", _GREEN)
            row_cls = "row-pass"

        tls_ver = _e(h.scan.tls_version or "") or "&mdash;"

        parts.append(
            f'<tr class="{row_cls}" data-host="{_e(h.scan.host)}">'
            f'<td class="mono host-link" data-target="{_e(host_label)}">'
            f'<span class="host-expand-icon">&#x25B8;</span>{_e(host_label)}</td>'
            f'<td>{tls_ver}</td>'
            f'<td style="text-align:center;color:{crit_color}">{crit}</td>'
            f'<td style="text-align:center;color:{warn_color}">{warns}</td>'
            f'{pqc_cell}'
            f'<td>{status}</td></tr>'
        )

        # Inline expand row with per-host findings summary
        non_pass = [f for f in h.audit.findings if f.severity != Severity.PASS]
        expand_parts: list[str] = []
        if non_pass:
            for finding in non_pass:
                icon = _severity_icon(finding.severity)
                action = f' <span class="action">&mdash; {_e(finding.remediation)}</span>' if finding.remediation else ''
                expand_parts.append(
                    f'<div class="finding-row">{icon} '
                    f'<span class="msg">{_e(finding.message)}</span>{action}</div>'
                )
        else:
            expand_parts.append(f'<div class="finding-row"><span style="color:{_GREEN}">&#x2714; All checks passed.</span></div>')

        parts.append(
            f'<tr class="overview-expand" data-expand="{_e(host_label)}" style="display:none">'
            f'<td colspan="{overview_colspan}"><div class="inline-findings">'
            + "".join(expand_parts)
            + f'<a class="detail-link" data-target="{_e(host_label)}">Full details &rarr;</a>'
            f'</div></td></tr>'
        )

    parts.append('</tbody></table></div></div></div>')

    # ── Tab: Certificate Inventory ──
    parts.append('<div class="tab-content" id="tab-inventory" role="tabpanel">')
    parts.append('<div class="section"><h2>Certificate Inventory</h2>')
    parts.append('<div class="filter-bar"><input type="text" id="inventory-filter" placeholder="Filter certificates..." class="filter-input" aria-label="Filter certificates"><button class="export-btn" onclick="exportCSV(\'inventory-table\',\'notafter-inventory\')">Export CSV</button></div>')
    parts.append('<div class="table-wrap"><table id="inventory-table">')
    parts.append('<thead><tr>')
    col_offset = 0
    if is_fleet:
        parts.append('<th class="sortable" data-col="0">Host</th>')
        col_offset = 1
    parts.append(f'<th>Role</th><th class="sortable" data-col="{col_offset + 1}">Subject</th><th class="sortable" data-col="{col_offset + 2}">Expires</th><th>Key</th><th>Signature</th><th>SAN</th>')
    parts.append('</tr></thead><tbody>')

    for cr in cert_rows:
        # Color expiry date
        try:
            exp_dt = datetime.fromisoformat(cr["not_after"])
            now = datetime.now(timezone.utc)
            days_left = (exp_dt - now).days
            if days_left < 0:
                exp_color = _RED
            elif days_left < 30:
                exp_color = _YELLOW
            else:
                exp_color = _GREEN
        except (ValueError, TypeError):
            exp_color = _MUTED
            days_left = None

        key_label = f"{cr['key_type']}" + (f" ({cr['key_size']})" if cr['key_size'] else "")
        exp_display = _e(cr["not_after"][:10]) if cr["not_after"] else "&mdash;"
        if days_left is not None:
            exp_display += f' <span style="color:{_MUTED};font-size:0.78rem">({days_left}d)</span>'

        host_cell = f'<td class="mono" style="white-space:nowrap">{_e(cr["host"])}</td>' if is_fleet else ""

        parts.append(
            f'<tr>'
            f'{host_cell}'
            f'<td>{_pill(cr["role"], _BLUE)}</td>'
            f'<td style="max-width:220px;overflow:hidden;text-overflow:ellipsis" title="{_e(cr["subject"])}">{_e(cr["subject"])}</td>'
            f'<td style="color:{exp_color};white-space:nowrap">{exp_display}</td>'
            f'<td class="mono" style="white-space:nowrap">{_e(key_label)}</td>'
            f'<td class="mono" style="font-size:0.78rem">{_e(cr["sig"])}</td>'
            f'<td style="font-size:0.78rem;max-width:180px;overflow:hidden;text-overflow:ellipsis" title="{_e(cr["san"])}">{_e(cr["san"]) or "&mdash;"}</td>'
            f'</tr>'
        )

    parts.append('</tbody></table></div></div></div>')

    # ── Tab: Timeline ──
    if "timeline" in tabs:
        parts.append('<div class="tab-content" id="tab-timeline" role="tabpanel">')
        parts.append('<div class="section"><h2>Certificate Timeline</h2>')
        parts.append(f'<p style="color:var(--text-secondary);margin-bottom:16px">Validity periods for all certificates. Vertical line marks today.</p>')

        # Build timeline entries
        tl_entries: list[dict] = []
        now = datetime.now(timezone.utc)
        for h in hosts:
            if not h.scan.chain:
                continue
            host_label = f"{h.scan.host}:{h.scan.port}"
            for i, c in enumerate(h.scan.chain):
                role = "Leaf" if i == 0 else ("Root" if getattr(c, 'is_self_signed', False) and getattr(c, 'is_ca', False) else f"Int #{i}")
                try:
                    nb = datetime.fromisoformat(c.not_before)
                    na = datetime.fromisoformat(c.not_after)
                    # Normalize to UTC-aware if naive
                    if nb.tzinfo is None:
                        nb = nb.replace(tzinfo=timezone.utc)
                    if na.tzinfo is None:
                        na = na.replace(tzinfo=timezone.utc)
                    days_left = (na - now).days
                except (ValueError, TypeError):
                    continue
                if days_left < 0:
                    color = _RED
                elif days_left < 30:
                    color = _YELLOW
                else:
                    color = _GREEN
                tl_entries.append({
                    "host": host_label, "role": role,
                    "subject": c.subject or "",
                    "nb": nb, "na": na, "color": color,
                    "days_left": days_left,
                })

        if tl_entries:
            # Calculate range
            all_dates = [e["nb"] for e in tl_entries] + [e["na"] for e in tl_entries]
            range_start = min(all_dates)
            range_end = max(all_dates)
            total_span = (range_end - range_start).total_seconds() or 1
            # Pad range by 5%, minimum 30 days
            pad_secs = max(total_span * 0.05, 86400 * 30)
            padding = timedelta(seconds=pad_secs)
            range_start = range_start - padding
            range_end = range_end + padding
            total_span = (range_end - range_start).total_seconds()

            # Today marker position
            today_pct = max(0, min(100, (now - range_start).total_seconds() / total_span * 100))

            # Sort by expiry (soonest first)
            tl_entries.sort(key=lambda e: e["na"])

            # Axis labels
            parts.append('<div class="tl-axis">')
            parts.append(f'<span>{range_start.strftime("%Y-%m")}</span>')
            parts.append(f'<span style="color:var(--link);font-weight:600">Today</span>')
            parts.append(f'<span>{range_end.strftime("%Y-%m")}</span>')
            parts.append('</div>')

            for e in tl_entries:
                left_pct = max(0, min(100, (e["nb"] - range_start).total_seconds() / total_span * 100))
                width_pct = max(0.5, min(100 - left_pct, (e["na"] - e["nb"]).total_seconds() / total_span * 100))
                label = f"{e['host']} / {e['role']}"
                short_subj = (e["subject"][:30] + "...") if len(e["subject"]) > 30 else e["subject"]
                days_txt = f"{e['days_left']}d" if e["days_left"] >= 0 else f"expired {-e['days_left']}d ago"
                parts.append(
                    f'<div class="tl-row">'
                    f'<div class="tl-label mono" title="{_e(e["subject"])}">{_e(label)}<br>'
                    f'<span style="color:var(--text-secondary);font-size:0.75rem">{_e(short_subj)} ({days_txt})</span></div>'
                    f'<div class="tl-track">'
                    f'<div class="tl-bar" style="left:{left_pct:.2f}%;width:{width_pct:.2f}%;background:{e["color"]}"></div>'
                    f'<div class="tl-today" style="left:{today_pct:.2f}%"></div>'
                    f'</div></div>'
                )
        else:
            parts.append(f'<p style="color:var(--text-secondary)">No certificate data available.</p>')

        parts.append('</div></div>')

    # ── Tab: PQC Posture ──
    if "pqc" in tabs:
        parts.append('<div class="tab-content" id="tab-pqc" role="tabpanel">')
        parts.append('<div class="section"><h2>PQC Readiness Posture</h2>')

        for h in hosts:
            if h.pqc is None:
                continue
            host_label = f"{h.scan.host}:{h.scan.port}"
            grade_color = _GRADE_COLORS.get(h.pqc.grade, _MUTED)
            safety_color = _QUANTUM_COLORS.get(h.pqc.overall_safety, _MUTED)
            safety_label = _QUANTUM_LABELS.get(h.pqc.overall_safety, "Unknown")

            parts.append(f'<div class="pqc-panel">')
            if is_fleet:
                parts.append(f'<h3 style="color:{_BLUE};margin-bottom:12px" class="mono">{_e(host_label)}</h3>')

            parts.append(f'<div class="pqc-score-row">')
            parts.append(
                f'<div class="pqc-score-circle" style="border-color:{grade_color};color:{grade_color}">'
                f'<span class="score">{h.pqc.score}/{h.pqc.max_score}</span></div>'
            )
            parts.append(f'<span class="pqc-grade" style="color:{grade_color}">Grade {h.pqc.grade}</span>')
            parts.append(f'<span class="pqc-info">Overall: <strong style="color:{safety_color}">{safety_label}</strong></span>')
            parts.append('</div>')

            # Component breakdown
            parts.append('<div class="table-wrap"><table>')
            parts.append('<thead><tr><th>Component</th><th>Algorithm</th><th>Quantum Safety</th><th style="text-align:center">Points</th></tr></thead>')
            parts.append('<tbody>')
            for pf in h.pqc.findings:
                pts = f"{pf.points_earned}/{pf.points_possible}" if pf.points_possible > 0 else "&mdash;"
                qc = _QUANTUM_COLORS.get(pf.quantum_safety, _MUTED)
                ql = _QUANTUM_LABELS.get(pf.quantum_safety, "Unknown")
                parts.append(
                    f'<tr><td>{_e(pf.component)}</td>'
                    f'<td class="mono">{_e(pf.algorithm)}</td>'
                    f'<td>{_pill(ql, qc)}</td>'
                    f'<td style="text-align:center" class="mono">{pts}</td></tr>'
                )
            parts.append('</tbody></table></div>')

            # CNSA 2.0
            if h.pqc.cnsa2_next_deadline:
                cnsa_color = _GREEN if h.pqc.cnsa2_compliant else _RED
                cnsa_label = "COMPLIANT" if h.pqc.cnsa2_compliant else "NOT COMPLIANT"
                parts.append(
                    f'<p style="margin-top:12px">CNSA 2.0: '
                    f'<strong style="color:{cnsa_color}">{cnsa_label}</strong> '
                    f'<span style="color:{_MUTED}">&mdash; Next deadline ({h.pqc.cnsa2_days_remaining} days): '
                    f'{_e(h.pqc.cnsa2_next_deadline)}</span></p>'
                )

            # Recommendations
            if h.pqc.recommendations:
                parts.append('<ul class="rec-list">')
                for rec in h.pqc.recommendations:
                    parts.append(f'<li>{_e(rec)}</li>')
                parts.append('</ul>')

            parts.append('</div>')  # close pqc-panel

        parts.append('</div></div>')

    # ── Tab: Revocation ──
    if "revocation" in tabs:
        parts.append('<div class="tab-content" id="tab-revocation" role="tabpanel">')
        parts.append('<div class="section"><h2>Revocation Status</h2>')
        parts.append('<div class="table-wrap"><table>')
        parts.append('<thead><tr>')
        if is_fleet:
            parts.append('<th>Host</th>')
        parts.append('<th>Method</th><th>Status</th><th>Details</th><th>URL</th></tr></thead>')
        parts.append('<tbody>')

        for h in hosts:
            if h.revocation is None:
                continue
            host_label = f"{h.scan.host}:{h.scan.port}"
            host_cell = f'<td class="mono" style="white-space:nowrap" rowspan="3">{_e(host_label)}</td>' if is_fleet else ""
            host_cell_empty = ""  # rowspan covers subsequent rows

            # Revoked warning
            if h.revocation.is_revoked:
                revoked_note = f' <strong style="color:{_RED}">REVOKED</strong>'
            else:
                revoked_note = ""

            # OCSP
            ocsp_color = _REVOCATION_COLORS.get(h.revocation.ocsp.status, _MUTED)
            parts.append(
                f'<tr>{host_cell}'
                f'<td>OCSP{revoked_note}</td>'
                f'<td>{_pill(h.revocation.ocsp.status.value.upper(), ocsp_color)}</td>'
                f'<td>{_e(h.revocation.ocsp.message)}</td>'
                f'<td class="mono" style="font-size:0.78rem;color:{_MUTED}">{_e(h.revocation.ocsp.responder_url) or "&mdash;"}</td></tr>'
            )

            # CRL
            crl_color = _REVOCATION_COLORS.get(h.revocation.crl.status, _MUTED)
            parts.append(
                f'<tr>{host_cell_empty}'
                f'<td>CRL</td>'
                f'<td>{_pill(h.revocation.crl.status.value.upper(), crl_color)}</td>'
                f'<td>{_e(h.revocation.crl.message)}</td>'
                f'<td class="mono" style="font-size:0.78rem;color:{_MUTED}">{_e(h.revocation.crl.crl_url) or "&mdash;"}</td></tr>'
            )

            # CT
            ct = h.revocation.ct
            if ct.logged:
                ct_label, ct_color = "LOGGED", _GREEN
            elif ct.logged is False:
                ct_label, ct_color = "NOT FOUND", _YELLOW
            else:
                ct_label, ct_color = "N/A", _MUTED
            ct_url = _e(ct.crt_sh_url) if ct.crt_sh_url else "&mdash;"
            parts.append(
                f'<tr>{host_cell_empty}'
                f'<td>CT</td>'
                f'<td>{_pill(ct_label, ct_color)}</td>'
                f'<td>{_e(ct.message)}</td>'
                f'<td class="mono" style="font-size:0.78rem;color:{_MUTED}">{ct_url}</td></tr>'
            )

        parts.append('</tbody></table></div></div></div>')

    # ── Tab: CBOM ──
    if "cbom" in tabs:
        import json as _json
        parts.append('<div class="tab-content" id="tab-cbom" role="tabpanel">')
        parts.append('<div class="section"><h2>Cryptographic Bill of Materials</h2>')
        parts.append('<p style="color:var(--text-secondary);margin-bottom:16px">CycloneDX 1.6 cryptographic asset inventory across all scanned hosts.</p>')

        # Build CBOM data
        cbom_rows: list[dict] = []
        all_cbom_components: list[dict] = []
        for h in hosts:
            if not h.scan.chain:
                continue
            cbom_data = generate_cbom(h.scan)
            host_label = f"{h.scan.host}:{h.scan.port}"
            for comp in cbom_data.get("components", []):
                all_cbom_components.append(comp)
                cp = comp.get("cryptoProperties", {})
                algo_props = cp.get("algorithmProperties", {})
                proto_props = cp.get("protocolProperties", {})
                cbom_rows.append({
                    "host": host_label,
                    "name": comp.get("name", ""),
                    "type": cp.get("assetType", ""),
                    "algorithm": algo_props.get("signatureAlgorithm", "")
                                or proto_props.get("cipherSuite", "")
                                or algo_props.get("algorithm", ""),
                    "key_type": algo_props.get("algorithm", proto_props.get("keyExchange", "")),
                    "key_size": algo_props.get("keySize", ""),
                    "quantum": cp.get("quantumReadiness", ""),
                })

        # CBOM summary table
        parts.append(f'<div class="filter-bar"><input type="text" id="cbom-filter" placeholder="Filter assets..." class="filter-input" aria-label="Filter CBOM assets"><button class="export-btn" onclick="exportCSV(\'cbom-table\',\'notafter-cbom\')">Export CSV</button></div>')
        parts.append('<div class="table-wrap"><table id="cbom-table">')
        parts.append('<thead><tr>')
        if is_fleet:
            parts.append('<th class="sortable" data-col="0">Host</th>')
        cbom_offset = 1 if is_fleet else 0
        parts.append(f'<th>Asset</th><th>Type</th><th class="sortable" data-col="{cbom_offset + 2}">Algorithm</th><th>Key</th><th>Size</th><th>Quantum Readiness</th>')
        parts.append('</tr></thead><tbody>')

        for cr in cbom_rows:
            host_cell = f'<td class="mono" style="white-space:nowrap">{_e(cr["host"])}</td>' if is_fleet else ""
            qr = cr["quantum"]
            if qr == "quantum_safe":
                qr_pill = _pill("Quantum-Safe", _GREEN)
            elif qr == "hybrid":
                qr_pill = _pill("Hybrid", _YELLOW)
            elif qr == "quantum_vulnerable":
                qr_pill = _pill("Vulnerable", _RED)
            else:
                qr_pill = _pill(str(qr) if qr else "Unknown", _MUTED)
            asset_type = _pill(cr["type"].upper() if cr["type"] else "?", _BLUE)
            parts.append(
                f'<tr>'
                f'{host_cell}'
                f'<td class="mono" style="font-size:0.82rem">{_e(cr["name"])}</td>'
                f'<td>{asset_type}</td>'
                f'<td class="mono" style="font-size:0.82rem">{_e(cr["algorithm"])}</td>'
                f'<td class="mono">{_e(cr["key_type"])}</td>'
                f'<td style="text-align:center">{_e(cr["key_size"]) or "&mdash;"}</td>'
                f'<td>{qr_pill}</td>'
                f'</tr>'
            )

        parts.append('</tbody></table></div>')

        # Raw JSON view
        fleet_cbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": all_cbom_components,
        }
        cbom_json_str = _e(_json.dumps(fleet_cbom, indent=2, default=str))
        parts.append(
            f'<details style="margin-top:16px">'
            f'<summary style="cursor:pointer;color:{_BLUE};font-size:0.88rem">View raw CycloneDX JSON</summary>'
            f'<pre style="background:var(--bg-secondary);border:1px solid var(--border);border-radius:6px;padding:16px;'
            f'margin-top:8px;overflow-x:auto;font-size:0.78rem;max-height:400px;overflow-y:auto">'
            f'<code>{cbom_json_str}</code></pre></details>'
        )

        parts.append('</div></div>')

    # ── Tab: Host Details ──
    parts.append('<div class="tab-content" id="tab-hosts" role="tabpanel">')
    parts.append('<div class="section"><h2>Host Details</h2>')
    parts.append('<div class="filter-bar"><input type="text" id="hosts-filter" placeholder="Filter hosts..." class="filter-input" aria-label="Filter host details"></div>')

    for h in hosts:
        host_label = f"{h.scan.host}:{h.scan.port}"

        if h.scan.error:
            parts.append(
                f'<details class="host-detail-block" data-host="{_e(host_label)}">'
                f'<summary class="host-summary host-error">'
                f'<span class="mono">{_e(host_label)}</span> {_pill("ERROR", _RED)}'
                f'</summary>'
                f'<div class="host-details"><p style="color:{_RED}">{_e(h.scan.error)}</p></div>'
                f'</details>'
            )
            continue

        crit = h.audit.critical_count
        warns = h.audit.warning_count
        if crit > 0:
            status_pill = _pill("CRITICAL", _RED)
        elif warns > 0:
            status_pill = _pill("WARNING", _YELLOW)
        else:
            status_pill = _pill("CLEAN", _GREEN)

        pqc_badge = ""
        if h.pqc:
            gc = _GRADE_COLORS.get(h.pqc.grade, _MUTED)
            pqc_badge = f' <span class="mono" style="color:{gc};margin-left:8px">PQC: {h.pqc.score}/10 {h.pqc.grade}</span>'

        parts.append(
            f'<details class="host-detail-block" data-host="{_e(host_label)}">'
            f'<summary class="host-summary">'
            f'<span class="mono">{_e(host_label)}</span> '
            f'{status_pill}{pqc_badge}'
            f' <span style="color:{_MUTED};font-size:0.82rem;margin-left:8px">'
            f'{_e(h.scan.tls_version or "")}'
            f' &middot; {_e(h.scan.cipher_suite or "")}</span>'
            f'</summary>'
            f'<div class="host-details">'
        )

        # Audit findings sub-table
        parts.append('<h4 style="margin-bottom:8px">Audit Findings</h4>')
        parts.append('<table style="font-size:0.82rem"><thead><tr><th style="width:30px"></th><th>Check</th><th>Component</th><th>Finding</th><th>Remediation</th></tr></thead><tbody>')
        for f in h.audit.findings:
            rc = _severity_row_class(f.severity)
            parts.append(
                f'<tr class="{rc}">'
                f'<td class="icon-cell">{_severity_icon(f.severity)}</td>'
                f'<td class="mono">{_e(f.check)}</td>'
                f'<td>{_e(f.component)}</td>'
                f'<td>{_e(f.message)}</td>'
                f'<td style="color:{_MUTED}">{_e(f.remediation) if f.remediation else "&mdash;"}</td></tr>'
            )
        parts.append('</tbody></table>')

        # Certificate chain
        if h.scan.chain:
            parts.append('<h4 style="margin:16px 0 8px">Certificate Chain</h4>')
            for i, cert in enumerate(h.scan.chain):
                if i == 0:
                    clabel = "Leaf"
                elif cert.is_self_signed and cert.is_ca:
                    clabel = "Root"
                else:
                    clabel = f"Int #{i}"
                parts.append(f'<h5 style="color:{_BLUE};font-size:0.88rem;margin:12px 0 4px">{clabel}</h5>')
                parts.append('<dl class="cert-grid">')
                parts.append(f'<dt>Subject</dt><dd class="mono">{_e(cert.subject)}</dd>')
                parts.append(f'<dt>Issuer</dt><dd class="mono">{_e(cert.issuer)}</dd>')
                parts.append(f'<dt>Not Before</dt><dd>{_e(cert.not_before)}</dd>')
                parts.append(f'<dt>Not After</dt><dd>{_e(cert.not_after)}</dd>')
                key_label = f"{cert.key_type}" + (f" ({cert.key_size} bits)" if cert.key_size else "")
                parts.append(f'<dt>Key</dt><dd>{_e(key_label)}</dd>')
                parts.append(f'<dt>Signature</dt><dd class="mono">{_e(cert.sig_algorithm_name)}</dd>')
                parts.append(f'<dt>Serial</dt><dd class="mono">{_e(cert.serial)}</dd>')
                if cert.san_names:
                    san_str = ", ".join(cert.san_names[:10])
                    if len(cert.san_names) > 10:
                        san_str += f" (+{len(cert.san_names) - 10} more)"
                    parts.append(f'<dt>SAN</dt><dd>{_e(san_str)}</dd>')
                parts.append('</dl>')

        # TLS connection info
        if h.scan.tls_version or h.scan.cipher_suite:
            parts.append('<h4 style="margin:16px 0 8px">TLS Connection</h4>')
            parts.append('<dl class="cert-grid">')
            if h.scan.tls_version:
                parts.append(f'<dt>Protocol</dt><dd>{_e(h.scan.tls_version)}</dd>')
            if h.scan.cipher_suite:
                parts.append(f'<dt>Cipher Suite</dt><dd class="mono">{_e(h.scan.cipher_suite)}</dd>')
            if h.scan.key_exchange:
                parts.append(f'<dt>Key Exchange</dt><dd>{_e(h.scan.key_exchange)}</dd>')
            if h.scan.peer_address:
                parts.append(f'<dt>Peer Address</dt><dd class="mono">{_e(h.scan.peer_address)}</dd>')
            parts.append('</dl>')

        parts.append('</div></details>')

    parts.append('</div></div>')

    # ── Footer ──
    parts.append(f"""
<div class="report-footer">
  Generated by <strong>notafter v{_e(__version__)}</strong> &mdash; {ts}
</div>
""")

    parts.append('</div>')  # close container

    return _page_wrapper(title, "\n".join(parts).lstrip("\n"))


# ── Page wrapper with CSS + JS ──

_CSS = """\
/* Theme variables */
:root {
  --bg-primary: #0d1117; --bg-secondary: #161b22; --bg-tertiary: #21262d;
  --border: #30363d; --text-primary: #e6edf3; --text-secondary: #8b949e;
  --text-muted: #484f58; --link: #58a6ff;
}
.light-theme {
  --bg-primary: #ffffff; --bg-secondary: #f6f8fa; --bg-tertiary: #e1e4e8;
  --border: #d0d7de; --text-primary: #1f2328; --text-secondary: #656d76;
  --text-muted: #8b949e; --link: #0969da;
}

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html { scroll-behavior: smooth; }
body {
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  background: var(--bg-primary); color: var(--text-primary); line-height: 1.6;
  -webkit-font-smoothing: antialiased; padding: 0; margin: 0;
}
.container { max-width: 1100px; margin: 0 auto; padding: 0 24px; }
h1, h2, h3, h4, h5 { letter-spacing: -0.02em; }
code, .mono { font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace; }

/* Header */
.report-header {
  background: var(--bg-secondary); border-bottom: 1px solid var(--border);
  padding: 32px 0; margin-bottom: 32px; position: relative;
}
.report-header h1 { font-size: 1.75rem; font-weight: 800; margin-bottom: 4px; }
.report-header .meta { color: var(--text-secondary); font-size: 0.85rem; }
.report-header .meta span { margin-right: 18px; }
.theme-toggle {
  position: absolute; top: 16px; right: 24px; border: none; background: transparent;
  color: var(--text-secondary); font-size: 1.3rem; cursor: pointer; padding: 4px 8px;
  border-radius: 6px; transition: color 0.2s;
}
.theme-toggle:hover { color: var(--text-primary); }

/* Section */
.section { margin-bottom: 32px; }
.section h2 {
  font-size: 1.2rem; font-weight: 700; margin-bottom: 16px;
  padding-bottom: 8px; border-bottom: 1px solid var(--border);
}

/* Stat cards */
.stat-cards {
  display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 24px;
}
.stat-card {
  flex: 1; min-width: 120px; background: var(--bg-secondary);
  border: 1px solid var(--border); border-radius: 10px;
  padding: 20px; text-align: center;
}
.stat-card .stat-value {
  font-size: 2rem; font-weight: 800;
  font-family: 'JetBrains Mono', monospace; line-height: 1;
}
.stat-card .stat-label {
  font-size: 0.82rem; color: var(--text-secondary); margin-top: 4px; font-weight: 500;
}

/* Tab navigation */
.tab-nav {
  display: flex; gap: 4px; border-bottom: 2px solid var(--border);
  margin-bottom: 24px; flex-wrap: wrap;
}
.tab-btn {
  padding: 10px 20px; border: none; background: transparent;
  color: var(--text-secondary); cursor: pointer; font-size: 0.88rem; font-weight: 600;
  border-bottom: 2px solid transparent; margin-bottom: -2px;
  font-family: inherit; transition: color 0.2s;
}
.tab-btn:hover { color: var(--text-primary); }
.tab-btn.active { color: var(--link); border-bottom-color: var(--link); }

/* Tab content */
.tab-content { display: none; }
.tab-content.active { display: block; }

/* Filter bar */
.filter-bar { margin-bottom: 12px; }
.filter-input {
  width: 100%; max-width: 400px; padding: 8px 14px;
  background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 6px;
  color: var(--text-primary); font-size: 0.88rem; font-family: inherit;
  outline: none; transition: border-color 0.2s;
}
.filter-input:focus { border-color: var(--link); }
.filter-input::placeholder { color: var(--text-muted); }

/* Tables */
table {
  width: 100%; border-collapse: collapse; font-size: 0.88rem;
  margin-bottom: 8px;
}
th, td {
  text-align: left; padding: 10px 14px;
  border-bottom: 1px solid var(--bg-tertiary);
}
th {
  color: var(--text-secondary); font-weight: 600; font-size: 0.78rem;
  text-transform: uppercase; letter-spacing: 0.04em;
  background: var(--bg-secondary); position: sticky; top: 0;
}
th.sortable { cursor: pointer; user-select: none; }
th.sortable:hover { color: var(--text-primary); }
th.sortable::after { content: ' \\25B2\\25BC'; font-size: 0.55rem; }
.table-wrap { overflow-x: auto; -webkit-overflow-scrolling: touch; }

/* Row severity backgrounds */
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

/* Host link */
.host-link { cursor: pointer; text-decoration: underline; text-decoration-style: dotted; text-underline-offset: 3px; }
.host-link:hover { color: var(--link); }
.host-expand-icon { color: var(--text-secondary); font-size: 0.7rem; display: inline-block; margin-right: 6px; transition: transform 0.2s; }
.host-expand-icon.open { transform: rotate(90deg); }

/* Inline findings (overview expand) */
.overview-expand > td { padding: 4px 16px 12px 16px; background: var(--bg-secondary); border-bottom: 1px solid var(--border); }
.inline-findings { font-size: 0.85rem; padding: 4px 0; }
.inline-findings .finding-row { padding: 3px 0; display: flex; gap: 8px; align-items: baseline; }
.inline-findings .finding-row .msg { color: var(--text-primary); }
.inline-findings .finding-row .action { color: var(--text-secondary); }
.detail-link { color: var(--link); font-size: 0.82rem; cursor: pointer; text-decoration: none; margin-top: 6px; display: inline-block; }
.detail-link:hover { text-decoration: underline; }

/* PQC panel */
.pqc-panel {
  background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 10px;
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
.pqc-info { color: var(--text-secondary); font-size: 0.88rem; }
.pqc-grade {
  font-size: 2rem; font-weight: 800;
  font-family: 'JetBrains Mono', monospace;
}
.rec-list { list-style: none; padding: 0; margin-top: 12px; }
.rec-list li {
  padding: 6px 0; color: var(--text-primary); font-size: 0.88rem;
  border-bottom: 1px solid var(--bg-tertiary);
}
.rec-list li::before { content: "> "; color: var(--text-secondary); font-family: 'JetBrains Mono', monospace; }

/* Cert details grid */
.cert-grid {
  display: grid; grid-template-columns: 140px 1fr;
  gap: 4px 16px; font-size: 0.88rem; margin-bottom: 16px;
}
.cert-grid dt { color: var(--text-secondary); font-weight: 600; }
.cert-grid dd { color: var(--text-primary); word-break: break-all; }

/* Host details (expand/collapse) */
.host-detail-block { margin-bottom: 2px; }
.host-summary {
  cursor: pointer; list-style: none; padding: 12px 16px;
  background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 6px;
  display: flex; align-items: center; gap: 12px; flex-wrap: wrap;
}
.host-summary::-webkit-details-marker { display: none; }
.host-summary::marker { display: none; }
.host-summary::before { content: '\\25B8'; color: var(--text-secondary); font-size: 0.8rem; transition: transform 0.2s; }
details[open] > .host-summary::before { transform: rotate(90deg); }
.host-summary.host-error { border-color: rgba(248,81,73,0.3); }
.host-details {
  padding: 16px 20px; background: var(--bg-primary);
  border: 1px solid var(--bg-tertiary); border-top: none; border-radius: 0 0 6px 6px;
}

/* Footer */
.report-footer {
  margin-top: 48px; padding: 24px 0; border-top: 1px solid var(--border);
  text-align: center; color: var(--text-secondary); font-size: 0.82rem;
}

/* Export button */
.export-btn {
  padding: 6px 14px; margin-left: 12px; background: var(--bg-tertiary);
  border: 1px solid var(--border); border-radius: 6px; color: var(--text-primary);
  font-size: 0.82rem; cursor: pointer; font-family: inherit;
  vertical-align: middle;
}
.export-btn:hover { background: var(--border); }

/* Timeline */
.tl-axis {
  display: flex; justify-content: space-between; font-size: 0.75rem;
  color: var(--text-secondary); margin-bottom: 8px; padding: 0 0 0 200px;
}
.tl-row { display: flex; gap: 12px; align-items: center; margin-bottom: 4px; min-height: 32px; }
.tl-label {
  width: 200px; min-width: 200px; font-size: 0.78rem; overflow: hidden;
  text-overflow: ellipsis; white-space: nowrap;
}
.tl-track {
  flex: 1; position: relative; background: var(--bg-tertiary);
  border-radius: 4px; height: 18px;
}
.tl-bar {
  position: absolute; top: 2px; bottom: 2px; border-radius: 3px;
  min-width: 2px; opacity: 0.85;
}
.tl-today {
  position: absolute; width: 2px; background: var(--link);
  top: -4px; bottom: -4px; z-index: 1; opacity: 0.9;
}

/* Responsive */
@media (max-width: 768px) {
  .report-header h1 { font-size: 1.3rem; }
  .pqc-score-row { flex-direction: column; align-items: flex-start; }
  .cert-grid { grid-template-columns: 1fr; }
  .stat-cards { flex-direction: column; }
  th, td { padding: 8px 10px; font-size: 0.82rem; }
  .tab-btn { padding: 8px 12px; font-size: 0.82rem; }
  .tl-label { width: 120px; min-width: 120px; }
  .tl-axis { padding-left: 132px; }
}

/* Print */
@media print {
  body { --bg-primary: #fff; --bg-secondary: #f6f8fa; --bg-tertiary: #e1e4e8;
    --border: #d0d7de; --text-primary: #1a1a1a; --text-secondary: #555; --text-muted: #888;
    -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  .tab-nav { display: none; }
  .theme-toggle { display: none; }
  .tab-content { display: block !important; page-break-inside: avoid; margin-bottom: 24px; }
  .filter-bar { display: none; }
  .export-btn { display: none; }
  .row-critical { background: rgba(248,81,73,0.15) !important; }
  .row-warning { background: rgba(210,153,34,0.15) !important; }
  .row-pass { background: rgba(63,185,80,0.10) !important; }
  details { break-inside: avoid; }
  details[open] > .host-details { display: block; }
  .overview-expand { display: table-row !important; }
  .host-expand-icon { display: none; }
  .detail-link { display: none; }
  a { color: #0366d6; }
}
"""

_JS = """\
(function(){
  /* Tab switching */
  document.querySelectorAll('.tab-btn').forEach(function(btn){
    btn.addEventListener('click', function(){
      document.querySelectorAll('.tab-btn').forEach(function(b){ b.classList.remove('active'); b.setAttribute('aria-selected','false'); });
      document.querySelectorAll('.tab-content').forEach(function(c){ c.classList.remove('active'); });
      btn.classList.add('active');
      btn.setAttribute('aria-selected','true');
      var target = document.getElementById('tab-' + btn.dataset.tab);
      if(target) target.classList.add('active');
    });
  });

  /* Host link click - toggle inline expand */
  document.querySelectorAll('.host-link').forEach(function(link){
    link.addEventListener('click', function(e){
      e.preventDefault();
      var hostId = link.dataset.target;
      var expandRow = document.querySelector('.overview-expand[data-expand="' + hostId + '"]');
      if(!expandRow) return;
      var isOpen = expandRow.style.display !== 'none';
      /* Close all expand rows */
      document.querySelectorAll('.overview-expand').forEach(function(r){ r.style.display = 'none'; });
      document.querySelectorAll('.host-expand-icon').forEach(function(ic){ ic.classList.remove('open'); });
      if(!isOpen){
        expandRow.style.display = '';
        var icon = link.querySelector('.host-expand-icon');
        if(icon) icon.classList.add('open');
      }
    });
  });

  /* Detail link - switch to hosts tab and open detail */
  document.querySelectorAll('.detail-link').forEach(function(link){
    link.addEventListener('click', function(e){
      e.stopPropagation();
      var hostId = link.dataset.target;
      document.querySelectorAll('.tab-btn').forEach(function(b){ b.classList.remove('active'); b.setAttribute('aria-selected','false'); });
      document.querySelectorAll('.tab-content').forEach(function(c){ c.classList.remove('active'); });
      var hostsBtn = document.querySelector('.tab-btn[data-tab="hosts"]');
      var hostsTab = document.getElementById('tab-hosts');
      if(hostsBtn){ hostsBtn.classList.add('active'); hostsBtn.setAttribute('aria-selected','true'); }
      if(hostsTab) hostsTab.classList.add('active');
      document.querySelectorAll('.host-detail-block').forEach(function(d){
        if(d.dataset.host === hostId){ d.open = true; d.scrollIntoView({behavior:'smooth', block:'start'}); }
      });
    });
  });

  /* Table filtering */
  function setupFilter(inputId, tableId){
    var input = document.getElementById(inputId);
    var table = document.getElementById(tableId);
    if(!input || !table) return;
    input.addEventListener('input', function(){
      var q = input.value.toLowerCase();
      table.querySelectorAll('tbody tr').forEach(function(row){
        if(row.classList.contains('overview-expand')){ row.style.display = 'none'; return; }
        row.style.display = row.textContent.toLowerCase().indexOf(q) >= 0 ? '' : 'none';
      });
      /* Collapse all expand icons */
      document.querySelectorAll('.host-expand-icon').forEach(function(ic){ ic.classList.remove('open'); });
    });
  }
  setupFilter('overview-filter', 'overview-table');
  setupFilter('inventory-filter', 'inventory-table');
  setupFilter('cbom-filter', 'cbom-table');
  /* Host details filter */
  var hostsInput = document.getElementById('hosts-filter');
  if(hostsInput){
    hostsInput.addEventListener('input', function(){
      var q = hostsInput.value.toLowerCase();
      document.querySelectorAll('.host-detail-block').forEach(function(d){
        d.style.display = d.textContent.toLowerCase().indexOf(q) >= 0 ? '' : 'none';
      });
    });
  }

  /* Table sorting */
  document.querySelectorAll('th.sortable').forEach(function(th){
    th.addEventListener('click', function(){
      var table = th.closest('table');
      var tbody = table.querySelector('tbody');
      var rows = Array.from(tbody.querySelectorAll('tr:not(.overview-expand)'));
      var col = parseInt(th.dataset.col);
      var asc = th.dataset.sort !== 'asc';
      th.dataset.sort = asc ? 'asc' : 'desc';
      rows.sort(function(a,b){
        var aText = (a.cells[col] || {textContent:''}).textContent.trim();
        var bText = (b.cells[col] || {textContent:''}).textContent.trim();
        var aNum = parseFloat(aText);
        var bNum = parseFloat(bText);
        if(!isNaN(aNum) && !isNaN(bNum)) return asc ? aNum - bNum : bNum - aNum;
        return asc ? aText.localeCompare(bText) : bText.localeCompare(aText);
      });
      rows.forEach(function(r){
        tbody.appendChild(r);
        var hostCell = r.querySelector('.host-link');
        if(hostCell){
          var ex = tbody.querySelector('.overview-expand[data-expand="' + hostCell.dataset.target + '"]');
          if(ex) tbody.appendChild(ex);
        }
      });
    });
  });
})();

/* Print: expand all details, restore after */
window.addEventListener('beforeprint', function(){
  document.querySelectorAll('details').forEach(function(d){
    d._wasOpen = d.open; d.open = true;
  });
});
window.addEventListener('afterprint', function(){
  document.querySelectorAll('details').forEach(function(d){
    if(d._wasOpen !== undefined) d.open = d._wasOpen;
  });
});

/* CSV export - called from onclick */
function exportCSV(tableId, prefix) {
  var table = document.getElementById(tableId);
  if (!table) return;
  var csv = [];
  var headers = [];
  table.querySelectorAll('thead th').forEach(function(th) {
    headers.push('"' + th.textContent.trim().replace(/"/g, '""') + '"');
  });
  csv.push(headers.join(','));
  table.querySelectorAll('tbody tr').forEach(function(row) {
    if (row.style.display === 'none') return;
    var cells = [];
    row.querySelectorAll('td').forEach(function(td) {
      cells.push('"' + td.textContent.trim().replace(/"/g, '""') + '"');
    });
    csv.push(cells.join(','));
  });
  var blob = new Blob([csv.join('\\n')], {type: 'text/csv;charset=utf-8'});
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url;
  var d = new Date().toISOString().slice(0, 10);
  a.download = prefix + '-' + d + '.csv';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/* Theme toggle */
function toggleTheme() {
  var el = document.documentElement;
  el.classList.toggle('light-theme');
  var isLight = el.classList.contains('light-theme');
  try { localStorage.setItem('notafter-theme', isLight ? 'light' : 'dark'); } catch(e) {}
  var btn = document.querySelector('.theme-toggle');
  if (btn) btn.textContent = isLight ? '\\u263C' : '\\u263E';
}
/* Sync toggle icon if theme was set in <head> */
(function(){
  var btn = document.querySelector('.theme-toggle');
  if (btn && document.documentElement.classList.contains('light-theme')) btn.textContent = '\\u263C';
})();
"""


def _page_wrapper(title: str, body: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'none'; script-src 'unsafe-inline'">
<title>{_e(title)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;700;800&display=swap" rel="stylesheet">
<style>
{_CSS}
</style>
<script>try{{if(localStorage.getItem('notafter-theme')==='light')document.documentElement.classList.add('light-theme')}}catch(e){{}}</script>
</head>
<body>
{body}
<script>
{_JS}
</script>
</body>
</html>"""
