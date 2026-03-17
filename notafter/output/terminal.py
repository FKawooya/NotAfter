"""Rich terminal output for notafter reports."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from notafter.checks.engine import AuditReport, Finding, Severity
from notafter.pqc.scorer import PQCReport
from notafter.pqc.oids import QuantumSafety
from notafter.revocation.checker import RevocationReport, RevocationStatus

#: Shared Rich console instance — use this instead of creating new Console() objects.
console = Console()


SEVERITY_STYLES = {
    Severity.CRITICAL: ("bold red", "CRIT"),
    Severity.WARNING: ("yellow", "WARN"),
    Severity.INFO: ("blue", "INFO"),
    Severity.PASS: ("green", "PASS"),
}

QUANTUM_STYLES = {
    QuantumSafety.QUANTUM_SAFE: ("bold green", "QUANTUM-SAFE"),
    QuantumSafety.QUANTUM_VULNERABLE: ("bold red", "VULNERABLE"),
    QuantumSafety.HYBRID: ("bold yellow", "HYBRID"),
    QuantumSafety.UNKNOWN: ("dim", "UNKNOWN"),
}


def print_audit(report: AuditReport) -> None:
    """Print certificate audit findings."""
    table = Table(
        title=f"Certificate Audit: {report.target}",
        show_header=True,
        header_style="bold",
        border_style="dim",
        title_style="bold cyan",
    )
    table.add_column("", width=4, justify="center")
    table.add_column("Check", style="dim", width=14, no_wrap=True)
    table.add_column("Component", max_width=32, overflow="ellipsis", no_wrap=True)
    table.add_column("Finding", ratio=1)

    for f in report.findings:
        style, label = SEVERITY_STYLES.get(f.severity, ("dim", "?"))
        severity_text = Text(label, style=style)
        message = f.message
        if f.remediation:
            message += f"\n  [dim]> {f.remediation}[/dim]"
        table.add_row(severity_text, f.check, f.component, message)

    console.print()
    console.print(table)

    # Summary line
    summary = Text()
    summary.append(f"\n  {report.critical_count} critical", style="bold red" if report.critical_count else "green")
    summary.append(f"  {report.warning_count} warnings", style="yellow" if report.warning_count else "green")
    summary.append(f"  {report.pass_count} passed", style="green")
    console.print(summary)


def print_pqc(report: PQCReport) -> None:
    """Print PQC readiness report."""
    # Score panel
    score_style = "bold green" if report.score >= 7 else "bold yellow" if report.score >= 4 else "bold red"
    grade_text = f"[{score_style}]{report.score}/10 (Grade: {report.grade})[/{score_style}]"

    safety_style, safety_label = QUANTUM_STYLES.get(
        report.overall_safety, ("dim", "UNKNOWN")
    )
    status_text = f"[{safety_style}]{safety_label}[/{safety_style}]"

    header = f"PQC Readiness Score: {grade_text}  Status: {status_text}"

    # Findings table
    table = Table(show_header=True, header_style="bold", border_style="dim")
    table.add_column("Component", max_width=20, overflow="ellipsis", no_wrap=True)
    table.add_column("Algorithm", max_width=28, overflow="ellipsis", no_wrap=True)
    table.add_column("Quantum Safety", width=16, justify="center")
    table.add_column("Points", width=8, justify="center")

    for f in report.findings:
        q_style, q_label = QUANTUM_STYLES.get(f.quantum_safety, ("dim", "?"))
        safety_cell = Text(q_label, style=q_style)
        points = f"{f.points_earned}/{f.points_possible}" if f.points_possible > 0 else "-"
        table.add_row(f.component, f.algorithm, safety_cell, points)

    panel_content = table

    console.print()
    console.print(Panel(
        panel_content,
        title=header,
        border_style="cyan",
        padding=(1, 2),
    ))

    # CNSA 2.0 status
    if report.cnsa2_next_deadline:
        cnsa_style = "green" if report.cnsa2_compliant else "bold red"
        compliant_text = "COMPLIANT" if report.cnsa2_compliant else "NOT COMPLIANT"
        console.print(f"\n  CNSA 2.0: [{cnsa_style}]{compliant_text}[/{cnsa_style}]")
        console.print(f"  [dim]Next deadline ({report.cnsa2_days_remaining} days): {report.cnsa2_next_deadline}[/dim]")

    # Recommendations
    if report.recommendations:
        console.print("\n  [bold]Recommendations:[/bold]")
        for rec in report.recommendations:
            console.print(f"  [dim]>[/dim] {rec}")


def print_revocation(report: RevocationReport) -> None:
    """Print revocation check results."""
    table = Table(
        title="Revocation Status",
        show_header=True,
        header_style="bold",
        border_style="dim",
        title_style="bold cyan",
    )
    table.add_column("Method", width=8)
    table.add_column("Status", width=12, justify="center")
    table.add_column("Details", ratio=1)

    # OCSP
    ocsp_style = _revocation_style(report.ocsp.status)
    table.add_row(
        "OCSP",
        Text(report.ocsp.status.value.upper(), style=ocsp_style),
        report.ocsp.message + (f"\n  [dim]{report.ocsp.responder_url}[/dim]" if report.ocsp.responder_url else ""),
    )

    # CRL
    crl_style = _revocation_style(report.crl.status)
    table.add_row(
        "CRL",
        Text(report.crl.status.value.upper(), style=crl_style),
        report.crl.message + (f"\n  [dim]{report.crl.crl_url}[/dim]" if report.crl.crl_url else ""),
    )

    # CT
    ct_status = "LOGGED" if report.ct.logged else "NOT FOUND" if report.ct.logged is False else "N/A"
    ct_style = "green" if report.ct.logged else "yellow" if report.ct.logged is False else "dim"
    table.add_row(
        "CT",
        Text(ct_status, style=ct_style),
        report.ct.message + (f"\n  [dim]{report.ct.crt_sh_url}[/dim]" if report.ct.crt_sh_url else ""),
    )

    console.print()
    console.print(table)

    if report.is_revoked:
        console.print("\n  [bold red]WARNING: Certificate has been REVOKED[/bold red]")


def _revocation_style(status: RevocationStatus) -> str:
    return {
        RevocationStatus.GOOD: "bold green",
        RevocationStatus.REVOKED: "bold red",
        RevocationStatus.UNKNOWN: "yellow",
        RevocationStatus.ERROR: "red",
        RevocationStatus.SKIPPED: "dim",
    }.get(status, "dim")


def print_diff(report) -> None:
    """Print a DiffReport as colored Rich output."""
    from rich.markup import escape as _esc

    from notafter.diff import DiffReport  # noqa: F811

    if not isinstance(report, DiffReport):
        return

    if not report.has_changes:
        console.print("\n  [green]No changes detected.[/green]\n")
        return

    # Summary
    added = sum(1 for h in report.host_diffs if h.status == "added")
    removed = sum(1 for h in report.host_diffs if h.status == "removed")
    changed = sum(1 for h in report.host_diffs if h.status == "changed")
    parts = []
    if added:
        parts.append(f"[green]{added} added[/green]")
    if removed:
        parts.append(f"[red]{removed} removed[/red]")
    if changed:
        parts.append(f"[yellow]{changed} changed[/yellow]")
    console.print(f"\n  [bold]{report.total_changes} change(s):[/bold] {', '.join(parts)}\n")

    table = Table(
        title="Diff Results",
        show_header=True,
        header_style="bold",
        border_style="dim",
        title_style="bold cyan",
    )
    table.add_column("Host", max_width=35, overflow="ellipsis", no_wrap=True)
    table.add_column("Status", width=10)
    table.add_column("Changes", ratio=1)

    for hd in report.host_diffs:
        if hd.status == "unchanged":
            continue

        host_safe = _esc(hd.host)

        if hd.status == "added":
            table.add_row(host_safe, Text("ADDED", style="bold green"), "New host in scan")
            continue
        if hd.status == "removed":
            table.add_row(host_safe, Text("REMOVED", style="bold red"), "Host no longer in scan")
            continue

        # Changed — build detail lines
        details: list[str] = []

        if hd.tls_old or hd.tls_new:
            details.append(f"TLS: {_esc(hd.tls_old or '?')} -> {_esc(hd.tls_new or '?')}")

        for cc in hd.cert_changes:
            short = _esc(cc.subject[:40] if len(cc.subject) > 40 else cc.subject)
            if cc.type == "renewed":
                old_exp = _esc(cc.details.get("old_expiry", "?"))
                new_exp = _esc(cc.details.get("new_expiry", "?"))
                details.append(f"[green]Renewed:[/green] {short} ({old_exp} -> {new_exp})")
            elif cc.type == "added":
                details.append(f"[green]+ Cert:[/green] {short}")
            elif cc.type == "removed":
                details.append(f"[red]- Cert:[/red] {short}")
            elif cc.type == "modified":
                details.append(f"[yellow]Modified:[/yellow] {short}")

        if hd.finding_changes:
            for f in hd.finding_changes.new_findings:
                msg = _esc(f.get("message") or f.get("detail", ""))
                details.append(f"[red]+ Finding:[/red] {msg[:60]}")
            for f in hd.finding_changes.resolved_findings:
                msg = _esc(f.get("message") or f.get("detail", ""))
                details.append(f"[green]- Resolved:[/green] {msg[:60]}")

        if hd.pqc_changes:
            pc = hd.pqc_changes
            arrow_style = "green" if pc.direction == "improved" else "red" if pc.direction == "degraded" else "dim"
            details.append(
                f"PQC: [{arrow_style}]{pc.old_score}/10 {_esc(pc.old_grade)} -> "
                f"{pc.new_score}/10 {_esc(pc.new_grade)}[/{arrow_style}]"
            )

        table.add_row(
            host_safe,
            Text("CHANGED", style="bold yellow"),
            "\n".join(details) if details else "Changes detected",
        )

    console.print(table)
