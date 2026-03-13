"""notafter CLI — PKI certificate auditor with PQC readiness scoring."""

from __future__ import annotations

import asyncio
import json
import sys
from contextlib import contextmanager

import click
from rich.progress import Progress, SpinnerColumn, TextColumn

from notafter import __version__
from notafter.output.terminal import console


@contextmanager
def _spinner(description: str):
    """Context manager for a transient progress spinner."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task(description, total=None)
        yield progress


def _build_chain_algos(chain, *, with_labels: bool = False):
    """Build the chain_algorithms list expected by score_chain.

    Args:
        chain: List of CertInfo objects from a ScanResult.
        with_labels: If True, generate human-readable labels for each cert.
    """
    return [
        {
            "sig_oid": c.sig_algorithm_oid,
            "key_type": c.key_type,
            "key_size": c.key_size,
            "label": (
                f"{'Leaf' if i == 0 else 'Root' if c.is_self_signed else f'Intermediate #{i}'} ({c.key_type})"
                if with_labels
                else ""
            ),
        }
        for i, c in enumerate(chain)
    ]


@click.group()
@click.version_option(__version__, prog_name="notafter")
def cli():
    """PKI certificate auditor with PQC readiness scoring.

    Audit TLS certificates against modern best practices, check revocation
    status, assess post-quantum cryptography readiness, and generate
    cryptographic bills of materials.
    """
    pass


@cli.command()
@click.argument("target")
@click.option("--file", "is_file", is_flag=True, help="Treat TARGET as a file path instead of a host.")
@click.option("--port", "-p", default=443, type=int, help="TLS port (default: 443).")
@click.option("--warn-days", "-w", default=30, type=int, help="Days before expiry to warn (default: 30).")
@click.option("--json-output", "--json", "json_out", is_flag=True, help="Output JSON instead of terminal.")
@click.option("--cbom", is_flag=True, help="Output CycloneDX CBOM (implies --json).")
@click.option("--no-revocation", is_flag=True, help="Skip revocation checks (OCSP/CRL/CT).")
@click.option("--no-pqc", is_flag=True, help="Skip PQC readiness assessment.")
@click.option("--timeout", "-t", default=10.0, type=float, help="Connection timeout in seconds.")
def scan(target, is_file, port, warn_days, json_out, cbom, no_revocation, no_pqc, timeout):
    """Audit a single host or certificate file.

    Examples:

        notafter scan example.com

        notafter scan example.com:8443

        notafter scan --file cert.pem

        notafter scan example.com --json

        notafter scan example.com --cbom > inventory.json
    """
    from notafter.scanner.tls import scan_host, scan_file
    from notafter.checks.engine import run_checks
    from notafter.pqc.scorer import score_chain
    from notafter.revocation.checker import check_revocation
    from notafter.cbom.generator import generate_cbom, cbom_to_json
    from notafter.output.terminal import print_audit, print_pqc, print_revocation

    # Scan
    if is_file:
        with _spinner("Scanning certificate file..."):
            result = scan_file(target)
    else:
        from notafter.scanner.fleet import parse_target
        host, scan_port = parse_target(target, port)
        with _spinner(f"Connecting to {host}:{scan_port}..."):
            result = scan_host(host, scan_port, timeout)

    if result.error and not result.chain:
        console.print(f"[bold red]Error:[/bold red] {result.error}")
        sys.exit(2)

    # CBOM output
    if cbom:
        cbom_data = generate_cbom(result)
        click.echo(cbom_to_json(cbom_data))
        sys.exit(0)

    # Run checks
    audit = run_checks(result, warn_days)

    # PQC assessment
    pqc_report = None
    if not no_pqc and result.chain:
        pqc_report = score_chain(
            _build_chain_algos(result.chain, with_labels=True),
            tls_version=result.tls_version,
            key_exchange=result.key_exchange,
        )

    # Revocation
    revocation_report = None
    if not no_revocation and result.chain and not is_file:
        with _spinner("Checking revocation status..."):
            issuer = result.chain[1] if len(result.chain) > 1 else None
            revocation_report = check_revocation(result.chain[0], issuer)

    # Output
    if json_out:
        output = _build_json(result, audit, pqc_report, revocation_report)
        click.echo(json.dumps(output, indent=2, default=str))
        sys.exit(audit.exit_code)

    # Terminal output
    print_audit(audit)

    if pqc_report:
        print_pqc(pqc_report)

    if revocation_report:
        print_revocation(revocation_report)

    console.print()
    sys.exit(audit.exit_code)


@cli.command()
@click.argument("source")
@click.option("--port", "-p", default=443, type=int, help="Default TLS port.")
@click.option("--concurrency", "-c", default=50, type=int, help="Max concurrent connections.")
@click.option("--timeout", "-t", default=10.0, type=float, help="Per-host timeout.")
@click.option("--warn-days", "-w", default=30, type=int, help="Days before expiry to warn.")
@click.option("--json-output", "--json", "json_out", is_flag=True, help="Output JSON.")
@click.option("--cbom", is_flag=True, help="Output fleet-wide CBOM.")
@click.option("--no-pqc", is_flag=True, help="Skip PQC assessment.")
def fleet(source, port, concurrency, timeout, warn_days, json_out, cbom, no_pqc):
    """Bulk scan hosts from a file or CIDR range.

    Examples:

        notafter fleet hosts.txt

        notafter fleet 10.0.0.0/24

        notafter fleet hosts.txt --json > report.json

        notafter fleet hosts.txt --cbom > fleet-inventory.json
    """
    from notafter.scanner.fleet import load_targets, scan_fleet
    from notafter.checks.engine import run_checks
    from notafter.pqc.scorer import score_chain
    from notafter.cbom.generator import generate_cbom, cbom_to_json

    # Load targets
    try:
        targets = load_targets(source)
    except ValueError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        sys.exit(2)

    console.print(f"[cyan]Scanning {len(targets)} hosts (concurrency: {concurrency})...[/cyan]")

    # Progress tracking
    completed = [0]

    def on_result(result, index, total):
        completed[0] += 1
        status = "[green]OK[/green]" if not result.error else f"[red]{result.error[:40]}[/red]"
        console.print(f"  [{completed[0]}/{total}] {result.host}:{result.port} {status}")

    # Run async fleet scan
    results = asyncio.run(scan_fleet(
        targets, port=port, concurrency=concurrency, timeout=timeout, on_result=on_result,
    ))

    # CBOM output
    if cbom:
        all_components = []
        for r in results:
            if r.chain:
                cbom_data = generate_cbom(r)
                all_components.extend(cbom_data.get("components", []))
        fleet_cbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": all_components,
        }
        click.echo(json.dumps(fleet_cbom, indent=2, default=str))
        sys.exit(0)

    # Process results
    fleet_data = []
    total_critical = 0
    total_warning = 0

    for r in results:
        audit = run_checks(r, warn_days)
        total_critical += audit.critical_count
        total_warning += audit.warning_count

        entry = {
            "host": r.host,
            "port": r.port,
            "error": r.error,
            "tls_version": r.tls_version,
            "critical": audit.critical_count,
            "warnings": audit.warning_count,
        }

        if not no_pqc and r.chain:
            pqc = score_chain(
                _build_chain_algos(r.chain),
                tls_version=r.tls_version,
                key_exchange=r.key_exchange,
            )
            entry["pqc_score"] = pqc.score
            entry["pqc_grade"] = pqc.grade

        fleet_data.append(entry)

    if json_out:
        click.echo(json.dumps(fleet_data, indent=2, default=str))
    else:
        _print_fleet_summary(fleet_data, total_critical, total_warning)

    exit_code = 2 if total_critical > 0 else 1 if total_warning > 0 else 0
    sys.exit(exit_code)


def _print_fleet_summary(fleet_data: list[dict], total_critical: int, total_warning: int) -> None:
    """Print fleet scan summary table."""
    from rich.table import Table

    table = Table(
        title="Fleet Scan Results",
        show_header=True,
        header_style="bold",
        border_style="dim",
        title_style="bold cyan",
    )
    table.add_column("Host", width=30)
    table.add_column("TLS", width=8)
    table.add_column("Crit", width=5, justify="center")
    table.add_column("Warn", width=5, justify="center")
    table.add_column("PQC", width=6, justify="center")
    table.add_column("Status", width=10)

    for entry in fleet_data:
        if entry.get("error"):
            table.add_row(
                f"{entry['host']}:{entry['port']}",
                "-", "-", "-", "-",
                f"[red]ERROR[/red]",
            )
            continue

        crit_style = "red" if entry["critical"] > 0 else "green"
        warn_style = "yellow" if entry["warnings"] > 0 else "green"
        pqc_score = entry.get("pqc_score", "-")
        pqc_grade = entry.get("pqc_grade", "")
        pqc_style = "green" if pqc_score != "-" and pqc_score >= 7 else "yellow" if pqc_score != "-" and pqc_score >= 4 else "red"

        status = "[green]CLEAN[/green]"
        if entry["critical"] > 0:
            status = "[bold red]CRITICAL[/bold red]"
        elif entry["warnings"] > 0:
            status = "[yellow]WARNING[/yellow]"

        table.add_row(
            f"{entry['host']}:{entry['port']}",
            entry.get("tls_version", "-") or "-",
            f"[{crit_style}]{entry['critical']}[/{crit_style}]",
            f"[{warn_style}]{entry['warnings']}[/{warn_style}]",
            f"[{pqc_style}]{pqc_score}/10 {pqc_grade}[/{pqc_style}]" if pqc_score != "-" else "-",
            status,
        )

    console.print()
    console.print(table)
    console.print(
        f"\n  [bold]Total:[/bold] {len(fleet_data)} hosts scanned"
        f"  [red]{total_critical} critical[/red]"
        f"  [yellow]{total_warning} warnings[/yellow]"
    )


def _build_json(scan, audit, pqc_report, revocation_report) -> dict:
    """Build JSON output combining all reports."""
    output = {
        "target": f"{scan.host}:{scan.port}",
        "tls_version": scan.tls_version,
        "cipher_suite": scan.cipher_suite,
        "key_exchange": scan.key_exchange,
        "chain": [
            {
                "subject": c.subject,
                "issuer": c.issuer,
                "not_before": c.not_before,
                "not_after": c.not_after,
                "sig_algorithm": c.sig_algorithm_name,
                "key_type": c.key_type,
                "key_size": c.key_size,
                "san": c.san_names,
                "is_ca": c.is_ca,
                "self_signed": c.is_self_signed,
            }
            for c in scan.chain
        ],
        "audit": {
            "critical": audit.critical_count,
            "warnings": audit.warning_count,
            "passed": audit.pass_count,
            "exit_code": audit.exit_code,
            "findings": [
                {
                    "check": f.check,
                    "severity": f.severity.value,
                    "component": f.component,
                    "message": f.message,
                    "remediation": f.remediation,
                }
                for f in audit.findings
            ],
        },
    }

    if pqc_report:
        output["pqc"] = {
            "score": pqc_report.score,
            "max_score": pqc_report.max_score,
            "grade": pqc_report.grade,
            "ready": pqc_report.ready,
            "overall_safety": pqc_report.overall_safety.value,
            "cnsa2_compliant": pqc_report.cnsa2_compliant,
            "cnsa2_next_deadline": pqc_report.cnsa2_next_deadline,
            "cnsa2_days_remaining": pqc_report.cnsa2_days_remaining,
            "recommendations": pqc_report.recommendations,
            "findings": [
                {
                    "component": f.component,
                    "algorithm": f.algorithm,
                    "quantum_safety": f.quantum_safety.value,
                    "points": f"{f.points_earned}/{f.points_possible}",
                }
                for f in pqc_report.findings
            ],
        }

    if revocation_report:
        output["revocation"] = {
            "is_revoked": revocation_report.is_revoked,
            "ocsp": {
                "status": revocation_report.ocsp.status.value,
                "responder": revocation_report.ocsp.responder_url,
                "message": revocation_report.ocsp.message,
            },
            "crl": {
                "status": revocation_report.crl.status.value,
                "url": revocation_report.crl.crl_url,
                "message": revocation_report.crl.message,
            },
            "ct": {
                "logged": revocation_report.ct.logged,
                "entries": revocation_report.ct.ct_entries,
                "message": revocation_report.ct.message,
            },
        }

    return output
