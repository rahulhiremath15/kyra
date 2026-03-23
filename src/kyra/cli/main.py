"""KYRA CLI — Command-line interface for post-quantum cryptography readiness scanning."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from kyra import __version__
from kyra.cbom import generate_cbom, write_file
from kyra.cbom.schema import CBOMReport
from kyra.network.cbom_bridge import tls_result_to_findings
from kyra.network.tls_scanner import TLSScanResult, parse_host, scan_tls
from kyra.report.exporters import export_csv, export_cyclonedx, export_json
from kyra.risk import RiskLevel, analyze_cbom
from kyra.risk.engine import RiskReport, ScoredFinding
from kyra.scanner import ScannerEngine
from kyra.scanner.engine import ScanResult


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"kyra {__version__}")
        raise typer.Exit()


app = typer.Typer(
    name="kyra",
    help="Post-quantum cryptography readiness scanner.",
    no_args_is_help=True,
)


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        help="Show version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    """KYRA — Post-quantum cryptography readiness scanner."""


cbom_app = typer.Typer(help="Cryptography Bill of Materials commands.")
risk_app = typer.Typer(help="HNDL risk analysis commands.")
tls_app = typer.Typer(help="TLS endpoint scanning commands.")
app.add_typer(cbom_app, name="cbom")
app.add_typer(risk_app, name="risk")
app.add_typer(tls_app, name="tls")

console = Console()
err_console = Console(stderr=True)

# Severity ordering for display and --fail-on-risk threshold.
_LEVEL_ORDER = {
    RiskLevel.LOW: 0,
    RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2,
    RiskLevel.CRITICAL: 3,
}

_LEVEL_COLORS = {
    RiskLevel.LOW: "green",
    RiskLevel.MEDIUM: "yellow",
    RiskLevel.HIGH: "red",
    RiskLevel.CRITICAL: "bold red",
}


def _validate_target(target: str) -> Path:
    """Resolve and validate that the scan target is a directory."""
    path = Path(target).resolve()
    if not path.exists():
        err_console.print(f"[red]Error:[/red] path does not exist: {path}")
        raise typer.Exit(code=1)
    if not path.is_dir():
        err_console.print(f"[red]Error:[/red] not a directory: {path}")
        raise typer.Exit(code=1)
    return path


def _run_pipeline(target: str) -> tuple[ScanResult, CBOMReport, RiskReport]:
    """Run the full scan → CBOM → risk pipeline and return all three results."""
    path = _validate_target(target)
    engine = ScannerEngine()
    scan_result = engine.scan(path)
    cbom_report = generate_cbom(scan_result)
    risk_report = analyze_cbom(cbom_report)
    return scan_result, cbom_report, risk_report


def _readiness_score(risk_report: RiskReport) -> int:
    """Compute a 0-100 readiness score from overall risk (0.0-1.0)."""
    return max(0, min(100, round((1.0 - risk_report.overall_risk) * 100)))


# ------------------------------------------------------------------
# kyra scan <directory>
# ------------------------------------------------------------------


@app.command()
def scan(
    target: str = typer.Argument(".", help="Directory to scan"),
    output: str = typer.Option(None, "--output", "-o", help="Save CBOM report to file"),
) -> None:
    """Scan a directory for cryptographic usage."""
    path = _validate_target(target)

    with console.status("[bold blue]Scanning...", spinner="dots"):
        engine = ScannerEngine()
        scan_result = engine.scan(path)

    console.print()
    console.print(
        Panel(
            f"[bold]Files scanned:[/bold] {scan_result.files_scanned}\n"
            f"[bold]Files skipped:[/bold] {scan_result.files_skipped}\n"
            f"[bold]Findings:[/bold]      {len(scan_result.findings)}\n"
            f"[bold]Duration:[/bold]      {scan_result.duration_s}s",
            title="[bold blue]Scan Results[/bold blue]",
            expand=False,
        )
    )

    if scan_result.findings:
        table = Table(title="Findings")
        table.add_column("File", style="cyan", no_wrap=True)
        table.add_column("Line", justify="right")
        table.add_column("Algorithm", style="magenta")
        table.add_column("Family")
        table.add_column("Confidence", justify="right")
        for f in scan_result.findings:
            if f.file_path.startswith(str(path)):
                rel = Path(f.file_path).relative_to(path)
            else:
                rel = Path(f.file_path)
            table.add_row(
                str(rel),
                str(f.line_number),
                f.algorithm,
                f.algorithm_family,
                f"{f.confidence:.0%}",
            )
        console.print(table)

    if scan_result.errors:
        err_console.print(f"\n[yellow]Warnings ({len(scan_result.errors)}):[/yellow]")
        for e in scan_result.errors:
            err_console.print(f"  {e}")

    if output:
        cbom_report = generate_cbom(scan_result)
        fmt = "csv" if output.endswith(".csv") else "json"
        write_file(cbom_report, output, fmt=fmt)
        console.print(f"\nCBOM written to [bold]{output}[/bold]")


# ------------------------------------------------------------------
# kyra cbom generate
# ------------------------------------------------------------------


@cbom_app.command("generate")
def cbom_generate(
    target: str = typer.Argument(".", help="Directory to scan"),
    format: str = typer.Option("json", "--format", "-f", help="Output format (json, csv)"),
    output: str = typer.Option(None, "--output", "-o", help="Output file path"),
) -> None:
    """Generate a Cryptography Bill of Materials from a scan."""
    scan_result, cbom_report, _ = _run_pipeline(target)

    console.print(
        Panel(
            f"[bold]Total entries:[/bold]  {cbom_report.summary.total_findings}\n"
            f"[bold]By readiness:[/bold]   {dict(cbom_report.summary.by_readiness)}\n"
            f"[bold]By family:[/bold]      {dict(cbom_report.summary.by_algorithm_family)}",
            title="[bold blue]CBOM Summary[/bold blue]",
            expand=False,
        )
    )

    if cbom_report.entries:
        table = Table(title="CBOM Entries")
        table.add_column("Component", style="cyan")
        table.add_column("Algorithm", style="magenta")
        table.add_column("PQ Readiness")
        table.add_column("Exposure")
        table.add_column("Lifetime")
        for entry in cbom_report.entries:
            readiness = entry.pq_readiness.value
            color = {
                "QUANTUM_SAFE": "green",
                "HYBRID_READY": "blue",
                "MIGRATION_NEEDED": "yellow",
                "CRITICAL": "red",
            }.get(readiness, "white")
            table.add_row(
                entry.component,
                entry.algorithm,
                f"[{color}]{readiness}[/{color}]",
                entry.exposure_level.value,
                entry.data_lifetime,
            )
        console.print(table)

    if output:
        write_file(cbom_report, output, fmt=format)
        console.print(f"\nCBOM written to [bold]{output}[/bold]")


# ------------------------------------------------------------------
# kyra risk analyze
# ------------------------------------------------------------------


@risk_app.command("analyze")
def risk_analyze(
    target: str = typer.Argument(".", help="Directory to scan"),
    fail_on_risk: str = typer.Option(
        None,
        "--fail-on-risk",
        help="Exit non-zero if any finding meets this level (low/medium/high/critical)",
    ),
) -> None:
    """Analyze HNDL risk from a scan."""
    _, _, risk_report = _run_pipeline(target)
    score = _readiness_score(risk_report)

    # Header with readiness score
    score_color = "green" if score >= 80 else "yellow" if score >= 50 else "red"
    console.print()
    console.print(
        Panel(
            f"[bold {score_color}]{score} / 100[/bold {score_color}]",
            title="[bold]KYRA Post-Quantum Readiness Score[/bold]",
            expand=False,
        )
    )

    # Group findings by severity, display in descending order
    by_level: dict[RiskLevel, list[ScoredFinding]] = {}
    for f in risk_report.findings:
        by_level.setdefault(f.risk_level, []).append(f)

    for level in (RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW):
        findings = by_level.get(level, [])
        if not findings:
            continue
        color = _LEVEL_COLORS[level]
        console.print(f"\n[{color}]{level.value}[/{color}]")
        for f in findings:
            console.print(f"  - {f.entry.algorithm} in {f.entry.component} ({f.recommendation})")

    # --fail-on-risk gate
    if fail_on_risk:
        threshold_str = fail_on_risk.upper()
        try:
            threshold = RiskLevel(threshold_str)
        except ValueError:
            err_console.print(f"[red]Error:[/red] invalid risk level: {fail_on_risk}")
            raise typer.Exit(code=2) from None
        threshold_order = _LEVEL_ORDER[threshold]
        if any(_LEVEL_ORDER[f.risk_level] >= threshold_order for f in risk_report.findings):
            err_console.print(
                f"\n[red]Risk gate failed:[/red] findings at or above {threshold.value}"
            )
            raise typer.Exit(code=1)


# ------------------------------------------------------------------
# kyra report
# ------------------------------------------------------------------


def _is_tls_target(target: str) -> bool:
    """Return True if the target looks like a hostname (not a local path)."""
    if target.startswith("tls://"):
        return True
    # Simple heuristic: contains a dot but no path separator, and doesn't exist on disk.
    if "." in target and "/" not in target and "\\" not in target:
        return not Path(target).exists()
    return False


def _run_tls_pipeline(target: str) -> tuple[ScanResult, CBOMReport, RiskReport]:
    """Run the TLS scan → CBOM → risk pipeline for a hostname target."""
    host, port = parse_host(target.removeprefix("tls://"))
    result = scan_tls(host, port, timeout=10.0)
    if result.error is not None:
        err_console.print(f"[red]Error:[/red] {result.error}")
        raise typer.Exit(code=1)
    findings = tls_result_to_findings(result)
    scan_result = ScanResult(
        target=f"tls://{host}:{port}",
        findings=findings,
        files_scanned=0,
        files_skipped=0,
        duration_s=0.0,
    )
    cbom_report = generate_cbom(scan_result)
    risk_report = analyze_cbom(cbom_report)
    return scan_result, cbom_report, risk_report


def _write_export(content: str, output_path: str, fmt: str) -> None:
    """Write export content to a file with correct newline handling."""
    if fmt == "csv":
        with open(output_path, "w", encoding="utf-8", newline="") as fh:
            fh.write(content)
    else:
        Path(output_path).write_text(content, encoding="utf-8")


@app.command()
def report(
    target: str = typer.Argument(".", help="Directory or hostname to scan"),
    format: str = typer.Option(
        None,
        "--format",
        "-f",
        help="Export format (json, csv, cyclonedx)",
    ),
    output: str = typer.Option(None, "--output", "-o", help="Output file path"),
) -> None:
    """Run full pipeline and display a readiness report."""
    if _is_tls_target(target):
        scan_result, cbom_report, risk_report = _run_tls_pipeline(target)
    else:
        scan_result, cbom_report, risk_report = _run_pipeline(target)

    # If a structured format is requested, export and skip Rich output.
    if format is not None:
        exporters: dict[str, Callable[[CBOMReport, RiskReport], str]] = {
            "json": export_json,
            "csv": export_csv,
            "cyclonedx": export_cyclonedx,
        }
        fmt_lower = format.lower()
        if fmt_lower not in exporters:
            err_console.print(
                f"[red]Error:[/red] unknown format '{format}'. Choose from: {', '.join(exporters)}"
            )
            raise typer.Exit(code=1)

        content = exporters[fmt_lower](cbom_report, risk_report)
        if output:
            _write_export(content, output, fmt_lower)
            console.print(f"Report written to [bold]{output}[/bold]")
        else:
            console.print(content)
        return

    # Default: Rich terminal report.
    score = _readiness_score(risk_report)
    score_color = "green" if score >= 80 else "yellow" if score >= 50 else "red"
    console.print()
    console.print(
        Panel(
            f"[bold {score_color}]{score} / 100[/bold {score_color}]",
            title="[bold]KYRA Post-Quantum Readiness Score[/bold]",
            expand=False,
        )
    )

    # Summary stats
    console.print(
        f"\n[bold]Files scanned:[/bold] {scan_result.files_scanned}  "
        f"[bold]Findings:[/bold] {len(scan_result.findings)}  "
        f"[bold]Overall risk:[/bold] {risk_report.overall_level.value}"
    )

    # Findings grouped by severity
    by_level: dict[RiskLevel, list[ScoredFinding]] = {}
    for f in risk_report.findings:
        by_level.setdefault(f.risk_level, []).append(f)

    for level in (RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW):
        findings = by_level.get(level, [])
        if not findings:
            continue
        color = _LEVEL_COLORS[level]
        console.print(f"\n[{color}]{level.value}[/{color}]")
        for f in findings:
            console.print(f"  - {f.entry.algorithm} in {f.entry.component}")

    if output:
        fmt = "csv" if output.endswith(".csv") else "json"
        write_file(cbom_report, output, fmt=fmt)
        console.print(f"\nCBOM written to [bold]{output}[/bold]")


# ------------------------------------------------------------------
# kyra tls scan <hostname>
# ------------------------------------------------------------------


@tls_app.command("scan")
def tls_scan(
    hostname: str = typer.Argument(..., help="Host to scan (e.g. example.com, example.com:443)"),
    timeout: float = typer.Option(10.0, "--timeout", "-t", help="Connection timeout in seconds"),
) -> None:
    """Scan a TLS endpoint for post-quantum cryptography readiness."""
    host, port = parse_host(hostname)

    with console.status(f"[bold blue]Connecting to {host}:{port}...", spinner="dots"):
        result = scan_tls(host, port, timeout=timeout)

    if result.error is not None:
        err_console.print(f"[red]Error:[/red] {result.error}")
        raise typer.Exit(code=1)

    # Build CBOM findings and run through risk pipeline.
    findings = tls_result_to_findings(result)
    scan_result = ScanResult(
        target=f"tls://{host}:{port}",
        findings=findings,
        files_scanned=0,
        files_skipped=0,
        duration_s=0.0,
    )
    cbom_report = generate_cbom(scan_result)
    risk_report = analyze_cbom(cbom_report)

    _print_tls_results(result, risk_report)


def _print_tls_results(result: TLSScanResult, risk_report: RiskReport) -> None:
    """Display Rich-formatted TLS scan results."""
    # Build the summary panel content.
    lines = [
        f"[bold]Host:[/bold]           {result.host}:{result.port}",
        f"[bold]TLS Version:[/bold]    {result.tls_version}",
        f"[bold]Cipher Suite:[/bold]   {result.cipher_suite}",
    ]
    if result.cert_signature_algorithm:
        lines.append(f"[bold]Signature Alg:[/bold]  {result.cert_signature_algorithm}")
    if result.cert_public_key_algorithm:
        pk_display = result.cert_public_key_algorithm
        if result.cert_public_key_size:
            pk_display += f"-{result.cert_public_key_size}"
        lines.append(f"[bold]Certificate:[/bold]    {pk_display}")
    if result.cert_public_key_size:
        lines.append(f"[bold]Key Size:[/bold]       {result.cert_public_key_size}")

    console.print()
    console.print(
        Panel("\n".join(lines), title="[bold blue]TLS Scan Results[/bold blue]", expand=False)
    )

    # Risk assessment
    if risk_report.findings:
        level = risk_report.overall_level
        color = _LEVEL_COLORS[level]
        console.print(f"\n[bold]Post-Quantum Risk:[/bold] [{color}]{level.value}[/{color}]")

        for f in risk_report.findings:
            console.print(f"[bold]Recommendation:[/bold]   {f.recommendation}")
    else:
        console.print("\n[bold]Post-Quantum Risk:[/bold] [green]LOW[/green]")
        console.print("[bold]Recommendation:[/bold]   No immediate action needed")


if __name__ == "__main__":
    app()
