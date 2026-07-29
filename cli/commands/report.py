"""phantom/cli/commands/report.py — `phantom report <session_id>`"""
from __future__ import annotations
import click
from cli.ui import console, error, info, success


@click.command("report")
@click.argument("session_prefix")
@click.option("--format", "-f", "fmt",
              default="generic",
              type=click.Choice(["generic", "hackerone", "bugcrowd"]),
              help="Report format")
@click.option("--output", "-o", default=None,
              help="Write report to this file path")
def report_cmd(session_prefix: str, fmt: str, output: str) -> None:
    """Generate a report from a session's findings."""
    from core.session import list_sessions
    all_sessions = list_sessions()
    matched = [s for s in all_sessions if s.id.startswith(session_prefix)]
    if not matched:
        error(f"No session found: {session_prefix}")
        raise SystemExit(1)
    sess = matched[0]

    from reporting.generator import generate_report
    info(f"Generating {fmt} report for session {sess.id[:8]}… ({sess.target})")
    report = generate_report(sess, format=fmt, output_path=output)

    if output:
        success(f"Report written to: {output}")
    else:
        console.print(report)
