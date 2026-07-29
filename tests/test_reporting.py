"""
tests/test_reporting.py

Tests for the report generator.
"""
from __future__ import annotations

import pytest
from reporting.generator import generate_report


class TestReportGeneration:
    def test_generic_report_contains_target(self, sample_session_with_findings):
        report = generate_report(sample_session_with_findings, format="generic")
        assert sample_session_with_findings.target in report

    def test_generic_report_contains_findings(self, sample_session_with_findings):
        report = generate_report(sample_session_with_findings, format="generic")
        # Should mention severity levels that exist in fixtures
        assert "critical" in report.lower() or "CRITICAL" in report

    def test_hackerone_format(self, sample_session_with_findings):
        report = generate_report(sample_session_with_findings, format="hackerone")
        assert report  # not empty

    def test_bugcrowd_format(self, sample_session_with_findings):
        report = generate_report(sample_session_with_findings, format="bugcrowd")
        assert report

    def test_empty_session_report(self, sample_session):
        report = generate_report(sample_session, format="generic")
        assert report  # should still produce output, not crash

    def test_report_mentions_session_id(self, sample_session_with_findings):
        report = generate_report(sample_session_with_findings, format="generic")
        # At least partial session ID should appear
        assert sample_session_with_findings.id[:8] in report

    def test_report_write_to_file(self, sample_session_with_findings, tmp_path):
        output = tmp_path / "report.md"
        generate_report(
            sample_session_with_findings,
            format="generic",
            output_path=str(output)
        )
        assert output.exists()
        content = output.read_text()
        assert sample_session_with_findings.target in content
