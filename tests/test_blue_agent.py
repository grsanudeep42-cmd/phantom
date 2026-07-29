"""
tests/test_blue_agent.py

Tests for blue agent IOC extraction and log analysis.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from agents.blue_agent import extract_iocs, analyze_log_file


class TestIOCExtraction:
    def test_extracts_public_ips(self):
        text = "Connection from 203.0.113.42 and 198.51.100.7"
        iocs = extract_iocs(text)
        assert "203.0.113.42" in iocs["ips"]
        assert "198.51.100.7" in iocs["ips"]

    def test_filters_private_ips(self):
        text = "Local: 192.168.1.1 and 10.0.0.5 and 127.0.0.1"
        iocs = extract_iocs(text)
        assert "192.168.1.1" not in iocs["ips"]
        assert "10.0.0.5" not in iocs["ips"]
        assert "127.0.0.1" not in iocs["ips"]

    def test_extracts_md5(self):
        text = "Hash: d41d8cd98f00b204e9800998ecf8427e"
        iocs = extract_iocs(text)
        assert "d41d8cd98f00b204e9800998ecf8427e" in iocs["md5"]

    def test_extracts_sha256(self):
        text = "SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        iocs = extract_iocs(text)
        assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in iocs["sha256"]

    def test_extracts_cves(self):
        text = "Affected by CVE-2024-12345 and CVE-2023-99999"
        iocs = extract_iocs(text)
        assert "CVE-2024-12345" in iocs["cves"]
        assert "CVE-2023-99999" in iocs["cves"]

    def test_empty_text(self):
        iocs = extract_iocs("")
        assert iocs["ips"] == []
        assert iocs["cves"] == []
        assert iocs["md5"] == []


class TestLogAnalysis:
    def _make_log(self, content: str) -> str:
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False)
        f.write(content)
        f.flush()
        return f.name

    def test_detects_sqli_pattern(self, sample_session):
        log = self._make_log("GET /search?q=UNION SELECT 1,2,3 HTTP/1.1")
        result = analyze_log_file(log, sample_session.id)
        assert result["findings_added"] > 0

    def test_detects_xss_pattern(self, sample_session):
        log = self._make_log("GET /page?name=<script>alert(1)</script> HTTP/1.1")
        result = analyze_log_file(log, sample_session.id)
        assert result["findings_added"] > 0

    def test_detects_path_traversal(self, sample_session):
        log = self._make_log("GET /../../../../../../etc/passwd HTTP/1.1")
        result = analyze_log_file(log, sample_session.id)
        assert result["findings_added"] > 0

    def test_missing_file(self, sample_session):
        result = analyze_log_file("/nonexistent/path/file.log", sample_session.id)
        assert "error" in result

    def test_clean_log_no_findings(self, sample_session):
        log = self._make_log("GET /index.html HTTP/1.1 200 1234\nGET /about HTTP/1.1 200 567\n")
        result = analyze_log_file(log, sample_session.id)
        assert result["findings_added"] == 0

    def test_reports_line_count(self, sample_session):
        log = self._make_log("line1\nline2\nline3\n")
        result = analyze_log_file(log, sample_session.id)
        assert result["total_lines"] == 3
