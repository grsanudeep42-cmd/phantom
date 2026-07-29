"""
tests/test_session.py

Unit tests for the session / database layer.
"""
from __future__ import annotations

import pytest
from core import session as db


class TestSessionCRUD:
    def test_create_session(self, fresh_db):
        sess = db.create_session(target="test.com", mode="grey", scope=["test.com"])
        assert sess.id
        assert len(sess.id) == 36  # UUID format
        assert sess.target == "test.com"
        assert sess.mode == "grey"
        assert "test.com" in sess.scope

    def test_list_sessions_empty(self, fresh_db):
        assert db.list_sessions() == []

    def test_list_sessions_returns_all(self, fresh_db):
        db.create_session(target="a.com", mode="red", scope=[])
        db.create_session(target="b.com", mode="blue", scope=[])
        sessions = db.list_sessions()
        assert len(sessions) == 2
        targets = {s.target for s in sessions}
        assert targets == {"a.com", "b.com"}

    def test_get_session_by_prefix(self, fresh_db):
        sess = db.create_session(target="x.com", mode="grey", scope=[])
        found = [s for s in db.list_sessions() if s.id.startswith(sess.id[:8])]
        assert len(found) == 1
        assert found[0].target == "x.com"

    def test_session_created_at_set(self, fresh_db):
        sess = db.create_session(target="t.com", mode="grey", scope=[])
        assert sess.started_at
        assert "T" in sess.started_at  # ISO format


class TestFindings:
    def test_add_and_get_findings(self, sample_session):
        sid = sample_session.id
        db.add_finding(sid, "xss", "Reflected XSS in q param", "high", "<script>")
        findings = db.get_findings(sid)
        assert len(findings) == 1
        assert findings[0].type == "xss"
        assert findings[0].severity == "high"

    def test_multiple_findings(self, sample_session_with_findings):
        findings = db.get_findings(sample_session_with_findings.id)
        assert len(findings) == 5

    def test_finding_severity_values(self, sample_session_with_findings):
        findings = db.get_findings(sample_session_with_findings.id)
        severities = {f.severity for f in findings}
        assert "critical" in severities
        assert "high" in severities
        assert "info" in severities

    def test_empty_findings(self, sample_session):
        findings = db.get_findings(sample_session.id)
        assert findings == []

    def test_findings_isolated_per_session(self, fresh_db):
        s1 = db.create_session(target="a.com", mode="grey", scope=[])
        s2 = db.create_session(target="b.com", mode="grey", scope=[])
        db.add_finding(s1.id, "xss", "only in s1", "high", "")
        assert db.get_findings(s1.id) != []
        assert db.get_findings(s2.id) == []


class TestTriedTools:
    def test_add_tried(self, sample_session):
        sid = sample_session.id
        db.add_tried(sid, "nmap", ["-sV", "example.com"], "80/tcp open", 0)
        tried = db.get_tried(sid)
        assert len(tried) == 1
        assert tried[0].tool == "nmap"
        assert tried[0].exit_code == 0

    def test_tried_empty(self, sample_session):
        assert db.get_tried(sample_session.id) == []


class TestHypotheses:
    def test_add_hypothesis(self, sample_session):
        sid = sample_session.id
        db.add_hypothesis(
            sid,
            "Check for SQLi in login",   # hypothesis
            rationale="Found login form",
            suggested_tool="sqlmap",
            confidence=0.9,
        )
        hyps = db.get_hypotheses(sid)
        assert len(hyps) == 1
        assert hyps[0].confidence == 0.9
        assert hyps[0].suggested_tool == "sqlmap"
